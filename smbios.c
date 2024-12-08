/*
 * Copyright 2019-2024 Bruno Costa
 * https://github.com/brunexgeek/smbios-parser
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "smbios.h"
#include <stdio.h>

#define VALID_VERSION(x) (((x) >= SMBIOS_2_0 && (x) <= SMBIOS_2_8) || (x) == SMBIOS_3_0)

#ifdef __cplusplus
namespace smbios {
#endif

static SMBIOS_CONSTEXPR size_t SMBIOS_HEADER_SIZE = 32;
static SMBIOS_CONSTEXPR size_t SMBIOS_ENTRY_HEADER_SIZE = 4;

#ifdef _WIN32

#include <Windows.h>

struct RawSMBIOSData
{
	BYTE    Used20CallingMethod;
	BYTE    SMBIOSMajorVersion;
	BYTE    SMBIOSMinorVersion;
	BYTE    DmiRevision;
	DWORD   Length;
	BYTE    SMBIOSTableData[];
};
#endif

int smbios_initialize(struct ParserContext *context, const uint8_t *data, size_t size, enum SpecVersion version )
{
    // we need at least the smbios header for now
    if (size < SMBIOS_HEADER_SIZE)
        return SMBERR_INVALID_DATA;

    memset(context, 0, sizeof(struct ParserContext));
    context->ptr = NULL;
    context->sversion = VALID_VERSION(version) ? SMBIOS_3_0 : version;

    // we have a valid SMBIOS entry point?
    #ifndef _WIN32
    context->data = data + SMBIOS_HEADER_SIZE;
    context->size = size - SMBIOS_HEADER_SIZE;

    if (data[0] == '_' && data[1] == 'S' && data[2] == 'M' && data[3] == '_')
    {
        // version 2.x

        // entry point length
        if (data[5] != 0x1F)
            return SMBERR_INVALID_DATA;
        // entry point revision
        if (data[10] != 0)
            return SMBERR_INVALID_DATA;
        // intermediate anchor string
        if (data[16] != '_' || data[17] != 'D' || data[18] != 'M' || data[19] != 'I' || data[20] != '_')
            return SMBERR_INVALID_DATA;

        // get the SMBIOS version
        context->oversion = data[6] << 8 | data[7];
    }
    else
    if (data[0] == '_' && data[1] == 'S' && data[2] == 'M' && data[3] == '3' && data[4] == '_')
    {
        // version 3.x

        // entry point length
        if (data[6] != 0x18)
            return SMBERR_INVALID_DATA;
        // entry point revision
        if (data[10] != 0x01)
            return SMBERR_INVALID_DATA;

        // get the SMBIOS version
        context->oversion = data[7] << 8 | data[8];
    }
    else
        return SMBERR_INVALID_DATA;
    #else

    struct RawSMBIOSData *smBiosData = NULL;
    smBiosData = (struct RawSMBIOSData*) data;

    // get the SMBIOS version
    context->oversion = smBiosData->SMBIOSMajorVersion << 8 | smBiosData->SMBIOSMinorVersion;
    context->data = smBiosData->SMBIOSTableData;
    context->size = smBiosData->Length;
    #endif

    if (!VALID_VERSION(context->oversion))
        return SMBERR_INVALID_DATA;
    if (context->sversion > context->oversion)
        context->sversion = context->oversion;

    return SMBERR_OK;
}

const char *smbios_get_string( const struct Entry *entry, int index )
{
    if (entry == NULL || index <= 0 || index > entry->string_count)
        return NULL;

    const char *ptr = entry->strings;
    for (int i = 1; *ptr != 0 && i < index; ++i)
    {
        while (*ptr != 0) ++ptr;
        ++ptr;
    }
    return ptr;
}

static const char *get_string( struct ParserContext *context, int index )
{
    return smbios_get_string(&context->entry, index);
}

int smbios_reset( struct ParserContext *context )
{
    if (context == NULL)
        return SMBERR_INVALID_ARGUMENT;
    if (context->data == NULL || context->failed)
        return SMBERR_INVALID_DATA;
    context->ptr = context->estart = context->eend = NULL;
    return SMBERR_OK;
}

static uint8_t read_uint8(struct ParserContext *context)
{
    if (context->ptr + 1 >= context->eend)
    {
        context->failed = true;
        return 0;
    }
    return *context->ptr++;
}

static uint16_t read_uint16(struct ParserContext *context)
{
    if (context->ptr + 2 >= context->eend)
    {
        context->failed = true;
        return 0;
    }

    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        uint16_t value = context->ptr[0] | ((uint16_t)context->ptr[1] << 8);
    #else
        uint16_t value = ((uint16_t)context->ptr[0] << 8) | context->ptr[1];
    #endif

    context->ptr += 2;
    return value;
}

static uint32_t read_uint32(struct ParserContext *context)
{
    if (context->ptr + 4 >= context->eend)
    {
        context->failed = true;
        return 0;
    }

    uint32_t value = 0;
    for (int i = 0; i < 4; ++i)
    {
        #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        value |= context->ptr[i] << (i * 8);
        #else
        value |= context->ptr[i] << ((3 - i) * 8);
        #endif
    }
    context->ptr += 4;
    return value;
}

static uint64_t read_uint64(struct ParserContext *context)
{
    if (context->ptr + 8 >= context->eend)
    {
        context->failed = true;
        return 0;
    }

    uint64_t value = 0;
    for (int i = 0; i < 8; ++i)
    {
        #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        value |= context->ptr[i] << (i * 8);
        #else
        value |= context->ptr[i] << ((7 - i) * 8);
        #endif
    }

    context->ptr += 8;
    return value;
}

static void parse_bios_info(struct ParserContext *context)
{
    // 2.0+
    if (context->sversion >= SMBIOS_2_0)
    {
        context->entry.data.bios_info.Vendor_ = read_uint8(context);
        context->entry.data.bios_info.BIOSVersion_ = read_uint8(context);
        context->entry.data.bios_info.BIOSStartingAddressSegment = read_uint16(context);
        context->entry.data.bios_info.BIOSReleaseDate_ = read_uint8(context);
        context->entry.data.bios_info.BIOSROMSize = read_uint8(context);
        for (size_t i = 0; i < 8; ++i)
            context->entry.data.bios_info.BIOSCharacteristics[i] = read_uint8(context);

        context->entry.data.bios_info.Vendor          = get_string(context, context->entry.data.bios_info.Vendor_);
        context->entry.data.bios_info.BIOSVersion     = get_string(context, context->entry.data.bios_info.BIOSVersion_);
        context->entry.data.bios_info.BIOSReleaseDate = get_string(context, context->entry.data.bios_info.BIOSReleaseDate_);
    }
    // 2.4+
    if (context->sversion >= SMBIOS_2_4)
    {
        context->entry.data.bios_info.BIOSCharacteristicsExtensionBytes[0] = read_uint8(context);
        context->entry.data.bios_info.BIOSCharacteristicsExtensionBytes[1] = read_uint8(context);
        context->entry.data.bios_info.SystemBIOSMajorRelease = read_uint8(context);
        context->entry.data.bios_info.SystemBIOSMinorRelease = read_uint8(context);
        context->entry.data.bios_info.EmbeddedControlerFirmwareMajorRelease = read_uint8(context);
        context->entry.data.bios_info.EmbeddedControlerFirmwareMinorRelease = read_uint8(context);
    }
}

static void parse_system_info(struct ParserContext *context)
{
    // 2.0+
    if (context->sversion >= SMBIOS_2_0)
    {
        context->entry.data.system_info.Manufacturer_ = read_uint8(context);
        context->entry.data.system_info.ProductName_ = read_uint8(context);
        context->entry.data.system_info.Version_ = read_uint8(context);
        context->entry.data.system_info.SerialNumber_ = read_uint8(context);

        context->entry.data.system_info.Manufacturer = get_string(context, context->entry.data.system_info.Manufacturer_);
        context->entry.data.system_info.ProductName  = get_string(context, context->entry.data.system_info.ProductName_);
        context->entry.data.system_info.Version = get_string(context, context->entry.data.system_info.Version_);
        context->entry.data.system_info.SerialNumber = get_string(context, context->entry.data.system_info.SerialNumber_);
    }
    // 2.1+
    if (context->sversion >= SMBIOS_2_1)
    {
        for(int i = 0 ; i < 16; ++i)
            context->entry.data.system_info.UUID[i] = read_uint8(context);
        context->entry.data.system_info.WakeupType = read_uint8(context);
    }
    // 2.4+
    if (context->sversion >= SMBIOS_2_4)
    {
        context->entry.data.system_info.SKUNumber_ = read_uint8(context);
        context->entry.data.system_info.Family_ = read_uint8(context);

        context->entry.data.system_info.SKUNumber = get_string(context, context->entry.data.system_info.SKUNumber_);
        context->entry.data.system_info.Family = get_string(context, context->entry.data.system_info.Family_);
    }
}

static void parse_baseboard_info(struct ParserContext *context)
{
    // 2.0+
    if (context->sversion >= SMBIOS_2_0)
    {
        context->entry.data.baseboard_info.Manufacturer_ = read_uint8(context);
        context->entry.data.baseboard_info.Product_ = read_uint8(context);
        context->entry.data.baseboard_info.Version_ = read_uint8(context);
        context->entry.data.baseboard_info.SerialNumber_ = read_uint8(context);
        context->entry.data.baseboard_info.AssetTag_ = read_uint8(context);
        context->entry.data.baseboard_info.FeatureFlags = read_uint8(context);
        context->entry.data.baseboard_info.LocationInChassis_ = read_uint8(context);
        context->entry.data.baseboard_info.ChassisHandle = read_uint16(context);
        context->entry.data.baseboard_info.BoardType = read_uint8(context);
        context->entry.data.baseboard_info.NumberOfContainedObjectHandles = read_uint8(context);
        context->entry.data.baseboard_info.ContainedObjectHandles = (uint16_t*) context->ptr;
        context->ptr += context->entry.data.baseboard_info.NumberOfContainedObjectHandles * sizeof(uint16_t);

        context->entry.data.baseboard_info.Manufacturer      = get_string(context, context->entry.data.baseboard_info.Manufacturer_);
        context->entry.data.baseboard_info.Product           = get_string(context, context->entry.data.baseboard_info.Product_);
        context->entry.data.baseboard_info.Version           = get_string(context, context->entry.data.baseboard_info.Version_);
        context->entry.data.baseboard_info.SerialNumber      = get_string(context, context->entry.data.baseboard_info.SerialNumber_);
        context->entry.data.baseboard_info.AssetTag          = get_string(context, context->entry.data.baseboard_info.AssetTag_);
        context->entry.data.baseboard_info.LocationInChassis = get_string(context, context->entry.data.baseboard_info.LocationInChassis_);
    }
}

static void parse_system_enclosure(struct ParserContext *context)
{
    // 2.0+
    if (context->sversion >= SMBIOS_2_0)
    {
        context->entry.data.system_enclosure.Manufacturer_ = read_uint8(context);
        context->entry.data.system_enclosure.Type = read_uint8(context);
        context->entry.data.system_enclosure.Version_ = read_uint8(context);
        context->entry.data.system_enclosure.SerialNumber_ = read_uint8(context);
        context->entry.data.system_enclosure.AssetTag_ = read_uint8(context);

        context->entry.data.system_enclosure.Manufacturer = get_string(context, context->entry.data.system_enclosure.Manufacturer_);
        context->entry.data.system_enclosure.Version      = get_string(context, context->entry.data.system_enclosure.Version_);
        context->entry.data.system_enclosure.SerialNumber = get_string(context, context->entry.data.system_enclosure.SerialNumber_);
        context->entry.data.system_enclosure.AssetTag     = get_string(context, context->entry.data.system_enclosure.AssetTag_);
    }
    // 2.1+
    if (context->sversion >= SMBIOS_2_1)
    {
        context->entry.data.system_enclosure.BootupState = read_uint8(context);
        context->entry.data.system_enclosure.PowerSupplyState = read_uint8(context);
        context->entry.data.system_enclosure.ThermalState = read_uint8(context);
        context->entry.data.system_enclosure.SecurityStatus = read_uint8(context);
    }
    // 2.3+
    if (context->sversion >= SMBIOS_2_3)
    {
        context->entry.data.system_enclosure.OEMdefined = read_uint32(context);
        context->entry.data.system_enclosure.Height = read_uint8(context);
        context->entry.data.system_enclosure.NumberOfPowerCords = read_uint8(context);
        context->entry.data.system_enclosure.ContainedElementCount = read_uint8(context);
        context->entry.data.system_enclosure.ContainedElementRecordLength = read_uint8(context);
        context->entry.data.system_enclosure.ContainedElements = context->ptr;
        context->ptr += context->entry.data.system_enclosure.ContainedElementCount * context->entry.data.system_enclosure.ContainedElementRecordLength;
    }
    // 2.7+
    if (context->sversion >= SMBIOS_2_7)
    {
        context->entry.data.system_enclosure.SKUNumber_ = read_uint8(context);

        context->entry.data.system_enclosure.SKUNumber = get_string(context, context->entry.data.system_enclosure.SKUNumber_);
    }
}

static void parse_processor_info(struct ParserContext *context)
{
    // 2.0+
    if (context->sversion >= SMBIOS_2_0)
    {
        context->entry.data.processor_info.SocketDesignation_ = read_uint8(context);
        context->entry.data.processor_info.ProcessorType = read_uint8(context);
        context->entry.data.processor_info.ProcessorFamily = read_uint8(context);
        context->entry.data.processor_info.ProcessorManufacturer_ = read_uint8(context);
        for(int i = 0 ; i < 8; ++i)
            context->entry.data.processor_info.ProcessorID[i] = read_uint8(context);
        context->entry.data.processor_info.ProcessorVersion_ = read_uint8(context);
        context->entry.data.processor_info.Voltage = read_uint8(context);
        context->entry.data.processor_info.ExternalClock = read_uint16(context);
        context->entry.data.processor_info.MaxSpeed = read_uint16(context);
        context->entry.data.processor_info.CurrentSpeed = read_uint16(context);
        context->entry.data.processor_info.Status = read_uint8(context);
        context->entry.data.processor_info.ProcessorUpgrade = read_uint8(context);

        context->entry.data.processor_info.SocketDesignation     = get_string(context, context->entry.data.processor_info.SocketDesignation_);
        context->entry.data.processor_info.ProcessorManufacturer = get_string(context, context->entry.data.processor_info.ProcessorManufacturer_);
        context->entry.data.processor_info.ProcessorVersion      = get_string(context, context->entry.data.processor_info.ProcessorVersion_);
    }
    // 2.1+
    if (context->sversion >= SMBIOS_2_1)
    {
        context->entry.data.processor_info.L1CacheHandle = read_uint16(context);
        context->entry.data.processor_info.L2CacheHandle = read_uint16(context);
        context->entry.data.processor_info.L3CacheHandle = read_uint16(context);
    }
    // 2.3+
    if (context->sversion >= SMBIOS_2_3)
    {
        context->entry.data.processor_info.SerialNumber_ = read_uint8(context);
        context->entry.data.processor_info.AssetTagNumber_ = read_uint8(context);
        context->entry.data.processor_info.PartNumber_ = read_uint8(context);

        context->entry.data.processor_info.SerialNumber = get_string(context, context->entry.data.processor_info.SerialNumber_);
        context->entry.data.processor_info.AssetTagNumber = get_string(context, context->entry.data.processor_info.AssetTagNumber_);
        context->entry.data.processor_info.PartNumber = get_string(context, context->entry.data.processor_info.PartNumber_);
    }
    // 2.5+
    if (context->sversion >= SMBIOS_2_5)
    {
        context->entry.data.processor_info.CoreCount = read_uint8(context);
        context->entry.data.processor_info.CoreEnabled = read_uint8(context);
        context->entry.data.processor_info.ThreadCount = read_uint8(context);
        context->entry.data.processor_info.ProcessorCharacteristics = read_uint16(context);
    }
    //2.6+
    if (context->sversion >= SMBIOS_2_6)
    {
        context->entry.data.processor_info.ProcessorFamily2 = read_uint16(context);
    }
    //3.0+
    if (context->sversion >= SMBIOS_3_0)
    {
        context->entry.data.processor_info.CoreCount2 = read_uint16(context);
        context->entry.data.processor_info.CoreEnabled2 = read_uint16(context);
        context->entry.data.processor_info.ThreadCount2 = read_uint16(context);
    }
}

static void parse_system_slot(struct ParserContext *context)
{
    // 2.0+
    if (context->sversion >= SMBIOS_2_0)
    {
        context->entry.data.system_slot.SlotDesignation_ = read_uint8(context);
        context->entry.data.system_slot.SlotType = read_uint8(context);
        context->entry.data.system_slot.SlotDataBusWidth = read_uint8(context);
        context->entry.data.system_slot.CurrentUsage = read_uint8(context);
        context->entry.data.system_slot.SlotLength = read_uint8(context);
        context->entry.data.system_slot.SlotID = read_uint16(context);
        context->entry.data.system_slot.SlotCharacteristics1 = read_uint8(context);

        context->entry.data.system_slot.SlotDesignation = get_string(context, context->entry.data.system_slot.SlotDesignation_);
    }
    // 2.1+
    if (context->sversion >= SMBIOS_2_1)
    {
        context->entry.data.system_slot.SlotCharacteristics2 = read_uint8(context);
    }
    // 2.6+
    if (context->sversion >= SMBIOS_2_6)
    {
        context->entry.data.system_slot.SegmentGroupNumber = read_uint16(context);
        context->entry.data.system_slot.BusNumber = read_uint8(context);
        context->entry.data.system_slot.DeviceOrFunctionNumber = read_uint8(context);
    }
}

static void parse_physical_memory_array(struct ParserContext *context)
{
    // 2.1+
    if (context->sversion >= SMBIOS_2_1)
    {
        context->entry.data.physical_memory_array.Location = read_uint8(context);
        context->entry.data.physical_memory_array.Use = read_uint8(context);
        context->entry.data.physical_memory_array.ErrorCorrection = read_uint8(context);
        context->entry.data.physical_memory_array.MaximumCapacity = read_uint32(context);
        context->entry.data.physical_memory_array.ErrorInformationHandle = read_uint16(context);
        context->entry.data.physical_memory_array.NumberDevices = read_uint16(context);
    }
    // 2.7+
    if (context->sversion >= SMBIOS_2_7)
    {
        context->entry.data.physical_memory_array.ExtendedMaximumCapacity = read_uint64(context);
    }
}

static void parse_memory_device(struct ParserContext *context)
{
    // 2.1+
    if (context->sversion >= SMBIOS_2_1)
    {
        context->entry.data.memory_device.PhysicalArrayHandle = read_uint16(context);
        context->entry.data.memory_device.ErrorInformationHandle = read_uint16(context);
        context->entry.data.memory_device.TotalWidth = read_uint16(context);
        context->entry.data.memory_device.DataWidth = read_uint16(context);
        context->entry.data.memory_device.Size = read_uint16(context);
        context->entry.data.memory_device.FormFactor = read_uint8(context);
        context->entry.data.memory_device.DeviceSet = read_uint8(context);
        context->entry.data.memory_device.DeviceLocator_ = read_uint8(context);
        context->entry.data.memory_device.BankLocator_ = read_uint8(context);
        context->entry.data.memory_device.MemoryType = read_uint8(context);
        context->entry.data.memory_device.TypeDetail = read_uint16(context);

        context->entry.data.memory_device.DeviceLocator  = get_string(context, context->entry.data.memory_device.DeviceLocator_);
        context->entry.data.memory_device.BankLocator    = get_string(context, context->entry.data.memory_device.BankLocator_);
    }
    // 2.3+
    if (context->sversion >= SMBIOS_2_3)
    {
        context->entry.data.memory_device.Speed = read_uint16(context);
        context->entry.data.memory_device.Manufacturer_ = read_uint8(context);
        context->entry.data.memory_device.SerialNumber_ = read_uint8(context);
        context->entry.data.memory_device.AssetTagNumber_ = read_uint8(context);
        context->entry.data.memory_device.PartNumber_ = read_uint8(context);

        context->entry.data.memory_device.Manufacturer   = get_string(context, context->entry.data.memory_device.Manufacturer_);
        context->entry.data.memory_device.SerialNumber   = get_string(context, context->entry.data.memory_device.SerialNumber_);
        context->entry.data.memory_device.AssetTagNumber = get_string(context, context->entry.data.memory_device.AssetTagNumber_);
        context->entry.data.memory_device.PartNumber     = get_string(context, context->entry.data.memory_device.PartNumber_);
    }
    // 2.6+
    if (context->sversion >= SMBIOS_2_6)
    {
        context->entry.data.memory_device.Attributes = read_uint8(context);
    }
    // 2.7+
    if (context->sversion >= SMBIOS_2_7)
    {
        context->entry.data.memory_device.ExtendedSize = read_uint32(context);
        context->entry.data.memory_device.ConfiguredClockSpeed = read_uint16(context);
    }
    // 2.8+
    if (context->sversion >= SMBIOS_2_8)
    {
        context->entry.data.memory_device.MinimumVoltage = read_uint16(context);
        context->entry.data.memory_device.MaximumVoltage = read_uint16(context);
        context->entry.data.memory_device.ConfiguredVoltage = read_uint16(context);
    }
}

static void parse_oem_strings(struct ParserContext *context)
{
    // 2.0+
    if (context->sversion >= SMBIOS_2_0)
    {
        context->entry.data.oem_strings.Count = read_uint8(context);
        context->entry.data.oem_strings.Values = (const char*) context->ptr;
    }
}

static void parse_port_connector(struct ParserContext *context)
{
    // 2.0+
    if (context->sversion >= SMBIOS_2_0)
    {
        context->entry.data.port_connector.InternalReferenceDesignator_ = read_uint8(context);
        context->entry.data.port_connector.InternalConnectorType = read_uint8(context);
        context->entry.data.port_connector.ExternalReferenceDesignator_ = read_uint8(context);
        context->entry.data.port_connector.ExternalConnectorType = read_uint8(context);
        context->entry.data.port_connector.PortType = read_uint8(context);

        context->entry.data.port_connector.ExternalReferenceDesignator = get_string(context, context->entry.data.port_connector.ExternalReferenceDesignator_);
        context->entry.data.port_connector.InternalReferenceDesignator = get_string(context, context->entry.data.port_connector.InternalReferenceDesignator_);
    }
}

static void parse_memory_array_mapped_address(struct ParserContext *context)
{
    if (context->sversion >= SMBIOS_2_1)
    {
        context->entry.data.memory_array_mapped_address.StartingAddress = read_uint32(context);
        context->entry.data.memory_array_mapped_address.EndingAddress = read_uint32(context);
        context->entry.data.memory_array_mapped_address.MemoryArrayHandle = read_uint16(context);
        context->entry.data.memory_array_mapped_address.PartitionWidth = read_uint8(context);
    }
    if (context->sversion >= SMBIOS_2_7)
    {
        context->entry.data.memory_array_mapped_address.ExtendedStartingAddress = read_uint64(context);
        context->entry.data.memory_array_mapped_address.ExtendedEndingAddress = read_uint64(context);
    }
}

static void parse_memory_device_mapped_address(struct ParserContext *context)
{
    if (context->sversion >= SMBIOS_2_1)
    {
        context->entry.data.memory_device_mapped_address.StartingAddress = read_uint32(context);
        context->entry.data.memory_device_mapped_address.EndingAddress = read_uint32(context);
        context->entry.data.memory_device_mapped_address.MemoryDeviceHandle = read_uint16(context);
        context->entry.data.memory_device_mapped_address.MemoryArrayMappedAddressHandle = read_uint16(context);
        context->entry.data.memory_device_mapped_address.PartitionRowPosition = read_uint8(context);
        context->entry.data.memory_device_mapped_address.InterleavePosition = read_uint8(context);
        context->entry.data.memory_device_mapped_address.InterleavedDataDepth = read_uint8(context);
    }
    if (context->sversion >= SMBIOS_2_7)
    {
        context->entry.data.memory_device_mapped_address.ExtendedStartingAddress = read_uint64(context);
        context->entry.data.memory_device_mapped_address.ExtendedEndingAddress = read_uint64(context);
    }
}


static void parse_system_boot_info(struct ParserContext *context)
{
    if (context->sversion >= SMBIOS_2_0)
    {
        context->ptr += sizeof(context->entry.data.system_boot_info.Reserved);
        context->entry.data.system_boot_info.BootStatus = context->ptr;
    }
}

static void parse_management_device(struct ParserContext *context)
{
    if (context->sversion >= SMBIOS_2_0)
    {
        context->entry.data.management_device.Description_ = read_uint8(context);
        context->entry.data.management_device.Type = read_uint8(context);
        context->entry.data.management_device.Address = read_uint32(context);
        context->entry.data.management_device.AddressType = read_uint8(context);

        context->entry.data.management_device.Description = get_string(context, context->entry.data.management_device.Description_);
    }
}

static void parse_management_device_component(struct ParserContext *context)
{
    if (context->sversion >= SMBIOS_2_0)
    {
        context->entry.data.management_device_component.Description_ = read_uint8(context);
        context->entry.data.management_device_component.ManagementDeviceHandle = read_uint16(context);
        context->entry.data.management_device_component.ComponentHandle = read_uint16(context);
        context->entry.data.management_device_component.ThresholdHandle = read_uint16(context);

        context->entry.data.management_device_component.Description = get_string(context, context->entry.data.management_device_component.Description_);
    }
}

static void parse_management_device_threshold_data(struct ParserContext *context)
{
    if (context->sversion >= SMBIOS_2_0)
    {
        context->entry.data.management_device_threshold_data.LowerThresholdNonCritical = read_uint16(context);
        context->entry.data.management_device_threshold_data.UpperThresholdNonCritical = read_uint16(context);
        context->entry.data.management_device_threshold_data.LowerThresholdCritical = read_uint16(context);
        context->entry.data.management_device_threshold_data.UpperThresholdCritical = read_uint16(context);
        context->entry.data.management_device_threshold_data.LowerThresholdNonRecoverable = read_uint16(context);
        context->entry.data.management_device_threshold_data.UpperThresholdNonRecoverable = read_uint16(context);
    }
}


static void parse_onboard_devices_extended_info(struct ParserContext *context)
{
    if (context->sversion >= SMBIOS_2_0)
    {
        context->entry.data.onboard_devices_extended_info.ReferenceDesignation_ = read_uint8(context);
        context->entry.data.onboard_devices_extended_info.DeviceType = read_uint8(context);
        context->entry.data.onboard_devices_extended_info.DeviceTypeInstance = read_uint8(context);
        context->entry.data.onboard_devices_extended_info.SegmentGroupNumber = read_uint16(context);
        context->entry.data.onboard_devices_extended_info.BusNumber = read_uint8(context);
        context->entry.data.onboard_devices_extended_info.DeviceOrFunctionNumber = read_uint8(context);

        context->entry.data.onboard_devices_extended_info.ReferenceDesignation = get_string(context, context->entry.data.onboard_devices_extended_info.ReferenceDesignation_);
    }
}

static int parse_entry(struct ParserContext *context, const struct Entry **entry)
{
    if (entry == NULL)
        return SMBERR_INVALID_ARGUMENT;

    switch (context->entry.type)
    {
        case TYPE_BIOS_INFO:
            parse_bios_info(context);
            break;
        case TYPE_SYSTEM_INFO:
            parse_system_info(context);
            break;
        case TYPE_BASEBOARD_INFO:
            parse_baseboard_info(context);
            break;
        case TYPE_SYSTEM_ENCLOSURE:
            parse_system_enclosure(context);
            break;
        case TYPE_PROCESSOR_INFO:
            parse_processor_info(context);
            break;
        case TYPE_PORT_CONNECTOR:
            parse_port_connector(context);
            break;
        case TYPE_SYSTEM_SLOT:
            parse_system_slot(context);
            break;
        case TYPE_OEM_STRINGS:
            parse_oem_strings(context);
            break;
        case TYPE_PHYSICAL_MEMORY_ARRAY:
            parse_physical_memory_array(context);
            break;
        case TYPE_MEMORY_DEVICE:
            parse_memory_device(context);
            break;
        case TYPE_MEMORY_ARRAY_MAPPED_ADDRESS:
            parse_memory_array_mapped_address(context);
            break;
        case TYPE_MEMORY_DEVICE_MAPPED_ADDRESS:
            parse_memory_device_mapped_address(context);
            break;
        case TYPE_SYSTEM_BOOT_INFO:
            parse_system_boot_info(context);
            break;
        case TYPE_MANAGEMENT_DEVICE:
            parse_management_device(context);
            break;
        case TYPE_MANAGEMENT_DEVICE_COMPONENT:
            parse_management_device_component(context);
            break;
        case TYPE_MANAGEMENT_DEVICE_THRESHOLD_DATA:
            parse_management_device_threshold_data(context);
            break;
        case TYPE_ONBOARD_DEVICES_EXTENDED_INFO:
            parse_onboard_devices_extended_info(context);
            break;
        default:
            // we have an unrecognized entry
            return SMBERR_OK;
    }

    if (context->failed)
        return SMBERR_INVALID_DATA;
    *entry = &context->entry;
    return SMBERR_OK;
}

int smbios_next(struct ParserContext *context, const struct Entry **entry)
{
    if (context == NULL || entry == NULL)
        return SMBERR_INVALID_ARGUMENT;
    if (context->data == NULL || context->failed)
        return SMBERR_INVALID_DATA;

    // jump to the next field
    if (context->estart == NULL)
        context->estart = context->ptr = context->data;
    else
        context->estart = context->ptr = context->eend;

    memset(&context->entry, 0, sizeof(context->entry));

    if (context->estart + SMBIOS_ENTRY_HEADER_SIZE >= context->data + context->size)
        return SMBERR_INVALID_DATA;

    // entry header
    context->entry.type = *context->ptr++;
    context->entry.length = *context->ptr++;
    context->entry.handle = *context->ptr++;
    context->entry.handle |= (uint16_t) ((*context->ptr++) << 8);
    context->entry.rawdata = context->estart;
    context->entry.strings = (const char *) context->estart + context->entry.length;

    // compute the end of the entry skipping all strings
    context->eend = (uint8_t*) context->entry.strings;
    int nulls = 0;
    while (context->eend < context->data + context->size)
    {
        if (*context->eend++ != 0)
            nulls = 0;
        else
        {
            if (nulls++ > 0)
                break;
            context->entry.string_count++;
        }
    }
    if (nulls != 2)
        return SMBERR_INVALID_DATA;

    if (context->entry.type == 127)
    {
        smbios_reset(context);
        return SMBERR_END_OF_STREAM;
    }

    return parse_entry(context, entry);
}

int smbios_get_version(struct ParserContext *context, enum SpecVersion *selected, enum SpecVersion *original)
{
    if (context == NULL)
        return SMBERR_INVALID_ARGUMENT;
    if (context->data == NULL || context->failed)
        return SMBERR_INVALID_DATA;

    if (selected)
        *selected = context->sversion;
    if (original)
        *original = context->oversion;
    return SMBERR_OK;
}

#ifdef __cplusplus
} // namespace smbios
#endif
