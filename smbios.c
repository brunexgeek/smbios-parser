/*
 * Copyright 2020 Bruno Ribeiro
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

#define DMI_ENTRY_HEADER_SIZE   4
#define VALID_VERSION(x) (((x) >= SMBIOS_2_0 && (x) <= SMBIOS_2_8) || (x) == SMBIOS_3_0)

#ifdef _cplusplus
namespace smbios {
#endif

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

int smbios_initialize(struct ParserContext *context, const uint8_t *data, size_t size, int version )
{
    // we need at least the smbios header for now
    if (size < 32)
        return SMBERR_INVALID_DATA;

    memset(context, 0, sizeof(struct ParserContext));
    context->data  = data + 32;
    context->size = size - 32;
    context->ptr = NULL;
    context->version = VALID_VERSION(version) ? SMBIOS_3_0 : version;
    int vn = 0;

    // we have a valid SMBIOS entry point?
    #ifndef _WIN32
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
        vn = data[6] << 8 | data[7];
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
        vn = data[7] << 8 | data[8];
    }
    else
        return SMBERR_INVALID_DATA;
    #else
    RawSMBIOSData *smBiosData = nullptr;
    smBiosData = (RawSMBIOSData *) data;

    // get the SMBIOS version
    vn = smBiosData->SMBIOSMajorVersion << 8 | smBiosData->SMBIOSMinorVersion;
    data_ = smBiosData->SMBIOSTableData;
    size_ = smBiosData->Length;
    #endif

    if (!VALID_VERSION(vn))
        return SMBERR_INVALID_DATA;
    if (context->version > vn)
        context->version = vn;

    return SMBERR_OK;
}

static const char *smbios_get_string( struct ParserContext *context, int index )
{
    if (index <= 0 || index > context->entry.string_count)
        return "";

    const char *ptr = context->entry.strings;
    for (int i = 1; *ptr != 0 && i < index; ++i)
    {
        // TODO: check buffer limits
        while (*ptr != 0) ++ptr;
        ++ptr;
    }
    return ptr;
}

int smbios_reset( struct ParserContext *context )
{
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
    return read_uint8(context) | (read_uint8(context) << 8);
}

static uint32_t read_uint32(struct ParserContext *context)
{
    return read_uint16(context) | ((uint32_t)read_uint16(context) << 16);
}

static uint64_t read_uint64(struct ParserContext *context)
{
    return read_uint32(context) | ((uint64_t)read_uint32(context) << 32);
}

static void parse_bios_info(struct ParserContext *context)
{
    // 2.0+
    if (context->version >= SMBIOS_2_0)
    {
        context->entry.data.bios.Vendor_ = read_uint8(context);
        context->entry.data.bios.BIOSVersion_ = read_uint8(context);
        context->entry.data.bios.BIOSStartingSegment = read_uint16(context);
        context->entry.data.bios.BIOSReleaseDate_ = read_uint8(context);
        context->entry.data.bios.BIOSROMSize = read_uint8(context);
        for (size_t i = 0; i < 8; ++i)
            context->entry.data.bios.BIOSCharacteristics[i] = read_uint8(context);

        context->entry.data.bios.Vendor          = smbios_get_string(context, context->entry.data.bios.Vendor_);
        context->entry.data.bios.BIOSVersion     = smbios_get_string(context, context->entry.data.bios.BIOSVersion_);
        context->entry.data.bios.BIOSReleaseDate = smbios_get_string(context, context->entry.data.bios.BIOSReleaseDate_);
    }
    // 2.4+
    if (context->version >= SMBIOS_2_4)
    {
        context->entry.data.bios.ExtensionByte1 = read_uint8(context);
        context->entry.data.bios.ExtensionByte2 = read_uint8(context);
        context->entry.data.bios.SystemBIOSMajorRelease = read_uint8(context);
        context->entry.data.bios.SystemBIOSMinorRelease = read_uint8(context);
        context->entry.data.bios.EmbeddedFirmwareMajorRelease = read_uint8(context);
        context->entry.data.bios.EmbeddedFirmwareMinorRelease = read_uint8(context);
    }
}

static void parse_system_info(struct ParserContext *context)
{
    // 2.0+
    if (context->version >= SMBIOS_2_0)
    {
        context->entry.data.sysinfo.Manufacturer_ = read_uint8(context);
        context->entry.data.sysinfo.ProductName_ = read_uint8(context);
        context->entry.data.sysinfo.Version_ = read_uint8(context);
        context->entry.data.sysinfo.SerialNumber_ = read_uint8(context);

        context->entry.data.sysinfo.Manufacturer = smbios_get_string(context, context->entry.data.sysinfo.Manufacturer_);
        context->entry.data.sysinfo.ProductName  = smbios_get_string(context, context->entry.data.sysinfo.ProductName_);
        context->entry.data.sysinfo.Version = smbios_get_string(context, context->entry.data.sysinfo.Version_);
        context->entry.data.sysinfo.SerialNumber = smbios_get_string(context, context->entry.data.sysinfo.SerialNumber_);
    }
    // 2.1+
    if (context->version >= SMBIOS_2_1)
    {
        for(int i = 0 ; i < 16; ++i)
            context->entry.data.sysinfo.UUID[i] = read_uint8(context);
        context->entry.data.sysinfo.WakeupType = read_uint8(context);
    }
    // 2.4+
    if (context->version >= SMBIOS_2_4)
    {
        context->entry.data.sysinfo.SKUNumber_ = read_uint8(context);
        context->entry.data.sysinfo.Family_ = read_uint8(context);

        context->entry.data.sysinfo.SKUNumber = smbios_get_string(context, context->entry.data.sysinfo.SKUNumber_);
        context->entry.data.sysinfo.Family = smbios_get_string(context, context->entry.data.sysinfo.Family_);
    }
}

static void parse_baseboard_info(struct ParserContext *context)
{
    // 2.0+
    if (context->version >= SMBIOS_2_0)
    {
        context->entry.data.baseboard.Manufacturer_ = read_uint8(context);
        context->entry.data.baseboard.Product_ = read_uint8(context);
        context->entry.data.baseboard.Version_ = read_uint8(context);
        context->entry.data.baseboard.SerialNumber_ = read_uint8(context);
        context->entry.data.baseboard.AssetTag_ = read_uint8(context);
        context->entry.data.baseboard.FeatureFlags = read_uint8(context);
        context->entry.data.baseboard.LocationInChassis_ = read_uint8(context);
        context->entry.data.baseboard.ChassisHandle = read_uint16(context);
        context->entry.data.baseboard.BoardType = read_uint8(context);
        context->entry.data.baseboard.NoOfContainedObjectHandles = read_uint8(context);
        context->entry.data.baseboard.ContainedObjectHandles = (uint16_t*) context->ptr;
        context->ptr += context->entry.data.baseboard.NoOfContainedObjectHandles * sizeof(uint16_t);

        context->entry.data.baseboard.Manufacturer      = smbios_get_string(context, context->entry.data.baseboard.Manufacturer_);
        context->entry.data.baseboard.Product           = smbios_get_string(context, context->entry.data.baseboard.Product_);
        context->entry.data.baseboard.Version           = smbios_get_string(context, context->entry.data.baseboard.Version_);
        context->entry.data.baseboard.SerialNumber      = smbios_get_string(context, context->entry.data.baseboard.SerialNumber_);
        context->entry.data.baseboard.AssetTag          = smbios_get_string(context, context->entry.data.baseboard.AssetTag_);
        context->entry.data.baseboard.LocationInChassis = smbios_get_string(context, context->entry.data.baseboard.LocationInChassis_);
    }
}

static void parse_system_enclosure(struct ParserContext *context)
{
    // 2.0+
    if (context->version >= SMBIOS_2_0)
    {
        context->entry.data.sysenclosure.Manufacturer_ = read_uint8(context);
        context->entry.data.sysenclosure.Type = read_uint8(context);
        context->entry.data.sysenclosure.Version_ = read_uint8(context);
        context->entry.data.sysenclosure.SerialNumber_ = read_uint8(context);
        context->entry.data.sysenclosure.AssetTag_ = read_uint8(context);

        context->entry.data.sysenclosure.Manufacturer = smbios_get_string(context, context->entry.data.sysenclosure.Manufacturer_);
        context->entry.data.sysenclosure.Version      = smbios_get_string(context, context->entry.data.sysenclosure.Version_);
        context->entry.data.sysenclosure.SerialNumber = smbios_get_string(context, context->entry.data.sysenclosure.SerialNumber_);
        context->entry.data.sysenclosure.AssetTag     = smbios_get_string(context, context->entry.data.sysenclosure.AssetTag_);
    }
    // 2.1+
    if (context->version >= SMBIOS_2_1)
    {
        context->entry.data.sysenclosure.BootupState = read_uint8(context);
        context->entry.data.sysenclosure.PowerSupplyState = read_uint8(context);
        context->entry.data.sysenclosure.ThermalState = read_uint8(context);
        context->entry.data.sysenclosure.SecurityStatus = read_uint8(context);
    }
    // 2.3+
    if (context->version >= SMBIOS_2_3)
    {
        context->entry.data.sysenclosure.OEMdefined = read_uint32(context);
        context->entry.data.sysenclosure.Height = read_uint8(context);
        context->entry.data.sysenclosure.NumberOfPowerCords = read_uint8(context);
        context->entry.data.sysenclosure.ContainedElementCount = read_uint8(context);
        context->entry.data.sysenclosure.ContainedElementRecordLength = read_uint8(context);
        context->entry.data.sysenclosure.ContainedElements = context->ptr;
        context->ptr += context->entry.data.sysenclosure.ContainedElementCount * context->entry.data.sysenclosure.ContainedElementRecordLength;
    }
    // 2.7+
    if (context->version >= SMBIOS_2_7)
    {
        context->entry.data.sysenclosure.SKUNumber_ = read_uint8(context);

        context->entry.data.sysenclosure.SKUNumber = smbios_get_string(context, context->entry.data.sysenclosure.SKUNumber_);
    }
}

static void parse_processor_info(struct ParserContext *context)
{
    // 2.0+
    if (context->version >= SMBIOS_2_0)
    {
        context->entry.data.processor.SocketDesignation_ = read_uint8(context);
        context->entry.data.processor.ProcessorType = read_uint8(context);
        context->entry.data.processor.ProcessorFamily = read_uint8(context);
        context->entry.data.processor.ProcessorManufacturer_ = read_uint8(context);
        for(int i = 0 ; i < 8; ++i)
            context->entry.data.processor.ProcessorID[i] = read_uint8(context);
        context->entry.data.processor.ProcessorVersion_ = read_uint8(context);
        context->entry.data.processor.Voltage = read_uint8(context);
        context->entry.data.processor.ExternalClock = read_uint16(context);
        context->entry.data.processor.MaxSpeed = read_uint16(context);
        context->entry.data.processor.CurrentSpeed = read_uint16(context);
        context->entry.data.processor.Status = read_uint8(context);
        context->entry.data.processor.ProcessorUpgrade = read_uint8(context);

        context->entry.data.processor.SocketDesignation     = smbios_get_string(context, context->entry.data.processor.SocketDesignation_);
        context->entry.data.processor.ProcessorManufacturer = smbios_get_string(context, context->entry.data.processor.ProcessorManufacturer_);
        context->entry.data.processor.ProcessorVersion      = smbios_get_string(context, context->entry.data.processor.ProcessorVersion_);
    }
    // 2.1+
    if (context->version >= SMBIOS_2_1)
    {
        context->entry.data.processor.L1CacheHandle = read_uint16(context);
        context->entry.data.processor.L2CacheHandle = read_uint16(context);
        context->entry.data.processor.L3CacheHandle = read_uint16(context);
    }
    // 2.3+
    if (context->version >= SMBIOS_2_3)
    {
        context->entry.data.processor.SerialNumber_ = read_uint8(context);
        context->entry.data.processor.AssetTagNumber_ = read_uint8(context);
        context->entry.data.processor.PartNumber_ = read_uint8(context);

        context->entry.data.processor.SerialNumber = smbios_get_string(context, context->entry.data.processor.SerialNumber_);
        context->entry.data.processor.AssetTagNumber = smbios_get_string(context, context->entry.data.processor.AssetTagNumber_);
        context->entry.data.processor.PartNumber = smbios_get_string(context, context->entry.data.processor.PartNumber_);
    }
    // 2.5+
    if (context->version >= SMBIOS_2_5)
    {
        context->entry.data.processor.CoreCount = read_uint8(context);
        context->entry.data.processor.CoreEnabled = read_uint8(context);
        context->entry.data.processor.ThreadCount = read_uint8(context);
        context->entry.data.processor.ProcessorCharacteristics = read_uint16(context);
    }
    //2.6+
    if (context->version >= SMBIOS_2_6)
    {
        context->entry.data.processor.ProcessorFamily2 = read_uint16(context);
    }
    //3.0+
    if (context->version >= SMBIOS_3_0)
    {
        context->entry.data.processor.CoreCount2 = read_uint16(context);
        context->entry.data.processor.CoreEnabled2 = read_uint16(context);
        context->entry.data.processor.ThreadCount2 = read_uint16(context);
    }
}

static void parse_system_slot(struct ParserContext *context)
{
    // 2.0+
    if (context->version >= SMBIOS_2_0)
    {
        context->entry.data.sysslot.SlotDesignation_ = read_uint8(context);
        context->entry.data.sysslot.SlotType = read_uint8(context);
        context->entry.data.sysslot.SlotDataBusWidth = read_uint8(context);
        context->entry.data.sysslot.CurrentUsage = read_uint8(context);
        context->entry.data.sysslot.SlotLength = read_uint8(context);
        context->entry.data.sysslot.SlotID = read_uint16(context);
        context->entry.data.sysslot.SlotCharacteristics1 = read_uint8(context);

        context->entry.data.sysslot.SlotDesignation = smbios_get_string(context, context->entry.data.sysslot.SlotDesignation_);
    }
    // 2.1+
    if (context->version >= SMBIOS_2_1)
    {
        context->entry.data.sysslot.SlotCharacteristics2 = read_uint8(context);
    }
    // 2.6+
    if (context->version >= SMBIOS_2_6)
    {
        context->entry.data.sysslot.SegmentGroupNumber = read_uint16(context);
        context->entry.data.sysslot.BusNumber = read_uint8(context);
        context->entry.data.sysslot.DeviceOrFunctionNumber = read_uint8(context);
    }
}

static void parse_physical_memory_array(struct ParserContext *context)
{
    // 2.1+
    if (context->version >= SMBIOS_2_1)
    {
        context->entry.data.physmem.Location = read_uint8(context);
        context->entry.data.physmem.Use = read_uint8(context);
        context->entry.data.physmem.ErrorCorrection = read_uint8(context);
        context->entry.data.physmem.MaximumCapacity = read_uint32(context);
        context->entry.data.physmem.ErrorInformationHandle = read_uint16(context);
        context->entry.data.physmem.NumberDevices = read_uint16(context);
    }
    // 2.7+
    if (context->version >= SMBIOS_2_7)
    {
        context->entry.data.physmem.ExtendedMaximumCapacity = read_uint64(context);
    }
}

static void parse_memory_device(struct ParserContext *context)
{
    // 2.1+
    if (context->version >= SMBIOS_2_1)
    {
        context->entry.data.memory.PhysicalArrayHandle = read_uint16(context);
        context->entry.data.memory.ErrorInformationHandle = read_uint16(context);
        context->entry.data.memory.TotalWidth = read_uint16(context);
        context->entry.data.memory.DataWidth = read_uint16(context);
        context->entry.data.memory.Size = read_uint16(context);
        context->entry.data.memory.FormFactor = read_uint8(context);
        context->entry.data.memory.DeviceSet = read_uint8(context);
        context->entry.data.memory.DeviceLocator_ = read_uint8(context);
        context->entry.data.memory.BankLocator_ = read_uint8(context);
        context->entry.data.memory.MemoryType = read_uint8(context);
        context->entry.data.memory.TypeDetail = read_uint16(context);

        context->entry.data.memory.DeviceLocator  = smbios_get_string(context, context->entry.data.memory.DeviceLocator_);
        context->entry.data.memory.BankLocator    = smbios_get_string(context, context->entry.data.memory.BankLocator_);
    }
    // 2.3+
    if (context->version >= SMBIOS_2_3)
    {
        context->entry.data.memory.Speed = read_uint16(context);
        context->entry.data.memory.Manufacturer_ = read_uint8(context);
        context->entry.data.memory.SerialNumber_ = read_uint8(context);
        context->entry.data.memory.AssetTagNumber_ = read_uint8(context);
        context->entry.data.memory.PartNumber_ = read_uint8(context);

        context->entry.data.memory.Manufacturer   = smbios_get_string(context, context->entry.data.memory.Manufacturer_);
        context->entry.data.memory.SerialNumber   = smbios_get_string(context, context->entry.data.memory.SerialNumber_);
        context->entry.data.memory.AssetTagNumber = smbios_get_string(context, context->entry.data.memory.AssetTagNumber_);
        context->entry.data.memory.PartNumber     = smbios_get_string(context, context->entry.data.memory.PartNumber_);
    }
    // 2.6+
    if (context->version >= SMBIOS_2_6)
    {
        context->entry.data.memory.Attributes = read_uint8(context);
    }
    // 2.7+
    if (context->version >= SMBIOS_2_7)
    {
        context->entry.data.memory.ExtendedSize = read_uint32(context);
        context->entry.data.memory.ConfiguredClockSpeed = read_uint16(context);
    }
    // 2.8+
    if (context->version >= SMBIOS_2_8)
    {
        context->entry.data.memory.MinimumVoltage = read_uint16(context);
        context->entry.data.memory.MaximumVoltage = read_uint16(context);
        context->entry.data.memory.ConfiguredVoltage = read_uint16(context);
    }
}

static void parse_oem_strings(struct ParserContext *context)
{
    // 2.0+
    if (context->version >= SMBIOS_2_0)
    {
        context->entry.data.oemstrings.Count = read_uint8(context);
        context->entry.data.oemstrings.Values = (const char*) context->ptr;
    }
}

static void parse_port_connector(struct ParserContext *context)
{
    // 2.0+
    if (context->version >= SMBIOS_2_0)
    {
        context->entry.data.portconn.InternalReferenceDesignator_ = read_uint8(context);
        context->entry.data.portconn.InternalConnectorType = read_uint8(context);
        context->entry.data.portconn.ExternalReferenceDesignator_ = read_uint8(context);
        context->entry.data.portconn.ExternalConnectorType = read_uint8(context);
        context->entry.data.portconn.PortType = read_uint8(context);

        context->entry.data.portconn.ExternalReferenceDesignator = smbios_get_string(context, context->entry.data.portconn.ExternalReferenceDesignator_);
        context->entry.data.portconn.InternalReferenceDesignator = smbios_get_string(context, context->entry.data.portconn.InternalReferenceDesignator_);
    }
}

static void parse_memory_array_mapped_address(struct ParserContext *context)
{
    if (context->version >= SMBIOS_2_1)
    {
        context->entry.data.mamaddr.StartingAddress = read_uint32(context);
        context->entry.data.mamaddr.EndingAddress = read_uint32(context);
        context->entry.data.mamaddr.MemoryArrayHandle = read_uint16(context);
        context->entry.data.mamaddr.PartitionWidth = read_uint8(context);
    }
    if (context->version >= SMBIOS_2_7)
    {
        context->entry.data.mamaddr.ExtendedStartingAddress = read_uint64(context);
        context->entry.data.mamaddr.ExtendedEndingAddress = read_uint64(context);
    }
}

static void parse_memory_device_mapped_address(struct ParserContext *context)
{
    if (context->version >= SMBIOS_2_1)
    {
        context->entry.data.mdmaddr.StartingAddress = read_uint32(context);
        context->entry.data.mdmaddr.EndingAddress = read_uint32(context);
        context->entry.data.mdmaddr.MemoryDeviceHandle = read_uint16(context);
        context->entry.data.mdmaddr.MemoryArrayMappedAddressHandle = read_uint16(context);
        context->entry.data.mdmaddr.PartitionRowPosition = read_uint8(context);
        context->entry.data.mdmaddr.InterleavePosition = read_uint8(context);
        context->entry.data.mdmaddr.InterleavedDataDepth = read_uint8(context);
    }
    if (context->version >= SMBIOS_2_7)
    {
        context->entry.data.mdmaddr.ExtendedStartingAddress = read_uint64(context);
        context->entry.data.mdmaddr.ExtendedEndingAddress = read_uint64(context);
    }
}


static void parse_system_boot_info(struct ParserContext *context)
{
    if (context->version >= SMBIOS_2_0)
    {
        context->ptr += sizeof(context->entry.data.bootinfo.Reserved);
        context->entry.data.bootinfo.BootStatus = context->ptr;
    }
}

static void parse_management_device(struct ParserContext *context)
{
    if (context->version >= SMBIOS_2_0)
    {
        context->entry.data.mdev.Description_ = read_uint8(context);
        context->entry.data.mdev.Type = read_uint8(context);
        context->entry.data.mdev.Address = read_uint32(context);
        context->entry.data.mdev.AddressType = read_uint8(context);

        context->entry.data.mdev.Description = smbios_get_string(context, context->entry.data.mdev.Description_);
    }
}

static void parse_management_device_component(struct ParserContext *context)
{
    if (context->version >= SMBIOS_2_0)
    {
        context->entry.data.mdcom.Description_ = read_uint8(context);
        context->entry.data.mdcom.ManagementDeviceHandle = read_uint16(context);
        context->entry.data.mdcom.ComponentHandle = read_uint16(context);
        context->entry.data.mdcom.ThresholdHandle = read_uint16(context);

        context->entry.data.mdev.Description = smbios_get_string(context, context->entry.data.mdev.Description_);
    }
}

static void parse_management_device_threshold_data(struct ParserContext *context)
{
    if (context->version >= SMBIOS_2_0)
    {
        context->entry.data.mdtdata.LowerThresholdNonCritical = read_uint16(context);
        context->entry.data.mdtdata.UpperThresholdNonCritical = read_uint16(context);
        context->entry.data.mdtdata.LowerThresholdCritical = read_uint16(context);
        context->entry.data.mdtdata.UpperThresholdCritical = read_uint16(context);
        context->entry.data.mdtdata.LowerThresholdNonRecoverable = read_uint16(context);
        context->entry.data.mdtdata.UpperThresholdNonRecoverable = read_uint16(context);
    }
}


static void parse_onboard_devices_extended_info(struct ParserContext *context)
{
    if (context->version >= SMBIOS_2_0)
    {
        context->entry.data.odeinfo.ReferenceDesignation_ = read_uint8(context);
        context->entry.data.odeinfo.DeviceType = read_uint8(context);
        context->entry.data.odeinfo.DeviceTypeInstance = read_uint8(context);
        context->entry.data.odeinfo.SegmentGroupNumber = read_uint16(context);
        context->entry.data.odeinfo.BusNumber = read_uint8(context);
        context->entry.data.odeinfo.DeviceOrFunctionNumber = read_uint8(context);

        context->entry.data.odeinfo.ReferenceDesignation = smbios_get_string(context, context->entry.data.odeinfo.ReferenceDesignation_);
    }
}

static int parse_entry(struct ParserContext *context, const struct Entry **entry)
{
    if (entry == NULL)
        return SMBERR_INVALID_ARGUMENT;
    if (context->failed)
        return SMBERR_INVALID_DATA;

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
    if (context->data == NULL)
        return SMBERR_INVALID_DATA;

    // jump to the next field
    if (context->estart == NULL)
        context->estart = context->ptr = context->data;
    else
        context->estart = context->ptr = context->eend;

    memset(&context->entry, 0, sizeof(context->entry));

    if (context->estart + DMI_ENTRY_HEADER_SIZE >= context->data + context->size)
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

int smbios_get_version(struct ParserContext *context)
{
    return context->version;
}

#ifdef _cplusplus
} // namespace smbios
#endif
