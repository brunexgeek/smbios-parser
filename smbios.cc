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

#include "smbios.hh"
#include <vector>
#include <stdio.h>

#define DMI_READ_8U    *context->ptr++
#define DMI_READ_16U   *((uint16_t*)context->ptr), context->ptr += 2
#define DMI_READ_32U   *((uint32_t*)context->ptr), context->ptr += 4
#define DMI_READ_64U   *((uint64_t*)context->ptr), context->ptr += 8
#define DMI_ENTRY_HEADER_SIZE   4
#define VALID_VERSION(x) (((x) >= SMBIOS_2_0 && (x) <= SMBIOS_2_8) || (x) == SMBIOS_3_0)

namespace smbios {

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

int smbios_initialize(ParserContext *context, const uint8_t *data, size_t size, int version )
{
    // we need at least the smbios header for now
    if (size < 32)
        return SMBERR_INVALID_SMBIOS_DATA;

    memset(context, 0, sizeof(ParserContext));
    context->data  = data + 32;
    context->size = size,
    context->ptr = nullptr;
    context->version = VALID_VERSION(version) ? SMBIOS_3_0 : version;
    int vn = 0;

    // we have a valid SMBIOS entry point?
    #ifndef _WIN32
    if (data[0] == '_' && data[1] == 'S' && data[2] == 'M' && data[3] == '_')
    {
        // version 2.x

        // entry point length
        if (data[5] != 0x1F)
            return SMBERR_INVALID_SMBIOS_DATA;
        // entry point revision
        if (data[10] != 0)
            return SMBERR_INVALID_SMBIOS_DATA;
        // intermediate anchor string
        if (data[16] != '_' || data[17] != 'D' || data[18] != 'M' || data[19] != 'I' || data[20] != '_')
            return SMBERR_INVALID_SMBIOS_DATA;

        // get the SMBIOS version
        vn = data[6] << 8 | data[7];
    }
    else
    if (data[0] == '_' && data[1] == 'S' && data[2] == 'M' && data[3] == '3' && data[4] == '_')
    {
        // version 3.x

        // entry point length
        if (data[6] != 0x18)
            return SMBERR_INVALID_SMBIOS_DATA;
        // entry point revision
        if (data[10] != 0x01)
            return SMBERR_INVALID_SMBIOS_DATA;

        // get the SMBIOS version
        vn = data[7] << 8 | data[8];
    }
    else
        return SMBERR_INVALID_SMBIOS_DATA;
    #else
    RawSMBIOSData *smBiosData = nullptr;
    smBiosData = (RawSMBIOSData *) data;

    // get the SMBIOS version
    vn = smBiosData->SMBIOSMajorVersion << 8 | smBiosData->SMBIOSMinorVersion;
    data_ = smBiosData->SMBIOSTableData;
    size_ = smBiosData->Length;
    #endif

    if (!VALID_VERSION(vn))
        return SMBERR_INVALID_SMBIOS_DATA;
    if (context->version > vn)
        context->version = vn;

    return SMBERR_OK;
}

const char *smbios_get_string( ParserContext *context, int index )
{
    if (index <= 0) return "";

    const char *ptr = (const char*) context->start + (size_t) context->entry.length - DMI_ENTRY_HEADER_SIZE;
    for (int i = 1; *ptr != 0 && i < index; ++i)
    {
        // TODO: check buffer limits
        while (*ptr != 0) ++ptr;
        ++ptr;
    }
    return ptr;
}

void smbios_reset( ParserContext *context )
{
    context->ptr = context->start = nullptr;
}

int smbios_parse(ParserContext *context, const Entry **entry);

int smbios_next(ParserContext *context, const Entry **entry)
{
    if (context->data == nullptr || entry == nullptr)
        return SMBERR_INVALID_ARGUMENT;

    // jump to the next field
    if (context->ptr == nullptr)
        context->ptr = context->start = context->data;
    else
    {
        context->ptr = context->start + context->entry.length - DMI_ENTRY_HEADER_SIZE;
        while (context->ptr < context->data + context->size - 1 && !(context->ptr[0] == 0 && context->ptr[1] == 0)) ++context->ptr;
        context->ptr += 2;
        if (context->ptr >= context->data + context->size)
        {
            context->ptr = context->start = nullptr;
            return SMBERR_END_OF_STREAM;
        }
    }

    memset(&context->entry, 0, sizeof(context->entry));

    // entry header
    context->entry.type = DMI_READ_8U;
    context->entry.length = DMI_READ_8U;
    context->entry.handle = DMI_READ_16U;
    context->entry.rawdata = context->ptr - 4;
    context->entry.strings = (const char *) context->entry.rawdata + context->entry.length;
    context->start = context->ptr;

    if (context->entry.type == 127)
    {
        smbios_reset(context);
        return SMBERR_END_OF_STREAM;
    }

    return smbios_parse(context, entry);
}

int smbios_parse(ParserContext *context, const Entry **entry)
{
    if (entry == nullptr)
        return SMBERR_INVALID_ARGUMENT;

    bool error = false;

    if (context->entry.type == TYPE_BIOS_INFO)
    {
        // 2.0+
        if (context->version >= SMBIOS_2_0)
        {
            context->entry.data.bios.Vendor_ = DMI_READ_8U;
            context->entry.data.bios.BIOSVersion_ = DMI_READ_8U;
            context->entry.data.bios.BIOSStartingSegment = DMI_READ_16U;
            context->entry.data.bios.BIOSReleaseDate_ = DMI_READ_8U;
            context->entry.data.bios.BIOSROMSize = DMI_READ_8U;
            for (size_t i = 0; i < 8; ++i)
                context->entry.data.bios.BIOSCharacteristics[i] = DMI_READ_8U;

            context->entry.data.bios.Vendor          = smbios_get_string(context, context->entry.data.bios.Vendor_);
            context->entry.data.bios.BIOSVersion     = smbios_get_string(context, context->entry.data.bios.BIOSVersion_);
            context->entry.data.bios.BIOSReleaseDate = smbios_get_string(context, context->entry.data.bios.BIOSReleaseDate_);
        }
        // 2.4+
        if (context->version >= SMBIOS_2_4)
        {
            context->entry.data.bios.ExtensionByte1 = DMI_READ_8U;
            context->entry.data.bios.ExtensionByte2 = DMI_READ_8U;
            context->entry.data.bios.SystemBIOSMajorRelease = DMI_READ_8U;
            context->entry.data.bios.SystemBIOSMinorRelease = DMI_READ_8U;
            context->entry.data.bios.EmbeddedFirmwareMajorRelease = DMI_READ_8U;
            context->entry.data.bios.EmbeddedFirmwareMinorRelease = DMI_READ_8U;
        }
    }
    else
    if (context->entry.type == TYPE_SYSTEM_INFO)
    {
        // 2.0+
        if (context->version >= SMBIOS_2_0)
        {
            context->entry.data.sysinfo.Manufacturer_ = DMI_READ_8U;
            context->entry.data.sysinfo.ProductName_ = DMI_READ_8U;
            context->entry.data.sysinfo.Version_ = DMI_READ_8U;
            context->entry.data.sysinfo.SerialNumber_ = DMI_READ_8U;

            context->entry.data.sysinfo.Manufacturer = smbios_get_string(context, context->entry.data.sysinfo.Manufacturer_);
            context->entry.data.sysinfo.ProductName  = smbios_get_string(context, context->entry.data.sysinfo.ProductName_);
            context->entry.data.sysinfo.Version = smbios_get_string(context, context->entry.data.sysinfo.Version_);
            context->entry.data.sysinfo.SerialNumber = smbios_get_string(context, context->entry.data.sysinfo.SerialNumber_);
        }
        // 2.1+
        if (context->version >= SMBIOS_2_1)
        {
            for(int i = 0 ; i < 16; ++i)
                context->entry.data.sysinfo.UUID[i] = DMI_READ_8U;
            context->entry.data.sysinfo.WakeupType = DMI_READ_8U;
        }
        // 2.4+
        if (context->version >= SMBIOS_2_4)
        {
            context->entry.data.sysinfo.SKUNumber_ = DMI_READ_8U;
            context->entry.data.sysinfo.Family_ = DMI_READ_8U;

            context->entry.data.sysinfo.SKUNumber = smbios_get_string(context, context->entry.data.sysinfo.SKUNumber_);
            context->entry.data.sysinfo.Family = smbios_get_string(context, context->entry.data.sysinfo.Family_);
        }
    }
    else
    if (context->entry.type == TYPE_BASEBOARD_INFO)
    {
        // 2.0+
        if (context->version >= SMBIOS_2_0)
        {
            context->entry.data.baseboard.Manufacturer_ = DMI_READ_8U;
            context->entry.data.baseboard.Product_ = DMI_READ_8U;
            context->entry.data.baseboard.Version_ = DMI_READ_8U;
            context->entry.data.baseboard.SerialNumber_ = DMI_READ_8U;
            context->entry.data.baseboard.AssetTag_ = DMI_READ_8U;
            context->entry.data.baseboard.FeatureFlags = DMI_READ_8U;
            context->entry.data.baseboard.LocationInChassis_ = DMI_READ_8U;
            context->entry.data.baseboard.ChassisHandle = DMI_READ_16U;
            context->entry.data.baseboard.BoardType = DMI_READ_8U;
            context->entry.data.baseboard.NoOfContainedObjectHandles = DMI_READ_8U;
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
    else
    if (context->entry.type == TYPE_SYSTEM_ENCLOSURE)
    {
        // 2.0+
        if (context->version >= SMBIOS_2_0)
        {
            context->entry.data.sysenclosure.Manufacturer_ = DMI_READ_8U;
            context->entry.data.sysenclosure.Type = DMI_READ_8U;
            context->entry.data.sysenclosure.Version_ = DMI_READ_8U;
            context->entry.data.sysenclosure.SerialNumber_ = DMI_READ_8U;
            context->entry.data.sysenclosure.AssetTag_ = DMI_READ_8U;

            context->entry.data.sysenclosure.Manufacturer = smbios_get_string(context, context->entry.data.sysenclosure.Manufacturer_);
            context->entry.data.sysenclosure.Version      = smbios_get_string(context, context->entry.data.sysenclosure.Version_);
            context->entry.data.sysenclosure.SerialNumber = smbios_get_string(context, context->entry.data.sysenclosure.SerialNumber_);
            context->entry.data.sysenclosure.AssetTag     = smbios_get_string(context, context->entry.data.sysenclosure.AssetTag_);
        }
        // 2.1+
        if (context->version >= SMBIOS_2_1)
        {
            context->entry.data.sysenclosure.BootupState = DMI_READ_8U;
            context->entry.data.sysenclosure.PowerSupplyState = DMI_READ_8U;
            context->entry.data.sysenclosure.ThermalState = DMI_READ_8U;
            context->entry.data.sysenclosure.SecurityStatus = DMI_READ_8U;
        }
        // 2.3+
        if (context->version >= SMBIOS_2_3)
        {
            context->entry.data.sysenclosure.OEMdefined = DMI_READ_32U;
            context->entry.data.sysenclosure.Height = DMI_READ_8U;
            context->entry.data.sysenclosure.NumberOfPowerCords = DMI_READ_8U;
            context->entry.data.sysenclosure.ContainedElementCount = DMI_READ_8U;
            context->entry.data.sysenclosure.ContainedElementRecordLength = DMI_READ_8U;
            context->entry.data.sysenclosure.ContainedElements = context->ptr;
            context->ptr += context->entry.data.sysenclosure.ContainedElementCount * context->entry.data.sysenclosure.ContainedElementRecordLength;
        }
        // 2.7+
        if (context->version >= SMBIOS_2_7)
        {
            context->entry.data.sysenclosure.SKUNumber_ = DMI_READ_8U;

            context->entry.data.sysenclosure.SKUNumber = smbios_get_string(context, context->entry.data.sysenclosure.SKUNumber_);
        }
    }
    if (context->entry.type == TYPE_PROCESSOR_INFO)
    {
        // 2.0+
        if (context->version >= smbios::SMBIOS_2_0)
        {
            context->entry.data.processor.SocketDesignation_ = DMI_READ_8U;
            context->entry.data.processor.ProcessorType = DMI_READ_8U;
            context->entry.data.processor.ProcessorFamily = DMI_READ_8U;
            context->entry.data.processor.ProcessorManufacturer_ = DMI_READ_8U;
            for(int i = 0 ; i < 8; ++i)
                context->entry.data.processor.ProcessorID[i] = DMI_READ_8U;
            context->entry.data.processor.ProcessorVersion_ = DMI_READ_8U;
            context->entry.data.processor.Voltage = DMI_READ_8U;
            context->entry.data.processor.ExternalClock = DMI_READ_16U;
            context->entry.data.processor.MaxSpeed = DMI_READ_16U;
            context->entry.data.processor.CurrentSpeed = DMI_READ_16U;
            context->entry.data.processor.Status = DMI_READ_8U;
            context->entry.data.processor.ProcessorUpgrade = DMI_READ_8U;

            context->entry.data.processor.SocketDesignation     = smbios_get_string(context, context->entry.data.processor.SocketDesignation_);
            context->entry.data.processor.ProcessorManufacturer = smbios_get_string(context, context->entry.data.processor.ProcessorManufacturer_);
            context->entry.data.processor.ProcessorVersion      = smbios_get_string(context, context->entry.data.processor.ProcessorVersion_);
        }
        // 2.1+
        if (context->version >= smbios::SMBIOS_2_1)
        {
            context->entry.data.processor.L1CacheHandle = DMI_READ_16U;
            context->entry.data.processor.L2CacheHandle = DMI_READ_16U;
            context->entry.data.processor.L3CacheHandle = DMI_READ_16U;
        }
        // 2.3+
        if (context->version >= smbios::SMBIOS_2_3)
        {
            context->entry.data.processor.SerialNumber_ = DMI_READ_8U;
            context->entry.data.processor.AssetTagNumber_ = DMI_READ_8U;
            context->entry.data.processor.PartNumber_ = DMI_READ_8U;

            context->entry.data.processor.SerialNumber = smbios_get_string(context, context->entry.data.processor.SerialNumber_);
            context->entry.data.processor.AssetTagNumber = smbios_get_string(context, context->entry.data.processor.AssetTagNumber_);
            context->entry.data.processor.PartNumber = smbios_get_string(context, context->entry.data.processor.PartNumber_);
        }
        // 2.5+
        if (context->version >= smbios::SMBIOS_2_5)
        {
            context->entry.data.processor.CoreCount = DMI_READ_8U;
            context->entry.data.processor.CoreEnabled = DMI_READ_8U;
            context->entry.data.processor.ThreadCount = DMI_READ_8U;
            context->entry.data.processor.ProcessorCharacteristics = DMI_READ_16U;
        }
        //2.6+
        if (context->version >= smbios::SMBIOS_2_6)
        {
            context->entry.data.processor.ProcessorFamily2 = DMI_READ_16U;
        }
        //3.0+
        if (context->version >= smbios::SMBIOS_3_0)
        {
            context->entry.data.processor.CoreCount2 = DMI_READ_16U;
            context->entry.data.processor.CoreEnabled2 = DMI_READ_16U;
            context->entry.data.processor.ThreadCount2 = DMI_READ_16U;
        }
    }
    else
    if (context->entry.type == TYPE_SYSTEM_SLOT)
    {
        // 2.0+
        if (context->version >= smbios::SMBIOS_2_0)
        {
            context->entry.data.sysslot.SlotDesignation_ = DMI_READ_8U;
            context->entry.data.sysslot.SlotType = DMI_READ_8U;
            context->entry.data.sysslot.SlotDataBusWidth = DMI_READ_8U;
            context->entry.data.sysslot.CurrentUsage = DMI_READ_8U;
            context->entry.data.sysslot.SlotLength = DMI_READ_8U;
            context->entry.data.sysslot.SlotID = DMI_READ_16U;
            context->entry.data.sysslot.SlotCharacteristics1 = DMI_READ_8U;

            context->entry.data.sysslot.SlotDesignation = smbios_get_string(context, context->entry.data.sysslot.SlotDesignation_);
        }
        // 2.1+
        if (context->version >= smbios::SMBIOS_2_1)
        {
            context->entry.data.sysslot.SlotCharacteristics2 = DMI_READ_8U;
        }
        // 2.6+
        if (context->version >= smbios::SMBIOS_2_6)
        {
            context->entry.data.sysslot.SegmentGroupNumber = DMI_READ_16U;
            context->entry.data.sysslot.BusNumber = DMI_READ_8U;
            context->entry.data.sysslot.DeviceOrFunctionNumber = DMI_READ_8U;
        }
    }
    else
    if (context->entry.type == TYPE_PHYSICAL_MEMORY_ARRAY)
    {
        // 2.1+
        if (context->version >= smbios::SMBIOS_2_1)
        {
            context->entry.data.physmem.Location = DMI_READ_8U;
            context->entry.data.physmem.Use = DMI_READ_8U;
            context->entry.data.physmem.ErrorCorrection = DMI_READ_8U;
            context->entry.data.physmem.MaximumCapacity = DMI_READ_32U;
            context->entry.data.physmem.ErrorInformationHandle = DMI_READ_16U;
            context->entry.data.physmem.NumberDevices = DMI_READ_16U;
        }
        // 2.7+
        if (context->version >= smbios::SMBIOS_2_7)
        {
            context->entry.data.physmem.ExtendedMaximumCapacity = DMI_READ_64U;
        }
    }
    else
    if (context->entry.type == TYPE_MEMORY_DEVICE)
    {
        // 2.1+
        if (context->version >= smbios::SMBIOS_2_1)
        {
            context->entry.data.memory.PhysicalArrayHandle = DMI_READ_16U;
            context->entry.data.memory.ErrorInformationHandle = DMI_READ_16U;
            context->entry.data.memory.TotalWidth = DMI_READ_16U;
            context->entry.data.memory.DataWidth = DMI_READ_16U;
            context->entry.data.memory.Size = DMI_READ_16U;
            context->entry.data.memory.FormFactor = DMI_READ_8U;
            context->entry.data.memory.DeviceSet = DMI_READ_8U;
            context->entry.data.memory.DeviceLocator_ = DMI_READ_8U;
            context->entry.data.memory.BankLocator_ = DMI_READ_8U;
            context->entry.data.memory.MemoryType = DMI_READ_8U;
            context->entry.data.memory.TypeDetail = DMI_READ_16U;

            context->entry.data.memory.DeviceLocator  = smbios_get_string(context, context->entry.data.memory.DeviceLocator_);
            context->entry.data.memory.BankLocator    = smbios_get_string(context, context->entry.data.memory.BankLocator_);
        }
        // 2.3+
        if (context->version >= smbios::SMBIOS_2_3)
        {
            context->entry.data.memory.Speed = DMI_READ_16U;
            context->entry.data.memory.Manufacturer_ = DMI_READ_8U;
            context->entry.data.memory.SerialNumber_ = DMI_READ_8U;
            context->entry.data.memory.AssetTagNumber_ = DMI_READ_8U;
            context->entry.data.memory.PartNumber_ = DMI_READ_8U;

            context->entry.data.memory.Manufacturer   = smbios_get_string(context, context->entry.data.memory.Manufacturer_);
            context->entry.data.memory.SerialNumber   = smbios_get_string(context, context->entry.data.memory.SerialNumber_);
            context->entry.data.memory.AssetTagNumber = smbios_get_string(context, context->entry.data.memory.AssetTagNumber_);
            context->entry.data.memory.PartNumber     = smbios_get_string(context, context->entry.data.memory.PartNumber_);
        }
        // 2.6+
        if (context->version >= smbios::SMBIOS_2_6)
        {
            context->entry.data.memory.Attributes = DMI_READ_8U;
        }
        // 2.7+
        if (context->version >= smbios::SMBIOS_2_7)
        {
            context->entry.data.memory.ExtendedSize = DMI_READ_32U;
            context->entry.data.memory.ConfiguredClockSpeed = DMI_READ_16U;
        }
        // 2.8+
        if (context->version >= smbios::SMBIOS_2_8)
        {
            context->entry.data.memory.MinimumVoltage = DMI_READ_16U;
            context->entry.data.memory.MaximumVoltage = DMI_READ_16U;
            context->entry.data.memory.ConfiguredVoltage = DMI_READ_16U;
        }
    }
    else
    if (context->entry.type == TYPE_OEM_STRINGS)
    {
        // 2.0+
        if (context->version >= smbios::SMBIOS_2_0)
        {
            context->entry.data.oemstrings.Count = DMI_READ_8U;
            context->entry.data.oemstrings.Values = (const char*) context->ptr;
        }
    }
    else
    if (context->entry.type == TYPE_PORT_CONNECTOR)
    {
        // 2.0+
        if (context->version >= smbios::SMBIOS_2_0)
        {
            context->entry.data.portconn.InternalReferenceDesignator_ = DMI_READ_8U;
            context->entry.data.portconn.InternalConnectorType = DMI_READ_8U;
            context->entry.data.portconn.ExternalReferenceDesignator_ = DMI_READ_8U;
            context->entry.data.portconn.ExternalConnectorType = DMI_READ_8U;
            context->entry.data.portconn.PortType = DMI_READ_8U;

            context->entry.data.portconn.ExternalReferenceDesignator = smbios_get_string(context, context->entry.data.portconn.ExternalReferenceDesignator_);
            context->entry.data.portconn.InternalReferenceDesignator = smbios_get_string(context, context->entry.data.portconn.InternalReferenceDesignator_);
        }
    }
    else
    if (context->entry.type == TYPE_MEMORY_ARRAY_MAPPED_ADDRESS)
    {
        if (context->version >= smbios::SMBIOS_2_1)
        {
            context->entry.data.mamaddr.StartingAddress = DMI_READ_32U;
            context->entry.data.mamaddr.EndingAddress = DMI_READ_32U;
            context->entry.data.mamaddr.MemoryArrayHandle = DMI_READ_16U;
            context->entry.data.mamaddr.PartitionWidth = DMI_READ_8U;
        }
        if (context->version >= smbios::SMBIOS_2_7)
        {
            context->entry.data.mamaddr.ExtendedStartingAddress = DMI_READ_64U;
            context->entry.data.mamaddr.ExtendedEndingAddress = DMI_READ_64U;
        }
    }
    else
    if (context->entry.type == TYPE_MEMORY_DEVICE_MAPPED_ADDRESS)
    {
        if (context->version >= smbios::SMBIOS_2_1)
        {
            context->entry.data.mdmaddr.StartingAddress = DMI_READ_32U;
            context->entry.data.mdmaddr.EndingAddress = DMI_READ_32U;
            context->entry.data.mdmaddr.MemoryDeviceHandle = DMI_READ_16U;
            context->entry.data.mdmaddr.MemoryArrayMappedAddressHandle = DMI_READ_16U;
            context->entry.data.mdmaddr.PartitionRowPosition = DMI_READ_8U;
            context->entry.data.mdmaddr.InterleavePosition = DMI_READ_8U;
            context->entry.data.mdmaddr.InterleavedDataDepth = DMI_READ_8U;
        }
        if (context->version >= smbios::SMBIOS_2_7)
        {
            context->entry.data.mdmaddr.ExtendedStartingAddress = DMI_READ_64U;
            context->entry.data.mdmaddr.ExtendedEndingAddress = DMI_READ_64U;
        }
    }
    else
    if (context->entry.type == TYPE_SYSTEM_BOOT_INFO)
    {
        if (context->version >= smbios::SMBIOS_2_0)
        {
            context->ptr += sizeof(context->entry.data.bootinfo.Reserved);
            context->entry.data.bootinfo.BootStatus = context->ptr;
        }
    }
    else
    if (context->entry.type == TYPE_MANAGEMENT_DEVICE)
    {
        if (context->version >= smbios::SMBIOS_2_0)
        {
            context->entry.data.mdev.Description_ = DMI_READ_8U;
            context->entry.data.mdev.Type = DMI_READ_8U;
            context->entry.data.mdev.Address = DMI_READ_32U;
            context->entry.data.mdev.AddressType = DMI_READ_8U;

            context->entry.data.mdev.Description = smbios_get_string(context, context->entry.data.mdev.Description_);
        }
    }
    else
    if (context->entry.type == TYPE_MANAGEMENT_DEVICE_COMPONENT)
    {
        if (context->version >= smbios::SMBIOS_2_0)
        {
            context->entry.data.mdcom.Description_ = DMI_READ_8U;
            context->entry.data.mdcom.ManagementDeviceHandle = DMI_READ_16U;
            context->entry.data.mdcom.ComponentHandle = DMI_READ_16U;
            context->entry.data.mdcom.ThresholdHandle = DMI_READ_16U;

            context->entry.data.mdev.Description = smbios_get_string(context, context->entry.data.mdev.Description_);
        }
    }
    else
    if (context->entry.type == TYPE_MANAGEMENT_DEVICE_THRESHOLD_DATA)
    {
        if (context->version >= smbios::SMBIOS_2_0)
        {
            context->entry.data.mdtdata.LowerThresholdNonCritical = DMI_READ_16U;
            context->entry.data.mdtdata.UpperThresholdNonCritical = DMI_READ_16U;
            context->entry.data.mdtdata.LowerThresholdCritical = DMI_READ_16U;
            context->entry.data.mdtdata.UpperThresholdCritical = DMI_READ_16U;
            context->entry.data.mdtdata.LowerThresholdNonRecoverable = DMI_READ_16U;
            context->entry.data.mdtdata.UpperThresholdNonRecoverable = DMI_READ_16U;
        }
    }
    else
    if (context->entry.type == TYPE_ONBOARD_DEVICES_EXTENDED_INFO)
    {
        if (context->version >= smbios::SMBIOS_2_0)
        {
            context->entry.data.odeinfo.ReferenceDesignation_ = DMI_READ_8U;
            context->entry.data.odeinfo.DeviceType = DMI_READ_8U;
            context->entry.data.odeinfo.DeviceTypeInstance = DMI_READ_8U;
            context->entry.data.odeinfo.SegmentGroupNumber = DMI_READ_16U;
            context->entry.data.odeinfo.BusNumber = DMI_READ_8U;
            context->entry.data.odeinfo.DeviceOrFunctionNumber = DMI_READ_8U;

            context->entry.data.odeinfo.ReferenceDesignation = smbios_get_string(context, context->entry.data.odeinfo.ReferenceDesignation_);
        }
    }

    *entry = &context->entry;
    return SMBERR_OK;
}

int smbios_get_version(ParserContext *context)
{
    return context->version;
}

bool smbios_valid(ParserContext *context)
{
    return context->data != nullptr;
}


} // namespace smbios
