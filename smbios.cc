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

#define DMI_READ_8U    *ptr_++
#define DMI_READ_16U   *((uint16_t*)ptr_), ptr_ += 2
#define DMI_READ_32U   *((uint32_t*)ptr_), ptr_ += 4
#define DMI_READ_64U   *((uint64_t*)ptr_), ptr_ += 8
#define DMI_ENTRY_HEADER_SIZE   4

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

Parser::Parser( const uint8_t *data, size_t size, int version ) : data_(data + 32), size_(size),
    ptr_(NULL), version_(version)
{
    int vn = 0;

    // we have a valid SMBIOS entry point?
    #ifndef _WIN32
    if (data[0] == '_' && data[1] == 'S' && data[2] == 'M' && data[3] == '_')
    {
        // version 2.x

        // entry point length
        if (data[5] != 0x1F) goto INVALID_DATA;
        // entry point revision
        if (data[10] != 0) goto INVALID_DATA;
        // intermediate anchor string
        if (data[16] != '_' || data[17] != 'D' || data[18] != 'M' || data[19] != 'I' || data[20] != '_') goto INVALID_DATA;

        // get the SMBIOS version
        vn = data[6] << 8 | data[7];
    }
    else
    if (data[0] == '_' && data[1] == 'S' && data[2] == 'M' && data[3] == '3' && data[4] == '_')
    {
        // version 3.x

        // entry point length
        if (data[6] != 0x18) goto INVALID_DATA;
        // entry point revision
        if (data[10] != 0x01) goto INVALID_DATA;

        // get the SMBIOS version
        vn = data[7] << 8 | data[8];
    }
    else
        goto INVALID_DATA;
    #else
    RawSMBIOSData *smBiosData = NULL;
    smBiosData = (RawSMBIOSData *) data;

    // get the SMBIOS version
    vn = smBiosData->SMBIOSMajorVersion << 8 | smBiosData->SMBIOSMinorVersion;
    data_ = smBiosData->SMBIOSTableData;
    size_ = smBiosData->Length;
    #endif

    if (version_ == 0) version_ = SMBIOS_3_0;
    if (version_ > vn) version_ = vn;
    // is a valid version?
    if ((version_ < SMBIOS_2_0 || version_ > SMBIOS_2_8) && version_ != SMBIOS_3_0 ) goto INVALID_DATA;
    reset();
    return;

INVALID_DATA:
    data_ = ptr_ = start_ = NULL;
}

const char *Parser::getString( int index ) const
{
    if (index <= 0) return "";

    const char *ptr = (const char*) start_ + (size_t) entry_.length - DMI_ENTRY_HEADER_SIZE;
    for (int i = 1; *ptr != 0 && i < index; ++i)
    {
        // TODO: check buffer limits
        while (*ptr != 0) ++ptr;
        ++ptr;
    }
    return ptr;
}

void Parser::reset()
{
    ptr_ = start_ = NULL;
}

const Entry *Parser::next()
{
    if (data_ == NULL) return NULL;

    // jump to the next field
    if (ptr_ == NULL)
        ptr_ = start_ = data_;
    else
    {
        ptr_ = start_ + entry_.length - DMI_ENTRY_HEADER_SIZE;
        while (ptr_ < data_ + size_ - 1 && !(ptr_[0] == 0 && ptr_[1] == 0)) ++ptr_;
        ptr_ += 2;
        if (ptr_ >= data_ + size_)
        {
            ptr_ = start_ = NULL;
            return NULL;
        }
    }

    memset(&entry_, 0, sizeof(entry_));

    // entry header
    entry_.type = DMI_READ_8U;
    entry_.length = DMI_READ_8U;
    entry_.handle = DMI_READ_16U;
    start_ = ptr_;

    if (entry_.type == 127)
    {
        reset();
        return NULL;
    }

    return parseEntry();
}

const Entry *Parser::parseEntry()
{
    if (entry_.type == DMI_TYPE_BIOS)
    {
        // 2.0+
        if (version_ >= SMBIOS_2_0)
        {
            entry_.data.bios.Vendor_ = DMI_READ_8U;
            entry_.data.bios.BIOSVersion_ = DMI_READ_8U;
            entry_.data.bios.BIOSStartingSegment = DMI_READ_16U;
            entry_.data.bios.BIOSReleaseDate_ = DMI_READ_8U;
            entry_.data.bios.BIOSROMSize = DMI_READ_8U;
            for (size_t i = 0; i < 8; ++i)
                entry_.data.bios.BIOSCharacteristics[i] = DMI_READ_8U;

            entry_.data.bios.Vendor          = getString(entry_.data.bios.Vendor_);
            entry_.data.bios.BIOSVersion     = getString(entry_.data.bios.BIOSVersion_);
            entry_.data.bios.BIOSReleaseDate = getString(entry_.data.bios.BIOSReleaseDate_);
        }
        // 2.4+
        if (version_ >= SMBIOS_2_4)
        {
            entry_.data.bios.ExtensionByte1 = DMI_READ_8U;
            entry_.data.bios.ExtensionByte2 = DMI_READ_8U;
            entry_.data.bios.SystemBIOSMajorRelease = DMI_READ_8U;
            entry_.data.bios.SystemBIOSMinorRelease = DMI_READ_8U;
            entry_.data.bios.EmbeddedFirmwareMajorRelease = DMI_READ_8U;
            entry_.data.bios.EmbeddedFirmwareMinorRelease = DMI_READ_8U;
        }
    }
    else
    if (entry_.type == DMI_TYPE_SYSINFO)
    {
        // 2.0+
        if (version_ >= SMBIOS_2_0)
        {
            entry_.data.sysinfo.Manufacturer_ = DMI_READ_8U;
            entry_.data.sysinfo.ProductName_ = DMI_READ_8U;
            entry_.data.sysinfo.Version_ = DMI_READ_8U;
            entry_.data.sysinfo.SerialNumber_ = DMI_READ_8U;

            entry_.data.sysinfo.Manufacturer = getString(entry_.data.sysinfo.Manufacturer_);
            entry_.data.sysinfo.ProductName  = getString(entry_.data.sysinfo.ProductName_);
            entry_.data.sysinfo.Version = getString(entry_.data.sysinfo.Version_);
            entry_.data.sysinfo.SerialNumber = getString(entry_.data.sysinfo.SerialNumber_);
        }
        // 2.1+
        if (version_ >= SMBIOS_2_1)
        {
            for(int i = 0 ; i < 16; ++i)
                entry_.data.sysinfo.UUID[i] = DMI_READ_8U;
            entry_.data.sysinfo.WakeupType = DMI_READ_8U;
        }
        // 2.4+
        if (version_ >= SMBIOS_2_4)
        {
            entry_.data.sysinfo.SKUNumber_ = DMI_READ_8U;
            entry_.data.sysinfo.Family_ = DMI_READ_8U;

            entry_.data.sysinfo.SKUNumber = getString(entry_.data.sysinfo.SKUNumber_);
            entry_.data.sysinfo.Family = getString(entry_.data.sysinfo.Family_);
        }
    }
    else
    if (entry_.type == DMI_TYPE_BASEBOARD)
    {
        // 2.0+
        if (version_ >= SMBIOS_2_0)
        {
            entry_.data.baseboard.Manufacturer_ = DMI_READ_8U;
            entry_.data.baseboard.Product_ = DMI_READ_8U;
            entry_.data.baseboard.Version_ = DMI_READ_8U;
            entry_.data.baseboard.SerialNumber_ = DMI_READ_8U;
            entry_.data.baseboard.AssetTag_ = DMI_READ_8U;
            entry_.data.baseboard.FeatureFlags = DMI_READ_8U;
            entry_.data.baseboard.LocationInChassis_ = DMI_READ_8U;
            entry_.data.baseboard.ChassisHandle = DMI_READ_16U;
            entry_.data.baseboard.BoardType = DMI_READ_8U;
            entry_.data.baseboard.NoOfContainedObjectHandles = DMI_READ_8U;
            entry_.data.baseboard.ContainedObjectHandles = (uint16_t*) ptr_;
            ptr_ += entry_.data.baseboard.NoOfContainedObjectHandles * sizeof(uint16_t);

            entry_.data.baseboard.Manufacturer      = getString(entry_.data.baseboard.Manufacturer_);
            entry_.data.baseboard.Product           = getString(entry_.data.baseboard.Product_);
            entry_.data.baseboard.Version           = getString(entry_.data.baseboard.Version_);
            entry_.data.baseboard.SerialNumber      = getString(entry_.data.baseboard.SerialNumber_);
            entry_.data.baseboard.AssetTag          = getString(entry_.data.baseboard.AssetTag_);
            entry_.data.baseboard.LocationInChassis = getString(entry_.data.baseboard.LocationInChassis_);
        }

        return &entry_;
    }
    else
    if (entry_.type == DMI_TYPE_SYSENCLOSURE)
    {
        // 2.0+
        if (version_ >= SMBIOS_2_0)
        {
            entry_.data.sysenclosure.Manufacturer_ = DMI_READ_8U;
            entry_.data.sysenclosure.Type = DMI_READ_8U;
            entry_.data.sysenclosure.Version_ = DMI_READ_8U;
            entry_.data.sysenclosure.SerialNumber_ = DMI_READ_8U;
            entry_.data.sysenclosure.AssetTag_ = DMI_READ_8U;

            entry_.data.sysenclosure.Manufacturer = getString(entry_.data.sysenclosure.Manufacturer_);
            entry_.data.sysenclosure.Version      = getString(entry_.data.sysenclosure.Version_);
            entry_.data.sysenclosure.SerialNumber = getString(entry_.data.sysenclosure.SerialNumber_);
            entry_.data.sysenclosure.AssetTag     = getString(entry_.data.sysenclosure.AssetTag_);
        }
        // 2.1+
        if (version_ >= SMBIOS_2_1)
        {
            entry_.data.sysenclosure.BootupState = DMI_READ_8U;
            entry_.data.sysenclosure.PowerSupplyState = DMI_READ_8U;
            entry_.data.sysenclosure.ThermalState = DMI_READ_8U;
            entry_.data.sysenclosure.SecurityStatus = DMI_READ_8U;
        }
        // 2.3+
        if (version_ >= SMBIOS_2_3)
        {
            entry_.data.sysenclosure.OEMdefined = DMI_READ_32U;
            entry_.data.sysenclosure.Height = DMI_READ_8U;
            entry_.data.sysenclosure.NumberOfPowerCords = DMI_READ_8U;
            entry_.data.sysenclosure.ContainedElementCount = DMI_READ_8U;
            entry_.data.sysenclosure.ContainedElementRecordLength = DMI_READ_8U;
            entry_.data.sysenclosure.ContainedElements = ptr_;
            ptr_ += entry_.data.sysenclosure.ContainedElementCount * entry_.data.sysenclosure.ContainedElementRecordLength;
        }
        // 2.7+
        if (version_ >= SMBIOS_2_7)
        {
            entry_.data.sysenclosure.SKUNumber_ = DMI_READ_8U;

            entry_.data.sysenclosure.SKUNumber = getString(entry_.data.sysenclosure.SKUNumber_);
        }
    }
    if (entry_.type == DMI_TYPE_PROCESSOR)
    {
        // 2.0+
        if (version_ >= smbios::SMBIOS_2_0)
        {
            entry_.data.processor.SocketDesignation_ = DMI_READ_8U;
            entry_.data.processor.ProcessorType = DMI_READ_8U;
            entry_.data.processor.ProcessorFamily = DMI_READ_8U;
            entry_.data.processor.ProcessorManufacturer_ = DMI_READ_8U;
            for(int i = 0 ; i < 8; ++i)
                entry_.data.processor.ProcessorID[i] = DMI_READ_8U;
            entry_.data.processor.ProcessorVersion_ = DMI_READ_8U;
            entry_.data.processor.Voltage = DMI_READ_8U;
            entry_.data.processor.ExternalClock = DMI_READ_16U;
            entry_.data.processor.MaxSpeed = DMI_READ_16U;
            entry_.data.processor.CurrentSpeed = DMI_READ_16U;
            entry_.data.processor.Status = DMI_READ_8U;
            entry_.data.processor.ProcessorUpgrade = DMI_READ_8U;

            entry_.data.processor.SocketDesignation     = getString(entry_.data.processor.SocketDesignation_);
            entry_.data.processor.ProcessorManufacturer = getString(entry_.data.processor.ProcessorManufacturer_);
            entry_.data.processor.ProcessorVersion      = getString(entry_.data.processor.ProcessorVersion_);
        }
        // 2.1+
        if (version_ >= smbios::SMBIOS_2_1)
        {
            entry_.data.processor.L1CacheHandle = DMI_READ_16U;
            entry_.data.processor.L2CacheHandle = DMI_READ_16U;
            entry_.data.processor.L3CacheHandle = DMI_READ_16U;
        }
        // 2.3+
        if (version_ >= smbios::SMBIOS_2_3)
        {
            entry_.data.processor.SerialNumber_ = DMI_READ_8U;
            entry_.data.processor.AssetTagNumber_ = DMI_READ_8U;
            entry_.data.processor.PartNumber_ = DMI_READ_8U;

            entry_.data.processor.SerialNumber = getString(entry_.data.processor.SerialNumber_);
            entry_.data.processor.AssetTagNumber = getString(entry_.data.processor.AssetTagNumber_);
            entry_.data.processor.PartNumber = getString(entry_.data.processor.PartNumber_);
        }
        // 2.5+
        if (version_ >= smbios::SMBIOS_2_5)
        {
            entry_.data.processor.CoreCount = DMI_READ_8U;
            entry_.data.processor.CoreEnabled = DMI_READ_8U;
            entry_.data.processor.ThreadCount = DMI_READ_8U;
            entry_.data.processor.ProcessorCharacteristics = DMI_READ_16U;
        }
        //2.6+
        if (version_ >= smbios::SMBIOS_2_6)
        {
            entry_.data.processor.ProcessorFamily2 = DMI_READ_16U;
        }
        //3.0+
        if (version_ >= smbios::SMBIOS_3_0)
        {
            entry_.data.processor.CoreCount2 = DMI_READ_16U;
            entry_.data.processor.CoreEnabled2 = DMI_READ_16U;
            entry_.data.processor.ThreadCount2 = DMI_READ_16U;
        }

        return &entry_;
    }
    else
    if (entry_.type == DMI_TYPE_SYSSLOT)
    {
        // 2.0+
        if (version_ >= smbios::SMBIOS_2_0)
        {
            entry_.data.sysslot.SlotDesignation_ = DMI_READ_8U;
            entry_.data.sysslot.SlotType = DMI_READ_8U;
            entry_.data.sysslot.SlotDataBusWidth = DMI_READ_8U;
            entry_.data.sysslot.CurrentUsage = DMI_READ_8U;
            entry_.data.sysslot.SlotLength = DMI_READ_8U;
            entry_.data.sysslot.SlotID = DMI_READ_16U;
            entry_.data.sysslot.SlotCharacteristics1 = DMI_READ_8U;

            entry_.data.sysslot.SlotDesignation = getString(entry_.data.sysslot.SlotDesignation_);
        }
        // 2.1+
        if (version_ >= smbios::SMBIOS_2_1)
        {
            entry_.data.sysslot.SlotCharacteristics2 = DMI_READ_8U;
        }
        // 2.6+
        if (version_ >= smbios::SMBIOS_2_6)
        {
            entry_.data.sysslot.SegmentGroupNumber = DMI_READ_16U;
            entry_.data.sysslot.BusNumber = DMI_READ_8U;
            entry_.data.sysslot.DeviceOrFunctionNumber = DMI_READ_8U;
        }
    }
    else
    if (entry_.type == DMI_TYPE_PHYSMEM)
    {
        // 2.1+
        if (version_ >= smbios::SMBIOS_2_1)
        {
            entry_.data.physmem.Location = DMI_READ_8U;
            entry_.data.physmem.Use = DMI_READ_8U;
            entry_.data.physmem.ErrorCorrection = DMI_READ_8U;
            entry_.data.physmem.MaximumCapacity = DMI_READ_32U;
            entry_.data.physmem.ErrorInformationHandle = DMI_READ_16U;
            entry_.data.physmem.NumberDevices = DMI_READ_16U;
        }
        // 2.7+
        if (version_ >= smbios::SMBIOS_2_7)
        {
            entry_.data.physmem.ExtendedMaximumCapacity = DMI_READ_64U;
        }
    }
    else
    if (entry_.type == DMI_TYPE_MEMORY)
    {
        // 2.1+
        if (version_ >= smbios::SMBIOS_2_1)
        {
            entry_.data.memory.PhysicalArrayHandle = DMI_READ_16U;
            entry_.data.memory.ErrorInformationHandle = DMI_READ_16U;
            entry_.data.memory.TotalWidth = DMI_READ_16U;
            entry_.data.memory.DataWidth = DMI_READ_16U;
            entry_.data.memory.Size = DMI_READ_16U;
            entry_.data.memory.FormFactor = DMI_READ_8U;
            entry_.data.memory.DeviceSet = DMI_READ_8U;
            entry_.data.memory.DeviceLocator_ = DMI_READ_8U;
            entry_.data.memory.BankLocator_ = DMI_READ_8U;
            entry_.data.memory.MemoryType = DMI_READ_8U;
            entry_.data.memory.TypeDetail = DMI_READ_16U;

            entry_.data.memory.DeviceLocator  = getString(entry_.data.memory.DeviceLocator_);
            entry_.data.memory.BankLocator    = getString(entry_.data.memory.BankLocator_);
        }
        // 2.3+
        if (version_ >= smbios::SMBIOS_2_3)
        {
            entry_.data.memory.Speed = DMI_READ_16U;
            entry_.data.memory.Manufacturer_ = DMI_READ_8U;
            entry_.data.memory.SerialNumber_ = DMI_READ_8U;
            entry_.data.memory.AssetTagNumber_ = DMI_READ_8U;
            entry_.data.memory.PartNumber_ = DMI_READ_8U;

            entry_.data.memory.Manufacturer   = getString(entry_.data.memory.Manufacturer_);
            entry_.data.memory.SerialNumber   = getString(entry_.data.memory.SerialNumber_);
            entry_.data.memory.AssetTagNumber = getString(entry_.data.memory.AssetTagNumber_);
            entry_.data.memory.PartNumber     = getString(entry_.data.memory.PartNumber_);
        }
        // 2.6+
        if (version_ >= smbios::SMBIOS_2_6)
        {
            entry_.data.memory.Attributes = DMI_READ_8U;
        }
        // 2.7+
        if (version_ >= smbios::SMBIOS_2_7)
        {
            entry_.data.memory.ExtendedSize = DMI_READ_32U;
            entry_.data.memory.ConfiguredClockSpeed = DMI_READ_16U;
        }
        // 2.8+
        if (version_ >= smbios::SMBIOS_2_8)
        {
            entry_.data.memory.MinimumVoltage = DMI_READ_16U;
            entry_.data.memory.MinimumVoltage = DMI_READ_16U;
            entry_.data.memory.ConfiguredVoltage = DMI_READ_16U;
        }
    }
    else
    if (entry_.type == DMI_TYPE_OEMSTRINGS)
    {
        // 2.0+
        if (version_ >= smbios::SMBIOS_2_0)
        {
            entry_.data.oemstrings.Count = DMI_READ_8U;
            entry_.data.oemstrings.Values = (const char*) ptr_;
        }
    }

    return &entry_;
}

int Parser::version() const
{
    return version_;
}

bool Parser::valid() const
{
    return data_ != NULL;
}

} // namespace smbios
