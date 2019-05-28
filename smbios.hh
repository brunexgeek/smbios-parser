/*
 * Copyright 2019 Bruno Ribeiro
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

#ifndef DMI_PARSER_HH
#define DMI_PARSER_HH


#include <stddef.h>
#include <stdint.h>
#include <cstring>


#define DMI_TYPE_BIOS         0
#define DMI_TYPE_SYSINFO      1
#define DMI_TYPE_BASEBOARD    2
#define DMI_TYPE_SYSENCLOSURE 3
#define DMI_TYPE_PROCESSOR    4
#define DMI_TYPE_SYSSLOT      9
#define DMI_TYPE_PHYSMEM      16
#define DMI_TYPE_MEMORY       17

#define SMBIOS_STRING(name)  uint8_t name##_; const char * name

namespace smbios {

// DMI_TYPE_BIOS
struct TypeBios
{
	SMBIOS_STRING(Vendor);
	SMBIOS_STRING(BIOSVersion);
	uint16_t BIOSStartingSegment;
	SMBIOS_STRING(BIOSReleaseDate);
	uint8_t BIOSROMSize;
	uint8_t BIOSCharacteristics[8];
	uint8_t ExtensionByte1;
	uint8_t ExtensionByte2;
	uint8_t SystemBIOSMajorRelease;
	uint8_t SystemBIOSMinorRelease;
	uint8_t EmbeddedFirmwareMajorRelease;
	uint8_t EmbeddedFirmwareMinorRelease;
};

// DMI_TYPE_SYSINFO
struct TypeSysInfo
{
	// 2.0+
	SMBIOS_STRING(Manufacturer);
	SMBIOS_STRING(ProductName);
	SMBIOS_STRING(Version);
	SMBIOS_STRING(SerialNumber);
	// 2.1+
	uint8_t UUID[16];
	uint8_t WakeupType;
	// 2.4+
	SMBIOS_STRING(SKUNumber);
	SMBIOS_STRING(Family);
};

// DMI_TYPE_BASEBOARD
struct TypeBaseboard
{
	// 2.0+
	SMBIOS_STRING(Manufacturer);
	SMBIOS_STRING(Product);
	SMBIOS_STRING(Version);
	SMBIOS_STRING(SerialNumber);
	SMBIOS_STRING(AssetTag);
	uint8_t FeatureFlags;
	SMBIOS_STRING(LocationInChassis);
	uint16_t ChassisHandle;
	uint8_t BoardType;
	uint8_t NoOfContainedObjectHandles;
	uint16_t *ContainedObjectHandles;
};

// DMI_TYPE_SYSENCLOSURE
struct TypeSystemEnclosure
{
	// 2.0+
	SMBIOS_STRING(Manufacturer);
	uint8_t Type;
	SMBIOS_STRING(Version);
	SMBIOS_STRING(SerialNumber);
	SMBIOS_STRING(AssetTag);
	// 2.1+
	uint8_t BootupState;
	uint8_t PowerSupplyState;
	uint8_t ThermalState;
	uint8_t SecurityStatus;
	// 2.3+
	uint32_t OEMdefined;
	uint8_t Height;
	uint8_t NumberOfPowerCords;
	uint8_t ContainedElementCount;
	uint8_t ContainedElementRecordLength;
	const uint8_t *ContainedElements;
	// 2.7+
	SMBIOS_STRING(SKUNumber);
};

// DMI_TYPE_PROCESSOR
struct TypeProcessor
{
	// 2.0+
	SMBIOS_STRING(SocketDesignation);
	uint8_t ProcessorType;
	uint8_t ProcessorFamily;
	SMBIOS_STRING(ProcessorManufacturer);
	uint8_t ProcessorID[8];
	SMBIOS_STRING(ProcessorVersion);
	uint8_t Voltage;
	uint16_t ExternalClock;
	uint16_t MaxSpeed;
	uint16_t CurrentSpeed;
	uint8_t Status;
	uint8_t ProcessorUpgrade;
	// 2.1+
	uint16_t L1CacheHandle;
	uint16_t L2CacheHandle;
	uint16_t L3CacheHandle;
	// 2.3+
	SMBIOS_STRING(SerialNumber);
    SMBIOS_STRING(AssetTagNumber);
    SMBIOS_STRING(PartNumber);
	// 2.5+
	uint8_t CoreCount;
	uint8_t CoreEnabled;
	uint8_t ThreadCount;
	uint16_t ProcessorCharacteristics;
	// 2.6+
	uint16_t ProcessorFamily2;
	// 3.0+
	uint16_t CoreCount2;
	uint16_t CoreEnabled2;
	uint16_t ThreadCount2;
};

// DMI_TYPE_SYSSLOT
struct SystemSlot
{
	// 2.0+
	SMBIOS_STRING(SlotDesignation);
	uint8_t SlotType;
	uint8_t SlotDataBusWidth;
	uint8_t CurrentUsage;
	uint8_t SlotLength;
	uint16_t SlotID;
	uint8_t SlotCharacteristics1;
	// 2.1+
	uint8_t SlotCharacteristics2;
	// 2.6+
	uint16_t SegmentGroupNumber;
	uint8_t BusNumber;
	uint8_t DeviceOrFunctionNumber;
};

// DMI_TYPE_PHYSMEM
struct TypePhysicalMemory
{
    // 2.1+
    uint8_t Location;
    uint8_t Use;
    uint8_t ErrorCorrection;
    uint32_t MaximumCapacity;
    uint16_t ErrorInformationHandle;
    uint16_t NumberDevices;
    // 2.7+
    uint64_t ExtendedMaximumCapacity;
};

// DMI_TYPE_MEMORY
struct TypeMemoryDevice
{
    // 2.1+
    uint16_t PhysicalArrayHandle;
    uint16_t ErrorInformationHandle;
    uint16_t TotalWidth;
    uint16_t DataWidth;
    uint16_t Size;
    uint8_t FormFactor;
    uint8_t DeviceSet;
    SMBIOS_STRING(DeviceLocator);
    SMBIOS_STRING(BankLocator);
    uint8_t MemoryType;
    uint16_t TypeDetail;
	// 2.3+
    uint16_t Speed;
    SMBIOS_STRING(Manufacturer);
    SMBIOS_STRING(SerialNumber);
    SMBIOS_STRING(AssetTagNumber);
    SMBIOS_STRING(PartNumber);
	// 2.6+
    uint8_t Attributes;
    // 2.7+
    uint32_t ExtendedSize;
	uint16_t ConfiguredClockSpeed;
	// 2.8+
	uint16_t MinimumVoltage;
	uint16_t MaximumVoltage;
	uint16_t ConfiguredVoltage;
};

struct Entry
{
    uint8_t type;
	uint8_t length;
	uint16_t handle;
    union
    {
        TypeProcessor processor;
        TypeBaseboard baseboard;
        TypeSysInfo sysinfo;
        TypeBios bios;
        TypeSystemEnclosure sysenclosure;
        TypePhysicalMemory physmem;
        TypeMemoryDevice memory;
		SystemSlot sysslot;
    } data;
};


enum SpecVersion
{
	SMBIOS_2_0 = 0x0200,
	SMBIOS_2_1 = 0x0201,
	SMBIOS_2_2 = 0x0202,
	SMBIOS_2_3 = 0x0203,
	SMBIOS_2_4 = 0x0204,
	SMBIOS_2_5 = 0x0205,
	SMBIOS_2_6 = 0x0206,
	SMBIOS_2_7 = 0x0207,
	SMBIOS_2_8 = 0x0208,
	SMBIOS_3_0 = 0x0300,
};


class Parser
{
    public:
        Parser( const uint8_t *data, size_t size, int version = 0 );
        void reset();
        const Entry *next();
		int version() const;
		bool valid() const;

    private:
        const uint8_t *data_;
        size_t size_;
        Entry entry_;
        const uint8_t *ptr_;
        const uint8_t *start_;
		int version_;

        const Entry *parseEntry();
        const char *getString( int index ) const;
};


} // namespace smbios


#undef DMI_READ_8U
#undef DMI_READ_16U


#endif // DMI_PARSER_HH
