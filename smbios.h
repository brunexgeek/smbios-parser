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

#pragma once

#define SMBIOS_STRING(name)  uint8_t name##_; const char * name

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(WIN32) || defined(_WIN32) || defined(WINNT) || defined(_WINNT) || defined(WIN64) || defined(_WIN64)
	#undef SMBIOS_WINDOWS
	#define SMBIOS_WINDOWS   1
#endif

#undef SMBIOS_EXPORT
#ifdef SMBIOS_WINDOWS
	#define SMBIOS_EXPORT                  __declspec(dllexport)
#else
	#define SMBIOS_EXPORT                  __attribute__ ((visibility("default")))
#endif

#ifdef __cplusplus
#define SMBIOS_CONSTEXPR constexpr
#else
#include <stdbool.h>
#define SMBIOS_CONSTEXPR const
#endif

#ifdef __cplusplus
namespace smbios {
#endif

static SMBIOS_CONSTEXPR int SMBERR_OK = 0;
static SMBIOS_CONSTEXPR int SMBERR_INVALID_ARGUMENT = -1;
static SMBIOS_CONSTEXPR int SMBERR_INVALID_DATA = -2;
static SMBIOS_CONSTEXPR int SMBERR_END_OF_STREAM = -3;

enum EntryType
{
	TYPE_BIOS_INFO = 0,
	TYPE_SYSTEM_INFO = 1,
	TYPE_BASEBOARD_INFO = 2,
	TYPE_SYSTEM_ENCLOSURE = 3,
	TYPE_PROCESSOR_INFO = 4,
	TYPE_PORT_CONNECTOR = 8,
	TYPE_SYSTEM_SLOT = 9,
	TYPE_OEM_STRINGS = 11,
	TYPE_PHYSICAL_MEMORY_ARRAY = 16,
	TYPE_MEMORY_DEVICE = 17,
	TYPE_MEMORY_ARRAY_MAPPED_ADDRESS = 19,
	TYPE_MEMORY_DEVICE_MAPPED_ADDRESS = 20,
	TYPE_SYSTEM_BOOT_INFO = 32,
	TYPE_MANAGEMENT_DEVICE = 34,
	TYPE_MANAGEMENT_DEVICE_COMPONENT = 35,
	TYPE_MANAGEMENT_DEVICE_THRESHOLD_DATA = 36,
	TYPE_ONBOARD_DEVICES_EXTENDED_INFO = 41,
};

struct BiosInfo
{
	// 2.0+
	SMBIOS_STRING(Vendor);
	SMBIOS_STRING(BIOSVersion);
	uint16_t BIOSStartingAddressSegment;
	SMBIOS_STRING(BIOSReleaseDate);
	uint8_t BIOSROMSize;
	uint8_t BIOSCharacteristics[8];
	// 2.4+
	uint8_t BIOSCharacteristicsExtensionBytes[2];
	uint8_t SystemBIOSMajorRelease;
	uint8_t SystemBIOSMinorRelease;
	uint8_t EmbeddedControlerFirmwareMajorRelease;
	uint8_t EmbeddedControlerFirmwareMinorRelease;
};

struct SystemInfo
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

struct BaseboardInfo
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
	uint8_t NumberOfContainedObjectHandles;
	uint16_t *ContainedObjectHandles;
};

struct SystemEnclosure
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

struct ProcessorInfo
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

struct PortConnector
{
	SMBIOS_STRING(InternalReferenceDesignator);
	uint8_t InternalConnectorType;
	SMBIOS_STRING(ExternalReferenceDesignator);
	uint8_t ExternalConnectorType;
	uint8_t PortType;
};

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

struct OemStrings
{
	// 2.0+
	uint8_t Count;
	const char *Values;
};

struct PhysicalMemoryArray
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

struct MemoryDevice
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

struct MemoryArrayMappedAddress
{
	// 2.1+
	uint32_t StartingAddress;
	uint32_t EndingAddress;
	uint16_t MemoryArrayHandle;
	uint8_t PartitionWidth;
	// 2.7+
	uint64_t ExtendedStartingAddress;
	uint64_t ExtendedEndingAddress;
};

struct MemoryDeviceMappedAddress
{
	// 2.1+
	uint32_t StartingAddress;
	uint32_t EndingAddress;
	uint16_t MemoryDeviceHandle;
	uint16_t MemoryArrayMappedAddressHandle;
	uint8_t PartitionRowPosition;
	uint8_t InterleavePosition;
	uint8_t InterleavedDataDepth;
	// 2.7+
	uint64_t ExtendedStartingAddress;
	uint64_t ExtendedEndingAddress;
};

struct SystemBootInfo
{
	// 2.0+
	uint8_t Reserved[6];
	const uint8_t *BootStatus;
};

struct ManagementDevice
{
	// 2.0+
	SMBIOS_STRING(Description);
	uint8_t Type;
	uint32_t Address;
	uint8_t AddressType;
};

struct ManagementDeviceComponent
{
	// 2.0+
	SMBIOS_STRING(Description);
	uint16_t ManagementDeviceHandle;
	uint16_t ComponentHandle;
	uint16_t ThresholdHandle;
};

struct ManagementDeviceThresholdData
{
	// 2.0+
	uint16_t LowerThresholdNonCritical;
	uint16_t UpperThresholdNonCritical;
	uint16_t LowerThresholdCritical;
	uint16_t UpperThresholdCritical;
	uint16_t LowerThresholdNonRecoverable;
	uint16_t UpperThresholdNonRecoverable;
};

struct OnboardDevicesExtendedInfo
{
	// 2.0+
	SMBIOS_STRING(ReferenceDesignation);
	uint8_t DeviceType;
	uint8_t DeviceTypeInstance;
	uint16_t SegmentGroupNumber;
	uint8_t BusNumber;
	uint8_t DeviceOrFunctionNumber;
};

struct Entry
{
	// Entry type, as defined in the SMBIOS specification.
    uint8_t type;

	// Length of the entry (SMBIOS header and data).
	uint8_t length;

	/**
	 * Entry handle, a unique 16-bit number in the range 0 to 0FFFEh (for version 2.0)
	 * or 0 to 0FEFFh (for version 2.1 and later).
	 */
	uint16_t handle;

	/**
	 * Union with the actual formatted data of the entry for each supported type. Supported types
	 * are listed in the `EntryType` enumeration. If the entry type is not supported, you can still
	 * read the data from `rawdata` field.
	 */
    union
    {
		struct BiosInfo bios_info;
		struct SystemInfo system_info;
		struct BaseboardInfo baseboard_info;
		struct SystemEnclosure system_enclosure;
		struct ProcessorInfo processor_info;
		struct PortConnector port_connector;
		struct SystemSlot system_slot;
		struct OemStrings oem_strings;
		struct PhysicalMemoryArray physical_memory_array;
		struct MemoryDevice memory_device;
		struct MemoryArrayMappedAddress memory_array_mapped_address;
		struct MemoryDeviceMappedAddress memory_device_mapped_address;
		struct SystemBootInfo system_boot_info;
		struct ManagementDevice management_device;
		struct ManagementDeviceComponent management_device_component;
		struct ManagementDeviceThresholdData management_device_threshold_data;
		struct OnboardDevicesExtendedInfo onboard_devices_extended_info;
    } data;

	// Raw SMBIOS data of the entry (header and data itself).
	const uint8_t *rawdata;

	// Pointer to the start of the string table;
	const char *strings;

	// Number of strings in the string table.
	int string_count;
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
	SMBIOS_3_0 = 0x0300
};

struct ParserContext
{
	// Pointer to extarnal buffer containing the SMBIOS data
	const uint8_t *data;
	// Total size of the SMBIOS data
	size_t size;
	// Pointer to the current byte in the SMBIOS data
	const uint8_t *ptr;
	// Pointer to the entry start
	const uint8_t *estart;
	// Pointer to one byte past the last byte of the entry
	const uint8_t *eend;
	// Selected SMBIOS version
	enum SpecVersion sversion;
	// Original SMBIOS version
	enum SpecVersion oversion;
	// Content of the current SMBIOS entry
	struct Entry entry;
	// true if parsing failed (cannot be reset)
	bool failed;
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the SMBIOS parser.
 *
 * If the actual version of the SMBIOS data is smaller than the value of the parameter
 * 'version', the parser will use the version of the SMBIOS data. Fields related to
 * SMBIOS versions not selected will be left blank. Valid values are the ones defined
 * in the enumeration 'SpecVersion'.
 *
 * @param context Parser context.
 * @param data SMBIOS data.
 * @param size Size of the SMBIOS data.
 * @param version Preferred SMBIOS version.
 * @return SMBERR_OK on success or a negative error code.
 */
SMBIOS_EXPORT int smbios_initialize(struct ParserContext *context, const uint8_t *data, size_t size, enum SpecVersion version );

/**
 * Get the next SMBIOS entry.
 *
 * Calling this function invalidates any previously returned entry.
 *
 * @param context Parser context.
 * @param entry Pointer to the entry.
 * @return SMBERR_OK on success or a negative error code.
 */
SMBIOS_EXPORT int smbios_next(struct ParserContext *context, const struct Entry **entry);

/**
 * Reset the SMBIOS parser and let it start from the beginning.
 *
 * If the parser failed (e.g. invalid SMBIOS data), calling this function will fail too.
 *
 * @param context Parser context.
 * @return SMBERR_OK on success or a negative error code.
 */
SMBIOS_EXPORT int smbios_reset(struct ParserContext * context);

/**
 * Returns the selected and/or the original SMBIOS versions.
 *
 * @param context Parser context.
 * @param selected (optional) Selected version used to parse the SMBIOS data.
 * @param original (optional) Version of the SMBIOS data.
 * @return SMBERR_OK on success or a negative error code.
 */
SMBIOS_EXPORT int smbios_get_version(struct ParserContext *context, enum SpecVersion *selected, enum SpecVersion *original);

/**
 * Returns a string from the SMBIOS entry.
 *
 * Fields in the entry that reference a string are automatically set with the corresponding string pointer.
 * However, some entry types have an arbitrary number of strings not pointed by entry fields (e.g. the
 * 'OEMStrings' entry type). In this case, you can use this function to retrieve them.
 *
 * This is a utility function to retrieve a string from the SMBIOS entry. The function will iterate over the
 * strings in the SMBIOS entry and return the string with the given index, starting from 1. If the index is
 * out of range, the function will return NULL.
 *
 * If you want to avoid the overhead of the iteration for each call, you can access the string table directly.
 * The start of the string table is set in the field 'strings' of the entry. Each string is terminated with a
 * null (00h) byte and the table is terminated with an additional null (00h) byte. The amount of strings is
 * given in the field 'string_count' of the entry.
 *
 * @param entry SMBIOS entry.
 * @param index Index of the string, starting from 1.
 * @return String associated with the given index or NULL in case of error.
 */
SMBIOS_EXPORT const char *smbios_get_string( const struct Entry *entry, int index );

#ifdef __cplusplus
} // extern "C"
#endif

#undef SMBIOS_STRING
#undef SMBIOS_WINDOWS
#undef SMBIOS_EXPORT


