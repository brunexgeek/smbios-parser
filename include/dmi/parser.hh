#ifndef DMI_PARSER_HH
#define DMI_PARSER_HH


#include <stddef.h>
#include <stdint.h>
#include <cstring>


#define DMI_TYPE_BIOS         0
#define DMI_TYPE_SYSINFO      1
#define DMI_TYPE_BASEBOARD    2
#define DMI_TYPE_PROCESSOR    4


namespace dmi {


struct TypeSysInfo
{
	uint8_t Manufacturer_;
	const char* Manufacturer;
	uint8_t ProductName_;
	const char* ProductName;
	uint8_t Version_;
	const char* Version;
	uint8_t SerialNumber_;
	const char* SerialNumber;
	uint8_t UUID[16];
	uint8_t WakeupType;
	uint8_t SKUNumber_;
    const char* SKUNumber;
	uint8_t Family_;
	const char* Family;
};


struct TypeBaseboard
{
	uint8_t Manufacturer_;
    const char *Manufacturer;
	uint8_t ProductName_;
    const char *ProductName;
	uint8_t Version_;
    const char *Version;
	uint8_t SerialNumber_;
    const char *SerialNumber;
	uint8_t AssetTag_;
    const char *AssetTag;
	uint8_t FeatureFlags;
	uint8_t LocationInChassis_;
    const char *LocationInChassis;
	uint16_t ChassisHandle;
	uint8_t BoardType;
	uint8_t NoOfContainedObjectHandles;
	uint16_t *ContainedObjectHandles;
};


struct TypeProcessor
{
	uint8_t SocketDesignation_;
    const char* SocketDesignation;
	uint8_t ProcessorType;
	uint8_t ProcessorFamily;
	uint8_t ProcessorManufacturer_;
    const char* ProcessorManufacturer;
	uint8_t ProcessorID[8];
	uint8_t ProcessorVersion_;
    const char* ProcessorVersion;
	uint8_t Voltage;
	uint16_t ExternalClock;
	uint16_t MaxSpeed;
	uint16_t CurrentSpeed;
	uint8_t Status;
	uint8_t ProcessorUpgrade;
	uint16_t L1CacheHandle;
	uint16_t L2CacheHandle;
	uint16_t L3CacheHandle;
	uint8_t SerialNumber_;
	const char* SerialNumber;
    uint8_t AssetTagNumber_;
	const char* AssetTagNumber;
    uint8_t PartNumber_;
	const char* PartNumber;
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
    } data;
};


class Parser
{
    public:
        Parser( const uint8_t *data, size_t size );
        const Entry *next();

    private:
        const uint8_t *data_;
        size_t size_;
        Entry entry_;
        const uint8_t *ptr_;
        const uint8_t *start_;

        const Entry *parseEntry();
        const char *getString( int index ) const;
};


} // namespace dmi


#undef DMI_READ_8U
#undef DMI_READ_16U


#endif // DMI_PARSER_HH