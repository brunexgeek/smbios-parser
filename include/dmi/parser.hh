#ifndef DMI_PARSER_HH
#define DMI_PARSER_HH


#include <stddef.h>
#include <stdint.h>
#include <cstring>


#define DMI_TYPE_BIOS         0
#define DMI_TYPE_PROCESSOR    4


namespace dmi {


struct Processor
{
	uint8_t SocketDesignation_;
    char* SocketDesignation;
	uint8_t ProcessorType;
	uint8_t ProcessorFamily;
	uint8_t ProcessorManufacturer_;
    char* ProcessorManufacturer;
	uint8_t ProcessorID[8];
	uint8_t ProcessorVersion_;
    char* ProcessorVersion;
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
	char* SerialNumber;
    uint8_t AssetTagNumber_;
	char* AssetTagNumber;
    uint8_t PartNumber_;
	char* PartNumber;
};


struct Entry
{
    uint8_t type;
	uint8_t length;
	uint16_t handle;
    union
    {
        Processor processor;
    } data;
};


class Parser
{
    public:
        Parser( const uint8_t *data, size_t size ) : data(data), size(size), ptr(NULL)
        {
        }

        const Entry *next();

    private:
        const uint8_t *data;
        size_t size;
        Entry entry;
        const uint8_t *ptr;
        const uint8_t *start;

        const Entry *parseEntry();
};


} // namespace dmi


#undef DMI_READ_8U
#undef DMI_READ_16U


#endif // DMI_PARSER_HH