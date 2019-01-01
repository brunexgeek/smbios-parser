#include <dmi/parser.hh>
#include <vector>


#define DMI_READ_8U    *ptr++
#define DMI_READ_16U   *((uint16_t*)ptr), ptr += 2


namespace dmi {


const Entry *Parser::next()
{
    if (data == NULL) return NULL;

    // skip to the next field
    if (ptr == NULL)
        ptr = start = data;
    else
    {
        ptr = start + entry.length - 4;
        while (ptr < data + size - 1 && !(ptr[0] == 0 && ptr[1] == 0)) ++ptr;
        ptr += 2;
        if (ptr >= data + size)
        {
            ptr = start = NULL;
            return NULL;
        }
    }

    memset(&entry, 0, sizeof(entry));

    // entry header
    entry.type = DMI_READ_8U;
    entry.length = DMI_READ_8U;
    entry.handle = DMI_READ_16U;
    start = ptr;

    return parseEntry();
}


const Entry *Parser::parseEntry()
{
    std::vector<const char *> strings;

    if (entry.type == DMI_TYPE_PROCESSOR)
    {
        // version 2.0
        entry.data.processor.SocketDesignation_ = DMI_READ_8U;
        entry.data.processor.ProcessorType = DMI_READ_8U;
        entry.data.processor.ProcessorFamily = DMI_READ_8U;
        entry.data.processor.ProcessorManufacturer_ = DMI_READ_8U;
        for(int i = 0 ; i < 8; ++i)
            entry.data.processor.ProcessorID[i] = DMI_READ_8U;
        entry.data.processor.ProcessorVersion_ = DMI_READ_8U;
        entry.data.processor.Voltage = DMI_READ_8U;
        entry.data.processor.ExternalClock = DMI_READ_16U;
        entry.data.processor.MaxSpeed = DMI_READ_16U;
        entry.data.processor.CurrentSpeed = DMI_READ_16U;
        entry.data.processor.Status = DMI_READ_8U;
        entry.data.processor.ProcessorUpgrade = DMI_READ_8U;

        return &entry;
    }

    return &entry;
    //return NULL;
}

} // namespace dmi
