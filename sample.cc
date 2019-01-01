#include <iostream>
#include <fstream>
#include <vector>
#include <sys/stat.h>
#include <dmi/parser.hh>


int main(int argc, char ** argv)
{
    if (argc != 2) return 1;

    struct stat info;
    if (stat(argv[1], &info) != 0) return 1;

    std::vector<uint8_t> buffer(info.st_size);

    std::ifstream input(argv[1], std::ios_base::binary);
    if (input.good())
    {
        input.read((char*) buffer.data(), info.st_size);
        input.close();
    }

    dmi::Parser parser(&buffer.front(), buffer.size());

    const dmi::Entry *entry = NULL;
    while (true)
    {
        entry = parser.next();
        if (entry == NULL) break;
        printf("Handle 0x%04X, DMI Type %d, %d bytes\n", entry->handle, entry->type, entry->length);
        if (entry->type == DMI_TYPE_PROCESSOR)
        {
            printf("Max speed: %d\n", entry->data.processor.MaxSpeed);
        }
    }

    return 0;
}