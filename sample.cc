#include <iostream>
#include <fstream>
#include <vector>
#include <sys/stat.h>
#include <dmi/parser.hh>


#ifdef _WIN32

void getDMI( std::vector<uint8_t> &buffer )
{
    DWORD error = ERROR_SUCCESS;
    DWORD smBiosDataSize = 0;
    RawSMBIOSData* smBiosData = NULL; // Defined in this link
    DWORD bytesWritten = 0;

    // Query size of SMBIOS data.
    smBiosDataSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);

    // Allocate memory for SMBIOS data
    smBiosData = (RawSMBIOSData*) HeapAlloc(GetProcessHeap(), 0, smBiosDataSize);
    if (!smBiosData) {
        error = ERROR_OUTOFMEMORY;
        goto exit;
    }

    // Retrieve the SMBIOS table
    bytesWritten = GetSystemFirmwareTable('RSMB', 0, smBiosData, smBiosDataSize);

    if (bytesWritten != smBiosDataSize) {
        error = ERROR_INVALID_DATA;
        goto exit;
    }
}

#else

void getDMI( const std::string &fileName, std::vector<uint8_t> &buffer )
{
    struct stat info;
    if (stat(fileName.c_str(), &info) != 0) return;
    buffer.resize(info.st_size);

    std::ifstream input(fileName.c_str(), std::ios_base::binary);
    if (input.good())
    {
        input.read((char*) buffer.data(), info.st_size);
        input.close();
    }
}

#endif



int main(int argc, char ** argv)
{
    if (argc != 2) return 1;

    std::vector<uint8_t> buffer;
    #ifdef _WIN32
    getDMI(buffer);
    #else
    if (argc != 2) return 1;
    getDMI(argv[1], buffer);
    #endif

    dmi::Parser parser(&buffer.front(), buffer.size());

    const dmi::Entry *entry = NULL;
    while (true)
    {
        entry = parser.next();
        if (entry == NULL) break;
        printf("Handle 0x%04X, DMI Type %d, %d bytes\n", entry->handle, entry->type, entry->length);

        if (entry->type == DMI_TYPE_SYSENCLOSURE)
        {
            printf("     Manufacturer: %s\n", entry->data.sysenclosure.Manufacturer);
            printf("          Version: %s\n", entry->data.sysenclosure.Version);
            printf("     SerialNumber: %s\n", entry->data.sysenclosure.SerialNumber);
            printf("         AssetTag: %s\n\n", entry->data.sysenclosure.AssetTag);
        }
        else
        if (entry->type == DMI_TYPE_BIOS)
        {
            printf("           Vendor: %s\n", entry->data.bios.Vendor);
            printf("      BIOSVersion: %s\n", entry->data.bios.BIOSVersion);
            printf("  BIOSReleaseDate: %s\n\n", entry->data.bios.BIOSReleaseDate);
        }
        else
        if (entry->type == DMI_TYPE_SYSINFO)
        {
            printf("     Manufacturer: %s\n", entry->data.sysinfo.Manufacturer);
            printf("      ProductName: %s\n", entry->data.sysinfo.ProductName);
            printf("          Version: %s\n", entry->data.sysinfo.Version);
            printf("             UUID: ");
            for (size_t i = 0; i < 16; ++i)
                printf("%02X ", entry->data.sysinfo.UUID[i]);
            printf("\n");
            printf("        SKUNumber: %s\n", entry->data.sysinfo.SKUNumber);
            printf("           Family: %s\n\n", entry->data.sysinfo.Family);
        }
        else
        if (entry->type == DMI_TYPE_BASEBOARD)
        {
            printf("     Manufacturer: %s\n", entry->data.baseboard.Manufacturer);
            printf("      ProductName: %s\n", entry->data.baseboard.ProductName);
            printf("          Version: %s\n", entry->data.baseboard.Version);
            printf("     SerialNumber: %s\n", entry->data.baseboard.SerialNumber);
            printf("         AssetTag: %s\n", entry->data.baseboard.AssetTag);
            printf("LocationInChassis: %s\n\n", entry->data.baseboard.LocationInChassis);
        }
        else
        if (entry->type == DMI_TYPE_PROCESSOR)
        {
            printf("    SocketDesignation: %s\n", entry->data.processor.SocketDesignation);
            printf("ProcessorManufacturer: %s\n", entry->data.processor.ProcessorManufacturer);
            printf("     ProcessorVersion: %s\n", entry->data.processor.ProcessorVersion);
            printf("          ProcessorID: ");
            for (size_t i = 0; i < 8; ++i)
                printf("%02X ", entry->data.processor.ProcessorID[i]);
            printf("\n\n");
        }
        else
        if (entry->type == DMI_TYPE_PHYSMEM)
        {
            printf("      MaximumCapacity: %d KiB\n", entry->data.physmem.MaximumCapacity);
            printf("   ExtMaximumCapacity: %lu KiB\n\n", entry->data.physmem.ExtendedMaximumCapacity);
        }
        else
        if (entry->type == DMI_TYPE_MEMORY)
        {
            printf("        DeviceLocator: %s\n", entry->data.memory.DeviceLocator);
            printf("          BankLocator: %s\n", entry->data.memory.BankLocator);
            printf("         Manufacturer: %s\n", entry->data.memory.Manufacturer);
            printf("         SerialNumber: %s\n", entry->data.memory.SerialNumber);
            printf("       AssetTagNumber: %s\n", entry->data.memory.AssetTagNumber);
            printf("           PartNumber: %s\n", entry->data.memory.PartNumber);
            printf("                 Size: %d MiB\n", entry->data.memory.Size);
            printf("         ExtendedSize: %lu MiB\n\n", entry->data.memory.ExtendedSize);
        }
    }

    return 0;
}