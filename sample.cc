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

#include <iostream>
#include <fstream>
#include <vector>
#include <sys/stat.h>
#include <iomanip>
#include "smbios.hh"



#ifdef _WIN32

#include <Windows.h>



bool getDMI( std::vector<uint8_t> &buffer )
{
    const BYTE byteSignature[] = { 'B', 'M', 'S', 'R' };
    const DWORD signature = *((DWORD*)byteSignature);

    // get the size of SMBIOS table
    DWORD size = GetSystemFirmwareTable(signature, 0, NULL, 0);
    if (size == 0) return false;
    buffer.resize(size, 0);
    // retrieve the SMBIOS table

    if (size != GetSystemFirmwareTable(Signature, 0, buffer.data(), size))
    {
        buffer.clear();
        return false;
    }

    return true;
}

#else

bool getDMI( const std::string &path, std::vector<uint8_t> &buffer )
{
    std::ifstream input;
    std::string fileName;

    // get the SMBIOS structures size
    fileName = path +  "/DMI";
    struct stat info;
    if (stat(fileName.c_str(), &info) != 0) return false;
    buffer.resize(info.st_size + 32);

    // read SMBIOS structures
    input.open(fileName.c_str(), std::ios_base::binary);
    if (!input.good()) return false;
    input.read((char*) buffer.data() + 32, info.st_size);
    input.close();

    // read SMBIOS entry point
    fileName = path + "/smbios_entry_point";
    input.open(fileName.c_str(), std::ios_base::binary);
    if (!input.good()) return false;
    input.read((char*) buffer.data(), 32);
    input.close();

    return true;
}

#endif


bool printSMBIOS(
    smbios::Parser &parser,
    std::ostream &output )
{
    int version = parser.version();
    const smbios::Entry *entry = NULL;
    while (true)
    {
        entry = parser.next();
        if (entry == NULL) break;
        output << "Handle 0x" << std::hex << std::setw(4) << std::setfill('0') << (int) entry->handle << std::dec
            << ", DMI Type " << (int) entry->type << ", " << (int) entry->length << " bytes\n";

        if (entry->type == DMI_TYPE_BIOS)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                output << "                      Vendor: " << entry->data.bios.Vendor << '\n';
                output << "                 BIOSVersion: " << entry->data.bios.BIOSVersion << '\n';
                output << "         BIOSStartingSegment: 0x" << std::hex << (int) entry->data.bios.BIOSStartingSegment << std::dec << '\n';
                output << "             BIOSReleaseDate: " << entry->data.bios.BIOSReleaseDate << '\n';
                output << "                 BIOSROMSize: " << (((int) entry->data.bios.BIOSROMSize + 1) * 64) << " KiB \n";
            }
            if (version >= smbios::SMBIOS_2_4)
            {
                output << "      SystemBIOSMajorRelease: " << (int) entry->data.bios.SystemBIOSMajorRelease  << '\n';
                output << "      SystemBIOSMinorRelease: " << (int) entry->data.bios.SystemBIOSMinorRelease  << '\n';
                output << "EmbeddedFirmwareMajorRelease: " << (int) entry->data.bios.EmbeddedFirmwareMajorRelease  << '\n';
                output << "EmbeddedFirmwareMinorRelease: " << (int) entry->data.bios.EmbeddedFirmwareMinorRelease  << '\n';
            }
            output << '\n';
        }
        else
        if (entry->type == DMI_TYPE_SYSINFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                output << "     Manufacturer: " << entry->data.sysinfo.Manufacturer << '\n';
                output << "      ProductName: " << entry->data.sysinfo.ProductName << '\n';
                output << "          Version: " << entry->data.sysinfo.Version << '\n';
                output << "     SerialNumber: " << entry->data.sysinfo.SerialNumber << '\n';
            }
            if (version >= smbios::SMBIOS_2_1)
            {
                output << "             UUID: ";
                for (size_t i = 0; i < 16; ++i)
                    output << std::hex << std::setw(2) << std::setfill('0') << (int) entry->data.sysinfo.UUID[i]  << ' ';
                output << '\n' << std::dec;
            }
            if (version >= smbios::SMBIOS_2_4)
            {
                output << "        SKUNumber: " << entry->data.sysinfo.SKUNumber << '\n';
                output << "           Family: " << entry->data.sysinfo.Family << '\n';
            }
            output << '\n';
        }
        else
        if (entry->type == DMI_TYPE_BASEBOARD)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                output << "     Manufacturer: " << entry->data.baseboard.Manufacturer << '\n';
                output << "          Product: " << entry->data.baseboard.Product << '\n';
                output << "          Version: " << entry->data.baseboard.Version << '\n';
                output << "     SerialNumber: " << entry->data.baseboard.SerialNumber << '\n';
                output << "         AssetTag: " << entry->data.baseboard.AssetTag << '\n';
                output << "LocationInChassis: " << entry->data.baseboard.LocationInChassis << '\n';
                output << "    ChassisHandle: " << entry->data.baseboard.ChassisHandle << '\n';
                output << "        BoardType: " << (int) entry->data.baseboard.BoardType << '\n';
            }
            output << '\n';
        }
        else
        if (entry->type == DMI_TYPE_SYSENCLOSURE)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                output << "     Manufacturer: " << entry->data.sysenclosure.Manufacturer << '\n';
                output << "          Version: " << entry->data.sysenclosure.Version << '\n';
                output << "     SerialNumber: " << entry->data.sysenclosure.SerialNumber << '\n';
                output << "         AssetTag: " << entry->data.sysenclosure.AssetTag << "\n";
            }
            if (version >= smbios::SMBIOS_2_3)
            {
                output << "  Contained Count: " << (int) entry->data.sysenclosure.ContainedElementCount << '\n';
                output << " Contained Length: " << (int) entry->data.sysenclosure.ContainedElementRecordLength << '\n';
            }
            if (version >= smbios::SMBIOS_2_7)
            {
                output << "        SKUNumber: " << entry->data.sysenclosure.SKUNumber << '\n';
            }
            output << '\n';
        }
        else
        if (entry->type == DMI_TYPE_PROCESSOR)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                output << "    SocketDesignation: " << entry->data.processor.SocketDesignation << '\n';
                output << "      ProcessorFamily: " << (int) entry->data.processor.ProcessorFamily << '\n';
                output << "ProcessorManufacturer: " << entry->data.processor.ProcessorManufacturer << '\n';
                output << "     ProcessorVersion: " << entry->data.processor.ProcessorVersion << '\n';
                output << "          ProcessorID: ";
                for (size_t i = 0; i < 8; ++i)
                    output << std::hex << std::setw(2) << std::setfill('0') << (int) entry->data.processor.ProcessorID[i] << ' ';
                output << std::dec << '\n';
            }
            if (version >= smbios::SMBIOS_2_5)
            {
                output << "            CoreCount: " << (int) entry->data.processor.CoreCount << '\n';
                output << "          CoreEnabled: " << (int) entry->data.processor.CoreEnabled << '\n';
                output << "          ThreadCount: " << (int) entry->data.processor.ThreadCount << '\n';
            }
            if (version >= smbios::SMBIOS_2_6)
            {
                output << "     ProcessorFamily2: " << entry->data.processor.ProcessorFamily2 << '\n';
            }
            output << '\n';
        }
        else
        if (entry->type == DMI_TYPE_SYSSLOT)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                output << "    SlotDesignation: " << entry->data.sysslot.SlotDesignation << '\n';
                output << "           SlotType: " << (int) entry->data.sysslot.SlotType << '\n';
                output << "   SlotDataBusWidth: " << (int) entry->data.sysslot.SlotDataBusWidth << '\n';
                output << "             SlotID: " << (int) entry->data.sysslot.SlotID << '\n';
            }
            if (version >= smbios::SMBIOS_2_6)
            {
                output << " SegmentGroupNumber: " << entry->data.sysslot.SegmentGroupNumber << '\n';
                output << "          BusNumber: " << (int) entry->data.sysslot.BusNumber << '\n';
            }
            output << '\n';
        }
        else
        if (entry->type == DMI_TYPE_PHYSMEM)
        {
            if (version >= smbios::SMBIOS_2_1)
            {
                output << "                  Use: 0x" << std::hex << (int) entry->data.physmem.Use << std::dec << '\n';
                output << "        NumberDevices: " << entry->data.physmem.NumberDevices << '\n';
                output << "      MaximumCapacity: " << entry->data.physmem.MaximumCapacity << " KiB\n";
                output << "   ExtMaximumCapacity: " << entry->data.physmem.ExtendedMaximumCapacity << " KiB\n";
            }
            output << '\n';
        }
        else
        if (entry->type == DMI_TYPE_MEMORY)
        {
            if (version >= smbios::SMBIOS_2_1)
            {
                output << "        DeviceLocator: " << entry->data.memory.DeviceLocator << '\n';
                output << "          BankLocator: " << entry->data.memory.BankLocator << '\n';
            }
            if (version >= smbios::SMBIOS_2_3)
            {
                output << "                Speed: " << entry->data.memory.Speed << " MHz\n";
                output << "         Manufacturer: " << entry->data.memory.Manufacturer << '\n';
                output << "         SerialNumber: " << entry->data.memory.SerialNumber << '\n';
                output << "       AssetTagNumber: " << entry->data.memory.AssetTagNumber << '\n';
                output << "           PartNumber: " << entry->data.memory.PartNumber << '\n';
                output << "                 Size: " << entry->data.memory.Size << " MiB\n";
                output << "         ExtendedSize: " << entry->data.memory.ExtendedSize << " MiB\n";
            }
            if (version >= smbios::SMBIOS_2_7)
            {
                output << " ConfiguredClockSpeed: " << entry->data.memory.ConfiguredClockSpeed << " MHz\n";
            }
            output << '\n';
        }
    }

    return true;
}


int main(int argc, char ** argv)
{
    std::vector<uint8_t> buffer;
    #ifdef _WIN32
    if (!getDMI(buffer)) return 1;
    #else
    if (argc != 2) return 1;
    if (!getDMI(argv[1], buffer)) return 1;
    #endif
    smbios::Parser parser(&buffer.front(), buffer.size());
    printSMBIOS(parser, std::cout);

    return 0;
}
