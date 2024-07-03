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

using namespace smbios;

#ifdef _WIN32

#include <Windows.h>

static bool getDMI( std::vector<uint8_t> &buffer )
{
    const BYTE byteSignature[] = { 'B', 'M', 'S', 'R' };
    const DWORD signature = *((DWORD*)byteSignature);

    // get the size of SMBIOS table
    DWORD size = GetSystemFirmwareTable(signature, 0, nullptr, 0);
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

static bool getDMI( const std::string &path, std::vector<uint8_t> &buffer )
{
    std::ifstream input;
    std::string fileName;

    // get the SMBIOS structures size
    fileName = path + "/DMI";
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

static void hexdump( FILE *output, const uint8_t *buffer, size_t size )
{
    size_t i = 0;
    fputs("\t\t", output);
    for (; i < size; ++i)
    {
        if (i > 0 && (i % 16) == 0)
            fputs("\n\t\t", output);
        fprintf(output, "%02X ", (int) buffer[i]);
    }
    if (i != 17)
        fputs("\n", output);
}

bool printSMBIOS( ParserContext *parser, FILE *output )
{
    int version = smbios_get_version(parser);
    const smbios::Entry *entry = nullptr;
    while (true)
    {
        if (smbios_next(parser, &entry) != SMBERR_OK)
            break;

        fprintf(output, "Handle 0x%04X, DMI type %d, %d bytes\n", (int) entry->handle, (int) entry->type, (int) entry->length);

        if (entry->type == TYPE_BIOS_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "Vendor: %s\n", entry->data.bios.Vendor);
                fprintf(output, "BIOSVersion: %s\n", entry->data.bios.BIOSVersion);
                fprintf(output, "BIOSStartingSegment: %X\n", (int) entry->data.bios.BIOSStartingSegment);
                fprintf(output, "BIOSReleaseDate: %s\n", entry->data.bios.BIOSReleaseDate);
                fprintf(output, "BIOSROMSize: %d KiB\n", ((int) entry->data.bios.BIOSROMSize + 1) * 64);
            }
            if (version >= smbios::SMBIOS_2_4)
            {
                fprintf(output, "SystemBIOSMajorRelease: %d\n", (int) entry->data.bios.SystemBIOSMajorRelease);
                fprintf(output, "SystemBIOSMinorRelease: %d\n", (int) entry->data.bios.SystemBIOSMinorRelease);
                fprintf(output, "EmbeddedFirmwareMajorRelease: %d\n", (int) entry->data.bios.EmbeddedFirmwareMajorRelease);
                fprintf(output, "EmbeddedFirmwareMinorRelease: %d\n", (int) entry->data.bios.EmbeddedFirmwareMinorRelease);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_SYSTEM_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "Manufacturer: %s\n", entry->data.sysinfo.Manufacturer);
                fprintf(output, "ProductName: %s\n", entry->data.sysinfo.ProductName);
                fprintf(output, "Version: %s\n", entry->data.sysinfo.Version);
                fprintf(output, "SerialNumber: %s\n", entry->data.sysinfo.SerialNumber);
            }
            if (version >= smbios::SMBIOS_2_1)
            {
                fputs("UUID:", output);
                for (int i = 0; i < 16; ++i)
                    fprintf(output, " %02X", entry->data.sysinfo.UUID[i]);
                fputs("\n", output);
            }
            if (version >= smbios::SMBIOS_2_4)
            {
                fprintf(output, "SKUNumber: %s\n", entry->data.sysinfo.SKUNumber);
                fprintf(output, "Family: %s\n", entry->data.sysinfo.Family);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_BASEBOARD_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "Manufacturer: %s\n", entry->data.baseboard.Manufacturer);
                fprintf(output, "Product Name: %s\n", entry->data.baseboard.Product);
                fprintf(output, "Version: %s\n", entry->data.baseboard.Version);
                fprintf(output, "Serial Number: %s\n", entry->data.baseboard.SerialNumber);
                fprintf(output, "Asset Tag: %s\n", entry->data.baseboard.AssetTag);
                fprintf(output, "Location In Chassis: %s\n", entry->data.baseboard.LocationInChassis);
                fprintf(output, "Chassis Handle: %d\n", entry->data.baseboard.ChassisHandle);
                fprintf(output, "Type: %d\n", (int) entry->data.baseboard.BoardType);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_SYSTEM_ENCLOSURE)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "Manufacturer: %s\n", entry->data.sysenclosure.Manufacturer);
                fprintf(output, "Version: %s\n", entry->data.sysenclosure.Version);
                fprintf(output, "SerialNumber: %s\n", entry->data.sysenclosure.SerialNumber);
                fprintf(output, "AssetTag: %s\n", entry->data.sysenclosure.AssetTag);
            }
            if (version >= smbios::SMBIOS_2_3)
            {
                fprintf(output, "ContainedCount: %d\n", (int) entry->data.sysenclosure.ContainedElementCount);
                fprintf(output, "ContainedLength: %d\n", (int) entry->data.sysenclosure.ContainedElementRecordLength);
            }
            if (version >= smbios::SMBIOS_2_7)
            {
                fprintf(output, "SKUNumber: %s\n", entry->data.sysenclosure.SKUNumber);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_PROCESSOR_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "SocketDesignation: %s\n", entry->data.processor.SocketDesignation);
                fprintf(output, "ProcessorFamily: %d\n", (int) entry->data.processor.ProcessorFamily);
                fprintf(output, "ProcessorManufacturer: %s\n", entry->data.processor.ProcessorManufacturer);
                fprintf(output, "ProcessorVersion: %s\n", entry->data.processor.ProcessorVersion);
                fputs("ProcessorID:", output);
                for (int i = 0; i < 8; ++i)
                    fprintf(output, " %c\n", entry->data.processor.ProcessorID[i]);
                fputs("\n", output);
            }
            if (version >= smbios::SMBIOS_2_5)
            {
                fprintf(output, "CoreCount: %d\n", (int) entry->data.processor.CoreCount);
                fprintf(output, "CoreEnabled: %d\n", (int) entry->data.processor.CoreEnabled);
                fprintf(output, "ThreadCount: %d\n", (int) entry->data.processor.ThreadCount);
            }
            if (version >= smbios::SMBIOS_2_6)
            {
                fprintf(output, "ProcessorFamily2: %d\n", entry->data.processor.ProcessorFamily2);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_SYSTEM_SLOT)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "SlotDesignation: %s\n", entry->data.sysslot.SlotDesignation);
                fprintf(output, "SlotType: %d\n", (int) entry->data.sysslot.SlotType);
                fprintf(output, "SlotDataBusWidth: %d\n", (int) entry->data.sysslot.SlotDataBusWidth);
                fprintf(output, "SlotID: %d\n", (int) entry->data.sysslot.SlotID);
            }
            if (version >= smbios::SMBIOS_2_6)
            {
                fprintf(output, "SegmentGroupNumber: %d\n", entry->data.sysslot.SegmentGroupNumber);
                fprintf(output, "BusNumber: %d\n", (int) entry->data.sysslot.BusNumber);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_PHYSICAL_MEMORY_ARRAY)
        {
            if (version >= smbios::SMBIOS_2_1)
            {
                fprintf(output, "Use: %d\n", (int) entry->data.physmem.Use);
                fprintf(output, "NumberDevices: %d\n", entry->data.physmem.NumberDevices);
                fprintf(output, "MaximumCapacity: %d KiB\n", entry->data.physmem.MaximumCapacity);
                fprintf(output, "ExtMaximumCapacity: %ld KiB\n", entry->data.physmem.ExtendedMaximumCapacity);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_MEMORY_DEVICE)
        {
            if (version >= smbios::SMBIOS_2_1)
            {
                fprintf(output, "DeviceLocator: %s\n", entry->data.memory.DeviceLocator);
                fprintf(output, "BankLocator: %s\n", entry->data.memory.BankLocator);
            }
            if (version >= smbios::SMBIOS_2_3)
            {
                fprintf(output, "Speed: %d MHz\n", entry->data.memory.Speed);
                fprintf(output, "Manufacturer: %s\n", entry->data.memory.Manufacturer);
                fprintf(output, "SerialNumber: %s\n", entry->data.memory.SerialNumber);
                fprintf(output, "AssetTagNumber: %s\n", entry->data.memory.AssetTagNumber);
                fprintf(output, "PartNumber: %s\n", entry->data.memory.PartNumber);
                fprintf(output, "Size: %d MiB\n", entry->data.memory.Size);
                fprintf(output, "ExtendedSize: %d MiB\n", entry->data.memory.ExtendedSize);
            }
            if (version >= smbios::SMBIOS_2_7)
            {
                fprintf(output, "ConfiguredClockSpeed: %d\n", entry->data.memory.ConfiguredClockSpeed);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_OEM_STRINGS)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "Count: %d\n", (int) entry->data.oemstrings.Count);
                fputs("\tStrings:\n", output);
                const char *ptr = entry->data.oemstrings.Values;
                int c = entry->data.oemstrings.Count;
                while (ptr != nullptr && *ptr != 0 && c > 0) // TODO: replace with 'smbios_get_string'
                {
                    fprintf(output, "\t\t%s\n", ptr);
                    while (*ptr != 0) ++ptr;
                    ++ptr;
                }
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_PORT_CONNECTOR)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "InternalReferenceDesignator: %s\n", entry->data.portconn.InternalReferenceDesignator);
                fprintf(output, "InternalConnectorType: %d\n", (int) entry->data.portconn.InternalConnectorType);
                fprintf(output, "ExternalReferenceDesignator: %s\n", entry->data.portconn.ExternalReferenceDesignator);
                fprintf(output, "ExternalConnectorType: %d\n", (int) entry->data.portconn.ExternalConnectorType);
                fprintf(output, "PortType: %d\n", (int) entry->data.portconn.PortType);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == smbios::TYPE_MEMORY_ARRAY_MAPPED_ADDRESS)
        {
            if (version >= smbios::SMBIOS_2_1)
            {
                fprintf(output, "StartingAddress: %0X\n", entry->data.mamaddr.StartingAddress);
                fprintf(output, "EndingAddress: %0X\n", entry->data.mamaddr.EndingAddress);
                fprintf(output, "MemoryArrayHandle: %0X\n", entry->data.mamaddr.MemoryArrayHandle);
                fprintf(output, "PartitionWidth: %0X\n", (int) entry->data.mamaddr.PartitionWidth);
            }
            if (version >= smbios::SMBIOS_2_7)
            {
                fprintf(output, "ExtendedStartingAddress: %lX\n", entry->data.mamaddr.ExtendedStartingAddress);
                fprintf(output, "ExtendedEndingAddress: %lX\n", entry->data.mamaddr.ExtendedEndingAddress);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == smbios::TYPE_MEMORY_DEVICE_MAPPED_ADDRESS)
        {
            if (version >= smbios::SMBIOS_2_1)
            {
                fprintf(output, "StartingAddress: %d\n", entry->data.mdmaddr.StartingAddress);
                fprintf(output, "EndingAddress: %d\n", entry->data.mdmaddr.EndingAddress);
                fprintf(output, "MemoryArrayHandle: %d\n", entry->data.mdmaddr.MemoryDeviceHandle);
                fprintf(output, "MemoryArrayMappedAddressHandle: %d\n", entry->data.mdmaddr.MemoryArrayMappedAddressHandle);
                fprintf(output, "PartitionRowPosition: %d\n", (int) entry->data.mdmaddr.PartitionRowPosition);
                fprintf(output, "InterleavePosition: %d\n", (int) entry->data.mdmaddr.InterleavePosition);
                fprintf(output, "InterleavedDataDepth: %d\n", (int) entry->data.mdmaddr.InterleavedDataDepth);
            }
            if (version >= smbios::SMBIOS_2_7)
            {
                fprintf(output, "ExtendedStartingAddress: %ld\n", entry->data.mdmaddr.ExtendedStartingAddress);
                fprintf(output, "ExtendedEndingAddress: %ld\n", entry->data.mdmaddr.ExtendedEndingAddress);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == smbios::TYPE_MANAGEMENT_DEVICE)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "Description: %s\n", entry->data.mdev.Description);
                fprintf(output, "Type: %d\n", (int) entry->data.mdev.Type);
                fprintf(output, "Address: %d\n", entry->data.mdev.Address);
                fprintf(output, "AddressType: %d\n", (int) entry->data.mdev.AddressType);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == smbios::TYPE_MANAGEMENT_DEVICE_COMPONENT)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "Description: %s\n", entry->data.mdcom.Description);
                fprintf(output, "ManagementDeviceHandle: %d\n", (int) entry->data.mdcom.ManagementDeviceHandle);
                fprintf(output, "ComponentHandle: %d\n", entry->data.mdcom.ComponentHandle);
                fprintf(output, "ThresholdHandle: %d\n", (int) entry->data.mdcom.ThresholdHandle);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == smbios::TYPE_MANAGEMENT_DEVICE_THRESHOLD_DATA)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "LowerThresholdNonCritical: %d\n", entry->data.mdtdata.LowerThresholdNonCritical);
                fprintf(output, "UpperThresholdNonCritical: %d\n", entry->data.mdtdata.UpperThresholdNonCritical);
                fprintf(output, "LowerThresholdCritical: %d\n", entry->data.mdtdata.LowerThresholdCritical);
                fprintf(output, "UpperThresholdCritical: %d\n", entry->data.mdtdata.UpperThresholdCritical);
                fprintf(output, "LowerThresholdNonRecoverable: %d\n", entry->data.mdtdata.LowerThresholdNonRecoverable);
                fprintf(output, "UpperThresholdNonRecoverable: %d\n", entry->data.mdtdata.UpperThresholdNonRecoverable);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == smbios::TYPE_ONBOARD_DEVICES_EXTENDED_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "ReferenceDesignation: %s\n", entry->data.odeinfo.ReferenceDesignation);
                fprintf(output, "DeviceType: %d\n", (int) entry->data.odeinfo.DeviceType);
                fprintf(output, "DeviceTypeInstance: %d\n", (int) entry->data.odeinfo.DeviceTypeInstance);
                fprintf(output, "SegmentGroupNumber: %d\n", entry->data.odeinfo.SegmentGroupNumber);
                fprintf(output, "BusNumber: %d\n", (int) entry->data.odeinfo.BusNumber);
                fprintf(output, "DeviceOrFunctionNumber: %d\n", (int) entry->data.odeinfo.DeviceOrFunctionNumber);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == smbios::TYPE_SYSTEM_BOOT_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "BootStatus:\n");
                if ((entry->length - 10) > 0)
                {
                    int i = 0;
                    for (; i < (entry->length - 10); ++i)
                    {
                        if (i > 0 && (i % 16) == 0)
                            fputs("\n", output);
                        fprintf(output, "%02X ", (int)entry->data.bootinfo.BootStatus[i]);
                    }
                    if ((i % 16) != 0)
                        fputs("\n", output);
                }
            }
            fputs("\n", output);
        }
        else
        {
            fputs("\tHeader and data:\n", output);
            if (entry->length > 0)
            {
                hexdump(output, entry->rawdata, entry->length);
            }

            const char *str = entry->strings;
            if (*str != 0)
            {
                fputs("\tStrings:\n", output);
                while (*str != 0)
                {
                    fprintf(output, "\t\t%s\n", str);
                    while (*str != 0) ++str;
                    ++str;
                }
            }

            fputs("\n", output);
        }
    }

    return true;
}

int main(int argc, char ** argv)
{
    std::vector<uint8_t> buffer;
    bool result = false;

    #ifdef _WIN32

    result = getDMI(buffer);

    #else

    const char *path = "/sys/firmware/dmi/tables";
    if (argc == 2) path = argv[1];
    std::cerr << "Using SMBIOS tables from " << path << std::endl;
    result = getDMI(path, buffer);

    #endif

    if (!result)
    {
        std::cerr << "Unable to open SMBIOS tables" << std::endl;
        return 1;
    }

    ParserContext parser;
    if (smbios_initialize(&parser, buffer.data(), buffer.size(), SMBIOS_3_0) == SMBERR_OK)
        printSMBIOS(&parser, stdout);
    else
        std::cerr << "Invalid SMBIOS data" << std::endl;

    return 0;
}
