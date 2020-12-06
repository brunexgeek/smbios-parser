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

static void field( std::ostream &out, const std::string &name, const std::string &value )
{
    out << "    " << name << ": " << value << std::endl;
}

static void field( std::ostream &out, const std::string &name, const uint8_t *value, size_t size )
{
    out << "    " << name << ": " << std::hex;
    for (size_t i = 0; i < size; ++i)
        out << std::setw(2) << std::setfill('0') << (int) value[i]  << ' ';
    out << std::dec << std::endl;
}

static void field( std::ostream &out, const std::string &name, uint64_t value )
{
    field(out, name, std::to_string(value));
}

static void hexdump( std::ostream &out, const uint8_t *buffer, size_t size )
{
    static const char *TABS = "        ";
    size_t i = 0;
    out << std::hex << TABS;
    for (; i < size; ++i)
    {
        if (i > 0 && (i % 16) == 0) out << std::endl << TABS;
        out << std::setw(2) << (int) buffer[i] << ' ';
    }
    if (i != 17) out << std::endl;
    out << std::dec;
}

bool printSMBIOS(
    smbios::Parser &parser,
    std::ostream &output )
{
    int version = parser.version();
    const smbios::Entry *entry = nullptr;
    while (true)
    {
        entry = parser.next();
        if (entry == nullptr) break;
        output << "Handle 0x" << std::hex << std::setw(4) << std::setfill('0') << (int) entry->handle << std::dec
            << ", DMI Type " << (int) entry->type << ", " << (int) entry->length << " bytes\n";

        if (entry->type == TYPE_BIOS_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                field(output, "Vendor", entry->data.bios.Vendor);
                field(output, "BIOSVersion", entry->data.bios.BIOSVersion);
                field(output, "BIOSStartingSegment", (int) entry->data.bios.BIOSStartingSegment);
                field(output, "BIOSReleaseDate", entry->data.bios.BIOSReleaseDate);
                field(output, "BIOSROMSize", std::to_string((((int) entry->data.bios.BIOSROMSize + 1) * 64)) + " KiB");
            }
            if (version >= smbios::SMBIOS_2_4)
            {
                field(output, "SystemBIOSMajorRelease", (int) entry->data.bios.SystemBIOSMajorRelease);
                field(output, "SystemBIOSMinorRelease", (int) entry->data.bios.SystemBIOSMinorRelease);
                field(output, "EmbeddedFirmwareMajorRelease", (int) entry->data.bios.EmbeddedFirmwareMajorRelease);
                field(output, "EmbeddedFirmwareMinorRelease", (int) entry->data.bios.EmbeddedFirmwareMinorRelease);
            }
            output << '\n';
        }
        else
        if (entry->type == TYPE_SYSTEM_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                field(output, "Manufacturer", entry->data.sysinfo.Manufacturer);
                field(output, "ProductName", entry->data.sysinfo.ProductName);
                field(output, "Version", entry->data.sysinfo.Version);
                field(output, "SerialNumber", entry->data.sysinfo.SerialNumber);
            }
            if (version >= smbios::SMBIOS_2_1)
            {
                field(output, "UUID", entry->data.sysinfo.UUID, 16);
            }
            if (version >= smbios::SMBIOS_2_4)
            {
                field(output, "SKUNumber", entry->data.sysinfo.SKUNumber);
                field(output, "Family", entry->data.sysinfo.Family);
            }
            output << std::endl;
        }
        else
        if (entry->type == TYPE_BASEBOARD_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                field(output, "Manufacturer", entry->data.baseboard.Manufacturer);
                field(output, "Product", entry->data.baseboard.Product);
                field(output, "Version", entry->data.baseboard.Version);
                field(output, "SerialNumber", entry->data.baseboard.SerialNumber);
                field(output, "AssetTag", entry->data.baseboard.AssetTag);
                field(output, "LocationInChassis", entry->data.baseboard.LocationInChassis);
                field(output, "ChassisHandle", entry->data.baseboard.ChassisHandle);
                field(output, "BoardType", (int) entry->data.baseboard.BoardType);
            }
            output << std::endl;
        }
        else
        if (entry->type == TYPE_SYSTEM_ENCLOSURE)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                field(output, "Manufacturer", entry->data.sysenclosure.Manufacturer);
                field(output, "Version", entry->data.sysenclosure.Version);
                field(output, "SerialNumber", entry->data.sysenclosure.SerialNumber);
                field(output, "AssetTag", entry->data.sysenclosure.AssetTag);
            }
            if (version >= smbios::SMBIOS_2_3)
            {
                field(output, "Contained Count", (int) entry->data.sysenclosure.ContainedElementCount);
                field(output, "Contained Length", (int) entry->data.sysenclosure.ContainedElementRecordLength);
            }
            if (version >= smbios::SMBIOS_2_7)
            {
                field(output, "SKUNumber", entry->data.sysenclosure.SKUNumber);
            }
            output << std::endl;
        }
        else
        if (entry->type == TYPE_PROCESSOR_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                field(output, "SocketDesignation", entry->data.processor.SocketDesignation);
                field(output, "ProcessorFamily", (int) entry->data.processor.ProcessorFamily);
                field(output, "ProcessorManufacturer", entry->data.processor.ProcessorManufacturer);
                field(output, "ProcessorVersion", entry->data.processor.ProcessorVersion);
                field(output, "ProcessorID", entry->data.processor.ProcessorID, 8);
            }
            if (version >= smbios::SMBIOS_2_5)
            {
                field(output, "CoreCount", (int) entry->data.processor.CoreCount);
                field(output, "CoreEnabled", (int) entry->data.processor.CoreEnabled);
                field(output, "ThreadCount", (int) entry->data.processor.ThreadCount);
            }
            if (version >= smbios::SMBIOS_2_6)
            {
                field(output, "ProcessorFamily2", entry->data.processor.ProcessorFamily2);
            }
            output << std::endl;
        }
        else
        if (entry->type == TYPE_SYSTEM_SLOT)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                field(output, "SlotDesignation", entry->data.sysslot.SlotDesignation);
                field(output, "SlotType", (int) entry->data.sysslot.SlotType);
                field(output, "SlotDataBusWidth", (int) entry->data.sysslot.SlotDataBusWidth);
                field(output, "SlotID", (int) entry->data.sysslot.SlotID);
            }
            if (version >= smbios::SMBIOS_2_6)
            {
                field(output, "SegmentGroupNumber", entry->data.sysslot.SegmentGroupNumber);
                field(output, "BusNumber", (int) entry->data.sysslot.BusNumber);
            }
            output << std::endl;
        }
        else
        if (entry->type == TYPE_PHYSICAL_MEMORY_ARRAY)
        {
            if (version >= smbios::SMBIOS_2_1)
            {
                field(output, "Use", (int) entry->data.physmem.Use);
                field(output, "NumberDevices", entry->data.physmem.NumberDevices);
                field(output, "MaximumCapacity", std::to_string(entry->data.physmem.MaximumCapacity) + " KiB");
                field(output, "ExtMaximumCapacity", std::to_string(entry->data.physmem.ExtendedMaximumCapacity) + " KiB");
            }
            output << std::endl;
        }
        else
        if (entry->type == TYPE_MEMORY_DEVICE)
        {
            if (version >= smbios::SMBIOS_2_1)
            {
                field(output, "DeviceLocator", entry->data.memory.DeviceLocator);
                field(output, "BankLocator", entry->data.memory.BankLocator);
            }
            if (version >= smbios::SMBIOS_2_3)
            {
                field(output, "Speed", std::to_string(entry->data.memory.Speed) + " MHz");
                field(output, "Manufacturer", entry->data.memory.Manufacturer);
                field(output, "SerialNumber", entry->data.memory.SerialNumber);
                field(output, "AssetTagNumber", entry->data.memory.AssetTagNumber);
                field(output, "PartNumber", entry->data.memory.PartNumber);
                field(output, "Size", std::to_string(entry->data.memory.Size) + " MiB");
                field(output, "ExtendedSize", std::to_string(entry->data.memory.ExtendedSize) + " MiB");
            }
            if (version >= smbios::SMBIOS_2_7)
            {
                field(output, "ConfiguredClockSpeed", std::to_string(entry->data.memory.ConfiguredClockSpeed) + " MHz");
            }
            output << std::endl;
        }
        else
        if (entry->type == TYPE_OEM_STRINGS)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                field(output, "Count", (int) entry->data.oemstrings.Count);
                output << "    Strings:" << std::endl;
                const char *ptr = entry->data.oemstrings.Values;
                int c = entry->data.oemstrings.Count;
                while (ptr != nullptr && *ptr != 0 && c > 0)
                {
                    output << "        " << ptr << std::endl;
                    while (*ptr != 0) ++ptr;
                    ++ptr;
                }
            }
            output << std::endl;
        }
        else
        if (entry->type == TYPE_PORT_CONNECTOR)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                field(output, "InternalReferenceDesignator", entry->data.portconn.InternalReferenceDesignator);
                field(output, "InternalConnectorType", (int) entry->data.portconn.InternalConnectorType);
                field(output, "ExternalReferenceDesignator", entry->data.portconn.ExternalReferenceDesignator);
                field(output, "ExternalConnectorType", (int) entry->data.portconn.ExternalConnectorType);
                field(output, "PortType", (int) entry->data.portconn.PortType);
            }
            output << std::endl;
        }
        else
        if (entry->type == smbios::TYPE_MEMORY_ARRAY_MAPPED_ADDRESS)
        {
            if (version >= smbios::SMBIOS_2_1)
            {
                field(output, "StartingAddress", entry->data.mamaddr.StartingAddress);
                field(output, "EndingAddress", entry->data.mamaddr.EndingAddress);
                field(output, "MemoryArrayHandle", entry->data.mamaddr.MemoryArrayHandle);
                field(output, "PartitionWidth", (int) entry->data.mamaddr.PartitionWidth);
            }
            if (version >= smbios::SMBIOS_2_7)
            {
                field(output, "ExtendedStartingAddress", entry->data.mamaddr.ExtendedStartingAddress);
                field(output, "ExtendedEndingAddress", entry->data.mamaddr.ExtendedEndingAddress);
            }
            output << std::endl;
        }
        else
        if (entry->type == smbios::TYPE_MEMORY_DEVICE_MAPPED_ADDRESS)
        {
            if (version >= smbios::SMBIOS_2_1)
            {
                field(output, "StartingAddress", entry->data.mdmaddr.StartingAddress);
                field(output, "EndingAddress", entry->data.mdmaddr.EndingAddress);
                field(output, "MemoryArrayHandle", entry->data.mdmaddr.MemoryDeviceHandle);
                field(output, "MemoryArrayMappedAddressHandle", entry->data.mdmaddr.MemoryArrayMappedAddressHandle);
                field(output, "PartitionRowPosition", (int) entry->data.mdmaddr.PartitionRowPosition);
                field(output, "InterleavePosition", (int) entry->data.mdmaddr.InterleavePosition);
                field(output, "InterleavedDataDepth", (int) entry->data.mdmaddr.InterleavedDataDepth);
            }
            if (version >= smbios::SMBIOS_2_7)
            {
                field(output, "ExtendedStartingAddress", entry->data.mdmaddr.ExtendedStartingAddress);
                field(output, "ExtendedEndingAddress", entry->data.mdmaddr.ExtendedEndingAddress);
            }
            output << std::endl;
        }
        else
        if (entry->type == smbios::TYPE_MANAGEMENT_DEVICE)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                field(output, "Description", entry->data.mdev.Description);
                field(output, "Type", (int) entry->data.mdev.Type);
                field(output, "Address", entry->data.mdev.Address);
                field(output, "AddressType", (int) entry->data.mdev.AddressType);
            }
            output << std::endl;
        }
        else
        if (entry->type == smbios::TYPE_MANAGEMENT_DEVICE_COMPONENT)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                field(output, "Description", entry->data.mdcom.Description);
                field(output, "ManagementDeviceHandle", (int) entry->data.mdcom.ManagementDeviceHandle);
                field(output, "ComponentHandle", entry->data.mdcom.ComponentHandle);
                field(output, "ThresholdHandle", (int) entry->data.mdcom.ThresholdHandle);
            }
            output << std::endl;
        }
        else
        if (entry->type == smbios::TYPE_MANAGEMENT_DEVICE_THRESHOLD_DATA)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                field(output, "LowerThresholdNonCritical", entry->data.mdtdata.LowerThresholdNonCritical);
                field(output, "UpperThresholdNonCritical", entry->data.mdtdata.UpperThresholdNonCritical);
                field(output, "LowerThresholdCritical", entry->data.mdtdata.LowerThresholdCritical);
                field(output, "UpperThresholdCritical", entry->data.mdtdata.UpperThresholdCritical);
                field(output, "LowerThresholdNonRecoverable", entry->data.mdtdata.LowerThresholdNonRecoverable);
                field(output, "UpperThresholdNonRecoverable", entry->data.mdtdata.UpperThresholdNonRecoverable);
            }
            output << std::endl;
        }
        else
        if (entry->type == smbios::TYPE_ONBOARD_DEVICES_EXTENDED_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                field(output, "ReferenceDesignation", entry->data.odeinfo.ReferenceDesignation);
                field(output, "DeviceType", (int) entry->data.odeinfo.DeviceType);
                field(output, "DeviceTypeInstance", (int) entry->data.odeinfo.DeviceTypeInstance);
                field(output, "SegmentGroupNumber", entry->data.odeinfo.SegmentGroupNumber);
                field(output, "BusNumber", (int) entry->data.odeinfo.BusNumber);
                field(output, "DeviceOrFunctionNumber", (int) entry->data.odeinfo.DeviceOrFunctionNumber);
            }
            output << std::endl;
        }
        else
        if (entry->type == smbios::TYPE_SYSTEM_BOOT_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                output << " BootStatus: " << (int) entry->length <<  std::setfill('0') << std::endl;
                if ((entry->length - 10) > 0)
                {
                    int i = 0;
                    output << std::hex;
                    for (; i < (entry->length - 10); ++i)
                    {
                        if (i > 0 && (i % 16) == 0) output << std::endl;
                        output << std::setw(2) << (int)entry->data.bootinfo.BootStatus[i] << ' ';
                    }
                    if ((i % 16) != 0) output << std::endl;
                    output << std::dec;
                }
            }
            output << std::endl;
        }
        else
        {
            field(output, "Header and data", "");
            if (entry->length > 0)
            {
                hexdump(output, entry->rawdata, entry->length);
            }

            const char *str = entry->strings;
            if (*str != 0)
            {
                field(output, "Strings", "");
                while (*str != 0)
                {
                    output << "        " << str << std::endl;
                    while (*str != 0) ++str;
                    ++str;
                }
            }

            output << std::endl;
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

    smbios::Parser parser(buffer.data(), buffer.size());
    if (parser.valid())
        printSMBIOS(parser, std::cout);
    else
        std::cerr << "Invalid SMBIOS data" << std::endl;

    return 0;
}
