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

const uint8_t s_malformedBiosBytes[] = {
0x00, 0x02, 0x07, 0x00, 0xDC, 0x02, 0x00, 0x18, 0x00, 0x00, 0x01, 0x02, 0x00, 0xE0, 0x03, 0x2F,
0x80, 0x9A, 0x09, 0x48, 0x00, 0x00, 0x00, 0x00, 0x83, 0x0F, 0x02, 0x1E, 0x02, 0x1E, 0x49, 0x6E,
0x73, 0x79, 0x64, 0x65, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x2E, 0x00, 0x52, 0x30, 0x32, 0x33, 0x30,
0x44, 0x41, 0x00, 0x30, 0x32, 0x2F, 0x32, 0x34, 0x2F, 0x32, 0x30, 0x31, 0x35, 0x00, 0x00, 0x01,
0x1B, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x40, 0xC5, 0xF0, 0x20, 0x2A, 0xE1, 0x3A, 0x12, 0xAA,
0xA8, 0x30, 0xF9, 0xED, 0xA4, 0x54, 0xA6, 0x06, 0x05, 0x06, 0x53, 0x6F, 0x6E, 0x79, 0x20, 0x43,
0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x53, 0x56, 0x46, 0x31, 0x35,
0x32, 0x31, 0x33, 0x43, 0x42, 0x42, 0x00, 0x43, 0x38, 0x30, 0x31, 0x4A, 0x44, 0x57, 0x59, 0x00,
0x35, 0x34, 0x35, 0x37, 0x37, 0x30, 0x38, 0x36, 0x2D, 0x30, 0x30, 0x33, 0x36, 0x34, 0x30, 0x39,
0x00, 0x35, 0x34, 0x35, 0x37, 0x37, 0x30, 0x38, 0x36, 0x00, 0x56, 0x41, 0x49, 0x4F, 0x00, 0x00,
0x02, 0x0A, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x53, 0x6F, 0x6E, 0x79, 0x20, 0x43,
0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x56, 0x41, 0x49, 0x4F, 0x00,
0x4E, 0x2F, 0x41, 0x00, 0x4E, 0x2F, 0x41, 0x00, 0x4E, 0x2F, 0x41, 0x00, 0x00, 0x03, 0x11, 0x03,
0x00, 0x01, 0x0A, 0x02, 0x03, 0x04, 0x03, 0x03, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x53, 0x6F,
0x6E, 0x79, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x4E,
0x2F, 0x41, 0x00, 0x4E, 0x2F, 0x41, 0x00, 0x4E, 0x2F, 0x41, 0x00, 0x00, 0x04, 0x28, 0x04, 0x00,
0x04, 0x03, 0xCD, 0x02, 0xA9, 0x06, 0x03, 0x00, 0xFF, 0xFB, 0xEB, 0xBF, 0x01, 0x8C, 0x64, 0x00,
0x08, 0x07, 0x08, 0x07, 0x41, 0x06, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x03, 0x05, 0x06, 0x02,
0x02, 0x04, 0xFC, 0x00, 0x49, 0x6E, 0x74, 0x65, 0x6C, 0x28, 0x52, 0x29, 0x20, 0x43, 0x6F, 0x72,
0x65, 0x28, 0x54, 0x4D, 0x29, 0x20, 0x69, 0x35, 0x2D, 0x33, 0x33, 0x33, 0x37, 0x55, 0x20, 0x43,
0x50, 0x55, 0x20, 0x40, 0x20, 0x31, 0x2E, 0x38, 0x30, 0x47, 0x48, 0x7A, 0x00, 0x49, 0x6E, 0x74,
0x65, 0x6C, 0x28, 0x52, 0x29, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F,
0x6E, 0x00, 0x4E, 0x2F, 0x41, 0x00, 0x4E, 0x2F, 0x41, 0x00, 0x4E, 0x2F, 0x41, 0x00, 0x4E, 0x2F,
0x41, 0x00, 0x00, 0x07, 0x13, 0x05, 0x00, 0x01, 0x80, 0x00, 0x80, 0x00, 0x80, 0x00, 0x02, 0x00,
0x02, 0x00, 0x00, 0x04, 0x04, 0x07, 0x4C, 0x31, 0x20, 0x43, 0x61, 0x63, 0x68, 0x65, 0x00, 0x00,
0x07, 0x13, 0x06, 0x00, 0x01, 0x81, 0x00, 0x00, 0x02, 0x00, 0x02, 0x02, 0x00, 0x02, 0x00, 0x00,
0x06, 0x05, 0x07, 0x4C, 0x32, 0x20, 0x43, 0x61, 0x63, 0x68, 0x65, 0x00, 0x00, 0x07, 0x13, 0x07,
0x00, 0x01, 0x82, 0x01, 0x30, 0x80, 0x30, 0x80, 0x02, 0x00, 0x02, 0x00, 0x00, 0x06, 0x05, 0x09,
0x4C, 0x33, 0x20, 0x43, 0x61, 0x63, 0x68, 0x65, 0x00, 0x00, 0x0B, 0x05, 0x08, 0x00, 0x05, 0x31,
0x31, 0x31, 0x31, 0x37, 0x37, 0x34, 0x32, 0x39, 0x35, 0x58, 0x00, 0x46, 0x4E, 0x43, 0x2D, 0x45,
0x58, 0x54, 0x42, 0x45, 0x53, 0x44, 0x4C, 0x00, 0x42, 0x55, 0x36, 0x34, 0x33, 0x36, 0x63, 0x66,
0x35, 0x48, 0x4B, 0x78, 0x51, 0x51, 0x57, 0x66, 0x44, 0x77, 0x69, 0x6B, 0x67, 0x41, 0x73, 0x4B,
0x40, 0x6F, 0x30, 0x6B, 0x52, 0x33, 0x5A, 0x38, 0x31, 0x4C, 0x45, 0x73, 0x63, 0x66, 0x41, 0x48,
0x4B, 0x78, 0x51, 0x51, 0x63, 0x66, 0x35, 0x4A, 0x6A, 0x78, 0x00, 0x52, 0x65, 0x73, 0x65, 0x72,
0x76, 0x65, 0x64, 0x00, 0x38, 0x2E, 0x31, 0x2E, 0x33, 0x2E, 0x31, 0x33, 0x32, 0x35, 0x00, 0x00,
0x10, 0x0F, 0x09, 0x00, 0x03, 0x03, 0x03, 0x00, 0x00, 0x00, 0x80, 0xFE, 0xFF, 0x02, 0x00, 0x00,
0x00, 0x11, 0x15, 0x0A, 0x00, 0x09, 0x00, 0xFE, 0xFF, 0x40, 0x00, 0x40, 0x00, 0x00, 0x10, 0x0D,
0x00, 0x01, 0x02, 0x18, 0x04, 0x00, 0x53, 0x4F, 0x44, 0x49, 0x4D, 0x4D, 0x31, 0x00, 0x42, 0x61,
0x6E, 0x6B, 0x20, 0x30, 0x00, 0x00, 0x11, 0x15, 0x0B, 0x00, 0x09, 0x00, 0xFE, 0xFF, 0x40, 0x00,
0x40, 0x00, 0x00, 0x10, 0x0D, 0x00, 0x01, 0x02, 0x18, 0x04, 0x00, 0x53, 0x4F, 0x44, 0x49, 0x4D,
0x4D, 0x32, 0x00, 0x42, 0x61, 0x6E, 0x6B, 0x20, 0x31, 0x00, 0x00, 0x13, 0x0F, 0x0C, 0x00, 0x00,
0x00, 0x00, 0x00, 0xFF, 0xFF, 0x7F, 0x00, 0x09, 0x00, 0x02, 0x00, 0x00, 0x14, 0x13, 0x0D, 0x00,
0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x3F, 0x00, 0x0A, 0x00, 0x0C, 0x00, 0xFF, 0xFF, 0xFF, 0x00,
0x00, 0x14, 0x13, 0x0E, 0x00, 0x00, 0x00, 0x40, 0x00, 0xFF, 0xFF, 0x7F, 0x00, 0x0B, 0x00, 0x0C,
0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x20, 0x14, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F, 0x04, 0x10, 0x00,
0x00, 0x00, 0x00, 0x00 };

static bool getDMI( const std::string &path, std::vector<uint8_t> &buffer )
{
    std::ifstream input;
    std::string fileName;

    // get the SMBIOS structures size
#if 1
    fileName = path + "/DMI";
    struct stat info;
    if (stat(fileName.c_str(), &info) != 0) return false;
    buffer.resize(info.st_size + 32);

    // read SMBIOS structures
    input.open(fileName.c_str(), std::ios_base::binary);
    if (!input.good()) return false;
    input.read((char*) buffer.data() + 32, info.st_size);
    input.close();
#else
    buffer.resize(sizeof(s_malformedBiosBytes) + 32);
    memcpy(buffer.data() + 32, s_malformedBiosBytes, sizeof(s_malformedBiosBytes));
#endif

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
                fprintf(output, "\tVendor: %s\n", entry->data.bios.Vendor);
                fprintf(output, "\tBIOSVersion: %s\n", entry->data.bios.BIOSVersion);
                fprintf(output, "\tBIOSStartingSegment: %X\n", (int) entry->data.bios.BIOSStartingSegment);
                fprintf(output, "\tBIOSReleaseDate: %s\n", entry->data.bios.BIOSReleaseDate);
                fprintf(output, "\tBIOSROMSize: %d KiB\n", ((int) entry->data.bios.BIOSROMSize + 1) * 64);
            }
            if (version >= smbios::SMBIOS_2_4)
            {
                fprintf(output, "\tSystemBIOSMajorRelease: %d\n", (int) entry->data.bios.SystemBIOSMajorRelease);
                fprintf(output, "\tSystemBIOSMinorRelease: %d\n", (int) entry->data.bios.SystemBIOSMinorRelease);
                fprintf(output, "\tEmbeddedFirmwareMajorRelease: %d\n", (int) entry->data.bios.EmbeddedFirmwareMajorRelease);
                fprintf(output, "\tEmbeddedFirmwareMinorRelease: %d\n", (int) entry->data.bios.EmbeddedFirmwareMinorRelease);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_SYSTEM_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "\tManufacturer: %s\n", entry->data.sysinfo.Manufacturer);
                fprintf(output, "\tProductName: %s\n", entry->data.sysinfo.ProductName);
                fprintf(output, "\tVersion: %s\n", entry->data.sysinfo.Version);
                fprintf(output, "\tSerialNumber: %s\n", entry->data.sysinfo.SerialNumber);
            }
            if (version >= smbios::SMBIOS_2_1)
            {
                fputs("\tUUID:", output);
                for (int i = 0; i < 16; ++i)
                    fprintf(output, " %02X", entry->data.sysinfo.UUID[i]);
                fputs("\n", output);
            }
            if (version >= smbios::SMBIOS_2_4)
            {
                fprintf(output, "\tSKUNumber: %s\n", entry->data.sysinfo.SKUNumber);
                fprintf(output, "\tFamily: %s\n", entry->data.sysinfo.Family);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_BASEBOARD_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "\tManufacturer: %s\n", entry->data.baseboard.Manufacturer);
                fprintf(output, "\tProduct Name: %s\n", entry->data.baseboard.Product);
                fprintf(output, "\tVersion: %s\n", entry->data.baseboard.Version);
                fprintf(output, "\tSerial Number: %s\n", entry->data.baseboard.SerialNumber);
                fprintf(output, "\tAsset Tag: %s\n", entry->data.baseboard.AssetTag);
                fprintf(output, "\tLocation In Chassis: %s\n", entry->data.baseboard.LocationInChassis);
                fprintf(output, "\tChassis Handle: %d\n", entry->data.baseboard.ChassisHandle);
                fprintf(output, "\tType: %d\n", (int) entry->data.baseboard.BoardType);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_SYSTEM_ENCLOSURE)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "\tManufacturer: %s\n", entry->data.sysenclosure.Manufacturer);
                fprintf(output, "\tVersion: %s\n", entry->data.sysenclosure.Version);
                fprintf(output, "\tSerialNumber: %s\n", entry->data.sysenclosure.SerialNumber);
                fprintf(output, "\tAssetTag: %s\n", entry->data.sysenclosure.AssetTag);
            }
            if (version >= smbios::SMBIOS_2_3)
            {
                fprintf(output, "\tContainedCount: %d\n", (int) entry->data.sysenclosure.ContainedElementCount);
                fprintf(output, "\tContainedLength: %d\n", (int) entry->data.sysenclosure.ContainedElementRecordLength);
            }
            if (version >= smbios::SMBIOS_2_7)
            {
                fprintf(output, "\tSKUNumber: %s\n", entry->data.sysenclosure.SKUNumber);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_PROCESSOR_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "\tSocketDesignation: %s\n", entry->data.processor.SocketDesignation);
                fprintf(output, "\tProcessorFamily: %d\n", (int) entry->data.processor.ProcessorFamily);
                fprintf(output, "\tProcessorManufacturer: %s\n", entry->data.processor.ProcessorManufacturer);
                fprintf(output, "\tProcessorVersion: %s\n", entry->data.processor.ProcessorVersion);
                fputs("ProcessorID:", output);
                for (int i = 0; i < 8; ++i)
                    fprintf(output, " %02X", entry->data.processor.ProcessorID[i]);
                fputs("\n", output);
            }
            if (version >= smbios::SMBIOS_2_5)
            {
                fprintf(output, "\tCoreCount: %d\n", (int) entry->data.processor.CoreCount);
                fprintf(output, "\tCoreEnabled: %d\n", (int) entry->data.processor.CoreEnabled);
                fprintf(output, "\tThreadCount: %d\n", (int) entry->data.processor.ThreadCount);
            }
            if (version >= smbios::SMBIOS_2_6)
            {
                fprintf(output, "\tProcessorFamily2: %d\n", entry->data.processor.ProcessorFamily2);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_SYSTEM_SLOT)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "\tSlotDesignation: %s\n", entry->data.sysslot.SlotDesignation);
                fprintf(output, "\tSlotType: %d\n", (int) entry->data.sysslot.SlotType);
                fprintf(output, "\tSlotDataBusWidth: %d\n", (int) entry->data.sysslot.SlotDataBusWidth);
                fprintf(output, "\tSlotID: %d\n", (int) entry->data.sysslot.SlotID);
            }
            if (version >= smbios::SMBIOS_2_6)
            {
                fprintf(output, "\tSegmentGroupNumber: %d\n", entry->data.sysslot.SegmentGroupNumber);
                fprintf(output, "\tBusNumber: %d\n", (int) entry->data.sysslot.BusNumber);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_PHYSICAL_MEMORY_ARRAY)
        {
            if (version >= smbios::SMBIOS_2_1)
            {
                fprintf(output, "\tUse: %d\n", (int) entry->data.physmem.Use);
                fprintf(output, "\tNumberDevices: %d\n", entry->data.physmem.NumberDevices);
                fprintf(output, "\tMaximumCapacity: %d KiB\n", entry->data.physmem.MaximumCapacity);
                fprintf(output, "\tExtMaximumCapacity: %ld KiB\n", entry->data.physmem.ExtendedMaximumCapacity);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_MEMORY_DEVICE)
        {
            if (version >= smbios::SMBIOS_2_1)
            {
                fprintf(output, "\tDeviceLocator: %s\n", entry->data.memory.DeviceLocator);
                fprintf(output, "\tBankLocator: %s\n", entry->data.memory.BankLocator);
            }
            if (version >= smbios::SMBIOS_2_3)
            {
                fprintf(output, "\tSpeed: %d MHz\n", entry->data.memory.Speed);
                fprintf(output, "\tManufacturer: %s\n", entry->data.memory.Manufacturer);
                fprintf(output, "\tSerialNumber: %s\n", entry->data.memory.SerialNumber);
                fprintf(output, "\tAssetTagNumber: %s\n", entry->data.memory.AssetTagNumber);
                fprintf(output, "\tPartNumber: %s\n", entry->data.memory.PartNumber);
                fprintf(output, "\tSize: %d MiB\n", entry->data.memory.Size);
                fprintf(output, "\tExtendedSize: %d MiB\n", entry->data.memory.ExtendedSize);
            }
            if (version >= smbios::SMBIOS_2_7)
            {
                fprintf(output, "\tConfiguredClockSpeed: %d\n", entry->data.memory.ConfiguredClockSpeed);
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
                fprintf(output, "\tInternalReferenceDesignator: %s\n", entry->data.portconn.InternalReferenceDesignator);
                fprintf(output, "\tInternalConnectorType: %d\n", (int) entry->data.portconn.InternalConnectorType);
                fprintf(output, "\tExternalReferenceDesignator: %s\n", entry->data.portconn.ExternalReferenceDesignator);
                fprintf(output, "\tExternalConnectorType: %d\n", (int) entry->data.portconn.ExternalConnectorType);
                fprintf(output, "\tPortType: %d\n", (int) entry->data.portconn.PortType);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == smbios::TYPE_MEMORY_ARRAY_MAPPED_ADDRESS)
        {
            if (version >= smbios::SMBIOS_2_1)
            {
                fprintf(output, "\tStartingAddress: %0X\n", entry->data.mamaddr.StartingAddress);
                fprintf(output, "\tEndingAddress: %0X\n", entry->data.mamaddr.EndingAddress);
                fprintf(output, "\tMemoryArrayHandle: %0X\n", entry->data.mamaddr.MemoryArrayHandle);
                fprintf(output, "\tPartitionWidth: %0X\n", (int) entry->data.mamaddr.PartitionWidth);
            }
            if (version >= smbios::SMBIOS_2_7)
            {
                fprintf(output, "\tExtendedStartingAddress: %lX\n", entry->data.mamaddr.ExtendedStartingAddress);
                fprintf(output, "\tExtendedEndingAddress: %lX\n", entry->data.mamaddr.ExtendedEndingAddress);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == smbios::TYPE_MEMORY_DEVICE_MAPPED_ADDRESS)
        {
            if (version >= smbios::SMBIOS_2_1)
            {
                fprintf(output, "\tStartingAddress: %d\n", entry->data.mdmaddr.StartingAddress);
                fprintf(output, "\tEndingAddress: %d\n", entry->data.mdmaddr.EndingAddress);
                fprintf(output, "\tMemoryArrayHandle: %d\n", entry->data.mdmaddr.MemoryDeviceHandle);
                fprintf(output, "\tMemoryArrayMappedAddressHandle: %d\n", entry->data.mdmaddr.MemoryArrayMappedAddressHandle);
                fprintf(output, "\tPartitionRowPosition: %d\n", (int) entry->data.mdmaddr.PartitionRowPosition);
                fprintf(output, "\tInterleavePosition: %d\n", (int) entry->data.mdmaddr.InterleavePosition);
                fprintf(output, "\tInterleavedDataDepth: %d\n", (int) entry->data.mdmaddr.InterleavedDataDepth);
            }
            if (version >= smbios::SMBIOS_2_7)
            {
                fprintf(output, "\tExtendedStartingAddress: %ld\n", entry->data.mdmaddr.ExtendedStartingAddress);
                fprintf(output, "\tExtendedEndingAddress: %ld\n", entry->data.mdmaddr.ExtendedEndingAddress);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == smbios::TYPE_MANAGEMENT_DEVICE)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "\tDescription: %s\n", entry->data.mdev.Description);
                fprintf(output, "\tType: %d\n", (int) entry->data.mdev.Type);
                fprintf(output, "\tAddress: %d\n", entry->data.mdev.Address);
                fprintf(output, "\tAddressType: %d\n", (int) entry->data.mdev.AddressType);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == smbios::TYPE_MANAGEMENT_DEVICE_COMPONENT)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "\tDescription: %s\n", entry->data.mdcom.Description);
                fprintf(output, "\tManagementDeviceHandle: %d\n", (int) entry->data.mdcom.ManagementDeviceHandle);
                fprintf(output, "\tComponentHandle: %d\n", entry->data.mdcom.ComponentHandle);
                fprintf(output, "\tThresholdHandle: %d\n", (int) entry->data.mdcom.ThresholdHandle);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == smbios::TYPE_MANAGEMENT_DEVICE_THRESHOLD_DATA)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "\tLowerThresholdNonCritical: %d\n", entry->data.mdtdata.LowerThresholdNonCritical);
                fprintf(output, "\tUpperThresholdNonCritical: %d\n", entry->data.mdtdata.UpperThresholdNonCritical);
                fprintf(output, "\tLowerThresholdCritical: %d\n", entry->data.mdtdata.LowerThresholdCritical);
                fprintf(output, "\tUpperThresholdCritical: %d\n", entry->data.mdtdata.UpperThresholdCritical);
                fprintf(output, "\tLowerThresholdNonRecoverable: %d\n", entry->data.mdtdata.LowerThresholdNonRecoverable);
                fprintf(output, "\tUpperThresholdNonRecoverable: %d\n", entry->data.mdtdata.UpperThresholdNonRecoverable);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == smbios::TYPE_ONBOARD_DEVICES_EXTENDED_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "\tReferenceDesignation: %s\n", entry->data.odeinfo.ReferenceDesignation);
                fprintf(output, "\tDeviceType: %d\n", (int) entry->data.odeinfo.DeviceType);
                fprintf(output, "\tDeviceTypeInstance: %d\n", (int) entry->data.odeinfo.DeviceTypeInstance);
                fprintf(output, "\tSegmentGroupNumber: %d\n", entry->data.odeinfo.SegmentGroupNumber);
                fprintf(output, "\tBusNumber: %d\n", (int) entry->data.odeinfo.BusNumber);
                fprintf(output, "\tDeviceOrFunctionNumber: %d\n", (int) entry->data.odeinfo.DeviceOrFunctionNumber);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == smbios::TYPE_SYSTEM_BOOT_INFO)
        {
            if (version >= smbios::SMBIOS_2_0)
            {
                fprintf(output, "\tBootStatus:\n\t\t");
                if ((entry->length - 10) > 0)
                {
                    int i = 0;
                    for (; i < (entry->length - 10); ++i)
                    {
                        if (i > 0 && (i % 16) == 0)
                            fputs("\n\t\t", output);
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
