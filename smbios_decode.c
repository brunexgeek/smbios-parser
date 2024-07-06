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

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include "smbios.h"

#ifdef _WIN32

#include <Windows.h>

static bool getDMI( std::vector<uint8_t> &buffer )
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

static bool get_dmi_data( const char *path, uint8_t **buffer, size_t *size )
{
    FILE *input;
    char fileName[128];

    // get the SMBIOS structures size
    snprintf(fileName, sizeof(fileName), "%s/DMI", path);
    struct stat info;
    if (stat(fileName, &info) != 0)
        return false;
    *size = (size_t) info.st_size + 32;
    *buffer = (uint8_t*) malloc(*size);
    if (*buffer == NULL)
        return false;

    // read SMBIOS structures
    input = fopen(fileName, "rb");
    if (input == NULL)
        return false;
    fread((char*) *buffer + 32, (size_t) info.st_size, 1, input);
    fclose(input);

    // read SMBIOS entry point
    snprintf(fileName, sizeof(fileName), "%s/smbios_entry_point", path);
    input = fopen(fileName, "rb");
    if (input == NULL)
        return false;
    fread((char*) *buffer, 32, 1, input);
    fclose(input);

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

bool printSMBIOS( struct ParserContext *parser, FILE *output )
{
    enum SpecVersion version;
    if (smbios_get_version(parser, &version, NULL) != SMBERR_OK)
        return false;

    const struct Entry *entry = NULL;
    while (true)
    {
        if (smbios_next(parser, &entry) != SMBERR_OK)
            break;

        fprintf(output, "Handle 0x%04X, DMI type %d, %d bytes\n", (int) entry->handle, (int) entry->type, (int) entry->length);

        if (entry->type == TYPE_BIOS_INFO)
        {
            if (version >= SMBIOS_2_0)
            {
                fprintf(output, "\tVendor: %s\n", entry->data.bios.Vendor);
                fprintf(output, "\tBIOSVersion: %s\n", entry->data.bios.BIOSVersion);
                fprintf(output, "\tBIOSStartingSegment: %X\n", (int) entry->data.bios.BIOSStartingSegment);
                fprintf(output, "\tBIOSReleaseDate: %s\n", entry->data.bios.BIOSReleaseDate);
                fprintf(output, "\tBIOSROMSize: %d KiB\n", ((int) entry->data.bios.BIOSROMSize + 1) * 64);
            }
            if (version >= SMBIOS_2_4)
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
            if (version >= SMBIOS_2_0)
            {
                fprintf(output, "\tManufacturer: %s\n", entry->data.sysinfo.Manufacturer);
                fprintf(output, "\tProductName: %s\n", entry->data.sysinfo.ProductName);
                fprintf(output, "\tVersion: %s\n", entry->data.sysinfo.Version);
                fprintf(output, "\tSerialNumber: %s\n", entry->data.sysinfo.SerialNumber);
            }
            if (version >= SMBIOS_2_1)
            {
                fputs("\tUUID:", output);
                for (int i = 0; i < 16; ++i)
                    fprintf(output, " %02X", entry->data.sysinfo.UUID[i]);
                fputs("\n", output);
            }
            if (version >= SMBIOS_2_4)
            {
                fprintf(output, "\tSKUNumber: %s\n", entry->data.sysinfo.SKUNumber);
                fprintf(output, "\tFamily: %s\n", entry->data.sysinfo.Family);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_BASEBOARD_INFO)
        {
            if (version >= SMBIOS_2_0)
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
            if (version >= SMBIOS_2_0)
            {
                fprintf(output, "\tManufacturer: %s\n", entry->data.sysenclosure.Manufacturer);
                fprintf(output, "\tVersion: %s\n", entry->data.sysenclosure.Version);
                fprintf(output, "\tSerialNumber: %s\n", entry->data.sysenclosure.SerialNumber);
                fprintf(output, "\tAssetTag: %s\n", entry->data.sysenclosure.AssetTag);
            }
            if (version >= SMBIOS_2_3)
            {
                fprintf(output, "\tContainedCount: %d\n", (int) entry->data.sysenclosure.ContainedElementCount);
                fprintf(output, "\tContainedLength: %d\n", (int) entry->data.sysenclosure.ContainedElementRecordLength);
            }
            if (version >= SMBIOS_2_7)
            {
                fprintf(output, "\tSKUNumber: %s\n", entry->data.sysenclosure.SKUNumber);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_PROCESSOR_INFO)
        {
            if (version >= SMBIOS_2_0)
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
            if (version >= SMBIOS_2_5)
            {
                fprintf(output, "\tCoreCount: %d\n", (int) entry->data.processor.CoreCount);
                fprintf(output, "\tCoreEnabled: %d\n", (int) entry->data.processor.CoreEnabled);
                fprintf(output, "\tThreadCount: %d\n", (int) entry->data.processor.ThreadCount);
            }
            if (version >= SMBIOS_2_6)
            {
                fprintf(output, "\tProcessorFamily2: %d\n", entry->data.processor.ProcessorFamily2);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_SYSTEM_SLOT)
        {
            if (version >= SMBIOS_2_0)
            {
                fprintf(output, "\tSlotDesignation: %s\n", entry->data.sysslot.SlotDesignation);
                fprintf(output, "\tSlotType: %d\n", (int) entry->data.sysslot.SlotType);
                fprintf(output, "\tSlotDataBusWidth: %d\n", (int) entry->data.sysslot.SlotDataBusWidth);
                fprintf(output, "\tSlotID: %d\n", (int) entry->data.sysslot.SlotID);
            }
            if (version >= SMBIOS_2_6)
            {
                fprintf(output, "\tSegmentGroupNumber: %d\n", entry->data.sysslot.SegmentGroupNumber);
                fprintf(output, "\tBusNumber: %d\n", (int) entry->data.sysslot.BusNumber);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_PHYSICAL_MEMORY_ARRAY)
        {
            if (version >= SMBIOS_2_1)
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
            if (version >= SMBIOS_2_1)
            {
                fprintf(output, "\tDeviceLocator: %s\n", entry->data.memory.DeviceLocator);
                fprintf(output, "\tBankLocator: %s\n", entry->data.memory.BankLocator);
            }
            if (version >= SMBIOS_2_3)
            {
                fprintf(output, "\tSpeed: %d MHz\n", entry->data.memory.Speed);
                fprintf(output, "\tManufacturer: %s\n", entry->data.memory.Manufacturer);
                fprintf(output, "\tSerialNumber: %s\n", entry->data.memory.SerialNumber);
                fprintf(output, "\tAssetTagNumber: %s\n", entry->data.memory.AssetTagNumber);
                fprintf(output, "\tPartNumber: %s\n", entry->data.memory.PartNumber);
                fprintf(output, "\tSize: %d MiB\n", entry->data.memory.Size);
                fprintf(output, "\tExtendedSize: %d MiB\n", entry->data.memory.ExtendedSize);
            }
            if (version >= SMBIOS_2_7)
            {
                fprintf(output, "\tConfiguredClockSpeed: %d\n", entry->data.memory.ConfiguredClockSpeed);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_OEM_STRINGS)
        {
            if (version >= SMBIOS_2_0)
            {
                fprintf(output, "Count: %d\n", (int) entry->data.oemstrings.Count);
                fputs("\tStrings:\n", output);
                for (int i = 0; i < entry->data.oemstrings.Count; ++i)
                    fprintf(output, "\t\t%s\n", smbios_get_string(entry, i));
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_PORT_CONNECTOR)
        {
            if (version >= SMBIOS_2_0)
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
        if (entry->type == TYPE_MEMORY_ARRAY_MAPPED_ADDRESS)
        {
            if (version >= SMBIOS_2_1)
            {
                fprintf(output, "\tStartingAddress: %0X\n", entry->data.mamaddr.StartingAddress);
                fprintf(output, "\tEndingAddress: %0X\n", entry->data.mamaddr.EndingAddress);
                fprintf(output, "\tMemoryArrayHandle: %0X\n", entry->data.mamaddr.MemoryArrayHandle);
                fprintf(output, "\tPartitionWidth: %0X\n", (int) entry->data.mamaddr.PartitionWidth);
            }
            if (version >= SMBIOS_2_7)
            {
                fprintf(output, "\tExtendedStartingAddress: %lX\n", entry->data.mamaddr.ExtendedStartingAddress);
                fprintf(output, "\tExtendedEndingAddress: %lX\n", entry->data.mamaddr.ExtendedEndingAddress);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_MEMORY_DEVICE_MAPPED_ADDRESS)
        {
            if (version >= SMBIOS_2_1)
            {
                fprintf(output, "\tStartingAddress: %d\n", entry->data.mdmaddr.StartingAddress);
                fprintf(output, "\tEndingAddress: %d\n", entry->data.mdmaddr.EndingAddress);
                fprintf(output, "\tMemoryArrayHandle: %d\n", entry->data.mdmaddr.MemoryDeviceHandle);
                fprintf(output, "\tMemoryArrayMappedAddressHandle: %d\n", entry->data.mdmaddr.MemoryArrayMappedAddressHandle);
                fprintf(output, "\tPartitionRowPosition: %d\n", (int) entry->data.mdmaddr.PartitionRowPosition);
                fprintf(output, "\tInterleavePosition: %d\n", (int) entry->data.mdmaddr.InterleavePosition);
                fprintf(output, "\tInterleavedDataDepth: %d\n", (int) entry->data.mdmaddr.InterleavedDataDepth);
            }
            if (version >= SMBIOS_2_7)
            {
                fprintf(output, "\tExtendedStartingAddress: %ld\n", entry->data.mdmaddr.ExtendedStartingAddress);
                fprintf(output, "\tExtendedEndingAddress: %ld\n", entry->data.mdmaddr.ExtendedEndingAddress);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_MANAGEMENT_DEVICE)
        {
            if (version >= SMBIOS_2_0)
            {
                fprintf(output, "\tDescription: %s\n", entry->data.mdev.Description);
                fprintf(output, "\tType: %d\n", (int) entry->data.mdev.Type);
                fprintf(output, "\tAddress: %d\n", entry->data.mdev.Address);
                fprintf(output, "\tAddressType: %d\n", (int) entry->data.mdev.AddressType);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_MANAGEMENT_DEVICE_COMPONENT)
        {
            if (version >= SMBIOS_2_0)
            {
                fprintf(output, "\tDescription: %s\n", entry->data.mdcom.Description);
                fprintf(output, "\tManagementDeviceHandle: %d\n", (int) entry->data.mdcom.ManagementDeviceHandle);
                fprintf(output, "\tComponentHandle: %d\n", entry->data.mdcom.ComponentHandle);
                fprintf(output, "\tThresholdHandle: %d\n", (int) entry->data.mdcom.ThresholdHandle);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_MANAGEMENT_DEVICE_THRESHOLD_DATA)
        {
            if (version >= SMBIOS_2_0)
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
        if (entry->type == TYPE_ONBOARD_DEVICES_EXTENDED_INFO)
        {
            if (version >= SMBIOS_2_0)
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
        if (entry->type == TYPE_SYSTEM_BOOT_INFO)
        {
            if (version >= SMBIOS_2_0)
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
                hexdump(output, entry->rawdata, entry->length);

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
    uint8_t *buffer = NULL;
    size_t size = 0;
    bool result = false;

    #ifdef _WIN32

    result = get_dmi_data(&buffer, &size);

    #else

    const char *path = "/sys/firmware/dmi/tables";
    if (argc == 2)
        path = argv[1];
    printf("Using SMBIOS tables from %s\n", path);
    result = get_dmi_data(path, &buffer, &size);

    #endif

    if (!result)
    {
        fputs("Unable to open SMBIOS tables", stderr);
        return 1;
    }

    struct ParserContext parser;
    if (smbios_initialize(&parser, buffer, size, SMBIOS_3_0) == SMBERR_OK)
        printSMBIOS(&parser, stdout);
    else
        fputs("Invalid SMBIOS data", stderr);

    free(buffer);
    return 0;
}
