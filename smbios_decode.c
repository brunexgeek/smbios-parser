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

static bool get_dmi_data( uint8_t **buffer, size_t *size )
{
    const BYTE byteSignature[] = { 'B', 'M', 'S', 'R' };
    const DWORD signature = *((DWORD*)byteSignature);

    // get the size of SMBIOS table
    *size = GetSystemFirmwareTable(signature, 0, NULL, 0);
    if (*size == 0)
        return false;
    *buffer = (uint8_t*) malloc(*size);
    if (*buffer == NULL)
        return false;
    // retrieve the SMBIOS table
    if (*size != GetSystemFirmwareTable(signature, 0, *buffer, *size))
    {
        free(*buffer);
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
    {
        free(*buffer);
        return false;
    }
    fread((char*) *buffer + 32, (size_t) info.st_size, 1, input);
    fclose(input);

    // read SMBIOS entry point
    snprintf(fileName, sizeof(fileName), "%s/smbios_entry_point", path);
    input = fopen(fileName, "rb");
    if (input == NULL)
    {
        free(*buffer);
        return false;
    }
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
    int sversion, oversion;
    if (smbios_get_version(parser, &sversion, &oversion) != SMBERR_OK)
        return false;

    fprintf(output, "Selected version: %d.%d\n", sversion >> 8, sversion & 0xFF);
    fprintf(output, "  SMBIOS version: %d.%d\n", oversion >> 8, oversion & 0xFF);

    const struct Entry *entry = NULL;
    int result = 0;
    while (true)
    {
        result = smbios_next(parser, &entry);
        if (result != SMBERR_OK)
            break;

        fprintf(output, "Handle 0x%04X, DMI type %d, %d bytes\n", (int) entry->handle, (int) entry->type, (int) entry->length);

        if (entry->type == TYPE_BIOS_INFO)
        {
            if (sversion >= SMBIOS_2_0)
            {
                fprintf(output, "\tVendor: %s\n", entry->data.bios_info.Vendor);
                fprintf(output, "\tBIOSVersion: %s\n", entry->data.bios_info.BIOSVersion);
                fprintf(output, "\tBIOSStartingSegment: %X\n", (int) entry->data.bios_info.BIOSStartingAddressSegment);
                fprintf(output, "\tBIOSReleaseDate: %s\n", entry->data.bios_info.BIOSReleaseDate);
                fprintf(output, "\tBIOSROMSize: %d KiB\n", ((int) entry->data.bios_info.BIOSROMSize + 1) * 64);
            }
            if (sversion >= SMBIOS_2_4)
            {
                fprintf(output, "\tSystemBIOSMajorRelease: %d\n", (int) entry->data.bios_info.SystemBIOSMajorRelease);
                fprintf(output, "\tSystemBIOSMinorRelease: %d\n", (int) entry->data.bios_info.SystemBIOSMinorRelease);
                fprintf(output, "\tEmbeddedFirmwareMajorRelease: %d\n", (int) entry->data.bios_info.EmbeddedControlerFirmwareMajorRelease);
                fprintf(output, "\tEmbeddedFirmwareMinorRelease: %d\n", (int) entry->data.bios_info.EmbeddedControlerFirmwareMinorRelease);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_SYSTEM_INFO)
        {
            if (sversion >= SMBIOS_2_0)
            {
                fprintf(output, "\tManufacturer: %s\n", entry->data.system_info.Manufacturer);
                fprintf(output, "\tProductName: %s\n", entry->data.system_info.ProductName);
                fprintf(output, "\tVersion: %s\n", entry->data.system_info.Version);
                fprintf(output, "\tSerialNumber: %s\n", entry->data.system_info.SerialNumber);
            }
            if (sversion >= SMBIOS_2_1)
            {
                fputs("\tUUID:", output);
                for (int i = 0; i < 16; ++i)
                    fprintf(output, " %02X", entry->data.system_info.UUID[i]);
                fputs("\n", output);
            }
            if (sversion >= SMBIOS_2_4)
            {
                fprintf(output, "\tSKUNumber: %s\n", entry->data.system_info.SKUNumber);
                fprintf(output, "\tFamily: %s\n", entry->data.system_info.Family);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_BASEBOARD_INFO)
        {
            if (sversion >= SMBIOS_2_0)
            {
                fprintf(output, "\tManufacturer: %s\n", entry->data.baseboard_info.Manufacturer);
                fprintf(output, "\tProduct Name: %s\n", entry->data.baseboard_info.Product);
                fprintf(output, "\tVersion: %s\n", entry->data.baseboard_info.Version);
                fprintf(output, "\tSerial Number: %s\n", entry->data.baseboard_info.SerialNumber);
                fprintf(output, "\tAsset Tag: %s\n", entry->data.baseboard_info.AssetTag);
                fprintf(output, "\tLocation In Chassis: %s\n", entry->data.baseboard_info.LocationInChassis);
                fprintf(output, "\tChassis Handle: %d\n", entry->data.baseboard_info.ChassisHandle);
                fprintf(output, "\tType: %d\n", (int) entry->data.baseboard_info.BoardType);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_SYSTEM_ENCLOSURE)
        {
            if (sversion >= SMBIOS_2_0)
            {
                fprintf(output, "\tManufacturer: %s\n", entry->data.system_enclosure.Manufacturer);
                fprintf(output, "\tVersion: %s\n", entry->data.system_enclosure.Version);
                fprintf(output, "\tSerialNumber: %s\n", entry->data.system_enclosure.SerialNumber);
                fprintf(output, "\tAssetTag: %s\n", entry->data.system_enclosure.AssetTag);
            }
            if (sversion >= SMBIOS_2_3)
            {
                fprintf(output, "\tContainedCount: %d\n", (int) entry->data.system_enclosure.ContainedElementCount);
                fprintf(output, "\tContainedLength: %d\n", (int) entry->data.system_enclosure.ContainedElementRecordLength);
            }
            if (sversion >= SMBIOS_2_7)
            {
                fprintf(output, "\tSKUNumber: %s\n", entry->data.system_enclosure.SKUNumber);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_PROCESSOR_INFO)
        {
            if (sversion >= SMBIOS_2_0)
            {
                fprintf(output, "\tSocketDesignation: %s\n", entry->data.processor_info.SocketDesignation);
                fprintf(output, "\tProcessorType: %d\n", (int) entry->data.processor_info.ProcessorType);
                fprintf(output, "\tProcessorFamily: %d\n", (int) entry->data.processor_info.ProcessorFamily);
                fprintf(output, "\tProcessorManufacturer: %s\n", entry->data.processor_info.ProcessorManufacturer);
                fprintf(output, "\tProcessorVersion: %s\n", entry->data.processor_info.ProcessorVersion);
                fputs("ProcessorID:", output);
                for (int i = 0; i < 8; ++i)
                    fprintf(output, " %02X", entry->data.processor_info.ProcessorID[i]);
                fputs("\n", output);
                fprintf(output, "\tVoltage: %d\n", entry->data.processor_info.Voltage);
                fprintf(output, "\tExternalClock: %d\n", entry->data.processor_info.ExternalClock);
                fprintf(output, "\tMaxSpeed: %d\n", entry->data.processor_info.MaxSpeed);
                fprintf(output, "\tCurrentSpeed: %d\n", entry->data.processor_info.CurrentSpeed);
                fprintf(output, "\tStatus: %d\n", entry->data.processor_info.Status);
                fprintf(output, "\tProcessorUpgrade: %d\n", entry->data.processor_info.ProcessorUpgrade);
            }
            if (sversion >= SMBIOS_2_1)
            {
                fprintf(output, "\tL1CacheHandle: %d\n", entry->data.processor_info.L1CacheHandle);
                fprintf(output, "\tL2CacheHandle: %d\n", entry->data.processor_info.L2CacheHandle);
                fprintf(output, "\tL3CacheHandle: %d\n", entry->data.processor_info.L3CacheHandle);
            }
            if (sversion >= SMBIOS_2_3)
            {
                fprintf(output, "\tSerialNumber: %s\n", entry->data.processor_info.SerialNumber);
                fprintf(output, "\tAssetTagNumber: %s\n", entry->data.processor_info.AssetTagNumber);
                fprintf(output, "\tPartNumber: %s\n", entry->data.processor_info.PartNumber);
            }
            if (sversion >= SMBIOS_2_3)
            {
                fprintf(output, "\tSerialNumber: %s\n", entry->data.processor_info.SerialNumber);
                fprintf(output, "\tAssetTagNumber: %s\n", entry->data.processor_info.AssetTagNumber);
                fprintf(output, "\tPartNumber: %s\n", entry->data.processor_info.PartNumber);
            }
            if (sversion >= SMBIOS_2_6)
            {
                fprintf(output, "\tProcessorFamily2: %d\n", entry->data.processor_info.ProcessorFamily2);
            }
            if (sversion >= SMBIOS_3_0)
            {
                fprintf(output, "\tCoreCount2: %d\n", entry->data.processor_info.CoreCount2);
                fprintf(output, "\tCoreEnabled2: %d\n", entry->data.processor_info.CoreEnabled2);
                fprintf(output, "\tThreadCount2: %d\n", entry->data.processor_info.ThreadCount2);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_SYSTEM_SLOT)
        {
            if (sversion >= SMBIOS_2_0)
            {
                fprintf(output, "\tSlotDesignation: %s\n", entry->data.system_slot.SlotDesignation);
                fprintf(output, "\tSlotType: %d\n", (int) entry->data.system_slot.SlotType);
                fprintf(output, "\tSlotDataBusWidth: %d\n", (int) entry->data.system_slot.SlotDataBusWidth);
                fprintf(output, "\tSlotID: %d\n", (int) entry->data.system_slot.SlotID);
            }
            if (sversion >= SMBIOS_2_6)
            {
                fprintf(output, "\tSegmentGroupNumber: %d\n", entry->data.system_slot.SegmentGroupNumber);
                fprintf(output, "\tBusNumber: %d\n", (int) entry->data.system_slot.BusNumber);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_PHYSICAL_MEMORY_ARRAY)
        {
            if (sversion >= SMBIOS_2_1)
            {
                fprintf(output, "\tUse: %d\n", (int) entry->data.physical_memory_array.Use);
                fprintf(output, "\tNumberDevices: %d\n", entry->data.physical_memory_array.NumberDevices);
                fprintf(output, "\tMaximumCapacity: %d KiB\n", entry->data.physical_memory_array.MaximumCapacity);
                fprintf(output, "\tExtMaximumCapacity: %ld KiB\n", entry->data.physical_memory_array.ExtendedMaximumCapacity);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_MEMORY_DEVICE)
        {
            if (sversion >= SMBIOS_2_1)
            {
                fprintf(output, "\tDeviceLocator: %s\n", entry->data.memory_device.DeviceLocator);
                fprintf(output, "\tBankLocator: %s\n", entry->data.memory_device.BankLocator);
            }
            if (sversion >= SMBIOS_2_3)
            {
                fprintf(output, "\tSpeed: %d MHz\n", entry->data.memory_device.Speed);
                fprintf(output, "\tManufacturer: %s\n", entry->data.memory_device.Manufacturer);
                fprintf(output, "\tSerialNumber: %s\n", entry->data.memory_device.SerialNumber);
                fprintf(output, "\tAssetTagNumber: %s\n", entry->data.memory_device.AssetTagNumber);
                fprintf(output, "\tPartNumber: %s\n", entry->data.memory_device.PartNumber);
                fprintf(output, "\tSize: %d MiB\n", entry->data.memory_device.Size);
                fprintf(output, "\tExtendedSize: %d MiB\n", entry->data.memory_device.ExtendedSize);
            }
            if (sversion >= SMBIOS_2_7)
            {
                fprintf(output, "\tConfiguredClockSpeed: %d\n", entry->data.memory_device.ConfiguredClockSpeed);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_OEM_STRINGS)
        {
            if (sversion >= SMBIOS_2_0)
            {
                fprintf(output, "Count: %d\n", (int) entry->data.oem_strings.Count);
                fputs("\tStrings:\n", output);
                for (int i = 0; i < entry->data.oem_strings.Count; ++i)
                    fprintf(output, "\t\t\"%s\"\n", smbios_get_string(entry, i));
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_PORT_CONNECTOR)
        {
            if (sversion >= SMBIOS_2_0)
            {
                fprintf(output, "\tInternalReferenceDesignator: %s\n", entry->data.port_connector.InternalReferenceDesignator);
                fprintf(output, "\tInternalConnectorType: %d\n", (int) entry->data.port_connector.InternalConnectorType);
                fprintf(output, "\tExternalReferenceDesignator: %s\n", entry->data.port_connector.ExternalReferenceDesignator);
                fprintf(output, "\tExternalConnectorType: %d\n", (int) entry->data.port_connector.ExternalConnectorType);
                fprintf(output, "\tPortType: %d\n", (int) entry->data.port_connector.PortType);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_MEMORY_ARRAY_MAPPED_ADDRESS)
        {
            if (sversion >= SMBIOS_2_1)
            {
                fprintf(output, "\tStartingAddress: %0X\n", entry->data.memory_array_mapped_address.StartingAddress);
                fprintf(output, "\tEndingAddress: %0X\n", entry->data.memory_array_mapped_address.EndingAddress);
                fprintf(output, "\tMemoryArrayHandle: %0X\n", entry->data.memory_array_mapped_address.MemoryArrayHandle);
                fprintf(output, "\tPartitionWidth: %0X\n", (int) entry->data.memory_array_mapped_address.PartitionWidth);
            }
            if (sversion >= SMBIOS_2_7)
            {
                fprintf(output, "\tExtendedStartingAddress: %lX\n", entry->data.memory_array_mapped_address.ExtendedStartingAddress);
                fprintf(output, "\tExtendedEndingAddress: %lX\n", entry->data.memory_array_mapped_address.ExtendedEndingAddress);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_MEMORY_DEVICE_MAPPED_ADDRESS)
        {
            if (sversion >= SMBIOS_2_1)
            {
                fprintf(output, "\tStartingAddress: %d\n", entry->data.memory_device_mapped_address.StartingAddress);
                fprintf(output, "\tEndingAddress: %d\n", entry->data.memory_device_mapped_address.EndingAddress);
                fprintf(output, "\tMemoryArrayHandle: %d\n", entry->data.memory_device_mapped_address.MemoryDeviceHandle);
                fprintf(output, "\tMemoryArrayMappedAddressHandle: %d\n", entry->data.memory_device_mapped_address.MemoryArrayMappedAddressHandle);
                fprintf(output, "\tPartitionRowPosition: %d\n", (int) entry->data.memory_device_mapped_address.PartitionRowPosition);
                fprintf(output, "\tInterleavePosition: %d\n", (int) entry->data.memory_device_mapped_address.InterleavePosition);
                fprintf(output, "\tInterleavedDataDepth: %d\n", (int) entry->data.memory_device_mapped_address.InterleavedDataDepth);
            }
            if (sversion >= SMBIOS_2_7)
            {
                fprintf(output, "\tExtendedStartingAddress: %ld\n", entry->data.memory_device_mapped_address.ExtendedStartingAddress);
                fprintf(output, "\tExtendedEndingAddress: %ld\n", entry->data.memory_device_mapped_address.ExtendedEndingAddress);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_MANAGEMENT_DEVICE)
        {
            if (sversion >= SMBIOS_2_0)
            {
                fprintf(output, "\tDescription: %s\n", entry->data.management_device.Description);
                fprintf(output, "\tType: %d\n", (int) entry->data.management_device.Type);
                fprintf(output, "\tAddress: %d\n", entry->data.management_device.Address);
                fprintf(output, "\tAddressType: %d\n", (int) entry->data.management_device.AddressType);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_MANAGEMENT_DEVICE_COMPONENT)
        {
            if (sversion >= SMBIOS_2_0)
            {
                fprintf(output, "\tDescription: %s\n", entry->data.management_device_component.Description);
                fprintf(output, "\tManagementDeviceHandle: %d\n", (int) entry->data.management_device_component.ManagementDeviceHandle);
                fprintf(output, "\tComponentHandle: %d\n", entry->data.management_device_component.ComponentHandle);
                fprintf(output, "\tThresholdHandle: %d\n", (int) entry->data.management_device_component.ThresholdHandle);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_MANAGEMENT_DEVICE_THRESHOLD_DATA)
        {
            if (sversion >= SMBIOS_2_0)
            {
                fprintf(output, "\tLowerThresholdNonCritical: %d\n", entry->data.management_device_threshold_data.LowerThresholdNonCritical);
                fprintf(output, "\tUpperThresholdNonCritical: %d\n", entry->data.management_device_threshold_data.UpperThresholdNonCritical);
                fprintf(output, "\tLowerThresholdCritical: %d\n", entry->data.management_device_threshold_data.LowerThresholdCritical);
                fprintf(output, "\tUpperThresholdCritical: %d\n", entry->data.management_device_threshold_data.UpperThresholdCritical);
                fprintf(output, "\tLowerThresholdNonRecoverable: %d\n", entry->data.management_device_threshold_data.LowerThresholdNonRecoverable);
                fprintf(output, "\tUpperThresholdNonRecoverable: %d\n", entry->data.management_device_threshold_data.UpperThresholdNonRecoverable);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_ONBOARD_DEVICES_EXTENDED_INFO)
        {
            if (sversion >= SMBIOS_2_0)
            {
                fprintf(output, "\tReferenceDesignation: %s\n", entry->data.onboard_devices_extended_info.ReferenceDesignation);
                fprintf(output, "\tDeviceType: %d\n", (int) entry->data.onboard_devices_extended_info.DeviceType);
                fprintf(output, "\tDeviceTypeInstance: %d\n", (int) entry->data.onboard_devices_extended_info.DeviceTypeInstance);
                fprintf(output, "\tSegmentGroupNumber: %d\n", entry->data.onboard_devices_extended_info.SegmentGroupNumber);
                fprintf(output, "\tBusNumber: %d\n", (int) entry->data.onboard_devices_extended_info.BusNumber);
                fprintf(output, "\tDeviceOrFunctionNumber: %d\n", (int) entry->data.onboard_devices_extended_info.DeviceOrFunctionNumber);
            }
            fputs("\n", output);
        }
        else
        if (entry->type == TYPE_SYSTEM_BOOT_INFO)
        {
            if (sversion >= SMBIOS_2_0)
            {
                fprintf(output, "\tBootStatus:\n\t\t");
                if ((entry->length - 10) > 0)
                {
                    int i = 0;
                    for (; i < (entry->length - 10); ++i)
                    {
                        if (i > 0 && (i % 16) == 0)
                            fputs("\n\t\t", output);
                        fprintf(output, "%02X ", (int)entry->data.system_boot_info.BootStatus[i]);
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
                    fprintf(output, "\t\t\"%s\"\n", str);
                    while (*str != 0) ++str;
                    ++str;
                }
            }

            fputs("\n", output);
        }
    }

    if (result != SMBERR_END_OF_STREAM)
    {
        fputs("Invalid SMBIOS data", output);
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
        fputs("Unable to open SMBIOS tables\n", stderr);
        return 1;
    }

    struct ParserContext parser;
    if (smbios_initialize(&parser, buffer, size, SMBIOS_ANY) == SMBERR_OK)
        printSMBIOS(&parser, stdout);
    else
        fputs("Invalid SMBIOS data\n", stderr);

    free(buffer);
    return 0;
}
