#include <dmi/parser.hh>
#include <vector>
#include <stdio.h>


#define DMI_READ_8U    *ptr_++
#define DMI_READ_16U   *((uint16_t*)ptr_), ptr_ += 2
#define DMI_ENTRY_HEADER_SIZE   4

namespace dmi {


Parser::Parser( const uint8_t *data, size_t size ) : data_(data), size_(size), ptr_(NULL)
{
}



const char *Parser::getString( int index ) const
{
    const char *ptr = (const char*) start_ + (size_t) entry_.length - DMI_ENTRY_HEADER_SIZE;
    for (int i = 1; i < index; ++i)
    {
        // TODO: check buffer limits
        while (*ptr != 0) ++ptr;
        ++ptr;
    }
    return ptr;
}

const Entry *Parser::next()
{
    if (data_ == NULL) return NULL;

    // jump to the next field
    if (ptr_ == NULL)
        ptr_ = start_ = data_;
    else
    {
        ptr_ = start_ + entry_.length - DMI_ENTRY_HEADER_SIZE;
        while (ptr_ < data_ + size_ - 1 && !(ptr_[0] == 0 && ptr_[1] == 0)) ++ptr_;
        ptr_ += 2;
        if (ptr_ >= data_ + size_)
        {
            ptr_ = start_ = NULL;
            return NULL;
        }
    }

    memset(&entry_, 0, sizeof(entry_));

    // entry header
    entry_.type = DMI_READ_8U;
    entry_.length = DMI_READ_8U;
    entry_.handle = DMI_READ_16U;
    start_ = ptr_;

    return parseEntry();
}


const Entry *Parser::parseEntry()
{
    std::vector<const char *> strings;

    if (entry_.type == DMI_TYPE_BIOS)
    {
        entry_.data.bios.Vendor_ = DMI_READ_8U;
        entry_.data.bios.BIOSVersion_ = DMI_READ_8U;
        entry_.data.bios.BIOSStartingSegment = DMI_READ_16U;
        entry_.data.bios.BIOSReleaseDate_ = DMI_READ_8U;
        entry_.data.bios.BIOSROMSize = DMI_READ_8U;
        for (size_t i = 0; i < 8; ++i)
            entry_.data.bios.BIOSCharacteristics[i] = DMI_READ_8U;
        entry_.data.bios.ExtensionByte1 = DMI_READ_8U;
        entry_.data.bios.ExtensionByte2 = DMI_READ_8U;
        entry_.data.bios.SystemBIOSMajorRelease = DMI_READ_8U;
        entry_.data.bios.SystemBIOSMinorRelease = DMI_READ_8U;
        entry_.data.bios.EmbeddedFirmwareMajorRelease = DMI_READ_8U;
        entry_.data.bios.EmbeddedFirmwareMinorRelease = DMI_READ_8U;

        entry_.data.bios.Vendor          = getString(entry_.data.bios.Vendor_);
        entry_.data.bios.BIOSVersion     = getString(entry_.data.bios.BIOSVersion_);
        entry_.data.bios.BIOSReleaseDate = getString(entry_.data.bios.BIOSReleaseDate_);
    }
    else
    if (entry_.type == DMI_TYPE_SYSENCLOSURE)
    {
        entry_.data.sysenclosure.Manufacturer_ = DMI_READ_8U;
        entry_.data.sysenclosure.Type = DMI_READ_8U;
        entry_.data.sysenclosure.Version_ = DMI_READ_8U;
        entry_.data.sysenclosure.SerialNumber_ = DMI_READ_8U;
        entry_.data.sysenclosure.AssetTag_ = DMI_READ_8U;
        entry_.data.sysenclosure.BootupState = DMI_READ_8U;
        entry_.data.sysenclosure.PowerSupplyState = DMI_READ_8U;
        entry_.data.sysenclosure.ThermalState = DMI_READ_8U;
        entry_.data.sysenclosure.SecurityStatus = DMI_READ_8U;
        entry_.data.sysenclosure.OEMdefined = DMI_READ_16U;
        entry_.data.sysenclosure.Height = DMI_READ_8U;
        entry_.data.sysenclosure.NumberOfPowerCords = DMI_READ_8U;
        entry_.data.sysenclosure.ContainedElementCount = DMI_READ_8U;
        entry_.data.sysenclosure.ContainedElementRecordLength = DMI_READ_8U;

        entry_.data.sysenclosure.Manufacturer = getString(entry_.data.sysenclosure.Manufacturer_);
        entry_.data.sysenclosure.Version      = getString(entry_.data.sysenclosure.Version_);
        entry_.data.sysenclosure.SerialNumber = getString(entry_.data.sysenclosure.SerialNumber_);
        entry_.data.sysenclosure.AssetTag     = getString(entry_.data.sysenclosure.AssetTag_);
    }
    if (entry_.type == DMI_TYPE_PROCESSOR)
    {
        // version 2.0
        entry_.data.processor.SocketDesignation_ = DMI_READ_8U;
        entry_.data.processor.ProcessorType = DMI_READ_8U;
        entry_.data.processor.ProcessorFamily = DMI_READ_8U;
        entry_.data.processor.ProcessorManufacturer_ = DMI_READ_8U;
        for(int i = 0 ; i < 8; ++i)
            entry_.data.processor.ProcessorID[i] = DMI_READ_8U;
        entry_.data.processor.ProcessorVersion_ = DMI_READ_8U;
        entry_.data.processor.Voltage = DMI_READ_8U;
        entry_.data.processor.ExternalClock = DMI_READ_16U;
        entry_.data.processor.MaxSpeed = DMI_READ_16U;
        entry_.data.processor.CurrentSpeed = DMI_READ_16U;
        entry_.data.processor.Status = DMI_READ_8U;
        entry_.data.processor.ProcessorUpgrade = DMI_READ_8U;

        entry_.data.processor.L1CacheHandle = 0;
	    entry_.data.processor.L2CacheHandle = 0;
	    entry_.data.processor.L3CacheHandle = 0;
	    entry_.data.processor.SerialNumber_ = 0;
	    entry_.data.processor.SerialNumber = 0;
        entry_.data.processor.AssetTagNumber_ = 0;
	    entry_.data.processor.AssetTagNumber = 0;
        entry_.data.processor.PartNumber_ = 0;
	    entry_.data.processor.PartNumber = 0;

        entry_.data.processor.SocketDesignation     = getString(entry_.data.processor.SocketDesignation_);
        entry_.data.processor.ProcessorManufacturer = getString(entry_.data.processor.ProcessorManufacturer_);
        entry_.data.processor.ProcessorVersion      = getString(entry_.data.processor.ProcessorVersion_);
        //entry_.data.processor.SerialNumber          = GET_STRING(entry_.data.processor.SerialNumber_);
        //entry_.data.processor.AssetTagNumber        = GET_STRING(entry_.data.processor.AssetTagNumber_);
        //entry_.data.processor.PartNumber            = GET_STRING(entry_.data.processor.PartNumber_);

        return &entry_;
    }
    else
    if (entry_.type == DMI_TYPE_BASEBOARD)
    {
        entry_.data.baseboard.Manufacturer_ = DMI_READ_8U;
        entry_.data.baseboard.ProductName_ = DMI_READ_8U;
        entry_.data.baseboard.Version_ = DMI_READ_8U;
        entry_.data.baseboard.SerialNumber_ = DMI_READ_8U;
        entry_.data.baseboard.AssetTag_ = DMI_READ_8U;
        entry_.data.baseboard.FeatureFlags = DMI_READ_8U;
        entry_.data.baseboard.LocationInChassis_ = DMI_READ_8U;
        entry_.data.baseboard.ChassisHandle = DMI_READ_16U;
        entry_.data.baseboard.BoardType = DMI_READ_8U;
        entry_.data.baseboard.NoOfContainedObjectHandles = DMI_READ_8U;
        entry_.data.baseboard.ContainedObjectHandles = (uint16_t*) ptr_;

        entry_.data.baseboard.Manufacturer      = getString(entry_.data.baseboard.Manufacturer_);
        entry_.data.baseboard.ProductName       = getString(entry_.data.baseboard.ProductName_);
        entry_.data.baseboard.Version           = getString(entry_.data.baseboard.Version_);
        entry_.data.baseboard.SerialNumber      = getString(entry_.data.baseboard.SerialNumber_);
        entry_.data.baseboard.AssetTag          = getString(entry_.data.baseboard.AssetTag_);
        entry_.data.baseboard.LocationInChassis = getString(entry_.data.baseboard.LocationInChassis_);

        return &entry_;
    }
    else
    if (entry_.type == DMI_TYPE_SYSINFO)
    {
        entry_.data.sysinfo.Manufacturer_ = DMI_READ_8U;
        entry_.data.sysinfo.ProductName_ = DMI_READ_8U;
        entry_.data.sysinfo.Version_ = DMI_READ_8U;
        entry_.data.sysinfo.SerialNumber_ = DMI_READ_8U;
        for(int i = 0 ; i < 16; ++i)
            entry_.data.sysinfo.UUID[i] = DMI_READ_8U;
        entry_.data.sysinfo.WakeupType = DMI_READ_8U;
        entry_.data.sysinfo.SKUNumber_ = DMI_READ_8U;
        entry_.data.sysinfo.Family_ = DMI_READ_8U;

        entry_.data.sysinfo.Manufacturer = getString(entry_.data.sysinfo.Manufacturer_);
        entry_.data.sysinfo.ProductName  = getString(entry_.data.sysinfo.ProductName_);
        entry_.data.sysinfo.Version      = getString(entry_.data.sysinfo.Version_);
        entry_.data.sysinfo.SerialNumber = getString(entry_.data.sysinfo.SerialNumber_);
        entry_.data.sysinfo.SKUNumber    = getString(entry_.data.sysinfo.SKUNumber_);
        entry_.data.sysinfo.Family       = getString(entry_.data.sysinfo.Family_);
    }

    return &entry_;
    //return NULL;
}

} // namespace dmi
