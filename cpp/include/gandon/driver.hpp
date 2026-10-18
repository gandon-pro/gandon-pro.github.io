#pragma once

#include "gandon/core.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace gandon {

// One IRP major-function dispatch routine a driver installs in its
// DRIVER_OBJECT.MajorFunction table.
struct DriverIrpHandler {
    int major{0};                 // IRP_MJ_* index
    std::string name;             // "IRP_MJ_DEVICE_CONTROL", ...
    std::uint64_t handler{0};     // routine address
};

// Static view of a Windows kernel driver: its DriverEntry, the IRP dispatch
// routines it registers, and the IOCTL codes its DeviceControl path compares
// against. This is file-level structure recovery, like IDA's driver plugins.
struct DriverInfo {
    bool is_driver{false};
    std::string error;
    std::uint64_t driver_entry{0};
    std::vector<DriverIrpHandler> handlers;
    std::vector<std::uint32_t> ioctls;   // candidate IOCTL codes from the DeviceControl handler
};

DriverInfo analyze_driver(const BinaryImage& image);

// "IRP_MJ_CREATE" etc. for a major-function index, or "IRP_MJ_0xNN".
std::string irp_major_name(int major);

} // namespace gandon
