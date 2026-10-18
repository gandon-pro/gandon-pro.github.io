#pragma once

#include "gandon/core.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace gandon {

// A C++ class recovered from MSVC RTTI (RTTICompleteObjectLocator + vftable),
// the same information IDA's "RTTI" / Ghidra's class recovery surface. Makes
// virtual-call targets and class layouts legible in C++ binaries.
struct RttiClass {
    std::string name;                     // demangled, e.g. "ns::Widget"
    std::uint64_t vtable_va{0};           // address of the virtual function table
    std::uint64_t locator_va{0};          // RTTICompleteObjectLocator address
    std::size_t method_count{0};          // consecutive code pointers in the vtable
    std::vector<std::uint64_t> methods;   // the virtual method addresses
    std::vector<std::string> base_classes;// parent class names (from the class hierarchy)
};

// Statically recover MSVC RTTI classes from a PE image. Returns the classes
// found, sorted by vtable address. Empty when the binary has no MSVC RTTI
// (stripped, GCC/Clang, or non-PE).
std::vector<RttiClass> recover_rtti(const BinaryImage& image);

// Demangle an MSVC RTTI type-descriptor name (".?AVWidget@ns@@" -> "ns::Widget").
std::string demangle_msvc_rtti_name(const std::string& decorated);

} // namespace gandon
