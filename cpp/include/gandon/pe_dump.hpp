#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace gandon::pe_dump {

// Turn a memory-image dump (the module as it sits in a process's address space,
// with every section already at its RVA) into a valid on-disk PE. File offsets
// are made equal to RVAs — a "memory-aligned" dump — by setting FileAlignment to
// SectionAlignment and each section's PointerToRawData/SizeOfRawData to its
// VirtualAddress/VirtualSize. This is how a runtime-unpacked module is captured.
struct DumpResult {
    bool ok{false};
    std::string error;
    std::vector<std::uint8_t> bytes;
};
DumpResult build_pe_from_memory(const std::vector<std::uint8_t>& memory_image,
                                std::optional<std::uint64_t> override_entry_rva = std::nullopt);

// Rebuild the import table of a (dumped) PE whose IAT holds resolved pointers.
// `resolve` maps an absolute pointer found in the image to "dll!symbol", or ""
// when it is not an import. Runs of resolvable pointers are treated as IAT
// thunk arrays; a fresh import directory, lookup tables and name blob are
// appended in a new section and the IMPORT data directory is repointed at it.
struct ImportRebuildResult {
    bool ok{false};
    std::string error;
    std::vector<std::uint8_t> bytes;
    std::size_t resolved{0};   // number of IAT slots mapped to a named import
    std::size_t dll_count{0};
};
ImportRebuildResult rebuild_imports(const std::vector<std::uint8_t>& pe, std::uint64_t image_base,
                                    const std::function<std::string(std::uint64_t)>& resolve);

} // namespace gandon::pe_dump
