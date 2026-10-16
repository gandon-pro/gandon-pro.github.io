#pragma once

#include "gandon/core.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace gandon {

struct ImportEntry {
    std::string library;          // "KERNEL32.dll"; empty for ELF
    std::string name;             // function name or "Ordinal N"
    std::uint32_t ordinal{0};
    bool by_ordinal{false};
    std::uint64_t iat{0};         // address of the pointer slot
};

struct ExportEntry {
    std::string name;             // empty when exported by ordinal only
    std::uint64_t address{0};
    std::uint32_t ordinal{0};
    std::string forwarder;        // "NTDLL.RtlAllocateHeap" for forwarded exports
};

struct ResourceEntry {
    std::string path;             // "RT_VERSION / #1 / #1033"
    std::uint32_t rva{0};
    std::uint32_t size{0};
    std::optional<std::size_t> file_offset;
};

// PE IMAGE_DEBUG_TYPE_CODEVIEW (RSDS) record: PDB path plus the GUID/age used
// to match it, formatted the way IDA/WinDbg print a module's debug signature.
struct PdbInfo {
    std::string path;       // on-disk PDB path recorded by the linker
    std::string guid;       // "01234567-89AB-CDEF-0123-456789ABCDEF"
    std::uint32_t age{0};
};

// PE data directory (index 0 export, 1 import, 2 resource, ...): {rva, size}.
std::optional<std::pair<std::uint32_t, std::uint32_t>> pe_data_directory(const BinaryImage& image, std::size_t index);

std::vector<ImportEntry> parse_imports(const BinaryImage& image);
std::vector<ExportEntry> parse_exports(const BinaryImage& image);
std::vector<ResourceEntry> parse_resources(const BinaryImage& image);
std::optional<PdbInfo> parse_pdb_info(const BinaryImage& image);

} // namespace gandon
