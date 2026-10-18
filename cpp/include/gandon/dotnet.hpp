#pragma once

#include "gandon/core.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace gandon {

// Managed (.NET / CLR) metadata extracted from a PE. Many game cheats and
// loaders are .NET assemblies, where the interesting names and literals live in
// the metadata heaps rather than in native code. This is a bounded reader: it
// surfaces the #Strings names, #US user strings, the metadata-table row counts
// and the CLR header — not a full IL decompiler.
struct DotNetInfo {
    bool is_dotnet{false};
    std::string error;
    std::string runtime_version;                 // e.g. "v4.0.30319"
    std::uint32_t entry_point_token{0};          // COR20 EntryPointToken
    std::uint32_t flags{0};                      // COR20 flags (ILONLY = 1, ...)
    bool il_only{false};
    std::vector<std::string> names;              // #Strings heap (type/method/field names)
    std::vector<std::string> user_strings;       // #US heap (UTF-16 literals, as UTF-8)
    std::map<std::string, std::uint32_t> table_rows;  // metadata table name -> row count
};

DotNetInfo parse_dotnet(const BinaryImage& image);

} // namespace gandon
