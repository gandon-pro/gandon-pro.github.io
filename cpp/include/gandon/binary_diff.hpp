#pragma once

#include "gandon/core.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace gandon {

// Function-level comparison of two analysed binaries (like BinDiff / Diaphora, in miniature):
// functions are paired by name, by identical normalised instruction streams, by call-graph
// neighbours and finally by instruction n-gram similarity.
struct FunctionDiffEntry {
    enum class Kind { Identical, Changed, Added, Removed };
    Kind kind{Kind::Identical};
    std::uint64_t a_start{0}, b_start{0};     // 0 when the function exists on one side only
    std::string a_name, b_name;
    double similarity{0.0};                    // 0..1
    std::size_t a_instructions{0}, b_instructions{0};
    std::string matched_by;                    // "name", "hash", "callgraph", "similarity"
};

struct FunctionDiffResult {
    std::vector<FunctionDiffEntry> entries;
    std::size_t identical{0}, changed{0}, added{0}, removed{0};
    std::string summary() const;
};

FunctionDiffResult diff_functions(const AnalysisDatabase& a, const AnalysisDatabase& b);

const char* diff_kind_name(FunctionDiffEntry::Kind kind);

} // namespace gandon
