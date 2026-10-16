#include "gandon/auto_analysis.hpp"
#include "gandon/binary_diff.hpp"
#include "gandon/core.hpp"

#include <cstdio>
#include <iostream>

static bool load(const char* path, std::unique_ptr<gandon::AnalysisDatabase>& db) {
    gandon::BinaryImage image; std::string error;
    if (!image.load(path, error)) { std::cerr << path << ": " << error << "\n"; return false; }
    db = std::make_unique<gandon::AnalysisDatabase>(std::move(image));
    db->discover_basic_xrefs();
    gandon::run_auto_analysis(*db);
    return true;
}

int main(int argc, char** argv) {
    if (argc < 3) { std::cout << "Usage: gandon_diff <binary A> <binary B> [--all]\n"; return 2; }
    std::unique_ptr<gandon::AnalysisDatabase> a, b;
    if (!load(argv[1], a) || !load(argv[2], b)) return 1;
    const bool all = argc > 3 && std::string(argv[3]) == "--all";
    const auto result = gandon::diff_functions(*a, *b);
    std::printf("%s\n", result.summary().c_str());
    for (const auto& e : result.entries) {
        if (!all && e.kind == gandon::FunctionDiffEntry::Kind::Identical) continue;
        std::printf("%-9s %5.1f%%  A %016llX %-28s | B %016llX %-28s  (%s)\n", gandon::diff_kind_name(e.kind), e.similarity * 100.0,
                    static_cast<unsigned long long>(e.a_start), e.a_name.c_str(), static_cast<unsigned long long>(e.b_start), e.b_name.c_str(), e.matched_by.c_str());
    }
    return 0;
}
