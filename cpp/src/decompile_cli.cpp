#include "gandon/core.hpp"
#include "gandon/auto_analysis.hpp"
#include "gandon/decompiler.hpp"

#include <cstdlib>
#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Usage: gandon_decompile <binary> [function-name | 0xADDRESS | --list | --all]\n";
        return 2;
    }
    gandon::BinaryImage image;
    std::string error;
    if (!image.load(argv[1], error)) { std::cerr << error << '\n'; return 1; }
    gandon::AnalysisDatabase db(std::move(image));
    db.discover_basic_xrefs();
    std::set<std::uint64_t> noreturn;
    {   // same analysis the GUI runs after opening a file (set GANDON_NO_AUTO=1 to skip)
        if (!std::getenv("GANDON_NO_AUTO")) noreturn = gandon::run_auto_analysis(db).noreturn;
    }
    const std::string what = argc > 2 ? argv[2] : "";
    const bool addr = argc > 3 && std::string(argv[3]) == "--addr";
    if (what == "--list" || what.empty()) {
        for (const auto& f : db.functions())
            std::cout << std::hex << "0x" << f.start << "  " << f.name << "  (" << std::dec << f.instructions.size() << " insns)\n";
        return 0;
    }
    std::size_t done = 0, failed = 0;
    for (const auto& f : db.functions()) {
        const bool match = what == "--all" || f.name == what ||
            (what.rfind("0x", 0) == 0 && f.start == std::strtoull(what.c_str(), nullptr, 16));
        if (!match) continue;
        const auto result = gandon::decompile_function_at(db, f.start, addr, {}, &noreturn);
        if (!result.ok) { std::cout << "// " << f.name << ": " << result.error << "\n"; ++failed; continue; }
        std::cout << result.text << "\n";
        ++done;
    }
    if (what == "--all") std::cerr << done << " decompiled, " << failed << " failed\n";
    return done ? 0 : 1;
}
