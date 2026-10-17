#include "gandon/auto_analysis.hpp"
#include "gandon/stack_frame.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <binary> [--sigs file.sig] [--make-sigs out.sig] [--names] [--noreturn]\n", argv[0]);
        return 2;
    }
    gandon::BinaryImage image;
    std::string error;
    if (!image.load(argv[1], error)) { std::cerr << error << "\n"; return 1; }
    gandon::AnalysisDatabase db(std::move(image));
    db.discover_basic_xrefs();
    const auto before = db.functions().size();

    gandon::SignatureSet signatures;
    const char* make_out = nullptr; const char* make_pat = nullptr; const char* verify_pat = nullptr;
    bool show_names = false, show_noreturn = false;
    for (int i = 2; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--sigs") && i + 1 < argc) {
            if (!signatures.load_file(argv[++i], error)) { std::cerr << error << "\n"; return 1; }
        } else if (!std::strcmp(argv[i], "--make-sigs") && i + 1 < argc) make_out = argv[++i];
        else if (!std::strcmp(argv[i], "--make-pat") && i + 1 < argc) make_pat = argv[++i];
        else if (!std::strcmp(argv[i], "--verify-pat") && i + 1 < argc) verify_pat = argv[++i];
        else if (!std::strcmp(argv[i], "--names")) show_names = true;
        else if (!std::strcmp(argv[i], "--noreturn")) show_noreturn = true;
    }
    if (make_pat) {
        const auto made = gandon::make_signatures(db, 96);
        std::ofstream(make_pat, std::ios::binary) << made.to_pat_text();
        std::printf("wrote %zu pattern(s) to %s\n", made.size(), make_pat);
        return 0;
    }
    if (verify_pat) {   // every named function of this binary must be recognised by the .pat made from it
        gandon::SignatureSet pat;
        if (!pat.load_file(verify_pat, error)) { std::cerr << error << "\n"; return 1; }
        std::size_t named = 0, same = 0, other = 0, none = 0;
        for (const auto& f : db.functions()) {
            if (f.name.empty() || f.name.rfind("sub_", 0) == 0) continue;
            ++named;
            const auto found = pat.match(db.image(), f.start);
            if (found == f.name) ++same; else if (found.empty()) ++none; else ++other;
        }
        std::printf("patterns loaded: %zu | named functions %zu: matched by name %zu, other name %zu, no match %zu\n", pat.size(), named, same, other, none);
        return 0;
    }
    if (make_out) {
        const auto made = gandon::make_signatures(db);
        std::ofstream(make_out) << made.to_text();
        std::printf("wrote %zu signature(s) to %s\n", made.size(), make_out);
        return 0;
    }
    bool show_frames = false; int frame_limit = 10;
    for (int i = 2; i < argc; ++i) if (!std::strcmp(argv[i], "--frames")) { show_frames = true; if (i + 1 < argc && std::isdigit((unsigned char)argv[i + 1][0])) frame_limit = std::atoi(argv[i + 1]); }

    gandon::AutoAnalysisOptions options;
    options.signatures = &signatures;
    const auto report = gandon::run_auto_analysis(db, options);
    if (show_frames) {
        const bool arm64 = db.image().architecture == gandon::MachineArchitecture::ARM64;
        const bool win = db.image().format == gandon::BinaryFormat::PE;
        int shown = 0;
        for (const auto& f : db.functions()) {
            if (f.instructions.empty()) continue;
            const auto frame = gandon::analyze_stack_frame(f, db.image().is_64_bit, arm64, win);
            if (frame.empty()) continue;
            std::printf("\n%s  @ %llX\n  proto: %s\n  reg args: %d, alloc: 0x%llX, base: %s\n",
                        f.name.c_str(), (unsigned long long)f.start, frame.prototype(f.name, win).c_str(),
                        frame.reg_args, (unsigned long long)frame.alloc,
                        frame.base == gandon::StackFrame::Base::Rbp ? "rbp" : frame.base == gandon::StackFrame::Base::Rsp ? "rsp" : "none");
            for (const auto& line : frame.summary_lines()) std::printf("    %s\n", line.c_str());
            if (++shown >= frame_limit) break;
        }
        return 0;
    }
    std::printf("functions: %zu -> %zu\n", before, db.functions().size());
    for (const auto& line : report.log) std::printf("  %s\n", line.c_str());
    if (show_names) for (const auto& [a, n] : report.new_names) std::printf("  name %llX = %s\n", (unsigned long long)a, n.c_str());
    if (show_noreturn) for (const auto a : report.noreturn) {
        auto f = db.function_at(a);
        std::printf("  noreturn %llX %s\n", (unsigned long long)a, f ? f->get().name.c_str() : "?");
    }
    return 0;
}
