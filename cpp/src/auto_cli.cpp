#include "gandon/auto_analysis.hpp"
#include "gandon/stack_frame.hpp"
#include "gandon/vm_analysis.hpp"
#include "gandon/dotnet.hpp"
#include "gandon/rtti.hpp"
#include "gandon/driver.hpp"

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

    bool scan_dotnet = false;
    for (int i = 2; i < argc; ++i) if (!std::strcmp(argv[i], "--dotnet")) scan_dotnet = true;
    if (scan_dotnet) {
        const auto info = gandon::parse_dotnet(db.image());
        if (!info.is_dotnet) { std::printf(".NET: %s\n", info.error.c_str()); return 0; }
        std::printf(".NET assembly\n  runtime: %s\n  entry token: 0x%08X\n  IL-only: %s\n",
                    info.runtime_version.c_str(), info.entry_point_token, info.il_only ? "yes" : "no");
        std::printf("  metadata tables:\n");
        for (const auto& [name, rows] : info.table_rows) std::printf("    %-18s %u\n", name.c_str(), rows);
        std::printf("  names (#Strings): %zu, user strings (#US): %zu\n", info.names.size(), info.user_strings.size());
        std::size_t shown = 0;
        for (const auto& s : info.user_strings) { std::printf("    \"%s\"\n", s.c_str()); if (++shown >= 40) { std::printf("    ... (%zu more)\n", info.user_strings.size() - shown); break; } }
        return 0;
    }

    bool scan_rtti = false, scan_driver = false;
    for (int i = 2; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--rtti")) scan_rtti = true;
        else if (!std::strcmp(argv[i], "--driver")) scan_driver = true;
    }
    if (scan_rtti) {
        const auto classes = gandon::recover_rtti(db.image());
        std::printf("RTTI classes: %zu\n", classes.size());
        for (const auto& c : classes) {
            std::printf("  %-40s vtable 0x%llX  methods %zu", c.name.c_str(), (unsigned long long)c.vtable_va, c.method_count);
            if (!c.base_classes.empty()) { std::printf("  : "); for (std::size_t i = 0; i < c.base_classes.size(); ++i) std::printf("%s%s", i ? ", " : "", c.base_classes[i].c_str()); }
            std::printf("\n");
        }
        return 0;
    }
    if (scan_driver) {
        const auto info = gandon::analyze_driver(db.image());
        if (!info.is_driver) { std::printf("driver: %s\n", info.error.c_str()); return 0; }
        std::printf("kernel driver\n  DriverEntry: 0x%llX\n  IRP dispatch routines: %zu\n", (unsigned long long)info.driver_entry, info.handlers.size());
        for (const auto& h : info.handlers) std::printf("    %-28s -> 0x%llX\n", h.name.c_str(), (unsigned long long)h.handler);
        std::printf("  IOCTL codes: %zu\n", info.ioctls.size());
        for (const auto c : info.ioctls) std::printf("    0x%08X\n", c);
        return 0;
    }

    bool scan_vm = false;
    for (int i = 2; i < argc; ++i) if (!std::strcmp(argv[i], "--vm")) scan_vm = true;
    if (scan_vm) {
        gandon::run_auto_analysis(db, gandon::AutoAnalysisOptions{});  // widen the function set first
        std::size_t found = 0, flattened = 0;
        for (const auto& f : db.functions()) {
            if (f.instructions.size() < 2) continue;
            const auto flat = gandon::detect_flattening(db.image(), f.start, f.instructions);
            if (flat.flattened) { ++flattened; std::printf("\nFlattening in %s @ %llX\n  dispatcher 0x%llX reached by %zu of %zu branches\n",
                                                           f.name.c_str(), (unsigned long long)f.start, (unsigned long long)flat.dispatcher,
                                                           flat.dispatcher_in_degree, flat.branch_count); }
            const auto vm = gandon::detect_vm_dispatch(db.image(), f.start, f.instructions);
            if (!vm.found) continue;
            ++found;
            std::printf("\nVM dispatcher in %s @ %llX\n  dispatch site: 0x%llX (table[idx*%d])\n  handler table: 0x%llX\n  handlers: %zu\n",
                        f.name.c_str(), (unsigned long long)f.start, (unsigned long long)vm.dispatch_site,
                        vm.scale, (unsigned long long)vm.table_va, vm.handlers.size());
            const auto classes = gandon::classify_vm_handlers(db.image(), vm);
            std::size_t shown = 0;
            for (const auto& hc : classes) { std::printf("    handler[%zu] = 0x%llX  [%s]\n", shown, (unsigned long long)hc.address, hc.classification.c_str()); if (++shown >= 24) { std::printf("    ... (%zu more)\n", classes.size() - shown); break; } }
        }
        std::printf("\nVM dispatchers found: %zu | flattened functions: %zu\n", found, flattened);
        return 0;
    }

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
