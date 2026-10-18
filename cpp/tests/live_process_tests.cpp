#include "gandon/live_process.hpp"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>
#include <map>

class Fixture final : public gandon::LiveMemoryReader {
public:
    unsigned width = 8;
    std::map<std::uint64_t, std::uint8_t> memory;
    std::vector<gandon::LiveRegion> ranges;
    std::vector<gandon::LiveModule> images;
    unsigned pointer_size() const override { return width; }
    auto regions() const -> std::vector<gandon::LiveRegion> override { return ranges; }
    auto modules() const -> std::vector<gandon::LiveModule> override { return images; }
    std::size_t read(std::uint64_t address, void* output, std::size_t size) const override {
        std::size_t count = 0;
        for (; count < size; ++count) {
            auto it = memory.find(address + count); if (it == memory.end()) break;
            static_cast<std::uint8_t*>(output)[count] = it->second;
        }
        return count;
    }
    void region(std::uint64_t base, std::size_t size) {
        ranges.push_back({base, size}); for (std::size_t i = 0; i < size; ++i) memory[base + i] = 0;
    }
    void pointer(std::uint64_t address, std::uint64_t value) {
        for (unsigned i = 0; i < width; ++i) memory[address + i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
};
int main() {
    for (unsigned width : {4u, 8u}) {
        Fixture reader; reader.width = width;
        // Pointer at +0x1800 proves the scan does not only inspect the first page.
        reader.region(0x10000, 0x3000); reader.region(0x20000, 0x1000);
        reader.images = {{0x10000, 0x3000, "sample.exe"}};
        reader.pointer(0x11800, 0x20000); reader.pointer(0x20020, 0x30000);
        gandon::PointerScanOptions options; options.depth = 2; options.max_offset = 0x80;
        const auto result = gandon::scan_pointers(reader, 0x30018, options);
        assert(!result.truncated && result.chains.size() == 1);
        const auto chain = result.chains.front();
        assert(chain.root == 0x11800 && chain.module_offset == 0x1800);
        assert((chain.offsets == std::vector<std::uint64_t>{0x20, 0x18}));
        assert(gandon::resolve_pointer_chain(reader, chain) == 0x30018);
        reader.pointer(0x20020, 0x31000);
        assert(gandon::resolve_pointer_chain(reader, chain) == 0x31018);
        reader.memory.erase(0x20020);
        assert(!gandon::resolve_pointer_chain(reader, chain));
        auto cancelled = gandon::scan_pointers(reader, 0x30018, options, [] { return true; });
        assert(cancelled.cancelled && cancelled.chains.empty());
        options.max_bytes = 4096;
        auto limited = gandon::scan_pointers(reader, 0x30018, options);
        assert(limited.truncated && limited.attempted_bytes <= 4096);
    }
    Fixture reader; reader.region(0x40000, 8192);
    reader.pointer(0x40000, 0x40000); // cycle must not expand forever
    auto cycle = gandon::scan_pointers(reader, 0x40000);
    assert(cycle.chains.empty());
    gandon::TypeLibrary types(8); std::string error;
    assert(types.parse("struct Node { unsigned int tag; unsigned int flags; void *next; };", error));
    reader.pointer(0x40008, 0x12345678); reader.memory.erase(0x41000);
    auto snapshot = gandon::dump_live_structure(reader, types, "Node", 0x40000);
    assert(snapshot.error.empty() && snapshot.bytes.size() == 16);
    assert(snapshot.report.find("next") != std::string::npos);
    auto hole = gandon::dump_live_structure(reader, types, "", 0x40ff8, 32);
    assert(hole.valid[0] && !hole.valid[8] && hole.report.find("??") != std::string::npos);
    assert(!gandon::dump_live_structure(reader, types, "MissingType", 0x40000).error.empty());
    assert(!gandon::dump_live_structure(reader, types, "", UINT64_MAX - 1, 16).error.empty());
    assert(!gandon::dump_live_structure(reader, types, "", 0x40000, 1048577).error.empty());
    std::cout << "Live process chain order, x86/x64, re-scan, cycles, cancellation, budgets and structure validity tests passed\n";
}
