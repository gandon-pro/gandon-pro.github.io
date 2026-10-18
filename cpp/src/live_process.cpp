#include "gandon/live_process.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace gandon {
namespace {
std::uint64_t load_pointer(const std::uint8_t* p, unsigned width) {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < width; ++i) value |= std::uint64_t(p[i]) << (i * 8);
    return value;
}
const LiveModule* owner(const std::vector<LiveModule>& modules, std::uint64_t address) {
    for (const auto& module : modules) if (address >= module.base && address - module.base < module.size) return &module;
    return nullptr;
}
}
PointerScanResult scan_pointers(const LiveMemoryReader& reader, std::uint64_t target,
                               const PointerScanOptions& options, const std::function<bool()>& cancel) {
    PointerScanResult result;
    const auto width = reader.pointer_size();
    if ((width != 4 && width != 8) || !target || (width == 4 && target > UINT32_MAX) ||
        !options.depth || options.depth > 10 || options.max_offset > 0x100000 ||
        options.max_bytes < width || options.max_bytes > (1ull << 30) ||
        !options.max_pointers || options.max_pointers > 4000000 || !options.max_states || options.max_states > 200000 ||
        !options.max_results || options.max_results > 10000 || !options.timeout_ms || options.timeout_ms > 120000) {
        result.truncated = true; result.reason = "Invalid pointer-scan limits or target address"; return result;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(options.timeout_ms);
    auto stop = [&] {
        if (cancel && cancel()) { result.cancelled = true; result.truncated = true; result.reason = "Cancelled"; return true; }
        if (std::chrono::steady_clock::now() >= deadline) { result.truncated = true; result.reason = "Time budget reached"; return true; }
        return false;
    };
    struct Pointer { std::uint64_t value, address; };
    std::vector<Pointer> index;
    const auto modules = reader.modules();
    std::vector<std::uint8_t> buffer(4096);
    bool indexing_done = false;
    for (const auto& region : reader.regions()) {
        if (indexing_done || stop()) break;
        if (!region.size || region.base > UINT64_MAX - region.size) continue;
        const auto end = region.base + region.size;
        for (auto address = region.base; address < end;) {
            if (stop()) { indexing_done = true; break; }
            if (result.attempted_bytes >= options.max_bytes) {
                result.truncated = true; result.reason = "Byte budget reached"; indexing_done = true; break;
            }
            const auto page_remaining = 4096 - (address & 4095);
            const auto size = static_cast<std::size_t>((std::min)({end - address, page_remaining, options.max_bytes - result.attempted_bytes}));
            const auto got = (std::min)(size, reader.read(address, buffer.data(), size));
            result.attempted_bytes += size; result.read_bytes += got;
            if (got != size) ++result.unreadable_pages;
            const auto alignment = (width - (address % width)) % width;
            for (auto offset = alignment; offset + width <= got; offset += width) {
                const auto value = load_pointer(buffer.data() + offset, width);
                if (!value) continue;
                if (index.size() == options.max_pointers) {
                    result.truncated = true; result.reason = "Pointer index budget reached"; indexing_done = true; break;
                }
                index.push_back({value, address + offset});
            }
            if (indexing_done) break;
            address += size;
        }
    }
    result.indexed_pointers = index.size();
    if (stop()) return result;
    std::sort(index.begin(), index.end(), [](const Pointer& a, const Pointer& b) {
        return a.value < b.value || (a.value == b.value && a.address < b.address);
    });
    struct Node { std::uint64_t address; std::vector<std::uint64_t> offsets, path; };
    std::vector<Node> frontier{{target, {}, {target}}};
    for (unsigned level = 0; level < options.depth && !frontier.empty(); ++level) {
        std::vector<Node> next;
        for (const auto& node : frontier) {
            if (stop()) return result;
            const auto lower = node.address > options.max_offset ? node.address - options.max_offset : 0;
            auto it = std::lower_bound(index.begin(), index.end(), lower, [](const Pointer& a, std::uint64_t value) { return a.value < value; });
            for (; it != index.end() && it->value <= node.address; ++it) {
                if (stop()) return result;
                if (++result.visited_states > options.max_states) {
                    result.truncated = true; result.reason = "Chain search budget reached"; return result;
                }
                if (std::find(node.path.begin(), node.path.end(), it->address) != node.path.end()) continue;
                Node candidate{it->address, {node.address - it->value}, node.path};
                candidate.offsets.insert(candidate.offsets.end(), node.offsets.begin(), node.offsets.end());
                candidate.path.push_back(it->address);
                const auto module = owner(modules, it->address);
                if (module || !options.module_roots_only) {
                    result.chains.push_back({it->address, target, module ? it->address - module->base : 0,
                                             module ? module->name : "", candidate.offsets});
                    if (result.chains.size() >= options.max_results) {
                        result.truncated = true; result.reason = "Result limit reached"; return result;
                    }
                }
                if (level + 1 < options.depth && (!module || !options.module_roots_only)) next.push_back(std::move(candidate));
            }
        }
        frontier = std::move(next);
    }
    return result;
}
std::optional<std::uint64_t> resolve_pointer_chain(const LiveMemoryReader& reader, const PointerChain& chain) {
    const auto width = reader.pointer_size();
    if ((width != 4 && width != 8) || chain.offsets.empty() || chain.offsets.size() > 10) return {};
    auto address = chain.root;
    for (const auto offset : chain.offsets) {
        std::uint8_t bytes[8]{};
        if (reader.read(address, bytes, width) != width) return {};
        const auto value = load_pointer(bytes, width);
        if (!value || offset > UINT64_MAX - value) return {};
        address = value + offset;
        if (width == 4 && address > UINT32_MAX) return {};
    }
    return address;
}
std::string format_pointer_scan(const PointerScanResult& result) {
    std::ostringstream out;
    out << "Pointer scan: " << result.chains.size() << " chain(s)\n"
        << "Live memory is not an atomic snapshot. Re-scan verifies chains against current memory.\n";
    for (const auto& chain : result.chains) {
        out << "0x" << std::hex << chain.root;
        if (!chain.module.empty()) out << " (" << chain.module << "+0x" << chain.module_offset << ')';
        for (auto offset : chain.offsets) out << " -> [ptr]+0x" << offset;
        out << " = 0x" << chain.target << '\n';
    }
    out << std::dec << "Read " << result.read_bytes << " / attempted " << result.attempted_bytes
        << " bytes; indexed " << result.indexed_pointers << "; visited " << result.visited_states
        << "; partial/unreadable pages " << result.unreadable_pages << '\n';
    if (result.truncated) out << "INCOMPLETE: " << result.reason << '\n';
    return out.str();
}
StructureSnapshot dump_live_structure(const LiveMemoryReader& reader, const TypeLibrary& types,
                                     const std::string& type, std::uint64_t address, std::size_t raw_size) {
    StructureSnapshot snapshot; snapshot.address = address;
    const TypeDef* definition = type.empty() ? nullptr : types.resolve(type);
    if (!type.empty() && (!definition || (definition->kind != TypeDef::Kind::Struct && definition->kind != TypeDef::Kind::Union))) {
        snapshot.error = "Select a struct/union from Local Types, or leave the type empty for raw memory"; return snapshot;
    }
    const auto size = definition ? definition->size : raw_size;
    if (!size || size > 1024 * 1024 || address > UINT64_MAX - size) { snapshot.error = "Dump size must be 1..1048576 bytes without address overflow"; return snapshot; }
    if (types.pointer_size() != static_cast<int>(reader.pointer_size())) { snapshot.error = "Type library does not match the target architecture"; return snapshot; }
    snapshot.bytes.resize(static_cast<std::size_t>(size)); snapshot.valid.resize(static_cast<std::size_t>(size));
    for (std::size_t offset = 0; offset < size;) {
        const auto count = (std::min)(static_cast<std::size_t>(size) - offset, std::size_t(4096 - ((address + offset) & 4095)));
        const auto got = (std::min)(count, reader.read(address + offset, snapshot.bytes.data() + offset, count));
        std::fill_n(snapshot.valid.begin() + offset, got, std::uint8_t{1}); offset += count;
    }
    std::ostringstream out;
    out << (type.empty() ? "Raw structure candidates" : type) << " @ 0x" << std::hex << address << std::dec << " (" << size << " bytes)\n"
        << "Live read; ?? marks unavailable bytes. Pointer-looking integers are candidates, not recovered C types.\n";
    auto field = [&](std::uint64_t offset, std::uint64_t count, const std::string& name) {
        out << "+0x" << std::hex << offset << " " << name << " [" << std::dec << count << "] = ";
        if (offset > size || count > size - offset) { out << "INVALID LAYOUT\n"; return; }
        const auto shown = (std::min)(count, std::uint64_t{32});
        bool valid = true;
        for (std::uint64_t i = 0; i < shown; ++i) {
            if (snapshot.valid[static_cast<std::size_t>(offset + i)]) out << std::hex << std::setw(2) << std::setfill('0') << unsigned(snapshot.bytes[static_cast<std::size_t>(offset + i)]) << ' ';
            else { out << "?? "; valid = false; }
        }
        if (count > shown) out << "...";
        if (valid && count && count <= 8) out << " (LE 0x" << std::hex << load_pointer(snapshot.bytes.data() + offset, static_cast<unsigned>(count)) << ')';
        out << '\n';
    };
    if (definition) for (const auto& member : definition->members) field(member.offset, member.size, member.declaration());
    else for (std::uint64_t offset = 0; offset < size; offset += reader.pointer_size()) field(offset, (std::min)(size - offset, std::uint64_t(reader.pointer_size())), "candidate");
    const auto valid_count = std::count(snapshot.valid.begin(), snapshot.valid.end(), std::uint8_t{1});
    out << std::dec << "Readable bytes: " << valid_count << '/' << size << '\n'; snapshot.report = out.str(); return snapshot;
}
} // namespace gandon
