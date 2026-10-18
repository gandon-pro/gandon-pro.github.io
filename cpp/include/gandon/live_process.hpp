#pragma once
#include "gandon/types.hpp"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace gandon {
struct LiveRegion { std::uint64_t base{}, size{}; };
struct LiveModule { std::uint64_t base{}, size{}; std::string name; };
class LiveMemoryReader {
public:
    virtual ~LiveMemoryReader() = default;
    virtual std::size_t read(std::uint64_t address, void* output, std::size_t size) const = 0;
    virtual std::vector<LiveRegion> regions() const = 0;
    virtual std::vector<LiveModule> modules() const = 0;
    virtual unsigned pointer_size() const = 0;
};
// Opens a fresh, read-only handle. Does not attach a debugger or enable privileges.
std::unique_ptr<LiveMemoryReader> open_live_process(std::uint32_t pid, bool kernel, std::string& error);
struct PointerScanOptions {
    unsigned depth{3};
    std::uint64_t max_offset{0x1000};
    std::uint64_t max_bytes{256ull * 1024 * 1024};
    std::size_t max_pointers{2000000}, max_states{100000}, max_results{1000};
    unsigned timeout_ms{30000};
    bool module_roots_only{true};
};
struct PointerChain {
    std::uint64_t root{}, target{}, module_offset{};
    std::string module;
    // Resolve as current = read_pointer(current) + offset, starting at root.
    std::vector<std::uint64_t> offsets;
};
struct PointerScanResult {
    std::vector<PointerChain> chains;
    std::uint64_t attempted_bytes{}, read_bytes{}, indexed_pointers{}, visited_states{}, unreadable_pages{};
    bool truncated{}, cancelled{};
    std::string reason;
};
PointerScanResult scan_pointers(const LiveMemoryReader&, std::uint64_t target, const PointerScanOptions& options = PointerScanOptions{}, const std::function<bool()>& cancel = std::function<bool()>{});
std::optional<std::uint64_t> resolve_pointer_chain(const LiveMemoryReader&, const PointerChain&);
std::string format_pointer_scan(const PointerScanResult&);
struct StructureSnapshot {
    std::uint64_t address{};
    std::vector<std::uint8_t> bytes, valid; // zero in valid means unavailable, not a zero byte
    std::string report, error;
};
StructureSnapshot dump_live_structure(const LiveMemoryReader&, const TypeLibrary&, const std::string& type,
                                     std::uint64_t address, std::size_t raw_size = 256);
} // namespace gandon
