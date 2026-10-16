#pragma once

#include <cstdint>
#include <array>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace gandon {

enum class BinaryFormat { Unknown, PE, ELF };
enum class MachineArchitecture { Unknown, X86, X64, ARM, ARM64, RISCV, Other };

struct BinaryImage {
    std::filesystem::path path;
    std::vector<std::uint8_t> bytes;
    BinaryFormat format{BinaryFormat::Unknown};
    MachineArchitecture architecture{MachineArchitecture::Unknown};
    bool is_64_bit{true};
    std::uint64_t image_base{0};
    std::uint64_t entry_point{0};

    struct Section {
        std::string name;
        std::uint64_t rva{0};
        std::uint32_t virtual_size{0};
        std::uint32_t raw_offset{0};
        std::uint32_t raw_size{0};
        std::uint32_t characteristics{0};
    };
    struct Symbol {
        std::string name;
        std::uint64_t address{0};
        std::uint64_t size{0};
        std::uint8_t kind{0}; // ELF STT_* value (notype=0, object=1, function=2)
    };
    struct Import {
        std::string name;
        std::uint64_t address{0}; // IAT/GOT slot address containing the imported function pointer.
    };
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
    std::vector<Import> imports;

    bool load(const std::filesystem::path& file, std::string& error);
    std::vector<std::uint64_t> find_bytes(const std::vector<std::uint8_t>& pattern) const;
    std::vector<std::uint64_t> find_pattern(const std::vector<std::optional<std::uint8_t>>& pattern,
                                            std::size_t max_matches = 10000,
                                            bool* truncated = nullptr) const;
    std::optional<std::size_t> rva_to_file_offset(std::uint64_t rva) const;
    std::optional<std::size_t> va_to_file_offset(std::uint64_t address) const;
    std::uint64_t rva_to_va(std::uint64_t rva) const noexcept { return image_base + rva; }
};

struct Instruction {
    std::uint64_t address{0};
    std::uint8_t size{0};
    std::string mnemonic;
    std::string operands;
    // x86/x64 instructions are at most 15 bytes. Inline storage avoids one
    // heap allocation per decoded instruction during large-file analysis.
    std::array<std::uint8_t, 16> bytes{};
};

struct Function {
    std::uint64_t start{0};
    std::string name;
    std::vector<Instruction> instructions;
    std::vector<std::uint64_t> callees;
    std::uint64_t end{0}; // Exclusive end when supplied by symbols/unwind metadata.
};

struct Xref {
    std::uint64_t from{0};
    std::uint64_t to{0};
    std::string kind;
};

class AnalysisDatabase {
public:
    explicit AnalysisDatabase(BinaryImage image);

    const BinaryImage& image() const noexcept { return image_; }
    const std::vector<Function>& functions() const noexcept { return functions_; }
    bool functions_truncated() const noexcept { return functions_truncated_; }
    const std::vector<Xref>& xrefs() const noexcept { return xrefs_; }
    bool xrefs_truncated() const noexcept { return xrefs_truncated_; }
    // Approximate resident bytes owned by decoded functions and XREF storage.
    // This excludes the binary image, GUI buffers, and allocator bookkeeping.
    std::size_t estimated_analysis_memory_bytes() const noexcept;
    std::vector<std::reference_wrapper<const Xref>> xrefs_at(std::uint64_t address) const;

    void add_function(Function function);
    // Keep functions address-sorted after add_function() calls and drop duplicate starts.
    void sort_functions();
    bool rename_function(std::uint64_t start, const std::string& name);
    void add_xref(Xref xref);
    void discover_basic_xrefs();
    std::optional<std::reference_wrapper<const Function>> function_at(std::uint64_t address) const;
    std::vector<std::uint64_t> call_path(std::uint64_t from, std::uint64_t to,
                                         std::size_t max_depth = 64) const;
    bool patch_bytes(std::uint64_t address, const std::vector<std::uint8_t>& replacement,
                     std::vector<std::uint8_t>& original, std::string& error);
    bool replace_file_bytes(std::size_t offset, const std::vector<std::uint8_t>& replacement, std::string& error);
    bool write_patched_file(const std::filesystem::path& file, std::string& error) const;

private:
    BinaryImage image_;
    std::vector<Function> functions_;
    std::vector<Xref> xrefs_;
    bool functions_truncated_{false};
    bool xrefs_truncated_{false};
    mutable bool xref_index_dirty_{true};
    // A compact sorted (address, xref-index) vector replaces the much larger
    // per-address unordered_map/vector allocation tree for large XREF sets.
    mutable std::vector<std::pair<std::uint64_t, std::size_t>> xref_index_;
};

std::vector<Instruction> decode_instructions(const BinaryImage& image, std::uint64_t address,
                                             std::size_t max_instructions = 256);
// Compatibility alias retained for existing x86/x64 clients. The selected
// image architecture determines the decoder, including AArch64 when available.
std::vector<Instruction> decode_x64(const BinaryImage& image, std::uint64_t address,
                                    std::size_t max_instructions = 256);
std::optional<Instruction> decode_x86_instruction(const std::uint8_t* bytes, std::size_t size,
                                                   std::uint64_t address, bool is_64_bit);
std::optional<Instruction> decode_arm64_instruction(const std::uint8_t* bytes, std::size_t size,
                                                     std::uint64_t address);

} // namespace gandon
