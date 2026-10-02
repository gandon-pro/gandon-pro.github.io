#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace gandon {

enum class BinaryFormat { Unknown, PE, ELF };

struct BinaryImage {
    std::filesystem::path path;
    std::vector<std::uint8_t> bytes;
    BinaryFormat format{BinaryFormat::Unknown};
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
    std::vector<Section> sections;

    bool load(const std::filesystem::path& file, std::string& error);
    std::vector<std::uint64_t> find_bytes(const std::vector<std::uint8_t>& pattern) const;
    std::optional<std::size_t> rva_to_file_offset(std::uint64_t rva) const;
    std::optional<std::size_t> va_to_file_offset(std::uint64_t address) const;
    std::uint64_t rva_to_va(std::uint64_t rva) const noexcept { return image_base + rva; }
};

struct Instruction {
    std::uint64_t address{0};
    std::uint8_t size{0};
    std::string mnemonic;
    std::string operands;
    std::vector<std::uint8_t> bytes;
};

struct Function {
    std::uint64_t start{0};
    std::string name;
    std::vector<Instruction> instructions;
    std::vector<std::uint64_t> callees;
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
    const std::vector<Xref>& xrefs() const noexcept { return xrefs_; }

    void add_function(Function function);
    void add_xref(Xref xref);
    void discover_basic_xrefs();
    std::optional<std::reference_wrapper<const Function>> function_at(std::uint64_t address) const;
    bool patch_bytes(std::uint64_t address, const std::vector<std::uint8_t>& replacement,
                     std::vector<std::uint8_t>& original, std::string& error);
    bool replace_file_bytes(std::size_t offset, const std::vector<std::uint8_t>& replacement, std::string& error);
    bool write_patched_file(const std::filesystem::path& file, std::string& error) const;

private:
    BinaryImage image_;
    std::vector<Function> functions_;
    std::vector<Xref> xrefs_;
};

std::vector<Instruction> decode_x64(const BinaryImage& image, std::uint64_t address,
                                    std::size_t max_instructions = 256);

} // namespace gandon
