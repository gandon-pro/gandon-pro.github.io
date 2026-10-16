#include "gandon/core.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

#if defined(GANDON_HAS_CAPSTONE)
#include <capstone/capstone.h>
#endif

namespace gandon {

namespace {
std::string hex_bytes(const std::uint8_t* data, std::size_t size) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < size; ++i) out << std::setw(2) << static_cast<unsigned>(data[i]);
    return out.str();
}

#if defined(GANDON_HAS_CAPSTONE)
class X86CapstoneHandles {
public:
    ~X86CapstoneHandles() {
        if (handle32_) cs_close(&handle32_);
        if (handle64_) cs_close(&handle64_);
    }

    csh get(bool is_64_bit) {
        auto& handle = is_64_bit ? handle64_ : handle32_;
        auto& attempted = is_64_bit ? attempted64_ : attempted32_;
        if (!attempted) {
            attempted = true;
            if (cs_open(CS_ARCH_X86, is_64_bit ? CS_MODE_64 : CS_MODE_32, &handle) == CS_ERR_OK)
                cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
        }
        return handle;
    }

private:
    csh handle32_{};
    csh handle64_{};
    bool attempted32_{false};
    bool attempted64_{false};
};

csh x86_capstone_handle(bool is_64_bit) {
    static thread_local X86CapstoneHandles handles;
    return handles.get(is_64_bit);
}

class Arm64CapstoneHandle {
public:
    ~Arm64CapstoneHandle() { if (handle_) cs_close(&handle_); }
    csh get() {
        if (!attempted_) {
            attempted_ = true;
            if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle_) == CS_ERR_OK)
                cs_option(handle_, CS_OPT_DETAIL, CS_OPT_OFF);
        }
        return handle_;
    }
private:
    csh handle_{};
    bool attempted_{false};
};

csh arm64_capstone_handle() {
    static thread_local Arm64CapstoneHandle handle;
    return handle.get();
}
#endif
}

std::vector<Instruction> decode_instructions(const BinaryImage& image, std::uint64_t address,
                                             std::size_t max_instructions) {
    std::vector<Instruction> result;
    const bool arm64 = image.architecture == MachineArchitecture::ARM64;
    if (image.architecture != MachineArchitecture::Unknown) {
        if ((!arm64 && image.architecture != MachineArchitecture::X86 && image.architecture != MachineArchitecture::X64) ||
            (image.architecture == MachineArchitecture::X86 && image.is_64_bit) ||
            ((image.architecture == MachineArchitecture::X64 || arm64) && !image.is_64_bit))
            return result;
    }
    if (address < image.image_base) return result;
    if (arm64 && address % 4 != 0) return result;
    const auto rva = address - image.image_base;
    const auto offset = image.rva_to_file_offset(rva);
    if (!offset) return result;
    const auto available = image.bytes.size() - *offset;

#if defined(GANDON_HAS_CAPSTONE)
    const auto handle = arm64 ? arm64_capstone_handle() : x86_capstone_handle(image.is_64_bit);
    if (!handle) return result;
    cs_insn* instructions = nullptr;
    const auto decode_size = arm64 ? available & ~std::size_t{3} : available;
    const auto count = cs_disasm(handle, image.bytes.data() + *offset, decode_size,
                                 address, max_instructions, &instructions);
    for (std::size_t i = 0; i < count; ++i) {
        Instruction item;
        item.address = instructions[i].address;
        item.size = static_cast<std::uint8_t>(instructions[i].size);
        item.mnemonic = instructions[i].mnemonic;
        item.operands = instructions[i].op_str;
        std::copy_n(instructions[i].bytes, item.size, item.bytes.begin());
        result.push_back(std::move(item));
    }
    cs_free(instructions, count);
#else
    if (arm64) return result;
    // Dependency-free x86 fallback: decode common instruction boundaries and
    // direct relative branches well enough for CFG/xref discovery. Capstone
    // remains the complete decoder when available.
    const auto limit = available;
    std::size_t cursor = 0;
    while (cursor < limit && result.size() < max_instructions) {
        const auto start = cursor;
        std::size_t opcode_index = cursor;
        bool operand16 = false;
        bool address_override = false;
        bool rex_w = false;
        while (opcode_index < limit) {
            const auto prefix = image.bytes[*offset + opcode_index];
            if (prefix == 0x66) operand16 = true;
            else if (prefix == 0x67) address_override = true;
            else if (image.is_64_bit && prefix >= 0x40 && prefix <= 0x4F) rex_w = (prefix & 8) != 0;
            else if (prefix != 0xF0 && prefix != 0xF2 && prefix != 0xF3 && prefix != 0x2E &&
                     prefix != 0x36 && prefix != 0x3E && prefix != 0x26 && prefix != 0x64 && prefix != 0x65) break;
            ++opcode_index;
        }
        if (opcode_index >= limit) break;
        const auto opcode = image.bytes[*offset + opcode_index];
        std::size_t length = opcode_index - start + 1;
        std::size_t relative_size = 0;
        std::string mnemonic = "db";
        bool modrm = false;
        bool rip_relative = false;
        std::size_t rip_displacement_offset = 0;
        std::size_t absolute_operand_size = 0;
        bool absolute_operand_is_immediate = false;
        std::size_t immediate_size = 0;
        if (opcode == 0x90) mnemonic = "nop";
        else if (opcode == 0xC3) { mnemonic = "ret"; }
        else if (opcode == 0xC2) { mnemonic = "ret"; immediate_size = 2; }
        else if (opcode == 0xCC) mnemonic = "int3";
        else if (opcode == 0xE8 || opcode == 0xE9) {
            mnemonic = opcode == 0xE8 ? "call" : "jmp";
            relative_size = operand16 ? 2 : 4;
        } else if (opcode == 0xEB || (opcode >= 0x70 && opcode <= 0x7F)) {
            static constexpr const char* conditions[]{"jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"};
            mnemonic = opcode == 0xEB ? "jmp" : conditions[opcode & 0x0F];
            relative_size = 1;
        } else if (opcode >= 0xE0 && opcode <= 0xE3) {
            static constexpr const char* loop_mnemonics[]{"loopne", "loope", "loop", "jcxz"};
            mnemonic = loop_mnemonics[opcode - 0xE0];
            relative_size = 1;
        } else if (opcode >= 0xB8 && opcode <= 0xBF) {
            immediate_size = operand16 ? 2 : (image.is_64_bit && rex_w ? 8 : 4);
        } else if (opcode == 0xA1 || opcode == 0xA3) {
            mnemonic = "mov";
            absolute_operand_is_immediate = true;
            absolute_operand_size = image.is_64_bit ? (address_override ? 4 : 8) : (address_override ? 2 : 4);
            immediate_size = absolute_operand_size;
        } else if (opcode == 0x68 || opcode == 0x6A) {
            mnemonic = "push";
            absolute_operand_is_immediate = true;
            immediate_size = opcode == 0x6A ? 1 : (operand16 ? 2 : 4);
        } else if ((opcode <= 0x3B && (opcode & 0x04) == 0 && (opcode & 0x07) <= 3) ||
                   opcode == 0x62 || opcode == 0x63 || opcode == 0x69 || opcode == 0x6B ||
                   (opcode >= 0x80 && opcode <= 0x8F) || opcode == 0xC0 || opcode == 0xC1 ||
                   opcode == 0xC6 || opcode == 0xC7 || opcode == 0xD0 || opcode == 0xD1 ||
                   opcode == 0xD2 || opcode == 0xD3 || opcode == 0xF6 || opcode == 0xF7 ||
                   opcode == 0xFE || opcode == 0xFF) {
            modrm = true;
            if (opcode == 0x69 || opcode == 0x81 || opcode == 0xC7) immediate_size = operand16 ? 2 : 4;
            else if (opcode == 0x6B || opcode == 0x80 || opcode == 0x82 || opcode == 0x83 || opcode == 0xC0 || opcode == 0xC1 || opcode == 0xC6) immediate_size = 1;
        } else if (opcode == 0x0F && opcode_index + 1 < limit) {
            const auto second = image.bytes[*offset + opcode_index + 1];
            if (second >= 0x80 && second <= 0x8F) {
                static constexpr const char* conditions[]{"jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"};
                mnemonic = conditions[second & 0x0F];
                relative_size = operand16 ? 2 : 4;
                ++length;
            }
            else if (second == 0x0B) { mnemonic = "ud2"; ++length; }
            else if (second == 0x1F || second == 0xAF || second == 0xB6 || second == 0xB7 || second == 0xBE || second == 0xBF) { modrm = true; ++length; }
            else { ++length; }
        }
        if (opcode == 0x8B || opcode == 0x89 || opcode == 0x8A || opcode == 0x88 || opcode == 0x8D)
            mnemonic = opcode == 0x8D ? "lea" : "mov";
        if (modrm) {
            if (start + length >= limit) break;
            const auto modrm_byte = image.bytes[*offset + start + length++];
            const auto mod = modrm_byte >> 6;
            const auto rm = modrm_byte & 7;
            if (mod != 3 && rm == 4 && start + length < limit) {
                const auto sib = image.bytes[*offset + start + length++];
                if (mod == 0 && (sib & 7) == 5) length += 4;
            } else if (mod == 0 && rm == 5) {
                rip_relative = image.is_64_bit && !address_override;
                rip_displacement_offset = start + length;
                length += 4;
            }
            if (mod == 1) ++length;
            else if (mod == 2) length += 4;
            if (opcode == 0xF6 && ((modrm_byte >> 3) & 7) == 0) immediate_size = 1;
            if (opcode == 0xF7 && ((modrm_byte >> 3) & 7) == 0) immediate_size = operand16 ? 2 : 4;
        }
        length += relative_size + immediate_size;
        if (length > limit - start || length > 15) length = 1;
        Instruction item;
        item.address = address + start;
        item.size = static_cast<std::uint8_t>(length);
        item.mnemonic = mnemonic;
        item.bytes = {};
        std::copy_n(image.bytes.data() + *offset + start, length, item.bytes.begin());
        if (relative_size && length >= relative_size) {
            std::int64_t displacement = 0;
            const auto disp_at = start + length - immediate_size - relative_size;
            if (relative_size == 1) displacement = static_cast<std::int8_t>(image.bytes[*offset + disp_at]);
            else if (relative_size == 2) { std::int16_t value{}; std::memcpy(&value, image.bytes.data() + *offset + disp_at, 2); displacement = value; }
            else { std::int32_t value{}; std::memcpy(&value, image.bytes.data() + *offset + disp_at, 4); displacement = value; }
            const auto next = item.address + length;
            const auto target = displacement < 0 ? next - static_cast<std::uint64_t>(-displacement) : next + static_cast<std::uint64_t>(displacement);
            std::ostringstream operand;
            operand << "0x" << std::hex << target;
            item.operands = operand.str();
        } else if (mnemonic == "db") item.operands = "0x" + hex_bytes(item.bytes.data(), length);
        if (rip_relative && rip_displacement_offset + 4 <= limit) {
            std::int32_t displacement{};
            std::memcpy(&displacement, image.bytes.data() + *offset + rip_displacement_offset, sizeof(displacement));
            std::ostringstream operand;
            operand << "[rip " << (displacement < 0 ? "- 0x" : "+ 0x") << std::hex
                    << static_cast<std::uint64_t>(displacement < 0 ? -static_cast<std::int64_t>(displacement) : displacement) << "]";
            item.operands = operand.str();
        } else if (absolute_operand_is_immediate && immediate_size && immediate_size <= 8) {
            const auto immediate_offset = start + length - immediate_size;
            std::uint64_t absolute = 0;
            std::memcpy(&absolute, image.bytes.data() + *offset + immediate_offset, immediate_size);
            std::ostringstream operand;
            operand << "0x" << std::hex << absolute;
            item.operands = opcode == 0xA1 || opcode == 0xA3 ? "[" + operand.str() + "]" : operand.str();
        }
        result.push_back(std::move(item));
        cursor = start + length;
    }
#endif
    return result;
}

std::vector<Instruction> decode_x64(const BinaryImage& image, std::uint64_t address,
                                    std::size_t max_instructions) {
    return decode_instructions(image, address, max_instructions);
}

std::optional<Instruction> decode_x86_instruction(const std::uint8_t* bytes, std::size_t size,
                                                   std::uint64_t address, bool is_64_bit) {
    if (!bytes || !size) return std::nullopt;
#if defined(GANDON_HAS_CAPSTONE)
    const auto handle = x86_capstone_handle(is_64_bit);
    if (!handle) return std::nullopt;
    cs_insn* decoded = nullptr;
    const auto count = cs_disasm(handle, bytes, size, address, 1, &decoded);
    std::optional<Instruction> result;
    if (count) {
        Instruction item;
        item.address = decoded[0].address;
        item.size = static_cast<std::uint8_t>(decoded[0].size);
        item.mnemonic = decoded[0].mnemonic;
        item.operands = decoded[0].op_str;
        std::copy_n(decoded[0].bytes, item.size, item.bytes.begin());
        result = std::move(item);
    }
    cs_free(decoded, count);
    return result;
#else
    const auto byte = bytes[0];
    std::string mnemonic = "db";
    if (byte == 0x90) mnemonic = "nop";
    else if (byte == 0xC3) mnemonic = "ret";
    else if (byte == 0xCC) mnemonic = "int3";
    else if (byte == 0xF4) mnemonic = "hlt";
    const auto operands = mnemonic == "db" ? "0x" + hex_bytes(bytes, 1) : std::string{};
    return Instruction{address, 1, std::move(mnemonic), operands, {byte}};
#endif
}

std::optional<Instruction> decode_arm64_instruction(const std::uint8_t* bytes, std::size_t size,
                                                     std::uint64_t address) {
    if (!bytes || size < 4 || address % 4 != 0) return std::nullopt;
#if defined(GANDON_HAS_CAPSTONE)
    const auto handle = arm64_capstone_handle();
    if (!handle) return std::nullopt;
    cs_insn* decoded = nullptr;
    const auto count = cs_disasm(handle, bytes, 4, address, 1, &decoded);
    std::optional<Instruction> result;
    if (count) {
        Instruction item;
        item.address = decoded[0].address;
        item.size = static_cast<std::uint8_t>(decoded[0].size);
        item.mnemonic = decoded[0].mnemonic;
        item.operands = decoded[0].op_str;
        std::copy_n(decoded[0].bytes, item.size, item.bytes.begin());
        result = std::move(item);
    }
    cs_free(decoded, count);
    return result;
#else
    std::uint32_t word{};
    std::memcpy(&word, bytes, sizeof(word));
    std::string mnemonic = "insn";
    std::int64_t displacement = 0;
    bool has_target = false;
    if ((word & 0xFC000000u) == 0x94000000u || (word & 0xFC000000u) == 0x14000000u) {
        mnemonic = (word & 0xFC000000u) == 0x94000000u ? "bl" : "b";
        auto immediate = static_cast<std::int32_t>(word & 0x03FFFFFFu);
        if (immediate & 0x02000000) immediate |= static_cast<std::int32_t>(0xFC000000u);
        displacement = static_cast<std::int64_t>(immediate) * 4;
        has_target = true;
    } else if ((word & 0xFFFFFC1Fu) == 0xD63F0000u) mnemonic = "blr";
    else if ((word & 0xFFFFFC1Fu) == 0xD61F0000u) mnemonic = "br";
    else if ((word & 0xFFFFFC1Fu) == 0xD65F0000u) mnemonic = "ret";
    else if ((word & 0xFF000010u) == 0x54000000u) {
        static constexpr const char* conditions[]{"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
            "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"};
        mnemonic = std::string("b.") + conditions[word & 0xFu];
        auto immediate = static_cast<std::int32_t>((word >> 5) & 0x7FFFFu);
        if (immediate & 0x40000) immediate |= static_cast<std::int32_t>(0xFFF80000u);
        displacement = static_cast<std::int64_t>(immediate) * 4;
        has_target = true;
    } else if ((word & 0x7E000000u) == 0x34000000u || (word & 0x7E000000u) == 0x36000000u) {
        mnemonic = (word & 0x7E000000u) == 0x34000000u ? ((word & 0x01000000u) ? "cbnz" : "cbz") :
            ((word & 0x01000000u) ? "tbnz" : "tbz");
        auto immediate = static_cast<std::int32_t>((word >> 5) & ((word & 0x7E000000u) == 0x34000000u ? 0x7FFFFu : 0x3FFFu));
        const auto sign_bit = (word & 0x7E000000u) == 0x34000000u ? 0x40000 : 0x2000;
        if (immediate & sign_bit) immediate |= (word & 0x7E000000u) == 0x34000000u ? static_cast<std::int32_t>(0xFFF80000u) : static_cast<std::int32_t>(0xFFFFC000u);
        displacement = static_cast<std::int64_t>(immediate) * 4;
        has_target = true;
    } else if (word == 0xD503201Fu) mnemonic = "nop";
    else if ((word & 0xFFE0001Fu) == 0xD4200000u) mnemonic = "brk";
    else if ((word & 0xFFE0001Fu) == 0xD4000001u) mnemonic = "svc";
    Instruction item;
    item.address = address;
    item.size = 4;
    item.mnemonic = std::move(mnemonic);
    std::copy_n(bytes, 4, item.bytes.begin());
    if (has_target) {
        const auto target = displacement < 0 ? address - static_cast<std::uint64_t>(-displacement) : address + static_cast<std::uint64_t>(displacement);
        std::ostringstream operand;
        operand << "0x" << std::hex << target;
        item.operands = operand.str();
    }
    return item;
#endif
}

} // namespace gandon
