#include "gandon/core.hpp"

#include <algorithm>
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
}

std::vector<Instruction> decode_x64(const BinaryImage& image, std::uint64_t address,
                                    std::size_t max_instructions) {
    std::vector<Instruction> result;
    if (address < image.image_base) return result;
    const auto rva = address - image.image_base;
    const auto offset = image.rva_to_file_offset(rva);
    if (!offset) return result;
    const auto available = image.bytes.size() - *offset;

#if defined(GANDON_HAS_CAPSTONE)
    csh handle{};
    if (cs_open(CS_ARCH_X86, image.is_64_bit ? CS_MODE_64 : CS_MODE_32, &handle) != CS_ERR_OK) return result;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
    cs_insn* instructions = nullptr;
    const auto count = cs_disasm(handle, image.bytes.data() + *offset, available,
                                 address, max_instructions, &instructions);
    for (std::size_t i = 0; i < count; ++i) {
        Instruction item;
        item.address = instructions[i].address;
        item.size = static_cast<std::uint8_t>(instructions[i].size);
        item.mnemonic = instructions[i].mnemonic;
        item.operands = instructions[i].op_str;
        item.bytes.assign(instructions[i].bytes, instructions[i].bytes + instructions[i].size);
        result.push_back(std::move(item));
    }
    cs_free(instructions, count);
    cs_close(&handle);
#else
    // Minimal dependency-free fallback. It intentionally handles only control
    // flow markers; installing Capstone enables complete x86/x64 decoding.
    const auto limit = std::min<std::size_t>(available, max_instructions);
    for (std::size_t i = 0; i < limit; ++i) {
        const auto byte = image.bytes[*offset + i];
        Instruction item{address + i, 1, "db", "0x" + hex_bytes(&byte, 1), {byte}};
        if (byte == 0x90) item.mnemonic = "nop";
        else if (byte == 0xC3) item.mnemonic = "ret";
        else if (byte == 0xCC) item.mnemonic = "int3";
        else if (byte == 0xE8) item.mnemonic = "call";
        else if (byte == 0xE9) item.mnemonic = "jmp";
        result.push_back(std::move(item));
    }
#endif
    return result;
}

} // namespace gandon
