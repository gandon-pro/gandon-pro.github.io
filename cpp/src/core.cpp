#include "gandon/core.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <limits>
#include <cstring>
#include <map>
#include <set>
#include <tuple>
#include <queue>
#include <unordered_map>
#include <unordered_set>

namespace gandon {

namespace {
std::string sub_name(std::uint64_t address) {
    char buffer[40];
    std::snprintf(buffer, sizeof buffer, "sub_%llX", static_cast<unsigned long long>(address));
    return buffer;
}
}

namespace {
// Keep a hard memory/work bound, but allow ordinary optimized Windows
// binaries such as ntoskrnl (tens of thousands of .pdata functions) through.
constexpr std::size_t kMaxDiscoveredFunctions = 65'536;
constexpr std::size_t kMaxInstructionsPerFunction = 2048;
constexpr std::size_t kMaxInstructionsPerAnalysis = 1'000'000;
// Keep headroom for large system binaries (ntoskrnl already produces >220k
// references) while retaining a deterministic bound on XREF and lazy-index RAM.
constexpr std::size_t kMaxXrefsPerAnalysis = 500'000;
constexpr std::size_t kMaxImportXrefTargets = 20'000;
constexpr std::size_t kDecodeChunkInstructions = 64;

bool is_unconditional_jump(const std::string& mnemonic) {
    return mnemonic == "jmp" || mnemonic == "jmpq" || mnemonic == "ljmp" || mnemonic == "b";
}

bool is_conditional_branch(const std::string& mnemonic) {
    return (mnemonic.size() > 1 && mnemonic.front() == 'j' && !is_unconditional_jump(mnemonic)) ||
           mnemonic.rfind("b.", 0) == 0 || mnemonic == "cbz" || mnemonic == "cbnz" ||
           mnemonic == "tbz" || mnemonic == "tbnz" ||
           mnemonic == "loop" || mnemonic == "loope" || mnemonic == "loopne" ||
           mnemonic == "jcxz" || mnemonic == "jecxz" || mnemonic == "jrcxz";
}

bool is_call_instruction(const std::string& mnemonic) {
    return mnemonic == "call" || mnemonic == "callq" || mnemonic == "bl" || mnemonic == "blr";
}

bool is_nonreturning_terminator(const std::string& mnemonic) {
    return mnemonic == "ud0" || mnemonic == "ud1" || mnemonic == "ud2" ||
           mnemonic == "int3" || mnemonic == "hlt" || mnemonic == "brk" || mnemonic == "udf";
}

std::vector<Instruction> decode_function(const BinaryImage& image,
                                         const std::vector<Function>& functions,
                                         std::size_t index,
                                         std::size_t instruction_limit = kMaxInstructionsPerFunction) {
    const auto& function = functions[index];
    auto end = function.end;
    if (index + 1 < functions.size() && (!end || functions[index + 1].start < end))
        end = functions[index + 1].start;
    if (!end && function.start >= image.image_base) {
        const auto rva = function.start - image.image_base;
        for (const auto& section : image.sections) {
            const auto extent = (std::max)(section.virtual_size, section.raw_size);
            if (rva >= section.rva && rva - section.rva < extent) {
                end = image.image_base + section.rva + extent;
                break;
            }
        }
    }
    const auto branch_target = [](const Instruction& instruction) -> std::optional<std::uint64_t> {
        if (instruction.operands.find('[') != std::string::npos) return std::nullopt;
        const auto literal = instruction.operands.find("0x");
        if (literal == std::string::npos) return std::nullopt;
        const auto literal_end = instruction.operands.find_first_not_of("0123456789abcdefABCDEF", literal + 2);
        try { return std::stoull(instruction.operands.substr(literal, literal_end - literal), nullptr, 16); }
        catch (...) { return std::nullopt; }
    };
    const auto in_function = [&](std::uint64_t address) {
        return address >= function.start && (!end || address < end) && image.va_to_file_offset(address).has_value();
    };
    std::vector<Instruction> result;
    std::vector<std::uint64_t> block_starts{function.start};
    std::unordered_set<std::uint64_t> decoded_addresses;
    decoded_addresses.reserve((std::min)(instruction_limit, std::size_t{256}));
    while (!block_starts.empty() && result.size() < instruction_limit) {
        auto address = block_starts.back();
        block_starts.pop_back();
        while (in_function(address) && result.size() < instruction_limit &&
               !decoded_addresses.contains(address)) {
            const auto remaining = instruction_limit - result.size();
            const auto chunk_limit = (std::min)(remaining, kDecodeChunkInstructions);
            auto block = decode_instructions(image, address, chunk_limit);
            if (block.empty()) break;
            bool ended_block = false;
            for (const auto& instruction : block) {
                if (!in_function(instruction.address) || (end && instruction.size > end - instruction.address) ||
                    !decoded_addresses.insert(instruction.address).second) {
                    ended_block = true;
                    break;
                }
                result.push_back(instruction);
                const auto& mnemonic = instruction.mnemonic;
                const bool is_return = mnemonic == "ret" || mnemonic == "retq" || mnemonic == "retn" ||
                                       mnemonic == "retf" || mnemonic == "iret" || mnemonic == "iretq";
                if (is_return || is_nonreturning_terminator(mnemonic)) {
                    ended_block = true;
                    break;
                }
                const bool unconditional_jump = is_unconditional_jump(mnemonic);
                const bool conditional_jump = is_conditional_branch(mnemonic);
                if (unconditional_jump || conditional_jump) {
                    const auto target = branch_target(instruction);
                    if (target && in_function(*target) && !decoded_addresses.contains(*target))
                        block_starts.push_back(*target);
                    if (conditional_jump) {
                        const auto fallthrough = instruction.address + instruction.size;
                        if (in_function(fallthrough) && !decoded_addresses.contains(fallthrough))
                            block_starts.push_back(fallthrough);
                    }
                    ended_block = true;
                    break;
                }
                address = instruction.address + instruction.size;
            }
            if (ended_block || block.size() < chunk_limit) break;
            const auto& last = block.back();
            const auto next = last.address + last.size;
            if (next <= last.address) break;
            address = next;
        }
    }
    std::sort(result.begin(), result.end(), [](const Instruction& left, const Instruction& right) {
        return left.address < right.address;
    });
    return result;
}

std::optional<std::uint64_t> direct_target(const Instruction& instruction) {
    if (instruction.operands.find('[') != std::string::npos) return std::nullopt;
    const auto literal = instruction.operands.find("0x");
    if (literal == std::string::npos) return std::nullopt;
    const auto end = instruction.operands.find_first_not_of("0123456789abcdefABCDEF", literal + 2);
    try { return std::stoull(instruction.operands.substr(literal, end - literal), nullptr, 16); }
    catch (...) { return std::nullopt; }
}

void discover_transitive_callees(const BinaryImage& image, std::vector<Function>& functions,
                                 std::set<std::uint64_t>& known_functions, bool& functions_truncated) {
    std::vector<std::uint64_t> worklist(known_functions.begin(), known_functions.end());
    worklist.reserve((std::min)(kMaxDiscoveredFunctions, worklist.size() + 256));
    std::unordered_set<std::uint64_t> processed;
    processed.reserve(worklist.size() + 256);
    std::unordered_map<std::uint64_t, std::size_t> function_indices;
    function_indices.reserve((std::min)(kMaxDiscoveredFunctions, functions.size() + 256));
    for (std::size_t index = 0; index < functions.size(); ++index)
        function_indices.emplace(functions[index].start, index);
    std::size_t instruction_budget = kMaxInstructionsPerAnalysis;
    for (std::size_t cursor = 0; cursor < worklist.size(); ++cursor) {
        if (!instruction_budget) break;
        const auto address = worklist[cursor];
        if (!processed.insert(address).second) continue;
        const auto metadata = function_indices.find(address);
        if (metadata == function_indices.end()) continue;
        Function probe = functions[metadata->second];
        if (!probe.end) {
            if (const auto next = known_functions.upper_bound(address); next != known_functions.end())
                probe.end = *next;
        }
        const std::vector<Function> probe_functions{std::move(probe)};
        auto instructions = decode_function(image, probe_functions, 0,
            (std::min)(kMaxInstructionsPerFunction, instruction_budget));
        instruction_budget -= instructions.size();
        for (const auto& instruction : instructions) {
            // decode_function already excludes unreachable bytes after returns;
            // do not stop at the first RET here because other CFG blocks may
            // sort after that return and still contain reachable calls.
            if (!is_call_instruction(instruction.mnemonic)) continue;
            const auto target = direct_target(instruction);
            if (!target || !image.va_to_file_offset(*target)) continue;
            const auto code_section = std::find_if(image.sections.begin(), image.sections.end(), [&](const auto& section) {
                const auto extent = static_cast<std::uint64_t>((std::max)(section.virtual_size, section.raw_size));
                return (section.characteristics & 0x20000000u) != 0 && *target >= image.image_base + section.rva &&
                       *target - (image.image_base + section.rva) < extent;
            });
            if (code_section == image.sections.end() || known_functions.contains(*target)) continue;
            if (functions.size() >= kMaxDiscoveredFunctions) { functions_truncated = true; break; }
            known_functions.insert(*target);
            function_indices.emplace(*target, functions.size());
            functions.push_back({*target, sub_name(*target), {}, {}});
            worklist.push_back(*target);
        }
        // Keep the decoded CFG for the final database build. Re-decoding every
        // discovered function after the worklist pass nearly doubles analysis
        // time on binaries with thousands of functions.
        functions[metadata->second].instructions = std::move(instructions);
    }
}

void decode_functions_bounded(const BinaryImage& image, std::vector<Function>& functions) {
    std::size_t instruction_budget = kMaxInstructionsPerAnalysis;
    const auto release_decoded_instructions = [](Function& function) {
        // clear() keeps vector capacity, which defeats the analysis memory
        // budget when a previously cached function is discarded.
        std::vector<Instruction>().swap(function.instructions);
    };
    for (std::size_t index = 0; index < functions.size(); ++index) {
        if (!functions[index].instructions.empty()) {
            if (functions[index].instructions.size() > instruction_budget) {
                release_decoded_instructions(functions[index]);
                continue;
            }
            instruction_budget -= functions[index].instructions.size();
            auto& cached = functions[index].instructions;
            const auto next_start = index + 1 < functions.size() ? functions[index + 1].start :
                                    std::numeric_limits<std::uint64_t>::max();
            const auto limit = functions[index].end ?
                (std::min)(functions[index].end, next_start) : next_start;
            auto cut = std::lower_bound(cached.begin(), cached.end(), limit,
                [](const Instruction& instruction, std::uint64_t address) {
                    return instruction.address < address;
                });
            // A later-discovered function can start inside an instruction
            // decoded during the discovery pass. Match decode_function's
            // boundary check by dropping that crossing instruction as well.
            if (cut != cached.begin()) {
                const auto previous = std::prev(cut);
                if (previous->size > limit - previous->address) cut = previous;
            }
            cached.erase(cut, cached.end());
            continue;
        }
        if (!instruction_budget) {
            release_decoded_instructions(functions[index]);
            continue;
        }
        functions[index].instructions = decode_function(image, functions, index,
            (std::min)(kMaxInstructionsPerFunction, instruction_budget));
        instruction_budget -= functions[index].instructions.size();
    }
}
}

bool BinaryImage::load(const std::filesystem::path& file, std::string& error) {
    struct FailedLoadCleanup {
        BinaryImage& image;
        bool succeeded{false};
        ~FailedLoadCleanup() {
            if (succeeded) return;
            image.path.clear();
            std::vector<std::uint8_t>().swap(image.bytes);
            std::vector<Section>().swap(image.sections);
            std::vector<Symbol>().swap(image.symbols);
            std::vector<Import>().swap(image.imports);
            image.format = BinaryFormat::Unknown;
            image.architecture = MachineArchitecture::Unknown;
            image.is_64_bit = true;
            image.image_base = 0;
            image.entry_point = 0;
        }
    } cleanup{*this};
    path.clear();
    std::vector<std::uint8_t>().swap(bytes);
    format = BinaryFormat::Unknown;
    architecture = MachineArchitecture::Unknown;
    is_64_bit = true;
    image_base = 0;
    entry_point = 0;
    std::vector<Section>().swap(sections);
    std::vector<Symbol>().swap(symbols);
    std::vector<Import>().swap(imports);
    error.clear();
    std::ifstream input(file, std::ios::binary);
    if (!input) {
        error = "Could not open binary: " + file.string();
        return false;
    }
    input.seekg(0, std::ios::end);
    const auto file_end = input.tellg();
    if (file_end < 0 || static_cast<std::uintmax_t>(file_end) >
            static_cast<std::uintmax_t>((std::numeric_limits<std::size_t>::max)()) ||
        static_cast<std::uintmax_t>(file_end) >
            static_cast<std::uintmax_t>((std::numeric_limits<std::streamsize>::max)())) {
        error = "Binary file size cannot be represented on this platform.";
        return false;
    }
    try {
        bytes.resize(static_cast<std::size_t>(file_end));
    } catch (const std::bad_alloc&) {
        error = "Not enough memory to load this binary file.";
        return false;
    } catch (const std::length_error&) {
        error = "Binary file exceeds the supported in-memory size.";
        return false;
    }
    input.seekg(0, std::ios::beg);
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!input || input.gcount() != static_cast<std::streamsize>(bytes.size())) {
            bytes.clear();
            error = "Could not read the complete binary file.";
            return false;
        }
    }
    if (bytes.size() < 4) {
        error = "File is too small to identify.";
        return false;
    }
    path = file;
    sections.clear();
    symbols.clear();
    if (bytes[0] == 'M' && bytes[1] == 'Z') {
        format = BinaryFormat::PE;
        if (bytes.size() < 0x40) { error = "Truncated PE header."; return false; }
        const auto read16 = [&](std::size_t o) -> std::uint16_t {
            return o + 2 <= bytes.size() ? static_cast<std::uint16_t>(bytes[o] | (bytes[o + 1] << 8)) : 0;
        };
        const auto read32 = [&](std::size_t o) -> std::uint32_t {
            return o + 4 <= bytes.size() ? static_cast<std::uint32_t>(bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) : 0;
        };
        const auto read64 = [&](std::size_t o) -> std::uint64_t {
            return static_cast<std::uint64_t>(read32(o)) | (static_cast<std::uint64_t>(read32(o + 4)) << 32);
        };
        const auto pe = static_cast<std::size_t>(read32(0x3c));
        if (pe + 0x18 > bytes.size() || read32(pe) != 0x00004550) { error = "Invalid PE signature."; return false; }
        const auto sections_count = read16(pe + 6);
        switch (read16(pe + 4)) {
        case 0x014c: architecture = MachineArchitecture::X86; break;
        case 0x8664: architecture = MachineArchitecture::X64; break;
        case 0x01c0: case 0x01c4: architecture = MachineArchitecture::ARM; break;
        case 0xaa64: architecture = MachineArchitecture::ARM64; break;
        case 0x5032: case 0x5064: architecture = MachineArchitecture::RISCV; break;
        default: architecture = MachineArchitecture::Other; break;
        }
        const auto optional_size = read16(pe + 20);
        const auto optional = pe + 24;
        if (optional + optional_size > bytes.size() || optional_size < 0x70) { error = "Invalid PE optional header."; return false; }
        const auto magic = read16(optional);
        if (magic == 0x20b && optional_size >= 0x70) {
            is_64_bit = true;
            image_base = read64(optional + 24);
            entry_point = rva_to_va(read32(optional + 16));
        } else if (magic == 0x10b && optional_size >= 0x60) {
            is_64_bit = false;
            image_base = read32(optional + 28);
            entry_point = rva_to_va(read32(optional + 16));
        } else { error = "Unsupported PE optional header."; return false; }
        const auto section_table = optional + optional_size;
        sections.clear();
        for (std::uint16_t i = 0; i < sections_count; ++i) {
            const auto o = section_table + static_cast<std::size_t>(i) * 40;
            if (o + 40 > bytes.size()) break;
            Section section;
            char name[9]{};
            std::memcpy(name, bytes.data() + o, 8);
            section.name = name;
            section.virtual_size = read32(o + 8);
            section.rva = read32(o + 12);
            section.raw_size = read32(o + 16);
            section.raw_offset = read32(o + 20);
            section.characteristics = read32(o + 36);
            sections.push_back(std::move(section));
        }
    } else if (bytes[0] == 0x7f && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F') {
        format = BinaryFormat::ELF;
        if (bytes.size() < 0x34 || bytes[5] != 1) {
            error = "Only little-endian ELF images are supported.";
            return false;
        }
        const bool is64 = bytes[4] == 2;
        is_64_bit = is64;
        if (bytes[4] != 1 && bytes[4] != 2) {
            error = "Unsupported ELF class.";
            return false;
        }
        if (is64 && bytes.size() < 0x40) {
            error = "Truncated ELF64 header.";
            return false;
        }
        const auto read16 = [&](std::size_t offset) -> std::uint16_t {
            return offset + 2 <= bytes.size() ? static_cast<std::uint16_t>(bytes[offset] | (bytes[offset + 1] << 8)) : 0;
        };
        const auto read32 = [&](std::size_t offset) -> std::uint32_t {
            return offset + 4 <= bytes.size() ? static_cast<std::uint32_t>(bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) : 0;
        };
        const auto read64 = [&](std::size_t offset) -> std::uint64_t {
            return static_cast<std::uint64_t>(read32(offset)) | (static_cast<std::uint64_t>(read32(offset + 4)) << 32);
        };
        const auto read_word = [&](std::size_t offset) -> std::uint64_t { return is64 ? read64(offset) : read32(offset); };
        switch (read16(18)) {
        case 3: architecture = MachineArchitecture::X86; break;
        case 62: architecture = MachineArchitecture::X64; break;
        case 40: architecture = MachineArchitecture::ARM; break;
        case 183: architecture = MachineArchitecture::ARM64; break;
        case 243: architecture = MachineArchitecture::RISCV; break;
        default: architecture = MachineArchitecture::Other; break;
        }
        const auto entry = read_word(24);
        const auto elf_type = read16(16);
        image_base = 0;
        entry_point = entry;
        sections.clear();

        const auto section_offset = is64 ? read64(40) : read32(32);
        const auto section_entry_size = read16(is64 ? 58 : 46);
        const auto section_count = read16(is64 ? 60 : 48);
        const auto string_table_index = read16(is64 ? 62 : 50);
        std::vector<std::uint8_t> section_names;
        if (section_offset && section_entry_size && string_table_index < section_count &&
            section_offset + static_cast<std::uint64_t>(section_entry_size) * section_count <= bytes.size()) {
            const auto string_header = section_offset + static_cast<std::uint64_t>(section_entry_size) * string_table_index;
            const auto string_offset = is64 ? read64(static_cast<std::size_t>(string_header + 24)) : read32(static_cast<std::size_t>(string_header + 16));
            const auto string_size = is64 ? read64(static_cast<std::size_t>(string_header + 32)) : read32(static_cast<std::size_t>(string_header + 20));
            if (string_offset <= bytes.size() && string_size <= bytes.size() - string_offset)
                section_names.assign(bytes.begin() + static_cast<std::ptrdiff_t>(string_offset), bytes.begin() + static_cast<std::ptrdiff_t>(string_offset + string_size));
        }
        if (section_offset && section_entry_size >= (is64 ? 64 : 40) &&
            section_offset + static_cast<std::uint64_t>(section_entry_size) * section_count <= bytes.size()) {
            for (std::uint16_t index = 0; index < section_count; ++index) {
                const auto header = section_offset + static_cast<std::uint64_t>(section_entry_size) * index;
                const auto section_type = read32(static_cast<std::size_t>(header + 4));
                if (section_type != 2 && section_type != 11) continue; // SHT_SYMTAB / SHT_DYNSYM
                const auto symbol_offset = read_word(static_cast<std::size_t>(header + (is64 ? 24 : 16)));
                const auto symbol_size = read_word(static_cast<std::size_t>(header + (is64 ? 32 : 20)));
                const auto string_index = read32(static_cast<std::size_t>(header + (is64 ? 40 : 24)));
                const auto entry_size = read_word(static_cast<std::size_t>(header + (is64 ? 56 : 36)));
                if (entry_size < (is64 ? 24u : 16u) || string_index >= section_count || symbol_offset > bytes.size() || symbol_size > bytes.size() - symbol_offset) continue;
                const auto strings_header = section_offset + static_cast<std::uint64_t>(section_entry_size) * string_index;
                const auto strings_offset = read_word(static_cast<std::size_t>(strings_header + (is64 ? 24 : 16)));
                const auto strings_size = read_word(static_cast<std::size_t>(strings_header + (is64 ? 32 : 20)));
                if (strings_offset > bytes.size() || strings_size > bytes.size() - strings_offset) continue;
                const auto count = (std::min<std::uint64_t>)(symbol_size / entry_size, 500000);
                for (std::uint64_t symbol_index = 0; symbol_index < count; ++symbol_index) {
                    if (symbols.size() >= 500000) break;
                    const auto item = symbol_offset + symbol_index * entry_size;
                    if (item > bytes.size() || entry_size > bytes.size() - item) break;
                    const auto name_index = read32(static_cast<std::size_t>(item));
                    const auto value = read_word(static_cast<std::size_t>(item + (is64 ? 8 : 4)));
                    const auto size = read_word(static_cast<std::size_t>(item + (is64 ? 16 : 8)));
                    const auto info = bytes[static_cast<std::size_t>(item + (is64 ? 4 : 12))];
                    const auto section_index = read16(static_cast<std::size_t>(item + (is64 ? 6 : 14)));
                    if (!name_index || name_index >= strings_size || !section_index || !value) continue;
                    const auto name_start = strings_offset + name_index;
                    std::string name;
                    constexpr std::uint64_t max_elf_symbol_name_length = 4096;
                    auto cursor = name_start;
                    const auto strings_end = strings_offset + strings_size;
                    while (cursor < strings_end && cursor - name_start < max_elf_symbol_name_length &&
                           bytes[static_cast<std::size_t>(cursor)]) {
                        name.push_back(static_cast<char>(bytes[static_cast<std::size_t>(cursor)]));
                        ++cursor;
                    }
                    if (cursor >= strings_end || bytes[static_cast<std::size_t>(cursor)] != 0) continue;
                    if (!name.empty()) symbols.push_back({std::move(name), value, size, static_cast<std::uint8_t>(info & 0x0f)});
                }
            }
        }
        if (section_offset && section_entry_size && section_offset + static_cast<std::uint64_t>(section_entry_size) * section_count <= bytes.size()) {
            for (std::uint16_t index = 0; index < section_count; ++index) {
                const auto header = section_offset + static_cast<std::uint64_t>(section_entry_size) * index;
                const auto name_index = read32(static_cast<std::size_t>(header));
                const auto flags = read_word(static_cast<std::size_t>(header + (is64 ? 8 : 8)));
                const auto address = read_word(static_cast<std::size_t>(header + (is64 ? 16 : 12)));
                const auto raw_offset = read_word(static_cast<std::size_t>(header + (is64 ? 24 : 16)));
                const auto raw_size = read_word(static_cast<std::size_t>(header + (is64 ? 32 : 20)));
                if (!raw_size || raw_offset >= bytes.size() || raw_size > bytes.size() - raw_offset) continue;
                Section section;
                if (name_index < section_names.size()) {
                    constexpr std::size_t max_section_name_length = 4096;
                    for (std::size_t cursor = name_index; cursor < section_names.size() && section_names[cursor] &&
                         section.name.size() < max_section_name_length; ++cursor)
                        section.name.push_back(static_cast<char>(section_names[cursor]));
                    if (section.name.size() == max_section_name_length &&
                        (name_index + section.name.size() >= section_names.size() ||
                         section_names[name_index + section.name.size()] != 0)) section.name.clear();
                }
                if (section.name.empty()) section.name = "section_" + std::to_string(index);
                section.rva = address;
                section.virtual_size = static_cast<std::uint32_t>((std::min<std::uint64_t>)(raw_size, UINT32_MAX));
                section.raw_offset = static_cast<std::uint32_t>((std::min<std::uint64_t>)(raw_offset, UINT32_MAX));
                section.raw_size = static_cast<std::uint32_t>((std::min<std::uint64_t>)(raw_size, UINT32_MAX));
                section.characteristics = (flags & 0x4u) ? 0x20000000u : 0x40000000u;
                if (flags & 0x1u) section.characteristics |= 0x80000000u;
                sections.push_back(std::move(section));
            }
        }
        // Resolve function imports from dynamic relocation entries. This feeds
        // the emulator's safe guest-side import stubs through ELF GOT slots.
        if ((elf_type == 2 || elf_type == 3) && section_offset && section_entry_size >= (is64 ? 64 : 40) &&
            section_offset + static_cast<std::uint64_t>(section_entry_size) * section_count <= bytes.size()) {
            const auto supported_relocation = [&](std::uint64_t type) {
                if (architecture == MachineArchitecture::X64) return type == 6 || type == 7; // GLOB_DAT, JUMP_SLOT
                if (architecture == MachineArchitecture::X86) return type == 6 || type == 7;
                if (architecture == MachineArchitecture::ARM64) return type == 1025 || type == 1026;
                if (architecture == MachineArchitecture::ARM) return type == 21 || type == 22;
                return false;
            };
            for (std::uint16_t index = 0; index < section_count && imports.size() < 20000; ++index) {
                const auto relocation_header = section_offset + static_cast<std::uint64_t>(section_entry_size) * index;
                const auto relocation_type = read32(static_cast<std::size_t>(relocation_header + 4));
                if (relocation_type != 4 && relocation_type != 9) continue; // SHT_RELA / SHT_REL
                const auto symbol_table_index = read32(static_cast<std::size_t>(relocation_header + (is64 ? 40 : 24)));
                const auto relocation_offset = read_word(static_cast<std::size_t>(relocation_header + (is64 ? 24 : 16)));
                const auto relocation_size = read_word(static_cast<std::size_t>(relocation_header + (is64 ? 32 : 20)));
                const auto relocation_entry_size = read_word(static_cast<std::size_t>(relocation_header + (is64 ? 56 : 36)));
                if (symbol_table_index >= section_count || !relocation_entry_size || relocation_size > bytes.size() ||
                    relocation_offset > bytes.size() || relocation_size > bytes.size() - relocation_offset) continue;
                const auto symbol_header = section_offset + static_cast<std::uint64_t>(section_entry_size) * symbol_table_index;
                const auto symbol_type = read32(static_cast<std::size_t>(symbol_header + 4));
                if (symbol_type != 2 && symbol_type != 11) continue; // SHT_SYMTAB / SHT_DYNSYM
                const auto symbol_offset = read_word(static_cast<std::size_t>(symbol_header + (is64 ? 24 : 16)));
                const auto symbol_size = read_word(static_cast<std::size_t>(symbol_header + (is64 ? 32 : 20)));
                const auto string_table_index = read32(static_cast<std::size_t>(symbol_header + (is64 ? 40 : 24)));
                const auto symbol_entry_size = read_word(static_cast<std::size_t>(symbol_header + (is64 ? 56 : 36)));
                if (string_table_index >= section_count || !symbol_entry_size || symbol_offset > bytes.size() ||
                    symbol_size > bytes.size() - symbol_offset) continue;
                const auto string_header = section_offset + static_cast<std::uint64_t>(section_entry_size) * string_table_index;
                const auto string_offset = read_word(static_cast<std::size_t>(string_header + (is64 ? 24 : 16)));
                const auto string_size = read_word(static_cast<std::size_t>(string_header + (is64 ? 32 : 20)));
                if (string_offset > bytes.size() || string_size > bytes.size() - string_offset) continue;
                const auto relocation_minimum = relocation_type == 4 ? (is64 ? 24u : 12u) : (is64 ? 16u : 8u);
                const auto symbol_minimum = is64 ? 24u : 16u;
                if (relocation_entry_size < relocation_minimum || symbol_entry_size < symbol_minimum) continue;
                const auto relocation_count = (std::min<std::uint64_t>)(relocation_size / relocation_entry_size, 200000);
                for (std::uint64_t relocation_index = 0; relocation_index < relocation_count && imports.size() < 20000; ++relocation_index) {
                    const auto item = relocation_offset + relocation_index * relocation_entry_size;
                    if (item > bytes.size() || relocation_entry_size > bytes.size() - item) break;
                    const auto slot_address = read_word(static_cast<std::size_t>(item));
                    const auto info = read_word(static_cast<std::size_t>(item + (is64 ? 8 : 4)));
                    const auto symbol_index = is64 ? info >> 32 : info >> 8;
                    const auto relocation_kind = is64 ? static_cast<std::uint32_t>(info) : static_cast<std::uint8_t>(info);
                    if (!symbol_index || !supported_relocation(relocation_kind) || symbol_index >= symbol_size / symbol_entry_size) continue;
                    const auto symbol_item = symbol_offset + symbol_index * symbol_entry_size;
                    if (symbol_item > bytes.size() || symbol_entry_size > bytes.size() - symbol_item) continue;
                    const auto name_index = read32(static_cast<std::size_t>(symbol_item));
                    const auto info_byte = bytes[static_cast<std::size_t>(symbol_item + (is64 ? 4 : 12))];
                    const auto section_index = read16(static_cast<std::size_t>(symbol_item + (is64 ? 6 : 14)));
                    if (!name_index || name_index >= string_size || section_index != 0 || (info_byte & 0x0f) == 1) continue;
                    const auto name_start = string_offset + name_index;
                    const auto string_end = string_offset + string_size;
                    std::string name;
                    auto name_cursor = name_start;
                    for (; name_cursor < string_end && bytes[static_cast<std::size_t>(name_cursor)] && name.size() < 256; ++name_cursor)
                        name.push_back(static_cast<char>(bytes[static_cast<std::size_t>(name_cursor)]));
                    const auto slot_offset = va_to_file_offset(slot_address);
                    const auto pointer_size = is64 ? sizeof(std::uint64_t) : sizeof(std::uint32_t);
                    if (name.empty() || name.size() == 256 || name_cursor >= string_end ||
                        bytes[static_cast<std::size_t>(name_cursor)] != 0 || !slot_offset ||
                        pointer_size > bytes.size() - *slot_offset) continue;
                    if (std::none_of(imports.begin(), imports.end(), [&](const Import& imported) {
                        return imported.address == slot_address && imported.name == name;
                    })) imports.push_back({std::move(name), slot_address});
                }
            }
        }
        // Stripped ELF files may have no section table. PT_LOAD entries still
        // provide an exact file-to-virtual-address mapping for disassembly.
        if (sections.empty()) {
            const auto program_offset = is64 ? read64(32) : read32(28);
            const auto program_entry_size = read16(is64 ? 54 : 42);
            const auto program_count = read16(is64 ? 56 : 44);
            if (program_offset && program_entry_size && program_offset + static_cast<std::uint64_t>(program_entry_size) * program_count <= bytes.size()) {
                for (std::uint16_t index = 0; index < program_count; ++index) {
                    const auto header = program_offset + static_cast<std::uint64_t>(program_entry_size) * index;
                    const auto type = read32(static_cast<std::size_t>(header));
                    if (type != 1) continue;
                    const auto flags = is64 ? read32(static_cast<std::size_t>(header + 4)) : read32(static_cast<std::size_t>(header + 24));
                    const auto raw_offset = is64 ? read64(static_cast<std::size_t>(header + 8)) : read32(static_cast<std::size_t>(header + 4));
                    const auto address = is64 ? read64(static_cast<std::size_t>(header + 16)) : read32(static_cast<std::size_t>(header + 8));
                    const auto raw_size = is64 ? read64(static_cast<std::size_t>(header + 32)) : read32(static_cast<std::size_t>(header + 16));
                    if (!raw_size || raw_offset >= bytes.size() || raw_size > bytes.size() - raw_offset) continue;
                    Section section;
                    section.name = "LOAD" + std::to_string(index);
                    section.rva = address;
                    section.virtual_size = static_cast<std::uint32_t>((std::min<std::uint64_t>)(raw_size, UINT32_MAX));
                    section.raw_offset = static_cast<std::uint32_t>((std::min<std::uint64_t>)(raw_offset, UINT32_MAX));
                    section.raw_size = static_cast<std::uint32_t>((std::min<std::uint64_t>)(raw_size, UINT32_MAX));
                    section.characteristics = (flags & 1u ? 0x80000000u : 0u) | (flags & 2u ? 0x40000000u : 0u) | (flags & 4u ? 0x20000000u : 0u);
                    sections.push_back(std::move(section));
                }
            }
        }
        if (sections.empty()) {
            error = "ELF contains no mappable sections.";
            return false;
        }
    } else {
        format = BinaryFormat::Unknown;
        error = "Unsupported binary format.";
        return false;
    }
    cleanup.succeeded = true;
    return true;
}

std::vector<std::uint64_t> BinaryImage::find_bytes(const std::vector<std::uint8_t>& pattern) const {
    std::vector<std::optional<std::uint8_t>> exact;
    exact.reserve(pattern.size());
    for (const auto byte : pattern) exact.emplace_back(byte);
    // Preserve the original API contract: find_bytes returns every match;
    // only interactive UI searches impose a display/result cap.
    return find_pattern(exact, (std::numeric_limits<std::size_t>::max)());
}

std::vector<std::uint64_t> BinaryImage::find_pattern(
    const std::vector<std::optional<std::uint8_t>>& pattern, std::size_t max_matches,
    bool* truncated) const {
    if (truncated) *truncated = false;
    std::vector<std::uint64_t> result;
    if (pattern.empty() || pattern.size() > bytes.size() || max_matches == 0) return result;

    std::size_t anchor_start = 0, anchor_size = 0;
    for (std::size_t i = 0; i < pattern.size();) {
        if (!pattern[i]) { ++i; continue; }
        const auto start = i;
        while (i < pattern.size() && pattern[i]) ++i;
        if (i - start > anchor_size) { anchor_start = start; anchor_size = i - start; }
    }

    const auto append_match = [&](std::size_t offset) {
        auto address = image_base + static_cast<std::uint64_t>(offset);
        for (const auto& section : sections) {
            if (offset >= section.raw_offset && offset - section.raw_offset < section.raw_size) {
                address = image_base + section.rva + static_cast<std::uint64_t>(offset - section.raw_offset);
                break;
            }
        }
        result.push_back(address);
    };

    if (!anchor_size) {
        const auto count = bytes.size() - pattern.size() + 1;
        const auto emit = (std::min)(count, max_matches);
        for (std::size_t offset = 0; offset < emit; ++offset) append_match(offset);
        if (truncated) *truncated = emit < count;
        return result;
    }

    std::array<std::size_t, 256> shifts;
    shifts.fill(anchor_size);
    for (std::size_t index = 0; index + 1 < anchor_size; ++index)
        shifts[*pattern[anchor_start + index]] = anchor_size - index - 1;

    std::size_t anchor_end = anchor_size - 1;
    while (anchor_end < bytes.size()) {
        std::size_t matched = 0;
        while (matched < anchor_size &&
               bytes[anchor_end - matched] == *pattern[anchor_start + anchor_size - 1 - matched])
            ++matched;
        if (matched == anchor_size) {
            const auto anchor_offset = anchor_end - anchor_size + 1;
        if (anchor_offset >= anchor_start) {
            const auto candidate = anchor_offset - anchor_start;
            if (candidate <= bytes.size() - pattern.size()) {
                bool matches = true;
                for (std::size_t index = 0; index < pattern.size(); ++index) {
                    if (pattern[index] && *pattern[index] != bytes[candidate + index]) { matches = false; break; }
                }
                if (matches) {
                    if (result.size() == max_matches) {
                        if (truncated) *truncated = true;
                        break;
                    }
                    append_match(candidate);
                }
            }
        }
        }
        const auto shift = shifts[bytes[anchor_end]];
        if (shift > bytes.size() - 1 - anchor_end) break;
        anchor_end += shift;
    }
    return result;
}

std::optional<std::size_t> BinaryImage::rva_to_file_offset(std::uint64_t rva) const {
    for (const auto& section : sections) {
        const auto span = static_cast<std::uint64_t>((std::max)(section.virtual_size, section.raw_size));
        if (rva >= section.rva && rva - section.rva < span) {
            const auto relative = rva - section.rva;
            if (relative > UINT64_MAX - section.raw_offset) continue;
            const auto offset64 = relative + section.raw_offset;
            if (offset64 < bytes.size()) return static_cast<std::size_t>(offset64);
        }
    }
    return std::nullopt;
}

std::optional<std::size_t> BinaryImage::va_to_file_offset(std::uint64_t address) const {
    if (address < image_base) return std::nullopt;
    return rva_to_file_offset(address - image_base);
}

AnalysisDatabase::AnalysisDatabase(BinaryImage image) : image_(std::move(image)) {}

void AnalysisDatabase::add_function(Function function) {
    functions_.push_back(std::move(function));
}

void AnalysisDatabase::sort_functions() {
    std::stable_sort(functions_.begin(), functions_.end(), [](const Function& a, const Function& b) { return a.start < b.start; });
    functions_.erase(std::unique(functions_.begin(), functions_.end(), [](const Function& a, const Function& b) { return a.start == b.start; }), functions_.end());
}

bool AnalysisDatabase::rename_function(std::uint64_t start, const std::string& name) {
    const auto it = std::lower_bound(functions_.begin(), functions_.end(), start, [](const Function& f, std::uint64_t v) { return f.start < v; });
    if (it == functions_.end() || it->start != start) return false;
    it->name = name;
    return true;
}

void AnalysisDatabase::add_xref(Xref xref) {
    if (xrefs_.size() >= kMaxXrefsPerAnalysis) { xrefs_truncated_ = true; return; }
    xrefs_.push_back(std::move(xref));
    xref_index_dirty_ = true;
}

std::size_t AnalysisDatabase::estimated_analysis_memory_bytes() const noexcept {
    std::size_t total = 0;
    const auto add = [&](std::size_t count, std::size_t element_size) {
        const auto maximum = (std::numeric_limits<std::size_t>::max)();
        if (element_size && count > (maximum - total) / element_size) total = maximum;
        else total += count * element_size;
    };
    const auto add_string = [&](const std::string& value) {
        // Capacity is intentionally used as a conservative approximation;
        // small-string storage may be counted even though it is inline.
        const auto maximum = (std::numeric_limits<std::size_t>::max)();
        if (value.capacity() >= maximum - total) total = maximum;
        else total += value.capacity() + 1;
    };

    add(functions_.capacity(), sizeof(Function));
    for (const auto& function : functions_) {
        add_string(function.name);
        add(function.instructions.capacity(), sizeof(Instruction));
        for (const auto& instruction : function.instructions) {
            add_string(instruction.mnemonic);
            add_string(instruction.operands);
        }
        add(function.callees.capacity(), sizeof(std::uint64_t));
    }
    add(xrefs_.capacity(), sizeof(Xref));
    for (const auto& xref : xrefs_) add_string(xref.kind);

    add(xref_index_.capacity(), sizeof(std::pair<std::uint64_t, std::size_t>));
    return total;
}

std::vector<std::reference_wrapper<const Xref>> AnalysisDatabase::xrefs_at(std::uint64_t address) const {
    if (xref_index_dirty_) {
        std::vector<std::pair<std::uint64_t, std::size_t>>().swap(xref_index_);
        xref_index_.reserve(xrefs_.size() * 2);
        for (std::size_t index = 0; index < xrefs_.size(); ++index) {
            const auto& xref = xrefs_[index];
            xref_index_.emplace_back(xref.from, index);
            if (xref.to != xref.from) xref_index_.emplace_back(xref.to, index);
        }
        std::sort(xref_index_.begin(), xref_index_.end());
        xref_index_dirty_ = false;
    }
    std::vector<std::reference_wrapper<const Xref>> result;
    auto found = std::lower_bound(xref_index_.begin(), xref_index_.end(), address,
        [](const auto& entry, std::uint64_t value) { return entry.first < value; });
    while (found != xref_index_.end() && found->first == address) {
        result.emplace_back(std::cref(xrefs_[found->second]));
        ++found;
    }
    return result;
}

void AnalysisDatabase::discover_basic_xrefs() {
    // Release peak-sized instruction caches instead of keeping the outer
    // Function array allocated until this database is destroyed.
    std::vector<Function>().swap(functions_);
    functions_truncated_ = false;
    std::vector<Xref>().swap(xrefs_);
    xrefs_truncated_ = false;
    std::vector<std::pair<std::uint64_t, std::size_t>>().swap(xref_index_);
    xref_index_dirty_ = true;
    const auto append_xref = [&](Xref xref) {
        if (xrefs_.size() >= kMaxXrefsPerAnalysis) { xrefs_truncated_ = true; return false; }
        xrefs_.push_back(std::move(xref));
        return true;
    };
    const auto xref_budget_full = [&] {
        if (xrefs_.size() < kMaxXrefsPerAnalysis) return false;
        xrefs_truncated_ = true;
        return true;
    };
    if (image_.format == BinaryFormat::ELF) {
        std::set<std::uint64_t> known_functions;
        const auto add_function = [&](std::uint64_t address, const std::string& name) {
            if (!image_.va_to_file_offset(address)) return;
            if (known_functions.contains(address)) {
                const auto existing = std::find_if(functions_.begin(), functions_.end(),
                    [address](const Function& function) { return function.start == address; });
                if (existing != functions_.end() && !name.empty() &&
                    (existing->name == "_start (EntryPoint)" || existing->name.rfind("sub_", 0) == 0))
                    existing->name = name;
                return;
            }
            if (functions_.size() >= kMaxDiscoveredFunctions) { functions_truncated_ = true; return; }
            if (known_functions.insert(address).second) {
                functions_.push_back({address, name, {}, {}});
            }
        };
        if (image_.entry_point) add_function(image_.entry_point, "_start (EntryPoint)");
        for (const auto& symbol : image_.symbols) {
                    if (symbol.kind == 2 && symbol.address && image_.va_to_file_offset(symbol.address)) {
                add_function(symbol.address, symbol.name);
                const auto found = std::find_if(functions_.begin(), functions_.end(),
                    [&](const Function& function) { return function.start == symbol.address; });
                if (found != functions_.end() && symbol.size && image_.va_to_file_offset(symbol.address + symbol.size - 1))
                    found->end = symbol.address + symbol.size;
            }
        }
        if (image_.architecture != MachineArchitecture::ARM64) for (const auto& section : image_.sections) {
            if ((section.characteristics & 0x20000000u) == 0) continue;
        const auto start = static_cast<std::size_t>(section.raw_offset);
        const auto end = (std::min)(image_.bytes.size(), start + static_cast<std::size_t>(section.raw_size));
        for (std::size_t offset = start; offset < end; ++offset) {
                const bool frame_prologue = image_.is_64_bit && offset + 4 <= end && image_.bytes[offset] == 0x55 && image_.bytes[offset + 1] == 0x48 && image_.bytes[offset + 2] == 0x89 && image_.bytes[offset + 3] == 0xE5;
                const bool stack_prologue = image_.is_64_bit && offset + 4 <= end && image_.bytes[offset] == 0x48 && image_.bytes[offset + 1] == 0x83 && image_.bytes[offset + 2] == 0xEC;
                const bool x86_frame = !image_.is_64_bit && offset + 2 <= end && image_.bytes[offset] == 0x55 && image_.bytes[offset + 1] == 0x8B;
                const auto candidate_va = image_.image_base + section.rva + static_cast<std::uint64_t>(offset - start);
                const bool after_endbr = offset >= start + 4 && image_.bytes[offset - 4] == 0xF3 && image_.bytes[offset - 3] == 0x0F &&
                                         image_.bytes[offset - 2] == 0x1E && image_.bytes[offset - 1] == 0xFA && known_functions.contains(candidate_va - 4);
                const bool inside_known = std::any_of(functions_.begin(), functions_.end(), [&](const Function& item) {
                    return item.end && item.start < candidate_va && candidate_va < item.end; });
                if ((frame_prologue || stack_prologue || x86_frame) && !after_endbr && !inside_known)
                if (known_functions.size() < kMaxDiscoveredFunctions)
                    add_function(image_.image_base + section.rva + static_cast<std::uint64_t>(offset - start), sub_name(image_.image_base + section.rva + static_cast<std::uint64_t>(offset - start)));
                else functions_truncated_ = true;
            }
        }
        std::sort(functions_.begin(), functions_.end(), [](const Function& left, const Function& right) { return left.start < right.start; });
        discover_transitive_callees(image_, functions_, known_functions, functions_truncated_);
        std::sort(functions_.begin(), functions_.end(), [](const Function& left, const Function& right) { return left.start < right.start; });
        decode_functions_bounded(image_, functions_);
        const auto elf_import_at = [&](std::uint64_t address) -> const BinaryImage::Import* {
            const auto found = std::find_if(image_.imports.begin(), image_.imports.end(),
                [&](const BinaryImage::Import& imported) { return imported.address == address; });
            return found == image_.imports.end() ? nullptr : &*found;
        };
        for (const auto& function : functions_) for (const auto& instruction : function.instructions) {
            if (xref_budget_full()) break;
            const auto& mnemonic = instruction.mnemonic;
            const bool conditional = is_conditional_branch(mnemonic);
            if (!is_call_instruction(mnemonic) && !is_unconditional_jump(mnemonic) && !conditional) continue;
            const auto target = direct_target(instruction);
            if (target && image_.va_to_file_offset(*target)) append_xref({instruction.address, *target,
                is_call_instruction(mnemonic) ? "call" : conditional ? "jcc" : "jmp"});
        }
        // ELF binaries need data references too, not only branch/call edges.
        // Resolve x86-64 RIP-relative memory operands against the next
        // instruction and classify printable targets as strings.
        const auto printable_string_at = [&](std::uint64_t address) {
            const auto offset = image_.va_to_file_offset(address);
            if (!offset) return false;
            std::size_t length = 0;
            while (*offset + length < image_.bytes.size() && length < 160) {
                const auto byte = image_.bytes[*offset + length];
                if (!byte) break;
                if (byte < 0x20 || byte > 0x7e) return false;
                ++length;
            }
            return length >= 4;
        };
        std::set<std::pair<std::uint64_t, std::uint64_t>> data_xrefs;
        for (const auto& function : functions_) for (const auto& instruction : function.instructions) {
            if (xref_budget_full()) break;
            const auto rip = instruction.operands.find("rip");
            if (rip == std::string::npos) continue;
            const auto plus = instruction.operands.find('+', rip);
            const auto minus = instruction.operands.find('-', rip);
            const bool negative = minus != std::string::npos && (plus == std::string::npos || minus < plus);
            const auto sign = negative ? minus : plus;
            if (sign == std::string::npos) continue;
            const auto literal = instruction.operands.find("0x", sign);
            if (literal == std::string::npos) continue;
            const auto end = instruction.operands.find_first_not_of("0123456789abcdefABCDEF", literal + 2);
            try {
                const auto displacement = std::stoull(instruction.operands.substr(literal, end - literal), nullptr, 16);
                const auto next = instruction.address + instruction.size;
                if (next < instruction.address) continue;
                if (negative && displacement > next) continue;
                if (!negative && displacement > UINT64_MAX - next) continue;
                const auto target = negative ? next - displacement : next + displacement;
                if (!image_.va_to_file_offset(target) || !data_xrefs.insert({instruction.address, target}).second) continue;
                const auto* imported = elf_import_at(target);
                append_xref({instruction.address, target, imported ? "import:ELF!" + imported->name :
                    printable_string_at(target) ? "string" : "data"});
            } catch (...) {
                // Malformed disassembler operand text is not an analysis failure.
            }
        }
        if (image_.architecture == MachineArchitecture::ARM64) {
            const auto register_key = [](std::string name) {
                if (name.size() > 1 && name.front() == 'w' &&
                    std::all_of(name.begin() + 1, name.end(), [](unsigned char c) { return std::isdigit(c); }))
                    name.front() = 'x';
                return name;
            };
            const auto trim = [](std::string value) {
                const auto first = value.find_first_not_of(" \t");
                if (first == std::string::npos) return std::string{};
                const auto last = value.find_last_not_of(" \t");
                value = value.substr(first, last - first + 1);
                std::transform(value.begin(), value.end(), value.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                return value;
            };
            const auto split_operands = [&](const std::string& text) {
                std::vector<std::string> result;
                std::size_t begin = 0;
                int brackets = 0;
                for (std::size_t index = 0; index < text.size(); ++index) {
                    if (text[index] == '[') ++brackets;
                    else if (text[index] == ']') --brackets;
                    else if (text[index] == ',' && brackets == 0) {
                        result.push_back(trim(text.substr(begin, index - begin)));
                        begin = index + 1;
                    }
                }
                if (begin < text.size()) result.push_back(trim(text.substr(begin)));
                return result;
            };
            const auto parse_immediate = [](std::string text) -> std::optional<std::uint64_t> {
                if (!text.empty() && text.front() == '#') text.erase(text.begin());
                try {
                    std::size_t consumed = 0;
                    const auto value = std::stoull(text, &consumed, 0);
                    if (consumed != text.size()) return std::nullopt;
                    return value;
                } catch (...) { return std::nullopt; }
            };
            const auto add_arm64_xref = [&](const Instruction& instruction, std::uint64_t target) {
                if (xref_budget_full() || !image_.va_to_file_offset(target) ||
                    !data_xrefs.insert({instruction.address, target}).second) return;
                const auto* imported = elf_import_at(target);
                append_xref({instruction.address, target, imported ? "import:ELF!" + imported->name :
                    printable_string_at(target) ? "string" : "data"});
            };
            const auto read_pointer_at = [&](std::uint64_t address, std::size_t width) -> std::optional<std::uint64_t> {
                const auto offset = image_.va_to_file_offset(address);
                if (!offset || width > image_.bytes.size() - *offset) return std::nullopt;
                std::uint64_t value = 0;
                for (std::size_t index = 0; index < width; ++index)
                    value |= static_cast<std::uint64_t>(image_.bytes[*offset + index]) << (index * 8);
                return value;
            };
            for (const auto& function : functions_) {
                std::unordered_map<std::string, std::uint64_t> address_registers;
                std::uint64_t previous_end = 0;
                for (const auto& instruction : function.instructions) {
                    if (xref_budget_full()) break;
                    if (previous_end && previous_end != instruction.address) address_registers.clear();
                    previous_end = instruction.address + instruction.size;
                    const auto operands = split_operands(instruction.operands);
                    const auto& mnemonic = instruction.mnemonic;
                    if (mnemonic == "adrp" || mnemonic == "adr") {
                        if (operands.size() >= 2) {
                            if (const auto target = direct_target(instruction)) {
                                address_registers[register_key(operands[0])] = *target;
                                add_arm64_xref(instruction, *target);
                            } else address_registers.erase(register_key(operands[0]));
                        }
                        continue;
                    }
                    if (mnemonic == "mov" && operands.size() >= 2) {
                        const auto source = address_registers.find(register_key(operands[1]));
                        if (source != address_registers.end() &&
                            (operands[0].empty() || operands[0][0] != 'w' || source->second <= UINT32_MAX))
                            address_registers[register_key(operands[0])] = source->second;
                        else address_registers.erase(register_key(operands[0]));
                        continue;
                    }
                    if (mnemonic == "add" || mnemonic == "sub") {
                        if (operands.size() >= 3 && address_registers.contains(register_key(operands[1]))) {
                            const auto immediate = parse_immediate(operands[2]);
                            const auto base = address_registers[register_key(operands[1])];
                            if (immediate && (mnemonic != "add" || *immediate <= UINT64_MAX - base) &&
                                (mnemonic != "sub" || *immediate <= base)) {
                                const auto target = mnemonic == "add" ? base + *immediate : base - *immediate;
                                if (operands[0].empty() || operands[0][0] != 'w' || target <= UINT32_MAX) {
                                    address_registers[register_key(operands[0])] = target;
                                    add_arm64_xref(instruction, target);
                                } else address_registers.erase(register_key(operands[0]));
                            } else address_registers.erase(register_key(operands[0]));
                        } else if (!operands.empty()) address_registers.erase(register_key(operands[0]));
                        continue;
                    }
                    if (mnemonic.rfind("ldr", 0) == 0 || mnemonic == "prfm") {
                        std::optional<std::uint64_t> load_address;
                        if (operands.size() >= 2) {
                            const auto open = operands[1].find('[');
                            const auto close = operands[1].find(']');
                            if (open != std::string::npos && close > open) {
                                const auto address_parts = split_operands(operands[1].substr(open + 1, close - open - 1));
                                if (!address_parts.empty() && address_registers.contains(register_key(address_parts[0]))) {
                                    const auto base = address_registers[register_key(address_parts[0])];
                                    const auto offset = address_parts.size() > 1
                                        ? parse_immediate(address_parts[1]) : std::optional<std::uint64_t>{0};
                                    if (offset && *offset <= UINT64_MAX - base) load_address = base + *offset;
                                }
                            } else load_address = direct_target(instruction);
                        }
                        if (load_address) {
                            add_arm64_xref(instruction, *load_address);
                            if (mnemonic == "ldr" && !operands.empty() && operands[0].size() > 1 &&
                                (operands[0][0] == 'x' || operands[0][0] == 'w') &&
                                std::all_of(operands[0].begin() + 1, operands[0].end(), [](unsigned char c) { return std::isdigit(c); })) {
                                const auto loaded = read_pointer_at(*load_address, operands[0][0] == 'w' ? 4 : 8);
                                if (loaded && image_.va_to_file_offset(*loaded)) {
                                    address_registers[register_key(operands[0])] = *loaded;
                                    add_arm64_xref(instruction, *loaded);
                                } else address_registers.erase(register_key(operands[0]));
                            } else if (!operands.empty()) address_registers.erase(register_key(operands[0]));
                        } else if (!operands.empty()) address_registers.erase(register_key(operands[0]));
                        continue;
                    }
                    address_registers.clear();
                }
            }
        }
        std::sort(xrefs_.begin(), xrefs_.end(), [](const Xref& left, const Xref& right) { return std::tie(left.from, left.to, left.kind) < std::tie(right.from, right.to, right.kind); });
        xrefs_.erase(std::unique(xrefs_.begin(), xrefs_.end(), [](const Xref& left, const Xref& right) { return left.from == right.from && left.to == right.to && left.kind == right.kind; }), xrefs_.end());
        for (const auto& xref : xrefs_) {
            if (xref.kind != "call") continue;
            auto caller = std::upper_bound(functions_.begin(), functions_.end(), xref.from,
                [](std::uint64_t address, const Function& item) { return address < item.start; });
            // lower_bound (not upper_bound), so an exact-start match is found; the
            // previous upper_bound version never matched (it always lands one past
            // any element equal to xref.to), so every function.callees stayed empty.
            auto callee = std::lower_bound(functions_.begin(), functions_.end(), xref.to,
                [](const Function& item, std::uint64_t address) { return item.start < address; });
            if (caller != functions_.begin()) {
                --caller;
                if (callee != functions_.end() && callee->start == xref.to)
                    caller->callees.push_back(callee->start);
            }
        }
        for (auto& function : functions_) {
            std::sort(function.callees.begin(), function.callees.end());
            function.callees.erase(std::unique(function.callees.begin(), function.callees.end()), function.callees.end());
        }
        return;
    }
    if (image_.format != BinaryFormat::PE) return;
    std::set<std::uint64_t> known_functions;
    if (image_.entry_point != 0) {
        known_functions.insert(image_.entry_point);
        functions_.push_back({image_.entry_point, "_start (EntryPoint)", {}, {}});
    }
    for (const auto& function : functions_) known_functions.insert(function.start);
    const auto read16 = [&](std::size_t offset) -> std::uint16_t {
        return offset + 2 <= image_.bytes.size() ? static_cast<std::uint16_t>(image_.bytes[offset] | (image_.bytes[offset + 1] << 8)) : 0;
    };
    const auto read32 = [&](std::size_t offset) -> std::uint32_t {
        return offset + 4 <= image_.bytes.size() ? static_cast<std::uint32_t>(image_.bytes[offset] | (image_.bytes[offset + 1] << 8) | (image_.bytes[offset + 2] << 16) | (image_.bytes[offset + 3] << 24)) : 0;
    };
    const auto add_discovered_function = [&](std::uint64_t address, std::string name) {
        const auto file_offset = image_.va_to_file_offset(address);
        if (!file_offset || address < image_.image_base) return;
        const auto rva = address - image_.image_base;
        const auto executable_section = std::find_if(image_.sections.begin(), image_.sections.end(), [&](const BinaryImage::Section& section) {
            const auto extent = static_cast<std::uint64_t>((std::max)(section.virtual_size, section.raw_size));
            return (section.characteristics & 0x20000000u) != 0 && rva >= section.rva && rva - section.rva < extent;
        });
        if (executable_section == image_.sections.end() || known_functions.contains(address)) return;
        if (functions_.size() >= kMaxDiscoveredFunctions) { functions_truncated_ = true; return; }
        known_functions.insert(address);
        functions_.push_back({address, std::move(name), {}, {}});
    };
    const auto pe_header = static_cast<std::size_t>(read32(0x3c));
    const auto optional_header = pe_header + 24;
    const auto optional_magic = read16(optional_header);
    const auto directory_base = optional_header + (optional_magic == 0x20b ? 0x70 : 0x60);
    const auto add_directory_functions = [&](std::size_t directory_index, const auto& visitor) {
        const auto directory = directory_base + directory_index * 8;
        if (directory + 8 > image_.bytes.size()) return;
        const auto rva = read32(directory), size = read32(directory + 4);
        if (!rva || !size) return;
        const auto offset = image_.rva_to_file_offset(rva);
        if (offset) visitor(*offset, size);
    };
    // Exported entry points are reliable function starts even in stripped binaries.
    add_directory_functions(0, [&](std::size_t export_offset, std::uint32_t export_size) {
        if (export_offset + 40 > image_.bytes.size()) return;
        const auto function_count = read32(export_offset + 20), name_count = read32(export_offset + 24);
        const auto functions_rva = read32(export_offset + 28), names_rva = read32(export_offset + 32), ordinals_rva = read32(export_offset + 36);
        const auto functions_offset = image_.rva_to_file_offset(functions_rva), names_offset = image_.rva_to_file_offset(names_rva), ordinals_offset = image_.rva_to_file_offset(ordinals_rva);
        if (!functions_offset || !names_offset || !ordinals_offset) return;
        if (name_count > kMaxDiscoveredFunctions) functions_truncated_ = true;
        for (std::uint32_t index = 0; index < name_count && index < kMaxDiscoveredFunctions; ++index) {
            const auto name_entry = *names_offset + static_cast<std::size_t>(index) * 4;
            const auto ordinal_entry = *ordinals_offset + static_cast<std::size_t>(index) * 2;
            if (name_entry + 4 > image_.bytes.size() || ordinal_entry + 2 > image_.bytes.size()) break;
            const auto name_offset = image_.rva_to_file_offset(read32(name_entry));
            const auto ordinal = read16(ordinal_entry);
            if (ordinal >= function_count) continue;
            const auto function_entry = *functions_offset + static_cast<std::size_t>(ordinal) * 4;
            if (function_entry + 4 > image_.bytes.size()) continue;
            const auto target_rva = read32(function_entry);
            const auto export_rva = read32(directory_base);
            if (target_rva >= export_rva && target_rva - export_rva < export_size) continue; // forwarded export string
            if (target_rva > UINT64_MAX - image_.image_base) continue;
            const auto target = image_.image_base + target_rva;
            std::string name;
            if (name_offset) {
                constexpr std::size_t max_export_name_length = 4096;
                std::size_t cursor = *name_offset;
                while (cursor < image_.bytes.size() && image_.bytes[cursor] &&
                       name.size() < max_export_name_length) {
                    name.push_back(static_cast<char>(image_.bytes[cursor++]));
                }
                if (cursor >= image_.bytes.size() || image_.bytes[cursor] != 0) continue;
            }
            if (!name.empty()) add_discovered_function(target, name);
        }
    });
    // x64 .pdata Runtime Function entries describe compiler-generated starts.
    // When that authoritative table is present, avoid the byte-pattern
    // prologue fallback below: scanning every byte of .text invents function
    // starts from immediates and embedded data.
    bool has_valid_unwind_entries = false;
    if (image_.architecture == MachineArchitecture::X64) add_directory_functions(3, [&](std::size_t pdata_offset, std::uint32_t directory_size) {
        const auto entry_count = (std::min<std::uint32_t>)(directory_size / 12, static_cast<std::uint32_t>(kMaxDiscoveredFunctions));
        if (directory_size / 12 > kMaxDiscoveredFunctions) functions_truncated_ = true;
        for (std::uint32_t index = 0; index < entry_count; ++index) {
            const auto entry = pdata_offset + static_cast<std::size_t>(index) * 12;
            if (entry + 12 > image_.bytes.size()) break;
            const auto begin_rva = read32(entry), end_rva = read32(entry + 4);
            if (!begin_rva || end_rva <= begin_rva || end_rva > UINT64_MAX - image_.image_base) continue;
            const auto begin = image_.image_base + begin_rva;
            const auto end = image_.image_base + end_rva;
            const auto code_section = std::find_if(image_.sections.begin(), image_.sections.end(), [&](const BinaryImage::Section& section) {
                if ((section.characteristics & 0x20000000u) == 0 || begin_rva < section.rva) return false;
                const auto extent = static_cast<std::uint64_t>((std::max)(section.virtual_size, section.raw_size));
                return begin_rva - section.rva < extent && end_rva - section.rva <= extent;
            });
            if (code_section == image_.sections.end() || !image_.va_to_file_offset(begin) ||
                !image_.va_to_file_offset(end - 1)) continue;
            has_valid_unwind_entries = true;
            add_discovered_function(begin, sub_name(begin));
            const auto function = std::find_if(functions_.begin(), functions_.end(),
                [begin](const Function& item) { return item.start == begin; });
            if (function != functions_.end() && image_.va_to_file_offset(end - 1)) function->end = end;
        }
    });
    if (!has_valid_unwind_entries && image_.architecture != MachineArchitecture::ARM64) for (const auto& section : image_.sections) {
        if ((section.characteristics & 0x20000000u) == 0) continue;
        const auto start = static_cast<std::size_t>(section.raw_offset);
        const auto end = std::min(image_.bytes.size(), start + static_cast<std::size_t>(section.raw_size));
        for (std::size_t i = start; i + 5 <= end; ++i) {
            const bool frame_prologue = i + 4 <= end && image_.bytes[i] == 0x55 && image_.bytes[i + 1] == 0x48 && image_.bytes[i + 2] == 0x89 && image_.bytes[i + 3] == 0xE5;
            const bool stack_prologue = i + 4 <= end && image_.bytes[i] == 0x48 && image_.bytes[i + 1] == 0x83 && image_.bytes[i + 2] == 0xEC;
            const bool large_stack_prologue = i + 7 <= end && image_.bytes[i] == 0x48 && image_.bytes[i + 1] == 0x81 && image_.bytes[i + 2] == 0xEC;
            const bool saved_register_prologue = i + 1 < end && image_.bytes[i] == 0x40 && image_.bytes[i + 1] >= 0x53 && image_.bytes[i + 1] <= 0x57;
            if (frame_prologue || stack_prologue || large_stack_prologue || saved_register_prologue) {
                const auto function_va = image_.image_base + section.rva + (i - start);
                if (known_functions.contains(function_va)) continue;
                // CET builds start every function with endbr64 (F3 0F 1E FA); the frame
                // prologue right after it belongs to the same function.
                if (i >= start + 4 && image_.bytes[i - 4] == 0xF3 && image_.bytes[i - 3] == 0x0F &&
                    image_.bytes[i - 2] == 0x1E && image_.bytes[i - 1] == 0xFA &&
                    known_functions.contains(function_va - 4)) continue;
                // Never start a function in the middle of one whose extent is already known
                // (ELF symbol sizes, .pdata ranges).
                if (const auto container = std::find_if(functions_.begin(), functions_.end(), [&](const Function& item) {
                        return item.end && item.start < function_va && function_va < item.end; });
                    container != functions_.end()) continue;
                if (functions_.size() < kMaxDiscoveredFunctions) {
                    known_functions.insert(function_va);
                    functions_.push_back({function_va, sub_name(function_va), {}, {}});
                } else functions_truncated_ = true;
            }
        }
    }

    // Discover callees transitively from decoded instructions, not raw opcode
    // bytes: E8/E9 can occur inside immediates and data embedded in code sections.
    discover_transitive_callees(image_, functions_, known_functions, functions_truncated_);
    std::sort(functions_.begin(), functions_.end(), [](const Function& left, const Function& right) {
        return left.start < right.start;
    });
    functions_.erase(std::unique(functions_.begin(), functions_.end(), [](const Function& left, const Function& right) {
        return left.start == right.start;
    }), functions_.end());
    // Keep the tree and graph deterministic and attach decoded instructions to
    // every discovered function. This makes navigation use the same analysis
    // data as the listing instead of drawing synthetic nodes.
    decode_functions_bounded(image_, functions_);

    // Capstone exposes RIP-relative memory operands as text such as
    // "qword ptr [rip + 0x40211]". Resolve those references to the actual
    // image address so globals, strings and the import table get XREFs too.
    std::set<std::pair<std::uint64_t, std::uint64_t>> data_xrefs;
    // Use the decoded instruction stream for control-flow references as well.
    // The old byte scan only recognized near E8/E9 forms and consequently
    // missed short jumps and all conditional-branch encodings.
    for (const auto& function : functions_) {
        for (const auto& instruction : function.instructions) {
            if (xref_budget_full()) break;
            const auto& mnemonic = instruction.mnemonic;
            const bool conditional_jump = is_conditional_branch(mnemonic);
            if (!is_call_instruction(mnemonic) && !is_unconditional_jump(mnemonic) && !conditional_jump) continue;
            const auto target = direct_target(instruction);
            if (!target || !image_.va_to_file_offset(*target)) continue;
            const auto kind = is_call_instruction(mnemonic) ? "call" : conditional_jump ? "jcc" : "jmp";
            append_xref({instruction.address, *target, kind});
        }
    }
    std::map<std::uint64_t, std::string> import_targets;
    // Build an import-slot map so XREF output identifies imported APIs instead
    // of presenting IAT/GOT accesses as anonymous data references.
    if (image_.format == BinaryFormat::PE && pe_header + 24 <= image_.bytes.size()) {
        const auto directory = directory_base + 8; // IMAGE_DIRECTORY_ENTRY_IMPORT
        if (directory + 8 <= image_.bytes.size()) {
            const auto import_rva = read32(directory);
            if (import_rva) {
                const auto descriptor = image_.rva_to_file_offset(import_rva);
                if (descriptor) {
                    const bool is64 = optional_magic == 0x20b;
                    const std::size_t thunk_width = is64 ? 8u : 4u;
                    const auto read64 = [&](std::size_t offset) -> std::uint64_t {
                        return static_cast<std::uint64_t>(read32(offset)) |
                               (static_cast<std::uint64_t>(read32(offset + 4)) << 32);
                    };
                    const auto read_c_string = [&](std::size_t offset) -> std::string {
                        std::string value;
                        for (std::size_t cursor = offset; cursor < image_.bytes.size() && image_.bytes[cursor] && value.size() < 256; ++cursor)
                            value.push_back(static_cast<char>(image_.bytes[cursor]));
                        return value;
                    };
                    for (std::size_t descriptor_index = 0;
                         descriptor_index < 4096 && import_targets.size() < kMaxImportXrefTargets; ++descriptor_index) {
                        const auto current = *descriptor + descriptor_index * 20;
                        if (current + 20 > image_.bytes.size()) break;
                        const auto original_thunk = read32(current);
                        const auto name_rva = read32(current + 12);
                        const auto first_thunk = read32(current + 16);
                        if (!original_thunk && !name_rva && !first_thunk) break;
                        const auto dll_offset = image_.rva_to_file_offset(name_rva);
                        const auto dll_name = dll_offset ? read_c_string(*dll_offset) : std::string("<unknown>");
                        const auto lookup_rva = original_thunk ? original_thunk : first_thunk;
                        const auto lookup_offset = image_.rva_to_file_offset(lookup_rva);
                        if (!lookup_offset || !first_thunk) continue;
                        for (std::size_t index = 0;
                             index < 65536 && import_targets.size() < kMaxImportXrefTargets; ++index) {
                            const auto entry = *lookup_offset + index * thunk_width;
                            if (entry + thunk_width > image_.bytes.size()) break;
                            const auto thunk = is64 ? read64(entry) : static_cast<std::uint64_t>(read32(entry));
                            if (!thunk) break;
                            std::string symbol;
                            if ((is64 && (thunk & (1ull << 63))) || (!is64 && (thunk & 0x80000000u))) {
                                symbol = "ordinal_" + std::to_string(thunk & 0xffffu);
                            } else {
                                const auto hint_name = image_.rva_to_file_offset(static_cast<std::uint32_t>(thunk));
                                if (hint_name && *hint_name + 2 < image_.bytes.size()) symbol = read_c_string(*hint_name + 2);
                            }
                            if (symbol.empty()) symbol = "ordinal_" + std::to_string(index);
                            import_targets[image_.image_base + first_thunk + index * thunk_width] = "import:" + dll_name + "!" + symbol;
                        }
                    }
                }
            }
        }
    }
    const auto printable_string_at = [&](std::uint64_t address) -> bool {
        const auto offset = image_.va_to_file_offset(address);
        if (!offset) return false;
        std::size_t length = 0;
        while (*offset + length < image_.bytes.size() && length < 160) {
            const auto byte = image_.bytes[*offset + length];
            if (!byte) break;
            if (byte < 0x20 || byte > 0x7e) return false;
            ++length;
        }
        return length >= 4;
    };
    if (image_.architecture == MachineArchitecture::ARM64) {
        const auto register_key = [](std::string name) {
            if (name.size() > 1 && name.front() == 'w' &&
                std::all_of(name.begin() + 1, name.end(), [](unsigned char c) { return std::isdigit(c); }))
                name.front() = 'x';
            return name;
        };
        const auto trim = [](std::string value) {
            const auto first = value.find_first_not_of(" \t");
            if (first == std::string::npos) return std::string{};
            const auto last = value.find_last_not_of(" \t");
            value = value.substr(first, last - first + 1);
            std::transform(value.begin(), value.end(), value.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return value;
        };
        const auto split_operands = [&](const std::string& text) {
            std::vector<std::string> result;
            std::size_t begin = 0;
            int brackets = 0;
            for (std::size_t index = 0; index < text.size(); ++index) {
                if (text[index] == '[') ++brackets;
                else if (text[index] == ']') --brackets;
                else if (text[index] == ',' && brackets == 0) {
                    result.push_back(trim(text.substr(begin, index - begin)));
                    begin = index + 1;
                }
            }
            if (begin < text.size()) result.push_back(trim(text.substr(begin)));
            return result;
        };
        const auto parse_immediate = [](std::string text) -> std::optional<std::uint64_t> {
            if (!text.empty() && text.front() == '#') text.erase(text.begin());
            try {
                std::size_t consumed = 0;
                const auto value = std::stoull(text, &consumed, 0);
                if (consumed != text.size()) return std::nullopt;
                return value;
            } catch (...) { return std::nullopt; }
        };
        const auto add_data_xref = [&](const Instruction& instruction, std::uint64_t target) {
            if (xref_budget_full() || !image_.va_to_file_offset(target) ||
                !data_xrefs.insert({instruction.address, target}).second) return;
            std::string kind = "data";
            if (const auto imported = import_targets.find(target); imported != import_targets.end()) kind = imported->second;
            else if (printable_string_at(target)) kind = "string";
            append_xref({instruction.address, target, std::move(kind)});
        };
        const auto read_pointer_at = [&](std::uint64_t address, std::size_t width) -> std::optional<std::uint64_t> {
            const auto offset = image_.va_to_file_offset(address);
            if (!offset || width > image_.bytes.size() - *offset) return std::nullopt;
            std::uint64_t value = 0;
            for (std::size_t index = 0; index < width; ++index)
                value |= static_cast<std::uint64_t>(image_.bytes[*offset + index]) << (index * 8);
            return value;
        };
        for (const auto& function : functions_) {
            std::unordered_map<std::string, std::uint64_t> address_registers;
            std::uint64_t previous_end = 0;
            for (const auto& instruction : function.instructions) {
                if (previous_end && previous_end != instruction.address) address_registers.clear();
                previous_end = instruction.address + instruction.size;
                const auto operands = split_operands(instruction.operands);
                const auto& mnemonic = instruction.mnemonic;
                if (mnemonic == "adrp" || mnemonic == "adr") {
                    if (operands.size() >= 2) {
                        const auto target = direct_target(instruction);
                        if (target) {
                            address_registers[register_key(operands[0])] = *target;
                            add_data_xref(instruction, *target);
                        } else address_registers.erase(register_key(operands[0]));
                    }
                    continue;
                }
                if (mnemonic == "mov" && operands.size() >= 2) {
                    const auto source = address_registers.find(register_key(operands[1]));
                    if (source != address_registers.end() &&
                        (operands[0].empty() || operands[0][0] != 'w' || source->second <= UINT32_MAX))
                        address_registers[register_key(operands[0])] = source->second;
                    else address_registers.erase(register_key(operands[0]));
                    continue;
                }
                if (mnemonic == "add" || mnemonic == "sub") {
                    if (operands.size() >= 3 && address_registers.contains(register_key(operands[1]))) {
                        const auto immediate = parse_immediate(operands[2]);
                        const auto base = address_registers[register_key(operands[1])];
                        if (immediate && (mnemonic != "add" || *immediate <= UINT64_MAX - base) &&
                            (mnemonic != "sub" || *immediate <= base)) {
                            const auto target = mnemonic == "add" ? base + *immediate : base - *immediate;
                            if (operands[0].empty() || operands[0][0] != 'w' || target <= UINT32_MAX) {
                                address_registers[register_key(operands[0])] = target;
                                add_data_xref(instruction, target);
                            } else address_registers.erase(register_key(operands[0]));
                        } else address_registers.erase(register_key(operands[0]));
                    } else if (!operands.empty()) address_registers.erase(register_key(operands[0]));
                    continue;
                }
                if (mnemonic.rfind("ldr", 0) == 0 || mnemonic == "prfm") {
                    std::optional<std::uint64_t> load_address;
                    if (operands.size() >= 2) {
                        const auto open = operands[1].find('[');
                        const auto close = operands[1].find(']');
                        if (open != std::string::npos && close > open) {
                            const auto address_parts = split_operands(operands[1].substr(open + 1, close - open - 1));
                            if (!address_parts.empty() && address_registers.contains(register_key(address_parts[0]))) {
                                const auto base = address_registers[register_key(address_parts[0])];
                                auto offset = address_parts.size() > 1 ? parse_immediate(address_parts[1]) : std::optional<std::uint64_t>{0};
                                if (offset && *offset <= UINT64_MAX - base) load_address = base + *offset;
                            }
                        } else load_address = direct_target(instruction); // PC-relative literal load.
                    }
                    if (load_address) {
                        add_data_xref(instruction, *load_address);
                        if (mnemonic == "ldr" && !operands.empty() && operands[0].size() > 1 &&
                            (operands[0][0] == 'x' || operands[0][0] == 'w') &&
                            std::all_of(operands[0].begin() + 1, operands[0].end(), [](unsigned char c) { return std::isdigit(c); })) {
                            const auto loaded = read_pointer_at(*load_address, operands[0][0] == 'w' ? 4 : 8);
                            if (loaded && image_.va_to_file_offset(*loaded)) {
                                address_registers[register_key(operands[0])] = *loaded;
                                add_data_xref(instruction, *loaded);
                            } else address_registers.erase(register_key(operands[0]));
                        } else if (!operands.empty()) address_registers.erase(register_key(operands[0]));
                    } else if (!operands.empty()) address_registers.erase(register_key(operands[0]));
                    continue;
                }
                // The tiny propagation window is intentionally killed by any
                // other instruction so stale constants cannot create false XREFs.
                address_registers.clear();
            }
        }
    }
    for (const auto& function : functions_) {
        for (const auto& instruction : function.instructions) {
            if (xref_budget_full()) break;
            if (image_.architecture == MachineArchitecture::ARM64) continue;
            const auto rip = instruction.operands.find("rip");
            if (rip == std::string::npos) {
                // In 32-bit x86, absolute memory operands are commonly rendered
                // as [0xXXXXXXXX]. Resolve only a plain numeric address inside
                // brackets; indexed/base-register expressions are not constants.
                const auto open = instruction.operands.find('[');
                const auto close = open == std::string::npos ? std::string::npos : instruction.operands.find(']', open + 1);
                std::string expression;
                const bool immediate_address = open == std::string::npos &&
                    (instruction.mnemonic == "push" || instruction.mnemonic == "mov" || instruction.mnemonic == "movabs");
                if (open != std::string::npos) {
                    if (close == std::string::npos) continue;
                    expression = instruction.operands.substr(open + 1, close - open - 1);
                } else if (immediate_address) {
                    const auto comma = instruction.operands.rfind(',');
                    expression = instruction.operands.substr(comma == std::string::npos ? 0 : comma + 1);
                } else {
                    continue;
                }
                const auto first = expression.find_first_not_of(" \t");
                const auto last = expression.find_last_not_of(" \t");
                if (first == std::string::npos) continue;
                expression = expression.substr(first, last - first + 1);
                if (expression.size() < 3 || expression[0] != '0' || (expression[1] != 'x' && expression[1] != 'X') ||
                    expression.find_first_not_of("0123456789abcdefABCDEF", 2) != std::string::npos) continue;
                try {
                    const auto target = std::stoull(expression, nullptr, 16);
                    if (!image_.va_to_file_offset(target)) continue;
                    if (data_xrefs.insert({instruction.address, target}).second) {
                        std::string kind = immediate_address ? "offset" : "data";
                        if (const auto imported = import_targets.find(target); imported != import_targets.end()) kind = imported->second;
                        else if (!immediate_address && printable_string_at(target)) kind = "string";
                        append_xref({instruction.address, target, std::move(kind)});
                    }
                } catch (...) {
                    // Ignore malformed disassembler text rather than aborting analysis.
                }
                continue;
            }
            const auto plus = instruction.operands.find('+', rip);
            const auto minus = instruction.operands.find('-', rip);
            const bool negative = minus != std::string::npos && (plus == std::string::npos || minus < plus);
            const auto sign = negative ? minus : plus;
            if (sign == std::string::npos) continue;
            const auto literal = instruction.operands.find("0x", sign);
            if (literal == std::string::npos) continue;
            const auto end = instruction.operands.find_first_not_of("0123456789abcdefABCDEF", literal + 2);
            try {
                const auto displacement = std::stoull(instruction.operands.substr(literal, end - literal), nullptr, 16);
                const auto next = instruction.address + instruction.size;
                const auto target = negative ? next - displacement : next + displacement;
                if (!image_.va_to_file_offset(target)) continue;
                if (data_xrefs.insert({instruction.address, target}).second) {
                    std::string kind = "data";
                    if (const auto imported = import_targets.find(target); imported != import_targets.end()) kind = imported->second;
                    else if (printable_string_at(target)) kind = "string";
                    append_xref({instruction.address, target, std::move(kind)});
                }
            } catch (...) {
                // An operand that only happens to contain the word "rip" is
                // ignored; it should not prevent the rest of the analysis.
            }
        }
    }
    std::sort(xrefs_.begin(), xrefs_.end(), [](const Xref& left, const Xref& right) {
        return std::tie(left.from, left.to, left.kind) < std::tie(right.from, right.to, right.kind);
    });
    xrefs_.erase(std::unique(xrefs_.begin(), xrefs_.end(), [](const Xref& left, const Xref& right) {
        return left.from == right.from && left.to == right.to && left.kind == right.kind;
    }), xrefs_.end());
    for (const auto& xref : xrefs_) {
        if (xref.kind != "call") continue;
        auto caller = std::upper_bound(functions_.begin(), functions_.end(), xref.from,
            [](std::uint64_t address, const Function& item) { return address < item.start; });
        // lower_bound (not upper_bound), so an exact-start match is found; the
        // previous upper_bound version never matched (it always lands one past any
        // element equal to xref.to), so every function.callees stayed empty.
        auto callee = std::lower_bound(functions_.begin(), functions_.end(), xref.to,
            [](const Function& item, std::uint64_t address) { return item.start < address; });
        if (caller != functions_.begin()) {
            --caller;
            if (callee != functions_.end() && callee->start == xref.to)
                caller->callees.push_back(callee->start);
        }
    }
    for (auto& function : functions_) {
        std::sort(function.callees.begin(), function.callees.end());
        function.callees.erase(std::unique(function.callees.begin(), function.callees.end()), function.callees.end());
    }
}

std::optional<std::reference_wrapper<const Function>>
AnalysisDatabase::function_at(std::uint64_t address) const {
    if (!image_.va_to_file_offset(address)) return std::nullopt;
    auto function = std::upper_bound(functions_.begin(), functions_.end(), address,
        [](std::uint64_t value, const Function& item) { return value < item.start; });
    if (function == functions_.begin()) return std::nullopt;
    --function;
    const auto next = std::next(function);
    const auto inferred_end = next == functions_.end() ? UINT64_MAX : next->start;
    const auto end = function->end && function->end < inferred_end ? function->end : inferred_end;
    return address < end ? std::optional<std::reference_wrapper<const Function>>(std::cref(*function)) : std::nullopt;
}

std::vector<std::uint64_t> AnalysisDatabase::call_path(std::uint64_t from, std::uint64_t to,
                                                       std::size_t max_depth) const {
    const auto source = function_at(from);
    const auto destination = function_at(to);
    if (!source || !destination || max_depth == 0) return {};
    const auto start = source->get().start;
    const auto goal = destination->get().start;
    if (start == goal) return {start};

    std::queue<std::pair<std::uint64_t, std::size_t>> pending;
    std::unordered_map<std::uint64_t, std::uint64_t> parent;
    parent.emplace(start, start);
    pending.emplace(start, 0);
    while (!pending.empty()) {
        const auto [current, depth] = pending.front();
        pending.pop();
        if (depth >= max_depth) continue;
        const auto function = std::lower_bound(functions_.begin(), functions_.end(), current,
            [](const Function& item, std::uint64_t address) { return item.start < address; });
        if (function == functions_.end() || function->start != current) continue;
        for (const auto callee : function->callees) {
            const auto target = std::lower_bound(functions_.begin(), functions_.end(), callee,
                [](const Function& item, std::uint64_t address) { return item.start < address; });
            if (target == functions_.end() || target->start != callee || parent.contains(callee)) continue;
            parent.emplace(callee, current);
            if (callee == goal) {
                std::vector<std::uint64_t> path{goal};
                for (auto node = goal; node != start;) {
                    node = parent.at(node);
                    path.push_back(node);
                }
                std::reverse(path.begin(), path.end());
                return path;
            }
            pending.emplace(callee, depth + 1);
        }
    }
    return {};
}

bool AnalysisDatabase::patch_bytes(std::uint64_t address, const std::vector<std::uint8_t>& replacement,
                                   std::vector<std::uint8_t>& original, std::string& error) {
    const auto offset = image_.va_to_file_offset(address);
    if (!offset || *offset + replacement.size() > image_.bytes.size()) {
        error = "Patch address is outside the file image.";
        return false;
    }
    original.assign(image_.bytes.begin() + static_cast<std::ptrdiff_t>(*offset),
                    image_.bytes.begin() + static_cast<std::ptrdiff_t>(*offset + replacement.size()));
    std::copy(replacement.begin(), replacement.end(), image_.bytes.begin() + static_cast<std::ptrdiff_t>(*offset));
    return true;
}

bool AnalysisDatabase::write_patched_file(const std::filesystem::path& file, std::string& error) const {
    std::ofstream output(file, std::ios::binary | std::ios::trunc);
    if (!output) { error = "Could not create patched file: " + file.string(); return false; }
    output.write(reinterpret_cast<const char*>(image_.bytes.data()), static_cast<std::streamsize>(image_.bytes.size()));
    if (!output) { error = "Could not write patched file: " + file.string(); return false; }
    return true;
}

bool AnalysisDatabase::replace_file_bytes(std::size_t offset, const std::vector<std::uint8_t>& replacement, std::string& error) {
    if (offset + replacement.size() > image_.bytes.size()) { error = "File offset is outside the image."; return false; }
    std::copy(replacement.begin(), replacement.end(), image_.bytes.begin() + static_cast<std::ptrdiff_t>(offset));
    return true;
}

} // namespace gandon
