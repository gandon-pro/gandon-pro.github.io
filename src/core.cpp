#include "gandon/core.hpp"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <cstring>
#include <map>
#include <set>
#include <tuple>

namespace gandon {

bool BinaryImage::load(const std::filesystem::path& file, std::string& error) {
    std::ifstream input(file, std::ios::binary);
    if (!input) {
        error = "Could not open binary: " + file.string();
        return false;
    }
    bytes.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    if (bytes.size() < 4) {
        error = "File is too small to identify.";
        return false;
    }
    path = file;
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
        if (bytes.size() < 0x40 || bytes[5] != 1) {
            error = "Only little-endian ELF images are supported.";
            return false;
        }
        const bool is64 = bytes[4] == 2;
        is_64_bit = is64;
        if (bytes[4] != 1 && bytes[4] != 2) {
            error = "Unsupported ELF class.";
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
        const auto entry = read_word(24);
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
                    for (std::size_t cursor = name_index; cursor < section_names.size() && section_names[cursor]; ++cursor) section.name.push_back(static_cast<char>(section_names[cursor]));
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
    return true;
}

std::vector<std::uint64_t> BinaryImage::find_bytes(const std::vector<std::uint8_t>& pattern) const {
    std::vector<std::uint64_t> result;
    if (pattern.empty() || pattern.size() > bytes.size()) return result;
    for (std::size_t i = 0; i + pattern.size() <= bytes.size(); ++i) {
        if (std::equal(pattern.begin(), pattern.end(), bytes.begin() + static_cast<std::ptrdiff_t>(i))) {
            auto address = image_base + static_cast<std::uint64_t>(i);
            for (const auto& section : sections) {
                if (i >= section.raw_offset && i < static_cast<std::size_t>(section.raw_offset) + section.raw_size) {
                    address = image_base + section.rva + static_cast<std::uint64_t>(i - section.raw_offset);
                    break;
                }
            }
            result.push_back(address);
        }
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

void AnalysisDatabase::add_xref(Xref xref) {
    xrefs_.push_back(std::move(xref));
}

void AnalysisDatabase::discover_basic_xrefs() {
    functions_.clear();
    xrefs_.clear();
    if (image_.format == BinaryFormat::ELF) {
        std::set<std::uint64_t> known_functions;
        const auto add_function = [&](std::uint64_t address, const std::string& name) {
            if (image_.va_to_file_offset(address) && known_functions.insert(address).second)
                functions_.push_back({address, name, {}, {}});
        };
        if (image_.entry_point) add_function(image_.entry_point, "_start (EntryPoint)");
        for (const auto& section : image_.sections) {
            if ((section.characteristics & 0x20000000u) == 0) continue;
            const auto start = static_cast<std::size_t>(section.raw_offset);
            const auto end = (std::min)(image_.bytes.size(), start + static_cast<std::size_t>(section.raw_size));
            for (std::size_t offset = start; offset < end; ++offset) {
                const bool frame_prologue = image_.is_64_bit && offset + 4 <= end && image_.bytes[offset] == 0x55 && image_.bytes[offset + 1] == 0x48 && image_.bytes[offset + 2] == 0x89 && image_.bytes[offset + 3] == 0xE5;
                const bool stack_prologue = image_.is_64_bit && offset + 4 <= end && image_.bytes[offset] == 0x48 && image_.bytes[offset + 1] == 0x83 && image_.bytes[offset + 2] == 0xEC;
                const bool x86_frame = !image_.is_64_bit && offset + 2 <= end && image_.bytes[offset] == 0x55 && image_.bytes[offset + 1] == 0x8B;
                if (frame_prologue || stack_prologue || x86_frame)
                    add_function(image_.image_base + section.rva + static_cast<std::uint64_t>(offset - start), "sub_" + std::to_string(image_.image_base + section.rva + static_cast<std::uint64_t>(offset - start)));
                if (image_.is_64_bit && offset + 5 <= end && image_.bytes[offset] == 0xE8) {
                    const auto displacement = static_cast<std::int32_t>(static_cast<std::uint32_t>(image_.bytes[offset + 1]) |
                        (static_cast<std::uint32_t>(image_.bytes[offset + 2]) << 8) | (static_cast<std::uint32_t>(image_.bytes[offset + 3]) << 16) |
                        (static_cast<std::uint32_t>(image_.bytes[offset + 4]) << 24));
                    const auto instruction = image_.image_base + section.rva + static_cast<std::uint64_t>(offset - start);
                    add_function(static_cast<std::uint64_t>(static_cast<std::int64_t>(instruction + 5) + displacement), "sub_" + std::to_string(static_cast<std::uint64_t>(static_cast<std::int64_t>(instruction + 5) + displacement)));
                }
            }
        }
        std::sort(functions_.begin(), functions_.end(), [](const Function& left, const Function& right) { return left.start < right.start; });
        for (auto& function : functions_) function.instructions = decode_x64(image_, function.start, 256);
        const auto target_from = [](const Instruction& instruction) -> std::optional<std::uint64_t> {
            if (instruction.operands.find('[') != std::string::npos) return std::nullopt;
            const auto literal = instruction.operands.find("0x");
            if (literal == std::string::npos) return std::nullopt;
            const auto end = instruction.operands.find_first_not_of("0123456789abcdefABCDEF", literal + 2);
            try { return std::stoull(instruction.operands.substr(literal, end - literal), nullptr, 16); } catch (...) { return std::nullopt; }
        };
        for (const auto& function : functions_) for (const auto& instruction : function.instructions) {
            const auto& mnemonic = instruction.mnemonic;
            const bool conditional = mnemonic.size() > 1 && mnemonic.front() == 'j' && mnemonic != "jmp";
            if (mnemonic != "call" && mnemonic != "jmp" && !conditional) continue;
            const auto target = target_from(instruction);
            if (target && image_.va_to_file_offset(*target)) xrefs_.push_back({instruction.address, *target, mnemonic == "call" ? "call" : conditional ? "jcc" : "jmp"});
        }
        std::sort(xrefs_.begin(), xrefs_.end(), [](const Xref& left, const Xref& right) { return std::tie(left.from, left.to, left.kind) < std::tie(right.from, right.to, right.kind); });
        xrefs_.erase(std::unique(xrefs_.begin(), xrefs_.end(), [](const Xref& left, const Xref& right) { return left.from == right.from && left.to == right.to && left.kind == right.kind; }), xrefs_.end());
        for (auto& function : functions_) for (const auto& xref : xrefs_) if (xref.from >= function.start && xref.from < function.start + 0x1000 && xref.kind == "call") function.callees.push_back(xref.to);
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
        if (!image_.va_to_file_offset(address)) return;
        if (known_functions.insert(address).second) functions_.push_back({address, std::move(name), {}, {}});
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
    add_directory_functions(0, [&](std::size_t export_offset, std::uint32_t) {
        if (export_offset + 40 > image_.bytes.size()) return;
        const auto function_count = read32(export_offset + 20), name_count = read32(export_offset + 24);
        const auto functions_rva = read32(export_offset + 28), names_rva = read32(export_offset + 32), ordinals_rva = read32(export_offset + 36);
        const auto functions_offset = image_.rva_to_file_offset(functions_rva), names_offset = image_.rva_to_file_offset(names_rva), ordinals_offset = image_.rva_to_file_offset(ordinals_rva);
        if (!functions_offset || !names_offset || !ordinals_offset) return;
        for (std::uint32_t index = 0; index < name_count && index < 8192; ++index) {
            const auto name_entry = *names_offset + static_cast<std::size_t>(index) * 4;
            const auto ordinal_entry = *ordinals_offset + static_cast<std::size_t>(index) * 2;
            if (name_entry + 4 > image_.bytes.size() || ordinal_entry + 2 > image_.bytes.size()) break;
            const auto name_offset = image_.rva_to_file_offset(read32(name_entry));
            const auto ordinal = read16(ordinal_entry);
            const auto function_entry = *functions_offset + static_cast<std::size_t>(ordinal) * 4;
            if (function_entry + 4 > image_.bytes.size()) continue;
            const auto target = image_.image_base + read32(function_entry);
            std::string name;
            if (name_offset) for (std::size_t cursor = *name_offset; cursor < image_.bytes.size() && image_.bytes[cursor]; ++cursor) name.push_back(static_cast<char>(image_.bytes[cursor]));
            if (!name.empty()) add_discovered_function(target, name);
        }
        (void)function_count;
    });
    // x64 .pdata Runtime Function entries describe compiler-generated starts.
    add_directory_functions(3, [&](std::size_t pdata_offset, std::uint32_t directory_size) {
        const auto entry_count = (std::min<std::uint32_t>)(directory_size / 12, 1u << 20);
        for (std::uint32_t index = 0; index < entry_count; ++index) {
            const auto entry = pdata_offset + static_cast<std::size_t>(index) * 12;
            if (entry + 12 > image_.bytes.size()) break;
            const auto begin_rva = read32(entry), end_rva = read32(entry + 4);
            if (!begin_rva || end_rva <= begin_rva) continue;
            add_discovered_function(image_.image_base + begin_rva, "sub_" + std::to_string(image_.image_base + begin_rva));
        }
    });
    for (const auto& section : image_.sections) {
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
                if (known_functions.insert(function_va).second)
                    functions_.push_back({function_va, "sub_" + std::to_string(function_va), {}, {}});
            }
            const auto opcode = image_.bytes[i];
            if (opcode != 0xE8 && opcode != 0xE9) continue;
            const auto disp = static_cast<std::int32_t>(
                static_cast<std::uint32_t>(image_.bytes[i + 1]) |
                (static_cast<std::uint32_t>(image_.bytes[i + 2]) << 8) |
                (static_cast<std::uint32_t>(image_.bytes[i + 3]) << 16) |
                (static_cast<std::uint32_t>(image_.bytes[i + 4]) << 24));
            const auto instruction_va = image_.image_base + section.rva + (i - start);
            const auto target = static_cast<std::uint64_t>(static_cast<std::int64_t>(instruction_va + 5) + disp);
            xrefs_.push_back({instruction_va, target, opcode == 0xE8 ? "call" : "jmp"});
            if (opcode == 0xE8 && known_functions.insert(target).second) {
                functions_.push_back({target, "sub_" + std::to_string(target), {}, {}});
            }
        }
    }

    // Keep the tree and graph deterministic and attach decoded instructions to
    // every discovered function. This makes navigation use the same analysis
    // data as the listing instead of drawing synthetic nodes.
    std::sort(functions_.begin(), functions_.end(), [](const Function& left, const Function& right) {
        return left.start < right.start;
    });
    functions_.erase(std::unique(functions_.begin(), functions_.end(), [](const Function& left, const Function& right) {
        return left.start == right.start;
    }), functions_.end());
    for (auto& function : functions_) function.instructions = decode_x64(image_, function.start, 256);

    // Capstone exposes RIP-relative memory operands as text such as
    // "qword ptr [rip + 0x40211]". Resolve those references to the actual
    // image address so globals, strings and the import table get XREFs too.
    std::set<std::pair<std::uint64_t, std::uint64_t>> data_xrefs;
    // Use the decoded instruction stream for control-flow references as well.
    // The old byte scan only recognized near E8/E9 forms and consequently
    // missed short jumps and all conditional-branch encodings.
    const auto direct_target = [](const Instruction& instruction) -> std::optional<std::uint64_t> {
        if (instruction.operands.find('[') != std::string::npos) return std::nullopt;
        const auto literal = instruction.operands.find("0x");
        if (literal == std::string::npos) return std::nullopt;
        const auto end = instruction.operands.find_first_not_of("0123456789abcdefABCDEF", literal + 2);
        try { return std::stoull(instruction.operands.substr(literal, end - literal), nullptr, 16); }
        catch (...) { return std::nullopt; }
    };
    for (const auto& function : functions_) {
        for (const auto& instruction : function.instructions) {
            const auto& mnemonic = instruction.mnemonic;
            const bool conditional_jump = mnemonic.size() > 1 && mnemonic.front() == 'j' && mnemonic != "jmp";
            if (mnemonic != "call" && mnemonic != "jmp" && !conditional_jump) continue;
            const auto target = direct_target(instruction);
            if (!target || !image_.va_to_file_offset(*target)) continue;
            const auto kind = mnemonic == "call" ? "call" : conditional_jump ? "jcc" : "jmp";
            xrefs_.push_back({instruction.address, *target, kind});
        }
    }
    std::map<std::uint64_t, std::string> import_targets;
    // Build a small IAT map so XREF output identifies imported APIs instead of
    // presenting every RIP-relative IAT access as an anonymous data reference.
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
                    for (std::size_t descriptor_index = 0; descriptor_index < 4096; ++descriptor_index) {
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
                        for (std::size_t index = 0; index < 65536; ++index) {
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
    for (const auto& function : functions_) {
        for (const auto& instruction : function.instructions) {
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
                const auto target = negative ? next - displacement : next + displacement;
                if (!image_.va_to_file_offset(target)) continue;
                if (data_xrefs.insert({instruction.address, target}).second) {
                    std::string kind = "data";
                    if (const auto imported = import_targets.find(target); imported != import_targets.end()) kind = imported->second;
                    else if (printable_string_at(target)) kind = "string";
                    xrefs_.push_back({instruction.address, target, std::move(kind)});
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
    for (auto& function : functions_) {
        for (const auto& xref : xrefs_) {
            if (xref.from >= function.start && xref.from < function.start + 0x1000 && xref.kind == "call")
                function.callees.push_back(xref.to);
        }
    }
}

std::optional<std::reference_wrapper<const Function>>
AnalysisDatabase::function_at(std::uint64_t address) const {
    for (std::size_t index = 0; index < functions_.size(); ++index) {
        const auto& function = functions_[index];
        const auto next = index + 1 < functions_.size() ? functions_[index + 1].start : UINT64_MAX;
        if (address >= function.start && address < next) return std::cref(function);
    }
    return std::nullopt;
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
