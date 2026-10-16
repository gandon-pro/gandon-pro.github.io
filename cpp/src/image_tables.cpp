#include "gandon/image_tables.hpp"

#include <algorithm>
#include <cstdio>
#include <set>
#include <unordered_map>

namespace gandon {
namespace {
std::uint16_t rd16(const BinaryImage& image, std::size_t offset) {
    return offset <= image.bytes.size() && image.bytes.size() - offset >= 2
        ? static_cast<std::uint16_t>(image.bytes[offset] | (image.bytes[offset + 1] << 8)) : 0;
}
std::uint32_t rd32(const BinaryImage& image, std::size_t offset) {
    return offset <= image.bytes.size() && image.bytes.size() - offset >= 4
        ? static_cast<std::uint32_t>(image.bytes[offset] | (image.bytes[offset + 1] << 8) |
                                     (image.bytes[offset + 2] << 16) | (static_cast<std::uint32_t>(image.bytes[offset + 3]) << 24)) : 0;
}
std::uint64_t rd64(const BinaryImage& image, std::size_t offset) {
    return static_cast<std::uint64_t>(rd32(image, offset)) | (static_cast<std::uint64_t>(rd32(image, offset + 4)) << 32);
}
std::string rd_string(const BinaryImage& image, std::size_t offset, std::size_t limit = 512) {
    std::string value;
    for (std::size_t i = offset; i < image.bytes.size() && image.bytes[i] && value.size() < limit; ++i)
        value.push_back(static_cast<char>(image.bytes[i]));
    return value;
}

const char* resource_type_name(std::uint32_t id) {
    switch (id) {
    case 1: return "RT_CURSOR"; case 2: return "RT_BITMAP"; case 3: return "RT_ICON"; case 4: return "RT_MENU";
    case 5: return "RT_DIALOG"; case 6: return "RT_STRING"; case 7: return "RT_FONTDIR"; case 8: return "RT_FONT";
    case 9: return "RT_ACCELERATOR"; case 10: return "RT_RCDATA"; case 11: return "RT_MESSAGETABLE";
    case 12: return "RT_GROUP_CURSOR"; case 14: return "RT_GROUP_ICON"; case 16: return "RT_VERSION";
    case 17: return "RT_DLGINCLUDE"; case 19: return "RT_PLUGPLAY"; case 20: return "RT_VXD"; case 21: return "RT_ANICURSOR";
    case 22: return "RT_ANIICON"; case 23: return "RT_HTML"; case 24: return "RT_MANIFEST";
    default: return nullptr;
    }
}
} // namespace

std::optional<std::pair<std::uint32_t, std::uint32_t>> pe_data_directory(const BinaryImage& image, std::size_t index) {
    if (image.format != BinaryFormat::PE || image.bytes.size() < 0x40) return std::nullopt;
    const auto pe = static_cast<std::size_t>(rd32(image, 0x3c));
    if (pe > image.bytes.size() || image.bytes.size() - pe < 24) return std::nullopt;
    const auto optional = pe + 24;
    const auto optional_size = static_cast<std::size_t>(rd16(image, pe + 20));
    if (optional > image.bytes.size() || optional_size > image.bytes.size() - optional) return std::nullopt;
    const auto magic = rd16(image, optional);
    const bool plus = magic == 0x20b;
    if (!plus && magic != 0x10b) return std::nullopt;
    const std::size_t count_offset = plus ? 108 : 92, dir_offset = plus ? 112 : 96;
    if (optional_size < count_offset + 4 || optional_size < dir_offset) return std::nullopt;
    const auto count = rd32(image, optional + count_offset);
    if (index >= count || index >= (optional_size - dir_offset) / 8) return std::nullopt;
    const auto entry = optional + dir_offset + index * 8;
    return std::make_pair(rd32(image, entry), rd32(image, entry + 4));
}

std::vector<ImportEntry> parse_imports(const BinaryImage& image) {
    constexpr std::size_t max_records = 50000;
    std::vector<ImportEntry> result;
    if (image.format == BinaryFormat::ELF) {
        for (const auto& imported : image.imports) {
            if (result.size() >= max_records) break;
            if (imported.name.empty() || !imported.address) continue;
            result.push_back({"", imported.name, 0, false, imported.address});
        }
        return result;
    }
    const auto directory = pe_data_directory(image, 1);
    if (!directory || !directory->first || !directory->second) return result;
    const auto descriptor = image.rva_to_file_offset(directory->first);
    if (!descriptor) return result;
    const std::size_t pointer_size = image.is_64_bit ? 8u : 4u;
    const auto descriptor_count = (std::min<std::size_t>)(directory->second / 20, 4096);
    for (std::size_t d = 0; d < descriptor_count; ++d) {
        const auto current = *descriptor + d * 20;
        if (current + 20 > image.bytes.size()) break;
        const auto original_thunk = rd32(image, current), name_rva = rd32(image, current + 12), first_thunk = rd32(image, current + 16);
        if (!original_thunk && !name_rva && !first_thunk) break;
        const auto dll_offset = image.rva_to_file_offset(name_rva);
        const auto lookup_offset = image.rva_to_file_offset(original_thunk ? original_thunk : first_thunk);
        if (!lookup_offset || !first_thunk) continue;
        const std::string dll = dll_offset ? rd_string(image, *dll_offset) : "<invalid DLL>";
        for (std::size_t i = 0; i < 65536 && result.size() < max_records; ++i) {
            const auto entry = *lookup_offset + i * pointer_size;
            if (entry + pointer_size > image.bytes.size()) break;
            const auto thunk = image.is_64_bit ? rd64(image, entry) : static_cast<std::uint64_t>(rd32(image, entry));
            if (!thunk) break;
            ImportEntry item;
            item.library = dll;
            item.iat = image.image_base + first_thunk + i * pointer_size;
            if ((image.is_64_bit && (thunk & (1ull << 63))) || (!image.is_64_bit && (thunk & 0x80000000u))) {
                item.by_ordinal = true; item.ordinal = static_cast<std::uint32_t>(thunk & 0xffffu);
                item.name = "Ordinal " + std::to_string(item.ordinal);
            } else if (const auto hint = image.rva_to_file_offset(static_cast<std::uint32_t>(thunk)); hint && *hint + 2 < image.bytes.size()) {
                item.ordinal = rd16(image, *hint);
                item.name = rd_string(image, *hint + 2);
            }
            if (item.name.empty()) item.name = "Ordinal " + std::to_string(i);
            result.push_back(std::move(item));
        }
        if (result.size() >= max_records) break;
    }
    return result;
}

std::vector<ExportEntry> parse_exports(const BinaryImage& image) {
    constexpr std::size_t max_rows = 50000;
    std::vector<ExportEntry> result;
    const auto directory = pe_data_directory(image, 0);
    if (!directory || !directory->first || !directory->second) return result;
    const auto export_offset = image.rva_to_file_offset(directory->first);
    if (!export_offset || image.bytes.size() - *export_offset < 40) return result;
    const auto base = rd32(image, *export_offset + 16);
    const auto function_count = static_cast<std::size_t>(rd32(image, *export_offset + 20));
    const auto name_count = static_cast<std::size_t>(rd32(image, *export_offset + 24));
    const auto functions = image.rva_to_file_offset(rd32(image, *export_offset + 28));
    if (!function_count || !functions) return result;
    const auto rows = (std::min)(function_count, max_rows);
    if (rows > (image.bytes.size() - *functions) / 4) return result;
    std::unordered_map<std::uint16_t, std::string> names;
    if (name_count) {
        const auto names_off = image.rva_to_file_offset(rd32(image, *export_offset + 32));
        const auto ords_off = image.rva_to_file_offset(rd32(image, *export_offset + 36));
        if (names_off && ords_off) {
            const auto limit = (std::min)(name_count, max_rows);
            if (limit <= (image.bytes.size() - *names_off) / 4 && limit <= (image.bytes.size() - *ords_off) / 2) {
                for (std::size_t i = 0; i < limit; ++i) {
                    const auto name_offset = image.rva_to_file_offset(rd32(image, *names_off + i * 4));
                    const auto ordinal_index = rd16(image, *ords_off + i * 2);
                    if (ordinal_index >= function_count || !name_offset) continue;
                    auto name = rd_string(image, *name_offset);
                    if (!name.empty()) names.emplace(ordinal_index, std::move(name));
                }
            }
        }
    }
    const auto dir_end = static_cast<std::uint64_t>(directory->first) + directory->second;
    for (std::size_t i = 0; i < rows; ++i) {
        const auto rva = rd32(image, *functions + i * 4);
        if (!rva) continue;
        ExportEntry item;
        item.address = image.image_base + rva;
        item.ordinal = static_cast<std::uint32_t>(base + i);
        if (const auto it = names.find(static_cast<std::uint16_t>(i)); it != names.end()) item.name = it->second;
        if (rva >= directory->first && rva < dir_end)
            if (const auto fo = image.rva_to_file_offset(rva)) item.forwarder = rd_string(image, *fo);
        result.push_back(std::move(item));
    }
    // The PE entry point is listed by IDA as an export-like "start" entry; leave that to the views.
    return result;
}

std::vector<ResourceEntry> parse_resources(const BinaryImage& image) {
    std::vector<ResourceEntry> result;
    const auto directory = pe_data_directory(image, 2);
    if (!directory || !directory->first || !directory->second) return result;
    const auto root = image.rva_to_file_offset(directory->first);
    if (!root) return result;
    const std::size_t limit = (std::min<std::size_t>)(directory->second, image.bytes.size() - *root);
    const auto valid = [&](std::size_t relative, std::size_t length) {
        return relative <= limit && length <= limit - relative && *root + relative + length <= image.bytes.size();
    };
    const auto entry_name = [&](std::uint32_t raw, int depth) -> std::string {
        if ((raw & 0x80000000u) == 0) {
            if (depth == 0) if (const char* known = resource_type_name(raw)) return known;
            return "#" + std::to_string(raw);
        }
        const auto relative = static_cast<std::size_t>(raw & 0x7fffffffu);
        if (!valid(relative, 2)) return "<invalid name>";
        const auto length = rd16(image, *root + relative);
        if (!valid(relative + 2, static_cast<std::size_t>(length) * 2)) return "<invalid name>";
        std::string value;
        for (std::size_t i = 0; i < length; ++i) { const auto c = rd16(image, *root + relative + 2 + i * 2); value.push_back(c < 0x80 ? static_cast<char>(c) : '?'); }
        return value.empty() ? "<unnamed>" : value;
    };
    std::set<std::size_t> visited;
    const auto walk = [&](auto&& self, std::size_t dir_rel, const std::string& path, int depth) -> void {
        if (depth > 8 || result.size() >= 20000 || !valid(dir_rel, 16) || !visited.insert(dir_rel).second) return;
        const auto dir_off = *root + dir_rel;
        const auto count = (std::min<std::size_t>)(static_cast<std::size_t>(rd16(image, dir_off + 12)) + rd16(image, dir_off + 14), 4096);
        if (!valid(dir_rel + 16, count * 8)) return;
        for (std::size_t i = 0; i < count; ++i) {
            const auto entry = dir_off + 16 + i * 8;
            const auto label = entry_name(rd32(image, entry), depth);
            const auto child = rd32(image, entry + 4);
            const auto next = path.empty() ? label : path + " / " + label;
            if (child & 0x80000000u) { self(self, child & 0x7fffffffu, next, depth + 1); continue; }
            const auto data_rel = static_cast<std::size_t>(child & 0x7fffffffu);
            if (!valid(data_rel, 16)) continue;
            const auto data_off = *root + data_rel;
            ResourceEntry item;
            item.path = next; item.rva = rd32(image, data_off); item.size = rd32(image, data_off + 4);
            item.file_offset = image.rva_to_file_offset(item.rva);
            result.push_back(std::move(item));
        }
    };
    walk(walk, 0, "", 0);
    return result;
}

std::optional<PdbInfo> parse_pdb_info(const BinaryImage& image) {
    // IMAGE_DIRECTORY_ENTRY_DEBUG is data directory index 6.
    const auto directory = pe_data_directory(image, 6);
    if (!directory || !directory->first || !directory->second) return std::nullopt;
    const auto table = image.rva_to_file_offset(directory->first);
    if (!table) return std::nullopt;
    constexpr std::size_t entry_size = 28;    // sizeof(IMAGE_DEBUG_DIRECTORY)
    const auto count = directory->second / entry_size;
    for (std::size_t i = 0; i < count; ++i) {
        const auto entry = *table + i * entry_size;
        if (entry + entry_size > image.bytes.size()) break;
        constexpr std::uint32_t kImageDebugTypeCodeView = 2;
        if (rd32(image, entry + 12) != kImageDebugTypeCodeView) continue;
        const auto data_size = rd32(image, entry + 16);
        const auto pointer_to_raw_data = rd32(image, entry + 24);   // file offset, not RVA
        if (!data_size || data_size < 24 || pointer_to_raw_data + 24 > image.bytes.size()) continue;
        if (rd32(image, pointer_to_raw_data) != 0x53445352u) continue;   // "RSDS"
        PdbInfo info;
        const std::uint32_t d1 = rd32(image, pointer_to_raw_data + 4);
        const std::uint16_t d2 = rd16(image, pointer_to_raw_data + 8), d3 = rd16(image, pointer_to_raw_data + 10);
        char guid[37]{};
        std::snprintf(guid, sizeof(guid), "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", d1, d2, d3,
                      image.bytes[pointer_to_raw_data + 12], image.bytes[pointer_to_raw_data + 13],
                      image.bytes[pointer_to_raw_data + 14], image.bytes[pointer_to_raw_data + 15],
                      image.bytes[pointer_to_raw_data + 16], image.bytes[pointer_to_raw_data + 17],
                      image.bytes[pointer_to_raw_data + 18], image.bytes[pointer_to_raw_data + 19]);
        info.guid = guid;
        info.age = rd32(image, pointer_to_raw_data + 20);
        info.path = rd_string(image, pointer_to_raw_data + 24, data_size > 24 ? data_size - 24 : 260);
        return info;
    }
    return std::nullopt;
}

} // namespace gandon
