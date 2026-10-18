#include "gandon/dotnet.hpp"

#include <array>
#include <cstring>

namespace gandon {
namespace {

std::uint16_t rd16(const std::vector<std::uint8_t>& b, std::size_t o) {
    return o + 2 <= b.size() ? static_cast<std::uint16_t>(b[o] | (b[o + 1] << 8)) : 0;
}
std::uint32_t rd32(const std::vector<std::uint8_t>& b, std::size_t o) {
    return o + 4 <= b.size() ? static_cast<std::uint32_t>(b[o]) | (static_cast<std::uint32_t>(b[o + 1]) << 8) |
                                   (static_cast<std::uint32_t>(b[o + 2]) << 16) | (static_cast<std::uint32_t>(b[o + 3]) << 24)
                             : 0;
}

// The 45 metadata table names, indexed by their table number (bit in Valid).
const char* table_name(int i) {
    static const std::array<const char*, 64> names = [] {
        std::array<const char*, 64> t{};
        t.fill("");
        t[0x00] = "Module"; t[0x01] = "TypeRef"; t[0x02] = "TypeDef"; t[0x04] = "Field";
        t[0x06] = "MethodDef"; t[0x08] = "Param"; t[0x09] = "InterfaceImpl"; t[0x0A] = "MemberRef";
        t[0x0B] = "Constant"; t[0x0C] = "CustomAttribute"; t[0x0D] = "FieldMarshal"; t[0x0E] = "DeclSecurity";
        t[0x0F] = "ClassLayout"; t[0x10] = "FieldLayout"; t[0x11] = "StandAloneSig"; t[0x12] = "EventMap";
        t[0x14] = "Event"; t[0x15] = "PropertyMap"; t[0x17] = "Property"; t[0x18] = "MethodSemantics";
        t[0x19] = "MethodImpl"; t[0x1A] = "ModuleRef"; t[0x1B] = "TypeSpec"; t[0x1C] = "ImplMap";
        t[0x1D] = "FieldRVA"; t[0x20] = "Assembly"; t[0x23] = "AssemblyRef"; t[0x26] = "File";
        t[0x27] = "ExportedType"; t[0x28] = "ManifestResource"; t[0x29] = "NestedClass";
        t[0x2A] = "GenericParam"; t[0x2B] = "MethodSpec"; t[0x2C] = "GenericParamConstraint";
        return t;
    }();
    return i >= 0 && i < 64 ? names[static_cast<std::size_t>(i)] : "";
}

// Offset of a PE data directory entry, or 0 if the PE is malformed.
std::size_t data_directory(const std::vector<std::uint8_t>& b, int index, bool& is64) {
    if (b.size() < 0x40 || b[0] != 'M' || b[1] != 'Z') return 0;
    const std::uint32_t pe = rd32(b, 0x3c);
    if (pe + 24 > b.size() || b[pe] != 'P' || b[pe + 1] != 'E') return 0;
    const std::uint16_t magic = rd16(b, pe + 24);
    is64 = magic == 0x20b;
    const std::size_t base = pe + 24 + (is64 ? 112 : 96);
    return base + static_cast<std::size_t>(index) * 8;
}

} // namespace

DotNetInfo parse_dotnet(const BinaryImage& image) {
    DotNetInfo info;
    const auto& b = image.bytes;
    bool is64 = false;
    const std::size_t dir14 = data_directory(b, 14, is64);  // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
    if (!dir14) { info.error = "not a PE"; return info; }
    const std::uint32_t cor_rva = rd32(b, dir14);
    const std::uint32_t cor_size = rd32(b, dir14 + 4);
    if (!cor_rva || !cor_size) { info.error = "no CLR directory (native binary)"; return info; }
    info.is_dotnet = true;

    const auto cor_off = image.rva_to_file_offset(cor_rva);
    if (!cor_off) { info.error = ".NET: CLR header RVA unmapped"; return info; }
    // IMAGE_COR20_HEADER: cb(4) major(2) minor(2) MetaData(rva4,size4) Flags(4) EntryPointToken(4) ...
    info.flags = rd32(b, *cor_off + 16);
    info.il_only = (info.flags & 1) != 0;
    info.entry_point_token = rd32(b, *cor_off + 20);
    const std::uint32_t md_rva = rd32(b, *cor_off + 8);
    const auto md = image.rva_to_file_offset(md_rva);
    if (!md) { info.error = ".NET: metadata RVA unmapped"; return info; }

    // Metadata root: "BSJB" signature, version length + string, then streams.
    const std::size_t root = *md;
    if (root + 20 > b.size() || rd32(b, root) != 0x424A5342u) { info.error = ".NET: bad metadata signature"; return info; }
    const std::uint32_t ver_len = rd32(b, root + 12);
    if (root + 16 + ver_len + 4 > b.size()) { info.error = ".NET: truncated metadata"; return info; }
    info.runtime_version.assign(reinterpret_cast<const char*>(b.data() + root + 16),
                                strnlen(reinterpret_cast<const char*>(b.data() + root + 16), ver_len));
    std::size_t p = root + 16 + ((ver_len + 3) & ~3u);
    p += 2;                                   // flags
    const std::uint16_t streams = rd16(b, p); p += 2;

    std::size_t strings_off = 0, strings_size = 0, us_off = 0, us_size = 0, tables_off = 0, tables_size = 0;
    for (std::uint16_t i = 0; i < streams && p + 8 <= b.size(); ++i) {
        const std::uint32_t s_off = rd32(b, p);
        const std::uint32_t s_size = rd32(b, p + 4);
        p += 8;
        std::string name(reinterpret_cast<const char*>(b.data() + p), strnlen(reinterpret_cast<const char*>(b.data() + p), 32));
        p += (name.size() + 1 + 3) & ~std::size_t(3);  // name is NUL-terminated, padded to 4
        if (name == "#Strings") { strings_off = root + s_off; strings_size = s_size; }
        else if (name == "#US") { us_off = root + s_off; us_size = s_size; }
        else if (name == "#~" || name == "#-") { tables_off = root + s_off; tables_size = s_size; }
    }

    // #Strings: NUL-separated UTF-8 names.
    if (strings_off && strings_off + strings_size <= b.size()) {
        std::size_t s = strings_off + 1;  // first entry is the empty string
        while (s < strings_off + strings_size) {
            const char* z = reinterpret_cast<const char*>(b.data() + s);
            const std::size_t len = strnlen(z, strings_off + strings_size - s);
            if (len) info.names.emplace_back(z, len);
            s += len + 1;
            if (!len) break;
        }
    }

    // #US: user-string heap. Each blob is [compressed length][UTF-16LE bytes][flag].
    if (us_off && us_off + us_size <= b.size()) {
        std::size_t s = us_off + 1;  // first blob is empty
        while (s < us_off + us_size) {
            std::uint32_t len = 0; std::size_t hdr = 0;
            const std::uint8_t c = b[s];
            if ((c & 0x80) == 0) { len = c; hdr = 1; }
            else if ((c & 0xC0) == 0x80) { len = ((c & 0x3F) << 8) | b[s + 1]; hdr = 2; }
            else { len = ((c & 0x1F) << 24) | (b[s + 1] << 16) | (b[s + 2] << 8) | b[s + 3]; hdr = 4; }
            if (len == 0 || s + hdr + len > us_off + us_size) break;
            // len includes a trailing flag byte; the text is (len-1) bytes of UTF-16LE.
            std::string text;
            for (std::size_t k = 0; k + 1 < len; k += 2) {
                const std::uint16_t ch = static_cast<std::uint16_t>(b[s + hdr + k] | (b[s + hdr + k + 1] << 8));
                if (ch < 0x80) text.push_back(static_cast<char>(ch));
                else text.push_back('?');   // keep it ASCII-safe for the listing
            }
            if (!text.empty()) info.user_strings.push_back(text);
            s += hdr + len;
        }
    }

    // #~ tables header: row counts for each present table (Valid bitmask).
    if (tables_off && tables_off + 24 <= b.size()) {
        const std::uint64_t valid = static_cast<std::uint64_t>(rd32(b, tables_off + 8)) |
                                    (static_cast<std::uint64_t>(rd32(b, tables_off + 12)) << 32);
        std::size_t rows_cursor = tables_off + 24;
        for (int i = 0; i < 64; ++i) {
            if (!(valid & (1ull << i))) continue;
            const std::uint32_t count = rd32(b, rows_cursor);
            rows_cursor += 4;
            const char* nm = table_name(i);
            if (nm[0]) info.table_rows[nm] = count;
        }
    }
    return info;
}

} // namespace gandon
