#include "gandon/pe_dump.hpp"

#include <algorithm>
#include <cstring>
#include <map>

namespace gandon::pe_dump {
namespace {

std::uint16_t rd16(const std::vector<std::uint8_t>& b, std::size_t o) {
    return o + 2 <= b.size() ? static_cast<std::uint16_t>(b[o] | (b[o + 1] << 8)) : 0;
}
std::uint32_t rd32(const std::vector<std::uint8_t>& b, std::size_t o) {
    return o + 4 <= b.size() ? static_cast<std::uint32_t>(b[o]) | (static_cast<std::uint32_t>(b[o + 1]) << 8) |
                                   (static_cast<std::uint32_t>(b[o + 2]) << 16) | (static_cast<std::uint32_t>(b[o + 3]) << 24)
                             : 0;
}
std::uint64_t rd64(const std::vector<std::uint8_t>& b, std::size_t o) {
    return static_cast<std::uint64_t>(rd32(b, o)) | (static_cast<std::uint64_t>(rd32(b, o + 4)) << 32);
}
void wr16(std::vector<std::uint8_t>& b, std::size_t o, std::uint16_t v) {
    if (o + 2 <= b.size()) { b[o] = v & 0xff; b[o + 1] = (v >> 8) & 0xff; }
}
void wr32(std::vector<std::uint8_t>& b, std::size_t o, std::uint32_t v) {
    if (o + 4 <= b.size()) { b[o] = v & 0xff; b[o + 1] = (v >> 8) & 0xff; b[o + 2] = (v >> 16) & 0xff; b[o + 3] = (v >> 24) & 0xff; }
}
std::uint32_t align_up(std::uint32_t v, std::uint32_t a) { return a ? (v + a - 1) / a * a : v; }

// Common PE header anchors parsed once.
struct PeView {
    bool ok{false};
    std::string error;
    std::size_t pe{0};              // offset of "PE\0\0"
    std::size_t opt{0};             // offset of the optional header
    std::uint16_t magic{0};         // 0x10b PE32, 0x20b PE32+
    bool is64{false};
    std::uint16_t sections{0};
    std::uint16_t opt_size{0};
    std::size_t section_table{0};   // offset of the first section header
    std::uint32_t section_align{0};
    std::uint32_t file_align{0};
    std::uint32_t size_of_image{0};
    std::uint32_t size_of_headers{0};
};

PeView parse(const std::vector<std::uint8_t>& b) {
    PeView v;
    if (b.size() < 0x40 || b[0] != 'M' || b[1] != 'Z') { v.error = "not a PE (no MZ header)"; return v; }
    v.pe = rd32(b, 0x3c);
    if (v.pe + 24 > b.size() || b[v.pe] != 'P' || b[v.pe + 1] != 'E' || b[v.pe + 2] || b[v.pe + 3]) {
        v.error = "not a PE (no PE signature)"; return v;
    }
    v.sections = rd16(b, v.pe + 6);
    v.opt_size = rd16(b, v.pe + 20);
    v.opt = v.pe + 24;
    v.magic = rd16(b, v.opt);
    v.is64 = v.magic == 0x20b;
    if (v.magic != 0x10b && v.magic != 0x20b) { v.error = "unknown optional header magic"; return v; }
    v.section_align = rd32(b, v.opt + 32);
    v.file_align = rd32(b, v.opt + 36);
    v.size_of_image = rd32(b, v.opt + 56);
    v.size_of_headers = rd32(b, v.opt + 60);
    v.section_table = v.opt + v.opt_size;
    if (v.section_table + static_cast<std::size_t>(v.sections) * 40 > b.size()) { v.error = "section table out of range"; return v; }
    v.ok = true;
    return v;
}

// Offset of the data directory entry `index` (0=export,1=import,12=IAT,...).
std::size_t data_directory(const PeView& v, int index) {
    // The directory array starts after the fixed optional header body:
    // PE32 -> opt+96, PE32+ -> opt+112.
    const std::size_t base = v.opt + (v.is64 ? 112 : 96);
    return base + static_cast<std::size_t>(index) * 8;
}

} // namespace

DumpResult build_pe_from_memory(const std::vector<std::uint8_t>& memory_image,
                                std::optional<std::uint64_t> override_entry_rva) {
    DumpResult out;
    PeView v = parse(memory_image);
    if (!v.ok) { out.error = v.error; return out; }

    out.bytes = memory_image;  // offsets will equal RVAs after the header fix-up
    auto& b = out.bytes;

    // Make the on-disk layout mirror memory: FileAlignment := SectionAlignment,
    // and each section is raw-mapped at its RVA.
    const std::uint32_t sa = v.section_align ? v.section_align : 0x1000;
    wr32(b, v.opt + 36, sa);  // FileAlignment
    for (std::uint16_t i = 0; i < v.sections; ++i) {
        const std::size_t sh = v.section_table + static_cast<std::size_t>(i) * 40;
        const std::uint32_t vsize = rd32(b, sh + 8);
        const std::uint32_t vaddr = rd32(b, sh + 12);
        const std::uint32_t raw = align_up(vsize ? vsize : rd32(b, sh + 16), sa);
        wr32(b, sh + 16, raw);    // SizeOfRawData
        wr32(b, sh + 20, vaddr);  // PointerToRawData := VirtualAddress
    }
    if (override_entry_rva) wr32(b, v.opt + 16, static_cast<std::uint32_t>(*override_entry_rva));

    // A freshly unpacked dump has nothing bound; clear the bound-import directory
    // so the loader does not trip over stale data.
    wr32(b, data_directory(v, 11), 0);
    wr32(b, data_directory(v, 11) + 4, 0);
    out.ok = true;
    return out;
}

ImportRebuildResult rebuild_imports(const std::vector<std::uint8_t>& pe, std::uint64_t image_base,
                                    const std::function<std::string(std::uint64_t)>& resolve) {
    ImportRebuildResult out;
    PeView v = parse(pe);
    if (!v.ok) { out.error = v.error; return out; }
    if (!resolve) { out.error = "no symbol resolver supplied"; return out; }
    (void)image_base;  // the IAT holds absolute pointers; the resolver maps them directly
    const std::size_t ptr = v.is64 ? 8 : 4;

    // Room for one more section header must exist between the end of the current
    // section table and the end of the headers.
    const std::size_t new_sh = v.section_table + static_cast<std::size_t>(v.sections) * 40;
    if (new_sh + 40 > v.size_of_headers || new_sh + 40 > pe.size()) {
        out.error = "no room in the PE header for a rebuilt import section"; return out;
    }

    // ---- 1. find IAT runs: consecutive resolvable pointers, split by DLL/gaps.
    struct Slot { std::uint32_t rva; std::string dll, symbol; };
    std::vector<Slot> slots;
    for (std::uint16_t i = 0; i < v.sections; ++i) {
        const std::size_t sh = v.section_table + static_cast<std::size_t>(i) * 40;
        const std::uint32_t vaddr = rd32(pe, sh + 12);
        const std::uint32_t vsize = align_up(rd32(pe, sh + 8), v.section_align ? v.section_align : 0x1000);
        for (std::uint32_t off = 0; off + ptr <= vsize && vaddr + off + ptr <= pe.size(); off += static_cast<std::uint32_t>(ptr)) {
            const std::uint64_t value = v.is64 ? rd64(pe, vaddr + off) : rd32(pe, vaddr + off);
            if (!value) continue;
            const std::string sym = resolve(value);
            if (sym.empty()) continue;
            const auto bang = sym.find('!');
            if (bang == std::string::npos) continue;
            slots.push_back({vaddr + off, sym.substr(0, bang), sym.substr(bang + 1)});
        }
    }
    if (slots.empty()) { out.error = "no resolvable IAT pointers found"; return out; }

    // ---- 2. group by DLL, preserving first-seen order.
    std::vector<std::string> dll_order;
    std::map<std::string, std::vector<Slot>> by_dll;
    for (const auto& s : slots) {
        if (!by_dll.count(s.dll)) dll_order.push_back(s.dll);
        by_dll[s.dll].push_back(s);
    }
    out.resolved = slots.size();
    out.dll_count = dll_order.size();

    // ---- 3. lay out a fresh import blob in a new section:
    //   [descriptors (N+1)] [per-DLL ILT arrays] [hint/name entries] [dll names]
    const std::size_t descr_size = (dll_order.size() + 1) * 20;
    std::size_t ilt_size = 0;
    for (const auto& d : dll_order) ilt_size += (by_dll[d].size() + 1) * ptr;
    std::size_t names_size = 0;
    for (const auto& s : slots) names_size += 2 + s.symbol.size() + 1 + ((s.symbol.size() + 1) & 1);  // hint + name + pad
    std::size_t dllname_size = 0;
    for (const auto& d : dll_order) dllname_size += d.size() + 1 + ((d.size() + 1) & 1);

    const std::uint32_t sa = v.section_align ? v.section_align : 0x1000;
    const std::uint32_t sec_rva = align_up(v.size_of_image, sa);
    const std::size_t blob_size = descr_size + ilt_size + names_size + dllname_size;
    const std::uint32_t sec_raw = align_up(static_cast<std::uint32_t>(blob_size), sa);

    std::vector<std::uint8_t> blob(sec_raw, 0);
    const auto w32 = [&](std::size_t o, std::uint32_t val) { blob[o] = val & 0xff; blob[o + 1] = (val >> 8) & 0xff; blob[o + 2] = (val >> 16) & 0xff; blob[o + 3] = (val >> 24) & 0xff; };
    const auto wptr = [&](std::size_t o, std::uint64_t val) { for (std::size_t k = 0; k < ptr; ++k) blob[o + k] = static_cast<std::uint8_t>(val >> (8 * k)); };

    std::size_t ilt_cursor = descr_size;
    std::size_t name_cursor = descr_size + ilt_size;
    std::size_t dllname_cursor = descr_size + ilt_size + names_size;

    for (std::size_t di = 0; di < dll_order.size(); ++di) {
        const auto& dll = dll_order[di];
        const auto& entries = by_dll[dll];
        const std::size_t descr = di * 20;
        const std::uint32_t ilt_rva = sec_rva + static_cast<std::uint32_t>(ilt_cursor);
        const std::uint32_t dllname_rva = sec_rva + static_cast<std::uint32_t>(dllname_cursor);
        // FirstThunk points at the real IAT run (first slot's RVA): existing code
        // that reads the IAT keeps working after the loader binds it.
        const std::uint32_t first_thunk = entries.front().rva;
        w32(descr + 0, ilt_rva);       // OriginalFirstThunk (ILT)
        w32(descr + 12, dllname_rva);  // Name
        w32(descr + 16, first_thunk);  // FirstThunk (IAT)

        for (std::size_t ei = 0; ei < entries.size(); ++ei) {
            const std::uint32_t hint_rva = sec_rva + static_cast<std::uint32_t>(name_cursor);
            wptr(ilt_cursor, hint_rva);
            ilt_cursor += ptr;
            // hint (0) + name + NUL, padded to even.
            blob[name_cursor] = 0; blob[name_cursor + 1] = 0;
            std::memcpy(blob.data() + name_cursor + 2, entries[ei].symbol.data(), entries[ei].symbol.size());
            name_cursor += 2 + entries[ei].symbol.size() + 1 + ((entries[ei].symbol.size() + 1) & 1);
        }
        wptr(ilt_cursor, 0);  // ILT terminator
        ilt_cursor += ptr;

        std::memcpy(blob.data() + dllname_cursor, dll.data(), dll.size());
        dllname_cursor += dll.size() + 1 + ((dll.size() + 1) & 1);
    }
    // Trailing null descriptor is already zero-filled.

    // ---- 4. assemble the output: original image + new section data.
    out.bytes = pe;
    const std::uint32_t file_off = static_cast<std::uint32_t>(out.bytes.size());
    out.bytes.insert(out.bytes.end(), blob.begin(), blob.end());

    // New section header ".rdata2".
    const char name[8] = {'.', 'r', 'd', 'a', 't', 'a', '2', 0};
    std::memcpy(out.bytes.data() + new_sh, name, 8);
    wr32(out.bytes, new_sh + 8, static_cast<std::uint32_t>(blob_size));  // VirtualSize
    wr32(out.bytes, new_sh + 12, sec_rva);                               // VirtualAddress
    wr32(out.bytes, new_sh + 16, sec_raw);                               // SizeOfRawData
    wr32(out.bytes, new_sh + 20, file_off);                              // PointerToRawData
    wr32(out.bytes, new_sh + 36, 0x40000040);                            // INITIALIZED_DATA | READ

    // ---- 5. header fix-ups: section count, image size, import directory.
    wr16(out.bytes, v.pe + 6, static_cast<std::uint16_t>(v.sections + 1));
    wr32(out.bytes, v.opt + 56, sec_rva + sec_raw);            // SizeOfImage
    wr32(out.bytes, data_directory(v, 1), sec_rva);            // IMPORT rva
    wr32(out.bytes, data_directory(v, 1) + 4, static_cast<std::uint32_t>(descr_size));  // IMPORT size
    out.ok = true;
    return out;
}

} // namespace gandon::pe_dump
