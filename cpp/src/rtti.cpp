#include "gandon/rtti.hpp"

#include <algorithm>
#include <string_view>
#include <unordered_map>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <dbghelp.h>
#endif

namespace gandon {
namespace {

// Plain fallback for the common non-template case ("Name@Scope@Sub@@"): reverse
// the @-separated, inner-first tokens into "Sub::Scope::Name". Used when
// dbghelp is unavailable (non-Windows builds) or fails to undecorate a name.
std::string demangle_plain_scope_chain(const std::string& decorated) {
    std::string s = decorated;
    if (s.rfind(".?A", 0) == 0) s = s.substr(s.size() > 4 ? 4 : 3);  // drop ".?AV" / ".?AU" / ".?A"
    const auto end = s.rfind("@@");
    if (end != std::string::npos) s = s.substr(0, end);
    std::vector<std::string> parts;
    std::string cur;
    for (char c : s) { if (c == '@') { parts.push_back(cur); cur.clear(); } else cur.push_back(c); }
    parts.push_back(cur);
    std::string out;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        if (it->empty()) continue;
        if (!out.empty()) out += "::";
        out += *it;
    }
    return out.empty() ? decorated : out;
}

std::uint32_t rd32(const BinaryImage& image, std::size_t off) {
    const auto& b = image.bytes;
    return off + 4 <= b.size() ? static_cast<std::uint32_t>(b[off]) | (static_cast<std::uint32_t>(b[off + 1]) << 8) |
                                     (static_cast<std::uint32_t>(b[off + 2]) << 16) | (static_cast<std::uint32_t>(b[off + 3]) << 24)
                               : 0;
}
std::uint64_t rd64(const BinaryImage& image, std::size_t off) {
    return static_cast<std::uint64_t>(rd32(image, off)) | (static_cast<std::uint64_t>(rd32(image, off + 4)) << 32);
}

bool is_exec_va(const BinaryImage& image, std::uint64_t va) {
    const std::uint64_t rva = va - image.image_base;
    for (const auto& s : image.sections)
        if (rva >= s.rva && rva < s.rva + (s.virtual_size ? s.virtual_size : s.raw_size))
            return (s.characteristics & 0x20000000u) != 0;  // IMAGE_SCN_MEM_EXECUTE
    return false;
}

// Read the mangled name out of a TypeDescriptor at image-relative `rva`.
std::string type_descriptor_name(const BinaryImage& image, std::uint32_t rva, bool is64) {
    const auto off = image.rva_to_file_offset(rva + (is64 ? 16 : 12));  // name[] follows vftable + spare
    if (!off) return {};
    std::string name;
    for (std::size_t i = *off; i < image.bytes.size() && image.bytes[i] && name.size() < 2048; ++i)
        name.push_back(static_cast<char>(image.bytes[i]));
    return name;
}

} // namespace

std::string demangle_msvc_rtti_name(const std::string& decorated) {
    // Type descriptor names look like ".?AVWidget@ns@@" (class), ".?AUStruct@@"
    // (struct), or, for a template instantiation, ".?AV?$vector@HV?$allocator@H@std@@@std@@".
#ifdef _WIN32
    // The descriptor's name is ".?A" followed by exactly the type-encoding
    // fragment MSVC would emit for a global variable of that type (e.g.
    // "VWidget@ns@@" for class ns::Widget). Wrapping that fragment into a
    // throwaway decorated data-symbol name and asking dbghelp to undecorate it
    // reuses the real MSVC demangler -- which already handles templates,
    // back-references and nested namespaces -- instead of a hand-rolled parser
    // that only covers the plain, non-template case.
    if (decorated.rfind(".?A", 0) == 0 && decorated.size() > 3) {
        const std::string fake = "?x@@3" + decorated.substr(3) + "A";
        char buffer[4096];
        if (UnDecorateSymbolName(fake.c_str(), buffer, sizeof(buffer), UNDNAME_COMPLETE) != 0) {
            std::string out = buffer;
            // Strip the leading type keyword and the trailing " x" throwaway
            // variable name that the fake declaration introduced.
            static constexpr std::string_view kKeywords[] = {"class ", "struct ", "union ", "enum "};
            for (const auto kw : kKeywords) if (out.rfind(kw, 0) == 0) { out = out.substr(kw.size()); break; }
            if (out.size() > 2 && out.compare(out.size() - 2, 2, " x") == 0) out.resize(out.size() - 2);
            if (!out.empty()) return out;
        }
    }
#endif
    return demangle_plain_scope_chain(decorated);
}

std::vector<RttiClass> recover_rtti(const BinaryImage& image) {
    std::vector<RttiClass> classes;
    if (image.format != BinaryFormat::PE) return classes;
    const bool is64 = image.is_64_bit;
    const std::size_t ptr = is64 ? 8 : 4;

    // ---- 1. find every RTTICompleteObjectLocator (COL) in a data section.
    // x64 COL: sig(4)=1, offset(4), cdOffset(4), typeDesc(4 RVA), classHier(4 RVA), self(4 RVA).
    // The self-RVA back-reference makes the match reliable.
    struct Col { std::string name; std::uint32_t chd_rva; };
    std::unordered_map<std::uint64_t, Col> col_by_va;   // VA of the COL -> info
    for (const auto& s : image.sections) {
        if (s.characteristics & 0x20000000u) continue;   // skip executable sections
        const std::uint64_t base_rva = s.rva;
        const std::uint32_t size = s.virtual_size ? s.virtual_size : s.raw_size;
        for (std::uint32_t off = 0; off + 24 <= size; off += 4) {
            const std::uint32_t rva = static_cast<std::uint32_t>(base_rva) + off;
            const auto fo = image.rva_to_file_offset(rva);
            if (!fo) continue;
            if (rd32(image, *fo) != 1) continue;                         // signature (x64)
            const std::uint32_t td_rva = rd32(image, *fo + 12);
            const std::uint32_t chd_rva = rd32(image, *fo + 16);
            const std::uint32_t self_rva = rd32(image, *fo + 20);
            if (self_rva != rva) continue;                               // COL self back-reference
            if (!image.rva_to_file_offset(td_rva) || !image.rva_to_file_offset(chd_rva)) continue;
            const std::string name = type_descriptor_name(image, td_rva, is64);
            if (name.rfind(".?A", 0) != 0) continue;                     // not a type descriptor
            col_by_va[image.image_base + rva] = {demangle_msvc_rtti_name(name), chd_rva};
        }
    }
    if (col_by_va.empty()) return classes;

    // ---- 2. a vtable is a pointer to a COL; the methods start one slot later.
    for (const auto& s : image.sections) {
        if (s.characteristics & 0x20000000u) continue;
        const std::uint32_t size = s.virtual_size ? s.virtual_size : s.raw_size;
        for (std::uint32_t off = 0; off + ptr <= size; off += static_cast<std::uint32_t>(ptr)) {
            const std::uint32_t rva = static_cast<std::uint32_t>(s.rva) + off;
            const auto fo = image.rva_to_file_offset(rva);
            if (!fo) continue;
            const std::uint64_t value = is64 ? rd64(image, *fo) : rd32(image, *fo);
            const auto col = col_by_va.find(value);
            if (col == col_by_va.end()) continue;
            const std::uint64_t vtable_va = image.image_base + rva + ptr;

            RttiClass rc;
            rc.name = col->second.name;
            rc.locator_va = value;
            rc.vtable_va = vtable_va;
            // Count consecutive code pointers.
            std::uint64_t mrva = rva + ptr;
            while (true) {
                const auto mfo = image.rva_to_file_offset(mrva);
                if (!mfo) break;
                const std::uint64_t m = is64 ? rd64(image, *mfo) : rd32(image, *mfo);
                if (!is_exec_va(image, m)) break;
                rc.methods.push_back(m);
                mrva += ptr;
                if (rc.methods.size() >= 4096) break;
            }
            rc.method_count = rc.methods.size();
            if (rc.method_count == 0) continue;   // a COL pointer with no vtable behind it

            // ---- 3. base classes from the ClassHierarchyDescriptor.
            const auto chd = image.rva_to_file_offset(col->second.chd_rva);
            if (chd) {
                const std::uint32_t num_bases = rd32(image, *chd + 8);
                const std::uint32_t array_rva = rd32(image, *chd + 12);
                const auto arr = image.rva_to_file_offset(array_rva);
                if (arr && num_bases <= 256) {
                    for (std::uint32_t i = 1; i < num_bases; ++i) {   // index 0 is the class itself
                        const std::uint32_t bcd_rva = rd32(image, *arr + i * 4);
                        const auto bcd = image.rva_to_file_offset(bcd_rva);
                        if (!bcd) continue;
                        const std::uint32_t btd_rva = rd32(image, *bcd);   // BaseClassDescriptor.pTypeDescriptor
                        const std::string bname = type_descriptor_name(image, btd_rva, is64);
                        if (bname.rfind(".?A", 0) == 0) rc.base_classes.push_back(demangle_msvc_rtti_name(bname));
                    }
                }
            }
            classes.push_back(std::move(rc));
        }
    }
    std::sort(classes.begin(), classes.end(), [](const RttiClass& a, const RttiClass& b) { return a.vtable_va < b.vtable_va; });
    return classes;
}

} // namespace gandon
