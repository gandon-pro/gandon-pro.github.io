#include "gandon/pe_dump.hpp"
#include "gandon/vm_analysis.hpp"
#include "gandon/dotnet.hpp"
#include "gandon/rtti.hpp"
#include "gandon/driver.hpp"
#include "gandon/core.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

void put16(std::vector<std::uint8_t>& b, std::size_t o, std::uint16_t v) { b[o] = v & 0xff; b[o + 1] = (v >> 8) & 0xff; }
void put32(std::vector<std::uint8_t>& b, std::size_t o, std::uint32_t v) { for (int i = 0; i < 4; ++i) b[o + i] = (v >> (8 * i)) & 0xff; }
void put64(std::vector<std::uint8_t>& b, std::size_t o, std::uint64_t v) { for (int i = 0; i < 8; ++i) b[o + i] = (v >> (8 * i)) & 0xff; }
std::uint32_t get32(const std::vector<std::uint8_t>& b, std::size_t o) { return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (static_cast<std::uint32_t>(b[o + 3]) << 24); }
std::uint16_t get16(const std::vector<std::uint8_t>& b, std::size_t o) { return static_cast<std::uint16_t>(b[o] | (b[o + 1] << 8)); }

// A minimal memory-aligned PE32+ with one ".text" section at RVA 0x1000 and
// room in the headers for one more section. `file_align` lets a test observe
// build_pe_from_memory rewriting it.
std::vector<std::uint8_t> make_mem_pe(std::uint32_t file_align = 0x200) {
    std::vector<std::uint8_t> b(0x2000, 0);
    b[0] = 'M'; b[1] = 'Z';
    put32(b, 0x3c, 0x80);                 // e_lfanew
    const std::size_t pe = 0x80;
    b[pe] = 'P'; b[pe + 1] = 'E';
    put16(b, pe + 4, 0x8664);             // Machine
    put16(b, pe + 6, 1);                  // NumberOfSections
    put16(b, pe + 20, 0xF0);              // SizeOfOptionalHeader
    put16(b, pe + 22, 0x2022);            // Characteristics (executable image, dll)
    const std::size_t opt = pe + 24;
    put16(b, opt + 0, 0x20b);             // PE32+
    put32(b, opt + 16, 0x1000);           // AddressOfEntryPoint
    put64(b, opt + 24, 0x140000000ull);   // ImageBase
    put32(b, opt + 32, 0x1000);           // SectionAlignment
    put32(b, opt + 36, file_align);       // FileAlignment
    put32(b, opt + 56, 0x2000);           // SizeOfImage
    put32(b, opt + 60, 0x400);            // SizeOfHeaders
    put16(b, opt + 68, 2);                // Subsystem (GUI)
    put32(b, opt + 108, 16);              // NumberOfRvaAndSizes
    const std::size_t sect = opt + 0xF0;  // 0x188
    std::memcpy(b.data() + sect, ".text\0\0\0", 8);
    put32(b, sect + 8, 0x200);            // VirtualSize
    put32(b, sect + 12, 0x1000);          // VirtualAddress
    put32(b, sect + 16, 0x200);           // SizeOfRawData
    put32(b, sect + 20, 0x1000);          // PointerToRawData (memory-aligned)
    put32(b, sect + 36, 0x60000020);      // code | exec | read
    return b;
}

void test_build_pe_from_memory_remaps_sections() {
    auto mem = make_mem_pe(0x200);
    const auto r = gandon::pe_dump::build_pe_from_memory(mem);
    assert(r.ok);
    const std::size_t opt = 0x80 + 24, sect = opt + 0xF0;
    assert(get32(r.bytes, opt + 36) == 0x1000);          // FileAlignment := SectionAlignment
    assert(get32(r.bytes, sect + 20) == 0x1000);         // PointerToRawData := VirtualAddress
    assert(get32(r.bytes, sect + 16) == 0x1000);         // SizeOfRawData aligned up to 0x1000
    std::puts("build_pe_from_memory remaps sections: OK");
}

void test_rebuild_imports_from_iat() {
    auto mem = make_mem_pe(0x1000);
    // Two absolute IAT pointers at RVA 0x1000 / 0x1008, then a null terminator.
    put64(mem, 0x1000, 0x7FF000001000ull);
    put64(mem, 0x1008, 0x7FF000002000ull);
    const auto resolve = [](std::uint64_t p) -> std::string {
        if (p == 0x7FF000001000ull) return "KERNEL32.dll!GetProcAddress";
        if (p == 0x7FF000002000ull) return "KERNEL32.dll!LoadLibraryA";
        return {};
    };
    const auto r = gandon::pe_dump::rebuild_imports(mem, 0x140000000ull, resolve);
    assert(r.ok);
    assert(r.resolved == 2);
    assert(r.dll_count == 1);
    assert(get16(r.bytes, 0x80 + 6) == 2);               // NumberOfSections incremented
    assert(get32(r.bytes, 0x80 + 24 + 112 + 8) != 0);    // IMPORT data directory RVA set
    const std::string hay(r.bytes.begin(), r.bytes.end());
    assert(hay.find("KERNEL32.dll") != std::string::npos);
    assert(hay.find("GetProcAddress") != std::string::npos);
    assert(hay.find("LoadLibraryA") != std::string::npos);
    std::puts("rebuild_imports from IAT: OK");
}

void test_vm_dispatch_detects_handler_table() {
    // Build an image whose .text has: lea rcx,[rip+table]; jmp [rcx+rax*8]; and a
    // handler table of 6 in-image pointers in a data area.
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x140000000ull;
    image.bytes.assign(0x3000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".rdata", 0x2000, 0x1000, 0x2000, 0x1000, 0x40000040});
    // handler table at VA 0x140002000 (RVA 0x2000): 6 pointers into .text.
    const std::uint64_t table_va = 0x140002000ull;
    for (int i = 0; i < 6; ++i)
        for (int k = 0; k < 8; ++k)
            image.bytes[0x2000 + i * 8 + k] = static_cast<std::uint8_t>((0x140001100ull + i * 0x20) >> (8 * k));

    // Decoded instructions (bytes are irrelevant to the detector; it reads text).
    std::vector<gandon::Instruction> insns;
    gandon::Instruction lea; lea.address = 0x140001000ull; lea.size = 7; lea.mnemonic = "lea"; lea.operands = "rcx, [rip + 0xff9]"; // 0x140001007 + 0xff9 = 0x140002000
    gandon::Instruction jmp; jmp.address = 0x140001007ull; jmp.size = 3; jmp.mnemonic = "jmp"; jmp.operands = "qword ptr [rcx + rax*8]";
    insns.push_back(lea); insns.push_back(jmp);

    const auto vm = gandon::detect_vm_dispatch(image, 0x140001000ull, insns);
    assert(vm.found);
    assert(vm.table_va == table_va);
    assert(vm.scale == 8);
    assert(vm.handlers.size() == 6);
    assert(vm.dispatch_site == 0x140001007ull);
    std::puts("vm dispatch detects handler table: OK");
}

void test_vm_dispatch_absent_on_plain_code() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x140000000ull;
    image.bytes.assign(0x2000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    std::vector<gandon::Instruction> insns;
    gandon::Instruction add; add.address = 0x140001000ull; add.size = 3; add.mnemonic = "add"; add.operands = "rax, rbx";
    gandon::Instruction ret; ret.address = 0x140001003ull; ret.size = 1; ret.mnemonic = "ret"; ret.operands = "";
    insns.push_back(add); insns.push_back(ret);
    const auto vm = gandon::detect_vm_dispatch(image, 0x140001000ull, insns);
    assert(!vm.found);
    std::puts("vm dispatch absent on plain code: OK");
}

void test_detect_flattening() {
    // 8 jmps to distinct targets (8 blocks) + 5 more jmps to the dispatcher T.
    std::vector<gandon::Instruction> insns;
    const std::uint64_t T = 0x140001000ull;
    const std::uint64_t others[7] = {0x140002000, 0x140003000, 0x140004000, 0x140005000, 0x140006000, 0x140007000, 0x140008000};
    auto jmp_to = [&](std::uint64_t a, std::uint64_t t) {
        gandon::Instruction j; j.address = a; j.size = 5; j.mnemonic = "jmp";
        char buf[32]; std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(t)); j.operands = buf;
        insns.push_back(j);
    };
    std::uint64_t pc = 0x140010000ull;
    jmp_to(pc, T); pc += 5;
    for (auto o : others) { jmp_to(pc, o); pc += 5; }
    for (int i = 0; i < 5; ++i) { jmp_to(pc, T); pc += 5; }
    gandon::BinaryImage image; image.architecture = gandon::MachineArchitecture::X64; image.is_64_bit = true;
    const auto r = gandon::detect_flattening(image, 0x140010000ull, insns);
    assert(r.flattened);
    assert(r.dispatcher == T);
    assert(r.dispatcher_in_degree == 6);
    std::puts("detect flattening: OK");
}

// Build a tiny .NET image: a PE with a COM data directory -> COR20 header ->
// metadata root with #Strings and #US heaps. One section maps RVA == offset.
std::vector<std::uint8_t> make_dotnet_pe() {
    std::vector<std::uint8_t> b(0x600, 0);
    b[0] = 'M'; b[1] = 'Z';
    put32(b, 0x3c, 0x80);
    const std::size_t pe = 0x80;
    b[pe] = 'P'; b[pe + 1] = 'E';
    put16(b, pe + 6, 1);                  // NumberOfSections (for completeness)
    put16(b, pe + 20, 0xF0);
    const std::size_t opt = pe + 24;
    put16(b, opt + 0, 0x20b);
    put32(b, opt + 108, 16);              // NumberOfRvaAndSizes
    // data directory 14 (COM descriptor) -> COR20 at 0x200
    const std::size_t dir14 = opt + 112 + 14 * 8;
    put32(b, dir14, 0x200);
    put32(b, dir14 + 4, 72);
    // COR20 header at 0x200
    put32(b, 0x200 + 0, 72);              // cb
    put16(b, 0x200 + 4, 2); put16(b, 0x200 + 6, 5);
    put32(b, 0x200 + 8, 0x300);           // MetaData RVA
    put32(b, 0x200 + 12, 0x200);          // MetaData size
    put32(b, 0x200 + 16, 1);              // Flags = ILONLY
    put32(b, 0x200 + 20, 0x06000001);     // EntryPointToken
    // Metadata root at 0x300
    const std::size_t root = 0x300;
    put32(b, root, 0x424A5342u);          // BSJB
    const char* ver = "v4.0.30319";
    put32(b, root + 12, 12);              // version length (padded)
    std::memcpy(b.data() + root + 16, ver, std::strlen(ver));
    std::size_t p = root + 16 + 12;       // 12 == padded version length
    put16(b, p, 0);                       // flags
    put16(b, p + 2, 2);                   // 2 streams
    p += 4;
    // stream header #Strings -> offset 0x40 (rel to root), size 16
    put32(b, p, 0x40); put32(b, p + 4, 16); std::memcpy(b.data() + p + 8, "#Strings", 8); p += 8 + 12; // name padded
    // stream header #US -> offset 0x60, size 8
    put32(b, p, 0x60); put32(b, p + 4, 8); std::memcpy(b.data() + p + 8, "#US", 3); p += 8 + 4;
    // #Strings heap at root+0x40: "\0Main\0Program\0"
    std::size_t s = root + 0x40;
    b[s++] = 0; std::memcpy(b.data() + s, "Main", 4); s += 4; b[s++] = 0;
    std::memcpy(b.data() + s, "Program", 7); s += 7; b[s++] = 0;
    // #US heap at root+0x60: "\0" + blob(len=5){'H',0,'i',0, flag=0}
    std::size_t u = root + 0x60;
    b[u++] = 0; b[u++] = 0x05; b[u++] = 'H'; b[u++] = 0; b[u++] = 'i'; b[u++] = 0; b[u++] = 0;
    return b;
}

void test_parse_dotnet() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.bytes = make_dotnet_pe();
    image.sections.push_back({".all", 0, static_cast<std::uint32_t>(image.bytes.size()), 0,
                              static_cast<std::uint32_t>(image.bytes.size()), 0x60000020});  // identity RVA->offset
    const auto info = gandon::parse_dotnet(image);
    assert(info.is_dotnet);
    assert(info.il_only);
    assert(info.entry_point_token == 0x06000001);
    assert(info.runtime_version == "v4.0.30319");
    assert(std::find(info.names.begin(), info.names.end(), "Main") != info.names.end());
    assert(std::find(info.names.begin(), info.names.end(), "Program") != info.names.end());
    assert(std::find(info.user_strings.begin(), info.user_strings.end(), "Hi") != info.user_strings.end());
    std::puts("parse .NET metadata: OK");
}

void test_parse_dotnet_native_is_rejected() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.bytes = make_mem_pe();          // native PE, no COM directory
    const auto info = gandon::parse_dotnet(image);
    assert(!info.is_dotnet);
    std::puts("parse .NET rejects native PE: OK");
}

void test_demangle_msvc_rtti_name() {
    assert(gandon::demangle_msvc_rtti_name(".?AVWidget@@") == "Widget");
    assert(gandon::demangle_msvc_rtti_name(".?AVWidget@ns@@") == "ns::Widget");
    assert(gandon::demangle_msvc_rtti_name(".?AUPlain@@") == "Plain");
    std::puts("demangle MSVC RTTI name: OK");
}

void test_demangle_msvc_rtti_template_name() {
    // The real TypeDescriptor name for std::vector<int, std::allocator<int>>.
    const auto out = gandon::demangle_msvc_rtti_name(".?AV?$vector@HV?$allocator@H@std@@@std@@");
    // On Windows this goes through dbghelp's real demangler and should resolve
    // the template instead of leaving "?$" mangling markers in the result; on a
    // non-Windows build the plain fallback at least keeps the scope chain sane.
#ifdef _WIN32
    assert(out.find("?$") == std::string::npos);
    assert(out.find("vector") != std::string::npos);
    assert(out.find("std::") != std::string::npos);
    assert(out.find("int") != std::string::npos);
#endif
    std::puts("demangle MSVC RTTI template name: OK");
}

void test_recover_rtti() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x140000000ull;
    image.bytes.assign(0x3000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});   // exec
    image.sections.push_back({".rdata", 0x2000, 0x1000, 0x2000, 0x1000, 0x40000040});  // data
    auto& b = image.bytes;
    // TypeDescriptor @ RVA 0x2000: name at +0x10 = ".?AVWidget@@"
    std::memcpy(b.data() + 0x2010, ".?AVWidget@@", 12);
    // COL @ RVA 0x2100: sig=1, 0, 0, typeDesc=0x2000, chd=0x2200, self=0x2100
    put32(b, 0x2100, 1); put32(b, 0x210C, 0x2000); put32(b, 0x2110, 0x2200); put32(b, 0x2114, 0x2100);
    // ClassHierarchyDescriptor @ 0x2200: sig, attr, numBase=1, array=0x2300
    put32(b, 0x2208, 1); put32(b, 0x220C, 0x2300);
    // vtable region @ 0x2400: [COL ptr][method0][method1][0]
    put64(b, 0x2400, image.image_base + 0x2100);
    put64(b, 0x2408, image.image_base + 0x1000);
    put64(b, 0x2410, image.image_base + 0x1008);
    const auto classes = gandon::recover_rtti(image);
    assert(classes.size() == 1);
    assert(classes[0].name == "Widget");
    assert(classes[0].vtable_va == image.image_base + 0x2408);
    assert(classes[0].method_count == 2);
    std::puts("recover RTTI classes: OK");
}

void test_analyze_driver() {
    auto bytes = make_mem_pe();
    // Subsystem := 1 (native) at optional header + 68.
    const std::size_t opt = 0x80 + 24;
    put16(bytes, opt + 68, 1);
    // DriverEntry @ RVA 0x1000: lea rax,[0x1100]; mov [rcx+0xE0],rax; ret
    const std::uint8_t entry_code[] = {
        0x48, 0x8D, 0x05, 0xF9, 0x00, 0x00, 0x00,   // lea rax, [rip+0xF9] -> 0x140001100
        0x48, 0x89, 0x81, 0xE0, 0x00, 0x00, 0x00,   // mov [rcx+0xE0], rax  (IRP_MJ_DEVICE_CONTROL)
        0xC3,
    };
    std::memcpy(bytes.data() + 0x1000, entry_code, sizeof entry_code);
    // DeviceControl handler @ RVA 0x1100: cmp edx, 0x222003 ; ret
    const std::uint8_t handler_code[] = {0x81, 0xFA, 0x03, 0x20, 0x22, 0x00, 0xC3};
    std::memcpy(bytes.data() + 0x1100, handler_code, sizeof handler_code);

    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x140000000ull;
    image.entry_point = 0x140001000ull;
    image.bytes = std::move(bytes);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});

    const auto info = gandon::analyze_driver(image);
    assert(info.is_driver);
    assert(info.driver_entry == 0x140001000ull);
    bool has_devctl = false;
    for (const auto& h : info.handlers) if (h.major == 0x0E && h.handler == 0x140001100ull) has_devctl = true;
    assert(has_devctl);
    assert(std::find(info.ioctls.begin(), info.ioctls.end(), 0x222003u) != info.ioctls.end());
    std::puts("analyze driver IRP/IOCTL: OK");
}

} // namespace

int main() {
    test_build_pe_from_memory_remaps_sections();
    test_rebuild_imports_from_iat();
    test_vm_dispatch_detects_handler_table();
    test_vm_dispatch_absent_on_plain_code();
    test_detect_flattening();
    test_parse_dotnet();
    test_parse_dotnet_native_is_rejected();
    test_demangle_msvc_rtti_name();
    test_demangle_msvc_rtti_template_name();
    test_recover_rtti();
    test_analyze_driver();
    std::puts("unpack tests passed");
    return 0;
}
