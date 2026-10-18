#include "gandon/driver.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <set>
#include <string>
#include <unordered_map>

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

std::uint16_t pe_subsystem(const BinaryImage& image) {
    const auto& b = image.bytes;
    if (b.size() < 0x40 || b[0] != 'M' || b[1] != 'Z') return 0;
    const std::uint32_t pe = rd32(b, 0x3c);
    if (pe + 24 > b.size() || b[pe] != 'P' || b[pe + 1] != 'E') return 0;
    return rd16(b, pe + 24 + 68);  // OptionalHeader.Subsystem
}

// Parse "0x1234" / "1234" starting at pos; returns value and whether parsed.
bool parse_uint(const std::string& s, std::size_t pos, std::uint64_t& out) {
    while (pos < s.size() && s[pos] == ' ') ++pos;
    int base = 10; std::size_t start = pos;
    if (s.compare(pos, 2, "0x") == 0) { base = 16; start = pos + 2; }
    std::uint64_t v = 0; std::size_t i = start;
    for (; i < s.size(); ++i) {
        const char c = s[i]; int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (base == 16 && c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        v = v * base + static_cast<std::uint64_t>(d);
    }
    if (i == start) return false;
    out = v; return true;
}

std::string first_reg(const std::string& operand) {
    std::size_t i = 0;
    while (i < operand.size() && !std::isalpha(static_cast<unsigned char>(operand[i]))) ++i;
    std::string r;
    while (i < operand.size() && (std::isalnum(static_cast<unsigned char>(operand[i])))) r.push_back(operand[i++]);
    return r;
}

} // namespace

std::string irp_major_name(int major) {
    static const std::unordered_map<int, const char*> names = {
        {0x00, "IRP_MJ_CREATE"}, {0x01, "IRP_MJ_CREATE_NAMED_PIPE"}, {0x02, "IRP_MJ_CLOSE"},
        {0x03, "IRP_MJ_READ"}, {0x04, "IRP_MJ_WRITE"}, {0x05, "IRP_MJ_QUERY_INFORMATION"},
        {0x06, "IRP_MJ_SET_INFORMATION"}, {0x09, "IRP_MJ_FLUSH_BUFFERS"}, {0x0C, "IRP_MJ_DIRECTORY_CONTROL"},
        {0x0D, "IRP_MJ_FILE_SYSTEM_CONTROL"}, {0x0E, "IRP_MJ_DEVICE_CONTROL"},
        {0x0F, "IRP_MJ_INTERNAL_DEVICE_CONTROL"}, {0x10, "IRP_MJ_SHUTDOWN"}, {0x12, "IRP_MJ_CLEANUP"},
        {0x1B, "IRP_MJ_PNP"},
    };
    const auto it = names.find(major);
    if (it != names.end()) return it->second;
    char buf[32]; std::snprintf(buf, sizeof buf, "IRP_MJ_0x%02X", major);
    return buf;
}

DriverInfo analyze_driver(const BinaryImage& image) {
    DriverInfo info;
    if (image.format != BinaryFormat::PE) { info.error = "not a PE"; return info; }
    const bool is64 = image.is_64_bit;

    bool kernel_import = false;
    for (const auto& imp : image.imports) {
        static const std::set<std::string> markers = {"IoCreateDevice", "IoCreateSymbolicLink", "IofCompleteRequest",
            "IoDeleteDevice", "KeInitializeMutex", "ExAllocatePool", "ExAllocatePoolWithTag", "RtlInitUnicodeString"};
        std::string n = imp.name; const auto bang = n.rfind('!'); if (bang != std::string::npos) n = n.substr(bang + 1);
        if (markers.count(n)) { kernel_import = true; break; }
    }
    if (pe_subsystem(image) != 1 && !kernel_import) { info.error = "not a kernel driver (subsystem is not native and no ntoskrnl imports)"; return info; }
    info.is_driver = true;
    info.driver_entry = image.entry_point;

    const std::uint64_t major_base = is64 ? 0x70 : 0x38;
    const std::size_t ptr = is64 ? 8 : 4;

    // Scan DriverEntry for `lea reg,[routine]` then `mov [obj+disp], reg` into the
    // MajorFunction table.
    const auto entry_insns = decode_instructions(image, info.driver_entry, 800);
    std::unordered_map<std::string, std::uint64_t> lea_target;
    std::uint64_t device_control_handler = 0;
    for (const auto& ins : entry_insns) {
        if (ins.mnemonic == "lea") {
            const auto comma = ins.operands.find(',');
            if (comma == std::string::npos) continue;
            const std::string dst = first_reg(ins.operands.substr(0, comma));
            const std::string mem = ins.operands.substr(comma + 1);
            const auto rip = mem.find("rip");
            std::uint64_t disp = 0;
            if (rip != std::string::npos) {
                const auto plus = mem.find('+', rip);
                if (plus != std::string::npos && parse_uint(mem, plus + 1, disp)) lea_target[dst] = ins.address + ins.size + disp;
            } else {
                const auto lb = mem.find('[');
                if (lb != std::string::npos && parse_uint(mem, lb + 1, disp) && image.va_to_file_offset(disp)) lea_target[dst] = disp;
            }
            continue;
        }
        if (ins.mnemonic == "mov" && ins.operands.find('[') != std::string::npos &&
            ins.operands.find('[') < ins.operands.find(',')) {
            const auto lb = ins.operands.find('[');
            const auto rb = ins.operands.find(']', lb);
            const auto comma = ins.operands.find(',', rb);
            if (rb == std::string::npos || comma == std::string::npos) continue;
            const std::string mem = ins.operands.substr(lb + 1, rb - lb - 1);
            const std::string src = first_reg(ins.operands.substr(comma + 1));
            const auto plus = mem.find('+');
            std::uint64_t disp = 0;
            if (plus == std::string::npos || !parse_uint(mem, plus + 1, disp)) continue;
            if (disp < major_base || disp > major_base + 27 * ptr || (disp - major_base) % ptr) continue;
            const auto lt = lea_target.find(src);
            if (lt == lea_target.end()) continue;
            const int major = static_cast<int>((disp - major_base) / ptr);
            info.handlers.push_back({major, irp_major_name(major), lt->second});
            if (major == 0x0E) device_control_handler = lt->second;
        }
    }

    // IOCTL codes compared in the DeviceControl handler.
    if (device_control_handler) {
        const auto h = decode_instructions(image, device_control_handler, 2000);
        std::set<std::uint32_t> seen;
        for (const auto& ins : h) {
            if (ins.mnemonic != "cmp" && ins.mnemonic != "sub") continue;
            const auto comma = ins.operands.rfind(',');
            if (comma == std::string::npos) continue;
            std::uint64_t imm = 0;
            if (!parse_uint(ins.operands, comma + 1, imm)) continue;
            if (imm < 0x10000 || imm > 0xffffffffull) continue;        // IOCTL codes are 32-bit, device type in the high bits
            if ((imm & 0x3) > 3) continue;
            if (seen.insert(static_cast<std::uint32_t>(imm)).second) info.ioctls.push_back(static_cast<std::uint32_t>(imm));
        }
    }
    std::sort(info.handlers.begin(), info.handlers.end(), [](const DriverIrpHandler& a, const DriverIrpHandler& b) { return a.major < b.major; });
    return info;
}

} // namespace gandon
