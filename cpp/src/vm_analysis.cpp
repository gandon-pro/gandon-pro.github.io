#include "gandon/vm_analysis.hpp"
#include "gandon/emulator.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <unordered_set>

namespace gandon {
namespace {

std::uint64_t read_ptr(const BinaryImage& image, std::uint64_t va, int width) {
    const auto off = image.va_to_file_offset(va);
    if (!off || *off + static_cast<std::size_t>(width) > image.bytes.size()) return 0;
    std::uint64_t value = 0;
    for (int i = 0; i < width; ++i) value |= static_cast<std::uint64_t>(image.bytes[*off + i]) << (8 * i);
    return value;
}

bool in_image(const BinaryImage& image, std::uint64_t va) { return image.va_to_file_offset(va).has_value(); }

// Parse a hexadecimal (0x...) or decimal integer embedded in text at `pos`.
bool parse_int(const std::string& s, std::size_t pos, std::uint64_t& out) {
    while (pos < s.size() && (s[pos] == ' ' || s[pos] == '+')) ++pos;
    if (pos >= s.size()) return false;
    int base = 10; std::size_t start = pos;
    if (s.compare(pos, 2, "0x") == 0 || s.compare(pos, 2, "0X") == 0) { base = 16; start = pos + 2; }
    std::size_t i = start;
    std::uint64_t value = 0;
    for (; i < s.size(); ++i) {
        const char c = s[i];
        int digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (base == 16 && c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else break;
        value = value * base + static_cast<std::uint64_t>(digit);
    }
    if (i == start) return false;
    out = value;
    return true;
}

// Scan a handler table starting at `table_va`, reading pointer entries until one
// falls outside the image or the cap is hit. Returns the distinct in-image
// handler addresses (order preserved).
std::vector<std::uint64_t> read_handler_table(const BinaryImage& image, std::uint64_t table_va, int width) {
    std::vector<std::uint64_t> handlers;
    std::set<std::uint64_t> seen;
    for (int i = 0; i < 4096; ++i) {
        const std::uint64_t entry = read_ptr(image, table_va + static_cast<std::uint64_t>(i) * width, width);
        if (!entry || !in_image(image, entry)) break;
        if (seen.insert(entry).second) handlers.push_back(entry);
    }
    return handlers;
}

} // namespace

VmDispatch detect_vm_dispatch(const BinaryImage& image, std::uint64_t function_start,
                              const std::vector<Instruction>& instructions) {
    (void)function_start;
    VmDispatch out;
    const int ptr_width = image.is_64_bit ? 8 : 4;

    // Track the most recent `lea reg, [rip + disp]` so a register-based table
    // dispatch (`jmp [base + idx*8]`) can recover the table address.
    std::uint64_t last_lea_target = 0;

    for (const auto& ins : instructions) {
        const std::string& m = ins.mnemonic;
        const std::string& ops = ins.operands;

        if (m == "lea") {
            // "reg, [rip + 0x1234]" -> absolute = next_ip + disp
            const auto rip = ops.find("rip");
            if (rip != std::string::npos) {
                std::uint64_t disp = 0;
                const auto plus = ops.find('+', rip);
                if (plus != std::string::npos && parse_int(ops, plus + 1, disp))
                    last_lea_target = ins.address + ins.size + disp;
            }
            continue;
        }

        const bool is_jmp = m == "jmp" || m == "bnd jmp";
        if (!is_jmp) continue;
        const auto lb = ops.find('[');
        if (lb == std::string::npos) continue;            // `jmp reg` handled by dynamic trace, not here
        const auto rb = ops.find(']', lb);
        if (rb == std::string::npos) continue;
        const std::string mem = ops.substr(lb + 1, rb - lb - 1);

        // Require an index*scale term (table dispatch), scale 4 or 8.
        const auto star = mem.find('*');
        if (star == std::string::npos) continue;
        int scale = 0;
        if (star + 1 < mem.size()) scale = mem[star + 1] - '0';
        if (scale != 4 && scale != 8) continue;

        std::uint64_t table_va = 0;
        if (mem.find("rip") != std::string::npos) {
            // jmp qword ptr [rip + disp + idx*scale] — rare but possible
            std::uint64_t disp = 0;
            const auto rip = mem.find("rip");
            const auto plus = mem.find('+', rip);
            if (plus != std::string::npos && parse_int(mem, plus + 1, disp)) table_va = ins.address + ins.size + disp;
        } else {
            // Absolute displacement in the operand (e.g. "rax*8 + 0x140001000").
            std::uint64_t disp = 0;
            std::size_t scan = 0; bool got = false;
            while (scan < mem.size()) {
                if (mem.compare(scan, 2, "0x") == 0) { if (parse_int(mem, scan, disp)) { got = true; break; } }
                ++scan;
            }
            if (got && in_image(image, disp)) table_va = disp;
            else if (last_lea_target && in_image(image, last_lea_target)) table_va = last_lea_target;  // base from a prior lea
        }
        if (!table_va || !in_image(image, table_va)) continue;

        auto handlers = read_handler_table(image, table_va, ptr_width);
        if (handlers.size() < 4) continue;   // too few to be a VM handler table

        out.found = true;
        out.dispatch_site = ins.address;
        out.table_va = table_va;
        out.scale = scale;
        out.handlers = std::move(handlers);
        out.note = "VM dispatch via table of " + std::to_string(out.handlers.size()) + " handler(s)";
        return out;
    }

    out.note = "no table-based VM dispatcher found in this function";
    return out;
}

std::vector<VmHandlerInfo> classify_vm_handlers(const BinaryImage& image, const VmDispatch& dispatch) {
    std::vector<VmHandlerInfo> out;
    for (const auto h : dispatch.handlers) {
        const auto insns = decode_instructions(image, h, 64);
        VmHandlerInfo info; info.address = h;
        bool add = false, sub = false, logic = false, shift = false, mul = false, mem = false, stack = false, branch = false;
        std::size_t n = 0;
        for (const auto& ins : insns) {
            ++n;
            const std::string& m = ins.mnemonic;
            if (m == "add" || m == "adc" || m == "inc") add = true;
            else if (m == "sub" || m == "sbb" || m == "dec" || m == "neg") sub = true;
            else if (m == "xor" || m == "and" || m == "or" || m == "not") logic = true;
            else if (m == "shl" || m == "shr" || m == "sar" || m == "rol" || m == "ror") shift = true;
            else if (m == "mul" || m == "imul" || m == "div" || m == "idiv") mul = true;
            else if (m == "push" || m == "pop") stack = true;
            else if (m == "cmp" || m == "test" || (!m.empty() && m[0] == 'j' && m != "jmp")) branch = true;
            if (ins.operands.find('[') != std::string::npos && (m == "mov" || m == "movzx" || m == "movsx")) mem = true;
            if (m == "ret" || m == "jmp") break;   // handler end / tail back to dispatcher
        }
        info.instruction_count = n;
        std::string c;
        auto add_tag = [&](const char* t) { if (!c.empty()) c += ","; c += t; };
        if (add) add_tag("arith(+)");
        if (sub) add_tag("arith(-)");
        if (mul) add_tag("mul/div");
        if (logic) add_tag("logic");
        if (shift) add_tag("shift");
        if (mem) add_tag("load/store");
        if (stack) add_tag("stack");
        if (branch) add_tag("branch");
        info.classification = c.empty() ? "misc/move" : c;
        out.push_back(std::move(info));
    }
    return out;
}

VmTrace trace_vm_handlers(const BinaryImage& image, std::uint64_t entry, const VmDispatch& dispatch,
                          std::size_t max_handlers) {
    VmTrace out;
    if (!dispatch.found || dispatch.handlers.empty()) { out.error = "no VM dispatch table to trace against"; return out; }
    Emulator emu(image);
    if (!emu.ready()) { out.error = emu.error(); return out; }
    std::string err;
    const char* pc = image.architecture == MachineArchitecture::ARM64 ? "PC" : image.is_64_bit ? "RIP" : "EIP";
    if (!emu.set_register(pc, entry, err)) { out.error = err; return out; }

    const std::unordered_set<std::uint64_t> handler_set(dispatch.handlers.begin(), dispatch.handlers.end());
    for (const auto h : dispatch.handlers) emu.add_breakpoint(h);

    for (std::size_t i = 0; i < max_handlers; ++i) {
        const auto result = emu.run(2'000'000, 2'000'000);
        if (result.stop == EmulationStop::Breakpoint && handler_set.count(result.program_counter)) {
            out.handler_sequence.push_back(result.program_counter);
            // Step once past the handler entry so run() does not re-trip the same breakpoint.
            if (emu.step().stop == EmulationStop::Error) { out.error = "emulation error after handler"; break; }
            continue;
        }
        if (result.stop == EmulationStop::InstructionLimit || result.stop == EmulationStop::TimedOut) { out.truncated = true; }
        else if (result.stop == EmulationStop::Error || result.stop == EmulationStop::MemoryFault) out.error = result.error.empty() ? "emulation fault (likely anti-emulation / protection)" : result.error;
        out.steps = result.instructions_executed;
        break;
    }
    out.ok = !out.handler_sequence.empty();
    if (!out.ok && out.error.empty()) out.error = "no handlers were reached during emulation";
    return out;
}

FlatteningReport detect_flattening(const BinaryImage& image, std::uint64_t function_start,
                                   const std::vector<Instruction>& instructions) {
    (void)image; (void)function_start;
    FlatteningReport out;
    std::map<std::uint64_t, std::size_t> in_degree;
    std::size_t blocks = 0;
    for (const auto& ins : instructions) {
        const std::string& m = ins.mnemonic;
        if (m.empty() || m[0] != 'j') continue;                   // jmp / jcc
        ++out.branch_count;
        const std::string& ops = ins.operands;
        if (ops.find('[') != std::string::npos) { ++out.indirect_jumps; continue; }
        // A register-indirect jump ("jmp rax") also counts as indirect.
        std::uint64_t target = 0;
        const bool literal = (ops.rfind("0x", 0) == 0) && parse_int(ops, 0, target);
        if (!literal) { if (m == "jmp") ++out.indirect_jumps; continue; }
        if (++in_degree[target] == 1) ++blocks;
    }
    for (const auto& [addr, deg] : in_degree)
        if (deg > out.dispatcher_in_degree) { out.dispatcher_in_degree = deg; out.dispatcher = addr; }

    // A flattened function funnels many blocks through one dispatcher: a high
    // in-degree target that dominates the branch mix.
    if (out.dispatcher_in_degree >= 5 && blocks >= 8 &&
        out.dispatcher_in_degree * 100 >= out.branch_count * 25) {
        out.flattened = true;
        out.note = "likely control-flow flattening: dispatcher at 0x reached by " +
                   std::to_string(out.dispatcher_in_degree) + " of " + std::to_string(out.branch_count) + " branches";
    } else if (out.indirect_jumps * 100 >= (out.branch_count ? out.branch_count : 1) * 50 && out.branch_count >= 6) {
        out.note = "heavy indirect branching (" + std::to_string(out.indirect_jumps) + "/" +
                   std::to_string(out.branch_count) + ") — possible VM or jump-table obfuscation";
    } else {
        out.note = "no flattening signature";
    }
    return out;
}

} // namespace gandon
