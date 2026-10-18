#include "gandon/stack_frame.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <sstream>
#include <unordered_map>

namespace gandon {
namespace {

std::string hex(std::uint64_t value) {
    std::ostringstream out;
    out << std::hex << std::uppercase << value;
    return out.str();
}

std::string no_spaces(const std::string& text) {
    std::string out;
    for (char c : text) if (c != ' ') out.push_back(c);
    return out;
}

std::string strip_prefix(std::string m) {
    for (const char* p : {"bnd ", "notrack ", "rep ", "repne ", "repe ", "lock "})
        if (m.rfind(p, 0) == 0) m = m.substr(std::string(p).size());
    return m;
}

// Parse a signed immediate at position `i` in `s` ("0x1f", "-0x8", "24").
bool parse_disp(const std::string& s, std::size_t i, long long& out, std::size_t& end) {
    long long sign = 1;
    if (i < s.size() && (s[i] == '+' || s[i] == '-')) { if (s[i] == '-') sign = -1; ++i; }
    if (i < s.size() && s[i] == '#') ++i;                 // AArch64 immediate marker
    if (i < s.size() && (s[i] == '+' || s[i] == '-')) { if (s[i] == '-') sign = -1; ++i; }
    const char* begin = s.c_str() + i;
    char* stop = nullptr;
    const auto value = std::strtoll(begin, &stop, 0);
    if (stop == begin) return false;
    out = sign * value;
    end = static_cast<std::size_t>(stop - s.c_str());
    return true;
}

// Frame-pointer / stack-pointer base registers.
bool is_base_reg(const std::string& r) {
    return r == "rbp" || r == "ebp" || r == "rsp" || r == "esp" || r == "x29" || r == "fp" || r == "sp";
}
bool is_fp_reg(const std::string& r) { return r == "rbp" || r == "ebp" || r == "x29" || r == "fp"; }

// A frame reference extracted from one bracket expression.
struct MemRef { std::string reg; long long disp{0}; bool indexed{false}; };

// Collect frame-base bracket references in an operand string (x86 and AArch64).
std::vector<MemRef> frame_refs(const std::string& operands) {
    std::vector<MemRef> refs;
    for (std::size_t p = 0; (p = operands.find('[', p)) != std::string::npos;) {
        const auto close = operands.find(']', p);
        if (close == std::string::npos) break;
        std::string inner = no_spaces(operands.substr(p + 1, close - p - 1));
        p = close + 1;
        for (char& c : inner) if (c == ',') c = '+';     // "sp,#0x10" -> "sp+#0x10"
        // leading register name
        std::size_t r = 0;
        while (r < inner.size() && (std::isalnum(static_cast<unsigned char>(inner[r])))) ++r;
        if (r == 0) continue;
        MemRef ref;
        ref.reg = inner.substr(0, r);
        if (!is_base_reg(ref.reg)) continue;
        ref.indexed = inner.find('*') != std::string::npos;
        long long disp = 0; std::size_t end = 0;
        if (r < inner.size() && (inner[r] == '+' || inner[r] == '-')) {
            if (parse_disp(inner, r, disp, end)) {
                // a second +/- (beyond a '#') means an index term: treat as indexed
                if (end < inner.size() && (inner[end] == '+' || inner[end] == '-')) ref.indexed = true;
                ref.disp = disp;
            }
        }
        refs.push_back(ref);
    }
    return refs;
}

std::uint32_t access_size(const std::string& operands, bool arm64, const std::string& mnem) {
    if (!arm64) {
        // Search with a leading space so "word ptr" does not match inside
        // "dword ptr"/"qword ptr"; test longest first for safety.
        const std::string hay = " " + operands;
        static const std::array<std::pair<const char*, std::uint32_t>, 7> sizes{{
            {" xmmword ptr", 16}, {" ymmword ptr", 32}, {" qword ptr", 8}, {" dword ptr", 4},
            {" tbyte ptr", 10}, {" word ptr", 2}, {" byte ptr", 1}}};
        for (auto [kw, sz] : sizes) if (hay.find(kw) != std::string::npos) return sz;
        return 0;
    }
    if (mnem.size() >= 4 && mnem.compare(mnem.size() - 1, 1, "b") == 0 && mnem.rfind("ld", 0) == 0) return 1;
    if (mnem.size() >= 4 && mnem.compare(mnem.size() - 1, 1, "h") == 0 && mnem.rfind("ld", 0) == 0) return 2;
    return operands.find(" w") != std::string::npos || operands.rfind("w", 0) == 0 ? 4 : 8;
}

// Canonical name for the ABI integer-argument registers (and their width
// aliases), or "" if the token is not one of them.
std::string canonical_arg_reg(std::string r, bool arm64) {
    for (auto& c : r) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (arm64) {
        if (r.size() >= 2 && (r[0] == 'x' || r[0] == 'w') && std::isdigit(static_cast<unsigned char>(r[1])))
            return "x" + r.substr(1);
        return {};
    }
    static const std::unordered_map<std::string, std::string> map = {
        {"rcx", "rcx"}, {"ecx", "rcx"}, {"cx", "rcx"}, {"cl", "rcx"},
        {"rdx", "rdx"}, {"edx", "rdx"}, {"dx", "rdx"}, {"dl", "rdx"},
        {"r8", "r8"}, {"r8d", "r8"}, {"r8w", "r8"}, {"r8b", "r8"},
        {"r9", "r9"}, {"r9d", "r9"}, {"r9w", "r9"}, {"r9b", "r9"},
        {"rdi", "rdi"}, {"edi", "rdi"}, {"di", "rdi"}, {"dil", "rdi"},
        {"rsi", "rsi"}, {"esi", "rsi"}, {"si", "rsi"}, {"sil", "rsi"},
    };
    const auto it = map.find(r);
    return it == map.end() ? std::string() : it->second;
}

// Split operands into tokens that look like registers.
std::vector<std::string> reg_tokens(const std::string& operands) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : operands) {
        if (std::isalnum(static_cast<unsigned char>(c))) cur.push_back(c);
        else { if (!cur.empty()) out.push_back(cur); cur.clear(); }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

bool pure_write(const std::string& m) {
    return m == "mov" || m == "lea" || m == "movzx" || m == "movsx" || m == "movsxd" ||
           m == "movabs" || m == "ldr" || m == "ldp" || m == "ldrb" || m == "ldrh";
}

int count_reg_args(const Function& f, bool arm64, bool windows_abi) {
    std::vector<std::string> order;
    if (arm64) order = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
    else if (windows_abi) order = {"rcx", "rdx", "r8", "r9"};
    else order = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};

    std::unordered_map<std::string, int> first_use, first_def;
    int idx = 0;
    for (const auto& ins : f.instructions) {
        const auto m = strip_prefix(ins.mnemonic);
        const auto comma = ins.operands.find(',');
        const std::string dest = comma == std::string::npos ? ins.operands : ins.operands.substr(0, comma);
        const auto dest_tokens = reg_tokens(dest);
        const std::string dest_reg = dest_tokens.empty() ? std::string() : canonical_arg_reg(dest_tokens.front(), arm64);
        const bool dest_in_brackets = dest.find('[') != std::string::npos;
        const auto tokens = reg_tokens(ins.operands);
        for (std::size_t t = 0; t < tokens.size(); ++t) {
            const auto canon = canonical_arg_reg(tokens[t], arm64);
            if (canon.empty()) continue;
            // The destination of a pure write is defined here, not read.
            const bool is_written_dest = t == 0 && !dest_in_brackets && pure_write(m) && canon == dest_reg;
            if (is_written_dest) continue;
            if (!first_use.count(canon)) first_use[canon] = idx;
        }
        if (!dest_reg.empty() && !dest_in_brackets && pure_write(m) && !first_def.count(dest_reg))
            first_def[dest_reg] = idx;
        ++idx;
    }
    int count = 0;
    for (const auto& reg : order) {
        const auto use = first_use.find(reg);
        const auto def = first_def.find(reg);
        const bool used_as_arg = use != first_use.end() && (def == first_def.end() || use->second <= def->second);
        if (used_as_arg) ++count; else break;   // arguments are contiguous
    }
    return count;
}

} // namespace

std::optional<std::string> StackFrame::rename(const std::string& reg, long long disp) const {
    if (is_fp_reg(reg)) {
        // Only a true frame-pointer frame names rbp/x29 references; otherwise
        // rbp/x29 is just a general-purpose register in this function.
        if (base != Base::Rbp) return std::nullopt;
        if (disp < 0) return "var_" + hex(static_cast<std::uint64_t>(-disp));
        if (!arm64 && disp >= 0x10) return "arg_" + hex(static_cast<std::uint64_t>(disp - 0x10));
        if (arm64 && disp > 0) return "var_s" + hex(static_cast<std::uint64_t>(disp));
        return std::nullopt;
    }
    // stack-pointer relative (rsp/esp/sp): only meaningful for an rsp frame.
    if (base != Base::Rsp || alloc == 0) return std::nullopt;
    const long long K = static_cast<long long>(alloc);
    if (disp >= 0 && disp < K) return "var_" + hex(static_cast<std::uint64_t>(K - disp));
    if (!arm64 && disp >= K + 8) return "arg_" + hex(static_cast<std::uint64_t>(disp - K - 8));
    return std::nullopt;
}

std::string StackFrame::convention(bool windows_abi) const {
    if (arm64) return "AAPCS64";
    if (ret_pop > 0) return "__stdcall";
    return windows_abi ? "__fastcall" : "System V";
}

std::string StackFrame::prototype(const std::string& func_name, bool windows_abi) const {
    std::size_t stack_args = 0;
    for (const auto& v : vars) if (v.is_arg) {
        // MS x64: the first 0x20 above the return address is the shadow/home
        // area for the register arguments, not additional stack parameters.
        if (!arm64 && windows_abi && v.offset >= 0 && v.offset < 0x20) continue;
        ++stack_args;
    }
    const std::size_t total = static_cast<std::size_t>(reg_args) + stack_args;
    std::ostringstream out;
    const std::string conv = arm64 ? "" : ret_pop > 0 ? "__stdcall " : windows_abi ? "__fastcall " : "";
    out << "__int64 " << conv << func_name << "(";
    if (total == 0) out << (arm64 ? "" : "void");
    for (std::size_t i = 0; i < total; ++i) {
        if (i) out << ", ";
        out << "__int64 a" << (i + 1);
    }
    out << ")";
    return out.str();
}

std::vector<std::string> StackFrame::summary_lines() const {
    std::vector<std::string> lines;
    auto kind = [](std::uint32_t s) -> const char* {
        switch (s) { case 1: return "db"; case 2: return "dw"; case 4: return "dd"; case 8: return "dq";
            case 16: return "xmmword"; case 32: return "ymmword"; default: return "dd"; }
    };
    for (const auto& v : vars) {
        std::ostringstream line;
        line << v.name;
        for (std::size_t pad = v.name.size(); pad < 15; ++pad) line << ' ';
        line << "= " << kind(v.size ? v.size : 4) << ' ';
        if (v.offset < 0) line << "-" << hex(static_cast<std::uint64_t>(-v.offset)) << "h";
        else line << hex(static_cast<std::uint64_t>(v.offset)) << "h";
        lines.push_back(line.str());
    }
    return lines;
}

StackFrame analyze_stack_frame(const Function& function, bool is_64_bit, bool arm64, bool windows_abi) {
    StackFrame frame;
    frame.arm64 = arm64;

    // ---- 1. frame base + reserved size from the prologue
    int seen = 0;
    for (const auto& ins : function.instructions) {
        if (++seen > 16) break;
        const auto m = strip_prefix(ins.mnemonic);
        const auto ops = no_spaces(ins.operands);
        if (!arm64) {
            if (m == "mov" && (ops == "rbp,rsp" || ops == "ebp,esp")) { frame.base = StackFrame::Base::Rbp; }
            else if (m == "sub" && (ops.rfind("rsp,", 0) == 0 || ops.rfind("esp,", 0) == 0) && frame.alloc == 0) {
                long long v = 0; std::size_t e = 0;
                if (parse_disp(ops, ops.find(',') + 1, v, e) && v > 0) {
                    frame.alloc = static_cast<std::uint64_t>(v);
                    if (frame.base == StackFrame::Base::None) frame.base = StackFrame::Base::Rsp;
                }
            }
        } else {
            if (m == "mov" && (ops == "x29,sp" || ops == "fp,sp")) frame.base = StackFrame::Base::Rbp;
            else if (m == "sub" && ops.rfind("sp,sp,", 0) == 0 && frame.alloc == 0) {
                long long v = 0; std::size_t e = 0;
                if (parse_disp(ops, ops.rfind(',') + 1, v, e) && v > 0) {
                    frame.alloc = static_cast<std::uint64_t>(v);
                    if (frame.base == StackFrame::Base::None) frame.base = StackFrame::Base::Rsp;
                }
            } else if ((m == "stp" || m == "str") && ins.operands.find("]!") != std::string::npos && frame.alloc == 0) {
                for (const auto& ref : frame_refs(ins.operands))
                    if ((ref.reg == "sp" || ref.reg == "x29") && ref.disp < 0) {
                        frame.alloc = static_cast<std::uint64_t>(-ref.disp);
                        if (frame.base == StackFrame::Base::None) frame.base = StackFrame::Base::Rbp;
                    }
            }
        }
    }

    // ---- 2. collect slots from every frame-base memory reference
    std::unordered_map<long long, StackVar> slots;   // keyed by normalised offset
    for (const auto& ins : function.instructions) {
        const auto size = access_size(ins.operands, arm64, strip_prefix(ins.mnemonic));
        for (const auto& ref : frame_refs(ins.operands)) {
            if (ref.indexed) continue;
            const auto name = frame.rename(ref.reg, ref.disp);
            if (!name) continue;
            long long norm;              // normalise to rbp semantics for keying
            const bool fp = is_fp_reg(ref.reg);
            if (fp) norm = ref.disp;
            else norm = (ref.disp < static_cast<long long>(frame.alloc))
                            ? ref.disp - static_cast<long long>(frame.alloc)        // local
                            : ref.disp - static_cast<long long>(frame.alloc) - 8;   // arg (past ret addr)
            auto& slot = slots[norm];
            slot.offset = norm;
            slot.name = *name;
            slot.is_arg = name->rfind("arg_", 0) == 0;
            slot.size = std::max(slot.size, size);
        }
    }
    frame.vars.reserve(slots.size());
    for (auto& [off, v] : slots) frame.vars.push_back(v);
    std::sort(frame.vars.begin(), frame.vars.end(),
              [](const StackVar& a, const StackVar& b) { return a.offset < b.offset; });

    // ---- 3. register arguments
    if (is_64_bit || arm64) frame.reg_args = count_reg_args(function, arm64, windows_abi);

    // ---- 4. callee stack cleanup: `ret N` marks a __stdcall function.
    if (!arm64)
        for (const auto& ins : function.instructions) {
            const auto m = strip_prefix(ins.mnemonic);
            if ((m == "ret" || m == "retn") && !ins.operands.empty()) {
                long long v = 0; std::size_t e = 0;
                if (parse_disp(no_spaces(ins.operands), 0, v, e) && v > 0 && v < 0x10000)
                    frame.ret_pop = static_cast<std::uint16_t>(v);
            }
        }
    return frame;
}

} // namespace gandon
