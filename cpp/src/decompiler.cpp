// Structured pseudocode generator for x86-64.
//
// Pipeline: instructions -> basic blocks -> per-block symbolic lifting into
// SSA-like temporaries -> inlining / dead-code elimination -> liveness over
// register variables -> region structuring (if / while / do-while / break /
// continue, goto only as a last resort) -> C-like text.
#include "gandon/decompiler.hpp"
#include "gandon/image_tables.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace gandon {
namespace {

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------
enum class K : std::uint8_t { Const, Var, Frame, Un, Bin, Deref, Cast, Call, Tern, Intrin };

struct Expr;
using EP = std::shared_ptr<const Expr>;

struct Expr {
    K kind{K::Const};
    std::string name;          // Var name / operator / callee / cast spelling / intrinsic
    std::uint64_t imm{0};      // Const value, Frame offset (signed), Call: 1 = indirect callee in a[0]
    int size{8};               // Var/Deref/Cast width in bytes
    bool is_signed{false};     // Cast signedness
    bool temp{false};          // Var: compiler temporary (block local)
    std::uint8_t fp{0};        // value type: 1 float, 2 double, 3 long double (0: integer / untyped)
    bool keep{false};          // node must survive rebuilds untouched (floating-point conversions)
    std::vector<EP> a;
};

EP make(Expr e) { return std::make_shared<const Expr>(std::move(e)); }

EP konst(std::uint64_t value, int size = 8) {
    Expr e; e.kind = K::Const; e.imm = value; e.size = size; return make(std::move(e));
}
EP var(const std::string& name, int size = 8, bool temp = false) {
    Expr e; e.kind = K::Var; e.name = name; e.size = size; e.temp = temp; return make(std::move(e));
}
EP frame(std::int64_t offset) {
    Expr e; e.kind = K::Frame; e.imm = static_cast<std::uint64_t>(offset); return make(std::move(e));
}
std::int64_t frame_offset(const EP& e) { return static_cast<std::int64_t>(e->imm); }

bool is_const(const EP& e) { return e->kind == K::Const; }
bool is_var(const EP& e) { return e->kind == K::Var; }

bool same(const EP& l, const EP& r) {
    if (l == r) return true;
    if (l->kind != r->kind || l->name != r->name || l->imm != r->imm || l->size != r->size ||
        l->is_signed != r->is_signed || l->a.size() != r->a.size()) return false;
    for (std::size_t i = 0; i < l->a.size(); ++i) if (!same(l->a[i], r->a[i])) return false;
    return true;
}

int width(const EP& e) {
    switch (e->kind) {
    case K::Const: return 0;
    case K::Var: return e->size;
    case K::Frame: return 8;
    case K::Deref: return e->size;
    case K::Cast: return e->size;
    case K::Call: return 8;
    case K::Un: return e->name == "!" ? 1 : width(e->a[0]);
    case K::Tern: return (std::max)(width(e->a[1]), width(e->a[2]));
    case K::Intrin: return 8;
    case K::Bin: {
        static const std::set<std::string> compare{"==", "!=", "<", "<=", ">", ">=", "&&", "||"};
        if (compare.contains(e->name)) return 1;
        if (e->name == "&" && is_const(e->a[1]) && e->a[1]->imm <= 0xFFFFFFFFull) return 4;
        return (std::max)(width(e->a[0]), width(e->a[1]));
    }
    }
    return 8;
}

std::uint64_t mask_for(int size) { return size >= 8 ? ~0ull : ((1ull << (size * 8)) - 1); }

std::string cast_name(int size, bool is_signed) {
    switch (size) {
    case 1: return is_signed ? "int8_t" : "uint8_t";
    case 2: return is_signed ? "int16_t" : "uint16_t";
    case 4: return is_signed ? "int32_t" : "uint32_t";
    default: return is_signed ? "int64_t" : "uint64_t";
    }
}

EP cast(int size, bool is_signed, const EP& e) {
    if (e->keep && e->kind == K::Cast && !e->fp && e->size <= size && size < 8) return e;   // (int32_t)double already is a 32-bit value
    if (size >= 8 && !is_signed) return e;
    if (e->kind == K::Const) {
        std::uint64_t v = e->imm & mask_for(size);
        if (is_signed && size < 8 && (v & (1ull << (size * 8 - 1)))) v |= ~mask_for(size);
        return konst(v, size);
    }
    if (!is_signed && width(e) != 0 && width(e) <= size && e->kind != K::Cast) return e;
    if (e->kind == K::Cast && e->size >= size && size < 8) {
        Expr c; c.kind = K::Cast; c.size = size; c.is_signed = is_signed; c.name = cast_name(size, is_signed); c.a = {e->a[0]};
        return make(std::move(c));
    }
    if (e->kind == K::Cast && e->size == size && e->is_signed == is_signed) return e;
    if (e->kind == K::Intrin && e->name == "__set_lo8" && size <= 1 && !is_signed) return cast(size, is_signed, e->a[1]);
    if (e->kind == K::Intrin && e->name == "__set_lo16" && size <= 2 && !is_signed) return cast(size, is_signed, e->a[1]);
    if (!is_signed && e->kind == K::Bin && width(e) == 1 && size >= 1) return e;
    Expr c; c.kind = K::Cast; c.size = size; c.is_signed = is_signed; c.name = cast_name(size, is_signed); c.a = {e};
    return make(std::move(c));
}

EP un(const std::string& op, const EP& a) {
    if (a->kind == K::Const) {
        if (op == "-") return konst(~a->imm + 1, a->size);
        if (op == "~") return konst(~a->imm, a->size);
        if (op == "!") return konst(a->imm == 0 ? 1 : 0, 1);
    }
    if (op == "!" && a->kind == K::Bin) {
        static const std::map<std::string, std::string> inverse{{"==", "!="}, {"!=", "=="}, {"<", ">="}, {">=", "<"}, {"<=", ">"}, {">", "<="}};
        if (const auto it = inverse.find(a->name); it != inverse.end()) {
            Expr e; e.kind = K::Bin; e.name = it->second; e.a = a->a; return make(std::move(e));
        }
    }
    if (op == "!" && a->kind == K::Un && a->name == "!") return a->a[0];
    Expr e; e.kind = K::Un; e.name = op; e.a = {a}; return make(std::move(e));
}

EP bin(const std::string& op, EP l, EP r) {
    if (op == "-" && is_const(r)) return bin("+", std::move(l), konst(~r->imm + 1, r->size));
    if (is_const(l) && is_const(r)) {
        const auto a = l->imm, b = r->imm;
        if (op == "==") return konst(a == b, 1);
        if (op == "!=") return konst(a != b, 1);
        if (op == "<" && l->size == r->size) { /* signedness unknown for raw constants */ }
        if (op == "+") return konst(a + b);
        if (op == "*") return konst(a * b);
        if (op == "&") return konst(a & b);
        if (op == "|") return konst(a | b);
        if (op == "^") return konst(a ^ b);
        if (op == "<<" && b < 64) return konst(a << b);
        if (op == ">>" && b < 64) return konst(a >> b);
    }
    if (op == "+" || op == "*" || op == "&" || op == "|" || op == "^") {
        if (is_const(l) && !is_const(r)) std::swap(l, r); // constants on the right
    }
    if (op == "+" && !is_const(l) && !is_const(r)) {
        if (same(l, r)) return bin("*", l, konst(2));
        if (l->kind == K::Bin && l->name == "*" && is_const(l->a[1]) && same(l->a[0], r)) return bin("*", r, konst(l->a[1]->imm + 1));
        if (r->kind == K::Bin && r->name == "*" && is_const(r->a[1]) && same(r->a[0], l)) return bin("*", l, konst(r->a[1]->imm + 1));
    }
    if (op == "+") {
        if (l->kind == K::Frame && is_const(r)) return frame(frame_offset(l) + static_cast<std::int64_t>(r->imm));
        if (is_const(r) && r->imm == 0) return l;
        if (l->kind == K::Bin && l->name == "+" && is_const(l->a[1]) && is_const(r))
            return bin("+", l->a[0], konst(l->a[1]->imm + r->imm));
    }
    if (op == "-") {
        if (l->kind == K::Frame && r->kind == K::Frame) return konst(static_cast<std::uint64_t>(frame_offset(l) - frame_offset(r)));
    }
    if (op == "*" && is_const(r)) {
        if (r->imm == 1) return l;
        if (r->imm == 0) return konst(0);
    }
    if ((op == "|" || op == "^") && is_const(r) && r->imm == 0) return l;
    if (op == "&" && is_const(r) && r->imm == 0) return konst(0);
    if (op == "^" && same(l, r)) return konst(0);
    if ((op == "<<" || op == ">>") && is_const(r) && r->imm == 0) return l;
    Expr e; e.kind = K::Bin; e.name = op; e.a = {std::move(l), std::move(r)}; return make(std::move(e));
}

EP deref(int size, const EP& addr) {
    Expr e; e.kind = K::Deref; e.size = size; e.a = {addr}; return make(std::move(e));
}
EP tern(const EP& c, const EP& t, const EP& f) {
    if (is_const(c)) return c->imm ? t : f;
    Expr e; e.kind = K::Tern; e.a = {c, t, f}; return make(std::move(e));
}
EP intrin(const std::string& name, std::vector<EP> args) {
    Expr e; e.kind = K::Intrin; e.name = name; e.a = std::move(args); return make(std::move(e));
}
EP call_direct(const std::string& name, std::vector<EP> args) {
    Expr e; e.kind = K::Call; e.name = name; e.a = std::move(args); return make(std::move(e));
}
EP call_indirect(const EP& callee, std::vector<EP> args) {
    Expr e; e.kind = K::Call; e.imm = 1; e.a.push_back(callee);
    for (auto& arg : args) e.a.push_back(std::move(arg));
    return make(std::move(e));
}

EP with_fp(const EP& e, int fp) { Expr c = *e; c.fp = static_cast<std::uint8_t>(fp); return make(std::move(c)); }
EP fconst(std::uint64_t bits, int fp) {
    Expr e; e.kind = K::Const; e.imm = bits; e.size = fp == 1 ? 4 : 8; e.fp = static_cast<std::uint8_t>(fp); return make(std::move(e));
}
EP fconst_double(double value, int fp) {
    if (fp == 1) { const float f = static_cast<float>(value); std::uint32_t bits; std::memcpy(&bits, &f, 4); return fconst(bits, 1); }
    std::uint64_t bits; std::memcpy(&bits, &value, 8); return fconst(bits, fp);
}
double fconst_value(const EP& e) {
    if (e->fp == 1) { const std::uint32_t bits = static_cast<std::uint32_t>(e->imm); float f; std::memcpy(&f, &bits, 4); return f; }
    double d; const std::uint64_t bits = e->imm; std::memcpy(&d, &bits, 8); return d;
}
EP fbin(const std::string& op, const EP& l, const EP& r, int fp) {
    Expr e; e.kind = K::Bin; e.name = op; e.a = {l, r}; e.fp = static_cast<std::uint8_t>(fp); e.keep = true; return make(std::move(e));
}
EP fneg(const EP& v) {
    if (v->kind == K::Const && v->fp) return fconst_double(-fconst_value(v), v->fp);
    Expr e; e.kind = K::Un; e.name = "-"; e.a = {v}; e.fp = v->fp; e.keep = true; return make(std::move(e));
}
EP fintrin(const std::string& name, std::vector<EP> args, int fp) {
    Expr e; e.kind = K::Intrin; e.name = name; e.a = std::move(args); e.fp = static_cast<std::uint8_t>(fp); e.keep = true; return make(std::move(e));
}
// Conversion into a floating-point type: (double)x
EP fcast_to(int fp, const EP& v) {
    if (v->kind == K::Const && !v->fp) {
        const auto signed_value = static_cast<std::int64_t>(v->imm);
        return fconst_double(static_cast<double>(signed_value), fp);
    }
    Expr e; e.kind = K::Cast; e.name = fp == 1 ? "float" : fp == 2 ? "double" : "long double"; e.size = fp == 1 ? 4 : 8; e.fp = static_cast<std::uint8_t>(fp);
    e.keep = true; e.a = {v}; return make(std::move(e));
}
// Conversion of a floating-point value into an integer: (int32_t)x
EP fcast_from(int size, const EP& v) {
    Expr e; e.kind = K::Cast; e.size = size; e.is_signed = true; e.name = cast_name(size, true); e.keep = true; e.a = {v}; return make(std::move(e));
}
EP fderef(int size, const EP& addr, int fp) {
    Expr e; e.kind = K::Deref; e.size = size; e.a = {addr}; e.fp = static_cast<std::uint8_t>(fp); e.keep = true; return make(std::move(e));
}

EP rebuild(const EP& e, std::vector<EP> kids) {
    if (e->keep || e->fp) { Expr c = *e; c.a = std::move(kids); return make(std::move(c)); }
    switch (e->kind) {
    case K::Un: return un(e->name, kids[0]);
    case K::Bin: return bin(e->name, kids[0], kids[1]);
    case K::Deref: return deref(e->size, kids[0]);
    case K::Cast: return cast(e->size, e->is_signed, kids[0]);
    case K::Tern: return tern(kids[0], kids[1], kids[2]);
    default: { Expr c = *e; c.a = std::move(kids); return make(std::move(c)); }
    }
}

EP substitute(const EP& e, const std::unordered_map<std::string, EP>& map) {
    if (e->kind == K::Var) {
        if (e->temp) if (const auto it = map.find(e->name); it != map.end()) return it->second;
        return e;
    }
    if (e->a.empty()) return e;
    std::vector<EP> kids; kids.reserve(e->a.size());
    bool changed = false;
    for (const auto& child : e->a) { auto n = substitute(child, map); changed |= (n != child); kids.push_back(std::move(n)); }
    return changed ? rebuild(e, std::move(kids)) : e;
}

void visit(const EP& e, const std::function<void(const EP&)>& fn) {
    fn(e);
    for (const auto& child : e->a) visit(child, fn);
}
bool contains_kind(const EP& e, K kind) {
    bool found = false;
    visit(e, [&](const EP& n) { if (n->kind == kind) found = true; });
    return found;
}
bool has_memory_or_call(const EP& e) {
    bool found = false;
    visit(e, [&](const EP& n) { if (n->kind == K::Deref || n->kind == K::Call) found = true; });
    return found;
}
int node_count(const EP& e) { int n = 1; for (const auto& c : e->a) n += node_count(c); return n; }

// ---------------------------------------------------------------------------
// Registers and operands
// ---------------------------------------------------------------------------
const char* const kGp64[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
constexpr int kRax = 0, kRcx = 1, kRdx = 2, kRbx = 3, kRsp = 4, kRbp = 5, kRsi = 6, kRdi = 7;
constexpr int kXmmBase = 16;
// AArch64 mode: x0..x30 are indices 0..30 and sp is 31 (the x86 register tables below are not used).
thread_local bool g_arm = false;
inline int xmm_base() { return g_arm ? 64 : 16; }
constexpr int kArmSp = 31, kArmFp = 29, kArmLr = 30;
constexpr int kRegCount = 32;

std::string canonical_name(int index) {
    if (g_arm) return index == kArmSp ? std::string("sp") : "x" + std::to_string(index);
    if (index < 16) return kGp64[index];
    return "xmm" + std::to_string(index - kXmmBase);
}

struct RegRef { int index{-1}; int size{8}; bool high{false}; };

std::optional<RegRef> parse_register(const std::string& raw) {
    static const std::unordered_map<std::string, RegRef> table = [] {
        std::unordered_map<std::string, RegRef> m;
        const char* r32[8] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
        const char* r16[8] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
        const char* r8[8] = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"};
        const char* r8h[4] = {"ah", "ch", "dh", "bh"};
        for (int i = 0; i < 16; ++i) m[kGp64[i]] = {i, 8, false};
        for (int i = 0; i < 8; ++i) { m[r32[i]] = {i, 4, false}; m[r16[i]] = {i, 2, false}; m[r8[i]] = {i, 1, false}; }
        for (int i = 0; i < 4; ++i) m[r8h[i]] = {i, 1, true};
        for (int i = 8; i < 16; ++i) {
            const std::string base = "r" + std::to_string(i);
            m[base + "d"] = {i, 4, false}; m[base + "w"] = {i, 2, false}; m[base + "b"] = {i, 1, false};
        }
        for (int i = 0; i < 16; ++i) {
            m["xmm" + std::to_string(i)] = {kXmmBase + i, 16, false};
            m["ymm" + std::to_string(i)] = {kXmmBase + i, 32, false};
        }
        return m;
    }();
    const auto it = table.find(raw);
    if (it == table.end()) return std::nullopt;
    return it->second;
}

struct MemRef {
    int size{0};
    int base{-1};
    int index{-1};
    int scale{1};
    std::int64_t disp{0};
    bool rip{false};
    std::string segment;
};

struct Operand {
    enum class T { None, Reg, Imm, Mem } type{T::None};
    RegRef reg;
    std::int64_t imm{0};
    MemRef mem;
};

std::string trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t"); if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(" \t"); return s.substr(b, e - b + 1);
}

std::optional<std::int64_t> parse_number(std::string s) {
    s = trim(s);
    if (s.empty()) return std::nullopt;
    bool negative = false;
    if (s[0] == '-') { negative = true; s = trim(s.substr(1)); }
    else if (s[0] == '+') s = trim(s.substr(1));
    if (s.empty()) return std::nullopt;
    try {
        std::size_t used = 0;
        const unsigned long long value = std::stoull(s, &used, 0);
        if (used != s.size()) return std::nullopt;
        return negative ? -static_cast<std::int64_t>(value) : static_cast<std::int64_t>(value);
    } catch (...) { return std::nullopt; }
}

Operand parse_operand(const std::string& text_in) {
    Operand op;
    std::string text = trim(text_in);
    if (text.empty()) return op;
    const auto bracket = text.find('[');
    if (bracket != std::string::npos) {
        op.type = Operand::T::Mem;
        std::string prefix = text.substr(0, bracket);
        const auto colon = prefix.find(':');
        if (colon != std::string::npos) { op.mem.segment = trim(prefix.substr(prefix.rfind(' ', colon) == std::string::npos ? 0 : prefix.rfind(' ', colon) + 1, colon - (prefix.rfind(' ', colon) == std::string::npos ? 0 : prefix.rfind(' ', colon) + 1))); prefix = prefix.substr(0, colon); }
        if (prefix.find("xmmword") != std::string::npos) op.mem.size = 16;
        else if (prefix.find("ymmword") != std::string::npos) op.mem.size = 32;
        else if (prefix.find("qword") != std::string::npos) op.mem.size = 8;
        else if (prefix.find("dword") != std::string::npos) op.mem.size = 4;
        else if (prefix.find("word") != std::string::npos) op.mem.size = 2;
        else if (prefix.find("tbyte") != std::string::npos) op.mem.size = 10;
        else if (prefix.find("byte") != std::string::npos) op.mem.size = 1;
        const auto close = text.find(']', bracket);
        const std::string inner = text.substr(bracket + 1, close == std::string::npos ? std::string::npos : close - bracket - 1);
        // Split into signed terms.
        std::vector<std::pair<int, std::string>> terms; // sign, text
        std::string current; int sign = 1;
        const auto flush = [&] { if (!trim(current).empty()) terms.push_back({sign, trim(current)}); current.clear(); };
        for (const char c : inner) {
            if (c == '+') { flush(); sign = 1; }
            else if (c == '-') { flush(); sign = -1; }
            else current.push_back(c);
        }
        flush();
        for (const auto& [term_sign, term] : terms) {
            const auto star = term.find('*');
            if (star != std::string::npos) {
                const auto reg = parse_register(trim(term.substr(0, star)));
                const auto scale = parse_number(term.substr(star + 1));
                if (reg && scale) { op.mem.index = reg->index; op.mem.scale = static_cast<int>(*scale); }
                continue;
            }
            if (term == "rip") { op.mem.rip = true; continue; }
            if (const auto reg = parse_register(term)) {
                if (op.mem.base < 0) op.mem.base = reg->index; else { op.mem.index = reg->index; op.mem.scale = 1; }
                continue;
            }
            if (const auto number = parse_number(term)) op.mem.disp += term_sign * *number;
        }
        return op;
    }
    if (const auto reg = parse_register(text)) { op.type = Operand::T::Reg; op.reg = *reg; return op; }
    if (const auto number = parse_number(text)) { op.type = Operand::T::Imm; op.imm = *number; return op; }
    return op;
}

std::vector<std::string> split_operands(const std::string& text) {
    std::vector<std::string> parts; std::string current; int depth = 0;
    for (const char c : text) {
        if (c == '[') ++depth; else if (c == ']') --depth;
        if (c == ',' && depth == 0) { parts.push_back(current); current.clear(); } else current.push_back(c);
    }
    if (!trim(current).empty()) parts.push_back(current);
    return parts;
}

// ---------------------------------------------------------------------------
// AArch64 operands
// ---------------------------------------------------------------------------
struct ArmOp {
    enum class T { None, Reg, Imm, Mem, Text, Fp } type{T::None};
    int fp_size{8};           // Fp: scalar width in bytes (b1 h2 s4 d8 q16); vectors count as 16
    bool vector{false};
    int index{-1};            // Reg / Fp
    int size{8};              // Reg: 4 (wN) or 8 (xN)
    bool zr{false};           // xzr / wzr
    std::int64_t imm{0};      // Imm
    std::string modifier;     // lsl / lsr / asr / ror / uxtw / sxtw / ...
    int amount{0};
    int base{-1};             // Mem
    int idx{-1};
    int idx_size{8};
    std::int64_t disp{0};
    bool pre{false}, post{false};
    std::string text;
};

bool arm_register(const std::string& raw, ArmOp& op) {
    std::string s = trim(raw);
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (s == "sp" || s == "wsp") { op.type = ArmOp::T::Reg; op.index = kArmSp; op.size = s == "sp" ? 8 : 4; return true; }
    if (s == "xzr" || s == "wzr") { op.type = ArmOp::T::Reg; op.zr = true; op.size = s == "xzr" ? 8 : 4; return true; }
    if (s == "fp") { op.type = ArmOp::T::Reg; op.index = kArmFp; op.size = 8; return true; }
    if (s == "lr") { op.type = ArmOp::T::Reg; op.index = kArmLr; op.size = 8; return true; }
    if (s.size() >= 2 && (s[0] == 'x' || s[0] == 'w') && std::all_of(s.begin() + 1, s.end(), [](unsigned char c) { return std::isdigit(c); })) {
        const int n = std::stoi(s.substr(1));
        if (n > 30) return false;
        op.type = ArmOp::T::Reg; op.index = n; op.size = s[0] == 'x' ? 8 : 4; return true;
    }
    return false;
}

bool arm_modifier(const std::string& raw, ArmOp& target) {
    std::string s = trim(raw);
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    static const char* names[] = {"lsl", "lsr", "asr", "ror", "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx", "msl"};
    for (const char* name : names) {
        const std::string n = name;
        if (s.rfind(n, 0) != 0) continue;
        target.modifier = n; target.amount = 0;
        const auto hash = s.find('#');
        if (hash != std::string::npos) { if (const auto v = parse_number(s.substr(hash + 1))) target.amount = static_cast<int>(*v); }
        return true;
    }
    return false;
}

ArmOp arm_parse_operand(const std::string& text_in) {
    ArmOp op; op.text = trim(text_in);
    std::string text = op.text;
    if (text.empty()) return op;
    const auto bracket = text.find('[');
    if (bracket != std::string::npos) {
        op.type = ArmOp::T::Mem;
        const auto close = text.find(']', bracket);
        const std::string inner = text.substr(bracket + 1, close == std::string::npos ? std::string::npos : close - bracket - 1);
        const auto parts = split_operands(inner);
        ArmOp last_reg;
        for (std::size_t i = 0; i < parts.size(); ++i) {
            ArmOp reg;
            if (arm_register(parts[i], reg)) {
                if (i == 0) op.base = reg.zr ? -1 : reg.index; else { op.idx = reg.index; op.idx_size = reg.size; }
            } else if (arm_modifier(parts[i], last_reg)) {
                op.modifier = last_reg.modifier; op.amount = last_reg.amount;
            } else {
                std::string number = trim(parts[i]);
                if (!number.empty() && number[0] == '#') number.erase(number.begin());
                if (const auto v = parse_number(number)) op.disp = *v;
            }
        }
        if (close != std::string::npos && close + 1 < text.size() && text[close + 1] == '!') op.pre = true;
        return op;
    }
    ArmOp reg;
    if (arm_register(text, reg)) return reg;
    {
        std::string low = text;
        for (auto& c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (low.size() >= 2 && std::string("bhsdqv").find(low[0]) != std::string::npos && std::isdigit(static_cast<unsigned char>(low[1]))) {
            std::size_t end = 1; while (end < low.size() && std::isdigit(static_cast<unsigned char>(low[end]))) ++end;
            if (end == low.size() || low[end] == '.' || low[end] == '[') {
                const int n = std::stoi(low.substr(1, end - 1));
                if (n < 32) {
                    op.type = ArmOp::T::Fp; op.index = n; op.vector = low[0] == 'v';
                    op.fp_size = low[0] == 'b' ? 1 : low[0] == 'h' ? 2 : low[0] == 's' ? 4 : low[0] == 'd' ? 8 : 16;
                    return op;
                }
            }
        }
    }
    std::string number = text;
    if (!number.empty() && number[0] == '#') number.erase(number.begin());
    if (const auto v = parse_number(number)) { op.type = ArmOp::T::Imm; op.imm = *v; return op; }
    op.type = ArmOp::T::Text;
    return op;
}

// Parses an operand list; shift/extend modifiers attach to the previous operand and a trailing
// immediate after a memory operand is a post-index displacement.
std::vector<ArmOp> arm_parse_operands(const std::string& text) {
    std::vector<ArmOp> ops;
    for (const auto& part : split_operands(text)) {
        ArmOp modifier;
        if (!ops.empty() && arm_modifier(part, modifier)) { ops.back().modifier = modifier.modifier; ops.back().amount = modifier.amount; continue; }
        ops.push_back(arm_parse_operand(part));
    }
    for (std::size_t i = 0; i + 1 < ops.size(); ++i)
        if (ops[i].type == ArmOp::T::Mem && !ops[i].pre && ops[i + 1].type == ArmOp::T::Imm) { ops[i].post = true; ops[i].disp = ops[i + 1].imm; ops.erase(ops.begin() + i + 1); break; }
    return ops;
}

std::optional<std::uint64_t> arm_branch_target(const Instruction& ins) {
    std::string last = ins.operands;
    if (const auto p = last.rfind(','); p != std::string::npos) last = last.substr(p + 1);
    last = trim(last);
    if (!last.empty() && last[0] == '#') last.erase(last.begin());
    if (last.find('[') != std::string::npos) return std::nullopt;
    if (const auto v = parse_number(last)) return static_cast<std::uint64_t>(*v);
    return std::nullopt;
}

bool arm_is_cond_branch(const std::string& m) {
    return m.rfind("b.", 0) == 0 || m == "cbz" || m == "cbnz" || m == "tbz" || m == "tbnz";
}
bool arm_is_ender(const std::string& m) {
    return m == "ret" || m == "br" || m == "brk" || m == "udf" || m == "eret" || m == "hlt" || m == "retaa" || m == "retab" || m == "braa" || m == "brab";
}

// Registers written by a typical AArch64 instruction (used for the argument-register analysis).
int arm_dest_register(const Instruction& ins) {
    static const std::set<std::string> writers{
        "mov", "movz", "movn", "movk", "mvn", "add", "adds", "sub", "subs", "and", "ands", "orr", "orn", "eor", "eon", "bic", "lsl", "lsr", "asr", "ror",
        "mul", "madd", "msub", "mneg", "smull", "umull", "smulh", "umulh", "sdiv", "udiv", "neg", "negs", "sxtw", "sxth", "sxtb", "uxtb", "uxth", "ubfx", "sbfx",
        "ubfiz", "sbfiz", "bfi", "bfxil", "ubfm", "sbfm", "csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc", "cinv", "cneg", "adrp", "adr",
        "ldr", "ldrb", "ldrh", "ldrsw", "ldrsb", "ldrsh", "ldur", "ldurb", "ldurh", "ldursw", "ldar", "ldaxr", "ldxr", "rev", "rbit", "clz", "extr"};
    if (!writers.contains(ins.mnemonic)) return -1;
    const auto ops = split_operands(ins.operands);
    if (ops.empty()) return -1;
    ArmOp reg;
    return arm_register(ops[0], reg) && !reg.zr ? reg.index : -1;
}

// ---------------------------------------------------------------------------
// Control-flow data
// ---------------------------------------------------------------------------
struct Stmt {
    enum class T { Assign, Store, Eval } type{T::Eval};
    EP lhs;               // Assign: Var
    EP addr;              // Store: address expression
    int size{8};          // Store width
    EP value;             // Assign rhs / Store value / Eval expression
    std::uint64_t source{0};
};

struct Move { EP lhs; EP rhs; };

struct Terminator {
    enum class T { Fall, Jmp, Cond, Ret, IndirectJmp, NoReturn, Switch } type{T::Fall};
    std::vector<std::uint64_t> cases;     // Switch: target address per table entry
    std::vector<int> case_blocks;         // Switch: block per table entry (-1 when unresolved)
    std::uint64_t default_target{0};      // Switch: address the range check jumps to
    int default_block{-1};
    EP fp_return;                         // Ret: value of xmm0 / st(0) at the return
    EP cond;                       // Cond: true -> `taken`
    EP value;                      // Ret: value (may be null), IndirectJmp: target
    std::uint64_t taken{0};        // Cond / Jmp target address
    std::uint64_t fallthrough{0};
    int taken_block{-1};
    int fall_block{-1};
    bool external_taken{false};    // Jump leaves the function
    std::uint64_t source{0};
};

struct Block {
    std::uint64_t address{0};
    std::size_t first{0}, last{0}; // [first, last) in the instruction vector
    std::vector<Stmt> stmts;
    std::vector<Move> moves;
    Terminator term;
    std::vector<int> succ, pred;
    // Frame tracking on entry.
    EP entry_rsp, entry_rbp;
    bool lifted{false};
    std::uint32_t arg_mask_in{0};
};

struct Flags {
    enum class T { None, Cmp, Test, Result, Chain } type{T::None};
    EP a, b;
    int size{8};
    bool fp{false};                       // floating-point compare (fcmp)
    std::shared_ptr<const Flags> prev;    // Chain: flags before a ccmp / ccmn
    std::string prev_cc;                  // Chain: condition under which the new compare applies
    int nzcv{0};                          // Chain: flags value when the condition is false
};

// Truth of an x86-style condition name for a literal NZCV nibble (used by ccmp).
bool nzcv_condition(int nzcv, const std::string& cc) {
    const bool n = nzcv & 8, z = nzcv & 4, c = nzcv & 2, v = nzcv & 1;
    if (cc == "e") return z;
    if (cc == "ne") return !z;
    if (cc == "ae") return c;
    if (cc == "b") return !c;
    if (cc == "s") return n;
    if (cc == "ns") return !n;
    if (cc == "a") return c && !z;
    if (cc == "be") return !(c && !z);
    if (cc == "ge") return n == v;
    if (cc == "l") return n != v;
    if (cc == "g") return !z && n == v;
    if (cc == "le") return z || n != v;
    if (cc == "o") return v;
    if (cc == "no") return !v;
    return false;
}

std::string arm_cc_to_x86(const std::string& cc) {
    static const std::map<std::string, std::string> names{{"eq", "e"}, {"ne", "ne"}, {"hs", "ae"}, {"cs", "ae"}, {"lo", "b"}, {"cc", "b"}, {"mi", "s"},
        {"pl", "ns"}, {"hi", "a"}, {"ls", "be"}, {"ge", "ge"}, {"lt", "l"}, {"gt", "g"}, {"le", "le"}, {"vs", "o"}, {"vc", "no"}};
    const auto it = names.find(cc);
    return it == names.end() ? cc : it->second;
}

bool is_conditional_jump(const std::string& m) {
    return m.size() >= 2 && m[0] == 'j' && m != "jmp";
}

std::string condition_code(const std::string& mnemonic, std::size_t prefix) {
    std::string cc = mnemonic.substr(prefix);
    static const std::map<std::string, std::string> alias{
        {"z", "e"}, {"nz", "ne"}, {"c", "b"}, {"nc", "ae"}, {"nae", "b"}, {"nb", "ae"}, {"na", "be"}, {"nbe", "a"},
        {"nge", "l"}, {"nl", "ge"}, {"ng", "le"}, {"nle", "g"}, {"pe", "p"}, {"po", "np"}};
    if (const auto it = alias.find(cc); it != alias.end()) cc = it->second;
    return cc;
}

const std::set<std::string>& noreturn_names() {
    static const std::set<std::string> names{
        "exit", "_exit", "_Exit", "abort", "quick_exit", "ExitProcess", "ExitThread", "TerminateProcess_noreturn",
        "__fastfail", "longjmp", "_longjmp", "siglongjmp", "__assert_fail", "__stack_chk_fail", "_CxxThrowException",
        "__cxa_throw", "__cxa_rethrow", "terminate", "std::terminate", "pthread_exit", "RtlExitUserProcess",
        "__chk_fail", "__fortify_fail", "_invalid_parameter_noinfo_noreturn", "__security_check_cookie_fail",
        "__report_gsfailure", "RaiseFailFastException", "abort_message", "__assert", "_wassert", "__imp_ExitProcess"};
    return names;
}

const std::map<std::string, int>& known_arg_counts() {
    static const std::map<std::string, int> table{
        {"puts", 1}, {"putchar", 1}, {"malloc", 1}, {"free", 1}, {"calloc", 2}, {"realloc", 2}, {"strlen", 1}, {"strcmp", 2},
        {"strncmp", 3}, {"strcpy", 2}, {"strncpy", 3}, {"strcat", 2}, {"strchr", 2}, {"strstr", 2}, {"memcpy", 3},
        {"memmove", 3}, {"memset", 3}, {"memcmp", 3}, {"fopen", 2}, {"fclose", 1}, {"fread", 4}, {"fwrite", 4},
        {"fgets", 3}, {"fputs", 2}, {"atoi", 1}, {"exit", 1}, {"_exit", 1}, {"abort", 0}, {"getenv", 1}, {"open", 2},
        {"close", 1}, {"read", 3}, {"write", 3}, {"mmap", 6}, {"munmap", 2}, {"sleep", 1}, {"usleep", 1},
        {"ExitProcess", 1}, {"ExitThread", 1}, {"GetLastError", 0}, {"SetLastError", 1}, {"GetModuleHandleA", 1},
        {"GetModuleHandleW", 1}, {"GetProcAddress", 2}, {"LoadLibraryA", 1}, {"LoadLibraryW", 1}, {"FreeLibrary", 1},
        {"VirtualAlloc", 4}, {"VirtualFree", 3}, {"VirtualProtect", 4}, {"HeapAlloc", 3}, {"HeapFree", 3},
        {"GetProcessHeap", 0}, {"CloseHandle", 1}, {"CreateFileA", 7}, {"CreateFileW", 7}, {"ReadFile", 5},
        {"WriteFile", 5}, {"GetFileSize", 2}, {"MessageBoxA", 4}, {"MessageBoxW", 4}, {"Sleep", 1},
        {"GetCurrentProcess", 0}, {"GetCurrentProcessId", 0}, {"GetCurrentThreadId", 0}, {"IsDebuggerPresent", 0},
        {"CreateThread", 6}, {"WaitForSingleObject", 2}, {"GetTickCount", 0}, {"QueryPerformanceCounter", 1},
        {"lstrlenA", 1}, {"lstrlenW", 1}, {"GetStdHandle", 1}, {"WriteConsoleA", 5}, {"WriteConsoleW", 5},
        {"RegOpenKeyExA", 5}, {"RegOpenKeyExW", 5}, {"RegCloseKey", 1}, {"WSAStartup", 2}, {"socket", 3}, {"connect", 3},
        {"send", 4}, {"recv", 4}, {"closesocket", 1}, {"__stack_chk_fail", 0}, {"_CxxThrowException", 2}};
    return table;
}

std::string strip_import_decoration(std::string name) {
    if (const auto bang = name.rfind('!'); bang != std::string::npos) name = name.substr(bang + 1);
    if (name.rfind("__imp_", 0) == 0) name = name.substr(6);
    if (name.rfind("_imp__", 0) == 0) name = name.substr(6);
    if (const auto at = name.find('@'); at != std::string::npos && at > 0 && name[0] != '?') name = name.substr(0, at);
    return name;
}

// ---------------------------------------------------------------------------
// Decompiler context
// ---------------------------------------------------------------------------
struct SwitchInfo {
    std::uint64_t jmp{0}, mov{0}, add{0}, lea{0};
    int idx_reg{-1};
    std::vector<std::uint64_t> targets;
    std::uint64_t default_target{0};
};

struct Ctx {
    const BinaryImage& image;
    const DecompilerOptions& options;
    std::vector<Instruction> insns;
    std::unordered_map<std::uint64_t, std::size_t> insn_at;
    std::vector<Block> blocks;
    std::unordered_map<std::uint64_t, int> block_at;
    std::uint64_t start{0};
    int next_temp{1};
    int next_var{1};
    std::set<std::string> used_regs;       // canonical registers used as variables
    std::map<std::int64_t, int> frame_sizes; // frame slot -> max access width
    std::set<std::int64_t> frame_reads;
    bool frame_escape{false};
    bool saw_return_value{false};
    bool saw_rax_write{false};
    std::set<std::string> extra_vars;      // v<N> temporaries that survived
    std::vector<std::string> arg_regs;
    std::set<int> callee_saved;
    std::set<int> caller_saved;
    std::map<std::int64_t, int> param_slot;  // stack slot -> parameter number (1-based)
    std::map<int, int> param_size;           // parameter number -> width in bytes
    std::map<std::uint64_t, SwitchInfo> switches;   // keyed by the `jmp reg` address
    std::map<std::uint64_t, int> switch_mov;        // address of the table load -> index register
    std::set<std::uint64_t> switch_skip;            // table-address arithmetic that is not real program logic
    int return_fp{0};                                // 1 float, 2 double, 3 long double when the function returns in xmm0 / st(0)
};

bool is_data_address(const BinaryImage& image, std::uint64_t address) {
    if (address < image.image_base) return false;
    const auto rva = address - image.image_base;
    for (const auto& section : image.sections) {
        const auto extent = static_cast<std::uint64_t>((std::max)(section.virtual_size, section.raw_size));
        if (rva >= section.rva && rva - section.rva < extent) return true;
    }
    return false;
}

bool is_code_address(const BinaryImage& image, std::uint64_t address) {
    if (address < image.image_base) return false;
    const auto rva = address - image.image_base;
    for (const auto& section : image.sections) {
        const auto extent = static_cast<std::uint64_t>((std::max)(section.virtual_size, section.raw_size));
        if (rva >= section.rva && rva - section.rva < extent) return (section.characteristics & 0x20000000u) != 0;
    }
    return false;
}

std::optional<std::string> read_c_string(const BinaryImage& image, std::uint64_t address) {
    const auto offset = image.va_to_file_offset(address);
    if (!offset) return std::nullopt;
    std::string text;
    for (std::size_t i = *offset; i < image.bytes.size() && text.size() < 200; ++i) {
        const auto c = image.bytes[i];
        if (c == 0) return text.size() >= 3 ? std::optional<std::string>(text) : std::nullopt;
        if (c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7F)) text.push_back(static_cast<char>(c));
        else return std::nullopt;
    }
    return std::nullopt;
}

std::optional<std::string> read_wide_string(const BinaryImage& image, std::uint64_t address) {
    const auto offset = image.va_to_file_offset(address);
    if (!offset) return std::nullopt;
    std::string text;
    for (std::size_t i = *offset; i + 1 < image.bytes.size() && text.size() < 200; i += 2) {
        const auto lo = image.bytes[i], hi = image.bytes[i + 1];
        if (lo == 0 && hi == 0) return text.size() >= 3 ? std::optional<std::string>(text) : std::nullopt;
        if (hi == 0 && (lo == '\n' || lo == '\r' || lo == '\t' || (lo >= 0x20 && lo < 0x7F))) text.push_back(static_cast<char>(lo));
        else return std::nullopt;
    }
    return std::nullopt;
}

std::string escape_c(const std::string& s) {
    std::string out;
    for (const char c : s) {
        switch (c) {
        case '\n': out += "\\n"; break; case '\r': out += "\\r"; break; case '\t': out += "\\t"; break;
        case '"': out += "\\\""; break; case '\\': out += "\\\\"; break;
        default: out.push_back(c);
        }
    }
    return out;
}

std::string hex(std::uint64_t v) { char b[32]; std::snprintf(b, sizeof b, "0x%llX", static_cast<unsigned long long>(v)); return b; }

// ---------------------------------------------------------------------------
// Lifting
// ---------------------------------------------------------------------------
class Lifter {
public:
    Lifter(Ctx& cx, Block& block, int index) : cx_(cx), block_(block), index_(index) {
        for (int i = 0; i < kRegCount; ++i) cur_[i] = var(canonical_name(i), i >= xmm_base() ? 16 : 8);
        if (g_arm) {
            cur_[kArmSp] = block.entry_rsp ? block.entry_rsp : frame(0);
            cur_[kArmFp] = block.entry_rbp ? block.entry_rbp : var("x29");
            return;
        }
        cur_[kRsp] = block.entry_rsp ? block.entry_rsp : frame(0);
        cur_[kRbp] = block.entry_rbp ? block.entry_rbp : var("rbp");
    }

    void run() {
        for (std::size_t i = block_.first; i < block_.last; ++i) {
            if (done_) break;
            lift(cx_.insns[i], i);
        }
        finish();
    }

private:
    Ctx& cx_;
    Block& block_;
    int index_;
    std::array<EP, kRegCount> cur_;
    std::array<bool, kRegCount> dirty_{};
    Flags flags_;
    bool done_{false};
    bool terminated_{false};
    std::uint64_t current_address_{0};
    std::uint32_t defined_since_call_{0};
    std::set<int> restored_;

    EP new_temp(const EP& value, int size = 8) {
        const std::string name = "t" + std::to_string(cx_.next_temp++);
        auto v = var(name, size, true);
        Stmt s; s.type = Stmt::T::Assign; s.lhs = v; s.value = value; s.source = current_address_;
        block_.stmts.push_back(std::move(s));
        return v;
    }
    static bool simple(const EP& e) {
        return e->kind == K::Const || e->kind == K::Var || e->kind == K::Frame;
    }
    EP fp_temp(const EP& value, int fp) {
        const std::string name = "t" + std::to_string(cx_.next_temp++);
        EP v = with_fp(var(name, 8, true), fp);
        Stmt s; s.type = Stmt::T::Assign; s.lhs = v; s.value = value; s.source = current_address_;
        block_.stmts.push_back(std::move(s));
        return v;
    }
    EP materialize(const EP& value, int size = 8) {
        if (simple(value)) return value;
        return new_temp(value, (std::max)(width(value), 1) > 8 ? 8 : (width(value) ? width(value) : size));
    }
    void emit_store(int size, const EP& addr, const EP& value) {
        Stmt s; s.type = Stmt::T::Store; s.size = size; s.addr = addr; s.value = value; s.source = current_address_;
        block_.stmts.push_back(std::move(s));
        if (addr->kind == K::Frame) {
            auto& w = cx_.frame_sizes[frame_offset(addr)];
            w = (std::max)(w, size);
        }
    }
    void emit_eval(const EP& value) {
        Stmt s; s.type = Stmt::T::Eval; s.value = value; s.source = current_address_;
        block_.stmts.push_back(std::move(s));
    }

    // ---- registers
    EP read_reg(const RegRef& r) {
        EP base = cur_[r.index];
        if (r.index >= xmm_base()) return base;
        if (r.size == 8) return base;
        if (r.high) return cast(1, false, bin(">>", base, konst(8)));
        return cast(r.size, false, base);
    }
    void write_full(int index, const EP& value) {
        if (index == kRax) cx_.saw_rax_write = true;
        if (g_arm) {
            cur_[index] = value; dirty_[index] = true;
            cx_.used_regs.insert(canonical_name(index));
            defined_since_call_ |= (1u << index);
            return;
        }
        if (index == kRsp || index == kRbp) {
            if (value->kind == K::Frame) { cur_[index] = value; dirty_[index] = false; return; }
        }
        cur_[index] = value; dirty_[index] = true;
        if (index < 16) cx_.used_regs.insert(kGp64[index]);
        if (index < 16) defined_since_call_ |= (1u << index);
        else if (index >= xmm_base() && index < xmm_base() + 16) fp_defined_since_call_ |= (1u << (index - xmm_base()));
    }
    void write_reg(const RegRef& r, const EP& value) {
        if (r.index >= xmm_base()) { write_full(r.index, simple(value) ? value : materialize(value, 16)); return; }
        if (r.size == 8) { write_full(r.index, simple(value) ? value : materialize(value)); return; }
        if (r.size == 4) { const auto v = cast(4, false, value); write_full(r.index, simple(v) ? v : materialize(v, 4)); return; }
        const EP old = cur_[r.index];
        if (old->kind == K::Const && old->imm == 0 && !r.high) {
            write_full(r.index, materialize(cast(r.size, false, value), r.size)); return;
        }
        EP combined;
        if (r.high) combined = intrin("__set_hi8", {old, value});
        else if (r.size == 1) combined = intrin("__set_lo8", {old, value});
        else combined = intrin("__set_lo16", {old, value});
        write_full(r.index, materialize(combined));
    }

    // ---- memory
    EP address_of(const MemRef& m, std::uint64_t next_address) {
        if (m.rip) return konst(next_address + static_cast<std::uint64_t>(m.disp));
        EP addr;
        if (m.base >= 0) addr = cur_[m.base];
        if (m.index >= 0) {
            EP index = cur_[m.index];
            if (m.scale != 1) index = bin("*", index, konst(static_cast<std::uint64_t>(m.scale)));
            addr = addr ? bin("+", addr, index) : index;
        }
        if (!addr) return konst(static_cast<std::uint64_t>(m.disp));
        if (m.disp) addr = bin("+", addr, konst(static_cast<std::uint64_t>(m.disp)));
        if (!m.segment.empty() && (m.segment == "fs" || m.segment == "gs")) addr = intrin("__" + m.segment + "base", {addr});
        return addr;
    }
    EP load(const MemRef& m, int size, std::uint64_t next) {
        const EP addr = address_of(m, next);
        if (addr->kind == K::Frame) cx_.frame_reads.insert(frame_offset(addr));
        return new_temp(deref(size, addr), size);
    }

    int operand_size(const Operand& a, const Operand& b) {
        if (a.type == Operand::T::Reg) return a.reg.size;
        if (b.type == Operand::T::Reg) return b.reg.size;
        if (a.type == Operand::T::Mem && a.mem.size) return a.mem.size;
        if (b.type == Operand::T::Mem && b.mem.size) return b.mem.size;
        return 8;
    }
    EP read_operand(const Operand& op, int size, std::uint64_t next) {
        switch (op.type) {
        case Operand::T::Reg: return read_reg(op.reg);
        case Operand::T::Imm: {
            auto v = static_cast<std::uint64_t>(op.imm);
            if (size < 8) v &= mask_for(size);
            return konst(v, size);
        }
        case Operand::T::Mem: return load(op.mem, op.mem.size ? op.mem.size : size, next);
        default: return konst(0);
        }
    }
    void write_operand(const Operand& op, const EP& value, int size, std::uint64_t next) {
        if (op.type == Operand::T::Reg) { write_reg(op.reg, value); return; }
        if (op.type == Operand::T::Mem) {
            const int s = op.mem.size ? op.mem.size : size;
            const EP addr = address_of(op.mem, next);
            emit_store(s, addr, s < 8 ? cast(s, false, value) : value);
        }
    }

    // ---- flags / conditions
    void set_flags_cmp(const EP& a, const EP& b, int size) { flags_ = {Flags::T::Cmp, a, b, size}; }
    void set_flags_test(const EP& a, const EP& b, int size) { flags_ = {Flags::T::Test, a, b, size}; }
    void set_flags_result(const EP& r, int size) { flags_ = {Flags::T::Result, r, nullptr, size}; }

    static EP signed_of(const EP& e, int size) { return cast(size, true, e); }
    static EP unsigned_of(const EP& e, int size) { return size >= 8 ? e : cast(size, false, e); }

    EP make_condition(const std::string& cc) { return make_condition_for(flags_, cc); }

    EP make_condition_for(const Flags& flags_, const std::string& cc) {
        if (flags_.type == Flags::T::Chain && flags_.prev) {
            // ccmp: the second compare only counts when the first condition held, otherwise the literal NZCV applies.
            const EP before = make_condition_for(*flags_.prev, flags_.prev_cc);
            Flags own = flags_; own.type = Flags::T::Cmp; own.prev = nullptr;
            const EP after = make_condition_for(own, cc);
            return nzcv_condition(flags_.nzcv, cc) ? bin("||", un("!", before), after) : bin("&&", before, after);
        }
        if (flags_.type == Flags::T::Cmp && flags_.fp) {
            static const std::map<std::string, std::string> fp_ops{{"e", "=="}, {"ne", "!="}, {"l", "<"}, {"b", "<"}, {"s", "<"}, {"ge", ">="}, {"ae", ">="}, {"ns", ">="},
                {"le", "<="}, {"be", "<="}, {"g", ">"}, {"a", ">"}};
            if (const auto it = fp_ops.find(cc); it != fp_ops.end()) return fbin(it->second, flags_.a, flags_.b, 0);
            if (cc == "p" || cc == "np") {
                const EP unordered = same(flags_.a, flags_.b) ? fbin("!=", flags_.a, flags_.a, 0) : fintrin("__isunordered", {flags_.a, flags_.b}, 0);
                return cc == "p" ? unordered : un("!", unordered);
            }
        }
        const auto zero = konst(0);
        const int size = flags_.size;
        const auto flag_var = [&](const std::string& n) { return var("__" + n, 1); };
        if (flags_.type == Flags::T::Cmp) {
            const EP a = flags_.a, b = flags_.b;
            if (cc == "e") return bin("==", a, b);
            if (cc == "ne") return bin("!=", a, b);
            if (cc == "l") return bin("<", signed_of(a, size), signed_of(b, size));
            if (cc == "ge") return bin(">=", signed_of(a, size), signed_of(b, size));
            if (cc == "le") return bin("<=", signed_of(a, size), signed_of(b, size));
            if (cc == "g") return bin(">", signed_of(a, size), signed_of(b, size));
            if (cc == "b") return bin("<", unsigned_of(a, size), unsigned_of(b, size));
            if (cc == "ae") return bin(">=", unsigned_of(a, size), unsigned_of(b, size));
            if (cc == "be") return bin("<=", unsigned_of(a, size), unsigned_of(b, size));
            if (cc == "a") return bin(">", unsigned_of(a, size), unsigned_of(b, size));
            if (cc == "s") return bin("<", signed_of(bin("-", a, b), size), zero);
            if (cc == "ns") return bin(">=", signed_of(bin("-", a, b), size), zero);
        } else if (flags_.type == Flags::T::Test || flags_.type == Flags::T::Result) {
            EP value = flags_.a;
            if (flags_.type == Flags::T::Test) value = same(flags_.a, flags_.b) ? flags_.a : bin("&", flags_.a, flags_.b);
            if (cc == "e") return bin("==", value, zero);
            if (cc == "ne") return bin("!=", value, zero);
            if (cc == "s" || cc == "l") return bin("<", signed_of(value, size), zero);
            if (cc == "ns" || cc == "ge") return bin(">=", signed_of(value, size), zero);
            if (cc == "g") return bin(">", signed_of(value, size), zero);
            if (cc == "le") return bin("<=", signed_of(value, size), zero);
            if (flags_.type == Flags::T::Test) {
                if (cc == "b") return konst(0, 1);
                if (cc == "ae") return konst(1, 1);
                if (cc == "be") return bin("==", value, zero);
                if (cc == "a") return bin("!=", value, zero);
            }
        }
        // Unknown flag source: expose the raw flag condition.
        return var("__cc_" + cc, 1);
        (void)flag_var;
    }

    // ---- calls
    EP callee_args_call(const std::string& direct_name, const EP& indirect, std::uint32_t arg_mask) {
        const std::vector<int> regs = g_arm ? std::vector<int>{0, 1, 2, 3, 4, 5, 6, 7}
                                            : cx_.options.windows_abi ? std::vector<int>{kRcx, kRdx, 8, 9} : std::vector<int>{kRdi, kRsi, kRdx, kRcx, 8, 9};
        const int register_args = static_cast<int>(regs.size());
        int count = 0;
        const std::string stripped = strip_import_decoration(direct_name);
        const auto known = known_arg_counts().find(stripped);
        if (known != known_arg_counts().end()) count = known->second;
        else {
            for (int i = 0; i < register_args; ++i) if (arg_mask & (1u << regs[i])) count = i + 1;
        }
        std::vector<EP> args;
        for (int i = 0; i < count; ++i) {
            if (i < register_args) args.push_back(cur_[regs[i]]);
            else if (g_arm && cur_[kArmSp]->kind == K::Frame) {
                const auto slot = frame_offset(cur_[kArmSp]) + 8 * (i - 8);
                cx_.frame_reads.insert(slot);
                args.push_back(new_temp(deref(8, frame(slot))));
            } else if (g_arm) args.push_back(konst(0));
            else if (cx_.options.windows_abi && cur_[kRsp]->kind == K::Frame) {
                const auto slot = frame_offset(cur_[kRsp]) + 0x20 + 8 * (i - 4);
                cx_.frame_reads.insert(slot);
                args.push_back(new_temp(deref(8, frame(slot))));
            } else if (!cx_.options.windows_abi && cur_[kRsp]->kind == K::Frame) {
                const auto slot = frame_offset(cur_[kRsp]) + 8 * (i - 6);
                cx_.frame_reads.insert(slot);
                args.push_back(new_temp(deref(8, frame(slot))));
            } else args.push_back(konst(0));
        }
        if (!g_arm && cx_.options.windows_abi) {
            int fp_count = 0; std::vector<int> fp_positions;
            for (int i = 0; i < 4; ++i)
                if ((fp_defined_since_call_ & (1u << i)) && !(arg_mask & (1u << regs[i]))) { fp_positions.push_back(i); fp_count = i + 1; }
            while (static_cast<int>(args.size()) < fp_count) args.push_back(cur_[regs[args.size()]]);
            for (const int i : fp_positions) { const EP v = cur_[xmm_base() + i]; args[static_cast<std::size_t>(i)] = v->kind == K::Var && !v->fp ? with_fp(v, 2) : v; }
        }
        for (const auto& a : args) visit(a, [&](const EP& n) { if (n->kind == K::Frame) cx_.frame_escape = true; });
        return indirect ? call_indirect(indirect, std::move(args)) : call_direct(direct_name, std::move(args));
    }

    std::string name_for(std::uint64_t address) {
        if (cx_.options.name_of) { const auto n = cx_.options.name_of(address); if (!n.empty()) return n; }
        char buf[40]; std::snprintf(buf, sizeof buf, "sub_%llX", static_cast<unsigned long long>(address)); return buf;
    }

    void do_call(const Instruction& ins, const Operand& target, std::uint64_t next) {
        std::string direct; EP indirect;
        bool noreturn = false;
        std::uint64_t direct_address = 0;
        if (target.type == Operand::T::Imm) {
            direct_address = static_cast<std::uint64_t>(target.imm);
            direct = name_for(direct_address);
        } else if (target.type == Operand::T::Mem && target.mem.rip && cx_.options.name_of) {
            const auto slot = next + static_cast<std::uint64_t>(target.mem.disp);
            const auto n = cx_.options.name_of(slot);
            if (!n.empty()) direct = n;
        }
        if (direct.empty()) {
            indirect = target.type == Operand::T::Reg ? read_reg(target.reg)
                     : target.type == Operand::T::Mem ? load(target.mem, 8, next) : konst(0);
        }
        const std::uint32_t mask = defined_since_call_ | block_.arg_mask_in;
        EP call = callee_args_call(direct, indirect, mask);
        if (!direct.empty() && noreturn_names().contains(strip_import_decoration(direct))) noreturn = true;
        if (direct_address && cx_.options.is_noreturn && cx_.options.is_noreturn(direct_address)) noreturn = true;
        const auto result = new_temp(call);
        // Return value and clobbers.
        for (int r = 0; r < 16; ++r) {
            if (cx_.caller_saved.contains(r)) { cur_[r] = var(kGp64[r]); dirty_[r] = false; }
        }
        for (int r = xmm_base(); r < kRegCount; ++r) { cur_[r] = var(canonical_name(r), 16); dirty_[r] = false; }
        cur_[kRax] = result; dirty_[kRax] = true; cx_.used_regs.insert("rax");
        defined_since_call_ = 0; block_.arg_mask_in = 0; fp_defined_since_call_ = 0;
        flags_ = {};
        (void)ins;
        if (noreturn) { block_.term.type = Terminator::T::NoReturn; terminated_ = true; done_ = true; }
    }

    EP return_value() {
        if (!g_arm) {
            const bool rax_set = !same(cur_[kRax], var("rax"));
            if (!rax_set && !st_.empty()) {   // long double / x87 return value
                cx_.return_fp = (std::max)(cx_.return_fp, 3);
                return st_.back();
            }
            const EP x = cur_[xmm_base()];
            if (!rax_set && x->fp && !(x->kind == K::Var && x->name == "xmm0")) {
                bool stored = false;
                for (const auto& s : block_.stmts) if (s.type == Stmt::T::Store && s.value && same(s.value, x)) stored = true;
                if (!stored) { cx_.return_fp = (std::max)(cx_.return_fp, static_cast<int>(x->fp)); return x; }
            }
        }
        if (!same(cur_[kRax], var(canonical_name(kRax)))) return cur_[kRax];
        return cx_.saw_rax_write ? var(canonical_name(kRax)) : nullptr;
    }

    // ---- main instruction dispatcher
    void lift(const Instruction& ins, std::size_t position) {
        current_address_ = ins.address;
        if (g_arm) { lift_arm(ins); return; }
        if (const auto sm = cx_.switch_mov.find(ins.address); sm != cx_.switch_mov.end()) switch_index_ = read_reg(RegRef{sm->second, 8, false});
        if (cx_.switch_skip.contains(ins.address) && ins.address != current_switch_jump_) return;
        const std::uint64_t next = ins.address + ins.size;
        std::string m = ins.mnemonic;
        std::string prefix;
        // Strip rep/lock prefixes that the disassembler concatenates into the mnemonic text.
        for (const char* p : {"rep ", "repe ", "repne ", "repz ", "repnz ", "lock ", "bnd ", "notrack "}) {
            if (m.rfind(p, 0) == 0) { prefix = p; m = m.substr(std::string(p).size()); }
        }
        auto ops_text = split_operands(ins.operands);
        std::vector<Operand> ops; for (auto& t : ops_text) ops.push_back(parse_operand(t));
        const auto op = [&](std::size_t i) -> const Operand& { static const Operand none; return i < ops.size() ? ops[i] : none; };
        const bool last_in_block = position + 1 >= block_.last;

        if (m == "nop" || m == "endbr64" || m == "endbr32" || m == "pause" || m == "fnop" || m == "int3" ||
            m == "ud2" || m == "hlt" || m == "cld" || m == "std" || m == "prefetcht0" || m == "prefetchw" || m == "prefetchnta" ||
            m == "lfence" || m == "mfence" || m == "sfence") {
            if (m == "ud2" || m == "hlt") { block_.term.type = Terminator::T::NoReturn; terminated_ = true; done_ = true; }
            return;
        }

        if (m == "ret" || m == "retn" || m == "retf") {
            block_.term.type = Terminator::T::Ret; block_.term.value = return_value(); block_.term.source = ins.address;
            block_.term.fp_return = !st_.empty() ? st_.back() : cur_[xmm_base()];
            terminated_ = true; done_ = true; if (block_.term.value) cx_.saw_return_value = true; return;
        }
        if (m == "jmp") {
            block_.term.source = ins.address;
            const bool import_tail = op(0).type == Operand::T::Mem && op(0).mem.rip && cx_.options.name_of &&
                !cx_.options.name_of(next + static_cast<std::uint64_t>(op(0).mem.disp)).empty();
            if (import_tail || (op(0).type == Operand::T::Imm && !cx_.insn_at.contains(static_cast<std::uint64_t>(op(0).imm)))) {
                // Tail call into another function.
                do_call(ins, op(0), next);
                block_.term.type = Terminator::T::Ret; block_.term.value = cur_[kRax]; block_.term.source = ins.address;
                cx_.saw_return_value = true; terminated_ = true; done_ = true; return;
            } else if (op(0).type == Operand::T::Imm) {
                block_.term.type = Terminator::T::Jmp; block_.term.taken = static_cast<std::uint64_t>(op(0).imm);
            } else if (const auto sw = cx_.switches.find(ins.address); sw != cx_.switches.end() && switch_index_) {
                block_.term.type = Terminator::T::Switch; block_.term.value = switch_index_;
                block_.term.cases = sw->second.targets; block_.term.default_target = sw->second.default_target;
            } else {
                block_.term.type = Terminator::T::IndirectJmp;
                block_.term.value = op(0).type == Operand::T::Reg ? read_reg(op(0).reg)
                                  : op(0).type == Operand::T::Mem ? load(op(0).mem, 8, next) : konst(0);
            }
            terminated_ = true; done_ = true; return;
        }
        if (is_conditional_jump(m) && op(0).type == Operand::T::Imm) {
            const std::string cc = condition_code(m, 1);
            block_.term.type = Terminator::T::Cond; block_.term.cond = make_condition(cc);
            block_.term.taken = static_cast<std::uint64_t>(op(0).imm); block_.term.fallthrough = next;
            block_.term.source = ins.address; terminated_ = true; done_ = true; return;
        }
        if (m == "call") { do_call(ins, op(0), next); return; }

        if (m == "push") {
            const EP value = read_operand(op(0), 8, next);
            const bool callee_saved = op(0).type == Operand::T::Reg && cx_.callee_saved.contains(op(0).reg.index);
            cur_[kRsp] = bin("+", cur_[kRsp], konst(~7ull));
            if (!callee_saved) emit_store(8, cur_[kRsp], value);
            return;
        }
        if (m == "pop") {
            if (op(0).type == Operand::T::Reg && cx_.callee_saved.contains(op(0).reg.index)) {
                cur_[kRsp] = bin("+", cur_[kRsp], konst(8));
                if (op(0).reg.index != kRsp) { cur_[op(0).reg.index] = var(kGp64[op(0).reg.index]); dirty_[op(0).reg.index] = false; }
                return;
            }
            if (cur_[kRsp]->kind == K::Frame) cx_.frame_reads.insert(frame_offset(cur_[kRsp]));
            const EP value = new_temp(deref(8, cur_[kRsp]));
            cur_[kRsp] = bin("+", cur_[kRsp], konst(8));
            if (op(0).type == Operand::T::Reg) write_reg(op(0).reg, value);
            return;
        }
        if (m == "leave") {
            cur_[kRsp] = bin("+", cur_[kRbp], konst(8));
            cur_[kRbp] = var("rbp"); dirty_[kRbp] = false;
            return;
        }

        if (lift_sse(ins, m, ops, next)) return;
        if (m.size() > 1 && (m[0] == 'f' || m == "sahf") && lift_x87(ins, m, ops_text, next)) return;
        if (m == "mov" || m == "movabs" || m == "movq" || m == "movd" || m == "movaps" || m == "movups" ||
            m == "movdqa" || m == "movdqu" || m == "movapd" || m == "movupd" || m == "movss" || m == "movsd" ||
            m == "vmovaps" || m == "vmovups" || m == "vmovdqa" || m == "vmovdqu" || m == "vmovss" || m == "vmovsd" ||
            m == "vmovq" || m == "vmovd") {
            if (ops.size() == 2 && !(op(0).type == Operand::T::Mem && op(1).type == Operand::T::Mem)) {
                const int size = operand_size(op(0), op(1));
                // `mov xmm, xmm` style moves are plain copies; sizes beyond 8 stay opaque.
                EP value = read_operand(op(1), size, next);
                if (op(0).type == Operand::T::Reg && op(0).reg.index >= xmm_base() && op(1).type == Operand::T::Mem) {
                    write_reg(op(0).reg, value);
                } else {
                    write_operand(op(0), value, size, next);
                }
                return;
            }
        }
        if (m == "movzx" && ops.size() == 2) {
            const int src_size = op(1).type == Operand::T::Reg ? op(1).reg.size : (op(1).mem.size ? op(1).mem.size : 1);
            write_operand(op(0), cast(src_size, false, read_operand(op(1), src_size, next)), op(0).reg.size, next);
            return;
        }
        if ((m == "movsx" || m == "movsxd") && ops.size() == 2) {
            const int src_size = op(1).type == Operand::T::Reg ? op(1).reg.size : (op(1).mem.size ? op(1).mem.size : (m == "movsxd" ? 4 : 1));
            const int dst_size = op(0).reg.size;
            write_operand(op(0), cast(dst_size, true, cast(src_size, true, read_operand(op(1), src_size, next))), dst_size, next);
            return;
        }
        if (m == "lea" && ops.size() == 2 && op(1).type == Operand::T::Mem) {
            EP addr = address_of(op(1).mem, next);
            if (op(0).reg.size < 8) addr = cast(op(0).reg.size, false, addr);
            write_reg(op(0).reg, addr);
            return;
        }
        if ((m == "add" || m == "sub" || m == "and" || m == "or" || m == "xor") && ops.size() == 2) {
            const int size = operand_size(op(0), op(1));
            if (m == "and" && op(0).type == Operand::T::Reg && op(0).reg.index == kRsp && op(1).type == Operand::T::Imm) return; // stack alignment
            const EP a = read_operand(op(0), size, next);
            const EP b = read_operand(op(1), size, next);
            const std::string sym = m == "add" ? "+" : m == "sub" ? "-" : m == "and" ? "&" : m == "or" ? "|" : "^";
            EP result = bin(sym, a, b);
            if (m == "xor" && op(0).type == Operand::T::Reg && op(1).type == Operand::T::Reg && op(0).reg.index == op(1).reg.index) result = konst(0);
            write_operand(op(0), result, size, next);
            if (m == "sub") set_flags_cmp(a, b, size); else set_flags_result(result, size);
            return;
        }
        if ((m == "adc" || m == "sbb") && ops.size() == 2) {
            const int size = operand_size(op(0), op(1));
            const EP a = read_operand(op(0), size, next), b = read_operand(op(1), size, next);
            write_operand(op(0), intrin(m == "adc" ? "__adc" : "__sbb", {a, b}), size, next);
            flags_ = {};
            return;
        }
        if (m == "cmp" && ops.size() == 2) {
            const int size = operand_size(op(0), op(1));
            set_flags_cmp(read_operand(op(0), size, next), read_operand(op(1), size, next), size);
            return;
        }
        if (m == "test" && ops.size() == 2) {
            const int size = operand_size(op(0), op(1));
            set_flags_test(read_operand(op(0), size, next), read_operand(op(1), size, next), size);
            return;
        }
        if ((m == "inc" || m == "dec") && ops.size() == 1) {
            const int size = operand_size(op(0), op(0));
            const EP a = read_operand(op(0), size, next);
            const EP result = bin("+", a, konst(m == "inc" ? 1 : ~0ull));
            write_operand(op(0), result, size, next);
            set_flags_result(result, size);
            return;
        }
        if ((m == "neg" || m == "not") && ops.size() == 1) {
            const int size = operand_size(op(0), op(0));
            const EP a = read_operand(op(0), size, next);
            const EP result = un(m == "neg" ? "-" : "~", a);
            write_operand(op(0), result, size, next);
            if (m == "neg") set_flags_result(result, size);
            return;
        }
        if ((m == "shl" || m == "sal" || m == "shr" || m == "sar" || m == "rol" || m == "ror") && !ops.empty()) {
            const int size = operand_size(op(0), op(0));
            const EP a = read_operand(op(0), size, next);
            const EP count = ops.size() > 1 ? read_operand(op(1), 1, next) : konst(1);
            EP result;
            if (m == "shl" || m == "sal") result = bin("<<", a, count);
            else if (m == "shr") result = bin(">>", unsigned_of(a, size), count);
            else if (m == "sar") result = bin(">>", signed_of(a, size), count);
            else result = intrin(m == "rol" ? "__ROL" + std::to_string(size) + "__" : "__ROR" + std::to_string(size) + "__", {a, count});
            write_operand(op(0), result, size, next);
            set_flags_result(result, size);
            return;
        }
        if (m == "imul") {
            if (ops.size() == 3) {
                const int size = operand_size(op(0), op(1));
                write_operand(op(0), bin("*", read_operand(op(1), size, next), read_operand(op(2), size, next)), size, next);
                flags_ = {}; return;
            }
            if (ops.size() == 2) {
                const int size = operand_size(op(0), op(1));
                write_operand(op(0), bin("*", read_operand(op(0), size, next), read_operand(op(1), size, next)), size, next);
                flags_ = {}; return;
            }
            if (ops.size() == 1) {
                const int size = operand_size(op(0), op(0));
                const EP a = read_reg({kRax, size, false}), b = read_operand(op(0), size, next);
                write_reg({kRax, size, false}, bin("*", signed_of(a, size), signed_of(b, size)));
                if (size > 1) write_reg({kRdx, size, false}, intrin("__mulhi", {a, b}));
                flags_ = {}; return;
            }
        }
        if (m == "mul" && ops.size() == 1) {
            const int size = operand_size(op(0), op(0));
            const EP a = read_reg({kRax, size, false}), b = read_operand(op(0), size, next);
            write_reg({kRax, size, false}, bin("*", a, b));
            if (size > 1) write_reg({kRdx, size, false}, intrin("__umulhi", {a, b}));
            flags_ = {}; return;
        }
        if ((m == "div" || m == "idiv") && ops.size() == 1) {
            const int size = operand_size(op(0), op(0));
            const bool sgn = m == "idiv";
            EP a = read_reg({kRax, size, false}), b = read_operand(op(0), size, next);
            if (sgn) { a = signed_of(a, size); b = signed_of(b, size); } else { a = unsigned_of(a, size); b = unsigned_of(b, size); }
            const EP quotient = bin("/", a, b), remainder = bin("%", a, b);
            const EP q = materialize(quotient, size), r = materialize(remainder, size);
            write_reg({kRax, size, false}, q);
            if (size > 1) write_reg({kRdx, size, false}, r);
            else write_reg({kRax, 2, true}, r);
            flags_ = {}; return;
        }
        if (m == "cdqe") { write_reg({kRax, 8, false}, cast(8, true, cast(4, true, read_reg({kRax, 4, false})))); return; }
        if (m == "cwde") { write_reg({kRax, 4, false}, cast(4, true, cast(2, true, read_reg({kRax, 2, false})))); return; }
        if (m == "cdq") { write_reg({kRdx, 4, false}, bin(">>", signed_of(read_reg({kRax, 4, false}), 4), konst(31))); return; }
        if (m == "cqo") { write_reg({kRdx, 8, false}, bin(">>", signed_of(read_reg({kRax, 8, false}), 8), konst(63))); return; }
        if (m.rfind("set", 0) == 0 && ops.size() == 1 && m != "setalc") {
            const EP c = make_condition(condition_code(m, 3));
            write_operand(op(0), c, 1, next); return;
        }
        if (m.rfind("cmov", 0) == 0 && ops.size() == 2) {
            const int size = operand_size(op(0), op(1));
            const EP c = make_condition(condition_code(m, 4));
            const EP src = read_operand(op(1), size, next), old = read_operand(op(0), size, next);
            write_operand(op(0), tern(c, src, old), size, next); return;
        }
        if (m == "xchg" && ops.size() == 2 && op(0).type == Operand::T::Reg && op(1).type == Operand::T::Reg) {
            const EP a = read_operand(op(0), 8, next), b = read_operand(op(1), 8, next);
            write_reg(op(0).reg, b); write_reg(op(1).reg, a); return;
        }
        if ((m == "pxor" || m == "xorps" || m == "xorpd" || m == "vpxor" || m == "vxorps") && ops.size() >= 2 &&
            op(0).type == Operand::T::Reg && op(1).type == Operand::T::Reg && op(0).reg.index == op(1).reg.index) {
            write_reg(op(0).reg, konst(0)); return;
        }
        {
            static const std::map<std::string, std::string> float_ops{
                {"addss", "+"}, {"addsd", "+"}, {"subss", "-"}, {"subsd", "-"}, {"mulss", "*"}, {"mulsd", "*"},
                {"divss", "/"}, {"divsd", "/"}, {"vaddss", "+"}, {"vaddsd", "+"}, {"vsubss", "-"}, {"vsubsd", "-"},
                {"vmulss", "*"}, {"vmulsd", "*"}, {"vdivss", "/"}, {"vdivsd", "/"}};
            if (const auto it = float_ops.find(m); it != float_ops.end() && ops.size() == 2) {
                const int size = m.find("ss") != std::string::npos ? 4 : 8;
                const EP a = read_operand(op(0), 16, next), b = read_operand(op(1), size, next);
                write_reg(op(0).reg, bin(it->second, a, b)); return;
            }
        }
        if ((m == "movsb" || m == "movsw" || m == "movsd" || m == "movsq" || m == "stosb" || m == "stosw" ||
             m == "stosd" || m == "stosq") &&
            (ops.empty() || (ops.size() == 2 && op(0).type == Operand::T::Mem))) {
            const bool store_only = m.rfind("stos", 0) == 0;
            const int size = m.back() == 'b' ? 1 : m.back() == 'w' ? 2 : m.back() == 'd' ? 4 : 8;
            const EP count = prefix.empty() ? konst(1) : cur_[kRcx];
            if (store_only) emit_eval(intrin("__rep_stos" + std::to_string(size), {cur_[kRdi], cur_[kRax], count}));
            else emit_eval(intrin("__rep_movs" + std::to_string(size), {cur_[kRdi], cur_[kRsi], count}));
            if (!prefix.empty()) { cur_[kRcx] = konst(0); dirty_[kRcx] = true; }
            cur_[kRdi] = intrin("__advance", {cur_[kRdi], count, konst(size)}); dirty_[kRdi] = true;
            if (!store_only) { cur_[kRsi] = intrin("__advance", {cur_[kRsi], count, konst(size)}); dirty_[kRsi] = true; }
            return;
        }

        // Generic fallback: keep data flow honest with an intrinsic.
        std::vector<EP> args;
        for (std::size_t i = 0; i < ops.size(); ++i) {
            if (ops[i].type == Operand::T::Reg || ops[i].type == Operand::T::Imm ||
                (ops[i].type == Operand::T::Mem && ops[i].mem.size >= 0)) {
                if (i == 0 && ops[i].type == Operand::T::Mem) { args.push_back(deref(ops[i].mem.size ? ops[i].mem.size : 8, address_of(ops[i].mem, next))); continue; }
                args.push_back(read_operand(ops[i], operand_size(ops[0], ops.size() > 1 ? ops[1] : ops[0]), next));
            }
        }
        const std::string name = "__" + m;
        const EP result = intrin(name, std::move(args));
        if (!ops.empty() && ops[0].type == Operand::T::Reg) write_reg(ops[0].reg, result);
        else if (!ops.empty() && ops[0].type == Operand::T::Mem) write_operand(ops[0], result, operand_size(ops[0], ops[0]), next);
        else emit_eval(result);
        flags_ = {};
        (void)last_in_block;
    }



    // ------------------------------------------------------------------ SSE / AVX scalar floating point
    static bool ends_with(const std::string& s, const char* suffix) {
        const std::string x = suffix; return s.size() >= x.size() && s.compare(s.size() - x.size(), x.size(), x) == 0;
    }
    bool is_xmm_op(const Operand& o) const { return o.type == Operand::T::Reg && o.reg.index >= xmm_base(); }

    // View a register / expression as a value of floating-point type `fp`.
    EP fp_view(const EP& e, int fp) {
        if (e->fp == fp) return e;
        if (e->kind == K::Const && !e->fp) return fconst(e->imm, fp);                 // raw bits of a constant
        if (e->kind == K::Var && !e->temp && e->name.rfind("xmm", 0) == 0) return with_fp(e, fp);
        if (e->fp) return with_fp(e, fp);
        return fintrin(fp == 1 ? "__as_float" : fp == 2 ? "__as_double" : "__as_long_double", {e}, fp);   // integer bits reinterpreted
    }
    EP fp_memory(const MemRef& m, int fp, std::uint64_t next) {
        const int size = fp == 1 ? 4 : fp == 2 ? 8 : 10;
        const EP addr = address_of(m, next);
        if (addr->kind == K::Const) {   // constant pool in read-only data
            const auto offset = cx_.image.va_to_file_offset(addr->imm);
            bool writable = true;
            for (const auto& s : cx_.image.sections) {
                const auto begin = cx_.image.image_base + s.rva;
                if (addr->imm >= begin && addr->imm < begin + (std::max)(s.virtual_size, s.raw_size)) { writable = (s.characteristics & 0x80000000u) != 0; break; }
            }
            if (offset && !writable && fp != 3 && *offset + static_cast<std::size_t>(size) <= cx_.image.bytes.size()) {
                std::uint64_t bits = 0;
                for (int b = 0; b < size; ++b) bits |= static_cast<std::uint64_t>(cx_.image.bytes[*offset + static_cast<std::size_t>(b)]) << (8 * b);
                return fconst(bits, fp);
            }
        }
        if (addr->kind == K::Frame) cx_.frame_reads.insert(frame_offset(addr));
        return fp_temp(fderef(size == 10 ? 8 : size, addr, fp), fp);
    }
    EP read_fp(const Operand& o, int fp, std::uint64_t next) {
        if (o.type == Operand::T::Mem) return fp_memory(o.mem, fp, next);
        if (is_xmm_op(o)) return fp_view(cur_[o.reg.index], fp);
        if (o.type == Operand::T::Imm) return fconst_double(static_cast<double>(o.imm), fp);
        return read_operand(o, 8, next);
    }
    void write_xmm(const Operand& o, const EP& value, int fp) {
        if (!is_xmm_op(o)) return;
        write_full(o.reg.index, simple(value) ? value : fp_temp(value, fp));
    }

    bool lift_sse(const Instruction& ins, const std::string& m, const std::vector<Operand>& ops, std::uint64_t next) {
        (void)ins;
        const bool avx = m.size() > 1 && m[0] == 'v' && m != "vzeroupper";
        const std::string base = avx ? m.substr(1) : m;
        const auto op = [&](std::size_t i) -> const Operand& { static const Operand none; return i < ops.size() ? ops[i] : none; };
        const int fp = ends_with(base, "ss") ? 1 : ends_with(base, "sd") ? 2 : 0;
        const bool is_scalar_name = fp != 0 && base.size() > 2;

        // --- moves between xmm and memory / registers with a known scalar type
        if ((base == "movss" || base == "movsd") && ops.size() >= 2 && (is_xmm_op(op(0)) || is_xmm_op(op(1)))) {
            const int size = fp == 1 ? 4 : 8;
            if (is_xmm_op(op(0)) && op(1).type == Operand::T::Mem) { write_full(op(0).reg.index, fp_memory(op(1).mem, fp, next)); return true; }
            if (op(0).type == Operand::T::Mem && is_xmm_op(op(1))) {
                const EP value = fp_view(cur_[op(1).reg.index], fp);
                const EP addr = address_of(op(0).mem, next);
                emit_store(size, addr, value); return true;
            }
            if (is_xmm_op(op(0)) && is_xmm_op(op(1))) { write_full(op(0).reg.index, fp_view(cur_[op(ops.size() - 1).reg.index], fp)); return true; }
            return false;
        }
        if ((base == "movq" || base == "movd") && ops.size() == 2) {
            const int size = base == "movq" ? 8 : 4, ftype = base == "movq" ? 2 : 1;
            if (op(0).type == Operand::T::Reg && !is_xmm_op(op(0)) && is_xmm_op(op(1))) {
                const EP x = cur_[op(1).reg.index];
                if (x->fp) {
                    const EP bits = x->kind == K::Const ? konst(x->imm, size) : fintrin(ftype == 2 ? "__double_bits" : "__float_bits", {x}, 0);
                    write_reg(op(0).reg, bits); return true;
                }
            }
            return false;
        }

        // --- scalar arithmetic: addsd xmm0, xmm1 / vaddsd xmm0, xmm1, xmm2
        if (is_scalar_name && ops.size() >= 2 && is_xmm_op(op(0))) {
            const std::string stem = base.substr(0, base.size() - 2);
            static const std::map<std::string, std::string> arithmetic{{"add", "+"}, {"sub", "-"}, {"mul", "*"}, {"div", "/"}};
            const std::size_t a_index = avx && ops.size() >= 3 ? 1 : 0, b_index = avx && ops.size() >= 3 ? 2 : 1;
            if (const auto it = arithmetic.find(stem); it != arithmetic.end() && ops.size() == (avx ? 3u : 2u)) {
                const EP a = read_fp(op(a_index), fp, next), b = read_fp(op(b_index), fp, next);
                write_xmm(op(0), fbin(it->second, a, b, fp), fp); return true;
            }
            if (stem == "sqrt") { write_xmm(op(0), fintrin(fp == 1 ? "sqrtf" : "sqrt", {read_fp(op(ops.size() - 1), fp, next)}, fp), fp); return true; }
            if ((stem == "min" || stem == "max") && ops.size() == (avx ? 3u : 2u)) {
                const EP a = read_fp(op(a_index), fp, next), b = read_fp(op(b_index), fp, next);
                write_xmm(op(0), fintrin(stem == "min" ? (fp == 1 ? "fminf" : "fmin") : (fp == 1 ? "fmaxf" : "fmax"), {a, b}, fp), fp); return true;
            }
            if (stem == "round" && ops.size() >= 2) {
                write_xmm(op(0), fintrin(fp == 1 ? "roundf" : "round", {read_fp(op(ops.size() >= 3 && avx ? 1 : 1), fp, next)}, fp), fp); return true;
            }
        }
        // --- fused multiply-add: vfmadd213sd xmm1, xmm2, xmm3 ...
        if (avx && ops.size() == 3 && is_xmm_op(op(0)) && fp != 0 && base.size() >= 9 && (base.rfind("fmadd", 0) == 0 || base.rfind("fmsub", 0) == 0 || base.rfind("fnmadd", 0) == 0 || base.rfind("fnmsub", 0) == 0)) {
            const bool negate_product = base[1] == 'n' || base.rfind("fnm", 0) == 0;
            const bool subtract = base.find("sub") != std::string::npos;
            const auto digits = base.find_first_of("123");
            if (digits != std::string::npos && digits + 3 <= base.size()) {
                const std::string order = base.substr(digits, 3);
                const EP a = read_fp(op(0), fp, next), b = read_fp(op(1), fp, next), c = read_fp(op(2), fp, next);
                EP product, addend;
                if (order == "132") { product = fbin("*", a, c, fp); addend = b; }
                else if (order == "213") { product = fbin("*", b, a, fp); addend = c; }
                else { product = fbin("*", b, c, fp); addend = a; }
                if (negate_product) product = fneg(product);
                write_xmm(op(0), fbin(subtract ? "-" : "+", product, addend, fp), fp); return true;
            }
        }
        // --- compares
        if ((base == "comisd" || base == "ucomisd" || base == "comiss" || base == "ucomiss") && ops.size() == 2) {
            const int ctype = ends_with(base, "ss") ? 1 : 2;
            Flags f; f.type = Flags::T::Cmp; f.fp = true; f.size = 8;
            f.a = read_fp(op(0), ctype, next); f.b = read_fp(op(1), ctype, next);
            flags_ = f; return true;
        }
        // --- conversions
        if ((base == "cvtsi2sd" || base == "cvtsi2ss") && ops.size() >= 2 && is_xmm_op(op(0))) {
            const Operand& src = op(ops.size() - 1);
            const int size = src.type == Operand::T::Reg ? src.reg.size : (src.mem.size ? src.mem.size : 4);
            const EP v = cast(size, true, read_operand(src, size, next));
            write_xmm(op(0), fcast_to(base == "cvtsi2sd" ? 2 : 1, v), base == "cvtsi2sd" ? 2 : 1); return true;
        }
        if ((base == "cvtss2sd" || base == "cvtsd2ss") && ops.size() >= 2 && is_xmm_op(op(0))) {
            const int from = base == "cvtss2sd" ? 1 : 2, to = base == "cvtss2sd" ? 2 : 1;
            write_xmm(op(0), fcast_to(to, read_fp(op(ops.size() - 1), from, next)), to); return true;
        }
        if ((base == "cvttsd2si" || base == "cvttss2si" || base == "cvtsd2si" || base == "cvtss2si") && ops.size() >= 2 && op(0).type == Operand::T::Reg) {
            const int from = ends_with(base, "ss2si") ? 1 : 2;
            write_reg(op(0).reg, fcast_from(op(0).reg.size, read_fp(op(1), from, next))); return true;
        }
        if ((base == "cvtdq2pd" || base == "cvtdq2ps") && ops.size() >= 2 && is_xmm_op(op(0))) {
            const int to = base == "cvtdq2pd" ? 2 : 1;
            const Operand& src = op(ops.size() - 1);
            const EP raw = src.type == Operand::T::Mem ? new_temp(deref(4, address_of(src.mem, next)), 4) : cur_[src.reg.index];
            write_xmm(op(0), fcast_to(to, cast(4, true, raw)), to); return true;
        }
        if ((base == "cvtps2pd" || base == "cvtpd2ps") && ops.size() >= 2 && is_xmm_op(op(0))) {
            const int from = base == "cvtps2pd" ? 1 : 2, to = base == "cvtps2pd" ? 2 : 1;
            write_xmm(op(0), fcast_to(to, read_fp(op(ops.size() - 1), from, next)), to); return true;
        }
        // --- sign / mask tricks on constants: xorps x, [signmask]  /  andps x, [absmask]
        if ((base == "xorps" || base == "xorpd" || base == "andps" || base == "andpd") && ops.size() >= 2 && is_xmm_op(op(0)) && op(1).type == Operand::T::Mem && !avx) {
            const EP addr = address_of(op(1).mem, next);
            if (addr->kind == K::Const) {
                const auto offset = cx_.image.va_to_file_offset(addr->imm);
                if (offset && *offset + 8 <= cx_.image.bytes.size()) {
                    std::uint64_t low = 0; for (int b = 0; b < 8; ++b) low |= static_cast<std::uint64_t>(cx_.image.bytes[*offset + static_cast<std::size_t>(b)]) << (8 * b);
                    const bool single = ends_with(base, "ps");
                    const int ftype = single ? 1 : 2;
                    const std::uint64_t sign = single ? 0x80000000ull : 0x8000000000000000ull, absolute = single ? 0x7FFFFFFFull : 0x7FFFFFFFFFFFFFFFull;
                    const std::uint64_t masked = single ? (low & 0xFFFFFFFFull) : low;
                    if (base[0] == 'x' && masked == sign) { write_xmm(op(0), fneg(fp_view(cur_[op(0).reg.index], ftype)), ftype); return true; }
                    if (base[0] == 'a' && masked == absolute) { write_xmm(op(0), fintrin(single ? "fabsf" : "fabs", {fp_view(cur_[op(0).reg.index], ftype)}, ftype), ftype); return true; }
                }
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ x87
    EP st_get(int i) {
        const int depth = static_cast<int>(st_.size());
        if (i < depth) return st_[static_cast<std::size_t>(depth - 1 - i)];
        return with_fp(var("st" + std::to_string(i - depth), 8), 3);
    }
    void st_set(int i, const EP& v) {
        const int depth = static_cast<int>(st_.size());
        if (i < depth) st_[static_cast<std::size_t>(depth - 1 - i)] = v;
    }
    void st_push(const EP& v) { st_.push_back(simple(v) ? v : fp_temp(v, 3)); if (st_.size() > 8) st_.erase(st_.begin()); }
    void st_pop() { if (!st_.empty()) st_.pop_back(); }
    static std::optional<int> st_index(const std::string& text) {
        std::string s = trim(text);
        for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (s == "st") return 0;
        if (s.rfind("st(", 0) == 0 && s.size() >= 5) return s[3] - '0';
        return std::nullopt;
    }
    EP x87_memory(const Operand& mem, int fp, std::uint64_t next) {
        const int size = fp == 1 ? 4 : fp == 2 ? 8 : 10;
        const EP addr = address_of(mem.mem, next);
        if (addr->kind == K::Frame) cx_.frame_reads.insert(frame_offset(addr));
        return fp_temp(fderef(size == 10 ? 8 : size, addr, fp), fp);
    }
    static int fp_from_size(int size) { return size == 4 ? 1 : size == 8 ? 2 : 3; }

    bool lift_x87(const Instruction& ins, const std::string& m, const std::vector<std::string>& text, std::uint64_t next) {
        (void)ins;
        std::vector<Operand> ops; for (const auto& t : text) ops.push_back(parse_operand(t));
        const auto sti = [&](std::size_t i) -> std::optional<int> { return i < text.size() ? st_index(text[i]) : std::nullopt; };
        const auto is_mem = [&](std::size_t i) { return i < ops.size() && ops[i].type == Operand::T::Mem; };
        const auto mem_size = [&](std::size_t i, int fallback) { return is_mem(i) && ops[i].mem.size ? ops[i].mem.size : fallback; };

        if (m == "fwait" || m == "wait" || m == "fninit" || m == "finit" || m == "fnclex" || m == "fclex" || m == "fnop" || m == "emms" || m == "ffree" || m == "ffreep" ||
            m == "fnstcw" || m == "fstcw" || m == "fldcw" || m == "fnstenv" || m == "fldenv") return true;
        if (m == "sahf") {
            if (!fpu_status_pending_) return false;
            Flags f; f.type = Flags::T::Cmp; f.fp = true; f.size = 8; f.a = fpu_a_; f.b = fpu_b_;
            flags_ = f; fpu_status_pending_ = false; return true;
        }
        if (m == "fld") {
            if (is_mem(0)) { st_push(x87_memory(ops[0], fp_from_size(mem_size(0, 8)), next)); return true; }
            if (const auto i = sti(0)) { st_push(st_get(*i)); return true; }
            return false;
        }
        if (m == "fild" && is_mem(0)) {
            const int size = mem_size(0, 4);
            const EP addr = address_of(ops[0].mem, next);
            if (addr->kind == K::Frame) cx_.frame_reads.insert(frame_offset(addr));
            const EP v = cast(size, true, new_temp(deref(size, addr), size));
            st_push(fcast_to(3, v)); return true;
        }
        if (m == "fld1") { st_push(fconst_double(1.0, 3)); return true; }
        if (m == "fldz") { st_push(fconst_double(0.0, 3)); return true; }
        if (m == "fldpi") { st_push(fconst_double(3.14159265358979323846, 3)); return true; }
        if (m == "fldl2e" || m == "fldl2t" || m == "fldlg2" || m == "fldln2") { st_push(fintrin("__" + m, {}, 3)); return true; }
        if ((m == "fst" || m == "fstp") && !text.empty()) {
            const EP v = st_get(0);
            if (is_mem(0)) {
                const int size = mem_size(0, 8), ftype = fp_from_size(size);
                const EP addr = address_of(ops[0].mem, next);
                emit_store(size == 10 ? 8 : size, addr, with_fp(v, ftype));
            } else if (const auto i = sti(0)) st_set(*i, v);
            if (m == "fstp") st_pop();
            return true;
        }
        if ((m == "fist" || m == "fistp" || m == "fisttp") && is_mem(0)) {
            const int size = mem_size(0, 4);
            const EP addr = address_of(ops[0].mem, next);
            emit_store(size, addr, fcast_from(size, st_get(0)));
            if (m != "fist") st_pop();
            return true;
        }
        // arithmetic: fadd / fsub / fsubr / fmul / fdiv / fdivr with the p and integer (fi...) variants
        {
            std::string stem = m;
            bool pop = false, integer = false;
            if (stem.size() > 1 && stem.back() == 'p' && stem != "fcomp") { pop = true; stem.pop_back(); }
            if (stem.size() > 2 && stem[1] == 'i' && (stem.rfind("fiadd", 0) == 0 || stem.rfind("fisub", 0) == 0 || stem.rfind("fimul", 0) == 0 || stem.rfind("fidiv", 0) == 0)) { integer = true; stem = "f" + stem.substr(2); }
            static const std::map<std::string, std::pair<std::string, bool>> table{
                {"fadd", {"+", false}}, {"fsub", {"-", false}}, {"fsubr", {"-", true}}, {"fmul", {"*", false}}, {"fdiv", {"/", false}}, {"fdivr", {"/", true}}};
            if (const auto it = table.find(stem); it != table.end()) {
                const std::string symbol = it->second.first; const bool reversed = it->second.second;
                int dst = 0; EP src;
                if (text.size() >= 2 && sti(0) && sti(1)) { dst = *sti(0); src = st_get(*sti(1)); }
                else if (text.size() == 1 && sti(0)) {
                    if (pop) { dst = *sti(0); src = st_get(0); }                          // faddp st(i)
                    else { dst = 0; src = st_get(*sti(0)); }                              // fadd st(i)
                }
                else if (text.empty()) { dst = 1; src = st_get(0); }                       // faddp
                else if (is_mem(0)) {
                    dst = 0;
                    if (integer) {
                        const int size = mem_size(0, 4); const EP addr = address_of(ops[0].mem, next);
                        src = fcast_to(3, cast(size, true, new_temp(deref(size, addr), size)));
                    } else src = x87_memory(ops[0], fp_from_size(mem_size(0, 8)), next);
                } else return false;
                const EP current = st_get(dst);
                const EP result = reversed ? fbin(symbol, src, current, 3) : fbin(symbol, current, src, 3);
                st_set(dst, simple(result) ? result : fp_temp(result, 3));
                if (pop) st_pop();
                return true;
            }
        }
        if (m == "fxch") {
            const int i = sti(0).value_or(1);
            const EP a = st_get(0), b = st_get(i);
            st_set(0, b); st_set(i, a); return true;
        }
        if (m == "fchs") { st_set(0, fneg(st_get(0))); return true; }
        if (m == "fabs" || m == "fsqrt" || m == "fsin" || m == "fcos" || m == "frndint" || m == "f2xm1" || m == "fptan") {
            static const std::map<std::string, std::string> functions{{"fabs", "fabs"}, {"fsqrt", "sqrt"}, {"fsin", "sin"}, {"fcos", "cos"}, {"frndint", "rint"}, {"f2xm1", "__f2xm1"}, {"fptan", "tan"}};
            st_set(0, fp_temp(fintrin(functions.at(m), {st_get(0)}, 3), 3));
            if (m == "fptan") st_push(fconst_double(1.0, 3));
            return true;
        }
        if (m == "fpatan" || m == "fyl2x" || m == "fscale" || m == "fprem" || m == "fprem1" || m == "fyl2xp1") {
            static const std::map<std::string, std::string> functions{{"fpatan", "atan2"}, {"fyl2x", "__fyl2x"}, {"fscale", "scalbn"}, {"fprem", "fmod"}, {"fprem1", "remainder"}, {"fyl2xp1", "__fyl2xp1"}};
            const EP value = fintrin(functions.at(m), {st_get(1), st_get(0)}, 3);
            st_set(1, fp_temp(value, 3));
            if (m != "fprem" && m != "fprem1" && m != "fscale") st_pop();
            return true;
        }
        // compares
        const bool compare_to_flags = m == "fcomi" || m == "fcomip" || m == "fcompi" || m == "fucomi" || m == "fucomip" || m == "fucompi";
        const bool compare_to_status = m == "fcom" || m == "fcomp" || m == "fcompp" || m == "fucom" || m == "fucomp" || m == "fucompp" || m == "ficom" || m == "ficomp" || m == "ftst";
        if (compare_to_flags || compare_to_status) {
            EP a = st_get(0), b;
            if (m == "ftst") b = fconst_double(0.0, 3);
            else if (m == "fcompp" || m == "fucompp") b = st_get(1);
            else if (is_mem(0)) b = m[1] == 'i' ? fcast_to(3, cast(mem_size(0, 4), true, new_temp(deref(mem_size(0, 4), address_of(ops[0].mem, next)), mem_size(0, 4))))
                                               : x87_memory(ops[0], fp_from_size(mem_size(0, 8)), next);
            else if (const auto i = text.size() >= 2 ? sti(1) : sti(0)) b = st_get(*i);
            else b = st_get(1);
            if (compare_to_flags) { Flags f; f.type = Flags::T::Cmp; f.fp = true; f.size = 8; f.a = a; f.b = b; flags_ = f; }
            else { fpu_a_ = a; fpu_b_ = b; fpu_status_pending_ = true; }
            if (m.back() == 'p' || m == "fcompi" || m == "fucompi" || m == "fcomp" || m == "fucomp") st_pop();
            if (m == "fcompp" || m == "fucompp") st_pop();
            return true;
        }
        if ((m == "fnstsw" || m == "fstsw") && !text.empty()) {
            if (ops.size() >= 1 && ops[0].type == Operand::T::Reg) write_reg(ops[0].reg, fintrin("__fpu_status", {}, 0));
            return true;
        }
        return false;
    }

    // ------------------------------------------------------------------ AArch64
    static EP arm_signed(const EP& e, int size) { return cast(size, true, e); }

    EP arm_apply_modifier(EP v, const ArmOp& op, int size) {
        const std::string& m = op.modifier;
        if (m.empty()) return v;
        if (m == "uxtb") v = cast(1, false, v); else if (m == "uxth") v = cast(2, false, v); else if (m == "uxtw") v = cast(4, false, v);
        else if (m == "sxtb") v = cast(8, true, cast(1, true, v)); else if (m == "sxth") v = cast(8, true, cast(2, true, v));
        else if (m == "sxtw") v = cast(8, true, cast(4, true, v));
        if (m == "lsl" || (m[0] == 'u' || m[0] == 's') ) { if (op.amount) v = bin("<<", v, konst(static_cast<std::uint64_t>(op.amount))); }
        else if (m == "lsr") v = bin(">>", size == 4 ? cast(4, false, v) : v, konst(static_cast<std::uint64_t>(op.amount)));
        else if (m == "asr") v = bin(">>", arm_signed(v, size), konst(static_cast<std::uint64_t>(op.amount)));
        else if (m == "ror") v = intrin("__ror", {v, konst(static_cast<std::uint64_t>(op.amount))});
        return v;
    }

    EP arm_read(const ArmOp& op, int size) {
        if (op.type == ArmOp::T::Imm) {
            std::uint64_t v = static_cast<std::uint64_t>(op.imm);
            if (size < 8) v &= mask_for(size);
            EP c = konst(v, size);
            if (op.modifier == "lsl" && op.amount) c = konst((v << op.amount) & mask_for(size), size);
            return c;
        }
        if (op.type != ArmOp::T::Reg) return konst(0);
        if (op.zr) return konst(0);
        EP v = cur_[op.index];
        if (op.size == 4 && op.index != kArmSp) v = cast(4, false, v);
        return arm_apply_modifier(v, op, size);
    }

    EP fp_read(const ArmOp& o) {
        const auto it = fp_.find(o.index);
        const EP v = it != fp_.end() ? it->second : var("v" + std::to_string(o.index), 16);
        return o.fp_size < 8 && !o.vector ? cast(o.fp_size, false, v) : v;
    }
    void fp_write(const ArmOp& o, const EP& value) {
        const EP v = o.fp_size < 8 && !o.vector ? cast(o.fp_size, false, value) : value;
        fp_[o.index] = simple(v) ? v : materialize(v, o.fp_size > 8 ? 8 : o.fp_size);
    }

    void arm_write(const ArmOp& reg, const EP& value) {
        if (reg.type != ArmOp::T::Reg || reg.zr) return;
        EP v = reg.size == 4 && reg.index != kArmSp ? cast(4, false, value) : value;
        if (reg.index == kArmSp) { cur_[kArmSp] = v; dirty_[kArmSp] = false; return; }
        if (reg.index == kArmFp && v->kind == K::Frame) { cur_[kArmFp] = v; dirty_[kArmFp] = false; return; }
        write_full(reg.index, simple(v) ? v : materialize(v, reg.size));
    }

    EP arm_address(const ArmOp& m, bool use_updated) {
        EP addr = m.base >= 0 ? cur_[m.base] : konst(0);
        if (m.idx >= 0) {
            EP index = cur_[m.idx];
            if (m.idx_size == 4) index = cast(4, false, index);
            ArmOp mod; mod.modifier = m.modifier; mod.amount = m.amount;
            index = arm_apply_modifier(index, mod, 8);
            addr = bin("+", addr, index);
        }
        if (m.disp && !m.post) addr = bin("+", addr, konst(static_cast<std::uint64_t>(m.disp)));
        (void)use_updated;
        return addr;
    }

    void arm_set_base(const ArmOp& m, const EP& value) {
        if (m.base < 0) return;
        ArmOp reg; reg.type = ArmOp::T::Reg; reg.index = m.base; reg.size = 8;
        arm_write(reg, value);
    }

    EP arm_load(const EP& addr, int size, bool sign_extend, int dest_size) {
        if (addr->kind == K::Frame) cx_.frame_reads.insert(frame_offset(addr));
        EP v = new_temp(deref(size, addr), size);
        if (sign_extend) v = cast(dest_size, true, cast(size, true, v));
        return v;
    }
    void arm_store(const EP& addr, int size, const EP& value) { emit_store(size, addr, size < 8 ? cast(size, false, value) : value); }

    EP arm_cond(const std::string& cc_in) {
        static const std::map<std::string, std::string> names{{"eq", "e"}, {"ne", "ne"}, {"hs", "ae"}, {"cs", "ae"}, {"lo", "b"}, {"cc", "b"}, {"mi", "s"},
            {"pl", "ns"}, {"hi", "a"}, {"ls", "be"}, {"ge", "ge"}, {"lt", "l"}, {"gt", "g"}, {"le", "le"}, {"vs", "o"}, {"vc", "no"}};
        const auto it = names.find(cc_in);
        if (cc_in == "al") return konst(1, 1);
        return make_condition(it == names.end() ? cc_in : it->second);
    }

    void arm_call(const Instruction& ins, std::optional<std::uint64_t> direct_address, const ArmOp* reg_target) {
        std::string direct; EP indirect;
        if (direct_address) direct = name_for(*direct_address);
        else if (reg_target && reg_target->type == ArmOp::T::Reg && !reg_target->zr) indirect = cur_[reg_target->index];
        else indirect = konst(0);
        const std::uint32_t mask = defined_since_call_ | block_.arg_mask_in;
        EP call = callee_args_call(direct, indirect, mask);
        const bool noreturn = (!direct.empty() && noreturn_names().contains(strip_import_decoration(direct))) ||
                              (direct_address && cx_.options.is_noreturn && cx_.options.is_noreturn(*direct_address));
        const auto result = new_temp(call);
        for (int r = 0; r < 31; ++r)
            if (cx_.caller_saved.contains(r)) { cur_[r] = var(canonical_name(r)); dirty_[r] = false; }
        cur_[kArmLr] = var("x30"); dirty_[kArmLr] = false;
        cur_[kRax] = result; dirty_[kRax] = true; cx_.used_regs.insert(canonical_name(kRax));
        defined_since_call_ = 0; block_.arg_mask_in = 0;
        flags_ = {};
        (void)ins;
        if (noreturn) { block_.term.type = Terminator::T::NoReturn; terminated_ = true; done_ = true; }
    }

    void lift_arm(const Instruction& ins) {
        if (const auto sm = cx_.switch_mov.find(ins.address); sm != cx_.switch_mov.end()) switch_index_ = cur_[sm->second];
        if (cx_.switch_skip.contains(ins.address)) return;
        const std::uint64_t next = ins.address + ins.size;
        const std::string m = ins.mnemonic;
        const auto ops = arm_parse_operands(ins.operands);
        const auto op = [&](std::size_t i) -> const ArmOp& { static const ArmOp none; return i < ops.size() ? ops[i] : none; };
        const auto size_of = [&](const ArmOp& o) { return o.type == ArmOp::T::Reg ? o.size : 8; };

        if (m == "nop" || m == "hint" || m == "dmb" || m == "dsb" || m == "isb" || m == "prfm" || m == "prfum" || m == "yield" || m == "wfi" || m == "wfe" ||
            m == "bti" || m == "paciasp" || m == "autiasp" || m == "pacibsp" || m == "autibsp" || m == "csdb" || m == "dc" || m == "ic") return;
        if (m == "brk" || m == "udf" || m == "hlt") { block_.term.type = Terminator::T::NoReturn; terminated_ = true; done_ = true; return; }
        if (m == "ret" || m == "retaa" || m == "retab" || m == "eret") {
            block_.term.type = Terminator::T::Ret; block_.term.value = return_value(); block_.term.source = ins.address;
            terminated_ = true; done_ = true; if (block_.term.value) cx_.saw_return_value = true; return;
        }
        if (m == "bl") { arm_call(ins, arm_branch_target(ins), nullptr); return; }
        if (m == "blr" || m == "blraa" || m == "blrab") { arm_call(ins, std::nullopt, &op(0)); return; }
        if (m == "b") {
            const auto target = arm_branch_target(ins);
            block_.term.source = ins.address;
            if (target && !cx_.insn_at.contains(*target)) {
                arm_call(ins, target, nullptr);   // tail call
                block_.term.type = Terminator::T::Ret; block_.term.value = cur_[kRax]; block_.term.source = ins.address;
                cx_.saw_return_value = true; terminated_ = true; done_ = true; return;
            }
            block_.term.type = Terminator::T::Jmp; block_.term.taken = target.value_or(0);
            terminated_ = true; done_ = true; return;
        }
        if ((m == "br" || m == "braa" || m == "brab")) {
            if (const auto sw = cx_.switches.find(ins.address); sw != cx_.switches.end() && switch_index_) {
                block_.term.type = Terminator::T::Switch; block_.term.value = switch_index_; block_.term.source = ins.address;
                block_.term.cases = sw->second.targets; block_.term.default_target = sw->second.default_target;
                terminated_ = true; done_ = true; return;
            }
            block_.term.type = Terminator::T::IndirectJmp; block_.term.source = ins.address;
            block_.term.value = op(0).type == ArmOp::T::Reg && !op(0).zr ? cur_[op(0).index] : konst(0);
            terminated_ = true; done_ = true; return;
        }
        if (m.rfind("b.", 0) == 0) {
            block_.term.type = Terminator::T::Cond; block_.term.cond = arm_cond(m.substr(2));
            block_.term.taken = arm_branch_target(ins).value_or(0); block_.term.fallthrough = next;
            block_.term.source = ins.address; terminated_ = true; done_ = true; return;
        }
        if (m == "cbz" || m == "cbnz") {
            const EP v = arm_read(op(0), size_of(op(0)));
            block_.term.type = Terminator::T::Cond; block_.term.cond = bin(m == "cbz" ? "==" : "!=", v, konst(0));
            block_.term.taken = arm_branch_target(ins).value_or(0); block_.term.fallthrough = next;
            block_.term.source = ins.address; terminated_ = true; done_ = true; return;
        }
        if (m == "tbz" || m == "tbnz") {
            const EP v = arm_read(op(0), 8);
            const EP bit = bin("&", bin(">>", v, konst(static_cast<std::uint64_t>(op(1).imm))), konst(1));
            block_.term.type = Terminator::T::Cond; block_.term.cond = bin(m == "tbz" ? "==" : "!=", bit, konst(0));
            block_.term.taken = arm_branch_target(ins).value_or(0); block_.term.fallthrough = next;
            block_.term.source = ins.address; terminated_ = true; done_ = true; return;
        }

        // ---- data movement
        if ((m == "adrp" || m == "adr") && ops.size() >= 2) {
            if (const auto target = arm_branch_target(ins)) { arm_write(op(0), konst(*target)); return; }
        }
        if (m == "mov" && ops.size() == 2) { arm_write(op(0), arm_read(op(1), size_of(op(0)))); return; }
        if ((m == "movz" || m == "movn") && ops.size() >= 2) {
            std::uint64_t v = static_cast<std::uint64_t>(op(1).imm) << (op(1).modifier == "lsl" ? op(1).amount : 0);
            if (m == "movn") v = ~v;
            const int size = size_of(op(0)); if (size < 8) v &= mask_for(size);
            arm_write(op(0), konst(v, size)); return;
        }
        if (m == "movk" && ops.size() >= 2) {
            const int shift = op(1).modifier == "lsl" ? op(1).amount : 0;
            const std::uint64_t part = static_cast<std::uint64_t>(op(1).imm) << shift, hole = 0xFFFFull << shift;
            const EP old = op(0).zr ? konst(0) : cur_[op(0).index];
            if (old->kind == K::Const) arm_write(op(0), konst((old->imm & ~hole) | part));
            else arm_write(op(0), bin("|", bin("&", old, konst(~hole)), konst(part)));
            return;
        }
        if (m == "mvn" && ops.size() >= 2) { arm_write(op(0), bin("^", arm_read(op(1), size_of(op(0))), konst(~0ull))); return; }
        if ((m == "neg" || m == "negs") && ops.size() >= 2) {
            const int size = size_of(op(0)); const EP v = arm_read(op(1), size);
            arm_write(op(0), bin("-", konst(0), v));
            if (m == "negs") set_flags_cmp(konst(0), v, size);
            return;
        }

        // ---- arithmetic / logic
        const bool is_add = m == "add" || m == "adds", is_sub = m == "sub" || m == "subs";
        if ((is_add || is_sub) && ops.size() >= 3) {
            const int size = size_of(op(0));
            const EP a = arm_read(op(1), size), b = arm_read(op(2), size);
            const EP result = bin(is_add ? "+" : "-", a, b);
            arm_write(op(0), result);
            if (m == "subs") set_flags_cmp(a, b, size); else if (m == "adds") set_flags_result(result, size);
            return;
        }
        if ((m == "cmp" || m == "cmn") && ops.size() >= 2) {
            const int size = size_of(op(0));
            const EP a = arm_read(op(0), size), b = arm_read(op(1), size);
            if (m == "cmp") set_flags_cmp(a, b, size); else set_flags_result(bin("+", a, b), size);
            return;
        }
        if ((m == "tst") && ops.size() >= 2) { const int size = size_of(op(0)); set_flags_test(arm_read(op(0), size), arm_read(op(1), size), size); return; }
        const bool logic = m == "and" || m == "ands" || m == "orr" || m == "eor" || m == "bic" || m == "orn" || m == "eon" || m == "bics";
        if (logic && ops.size() >= 3) {
            const int size = size_of(op(0));
            const EP a = arm_read(op(1), size);
            EP b = arm_read(op(2), size);
            if (m == "bic" || m == "bics" || m == "orn" || m == "eon") b = bin("^", b, konst(size == 4 ? 0xFFFFFFFFull : ~0ull));
            const char* sym = (m == "and" || m == "ands" || m == "bic" || m == "bics") ? "&" : (m == "orr" || m == "orn") ? "|" : "^";
            const EP result = bin(sym, a, b);
            arm_write(op(0), result);
            if (m == "ands" || m == "bics") set_flags_test(a, b, size);
            return;
        }
        if ((m == "lsl" || m == "lsr" || m == "asr" || m == "ror") && ops.size() >= 3) {
            const int size = size_of(op(0));
            EP a = arm_read(op(1), size); const EP b = arm_read(op(2), size);
            EP result = m == "lsl" ? bin("<<", a, b) : m == "lsr" ? bin(">>", size == 4 ? cast(4, false, a) : a, b)
                      : m == "asr" ? bin(">>", arm_signed(a, size), b) : intrin("__ror", {a, b});
            arm_write(op(0), result); return;
        }
        if ((m == "mul" || m == "mneg") && ops.size() >= 3) {
            const int size = size_of(op(0)); EP r = bin("*", arm_read(op(1), size), arm_read(op(2), size));
            arm_write(op(0), m == "mneg" ? bin("-", konst(0), r) : r); return;
        }
        if ((m == "madd" || m == "msub") && ops.size() >= 4) {
            const int size = size_of(op(0));
            const EP prod = bin("*", arm_read(op(1), size), arm_read(op(2), size)), acc = arm_read(op(3), size);
            arm_write(op(0), m == "madd" ? bin("+", acc, prod) : bin("-", acc, prod)); return;
        }
        if ((m == "smull" || m == "umull") && ops.size() >= 3) {
            const bool s = m == "smull";
            const EP a = cast(8, s, cast(4, s, cur_[op(1).index])), b = cast(8, s, cast(4, s, cur_[op(2).index]));
            arm_write(op(0), bin("*", a, b)); return;
        }
        if ((m == "smulh" || m == "umulh") && ops.size() >= 3) { arm_write(op(0), intrin(m == "smulh" ? "__mulhi" : "__umulhi", {arm_read(op(1), 8), arm_read(op(2), 8)})); return; }
        if ((m == "sdiv" || m == "udiv") && ops.size() >= 3) {
            const int size = size_of(op(0)); const bool s = m == "sdiv";
            const EP a = arm_read(op(1), size), b = arm_read(op(2), size);
            arm_write(op(0), bin("/", s ? arm_signed(a, size) : a, s ? arm_signed(b, size) : b)); return;
        }
        if ((m == "sxtw" || m == "sxth" || m == "sxtb" || m == "uxtb" || m == "uxth") && ops.size() >= 2) {
            const int from = (m == "sxtw") ? 4 : (m == "sxth" || m == "uxth") ? 2 : 1; const bool s = m[0] == 's';
            arm_write(op(0), cast(size_of(op(0)), s, cast(from, s, cur_[op(1).index]))); return;
        }
        if (m == "ubfiz" && ops.size() >= 4) {
            const int size = size_of(op(0));
            const std::uint64_t lsb = static_cast<std::uint64_t>(op(2).imm), width = static_cast<std::uint64_t>(op(3).imm);
            arm_write(op(0), bin("<<", bin("&", arm_read(op(1), size), konst(width >= 64 ? ~0ull : ((1ull << width) - 1))), konst(lsb))); return;
        }
        if ((m == "ubfx" || m == "sbfx") && ops.size() >= 4) {
            const int size = size_of(op(0)); const bool s = m == "sbfx";
            const std::uint64_t lsb = static_cast<std::uint64_t>(op(2).imm), width = static_cast<std::uint64_t>(op(3).imm);
            EP v = arm_read(op(1), size);
            EP field = bin("&", bin(">>", s ? arm_signed(v, size) : v, konst(lsb)), konst(width >= 64 ? ~0ull : ((1ull << width) - 1)));
            arm_write(op(0), s ? intrin("__sbfx", {v, konst(lsb), konst(width)}) : field); return;
        }
        if ((m == "csel" || m == "csinc" || m == "csinv" || m == "csneg") && ops.size() >= 4) {
            const int size = size_of(op(0));
            const EP cond = arm_cond(trim(ops[3].text));
            const EP a = arm_read(op(1), size);
            EP b = arm_read(op(2), size);
            if (m == "csinc") b = bin("+", b, konst(1)); else if (m == "csinv") b = bin("^", b, konst(~0ull)); else if (m == "csneg") b = bin("-", konst(0), b);
            arm_write(op(0), tern(cond, a, b)); return;
        }
        if ((m == "cset" || m == "csetm") && ops.size() >= 2) {
            const EP cond = arm_cond(trim(ops[1].text));
            arm_write(op(0), tern(cond, konst(m == "cset" ? 1 : ~0ull), konst(0))); return;
        }
        if ((m == "cinc" || m == "cinv" || m == "cneg") && ops.size() >= 3) {
            const int size = size_of(op(0)); const EP cond = arm_cond(trim(ops[2].text)); const EP a = arm_read(op(1), size);
            EP alt = m == "cinc" ? bin("+", a, konst(1)) : m == "cinv" ? bin("^", a, konst(~0ull)) : bin("-", konst(0), a);
            arm_write(op(0), tern(cond, alt, a)); return;
        }

        if (m == "svc") {
            const EP result = new_temp(intrin("syscall", {cur_[8], cur_[0], cur_[1], cur_[2], cur_[3], cur_[4], cur_[5]}));
            write_full(0, result); return;
        }
        if ((m == "ccmp" || m == "ccmn") && ops.size() >= 4) {
            const int size = size_of(op(0));
            const EP a = arm_read(op(0), size);
            EP b = arm_read(op(1), size);
            if (m == "ccmn") b = bin("-", konst(0), b);
            Flags chained;
            chained.type = Flags::T::Chain; chained.prev = std::make_shared<const Flags>(flags_);
            chained.prev_cc = arm_cc_to_x86(trim(ops[3].text)); chained.a = a; chained.b = b; chained.size = size;
            chained.nzcv = static_cast<int>(op(2).imm);
            flags_ = chained; return;
        }
        if ((m == "umaddl" || m == "smaddl" || m == "umsubl" || m == "smsubl") && ops.size() >= 4) {
            const bool s = m[0] == 's';
            const EP prod = bin("*", cast(8, s, cast(4, s, arm_read(op(1), 8))), cast(8, s, cast(4, s, arm_read(op(2), 8))));
            const EP acc = arm_read(op(3), 8);
            arm_write(op(0), m.find("add") != std::string::npos ? bin("+", acc, prod) : bin("-", acc, prod)); return;
        }
        if ((m == "umull" || m == "smull") && false) return;

        // ---- floating point / SIMD registers (tracked inside the block only)
        if ((m == "ldr" || m == "ldur" || m == "ldp" || m == "ldnp" || m == "str" || m == "stur" || m == "stp" || m == "stnp") && ops.size() >= 2 && op(0).type == ArmOp::T::Fp) {
            const bool pair = m == "ldp" || m == "stp" || m == "ldnp" || m == "stnp";
            const ArmOp& mem = pair ? op(2) : op(1);
            if (mem.type == ArmOp::T::Mem) {
                const bool store = m[0] == 's';
                const int size = op(0).fp_size;
                const EP addr = arm_address(mem, false);
                if (mem.pre) arm_set_base(mem, addr);
                for (int r = 0; r < (pair ? 2 : 1); ++r) {
                    const EP at = r ? bin("+", addr, konst(static_cast<std::uint64_t>(size))) : addr;
                    if (store) arm_store(at, size, fp_read(op(r)));
                    else fp_write(op(r), arm_load(at, size, false, size));
                }
                if (mem.post && mem.base >= 0) arm_set_base(mem, bin("+", cur_[mem.base], konst(static_cast<std::uint64_t>(mem.disp))));
                return;
            }
        }
        if (m == "fmov" && ops.size() == 2) {
            if (op(0).type == ArmOp::T::Fp && op(1).type == ArmOp::T::Reg) { fp_write(op(0), arm_read(op(1), 8)); return; }
            if (op(0).type == ArmOp::T::Reg && op(1).type == ArmOp::T::Fp) { arm_write(op(0), fp_read(op(1))); return; }
            if (op(0).type == ArmOp::T::Fp && op(1).type == ArmOp::T::Fp) { fp_write(op(0), fp_read(op(1))); return; }
            if (op(0).type == ArmOp::T::Fp) { fp_write(op(0), intrin("__fimm", {})); return; }
        }
        if ((m == "fcmp" || m == "fcmpe") && ops.size() >= 2) {
            Flags f; f.type = Flags::T::Cmp; f.fp = true; f.size = 8;
            f.a = op(0).type == ArmOp::T::Fp ? fp_read(op(0)) : konst(0);
            f.b = op(1).type == ArmOp::T::Fp ? fp_read(op(1)) : konst(0);
            flags_ = f; return;
        }

        // ---- memory
        const auto load_size = [&](const std::string& mn, int dest_size, bool& sign) {
            sign = mn.find("sw") != std::string::npos || mn == "ldrsb" || mn == "ldrsh" || mn == "ldursb" || mn == "ldursh";
            if (mn == "ldrb" || mn == "ldurb" || mn == "ldrsb" || mn == "ldursb" || mn == "ldarb" || mn == "ldaxrb") return 1;
            if (mn == "ldrh" || mn == "ldurh" || mn == "ldrsh" || mn == "ldursh" || mn == "ldarh") return 2;
            if (mn == "ldrsw" || mn == "ldursw") return 4;
            return dest_size;
        };
        if ((m == "ldr" || m == "ldrb" || m == "ldrh" || m == "ldrsw" || m == "ldrsb" || m == "ldrsh" || m == "ldur" || m == "ldurb" || m == "ldurh" ||
             m == "ldursw" || m == "ldar" || m == "ldarb" || m == "ldarh" || m == "ldxr" || m == "ldaxr") && ops.size() >= 2 && op(0).type == ArmOp::T::Reg) {
            bool sign = false; const int dest = size_of(op(0)); const int size = load_size(m, dest, sign);
            if (op(1).type == ArmOp::T::Imm || op(1).type == ArmOp::T::Text) {   // ldr x0, #literal
                if (const auto target = arm_branch_target(ins)) { arm_write(op(0), arm_load(konst(*target), size, sign, 8)); return; }
            }
            if (op(1).type == ArmOp::T::Mem) {
                const EP addr = arm_address(op(1), false);
                if (op(1).pre) arm_set_base(op(1), addr);
                arm_write(op(0), arm_load(addr, size, sign, dest));
                if (op(1).post && op(1).base >= 0) arm_set_base(op(1), bin("+", cur_[op(1).base], konst(static_cast<std::uint64_t>(op(1).disp))));
                return;
            }
        }
        if ((m == "str" || m == "strb" || m == "strh" || m == "stur" || m == "sturb" || m == "sturh" || m == "stlr" || m == "stlrb" || m == "stlrh") && ops.size() >= 2 &&
            op(0).type == ArmOp::T::Reg && op(1).type == ArmOp::T::Mem) {
            const int size = (m == "strb" || m == "sturb" || m == "stlrb") ? 1 : (m == "strh" || m == "sturh" || m == "stlrh") ? 2 : size_of(op(0));
            const EP value = arm_read(op(0), size);
            const EP addr = arm_address(op(1), false);
            if (op(1).pre) arm_set_base(op(1), addr);
            arm_store(addr, size, value);
            if (op(1).post && op(1).base >= 0) arm_set_base(op(1), bin("+", cur_[op(1).base], konst(static_cast<std::uint64_t>(op(1).disp))));
            return;
        }
        if ((m == "stp" || m == "ldp" || m == "ldpsw") && ops.size() >= 3 && op(2).type == ArmOp::T::Mem) {
            const int size = m == "ldpsw" ? 4 : size_of(op(0));
            const EP addr = arm_address(op(2), false);
            if (op(2).pre) arm_set_base(op(2), addr);
            const EP second = bin("+", addr, konst(static_cast<std::uint64_t>(size)));
            if (m == "stp") { arm_store(addr, size, arm_read(op(0), size)); arm_store(second, size, arm_read(op(1), size)); }
            else {
                const EP a = arm_load(addr, size, m == "ldpsw", 8), b = arm_load(second, size, m == "ldpsw", 8);
                // callee-saved restores (x29/x30/x19-x28 from the frame) keep the register unchanged
                const auto restores = [&](const ArmOp& r) { return r.type == ArmOp::T::Reg && !r.zr && cx_.callee_saved.contains(r.index) && addr->kind == K::Frame; };
                if (restores(op(0))) { cur_[op(0).index] = var(canonical_name(op(0).index)); dirty_[op(0).index] = false; } else arm_write(op(0), a);
                if (restores(op(1))) { cur_[op(1).index] = var(canonical_name(op(1).index)); dirty_[op(1).index] = false; } else arm_write(op(1), b);
            }
            if (op(2).post && op(2).base >= 0) arm_set_base(op(2), bin("+", cur_[op(2).base], konst(static_cast<std::uint64_t>(op(2).disp))));
            return;
        }

        // ---- anything else (floating point, SIMD, atomics, system): opaque intrinsic on the first register
        std::vector<EP> args;
        for (std::size_t i = (ops.size() && (ops[0].type == ArmOp::T::Reg || ops[0].type == ArmOp::T::Fp) ? 1 : 0); i < ops.size(); ++i) {
            if (ops[i].type == ArmOp::T::Fp) args.push_back(fp_read(ops[i]));
            else if (ops[i].type == ArmOp::T::Reg) args.push_back(arm_read(ops[i], size_of(ops[i])));
            else if (ops[i].type == ArmOp::T::Imm) args.push_back(konst(static_cast<std::uint64_t>(ops[i].imm)));
            else if (ops[i].type == ArmOp::T::Mem) args.push_back(deref(8, arm_address(ops[i], false)));
        }
        const EP result = intrin("__" + m, std::move(args));
        if (!ops.empty() && ops[0].type == ArmOp::T::Fp) fp_write(ops[0], result);
        else if (!ops.empty() && ops[0].type == ArmOp::T::Reg && !ops[0].zr) arm_write(ops[0], result);
        else emit_eval(result);
        flags_ = {};
    }

    void finish() {
        if (!terminated_) {
            block_.term.type = Terminator::T::Fall;
            if (block_.last < cx_.insns.size()) block_.term.fallthrough = cx_.insns[block_.last].address;
            else block_.term.type = Terminator::T::NoReturn;
        }
        if (block_.term.type == Terminator::T::Ret || block_.term.type == Terminator::T::NoReturn) {
            // Register state is irrelevant when leaving the function.
        } else {
            for (int r = 0; r < kRegCount; ++r) {
                if (r == (g_arm ? kArmSp : kRsp)) continue;
                if (cur_[r]->kind == K::Frame) continue;
                if (cur_[r]->kind == K::Var && cur_[r]->name == canonical_name(r)) continue;
                block_.moves.push_back({var(canonical_name(r), r >= xmm_base() ? 16 : 8), cur_[r]});
                if (g_arm || r < 16) cx_.used_regs.insert(canonical_name(r));
            }
        }
        block_.entry_rsp = cur_[g_arm ? kArmSp : kRsp];
        exit_rsp = cur_[g_arm ? kArmSp : kRsp];
        exit_rbp = cur_[g_arm ? kArmFp : kRbp];
        (void)index_;
    }

public:
    EP exit_rsp, exit_rbp;
    EP switch_index_;
    std::uint64_t current_switch_jump_{0};
    std::map<int, EP> fp_;
    std::vector<EP> st_;                  // x87 register stack (top is back); only tracked inside one block
    EP fpu_a_, fpu_b_;
    bool fpu_status_pending_{false};
    std::uint32_t fp_defined_since_call_{0};
};

// ---------------------------------------------------------------------------
// Jump tables (switch statements)
// ---------------------------------------------------------------------------
std::string mnemonic_of(const Instruction& ins) {
    std::string m = ins.mnemonic;
    for (const char* p : {"rep ", "repe ", "repne ", "repz ", "repnz ", "lock ", "bnd ", "notrack "})
        if (m.rfind(p, 0) == 0) m = m.substr(std::string(p).size());
    return m;
}

void finish_switches(Ctx& cx, std::vector<SwitchInfo>& found) {
    if (found.empty()) return;
    const auto& image = cx.image;
    // Decode the case bodies that are not part of the instruction list yet.
    std::set<std::uint64_t> known; for (const auto& ins : cx.insns) known.insert(ins.address);
    std::vector<std::uint64_t> work;
    for (const auto& info : found) { for (const auto t : info.targets) work.push_back(t); if (info.default_target) work.push_back(info.default_target); }
    const std::uint64_t low = cx.start, high = cx.insns.back().address + 0x4000;
    std::size_t added = 0;
    while (!work.empty() && added < 800) {
        const std::uint64_t address = work.back(); work.pop_back();
        if (known.contains(address) || address < low || address > high) continue;
        const auto decoded = decode_instructions(image, address, 160);
        for (const auto& ins : decoded) {
            if (known.contains(ins.address)) break;
            known.insert(ins.address); cx.insns.push_back(ins); ++added;
            const std::string m = mnemonic_of(ins);
            if (g_arm) {
                if (m == "ret" || m == "br" || m == "brk" || m == "udf" || m == "hlt" || m == "eret") break;
                if (m == "b" || arm_is_cond_branch(m)) {
                    if (const auto target = arm_branch_target(ins)) work.push_back(*target);
                    if (m == "b") break;
                }
                continue;
            }
            if (m == "ret" || m == "retn" || m == "ud2" || m == "hlt" || m == "int3") break;
            if (m == "jmp" || is_conditional_jump(m)) {
                const Operand o = parse_operand(ins.operands);
                if (o.type == Operand::T::Imm) work.push_back(static_cast<std::uint64_t>(o.imm));
                if (m == "jmp") break;
            }
        }
    }
    std::sort(cx.insns.begin(), cx.insns.end(), [](const Instruction& a, const Instruction& b) { return a.address < b.address; });
    cx.insn_at.clear();
    for (std::size_t i = 0; i < cx.insns.size(); ++i) cx.insn_at[cx.insns[i].address] = i;
    for (auto& info : found) {
        cx.switch_mov[info.mov] = info.idx_reg;
        cx.switch_skip.insert(info.mov); if (info.add) cx.switch_skip.insert(info.add); if (info.lea) cx.switch_skip.insert(info.lea);
        const auto key = info.jmp; cx.switches[key] = std::move(info);
    }
}



// AArch64 jump tables: adrp/add table base, ldrb/ldrh/ldr[sw] entry, add anchor + (entry << n), br.
void find_arm_switches(Ctx& cx) {
    const auto& image = cx.image;
    const std::size_t original = cx.insns.size();
    std::vector<SwitchInfo> found;
    for (std::size_t k = 0; k < original; ++k) {
        if (cx.insns[k].mnemonic != "br") continue;
        const auto jops = arm_parse_operands(cx.insns[k].operands);
        if (jops.empty() || jops[0].type != ArmOp::T::Reg || jops[0].zr) continue;
        const int jreg = jops[0].index;
        struct Load { std::size_t at{0}; int dest{-1}, base{-1}, idx{-1}, size{4}; bool sign{false}; };
        std::map<int, std::uint64_t> constants;
        std::optional<Load> load;
        std::size_t add_at = original; ArmOp anchor, extra;
        for (std::size_t j = k > 18 ? k - 18 : 0; j < k; ++j) {
            const auto& ins = cx.insns[j];
            const std::string& m = ins.mnemonic;
            const auto ops = arm_parse_operands(ins.operands);
            if (m == "b" || m == "ret" || m == "bl" || m == "blr") { constants.clear(); load.reset(); add_at = original; continue; }
            if ((m == "adrp" || m == "adr") && ops.size() >= 2 && ops[0].type == ArmOp::T::Reg) {
                if (const auto t = arm_branch_target(ins)) constants[ops[0].index] = *t; else constants.erase(ops[0].index);
                continue;
            }
            if (m == "add" && ops.size() >= 3 && ops[0].type == ArmOp::T::Reg && ops[1].type == ArmOp::T::Reg && ops[2].type == ArmOp::T::Imm) {
                if (const auto c = constants.find(ops[1].index); c != constants.end())
                    constants[ops[0].index] = c->second + (static_cast<std::uint64_t>(ops[2].imm) << (ops[2].modifier == "lsl" ? ops[2].amount : 0));
                else constants.erase(ops[0].index);
                continue;
            }
            if ((m == "ldrb" || m == "ldrh" || m == "ldr" || m == "ldrsw" || m == "ldrsb" || m == "ldrsh") && ops.size() >= 2 && ops[0].type == ArmOp::T::Reg &&
                ops[1].type == ArmOp::T::Mem && ops[1].base >= 0 && ops[1].idx >= 0 && constants.contains(ops[1].base)) {
                Load l; l.at = j; l.dest = ops[0].index; l.base = ops[1].base; l.idx = ops[1].idx;
                l.size = (m == "ldrb" || m == "ldrsb") ? 1 : (m == "ldrh" || m == "ldrsh") ? 2 : (m == "ldrsw") ? 4 : ops[0].size;
                l.sign = m == "ldrsw" || m == "ldrsb" || m == "ldrsh";
                load = l; continue;
            }
            if (m == "add" && ops.size() >= 3 && ops[0].type == ArmOp::T::Reg && ops[0].index == jreg && ops[1].type == ArmOp::T::Reg && ops[2].type == ArmOp::T::Reg &&
                load && ops[2].index == load->dest && constants.contains(ops[1].index)) { add_at = j; anchor = ops[1]; extra = ops[2]; continue; }
            if (arm_dest_register(ins) == jreg || (load && arm_dest_register(ins) == load->dest && j != load->at)) { /* redefined: keep scanning */ }
        }
        if (!load || add_at == original) continue;
        // Range check: cmp idx, #N ; b.hi / b.hs default
        std::size_t count = 0; std::uint64_t default_target = 0;
        for (std::size_t j = load->at; j-- > 0 && load->at - j <= 40;) {
            if (cx.insns[j].mnemonic != "cmp" || j + 1 >= original) continue;
            const auto o = arm_parse_operands(cx.insns[j].operands);
            if (o.size() < 2 || o[0].type != ArmOp::T::Reg || o[0].index != load->idx || o[1].type != ArmOp::T::Imm || o[1].imm < 0 || o[1].imm > 1024) continue;
            const std::string& next = cx.insns[j + 1].mnemonic;
            if (next != "b.hi" && next != "b.hs" && next != "b.cs") continue;
            count = static_cast<std::size_t>(o[1].imm) + (next == "b.hi" ? 1 : 0);
            if (const auto t = arm_branch_target(cx.insns[j + 1])) default_target = *t;
            break;
        }
        if (count < 2 || count > 1024) continue;
        const std::uint64_t base = constants[load->base], anchor_value = constants[anchor.index];
        const int shift = extra.modifier == "lsl" || extra.modifier.rfind("sxt", 0) == 0 || extra.modifier.rfind("uxt", 0) == 0 ? extra.amount : 0;
        SwitchInfo info; info.jmp = cx.insns[k].address; info.mov = cx.insns[load->at].address; info.add = cx.insns[add_at].address;
        info.idx_reg = load->idx; info.default_target = default_target;
        bool valid = true;
        for (std::size_t i = 0; i < count && valid; ++i) {
            const auto offset = image.va_to_file_offset(base + i * static_cast<std::size_t>(load->size));
            if (!offset || *offset + static_cast<std::size_t>(load->size) > image.bytes.size()) { valid = false; break; }
            std::uint64_t value = 0;
            for (int b = 0; b < load->size; ++b) value |= static_cast<std::uint64_t>(image.bytes[*offset + static_cast<std::size_t>(b)]) << (8 * b);
            std::int64_t extended = static_cast<std::int64_t>(value);
            const bool signed_extend = load->sign || extra.modifier == "sxtb" || extra.modifier == "sxth" || extra.modifier == "sxtw";
            if (signed_extend && load->size < 8 && (value & (1ull << (load->size * 8 - 1)))) extended = static_cast<std::int64_t>(value | ~mask_for(load->size));
            const std::uint64_t destination = anchor_value + (static_cast<std::uint64_t>(extended) << shift);
            if (!is_code_address(image, destination) && !cx.insn_at.contains(destination)) valid = false;
            info.targets.push_back(destination);
        }
        if (!valid) continue;
        found.push_back(std::move(info));
    }
    finish_switches(cx, found);
}

// Recognises `cmp idx, N ; ja default ; ... ; mov r, [base + idx*4 + table] ; add r, base ; jmp r`
// (and the absolute `jmp [idx*8 + table]` form), reads the table from the image and decodes the case
// bodies that the linear function discovery did not reach.
void find_switches(Ctx& cx) {
    if (g_arm) { find_arm_switches(cx); return; }
    const auto& image = cx.image;
    const std::size_t original = cx.insns.size();
    std::vector<SwitchInfo> found;
    for (std::size_t k = 0; k < original; ++k) {
        if (mnemonic_of(cx.insns[k]) != "jmp") continue;
        const auto ops = split_operands(cx.insns[k].operands);
        if (ops.empty()) continue;
        const Operand target = parse_operand(ops[0]);
        SwitchInfo info; info.jmp = cx.insns[k].address;
        std::uint64_t table = 0; bool relative = false; std::size_t mov_index = original;
        if (target.type == Operand::T::Reg && target.reg.size == 8) {
            int base_reg = -1; bool seen_add = false;
            for (std::size_t j = k; j-- > 0 && k - j <= 10;) {
                const std::string m = mnemonic_of(cx.insns[j]);
                if (m == "jmp" || m == "ret" || m == "call") break;
                const auto o = split_operands(cx.insns[j].operands);
                if (mov_index != original) {   // table load already found: look for `lea base, [image base]`
                    if (m == "lea" && o.size() == 2) {
                        const Operand a = parse_operand(o[0]), b = parse_operand(o[1]);
                        if (a.type == Operand::T::Reg && a.reg.index == base_reg && b.type == Operand::T::Mem && b.mem.rip &&
                            cx.insns[j].address + cx.insns[j].size + static_cast<std::uint64_t>(b.mem.disp) == image.image_base) { info.lea = cx.insns[j].address; break; }
                    }
                    continue;
                }
                if (!seen_add && m == "add" && o.size() == 2) {
                    const Operand a = parse_operand(o[0]), b = parse_operand(o[1]);
                    if (a.type == Operand::T::Reg && a.reg.index == target.reg.index && b.type == Operand::T::Reg && b.reg.size == 8) { base_reg = b.reg.index; seen_add = true; info.add = cx.insns[j].address; }
                    continue;
                }
                if (seen_add && (m == "mov" || m == "movsxd" || m == "movzx") && o.size() == 2) {
                    const Operand a = parse_operand(o[0]), b = parse_operand(o[1]);
                    if (a.type == Operand::T::Reg && a.reg.index == target.reg.index && b.type == Operand::T::Mem && !b.mem.rip &&
                        b.mem.base == base_reg && b.mem.index >= 0 && b.mem.scale == 4) {
                        info.idx_reg = b.mem.index; mov_index = j;
                        table = b.mem.disp >= static_cast<std::int64_t>(image.image_base) ? static_cast<std::uint64_t>(b.mem.disp) : image.image_base + static_cast<std::uint64_t>(b.mem.disp);
                        relative = true; continue;
                    }
                }
            }
        } else if (target.type == Operand::T::Mem && !target.mem.rip && target.mem.base < 0 && target.mem.index >= 0 && target.mem.scale == 8 &&
                   target.mem.disp >= static_cast<std::int64_t>(image.image_base)) {
            info.idx_reg = target.mem.index; mov_index = k; table = static_cast<std::uint64_t>(target.mem.disp); relative = false;
        }
        if (info.idx_reg < 0 || mov_index >= original) continue;
        // Range check: cmp idx, N / ja|jae default  (within 40 instructions before the table load).
        std::size_t count = 0;
        for (std::size_t j = mov_index; j-- > 0 && mov_index - j <= 40;) {
            if (mnemonic_of(cx.insns[j]) != "cmp" || j + 1 >= original) continue;
            const auto o = split_operands(cx.insns[j].operands);
            if (o.size() != 2) continue;
            const Operand a = parse_operand(o[0]), b = parse_operand(o[1]);
            if (a.type != Operand::T::Reg || a.reg.index != info.idx_reg || b.type != Operand::T::Imm || b.imm < 0 || b.imm > 1024) continue;
            const std::string next = mnemonic_of(cx.insns[j + 1]);
            if (next != "ja" && next != "jae" && next != "jnbe" && next != "jnb" && next != "jg") continue;
            count = static_cast<std::size_t>(b.imm) + ((next == "ja" || next == "jnbe" || next == "jg") ? 1 : 0);
            const Operand jt = parse_operand(cx.insns[j + 1].operands);
            if (jt.type == Operand::T::Imm) info.default_target = static_cast<std::uint64_t>(jt.imm);
            break;
        }
        if (count < 2 || count > 1024) continue;
        const auto offset = image.va_to_file_offset(table);
        if (!offset) continue;
        const std::size_t width = relative ? 4 : 8;
        if (*offset + count * width > image.bytes.size()) continue;
        bool valid = true;
        for (std::size_t i = 0; i < count && valid; ++i) {
            std::uint64_t value = 0;
            for (std::size_t b = 0; b < width; ++b) value |= static_cast<std::uint64_t>(image.bytes[*offset + i * width + b]) << (8 * b);
            const std::uint64_t destination = relative ? image.image_base + (value & 0xFFFFFFFFull) : value;
            if (!is_code_address(image, destination)) valid = false;
            info.targets.push_back(destination);
        }
        if (!valid) continue;
        info.mov = cx.insns[mov_index].address;
        found.push_back(std::move(info));
    }
    finish_switches(cx, found);
}
// ---------------------------------------------------------------------------
// Block construction
// ---------------------------------------------------------------------------
void build_blocks(Ctx& cx) {
    std::set<std::uint64_t> leaders;
    leaders.insert(cx.start);
    if (g_arm) {
        for (std::size_t i = 0; i < cx.insns.size(); ++i) {
            const auto& ins = cx.insns[i];
            const bool cond = arm_is_cond_branch(ins.mnemonic), plain = ins.mnemonic == "b", ender = arm_is_ender(ins.mnemonic);
            if (cond || plain) {
                const auto target = arm_branch_target(ins);
                if (target && cx.insn_at.contains(*target)) leaders.insert(*target);
            }
            if ((cond || plain || ender) && i + 1 < cx.insns.size()) leaders.insert(cx.insns[i + 1].address);
        }
        std::size_t k = 0;
        while (k < cx.insns.size()) {
            Block block; block.address = cx.insns[k].address; block.first = k;
            std::size_t j = k + 1;
            while (j < cx.insns.size() && !leaders.contains(cx.insns[j].address)) ++j;
            block.last = j;
            cx.block_at[block.address] = static_cast<int>(cx.blocks.size());
            cx.blocks.push_back(std::move(block));
            k = j;
        }
        return;
    }
    for (const auto& [jmp, info] : cx.switches) for (const auto target : info.targets) if (cx.insn_at.contains(target)) leaders.insert(target);
    for (std::size_t i = 0; i < cx.insns.size(); ++i) {
        const auto& ins = cx.insns[i];
        std::string m = ins.mnemonic;
        const auto sp = m.find(' '); if (sp != std::string::npos) m = m.substr(sp + 1);
        const bool is_jcc = is_conditional_jump(m);
        const bool is_jmp = m == "jmp";
        if (is_jcc || is_jmp) {
            const auto o = parse_operand(ins.operands);
            if (o.type == Operand::T::Imm && cx.insn_at.contains(static_cast<std::uint64_t>(o.imm))) leaders.insert(static_cast<std::uint64_t>(o.imm));
            if (i + 1 < cx.insns.size()) leaders.insert(cx.insns[i + 1].address);
        } else if (m == "ret" || m == "retn" || m == "retf" || m == "ud2" || m == "hlt") {
            if (i + 1 < cx.insns.size()) leaders.insert(cx.insns[i + 1].address);
        }
    }
    std::size_t i = 0;
    while (i < cx.insns.size()) {
        Block block; block.address = cx.insns[i].address; block.first = i;
        std::size_t j = i + 1;
        while (j < cx.insns.size() && !leaders.contains(cx.insns[j].address)) ++j;
        block.last = j;
        cx.block_at[block.address] = static_cast<int>(cx.blocks.size());
        cx.blocks.push_back(std::move(block));
        i = j;
    }
}


// Instructions that overwrite their first (register) operand.
bool writes_first_operand(const std::string& m) {
    static const std::set<std::string> writers{
        "mov", "movabs", "movzx", "movsx", "movsxd", "lea", "add", "sub", "and", "or", "xor", "imul", "shl", "shr",
        "sar", "sal", "rol", "ror", "neg", "not", "inc", "dec", "adc", "sbb", "pop", "xchg", "movq", "movd", "bsf",
        "bsr", "popcnt", "lzcnt", "tzcnt", "bswap", "cvttsd2si", "cvttss2si"};
    return writers.contains(m) || m.rfind("cmov", 0) == 0 || m.rfind("set", 0) == 0;
}

std::string base_mnemonic(const std::string& m) {
    for (const char* p : {"rep ", "repe ", "repne ", "repz ", "repnz ", "lock ", "bnd ", "notrack "})
        if (m.rfind(p, 0) == 0) return m.substr(std::string(p).size());
    return m;
}

// Raw (pre-lift) successor edges, used only for the argument-register analysis.
std::vector<std::vector<int>> raw_edges(const Ctx& cx) {
    std::vector<std::vector<int>> succ(cx.blocks.size());
    for (std::size_t b = 0; b < cx.blocks.size(); ++b) {
        const auto& last = cx.insns[cx.blocks[b].last - 1];
        if (g_arm) {
            const int next_block = b + 1 < cx.blocks.size() ? static_cast<int>(b + 1) : -1;
            const auto target_block = [&]() -> int {
                const auto t = arm_branch_target(last);
                if (!t) return -1;
                const auto it = cx.block_at.find(*t);
                return it == cx.block_at.end() ? -1 : it->second;
            };
            if (arm_is_ender(last.mnemonic)) continue;
            if (last.mnemonic == "b") { if (const int t = target_block(); t >= 0) succ[b].push_back(t); continue; }
            if (arm_is_cond_branch(last.mnemonic)) { if (const int t = target_block(); t >= 0) succ[b].push_back(t); if (next_block >= 0) succ[b].push_back(next_block); continue; }
            if (next_block >= 0) succ[b].push_back(next_block);
            continue;
        }
        const std::string m = base_mnemonic(last.mnemonic);
        const auto target = [&]() -> int {
            const auto o = parse_operand(last.operands);
            if (o.type != Operand::T::Imm) return -1;
            const auto it = cx.block_at.find(static_cast<std::uint64_t>(o.imm));
            return it == cx.block_at.end() ? -1 : it->second;
        };
        const int next = b + 1 < cx.blocks.size() ? static_cast<int>(b + 1) : -1;
        if (m == "ret" || m == "retn" || m == "retf" || m == "ud2" || m == "hlt") continue;
        if (m == "jmp") {
            if (const auto sw = cx.switches.find(last.address); sw != cx.switches.end()) {
                for (const auto t : sw->second.targets) if (const auto it = cx.block_at.find(t); it != cx.block_at.end()) succ[b].push_back(it->second);
                continue;
            }
            if (const int t = target(); t >= 0) succ[b].push_back(t);
            continue;
        }
        if (is_conditional_jump(m)) {
            if (const int t = target(); t >= 0) succ[b].push_back(t);
            if (next >= 0) succ[b].push_back(next);
            continue;
        }
        if (next >= 0) succ[b].push_back(next);
    }
    return succ;
}

// May-analysis: which registers were written since the most recent call.
void compute_arg_masks(Ctx& cx) {
    const std::size_t n = cx.blocks.size();
    const auto succ = raw_edges(cx);
    std::vector<std::uint32_t> in(n, 0), out(n, 0), gen(n, 0);
    std::vector<bool> has_call(n, false);
    for (std::size_t b = 0; b < n; ++b) {
        std::uint32_t mask = 0; bool call_seen = false;
        for (std::size_t i = cx.blocks[b].first; i < cx.blocks[b].last; ++i) {
            const auto& ins = cx.insns[i];
            if (cx.switch_skip.contains(ins.address)) continue;
            if (g_arm) {
                if (ins.mnemonic == "bl" || ins.mnemonic == "blr") { mask = 0; call_seen = true; continue; }
                const int dest = arm_dest_register(ins);
                if (dest >= 0 && dest < 32) mask |= (1u << dest);
                continue;
            }
            const std::string m = base_mnemonic(ins.mnemonic);
            if (m == "call") { mask = 0; call_seen = true; continue; }
            if (!writes_first_operand(m)) continue;
            const auto ops = split_operands(ins.operands);
            if (ops.empty()) continue;
            const auto o = parse_operand(ops[0]);
            if (o.type == Operand::T::Reg && o.reg.index < 16) mask |= (1u << o.reg.index);
        }
        gen[b] = mask; has_call[b] = call_seen;
    }
    bool changed = true;
    int guard = 0;
    while (changed && guard++ < 200) {
        changed = false;
        for (std::size_t b = 0; b < n; ++b) {
            std::uint32_t new_in = 0;
            for (std::size_t p = 0; p < n; ++p) for (const int s : succ[p]) if (s == static_cast<int>(b)) new_in |= out[p];
            const std::uint32_t new_out = has_call[b] ? gen[b] : (new_in | gen[b]);
            if (new_in != in[b] || new_out != out[b]) { in[b] = new_in; out[b] = new_out; changed = true; }
        }
    }
    for (std::size_t b = 0; b < n; ++b) cx.blocks[b].arg_mask_in = in[b];
}

void init_abi(Ctx& cx) {
    if (g_arm) {
        cx.callee_saved = {19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, kArmSp};
        cx.arg_regs = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
        for (int r = 0; r < 31; ++r) if (!cx.callee_saved.contains(r)) cx.caller_saved.insert(r);
        return;
    }
    if (cx.options.windows_abi) {
        cx.callee_saved = {kRbx, kRbp, kRdi, kRsi, kRsp, 12, 13, 14, 15};
        cx.arg_regs = {"rcx", "rdx", "r8", "r9"};
    } else {
        cx.callee_saved = {kRbx, kRbp, kRsp, 12, 13, 14, 15};
        cx.arg_regs = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    }
    for (int r = 0; r < 16; ++r) if (!cx.callee_saved.contains(r)) cx.caller_saved.insert(r);
}

void resolve_edges(Ctx& cx);

// Branches on constant conditions become unconditional; unreachable blocks are dropped.
void fold_constant_branches(Ctx& cx) {
    bool any = false;
    for (auto& b : cx.blocks) {
        if (!b.lifted || b.term.type != Terminator::T::Cond || !b.term.cond || b.term.cond->kind != K::Const) continue;
        const bool taken = b.term.cond->imm != 0;
        if (taken) { b.term.type = Terminator::T::Jmp; }
        else { b.term.type = Terminator::T::Fall; }
        any = true;
    }
    if (!any) return;
    resolve_edges(cx);
    // Recompute reachability.
    const auto entry = cx.block_at.find(cx.start);
    if (entry == cx.block_at.end()) return;
    std::vector<char> seen(cx.blocks.size(), 0);
    std::vector<int> work{entry->second};
    while (!work.empty()) {
        const int x = work.back(); work.pop_back();
        if (seen[x]) continue; seen[x] = 1;
        for (const int s : cx.blocks[x].succ) work.push_back(s);
    }
    for (std::size_t i = 0; i < cx.blocks.size(); ++i) if (!seen[i]) { cx.blocks[i].lifted = false; cx.blocks[i].succ.clear(); }
    resolve_edges(cx);
}

void resolve_edges(Ctx& cx) {
    for (std::size_t b = 0; b < cx.blocks.size(); ++b) {
        auto& block = cx.blocks[b];
        block.succ.clear();
        if (!block.lifted) continue;
        auto& t = block.term;
        const auto find = [&](std::uint64_t a) -> int { const auto it = cx.block_at.find(a); return it == cx.block_at.end() ? -1 : it->second; };
        if (t.type == Terminator::T::Fall) { t.fall_block = find(t.fallthrough); if (t.fall_block >= 0) block.succ.push_back(t.fall_block); }
        else if (t.type == Terminator::T::Jmp) { t.taken_block = find(t.taken); if (t.taken_block >= 0) block.succ.push_back(t.taken_block); }
        else if (t.type == Terminator::T::Switch) {
            t.case_blocks.clear(); t.default_block = find(t.default_target);
            for (const auto target : t.cases) {
                const int cb = find(target); t.case_blocks.push_back(cb);
                if (cb >= 0 && std::find(block.succ.begin(), block.succ.end(), cb) == block.succ.end()) block.succ.push_back(cb);
            }
        }
        else if (t.type == Terminator::T::Cond) {
            t.taken_block = find(t.taken); t.fall_block = find(t.fallthrough);
            t.external_taken = t.taken_block < 0;
            if (t.taken_block >= 0) block.succ.push_back(t.taken_block);
            if (t.fall_block >= 0) block.succ.push_back(t.fall_block);
        }
    }
    for (auto& b : cx.blocks) b.pred.clear();
    for (std::size_t b = 0; b < cx.blocks.size(); ++b)
        for (const int s : cx.blocks[b].succ) cx.blocks[s].pred.push_back(static_cast<int>(b));
}

void lift_all(Ctx& cx) {
    const auto entry_it = cx.block_at.find(cx.start);
    if (entry_it == cx.block_at.end()) return;
    std::vector<int> queue{entry_it->second};
    std::set<int> queued{entry_it->second};
    for (std::size_t q = 0; q < queue.size(); ++q) {
        const int b = queue[q];
        auto& block = cx.blocks[b];
        Lifter lifter(cx, block, b);
        lifter.run();
        block.lifted = true;
        const auto enqueue = [&](std::uint64_t address) {
            const auto it = cx.block_at.find(address);
            if (it == cx.block_at.end()) return;
            auto& next = cx.blocks[it->second];
            if (!next.entry_rsp) { next.entry_rsp = lifter.exit_rsp; next.entry_rbp = lifter.exit_rbp; }
            if (queued.insert(it->second).second) queue.push_back(it->second);
        };
        switch (block.term.type) {
        case Terminator::T::Fall: enqueue(block.term.fallthrough); break;
        case Terminator::T::Jmp: enqueue(block.term.taken); break;
        case Terminator::T::Cond: enqueue(block.term.taken); enqueue(block.term.fallthrough); break;
        case Terminator::T::Switch: for (const auto target : block.term.cases) enqueue(target); break;
        default: break;
        }
    }
    resolve_edges(cx);
    if (cx.return_fp) {   // the function returns a floating-point value: every return path hands back xmm0 / st(0)
        for (auto& b : cx.blocks) {
            if (!b.lifted || b.term.type != Terminator::T::Ret || !b.term.fp_return) continue;
            const EP x = b.term.fp_return;
            b.term.value = x->fp == cx.return_fp ? x : x->kind == K::Var ? with_fp(x, cx.return_fp)
                         : x->kind == K::Const && !x->fp ? fconst(x->imm, cx.return_fp) : with_fp(x, cx.return_fp);
            cx.saw_return_value = true;
        }
    }
}

// ---------------------------------------------------------------------------
// Optimisation passes
// ---------------------------------------------------------------------------
void count_temp_uses(const Block& b, std::unordered_map<std::string, int>& counts) {
    const auto add = [&](const EP& e) {
        if (!e) return;
        visit(e, [&](const EP& n) { if (n->kind == K::Var && n->temp) ++counts[n->name]; });
    };
    for (const auto& s : b.stmts) { add(s.addr); add(s.value); }
    for (const auto& m : b.moves) add(m.rhs);
    add(b.term.cond); add(b.term.value);
}

bool references_temp(const EP& e, const std::string& name) {
    bool found = false;
    if (e) visit(e, [&](const EP& n) { if (n->kind == K::Var && n->temp && n->name == name) found = true; });
    return found;
}

bool is_cheap(const EP& e) {
    switch (e->kind) {
    case K::Const: case K::Var: case K::Frame: return true;
    case K::Cast: return e->a[0]->kind == K::Var || e->a[0]->kind == K::Const;
    case K::Bin: return e->name == "+" && (e->a[0]->kind == K::Var || e->a[0]->kind == K::Frame) && is_const(e->a[1]);
    default: return false;
    }
}

bool stmt_has_call(const Stmt& s) { return (s.value && contains_kind(s.value, K::Call)) || (s.addr && contains_kind(s.addr, K::Call)); }
bool stmt_has_memory(const Stmt& s) { return (s.value && has_memory_or_call(s.value)) || (s.addr && has_memory_or_call(s.addr)); }

void apply_substitution(Block& b, std::size_t from, const std::unordered_map<std::string, EP>& map) {
    for (std::size_t i = from; i < b.stmts.size(); ++i) {
        if (b.stmts[i].addr) b.stmts[i].addr = substitute(b.stmts[i].addr, map);
        if (b.stmts[i].value) b.stmts[i].value = substitute(b.stmts[i].value, map);
    }
    for (auto& m : b.moves) m.rhs = substitute(m.rhs, map);
    if (b.term.cond) b.term.cond = substitute(b.term.cond, map);
    if (b.term.value) b.term.value = substitute(b.term.value, map);
}

bool inline_block_once(Block& b) {
    std::unordered_map<std::string, int> counts;
    count_temp_uses(b, counts);
    for (std::size_t i = 0; i < b.stmts.size(); ++i) {
        Stmt& s = b.stmts[i];
        if (s.type != Stmt::T::Assign || !s.lhs->temp) continue;
        const std::string name = s.lhs->name;
        const int uses = counts[name];
        const bool has_call = contains_kind(s.value, K::Call);
        if (uses == 0) {
            if (has_call) { s.type = Stmt::T::Eval; s.lhs = nullptr; return true; }
            b.stmts.erase(b.stmts.begin() + i);
            return true;
        }
        bool do_inline = false;
        if (is_cheap(s.value)) do_inline = true;
        else if (uses >= 2 && s.value->kind == K::Deref && s.value->a[0]->kind == K::Frame) {
            // Re-reading an unmodified stack slot is idempotent: inline when nothing can write it in between.
            std::size_t last_use = i;
            bool in_tail = false;
            for (std::size_t j = i + 1; j < b.stmts.size(); ++j)
                if (references_temp(b.stmts[j].addr, name) || references_temp(b.stmts[j].value, name)) last_use = j;
            for (const auto& m : b.moves) if (references_temp(m.rhs, name)) in_tail = true;
            if (references_temp(b.term.cond, name) || references_temp(b.term.value, name)) in_tail = true;
            if (in_tail) last_use = b.stmts.size();
            bool blocked = false;
            for (std::size_t j = i + 1; j < last_use && j < b.stmts.size() && !blocked; ++j) {
                const Stmt& between = b.stmts[j];
                if (between.type == Stmt::T::Store || between.type == Stmt::T::Eval || stmt_has_call(between)) blocked = true;
            }
            do_inline = !blocked;
        }
        if (!do_inline && uses == 1) {
            // Locate the use; make sure no side effect can reorder with it.
            std::size_t use_at = b.stmts.size();
            for (std::size_t j = i + 1; j < b.stmts.size(); ++j) {
                if (references_temp(b.stmts[j].addr, name) || references_temp(b.stmts[j].value, name)) { use_at = j; break; }
            }
            const bool reads_memory = has_memory_or_call(s.value);
            bool blocked = false;
            if (reads_memory || has_call) {
                for (std::size_t j = i + 1; j < use_at && !blocked; ++j) {
                    const Stmt& between = b.stmts[j];
                    if (between.type == Stmt::T::Store || between.type == Stmt::T::Eval || stmt_has_call(between)) blocked = true;
                    else if (has_call && stmt_has_memory(between)) blocked = true;
                    else if (contains_kind(between.value ? between.value : s.value, K::Intrin) && between.type != Stmt::T::Assign) blocked = true;
                }
            }
            // A call may not move past the evaluation of another call inside the use statement.
            if (!blocked && has_call && use_at < b.stmts.size()) {
                int calls_in_use = 0;
                const auto count_calls = [&](const EP& e) { if (e) visit(e, [&](const EP& n) { if (n->kind == K::Call) ++calls_in_use; }); };
                count_calls(b.stmts[use_at].addr); count_calls(b.stmts[use_at].value);
                if (calls_in_use > 0 && b.stmts[use_at].type != Stmt::T::Eval) blocked = true;
            }
            do_inline = !blocked;
        }
        if (!do_inline) continue;
        std::unordered_map<std::string, EP> map{{name, s.value}};
        b.stmts.erase(b.stmts.begin() + i);
        apply_substitution(b, i, map);
        return true;
    }
    return false;
}

void inline_all(Ctx& cx) {
    for (auto& b : cx.blocks) {
        if (!b.lifted) continue;
        int guard = 0;
        while (inline_block_once(b) && guard++ < 100000) {}
    }
}

int register_index(const std::string& name) {
    if (g_arm) {
        if (name == "sp") return kArmSp;
        if (name.size() >= 2 && name[0] == 'x' && std::all_of(name.begin() + 1, name.end(), [](unsigned char c) { return std::isdigit(c); })) {
            const int n = std::stoi(name.substr(1));
            return n < 31 ? n : -1;
        }
        return -1;
    }
    if (const auto r = parse_register(name); r && r->size == (name[0] == 'x' ? 16 : 8) && !r->high) return r->index;
    return -1;
}

std::uint32_t regs_used(const EP& e) {
    std::uint32_t mask = 0;
    if (!e) return 0;
    visit(e, [&](const EP& n) {
        if (n->kind != K::Var || n->temp) return;
        const int idx = register_index(n->name);
        if (idx >= 0) mask |= (1u << idx);
    });
    return mask;
}

std::uint32_t block_uses(const Block& b) {
    std::uint32_t mask = 0;
    for (const auto& s : b.stmts) { mask |= regs_used(s.addr) | regs_used(s.value); }
    mask |= regs_used(b.term.cond) | regs_used(b.term.value);
    return mask;
}

// Global liveness over register variables; drops dead moves.
std::uint32_t liveness_prune(Ctx& cx) {
    const std::size_t n = cx.blocks.size();
    std::vector<std::uint32_t> live_in(n, 0), live_out(n, 0);
    bool changed = true; int guard = 0;
    const auto kept_moves = [&](const Block& b, std::uint32_t out) {
        std::uint32_t uses = 0, defs = 0;
        for (const auto& m : b.moves) {
            const int idx = register_index(m.lhs->name);
            if (idx < 0 || !(out & (1u << idx))) {
                // A dead result whose expression contains a call is kept as a plain call statement,
                // so the registers feeding that call stay live.
                if (contains_kind(m.rhs, K::Call)) uses |= regs_used(m.rhs);
                continue;
            }
            uses |= regs_used(m.rhs); defs |= (1u << idx);
        }
        return std::make_pair(uses, defs);
    };
    while (changed && guard++ < 500) {
        changed = false;
        for (std::size_t bi = n; bi-- > 0;) {
            const auto& b = cx.blocks[bi];
            if (!b.lifted) continue;
            std::uint32_t out = 0;
            for (const int s : b.succ) out |= live_in[s];
            if (b.term.type == Terminator::T::Ret || b.term.type == Terminator::T::NoReturn) out = 0;
            const auto [move_uses, move_defs] = kept_moves(b, out);
            const std::uint32_t in = block_uses(b) | move_uses | (out & ~move_defs);
            if (in != live_in[bi] || out != live_out[bi]) { live_in[bi] = in; live_out[bi] = out; changed = true; }
        }
    }
    for (std::size_t bi = 0; bi < n; ++bi) {
        auto& b = cx.blocks[bi];
        if (!b.lifted) continue;
        std::vector<Move> kept;
        for (auto& m : b.moves) {
            const int idx = register_index(m.lhs->name);
            if (idx >= 0 && (live_out[bi] & (1u << idx))) kept.push_back(m);
            else if (contains_kind(m.rhs, K::Call)) {
                // The register result is dead but the call must still happen.
                Stmt effect; effect.type = Stmt::T::Eval; effect.value = m.rhs; effect.source = b.term.source;
                b.stmts.push_back(std::move(effect));
            }
        }
        b.moves = std::move(kept);
    }
    const auto entry = cx.block_at.find(cx.start);
    return entry == cx.block_at.end() ? 0 : live_in[entry->second];
}

void frame_store_elimination(Ctx& cx) {
    std::set<std::int64_t> reads;
    bool escape = false;
    const std::function<void(const EP&, bool)> scan = [&](const EP& e, bool address_of_deref) {
        if (!e) return;
        if (e->kind == K::Frame) { if (address_of_deref) reads.insert(frame_offset(e)); else escape = true; return; }
        if (e->kind == K::Deref) { scan(e->a[0], true); return; }
        for (const auto& c : e->a) scan(c, false);
    };
    for (const auto& b : cx.blocks) {
        if (!b.lifted) continue;
        for (const auto& s : b.stmts) {
            if (s.type == Stmt::T::Store) { if (s.addr->kind != K::Frame) scan(s.addr, false); }
            else scan(s.addr, false);
            scan(s.value, false);
        }
        for (const auto& m : b.moves) scan(m.rhs, false);
        scan(b.term.cond, false); scan(b.term.value, false);
    }
    cx.frame_escape = escape;
    cx.frame_reads = reads;
    if (escape) return;
    for (auto& b : cx.blocks) {
        if (!b.lifted) continue;
        std::vector<Stmt> kept;
        for (auto& s : b.stmts) {
            if (s.type == Stmt::T::Store && s.addr->kind == K::Frame && !reads.contains(frame_offset(s.addr)) &&
                !contains_kind(s.value, K::Call)) continue;
            kept.push_back(std::move(s));
        }
        b.stmts = std::move(kept);
    }
}

// A stack slot that merely spills an incoming argument register becomes that parameter.
std::uint32_t promote_parameters(Ctx& cx) {
    std::uint32_t promoted = 0;
    if (cx.frame_escape) return 0;
    std::set<std::string> assigned;
    for (const auto& b : cx.blocks) for (const auto& m : b.moves) assigned.insert(m.lhs->name);
    std::map<std::int64_t, int> store_count;
    for (const auto& b : cx.blocks) {
        if (!b.lifted) continue;
        for (const auto& st : b.stmts) if (st.type == Stmt::T::Store && st.addr->kind == K::Frame) ++store_count[frame_offset(st.addr)];
    }
    const auto it = cx.block_at.find(cx.start);
    if (it == cx.block_at.end()) return 0;
    auto& entry = cx.blocks[it->second];
    for (std::size_t i = 0; i < entry.stmts.size();) {
        const Stmt& st = entry.stmts[i];
        bool removed = false;
        if (st.type == Stmt::T::Store && st.addr->kind == K::Frame && st.addr->imm != 0) {
            EP v = st.value;
            while (v->kind == K::Cast) v = v->a[0];
            if (v->kind == K::Var && !v->temp && !assigned.contains(v->name)) {
                const auto pos = std::find(cx.arg_regs.begin(), cx.arg_regs.end(), v->name);
                const std::int64_t slot = frame_offset(st.addr);
                if (pos != cx.arg_regs.end() && !cx.param_slot.contains(slot) && st.size <= 8) {
                    const int number = static_cast<int>(pos - cx.arg_regs.begin()) + 1;
                    bool taken = false;
                    for (const auto& [s2, n2] : cx.param_slot) if (n2 == number) taken = true;
                    if (!taken && slot < 0) {
                        cx.param_slot[slot] = number;
                        cx.param_size[number] = st.size;
                        promoted |= (1u << register_index(*pos));
                        entry.stmts.erase(entry.stmts.begin() + i);
                        removed = true;
                    }
                }
            }
        }
        if (!removed) ++i;
    }
    (void)store_count;
    return promoted;
}

// Turn each block's parallel register moves into an ordered assignment list.
void sequentialize_moves(Ctx& cx) {
    for (auto& b : cx.blocks) {
        if (!b.lifted) continue;
        // Branch conditions are evaluated before the moves; keep their operands intact.
        std::uint32_t assigned = 0;
        for (const auto& m : b.moves) { const int idx = register_index(m.lhs->name); if (idx >= 0) assigned |= (1u << idx); }
        const auto protect = [&](EP& expr) {
            if (!expr || !(regs_used(expr) & assigned)) return;
            const std::string name = "t" + std::to_string(cx.next_temp++);
            const auto v = var(name, (std::max)(width(expr), 1) > 8 ? 8 : (width(expr) ? width(expr) : 8), true);
            Stmt s; s.type = Stmt::T::Assign; s.lhs = v; s.value = expr; s.source = b.term.source;
            b.stmts.push_back(std::move(s));
            expr = v;
        };
        protect(b.term.cond);
        if (b.term.type == Terminator::T::IndirectJmp || b.term.type == Terminator::T::Switch) protect(b.term.value);

        std::vector<Move> pending = std::move(b.moves);
        b.moves.clear();
        while (!pending.empty()) {
            std::size_t pick = pending.size();
            for (std::size_t i = 0; i < pending.size() && pick == pending.size(); ++i) {
                const int idx = register_index(pending[i].lhs->name);
                bool read_elsewhere = false;
                for (std::size_t j = 0; j < pending.size(); ++j) if (j != i && (regs_used(pending[j].rhs) & (1u << idx))) read_elsewhere = true;
                if (!read_elsewhere) pick = i;
            }
            if (pick == pending.size()) {
                const auto& first = pending.front();
                const std::string name = "t" + std::to_string(cx.next_temp++);
                const auto tmp = var(name, 8, true);
                Stmt s; s.type = Stmt::T::Assign; s.lhs = tmp; s.value = first.lhs; b.stmts.push_back(std::move(s));
                const auto from = first.lhs->name;
                for (std::size_t j = 1; j < pending.size(); ++j) {
                    std::function<EP(const EP&)> rep = [&](const EP& e) -> EP {
                        if (e->kind == K::Var && !e->temp && e->name == from) return tmp;
                        if (e->a.empty()) return e;
                        std::vector<EP> kids; for (const auto& c : e->a) kids.push_back(rep(c));
                        return rebuild(e, std::move(kids));
                    };
                    pending[j].rhs = rep(pending[j].rhs);
                }
                continue;
            }
            Stmt s; s.type = Stmt::T::Assign; s.lhs = pending[pick].lhs; s.value = pending[pick].rhs; s.source = b.term.source;
            b.stmts.push_back(std::move(s));
            pending.erase(pending.begin() + pick);
        }
    }
}

// ---------------------------------------------------------------------------
// Structuring
// ---------------------------------------------------------------------------
struct Node;
using NP = std::unique_ptr<Node>;
using Seq = std::vector<NP>;

struct Node {
    enum class T { Stmt, If, Loop, While, DoWhile, Break, Continue, Goto, Label, Return, Raw, Switch, Case } type{T::Stmt};
    std::vector<std::uint64_t> values;   // Case: table indices that select this body
    bool is_default{false};              // Case
    Stmt stmt;
    EP cond;          // If / While / DoWhile
    EP value;         // Return
    Seq body, other;  // If: then/else; loops: body
    int block{-1};    // Label / Goto
    std::string text; // Raw
    std::uint64_t address{0};
};

NP make_node(Node::T type) { auto n = std::make_unique<Node>(); n->type = type; return n; }

bool ends_with_jump(const Seq& s) {
    if (s.empty()) return false;
    const auto t = s.back()->type;
    return t == Node::T::Return || t == Node::T::Break || t == Node::T::Continue || t == Node::T::Goto;
}

class Structurer {
public:
    explicit Structurer(Ctx& cx) : cx_(cx), n_(static_cast<int>(cx.blocks.size())) {}

    Seq run() {
        const auto it = cx_.block_at.find(cx_.start);
        if (it == cx_.block_at.end()) return {};
        entry_ = it->second;
        compute_orders();
        compute_dominators();
        compute_post_dominators();
        compute_loops();
        emitted_.assign(n_, false); labeled_.assign(n_, false);
        Seq out = emit(entry_, -1, false);
        strip_labels(out);
        simplify(out);
        propagate_returns(out);
        simplify(out);
        // Trailing `return;` of a void function and trailing continue are noise.
        return out;
    }
    std::size_t goto_count() const { return gotos_; }
    void count_gotos(const Seq& s) { for (const auto& node : s) { if (node->type == Node::T::Goto) ++gotos_; count_gotos(node->body); count_gotos(node->other); } }

private:
    struct LoopCtx { int header; int after; };
    Ctx& cx_;
    int n_;
    int entry_{0};
    std::vector<int> rpo_, rpo_index_, idom_, ipdom_;
    std::vector<std::set<int>> loop_body_;     // by header
    std::vector<bool> is_header_;
    std::vector<LoopCtx> loops_;
    std::vector<int> stops_;
    std::vector<bool> emitted_, labeled_;
    std::size_t gotos_{0};
    int cloning_{0};
    std::vector<std::pair<int, std::size_t>> switch_merges_;   // (merge block, loop depth) of enclosing switches
    int clone_budget_{240};

    const Block& blk(int i) const { return cx_.blocks[i]; }

    void compute_orders() {
        rpo_index_.assign(n_, -1);
        std::vector<int> post; std::vector<char> seen(n_, 0);
        std::function<void(int)> dfs = [&](int u) {
            seen[u] = 1;
            for (const int v : blk(u).succ) if (!seen[v]) dfs(v);
            post.push_back(u);
        };
        dfs(entry_);
        rpo_.assign(post.rbegin(), post.rend());
        for (std::size_t i = 0; i < rpo_.size(); ++i) rpo_index_[rpo_[i]] = static_cast<int>(i);
    }

    void compute_dominators() {
        idom_.assign(n_, -1);
        idom_[entry_] = entry_;
        bool changed = true;
        const auto intersect = [&](int a, int b) {
            while (a != b) {
                while (rpo_index_[a] > rpo_index_[b]) a = idom_[a];
                while (rpo_index_[b] > rpo_index_[a]) b = idom_[b];
            }
            return a;
        };
        while (changed) {
            changed = false;
            for (const int b : rpo_) {
                if (b == entry_) continue;
                int new_idom = -1;
                for (const int p : blk(b).pred) {
                    if (rpo_index_[p] < 0 || idom_[p] < 0) continue;
                    new_idom = new_idom < 0 ? p : intersect(p, new_idom);
                }
                if (new_idom != idom_[b]) { idom_[b] = new_idom; changed = true; }
            }
        }
    }
    bool dominates(int a, int b) const {
        while (true) {
            if (a == b) return true;
            if (b == entry_ || idom_[b] < 0) return false;
            b = idom_[b];
        }
    }

    void compute_post_dominators() {
        // Reverse graph with a virtual exit node `n_`.
        const int exit_node = n_;
        std::vector<std::vector<int>> rsucc(n_ + 1), rpred(n_ + 1); // rsucc = original preds
        for (int b = 0; b < n_; ++b) {
            if (rpo_index_[b] < 0) continue;
            if (blk(b).succ.empty()) { rsucc[exit_node].push_back(b); rpred[b].push_back(exit_node); }
            for (const int s : blk(b).succ) { rsucc[s].push_back(b); rpred[b].push_back(s); }
        }
        std::vector<int> post; std::vector<char> seen(n_ + 1, 0);
        std::function<void(int)> dfs = [&](int u) {
            seen[u] = 1;
            for (const int v : rsucc[u]) if (!seen[v]) dfs(v);
            post.push_back(u);
        };
        dfs(exit_node);
        std::vector<int> order(post.rbegin(), post.rend()), index(n_ + 1, -1);
        for (std::size_t i = 0; i < order.size(); ++i) index[order[i]] = static_cast<int>(i);
        ipdom_.assign(n_ + 1, -1);
        ipdom_[exit_node] = exit_node;
        const auto intersect = [&](int a, int b) {
            while (a != b) {
                while (index[a] > index[b]) a = ipdom_[a];
                while (index[b] > index[a]) b = ipdom_[b];
            }
            return a;
        };
        bool changed = true;
        while (changed) {
            changed = false;
            for (const int b : order) {
                if (b == exit_node) continue;
                int cand = -1;
                for (const int p : rpred[b]) {   // successors in the original graph
                    if (index[p] < 0 || ipdom_[p] < 0) continue;
                    cand = cand < 0 ? p : intersect(p, cand);
                }
                if (cand != ipdom_[b]) { ipdom_[b] = cand; changed = true; }
            }
        }
    }

    void compute_loops() {
        loop_body_.assign(n_, {});
        is_header_.assign(n_, false);
        for (int u = 0; u < n_; ++u) {
            if (rpo_index_[u] < 0) continue;
            for (const int h : blk(u).succ) {
                if (rpo_index_[h] < 0 || !dominates(h, u)) continue;
                is_header_[h] = true;
                auto& body = loop_body_[h];
                body.insert(h);
                std::vector<int> work{u};
                while (!work.empty()) {
                    const int x = work.back(); work.pop_back();
                    if (!body.insert(x).second) continue;
                    for (const int p : blk(x).pred) if (rpo_index_[p] >= 0) work.push_back(p);
                }
            }
        }
    }

    int loop_after(int header) const {
        const auto& body = loop_body_[header];
        int best = -1;
        for (const int b : body) {
            for (const int s : blk(b).succ) {
                if (body.contains(s)) continue;
                if (best < 0 || rpo_index_[s] < rpo_index_[best]) best = s;
            }
        }
        return best;
    }

    bool is_active_header(int b) const {
        return std::any_of(loops_.begin(), loops_.end(), [&](const LoopCtx& l) { return l.header == b; });
    }

    NP make_goto(int b) {
        labeled_[b] = true;
        auto g = make_node(Node::T::Goto); g->block = b; return g;
    }

    // Small straight-line tail that ends the function (return / noreturn call): copy it at the
    // jump site instead of emitting `goto LABEL`. Keeps shared epilogues readable.
    bool tail_copy(int b, Seq& out) {
        Seq tmp; int total = 0; int cur = b;
        for (int hops = 0; hops < 4 && cur >= 0; ++hops) {
            if (is_header_[cur]) return false;
            const auto& bl = blk(cur);
            for (const auto& s : bl.stmts) { auto node = make_node(Node::T::Stmt); node->stmt = s; node->address = s.source; tmp.push_back(std::move(node)); ++total; }
            if (total > 10) return false;
            const auto& term = bl.term;
            if (term.type == Terminator::T::Fall) { cur = term.fall_block; continue; }
            if (term.type == Terminator::T::Jmp) { cur = term.taken_block; continue; }
            if (term.type == Terminator::T::Ret) { auto r = make_node(Node::T::Return); r->value = term.value; tmp.push_back(std::move(r)); }
            else if (term.type != Terminator::T::NoReturn) return false;
            for (auto& node : tmp) out.push_back(std::move(node));
            return true;
        }
        return false;
    }

    // Larger shared tails (small acyclic regions that end the function): duplicate them at the jump
    // site rather than jumping into the middle of another branch.
    bool region_small(int b, std::set<int>& seen, int& stmts) const {
        if (b < 0 || seen.contains(b)) return true;
        if (is_header_[b] || rpo_index_[b] < 0) return false;
        seen.insert(b);
        if (seen.size() > 14) return false;
        const auto& bl = blk(b);
        stmts += static_cast<int>(bl.stmts.size());
        if (stmts > 48) return false;
        switch (bl.term.type) {
        case Terminator::T::Ret: case Terminator::T::NoReturn: return true;
        case Terminator::T::IndirectJmp: return false;
        default: break;
        }
        for (const int s : bl.succ) if (!region_small(s, seen, stmts)) return false;
        return true;
    }

    bool clone_region(int b, Seq& out) {
        if (!loops_.empty() || cloning_ > 3 || clone_budget_ <= 0) return false;
        std::set<int> region; int stmts = 0;
        if (!region_small(b, region, stmts) || stmts == 0) return false;
        clone_budget_ -= stmts;
        const auto saved_emitted = emitted_; const auto saved_stops = stops_;
        for (const int x : region) emitted_[x] = false;
        stops_.clear();
        ++cloning_;
        Seq copy = emit(b, -1, false);
        --cloning_;
        emitted_ = saved_emitted; stops_ = saved_stops;
        for (auto& node : copy) out.push_back(std::move(node));
        return true;
    }

    Seq emit(int b, int stop, bool header_entry) {
        Seq out;
        bool first = true;
        while (true) {
            const bool at_header_entry = header_entry && first;
            first = false;
            if (b < 0) break;
            if (b == stop) break;
            if (!at_header_entry) {
                if (!loops_.empty()) {
                    const auto& inner = loops_.back();
                    if (b == inner.header) { out.push_back(make_node(Node::T::Continue)); break; }
                    if (b == inner.after) { out.push_back(make_node(Node::T::Break)); break; }
                    bool outer_target = false;
                    for (std::size_t i = 0; i + 1 < loops_.size(); ++i) if (b == loops_[i].header || b == loops_[i].after) outer_target = true;
                    if (outer_target) { out.push_back(make_goto(b)); break; }
                }
                if (!switch_merges_.empty() && switch_merges_.back().first == b && switch_merges_.back().second == loops_.size()) { out.push_back(make_node(Node::T::Break)); break; }
                if (std::find(stops_.begin(), stops_.end(), b) != stops_.end()) { if (!tail_copy(b, out)) out.push_back(make_goto(b)); break; }
                if (emitted_[b]) { if (!tail_copy(b, out) && !clone_region(b, out)) out.push_back(make_goto(b)); break; }
                if (is_header_[b] && !is_active_header(b)) {
                    const int after = loop_after(b);
                    loops_.push_back({b, after});
                    auto loop = make_node(Node::T::Loop);
                    loop->body = emit(b, -1, true);
                    loops_.pop_back();
                    out.push_back(std::move(loop));
                    if (after < 0) break;
                    b = after;
                    continue;
                }
            }
            emitted_[b] = true;
            if (cloning_ == 0) { auto label = make_node(Node::T::Label); label->block = b; out.push_back(std::move(label)); }
            for (const auto& s : blk(b).stmts) {
                auto node = make_node(Node::T::Stmt); node->stmt = s; node->address = s.source; out.push_back(std::move(node));
            }
            const auto& t = blk(b).term;
            switch (t.type) {
            case Terminator::T::Fall: b = t.fall_block; continue;
            case Terminator::T::Jmp: b = t.taken_block; continue;
            case Terminator::T::Ret: { auto r = make_node(Node::T::Return); r->value = t.value; out.push_back(std::move(r)); return out; }
            case Terminator::T::NoReturn: return out;
            case Terminator::T::IndirectJmp: {
                auto raw = make_node(Node::T::Raw); raw->value = t.value; raw->text = "JUMPOUT"; out.push_back(std::move(raw)); return out;
            }
            case Terminator::T::Switch: {
                if (!loops_.empty() || cloning_ > 0) { auto raw = make_node(Node::T::Raw); raw->value = t.value; raw->text = "JUMPOUT"; out.push_back(std::move(raw)); return out; }
                int merge = ipdom_[b];
                if (merge == n_) merge = -1;
                std::vector<int> order; std::map<int, std::vector<std::uint64_t>> values;
                for (std::size_t i = 0; i < t.case_blocks.size(); ++i) {
                    const int tb = t.case_blocks[i];
                    if (tb < 0) continue;
                    if (!values.contains(tb)) order.push_back(tb);
                    values[tb].push_back(i);
                }
                auto sw = make_node(Node::T::Switch); sw->cond = t.value;
                if (merge >= 0) { stops_.push_back(merge); switch_merges_.push_back({merge, loops_.size()}); }
                for (const int tb : order) {
                    auto c = make_node(Node::T::Case); c->values = values[tb]; c->is_default = tb == t.default_block;
                    c->body = emit(tb, merge >= 0 ? merge : stop, false);
                    if (merge >= 0 && !ends_with_jump(c->body)) c->body.push_back(make_node(Node::T::Break));
                    sw->body.push_back(std::move(c));
                }
                if (merge >= 0) { stops_.pop_back(); switch_merges_.pop_back(); }
                std::stable_sort(sw->body.begin(), sw->body.end(), [](const NP& l, const NP& r) { return !l->is_default && r->is_default; });
                out.push_back(std::move(sw));
                if (merge < 0) return out;
                b = merge;
                continue;
            }
            case Terminator::T::Cond: {
                int merge = ipdom_[b];
                if (merge == n_) merge = -1;
                if (merge >= 0 && !loops_.empty() && !loop_body_[loops_.back().header].contains(merge) &&
                    merge != loops_.back().after) merge = -1;
                auto branch = make_node(Node::T::If);
                branch->cond = t.cond;
                const int region_stop = merge >= 0 ? merge : stop;
                if (merge >= 0) stops_.push_back(merge);
                if (t.external_taken) {
                    auto raw = make_node(Node::T::Raw); raw->text = "goto"; raw->address = t.taken; branch->body.push_back(std::move(raw));
                } else {
                    branch->body = emit(t.taken_block, region_stop, false);
                }
                branch->other = emit(t.fall_block, region_stop, false);
                if (merge >= 0) stops_.pop_back();
                out.push_back(std::move(branch));
                if (merge < 0) return out;
                b = merge;
                continue;
            }
            }
        }
        return out;
    }

    // `if (c) { v = X; } else { v = Y; } return v;`  ==>  `if (c) return X; else return Y;`
    static bool push_return(Seq& branch, const EP& value) {
        if (branch.empty()) { auto r = make_node(Node::T::Return); r->value = value; branch.push_back(std::move(r)); return true; }
        Node& last = *branch.back();
        if (last.type == Node::T::Return || last.type == Node::T::Break || last.type == Node::T::Continue || last.type == Node::T::Goto) return true;
        if (last.type == Node::T::Stmt && last.stmt.type == Stmt::T::Assign && last.stmt.lhs && same(last.stmt.lhs, value)) {
            auto r = make_node(Node::T::Return); r->value = last.stmt.value;
            branch.pop_back(); branch.push_back(std::move(r)); return true;
        }
        if (last.type == Node::T::If) {
            const bool a = push_return(last.body, value), b = push_return(last.other, value);
            return a && b;
        }
        if (last.type == Node::T::Stmt || last.type == Node::T::Label) {
            auto r = make_node(Node::T::Return); r->value = value; branch.push_back(std::move(r)); return true;
        }
        return false;
    }
    void propagate_returns(Seq& s) {
        for (auto& node : s) { propagate_returns(node->body); propagate_returns(node->other); }
        if (s.size() < 2) return;
        Node& last = *s.back();
        Node& before = *s[s.size() - 2];
        if (last.type != Node::T::Return || !last.value || last.value->kind != K::Var || last.value->temp) return;
        if (before.type != Node::T::If) return;
        const EP value = last.value;
        if (!push_return(before.body, value) || !push_return(before.other, value)) return;
        // `if` with an empty else now ends in returns on every path; the final return is dead.
        if (before.other.empty()) { auto r = make_node(Node::T::Return); r->value = value; before.other.push_back(std::move(r)); }
        s.pop_back();
    }

    // ---- clean-up
    void strip_labels(Seq& s) {
        Seq kept;
        for (auto& node : s) {
            if (node->type == Node::T::Label && !labeled_[node->block]) continue;
            strip_labels(node->body); strip_labels(node->other);
            kept.push_back(std::move(node));
        }
        s = std::move(kept);
    }

    static bool is_noop_label(const Node& n) { return n.type == Node::T::Label; }

    void simplify(Seq& s) {
        for (auto& node : s) { simplify(node->body); simplify(node->other); }
        for (std::size_t i = 0; i < s.size(); ++i) {
            Node& node = *s[i];
            if (node.type == Node::T::If) {
                if (node.body.empty() && !node.other.empty()) { node.cond = un("!", node.cond); std::swap(node.body, node.other); }
                if (node.body.empty() && node.other.empty()) { s.erase(s.begin() + i); --i; continue; }
                if (!node.other.empty() && ends_with_jump(node.body)) {
                    Seq tail = std::move(node.other); node.other.clear();
                    for (std::size_t k = 0; k < tail.size(); ++k) s.insert(s.begin() + i + 1 + k, std::move(tail[k]));
                    continue;
                }
                if (node.other.empty() && node.body.size() == 1 && node.body[0]->type == Node::T::If && node.body[0]->other.empty()) {
                    auto inner = std::move(node.body[0]);
                    node.cond = bin("&&", node.cond, inner->cond);
                    node.body = std::move(inner->body);
                }
            } else if (node.type == Node::T::Loop) {
                while (!node.body.empty() && node.body.back()->type == Node::T::Continue) node.body.pop_back();
                // do { ... } while (c);
                if (node.body.size() >= 1) {
                    Node& last = *node.body.back();
                    if (last.type == Node::T::If && last.body.size() == 1 && last.body[0]->type == Node::T::Continue &&
                        last.other.size() == 1 && last.other[0]->type == Node::T::Break) {
                        node.type = Node::T::DoWhile; node.cond = last.cond; node.body.pop_back();
                    } else if (last.type == Node::T::Break && node.body.size() >= 2) {
                        Node& prev = *node.body[node.body.size() - 2];
                        if (prev.type == Node::T::If && prev.other.empty() && prev.body.size() == 1 && prev.body[0]->type == Node::T::Continue) {
                            node.type = Node::T::DoWhile; node.cond = prev.cond;
                            node.body.pop_back(); node.body.pop_back();
                        }
                    }
                }
                if (node.type == Node::T::Loop && node.body.size() == 2 && node.body[0]->type == Node::T::If &&
                    node.body[1]->type == Node::T::Break) {
                    // while (1) { if (c) { A; continue; } break; }  ==>  while (c) { A; }
                    Node& guard = *node.body[0];
                    if (guard.other.empty() && !guard.body.empty() && guard.body.back()->type == Node::T::Continue) {
                        node.type = Node::T::While; node.cond = guard.cond;
                        Seq inner = std::move(guard.body); inner.pop_back();
                        node.body = std::move(inner);
                    }
                }
                if (node.type == Node::T::Loop && node.body.size() == 1 && node.body[0]->type == Node::T::If) {
                    Node& guard = *node.body[0];
                    if (!guard.body.empty() && guard.body.back()->type == Node::T::Continue &&
                        guard.other.size() == 1 && guard.other[0]->type == Node::T::Break) {
                        node.type = Node::T::While; node.cond = guard.cond;
                        Seq inner = std::move(guard.body); inner.pop_back();
                        node.body = std::move(inner);
                    }
                }
                if (node.type == Node::T::Loop && !node.body.empty()) {
                    Node& first = *node.body.front();
                    if (first.type == Node::T::If && first.body.size() == 1 && first.body[0]->type == Node::T::Break) {
                        node.type = Node::T::While; node.cond = un("!", first.cond);
                        Seq rest = std::move(first.other);
                        node.body.erase(node.body.begin());
                        for (std::size_t k = 0; k < rest.size(); ++k) node.body.insert(node.body.begin() + k, std::move(rest[k]));
                    } else if (first.type == Node::T::If && first.body.empty() && first.other.size() == 1 && first.other[0]->type == Node::T::Break) {
                        node.type = Node::T::While; node.cond = first.cond;
                        node.body.erase(node.body.begin());
                    }
                }
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Printing
// ---------------------------------------------------------------------------
int precedence(const std::string& op) {
    if (op == "||") return 2;
    if (op == "&&") return 3;
    if (op == "|") return 4;
    if (op == "^") return 5;
    if (op == "&") return 6;
    if (op == "==" || op == "!=") return 7;
    if (op == "<" || op == "<=" || op == ">" || op == ">=") return 8;
    if (op == "<<" || op == ">>") return 9;
    if (op == "+" || op == "-") return 10;
    if (op == "*" || op == "/" || op == "%") return 11;
    return 12;
}

std::string type_for_size(int size) {
    switch (size) {
    case 1: return "uint8_t"; case 2: return "uint16_t"; case 4: return "uint32_t"; case 8: return "uint64_t";
    case 16: return "__m128"; default: return "uint64_t";
    }
}

class Printer {
public:
    Printer(Ctx& cx, std::uint32_t entry_live) : cx_(cx) {
        int arg = 1;
        for (const auto& reg : cx.arg_regs) {
            const int idx = register_index(reg);
            if (idx >= 0 && (entry_live & (1u << idx))) { rename_[reg] = "a" + std::to_string(arg); arg_count_ = arg; }
            ++arg;
        }
        if (!g_arm && cx.options.windows_abi)
            for (int i = 0; i < 4; ++i)
                if (entry_live & (1u << (xmm_base() + i)) && !rename_.contains(cx.arg_regs[static_cast<std::size_t>(i)])) {
                    rename_["xmm" + std::to_string(i)] = "a" + std::to_string(i + 1);
                    fp_param_[i + 1] = "xmm" + std::to_string(i);
                    arg_count_ = (std::max)(arg_count_, i + 1);
                }
        // Parameters in between that are not live still need a slot in the prototype.
    }

    std::string param_fp_type(int number) {
        const auto it = fp_param_.find(number);
        if (it == fp_param_.end()) return "";
        const auto fp = reg_fp_.find(it->second);
        return fp_type_name(fp != reg_fp_.end() && fp->second ? fp->second : 2);
    }

    int arg_count() const { int n = arg_count_; for (const int p : used_params_) n = (std::max)(n, p); return n; }

    std::string const_text(std::uint64_t v, int size) {
        if (v < 10) return std::to_string(v);
        if (size >= 8 && v >= 0xFFFFFFFFFFFF0000ull) return "-" + std::to_string(~v + 1);
        if (size == 4 && v >= 0xFFFFFF00ull && v <= 0xFFFFFFFFull) return "-" + std::to_string((~static_cast<std::uint32_t>(v)) + 1u);
        const auto& image = cx_.image;
        const bool pie = image.image_base < 0x10000;
        if (v >= (pie ? 0x1000u : image.image_base) && is_data_address(image, v)) {
            if (cx_.options.name_of) {
                const auto n = cx_.options.name_of(v);
                if (!n.empty()) return is_code_address(image, v) ? n : "&" + n;
            }
            if (const auto s = read_c_string(image, v); s && s->size() >= 4) return "\"" + escape_c(*s) + "\"";
            if (const auto w = read_wide_string(image, v); w && w->size() >= 4) return "L\"" + escape_c(*w) + "\"";
            if (!pie) return "(void*)" + hex(v);
        }
        return hex(v);
    }

    std::string frame_name(std::int64_t off, int size) {
        if (const auto alias = cx_.param_slot.find(off); alias != cx_.param_slot.end()) {
            used_params_.insert(alias->second);
            return "a" + std::to_string(alias->second);
        }
        char buf[48];
        if (off < 0) std::snprintf(buf, sizeof buf, "var_%llX", static_cast<unsigned long long>(-off));
        else std::snprintf(buf, sizeof buf, "arg_%llX", static_cast<unsigned long long>(off));
        const std::string name = buf;
        auto& entry = declared_frame_[name];
        entry = (std::max)(entry, size);
        const int declared = cx_.frame_sizes.count(off) ? cx_.frame_sizes[off] : size;
        if (size != declared && declared != 0) return "*(" + type_for_size(size) + "*)&" + name;
        return name;
    }

    static std::string fp_type_name(int fp) { return fp == 1 ? "float" : fp == 2 ? "double" : "long double"; }

    std::string fp_const_text(const EP& e) {
        const double value = fconst_value(e);
        if (std::isnan(value)) return e->fp == 1 ? "NAN" : "(double)NAN";
        if (std::isinf(value)) return value < 0 ? "-INFINITY" : "INFINITY";
        std::string text;
        const double magnitude = std::fabs(value);
        const bool plain = magnitude == 0.0 || (magnitude >= 1e-5 && magnitude < 1e15);
        for (int precision = plain ? 0 : 1; precision <= 17; ++precision) {
            std::ostringstream s;
            if (plain) s << std::fixed << std::setprecision(precision) << value; else s << std::setprecision(precision) << value;
            text = s.str();
            const double back = e->fp == 1 ? static_cast<double>(std::strtof(text.c_str(), nullptr)) : std::strtod(text.c_str(), nullptr);
            if (back == value) break;
        }
        if (plain && text.find('.') != std::string::npos) while (text.size() > 1 && text.back() == '0' && text[text.size() - 2] != '.') text.pop_back();
        if (text.find_first_of(".eEn") == std::string::npos) text += ".0";
        if (e->fp == 1) text += "f";
        return text;
    }

    std::string var_text(const EP& e) {
        if (e->temp) {
            auto it = temp_names_.find(e->name);
            if (it == temp_names_.end()) it = temp_names_.emplace(e->name, "v" + std::to_string(temp_names_.size() + 1)).first;
            temp_types_[it->second] = (std::max)(temp_types_[it->second], e->size);
            if (e->fp) temp_fp_[it->second] = (std::max)(temp_fp_[it->second], static_cast<int>(e->fp));
            return it->second;
        }
        if (e->fp && !(e->name.size() >= 2 && e->name[0] == 'a' && std::isdigit(static_cast<unsigned char>(e->name[1])))) reg_fp_[e->name] = (std::max)(reg_fp_[e->name], static_cast<int>(e->fp));

        if (const auto it = rename_.find(e->name); it != rename_.end()) { used_regs_.insert(it->second); return it->second; }
        if (e->name.rfind("__cc_", 0) == 0) return "/*" + e->name.substr(5) + "*/ flag";
        used_regs_.insert(e->name);
        return e->name;
    }

    std::string deref_text(const EP& e, bool lvalue = false) {
        (void)lvalue;
        const int size = e->size;
        const EP& addr = e->a[0];
        const std::string elem = e->fp ? fp_type_name(e->fp) : type_for_size(size);
        if (addr->kind == K::Frame) {
            const std::string name = frame_name(frame_offset(addr), size);
            if (e->fp && name.find_first_of("*(") == std::string::npos && name.rfind("a", 0) != 0) frame_fp_[name] = (std::max)(frame_fp_[name], static_cast<int>(e->fp));
            return name;
        }
        if (addr->kind == K::Const) {
            const std::uint64_t a = addr->imm;
            if (cx_.options.name_of) { const auto n = cx_.options.name_of(a); if (!n.empty()) return n; }
            static const char* prefix[] = {"", "byte_", "word_", "", "dword_", "", "", "", "qword_"};
            char buf[64]; std::snprintf(buf, sizeof buf, "%s%llX", size <= 8 ? prefix[size] : "data_", static_cast<unsigned long long>(a));
            if (size == 3 || size == 5 || size == 6 || size == 7) return "*(" + type_for_size(size) + "*)" + hex(a);
            if (e->fp) return "*(" + elem + "*)" + hex(a);
            return buf;
        }
        if (addr->kind == K::Intrin && (addr->name == "__fsbase" || addr->name == "__gsbase") && !addr->a.empty()) {
            const std::string seg = addr->name == "__fsbase" ? "fs" : "gs";
            const char* w = size == 1 ? "byte" : size == 2 ? "word" : size == 4 ? "dword" : "qword";
            return "__read" + seg + w + "(" + expr(addr->a[0]) + ")";
        }
        // base + index*scale  ->  ((T*)base)[index]
        if (addr->kind == K::Bin && addr->name == "+") {
            const EP& l = addr->a[0]; const EP& r = addr->a[1];
            if (r->kind == K::Bin && r->name == "*" && is_const(r->a[1]) && static_cast<int>(r->a[1]->imm) == size && !is_const(l))
                return "((" + elem + "*)" + expr(l, 13) + ")[" + expr(r->a[0]) + "]";
            if (size == 1 && !is_const(r) && !is_const(l))
                return "((uint8_t*)" + expr(l, 13) + ")[" + expr(r) + "]";
        }
        return "*(" + elem + "*)" + (addr->kind == K::Var || addr->kind == K::Call ? expr(addr, 13) : "(" + expr(addr) + ")");
    }

    std::string expr(const EP& e, int parent = 0) {
        switch (e->kind) {
        case K::Const: return e->fp ? fp_const_text(e) : const_text(e->imm, e->size);
        case K::Var: return var_text(e);
        case K::Frame: {
            const auto off = frame_offset(e);
            char buf[48];
            if (off < 0) std::snprintf(buf, sizeof buf, "&var_%llX", static_cast<unsigned long long>(-off));
            else std::snprintf(buf, sizeof buf, "&arg_%llX", static_cast<unsigned long long>(off));
            declared_frame_[buf + 1];
            return buf;
        }
        case K::Un: return paren(e->name + expr(e->a[0], 12), 12, parent);
        case K::Cast: return paren("(" + e->name + ")" + expr(e->a[0], 12), 12, parent);
        case K::Deref: return deref_text(e);
        case K::Tern: return paren(expr(e->a[0], 2) + " ? " + expr(e->a[1], 1) + " : " + expr(e->a[2], 1), 1, parent);
        case K::Intrin: {
            std::string out = e->name + "(";
            for (std::size_t i = 0; i < e->a.size(); ++i) out += (i ? ", " : "") + expr(e->a[i]);
            return out + ")";
        }
        case K::Call: {
            std::string out;
            std::size_t first = 0;
            if (e->imm == 1) { out = "(" + expr(e->a[0], 0) + ")"; first = 1; }
            else out = strip_import_decoration(e->name);
            out += "(";
            for (std::size_t i = first; i < e->a.size(); ++i) out += (i > first ? ", " : "") + expr(e->a[i]);
            return out + ")";
        }
        case K::Bin: {
            const int p = precedence(e->name);
            std::string op = e->name;
            EP r = e->a[1];
            if (op == "+" && is_const(r) && (static_cast<std::int64_t>(r->imm) < 0) && static_cast<std::int64_t>(r->imm) > -0x100000) {
                op = "-"; r = konst(~r->imm + 1, r->size);
            }
            return paren(expr(e->a[0], p) + " " + op + " " + expr(r, p + 1), p, parent);
        }
        }
        return "?";
    }

    static std::string paren(const std::string& text, int own, int parent) { return own < parent ? "(" + text + ")" : text; }

    std::string stmt_text(const Stmt& s) {
        std::string lhs;
        if (s.type == Stmt::T::Assign) lhs = expr(s.lhs);
        else if (s.type == Stmt::T::Store) {
            const int store_fp = s.value && s.value->fp ? (s.size == 4 ? 1 : s.size == 8 ? 2 : 3) : 0;
            if (s.addr->kind == K::Frame) {
                lhs = frame_name(frame_offset(s.addr), s.size);
                if (store_fp && lhs.find_first_of("*(") == std::string::npos && lhs.rfind("a", 0) != 0) frame_fp_[lhs] = (std::max)(frame_fp_[lhs], store_fp);
            } else lhs = deref_text(store_fp ? fderef(s.size, s.addr, store_fp) : deref(s.size, s.addr), true);
        } else return expr(s.value) + ";";
        const EP& v = s.value;
        if (v->kind == K::Bin) {
            static const std::set<std::string> compound{"+", "-", "*", "&", "|", "^", "<<", ">>"};
            std::string op = v->name; EP rhs = v->a[1];
            if (op == "+" && is_const(rhs) && static_cast<std::int64_t>(rhs->imm) < 0 && static_cast<std::int64_t>(rhs->imm) > -0x100000) { op = "-"; rhs = konst(~rhs->imm + 1, rhs->size); }
            if (compound.contains(op) && expr(v->a[0]) == lhs) {
                if ((op == "+" || op == "-") && is_const(rhs) && rhs->imm == 1) return lhs + (op == "+" ? "++;" : "--;");
                return lhs + " " + op + "= " + expr(rhs) + ";";
            }
        }
        return lhs + " = " + expr(v) + ";";
    }

    void print_seq(const Seq& seq, int indent, std::ostringstream& out) {
        const std::string pad(indent * 4, ' ');
        for (const auto& node : seq) {
            switch (node->type) {
            case Node::T::Label:
                out << "LABEL_" << hex_label(cx_.blocks[node->block].address) << ":\n"; break;
            case Node::T::Stmt:
                if (cx_.options.address_comments && node->address) out << pad << "// " << hex(node->address) << "\n";
                out << pad << stmt_text(node->stmt) << "\n"; break;
            case Node::T::Return:
                if (node->value) out << pad << "return " << expr(node->value) << ";\n"; else out << pad << "return;\n";
                break;
            case Node::T::Break: out << pad << "break;\n"; break;
            case Node::T::Continue: out << pad << "continue;\n"; break;
            case Node::T::Goto: out << pad << "goto LABEL_" << hex_label(cx_.blocks[node->block].address) << ";\n"; break;
            case Node::T::Raw:
                if (node->text == "goto") out << pad << "goto " << (cx_.options.name_of && !cx_.options.name_of(node->address).empty() ? cx_.options.name_of(node->address) : "loc_" + hex_label(node->address)) << ";\n";
                else out << pad << node->text << "(" << (node->value ? expr(node->value) : "") << ");\n";
                break;
            case Node::T::If: {
                out << pad << "if ( " << expr(node->cond) << " )\n" << pad << "{\n";
                print_seq(node->body, indent + 1, out);
                out << pad << "}\n";
                if (!node->other.empty()) {
                    if (node->other.size() == 1 && node->other[0]->type == Node::T::If) {
                        out << pad << "else\n";
                        // else-if chain
                        std::ostringstream inner; print_seq(node->other, indent, inner);
                        std::string text = inner.str();
                        out << text;
                    } else {
                        out << pad << "else\n" << pad << "{\n";
                        print_seq(node->other, indent + 1, out);
                        out << pad << "}\n";
                    }
                }
                break;
            }
            case Node::T::Switch:
                out << pad << "switch ( " << expr(node->cond) << " )\n" << pad << "{\n";
                print_seq(node->body, indent + 1, out);
                out << pad << "}\n"; break;
            case Node::T::Case: {
                const std::string case_pad((indent > 0 ? indent - 1 : 0) * 4, ' ');
                if (node->is_default) out << case_pad << "default:\n";
                else for (const auto v : node->values) out << case_pad << "case " << v << ":\n";
                print_seq(node->body, indent, out);
                break;
            }
            case Node::T::Loop:
                out << pad << "while ( 1 )\n" << pad << "{\n"; print_seq(node->body, indent + 1, out); out << pad << "}\n"; break;
            case Node::T::While:
                out << pad << "while ( " << expr(node->cond) << " )\n" << pad << "{\n"; print_seq(node->body, indent + 1, out); out << pad << "}\n"; break;
            case Node::T::DoWhile:
                out << pad << "do\n" << pad << "{\n"; print_seq(node->body, indent + 1, out); out << pad << "}\n"
                    << pad << "while ( " << expr(node->cond) << " );\n"; break;
            }
        }
    }

    static std::string hex_label(std::uint64_t a) { char b[24]; std::snprintf(b, sizeof b, "%llX", static_cast<unsigned long long>(a)); return b; }

    std::string declarations() {
        std::ostringstream out;
        for (const auto& [name, size] : declared_frame_) {
            const std::string clean = name;
            if (clean.empty()) continue;
            const auto fp = frame_fp_.find(clean);
            out << "    " << (fp != frame_fp_.end() ? fp_type_name(fp->second) : type_for_size(size ? size : 8)) << " " << clean << ";\n";
        }
        for (const auto& reg : used_regs_) {
            if (reg.size() >= 2 && reg[0] == 'a' && std::isdigit(static_cast<unsigned char>(reg[1]))) continue; // parameter
            const auto fp = reg_fp_.find(reg);
            std::string type = reg.rfind("xmm", 0) == 0 ? "__m128" : "int64_t";
            if (fp != reg_fp_.end() && fp->second) type = fp_type_name(fp->second);
            out << "    " << type << " " << reg << ";\n";
        }
        std::map<int, std::string> by_number;
        for (const auto& [name, size] : temp_types_) {
            const auto fp = temp_fp_.find(name);
            by_number[std::stoi(name.substr(1))] = "    " + (fp != temp_fp_.end() && fp->second ? fp_type_name(fp->second) : type_for_size(size ? size : 8)) + " " + name + ";\n";
        }
        for (const auto& [number, line] : by_number) out << line;
        return out.str();
    }

private:
    Ctx& cx_;
    std::map<std::string, std::string> rename_;
    std::unordered_map<std::string, std::string> temp_names_;
    std::map<std::string, int> temp_types_;
    std::map<std::string, int> temp_fp_, reg_fp_, frame_fp_;
    std::map<int, std::string> fp_param_;
    std::set<std::string> used_regs_;
    std::map<std::string, int> declared_frame_;
    int arg_count_{0};
    std::set<int> used_params_;
};

} // namespace

DecompileResult decompile_function(const BinaryImage& image, const std::string& name, std::uint64_t start,
                                   const std::vector<Instruction>& instructions, const DecompilerOptions& options) {
    DecompileResult result;
    if (image.architecture != MachineArchitecture::X64 && image.architecture != MachineArchitecture::ARM64 && image.architecture != MachineArchitecture::Unknown) {
        result.error = "Structured decompilation currently supports x86-64 and AArch64 only."; return result;
    }
    if (!image.is_64_bit && image.architecture != MachineArchitecture::Unknown) {
        result.error = "Structured decompilation currently supports 64-bit code only."; return result;
    }
    struct ArmScope { bool previous; explicit ArmScope(bool on) : previous(g_arm) { g_arm = on; } ~ArmScope() { g_arm = previous; } } arm_scope(image.architecture == MachineArchitecture::ARM64);
    if (instructions.empty()) { result.error = "No instructions to decompile."; return result; }

    Ctx cx{image, options, {}, {}, {}, {}, start};
    cx.insns = instructions;
    std::sort(cx.insns.begin(), cx.insns.end(), [](const Instruction& a, const Instruction& b) { return a.address < b.address; });
    cx.insns.erase(std::unique(cx.insns.begin(), cx.insns.end(), [](const Instruction& a, const Instruction& b) { return a.address == b.address; }), cx.insns.end());
    for (std::size_t i = 0; i < cx.insns.size(); ++i) cx.insn_at[cx.insns[i].address] = i;
    if (!cx.insn_at.contains(start)) { result.error = "Function entry is not among the supplied instructions."; return result; }

    init_abi(cx);
    find_switches(cx);
    build_blocks(cx);
    compute_arg_masks(cx);
    lift_all(cx);
    inline_all(cx);
    fold_constant_branches(cx);
    liveness_prune(cx);
    inline_all(cx);
    frame_store_elimination(cx);
    inline_all(cx);
    liveness_prune(cx);
    std::uint32_t entry_live = liveness_prune(cx);
    entry_live |= promote_parameters(cx);
    sequentialize_moves(cx);

    for (const auto& b : cx.blocks) if (b.lifted) ++result.block_count;

    Structurer structurer(cx);
    Seq body = structurer.run();
    structurer.count_gotos(body);
    result.goto_count = structurer.goto_count();

    Printer printer(cx, entry_live);
    std::ostringstream body_text;
    printer.print_seq(body, 1, body_text);

    std::ostringstream out;
    out << "// " << name << "  @ " << hex(start) << "\n";
    const bool returns_value = cx.saw_return_value;
    const char* return_type = cx.return_fp == 1 ? "float" : cx.return_fp == 2 ? "double" : cx.return_fp == 3 ? "long double" : returns_value ? "int64_t" : "void";
    out << return_type << (options.windows_abi && !g_arm ? " __fastcall " : " ") << name << "(";
    for (int i = 1; i <= printer.arg_count(); ++i) {
        const auto sz = cx.param_size.find(i);
        const std::string fp_type = printer.param_fp_type(i);
        const char* type = sz == cx.param_size.end() || sz->second == 8 ? "int64_t" : sz->second == 4 ? "int32_t" : sz->second == 2 ? "uint16_t" : "uint8_t";
        out << (i > 1 ? ", " : "") << (fp_type.empty() ? std::string(type) : fp_type) << " a" << i;
    }
    if (printer.arg_count() == 0) out << "void";
    out << ")\n{\n";
    out << printer.declarations();
    out << body_text.str();
    out << "}\n";
    result.text = out.str();
    result.ok = true;
    return result;
}

DecompileResult decompile_function_at(const AnalysisDatabase& database, std::uint64_t address, bool address_comments,
                                      const std::function<std::string(std::uint64_t)>& user_names,
                                      const std::set<std::uint64_t>* noreturn_functions) {
    const auto function = database.function_at(address);
    DecompileResult result;
    if (!function) { result.error = "No function contains this address."; return result; }
    const BinaryImage& image = database.image();
    DecompilerOptions options;
    options.windows_abi = image.format == BinaryFormat::PE;
    if (noreturn_functions) options.is_noreturn = [noreturn_functions](std::uint64_t a) { return noreturn_functions->count(a) != 0; };
    options.address_comments = address_comments;
    std::unordered_map<std::uint64_t, std::string> names;
    for (const auto& f : database.functions()) names[f.start] = f.name;
    std::unordered_map<std::uint64_t, std::string> slot_names;
    for (const auto& imp : image.imports) slot_names[imp.address] = imp.name;
    for (const auto& imp : parse_imports(image)) {
        std::string clean = imp.name;
        for (auto& ch : clean) if (ch == ' ') ch = '_';   // "Ordinal 413" -> "Ordinal_413"
        slot_names[imp.iat] = clean;
    }
    for (const auto& [slot, name] : slot_names) names[slot] = name;
    // PLT / import thunks: a function that is only `jmp [slot]` is named after the import.
    for (const auto& f : database.functions()) {
        const Instruction* sole = nullptr; int count = 0;
        for (const auto& ins : f.instructions) {
            if (ins.mnemonic == "endbr64" || ins.mnemonic == "nop") continue;
            sole = &ins; ++count;
        }
        if (count != 1 || !sole) continue;
        std::string m = sole->mnemonic;
        if (m.rfind("bnd ", 0) == 0) m = m.substr(4);
        if (m != "jmp") continue;
        const auto op = parse_operand(sole->operands);
        if (op.type != Operand::T::Mem || !op.mem.rip) continue;
        const auto slot = sole->address + sole->size + static_cast<std::uint64_t>(op.mem.disp);
        const auto found = slot_names.find(slot);
        if (found != slot_names.end()) names[f.start] = found->second;
    }
    for (const auto& sym : image.symbols) if (!sym.name.empty() && !names.contains(sym.address)) names[sym.address] = sym.name;
    options.name_of = [names = std::move(names), user_names](std::uint64_t a) -> std::string {
        if (user_names) { auto custom = user_names(a); if (!custom.empty()) return custom; }
        const auto it = names.find(a); return it == names.end() ? std::string() : it->second;
    };
    std::string function_name = function->get().name;
    if (user_names) { auto custom = user_names(function->get().start); if (!custom.empty()) function_name = custom; }
    else if (const auto resolved = options.name_of(function->get().start); !resolved.empty()) function_name = resolved;
    if (const auto cut = function_name.find(' '); cut != std::string::npos && cut > 0) function_name.resize(cut);
    return decompile_function(image, function_name, function->get().start, function->get().instructions, options);
}

} // namespace gandon
