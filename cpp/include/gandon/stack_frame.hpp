#pragma once

#include "gandon/core.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace gandon {

// A single stack slot discovered in a function's frame. Offsets are normalised
// to rbp semantics: negative = local variable, >= 0x10 = incoming stack
// argument (above the saved frame pointer and return address).
struct StackVar {
    long long offset{0};
    std::uint32_t size{0};   // best-guess access width in bytes (0 = unknown)
    std::string name;        // "var_8", "arg_0", ...
    bool is_arg{false};
};

// The reconstructed stack frame of one function: how it addresses locals, how
// much stack it reserves, the discovered slots, and a rough prototype.
struct StackFrame {
    enum class Base { None, Rbp, Rsp };
    Base base{Base::None};
    std::uint64_t alloc{0};         // bytes reserved by the prologue (sub rsp, N)
    int reg_args{0};                // integer register arguments detected (ABI order)
    bool arm64{false};
    std::vector<StackVar> vars;     // offset-sorted (most negative first)

    bool empty() const { return vars.empty() && base == Base::None && reg_args == 0; }

    // Name for a frame memory reference "[reg +/- disp]"; reg is a stack-pointer
    // or frame-pointer register ("rbp"/"rsp"/"ebp"/"esp"). Returns nullopt when
    // the reference is not a recognisable local/argument slot.
    std::optional<std::string> rename(const std::string& reg, long long signed_disp) const;

    // "__int64 __fastcall name(__int64 a1, __int64 a2)" — a best-effort prototype.
    std::string prototype(const std::string& func_name, bool windows_abi) const;

    // IDA-style frame listing, e.g. "var_8          = dword ptr -8".
    std::vector<std::string> summary_lines() const;
};

// Analyses one function's instructions. `windows_abi` selects the integer
// argument registers used for register-argument counting (MS x64 vs SysV).
StackFrame analyze_stack_frame(const Function& function, bool is_64_bit, bool arm64, bool windows_abi);

} // namespace gandon
