#pragma once

#include "gandon/core.hpp"

#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <vector>

namespace gandon {

// Options for the structured pseudocode generator.
struct DecompilerOptions {
    // true: Microsoft x64 ABI (rcx, rdx, r8, r9). false: System V AMD64 ABI.
    bool windows_abi{true};
    // Prefix every emitted statement with its source address as a comment.
    bool address_comments{false};
    // Maps a virtual address to a symbol (function, import slot, global).
    // Return an empty string when nothing is known.
    std::function<std::string(std::uint64_t)> name_of;
    // Returns true when the function at the address never returns (calls to it end the block).
    std::function<bool(std::uint64_t)> is_noreturn;
    // Interprocedural hint: the recovered integer-argument count of a locally
    // defined callee, so a direct `call sub_X` renders with the callee's real
    // parameters even when the caller does not set every argument register in
    // this block. Return a negative value when nothing is known.
    std::function<int(std::uint64_t)> arg_count_of;
};

struct DecompileResult {
    bool ok{false};
    std::string error;           // Filled when ok == false (e.g. unsupported architecture).
    std::string text;            // C-like pseudocode.
    std::size_t block_count{0};
    std::size_t goto_count{0};   // Remaining unstructured jumps.
    // Recovered signature, usable for interprocedural propagation.
    int recovered_args{0};       // integer/pointer parameters in the prototype
    bool returns_value{false};   // function produces a value in rax/xmm0
    int return_fp{0};            // 1 float, 2 double, 3 long double when FP-returning
    std::string convention;      // "__fastcall" / "__stdcall" / "System V" / "AAPCS64"
};

// Decompile one x86-64 function. `instructions` must be the decoded
// instruction list of the function (address-sorted or not, duplicates are
// ignored). The image is used for string / global resolution only.
DecompileResult decompile_function(const BinaryImage& image, const std::string& name,
                                   std::uint64_t start,
                                   const std::vector<Instruction>& instructions,
                                   const DecompilerOptions& options = {});

// Convenience wrapper: resolves function names and import slots from the
// database and picks the ABI from the image format (PE = Windows, ELF = SysV).
DecompileResult decompile_function_at(const AnalysisDatabase& database, std::uint64_t address,
                                      bool address_comments = false,
                                      const std::function<std::string(std::uint64_t)>& user_names = {},
                                      const std::set<std::uint64_t>* noreturn_functions = nullptr);

} // namespace gandon
