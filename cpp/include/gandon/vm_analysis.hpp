#pragma once

#include "gandon/core.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace gandon {

// Result of scanning a function for a byte-code virtual machine dispatcher of
// the kind VMProtect / Themida / custom protectors use: a loop that fetches a
// virtual opcode and jumps through a table of handler routines. Finding the
// dispatch site and the handler table is the foothold for manual
// devirtualisation — it is NOT a full automatic lift of the bytecode.
struct VmDispatch {
    bool found{false};
    std::uint64_t dispatch_site{0};        // address of the indirect jmp that dispatches
    std::uint64_t table_va{0};             // virtual address of the handler-pointer table
    int scale{0};                          // index scale of the table (4 or 8)
    std::vector<std::uint64_t> handlers;   // distinct handler addresses read from the table
    std::string note;                      // human-readable summary / why nothing was found
};

// Statically scan a decoded function for a VM dispatch loop and, when found,
// read the handler table out of the image. `instructions` is the function's
// decoded instruction list.
VmDispatch detect_vm_dispatch(const BinaryImage& image, std::uint64_t function_start,
                              const std::vector<Instruction>& instructions);

// Dynamic VM handler trace: emulate from `entry` and record the sequence of
// handler routines reached, by breakpointing each handler of a detected
// dispatch table. This recovers the order handlers run in — the raw material
// for manual devirtualisation. Heavy protectors with anti-emulation behaviour
// will cut the trace short; it is not a full lift of the bytecode.
struct VmTrace {
    bool ok{false};
    std::string error;
    std::vector<std::uint64_t> handler_sequence;
    std::size_t steps{0};
    bool truncated{false};
};
VmTrace trace_vm_handlers(const BinaryImage& image, std::uint64_t entry, const VmDispatch& dispatch,
                          std::size_t max_handlers = 2000);

// Control-flow-flattening / obfuscation triage for one function. A flattened
// function routes almost every block back through a central dispatcher that
// switches on a state variable; this reports the suspected dispatcher (the
// branch target with the highest in-degree) and coarse obfuscation metrics.
// It is a detector, not an automatic de-flattener.
struct FlatteningReport {
    bool flattened{false};
    std::uint64_t dispatcher{0};     // most-targeted address inside the function
    std::size_t dispatcher_in_degree{0};
    std::size_t branch_count{0};
    std::size_t indirect_jumps{0};
    std::string note;
};
FlatteningReport detect_flattening(const BinaryImage& image, std::uint64_t function_start,
                                   const std::vector<Instruction>& instructions);

// A one-line guess at what a single VM handler does, from the operations in its
// body (semi-automatic devirtualisation: the operator still reads each handler,
// but the classification narrows down which bytecode op it implements).
struct VmHandlerInfo {
    std::uint64_t address{0};
    std::size_t instruction_count{0};
    std::string classification;     // e.g. "arith(+)", "logic(xor)", "load/store", "stack", "branch"
};
std::vector<VmHandlerInfo> classify_vm_handlers(const BinaryImage& image, const VmDispatch& dispatch);

} // namespace gandon
