#pragma once

#include "gandon/core.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace gandon {

enum class EmulationStop { Paused, Returned, Exited, Breakpoint, Watchpoint, InstructionLimit, TimedOut, MemoryFault, Error };

struct EmulationResult {
    EmulationStop stop{EmulationStop::Error};
    std::size_t instructions_executed{0};
    std::uint64_t program_counter{0};
    std::string error;
};

struct EmulationTraceEntry {
    std::uint64_t address{0};
    std::uint8_t size{0};
    std::array<std::uint8_t, 15> bytes{};
    std::uint8_t byte_count{0};
    std::string annotation;
};

struct EmulationMemoryAccess {
    std::uint64_t instruction_address{0};
    std::uint64_t address{0};
    std::uint64_t value{0};
    std::uint32_t size{0};
    bool write{false};
    bool value_captured{false};
};

struct EmulationRegisterDelta {
    std::size_t trace_index{0};
    // x86 bits: A, B, C, D, SI, DI, BP, SP, R8-R15, EFLAGS.
    // AArch64 bits: X0-X30, SP, PC, NZCV.
    std::uint64_t changed_mask{0};
    // Packed values follow ascending set-bit order in changed_mask.
    std::array<std::uint64_t, 4> values{};
    std::uint8_t value_count{0};
    bool values_truncated{false};
};

// In-process, sandboxed CPU emulation. Guest instructions run inside Unicorn;
// they are never executed as host code. Modeled guest syscalls use in-memory shims only.
class Emulator {
public:
    explicit Emulator(const BinaryImage& image);
    ~Emulator();
    Emulator(Emulator&&) noexcept;
    Emulator& operator=(Emulator&&) noexcept;
    Emulator(const Emulator&) = delete;
    Emulator& operator=(const Emulator&) = delete;

    bool ready() const noexcept;
    const std::string& error() const noexcept;
    void set_standard_input(std::string input);
    const std::string& standard_output() const noexcept;
    const std::string& standard_error() const noexcept;
    int exit_code() const noexcept;
    bool set_register(const std::string& name, std::uint64_t value, std::string& error);
    bool register_value(const std::string& name, std::uint64_t& value, std::string& error) const;
    bool read_memory(std::uint64_t address, void* destination, std::size_t size, std::string& error) const;
    bool write_memory(std::uint64_t address, const void* source, std::size_t size, std::string& error);
    void add_breakpoint(std::uint64_t address);
    void remove_breakpoint(std::uint64_t address);
    bool has_breakpoint(std::uint64_t address) const noexcept;
    bool add_watchpoint(std::uint64_t address, std::uint64_t size, bool on_read, bool on_write);
    void clear_watchpoints() noexcept;
    EmulationResult step();
    EmulationResult step_over(std::size_t instruction_limit = 100'000,
                              std::uint64_t timeout_microseconds = 1'000'000);
    EmulationResult step_out(std::size_t instruction_limit = 100'000,
                             std::uint64_t timeout_microseconds = 1'000'000);
    EmulationResult run(std::size_t instruction_limit = 100'000, std::uint64_t timeout_microseconds = 1'000'000);
    const std::vector<EmulationTraceEntry>& trace() const noexcept;
    bool trace_truncated() const noexcept;
    void set_register_delta_capture(bool enabled) noexcept;
    bool register_delta_capture_enabled() const noexcept;
    const std::vector<EmulationRegisterDelta>& register_deltas() const noexcept;
    bool register_deltas_truncated() const noexcept;
    const std::vector<EmulationMemoryAccess>& memory_accesses() const noexcept;
    bool memory_accesses_truncated() const noexcept;
    const std::vector<std::uint64_t>& call_stack() const noexcept;
    bool call_stack_truncated() const noexcept;
    void clear_trace() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace gandon
