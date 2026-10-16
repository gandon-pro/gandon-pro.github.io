#pragma once

#include "gandon/core.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace gandon {

// A small, architecture-neutral, LLIL-inspired IR. Expression references are
// indexes into LowLevelIlProgram::expressions; statement branch targets are
// indexes into LowLevelIlProgram::statements.
enum class IlExpressionOp : std::uint8_t {
    Constant,
    Register,
    Load,
    Add,
    Subtract,
    Multiply,
    UnsignedDivide,
    And,
    Or,
    Xor,
    ShiftLeft,
    LogicalShiftRight,
    ArithmeticShiftRight,
    Equal,
    NotEqual,
    UnsignedLessThan,
    SignedLessThan,
    ZeroExtend,
    SignExtend,
    Truncate,
    Select
};

struct IlExpression {
    IlExpressionOp operation{IlExpressionOp::Constant};
    std::uint8_t size_bytes{8};
    std::uint32_t left{UINT32_MAX};
    std::uint32_t right{UINT32_MAX};
    std::uint32_t third{UINT32_MAX};
    std::uint64_t immediate{0};
    std::string register_name;
};

enum class IlStatementOp : std::uint8_t { Nop, SetRegister, Store, Push, PopRegister, Jump, Branch, Return };

struct IlStatement {
    IlStatementOp operation{IlStatementOp::Nop};
    std::uint8_t size_bytes{8};
    std::uint32_t value{UINT32_MAX};
    std::uint32_t address{UINT32_MAX};
    std::uint32_t condition{UINT32_MAX};
    std::size_t true_target{0};
    std::size_t false_target{0};
    std::string register_name;
    std::uint64_t source_address{0};
};

struct LowLevelIlProgram {
    std::vector<IlExpression> expressions;
    std::vector<IlStatement> statements;
    std::size_t entry_statement{0};
};

enum class IlEmulationStop { Paused, Returned, InstructionLimit, Error };

struct IlEmulationResult {
    IlEmulationStop stop{IlEmulationStop::Error};
    std::size_t statements_executed{0};
    std::size_t statement_index{0};
    std::optional<std::uint64_t> return_value;
    std::string error;
};

// Standalone LLIL-style snippet interpreter. It deliberately does not depend
// on Binary Ninja's SDK; native CPU emulation remains available via Emulator.
class LowLevelIlEmulator {
public:
    static constexpr std::size_t maximum_mapped_bytes = 64 * 1024 * 1024;

    explicit LowLevelIlEmulator(LowLevelIlProgram program);

    bool ready() const noexcept { return error_.empty(); }
    const std::string& error() const noexcept { return error_; }
    std::size_t statement_index() const noexcept { return statement_index_; }
    bool set_register(const std::string& name, std::uint64_t value, std::string& error);
    bool register_value(const std::string& name, std::uint64_t& value, std::string& error) const;
    bool write_memory(std::uint64_t address, const void* data, std::size_t size, std::string& error);
    bool read_memory(std::uint64_t address, void* data, std::size_t size, std::string& error) const;
    bool map_image_sections(const BinaryImage& image, bool& truncated, std::string& error);
    std::size_t mapped_memory_bytes() const noexcept { return mapped_memory_bytes_; }
    IlEmulationResult step();
    IlEmulationResult run(std::size_t statement_limit = 100'000);

private:
    std::optional<std::uint64_t> evaluate(std::uint32_t expression, std::size_t depth,
                                          std::string& error) const;
    LowLevelIlProgram program_;
    std::unordered_map<std::string, std::uint64_t> registers_;
    // Contiguous ranges keep image-backed data compact; a byte-per-node hash
    // table made even modest executable images consume hundreds of MiB.
    std::map<std::uint64_t, std::vector<std::uint8_t>> memory_;
    std::size_t mapped_memory_bytes_{0};
    std::size_t statement_index_{0};
    bool returned_{false};
    std::optional<std::uint64_t> return_value_;
    std::string error_;
};

// Lift a deliberately small, explicit x86-64 integer subset from decoded
// instructions into the standalone IL. Unsupported mnemonics/operands fail
// with a diagnostic instead of silently producing inaccurate semantics.
std::optional<LowLevelIlProgram> lift_x64_to_low_level_il(
    const std::vector<Instruction>& instructions, std::string& error);

} // namespace gandon
