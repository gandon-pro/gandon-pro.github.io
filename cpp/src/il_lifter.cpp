#include "gandon/il_emulator.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

namespace gandon {
namespace {

struct RegisterInfo { std::string canonical; std::uint8_t size_bytes; };

std::optional<RegisterInfo> register_info(const std::string& name) {
    static const std::unordered_map<std::string, RegisterInfo> aliases = {
        {"rax", {"rax", 8}}, {"eax", {"rax", 4}}, {"ax", {"rax", 2}}, {"al", {"rax", 1}},
        {"rbx", {"rbx", 8}}, {"ebx", {"rbx", 4}}, {"bx", {"rbx", 2}}, {"bl", {"rbx", 1}},
        {"rcx", {"rcx", 8}}, {"ecx", {"rcx", 4}}, {"cx", {"rcx", 2}}, {"cl", {"rcx", 1}},
        {"rdx", {"rdx", 8}}, {"edx", {"rdx", 4}}, {"dx", {"rdx", 2}}, {"dl", {"rdx", 1}},
        {"rsi", {"rsi", 8}}, {"esi", {"rsi", 4}}, {"si", {"rsi", 2}}, {"sil", {"rsi", 1}},
        {"rdi", {"rdi", 8}}, {"edi", {"rdi", 4}}, {"di", {"rdi", 2}}, {"dil", {"rdi", 1}},
        {"rbp", {"rbp", 8}}, {"ebp", {"rbp", 4}}, {"bp", {"rbp", 2}}, {"bpl", {"rbp", 1}},
        {"rsp", {"rsp", 8}}, {"esp", {"rsp", 4}}, {"sp", {"rsp", 2}}, {"spl", {"rsp", 1}}
    };
    if (const auto found = aliases.find(name); found != aliases.end()) return found->second;
    if (name.size() >= 2 && name[0] == 'r' && std::isdigit(static_cast<unsigned char>(name[1]))) {
        std::size_t digit_end = 1;
        while (digit_end < name.size() && std::isdigit(static_cast<unsigned char>(name[digit_end]))) ++digit_end;
        unsigned number = 0;
        for (std::size_t index = 1; index < digit_end; ++index) {
            number = number * 10 + static_cast<unsigned>(name[index] - '0');
            if (number > 15) return std::nullopt;
        }
        if (number < 8 || number > 15) return std::nullopt;
        const auto suffix = name.substr(digit_end);
        const std::uint8_t size = suffix.empty() ? 8 : suffix == "d" ? 4 : suffix == "w" ? 2 : suffix == "b" ? 1 : 0;
        if (size) return RegisterInfo{"r" + std::to_string(number), size};
    }
    return std::nullopt;
}

std::string lower_trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    value = value.substr(first, last - first + 1);
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return value;
}

std::vector<std::string> split_operands(const std::string& text) {
    std::vector<std::string> result;
    std::size_t begin = 0;
    int bracket_depth = 0;
    for (std::size_t index = 0; index <= text.size(); ++index) {
        if (index < text.size() && text[index] == '[') ++bracket_depth;
        else if (index < text.size() && text[index] == ']') --bracket_depth;
        if (index == text.size() || (text[index] == ',' && bracket_depth == 0)) {
            result.push_back(lower_trim(text.substr(begin, index - begin)));
            begin = index + 1;
        }
    }
    if (result.size() == 1 && result.front().empty()) result.clear();
    return result;
}

std::optional<std::uint64_t> parse_immediate(const std::string& operand) {
    if (operand.empty() || operand.find('[') != std::string::npos) return std::nullopt;
    const auto stop = operand.find_first_of(" \t<");
    const auto token = operand.substr(0, stop);
    try {
        std::size_t used = 0;
        const auto value = std::stoull(token, &used, 0);
        if (used != token.size()) return std::nullopt;
        return value;
    } catch (...) { return std::nullopt; }
}

struct PendingBranch { std::size_t statement; std::uint64_t target; std::uint64_t fallthrough; bool conditional; };

struct MemoryTerm {
    std::string value;
    std::uint8_t scale{1};
    bool negative{false};
    bool immediate{false};
};

struct MemoryOperandSpec {
    std::optional<std::uint8_t> size_bytes;
    std::vector<MemoryTerm> terms;
};

std::optional<MemoryOperandSpec> parse_memory_operand(const std::string& operand) {
    const auto open = operand.find('[');
    const auto close = open == std::string::npos ? std::string::npos : operand.find(']', open + 1);
    if (open == std::string::npos || close == std::string::npos || operand.find('[', open + 1) != std::string::npos ||
        operand.find(']', close + 1) != std::string::npos || !lower_trim(operand.substr(close + 1)).empty()) return std::nullopt;

    MemoryOperandSpec result;
    const auto prefix = lower_trim(operand.substr(0, open));
    if (!prefix.empty()) {
        if (prefix.find("qword ptr") != std::string::npos) result.size_bytes = 8;
        else if (prefix.find("dword ptr") != std::string::npos) result.size_bytes = 4;
        else if (prefix.find("word ptr") != std::string::npos) result.size_bytes = 2;
        else if (prefix.find("byte ptr") != std::string::npos) result.size_bytes = 1;
        else return std::nullopt;
    }

    const auto expression = operand.substr(open + 1, close - open - 1);
    std::size_t position = 0;
    while (position < expression.size()) {
        while (position < expression.size() && std::isspace(static_cast<unsigned char>(expression[position]))) ++position;
        if (position == expression.size()) break;
        bool negative = false;
        if (expression[position] == '+' || expression[position] == '-') {
            negative = expression[position] == '-';
            ++position;
            while (position < expression.size() && std::isspace(static_cast<unsigned char>(expression[position]))) ++position;
        } else if (!result.terms.empty()) return std::nullopt;

        const auto begin = position;
        while (position < expression.size() && expression[position] != '+' && expression[position] != '-') ++position;
        auto token = lower_trim(expression.substr(begin, position - begin));
        token.erase(std::remove_if(token.begin(), token.end(), [](unsigned char c) { return std::isspace(c); }), token.end());
        if (token.empty()) return std::nullopt;

        MemoryTerm term;
        term.negative = negative;
        const auto star = token.find('*');
        if (star != std::string::npos) {
            if (token.find('*', star + 1) != std::string::npos) return std::nullopt;
            auto left = token.substr(0, star);
            auto right = token.substr(star + 1);
            auto reg = register_info(left);
            auto scale = parse_immediate(right);
            if (!reg || !scale) {
                reg = register_info(right);
                scale = parse_immediate(left);
                if (!reg || !scale) return std::nullopt;
                left = right;
            }
            if (*scale != 1 && *scale != 2 && *scale != 4 && *scale != 8) return std::nullopt;
            term.value = reg->canonical;
            term.scale = static_cast<std::uint8_t>(*scale);
        } else if (token == "rip") {
            term.value = token;
        } else if (const auto reg = register_info(token)) {
            term.value = reg->canonical;
        } else if (parse_immediate(token)) {
            term.value = token;
            term.immediate = true;
        } else return std::nullopt;
        result.terms.push_back(std::move(term));
    }
    if (result.terms.empty()) return std::nullopt;
    return result;
}

} // namespace

std::optional<LowLevelIlProgram> lift_x64_to_low_level_il(
    const std::vector<Instruction>& instructions, std::string& error) {
    if (instructions.empty()) { error = "No instructions were provided to the IL lifter."; return std::nullopt; }

    LowLevelIlProgram program;
    std::unordered_map<std::uint64_t, std::size_t> address_to_statement;
    std::vector<PendingBranch> pending_branches;
    std::uint64_t current_source_address = 0;
    std::uint64_t current_next_address = 0;
    const auto add_expression = [&](IlExpression expression) -> std::uint32_t {
        if (program.expressions.size() >= UINT32_MAX) return UINT32_MAX;
        program.expressions.push_back(std::move(expression));
        return static_cast<std::uint32_t>(program.expressions.size() - 1);
    };
    const auto constant = [&](std::uint8_t size, std::uint64_t value) {
        return add_expression({IlExpressionOp::Constant, size, UINT32_MAX, UINT32_MAX, UINT32_MAX, value, {}});
    };
    const auto register_expression = [&](const std::string& name, std::uint8_t size = 8) {
        return add_expression({IlExpressionOp::Register, size, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0, name});
    };
    const auto unary = [&](IlExpressionOp operation, std::uint8_t size, std::uint32_t child) {
        return add_expression({operation, size, child});
    };
    const auto binary = [&](IlExpressionOp operation, std::uint8_t size, std::uint32_t left, std::uint32_t right) {
        return add_expression({operation, size, left, right});
    };
    const auto append_statement = [&](IlStatement statement) -> std::size_t {
        if (!statement.source_address) statement.source_address = current_source_address;
        program.statements.push_back(std::move(statement));
        return program.statements.size() - 1;
    };
    const auto read_register = [&](const RegisterInfo& reg, std::uint8_t target_size) -> std::uint32_t {
        auto value = register_expression(reg.canonical);
        if (reg.size_bytes < 8) value = unary(IlExpressionOp::Truncate, reg.size_bytes, value);
        if (reg.size_bytes < target_size) value = unary(IlExpressionOp::ZeroExtend, target_size, value);
        else if (reg.size_bytes > target_size) value = unary(IlExpressionOp::Truncate, target_size, value);
        return value;
    };
    const auto memory_address = [&](const MemoryOperandSpec& memory) -> std::optional<std::uint32_t> {
        std::uint32_t address = UINT32_MAX;
        for (const auto& term : memory.terms) {
            std::uint32_t value = UINT32_MAX;
            if (term.immediate) {
                const auto immediate = parse_immediate(term.value);
                if (!immediate) return std::nullopt;
                value = constant(8, *immediate);
            } else if (term.value == "rip") {
                value = constant(8, current_next_address);
            } else {
                const auto reg = register_info(term.value);
                if (!reg) return std::nullopt;
                value = read_register(*reg, 8);
                if (term.scale > 1) value = binary(IlExpressionOp::Multiply, 8, value, constant(8, term.scale));
            }
            if (term.negative) value = binary(IlExpressionOp::Subtract, 8, constant(8, 0), value);
            address = address == UINT32_MAX ? value : binary(IlExpressionOp::Add, 8, address, value);
        }
        return address == UINT32_MAX ? std::nullopt : std::optional<std::uint32_t>(address);
    };
    const auto read_operand = [&](const std::string& operand, std::uint8_t target_size) -> std::optional<std::uint32_t> {
        if (const auto reg = register_info(operand)) return read_register(*reg, target_size);
        if (const auto immediate = parse_immediate(operand)) return constant(target_size, *immediate);
        if (const auto memory = parse_memory_operand(operand)) {
            const auto size = memory->size_bytes.value_or(target_size);
            if (size > target_size || !size) return std::nullopt;
            const auto address = memory_address(*memory);
            if (!address) return std::nullopt;
            auto value = add_expression({IlExpressionOp::Load, size, *address});
            if (size < target_size) value = unary(IlExpressionOp::ZeroExtend, target_size, value);
            return value;
        }
        return std::nullopt;
    };
    const auto write_register = [&](const RegisterInfo& reg, std::uint32_t value) {
        std::uint32_t full_value = value;
        if (reg.size_bytes == 4) {
            full_value = unary(IlExpressionOp::ZeroExtend, 8, value);
        } else if (reg.size_bytes < 4) {
            const auto old_value = register_expression(reg.canonical);
            const auto low_bits = (std::uint64_t{1} << (reg.size_bytes * 8)) - 1;
            const auto preserve_mask = constant(8, ~low_bits);
            const auto preserved = binary(IlExpressionOp::And, 8, old_value, preserve_mask);
            const auto zero_extended = unary(IlExpressionOp::ZeroExtend, 8, value);
            full_value = binary(IlExpressionOp::Or, 8, preserved, zero_extended);
        }
        append_statement({IlStatementOp::SetRegister, 8, full_value, UINT32_MAX, UINT32_MAX, 0, 0, reg.canonical});
    };
    const auto set_flag = [&](const char* name, std::uint32_t value) {
        append_statement({IlStatementOp::SetRegister, 1, value, UINT32_MAX, UINT32_MAX, 0, 0,
                          std::string("$il_") + name});
    };
    const auto update_arithmetic_flags = [&](std::uint32_t left, std::uint32_t right,
                                             std::uint32_t result, std::uint8_t size,
                                             bool is_subtraction, bool is_logical) {
        const auto zero = constant(size, 0);
        const auto is_zero = binary(IlExpressionOp::Equal, 1, result, zero);
        const auto is_sign = binary(IlExpressionOp::SignedLessThan, 1, result, zero);

        auto low_byte = result;
        if (size > 1) low_byte = unary(IlExpressionOp::Truncate, 1, low_byte);
        auto parity_fold = binary(IlExpressionOp::Xor, 1, low_byte,
                                  binary(IlExpressionOp::LogicalShiftRight, 1, low_byte, constant(1, 4)));
        parity_fold = binary(IlExpressionOp::Xor, 1, parity_fold,
                             binary(IlExpressionOp::LogicalShiftRight, 1, parity_fold, constant(1, 2)));
        parity_fold = binary(IlExpressionOp::Xor, 1, parity_fold,
                             binary(IlExpressionOp::LogicalShiftRight, 1, parity_fold, constant(1, 1)));
        const auto parity_bit = binary(IlExpressionOp::And, 1, parity_fold, constant(1, 1));
        const auto even_parity = binary(IlExpressionOp::Equal, 1, parity_bit, constant(1, 0));

        std::uint64_t width_mask = size == 8 ? UINT64_MAX : ((std::uint64_t{1} << (size * 8)) - 1);
        const auto mask = constant(size, width_mask);
        const auto left_xor_right = binary(IlExpressionOp::Xor, size, left, right);
        const auto left_xor_result = binary(IlExpressionOp::Xor, size, left, result);
        auto overflow_bits = is_subtraction
            ? binary(IlExpressionOp::And, size, left_xor_right, left_xor_result)
            : binary(IlExpressionOp::And, size,
                     binary(IlExpressionOp::Xor, size, left_xor_right, mask), left_xor_result);
        const auto sign_mask = constant(size, std::uint64_t{1} << (size * 8 - 1));
        const auto overflow_sign = binary(IlExpressionOp::And, size, overflow_bits, sign_mask);
        const auto overflow = binary(IlExpressionOp::NotEqual, 1, overflow_sign, zero);

        const auto carry = is_logical
            ? constant(1, 0)
            : binary(IlExpressionOp::UnsignedLessThan, 1,
                     is_subtraction ? left : result, is_subtraction ? right : left);
        const auto auxiliary_bits = is_logical
            ? constant(size, 0)
            : binary(IlExpressionOp::And, size,
                     binary(IlExpressionOp::Xor, size, left_xor_right, result), constant(size, 0x10));
        const auto auxiliary_carry = binary(IlExpressionOp::NotEqual, 1, auxiliary_bits, zero);

        set_flag("cf", carry);
        set_flag("zf", is_zero);
        set_flag("sf", is_sign);
        set_flag("of", is_logical ? constant(1, 0) : overflow);
        set_flag("pf", even_parity);
        set_flag("af", auxiliary_carry);
    };

    for (std::size_t index = 0; index < instructions.size(); ++index) {
        const auto& instruction = instructions[index];
        current_source_address = instruction.address;
        if (!address_to_statement.emplace(instruction.address, program.statements.size()).second) {
            error = "Duplicate instruction address in IL-lifter input.";
            return std::nullopt;
        }
        auto mnemonic = lower_trim(instruction.mnemonic);
        const auto operands = split_operands(instruction.operands);
        const auto next_address = index + 1 < instructions.size() ? instructions[index + 1].address :
            (instruction.address <= (std::numeric_limits<std::uint64_t>::max)() - instruction.size
                ? instruction.address + instruction.size : instruction.address);
        current_next_address = next_address;

        if (mnemonic == "nop") {
            append_statement({IlStatementOp::Nop});
        } else if (mnemonic == "push") {
            if (operands.size() != 1) { error = "Expected one operand for push."; return std::nullopt; }
            if (const auto reg = register_info(operands[0]); reg && reg->size_bytes != 8) {
                error = "The x86-64 LLIL subset supports push of 64-bit registers only.";
                return std::nullopt;
            }
            if (const auto memory = parse_memory_operand(operands[0]);
                memory && memory->size_bytes && *memory->size_bytes != 8) {
                error = "The x86-64 LLIL subset supports 64-bit memory pushes only.";
                return std::nullopt;
            }
            std::uint32_t value = UINT32_MAX;
            if (const auto immediate = parse_immediate(operands[0])) {
                if (instruction.size == 2 && instruction.bytes[0] == 0x6A) {
                    const auto raw = instruction.bytes[1];
                    const auto extended = (raw & 0x80) ? (UINT64_MAX ^ std::uint64_t{0xFF}) | raw : raw;
                    value = constant(8, extended);
                } else if (instruction.size == 5 && instruction.bytes[0] == 0x68) {
                    const std::uint32_t raw = static_cast<std::uint32_t>(instruction.bytes[1]) |
                        (static_cast<std::uint32_t>(instruction.bytes[2]) << 8) |
                        (static_cast<std::uint32_t>(instruction.bytes[3]) << 16) |
                        (static_cast<std::uint32_t>(instruction.bytes[4]) << 24);
                    const auto extended = (raw & 0x80000000u)
                        ? (UINT64_MAX ^ std::uint64_t{0xFFFFFFFF}) | raw : raw;
                    value = constant(8, extended);
                } else {
                    error = "Cannot safely determine the encoded width of the push immediate.";
                    return std::nullopt;
                }
                (void)immediate;
            } else {
                const auto operand_value = read_operand(operands[0], 8);
                if (!operand_value) { error = "Unsupported push operand: " + operands[0]; return std::nullopt; }
                value = *operand_value;
            }
            append_statement({IlStatementOp::Push, 8, value});
        } else if (mnemonic == "pop") {
            if (operands.size() != 1) { error = "Expected one register operand for pop."; return std::nullopt; }
            const auto destination = register_info(operands[0]);
            if (!destination || destination->size_bytes != 8) {
                error = "The x86-64 LLIL subset supports pop into 64-bit registers only.";
                return std::nullopt;
            }
            append_statement({IlStatementOp::PopRegister, 8, UINT32_MAX, UINT32_MAX, UINT32_MAX,
                              0, 0, destination->canonical});
        } else if (mnemonic == "leave") {
            append_statement({IlStatementOp::SetRegister, 8, register_expression("rbp"), UINT32_MAX,
                              UINT32_MAX, 0, 0, "rsp"});
            append_statement({IlStatementOp::PopRegister, 8, UINT32_MAX, UINT32_MAX, UINT32_MAX,
                              0, 0, "rbp"});
        } else if (mnemonic == "ret" || mnemonic == "retq") {
            append_statement({IlStatementOp::Return});
        } else if (mnemonic == "jmp") {
            if (operands.size() != 1) { error = "IL lifter supports only direct x86-64 jumps."; return std::nullopt; }
            const auto target = parse_immediate(operands[0]);
            if (!target) { error = "Unsupported indirect jump operand: " + operands[0]; return std::nullopt; }
            const auto target_expression = constant(8, 0);
            const auto statement_index = append_statement({IlStatementOp::Jump, 8, target_expression});
            pending_branches.push_back({statement_index, *target, 0, false});
        } else if (mnemonic == "je" || mnemonic == "jz" || mnemonic == "jne" || mnemonic == "jnz" ||
                   mnemonic == "ja" || mnemonic == "jnbe" || mnemonic == "jae" || mnemonic == "jnb" ||
                   mnemonic == "jnc" || mnemonic == "jb" || mnemonic == "jc" || mnemonic == "jnae" ||
                   mnemonic == "jbe" || mnemonic == "jna" || mnemonic == "jo" || mnemonic == "jno" ||
                   mnemonic == "js" || mnemonic == "jns" || mnemonic == "jp" || mnemonic == "jpe" ||
                   mnemonic == "jnp" || mnemonic == "jpo" || mnemonic == "jg" || mnemonic == "jnle" ||
                   mnemonic == "jge" || mnemonic == "jnl" || mnemonic == "jl" || mnemonic == "jnge" ||
                   mnemonic == "jle" || mnemonic == "jng") {
            if (operands.size() != 1) { error = "IL lifter supports only direct conditional jumps."; return std::nullopt; }
            const auto target = parse_immediate(operands[0]);
            if (!target) { error = "Unsupported conditional jump operand: " + operands[0]; return std::nullopt; }
            const auto flag = [&](const char* name) { return register_expression(std::string("$il_") + name, 1); };
            const auto not_flag = [&](const char* name) { return binary(IlExpressionOp::Equal, 1, flag(name), constant(1, 0)); };
            const auto both = [&](std::uint32_t left, std::uint32_t right) {
                return binary(IlExpressionOp::And, 1, left, right);
            };
            const auto either = [&](std::uint32_t left, std::uint32_t right) {
                return binary(IlExpressionOp::Or, 1, left, right);
            };
            const auto sign_differs_from_overflow = binary(IlExpressionOp::Xor, 1, flag("sf"), flag("of"));
            std::uint32_t condition = UINT32_MAX;
            if (mnemonic == "je" || mnemonic == "jz") condition = flag("zf");
            else if (mnemonic == "jne" || mnemonic == "jnz") condition = not_flag("zf");
            else if (mnemonic == "ja" || mnemonic == "jnbe") condition = both(not_flag("cf"), not_flag("zf"));
            else if (mnemonic == "jae" || mnemonic == "jnb" || mnemonic == "jnc") condition = not_flag("cf");
            else if (mnemonic == "jb" || mnemonic == "jc" || mnemonic == "jnae") condition = flag("cf");
            else if (mnemonic == "jbe" || mnemonic == "jna") condition = either(flag("cf"), flag("zf"));
            else if (mnemonic == "jo") condition = flag("of");
            else if (mnemonic == "jno") condition = not_flag("of");
            else if (mnemonic == "js") condition = flag("sf");
            else if (mnemonic == "jns") condition = not_flag("sf");
            else if (mnemonic == "jp" || mnemonic == "jpe") condition = flag("pf");
            else if (mnemonic == "jnp" || mnemonic == "jpo") condition = not_flag("pf");
            else if (mnemonic == "jl" || mnemonic == "jnge") condition = sign_differs_from_overflow;
            else if (mnemonic == "jge" || mnemonic == "jnl") condition = binary(IlExpressionOp::Equal, 1, flag("sf"), flag("of"));
            else if (mnemonic == "jle" || mnemonic == "jng") condition = either(flag("zf"), sign_differs_from_overflow);
            else if (mnemonic == "jg" || mnemonic == "jnle")
                condition = both(not_flag("zf"), binary(IlExpressionOp::Equal, 1, flag("sf"), flag("of")));
            const auto statement_index = append_statement({IlStatementOp::Branch, 1, UINT32_MAX, UINT32_MAX,
                                                           condition, 0, 0});
            pending_branches.push_back({statement_index, *target, next_address, true});
        } else if (mnemonic == "lea") {
            if (operands.size() != 2) { error = "Expected a register and an effective-address operand for lea."; return std::nullopt; }
            const auto destination = register_info(operands[0]);
            const auto address_operand = parse_memory_operand(operands[1]);
            if (!destination || !address_operand) { error = "Unsupported lea operand."; return std::nullopt; }
            const auto address = memory_address(*address_operand);
            if (!address) { error = "Unsupported effective address in lea."; return std::nullopt; }
            write_register(*destination, *address);
        } else if (mnemonic == "mov" || mnemonic == "movabs") {
            if (operands.size() != 2) { error = "Expected two operands for " + mnemonic + "."; return std::nullopt; }
            if (const auto destination = register_info(operands[0])) {
                if (const auto source_memory = parse_memory_operand(operands[1]);
                    source_memory && source_memory->size_bytes && *source_memory->size_bytes != destination->size_bytes) {
                    error = "Mismatched register and memory widths in mov.";
                    return std::nullopt;
                }
                const auto value = read_operand(operands[1], destination->size_bytes);
                if (!value) { error = "Unsupported source operand: " + operands[1]; return std::nullopt; }
                write_register(*destination, *value);
            } else if (const auto destination_memory = parse_memory_operand(operands[0])) {
                if (parse_memory_operand(operands[1])) { error = "Memory-to-memory mov is not supported."; return std::nullopt; }
                const auto source_register = register_info(operands[1]);
                const auto size = static_cast<std::uint8_t>(destination_memory->size_bytes ? *destination_memory->size_bytes :
                    source_register ? source_register->size_bytes : 0);
                if (!size) { error = "An immediate-to-memory mov needs a byte/word/dword/qword ptr size."; return std::nullopt; }
                if (source_register && source_register->size_bytes != size) {
                    error = "Mismatched register and memory widths in mov.";
                    return std::nullopt;
                }
                const auto address = memory_address(*destination_memory);
                const auto value = read_operand(operands[1], size);
                if (!address || !value) { error = "Unsupported mov memory operand."; return std::nullopt; }
                append_statement({IlStatementOp::Store, size, *value, *address});
            } else {
                error = "Unsupported destination operand: " + operands[0];
                return std::nullopt;
            }
        } else if (mnemonic == "add" || mnemonic == "sub" || mnemonic == "and" || mnemonic == "or" ||
                   mnemonic == "xor" || mnemonic == "cmp" || mnemonic == "test") {
            if (operands.size() != 2) { error = "Expected two register/immediate operands for " + mnemonic + "."; return std::nullopt; }
            const auto destination = register_info(operands[0]);
            if (!destination) { error = "Unsupported destination operand: " + operands[0]; return std::nullopt; }
            const auto left = read_register(*destination, destination->size_bytes);
            const auto right = read_operand(operands[1], destination->size_bytes);
            if (!right) { error = "Unsupported source operand: " + operands[1]; return std::nullopt; }

            const bool is_subtraction = mnemonic == "sub" || mnemonic == "cmp";
            const bool is_logical = mnemonic == "and" || mnemonic == "or" || mnemonic == "xor" || mnemonic == "test";
            const auto operation = mnemonic == "add" ? IlExpressionOp::Add :
                is_subtraction ? IlExpressionOp::Subtract :
                mnemonic == "or" ? IlExpressionOp::Or :
                mnemonic == "xor" ? IlExpressionOp::Xor : IlExpressionOp::And;
            const auto result = binary(operation, destination->size_bytes, left, *right);
            update_arithmetic_flags(left, *right, result, destination->size_bytes, is_subtraction, is_logical);
            if (mnemonic != "cmp" && mnemonic != "test") write_register(*destination, result);
        } else {
            error = "Unsupported instruction in LLIL-style x86-64 lift: " + mnemonic;
            return std::nullopt;
        }
    }

    const auto exit_statement = program.statements.size();
    current_source_address = 0;
    append_statement({IlStatementOp::Return});
    for (const auto& pending : pending_branches) {
        const auto target = address_to_statement.find(pending.target);
        const auto target_index = target == address_to_statement.end() ? exit_statement : target->second;
        if (pending.conditional) {
            auto& statement = program.statements[pending.statement];
            statement.true_target = target_index;
            const auto fallthrough = address_to_statement.find(pending.fallthrough);
            statement.false_target = fallthrough == address_to_statement.end() ? exit_statement : fallthrough->second;
        } else {
            program.expressions[program.statements[pending.statement].value].immediate = target_index;
        }
    }
    error.clear();
    return program;
}

} // namespace gandon
