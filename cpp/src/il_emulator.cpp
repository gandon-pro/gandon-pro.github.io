#include "gandon/il_emulator.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <sstream>
#include <limits>
#include <utility>

namespace gandon {
namespace {

std::uint64_t width_mask(std::uint8_t size_bytes) {
    return size_bytes >= sizeof(std::uint64_t)
        ? (std::numeric_limits<std::uint64_t>::max)()
        : ((std::uint64_t{1} << (size_bytes * 8)) - 1);
}

bool valid_size(std::uint8_t size_bytes) {
    return size_bytes >= 1 && size_bytes <= sizeof(std::uint64_t);
}

bool valid_span(std::uint64_t address, std::size_t size) {
    return size == 0 || size - 1 <= (std::numeric_limits<std::uint64_t>::max)() - address;
}

std::string format_address(std::uint64_t address) {
    std::ostringstream text;
    text << "0x" << std::hex << std::uppercase << address;
    return text.str();
}

} // namespace

LowLevelIlEmulator::LowLevelIlEmulator(LowLevelIlProgram program) : program_(std::move(program)) {
    if (program_.entry_statement > program_.statements.size()) {
        error_ = "IL entry statement is outside the program.";
        return;
    }
    for (std::size_t index = 0; index < program_.expressions.size(); ++index) {
        if (!valid_size(program_.expressions[index].size_bytes)) {
            error_ = "IL expression " + std::to_string(index) + " has an invalid width.";
            return;
        }
    }
    for (std::size_t index = 0; index < program_.statements.size(); ++index) {
        const auto& statement = program_.statements[index];
        if ((statement.operation == IlStatementOp::SetRegister || statement.operation == IlStatementOp::Store ||
             statement.operation == IlStatementOp::Push || statement.operation == IlStatementOp::PopRegister) &&
            !valid_size(statement.size_bytes)) {
            error_ = "IL statement " + std::to_string(index) + " has an invalid width.";
            return;
        }
        if (statement.operation == IlStatementOp::SetRegister && statement.register_name.empty()) {
            error_ = "IL register assignment has an empty register name.";
            return;
        }
        if (statement.operation == IlStatementOp::Push && statement.size_bytes != sizeof(std::uint64_t)) {
            error_ = "The x86-64 LLIL subset currently supports 64-bit stack pushes only.";
            return;
        }
        if (statement.operation == IlStatementOp::PopRegister &&
            (statement.size_bytes != sizeof(std::uint64_t) || statement.register_name.empty())) {
            error_ = "The x86-64 LLIL subset currently supports pop into a 64-bit register only.";
            return;
        }
        if (statement.operation == IlStatementOp::Branch &&
            (statement.true_target > program_.statements.size() || statement.false_target > program_.statements.size())) {
            error_ = "IL branch target is outside the program.";
            return;
        }
    }
    statement_index_ = program_.entry_statement;
}

bool LowLevelIlEmulator::set_register(const std::string& name, std::uint64_t value, std::string& error) {
    if (!ready()) { error = error_; return false; }
    if (name.empty()) { error = "Register name cannot be empty."; return false; }
    registers_[name] = value;
    error.clear();
    return true;
}

bool LowLevelIlEmulator::register_value(const std::string& name, std::uint64_t& value, std::string& error) const {
    if (!ready()) { error = error_; return false; }
    const auto found = registers_.find(name);
    if (found == registers_.end()) { error = "Register has no emulated value: " + name; return false; }
    value = found->second;
    error.clear();
    return true;
}

bool LowLevelIlEmulator::write_memory(std::uint64_t address, const void* data, std::size_t size, std::string& error) {
    if (!ready()) { error = error_; return false; }
    if (size && !data) { error = "Memory source is null."; return false; }
    if (!valid_span(address, size)) { error = "Memory write wraps the address space."; return false; }
    if (size > maximum_mapped_bytes) { error = "IL memory budget exceeded (64 MiB)."; return false; }
    if (!size) { error.clear(); return true; }
    if (size > (std::numeric_limits<std::uint64_t>::max)() - address) {
        error = "Memory range end wraps the address space.";
        return false;
    }

    const auto input_end = address + size;
    std::size_t already_mapped = 0;
    auto overlap = memory_.upper_bound(address);
    if (overlap != memory_.begin()) {
        auto previous = std::prev(overlap);
        if (previous->first + previous->second.size() > address) overlap = previous;
    }
    for (auto it = overlap; it != memory_.end() && it->first < input_end; ++it) {
        const auto region_end = it->first + it->second.size();
        const auto overlap_start = (std::max)(address, it->first);
        const auto overlap_end = (std::min)(input_end, region_end);
        if (overlap_end > overlap_start)
            already_mapped += static_cast<std::size_t>(overlap_end - overlap_start);
    }
    const auto newly_mapped = size - already_mapped;
    if (newly_mapped > maximum_mapped_bytes - mapped_memory_bytes_) {
        error = "IL memory budget exceeded (64 MiB).";
        return false;
    }

    std::uint64_t merged_start = address;
    std::uint64_t merged_end = input_end;
    auto first = memory_.lower_bound(address);
    if (first != memory_.begin()) {
        auto previous = std::prev(first);
        if (previous->first + previous->second.size() >= address) first = previous;
    }
    std::vector<std::uint64_t> merged_regions;
    for (auto it = first; it != memory_.end() && it->first <= merged_end; ++it) {
        const auto region_end = it->first + it->second.size();
        if (region_end < merged_start) continue;
        merged_regions.push_back(it->first);
        merged_start = (std::min)(merged_start, it->first);
        merged_end = (std::max)(merged_end, region_end);
    }

    std::vector<std::uint8_t> merged(static_cast<std::size_t>(merged_end - merged_start));
    for (const auto region_start : merged_regions) {
        const auto& region = memory_.at(region_start);
        std::copy(region.begin(), region.end(), merged.begin() + static_cast<std::size_t>(region_start - merged_start));
    }
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::copy_n(bytes, size, merged.begin() + static_cast<std::size_t>(address - merged_start));
    for (const auto region_start : merged_regions) memory_.erase(region_start);
    memory_.emplace(merged_start, std::move(merged));
    mapped_memory_bytes_ += newly_mapped;
    error.clear();
    return true;
}

bool LowLevelIlEmulator::read_memory(std::uint64_t address, void* data, std::size_t size, std::string& error) const {
    if (!ready()) { error = error_; return false; }
    if (size && !data) { error = "Memory destination is null."; return false; }
    if (!valid_span(address, size)) { error = "Memory read wraps the address space."; return false; }
    auto* bytes = static_cast<std::uint8_t*>(data);
    std::uint64_t current = address;
    std::size_t remaining = size;
    while (remaining) {
        auto found = memory_.upper_bound(current);
        if (found == memory_.begin()) {
            error = "Read from unmapped IL memory at " + format_address(current) + ".";
            return false;
        }
        --found;
        const auto offset = current - found->first;
        if (offset >= found->second.size()) {
            error = "Read from unmapped IL memory at " + format_address(current) + ".";
            return false;
        }
        const auto available = found->second.size() - static_cast<std::size_t>(offset);
        const auto count = (std::min)(remaining, available);
        std::memcpy(bytes, found->second.data() + static_cast<std::size_t>(offset), count);
        bytes += count;
        remaining -= count;
        if (remaining) current += count;
    }
    error.clear();
    return true;
}

bool LowLevelIlEmulator::map_image_sections(const BinaryImage& image, bool& truncated, std::string& error) {
    truncated = false;
    error.clear();
    std::vector<const BinaryImage::Section*> ordered;
    ordered.reserve(image.sections.size());
    for (const auto& section : image.sections) ordered.push_back(&section);
    const auto priority = [](const BinaryImage::Section& section) {
        std::string name = section.name;
        std::transform(name.begin(), name.end(), name.begin(),
                       [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        if (name.find(".text") != std::string::npos || name.find("__text") != std::string::npos ||
            name == "code" || name.find(".code") != std::string::npos) return 2;
        if (name.find("data") != std::string::npos || name.find("rodata") != std::string::npos ||
            name.find("bss") != std::string::npos || name.find("got") != std::string::npos ||
            name.find("const") != std::string::npos || name.find("tls") != std::string::npos) return 0;
        return 1;
    };
    std::stable_sort(ordered.begin(), ordered.end(), [&](const auto* left, const auto* right) {
        return priority(*left) < priority(*right);
    });

    for (const auto* section : ordered) {
        if (!section) continue;
        if (section->rva > (std::numeric_limits<std::uint64_t>::max)() - image.image_base) {
            error = "Image section address wraps the address space.";
            return false;
        }
        const auto base = image.image_base + section->rva;
        const auto file_offset = static_cast<std::size_t>(section->raw_offset);
        const auto raw_available = file_offset < image.bytes.size()
            ? (std::min)(static_cast<std::size_t>(section->raw_size), image.bytes.size() - file_offset) : 0;
        if (raw_available < section->raw_size) truncated = true;
        if (raw_available) {
            if (!write_memory(base, image.bytes.data() + file_offset, raw_available, error)) {
                if (error.find("budget exceeded") == std::string::npos) return false;
                truncated = true;
                error.clear();
                continue;
            }
        }

        if (section->virtual_size > section->raw_size) {
            const auto zero_size = static_cast<std::size_t>(section->virtual_size - section->raw_size);
            if (zero_size > maximum_mapped_bytes - mapped_memory_bytes_) {
                truncated = true;
                continue;
            }
            if (section->raw_size > (std::numeric_limits<std::uint64_t>::max)() - base) {
                error = "Image section zero-fill address wraps the address space.";
                return false;
            }
            const std::vector<std::uint8_t> zeros(zero_size, 0);
            if (!write_memory(base + section->raw_size, zeros.data(), zeros.size(), error)) {
                if (error.find("budget exceeded") == std::string::npos) return false;
                truncated = true;
                error.clear();
            }
        }
    }
    return true;
}

std::optional<std::uint64_t> LowLevelIlEmulator::evaluate(std::uint32_t expression_id, std::size_t depth,
                                                          std::string& error) const {
    constexpr std::size_t kMaximumExpressionDepth = 256;
    if (depth >= kMaximumExpressionDepth) { error = "IL expression nesting limit exceeded."; return std::nullopt; }
    if (expression_id >= program_.expressions.size()) { error = "IL expression reference is out of range."; return std::nullopt; }
    const auto& expression = program_.expressions[expression_id];
    const auto mask = width_mask(expression.size_bytes);
    const auto child = [&](std::uint32_t id) { return evaluate(id, depth + 1, error); };
    const auto binary = [&]() -> std::optional<std::pair<std::uint64_t, std::uint64_t>> {
        const auto left = child(expression.left);
        if (!left) return std::nullopt;
        const auto right = child(expression.right);
        if (!right) return std::nullopt;
        return std::pair{*left, *right};
    };

    switch (expression.operation) {
    case IlExpressionOp::Constant:
        return expression.immediate & mask;
    case IlExpressionOp::Register: {
        if (expression.register_name.empty()) { error = "IL register read has an empty register name."; return std::nullopt; }
        const auto found = registers_.find(expression.register_name);
        if (found == registers_.end()) { error = "Register has no emulated value: " + expression.register_name; return std::nullopt; }
        return found->second & mask;
    }
    case IlExpressionOp::Load: {
        const auto address = child(expression.left);
        if (!address) return std::nullopt;
        std::array<std::uint8_t, sizeof(std::uint64_t)> bytes{};
        if (!read_memory(*address, bytes.data(), expression.size_bytes, error)) return std::nullopt;
        std::uint64_t value = 0;
        for (std::uint8_t index = 0; index < expression.size_bytes; ++index)
            value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8);
        return value & mask;
    }
    case IlExpressionOp::ZeroExtend:
    case IlExpressionOp::Truncate: {
        const auto value = child(expression.left);
        return value ? std::optional<std::uint64_t>(*value & mask) : std::nullopt;
    }
    case IlExpressionOp::SignExtend: {
        const auto value = child(expression.left);
        if (!value) return std::nullopt;
        const auto source_size = program_.expressions[expression.left].size_bytes;
        const auto source_mask = width_mask(source_size);
        const auto sign_bit = std::uint64_t{1} << (source_size * 8 - 1);
        auto extended = *value & source_mask;
        if (extended & sign_bit) extended |= ~source_mask;
        return extended & mask;
    }
    case IlExpressionOp::Select: {
        const auto condition = child(expression.left);
        if (!condition) return std::nullopt;
        return child(*condition ? expression.right : expression.third);
    }
    default:
        break;
    }

    const auto values = binary();
    if (!values) return std::nullopt;
    const auto [left, right] = *values;
    const auto shift = static_cast<unsigned>(right & 0xFF);
    switch (expression.operation) {
    case IlExpressionOp::Add: return (left + right) & mask;
    case IlExpressionOp::Subtract: return (left - right) & mask;
    case IlExpressionOp::Multiply: return (left * right) & mask;
    case IlExpressionOp::UnsignedDivide:
        if (!right) { error = "Unsigned IL division by zero."; return std::nullopt; }
        return (left / right) & mask;
    case IlExpressionOp::And: return (left & right) & mask;
    case IlExpressionOp::Or: return (left | right) & mask;
    case IlExpressionOp::Xor: return (left ^ right) & mask;
    case IlExpressionOp::ShiftLeft: return shift >= expression.size_bytes * 8 ? 0 : (left << shift) & mask;
    case IlExpressionOp::LogicalShiftRight: return shift >= expression.size_bytes * 8 ? 0 : (left & mask) >> shift;
    case IlExpressionOp::ArithmeticShiftRight: {
        const auto width = static_cast<unsigned>(expression.size_bytes) * 8;
        const auto value = left & mask;
        if (shift >= width) return (value & (std::uint64_t{1} << (width - 1))) ? mask : 0;
        if (!shift) return value;
        auto result = value >> shift;
        if (value & (std::uint64_t{1} << (width - 1))) result |= mask ^ ((std::uint64_t{1} << (width - shift)) - 1);
        return result & mask;
    }
    case IlExpressionOp::Equal: return left == right ? 1 : 0;
    case IlExpressionOp::NotEqual: return left != right ? 1 : 0;
    case IlExpressionOp::UnsignedLessThan: return left < right ? 1 : 0;
    case IlExpressionOp::SignedLessThan: {
        if (expression.left >= program_.expressions.size()) {
            error = "Signed comparison has an invalid left operand.";
            return std::nullopt;
        }
        const auto operand_size = program_.expressions[expression.left].size_bytes;
        const auto operand_mask = width_mask(operand_size);
        const auto sign_bit = std::uint64_t{1} << (operand_size * 8 - 1);
        return (((left & operand_mask) ^ sign_bit) < ((right & operand_mask) ^ sign_bit)) ? 1 : 0;
    }
    default:
        error = "Unsupported IL expression operation.";
        return std::nullopt;
    }
}

IlEmulationResult LowLevelIlEmulator::step() {
    if (!ready()) return {IlEmulationStop::Error, 0, statement_index_, return_value_, error_};
    if (returned_) return {IlEmulationStop::Returned, 0, statement_index_, return_value_, {}};
    if (statement_index_ >= program_.statements.size()) {
        returned_ = true;
        return {IlEmulationStop::Returned, 0, statement_index_, return_value_, {}};
    }

    const auto current_index = statement_index_;
    const auto& statement = program_.statements[current_index];
    std::string error;
    const auto value = [&](std::uint32_t id) { return evaluate(id, 0, error); };
    switch (statement.operation) {
    case IlStatementOp::Nop:
        ++statement_index_;
        break;
    case IlStatementOp::SetRegister: {
        const auto result = value(statement.value);
        if (!result) return {IlEmulationStop::Error, 0, current_index, return_value_, std::move(error)};
        registers_[statement.register_name] = *result & width_mask(statement.size_bytes);
        ++statement_index_;
        break;
    }
    case IlStatementOp::Store: {
        const auto address = value(statement.address);
        if (!address) return {IlEmulationStop::Error, 0, current_index, return_value_, std::move(error)};
        const auto result = value(statement.value);
        if (!result) return {IlEmulationStop::Error, 0, current_index, return_value_, std::move(error)};
        std::array<std::uint8_t, sizeof(std::uint64_t)> bytes{};
        for (std::uint8_t index = 0; index < statement.size_bytes; ++index)
            bytes[index] = static_cast<std::uint8_t>(*result >> (index * 8));
        if (!write_memory(*address, bytes.data(), statement.size_bytes, error))
            return {IlEmulationStop::Error, 0, current_index, return_value_, std::move(error)};
        ++statement_index_;
        break;
    }
    case IlStatementOp::Push: {
        const auto stack = registers_.find("rsp");
        if (stack == registers_.end())
            return {IlEmulationStop::Error, 0, current_index, return_value_, "RSP has no emulated value for push."};
        if (stack->second < statement.size_bytes)
            return {IlEmulationStop::Error, 0, current_index, return_value_, "RSP underflow during push."};
        const auto pushed = value(statement.value);
        if (!pushed) return {IlEmulationStop::Error, 0, current_index, return_value_, std::move(error)};
        const auto next_stack = stack->second - statement.size_bytes;
        std::array<std::uint8_t, sizeof(std::uint64_t)> bytes{};
        for (std::uint8_t index = 0; index < statement.size_bytes; ++index)
            bytes[index] = static_cast<std::uint8_t>(*pushed >> (index * 8));
        if (!write_memory(next_stack, bytes.data(), statement.size_bytes, error))
            return {IlEmulationStop::Error, 0, current_index, return_value_, std::move(error)};
        stack->second = next_stack;
        ++statement_index_;
        break;
    }
    case IlStatementOp::PopRegister: {
        const auto stack = registers_.find("rsp");
        if (stack == registers_.end())
            return {IlEmulationStop::Error, 0, current_index, return_value_, "RSP has no emulated value for pop."};
        if (statement.size_bytes > (std::numeric_limits<std::uint64_t>::max)() - stack->second)
            return {IlEmulationStop::Error, 0, current_index, return_value_, "RSP overflow during pop."};
        std::array<std::uint8_t, sizeof(std::uint64_t)> bytes{};
        if (!read_memory(stack->second, bytes.data(), statement.size_bytes, error))
            return {IlEmulationStop::Error, 0, current_index, return_value_, std::move(error)};
        std::uint64_t popped = 0;
        for (std::uint8_t index = 0; index < statement.size_bytes; ++index)
            popped |= static_cast<std::uint64_t>(bytes[index]) << (index * 8);
        const auto next_stack = stack->second + statement.size_bytes;
        if (statement.register_name == "rsp") {
            stack->second = popped;
        } else {
            stack->second = next_stack;
            registers_[statement.register_name] = popped;
        }
        ++statement_index_;
        break;
    }
    case IlStatementOp::Jump: {
        const auto target = value(statement.value);
        if (!target) return {IlEmulationStop::Error, 0, current_index, return_value_, std::move(error)};
        if (*target >= program_.statements.size())
            return {IlEmulationStop::Error, 0, current_index, return_value_, "IL jump target is outside the program."};
        statement_index_ = static_cast<std::size_t>(*target);
        break;
    }
    case IlStatementOp::Branch: {
        const auto condition = value(statement.condition);
        if (!condition) return {IlEmulationStop::Error, 0, current_index, return_value_, std::move(error)};
        statement_index_ = *condition ? statement.true_target : statement.false_target;
        break;
    }
    case IlStatementOp::Return:
        if (statement.value != UINT32_MAX) {
            return_value_ = value(statement.value);
            if (!return_value_) return {IlEmulationStop::Error, 0, current_index, return_value_, std::move(error)};
        }
        returned_ = true;
        return {IlEmulationStop::Returned, 1, current_index, return_value_, {}};
    }
    return {IlEmulationStop::Paused, 1, current_index, return_value_, {}};
}

IlEmulationResult LowLevelIlEmulator::run(std::size_t statement_limit) {
    std::size_t executed = 0;
    while (executed < statement_limit) {
        auto result = step();
        executed += result.statements_executed;
        if (result.stop != IlEmulationStop::Paused) {
            result.statements_executed = executed;
            return result;
        }
    }
    return {IlEmulationStop::InstructionLimit, executed, statement_index_, return_value_, {}};
}

} // namespace gandon
