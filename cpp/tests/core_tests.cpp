#include "gandon/core.hpp"
#include "gandon/emulator.hpp"
#include "gandon/il_emulator.hpp"

#include <cassert>
#include <cstdio>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {
void test_low_level_il_emulator_arithmetic_memory_and_return() {
    gandon::LowLevelIlProgram program;
    program.expressions = {
        {gandon::IlExpressionOp::Constant, 1, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0xFE, {}},
        {gandon::IlExpressionOp::Constant, 1, UINT32_MAX, UINT32_MAX, UINT32_MAX, 1, {}},
        {gandon::IlExpressionOp::Add, 1, 0, 1},
        {gandon::IlExpressionOp::SignExtend, 8, 2},
        {gandon::IlExpressionOp::Constant, 8, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0x1000, {}},
        {gandon::IlExpressionOp::Constant, 1, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0x42, {}},
        {gandon::IlExpressionOp::Load, 1, 4}
    };
    program.statements = {
        {gandon::IlStatementOp::SetRegister, 8, 3, UINT32_MAX, UINT32_MAX, 0, 0, "rax"},
        {gandon::IlStatementOp::Store, 1, 5, 4},
        {gandon::IlStatementOp::Return, 8, 6}
    };

    gandon::LowLevelIlEmulator emulator(std::move(program));
    assert(emulator.ready());
    const auto result = emulator.run(8);
    assert(result.stop == gandon::IlEmulationStop::Returned);
    assert(result.statements_executed == 3);
    assert(result.return_value && *result.return_value == 0x42);
    std::uint64_t rax = 0;
    std::string error;
    assert(emulator.register_value("rax", rax, error) && rax == UINT64_MAX);
    std::uint8_t byte = 0;
    assert(emulator.read_memory(0x1000, &byte, sizeof(byte), error) && byte == 0x42);
}

void test_low_level_il_emulator_branches_and_instruction_budget() {
    gandon::LowLevelIlProgram program;
    program.expressions = {
        {gandon::IlExpressionOp::Register, 1, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0, "counter"},
        {gandon::IlExpressionOp::Constant, 1, UINT32_MAX, UINT32_MAX, UINT32_MAX, 3, {}},
        {gandon::IlExpressionOp::UnsignedLessThan, 1, 0, 1},
        {gandon::IlExpressionOp::Constant, 1, UINT32_MAX, UINT32_MAX, UINT32_MAX, 1, {}},
        {gandon::IlExpressionOp::Add, 1, 0, 3},
        {gandon::IlExpressionOp::Constant, 8, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0, {}}
    };
    program.statements = {
        {gandon::IlStatementOp::Branch, 1, UINT32_MAX, UINT32_MAX, 2, 1, 3},
        {gandon::IlStatementOp::SetRegister, 1, 4, UINT32_MAX, UINT32_MAX, 0, 0, "counter"},
        {gandon::IlStatementOp::Jump, 8, 5},
        {gandon::IlStatementOp::Return, 1, 0}
    };

    gandon::LowLevelIlEmulator emulator(std::move(program));
    std::string error;
    assert(emulator.ready() && emulator.set_register("counter", 0, error));
    auto result = emulator.run(2);
    assert(result.stop == gandon::IlEmulationStop::InstructionLimit && result.statements_executed == 2);
    result = emulator.run(16);
    assert(result.stop == gandon::IlEmulationStop::Returned);
    assert(result.return_value && *result.return_value == 3);
}

void test_low_level_il_emulator_signed_compare_uses_operand_width() {
    gandon::LowLevelIlProgram program;
    program.expressions = {
        {gandon::IlExpressionOp::Constant, 8, UINT32_MAX, UINT32_MAX, UINT32_MAX, std::uint64_t{1} << 63, {}},
        {gandon::IlExpressionOp::Constant, 8, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0, {}},
        {gandon::IlExpressionOp::SignedLessThan, 1, 0, 1}
    };
    program.statements = {{gandon::IlStatementOp::Return, 1, 2}};
    gandon::LowLevelIlEmulator emulator(std::move(program));
    const auto result = emulator.step();
    assert(result.stop == gandon::IlEmulationStop::Returned);
    assert(result.return_value && *result.return_value == 1);
}

void test_low_level_il_emulator_rejects_unmapped_loads_and_divide_by_zero() {
    gandon::LowLevelIlProgram load_program;
    load_program.expressions = {
        {gandon::IlExpressionOp::Constant, 8, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0x2000, {}},
        {gandon::IlExpressionOp::Load, 4, 0}
    };
    load_program.statements = {{gandon::IlStatementOp::Return, 4, 1}};
    gandon::LowLevelIlEmulator load_emulator(std::move(load_program));
    auto result = load_emulator.step();
    assert(result.stop == gandon::IlEmulationStop::Error);
    assert(result.error.find("unmapped") != std::string::npos);

    std::string error;
    gandon::LowLevelIlProgram initialized_load_program;
    initialized_load_program.expressions = {
        {gandon::IlExpressionOp::Constant, 8, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0x2000, {}},
        {gandon::IlExpressionOp::Load, 4, 0}
    };
    initialized_load_program.statements = {{gandon::IlStatementOp::Return, 4, 1}};
    gandon::LowLevelIlEmulator initialized_load_emulator(std::move(initialized_load_program));
    const std::array<std::uint8_t, 4> input_memory{0x78, 0x56, 0x34, 0x12};
    assert(initialized_load_emulator.write_memory(0x2000, input_memory.data(), input_memory.size(), error));
    result = initialized_load_emulator.step();
    assert(result.stop == gandon::IlEmulationStop::Returned);
    assert(result.return_value && *result.return_value == 0x12345678);

    gandon::LowLevelIlProgram divide_program;
    divide_program.expressions = {
        {gandon::IlExpressionOp::Constant, 8, UINT32_MAX, UINT32_MAX, UINT32_MAX, 7, {}},
        {gandon::IlExpressionOp::Constant, 8, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0, {}},
        {gandon::IlExpressionOp::UnsignedDivide, 8, 0, 1}
    };
    divide_program.statements = {{gandon::IlStatementOp::Return, 8, 2}};
    gandon::LowLevelIlEmulator divide_emulator(std::move(divide_program));
    result = divide_emulator.step();
    assert(result.stop == gandon::IlEmulationStop::Error);
    assert(result.error.find("division by zero") != std::string::npos);

    gandon::LowLevelIlProgram empty_program;
    gandon::LowLevelIlEmulator bounded_memory_emulator(std::move(empty_program));
    const std::array<std::uint8_t, 4> original_region{1, 2, 3, 4};
    const std::array<std::uint8_t, 2> overlay{0xAA, 0xBB};
    const std::uint8_t adjacent = 0xCC;
    assert(bounded_memory_emulator.write_memory(0x3000, original_region.data(), original_region.size(), error));
    assert(bounded_memory_emulator.write_memory(0x3001, overlay.data(), overlay.size(), error));
    assert(bounded_memory_emulator.write_memory(0x3004, &adjacent, 1, error));
    assert(bounded_memory_emulator.mapped_memory_bytes() == 5);
    const std::array<std::uint8_t, 5> expected_region{1, 0xAA, 0xBB, 4, 0xCC};
    std::array<std::uint8_t, 5> actual_region{};
    assert(bounded_memory_emulator.read_memory(0x3000, actual_region.data(), actual_region.size(), error));
    assert(actual_region == expected_region);

    gandon::BinaryImage image;
    image.image_base = 0x400000;
    image.bytes = {0x90, 0xC3, 0x11, 0x22, 0x33};
    image.sections.push_back({".text", 0x1000, 4, 0, 2, 0});
    image.sections.push_back({".data", 0x2000, 4, 2, 3, 0});
    gandon::LowLevelIlEmulator image_emulator(gandon::LowLevelIlProgram{});
    bool truncated = true;
    assert(image_emulator.map_image_sections(image, truncated, error));
    assert(!truncated && image_emulator.mapped_memory_bytes() == 8);
    const std::array<std::uint8_t, 4> expected_text{0x90, 0xC3, 0, 0};
    const std::array<std::uint8_t, 4> expected_data{0x11, 0x22, 0x33, 0};
    std::array<std::uint8_t, 4> actual_section{};
    assert(image_emulator.read_memory(0x401000, actual_section.data(), actual_section.size(), error));
    assert(actual_section == expected_text);
    assert(image_emulator.read_memory(0x402000, actual_section.data(), actual_section.size(), error));
    assert(actual_section == expected_data);

    const std::uint8_t sentinel = 0;
    assert(!bounded_memory_emulator.write_memory(0x90000000, &sentinel,
           gandon::LowLevelIlEmulator::maximum_mapped_bytes + 1, error));
    assert(error.find("memory budget") != std::string::npos);
}

void test_x64_il_lifter_arithmetic_and_extended_register_aliases() {
    const std::vector<gandon::Instruction> instructions = {
        {0x1000, 7, "mov", "r10, 0x1122334455667788", {}},
        {0x1007, 4, "mov", "r10b, 0xaa", {}},
        {0x100B, 5, "mov", "rax, 0x2a", {}},
        {0x1010, 4, "add", "rax, 0x1", {}},
        {0x1014, 1, "ret", "", {}}
    };
    std::string error;
    const auto program = gandon::lift_x64_to_low_level_il(instructions, error);
    assert(program && error.empty());
    gandon::LowLevelIlEmulator emulator(*program);
    assert(emulator.ready());
    const auto result = emulator.run();
    assert(result.stop == gandon::IlEmulationStop::Returned);
    std::uint64_t rax = 0;
    std::uint64_t r10 = 0;
    assert(emulator.register_value("rax", rax, error) && rax == 43);
    assert(emulator.register_value("r10", r10, error) && r10 == 0x11223344556677AA);
}

void test_x64_il_lifter_resolves_conditional_branches() {
    const std::vector<gandon::Instruction> instructions = {
        {0x2000, 5, "mov", "rax, 0", {}},
        {0x2005, 4, "cmp", "rax, 0", {}},
        {0x2009, 2, "je", "0x2012", {}},
        {0x200B, 7, "mov", "rax, 0x55", {}},
        {0x2012, 1, "ret", "", {}}
    };
    std::string error;
    const auto program = gandon::lift_x64_to_low_level_il(instructions, error);
    assert(program && error.empty());
    gandon::LowLevelIlEmulator emulator(*program);
    assert(emulator.ready());
    const auto result = emulator.run();
    assert(result.stop == gandon::IlEmulationStop::Returned);
    std::uint64_t rax = 1;
    assert(emulator.register_value("rax", rax, error) && rax == 0);
}

void test_x64_il_lifter_arithmetic_flags_and_conditional_branches() {
    const auto run_and_read_rax = [](const std::vector<gandon::Instruction>& instructions) {
        std::string error;
        const auto program = gandon::lift_x64_to_low_level_il(instructions, error);
        assert(program && error.empty());
        gandon::LowLevelIlEmulator emulator(*program);
        assert(emulator.ready());
        for (const auto& expression : program->expressions)
            if (expression.operation == gandon::IlExpressionOp::Register)
                assert(emulator.set_register(expression.register_name, 0, error));
        const auto result = emulator.run();
        assert(result.stop == gandon::IlEmulationStop::Returned);
        std::uint64_t rax = 0;
        assert(emulator.register_value("rax", rax, error));
        return rax;
    };

    // -1 is signed-less-than 1 but unsigned-greater-than 1. JL must use SF XOR OF.
    const std::vector<gandon::Instruction> signed_compare = {
        {0x5000, 10, "mov", "rax, 0xffffffffffffffff", {}},
        {0x500A, 4, "cmp", "rax, 1", {}},
        {0x500E, 2, "jl", "0x501a", {}},
        {0x5010, 5, "mov", "rax, 0", {}},
        {0x5015, 5, "jmp", "0x501f", {}},
        {0x501A, 5, "mov", "rax, 1", {}},
        {0x501F, 1, "ret", "", {}}
    };
    assert(run_and_read_rax(signed_compare) == 1);

    // 0x7f + 1 sets OF; JO must take the branch even though the result is negative.
    const std::vector<gandon::Instruction> signed_overflow = {
        {0x6000, 2, "mov", "al, 0x7f", {}},
        {0x6002, 2, "add", "al, 1", {}},
        {0x6004, 2, "jo", "0x6010", {}},
        {0x6006, 5, "mov", "rax, 0", {}},
        {0x600B, 5, "jmp", "0x6015", {}},
        {0x6010, 5, "mov", "rax, 1", {}},
        {0x6015, 1, "ret", "", {}}
    };
    assert(run_and_read_rax(signed_overflow) == 1);

    // TEST AL,1 produces odd parity, so JNP must branch.
    const std::vector<gandon::Instruction> parity_branch = {
        {0x7000, 2, "mov", "al, 1", {}},
        {0x7002, 2, "test", "al, 1", {}},
        {0x7004, 2, "jnp", "0x7010", {}},
        {0x7006, 5, "mov", "rax, 0", {}},
        {0x700B, 5, "jmp", "0x7015", {}},
        {0x7010, 5, "mov", "rax, 1", {}},
        {0x7015, 1, "ret", "", {}}
    };
    assert(run_and_read_rax(parity_branch) == 1);
}

void test_x64_il_lifter_memory_operands_and_rip_relative_lea() {
    const std::vector<gandon::Instruction> instructions = {
        {0x4000, 5, "mov", "rax, 0x5000", {}},
        {0x4005, 10, "mov", "qword ptr [rax + 0x8], 0x1122334455667788", {}},
        {0x400F, 8, "mov", "rbx, qword ptr [rax + 0x8]", {}},
        {0x4017, 7, "lea", "r10, [rip + 0x20]", {}},
        {0x401E, 1, "ret", "", {}}
    };
    std::string error;
    const auto program = gandon::lift_x64_to_low_level_il(instructions, error);
    assert(program && error.empty());
    gandon::LowLevelIlEmulator emulator(*program);
    assert(emulator.ready());
    const auto result = emulator.run();
    assert(result.stop == gandon::IlEmulationStop::Returned);
    std::uint64_t rbx = 0;
    std::uint64_t r10 = 0;
    assert(emulator.register_value("rbx", rbx, error) && rbx == 0x1122334455667788);
    assert(emulator.register_value("r10", r10, error) && r10 == 0x403E);
}

void test_x64_il_lifter_stack_push_pop_and_leave() {
    const std::vector<gandon::Instruction> instructions = {
        {0x8000, 1, "push", "rbp", {}},
        {0x8001, 3, "mov", "rbp, rsp", {}},
        {0x8004, 1, "leave", "", {}},
        {0x8005, 10, "mov", "rax, 0x1122334455667788", {}},
        {0x800F, 1, "push", "rax", {}},
        {0x8010, 1, "pop", "rbx", {}},
        {0x8011, 1, "ret", "", {}}
    };
    std::string error;
    const auto program = gandon::lift_x64_to_low_level_il(instructions, error);
    assert(program && error.empty());
    gandon::LowLevelIlEmulator emulator(*program);
    assert(emulator.ready());
    assert(emulator.set_register("rsp", 0x8000, error));
    assert(emulator.set_register("rbp", 0x123456789ABCDEF0, error));
    const auto stack_result = emulator.run();
    assert(stack_result.stop == gandon::IlEmulationStop::Returned);
    std::uint64_t rsp_after = 0, rbp = 0, rbx = 0;
    assert(emulator.register_value("rsp", rsp_after, error) && rsp_after == 0x8000);
    assert(emulator.register_value("rbp", rbp, error) && rbp == 0x123456789ABCDEF0);
    assert(emulator.register_value("rbx", rbx, error) && rbx == 0x1122334455667788);
    assert(emulator.mapped_memory_bytes() == 8);

    const std::vector<gandon::Instruction> sign_extended_push = {
        {0x9000, 2, "push", "-1", {0x6A, 0xFF}},
        {0x9002, 1, "pop", "rax", {}},
        {0x9003, 1, "ret", "", {}}
    };
    const auto sign_extended_program = gandon::lift_x64_to_low_level_il(sign_extended_push, error);
    assert(sign_extended_program && error.empty());
    gandon::LowLevelIlEmulator immediate_emulator(*sign_extended_program);
    assert(immediate_emulator.set_register("rsp", 0xA000, error));
    const auto immediate_result = immediate_emulator.run();
    assert(immediate_result.stop == gandon::IlEmulationStop::Returned);
    std::uint64_t pushed_value = 0;
    assert(immediate_emulator.register_value("rax", pushed_value, error) && pushed_value == UINT64_MAX);

    const std::vector<gandon::Instruction> ambiguous_push = {{0x9100, 5, "push", "0xFFFFFFFF", {}}};
    assert(!gandon::lift_x64_to_low_level_il(ambiguous_push, error));
    assert(error.find("encoded width") != std::string::npos);

    const std::vector<gandon::Instruction> unsupported = {{0x9000, 2, "pop", "eax", {}}};
    assert(!gandon::lift_x64_to_low_level_il(unsupported, error));
    assert(error.find("64-bit registers only") != std::string::npos);

    const std::vector<gandon::Instruction> underflow_code = {
        {0xA000, 1, "push", "rax", {}}, {0xA001, 1, "ret", "", {}}
    };
    const auto underflow_program = gandon::lift_x64_to_low_level_il(underflow_code, error);
    assert(underflow_program);
    gandon::LowLevelIlEmulator underflow_emulator(*underflow_program);
    assert(underflow_emulator.set_register("rsp", 4, error));
    assert(underflow_emulator.set_register("rax", 0x55, error));
    auto failure_result = underflow_emulator.run();
    assert(failure_result.stop == gandon::IlEmulationStop::Error && failure_result.error.find("underflow") != std::string::npos);
    std::uint64_t rsp = 0;
    assert(underflow_emulator.register_value("rsp", rsp, error) && rsp == 4);

    const std::vector<gandon::Instruction> unmapped_pop_code = {
        {0xB000, 1, "pop", "rbx", {}}, {0xB001, 1, "ret", "", {}}
    };
    const auto unmapped_pop_program = gandon::lift_x64_to_low_level_il(unmapped_pop_code, error);
    assert(unmapped_pop_program);
    gandon::LowLevelIlEmulator unmapped_pop_emulator(*unmapped_pop_program);
    assert(unmapped_pop_emulator.set_register("rsp", 0x9000, error));
    failure_result = unmapped_pop_emulator.run();
    assert(failure_result.stop == gandon::IlEmulationStop::Error && failure_result.error.find("unmapped") != std::string::npos);
    assert(unmapped_pop_emulator.register_value("rsp", rsp, error) && rsp == 0x9000);
}

void test_x64_il_lifter_fails_closed_for_unsupported_instructions() {
    const std::vector<gandon::Instruction> instructions = {{0x3000, 2, "call", "rax", {}}};
    std::string error;
    assert(!gandon::lift_x64_to_low_level_il(instructions, error));
    assert(error.find("Unsupported instruction") != std::string::npos);
}

void put16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

void put32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index)
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8));
}

void put64(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index)
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8));
}

void write_section(std::vector<std::uint8_t>& bytes, std::size_t offset,
                   std::uint32_t name, std::uint32_t type, std::uint64_t flags,
                   std::uint64_t address, std::uint64_t file_offset,
                   std::uint64_t size, std::uint32_t link = 0,
                   std::uint64_t entry_size = 0) {
    put32(bytes, offset, name);
    put32(bytes, offset + 4, type);
    put64(bytes, offset + 8, flags);
    put64(bytes, offset + 16, address);
    put64(bytes, offset + 24, file_offset);
    put64(bytes, offset + 32, size);
    put32(bytes, offset + 40, link);
    put64(bytes, offset + 56, entry_size);
}

void test_elf_symbol_loading() {
    std::vector<std::uint8_t> bytes(0x500, 0);
    bytes[0] = 0x7f; bytes[1] = 'E'; bytes[2] = 'L'; bytes[3] = 'F';
    bytes[4] = 2; // ELF64
    bytes[5] = 1; // little endian
    bytes[6] = 1;
    put16(bytes, 16, 2); put16(bytes, 18, 62); put32(bytes, 20, 1);
    put64(bytes, 24, 0x1000);
    put64(bytes, 40, 0x300);
    put16(bytes, 52, 64); put16(bytes, 58, 64); put16(bytes, 60, 5); put16(bytes, 62, 4);
    std::fill(bytes.begin() + 0x100, bytes.begin() + 0x110, 0x90);
    put32(bytes, 0x180, 1); // st_name
    bytes[0x184] = 0x12; // STB_GLOBAL | STT_FUNC
    put16(bytes, 0x186, 1); // .text
    put64(bytes, 0x180 + 8, 0x1000);
    put64(bytes, 0x180 + 16, 8);
    put32(bytes, 0x1b0, 10); // name is not NUL-terminated inside the string table
    bytes[0x1b4] = 0x12;
    put16(bytes, 0x1b6, 1);
    put64(bytes, 0x1b8, 0x1008);
    put64(bytes, 0x1c0, 8);
    const std::string symbol_names("\0named_fn\0", 10);
    std::copy(symbol_names.begin(), symbol_names.end(), bytes.begin() + 0x240);
    std::fill(bytes.begin() + 0x24a, bytes.begin() + 0x280, static_cast<std::uint8_t>('X'));
    const std::string section_names("\0.text\0.symtab\0.strtab\0.shstrtab\0", 33);
    std::copy(section_names.begin(), section_names.end(), bytes.begin() + 0x200);
    write_section(bytes, 0x340, 1, 1, 6, 0x1000, 0x100, 0x10);
    write_section(bytes, 0x380, 7, 2, 0, 0, 0x180, 72, 3, 24);
    write_section(bytes, 0x3c0, 15, 3, 0, 0, 0x240, 0x40);
    write_section(bytes, 0x400, 23, 3, 0, 0, 0x200, section_names.size());

    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto path = std::filesystem::temp_directory_path() /
        ("gandon-elf-symbol-test-" + std::to_string(stamp) + ".elf");
    {
        std::ofstream output(path, std::ios::binary);
        assert(output);
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        assert(output);
    }

    gandon::BinaryImage image;
    std::string error;
    assert(image.load(path, error));
    assert(image.bytes == bytes);
    assert(image.symbols.size() == 1);
    assert(image.symbols.front().name == "named_fn");
    assert(image.symbols.front().kind == 2);
    assert(image.symbols.front().size == 8);
    assert(image.architecture == gandon::MachineArchitecture::X64);
    gandon::AnalysisDatabase analyzed(std::move(image));
    analyzed.discover_basic_xrefs();
    assert(!analyzed.functions().empty());
    assert(analyzed.functions().front().name == "named_fn");
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

void test_elf_dynamic_jump_slot_import_loading() {
    std::vector<std::uint8_t> bytes(0x500, 0);
    bytes[0] = 0x7f; bytes[1] = 'E'; bytes[2] = 'L'; bytes[3] = 'F';
    bytes[4] = 2; bytes[5] = 1; bytes[6] = 1;
    put16(bytes, 16, 3); put16(bytes, 18, 62); put32(bytes, 20, 1); // ELF64 ET_DYN x86-64
    put64(bytes, 24, 0x1000);
    put64(bytes, 40, 0x300);
    put16(bytes, 52, 64); put16(bytes, 58, 64); put16(bytes, 60, 7); put16(bytes, 62, 6);
    const std::string section_names("\0.text\0.dynsym\0.dynstr\0.rela.plt\0.got\0.shstrtab\0", 48);
    const auto name_offset = [&](const std::string& name) {
        const auto offset = section_names.find(name);
        assert(offset != std::string::npos);
        return static_cast<std::uint32_t>(offset);
    };
    std::copy(section_names.begin(), section_names.end(), bytes.begin() + 0x200);
    std::memcpy(bytes.data() + 0x100, "\xC3", 1);
    put32(bytes, 0x158, 1); // dynsym[1].st_name -> puts
    bytes[0x15c] = 0x12; // STB_GLOBAL | STT_FUNC
    put16(bytes, 0x15e, 0); // SHN_UNDEF
    const std::string dynamic_names("\0puts\0", 6);
    std::copy(dynamic_names.begin(), dynamic_names.end(), bytes.begin() + 0x180);
    put64(bytes, 0x1a0, 0x2000); // r_offset
    put64(bytes, 0x1a8, (std::uint64_t{1} << 32) | 7); // ELF64_R_INFO(1, R_X86_64_JUMP_SLOT)
    put64(bytes, 0x1b0, 0);
    write_section(bytes, 0x340, name_offset(".text"), 1, 6, 0x1000, 0x100, 0x10);
    write_section(bytes, 0x380, name_offset(".dynsym"), 11, 0, 0, 0x140, 48, 3, 24);
    write_section(bytes, 0x3c0, name_offset(".dynstr"), 3, 0, 0, 0x180, 6);
    write_section(bytes, 0x400, name_offset(".rela.plt"), 4, 0, 0, 0x1a0, 24, 2, 24);
    write_section(bytes, 0x440, name_offset(".got"), 1, 3, 0x2000, 0x1c0, 8);
    write_section(bytes, 0x480, name_offset(".shstrtab"), 3, 0, 0, 0x200, section_names.size());

    const auto path = std::filesystem::temp_directory_path() /
        ("gandon-elf-import-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".elf");
    {
        std::ofstream output(path, std::ios::binary);
        assert(output);
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        assert(output);
    }
    gandon::BinaryImage image;
    std::string error;
    assert(image.load(path, error));
    assert(image.imports.size() == 1);
    assert(image.imports.front().name == "puts" && image.imports.front().address == 0x2000);
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

void test_failed_binary_reload_clears_stale_metadata() {
    gandon::BinaryImage image;
    image.path = "old-image.elf";
    image.bytes = {0x7f, 'E', 'L', 'F'};
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = false;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.sections.push_back({".text", 0x1000, 0x100, 0, 0x100, 0x20000000});
    image.symbols.push_back({"old_symbol", 0x401000, 1, 2});
    image.imports.push_back({"old_import", 0x401008});

    std::string error;
    const auto missing_path = std::filesystem::temp_directory_path() /
        ("gandon-missing-reload-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    assert(!image.load(missing_path, error));
    assert(!error.empty());
    assert(image.path.empty());
    assert(image.bytes.empty());
    assert(image.bytes.capacity() == 0);
    assert(image.format == gandon::BinaryFormat::Unknown);
    assert(image.architecture == gandon::MachineArchitecture::Unknown);
    assert(image.is_64_bit);
    assert(image.image_base == 0 && image.entry_point == 0);
    assert(image.sections.empty() && image.symbols.empty() && image.imports.empty());
    assert(image.sections.capacity() == 0 && image.symbols.capacity() == 0 && image.imports.capacity() == 0);

    const auto malformed_path = std::filesystem::temp_directory_path() /
        ("gandon-malformed-reload-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    {
        std::ofstream output(malformed_path, std::ios::binary);
        const std::uint8_t malformed[] = {0, 1, 2, 3, 4, 5, 6, 7};
        output.write(reinterpret_cast<const char*>(malformed), sizeof(malformed));
        assert(output);
    }
    assert(!image.load(malformed_path, error));
    assert(image.bytes.empty() && image.bytes.capacity() == 0);
    assert(image.sections.capacity() == 0 && image.symbols.capacity() == 0);
    assert(image.imports.empty() && image.imports.capacity() == 0);
    std::error_code ignored;
    std::filesystem::remove(malformed_path, ignored);
}

void test_large_sparse_elf_load_uses_exact_file_extent() {
    constexpr std::uint64_t file_size = 16ull * 1024 * 1024;
    std::vector<std::uint8_t> header(120, 0);
    header[0] = 0x7f; header[1] = 'E'; header[2] = 'L'; header[3] = 'F';
    header[4] = 2; header[5] = 1; header[6] = 1;
    put16(header, 16, 2); put16(header, 18, 62); put32(header, 20, 1);
    put64(header, 24, 0x400080); put64(header, 32, 64);
    put16(header, 52, 64); put16(header, 54, 56); put16(header, 56, 1);
    put32(header, 64, 1); put32(header, 68, 5);
    put64(header, 72, 0); put64(header, 80, 0x400000);
    put64(header, 96, file_size); put64(header, 104, file_size); put64(header, 112, 0x1000);

    const auto path = std::filesystem::temp_directory_path() /
        ("gandon-large-sparse-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".elf");
    {
        std::ofstream output(path, std::ios::binary);
        assert(output);
        output.write(reinterpret_cast<const char*>(header.data()), static_cast<std::streamsize>(header.size()));
        output.seekp(static_cast<std::streamoff>(file_size - 1));
        output.put('\0');
        assert(output);
    }
    gandon::BinaryImage image;
    std::string error;
    assert(image.load(path, error));
    assert(error.empty());
    assert(image.bytes.size() == file_size);
    assert(image.sections.size() == 1);
    assert(image.sections.front().raw_size == file_size);
    assert(image.entry_point == 0x400080);
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::path malformed_path = path; malformed_path += ".bad";
    {
        std::ofstream output(malformed_path, std::ios::binary);
        const std::uint8_t malformed[] = {0, 1, 2, 3};
        output.write(reinterpret_cast<const char*>(malformed), sizeof(malformed));
        assert(output);
    }
    assert(!image.load(malformed_path, error));
    assert(image.bytes.empty() && image.bytes.capacity() == 0);
    assert(image.sections.capacity() == 0 && image.symbols.capacity() == 0);
    std::filesystem::remove(malformed_path, ignored);
}

void test_wildcard_signature_search_keeps_overlaps_and_caps_results() {
    gandon::BinaryImage image;
    image.image_base = 0x1000;
    image.bytes = {0xAA, 0xAA, 0xAA, 0x00};
    const std::vector<std::optional<std::uint8_t>> overlapping{0xAA, 0xAA};
    bool truncated = false;
    const auto limited = image.find_pattern(overlapping, 1, &truncated);
    assert((limited == std::vector<std::uint64_t>{0x1000}));
    assert(truncated);
    const auto all = image.find_pattern(overlapping, 2, &truncated);
    assert((all == std::vector<std::uint64_t>{0x1000, 0x1001}));
    assert(!truncated);

    const std::vector<std::optional<std::uint8_t>> wildcard_only{std::nullopt, std::nullopt};
    const auto wildcard_matches = image.find_pattern(wildcard_only, 2, &truncated);
    assert((wildcard_matches == std::vector<std::uint64_t>{0x1000, 0x1001}));
    assert(truncated);
}

void test_exact_byte_search_retains_unlimited_legacy_results() {
    gandon::BinaryImage image;
    image.image_base = 0x100000;
    image.bytes.assign(10025, 0x90);
    const auto matches = image.find_bytes({0x90});
    assert(matches.size() == image.bytes.size());
    assert(matches.front() == image.image_base);
    assert(matches.back() == image.image_base + image.bytes.size() - 1);
}

void test_xref_address_index_tracks_incoming_outgoing_and_updates() {
    gandon::BinaryImage image;
    gandon::AnalysisDatabase database(std::move(image));
    database.add_xref({0x10, 0x20, "call"});
    database.add_xref({0x30, 0x10, "data"});
    auto references = database.xrefs_at(0x10);
    assert(references.size() == 2);
    assert(references[0].get().from == 0x10 && references[0].get().to == 0x20);
    assert(references[1].get().from == 0x30 && references[1].get().to == 0x10);
    assert(database.xrefs_at(0x20).size() == 1);
    database.add_xref({0x10, 0x10, "self"});
    references = database.xrefs_at(0x10);
    assert(references.size() == 3);
    database.discover_basic_xrefs();
    assert(database.xrefs_at(0x10).empty());
}

void test_xref_budget_is_bounded_and_discovery_releases_old_storage() {
    gandon::BinaryImage image;
    gandon::AnalysisDatabase database(std::move(image));
    constexpr std::size_t limit = 500'000;
    for (std::size_t index = 0; index <= limit; ++index)
        database.add_xref({index, index + 1, "data"});
    assert(database.xrefs().size() == limit);
    assert(database.xrefs_truncated());
    const auto memory_before_index = database.estimated_analysis_memory_bytes();
    assert(database.xrefs_at(0).size() == 1); // Materialize the address index before rediscovery.
    const auto memory_after_index = database.estimated_analysis_memory_bytes();
    assert(memory_after_index >= memory_before_index +
        database.xrefs().size() * 2 * sizeof(std::pair<std::uint64_t, std::size_t>));
    database.discover_basic_xrefs();
    assert(database.xrefs().empty());
    assert(!database.xrefs_truncated());
    assert(database.estimated_analysis_memory_bytes() == 0);
}

void test_discovery_releases_function_and_xref_cache_memory() {
    gandon::BinaryImage image;
    gandon::AnalysisDatabase database(std::move(image));
    gandon::Function cached_function;
    cached_function.start = 0x1000;
    cached_function.name = "cached-function";
    cached_function.instructions.resize(256);
    for (auto& instruction : cached_function.instructions) {
        instruction.mnemonic = std::string(48, 'm');
        instruction.operands = std::string(96, 'o');
    }
    cached_function.callees.resize(128, 0x2000);
    database.add_function(std::move(cached_function));
    database.add_xref({0x1000, 0x2000, "data"});
    assert(database.xrefs_at(0x1000).size() == 1); // Materialize the lazy XREF index too.
    assert(database.estimated_analysis_memory_bytes() > 32 * 1024);

    database.discover_basic_xrefs();
    assert(database.functions().empty());
    assert(database.xrefs().empty());
    assert(database.xrefs_at(0x1000).empty());
    assert(database.estimated_analysis_memory_bytes() == 0);
}

void test_function_discovery_exceeds_legacy_limit() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x140000000;
    image.entry_point = image.image_base + 0x1000;
    constexpr std::size_t candidate_count = 9000;
    image.bytes.resize(0x1000 + candidate_count * 8, 0x90);
    image.sections.push_back({".text", 0x1000, static_cast<std::uint32_t>(candidate_count * 8),
                              0x1000, static_cast<std::uint32_t>(candidate_count * 8), 0x60000020});
    for (std::size_t index = 0; index < candidate_count; ++index) {
        const auto offset = 0x1000 + index * 8;
        image.bytes[offset] = 0x55; image.bytes[offset + 1] = 0x48;
        image.bytes[offset + 2] = 0x89; image.bytes[offset + 3] = 0xE5;
        image.bytes[offset + 4] = 0xC3;
    }
    gandon::AnalysisDatabase database(std::move(image));
    database.discover_basic_xrefs();
    assert(database.functions().size() == candidate_count);
    assert(!database.functions_truncated());

    // The previous 8192-entry cap also truncated authoritative x64 .pdata
    // tables, so cover the real unwind-metadata path independently of prologue
    // scanning.
    gandon::BinaryImage unwind_image;
    unwind_image.format = gandon::BinaryFormat::PE;
    unwind_image.architecture = gandon::MachineArchitecture::X64;
    unwind_image.is_64_bit = true;
    unwind_image.image_base = 0x140000000;
    unwind_image.entry_point = unwind_image.image_base + 0x1000;
    constexpr std::uint32_t text_rva = 0x1000;
    constexpr std::uint32_t text_raw = 0x1000;
    constexpr std::uint32_t pdata_rva = 0x30000;
    constexpr std::uint32_t pdata_raw = 0x200000;
    constexpr std::uint32_t function_stride = 0x10;
    const auto text_bytes = static_cast<std::uint32_t>(candidate_count * function_stride);
    const auto pdata_bytes = static_cast<std::uint32_t>(candidate_count * 12);
    unwind_image.bytes.resize(static_cast<std::size_t>(pdata_raw) + pdata_bytes, 0);
    unwind_image.bytes[0] = 'M'; unwind_image.bytes[1] = 'Z';
    put32(unwind_image.bytes, 0x3c, 0x80);
    put32(unwind_image.bytes, 0x80, 0x00004550);
    put16(unwind_image.bytes, 0x84, 0x8664);
    put16(unwind_image.bytes, 0x94, 0xF0);
    constexpr std::size_t optional = 0x98;
    put16(unwind_image.bytes, optional, 0x20b);
    put32(unwind_image.bytes, optional + 0x70 + 3 * 8, pdata_rva);
    put32(unwind_image.bytes, optional + 0x70 + 3 * 8 + 4, pdata_bytes);
    unwind_image.sections.push_back({".text", text_rva, text_bytes, text_raw, text_bytes, 0x60000020});
    unwind_image.sections.push_back({".pdata", pdata_rva, pdata_bytes, pdata_raw, pdata_bytes, 0x40000040});
    for (std::size_t index = 0; index < candidate_count; ++index) {
        const auto begin_rva = text_rva + static_cast<std::uint32_t>(index * function_stride);
        const auto entry = static_cast<std::size_t>(pdata_raw) + index * 12;
        put32(unwind_image.bytes, entry, begin_rva);
        put32(unwind_image.bytes, entry + 4, begin_rva + function_stride);
        unwind_image.bytes[text_raw + index * function_stride] = 0xC3;
    }
    gandon::AnalysisDatabase unwind_database(std::move(unwind_image));
    unwind_database.discover_basic_xrefs();
    assert(unwind_database.functions().size() == candidate_count);
    assert(!unwind_database.functions_truncated());
}

void test_pe_xrefs_use_decoded_instruction_boundaries() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x140000000;
    image.entry_point = image.image_base + 0x100;
    image.bytes.resize(0x300);
    image.sections.push_back({".text", 0x100, 0x200, 0x100, 0x200, 0x20000000});

    // The E8 byte at entry+1 is inside MOV's immediate, followed by zeros;
    // byte scanning mistakes it for a CALL to the real CALL opcode at +6.
    image.bytes[0x100] = 0xB8;
    image.bytes[0x101] = 0xE8;
    image.bytes[0x105] = 0x00;
    image.bytes[0x106] = 0xC0; // valid ADD encoding consumes bytes +5..+6
    image.bytes[0x107] = 0xE8;
    image.bytes[0x108] = 0x14; // decoded CALL at +7 targets +0x120
    image.bytes[0x10C] = 0xC3;
    image.bytes[0x120] = 0xE8;
    image.bytes[0x121] = 0x1B; // second-level CALL targets +0x140
    image.bytes[0x125] = 0xC3;
    image.bytes[0x140] = 0xC3;

    gandon::AnalysisDatabase analyzed(std::move(image));
    analyzed.discover_basic_xrefs();
    const auto false_source = 0x140000101ull;
    const auto false_target = 0x140000106ull;
    const auto real_source = 0x140000107ull;
    const auto real_target = 0x140000120ull;
    const auto nested_target = 0x140000140ull;
    assert(std::none_of(analyzed.xrefs().begin(), analyzed.xrefs().end(),
        [false_source](const gandon::Xref& xref) { return xref.from == false_source; }));
    assert(std::any_of(analyzed.xrefs().begin(), analyzed.xrefs().end(),
        [real_source, real_target](const gandon::Xref& xref) {
            return xref.from == real_source && xref.to == real_target && xref.kind == "call";
        }));
    assert(std::any_of(analyzed.functions().begin(), analyzed.functions().end(),
        [real_target](const gandon::Function& function) { return function.start == real_target; }));
    assert(std::any_of(analyzed.functions().begin(), analyzed.functions().end(),
        [nested_target](const gandon::Function& function) { return function.start == nested_target; }));
    assert(std::any_of(analyzed.xrefs().begin(), analyzed.xrefs().end(),
        [real_target, nested_target](const gandon::Xref& xref) {
            return xref.from == real_target && xref.to == nested_target && xref.kind == "call";
        }));
    assert(std::none_of(analyzed.functions().begin(), analyzed.functions().end(),
        [false_target](const gandon::Function& function) { return function.start == false_target; }));
}

void test_pe_unwind_metadata_suppresses_false_prologue_functions() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x140000000;
    image.entry_point = image.image_base + 0x1000;
    image.bytes.resize(0x400, 0);
    image.bytes[0] = 'M'; image.bytes[1] = 'Z';
    put32(image.bytes, 0x3c, 0x80);
    put32(image.bytes, 0x80, 0x00004550);
    constexpr std::size_t optional = 0x98;
    put16(image.bytes, optional, 0x20b);
    put32(image.bytes, optional + 0x70 + 3 * 8, 0x2000); // Exception directory (.pdata)
    put32(image.bytes, optional + 0x70 + 3 * 8 + 4, 12);
    image.sections.push_back({".text", 0x1000, 0x100, 0x200, 0x100, 0x60000020});
    image.sections.push_back({".pdata", 0x2000, 0x100, 0x300, 0x100, 0x40000040});
    put32(image.bytes, 0x300, 0x1000); // runtime function begin RVA
    put32(image.bytes, 0x304, 0x1010); // runtime function end RVA
    image.bytes[0x200] = 0xC3; // the table-listed function
    image.bytes[0x210] = 0x55; image.bytes[0x211] = 0x48;
    image.bytes[0x212] = 0x89; image.bytes[0x213] = 0xE5; // prologue-like bytes inside .text data
    image.bytes[0x214] = 0xC3;

    gandon::AnalysisDatabase analyzed(image);
    analyzed.discover_basic_xrefs();
    assert(std::any_of(analyzed.functions().begin(), analyzed.functions().end(),
        [](const gandon::Function& function) { return function.start == 0x140001000ull; }));
    assert(std::none_of(analyzed.functions().begin(), analyzed.functions().end(),
        [](const gandon::Function& function) { return function.start == 0x140001010ull; }));

    auto malformed_table_image = image;
    put32(malformed_table_image.bytes, 0x300, 0x2000); // invalid: points into non-executable .pdata
    put32(malformed_table_image.bytes, 0x304, 0x2010);
    gandon::AnalysisDatabase malformed_table(std::move(malformed_table_image));
    malformed_table.discover_basic_xrefs();
    assert(std::any_of(malformed_table.functions().begin(), malformed_table.functions().end(),
        [](const gandon::Function& function) { return function.start == 0x140001010ull; }));
}

void test_pe_export_ordinal_is_bounded_by_function_count() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x140000000;
    image.entry_point = image.image_base + 0x1000;
    image.bytes.resize(0x700, 0);
    image.bytes[0] = 'M'; image.bytes[1] = 'Z';
    put32(image.bytes, 0x3c, 0x80);
    put32(image.bytes, 0x80, 0x00004550);
    constexpr std::size_t optional = 0x98;
    put16(image.bytes, optional, 0x20b);
    put32(image.bytes, optional + 0x70, 0x3000); // export directory RVA
    put32(image.bytes, optional + 0x74, 0x100);
    image.sections.push_back({".text", 0x1000, 0x100, 0x200, 0x100, 0x60000020});
    image.sections.push_back({".edata", 0x3000, 0x100, 0x500, 0x100, 0x40000040});
    put32(image.bytes, 0x500 + 20, 2); // function ordinals 0 and 1
    put32(image.bytes, 0x500 + 24, 3); // invalid ordinal, forwarder, and unterminated name
    put32(image.bytes, 0x500 + 28, 0x3050);
    put32(image.bytes, 0x500 + 32, 0x3060);
    put32(image.bytes, 0x500 + 36, 0x3070);
    put32(image.bytes, 0x550, 0x3080); // valid ordinal points to a forwarder string
    put32(image.bytes, 0x554, 0x1010); // valid ordinal points to code, but its name is malformed
    put32(image.bytes, 0x558, 0x1020); // adjacent bytes must not be accepted for ordinal 2
    put32(image.bytes, 0x560, 0x3080);
    put32(image.bytes, 0x564, 0x3090);
    put32(image.bytes, 0x568, 0x30F0);
    put16(image.bytes, 0x570, 2); // out-of-range ordinal
    put16(image.bytes, 0x572, 0); // valid ordinal, but its target is a forwarder string
    put16(image.bytes, 0x574, 1); // valid code ordinal with an unterminated name
    const std::string exported_name = "bogus_export";
    std::copy(exported_name.begin(), exported_name.end(), image.bytes.begin() + 0x580);
    const std::string forwarded_name = "forwarded_export";
    std::copy(forwarded_name.begin(), forwarded_name.end(), image.bytes.begin() + 0x590);
    std::fill(image.bytes.begin() + 0x5F0, image.bytes.end(), static_cast<std::uint8_t>('A'));
    image.bytes[0x200] = 0xC3;
    image.bytes[0x210] = 0xC3;

    gandon::AnalysisDatabase analyzed(std::move(image));
    analyzed.discover_basic_xrefs();
    assert(std::none_of(analyzed.functions().begin(), analyzed.functions().end(),
        [](const gandon::Function& function) { return function.start == 0x140001010ull; }));
    assert(std::none_of(analyzed.functions().begin(), analyzed.functions().end(),
        [](const gandon::Function& function) { return function.start == 0x140003080ull; }));
    assert(std::none_of(analyzed.functions().begin(), analyzed.functions().end(),
        [](const gandon::Function& function) { return function.start == 0x140001020ull; }));
}

void test_pe_function_decode_walks_branches_and_stops_at_ret() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.is_64_bit = true;
    image.image_base = 0x140000000;
    image.entry_point = image.image_base + 0x100;
    image.bytes.resize(0x300);
    image.sections.push_back({".text", 0x100, 0x200, 0x100, 0x200, 0x20000000});
    const std::uint8_t code[] = {
        0x75, 0x06,                         // jne entry+8
        0xB8, 0x01, 0x00, 0x00, 0x00,     // fallthrough: mov eax, 1
        0xC3,                               // ret
        0xB8, 0x02, 0x00, 0x00, 0x00,     // branch: mov eax, 2
        0xC3,                               // ret
        0xE8, 0x00, 0x00, 0x00, 0x00      // unreachable CALL-shaped bytes
    };
    std::copy(std::begin(code), std::end(code), image.bytes.begin() + 0x100);
    const std::uint8_t near_condition[] = {0x0F, 0x84, 0x01, 0x00, 0x00, 0x00, 0xC3}; // je +1; ret
    std::copy(std::begin(near_condition), std::end(near_condition), image.bytes.begin() + 0x120);
    const auto short_branch = gandon::decode_instructions(image, image.entry_point, 1);
    const auto near_branch = gandon::decode_instructions(image, image.image_base + 0x120, 1);
    assert(short_branch.size() == 1 && short_branch[0].mnemonic == "jne");
    assert(near_branch.size() == 1 && near_branch[0].mnemonic == "je");

    gandon::AnalysisDatabase analyzed(std::move(image));
    analyzed.discover_basic_xrefs();
    const auto function = std::find_if(analyzed.functions().begin(), analyzed.functions().end(),
        [](const gandon::Function& item) { return item.start == 0x140000100ull; });
    assert(function != analyzed.functions().end());
    const auto has_instruction = [&](std::uint64_t address) {
        return std::any_of(function->instructions.begin(), function->instructions.end(),
            [address](const gandon::Instruction& item) { return item.address == address; });
    };
    assert(has_instruction(0x140000100ull));
    assert(has_instruction(0x140000102ull));
    assert(has_instruction(0x140000107ull));
    assert(has_instruction(0x140000108ull));
    assert(has_instruction(0x14000010Dull));
    assert(!has_instruction(0x14000010Eull));
    assert(std::none_of(analyzed.xrefs().begin(), analyzed.xrefs().end(),
        [](const gandon::Xref& xref) { return xref.from == 0x14000010Eull; }));
}

void test_pe_call_on_alternate_cfg_branch_discovers_callee() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.is_64_bit = true;
    image.image_base = 0x140000000;
    image.entry_point = image.image_base + 0x100;
    image.bytes.resize(0x300);
    image.sections.push_back({".text", 0x100, 0x200, 0x100, 0x200, 0x20000000});
    image.bytes[0x100] = 0x75; image.bytes[0x101] = 0x01; // jne entry+3
    image.bytes[0x102] = 0xC3;                            // fallthrough returns
    image.bytes[0x103] = 0xE8; image.bytes[0x104] = 0x38; // branch-only call to +0x140
    image.bytes[0x108] = 0xC3;
    image.bytes[0x140] = 0xC3;

    gandon::AnalysisDatabase analyzed(std::move(image));
    analyzed.discover_basic_xrefs();
    assert(std::any_of(analyzed.functions().begin(), analyzed.functions().end(),
        [](const gandon::Function& function) { return function.start == 0x140000140ull; }));
    assert(std::any_of(analyzed.xrefs().begin(), analyzed.xrefs().end(),
        [](const gandon::Xref& xref) {
            return xref.from == 0x140000103ull && xref.to == 0x140000140ull && xref.kind == "call";
        }));
}

void test_arm64_decoder_and_direct_control_flow_xrefs() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::ARM64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x300);
    image.sections.push_back({".text", 0x1000, 0x100, 0x100, 0x100, 0x20000000});
    const auto put_instruction = [&](std::size_t offset, std::uint32_t instruction) {
        image.bytes[offset] = static_cast<std::uint8_t>(instruction);
        image.bytes[offset + 1] = static_cast<std::uint8_t>(instruction >> 8);
        image.bytes[offset + 2] = static_cast<std::uint8_t>(instruction >> 16);
        image.bytes[offset + 3] = static_cast<std::uint8_t>(instruction >> 24);
    };
    put_instruction(0x100, 0x94000004); // bl +0x10 -> 0x401010
    put_instruction(0x104, 0x54000040); // b.eq +8 -> 0x40100C
    put_instruction(0x108, 0xD65F03C0); // ret
    put_instruction(0x10C, 0xD65F03C0); // ret
    put_instruction(0x110, 0xD65F03C0); // callee ret

    const auto decoded = gandon::decode_instructions(image, image.entry_point, 4);
#if defined(GANDON_TEST_HAS_CAPSTONE)
    assert(!decoded.empty());
#else
    if (decoded.empty()) return; // Capstone is optional in dependency-free builds.
#endif
    assert(decoded.size() >= 2);
    assert(decoded[0].mnemonic == "bl" && decoded[0].size == 4);
    assert(decoded[1].mnemonic == "b.eq" && decoded[1].size == 4);

    gandon::AnalysisDatabase analyzed(std::move(image));
    analyzed.discover_basic_xrefs();
    assert(std::any_of(analyzed.functions().begin(), analyzed.functions().end(),
        [](const gandon::Function& function) { return function.start == 0x401010; }));
    assert(std::any_of(analyzed.xrefs().begin(), analyzed.xrefs().end(), [](const gandon::Xref& xref) {
        return xref.from == 0x401000 && xref.to == 0x401010 && xref.kind == "call";
    }));
    assert(std::any_of(analyzed.xrefs().begin(), analyzed.xrefs().end(), [](const gandon::Xref& xref) {
        return xref.from == 0x401004 && xref.to == 0x40100C && xref.kind == "jcc";
    }));
}

void test_arm64_adrp_add_load_sequence_resolves_data_xref() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::ARM64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    const std::uint32_t code[]{0xB0000000, 0x91008000, 0x2A0003E1, 0xF9400022, 0xD65F03C0}; // adrp x0,0x402000; add x0,x0,#0x20; mov w1,w0; ldr x2,[x1]; ret
    std::memcpy(image.bytes.data() + 0x1000, code, sizeof(code));
    const std::string text = "ARM64_STRING";
    std::copy(text.begin(), text.end(), image.bytes.begin() + 0x2020);
    const auto decoded = gandon::decode_instructions(image, image.entry_point, 5);
#if defined(GANDON_TEST_HAS_CAPSTONE)
    assert(decoded.size() >= 4);
    assert(decoded[0].mnemonic == "adrp" && decoded[1].mnemonic == "add" &&
           decoded[2].mnemonic == "mov" && decoded[3].mnemonic == "ldr");
#else
    if (decoded.empty()) return;
#endif
    gandon::AnalysisDatabase analyzed(std::move(image));
    analyzed.discover_basic_xrefs();
    assert(std::any_of(analyzed.xrefs().begin(), analyzed.xrefs().end(), [](const gandon::Xref& xref) {
        return xref.from == 0x40100C && xref.to == 0x402020 && xref.kind == "string";
    }));

    gandon::BinaryImage got_image;
    got_image.format = gandon::BinaryFormat::ELF;
    got_image.architecture = gandon::MachineArchitecture::ARM64;
    got_image.is_64_bit = true;
    got_image.image_base = 0x400000;
    got_image.entry_point = 0x401000;
    got_image.bytes.resize(0x3000, 0);
    got_image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    got_image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    got_image.imports.push_back({"puts", 0x402000});
    const std::uint32_t got_code[]{0xB0000000, 0xF9400001, 0xF9400022, 0xD65F03C0}; // ADRP; LDR pointer from GOT; LDR through pointer; RET
    std::memcpy(got_image.bytes.data() + 0x1000, got_code, sizeof(got_code));
    const std::uint64_t string_address = 0x402020;
    std::memcpy(got_image.bytes.data() + 0x2000, &string_address, sizeof(string_address));
    std::copy(text.begin(), text.end(), got_image.bytes.begin() + 0x2020);
    gandon::AnalysisDatabase got_analysis(std::move(got_image));
    got_analysis.discover_basic_xrefs();
    assert(std::any_of(got_analysis.xrefs().begin(), got_analysis.xrefs().end(), [](const gandon::Xref& xref) {
        return xref.from == 0x401000 && xref.to == 0x402000 && xref.kind == "import:ELF!puts";
    }));
    assert(std::any_of(got_analysis.xrefs().begin(), got_analysis.xrefs().end(), [](const gandon::Xref& xref) {
        return xref.from == 0x401004 && xref.to == 0x402020 && xref.kind == "string";
    }));
}

void test_arm64_emulation_executes_and_returns() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::ARM64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x200);
    image.sections.push_back({".text", 0x1000, 0x100, 0x100, 0x100, 0x20000000});
    const std::uint32_t code[]{0xD2800540, 0x91000400, 0xD65F03C0}; // mov x0,#42; add x0,x0,#1; ret
    std::memcpy(image.bytes.data() + 0x100, code, sizeof(code));
    gandon::Emulator emulator(image);
    if (!emulator.ready()) { std::fprintf(stderr, "ARM64 emulator initialization: %s\n", emulator.error().c_str()); std::abort(); }
    std::string error;
    std::uint64_t initial_pc{};
    assert(emulator.register_value("PC", initial_pc, error) && initial_pc == image.entry_point);
    const auto result = emulator.run(16, 100'000);
    if (result.stop != gandon::EmulationStop::Returned)
        std::fprintf(stderr, "ARM64 stop=%d pc=0x%llx executed=%zu error=%s\n", static_cast<int>(result.stop),
            static_cast<unsigned long long>(result.program_counter), result.instructions_executed, result.error.c_str());
    assert(result.stop == gandon::EmulationStop::Returned);
    std::uint64_t value{};
    assert(emulator.register_value("X0", value, error) && value == 43);
    assert(emulator.trace().size() == 3);
}

void test_x64_emulation_step_over_calls_and_preserves_user_breakpoints() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x2000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    const std::uint8_t code[]{
        0xE8, 0x05, 0x00, 0x00, 0x00,       // call callee at entry + 10
        0xB8, 0x11, 0x00, 0x00, 0x00,       // caller: mov eax, 17
        0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 // callee: mov eax, 42; ret
    };
    std::copy(std::begin(code), std::end(code), image.bytes.begin() + 0x1000);

    gandon::Emulator emulator(image);
    assert(emulator.ready());
    auto result = emulator.step_over(32, 100'000);
    assert(result.stop == gandon::EmulationStop::Paused && result.program_counter == image.entry_point + 5);
    assert(!emulator.has_breakpoint(image.entry_point + 5)); // temporary return breakpoint was removed
    std::string error;
    std::uint64_t value{};
    assert(emulator.register_value("RAX", value, error) && value == 42);
    result = emulator.step_over(); // Non-call instructions still advance exactly one instruction.
    assert(result.stop == gandon::EmulationStop::Paused && result.program_counter == image.entry_point + 10);
    assert(emulator.register_value("RAX", value, error) && value == 17);

    gandon::Emulator user_breakpoint_emulator(image);
    assert(user_breakpoint_emulator.ready());
    user_breakpoint_emulator.add_breakpoint(image.entry_point + 5);
    result = user_breakpoint_emulator.step_over(32, 100'000);
    assert(result.stop == gandon::EmulationStop::Breakpoint && result.program_counter == image.entry_point + 5);
    assert(user_breakpoint_emulator.has_breakpoint(image.entry_point + 5));
}

void test_x64_emulation_step_over_indirect_call() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x2000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    constexpr std::uint64_t callee = 0x401020;
    const std::uint8_t caller_prefix[]{0x48, 0xB8}; // mov rax, callee
    std::copy(std::begin(caller_prefix), std::end(caller_prefix), image.bytes.begin() + 0x1000);
    std::memcpy(image.bytes.data() + 0x1002, &callee, sizeof(callee));
    image.bytes[0x100A] = 0xFF; image.bytes[0x100B] = 0xD0; // call rax
    image.bytes[0x100C] = 0xB8; image.bytes[0x100D] = 17; // caller resumes here
    image.bytes[0x100E] = image.bytes[0x100F] = image.bytes[0x1010] = 0;
    image.bytes[0x1020] = 0xB8; image.bytes[0x1021] = 42; // callee: mov eax, 42; ret
    image.bytes[0x1022] = image.bytes[0x1023] = image.bytes[0x1024] = 0;
    image.bytes[0x1025] = 0xC3;

    gandon::Emulator emulator(image);
    assert(emulator.ready());
    assert(emulator.step().stop == gandon::EmulationStop::Paused);
    const auto result = emulator.step_over(32, 100'000);
    assert(result.stop == gandon::EmulationStop::Paused && result.program_counter == image.entry_point + 12);
    assert(!emulator.has_breakpoint(image.entry_point + 12));
    std::uint64_t value{};
    std::string error;
    assert(emulator.register_value("RAX", value, error) && value == 42);

    gandon::Emulator call_breakpoint_emulator(image);
    assert(call_breakpoint_emulator.ready());
    assert(call_breakpoint_emulator.step().stop == gandon::EmulationStop::Paused);
    call_breakpoint_emulator.add_breakpoint(image.entry_point + 10);
    auto breakpoint_result = call_breakpoint_emulator.step_over(32, 100'000);
    assert(breakpoint_result.stop == gandon::EmulationStop::Breakpoint &&
           breakpoint_result.program_counter == image.entry_point + 10);

    gandon::Emulator return_breakpoint_emulator(image);
    assert(return_breakpoint_emulator.ready());
    assert(return_breakpoint_emulator.step().stop == gandon::EmulationStop::Paused);
    return_breakpoint_emulator.add_breakpoint(image.entry_point + 12);
    breakpoint_result = return_breakpoint_emulator.step_over(32, 100'000);
    assert(breakpoint_result.stop == gandon::EmulationStop::Breakpoint &&
           breakpoint_result.program_counter == image.entry_point + 12 &&
           return_breakpoint_emulator.has_breakpoint(image.entry_point + 12));
}

void test_x86_emulation_step_over_indirect_call() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X86;
    image.is_64_bit = false;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x2000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    constexpr std::uint32_t callee = 0x401020;
    image.bytes[0x1000] = 0xB8; // mov eax, callee
    std::memcpy(image.bytes.data() + 0x1001, &callee, sizeof(callee));
    image.bytes[0x1005] = 0xFF; image.bytes[0x1006] = 0xD0; // call eax
    image.bytes[0x1020] = 0xB8; image.bytes[0x1021] = 42; // callee: mov eax, 42; ret
    image.bytes[0x1022] = image.bytes[0x1023] = image.bytes[0x1024] = 0;
    image.bytes[0x1025] = 0xC3;

    gandon::Emulator emulator(image);
    assert(emulator.ready());
    assert(emulator.step().stop == gandon::EmulationStop::Paused);
    const auto result = emulator.step_over(32, 100'000);
    assert(result.stop == gandon::EmulationStop::Paused && result.program_counter == image.entry_point + 7);
    std::uint64_t value{};
    std::string error;
    assert(emulator.register_value("EAX", value, error) && value == 42);
}

void test_x64_emulation_step_over_rip_relative_indirect_call() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x2000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    constexpr std::uint64_t callee = 0x401020;
    image.bytes[0x1000] = 0xFF; image.bytes[0x1001] = 0x15; // call qword ptr [rip + 0xa]
    const std::int32_t displacement = 0xA;
    std::memcpy(image.bytes.data() + 0x1002, &displacement, sizeof(displacement));
    std::memcpy(image.bytes.data() + 0x1010, &callee, sizeof(callee)); // indirect-call pointer slot
    image.bytes[0x1020] = 0xB8; image.bytes[0x1021] = 42; // callee: mov eax, 42; ret
    image.bytes[0x1022] = image.bytes[0x1023] = image.bytes[0x1024] = 0;
    image.bytes[0x1025] = 0xC3;

    gandon::Emulator emulator(image);
    assert(emulator.ready());
    const auto result = emulator.step_over(32, 100'000);
    assert(result.stop == gandon::EmulationStop::Paused && result.program_counter == image.entry_point + 6);
    std::uint64_t value{};
    std::string error;
    assert(emulator.register_value("RAX", value, error) && value == 42);
}

void test_x86_emulation_step_over_direct_call() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X86;
    image.is_64_bit = false;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x2000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    const std::uint8_t code[]{
        0xE8, 0x05, 0x00, 0x00, 0x00,       // call callee at entry + 10
        0xB8, 0x11, 0x00, 0x00, 0x00,       // caller: mov eax, 17
        0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 // callee: mov eax, 42; ret
    };
    std::copy(std::begin(code), std::end(code), image.bytes.begin() + 0x1000);
    gandon::Emulator emulator(image);
    assert(emulator.ready());
    const auto result = emulator.step_over(32, 100'000);
    assert(result.stop == gandon::EmulationStop::Paused && result.program_counter == image.entry_point + 5);
    std::uint64_t value{};
    std::string error;
    assert(emulator.register_value("EAX", value, error) && value == 42);

    gandon::Emulator stepper(image);
    assert(stepper.ready());
    assert(stepper.step().stop == gandon::EmulationStop::Paused);
    assert(stepper.call_stack().size() == 1 && stepper.call_stack().back() == image.entry_point + 5);
    const auto step_out_result = stepper.step_out(32, 100'000);
    assert(step_out_result.stop == gandon::EmulationStop::Paused &&
           step_out_result.program_counter == image.entry_point + 5);
    assert(stepper.register_value("EAX", value, error) && value == 42);
}

void test_arm64_emulation_step_over_bl() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::ARM64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x2000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    const std::uint32_t code[]{0x94000002, 0xD2800220, 0xD2800540, 0xD65F03C0}; // bl callee; mov x0,#17; callee: mov x0,#42; ret
    std::memcpy(image.bytes.data() + 0x1000, code, sizeof(code));
    gandon::Emulator emulator(image);
    assert(emulator.ready());
    auto result = emulator.step_over(32, 100'000);
    assert(result.stop == gandon::EmulationStop::Paused && result.program_counter == image.entry_point + 4);
    std::uint64_t value{};
    std::string error;
    assert(emulator.register_value("X0", value, error) && value == 42);
    result = emulator.step_over();
    assert(result.stop == gandon::EmulationStop::Paused && result.program_counter == image.entry_point + 8);
    assert(emulator.register_value("X0", value, error) && value == 17);
}

void test_arm64_emulation_step_out_uses_tracked_return_address() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::ARM64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x2000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    const std::uint32_t code[]{0x94000002, 0xD2800220, 0xD2800540, 0xD65F03C0}; // bl callee; caller MOV; callee MOV; ret
    std::memcpy(image.bytes.data() + 0x1000, code, sizeof(code));
    gandon::Emulator emulator(image);
    assert(emulator.ready());
    assert(emulator.step().stop == gandon::EmulationStop::Paused); // enter callee
    assert(emulator.call_stack().size() == 1 && emulator.call_stack().back() == image.entry_point + 4);
    const auto result = emulator.step_out(32, 100'000);
    assert(result.stop == gandon::EmulationStop::Paused && result.program_counter == image.entry_point + 4);
    assert(emulator.call_stack().empty());
    std::uint64_t value{};
    std::string error;
    assert(emulator.register_value("X0", value, error) && value == 42);

    gandon::Emulator top_level(image);
    assert(top_level.ready());
    assert(top_level.step_out().stop == gandon::EmulationStop::Error);
}

void test_arm64_emulation_tracks_calls_breakpoints_and_register_deltas() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::ARM64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x200);
    image.sections.push_back({".text", 0x1000, 0x100, 0x100, 0x100, 0x20000000});
    const std::uint32_t code[]{0x94000003, 0xD28000E1, 0xD65F03C0, 0xD2800540, 0xD65F03C0};
    std::memcpy(image.bytes.data() + 0x100, code, sizeof(code)); // bl callee; mov x1,#7; ret; callee: mov x0,#42; ret
    gandon::Emulator emulator(image);
    assert(emulator.ready());
    std::string error;
    emulator.set_register_delta_capture(true);
    emulator.add_breakpoint(0x40100C);
    auto result = emulator.run(16, 100'000);
    assert(result.stop == gandon::EmulationStop::Breakpoint);
    assert(emulator.call_stack().size() == 1 && emulator.call_stack().back() == 0x401004);
    emulator.remove_breakpoint(0x40100C);
    assert(emulator.step().stop == gandon::EmulationStop::Paused); // callee MOVZ
    assert(emulator.step().stop == gandon::EmulationStop::Paused); // callee RET
    assert(emulator.call_stack().empty());
    assert(emulator.set_register("LR", 0x7fff00000000ull, error)); // caller's top-level return sentinel
    result = emulator.run(16, 100'000);
    assert(result.stop == gandon::EmulationStop::Returned);
    assert(emulator.call_stack().empty());
    std::uint64_t value{};
    assert(emulator.register_value("X0", value, error) && value == 42);
    assert(std::any_of(emulator.register_deltas().begin(), emulator.register_deltas().end(),
        [](const gandon::EmulationRegisterDelta& delta) { return (delta.changed_mask & 1u) != 0; }));
}

void test_pe_arm64_emulation_resolves_and_safely_stubs_imports() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::ARM64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.bytes[0] = 'M'; image.bytes[1] = 'Z';
    put32(image.bytes, 0x3c, 0x80);
    put32(image.bytes, 0x80, 0x00004550);
    put16(image.bytes, 0x84, 0xAA64);
    put16(image.bytes, 0x86, 2);
    put16(image.bytes, 0x94, 0xF0);
    constexpr std::size_t optional = 0x98;
    put16(image.bytes, optional, 0x20b);
    put32(image.bytes, optional + 16, 0x1000);
    put64(image.bytes, optional + 24, image.image_base);
    put32(image.bytes, optional + 108, 16);
    put32(image.bytes, optional + 112 + 8, 0x2000);
    put32(image.bytes, optional + 112 + 12, 40);
    constexpr std::size_t section_table = optional + 0xF0;
    std::memcpy(image.bytes.data() + section_table, ".text", 5);
    put32(image.bytes, section_table + 8, 0x1000);
    put32(image.bytes, section_table + 12, 0x1000);
    put32(image.bytes, section_table + 16, 0x1000);
    put32(image.bytes, section_table + 20, 0x1000);
    put32(image.bytes, section_table + 36, 0x60000020);
    const auto idata = section_table + 40;
    std::memcpy(image.bytes.data() + idata, ".idata", 6);
    put32(image.bytes, idata + 8, 0x1000);
    put32(image.bytes, idata + 12, 0x2000);
    put32(image.bytes, idata + 16, 0x1000);
    put32(image.bytes, idata + 20, 0x2000);
    put32(image.bytes, idata + 36, 0xC0000040);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".idata", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    const std::uint32_t code[]{0x58008C10, 0xD63F0200, 0xD65F03C0}; // ldr x16, [0x402180]; blr x16; ret
    std::memcpy(image.bytes.data() + 0x1000, code, sizeof(code));
    put32(image.bytes, 0x2000, 0x2100);
    put32(image.bytes, 0x2000 + 12, 0x2200);
    put32(image.bytes, 0x2000 + 16, 0x2180);
    put64(image.bytes, 0x2100, 0x2300);
    put64(image.bytes, 0x2180, 0x2300);
    const std::string dll = "KERNEL32.dll", function = "ApiFoo";
    std::copy(dll.begin(), dll.end(), image.bytes.begin() + 0x2200);
    put16(image.bytes, 0x2300, 0);
    std::copy(function.begin(), function.end(), image.bytes.begin() + 0x2302);

    gandon::Emulator emulator(image);
    assert(emulator.ready());
    emulator.add_breakpoint(0x401008);
    const auto result = emulator.run(20, 100'000);
    assert(result.stop == gandon::EmulationStop::Breakpoint);
    std::uint64_t return_value = 1;
    std::string error;
    assert(emulator.register_value("X0", return_value, error) && return_value == 0);
    assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [](const auto& item) {
        return item.annotation == "import ApiFoo [stubbed]" && item.byte_count == 4 &&
               item.bytes[0] == 0xC0 && item.bytes[1] == 0x03 && item.bytes[2] == 0x5F && item.bytes[3] == 0xD6;
    }));

    auto strlen_image = image;
    const std::string strlen_name = "strlen", sample = "arm64";
    std::copy(strlen_name.begin(), strlen_name.end(), strlen_image.bytes.begin() + 0x2302);
    std::copy(sample.begin(), sample.end(), strlen_image.bytes.begin() + 0x2400);
    gandon::Emulator strlen_emulator(strlen_image);
    assert(strlen_emulator.ready());
    assert(strlen_emulator.set_register("X0", 0x402400, error));
    strlen_emulator.add_breakpoint(0x401008);
    const auto strlen_result = strlen_emulator.run(20, 100'000);
    assert(strlen_result.stop == gandon::EmulationStop::Breakpoint);
    std::uint64_t length{};
    assert(strlen_emulator.register_value("X0", length, error) && length == sample.size());
    assert(std::any_of(strlen_emulator.trace().begin(), strlen_emulator.trace().end(), [](const auto& item) {
        return item.annotation == "import strlen [modeled]";
    }));
}

void test_elf_arm64_emulation_resolves_got_import_stubs() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::ARM64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".got", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    image.imports.push_back({"strlen", 0x402000});
    const std::uint32_t code[]{0xAA1E03F4, 0xB0000010, 0xF9400210, 0xAA1303E0,
                               0xD63F0200, 0xAA1403FE, 0xD65F03C0}; // save LR; ADRP/LDR GOT; strlen; restore LR; RET
    std::memcpy(image.bytes.data() + 0x1000, code, sizeof(code));
    const std::string sample = "hello";
    std::copy(sample.begin(), sample.end(), image.bytes.begin() + 0x2100);

    gandon::Emulator emulator(image);
    assert(emulator.ready());
    std::string error;
    assert(emulator.set_register("X19", 0x402100, error));
    emulator.add_breakpoint(0x401014);
    auto result = emulator.run(32, 100'000);
    assert(result.stop == gandon::EmulationStop::Breakpoint);
    std::uint64_t length{};
    assert(emulator.register_value("X0", length, error) && length == sample.size());
    assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [](const auto& item) {
        return item.annotation == "import strlen [modeled]";
    }));
    emulator.remove_breakpoint(0x401014);
    result = emulator.run(8, 100'000);
    assert(result.stop == gandon::EmulationStop::Returned);

    const auto verify_search = [&](const std::string& name, std::uint64_t expected_offset) {
        auto search_image = image;
        search_image.imports.front().name = name;
        gandon::Emulator search_emulator(search_image);
        assert(search_emulator.ready());
        assert(search_emulator.set_register("X19", 0x402100, error));
        assert(search_emulator.set_register("X1", 'l', error));
        const auto search_result = search_emulator.run(32, 100'000);
        assert(search_result.stop == gandon::EmulationStop::Returned);
        std::uint64_t found{};
        assert(search_emulator.register_value("X0", found, error) && found == 0x402100 + expected_offset);
        assert(std::any_of(search_emulator.trace().begin(), search_emulator.trace().end(), [&](const auto& item) {
            return item.annotation == "import " + name + " [modeled]";
        }));
    };
    verify_search("strchr", 2);
    verify_search("strrchr", 3);

    const auto verify_string_import = [&](const std::string& name, const std::string& second_argument,
                                          std::uint64_t expected) {
        auto string_image = image;
        string_image.imports.front().name = name;
        std::copy(second_argument.begin(), second_argument.end(), string_image.bytes.begin() + 0x2200);
        gandon::Emulator string_emulator(string_image);
        assert(string_emulator.ready());
        assert(string_emulator.set_register("X19", 0x402100, error));
        assert(string_emulator.set_register("X1", 0x402200, error));
        const auto string_result = string_emulator.run(32, 100'000);
        assert(string_result.stop == gandon::EmulationStop::Returned);
        std::uint64_t value{};
        assert(string_emulator.register_value("X0", value, error) && value == expected);
        assert(std::any_of(string_emulator.trace().begin(), string_emulator.trace().end(), [&](const auto& item) {
            return item.annotation == "import " + name + " [modeled]";
        }));
    };
    verify_string_import("strstr", "ll", 0x402102);
    verify_string_import("strspn", "hel", 4);
    verify_string_import("strcspn", "l", 2);

    const auto verify_memchr = [&](std::uint64_t byte, std::uint64_t count, std::uint64_t expected) {
        auto memory_image = image;
        memory_image.imports.front().name = "memchr";
        memory_image.bytes[0x2102] = 0; // Search must treat NUL as ordinary binary data.
        gandon::Emulator memory_emulator(memory_image);
        assert(memory_emulator.ready());
        assert(memory_emulator.set_register("X19", 0x402100, error));
        assert(memory_emulator.set_register("X1", byte, error));
        assert(memory_emulator.set_register("X2", count, error));
        const auto memory_result = memory_emulator.run(32, 100'000);
        assert(memory_result.stop == gandon::EmulationStop::Returned);
        std::uint64_t value{};
        assert(memory_emulator.register_value("X0", value, error) && value == expected);
        assert(std::any_of(memory_emulator.trace().begin(), memory_emulator.trace().end(), [](const auto& item) {
            return item.annotation == "import memchr [modeled]";
        }));
    };
    verify_memchr(0, 5, 0x402102);
    verify_memchr('l', 1, 0); // The matching byte is just beyond the requested range.
}

void test_elf_x64_emulation_uses_sysv_import_abi() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".got", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    image.imports.push_back({"strlen", 0x402000});
    const std::uint8_t code[]{0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00, // mov rax,[rip+0xff9] -> GOT slot
                              0xFF, 0xD0, 0xC3}; // call rax; ret
    std::copy(std::begin(code), std::end(code), image.bytes.begin() + 0x1000);
    const std::string sample = "sysv";
    std::copy(sample.begin(), sample.end(), image.bytes.begin() + 0x2100);

    gandon::Emulator emulator(image);
    assert(emulator.ready());
    std::string error;
    assert(emulator.set_register("RDI", 0x402100, error));
    const auto result = emulator.run(16, 100'000);
    assert(result.stop == gandon::EmulationStop::Returned);
    std::uint64_t length{};
    assert(emulator.register_value("RAX", length, error) && length == sample.size());
    assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [](const auto& item) {
        return item.annotation == "import strlen [modeled]";
    }));
}

void test_elf_x64_emulation_models_strchr_family() {
    const auto run_search = [](const std::string& imported_name, std::uint64_t expected_offset) {
        gandon::BinaryImage image;
        image.format = gandon::BinaryFormat::ELF;
        image.architecture = gandon::MachineArchitecture::X64;
        image.is_64_bit = true;
        image.image_base = 0x400000;
        image.entry_point = 0x401000;
        image.bytes.resize(0x3000, 0);
        image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
        image.sections.push_back({".got", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
        image.imports.push_back({imported_name, 0x402000});
        const std::uint8_t code[]{0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00, 0xFF, 0xD0, 0xC3};
        std::copy(std::begin(code), std::end(code), image.bytes.begin() + 0x1000);
        const std::string sample = "banana";
        std::copy(sample.begin(), sample.end(), image.bytes.begin() + 0x2100);

        gandon::Emulator emulator(image);
        assert(emulator.ready());
        std::string error;
        assert(emulator.set_register("RDI", 0x402100, error));
        assert(emulator.set_register("RSI", 'a', error));
        const auto result = emulator.run(16, 100'000);
        assert(result.stop == gandon::EmulationStop::Returned);
        std::uint64_t value{};
        assert(emulator.register_value("RAX", value, error) && value == 0x402100 + expected_offset);
        assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [&](const auto& item) {
            return item.annotation == "import " + imported_name + " [modeled]";
        }));
    };
    run_search("strchr", 1);
    run_search("strrchr", 5);
}

void test_elf_x64_emulation_models_memchr() {
    const auto run_search = [](std::uint64_t needle, std::uint64_t count, std::uint64_t expected) {
        gandon::BinaryImage image;
        image.format = gandon::BinaryFormat::ELF;
        image.architecture = gandon::MachineArchitecture::X64;
        image.is_64_bit = true;
        image.image_base = 0x400000;
        image.entry_point = 0x401000;
        image.bytes.resize(0x3000, 0);
        image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
        image.sections.push_back({".got", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
        image.imports.push_back({"memchr", 0x402000});
        const std::uint8_t code[]{0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00, 0xFF, 0xD0, 0xC3};
        std::copy(std::begin(code), std::end(code), image.bytes.begin() + 0x1000);
        const std::uint8_t sample[]{'a', 0, 'b', 'a'};
        std::copy(std::begin(sample), std::end(sample), image.bytes.begin() + 0x2100);

        gandon::Emulator emulator(image);
        assert(emulator.ready());
        std::string error;
        assert(emulator.set_register("RDI", 0x402100, error));
        assert(emulator.set_register("RSI", needle, error));
        assert(emulator.set_register("RDX", count, error));
        const auto result = emulator.run(16, 100'000);
        assert(result.stop == gandon::EmulationStop::Returned);
        std::uint64_t value{};
        assert(emulator.register_value("RAX", value, error) && value == expected);
        assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [](const auto& item) {
            return item.annotation == "import memchr [modeled]";
        }));
    };
    run_search(0, 4, 0x402101); // Searches binary data too; NUL is a valid match.
    run_search('b', 4, 0x402102);
    run_search('b', 2, 0); // The byte beyond n must not be found.
    run_search('a', 0, 0);
}

void test_elf_x64_emulation_models_strstr() {
    const auto run_search = [](const std::string& needle, std::uint64_t expected,
                               std::uint32_t expected_haystack_reads) {
        gandon::BinaryImage image;
        image.format = gandon::BinaryFormat::ELF;
        image.architecture = gandon::MachineArchitecture::X64;
        image.is_64_bit = true;
        image.image_base = 0x400000;
        image.entry_point = 0x401000;
        image.bytes.resize(0x3000, 0);
        image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
        image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
        image.imports.push_back({"strstr", 0x402000});
        const std::uint8_t code[]{0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00, 0xFF, 0xD0, 0xC3};
        std::copy(std::begin(code), std::end(code), image.bytes.begin() + 0x1000);
        const std::string haystack = "banana";
        std::copy(haystack.begin(), haystack.end(), image.bytes.begin() + 0x2100);
        std::copy(needle.begin(), needle.end(), image.bytes.begin() + 0x2200);

        gandon::Emulator emulator(image);
        assert(emulator.ready());
        std::string error;
        assert(emulator.set_register("RDI", 0x402100, error));
        assert(emulator.set_register("RSI", 0x402200, error));
        const auto result = emulator.run(16, 100'000);
        assert(result.stop == gandon::EmulationStop::Returned);
        std::uint64_t value{};
        assert(emulator.register_value("RAX", value, error) && value == expected);
        assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [](const auto& item) {
            return item.annotation == "import strstr [modeled]";
        }));
        const auto haystack_access = std::find_if(emulator.memory_accesses().begin(), emulator.memory_accesses().end(),
            [](const auto& access) { return access.address == 0x402100 && !access.write; });
        if (expected_haystack_reads)
            assert(haystack_access != emulator.memory_accesses().end() && haystack_access->size == expected_haystack_reads);
        else assert(haystack_access == emulator.memory_accesses().end());
    };
    run_search("ana", 0x402101, 4); // Stops on first match rather than reading the rest of the haystack.
    run_search("pear", 0, 7);
    run_search("", 0x402100, 0); // Empty needle returns without touching the haystack.
}

void test_elf_x64_emulation_models_strspn_family() {
    const auto run_span = [](const std::string& function, const std::string& input,
                             const std::string& set, std::uint64_t expected,
                             std::uint32_t expected_input_reads) {
        gandon::BinaryImage image;
        image.format = gandon::BinaryFormat::ELF;
        image.architecture = gandon::MachineArchitecture::X64;
        image.is_64_bit = true;
        image.image_base = 0x400000;
        image.entry_point = 0x401000;
        image.bytes.resize(0x3000, 0);
        image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
        image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
        image.imports.push_back({function, 0x402000});
        const std::uint8_t code[]{0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00, 0xFF, 0xD0, 0xC3};
        std::copy(std::begin(code), std::end(code), image.bytes.begin() + 0x1000);
        std::copy(input.begin(), input.end(), image.bytes.begin() + 0x2100);
        std::copy(set.begin(), set.end(), image.bytes.begin() + 0x2200);

        gandon::Emulator emulator(image);
        assert(emulator.ready());
        std::string error;
        assert(emulator.set_register("RDI", 0x402100, error));
        assert(emulator.set_register("RSI", 0x402200, error));
        assert(emulator.run(16, 100'000).stop == gandon::EmulationStop::Returned);
        std::uint64_t value{};
        assert(emulator.register_value("RAX", value, error) && value == expected);
        assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [&](const auto& item) {
            return item.annotation == "import " + function + " [modeled]";
        }));
        const auto input_access = std::find_if(emulator.memory_accesses().begin(), emulator.memory_accesses().end(),
            [](const auto& access) { return access.address == 0x402100 && !access.write; });
        assert(input_access != emulator.memory_accesses().end() && input_access->size == expected_input_reads);
    };
    run_span("strspn", "123abc", "0123456789", 3, 4);
    run_span("strcspn", "123abc", "abc", 3, 4);
    run_span("strspn", "abc", "", 0, 1);
    run_span("strcspn", "abc", "a", 0, 1);
}

void test_elf_x64_emulation_handles_virtual_linux_io_and_exit() {
    const auto make_image = [] {
        gandon::BinaryImage image;
        image.format = gandon::BinaryFormat::ELF;
        image.architecture = gandon::MachineArchitecture::X64;
        image.is_64_bit = true;
        image.image_base = 0x400000;
        image.entry_point = 0x401000;
        image.bytes.resize(0x3000, 0);
        image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
        image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
        return image;
    };
    const auto emit_mov_imm32 = [](std::vector<std::uint8_t>& code, std::uint8_t opcode, std::uint32_t value) {
        code.push_back(opcode);
        for (unsigned shift = 0; shift < 32; shift += 8)
            code.push_back(static_cast<std::uint8_t>(value >> shift));
    };
    std::string error;

    auto write_image = make_image();
    std::vector<std::uint8_t> write_code;
    emit_mov_imm32(write_code, 0xB8, 1); // SYS_write
    emit_mov_imm32(write_code, 0xBF, 1); // fd=stdout
    emit_mov_imm32(write_code, 0xBE, 0x402100);
    emit_mov_imm32(write_code, 0xBA, 5);
    write_code.insert(write_code.end(), {0x0F, 0x05});
    emit_mov_imm32(write_code, 0xB8, 60); // SYS_exit
    emit_mov_imm32(write_code, 0xBF, 7);
    write_code.insert(write_code.end(), {0x0F, 0x05});
    std::copy(write_code.begin(), write_code.end(), write_image.bytes.begin() + 0x1000);
    std::copy_n("hello", 5, write_image.bytes.begin() + 0x2100);
    gandon::Emulator writer(write_image);
    assert(writer.ready());
    const auto write_result = writer.run(64, 100'000);
    assert(write_result.stop == gandon::EmulationStop::Exited);
    assert(writer.exit_code() == 7);
    assert(writer.standard_output() == "hello" && writer.standard_error().empty());
    assert(writer.run(64, 100'000).stop == gandon::EmulationStop::Exited); // Exit is terminal.
    assert(std::any_of(writer.trace().begin(), writer.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux x86-64 syscall write";
    }));

    auto read_image = make_image();
    std::vector<std::uint8_t> read_code;
    emit_mov_imm32(read_code, 0xB8, 0); // SYS_read
    emit_mov_imm32(read_code, 0xBF, 0); // fd=stdin
    emit_mov_imm32(read_code, 0xBE, 0x402200);
    emit_mov_imm32(read_code, 0xBA, 4);
    read_code.insert(read_code.end(), {0x0F, 0x05});
    emit_mov_imm32(read_code, 0xB8, 60);
    emit_mov_imm32(read_code, 0xBF, 0);
    read_code.insert(read_code.end(), {0x0F, 0x05});
    std::copy(read_code.begin(), read_code.end(), read_image.bytes.begin() + 0x1000);
    gandon::Emulator reader(read_image);
    assert(reader.ready());
    reader.set_standard_input("xyz");
    const auto read_result = reader.run(64, 100'000);
    assert(read_result.stop == gandon::EmulationStop::Exited && reader.exit_code() == 0);
    std::array<char, 4> input{};
    assert(reader.read_memory(0x402200, input.data(), input.size(), error));
    assert(std::string(input.data(), 3) == "xyz" && input[3] == 0);
    assert(reader.standard_output().empty());
}

void test_elf_x64_emulation_handles_readv_and_writev() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    const auto emit_mov_imm32 = [](std::vector<std::uint8_t>& code, std::uint8_t opcode, std::uint32_t value) {
        code.push_back(opcode);
        for (unsigned shift = 0; shift < 32; shift += 8) code.push_back(static_cast<std::uint8_t>(value >> shift));
    };
    const auto put_iovec = [&](std::size_t file_offset, std::uint64_t base, std::uint64_t length) {
        for (unsigned i = 0; i < 8; ++i) image.bytes[file_offset + i] = static_cast<std::uint8_t>(base >> (8 * i));
        for (unsigned i = 0; i < 8; ++i) image.bytes[file_offset + 8 + i] = static_cast<std::uint8_t>(length >> (8 * i));
    };
    // writev array at 0x402000: "he" + "llo"; readv array at 0x402040: 2 + 4 bytes.
    put_iovec(0x2000, 0x402100, 2); put_iovec(0x2010, 0x402108, 3);
    put_iovec(0x2040, 0x402200, 2); put_iovec(0x2050, 0x402300, 4);
    std::copy_n("he", 2, image.bytes.begin() + 0x2100);
    std::copy_n("llo", 3, image.bytes.begin() + 0x2108);

    std::vector<std::uint8_t> code;
    emit_mov_imm32(code, 0xB8, 20);       // SYS_writev
    emit_mov_imm32(code, 0xBF, 1);        // stdout
    emit_mov_imm32(code, 0xBE, 0x402000);
    emit_mov_imm32(code, 0xBA, 2);
    code.insert(code.end(), {0x0F, 0x05});
    emit_mov_imm32(code, 0xB8, 19);       // SYS_readv
    emit_mov_imm32(code, 0xBF, 0);        // stdin
    emit_mov_imm32(code, 0xBE, 0x402040);
    emit_mov_imm32(code, 0xBA, 2);
    code.insert(code.end(), {0x0F, 0x05});
    emit_mov_imm32(code, 0xB8, 60);       // SYS_exit
    emit_mov_imm32(code, 0xBF, 0);
    code.insert(code.end(), {0x0F, 0x05});
    std::copy(code.begin(), code.end(), image.bytes.begin() + 0x1000);

    gandon::Emulator emulator(image);
    assert(emulator.ready());
    emulator.set_standard_input("abcdef");
    const auto result = emulator.run(64, 100'000);
    assert(result.stop == gandon::EmulationStop::Exited);
    assert(emulator.standard_output() == "hello" && emulator.standard_error().empty());
    std::string error;
    std::array<char, 2> first{}; std::array<char, 4> second{};
    assert(emulator.read_memory(0x402200, first.data(), first.size(), error));
    assert(emulator.read_memory(0x402300, second.data(), second.size(), error));
    assert(std::string(first.data(), 2) == "ab" && std::string(second.data(), 4) == "cdef");
    assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux x86-64 syscall writev";
    }));
}

void test_elf_arm64_emulation_handles_virtual_linux_io_and_exit() {
    const auto make_image = [] {
        gandon::BinaryImage image;
        image.format = gandon::BinaryFormat::ELF;
        image.architecture = gandon::MachineArchitecture::ARM64;
        image.is_64_bit = true;
        image.image_base = 0;
        image.entry_point = 0x1000;
        image.bytes.resize(0x3000, 0);
        image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
        image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
        return image;
    };
    const auto movz = [](std::vector<std::uint8_t>& code, unsigned reg, std::uint16_t value) {
        const auto word = 0xD2800000u | (static_cast<std::uint32_t>(value) << 5) | reg;
        for (unsigned shift = 0; shift < 32; shift += 8)
            code.push_back(static_cast<std::uint8_t>(word >> shift));
    };
    const auto svc = [](std::vector<std::uint8_t>& code) {
        code.insert(code.end(), {0x01, 0x00, 0x00, 0xD4});
    };
    auto write_image = make_image();
    std::vector<std::uint8_t> write_code;
    movz(write_code, 8, 64); movz(write_code, 0, 1); movz(write_code, 1, 0x2100); movz(write_code, 2, 5); svc(write_code);
    movz(write_code, 8, 93); movz(write_code, 0, 7); svc(write_code);
    std::copy(write_code.begin(), write_code.end(), write_image.bytes.begin() + 0x1000);
    std::copy_n("hello", 5, write_image.bytes.begin() + 0x2100);
    gandon::Emulator writer(write_image);
    assert(writer.ready());
    const auto write_result = writer.run(64, 100'000);
    assert(write_result.stop == gandon::EmulationStop::Exited && writer.exit_code() == 7);
    assert(writer.standard_output() == "hello" && writer.standard_error().empty());
    assert(std::any_of(writer.trace().begin(), writer.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux ARM64 syscall write";
    }));

    auto read_image = make_image();
    std::vector<std::uint8_t> read_code;
    movz(read_code, 8, 63); movz(read_code, 0, 0); movz(read_code, 1, 0x2200); movz(read_code, 2, 4); svc(read_code);
    movz(read_code, 8, 93); movz(read_code, 0, 0); svc(read_code);
    std::copy(read_code.begin(), read_code.end(), read_image.bytes.begin() + 0x1000);
    gandon::Emulator reader(read_image);
    assert(reader.ready());
    reader.set_standard_input("xyz");
    const auto read_result = reader.run(64, 100'000);
    assert(read_result.stop == gandon::EmulationStop::Exited && reader.exit_code() == 0);
    std::array<char, 4> input{};
    std::string error;
    assert(reader.read_memory(0x2200, input.data(), input.size(), error));
    assert(std::string(input.data(), 3) == "xyz" && input[3] == 0);

    auto mapped_image = make_image();
    std::vector<std::uint8_t> mapped_code;
    movz(mapped_code, 8, 222); movz(mapped_code, 0, 0); movz(mapped_code, 1, 0x1000);
    movz(mapped_code, 2, 3); movz(mapped_code, 3, 0x22); movz(mapped_code, 4, 0); movz(mapped_code, 5, 0); svc(mapped_code);
    mapped_code.insert(mapped_code.end(), {0xF3, 0x03, 0x00, 0xAA}); // X19 = mmap result
    movz(mapped_code, 9, 'O');
    mapped_code.insert(mapped_code.end(), {0x69, 0x02, 0x00, 0x39}); // strb w9, [x19]
    movz(mapped_code, 8, 64); movz(mapped_code, 0, 1);
    mapped_code.insert(mapped_code.end(), {0xE1, 0x03, 0x13, 0xAA}); // X1 = X19
    movz(mapped_code, 2, 1); svc(mapped_code);
    mapped_code.insert(mapped_code.end(), {0xE0, 0x03, 0x13, 0xAA}); // X0 = X19
    movz(mapped_code, 1, 0x1000); movz(mapped_code, 2, 1); movz(mapped_code, 8, 226); svc(mapped_code); // mprotect
    mapped_code.insert(mapped_code.end(), {0xE0, 0x03, 0x13, 0xAA}); // X0 = X19
    movz(mapped_code, 1, 0x1000); movz(mapped_code, 8, 215); svc(mapped_code);
    movz(mapped_code, 8, 93); movz(mapped_code, 0, 0); svc(mapped_code);
    std::copy(mapped_code.begin(), mapped_code.end(), mapped_image.bytes.begin() + 0x1000);
    gandon::Emulator mapper(mapped_image);
    assert(mapper.ready());
    const auto mapped_result = mapper.run(128, 100'000);
    assert(mapped_result.stop == gandon::EmulationStop::Exited && mapper.exit_code() == 0);
    assert(mapper.standard_output() == "O");
    assert(std::any_of(mapper.trace().begin(), mapper.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux ARM64 syscall mmap";
    }));
    assert(std::any_of(mapper.trace().begin(), mapper.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux ARM64 syscall munmap";
    }));
    assert(std::any_of(mapper.trace().begin(), mapper.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux ARM64 syscall mprotect";
    }));
}

void test_elf_x86_emulation_handles_int80_mmap2_write_and_exit() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X86;
    image.is_64_bit = false;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    std::vector<std::uint8_t> code;
    const auto mov_imm32 = [&](std::uint8_t opcode, std::uint32_t value) {
        code.push_back(opcode);
        for (unsigned shift = 0; shift < 32; shift += 8)
            code.push_back(static_cast<std::uint8_t>(value >> shift));
    };
    const auto int80 = [&] { code.insert(code.end(), {0xCD, 0x80}); };
    mov_imm32(0xB8, 192);       // mmap2
    mov_imm32(0xBB, 0);         // hint
    mov_imm32(0xB9, 0x1000);    // one page
    mov_imm32(0xBA, 3);         // PROT_READ | PROT_WRITE
    mov_imm32(0xBE, 0x22);      // MAP_PRIVATE | MAP_ANONYMOUS
    mov_imm32(0xBF, 0xFFFFFFFF); // fd = -1
    mov_imm32(0xBD, 0);         // page offset = 0
    int80();
    code.insert(code.end(), {0x89, 0xC5}); // EBP = mapped address
    code.insert(code.end(), {0xC6, 0x00, 'I'}); // *(char*)EAX = 'I'
    mov_imm32(0xBB, 1);         // stdout
    code.insert(code.end(), {0x89, 0xC1}); // ECX = EAX
    mov_imm32(0xBA, 1);         // one byte
    mov_imm32(0xB8, 4);         // write
    int80();
    code.insert(code.end(), {0x89, 0xEB}); // EBX = mapping base
    mov_imm32(0xB9, 0x1000);
    mov_imm32(0xB8, 91);        // munmap
    int80();
    mov_imm32(0xBB, 0x402100);  // timeval32 destination
    mov_imm32(0xB9, 0);
    mov_imm32(0xB8, 78);        // gettimeofday
    int80();
    mov_imm32(0xBB, 1);         // CLOCK_MONOTONIC
    mov_imm32(0xB9, 0x402200);  // timespec32 destination
    mov_imm32(0xB8, 265);       // clock_gettime
    int80();
    mov_imm32(0xB8, 1);         // exit
    mov_imm32(0xBB, 0);
    int80();
    std::copy(code.begin(), code.end(), image.bytes.begin() + 0x1000);

    gandon::Emulator emulator(image);
    assert(emulator.ready());
    const auto result = emulator.run(128, 100'000);
    assert(result.stop == gandon::EmulationStop::Exited && emulator.exit_code() == 0);
    assert(emulator.standard_output() == "I");
    struct Time32 { std::int32_t first; std::int32_t second; } timeval{}, timespec{};
    std::string error;
    assert(emulator.read_memory(0x402100, &timeval, sizeof(timeval), error));
    assert(emulator.read_memory(0x402200, &timespec, sizeof(timespec), error));
    assert(timeval.first == 1'700'000'000 && timeval.second == 0);
    assert(timespec.first == 10 && timespec.second == 1'000'000);
    assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux x86 syscall mmap2";
    }));
    assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux x86 syscall munmap";
    }));
    assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux x86 syscall clock_gettime";
    }));
}

void test_elf_x86_emulation_returns_efault_for_invalid_write_pointer() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X86;
    image.is_64_bit = false;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x2000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    std::vector<std::uint8_t> code;
    const auto mov_imm32 = [&](std::uint8_t opcode, std::uint32_t value) {
        code.push_back(opcode);
        for (unsigned shift = 0; shift < 32; shift += 8)
            code.push_back(static_cast<std::uint8_t>(value >> shift));
    };
    mov_imm32(0xB8, 4);          // write
    mov_imm32(0xBB, 1);          // stdout
    mov_imm32(0xB9, 0x50000000); // unmapped guest address
    mov_imm32(0xBA, 1);
    code.insert(code.end(), {0xCD, 0x80, 0x83, 0xF8, 0xF2, 0x75, 0x09}); // check EAX == -EFAULT
    mov_imm32(0xB8, 1);          // expected path: exit(0)
    mov_imm32(0xBB, 0);
    code.insert(code.end(), {0xCD, 0x80});
    mov_imm32(0xB8, 1);          // failure path: exit(1)
    mov_imm32(0xBB, 1);
    code.insert(code.end(), {0xCD, 0x80});
    std::copy(code.begin(), code.end(), image.bytes.begin() + 0x1000);

    gandon::Emulator emulator(image);
    assert(emulator.ready());
    const auto result = emulator.run(64, 100'000);
    assert(result.stop == gandon::EmulationStop::Exited && emulator.exit_code() == 0);
    assert(emulator.standard_output().empty());
}

void test_elf_x86_emulation_models_getrandom_and_brk() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X86;
    image.is_64_bit = false;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    std::vector<std::uint8_t> code;
    const auto mov_imm32 = [&](std::uint8_t opcode, std::uint32_t value) {
        code.push_back(opcode);
        for (unsigned shift = 0; shift < 32; shift += 8)
            code.push_back(static_cast<std::uint8_t>(value >> shift));
    };
    const auto int80 = [&] { code.insert(code.end(), {0xCD, 0x80}); };
    mov_imm32(0xB8, 355);       // getrandom
    mov_imm32(0xBB, 0x402100);  // buffer
    mov_imm32(0xB9, 4);         // length
    mov_imm32(0xBA, 0);         // flags
    int80();
    mov_imm32(0xB8, 4); mov_imm32(0xBB, 1); mov_imm32(0xB9, 0x402100);
    mov_imm32(0xBA, 4); int80(); // write random bytes to virtual stdout
    mov_imm32(0xB8, 45);         // brk(base + one page)
    mov_imm32(0xBB, 0x74001000);
    int80();
    code.insert(code.end(), {0x8D, 0x48, 0xFF, 0xC6, 0x01, 'B'}); // *(brk - 1) = 'B'
    mov_imm32(0xB8, 4); mov_imm32(0xBB, 1); mov_imm32(0xBA, 1); int80();
    mov_imm32(0xB8, 45);         // shrink heap back to base
    mov_imm32(0xBB, 0x74000000);
    int80();
    mov_imm32(0xB8, 1); mov_imm32(0xBB, 0); int80();
    std::copy(code.begin(), code.end(), image.bytes.begin() + 0x1000);

    gandon::Emulator first(image);
    gandon::Emulator second(image);
    assert(first.ready() && second.ready());
    const auto first_result = first.run(128, 100'000);
    const auto second_result = second.run(128, 100'000);
    assert(first_result.stop == gandon::EmulationStop::Exited && first.exit_code() == 0);
    assert(second_result.stop == gandon::EmulationStop::Exited && second.exit_code() == 0);
    assert(first.standard_output().size() == 5 && first.standard_output().back() == 'B');
    assert(first.standard_output() == second.standard_output());
    assert(std::any_of(first.trace().begin(), first.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux x86 syscall getrandom";
    }));
    assert(std::any_of(first.trace().begin(), first.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux x86 syscall brk";
    }));
}

void test_elf_x64_emulation_maps_anonymous_guest_memory() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    std::vector<std::uint8_t> code;
    const auto imm32 = [&](std::uint8_t opcode, std::uint32_t value) {
        code.push_back(opcode);
        for (unsigned shift = 0; shift < 32; shift += 8)
            code.push_back(static_cast<std::uint8_t>(value >> shift));
    };
    imm32(0xB8, 9);       // mmap
    imm32(0xBF, 0);       // address hint
    imm32(0xBE, 0x2000);  // length
    imm32(0xBA, 3);       // PROT_READ | PROT_WRITE
    code.insert(code.end(), {0x41, 0xBA}); // R10D = MAP_PRIVATE | MAP_ANONYMOUS
    for (const auto byte : {0x22, 0x00, 0x00, 0x00}) code.push_back(static_cast<std::uint8_t>(byte));
    code.insert(code.end(), {0x41, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF}); // R8D = -1
    code.insert(code.end(), {0x45, 0x31, 0xC9, 0x0F, 0x05}); // R9D = 0; syscall
    code.insert(code.end(), {0xC6, 0x00, 'O'});             // *(char*)RAX = 'O'
    code.insert(code.end(), {0x48, 0x89, 0xC6});            // RSI = RAX
    imm32(0xBA, 1); imm32(0xBF, 1); imm32(0xB8, 1);        // write(1, RSI, 1)
    code.insert(code.end(), {0x0F, 0x05});
    code.insert(code.end(), {0x48, 0x89, 0xF7}); // RDI = mapping base
    imm32(0xBE, 0x1000); imm32(0xBA, 1); imm32(0xB8, 10); code.insert(code.end(), {0x0F, 0x05}); // mprotect first page read-only
    code.insert(code.end(), {0x48, 0x89, 0xF7, 0x48, 0x81, 0xC7, 0x00, 0x10, 0x00, 0x00}); // RDI = second page
    imm32(0xBE, 0x1000); imm32(0xB8, 11); code.insert(code.end(), {0x0F, 0x05}); // munmap
    imm32(0xB8, 60); imm32(0xBF, 0); code.insert(code.end(), {0x0F, 0x05});
    std::copy(code.begin(), code.end(), image.bytes.begin() + 0x1000);
    gandon::Emulator emulator(image);
    assert(emulator.ready());
    const auto result = emulator.run(128, 100'000);
    assert(result.stop == gandon::EmulationStop::Exited && emulator.exit_code() == 0);
    assert(emulator.standard_output() == "O");
    assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux x86-64 syscall mmap";
    }));
    assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux x86-64 syscall munmap";
    }));
    assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux x86-64 syscall mprotect";
    }));
}

void test_elf_x64_emulation_grows_and_shrinks_brk() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    std::vector<std::uint8_t> code;
    const std::array<std::uint8_t, 8> brk_base{0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00};
    const auto load_brk_base = [&] {
        code.insert(code.end(), {0x48, 0xBF});
        code.insert(code.end(), brk_base.begin(), brk_base.end());
    };
    const auto imm32 = [&](std::uint8_t opcode, std::uint32_t value) {
        code.push_back(opcode);
        for (unsigned shift = 0; shift < 32; shift += 8)
            code.push_back(static_cast<std::uint8_t>(value >> shift));
    };
    load_brk_base();
    code.insert(code.end(), {0x48, 0x81, 0xC7, 0x00, 0x10, 0x00, 0x00}); // request base + one page
    imm32(0xB8, 12); code.insert(code.end(), {0x0F, 0x05}); // brk
    code.insert(code.end(), {0x48, 0xFF, 0xC8, 0xC6, 0x00, 'B', 0x48, 0x89, 0xC6}); // write at brk - 1
    imm32(0xBA, 1); imm32(0xBF, 1); imm32(0xB8, 1); code.insert(code.end(), {0x0F, 0x05}); // write byte
    load_brk_base();
    imm32(0xB8, 12); code.insert(code.end(), {0x0F, 0x05}); // shrink brk back to base
    imm32(0xB8, 60); imm32(0xBF, 0); code.insert(code.end(), {0x0F, 0x05}); // exit
    std::copy(code.begin(), code.end(), image.bytes.begin() + 0x1000);
    gandon::Emulator emulator(image);
    assert(emulator.ready());
    const auto result = emulator.run(128, 100'000);
    assert(result.stop == gandon::EmulationStop::Exited && emulator.exit_code() == 0);
    assert(emulator.standard_output() == "B");
    assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux x86-64 syscall brk";
    }));
}

void test_elf_x64_emulation_enforces_mprotect_permissions() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    std::vector<std::uint8_t> code;
    const auto imm32 = [&](std::uint8_t opcode, std::uint32_t value) {
        code.push_back(opcode);
        for (unsigned shift = 0; shift < 32; shift += 8)
            code.push_back(static_cast<std::uint8_t>(value >> shift));
    };
    imm32(0xB8, 9); imm32(0xBF, 0); imm32(0xBE, 0x1000); imm32(0xBA, 3);
    code.insert(code.end(), {0x41, 0xBA, 0x22, 0x00, 0x00, 0x00, 0x41, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
        0x45, 0x31, 0xC9, 0x0F, 0x05});
    code.insert(code.end(), {0x48, 0x89, 0xC3}); // RBX = mapping address
    code.insert(code.end(), {0x48, 0x89, 0xDF}); // RDI = mapping address
    imm32(0xBE, 0x1000); imm32(0xBA, 1); imm32(0xB8, 10); code.insert(code.end(), {0x0F, 0x05});
    code.insert(code.end(), {0xC6, 0x03, 'X'}); // write through RBX must fault after PROT_READ
    imm32(0xB8, 60); imm32(0xBF, 0); code.insert(code.end(), {0x0F, 0x05});
    std::copy(code.begin(), code.end(), image.bytes.begin() + 0x1000);
    gandon::Emulator emulator(image);
    assert(emulator.ready());
    const auto result = emulator.run(128, 100'000);
    assert(result.stop == gandon::EmulationStop::MemoryFault);
    assert(result.program_counter != 0);
}

void test_elf_x64_emulation_models_arch_prctl_fs_base() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    std::vector<std::uint8_t> code;
    const auto imm32 = [&](std::uint8_t opcode, std::uint32_t value) {
        code.push_back(opcode);
        for (unsigned shift = 0; shift < 32; shift += 8)
            code.push_back(static_cast<std::uint8_t>(value >> shift));
    };
    imm32(0xB8, 158); imm32(0xBF, 0x1002); imm32(0xBE, 0x402300); // ARCH_SET_FS
    code.insert(code.end(), {0x0F, 0x05});
    imm32(0xB8, 158); imm32(0xBF, 0x1003); imm32(0xBE, 0x402200); // ARCH_GET_FS
    code.insert(code.end(), {0x0F, 0x05});
    imm32(0xB8, 60); imm32(0xBF, 0); code.insert(code.end(), {0x0F, 0x05});
    std::copy(code.begin(), code.end(), image.bytes.begin() + 0x1000);
    gandon::Emulator emulator(image);
    assert(emulator.ready());
    const auto result = emulator.run(64, 100'000);
    assert(result.stop == gandon::EmulationStop::Exited && emulator.exit_code() == 0);
    std::uint64_t fs_base{};
    std::string error;
    assert(emulator.read_memory(0x402200, &fs_base, sizeof(fs_base), error));
    assert(fs_base == 0x402300);
    assert(std::count_if(emulator.trace().begin(), emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "Linux x86-64 syscall arch_prctl";
    }) == 2);
}

void test_elf_virtual_getrandom_is_deterministic_on_x64_and_arm64() {
    const auto run = [](gandon::MachineArchitecture architecture) {
        gandon::BinaryImage image;
        image.format = gandon::BinaryFormat::ELF;
        image.architecture = architecture;
        image.is_64_bit = true;
        image.image_base = architecture == gandon::MachineArchitecture::ARM64 ? 0 : 0x400000;
        image.entry_point = image.image_base + 0x1000;
        image.bytes.resize(0x3000, 0);
        image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
        image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
        std::vector<std::uint8_t> code;
        if (architecture == gandon::MachineArchitecture::X64) {
            const auto imm32 = [&](std::uint8_t opcode, std::uint32_t value) {
                code.push_back(opcode);
                for (unsigned shift = 0; shift < 32; shift += 8)
                    code.push_back(static_cast<std::uint8_t>(value >> shift));
            };
            imm32(0xB8, 318); imm32(0xBF, 0x402100); imm32(0xBE, 32); imm32(0xBA, 0);
            code.insert(code.end(), {0x0F, 0x05});
            imm32(0xB8, 60); imm32(0xBF, 0); code.insert(code.end(), {0x0F, 0x05});
        } else {
            const auto movz = [&](unsigned reg, std::uint16_t value) {
                const auto word = 0xD2800000u | (static_cast<std::uint32_t>(value) << 5) | reg;
                for (unsigned shift = 0; shift < 32; shift += 8)
                    code.push_back(static_cast<std::uint8_t>(word >> shift));
            };
            const auto svc = [&] { code.insert(code.end(), {0x01, 0x00, 0x00, 0xD4}); };
            movz(8, 278); movz(0, 0x2100); movz(1, 32); movz(2, 0); svc();
            movz(8, 93); movz(0, 0); svc();
        }
        std::copy(code.begin(), code.end(), image.bytes.begin() + 0x1000);
        gandon::Emulator emulator(image);
        assert(emulator.ready());
        const auto result = emulator.run(64, 100'000);
        assert(result.stop == gandon::EmulationStop::Exited && emulator.exit_code() == 0);
        std::array<std::uint8_t, 32> bytes{};
        std::string error;
        const auto address = architecture == gandon::MachineArchitecture::ARM64 ? 0x2100 : 0x402100;
        assert(emulator.read_memory(address, bytes.data(), bytes.size(), error));
        assert(std::any_of(bytes.begin(), bytes.end(), [](auto byte) { return byte != 0; }));
        return bytes;
    };
    assert(run(gandon::MachineArchitecture::X64) == run(gandon::MachineArchitecture::X64));
    assert(run(gandon::MachineArchitecture::ARM64) == run(gandon::MachineArchitecture::ARM64));
}

void test_elf_virtual_process_ids_and_clock_on_x64_and_arm64() {
    const auto run = [](gandon::MachineArchitecture architecture) {
        gandon::BinaryImage image;
        image.format = gandon::BinaryFormat::ELF;
        image.architecture = architecture;
        image.is_64_bit = true;
        image.image_base = architecture == gandon::MachineArchitecture::ARM64 ? 0 : 0x400000;
        image.entry_point = image.image_base + 0x1000;
        image.bytes.resize(0x3000, 0);
        image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
        image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
        std::vector<std::uint8_t> code;
        if (architecture == gandon::MachineArchitecture::X64) {
            const auto imm32 = [&](std::uint8_t opcode, std::uint32_t value) {
                code.push_back(opcode);
                for (unsigned shift = 0; shift < 32; shift += 8)
                    code.push_back(static_cast<std::uint8_t>(value >> shift));
            };
            imm32(0xBF, 0x402100); imm32(0xB8, 39); code.insert(code.end(), {0x0F, 0x05});
            code.insert(code.end(), {0x48, 0x89, 0x07}); // save pid
            imm32(0xB8, 186); code.insert(code.end(), {0x0F, 0x05, 0x48, 0x89, 0x47, 0x08}); // save tid
            imm32(0xBF, 1); imm32(0xBE, 0x402110); imm32(0xB8, 228); code.insert(code.end(), {0x0F, 0x05});
            imm32(0xB8, 60); imm32(0xBF, 0); code.insert(code.end(), {0x0F, 0x05});
        } else {
            const auto movz = [&](unsigned reg, std::uint16_t value) {
                const auto word = 0xD2800000u | (static_cast<std::uint32_t>(value) << 5) | reg;
                for (unsigned shift = 0; shift < 32; shift += 8)
                    code.push_back(static_cast<std::uint8_t>(word >> shift));
            };
            const auto emit = [&](std::uint32_t word) {
                for (unsigned shift = 0; shift < 32; shift += 8)
                    code.push_back(static_cast<std::uint8_t>(word >> shift));
            };
            const auto svc = [&] { code.insert(code.end(), {0x01, 0x00, 0x00, 0xD4}); };
            movz(19, 0x2100); movz(8, 172); svc(); emit(0xF9000260); // save pid
            movz(8, 178); svc(); emit(0xF9000660); // save tid at +8
            movz(0, 1); movz(1, 0x2110); movz(8, 113); svc();
            movz(8, 93); movz(0, 0); svc();
        }
        std::copy(code.begin(), code.end(), image.bytes.begin() + 0x1000);
        gandon::Emulator emulator(image);
        assert(emulator.ready());
        const auto result = emulator.run(64, 100'000);
        assert(result.stop == gandon::EmulationStop::Exited && emulator.exit_code() == 0);
        std::array<std::uint64_t, 4> values{};
        std::string error;
        const auto address = architecture == gandon::MachineArchitecture::ARM64 ? 0x2100 : 0x402100;
        assert(emulator.read_memory(address, values.data(), sizeof(values), error));
        assert(values[0] == 1 && values[1] == 1);
        assert(values[2] == 10 && values[3] == 0);
    };
    run(gandon::MachineArchitecture::X64);
    run(gandon::MachineArchitecture::ARM64);
}

void test_elf_x64_emulation_models_strcat() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    image.imports.push_back({"strcat", 0x402000});
    const std::uint8_t code[]{0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00, 0xFF, 0xD0, 0xC3};
    std::copy(std::begin(code), std::end(code), image.bytes.begin() + 0x1000);
    const std::string destination = "hi", source = " there";
    std::copy(destination.begin(), destination.end(), image.bytes.begin() + 0x2100);
    std::copy(source.begin(), source.end(), image.bytes.begin() + 0x2200);

    gandon::Emulator emulator(image);
    assert(emulator.ready());
    std::string error;
    assert(emulator.set_register("RDI", 0x402100, error));
    assert(emulator.set_register("RSI", 0x402200, error));
    const auto result = emulator.run(16, 100'000);
    assert(result.stop == gandon::EmulationStop::Returned);
    std::array<char, 16> combined{};
    assert(emulator.read_memory(0x402100, combined.data(), combined.size(), error));
    assert(std::string(combined.data()) == "hi there");
    std::uint64_t return_value{};
    assert(emulator.register_value("RAX", return_value, error) && return_value == 0x402100);

    auto bounded_image = image;
    bounded_image.imports.front().name = "strncat";
    gandon::Emulator bounded_emulator(bounded_image);
    assert(bounded_emulator.ready());
    assert(bounded_emulator.set_register("RDI", 0x402100, error));
    assert(bounded_emulator.set_register("RSI", 0x402200, error));
    assert(bounded_emulator.set_register("RDX", 3, error));
    const auto bounded_result = bounded_emulator.run(16, 100'000);
    assert(bounded_result.stop == gandon::EmulationStop::Returned);
    combined.fill(0);
    assert(bounded_emulator.read_memory(0x402100, combined.data(), combined.size(), error));
    assert(std::string(combined.data()) == "hi th");
}

void test_arm64_emulation_memory_access_and_watchpoints() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::ARM64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    const std::uint32_t code[]{0xF9000020, 0xF9400022, 0xD65F03C0}; // str x0,[x1]; ldr x2,[x1]; ret
    std::memcpy(image.bytes.data() + 0x1000, code, sizeof(code));
    gandon::Emulator emulator(image);
    assert(emulator.ready());
    std::string error;
    constexpr std::uint64_t expected = 0x1122334455667788ull;
    assert(emulator.set_register("X0", expected, error));
    assert(emulator.set_register("X1", 0x402000, error));
    assert(emulator.add_watchpoint(0x402000, sizeof(expected), false, true));
    auto result = emulator.run(10, 100'000);
    assert(result.stop == gandon::EmulationStop::Watchpoint && result.error.find("write watchpoint") != std::string::npos);
    std::uint64_t observed{};
    assert(emulator.read_memory(0x402000, &observed, sizeof(observed), error) && observed == expected);
    assert(!emulator.memory_accesses().empty() && emulator.memory_accesses().back().write);
    assert(std::any_of(emulator.memory_accesses().begin(), emulator.memory_accesses().end(), [](const auto& access) {
        return access.instruction_address == 0x401000 && access.write;
    }));

    emulator.clear_watchpoints();
    assert(emulator.add_watchpoint(0x402000, sizeof(expected), true, false));
    result = emulator.run(10, 100'000);
    assert(result.stop == gandon::EmulationStop::Watchpoint && result.error.find("read watchpoint") != std::string::npos);
    assert(emulator.register_value("X2", observed, error) && observed == expected);
    assert(!emulator.memory_accesses().back().write);
    assert(std::any_of(emulator.memory_accesses().begin(), emulator.memory_accesses().end(), [](const auto& access) {
        return access.instruction_address == 0x401004 && !access.write;
    }));

    emulator.clear_watchpoints();
    result = emulator.run(10, 100'000);
    assert(result.stop == gandon::EmulationStop::Returned);
}

void test_late_discovered_function_trims_crossing_cached_instruction() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x140000000;
    image.entry_point = image.image_base + 0x100;
    image.bytes.resize(0x300);
    image.sections.push_back({".text", 0x100, 0x200, 0x100, 0x200, 0x20000000});
    image.bytes[0x100] = 0xEB; image.bytes[0x101] = 0x01; // jmp from +0x100 to +0x103
    image.bytes[0x102] = 0xCC;
    image.bytes[0x103] = 0xE8; image.bytes[0x104] = 0x38; // call +0x140
    image.bytes[0x108] = 0xC3;
    image.bytes[0x140] = 0x55; image.bytes[0x141] = 0x48; // discoverable prologue
    image.bytes[0x142] = 0x89; image.bytes[0x143] = 0xE5;
    image.bytes[0x144] = 0xE8; image.bytes[0x145] = 0xBD; // call backwards into +0x106
    image.bytes[0x146] = 0xFF; image.bytes[0x147] = 0xFF; image.bytes[0x148] = 0xFF;
    image.bytes[0x149] = 0xC3;

    gandon::AnalysisDatabase analyzed(std::move(image));
    analyzed.discover_basic_xrefs();
    const auto owner = std::find_if(analyzed.functions().begin(), analyzed.functions().end(),
        [](const gandon::Function& function) { return function.start == 0x140000100ull; });
    assert(owner != analyzed.functions().end());
    assert(std::any_of(analyzed.functions().begin(), analyzed.functions().end(),
        [](const gandon::Function& function) { return function.start == 0x140000106ull; }));
    assert(std::none_of(owner->instructions.begin(), owner->instructions.end(),
        [](const gandon::Instruction& instruction) { return instruction.address == 0x140000103ull; }));
    assert(std::none_of(analyzed.xrefs().begin(), analyzed.xrefs().end(),
        [](const gandon::Xref& xref) { return xref.from == 0x140000103ull; }));
}

void test_elf_xrefs_use_decoded_boundaries_and_transitive_cfg_calls() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = image.image_base + 0x100;
    image.bytes.resize(0x300);
    image.sections.push_back({".text", 0x100, 0x200, 0x100, 0x200, 0x20000000});
    image.bytes[0x100] = 0xB8;
    image.bytes[0x101] = 0xE8;
    image.bytes[0x105] = 0x00;
    image.bytes[0x106] = 0xC0;
    image.bytes[0x107] = 0xE8;
    image.bytes[0x108] = 0x14; // call entry+7 -> entry+0x120
    image.bytes[0x10C] = 0xC3;
    image.bytes[0x120] = 0xE8;
    image.bytes[0x121] = 0x1B; // nested call -> entry+0x140
    image.bytes[0x125] = 0xC3;
    image.bytes[0x140] = 0xC3;

    gandon::AnalysisDatabase analyzed(std::move(image));
    analyzed.discover_basic_xrefs();
    assert(std::none_of(analyzed.xrefs().begin(), analyzed.xrefs().end(),
        [](const gandon::Xref& xref) { return xref.from == 0x400101ull; }));
    assert(std::any_of(analyzed.xrefs().begin(), analyzed.xrefs().end(),
        [](const gandon::Xref& xref) {
            return xref.from == 0x400107ull && xref.to == 0x400120ull && xref.kind == "call";
        }));
    assert(std::any_of(analyzed.xrefs().begin(), analyzed.xrefs().end(),
        [](const gandon::Xref& xref) {
            return xref.from == 0x400120ull && xref.to == 0x400140ull && xref.kind == "call";
        }));
    assert(std::any_of(analyzed.functions().begin(), analyzed.functions().end(),
        [](const gandon::Function& function) { return function.start == 0x400140ull; }));
}

void test_elf_rip_relative_data_reference_is_indexed() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = image.image_base + 0x100;
    image.bytes.resize(0x300, 0);
    image.sections.push_back({".text", 0x100, 0x100, 0x100, 0x100, 0x6});
    image.sections.push_back({".got", 0x200, 0x100, 0x200, 0x100, 0x2});
    image.imports.push_back({"puts", 0x400200});
    const std::uint8_t code[] = {0x48, 0x8B, 0x05, 0xF9, 0x00, 0x00, 0x00, 0xC3};
    std::copy(std::begin(code), std::end(code), image.bytes.begin() + 0x100);
    const std::string value = "ELF string";
    std::copy(value.begin(), value.end(), image.bytes.begin() + 0x200);

    gandon::AnalysisDatabase analyzed(std::move(image));
    analyzed.discover_basic_xrefs();
    assert(std::any_of(analyzed.xrefs().begin(), analyzed.xrefs().end(),
        [](const gandon::Xref& xref) {
            return xref.from == 0x400100ull && xref.to == 0x400200ull && xref.kind == "import:ELF!puts";
        }));
}

void test_long_function_keeps_late_calls_with_bounded_instruction_budget() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.is_64_bit = true;
    image.image_base = 0x140000000;
    image.entry_point = image.image_base + 0x100;
    image.bytes.resize(0x300, 0x90);
    image.sections.push_back({".text", 0x100, 0x200, 0x100, 0x200, 0x20000000});
    image.bytes[0x1E0] = 0xE8;
    image.bytes[0x1E1] = 0x9B; // after 224 NOPs, call entry+0x180
    image.bytes[0x1E2] = image.bytes[0x1E3] = image.bytes[0x1E4] = 0x00;
    image.bytes[0x1E5] = 0xC3;
    image.bytes[0x280] = 0xC3;

    gandon::AnalysisDatabase analyzed(std::move(image));
    analyzed.discover_basic_xrefs();
    assert(std::any_of(analyzed.xrefs().begin(), analyzed.xrefs().end(),
        [](const gandon::Xref& xref) {
            return xref.from == 0x1400001E0ull && xref.to == 0x140000280ull && xref.kind == "call";
        }));
    assert(std::any_of(analyzed.functions().begin(), analyzed.functions().end(),
        [](const gandon::Function& function) { return function.start == 0x140000280ull; }));
}

void test_loop_family_branches_produce_cfg_xrefs() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.is_64_bit = true;
    image.image_base = 0x140000000;
    image.entry_point = image.image_base + 0x100;
    image.bytes.resize(0x300, 0x90);
    image.sections.push_back({".text", 0x100, 0x200, 0x100, 0x200, 0x20000000});
    image.bytes[0x100] = 0xE2; image.bytes[0x101] = 0x02; // loop entry+4
    image.bytes[0x102] = 0xC3;
    image.bytes[0x104] = 0xC3;

    gandon::AnalysisDatabase analyzed(std::move(image));
    analyzed.discover_basic_xrefs();
    assert(std::any_of(analyzed.xrefs().begin(), analyzed.xrefs().end(),
        [](const gandon::Xref& xref) {
            return xref.from == 0x140000100ull && xref.to == 0x140000104ull && xref.kind == "jcc";
        }));
}

void test_invalid_and_trap_instructions_terminate_cfg_blocks() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.is_64_bit = true;
    image.image_base = 0x140000000;
    image.entry_point = image.image_base + 0x100;
    image.bytes.resize(0x300, 0x90);
    image.sections.push_back({".text", 0x100, 0x200, 0x100, 0x200, 0x20000000});
    image.bytes[0x100] = 0x0F; image.bytes[0x101] = 0x0B; // ud2
    image.bytes[0x102] = 0xE8; image.bytes[0x103] = 0x79;
    image.bytes[0x104] = image.bytes[0x105] = image.bytes[0x106] = 0x00;

    gandon::AnalysisDatabase analyzed(std::move(image));
    analyzed.discover_basic_xrefs();
    const auto function = std::find_if(analyzed.functions().begin(), analyzed.functions().end(),
        [](const gandon::Function& item) { return item.start == 0x140000100ull; });
    assert(function != analyzed.functions().end());
    assert(function->instructions.size() == 1);
    assert(function->instructions.front().mnemonic == "ud2");
    assert(std::none_of(analyzed.xrefs().begin(), analyzed.xrefs().end(),
        [](const gandon::Xref& xref) { return xref.from >= 0x140000102ull; }));
}

void test_pe_emulation_safely_stubs_imports() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.bytes[0] = 'M'; image.bytes[1] = 'Z';
    put32(image.bytes, 0x3c, 0x80);
    put32(image.bytes, 0x80, 0x00004550);
    put16(image.bytes, 0x84, 0x8664);
    put16(image.bytes, 0x86, 2);
    put16(image.bytes, 0x94, 0xF0);
    constexpr std::size_t optional = 0x98;
    put16(image.bytes, optional, 0x20b);
    put32(image.bytes, optional + 16, 0x1000);
    put64(image.bytes, optional + 24, image.image_base);
    put32(image.bytes, optional + 108, 16);
    put32(image.bytes, optional + 112 + 8, 0x2000);
    put32(image.bytes, optional + 112 + 12, 40);
    constexpr std::size_t section_table = optional + 0xF0;
    std::memcpy(image.bytes.data() + section_table, ".text", 5);
    put32(image.bytes, section_table + 8, 0x1000);
    put32(image.bytes, section_table + 12, 0x1000);
    put32(image.bytes, section_table + 16, 0x1000);
    put32(image.bytes, section_table + 20, 0x1000);
    put32(image.bytes, section_table + 36, 0x60000020);
    const auto idata = section_table + 40;
    std::memcpy(image.bytes.data() + idata, ".idata", 6);
    put32(image.bytes, idata + 8, 0x1000);
    put32(image.bytes, idata + 12, 0x2000);
    put32(image.bytes, idata + 16, 0x1000);
    put32(image.bytes, idata + 20, 0x2000);
    put32(image.bytes, idata + 36, 0xC0000040);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".idata", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});

    const std::uint8_t code[] = {0xFF, 0x15, 0x7A, 0x11, 0x00, 0x00, 0xC3}; // call [IAT]; ret
    std::copy(std::begin(code), std::end(code), image.bytes.begin() + 0x1000);
    put32(image.bytes, 0x2000, 0x2100); // OriginalFirstThunk
    put32(image.bytes, 0x2000 + 12, 0x2200); // DLL name
    put32(image.bytes, 0x2000 + 16, 0x2180); // FirstThunk
    put64(image.bytes, 0x2100, 0x2300);
    put64(image.bytes, 0x2180, 0x2300);
    const std::string dll = "KERNEL32.dll";
    std::copy(dll.begin(), dll.end(), image.bytes.begin() + 0x2200);
    put16(image.bytes, 0x2300, 0);
    const std::string name = "ApiFoo";
    std::copy(name.begin(), name.end(), image.bytes.begin() + 0x2302);

    gandon::Emulator emulator(image);
    assert(emulator.ready());
    std::string error;
    std::uint64_t stub_address{};
    assert(emulator.read_memory(0x402180, &stub_address, sizeof(stub_address), error));
    assert(stub_address >= 0x710000000000ull && stub_address != 0x402300);
    const auto result = emulator.run(20, 0);
    assert(result.stop == gandon::EmulationStop::Returned);
    assert(std::any_of(emulator.trace().begin(), emulator.trace().end(), [&](const auto& entry) {
        return entry.address == stub_address && entry.byte_count == 1 && entry.bytes[0] == 0xC3 &&
               entry.annotation == "import ApiFoo [stubbed]";
    }));

    const auto check_virtual_query_image = [&](const std::string& import_name, bool query_ex) {
        auto query_image = image;
        std::fill(query_image.bytes.begin() + 0x2302, query_image.bytes.begin() + 0x2302 + 32, 0);
        std::copy(import_name.begin(), import_name.end(), query_image.bytes.begin() + 0x2302);
        gandon::Emulator query_emulator(query_image);
        assert(query_emulator.ready());
        std::string query_error;
        assert(query_emulator.set_register("RCX", query_ex ? UINT64_MAX : 0x401000, query_error));
        assert(query_emulator.set_register("RDX", query_ex ? 0x401000 : 0x402500, query_error));
        assert(query_emulator.set_register("R8", query_ex ? 0x402500 : 48, query_error));
        if (query_ex) assert(query_emulator.set_register("R9", 48, query_error));
        const auto query_result = query_emulator.run(20, 0);
        assert(query_result.stop == gandon::EmulationStop::Returned);
        std::uint64_t structure_size{};
        assert(query_emulator.register_value("RAX", structure_size, query_error) && structure_size == 48);
        std::array<std::uint8_t, 48> memory_info{};
        assert(query_emulator.read_memory(0x402500, memory_info.data(), memory_info.size(), query_error));
        const auto read_u32 = [&](std::size_t offset) {
            return static_cast<std::uint32_t>(memory_info[offset]) |
                (static_cast<std::uint32_t>(memory_info[offset + 1]) << 8) |
                (static_cast<std::uint32_t>(memory_info[offset + 2]) << 16) |
                (static_cast<std::uint32_t>(memory_info[offset + 3]) << 24);
        };
        const auto read_u64 = [&](std::size_t offset) {
            return static_cast<std::uint64_t>(read_u32(offset)) |
                (static_cast<std::uint64_t>(read_u32(offset + 4)) << 32);
        };
        assert(read_u64(0) == 0x401000);
        assert(read_u64(8) == 0x400000);
        assert(read_u32(16) == 0x20); // PAGE_EXECUTE_READ allocation protection
        assert(read_u64(24) == 0x1000);
        assert(read_u32(32) == 0x1000); // MEM_COMMIT
        assert(read_u32(36) == 0x20); // PAGE_EXECUTE_READ
        assert(read_u32(40) == 0x01000000); // MEM_IMAGE
        assert(std::any_of(query_emulator.trace().begin(), query_emulator.trace().end(), [&](const auto& entry) {
            return entry.annotation == "import " + import_name + " [modeled]";
        }));
    };
    check_virtual_query_image("VirtualQuery", false);
    check_virtual_query_image("VirtualQueryEx", true);

    auto strlen_image = image;
    const std::string strlen_name = "strlen";
    std::copy(strlen_name.begin(), strlen_name.end(), strlen_image.bytes.begin() + 0x2302);
    const std::string sample = "hello";
    std::copy(sample.begin(), sample.end(), strlen_image.bytes.begin() + 0x2400);
    gandon::Emulator strlen_emulator(strlen_image);
    assert(strlen_emulator.ready());
    assert(strlen_emulator.set_register("RCX", 0x402400, error));
    const auto strlen_result = strlen_emulator.run(20, 0);
    assert(strlen_result.stop == gandon::EmulationStop::Returned);
    std::uint64_t length{};
    assert(strlen_emulator.register_value("RAX", length, error) && length == sample.size());
    assert(std::any_of(strlen_emulator.trace().begin(), strlen_emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "import strlen [modeled]";
    }));

    auto memcpy_image = image;
    const std::string memcpy_name = "memcpy";
    std::copy(memcpy_name.begin(), memcpy_name.end(), memcpy_image.bytes.begin() + 0x2302);
    std::copy(sample.begin(), sample.end(), memcpy_image.bytes.begin() + 0x2400);
    gandon::Emulator memcpy_emulator(memcpy_image);
    assert(memcpy_emulator.ready());
    assert(memcpy_emulator.set_register("RCX", 0x402500, error));
    assert(memcpy_emulator.set_register("RDX", 0x402400, error));
    assert(memcpy_emulator.set_register("R8", sample.size(), error));
    const auto memcpy_result = memcpy_emulator.run(20, 0);
    assert(memcpy_result.stop == gandon::EmulationStop::Returned);
    std::array<char, 5> copied{};
    assert(memcpy_emulator.read_memory(0x402500, copied.data(), copied.size(), error));
    assert(std::string(copied.begin(), copied.end()) == sample);

    auto memmove_image = image;
    const std::string memmove_name = "memmove";
    std::copy(memmove_name.begin(), memmove_name.end(), memmove_image.bytes.begin() + 0x2302);
    std::copy(sample.begin(), sample.end(), memmove_image.bytes.begin() + 0x2400);
    gandon::Emulator memmove_emulator(memmove_image);
    assert(memmove_emulator.ready());
    assert(memmove_emulator.set_register("RCX", 0x402401, error));
    assert(memmove_emulator.set_register("RDX", 0x402400, error));
    assert(memmove_emulator.set_register("R8", sample.size(), error));
    const auto memmove_result = memmove_emulator.run(20, 0);
    assert(memmove_result.stop == gandon::EmulationStop::Returned);
    std::array<char, 6> moved{};
    assert(memmove_emulator.read_memory(0x402400, moved.data(), moved.size(), error));
    assert(std::string(moved.begin(), moved.end()) == "hhello");

    auto memset_image = image;
    const std::string memset_name = "memset";
    std::copy(memset_name.begin(), memset_name.end(), memset_image.bytes.begin() + 0x2302);
    gandon::Emulator memset_emulator(memset_image);
    assert(memset_emulator.ready());
    assert(memset_emulator.set_register("RCX", 0x402500, error));
    assert(memset_emulator.set_register("RDX", 0x5A, error));
    assert(memset_emulator.set_register("R8", 4, error));
    const auto memset_result = memset_emulator.run(20, 0);
    assert(memset_result.stop == gandon::EmulationStop::Returned);
    std::array<std::uint8_t, 4> filled{};
    assert(memset_emulator.read_memory(0x402500, filled.data(), filled.size(), error));
    assert((filled == std::array<std::uint8_t, 4>{0x5A, 0x5A, 0x5A, 0x5A}));

    auto memcmp_image = image;
    const std::string memcmp_name = "memcmp";
    std::copy(memcmp_name.begin(), memcmp_name.end(), memcmp_image.bytes.begin() + 0x2302);
    std::copy_n("abcde", 5, memcmp_image.bytes.begin() + 0x2400);
    std::copy_n("abcdf", 5, memcmp_image.bytes.begin() + 0x2500);
    gandon::Emulator memcmp_emulator(memcmp_image);
    assert(memcmp_emulator.ready());
    assert(memcmp_emulator.set_register("RCX", 0x402400, error));
    assert(memcmp_emulator.set_register("RDX", 0x402500, error));
    assert(memcmp_emulator.set_register("R8", 5, error));
    const auto memcmp_result = memcmp_emulator.run(20, 0);
    assert(memcmp_result.stop == gandon::EmulationStop::Returned);
    std::uint64_t comparison{};
    assert(memcmp_emulator.register_value("RAX", comparison, error) && comparison == UINT64_MAX);

    auto strnlen_image = image;
    const std::string strnlen_name = "strnlen";
    std::copy(strnlen_name.begin(), strnlen_name.end(), strnlen_image.bytes.begin() + 0x2302);
    std::copy(sample.begin(), sample.end(), strnlen_image.bytes.begin() + 0x2400);
    gandon::Emulator strnlen_emulator(strnlen_image);
    assert(strnlen_emulator.ready());
    assert(strnlen_emulator.set_register("RCX", 0x402400, error));
    assert(strnlen_emulator.set_register("RDX", 3, error));
    const auto strnlen_result = strnlen_emulator.run(20, 0);
    assert(strnlen_result.stop == gandon::EmulationStop::Returned);
    assert(strnlen_emulator.register_value("RAX", length, error) && length == 3);

    auto strcpy_image = image;
    const std::string strcpy_name = "strcpy";
    std::copy(strcpy_name.begin(), strcpy_name.end(), strcpy_image.bytes.begin() + 0x2302);
    std::copy(sample.begin(), sample.end(), strcpy_image.bytes.begin() + 0x2400);
    gandon::Emulator strcpy_emulator(strcpy_image);
    assert(strcpy_emulator.ready());
    assert(strcpy_emulator.set_register("RCX", 0x402500, error));
    assert(strcpy_emulator.set_register("RDX", 0x402400, error));
    const auto strcpy_result = strcpy_emulator.run(20, 0);
    assert(strcpy_result.stop == gandon::EmulationStop::Returned);
    std::array<char, 6> copied_string{};
    assert(strcpy_emulator.read_memory(0x402500, copied_string.data(), copied_string.size(), error));
    assert(std::string(copied_string.data()) == sample);

    auto strcmp_image = image;
    const std::string strcmp_name = "strcmp";
    std::copy(strcmp_name.begin(), strcmp_name.end(), strcmp_image.bytes.begin() + 0x2302);
    std::copy_n("abcde", 6, strcmp_image.bytes.begin() + 0x2400);
    std::copy_n("abcdf", 6, strcmp_image.bytes.begin() + 0x2500);
    gandon::Emulator strcmp_emulator(strcmp_image);
    assert(strcmp_emulator.ready());
    assert(strcmp_emulator.set_register("RCX", 0x402400, error));
    assert(strcmp_emulator.set_register("RDX", 0x402500, error));
    const auto strcmp_result = strcmp_emulator.run(20, 0);
    assert(strcmp_result.stop == gandon::EmulationStop::Returned);
    assert(strcmp_emulator.register_value("RAX", comparison, error) && comparison == UINT64_MAX);

    auto strncmp_image = strcmp_image;
    const std::string strncmp_name = "strncmp";
    std::copy(strncmp_name.begin(), strncmp_name.end(), strncmp_image.bytes.begin() + 0x2302);
    gandon::Emulator strncmp_emulator(strncmp_image);
    assert(strncmp_emulator.ready());
    assert(strncmp_emulator.set_register("RCX", 0x402400, error));
    assert(strncmp_emulator.set_register("RDX", 0x402500, error));
    assert(strncmp_emulator.set_register("R8", 3, error));
    const auto strncmp_result = strncmp_emulator.run(20, 0);
    assert(strncmp_result.stop == gandon::EmulationStop::Returned);
    assert(strncmp_emulator.register_value("RAX", comparison, error) && comparison == 0);

    auto malloc_image = image;
    const std::string malloc_name = "malloc";
    std::copy(malloc_name.begin(), malloc_name.end(), malloc_image.bytes.begin() + 0x2302);
    gandon::Emulator malloc_emulator(malloc_image);
    assert(malloc_emulator.ready());
    assert(malloc_emulator.set_register("RCX", 32, error));
    const auto malloc_result = malloc_emulator.run(20, 0);
    assert(malloc_result.stop == gandon::EmulationStop::Returned);
    std::uint64_t allocated{};
    assert(malloc_emulator.register_value("RAX", allocated, error) && allocated >= 0x720000000000ull);
    const std::uint8_t marker = 0xA5;
    assert(malloc_emulator.write_memory(allocated, &marker, sizeof(marker), error));
    std::uint8_t observed{};
    assert(malloc_emulator.read_memory(allocated, &observed, sizeof(observed), error) && observed == marker);
    assert(std::any_of(malloc_emulator.trace().begin(), malloc_emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "import malloc [modeled]";
    }));

    auto calloc_image = image;
    const std::string calloc_name = "calloc";
    std::copy(calloc_name.begin(), calloc_name.end(), calloc_image.bytes.begin() + 0x2302);
    gandon::Emulator calloc_emulator(calloc_image);
    assert(calloc_emulator.ready());
    assert(calloc_emulator.set_register("RCX", 8, error));
    assert(calloc_emulator.set_register("RDX", 4, error));
    const auto calloc_result = calloc_emulator.run(20, 0);
    assert(calloc_result.stop == gandon::EmulationStop::Returned);
    assert(calloc_emulator.register_value("RAX", allocated, error) && allocated >= 0x720000000000ull);
    std::array<std::uint8_t, 32> zeroed{};
    zeroed.fill(0xFF);
    assert(calloc_emulator.read_memory(allocated, zeroed.data(), zeroed.size(), error));
    assert(std::all_of(zeroed.begin(), zeroed.end(), [](std::uint8_t value) { return value == 0; }));

    auto realloc_image = image;
    const std::string realloc_name = "realloc";
    std::copy(realloc_name.begin(), realloc_name.end(), realloc_image.bytes.begin() + 0x2302);
    gandon::Emulator realloc_emulator(realloc_image);
    assert(realloc_emulator.ready());
    assert(realloc_emulator.set_register("RCX", 0, error));
    assert(realloc_emulator.set_register("RDX", 24, error));
    std::uint64_t initial_stack{}, stop_sentinel{};
    assert(realloc_emulator.register_value("RSP", initial_stack, error));
    assert(realloc_emulator.read_memory(initial_stack, &stop_sentinel, sizeof(stop_sentinel), error));
    assert(realloc_emulator.run(20, 0).stop == gandon::EmulationStop::Returned);
    assert(realloc_emulator.register_value("RAX", allocated, error) && allocated >= 0x720000000000ull);
    const std::array<std::uint8_t, 24> original_data{
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24};
    assert(realloc_emulator.write_memory(allocated, original_data.data(), original_data.size(), error));
    const auto invoke_realloc = [&](std::uint64_t pointer, std::uint64_t size) {
        assert(realloc_emulator.set_register("RSP", initial_stack, error));
        assert(realloc_emulator.write_memory(initial_stack, &stop_sentinel, sizeof(stop_sentinel), error));
        assert(realloc_emulator.set_register("RIP", 0x401000, error));
        assert(realloc_emulator.set_register("RCX", pointer, error));
        assert(realloc_emulator.set_register("RDX", size, error));
        assert(realloc_emulator.run(20, 0).stop == gandon::EmulationStop::Returned);
        std::uint64_t value{};
        assert(realloc_emulator.register_value("RAX", value, error));
        return value;
    };
    const auto original_address = allocated;
    allocated = invoke_realloc(original_address, 0x2000);
    assert(allocated && allocated != original_address);
    std::array<std::uint8_t, 24> preserved_data{};
    assert(realloc_emulator.read_memory(allocated, preserved_data.data(), preserved_data.size(), error));
    assert(preserved_data == original_data);
    const auto freed_address = allocated;
    assert(invoke_realloc(freed_address, 0) == 0);
    assert(invoke_realloc(0, 32) == original_address); // first-fit reuses the earlier freed block

    auto calloc_overflow_image = calloc_image;
    gandon::Emulator calloc_overflow_emulator(calloc_overflow_image);
    assert(calloc_overflow_emulator.ready());
    assert(calloc_overflow_emulator.set_register("RCX", UINT64_MAX, error));
    assert(calloc_overflow_emulator.set_register("RDX", 2, error));
    assert(calloc_overflow_emulator.run(20, 0).stop == gandon::EmulationStop::Returned);
    assert(calloc_overflow_emulator.register_value("RAX", allocated, error) && allocated == 0);

    auto free_image = image;
    const std::string free_name = "free";
    std::copy(free_name.begin(), free_name.end(), free_image.bytes.begin() + 0x2302);
    gandon::Emulator free_emulator(free_image);
    assert(free_emulator.ready());
    assert(free_emulator.set_register("RCX", 0x720000000000ull, error));
    assert(free_emulator.run(20, 0).stop == gandon::EmulationStop::Returned);

    auto protected_memcpy_image = memcpy_image;
    gandon::Emulator protected_memcpy_emulator(protected_memcpy_image);
    assert(protected_memcpy_emulator.ready());
    assert(protected_memcpy_emulator.set_register("RCX", 0x401100, error));
    assert(protected_memcpy_emulator.set_register("RDX", 0x402400, error));
    assert(protected_memcpy_emulator.set_register("R8", sample.size(), error));
    const auto protected_memcpy_result = protected_memcpy_emulator.run(20, 0);
    assert(protected_memcpy_result.stop == gandon::EmulationStop::MemoryFault);
    assert(protected_memcpy_result.error.find("write") != std::string::npos);
    std::uint8_t code_byte{};
    assert(protected_memcpy_emulator.read_memory(0x401100, &code_byte, 1, error));
    assert(code_byte == 0); // Host-side import modeling must honor guest RX permissions.

    const auto windows_import_image = [&](const std::string& api) {
        auto result = image;
        std::fill(result.bytes.begin() + 0x2302, result.bytes.begin() + 0x2380, 0);
        std::copy(api.begin(), api.end(), result.bytes.begin() + 0x2302);
        return result;
    };
    const auto windows_multi_import_image = [&](const std::vector<std::string>& apis) {
        auto result = image;
        std::fill(result.bytes.begin() + 0x2100, result.bytes.begin() + 0x2180, 0);
        std::fill(result.bytes.begin() + 0x2180, result.bytes.begin() + 0x2200, 0);
        std::fill(result.bytes.begin() + 0x2300, result.bytes.begin() + 0x2800, 0);
        for (std::size_t index = 0; index < apis.size(); ++index) {
            const auto name_rva = static_cast<std::uint32_t>(0x2300 + index * 0x40);
            const auto name_offset = static_cast<std::size_t>(name_rva);
            put64(result.bytes, 0x2100 + index * sizeof(std::uint64_t), name_rva);
            put64(result.bytes, 0x2180 + index * sizeof(std::uint64_t), name_rva);
            put16(result.bytes, name_offset, 0);
            std::copy(apis[index].begin(), apis[index].end(), result.bytes.begin() + name_offset + 2);
        }
        return result;
    };
    auto frequency_image = windows_import_image("QueryPerformanceFrequency");
    gandon::Emulator frequency_emulator(frequency_image);
    assert(frequency_emulator.ready());
    assert(frequency_emulator.set_register("RCX", 0x402500, error));
    assert(frequency_emulator.run(20, 0).stop == gandon::EmulationStop::Returned);
    std::uint64_t frequency{};
    assert(frequency_emulator.read_memory(0x402500, &frequency, sizeof(frequency), error));
    assert(frequency == 10'000'000);
    std::uint64_t api_result{};
    assert(frequency_emulator.register_value("RAX", api_result, error) && api_result == 1);
    assert(std::any_of(frequency_emulator.trace().begin(), frequency_emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "import QueryPerformanceFrequency [modeled]";
    }));

    auto counter_image = windows_import_image("QueryPerformanceCounter");
    gandon::Emulator counter_emulator(counter_image);
    assert(counter_emulator.ready());
    assert(counter_emulator.set_register("RCX", 0x402500, error));
    assert(counter_emulator.run(20, 0).stop == gandon::EmulationStop::Returned);
    std::uint64_t counter{};
    assert(counter_emulator.read_memory(0x402500, &counter, sizeof(counter), error) && counter == 0);
    assert(counter_emulator.register_value("RAX", api_result, error) && api_result == 1);

    auto pid_image = windows_import_image("GetCurrentProcessId");
    gandon::Emulator pid_emulator(pid_image);
    assert(pid_emulator.ready());
    assert(pid_emulator.run(20, 0).stop == gandon::EmulationStop::Returned);
    assert(pid_emulator.register_value("RAX", api_result, error) && api_result == 1);

    auto debugger_image = windows_import_image("CheckRemoteDebuggerPresent");
    gandon::Emulator debugger_emulator(debugger_image);
    assert(debugger_emulator.ready());
    assert(debugger_emulator.set_register("RCX", UINT64_MAX, error));
    assert(debugger_emulator.set_register("RDX", 0x402500, error));
    assert(debugger_emulator.run(20, 0).stop == gandon::EmulationStop::Returned);
    std::uint32_t debugger_present = 1;
    assert(debugger_emulator.read_memory(0x402500, &debugger_present, sizeof(debugger_present), error));
    assert(debugger_present == 0);
    assert(debugger_emulator.register_value("RAX", api_result, error) && api_result == 1);

    gandon::Emulator invalid_counter_emulator(counter_image);
    assert(invalid_counter_emulator.ready());
    assert(invalid_counter_emulator.set_register("RCX", 0x500000, error));
    assert(invalid_counter_emulator.run(20, 0).stop == gandon::EmulationStop::MemoryFault);

    const auto heap_image = windows_multi_import_image({
        "GetProcessHeap", "HeapAlloc", "HeapSize", "HeapReAlloc", "HeapFree", "HeapValidate",
        "VirtualAlloc", "VirtualFree", "VirtualProtect", "memset", "memcpy", "FlushInstructionCache"});
    gandon::Emulator heap_emulator(heap_image);
    assert(heap_emulator.ready());
    std::uint64_t return_sentinel{};
    assert(heap_emulator.register_value("RSP", initial_stack, error));
    assert(heap_emulator.read_memory(initial_stack, &return_sentinel, sizeof(return_sentinel), error));
    const auto heap_stub = [&](std::size_t index) {
        std::uint64_t address{};
        assert(heap_emulator.read_memory(0x402180 + index * sizeof(address), &address, sizeof(address), error));
        assert(address >= 0x710000000000ull);
        return address;
    };
    const auto call_heap_api = [&](std::size_t index, std::array<std::uint64_t, 4> arguments) {
        assert(heap_emulator.set_register("RSP", initial_stack, error));
        assert(heap_emulator.write_memory(initial_stack, &return_sentinel, sizeof(return_sentinel), error));
        assert(heap_emulator.set_register("RIP", heap_stub(index), error));
        assert(heap_emulator.set_register("RCX", arguments[0], error));
        assert(heap_emulator.set_register("RDX", arguments[1], error));
        assert(heap_emulator.set_register("R8", arguments[2], error));
        assert(heap_emulator.set_register("R9", arguments[3], error));
        assert(heap_emulator.run(20, 0).stop == gandon::EmulationStop::Returned);
        std::uint64_t result{};
        assert(heap_emulator.register_value("RAX", result, error));
        return result;
    };
    constexpr std::uint64_t guest_heap_handle = 0x7000;
    assert(call_heap_api(0, {}) == guest_heap_handle);
    auto heap_pointer = call_heap_api(1, {guest_heap_handle, 0x8, 16, 0});
    assert(heap_pointer >= 0x720000000000ull);
    std::array<std::uint8_t, 16> heap_zeroed{};
    heap_zeroed.fill(0xFF);
    assert(heap_emulator.read_memory(heap_pointer, heap_zeroed.data(), heap_zeroed.size(), error));
    assert(std::all_of(heap_zeroed.begin(), heap_zeroed.end(), [](std::uint8_t value) { return value == 0; }));
    assert(call_heap_api(2, {guest_heap_handle, 0, heap_pointer, 0}) == 16);
    assert(call_heap_api(5, {guest_heap_handle, 0, heap_pointer, 0}) == 1);
    assert(call_heap_api(5, {guest_heap_handle, 0, 0, 0}) == 1);
    assert(call_heap_api(5, {guest_heap_handle, 0, heap_pointer + 1, 0}) == 0);

    const std::array<std::uint8_t, 8> heap_original{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    assert(heap_emulator.write_memory(heap_pointer, heap_original.data(), heap_original.size(), error));
    auto resized_heap_pointer = call_heap_api(3, {guest_heap_handle, 0x8, heap_pointer, 5000});
    assert(resized_heap_pointer && resized_heap_pointer != heap_pointer);
    std::array<std::uint8_t, 8> heap_preserved{};
    assert(heap_emulator.read_memory(resized_heap_pointer, heap_preserved.data(), heap_preserved.size(), error));
    assert(heap_preserved == heap_original);
    std::array<std::uint8_t, 64> heap_growth_zeroed{};
    heap_growth_zeroed.fill(0xFF);
    assert(heap_emulator.read_memory(resized_heap_pointer + 16, heap_growth_zeroed.data(), heap_growth_zeroed.size(), error));
    assert(std::all_of(heap_growth_zeroed.begin(), heap_growth_zeroed.end(), [](std::uint8_t value) { return value == 0; }));
    assert(call_heap_api(2, {guest_heap_handle, 0, resized_heap_pointer, 0}) == 5000);
    assert(call_heap_api(3, {guest_heap_handle, 0x10, resized_heap_pointer, 9000}) == 0);
    assert(call_heap_api(2, {guest_heap_handle, 0, resized_heap_pointer, 0}) == 5000);

    constexpr std::uint64_t growth_offset = 5000;
    const std::uint8_t dirty_tail = 0xA5;
    assert(heap_emulator.write_memory(resized_heap_pointer + growth_offset, &dirty_tail, sizeof(dirty_tail), error));
    resized_heap_pointer = call_heap_api(3, {guest_heap_handle, 0x8, resized_heap_pointer, 6000});
    assert(resized_heap_pointer);
    std::uint8_t cleared_tail = 0xFF;
    assert(heap_emulator.read_memory(resized_heap_pointer + growth_offset, &cleared_tail, sizeof(cleared_tail), error));
    assert(cleared_tail == 0);
    assert(call_heap_api(4, {guest_heap_handle, 0, resized_heap_pointer, 0}) == 1);
    assert(call_heap_api(5, {guest_heap_handle, 0, resized_heap_pointer, 0}) == 0);
    assert(call_heap_api(2, {guest_heap_handle, 0, resized_heap_pointer, 0}) == UINT64_MAX);
    assert(call_heap_api(1, {0x1234, 0, 32, 0}) == 0);
    assert(std::any_of(heap_emulator.trace().begin(), heap_emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "import HeapReAlloc [modeled]";
    }));

    const auto virtual_address = call_heap_api(6, {0, 0x3000, 0x2000, 0x04}); // MEM_RESERVE, PAGE_READWRITE
    assert(virtual_address >= 0x750000000000ull);
    assert(call_heap_api(6, {virtual_address + 1, 0x1000, 0x1000, 0x04}) == virtual_address); // address rounds down; range rounds up
    std::uint8_t virtual_marker = 0xA5;
    assert(heap_emulator.write_memory(virtual_address, &virtual_marker, sizeof(virtual_marker), error));
    assert(call_heap_api(8, {virtual_address, 0x1000, 0x02, 0x402600}) == 1); // PAGE_READONLY
    std::uint32_t old_protection{};
    assert(heap_emulator.read_memory(0x402600, &old_protection, sizeof(old_protection), error));
    assert(old_protection == 0x04);
    assert(heap_emulator.set_register("RSP", initial_stack, error));
    assert(heap_emulator.write_memory(initial_stack, &return_sentinel, sizeof(return_sentinel), error));
    assert(heap_emulator.set_register("RIP", heap_stub(9), error));
    assert(heap_emulator.set_register("RCX", virtual_address, error));
    assert(heap_emulator.set_register("RDX", 0x7F, error));
    assert(heap_emulator.set_register("R8", 1, error));
    assert(heap_emulator.run(20, 0).stop == gandon::EmulationStop::MemoryFault);
    assert(call_heap_api(8, {virtual_address, 0x1000, 0x40, 0x402604}) == 1); // PAGE_EXECUTE_READWRITE
    assert(heap_emulator.read_memory(0x402604, &old_protection, sizeof(old_protection), error));
    assert(old_protection == 0x02);

    const std::array<std::uint8_t, 6> initial_dynamic_code{0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3}; // mov eax,1; ret
    const std::array<std::uint8_t, 6> replacement_dynamic_code{0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3}; // mov eax,42; ret
    assert(heap_emulator.write_memory(virtual_address, initial_dynamic_code.data(), initial_dynamic_code.size(), error));
    assert(heap_emulator.set_register("RIP", virtual_address, error));
    assert(heap_emulator.set_register("RSP", initial_stack, error));
    assert(heap_emulator.run(20, 0).stop == gandon::EmulationStop::Returned);
    assert(heap_emulator.register_value("RAX", api_result, error) && api_result == 1);
    assert(heap_emulator.write_memory(0x402700, replacement_dynamic_code.data(), replacement_dynamic_code.size(), error));
    assert(call_heap_api(10, {virtual_address, 0x402700, replacement_dynamic_code.size(), 0}) == virtual_address);
    assert(call_heap_api(11, {UINT64_MAX, virtual_address, replacement_dynamic_code.size(), 0}) == 1);
    assert(call_heap_api(11, {1, virtual_address, replacement_dynamic_code.size(), 0}) == 0);
    assert(heap_emulator.set_register("RIP", virtual_address, error));
    assert(heap_emulator.set_register("RSP", initial_stack, error));
    assert(heap_emulator.run(20, 0).stop == gandon::EmulationStop::Returned);
    assert(heap_emulator.register_value("RAX", api_result, error) && api_result == 42);

    assert(call_heap_api(7, {virtual_address, 0x1000, 0x4000, 0}) == 1); // MEM_DECOMMIT
    assert(call_heap_api(6, {virtual_address, 0x1000, 0x1000, 0x04}) == virtual_address); // recommit zero-filled pages
    std::array<std::uint8_t, 16> recommitted_zeroes{};
    recommitted_zeroes.fill(0xFF);
    assert(heap_emulator.read_memory(virtual_address, recommitted_zeroes.data(), recommitted_zeroes.size(), error));
    assert(std::all_of(recommitted_zeroes.begin(), recommitted_zeroes.end(), [](std::uint8_t value) { return value == 0; }));
    assert(call_heap_api(7, {virtual_address, 0, 0x8000, 0}) == 1); // MEM_RELEASE
    assert(!heap_emulator.read_memory(virtual_address, &virtual_marker, sizeof(virtual_marker), error));

    auto dynamic_load_image = image;
    put32(dynamic_load_image.bytes, optional + 112 + 12, 60); // two import descriptors plus terminator
    put32(dynamic_load_image.bytes, 0x2000 + 20, 0x2120); // second OriginalFirstThunk
    put32(dynamic_load_image.bytes, 0x2000 + 20 + 12, 0x2220); // second DLL name
    put32(dynamic_load_image.bytes, 0x2000 + 20 + 16, 0x2188); // second FirstThunk
    put64(dynamic_load_image.bytes, 0x2120, 0x2320);
    std::fill(dynamic_load_image.bytes.begin() + 0x2180,
              dynamic_load_image.bytes.begin() + 0x2180 + 16, 0);
    put64(dynamic_load_image.bytes, 0x2180, 0x2300);
    put64(dynamic_load_image.bytes, 0x2188, 0x2320);
    std::fill(dynamic_load_image.bytes.begin() + 0x2302,
              dynamic_load_image.bytes.begin() + 0x2302 + 32, 0);
    const std::string load_library_name = "LoadLibraryA";
    std::copy(load_library_name.begin(), load_library_name.end(), dynamic_load_image.bytes.begin() + 0x2302);
    const std::string second_dll = "KERNEL32.dll";
    std::copy(second_dll.begin(), second_dll.end(), dynamic_load_image.bytes.begin() + 0x2220);
    put16(dynamic_load_image.bytes, 0x2320, 0);
    const std::string get_proc_name = "GetProcAddress";
    std::copy(get_proc_name.begin(), get_proc_name.end(), dynamic_load_image.bytes.begin() + 0x2322);
    const std::string module_name = "kernel32.dll";
    std::copy(module_name.begin(), module_name.end(), dynamic_load_image.bytes.begin() + 0x2400);
    const std::string export_name = "GetCurrentProcessId";
    std::copy(export_name.begin(), export_name.end(), dynamic_load_image.bytes.begin() + 0x2440);
    const std::uint8_t dynamic_load_code[] = {
        0x48, 0xB9, 0x00, 0x24, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, module string
        0xFF, 0x15, 0x70, 0x11, 0x00, 0x00,                         // call [LoadLibraryA IAT]
        0x48, 0x89, 0xC1,                                           // mov rcx, rax (module handle)
        0x48, 0xBA, 0x40, 0x24, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, export string
        0xFF, 0x15, 0x65, 0x11, 0x00, 0x00,                         // call [GetProcAddress IAT]
        0xFF, 0xD0,                                                 // call rax (dynamic guest trampoline)
        0xC3
    };
    std::copy(std::begin(dynamic_load_code), std::end(dynamic_load_code),
              dynamic_load_image.bytes.begin() + 0x1000);
    gandon::Emulator dynamic_load_emulator(dynamic_load_image);
    assert(dynamic_load_emulator.ready());
    const auto dynamic_load_result = dynamic_load_emulator.run(50, 0);
    assert(dynamic_load_result.stop == gandon::EmulationStop::Returned);
    std::uint64_t dynamic_api_result{};
    assert(dynamic_load_emulator.register_value("RAX", dynamic_api_result, error) && dynamic_api_result == 1);
    assert(std::any_of(dynamic_load_emulator.trace().begin(), dynamic_load_emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "import LoadLibraryA [modeled]";
    }));
    assert(std::any_of(dynamic_load_emulator.trace().begin(), dynamic_load_emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "import GetProcAddress [modeled]";
    }));
    assert(std::any_of(dynamic_load_emulator.trace().begin(), dynamic_load_emulator.trace().end(), [](const auto& entry) {
        return entry.annotation == "import GetCurrentProcessId [modeled]";
    }));
}

void test_pe_emulator_uses_isolated_virtual_filesystem() {
#if defined(GANDON_HAS_UNICORN)
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.bytes[0] = 'M'; image.bytes[1] = 'Z';
    put32(image.bytes, 0x3c, 0x80);
    put32(image.bytes, 0x80, 0x00004550);
    put16(image.bytes, 0x84, 0x8664);
    put16(image.bytes, 0x86, 2);
    put16(image.bytes, 0x94, 0xF0);
    constexpr std::size_t optional = 0x98;
    put16(image.bytes, optional, 0x20b);
    put32(image.bytes, optional + 16, 0x1000);
    put64(image.bytes, optional + 24, image.image_base);
    put32(image.bytes, optional + 108, 16);
    put32(image.bytes, optional + 112 + 8, 0x2000);
    put32(image.bytes, optional + 112 + 12, 40);
    constexpr std::size_t section_table = optional + 0xF0;
    std::memcpy(image.bytes.data() + section_table, ".text", 5);
    put32(image.bytes, section_table + 8, 0x1000);
    put32(image.bytes, section_table + 12, 0x1000);
    put32(image.bytes, section_table + 16, 0x1000);
    put32(image.bytes, section_table + 20, 0x1000);
    put32(image.bytes, section_table + 36, 0x60000020);
    const auto idata = section_table + 40;
    std::memcpy(image.bytes.data() + idata, ".idata", 6);
    put32(image.bytes, idata + 8, 0x1000);
    put32(image.bytes, idata + 12, 0x2000);
    put32(image.bytes, idata + 16, 0x1000);
    put32(image.bytes, idata + 20, 0x2000);
    put32(image.bytes, idata + 36, 0xC0000040);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".idata", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});

    const std::array<std::string, 8> import_names{
        "CreateFileA", "WriteFile", "SetFilePointer", "ReadFile", "GetFileSize", "CloseHandle",
        "DeleteFileA", "GetFileAttributesA"
    };
    put32(image.bytes, 0x2000, 0x2100);
    put32(image.bytes, 0x2000 + 12, 0x2200);
    put32(image.bytes, 0x2000 + 16, 0x2180);
    const std::string dll_name = "KERNEL32.dll";
    std::copy(dll_name.begin(), dll_name.end(), image.bytes.begin() + 0x2200);
    for (std::size_t index = 0; index < import_names.size(); ++index) {
        const auto name_rva = static_cast<std::uint32_t>(0x2300 + index * 0x20);
        put64(image.bytes, 0x2100 + index * 8, name_rva);
        put64(image.bytes, 0x2180 + index * 8, name_rva);
        put16(image.bytes, name_rva, 0);
        std::copy(import_names[index].begin(), import_names[index].end(), image.bytes.begin() + name_rva + 2);
    }
    const std::string guest_path = "C:\\Temp\\Sample.BIN";
    const std::string payload = "sandbox";
    std::copy(guest_path.begin(), guest_path.end(), image.bytes.begin() + 0x2400);
    std::copy(payload.begin(), payload.end(), image.bytes.begin() + 0x2500);

    gandon::Emulator emulator(image);
    assert(emulator.ready());
    std::string error;
    std::array<std::uint64_t, 8> stubs{};
    for (std::size_t index = 0; index < stubs.size(); ++index)
        assert(emulator.read_memory(0x402180 + index * sizeof(std::uint64_t), &stubs[index], sizeof(stubs[index]), error));

    constexpr std::uint64_t initial_stack = 0x700000000000ull + 0x100000 - 0x1000 - sizeof(std::uint64_t);
    constexpr std::uint64_t stop_sentinel = 0x7fff00000000ull;
    const auto invoke = [&](std::size_t import_index, const std::array<std::uint64_t, 7>& args) {
        assert(emulator.write_memory(initial_stack, &stop_sentinel, sizeof(stop_sentinel), error));
        for (std::size_t index = 4; index < args.size(); ++index)
            assert(emulator.write_memory(initial_stack + 0x28 + (index - 4) * sizeof(std::uint64_t),
                                         &args[index], sizeof(args[index]), error));
        assert(emulator.set_register("RCX", args[0], error));
        assert(emulator.set_register("RDX", args[1], error));
        assert(emulator.set_register("R8", args[2], error));
        assert(emulator.set_register("R9", args[3], error));
        assert(emulator.set_register("RSP", initial_stack, error));
        assert(emulator.set_register("RIP", stubs[import_index], error));
        return emulator.run(20, 0);
    };

    const std::array<std::uint64_t, 7> create_args{
        0x402400, 0xC0000000, 0, 0, 2, 0, 0 // read/write, CREATE_ALWAYS
    };
    const std::array<std::uint64_t, 7> attributes_args{0x402400, 0, 0, 0, 0, 0, 0};
    assert(invoke(7, attributes_args).stop == gandon::EmulationStop::Returned);
    std::uint64_t result{};
    assert(emulator.register_value("RAX", result, error) && result == UINT32_MAX);
    assert(invoke(0, create_args).stop == gandon::EmulationStop::Returned);
    std::uint64_t handle{};
    assert(emulator.register_value("RAX", handle, error) && handle == 0x770000000000ull);
    assert(invoke(7, attributes_args).stop == gandon::EmulationStop::Returned);
    assert(emulator.register_value("RAX", result, error) && result == 0x80);

    const std::array<std::uint64_t, 7> bad_write_args{handle, 0xDEAD0000, payload.size(), 0x402620, 0, 0, 0};
    assert(invoke(1, bad_write_args).stop == gandon::EmulationStop::MemoryFault);
    const std::array<std::uint64_t, 7> write_args{handle, 0x402500, payload.size(), 0x402620, 0, 0, 0};
    assert(invoke(1, write_args).stop == gandon::EmulationStop::Returned);
    std::uint32_t transferred{};
    assert(emulator.read_memory(0x402620, &transferred, sizeof(transferred), error) && transferred == payload.size());

    const std::array<std::uint64_t, 7> seek_args{handle, 0, 0, 0, 0, 0, 0};
    assert(invoke(2, seek_args).stop == gandon::EmulationStop::Returned);
    assert(emulator.register_value("RAX", result, error) && result == 0);
    const std::array<std::uint64_t, 7> read_args{handle, 0x402600, payload.size(), 0x402624, 0, 0, 0};
    assert(invoke(3, read_args).stop == gandon::EmulationStop::Returned);
    std::array<char, 7> read_back{};
    assert(emulator.read_memory(0x402600, read_back.data(), read_back.size(), error));
    assert(std::string(read_back.begin(), read_back.end()) == payload);
    assert(emulator.read_memory(0x402624, &transferred, sizeof(transferred), error) && transferred == payload.size());

    const std::array<std::uint64_t, 7> size_args{handle, 0x402628, 0, 0, 0, 0, 0};
    assert(invoke(4, size_args).stop == gandon::EmulationStop::Returned);
    assert(emulator.register_value("RAX", result, error) && result == payload.size());
    assert(emulator.read_memory(0x402628, &transferred, sizeof(transferred), error) && transferred == 0);
    const std::array<std::uint64_t, 7> delete_args{0x402400, 0, 0, 0, 0, 0, 0};
    assert(invoke(6, delete_args).stop == gandon::EmulationStop::Returned);
    assert(emulator.register_value("RAX", result, error) && result == 0); // still open
    const std::array<std::uint64_t, 7> close_args{handle, 0, 0, 0, 0, 0, 0};
    assert(invoke(5, close_args).stop == gandon::EmulationStop::Returned);
    assert(emulator.register_value("RAX", result, error) && result == 1);
    assert(invoke(6, delete_args).stop == gandon::EmulationStop::Returned);
    assert(emulator.register_value("RAX", result, error) && result == 1);
    assert(invoke(7, attributes_args).stop == gandon::EmulationStop::Returned);
    assert(emulator.register_value("RAX", result, error) && result == UINT32_MAX);

    auto arm64_image = image;
    arm64_image.architecture = gandon::MachineArchitecture::ARM64;
    put16(arm64_image.bytes, 0x84, 0xAA64);
    gandon::Emulator arm64_emulator(arm64_image);
    assert(arm64_emulator.ready());
    std::array<std::uint64_t, 8> arm64_stubs{};
    for (std::size_t index = 0; index < arm64_stubs.size(); ++index)
        assert(arm64_emulator.read_memory(0x402180 + index * sizeof(std::uint64_t),
                                          &arm64_stubs[index], sizeof(arm64_stubs[index]), error));
    const auto arm64_invoke = [&](std::size_t import_index, const std::array<std::uint64_t, 7>& args) {
        for (std::size_t index = 0; index < args.size(); ++index)
            assert(arm64_emulator.set_register("X" + std::to_string(index), args[index], error));
        assert(arm64_emulator.set_register("PC", arm64_stubs[import_index], error));
        return arm64_emulator.run(8, 0);
    };
    assert(arm64_invoke(7, attributes_args).stop == gandon::EmulationStop::Returned);
    assert(arm64_emulator.register_value("X0", result, error) && result == UINT32_MAX);
    assert(arm64_invoke(0, create_args).stop == gandon::EmulationStop::Returned);
    assert(arm64_emulator.register_value("X0", result, error) && result == 0x770000000000ull);
    const auto arm64_handle = result;
    assert(arm64_invoke(7, attributes_args).stop == gandon::EmulationStop::Returned);
    assert(arm64_emulator.register_value("X0", result, error) && result == 0x80);
    const std::array<std::uint64_t, 7> arm64_bad_write_args{
        arm64_handle, 0xDEAD0000, payload.size(), 0x402620, 0, 0, 0
    };
    assert(arm64_invoke(1, arm64_bad_write_args).stop == gandon::EmulationStop::MemoryFault);
    const std::array<std::uint64_t, 7> arm64_write_args{
        arm64_handle, 0x402500, payload.size(), 0x402620, 0, 0, 0
    };
    assert(arm64_invoke(1, arm64_write_args).stop == gandon::EmulationStop::Returned);
    assert(arm64_emulator.read_memory(0x402620, &transferred, sizeof(transferred), error));
    assert(transferred == payload.size());
    assert(arm64_invoke(2, seek_args).stop == gandon::EmulationStop::Returned);
    assert(arm64_emulator.register_value("X0", result, error) && result == 0);
    assert(arm64_invoke(3, read_args).stop == gandon::EmulationStop::Returned);
    assert(arm64_emulator.read_memory(0x402600, read_back.data(), read_back.size(), error));
    assert(std::string(read_back.begin(), read_back.end()) == payload);
    assert(arm64_emulator.read_memory(0x402624, &transferred, sizeof(transferred), error));
    assert(transferred == payload.size());
    assert(arm64_invoke(4, size_args).stop == gandon::EmulationStop::Returned);
    assert(arm64_emulator.register_value("X0", result, error) && result == payload.size());
    assert(arm64_emulator.read_memory(0x402628, &transferred, sizeof(transferred), error) && transferred == 0);
    assert(arm64_invoke(6, delete_args).stop == gandon::EmulationStop::Returned);
    assert(arm64_emulator.register_value("X0", result, error) && result == 0);
    assert(arm64_invoke(5, close_args).stop == gandon::EmulationStop::Returned);
    assert(arm64_emulator.register_value("X0", result, error) && result == 1);
    assert(arm64_invoke(6, delete_args).stop == gandon::EmulationStop::Returned);
    assert(arm64_emulator.register_value("X0", result, error) && result == 1);
    assert(arm64_invoke(7, attributes_args).stop == gandon::EmulationStop::Returned);
    assert(arm64_emulator.register_value("X0", result, error) && result == UINT32_MAX);

    auto arm64_guest_image = arm64_image;
    std::vector<std::uint8_t> arm64_guest_code;
    const auto emit_arm64 = [&](std::uint32_t instruction) {
        for (unsigned shift = 0; shift < 32; shift += 8)
            arm64_guest_code.push_back(static_cast<std::uint8_t>(instruction >> shift));
    };
    const auto arm64_mov_imm = [&](unsigned reg, std::uint64_t value) {
        emit_arm64(0xD2800000u | (static_cast<std::uint32_t>(value & 0xffffu) << 5) | reg);
        if (value >> 16)
            emit_arm64(0xF2A00000u | (static_cast<std::uint32_t>((value >> 16) & 0xffffu) << 5) | reg);
    };
    const auto arm64_mov_reg = [&](unsigned destination, unsigned source) {
        emit_arm64(0xAA0003E0u | (source << 16) | destination); // ORR Xd, XZR, Xm
    };
    const auto arm64_call_import = [&](std::size_t index) {
        arm64_mov_imm(16, 0x402180 + index * sizeof(std::uint64_t));
        emit_arm64(0xF9400210u); // LDR X16, [X16]
        emit_arm64(0xD63F0200u); // BLR X16
    };
    emit_arm64(0xAA1E03F3u); // Save the initial X30 return sentinel in X19.
    arm64_mov_imm(21, 0x402650); // Scratch area for captured API results.
    arm64_mov_imm(22, 0x402670); // Attribute results.
    arm64_mov_imm(0, 0x402400); arm64_call_import(7);
    emit_arm64(0xB90002C0u); // STR W0, [X22]
    arm64_mov_imm(0, 0x402400); arm64_mov_imm(1, 0xC0000000);
    arm64_mov_imm(2, 0); arm64_mov_imm(3, 0); arm64_mov_imm(4, 2);
    arm64_mov_imm(5, 0); arm64_mov_imm(6, 0);
    arm64_call_import(0); arm64_mov_reg(20, 0); // CreateFileA; preserve HANDLE in X20.
    arm64_mov_imm(0, 0x402400); arm64_call_import(7);
    emit_arm64(0xB90006C0u); // STR W0, [X22, #4]
    arm64_mov_reg(0, 20); arm64_mov_imm(1, 0x402500);
    arm64_mov_imm(2, static_cast<std::uint32_t>(payload.size())); arm64_mov_imm(3, 0x402620);
    arm64_mov_imm(4, 0); arm64_call_import(1); // WriteFile
    arm64_mov_reg(0, 20); arm64_mov_imm(1, 0); arm64_mov_imm(2, 0); arm64_mov_imm(3, 0);
    arm64_call_import(2); // SetFilePointer(..., FILE_BEGIN)
    arm64_mov_reg(0, 20); arm64_mov_imm(1, 0x402600);
    arm64_mov_imm(2, static_cast<std::uint32_t>(payload.size())); arm64_mov_imm(3, 0x402624);
    arm64_mov_imm(4, 0); arm64_call_import(3); // ReadFile
    arm64_mov_reg(0, 20); arm64_mov_imm(1, 0); arm64_call_import(4); // GetFileSize
    emit_arm64(0xF9000AA0u); // STR X0, [X21, #16]
    arm64_mov_imm(0, 0x402400); arm64_call_import(6); // DeleteFileA must fail while open.
    emit_arm64(0xB90002A0u); // STR W0, [X21]
    arm64_mov_reg(0, 20); arm64_call_import(5); // CloseHandle
    emit_arm64(0xB90006A0u); // STR W0, [X21, #4]
    arm64_mov_imm(0, 0x402400); arm64_call_import(6); // DeleteFileA succeeds after close.
    emit_arm64(0xB9000AA0u); // STR W0, [X21, #8]
    arm64_mov_imm(0, 0x402400); arm64_call_import(7);
    emit_arm64(0xB9000AC0u); // STR W0, [X22, #8]
    arm64_mov_reg(30, 19); emit_arm64(0xD65F03C0u); // Restore X30 and RET to sentinel.
    std::fill(arm64_guest_image.bytes.begin() + 0x1000, arm64_guest_image.bytes.begin() + 0x2000, 0);
    std::copy(arm64_guest_code.begin(), arm64_guest_code.end(), arm64_guest_image.bytes.begin() + 0x1000);
    gandon::Emulator arm64_guest_emulator(arm64_guest_image);
    assert(arm64_guest_emulator.ready());
    assert(arm64_guest_emulator.run(300, 0).stop == gandon::EmulationStop::Returned);
    std::array<std::uint32_t, 3> arm64_file_results{};
    assert(arm64_guest_emulator.read_memory(0x402650, arm64_file_results.data(),
                                            sizeof(arm64_file_results), error));
    assert(arm64_file_results[0] == 0 && arm64_file_results[1] == 1 && arm64_file_results[2] == 1);
    std::uint64_t arm64_file_size{};
    assert(arm64_guest_emulator.read_memory(0x402660, &arm64_file_size, sizeof(arm64_file_size), error));
    assert(arm64_file_size == payload.size());
    std::array<std::uint32_t, 3> arm64_attributes{};
    assert(arm64_guest_emulator.read_memory(0x402670, arm64_attributes.data(),
                                            sizeof(arm64_attributes), error));
    assert(arm64_attributes[0] == UINT32_MAX && arm64_attributes[1] == 0x80 &&
           arm64_attributes[2] == UINT32_MAX);
    assert(arm64_guest_emulator.read_memory(0x402620, &transferred, sizeof(transferred), error));
    assert(transferred == payload.size());
    assert(arm64_guest_emulator.read_memory(0x402624, &transferred, sizeof(transferred), error));
    assert(transferred == payload.size());
    assert(arm64_guest_emulator.read_memory(0x402600, read_back.data(), read_back.size(), error));
    assert(std::string(read_back.begin(), read_back.end()) == payload);
    assert(std::count_if(arm64_guest_emulator.trace().begin(), arm64_guest_emulator.trace().end(),
        [](const auto& entry) { return entry.annotation == "import WriteFile [modeled]"; }) == 1);
#endif
}

void test_pe32_import_emulation_uses_stdcall_cleanup() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::X86;
    image.is_64_bit = false;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000, 0);
    image.bytes[0] = 'M'; image.bytes[1] = 'Z';
    put32(image.bytes, 0x3c, 0x80);
    put32(image.bytes, 0x80, 0x00004550);
    put16(image.bytes, 0x84, 0x014c);
    put16(image.bytes, 0x86, 2);
    put16(image.bytes, 0x94, 0xE0);
    constexpr std::size_t optional = 0x98;
    put16(image.bytes, optional, 0x10b);
    put32(image.bytes, optional + 16, 0x1000);
    put32(image.bytes, optional + 28, 0x400000);
    put32(image.bytes, optional + 92, 16);
    put32(image.bytes, optional + 96 + 8, 0x2000);
    put32(image.bytes, optional + 96 + 12, 40);
    constexpr std::size_t section_table = optional + 0xE0;
    std::memcpy(image.bytes.data() + section_table, ".text", 5);
    put32(image.bytes, section_table + 8, 0x1000);
    put32(image.bytes, section_table + 12, 0x1000);
    put32(image.bytes, section_table + 16, 0x1000);
    put32(image.bytes, section_table + 20, 0x1000);
    put32(image.bytes, section_table + 36, 0x60000020);
    const auto idata = section_table + 40;
    std::memcpy(image.bytes.data() + idata, ".idata", 6);
    put32(image.bytes, idata + 8, 0x1000);
    put32(image.bytes, idata + 12, 0x2000);
    put32(image.bytes, idata + 16, 0x1000);
    put32(image.bytes, idata + 20, 0x2000);
    put32(image.bytes, idata + 36, 0xC0000040);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".idata", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});

    const std::uint8_t code[] = {
        0x68, 0x00, 0x24, 0x40, 0x00,             // push 0x402400
        0xFF, 0x15, 0x80, 0x21, 0x40, 0x00,       // call dword ptr [0x402180]
        0xC3                                        // ret
    };
    std::copy(std::begin(code), std::end(code), image.bytes.begin() + 0x1000);
    put32(image.bytes, 0x2000, 0x2100);
    put32(image.bytes, 0x2000 + 12, 0x2200);
    put32(image.bytes, 0x2000 + 16, 0x2180);
    put32(image.bytes, 0x2100, 0x2300);
    put32(image.bytes, 0x2180, 0x2300);
    const std::string dll = "MSVCRT.dll";
    std::copy(dll.begin(), dll.end(), image.bytes.begin() + 0x2200);
    put16(image.bytes, 0x2300, 0);
    const std::string name = "_strlen@4";
    std::copy(name.begin(), name.end(), image.bytes.begin() + 0x2302);
    const std::string sample = "hello";
    std::copy(sample.begin(), sample.end(), image.bytes.begin() + 0x2400);

    gandon::Emulator emulator(image);
    assert(emulator.ready());
    const auto result = emulator.run(20, 0);
    assert(result.stop == gandon::EmulationStop::Returned);
    std::uint64_t length{}, stack_pointer{};
    std::string error;
    assert(emulator.register_value("EAX", length, error) && length == sample.size());
    assert(emulator.register_value("ESP", stack_pointer, error) && stack_pointer == 0x700ff000);

    auto x86_virtual_query_image = image;
    const std::string virtual_query_name = "VirtualQuery";
    std::fill(x86_virtual_query_image.bytes.begin() + 0x2302,
              x86_virtual_query_image.bytes.begin() + 0x2302 + 32, 0);
    std::copy(virtual_query_name.begin(), virtual_query_name.end(),
              x86_virtual_query_image.bytes.begin() + 0x2302);
    const std::uint8_t x86_virtual_query_code[] = {
        0x6A, 0x1C,                               // push sizeof(MEMORY_BASIC_INFORMATION)
        0x68, 0x00, 0x25, 0x40, 0x00,           // push output buffer
        0x68, 0x00, 0x10, 0x40, 0x00,           // push address to query
        0xFF, 0x15, 0x80, 0x21, 0x40, 0x00,     // call VirtualQuery through the IAT
        0xC3
    };
    std::copy(std::begin(x86_virtual_query_code), std::end(x86_virtual_query_code),
              x86_virtual_query_image.bytes.begin() + 0x1000);
    gandon::Emulator x86_virtual_query_emulator(x86_virtual_query_image);
    assert(x86_virtual_query_emulator.ready());
    assert(x86_virtual_query_emulator.run(40, 0).stop == gandon::EmulationStop::Returned);
    assert(x86_virtual_query_emulator.register_value("EAX", length, error) && length == 28);
    assert(x86_virtual_query_emulator.register_value("ESP", stack_pointer, error) && stack_pointer == 0x700ff000);
    std::array<std::uint8_t, 28> x86_memory_info{};
    assert(x86_virtual_query_emulator.read_memory(0x402500, x86_memory_info.data(), x86_memory_info.size(), error));
    const auto read_x86_u32 = [&](std::size_t offset) {
        return static_cast<std::uint32_t>(x86_memory_info[offset]) |
            (static_cast<std::uint32_t>(x86_memory_info[offset + 1]) << 8) |
            (static_cast<std::uint32_t>(x86_memory_info[offset + 2]) << 16) |
            (static_cast<std::uint32_t>(x86_memory_info[offset + 3]) << 24);
    };
    assert(read_x86_u32(0) == 0x401000);
    assert(read_x86_u32(4) == 0x400000);
    assert(read_x86_u32(8) == 0x20);
    assert(read_x86_u32(12) == 0x1000);
    assert(read_x86_u32(16) == 0x1000);
    assert(read_x86_u32(20) == 0x20);
    assert(read_x86_u32(24) == 0x01000000);

    auto x86_load_library_image = image;
    const std::string load_library_name = "LoadLibraryA";
    std::fill(x86_load_library_image.bytes.begin() + 0x2302,
              x86_load_library_image.bytes.begin() + 0x2302 + 32, 0);
    std::copy(load_library_name.begin(), load_library_name.end(),
              x86_load_library_image.bytes.begin() + 0x2302);
    const std::string module_path = "C:\\Windows\\System32\\KERNEL32.DLL";
    std::copy(module_path.begin(), module_path.end(), x86_load_library_image.bytes.begin() + 0x2400);
    const std::uint8_t x86_load_library_code[] = {
        0x68, 0x00, 0x24, 0x40, 0x00,             // push module path
        0xFF, 0x15, 0x80, 0x21, 0x40, 0x00,     // call LoadLibraryA through the IAT
        0xC3
    };
    std::copy(std::begin(x86_load_library_code), std::end(x86_load_library_code),
              x86_load_library_image.bytes.begin() + 0x1000);
    gandon::Emulator x86_load_library_emulator(x86_load_library_image);
    assert(x86_load_library_emulator.ready());
    assert(x86_load_library_emulator.run(20, 0).stop == gandon::EmulationStop::Returned);
    assert(x86_load_library_emulator.register_value("EAX", length, error) && length == 0x76000000);
    assert(x86_load_library_emulator.register_value("ESP", stack_pointer, error) && stack_pointer == 0x700ff000);

    auto x86_unknown_module_image = x86_load_library_image;
    std::fill(x86_unknown_module_image.bytes.begin() + 0x2400,
              x86_unknown_module_image.bytes.begin() + 0x2400 + module_path.size(), 0);
    const std::string unknown_module = "not-a-supported-guest-module.dll";
    std::copy(unknown_module.begin(), unknown_module.end(), x86_unknown_module_image.bytes.begin() + 0x2400);
    gandon::Emulator x86_unknown_module_emulator(x86_unknown_module_image);
    assert(x86_unknown_module_emulator.ready());
    assert(x86_unknown_module_emulator.run(20, 0).stop == gandon::EmulationStop::Returned);
    assert(x86_unknown_module_emulator.register_value("EAX", length, error) && length == 0);
    assert(x86_unknown_module_emulator.register_value("ESP", stack_pointer, error) && stack_pointer == 0x700ff000);

    auto x86_file_image = image;
    const std::array<std::string, 6> x86_file_imports{
        "CreateFileA", "WriteFile", "SetFilePointer", "ReadFile", "CloseHandle", "GetFileAttributesA"
    };
    std::fill(x86_file_image.bytes.begin() + 0x2100, x86_file_image.bytes.begin() + 0x21a0, 0);
    std::fill(x86_file_image.bytes.begin() + 0x2300, x86_file_image.bytes.begin() + 0x23c0, 0);
    for (std::size_t index = 0; index < x86_file_imports.size(); ++index) {
        const auto name_rva = static_cast<std::uint32_t>(0x2300 + index * 0x20);
        put32(x86_file_image.bytes, 0x2100 + index * sizeof(std::uint32_t), name_rva);
        put32(x86_file_image.bytes, 0x2180 + index * sizeof(std::uint32_t), name_rva);
        put16(x86_file_image.bytes, name_rva, 0);
        std::copy(x86_file_imports[index].begin(), x86_file_imports[index].end(),
                  x86_file_image.bytes.begin() + name_rva + 2);
    }
    const std::string x86_guest_path = "C:\\Temp\\x86-sample.bin";
    const std::string x86_payload = "pe32-io";
    std::copy(x86_guest_path.begin(), x86_guest_path.end(), x86_file_image.bytes.begin() + 0x2400);
    std::copy(x86_payload.begin(), x86_payload.end(), x86_file_image.bytes.begin() + 0x2500);
    std::vector<std::uint8_t> x86_file_code;
    const auto push_immediate = [&](std::uint32_t value) {
        x86_file_code.push_back(0x68);
        for (unsigned shift = 0; shift < 32; shift += 8)
            x86_file_code.push_back(static_cast<std::uint8_t>(value >> shift));
    };
    const auto push_memory = [&](std::uint32_t address) {
        x86_file_code.insert(x86_file_code.end(), {0xFF, 0x35});
        for (unsigned shift = 0; shift < 32; shift += 8)
            x86_file_code.push_back(static_cast<std::uint8_t>(address >> shift));
    };
    const auto call_iat = [&](std::uint32_t address) {
        x86_file_code.insert(x86_file_code.end(), {0xFF, 0x15});
        for (unsigned shift = 0; shift < 32; shift += 8)
            x86_file_code.push_back(static_cast<std::uint8_t>(address >> shift));
    };
    const auto store_eax = [&](std::uint32_t address) {
        x86_file_code.push_back(0xA3);
        for (unsigned shift = 0; shift < 32; shift += 8)
            x86_file_code.push_back(static_cast<std::uint8_t>(address >> shift));
    };
    push_immediate(0x402400); call_iat(0x402194); store_eax(0x402610); // Missing file attributes.
    push_immediate(0); push_immediate(0); push_immediate(2); push_immediate(0);
    push_immediate(0); push_immediate(0xC0000000); push_immediate(0x402400);
    call_iat(0x402180); store_eax(0x402600); // CreateFileA(path, read|write, ..., CREATE_ALWAYS)
    push_immediate(0x402400); call_iat(0x402194); store_eax(0x402614); // Existing file attributes.
    push_immediate(0); push_immediate(0x402604); push_immediate(static_cast<std::uint32_t>(x86_payload.size()));
    push_immediate(0x402500); push_memory(0x402600);
    call_iat(0x402184); // WriteFile(handle, payload, size, &written, nullptr)
    push_immediate(0); push_immediate(0); push_immediate(0); push_memory(0x402600);
    call_iat(0x402188); // SetFilePointer(handle, 0, nullptr, FILE_BEGIN)
    push_immediate(0); push_immediate(0x402608); push_immediate(static_cast<std::uint32_t>(x86_payload.size()));
    push_immediate(0x402520); push_memory(0x402600);
    call_iat(0x40218C); // ReadFile(handle, readback, size, &read, nullptr)
    push_memory(0x402600); call_iat(0x402190); // CloseHandle(handle)
    x86_file_code.push_back(0xC3);
    std::fill(x86_file_image.bytes.begin() + 0x1000, x86_file_image.bytes.begin() + 0x2000, 0x90);
    std::copy(x86_file_code.begin(), x86_file_code.end(), x86_file_image.bytes.begin() + 0x1000);
    gandon::Emulator x86_file_emulator(x86_file_image);
    assert(x86_file_emulator.ready());
    assert(x86_file_emulator.run(100, 0).stop == gandon::EmulationStop::Returned);
    assert(x86_file_emulator.register_value("EAX", length, error) && length == 1);
    assert(x86_file_emulator.register_value("ESP", stack_pointer, error) && stack_pointer == 0x700ff000);
    std::uint32_t x86_file_handle{}, x86_written{}, x86_read{};
    assert(x86_file_emulator.read_memory(0x402600, &x86_file_handle, sizeof(x86_file_handle), error));
    assert(x86_file_handle == 0x77000000);
    std::uint32_t x86_missing_attributes{}, x86_file_attributes{};
    assert(x86_file_emulator.read_memory(0x402610, &x86_missing_attributes,
                                         sizeof(x86_missing_attributes), error));
    assert(x86_missing_attributes == UINT32_MAX);
    assert(x86_file_emulator.read_memory(0x402614, &x86_file_attributes, sizeof(x86_file_attributes), error));
    assert(x86_file_attributes == 0x80);
    assert(x86_file_emulator.read_memory(0x402604, &x86_written, sizeof(x86_written), error));
    assert(x86_written == x86_payload.size());
    assert(x86_file_emulator.read_memory(0x402608, &x86_read, sizeof(x86_read), error));
    assert(x86_read == x86_payload.size());
    std::array<char, 7> x86_readback{};
    assert(x86_file_emulator.read_memory(0x402520, x86_readback.data(), x86_readback.size(), error));
    assert(std::string(x86_readback.begin(), x86_readback.end()) == x86_payload);

    auto x86_dynamic_load_image = image;
    put32(x86_dynamic_load_image.bytes, optional + 96 + 12, 60);
    put32(x86_dynamic_load_image.bytes, 0x2000 + 20, 0x2120);
    put32(x86_dynamic_load_image.bytes, 0x2000 + 20 + 12, 0x2220);
    put32(x86_dynamic_load_image.bytes, 0x2000 + 20 + 16, 0x2184);
    put32(x86_dynamic_load_image.bytes, 0x2120, 0x2320);
    put32(x86_dynamic_load_image.bytes, 0x2180, 0x2300);
    put32(x86_dynamic_load_image.bytes, 0x2184, 0x2320);
    std::fill(x86_dynamic_load_image.bytes.begin() + 0x2302,
              x86_dynamic_load_image.bytes.begin() + 0x2302 + 32, 0);
    std::copy(load_library_name.begin(), load_library_name.end(),
              x86_dynamic_load_image.bytes.begin() + 0x2302);
    const std::string x86_second_dll = "KERNEL32.dll";
    const std::string x86_get_proc_name = "GetProcAddress";
    const std::string x86_module_name = "kernel32.dll";
    const std::string x86_export_name = "GetCurrentProcessId";
    std::copy(x86_second_dll.begin(), x86_second_dll.end(), x86_dynamic_load_image.bytes.begin() + 0x2220);
    put16(x86_dynamic_load_image.bytes, 0x2320, 0);
    std::copy(x86_get_proc_name.begin(), x86_get_proc_name.end(), x86_dynamic_load_image.bytes.begin() + 0x2322);
    std::copy(x86_module_name.begin(), x86_module_name.end(), x86_dynamic_load_image.bytes.begin() + 0x2400);
    std::copy(x86_export_name.begin(), x86_export_name.end(), x86_dynamic_load_image.bytes.begin() + 0x2440);
    const std::uint8_t x86_dynamic_load_code[] = {
        0x68, 0x00, 0x24, 0x40, 0x00,             // push module string
        0xFF, 0x15, 0x80, 0x21, 0x40, 0x00,     // call LoadLibraryA
        0x68, 0x40, 0x24, 0x40, 0x00,           // push export string
        0x50,                                     // push module handle
        0xFF, 0x15, 0x84, 0x21, 0x40, 0x00,     // call GetProcAddress
        0xFF, 0xD0,                               // call dynamic stdcall trampoline
        0xC3
    };
    std::copy(std::begin(x86_dynamic_load_code), std::end(x86_dynamic_load_code),
              x86_dynamic_load_image.bytes.begin() + 0x1000);
    gandon::Emulator x86_dynamic_load_emulator(x86_dynamic_load_image);
    assert(x86_dynamic_load_emulator.ready());
    assert(x86_dynamic_load_emulator.run(40, 0).stop == gandon::EmulationStop::Returned);
    assert(x86_dynamic_load_emulator.register_value("EAX", length, error) && length == 1);
    assert(x86_dynamic_load_emulator.register_value("ESP", stack_pointer, error) && stack_pointer == 0x700ff000);

    auto qpf_image = image;
    const std::string qpf_name = "QueryPerformanceFrequency";
    std::fill(qpf_image.bytes.begin() + 0x2302, qpf_image.bytes.begin() + 0x2380, 0);
    std::copy(qpf_name.begin(), qpf_name.end(), qpf_image.bytes.begin() + 0x2302);
    gandon::Emulator qpf_emulator(qpf_image);
    assert(qpf_emulator.ready());
    const auto qpf_result = qpf_emulator.run(30, 0);
    assert(qpf_result.stop == gandon::EmulationStop::Returned);
    assert(qpf_emulator.register_value("ESP", stack_pointer, error) && stack_pointer == 0x700ff000);
    std::uint64_t qpf_value{};
    assert(qpf_emulator.read_memory(0x402400, &qpf_value, sizeof(qpf_value), error));
    assert(qpf_value == 10'000'000);

    auto cdecl_image = image;
    const std::string cdecl_name = "memcpy";
    std::copy(cdecl_name.begin(), cdecl_name.end(), cdecl_image.bytes.begin() + 0x2302);
    std::fill(cdecl_image.bytes.begin() + 0x2302 + cdecl_name.size(),
              cdecl_image.bytes.begin() + 0x2302 + name.size(), 0);
    const std::uint8_t cdecl_code[] = {
        0x68, 0x05, 0x00, 0x00, 0x00,             // push 5
        0x68, 0x00, 0x24, 0x40, 0x00,             // push source
        0x68, 0x00, 0x25, 0x40, 0x00,             // push destination
        0xFF, 0x15, 0x80, 0x21, 0x40, 0x00,       // call dword ptr [IAT]
        0x83, 0xC4, 0x0C,                         // caller removes 3 args
        0xC3
    };
    std::copy(std::begin(cdecl_code), std::end(cdecl_code), cdecl_image.bytes.begin() + 0x1000);
    std::copy(sample.begin(), sample.end(), cdecl_image.bytes.begin() + 0x2400);
    gandon::Emulator cdecl_emulator(cdecl_image);
    assert(cdecl_emulator.ready());
    const auto cdecl_result = cdecl_emulator.run(30, 0);
    assert(cdecl_result.stop == gandon::EmulationStop::Returned);
    assert(cdecl_emulator.register_value("EAX", length, error) && length == 0x402500);
    assert(cdecl_emulator.register_value("ESP", stack_pointer, error) && stack_pointer == 0x700ff000);
    std::array<char, 5> cdecl_copied{};
    assert(cdecl_emulator.read_memory(0x402500, cdecl_copied.data(), cdecl_copied.size(), error));
    assert(std::string(cdecl_copied.begin(), cdecl_copied.end()) == sample);

    auto x86_malloc_image = image;
    const std::string x86_malloc_name = "malloc";
    std::fill(x86_malloc_image.bytes.begin() + 0x2302,
              x86_malloc_image.bytes.begin() + 0x2302 + name.size(), 0);
    std::copy(x86_malloc_name.begin(), x86_malloc_name.end(), x86_malloc_image.bytes.begin() + 0x2302);
    const std::uint8_t x86_malloc_code[] = {
        0x6A, 0x20,                               // push 32
        0xFF, 0x15, 0x80, 0x21, 0x40, 0x00,     // call dword ptr [0x402180]
        0x83, 0xC4, 0x04,                       // caller removes cdecl argument
        0xC3
    };
    std::copy(std::begin(x86_malloc_code), std::end(x86_malloc_code), x86_malloc_image.bytes.begin() + 0x1000);
    gandon::Emulator x86_malloc_emulator(x86_malloc_image);
    assert(x86_malloc_emulator.ready());
    assert(x86_malloc_emulator.run(30, 0).stop == gandon::EmulationStop::Returned);
    std::uint64_t allocated{};
    assert(x86_malloc_emulator.register_value("EAX", allocated, error) && allocated >= 0x72000000u);
    assert(x86_malloc_emulator.register_value("ESP", stack_pointer, error) && stack_pointer == 0x700ff000);
    std::uint8_t heap_byte{};
    assert(x86_malloc_emulator.read_memory(allocated, &heap_byte, sizeof(heap_byte), error));

    auto x86_calloc_image = image;
    const std::string x86_calloc_name = "calloc";
    std::fill(x86_calloc_image.bytes.begin() + 0x2302,
              x86_calloc_image.bytes.begin() + 0x2302 + name.size(), 0);
    std::copy(x86_calloc_name.begin(), x86_calloc_name.end(), x86_calloc_image.bytes.begin() + 0x2302);
    const std::uint8_t x86_calloc_code[] = {
        0x6A, 0x04,                               // push element size
        0x6A, 0x08,                               // push element count
        0xFF, 0x15, 0x80, 0x21, 0x40, 0x00,     // call dword ptr [0x402180]
        0x83, 0xC4, 0x08,                       // caller removes cdecl arguments
        0xC3
    };
    std::copy(std::begin(x86_calloc_code), std::end(x86_calloc_code), x86_calloc_image.bytes.begin() + 0x1000);
    gandon::Emulator x86_calloc_emulator(x86_calloc_image);
    assert(x86_calloc_emulator.ready());
    assert(x86_calloc_emulator.run(30, 0).stop == gandon::EmulationStop::Returned);
    assert(x86_calloc_emulator.register_value("EAX", allocated, error) && allocated >= 0x72000000u);
    std::array<std::uint8_t, 32> x86_zeroed{};
    x86_zeroed.fill(0xFF);
    assert(x86_calloc_emulator.read_memory(allocated, x86_zeroed.data(), x86_zeroed.size(), error));
    assert(std::all_of(x86_zeroed.begin(), x86_zeroed.end(), [](std::uint8_t value) { return value == 0; }));
    assert(x86_calloc_emulator.register_value("ESP", stack_pointer, error) && stack_pointer == 0x700ff000);

    auto x86_heap_image = image;
    const std::string heap_realloc_name = "HeapReAlloc";
    std::fill(x86_heap_image.bytes.begin() + 0x2302,
              x86_heap_image.bytes.begin() + 0x2302 + name.size(), 0);
    std::copy(heap_realloc_name.begin(), heap_realloc_name.end(), x86_heap_image.bytes.begin() + 0x2302);
    const std::uint8_t x86_heap_realloc_code[] = {
        0x6A, 0x20,                               // push 32-byte requested size
        0x6A, 0x00,                               // push nullptr (HeapReAlloc behaves like HeapAlloc)
        0x6A, 0x08,                               // push HEAP_ZERO_MEMORY
        0x68, 0x00, 0x70, 0x00, 0x00,           // push guest process-heap handle
        0xFF, 0x15, 0x80, 0x21, 0x40, 0x00,     // call dword ptr [0x402180]
        0xC3                                        // stdcall stub pops all 16 argument bytes
    };
    std::copy(std::begin(x86_heap_realloc_code), std::end(x86_heap_realloc_code),
              x86_heap_image.bytes.begin() + 0x1000);
    gandon::Emulator x86_heap_emulator(x86_heap_image);
    assert(x86_heap_emulator.ready());
    assert(x86_heap_emulator.run(40, 0).stop == gandon::EmulationStop::Returned);
    assert(x86_heap_emulator.register_value("EAX", allocated, error) && allocated >= 0x72000000u);
    assert(x86_heap_emulator.register_value("ESP", stack_pointer, error) && stack_pointer == 0x700ff000);
    std::array<std::uint8_t, 32> x86_heap_zeroed{};
    x86_heap_zeroed.fill(0xFF);
    assert(x86_heap_emulator.read_memory(allocated, x86_heap_zeroed.data(), x86_heap_zeroed.size(), error));
    assert(std::all_of(x86_heap_zeroed.begin(), x86_heap_zeroed.end(), [](std::uint8_t value) { return value == 0; }));

    auto x86_virtual_image = image;
    const std::string virtual_alloc_name = "VirtualAlloc";
    std::fill(x86_virtual_image.bytes.begin() + 0x2302,
              x86_virtual_image.bytes.begin() + 0x2302 + name.size(), 0);
    std::copy(virtual_alloc_name.begin(), virtual_alloc_name.end(), x86_virtual_image.bytes.begin() + 0x2302);
    const std::uint8_t x86_virtual_alloc_code[] = {
        0x6A, 0x04,                               // push PAGE_READWRITE (fourth argument)
        0x68, 0x00, 0x30, 0x00, 0x00,           // push MEM_RESERVE | MEM_COMMIT
        0x68, 0x00, 0x10, 0x00, 0x00,           // push 0x1000 bytes
        0x6A, 0x00,                               // push nullptr address
        0xFF, 0x15, 0x80, 0x21, 0x40, 0x00,     // call dword ptr [0x402180]
        0xC3                                        // stdcall stub removes 16 bytes
    };
    std::copy(std::begin(x86_virtual_alloc_code), std::end(x86_virtual_alloc_code),
              x86_virtual_image.bytes.begin() + 0x1000);
    gandon::Emulator x86_virtual_emulator(x86_virtual_image);
    assert(x86_virtual_emulator.ready());
    assert(x86_virtual_emulator.run(40, 0).stop == gandon::EmulationStop::Returned);
    assert(x86_virtual_emulator.register_value("EAX", allocated, error) && allocated >= 0x75000000u);
    assert(x86_virtual_emulator.register_value("ESP", stack_pointer, error) && stack_pointer == 0x700ff000);

    auto x86_flush_image = image;
    const std::string flush_name = "FlushInstructionCache";
    std::fill(x86_flush_image.bytes.begin() + 0x2302,
              x86_flush_image.bytes.begin() + 0x2302 + name.size(), 0);
    std::copy(flush_name.begin(), flush_name.end(), x86_flush_image.bytes.begin() + 0x2302);
    const std::uint8_t x86_flush_code[] = {
        0x6A, 0x01,                               // push one byte to flush
        0x68, 0x00, 0x10, 0x40, 0x00,           // push base address 0x401000
        0x6A, 0xFF,                               // push pseudo-handle (HANDLE)-1
        0xFF, 0x15, 0x80, 0x21, 0x40, 0x00,     // call dword ptr [0x402180]
        0xC3                                        // stdcall stub removes 12 bytes
    };
    std::copy(std::begin(x86_flush_code), std::end(x86_flush_code), x86_flush_image.bytes.begin() + 0x1000);
    gandon::Emulator x86_flush_emulator(x86_flush_image);
    assert(x86_flush_emulator.ready());
    assert(x86_flush_emulator.run(40, 0).stop == gandon::EmulationStop::Returned);
    assert(x86_flush_emulator.register_value("EAX", allocated, error) && allocated == 1);
    assert(x86_flush_emulator.register_value("ESP", stack_pointer, error) && stack_pointer == 0x700ff000);
}

void test_cpu_emulator_steps_and_runs_x64_code() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    const std::uint8_t code[] = {
        0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00, // mov rax, [rip + 0xff9] -> 0x402000
        0x48, 0x83, 0xC0, 0x01,                   // add rax, 1
        0xC3                                        // ret to the emulator sentinel
    };
    std::copy(std::begin(code), std::end(code), image.bytes.begin() + 0x1000);
    const std::uint64_t initial_data = 41;
    std::memcpy(image.bytes.data() + 0x2000, &initial_data, sizeof(initial_data));

    gandon::Emulator read_watchpoint_emulator(image);
#if defined(GANDON_HAS_UNICORN)
    assert(read_watchpoint_emulator.ready());
    assert(read_watchpoint_emulator.add_watchpoint(0x402000, sizeof(initial_data), true, false));
    const auto read_watchpoint_result = read_watchpoint_emulator.run(10, 0);
    assert(read_watchpoint_result.stop == gandon::EmulationStop::Watchpoint);
    assert(read_watchpoint_result.error.find("read watchpoint") != std::string::npos);
    assert(!read_watchpoint_emulator.memory_accesses().empty());
    assert(!read_watchpoint_emulator.memory_accesses().front().write);
    assert(!read_watchpoint_emulator.add_watchpoint(UINT64_MAX - 1, 4, true, true));
    gandon::Emulator single_step_watchpoint_emulator(image);
    assert(single_step_watchpoint_emulator.ready());
    assert(single_step_watchpoint_emulator.add_watchpoint(0x402000, sizeof(initial_data), true, false));
    assert(single_step_watchpoint_emulator.step().stop == gandon::EmulationStop::Watchpoint);
    single_step_watchpoint_emulator.clear_watchpoints();
    gandon::Emulator resumed_breakpoint_emulator(image);
    assert(resumed_breakpoint_emulator.ready());
    resumed_breakpoint_emulator.add_breakpoint(image.entry_point);
    resumed_breakpoint_emulator.add_breakpoint(image.entry_point + 7);
    assert(resumed_breakpoint_emulator.run(10, 0).stop == gandon::EmulationStop::Breakpoint);
    const auto resumed_result = resumed_breakpoint_emulator.run(10, 0);
    assert(resumed_result.stop == gandon::EmulationStop::Breakpoint);
    assert(resumed_result.instructions_executed == 1 && resumed_result.program_counter == image.entry_point + 7);
    std::uint64_t resumed_rax{};
    std::string resumed_error;
    assert(resumed_breakpoint_emulator.register_value("RAX", resumed_rax, resumed_error) && resumed_rax == initial_data);
    const auto resumed_second_result = resumed_breakpoint_emulator.run(1, 0);
    assert(resumed_second_result.stop == gandon::EmulationStop::InstructionLimit);
    assert(resumed_second_result.instructions_executed == 1 && resumed_second_result.program_counter == image.entry_point + 11);
    assert(resumed_breakpoint_emulator.register_value("RAX", resumed_rax, resumed_error) && resumed_rax == initial_data + 1);
#endif

    gandon::Emulator emulator(image);
#if defined(GANDON_HAS_UNICORN)
    assert(emulator.ready());
    emulator.set_register_delta_capture(true);
    auto result = emulator.step();
    assert(result.stop == gandon::EmulationStop::Paused);
    assert(result.instructions_executed == 1);
    assert(emulator.memory_accesses().size() == 1);
    assert(emulator.memory_accesses().front().instruction_address == image.entry_point);
    assert(emulator.memory_accesses().front().address == 0x402000);
    assert(emulator.memory_accesses().front().size == sizeof(std::uint64_t));
    assert(!emulator.memory_accesses().front().write);
    assert(emulator.memory_accesses().front().value_captured);
    assert(emulator.memory_accesses().front().value == 41);
    std::uint64_t value{};
    std::string error;
    assert(emulator.register_value("RAX", value, error) && value == 41);
    assert(!emulator.register_deltas().empty());
    assert(emulator.register_deltas().front().trace_index == 0);
    assert((emulator.register_deltas().front().changed_mask & 1u) != 0);
    assert(emulator.register_deltas().front().values[0] == 41);
    result = emulator.run(20);
    assert(result.stop == gandon::EmulationStop::Returned);
    assert(result.instructions_executed == 2);
    assert(emulator.register_value("RAX", value, error) && value == 42);
    assert(std::any_of(emulator.register_deltas().begin(), emulator.register_deltas().end(), [](const auto& delta) {
        return delta.trace_index == 1 && (delta.changed_mask & 1u) != 0 && delta.values[0] == 42;
    }));
    assert(emulator.set_register("RAX", 0x1122334455667788ull, error));
    assert(emulator.set_register("AL", 0xAA, error));
    assert(emulator.register_value("RAX", value, error) && value == 0x11223344556677AAull);
    assert(emulator.register_value("AH", value, error) && value == 0x77);
    assert(emulator.set_register("EAX", 0x12345678, error));
    assert(emulator.register_value("RAX", value, error) && value == 0x12345678);
    assert(emulator.trace().size() == 3);
    assert(emulator.trace().front().address == image.entry_point);
    assert(emulator.trace().front().byte_count == 7 && emulator.trace().front().bytes[0] == 0x48);
    auto memory_write_image = image;
    const std::uint8_t write_data[] = {0x48, 0x89, 0x05, 0xF9, 0x0F, 0x00, 0x00, 0xC3};
    std::copy(std::begin(write_data), std::end(write_data), memory_write_image.bytes.begin() + 0x1000);
    gandon::Emulator memory_write_emulator(memory_write_image);
    assert(memory_write_emulator.ready());
    assert(memory_write_emulator.add_watchpoint(0x402000, sizeof(std::uint64_t), false, true));
    assert(memory_write_emulator.set_register("RAX", 0xAABBCCDDEEFF0011ull, error));
    result = memory_write_emulator.run(10, 0);
    assert(result.stop == gandon::EmulationStop::Watchpoint);
    assert(result.error.find("write watchpoint") != std::string::npos);
    const auto write_event = std::find_if(memory_write_emulator.memory_accesses().begin(),
        memory_write_emulator.memory_accesses().end(), [](const auto& access) {
            return access.write && access.instruction_address == 0x401000;
        });
    assert(write_event != memory_write_emulator.memory_accesses().end());
    assert(write_event->address == 0x402000 && write_event->size == sizeof(std::uint64_t));
    assert(write_event->value_captured);
    assert(write_event->value == 0xAABBCCDDEEFF0011ull);
    auto nested_call_image = image;
    const std::uint8_t nested_call[] = {
        0xE8, 0x01, 0x00, 0x00, 0x00, // call +1 -> 0x401006
        0xC3,                         // caller return
        0x48, 0xC7, 0xC0, 0x2A, 0, 0, 0, // mov rax, 42
        0xC3                          // callee return
    };
    std::copy(std::begin(nested_call), std::end(nested_call), nested_call_image.bytes.begin() + 0x1000);
    gandon::Emulator nested_call_emulator(nested_call_image);
    assert(nested_call_emulator.ready());
    nested_call_emulator.add_breakpoint(0x401006);
    result = nested_call_emulator.run(10, 0);
    assert(result.stop == gandon::EmulationStop::Breakpoint);
    assert(nested_call_emulator.call_stack().size() == 1);
    assert(nested_call_emulator.call_stack().front() == 0x401005);
    nested_call_emulator.remove_breakpoint(0x401006);
    result = nested_call_emulator.run(10, 0);
    assert(result.stop == gandon::EmulationStop::Returned);
    assert(nested_call_emulator.call_stack().empty());
    auto recursive_call_image = image;
    const std::uint8_t recursive_call[] = {0xE8, 0xFB, 0xFF, 0xFF, 0xFF}; // call entry
    std::copy(std::begin(recursive_call), std::end(recursive_call), recursive_call_image.bytes.begin() + 0x1000);
    gandon::Emulator recursive_call_emulator(recursive_call_image);
    assert(recursive_call_emulator.ready());
    result = recursive_call_emulator.run(5000, 0);
    assert(result.stop == gandon::EmulationStop::InstructionLimit);
    assert(recursive_call_emulator.call_stack().size() == 4096);
    assert(recursive_call_emulator.call_stack_truncated());
    const std::uint64_t replacement = 0x1122334455667788ull;
    assert(emulator.write_memory(0x402100, &replacement, sizeof(replacement), error));
    std::uint64_t loaded{};
    assert(emulator.read_memory(0x402100, &loaded, sizeof(loaded), error) && loaded == replacement);
    assert(!emulator.register_value("NOT_A_REGISTER", value, error));
    assert(!emulator.trace().empty() && !emulator.register_deltas().empty() && !emulator.memory_accesses().empty());
    emulator.clear_trace();
    assert(emulator.trace().empty() && emulator.trace().capacity() == 0 && !emulator.trace_truncated());
    assert(emulator.register_deltas().empty() && emulator.register_deltas().capacity() == 0);
    assert(emulator.memory_accesses().empty() && emulator.memory_accesses().capacity() == 0);

    const std::uint8_t endless_jump[] = {0xEB, 0xFE};
    assert(emulator.write_memory(image.entry_point, endless_jump, sizeof(endless_jump), error));
    assert(emulator.set_register("RIP", image.entry_point, error));
    assert(emulator.register_value("RIP", value, error));
    assert(value == image.entry_point);
    result = emulator.run(2, 0);
    assert(result.stop == gandon::EmulationStop::InstructionLimit);
    assert(result.instructions_executed == 2);
    assert(result.program_counter == image.entry_point);

    auto external_jump_image = image;
    const auto displacement = static_cast<std::uint32_t>(0x500000 - (image.entry_point + 5));
    const std::uint8_t external_jump[] = {
        0xE9, static_cast<std::uint8_t>(displacement), static_cast<std::uint8_t>(displacement >> 8),
        static_cast<std::uint8_t>(displacement >> 16), static_cast<std::uint8_t>(displacement >> 24)
    };
    std::copy(std::begin(external_jump), std::end(external_jump), external_jump_image.bytes.begin() + 0x1000);
    gandon::Emulator external_jump_emulator(external_jump_image);
    assert(external_jump_emulator.ready());
    result = external_jump_emulator.run(10, 0);
    assert(result.stop == gandon::EmulationStop::MemoryFault);
    assert(result.program_counter == 0x500000);
    assert(result.error.find("instruction fetch") != std::string::npos);
    assert(result.error.find("500000") != std::string::npos);

    auto breakpoint_image = image;
    const std::uint8_t self_loop[] = {0xEB, 0xFE};
    std::copy(std::begin(self_loop), std::end(self_loop), breakpoint_image.bytes.begin() + 0x1000);
    gandon::Emulator breakpoint_emulator(breakpoint_image);
    assert(breakpoint_emulator.ready());
    breakpoint_emulator.add_breakpoint(breakpoint_image.entry_point);
    result = breakpoint_emulator.run(10, 0);
    assert(result.stop == gandon::EmulationStop::Breakpoint);
    assert(result.instructions_executed == 0 && result.program_counter == breakpoint_image.entry_point);
    result = breakpoint_emulator.step();
    assert(result.stop == gandon::EmulationStop::Paused && result.instructions_executed == 1);
    result = breakpoint_emulator.run(10, 0);
    assert(result.stop == gandon::EmulationStop::Breakpoint && result.instructions_executed == 0);
    breakpoint_emulator.remove_breakpoint(breakpoint_image.entry_point);
    assert(!breakpoint_emulator.has_breakpoint(breakpoint_image.entry_point));

    gandon::Emulator midrun_breakpoint_emulator(image);
    assert(midrun_breakpoint_emulator.ready());
    midrun_breakpoint_emulator.add_breakpoint(image.entry_point + 7); // After the first 7-byte MOV.
    result = midrun_breakpoint_emulator.run(10, 0);
    assert(result.stop == gandon::EmulationStop::Breakpoint);
    assert(result.instructions_executed == 1 && result.program_counter == image.entry_point + 7);

    auto protected_image = image;
    const std::uint8_t write_read_only[] = {0xC6, 0x05, 0xF9, 0x0F, 0x00, 0x00, 0x01, 0xC3};
    std::copy(std::begin(write_read_only), std::end(write_read_only), protected_image.bytes.begin() + 0x1000);
    protected_image.sections[1].characteristics = 0x40000040u; // Read-only initialized data.
    gandon::Emulator protected_emulator(protected_image);
    assert(protected_emulator.ready());
    result = protected_emulator.run(10, 0);
    assert(result.stop == gandon::EmulationStop::MemoryFault);
    assert(result.error.find("write") != std::string::npos);

    auto runtime_code_image = image;
    runtime_code_image.sections[0].characteristics |= 0x80000000u;
    gandon::Emulator runtime_code_emulator(runtime_code_image);
    assert(runtime_code_emulator.ready());
    const std::uint8_t runtime_nop = 0x90;
    assert(runtime_code_emulator.write_memory(image.entry_point, &runtime_nop, sizeof(runtime_nop), error));
    result = runtime_code_emulator.step();
    assert(result.stop == gandon::EmulationStop::Paused && result.instructions_executed == 1);
    assert(runtime_code_emulator.trace().size() == 1);
    assert(runtime_code_emulator.trace().front().byte_count == 1 &&
           runtime_code_emulator.trace().front().bytes[0] == runtime_nop);
    const auto runtime_decoded = gandon::decode_x86_instruction(
        runtime_code_emulator.trace().front().bytes.data(),
        runtime_code_emulator.trace().front().byte_count,
        runtime_code_emulator.trace().front().address, true);
    assert(runtime_decoded && runtime_decoded->mnemonic == "nop");

    auto unsupported_image = image;
    unsupported_image.architecture = gandon::MachineArchitecture::Other;
    gandon::Emulator unsupported(unsupported_image);
    assert(!unsupported.ready());
    assert(unsupported.error().find("architecture") != std::string::npos);
#else
    assert(!emulator.ready());
    assert(emulator.error().find("Unicorn") != std::string::npos);
#endif
}

void test_x86_absolute_memory_operand_adds_data_xref() {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::PE;
    image.architecture = gandon::MachineArchitecture::X86;
    image.is_64_bit = false;
    image.image_base = 0x400000;
    image.entry_point = 0x401000;
    image.bytes.resize(0x3000);
    image.sections.push_back({".text", 0x1000, 0x1000, 0x1000, 0x1000, 0x60000020});
    image.sections.push_back({".data", 0x2000, 0x1000, 0x2000, 0x1000, 0xC0000040});
    const std::uint8_t code[] = {
        0xA1, 0x00, 0x20, 0x40, 0x00,       // mov eax, [0x402000]
        0x68, 0x00, 0x20, 0x40, 0x00,       // push 0x402000
        0xC3                                  // ret
    };
    std::copy(std::begin(code), std::end(code), image.bytes.begin() + 0x1000);

    gandon::AnalysisDatabase analyzed(std::move(image));
    analyzed.discover_basic_xrefs();
    assert(std::any_of(analyzed.xrefs().begin(), analyzed.xrefs().end(),
        [](const gandon::Xref& xref) {
            return xref.from == 0x401000 && xref.to == 0x402000 && xref.kind == "data";
        }));
    assert(std::any_of(analyzed.xrefs().begin(), analyzed.xrefs().end(),
        [](const gandon::Xref& xref) {
            return xref.from == 0x401005 && xref.to == 0x402000 && xref.kind == "offset";
        }));
}
}

int main() {
    test_low_level_il_emulator_arithmetic_memory_and_return();
    test_low_level_il_emulator_branches_and_instruction_budget();
    test_low_level_il_emulator_signed_compare_uses_operand_width();
    test_low_level_il_emulator_rejects_unmapped_loads_and_divide_by_zero();
    test_x64_il_lifter_arithmetic_and_extended_register_aliases();
    test_x64_il_lifter_resolves_conditional_branches();
    test_x64_il_lifter_arithmetic_flags_and_conditional_branches();
    test_x64_il_lifter_memory_operands_and_rip_relative_lea();
    test_x64_il_lifter_stack_push_pop_and_leave();
    test_x64_il_lifter_fails_closed_for_unsupported_instructions();
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.image_base = 0x1000;
    image.bytes.resize(0x1000);
    image.sections.push_back({".text", 0, 0x1000, 0, 0x1000, 0x20000000});

    gandon::AnalysisDatabase database(std::move(image));
    database.add_function({0x1100, "start", {}, {0x1200, 0x1300}, 0x1150});
    database.add_function({0x1200, "middle", {}, {0x1300}});
    database.add_function({0x1300, "target", {}, {}});
    database.add_function({0x1400, "unreachable", {}, {}});

    assert((database.call_path(0x1100, 0x1300) == std::vector<std::uint64_t>{0x1100, 0x1300}));
    assert((database.call_path(0x1100, 0x1300, 1) == std::vector<std::uint64_t>{0x1100, 0x1300}));
    assert(database.call_path(0x1100, 0x1300, 0).empty());
    assert(database.call_path(0x1100, 0x1400).empty());
    assert((database.call_path(0x1200, 0x1200) == std::vector<std::uint64_t>{0x1200}));
    assert(database.call_path(0x2000, 0x1300).empty());
    assert(database.function_at(0x114f)->get().start == 0x1100);
    assert(!database.function_at(0x1160));
    assert(database.function_at(0x1200)->get().start == 0x1200);
    test_elf_symbol_loading();
    test_elf_dynamic_jump_slot_import_loading();
    test_failed_binary_reload_clears_stale_metadata();
    test_large_sparse_elf_load_uses_exact_file_extent();
    test_wildcard_signature_search_keeps_overlaps_and_caps_results();
    test_exact_byte_search_retains_unlimited_legacy_results();
    test_xref_address_index_tracks_incoming_outgoing_and_updates();
    test_xref_budget_is_bounded_and_discovery_releases_old_storage();
    test_discovery_releases_function_and_xref_cache_memory();
    test_function_discovery_exceeds_legacy_limit();
    test_pe_xrefs_use_decoded_instruction_boundaries();
    test_pe_unwind_metadata_suppresses_false_prologue_functions();
    test_pe_export_ordinal_is_bounded_by_function_count();
    test_pe_function_decode_walks_branches_and_stops_at_ret();
    test_pe_call_on_alternate_cfg_branch_discovers_callee();
    test_arm64_decoder_and_direct_control_flow_xrefs();
    test_arm64_adrp_add_load_sequence_resolves_data_xref();
    test_arm64_emulation_executes_and_returns();
    test_x64_emulation_step_over_calls_and_preserves_user_breakpoints();
    test_x64_emulation_step_over_indirect_call();
    test_x86_emulation_step_over_indirect_call();
    test_x64_emulation_step_over_rip_relative_indirect_call();
    test_x86_emulation_step_over_direct_call();
    test_arm64_emulation_step_over_bl();
    test_arm64_emulation_step_out_uses_tracked_return_address();
    test_arm64_emulation_tracks_calls_breakpoints_and_register_deltas();
    test_pe_arm64_emulation_resolves_and_safely_stubs_imports();
    test_elf_arm64_emulation_resolves_got_import_stubs();
    test_elf_x64_emulation_uses_sysv_import_abi();
    test_elf_x64_emulation_models_strchr_family();
    test_elf_x64_emulation_models_memchr();
    test_elf_x64_emulation_models_strstr();
    test_elf_x64_emulation_models_strspn_family();
    test_elf_x64_emulation_handles_virtual_linux_io_and_exit();
    test_elf_arm64_emulation_handles_virtual_linux_io_and_exit();
    test_elf_x86_emulation_handles_int80_mmap2_write_and_exit();
    test_elf_x86_emulation_returns_efault_for_invalid_write_pointer();
    test_elf_x64_emulation_handles_readv_and_writev();
    test_elf_x86_emulation_models_getrandom_and_brk();
    test_elf_x64_emulation_maps_anonymous_guest_memory();
    test_elf_x64_emulation_grows_and_shrinks_brk();
    test_elf_x64_emulation_enforces_mprotect_permissions();
    test_elf_x64_emulation_models_arch_prctl_fs_base();
    test_elf_virtual_getrandom_is_deterministic_on_x64_and_arm64();
    test_elf_virtual_process_ids_and_clock_on_x64_and_arm64();
    test_elf_x64_emulation_models_strcat();
    test_arm64_emulation_memory_access_and_watchpoints();
    test_late_discovered_function_trims_crossing_cached_instruction();
    test_elf_xrefs_use_decoded_boundaries_and_transitive_cfg_calls();
    test_elf_rip_relative_data_reference_is_indexed();
    test_long_function_keeps_late_calls_with_bounded_instruction_budget();
    test_loop_family_branches_produce_cfg_xrefs();
    test_invalid_and_trap_instructions_terminate_cfg_blocks();
    test_x86_absolute_memory_operand_adds_data_xref();
    test_pe_emulation_safely_stubs_imports();
    test_pe_emulator_uses_isolated_virtual_filesystem();
    test_pe32_import_emulation_uses_stdcall_cleanup();
    test_cpu_emulator_steps_and_runs_x64_code();
    return 0;
}
