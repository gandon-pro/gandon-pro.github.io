#include "gandon/core.hpp"
#include "gandon/decompiler.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "decompiler_samples.inc"

namespace {
gandon::DecompileResult decompile_bytes(const std::uint8_t* bytes, std::size_t size, std::uint64_t address,
                                        const std::string& name) {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::X64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = address;
    const std::uint64_t rva = address - image.image_base;
    image.bytes.assign(rva + size + 0x100, 0);
    std::memcpy(image.bytes.data() + rva, bytes, size);
    image.sections.push_back({".text", static_cast<std::uint64_t>(rva), static_cast<std::uint32_t>(size + 0x100),
                              static_cast<std::uint32_t>(rva), static_cast<std::uint32_t>(size + 0x100), 0x60000020});
    const auto instructions = gandon::decode_instructions(image, address, 512);
    gandon::DecompilerOptions options;
    options.windows_abi = false;
    return gandon::decompile_function(image, name, address, instructions, options);
}

gandon::DecompileResult decompile_arm(const std::uint8_t* bytes, std::size_t size, std::uint64_t address,
                                      const std::string& name) {
    gandon::BinaryImage image;
    image.format = gandon::BinaryFormat::ELF;
    image.architecture = gandon::MachineArchitecture::ARM64;
    image.is_64_bit = true;
    image.image_base = 0x400000;
    image.entry_point = address;
    const std::uint64_t rva = address - image.image_base;
    image.bytes.assign(rva + size + 0x100, 0);
    std::memcpy(image.bytes.data() + rva, bytes, size);
    image.sections.push_back({".text", static_cast<std::uint64_t>(rva), static_cast<std::uint32_t>(size + 0x100),
                              static_cast<std::uint32_t>(rva), static_cast<std::uint32_t>(size + 0x100), 0x60000020});
    const auto instructions = gandon::decode_instructions(image, address, 512);
    gandon::DecompilerOptions options;
    options.windows_abi = false;
    return gandon::decompile_function(image, name, address, instructions, options);
}

bool contains(const std::string& text, const char* needle) { return text.find(needle) != std::string::npos; }

void fail(const char* test, const std::string& text) {
    std::cerr << "FAILED: " << test << "\n" << text << "\n";
    std::abort();
}
#define CHECK(test, cond, text) do { if (!(cond)) fail(test, text); } while (0)

void test_parameter_arithmetic_has_no_stack_noise() {
    const auto r = decompile_bytes(k_add3_bytes, sizeof k_add3_bytes, k_add3_address, "add3");
    CHECK("add3 ok", r.ok, r.error);
    CHECK("add3 params", contains(r.text, "a1") && contains(r.text, "a2") && contains(r.text, "a3"), r.text);
    CHECK("add3 return", contains(r.text, "return a1 + a2 * a3;") || contains(r.text, "return (uint32_t)(a1 + a2 * a3);") ||
                          contains(r.text, "return a1 + a3 * a2;"), r.text);
    CHECK("add3 no goto", !contains(r.text, "goto"), r.text);
    CHECK("add3 no locals", !contains(r.text, "var_"), r.text);
}

void test_if_return_becomes_early_return() {
    const auto r = decompile_bytes(k_max2_bytes, sizeof k_max2_bytes, k_max2_address, "max2");
    CHECK("max2 ok", r.ok, r.error);
    CHECK("max2 if", contains(r.text, "if ("), r.text);
    CHECK("max2 returns", contains(r.text, "return a1;") && contains(r.text, "return a2;"), r.text);
    CHECK("max2 no goto", r.goto_count == 0, r.text);
    CHECK("max2 no temp register", !contains(r.text, "rax"), r.text);
}

void test_for_loop_becomes_while() {
    const auto r = decompile_bytes(k_sum_to_bytes, sizeof k_sum_to_bytes, k_sum_to_address, "sum_to");
    CHECK("sum_to ok", r.ok, r.error);
    CHECK("sum_to while", contains(r.text, "while ("), r.text);
    CHECK("sum_to compound", contains(r.text, "+="), r.text);
    CHECK("sum_to no goto", r.goto_count == 0 && !contains(r.text, "while ( 1 )"), r.text);
}

void test_nested_loop_and_branch_stays_structured() {
    const auto r = decompile_bytes(k_collatz_bytes, sizeof k_collatz_bytes, k_collatz_address, "collatz");
    CHECK("collatz ok", r.ok, r.error);
    CHECK("collatz while", contains(r.text, "while ( a1 != 1 )"), r.text);
    CHECK("collatz else", contains(r.text, "else"), r.text);
    CHECK("collatz algebra", contains(r.text, "a1 * 3 + 1"), r.text);
    CHECK("collatz no goto", r.goto_count == 0, r.text);
}

void test_else_if_chain_flattens_to_early_returns() {
    const auto r = decompile_bytes(k_classify_bytes, sizeof k_classify_bytes, k_classify_address, "classify");
    CHECK("classify ok", r.ok, r.error);
    CHECK("classify returns", contains(r.text, "return -1;") && contains(r.text, "return 0;") &&
                              contains(r.text, "return 1;") && contains(r.text, "return 2;"), r.text);
    CHECK("classify no goto", r.goto_count == 0 && !contains(r.text, "rax"), r.text);
}

void test_pointer_loop() {
    const auto r = decompile_bytes(k_strlen_like_bytes, sizeof k_strlen_like_bytes, k_strlen_like_address, "strlen_like");
    CHECK("strlen_like ok", r.ok, r.error);
    CHECK("strlen_like loop", contains(r.text, "while ("), r.text);
    CHECK("strlen_like byte load", contains(r.text, "uint8_t"), r.text);
}

void test_arm_float_arithmetic() {
    // scvtf d0, w0 ; scvtf d1, w1 ; fadd d0, d0, d1 ; ret
    static const std::uint8_t k_arm_fadd[] = {
        0x00, 0x00, 0x62, 0x1E,
        0x21, 0x00, 0x62, 0x1E,
        0x00, 0x28, 0x61, 0x1E,
        0xC0, 0x03, 0x5F, 0xD6,
    };
    const auto r = decompile_arm(k_arm_fadd, sizeof k_arm_fadd, 0x400000, "fadder");
    CHECK("arm fadd ok", r.ok, r.error);
    CHECK("arm fadd structured (no opaque __fadd)", !contains(r.text, "__fadd"), r.text);
    CHECK("arm fadd no opaque scvtf", !contains(r.text, "__scvtf"), r.text);
    CHECK("arm fadd addition present", contains(r.text, "+"), r.text);
}

void test_x86_packed_simd_uses_intrinsics() {
    // xorps xmm0,xmm0 ; addps xmm0,xmm1 ; mulps xmm0,xmm2 ; movups [rdi],xmm0 ; ret
    static const std::uint8_t k_vec[] = {
        0x0F, 0x57, 0xC0,
        0x0F, 0x58, 0xC1,
        0x0F, 0x59, 0xC2,
        0x0F, 0x11, 0x07,
        0xC3,
    };
    const auto r = decompile_bytes(k_vec, sizeof k_vec, 0x400000, "vec");
    CHECK("vec ok", r.ok, r.error);
    CHECK("vec add intrinsic", contains(r.text, "_mm_add_ps"), r.text);
    CHECK("vec mul intrinsic", contains(r.text, "_mm_mul_ps"), r.text);
    CHECK("vec no opaque addps", !contains(r.text, "__addps"), r.text);
    CHECK("vec no opaque mulps", !contains(r.text, "__mulps"), r.text);
    CHECK("vec no opaque xorps", !contains(r.text, "__xorps"), r.text);
}

void test_unsupported_architecture_is_rejected() {
    gandon::BinaryImage image;
    image.architecture = gandon::MachineArchitecture::ARM64;
    std::vector<gandon::Instruction> none;
    const auto r = gandon::decompile_function(image, "f", 0x1000, none);
    assert(!r.ok && !r.error.empty());
}
} // namespace

int main() {
    test_parameter_arithmetic_has_no_stack_noise();
    test_if_return_becomes_early_return();
    test_for_loop_becomes_while();
    test_nested_loop_and_branch_stays_structured();
    test_else_if_chain_flattens_to_early_returns();
    test_pointer_loop();
    test_arm_float_arithmetic();
    test_x86_packed_simd_uses_intrinsics();
    test_unsupported_architecture_is_rejected();
    std::puts("decompiler tests passed");
    return 0;
}
