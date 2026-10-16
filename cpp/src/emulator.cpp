#include "gandon/emulator.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <iterator>
#include <limits>
#include <sstream>
#include <unordered_set>
#include <utility>
#include <vector>

#if defined(GANDON_HAS_UNICORN)
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include <unicorn/arm64.h>

#include <map>
#endif

namespace gandon {

#if defined(GANDON_HAS_UNICORN)
namespace {
std::uint16_t modeled_windows_stdcall_bytes(std::string name);
}
#endif

struct Emulator::Impl {
    static constexpr std::size_t max_trace_instructions = 1'000'000;
    static constexpr std::size_t max_memory_accesses = 200'000;
    static constexpr std::size_t max_call_stack_depth = 4096;
    static constexpr std::size_t max_watchpoints = 256;
    static constexpr std::size_t max_register_deltas = 200'000;
    struct Watchpoint { std::uint64_t address{}, size{}; bool on_read{}, on_write{}; };
    std::string error;
    std::vector<EmulationTraceEntry> trace;
    std::vector<EmulationMemoryAccess> memory_accesses;
    std::vector<EmulationRegisterDelta> register_deltas;
    std::vector<std::uint64_t> call_stack;
    std::size_t untracked_call_depth{0};
    std::size_t instruction_count{0};
    std::uint64_t stop_address{0};
    std::uint64_t breakpoint_address{0};
    std::uint64_t breakpoint_skip_once{0};
    bool returned{false};
    bool guest_exited{false};
    bool syscall_yielded{false};
    int guest_exit_code{0};
    std::uint64_t guest_exit_pc{0};
    std::string guest_stdin;
    std::size_t guest_stdin_offset{0};
    std::string guest_stdout;
    std::string guest_stderr;
    // Repeatable guest-only byte stream for emulation; deliberately not cryptographic.
    std::uint64_t guest_random_state{0x9E3779B97F4A7C15ull};
    std::uint64_t guest_clock_ticks{0};
    std::uint32_t guest_last_error{0};
    bool trace_was_truncated{false};
    bool memory_accesses_were_truncated{false};
    bool call_stack_was_truncated{false};
    bool register_delta_capture{false};
    bool register_deltas_were_truncated{false};
    bool pending_register_snapshot{false};
    std::size_t pending_trace_index{0};
    std::array<std::uint64_t, 34> pending_register_values{};
    std::uint64_t fault_address{0};
    int fault_access{0};
    int fault_size{0};
    bool memory_fault{false};
    bool breakpoint_hit{false};
    bool single_step_active{false};
    std::unordered_set<std::uint64_t> breakpoints;
    std::vector<Watchpoint> watchpoints;
    bool watchpoint_hit{false};
    bool watchpoint_write{false};
    std::uint64_t watchpoint_address{0};
#if defined(GANDON_HAS_UNICORN)
    uc_engine* engine{nullptr};
    uc_hook code_hook{};
    uc_hook memory_access_hook{};
    bool is_64_bit{false};
    bool is_arm64{false};
    bool is_elf{false};
    std::map<std::uint64_t, std::pair<std::string, std::uint16_t>> import_stubs;
    struct GuestModule {
        std::uint64_t handle{};
        std::uint32_t references{};
        bool windows_api{};
        bool c_runtime{};
    };
    std::map<std::string, GuestModule> guest_modules;
    std::map<std::uint64_t, std::string> guest_module_names;
    std::map<std::string, std::uint64_t> dynamic_import_addresses;
    struct GuestFileHandle {
        std::string path;
        std::uint64_t position{};
        bool readable{};
        bool writable{};
        bool append{};
    };
    std::map<std::string, std::vector<std::uint8_t>> guest_files;
    std::map<std::uint64_t, GuestFileHandle> guest_file_handles;
    std::uint64_t next_guest_file_handle{0};
    std::uint64_t guest_file_bytes{0};
    std::uint64_t next_guest_module_handle{0};
    std::uint64_t main_module_handle{0};
    std::uint64_t dynamic_stub_base{0};
    std::uint64_t dynamic_stub_capacity{0};
    std::uint64_t dynamic_stub_cursor{0};
    std::map<std::uint64_t, std::uint32_t> page_permissions;
    std::map<std::uint64_t, std::uint64_t> heap_allocations;
    std::map<std::uint64_t, std::uint64_t> heap_allocation_capacities;
    std::map<std::uint64_t, std::uint64_t> heap_free_blocks;
    std::map<std::uint64_t, std::uint64_t> windows_virtual_allocations;
    std::unordered_set<std::uint64_t> windows_committed_pages;
    std::unordered_set<std::uint64_t> image_pages;
    std::uint64_t windows_virtual_base{0};
    std::uint64_t windows_virtual_reserved_bytes{0};
    std::uint64_t windows_virtual_committed_bytes{0};
    std::map<std::uint64_t, std::uint32_t> windows_virtual_allocation_protections;
    std::map<std::uint64_t, std::uint32_t> initial_page_permissions;
    struct GuestMapping { std::uint64_t size{}; std::uint32_t permissions{}; };
    struct WindowsPageAttributes {
        std::uint64_t allocation_base{};
        std::uint32_t allocation_protect{};
        std::uint32_t state{};
        std::uint32_t protect{};
        std::uint32_t type{};
        bool operator==(const WindowsPageAttributes& other) const {
            return allocation_base == other.allocation_base && allocation_protect == other.allocation_protect &&
                state == other.state && protect == other.protect && type == other.type;
        }
    };
    std::map<std::uint64_t, GuestMapping> guest_mappings;
    std::uint64_t mmap_base{0x730000000000ull};
    std::uint64_t mmap_cursor{0x730000000000ull};
    std::uint64_t mmap_committed{0};
    std::uint64_t brk_base{0x740000000000ull};
    std::uint64_t brk_current{0x740000000000ull};
    std::uint64_t brk_committed{0};
    std::uint64_t stack_base{0};
    std::uint64_t stack_size{0};
    std::uint64_t heap_base{0};
    std::uint64_t heap_cursor{0};
    std::uint64_t heap_committed{0};

    ~Impl() { if (engine) uc_close(engine); }

    static int tracked_register_id(bool is64, std::size_t index) {
        static constexpr int x64_ids[]{UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
            UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP, UC_X86_REG_R8, UC_X86_REG_R9,
            UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
            UC_X86_REG_EFLAGS};
        static constexpr int x86_ids[]{UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
            UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
            UC_X86_REG_INVALID, UC_X86_REG_INVALID, UC_X86_REG_INVALID, UC_X86_REG_INVALID,
            UC_X86_REG_INVALID, UC_X86_REG_INVALID, UC_X86_REG_INVALID, UC_X86_REG_INVALID, UC_X86_REG_EFLAGS};
        return index < 17 ? (is64 ? x64_ids[index] : x86_ids[index]) : UC_X86_REG_INVALID;
    }

    static bool read_tracked_registers(uc_engine* engine, bool is64, bool arm64, std::array<std::uint64_t, 34>& values) {
        values.fill(0);
        for (std::size_t index = 0; index < values.size(); ++index) {
            const auto id = arm64 ? (index < 31 ? UC_ARM64_REG_X0 + static_cast<int>(index) :
                index == 31 ? UC_ARM64_REG_SP : index == 32 ? UC_ARM64_REG_PC : UC_ARM64_REG_NZCV) :
                tracked_register_id(is64, index);
            if (!arm64 && id == UC_X86_REG_INVALID) continue;
            if (uc_reg_read(engine, id, &values[index]) != UC_ERR_OK) return false;
            if (!arm64 && (!is64 || index == 16)) values[index] &= 0xffffffffu;
        }
        return true;
    }

    static void finalize_register_snapshot(uc_engine* engine, Impl& self) {
        if (!self.pending_register_snapshot) return;
        self.pending_register_snapshot = false;
        if (!self.register_delta_capture) return;
        std::array<std::uint64_t, 34> current{};
        if (!read_tracked_registers(engine, self.is_64_bit, self.is_arm64, current)) return;
        EmulationRegisterDelta delta;
        delta.trace_index = self.pending_trace_index;
        for (std::size_t index = 0; index < current.size(); ++index) {
            if (current[index] == self.pending_register_values[index]) continue;
            delta.changed_mask |= (std::uint64_t{1} << index);
            if (delta.value_count < delta.values.size())
                delta.values[delta.value_count++] = current[index];
            else
                delta.values_truncated = true;
        }
        if (!delta.changed_mask) return;
        if (self.register_deltas.size() >= max_register_deltas) {
            self.register_deltas_were_truncated = true;
            return;
        }
        self.register_deltas.push_back(delta);
    }

    static void on_code(uc_engine* engine, std::uint64_t address, std::uint32_t size, void* data) {
        auto& self = *static_cast<Impl*>(data);
        if (address == self.stop_address) {
            finalize_register_snapshot(engine, self);
            self.returned = true;
            uc_emu_stop(engine);
            return;
        }
        if (!self.single_step_active) {
            const bool skip_current_breakpoint = self.breakpoint_skip_once == address;
            self.breakpoint_skip_once = 0;
            if (!skip_current_breakpoint && self.breakpoints.contains(address)) {
                finalize_register_snapshot(engine, self);
                self.breakpoint_hit = true;
                self.breakpoint_address = address;
                uc_emu_stop(engine);
                return;
            }
        }
        const auto imported = self.import_stubs.find(address);
        if (imported == self.import_stubs.end()) finalize_register_snapshot(engine, self);
        bool import_modeled = false;
        if (imported != self.import_stubs.end()) {
            import_modeled = emulate_safe_import(engine, imported->second.first, imported->second.second, self);
            if (self.is_arm64 && !import_modeled) {
                std::uint64_t zero = 0;
                if (uc_reg_write(engine, UC_ARM64_REG_X0, &zero) != UC_ERR_OK) self.memory_fault = true;
            }
            if (self.memory_fault) {
                finalize_register_snapshot(engine, self);
                uc_emu_stop(engine);
                return;
            }
        }
        if (imported != self.import_stubs.end()) finalize_register_snapshot(engine, self);
        ++self.instruction_count;
        EmulationTraceEntry item;
        item.address = address;
        item.size = static_cast<std::uint8_t>((std::min<std::uint32_t>)(size, item.bytes.size()));
        if (item.size && uc_mem_read(engine, address, item.bytes.data(), item.size) == UC_ERR_OK)
            item.byte_count = item.size;
        if (imported != self.import_stubs.end())
            item.annotation = "import " + imported->second.first +
                (import_modeled ? " [modeled]" : " [stubbed]");
        if (self.is_elf && !self.is_arm64 && size == 2) {
            std::uint8_t opcode[2]{};
            if (uc_mem_read(engine, address, opcode, sizeof(opcode)) == UC_ERR_OK) {
                std::uint64_t syscall_number{};
                if (!self.is_64_bit && opcode[0] == 0xcd && opcode[1] == 0x80) {
                    std::uint32_t number32{};
                    (void)uc_reg_read(engine, UC_X86_REG_EAX, &number32);
                    syscall_number = number32;
                    const char* syscall_name = syscall_number == 1 ? "exit" : syscall_number == 3 ? "read" :
                        syscall_number == 4 ? "write" : syscall_number == 20 ? "getpid" :
                        syscall_number == 45 ? "brk" : syscall_number == 91 ? "munmap" :
                        syscall_number == 125 ? "mprotect" : syscall_number == 192 ? "mmap2" :
                        syscall_number == 224 ? "gettid" : syscall_number == 252 ? "exit_group" :
                        syscall_number == 78 ? "gettimeofday" : syscall_number == 265 ? "clock_gettime" :
                        syscall_number == 258 ? "set_tid_address" : syscall_number == 311 ? "set_robust_list" :
                        syscall_number == 355 ? "getrandom" : syscall_number == 145 ? "readv" :
                        syscall_number == 146 ? "writev" : nullptr;
                    item.annotation = "Linux x86 syscall " +
                        (syscall_name ? std::string(syscall_name) : "#" + std::to_string(syscall_number));
                    emulate_linux_x86_syscall(engine, address, self);
                    self.syscall_yielded = true;
                } else if (self.is_64_bit && opcode[0] == 0x0f && opcode[1] == 0x05) {
                    (void)uc_reg_read(engine, UC_X86_REG_RAX, &syscall_number);
                    const char* syscall_name = syscall_number == 0 ? "read" : syscall_number == 1 ? "write" :
                        syscall_number == 9 ? "mmap" : syscall_number == 10 ? "mprotect" :
                        syscall_number == 11 ? "munmap" : syscall_number == 12 ? "brk" :
                        syscall_number == 39 ? "getpid" : syscall_number == 158 ? "arch_prctl" : syscall_number == 186 ? "gettid" :
                        syscall_number == 218 ? "set_tid_address" : syscall_number == 228 ? "clock_gettime" :
                        syscall_number == 273 ? "set_robust_list" : syscall_number == 318 ? "getrandom" :
                        syscall_number == 19 ? "readv" : syscall_number == 20 ? "writev" :
                        syscall_number == 60 ? "exit" : syscall_number == 231 ? "exit_group" : nullptr;
                    item.annotation = "Linux x86-64 syscall " +
                        (syscall_name ? std::string(syscall_name) : "#" + std::to_string(syscall_number));
                    emulate_linux_x64_syscall(engine, address, self);
                    self.syscall_yielded = true;
                }
            }
        }
        if (self.is_elf && self.is_arm64 && item.byte_count == 4) {
            const auto word = static_cast<std::uint32_t>(item.bytes[0]) |
                (static_cast<std::uint32_t>(item.bytes[1]) << 8) |
                (static_cast<std::uint32_t>(item.bytes[2]) << 16) |
                (static_cast<std::uint32_t>(item.bytes[3]) << 24);
            if (word == 0xD4000001u) { // Linux AArch64 svc #0
                std::uint64_t syscall_number{};
                (void)uc_reg_read(engine, UC_ARM64_REG_X8, &syscall_number);
                const char* syscall_name = syscall_number == 63 ? "read" : syscall_number == 64 ? "write" :
                    syscall_number == 214 ? "brk" : syscall_number == 215 ? "munmap" :
                    syscall_number == 222 ? "mmap" : syscall_number == 226 ? "mprotect" :
                    syscall_number == 96 ? "set_tid_address" : syscall_number == 99 ? "set_robust_list" :
                    syscall_number == 113 ? "clock_gettime" : syscall_number == 172 ? "getpid" :
                    syscall_number == 169 ? "gettimeofday" : syscall_number == 178 ? "gettid" : syscall_number == 278 ? "getrandom" :
                    syscall_number == 65 ? "readv" : syscall_number == 66 ? "writev" :
                    syscall_number == 93 ? "exit" : syscall_number == 94 ? "exit_group" : nullptr;
                item.annotation = "Linux ARM64 syscall " +
                    (syscall_name ? std::string(syscall_name) : "#" + std::to_string(syscall_number));
                emulate_linux_arm64_syscall(engine, address, self);
                self.syscall_yielded = true;
            }
        }
        std::optional<Instruction> decoded;
        if (self.is_arm64 && item.byte_count == 4) {
            const auto word = static_cast<std::uint32_t>(item.bytes[0]) |
                (static_cast<std::uint32_t>(item.bytes[1]) << 8) |
                (static_cast<std::uint32_t>(item.bytes[2]) << 16) |
                (static_cast<std::uint32_t>(item.bytes[3]) << 24);
            const bool call = (word & 0xFC000000u) == 0x94000000u || (word & 0xFFFFFC1Fu) == 0xD63F0000u;
            const bool ret = (word & 0xFFFFFC1Fu) == 0xD65F0000u;
            if (call) {
                if (self.call_stack.size() < max_call_stack_depth) self.call_stack.push_back(address + size);
                else { ++self.untracked_call_depth; self.call_stack_was_truncated = true; }
            } else if (ret) {
                if (self.untracked_call_depth) --self.untracked_call_depth;
                else if (!self.call_stack.empty()) self.call_stack.pop_back();
            }
        } else if (!self.is_arm64) {
            decoded = decode_x86_instruction(item.bytes.data(), item.byte_count, address, self.is_64_bit);
        }
        if (!self.is_arm64) {
            bool call = decoded && (decoded->mnemonic == "call" || decoded->mnemonic == "callq" || decoded->mnemonic == "lcall");
            bool ret = decoded && (decoded->mnemonic == "ret" || decoded->mnemonic == "retn" || decoded->mnemonic == "retf");
            if ((!decoded || decoded->mnemonic == "db") && item.byte_count) {
                // Keep the call stack useful without Capstone for common x86
                // control-transfer opcodes; Unicorn supplies the full length.
                std::size_t opcode_index = 0;
                while (opcode_index < item.byte_count) {
                    const auto prefix = item.bytes[opcode_index];
                    const bool legacy_prefix = prefix == 0xF0 || prefix == 0xF2 || prefix == 0xF3 ||
                        prefix == 0x2E || prefix == 0x36 || prefix == 0x3E || prefix == 0x26 ||
                        prefix == 0x64 || prefix == 0x65 || prefix == 0x66 || prefix == 0x67;
                    const bool rex_prefix = self.is_64_bit && prefix >= 0x40 && prefix <= 0x4F;
                    if (!legacy_prefix && !rex_prefix) break;
                    ++opcode_index;
                }
                if (opcode_index < item.byte_count) {
                    const auto opcode = item.bytes[opcode_index];
                    if (opcode == 0xE8) call = true;
                    else if (opcode == 0xFF && opcode_index + 1 < item.byte_count) {
                        const auto group = (item.bytes[opcode_index + 1] >> 3) & 7;
                        call = group == 2 || group == 3;
                    } else if (opcode == 0xC3 || opcode == 0xC2 || opcode == 0xCB || opcode == 0xCA) ret = true;
                }
            }
            if (call) {
                if (self.call_stack.size() < max_call_stack_depth)
                    self.call_stack.push_back(address + size);
                else {
                    ++self.untracked_call_depth;
                    self.call_stack_was_truncated = true;
                }
            } else if (ret) {
                if (self.untracked_call_depth) --self.untracked_call_depth;
                else if (!self.call_stack.empty()) self.call_stack.pop_back();
            }
        }
        if (self.trace.size() >= max_trace_instructions) {
            self.trace_was_truncated = true;
            if (self.syscall_yielded || self.guest_exited) uc_emu_stop(engine);
            return;
        }
        self.trace.push_back(std::move(item));
        if (self.register_delta_capture && read_tracked_registers(engine, self.is_64_bit, self.is_arm64, self.pending_register_values)) {
            self.pending_trace_index = self.trace.size() - 1;
            self.pending_register_snapshot = true;
        }
        if (self.syscall_yielded || self.guest_exited) uc_emu_stop(engine);
    }

    static std::uint64_t emulate_linux_virtual_syscall(uc_engine* engine, std::uint64_t number,
            std::uint64_t descriptor, std::uint64_t buffer, std::uint64_t requested,
            std::uint64_t flags, std::uint64_t fd, std::uint64_t offset,
            std::uint64_t read_number, std::uint64_t write_number,
            std::uint64_t exit_number, std::uint64_t exit_group_number,
            std::uint64_t mmap_number, std::uint64_t mprotect_number,
            std::uint64_t munmap_number, std::uint64_t brk_number, std::uint64_t getrandom_number,
            std::uint64_t getpid_number, std::uint64_t gettid_number,
            std::uint64_t set_tid_address_number, std::uint64_t clock_gettime_number,
            std::uint64_t gettimeofday_number, std::uint64_t set_robust_list_number,
            std::uint64_t readv_number, std::uint64_t writev_number, bool wide_iovec,
            std::uint64_t next_pc, Impl& self) {
        constexpr std::uint64_t max_transfer = 16ull * 1024 * 1024;
        constexpr std::size_t max_output = 16u * 1024 * 1024;
        std::uint64_t result = static_cast<std::uint64_t>(-38); // -ENOSYS for unsupported guest calls.
        if (number == read_number) { // stdin is a caller-supplied in-memory byte string only.
            if (descriptor == 0) {
                const auto count = (std::min<std::uint64_t>)(requested, max_transfer);
                const auto remaining = self.guest_stdin.size() - self.guest_stdin_offset;
                const auto copied = (std::min<std::size_t>)(static_cast<std::size_t>(count), remaining);
                if (accessible_prefix(self, buffer, copied, UC_PROT_WRITE) != copied) result = static_cast<std::uint64_t>(-14);
                else if (copied && uc_mem_write(engine, buffer,
                    self.guest_stdin.data() + self.guest_stdin_offset, copied) != UC_ERR_OK) result = static_cast<std::uint64_t>(-14);
                else {
                    if (copied) {
                        append_memory_access(engine, buffer, static_cast<int>(copied), 0, true, false, &self);
                        self.guest_stdin_offset += copied;
                    }
                    result = copied;
                }
            } else result = static_cast<std::uint64_t>(-9);
        } else if (number == write_number) { // only virtual stdout/stderr; never reaches host descriptors.
            if (descriptor == 1 || descriptor == 2) {
                auto& output = descriptor == 1 ? self.guest_stdout : self.guest_stderr;
                const auto count = (std::min<std::uint64_t>)(requested, max_transfer);
                if (count > max_output - (std::min)(max_output, output.size())) result = static_cast<std::uint64_t>(-12);
                else if (accessible_prefix(self, buffer, count, UC_PROT_READ) != count) result = static_cast<std::uint64_t>(-14);
                else {
                    const auto old_size = output.size();
                    output.resize(old_size + static_cast<std::size_t>(count));
                    if (count && uc_mem_read(engine, buffer, output.data() + old_size, static_cast<std::size_t>(count)) != UC_ERR_OK) {
                        output.resize(old_size);
                        result = static_cast<std::uint64_t>(-14);
                    } else {
                        if (count) append_memory_access(engine, buffer, static_cast<int>(count), 0, false, false, &self);
                        result = count;
                    }
                }
            } else result = static_cast<std::uint64_t>(-9);
        } else if (number == readv_number || number == writev_number) {
            // Scatter/gather variants of the virtual stdin/stdout/stderr model:
            // descriptor = fd, buffer = guest iovec array, requested = iovcnt.
            constexpr std::uint64_t max_iovecs = 1024;
            const bool is_write = number == writev_number;
            const std::uint64_t entry_size = wide_iovec ? 16 : 8;
            struct Segment { std::uint64_t base; std::uint64_t length; };
            std::vector<Segment> segments;
            bool fault = false;
            std::uint64_t total = 0;
            if (is_write ? (descriptor != 1 && descriptor != 2) : descriptor != 0) {
                result = static_cast<std::uint64_t>(-9); // -EBADF
            } else if (requested > max_iovecs) {
                result = static_cast<std::uint64_t>(-22); // -EINVAL
            } else {
                for (std::uint64_t index = 0; index < requested && !fault; ++index) {
                    std::uint8_t raw[16]{};
                    if (accessible_prefix(self, buffer + index * entry_size, entry_size, UC_PROT_READ) != entry_size ||
                        uc_mem_read(engine, buffer + index * entry_size, raw, static_cast<std::size_t>(entry_size)) != UC_ERR_OK) {
                        fault = true; break;
                    }
                    Segment segment{};
                    if (wide_iovec) { std::memcpy(&segment.base, raw, 8); std::memcpy(&segment.length, raw + 8, 8); }
                    else { std::uint32_t base32{}, length32{}; std::memcpy(&base32, raw, 4); std::memcpy(&length32, raw + 4, 4); segment = {base32, length32}; }
                    if (segment.length > max_transfer || total + segment.length > max_transfer) { total = max_transfer + 1; break; }
                    total += segment.length;
                    segments.push_back(segment);
                }
                if (fault) {
                    result = static_cast<std::uint64_t>(-14); // -EFAULT
                } else if (total > max_transfer) {
                    result = static_cast<std::uint64_t>(-22);
                } else if (is_write) {
                    auto& output = descriptor == 1 ? self.guest_stdout : self.guest_stderr;
                    if (total > max_output - (std::min)(max_output, output.size())) {
                        result = static_cast<std::uint64_t>(-12); // -ENOMEM
                    } else {
                        std::string gathered;
                        gathered.reserve(static_cast<std::size_t>(total));
                        for (const auto& segment : segments) {
                            if (!segment.length) continue;
                            const auto old = gathered.size();
                            gathered.resize(old + static_cast<std::size_t>(segment.length));
                            if (accessible_prefix(self, segment.base, segment.length, UC_PROT_READ) != segment.length ||
                                uc_mem_read(engine, segment.base, gathered.data() + old, static_cast<std::size_t>(segment.length)) != UC_ERR_OK) {
                                fault = true; break;
                            }
                        }
                        if (fault) result = static_cast<std::uint64_t>(-14);
                        else {
                            for (const auto& segment : segments)
                                if (segment.length) append_memory_access(engine, segment.base, static_cast<int>(segment.length), 0, false, false, &self);
                            output += gathered;
                            result = gathered.size();
                        }
                    }
                } else {
                    std::uint64_t copied_total = 0;
                    for (const auto& segment : segments) {
                        const auto remaining = self.guest_stdin.size() - self.guest_stdin_offset;
                        const auto copied = (std::min<std::size_t>)(static_cast<std::size_t>(segment.length), remaining);
                        if (!copied) { if (!remaining) break; continue; }
                        if (accessible_prefix(self, segment.base, copied, UC_PROT_WRITE) != copied ||
                            uc_mem_write(engine, segment.base, self.guest_stdin.data() + self.guest_stdin_offset, copied) != UC_ERR_OK) {
                            fault = true; break;
                        }
                        append_memory_access(engine, segment.base, static_cast<int>(copied), 0, true, false, &self);
                        self.guest_stdin_offset += copied;
                        copied_total += copied;
                        if (copied < segment.length) break;   // short read: stdin exhausted
                    }
                    result = fault && !copied_total ? static_cast<std::uint64_t>(-14) : copied_total;
                }
            }
        } else if (number == getpid_number || number == gettid_number || number == set_tid_address_number) {
            // The emulator currently models a single guest thread/process.
            result = 1;
        } else if (number == set_robust_list_number) {
            constexpr std::uint64_t robust_list_head_size = 24;
            if (buffer != robust_list_head_size) result = static_cast<std::uint64_t>(-22);
            else if (accessible_prefix(self, descriptor, robust_list_head_size, UC_PROT_READ) != robust_list_head_size)
                result = static_cast<std::uint64_t>(-14);
            else result = 0; // Single-threaded model: registration has no scheduling effect.
        } else if (number == clock_gettime_number) {
            constexpr std::uint64_t max_timespec = 0x00007FFFFFFFFFFFull;
            if (buffer > max_timespec || accessible_prefix(self, buffer, 16, UC_PROT_WRITE) != 16) {
                result = static_cast<std::uint64_t>(-14); // -EFAULT
            } else if (descriptor != 0 && descriptor != 1 && descriptor != 4 && descriptor != 5 &&
                       descriptor != 6 && descriptor != 7 && descriptor != 11) {
                result = static_cast<std::uint64_t>(-22); // -EINVAL
            } else {
                // Virtual clocks intentionally advance in a fixed 1 ms step per call.
                constexpr std::uint64_t tick_ns = 1'000'000;
                constexpr std::uint64_t realtime_epoch_ns = 1'700'000'000'000'000'000ull;
                constexpr std::uint64_t monotonic_epoch_ns = 10'000'000'000ull;
                const auto epoch = descriptor == 0 || descriptor == 5 || descriptor == 11
                    ? realtime_epoch_ns : monotonic_epoch_ns;
                const auto now = epoch + self.guest_clock_ticks * tick_ns;
                struct GuestTimespec { std::int64_t seconds; std::int64_t nanoseconds; } value{
                    static_cast<std::int64_t>(now / 1'000'000'000ull),
                    static_cast<std::int64_t>(now % 1'000'000'000ull)};
                if (uc_mem_write(engine, buffer, &value, sizeof(value)) != UC_ERR_OK) {
                    result = static_cast<std::uint64_t>(-14);
                } else {
                    append_memory_access(engine, buffer, sizeof(value), 0, true, false, &self);
                    ++self.guest_clock_ticks;
                    result = 0;
                }
            }
        } else if (number == gettimeofday_number) {
            constexpr std::uint64_t max_user_address = 0x00007FFFFFFFFFFFull;
            if (!descriptor) result = 0;
            else if (descriptor > max_user_address || accessible_prefix(self, descriptor, 16, UC_PROT_WRITE) != 16)
                result = static_cast<std::uint64_t>(-14);
            else {
                struct GuestTimeval { std::int64_t seconds; std::int64_t microseconds; } value{
                    1'700'000'000, static_cast<std::int64_t>(self.guest_clock_ticks * 1000)};
                if (uc_mem_write(engine, descriptor, &value, sizeof(value)) != UC_ERR_OK)
                    result = static_cast<std::uint64_t>(-14);
                else {
                    append_memory_access(engine, descriptor, sizeof(value), 0, true, false, &self);
                    ++self.guest_clock_ticks;
                    result = 0;
                }
            }
        } else if (number == getrandom_number) {
            constexpr std::uint64_t grnd_nonblock = 1, grnd_random = 2;
            if ((requested & ~(grnd_nonblock | grnd_random)) != 0 || buffer > max_transfer) {
                result = static_cast<std::uint64_t>(-22); // -EINVAL
            } else if (accessible_prefix(self, descriptor, buffer, UC_PROT_WRITE) != buffer) {
                result = static_cast<std::uint64_t>(-14); // -EFAULT
            } else {
                std::vector<std::uint8_t> bytes(static_cast<std::size_t>(buffer));
                for (auto& byte : bytes) {
                    auto state = self.guest_random_state;
                    state ^= state >> 12;
                    state ^= state << 25;
                    state ^= state >> 27;
                    self.guest_random_state = state;
                    byte = static_cast<std::uint8_t>((state * 0x2545F4914F6CDD1Dull) >> 56);
                }
                if (!bytes.empty() && uc_mem_write(engine, descriptor, bytes.data(), bytes.size()) != UC_ERR_OK)
                    result = static_cast<std::uint64_t>(-14);
                else {
                    if (!bytes.empty()) append_memory_access(engine, descriptor, static_cast<int>(bytes.size()), 0, true, false, &self);
                    result = bytes.size();
                }
            }
        } else if (number == exit_number || number == exit_group_number) { // exit / exit_group
            self.guest_exit_code = static_cast<int>(descriptor & 0xffu);
            self.guest_exited = true;
            self.guest_exit_pc = next_pc;
            result = 0;
        } else if (number == mmap_number) {
            constexpr std::uint64_t page_size = 0x1000;
            constexpr std::uint64_t max_mmap = 256ull * 1024 * 1024;
            constexpr std::uint64_t map_private = 0x02, map_anonymous = 0x20, map_noreserve = 0x4000;
            if (!buffer || buffer > max_mmap || offset != 0 ||
                (flags & (map_private | map_anonymous)) != (map_private | map_anonymous) ||
                (flags & ~(map_private | map_anonymous | map_noreserve)) != 0 ||
                (requested & ~std::uint64_t{7}) != 0) {
                result = static_cast<std::uint64_t>(-22); // -EINVAL
            } else {
                const auto size = buffer <= UINT64_MAX - (page_size - 1)
                    ? (buffer + page_size - 1) & ~(page_size - 1) : 0;
                const auto address = self.mmap_cursor;
                if (!size || size > max_mmap - self.mmap_committed || address > UINT64_MAX - size ||
                    address < self.mmap_base || address - self.mmap_base > max_mmap - size) {
                    result = static_cast<std::uint64_t>(-12); // -ENOMEM
                } else {
                    std::uint32_t permissions = 0;
                    if (requested & 1) permissions |= UC_PROT_READ;
                    if (requested & 2) permissions |= UC_PROT_WRITE;
                    if (requested & 4) permissions |= UC_PROT_EXEC;
                    const auto status = uc_mem_map(engine, address, static_cast<std::size_t>(size), permissions);
                    if (status != UC_ERR_OK) result = static_cast<std::uint64_t>(-12);
                    else {
                        self.guest_mappings.emplace(address, GuestMapping{size, permissions});
                        for (auto page = address; page < address + size; page += page_size)
                            self.page_permissions[page] = permissions;
                        self.mmap_cursor += size;
                        self.mmap_committed += size;
                        result = address;
                    }
                }
            }
        } else if (number == mprotect_number) {
            constexpr std::uint64_t page_size = 0x1000;
            if (!buffer || (descriptor & (page_size - 1)) != 0 || buffer > UINT64_MAX - (page_size - 1) ||
                (requested & ~std::uint64_t{7}) != 0) {
                result = static_cast<std::uint64_t>(-22);
            } else {
                const auto size = (buffer + page_size - 1) & ~(page_size - 1);
                bool range_mapped = size != 0 && descriptor <= UINT64_MAX - size;
                for (auto page = descriptor; range_mapped && page < descriptor + size; page += page_size)
                    range_mapped = self.page_permissions.contains(page);
                if (!range_mapped || uc_mem_protect(engine, descriptor, static_cast<std::size_t>(size),
                        static_cast<std::uint32_t>(requested)) != UC_ERR_OK) {
                    result = static_cast<std::uint64_t>(-12); // -ENOMEM for unmapped/invalid page ranges.
                } else {
                    for (auto page = descriptor; page < descriptor + size; page += page_size)
                        self.page_permissions[page] = static_cast<std::uint32_t>(requested);
                    const auto end = descriptor + size;
                    std::vector<std::pair<std::uint64_t, GuestMapping>> replacements;
                    for (auto mapping = self.guest_mappings.begin(); mapping != self.guest_mappings.end();) {
                        const auto old_begin = mapping->first;
                        const auto old_end = old_begin + mapping->second.size;
                        const auto old_permissions = mapping->second.permissions;
                        if (old_begin >= end || old_end <= descriptor) { ++mapping; continue; }
                        mapping = self.guest_mappings.erase(mapping);
                        const auto changed_begin = (std::max)(old_begin, descriptor);
                        const auto changed_end = (std::min)(old_end, end);
                        if (old_begin < changed_begin)
                            replacements.push_back({old_begin, {changed_begin - old_begin, old_permissions}});
                        replacements.push_back({changed_begin, {changed_end - changed_begin,
                            static_cast<std::uint32_t>(requested)}});
                        if (changed_end < old_end)
                            replacements.push_back({changed_end, {old_end - changed_end, old_permissions}});
                    }
                    for (const auto& replacement : replacements)
                        self.guest_mappings.emplace(replacement.first, replacement.second);
                    result = 0;
                }
            }
        } else if (number == munmap_number) {
            constexpr std::uint64_t page_size = 0x1000;
            if (!buffer || (descriptor & (page_size - 1)) != 0 || buffer > UINT64_MAX - (page_size - 1)) {
                result = static_cast<std::uint64_t>(-22);
            } else {
                const auto size = (buffer + page_size - 1) & ~(page_size - 1);
                auto mapping = self.guest_mappings.upper_bound(descriptor);
                if (mapping != self.guest_mappings.begin()) --mapping;
                const bool contained = mapping != self.guest_mappings.end() && descriptor >= mapping->first &&
                    descriptor - mapping->first <= mapping->second.size &&
                    size <= mapping->second.size - (descriptor - mapping->first);
                if (!contained)
                    result = static_cast<std::uint64_t>(-22);
                else if (uc_mem_unmap(engine, descriptor, static_cast<std::size_t>(size)) != UC_ERR_OK)
                    result = static_cast<std::uint64_t>(-22);
                else {
                    for (auto page = descriptor; page < descriptor + size; page += page_size)
                        self.page_permissions.erase(page);
                    self.mmap_committed -= size;
                    const auto original_begin = mapping->first;
                    const auto original_end = original_begin + mapping->second.size;
                    const auto original_permissions = mapping->second.permissions;
                    self.guest_mappings.erase(mapping);
                    if (descriptor > original_begin)
                        self.guest_mappings.emplace(original_begin,
                            GuestMapping{descriptor - original_begin, original_permissions});
                    const auto unmap_end = descriptor + size;
                    if (unmap_end < original_end)
                        self.guest_mappings.emplace(unmap_end,
                            GuestMapping{original_end - unmap_end, original_permissions});
                    result = 0;
                }
            }
        } else if (number == brk_number) {
            constexpr std::uint64_t page_size = 0x1000;
            constexpr std::uint64_t max_brk = 64ull * 1024 * 1024;
            if (!descriptor) result = self.brk_current;
            else if (descriptor < self.brk_base || descriptor - self.brk_base > max_brk ||
                     descriptor > UINT64_MAX - (page_size - 1)) result = self.brk_current;
            else {
                const auto old_committed = self.brk_committed;
                const auto new_committed = (descriptor - self.brk_base + page_size - 1) & ~(page_size - 1);
                uc_err status = UC_ERR_OK;
                if (new_committed > old_committed)
                    status = uc_mem_map(engine, self.brk_base + old_committed,
                        static_cast<std::size_t>(new_committed - old_committed), UC_PROT_READ | UC_PROT_WRITE);
                else if (new_committed < old_committed)
                    status = uc_mem_unmap(engine, self.brk_base + new_committed,
                        static_cast<std::size_t>(old_committed - new_committed));
                if (status != UC_ERR_OK) result = self.brk_current;
                else {
                    if (new_committed > old_committed) {
                        for (auto page = self.brk_base + old_committed; page < self.brk_base + new_committed; page += page_size)
                            self.page_permissions[page] = UC_PROT_READ | UC_PROT_WRITE;
                    } else if (new_committed < old_committed) {
                        for (auto page = self.brk_base + new_committed; page < self.brk_base + old_committed; page += page_size)
                            self.page_permissions.erase(page);
                    }
                    self.brk_current = descriptor;
                    self.brk_committed = new_committed;
                    result = descriptor;
                }
            }
        }
        return result;
    }

    static void emulate_linux_x64_syscall(uc_engine* engine, std::uint64_t address, Impl& self) {
        std::uint64_t number{}, descriptor{}, buffer{}, requested{};
        if (uc_reg_read(engine, UC_X86_REG_RAX, &number) != UC_ERR_OK ||
            uc_reg_read(engine, UC_X86_REG_RDI, &descriptor) != UC_ERR_OK ||
            uc_reg_read(engine, UC_X86_REG_RSI, &buffer) != UC_ERR_OK ||
            uc_reg_read(engine, UC_X86_REG_RDX, &requested) != UC_ERR_OK) {
            self.memory_fault = true;
            return;
        }
        std::uint64_t syscall_flags{}, fd{}, offset{};
        if (uc_reg_read(engine, UC_X86_REG_R10, &syscall_flags) != UC_ERR_OK ||
            uc_reg_read(engine, UC_X86_REG_R8, &fd) != UC_ERR_OK ||
            uc_reg_read(engine, UC_X86_REG_R9, &offset) != UC_ERR_OK) {
            self.memory_fault = true;
            return;
        }
        const auto next_pc = address + 2;
        const auto result = number == 158
            ? emulate_linux_x64_arch_prctl(engine, descriptor, buffer, self)
            : emulate_linux_virtual_syscall(engine, number, descriptor, buffer, requested, syscall_flags, fd, offset,
                0, 1, 60, 231, 9, 10, 11, 12, 318, 39, 186, 218, 228, 96, 273, 19, 20, true, next_pc, self);
        std::uint64_t flags{};
        (void)uc_reg_read(engine, UC_X86_REG_EFLAGS, &flags);
        if (uc_reg_write(engine, UC_X86_REG_RCX, &next_pc) != UC_ERR_OK ||
            uc_reg_write(engine, UC_X86_REG_R11, &flags) != UC_ERR_OK ||
            uc_reg_write(engine, UC_X86_REG_RIP, &next_pc) != UC_ERR_OK ||
            uc_reg_write(engine, UC_X86_REG_RAX, &result) != UC_ERR_OK)
            self.memory_fault = true;
    }

    static void emulate_linux_x86_syscall(uc_engine* engine, std::uint64_t address, Impl& self) {
        std::uint32_t number{}, descriptor{}, buffer{}, requested{}, syscall_flags{}, fd{}, offset{};
        if (uc_reg_read(engine, UC_X86_REG_EAX, &number) != UC_ERR_OK ||
            uc_reg_read(engine, UC_X86_REG_EBX, &descriptor) != UC_ERR_OK ||
            uc_reg_read(engine, UC_X86_REG_ECX, &buffer) != UC_ERR_OK ||
            uc_reg_read(engine, UC_X86_REG_EDX, &requested) != UC_ERR_OK ||
            uc_reg_read(engine, UC_X86_REG_ESI, &syscall_flags) != UC_ERR_OK ||
            uc_reg_read(engine, UC_X86_REG_EDI, &fd) != UC_ERR_OK ||
            uc_reg_read(engine, UC_X86_REG_EBP, &offset) != UC_ERR_OK) {
            self.memory_fault = true;
            return;
        }
        const auto next_pc = address + 2;
        std::uint64_t result{};
        if (number == 265) { // i386 clock_gettime has a pair of 32-bit fields.
            constexpr std::uint32_t max_clock_id = 11;
            struct GuestTimespec32 { std::int32_t seconds; std::int32_t nanoseconds; } value{};
            if (descriptor != 0 && descriptor != 1 && descriptor != 4 && descriptor != 5 &&
                descriptor != 6 && descriptor != 7 && descriptor != max_clock_id) {
                result = static_cast<std::uint32_t>(-22); // -EINVAL
            } else if (accessible_prefix(self, buffer, sizeof(value), UC_PROT_WRITE) != sizeof(value)) {
                result = static_cast<std::uint32_t>(-14); // -EFAULT
            } else {
                constexpr std::uint64_t tick_ns = 1'000'000;
                constexpr std::uint64_t realtime_epoch_ns = 1'700'000'000'000'000'000ull;
                constexpr std::uint64_t monotonic_epoch_ns = 10'000'000'000ull;
                const auto epoch = descriptor == 0 || descriptor == 5 || descriptor == max_clock_id
                    ? realtime_epoch_ns : monotonic_epoch_ns;
                const auto now = epoch + self.guest_clock_ticks * tick_ns;
                value.seconds = static_cast<std::int32_t>(now / 1'000'000'000ull);
                value.nanoseconds = static_cast<std::int32_t>(now % 1'000'000'000ull);
                if (uc_mem_write(engine, buffer, &value, sizeof(value)) != UC_ERR_OK)
                    result = static_cast<std::uint32_t>(-14);
                else {
                    append_memory_access(engine, buffer, sizeof(value), 0, true, false, &self);
                    ++self.guest_clock_ticks;
                }
            }
        } else if (number == 78) { // i386 timeval is also two 32-bit fields.
            struct GuestTimeval32 { std::int32_t seconds; std::int32_t microseconds; } value{
                1'700'000'000, static_cast<std::int32_t>(self.guest_clock_ticks * 1000)};
            if (!descriptor) result = 0;
            else if (accessible_prefix(self, descriptor, sizeof(value), UC_PROT_WRITE) != sizeof(value))
                result = static_cast<std::uint32_t>(-14);
            else if (uc_mem_write(engine, descriptor, &value, sizeof(value)) != UC_ERR_OK)
                result = static_cast<std::uint32_t>(-14);
            else {
                append_memory_access(engine, descriptor, sizeof(value), 0, true, false, &self);
                ++self.guest_clock_ticks;
            }
        } else {
        // mmap2's sixth argument is an offset in pages. The shared virtual mmap
        // model only permits offset zero, so nonzero page offsets are rejected.
        result = emulate_linux_virtual_syscall(engine, number, descriptor, buffer, requested,
            syscall_flags, fd, offset, 3, 4, 1, 252, 192, 125, 91, 45, 355,
            20, 224, 258, UINT64_MAX, UINT64_MAX, 311, 145, 146, false, next_pc, self);
        }
        const auto result32 = static_cast<std::uint32_t>(result);
        const auto next_pc32 = static_cast<std::uint32_t>(next_pc);
        if (uc_reg_write(engine, UC_X86_REG_EIP, &next_pc32) != UC_ERR_OK ||
            uc_reg_write(engine, UC_X86_REG_EAX, &result32) != UC_ERR_OK)
            self.memory_fault = true;
    }

    static std::uint64_t emulate_linux_x64_arch_prctl(uc_engine* engine, std::uint64_t operation,
                                                       std::uint64_t guest_address, Impl& self) {
        constexpr std::uint64_t arch_set_gs = 0x1001, arch_set_fs = 0x1002;
        constexpr std::uint64_t arch_get_fs = 0x1003, arch_get_gs = 0x1004;
        constexpr std::uint64_t max_user_address = 0x00007FFFFFFFFFFFull;
        if (operation == arch_set_fs || operation == arch_set_gs) {
            if (guest_address > max_user_address) return static_cast<std::uint64_t>(-1); // -EPERM
            const auto reg = operation == arch_set_fs ? UC_X86_REG_FS_BASE : UC_X86_REG_GS_BASE;
            return uc_reg_write(engine, reg, &guest_address) == UC_ERR_OK ? 0 : static_cast<std::uint64_t>(-22);
        }
        if (operation == arch_get_fs || operation == arch_get_gs) {
            if (accessible_prefix(self, guest_address, sizeof(std::uint64_t), UC_PROT_WRITE) != sizeof(std::uint64_t))
                return static_cast<std::uint64_t>(-14); // -EFAULT
            std::uint64_t base{};
            const auto reg = operation == arch_get_fs ? UC_X86_REG_FS_BASE : UC_X86_REG_GS_BASE;
            if (uc_reg_read(engine, reg, &base) != UC_ERR_OK ||
                uc_mem_write(engine, guest_address, &base, sizeof(base)) != UC_ERR_OK)
                return static_cast<std::uint64_t>(-14);
            append_memory_access(engine, guest_address, sizeof(base), 0, true, false, &self);
            return 0;
        }
        return static_cast<std::uint64_t>(-22); // -EINVAL
    }

    static void emulate_linux_arm64_syscall(uc_engine* engine, std::uint64_t address, Impl& self) {
        std::uint64_t number{}, descriptor{}, buffer{}, requested{}, syscall_flags{}, fd{}, offset{};
        if (uc_reg_read(engine, UC_ARM64_REG_X8, &number) != UC_ERR_OK ||
            uc_reg_read(engine, UC_ARM64_REG_X0, &descriptor) != UC_ERR_OK ||
            uc_reg_read(engine, UC_ARM64_REG_X1, &buffer) != UC_ERR_OK ||
            uc_reg_read(engine, UC_ARM64_REG_X2, &requested) != UC_ERR_OK ||
            uc_reg_read(engine, UC_ARM64_REG_X3, &syscall_flags) != UC_ERR_OK ||
            uc_reg_read(engine, UC_ARM64_REG_X4, &fd) != UC_ERR_OK ||
            uc_reg_read(engine, UC_ARM64_REG_X5, &offset) != UC_ERR_OK) {
            self.memory_fault = true;
            return;
        }
        const auto next_pc = address + 4;
        const auto result = emulate_linux_virtual_syscall(engine, number, descriptor, buffer, requested, syscall_flags, fd, offset,
            63, 64, 93, 94, 222, 226, 215, 214, 278, 172, 178, 96, 113, 169, 99, 65, 66, true, next_pc, self);
        if (uc_reg_write(engine, UC_ARM64_REG_PC, &next_pc) != UC_ERR_OK ||
            uc_reg_write(engine, UC_ARM64_REG_X0, &result) != UC_ERR_OK)
            self.memory_fault = true;
    }

    static std::string canonical_import_name(std::string name) {
        if (!name.empty() && name.front() == '_') name.erase(name.begin());
        const auto decoration = name.rfind('@');
        if (decoration != std::string::npos && decoration + 1 < name.size() &&
            std::all_of(name.begin() + static_cast<std::ptrdiff_t>(decoration + 1), name.end(),
                        [](unsigned char c) { return c >= '0' && c <= '9'; }))
            name.resize(decoration);
        return name;
    }

    static bool is_supported_guest_import(const std::string& raw_name) {
        static const std::unordered_set<std::string> supported{
            "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset", "memchr", "memcmp",
            "strlen", "strnlen", "strcpy", "strcat", "strncat", "strcmp", "strncmp", "strstr",
            "strspn", "strcspn", "strchr", "strrchr", "GetTickCount", "GetTickCount64",
            "IsDebuggerPresent", "GetCurrentProcessId", "GetCurrentThreadId", "GetCurrentProcess",
            "GetCurrentThread", "GetProcessHeap", "HeapAlloc", "HeapFree", "HeapReAlloc", "HeapSize",
            "HeapValidate", "VirtualAlloc", "VirtualFree", "VirtualProtect", "GetLastError", "SetLastError",
            "VirtualQuery", "VirtualQueryEx",
            "QueryPerformanceCounter", "QueryPerformanceFrequency", "GetSystemTimeAsFileTime",
            "CheckRemoteDebuggerPresent", "FlushInstructionCache", "LoadLibraryA", "LoadLibraryW",
            "LoadLibraryExA", "LoadLibraryExW", "FreeLibrary", "GetProcAddress", "GetModuleHandleA",
            "GetModuleHandleW", "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
            "GetFileSize", "GetFileSizeEx", "SetFilePointer", "GetFileAttributesA", "GetFileAttributesW",
            "DeleteFileA", "DeleteFileW"
        };
        return supported.contains(canonical_import_name(raw_name));
    }

    static bool is_crt_guest_import(const std::string& raw_name) {
        static const std::unordered_set<std::string> crt_imports{
            "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset", "memchr", "memcmp",
            "strlen", "strnlen", "strcpy", "strcat", "strncat", "strcmp", "strncmp", "strstr",
            "strspn", "strcspn", "strchr", "strrchr"
        };
        return crt_imports.contains(canonical_import_name(raw_name));
    }

    static bool guest_module_kind(const std::string& requested_name, bool& windows_api, bool& c_runtime,
                                  std::string& normalized_name) {
        windows_api = false;
        c_runtime = false;
        const auto separator = requested_name.find_last_of("/\\");
        normalized_name = separator == std::string::npos ? requested_name : requested_name.substr(separator + 1);
        for (auto& character : normalized_name)
            character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
        if (normalized_name.empty()) return false;
        if (normalized_name.find('.') == std::string::npos) normalized_name += ".dll";

        c_runtime = normalized_name == "msvcrt.dll" || normalized_name == "ucrtbase.dll" ||
            normalized_name == "vcruntime140.dll" || normalized_name == "vcruntime140_1.dll" ||
            normalized_name.rfind("api-ms-win-crt-", 0) == 0;
        static const std::unordered_set<std::string> windows_modules{
            "kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll", "advapi32.dll", "gdi32.dll",
            "shell32.dll", "ole32.dll", "oleaut32.dll", "ws2_32.dll", "wininet.dll", "winhttp.dll",
            "bcrypt.dll", "crypt32.dll", "version.dll", "psapi.dll", "dbghelp.dll", "comdlg32.dll",
            "comctl32.dll", "shlwapi.dll", "rpcrt4.dll", "secur32.dll", "iphlpapi.dll"
        };
        windows_api = windows_modules.contains(normalized_name) ||
            normalized_name.rfind("api-ms-win-core-", 0) == 0 ||
            normalized_name.rfind("api-ms-win-security-", 0) == 0;
        return windows_api || c_runtime;
    }

    static bool guest_module_exports(const GuestModule& module, const std::string& raw_name) {
        if (module.windows_api && !is_crt_guest_import(raw_name)) return is_supported_guest_import(raw_name);
        if (module.c_runtime) return is_crt_guest_import(raw_name);
        return false;
    }

    static bool normalize_guest_file_path(std::string path, std::string& normalized) {
        normalized.clear();
        if (path.empty() || path.size() > 1024) return false;
        for (auto character : path) {
            if (character == '\\') character = '/';
            normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
        }
        for (auto duplicate = normalized.find("//"); duplicate != std::string::npos;
             duplicate = normalized.find("//", duplicate + 1)) {
            if (duplicate == 0 && normalized.size() > 2 && normalized[2] != '/') continue; // retain UNC prefix
            normalized.erase(duplicate, 1);
        }
        while (normalized.size() > 1 && normalized.back() == '/' &&
               !(normalized.size() == 3 && normalized[1] == ':')) normalized.pop_back();
        return !normalized.empty();
    }

    static std::uint64_t create_dynamic_import_stub(uc_engine* engine, const std::string& raw_name, Impl& self) {
        const auto name = canonical_import_name(raw_name);
        if (!is_supported_guest_import(name)) return 0;
        if (const auto found = self.dynamic_import_addresses.find(name); found != self.dynamic_import_addresses.end())
            return found->second;
        constexpr std::uint64_t stub_stride = 16;
        if (!self.dynamic_stub_base || self.dynamic_stub_cursor > self.dynamic_stub_capacity ||
            stub_stride > self.dynamic_stub_capacity - self.dynamic_stub_cursor) return 0;

        const auto address = self.dynamic_stub_base + self.dynamic_stub_cursor;
        std::uint8_t code[4] = {0xC3, 0, 0, 0};
        std::size_t code_size = 1;
        const auto stack_bytes = self.is_arm64 ? std::uint16_t{0} : modeled_windows_stdcall_bytes(name);
        if (self.is_arm64) {
            code[0] = 0xC0; code[1] = 0x03; code[2] = 0x5F; code[3] = 0xD6; // RET X30
            code_size = 4;
        } else if (!self.is_64_bit && stack_bytes) {
            code[0] = 0xC2;
            code[1] = static_cast<std::uint8_t>(stack_bytes & 0xffu);
            code[2] = static_cast<std::uint8_t>(stack_bytes >> 8);
            code_size = 3;
        }
        if (uc_mem_write(engine, address, code, code_size) != UC_ERR_OK) return 0;
        self.import_stubs.emplace(address, std::make_pair(name, stack_bytes));
        self.dynamic_import_addresses.emplace(name, address);
        self.dynamic_stub_cursor += stub_stride;
        return address;
    }

    static bool emulate_safe_import(uc_engine* engine, const std::string& imported_name,
                                    std::uint16_t, Impl& self) {
        const bool is64 = self.is_64_bit;
        const bool arm64 = self.is_arm64;
        const auto name = canonical_import_name(imported_name);
        if (!is_supported_guest_import(name)) return false;
        const bool file_api = name == "CreateFileA" || name == "CreateFileW" || name == "ReadFile" ||
            name == "WriteFile" || name == "CloseHandle" || name == "GetFileSize" ||
            name == "GetFileSizeEx" || name == "SetFilePointer" || name == "GetFileAttributesA" ||
            name == "GetFileAttributesW" || name == "DeleteFileA" || name == "DeleteFileW";
        if (file_api && self.is_elf) return false;

        const auto read_register = [&](int id, std::uint64_t& value) {
            value = 0;
            std::uint32_t value32{};
            const auto status = uc_reg_read(engine, id, is64 ? static_cast<void*>(&value) : static_cast<void*>(&value32));
            if (!is64) value = value32;
            return status == UC_ERR_OK;
        };
        std::array<std::uint64_t, 7> arguments{};
        if (arm64) {
            const auto count = file_api ? (name == "CreateFileA" || name == "CreateFileW" ? 7u :
                name == "ReadFile" || name == "WriteFile" ? 5u : name == "SetFilePointer" ? 4u :
                name == "GetFileSize" || name == "GetFileSizeEx" ? 2u : 1u) :
                (name == "HeapReAlloc" || name == "VirtualAlloc" || name == "VirtualProtect" ||
                 name == "VirtualQueryEx") ? 4u : 3u;
            for (std::uint32_t index = 0; index < count; ++index)
                if (!read_register(UC_ARM64_REG_X0 + static_cast<int>(index), arguments[index])) return false;
        } else if (is64 && self.is_elf) {
            if (!read_register(UC_X86_REG_RDI, arguments[0]) || !read_register(UC_X86_REG_RSI, arguments[1]) ||
                !read_register(UC_X86_REG_RDX, arguments[2])) return false;
        } else if (is64) {
            if (!read_register(UC_X86_REG_RCX, arguments[0]) || !read_register(UC_X86_REG_RDX, arguments[1]) ||
                !read_register(UC_X86_REG_R8, arguments[2])) return false;
            const bool has_fourth = file_api || name == "HeapReAlloc" || name == "VirtualAlloc" ||
                name == "VirtualProtect" || name == "VirtualQueryEx";
            if (has_fourth && !read_register(UC_X86_REG_R9, arguments[3])) return false;
            const auto argument_count = file_api ? (name == "CreateFileA" || name == "CreateFileW" ? 7u :
                name == "ReadFile" || name == "WriteFile" ? 5u : name == "SetFilePointer" ? 4u :
                name == "GetFileSize" || name == "GetFileSizeEx" ? 2u : 1u) : 4u;
            if (argument_count > 4) {
                std::uint64_t sp{};
                if (!read_register(UC_X86_REG_RSP, sp) || sp > UINT64_MAX - 0x28) return false;
                std::array<std::uint64_t, 3> stack_arguments{};
                const auto stack_count = argument_count - 4;
                if (uc_mem_read(engine, sp + 0x28, stack_arguments.data(), stack_count * sizeof(stack_arguments[0])) != UC_ERR_OK) {
                    set_import_memory_fault(engine, self, sp + 0x28,
                        stack_count * sizeof(stack_arguments[0]), UC_MEM_READ);
                    return false;
                }
                for (std::uint32_t index = 0; index < stack_count; ++index)
                    arguments[index + 4] = stack_arguments[index];
            }
        } else {
            std::uint32_t sp{};
            if (uc_reg_read(engine, UC_X86_REG_ESP, &sp) != UC_ERR_OK) return false;
            std::uint32_t args[7]{};
            const auto count = (name == "GetTickCount" || name == "GetTickCount64" ||
                                name == "IsDebuggerPresent" || name == "GetCurrentProcessId" ||
                                name == "GetCurrentThreadId" || name == "GetCurrentProcess" ||
                                name == "GetCurrentThread" || name == "GetProcessHeap" ||
                                name == "GetLastError") ? 0u :
                (name == "strlen" || name == "malloc" || name == "free" || name == "SetLastError" ||
                 name == "LoadLibraryA" || name == "LoadLibraryW" || name == "GetModuleHandleA" ||
                 name == "GetModuleHandleW" || name == "FreeLibrary" || name == "CloseHandle" ||
                 name == "DeleteFileA" || name == "DeleteFileW" || name == "GetFileAttributesA" ||
                 name == "GetFileAttributesW" ||
                 name == "QueryPerformanceCounter" || name == "QueryPerformanceFrequency" ||
                 name == "GetSystemTimeAsFileTime") ? 1u :
                (name == "CheckRemoteDebuggerPresent" || name == "GetProcAddress" || name == "GetFileSize" ||
                 name == "GetFileSizeEx") ? 2u :
                (name == "FlushInstructionCache") ? 3u :
                (name == "HeapReAlloc" || name == "VirtualAlloc" || name == "VirtualProtect" ||
                 name == "VirtualQueryEx") ? 4u :
                name == "VirtualQuery" ? 3u :
                (name == "SetFilePointer") ? 4u :
                (name == "ReadFile" || name == "WriteFile") ? 5u :
                (name == "CreateFileA" || name == "CreateFileW") ? 7u :
                (name == "strnlen" || name == "strcpy" || name == "strcat" || name == "strcmp" || name == "strstr" ||
                 name == "strspn" || name == "strcspn" ||
                 name == "strncat" ||
                 name == "strchr" || name == "strrchr" || name == "calloc" || name == "realloc") ? 2u : 3u;
            if (uc_mem_read(engine, static_cast<std::uint64_t>(sp) + 4, args, count * sizeof(args[0])) != UC_ERR_OK) return false;
            for (std::uint32_t index = 0; index < count; ++index) arguments[index] = args[index];
        }
        const auto first = arguments[0], second = arguments[1], third = arguments[2], fourth = arguments[3];
        const auto fifth = arguments[4], sixth = arguments[5], seventh = arguments[6];
        constexpr std::uint64_t max_copy = 16ull * 1024 * 1024;
        constexpr std::uint64_t max_string_scan = 1ull * 1024 * 1024;
        constexpr std::uint64_t max_heap = 64ull * 1024 * 1024;
        const auto read_guest_string = [&](std::uint64_t address, bool wide, std::string& value,
                                           bool& supported_encoding) {
            value.clear();
            supported_encoding = true;
            if (!address) return true;
            constexpr std::uint64_t max_api_string_chars = 1024;
            const std::uint64_t unit_size = wide ? 2 : 1;
            for (std::uint64_t index = 0; index < max_api_string_chars; ++index) {
                if (index > (UINT64_MAX - address) / unit_size) {
                    set_import_memory_fault(engine, self, address, unit_size, UC_MEM_READ);
                    return false;
                }
                const auto character_address = address + index * unit_size;
                if (accessible_prefix(self, character_address, unit_size, UC_PROT_READ) != unit_size) {
                    set_import_memory_fault(engine, self, character_address, unit_size, UC_MEM_READ);
                    return false;
                }
                std::uint8_t bytes[2]{};
                if (uc_mem_read(engine, character_address, bytes, static_cast<std::size_t>(unit_size)) != UC_ERR_OK) {
                    set_import_memory_fault(engine, self, character_address, unit_size, UC_MEM_READ);
                    return false;
                }
                const auto character = wide
                    ? static_cast<std::uint16_t>(bytes[0] | (static_cast<std::uint16_t>(bytes[1]) << 8))
                    : static_cast<std::uint16_t>(bytes[0]);
                if (!character) {
                    append_memory_access(engine, address,
                        static_cast<int>((index + 1) * unit_size), 0, false, false, &self);
                    return true;
                }
                if (character > 0x7f) supported_encoding = false;
                else if (supported_encoding) value.push_back(static_cast<char>(character));
            }
            const auto next_address = address > UINT64_MAX - max_api_string_chars * unit_size
                ? UINT64_MAX : address + max_api_string_chars * unit_size;
            set_import_memory_fault(engine, self, next_address, unit_size, UC_MEM_READ);
            return false;
        };
        const auto allocate_guest = [&](std::uint64_t requested, bool zero) -> std::uint64_t {
            if (!requested || requested > max_heap) return 0;
            auto reusable = std::find_if(self.heap_free_blocks.begin(), self.heap_free_blocks.end(),
                [&](const auto& block) { return block.second >= requested; });
            std::uint64_t address{};
            std::uint64_t capacity{};
            if (reusable != self.heap_free_blocks.end()) {
                address = reusable->first;
                capacity = reusable->second;
                self.heap_free_blocks.erase(reusable);
            } else {
                constexpr std::uint64_t guest_page_size = 0x1000;
                const auto allocation_cursor = self.heap_base + self.heap_cursor;
                const auto allocation_base = allocation_cursor <= UINT64_MAX - (guest_page_size - 1)
                    ? (allocation_cursor + guest_page_size - 1) & ~(guest_page_size - 1) : 0;
                if (!allocation_base || requested > UINT64_MAX - allocation_base) return 0;
                const auto requested_end = allocation_base + requested;
                const auto allocation_end = requested_end <= UINT64_MAX - (guest_page_size - 1)
                    ? (requested_end + guest_page_size - 1) & ~(guest_page_size - 1) : 0;
                if (!allocation_end || allocation_end <= allocation_base) return 0;
                capacity = allocation_end - allocation_base;
                if (capacity > max_heap - self.heap_committed ||
                    uc_mem_map(engine, allocation_base, static_cast<std::size_t>(capacity),
                               UC_PROT_READ | UC_PROT_WRITE) != UC_ERR_OK) return 0;
                for (auto page = allocation_base; page < allocation_end; page += guest_page_size) {
                    self.page_permissions[page] = UC_PROT_READ | UC_PROT_WRITE;
                    self.initial_page_permissions[page] = UC_PROT_READ | UC_PROT_WRITE;
                }
                self.heap_committed += capacity;
                self.heap_cursor = allocation_end - self.heap_base;
                address = allocation_base;
            }
            if (zero) {
                std::vector<std::uint8_t> zeros(static_cast<std::size_t>(requested), 0);
                if (uc_mem_write(engine, address, zeros.data(), zeros.size()) != UC_ERR_OK) {
                    self.heap_free_blocks[address] = capacity;
                    return 0;
                }
            }
            self.heap_allocations[address] = requested;
            self.heap_allocation_capacities[address] = capacity;
            return address;
        };
        const auto release_guest = [&](std::uint64_t address) {
            const auto capacity = self.heap_allocation_capacities.find(address);
            if (capacity == self.heap_allocation_capacities.end()) return false;
            self.heap_free_blocks[address] = capacity->second;
            self.heap_allocation_capacities.erase(capacity);
            self.heap_allocations.erase(address);
            return true;
        };
        const auto reallocate_guest = [&](std::uint64_t address, std::uint64_t requested,
                                          bool zero_new, bool in_place_only) -> std::uint64_t {
            if (requested > max_heap) return 0;
            if (!address) return allocate_guest(requested ? requested : 1, zero_new);
            if (!requested) {
                (void)release_guest(address);
                return 0;
            }
            const auto current = self.heap_allocations.find(address);
            const auto capacity = self.heap_allocation_capacities.find(address);
            if (current == self.heap_allocations.end() || capacity == self.heap_allocation_capacities.end()) return 0;
            const auto old_size = current->second;
            if (requested <= capacity->second) {
                if (zero_new && requested > old_size) {
                    const auto zero_count = requested - old_size;
                    std::vector<std::uint8_t> zeros(static_cast<std::size_t>(zero_count), 0);
                    if (uc_mem_write(engine, address + old_size, zeros.data(), zeros.size()) != UC_ERR_OK) {
                        set_import_memory_fault(engine, self, address + old_size, zero_count, UC_MEM_WRITE);
                        return 0;
                    }
                    append_memory_access(engine, address + old_size,
                        static_cast<int>((std::min<std::uint64_t>)(zero_count,
                            static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))),
                        0, true, false, &self);
                }
                current->second = requested;
                return address;
            }
            if (in_place_only) return 0;
            const auto bytes_to_preserve = (std::min)(old_size, requested);
            std::vector<std::uint8_t> old_bytes(static_cast<std::size_t>(bytes_to_preserve));
            if (uc_mem_read(engine, address, old_bytes.data(), old_bytes.size()) != UC_ERR_OK) {
                set_import_memory_fault(engine, self, address, bytes_to_preserve, UC_MEM_READ);
                return 0;
            }
            if (bytes_to_preserve) append_memory_access(engine, address,
                static_cast<int>((std::min<std::uint64_t>)(bytes_to_preserve,
                    static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))),
                0, false, false, &self);
            const auto replacement = allocate_guest(requested, zero_new);
            if (!replacement) return 0;
            if (bytes_to_preserve && uc_mem_write(engine, replacement, old_bytes.data(), old_bytes.size()) != UC_ERR_OK) {
                (void)release_guest(replacement);
                set_import_memory_fault(engine, self, replacement, bytes_to_preserve, UC_MEM_WRITE);
                return 0;
            }
            if (bytes_to_preserve) append_memory_access(engine, replacement,
                static_cast<int>((std::min<std::uint64_t>)(bytes_to_preserve,
                    static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))),
                0, true, false, &self);
            (void)release_guest(address);
            return replacement;
        };
        const auto write_guest = [&](std::uint64_t address, const void* value, std::size_t size) {
            if (accessible_prefix(self, address, size, UC_PROT_WRITE) != size) {
                set_import_memory_fault(engine, self, address, size, UC_MEM_WRITE);
                return false;
            }
            if (uc_mem_write(engine, address, value, size) != UC_ERR_OK) {
                set_import_memory_fault(engine, self, address, size, UC_MEM_WRITE);
                return false;
            }
            if (size) append_memory_access(engine, address,
                size > static_cast<std::size_t>((std::numeric_limits<int>::max)())
                    ? (std::numeric_limits<int>::max)() : static_cast<int>(size), 0, true, false, &self);
            return true;
        };
        constexpr std::uint64_t guest_page_size = 0x1000;
        constexpr std::uint64_t max_virtual_memory = 256ull * 1024 * 1024;
        const auto rounded_page_size = [](std::uint64_t size) {
            return size && size <= UINT64_MAX - 0xfffull ? (size + 0xfffull) & ~std::uint64_t{0xfff} : 0;
        };
        const auto rounded_page_range = [&](std::uint64_t address, std::uint64_t requested_size,
                                            std::uint64_t& base, std::uint64_t& size) {
            if (!requested_size || requested_size > UINT64_MAX - address) return false;
            base = address & ~(guest_page_size - 1);
            const auto end = rounded_page_size(address + requested_size);
            if (!end || end <= base) return false;
            size = end - base;
            return true;
        };
        const auto to_guest_permissions = [](std::uint64_t protection, std::uint32_t& permissions) {
            switch (protection) {
            case 0x01: permissions = 0; return true; // PAGE_NOACCESS
            case 0x02: permissions = UC_PROT_READ; return true; // PAGE_READONLY
            case 0x04: case 0x08: permissions = UC_PROT_READ | UC_PROT_WRITE; return true;
            case 0x10: permissions = UC_PROT_EXEC; return true; // PAGE_EXECUTE
            case 0x20: permissions = UC_PROT_READ | UC_PROT_EXEC; return true;
            case 0x40: case 0x80: permissions = UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC; return true;
            default: return false;
            }
        };
        const auto to_windows_protection = [](std::uint32_t permissions) -> std::uint32_t {
            switch (permissions & (UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)) {
            case UC_PROT_READ: return 0x02;
            case UC_PROT_READ | UC_PROT_WRITE: return 0x04;
            case UC_PROT_EXEC: return 0x10;
            case UC_PROT_READ | UC_PROT_EXEC: return 0x20;
            case UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC: return 0x40;
            default: return 0x01;
            }
        };
        const auto find_virtual_region = [&](std::uint64_t address, std::uint64_t size) {
            auto region = self.windows_virtual_allocations.upper_bound(address);
            if (region != self.windows_virtual_allocations.begin()) --region;
            if (region == self.windows_virtual_allocations.end() || address < region->first ||
                address - region->first > region->second || size > region->second - (address - region->first))
                return self.windows_virtual_allocations.end();
            return region;
        };
        const auto virtual_query = [&]() -> std::uint64_t {
            constexpr std::uint32_t mem_commit = 0x1000;
            constexpr std::uint32_t mem_reserve = 0x2000;
            constexpr std::uint32_t mem_free = 0x10000;
            constexpr std::uint32_t mem_private = 0x20000;
            constexpr std::uint32_t mem_image = 0x1000000;
            const bool query_ex = name == "VirtualQueryEx";
            const auto current_process = is64 ? UINT64_MAX : static_cast<std::uint64_t>(UINT32_MAX);
            if (query_ex && first != current_process) {
                self.guest_last_error = 6; // ERROR_INVALID_HANDLE
                return 0;
            }
            const auto address = query_ex ? second : first;
            const auto buffer = query_ex ? third : second;
            const auto buffer_size = query_ex ? fourth : third;
            const auto maximum_user_address = is64 ? 0x00007FFFFFFEFFFFull : 0x7FFFFFFFull;
            if (address > maximum_user_address) {
                self.guest_last_error = 87; // ERROR_INVALID_PARAMETER
                return 0;
            }
            const auto last_page = maximum_user_address & ~(guest_page_size - 1);
            const auto maximum_user_end = last_page + guest_page_size;
            const auto page = address & ~(guest_page_size - 1);

            using PageAttributes = WindowsPageAttributes;
            const auto attributes_at = [&](std::uint64_t queried_page, PageAttributes& attributes) {
                const auto permissions = self.page_permissions.find(queried_page);
                if (permissions == self.page_permissions.end()) return false;
                attributes = PageAttributes{};
                attributes.state = mem_commit;
                attributes.protect = to_windows_protection(permissions->second);
                attributes.allocation_protect = attributes.protect;
                attributes.type = mem_private;
                if (self.image_pages.contains(queried_page)) {
                    attributes.allocation_base = self.main_module_handle;
                    attributes.type = mem_image;
                } else if (const auto allocation = find_virtual_region(queried_page, guest_page_size);
                           allocation != self.windows_virtual_allocations.end()) {
                    attributes.allocation_base = allocation->first;
                    if (!self.windows_committed_pages.contains(queried_page)) {
                        attributes.state = mem_reserve;
                        attributes.protect = 0;
                    }
                    if (const auto initial = self.windows_virtual_allocation_protections.find(allocation->first);
                        initial != self.windows_virtual_allocation_protections.end())
                        attributes.allocation_protect = initial->second;
                } else {
                    auto mapping = self.guest_mappings.upper_bound(queried_page);
                    if (mapping != self.guest_mappings.begin()) --mapping;
                    if (mapping != self.guest_mappings.end() && queried_page >= mapping->first &&
                        queried_page - mapping->first < mapping->second.size)
                        attributes.allocation_base = mapping->first;
                    else if (queried_page >= self.stack_base && queried_page - self.stack_base < self.stack_size)
                        attributes.allocation_base = self.stack_base;
                    else if (queried_page >= self.heap_base && queried_page - self.heap_base < self.heap_cursor)
                        attributes.allocation_base = self.heap_base;
                    else
                        attributes.allocation_base = queried_page;
                    if (const auto initial = self.initial_page_permissions.find(queried_page);
                        initial != self.initial_page_permissions.end())
                        attributes.allocation_protect = to_windows_protection(initial->second);
                }
                return true;
            };

            PageAttributes attributes{};
            const bool current = attributes_at(page, attributes);
            std::uint64_t region_begin = page;
            std::uint64_t region_end = page + guest_page_size;
            if (current) {
                while (region_begin >= guest_page_size) {
                    PageAttributes previous{};
                    if (!attributes_at(region_begin - guest_page_size, previous) || !(previous == attributes)) break;
                    region_begin -= guest_page_size;
                }
                while (region_end <= last_page) {
                    PageAttributes next{};
                    if (!attributes_at(region_end, next) || !(next == attributes)) break;
                    region_end += guest_page_size;
                }
            } else {
                const auto next = self.page_permissions.lower_bound(page);
                if (next != self.page_permissions.begin()) {
                    const auto previous = std::prev(next);
                    region_begin = previous->first + guest_page_size;
                } else {
                    region_begin = 0;
                }
                region_end = next == self.page_permissions.end() ? maximum_user_end : next->first;
                if (region_begin > page || region_end <= page) {
                    self.guest_last_error = 87; // ERROR_INVALID_PARAMETER
                    return 0;
                }
                attributes.state = mem_free;
            }

            const std::size_t structure_size = is64 ? 48u : 28u;
            if (buffer_size < structure_size) {
                self.guest_last_error = 24; // ERROR_BAD_LENGTH
                return 0;
            }
            std::array<std::uint8_t, 48> information{};
            const auto store_field = [&](std::size_t offset, std::uint64_t value, std::size_t width) {
                for (std::size_t index = 0; index < width; ++index)
                    information[offset + index] = static_cast<std::uint8_t>(value >> (index * 8));
            };
            if (is64) {
                store_field(0, region_begin, 8);
                store_field(8, attributes.allocation_base, 8);
                store_field(16, attributes.allocation_protect, 4);
                store_field(24, region_end - region_begin, 8);
                store_field(32, attributes.state, 4);
                store_field(36, attributes.protect, 4);
                store_field(40, attributes.type, 4);
            } else {
                store_field(0, region_begin, 4);
                store_field(4, attributes.allocation_base, 4);
                store_field(8, attributes.allocation_protect, 4);
                store_field(12, region_end - region_begin, 4);
                store_field(16, attributes.state, 4);
                store_field(20, attributes.protect, 4);
                store_field(24, attributes.type, 4);
            }
            if (!write_guest(buffer, information.data(), structure_size)) return 0;
            return structure_size;
        };
        const auto protect_page_runs = [&](const std::vector<std::uint64_t>& pages, std::uint32_t permissions) {
            for (std::size_t index = 0; index < pages.size();) {
                auto next = index + 1;
                while (next < pages.size() && pages[next - 1] <= UINT64_MAX - guest_page_size &&
                       pages[next] == pages[next - 1] + guest_page_size) ++next;
                const auto size = static_cast<std::uint64_t>(next - index) * guest_page_size;
                if (uc_mem_protect(engine, pages[index], static_cast<std::size_t>(size), permissions) != UC_ERR_OK)
                    return false;
                index = next;
            }
            return true;
        };
        const auto zero_guest_range = [&](std::uint64_t address, std::uint64_t size) {
            constexpr std::size_t chunk_size = 64 * 1024;
            const std::vector<std::uint8_t> zeros(chunk_size, 0);
            std::uint64_t offset = 0;
            while (offset < size) {
                const auto count = static_cast<std::size_t>((std::min<std::uint64_t>)(chunk_size, size - offset));
                if (uc_mem_write(engine, address + offset, zeros.data(), count) != UC_ERR_OK) return false;
                append_memory_access(engine, address + offset, static_cast<int>(count), 0, true, false, &self);
                offset += count;
            }
            return true;
        };
        const auto virtual_alloc = [&]() -> std::uint64_t {
            constexpr std::uint64_t mem_commit = 0x1000;
            constexpr std::uint64_t mem_reserve = 0x2000;
            constexpr std::uint64_t mem_top_down = 0x100000;
            const bool reserve = (third & mem_reserve) != 0;
            const bool commit = (third & mem_commit) != 0;
            std::uint32_t permissions{};
            std::uint64_t base = self.windows_virtual_base;
            std::uint64_t size = rounded_page_size(second);
            const auto address_limit = is64 ? UINT64_MAX : 0x1'0000'0000ull;
            if ((!reserve && !commit) || (third & ~(mem_commit | mem_reserve | mem_top_down)) != 0 ||
                !size || size > max_virtual_memory || !to_guest_permissions(fourth, permissions)) return 0;
            if (first && !rounded_page_range(first, second, base, size)) return 0;
            if (size > max_virtual_memory) return 0;

            if (reserve) {
                if (size > max_virtual_memory - self.windows_virtual_reserved_bytes) return 0;
                if (!base) base = guest_page_size;
                bool conflict = false;
                while (base <= address_limit - size) {
                    const auto mapped = self.page_permissions.lower_bound(base);
                    conflict = mapped != self.page_permissions.end() && mapped->first < base + size;
                    if (!conflict) break;
                    if (first || mapped->first > address_limit - guest_page_size) return 0;
                    base = mapped->first + guest_page_size;
                }
                if (conflict || base > address_limit - size) return 0;
                const auto initial_permissions = commit ? permissions : 0u;
                if (uc_mem_map(engine, base, static_cast<std::size_t>(size), initial_permissions) != UC_ERR_OK) return 0;
                self.windows_virtual_allocations.emplace(base, size);
                self.windows_virtual_allocation_protections[base] = to_windows_protection(permissions);
                self.windows_virtual_reserved_bytes += size;
                for (auto page = base; page < base + size; page += guest_page_size) {
                    self.page_permissions[page] = initial_permissions;
                    self.initial_page_permissions[page] = initial_permissions;
                    if (commit) self.windows_committed_pages.insert(page);
                }
                if (commit) self.windows_virtual_committed_bytes += size;
                if (commit && !zero_guest_range(base, size)) {
                    (void)uc_mem_unmap(engine, base, static_cast<std::size_t>(size));
                    for (auto page = base; page < base + size; page += guest_page_size) {
                        self.page_permissions.erase(page);
                        self.initial_page_permissions.erase(page);
                        self.windows_committed_pages.erase(page);
                    }
                    self.windows_virtual_allocations.erase(base);
                    self.windows_virtual_allocation_protections.erase(base);
                    self.windows_virtual_reserved_bytes -= size;
                    self.windows_virtual_committed_bytes -= size;
                    return 0;
                }
                return base;
            }

            if (!first) return 0;
            if (base > address_limit - size) return 0;
            const auto region = find_virtual_region(base, size);
            if (region == self.windows_virtual_allocations.end()) return 0;
            std::vector<std::uint64_t> new_pages;
            for (auto page = base; page < base + size; page += guest_page_size) {
                if (!self.page_permissions.contains(page)) return 0;
                if (!self.windows_committed_pages.contains(page)) new_pages.push_back(page);
            }
            const auto newly_committed = static_cast<std::uint64_t>(new_pages.size()) * guest_page_size;
            if (newly_committed > max_virtual_memory - self.windows_virtual_committed_bytes) return 0;
            if (new_pages.empty()) return base;

            std::vector<std::uint64_t> changed_pages;
            for (std::size_t index = 0; index < new_pages.size();) {
                auto next = index + 1;
                while (next < new_pages.size() && new_pages[next] == new_pages[next - 1] + guest_page_size) ++next;
                const auto run_size = static_cast<std::uint64_t>(next - index) * guest_page_size;
                if (uc_mem_protect(engine, new_pages[index], static_cast<std::size_t>(run_size), permissions) != UC_ERR_OK) {
                    (void)protect_page_runs(changed_pages, 0);
                    return 0;
                }
                changed_pages.insert(changed_pages.end(), new_pages.begin() + static_cast<std::ptrdiff_t>(index),
                                     new_pages.begin() + static_cast<std::ptrdiff_t>(next));
                index = next;
            }
            for (const auto page : new_pages) {
                self.page_permissions[page] = permissions;
                self.windows_committed_pages.insert(page);
            }
            self.windows_virtual_committed_bytes += newly_committed;
            for (std::size_t index = 0; index < new_pages.size();) {
                auto next = index + 1;
                while (next < new_pages.size() && new_pages[next] == new_pages[next - 1] + guest_page_size) ++next;
                const auto run_size = static_cast<std::uint64_t>(next - index) * guest_page_size;
                if (!zero_guest_range(new_pages[index], run_size)) {
                    (void)protect_page_runs(new_pages, 0);
                    for (const auto page : new_pages) {
                        self.page_permissions[page] = 0;
                        self.windows_committed_pages.erase(page);
                    }
                    self.windows_virtual_committed_bytes -= newly_committed;
                    return 0;
                }
                index = next;
            }
            return base;
        };
        const auto virtual_free = [&]() -> std::uint64_t {
            constexpr std::uint64_t mem_decommit = 0x4000;
            constexpr std::uint64_t mem_release = 0x8000;
            if (third == mem_release) {
                if (second != 0) return 0;
                const auto region = self.windows_virtual_allocations.find(first);
                if (region == self.windows_virtual_allocations.end()) return 0;
                const auto size = region->second;
                if (uc_mem_unmap(engine, first, static_cast<std::size_t>(size)) != UC_ERR_OK) return 0;
                for (auto page = first; page < first + size; page += guest_page_size) {
                    self.page_permissions.erase(page);
                    self.initial_page_permissions.erase(page);
                    if (self.windows_committed_pages.erase(page))
                        self.windows_virtual_committed_bytes -= guest_page_size;
                }
                self.windows_virtual_allocations.erase(region);
                self.windows_virtual_allocation_protections.erase(first);
                self.windows_virtual_reserved_bytes -= size;
                return 1;
            }
            if (third != mem_decommit || !second) return 0;
            std::uint64_t base{}, size{};
            if (!rounded_page_range(first, second, base, size)) return 0;
            const auto region = find_virtual_region(base, size);
            if (region == self.windows_virtual_allocations.end() ||
                uc_mem_protect(engine, base, static_cast<std::size_t>(size), 0) != UC_ERR_OK) return 0;
            for (auto page = base; page < base + size; page += guest_page_size) {
                self.page_permissions[page] = 0;
                if (self.windows_committed_pages.erase(page))
                    self.windows_virtual_committed_bytes -= guest_page_size;
            }
            return 1;
        };
        const auto virtual_protect = [&]() -> std::uint64_t {
            std::uint32_t permissions{};
            if (!second || !fourth || !to_guest_permissions(third, permissions) ||
                second > UINT64_MAX - first) return 0;
            const auto begin = first & ~(guest_page_size - 1);
            const auto end = rounded_page_size(first + second);
            if (!end || end <= begin) return 0;
            const auto size = end - begin;
            if (accessible_prefix(self, begin, size, 0) != size) return 0;
            for (auto page = begin; page < end; page += guest_page_size) {
                auto region = self.windows_virtual_allocations.upper_bound(page);
                if (region != self.windows_virtual_allocations.begin()) --region;
                const bool reserved_virtual_page = region != self.windows_virtual_allocations.end() &&
                    page >= region->first && page - region->first < region->second;
                if (reserved_virtual_page && !self.windows_committed_pages.contains(page)) return 0;
            }
            if (accessible_prefix(self, fourth, sizeof(std::uint32_t), UC_PROT_WRITE) != sizeof(std::uint32_t)) {
                set_import_memory_fault(engine, self, fourth, sizeof(std::uint32_t), UC_MEM_WRITE);
                return 0;
            }
            const auto previous = to_windows_protection(self.page_permissions.at(begin));
            if (!write_guest(fourth, &previous, sizeof(previous))) return 0;
            if (uc_mem_protect(engine, begin, static_cast<std::size_t>(size), permissions) != UC_ERR_OK) return 0;
            for (auto page = begin; page < end; page += guest_page_size) self.page_permissions[page] = permissions;
            return 1;
        };
        std::uint64_t result = first;
        if (name == "CreateFileA" || name == "CreateFileW") {
            std::string requested_path, normalized_path;
            bool supported_encoding = true;
            if (!read_guest_string(first, name == "CreateFileW", requested_path, supported_encoding)) return false;
            if (!supported_encoding || !normalize_guest_file_path(requested_path, normalized_path) || seventh) {
                self.guest_last_error = seventh ? 87 : 123; // invalid parameter / invalid name
                result = is64 ? UINT64_MAX : UINT32_MAX;
            } else {
                constexpr std::uint64_t generic_read = 0x80000000ull;
                constexpr std::uint64_t generic_write = 0x40000000ull;
                constexpr std::uint64_t file_read_data = 0x1ull;
                constexpr std::uint64_t file_write_data = 0x2ull;
                constexpr std::uint64_t file_append_data = 0x4ull;
                constexpr std::uint64_t generic_all = 0x10000000ull;
                const bool readable = (second & (generic_read | file_read_data | generic_all)) != 0;
                const bool writable = (second & (generic_write | file_write_data | file_append_data | generic_all)) != 0;
                const auto disposition = static_cast<std::uint32_t>(fifth);
                auto file = self.guest_files.find(normalized_path);
                const bool exists = file != self.guest_files.end();
                bool create = false, truncate = false;
                if (disposition == 1) { // CREATE_NEW
                    if (exists) { self.guest_last_error = 80; result = is64 ? UINT64_MAX : UINT32_MAX; }
                    else create = true;
                } else if (disposition == 2) { // CREATE_ALWAYS
                    if (!writable) { self.guest_last_error = 5; result = is64 ? UINT64_MAX : UINT32_MAX; }
                    else { create = !exists; truncate = exists; }
                } else if (disposition == 3) { // OPEN_EXISTING
                    if (!exists) { self.guest_last_error = 2; result = is64 ? UINT64_MAX : UINT32_MAX; }
                } else if (disposition == 4) { // OPEN_ALWAYS
                    create = !exists;
                    if (exists) self.guest_last_error = 183;
                } else if (disposition == 5) { // TRUNCATE_EXISTING
                    if (!exists) { self.guest_last_error = 2; result = is64 ? UINT64_MAX : UINT32_MAX; }
                    else if (!writable) { self.guest_last_error = 5; result = is64 ? UINT64_MAX : UINT32_MAX; }
                    else truncate = true;
                } else {
                    self.guest_last_error = 87;
                    result = is64 ? UINT64_MAX : UINT32_MAX;
                }
                if (result == first) {
                    if (create) {
                        if (self.guest_files.size() >= 65'536) {
                            self.guest_last_error = 8;
                            result = is64 ? UINT64_MAX : UINT32_MAX;
                        } else {
                            file = self.guest_files.emplace(normalized_path, std::vector<std::uint8_t>{}).first;
                        }
                    }
                    if (result == first && truncate && file != self.guest_files.end()) {
                        self.guest_file_bytes -= file->second.size();
                        file->second.clear();
                    }
                    if (result == first) {
                        const auto max_handle = is64 ? UINT64_MAX : static_cast<std::uint64_t>(UINT32_MAX);
                        if (!self.next_guest_file_handle || self.next_guest_file_handle > max_handle - 0x10000) {
                            self.guest_last_error = 8;
                            result = is64 ? UINT64_MAX : UINT32_MAX;
                        } else {
                            result = self.next_guest_file_handle;
                            self.next_guest_file_handle += 0x10000;
                            self.guest_file_handles.emplace(result, GuestFileHandle{
                                normalized_path, 0, readable, writable,
                                (second & file_append_data) != 0 && (second & generic_write) == 0});
                        }
                    }
                }
            }
        } else if (name == "ReadFile") {
            const auto opened = self.guest_file_handles.find(first);
            if (opened == self.guest_file_handles.end()) {
                self.guest_last_error = 6; // ERROR_INVALID_HANDLE
                result = 0;
            } else if (!opened->second.readable) {
                self.guest_last_error = 5; // ERROR_ACCESS_DENIED
                result = 0;
            } else if (fifth) {
                self.guest_last_error = 87; // OVERLAPPED I/O is not modeled.
                result = 0;
            } else if (third > max_copy || third > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
                self.guest_last_error = 87;
                result = 0;
            } else {
                auto file = self.guest_files.find(opened->second.path);
                if (file == self.guest_files.end()) {
                    self.guest_last_error = 6;
                    result = 0;
                } else {
                    const auto available = opened->second.position < file->second.size()
                        ? static_cast<std::uint64_t>(file->second.size()) - opened->second.position : 0;
                    const auto count = (std::min)(third, available);
                    if (count && accessible_prefix(self, second, count, UC_PROT_WRITE) != count) {
                        set_import_memory_fault(engine, self, second, count, UC_MEM_WRITE);
                        return false;
                    }
                    if (count && uc_mem_write(engine, second,
                        file->second.data() + static_cast<std::size_t>(opened->second.position),
                        static_cast<std::size_t>(count)) != UC_ERR_OK) {
                        set_import_memory_fault(engine, self, second, count, UC_MEM_WRITE);
                        return false;
                    }
                    if (count) append_memory_access(engine, second,
                        static_cast<int>((std::min<std::uint64_t>)(count, static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))),
                        0, true, false, &self);
                    if (fourth) {
                        const auto count32 = static_cast<std::uint32_t>(count);
                        if (!write_guest(fourth, &count32, sizeof(count32))) return false;
                    }
                    opened->second.position += count;
                    result = 1;
                }
            }
        } else if (name == "WriteFile") {
            const auto opened = self.guest_file_handles.find(first);
            if (opened == self.guest_file_handles.end()) {
                self.guest_last_error = 6;
                result = 0;
            } else if (!opened->second.writable) {
                self.guest_last_error = 5;
                result = 0;
            } else if (fifth) {
                self.guest_last_error = 87;
                result = 0;
            } else if (third > max_copy || third > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
                self.guest_last_error = 87;
                result = 0;
            } else {
                auto file = self.guest_files.find(opened->second.path);
                if (file == self.guest_files.end()) {
                    self.guest_last_error = 6;
                    result = 0;
                } else {
                    const auto write_position = opened->second.append ? static_cast<std::uint64_t>(file->second.size()) : opened->second.position;
                    if (write_position > max_heap || third > max_heap - write_position) {
                        self.guest_last_error = 112; // ERROR_DISK_FULL (virtual store limit)
                        result = 0;
                    } else if (third && accessible_prefix(self, second, third, UC_PROT_READ) != third) {
                        set_import_memory_fault(engine, self, second, third, UC_MEM_READ);
                        return false;
                    } else {
                        const auto end_position = write_position + third;
                        const auto old_size = static_cast<std::uint64_t>(file->second.size());
                        const auto new_size = (std::max)(old_size, end_position);
                        const auto growth = new_size - old_size;
                        if (growth > max_heap - self.guest_file_bytes) {
                            self.guest_last_error = 112;
                            result = 0;
                        } else {
                            std::vector<std::uint8_t> bytes(static_cast<std::size_t>(third));
                            if (third && uc_mem_read(engine, second, bytes.data(), bytes.size()) != UC_ERR_OK) {
                                set_import_memory_fault(engine, self, second, third, UC_MEM_READ);
                                return false;
                            }
                            if (third) append_memory_access(engine, second,
                                static_cast<int>((std::min<std::uint64_t>)(third, static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))),
                                0, false, false, &self);
                            file->second.resize(static_cast<std::size_t>(new_size), 0);
                            if (third) std::copy(bytes.begin(), bytes.end(),
                                file->second.begin() + static_cast<std::ptrdiff_t>(write_position));
                            self.guest_file_bytes += growth;
                            opened->second.position = end_position;
                            if (fourth) {
                                const auto count32 = static_cast<std::uint32_t>(third);
                                if (!write_guest(fourth, &count32, sizeof(count32))) return false;
                            }
                            result = 1;
                        }
                    }
                }
            }
        } else if (name == "GetFileAttributesA" || name == "GetFileAttributesW") {
            std::string requested_path, normalized_path;
            bool supported_encoding = true;
            if (!read_guest_string(first, name == "GetFileAttributesW", requested_path, supported_encoding)) return false;
            if (!supported_encoding || !normalize_guest_file_path(requested_path, normalized_path)) {
                self.guest_last_error = 123; // ERROR_INVALID_NAME
                result = UINT32_MAX; // INVALID_FILE_ATTRIBUTES
            } else if (!self.guest_files.contains(normalized_path)) {
                self.guest_last_error = 2; // ERROR_FILE_NOT_FOUND
                result = UINT32_MAX;
            } else {
                result = 0x80; // FILE_ATTRIBUTE_NORMAL; directories are not modeled.
            }
        } else if (name == "CloseHandle") {
            result = self.guest_file_handles.erase(first) ? 1 : 0;
            if (!result) self.guest_last_error = 6;
        } else if (name == "GetFileSize" || name == "GetFileSizeEx") {
            const auto opened = self.guest_file_handles.find(first);
            const auto file = opened == self.guest_file_handles.end()
                ? self.guest_files.end() : self.guest_files.find(opened->second.path);
            if (file == self.guest_files.end()) {
                self.guest_last_error = 6;
                result = name == "GetFileSizeEx" ? 0 : UINT32_MAX;
            } else {
                const auto file_size = static_cast<std::uint64_t>(file->second.size());
                if (name == "GetFileSizeEx") {
                    if (!second || !write_guest(second, &file_size, sizeof(file_size))) return false;
                    result = 1;
                } else {
                    const auto high = static_cast<std::uint32_t>(file_size >> 32);
                    if (second && !write_guest(second, &high, sizeof(high))) return false;
                    result = static_cast<std::uint32_t>(file_size);
                }
            }
        } else if (name == "SetFilePointer") {
            const auto opened = self.guest_file_handles.find(first);
            if (opened == self.guest_file_handles.end()) {
                self.guest_last_error = 6;
                result = UINT32_MAX;
            } else {
                std::int32_t distance_high = 0;
                if (third) {
                    std::int32_t high_in{};
                    if (accessible_prefix(self, third, sizeof(high_in), UC_PROT_READ) != sizeof(high_in) ||
                        uc_mem_read(engine, third, &high_in, sizeof(high_in)) != UC_ERR_OK) {
                        set_import_memory_fault(engine, self, third, sizeof(high_in), UC_MEM_READ);
                        return false;
                    }
                    distance_high = high_in;
                } else {
                    distance_high = static_cast<std::int32_t>(second) < 0 ? -1 : 0;
                }
                const auto distance = static_cast<std::int64_t>(distance_high) * 0x1'0000'0000ll +
                    static_cast<std::uint32_t>(second);
                const auto file = self.guest_files.find(opened->second.path);
                const auto base = fourth == 0 ? std::uint64_t{0} : fourth == 1 ? opened->second.position :
                    fourth == 2 && file != self.guest_files.end() ? static_cast<std::uint64_t>(file->second.size()) : UINT64_MAX;
                if (fourth > 2 || base == UINT64_MAX || base > max_heap) {
                    self.guest_last_error = 87;
                    result = UINT32_MAX;
                } else {
                    std::uint64_t position{};
                    const auto magnitude = distance < 0 ? static_cast<std::uint64_t>(-(distance + 1)) + 1 :
                        static_cast<std::uint64_t>(distance);
                    if ((distance < 0 && magnitude > base) || (distance >= 0 && magnitude > max_heap - base)) {
                        self.guest_last_error = 87;
                        result = UINT32_MAX;
                    } else {
                        position = distance < 0 ? base - magnitude : base + magnitude;
                        if (third) {
                            const auto high_out = static_cast<std::int32_t>(position >> 32);
                            if (!write_guest(third, &high_out, sizeof(high_out))) return false;
                        }
                        opened->second.position = position;
                        result = static_cast<std::uint32_t>(position);
                    }
                }
            }
        } else if (name == "DeleteFileA" || name == "DeleteFileW") {
            std::string requested_path, normalized_path;
            bool supported_encoding = true;
            if (!read_guest_string(first, name == "DeleteFileW", requested_path, supported_encoding)) return false;
            if (!supported_encoding || !normalize_guest_file_path(requested_path, normalized_path)) {
                self.guest_last_error = 123;
                result = 0;
            } else {
                const bool open = std::any_of(self.guest_file_handles.begin(), self.guest_file_handles.end(),
                    [&](const auto& handle) { return handle.second.path == normalized_path; });
                const auto file = self.guest_files.find(normalized_path);
                if (file == self.guest_files.end()) {
                    self.guest_last_error = 2;
                    result = 0;
                } else if (open) {
                    self.guest_last_error = 5;
                    result = 0;
                } else {
                    self.guest_file_bytes -= file->second.size();
                    self.guest_files.erase(file);
                    result = 1;
                }
            }
        } else if (name == "LoadLibraryA" || name == "LoadLibraryW" ||
            name == "LoadLibraryExA" || name == "LoadLibraryExW") {
            const bool wide = name.back() == 'W';
            const bool extended = name.rfind("LoadLibraryEx", 0) == 0;
            std::string requested_module;
            bool supported_encoding = true;
            if (!read_guest_string(first, wide, requested_module, supported_encoding)) return false;
            bool windows_api = false, c_runtime = false;
            std::string normalized_module;
            if (!supported_encoding || !guest_module_kind(requested_module, windows_api, c_runtime, normalized_module)) {
                self.guest_last_error = 126; // ERROR_MOD_NOT_FOUND
                result = 0;
            } else if (extended && (second || (third & ~std::uint64_t{0x1F08}))) {
                self.guest_last_error = 87; // ERROR_INVALID_PARAMETER
                result = 0;
            } else if (const auto found = self.guest_modules.find(normalized_module);
                       found != self.guest_modules.end()) {
                if (found->second.references != UINT32_MAX) ++found->second.references;
                result = found->second.handle;
            } else {
                const auto max_handle = is64 ? UINT64_MAX : static_cast<std::uint64_t>(UINT32_MAX);
                if (!self.next_guest_module_handle || self.next_guest_module_handle > max_handle - 0x10000) {
                    self.guest_last_error = 8; // ERROR_NOT_ENOUGH_MEMORY
                    result = 0;
                } else {
                    const auto handle = self.next_guest_module_handle;
                    self.next_guest_module_handle += 0x10000;
                    self.guest_modules.emplace(normalized_module,
                        GuestModule{handle, 1, windows_api, c_runtime});
                    self.guest_module_names.emplace(handle, normalized_module);
                    result = handle;
                }
            }
        } else if (name == "GetModuleHandleA" || name == "GetModuleHandleW") {
            if (!first) {
                result = self.main_module_handle;
            } else {
                std::string requested_module;
                bool supported_encoding = true;
                if (!read_guest_string(first, name == "GetModuleHandleW", requested_module, supported_encoding))
                    return false;
                bool windows_api = false, c_runtime = false;
                std::string normalized_module;
                const auto module_known = supported_encoding &&
                    guest_module_kind(requested_module, windows_api, c_runtime, normalized_module);
                const auto loaded = module_known ? self.guest_modules.find(normalized_module) : self.guest_modules.end();
                if (loaded == self.guest_modules.end()) {
                    self.guest_last_error = 126; // ERROR_MOD_NOT_FOUND
                    result = 0;
                } else {
                    result = loaded->second.handle;
                }
            }
        } else if (name == "FreeLibrary") {
            const auto loaded_name = self.guest_module_names.find(first);
            if (loaded_name == self.guest_module_names.end()) {
                self.guest_last_error = 6; // ERROR_INVALID_HANDLE
                result = 0;
            } else {
                const auto loaded = self.guest_modules.find(loaded_name->second);
                if (loaded == self.guest_modules.end() || !loaded->second.references) {
                    self.guest_last_error = 6; // ERROR_INVALID_HANDLE
                    result = 0;
                } else if (--loaded->second.references == 0) {
                    self.guest_module_names.erase(loaded_name);
                    self.guest_modules.erase(loaded);
                    result = 1;
                } else {
                    result = 1;
                }
            }
        } else if (name == "GetProcAddress") {
            result = 0;
            const auto loaded_name = self.guest_module_names.find(first);
            if (loaded_name == self.guest_module_names.end()) {
                self.guest_last_error = 6; // ERROR_INVALID_HANDLE
            } else if (second <= 0xffffu) {
                self.guest_last_error = 127; // ERROR_PROC_NOT_FOUND (ordinals are not modeled)
            } else {
                std::string requested_function;
                bool supported_encoding = true;
                if (!read_guest_string(second, false, requested_function, supported_encoding)) return false;
                const auto loaded = self.guest_modules.find(loaded_name->second);
                if (loaded == self.guest_modules.end() || !supported_encoding ||
                    !guest_module_exports(loaded->second, requested_function)) {
                    self.guest_last_error = 127; // ERROR_PROC_NOT_FOUND
                } else {
                    result = create_dynamic_import_stub(engine, requested_function, self);
                    if (!result) self.guest_last_error = 8; // no guest trampoline capacity
                }
            }
        } else if (name == "GetTickCount" || name == "GetTickCount64") {
            result = self.guest_clock_ticks;
        } else if (name == "IsDebuggerPresent") {
            result = 0; // The sandboxed guest is not attached to a debugger.
        } else if (name == "GetCurrentProcessId" || name == "GetCurrentThreadId") {
            result = 1; // One deterministic virtual process and thread.
        } else if (name == "GetCurrentProcess" || name == "GetCurrentThread") {
            result = UINT64_MAX; // Windows pseudo-handle: (HANDLE)-1.
        } else if (name == "GetProcessHeap") {
            result = 0x7000; // Stable guest-only process-heap pseudo-handle.
        } else if (name == "GetLastError") {
            result = self.guest_last_error;
        } else if (name == "SetLastError") {
            self.guest_last_error = static_cast<std::uint32_t>(first);
            result = 0;
        } else if (name == "QueryPerformanceFrequency") {
            const std::uint64_t frequency = 10'000'000; // deterministic 10 MHz virtual clock
            if (!write_guest(first, &frequency, sizeof(frequency))) return false;
            result = 1;
        } else if (name == "QueryPerformanceCounter") {
            const std::uint64_t counter = self.guest_clock_ticks * 10'000;
            if (!write_guest(first, &counter, sizeof(counter))) return false;
            result = 1;
            ++self.guest_clock_ticks;
        } else if (name == "GetSystemTimeAsFileTime") {
            // Fixed 2023-11-14 epoch plus the deterministic guest clock, in 100 ns units.
            const std::uint64_t file_time = 133'444'736'000'000'000ull + self.guest_clock_ticks * 10'000;
            if (!write_guest(first, &file_time, sizeof(file_time))) return false;
            ++self.guest_clock_ticks;
            result = 0;
        } else if (name == "CheckRemoteDebuggerPresent") {
            const std::uint32_t not_debugged = 0;
            if (!write_guest(second, &not_debugged, sizeof(not_debugged))) return false;
            result = 1;
        } else if (name == "FlushInstructionCache") {
            const auto current_process = is64 ? UINT64_MAX : static_cast<std::uint64_t>(UINT32_MAX);
            if (first != current_process || (third && second > UINT64_MAX - third)) {
                result = 0;
            } else if (!third) {
                result = 1;
            } else {
                result = uc_ctl_remove_cache(engine, second, second + third) == UC_ERR_OK ? 1 : 0;
            }
        } else if (name == "HeapAlloc") {
            result = first == 0x7000 ? allocate_guest(third ? third : 1, (second & 0x8u) != 0) : 0;
        } else if (name == "HeapFree") {
            result = first == 0x7000 && third && release_guest(third) ? 1 : 0;
        } else if (name == "HeapReAlloc") {
            result = first == 0x7000
                ? reallocate_guest(third, fourth, (second & 0x8u) != 0, (second & 0x10u) != 0) : 0;
        } else if (name == "HeapSize") {
            const auto allocation = self.heap_allocations.find(third);
            result = first == 0x7000 && allocation != self.heap_allocations.end()
                ? allocation->second : UINT64_MAX;
        } else if (name == "HeapValidate") {
            result = first == 0x7000 && (!third || self.heap_allocations.contains(third)) ? 1 : 0;
        } else if (name == "VirtualAlloc") {
            result = virtual_alloc();
        } else if (name == "VirtualFree") {
            result = virtual_free();
        } else if (name == "VirtualProtect") {
            result = virtual_protect();
        } else if (name == "VirtualQuery" || name == "VirtualQueryEx") {
            result = virtual_query();
        } else if (name == "malloc") {
            result = allocate_guest(first, false);
        } else if (name == "calloc") {
            const auto requested = first && second > max_heap / first ? max_heap + 1 : first * second;
            result = allocate_guest(requested, true);
        } else if (name == "realloc") {
            result = !first && !second ? 0 : reallocate_guest(first, second, false, false);
        } else if (name == "free") {
            // Keep mapped pages available to the CPU engine; a guest allocator may
            // reuse or inspect a freed block, just as an OS heap often does.
            if (first) release_guest(first);
            result = 0;
        } else if (name == "memcpy" || name == "memmove") {
            if (third > max_copy || third > (std::numeric_limits<std::size_t>::max)()) return false;
            if (accessible_prefix(self, second, third, UC_PROT_READ) != third) {
                set_import_memory_fault(engine, self, second, third, UC_MEM_READ);
                return false;
            }
            if (accessible_prefix(self, first, third, UC_PROT_WRITE) != third) {
                set_import_memory_fault(engine, self, first, third, UC_MEM_WRITE);
                return false;
            }
            std::vector<std::uint8_t> buffer(static_cast<std::size_t>(third));
            if (third && uc_mem_read(engine, second, buffer.data(), buffer.size()) != UC_ERR_OK) {
                set_import_memory_fault(engine, self, second, third, UC_MEM_READ);
                return false;
            }
            if (third && uc_mem_write(engine, first, buffer.data(), buffer.size()) != UC_ERR_OK) {
                set_import_memory_fault(engine, self, first, third, UC_MEM_WRITE);
                return false;
            }
            if (third) {
                append_memory_access(engine, second, static_cast<int>((std::min<std::uint64_t>)(third, (std::numeric_limits<int>::max)())), 0, false, false, &self);
                append_memory_access(engine, first, static_cast<int>((std::min<std::uint64_t>)(third, (std::numeric_limits<int>::max)())), 0, true, false, &self);
            }
        } else if (name == "memset") {
            if (third > max_copy || third > (std::numeric_limits<std::size_t>::max)()) return false;
            if (accessible_prefix(self, first, third, UC_PROT_WRITE) != third) {
                set_import_memory_fault(engine, self, first, third, UC_MEM_WRITE);
                return false;
            }
            std::vector<std::uint8_t> buffer(static_cast<std::size_t>(third), static_cast<std::uint8_t>(second));
            if (third && uc_mem_write(engine, first, buffer.data(), buffer.size()) != UC_ERR_OK) {
                set_import_memory_fault(engine, self, first, third, UC_MEM_WRITE);
                return false;
            }
            if (third) append_memory_access(engine, first, static_cast<int>((std::min<std::uint64_t>)(third, (std::numeric_limits<int>::max)())), 0, true, false, &self);
        } else if (name == "memchr") {
            if (third > max_copy || third > (std::numeric_limits<std::size_t>::max)()) return false;
            const auto readable = accessible_prefix(self, first, third, UC_PROT_READ);
            result = 0;
            const auto wanted = static_cast<std::uint8_t>(second);
            std::uint64_t scanned = 0;
            for (; scanned < readable; ++scanned) {
                std::uint8_t value{};
                if (scanned > UINT64_MAX - first ||
                    uc_mem_read(engine, first + scanned, &value, 1) != UC_ERR_OK) {
                    set_import_memory_fault(engine, self, first + scanned, 1, UC_MEM_READ);
                    return false;
                }
                if (value == wanted) {
                    result = first + scanned;
                    ++scanned;
                    break;
                }
            }
            if (!result && readable < third) {
                set_import_memory_fault(engine, self, first + readable, 1, UC_MEM_READ);
                return false;
            }
            if (scanned) append_memory_access(engine, first,
                static_cast<int>((std::min<std::uint64_t>)(scanned, (std::numeric_limits<int>::max)())),
                0, false, false, &self);
        } else if (name == "memcmp") {
            const auto count = third;
            if (count > max_copy || count > (std::numeric_limits<std::size_t>::max)()) return false;
            if (accessible_prefix(self, first, count, UC_PROT_READ) != count) {
                set_import_memory_fault(engine, self, first, count, UC_MEM_READ);
                return false;
            }
            if (accessible_prefix(self, second, count, UC_PROT_READ) != count) {
                set_import_memory_fault(engine, self, second, count, UC_MEM_READ);
                return false;
            }
            std::vector<std::uint8_t> left(static_cast<std::size_t>(count)), right(static_cast<std::size_t>(count));
            if (count && (uc_mem_read(engine, first, left.data(), left.size()) != UC_ERR_OK ||
                          uc_mem_read(engine, second, right.data(), right.size()) != UC_ERR_OK)) {
                set_import_memory_fault(engine, self, first, count, UC_MEM_READ);
                return false;
            }
            if (count) {
                const auto event_size = static_cast<int>((std::min<std::uint64_t>)(count, (std::numeric_limits<int>::max)()));
                append_memory_access(engine, first, event_size, 0, false, false, &self);
                append_memory_access(engine, second, event_size, 0, false, false, &self);
            }
            result = 0;
            for (std::size_t index = 0; index < left.size(); ++index) {
                if (left[index] != right[index]) { result = left[index] < right[index] ? UINT64_MAX : 1; break; }
            }
        } else if (name == "strcat" || name == "strncat") {
            if (name == "strncat" && third > max_string_scan) return false;
            const auto destination_readable = accessible_prefix(self, first, max_string_scan, UC_PROT_READ);
            if (!destination_readable) {
                set_import_memory_fault(engine, self, first, 1, UC_MEM_READ);
                return false;
            }
            std::uint64_t destination_length = 0;
            bool destination_terminated = false;
            for (; destination_length < destination_readable; ++destination_length) {
                std::uint8_t character{};
                if (uc_mem_read(engine, first + destination_length, &character, 1) != UC_ERR_OK) {
                    set_import_memory_fault(engine, self, first + destination_length, 1, UC_MEM_READ);
                    return false;
                }
                if (!character) { destination_terminated = true; break; }
            }
            if (!destination_terminated) {
                if (destination_readable < max_string_scan)
                    set_import_memory_fault(engine, self, first + destination_readable, 1, UC_MEM_READ);
                return false;
            }
            const auto source_limit = name == "strncat" ? (std::min)(third, max_string_scan) : max_string_scan;
            std::uint64_t source_length = 0;
            if (source_limit) {
                const auto source_readable = accessible_prefix(self, second, source_limit, UC_PROT_READ);
                if (!source_readable) {
                    set_import_memory_fault(engine, self, second, 1, UC_MEM_READ);
                    return false;
                }
                bool source_terminated = false;
                for (; source_length < source_readable; ++source_length) {
                    std::uint8_t character{};
                    if (source_length > UINT64_MAX - second ||
                        uc_mem_read(engine, second + source_length, &character, 1) != UC_ERR_OK) {
                        set_import_memory_fault(engine, self, second + source_length, 1, UC_MEM_READ);
                        return false;
                    }
                    if (!character) { source_terminated = true; break; }
                }
                if (!source_terminated && name == "strcat") {
                    if (source_readable < max_string_scan)
                        set_import_memory_fault(engine, self, second + source_readable, 1, UC_MEM_READ);
                    return false;
                }
                if (!source_terminated && source_length < source_limit) {
                    set_import_memory_fault(engine, self, second + source_length, 1, UC_MEM_READ);
                    return false;
                }
                if (!source_terminated) source_length = source_limit;
            }
            if (destination_length > UINT64_MAX - first ||
                source_length > UINT64_MAX - destination_length - 1) {
                set_import_memory_fault(engine, self, first, destination_length + source_length + 1, UC_MEM_WRITE);
                return false;
            }
            const auto write_length = source_length + 1;
            const auto write_address = first + destination_length;
            if (accessible_prefix(self, write_address, write_length, UC_PROT_WRITE) != write_length) {
                set_import_memory_fault(engine, self, write_address, write_length, UC_MEM_WRITE);
                return false;
            }
            std::vector<std::uint8_t> buffer(static_cast<std::size_t>(write_length), 0);
            if (source_length && uc_mem_read(engine, second, buffer.data(), static_cast<std::size_t>(source_length)) != UC_ERR_OK) {
                set_import_memory_fault(engine, self, second, source_length, UC_MEM_READ);
                return false;
            }
            if (uc_mem_write(engine, write_address, buffer.data(), buffer.size()) != UC_ERR_OK) {
                set_import_memory_fault(engine, self, write_address, write_length, UC_MEM_WRITE);
                return false;
            }
            append_memory_access(engine, first, static_cast<int>(destination_length + 1), 0, false, false, &self);
            if (source_length) append_memory_access(engine, second,
                static_cast<int>((std::min<std::uint64_t>)(source_length + (name == "strcat" ? 1u : 0u),
                    (std::numeric_limits<int>::max)())), 0, false, false, &self);
            append_memory_access(engine, write_address, static_cast<int>(write_length), 0, true, false, &self);
            result = first;
        } else if (name == "strcpy") {
            const auto readable = accessible_prefix(self, second, max_string_scan, UC_PROT_READ);
            if (!readable) {
                set_import_memory_fault(engine, self, second, 1, UC_MEM_READ);
                return false;
            }
            std::uint64_t length = 0;
            bool terminated = false;
            for (; length < readable; ++length) {
                std::uint8_t character{};
                if (uc_mem_read(engine, second + length, &character, 1) != UC_ERR_OK) {
                    set_import_memory_fault(engine, self, second + length, 1, UC_MEM_READ);
                    return false;
                }
                if (!character) { terminated = true; break; }
            }
            if (!terminated) {
                if (readable < max_string_scan) set_import_memory_fault(engine, self, second + readable, 1, UC_MEM_READ);
                return false;
            }
            const auto count = length + 1;
            if (accessible_prefix(self, first, count, UC_PROT_WRITE) != count) {
                set_import_memory_fault(engine, self, first, count, UC_MEM_WRITE);
                return false;
            }
            std::vector<std::uint8_t> buffer(static_cast<std::size_t>(count));
            if (uc_mem_read(engine, second, buffer.data(), buffer.size()) != UC_ERR_OK) {
                set_import_memory_fault(engine, self, second, count, UC_MEM_READ);
                return false;
            }
            if (uc_mem_write(engine, first, buffer.data(), buffer.size()) != UC_ERR_OK) {
                set_import_memory_fault(engine, self, first, count, UC_MEM_WRITE);
                return false;
            }
            append_memory_access(engine, second, static_cast<int>(count), 0, false, false, &self);
            append_memory_access(engine, first, static_cast<int>(count), 0, true, false, &self);
        } else if (name == "strchr" || name == "strrchr") {
            const auto readable = accessible_prefix(self, first, max_string_scan, UC_PROT_READ);
            if (!readable) {
                set_import_memory_fault(engine, self, first, 1, UC_MEM_READ);
                return false;
            }
            const auto wanted = static_cast<std::uint8_t>(second);
            bool terminated = false;
            result = 0;
            std::uint64_t scanned = 0;
            for (; scanned < readable; ++scanned) {
                std::uint8_t character{};
                if (scanned > UINT64_MAX - first ||
                    uc_mem_read(engine, first + scanned, &character, 1) != UC_ERR_OK) {
                    set_import_memory_fault(engine, self, first + scanned, 1, UC_MEM_READ);
                    return false;
                }
                if (character == wanted) {
                    result = first + scanned;
                    if (name == "strchr") { ++scanned; terminated = true; break; }
                }
                if (!character) { terminated = true; ++scanned; break; }
            }
            if (!terminated) {
                if (readable < max_string_scan) set_import_memory_fault(engine, self, first + readable, 1, UC_MEM_READ);
                return false;
            }
            if (scanned) append_memory_access(engine, first,
                static_cast<int>((std::min<std::uint64_t>)(scanned, (std::numeric_limits<int>::max)())),
                0, false, false, &self);
        } else if (name == "strspn" || name == "strcspn") {
            const auto set_readable = accessible_prefix(self, second, max_string_scan, UC_PROT_READ);
            if (!set_readable) {
                set_import_memory_fault(engine, self, second, 1, UC_MEM_READ);
                return false;
            }
            std::array<bool, 256> members{};
            std::uint64_t set_length = 0;
            bool set_terminated = false;
            for (; set_length < set_readable; ++set_length) {
                std::uint8_t character{};
                if (uc_mem_read(engine, second + set_length, &character, 1) != UC_ERR_OK) {
                    set_import_memory_fault(engine, self, second + set_length, 1, UC_MEM_READ);
                    return false;
                }
                if (!character) { set_terminated = true; ++set_length; break; }
                members[character] = true;
            }
            if (!set_terminated) {
                if (set_readable < max_string_scan)
                    set_import_memory_fault(engine, self, second + set_readable, 1, UC_MEM_READ);
                return false;
            }
            const auto input_readable = accessible_prefix(self, first, max_string_scan, UC_PROT_READ);
            if (!input_readable) {
                set_import_memory_fault(engine, self, first, 1, UC_MEM_READ);
                return false;
            }
            std::uint64_t length = 0;
            for (; length < input_readable; ++length) {
                std::uint8_t character{};
                if (uc_mem_read(engine, first + length, &character, 1) != UC_ERR_OK) {
                    set_import_memory_fault(engine, self, first + length, 1, UC_MEM_READ);
                    return false;
                }
                if (!character || members[character] != (name == "strspn")) { ++length; break; }
            }
            if (length == input_readable && input_readable < max_string_scan) {
                set_import_memory_fault(engine, self, first + input_readable, 1, UC_MEM_READ);
                return false;
            }
            result = length - 1;
            append_memory_access(engine, first, static_cast<int>((std::min<std::uint64_t>)(length,
                (std::numeric_limits<int>::max)())), 0, false, false, &self);
            append_memory_access(engine, second, static_cast<int>((std::min<std::uint64_t>)(set_length,
                (std::numeric_limits<int>::max)())), 0, false, false, &self);
        } else if (name == "strstr") {
            const auto needle_readable = accessible_prefix(self, second, max_string_scan, UC_PROT_READ);
            if (!needle_readable) {
                set_import_memory_fault(engine, self, second, 1, UC_MEM_READ);
                return false;
            }
            std::vector<std::uint8_t> needle;
            bool needle_terminated = false;
            for (std::uint64_t index = 0; index < needle_readable; ++index) {
                std::uint8_t character{};
                if (uc_mem_read(engine, second + index, &character, 1) != UC_ERR_OK) {
                    set_import_memory_fault(engine, self, second + index, 1, UC_MEM_READ);
                    return false;
                }
                if (!character) { needle_terminated = true; break; }
                needle.push_back(character);
            }
            if (!needle_terminated) {
                if (needle_readable < max_string_scan)
                    set_import_memory_fault(engine, self, second + needle_readable, 1, UC_MEM_READ);
                return false;
            }
            const auto needle_bytes_read = static_cast<std::uint64_t>(needle.size()) + 1;
            append_memory_access(engine, second, static_cast<int>((std::min<std::uint64_t>)(needle_bytes_read,
                (std::numeric_limits<int>::max)())), 0, false, false, &self);
            result = first;
            if (!needle.empty()) {
                result = 0;
                const auto haystack_readable = accessible_prefix(self, first, max_string_scan, UC_PROT_READ);
                if (!haystack_readable) {
                    set_import_memory_fault(engine, self, first, 1, UC_MEM_READ);
                    return false;
                }
                std::vector<std::size_t> prefix(needle.size());
                for (std::size_t index = 1, matched = 0; index < needle.size(); ++index) {
                    while (matched && needle[index] != needle[matched]) matched = prefix[matched - 1];
                    if (needle[index] == needle[matched]) ++matched;
                    prefix[index] = matched;
                }
                std::size_t matched = 0;
                std::uint64_t scanned = 0;
                bool finished = false;
                for (; scanned < haystack_readable; ++scanned) {
                    std::uint8_t character{};
                    if (uc_mem_read(engine, first + scanned, &character, 1) != UC_ERR_OK) {
                        set_import_memory_fault(engine, self, first + scanned, 1, UC_MEM_READ);
                        return false;
                    }
                    if (!character) { finished = true; ++scanned; break; }
                    while (matched && character != needle[matched]) matched = prefix[matched - 1];
                    if (character == needle[matched]) ++matched;
                    if (matched == needle.size()) {
                        result = first + scanned + 1 - needle.size();
                        ++scanned;
                        finished = true;
                        break;
                    }
                }
                if (!finished) {
                    if (haystack_readable < max_string_scan)
                        set_import_memory_fault(engine, self, first + haystack_readable, 1, UC_MEM_READ);
                    return false;
                }
                append_memory_access(engine, first, static_cast<int>((std::min<std::uint64_t>)(scanned,
                    (std::numeric_limits<int>::max)())), 0, false, false, &self);
            }
        } else if (name == "strcmp" || name == "strncmp") {
            const auto limit = name == "strncmp" ? (std::min)(third, max_string_scan) : max_string_scan;
            result = 0;
            if (limit) {
                const auto left_available = accessible_prefix(self, first, limit, UC_PROT_READ);
                const auto right_available = accessible_prefix(self, second, limit, UC_PROT_READ);
                const auto readable = (std::min)(left_available, right_available);
                if (!readable) {
                    set_import_memory_fault(engine, self, left_available ? second : first, 1, UC_MEM_READ);
                    return false;
                }
                std::uint64_t index = 0;
                bool finished = false;
                for (; index < readable; ++index) {
                    std::uint8_t left{}, right{};
                    if (uc_mem_read(engine, first + index, &left, 1) != UC_ERR_OK) {
                        set_import_memory_fault(engine, self, first + index, 1, UC_MEM_READ);
                        return false;
                    }
                    if (uc_mem_read(engine, second + index, &right, 1) != UC_ERR_OK) {
                        set_import_memory_fault(engine, self, second + index, 1, UC_MEM_READ);
                        return false;
                    }
                    if (left != right) {
                        result = left < right ? UINT64_MAX : 1;
                        finished = true;
                        ++index;
                        break;
                    }
                    if (!left) { finished = true; ++index; break; }
                }
                if (!finished && readable < limit) {
                    const auto bad_address = left_available < right_available ? first + readable : second + readable;
                    set_import_memory_fault(engine, self, bad_address, 1, UC_MEM_READ);
                    return false;
                }
                if (!finished && limit == max_string_scan) return false;
                if (index) {
                    const auto event_size = static_cast<int>(index);
                    append_memory_access(engine, first, event_size, 0, false, false, &self);
                    append_memory_access(engine, second, event_size, 0, false, false, &self);
                }
            }
        } else {
            const auto limit = name == "strnlen" ? (std::min)(second, max_string_scan) : max_string_scan;
            if (!limit) {
                result = 0;
            } else {
            const auto readable = accessible_prefix(self, first, limit, UC_PROT_READ);
            if (!readable) {
                set_import_memory_fault(engine, self, first, 1, UC_MEM_READ);
                return false;
            }
            result = 0;
            for (; result < readable; ++result) {
                std::uint8_t character{};
                if (result > (std::numeric_limits<std::uint64_t>::max)() - first) {
                    set_import_memory_fault(engine, self, first, result + 1, UC_MEM_READ);
                    return false;
                }
                if (uc_mem_read(engine, first + result, &character, 1) != UC_ERR_OK) {
                    set_import_memory_fault(engine, self, first + result, 1, UC_MEM_READ);
                    return false;
                }
                if (!character) break;
            }
            if (result == readable && result < limit) {
                set_import_memory_fault(engine, self, first + result, 1, UC_MEM_READ);
                return false;
            }
            if (name == "strlen" && result == max_string_scan) return false;
            if (result < readable) append_memory_access(engine, first, static_cast<int>(result + 1), 0, false, false, &self);
            else if (result) append_memory_access(engine, first, static_cast<int>((std::min<std::uint64_t>)(result, (std::numeric_limits<int>::max)())), 0, false, false, &self);
            }
        }
        if (arm64) return uc_reg_write(engine, UC_ARM64_REG_X0, &result) == UC_ERR_OK;
        if (is64) return uc_reg_write(engine, UC_X86_REG_RAX, &result) == UC_ERR_OK;
        const auto result32 = static_cast<std::uint32_t>(result);
        return uc_reg_write(engine, UC_X86_REG_EAX, &result32) == UC_ERR_OK;
    }

    static std::uint64_t accessible_prefix(const Impl& self, std::uint64_t address,
                                           std::uint64_t size, std::uint32_t required_permissions) {
        if (!size) return 0;
        if (size - 1 > (std::numeric_limits<std::uint64_t>::max)() - address) return 0;
        std::uint64_t cursor = address;
        std::uint64_t accessible = 0;
        constexpr std::uint64_t page_size = 0x1000;
        while (accessible < size) {
            const auto page = cursor & ~(page_size - 1);
            const auto permissions = self.page_permissions.find(page);
            if (permissions == self.page_permissions.end() ||
                (permissions->second & required_permissions) != required_permissions) break;
            const auto remaining_in_page = page_size - (cursor - page);
            const auto consumed = (std::min)(remaining_in_page, size - accessible);
            accessible += consumed;
            cursor += consumed;
        }
        return accessible;
    }

    static void set_import_memory_fault(uc_engine* engine, Impl& self, std::uint64_t address,
                                        std::uint64_t size, uc_mem_type access) {
        self.memory_fault = true;
        self.fault_address = address;
        self.fault_access = static_cast<int>(access);
        self.fault_size = size > static_cast<std::uint64_t>((std::numeric_limits<int>::max)())
            ? (std::numeric_limits<int>::max)() : static_cast<int>(size);
        (void)engine;
    }

    static bool on_unmapped_memory(uc_engine* engine, uc_mem_type access, std::uint64_t address,
                                   int size, std::int64_t, void* data) {
        auto& self = *static_cast<Impl*>(data);
        self.memory_fault = true;
        self.fault_address = address;
        self.fault_access = static_cast<int>(access);
        self.fault_size = size;
        uc_emu_stop(engine);
        return false;
    }

    static void append_memory_access(uc_engine* engine, std::uint64_t address, int size,
                                     std::uint64_t value, bool write, bool value_captured, void* data) {
        auto& self = *static_cast<Impl*>(data);
        if (size > 0) {
            const auto access_size = static_cast<std::uint64_t>(size);
            const auto access_end = access_size - 1 > (std::numeric_limits<std::uint64_t>::max)() - address
                ? (std::numeric_limits<std::uint64_t>::max)() : address + access_size - 1;
            for (const auto& watchpoint : self.watchpoints) {
                const auto watch_end = watchpoint.address + watchpoint.size - 1;
                if ((write ? watchpoint.on_write : watchpoint.on_read) &&
                    address <= watch_end && watchpoint.address <= access_end) {
                    self.watchpoint_hit = true;
                    self.watchpoint_write = write;
                    self.watchpoint_address = address;
                    uc_emu_stop(engine);
                    break;
                }
            }
        }
        if (self.memory_accesses.size() >= max_memory_accesses) {
            self.memory_accesses_were_truncated = true;
            return;
        }
        std::uint64_t instruction_address{};
        const auto pc_register = self.is_arm64 ? UC_ARM64_REG_PC :
            self.is_64_bit ? UC_X86_REG_RIP : UC_X86_REG_EIP;
        if (uc_reg_read(engine, pc_register, &instruction_address) != UC_ERR_OK) instruction_address = 0;
        self.memory_accesses.push_back({instruction_address, address, value,
            size > 0 ? static_cast<std::uint32_t>(size) : 0, write, value_captured});
    }

    static void on_memory_write(uc_engine* engine, uc_mem_type, std::uint64_t address,
                                int size, std::int64_t value, void* data) {
        append_memory_access(engine, address, size, static_cast<std::uint64_t>(value), true,
                             size > 0 && size <= 8, data);
    }

    static void on_memory_read_after(uc_engine* engine, uc_mem_type, std::uint64_t address,
                                     int size, std::int64_t, void* data) {
        std::uint64_t value = 0;
        bool captured = size > 0 && size <= static_cast<int>(sizeof(value));
        if (captured) {
            std::uint8_t raw[sizeof(value)]{};
            if (uc_mem_read(engine, address, raw, static_cast<std::size_t>(size)) != UC_ERR_OK) captured = false;
            else for (int index = 0; index < size; ++index)
                value |= static_cast<std::uint64_t>(raw[index]) << (index * 8);
        }
        append_memory_access(engine, address, size, value, false, captured, data);
    }
#endif
};

namespace {
#if defined(GANDON_HAS_UNICORN)
constexpr std::uint64_t kPageSize = 0x1000;
constexpr std::uint64_t kMaxMappedImage = 512ull * 1024 * 1024;
constexpr std::size_t kMaxEmulatedImports = 20000;

struct ImportStubRequest {
    std::uint64_t iat_address{};
    std::uint16_t stack_bytes{};
    std::string function_name;
};

std::uint16_t modeled_windows_stdcall_bytes(std::string name) {
    if (!name.empty() && name.front() == '_') name.erase(name.begin());
    const auto decoration = name.rfind('@');
    if (decoration != std::string::npos && decoration + 1 < name.size() &&
        std::all_of(name.begin() + static_cast<std::ptrdiff_t>(decoration + 1), name.end(),
                    [](unsigned char ch) { return ch >= '0' && ch <= '9'; }))
        name.resize(decoration);
    if (name == "SetLastError" || name == "QueryPerformanceCounter" ||
        name == "QueryPerformanceFrequency" || name == "GetSystemTimeAsFileTime") return 4;
    if (name == "LoadLibraryA" || name == "LoadLibraryW" || name == "FreeLibrary" ||
        name == "GetModuleHandleA" || name == "GetModuleHandleW") return 4;
    if (name == "GetProcAddress") return 8;
    if (name == "LoadLibraryExA" || name == "LoadLibraryExW") return 12;
    if (name == "CloseHandle" || name == "DeleteFileA" || name == "DeleteFileW" ||
        name == "GetFileAttributesA" || name == "GetFileAttributesW" ||
        name == "GetFileSizeEx") return 4;
    if (name == "GetFileSize") return 8;
    if (name == "SetFilePointer") return 16;
    if (name == "ReadFile" || name == "WriteFile") return 20;
    if (name == "CreateFileA" || name == "CreateFileW") return 28;
    if (name == "HeapAlloc" || name == "HeapFree" || name == "HeapSize" || name == "HeapValidate") return 12;
    if (name == "HeapReAlloc") return 16;
    if (name == "VirtualAlloc" || name == "VirtualProtect" || name == "VirtualQueryEx") return 16;
    if (name == "VirtualQuery") return 12;
    if (name == "VirtualFree") return 12;
    if (name == "CheckRemoteDebuggerPresent") return 8;
    if (name == "FlushInstructionCache") return 12;
    return 0;
}

std::vector<ImportStubRequest> pe_import_stub_requests(const BinaryImage& image) {
    std::vector<ImportStubRequest> result;
    const auto& bytes = image.bytes;
    const auto read16 = [&](std::size_t offset) -> std::uint16_t {
        return offset <= bytes.size() && bytes.size() - offset >= 2
            ? static_cast<std::uint16_t>(bytes[offset] | (bytes[offset + 1] << 8)) : 0;
    };
    const auto read32 = [&](std::size_t offset) -> std::uint32_t {
        return offset <= bytes.size() && bytes.size() - offset >= 4
            ? static_cast<std::uint32_t>(bytes[offset] | (bytes[offset + 1] << 8) |
                                         (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) : 0;
    };
    if (image.format != BinaryFormat::PE || bytes.size() < 0x40 || bytes[0] != 'M' || bytes[1] != 'Z') return result;
    const auto pe = static_cast<std::size_t>(read32(0x3c));
    if (pe > bytes.size() || bytes.size() - pe < 24 || read32(pe) != 0x00004550) return result;
    const auto optional = pe + 24;
    const auto optional_size = static_cast<std::size_t>(read16(pe + 20));
    if (optional > bytes.size() || optional_size > bytes.size() - optional) return result;
    const auto magic = read16(optional);
    const bool is64 = magic == 0x20b;
    if (!is64 && magic != 0x10b) return result;
    if (is64 != image.is_64_bit) return result;
    const std::size_t directory_offset = is64 ? 112 : 96;
    const std::size_t count_offset = is64 ? 108 : 92;
    if (optional_size < count_offset + 4 || optional_size < directory_offset + 16 || read32(optional + count_offset) <= 1) return result;
    const auto import_rva = read32(optional + directory_offset + 8);
    const auto import_size = read32(optional + directory_offset + 12);
    if (!import_rva || import_size < 20) return result;
    const auto descriptor = image.rva_to_file_offset(import_rva);
    if (!descriptor) return result;
    const std::size_t width = is64 ? 8 : 4;
    const auto read_thunk = [&](std::size_t offset) -> std::uint64_t {
        if (offset > bytes.size() || width > bytes.size() - offset) return 0;
        if (!is64) return read32(offset);
        return static_cast<std::uint64_t>(read32(offset)) | (static_cast<std::uint64_t>(read32(offset + 4)) << 32);
    };
    const auto read_name = [&](std::uint32_t rva) {
        std::string value;
        const auto offset = image.rva_to_file_offset(rva);
        if (!offset) return value;
        for (std::size_t cursor = *offset; cursor < bytes.size() && bytes[cursor] && value.size() < 256; ++cursor)
            value.push_back(static_cast<char>(bytes[cursor]));
        return value;
    };
    const auto read_api_name = [&](std::uint32_t rva) {
        if (rva > UINT32_MAX - 2) return std::string{};
        const auto offset = image.rva_to_file_offset(rva);
        return offset && *offset <= bytes.size() && bytes.size() - *offset >= 2
            ? read_name(rva + 2) : std::string{};
    };
    const auto descriptor_count = (std::min<std::size_t>)(import_size / 20, 4096);
    for (std::size_t descriptor_index = 0; descriptor_index < descriptor_count && result.size() < kMaxEmulatedImports; ++descriptor_index) {
        const auto descriptor_offset = *descriptor + descriptor_index * 20;
        if (descriptor_offset > bytes.size() || bytes.size() - descriptor_offset < 20) break;
        const auto original_thunk = read32(descriptor_offset);
        const auto name_rva = read32(descriptor_offset + 12);
        const auto first_thunk = read32(descriptor_offset + 16);
        if (!original_thunk && !name_rva && !first_thunk) break;
        if (!first_thunk) continue;
        const auto thunk_rva = original_thunk ? original_thunk : first_thunk;
        const auto thunk_offset = image.rva_to_file_offset(thunk_rva);
        if (!thunk_offset) continue;
        for (std::size_t index = 0; index < 65536 && result.size() < kMaxEmulatedImports; ++index) {
            if (index > (UINT64_MAX - first_thunk) / width) break;
            const auto thunk_file_offset = *thunk_offset + index * width;
            const auto thunk = read_thunk(thunk_file_offset);
            if (!thunk) break;
            std::uint16_t stack_bytes = 0;
            std::string function_name;
            if (!is64 && !(thunk & 0x80000000u) && thunk <= UINT32_MAX) {
                function_name = read_api_name(static_cast<std::uint32_t>(thunk));
                const auto& name = function_name;
                const auto at = name.rfind('@');
                if (at != std::string::npos && at + 1 < name.size()) {
                    unsigned parsed = 0;
                    bool valid = true;
                    for (std::size_t character = at + 1; character < name.size(); ++character) {
                        if (name[character] < '0' || name[character] > '9') { valid = false; break; }
                        const auto digit = static_cast<unsigned>(name[character] - '0');
                        if (parsed > (UINT16_MAX - digit) / 10) { valid = false; break; }
                        parsed = parsed * 10 + digit;
                    }
                    if (valid) stack_bytes = static_cast<std::uint16_t>(parsed);
                }
                if (!stack_bytes) stack_bytes = modeled_windows_stdcall_bytes(function_name);
            }
            if (is64 && !(thunk & (1ull << 63)) && thunk <= UINT32_MAX) {
                function_name = read_api_name(static_cast<std::uint32_t>(thunk));
            }
            const auto iat_rva = static_cast<std::uint64_t>(first_thunk) + index * width;
            if (iat_rva > UINT64_MAX - image.image_base) break;
            const auto iat_address = image.image_base + iat_rva;
            if (!image.va_to_file_offset(iat_address)) break;
            result.push_back({iat_address, stack_bytes, std::move(function_name)});
        }
    }
    return result;
}

std::uint64_t page_down(std::uint64_t value) { return value & ~(kPageSize - 1); }
std::uint64_t page_up(std::uint64_t value) {
    if (value > (std::numeric_limits<std::uint64_t>::max)() - (kPageSize - 1)) return 0;
    return (value + kPageSize - 1) & ~(kPageSize - 1);
}

const char* pc_register_name(bool is_64_bit, bool is_arm64) {
    return is_arm64 ? "PC" : (is_64_bit ? "RIP" : "EIP");
}

int register_id(bool is_64_bit, bool is_arm64, std::string name) {
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    if (is_arm64) {
        static const std::map<std::string, int> arm64{
            {"SP", UC_ARM64_REG_SP}, {"PC", UC_ARM64_REG_PC}, {"FP", UC_ARM64_REG_FP}, {"LR", UC_ARM64_REG_LR},
            {"XZR", UC_ARM64_REG_XZR}, {"WZR", UC_ARM64_REG_WZR}, {"NZCV", UC_ARM64_REG_NZCV}
        };
        if (const auto found = arm64.find(name); found != arm64.end()) return found->second;
        if (name.size() >= 2 && (name[0] == 'X' || name[0] == 'W')) {
            unsigned index{};
            try { index = static_cast<unsigned>(std::stoul(name.substr(1))); } catch (...) { return UC_ARM64_REG_INVALID; }
            if (index <= 30) return (name[0] == 'X' ? UC_ARM64_REG_X0 : UC_ARM64_REG_W0) + static_cast<int>(index);
        }
        return UC_ARM64_REG_INVALID;
    }
    static const std::map<std::string, int> x64{
        {"RAX", UC_X86_REG_RAX}, {"EAX", UC_X86_REG_EAX}, {"AX", UC_X86_REG_AX}, {"AH", UC_X86_REG_AH}, {"AL", UC_X86_REG_AL},
        {"RBX", UC_X86_REG_RBX}, {"EBX", UC_X86_REG_EBX}, {"BX", UC_X86_REG_BX}, {"BH", UC_X86_REG_BH}, {"BL", UC_X86_REG_BL},
        {"RCX", UC_X86_REG_RCX}, {"ECX", UC_X86_REG_ECX}, {"CX", UC_X86_REG_CX}, {"CH", UC_X86_REG_CH}, {"CL", UC_X86_REG_CL},
        {"RDX", UC_X86_REG_RDX}, {"EDX", UC_X86_REG_EDX}, {"DX", UC_X86_REG_DX}, {"DH", UC_X86_REG_DH}, {"DL", UC_X86_REG_DL},
        {"RSI", UC_X86_REG_RSI}, {"ESI", UC_X86_REG_ESI}, {"SI", UC_X86_REG_SI}, {"SIL", UC_X86_REG_SIL},
        {"RDI", UC_X86_REG_RDI}, {"EDI", UC_X86_REG_EDI}, {"DI", UC_X86_REG_DI}, {"DIL", UC_X86_REG_DIL},
        {"RBP", UC_X86_REG_RBP}, {"EBP", UC_X86_REG_EBP}, {"BP", UC_X86_REG_BP}, {"BPL", UC_X86_REG_BPL},
        {"RSP", UC_X86_REG_RSP}, {"ESP", UC_X86_REG_ESP}, {"SP", UC_X86_REG_SP}, {"SPL", UC_X86_REG_SPL},
        {"RIP", UC_X86_REG_RIP}, {"EIP", UC_X86_REG_EIP}, {"IP", UC_X86_REG_IP},
        {"R8", UC_X86_REG_R8}, {"R8D", UC_X86_REG_R8D}, {"R8W", UC_X86_REG_R8W}, {"R8B", UC_X86_REG_R8B},
        {"R9", UC_X86_REG_R9}, {"R9D", UC_X86_REG_R9D}, {"R9W", UC_X86_REG_R9W}, {"R9B", UC_X86_REG_R9B},
        {"R10", UC_X86_REG_R10}, {"R10D", UC_X86_REG_R10D}, {"R10W", UC_X86_REG_R10W}, {"R10B", UC_X86_REG_R10B},
        {"R11", UC_X86_REG_R11}, {"R11D", UC_X86_REG_R11D}, {"R11W", UC_X86_REG_R11W}, {"R11B", UC_X86_REG_R11B},
        {"R12", UC_X86_REG_R12}, {"R12D", UC_X86_REG_R12D}, {"R12W", UC_X86_REG_R12W}, {"R12B", UC_X86_REG_R12B},
        {"R13", UC_X86_REG_R13}, {"R13D", UC_X86_REG_R13D}, {"R13W", UC_X86_REG_R13W}, {"R13B", UC_X86_REG_R13B},
        {"R14", UC_X86_REG_R14}, {"R14D", UC_X86_REG_R14D}, {"R14W", UC_X86_REG_R14W}, {"R14B", UC_X86_REG_R14B},
        {"R15", UC_X86_REG_R15}, {"R15D", UC_X86_REG_R15D}, {"R15W", UC_X86_REG_R15W}, {"R15B", UC_X86_REG_R15B},
        {"EFLAGS", UC_X86_REG_EFLAGS}
    };
    static const std::map<std::string, int> x86{
        {"EAX", UC_X86_REG_EAX}, {"AX", UC_X86_REG_AX}, {"AH", UC_X86_REG_AH}, {"AL", UC_X86_REG_AL},
        {"EBX", UC_X86_REG_EBX}, {"BX", UC_X86_REG_BX}, {"BH", UC_X86_REG_BH}, {"BL", UC_X86_REG_BL},
        {"ECX", UC_X86_REG_ECX}, {"CX", UC_X86_REG_CX}, {"CH", UC_X86_REG_CH}, {"CL", UC_X86_REG_CL},
        {"EDX", UC_X86_REG_EDX}, {"DX", UC_X86_REG_DX}, {"DH", UC_X86_REG_DH}, {"DL", UC_X86_REG_DL},
        {"ESI", UC_X86_REG_ESI}, {"SI", UC_X86_REG_SI}, {"EDI", UC_X86_REG_EDI}, {"DI", UC_X86_REG_DI},
        {"EBP", UC_X86_REG_EBP}, {"BP", UC_X86_REG_BP}, {"ESP", UC_X86_REG_ESP}, {"SP", UC_X86_REG_SP},
        {"EIP", UC_X86_REG_EIP}, {"IP", UC_X86_REG_IP}, {"EFLAGS", UC_X86_REG_EFLAGS}
    };
    const auto& registers = is_64_bit ? x64 : x86;
    const auto found = registers.find(name);
    return found == registers.end() ? UC_X86_REG_INVALID : found->second;
}

int zero_extending_parent_register(const std::string& name) {
    static const std::map<std::string, int> parents{
        {"EAX", UC_X86_REG_RAX}, {"EBX", UC_X86_REG_RBX}, {"ECX", UC_X86_REG_RCX}, {"EDX", UC_X86_REG_RDX},
        {"ESI", UC_X86_REG_RSI}, {"EDI", UC_X86_REG_RDI}, {"EBP", UC_X86_REG_RBP}, {"ESP", UC_X86_REG_RSP},
        {"EIP", UC_X86_REG_RIP}, {"R8D", UC_X86_REG_R8}, {"R9D", UC_X86_REG_R9}, {"R10D", UC_X86_REG_R10},
        {"R11D", UC_X86_REG_R11}, {"R12D", UC_X86_REG_R12}, {"R13D", UC_X86_REG_R13}, {"R14D", UC_X86_REG_R14},
        {"R15D", UC_X86_REG_R15}
    };
    const auto found = parents.find(name);
    return found == parents.end() ? UC_X86_REG_INVALID : found->second;
}
#endif
}

Emulator::Emulator(const BinaryImage& image) : impl_(std::make_unique<Impl>()) {
#if defined(GANDON_HAS_UNICORN)
    auto& self = *impl_;
    const bool arm64 = image.architecture == MachineArchitecture::ARM64;
    if (image.architecture != MachineArchitecture::Unknown && image.architecture != MachineArchitecture::X86 &&
        image.architecture != MachineArchitecture::X64 && !arm64) {
        self.error = "Unicorn backend cannot emulate this image architecture.";
        return;
    }
    if ((image.architecture == MachineArchitecture::X86 && image.is_64_bit) ||
        (image.architecture == MachineArchitecture::X64 && !image.is_64_bit)) {
        self.error = "Image architecture disagrees with its 32/64-bit mode.";
        return;
    }
    self.is_64_bit = image.is_64_bit;
    self.is_arm64 = arm64;
    self.is_elf = image.format == BinaryFormat::ELF;
    self.main_module_handle = image.image_base;
    self.next_guest_module_handle = image.is_64_bit ? 0x760000000000ull : 0x76000000ull;
    self.next_guest_file_handle = image.is_64_bit ? 0x770000000000ull : 0x77000000ull;
    if (self.is_elf && !image.is_64_bit) {
        self.mmap_base = self.mmap_cursor = 0x73000000ull;
        self.brk_base = self.brk_current = 0x74000000ull;
    }
    if (arm64 && !image.is_64_bit) { self.error = "ARM64 emulation requires a 64-bit image."; return; }
    self.heap_base = image.is_64_bit ? 0x720000000000ull : 0x72000000ull;
    self.windows_virtual_base = image.is_64_bit ? 0x750000000000ull : 0x75000000ull;
    const auto mode = arm64 ? UC_MODE_ARM : (image.is_64_bit ? UC_MODE_64 : UC_MODE_32);
    auto status = uc_open(arm64 ? UC_ARCH_ARM64 : UC_ARCH_X86, mode, &self.engine);
    if (status != UC_ERR_OK) { self.error = uc_strerror(status); return; }

    // Reconstruct the mapped image from its section table, rather than executing
    // raw file offsets as if PE/ELF images were flat files in memory.
    std::map<std::uint64_t, std::uint64_t> ranges;
    std::map<std::uint64_t, std::uint32_t> page_permissions;
    for (const auto& section : image.sections) {
        const auto extent = static_cast<std::uint64_t>((std::max)(section.virtual_size, section.raw_size));
        if (!extent) continue;
        if (section.rva > (std::numeric_limits<std::uint64_t>::max)() - image.image_base) {
            self.error = "Section address overflow."; return;
        }
        const auto start = image.rva_to_va(section.rva);
        if (extent > (std::numeric_limits<std::uint64_t>::max)() - start) { self.error = "Section address overflow."; return; }
        const auto begin = page_down(start);
        const auto end = page_up(start + extent);
        if (!end || end <= begin) { self.error = "Invalid section mapping range."; return; }
        const auto [range, inserted] = ranges.emplace(begin, end);
        if (!inserted) range->second = (std::max)(range->second, end);
        std::uint32_t permissions = 0;
        if (section.characteristics & 0x40000000u) permissions |= UC_PROT_READ;
        if (section.characteristics & 0x80000000u) permissions |= UC_PROT_WRITE;
        if (section.characteristics & 0x20000000u) permissions |= UC_PROT_EXEC;
        if (!permissions) permissions = UC_PROT_READ;
        for (auto page = begin; page < end; page += kPageSize) {
            page_permissions[page] |= permissions;
            self.image_pages.insert(page);
        }
    }
    if (ranges.empty()) { self.error = "Image has no mappable sections."; return; }
    std::vector<std::pair<std::uint64_t, std::uint64_t>> merged;
    for (const auto& [begin, end] : ranges) {
        if (!merged.empty() && begin <= merged.back().second) merged.back().second = (std::max)(merged.back().second, end);
        else merged.emplace_back(begin, end);
    }
    std::uint64_t mapped_total = 0;
    for (const auto& [begin, end] : merged) {
        const auto size = end - begin;
        if (size > kMaxMappedImage - mapped_total) { self.error = "Image mapping exceeds 512 MiB safety limit."; return; }
        status = uc_mem_map(self.engine, begin, static_cast<std::size_t>(size), UC_PROT_ALL);
        if (status != UC_ERR_OK) { self.error = uc_strerror(status); return; }
        mapped_total += size;
    }
    for (const auto& section : image.sections) {
        if (!section.raw_size) continue;
        if (section.raw_offset > image.bytes.size() || section.raw_size > image.bytes.size() - section.raw_offset) {
            self.error = "Section file range is outside the input image."; return;
        }
        status = uc_mem_write(self.engine, image.rva_to_va(section.rva), image.bytes.data() + section.raw_offset, section.raw_size);
        if (status != UC_ERR_OK) { self.error = uc_strerror(status); return; }
    }
    auto import_stubs = pe_import_stub_requests(image);
    if (image.format == BinaryFormat::ELF) {
        for (const auto& imported : image.imports) {
            if (import_stubs.size() >= kMaxEmulatedImports) break;
            if (imported.address && image.va_to_file_offset(imported.address))
                import_stubs.push_back({imported.address, 0, imported.name});
        }
    }
    if (!import_stubs.empty()) {
        constexpr std::uint64_t stub_stride = 16;
        constexpr std::uint64_t dynamic_arena_size = 1ull * 1024 * 1024;
        const auto required_bytes = static_cast<std::uint64_t>(import_stubs.size()) * stub_stride;
        const auto stub_size = page_up(required_bytes);
        if (!stub_size || stub_size > kMaxMappedImage - dynamic_arena_size) {
            self.error = "Import stubs exceed the emulation mapping limit."; return;
        }
        const auto total_stub_size = stub_size + dynamic_arena_size;
        std::uint64_t stub_base = self.is_64_bit ? 0x710000000000ull : 0x71000000ull;
        bool stub_mapped = false;
        for (unsigned attempt = 0; attempt < 64; ++attempt) {
            status = uc_mem_map(self.engine, stub_base, static_cast<std::size_t>(total_stub_size), UC_PROT_ALL);
            if (status == UC_ERR_OK) { stub_mapped = true; break; }
            if (stub_base > UINT64_MAX - total_stub_size - kPageSize) break;
            stub_base += total_stub_size + kPageSize;
        }
        if (!stub_mapped) { self.error = "Could not reserve guest memory for PE import stubs."; return; }
        self.dynamic_stub_base = stub_base + stub_size;
        self.dynamic_stub_capacity = dynamic_arena_size;
        for (std::size_t index = 0; index < import_stubs.size(); ++index) {
            const auto& request = import_stubs[index];
            const auto address = stub_base + index * stub_stride;
            self.import_stubs.emplace(address, std::make_pair(request.function_name, request.stack_bytes));
            std::uint8_t code[4] = {0xC3, 0, 0, 0}; // x86 RET, replaced below for AArch64.
            std::size_t code_size = arm64 ? 4 : 1;
            if (arm64) {
                code[0] = 0xC0; code[1] = 0x03; code[2] = 0x5F; code[3] = 0xD6; // RET X30
            } else if (!self.is_64_bit && request.stack_bytes) {
                code[0] = 0xC2;
                code[1] = static_cast<std::uint8_t>(request.stack_bytes & 0xffu);
                code[2] = static_cast<std::uint8_t>(request.stack_bytes >> 8);
                code_size = 3;
            }
            status = uc_mem_write(self.engine, address, code, code_size);
            if (status != UC_ERR_OK) { self.error = uc_strerror(status); return; }
        }
        for (const auto& request : import_stubs) {
            const auto index = static_cast<std::size_t>(&request - import_stubs.data());
            const auto destination = stub_base + index * stub_stride;
            if (self.is_64_bit) {
                status = uc_mem_write(self.engine, request.iat_address, &destination, sizeof(destination));
            } else {
                const auto destination32 = static_cast<std::uint32_t>(destination);
                status = uc_mem_write(self.engine, request.iat_address, &destination32, sizeof(destination32));
            }
            if (status != UC_ERR_OK) { self.error = uc_strerror(status); return; }
        }
        status = uc_mem_protect(self.engine, stub_base, static_cast<std::size_t>(total_stub_size), UC_PROT_READ | UC_PROT_EXEC);
        if (status != UC_ERR_OK) { self.error = uc_strerror(status); return; }
    }
    for (auto permission = page_permissions.begin(); permission != page_permissions.end();) {
        const auto begin = permission->first;
        const auto flags = permission->second;
        auto end = begin + kPageSize;
        auto next = std::next(permission);
        while (next != page_permissions.end() && next->first == end && next->second == flags) {
            end += kPageSize;
            ++next;
        }
        status = uc_mem_protect(self.engine, begin, static_cast<std::size_t>(end - begin), flags);
        if (status != UC_ERR_OK) { self.error = uc_strerror(status); return; }
        permission = next;
    }
    // A private stack and return sentinel give entry-point emulation a
    // deterministic stop condition. Only explicitly modeled guest syscalls
    // are intercepted; none are forwarded to the host operating system.
    const std::uint64_t stack_base = image.is_64_bit ? 0x700000000000ull : 0x70000000ull;
    constexpr std::uint64_t stack_size = 0x100000;
    self.stack_base = stack_base;
    self.stack_size = stack_size;
    self.stop_address = image.is_64_bit ? 0x7fff00000000ull : 0x7fff0000ull;
    status = uc_mem_map(self.engine, stack_base, stack_size, UC_PROT_READ | UC_PROT_WRITE);
    if (status != UC_ERR_OK) { self.error = uc_strerror(status); return; }
    status = uc_mem_map(self.engine, self.stop_address, kPageSize, UC_PROT_READ | UC_PROT_EXEC);
    if (status != UC_ERR_OK) { self.error = uc_strerror(status); return; }
    self.page_permissions = std::move(page_permissions);
    for (auto page = stack_base; page < stack_base + stack_size; page += kPageSize)
        self.page_permissions[page] = UC_PROT_READ | UC_PROT_WRITE;
    self.page_permissions[page_down(self.stop_address)] = UC_PROT_READ | UC_PROT_EXEC;
    for (const auto& [stub_address, _] : self.import_stubs)
        self.page_permissions[page_down(stub_address)] = UC_PROT_READ | UC_PROT_EXEC;
    self.initial_page_permissions = self.page_permissions;
    const auto word_size = image.is_64_bit ? sizeof(std::uint64_t) : sizeof(std::uint32_t);
    const auto stack_pointer = stack_base + stack_size - 0x1000 - word_size;
    status = uc_mem_write(self.engine, stack_pointer, &self.stop_address, word_size);
    if (status != UC_ERR_OK) { self.error = uc_strerror(status); return; }
    const auto sp_id = register_id(image.is_64_bit, arm64, arm64 ? "SP" : (image.is_64_bit ? "RSP" : "ESP"));
    const auto pc_id = register_id(image.is_64_bit, arm64, arm64 ? "PC" : (image.is_64_bit ? "RIP" : "EIP"));
    status = uc_reg_write(self.engine, sp_id, &stack_pointer);
    if (status == UC_ERR_OK) status = uc_reg_write(self.engine, pc_id, &image.entry_point);
    if (status == UC_ERR_OK && arm64) status = uc_reg_write(self.engine, UC_ARM64_REG_X30, &self.stop_address);
    if (status != UC_ERR_OK) { self.error = uc_strerror(status); return; }
    status = uc_hook_add(self.engine, &self.code_hook, UC_HOOK_CODE,
                         reinterpret_cast<void*>(Impl::on_code), &self, 1, 0);
    if (status != UC_ERR_OK) self.error = uc_strerror(status);
    if (self.error.empty()) {
        status = uc_hook_add(self.engine, &self.memory_access_hook, UC_HOOK_MEM_WRITE,
                             reinterpret_cast<void*>(Impl::on_memory_write), &self, 1, 0);
        if (status == UC_ERR_OK)
            status = uc_hook_add(self.engine, &self.memory_access_hook, UC_HOOK_MEM_READ_AFTER,
                                 reinterpret_cast<void*>(Impl::on_memory_read_after), &self, 1, 0);
        if (status != UC_ERR_OK) self.error = uc_strerror(status);
    }
    if (self.error.empty()) {
        uc_hook memory_hook{};
        status = uc_hook_add(self.engine, &memory_hook, UC_HOOK_MEM_UNMAPPED | UC_HOOK_MEM_PROT,
                             reinterpret_cast<void*>(Impl::on_unmapped_memory), &self, 1, 0);
        if (status != UC_ERR_OK) self.error = uc_strerror(status);
    }
#else
    (void)image;
    impl_->error = "Emulation backend is unavailable. Configure with Unicorn Engine support.";
#endif
}

Emulator::~Emulator() = default;

Emulator::Emulator(Emulator&&) noexcept = default;
Emulator& Emulator::operator=(Emulator&&) noexcept = default;
bool Emulator::ready() const noexcept { return impl_ && impl_->error.empty(); }
const std::string& Emulator::error() const noexcept { return impl_->error; }
void Emulator::set_standard_input(std::string input) {
    if (!impl_) return;
    impl_->guest_stdin = std::move(input);
    impl_->guest_stdin_offset = 0;
}
const std::string& Emulator::standard_output() const noexcept {
    static const std::string empty;
    return impl_ ? impl_->guest_stdout : empty;
}
const std::string& Emulator::standard_error() const noexcept {
    static const std::string empty;
    return impl_ ? impl_->guest_stderr : empty;
}
int Emulator::exit_code() const noexcept { return impl_ ? impl_->guest_exit_code : 0; }

bool Emulator::set_register(const std::string& name, std::uint64_t value, std::string& error) {
#if defined(GANDON_HAS_UNICORN)
    if (!ready()) { error = impl_->error; return false; }
    const auto id = register_id(impl_->is_64_bit, impl_->is_arm64, name);
    if (id == (impl_->is_arm64 ? UC_ARM64_REG_INVALID : UC_X86_REG_INVALID)) { error = "Unknown register for this architecture: " + name; return false; }
    auto target_id = id;
    if (impl_->is_64_bit) {
        std::string normalized = name;
        std::transform(normalized.begin(), normalized.end(), normalized.begin(),
            [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        const auto parent = zero_extending_parent_register(normalized);
        if (parent != UC_X86_REG_INVALID) target_id = parent;
    }
    const auto status = uc_reg_write(impl_->engine, target_id, &value);
    if (status != UC_ERR_OK) { error = uc_strerror(status); return false; }
    return true;
#else
    (void)name; (void)value; error = impl_->error; return false;
#endif
}

bool Emulator::register_value(const std::string& name, std::uint64_t& value, std::string& error) const {
#if defined(GANDON_HAS_UNICORN)
    if (!ready()) { error = impl_->error; return false; }
    const auto id = register_id(impl_->is_64_bit, impl_->is_arm64, name);
    if (id == (impl_->is_arm64 ? UC_ARM64_REG_INVALID : UC_X86_REG_INVALID)) { error = "Unknown register for this architecture: " + name; return false; }
    value = 0;
    std::uint32_t value32{};
    const bool is_32_bit_register = !impl_->is_64_bit || (!impl_->is_arm64 && id == UC_X86_REG_EFLAGS);
    auto* output = is_32_bit_register ? static_cast<void*>(&value32) : static_cast<void*>(&value);
    const auto status = uc_reg_read(impl_->engine, id, output);
    if (status != UC_ERR_OK) { error = uc_strerror(status); return false; }
    if (is_32_bit_register) value = value32;
    return true;
#else
    (void)name; (void)value; error = impl_->error; return false;
#endif
}

bool Emulator::read_memory(std::uint64_t address, void* destination, std::size_t size, std::string& error) const {
#if defined(GANDON_HAS_UNICORN)
    if (!ready()) { error = impl_->error; return false; }
    const auto status = uc_mem_read(impl_->engine, address, destination, size);
    if (status != UC_ERR_OK) { error = uc_strerror(status); return false; }
    return true;
#else
    (void)address; (void)destination; (void)size; error = impl_->error; return false;
#endif
}

bool Emulator::write_memory(std::uint64_t address, const void* source, std::size_t size, std::string& error) {
#if defined(GANDON_HAS_UNICORN)
    if (!ready()) { error = impl_->error; return false; }
    if (size && size > (std::numeric_limits<std::uint64_t>::max)() - address) {
        error = "Memory write range overflows the guest address space.";
        return false;
    }
    const auto status = uc_mem_write(impl_->engine, address, source, size);
    if (status != UC_ERR_OK) { error = uc_strerror(status); return false; }
    if (size && size <= (std::numeric_limits<std::uint64_t>::max)() - address) {
        const auto cache_status = uc_ctl_remove_cache(impl_->engine, address, address + size);
        if (cache_status != UC_ERR_OK) { error = uc_strerror(cache_status); return false; }
    }
    return true;
#else
    (void)address; (void)source; (void)size; error = impl_->error; return false;
#endif
}

void Emulator::add_breakpoint(std::uint64_t address) {
    if (impl_ && address) impl_->breakpoints.insert(address);
}

void Emulator::remove_breakpoint(std::uint64_t address) {
    if (impl_) impl_->breakpoints.erase(address);
}

bool Emulator::add_watchpoint(std::uint64_t address, std::uint64_t size, bool on_read, bool on_write) {
    if (!impl_ || !address || !size || (!on_read && !on_write) ||
        size - 1 > (std::numeric_limits<std::uint64_t>::max)() - address ||
        impl_->watchpoints.size() >= Impl::max_watchpoints) return false;
    const auto duplicate = std::find_if(impl_->watchpoints.begin(), impl_->watchpoints.end(),
        [&](const auto& item) { return item.address == address && item.size == size &&
                                      item.on_read == on_read && item.on_write == on_write; });
    if (duplicate != impl_->watchpoints.end()) return true;
    impl_->watchpoints.push_back({address, size, on_read, on_write});
    return true;
}

void Emulator::clear_watchpoints() noexcept {
    if (impl_) impl_->watchpoints.clear();
}

bool Emulator::has_breakpoint(std::uint64_t address) const noexcept {
    return impl_ && impl_->breakpoints.contains(address);
}

EmulationResult Emulator::step() {
#if defined(GANDON_HAS_UNICORN)
    if (!ready()) return {EmulationStop::Error, 0, 0, impl_->error};
    if (impl_->guest_exited) return {EmulationStop::Exited, 0, impl_->guest_exit_pc, {}};
    std::uint64_t pc{};
    std::string error;
    if (!register_value(pc_register_name(impl_->is_64_bit, impl_->is_arm64), pc, error)) return {EmulationStop::Error, 0, pc, error};
    impl_->breakpoint_skip_once = 0;
    impl_->returned = false;
    impl_->memory_fault = false;
    impl_->breakpoint_hit = false;
    impl_->breakpoint_address = 0;
    impl_->watchpoint_hit = false;
    impl_->watchpoint_address = 0;
    impl_->single_step_active = true;
    const auto before = impl_->instruction_count;
    const auto status = uc_emu_start(impl_->engine, pc, 0, 0, 1);
    impl_->single_step_active = false;
    Impl::finalize_register_snapshot(impl_->engine, *impl_);
    if (impl_->guest_exited) return {EmulationStop::Exited, impl_->instruction_count - before, impl_->guest_exit_pc, {}};
    impl_->syscall_yielded = false;
    if (impl_->returned) return {EmulationStop::Returned, impl_->instruction_count - before, impl_->stop_address, {}};
    if (impl_->watchpoint_hit) {
        std::ostringstream detail;
        detail << (impl_->watchpoint_write ? "write" : "read") << " watchpoint at 0x"
               << std::hex << std::uppercase << impl_->watchpoint_address;
        std::uint64_t current_pc = pc;
        (void)register_value(pc_register_name(impl_->is_64_bit, impl_->is_arm64), current_pc, error);
        return {EmulationStop::Watchpoint, impl_->instruction_count - before, current_pc, detail.str()};
    }
    if (status != UC_ERR_OK || impl_->memory_fault) {
        if (impl_->memory_fault) {
            const auto access = impl_->fault_access;
            const char* operation = access == UC_MEM_FETCH_UNMAPPED || access == UC_MEM_FETCH_PROT ? "instruction fetch" :
                                   access == UC_MEM_WRITE || access == UC_MEM_WRITE_UNMAPPED || access == UC_MEM_WRITE_PROT ? "write" : "read";
            std::ostringstream detail;
            detail << "Unmapped or protected guest " << operation << " at 0x" << std::hex
                   << std::uppercase << impl_->fault_address << std::dec << " (" << impl_->fault_size << " bytes).";
            return {EmulationStop::MemoryFault, impl_->instruction_count - before, pc, detail.str()};
        }
        return {EmulationStop::Error, impl_->instruction_count - before, pc, uc_strerror(status)};
    }
    if (!register_value(pc_register_name(impl_->is_64_bit, impl_->is_arm64), pc, error)) return {EmulationStop::Error, impl_->instruction_count - before, pc, error};
    return {EmulationStop::Paused, impl_->instruction_count - before, pc, {}};
#else
    return {EmulationStop::Error, 0, 0, impl_->error};
#endif
}

EmulationResult Emulator::step_over(std::size_t instruction_limit, std::uint64_t timeout_microseconds) {
    if (!ready()) return {EmulationStop::Error, 0, 0, impl_ ? impl_->error : "Emulator is not initialized."};
    if (impl_->guest_exited) return {EmulationStop::Exited, 0, impl_->guest_exit_pc, {}};
    if (!instruction_limit) return {EmulationStop::InstructionLimit, 0, 0, {}};

    std::uint64_t pc{};
    std::string error;
    if (!register_value(pc_register_name(impl_->is_64_bit, impl_->is_arm64), pc, error))
        return {EmulationStop::Error, 0, pc, error};
    std::array<std::uint8_t, 15> bytes{};
    const auto available = impl_->is_arm64 ? std::size_t{4} : bytes.size();
    if (!read_memory(pc, bytes.data(), available, error))
        return {EmulationStop::Error, 0, pc, error};

    bool is_call = false;
    bool decode_unknown = false;
    std::uint8_t instruction_size = 0;
    if (impl_->is_arm64) {
        const auto decoded = decode_arm64_instruction(bytes.data(), 4, pc);
        if (decoded) {
            instruction_size = decoded->size;
            const auto word = static_cast<std::uint32_t>(bytes[0]) |
                (static_cast<std::uint32_t>(bytes[1]) << 8) |
                (static_cast<std::uint32_t>(bytes[2]) << 16) |
                (static_cast<std::uint32_t>(bytes[3]) << 24);
            is_call = (word & 0xFC000000u) == 0x94000000u || (word & 0xFFFFFC1Fu) == 0xD63F0000u;
        }
    } else {
        const auto decoded = decode_x86_instruction(bytes.data(), bytes.size(), pc, impl_->is_64_bit);
        decode_unknown = !decoded || decoded->mnemonic == "db";
        if (decoded) {
            instruction_size = decoded->size;
            is_call = decoded->mnemonic == "call";
            if (!is_call && bytes[0] == 0xE8) {
                // The built-in minimal decoder reports unknown instructions as
                // one-byte data; recognize the ubiquitous rel32 CALL here.
                is_call = true;
                instruction_size = 5;
            }
        } else if (bytes[0] == 0xE8) {
            // Keep direct near CALL step-over usable in builds without Capstone.
            is_call = true;
            instruction_size = 5;
        }
    }
    if (!is_call && !impl_->is_arm64 && decode_unknown) {
        // With the minimal decoder, execute exactly one guest instruction to
        // let the CPU and call-stack hook identify indirect CALL forms (FF /2
        // and /3) without trying to reimplement x86 effective-address length.
        const bool resume_past_current_breakpoint = impl_->breakpoint_hit &&
            impl_->breakpoint_address == pc && impl_->breakpoints.contains(pc);
        if (impl_->breakpoints.contains(pc) && !resume_past_current_breakpoint)
            return {EmulationStop::Breakpoint, 0, pc, {}};
        const auto old_stack_size = impl_->call_stack.size();
        const auto old_untracked_depth = impl_->untracked_call_depth;
        auto stepped = step();
        if (stepped.stop != EmulationStop::Paused) return stepped;
        const bool executed_call = impl_->call_stack.size() > old_stack_size ||
            impl_->untracked_call_depth > old_untracked_depth;
        if (!executed_call) return stepped;
        if (impl_->untracked_call_depth > old_untracked_depth || impl_->call_stack.size() <= old_stack_size)
            return {EmulationStop::Error, stepped.instructions_executed, stepped.program_counter,
                    "CALL executed, but its return address could not be tracked reliably."};
        if (instruction_limit == 1)
            return {EmulationStop::InstructionLimit, stepped.instructions_executed, stepped.program_counter, {}};

        const auto return_address = impl_->call_stack.back();
        const bool temporary_breakpoint = !has_breakpoint(return_address);
        if (temporary_breakpoint) add_breakpoint(return_address);
        auto result = run(instruction_limit - 1, timeout_microseconds);
        if (temporary_breakpoint) remove_breakpoint(return_address);
        if (temporary_breakpoint && result.stop == EmulationStop::Breakpoint &&
            result.program_counter == return_address)
            result.stop = EmulationStop::Paused;
        result.instructions_executed += stepped.instructions_executed;
        return result;
    }
    if (!is_call || !instruction_size || instruction_size > UINT64_MAX - pc) return step();

    const auto return_address = pc + instruction_size;
    const bool temporary_breakpoint = !has_breakpoint(return_address);
    if (temporary_breakpoint) add_breakpoint(return_address);
    auto result = run(instruction_limit, timeout_microseconds);
    if (temporary_breakpoint) remove_breakpoint(return_address);
    if (temporary_breakpoint && result.stop == EmulationStop::Breakpoint &&
        result.program_counter == return_address)
        result.stop = EmulationStop::Paused;
    return result;
}

EmulationResult Emulator::step_out(std::size_t instruction_limit, std::uint64_t timeout_microseconds) {
    if (!ready()) return {EmulationStop::Error, 0, 0, impl_ ? impl_->error : "Emulator is not initialized."};
    if (impl_->guest_exited) return {EmulationStop::Exited, 0, impl_->guest_exit_pc, {}};
    if (impl_->untracked_call_depth || impl_->call_stack.empty())
        return {EmulationStop::Error, 0, 0, "No reliable return address is available for step-out."};

    const auto return_address = impl_->call_stack.back();
    const bool temporary_breakpoint = !has_breakpoint(return_address);
    if (temporary_breakpoint) add_breakpoint(return_address);
    auto result = run(instruction_limit, timeout_microseconds);
    if (temporary_breakpoint) remove_breakpoint(return_address);
    if (temporary_breakpoint && result.stop == EmulationStop::Breakpoint &&
        result.program_counter == return_address)
        result.stop = EmulationStop::Paused;
    return result;
}

EmulationResult Emulator::run(std::size_t instruction_limit, std::uint64_t timeout_microseconds) {
#if defined(GANDON_HAS_UNICORN)
    if (!ready()) return {EmulationStop::Error, 0, 0, impl_->error};
    if (impl_->guest_exited) return {EmulationStop::Exited, 0, impl_->guest_exit_pc, {}};
    if (!instruction_limit) return {EmulationStop::InstructionLimit, 0, 0, {}};
    instruction_limit = (std::min)(instruction_limit, std::size_t{10'000'000});
    timeout_microseconds = (std::min)(timeout_microseconds, std::uint64_t{10'000'000});
    std::uint64_t pc{};
    std::string error;
    if (!register_value(pc_register_name(impl_->is_64_bit, impl_->is_arm64), pc, error)) return {EmulationStop::Error, 0, pc, error};
    impl_->breakpoint_skip_once = impl_->breakpoint_hit && impl_->breakpoint_address == pc &&
        impl_->breakpoints.contains(pc) ? pc : 0;
    impl_->returned = false;
    impl_->memory_fault = false;
    impl_->breakpoint_hit = false;
    impl_->breakpoint_address = 0;
    impl_->watchpoint_hit = false;
    impl_->watchpoint_address = 0;
    impl_->single_step_active = false;
    const auto before = impl_->instruction_count;
    const auto started = std::chrono::steady_clock::now();
    uc_err status = UC_ERR_OK;
    while (true) {
        const auto executed_before = impl_->instruction_count - before;
        if (executed_before >= instruction_limit) break;
        std::uint64_t remaining_timeout = timeout_microseconds;
        if (timeout_microseconds) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - started).count();
            if (elapsed >= 0 && static_cast<std::uint64_t>(elapsed) >= timeout_microseconds) break;
            if (elapsed > 0) remaining_timeout -= static_cast<std::uint64_t>(elapsed);
        }
        status = uc_emu_start(impl_->engine, pc, 0, remaining_timeout,
                              instruction_limit - executed_before);
        if (impl_->guest_exited || !impl_->syscall_yielded || status != UC_ERR_OK) break;
        impl_->syscall_yielded = false;
        if (!register_value(pc_register_name(impl_->is_64_bit, impl_->is_arm64), pc, error))
            return {EmulationStop::Error, impl_->instruction_count - before, pc, error};
    }
    Impl::finalize_register_snapshot(impl_->engine, *impl_);
    if (impl_->guest_exited) return {EmulationStop::Exited, impl_->instruction_count - before, impl_->guest_exit_pc, {}};
    impl_->syscall_yielded = false;
    if (impl_->returned) return {EmulationStop::Returned, impl_->instruction_count - before, impl_->stop_address, {}};
    if (impl_->breakpoint_hit)
        return {EmulationStop::Breakpoint, impl_->instruction_count - before, impl_->breakpoint_address, {}};
    if (impl_->watchpoint_hit) {
        std::ostringstream detail;
        detail << (impl_->watchpoint_write ? "write" : "read") << " watchpoint at 0x"
               << std::hex << std::uppercase << impl_->watchpoint_address;
        std::uint64_t current_pc = pc;
        (void)register_value(pc_register_name(impl_->is_64_bit, impl_->is_arm64), current_pc, error);
        return {EmulationStop::Watchpoint, impl_->instruction_count - before, current_pc, detail.str()};
    }
    if (status != UC_ERR_OK || impl_->memory_fault) {
        std::uint64_t fault_pc = pc;
        (void)register_value(pc_register_name(impl_->is_64_bit, impl_->is_arm64), fault_pc, error);
        if (impl_->memory_fault) {
            const auto access = impl_->fault_access;
            const char* operation = access == UC_MEM_FETCH_UNMAPPED || access == UC_MEM_FETCH_PROT ? "instruction fetch" :
                                   access == UC_MEM_WRITE || access == UC_MEM_WRITE_UNMAPPED || access == UC_MEM_WRITE_PROT ? "write" : "read";
            std::ostringstream detail;
            detail << "Unmapped or protected guest " << operation << " at 0x" << std::hex
                   << std::uppercase << impl_->fault_address << std::dec << " (" << impl_->fault_size << " bytes).";
            return {EmulationStop::MemoryFault, impl_->instruction_count - before, fault_pc, detail.str()};
        }
        return {EmulationStop::Error, impl_->instruction_count - before, fault_pc, uc_strerror(status)};
    }
    if (!register_value(pc_register_name(impl_->is_64_bit, impl_->is_arm64), pc, error)) return {EmulationStop::Error, impl_->instruction_count - before, pc, error};
    const auto executed = impl_->instruction_count - before;
    return {timeout_microseconds && executed < instruction_limit ? EmulationStop::TimedOut : EmulationStop::InstructionLimit,
            executed, pc, {}};
#else
    (void)instruction_limit; (void)timeout_microseconds;
    return {EmulationStop::Error, 0, 0, impl_->error};
#endif
}

const std::vector<EmulationTraceEntry>& Emulator::trace() const noexcept { return impl_->trace; }
bool Emulator::trace_truncated() const noexcept { return impl_->trace_was_truncated; }
void Emulator::set_register_delta_capture(bool enabled) noexcept {
    if (!impl_) return;
    impl_->register_delta_capture = enabled;
    impl_->pending_register_snapshot = false;
}
bool Emulator::register_delta_capture_enabled() const noexcept { return impl_ && impl_->register_delta_capture; }
const std::vector<EmulationRegisterDelta>& Emulator::register_deltas() const noexcept { return impl_->register_deltas; }
bool Emulator::register_deltas_truncated() const noexcept { return impl_->register_deltas_were_truncated; }
const std::vector<EmulationMemoryAccess>& Emulator::memory_accesses() const noexcept { return impl_->memory_accesses; }
bool Emulator::memory_accesses_truncated() const noexcept { return impl_->memory_accesses_were_truncated; }
const std::vector<std::uint64_t>& Emulator::call_stack() const noexcept { return impl_->call_stack; }
bool Emulator::call_stack_truncated() const noexcept { return impl_->call_stack_was_truncated; }
void Emulator::clear_trace() noexcept {
    if (!impl_) return;
    // The trace can reach one million instructions. clear() retains its
    // high-water allocation, so explicitly release it when the user clears
    // execution history (especially important before a long new run).
    std::vector<EmulationTraceEntry>().swap(impl_->trace);
    impl_->trace_was_truncated = false;
    std::vector<EmulationRegisterDelta>().swap(impl_->register_deltas);
    impl_->register_deltas_were_truncated = false;
    impl_->pending_register_snapshot = false;
    std::vector<EmulationMemoryAccess>().swap(impl_->memory_accesses);
    impl_->memory_accesses_were_truncated = false;
}

} // namespace gandon
