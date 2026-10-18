#include "gandon/live_process.hpp"
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <winioctl.h>
#include "gandon/kernel_protocol.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace gandon {
namespace {
struct Handle {
    HANDLE value{};
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
std::string utf8(const wchar_t* text) {
    const auto size = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) return {};
    std::string value(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, value.data(), size, nullptr, nullptr); value.pop_back(); return value;
}
class WindowsReader final : public LiveMemoryReader {
    Handle process_, device_;
    DWORD pid_{}; unsigned width_{};
public:
    WindowsReader(DWORD pid, bool kernel) : pid_(pid) {
        process_.value = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process_.value) throw std::runtime_error("OpenProcess failed, Win32 error " + std::to_string(GetLastError()));
        BOOL wow64 = FALSE;
        if (!IsWow64Process(process_.value, &wow64)) throw std::runtime_error("Could not determine process architecture");
        SYSTEM_INFO system{}; GetNativeSystemInfo(&system);
        if (system.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 && system.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_INTEL)
            throw std::runtime_error("Live process reader currently supports x86/x64 Windows only");
        width_ = system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 && !wow64 ? 8 : 4;
        if (width_ > sizeof(void*)) throw std::runtime_error("Use the x64 debugger to inspect a 64-bit process");
        if (kernel) {
            device_.value = CreateFileW(GD_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            if (device_.value == INVALID_HANDLE_VALUE) throw std::runtime_error("Kernel device unavailable, Win32 error " + std::to_string(GetLastError()));
            GD_VERSION_RESPONSE version{}; DWORD got{};
            if (!DeviceIoControl(device_.value, GD_IOCTL_VERSION, nullptr, 0, &version, sizeof(version), &got, nullptr) || got != sizeof(version) || version.version != GD_PROTOCOL_VERSION || version.max_read != GD_MAX_READ)
                throw std::runtime_error("Kernel protocol/version mismatch");
        }
    }
    unsigned pointer_size() const override { return width_; }
    std::size_t read(std::uint64_t address, void* output, std::size_t size) const override {
        if (!output || !size || address > (std::numeric_limits<std::uintptr_t>::max)() || size - 1 > (std::numeric_limits<std::uintptr_t>::max)() - address) return 0;
        if (!device_.value || device_.value == INVALID_HANDLE_VALUE) {
            SIZE_T got{}; ReadProcessMemory(process_.value, reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)), output, size, &got); return got;
        }
        std::size_t total = 0;
        while (total < size) {
            const auto chunk = static_cast<std::uint32_t>((std::min)(size - total, std::size_t(GD_MAX_READ)));
            GD_READ_REQUEST request{static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(process_.value)), address + total, chunk, 0};
            std::vector<std::uint8_t> reply(sizeof(GD_READ_RESPONSE) + chunk); DWORD got{};
            if (!DeviceIoControl(device_.value, GD_IOCTL_READ, &request, sizeof(request), reply.data(), static_cast<DWORD>(reply.size()), &got, nullptr) || got < sizeof(GD_READ_RESPONSE)) break;
            GD_READ_RESPONSE header{}; std::memcpy(&header, reply.data(), sizeof(header));
            if (header.transferred > chunk || got != sizeof(header) + header.transferred) break;
            std::memcpy(static_cast<std::uint8_t*>(output) + total, reply.data() + sizeof(header), header.transferred);
            total += header.transferred;
            if (header.transferred != chunk || header.status != 0) break;
        }
        return total;
    }
    std::vector<LiveRegion> regions() const override {
        std::vector<LiveRegion> result;
        SYSTEM_INFO system{}; GetNativeSystemInfo(&system);
        const auto maximum = width_ == 4 ? std::uint64_t(UINT32_MAX) : reinterpret_cast<std::uintptr_t>(system.lpMaximumApplicationAddress);
        std::uint64_t address = 0;
        MEMORY_BASIC_INFORMATION info{};
        while (address <= maximum && VirtualQueryEx(process_.value, reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)), &info, sizeof(info)) == sizeof(info)) {
            const auto base = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
            const auto size = std::uint64_t(info.RegionSize);
            const auto protection = info.Protect;
            if (info.State == MEM_COMMIT && !(protection & (PAGE_GUARD | PAGE_NOACCESS)) &&
                (protection & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) result.push_back({base, size});
            if (!size || size > maximum - address || base > UINT64_MAX - size || base + size <= address) break;
            address = base + size;
        }
        return result;
    }
    std::vector<LiveModule> modules() const override {
        Handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_)};
        std::vector<LiveModule> result;
        if (snapshot.value == INVALID_HANDLE_VALUE) return result;
        MODULEENTRY32W entry{}; entry.dwSize = sizeof(entry);
        if (Module32FirstW(snapshot.value, &entry)) do {
            result.push_back({reinterpret_cast<std::uintptr_t>(entry.modBaseAddr), entry.modBaseSize, utf8(entry.szModule)});
        } while (Module32NextW(snapshot.value, &entry));
        return result;
    }
};
}
std::unique_ptr<LiveMemoryReader> open_live_process(std::uint32_t pid, bool kernel, std::string& error) {
    error.clear();
    try { return std::make_unique<WindowsReader>(pid, kernel); }
    catch (const std::exception& e) { error = e.what(); return {}; }
}
} // namespace gandon
#else
namespace gandon {
std::unique_ptr<LiveMemoryReader> open_live_process(std::uint32_t, bool, std::string& error) {
    error = "Live process access requires Windows"; return {};
}
}
#endif
