#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "gandon/driver_setup.hpp"
#include <windows.h>
#include <winioctl.h>
#include <wintrust.h>
#include <softpub.h>
#include "gandon/kernel_protocol.h"
#include <filesystem>
#include <iterator>
#include <exception>
#include <cwchar>
#include <string>
#include <vector>

namespace gandon {
namespace {
struct ServiceHandle {
    SC_HANDLE value{};
    ~ServiceHandle() { if (value) CloseServiceHandle(value); }
};
std::wstring error_text(DWORD code) {
    wchar_t* buffer{};
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, code, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::wstring message = buffer ? buffer : L"Unknown Windows error";
    if (buffer) LocalFree(buffer);
    return message + L" (" + std::to_wstring(code) + L")";
}
bool failure(HWND owner, const std::wstring& message) {
    MessageBoxW(owner, message.c_str(), L"GandonMemory — драйвер не подключён", MB_OK | MB_ICONWARNING);
    return false;
}
bool verify_image(const std::filesystem::path& path) {
    WINTRUST_FILE_INFO file{}; file.cbStruct = sizeof(file); file.pcwszFilePath = path.c_str();
    WINTRUST_DATA data{}; data.cbStruct = sizeof(data); data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE; data.dwUnionChoice = WTD_CHOICE_FILE; data.pFile = &file;
    data.dwStateAction = WTD_STATEACTION_VERIFY; data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const auto status = WinVerifyTrust(nullptr, &policy, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE; WinVerifyTrust(nullptr, &policy, &data);
    return status == ERROR_SUCCESS;
}
bool device_available() {
    const auto device = CreateFileW(GD_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr, OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) return false;
    GD_VERSION_RESPONSE version{}; DWORD got{};
    const bool ok = DeviceIoControl(device, GD_IOCTL_VERSION, nullptr, 0, &version, sizeof(version), &got, nullptr) &&
                    got == sizeof(version) && version.version == GD_PROTOCOL_VERSION && version.max_read == GD_MAX_READ;
    CloseHandle(device); return ok;
}
std::wstring normalized_image(std::wstring value) {
    if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"') value = value.substr(1, value.size() - 2);
    return std::filesystem::path(value).lexically_normal().wstring();
}
}
bool offer_memory_driver_setup(void* owner_pointer) {
    const auto owner = static_cast<HWND>(owner_pointer);
    const auto answer = MessageBoxW(owner,
        L"Установить и запустить драйвер GandonMemory?\r\n\r\n"
        L"Он даёт дополнительный канал чтения памяти живого процесса для pointer-scan и дампа структур. "
        L"Права доступа к процессу сохраняются. Драйвер не скрывает отладчик на уровне ядра.\r\n\r\n"
        L"Без драйвера эти функции работают через обычный ReadProcessMemory; анализ файлов тоже доступен.\r\n\r\n"
        L"При выборе «Да» будет проверена подпись, создана служба с ручным запуском и запущен драйвер. "
        L"Нужен файл drivers\\GandonMemory.sys рядом с программой с допустимой для Windows подписью. "
        L"Если драйвер уже установлен, программа попробует подключиться к нему.\r\n\r\n"
        L"Для нашего драйвера с тестовой подписью: отключите Secure Boot в UEFI/BIOS, "
        L"установите тестовый сертификат и включите тестовый режим Windows (testsigning), затем перезагрузите компьютер. "
        L"Одного отключения Secure Boot недостаточно. Если включён BitLocker, заранее сохраните ключ восстановления.\r\n\r\n"
        L"«Нет» — продолжить без установки и запуска драйвера.",
        L"Gandon-PRO — дополнительный драйвер", MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION);
    if (answer != IDYES) return false;
    if (device_available()) return true;

    try {
        wchar_t exe[32768]{};
        const auto length = GetModuleFileNameW(nullptr, exe, static_cast<DWORD>(std::size(exe)));
        if (!length || length >= std::size(exe)) return failure(owner, L"Не удалось определить папку программы.");
        BOOL wow64 = FALSE;
        if (!IsWow64Process(GetCurrentProcess(), &wow64) || wow64)
            return failure(owner, L"Для установки x64-драйвера используйте 64-разрядную версию программы.");
        wchar_t system_directory[MAX_PATH]{};
        const auto system_length = GetSystemDirectoryW(system_directory, MAX_PATH);
        if (!system_length || system_length >= MAX_PATH) return failure(owner, L"Не удалось определить системную папку Windows.");
        const auto source = std::filesystem::path(exe).parent_path() / L"drivers" / L"GandonMemory.sys";
        const auto installed = std::filesystem::path(system_directory) / L"drivers" / L"GandonMemory.sys";
        ServiceHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)};
        if (!manager.value) return failure(owner, L"Не удалось открыть диспетчер служб.\r\n" + error_text(GetLastError()));
        ServiceHandle service{OpenServiceW(manager.value, L"GandonMemory", SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START)};
        bool created_service = false, copied_image = false;
        if (!service.value) {
            const auto open_error = GetLastError();
            if (open_error != ERROR_SERVICE_DOES_NOT_EXIST) return failure(owner, error_text(open_error));
            if (!std::filesystem::exists(source)) return failure(owner, L"Файл драйвера не найден:\r\n" + source.wstring() + L"\r\nПродолжаем без драйвера.");
            if (!verify_image(source)) return failure(owner, L"Подпись файла драйвера отсутствует или не прошла проверку.\r\n"
                L"Неподписанный .sys из текущей сборки установить нельзя. Нужна допустимая kernel-подпись. "
                L"Проверка подписи и Secure Boot не изменялись.");
            if (!std::filesystem::exists(installed)) {
                if (!CopyFileW(source.c_str(), installed.c_str(), TRUE)) return failure(owner, error_text(GetLastError()));
                copied_image = true;
            }
            if (!verify_image(installed)) {
                if (copied_image) DeleteFileW(installed.c_str());
                return failure(owner, L"Системная копия драйвера не прошла проверку подписи.");
            }
            const auto quoted = L"\"" + installed.wstring() + L"\"";
            service.value = CreateServiceW(manager.value, L"GandonMemory", L"GandonMemory live-memory reader",
                SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | DELETE, SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, quoted.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
            if (!service.value) {
                const auto code = GetLastError(); if (copied_image) DeleteFileW(installed.c_str());
                return failure(owner, error_text(code));
            }
            created_service = true;
        }
        // Do not repurpose another service that happens to have the same name.
        DWORD needed{}; QueryServiceConfigW(service.value, nullptr, 0, &needed);
        if (!needed) {
            if (created_service) { DeleteService(service.value); if (copied_image) DeleteFileW(installed.c_str()); }
            return failure(owner, L"Не удалось проверить конфигурацию службы.");
        }
        std::vector<BYTE> storage(needed);
        auto config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());
        if (!QueryServiceConfigW(service.value, config, needed, &needed) || config->dwServiceType != SERVICE_KERNEL_DRIVER ||
            _wcsicmp(normalized_image(config->lpBinaryPathName).c_str(), installed.lexically_normal().c_str()) != 0) {
            if (created_service) { DeleteService(service.value); if (copied_image) DeleteFileW(installed.c_str()); }
            return failure(owner, L"Имя GandonMemory занято другой конфигурацией службы. Она не была изменена.");
        }
        if (!verify_image(installed)) {
            if (created_service) { DeleteService(service.value); if (copied_image) DeleteFileW(installed.c_str()); }
            return failure(owner, L"Подпись установленного драйвера не прошла проверку.");
        }
        if (!StartServiceW(service.value, 0, nullptr)) {
            const auto code = GetLastError();
            if (code != ERROR_SERVICE_ALREADY_RUNNING) {
                if (created_service) { DeleteService(service.value); if (copied_image) DeleteFileW(installed.c_str()); }
                return failure(owner, L"Windows не загрузила драйвер:\r\n" + error_text(code) +
                    L"\r\nДля тестовой подписи проверьте: Secure Boot выключен в UEFI/BIOS, сертификат установлен, "
                    L"testsigning включён и после этого выполнена перезагрузка. Подпись должна соответствовать политике Windows. "
                    L"Программа продолжит работу без драйвера.");
            }
        }
        // A newly started service may briefly be START_PENDING.
        for (unsigned attempt = 0; attempt != 20; ++attempt) {
            if (device_available()) return true;
            SERVICE_STATUS_PROCESS status{}; DWORD count{};
            if (!QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &count) || status.dwCurrentState != SERVICE_START_PENDING) break;
            Sleep(100);
        }
        if (created_service) {
            SERVICE_STATUS status{};
            if (ControlService(service.value, SERVICE_CONTROL_STOP, &status)) {
                DeleteService(service.value);
                if (copied_image && status.dwCurrentState == SERVICE_STOPPED) DeleteFileW(installed.c_str());
            }
        }
        return failure(owner, L"Драйвер не отвечает ожидаемой версии протокола. Kernel-режим не включён.");
    } catch (const std::exception&) { return failure(owner, L"Не удалось подготовить установку драйвера. Программа продолжит работу через ReadProcessMemory."); }
}
} // namespace gandon
