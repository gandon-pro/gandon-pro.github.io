#include "gandon/core.hpp"
#include "gandon/plugin_host.hpp"

#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>
#include <dbghelp.h>
#include <wincodec.h>
#include <dwmapi.h>
#include <commdlg.h>
#include <commctrl.h>
#include <memory>
#include <sstream>
#include <string>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <cstring>
#include <cctype>
#include <cwctype>
#include <thread>
#include <atomic>
#include <map>
#include <set>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <iomanip>
#include <regex>
#include <cmath>

#pragma comment(lib, "windowscodecs.lib")

namespace {
constexpr int ID_OPEN = 1001;
constexpr int ID_EXIT = 1002;
constexpr int ID_REFRESH = 1003;
constexpr int ID_PLUGIN_LOAD = 1201;
constexpr int ID_PLUGIN_FOLDER = 1202;
constexpr int ID_NATIVE_PLUGIN_LOAD = 1203;
constexpr int ID_PYTHON_PLUGIN_UNLOAD = 1204;
constexpr int ID_NATIVE_PLUGIN_FIRST = 1500;
constexpr int ID_PYTHON_PLUGIN_FIRST = 1700;
constexpr int ID_SAVE_DB = 1301, ID_LOAD_DB = 1302, ID_APPLY_PATCHES = 1303, ID_EXPORT_GRAPH = 1304;
constexpr int ID_RENAME_LABEL = 1310, ID_ADD_COMMENT = 1311, ID_NOP_BLOCK = 1312, ID_EDIT_INSTRUCTION = 1313, ID_UNDO_PATCH = 1314, ID_REDO_PATCH = 1315, ID_ASSIGN_TYPE = 1316;
constexpr int ID_DECOMPILE = 1320, ID_SIGMAKER = 1321, ID_SEARCH_SIGNATURE = 1322, ID_CALL_GRAPH = 1323, ID_MEMORY_VIEW = 1324, ID_WATCH_LOCALS = 1325, ID_CALL_STACK = 1326, ID_COMPARE = 1327, ID_PY_CONSOLE = 1328, ID_SEARCH = 1329;
constexpr int ID_JUMP_BACK = 1330, ID_TOGGLE_BOOKMARK = 1331, ID_NEXT_BOOKMARK = 1332, ID_EXPORT_JSON = 1333, ID_EXPORT_BREAKPOINTS = 1334, ID_EXPORT_DEBUG_LOG = 1335;
constexpr int ID_LIST_XREFS = 1336, ID_SEARCH_PROCESS_MEMORY = 1337, ID_FIND_FUNCTION = 1338, ID_HIDE_FUNCTION = 1339;
constexpr int ID_RUN = 1340, ID_STEP_INTO = 1341, ID_STEP_OVER = 1342, ID_TOGGLE_BP = 1343, ID_COND_BP = 1344, ID_CONFIG_BP = 1345, ID_BP_MANAGER = 1346, ID_HW_BP = 1347, ID_DELETE_BP = 1348, ID_STOP = 1349;
constexpr int ID_ANTI_DEBUG = 1350;
constexpr int ID_TRACE_TOGGLE = 1351, ID_EXPORT_TRACE = 1352, ID_HIDDEN_SYMBOLS = 1353, ID_RESTORE_HIDDEN = 1354;
constexpr int ID_HIDE_IMPORT = 1355;
constexpr int ID_MEMORY_SNAPSHOT = 1356, ID_MEMORY_COMPARE = 1357;
constexpr int ID_PAUSE = 1358;
constexpr int ID_VIEW_GRAPH = 1360, ID_VIEW_LISTING = 1361, ID_VIEW_PSEUDO = 1362, ID_VIEW_DEBUGGER = 1363, ID_VIEW_HEX = 1364, ID_VIEW_TYPES = 1365, ID_VIEW_IMPORTS = 1366, ID_VIEW_EXPORTS = 1367, ID_VIEW_STRINGS = 1368, ID_VIEW_RESOURCES = 1369, ID_VIEW_SYMBOLS = 1370, ID_VIEW_MEMORY = 1371, ID_VIEW_PROBLEMS = 1372, ID_ABOUT = 1380;
constexpr int ID_TOGGLE_GRAPH_LIST = 1373, ID_FIT_GRAPH = 1374, ID_TOGGLE_MINIMAP = 1375;
constexpr int ID_CONTEXT_FOLLOW = 1390, ID_CONTEXT_COPY = 1391, ID_CONTEXT_FOLLOW_TARGET = 1392;
constexpr int ID_COLOR_DEFAULT = 1393, ID_COLOR_GREEN = 1394, ID_COLOR_RED = 1395, ID_COLOR_BLUE = 1396;
constexpr int GRAPH_PAN_PADDING = 100000;
constexpr UINT WM_DEBUG_STATUS = WM_APP + 7;
constexpr int ID_TABS = 1100;
constexpr int ID_TREE = 1101;
constexpr int ID_EDITOR = 1102;
constexpr int ID_STATUS = 1103;

HINSTANCE g_instance{};
HWND g_main_window{}, g_tree{}, g_tabs{}, g_editor{}, g_status{}, g_minimap{};
HWND g_view{};
HBRUSH g_background{}, g_panel{};
HFONT g_ui_font{}, g_code_font{};
bool g_code_font_owned = false;
struct GraphBlock {
    std::uint64_t start{};
    std::vector<gandon::Instruction> instructions;
    int x{}, y{}, width{520}, height{100};
};
enum class GraphEdgeKind { Unconditional, TrueBranch, FalseBranch };
struct GraphEdge { std::uint64_t from{}, to{}; GraphEdgeKind kind{GraphEdgeKind::Unconditional}; };
struct ImportRecord {
    std::wstring dll;
    std::wstring name;
    std::uint64_t iat_va{};
};
struct InstalledImportDisable {
    std::uint64_t runtime_iat{};
    std::uint64_t original_target{};
    std::uint64_t stub{};
};
std::vector<GraphBlock> g_graph_blocks;
std::vector<GraphEdge> g_graph_edges;
std::unordered_map<std::uint64_t, std::pair<int, int>> g_graph_positions;
std::set<std::uint64_t> g_string_addresses;
int g_graph_zoom = 100;
int g_graph_scroll_x = 0;
int g_graph_scroll_y = 0;
bool g_graph_panning = false;
bool g_graph_pan_moved = false;
bool g_minimap_visible = true;
bool g_minimap_dragging = false;
POINT g_graph_pan_origin{};
int g_graph_pan_start_x = 0;
int g_graph_pan_start_y = 0;
std::unique_ptr<gandon::AnalysisDatabase> g_database;
std::wstring g_listing, g_pseudocode, g_xrefs, g_memory_map;
std::vector<std::uint8_t> g_memory_snapshot;
std::uint64_t g_memory_snapshot_address = 0;
std::uint64_t g_current_address = 0;
struct PatchChange { std::size_t offset{}; std::uint8_t old_value{}; std::uint8_t new_value{}; };
std::vector<std::vector<PatchChange>> g_patch_undo, g_patch_redo;
std::unordered_map<std::uint64_t, std::wstring> g_custom_labels, g_custom_comments;
std::unordered_map<std::uint64_t, std::wstring> g_custom_types;
std::unordered_map<std::uint64_t, COLORREF> g_graph_colors;
struct NavigationPoint { std::uint64_t address{}; int tab{}; };
std::vector<NavigationPoint> g_navigation_history;
std::set<std::uint64_t> g_bookmarks;
std::set<std::uint64_t> g_hidden_functions;
std::set<std::pair<std::wstring, std::wstring>> g_hidden_imports;
std::vector<std::wstring> g_watch_expressions;
std::mutex g_debug_log_mutex;
std::vector<std::wstring> g_debug_event_log;
struct DebugTraceRecord { std::wstring event; DWORD process{}; DWORD thread{}; std::uint64_t address{}; };
std::mutex g_trace_mutex;
std::vector<DebugTraceRecord> g_debug_trace;
std::atomic_bool g_trace_enabled{false};
std::filesystem::path g_session_path;
bool g_session_dirty = false;
int g_session_tab = 0;
std::uint64_t g_session_address = 0;
constexpr UINT_PTR ID_SESSION_TIMER = 1;
std::atomic<HANDLE> g_debug_process{nullptr};
std::atomic<DWORD> g_debug_pid{0};
std::atomic<DWORD> g_debug_thread{0};
std::atomic<std::uint64_t> g_debug_base{0};
std::atomic_bool g_debug_starting{false};
std::atomic_bool g_stealth_applied{false};
enum class DebugResumeMode { None, Continue, StepInto, StepOver };
std::mutex g_debug_control_mutex;
std::condition_variable g_debug_control_cv;
DebugResumeMode g_debug_resume_mode = DebugResumeMode::None;
std::atomic_bool g_debug_paused{false};
std::atomic_bool g_pause_on_next_single_step{false};
std::atomic<std::uint64_t> g_debug_pause_address{0};
std::mutex g_breakpoint_mutex;
std::set<std::uint64_t> g_requested_breakpoints;
std::unordered_map<std::uint64_t, std::wstring> g_breakpoint_conditions;
std::unordered_map<std::uint64_t, std::uint64_t> g_breakpoint_hit_counts;
std::unordered_map<std::uint64_t, std::uint64_t> g_breakpoint_hit_limits;
std::set<std::uint64_t> g_breakpoint_log_only;
struct RuntimeBreakpoint { std::uint64_t static_address{}; std::uint8_t original{}; };
std::map<std::uint64_t, RuntimeBreakpoint> g_runtime_breakpoints;
std::map<std::wstring, ImportRecord> g_requested_disabled_imports;
std::map<std::wstring, InstalledImportDisable> g_installed_import_disables;
std::atomic<std::uint64_t> g_step_over_runtime{0};
bool g_hardware_breakpoint = false;
std::uint64_t g_hardware_breakpoint_address = 0;
std::uint64_t g_graph_drag_block = 0;
POINT g_graph_drag_origin{};
int g_graph_drag_start_x = 0;
int g_graph_drag_start_y = 0;
bool g_graph_dragging = false;
bool g_graph_drag_moved = false;
std::wstring wide(const std::string& value);
std::string python_interpreter_command();
std::optional<std::filesystem::path> python_interpreter_path();
struct NativePluginAction { int menu_id{}; void (*callback)(void*){}; void* callback_user_data{}; };
struct PythonPluginAction { int menu_id{}; std::filesystem::path script; std::string action; };
std::unique_ptr<gandon::PluginHost> g_native_plugin_host;
HMENU g_plugins_menu{};
std::vector<NativePluginAction> g_native_plugin_actions;
std::vector<PythonPluginAction> g_python_plugin_actions;
HACCEL g_accelerators{};
void load_native_plugins(HWND window);
bool invoke_native_plugin_action(HWND window, int menu_id);
bool invoke_python_plugin_action(HWND window, int menu_id);
void select_view(HWND window, int tab);
void rebuild_graph_model();
void update_graph_scrollbars(HWND graph);
void fill_tree();
std::pair<int, int> graph_content_size();
void invalidate_minimap();
std::vector<ImportRecord> enumerate_imports(const gandon::BinaryImage& image);
std::wstring import_key(const std::wstring& dll, const std::wstring& name);
std::optional<ImportRecord> import_for_iat(std::uint64_t iat_va);
void install_requested_import_disables(HANDLE process, std::uint64_t module_base);
void restore_import_disables(HANDLE process);
std::wstring listing_text_at(const gandon::AnalysisDatabase& db, std::uint64_t address);
std::optional<std::uint64_t> editor_line_address(HWND editor);
void sync_current_address_from_editor();
void navigate_to_address(HWND window, std::uint64_t address, int tab = 1);

std::filesystem::path debug_pid_file() {
    return std::filesystem::temp_directory_path() / L"gandon-pro-debug.pid";
}

void write_debug_pid_file(DWORD pid) {
    std::ofstream output(debug_pid_file(), std::ios::trunc);
    if (output) output << pid << '\n';
}

void remove_debug_pid_file() {
    std::error_code ignored;
    std::filesystem::remove(debug_pid_file(), ignored);
}

std::wstring graph_bytes(const gandon::Instruction& instruction) {
    std::wostringstream text;
    const auto count = (std::min<std::size_t>)(instruction.bytes.size(), 7);
    for (std::size_t index = 0; index < count; ++index) {
        if (index) text << L' ';
        text << std::uppercase << std::hex << std::setfill(L'0') << std::setw(2)
             << static_cast<unsigned>(instruction.bytes[index]);
    }
    if (instruction.bytes.size() > count) text << L" …";
    return text.str();
}

struct PromptContext { std::wstring value; std::wstring initial; };

void prompt_word(std::vector<BYTE>& data, WORD value) {
    if (data.size() & 1u) data.push_back(0);
    data.push_back(static_cast<BYTE>(value & 0xff)); data.push_back(static_cast<BYTE>(value >> 8));
}

void prompt_string(std::vector<BYTE>& data, const wchar_t* value) {
    while (*value) prompt_word(data, static_cast<WORD>(*value++));
    prompt_word(data, 0);
}

INT_PTR CALLBACK prompt_proc(HWND dialog, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* context = reinterpret_cast<PromptContext*>(GetWindowLongPtrW(dialog, DWLP_USER));
    if (message == WM_INITDIALOG) {
        SetWindowLongPtrW(dialog, DWLP_USER, lparam);
        context = reinterpret_cast<PromptContext*>(lparam);
        SetDlgItemTextW(dialog, 101, context->initial.c_str());
        SetFocus(GetDlgItem(dialog, 101));
        return FALSE;
    }
    if (message == WM_COMMAND && context) {
        if (LOWORD(wparam) == IDOK) {
            wchar_t value[512]{}; GetDlgItemTextW(dialog, 101, value, 512); context->value = value; EndDialog(dialog, IDOK); return TRUE;
        }
        if (LOWORD(wparam) == IDCANCEL) { EndDialog(dialog, IDCANCEL); return TRUE; }
    }
    return FALSE;
}

std::optional<std::wstring> prompt_text(HWND owner, const wchar_t* title, const wchar_t* label, const std::wstring& initial = {}) {
    std::vector<BYTE> data(1024, 0);
    auto* dialog = reinterpret_cast<DLGTEMPLATE*>(data.data());
    dialog->style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME | DS_SETFONT;
    dialog->dwExtendedStyle = WS_EX_DLGMODALFRAME; dialog->cdit = 4; dialog->x = 10; dialog->y = 10; dialog->cx = 250; dialog->cy = 88;
    std::size_t cursor = sizeof(DLGTEMPLATE); prompt_word(data, 0); prompt_word(data, 0); prompt_string(data, title); prompt_word(data, 9); prompt_string(data, L"Segoe UI"); cursor = data.size();
    auto add_control = [&](DWORD style, short x, short y, short cx, short cy, WORD id, WORD klass, const wchar_t* text) {
        while (data.size() & 3u) data.push_back(0);
        auto* item = reinterpret_cast<DLGITEMTEMPLATE*>(data.data() + data.size()); item->style = style; item->dwExtendedStyle = 0; item->x = x; item->y = y; item->cx = cx; item->cy = cy; item->id = id;
        prompt_word(data, 0xffff); prompt_word(data, klass); prompt_string(data, text); prompt_word(data, 0);
    };
    add_control(WS_CHILD | WS_VISIBLE | SS_LEFT, 8, 8, 234, 12, 100, 0x0082, label);
    add_control(WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL, 8, 23, 234, 18, 101, 0x0081, L"");
    add_control(WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 118, 55, 58, 20, IDOK, 0x0080, L"OK");
    add_control(WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 184, 55, 58, 20, IDCANCEL, 0x0080, L"Cancel");
    PromptContext context; context.initial = initial;
    if (DialogBoxIndirectParamW(g_instance, dialog, owner, prompt_proc, reinterpret_cast<LPARAM>(&context)) == IDOK) return context.value;
    return std::nullopt;
}

void set_code_font(const std::wstring& name) {
    if (name.empty()) return;
    HFONT next = nullptr;
    bool next_owned = true;
    if (name == L"ANSI_FIXED_FONT") {
        next = reinterpret_cast<HFONT>(GetStockObject(ANSI_FIXED_FONT));
        next_owned = false;
    } else {
        next = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            FIXED_PITCH | FF_DONTCARE, name.c_str());
    }
    if (!next) return;
    HFONT previous = g_code_font;
    const bool previous_owned = g_code_font_owned;
    g_code_font = next;
    g_code_font_owned = next_owned;
    if (g_editor) SendMessageW(g_editor, WM_SETFONT, reinterpret_cast<WPARAM>(g_code_font), TRUE);
    if (g_view) InvalidateRect(g_view, nullptr, TRUE);
    if (previous && previous_owned) DeleteObject(previous);
}

std::wstring python_plugin_font() {
    wchar_t module_path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, module_path, MAX_PATH);
    const auto plugin_dir = std::filesystem::path(module_path).parent_path() / L"plugins" / L"python";
    if (!std::filesystem::exists(plugin_dir)) return {};
    const std::string python_command = python_interpreter_command();
    for (const auto& entry : std::filesystem::directory_iterator(plugin_dir)) {
        if (entry.path().extension() != L".py") continue;
        if (entry.path().filename() == L"plugin_window_host.py") continue;
        const auto command = python_command + " \"" + entry.path().string() + "\" --query-font 2>NUL";
        FILE* pipe = _popen(command.c_str(), "r");
        if (!pipe) continue;
        char buffer[256]{};
        std::string output;
        if (fgets(buffer, sizeof(buffer), pipe)) output = buffer;
        _pclose(pipe);
        const std::string prefix = "font=";
        if (output.rfind(prefix, 0) == 0) {
            auto name = output.substr(prefix.size());
            while (!name.empty() && (name.back() == '\r' || name.back() == '\n')) name.pop_back();
            return wide(name);
        }
    }
    return {};
}

std::optional<std::filesystem::path> python_interpreter_path() {
    const std::filesystem::path system_python = L"C:\\Python314\\python.exe";
    if (std::filesystem::exists(system_python)) return system_python;
    wchar_t local_app_data[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data, MAX_PATH) != 0) {
        for (const auto version : {L"Python314", L"Python313", L"Python312"}) {
            const auto candidate = std::filesystem::path(local_app_data) / L"Programs" / L"Python" / version / L"python.exe";
            if (std::filesystem::exists(candidate)) return candidate;
        }
    }
    return std::nullopt;
}

std::string python_interpreter_command() {
    if (const auto path = python_interpreter_path()) return "\"" + path->string() + "\"";
    return "py -3";
}

std::wstring quote_process_argument(const std::filesystem::path& value) {
    return L"\"" + value.wstring() + L"\"";
}

bool plugin_exposes_python_register(const std::filesystem::path& script) {
    std::ifstream input(script, std::ios::binary);
    if (!input) return false;
    const std::string source((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    return source.find("def register(") != std::string::npos || source.find("def register (" ) != std::string::npos;
}

bool launch_python_plugin_window(HWND window, const std::filesystem::path& plugin) {
    wchar_t module_path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, module_path, MAX_PATH);
    const auto host = std::filesystem::path(module_path).parent_path() / L"plugins" / L"python" / L"plugin_window_host.py";
    if (!std::filesystem::exists(host)) {
        MessageBoxW(window, L"Не найден Python plugin window host.", L"Plugins", MB_ICONERROR);
        return false;
    }

    std::filesystem::path executable;
    std::wstring arguments;
    if (const auto python = python_interpreter_path()) {
        executable = *python;
        arguments = quote_process_argument(host) + L" " + quote_process_argument(plugin)
            + L" --pid " + std::to_wstring(g_debug_pid.load())
            + L" --pid-file " + quote_process_argument(debug_pid_file());
    } else {
        wchar_t system_directory[MAX_PATH]{};
        GetSystemDirectoryW(system_directory, MAX_PATH);
        executable = std::filesystem::path(system_directory) / L"py.exe";
        if (!std::filesystem::exists(executable)) executable = L"py.exe";
        arguments = L"-3 " + quote_process_argument(host) + L" " + quote_process_argument(plugin)
            + L" --pid " + std::to_wstring(g_debug_pid.load())
            + L" --pid-file " + quote_process_argument(debug_pid_file());
    }
    std::wstring command_line = quote_process_argument(executable) + L" " + arguments;
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, command_line.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, nullptr,
                        host.parent_path().c_str(), &startup, &process)) {
        MessageBoxW(window, L"Не удалось запустить отдельное окно Python-плагина.", L"Plugins", MB_ICONERROR);
        return false;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return true;
}

std::string utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<std::size_t>(size), '\0'); WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr); return result;
}

std::vector<std::uint8_t> assemble_with_keystone(const std::wstring& assembly, std::uint64_t address, bool is64, std::string& error) {
    const auto directory = std::filesystem::temp_directory_path();
    const auto stem = std::string("gandon_keystone_") + std::to_string(GetCurrentProcessId());
    const auto script = directory / (stem + ".py"); const auto source = directory / (stem + ".asm");
    { std::ofstream output(source, std::ios::binary | std::ios::trunc); const auto text = utf8(assembly); output.write(text.data(), static_cast<std::streamsize>(text.size())); }
    const char* script_text =
        "import sys\n"
        "from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64\n"
        "try:\n"
        "    text = open(sys.argv[1], encoding='utf-8').read()\n"
        "    mode = KS_MODE_64 if sys.argv[3] == '64' else KS_MODE_32\n"
        "    encoded, _ = Ks(KS_ARCH_X86, mode).asm(text, int(sys.argv[2], 0))\n"
        "    print(bytes(encoded).hex())\n"
        "except Exception as exc:\n"
        "    print('ERROR:' + str(exc))\n";
    { std::ofstream output(script, std::ios::binary | std::ios::trunc); output.write(script_text, static_cast<std::streamsize>(std::strlen(script_text))); }
    const auto command = "set PYTHONUTF8=1&& set PYTHONIOENCODING=utf-8&& " + python_interpreter_command() + " \"" + script.string() + "\" \"" + source.string() + "\" \"0x" + [&] { std::ostringstream value; value << std::hex << address; return value.str(); }() + "\" \"" + (is64 ? "64" : "32") + "\" 2>&1";
    FILE* pipe = _popen(command.c_str(), "r"); std::string output;
    if (pipe) { char buffer[512]{}; while (fgets(buffer, sizeof(buffer), pipe)) output += buffer; _pclose(pipe); }
    std::error_code ignored; std::filesystem::remove(script, ignored); std::filesystem::remove(source, ignored);
    while (!output.empty() && (output.back() == '\r' || output.back() == '\n' || output.back() == ' ')) output.pop_back();
    if (output.rfind("ERROR:", 0) == 0) { error = output.substr(6); return {}; }
    if (output.empty()) { error = "Keystone returned no bytes."; return {}; }
    std::vector<std::uint8_t> bytes; if (output.size() % 2 != 0) { error = "Keystone returned malformed bytes."; return {}; }
    for (std::size_t index = 0; index < output.size(); index += 2) { try { bytes.push_back(static_cast<std::uint8_t>(std::stoul(output.substr(index, 2), nullptr, 16))); } catch (...) { error = "Keystone returned invalid bytes."; return {}; } }
    return bytes;
}

void load_python_plugin(HWND window) {
    wchar_t file_name[MAX_PATH]{};
    OPENFILENAMEW dialog{sizeof(dialog)};
    dialog.hwndOwner = window;
    dialog.lpstrFilter = L"Python plugins (*.py)\0*.py\0All files (*.*)\0*.*\0";
    dialog.lpstrFile = file_name;
    dialog.nMaxFile = MAX_PATH;
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&dialog)) return;

    const auto script_path = std::filesystem::path(file_name);
    const auto command = "set PYTHONUTF8=1&& set PYTHONIOENCODING=utf-8&& " + python_interpreter_command() + " \"" + script_path.string() + "\" --gandon-load 2>&1";
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        MessageBoxW(window, L"Не удалось запустить Python-плагин.", L"Plugins", MB_ICONERROR);
        return;
    }
    char buffer[512]{};
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe)) output += buffer;
    const int exit_code = _pclose(pipe);
    bool returned_font = false;
    bool separate_window = false;
    std::vector<std::string> actions;
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.rfind("font=", 0) == 0) {
            set_code_font(wide(line.substr(5)));
            returned_font = true;
            InvalidateRect(window, nullptr, TRUE);
        } else if (line.rfind("action=", 0) == 0 && line.size() > 7) {
            actions.push_back(line.substr(7));
        }
    }
    std::size_t registered = 0;
    for (const auto& action : actions) {
        if (g_python_plugin_actions.size() >= 256) break;
        const int menu_id = ID_PYTHON_PLUGIN_FIRST + static_cast<int>(g_python_plugin_actions.size());
        g_python_plugin_actions.push_back({menu_id, script_path, action});
        AppendMenuW(g_plugins_menu, MF_STRING, menu_id, wide(action).c_str());
        ++registered;
    }
    if (actions.empty() && !returned_font && plugin_exposes_python_register(script_path))
        separate_window = launch_python_plugin_window(window, script_path);
    if (registered) DrawMenuBar(window);
    std::wstring message = L"Plugin: " + std::filesystem::path(file_name).filename().wstring() + L"\r\n";
    const bool loaded = separate_window || exit_code == 0 || returned_font || registered != 0;
    message += loaded ? L"Loaded successfully." : L"Plugin returned an error.";
    if (registered) message += L"\r\nActions registered: " + std::to_wstring(registered);
    if (separate_window) message += L"\r\nSeparate Python plugin window started.";
    if (!loaded && !output.empty()) message += L"\r\n\r\n" + wide(output);
    MessageBoxW(window, message.c_str(), L"Plugins", loaded ? MB_ICONINFORMATION : MB_ICONERROR);
}

bool invoke_python_plugin_action(HWND window, int menu_id) {
    const auto found = std::find_if(g_python_plugin_actions.begin(), g_python_plugin_actions.end(), [menu_id](const auto& action) { return action.menu_id == menu_id; });
    if (found == g_python_plugin_actions.end()) return false;
    std::string binary;
    if (g_database) binary = g_database->image().path.string();
    std::ostringstream address; address << "0x" << std::hex << std::uppercase << g_current_address;
    const auto command = "set PYTHONUTF8=1&& set PYTHONIOENCODING=utf-8&& " + python_interpreter_command() + " \"" + found->script.string() + "\" --gandon-action \"" + found->action + "\" --binary \"" + binary + "\" --address " + address.str() + " 2>&1";
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) { SetWindowTextW(g_status, L"Could not start Python plugin action."); return true; }
    char buffer[512]{}; std::string output;
    while (fgets(buffer, sizeof(buffer), pipe)) output += buffer;
    const int exit_code = _pclose(pipe);
    std::wstring status;
    std::istringstream lines(output); std::string line;
    while (std::getline(lines, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.rfind("status=", 0) == 0) status = wide(line.substr(7));
        else if (line.rfind("font=", 0) == 0) set_code_font(wide(line.substr(5)));
        else if (line.rfind("navigate=", 0) == 0 && g_database) {
            try { navigate_to_address(window, std::stoull(line.substr(9), nullptr, 0), 1); } catch (...) {}
        }
    }
    if (!status.empty()) SetWindowTextW(g_status, status.c_str());
    if (exit_code != 0) MessageBoxW(window, wide(output).c_str(), L"Python Plugin Action", MB_ICONERROR);
    else if (!output.empty() && status.empty()) MessageBoxW(window, wide(output).c_str(), L"Python Plugin Action", MB_ICONINFORMATION);
    return true;
}

void unload_python_plugins(HWND window) {
    for (const auto& action : g_python_plugin_actions) DeleteMenu(g_plugins_menu, action.menu_id, MF_BYCOMMAND);
    g_python_plugin_actions.clear();
    DrawMenuBar(window);
    SetWindowTextW(g_status, L"Python plugin actions unloaded.");
}

void open_python_plugins_folder() {
    wchar_t module_path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, module_path, MAX_PATH);
    const auto plugin_dir = std::filesystem::path(module_path).parent_path() / L"plugins" / L"python";
    std::filesystem::create_directories(plugin_dir);
    const auto target = L"explorer.exe \"" + plugin_dir.wstring() + L"\"";
    _wsystem(target.c_str());
}

void rebuild_graph_model() {
    g_graph_blocks.clear();
    g_graph_edges.clear();
    if (!g_database) return;
    const auto function = g_database->function_at(g_current_address);
    const auto start = function ? function->get().start : g_database->image().entry_point;
    if (!start) return;
    std::uint64_t function_end = UINT64_MAX;
    const auto& functions = g_database->functions();
    for (std::size_t index = 0; index < functions.size(); ++index) {
        if (functions[index].start != start) continue;
        if (index + 1 < functions.size()) function_end = functions[index + 1].start;
        break;
    }
    auto branch_target = [](const std::string& operands) -> std::optional<std::uint64_t> {
        const auto first = operands.find("0x");
        if (first == std::string::npos) return std::nullopt;
        const auto last = operands.find_first_not_of("0123456789abcdefABCDEF", first + 2);
        try { return std::stoull(operands.substr(first, last - first), nullptr, 16); } catch (...) { return std::nullopt; }
    };
    const auto inside_function = [&](std::uint64_t address) {
        return address >= start && address < function_end && g_database->image().va_to_file_offset(address).has_value();
    };
    std::vector<std::uint64_t> worklist{start};
    std::set<std::uint64_t> visited;
    while (!worklist.empty() && g_graph_blocks.size() < 48) {
        const auto block_start = worklist.front(); worklist.erase(worklist.begin());
        if (!inside_function(block_start) || !visited.insert(block_start).second) continue;
        GraphBlock block; block.start = block_start;
        const auto decoded = gandon::decode_x64(g_database->image(), block_start, 96);
        for (const auto& instruction : decoded) {
            if (!inside_function(instruction.address)) break;
            block.instructions.push_back(instruction);
            const auto& mnemonic = instruction.mnemonic;
            const bool conditional_jump = mnemonic.size() > 1 && mnemonic.front() == 'j' && mnemonic != "jmp";
            if (mnemonic == "jmp" || conditional_jump) {
                const auto target = branch_target(instruction.operands);
                if (target && inside_function(*target)) {
                    g_graph_edges.push_back({block_start, *target, conditional_jump ? GraphEdgeKind::TrueBranch : GraphEdgeKind::Unconditional});
                    worklist.push_back(*target);
                }
                if (conditional_jump) {
                    const auto fallthrough = instruction.address + instruction.size;
                    if (inside_function(fallthrough)) {
                        g_graph_edges.push_back({block_start, fallthrough, GraphEdgeKind::FalseBranch});
                        worklist.push_back(fallthrough);
                    }
                }
                break;
            }
            if (mnemonic == "ret" || mnemonic == "iret" || mnemonic == "int3") break;
        }
        if (block.instructions.empty()) continue;
        block.height = 44 + static_cast<int>((std::min<std::size_t>)(block.instructions.size(), 14)) * 18 + (g_custom_comments.contains(block.start) ? 18 : 0);
        g_graph_blocks.push_back(std::move(block));
    }
    std::sort(g_graph_edges.begin(), g_graph_edges.end(), [](const GraphEdge& left, const GraphEdge& right) {
        return std::tie(left.from, left.to, left.kind) < std::tie(right.from, right.to, right.kind);
    });
    g_graph_edges.erase(std::unique(g_graph_edges.begin(), g_graph_edges.end(), [](const GraphEdge& left, const GraphEdge& right) {
        return left.from == right.from && left.to == right.to && left.kind == right.kind;
    }), g_graph_edges.end());

    // Assign each block once using a breadth-first traversal. Repeatedly
    // relaxing levels makes every loop/back-edge increase its own level and
    // eventually pushes the whole CFG far below the visible canvas.
    std::map<std::uint64_t, int> levels;
    levels[start] = 0;
    std::vector<std::uint64_t> level_queue{start};
    for (std::size_t cursor = 0; cursor < level_queue.size(); ++cursor) {
        const auto source_address = level_queue[cursor];
        for (const auto& edge : g_graph_edges) {
            if (edge.from != source_address || levels.contains(edge.to)) continue;
            levels[edge.to] = levels[source_address] + 1;
            level_queue.push_back(edge.to);
        }
    }
    std::map<int, std::vector<GraphBlock*>> rows;
    for (auto& block : g_graph_blocks) {
        const auto level = levels.contains(block.start) ? levels[block.start] : 0;
        rows[level].push_back(&block);
    }
    for (auto& [level, row] : rows) {
        // Keep a real gutter between sibling blocks.  The old 470px pitch was
        // only 40px wider than the old 430px block and long operands leaked
        // into the neighbouring node.
        constexpr int column_pitch = 620;
        const int row_width = static_cast<int>(row.size()) * column_pitch - 100;
        const int left = (std::max)(64, 640 - row_width / 2);
        for (std::size_t column = 0; column < row.size(); ++column) {
            row[column]->x = left + static_cast<int>(column) * column_pitch;
            row[column]->y = 42 + level * 300;
            if (const auto saved = g_graph_positions.find(row[column]->start); saved != g_graph_positions.end()) {
                row[column]->x = saved->second.first;
                row[column]->y = saved->second.second;
            }
        }
    }
    g_graph_scroll_x = 0;
    g_graph_scroll_y = 0;
    update_graph_scrollbars(g_view);
    invalidate_minimap();
}

std::pair<int, int> graph_content_size() {
    int width = 1, height = 1;
    for (const auto& block : g_graph_blocks) {
        width = (std::max)(width, block.x + block.width + 100);
        height = (std::max)(height, block.y + block.height + 100);
    }
    return {width, height};
}

void invalidate_minimap() {
    if (!g_minimap) return;
    InvalidateRect(g_minimap, nullptr, FALSE);
    UpdateWindow(g_minimap);
}

void clamp_graph_scroll(HWND graph) {
    if (!graph) return;
    RECT client{}; GetClientRect(graph, &client);
    const double scale = static_cast<double>(g_graph_zoom) / 100.0;
    const auto [world_width, world_height] = graph_content_size();
    const int max_x = static_cast<int>(world_width * scale) + GRAPH_PAN_PADDING;
    const int max_y = static_cast<int>(world_height * scale) + GRAPH_PAN_PADDING;
    g_graph_scroll_x = (std::max)(-GRAPH_PAN_PADDING, (std::min)(g_graph_scroll_x, max_x));
    g_graph_scroll_y = (std::max)(-GRAPH_PAN_PADDING, (std::min)(g_graph_scroll_y, max_y));
    SetScrollPos(graph, SB_HORZ, g_graph_scroll_x, FALSE);
    SetScrollPos(graph, SB_VERT, g_graph_scroll_y, FALSE);
}

void update_graph_scrollbars(HWND graph) {
    if (!graph) return;
    RECT client{};
    GetClientRect(graph, &client);
    const double scale = static_cast<double>(g_graph_zoom) / 100.0;
    const auto [world_width, world_height] = graph_content_size();
    int content_width = static_cast<int>(world_width * scale);
    int content_height = static_cast<int>(world_height * scale);
    const int client_width = (std::max)(1, static_cast<int>(client.right));
    const int client_height = (std::max)(1, static_cast<int>(client.bottom));
    content_width = (std::max)(content_width, client_width);
    content_height = (std::max)(content_height, client_height);
    SCROLLINFO horizontal{sizeof(horizontal), SIF_RANGE | SIF_PAGE | SIF_POS, -GRAPH_PAN_PADDING,
                          content_width + GRAPH_PAN_PADDING + client_width - 1, static_cast<UINT>(client_width), static_cast<int>(g_graph_scroll_x), 0};
    SCROLLINFO vertical{sizeof(vertical), SIF_RANGE | SIF_PAGE | SIF_POS, -GRAPH_PAN_PADDING,
                        content_height + GRAPH_PAN_PADDING + client_height - 1, static_cast<UINT>(client_height), static_cast<int>(g_graph_scroll_y), 0};
    SetScrollInfo(graph, SB_HORZ, &horizontal, TRUE);
    SetScrollInfo(graph, SB_VERT, &vertical, TRUE);
    g_graph_scroll_x = GetScrollPos(graph, SB_HORZ);
    g_graph_scroll_y = GetScrollPos(graph, SB_VERT);
}

void scroll_graph(HWND graph, int bar, UINT code, int track_position = 0) {
    if (!graph) return;
    SCROLLINFO info{sizeof(info), SIF_ALL};
    GetScrollInfo(graph, bar, &info);
    int position = info.nPos;
    const int step = 48;
    const int page = (std::max)(1, static_cast<int>(info.nPage));
    if (bar == SB_HORZ) switch (code) {
    case SB_LINELEFT: position -= step; break;
    case SB_LINERIGHT: position += step; break;
    case SB_PAGELEFT: position -= page; break;
    case SB_PAGERIGHT: position += page; break;
    case SB_THUMBTRACK: case SB_THUMBPOSITION: position = track_position; break;
    case SB_TOP: position = info.nMin; break;
    case SB_BOTTOM: position = info.nMax - page + 1; break;
    default: return;
    } else switch (code) {
    case SB_LINEUP: position -= step; break;
    case SB_LINEDOWN: position += step; break;
    case SB_PAGEUP: position -= page; break;
    case SB_PAGEDOWN: position += page; break;
    case SB_THUMBTRACK: case SB_THUMBPOSITION: position = track_position; break;
    case SB_TOP: position = info.nMin; break;
    case SB_BOTTOM: position = info.nMax - page + 1; break;
    default: return;
    }
    const int minimum = info.nMin;
    const int maximum = (std::max)(minimum, info.nMax - page + 1);
    position = (std::max)(minimum, (std::min)(position, maximum));
    info.fMask = SIF_POS;
    info.nPos = position;
    SetScrollInfo(graph, bar, &info, TRUE);
    if (bar == SB_HORZ) g_graph_scroll_x = position;
    else g_graph_scroll_y = position;
    InvalidateRect(graph, nullptr, FALSE);
    invalidate_minimap();
}

std::optional<std::uint64_t> graph_address_at(int client_x, int client_y) {
    const double scale = static_cast<double>(g_graph_zoom) / 100.0;
    const int x = static_cast<int>((client_x + g_graph_scroll_x) / scale);
    const int y = static_cast<int>((client_y + g_graph_scroll_y) / scale);
    for (const auto& block : g_graph_blocks) {
        if (x < block.x || x >= block.x + block.width || y < block.y || y >= block.y + block.height) continue;
        if (y < block.y + 28) return block.start;
        const auto comment_lines = g_custom_comments.contains(block.start) ? 1 : 0;
        const auto raw_index = (y - block.y - 26) / 18 - comment_lines;
        if (raw_index < 0) return block.start;
        const auto index = static_cast<std::size_t>(raw_index);
        if (index < block.instructions.size()) return block.instructions[index].address;
        return block.start;
    }
    return std::nullopt;
}

GraphBlock* graph_block_at(int client_x, int client_y) {
    const double scale = static_cast<double>(g_graph_zoom) / 100.0;
    const int x = static_cast<int>((client_x + g_graph_scroll_x) / scale);
    const int y = static_cast<int>((client_y + g_graph_scroll_y) / scale);
    for (auto& block : g_graph_blocks) {
        if (x >= block.x && x < block.x + block.width && y >= block.y && y < block.y + block.height)
            return &block;
    }
    return nullptr;
}

LRESULT CALLBACK minimap_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_ERASEBKGND) return 1;
    if (message == WM_LBUTTONDOWN && g_view && !g_graph_blocks.empty()) {
        RECT client{}; GetClientRect(window, &client);
        const auto [world_width, world_height] = graph_content_size();
        const int map_width = (std::max)(1L, client.right - 16L);
        const int map_height = (std::max)(1L, client.bottom - 16L);
        const int mouse_x = static_cast<int>(static_cast<short>(LOWORD(lparam)));
        const int mouse_y = static_cast<int>(static_cast<short>(HIWORD(lparam)));
        const double world_x = (std::max)(0.0, (std::min)(static_cast<double>(world_width),
            (static_cast<double>(mouse_x - 8) / map_width) * world_width));
        const double world_y = (std::max)(0.0, (std::min)(static_cast<double>(world_height),
            (static_cast<double>(mouse_y - 8) / map_height) * world_height));
        RECT view{}; GetClientRect(g_view, &view);
        const double scale = static_cast<double>(g_graph_zoom) / 100.0;
        g_graph_scroll_x = static_cast<int>(world_x * scale - view.right / 2.0);
        g_graph_scroll_y = static_cast<int>(world_y * scale - view.bottom / 2.0);
        clamp_graph_scroll(g_view);
        g_minimap_dragging = true;
        SetCapture(window);
        InvalidateRect(g_view, nullptr, FALSE);
        InvalidateRect(window, nullptr, FALSE);
        invalidate_minimap();
        return 0;
    }
    if (message == WM_MOUSEMOVE && g_minimap_dragging && g_view && !g_graph_blocks.empty()) {
        RECT client{}; GetClientRect(window, &client);
        const auto [world_width, world_height] = graph_content_size();
        const int map_width = (std::max)(1L, client.right - 16L);
        const int map_height = (std::max)(1L, client.bottom - 16L);
        const int mouse_x = static_cast<int>(static_cast<short>(LOWORD(lparam)));
        const int mouse_y = static_cast<int>(static_cast<short>(HIWORD(lparam)));
        const double world_x = (std::max)(0.0, (std::min)(static_cast<double>(world_width),
            (static_cast<double>(mouse_x - 8) / map_width) * world_width));
        const double world_y = (std::max)(0.0, (std::min)(static_cast<double>(world_height),
            (static_cast<double>(mouse_y - 8) / map_height) * world_height));
        RECT view{}; GetClientRect(g_view, &view);
        const double scale = static_cast<double>(g_graph_zoom) / 100.0;
        g_graph_scroll_x = static_cast<int>(world_x * scale - view.right / 2.0);
        g_graph_scroll_y = static_cast<int>(world_y * scale - view.bottom / 2.0);
        clamp_graph_scroll(g_view);
        InvalidateRect(g_view, nullptr, FALSE);
        InvalidateRect(window, nullptr, FALSE);
        return 0;
    }
    if (message == WM_LBUTTONUP || message == WM_CAPTURECHANGED) {
        if (g_minimap_dragging) {
            g_minimap_dragging = false;
            if (GetCapture() == window) ReleaseCapture();
            InvalidateRect(window, nullptr, FALSE);
            return 0;
        }
    }
    if (message == WM_PAINT) {
        PAINTSTRUCT paint{}; HDC dc = BeginPaint(window, &paint);
        RECT client{}; GetClientRect(window, &client);
        HBRUSH background = CreateSolidBrush(RGB(16, 19, 24));
        FillRect(dc, &client, background); DeleteObject(background);
        if (!g_graph_blocks.empty()) {
            const auto [world_width, world_height] = graph_content_size();
            const int map_width = (std::max)(1L, client.right - 16L);
            const int map_height = (std::max)(1L, client.bottom - 16L);
            const auto map_x = [&](int value) { return 8 + static_cast<int>(value * static_cast<double>(map_width) / world_width); };
            const auto map_y = [&](int value) { return 8 + static_cast<int>(value * static_cast<double>(map_height) / world_height); };
            const auto find_block = [](std::uint64_t address) -> const GraphBlock* {
                for (const auto& block : g_graph_blocks) if (block.start == address) return &block;
                return nullptr;
            };
            for (const auto& edge : g_graph_edges) {
                const auto* source = find_block(edge.from); const auto* target = find_block(edge.to);
                if (!source || !target) continue;
                const COLORREF color = edge.kind == GraphEdgeKind::TrueBranch ? RGB(73, 190, 104)
                    : edge.kind == GraphEdgeKind::FalseBranch ? RGB(224, 92, 92) : RGB(86, 157, 214);
                HPEN pen = CreatePen(PS_SOLID, 1, color); HGDIOBJ old = SelectObject(dc, pen);
                MoveToEx(dc, map_x(source->x + source->width / 2), map_y(source->y + source->height), nullptr);
                LineTo(dc, map_x(target->x + target->width / 2), map_y(target->y));
                SelectObject(dc, old); DeleteObject(pen);
            }
            for (const auto& block : g_graph_blocks) {
                RECT box{map_x(block.x), map_y(block.y), map_x(block.x + block.width), map_y(block.y + block.height)};
                const bool active = block.start == g_current_address || std::any_of(block.instructions.begin(), block.instructions.end(),
                    [](const auto& instruction) { return instruction.address == g_current_address; });
                HBRUSH fill = CreateSolidBrush(active ? RGB(0, 139, 190) : RGB(67, 82, 96));
                FillRect(dc, &box, fill); DeleteObject(fill);
            }
            RECT view{}; GetClientRect(g_view, &view);
            const double scale = static_cast<double>(g_graph_zoom) / 100.0;
            RECT viewport{
                map_x(static_cast<int>(g_graph_scroll_x / scale)),
                map_y(static_cast<int>(g_graph_scroll_y / scale)),
                map_x(static_cast<int>((g_graph_scroll_x + view.right) / scale)),
                map_y(static_cast<int>((g_graph_scroll_y + view.bottom) / scale))};
            HPEN frame = CreatePen(PS_SOLID, 2, RGB(230, 190, 70)); HGDIOBJ old = SelectObject(dc, frame);
            HGDIOBJ old_brush = SelectObject(dc, GetStockObject(NULL_BRUSH)); Rectangle(dc, viewport.left, viewport.top, viewport.right, viewport.bottom);
            SelectObject(dc, old_brush); SelectObject(dc, old); DeleteObject(frame);
        }
        SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(170, 185, 198));
        HFONT old_font = reinterpret_cast<HFONT>(SelectObject(dc, g_ui_font));
        TextOutW(dc, 8, client.bottom - 15, L"MINIMAP", 7);
        SelectObject(dc, old_font); EndPaint(window, &paint); return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

void show_graph_context_menu(HWND graph, int client_x, int client_y) {
    const auto address = graph_address_at(client_x, client_y);
    if (!address || !g_database) return;
    g_current_address = *address;
    g_session_dirty = true;
    std::wostringstream status; status << L"Selected instruction: 0x" << std::hex << std::uppercase << *address;
    SetWindowTextW(g_status, status.str().c_str());
    HMENU context = CreatePopupMenu();
    AppendMenuW(context, MF_STRING, ID_EDIT_INSTRUCTION, L"Patch Instruction...");
    AppendMenuW(context, MF_STRING, ID_NOP_BLOCK, L"Patch Function (NOP)");
    AppendMenuW(context, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(context, MF_STRING, ID_TOGGLE_BP, L"Toggle Breakpoint");
    AppendMenuW(context, MF_STRING, ID_DECOMPILE, L"View Pseudocode (F5)");
    AppendMenuW(context, MF_STRING, ID_SIGMAKER, L"Generate Signature");
    AppendMenuW(context, MF_STRING, ID_RENAME_LABEL, L"Rename Label");
    AppendMenuW(context, MF_STRING, ID_ADD_COMMENT, L"Add Comment");
    AppendMenuW(context, MF_STRING, ID_ASSIGN_TYPE, L"Assign Type...");
    AppendMenuW(context, MF_STRING, ID_HIDE_FUNCTION, L"Hide Function from Analysis");
    HMENU colors = CreatePopupMenu();
    AppendMenuW(colors, MF_STRING, ID_COLOR_DEFAULT, L"Default Dark");
    AppendMenuW(colors, MF_STRING, ID_COLOR_GREEN, L"Success / True (Green)");
    AppendMenuW(colors, MF_STRING, ID_COLOR_RED, L"Failure / Detection (Red)");
    AppendMenuW(colors, MF_STRING, ID_COLOR_BLUE, L"Info (Blue)");
    AppendMenuW(context, MF_POPUP, reinterpret_cast<UINT_PTR>(colors), L"Set Color Tag");
    POINT point{client_x, client_y}; ClientToScreen(graph, &point);
    TrackPopupMenu(context, TPM_RIGHTBUTTON, point.x, point.y, 0, GetParent(graph), nullptr);
    DestroyMenu(context);
}

LRESULT CALLBACK graph_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_ERASEBKGND) return 1;
    if (message == WM_MOUSEWHEEL) {
        const int delta = GET_WHEEL_DELTA_WPARAM(wparam);
        g_graph_zoom = (std::max)(25, (std::min)(180, g_graph_zoom + (delta > 0 ? 10 : -10)));
        update_graph_scrollbars(window);
        InvalidateRect(window, nullptr, FALSE);
        invalidate_minimap();
        return 0;
    }
    if (message == WM_HSCROLL) {
        scroll_graph(window, SB_HORZ, LOWORD(wparam), HIWORD(wparam));
        return 0;
    }
    if (message == WM_VSCROLL) {
        scroll_graph(window, SB_VERT, LOWORD(wparam), HIWORD(wparam));
        return 0;
    }
    if (message == WM_MBUTTONDOWN) {
        g_graph_panning = true;
        g_graph_pan_moved = false;
        g_graph_pan_origin = {static_cast<LONG>(static_cast<short>(LOWORD(lparam))), static_cast<LONG>(static_cast<short>(HIWORD(lparam)))};
        g_graph_pan_start_x = g_graph_scroll_x;
        g_graph_pan_start_y = g_graph_scroll_y;
        SetCapture(window);
        return 0;
    }
    if (message == WM_RBUTTONDOWN) {
        g_graph_panning = true;
        g_graph_pan_moved = false;
        g_graph_pan_origin = {static_cast<LONG>(static_cast<short>(LOWORD(lparam))), static_cast<LONG>(static_cast<short>(HIWORD(lparam)))};
        g_graph_pan_start_x = g_graph_scroll_x;
        g_graph_pan_start_y = g_graph_scroll_y;
        SetCapture(window);
        return 0;
    }
    if (message == WM_MOUSEMOVE && g_graph_panning) {
        const int current_x = static_cast<int>(static_cast<short>(LOWORD(lparam)));
        const int current_y = static_cast<int>(static_cast<short>(HIWORD(lparam)));
        g_graph_pan_moved = g_graph_pan_moved || current_x != g_graph_pan_origin.x || current_y != g_graph_pan_origin.y;
        g_graph_scroll_x = g_graph_pan_start_x - (current_x - g_graph_pan_origin.x);
        g_graph_scroll_y = g_graph_pan_start_y - (current_y - g_graph_pan_origin.y);
        clamp_graph_scroll(window);
        InvalidateRect(window, nullptr, FALSE);
        invalidate_minimap();
        return 0;
    }
    if (message == WM_MBUTTONUP) {
        g_graph_panning = false;
        g_graph_pan_moved = false;
        ReleaseCapture();
        return 0;
    }
    if (message == WM_RBUTTONUP) {
        const bool moved = g_graph_pan_moved;
        g_graph_panning = false;
        g_graph_pan_moved = false;
        ReleaseCapture();
        if (moved) return 0;
        if (g_database) show_graph_context_menu(window, static_cast<int>(static_cast<short>(LOWORD(lparam))), static_cast<int>(static_cast<short>(HIWORD(lparam))));
        return 0;
    }
    if (message == WM_LBUTTONDOWN && g_database) {
        const int x = static_cast<int>(static_cast<short>(LOWORD(lparam)));
        const int y = static_cast<int>(static_cast<short>(HIWORD(lparam)));
        if (const auto* block = graph_block_at(x, y)) {
            g_graph_dragging = true;
            g_graph_drag_moved = false;
            g_graph_drag_block = block->start;
            g_graph_drag_origin = {x, y};
            g_graph_drag_start_x = block->x;
            g_graph_drag_start_y = block->y;
            SetCapture(window);
            return 0;
        }
    }
    if (message == WM_MOUSEMOVE && g_graph_dragging) {
        const int x = static_cast<int>(static_cast<short>(LOWORD(lparam)));
        const int y = static_cast<int>(static_cast<short>(HIWORD(lparam)));
        const double scale = static_cast<double>(g_graph_zoom) / 100.0;
        const int delta_x = static_cast<int>((x - g_graph_drag_origin.x) / scale);
        const int delta_y = static_cast<int>((y - g_graph_drag_origin.y) / scale);
        g_graph_drag_moved = g_graph_drag_moved || delta_x != 0 || delta_y != 0;
        for (auto& block : g_graph_blocks) {
            if (block.start != g_graph_drag_block) continue;
            block.x = g_graph_drag_start_x + delta_x;
            block.y = g_graph_drag_start_y + delta_y;
            g_graph_positions[block.start] = {block.x, block.y};
            break;
        }
        update_graph_scrollbars(window);
        InvalidateRect(window, nullptr, FALSE);
        invalidate_minimap();
        return 0;
    }
    if (message == WM_LBUTTONUP && g_graph_dragging) {
        const bool moved = g_graph_drag_moved;
        const int x = static_cast<int>(static_cast<short>(LOWORD(lparam)));
        const int y = static_cast<int>(static_cast<short>(HIWORD(lparam)));
        g_graph_dragging = false;
        g_graph_drag_moved = false;
        g_graph_drag_block = 0;
        ReleaseCapture();
        if (!moved) {
            // Selecting a node/instruction in View-A must keep View-A active.
            // The old handler always switched to Text Listing, which made a
            // normal graph click look like an unwanted tab jump.
            if (const auto address = graph_address_at(x, y)) navigate_to_address(GetParent(window), *address, 0);
        } else {
            g_session_dirty = true;
            SetWindowTextW(g_status, L"CFG block moved. Position saved in the current session.");
        }
        return 0;
    }
    if (message == WM_PAINT) {
        PAINTSTRUCT paint{};
        HDC dc = BeginPaint(window, &paint);
        RECT client{}; GetClientRect(window, &client);
        const double scale = static_cast<double>(g_graph_zoom) / 100.0;
        HBRUSH graph_background = CreateSolidBrush(RGB(24, 27, 32));
        FillRect(dc, &client, graph_background); DeleteObject(graph_background);
        SetBkMode(dc, TRANSPARENT);
        HGDIOBJ graph_font = SelectObject(dc, g_code_font);
        if (!g_database) {
            SetTextColor(dc, RGB(170, 239, 207));
            TextOutW(dc, 24, 24, L"Gandon View-A", 13);
            TextOutW(dc, 24, 52, L"Open a binary to build the control-flow graph.", 45);
        } else {
            RECT header{12, 8, 500, 32};
            HBRUSH header_brush = CreateSolidBrush(RGB(18, 22, 27));
            FillRect(dc, &header, header_brush); DeleteObject(header_brush);
            std::wostringstream graph_header;
            graph_header << L"CFG  0x" << std::hex << std::uppercase << g_current_address
                         << L"   |   blocks " << std::dec << g_graph_blocks.size()
                         << L"   |   zoom " << g_graph_zoom << L"%";
            SetTextColor(dc, RGB(155, 190, 214));
            TextOutW(dc, 22, 14, graph_header.str().c_str(), static_cast<int>(graph_header.str().size()));
            auto find_block = [](std::uint64_t address) -> const GraphBlock* {
                for (const auto& block : g_graph_blocks) if (block.start == address) return &block;
                return nullptr;
            };
            for (const auto& edge : g_graph_edges) {
                const auto* source = find_block(edge.from); const auto* target = find_block(edge.to);
                if (!source || !target) continue;
                const int sx = static_cast<int>((source->x + source->width / 2) * scale) - g_graph_scroll_x;
                const int sy = static_cast<int>((source->y + source->height) * scale) - g_graph_scroll_y;
                const int tx = static_cast<int>((target->x + target->width / 2) * scale) - g_graph_scroll_x;
                const int ty = static_cast<int>(target->y * scale) - g_graph_scroll_y;
                const COLORREF edge_color = edge.kind == GraphEdgeKind::TrueBranch ? RGB(73, 190, 104)
                    : edge.kind == GraphEdgeKind::FalseBranch ? RGB(224, 92, 92) : RGB(86, 157, 214);
                HPEN edge_pen = CreatePen(PS_SOLID, edge.kind == GraphEdgeKind::Unconditional ? 3 : 2, edge_color);
                HGDIOBJ old_pen = SelectObject(dc, edge_pen);
                MoveToEx(dc, sx, sy, nullptr); LineTo(dc, sx, (sy + ty) / 2); LineTo(dc, tx, (sy + ty) / 2); LineTo(dc, tx, ty);
                MoveToEx(dc, tx, ty, nullptr); LineTo(dc, tx - 7, ty - 9); MoveToEx(dc, tx, ty, nullptr); LineTo(dc, tx + 7, ty - 9);
                if (edge.kind != GraphEdgeKind::Unconditional) {
                    const wchar_t* label = edge.kind == GraphEdgeKind::TrueBranch ? L"true" : L"false";
                    SetTextColor(dc, edge_color);
                    const int label_x = tx < sx ? sx - 54 : sx + 8;
                    const int label_y = (sy + ty) / 2 - (edge.kind == GraphEdgeKind::TrueBranch ? 21 : 3);
                    TextOutW(dc, label_x, label_y, label, static_cast<int>(wcslen(label)));
                }
                SelectObject(dc, old_pen); DeleteObject(edge_pen);
            }
            for (const auto& block : g_graph_blocks) {
                const int x = static_cast<int>(block.x * scale) - g_graph_scroll_x, y = static_cast<int>(block.y * scale) - g_graph_scroll_y;
                const int width = static_cast<int>(block.width * scale), height = static_cast<int>(block.height * scale);
                RECT box{x, y, x + width, y + height};
                const bool active_block = block.start == g_current_address || std::any_of(block.instructions.begin(), block.instructions.end(), [](const auto& instruction) { return instruction.address == g_current_address; });
                COLORREF block_color = active_block ? RGB(36, 57, 66) : RGB(32, 39, 47);
                if (const auto color = g_graph_colors.find(block.start); color != g_graph_colors.end()) block_color = color->second;
                HBRUSH fill = CreateSolidBrush(block_color);
                FillRect(dc, &box, fill); DeleteObject(fill);
                HPEN border = CreatePen(PS_SOLID, active_block ? 2 : 1, active_block ? RGB(0, 160, 210) : RGB(62, 78, 91));
                HGDIOBJ old_pen = SelectObject(dc, border); HGDIOBJ old_brush = SelectObject(dc, GetStockObject(NULL_BRUSH));
                Rectangle(dc, box.left, box.top, box.right, box.bottom); SelectObject(dc, old_brush); SelectObject(dc, old_pen); DeleteObject(border);
                // Block geometry is zoomed in world coordinates.  Use a
                // matching font and scaled padding as well; otherwise Fit
                // Graph shrinks the boxes while leaving the text at 100%,
                // producing the overlapping screenshot.
                const int text_height = (std::max)(8, static_cast<int>(std::lround(15.0 * scale)));
                HFONT scaled_font = CreateFontW(-text_height, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                    FIXED_PITCH | FF_DONTCARE, L"Cascadia Mono");
                HGDIOBJ old_block_font = scaled_font ? SelectObject(dc, scaled_font) : nullptr;
                const auto sx = [scale](int value) { return (std::max)(1, static_cast<int>(std::lround(value * scale))); };
                std::wstring title = g_custom_labels.contains(block.start) ? g_custom_labels[block.start] : L"loc_" + [&] { std::wostringstream value; value << std::hex << std::uppercase << block.start; return value.str(); }();
                title += L":";
                SetTextColor(dc, RGB(170, 239, 207)); TextOutW(dc, x + sx(12), y + sx(8), title.c_str(), static_cast<int>(title.size()));
                HPEN separator = CreatePen(PS_SOLID, 1, RGB(52, 64, 74));
                HGDIOBJ old_separator = SelectObject(dc, separator);
                MoveToEx(dc, x + 1, y + sx(27), nullptr); LineTo(dc, x + width - 1, y + sx(27));
                SelectObject(dc, old_separator); DeleteObject(separator);
                int line_y = y + sx(30);
                if (g_custom_comments.contains(block.start)) {
                    const auto comment = L"// " + g_custom_comments[block.start];
                    SetTextColor(dc, RGB(155, 170, 184)); TextOutW(dc, x + sx(12), line_y, comment.c_str(), static_cast<int>(comment.size())); line_y += sx(18);
                }
                for (std::size_t index = 0; index < block.instructions.size() && index < 14; ++index) {
                    const auto& instruction = block.instructions[index];
                    wchar_t address[24]{};
                    swprintf_s(address, L"%llX", static_cast<unsigned long long>(instruction.address));
                    const auto bytes = graph_bytes(instruction);
                    const auto mnemonic = wide(instruction.mnemonic);
                    const auto operands = wide(instruction.operands);
                    SetTextColor(dc, RGB(106, 168, 219)); TextOutW(dc, x + sx(10), line_y, address, static_cast<int>(wcslen(address)));
                    SetTextColor(dc, RGB(125, 132, 140)); TextOutW(dc, x + sx(102), line_y, bytes.c_str(), static_cast<int>(bytes.size()));
                    const COLORREF mnemonic_color = instruction.mnemonic == "call" ? RGB(220, 170, 90)
                        : (!instruction.mnemonic.empty() && instruction.mnemonic.front() == 'j') ? RGB(78, 201, 176)
                        : instruction.mnemonic == "ret" ? RGB(224, 92, 92) : RGB(205, 214, 222);
                    SetTextColor(dc, mnemonic_color); TextOutW(dc, x + sx(252), line_y, mnemonic.c_str(), static_cast<int>(mnemonic.size()));
                    if (x + sx(302) < box.right - sx(8)) {
                        RECT operand_rect{x + sx(302), line_y, box.right - sx(8), line_y + sx(18)};
                        SetTextColor(dc, RGB(215, 228, 238));
                        DrawTextW(dc, operands.c_str(), static_cast<int>(operands.size()), &operand_rect,
                                  DT_SINGLELINE | DT_NOPREFIX | DT_LEFT | DT_END_ELLIPSIS);
                    }
                    line_y += sx(18);
                }
                if (scaled_font) { SelectObject(dc, old_block_font); DeleteObject(scaled_font); }
            }
        }
        SelectObject(dc, graph_font); EndPaint(window, &paint); return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

std::wstring wide(const std::string& value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size);
    if (result.find(L'\ufffd') != std::wstring::npos) {
        const int ansi_size = MultiByteToWideChar(CP_ACP, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
        result.assign(static_cast<std::size_t>(ansi_size), L'\0');
        MultiByteToWideChar(CP_ACP, 0, value.data(), static_cast<int>(value.size()), result.data(), ansi_size);
    }
    return result;
}

void native_plugin_log(void*, const char* message) {
    if (message) OutputDebugStringA(message);
}

void native_plugin_status(void* user_data, const char* message) {
    const auto window = reinterpret_cast<HWND>(user_data);
    if (window && message) SetWindowTextW(g_status, wide(message).c_str());
}

std::uint64_t native_plugin_current_address(void*) {
    return g_current_address;
}

int native_plugin_read_file_bytes(void*, std::uint64_t offset, std::uint8_t* output, std::uint64_t size) {
    if (!g_database || !output || offset > g_database->image().bytes.size() || size > g_database->image().bytes.size() - offset) return 0;
    std::memcpy(output, g_database->image().bytes.data() + static_cast<std::size_t>(offset), static_cast<std::size_t>(size));
    return 1;
}

std::uint64_t native_plugin_function_count(void*) {
    return g_database ? static_cast<std::uint64_t>(g_database->functions().size()) : 0;
}

int native_plugin_function_at(void*, std::uint64_t index, GandonFunctionView* output) {
    if (!g_database || !output || index >= g_database->functions().size()) return 0;
    const auto& function = g_database->functions()[static_cast<std::size_t>(index)];
    thread_local std::string name;
    name = g_custom_labels.contains(function.start) ? utf8(g_custom_labels[function.start]) : function.name;
    output->start = function.start;
    output->name = name.c_str();
    return 1;
}

std::uint64_t native_plugin_xref_count(void*) {
    return g_database ? static_cast<std::uint64_t>(g_database->xrefs().size()) : 0;
}

int native_plugin_xref_at(void*, std::uint64_t index, GandonXrefView* output) {
    if (!g_database || !output || index >= g_database->xrefs().size()) return 0;
    const auto& xref = g_database->xrefs()[static_cast<std::size_t>(index)];
    output->from = xref.from;
    output->to = xref.to;
    output->kind = xref.kind.c_str();
    return 1;
}

std::uint64_t native_plugin_function_instruction_count(void*, std::uint64_t function_index) {
    if (!g_database || function_index >= g_database->functions().size()) return 0;
    return static_cast<std::uint64_t>(g_database->functions()[static_cast<std::size_t>(function_index)].instructions.size());
}

int native_plugin_function_instruction_at(void*, std::uint64_t function_index,
                                          std::uint64_t instruction_index,
                                          GandonInstructionView* output) {
    if (!g_database || !output || function_index >= g_database->functions().size()) return 0;
    const auto& instructions = g_database->functions()[static_cast<std::size_t>(function_index)].instructions;
    if (instruction_index >= instructions.size()) return 0;
    const auto& instruction = instructions[static_cast<std::size_t>(instruction_index)];
    thread_local std::string mnemonic;
    thread_local std::string operands;
    mnemonic = instruction.mnemonic;
    operands = instruction.operands;
    output->address = instruction.address;
    output->size = instruction.size;
    output->mnemonic = mnemonic.c_str();
    output->operands = operands.c_str();
    return 1;
}

int native_plugin_read_process_bytes(void*, std::uint64_t address, std::uint8_t* output, std::uint64_t size) {
    const auto process = g_debug_process.load();
    if (!process || !output || size == 0 || size > static_cast<std::uint64_t>(SIZE_MAX)) return 0;
    SIZE_T read = 0;
    return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), output, static_cast<SIZE_T>(size), &read) && read == size;
}

void native_plugin_navigate(void* user_data, std::uint64_t address) {
    const auto window = reinterpret_cast<HWND>(user_data);
    if (!window || !g_database) return;
    navigate_to_address(window, address, 1);
}

int native_plugin_register_action(void* user_data, const char*, const char* title,
                                  void (*callback)(void*), void* callback_user_data) {
    if (!g_plugins_menu || !title || !callback) return 0;
    if (g_native_plugin_actions.size() >= 256) return 0;
    const int menu_id = ID_NATIVE_PLUGIN_FIRST + static_cast<int>(g_native_plugin_actions.size());
    g_native_plugin_actions.push_back({menu_id, callback, callback_user_data});
    const auto label = wide(title);
    AppendMenuW(g_plugins_menu, MF_STRING, menu_id, label.c_str());
    (void)user_data;
    return 1;
}

bool invoke_native_plugin_action(HWND window, int menu_id) {
    for (const auto& action : g_native_plugin_actions) {
        if (action.menu_id == menu_id) {
            action.callback(action.callback_user_data);
            SetWindowTextW(g_status, L"Native plugin action invoked.");
            (void)window;
            return true;
        }
    }
    return false;
}

void load_native_plugins(HWND window) {
    if (!g_native_plugin_host) g_native_plugin_host = std::make_unique<gandon::PluginHost>();
    g_native_plugin_host->unload_all();
    for (const auto& action : g_native_plugin_actions) DeleteMenu(g_plugins_menu, action.menu_id, MF_BYCOMMAND);
    g_native_plugin_actions.clear();
    wchar_t module_path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, module_path, MAX_PATH);
    const auto directory = std::filesystem::path(module_path).parent_path();
    GandonPluginHost api{};
    api.api_version = GANDON_PLUGIN_API_VERSION;
    api.user_data = window;
    api.log = native_plugin_log;
    api.status = native_plugin_status;
    api.current_address = native_plugin_current_address;
    api.read_file_bytes = native_plugin_read_file_bytes;
    api.navigate = native_plugin_navigate;
    api.register_action = native_plugin_register_action;
    api.function_count = native_plugin_function_count;
    api.function_at = native_plugin_function_at;
    api.xref_count = native_plugin_xref_count;
    api.xref_at = native_plugin_xref_at;
    api.function_instruction_count = native_plugin_function_instruction_count;
    api.function_instruction_at = native_plugin_function_instruction_at;
    api.read_process_bytes = native_plugin_read_process_bytes;
    std::string error;
    if (!g_native_plugin_host->load_directory(directory, api, error)) {
        MessageBoxW(window, wide(error).c_str(), L"Native Plugins", MB_ICONERROR);
        return;
    }
    DrawMenuBar(window);
    SetWindowTextW(g_status, L"Native plugins loaded.");
}

std::wstring listing_text(const gandon::AnalysisDatabase& db) {
    std::wostringstream out;
    out << L"; Gandon-PRO native listing\r\n; Entry point: 0x" << std::hex << db.image().entry_point << L"\r\n\r\n";
    for (const auto& instruction : gandon::decode_x64(db.image(), db.image().entry_point, 400))
        out << L"0x" << std::hex << instruction.address << L"    " << wide(instruction.mnemonic) << L" " << wide(instruction.operands) << L"\r\n";
    return out.str();
}

std::wstring listing_text_at(const gandon::AnalysisDatabase& db, std::uint64_t address) {
    std::wostringstream out;
    out << L"; Function listing\r\n; Start: 0x" << std::hex << address << L"\r\n\r\n";
    for (const auto& instruction : gandon::decode_x64(db.image(), address, 400))
        out << L"0x" << std::hex << instruction.address << L"    " << wide(instruction.mnemonic) << L" " << wide(instruction.operands) << L"\r\n";
    return out.str();
}

std::string trim_ascii(std::string value) {
    const auto first = value.find_first_not_of(" \t"); const auto last = value.find_last_not_of(" \t");
    return first == std::string::npos ? std::string{} : value.substr(first, last - first + 1);
}

bool simple_identifier(const std::string& value) {
    if (value.empty() || !(std::isalpha(static_cast<unsigned char>(value.front())) || value.front() == '_')) return false;
    return std::all_of(value.begin() + 1, value.end(), [](char character) { return std::isalnum(static_cast<unsigned char>(character)) || character == '_'; });
}

std::wstring pseudocode_label(std::uint64_t address) {
    if (g_custom_labels.contains(address)) return g_custom_labels[address];
    wchar_t buffer[40]{}; swprintf_s(buffer, L"loc_%llX", static_cast<unsigned long long>(address)); return buffer;
}

std::wstring pseudocode_text_at(const gandon::AnalysisDatabase& db, std::uint64_t address) {
    const auto function = db.function_at(address);
    const auto start = function ? function->get().start : address;
    const auto name = function ? wide(function->get().name) : pseudocode_label(start);
    const auto instructions = gandon::decode_x64(db.image(), start, 256);
    std::wostringstream out;
    out << L"// =========================================================================\r\n// Decompiled by Gandon-PRO Native Pseudocode Engine\r\n// Function Entry: 0x" << std::hex << std::uppercase << start << L" - " << name << L"\r\n// =========================================================================\r\n\r\n";
    out << L"uint64_t __fastcall " << name << L"(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)\r\n{\r\n    uint64_t result = 0;\r\n";
    if (const auto type = g_custom_types.find(address); type != g_custom_types.end())
        out << L"    // User-assigned type at 0x" << std::hex << std::uppercase << address << L": " << type->second << L"\r\n";
    std::set<std::string> variables; std::vector<std::string> variable_order; std::unordered_map<std::string, std::string> inferred_types; std::string last_left = "result", last_right = "0", last_compare = "==";
    auto infer_type = [](const std::string& operand) {
        std::string lower = operand;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        if (lower.find("xmm") != std::string::npos) return std::string("double");
        if (lower.find("qword ptr") != std::string::npos) return lower.find('[') != std::string::npos ? std::string("uint64_t*") : std::string("uint64_t");
        if (lower.find("dword ptr") != std::string::npos) return std::string("uint32_t");
        if (lower.find("word ptr") != std::string::npos) return std::string("uint16_t");
        if (lower.find("byte ptr") != std::string::npos) return std::string("uint8_t");
        if (lower.find('[') != std::string::npos) return std::string("uint64_t*");
        if (lower == "eax" || lower == "ebx" || lower == "ecx" || lower == "edx" || lower == "esi" || lower == "edi" || lower == "esp" || lower == "ebp") return std::string("uint32_t");
        if (lower == "al" || lower == "bl" || lower == "cl" || lower == "dl") return std::string("uint8_t");
        return std::string("uint64_t");
    };
    for (const auto& instruction : instructions) {
        const auto comma = instruction.operands.find(',');
        const auto left = trim_ascii(comma == std::string::npos ? instruction.operands : instruction.operands.substr(0, comma));
        const auto right = trim_ascii(comma == std::string::npos ? std::string{} : instruction.operands.substr(comma + 1));
        if (simple_identifier(left)) {
            if (variables.insert(left).second) variable_order.push_back(left);
            inferred_types[left] = infer_type(right.empty() ? instruction.operands : right);
        }
    }
    if (!variable_order.empty()) {
        out << L"    // Inferred register/temporary types:\r\n";
        for (const auto& variable : variable_order) out << L"    " << wide(inferred_types.contains(variable) ? inferred_types[variable] : std::string("uint64_t")) << L" " << wide(variable) << L";\r\n";
    }
    out << L"    // Pointer widths and register operands are inferred from Capstone operands.\r\n\r\n";
    int stack_depth = 0;
    for (const auto& instruction : instructions) {
        const auto mnem = instruction.mnemonic; const auto operands = instruction.operands; const auto comma = operands.find(',');
        const auto left = trim_ascii(comma == std::string::npos ? operands : operands.substr(0, comma));
        const auto right = trim_ascii(comma == std::string::npos ? std::string{} : operands.substr(comma + 1));
        out << L"    // 0x" << std::hex << std::uppercase << instruction.address << L": " << wide(mnem + (operands.empty() ? "" : " " + operands)) << L"\r\n";
        if (mnem == "mov" || mnem == "movzx" || mnem == "movsx" || mnem == "movsxd") {
            if (!left.empty() && !right.empty()) out << L"    " << wide(left) << L" = " << wide(right) << L";\r\n";
        } else if (mnem == "lea") {
            if (!left.empty() && !right.empty()) out << L"    " << wide(left) << L" = &(" << wide(right) << L");\r\n";
        } else if (mnem == "xor" && left == right && !left.empty()) out << L"    " << wide(left) << L" = 0;\r\n";
        else if (mnem == "add" || mnem == "sub" || mnem == "xor" || mnem == "and" || mnem == "or" || mnem == "shl" || mnem == "shr" || mnem == "sar" || mnem == "rol" || mnem == "ror") {
            const wchar_t* symbol = mnem == "add" ? L" += " : mnem == "sub" ? L" -= " : mnem == "xor" ? L" ^= " : mnem == "and" ? L" &= " : mnem == "or" ? L" |= " : mnem == "shl" ? L" <<= " : mnem == "shr" ? L" >>= " : mnem == "sar" ? L" >>= " : mnem == "rol" ? L" = rol(" : L" = ror(";
            if (!left.empty() && !right.empty()) {
                if (mnem == "rol" || mnem == "ror") out << L"    " << wide(left) << symbol << wide(left) << L", " << wide(right) << L");\r\n";
                else out << L"    " << wide(left) << symbol << wide(right) << L";\r\n";
            }
        } else if (mnem == "inc" || mnem == "dec" || mnem == "neg" || mnem == "not") {
            if (!left.empty()) {
                const wchar_t* symbol = mnem == "inc" ? L" += 1" : mnem == "dec" ? L" -= 1" : mnem == "neg" ? L" = -" : L" = ~";
                if (mnem == "neg" || mnem == "not") out << L"    " << wide(left) << symbol << wide(left) << L";\r\n";
                else out << L"    " << wide(left) << symbol << L";\r\n";
            }
        } else if (mnem == "imul") {
            if (!left.empty() && !right.empty()) out << L"    " << wide(left) << L" *= " << wide(right) << L";\r\n";
            else if (!left.empty()) out << L"    result = " << wide(left) << L" * result;\r\n";
        } else if (mnem == "idiv" || mnem == "div") {
            if (!left.empty()) out << L"    result /= " << wide(left) << L";\r\n";
        } else if (mnem == "adc" || mnem == "sbb") {
            if (!left.empty() && !right.empty()) out << L"    " << wide(left) << (mnem == "adc" ? L" += " : L" -= ") << wide(right) << L" + carry;\r\n";
        } else if (mnem == "cmp" || mnem == "test") {
            if (mnem == "test") {
                last_left = left.empty() ? "result" : "(" + left + " & " + (right.empty() ? left : right) + ")";
                last_right = "0";
            } else {
                last_left = left.empty() ? "result" : left;
                last_right = right.empty() ? "0" : right;
            }
            last_compare = "==";
        }
        else if (!mnem.empty() && mnem[0] == 'j' && mnem != "jmp") {
            const std::string condition = (mnem == "jne" || mnem == "jnz") ? "!=" : (mnem == "jge" || mnem == "jae" || mnem == "jnc") ? ">=" : (mnem == "jg" || mnem == "ja") ? ">" : (mnem == "jle" || mnem == "jbe") ? "<=" : (mnem == "jl" || mnem == "jb") ? "<" : (mnem == "jc") ? "<" : "==";
            std::uint64_t target = 0; try { target = std::stoull(left, nullptr, 0); } catch (...) {}
            out << L"    if (" << wide(last_left) << L" " << wide(condition) << L" " << wide(last_right) << L") goto " << (target ? pseudocode_label(target) : L"loc_unknown") << L";\r\n";
        } else if (mnem == "jmp") {
            std::uint64_t target = 0; try { target = std::stoull(left, nullptr, 0); } catch (...) {}
            out << L"    goto " << (target ? pseudocode_label(target) : L"loc_unknown") << L";\r\n";
        } else if (mnem == "call") {
            std::uint64_t target = 0; try { target = std::stoull(left, nullptr, 0); } catch (...) {}
            out << L"    result = " << (target ? pseudocode_label(target) : L"sub_unknown") << L"();\r\n";
        } else if (mnem == "cmov" || (mnem.size() > 4 && mnem.rfind("cmov", 0) == 0)) {
            if (!left.empty() && !right.empty()) out << L"    /* conditional move */ " << wide(left) << L" = " << wide(right) << L";\r\n";
        } else if (mnem.size() > 3 && mnem.rfind("set", 0) == 0) {
            if (!left.empty()) out << L"    " << wide(left) << L" = (condition);\r\n";
        } else if (mnem == "push") {
            ++stack_depth;
            out << L"    /* push " << wide(left.empty() ? "value" : left) << L" (stack depth " << stack_depth << L") */\r\n";
        } else if (mnem == "pop") {
            stack_depth = (std::max)(0, stack_depth - 1);
            out << L"    /* pop " << wide(left.empty() ? "value" : left) << L" (stack depth " << stack_depth << L") */\r\n";
        } else if (mnem == "leave") {
            stack_depth = 0;
            out << L"    /* leave: restore frame pointer */\r\n";
        } else if (mnem == "nop" || mnem == "int3" || mnem == "syscall" || mnem == "sysenter") {
            out << L"    /* " << wide(mnem) << L" */\r\n";
        } else if (mnem == "ret") out << L"    return result;\r\n";
        else out << L"    /* " << wide(mnem + (operands.empty() ? "" : " " + operands)) << L" */\r\n";
    }
    out << L"}\r\n"; return out.str();
}

std::wstring pseudocode_text(const gandon::AnalysisDatabase& db) {
    return pseudocode_text_at(db, db.image().entry_point ? db.image().entry_point : db.functions().empty() ? 0 : db.functions().front().start);
}

std::wstring xref_text(const gandon::AnalysisDatabase& db) {
    std::wostringstream out;
    out << L"From                    To                      Type\r\n";
    for (const auto& xref : db.xrefs())
        out << L"0x" << std::hex << xref.from << L"              0x" << xref.to << L"              " << wide(xref.kind) << L"\r\n";
    return out.str();
}

std::wstring memory_map_text(const gandon::AnalysisDatabase& db) {
    std::wostringstream out;
    out << L"Name                 RVA        Raw size       Permissions\r\n";
    for (const auto& section : db.image().sections) {
        out << wide(section.name) << L"                 0x" << std::hex << section.rva << L"       " << std::dec << section.raw_size << L"           ";
        if (section.characteristics & 0x20000000u) out << L"R-X";
        else if (section.characteristics & 0x80000000u) out << L"RW-";
        else out << L"R--";
        out << L"\r\n";
    }
    const auto process = g_debug_process.load();
    if (process) {
        out << L"\r\nProcess memory regions\r\n=======================\r\n";
        std::uintptr_t address = 0;
        MEMORY_BASIC_INFORMATION region{};
        while (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &region, sizeof(region)) == sizeof(region)) {
            std::wstring permissions = L"---";
            const auto protect = region.Protect ? region.Protect : region.AllocationProtect;
            permissions[0] = (protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ? L'R' : L'-';
            permissions[1] = (protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ? L'W' : L'-';
            permissions[2] = (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ? L'X' : L'-';
            out << L"0x" << std::hex << reinterpret_cast<std::uintptr_t>(region.BaseAddress)
                << L"  size 0x" << static_cast<std::uintptr_t>(region.RegionSize)
                << L"  " << permissions << L"  state 0x" << region.State << L"  type 0x" << region.Type << L"\r\n";
            const auto next = reinterpret_cast<std::uintptr_t>(region.BaseAddress) + static_cast<std::uintptr_t>(region.RegionSize);
            if (next <= address) break;
            address = next;
            region = {};
        }
    }
    return out.str();
}

std::uint64_t file_offset_to_va(const gandon::BinaryImage& image, std::size_t offset);

std::optional<std::pair<std::uint32_t, std::uint32_t>> pe_directory(const gandon::BinaryImage& image, std::size_t index) {
    if (image.format != gandon::BinaryFormat::PE || image.bytes.size() < 0x40) return std::nullopt;
    auto read16 = [&](std::size_t offset) -> std::uint16_t { return offset + 2 <= image.bytes.size() ? static_cast<std::uint16_t>(image.bytes[offset] | (image.bytes[offset + 1] << 8)) : 0; };
    auto read32 = [&](std::size_t offset) -> std::uint32_t { return offset + 4 <= image.bytes.size() ? static_cast<std::uint32_t>(image.bytes[offset] | (image.bytes[offset + 1] << 8) | (image.bytes[offset + 2] << 16) | (image.bytes[offset + 3] << 24)) : 0; };
    const auto pe = static_cast<std::size_t>(read32(0x3c)); if (pe + 24 > image.bytes.size()) return std::nullopt;
    const auto optional = pe + 24;
    const auto magic = read16(optional);
    const auto directory = optional + (magic == 0x20b ? 0x70 : 0x60) + index * 8;
    if (directory + 8 > image.bytes.size()) return std::nullopt;
    return std::make_pair(read32(directory), read32(directory + 4));
}

std::wstring import_key(const std::wstring& dll, const std::wstring& name) {
    std::wstring key = dll + L"\n" + name;
    std::transform(key.begin(), key.end(), key.begin(), [](wchar_t value) { return static_cast<wchar_t>(towlower(value)); });
    return key;
}

std::vector<ImportRecord> enumerate_imports(const gandon::BinaryImage& image) {
    std::vector<ImportRecord> result;
    const auto directory = pe_directory(image, 1);
    if (!directory || !directory->first || !directory->second) return result;
    const auto descriptor = image.rva_to_file_offset(directory->first);
    if (!descriptor) return result;
    const auto read32 = [&](std::size_t offset) -> std::uint32_t {
        return offset + 4 <= image.bytes.size()
            ? static_cast<std::uint32_t>(image.bytes[offset] | (image.bytes[offset + 1] << 8) |
                                         (image.bytes[offset + 2] << 16) | (image.bytes[offset + 3] << 24))
            : 0;
    };
    const auto read64 = [&](std::size_t offset) -> std::uint64_t {
        return static_cast<std::uint64_t>(read32(offset)) |
               (static_cast<std::uint64_t>(read32(offset + 4)) << 32);
    };
    const auto read_string = [&](std::size_t offset) {
        std::string value;
        for (std::size_t index = offset; index < image.bytes.size() && image.bytes[index] && value.size() < 512; ++index)
            value.push_back(static_cast<char>(image.bytes[index]));
        return value;
    };
    const std::size_t pointer_size = image.is_64_bit ? 8u : 4u;
    for (std::size_t descriptor_index = 0; descriptor_index < 4096; ++descriptor_index) {
        const auto current = *descriptor + descriptor_index * 20;
        if (current + 20 > image.bytes.size()) break;
        const auto original_thunk = read32(current);
        const auto name_rva = read32(current + 12);
        const auto first_thunk = read32(current + 16);
        if (!original_thunk && !name_rva && !first_thunk) break;
        const auto dll_offset = image.rva_to_file_offset(name_rva);
        const auto lookup_rva = original_thunk ? original_thunk : first_thunk;
        const auto lookup_offset = image.rva_to_file_offset(lookup_rva);
        if (!lookup_offset || !first_thunk) continue;
        const auto dll = dll_offset ? wide(read_string(*dll_offset)) : L"<invalid DLL>";
        for (std::size_t index = 0; index < 65536; ++index) {
            const auto entry = *lookup_offset + index * pointer_size;
            if (entry + pointer_size > image.bytes.size()) break;
            const auto thunk = image.is_64_bit ? read64(entry) : static_cast<std::uint64_t>(read32(entry));
            if (!thunk) break;
            std::wstring name;
            if ((image.is_64_bit && (thunk & (1ull << 63))) || (!image.is_64_bit && (thunk & 0x80000000u))) {
                name = L"Ordinal " + std::to_wstring(thunk & 0xffffu);
            } else {
                const auto hint_name = image.rva_to_file_offset(static_cast<std::uint32_t>(thunk));
                if (hint_name && *hint_name + 2 < image.bytes.size()) name = wide(read_string(*hint_name + 2));
            }
            if (name.empty()) name = L"Ordinal " + std::to_wstring(index);
            result.push_back({dll, name, image.image_base + first_thunk + index * pointer_size});
        }
    }
    return result;
}

std::optional<ImportRecord> import_for_iat(std::uint64_t iat_va) {
    if (!g_database) return std::nullopt;
    for (const auto& record : enumerate_imports(g_database->image()))
        if (record.iat_va == iat_va) return record;
    return std::nullopt;
}

std::optional<ImportRecord> selected_tree_import() {
    if (!g_tree) return std::nullopt;
    const auto item = TreeView_GetSelection(g_tree);
    if (!item) return std::nullopt;
    TVITEMW value{};
    value.mask = TVIF_PARAM;
    value.hItem = item;
    if (!TreeView_GetItem(g_tree, &value) || !value.lParam) return std::nullopt;
    return import_for_iat(static_cast<std::uint64_t>(value.lParam));
}

std::wstring resources_text(const gandon::BinaryImage& image) {
    std::wostringstream out;
    out << L"Resources\r\n=========\r\nType / Name / Language       RVA          Size        File offset\r\n";
    const auto directory = pe_directory(image, 2);
    if (!directory || !directory->first || !directory->second) {
        out << L"No PE resource directory.\r\n";
        return out.str();
    }
    const auto root = image.rva_to_file_offset(directory->first);
    if (!root) {
        out << L"Invalid resource directory.\r\n";
        return out.str();
    }
    const std::size_t resource_limit = (std::min<std::size_t>)(directory->second, image.bytes.size() - *root);
    const auto valid = [&](std::size_t relative, std::size_t length) {
        return relative <= resource_limit && length <= resource_limit - relative && *root + relative + length <= image.bytes.size();
    };
    const auto read16 = [&](std::size_t offset) -> std::uint16_t {
        return offset + 2 <= image.bytes.size() ? static_cast<std::uint16_t>(image.bytes[offset] | (image.bytes[offset + 1] << 8)) : 0;
    };
    const auto read32 = [&](std::size_t offset) -> std::uint32_t {
        return offset + 4 <= image.bytes.size() ? static_cast<std::uint32_t>(image.bytes[offset] | (image.bytes[offset + 1] << 8) | (image.bytes[offset + 2] << 16) | (image.bytes[offset + 3] << 24)) : 0;
    };
    const auto entry_name = [&](std::uint32_t raw) {
        if ((raw & 0x80000000u) == 0) return std::wstring(L"#") + std::to_wstring(raw);
        const auto relative = static_cast<std::size_t>(raw & 0x7fffffffu);
        if (!valid(relative, 2)) return std::wstring(L"<invalid name>");
        const auto length = read16(*root + relative);
        if (!valid(relative + 2, static_cast<std::size_t>(length) * 2)) return std::wstring(L"<invalid name>");
        std::wstring value;
        for (std::size_t index = 0; index < length; ++index) value.push_back(static_cast<wchar_t>(read16(*root + relative + 2 + index * 2)));
        return value.empty() ? std::wstring(L"<unnamed>") : value;
    };
    std::set<std::size_t> visited;
    std::size_t records = 0;
    const auto walk = [&](auto&& self, std::size_t directory_relative, const std::wstring& path, int depth) -> void {
        if (depth > 8 || records >= 10000 || !valid(directory_relative, 16) || !visited.insert(directory_relative).second) return;
        const auto directory_offset = *root + directory_relative;
        const auto named = read16(directory_offset + 12);
        const auto ids = read16(directory_offset + 14);
        const auto count = (std::min<std::size_t>(static_cast<std::size_t>(named) + ids, 4096));
        if (!valid(directory_relative + 16, count * 8)) return;
        for (std::size_t index = 0; index < count; ++index) {
            const auto entry = directory_offset + 16 + index * 8;
            const auto label = entry_name(read32(entry));
            const auto child = read32(entry + 4);
            const auto next_path = path.empty() ? label : path + L" / " + label;
            if (child & 0x80000000u) {
                self(self, static_cast<std::size_t>(child & 0x7fffffffu), next_path, depth + 1);
                continue;
            }
            const auto data_relative = static_cast<std::size_t>(child & 0x7fffffffu);
            if (!valid(data_relative, 16)) continue;
            const auto data_offset = *root + data_relative;
            const auto data_rva = read32(data_offset);
            const auto data_size = read32(data_offset + 4);
            const auto file_offset = image.rva_to_file_offset(data_rva);
            out << next_path << L"  0x" << std::hex << std::uppercase << data_rva << L"  " << std::dec << data_size << L"  ";
            if (file_offset) out << L"0x" << std::hex << std::uppercase << *file_offset;
            else out << L"<not in file>";
            out << L"\r\n";
            ++records;
        }
    };
    walk(walk, 0, L"", 0);
    if (records == 0) out << L"No resource entries found.\r\n";
    return out.str();
}

std::wstring imports_text(const gandon::BinaryImage& image) {
    std::wostringstream out; out << L"Imports\r\n========\r\nDLL / Function / IAT\r\n";
    const auto records = enumerate_imports(image);
    if (records.empty()) { out << L"No import directory or no valid imports.\r\n"; return out.str(); }
    std::wstring current_dll;
    for (const auto& record : records) {
        const auto hidden = std::any_of(g_hidden_imports.begin(), g_hidden_imports.end(), [&](const auto& hidden_record) {
            return import_key(hidden_record.first, hidden_record.second) == import_key(record.dll, record.name);
        });
        if (hidden) continue;
        if (record.dll != current_dll) {
            current_dll = record.dll;
            out << L"\r\n" << current_dll << L":\r\n";
        }
        out << L"  0x" << std::hex << std::uppercase << record.iat_va << L"  " << record.name;
        if (g_requested_disabled_imports.contains(import_key(record.dll, record.name))) out << L"  [DISABLED]";
        out << L"\r\n";
    }
    return out.str();
}

std::wstring exports_text(const gandon::BinaryImage& image) {
    std::wostringstream out; out << L"Exports\r\n========\r\n";
    const auto directory = pe_directory(image, 0); if (!directory || directory->first == 0) { out << L"No export directory.\r\n"; return out.str(); }
    const auto export_offset = image.rva_to_file_offset(directory->first); if (!export_offset || *export_offset + 40 > image.bytes.size()) { out << L"Invalid export directory.\r\n"; return out.str(); }
    auto read32 = [&](std::size_t offset) -> std::uint32_t { return offset + 4 <= image.bytes.size() ? static_cast<std::uint32_t>(image.bytes[offset] | (image.bytes[offset + 1] << 8) | (image.bytes[offset + 2] << 16) | (image.bytes[offset + 3] << 24)) : 0; };
    const auto base = read32(*export_offset + 16), function_count = read32(*export_offset + 20), name_count = read32(*export_offset + 24), functions_rva = read32(*export_offset + 28), names_rva = read32(*export_offset + 32), ordinals_rva = read32(*export_offset + 36);
    const auto functions = image.rva_to_file_offset(functions_rva), names = image.rva_to_file_offset(names_rva), ordinals = image.rva_to_file_offset(ordinals_rva); if (!functions || !names || !ordinals) { out << L"Invalid export arrays.\r\n"; return out.str(); }
    for (std::uint32_t index = 0; index < name_count && index < 1024; ++index) {
        const auto name_rva = index * 4 + *names; if (name_rva + 4 > image.bytes.size()) break; const auto name_offset = image.rva_to_file_offset(read32(name_rva));
        const auto ordinal_offset = *ordinals + index * 2; if (ordinal_offset + 2 > image.bytes.size()) break; const auto ordinal = static_cast<std::uint16_t>(image.bytes[ordinal_offset] | (image.bytes[ordinal_offset + 1] << 8));
        const auto function_offset = *functions + static_cast<std::size_t>(ordinal) * 4; if (function_offset + 4 > image.bytes.size()) break; const auto rva = read32(function_offset);
        out << L"0x" << std::hex << std::uppercase << image.image_base + rva << L"  " << (name_offset ? wide(reinterpret_cast<const char*>(image.bytes.data() + *name_offset)) : L"<unnamed>") << L"  ordinal " << std::dec << (base + ordinal) << L"\r\n";
    }
    if (function_count == 0) out << L"No named exports.\r\n";
    return out.str();
}

std::wstring strings_text(const gandon::BinaryImage& image) {
    std::wostringstream out; out << L"Strings (ASCII, 4+ characters)\r\n==============================\r\n"; std::size_t count = 0;
    for (std::size_t index = 0; index < image.bytes.size() && count < 200; ) {
        const auto start = index; while (index < image.bytes.size() && image.bytes[index] >= 0x20 && image.bytes[index] <= 0x7e) ++index;
        if (index - start >= 4) { std::string value(reinterpret_cast<const char*>(image.bytes.data() + start), index - start); out << L"0x" << std::hex << std::uppercase << file_offset_to_va(image, start) << L"  " << wide(value) << L"\r\n"; ++count; }
        if (index == start) ++index;
    }
    return out.str();
}

std::wstring hex_text(const gandon::BinaryImage& image, std::uint64_t address) {
    const auto offset = image.va_to_file_offset(address).value_or(0); std::wostringstream out; out << L"Address              Bytes                                             ASCII\r\n";
    for (std::size_t row = 0; row < 256 && offset + row * 16 < image.bytes.size(); ++row) {
        const auto current = offset + row * 16; out << L"0x" << std::hex << std::uppercase << file_offset_to_va(image, current) << L"  ";
        for (std::size_t col = 0; col < 16; ++col) { if (current + col < image.bytes.size()) out << std::setfill(L'0') << std::setw(2) << static_cast<unsigned>(image.bytes[current + col]) << L" "; else out << L"   "; }
        out << L" "; for (std::size_t col = 0; col < 16 && current + col < image.bytes.size(); ++col) { const auto byte = image.bytes[current + col]; out << static_cast<wchar_t>(byte >= 0x20 && byte <= 0x7e ? byte : L'.'); } out << L"\r\n";
    }
    return out.str();
}

std::wstring symbols_text(const gandon::AnalysisDatabase& db) {
    std::wostringstream out; out << L"Functions / Symbols\r\n===================\r\n";
    for (const auto& function : db.functions()) out << L"0x" << std::hex << std::uppercase << function.start << L"  " << wide(function.name) << L"\r\n";
    return out.str();
}

std::wstring debugger_text() {
    std::wostringstream out;
    const auto process = g_debug_process.load();
    const auto paused = g_debug_paused.load();
    out << L"Win32 Debugger\r\n==============\r\n"
        << (process ? (paused ? L"State: PAUSED\r\n" : L"State: RUNNING\r\n")
                    : (g_debug_starting.load() ? L"State: STARTING\r\n" : L"State: STOPPED\r\n"))
        << L"PID: " << std::dec << g_debug_pid.load() << L"\r\n"
        << L"Thread: " << g_debug_thread.load() << L"\r\n";
    if (paused) {
        out << L"Break address: 0x" << std::hex << std::uppercase << g_debug_pause_address.load() << L"\r\n";
        const auto thread_id = g_debug_thread.load();
        HANDLE thread = thread_id ? OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, thread_id) : nullptr;
        if (thread) {
            CONTEXT context{}; context.ContextFlags = CONTEXT_FULL;
            if (GetThreadContext(thread, &context)) {
                out << L"\r\nRegisters\r\n---------\r\n"
                    << L"RIP  0x" << context.Rip << L"    RSP  0x" << context.Rsp << L"\r\n"
                    << L"RAX  0x" << context.Rax << L"    RBX  0x" << context.Rbx << L"\r\n"
                    << L"RCX  0x" << context.Rcx << L"    RDX  0x" << context.Rdx << L"\r\n"
                    << L"RSI  0x" << context.Rsi << L"    RDI  0x" << context.Rdi << L"\r\n"
                    << L"RBP  0x" << context.Rbp << L"    FLAGS 0x" << context.EFlags << L"\r\n"
                    << L"R8   0x" << context.R8  << L"    R9   0x" << context.R9 << L"\r\n"
                    << L"R10  0x" << context.R10 << L"    R11  0x" << context.R11 << L"\r\n"
                    << L"R12  0x" << context.R12 << L"    R13  0x" << context.R13 << L"\r\n"
                    << L"R14  0x" << context.R14 << L"    R15  0x" << context.R15 << L"\r\n";
            }
            CloseHandle(thread);
        }
    }
    {
        std::lock_guard lock(g_breakpoint_mutex);
        out << L"\r\nSoftware breakpoints: " << std::dec << g_requested_breakpoints.size() << L"\r\n";
        for (const auto address : g_requested_breakpoints)
            out << L"  0x" << std::hex << std::uppercase << address << L"\r\n";
    }
    {
        std::lock_guard lock(g_debug_log_mutex);
        out << L"\r\nRecent events\r\n-------------\r\n";
        const auto first = g_debug_event_log.size() > 12 ? g_debug_event_log.size() - 12 : 0;
        for (std::size_t index = first; index < g_debug_event_log.size(); ++index)
            out << g_debug_event_log[index] << L"\r\n";
    }
    return out.str();
}

std::wstring call_graph_text(const gandon::AnalysisDatabase& db, std::uint64_t address) {
    std::uint64_t root = address;
    if (const auto function = db.function_at(address)) root = function->get().start;
    if (!root && !db.functions().empty()) root = db.functions().front().start;
    std::map<std::uint64_t, const gandon::Function*> by_address;
    for (const auto& function : db.functions()) by_address[function.start] = &function;
    const auto name_for = [&](std::uint64_t target) {
        if (const auto found = by_address.find(target); found != by_address.end()) return wide(found->second->name);
        return pseudocode_label(target);
    };
    std::wostringstream out;
    out << L"Call Graph\r\n==========\r\n";
    if (!root || !by_address.contains(root)) {
        out << L"No function is selected.\r\n";
        return out.str();
    }
    out << L"Root: 0x" << std::hex << std::uppercase << root << L"  " << name_for(root) << L"\r\n\r\n";
    std::vector<std::pair<std::uint64_t, int>> queue{{root, 0}};
    std::set<std::uint64_t> expanded;
    while (!queue.empty()) {
        const auto [current, depth] = queue.front();
        queue.erase(queue.begin());
        const auto found = by_address.find(current);
        if (found == by_address.end() || !expanded.insert(current).second) continue;
        const auto& function = *found->second;
        const std::wstring indent(static_cast<std::size_t>(depth) * 2, L' ');
        out << indent << L"0x" << std::hex << std::uppercase << current << L"  " << name_for(current)
            << L"  [" << std::dec << function.callees.size() << L" callees]\r\n";
        for (const auto callee : function.callees) {
            out << indent << L"  -> 0x" << std::hex << std::uppercase << callee << L"  " << name_for(callee) << L"\r\n";
            if (depth < 4 && by_address.contains(callee)) queue.push_back({callee, depth + 1});
        }
    }
    return out.str();
}

std::wstring problems_text(const gandon::AnalysisDatabase& db) {
    std::wostringstream out; out << L"Problems / Events\r\n=================\r\nAnalysis completed without fatal errors.\r\nFunctions: " << std::dec << db.functions().size() << L"\r\nXREFs: " << db.xrefs().size() << L"\r\n";
    std::lock_guard lock(g_debug_log_mutex);
    if (!g_debug_event_log.empty()) {
        out << L"\r\nDebug events\r\n============\r\n";
        for (const auto& event : g_debug_event_log) out << event << L"\r\n";
    }
    return out.str();
}

void log_debug_event(const std::wstring& event) {
    std::lock_guard lock(g_debug_log_mutex);
    g_debug_event_log.push_back(event);
    if (g_debug_event_log.size() > 2000) g_debug_event_log.erase(g_debug_event_log.begin(), g_debug_event_log.begin() + 500);
}

void trace_debug_event(const wchar_t* name, const DEBUG_EVENT& event, std::uint64_t address = 0) {
    if (!g_trace_enabled.load()) return;
    std::lock_guard lock(g_trace_mutex);
    g_debug_trace.push_back({name, event.dwProcessId, event.dwThreadId, address});
    if (g_debug_trace.size() > 10000) g_debug_trace.erase(g_debug_trace.begin(), g_debug_trace.begin() + 1000);
}

void navigate_to_address(HWND window, std::uint64_t address, int tab) {
    if (!g_database || !address) return;
    if (g_current_address && g_current_address != address) {
        g_navigation_history.push_back({g_current_address, g_tabs ? TabCtrl_GetCurSel(g_tabs) : 1});
        if (g_navigation_history.size() > 256) g_navigation_history.erase(g_navigation_history.begin());
    }
    g_current_address = address;
    g_session_dirty = true;
    if (tab == 2) g_pseudocode = pseudocode_text_at(*g_database, address);
    else if (tab == 1) g_listing = listing_text_at(*g_database, address);
    select_view(window, tab);
}

void toggle_graph_listing(HWND window) {
    const auto tab = TabCtrl_GetCurSel(g_tabs);
    select_view(window, tab == 0 ? 1 : 0);
}

void fit_graph(HWND window) {
    if (!g_database || g_graph_blocks.empty() || !g_view) return;
    RECT client{}; GetClientRect(g_view, &client);
    int right = 1, bottom = 1;
    for (const auto& block : g_graph_blocks) {
        right = (std::max)(right, block.x + block.width + 50);
        bottom = (std::max)(bottom, block.y + block.height + 50);
    }
    const auto horizontal = static_cast<double>((std::max)(1L, client.right - 30)) / right;
    const auto vertical = static_cast<double>((std::max)(1L, client.bottom - 30)) / bottom;
    g_graph_zoom = static_cast<int>((std::min)(horizontal, vertical) * 100.0);
    g_graph_zoom = (std::max)(25, (std::min)(180, g_graph_zoom));
    const auto [world_width, world_height] = graph_content_size();
    g_graph_scroll_x = (std::max)(0, static_cast<int>(world_width * (static_cast<double>(g_graph_zoom) / 100.0) - client.right) / 2);
    g_graph_scroll_y = (std::max)(0, static_cast<int>(world_height * (static_cast<double>(g_graph_zoom) / 100.0) - client.bottom) / 2);
    clamp_graph_scroll(g_view);
    update_graph_scrollbars(g_view);
    InvalidateRect(g_view, nullptr, FALSE);
    invalidate_minimap();
    g_session_dirty = true;
    SetWindowTextW(g_status, L"Graph fitted to the current window.");
}

void toggle_minimap(HWND window) {
    g_minimap_visible = !g_minimap_visible;
    if (g_minimap) ShowWindow(g_minimap, g_minimap_visible && TabCtrl_GetCurSel(g_tabs) == 0 ? SW_SHOW : SW_HIDE);
    CheckMenuItem(GetMenu(window), ID_TOGGLE_MINIMAP, MF_BYCOMMAND | (g_minimap_visible ? MF_CHECKED : MF_UNCHECKED));
    SendMessageW(window, WM_SIZE, 0, 0);
    InvalidateRect(g_view, nullptr, FALSE);
}

void find_function(HWND window) {
    if (!g_database) return;
    const auto query = prompt_text(window, L"Find Function", L"Function name or address:");
    if (!query || query->empty()) return;
    try {
        if (query->rfind(L"0x", 0) == 0 || query->find_first_not_of(L"0123456789") == std::wstring::npos) {
            navigate_to_address(window, std::stoull(*query, nullptr, 0), 0);
            return;
        }
    } catch (...) {}
    std::wstring lowered = *query;
    for (auto& character : lowered) character = static_cast<wchar_t>(towlower(character));
    for (const auto& function : g_database->functions()) {
        if (g_hidden_functions.contains(function.start)) continue;
        auto name = g_custom_labels.contains(function.start) ? g_custom_labels[function.start] : wide(function.name);
        auto candidate = name;
        for (auto& character : candidate) character = static_cast<wchar_t>(towlower(character));
        if (candidate.find(lowered) != std::wstring::npos) {
            navigate_to_address(window, function.start, 0);
            return;
        }
    }
    MessageBoxW(window, L"Функция не найдена.", L"Find Function", MB_ICONINFORMATION);
}

void hide_current_function(HWND window) {
    if (!g_database || !g_current_address) return;
    const auto function = g_database->function_at(g_current_address);
    if (!function) return;
    g_hidden_functions.insert(function->get().start);
    g_session_dirty = true;
    fill_tree();
    SetWindowTextW(g_status, L"Function hidden from navigation.");
}

void hide_selected_import(HWND window, std::uint64_t iat_va) {
    const auto record = import_for_iat(iat_va);
    if (!record) return;
    g_hidden_imports.insert({record->dll, record->name});
    fill_tree();
    g_session_dirty = true;
    SetWindowTextW(g_status, (L"Import hidden from navigation: " + record->dll + L"!" + record->name).c_str());
    (void)window;
}

void show_hidden_symbols(HWND window) {
    if (g_hidden_functions.empty() && g_hidden_imports.empty()) {
        MessageBoxW(window, L"Нет скрытых функций или импортов.", L"Hidden Symbols", MB_ICONINFORMATION);
        return;
    }
    std::wostringstream listing;
    listing << L"Hidden functions:\r\n";
    for (const auto address : g_hidden_functions) listing << L"  0x" << std::hex << std::uppercase << address << L"\r\n";
    listing << L"\r\nHidden imports:\r\n";
    for (const auto& [dll, name] : g_hidden_imports) listing << L"  " << dll << L"!" << name << L"\r\n";
    const auto value = prompt_text(window, L"Hidden Symbols", (listing.str() + L"\r\nAddress or dll!name to restore (empty = close):").c_str());
    if (!value || value->empty()) return;
    try {
        const auto address = std::stoull(*value, nullptr, 0);
        if (g_hidden_functions.erase(address)) {
            fill_tree(); g_session_dirty = true; SetWindowTextW(g_status, L"Hidden function restored.");
        }
    } catch (...) {
        const auto separator = value->find(L'!');
        if (separator == std::wstring::npos) {
            MessageBoxW(window, L"Неверный адрес или импорт.", L"Hidden Symbols", MB_ICONWARNING);
            return;
        }
        const auto dll = value->substr(0, separator);
        const auto name = value->substr(separator + 1);
        for (auto it = g_hidden_imports.begin(); it != g_hidden_imports.end(); ++it) {
            if (import_key(it->first, it->second) == import_key(dll, name)) {
                g_hidden_imports.erase(it);
                fill_tree(); g_session_dirty = true; SetWindowTextW(g_status, L"Hidden import restored.");
                return;
            }
        }
        MessageBoxW(window, L"Скрытый импорт не найден.", L"Hidden Symbols", MB_ICONINFORMATION);
    }
}

void restore_all_hidden_symbols(HWND) {
    g_hidden_functions.clear();
    g_hidden_imports.clear();
    fill_tree();
    g_session_dirty = true;
    SetWindowTextW(g_status, L"All hidden functions restored.");
}

void jump_back(HWND window) {
    if (!g_database || g_navigation_history.empty()) {
        SetWindowTextW(g_status, L"Navigation history is empty.");
        return;
    }
    const auto point = g_navigation_history.back();
    g_navigation_history.pop_back();
    g_current_address = point.address;
    g_session_dirty = true;
    if (point.tab == 2) g_pseudocode = pseudocode_text_at(*g_database, point.address);
    else if (point.tab == 1) g_listing = listing_text_at(*g_database, point.address);
    select_view(window, point.tab);
}

void toggle_bookmark(HWND window) {
    if (!g_database || !g_current_address) return;
    const auto inserted = g_bookmarks.insert(g_current_address).second;
    if (!inserted) g_bookmarks.erase(g_current_address);
    g_session_dirty = true;
    SetWindowTextW(g_status, inserted ? L"Bookmark added." : L"Bookmark removed.");
}

void next_bookmark(HWND window) {
    if (!g_database || g_bookmarks.empty()) {
        SetWindowTextW(g_status, L"No bookmarks.");
        return;
    }
    auto it = g_bookmarks.upper_bound(g_current_address);
    if (it == g_bookmarks.end()) it = g_bookmarks.begin();
    navigate_to_address(window, *it, 1);
}

std::string json_escape(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size() + 16);
    for (const unsigned char ch : value) {
        switch (ch) {
        case '\\': escaped += "\\\\"; break;
        case '"': escaped += "\\\""; break;
        case '\r': escaped += "\\r"; break;
        case '\n': escaped += "\\n"; break;
        case '\t': escaped += "\\t"; break;
        default:
            if (ch < 0x20) { char buffer[7]{}; std::snprintf(buffer, sizeof(buffer), "\\u%04x", ch); escaped += buffer; }
            else escaped.push_back(static_cast<char>(ch));
        }
    }
    return escaped;
}

void export_analysis_json(HWND window) {
    if (!g_database) { MessageBoxW(window, L"Сначала открой бинарный файл.", L"Export Analysis JSON", MB_ICONINFORMATION); return; }
    wchar_t file_name[MAX_PATH] = L"analysis.json";
    OPENFILENAMEW dialog{sizeof(dialog)}; dialog.hwndOwner = window; dialog.lpstrFilter = L"JSON (*.json)\0*.json\0All files (*.*)\0*.*\0"; dialog.lpstrFile = file_name; dialog.nMaxFile = MAX_PATH; dialog.Flags = OFN_OVERWRITEPROMPT;
    if (!GetSaveFileNameW(&dialog)) return;
    std::ofstream output(file_name, std::ios::binary | std::ios::trunc);
    if (!output) { MessageBoxW(window, L"Не удалось создать JSON-файл.", L"Export Analysis JSON", MB_ICONERROR); return; }
    const auto& image = g_database->image();
    output << "{\n  \"path\": \"" << json_escape(utf8(image.path.wstring())) << "\",\n"
           << "  \"format\": \"" << (image.format == gandon::BinaryFormat::PE ? "PE" : image.format == gandon::BinaryFormat::ELF ? "ELF" : "Unknown") << "\",\n"
           << "  \"image_base\": \"0x" << std::hex << std::uppercase << image.image_base << "\",\n"
           << "  \"entry_point\": \"0x" << image.entry_point << "\",\n  \"sections\": [\n";
    for (std::size_t index = 0; index < image.sections.size(); ++index) {
        const auto& section = image.sections[index];
        output << "    {\"name\": \"" << json_escape(section.name) << "\", \"rva\": \"0x" << section.rva
               << "\", \"virtual_size\": " << std::dec << section.virtual_size << ", \"raw_offset\": " << section.raw_offset
               << ", \"raw_size\": " << section.raw_size << ", \"characteristics\": \"0x" << std::hex << section.characteristics << "\"}"
               << (index + 1 == image.sections.size() ? "\n" : ",\n");
    }
    output << "  ],\n  \"functions\": [\n";
    for (std::size_t index = 0; index < g_database->functions().size(); ++index) {
        const auto& function = g_database->functions()[index];
        output << "    {\"address\": \"0x" << std::hex << std::uppercase << function.start << "\", \"name\": \"" << json_escape(function.name) << "\", \"instruction_count\": " << std::dec << function.instructions.size() << "}" << (index + 1 == g_database->functions().size() ? "\n" : ",\n");
    }
    output << "  ],\n  \"xrefs\": [\n";
    for (std::size_t index = 0; index < g_database->xrefs().size(); ++index) {
        const auto& xref = g_database->xrefs()[index];
        output << "    {\"from\": \"0x" << std::hex << std::uppercase << xref.from << "\", \"to\": \"0x" << xref.to << "\", \"kind\": \"" << json_escape(xref.kind) << "\"}" << (index + 1 == g_database->xrefs().size() ? "\n" : ",\n");
    }
    output << "  ],\n  \"hidden_imports\": [";
    std::size_t hidden_import_index = 0;
    for (const auto& [dll, name] : g_hidden_imports) {
        output << (hidden_import_index++ ? ", " : "") << "[\"" << json_escape(utf8(dll)) << "\", \"" << json_escape(utf8(name)) << "\"]";
    }
    output << "],\n  \"disabled_imports\": [";
    std::size_t disabled_import_index = 0;
    for (const auto& [key, record] : g_requested_disabled_imports) {
        output << (disabled_import_index++ ? ", " : "") << "[\"" << json_escape(utf8(record.dll)) << "\", \"" << json_escape(utf8(record.name))
               << "\", \"0x" << std::hex << std::uppercase << record.iat_va << "\", \"0x" << image.image_base << "\"]";
    }
    output << "],\n  \"bookmarks\": [";
    std::size_t bookmark_index = 0; for (const auto address : g_bookmarks) output << (bookmark_index++ ? ", " : "") << "\"0x" << std::hex << std::uppercase << address << "\"";
    output << "],\n  \"patches\": " << std::dec << g_patch_undo.size() << "\n}\n";
    if (!output) { MessageBoxW(window, L"Ошибка записи JSON-файла.", L"Export Analysis JSON", MB_ICONERROR); return; }
    MessageBoxW(window, L"Анализ экспортирован в JSON.", L"Export Analysis JSON", MB_ICONINFORMATION);
}

void export_breakpoints_csv(HWND window) {
    wchar_t file_name[MAX_PATH] = L"breakpoints.csv";
    OPENFILENAMEW dialog{sizeof(dialog)}; dialog.hwndOwner = window; dialog.lpstrFilter = L"CSV (*.csv)\0*.csv\0All files (*.*)\0*.*\0"; dialog.lpstrFile = file_name; dialog.nMaxFile = MAX_PATH; dialog.Flags = OFN_OVERWRITEPROMPT;
    if (!GetSaveFileNameW(&dialog)) return;
    std::ofstream output(file_name, std::ios::binary | std::ios::trunc);
    if (!output) { MessageBoxW(window, L"Не удалось создать CSV-файл.", L"Export Breakpoints", MB_ICONERROR); return; }
    output << "address,condition,hit_limit,hit_count,mode,hardware\n";
    {
        std::lock_guard lock(g_breakpoint_mutex);
        for (const auto address : g_requested_breakpoints) {
            output << "0x" << std::hex << std::uppercase << address << ",\""
                   << json_escape(utf8(g_breakpoint_conditions.contains(address) ? g_breakpoint_conditions[address] : L"")) << "\"," << std::dec
                   << (g_breakpoint_hit_limits.contains(address) ? g_breakpoint_hit_limits[address] : 0) << ","
                   << (g_breakpoint_hit_counts.contains(address) ? g_breakpoint_hit_counts[address] : 0) << ","
                   << (g_breakpoint_log_only.contains(address) ? "log" : "stop") << ",no\n";
        }
    }
    if (g_hardware_breakpoint) output << "0x" << std::hex << std::uppercase << g_hardware_breakpoint_address << ",,0,0,stop,yes\n";
    MessageBoxW(window, L"Точки останова экспортированы в CSV.", L"Export Breakpoints", MB_ICONINFORMATION);
}

void export_debug_log(HWND window) {
    wchar_t file_name[MAX_PATH] = L"debug_events.log";
    OPENFILENAMEW dialog{sizeof(dialog)}; dialog.hwndOwner = window; dialog.lpstrFilter = L"Log (*.log;*.txt)\0*.log;*.txt\0All files (*.*)\0*.*\0"; dialog.lpstrFile = file_name; dialog.nMaxFile = MAX_PATH; dialog.Flags = OFN_OVERWRITEPROMPT;
    if (!GetSaveFileNameW(&dialog)) return;
    std::wofstream output(file_name, std::ios::trunc);
    if (!output) { MessageBoxW(window, L"Не удалось создать файл журнала.", L"Export Debug Event Log", MB_ICONERROR); return; }
    std::lock_guard lock(g_debug_log_mutex); for (const auto& event : g_debug_event_log) output << event << L"\n";
    MessageBoxW(window, L"Журнал отладки экспортирован.", L"Export Debug Event Log", MB_ICONINFORMATION);
}

void toggle_debug_trace(HWND window) {
    const bool enabled = !g_trace_enabled.load();
    g_trace_enabled.store(enabled);
    if (enabled) { std::lock_guard lock(g_trace_mutex); g_debug_trace.clear(); }
    CheckMenuItem(GetMenu(window), ID_TRACE_TOGGLE, MF_BYCOMMAND | (enabled ? MF_CHECKED : MF_UNCHECKED));
    SetWindowTextW(g_status, enabled ? L"Debug event trace enabled." : L"Debug event trace disabled.");
}

void export_debug_trace(HWND window) {
    std::vector<DebugTraceRecord> trace;
    { std::lock_guard lock(g_trace_mutex); trace = g_debug_trace; }
    if (trace.empty()) { MessageBoxW(window, L"Trace пуст. Включи Trace Debug Events и запусти отладчик.", L"Trace", MB_ICONINFORMATION); return; }
    wchar_t file_name[MAX_PATH] = L"debug-trace.json";
    OPENFILENAMEW dialog{sizeof(dialog)}; dialog.hwndOwner = window; dialog.lpstrFilter = L"JSON (*.json)\0*.json\0All files (*.*)\0*.*\0"; dialog.lpstrFile = file_name; dialog.nMaxFile = MAX_PATH; dialog.Flags = OFN_OVERWRITEPROMPT;
    if (!GetSaveFileNameW(&dialog)) return;
    std::ofstream output(file_name, std::ios::binary | std::ios::trunc);
    if (!output) { MessageBoxW(window, L"Не удалось создать trace-файл.", L"Trace", MB_ICONERROR); return; }
    output << "[\n";
    for (std::size_t index = 0; index < trace.size(); ++index) {
        const auto& record = trace[index];
        output << "  {\"event\":\"" << json_escape(utf8(record.event)) << "\",\"process\":" << record.process
               << ",\"thread\":" << record.thread << ",\"address\":\"0x" << std::hex << std::uppercase << record.address << "\"}"
               << (index + 1 == trace.size() ? "\n" : ",\n");
    }
    output << "]\n";
    MessageBoxW(window, L"Trace экспортирован.", L"Trace", MB_ICONINFORMATION);
}

void set_color_tag(HWND window, COLORREF color, bool clear) {
    if (!g_database || !g_current_address) return;
    const auto function = g_database->function_at(g_current_address);
    const auto address = function ? function->get().start : g_current_address;
    if (clear) g_graph_colors.erase(address);
    else g_graph_colors[address] = color;
    g_session_dirty = true;
    rebuild_graph_model();
    InvalidateRect(g_view, nullptr, TRUE);
    SetWindowTextW(g_status, clear ? L"View-A color tag cleared." : L"View-A color tag updated.");
}

std::optional<std::uint64_t> editor_line_address(HWND editor) {
    if (!editor) return std::nullopt;
    DWORD selection_start = 0, selection_end = 0; SendMessageW(editor, EM_GETSEL, reinterpret_cast<WPARAM>(&selection_start), reinterpret_cast<LPARAM>(&selection_end));
    const auto line = static_cast<int>(SendMessageW(editor, EM_LINEFROMCHAR, selection_start, 0));
    const auto line_start = static_cast<int>(SendMessageW(editor, EM_LINEINDEX, line, 0));
    const auto line_length = static_cast<int>(SendMessageW(editor, EM_LINELENGTH, line_start, 0));
    if (line_length <= 0) return std::nullopt;
    std::vector<wchar_t> buffer(static_cast<std::size_t>(line_length) + 1, L'\0'); *reinterpret_cast<WORD*>(buffer.data()) = static_cast<WORD>((std::min)(line_length, 0xffff));
    SendMessageW(editor, EM_GETLINE, line, reinterpret_cast<LPARAM>(buffer.data())); buffer[static_cast<std::size_t>(line_length)] = L'\0';
    const std::wstring text(buffer.data());
    for (std::size_t position = 0; position + 2 < text.size(); ++position) {
        if (text[position] != L'0' || (text[position + 1] != L'x' && text[position + 1] != L'X')) continue;
        const auto first = position + 2, last = text.find_first_not_of(L"0123456789abcdefABCDEF", first); if (last == first) continue;
        try { return std::stoull(text.substr(first, last == std::wstring::npos ? last : last - first), nullptr, 16); } catch (...) {}
    }
    // Pseudocode control-flow lines show a symbolic target (loc_...) while
    // the preceding generated comment carries the address of the branch
    // instruction. Patch the selected branch, not the destination block.
    if (line > 0 && (text.find(L"loc_") != std::wstring::npos || text.find(L"sub_") != std::wstring::npos)) {
        const auto previous_start = static_cast<int>(SendMessageW(editor, EM_LINEINDEX, line - 1, 0));
        const auto previous_length = static_cast<int>(SendMessageW(editor, EM_LINELENGTH, previous_start, 0));
        if (previous_length > 0) {
            std::vector<wchar_t> previous_buffer(static_cast<std::size_t>(previous_length) + 1, L'\0');
            *reinterpret_cast<WORD*>(previous_buffer.data()) = static_cast<WORD>((std::min)(previous_length, 0xffff));
            SendMessageW(editor, EM_GETLINE, line - 1, reinterpret_cast<LPARAM>(previous_buffer.data()));
            const std::wstring previous(previous_buffer.data());
            for (std::size_t position = 0; position + 2 < previous.size(); ++position) {
                if (previous[position] != L'0' || (previous[position + 1] != L'x' && previous[position + 1] != L'X')) continue;
                const auto first = position + 2, last = previous.find_first_not_of(L"0123456789abcdefABCDEF", first); if (last == first) continue;
                try { return std::stoull(previous.substr(first, last == std::wstring::npos ? last : last - first), nullptr, 16); } catch (...) {}
            }
        }
    }
    for (const auto prefix : {std::wstring(L"loc_"), std::wstring(L"sub_")}) {
        const auto position = text.find(prefix);
        if (position == std::wstring::npos) continue;
        const auto first = position + prefix.size(), last = text.find_first_not_of(L"0123456789abcdefABCDEF", first);
        if (last == first) continue;
        try { return std::stoull(text.substr(first, last == std::wstring::npos ? last : last - first), nullptr, 16); } catch (...) {}
    }
    return std::nullopt;
}

void sync_current_address_from_editor() {
    if (!g_database || !g_editor || !g_tabs || TabCtrl_GetCurSel(g_tabs) == 0) return;
    if (const auto address = editor_line_address(g_editor)) {
        g_current_address = *address;
        g_session_dirty = true;
    }
}

std::optional<std::uint64_t> editor_line_target_address(HWND editor) {
    if (!editor) return std::nullopt;
    DWORD selection_start = 0, selection_end = 0; SendMessageW(editor, EM_GETSEL, reinterpret_cast<WPARAM>(&selection_start), reinterpret_cast<LPARAM>(&selection_end));
    const auto line = static_cast<int>(SendMessageW(editor, EM_LINEFROMCHAR, selection_start, 0));
    const auto line_start = static_cast<int>(SendMessageW(editor, EM_LINEINDEX, line, 0));
    const auto line_length = static_cast<int>(SendMessageW(editor, EM_LINELENGTH, line_start, 0));
    if (line_length <= 0) return std::nullopt;
    std::vector<wchar_t> buffer(static_cast<std::size_t>(line_length) + 1, L'\0'); *reinterpret_cast<WORD*>(buffer.data()) = static_cast<WORD>((std::min)(line_length, 0xffff));
    SendMessageW(editor, EM_GETLINE, line, reinterpret_cast<LPARAM>(buffer.data())); buffer[static_cast<std::size_t>(line_length)] = L'\0';
    const std::wstring text(buffer.data()); std::size_t found = 0;
    for (std::size_t position = 0; position + 2 < text.size(); ++position) {
        if (text[position] != L'0' || (text[position + 1] != L'x' && text[position + 1] != L'X')) continue;
        const auto first = position + 2, last = text.find_first_not_of(L"0123456789abcdefABCDEF", first); if (last == first) continue;
        try {
            const auto address = std::stoull(text.substr(first, last == std::wstring::npos ? last : last - first), nullptr, 16);
            if (++found == 2) return address;
        } catch (...) {}
    }
    return std::nullopt;
}

void set_editor_text() {
    if (!g_editor) return;
    const int tab = TabCtrl_GetCurSel(g_tabs);
    const bool graph = tab == 0;
    if (graph) {
        ShowWindow(g_editor, SW_HIDE);
        ShowWindow(g_view, SW_SHOW);
        if (g_minimap) ShowWindow(g_minimap, g_minimap_visible ? SW_SHOW : SW_HIDE);
        InvalidateRect(g_view, nullptr, TRUE);
    } else {
        ShowWindow(g_view, SW_HIDE);
        if (g_minimap) ShowWindow(g_minimap, SW_HIDE);
        SetWindowPos(g_editor, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    }
    std::wstring text;
    if (!g_database) text = g_listing;
    else if (tab == 2) text = g_pseudocode;
    else if (tab == 3) text = g_xrefs;
    else if (tab == 4) text = debugger_text();
    else if (tab == 5) text = hex_text(g_database->image(), g_current_address ? g_current_address : g_database->image().entry_point);
    else if (tab == 6) {
        text = L"Local Types\r\n===========\r\nuint8_t   byte\r\nuint16_t  word\r\nuint32_t  dword\r\nuint64_t  qword\r\nvoid*     pointer\r\n\r\nUser assignments\r\n----------------\r\n";
        if (g_custom_types.empty()) text += L"(none)\r\n";
        else for (const auto& [address, type] : g_custom_types) {
            std::wostringstream row;
            row << L"0x" << std::hex << std::uppercase << address << L"  " << type << L"\r\n";
            text += row.str();
        }
        text += L"\r\nSelect an instruction or function and use Edit -> Assign Type... to change it.\r\n";
    }
    else if (tab == 7) text = imports_text(g_database->image());
    else if (tab == 8) text = exports_text(g_database->image());
    else if (tab == 9) text = strings_text(g_database->image());
    else if (tab == 10) text = resources_text(g_database->image());
    else if (tab == 11) text = symbols_text(*g_database);
    else if (tab == 12) text = g_memory_map;
    else if (tab == 13) text = problems_text(*g_database);
    else text = g_listing;
    SetWindowTextW(g_editor, text.c_str());
    if (graph) { InvalidateRect(g_view, nullptr, TRUE); UpdateWindow(g_view); }
}

void fill_tree() {
    TreeView_DeleteAllItems(g_tree);
    g_string_addresses.clear();
    TVINSERTSTRUCTW insert{};
    insert.item.mask = TVIF_TEXT | TVIF_PARAM;
    wchar_t root_name[] = L"Functions / Symbols";
    insert.item.pszText = root_name;
    const HTREEITEM root = TreeView_InsertItem(g_tree, &insert);
    if (!g_database) return;
    wchar_t sections_name[] = L"Sections";
    insert.hParent = root; insert.item.pszText = sections_name; insert.item.lParam = 0;
    const HTREEITEM sections = TreeView_InsertItem(g_tree, &insert);
    for (const auto& section : g_database->image().sections) {
        auto name = wide(section.name); insert.hParent = sections; insert.item.pszText = name.data(); insert.item.lParam = 0; TreeView_InsertItem(g_tree, &insert);
    }
    wchar_t functions_name[] = L"Functions";
    insert.hParent = root; insert.item.pszText = functions_name; insert.item.lParam = 0;
    const HTREEITEM functions = TreeView_InsertItem(g_tree, &insert);
    for (const auto& function : g_database->functions()) {
        if (g_hidden_functions.contains(function.start)) continue;
        auto name = g_custom_labels.contains(function.start) ? g_custom_labels[function.start] : wide(function.name); insert.hParent = functions; insert.item.pszText = name.data(); insert.item.lParam = static_cast<LPARAM>(function.start); TreeView_InsertItem(g_tree, &insert);
    }
    wchar_t imports_name[] = L"Imports";
    insert.hParent = root; insert.item.pszText = imports_name; insert.item.lParam = 0;
    const auto imports = TreeView_InsertItem(g_tree, &insert);
    std::map<std::wstring, HTREEITEM> import_dll_items;
    for (const auto& record : enumerate_imports(g_database->image())) {
        const auto record_key = import_key(record.dll, record.name);
        const auto hidden = std::any_of(g_hidden_imports.begin(), g_hidden_imports.end(), [&](const auto& hidden_record) {
            return import_key(hidden_record.first, hidden_record.second) == record_key;
        });
        if (hidden) continue;
        auto dll_item = import_dll_items.find(record.dll);
        HTREEITEM parent = nullptr;
        if (dll_item == import_dll_items.end()) {
            auto dll_name = record.dll;
            insert.hParent = imports; insert.item.pszText = dll_name.data(); insert.item.lParam = 0;
            parent = TreeView_InsertItem(g_tree, &insert);
            import_dll_items.emplace(record.dll, parent);
        } else parent = dll_item->second;
        std::wostringstream import_label;
        import_label << record.name << L"  [IAT 0x" << std::hex << std::uppercase << record.iat_va << L"]";
        auto label = import_label.str();
        insert.hParent = parent; insert.item.pszText = label.data(); insert.item.lParam = static_cast<LPARAM>(record.iat_va);
        TreeView_InsertItem(g_tree, &insert);
    }
    wchar_t strings_name[] = L"Strings";
    insert.hParent = root; insert.item.pszText = strings_name; insert.item.lParam = 0;
    const auto strings = TreeView_InsertItem(g_tree, &insert);
    std::size_t string_count = 0;
    for (std::size_t offset = 0; offset < g_database->image().bytes.size() && string_count < 200; ) {
        const auto start = offset;
        while (offset < g_database->image().bytes.size() && g_database->image().bytes[offset] >= 0x20 && g_database->image().bytes[offset] <= 0x7e) ++offset;
        if (offset - start >= 4) {
            const auto address = file_offset_to_va(g_database->image(), start);
            g_string_addresses.insert(address);
            std::string value(reinterpret_cast<const char*>(g_database->image().bytes.data() + start), offset - start);
            if (value.size() > 80) value.resize(80), value += "...";
            auto label = L"0x" + [&] { std::wostringstream text; text << std::hex << std::uppercase << address; return text.str(); }() + L"  " + wide(value);
            insert.hParent = strings; insert.item.pszText = label.data(); insert.item.lParam = static_cast<LPARAM>(address); TreeView_InsertItem(g_tree, &insert); ++string_count;
        }
        if (offset == start) ++offset;
    }
    TreeView_Expand(g_tree, root, TVE_EXPAND); TreeView_Expand(g_tree, sections, TVE_EXPAND); TreeView_Expand(g_tree, functions, TVE_EXPAND);
    TreeView_Expand(g_tree, imports, TVE_EXPAND); TreeView_Expand(g_tree, strings, TVE_EXPAND);
}

void refresh_views(HWND window) {
    if (!g_database) return;
    g_listing = listing_text(*g_database); g_pseudocode = pseudocode_text_at(*g_database, g_current_address ? g_current_address : g_database->image().entry_point); g_xrefs = xref_text(*g_database); g_memory_map = memory_map_text(*g_database);
    rebuild_graph_model(); fill_tree(); set_editor_text();
    std::wstring status = L"Loaded: " + g_database->image().path.wstring() + L" | Functions: " + std::to_wstring(g_database->functions().size()) + L" | XREFs: " + std::to_wstring(g_database->xrefs().size());
    SendMessageW(g_status, SB_SETTEXTW, 0, reinterpret_cast<LPARAM>(status.c_str()));
    SetWindowTextW(window, (L"Gandon-PRO - " + g_database->image().path.wstring()).c_str());
}

bool load_binary_path(HWND window, const std::filesystem::path& file_path) {
    gandon::BinaryImage image; std::string error;
    if (!image.load(file_path, error)) { MessageBoxW(window, wide(error).c_str(), L"Gandon-PRO", MB_ICONERROR); return false; }
    g_database = std::make_unique<gandon::AnalysisDatabase>(std::move(image)); g_database->discover_basic_xrefs(); g_current_address = g_database->image().entry_point; g_graph_zoom = 100; g_graph_scroll_x = 0; g_graph_scroll_y = 0; g_graph_positions.clear(); g_memory_snapshot.clear(); g_memory_snapshot_address = 0; g_patch_undo.clear(); g_patch_redo.clear(); g_custom_labels.clear(); g_custom_comments.clear(); g_custom_types.clear(); g_navigation_history.clear(); g_bookmarks.clear(); g_hidden_functions.clear(); g_hidden_imports.clear(); g_watch_expressions.clear(); g_requested_disabled_imports.clear(); g_installed_import_disables.clear(); { std::lock_guard lock(g_breakpoint_mutex); g_requested_breakpoints.clear(); g_breakpoint_conditions.clear(); g_breakpoint_hit_counts.clear(); g_breakpoint_hit_limits.clear(); g_breakpoint_log_only.clear(); } g_session_path = g_database->image().path.wstring() + L".gnd"; g_session_dirty = false; refresh_views(window);
    return true;
}

void open_binary(HWND window) {
    wchar_t file_name[MAX_PATH]{};
    OPENFILENAMEW dialog{sizeof(dialog)};
    dialog.hwndOwner = window; dialog.lpstrFilter = L"Supported binaries (*.exe;*.dll;*.sys;*.so;*.elf)\0*.exe;*.dll;*.sys;*.so;*.elf\0All files (*.*)\0*.*\0"; dialog.lpstrFile = file_name; dialog.nMaxFile = MAX_PATH; dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&dialog)) return;
    load_binary_path(window, file_name);
}

void refresh_after_patch(HWND window) {
    if (!g_database) return;
    g_session_dirty = true;
    g_database->discover_basic_xrefs();
    refresh_views(window);
}

void nop_current_function(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Выбери функцию или блок.", L"NOP Current Block", MB_ICONINFORMATION); return; }
    const auto function = g_database->function_at(g_current_address);
    if (!function) { MessageBoxW(window, L"Текущий адрес не соответствует функции.", L"NOP Current Block", MB_ICONINFORMATION); return; }
    std::uint64_t next_function = UINT64_MAX;
    for (const auto& candidate : g_database->functions()) {
        if (candidate.start > function->get().start) { next_function = candidate.start; break; }
    }
    std::vector<PatchChange> changes;
    for (const auto& instruction : function->get().instructions) {
        if (instruction.address >= next_function) break;
        if (instruction.size == 0) continue;
        std::vector<std::uint8_t> replacement(instruction.size, 0x90), original;
        std::string error;
        const auto offset = g_database->image().va_to_file_offset(instruction.address);
        if (!offset || !g_database->patch_bytes(instruction.address, replacement, original, error)) continue;
        for (std::size_t i = 0; i < replacement.size(); ++i)
            if (original[i] != replacement[i]) changes.push_back({*offset + i, original[i], replacement[i]});
        if (instruction.mnemonic == "ret" || instruction.mnemonic == "jmp" || instruction.mnemonic == "int3") break;
    }
    if (changes.empty()) { MessageBoxW(window, L"В функции нечего патчить.", L"NOP Current Block", MB_ICONINFORMATION); return; }
    g_patch_undo.push_back(std::move(changes)); g_patch_redo.clear(); refresh_after_patch(window);
}

void undo_patch(HWND window) {
    if (!g_database || g_patch_undo.empty()) return;
    auto changes = std::move(g_patch_undo.back()); g_patch_undo.pop_back();
    for (const auto& change : changes) { std::string error; g_database->replace_file_bytes(change.offset, {change.old_value}, error); }
    g_patch_redo.push_back(std::move(changes)); refresh_after_patch(window);
}

void redo_patch(HWND window) {
    if (!g_database || g_patch_redo.empty()) return;
    auto changes = std::move(g_patch_redo.back()); g_patch_redo.pop_back();
    for (const auto& change : changes) { std::string error; g_database->replace_file_bytes(change.offset, {change.new_value}, error); }
    g_patch_undo.push_back(std::move(changes)); refresh_after_patch(window);
}

void apply_patches_to_file(HWND window) {
    if (!g_database || g_patch_undo.empty()) { MessageBoxW(window, L"Нет применённых патчей.", L"Apply Patches", MB_ICONINFORMATION); return; }
    wchar_t file_name[MAX_PATH] = L"patched.exe";
    OPENFILENAMEW dialog{sizeof(dialog)}; dialog.hwndOwner = window; dialog.lpstrFilter = L"Executables (*.exe;*.dll)\0*.exe;*.dll\0All files (*.*)\0*.*\0"; dialog.lpstrFile = file_name; dialog.nMaxFile = MAX_PATH; dialog.Flags = OFN_OVERWRITEPROMPT;
    if (!GetSaveFileNameW(&dialog)) return;
    std::string error;
    if (!g_database->write_patched_file(file_name, error)) { MessageBoxW(window, wide(error).c_str(), L"Apply Patches", MB_ICONERROR); return; }
    MessageBoxW(window, L"Патченный файл сохранён.", L"Apply Patches", MB_ICONINFORMATION);
}

void rename_current_label(HWND window) {
    if (!g_current_address) return;
    const auto current = g_custom_labels.contains(g_current_address) ? g_custom_labels[g_current_address] : L"sub_" + std::to_wstring(g_current_address);
    const auto value = prompt_text(window, L"Rename Label", L"Label:", current);
    if (!value || value->empty()) return;
    g_custom_labels[g_current_address] = *value; g_session_dirty = true; refresh_views(window);
}

void add_current_comment(HWND window) {
    if (!g_current_address) return;
    const auto current = g_custom_comments.contains(g_current_address) ? g_custom_comments[g_current_address] : L"";
    const auto value = prompt_text(window, L"Add Comment", L"Comment:", current);
    if (!value) return;
    g_custom_comments[g_current_address] = *value; g_session_dirty = true; refresh_views(window);
}

void assign_current_type(HWND window) {
    if (!g_database || !g_current_address) {
        MessageBoxW(window, L"Сначала выбери адрес инструкции или функции.", L"Assign Type", MB_ICONINFORMATION);
        return;
    }
    const auto current = g_custom_types.contains(g_current_address) ? g_custom_types[g_current_address] : L"uint64_t";
    const auto value = prompt_text(window, L"Assign Type", L"C/C++ type (empty removes the type):", current);
    if (!value) return;
    if (value->empty()) g_custom_types.erase(g_current_address);
    else g_custom_types[g_current_address] = *value;
    g_session_dirty = true;
    refresh_views(window);
    SetWindowTextW(g_status, value->empty() ? L"User type removed." : L"User type assigned.");
}

bool write_database_file(const std::filesystem::path& file, std::string& error) {
    if (!g_database) { error = "No database is loaded."; return false; }
    std::wofstream output(file, std::ios::trunc);
    if (!output) { error = "Could not create database: " + file.string(); return false; }
    output << L"GANDON-GND-3\n" << g_database->image().path.wstring() << L"\n";
    const auto tab = g_tabs ? TabCtrl_GetCurSel(g_tabs) : g_session_tab;
    const auto address = g_current_address ? g_current_address : g_session_address;
    output << L"P|" << address << L"|" << tab << L"\n";
    for (const auto& [address, label] : g_custom_labels) output << L"L|" << address << L"|" << label << L"\n";
    for (const auto& [address, comment] : g_custom_comments) output << L"C|" << address << L"|" << comment << L"\n";
    for (const auto& [address, type] : g_custom_types) output << L"Y|" << address << L"|" << type << L"\n";
    for (const auto address : g_bookmarks) output << L"K|" << address << L"|bookmark\n";
    for (const auto address : g_hidden_functions) output << L"F|" << address << L"|hidden_function\n";
    for (const auto& [dll, name] : g_hidden_imports) output << L"N|0|" << dll << L"!" << name << L"\n";
    for (const auto& [key, record] : g_requested_disabled_imports) output << L"D|0|" << record.dll << L"!" << record.name << L"\n";
    for (const auto& expression : g_watch_expressions) output << L"W|0|" << expression << L"\n";
    for (const auto& [address, color] : g_graph_colors) output << L"T|" << address << L"|" << std::hex << color << L"\n";
    for (const auto& [address, position] : g_graph_positions) output << L"V|" << address << L"|" << position.first << L"," << position.second << L"\n";
    output << L"G|" << std::dec << g_graph_zoom << L"|graph_zoom\n";
    output << L"H|" << g_graph_scroll_x << L"," << g_graph_scroll_y << L"|graph_scroll\n";
    // Persist the effective byte values, not only the undo stack metadata.
    // A database is reopened from the original binary, so these records are
    // what makes patches survive a close/load cycle.
    std::map<std::size_t, std::uint8_t> effective_patches;
    for (const auto& batch : g_patch_undo)
        for (const auto& change : batch) effective_patches[change.offset] = change.new_value;
    for (const auto& [offset, value] : effective_patches)
        output << L"U|" << offset << L"|" << static_cast<unsigned>(value) << L"\n";
    RECT window_rect{}; if (g_main_window && GetWindowRect(g_main_window, &window_rect)) output << L"R|" << window_rect.left << L"," << window_rect.top << L"," << window_rect.right << L"," << window_rect.bottom << L"|window\n";
    { std::lock_guard lock(g_breakpoint_mutex); for (const auto address : g_requested_breakpoints) {
        output << L"B|" << address << L"|" << (g_breakpoint_conditions.contains(address) ? g_breakpoint_conditions[address] : L"") << L"\n";
        output << L"Q|" << address << L"|" << (g_breakpoint_hit_limits.contains(address) ? g_breakpoint_hit_limits[address] : 0)
               << L"," << (g_breakpoint_log_only.contains(address) ? 1 : 0) << L"\n";
    } }
    if (!output) { error = "Could not write database: " + file.string(); return false; }
    return true;
}

void save_session_backup() {
    if (!g_database || !g_session_dirty || g_session_path.empty()) return;
    std::string error; write_database_file(g_session_path.wstring() + L".bak", error);
}

void save_database(HWND window) {
    if (!g_database) { MessageBoxW(window, L"Сначала открой бинарный файл.", L"Save Database", MB_ICONINFORMATION); return; }
    wchar_t file_name[MAX_PATH] = L"analysis.gnd";
    if (!g_session_path.empty()) wcsncpy_s(file_name, g_session_path.wstring().c_str(), _TRUNCATE);
    OPENFILENAMEW dialog{sizeof(dialog)}; dialog.hwndOwner = window; dialog.lpstrFilter = L"Gandon database (*.gnd)\0*.gnd\0\0"; dialog.lpstrFile = file_name; dialog.nMaxFile = MAX_PATH; dialog.Flags = OFN_OVERWRITEPROMPT;
    if (!GetSaveFileNameW(&dialog)) return;
    std::string error; if (!write_database_file(file_name, error)) { MessageBoxW(window, wide(error).c_str(), L"Save Database", MB_ICONERROR); return; }
    g_session_path = file_name; g_session_dirty = false; std::error_code ignored; std::filesystem::remove(g_session_path.wstring() + L".bak", ignored);
    MessageBoxW(window, L"База данных сохранена.", L"Save Database", MB_ICONINFORMATION);
}

bool load_legacy_python_database(HWND window, const std::filesystem::path& file) {
    if (!g_database) {
        MessageBoxW(window, L"Сначала открой бинарник, поверх которого нужно загрузить Python-базу.", L"Load Database", MB_ICONINFORMATION);
        return true;
    }
    std::ifstream input(file, std::ios::binary);
    const std::string json((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    if (json.empty()) return false;
    const auto unescape = [](std::string value) {
        std::string result;
        result.reserve(value.size());
        for (std::size_t index = 0; index < value.size(); ++index) {
            if (value[index] != '\\' || index + 1 >= value.size()) { result.push_back(value[index]); continue; }
            const auto escaped = value[++index];
            if (escaped == 'n') result.push_back('\n');
            else if (escaped == 'r') result.push_back('\r');
            else if (escaped == 't') result.push_back('\t');
            else result.push_back(escaped);
        }
        return result;
    };
    const auto parse_map = [&](const char* key, const auto& visitor) {
        const auto key_position = json.find(std::string("\"") + key + "\"");
        if (key_position == std::string::npos) return;
        const auto object_start = json.find('{', key_position);
        const auto object_end = object_start == std::string::npos ? std::string::npos : json.find('}', object_start);
        if (object_start == std::string::npos || object_end == std::string::npos) return;
        const std::regex pair_pattern(R"(\"([0-9]+)\"\s*:\s*\"([^\"]*)\")");
        const auto begin = json.cbegin() + static_cast<std::ptrdiff_t>(object_start);
        const auto end = json.cbegin() + static_cast<std::ptrdiff_t>(object_end);
        for (std::sregex_iterator match(begin, end, pair_pattern), last; match != last; ++match) {
            try { visitor(std::stoull((*match)[1].str()), unescape((*match)[2].str())); } catch (...) {}
        }
    };
    parse_map("custom_names", [&](std::uint64_t address, const std::string& value) { g_custom_labels[address] = wide(value); });
    parse_map("custom_comments", [&](std::uint64_t address, const std::string& value) { g_custom_comments[address] = wide(value); });
    parse_map("custom_colors", [&](std::uint64_t address, const std::string& value) {
        try {
            const auto hex = value.rfind('#', 0) == 0 ? value.substr(1) : value;
            const auto rgb = static_cast<COLORREF>(std::stoul(hex, nullptr, 16));
            g_graph_colors[address] = RGB((rgb >> 16) & 0xffu, (rgb >> 8) & 0xffu, rgb & 0xffu);
        } catch (...) {}
    });
    const auto json_array = [&](const char* key) {
        const auto key_position = json.find(std::string("\"") + key + "\"");
        if (key_position == std::string::npos) return std::string{};
        const auto start = json.find('[', key_position);
        if (start == std::string::npos) return std::string{};
        const auto nested_end = json.find("]]", start);
        const auto end = nested_end == std::string::npos ? json.find(']', start) : nested_end + 1;
        if (end == std::string::npos || end <= start) return std::string{};
        return json.substr(start, end - start + 1);
    };
    const auto parse_number_array = [&](const char* key, const auto& visitor) {
        const auto section = json_array(key);
        const std::regex number_pattern(R"((0x[0-9A-Fa-f]+|[0-9]+))");
        for (std::sregex_iterator match(section.begin(), section.end(), number_pattern), last; match != last; ++match) {
            try { visitor(std::stoull((*match)[1].str(), nullptr, 0)); } catch (...) {}
        }
    };
    parse_number_array("hidden_functions", [&](std::uint64_t address) { g_hidden_functions.insert(address); });
    parse_number_array("breakpoints", [&](std::uint64_t address) { g_requested_breakpoints.insert(address); });
    parse_number_array("hardware_breakpoints", [&](std::uint64_t address) { g_hardware_breakpoint_address = address; });
    parse_number_array("breakpoint_log_only", [&](std::uint64_t address) { g_breakpoint_log_only.insert(address); });
    // Python Gandon databases store bookmarks as an object keyed by address,
    // while the native format stores one record per address.
    parse_map("bookmarks", [&](std::uint64_t address, const std::string&) { g_bookmarks.insert(address); });
    parse_map("breakpoint_conditions", [&](std::uint64_t address, const std::string& condition) {
        g_breakpoint_conditions[address] = wide(condition);
    });
    const auto parse_numeric_map = [&](const char* key, const auto& visitor) {
        const auto key_position = json.find(std::string("\"") + key + "\"");
        if (key_position == std::string::npos) return;
        const auto object_start = json.find('{', key_position);
        const auto object_end = object_start == std::string::npos ? std::string::npos : json.find('}', object_start);
        if (object_start == std::string::npos || object_end == std::string::npos) return;
        const std::regex pair_pattern(R"(\"([0-9]+)\"\s*:\s*(-?[0-9]+))");
        const auto begin = json.cbegin() + static_cast<std::ptrdiff_t>(object_start);
        const auto end = json.cbegin() + static_cast<std::ptrdiff_t>(object_end);
        for (std::sregex_iterator match(begin, end, pair_pattern), last; match != last; ++match) {
            try { visitor(std::stoull((*match)[1].str()), std::stoull((*match)[2].str())); } catch (...) {}
        }
    };
    parse_numeric_map("breakpoint_hit_limits", [&](std::uint64_t address, std::uint64_t limit) {
        g_breakpoint_hit_limits[address] = limit;
    });
    const auto hidden_imports = json_array("hidden_imports");
    const std::regex import_pair_pattern(R"(\[\s*\"([^\"]*)\"\s*,\s*\"([^\"]*)\"\s*\])");
    for (std::sregex_iterator match(hidden_imports.begin(), hidden_imports.end(), import_pair_pattern), last; match != last; ++match)
        g_hidden_imports.insert({wide((*match)[1].str()), wide((*match)[2].str())});
    const auto disabled_imports = json_array("disabled_imports");
    const std::regex disabled_pattern(R"(\[\s*\"([^\"]*)\"\s*,\s*\"([^\"]*)\"\s*,\s*\"([^\"]*)\"\s*,\s*\"([^\"]*)\"\s*\])");
    for (std::sregex_iterator match(disabled_imports.begin(), disabled_imports.end(), disabled_pattern), last; match != last; ++match) {
        try {
            const auto dll = wide((*match)[1].str());
            const auto name = wide((*match)[2].str());
            const auto iat = std::stoull((*match)[3].str(), nullptr, 0);
            (void)std::stoull((*match)[4].str(), nullptr, 0);
            g_requested_disabled_imports[import_key(dll, name)] = {dll, name, iat};
        } catch (...) {}
    }
    g_session_path = file;
    g_session_dirty = false;
    std::error_code ignored;
    std::filesystem::remove(g_session_path.wstring() + L".bak", ignored);
    refresh_views(window);
    SetWindowTextW(g_status, L"Python database annotations loaded.");
    return true;
}

void load_database(HWND window) {
    wchar_t file_name[MAX_PATH]{};
    OPENFILENAMEW dialog{sizeof(dialog)}; dialog.hwndOwner = window; dialog.lpstrFilter = L"Gandon database (*.gnd)\0*.gnd\0\0"; dialog.lpstrFile = file_name; dialog.nMaxFile = MAX_PATH; dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&dialog)) return;
    {
        std::ifstream probe(file_name, std::ios::binary);
        std::string contents((std::istreambuf_iterator<char>(probe)), std::istreambuf_iterator<char>());
        const auto first = contents.find_first_not_of(" \t\r\n\xEF\xBB\xBF");
        if (first != std::string::npos && contents[first] == '{') {
            load_legacy_python_database(window, file_name);
            return;
        }
    }
    std::wifstream input(file_name); std::wstring header, binary_path;
    if (!input || !std::getline(input, header) || (header != L"GANDON-GND-1" && header != L"GANDON-GND-2" && header != L"GANDON-GND-3") || !std::getline(input, binary_path)) { MessageBoxW(window, L"Неверный формат базы данных.", L"Load Database", MB_ICONERROR); return; }
    gandon::BinaryImage image; std::string error;
    if (!image.load(binary_path, error)) { MessageBoxW(window, wide(error).c_str(), L"Load Database", MB_ICONERROR); return; }
    g_database = std::make_unique<gandon::AnalysisDatabase>(std::move(image)); g_database->discover_basic_xrefs(); g_current_address = g_database->image().entry_point; g_session_address = g_current_address; g_session_tab = 0; g_graph_zoom = 100; g_graph_scroll_x = 0; g_graph_scroll_y = 0; g_graph_positions.clear(); g_memory_snapshot.clear(); g_memory_snapshot_address = 0; g_patch_undo.clear(); g_patch_redo.clear(); g_custom_labels.clear(); g_custom_comments.clear(); g_custom_types.clear(); g_navigation_history.clear(); g_bookmarks.clear(); g_hidden_functions.clear(); g_hidden_imports.clear(); g_watch_expressions.clear(); g_graph_colors.clear(); g_requested_disabled_imports.clear(); g_installed_import_disables.clear(); { std::lock_guard lock(g_breakpoint_mutex); g_requested_breakpoints.clear(); g_breakpoint_conditions.clear(); g_breakpoint_hit_counts.clear(); g_breakpoint_hit_limits.clear(); g_breakpoint_log_only.clear(); }
    std::vector<PatchChange> restored_patches;
    std::wstring record; while (std::getline(input, record)) {
        if (record.size() < 3 || record[1] != L'|') continue;
        const auto split = record.find(L'|', 2);
        if (record[0] == L'P' && split != std::wstring::npos) {
            try {
                g_session_address = std::stoull(record.substr(2, split - 2));
                g_session_tab = std::stoi(record.substr(split + 1));
            } catch (...) {}
            continue;
        }
        if (split == std::wstring::npos) continue;
        if (record[0] == L'G') { try { g_graph_zoom = (std::max)(25, (std::min)(180, std::stoi(record.substr(2, split - 2)))); } catch (...) {} continue; }
        if (record[0] == L'H') {
            try {
                std::wistringstream values(record.substr(2, split - 2));
                wchar_t comma{};
                values >> g_graph_scroll_x >> comma >> g_graph_scroll_y;
            } catch (...) {}
            continue;
        }
        if (record[0] == L'R') {
            try { std::wistringstream values(record.substr(2, split - 2)); wchar_t comma{}; RECT rect{}; values >> rect.left >> comma >> rect.top >> comma >> rect.right >> comma >> rect.bottom; if (values && rect.right > rect.left && rect.bottom > rect.top) SetWindowPos(window, nullptr, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, SWP_NOZORDER | SWP_NOACTIVATE); } catch (...) {}
            continue;
        }
        if (record[0] == L'U') {
            try {
                const auto offset = static_cast<std::size_t>(std::stoull(record.substr(2, split - 2)));
                const auto value = static_cast<std::uint8_t>(std::stoul(record.substr(split + 1)) & 0xffu);
                if (offset < g_database->image().bytes.size() && g_database->image().bytes[offset] != value) {
                    const auto original = g_database->image().bytes[offset];
                    std::string patch_error;
                    if (g_database->replace_file_bytes(offset, {value}, patch_error)) restored_patches.push_back({offset, original, value});
                }
            } catch (...) {}
            continue;
        }
        if (record[0] == L'N' || record[0] == L'D') {
            const auto import_name = record.substr(split + 1);
            const auto separator = import_name.find(L'!');
            if (separator != std::wstring::npos) {
                const auto dll = import_name.substr(0, separator);
                const auto name = import_name.substr(separator + 1);
                if (record[0] == L'N') g_hidden_imports.insert({dll, name});
                else {
                    for (const auto& item : enumerate_imports(g_database->image())) {
                        if (import_key(item.dll, item.name) == import_key(dll, name)) {
                            g_requested_disabled_imports[import_key(item.dll, item.name)] = item;
                            break;
                        }
                    }
                }
            }
            continue;
        }
        try {
            const auto address = std::stoull(record.substr(2, split - 2));
            if (record[0] == L'L') g_custom_labels[address] = record.substr(split + 1);
            else if (record[0] == L'C') g_custom_comments[address] = record.substr(split + 1);
            else if (record[0] == L'Y') g_custom_types[address] = record.substr(split + 1);
            else if (record[0] == L'K') g_bookmarks.insert(address);
            else if (record[0] == L'F') g_hidden_functions.insert(address);
            else if (record[0] == L'W') g_watch_expressions.push_back(record.substr(split + 1));
            else if (record[0] == L'T') { try { g_graph_colors[address] = static_cast<COLORREF>(std::stoul(record.substr(split + 1), nullptr, 16)); } catch (...) {} }
            else if (record[0] == L'V') {
                std::wistringstream position(record.substr(split + 1));
                wchar_t comma{}; int x = 0, y = 0;
                position >> x >> comma >> y;
                if (position && comma == L',') g_graph_positions[address] = {x, y};
            }
            else if (record[0] == L'B') { g_requested_breakpoints.insert(address); g_breakpoint_conditions[address] = record.substr(split + 1); }
            else if (record[0] == L'Q') {
                std::wistringstream values(record.substr(split + 1));
                std::uint64_t limit = 0; int log_only = 0; wchar_t comma{};
                values >> limit >> comma >> log_only;
                g_breakpoint_hit_limits[address] = limit;
                if (log_only) g_breakpoint_log_only.insert(address);
            }
        } catch (...) {}
    }
    if (!restored_patches.empty()) g_patch_undo.push_back(std::move(restored_patches));
    const int saved_graph_scroll_x = g_graph_scroll_x;
    const int saved_graph_scroll_y = g_graph_scroll_y;
    g_current_address = g_session_address ? g_session_address : g_database->image().entry_point;
    g_session_path = file_name; g_session_dirty = false; std::error_code ignored; std::filesystem::remove(g_session_path.wstring() + L".bak", ignored);
    refresh_views(window);
    if (g_session_tab >= 0 && g_session_tab < 14) select_view(window, g_session_tab);
    g_graph_scroll_x = saved_graph_scroll_x;
    g_graph_scroll_y = saved_graph_scroll_y;
    clamp_graph_scroll(g_view);
    update_graph_scrollbars(g_view);
    InvalidateRect(g_view, nullptr, FALSE);
    invalidate_minimap();
}

std::wstring make_signature(std::uint64_t address) {
    if (!g_database) return {};
    const auto decoded = gandon::decode_x64(g_database->image(), address, 18);
    if (decoded.empty()) return {};
    std::wostringstream result;
    result << L"Gandon signature at 0x" << std::hex << std::uppercase << address << L"\r\n\r\n";
    for (const auto& instruction : decoded) {
        const bool call_or_jump = instruction.mnemonic == "call" || instruction.mnemonic == "jmp";
        const bool conditional_jump = !instruction.mnemonic.empty() && instruction.mnemonic[0] == 'j' && !call_or_jump;
        for (std::size_t index = 0; index < instruction.bytes.size(); ++index) {
            bool wildcard = false;
            if (call_or_jump && instruction.bytes.size() >= 5) wildcard = index + 4 >= instruction.bytes.size();
            else if (conditional_jump && instruction.bytes.size() >= 2) wildcard = index + (instruction.bytes.size() >= 5 ? 4 : 1) >= instruction.bytes.size();
            if (wildcard) result << L"?? ";
            else result << std::uppercase << std::setfill(L'0') << std::setw(2) << std::hex
                        << static_cast<unsigned>(instruction.bytes[index]) << L" ";
        }
        if (result.tellp() > std::streampos(0)) result << L"\r\n";
    }
    return result.str();
}

bool parse_signature(const std::wstring& text, std::vector<std::optional<std::uint8_t>>& pattern) {
    std::wistringstream input(text);
    std::wstring token;
    while (input >> token) {
        if (token == L"?" || token == L"??") { pattern.push_back(std::nullopt); continue; }
        if (token.size() != 2 || token.find_first_not_of(L"0123456789abcdefABCDEF") != std::wstring::npos) return false;
        try { pattern.push_back(static_cast<std::uint8_t>(std::stoul(token, nullptr, 16))); }
        catch (...) { return false; }
    }
    return !pattern.empty();
}

std::uint64_t file_offset_to_va(const gandon::BinaryImage& image, std::size_t offset) {
    for (const auto& section : image.sections) {
        if (offset >= section.raw_offset && offset < static_cast<std::size_t>(section.raw_offset) + section.raw_size)
            return image.image_base + section.rva + static_cast<std::uint64_t>(offset - section.raw_offset);
    }
    return image.image_base + static_cast<std::uint64_t>(offset);
}

void generate_signature(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Сначала выбери инструкцию или функцию.", L"SigMaker", MB_ICONINFORMATION); return; }
    const auto signature = make_signature(g_current_address);
    if (signature.empty()) { MessageBoxW(window, L"Не удалось построить сигнатуру.", L"SigMaker", MB_ICONERROR); return; }
    MessageBoxW(window, signature.c_str(), L"Gandon Signature", MB_ICONINFORMATION);
}

void search_signature(HWND window) {
    if (!g_database) { MessageBoxW(window, L"Сначала открой бинарный файл.", L"Search Signature", MB_ICONINFORMATION); return; }
    const auto query = prompt_text(window, L"Search Gandon Signature", L"Bytes separated by spaces; use ?? for wildcards:");
    if (!query) return;
    std::vector<std::optional<std::uint8_t>> pattern;
    if (!parse_signature(*query, pattern)) { MessageBoxW(window, L"Неверная сигнатура. Пример: 48 8B ?? ?? E8 ?? ?? ?? ??.", L"Search Signature", MB_ICONWARNING); return; }
    const auto& bytes = g_database->image().bytes;
    std::vector<std::uint64_t> matches;
    for (std::size_t offset = 0; offset + pattern.size() <= bytes.size(); ++offset) {
        bool match = true;
        for (std::size_t index = 0; index < pattern.size(); ++index)
            if (pattern[index] && *pattern[index] != bytes[offset + index]) { match = false; break; }
        if (match) matches.push_back(file_offset_to_va(g_database->image(), offset));
    }
    std::wostringstream result; result << L"Signature matches: " << std::dec << matches.size() << L"\r\n\r\n";
    for (const auto address : matches) result << L"0x" << std::hex << std::uppercase << address << L"\r\n";
    g_listing = result.str();
    if (!matches.empty()) g_current_address = matches.front();
    select_view(window, 1);
}

void draw_export_graph(HDC dc, int width, int height) {
    RECT canvas{0, 0, width, height};
    HBRUSH background = CreateSolidBrush(RGB(24, 27, 32));
    FillRect(dc, &canvas, background); DeleteObject(background);
    if (!g_database) return;
    rebuild_graph_model();
    int graph_width = 0;
    int graph_height = 0;
    for (const auto& block : g_graph_blocks) {
        graph_width = (std::max)(graph_width, block.x + block.width);
        graph_height = (std::max)(graph_height, block.y + block.height);
    }
    const double scale = graph_width > 0 && graph_height > 0
        ? (std::min)(1.0, (std::min)(static_cast<double>(width - 48) / graph_width, static_cast<double>(height - 48) / graph_height))
        : 1.0;
    const int offset_x = 24;
    const int offset_y = 24;
    const auto find_block = [](std::uint64_t address) -> const GraphBlock* {
        for (const auto& block : g_graph_blocks) if (block.start == address) return &block;
        return nullptr;
    };
    for (const auto& edge : g_graph_edges) {
        const auto* source = find_block(edge.from);
        const auto* target = find_block(edge.to);
        if (!source || !target) continue;
        const int sx = offset_x + static_cast<int>((source->x + source->width / 2) * scale);
        const int sy = offset_y + static_cast<int>((source->y + source->height) * scale);
        const int tx = offset_x + static_cast<int>((target->x + target->width / 2) * scale);
        const int ty = offset_y + static_cast<int>(target->y * scale);
        const COLORREF edge_color = edge.kind == GraphEdgeKind::TrueBranch ? RGB(73, 190, 104)
            : edge.kind == GraphEdgeKind::FalseBranch ? RGB(224, 92, 92) : RGB(86, 157, 214);
        HPEN pen = CreatePen(PS_SOLID, edge.kind == GraphEdgeKind::Unconditional ? 3 : 2, edge_color);
        HGDIOBJ old_pen = SelectObject(dc, pen);
        MoveToEx(dc, sx, sy, nullptr); LineTo(dc, sx, (sy + ty) / 2); LineTo(dc, tx, (sy + ty) / 2); LineTo(dc, tx, ty);
        MoveToEx(dc, tx, ty, nullptr); LineTo(dc, tx - 7, ty - 9); MoveToEx(dc, tx, ty, nullptr); LineTo(dc, tx + 7, ty - 9);
        SelectObject(dc, old_pen); DeleteObject(pen);
    }
    HGDIOBJ export_font = SelectObject(dc, g_code_font);
    SetBkMode(dc, TRANSPARENT);
    for (const auto& block : g_graph_blocks) {
        const int x = offset_x + static_cast<int>(block.x * scale);
        const int y = offset_y + static_cast<int>(block.y * scale);
        const int box_width = static_cast<int>(block.width * scale);
        const int box_height = static_cast<int>(block.height * scale);
        RECT box{x, y, x + box_width, y + box_height};
        const bool active = block.start == g_current_address || std::any_of(block.instructions.begin(), block.instructions.end(), [](const auto& instruction) { return instruction.address == g_current_address; });
        HBRUSH fill = CreateSolidBrush(active ? RGB(36, 57, 66) : RGB(32, 39, 47));
        FillRect(dc, &box, fill); DeleteObject(fill);
        HPEN border = CreatePen(PS_SOLID, active ? 2 : 1, active ? RGB(0, 160, 210) : RGB(62, 78, 91));
        HGDIOBJ old_pen = SelectObject(dc, border); HGDIOBJ old_brush = SelectObject(dc, GetStockObject(NULL_BRUSH));
        Rectangle(dc, box.left, box.top, box.right, box.bottom); SelectObject(dc, old_brush); SelectObject(dc, old_pen); DeleteObject(border);
        std::wstring title = g_custom_labels.contains(block.start) ? g_custom_labels[block.start] : L"loc_" + [&] { std::wostringstream value; value << std::hex << std::uppercase << block.start; return value.str(); }();
        title += L":";
        SetTextColor(dc, RGB(170, 239, 207)); TextOutW(dc, x + 12, y + 8, title.c_str(), static_cast<int>(title.size()));
        int line_y = y + 30;
        if (g_custom_comments.contains(block.start)) {
            const auto comment = L"// " + g_custom_comments[block.start];
            SetTextColor(dc, RGB(155, 170, 184)); TextOutW(dc, x + 12, line_y, comment.c_str(), static_cast<int>(comment.size())); line_y += static_cast<int>(18 * scale);
        }
        for (std::size_t index = 0; index < block.instructions.size() && index < 9; ++index) {
            const auto& instruction = block.instructions[index];
            const auto text = wide(instruction.mnemonic + (instruction.operands.empty() ? "" : " " + instruction.operands));
            SetTextColor(dc, !instruction.mnemonic.empty() && instruction.mnemonic.front() == 'j' ? RGB(78, 201, 176) : RGB(215, 228, 238));
            TextOutW(dc, x + 12, line_y, text.c_str(), static_cast<int>(text.size()));
            line_y += static_cast<int>(18 * scale);
        }
    }
    SelectObject(dc, export_font);
    return;
    const int box_width = 300, box_height = 82, gap = 55, left = 24, top = 28;
    const auto count = (std::min<std::size_t>)(g_database->functions().size(), 12);
    auto point = [&](std::size_t index, bool right) {
        const int column = static_cast<int>(index % 3), row = static_cast<int>(index / 3);
        return POINT{left + column * (box_width + gap) + (right ? box_width : 0), top + row * (box_height + 40) + box_height / 2};
    };
    auto visible_function = [&](std::uint64_t address) -> int {
        for (std::size_t index = 0; index < count; ++index)
            if (g_database->functions()[index].start == address) return static_cast<int>(index);
        return -1;
    };
    for (const auto& xref : g_database->xrefs()) {
        int source = -1, target = visible_function(xref.to);
        for (std::size_t index = 0; index < count; ++index) {
            const auto start = g_database->functions()[index].start;
            const auto next = index + 1 < g_database->functions().size() ? g_database->functions()[index + 1].start : UINT64_MAX;
            if (xref.from >= start && xref.from < next) { source = static_cast<int>(index); break; }
        }
        if (source < 0 || target < 0 || source == target) continue;
        const auto from = point(static_cast<std::size_t>(source), true), to = point(static_cast<std::size_t>(target), false);
        HPEN edge = CreatePen(PS_SOLID, 2, xref.kind == "call" ? RGB(54, 157, 220) : RGB(231, 76, 60));
        HGDIOBJ old = SelectObject(dc, edge); MoveToEx(dc, from.x, from.y, nullptr);
        if (from.y == to.y) LineTo(dc, to.x, to.y);
        else { const int bend = (from.x + to.x) / 2; LineTo(dc, bend, from.y); LineTo(dc, bend, to.y); LineTo(dc, to.x, to.y); }
        const int direction = to.x >= from.x ? 1 : -1;
        MoveToEx(dc, to.x, to.y, nullptr); LineTo(dc, to.x - direction * 9, to.y - 5);
        MoveToEx(dc, to.x, to.y, nullptr); LineTo(dc, to.x - direction * 9, to.y + 5);
        SelectObject(dc, old); DeleteObject(edge);
    }
    HGDIOBJ old_font = SelectObject(dc, g_code_font); SetBkMode(dc, TRANSPARENT);
    for (std::size_t index = 0; index < count; ++index) {
        const int column = static_cast<int>(index % 3), row = static_cast<int>(index / 3);
        const int x = left + column * (box_width + gap), y = top + row * (box_height + 40);
        RECT box{x, y, x + box_width, y + box_height};
        HBRUSH fill = CreateSolidBrush(RGB(32, 39, 47)); FillRect(dc, &box, fill); DeleteObject(fill);
        HPEN border = CreatePen(PS_SOLID, 1, RGB(62, 78, 91)); HGDIOBJ old_pen = SelectObject(dc, border); HGDIOBJ old_brush = SelectObject(dc, GetStockObject(NULL_BRUSH)); Rectangle(dc, box.left, box.top, box.right, box.bottom); SelectObject(dc, old_brush); SelectObject(dc, old_pen); DeleteObject(border);
        const auto& function = g_database->functions()[index];
        const auto name = g_custom_labels.contains(function.start) ? g_custom_labels[function.start] : wide(function.name);
        SetTextColor(dc, RGB(170, 239, 207)); TextOutW(dc, x + 12, y + 12, name.c_str(), static_cast<int>(name.size()));
        wchar_t address[40]{}; swprintf_s(address, L"0x%llX", static_cast<unsigned long long>(function.start));
        SetTextColor(dc, RGB(125, 191, 231)); TextOutW(dc, x + 12, y + 40, address, static_cast<int>(wcslen(address)));
        if (g_custom_comments.contains(function.start) && !g_custom_comments[function.start].empty()) {
            SetTextColor(dc, RGB(180, 180, 180)); TextOutW(dc, x + 12, y + 62, g_custom_comments[function.start].c_str(),  static_cast<int>(g_custom_comments[function.start].size()));
        }
    }
    SelectObject(dc, old_font);
}

void export_graph_png(HWND window) {
    if (!g_database) { MessageBoxW(window, L"Сначала открой бинарный файл.", L"Export Graph", MB_ICONINFORMATION); return; }
    wchar_t file_name[MAX_PATH] = L"gandon_view_a.png";
    OPENFILENAMEW dialog{sizeof(dialog)}; dialog.hwndOwner = window; dialog.lpstrFilter = L"PNG image (*.png)\0*.png\0"; dialog.lpstrFile = file_name; dialog.nMaxFile = MAX_PATH; dialog.Flags = OFN_OVERWRITEPROMPT;
    if (!GetSaveFileNameW(&dialog)) return;
    constexpr int width = 1280, height = 760;
    BITMAPINFO info{}; info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER); info.bmiHeader.biWidth = width; info.bmiHeader.biHeight = -height; info.bmiHeader.biPlanes = 1; info.bmiHeader.biBitCount = 32; info.bmiHeader.biCompression = BI_RGB;
    void* pixels = nullptr; HBITMAP bitmap = CreateDIBSection(nullptr, &info, DIB_RGB_COLORS, &pixels, nullptr, 0);
    if (!bitmap || !pixels) { if (bitmap) DeleteObject(bitmap); MessageBoxW(window, L"Не удалось создать буфер изображения графа.", L"Export Graph", MB_ICONERROR); return; }
    HDC memory = CreateCompatibleDC(nullptr);
    if (!memory) { DeleteObject(bitmap); MessageBoxW(window, L"Не удалось создать графический контекст PNG.", L"Export Graph", MB_ICONERROR); return; }
    HGDIOBJ old_bitmap = SelectObject(memory, bitmap);
    if (!old_bitmap || old_bitmap == HGDI_ERROR) { DeleteDC(memory); DeleteObject(bitmap); MessageBoxW(window, L"Не удалось выбрать буфер PNG.", L"Export Graph", MB_ICONERROR); return; }
    draw_export_graph(memory, width, height);
    SelectObject(memory, old_bitmap); DeleteDC(memory);
    auto* pixels32 = static_cast<std::uint32_t*>(pixels);
    for (std::size_t index = 0; index < static_cast<std::size_t>(width) * height; ++index) pixels32[index] |= 0xff000000u;
    const HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    IWICImagingFactory* factory = nullptr; IWICBitmap* source = nullptr; IWICStream* stream = nullptr; IWICBitmapEncoder* encoder = nullptr; IWICBitmapFrameEncode* frame = nullptr; IPropertyBag2* properties = nullptr;
    HRESULT result = SUCCEEDED(init) || init == RPC_E_CHANGED_MODE
        ? CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&factory))
        : init;
    if (SUCCEEDED(result)) result = factory->CreateBitmapFromMemory(width, height, GUID_WICPixelFormat32bppBGRA, width * 4, width * height * 4, reinterpret_cast<BYTE*>(pixels32), &source);
    if (SUCCEEDED(result)) result = factory->CreateStream(&stream);
    if (SUCCEEDED(result)) result = stream->InitializeFromFilename(file_name, GENERIC_WRITE);
    if (SUCCEEDED(result)) result = factory->CreateEncoder(GUID_ContainerFormatPng, nullptr, &encoder);
    if (SUCCEEDED(result)) result = encoder->Initialize(stream, WICBitmapEncoderNoCache);
    if (SUCCEEDED(result)) result = encoder->CreateNewFrame(&frame, &properties);
    if (SUCCEEDED(result)) result = frame->Initialize(properties);
    if (SUCCEEDED(result)) result = frame->SetSize(width, height);
    if (SUCCEEDED(result)) { WICPixelFormatGUID format = GUID_WICPixelFormat32bppBGRA; result = frame->SetPixelFormat(&format); }
    if (SUCCEEDED(result)) result = frame->WriteSource(source, nullptr);
    if (SUCCEEDED(result)) result = frame->Commit();
    if (SUCCEEDED(result)) result = encoder->Commit();
    if (properties) properties->Release(); if (frame) frame->Release(); if (encoder) encoder->Release(); if (stream) stream->Release(); if (source) source->Release(); if (factory) factory->Release();
    if (SUCCEEDED(init)) CoUninitialize();
    DeleteObject(bitmap);
    if (FAILED(result)) { DeleteFileW(file_name); MessageBoxW(window, L"Не удалось сохранить PNG графа.", L"Export Graph", MB_ICONERROR); return; }
    MessageBoxW(window, L"Граф View-A экспортирован в PNG.", L"Export Graph", MB_ICONINFORMATION);
}

void select_view(HWND window, int tab) {
    if (g_database && g_session_tab != tab) g_session_dirty = true;
    g_session_tab = tab;
    if (tab == 0) rebuild_graph_model();
    TabCtrl_SetCurSel(g_tabs, tab);
    set_editor_text();
    InvalidateRect(window, nullptr, TRUE);
}

void search_binary(HWND window) {
    if (!g_database) { MessageBoxW(window, L"Сначала открой бинарный файл.", L"Search", MB_ICONINFORMATION); return; }
    const auto query = prompt_text(window, L"Search Text / Address / Regex", L"ASCII text, hex bytes, address or regex:<pattern>:");
    if (!query || query->empty()) return;
    const auto& text = *query;
    const std::wstring regex_prefix = text.rfind(L"regex:", 0) == 0 ? L"regex:" : (text.rfind(L"re:", 0) == 0 ? L"re:" : L"");
    if (!regex_prefix.empty()) {
        std::string pattern;
        const auto expression = text.substr(regex_prefix.size());
        const int size = WideCharToMultiByte(CP_UTF8, 0, expression.c_str(), static_cast<int>(expression.size()), nullptr, 0, nullptr, nullptr);
        pattern.resize(static_cast<std::size_t>(size));
        WideCharToMultiByte(CP_UTF8, 0, expression.c_str(), static_cast<int>(expression.size()), pattern.data(), size, nullptr, nullptr);
        try {
            const std::regex matcher(pattern, std::regex::ECMAScript | std::regex::optimize);
            const std::string binary(reinterpret_cast<const char*>(g_database->image().bytes.data()), g_database->image().bytes.size());
            std::wostringstream result; std::size_t match_count = 0;
            result << L"Regex matches for /" << expression << L"/\r\n\r\n";
            for (std::sregex_iterator match(binary.begin(), binary.end(), matcher), end; match != end && match_count < 500; ++match, ++match_count) {
                const auto offset = static_cast<std::size_t>(match->position());
                result << L"0x" << std::hex << std::uppercase << file_offset_to_va(g_database->image(), offset)
                       << L"  length " << std::dec << match->length() << L"\r\n";
                if (match_count == 0) g_current_address = file_offset_to_va(g_database->image(), offset);
            }
            result << L"\r\nTotal shown: " << std::dec << match_count;
            g_listing = result.str(); select_view(window, 1); return;
        } catch (const std::regex_error& error) {
            MessageBoxW(window, wide(std::string("Invalid regex: ") + error.what()).c_str(), L"Search Regex", MB_ICONWARNING);
            return;
        }
    }
    try {
        if (text.rfind(L"0x", 0) == 0 || text.find_first_not_of(L"0123456789") == std::wstring::npos) {
            const auto address = std::stoull(text, nullptr, 0);
            g_current_address = address; g_session_dirty = true;
            g_listing = listing_text_at(*g_database, address);
            select_view(window, 1);
            return;
        }
    } catch (...) {}
    std::vector<std::uint8_t> pattern;
    std::wstring token; bool hex_pattern = true;
    for (std::size_t i = 0; i <= text.size(); ++i) {
        const wchar_t ch = i < text.size() ? text[i] : L' ';
        if (std::iswspace(ch)) {
            if (!token.empty()) {
                if (token.size() != 2 || token.find_first_not_of(L"0123456789abcdefABCDEF") != std::wstring::npos) { hex_pattern = false; break; }
                pattern.push_back(static_cast<std::uint8_t>(std::stoul(token, nullptr, 16))); token.clear();
            }
        } else token.push_back(ch);
    }
    if (!hex_pattern || pattern.empty()) {
        int size = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
        std::string ascii(static_cast<std::size_t>(size), '\0'); WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), ascii.data(), size, nullptr, nullptr);
        pattern.assign(ascii.begin(), ascii.end());
    }
    const auto matches = g_database->image().find_bytes(pattern);
    std::wostringstream result; result << L"Matches: " << matches.size() << L"\r\n\r\n";
    const auto limit = (std::min<std::size_t>)(matches.size(), 100);
    for (std::size_t i = 0; i < limit; ++i) result << L"0x" << std::hex << matches[i] << L"\r\n";
    g_listing = result.str();
    if (!matches.empty()) {
        g_current_address = matches.front();
        g_session_dirty = true;
    }
    select_view(window, 1);
}

void list_xrefs(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Сначала выбери адрес.", L"XREFs", MB_ICONINFORMATION); return; }
    std::wostringstream result;
    result << L"XREFs for 0x" << std::hex << std::uppercase << g_current_address << L"\r\n\r\nFrom                    To                      Type\r\n";
    std::size_t count = 0;
    for (const auto& xref : g_database->xrefs()) {
        if (xref.from != g_current_address && xref.to != g_current_address) continue;
        result << L"0x" << std::hex << std::uppercase << xref.from << L"              0x" << xref.to << L"              " << wide(xref.kind) << L"\r\n";
        ++count;
    }
    if (!count) result << L"No references found.\r\n";
    g_xrefs = result.str();
    select_view(window, 3);
}

bool parse_search_bytes(const std::wstring& query, std::vector<std::uint8_t>& bytes) {
    std::wstring token;
    bool hex = true;
    for (std::size_t index = 0; index <= query.size(); ++index) {
        const auto ch = index < query.size() ? query[index] : L' ';
        if (std::iswspace(ch)) {
            if (token.empty()) continue;
            if (token.size() != 2 || token.find_first_not_of(L"0123456789abcdefABCDEF") != std::wstring::npos) { hex = false; break; }
            try { bytes.push_back(static_cast<std::uint8_t>(std::stoul(token, nullptr, 16))); } catch (...) { hex = false; break; }
            token.clear();
        } else token.push_back(ch);
    }
    if (!hex || bytes.empty()) {
        bytes.clear();
        const auto value = utf8(query);
        bytes.assign(value.begin(), value.end());
    }
    return !bytes.empty();
}

std::vector<std::uint8_t> read_memory_bytes(std::uint64_t address, std::size_t count) {
    if (!g_database || count == 0) return {};
    std::vector<std::uint8_t> bytes(count);
    if (const auto process = g_debug_process.load()) {
        auto runtime = address;
        const auto base = g_debug_base.load();
        if (base && address >= g_database->image().image_base) runtime = base + (address - g_database->image().image_base);
        SIZE_T read = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(runtime), bytes.data(), bytes.size(), &read) || !read) return {};
        bytes.resize(static_cast<std::size_t>(read));
        return bytes;
    }
    if (const auto offset = g_database->image().va_to_file_offset(address)) {
        const auto available = (std::min)(count, g_database->image().bytes.size() - *offset);
        bytes.resize(available);
        std::copy_n(g_database->image().bytes.begin() + static_cast<std::ptrdiff_t>(*offset), available, bytes.begin());
        return bytes;
    }
    return {};
}

void capture_memory_snapshot(HWND window) {
    if (!g_database) { MessageBoxW(window, L"Сначала открой бинарный файл.", L"Memory Snapshot", MB_ICONINFORMATION); return; }
    g_memory_snapshot_address = g_current_address ? g_current_address : g_database->image().image_base;
    g_memory_snapshot = read_memory_bytes(g_memory_snapshot_address, 512);
    if (g_memory_snapshot.empty()) { MessageBoxW(window, L"Не удалось снять снимок памяти.", L"Memory Snapshot", MB_ICONWARNING); return; }
    SetWindowTextW(g_status, L"Memory snapshot captured.");
}

void compare_memory_snapshot(HWND window) {
    if (g_memory_snapshot.empty()) { MessageBoxW(window, L"Сначала создай снимок памяти.", L"Memory Snapshot", MB_ICONINFORMATION); return; }
    const auto current = read_memory_bytes(g_memory_snapshot_address, g_memory_snapshot.size());
    std::size_t differences = 0;
    std::wostringstream report;
    report << L"Memory snapshot comparison at 0x" << std::hex << std::uppercase << g_memory_snapshot_address << L"\r\n\r\n";
    const auto limit = (std::min)(g_memory_snapshot.size(), current.size());
    for (std::size_t index = 0; index < limit; ++index) {
        if (g_memory_snapshot[index] == current[index]) continue;
        ++differences;
        if (differences <= 200) report << L"0x" << std::hex << std::uppercase << (g_memory_snapshot_address + index)
            << L"  " << std::setw(2) << static_cast<unsigned>(g_memory_snapshot[index]) << L" -> "
            << std::setw(2) << static_cast<unsigned>(current[index]) << L"\r\n";
    }
    differences += g_memory_snapshot.size() > limit ? g_memory_snapshot.size() - limit : current.size() < limit ? limit - current.size() : 0;
    report << L"\r\nChanged bytes: " << std::dec << differences;
    g_listing = report.str();
    select_view(window, 1);
}

void show_memory_view(HWND window) {
    if (!g_database) { MessageBoxW(window, L"Сначала открой бинарный файл.", L"Memory View", MB_ICONINFORMATION); return; }
    std::wostringstream initial;
    initial << L"0x" << std::hex << std::uppercase << (g_current_address ? g_current_address : g_database->image().image_base);
    const auto value = prompt_text(window, L"Memory View", L"Address:", initial.str());
    if (!value || value->empty()) return;
    std::uint64_t address = 0;
    try { address = std::stoull(*value, nullptr, 0); }
    catch (...) { MessageBoxW(window, L"Неверный адрес.", L"Memory View", MB_ICONWARNING); return; }

    constexpr std::size_t byte_count = 512;
    const auto bytes = read_memory_bytes(address, byte_count);
    const std::size_t available = bytes.size();
    if (!available) { MessageBoxW(window, L"Не удалось прочитать память по этому адресу.", L"Memory View", MB_ICONWARNING); return; }

    std::wostringstream out;
    out << (g_debug_process.load() ? L"Process Memory" : L"File Image Memory") << L"\r\n==============\r\n";
    for (std::size_t row = 0; row < available; row += 16) {
        out << L"0x" << std::hex << std::uppercase << std::setfill(L'0') << std::setw(16) << (address + row) << L"  ";
        for (std::size_t column = 0; column < 16; ++column) {
            if (row + column < available) out << std::setw(2) << static_cast<unsigned>(bytes[row + column]) << L' ';
            else out << L"   ";
        }
        out << L" |";
        for (std::size_t column = 0; column < 16 && row + column < available; ++column) {
            const auto byte = bytes[row + column];
            out << static_cast<wchar_t>(byte >= 0x20 && byte <= 0x7e ? byte : '.');
        }
        out << L"|\r\n";
    }
    g_listing = out.str();
    g_current_address = address;
    select_view(window, 1);
    SetWindowTextW(g_status, g_debug_process.load() ? L"Process memory loaded." : L"File-image memory loaded.");
}

void search_process_memory(HWND window) {
    const auto process = g_debug_process.load();
    if (!process) { MessageBoxW(window, L"Сначала запусти процесс под отладчиком.", L"Search Process Memory", MB_ICONINFORMATION); return; }
    const auto query = prompt_text(window, L"Search Process Memory", L"Hex bytes (48 8B ??) or ASCII text:");
    if (!query || query->empty()) return;
    std::vector<std::uint8_t> pattern;
    if (!parse_search_bytes(*query, pattern)) return;
    std::wostringstream result; result << L"Process memory matches for: " << *query << L"\r\n\r\n";
    std::uintptr_t address = 0; std::size_t matches = 0, scanned = 0;
    MEMORY_BASIC_INFORMATION region{};
    while (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &region, sizeof(region)) == sizeof(region) && matches < 500 && scanned < 256u * 1024u * 1024u) {
        const auto protect = region.Protect ? region.Protect : region.AllocationProtect;
        const bool readable = region.State == MEM_COMMIT && !(protect & PAGE_GUARD) && !(protect & PAGE_NOACCESS) && (protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
        const auto base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
        const auto size = static_cast<std::size_t>(region.RegionSize);
        if (readable && size > 0) {
            const auto read_size = (std::min<std::size_t>)(size, 16u * 1024u * 1024u);
            std::vector<std::uint8_t> data(read_size); SIZE_T read = 0;
            if (ReadProcessMemory(process, region.BaseAddress, data.data(), data.size(), &read) && read >= pattern.size()) {
                scanned += read;
                for (std::size_t offset = 0; offset + pattern.size() <= read && matches < 500; ++offset) {
                    if (std::equal(pattern.begin(), pattern.end(), data.begin() + static_cast<std::ptrdiff_t>(offset))) {
                        result << L"0x" << std::hex << std::uppercase << (base + offset) << L"\r\n"; ++matches;
                    }
                }
            }
        }
        const auto next = base + size;
        if (next <= address) break;
        address = next; region = {};
    }
    result << L"\r\nMatches shown: " << std::dec << matches << L"\r\nBytes scanned: " << scanned;
    g_listing = result.str(); select_view(window, 1);
}

void edit_instruction(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Сначала выбери адрес инструкции.", L"Edit Instruction", MB_ICONINFORMATION); return; }
    const auto decoded = gandon::decode_x64(g_database->image(), g_current_address, 1);
    if (decoded.empty()) { MessageBoxW(window, L"Не удалось декодировать инструкцию.", L"Edit Instruction", MB_ICONERROR); return; }
    const auto& instruction = decoded.front();
    std::wstring original = wide(instruction.mnemonic + (instruction.operands.empty() ? "" : " " + instruction.operands));
    const auto replacement_text = prompt_text(window, L"Patch Instruction", L"Assembly instruction:", original);
    if (!replacement_text || replacement_text->empty()) return;
    std::string assembly_error;
    const auto bytes = assemble_with_keystone(*replacement_text, g_current_address, g_database->image().image_base > 0xffffffffull, assembly_error);
    if (bytes.empty()) { MessageBoxW(window, wide(assembly_error.empty() ? "Не удалось собрать инструкцию через Keystone." : assembly_error).c_str(), L"Patch Instruction", MB_ICONWARNING); return; }
    if (bytes.size() > instruction.size) { MessageBoxW(window, L"Новая инструкция длиннее исходной. Выбери инструкцию такого же или меньшего размера.", L"Patch Instruction", MB_ICONWARNING); return; }
    std::vector<std::uint8_t> replacement = bytes; replacement.resize(instruction.size, 0x90);
    std::vector<std::uint8_t> original_bytes; std::string error;
    const auto offset = g_database->image().va_to_file_offset(g_current_address);
    if (!offset || !g_database->patch_bytes(g_current_address, replacement, original_bytes, error)) { MessageBoxW(window, wide(error).c_str(), L"Patch Instruction", MB_ICONERROR); return; }
    std::vector<PatchChange> changes; for (std::size_t i = 0; i < replacement.size(); ++i) if (replacement[i] != original_bytes[i]) changes.push_back({*offset + i, original_bytes[i], replacement[i]});
    if (!changes.empty()) { g_patch_undo.push_back(std::move(changes)); g_patch_redo.clear(); refresh_after_patch(window); }
}

void python_console(HWND window) {
    const auto code = prompt_text(window, L"Python Console", L"Python expression or statements:", L"print('Gandon-PRO native console')");
    if (!code || code->empty()) return;
    wchar_t temp_path[MAX_PATH]{};
    if (GetTempPathW(MAX_PATH, temp_path) == 0) { MessageBoxW(window, L"Не удалось определить TEMP-каталог.", L"Python Console", MB_ICONERROR); return; }
    const auto script = std::filesystem::path(temp_path) / (L"gandon_native_console_" + std::to_wstring(GetCurrentProcessId()) + L".py");
    int size = WideCharToMultiByte(CP_UTF8, 0, code->c_str(), static_cast<int>(code->size()), nullptr, 0, nullptr, nullptr);
    std::string source(static_cast<std::size_t>((std::max)(0, size)), '\0');
    if (size > 0) WideCharToMultiByte(CP_UTF8, 0, code->c_str(), static_cast<int>(code->size()), source.data(), size, nullptr, nullptr);
    { std::ofstream output(script, std::ios::binary | std::ios::trunc); const char header[] = "# -*- coding: utf-8 -*-\n"; output.write(header, static_cast<std::streamsize>(sizeof(header) - 1)); output.write(source.data(), static_cast<std::streamsize>(source.size())); if (!output) { MessageBoxW(window, L"Не удалось создать временный Python-скрипт.", L"Python Console", MB_ICONERROR); return; } }
    const auto command = "set PYTHONUTF8=1&& set PYTHONIOENCODING=utf-8&& " + python_interpreter_command() + " \"" + script.string() + "\" 2>&1";
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) { std::error_code ignored; std::filesystem::remove(script, ignored); MessageBoxW(window, L"Не удалось запустить Python.", L"Python Console", MB_ICONERROR); return; }
    std::string output; char buffer[512]{}; while (fgets(buffer, sizeof(buffer), pipe)) output += buffer;
    const int exit_code = _pclose(pipe);
    std::error_code ignored; std::filesystem::remove(script, ignored);
    while (!output.empty() && (output.back() == '\r' || output.back() == '\n')) output.pop_back();
    const auto message = output.empty() ? std::wstring(L"(no output)") : wide(output);
    MessageBoxW(window, message.c_str(), L"Python Console", exit_code == 0 ? MB_ICONINFORMATION : MB_ICONERROR);
}

void compare_binary(HWND window) {
    if (!g_database) { MessageBoxW(window, L"Сначала открой бинарный файл.", L"Compare Binary", MB_ICONINFORMATION); return; }
    wchar_t file_name[MAX_PATH]{}; OPENFILENAMEW dialog{sizeof(dialog)}; dialog.hwndOwner = window; dialog.lpstrFilter = L"Binaries (*.exe;*.dll;*.so)\0*.exe;*.dll;*.so\0All files (*.*)\0*.*\0"; dialog.lpstrFile = file_name; dialog.nMaxFile = MAX_PATH; dialog.Flags = OFN_FILEMUSTEXIST;
    if (!GetOpenFileNameW(&dialog)) return;
    std::ifstream other(file_name, std::ios::binary); std::vector<std::uint8_t> bytes(std::istreambuf_iterator<char>(other), {});
    const bool same_size = bytes.size() == g_database->image().bytes.size();
    std::size_t differences = 0, limit = (std::min)(bytes.size(), g_database->image().bytes.size());
    for (std::size_t i = 0; i < limit; ++i) if (bytes[i] != g_database->image().bytes[i]) ++differences;
    differences += bytes.size() > limit ? bytes.size() - limit : g_database->image().bytes.size() - limit;
    std::wostringstream report;
    report << L"Compared with:\r\n" << std::filesystem::path(file_name).wstring()
           << L"\r\n\r\nSize equal: " << (same_size ? L"yes" : L"no")
           << L"\r\nDifferent bytes: " << differences << L"\r\n\r\nOffset / Current / Other\r\n";
    std::size_t shown = 0;
    for (std::size_t i = 0; i < limit && shown < 300; ++i) {
        if (bytes[i] == g_database->image().bytes[i]) continue;
        report << L"0x" << std::hex << std::uppercase << i << L"  "
               << std::setw(2) << static_cast<unsigned>(g_database->image().bytes[i]) << L"  "
               << std::setw(2) << static_cast<unsigned>(bytes[i]) << L"\r\n";
        ++shown;
    }
    g_listing = report.str();
    select_view(window, 1);
    SetWindowTextW(g_status, L"Binary comparison loaded in Gandon Text Listing.");
}

bool write_runtime_byte(HANDLE process, std::uint64_t address, std::uint8_t value) {
    SIZE_T written{};
    if (!WriteProcessMemory(process, reinterpret_cast<LPVOID>(address), &value, 1, &written) || written != 1) return false;
    FlushInstructionCache(process, reinterpret_cast<LPCVOID>(address), 1);
    return true;
}

bool write_runtime_bytes(HANDLE process, std::uint64_t address, const std::vector<std::uint8_t>& bytes) {
    if (!process || bytes.empty()) return false;
    SIZE_T written{};
    if (!WriteProcessMemory(process, reinterpret_cast<LPVOID>(address), bytes.data(), bytes.size(), &written) || written != bytes.size()) return false;
    FlushInstructionCache(process, reinterpret_cast<LPCVOID>(address), bytes.size());
    return true;
}

void install_requested_import_disables(HANDLE process, std::uint64_t module_base) {
    if (!process || !g_database || !module_base) return;
    const auto pointer_size = g_database->image().is_64_bit ? 8u : 4u;
    for (const auto& [key, record] : g_requested_disabled_imports) {
        if (g_installed_import_disables.contains(key)) continue;
        const auto runtime_iat = module_base + (record.iat_va - g_database->image().image_base);
        std::uint64_t original = 0;
        SIZE_T read{};
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(runtime_iat), &original, pointer_size, &read) || read != pointer_size) {
            log_debug_event(L"Import disable failed: cannot read IAT for " + record.dll + L"!" + record.name);
            continue;
        }
        const std::vector<std::uint8_t> stub_code{0x31, 0xC0, 0xC3};
        const auto stub = reinterpret_cast<std::uint64_t>(VirtualAllocEx(process, nullptr, stub_code.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!stub || !write_runtime_bytes(process, stub, stub_code)) {
            if (stub) VirtualFreeEx(process, reinterpret_cast<LPVOID>(stub), 0, MEM_RELEASE);
            log_debug_event(L"Import disable failed: cannot create stub for " + record.dll + L"!" + record.name);
            continue;
        }
        std::vector<std::uint8_t> pointer(pointer_size, 0);
        for (std::size_t index = 0; index < pointer.size(); ++index) pointer[index] = static_cast<std::uint8_t>((stub >> (index * 8)) & 0xffu);
        if (!write_runtime_bytes(process, runtime_iat, pointer)) {
            VirtualFreeEx(process, reinterpret_cast<LPVOID>(stub), 0, MEM_RELEASE);
            log_debug_event(L"Import disable failed: cannot patch IAT for " + record.dll + L"!" + record.name);
            continue;
        }
        g_installed_import_disables[key] = {runtime_iat, original, stub};
        log_debug_event(L"Import disabled: " + record.dll + L"!" + record.name + L" (returns FALSE)");
    }
}

void restore_import_disables(HANDLE process) {
    for (const auto& [key, installed] : g_installed_import_disables) {
        if (process) {
            const auto pointer_size = g_database && g_database->image().is_64_bit ? 8u : 4u;
            std::vector<std::uint8_t> pointer(pointer_size, 0);
            for (std::size_t index = 0; index < pointer.size(); ++index) pointer[index] = static_cast<std::uint8_t>((installed.original_target >> (index * 8)) & 0xffu);
            write_runtime_bytes(process, installed.runtime_iat, pointer);
            VirtualFreeEx(process, reinterpret_cast<LPVOID>(installed.stub), 0, MEM_RELEASE);
        }
    }
    g_installed_import_disables.clear();
}

void toggle_import_disable(HWND window, std::uint64_t iat_va) {
    if (!g_database) return;
    const auto record = import_for_iat(iat_va);
    if (!record) return;
    const auto key = import_key(record->dll, record->name);
    const auto requested = g_requested_disabled_imports.find(key);
    if (requested != g_requested_disabled_imports.end()) {
        const auto installed = g_installed_import_disables.find(key);
        if (installed != g_installed_import_disables.end()) {
            const auto process = g_debug_process.load();
            const auto pointer_size = g_database->image().is_64_bit ? 8u : 4u;
            std::vector<std::uint8_t> pointer(pointer_size, 0);
            for (std::size_t index = 0; index < pointer.size(); ++index) pointer[index] = static_cast<std::uint8_t>((installed->second.original_target >> (index * 8)) & 0xffu);
            if (process) write_runtime_bytes(process, installed->second.runtime_iat, pointer);
            if (process) VirtualFreeEx(process, reinterpret_cast<LPVOID>(installed->second.stub), 0, MEM_RELEASE);
            g_installed_import_disables.erase(installed);
        }
        g_requested_disabled_imports.erase(requested);
        SetWindowTextW(g_status, (L"Import enabled: " + record->dll + L"!" + record->name).c_str());
    } else {
        g_requested_disabled_imports.emplace(key, *record);
        if (const auto process = g_debug_process.load()) install_requested_import_disables(process, g_debug_base.load());
        SetWindowTextW(g_status, (L"Import queued for disable: " + record->dll + L"!" + record->name).c_str());
    }
    g_session_dirty = true;
    fill_tree();
    (void)window;
}

std::optional<std::uint64_t> remote_module_base(DWORD pid, const std::wstring& module_name) {
    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return std::nullopt;
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::optional<std::uint64_t> result;
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, module_name.c_str()) == 0) {
                result = reinterpret_cast<std::uint64_t>(entry.modBaseAddr);
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}

bool patch_remote_export(HANDLE process, DWORD pid, const std::wstring& module_name,
                         const char* export_name, const std::vector<std::uint8_t>& patch) {
    if (!process || patch.empty()) return false;
    const auto local_module = GetModuleHandleW(module_name.c_str());
    if (!local_module) return false;
    const auto local_export = GetProcAddress(local_module, export_name);
    const auto remote_module = remote_module_base(pid, module_name);
    if (!local_export || !remote_module) return false;
    const auto local_rva = reinterpret_cast<std::uintptr_t>(local_export) - reinterpret_cast<std::uintptr_t>(local_module);
    const auto remote_address = *remote_module + local_rva;
    DWORD old_protection{};
    if (!VirtualProtectEx(process, reinterpret_cast<LPVOID>(remote_address), patch.size(), PAGE_EXECUTE_READWRITE, &old_protection)) return false;
    bool success = false;
    SIZE_T written{};
    if (WriteProcessMemory(process, reinterpret_cast<LPVOID>(remote_address), patch.data(), patch.size(), &written) && written == patch.size()) {
        FlushInstructionCache(process, reinterpret_cast<LPCVOID>(remote_address), patch.size());
        std::vector<std::uint8_t> verify(patch.size());
        SIZE_T read{};
        success = ReadProcessMemory(process, reinterpret_cast<LPCVOID>(remote_address), verify.data(), verify.size(), &read) &&
                  read == verify.size() && verify == patch;
    }
    VirtualProtectEx(process, reinterpret_cast<LPVOID>(remote_address), patch.size(), old_protection, &old_protection);
    return success;
}

struct NativeProcessBasicInformation {
    PVOID reserved1{};
    PVOID peb_address{};
    PVOID reserved2[2]{};
    ULONG_PTR unique_process_id{};
    PVOID reserved3{};
};

std::pair<int, std::wstring> apply_stealth_to_process(HANDLE process, DWORD pid, bool target_is_64) {
    if (!process || !pid) return {0, L"Target process is not running."};
    int patched = 0;
    std::vector<std::wstring> details;
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    using NtQueryInformationProcessFn = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    const auto query_process = ntdll ? reinterpret_cast<NtQueryInformationProcessFn>(GetProcAddress(ntdll, "NtQueryInformationProcess")) : nullptr;
    if (query_process) {
        NativeProcessBasicInformation information{};
        ULONG returned{};
        if (query_process(process, 0, &information, sizeof(information), &returned) == 0 && information.peb_address) {
            const auto peb = reinterpret_cast<std::uintptr_t>(information.peb_address);
            std::uint8_t zero_byte = 0;
            DWORD zero_flag = 0;
            SIZE_T written{};
            bool being_debugged = WriteProcessMemory(process, reinterpret_cast<LPVOID>(peb + 2), &zero_byte, sizeof(zero_byte), &written) && written == sizeof(zero_byte);
            written = 0;
            const auto nt_global_flag_offset = target_is_64 ? 0xBCu : 0x68u;
            bool global_flag = WriteProcessMemory(process, reinterpret_cast<LPVOID>(peb + nt_global_flag_offset), &zero_flag, sizeof(zero_flag), &written) && written == sizeof(zero_flag);
            if (being_debugged) details.push_back(L"PEB.BeingDebugged=0");
            if (global_flag) details.push_back(L"PEB.NtGlobalFlag=0");
        }
    }
    const std::vector<std::uint8_t> is_debugger_present = {0x31, 0xC0, 0xC3};
    for (const auto& module : {std::wstring(L"kernel32.dll"), std::wstring(L"kernelbase.dll")})
        if (patch_remote_export(process, pid, module, "IsDebuggerPresent", is_debugger_present)) ++patched;
    const std::vector<std::uint8_t> check_remote_debugger = target_is_64
        ? std::vector<std::uint8_t>{0xC7, 0x02, 0x00, 0x00, 0x00, 0x00, 0xC3}
        : std::vector<std::uint8_t>{0xC7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x00, 0xC2, 0x08, 0x00};
    for (const auto& module : {std::wstring(L"kernel32.dll"), std::wstring(L"kernelbase.dll")})
        if (patch_remote_export(process, pid, module, "CheckRemoteDebuggerPresent", check_remote_debugger)) ++patched;
    if (patched || !details.empty()) {
        std::wostringstream message;
        message << L"Anti-debug bypass: " << patched << L" API hook(s)";
        if (!details.empty()) { message << L"; "; for (std::size_t index = 0; index < details.size(); ++index) message << (index ? L", " : L"") << details[index]; }
        return {patched + static_cast<int>(details.size()), message.str()};
    }
    return {0, L"Anti-debug bypass could not patch the target (system modules may not be loaded yet)."};
}

void apply_antidebug(HWND window) {
    const auto process = g_debug_process.load();
    const auto pid = g_debug_pid.load();
    if (!process || !pid) {
        MessageBoxW(window, L"Сначала запусти процесс под отладчиком.", L"Anti-Debug Bypass", MB_ICONINFORMATION);
        return;
    }
    const bool target_is_64 = !g_database || g_database->image().image_base > 0xffffffffull;
    const auto result = apply_stealth_to_process(process, pid, target_is_64);
    if (result.first > 0) g_stealth_applied.store(true);
    log_debug_event(result.second);
    SetWindowTextW(g_status, result.second.c_str());
    MessageBoxW(window, result.second.c_str(), L"Anti-Debug Bypass", result.first > 0 ? MB_ICONINFORMATION : MB_ICONWARNING);
}

std::uint64_t context_register_value(const CONTEXT& context, const std::wstring& name, bool& found) {
    std::wstring lowered = name; for (auto& character : lowered) character = static_cast<wchar_t>(towlower(character));
    found = true;
    if (lowered == L"rax") return context.Rax; if (lowered == L"rbx") return context.Rbx;
    if (lowered == L"rcx") return context.Rcx; if (lowered == L"rdx") return context.Rdx;
    if (lowered == L"rsi") return context.Rsi; if (lowered == L"rdi") return context.Rdi;
    if (lowered == L"rsp") return context.Rsp; if (lowered == L"rbp") return context.Rbp;
    if (lowered == L"rip") return context.Rip; if (lowered == L"r8") return context.R8;
    if (lowered == L"r9") return context.R9; if (lowered == L"r10") return context.R10;
    if (lowered == L"r11") return context.R11; if (lowered == L"r12") return context.R12;
    if (lowered == L"r13") return context.R13; if (lowered == L"r14") return context.R14;
    if (lowered == L"r15") return context.R15;
    found = false; return 0;
}

bool breakpoint_condition_matches(HANDLE process, DWORD thread_id, std::uint64_t static_address) {
    std::wstring condition;
    const auto it = g_breakpoint_conditions.find(static_address); if (it == g_breakpoint_conditions.end() || it->second.empty()) return true; condition = it->second;
    enum class Comparison { Equal, NotEqual, Less, LessEqual, Greater, GreaterEqual } comparison{};
    std::size_t operator_position = std::wstring::npos, operator_length = 0;
    const std::pair<std::wstring_view, Comparison> operators[] = {
        {L"==", Comparison::Equal}, {L"!=", Comparison::NotEqual},
        {L"<=", Comparison::LessEqual}, {L">=", Comparison::GreaterEqual},
        {L"<", Comparison::Less}, {L">", Comparison::Greater}
    };
    for (const auto& candidate : operators) {
        const auto position = condition.find(candidate.first);
        if (position != std::wstring::npos && (operator_position == std::wstring::npos || position < operator_position)) {
            operator_position = position;
            operator_length = candidate.first.size();
            comparison = candidate.second;
        }
    }
    if (operator_position == std::wstring::npos) return false;
    std::wstring register_name = condition.substr(0, operator_position), value_text = condition.substr(operator_position + operator_length);
    auto trim = [](std::wstring& value) { const auto first = value.find_first_not_of(L" \t"); const auto last = value.find_last_not_of(L" \t"); value = first == std::wstring::npos ? L"" : value.substr(first, last - first + 1); };
    trim(register_name); trim(value_text);
    std::uint64_t expected = 0; try { expected = std::stoull(value_text, nullptr, 0); } catch (...) { return false; }
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT, FALSE, thread_id); if (!thread) return false;
    CONTEXT context{}; context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL; const bool read = GetThreadContext(thread, &context); CloseHandle(thread); if (!read) return false;
    bool found = false; const auto actual = context_register_value(context, register_name, found); if (!found) return false;
    switch (comparison) {
    case Comparison::Equal: return actual == expected;
    case Comparison::NotEqual: return actual != expected;
    case Comparison::Less: return actual < expected;
    case Comparison::LessEqual: return actual <= expected;
    case Comparison::Greater: return actual > expected;
    case Comparison::GreaterEqual: return actual >= expected;
    }
    return false;
}

void install_requested_breakpoints(HANDLE process, std::uint64_t base) {
    std::lock_guard lock(g_breakpoint_mutex);
    for (const auto static_address : g_requested_breakpoints) {
        const auto runtime = base + (static_address - g_database->image().image_base);
        if (g_runtime_breakpoints.contains(runtime)) continue;
        std::uint8_t original{}; SIZE_T read{};
        if (ReadProcessMemory(process, reinterpret_cast<LPCVOID>(runtime), &original, 1, &read) && read == 1 && write_runtime_byte(process, runtime, 0xcc))
            g_runtime_breakpoints[runtime] = {static_address, original};
    }
}

DebugResumeMode wait_for_debug_resume(HWND window, std::uint64_t address, WPARAM status_kind) {
    std::unique_lock lock(g_debug_control_mutex);
    g_debug_resume_mode = DebugResumeMode::None;
    g_debug_pause_address.store(address);
    g_debug_paused.store(true);
    PostMessageW(window, WM_DEBUG_STATUS, status_kind, static_cast<LPARAM>(address));
    g_debug_control_cv.wait(lock, [] { return g_debug_resume_mode != DebugResumeMode::None; });
    const auto mode = g_debug_resume_mode;
    g_debug_resume_mode = DebugResumeMode::None;
    g_debug_paused.store(false);
    return mode;
}

bool request_debug_resume(DebugResumeMode mode) {
    std::lock_guard lock(g_debug_control_mutex);
    if (!g_debug_paused.load()) return false;
    g_debug_resume_mode = mode;
    // Reflect the resume immediately in the UI. The debugger worker clears the
    // flag as well after it wakes, but waiting for that creates a stale PAUSED
    // frame when Start/Continue is pressed.
    g_debug_paused.store(false);
    g_debug_control_cv.notify_one();
    return true;
}

bool set_thread_trap_flag(DWORD thread_id, bool enabled) {
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, thread_id);
    if (!thread) return false;
    CONTEXT context{}; context.ContextFlags = CONTEXT_CONTROL;
    bool ok = GetThreadContext(thread, &context) != FALSE;
    if (ok) {
        if (enabled) context.EFlags |= 0x100u;
        else context.EFlags &= ~0x100u;
        ok = SetThreadContext(thread, &context) != FALSE;
    }
    CloseHandle(thread);
    return ok;
}

bool arm_step_over_breakpoint(HANDLE process, std::uint64_t runtime_address) {
    if (!g_database || !g_debug_base.load() || runtime_address < g_debug_base.load()) return false;
    const auto static_address = g_database->image().image_base + (runtime_address - g_debug_base.load());
    const auto decoded = gandon::decode_x64(g_database->image(), static_address, 1);
    if (decoded.empty() || decoded.front().mnemonic != "call" || decoded.front().size == 0) return false;
    const auto next_runtime = runtime_address + decoded.front().size;
    std::lock_guard lock(g_breakpoint_mutex);
    if (g_runtime_breakpoints.contains(next_runtime)) return false;
    std::uint8_t original{}; SIZE_T read{};
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(next_runtime), &original, 1, &read)
        || read != 1 || !write_runtime_byte(process, next_runtime, 0xcc)) return false;
    g_runtime_breakpoints[next_runtime] = {0, original};
    g_step_over_runtime.store(next_runtime);
    return true;
}

void configure_debug_resume(HANDLE process, DWORD thread_id, std::uint64_t runtime_address,
                            DebugResumeMode mode, bool must_rearm_breakpoint) {
    const bool step_over_armed = mode == DebugResumeMode::StepOver
        && arm_step_over_breakpoint(process, runtime_address);
    const bool trap = must_rearm_breakpoint || mode == DebugResumeMode::StepInto
        || (mode == DebugResumeMode::StepOver && !step_over_armed);
    set_thread_trap_flag(thread_id, trap);
    g_pause_on_next_single_step.store(
        mode == DebugResumeMode::StepInto
        || (mode == DebugResumeMode::StepOver && !step_over_armed));
}

void debug_loop(HWND window, HANDLE process, DWORD pid) {
    DEBUG_EVENT event{};
    std::uint64_t rearm_runtime = 0; DWORD rearm_thread = 0;
    bool initial_breakpoint_seen = false;
    while (WaitForDebugEvent(&event, INFINITE)) {
        DWORD continue_status = DBG_CONTINUE;
        const auto trace_address = event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
            ? reinterpret_cast<std::uint64_t>(event.u.Exception.ExceptionRecord.ExceptionAddress) : 0;
        const wchar_t* trace_name = event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT ? L"CREATE_PROCESS"
            : event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT ? L"EXIT_PROCESS"
            : event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT ? L"CREATE_THREAD"
            : event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT ? L"EXIT_THREAD"
            : event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT ? L"LOAD_DLL"
            : event.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT ? L"UNLOAD_DLL"
            : event.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT ? L"OUTPUT_DEBUG_STRING"
            : event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT ? L"EXCEPTION" : L"DEBUG_EVENT";
        trace_debug_event(trace_name, event, trace_address);
        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            const auto base = reinterpret_cast<std::uint64_t>(event.u.CreateProcessInfo.lpBaseOfImage);
            g_debug_base.store(base); g_debug_thread.store(event.dwThreadId);
            install_requested_breakpoints(process, base);
            install_requested_import_disables(process, base);
            { std::wostringstream text; text << L"CREATE_PROCESS pid=" << event.dwProcessId << L" base=0x" << std::hex << std::uppercase << base; log_debug_event(text.str()); }
            PostMessageW(window, WM_DEBUG_STATUS, 2, 0);
            if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
        } else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            g_debug_thread.store(event.dwThreadId);
            const auto code = event.u.Exception.ExceptionRecord.ExceptionCode;
            const auto exception_address = reinterpret_cast<std::uint64_t>(event.u.Exception.ExceptionRecord.ExceptionAddress);
            if (code == EXCEPTION_BREAKPOINT) {
                RuntimeBreakpoint breakpoint{};
                std::uint64_t runtime = exception_address;
                bool managed = false;
                {
                    std::lock_guard lock(g_breakpoint_mutex);
                    auto hit = g_runtime_breakpoints.find(runtime);
                    // ExceptionAddress normally identifies the INT3 byte.  Keep
                    // the fallback for environments that report the post-INT3 IP.
                    if (hit == g_runtime_breakpoints.end() && exception_address)
                        hit = g_runtime_breakpoints.find(exception_address - 1);
                    if (hit != g_runtime_breakpoints.end()) {
                        runtime = hit->first;
                        breakpoint = hit->second;
                        managed = true;
                    }
                }
                if (managed) {
                    const auto static_address = breakpoint.static_address;
                    const bool temporary_step_over = static_address == 0 && g_step_over_runtime.load() == runtime;
                    write_runtime_byte(process, runtime, breakpoint.original);
                    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
                    if (thread) {
                        CONTEXT context{}; context.ContextFlags = CONTEXT_CONTROL;
                        if (GetThreadContext(thread, &context)) {
                            context.Rip = runtime;
                            context.EFlags &= ~0x100u;
                            SetThreadContext(thread, &context);
                        }
                        CloseHandle(thread);
                    }
                    if (temporary_step_over) {
                        {
                            std::lock_guard lock(g_breakpoint_mutex);
                            g_runtime_breakpoints.erase(runtime);
                        }
                        g_step_over_runtime.store(0);
                        log_debug_event(L"STEP_OVER completed");
                        const auto mode = wait_for_debug_resume(window, runtime, 5);
                        configure_debug_resume(process, event.dwThreadId, runtime, mode, false);
                    } else {
                        std::uint64_t hit_count = 0, hit_limit = 0;
                        bool log_only = false;
                        {
                            std::lock_guard lock(g_breakpoint_mutex);
                            hit_count = ++g_breakpoint_hit_counts[static_address];
                            hit_limit = g_breakpoint_hit_limits.contains(static_address) ? g_breakpoint_hit_limits[static_address] : 0;
                            log_only = g_breakpoint_log_only.contains(static_address);
                        }
                        const bool condition_matches = breakpoint_condition_matches(process, event.dwThreadId, static_address);
                        const bool limit_reached = hit_limit == 0 || hit_count >= hit_limit;
                        std::wostringstream text;
                        text << L"BREAKPOINT 0x" << std::hex << std::uppercase << static_address
                             << L" hit=" << std::dec << hit_count;
                        if (hit_limit) text << L"/" << hit_limit;
                        if (!condition_matches) text << L" condition=false";
                        else if (!limit_reached) text << L" waiting-for-limit";
                        else if (log_only) text << L" log-only";
                        log_debug_event(text.str());
                        const bool should_pause = condition_matches && limit_reached && !log_only;
                        const auto mode = should_pause
                            ? wait_for_debug_resume(window, runtime, 1)
                            : DebugResumeMode::Continue;
                        rearm_runtime = runtime;
                        rearm_thread = event.dwThreadId;
                        configure_debug_resume(process, event.dwThreadId, runtime, mode, true);
                    }
                } else if (!initial_breakpoint_seen) {
                    initial_breakpoint_seen = true;
                    log_debug_event(L"INITIAL_BREAKPOINT");
                } else {
                    log_debug_event(L"BREAK requested by debugger");
                    const auto mode = wait_for_debug_resume(window, exception_address, 1);
                    configure_debug_resume(process, event.dwThreadId, exception_address, mode, false);
                }
            } else if (code == EXCEPTION_SINGLE_STEP && rearm_runtime && event.dwThreadId == rearm_thread) {
                HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
                if (thread) {
                    CONTEXT context{}; context.ContextFlags = CONTEXT_CONTROL;
                    if (GetThreadContext(thread, &context)) { context.EFlags &= ~0x100u; SetThreadContext(thread, &context); }
                    CloseHandle(thread);
                }
                {
                    std::lock_guard lock(g_breakpoint_mutex);
                    const auto it = g_runtime_breakpoints.find(rearm_runtime);
                    if (it != g_runtime_breakpoints.end()) write_runtime_byte(process, rearm_runtime, 0xcc);
                }
                rearm_runtime = 0; rearm_thread = 0;
                if (g_pause_on_next_single_step.exchange(false)) {
                    const auto mode = wait_for_debug_resume(window, exception_address, 5);
                    configure_debug_resume(process, event.dwThreadId, exception_address, mode, false);
                }
            } else if (code == EXCEPTION_SINGLE_STEP) {
                set_thread_trap_flag(event.dwThreadId, false);
                g_pause_on_next_single_step.store(false);
                const auto mode = wait_for_debug_resume(window, exception_address, 5);
                configure_debug_resume(process, event.dwThreadId, exception_address, mode, false);
            } else if (code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP) {
                continue_status = DBG_EXCEPTION_NOT_HANDLED;
            }
        } else if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            { std::wostringstream text; text << L"EXIT_PROCESS code=" << std::dec << event.u.ExitProcess.dwExitCode; log_debug_event(text.str()); }
            PostMessageW(window, WM_DEBUG_STATUS, 3, static_cast<LPARAM>(event.u.ExitProcess.dwExitCode));
        } else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && event.u.LoadDll.hFile) {
            CloseHandle(event.u.LoadDll.hFile);
        }
        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continue_status);
        if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) break;
    }
    restore_import_disables(process);
    CloseHandle(process);
    {
        std::lock_guard lock(g_breakpoint_mutex);
        g_runtime_breakpoints.clear();
    }
    g_step_over_runtime.store(0);
    g_debug_process.store(nullptr);
    g_debug_pid.store(0);
    g_debug_thread.store(0);
    g_debug_base.store(0);
    g_debug_paused.store(false);
    g_debug_pause_address.store(0);
    remove_debug_pid_file();
    g_pause_on_next_single_step.store(false);
    g_stealth_applied.store(false);
    log_debug_event(L"DEBUG_SESSION_STOPPED");
    PostMessageW(window, WM_DEBUG_STATUS, 4, 0);
}

void start_debugger(HWND window) {
    if (!g_database) { MessageBoxW(window, L"Сначала открой исполняемый файл.", L"Debugger", MB_ICONINFORMATION); return; }
    if (g_debug_process.load()) {
        if (request_debug_resume(DebugResumeMode::Continue)) {
            SetWindowTextW(g_status, L"Debug process continued.");
            if (TabCtrl_GetCurSel(g_tabs) == 4) set_editor_text();
        } else
            SetWindowTextW(g_status, L"Debug process is already running.");
        return;
    }
    if (g_debug_starting.exchange(true)) {
        SetWindowTextW(g_status, L"Debug process is already starting...");
        return;
    }
    {
        std::lock_guard lock(g_breakpoint_mutex);
        g_breakpoint_hit_counts.clear();
    }
    const auto executable = g_database->image().path;
    std::thread([window, executable] {
        // WaitForDebugEvent must run in the same thread that created the
        // debuggee with DEBUG_ONLY_THIS_PROCESS.
        std::wstring command_line = L"\"" + executable.wstring() + L"\"";
        STARTUPINFOW startup{sizeof(startup)}; PROCESS_INFORMATION process{};
        if (!CreateProcessW(nullptr, command_line.data(), nullptr, nullptr, FALSE,
                            DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, nullptr,
                            executable.parent_path().c_str(), &startup, &process)) {
            const auto error = GetLastError();
            g_debug_starting.store(false);
            PostMessageW(window, WM_DEBUG_STATUS, 7, static_cast<LPARAM>(error));
            return;
        }
        CloseHandle(process.hThread);
        g_debug_process.store(process.hProcess);
        g_debug_pid.store(process.dwProcessId);
        write_debug_pid_file(process.dwProcessId);
        g_stealth_applied.store(false);
        g_debug_paused.store(false);
        g_debug_pause_address.store(0);
        g_pause_on_next_single_step.store(false);
        g_debug_starting.store(false);
        { std::wostringstream text; text << L"START_DEBUGGER pid=" << process.dwProcessId; log_debug_event(text.str()); }
        PostMessageW(window, WM_DEBUG_STATUS, 8, static_cast<LPARAM>(process.dwProcessId));
        debug_loop(window, process.hProcess, process.dwProcessId);
    }).detach();
    SetWindowTextW(g_status, L"Starting debug process...");
}

void stop_debugger(HWND window) {
    const auto process = g_debug_process.load();
    if (!process) { SetWindowTextW(g_status, L"No debug process."); return; }
    request_debug_resume(DebugResumeMode::Continue);
    TerminateProcess(process, 1);
    SetWindowTextW(g_status, L"Stopping debug process...");
}

void pause_debugger(HWND window) {
    const auto process = g_debug_process.load();
    if (!process) { SetWindowTextW(g_status, L"No debug process to pause."); return; }
    if (g_debug_paused.load()) { SetWindowTextW(g_status, L"Debug process is already paused."); return; }
    if (!DebugBreakProcess(process)) {
        MessageBoxW(window, L"Не удалось приостановить процесс.", L"Debugger", MB_ICONERROR);
        return;
    }
    SetWindowTextW(g_status, L"Pause requested...");
}

bool read_debug_context(CONTEXT& context, HANDLE& thread) {
    const auto thread_id = g_debug_thread.load();
    thread = thread_id ? OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, thread_id) : nullptr;
    if (!thread) return false;
    SuspendThread(thread);
    context = {};
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(thread, &context)) { ResumeThread(thread); CloseHandle(thread); thread = nullptr; return false; }
    return true;
}

void finish_debug_context(HANDLE thread) {
    if (thread) { ResumeThread(thread); CloseHandle(thread); }
}

bool evaluate_watch_expression(HANDLE process, const CONTEXT& context, std::wstring expression,
                               std::uint64_t& result, std::wstring& error) {
    auto trim = [](std::wstring& value) {
        const auto first = value.find_first_not_of(L" \t");
        const auto last = value.find_last_not_of(L" \t");
        value = first == std::wstring::npos ? L"" : value.substr(first, last - first + 1);
    };
    trim(expression);
    int dereferences = 0;
    while (expression.size() >= 2 && expression.front() == L'[' && expression.back() == L']') {
        ++dereferences;
        expression = expression.substr(1, expression.size() - 2);
        trim(expression);
    }
    const auto plus = expression.find(L'+');
    const auto minus = expression.find(L'-', 1);
    const auto separator = plus != std::wstring::npos ? plus : minus;
    std::wstring register_name = separator == std::wstring::npos ? expression : expression.substr(0, separator);
    trim(register_name);
    bool found = false;
    auto value = context_register_value(context, register_name, found);
    if (!found) { error = L"Неизвестный регистр."; return false; }
    if (separator != std::wstring::npos) {
        auto offset_text = expression.substr(separator + 1); trim(offset_text);
        try {
            const auto offset = std::stoull(offset_text, nullptr, 0);
            value = expression[separator] == L'-' ? value - offset : value + offset;
        } catch (...) { error = L"Неверное смещение."; return false; }
    }
    for (int index = 0; index < dereferences; ++index) {
        std::uint64_t memory_value = 0; SIZE_T read = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(value), &memory_value, sizeof(memory_value), &read) || read != sizeof(memory_value)) {
            error = L"Не удалось прочитать память по адресу."; return false;
        }
        value = memory_value;
    }
    result = value;
    return true;
}

void show_watch_locals(HWND window) {
    const auto process = g_debug_process.load();
    CONTEXT context{}; HANDLE thread = nullptr;
    if (!process || !read_debug_context(context, thread)) { MessageBoxW(window, L"Процесс не запущен или поток недоступен.", L"Watch / Locals", MB_ICONINFORMATION); return; }
    std::wostringstream text;
    text << L"Thread: " << std::dec << g_debug_thread.load() << L"\r\n"
         << L"RIP = 0x" << std::hex << std::uppercase << context.Rip << L"\r\n"
         << L"RSP = 0x" << context.Rsp << L"\r\n"
         << L"RBP = 0x" << context.Rbp << L"\r\n"
         << L"RAX = 0x" << context.Rax << L"\r\n"
         << L"RBX = 0x" << context.Rbx << L"\r\n"
         << L"RCX = 0x" << context.Rcx << L"\r\n"
         << L"RDX = 0x" << context.Rdx << L"\r\n"
         << L"RSI = 0x" << context.Rsi << L"\r\n"
         << L"RDI = 0x" << context.Rdi << L"\r\n"
         << L"R8  = 0x" << context.R8  << L"\r\n"
         << L"R9  = 0x" << context.R9  << L"\r\n"
         << L"EFLAGS = 0x" << context.EFlags;
    finish_debug_context(thread);
    const auto expression = prompt_text(window, L"Watch / Locals", L"Add watch expression (empty refreshes existing watches):", L"");
    if (expression && !expression->empty() && std::find(g_watch_expressions.begin(), g_watch_expressions.end(), *expression) == g_watch_expressions.end()) {
        g_watch_expressions.push_back(*expression);
        g_session_dirty = true;
    }
    if (!g_watch_expressions.empty()) text << L"\r\n\r\nWatch expressions\r\n-----------------";
    for (const auto& watch : g_watch_expressions) {
        std::uint64_t value = 0; std::wstring error;
        if (evaluate_watch_expression(process, context, watch, value, error))
            text << L"\r\n" << watch << L" = 0x" << std::hex << std::uppercase << value;
        else
            text << L"\r\n" << watch << L" = <" << error << L">";
    }
    MessageBoxW(window, text.str().c_str(), L"Watch / Locals", MB_ICONINFORMATION);
}

void show_call_stack(HWND window) {
    const auto process = g_debug_process.load();
    CONTEXT context{}; HANDLE thread = nullptr;
    if (!process || !read_debug_context(context, thread)) { MessageBoxW(window, L"Процесс не запущен или поток недоступен.", L"Threads / Call Stack", MB_ICONINFORMATION); return; }
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
    SymInitialize(process, nullptr, TRUE);
    STACKFRAME64 frame{};
    frame.AddrPC.Offset = context.Rip; frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context.Rsp; frame.AddrStack.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context.Rbp; frame.AddrFrame.Mode = AddrModeFlat;
    std::wostringstream text; text << L"Thread " << std::dec << g_debug_thread.load() << L" call stack\r\n\r\n";
    for (int depth = 0; depth < 32; ++depth) {
        const auto address = frame.AddrPC.Offset;
        if (!address) break;
        char symbol_storage[sizeof(SYMBOL_INFO) + MAX_SYM_NAME]{};
        auto* symbol = reinterpret_cast<PSYMBOL_INFO>(symbol_storage); symbol->SizeOfStruct = sizeof(SYMBOL_INFO); symbol->MaxNameLen = MAX_SYM_NAME;
        DWORD64 displacement = 0;
        text << std::dec << depth << L": 0x" << std::hex << std::uppercase << address;
        if (SymFromAddr(process, address, &displacement, symbol)) text << L"  " << wide(symbol->Name);
        text << L"\r\n";
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, thread, &frame, &context, nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) break;
    }
    SymCleanup(process); finish_debug_context(thread);
    MessageBoxW(window, text.str().c_str(), L"Threads / Call Stack", MB_ICONINFORMATION);
}

void step_debugger(HWND window, bool over) {
    if (!g_debug_process.load()) { SetWindowTextW(g_status, L"No debug process to step."); return; }
    if (!g_debug_paused.load()) {
        MessageBoxW(window, L"Сначала останови процесс на breakpoint или выбери Pause.", L"Debugger", MB_ICONINFORMATION);
        return;
    }
    if (request_debug_resume(over ? DebugResumeMode::StepOver : DebugResumeMode::StepInto))
        SetWindowTextW(g_status, over ? L"Step Over requested." : L"Step Into requested.");
}

void show_breakpoint_manager(HWND window) {
    std::lock_guard lock(g_breakpoint_mutex);
    std::wostringstream text; text << L"Software breakpoints: " << g_requested_breakpoints.size() << L"\r\n";
    for (const auto address : g_requested_breakpoints) {
        text << L"  0x" << std::hex << std::uppercase << address;
        const auto condition = g_breakpoint_conditions.find(address);
        if (condition != g_breakpoint_conditions.end() && !condition->second.empty()) text << L"  if " << condition->second;
        const auto hits = g_breakpoint_hit_counts.contains(address) ? g_breakpoint_hit_counts[address] : 0;
        const auto limit = g_breakpoint_hit_limits.contains(address) ? g_breakpoint_hit_limits[address] : 0;
        text << L"  hits=" << std::dec << hits;
        if (limit) text << L"/" << limit;
        if (g_breakpoint_log_only.contains(address)) text << L"  [log only]";
        text << L"\r\n";
    }
    if (g_hardware_breakpoint) text << L"\r\nHardware DR0: 0x" << std::hex << std::uppercase << g_hardware_breakpoint_address << L"\r\n";
    MessageBoxW(window, text.str().c_str(), L"Breakpoint Manager", MB_ICONINFORMATION);
}

void toggle_hardware_breakpoint(HWND window) {
    const auto process = g_debug_process.load(); const auto thread_id = g_debug_thread.load();
    if (!process || !thread_id || !g_database || !g_current_address) { MessageBoxW(window, L"Запусти процесс и выбери адрес инструкции.", L"Hardware Breakpoint", MB_ICONINFORMATION); return; }
    const auto base = g_debug_base.load();
    const auto runtime = base + (g_current_address - g_database->image().image_base);
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, thread_id);
    if (!thread) { MessageBoxW(window, L"Не удалось открыть поток отладки.", L"Hardware Breakpoint", MB_ICONERROR); return; }
    CONTEXT context{}; context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    bool ok = GetThreadContext(thread, &context);
    if (ok) {
        if (!g_hardware_breakpoint) {
            context.Dr0 = runtime; context.Dr7 |= 1ull; context.Dr7 &= ~(0xFull << 16); g_hardware_breakpoint_address = g_current_address; g_hardware_breakpoint = true;
        } else {
            context.Dr0 = 0; context.Dr7 &= ~1ull; g_hardware_breakpoint_address = 0; g_hardware_breakpoint = false;
        }
        ok = SetThreadContext(thread, &context);
    }
    CloseHandle(thread);
    if (ok) g_session_dirty = true;
    SetWindowTextW(g_status, ok ? (g_hardware_breakpoint ? L"Hardware breakpoint enabled." : L"Hardware breakpoint removed.") : L"Unable to update debug registers.");
}

void toggle_breakpoint(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Сначала выбери адрес функции или инструкции.", L"Breakpoint", MB_ICONINFORMATION); return; }
    std::lock_guard lock(g_breakpoint_mutex);
    if (g_requested_breakpoints.contains(g_current_address)) {
        g_requested_breakpoints.erase(g_current_address);
        g_breakpoint_conditions.erase(g_current_address);
        g_breakpoint_hit_counts.erase(g_current_address);
        g_breakpoint_hit_limits.erase(g_current_address);
        g_breakpoint_log_only.erase(g_current_address);
        const auto base = g_debug_base.load(); const auto process = g_debug_process.load();
        if (process && base) {
            const auto runtime = base + (g_current_address - g_database->image().image_base);
            const auto it = g_runtime_breakpoints.find(runtime);
            if (it != g_runtime_breakpoints.end()) { write_runtime_byte(process, runtime, it->second.original); g_runtime_breakpoints.erase(it); }
        }
        SetWindowTextW(g_status, L"Breakpoint removed.");
    } else {
        g_requested_breakpoints.insert(g_current_address);
        const auto process = g_debug_process.load(); const auto base = g_debug_base.load();
        if (process && base) {
            const auto runtime = base + (g_current_address - g_database->image().image_base);
            std::uint8_t original{}; SIZE_T read{};
            if (ReadProcessMemory(process, reinterpret_cast<LPCVOID>(runtime), &original, 1, &read) && read == 1 && write_runtime_byte(process, runtime, 0xcc) && !g_runtime_breakpoints.contains(runtime)) g_runtime_breakpoints[runtime] = {g_current_address, original};
        }
        SetWindowTextW(g_status, L"Breakpoint added.");
    }
    g_session_dirty = true;
}

void remove_breakpoint(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Сначала выбери адрес инструкции.", L"Breakpoint", MB_ICONINFORMATION); return; }
    std::lock_guard lock(g_breakpoint_mutex);
    const auto requested = g_requested_breakpoints.erase(g_current_address);
    g_breakpoint_conditions.erase(g_current_address);
    g_breakpoint_hit_counts.erase(g_current_address);
    g_breakpoint_hit_limits.erase(g_current_address);
    g_breakpoint_log_only.erase(g_current_address);
    const auto base = g_debug_base.load(); const auto process = g_debug_process.load();
    if (process && base) {
        const auto runtime = base + (g_current_address - g_database->image().image_base);
        const auto it = g_runtime_breakpoints.find(runtime);
        if (it != g_runtime_breakpoints.end()) { write_runtime_byte(process, runtime, it->second.original); g_runtime_breakpoints.erase(it); }
    }
    g_session_dirty = true;
    SetWindowTextW(g_status, requested ? L"Breakpoint removed." : L"No breakpoint at current address.");
}

void configure_breakpoint_condition(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Сначала выбери адрес инструкции.", L"Conditional Breakpoint", MB_ICONINFORMATION); return; }
    const auto old = g_breakpoint_conditions.contains(g_current_address) ? g_breakpoint_conditions[g_current_address] : L"rax == 0";
    const auto value = prompt_text(window, L"Conditional Breakpoint", L"Condition (register ==, !=, <, <=, > or >= value):", old);
    if (!value || value->empty()) return;
    if (!g_requested_breakpoints.contains(g_current_address)) toggle_breakpoint(window);
    if (!g_requested_breakpoints.contains(g_current_address)) return;
    { std::lock_guard lock(g_breakpoint_mutex); g_breakpoint_conditions[g_current_address] = *value; }
    g_session_dirty = true;
    SetWindowTextW(g_status, L"Conditional breakpoint configured.");
}

void configure_breakpoint(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Сначала выбери адрес инструкции.", L"Configure Breakpoint", MB_ICONINFORMATION); return; }
    if (!g_requested_breakpoints.contains(g_current_address)) toggle_breakpoint(window);
    if (!g_requested_breakpoints.contains(g_current_address)) return;
    const auto current_limit = g_breakpoint_hit_limits.contains(g_current_address) ? g_breakpoint_hit_limits[g_current_address] : 0;
    const auto limit_text = prompt_text(window, L"Breakpoint Hit Count", L"Stop after N hits (0 = every hit):", std::to_wstring(current_limit));
    if (!limit_text) return;
    std::uint64_t limit = 0;
    try { limit = std::stoull(*limit_text, nullptr, 0); }
    catch (...) { MessageBoxW(window, L"Неверное число срабатываний.", L"Configure Breakpoint", MB_ICONWARNING); return; }
    const auto mode = prompt_text(window, L"Breakpoint Mode", L"Action: Stop or Log", g_breakpoint_log_only.contains(g_current_address) ? L"Log" : L"Stop");
    if (!mode) return;
    auto lowered = *mode;
    for (auto& character : lowered) character = static_cast<wchar_t>(towlower(character));
    {
        std::lock_guard lock(g_breakpoint_mutex);
        g_breakpoint_hit_limits[g_current_address] = limit;
        if (lowered == L"log" || lowered == L"log only") g_breakpoint_log_only.insert(g_current_address);
        else g_breakpoint_log_only.erase(g_current_address);
    }
    g_session_dirty = true;
    SetWindowTextW(g_status, L"Breakpoint hit count and action configured.");
}

LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
    case WM_CREATE: {
        HMENU menu = CreateMenu(), file = CreatePopupMenu();
        AppendMenuW(file, MF_STRING, ID_OPEN, L"Open Binary (PE/ELF/SO)...\tCtrl+O");
        AppendMenuW(file, MF_STRING, ID_SAVE_DB, L"Save Database (.gnd)...\tCtrl+S");
        AppendMenuW(file, MF_STRING, ID_LOAD_DB, L"Load Database (.gnd)...\tCtrl+L");
        AppendMenuW(file, MF_STRING, ID_APPLY_PATCHES, L"Apply Patches to File...\tCtrl+Alt+P");
        AppendMenuW(file, MF_STRING, ID_EXPORT_GRAPH, L"Export Graph to PNG...");
        AppendMenuW(file, MF_STRING, ID_EXPORT_JSON, L"Export Analysis JSON...");
        AppendMenuW(file, MF_STRING, ID_EXPORT_BREAKPOINTS, L"Export Breakpoints CSV...");
        AppendMenuW(file, MF_SEPARATOR, 0, nullptr); AppendMenuW(file, MF_STRING, ID_EXIT, L"Exit");
        HMENU edit = CreatePopupMenu();
        AppendMenuW(edit, MF_STRING, ID_RENAME_LABEL, L"Rename Label\tN"); AppendMenuW(edit, MF_STRING, ID_ADD_COMMENT, L"Add Comment\t;"); AppendMenuW(edit, MF_STRING, ID_ASSIGN_TYPE, L"Assign Type...");
        AppendMenuW(edit, MF_STRING, ID_NOP_BLOCK, L"NOP Current Block\tCtrl+F2"); AppendMenuW(edit, MF_STRING, ID_EDIT_INSTRUCTION, L"Edit Instruction\tCtrl+E");
        AppendMenuW(edit, MF_STRING, ID_UNDO_PATCH, L"Undo Patch\tCtrl+Z"); AppendMenuW(edit, MF_STRING, ID_REDO_PATCH, L"Redo Patch\tCtrl+Y");
        HMENU jump = CreatePopupMenu();
        AppendMenuW(jump, MF_STRING, ID_SEARCH, L"Jump to Address / Label...");
        AppendMenuW(jump, MF_STRING, ID_JUMP_BACK, L"Jump Back");
        AppendMenuW(jump, MF_STRING, ID_TOGGLE_BOOKMARK, L"Toggle Bookmark");
        AppendMenuW(jump, MF_STRING, ID_NEXT_BOOKMARK, L"Next Bookmark");
        AppendMenuW(jump, MF_STRING, ID_LIST_XREFS, L"List XREFs");
        AppendMenuW(jump, MF_STRING, ID_FIND_FUNCTION, L"Find Function...	Ctrl+G");
        AppendMenuW(jump, MF_STRING, ID_CALL_GRAPH, L"Call Graph");
        HMENU tools = CreatePopupMenu();
        AppendMenuW(tools, MF_STRING, ID_DECOMPILE, L"Decompile to Pseudocode\tF5"); AppendMenuW(tools, MF_STRING, ID_SIGMAKER, L"SigMaker: Generate Gandon Signature\tCtrl+B");
        AppendMenuW(tools, MF_STRING, ID_SEARCH_SIGNATURE, L"Search Gandon Signature Pattern...\tCtrl+Shift+F"); AppendMenuW(tools, MF_STRING, ID_CALL_GRAPH, L"Call Graph");
        AppendMenuW(tools, MF_STRING, ID_MEMORY_VIEW, L"Memory View"); AppendMenuW(tools, MF_STRING, ID_MEMORY_SNAPSHOT, L"Memory Snapshot"); AppendMenuW(tools, MF_STRING, ID_MEMORY_COMPARE, L"Compare Memory Snapshot"); AppendMenuW(tools, MF_STRING, ID_WATCH_LOCALS, L"Watch / Locals"); AppendMenuW(tools, MF_STRING, ID_CALL_STACK, L"Threads / Call Stack");
        AppendMenuW(tools, MF_STRING, ID_COMPARE, L"Compare Binary..."); AppendMenuW(tools, MF_STRING, ID_PLUGIN_LOAD, L"Load Python Plugin..."); AppendMenuW(tools, MF_STRING, ID_PY_CONSOLE, L"Python Console"); AppendMenuW(tools, MF_STRING, ID_SEARCH, L"Search Text / Address...\tCtrl+F");
        AppendMenuW(tools, MF_STRING, ID_EXPORT_DEBUG_LOG, L"Export Debug Event Log...");
        AppendMenuW(tools, MF_STRING | MF_UNCHECKED, ID_TRACE_TOGGLE, L"Trace Debug Events");
        AppendMenuW(tools, MF_STRING, ID_EXPORT_TRACE, L"Export Trace...");
        AppendMenuW(tools, MF_STRING, ID_SEARCH_PROCESS_MEMORY, L"Search Process Memory...");
        AppendMenuW(tools, MF_STRING, ID_HIDDEN_SYMBOLS, L"Hidden Symbols...");
        AppendMenuW(tools, MF_STRING, ID_RESTORE_HIDDEN, L"Restore All Hidden Symbols");
        HMENU debugger = CreatePopupMenu();
        AppendMenuW(debugger, MF_STRING, ID_RUN, L"Start / Continue Process\tF9"); AppendMenuW(debugger, MF_STRING, ID_PAUSE, L"Pause Process\tF6"); AppendMenuW(debugger, MF_STRING, ID_STEP_INTO, L"Step Into\tF7"); AppendMenuW(debugger, MF_STRING, ID_STEP_OVER, L"Step Over\tF8");
        AppendMenuW(debugger, MF_STRING | MF_GRAYED, ID_ANTI_DEBUG, L"Anti-Debug injection unavailable");
        AppendMenuW(debugger, MF_STRING, ID_TOGGLE_BP, L"Toggle Breakpoint\tF2"); AppendMenuW(debugger, MF_STRING, ID_COND_BP, L"Set Conditional Breakpoint..."); AppendMenuW(debugger, MF_STRING, ID_CONFIG_BP, L"Configure Breakpoint..."); AppendMenuW(debugger, MF_STRING, ID_BP_MANAGER, L"Breakpoint Manager...");
        AppendMenuW(debugger, MF_STRING, ID_HW_BP, L"Toggle Hardware Breakpoint"); AppendMenuW(debugger, MF_STRING, ID_DELETE_BP, L"Delete Selected Breakpoint\tDel"); AppendMenuW(debugger, MF_STRING, ID_STOP, L"Stop Process");
        HMENU view = CreatePopupMenu();
        AppendMenuW(view, MF_STRING, ID_TOGGLE_GRAPH_LIST, L"Switch Graph / Text Listing	Space");
        AppendMenuW(view, MF_STRING, ID_FIT_GRAPH, L"Fit Graph	Home");
        AppendMenuW(view, MF_STRING | MF_CHECKED, ID_TOGGLE_MINIMAP, L"Graph Minimap");
        AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(view, MF_STRING, ID_VIEW_GRAPH, L"Gandon View-A (Graph)\tSpace"); AppendMenuW(view, MF_STRING, ID_VIEW_LISTING, L"Gandon Text Listing"); AppendMenuW(view, MF_STRING, ID_VIEW_PSEUDO, L"Pseudocode-A (F5)"); AppendMenuW(view, MF_STRING, ID_VIEW_DEBUGGER, L"Debugger Win32"); AppendMenuW(view, MF_STRING, ID_VIEW_HEX, L"Hex View-1");
        AppendMenuW(view, MF_SEPARATOR, 0, nullptr); AppendMenuW(view, MF_STRING, ID_VIEW_TYPES, L"Local Types"); AppendMenuW(view, MF_STRING, ID_VIEW_IMPORTS, L"Imports"); AppendMenuW(view, MF_STRING, ID_VIEW_EXPORTS, L"Exports"); AppendMenuW(view, MF_STRING, ID_VIEW_STRINGS, L"Strings\tShift+F12"); AppendMenuW(view, MF_STRING, ID_VIEW_RESOURCES, L"Resources"); AppendMenuW(view, MF_STRING, ID_VIEW_SYMBOLS, L"Symbols / Debug Info"); AppendMenuW(view, MF_STRING, ID_VIEW_MEMORY, L"Memory Map"); AppendMenuW(view, MF_STRING, ID_VIEW_PROBLEMS, L"Problems / Events");
        HMENU help = CreatePopupMenu(); AppendMenuW(help, MF_STRING, ID_ABOUT, L"About Gandon-PRO...");
        HMENU plugins = CreatePopupMenu();
        AppendMenuW(plugins, MF_STRING, ID_PLUGIN_LOAD, L"Load Python Plugin...");
        AppendMenuW(plugins, MF_STRING, ID_PYTHON_PLUGIN_UNLOAD, L"Unload Python Plugin Actions");
        AppendMenuW(plugins, MF_STRING, ID_PLUGIN_FOLDER, L"Open Plugins Folder");
        AppendMenuW(plugins, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(plugins, MF_STRING, ID_NATIVE_PLUGIN_LOAD, L"Load Native DLL Plugins");
        g_plugins_menu = plugins;
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(file), L"File"); AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(edit), L"Edit"); AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(jump), L"Jump"); AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(tools), L"Tools"); AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(debugger), L"Debugger"); AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(view), L"View"); AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(help), L"Help");
        AppendMenuW(menu, MF_STRING, ID_REFRESH, L"Refresh F5");
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(plugins), L"Plugins");
        SetMenu(window, menu);
        g_tree = CreateWindowExW(WS_EX_CLIENTEDGE, WC_TREEVIEWW, nullptr, WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS, 0, 0, 0, 0, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_TREE)), g_instance, nullptr);
        g_tabs = CreateWindowExW(0, WC_TABCONTROLW, nullptr, WS_CHILD | WS_VISIBLE | TCS_TABS | TCS_OWNERDRAWFIXED, 0, 0, 0, 0, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_TABS)), g_instance, nullptr);
        const wchar_t* labels[] = {L"Gandon View-A", L"Gandon Text Listing", L"Pseudocode-A", L"XREFs", L"Debugger Win32", L"Hex View-1", L"Local Types", L"Imports", L"Exports", L"Strings", L"Resources", L"Symbols / Debug Info", L"Memory Map", L"Problems / Events"};
        for (const auto* label : labels) { TCITEMW item{TCIF_TEXT, 0, 0, const_cast<wchar_t*>(label), 0, 0, 0}; TabCtrl_InsertItem(g_tabs, TabCtrl_GetItemCount(g_tabs), &item); }
        g_view = CreateWindowExW(WS_EX_CLIENTEDGE | WS_EX_COMPOSITED, L"GandonGraphView", nullptr, WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL, 0, 0, 0, 0, window, nullptr, g_instance, nullptr);
        g_minimap = CreateWindowExW(WS_EX_CLIENTEDGE, L"GandonMiniMap", nullptr, WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, 0, 0, 0, 0, window, nullptr, g_instance, nullptr);
        g_editor = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"Open EXE file from File -> Open EXE file...", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 0, 0, 0, 0, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_EDITOR)), g_instance, nullptr);
        SendMessageW(g_tree, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        SendMessageW(g_tabs, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        SendMessageW(g_editor, WM_SETFONT, reinterpret_cast<WPARAM>(g_code_font), TRUE);
        g_status = CreateWindowExW(0, STATUSCLASSNAMEW, L"Ready", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_STATUS)), g_instance, nullptr);
        SendMessageW(g_status, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        TabCtrl_SetCurSel(g_tabs, 0);
        set_editor_text();
        SetTimer(window, ID_SESSION_TIMER, 3000, nullptr);
        return 0;
    }
    case WM_SIZE: {
        RECT client{}; GetClientRect(window, &client); SendMessageW(g_status, WM_SIZE, 0, 0); RECT status_rect{}; GetWindowRect(g_status, &status_rect); const int status_height = status_rect.bottom - status_rect.top; const int width = client.right, height = client.bottom - status_height, left = 290;
        const bool dock_minimap = g_minimap_visible && TabCtrl_GetCurSel(g_tabs) == 0;
        const int minimap_width = dock_minimap ? 230 : 0;
        const int view_width = (std::max)(120, width - left - 18 - minimap_width);
        MoveWindow(g_tree, 6, 6, left - 12, height - 12, TRUE);
        MoveWindow(g_tabs, left, 6, width - left - 6, 30, TRUE);
        MoveWindow(g_view, left + 6, 38, view_width, height - 48, TRUE);
        MoveWindow(g_editor, left + 6, 38, width - left - 18, height - 48, TRUE);
        MoveWindow(g_minimap, left + 12 + view_width, 38, minimap_width - 8, height - 48, TRUE);
        ShowWindow(g_minimap, dock_minimap ? SW_SHOW : SW_HIDE);
        update_graph_scrollbars(g_view); InvalidateRect(g_minimap, nullptr, TRUE); return 0;
    }
    case WM_TIMER:
        if (wparam == ID_SESSION_TIMER) save_session_backup();
        return 0;
    case WM_COMMAND: {
        const auto id = LOWORD(wparam);
        // Menu commands can be invoked while the read-only listing editor has
        // focus.  Keep the selected line as the command target instead of
        // silently reusing the previously selected address.
        if (GetFocus() == g_editor) sync_current_address_from_editor();
        if (invoke_native_plugin_action(window, id)) return 0;
        if (invoke_python_plugin_action(window, id)) return 0;
        if (id == ID_OPEN) open_binary(window);
        else if (id == ID_SAVE_DB) save_database(window);
        else if (id == ID_LOAD_DB) load_database(window);
        else if (id == ID_REFRESH) refresh_views(window);
        else if (id == ID_APPLY_PATCHES) apply_patches_to_file(window);
        else if (id == ID_NOP_BLOCK) nop_current_function(window);
        else if (id == ID_EDIT_INSTRUCTION) edit_instruction(window);
        else if (id == ID_UNDO_PATCH) undo_patch(window);
        else if (id == ID_REDO_PATCH) redo_patch(window);
        else if (id == ID_EXPORT_GRAPH) export_graph_png(window);
        else if (id == ID_EXPORT_JSON) export_analysis_json(window);
        else if (id == ID_EXPORT_BREAKPOINTS) export_breakpoints_csv(window);
        else if (id == ID_EXPORT_DEBUG_LOG) export_debug_log(window);
        else if (id == ID_COLOR_DEFAULT) set_color_tag(window, RGB(32, 39, 47), true);
        else if (id == ID_COLOR_GREEN) set_color_tag(window, RGB(35, 83, 64), false);
        else if (id == ID_COLOR_RED) set_color_tag(window, RGB(94, 45, 50), false);
        else if (id == ID_COLOR_BLUE) set_color_tag(window, RGB(37, 62, 91), false);
        else if (id == ID_SEARCH) search_binary(window);
        else if (id == ID_JUMP_BACK) jump_back(window);
        else if (id == ID_TOGGLE_BOOKMARK) toggle_bookmark(window);
        else if (id == ID_NEXT_BOOKMARK) next_bookmark(window);
        else if (id == ID_LIST_XREFS) list_xrefs(window);
        else if (id == ID_FIND_FUNCTION) find_function(window);
        else if (id == ID_SEARCH_PROCESS_MEMORY) search_process_memory(window);
        else if (id == ID_PY_CONSOLE) python_console(window);
        else if (id == ID_RENAME_LABEL) rename_current_label(window);
        else if (id == ID_ADD_COMMENT) add_current_comment(window);
        else if (id == ID_ASSIGN_TYPE) assign_current_type(window);
        else if (id == ID_CONTEXT_FOLLOW) { if (g_database && g_current_address) navigate_to_address(window, g_current_address, 1); }
        else if (id == ID_CONTEXT_COPY) SendMessageW(g_editor, WM_COPY, 0, 0);
        else if (id == ID_CALL_GRAPH) { if (g_database) { g_listing = call_graph_text(*g_database, g_current_address); select_view(window, 1); } }
        else if (id == ID_MEMORY_VIEW) show_memory_view(window);
        else if (id == ID_MEMORY_SNAPSHOT) capture_memory_snapshot(window);
        else if (id == ID_MEMORY_COMPARE) compare_memory_snapshot(window);
        else if (id == ID_COMPARE) compare_binary(window);
        else if (id == ID_ABOUT) MessageBoxW(window, L"Gandon-PRO Native\r\nCapstone x86/x64 analysis\r\nPython plugin bridge", L"About Gandon-PRO", MB_ICONINFORMATION);
        else if (id == ID_RUN) start_debugger(window);
        else if (id == ID_PAUSE) pause_debugger(window);
        else if (id == ID_ANTI_DEBUG) MessageBoxW(window, L"Anti-debug injection is not included in the native build. The debugger and safe Python plugin bridge remain available.", L"Debugger", MB_ICONINFORMATION);
        else if (id == ID_STOP) stop_debugger(window);
        else if (id == ID_TOGGLE_BP) {
            if (GetFocus() == g_tree) {
                if (const auto record = selected_tree_import()) toggle_import_disable(window, record->iat_va);
                else toggle_breakpoint(window);
            } else toggle_breakpoint(window);
        }
        else if (id == ID_DELETE_BP) remove_breakpoint(window);
        else if (id == ID_SIGMAKER) generate_signature(window);
        else if (id == ID_SEARCH_SIGNATURE) search_signature(window);
        else if (id == ID_PLUGIN_LOAD) load_python_plugin(window);
        else if (id == ID_PYTHON_PLUGIN_UNLOAD) unload_python_plugins(window);
        else if (id == ID_PLUGIN_FOLDER) open_python_plugins_folder();
        else if (id == ID_NATIVE_PLUGIN_LOAD) load_native_plugins(window);
        else if (id == ID_TRACE_TOGGLE) toggle_debug_trace(window);
        else if (id == ID_EXPORT_TRACE) export_debug_trace(window);
        else if (id == ID_HIDDEN_SYMBOLS) show_hidden_symbols(window);
        else if (id == ID_RESTORE_HIDDEN) restore_all_hidden_symbols(window);
        else if (id == ID_HIDE_FUNCTION) hide_current_function(window);
        else if (id == ID_HIDE_IMPORT) {
            if (const auto record = selected_tree_import()) hide_selected_import(window, record->iat_va);
        }
        else if (id == ID_CONTEXT_FOLLOW_TARGET) { if (g_database) { const auto target = editor_line_target_address(g_editor); if (target) navigate_to_address(window, *target, 1); } }
        else if (id == ID_EXIT) SendMessageW(window, WM_CLOSE, 0, 0);
        else if (id == ID_VIEW_GRAPH) select_view(window, 0);
        else if (id == ID_VIEW_LISTING) select_view(window, 1);
        else if (id == ID_VIEW_PSEUDO) select_view(window, 2);
        else if (id == ID_VIEW_DEBUGGER) select_view(window, 4);
        else if (id == ID_VIEW_HEX) select_view(window, 5);
        else if (id == ID_VIEW_TYPES) select_view(window, 6);
        else if (id == ID_VIEW_IMPORTS) select_view(window, 7);
        else if (id == ID_VIEW_EXPORTS) select_view(window, 8);
        else if (id == ID_VIEW_STRINGS) select_view(window, 9);
        else if (id == ID_VIEW_RESOURCES) select_view(window, 10);
        else if (id == ID_VIEW_SYMBOLS) select_view(window, 11);
        else if (id == ID_VIEW_MEMORY) select_view(window, 12);
        else if (id == ID_VIEW_PROBLEMS) select_view(window, 13);
        else if (id == ID_TOGGLE_GRAPH_LIST) toggle_graph_listing(window);
        else if (id == ID_FIT_GRAPH) fit_graph(window);
        else if (id == ID_TOGGLE_MINIMAP) toggle_minimap(window);
        else if (id == ID_DECOMPILE) { if (g_database) g_pseudocode = pseudocode_text_at(*g_database, g_current_address ? g_current_address : g_database->image().entry_point); select_view(window, 2); }
        else if (id == ID_STEP_INTO) step_debugger(window, false);
        else if (id == ID_STEP_OVER) step_debugger(window, true);
        else if (id == ID_BP_MANAGER) show_breakpoint_manager(window);
        else if (id == ID_HW_BP) toggle_hardware_breakpoint(window);
        else if (id == ID_WATCH_LOCALS) show_watch_locals(window);
        else if (id == ID_CALL_STACK) show_call_stack(window);
        else if (id == ID_COND_BP) configure_breakpoint_condition(window);
        else if (id == ID_CONFIG_BP) configure_breakpoint(window);
        return 0;
    }
    case WM_CONTEXTMENU: {
        if (reinterpret_cast<HWND>(wparam) == g_tree) {
            POINT screen_point{static_cast<int>(static_cast<short>(LOWORD(lparam))), static_cast<int>(static_cast<short>(HIWORD(lparam)))};
            if (screen_point.x == -1 && screen_point.y == -1) GetCursorPos(&screen_point);
            POINT tree_point = screen_point;
            ScreenToClient(g_tree, &tree_point);
            TVHITTESTINFO hit{};
            hit.pt = tree_point;
            if (const auto item = TreeView_HitTest(g_tree, &hit)) TreeView_SelectItem(g_tree, item);
            HMENU context = CreatePopupMenu();
            if (const auto record = selected_tree_import()) {
                const auto disabled = g_requested_disabled_imports.contains(import_key(record->dll, record->name));
                AppendMenuW(context, MF_STRING, ID_TOGGLE_BP, disabled ? L"Enable Import at Runtime (F2)" : L"Disable Import at Runtime (F2)");
                AppendMenuW(context, MF_STRING, ID_HIDE_IMPORT, L"Hide Import from Analysis");
            } else {
                AppendMenuW(context, MF_STRING, ID_HIDDEN_SYMBOLS, L"Hidden Symbols...");
            }
            TrackPopupMenu(context, TPM_RIGHTBUTTON, screen_point.x, screen_point.y, 0, window, nullptr);
            DestroyMenu(context);
            return 0;
        }
        if (reinterpret_cast<HWND>(wparam) != g_editor) break;
        const auto address = editor_line_address(g_editor); if (address) { g_current_address = *address; SetWindowTextW(g_status, (L"Selected instruction: 0x" + [&] { std::wostringstream value; value << std::hex << std::uppercase << *address; return value.str(); }()).c_str()); }
        HMENU context = CreatePopupMenu();
        AppendMenuW(context, MF_STRING, ID_CONTEXT_COPY, L"Copy");
        if (address) {
            AppendMenuW(context, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(context, MF_STRING, ID_CONTEXT_FOLLOW, L"Follow Address");
            if (TabCtrl_GetCurSel(g_tabs) == 3 && editor_line_target_address(g_editor)) AppendMenuW(context, MF_STRING, ID_CONTEXT_FOLLOW_TARGET, L"Follow XREF Target");
            AppendMenuW(context, MF_STRING, ID_EDIT_INSTRUCTION, L"Patch Instruction...");
            AppendMenuW(context, MF_STRING, ID_NOP_BLOCK, L"Patch Function (NOP)");
            AppendMenuW(context, MF_STRING, ID_RENAME_LABEL, L"Rename Label");
            AppendMenuW(context, MF_STRING, ID_ADD_COMMENT, L"Add Comment");
            AppendMenuW(context, MF_STRING, ID_ASSIGN_TYPE, L"Assign Type...");
            AppendMenuW(context, MF_STRING, ID_HIDE_FUNCTION, L"Hide Function from Analysis");
            HMENU colors = CreatePopupMenu();
            AppendMenuW(colors, MF_STRING, ID_COLOR_DEFAULT, L"Default Dark");
            AppendMenuW(colors, MF_STRING, ID_COLOR_GREEN, L"Success / True (Green)");
            AppendMenuW(colors, MF_STRING, ID_COLOR_RED, L"Failure / Detection (Red)");
            AppendMenuW(colors, MF_STRING, ID_COLOR_BLUE, L"Info (Blue)");
            AppendMenuW(context, MF_POPUP, reinterpret_cast<UINT_PTR>(colors), L"Set Color Tag");
        }
        POINT point{static_cast<int>(static_cast<short>(LOWORD(lparam))), static_cast<int>(static_cast<short>(HIWORD(lparam)))}; if (point.x == -1 && point.y == -1) GetCursorPos(&point);
        TrackPopupMenu(context, TPM_RIGHTBUTTON, point.x, point.y, 0, window, nullptr); DestroyMenu(context); return 0;
    }
    case WM_DEBUG_STATUS:
        if (wparam == 1) {
            wchar_t text[96]{}; swprintf_s(text, L"Breakpoint / single-step at 0x%llX", static_cast<unsigned long long>(lparam)); SetWindowTextW(g_status, text);
        } else if (wparam == 2) { SetWindowTextW(g_status, L"Debug process initialized."); if (g_database) { g_memory_map = memory_map_text(*g_database); if (TabCtrl_GetCurSel(g_tabs) == 12) set_editor_text(); } }
        else if (wparam == 3) { wchar_t text[64]{}; swprintf_s(text, L"Debug process exited: %llu", static_cast<unsigned long long>(lparam)); SetWindowTextW(g_status, text); }
        else if (wparam == 4) { SetWindowTextW(g_status, L"Debug process stopped."); if (g_database) { g_memory_map = memory_map_text(*g_database); if (TabCtrl_GetCurSel(g_tabs) == 12) set_editor_text(); } }
        else if (wparam == 5) { wchar_t text[96]{}; swprintf_s(text, L"Single-step at 0x%llX", static_cast<unsigned long long>(lparam)); SetWindowTextW(g_status, text); }
        else if (wparam == 6) { SetWindowTextW(g_status, g_stealth_applied.load() ? L"Anti-debug bypass applied." : L"Anti-debug bypass was not applied."); }
        else if (wparam == 7) {
            wchar_t system_message[512]{};
            FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                           static_cast<DWORD>(lparam), 0, system_message,
                           static_cast<DWORD>(std::size(system_message)), nullptr);
            std::wostringstream text;
            text << L"Could not start debug process (Win32 error " << std::dec << lparam << L").";
            SetWindowTextW(g_status, text.str().c_str());
            std::wstring details = text.str();
            if (*system_message) details += L"\r\n\r\n" + std::wstring(system_message);
            MessageBoxW(window, details.c_str(), L"Debugger", MB_ICONERROR);
        }
        else if (wparam == 8) {
            wchar_t text[96]{}; swprintf_s(text, L"Debug process started. PID %llu", static_cast<unsigned long long>(lparam));
            SetWindowTextW(g_status, text);
        }
        if (TabCtrl_GetCurSel(g_tabs) == 4) set_editor_text();
        return 0;
    case WM_KEYDOWN:
        if (wparam == VK_SPACE) { toggle_graph_listing(window); return 0; }
        if (wparam == VK_HOME && TabCtrl_GetCurSel(g_tabs) == 0) { fit_graph(window); return 0; }
        if (wparam == VK_F5) { refresh_views(window); return 0; }
        if (wparam == VK_F6) { pause_debugger(window); return 0; }
        if (wparam == VK_F2) { toggle_breakpoint(window); return 0; }
        if (wparam == VK_F9) { start_debugger(window); return 0; }
        if (wparam == VK_F7) { step_debugger(window, false); return 0; }
        if (wparam == VK_F8) { step_debugger(window, true); return 0; }
        if (GetKeyState(VK_CONTROL) & 0x8000) {
            if (wparam == 'F') { search_binary(window); return 0; }
            if (wparam == 'G') { find_function(window); return 0; }
            if (wparam == 'E') { edit_instruction(window); return 0; }
            if (wparam == 'Z') { undo_patch(window); return 0; }
            if (wparam == 'Y') { redo_patch(window); return 0; }
            if ((GetKeyState(VK_MENU) & 0x8000) && wparam == 'P') { apply_patches_to_file(window); return 0; }
        }
        break;
    case WM_DRAWITEM: {
        auto* draw = reinterpret_cast<LPDRAWITEMSTRUCT>(lparam);
        if (draw && draw->CtlType == ODT_TAB && draw->CtlID == ID_TABS) {
            wchar_t label[128]{};
            TCITEMW item{}; item.mask = TCIF_TEXT; item.pszText = label; item.cchTextMax = 128;
            TabCtrl_GetItem(g_tabs, draw->itemID, &item);
            const bool active = draw->itemID == static_cast<UINT>(TabCtrl_GetCurSel(g_tabs));
            HBRUSH fill = CreateSolidBrush(active ? RGB(30, 34, 40) : RGB(24, 27, 32));
            FillRect(draw->hDC, &draw->rcItem, fill); DeleteObject(fill);
            if (active) {
                RECT underline = draw->rcItem; underline.top = underline.bottom - 2;
                HBRUSH accent = CreateSolidBrush(RGB(0, 122, 204)); FillRect(draw->hDC, &underline, accent); DeleteObject(accent);
            }
            SetBkMode(draw->hDC, TRANSPARENT); SetTextColor(draw->hDC, active ? RGB(225, 235, 242) : RGB(155, 170, 184));
            HFONT old_font = reinterpret_cast<HFONT>(SelectObject(draw->hDC, g_ui_font));
            RECT text = draw->rcItem; text.left += 9; DrawTextW(draw->hDC, label, -1, &text, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX);
            SelectObject(draw->hDC, old_font);
            return TRUE;
        }
        break;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: { auto dc = reinterpret_cast<HDC>(wparam); SetTextColor(dc, RGB(215, 228, 238)); SetBkColor(dc, RGB(24, 27, 32)); return reinterpret_cast<LRESULT>(g_panel); }
    case WM_NOTIFY: {
        auto* header = reinterpret_cast<LPNMHDR>(lparam);
        if (header->idFrom == ID_TREE && header->code == TVN_KEYDOWN) {
            const auto* key = reinterpret_cast<const NMTVKEYDOWN*>(lparam);
            if (key->wVKey == VK_F2) {
                if (const auto record = selected_tree_import()) toggle_import_disable(window, record->iat_va);
                return 0;
            }
        }
        if (header->idFrom == ID_TABS && header->code == TCN_SELCHANGE) {
            const int tab = TabCtrl_GetCurSel(g_tabs);
            if (tab == 0) rebuild_graph_model();
            set_editor_text();
            update_graph_scrollbars(g_view);
            invalidate_minimap();
        }
        if (header->idFrom == ID_TREE && header->code == TVN_SELCHANGEDW && g_database) {
            const auto* change = reinterpret_cast<const NMTREEVIEWW*>(lparam);
            const auto address = static_cast<std::uint64_t>(change->itemNew.lParam);
            if (address != 0) {
                if (g_string_addresses.contains(address)) {
                    navigate_to_address(window, address, 5);
                } else {
                    // Keep View-A active while browsing the Functions tree.  The
                    // old double-click-only handler always forced Text Listing,
                    // leaving the graph on the previously selected function.
                    const int current_tab = TabCtrl_GetCurSel(g_tabs);
                    const int target_tab = current_tab == 0 ? 0 : (current_tab == 2 ? 2 : 1);
                    navigate_to_address(window, address, target_tab);
                }
                std::wostringstream status;
                status << L"Selected: 0x" << std::hex << std::uppercase << address;
                const auto status_text = status.str();
                SendMessageW(g_status, SB_SETTEXTW, 0, reinterpret_cast<LPARAM>(status_text.c_str()));
            }
        }
        if (header->idFrom == ID_TREE && header->code == NM_CUSTOMDRAW) {
            auto* draw = reinterpret_cast<LPNMTVCUSTOMDRAW>(lparam);
            if (draw->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (draw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) { draw->clrText = RGB(215, 228, 238); draw->clrTextBk = RGB(30, 34, 40); return CDRF_DODEFAULT; }
        }
        if (header->idFrom == ID_TABS && header->code == NM_CUSTOMDRAW) {
            auto* draw = reinterpret_cast<LPNMCUSTOMDRAW>(lparam);
            if (draw->dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (draw->dwDrawStage == CDDS_ITEMPREPAINT) { SetTextColor(draw->hdc, RGB(215, 228, 238)); SetBkColor(draw->hdc, RGB(30, 34, 40)); return CDRF_DODEFAULT; }
        }
        return 0;
    }
    case WM_LBUTTONDOWN: {
        if (TabCtrl_GetCurSel(g_tabs) == 0 && g_database) {
            const int mouse_x = static_cast<int>(static_cast<short>(LOWORD(lparam)));
            const int mouse_y = static_cast<int>(static_cast<short>(HIWORD(lparam)));
            const int left = 300, box_width = 300, box_height = 82, gap = 55;
            const int column = (mouse_x - (left + 24)) / (box_width + gap);
            const int row = (mouse_y - 72) / (box_height + 40);
            if (column >= 0 && column < 3 && row >= 0) {
                const auto index = static_cast<std::size_t>(row * 3 + column);
                if (index < g_database->functions().size()) {
                    navigate_to_address(window, g_database->functions()[index].start, 1);
                }
            }
        }
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT paint{};
        HDC dc = BeginPaint(window, &paint);
        RECT client{}; GetClientRect(window, &client); RECT canvas{300, 38, client.right, client.bottom - 24}; FillRect(dc, &canvas, g_background);
        // View-A is a real child canvas (g_view/graph_proc).  Do not paint the
        // old function-card preview underneath it: the two renderers used to
        // compete for the same tab and made the UI look like a stale preview.
        if (TabCtrl_GetCurSel(g_tabs) == 0) {
            EndPaint(window, &paint);
            return 0;
        }
        if (TabCtrl_GetCurSel(g_tabs) == 0) {
            HGDIOBJ old_font = SelectObject(dc, g_code_font);
            SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(170, 239, 207));
            const int left = 300;
            if (!g_database) {
                TextOutW(dc, left + 24, 72, L"Gandon View-A", 13);
                TextOutW(dc, left + 24, 102, L"Open EXE file to build the control-flow graph.", 46);
            } else {
                const int box_width = 300, box_height = 82, gap = 55;
                const auto count = (std::min<std::size_t>)(g_database->functions().size(), 12);
                for (std::size_t i = 0; i < count; ++i) {
                    const int col = static_cast<int>(i % 3), row = static_cast<int>(i / 3);
                    const int x = left + 24 + col * (box_width + gap), y = 72 + row * (box_height + 40);
                    RECT box{x, y, x + box_width, y + box_height};
                    HBRUSH fill = CreateSolidBrush(RGB(32, 39, 47)); FillRect(dc, &box, fill); DeleteObject(fill);
                    HPEN pen = CreatePen(PS_SOLID, 1, RGB(62, 78, 91)); HGDIOBJ old_pen = SelectObject(dc, pen); HGDIOBJ old_brush = SelectObject(dc, GetStockObject(NULL_BRUSH)); Rectangle(dc, box.left, box.top, box.right, box.bottom); SelectObject(dc, old_brush); SelectObject(dc, old_pen); DeleteObject(pen);
                    const auto& function = g_database->functions()[i]; auto name = g_custom_labels.contains(function.start) ? g_custom_labels[function.start] : wide(function.name); TextOutW(dc, x + 12, y + 12, name.c_str(), static_cast<int>(name.size()));
                    wchar_t address[40]{}; swprintf_s(address, L"0x%llX", static_cast<unsigned long long>(function.start)); SetTextColor(dc, RGB(125, 191, 231)); TextOutW(dc, x + 12, y + 40, address, static_cast<int>(wcslen(address))); SetTextColor(dc, RGB(170, 239, 207));
                }
                // Draw only relationships discovered by the analyzer. The old preview
                // connected every neighboring card, which made View-A look populated but
                // unrelated to the actual binary.
                auto visible_function = [&](std::uint64_t address) -> int {
                    for (std::size_t n = 0; n < count; ++n)
                        if (g_database->functions()[n].start == address) return static_cast<int>(n);
                    return -1;
                };
                for (const auto& xref : g_database->xrefs()) {
                    int source = -1, target = visible_function(xref.to);
                    for (std::size_t n = 0; n < count; ++n) {
                        const auto start = g_database->functions()[n].start;
                        const auto next = n + 1 < g_database->functions().size() ? g_database->functions()[n + 1].start : UINT64_MAX;
                        if (xref.from >= start && xref.from < next) { source = static_cast<int>(n); break; }
                    }
                    if (source < 0 || target < 0 || source == target) continue;
                    const int sx = left + 24 + (source % 3) * (box_width + gap) + box_width;
                    const int sy = 72 + (source / 3) * (box_height + 40) + box_height / 2;
                    const int tx = left + 24 + (target % 3) * (box_width + gap);
                    const int ty = 72 + (target / 3) * (box_height + 40) + box_height / 2;
                    HPEN edge = CreatePen(PS_SOLID, 2, xref.kind == "call" ? RGB(54, 157, 220) : RGB(231, 76, 60));
                    HGDIOBJ old_edge = SelectObject(dc, edge);
                    MoveToEx(dc, sx, sy, nullptr);
                    if (sy == ty) {
                        LineTo(dc, tx, ty);
                    } else {
                        const int bend = (sx + tx) / 2;
                        LineTo(dc, bend, sy); LineTo(dc, bend, ty); LineTo(dc, tx, ty);
                    }
                    const int direction = tx >= sx ? 1 : -1;
                    MoveToEx(dc, tx, ty, nullptr); LineTo(dc, tx - direction * 9, ty - 5); MoveToEx(dc, tx, ty, nullptr); LineTo(dc, tx - direction * 9, ty + 5);
                    SelectObject(dc, old_edge); DeleteObject(edge);
                }
                // Restore node surfaces after drawing edges so connectors stay behind
                // the blocks, as they do in an interactive graph view.
                for (std::size_t i = 0; i < count; ++i) {
                    const int col = static_cast<int>(i % 3), row = static_cast<int>(i / 3);
                    const int x = left + 24 + col * (box_width + gap), y = 72 + row * (box_height + 40);
                    RECT box{x, y, x + box_width, y + box_height};
                    HBRUSH fill = CreateSolidBrush(RGB(32, 39, 47)); FillRect(dc, &box, fill); DeleteObject(fill);
                    HPEN pen = CreatePen(PS_SOLID, 1, RGB(62, 78, 91)); HGDIOBJ old_pen = SelectObject(dc, pen); HGDIOBJ old_brush = SelectObject(dc, GetStockObject(NULL_BRUSH)); Rectangle(dc, box.left, box.top, box.right, box.bottom); SelectObject(dc, old_brush); SelectObject(dc, old_pen); DeleteObject(pen);
                    const auto& function = g_database->functions()[i];
                    auto name = g_custom_labels.contains(function.start) ? g_custom_labels[function.start] : wide(function.name); SetTextColor(dc, RGB(170, 239, 207)); TextOutW(dc, x + 12, y + 12, name.c_str(), static_cast<int>(name.size()));
                    wchar_t address[40]{}; swprintf_s(address, L"0x%llX", static_cast<unsigned long long>(function.start)); SetTextColor(dc, RGB(125, 191, 231)); TextOutW(dc, x + 12, y + 40, address, static_cast<int>(wcslen(address)));
                    if (g_custom_comments.contains(function.start) && !g_custom_comments[function.start].empty()) { SetTextColor(dc, RGB(180, 180, 180)); TextOutW(dc, x + 12, y + 62, g_custom_comments[function.start].c_str(), static_cast<int>(g_custom_comments[function.start].size())); }
                }
                RECT mini{client.right - 225, client.bottom - 185, client.right - 24, client.bottom - 24};
                HBRUSH mini_fill = CreateSolidBrush(RGB(18, 29, 38)); FillRect(dc, &mini, mini_fill); DeleteObject(mini_fill);
                HPEN mini_pen = CreatePen(PS_SOLID, 1, RGB(62, 78, 91)); HGDIOBJ old_mini_pen = SelectObject(dc, mini_pen); HGDIOBJ old_mini_brush = SelectObject(dc, GetStockObject(NULL_BRUSH)); Rectangle(dc, mini.left, mini.top, mini.right, mini.bottom); SelectObject(dc, old_mini_brush); SelectObject(dc, old_mini_pen); DeleteObject(mini_pen);
                for (std::size_t i = 0; i < count; ++i) {
                    const int mx = mini.left + 10 + static_cast<int>((i % 3) * 58);
                    const int my = mini.top + 10 + static_cast<int>((i / 3) * 24);
                    RECT dot{mx, my, mx + 40, my + 11};
                    HBRUSH dot_fill = CreateSolidBrush(i == 0 ? RGB(43, 104, 139) : RGB(48, 48, 52)); FillRect(dc, &dot, dot_fill); DeleteObject(dot_fill);
                }
            }
            SelectObject(dc, old_font);
        }
        EndPaint(window, &paint); return 0;
    }
    case WM_ERASEBKGND: { RECT rect{}; GetClientRect(window, &rect); FillRect(reinterpret_cast<HDC>(wparam), &rect, g_background); return 1; }
    case WM_CLOSE: {
        if (g_debug_process.load()) stop_debugger(window);
        if (g_database && g_session_dirty) {
            const auto choice = MessageBoxW(window, L"Сохранить рабочую сессию перед выходом?\r\nДа — сохранить .gnd и удалить backup.\r\nНет — удалить backup без сохранения.", L"Gandon-PRO", MB_YESNOCANCEL | MB_ICONQUESTION);
            if (choice == IDCANCEL) return 0;
            if (choice == IDYES) {
                std::string error;
                if (g_session_path.empty() || !write_database_file(g_session_path, error)) {
                    MessageBoxW(window, wide(error.empty() ? "Could not save the current session." : error).c_str(), L"Save Database", MB_ICONERROR);
                    return 0;
                }
                std::error_code ignored;
                std::filesystem::remove(g_session_path.wstring() + L".bak", ignored);
                g_session_dirty = false;
            }
            else { std::error_code ignored; if (!g_session_path.empty()) std::filesystem::remove(g_session_path.wstring() + L".bak", ignored); g_session_dirty = false; }
        } else if (!g_session_path.empty()) { std::error_code ignored; std::filesystem::remove(g_session_path.wstring() + L".bak", ignored); }
        if (g_native_plugin_host) g_native_plugin_host->unload_all();
        g_native_plugin_actions.clear();
        DestroyWindow(window); return 0;
    }
    case WM_DESTROY: KillTimer(window, ID_SESSION_TIMER); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR command_line, int show_command) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    g_instance = instance; INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_TREEVIEW_CLASSES | ICC_TAB_CLASSES | ICC_BAR_CLASSES}; InitCommonControlsEx(&controls);
    g_background = CreateSolidBrush(RGB(30, 34, 40)); g_panel = CreateSolidBrush(RGB(24, 27, 32));
    g_ui_font = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    const auto plugin_font = python_plugin_font();
    const wchar_t* code_font_name = plugin_font.empty() ? L"Cascadia Mono" : plugin_font.c_str();
    g_code_font = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_DONTCARE, code_font_name);
    g_code_font_owned = true;
    const wchar_t class_name[] = L"GandonProNativeWindow"; WNDCLASSW window_class{}; window_class.hInstance = instance; window_class.lpfnWndProc = window_proc; window_class.lpszClassName = class_name; window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW); window_class.hbrBackground = g_background; RegisterClassW(&window_class);
    WNDCLASSW graph_class{}; graph_class.hInstance = instance; graph_class.lpfnWndProc = graph_proc; graph_class.lpszClassName = L"GandonGraphView"; graph_class.hCursor = LoadCursorW(nullptr, IDC_ARROW); graph_class.hbrBackground = g_panel; RegisterClassW(&graph_class);
    WNDCLASSW minimap_class{}; minimap_class.hInstance = instance; minimap_class.lpfnWndProc = minimap_proc; minimap_class.lpszClassName = L"GandonMiniMap"; minimap_class.hCursor = LoadCursorW(nullptr, IDC_CROSS); minimap_class.hbrBackground = g_panel; RegisterClassW(&minimap_class);
    HWND window = CreateWindowExW(0, class_name, L"Gandon-PRO - Native Disassembler", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_CLIPSIBLINGS, CW_USEDEFAULT, CW_USEDEFAULT, 1400, 850, nullptr, nullptr, instance, nullptr); if (!window) return 1;
    g_main_window = window;
    const BOOL dark = TRUE;
    DwmSetWindowAttribute(window, 20, &dark, sizeof(dark));
    const COLORREF caption = RGB(30, 34, 40);
    DwmSetWindowAttribute(window, 35, &caption, sizeof(caption));
    ShowWindow(window, show_command); UpdateWindow(window);
    if (command_line && *command_line) {
        std::wstring argument(command_line);
        const auto first = argument.find_first_not_of(L" \t");
        const auto last = argument.find_last_not_of(L" \t");
        if (first != std::wstring::npos) argument = argument.substr(first, last - first + 1);
        if (argument.size() >= 2 && argument.front() == L'"' && argument.back() == L'"') argument = argument.substr(1, argument.size() - 2);
        if (!argument.empty() && std::filesystem::exists(argument)) load_binary_path(window, argument);
    }
    const ACCEL accelerators[] = {
        {FVIRTKEY | FCONTROL, 'O', ID_OPEN},
        {FVIRTKEY | FCONTROL, 'S', ID_SAVE_DB},
        {FVIRTKEY | FCONTROL, 'L', ID_LOAD_DB},
        {FVIRTKEY | FCONTROL | FALT, 'P', ID_APPLY_PATCHES},
        {FVIRTKEY | FCONTROL, 'F', ID_SEARCH},
        {FVIRTKEY | FCONTROL, 'G', ID_FIND_FUNCTION},
        {FVIRTKEY | FCONTROL, 'E', ID_EDIT_INSTRUCTION},
        {FVIRTKEY | FCONTROL, 'Z', ID_UNDO_PATCH},
        {FVIRTKEY | FCONTROL, 'Y', ID_REDO_PATCH},
        {FVIRTKEY | FCONTROL, 'B', ID_SIGMAKER},
        {FVIRTKEY | FCONTROL | FSHIFT, 'F', ID_SEARCH_SIGNATURE},
        {FVIRTKEY, VK_F2, ID_TOGGLE_BP},
        {FVIRTKEY, VK_F5, ID_REFRESH},
        {FVIRTKEY, VK_F6, ID_PAUSE},
        {FVIRTKEY, VK_F7, ID_STEP_INTO},
        {FVIRTKEY, VK_F8, ID_STEP_OVER},
        {FVIRTKEY, VK_F9, ID_RUN},
        {FVIRTKEY, VK_HOME, ID_FIT_GRAPH},
        {FVIRTKEY, VK_SPACE, ID_TOGGLE_GRAPH_LIST},
        {FVIRTKEY | FSHIFT, VK_F12, ID_VIEW_STRINGS},
    };
    g_accelerators = CreateAcceleratorTableW(const_cast<LPACCEL>(accelerators), static_cast<int>(std::size(accelerators)));
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (!TranslateAcceleratorW(window, g_accelerators, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    if (g_accelerators) DestroyAcceleratorTable(g_accelerators);
    return static_cast<int>(message.wParam);
}
