#include "gandon/core.hpp"
#include "gandon/decompiler.hpp"
#include "gandon/emulator.hpp"
#include "gandon/ida_views.hpp"
#include "gandon/auto_analysis.hpp"
#include "gandon/il_emulator.hpp"
#include "gandon/plugin_host.hpp"
#include "gandon/pe_dump.hpp"
#include "gandon/vm_analysis.hpp"
#include "gandon/dotnet.hpp"
#include "gandon/rtti.hpp"
#include "gandon/driver.hpp"
#include "gandon/live_process.hpp"
#include "gandon/driver_setup.hpp"

#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>
#include <dbghelp.h>
#include <wincodec.h>
#include <dwmapi.h>
#include <commdlg.h>
#include <commctrl.h>
#include <windowsx.h>
#include "gandon/types.hpp"
#include "gandon/binary_diff.hpp"
#include "gandon/stack_frame.hpp"
#include <richedit.h>
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
#include <functional>
#include <map>
#include <set>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <iomanip>
#include <regex>
#include <cmath>
#include <new>
#include <exception>
#include <optional>

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
constexpr int ID_JUMP_BACK = 1330, ID_TOGGLE_BOOKMARK = 1331, ID_NEXT_BOOKMARK = 1332, ID_EXPORT_JSON = 1333, ID_EXPORT_BREAKPOINTS = 1334, ID_EXPORT_DEBUG_LOG = 1335, ID_JUMP_ADDR = 1336, ID_JUMP_FORWARD = 1359;
constexpr int ID_LIST_XREFS = 1336, ID_SEARCH_PROCESS_MEMORY = 1337, ID_FIND_FUNCTION = 1338, ID_HIDE_FUNCTION = 1339;
constexpr int ID_RUN = 1340, ID_STEP_INTO = 1341, ID_STEP_OVER = 1342, ID_TOGGLE_BP = 1343, ID_COND_BP = 1344, ID_CONFIG_BP = 1345, ID_BP_MANAGER = 1346, ID_HW_BP = 1347, ID_DELETE_BP = 1348, ID_STOP = 1349;
constexpr int ID_ANTI_DEBUG = 1350;
constexpr int ID_POINTER_SCAN = 1427, ID_POINTER_RESCAN = 1428, ID_STRUCT_DUMP = 1429;
constexpr int ID_LIVE_CANCEL = 1430, ID_KERNEL_BACKEND = 1431, ID_ANTIDEBUG_STATUS = 1432, ID_LIVE_EXPORT = 1433;
constexpr UINT WM_LIVE_RESULT = WM_APP + 56;
constexpr int ID_TRACE_TOGGLE = 1351, ID_EXPORT_TRACE = 1352, ID_HIDDEN_SYMBOLS = 1353, ID_RESTORE_HIDDEN = 1354;
constexpr int ID_HIDE_IMPORT = 1355;
constexpr int ID_MEMORY_SNAPSHOT = 1356, ID_MEMORY_COMPARE = 1357;
constexpr int ID_PAUSE = 1358;
constexpr int ID_VIEW_GRAPH = 1360, ID_VIEW_LISTING = 1361, ID_VIEW_PSEUDO = 1362, ID_VIEW_DEBUGGER = 1363, ID_VIEW_HEX = 1364, ID_VIEW_TYPES = 1365, ID_VIEW_IMPORTS = 1366, ID_VIEW_EXPORTS = 1367, ID_VIEW_STRINGS = 1368, ID_VIEW_RESOURCES = 1369, ID_VIEW_SYMBOLS = 1370, ID_VIEW_MEMORY = 1371, ID_VIEW_PROBLEMS = 1372, ID_GRAPH_COLLAPSE = 1373, ID_GRAPH_EXPAND_ALL = 1374, ID_ABOUT = 1380;
constexpr int ID_TOGGLE_GRAPH_LIST = 1373, ID_FIT_GRAPH = 1374, ID_TOGGLE_MINIMAP = 1375;
constexpr int ID_PATHFINDER = 1376;
constexpr int ID_EMULATE = 1377, ID_EMULATE_STEP = 1378, ID_EMULATE_RESET = 1379;
constexpr int ID_EMULATE_BREAKPOINT = 1381;
constexpr int ID_EMULATE_SET_REGISTER = 1382, ID_EMULATE_WRITE_MEMORY = 1383, ID_EMULATE_STEP_OVER = 1384;
constexpr int ID_EMULATE_WATCHPOINT = 1385, ID_EMULATE_CLEAR_WATCHPOINTS = 1386;
constexpr int ID_EMULATE_REGISTER_DELTAS = 1387;
constexpr int ID_EMULATE_STEP_OUT = 1388;
constexpr int ID_EMULATE_PREPARE = 1389;
constexpr int ID_EMULATE_CLEAR_HISTORY = 1397;
constexpr int ID_VIEW_FUNCTIONS = 1405;
constexpr int ID_DIFF_FUNCTIONS = 1410;
constexpr int ID_PANEL_BASE = 1450, ID_PANEL_RESET = 1470;   // View -> Panels
constexpr int ID_STRUCT_OFFSET = 1406, ID_ENUM_OPERAND = 1407, ID_SET_PROTOTYPE = 1408, ID_TYPES_EDITOR = 1409;
constexpr int ID_VIEW_LLIL = 1398, ID_LLIL_LIFT = 1399, ID_LLIL_STEP = 1400, ID_LLIL_RUN = 1401;
constexpr int ID_LLIL_SET_REGISTER = 1402, ID_LLIL_RESET = 1403;
constexpr int ID_LLIL_WRITE_MEMORY = 1404;
constexpr int ID_GRAPH_GROUP = 1411, ID_GRAPH_UNGROUP = 1412, ID_GRAPH_CLEAR_SELECTION = 1413;
constexpr int ID_INVERT_BRANCH = 1414, ID_FORCE_BRANCH = 1415, ID_NOP_BRANCH = 1416, ID_STUB_RET0 = 1417, ID_STUB_RET1 = 1418;
constexpr int ID_DUMP_MODULE = 1419, ID_DETECT_VM = 1420, ID_EMULATE_DECRYPT = 1421;
constexpr int ID_ANALYZE_DOTNET = 1422, ID_TRACE_VM = 1423;
constexpr int ID_RECOVER_RTTI = 1424, ID_ANALYZE_DRIVER = 1425, ID_DEVIRT_VM = 1426;
HMENU build_patch_submenu();  // defined with the semantic patch operations below
constexpr int ID_CONTEXT_FOLLOW = 1390, ID_CONTEXT_COPY = 1391, ID_CONTEXT_FOLLOW_TARGET = 1392;
constexpr int ID_COLOR_DEFAULT = 1393, ID_COLOR_GREEN = 1394, ID_COLOR_RED = 1395, ID_COLOR_BLUE = 1396;
constexpr int GRAPH_PAN_PADDING = 100000;
constexpr UINT WM_DEBUG_STATUS = WM_APP + 7;
constexpr UINT WM_RUN_ON_UI = WM_APP + 55;
constexpr int ID_TABS = 1100;
constexpr int ID_TREE = 1101;
constexpr int ID_EDITOR = 1102;
constexpr int ID_STATUS = 1103;

// ---- Theme: IDA 9 dark by default, "--light" selects the classic light palette ----
bool g_light_theme = false;   // IDA 9 dark by default; "--light" selects the classic light palette
inline COLORREF themed_color(COLORREF c) {
    if (!g_light_theme) {
        // IDA 9.x dark: neutral grays (#363636 background, #DDDDDD text).
        static const std::unordered_map<COLORREF, COLORREF> dark_table = {
            {RGB(24, 27, 32), RGB(54, 54, 54)},   {RGB(30, 34, 40), RGB(66, 66, 66)},    {RGB(18, 22, 27), RGB(44, 44, 44)},
            {RGB(16, 19, 24), RGB(48, 48, 48)},   {RGB(215, 228, 238), RGB(221, 221, 221)}, {RGB(225, 235, 242), RGB(240, 240, 240)},
            {RGB(155, 170, 184), RGB(165, 165, 165)}, {RGB(170, 185, 198), RGB(190, 190, 190)},
            {RGB(32, 39, 47), RGB(46, 46, 46)},   {RGB(36, 57, 66), RGB(58, 70, 88)},    {RGB(62, 78, 91), RGB(125, 125, 125)},
            {RGB(52, 64, 74), RGB(90, 90, 90)},   {RGB(88, 108, 128), RGB(110, 110, 110)}, {RGB(18, 29, 38), RGB(44, 44, 44)},
            {RGB(48, 48, 52), RGB(80, 80, 80)},   {RGB(125, 138, 150), RGB(150, 150, 150)},
        };
        const auto found = dark_table.find(c);
        return found == dark_table.end() ? c : found->second;
    }
    static const std::unordered_map<COLORREF, COLORREF> table = {
        {RGB(24, 27, 32), RGB(255, 255, 255)},   {RGB(30, 34, 40), RGB(240, 240, 240)},  {RGB(18, 22, 27), RGB(214, 214, 214)},
        {RGB(16, 19, 24), RGB(255, 255, 255)},   {RGB(215, 228, 238), RGB(0, 0, 0)},     {RGB(225, 235, 242), RGB(0, 0, 0)},
        {RGB(155, 170, 184), RGB(96, 96, 96)},   {RGB(170, 185, 198), RGB(64, 64, 64)},  {RGB(170, 239, 207), RGB(0, 0, 128)},
        {RGB(155, 190, 214), RGB(0, 0, 128)},    {RGB(32, 39, 47), RGB(255, 255, 255)},  {RGB(36, 57, 66), RGB(222, 236, 255)},
        {RGB(62, 78, 91), RGB(40, 40, 40)},      {RGB(0, 160, 210), RGB(0, 0, 255)},     {RGB(52, 64, 74), RGB(170, 170, 170)},
        {RGB(120, 170, 235), RGB(0, 0, 128)},    {RGB(106, 168, 219), RGB(0, 0, 128)},   {RGB(125, 191, 231), RGB(0, 0, 128)},
        {RGB(220, 170, 90), RGB(0, 0, 128)},     {RGB(78, 201, 176), RGB(0, 0, 128)},    {RGB(224, 92, 93), RGB(0, 0, 128)},
        {RGB(73, 190, 104), RGB(0, 128, 0)},     {RGB(224, 92, 92), RGB(255, 0, 0)},     {RGB(86, 157, 214), RGB(0, 0, 255)},
        {RGB(88, 108, 128), RGB(200, 200, 200)}, {RGB(0, 139, 190), RGB(150, 190, 255)}, {RGB(230, 190, 70), RGB(0, 0, 255)},
        {RGB(54, 157, 220), RGB(0, 0, 255)},     {RGB(231, 76, 60), RGB(255, 0, 0)},     {RGB(180, 180, 180), RGB(90, 90, 90)},
        {RGB(125, 138, 150), RGB(64, 64, 64)},   {RGB(106, 170, 110), RGB(0, 0, 255)},   {RGB(86, 156, 214), RGB(0, 0, 128)},
        {RGB(229, 160, 80), RGB(0, 0, 128)},     {RGB(230, 219, 140), RGB(0, 0, 0)},     {RGB(181, 206, 168), RGB(0, 0, 192)},
        {RGB(206, 145, 120), RGB(0, 128, 0)},    {RGB(150, 190, 235), RGB(0, 0, 128)},   {RGB(35, 83, 64), RGB(200, 240, 210)},
        {RGB(94, 45, 50), RGB(250, 205, 205)},   {RGB(37, 62, 91), RGB(205, 225, 250)},  {RGB(18, 29, 38), RGB(245, 245, 245)},
        {RGB(43, 104, 139), RGB(120, 170, 230)}, {RGB(48, 48, 52), RGB(200, 200, 200)},  {RGB(0, 122, 204), RGB(0, 0, 255)},
        {RGB(70, 76, 84), RGB(150, 150, 150)},
    };
    const auto it = table.find(c);
    return it == table.end() ? c : it->second;
}
#define THEMED_RGB(r, g, b) themed_color(RGB(r, g, b))

HINSTANCE g_instance{};
HICON g_small_icon{};
HWND g_main_window{}, g_tree{}, g_tabs{}, g_editor{}, g_status{}, g_minimap{};
HWND g_view{}, g_navband{}, g_output{}, g_toolbar{};
HBRUSH g_background{}, g_panel{};
HFONT g_ui_font{}, g_code_font{};
bool g_code_font_owned = false;
struct GraphBlock {
    std::uint64_t start{};
    std::vector<const gandon::Instruction*> instructions;
    int x{}, y{}, width{520}, height{100};
    bool is_group{};                // folded user-defined group of several blocks
    std::size_t group_members{};    // how many original blocks it stands for
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
std::set<std::uint64_t> g_collapsed_blocks;   // graph nodes drawn as a one-line header
std::vector<std::vector<std::uint64_t>> g_graph_groups;  // each: member block-starts folded into one node
std::set<std::uint64_t> g_graph_selection;    // block-starts tagged for the next "Group" (session-only)
std::vector<gandon::Instruction> g_graph_fallback_instructions;
std::unordered_map<std::uint64_t, std::pair<int, int>> g_graph_positions;
std::set<std::uint64_t> g_string_addresses;
std::unordered_map<HTREEITEM, std::pair<std::size_t, std::size_t>> g_lazy_function_ranges;
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
std::unique_ptr<gandon::Emulator> g_emulator;
std::optional<gandon::LowLevelIlProgram> g_llil_program;
std::unique_ptr<gandon::LowLevelIlEmulator> g_llil_emulator;
std::wstring g_llil_status;
std::wstring g_llil_memory_status;
std::wstring g_listing, g_pseudocode, g_xrefs, g_memory_map;
std::vector<std::uint8_t> g_memory_snapshot;
std::uint64_t g_memory_snapshot_address = 0;
std::uint64_t g_current_address = 0;
struct PatchChange { std::size_t offset{}; std::uint8_t old_value{}; std::uint8_t new_value{}; };
std::vector<std::vector<PatchChange>> g_patch_undo, g_patch_redo;
// Unified undo timeline: patches ("p") and label/comment edits ("e") are undone in the order they were made.
struct TextEdit { bool comment{}; std::uint64_t address{}; bool had_before{}; std::wstring before, after; };
std::vector<TextEdit> g_edit_undo, g_edit_redo;
std::vector<char> g_timeline, g_timeline_redo;
std::unordered_map<std::uint64_t, std::wstring> g_custom_labels, g_custom_comments;
std::unordered_map<std::uint64_t, std::wstring> g_custom_types;
// Local type library: built-in Windows declarations + the user's own source, and the places they are applied.
gandon::TypeLibrary g_types(8);
std::string g_type_source, g_type_error;
std::map<std::uint64_t, std::string> g_struct_ops, g_enum_ops, g_prototypes;
unsigned g_types_version = 1;
void reload_type_library(bool is_64_bit) {
    g_types = gandon::TypeLibrary(is_64_bit ? 8 : 4);
    std::string ignored; g_types.parse(gandon::default_type_declarations(), ignored);
    g_type_error.clear(); g_types.parse(g_type_source, g_type_error);
    ++g_types_version;
}
void ensure_types(bool is_64_bit) {
    static std::size_t last = 0; static bool initialised = false;
    const std::size_t key = std::hash<std::string>{}(g_type_source) ^ (is_64_bit ? 0x9E37u : 0u);
    if (!initialised || key != last) { initialised = true; last = key; reload_type_library(is_64_bit); }
}
std::unordered_map<std::uint64_t, COLORREF> g_graph_colors;
struct NavigationPoint { std::uint64_t address{}; int tab{}; };
std::vector<NavigationPoint> g_navigation_history;   // back stack
std::vector<NavigationPoint> g_navigation_forward;   // forward stack (after Jump Back)
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
std::wstring low_level_il_text();
void clear_llil_state();
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
void colorize_editor(int tab);
gandon::IdaViews& ida_views(const gandon::AnalysisDatabase& db);
void gui_auto_analysis(gandon::AnalysisDatabase& db);
void output_log(const std::wstring& line);
std::set<std::uint64_t> g_noreturn;
std::wstring g_auto_analysis_summary;
void select_view(HWND window, int tab);
void py_console_log(const std::wstring& text);
void py_console_log_command(int id);
void functions_window(HWND owner);
HWND funcwin_create(HWND parent);
HWND diffwin_create(HWND parent);
void diff_with_binary(HWND window);
bool run_function_diff(const std::filesystem::path& other_path, std::string& error);
namespace diffdata { gandon::FunctionDiffResult result; std::wstring other_name; }
HWND pyconsole_create(HWND parent);
HWND typewin_create(HWND parent);
void apply_struct_offset(HWND window);
void apply_enum_operand(HWND window);
void set_function_prototype(HWND window);
void types_editor_window(HWND owner);
void dark_title_bar(HWND hwnd);
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
std::wstring lowered(std::wstring value);
std::optional<std::wstring> prompt_text(HWND owner, const wchar_t* title, const wchar_t* label, const std::wstring& initial = {}, const wchar_t* hint = L"");

std::string utf8_from_wide(const std::wstring& value);
struct LiveTaskResult {
    bool scan{};
    DWORD pid{};
    gandon::PointerScanResult pointers;
    gandon::StructureSnapshot structure;
    std::string report;
};
std::thread g_live_worker;
std::atomic_bool g_live_cancel{false};
bool g_live_busy = false, g_live_kernel = false;
gandon::PointerScanResult g_live_last_scan;
gandon::StructureSnapshot g_live_last_structure;
DWORD g_live_last_pid{};
std::string g_live_last_report;

std::optional<std::uint64_t> live_number(HWND owner, const wchar_t* title, const wchar_t* label, const std::wstring& initial, std::uint64_t maximum) {
    const auto text = prompt_text(owner, title, label, initial);
    if (!text) return {};
    try {
        const auto first = text->find_first_not_of(L" \t");
        if (first == std::wstring::npos || (*text)[first] == L'-' || (*text)[first] == L'+') throw std::invalid_argument("number");
        std::size_t used{}; const auto number = std::stoull(*text, &used, 0);
        if (text->find_first_not_of(L" \t", used) != std::wstring::npos || number > maximum) throw std::invalid_argument("range");
        return number;
    } catch (...) { MessageBoxW(owner, L"Invalid value or range. Use decimal or 0x-prefixed hexadecimal.", title, MB_ICONWARNING); return {}; }
}
std::unique_ptr<gandon::LiveMemoryReader> live_reader(HWND window, DWORD& pid) {
    auto value = live_number(window, L"Live Process", L"Process ID (PID):", std::to_wstring(g_debug_pid.load() ? g_debug_pid.load() : g_live_last_pid), UINT32_MAX);
    if (!value || !*value) return {};
    pid = static_cast<DWORD>(*value);
    std::string error;
    auto reader = gandon::open_live_process(pid, g_live_kernel, error);
    if (!reader) MessageBoxW(window, wide(error).c_str(), L"Live Process", MB_ICONWARNING);
    return reader;
}
bool begin_live_job(HWND window, std::function<LiveTaskResult()> job) {
    if (g_live_busy) { SetWindowTextW(g_status, L"A live operation is running. Use Cancel Live Operation first."); return false; }
    if (g_live_worker.joinable()) g_live_worker.join();
    g_live_cancel.store(false); g_live_busy = true;
    try {
        g_live_worker = std::thread([window, job = std::move(job)] {
            auto result = std::make_unique<LiveTaskResult>();
            try { *result = job(); }
            catch (const std::exception& e) { result->report = std::string("Live operation failed: ") + e.what(); }
            catch (...) { result->report = "Live operation failed with an unknown error"; }
            if (PostMessageW(window, WM_LIVE_RESULT, 0, reinterpret_cast<LPARAM>(result.get()))) result.release();
        });
    } catch (...) { g_live_busy = false; SetWindowTextW(g_status, L"Could not create live-operation worker."); return false; }
    SetWindowTextW(g_status, L"Live operation running; Tools > Cancel Live Operation stops it."); return true;
}
void live_pointer_scan(HWND window, bool rescan) {
    if (g_live_busy) { SetWindowTextW(g_status, L"Cancel or finish the current live operation first."); return; }
    if (rescan && g_live_last_scan.chains.empty()) { SetWindowTextW(g_status, L"Run Pointer Scan first."); return; }
    DWORD pid{}; auto reader = live_reader(window, pid); if (!reader) return;
    std::wostringstream initial;
    initial << L"0x" << std::hex << (rescan ? g_live_last_scan.chains.front().target : g_debug_pause_address.load());
    auto target = live_number(window, L"Pointer Scan", L"Target runtime address (not a file VA):", initial.str(), reader->pointer_size() == 4 ? UINT32_MAX : UINT64_MAX);
    if (!target || !*target) return;
    gandon::PointerScanOptions options;
    if (!rescan) {
        auto depth = live_number(window, L"Pointer Scan", L"Maximum pointer depth (1..10):", L"3", 10);
        if (!depth || !*depth) return; options.depth = static_cast<unsigned>(*depth);
        auto offset = live_number(window, L"Pointer Scan", L"Maximum nonnegative offset per hop (0..0x100000):", L"0x1000", 0x100000);
        if (!offset) return; options.max_offset = *offset;
        const auto roots = prompt_text(window, L"Pointer Scan", L"Root filter: module (ASLR-friendly module+RVA) or all:", L"module");
        if (!roots) return;
        if (*roots == L"all") options.module_roots_only = false;
        else if (*roots != L"module") { SetWindowTextW(g_status, L"Root filter must be module or all."); return; }
    }
    auto shared = std::shared_ptr<gandon::LiveMemoryReader>(std::move(reader));
    auto previous = g_live_last_scan.chains;
    begin_live_job(window, [shared, pid, target = *target, options, rescan, previous = std::move(previous)] {
        LiveTaskResult result; result.scan = true; result.pid = pid;
        if (rescan) {
            const auto modules = shared->modules();
            for (auto chain : previous) {
                if (g_live_cancel.load()) { result.pointers.cancelled = result.pointers.truncated = true; result.pointers.reason = "Cancelled"; break; }
                if (!chain.module.empty()) {
                    const auto found = std::find_if(modules.begin(), modules.end(), [&](const auto& module) { return module.name == chain.module && chain.module_offset < module.size; });
                    if (found == modules.end() || found->base > UINT64_MAX - chain.module_offset) continue;
                    chain.root = found->base + chain.module_offset;
                }
                ++result.pointers.visited_states;
                if (gandon::resolve_pointer_chain(*shared, chain) == target) { chain.target = target; result.pointers.chains.push_back(std::move(chain)); }
            }
        } else result.pointers = gandon::scan_pointers(*shared, target, options, [] { return g_live_cancel.load(); });
        result.report = "PID " + std::to_string(pid) + (rescan ? " re-scan\n" : "\n") + gandon::format_pointer_scan(result.pointers);
        return result;
    });
}
void live_structure_dump(HWND window) {
    if (g_live_busy) { SetWindowTextW(g_status, L"Finish or cancel the live operation first."); return; }
    DWORD pid{}; auto reader = live_reader(window, pid); if (!reader) return;
    auto address = live_number(window, L"Structure Dump", L"Runtime address:", L"0x0", reader->pointer_size() == 4 ? UINT32_MAX : UINT64_MAX);
    if (!address || !*address) return;
    const auto type = prompt_text(window, L"Structure Dump", L"Struct/union name from Local Types (empty = raw candidates):", L"");
    if (!type) return;
    std::size_t size = 256;
    if (type->empty()) {
        auto count = live_number(window, L"Structure Dump", L"Byte count (1..1048576):", L"256", 1048576);
        if (!count || !*count) return; size = static_cast<std::size_t>(*count);
    }
    gandon::TypeLibrary types(static_cast<int>(reader->pointer_size())); std::string error;
    if (!types.parse(gandon::default_type_declarations(), error) || !types.parse(g_type_source, error)) {
        MessageBoxW(window, wide(error).c_str(), L"Local Types", MB_ICONWARNING); return;
    }
    auto shared = std::shared_ptr<gandon::LiveMemoryReader>(std::move(reader));
    begin_live_job(window, [shared, pid, address = *address, type_name = utf8_from_wide(*type), size, types = std::move(types)] {
        LiveTaskResult result; result.pid = pid;
        result.structure = gandon::dump_live_structure(*shared, types, type_name, address, size);
        result.report = "PID " + std::to_string(pid) + "\n" + (result.structure.error.empty() ? result.structure.report : result.structure.error);
        return result;
    });
}
void export_live_result(HWND window) {
    if (g_live_last_report.empty()) { SetWindowTextW(g_status, L"No live result to export."); return; }
    wchar_t path[MAX_PATH] = L"live-process.txt";
    OPENFILENAMEW dialog{sizeof(dialog)}; dialog.hwndOwner = window;
    dialog.lpstrFilter = L"Text report (*.txt)\0*.txt\0All files\0*.*\0"; dialog.lpstrFile = path; dialog.nMaxFile = MAX_PATH;
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST; dialog.lpstrDefExt = L"txt";
    if (!GetSaveFileNameW(&dialog)) return;
    try {
        auto write = [](const std::filesystem::path& target, const char* data, std::size_t size) {
            std::ofstream out(target, std::ios::binary | std::ios::trunc); out.exceptions(std::ios::failbit | std::ios::badbit);
            out.write(data, static_cast<std::streamsize>(size)); out.close();
        };
        write(path, g_live_last_report.data(), g_live_last_report.size());
        if (!g_live_last_structure.bytes.empty()) {
            write(std::wstring(path) + L".bin", reinterpret_cast<const char*>(g_live_last_structure.bytes.data()), g_live_last_structure.bytes.size());
            write(std::wstring(path) + L".valid.bin", reinterpret_cast<const char*>(g_live_last_structure.valid.data()), g_live_last_structure.valid.size());
        }
        SetWindowTextW(g_status, L"Live report exported; structure dumps also include .bin and .valid.bin.");
    } catch (const std::exception& e) { MessageBoxW(window, wide(e.what()).c_str(), L"Export Live Result", MB_ICONERROR); }
}

std::optional<std::uint64_t> resolve_jump_target(std::wstring text);
std::wstring pseudocode_text_at(const gandon::AnalysisDatabase& db, std::uint64_t address);
std::wstring hex_text(const gandon::BinaryImage& image, std::uint64_t address);
std::wstring strings_text(const gandon::BinaryImage& image);
std::wstring imports_text(const gandon::BinaryImage& image);
std::wstring exports_text(const gandon::BinaryImage& image);
std::wstring resources_text(const gandon::BinaryImage& image);
std::wstring memory_map_text(const gandon::AnalysisDatabase& db);
void refresh_views(HWND window);
void refresh_after_patch(HWND window);
bool write_database_file(const std::filesystem::path& file, std::string& error);
bool load_database_core(HWND window, const std::filesystem::path& file_name, bool allow_legacy_json, std::string& error);

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
    const auto count = (std::min<std::size_t>)(instruction.size, 7);
    for (std::size_t index = 0; index < count; ++index) {
        if (index) text << L' ';
        text << std::uppercase << std::hex << std::setfill(L'0') << std::setw(2)
             << static_cast<unsigned>(instruction.bytes[index]);
    }
    if (instruction.size > count) text << L" …";
    return text.str();
}

struct PromptContext { std::wstring value; std::wstring initial; std::wstring hint; };

void prompt_word(std::vector<BYTE>& data, WORD value) {
    if (data.size() & 1u) data.push_back(0);
    data.push_back(static_cast<BYTE>(value & 0xff)); data.push_back(static_cast<BYTE>(value >> 8));
}

void prompt_string(std::vector<BYTE>& data, const wchar_t* value) {
    while (*value) prompt_word(data, static_cast<WORD>(*value++));
    prompt_word(data, 0);
}

COLORREF prompt_text_color() { return g_light_theme ? RGB(0, 0, 0) : RGB(221, 221, 221); }

void prompt_draw_button(const DRAWITEMSTRUCT& item) {
    wchar_t caption[64]{}; GetWindowTextW(item.hwndItem, caption, 64);
    const bool pressed = (item.itemState & ODS_SELECTED) != 0, focused = (item.itemState & ODS_FOCUS) != 0;
    const bool is_default = item.CtlID == IDOK;
    const COLORREF fill = g_light_theme ? (pressed ? RGB(205, 205, 205) : RGB(225, 225, 225)) : (pressed ? RGB(88, 88, 88) : RGB(66, 66, 66));
    const COLORREF edge = (focused || is_default) ? RGB(0, 122, 204) : (g_light_theme ? RGB(150, 150, 150) : RGB(98, 98, 98));
    HBRUSH brush = CreateSolidBrush(fill); FillRect(item.hDC, &item.rcItem, brush); DeleteObject(brush);
    HBRUSH frame = CreateSolidBrush(edge); FrameRect(item.hDC, &item.rcItem, frame); DeleteObject(frame);
    SetBkMode(item.hDC, TRANSPARENT); SetTextColor(item.hDC, prompt_text_color());
    HFONT old_font = reinterpret_cast<HFONT>(SelectObject(item.hDC, g_ui_font ? g_ui_font : GetStockObject(DEFAULT_GUI_FONT)));
    RECT text = item.rcItem; if (pressed) OffsetRect(&text, 1, 1);
    DrawTextW(item.hDC, caption, -1, &text, DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_NOPREFIX);
    SelectObject(item.hDC, old_font);
}

INT_PTR CALLBACK prompt_proc(HWND dialog, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* context = reinterpret_cast<PromptContext*>(GetWindowLongPtrW(dialog, DWLP_USER));
    switch (message) {
    case WM_INITDIALOG: {
        SetWindowLongPtrW(dialog, DWLP_USER, lparam);
        context = reinterpret_cast<PromptContext*>(lparam);
        const BOOL dark = g_light_theme ? FALSE : TRUE;
        DwmSetWindowAttribute(dialog, 20, &dark, sizeof(dark));
        SetDlgItemTextW(dialog, 101, context->initial.c_str());
        SetDlgItemTextW(dialog, 102, context->hint.c_str());
        SendMessageW(dialog, DM_SETDEFID, IDOK, 0);
        HWND edit = GetDlgItem(dialog, 101);
        SendMessageW(edit, EM_SETSEL, 0, -1);
        // centre over the owner like IDA does
        RECT own{}, box{}; GetWindowRect(GetParent(dialog) ? GetParent(dialog) : GetDesktopWindow(), &own); GetWindowRect(dialog, &box);
        SetWindowPos(dialog, nullptr, own.left + ((own.right - own.left) - (box.right - box.left)) / 2, own.top + ((own.bottom - own.top) - (box.bottom - box.top)) / 3, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
        SetFocus(edit);
        return FALSE;
    }
    case WM_CTLCOLORDLG: return g_light_theme ? static_cast<INT_PTR>(reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_BTNFACE))) : reinterpret_cast<INT_PTR>(g_background);
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wparam);
        const bool hint = reinterpret_cast<HWND>(lparam) == GetDlgItem(dialog, 102);
        SetTextColor(dc, hint ? (g_light_theme ? RGB(100, 100, 100) : RGB(150, 150, 150)) : prompt_text_color());
        if (g_light_theme) { SetBkColor(dc, GetSysColor(COLOR_BTNFACE)); return reinterpret_cast<INT_PTR>(GetSysColorBrush(COLOR_BTNFACE)); }
        SetBkColor(dc, THEMED_RGB(30, 34, 40)); return reinterpret_cast<INT_PTR>(g_background);
    }
    case WM_CTLCOLOREDIT: {
        HDC dc = reinterpret_cast<HDC>(wparam);
        SetTextColor(dc, prompt_text_color());
        if (g_light_theme) { SetBkColor(dc, RGB(255, 255, 255)); return reinterpret_cast<INT_PTR>(GetStockObject(WHITE_BRUSH)); }
        SetBkColor(dc, THEMED_RGB(24, 27, 32)); return reinterpret_cast<INT_PTR>(g_panel);
    }
    case WM_DRAWITEM:
        prompt_draw_button(*reinterpret_cast<DRAWITEMSTRUCT*>(lparam));
        return TRUE;
    case WM_COMMAND:
        if (!context) break;
        if (LOWORD(wparam) == IDOK) {
            wchar_t value[512]{}; GetDlgItemTextW(dialog, 101, value, 512); context->value = value; EndDialog(dialog, IDOK); return TRUE;
        }
        if (LOWORD(wparam) == IDCANCEL) { EndDialog(dialog, IDCANCEL); return TRUE; }
        break;
    }
    return FALSE;
}

std::optional<std::wstring> prompt_text(HWND owner, const wchar_t* title, const wchar_t* label, const std::wstring& initial, const wchar_t* hint) {
    // Template buffer holds only what was written: header first, then strings and items in order.
    std::vector<BYTE> data(sizeof(DLGTEMPLATE), 0);
    {
        DLGTEMPLATE header{};
        header.style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME | DS_SETFONT;
        header.dwExtendedStyle = WS_EX_DLGMODALFRAME; header.cdit = 5; header.x = 10; header.y = 10; header.cx = 230; header.cy = 82;
        std::memcpy(data.data(), &header, sizeof(header));
    }
    prompt_word(data, 0); prompt_word(data, 0); prompt_string(data, title); prompt_word(data, 9); prompt_string(data, L"Segoe UI");
    auto add_control = [&](DWORD style, short x, short y, short cx, short cy, WORD id, WORD klass, const wchar_t* text) {
        while (data.size() & 3u) data.push_back(0);
        DLGITEMTEMPLATE item{}; item.style = style; item.dwExtendedStyle = 0; item.x = x; item.y = y; item.cx = cx; item.cy = cy; item.id = id;
        const auto at = data.size(); data.resize(at + sizeof(item)); std::memcpy(data.data() + at, &item, sizeof(item));
        prompt_word(data, 0xffff); prompt_word(data, klass); prompt_string(data, text); prompt_word(data, 0);
    };
    add_control(WS_CHILD | WS_VISIBLE | SS_LEFT, 10, 9, 210, 10, 100, 0x0082, label);
    add_control(WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL, 10, 22, 210, 14, 101, 0x0081, L"");
    add_control(WS_CHILD | WS_VISIBLE | SS_LEFT, 10, 41, 210, 10, 102, 0x0082, L"");
    add_control(WS_CHILD | WS_VISIBLE | WS_TABSTOP | 0x0000000BL /* BS_OWNERDRAW */, 100, 59, 56, 16, IDOK, 0x0080, L"OK");
    add_control(WS_CHILD | WS_VISIBLE | WS_TABSTOP | 0x0000000BL, 164, 59, 56, 16, IDCANCEL, 0x0080, L"Cancel");
    PromptContext context; context.initial = initial; context.hint = hint ? hint : L"";
    const auto result = DialogBoxIndirectParamW(g_instance, reinterpret_cast<DLGTEMPLATE*>(data.data()), owner, prompt_proc, reinterpret_cast<LPARAM>(&context));
    if (result == -1) { MessageBoxW(owner, L"Не удалось создать диалог ввода.", title, MB_ICONERROR); return std::nullopt; }
    if (result == IDOK) return context.value;
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
    std::vector<gandon::Instruction>().swap(g_graph_fallback_instructions);
    if (!g_database) return;
    const auto function = g_database->function_at(g_current_address);
    const auto start = function ? function->get().start : g_database->image().entry_point;
    if (!start) return;
    std::uint64_t function_end = UINT64_MAX;
    const auto& functions = g_database->functions();
    for (std::size_t index = 0; index < functions.size(); ++index) {
        if (functions[index].start != start) continue;
        if (functions[index].end) function_end = functions[index].end;
        else if (index + 1 < functions.size()) function_end = functions[index + 1].start;
        break;
    }
    auto branch_target = [](const std::string& operands) -> std::optional<std::uint64_t> {
        if (operands.find('[') != std::string::npos) return std::nullopt;
        const auto first = operands.find("0x");
        if (first == std::string::npos) return std::nullopt;
        const auto last = operands.find_first_not_of("0123456789abcdefABCDEF", first + 2);
        try { return std::stoull(operands.substr(first, last - first), nullptr, 16); } catch (...) { return std::nullopt; }
    };
    const auto is_unconditional_jump = [](const std::string& mnemonic) {
        return mnemonic == "jmp" || mnemonic == "jmpq" || mnemonic == "ljmp" || mnemonic == "b";
    };
    const auto is_conditional_jump = [](const std::string& mnemonic) {
        return (mnemonic.size() > 1 && mnemonic.front() == 'j' && mnemonic != "jmp" &&
                mnemonic != "jmpq" && mnemonic != "ljmp") ||
               mnemonic.rfind("b.", 0) == 0 || mnemonic == "cbz" || mnemonic == "cbnz" ||
               mnemonic == "tbz" || mnemonic == "tbnz" ||
               mnemonic == "loop" || mnemonic == "loope" || mnemonic == "loopne" ||
               mnemonic == "jcxz" || mnemonic == "jecxz" || mnemonic == "jrcxz";
    };
    const auto inside_function = [&](std::uint64_t address) {
        return address >= start && address < function_end && g_database->image().va_to_file_offset(address).has_value();
    };
    const std::vector<gandon::Instruction>* instructions = nullptr;
    if (function && !function->get().instructions.empty()) instructions = &function->get().instructions;
    else {
        g_graph_fallback_instructions = gandon::decode_x64(g_database->image(), start, 2048);
        instructions = &g_graph_fallback_instructions;
    }
    const auto is_terminator = [](const std::string& mnemonic) {
        return mnemonic == "ret" || mnemonic == "retq" || mnemonic == "retn" || mnemonic == "retf" ||
               mnemonic == "iret" || mnemonic == "iretq" || mnemonic == "int3" || mnemonic == "ud0" ||
               mnemonic == "ud1" || mnemonic == "ud2" || mnemonic == "hlt" || mnemonic == "brk" || mnemonic == "udf";
    };
    std::unordered_map<std::uint64_t, std::size_t> instruction_indices;
    instruction_indices.reserve(instructions->size());
    for (std::size_t index = 0; index < instructions->size(); ++index)
        if (inside_function((*instructions)[index].address)) instruction_indices.emplace((*instructions)[index].address, index);

    // Split the already analyzed reachable instruction stream at every branch
    // target and conditional fallthrough. This keeps graph edges aligned with
    // the decoder's CFG and avoids duplicate blocks when a jump lands in code
    // that an earlier linear decode had already traversed.
    std::set<std::uint64_t> leaders{start};
    for (const auto& instruction : *instructions) {
        if (!inside_function(instruction.address)) continue;
        const auto& mnemonic = instruction.mnemonic;
        const bool conditional = is_conditional_jump(mnemonic);
        if (!is_unconditional_jump(mnemonic) && !conditional) continue;
        if (const auto target = branch_target(instruction.operands); target && instruction_indices.contains(*target))
            leaders.insert(*target);
        const auto fallthrough = instruction.address + instruction.size;
        if (conditional && instruction_indices.contains(fallthrough)) leaders.insert(fallthrough);
    }

    GraphBlock block;
    const auto finish_block = [&]() {
        if (block.instructions.empty()) return;
        if (g_collapsed_blocks.contains(block.start))
            block.height = 44;   // header only
        else
            block.height = 44 + static_cast<int>((std::min<std::size_t>)(block.instructions.size(), 40)) * 18 +
                           (g_custom_comments.contains(block.start) ? 18 : 0);
        g_graph_blocks.push_back(std::move(block));
        block = GraphBlock{};
    };
    for (const auto& instruction : *instructions) {
        if (!inside_function(instruction.address)) continue;
        if (!block.instructions.empty()) {
            const auto& previous = *block.instructions.back();
            const auto previous_end = previous.address + previous.size;
            if (leaders.contains(instruction.address) || previous_end != instruction.address ||
                is_unconditional_jump(previous.mnemonic) || is_conditional_jump(previous.mnemonic) ||
                is_terminator(previous.mnemonic)) finish_block();
        }
        if (block.instructions.empty()) block.start = instruction.address;
        block.instructions.push_back(&instruction);
        if (is_unconditional_jump(instruction.mnemonic) || is_conditional_jump(instruction.mnemonic) ||
            is_terminator(instruction.mnemonic)) finish_block();
    }
    finish_block();

    std::set<std::uint64_t> block_starts;
    for (const auto& item : g_graph_blocks) block_starts.insert(item.start);
    for (const auto& item : g_graph_blocks) {
        const auto& last = *item.instructions.back();
        const auto& mnemonic = last.mnemonic;
        const bool conditional = is_conditional_jump(mnemonic);
        if (is_unconditional_jump(mnemonic) || conditional) {
            if (const auto target = branch_target(last.operands); target && block_starts.contains(*target))
                g_graph_edges.push_back({item.start, *target, conditional ? GraphEdgeKind::TrueBranch : GraphEdgeKind::Unconditional});
            const auto fallthrough = last.address + last.size;
            if (conditional && block_starts.contains(fallthrough))
                g_graph_edges.push_back({item.start, fallthrough, GraphEdgeKind::FalseBranch});
        } else if (!is_terminator(mnemonic)) {
            const auto fallthrough = last.address + last.size;
            if (block_starts.contains(fallthrough))
                g_graph_edges.push_back({item.start, fallthrough, GraphEdgeKind::Unconditional});
        }
    }
    std::sort(g_graph_edges.begin(), g_graph_edges.end(), [](const GraphEdge& left, const GraphEdge& right) {
        return std::tie(left.from, left.to, left.kind) < std::tie(right.from, right.to, right.kind);
    });
    g_graph_edges.erase(std::unique(g_graph_edges.begin(), g_graph_edges.end(), [](const GraphEdge& left, const GraphEdge& right) {
        return left.from == right.from && left.to == right.to && left.kind == right.kind;
    }), g_graph_edges.end());

    // Fold user-defined groups: every member block collapses into one node drawn
    // at the group's anchor (its lowest-address member). Edges touching a member
    // are rerouted to the anchor and edges wholly inside the group are dropped, so
    // the CFG stays well-formed and the level/row layout treats the group as one.
    if (!g_graph_groups.empty() && !g_graph_blocks.empty()) {
        std::set<std::uint64_t> present;
        for (const auto& b : g_graph_blocks) present.insert(b.start);
        std::unordered_map<std::uint64_t, std::uint64_t> remap;   // member -> anchor
        std::map<std::uint64_t, std::size_t> member_count;        // anchor -> members folded
        for (const auto& group : g_graph_groups) {
            std::vector<std::uint64_t> members;
            for (const auto m : group) if (present.contains(m)) members.push_back(m);
            if (members.size() < 2) continue;                     // nothing to fold this function
            const std::uint64_t anchor = *std::min_element(members.begin(), members.end());
            for (const auto m : members) remap[m] = anchor;
            member_count[anchor] = members.size();
        }
        if (!remap.empty()) {
            std::vector<GraphBlock> kept;
            kept.reserve(g_graph_blocks.size());
            for (auto& b : g_graph_blocks) {
                const auto it = remap.find(b.start);
                if (it == remap.end()) { kept.push_back(std::move(b)); continue; }
                if (it->second != b.start) continue;              // non-anchor member: drop
                b.is_group = true;
                b.group_members = member_count[b.start];
                b.instructions.clear();
                b.height = 44;                                    // header-only, like a collapsed node
                kept.push_back(std::move(b));
            }
            g_graph_blocks = std::move(kept);
            for (auto& e : g_graph_edges) {
                if (const auto it = remap.find(e.from); it != remap.end()) e.from = it->second;
                if (const auto it = remap.find(e.to); it != remap.end()) e.to = it->second;
            }
            g_graph_edges.erase(std::remove_if(g_graph_edges.begin(), g_graph_edges.end(),
                [](const GraphEdge& e) { return e.from == e.to; }), g_graph_edges.end());
            std::sort(g_graph_edges.begin(), g_graph_edges.end(), [](const GraphEdge& left, const GraphEdge& right) {
                return std::tie(left.from, left.to, left.kind) < std::tie(right.from, right.to, right.kind);
            });
            g_graph_edges.erase(std::unique(g_graph_edges.begin(), g_graph_edges.end(), [](const GraphEdge& left, const GraphEdge& right) {
                return left.from == right.from && left.to == right.to && left.kind == right.kind;
            }), g_graph_edges.end());
        }
    }

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
        if (index < block.instructions.size()) return block.instructions[index]->address;
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

// ---- IDA-style navigation band: the whole image as a coloured strip ----
struct NavSection { std::uint64_t begin{}, size{}; std::size_t first_bucket{}, buckets{}; };
constexpr std::size_t kNavBuckets = 4096;
std::vector<std::uint8_t> g_nav_kind;   // 0 unexplored, 1 function, 2 data, 3 string, 4 import, 5 bss
std::vector<NavSection> g_nav_sections;
const gandon::AnalysisDatabase* g_nav_owner = nullptr;
std::size_t g_nav_signature = 0;

void rebuild_nav_band() {
    g_nav_kind.clear(); g_nav_sections.clear();
    g_nav_owner = g_database.get();
    if (!g_database) return;
    const auto& image = g_database->image();
    std::uint64_t total = 0;
    for (const auto& s : image.sections) total += (std::max<std::uint64_t>)(s.virtual_size, s.raw_size);
    if (!total) return;
    g_nav_kind.assign(kNavBuckets, 0);
    std::size_t cursor = 0;
    for (const auto& s : image.sections) {
        const auto size = (std::max<std::uint64_t>)(s.virtual_size, s.raw_size);
        if (!size) continue;
        NavSection n; n.begin = image.image_base + s.rva; n.size = size; n.first_bucket = cursor;
        n.buckets = (std::max<std::size_t>)(1, static_cast<std::size_t>(static_cast<double>(size) * kNavBuckets / static_cast<double>(total)));
        if (cursor + n.buckets > kNavBuckets) n.buckets = kNavBuckets - cursor;
        if (!n.buckets) break;
        cursor += n.buckets;
        const std::uint8_t base_kind = s.raw_size == 0 ? 5 : ((s.characteristics & 0x20000000u) ? 0 : 2);
        for (std::size_t i = 0; i < n.buckets; ++i) g_nav_kind[n.first_bucket + i] = base_kind;
        g_nav_sections.push_back(n);
    }
    auto paint_range = [&](std::uint64_t begin, std::uint64_t end, std::uint8_t kind) {
        for (const auto& n : g_nav_sections) {
            const auto lo = (std::max)(begin, n.begin), hi = (std::min)(end, n.begin + n.size);
            if (hi <= lo) continue;
            const auto b0 = n.first_bucket + static_cast<std::size_t>((lo - n.begin) * n.buckets / n.size);
            const auto b1 = n.first_bucket + static_cast<std::size_t>(((hi - 1) - n.begin) * n.buckets / n.size);
            for (auto b = b0; b <= b1 && b < kNavBuckets; ++b) g_nav_kind[b] = kind;
        }
    };
    for (const auto& r : ida_views(*g_database).item_ranges())
        paint_range(r.begin, r.end, r.kind == 'F' ? 1 : r.kind == 'S' ? 3 : r.kind == 'I' ? 4 : 2);
    g_nav_signature = g_database->functions().size();
}

std::optional<std::uint64_t> nav_address_at(int x, int width) {
    if (g_nav_sections.empty() || width <= 0) return std::nullopt;
    const auto bucket = (std::min<std::size_t>)(kNavBuckets - 1, static_cast<std::size_t>(static_cast<double>(x) * kNavBuckets / width));
    for (const auto& n : g_nav_sections)
        if (bucket >= n.first_bucket && bucket < n.first_bucket + n.buckets)
            return n.begin + (bucket - n.first_bucket) * n.size / n.buckets;
    return std::nullopt;
}

LRESULT CALLBACK dark_background_subclass(HWND window, UINT message, WPARAM wparam, LPARAM lparam, UINT_PTR id, DWORD_PTR) {
    if (message == WM_ERASEBKGND) {
        RECT client{}; GetClientRect(window, &client);
        HBRUSH brush = CreateSolidBrush(THEMED_RGB(24, 27, 32));
        FillRect(reinterpret_cast<HDC>(wparam), &client, brush); DeleteObject(brush);
        return 1;
    }
    if (message == WM_PAINT && id == 2) {
        // Fully custom tab strip: no system frames, no pane border line.
        PAINTSTRUCT paint{};
        HDC dc = BeginPaint(window, &paint);
        RECT client{}; GetClientRect(window, &client);
        HBRUSH strip = CreateSolidBrush(THEMED_RGB(24, 27, 32));
        FillRect(dc, &client, strip); DeleteObject(strip);
        const int selected = TabCtrl_GetCurSel(window);
        const int count = TabCtrl_GetItemCount(window);
        HFONT old_font = reinterpret_cast<HFONT>(SelectObject(dc, g_ui_font));
        SetBkMode(dc, TRANSPARENT);
        for (int index = 0; index < count; ++index) {
            RECT item_rect{};
            if (!TabCtrl_GetItemRect(window, index, &item_rect)) continue;
            wchar_t label[128]{};
            TCITEMW item{}; item.mask = TCIF_TEXT; item.pszText = label; item.cchTextMax = 128;
            TabCtrl_GetItem(window, index, &item);
            const bool active = index == selected;
            HBRUSH fill = CreateSolidBrush(active ? THEMED_RGB(30, 34, 40) : THEMED_RGB(24, 27, 32));
            FillRect(dc, &item_rect, fill); DeleteObject(fill);
            if (active) {
                RECT underline = item_rect; underline.top = underline.bottom - 2;
                HBRUSH accent = CreateSolidBrush(THEMED_RGB(0, 122, 204)); FillRect(dc, &underline, accent); DeleteObject(accent);
            }
            RECT separator{item_rect.right - 1, item_rect.top + 4, item_rect.right, item_rect.bottom - 4};
            if (index != count - 1) { HBRUSH separator_brush = CreateSolidBrush(THEMED_RGB(52, 64, 74)); FillRect(dc, &separator, separator_brush); DeleteObject(separator_brush); }
            SetTextColor(dc, active ? THEMED_RGB(225, 235, 242) : THEMED_RGB(155, 170, 184));
            RECT text = item_rect;
            DrawTextW(dc, label, -1, &text, DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_NOPREFIX | DT_NOCLIP);
        }
        SelectObject(dc, old_font);
        EndPaint(window, &paint);
        return 0;
    }
    return DefSubclassProc(window, message, wparam, lparam);
}

// Flat 16x16 toolbar icons drawn with GDI in the spirit of IDA's toolbar.
HIMAGELIST make_ida_toolbar_images() {
    constexpr int size = 16, count = 7;
    HDC screen = GetDC(nullptr);
    HDC dc = CreateCompatibleDC(screen);
    HBITMAP bitmap = CreateCompatibleBitmap(screen, size * count, size);
    ReleaseDC(nullptr, screen);
    HGDIOBJ old_bitmap = SelectObject(dc, bitmap);
    const COLORREF mask = RGB(255, 0, 255);
    HBRUSH background = CreateSolidBrush(mask);
    RECT all{0, 0, size * count, size};
    FillRect(dc, &all, background); DeleteObject(background);
    auto brush_pen = [&](COLORREF fill, COLORREF line, int width = 1) {
        SelectObject(dc, CreateSolidBrush(fill)); SelectObject(dc, CreatePen(PS_SOLID, width, line));
    };
    auto release = [&]() {
        DeleteObject(SelectObject(dc, GetStockObject(NULL_BRUSH))); DeleteObject(SelectObject(dc, GetStockObject(BLACK_PEN)));
    };
    // 0 open: folder
    {
        const int x = 0;
        brush_pen(RGB(236, 190, 70), RGB(150, 110, 30));
        const POINT back[] = {{x + 1, 4}, {x + 6, 4}, {x + 7, 6}, {x + 14, 6}, {x + 14, 13}, {x + 1, 13}};
        Polygon(dc, back, 6); release();
        brush_pen(RGB(250, 215, 110), RGB(150, 110, 30));
        const POINT front[] = {{x + 3, 8}, {x + 15, 8}, {x + 13, 13}, {x + 1, 13}};
        Polygon(dc, front, 4); release();
    }
    // 1 save: floppy
    {
        const int x = size;
        brush_pen(RGB(90, 150, 225), RGB(30, 70, 140));
        Rectangle(dc, x + 2, 2, x + 14, 14); release();
        brush_pen(RGB(240, 240, 240), RGB(30, 70, 140));
        Rectangle(dc, x + 4, 2, x + 12, 7); release();
        brush_pen(RGB(40, 60, 110), RGB(40, 60, 110));
        Rectangle(dc, x + 5, 9, x + 11, 14); release();
    }
    // 2 back / 3 forward arrows
    for (int k = 0; k < 2; ++k) {
        const int x = size * (2 + k);
        brush_pen(RGB(90, 200, 120), RGB(30, 120, 60));
        if (k == 0) { const POINT arrow[] = {{x + 2, 8}, {x + 8, 2}, {x + 8, 6}, {x + 14, 6}, {x + 14, 10}, {x + 8, 10}, {x + 8, 14}}; Polygon(dc, arrow, 7); }
        else { const POINT arrow[] = {{x + 14, 8}, {x + 8, 2}, {x + 8, 6}, {x + 2, 6}, {x + 2, 10}, {x + 8, 10}, {x + 8, 14}}; Polygon(dc, arrow, 7); }
        release();
    }
    // 4 search: magnifier
    {
        const int x = size * 4;
        brush_pen(RGB(60, 60, 60), RGB(225, 225, 225), 2);
        Ellipse(dc, x + 2, 2, x + 10, 10); release();
        HPEN handle = CreatePen(PS_SOLID, 3, RGB(225, 225, 225)); HGDIOBJ old = SelectObject(dc, handle);
        MoveToEx(dc, x + 9, 9, nullptr); LineTo(dc, x + 14, 14); SelectObject(dc, old); DeleteObject(handle);
    }
    // 5 pseudocode: "F5" label
    {
        const int x = size * 5;
        brush_pen(RGB(70, 90, 130), RGB(150, 180, 230));
        Rectangle(dc, x + 1, 2, x + 15, 14); release();
        HFONT font = CreateFontW(-9, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HGDIOBJ old_font = SelectObject(dc, font);
        SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(235, 240, 250));
        TextOutW(dc, x + 2, 2, L"F5", 2);
        SelectObject(dc, old_font); DeleteObject(font);
    }
    // 6 graph: three linked nodes
    {
        const int x = size * 6;
        HPEN line = CreatePen(PS_SOLID, 1, RGB(120, 170, 235)); HGDIOBJ old = SelectObject(dc, line);
        MoveToEx(dc, x + 8, 5, nullptr); LineTo(dc, x + 8, 8); LineTo(dc, x + 4, 8); LineTo(dc, x + 4, 11);
        MoveToEx(dc, x + 8, 8, nullptr); LineTo(dc, x + 12, 8); LineTo(dc, x + 12, 11);
        SelectObject(dc, old); DeleteObject(line);
        brush_pen(RGB(235, 235, 235), RGB(120, 170, 235));
        Rectangle(dc, x + 5, 1, x + 12, 5);
        Rectangle(dc, x + 1, 11, x + 8, 15);
        Rectangle(dc, x + 9, 11, x + 16, 15);
        release();
    }
    SelectObject(dc, old_bitmap);
    HIMAGELIST list = ImageList_Create(size, size, ILC_COLOR24 | ILC_MASK, count, 0);
    ImageList_AddMasked(list, bitmap, mask);
    DeleteObject(bitmap); DeleteDC(dc);
    return list;
}

LRESULT CALLBACK navband_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_ERASEBKGND) return 1;
    if (message == WM_LBUTTONDOWN || (message == WM_MOUSEMOVE && (wparam & MK_LBUTTON))) {
        RECT client{}; GetClientRect(window, &client);
        if (g_database) if (const auto address = nav_address_at(static_cast<int>(static_cast<short>(LOWORD(lparam))), client.right)) {
            g_current_address = *address;
            if (message == WM_LBUTTONDOWN) navigate_to_address(GetParent(window), *address, TabCtrl_GetCurSel(g_tabs) == 0 ? 0 : 1);
            InvalidateRect(window, nullptr, FALSE);
        }
        return 0;
    }
    if (message == WM_PAINT) {
        PAINTSTRUCT paint{};
        HDC target = BeginPaint(window, &paint);
        RECT client{}; GetClientRect(window, &client);
        HDC dc = target;
        HBRUSH background = CreateSolidBrush(THEMED_RGB(18, 22, 27)); FillRect(dc, &client, background); DeleteObject(background);
        if (g_database && (g_nav_owner != g_database.get() || g_nav_signature != g_database->functions().size())) rebuild_nav_band();
        if (g_database && !g_nav_kind.empty() && client.right > 0) {
            static const COLORREF colors[] = {THEMED_RGB(150, 140, 120), THEMED_RGB(96, 165, 220), THEMED_RGB(184, 150, 96), THEMED_RGB(102, 204, 204), THEMED_RGB(240, 140, 190), THEMED_RGB(70, 76, 84)};
            const int bar_top = 3, bar_bottom = client.bottom - 3;
            for (int x = 0; x < client.right; ++x) {
                const auto b0 = static_cast<std::size_t>(static_cast<double>(x) * kNavBuckets / client.right);
                const auto b1 = (std::max)(b0 + 1, static_cast<std::size_t>(static_cast<double>(x + 1) * kNavBuckets / client.right));
                std::uint8_t kind = g_nav_kind[b0];
                for (auto b = b0; b < b1 && b < kNavBuckets; ++b) if (g_nav_kind[b] == 1 || g_nav_kind[b] == 3 || g_nav_kind[b] == 4) { kind = g_nav_kind[b]; break; }
                HBRUSH brush = CreateSolidBrush(colors[kind]);
                RECT column{x, bar_top, x + 1, bar_bottom}; FillRect(dc, &column, brush); DeleteObject(brush);
            }
            // segment separators
            HPEN separator = CreatePen(PS_SOLID, 1, THEMED_RGB(18, 22, 27)); HGDIOBJ old_pen = SelectObject(dc, separator);
            for (const auto& n : g_nav_sections) {
                const int x = static_cast<int>(static_cast<double>(n.first_bucket) * client.right / kNavBuckets);
                if (x > 0) { MoveToEx(dc, x, bar_top, nullptr); LineTo(dc, x, bar_bottom); }
            }
            SelectObject(dc, old_pen); DeleteObject(separator);
            // current position marker
            for (const auto& n : g_nav_sections) {
                if (g_current_address < n.begin || g_current_address >= n.begin + n.size) continue;
                const auto bucket = n.first_bucket + static_cast<std::size_t>((g_current_address - n.begin) * n.buckets / n.size);
                const int x = static_cast<int>(static_cast<double>(bucket) * client.right / kNavBuckets);
                HPEN marker = CreatePen(PS_SOLID, 2, THEMED_RGB(255, 80, 80)); HGDIOBJ old_marker = SelectObject(dc, marker);
                MoveToEx(dc, x, 0, nullptr); LineTo(dc, x, client.bottom);
                SelectObject(dc, old_marker); DeleteObject(marker);
                HBRUSH tip = CreateSolidBrush(THEMED_RGB(255, 80, 80)); HGDIOBJ old_tip = SelectObject(dc, tip);
                const POINT triangle[3] = {{x - 4, 0}, {x + 4, 0}, {x, 5}};
                Polygon(dc, triangle, 3);
                SelectObject(dc, old_tip); DeleteObject(tip);
                break;
            }
        }
        EndPaint(window, &paint);
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

struct MinimapTransform { double scale{1}; double origin_x{8}, origin_y{8}; int world_width{1}, world_height{1}; };
// Uniform scale (aspect ratio preserved) and centred, like IDA's graph overview.
MinimapTransform minimap_transform(const RECT& client) {
    MinimapTransform t;
    const auto [world_width, world_height] = graph_content_size();
    t.world_width = (std::max)(1, world_width); t.world_height = (std::max)(1, world_height);
    const double map_width = (std::max)(1L, client.right - 16L), map_height = (std::max)(1L, client.bottom - 28L);
    t.scale = (std::min)(map_width / t.world_width, map_height / t.world_height);
    t.origin_x = 8 + (map_width - t.world_width * t.scale) / 2.0;
    t.origin_y = 8 + (map_height - t.world_height * t.scale) / 2.0;
    return t;
}

void minimap_scroll_to(HWND window, int mouse_x, int mouse_y) {
    RECT client{}; GetClientRect(window, &client);
    const auto t = minimap_transform(client);
    const double world_x = (std::max)(0.0, (std::min)(static_cast<double>(t.world_width), (mouse_x - t.origin_x) / t.scale));
    const double world_y = (std::max)(0.0, (std::min)(static_cast<double>(t.world_height), (mouse_y - t.origin_y) / t.scale));
    RECT view{}; GetClientRect(g_view, &view);
    const double zoom = static_cast<double>(g_graph_zoom) / 100.0;
    g_graph_scroll_x = static_cast<int>(world_x * zoom - view.right / 2.0);
    g_graph_scroll_y = static_cast<int>(world_y * zoom - view.bottom / 2.0);
    clamp_graph_scroll(g_view);
    InvalidateRect(g_view, nullptr, FALSE);
    InvalidateRect(window, nullptr, FALSE);
}

LRESULT CALLBACK minimap_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_ERASEBKGND) return 1;
    if ((message == WM_LBUTTONDOWN || (message == WM_MOUSEMOVE && g_minimap_dragging)) && g_view && !g_graph_blocks.empty()) {
        minimap_scroll_to(window, static_cast<int>(static_cast<short>(LOWORD(lparam))), static_cast<int>(static_cast<short>(HIWORD(lparam))));
        if (message == WM_LBUTTONDOWN) { g_minimap_dragging = true; SetCapture(window); invalidate_minimap(); }
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
        PAINTSTRUCT paint{}; HDC target = BeginPaint(window, &paint);
        RECT client{}; GetClientRect(window, &client);
        HDC dc = CreateCompatibleDC(target);
        HBITMAP bitmap = CreateCompatibleBitmap(target, client.right, client.bottom);
        HGDIOBJ old_bitmap = SelectObject(dc, bitmap);
        HBRUSH background = CreateSolidBrush(THEMED_RGB(16, 19, 24));
        FillRect(dc, &client, background); DeleteObject(background);
        if (!g_graph_blocks.empty()) {
            const auto t = minimap_transform(client);
            const auto map_x = [&](int value) { return static_cast<int>(std::lround(t.origin_x + value * t.scale)); };
            const auto map_y = [&](int value) { return static_cast<int>(std::lround(t.origin_y + value * t.scale)); };
            std::unordered_map<std::uint64_t, const GraphBlock*> by_start;
            for (const auto& block : g_graph_blocks) by_start[block.start] = &block;
            for (const auto& edge : g_graph_edges) {
                const auto source = by_start.find(edge.from); const auto target_block = by_start.find(edge.to);
                if (source == by_start.end() || target_block == by_start.end()) continue;
                const auto* a = source->second; const auto* b = target_block->second;
                const COLORREF color = edge.kind == GraphEdgeKind::TrueBranch ? THEMED_RGB(73, 190, 104)
                    : edge.kind == GraphEdgeKind::FalseBranch ? THEMED_RGB(224, 92, 92) : THEMED_RGB(86, 157, 214);
                HPEN pen = CreatePen(PS_SOLID, 1, color); HGDIOBJ old = SelectObject(dc, pen);
                const int sx = map_x(a->x + a->width / 2), sy = map_y(a->y + a->height), tx = map_x(b->x + b->width / 2), ty = map_y(b->y);
                MoveToEx(dc, sx, sy, nullptr); LineTo(dc, sx, (sy + ty) / 2); LineTo(dc, tx, (sy + ty) / 2); LineTo(dc, tx, ty);
                SelectObject(dc, old); DeleteObject(pen);
            }
            for (const auto& block : g_graph_blocks) {
                RECT box{map_x(block.x), map_y(block.y), map_x(block.x + block.width), map_y(block.y + block.height)};
                if (box.right <= box.left) box.right = box.left + 2;
                if (box.bottom <= box.top) box.bottom = box.top + 2;
                const bool active = block.start == g_current_address || std::any_of(block.instructions.begin(), block.instructions.end(),
                    [](const auto* instruction) { return instruction->address == g_current_address; });
                COLORREF block_color = active ? THEMED_RGB(0, 139, 190) : THEMED_RGB(88, 108, 128);
                if (const auto tag = g_graph_colors.find(block.start); tag != g_graph_colors.end()) block_color = tag->second;
                HBRUSH fill = CreateSolidBrush(block_color);
                FillRect(dc, &box, fill); DeleteObject(fill);
                HBRUSH outline = CreateSolidBrush(THEMED_RGB(16, 19, 24)); FrameRect(dc, &box, outline); DeleteObject(outline);
            }
            RECT view{}; GetClientRect(g_view, &view);
            const double zoom = static_cast<double>(g_graph_zoom) / 100.0;
            RECT viewport{
                map_x(static_cast<int>(g_graph_scroll_x / zoom)), map_y(static_cast<int>(g_graph_scroll_y / zoom)),
                map_x(static_cast<int>((g_graph_scroll_x + view.right) / zoom)), map_y(static_cast<int>((g_graph_scroll_y + view.bottom) / zoom))};
            IntersectRect(&viewport, &viewport, &client);
            HPEN frame = CreatePen(PS_SOLID, 2, THEMED_RGB(230, 190, 70)); HGDIOBJ old = SelectObject(dc, frame);
            HGDIOBJ old_brush = SelectObject(dc, GetStockObject(NULL_BRUSH));
            if (viewport.right > viewport.left && viewport.bottom > viewport.top) Rectangle(dc, viewport.left, viewport.top, viewport.right, viewport.bottom);
            SelectObject(dc, old_brush); SelectObject(dc, old); DeleteObject(frame);
        }
        SetBkMode(dc, TRANSPARENT); SetTextColor(dc, THEMED_RGB(170, 185, 198));
        HFONT old_font = reinterpret_cast<HFONT>(SelectObject(dc, g_ui_font));
        TextOutW(dc, 8, client.bottom - 18, L"Graph overview", 14);
        SelectObject(dc, old_font);
        BitBlt(target, 0, 0, client.right, client.bottom, dc, 0, 0, SRCCOPY);
        SelectObject(dc, old_bitmap); DeleteObject(bitmap); DeleteDC(dc);
        EndPaint(window, &paint); return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

std::uint64_t graph_block_start_containing(std::uint64_t address) {
    for (const auto& b : g_graph_blocks) {
        if (b.instructions.empty()) continue;
        const auto lo = b.instructions.front()->address;
        const auto hi = b.instructions.back()->address + b.instructions.back()->size;
        if (address >= lo && address < hi) return b.start;
    }
    return 0;
}

void refresh_graph_after_collapse() {
    rebuild_graph_model();
    if (g_view) { update_graph_scrollbars(g_view); InvalidateRect(g_view, nullptr, FALSE); }
    invalidate_minimap();
}

void toggle_block_collapse(std::uint64_t address) {
    const auto start = graph_block_start_containing(address);
    if (!start) return;
    if (g_collapsed_blocks.contains(start)) g_collapsed_blocks.erase(start);
    else g_collapsed_blocks.insert(start);
    g_session_dirty = true;
    refresh_graph_after_collapse();
}

void expand_all_blocks() {
    if (g_collapsed_blocks.empty()) return;
    g_collapsed_blocks.clear();
    g_session_dirty = true;
    refresh_graph_after_collapse();
}

// Index of the group whose member list contains `address` (a block start), or -1.
int graph_group_index_for(std::uint64_t address) {
    for (std::size_t i = 0; i < g_graph_groups.size(); ++i)
        if (std::find(g_graph_groups[i].begin(), g_graph_groups[i].end(), address) != g_graph_groups[i].end())
            return static_cast<int>(i);
    return -1;
}

bool address_in_any_group(std::uint64_t address) { return graph_group_index_for(address) >= 0; }

void toggle_graph_selection(std::uint64_t block_start) {
    if (!block_start) return;
    if (g_graph_selection.contains(block_start)) g_graph_selection.erase(block_start);
    else g_graph_selection.insert(block_start);
    if (g_view) InvalidateRect(g_view, nullptr, FALSE);
    invalidate_minimap();
}

void clear_graph_selection() {
    if (g_graph_selection.empty()) return;
    g_graph_selection.clear();
    if (g_view) InvalidateRect(g_view, nullptr, FALSE);
    invalidate_minimap();
}

// Fold the current selection into a new group. Members already belonging to an
// existing group are skipped so member sets never overlap.
void group_selected_nodes() {
    std::vector<std::uint64_t> members;
    for (const auto s : g_graph_selection) if (!address_in_any_group(s)) members.push_back(s);
    g_graph_selection.clear();
    if (members.size() < 2) { if (g_view) InvalidateRect(g_view, nullptr, FALSE); invalidate_minimap(); return; }
    g_graph_groups.push_back(std::move(members));
    g_session_dirty = true;
    refresh_graph_after_collapse();
}

// Dissolve the group that owns `address` (its anchor or any member).
bool ungroup_at(std::uint64_t address) {
    const int gi = graph_group_index_for(address);
    if (gi < 0) return false;
    g_graph_groups.erase(g_graph_groups.begin() + gi);
    g_session_dirty = true;
    refresh_graph_after_collapse();
    return true;
}

// Double-click on a node: a group dissolves, anything else collapses/expands.
void graph_handle_double_click(std::uint64_t address) {
    if (ungroup_at(address)) return;
    toggle_block_collapse(address);
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
    AppendMenuW(context, MF_POPUP, reinterpret_cast<UINT_PTR>(build_patch_submenu()), L"Patch");
    AppendMenuW(context, MF_STRING, ID_NOP_BLOCK, L"Patch Function (NOP)");
    AppendMenuW(context, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(context, MF_STRING, ID_TOGGLE_BP, L"Toggle Breakpoint");
    AppendMenuW(context, MF_STRING, ID_DECOMPILE, L"View Pseudocode (F5)");
    AppendMenuW(context, MF_STRING, ID_SIGMAKER, L"Generate Signature");
    AppendMenuW(context, MF_STRING, ID_RENAME_LABEL, L"Rename Label");
    AppendMenuW(context, MF_STRING, ID_ADD_COMMENT, L"Add Comment");
    AppendMenuW(context, MF_STRING, ID_ASSIGN_TYPE, L"Assign Type...");
    AppendMenuW(context, MF_STRING, ID_HIDE_FUNCTION, L"Hide Function from Analysis");
    AppendMenuW(context, MF_SEPARATOR, 0, nullptr);
    {
        const auto start = graph_block_start_containing(*address);
        const bool collapsed = start && g_collapsed_blocks.contains(start);
        AppendMenuW(context, MF_STRING, ID_GRAPH_COLLAPSE, collapsed ? L"Expand Node\tDbl-click" : L"Collapse Node\tDbl-click");
        AppendMenuW(context, MF_STRING | (g_collapsed_blocks.empty() ? MF_GRAYED : 0), ID_GRAPH_EXPAND_ALL, L"Expand All Nodes");
        AppendMenuW(context, MF_SEPARATOR, 0, nullptr);
        std::size_t selectable = 0;
        for (const auto s : g_graph_selection) if (!address_in_any_group(s)) ++selectable;
        std::wstring group_text = L"Group Selected Nodes (" + std::to_wstring(selectable) + L")\tCtrl+click";
        AppendMenuW(context, MF_STRING | (selectable >= 2 ? 0 : MF_GRAYED), ID_GRAPH_GROUP, group_text.c_str());
        AppendMenuW(context, MF_STRING | (graph_group_index_for(*address) >= 0 ? 0 : MF_GRAYED), ID_GRAPH_UNGROUP, L"Ungroup\tDbl-click");
        AppendMenuW(context, MF_STRING | (g_graph_selection.empty() ? MF_GRAYED : 0), ID_GRAPH_CLEAR_SELECTION, L"Clear Selection");
    }
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
    if (message == WM_LBUTTONDBLCLK) {
        if (const auto address = graph_address_at(static_cast<short>(LOWORD(lparam)), static_cast<short>(HIWORD(lparam)))) {
            graph_handle_double_click(*address);
            return 0;
        }
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
        // Ctrl+click tags a node for grouping instead of starting a drag.
        if (GetKeyState(VK_CONTROL) < 0) {
            if (const auto* block = graph_block_at(x, y)) toggle_graph_selection(block->start);
            return 0;
        }
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
        HDC target_dc = BeginPaint(window, &paint);
        RECT client{}; GetClientRect(window, &client);
        // Manual double buffering (replaces WS_EX_COMPOSITED, which left the hidden
        // text editor's pixels on top of the graph after switching tabs).
        HDC dc = CreateCompatibleDC(target_dc);
        HBITMAP buffer_bitmap = CreateCompatibleBitmap(target_dc, (std::max)(1L, client.right), (std::max)(1L, client.bottom));
        HGDIOBJ buffer_old = SelectObject(dc, buffer_bitmap);
        const double scale = static_cast<double>(g_graph_zoom) / 100.0;
        HBRUSH graph_background = CreateSolidBrush(THEMED_RGB(24, 27, 32));
        FillRect(dc, &client, graph_background); DeleteObject(graph_background);
        SetBkMode(dc, TRANSPARENT);
        HGDIOBJ graph_font = SelectObject(dc, g_code_font);
        if (!g_database) {
            SetTextColor(dc, THEMED_RGB(170, 239, 207));
            TextOutW(dc, 24, 24, L"Gandon View-A", 13);
            TextOutW(dc, 24, 52, L"Open a binary to build the control-flow graph.", 45);
        } else {
            RECT header{12, 8, 500, 32};
            HBRUSH header_brush = CreateSolidBrush(THEMED_RGB(18, 22, 27));
            FillRect(dc, &header, header_brush); DeleteObject(header_brush);
            std::wostringstream graph_header;
            graph_header << L"CFG  0x" << std::hex << std::uppercase << g_current_address
                         << L"   |   blocks " << std::dec << g_graph_blocks.size()
                         << L"   |   zoom " << g_graph_zoom << L"%";
            SetTextColor(dc, THEMED_RGB(155, 190, 214));
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
                const COLORREF edge_color = edge.kind == GraphEdgeKind::TrueBranch ? THEMED_RGB(73, 190, 104)
                    : edge.kind == GraphEdgeKind::FalseBranch ? THEMED_RGB(224, 92, 92) : THEMED_RGB(86, 157, 214);
                HPEN edge_pen = CreatePen(PS_SOLID, edge.kind == GraphEdgeKind::Unconditional ? 3 : 2, edge_color);
                HGDIOBJ old_pen = SelectObject(dc, edge_pen);
                MoveToEx(dc, sx, sy, nullptr); LineTo(dc, sx, (sy + ty) / 2); LineTo(dc, tx, (sy + ty) / 2); LineTo(dc, tx, ty);
                {
                    HBRUSH arrow_brush = CreateSolidBrush(edge_color); HGDIOBJ old_arrow = SelectObject(dc, arrow_brush);
                    const POINT arrow[3] = {{tx, ty}, {tx - 6, ty - 11}, {tx + 6, ty - 11}};
                    Polygon(dc, arrow, 3);
                    SelectObject(dc, old_arrow); DeleteObject(arrow_brush);
                }
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
                const bool active_block = block.start == g_current_address || std::any_of(block.instructions.begin(), block.instructions.end(), [](const auto* instruction) { return instruction->address == g_current_address; });
                const bool selected = g_graph_selection.contains(block.start);
                COLORREF block_color = active_block ? THEMED_RGB(36, 57, 66) : THEMED_RGB(32, 39, 47);
                if (block.is_group) block_color = active_block ? THEMED_RGB(48, 44, 66) : THEMED_RGB(40, 37, 56);  // group tint
                if (const auto color = g_graph_colors.find(block.start); color != g_graph_colors.end()) block_color = color->second;
                HBRUSH fill = CreateSolidBrush(block_color);
                FillRect(dc, &box, fill); DeleteObject(fill);
                HPEN border = CreatePen(PS_SOLID, active_block ? 2 : 1, active_block ? THEMED_RGB(0, 160, 210) : THEMED_RGB(62, 78, 91));
                HGDIOBJ old_pen = SelectObject(dc, border); HGDIOBJ old_brush = SelectObject(dc, GetStockObject(NULL_BRUSH));
                Rectangle(dc, box.left, box.top, box.right, box.bottom); SelectObject(dc, old_pen); DeleteObject(border);
                if (selected) {   // amber outline around nodes tagged for grouping
                    const int inset = (std::max)(2, static_cast<int>(std::lround(2 * scale)));
                    HPEN mark = CreatePen(PS_SOLID, (std::max)(2, static_cast<int>(std::lround(3 * scale))), THEMED_RGB(230, 190, 70));
                    HGDIOBJ old_mark = SelectObject(dc, mark);
                    Rectangle(dc, box.left + inset, box.top + inset, box.right - inset, box.bottom - inset);
                    SelectObject(dc, old_mark); DeleteObject(mark);
                }
                SelectObject(dc, old_brush);
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
                std::wstring title;
                if (block.is_group && !g_custom_labels.contains(block.start)) {
                    std::wostringstream value; value << L"⊞ group_" << std::hex << std::uppercase << block.start; title = value.str();
                } else if (g_custom_labels.contains(block.start)) title = g_custom_labels[block.start];
                else {
                    const auto known = ida_views(*g_database).name_at(block.start);
                    if (!known.empty()) title = wide(known);
                    else { std::wostringstream value; value << L"loc_" << std::hex << std::uppercase << block.start; title = value.str(); }
                }
                title += L":";
                const bool collapsed = g_collapsed_blocks.contains(block.start) || block.is_group;
                // [-]/[+] toggle glyph at the right edge of the header.
                const std::wstring glyph = collapsed ? L"[+]" : L"[-]";
                SetTextColor(dc, THEMED_RGB(155, 170, 184)); TextOutW(dc, x + width - sx(34), y + sx(8), glyph.c_str(), 3);
                SetTextColor(dc, block.is_group ? THEMED_RGB(206, 184, 247) : THEMED_RGB(170, 239, 207)); TextOutW(dc, x + sx(12), y + sx(8), title.c_str(), static_cast<int>(title.size()));
                HPEN separator = CreatePen(PS_SOLID, 1, THEMED_RGB(52, 64, 74));
                HGDIOBJ old_separator = SelectObject(dc, separator);
                MoveToEx(dc, x + 1, y + sx(27), nullptr); LineTo(dc, x + width - 1, y + sx(27));
                SelectObject(dc, old_separator); DeleteObject(separator);
                int line_y = y + sx(30);
                if (block.is_group) {
                    std::wostringstream summary; summary << L"▣ group of " << block.group_members << L" blocks (double-click to ungroup)";
                    const auto text = summary.str();
                    SetTextColor(dc, THEMED_RGB(206, 184, 247)); TextOutW(dc, x + sx(12), line_y, text.c_str(), static_cast<int>(text.size()));
                } else if (collapsed) {
                    std::wostringstream summary; summary << L"▸ " << block.instructions.size() << L" instruction" << (block.instructions.size() == 1 ? L"" : L"s") << L" (double-click to expand)";
                    const auto text = summary.str();
                    SetTextColor(dc, THEMED_RGB(155, 170, 184)); TextOutW(dc, x + sx(12), line_y, text.c_str(), static_cast<int>(text.size()));
                }
                if (g_custom_comments.contains(block.start) && !collapsed) {
                    const auto comment = L"// " + g_custom_comments[block.start];
                    SetTextColor(dc, THEMED_RGB(155, 170, 184)); TextOutW(dc, x + sx(12), line_y, comment.c_str(), static_cast<int>(comment.size())); line_y += sx(18);
                }
                for (std::size_t index = 0; index < block.instructions.size() && index < 40 && !collapsed; ++index) {
                    const auto& instruction = *block.instructions[index];
                    const auto& views = ida_views(*g_database);
                    const auto address = wide(views.address_text(instruction.address));
                    const auto formatted = wide(views.format_instruction(instruction));
                    const auto split = formatted.find(L' ');
                    const std::wstring mnemonic = formatted.substr(0, split);
                    const std::wstring operands = split == std::wstring::npos ? std::wstring() : formatted.substr(formatted.find_first_not_of(L' ', split));
                    SetTextColor(dc, THEMED_RGB(106, 168, 219)); TextOutW(dc, x + sx(10), line_y, address.c_str(), static_cast<int>(address.size()));
                    const COLORREF mnemonic_color = instruction.mnemonic == "call" ? THEMED_RGB(220, 170, 90)
                        : (!instruction.mnemonic.empty() && instruction.mnemonic.front() == 'j') ? THEMED_RGB(78, 201, 176)
                        : instruction.mnemonic == "ret" ? THEMED_RGB(224, 92, 93) : THEMED_RGB(120, 170, 235);
                    const int mnemonic_x = x + sx(10) + sx(9) * static_cast<int>(address.size()) + sx(14);
                    SetTextColor(dc, mnemonic_color); TextOutW(dc, mnemonic_x, line_y, mnemonic.c_str(), static_cast<int>(mnemonic.size()));
                    if (mnemonic_x + sx(70) < box.right - sx(8)) {
                        RECT operand_rect{mnemonic_x + sx(70), line_y, box.right - sx(8), line_y + sx(18)};
                        SetTextColor(dc, THEMED_RGB(215, 228, 238));
                        DrawTextW(dc, operands.c_str(), static_cast<int>(operands.size()), &operand_rect,
                                  DT_SINGLELINE | DT_NOPREFIX | DT_LEFT | DT_END_ELLIPSIS);
                    }
                    line_y += sx(18);
                }
                if (scaled_font) { SelectObject(dc, old_block_font); DeleteObject(scaled_font); }
            }
        }
        SelectObject(dc, graph_font); BitBlt(target_dc, 0, 0, client.right, client.bottom, dc, 0, 0, SRCCOPY); SelectObject(dc, buffer_old); DeleteObject(buffer_bitmap); DeleteDC(dc); EndPaint(window, &paint); return 0;
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

// ---------------------------------------------------------------------------
// Plugin ABI v2: text-returning analysis/edit calls (listing, decompiler,
// strings, search, live patch...). Each one runs the real work on the UI
// thread via WM_RUN_ON_UI so a plugin's own background thread (an MCP
// server, say) never touches g_database directly.
// ---------------------------------------------------------------------------

void run_on_ui_thread(const std::function<void()>& job) {
    if (!g_main_window || GetCurrentThreadId() == GetWindowThreadProcessId(g_main_window, nullptr)) { job(); return; }
    auto copy = job; // SendMessageW blocks until the handler returns, so this local outlives the call
    SendMessageW(g_main_window, WM_RUN_ON_UI, 0, reinterpret_cast<LPARAM>(&copy));
}

// strtok-style: the returned pointer is only valid until the next call to
// THIS SAME function (each has its own static buffer), which is exactly how
// the plugin ABI documents it.
const char* native_plugin_info_json(void*) {
    static std::string buffer;
    run_on_ui_thread([&] {
        buffer.clear();
        if (!g_database) return;
        const auto& image = g_database->image();
        std::ostringstream out;
        out << "{\"path\":\"";
        for (const auto ch : image.path.generic_string()) { if (ch == '"' || ch == '\'') out << '\''; out << ch; }
        out << "\",\"format\":\"" << (image.format == gandon::BinaryFormat::PE ? "PE" : image.format == gandon::BinaryFormat::ELF ? "ELF" : "unknown")
            << "\",\"architecture\":\"" << (image.architecture == gandon::MachineArchitecture::X64 ? "x64" : image.architecture == gandon::MachineArchitecture::X86 ? "x86" : image.architecture == gandon::MachineArchitecture::ARM64 ? "arm64" : "unknown")
            << "\",\"is_64_bit\":" << (image.is_64_bit ? "true" : "false")
            << ",\"image_base\":\"0x" << std::hex << image.image_base << "\",\"entry_point\":\"0x" << image.entry_point << std::dec
            << "\",\"size\":" << image.bytes.size() << ",\"function_count\":" << g_database->functions().size()
            << ",\"xref_count\":" << g_database->xrefs().size() << "}";
        buffer = out.str();
    });
    return buffer.empty() ? nullptr : buffer.c_str();
}

int native_plugin_resolve_address(void*, const char* text, uint64_t* out_address) {
    if (!text || !out_address) return 0;
    int ok = 0;
    run_on_ui_thread([&] {
        if (!g_database) return;
        if (const auto resolved = resolve_jump_target(wide(text))) { *out_address = *resolved; ok = 1; }
    });
    return ok;
}

const char* native_plugin_listing_at(void*, uint64_t address) {
    static std::string buffer;
    run_on_ui_thread([&] {
        buffer.clear();
        if (!g_database || !address) return;
        buffer = utf8_from_wide(listing_text_at(*g_database, address));
    });
    return buffer.empty() ? nullptr : buffer.c_str();
}

const char* native_plugin_decompile_at(void*, uint64_t address, int address_comments, int* out_ok) {
    static std::string buffer;
    int ok = 0;
    run_on_ui_thread([&] {
        buffer.clear();
        if (!g_database || !address) return;
        const auto result = gandon::decompile_function_at(*g_database, address, address_comments != 0, [](std::uint64_t a) -> std::string {
            const auto label = g_custom_labels.find(a);
            return label == g_custom_labels.end() ? std::string{} : utf8_from_wide(label->second);
        }, &g_noreturn);
        ok = result.ok ? 1 : 0;
        buffer = result.ok ? result.text : result.error;
    });
    if (out_ok) *out_ok = ok;
    return buffer.empty() ? nullptr : buffer.c_str();
}

const char* native_plugin_hex_dump_at(void*, uint64_t address, uint64_t) {
    static std::string buffer;
    run_on_ui_thread([&] {
        buffer.clear();
        if (!g_database || !address) return;
        buffer = utf8_from_wide(hex_text(g_database->image(), address));
    });
    return buffer.empty() ? nullptr : buffer.c_str();
}

const char* native_plugin_strings(void*, uint64_t) {
    static std::string buffer;
    run_on_ui_thread([&] {
        buffer.clear();
        if (!g_database) return;
        buffer = utf8_from_wide(strings_text(g_database->image()));
    });
    return buffer.empty() ? nullptr : buffer.c_str();
}

const char* native_plugin_imports_text(void*) {
    static std::string buffer;
    run_on_ui_thread([&] { buffer.clear(); if (g_database) buffer = utf8_from_wide(imports_text(g_database->image())); });
    return buffer.empty() ? nullptr : buffer.c_str();
}

const char* native_plugin_exports_text(void*) {
    static std::string buffer;
    run_on_ui_thread([&] { buffer.clear(); if (g_database) buffer = utf8_from_wide(exports_text(g_database->image())); });
    return buffer.empty() ? nullptr : buffer.c_str();
}

const char* native_plugin_resources_text(void*) {
    static std::string buffer;
    run_on_ui_thread([&] { buffer.clear(); if (g_database) buffer = utf8_from_wide(resources_text(g_database->image())); });
    return buffer.empty() ? nullptr : buffer.c_str();
}

const char* native_plugin_segments_text(void*) {
    static std::string buffer;
    run_on_ui_thread([&] { buffer.clear(); if (g_database) buffer = utf8_from_wide(memory_map_text(*g_database)); });
    return buffer.empty() ? nullptr : buffer.c_str();
}

const char* native_plugin_search_bytes(void*, const char* pattern_text) {
    static std::string buffer;
    run_on_ui_thread([&] {
        buffer.clear();
        if (!g_database || !pattern_text) return;
        std::vector<std::optional<std::uint8_t>> pattern;
        std::istringstream tokens(pattern_text);
        std::string token;
        bool bad = false;
        while (tokens >> token) {
            if (token == "??" || token == "?") { pattern.push_back(std::nullopt); continue; }
            try { pattern.push_back(static_cast<std::uint8_t>(std::stoul(token, nullptr, 16))); } catch (...) { bad = true; break; }
        }
        if (bad || pattern.empty()) return;
        const auto matches = g_database->image().find_pattern(pattern, 500);
        std::ostringstream out;
        for (std::size_t i = 0; i < matches.size(); ++i) { if (i) out << ' '; out << "0x" << std::hex << matches[i]; }
        buffer = out.str();
    });
    return buffer.c_str(); // empty string is a valid "no matches" result, unlike the other callbacks
}

const char* native_plugin_search_text(void*, const char* text) {
    static std::string buffer;
    run_on_ui_thread([&] {
        buffer.clear();
        if (!g_database || !text) return;
        const std::string needle = text;
        const std::vector<std::uint8_t> pattern(needle.begin(), needle.end());
        const auto matches = g_database->image().find_bytes(pattern);
        std::ostringstream out;
        for (std::size_t i = 0; i < matches.size() && i < 500; ++i) { if (i) out << ' '; out << "0x" << std::hex << matches[i]; }
        buffer = out.str();
    });
    return buffer.c_str();
}

const char* native_plugin_run_auto_analysis(void*) {
    static std::string buffer;
    run_on_ui_thread([&] {
        buffer.clear();
        if (!g_database) { buffer = "no binary open"; return; }
        gui_auto_analysis(*g_database);
        fill_tree();
        refresh_views(g_main_window);
        g_session_dirty = true;
        buffer = utf8_from_wide(g_auto_analysis_summary);
    });
    return buffer.empty() ? nullptr : buffer.c_str();
}

void set_text_entry(bool comment, std::uint64_t address, bool present, const std::wstring& text) {
    auto& map = comment ? g_custom_comments : g_custom_labels;
    if (present) map[address] = text; else map.erase(address);
}

// Stores a rename / comment change for Ctrl+Z.
void record_text_edit(bool comment, std::uint64_t address, const std::wstring& after) {
    auto& map = comment ? g_custom_comments : g_custom_labels;
    TextEdit edit; edit.comment = comment; edit.address = address; edit.after = after;
    if (const auto it = map.find(address); it != map.end()) { edit.had_before = true; edit.before = it->second; }
    if (edit.had_before && edit.before == after) return;
    g_edit_undo.push_back(std::move(edit)); g_edit_redo.clear();
    g_timeline.push_back('e'); g_timeline_redo.clear();
}

int native_plugin_rename(void*, uint64_t address, const char* new_name) {
    if (!new_name || !*new_name) return 0;
    int ok = 0;
    run_on_ui_thread([&] {
        if (!g_database || !address) return;
        record_text_edit(false, address, wide(new_name));
        g_custom_labels[address] = wide(new_name);
        g_session_dirty = true;
        refresh_views(g_main_window);
        ok = 1;
    });
    return ok;
}

int native_plugin_add_comment(void*, uint64_t address, const char* comment_utf8) {
    if (!comment_utf8) return 0;
    int ok = 0;
    run_on_ui_thread([&] {
        if (!g_database || !address) return;
        record_text_edit(true, address, wide(comment_utf8));
        g_custom_comments[address] = wide(comment_utf8);
        g_session_dirty = true;
        refresh_views(g_main_window);
        ok = 1;
    });
    return ok;
}

int native_plugin_patch_bytes_live(void*, uint64_t address, const uint8_t* bytes, uint64_t size) {
    if (!bytes || !size) return 0;
    int ok = 0;
    run_on_ui_thread([&] {
        if (!g_database || !address) return;
        const auto offset = g_database->image().va_to_file_offset(address);
        if (!offset) return;
        std::vector<std::uint8_t> replacement(bytes, bytes + size), original;
        std::string error;
        if (!g_database->patch_bytes(address, replacement, original, error)) return;
        std::vector<PatchChange> changes;
        for (std::size_t i = 0; i < replacement.size(); ++i)
            if (replacement[i] != original[i]) changes.push_back({*offset + i, original[i], replacement[i]});
        if (!changes.empty()) { g_patch_undo.push_back(std::move(changes)); g_patch_redo.clear(); g_timeline.push_back('p'); g_timeline_redo.clear(); }
        refresh_after_patch(g_main_window);
        ok = 1;
    });
    return ok;
}

// Mirrors `require_text`'s strtok-style buffer convention: a plugin can read
// the reason a save/load call returned 0 via `last_database_error`, valid
// until the next save_database/load_database call.
std::string g_last_database_error;

int native_plugin_save_database(void*, const char* path) {
    if (!path || !*path) return 0;
    int ok = 0;
    run_on_ui_thread([&] {
        g_last_database_error.clear();
        if (!g_database) { g_last_database_error = "no binary open"; return; }
        std::string error;
        if (!write_database_file(std::filesystem::path(wide(path)), error)) { g_last_database_error = error; return; }
        g_session_path = wide(path);
        g_session_dirty = false;
        ok = 1;
    });
    return ok;
}

int native_plugin_load_database(void*, const char* path) {
    if (!path || !*path) return 0;
    int ok = 0;
    run_on_ui_thread([&] {
        std::string error;
        ok = load_database_core(g_main_window, std::filesystem::path(wide(path)), /*allow_legacy_json=*/false, error) ? 1 : 0;
        g_last_database_error = error;
    });
    return ok;
}

const char* native_plugin_last_database_error(void*) {
    static std::string buffer;
    run_on_ui_thread([&] { buffer = g_last_database_error; });
    return buffer.c_str();
}

void load_native_plugins(HWND window) {
    if (!g_native_plugin_host) g_native_plugin_host = std::make_unique<gandon::PluginHost>();
    g_native_plugin_host->unload_all();
    for (const auto& action : g_native_plugin_actions) DeleteMenu(g_plugins_menu, action.menu_id, MF_BYCOMMAND);
    g_native_plugin_actions.clear();
    wchar_t module_path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, module_path, MAX_PATH);
    const auto directory = std::filesystem::path(module_path).parent_path();
    // `static`: a loaded DLL keeps the `const GandonPluginHost*` it was handed
    // in GandonPluginInit and may dereference it for as long as it stays
    // loaded (an MCP-server plugin reads it from a background thread for the
    // whole session). A function-local non-static struct here was destroyed
    // the moment load_native_plugins() returned, leaving every plugin with a
    // dangling host pointer after that.
    static GandonPluginHost api{};
    api = GandonPluginHost{};
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
    api.info_json = native_plugin_info_json;
    api.resolve_address = native_plugin_resolve_address;
    api.listing_at = native_plugin_listing_at;
    api.decompile_at = native_plugin_decompile_at;
    api.hex_dump_at = native_plugin_hex_dump_at;
    api.strings = native_plugin_strings;
    api.imports_text = native_plugin_imports_text;
    api.exports_text = native_plugin_exports_text;
    api.resources_text = native_plugin_resources_text;
    api.segments_text = native_plugin_segments_text;
    api.search_bytes = native_plugin_search_bytes;
    api.search_text = native_plugin_search_text;
    api.run_auto_analysis = native_plugin_run_auto_analysis;
    api.rename = native_plugin_rename;
    api.add_comment = native_plugin_add_comment;
    api.patch_bytes = native_plugin_patch_bytes_live;
    api.save_database = native_plugin_save_database;
    api.load_database = native_plugin_load_database;
    api.last_database_error = native_plugin_last_database_error;
    std::string error;
    if (!g_native_plugin_host->load_directory(directory, api, error)) {
        MessageBoxW(window, wide(error).c_str(), L"Native Plugins", MB_ICONERROR);
        return;
    }
    DrawMenuBar(window);
    SetWindowTextW(g_status, L"Native plugins loaded.");
}


std::string utf8_from_wide(const std::wstring& value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring crlf_wide(const std::string& utf8) {
    const auto text = wide(utf8);
    std::wstring out;
    out.reserve(text.size() + text.size() / 20);
    for (const auto ch : text) {
        if (ch == L'\n') out.push_back(L'\r');
        out.push_back(ch);
    }
    return out;
}

void output_log(const std::wstring& line) {
    if (!g_output) return;
    const auto length = GetWindowTextLengthW(g_output);
    SendMessageW(g_output, EM_SETSEL, length, length);
    const std::wstring text = line + L"\r\n";
    SendMessageW(g_output, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
    SendMessageW(g_output, EM_SCROLLCARET, 0, 0);
}

void gui_auto_analysis(gandon::AnalysisDatabase& db) {
    g_noreturn.clear();
    g_auto_analysis_summary.clear();
    output_log(L"Loading: " + db.image().path.wstring());
    output_log(L"Running auto-analysis (functions, thunks, signatures, noreturn)...");
    try {
        gandon::SignatureSet signatures;
        wchar_t module[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, module, MAX_PATH);
        const auto directory = std::filesystem::path(module).parent_path() / L"signatures";
        std::error_code ec;
        if (std::filesystem::is_directory(directory, ec)) {
            for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
                { auto ext = entry.path().extension().wstring(); for (auto& ch : ext) ch = static_cast<wchar_t>(std::towlower(ch)); if (ext != L".sig" && ext != L".pat") continue; }
                std::string error;
                signatures.load_file(entry.path(), error);
            }
        }
        gandon::AutoAnalysisOptions options;
        options.signatures = &signatures;
        const auto report = gandon::run_auto_analysis(db, options);
        g_noreturn = report.noreturn;
        std::wostringstream summary;
        summary << L"Auto-analysis: +" << report.functions_added << L" functions, " << report.import_thunks << L" import thunks, "
                << report.functions_renamed << L" signature names, " << report.noreturn_functions << L" noreturn";
        g_auto_analysis_summary = summary.str();
        output_log(g_auto_analysis_summary);
        output_log(L"The initial autoanalysis has been finished.");
    } catch (const std::exception&) {
        g_auto_analysis_summary = L"Auto-analysis stopped after an internal error.";
    }
}

// Cached IDA-style text renderer; rebuilt when the database or user names change.
gandon::IdaViews& ida_views(const gandon::AnalysisDatabase& db) {
    static std::unique_ptr<gandon::IdaViews> views;
    static const gandon::AnalysisDatabase* owner = nullptr;
    static std::size_t signature = 0;
    ensure_types(db.image().is_64_bit);
    std::size_t current = g_custom_labels.size() * 1000003u + g_custom_comments.size() + g_noreturn.size() * 7919u + db.functions().size()
        + g_types_version * 104729u + g_struct_ops.size() * 31u + g_enum_ops.size() * 37u + g_prototypes.size() * 41u;
    for (const auto& [address, text] : g_struct_ops) current ^= address * 13u + std::hash<std::string>{}(text);
    for (const auto& [address, text] : g_enum_ops) current ^= address * 19u + std::hash<std::string>{}(text);
    for (const auto& [address, text] : g_prototypes) current ^= address * 23u + std::hash<std::string>{}(text);
    for (const auto& [address, text] : g_custom_labels) current ^= address * 31u + std::hash<std::wstring>{}(text);
    for (const auto& [address, text] : g_custom_comments) current ^= address * 17u + std::hash<std::wstring>{}(text);
    if (!views || owner != &db || signature != current) {
        gandon::IdaViewConfig config;
        for (const auto& [address, text] : g_custom_labels) config.user_names[address] = utf8_from_wide(text);
        for (const auto& [address, text] : g_custom_comments) config.user_comments[address] = utf8_from_wide(text);
        config.noreturn = g_noreturn;
        config.types = &g_types; config.struct_offsets = g_struct_ops; config.enum_operands = g_enum_ops; config.prototypes = g_prototypes;
        views = std::make_unique<gandon::IdaViews>(db, std::move(config));
        owner = &db;
        signature = current;
    }
    return *views;
}

std::wstring listing_text(const gandon::AnalysisDatabase& db) {
    return crlf_wide(ida_views(db).listing(db.image().entry_point));
}

std::wstring listing_text_at(const gandon::AnalysisDatabase& db, std::uint64_t address) {
    return crlf_wide(ida_views(db).listing(address));
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
    // Structured decompiler first; the line-by-line translator below stays as the fallback
    // for architectures / functions the structured engine cannot handle.
    if (db.function_at(address)) {
        const auto structured = gandon::decompile_function_at(db, address, false, [](std::uint64_t a) -> std::string {
            const auto label = g_custom_labels.find(a);
            if (label == g_custom_labels.end()) return {};
            std::string narrow; for (const wchar_t c : label->second) narrow.push_back(c < 0x80 ? static_cast<char>(c) : '_');
            return narrow;
        }, &g_noreturn);
        if (structured.ok) {
            std::wstring text;
            text.reserve(structured.text.size() + 256);
            text += L"// Decompiled by Gandon-PRO structured engine\r\n";
            if (const auto fn = db.function_at(address)) if (const auto proto = g_prototypes.find(fn->get().start); proto != g_prototypes.end()) text += L"// prototype: " + wide(proto->second) + L"\r\n";
            if (structured.goto_count) text += L"// " + std::to_wstring(structured.goto_count) + L" unstructured jump(s) remain\r\n";
            std::string body = structured.text;
            if (const auto fn = db.function_at(address)) if (const auto proto = g_prototypes.find(fn->get().start); proto != g_prototypes.end()) {
                // Replace the generated signature line with the user's prototype.
                std::size_t line_start = 0;
                while (line_start < body.size()) {
                    const auto line_end = body.find('\n', line_start);
                    const std::string current = body.substr(line_start, line_end == std::string::npos ? std::string::npos : line_end - line_start);
                    if (!current.empty() && current.rfind("//", 0) != 0 && current.find('(') != std::string::npos && current.back() == ')') {
                        body.replace(line_start, current.size(), proto->second); break;
                    }
                    if (line_end == std::string::npos) break;
                    line_start = line_end + 1;
                }
            }
            for (const char c : body) { if (c == '\n') text += L"\r\n"; else text.push_back(static_cast<unsigned char>(c)); }
            return text;
        }
    }
    const auto function = db.function_at(address);
    const auto start = function ? function->get().start : address;
    const auto name = function ? wide(function->get().name) : pseudocode_label(start);
    std::vector<gandon::Instruction> decoded_instructions;
    const std::vector<gandon::Instruction>* instructions = nullptr;
    if (function && !function->get().instructions.empty()) instructions = &function->get().instructions;
    else {
        decoded_instructions = gandon::decode_x64(db.image(), start, 256);
        instructions = &decoded_instructions;
    }
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
    for (const auto& instruction : *instructions) {
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
    for (const auto& instruction : *instructions) {
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
    return crlf_wide(ida_views(db).xrefs_overview());
}

std::wstring memory_map_text(const gandon::AnalysisDatabase& db) {
    return crlf_wide(ida_views(db).segments());
}

std::uint64_t file_offset_to_va(const gandon::BinaryImage& image, std::size_t offset);

std::optional<std::pair<std::uint32_t, std::uint32_t>> pe_directory(const gandon::BinaryImage& image, std::size_t index) {
    if (image.format != gandon::BinaryFormat::PE || image.bytes.size() < 0x40) return std::nullopt;
    auto read16 = [&](std::size_t offset) -> std::uint16_t { return offset + 2 <= image.bytes.size() ? static_cast<std::uint16_t>(image.bytes[offset] | (image.bytes[offset + 1] << 8)) : 0; };
    auto read32 = [&](std::size_t offset) -> std::uint32_t { return offset + 4 <= image.bytes.size() ? static_cast<std::uint32_t>(image.bytes[offset] | (image.bytes[offset + 1] << 8) | (image.bytes[offset + 2] << 16) | (image.bytes[offset + 3] << 24)) : 0; };
    const auto pe = static_cast<std::size_t>(read32(0x3c)); if (pe > image.bytes.size() || image.bytes.size() - pe < 24) return std::nullopt;
    const auto optional = pe + 24;
    const auto optional_size = static_cast<std::size_t>(read16(pe + 20));
    if (optional > image.bytes.size() || optional_size > image.bytes.size() - optional) return std::nullopt;
    const auto magic = read16(optional);
    const bool is_pe32_plus = magic == 0x20b;
    if (!is_pe32_plus && magic != 0x10b) return std::nullopt;
    const std::size_t number_of_directories_offset = is_pe32_plus ? 108 : 92;
    const std::size_t directory_offset = is_pe32_plus ? 112 : 96;
    if (optional_size < number_of_directories_offset + 4 || optional_size < directory_offset) return std::nullopt;
    const auto number_of_directories = read32(optional + number_of_directories_offset);
    if (index >= number_of_directories || index > (optional_size - directory_offset) / 8 ||
        (optional_size - directory_offset) / 8 - index < 1) return std::nullopt;
    const auto directory = optional + directory_offset + index * 8;
    return std::make_pair(read32(directory), read32(directory + 4));
}

std::wstring import_key(const std::wstring& dll, const std::wstring& name) {
    std::wstring key = dll + L"\n" + name;
    std::transform(key.begin(), key.end(), key.begin(), [](wchar_t value) { return static_cast<wchar_t>(towlower(value)); });
    return key;
}

std::vector<ImportRecord> enumerate_imports(const gandon::BinaryImage& image) {
    constexpr std::size_t max_import_records = 20000;
    std::vector<ImportRecord> result;
    if (image.format == gandon::BinaryFormat::ELF) {
        result.reserve((std::min)(image.imports.size(), max_import_records));
        for (const auto& imported : image.imports) {
            if (result.size() >= max_import_records) break;
            if (imported.name.empty() || !imported.address) continue;
            result.push_back({L"ELF", wide(imported.name), imported.address});
        }
        return result;
    }
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
    const auto descriptor_count = (std::min<std::size_t>)(directory->second / 20, 4096);
    for (std::size_t descriptor_index = 0; descriptor_index < descriptor_count; ++descriptor_index) {
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
        for (std::size_t index = 0; index < 65536 && result.size() < max_import_records; ++index) {
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
        if (result.size() >= max_import_records) break;
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
    (void)image;
    return crlf_wide(ida_views(*g_database).resources());
}

std::wstring imports_text(const gandon::BinaryImage& image) {
    (void)image;
    return crlf_wide(ida_views(*g_database).imports());
}

std::wstring exports_text(const gandon::BinaryImage& image) {
    (void)image;
    return crlf_wide(ida_views(*g_database).exports());
}

std::wstring strings_text(const gandon::BinaryImage& image) {
    (void)image;
    return crlf_wide(ida_views(*g_database).strings());
}

std::wstring hex_text(const gandon::BinaryImage& image, std::uint64_t address) {
    (void)image;
    return crlf_wide(ida_views(*g_database).hex_view(address));
}

std::wstring symbols_text(const gandon::AnalysisDatabase& db) {
    return crlf_wide(ida_views(db).names());
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
    std::vector<std::string> events;
    {
        std::lock_guard lock(g_debug_log_mutex);
        for (const auto& event : g_debug_event_log) events.push_back(utf8_from_wide(event));
    }
    return crlf_wide(ida_views(db).problems(events));
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

bool graph_shows_address(std::uint64_t address) {
    for (const auto& block : g_graph_blocks) {
        if (block.start == address) return true;
        for (const auto* instruction : block.instructions) if (instruction->address == address) return true;
    }
    return false;
}

void navigate_to_address(HWND window, std::uint64_t address, int tab) {
    { wchar_t text[64]{}; swprintf_s(text, L"goto 0x%llX", static_cast<unsigned long long>(address)); py_console_log(text); }
    if (!g_database || !address) return;
    // Selecting a node/instruction that is already on screen in View-A must not
    // rebuild the graph (that reset the scroll position to the graph start).
    if (tab == 0 && g_tabs && TabCtrl_GetCurSel(g_tabs) == 0 && graph_shows_address(address)) {
        g_current_address = address;
        g_session_dirty = true;
        if (g_navband) InvalidateRect(g_navband, nullptr, FALSE);
        if (g_view) InvalidateRect(g_view, nullptr, FALSE);
        invalidate_minimap();
        return;
    }
    if (g_current_address && g_current_address != address) {
        g_navigation_history.push_back({g_current_address, g_tabs ? TabCtrl_GetCurSel(g_tabs) : 1});
        if (g_navigation_history.size() > 256) g_navigation_history.erase(g_navigation_history.begin());
        g_navigation_forward.clear();   // a fresh jump invalidates the forward trail
    }
    g_current_address = address;
    g_session_dirty = true;
    if (g_navband) InvalidateRect(g_navband, nullptr, FALSE);
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

void find_call_path(HWND window) {
    if (!g_database) return;
    std::wostringstream initial;
    initial << L"0x" << std::hex << g_current_address;
    const auto from_text = prompt_text(window, L"Pathfinder", L"Start function address:", initial.str());
    if (!from_text || from_text->empty()) return;
    const auto to_text = prompt_text(window, L"Pathfinder", L"Destination function address:");
    if (!to_text || to_text->empty()) return;
    try {
        const auto path = g_database->call_path(std::stoull(*from_text, nullptr, 0),
                                                std::stoull(*to_text, nullptr, 0));
        if (path.empty()) {
            MessageBoxW(window, L"No call path was found, or an address is not inside a known function.", L"Pathfinder", MB_ICONINFORMATION);
            return;
        }
        std::wostringstream result;
        result << L"Call path (" << path.size() - 1 << L" call(s)):\r\n\r\n";
        for (std::size_t index = 0; index < path.size(); ++index) {
            const auto label = g_custom_labels.find(path[index]);
            const auto& functions = g_database->functions();
            const auto function = std::lower_bound(functions.begin(), functions.end(), path[index],
                [](const gandon::Function& item, std::uint64_t address) { return item.start < address; });
            const auto name = label != g_custom_labels.end() ? label->second :
                function != functions.end() ? wide(function->name) : L"function";
            result << (index ? L"  -> " : L"") << L"0x" << std::hex << std::uppercase
                   << path[index] << L"  " << name << L"\r\n";
        }
        MessageBoxW(window, result.str().c_str(), L"Pathfinder", MB_ICONINFORMATION);
    } catch (...) {
        MessageBoxW(window, L"Enter valid addresses (for example, 0x140001000).", L"Pathfinder", MB_ICONWARNING);
    }
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

void jump_to_point(HWND window, const NavigationPoint& point) {
    g_current_address = point.address;
    g_session_dirty = true;
    if (g_navband) InvalidateRect(g_navband, nullptr, FALSE);
    if (point.tab == 2) g_pseudocode = pseudocode_text_at(*g_database, point.address);
    else if (point.tab == 1) g_listing = listing_text_at(*g_database, point.address);
    select_view(window, point.tab);
}

void jump_back(HWND window) {
    if (!g_database || g_navigation_history.empty()) {
        SetWindowTextW(g_status, L"Navigation history is empty.");
        return;
    }
    const auto point = g_navigation_history.back();
    g_navigation_history.pop_back();
    if (g_current_address) g_navigation_forward.push_back({g_current_address, g_tabs ? TabCtrl_GetCurSel(g_tabs) : 1});
    jump_to_point(window, point);
}

void jump_forward(HWND window) {
    if (!g_database || g_navigation_forward.empty()) {
        SetWindowTextW(g_status, L"Nothing to jump forward to.");
        return;
    }
    const auto point = g_navigation_forward.back();
    g_navigation_forward.pop_back();
    if (g_current_address) g_navigation_history.push_back({g_current_address, g_tabs ? TabCtrl_GetCurSel(g_tabs) : 1});
    jump_to_point(window, point);
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
        case '\'': escaped += "\\\\"; break;
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
    {   // IDA-style "<segment>:<hex address>" prefix
        const auto colon = text.find(L':');
        if (colon != std::wstring::npos && colon > 0 && colon < 24 && text.find(L' ') > colon) {
            const auto last = text.find_first_not_of(L"0123456789ABCDEFabcdef", colon + 1);
            const auto digits = (last == std::wstring::npos ? text.size() : last) - (colon + 1);
            if (digits == 8 || digits == 16) {
                try { return std::stoull(text.substr(colon + 1, digits), nullptr, 16); } catch (...) {}
            }
        }
    }
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
        if (g_navband) InvalidateRect(g_navband, nullptr, FALSE);
    }
}

std::wstring low_level_il_text() {
    if (!g_llil_program) {
        return L"Experimental Low-Level IL Emulator\r\n"
               L"===================================\r\n\r\n"
               L"Open an x64 binary, select a function or address, then use Tools -> Lift Current Function to LLIL.\r\n"
               L"This first GUI version supports only a documented subset; unsupported instructions fail explicitly.\r\n";
    }

    const auto& program = *g_llil_program;
    std::wostringstream out;
    out << L"Experimental LLIL — x86-64 subset\r\n"
        << L"==================================\r\n"
        << L"Status: " << (g_llil_status.empty() ? L"Lifted; set argument registers, then Step or Run." : g_llil_status) << L"\r\n"
        << L"Statements: " << std::dec << program.statements.size()
        << L" | Expressions: " << program.expressions.size() << L"\r\n\r\n"
        << L"Expressions (eN are shared nodes):\r\n";

    const auto expression_ref = [](std::uint32_t id) {
        return id == UINT32_MAX ? std::wstring(L"<none>") : L"e" + std::to_wstring(id);
    };
    const auto operation_name = [](gandon::IlExpressionOp operation) -> const wchar_t* {
        using Op = gandon::IlExpressionOp;
        switch (operation) {
        case Op::Constant: return L"CONST"; case Op::Register: return L"REG"; case Op::Load: return L"LOAD";
        case Op::Add: return L"ADD"; case Op::Subtract: return L"SUB"; case Op::Multiply: return L"MUL";
        case Op::UnsignedDivide: return L"UDIV"; case Op::And: return L"AND"; case Op::Or: return L"OR";
        case Op::Xor: return L"XOR"; case Op::ShiftLeft: return L"LSL"; case Op::LogicalShiftRight: return L"LSR";
        case Op::ArithmeticShiftRight: return L"ASR"; case Op::Equal: return L"EQ"; case Op::NotEqual: return L"NE";
        case Op::UnsignedLessThan: return L"ULT"; case Op::SignedLessThan: return L"SLT";
        case Op::ZeroExtend: return L"ZEXT"; case Op::SignExtend: return L"SEXT"; case Op::Truncate: return L"TRUNC";
        case Op::Select: return L"SELECT";
        }
        return L"?";
    };
    constexpr std::size_t max_displayed_expressions = 50000;
    const auto expression_count = (std::min)(program.expressions.size(), max_displayed_expressions);
    for (std::size_t index = 0; index < expression_count; ++index) {
        const auto& expression = program.expressions[index];
        out << L"e" << std::dec << index << L" : u" << static_cast<unsigned>(expression.size_bytes) * 8 << L" = "
            << operation_name(expression.operation);
        switch (expression.operation) {
        case gandon::IlExpressionOp::Constant:
            out << L" 0x" << std::hex << std::uppercase << expression.immediate;
            break;
        case gandon::IlExpressionOp::Register:
            out << L" " << wide(expression.register_name);
            break;
        case gandon::IlExpressionOp::Load:
        case gandon::IlExpressionOp::ZeroExtend:
        case gandon::IlExpressionOp::SignExtend:
        case gandon::IlExpressionOp::Truncate:
            out << L" " << expression_ref(expression.left);
            break;
        case gandon::IlExpressionOp::Select:
            out << L" " << expression_ref(expression.left) << L", " << expression_ref(expression.right)
                << L", " << expression_ref(expression.third);
            break;
        default:
            out << L" " << expression_ref(expression.left) << L", " << expression_ref(expression.right);
            break;
        }
        out << L"\r\n";
    }
    if (expression_count < program.expressions.size())
        out << L"... display capped; " << std::dec << (program.expressions.size() - expression_count) << L" expression(s) omitted.\r\n";

    out << L"\r\nStatements:\r\n";
    constexpr std::size_t max_displayed_statements = 20000;
    const auto statement_count = (std::min)(program.statements.size(), max_displayed_statements);
    const auto active_statement = g_llil_emulator ? g_llil_emulator->statement_index() : 0;
    for (std::size_t index = 0; index < statement_count; ++index) {
        const auto& statement = program.statements[index];
        out << (index == active_statement ? L"=> " : L"   ") << L"s" << std::dec << index;
        if (statement.source_address)
            out << L" [0x" << std::hex << std::uppercase << statement.source_address << L"]";
        out << L"  ";
        switch (statement.operation) {
        case gandon::IlStatementOp::Nop: out << L"NOP"; break;
        case gandon::IlStatementOp::SetRegister:
            out << wide(statement.register_name) << L" = " << expression_ref(statement.value);
            break;
        case gandon::IlStatementOp::Store:
            out << L"STORE" << static_cast<unsigned>(statement.size_bytes) << L" ["
                << expression_ref(statement.address) << L"] = " << expression_ref(statement.value);
            break;
        case gandon::IlStatementOp::Jump:
            if (statement.value < program.expressions.size())
                out << L"JMP s" << std::dec << program.expressions[statement.value].immediate;
            else out << L"JMP " << expression_ref(statement.value);
            break;
        case gandon::IlStatementOp::Branch:
            out << L"IF " << expression_ref(statement.condition) << L" GOTO s" << std::dec << statement.true_target
                << L" ELSE s" << statement.false_target;
            break;
        case gandon::IlStatementOp::Return:
            out << L"RET";
            if (statement.value != UINT32_MAX) out << L" " << expression_ref(statement.value);
            break;
        }
        out << L"\r\n";
    }
    if (statement_count < program.statements.size())
        out << L"... display capped; " << std::dec << (program.statements.size() - statement_count) << L" statement(s) omitted.\r\n";

    if (g_llil_emulator) {
        out << L"\r\nImage-backed memory: " << std::dec << g_llil_emulator->mapped_memory_bytes()
            << L" byte(s) mapped; " << g_llil_memory_status << L"\r\n";
        out << L"\r\nRegisters (uninitialized inputs start at zero; RSP uses a synthetic stack; Tools -> Set LLIL Register changes them):\r\n";
        std::set<std::string> registers;
        for (const auto& expression : program.expressions)
            if (expression.operation == gandon::IlExpressionOp::Register && !expression.register_name.empty())
                registers.insert(expression.register_name);
        for (const auto& statement : program.statements) {
            if ((statement.operation == gandon::IlStatementOp::SetRegister ||
                 statement.operation == gandon::IlStatementOp::PopRegister) && !statement.register_name.empty())
                registers.insert(statement.register_name);
            if (statement.operation == gandon::IlStatementOp::Push ||
                statement.operation == gandon::IlStatementOp::PopRegister)
                registers.insert("rsp");
        }
        std::string error;
        for (const auto& name : registers) {
            std::uint64_t value = 0;
            if (g_llil_emulator->register_value(name, value, error))
                out << wide(name) << L" = 0x" << std::hex << std::uppercase << value << L"\r\n";
        }
        if (g_llil_emulator->statement_index() >= program.statements.size()) out << L"\r\nExecution reached the end of the IL program.\r\n";
    }
    out << L"\r\nSubset: scalar MOV/MOVABS/LEA, PUSH/POP/LEAVE, ADD/SUB/AND/OR/XOR/CMP/TEST, RET, direct JMP, and common direct Jcc conditions. "
           L"CF/ZF/SF/OF/PF are modeled for these operations; AF is computed for ADD/SUB/CMP and deterministic for logical ops. "
           L"Stack support covers 64-bit PUSH/POP and LEAVE; RSP is initialized to a synthetic stack address. "
           L"Memory is supported for selected MOV/LEA/PUSH forms. "
           L"CALL, floating-point/vector instructions, and flag effects from unsupported instructions are not modeled yet.\r\n";
    return out.str();
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

// SetWindowText on a rich edit keeps whatever character format sat at position 0
// (often the system black), so reset the whole document to the themed text colour
// before the syntax colouring is applied.
void reset_editor_text_color() {
    if (!g_editor) return;
    wchar_t editor_class[32] = {};
    GetClassNameW(g_editor, editor_class, 32);
    if (wcscmp(editor_class, L"RICHEDIT50W") != 0) return;
    CHARFORMAT2W format{}; format.cbSize = sizeof format; format.dwMask = CFM_COLOR | CFM_EFFECTS; format.dwEffects = 0;
    format.crTextColor = THEMED_RGB(215, 228, 238);
    SendMessageW(g_editor, EM_SETCHARFORMAT, SCF_DEFAULT, reinterpret_cast<LPARAM>(&format));
    SendMessageW(g_editor, EM_SETCHARFORMAT, SCF_ALL, reinterpret_cast<LPARAM>(&format));
}

void set_editor_text() {
    if (!g_editor) return;
    const int tab = TabCtrl_GetCurSel(g_tabs);
    const bool graph = tab == 0;
    if (graph) {
        SetWindowPos(g_editor, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_HIDEWINDOW);
        SetWindowPos(g_view, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
        if (g_minimap) ShowWindow(g_minimap, g_minimap_visible ? SW_SHOW : SW_HIDE);
        // The editor used to cover this area; repaint the parent and the canvas fully.
        if (HWND parent = GetParent(g_view)) { RECT area{}; GetWindowRect(g_view, &area); MapWindowPoints(nullptr, parent, reinterpret_cast<POINT*>(&area), 2); RedrawWindow(parent, &area, nullptr, RDW_INVALIDATE | RDW_ERASE); }
        RedrawWindow(g_view, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
    } else {
        SetWindowPos(g_view, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_HIDEWINDOW);
        if (g_minimap) ShowWindow(g_minimap, SW_HIDE);
        SetWindowPos(g_editor, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    }
    std::wstring text;
    const std::wstring* shared_text = nullptr;
    if (!g_database) shared_text = &g_listing;
    else if (tab == 1) {
        if (g_listing.empty()) g_listing = listing_text(*g_database);
        shared_text = &g_listing;
    }
    else if (tab == 2) {
        g_pseudocode = pseudocode_text_at(*g_database, g_current_address ? g_current_address : g_database->image().entry_point);
        shared_text = &g_pseudocode;
    }
    else if (tab == 3) {
        if (g_xrefs.empty()) g_xrefs = xref_text(*g_database);
        shared_text = &g_xrefs;
    }
    else if (tab == 4) text = debugger_text();
    else if (tab == 5) text = hex_text(g_database->image(), g_current_address ? g_current_address : g_database->image().entry_point);
    else if (tab == 6) {
        ensure_types(g_database->image().is_64_bit);
        text = L"Local Types  (Shift+F1 to edit your own declarations)\r\n===========\r\n";
        if (!g_type_error.empty()) text += L"!! your declarations: " + wide(g_type_error) + L"\r\n\r\n";
        { std::wstring body = wide(g_types.format()); std::wstring fixed; for (const wchar_t ch : body) { if (ch == L'\n') fixed += L"\r\n"; else fixed += ch; } text += fixed; }
        text += L"\r\nStructure offsets (T)\r\n---------------------\r\n";
        if (g_struct_ops.empty()) text += L"(none)\r\n"; else for (const auto& [address, type] : g_struct_ops) { std::wostringstream row; row << L"0x" << std::hex << std::uppercase << address << L"  " << wide(type) << L"\r\n"; text += row.str(); }
        text += L"\r\nEnum constants (M)\r\n------------------\r\n";
        if (g_enum_ops.empty()) text += L"(none)\r\n"; else for (const auto& [address, type] : g_enum_ops) { std::wostringstream row; row << L"0x" << std::hex << std::uppercase << address << L"  " << wide(type) << L"\r\n"; text += row.str(); }
        text += L"\r\nFunction prototypes (Y)\r\n-----------------------\r\n";
        if (g_prototypes.empty()) text += L"(none)\r\n"; else for (const auto& [address, proto] : g_prototypes) { std::wostringstream row; row << L"0x" << std::hex << std::uppercase << address << L"  " << wide(proto) << L"\r\n"; text += row.str(); }
        text += L"\r\nUser assignments\r\n----------------\r\n";
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
    else if (tab == 12) text = memory_map_text(*g_database);
    else if (tab == 13) text = problems_text(*g_database);
    else if (tab == 14) text = low_level_il_text();
    else shared_text = &g_listing;
    SetWindowTextW(g_editor, shared_text ? shared_text->c_str() : text.c_str());
    reset_editor_text_color();
    if (tab != 0 && tab != 4 && tab != 14 && tab != 6) colorize_editor(tab);
    if (graph) { InvalidateRect(g_view, nullptr, TRUE); UpdateWindow(g_view); }
}

void fill_tree() {
    if (!g_tree) return;
    struct TreeRedrawRestorer {
        HWND tree;
        ~TreeRedrawRestorer() {
            SendMessageW(tree, WM_SETREDRAW, TRUE, 0);
            InvalidateRect(tree, nullptr, TRUE);
        }
    } redraw_restorer{g_tree};
    SendMessageW(g_tree, WM_SETREDRAW, FALSE, 0);
    TreeView_DeleteAllItems(g_tree);
    g_lazy_function_ranges.clear();
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
    std::wstring functions_name = L"Functions (" + std::to_wstring(g_database->functions().size()) + L")";
    insert.hParent = root; insert.item.pszText = functions_name.data(); insert.item.lParam = 0;
    const HTREEITEM functions = TreeView_InsertItem(g_tree, &insert);
    constexpr std::size_t kLazyFunctionTreeThreshold = 5000;
    constexpr std::size_t kFunctionsPerTreeGroup = 256;
    const auto& discovered_functions = g_database->functions();
    if (discovered_functions.size() > kLazyFunctionTreeThreshold) {
        for (std::size_t begin = 0; begin < discovered_functions.size(); begin += kFunctionsPerTreeGroup) {
            const auto end = (std::min)(begin + kFunctionsPerTreeGroup, discovered_functions.size());
            std::size_t visible_count = 0;
            for (std::size_t index = begin; index < end; ++index)
                if (!g_hidden_functions.contains(discovered_functions[index].start)) ++visible_count;
            if (!visible_count) continue;

            auto group_name = L"Functions " + std::to_wstring(begin + 1) + L"-" + std::to_wstring(end) +
                              L" (" + std::to_wstring(visible_count) + L")";
            insert.hParent = functions; insert.item.pszText = group_name.data(); insert.item.lParam = 0;
            const auto group = TreeView_InsertItem(g_tree, &insert);
            g_lazy_function_ranges.emplace(group, std::pair{begin, end});

            wchar_t placeholder_name[] = L"(expand to load functions)";
            insert.hParent = group; insert.item.pszText = placeholder_name; insert.item.lParam = 0;
            TreeView_InsertItem(g_tree, &insert);
        }
    } else {
        for (const auto& function : discovered_functions) {
            if (g_hidden_functions.contains(function.start)) continue;
            auto name = g_custom_labels.contains(function.start) ? g_custom_labels[function.start] : wide(function.name);
            insert.hParent = functions; insert.item.pszText = name.data(); insert.item.lParam = static_cast<LPARAM>(function.start);
            TreeView_InsertItem(g_tree, &insert);
        }
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
    TreeView_Expand(g_tree, root, TVE_EXPAND); TreeView_Expand(g_tree, sections, TVE_EXPAND);
    // Large function lists are represented by small lazy groups. Expanding a
    // group materializes only its own range, keeping startup and tree memory low.
    TreeView_Expand(g_tree, functions, TVE_EXPAND);
    TreeView_Expand(g_tree, imports, TVE_EXPAND); TreeView_Expand(g_tree, strings, TVE_EXPAND);
}

void refresh_views(HWND window) {
    if (!g_database) return;
    // Full listing, XREF, pseudocode, and memory-map strings can each be large.
    // Materialize only the active text view and keep inactive views out of RAM.
    // std::wstring::clear() preserves the old capacity. Release inactive views
    // so switching across large tabs/files does not accumulate their high-water marks.
    std::wstring().swap(g_listing); std::wstring().swap(g_pseudocode);
    std::wstring().swap(g_xrefs); std::wstring().swap(g_memory_map);
    rebuild_graph_model(); fill_tree(); set_editor_text();
    std::wstring status = L"Loaded: " + g_database->image().path.wstring() + L" | Functions: " + std::to_wstring(g_database->functions().size()) + L" | XREFs: " + std::to_wstring(g_database->xrefs().size());
    status += L" | Analysis buffers: ~" + std::to_wstring(g_database->estimated_analysis_memory_bytes() / 1024) + L" KiB";
    if (g_database->functions_truncated()) status += L" (functions truncated)";
    if (g_database->xrefs_truncated()) status += L" (truncated)";
    if (!g_database->image().symbols.empty()) status += L" | ELF symbols: " + std::to_wstring(g_database->image().symbols.size());
    SendMessageW(g_status, SB_SETTEXTW, 0, reinterpret_cast<LPARAM>(status.c_str()));
    SetWindowTextW(window, (L"Gandon-PRO - " + g_database->image().path.wstring()).c_str());
}

void release_analysis_state_for_replacement() {
    // Drop the previous analysis and all high-water GUI buffers before building
    // the next one; even the native edit control otherwise retains old text.
    g_emulator.reset();
    clear_llil_state();
    g_database.reset();
    std::wstring().swap(g_listing); std::wstring().swap(g_pseudocode);
    std::wstring().swap(g_xrefs); std::wstring().swap(g_memory_map);
    if (g_editor) SetWindowTextW(g_editor, L"");
    std::vector<GraphBlock>().swap(g_graph_blocks);
    std::vector<GraphEdge>().swap(g_graph_edges);
    std::vector<gandon::Instruction>().swap(g_graph_fallback_instructions);
    std::unordered_map<std::uint64_t, std::pair<int, int>>().swap(g_graph_positions);
    std::vector<std::uint8_t>().swap(g_memory_snapshot);
    std::vector<std::vector<PatchChange>>().swap(g_patch_undo);
    std::vector<std::vector<PatchChange>>().swap(g_patch_redo); g_edit_undo.clear(); g_edit_redo.clear(); g_timeline.clear(); g_timeline_redo.clear();
    if (g_tree) TreeView_DeleteAllItems(g_tree);
    g_lazy_function_ranges.clear();
    g_current_address = 0;
    g_graph_zoom = 100; g_graph_scroll_x = 0; g_graph_scroll_y = 0;
    g_memory_snapshot_address = 0;
    // clear() destroys entries but leaves unordered-map bucket arrays allocated.
    // These per-binary tables may have grown substantially on a large analysis;
    // swap them out so opening another file actually releases that high-water RAM.
    decltype(g_custom_labels)().swap(g_custom_labels);
    decltype(g_custom_comments)().swap(g_custom_comments);
    decltype(g_custom_types)().swap(g_custom_types);
    g_struct_ops.clear(); g_enum_ops.clear(); g_prototypes.clear(); g_type_source.clear();
    decltype(g_graph_colors)().swap(g_graph_colors);
    decltype(g_requested_disabled_imports)().swap(g_requested_disabled_imports);
    decltype(g_installed_import_disables)().swap(g_installed_import_disables);
    std::vector<NavigationPoint>().swap(g_navigation_history);
    std::vector<NavigationPoint>().swap(g_navigation_forward);
    g_collapsed_blocks.clear();
    g_graph_groups.clear();
    g_graph_selection.clear();
    std::vector<std::wstring>().swap(g_watch_expressions);
    g_bookmarks.clear(); g_hidden_functions.clear(); g_hidden_imports.clear();
    { std::lock_guard lock(g_breakpoint_mutex);
        g_requested_breakpoints.clear();
        decltype(g_breakpoint_conditions)().swap(g_breakpoint_conditions);
        decltype(g_breakpoint_hit_counts)().swap(g_breakpoint_hit_counts);
        decltype(g_breakpoint_hit_limits)().swap(g_breakpoint_hit_limits);
        g_breakpoint_log_only.clear();
    }
}

bool load_binary_path(HWND window, const std::filesystem::path& file_path) {
    gandon::BinaryImage image; std::string error;
    try {
        if (!image.load(file_path, error)) { MessageBoxW(window, wide(error).c_str(), L"Gandon-PRO", MB_ICONERROR); return false; }
    } catch (const std::bad_alloc&) {
        MessageBoxW(window, L"Недостаточно памяти для чтения файла.", L"Gandon-PRO", MB_ICONERROR);
        return false;
    } catch (const std::exception& exception) {
        MessageBoxW(window, wide(exception.what()).c_str(), L"Gandon-PRO", MB_ICONERROR);
        return false;
    }

    release_analysis_state_for_replacement();

    try {
        auto database = std::make_unique<gandon::AnalysisDatabase>(std::move(image));
        database->discover_basic_xrefs();
        gui_auto_analysis(*database);
        g_database = std::move(database);
    } catch (const std::bad_alloc&) {
        g_listing = L"Analysis stopped: not enough memory to build the analysis database.\r\n";
        SetWindowTextW(g_status, L"Analysis failed: insufficient memory.");
        select_view(window, 1);
        MessageBoxW(window, L"Недостаточно памяти для анализа файла. Старые данные освобождены.", L"Gandon-PRO", MB_ICONERROR);
        return false;
    } catch (const std::exception& exception) {
        g_listing = L"Analysis failed: " + wide(exception.what()) + L"\r\n";
        SetWindowTextW(g_status, L"Analysis failed.");
        select_view(window, 1);
        MessageBoxW(window, wide(exception.what()).c_str(), L"Gandon-PRO", MB_ICONERROR);
        return false;
    }

    g_current_address = g_database->image().entry_point;
    g_session_path = g_database->image().path.wstring() + L".gnd";
    g_session_dirty = false;
    refresh_views(window);
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
    g_patch_undo.push_back(std::move(changes)); g_patch_redo.clear(); g_timeline.push_back('p'); g_timeline_redo.clear(); refresh_after_patch(window);
}

void undo_patch(HWND window) {
    if (g_database && !g_timeline.empty() && g_timeline.back() == 'e' && !g_edit_undo.empty()) {
        auto edit = std::move(g_edit_undo.back()); g_edit_undo.pop_back(); g_timeline.pop_back(); g_timeline_redo.push_back('e');
        set_text_entry(edit.comment, edit.address, edit.had_before, edit.before);
        g_edit_redo.push_back(std::move(edit)); g_session_dirty = true; refresh_views(window);
        SetWindowTextW(g_status, L"Rename / comment undone. Redo with Ctrl+Y."); py_console_log(L"undo edit"); return;
    }
    if (!g_timeline.empty() && g_timeline.back() == 'p' && !g_patch_undo.empty()) { g_timeline.pop_back(); g_timeline_redo.push_back('p'); }
    if (!g_database || g_patch_undo.empty()) { SetWindowTextW(g_status, L"Nothing to undo: no patches applied."); return; }
    auto changes = std::move(g_patch_undo.back()); g_patch_undo.pop_back();
    for (const auto& change : changes) { std::string error; g_database->replace_file_bytes(change.offset, {change.old_value}, error); }
    g_patch_redo.push_back(std::move(changes)); refresh_after_patch(window);
    SetWindowTextW(g_status, L"Patch undone. Redo with Ctrl+Y.");
}

void redo_patch(HWND window) {
    if (g_database && !g_timeline_redo.empty() && g_timeline_redo.back() == 'e' && !g_edit_redo.empty()) {
        auto edit = std::move(g_edit_redo.back()); g_edit_redo.pop_back(); g_timeline_redo.pop_back(); g_timeline.push_back('e');
        set_text_entry(edit.comment, edit.address, true, edit.after);
        g_edit_undo.push_back(std::move(edit)); g_session_dirty = true; refresh_views(window);
        SetWindowTextW(g_status, L"Rename / comment redone."); py_console_log(L"redo edit"); return;
    }
    if (!g_timeline_redo.empty() && g_timeline_redo.back() == 'p' && !g_patch_redo.empty()) { g_timeline_redo.pop_back(); g_timeline.push_back('p'); }
    if (!g_database || g_patch_redo.empty()) { SetWindowTextW(g_status, L"Nothing to redo: use Undo Patch first (Ctrl+Z)."); return; }
    auto changes = std::move(g_patch_redo.back()); g_patch_redo.pop_back();
    for (const auto& change : changes) { std::string error; g_database->replace_file_bytes(change.offset, {change.new_value}, error); }
    g_patch_undo.push_back(std::move(changes)); refresh_after_patch(window);
    SetWindowTextW(g_status, L"Patch redone.");
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
    const auto current = g_custom_labels.contains(g_current_address) ? g_custom_labels[g_current_address] : [&] { wchar_t b[40]{}; swprintf_s(b, L"sub_%llX", static_cast<unsigned long long>(g_current_address)); return std::wstring(b); }();
    const auto value = prompt_text(window, L"Rename Label", L"Label:", current);
    if (!value || value->empty()) return;
    record_text_edit(false, g_current_address, *value); g_custom_labels[g_current_address] = *value; g_session_dirty = true; { wchar_t a[40]{}; swprintf_s(a, L"0x%llX", static_cast<unsigned long long>(g_current_address)); py_console_log(L"rename " + std::wstring(a) + L" -> " + *value); } refresh_views(window);
}

void add_current_comment(HWND window) {
    if (!g_current_address) return;
    const auto current = g_custom_comments.contains(g_current_address) ? g_custom_comments[g_current_address] : L"";
    const auto value = prompt_text(window, L"Add Comment", L"Comment:", current);
    if (!value) return;
    record_text_edit(true, g_current_address, *value); g_custom_comments[g_current_address] = *value; g_session_dirty = true; { wchar_t a[40]{}; swprintf_s(a, L"0x%llX", static_cast<unsigned long long>(g_current_address)); py_console_log(L"comment " + std::wstring(a) + L": " + *value); } refresh_views(window);
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
    { std::istringstream lines(g_type_source); std::string line; while (std::getline(lines, line)) { if (!line.empty() && line.back() == '\r') line.pop_back(); output << L"Z|0|" << wide(line) << L"\n"; } }
    for (const auto& [address, type] : g_struct_ops) output << L"X|" << address << L"|" << wide(type) << L"\n";
    for (const auto& [address, type] : g_enum_ops) output << L"E|" << address << L"|" << wide(type) << L"\n";
    for (const auto& [address, proto] : g_prototypes) output << L"O|" << address << L"|" << wide(proto) << L"\n";
    for (const auto address : g_bookmarks) output << L"K|" << address << L"|bookmark\n";
    for (const auto address : g_hidden_functions) output << L"F|" << address << L"|hidden_function\n";
    for (const auto& [dll, name] : g_hidden_imports) output << L"N|0|" << dll << L"!" << name << L"\n";
    for (const auto& [key, record] : g_requested_disabled_imports) output << L"D|0|" << record.dll << L"!" << record.name << L"\n";
    for (const auto& expression : g_watch_expressions) output << L"W|0|" << expression << L"\n";
    for (const auto& [address, color] : g_graph_colors) output << L"T|" << address << L"|" << std::hex << color << L"\n";
    for (const auto& [address, position] : g_graph_positions) output << L"V|" << address << L"|" << position.first << L"," << position.second << L"\n";
    output << L"G|" << std::dec << g_graph_zoom << L"|graph_zoom\n";
    output << L"H|" << g_graph_scroll_x << L"," << g_graph_scroll_y << L"|graph_scroll\n";
    for (const auto& group : g_graph_groups) {
        if (group.size() < 2) continue;
        output << L"M|0|" << std::dec;
        for (std::size_t i = 0; i < group.size(); ++i) output << (i ? L"," : L"") << group[i];
        output << L"\n";
    }
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
            if (value[index] != '\'' || index + 1 >= value.size()) { result.push_back(value[index]); continue; }
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

// Shared body of File > Load Database and the MCP plugin's load_database
// callback. `allow_legacy_json` gates the old Python-annotations format: the
// GUI's own file picker still accepts it, but a plugin call never should -
// load_legacy_python_database() pops a blocking MessageBoxW when no binary is
// open yet, which would hang the UI thread with no one there to click it.
bool load_database_core(HWND window, const std::filesystem::path& file_name, bool allow_legacy_json, std::string& error) {
    {
        std::ifstream probe(file_name, std::ios::binary);
        std::string contents((std::istreambuf_iterator<char>(probe)), std::istreambuf_iterator<char>());
        const auto first = contents.find_first_not_of(" \t\r\n\xEF\xBB\xBF");
        if (first != std::string::npos && contents[first] == '{') {
            if (!allow_legacy_json) { error = "legacy Python (.gnd JSON) database format is not supported here"; return false; }
            return load_legacy_python_database(window, file_name);
        }
    }
    std::wifstream input(file_name); std::wstring header, binary_path;
    if (!input || !std::getline(input, header) || (header != L"GANDON-GND-1" && header != L"GANDON-GND-2" && header != L"GANDON-GND-3") || !std::getline(input, binary_path)) { error = "Invalid database file format."; return false; }
    gandon::BinaryImage image;
    if (!image.load(binary_path, error)) return false;
    release_analysis_state_for_replacement();
    g_database = std::make_unique<gandon::AnalysisDatabase>(std::move(image));
    g_database->discover_basic_xrefs();
    gui_auto_analysis(*g_database);
    g_current_address = g_database->image().entry_point;
    g_session_address = g_current_address;
    g_session_tab = 0;
    g_graph_zoom = 100; g_graph_scroll_x = 0; g_graph_scroll_y = 0;
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
        if (record[0] == L'M') {   // graph node group: comma-separated member block-starts
            std::vector<std::uint64_t> members;
            const auto list = record.substr(split + 1);
            std::size_t pos = 0;
            while (pos < list.size()) {
                const auto comma = list.find(L',', pos);
                const auto token = list.substr(pos, comma == std::wstring::npos ? std::wstring::npos : comma - pos);
                try { if (!token.empty()) members.push_back(std::stoull(token)); } catch (...) {}
                if (comma == std::wstring::npos) break;
                pos = comma + 1;
            }
            if (members.size() >= 2) g_graph_groups.push_back(std::move(members));
            continue;
        }
        try {
            const auto address = std::stoull(record.substr(2, split - 2));
            if (record[0] == L'L') g_custom_labels[address] = record.substr(split + 1);
            else if (record[0] == L'C') g_custom_comments[address] = record.substr(split + 1);
            else if (record[0] == L'Y') g_custom_types[address] = record.substr(split + 1);
            else if (record[0] == L'Z') g_type_source += utf8_from_wide(record.substr(split + 1)) + "\n";
            else if (record[0] == L'X') g_struct_ops[address] = utf8_from_wide(record.substr(split + 1));
            else if (record[0] == L'E') g_enum_ops[address] = utf8_from_wide(record.substr(split + 1));
            else if (record[0] == L'O') g_prototypes[address] = utf8_from_wide(record.substr(split + 1));
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
    return true;
}

void load_database(HWND window) {
    wchar_t file_name[MAX_PATH]{};
    OPENFILENAMEW dialog{sizeof(dialog)}; dialog.hwndOwner = window; dialog.lpstrFilter = L"Gandon database (*.gnd)\0*.gnd\0\0"; dialog.lpstrFile = file_name; dialog.nMaxFile = MAX_PATH; dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&dialog)) return;
    std::string error;
    if (!load_database_core(window, file_name, /*allow_legacy_json=*/true, error)) MessageBoxW(window, wide(error).c_str(), L"Load Database", MB_ICONERROR);
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
        for (std::size_t index = 0; index < instruction.size; ++index) {
            bool wildcard = false;
            if (call_or_jump && instruction.size >= 5) wildcard = index + 4 >= instruction.size;
            else if (conditional_jump && instruction.size >= 2) wildcard = index + (instruction.size >= 5 ? 4 : 1) >= instruction.size;
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
    bool truncated = false;
    const auto matches = g_database->image().find_pattern(pattern, 10000, &truncated);
    std::wostringstream result;
    result << L"Signature matches" << (truncated ? L" (first 10000 shown; more exist)" : L"")
           << L": " << std::dec << matches.size() << L"\r\n\r\n";
    for (const auto address : matches) result << L"0x" << std::hex << std::uppercase << address << L"\r\n";
    g_listing = result.str();
    if (!matches.empty()) g_current_address = matches.front();
    select_view(window, 1);
}

void draw_export_graph(HDC dc, int width, int height) {
    RECT canvas{0, 0, width, height};
    HBRUSH background = CreateSolidBrush(THEMED_RGB(24, 27, 32));
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
        const COLORREF edge_color = edge.kind == GraphEdgeKind::TrueBranch ? THEMED_RGB(73, 190, 104)
            : edge.kind == GraphEdgeKind::FalseBranch ? THEMED_RGB(224, 92, 92) : THEMED_RGB(86, 157, 214);
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
        const bool active = block.start == g_current_address || std::any_of(block.instructions.begin(), block.instructions.end(), [](const auto* instruction) { return instruction->address == g_current_address; });
        HBRUSH fill = CreateSolidBrush(active ? THEMED_RGB(36, 57, 66) : THEMED_RGB(32, 39, 47));
        FillRect(dc, &box, fill); DeleteObject(fill);
        HPEN border = CreatePen(PS_SOLID, active ? 2 : 1, active ? THEMED_RGB(0, 160, 210) : THEMED_RGB(62, 78, 91));
        HGDIOBJ old_pen = SelectObject(dc, border); HGDIOBJ old_brush = SelectObject(dc, GetStockObject(NULL_BRUSH));
        Rectangle(dc, box.left, box.top, box.right, box.bottom); SelectObject(dc, old_brush); SelectObject(dc, old_pen); DeleteObject(border);
        std::wstring title = g_custom_labels.contains(block.start) ? g_custom_labels[block.start] : L"loc_" + [&] { std::wostringstream value; value << std::hex << std::uppercase << block.start; return value.str(); }();
        title += L":";
        SetTextColor(dc, THEMED_RGB(170, 239, 207)); TextOutW(dc, x + 12, y + 8, title.c_str(), static_cast<int>(title.size()));
        int line_y = y + 30;
        if (g_custom_comments.contains(block.start)) {
            const auto comment = L"// " + g_custom_comments[block.start];
            SetTextColor(dc, THEMED_RGB(155, 170, 184)); TextOutW(dc, x + 12, line_y, comment.c_str(), static_cast<int>(comment.size())); line_y += static_cast<int>(18 * scale);
        }
        for (std::size_t index = 0; index < block.instructions.size() && index < 9; ++index) {
            const auto& instruction = *block.instructions[index];
            const auto text = wide(instruction.mnemonic + (instruction.operands.empty() ? "" : " " + instruction.operands));
            SetTextColor(dc, !instruction.mnemonic.empty() && instruction.mnemonic.front() == 'j' ? THEMED_RGB(78, 201, 176) : THEMED_RGB(215, 228, 238));
            TextOutW(dc, x + 12, line_y, text.c_str(), static_cast<int>(text.size()));
            if (const auto note = g_custom_comments.find(instruction.address); note != g_custom_comments.end() && instruction.address != block.start && !note->second.empty()) {
                SIZE extent{}; GetTextExtentPoint32W(dc, text.c_str(), static_cast<int>(text.size()), &extent);
                const auto comment = L"  ; " + note->second;
                SetTextColor(dc, THEMED_RGB(155, 170, 184)); TextOutW(dc, x + 12 + extent.cx, line_y, comment.c_str(), static_cast<int>(comment.size()));
            }
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
        HPEN edge = CreatePen(PS_SOLID, 2, xref.kind == "call" ? THEMED_RGB(54, 157, 220) : THEMED_RGB(231, 76, 60));
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
        HBRUSH fill = CreateSolidBrush(THEMED_RGB(32, 39, 47)); FillRect(dc, &box, fill); DeleteObject(fill);
        HPEN border = CreatePen(PS_SOLID, 1, THEMED_RGB(62, 78, 91)); HGDIOBJ old_pen = SelectObject(dc, border); HGDIOBJ old_brush = SelectObject(dc, GetStockObject(NULL_BRUSH)); Rectangle(dc, box.left, box.top, box.right, box.bottom); SelectObject(dc, old_brush); SelectObject(dc, old_pen); DeleteObject(border);
        const auto& function = g_database->functions()[index];
        const auto name = g_custom_labels.contains(function.start) ? g_custom_labels[function.start] : wide(function.name);
        SetTextColor(dc, THEMED_RGB(170, 239, 207)); TextOutW(dc, x + 12, y + 12, name.c_str(), static_cast<int>(name.size()));
        wchar_t address[40]{}; swprintf_s(address, L"0x%llX", static_cast<unsigned long long>(function.start));
        SetTextColor(dc, THEMED_RGB(125, 191, 231)); TextOutW(dc, x + 12, y + 40, address, static_cast<int>(wcslen(address)));
        if (g_custom_comments.contains(function.start) && !g_custom_comments[function.start].empty()) {
            SetTextColor(dc, THEMED_RGB(180, 180, 180)); TextOutW(dc, x + 12, y + 62, g_custom_comments[function.start].c_str(),  static_cast<int>(g_custom_comments[function.start].size()));
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


// IDA-like syntax colouring for the rich-edit text views.
void colorize_editor(int tab) {
    if (!g_editor) return;
    wchar_t editor_class[32] = {};
    GetClassNameW(g_editor, editor_class, 32);
    if (wcscmp(editor_class, L"RICHEDIT50W") != 0) return;
    const auto length = GetWindowTextLengthW(g_editor);
    if (length <= 0 || length > 4000000) return;
    std::wstring text(static_cast<std::size_t>(length) + 1, L'\0');
    GetWindowTextW(g_editor, text.data(), length + 1);
    text.resize(static_cast<std::size_t>(length));
    // Rich edit stores line breaks as a single character; GetWindowText returns CRLF.
    const COLORREF addr_color = THEMED_RGB(125, 138, 150), comment_color = THEMED_RGB(106, 170, 110), mnemonic_color = THEMED_RGB(86, 156, 214),
                   flow_color = THEMED_RGB(229, 160, 80), label_color = THEMED_RGB(230, 219, 140), number_color = THEMED_RGB(181, 206, 168),
                   string_color = THEMED_RGB(206, 145, 120), head_color = THEMED_RGB(150, 190, 235);
    // WM_SETREDRAW(TRUE) re-applies WS_VISIBLE, which resurrected the hidden editor on top of View-A.
    const bool editor_was_visible = IsWindowVisible(g_editor) != FALSE;
    SendMessageW(g_editor, WM_SETREDRAW, FALSE, 0);
    const auto old_mask = SendMessageW(g_editor, EM_SETEVENTMASK, 0, 0);
    CHARRANGE saved{}; SendMessageW(g_editor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&saved));
    auto paint = [&](LONG begin, LONG end, COLORREF color) {
        if (end <= begin) return;
        CHARRANGE range{begin, end}; SendMessageW(g_editor, EM_EXSETSEL, 0, reinterpret_cast<LPARAM>(&range));
        CHARFORMAT2W format{}; format.cbSize = sizeof format; format.dwMask = CFM_COLOR; format.crTextColor = color;
        SendMessageW(g_editor, EM_SETCHARFORMAT, SCF_SELECTION, reinterpret_cast<LPARAM>(&format));
    };
    LONG offset = 0; // position in the rich-edit character stream
    std::size_t i = 0;
    int line_number = 0;
    while (i < text.size()) {
        auto eol = text.find(L'\n', i);
        const auto line_end = eol == std::wstring::npos ? text.size() : eol;
        std::size_t content_end = line_end; if (content_end > i && text[content_end - 1] == L'\r') --content_end;
        const std::wstring line = text.substr(i, content_end - i);
        const LONG base = offset;
        if (!line.empty()) {
            std::size_t cursor = 0;
            // "<seg>:<hex address>" prefix, as in IDA.
            const auto colon = line.find(L':');
            if (colon != std::wstring::npos && colon < 24 && line.find(L' ') > colon && colon + 9 <= line.size() &&
                line.find_first_not_of(L"0123456789ABCDEFabcdef", colon + 1) >= colon + 9 && line[0] != L';') {
                cursor = line.find_first_not_of(L"0123456789ABCDEFabcdef", colon + 1);
                if (cursor == std::wstring::npos) cursor = line.size();
                paint(base, base + static_cast<LONG>(cursor), addr_color);
            } else if (line.rfind(L"0x", 0) == 0) {
                cursor = line.find_first_not_of(L"0123456789ABCDEFabcdefx");
                if (cursor == std::wstring::npos) cursor = line.size();
                paint(base, base + static_cast<LONG>(cursor), addr_color);
            }
            // trailing comment
            auto semicolon = line.find(L';', cursor);
            if (semicolon != std::wstring::npos) paint(base + static_cast<LONG>(semicolon), base + static_cast<LONG>(line.size()), comment_color);
            const auto code_end = semicolon == std::wstring::npos ? line.size() : semicolon;
            if (tab == 1 && semicolon != cursor + 1) {
                // label line or instruction line
                const auto first = line.find_first_not_of(L' ', cursor);
                if (first != std::wstring::npos && first < code_end) {
                    const auto word_end = line.find_first_of(L" \t", first);
                    const auto stop = word_end == std::wstring::npos ? line.size() : word_end;
                    const std::wstring word = line.substr(first, stop - first);
                    const bool is_label = !word.empty() && (word.back() == L':' || (first - cursor <= 1));
                    if (is_label) {
                        paint(base + static_cast<LONG>(first), base + static_cast<LONG>(stop), label_color);
                    } else {
                        static const std::set<std::wstring> flow = {L"call", L"jmp", L"ret", L"retn", L"je", L"jne", L"jz", L"jnz", L"jg", L"jge", L"jl", L"jle",
                            L"ja", L"jae", L"jb", L"jbe", L"js", L"jns", L"loop", L"leave", L"int3", L"syscall", L"hlt"};
                        paint(base + static_cast<LONG>(first), base + static_cast<LONG>(stop), flow.count(word) ? flow_color : mnemonic_color);
                        // operands: numbers ending in h, quoted strings
                        for (std::size_t k = stop; k < code_end; ++k) {
                            if (line[k] == L'\'') {
                                const auto close = line.find(L'\'', k + 1);
                                const auto e = close == std::wstring::npos ? code_end : (std::min)(close + 1, code_end);
                                paint(base + static_cast<LONG>(k), base + static_cast<LONG>(e), string_color);
                                k = e;
                            } else if (std::iswxdigit(line[k]) && (k == stop || !std::iswalnum(line[k - 1]) && line[k - 1] != L'_')) {
                                std::size_t e = k;
                                while (e < code_end && std::iswxdigit(line[e])) ++e;
                                if (e < code_end && line[e] == L'h' && (e + 1 >= code_end || !std::iswalnum(line[e + 1]))) {
                                    paint(base + static_cast<LONG>(k), base + static_cast<LONG>(e + 1), number_color);
                                    k = e;
                                } else if (e == k + 1 && line[k] >= L'0' && line[k] <= L'9' && (e >= code_end || !std::iswalnum(line[e]))) {
                                    paint(base + static_cast<LONG>(k), base + static_cast<LONG>(e), number_color);
                                    k = e;
                                } else {
                                    k = e;
                                }
                            } else if (std::iswalpha(line[k]) || line[k] == L'_') {
                                std::size_t e = k;
                                while (e < code_end && (std::iswalnum(line[e]) || line[e] == L'_')) ++e;
                                const std::wstring name = line.substr(k, e - k);
                                if (name.rfind(L"loc_", 0) == 0 || name.rfind(L"sub_", 0) == 0) paint(base + static_cast<LONG>(k), base + static_cast<LONG>(e), label_color);
                                k = e - 1;
                            }
                        }
                    }
                }
            } else if (tab != 1 && tab != 5 && line_number < 2 && semicolon == std::wstring::npos) {
                paint(base, base + static_cast<LONG>(line.size()), head_color);
            }
        }
        offset += static_cast<LONG>(line.size()) + (eol == std::wstring::npos ? 0 : 1);
        i = eol == std::wstring::npos ? text.size() : eol + 1;
        ++line_number;
    }
    SendMessageW(g_editor, EM_EXSETSEL, 0, reinterpret_cast<LPARAM>(&saved));
    SendMessageW(g_editor, EM_SETEVENTMASK, 0, old_mask);
    SendMessageW(g_editor, WM_SETREDRAW, TRUE, 0);
    if (!editor_was_visible) ShowWindow(g_editor, SW_HIDE);
    else InvalidateRect(g_editor, nullptr, TRUE);
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
            const auto& binary = g_database->image().bytes;
            const char* binary_begin = reinterpret_cast<const char*>(binary.data());
            const char* binary_end = binary_begin + binary.size();
            std::wostringstream result; std::size_t match_count = 0;
            result << L"Regex matches for /" << expression << L"/\r\n\r\n";
            for (std::regex_iterator<const char*> match(binary_begin, binary_end, matcher), end;
                 match != end && match_count < 500; ++match, ++match_count) {
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

// Short printable-string preview at a virtual address, or empty when the
// bytes there are not a clean ASCII string. Used to annotate string xrefs.
std::wstring xref_string_preview(std::uint64_t va) {
    if (!g_database) return {};
    const auto off = g_database->image().va_to_file_offset(va);
    if (!off) return {};
    const auto& bytes = g_database->image().bytes;
    std::wstring out; std::size_t i = *off;
    for (; i < bytes.size() && out.size() < 40; ++i) {
        const auto c = bytes[i];
        if (c == 0) break;
        if (c < 0x20 || c > 0x7e) return {};
        out.push_back(static_cast<wchar_t>(c));
    }
    if (out.empty()) return {};
    const bool terminated = i < bytes.size() && bytes[i] == 0;
    return L"\"" + out + (terminated ? L"\"" : L"...\"");
}

// A friendly label for a referenced address: custom label, import, function name
// or a string preview; empty when nothing is known.
std::wstring xref_symbol(std::uint64_t addr, const std::string& kind) {
    if (!g_database) return {};
    if (const auto it = g_custom_labels.find(addr); it != g_custom_labels.end()) return it->second;
    for (const auto& imp : g_database->image().imports) if (imp.address == addr) return wide(imp.name);
    if (const auto fn = g_database->function_at(addr); fn && fn->get().start == addr && !fn->get().name.empty())
        return wide(fn->get().name);
    if (kind == "string") return xref_string_preview(addr);
    return {};
}

// The source site as "function+0xNN".
std::wstring xref_from_label(std::uint64_t from) {
    if (!g_database) return {};
    const auto fn = g_database->function_at(from);
    if (!fn) return {};
    std::wstring base = g_custom_labels.contains(fn->get().start) ? g_custom_labels[fn->get().start] : wide(fn->get().name);
    if (const auto delta = from - fn->get().start) { wchar_t buf[24]; swprintf_s(buf, L"+0x%llX", static_cast<unsigned long long>(delta)); base += buf; }
    return base;
}

void list_xrefs(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Сначала выбери адрес.", L"XREFs", MB_ICONINFORMATION); return; }
    std::wostringstream result;
    const auto target_name = xref_symbol(g_current_address, "");
    result << L"XREFs for 0x" << std::hex << std::uppercase << g_current_address;
    if (!target_name.empty()) result << L"  (" << target_name << L")";
    result << L"\r\n\r\nFrom                          To                      Type\r\n";
    const auto references = g_database->xrefs_at(g_current_address);
    std::size_t count = 0;
    for (const auto& reference : references) {
        const auto& xref = reference.get();
        std::wstring from_text = xref_from_label(xref.from);
        std::wostringstream from_cell; from_cell << L"0x" << std::hex << std::uppercase << xref.from;
        if (!from_text.empty()) from_cell << L" " << from_text;
        std::wstring from_str = from_cell.str();
        if (from_str.size() < 30) from_str.append(30 - from_str.size(), L' ');
        const auto to_name = xref_symbol(xref.to, xref.kind);
        result << from_str << L"0x" << std::hex << std::uppercase << xref.to << L"  " << wide(xref.kind);
        if (!to_name.empty()) result << L"  " << to_name;
        result << L"\r\n";
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

std::optional<std::uint64_t> resolve_jump_target(std::wstring text);

namespace builtin_asm {
std::string squeeze(const std::wstring& input) {
    std::string out; bool space = false;
    for (wchar_t ch : input) {
        if (ch == L',' ) { while (!out.empty() && out.back() == ' ') out.pop_back(); out += ','; space = true; continue; }
        if (ch == L' ' || ch == L'\t') { if (!out.empty() && !space) { out += ' '; space = true; } continue; }
        space = false; out += static_cast<char>(ch < 128 ? std::tolower(static_cast<int>(ch)) : '?');
    }
    while (!out.empty() && (out.back() == ' ')) out.pop_back();
    return out;
}

bool parse_number(const std::string& token, std::int64_t& value) {
    if (token.empty()) return false;
    std::string t = token; bool negative = false;
    if (t[0] == '-') { negative = true; t.erase(0, 1); } else if (t[0] == '+') t.erase(0, 1);
    if (t.empty()) return false;
    try {
        std::size_t used = 0; unsigned long long v = 0;
        if (t.rfind("0x", 0) == 0) v = std::stoull(t.substr(2), &used, 16), used += 2;
        else if (t.back() == 'h') { v = std::stoull(t.substr(0, t.size() - 1), &used, 16); used += 1; }
        else if (t[0] == '#') { return parse_number(t.substr(1), value) && (negative ? (value = -value, true) : true); }
        else v = std::stoull(t, &used, 10);
        if (used != t.size()) return false;
        value = negative ? -static_cast<std::int64_t>(v) : static_cast<std::int64_t>(v);
        return true;
    } catch (...) { return false; }
}

bool parse_target(const std::string& token, std::uint64_t& value) {
    std::int64_t number = 0;
    // branch targets are addresses: bare digits are hex, like in IDA
    if (!token.empty() && token.size() <= 16 && token.find_first_not_of("0123456789abcdef") == std::string::npos) { value = std::stoull(token, nullptr, 16); return true; }
    if (parse_number(token, number)) { value = static_cast<std::uint64_t>(number); return true; }
    if (const auto resolved = resolve_jump_target(wide(token))) { value = *resolved; return true; }
    return false;
}

int reg_index(const std::string& name, int& bits) {
    static const char* r64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"};
    static const char* r32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    for (int i = 0; i < 8; ++i) { if (name == r64[i]) { bits = 64; return i; } if (name == r32[i]) { bits = 32; return i; } }
    if (name.size() >= 2 && name[0] == 'r' && std::isdigit(static_cast<unsigned char>(name[1]))) {
        std::string digits = name.substr(1); int width = 64;
        if (digits.back() == 'd') { digits.pop_back(); width = 32; }
        if (digits.find_first_not_of("0123456789") != std::string::npos) return -1;
        const int n = std::stoi(digits);
        if (n >= 8 && n <= 15) { bits = width; return n; }
    }
    return -1;
}

void emit32(std::vector<std::uint8_t>& out, std::uint32_t value) { for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>(value >> (8 * i))); }

std::vector<std::uint8_t> x86(const std::string& text, std::uint64_t address, bool is64, std::string& error) {
    std::vector<std::uint8_t> out;
    if (text == "nop") return {0x90};
    if (text == "ret" || text == "retn") return {0xC3};
    if (text == "int3") return {0xCC};
    if (text == "leave") return {0xC9};
    if (text == "hlt") return {0xF4};
    if (text == "ud2") return {0x0F, 0x0B};
    if (text == "syscall") return {0x0F, 0x05};
    const auto space = text.find(' ');
    const std::string op = text.substr(0, space);
    const std::string rest = space == std::string::npos ? "" : text.substr(space + 1);
    std::string a = rest, b;
    if (const auto comma = rest.find(','); comma != std::string::npos) { a = rest.substr(0, comma); b = rest.substr(comma + 1); }
    int bits_a = 0, bits_b = 0;
    if (op == "ret" || op == "retn") { std::int64_t n; if (parse_number(a, n) && n >= 0 && n < 65536) return {0xC2, static_cast<std::uint8_t>(n), static_cast<std::uint8_t>(n >> 8)}; }
    if (op == "int") { std::int64_t n; if (parse_number(a, n) && n >= 0 && n < 256) return {0xCD, static_cast<std::uint8_t>(n)}; }
    if (op == "push" || op == "pop") {
        const int r = reg_index(a, bits_a);
        if (r >= 0 && (is64 ? bits_a == 64 : bits_a == 32)) {
            if (r >= 8) out.push_back(0x41);
            out.push_back(static_cast<std::uint8_t>((op == "push" ? 0x50 : 0x58) + (r & 7))); return out;
        }
        std::int64_t n; if (op == "push" && parse_number(a, n)) { if (n >= -128 && n <= 127) return {0x6A, static_cast<std::uint8_t>(n)}; out.push_back(0x68); emit32(out, static_cast<std::uint32_t>(n)); return out; }
    }
    if (op == "mov" || op == "xor" || op == "test" || op == "add" || op == "sub" || op == "cmp" || op == "and" || op == "or") {
        const int dst = reg_index(a, bits_a);
        if (dst >= 0) {
            const int src = reg_index(b, bits_b);
            std::int64_t imm = 0;
            const bool wide_dst = bits_a == 64;
            if (src >= 0 && bits_a == bits_b) {
                std::uint8_t opcode = op == "mov" ? 0x89 : op == "xor" ? 0x31 : op == "test" ? 0x85 : op == "add" ? 0x01 : op == "sub" ? 0x29 : op == "cmp" ? 0x39 : op == "and" ? 0x21 : 0x09;
                const std::uint8_t rex = static_cast<std::uint8_t>(0x40 | (wide_dst ? 8 : 0) | (src >= 8 ? 4 : 0) | (dst >= 8 ? 1 : 0));
                if (rex != 0x40) out.push_back(rex);
                out.push_back(opcode); out.push_back(static_cast<std::uint8_t>(0xC0 | ((src & 7) << 3) | (dst & 7))); return out;
            }
            if (parse_number(b, imm)) {
                if (op == "mov") {
                    if (!wide_dst) { if (dst >= 8) out.push_back(0x41); out.push_back(static_cast<std::uint8_t>(0xB8 + (dst & 7))); emit32(out, static_cast<std::uint32_t>(imm)); return out; }
                    if (imm >= INT32_MIN && imm <= INT32_MAX) { out.push_back(static_cast<std::uint8_t>(0x48 | (dst >= 8 ? 1 : 0))); out.push_back(0xC7); out.push_back(static_cast<std::uint8_t>(0xC0 | (dst & 7))); emit32(out, static_cast<std::uint32_t>(imm)); return out; }
                    out.push_back(static_cast<std::uint8_t>(0x48 | (dst >= 8 ? 1 : 0))); out.push_back(static_cast<std::uint8_t>(0xB8 + (dst & 7)));
                    for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>(static_cast<std::uint64_t>(imm) >> (8 * i))); return out;
                }
                const int ext = op == "add" ? 0 : op == "or" ? 1 : op == "and" ? 4 : op == "sub" ? 5 : op == "cmp" ? 7 : -1;
                if (ext >= 0 && imm >= -128 && imm <= 127) {
                    const std::uint8_t rex = static_cast<std::uint8_t>(0x40 | (wide_dst ? 8 : 0) | (dst >= 8 ? 1 : 0)); if (rex != 0x40) out.push_back(rex);
                    out.push_back(0x83); out.push_back(static_cast<std::uint8_t>(0xC0 | (ext << 3) | (dst & 7))); out.push_back(static_cast<std::uint8_t>(imm)); return out;
                }
            }
        }
    }
    if (op == "jmp" || op == "call" || (op.size() >= 2 && op[0] == 'j')) {
        static const std::pair<const char*, int> conditions[] = {{"jo", 0}, {"jno", 1}, {"jb", 2}, {"jc", 2}, {"jnae", 2}, {"jae", 3}, {"jnb", 3}, {"jnc", 3}, {"je", 4}, {"jz", 4}, {"jne", 5}, {"jnz", 5}, {"jbe", 6}, {"jna", 6}, {"ja", 7}, {"jnbe", 7}, {"js", 8}, {"jns", 9}, {"jp", 10}, {"jnp", 11}, {"jl", 12}, {"jnge", 12}, {"jge", 13}, {"jnl", 13}, {"jle", 14}, {"jng", 14}, {"jg", 15}, {"jnle", 15}};
        int condition = -1; for (const auto& [name, code] : conditions) if (op == name) condition = code;
        std::uint64_t target = 0;
        if ((op == "jmp" || op == "call" || condition >= 0) && parse_target(a, target)) {
            const auto short_delta = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(address + 2);
            if ((op == "jmp" || condition >= 0) && short_delta >= -128 && short_delta <= 127) { out.push_back(op == "jmp" ? 0xEB : static_cast<std::uint8_t>(0x70 + condition)); out.push_back(static_cast<std::uint8_t>(short_delta)); return out; }
            if (op == "jmp" || op == "call") { out.push_back(op == "jmp" ? 0xE9 : 0xE8); emit32(out, static_cast<std::uint32_t>(static_cast<std::int64_t>(target) - static_cast<std::int64_t>(address + 5))); return out; }
            out.push_back(0x0F); out.push_back(static_cast<std::uint8_t>(0x80 + condition)); emit32(out, static_cast<std::uint32_t>(static_cast<std::int64_t>(target) - static_cast<std::int64_t>(address + 6))); return out;
        }
    }
    error = "unsupported by built-in assembler";
    return {};
}

std::vector<std::uint8_t> arm64(const std::string& text, std::uint64_t address, std::string& error) {
    auto word = [](std::uint32_t value) { return std::vector<std::uint8_t>{static_cast<std::uint8_t>(value), static_cast<std::uint8_t>(value >> 8), static_cast<std::uint8_t>(value >> 16), static_cast<std::uint8_t>(value >> 24)}; };
    if (text == "nop") return word(0xD503201F);
    if (text == "ret") return word(0xD65F03C0);
    const auto space = text.find(' ');
    const std::string op = text.substr(0, space);
    const std::string rest = space == std::string::npos ? "" : text.substr(space + 1);
    std::uint64_t target = 0; std::int64_t number = 0;
    if ((op == "b" || op == "bl") && parse_target(rest, target)) {
        const auto delta = (static_cast<std::int64_t>(target) - static_cast<std::int64_t>(address)) / 4;
        if (delta >= -(1 << 25) && delta < (1 << 25)) return word((op == "b" ? 0x14000000u : 0x94000000u) | (static_cast<std::uint32_t>(delta) & 0x03FFFFFFu));
    }
    if (op == "brk" && parse_number(rest, number) && number >= 0 && number < 65536) return word(0xD4200000u | (static_cast<std::uint32_t>(number) << 5));
    if (op == "mov") {
        const auto comma = rest.find(',');
        if (comma != std::string::npos) {
            const std::string reg = rest.substr(0, comma), imm = rest.substr(comma + 1);
            if (reg.size() >= 2 && (reg[0] == 'x' || reg[0] == 'w') && parse_number(imm, number) && number >= 0 && number < 65536) {
                try { const int rd = std::stoi(reg.substr(1)); if (rd >= 0 && rd < 31) return word((reg[0] == 'x' ? 0xD2800000u : 0x52800000u) | (static_cast<std::uint32_t>(number) << 5) | static_cast<std::uint32_t>(rd)); } catch (...) {}
            }
        }
    }
    error = "unsupported by built-in ARM64 assembler";
    return {};
}

// Raw bytes: "90", "EB 05", "0x90 0x90", "db 90 90"
bool raw_bytes(const std::wstring& input, std::vector<std::uint8_t>& out) {
    std::wstring text = input;
    if (lowered(text).rfind(L"db ", 0) == 0) text = text.substr(3);
    std::wstring token; out.clear();
    for (std::size_t i = 0; i <= text.size(); ++i) {
        const wchar_t ch = i < text.size() ? text[i] : L' ';
        if (std::iswspace(ch) || ch == L',') {
            if (token.empty()) continue;
            if (token.rfind(L"0x", 0) == 0 || token.rfind(L"0X", 0) == 0) token = token.substr(2);
            if (token.size() != 2 || token.find_first_not_of(L"0123456789abcdefABCDEF") != std::wstring::npos) return false;
            out.push_back(static_cast<std::uint8_t>(std::stoul(token, nullptr, 16))); token.clear();
        } else token.push_back(ch);
    }
    return !out.empty();
}
} // namespace builtin_asm

void edit_instruction(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Сначала выбери адрес инструкции.", L"Edit Instruction", MB_ICONINFORMATION); return; }
    const bool arm64 = g_database->image().architecture == gandon::MachineArchitecture::ARM64;
    const auto decoded = gandon::decode_x64(g_database->image(), g_current_address, 1);
    if (decoded.empty()) { MessageBoxW(window, L"Не удалось декодировать инструкцию.", L"Edit Instruction", MB_ICONERROR); return; }
    const auto& instruction = decoded.front();
    std::wstring original = wide(instruction.mnemonic + (instruction.operands.empty() ? "" : " " + instruction.operands));
    const auto replacement_text = prompt_text(window, L"Patch Instruction", L"Assembly instruction", original,
        arm64 ? L"nop, ret, b/bl target, mov x0,#imm, brk #n or raw bytes (1F 20 03 D5)" : L"Assembly (nop, jmp, mov, xor...) or raw bytes (90 90); Keystone is used when installed");
    if (!replacement_text || replacement_text->empty()) return;
    std::string assembly_error;
    std::vector<std::uint8_t> bytes;
    if (!builtin_asm::raw_bytes(*replacement_text, bytes)) {
        const auto normalized = builtin_asm::squeeze(*replacement_text);
        std::string builtin_error;
        bytes = arm64 ? builtin_asm::arm64(normalized, g_current_address, builtin_error) : builtin_asm::x86(normalized, g_current_address, g_database->image().image_base > 0xffffffffull, builtin_error);
        if (bytes.empty() && !arm64) {
            bytes = assemble_with_keystone(*replacement_text, g_current_address, g_database->image().image_base > 0xffffffffull, assembly_error);
            if (bytes.empty() && assembly_error.find("keystone") != std::string::npos) {
                if (MessageBoxW(window, L"Для сложных инструкций нужен пакет Python keystone-engine, он не установлен.\r\nУстановить сейчас (pip install keystone-engine)?", L"Patch Instruction", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                    SetWindowTextW(g_status, L"Installing keystone-engine...");
                    const auto command = python_interpreter_command() + " -m pip install keystone-engine 2>&1";
                    FILE* pipe = _popen(command.c_str(), "r"); std::string log;
                    if (pipe) { char buffer[256]{}; while (fgets(buffer, sizeof(buffer), pipe)) log += buffer; _pclose(pipe); }
                    assembly_error.clear();
                    bytes = assemble_with_keystone(*replacement_text, g_current_address, g_database->image().image_base > 0xffffffffull, assembly_error);
                    if (bytes.empty() && assembly_error.empty()) assembly_error = log.substr(log.size() > 400 ? log.size() - 400 : 0);
                }
            }
        } else if (bytes.empty()) assembly_error = builtin_error;
    }
    if (bytes.empty()) { MessageBoxW(window, wide(assembly_error.empty() ? "Не удалось собрать инструкцию." : assembly_error).c_str(), L"Patch Instruction", MB_ICONWARNING); return; }
    if (bytes.size() > instruction.size) { MessageBoxW(window, L"Новая инструкция длиннее исходной. Выбери инструкцию такого же или меньшего размера.", L"Patch Instruction", MB_ICONWARNING); return; }
    if (arm64 && bytes.size() != instruction.size) { MessageBoxW(window, L"Для ARM64 нужна ровно одна 4-байтовая инструкция.", L"Patch Instruction", MB_ICONWARNING); return; }
    std::vector<std::uint8_t> replacement = bytes; replacement.resize(instruction.size, 0x90);
    std::vector<std::uint8_t> original_bytes; std::string error;
    const auto offset = g_database->image().va_to_file_offset(g_current_address);
    if (!offset || !g_database->patch_bytes(g_current_address, replacement, original_bytes, error)) { MessageBoxW(window, wide(error).c_str(), L"Patch Instruction", MB_ICONERROR); return; }
    std::vector<PatchChange> changes; for (std::size_t i = 0; i < replacement.size(); ++i) if (replacement[i] != original_bytes[i]) changes.push_back({*offset + i, original_bytes[i], replacement[i]});
    if (!changes.empty()) { g_patch_undo.push_back(std::move(changes)); g_patch_redo.clear(); g_timeline.push_back('p'); g_timeline_redo.clear(); refresh_after_patch(window); SetWindowTextW(g_status, L"Instruction patched. Undo with Ctrl+Z."); }
}

// ---------------------------------------------------------------------------
// One-click semantic patches (no assembly typing): the operations a reverse
// engineer reaches for constantly — flip/force/kill a branch, stub a function
// to return 0 or 1. Each goes through the normal patch_bytes + undo pipeline.
// ---------------------------------------------------------------------------
std::optional<gandon::Instruction> instruction_at_cursor() {
    if (!g_database || !g_current_address) return std::nullopt;
    const auto decoded = gandon::decode_x64(g_database->image(), g_current_address, 1);
    if (decoded.empty() || decoded.front().size == 0) return std::nullopt;
    return decoded.front();
}

bool apply_semantic_patch(HWND window, std::uint64_t address, const std::vector<std::uint8_t>& replacement,
                          const wchar_t* title, const wchar_t* ok_status) {
    if (!g_database) return false;
    std::vector<std::uint8_t> original; std::string error;
    const auto offset = g_database->image().va_to_file_offset(address);
    if (!offset || !g_database->patch_bytes(address, replacement, original, error)) {
        MessageBoxW(window, wide(error.empty() ? std::string("Патч не применён (адрес не в файле?).") : error).c_str(), title, MB_ICONERROR);
        return false;
    }
    std::vector<PatchChange> changes;
    for (std::size_t i = 0; i < replacement.size(); ++i)
        if (replacement[i] != original[i]) changes.push_back({*offset + i, original[i], replacement[i]});
    if (changes.empty()) { SetWindowTextW(g_status, L"Нет изменений: байты уже такие."); return false; }
    g_patch_undo.push_back(std::move(changes)); g_patch_redo.clear(); g_timeline.push_back('p'); g_timeline_redo.clear();
    refresh_after_patch(window); SetWindowTextW(g_status, ok_status);
    return true;
}

// A conditional Jcc is either a 2-byte short form (0x70..0x7F) or a 6-byte near
// form (0x0F 0x80..0x8F). Reports which, so the branch ops can rewrite it.
bool classify_conditional_jump(const gandon::Instruction& ins, bool& is_short) {
    if (ins.size == 2 && ins.bytes[0] >= 0x70 && ins.bytes[0] <= 0x7F) { is_short = true; return true; }
    if (ins.size == 6 && ins.bytes[0] == 0x0F && ins.bytes[1] >= 0x80 && ins.bytes[1] <= 0x8F) { is_short = false; return true; }
    return false;
}

void invert_branch(HWND window) {
    const auto ins = instruction_at_cursor();
    if (!ins) { MessageBoxW(window, L"Сначала выбери инструкцию.", L"Invert Jump", MB_ICONINFORMATION); return; }
    bool is_short = false;
    if (!classify_conditional_jump(*ins, is_short)) {
        MessageBoxW(window, L"Это не условный переход (je/jne/jl/jg/...).", L"Invert Jump", MB_ICONINFORMATION); return;
    }
    // The low bit of the condition code selects the opposite predicate (je<->jne, jb<->jae, ...).
    std::vector<std::uint8_t> rep(ins->bytes.begin(), ins->bytes.begin() + ins->size);
    if (is_short) rep[0] ^= 0x01; else rep[1] ^= 0x01;
    apply_semantic_patch(window, g_current_address, rep, L"Invert Jump", L"Условие перехода инвертировано. Ctrl+Z — отмена.");
}

void force_branch(HWND window) {
    const auto ins = instruction_at_cursor();
    if (!ins) { MessageBoxW(window, L"Сначала выбери инструкцию.", L"Force Jump", MB_ICONINFORMATION); return; }
    bool is_short = false;
    if (!classify_conditional_jump(*ins, is_short)) {
        MessageBoxW(window, L"Это не условный переход — форсировать нечего.", L"Force Jump", MB_ICONINFORMATION); return;
    }
    std::vector<std::uint8_t> rep;
    if (is_short) {
        rep = {0xEB, ins->bytes[1]};               // jcc rel8 -> jmp short rel8 (same displacement)
    } else {
        // jcc rel32 (6 bytes) -> jmp rel32 (5 bytes) + NOP. The displacement is measured
        // from the end of the instruction, which moves back one byte, so add 1.
        std::int32_t rel = static_cast<std::int32_t>(ins->bytes[2] | (ins->bytes[3] << 8) |
                                                     (ins->bytes[4] << 16) | (ins->bytes[5] << 24));
        const std::int32_t adjusted = rel + 1;
        rep = {0xE9, static_cast<std::uint8_t>(adjusted), static_cast<std::uint8_t>(adjusted >> 8),
               static_cast<std::uint8_t>(adjusted >> 16), static_cast<std::uint8_t>(adjusted >> 24), 0x90};
    }
    apply_semantic_patch(window, g_current_address, rep, L"Force Jump", L"Переход сделан безусловным. Ctrl+Z — отмена.");
}

void never_branch(HWND window) {
    const auto ins = instruction_at_cursor();
    if (!ins) { MessageBoxW(window, L"Сначала выбери инструкцию.", L"Never Jump", MB_ICONINFORMATION); return; }
    bool is_short = false;
    if (!classify_conditional_jump(*ins, is_short)) {
        MessageBoxW(window, L"Это не условный переход — убирать нечего.", L"Never Jump", MB_ICONINFORMATION); return;
    }
    std::vector<std::uint8_t> rep(ins->size, 0x90);   // fall through: replace the Jcc with NOPs
    apply_semantic_patch(window, g_current_address, rep, L"Never Jump", L"Переход вырезан (всегда fall-through). Ctrl+Z — отмена.");
}

void stub_return(HWND window, bool one) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Сначала выбери адрес функции.", L"Stub Return", MB_ICONINFORMATION); return; }
    // xor eax,eax; ret  /  mov eax,1; ret
    std::vector<std::uint8_t> stub = one ? std::vector<std::uint8_t>{0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3}
                                         : std::vector<std::uint8_t>{0x31, 0xC0, 0xC3};
    // Pad with NOPs up to the end of whichever instructions the stub overruns, so the
    // disassembly stays aligned instead of leaving a dangling partial instruction.
    std::size_t covered = 0; std::uint64_t a = g_current_address;
    for (int guard = 0; guard < 8 && covered < stub.size(); ++guard) {
        const auto d = gandon::decode_x64(g_database->image(), a, 1);
        if (d.empty() || d.front().size == 0) break;
        covered += d.front().size; a += d.front().size;
    }
    std::vector<std::uint8_t> rep = stub;
    rep.resize((std::max)(stub.size(), covered), 0x90);
    apply_semantic_patch(window, g_current_address, rep, L"Stub Return",
                         one ? L"Функция застаблена: return 1. Ctrl+Z — отмена." : L"Функция застаблена: return 0. Ctrl+Z — отмена.");
}

// Popup with the semantic patch operations, reused by the Edit menu and the
// disassembly context menus. Ownership transfers to the parent menu.
HMENU build_patch_submenu() {
    HMENU patch = CreatePopupMenu();
    AppendMenuW(patch, MF_STRING, ID_INVERT_BRANCH, L"Invert Jump (je↔jne)");
    AppendMenuW(patch, MF_STRING, ID_FORCE_BRANCH, L"Force Jump (always)");
    AppendMenuW(patch, MF_STRING, ID_NOP_BRANCH, L"Never Jump (NOP)");
    AppendMenuW(patch, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(patch, MF_STRING, ID_STUB_RET0, L"Stub → return 0");
    AppendMenuW(patch, MF_STRING, ID_STUB_RET1, L"Stub → return 1");
    return patch;
}

// ---------------------------------------------------------------------------
// Jump to address / label
// ---------------------------------------------------------------------------
std::wstring lowered(std::wstring value) {
    for (auto& ch : value) ch = static_cast<wchar_t>(std::towlower(ch));
    return value;
}

bool parse_hex_value(const std::wstring& text, std::uint64_t& value) {
    if (text.empty() || text.size() > 16 || text.find_first_not_of(L"0123456789abcdefABCDEF") != std::wstring::npos) return false;
    value = std::stoull(text, nullptr, 16);
    return true;
}

bool address_is_mapped(std::uint64_t address) {
    if (!g_database) return false;
    return g_database->image().va_to_file_offset(address).has_value() || g_database->function_at(address).has_value();
}

std::optional<std::uint64_t> resolve_jump_target(std::wstring text) {
    if (!g_database) return std::nullopt;
    const auto first = text.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) return std::nullopt;
    text = text.substr(first, text.find_last_not_of(L" \t\r\n") - first + 1);
    const auto wanted = lowered(text);
    // 1. names: renamed labels, functions, imports and symbols
    for (const auto& [address, name] : g_custom_labels) if (lowered(name) == wanted) return address;
    for (const auto& function : g_database->functions()) if (!function.name.empty() && lowered(wide(function.name)) == wanted) return function.start;
    for (const auto& symbol : g_database->image().symbols) if (!symbol.name.empty() && lowered(wide(symbol.name)) == wanted) return symbol.address;
    for (const auto& import : g_database->image().imports) if (lowered(wide(import.name)) == wanted) return import.address;
    // 2. numeric forms: 0x1400, 1400h, .text:1400, sub_1400, plain hex
    std::wstring number = wanted;
    if (const auto colon = number.rfind(L':'); colon != std::wstring::npos) number = number.substr(colon + 1);
    for (const wchar_t* prefix : {L"sub_", L"loc_", L"off_", L"unk_", L"byte_", L"word_", L"dword_", L"qword_", L"nullsub_"}) {
        const std::wstring p = prefix;
        if (number.size() > p.size() && number.compare(0, p.size(), p) == 0) { number = number.substr(p.size()); break; }
    }
    if (number.rfind(L"0x", 0) == 0) number = number.substr(2);
    else if (!number.empty() && number.back() == L'h') number.pop_back();
    std::uint64_t value = 0;
    if (!parse_hex_value(number, value)) return std::nullopt;
    const auto base = g_database->image().image_base;
    if (!address_is_mapped(value) && base && value < base && address_is_mapped(base + value)) value += base; // RVA typed
    return value;
}

void jump_to_address(HWND window) {
    if (!g_database) { SetWindowTextW(g_status, L"Open a binary first."); return; }
    wchar_t initial[32]{}; swprintf_s(initial, L"%llX", static_cast<unsigned long long>(g_current_address));
    const auto value = prompt_text(window, L"Jump to address", L"Jump address", initial, L"Hex address, 0x..., sub_XXXX, function / label / import name");
    if (!value || value->empty()) return;
    const auto target = resolve_jump_target(*value);
    if (!target) { SetWindowTextW(g_status, (L"Cannot resolve: " + *value).c_str()); MessageBoxW(window, (L"Не удалось найти адрес или имя: " + *value).c_str(), L"Jump to address", MB_ICONWARNING); return; }
    if (!address_is_mapped(*target)) {
        wchar_t message[160]{}; swprintf_s(message, L"Адрес %llX не принадлежит образу.", static_cast<unsigned long long>(*target));
        SetWindowTextW(g_status, message); MessageBoxW(window, message, L"Jump to address", MB_ICONWARNING); return;
    }
    const int tab = TabCtrl_GetCurSel(g_tabs);
    navigate_to_address(window, *target, (tab == 0 || tab == 2) ? tab : 1);
    wchar_t status[96]{}; swprintf_s(status, L"Jumped to %llX", static_cast<unsigned long long>(*target));
    SetWindowTextW(g_status, status);
}

// ---------------------------------------------------------------------------
// Python console: a persistent interpreter with a small `gandon` API
// ---------------------------------------------------------------------------
namespace pyconsole {
constexpr UINT WM_PY_OUTPUT = WM_APP + 41;
constexpr UINT_PTR TIMER_COMMANDS = 77;
HWND window{}, output{}, input{};
HANDLE process{}, stdin_write{}, stdout_read{};
std::filesystem::path directory;
std::wstring meta_stamp;
std::vector<std::wstring> history; std::size_t history_pos = 0;
WNDPROC input_proc_old{};

const char* driver_source = R"PY(# -*- coding: utf-8 -*-
import sys, json, code, os
meta_path, cur_path, cmd_path = sys.argv[1], sys.argv[2], sys.argv[3]
_state = {"mtime": None, "meta": {}, "data": None}
def _meta():
    try:
        m = os.path.getmtime(meta_path)
        if m != _state["mtime"]:
            _state["mtime"] = m
            _state["meta"] = json.load(open(meta_path, encoding="utf-8"))
            _state["data"] = None
    except Exception:
        pass
    return _state["meta"]
def here():
    """Current address selected in the GUI."""
    try: return state()["address"]
    except Exception:
        try: return int(open(cur_path).read().strip() or "0", 16)
        except Exception: return 0
_req_dir = os.path.dirname(cmd_path)
_req_seq = [0]
def _esc(v):
    return str(v).replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")
def _call(op, *args, timeout=60.0):
    """Send one request to the GUI thread and wait for its answer."""
    import time
    _req_seq[0] += 1
    name = "%d_%d.txt" % (os.getpid(), _req_seq[0])
    req, tmp, resp = (os.path.join(_req_dir, "req_" + name), os.path.join(_req_dir, "tmp_" + name), os.path.join(_req_dir, "resp_" + name))
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join([_esc(op)] + [_esc(a) for a in args]) + "\n")
    os.replace(tmp, req)
    end = time.time() + timeout
    while time.time() < end:
        if os.path.exists(resp):
            time.sleep(0.005)
            data = open(resp, encoding="utf-8").read()
            try: os.remove(resp)
            except OSError: pass
            status, _, payload = data.partition("\n")
            if status == "OK": return payload
            raise RuntimeError(payload or "request failed")
        time.sleep(0.02)
    raise TimeoutError("GUI did not answer %r (a dialog may be waiting for you)" % op)
def _addr(a):
    return "" if a is None else (a if isinstance(a, str) else "0x%x" % int(a))
def goto(address, tab=None):
    """Navigate the GUI to an address or label. tab: 0 graph, 1 listing, 3 xrefs..."""
    _call("goto", _addr(address), "" if tab is None else tab)
def resolve(text):
    """Resolve a label / expression to an address."""
    return int(_call("resolve", text), 16)
def info():
    """Summary of the open binary (dict)."""
    return json.loads(_call("info"))
def state():
    """Current GUI state: address, tab, loaded, dirty, debugging."""
    d = dict(l.split("=", 1) for l in _call("state").splitlines() if "=" in l)
    return {"address": int(d["address"], 16), "tab": int(d["tab"]), "loaded": d["loaded"] == "1", "dirty": d["dirty"] == "1", "debugging": d["debugging"] == "1"}
def status(text=None):
    """Read (or set) the status bar text."""
    return _call("status") if text is None else _call("set_status", text)
def registers(show=True):
    """Debugger state + register dump (only meaningful while paused at a breakpoint)."""
    t = _call("registers")
    if show: print(t, end="")
    else: return t
def readmem(address, size=64):
    """Live process memory (debugger must be running+paused). Returns a list of ints."""
    return [int(x, 16) for x in _call("readmem", _addr(address), size).split()]
def readqword(address):
    return int(_call("readqword", _addr(address)), 16)
def readdword(address):
    return int(_call("readdword", _addr(address)), 16)
def disasm(address=None, count=16, show=True):
    """Disassemble `count` instructions (default: at the current address)."""
    t = _call("disasm", _addr(address), count)
    if show: print(t, end="")
    else: return t
def listing(address=None, show=True):
    t = _call("listing", _addr(address))
    if show: print(t, end="")
    else: return t
def decompile(address=None, comments=False, show=True):
    """Pseudocode of the function at `address` (default: current)."""
    t = _call("decompile", _addr(address), "1" if comments else "0")
    if show: print(t, end="")
    else: return t
def hexview(address=None, show=True):
    t = _call("hexdump", _addr(address))
    if show: print(t, end="")
    else: return t
def imports(show=True):
    t = _call("imports"); print(t, end="") if show else None; return None if show else t
def exports(show=True):
    t = _call("exports"); print(t, end="") if show else None; return None if show else t
def resources(show=True):
    t = _call("resources"); print(t, end="") if show else None; return None if show else t
def segments(show=True):
    t = _call("segments"); print(t, end="") if show else None; return None if show else t
def gui_strings(show=True):
    """Strings window text from the GUI (see also strings(min) for a python scan)."""
    t = _call("strings"); print(t, end="") if show else None; return None if show else t
def find_bytes(pattern):
    """Addresses matching a hex pattern like "48 8B ?? 05"."""
    return [int(x, 16) for x in _call("find_bytes", pattern).split()]
def find_text(text):
    return [int(x, 16) for x in _call("find_text", text).split()]
def rename(address, name):
    """Rename a label / function."""
    _call("rename", _addr(address), name)
def comment(address, text):
    _call("comment", _addr(address), text)
def patch(address, data):
    """Patch bytes (hex string "90 90" or bytes) at a virtual address; undo with act("undo_patch")."""
    if isinstance(data, (bytes, bytearray)): data = " ".join("%02X" % b for b in data)
    _call("patch", _addr(address), data)
def nop(address, count=1):
    """NOP `count` bytes at address."""
    patch(address, "90 " * count)
def types_add(source):
    """Add C declarations (struct/union/enum/typedef) to the local types."""
    _call("types_add", source)
def types_text():
    """Everything in Local Types, formatted."""
    return _call("types_text")
def sizeof(type_name):
    return int(_call("sizeof", type_name))
def field_at(type_name, offset):
    return _call("field_at", type_name, offset)
def apply_struct(address, type_name=""):
    """Show [reg+disp] of the instruction at `address` as [reg+TYPE.field] (empty type removes)."""
    _call("struct", _addr(address), type_name)
def apply_enum(address, type_name=""):
    """Show the immediate of the instruction at `address` as an enum constant."""
    _call("enum", _addr(address), type_name)
def set_prototype(address, text=""):
    """Attach a prototype such as "int __fastcall f(int a, char *b)" to the function at `address`."""
    _call("prototype", _addr(address), text)
def diff(path, show=True):
    """Compare the open binary with another one function by function (opens the Diff panel)."""
    text = _call("diff", path, timeout=300.0)
    if show: print(text, end="")
    else: return text
def auto_analysis():
    """Run auto-analysis (recursive descent + signatures) and refresh the GUI."""
    return _call("auto_analysis")
def save_db(path):
    _call("save_db", path)
def load_db(path):
    _call("load_db", path)
def actions():
    """Names of every GUI action that act() accepts."""
    return _call("actions").split()
def act(name, address=None):
    """Run any menu/toolbar action by name (e.g. act("run"), act("view_pseudocode")). Optional address selects it first."""
    if address is not None: goto(address)
    return _call("act", name)
def view(name):
    """Switch the main tab: graph, listing, pseudocode, hex, types, imports, exports, strings, resources, symbols, memory, problems, llil, debugger."""
    return act("view_" + name)
def bp(address=None):
    """Toggle a breakpoint at `address` (default: current)."""
    return act("toggle_bp", address)
def run(): return act("run")
def stop(): return act("stop")
def pause(): return act("pause")
def step_into(): return act("step_into")
def step_over(): return act("step_over")
def bookmark(address=None): return act("bookmark", address)
def undo(): return act("undo_patch")
def redo(): return act("redo_patch")
def functions():
    """List of (start, name) for every discovered function."""
    return [(f[0], f[1]) for f in _meta().get("functions", [])]
def function(key=None):
    """Find a function by name or address (default: the current one)."""
    fs = _meta().get("functions", [])
    if key is None: key = here()
    if isinstance(key, str):
        for f in fs:
            if f[1] == key: return (f[0], f[1])
        return None
    best = None
    for f in fs:
        if f[0] <= key: best = f
        else: break
    return (best[0], best[1]) if best else None
def xrefs_to(address):
    """XREFs pointing at `address`: [(from, kind)]."""
    return [(x[0], x[2]) for x in _meta().get("xrefs", []) if x[1] == address]
def xrefs_from(address):
    return [(x[1], x[2]) for x in _meta().get("xrefs", []) if x[0] == address]
def _file_data():
    if _state["data"] is None:
        _state["data"] = open(_meta()["path"], "rb").read()
    return _state["data"]
def read(address, size=16):
    """Read bytes from the image at a virtual address."""
    m = _meta(); base = m.get("image_base", 0); data = _file_data()
    for s in m.get("sections", []):
        start = base + s[1]
        span = max(s[2], s[4])
        if start <= address < start + span:
            off = s[3] + (address - start)
            return data[off:off + size]
    raise ValueError("address 0x%x is not inside any section" % address)
def hexdump(address, size=64):
    b = read(address, size)
    for i in range(0, len(b), 16):
        chunk = b[i:i+16]
        print("%016X  %-47s  %s" % (address + i, " ".join("%02X" % c for c in chunk), "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))
def strings(minimum=5):
    """ASCII strings found in the file: [(file_offset, text)]."""
    import re
    return [(m.start(), m.group().decode("ascii")) for m in re.finditer(rb"[ -~]{%d,}" % minimum, _file_data())]
def help():
    print("gandon console - everything the GUI does is scriptable:\n"
          "  navigation : here() goto(a) resolve(s) state() status() view(name)\n"
          "  analysis   : functions() function(x) xrefs_to(a) xrefs_from(a) info() auto_analysis() find_bytes(p) find_text(s)\n"
          "  views      : disasm(a,n) listing(a) decompile(a) hexview(a) imports() exports() resources() segments() gui_strings()\n"
          "  data       : read(a,n) hexdump(a,n) strings(min) image_base entry path\n"
          "  editing    : rename(a,n) comment(a,t) patch(a,hex) nop(a,n) undo() redo() bookmark(a)\n"
          "  debugging  : bp(a) run() pause() step_into() step_over() stop()\n"
          "  database   : save_db(p) load_db(p)\n"
          "  types      : types_add(src) types_text() sizeof(t) field_at(t,off) apply_struct(a,t) apply_enum(a,t) set_prototype(a,text)\n"
          "  any action : act(name[,addr]) - actions() lists all menu items (emulation, LLIL, call graph, sigmaker, ...)\n"
          "  addresses may be ints, labels ('main') or hex strings")
ns = {k: v for k, v in globals().items() if not k.startswith("_") and k not in ("sys", "json", "code", "os", "meta_path", "cur_path", "cmd_path")}
ns["_call"] = _call
def _refresh():
    m = _meta(); ns["image_base"] = m.get("image_base", 0); ns["entry"] = m.get("entry", 0); ns["path"] = m.get("path", "")
_refresh()
console = code.InteractiveConsole(ns)
print("Gandon-PRO Python %s  -  type help() for the gandon API" % sys.version.split()[0])
more = False
while True:
    sys.stdout.write("... " if more else ">>> "); sys.stdout.flush()
    line = sys.stdin.readline()
    if not line: break
    _refresh()
    more = console.push(line.rstrip("\r\n"))
)PY";

std::string json_escape(const std::string& value) {
    std::string out;
    for (unsigned char ch : value) {
        if (ch == '"' || ch == '\'') { out += '\''; out += static_cast<char>(ch); }
        else if (ch < 0x20) { char buffer[8]; snprintf(buffer, sizeof(buffer), "\\u%04x", ch); out += buffer; }
        else out += static_cast<char>(ch);
    }
    return out;
}

void write_meta() {
    std::wstring stamp = g_database ? g_database->image().path.wstring() + L"|" + std::to_wstring(g_database->functions().size()) + L"|" + std::to_wstring(g_database->xrefs().size()) + L"|" + std::to_wstring([] { std::size_t h = g_custom_labels.size(); for (const auto& [a, n] : g_custom_labels) h ^= static_cast<std::size_t>(a) * 31u + std::hash<std::wstring>{}(n); return h; }()) : L"";
    if (stamp == meta_stamp && std::filesystem::exists(directory / L"meta.json")) return;
    meta_stamp = stamp;
    std::ostringstream out;
    out << "{";
    if (g_database) {
        const auto& image = g_database->image();
        out << "\"path\":\"" << json_escape(utf8_from_wide(image.path.generic_wstring())) << "\",\"image_base\":" << image.image_base << ",\"entry\":" << image.entry_point << ",\"sections\":[";
        bool first = true;
        for (const auto& section : image.sections) {
            out << (first ? "" : ",") << "[\"" << json_escape(section.name) << "\"," << section.rva << "," << section.virtual_size << "," << section.raw_offset << "," << section.raw_size << "]"; first = false;
        }
        out << "],\"functions\":[";
        first = true;
        for (const auto& function : g_database->functions()) {
            std::string name = g_custom_labels.contains(function.start) ? utf8_from_wide(g_custom_labels[function.start]) : function.name;
            if (name.empty()) { char buffer[40]; snprintf(buffer, sizeof(buffer), "sub_%llX", static_cast<unsigned long long>(function.start)); name = buffer; }
            out << (first ? "" : ",") << "[" << function.start << ",\"" << json_escape(name) << "\"]"; first = false;
        }
        out << "],\"xrefs\":[";
        first = true; std::size_t count = 0;
        for (const auto& xref : g_database->xrefs()) {
            if (++count > 200000) break;
            out << (first ? "" : ",") << "[" << xref.from << "," << xref.to << ",\"" << json_escape(xref.kind) << "\"]"; first = false;
        }
        out << "]";
    }
    out << "}";
    std::ofstream file(directory / L"meta.json", std::ios::binary | std::ios::trunc);
    file << out.str();
}

void write_current() {
    std::ofstream file(directory / L"cur.txt", std::ios::trunc);
    file << std::hex << g_current_address;
}

void append_output(const std::wstring& text) {
    if (!output) return;
    std::wstring fixed; fixed.reserve(text.size() + 8);
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == L'\r') continue;
        if (text[i] == L'\n') fixed += L"\r\n"; else fixed += text[i];
    }
    const int length = GetWindowTextLengthW(output);
    if (length > 400000) { SendMessageW(output, EM_SETSEL, 0, 100000); SendMessageW(output, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L"")); }
    const int end = GetWindowTextLengthW(output);
    SendMessageW(output, EM_SETSEL, end, end);
    SendMessageW(output, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(fixed.c_str()));
    SendMessageW(output, EM_SCROLLCARET, 0, 0);
}

void reader_thread(HANDLE pipe, HWND target) {
    char buffer[4096]; DWORD read = 0;
    std::string pending;
    while (ReadFile(pipe, buffer, sizeof(buffer), &read, nullptr) && read) {
        pending.append(buffer, read);
        // never split a UTF-8 sequence between two messages
        std::size_t complete = pending.size();
        while (complete > 0 && (static_cast<unsigned char>(pending[complete - 1]) & 0xC0) == 0x80) --complete;
        if (complete > 0 && static_cast<unsigned char>(pending[complete - 1]) >= 0xC0) --complete;
        if (complete == 0) continue;
        const int size = MultiByteToWideChar(CP_UTF8, 0, pending.data(), static_cast<int>(complete), nullptr, 0);
        auto* text = new std::wstring(static_cast<std::size_t>(size), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, pending.data(), static_cast<int>(complete), text->data(), size);
        pending.erase(0, complete);
        if (!PostMessageW(target, WM_PY_OUTPUT, reinterpret_cast<WPARAM>(text), 0)) { delete text; break; }
    }
    PostMessageW(target, WM_PY_OUTPUT, 0, 0);
}

void stop_process() {
    if (process) { TerminateProcess(process, 0); CloseHandle(process); process = nullptr; }
    if (stdin_write) { CloseHandle(stdin_write); stdin_write = nullptr; }
    // stdout_read is owned by the reader thread's pipe; closing it ends the thread
    if (stdout_read) { CloseHandle(stdout_read); stdout_read = nullptr; }
}

bool start_process() {
    stop_process();
    wchar_t temp[MAX_PATH]{}; GetTempPathW(MAX_PATH, temp);
    directory = std::filesystem::path(temp) / (L"gandon_pyconsole_" + std::to_wstring(GetCurrentProcessId()));
    std::error_code ignored; std::filesystem::create_directories(directory, ignored);
    { std::ofstream driver(directory / L"driver.py", std::ios::binary | std::ios::trunc); driver << driver_source; }
    { std::ofstream commands(directory / L"cmd.txt", std::ios::trunc); }
    meta_stamp.clear(); write_meta(); write_current();

    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE child_in_read{}, child_out_write{};
    if (!CreatePipe(&child_in_read, &stdin_write, &security, 0) || !CreatePipe(&stdout_read, &child_out_write, &security, 0)) return false;
    SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW startup{sizeof(startup)}; startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = child_in_read; startup.hStdOutput = child_out_write; startup.hStdError = child_out_write;
    std::wstring command = wide(python_interpreter_command()) + L" -u " + quote_process_argument(directory / L"driver.py") + L" "
        + quote_process_argument(directory / L"meta.json") + L" " + quote_process_argument(directory / L"cur.txt") + L" " + quote_process_argument(directory / L"cmd.txt");
    SetEnvironmentVariableW(L"PYTHONUTF8", L"1"); SetEnvironmentVariableW(L"PYTHONIOENCODING", L"utf-8");
    PROCESS_INFORMATION info{};
    const BOOL created = CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info);
    CloseHandle(child_in_read); CloseHandle(child_out_write);
    if (!created) { stop_process(); return false; }
    CloseHandle(info.hThread); process = info.hProcess;
    std::thread(reader_thread, stdout_read, window).detach();
    return true;
}

void submit_line() {
    const int length = GetWindowTextLengthW(input);
    std::wstring line(static_cast<std::size_t>(length) + 1, L'\0');
    GetWindowTextW(input, line.data(), length + 1); line.resize(static_cast<std::size_t>(length));
    SetWindowTextW(input, L"");
    append_output(line + L"\n");
    if (!line.empty() && (history.empty() || history.back() != line)) history.push_back(line);
    history_pos = history.size();
    if (!stdin_write) { append_output(L"[python is not running - close and reopen the console]\n"); return; }
    write_meta(); write_current();
    const std::string utf8 = utf8_from_wide(line) + "\n";
    DWORD written = 0; WriteFile(stdin_write, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
}

// ---- request/response bridge: the Python console can call any GUI action or data query ----
struct ActionName { const char* name; int id; };
const ActionName kActions[] = {
    {"open", ID_OPEN}, {"save_db", ID_SAVE_DB}, {"load_db", ID_LOAD_DB}, {"apply_patches", ID_APPLY_PATCHES}, {"export_graph", ID_EXPORT_GRAPH},
    {"export_json", ID_EXPORT_JSON}, {"export_breakpoints", ID_EXPORT_BREAKPOINTS}, {"export_debug_log", ID_EXPORT_DEBUG_LOG}, {"export_trace", ID_EXPORT_TRACE},
    {"rename", ID_RENAME_LABEL}, {"comment", ID_ADD_COMMENT}, {"assign_type", ID_ASSIGN_TYPE}, {"nop_block", ID_NOP_BLOCK}, {"edit_instruction", ID_EDIT_INSTRUCTION},
    {"invert_branch", ID_INVERT_BRANCH}, {"force_branch", ID_FORCE_BRANCH}, {"never_branch", ID_NOP_BRANCH}, {"stub_ret0", ID_STUB_RET0}, {"stub_ret1", ID_STUB_RET1},
    {"dump_module", ID_DUMP_MODULE}, {"detect_vm", ID_DETECT_VM}, {"emulate_decrypt", ID_EMULATE_DECRYPT},
    {"trace_vm", ID_TRACE_VM}, {"analyze_dotnet", ID_ANALYZE_DOTNET},
    {"recover_rtti", ID_RECOVER_RTTI}, {"analyze_driver", ID_ANALYZE_DRIVER}, {"devirtualize_vm", ID_DEVIRT_VM},
    {"undo_patch", ID_UNDO_PATCH}, {"redo_patch", ID_REDO_PATCH},
    {"jump_dialog", ID_JUMP_ADDR}, {"jump_back", ID_JUMP_BACK}, {"bookmark", ID_TOGGLE_BOOKMARK}, {"next_bookmark", ID_NEXT_BOOKMARK}, {"list_xrefs", ID_LIST_XREFS},
    {"find_function", ID_FIND_FUNCTION}, {"call_graph", ID_CALL_GRAPH}, {"find_call_path", ID_PATHFINDER},
    {"decompile", ID_DECOMPILE}, {"sigmaker", ID_SIGMAKER}, {"search_signature", ID_SEARCH_SIGNATURE}, {"search", ID_SEARCH},
    {"memory_view", ID_MEMORY_VIEW}, {"memory_snapshot", ID_MEMORY_SNAPSHOT}, {"memory_compare", ID_MEMORY_COMPARE}, {"search_process_memory", ID_SEARCH_PROCESS_MEMORY},
    {"compare_binary", ID_COMPARE}, {"load_plugin", ID_PLUGIN_LOAD}, {"hidden_symbols", ID_HIDDEN_SYMBOLS}, {"restore_hidden", ID_RESTORE_HIDDEN},
    {"watch_locals", ID_WATCH_LOCALS}, {"call_stack", ID_CALL_STACK}, {"trace_toggle", ID_TRACE_TOGGLE},
    {"run", ID_RUN}, {"pause", ID_PAUSE}, {"step_into", ID_STEP_INTO}, {"step_over", ID_STEP_OVER}, {"stop", ID_STOP},
    {"toggle_bp", ID_TOGGLE_BP}, {"cond_bp", ID_COND_BP}, {"config_bp", ID_CONFIG_BP}, {"bp_manager", ID_BP_MANAGER}, {"hw_bp", ID_HW_BP}, {"delete_bp", ID_DELETE_BP},
    {"emulate", ID_EMULATE}, {"emulate_prepare", ID_EMULATE_PREPARE}, {"emulate_step", ID_EMULATE_STEP}, {"emulate_step_over", ID_EMULATE_STEP_OVER},
    {"emulate_step_out", ID_EMULATE_STEP_OUT}, {"emulate_breakpoint", ID_EMULATE_BREAKPOINT}, {"emulate_watchpoint", ID_EMULATE_WATCHPOINT},
    {"emulate_clear_watchpoints", ID_EMULATE_CLEAR_WATCHPOINTS}, {"emulate_register_deltas", ID_EMULATE_REGISTER_DELTAS}, {"emulate_clear_history", ID_EMULATE_CLEAR_HISTORY},
    {"emulate_set_register", ID_EMULATE_SET_REGISTER}, {"emulate_write_memory", ID_EMULATE_WRITE_MEMORY}, {"emulate_reset", ID_EMULATE_RESET},
    {"llil_lift", ID_LLIL_LIFT}, {"llil_step", ID_LLIL_STEP}, {"llil_run", ID_LLIL_RUN}, {"llil_set_register", ID_LLIL_SET_REGISTER}, {"llil_write_memory", ID_LLIL_WRITE_MEMORY}, {"llil_reset", ID_LLIL_RESET},
    {"toggle_graph_list", ID_TOGGLE_GRAPH_LIST}, {"fit_graph", ID_FIT_GRAPH}, {"toggle_minimap", ID_TOGGLE_MINIMAP},
    {"view_graph", ID_VIEW_GRAPH}, {"view_listing", ID_VIEW_LISTING}, {"view_pseudocode", ID_VIEW_PSEUDO}, {"view_debugger", ID_VIEW_DEBUGGER}, {"view_hex", ID_VIEW_HEX},
    {"view_types", ID_VIEW_TYPES}, {"view_imports", ID_VIEW_IMPORTS}, {"view_exports", ID_VIEW_EXPORTS}, {"view_strings", ID_VIEW_STRINGS}, {"view_resources", ID_VIEW_RESOURCES},
    {"view_symbols", ID_VIEW_SYMBOLS}, {"view_memory", ID_VIEW_MEMORY}, {"view_problems", ID_VIEW_PROBLEMS}, {"view_llil", ID_VIEW_LLIL}, {"view_functions", ID_VIEW_FUNCTIONS}, {"diff_functions", ID_DIFF_FUNCTIONS}, {"panel_diff", ID_PANEL_BASE + 5}, {"panel_navigator", ID_PANEL_BASE}, {"panel_functions", ID_PANEL_BASE + 1}, {"panel_output", ID_PANEL_BASE + 2}, {"panel_python", ID_PANEL_BASE + 3}, {"panel_types", ID_PANEL_BASE + 4}, {"reset_layout", ID_PANEL_RESET}, {"struct_offset", ID_STRUCT_OFFSET}, {"enum_operand", ID_ENUM_OPERAND}, {"set_prototype", ID_SET_PROTOTYPE}, {"types_editor", ID_TYPES_EDITOR},
    {"about", ID_ABOUT},
};

std::string unescape_arg(const std::string& value) {
    std::string out;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\'' && i + 1 < value.size()) { ++i; out += value[i] == 'n' ? '\n' : value[i] == 'r' ? '\r' : value[i]; }
        else out += value[i];
    }
    return out;
}

std::uint64_t parse_address(const std::string& text) {
    if (text.empty()) return g_current_address;
    std::uint64_t resolved = 0;
    if (native_plugin_resolve_address(nullptr, text.c_str(), &resolved)) return resolved;
    return std::strtoull(text.c_str(), nullptr, 0);
}

std::string own(const char* text) { return text ? std::string(text) : std::string(); }

std::string disassemble_text(std::uint64_t address, std::size_t count) {
    if (!g_database) return "no binary open";
    std::ostringstream out;
    for (const auto& instruction : gandon::decode_instructions(g_database->image(), address, count)) {
        char head[40]; snprintf(head, sizeof(head), "%016llX  ", static_cast<unsigned long long>(instruction.address));
        out << head;
        for (std::size_t i = 0; i < instruction.size && i < instruction.bytes.size(); ++i) { char b[4]; snprintf(b, sizeof(b), "%02X ", instruction.bytes[i]); out << b; }
        for (std::size_t i = instruction.size; i < 10; ++i) out << "   ";
        out << instruction.mnemonic << (instruction.operands.empty() ? "" : " ") << instruction.operands << "\n";
    }
    return out.str();
}

// Returns "OK\n<payload>" or "ERR\n<message>".
std::string handle_request(const std::string& op, const std::vector<std::string>& args) {
    auto arg = [&](std::size_t i) -> std::string { return i < args.size() ? args[i] : std::string(); };
    const auto ok = [](const std::string& payload) { return "OK\n" + payload; };
    const auto err = [](const std::string& message) { return "ERR\n" + message; };
    if (op == "ping") return ok("pong");
    if (op == "actions") { std::string names; for (const auto& a : kActions) { names += a.name; names += '\n'; } return ok(names); }
    if (op == "act") {
        for (const auto& a : kActions) if (arg(0) == a.name) { PostMessageW(g_main_window, WM_COMMAND, MAKEWPARAM(a.id, 0), 0); return ok("queued " + arg(0)); }
        return err("unknown action '" + arg(0) + "' - see actions()");
    }
    if (op == "state") {
        std::ostringstream out;
        out << std::hex << "address=" << g_current_address << "\ntab=" << std::dec << (g_tabs ? TabCtrl_GetCurSel(g_tabs) : -1)
            << "\nloaded=" << (g_database ? 1 : 0) << "\ndirty=" << (g_session_dirty ? 1 : 0)
            << "\ndebugging=" << (g_debug_process.load() ? 1 : 0) << "\n";
        return ok(out.str());
    }
    if (op == "status") { wchar_t text[512]{}; if (g_status) GetWindowTextW(g_status, text, 512); return ok(utf8_from_wide(text)); }
    if (op == "registers") return ok(utf8_from_wide(debugger_text()));
    if (op == "readmem") {
        const auto address = parse_address(arg(0));
        const std::uint64_t size = arg(1).empty() ? 64 : std::strtoull(arg(1).c_str(), nullptr, 0);
        if (size == 0 || size > 0x10000) return err("size out of range");
        std::vector<std::uint8_t> buffer(static_cast<std::size_t>(size));
        if (!native_plugin_read_process_bytes(nullptr, address, buffer.data(), size)) return err("ReadProcessMemory failed (is the debugger running and paused?)");
        std::ostringstream out; for (const auto b : buffer) { char h[4]; snprintf(h, sizeof h, "%02X ", b); out << h; }
        return ok(out.str());
    }
    if (op == "readqword" || op == "readdword") {
        const auto address = parse_address(arg(0));
        std::uint8_t buffer[8]{};
        const std::uint64_t size = op == "readqword" ? 8 : 4;
        if (!native_plugin_read_process_bytes(nullptr, address, buffer, size)) return err("ReadProcessMemory failed");
        std::uint64_t value = 0; for (std::uint64_t i = 0; i < size; ++i) value |= static_cast<std::uint64_t>(buffer[i]) << (8 * i);
        char h[24]; snprintf(h, sizeof h, "%llx", static_cast<unsigned long long>(value));
        return ok(h);
    }
    if (op == "bp_list") { std::lock_guard lock(g_breakpoint_mutex); std::string out; for (const auto a : g_requested_breakpoints) { char b[20]; snprintf(b, sizeof b, "%llx\n", (unsigned long long)a); out += b; } return ok(out); }
    if (op == "set_status") { if (g_status) SetWindowTextW(g_status, wide(arg(0)).c_str()); return ok(""); }
    if (op == "resolve") { std::uint64_t value = 0; if (native_plugin_resolve_address(nullptr, arg(0).c_str(), &value)) { char b[32]; snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(value)); return ok(b); } return err("cannot resolve '" + arg(0) + "'"); }
    if (op == "goto") { const auto a = parse_address(arg(0)); if (!g_database || !address_is_mapped(a)) return err("address is not mapped"); navigate_to_address(g_main_window, a, arg(1).empty() ? 1 : std::atoi(arg(1).c_str())); return ok(""); }
    if (!g_database && op != "load_db") return err("no binary is open");
    if (op == "info") return ok(own(native_plugin_info_json(nullptr)));
    if (op == "disasm") return ok(disassemble_text(parse_address(arg(0)), arg(1).empty() ? 16 : static_cast<std::size_t>(std::atoi(arg(1).c_str()))));
    if (op == "listing") return ok(own(native_plugin_listing_at(nullptr, parse_address(arg(0)))));
    if (op == "decompile") { int good = 0; const auto text = own(native_plugin_decompile_at(nullptr, parse_address(arg(0)), arg(1) == "1", &good)); return good ? ok(text) : err(text.empty() ? "decompilation failed" : text); }
    if (op == "hexdump") return ok(own(native_plugin_hex_dump_at(nullptr, parse_address(arg(0)), 0)));
    if (op == "strings") return ok(own(native_plugin_strings(nullptr, 0)));
    if (op == "imports") return ok(own(native_plugin_imports_text(nullptr)));
    if (op == "exports") return ok(own(native_plugin_exports_text(nullptr)));
    if (op == "resources") return ok(own(native_plugin_resources_text(nullptr)));
    if (op == "segments") return ok(own(native_plugin_segments_text(nullptr)));
    if (op == "find_bytes") return ok(own(native_plugin_search_bytes(nullptr, arg(0).c_str())));
    if (op == "find_text") return ok(own(native_plugin_search_text(nullptr, arg(0).c_str())));
    if (op == "auto_analysis") return ok(own(native_plugin_run_auto_analysis(nullptr)));
    if (op == "rename") return native_plugin_rename(nullptr, parse_address(arg(0)), arg(1).c_str()) ? ok("") : err("rename failed");
    if (op == "comment") return native_plugin_add_comment(nullptr, parse_address(arg(0)), arg(1).c_str()) ? ok("") : err("comment failed");
    if (op == "patch") {
        std::vector<std::uint8_t> bytes; std::istringstream tokens(arg(1)); std::string token;
        while (tokens >> token) { try { bytes.push_back(static_cast<std::uint8_t>(std::stoul(token, nullptr, 16))); } catch (...) { return err("bad hex byte '" + token + "'"); } }
        if (bytes.empty()) return err("no bytes given");
        return native_plugin_patch_bytes_live(nullptr, parse_address(arg(0)), bytes.data(), bytes.size()) ? ok("") : err("patch failed (address not in file?)");
    }
    if (op == "types_add") {
        g_type_source += arg(0) + "\n"; ensure_types(g_database->image().is_64_bit); g_session_dirty = true; refresh_views(g_main_window);
        return g_type_error.empty() ? ok("") : err(g_type_error);
    }
    if (op == "types_text") { ensure_types(g_database->image().is_64_bit); return ok(g_types.format()); }
    if (op == "sizeof") { ensure_types(g_database->image().is_64_bit); const auto size = g_types.size_of(arg(0)); return size ? ok(std::to_string(*size)) : err("unknown type " + arg(0)); }
    if (op == "field_at") { ensure_types(g_database->image().is_64_bit); const auto field = g_types.field_at(arg(0), std::strtoull(arg(1).c_str(), nullptr, 0)); return field.empty() ? err("no field at that offset") : ok(field); }
    if (op == "struct" || op == "enum") {
        ensure_types(g_database->image().is_64_bit);
        const auto address = parse_address(arg(0)); const auto type = arg(1);
        auto& map = op == "struct" ? g_struct_ops : g_enum_ops;
        if (type.empty()) map.erase(address);
        else {
            const auto resolved = g_types.resolve(type);
            if (!resolved) return err("unknown type " + type);
            map[address] = type;
        }
        ++g_types_version; g_session_dirty = true; refresh_views(g_main_window); return ok("");
    }
    if (op == "prototype") {
        const auto function = g_database->function_at(parse_address(arg(0)));
        if (!function) return err("not inside a function");
        if (arg(1).empty()) g_prototypes.erase(function->get().start);
        else { const auto proto = gandon::parse_prototype(arg(1)); if (!proto) return err("cannot parse prototype"); g_prototypes[function->get().start] = proto->text(); }
        ++g_types_version; g_session_dirty = true; refresh_views(g_main_window); return ok("");
    }
    if (op == "diff") {
        std::string error;
        if (!run_function_diff(std::filesystem::path(wide(arg(0))), error)) return err(error);
        std::ostringstream out; out << diffdata::result.summary() << "\n";
        for (const auto& e : diffdata::result.entries) {
            if (e.kind == gandon::FunctionDiffEntry::Kind::Identical) continue;
            char line[320]; snprintf(line, sizeof line, "%-8s %5.1f%%  A %llx %s | B %llx %s (%s)\n", gandon::diff_kind_name(e.kind), e.similarity * 100.0,
                                     static_cast<unsigned long long>(e.a_start), e.a_name.c_str(), static_cast<unsigned long long>(e.b_start), e.b_name.c_str(), e.matched_by.c_str());
            out << line;
        }
        return ok(out.str());
    }
    if (op == "save_db") return native_plugin_save_database(nullptr, arg(0).c_str()) ? ok("") : err(own(native_plugin_last_database_error(nullptr)));
    if (op == "load_db") return native_plugin_load_database(nullptr, arg(0).c_str()) ? ok("") : err(own(native_plugin_last_database_error(nullptr)));
    return err("unknown request '" + op + "'");
}

void process_requests() {
    std::error_code ignored;
    std::vector<std::filesystem::path> pending;
    for (const auto& entry : std::filesystem::directory_iterator(directory, ignored)) {
        const auto name = entry.path().filename().wstring();
        if (name.rfind(L"req_", 0) == 0 && entry.path().extension() == L".txt") pending.push_back(entry.path());
    }
    for (const auto& path : pending) {
        std::ifstream file(path, std::ios::binary);
        std::string line; std::vector<std::string> lines;
        while (std::getline(file, line)) { if (!line.empty() && line.back() == '\r') line.pop_back(); lines.push_back(unescape_arg(line)); }
        file.close(); std::filesystem::remove(path, ignored);
        if (lines.empty()) continue;
        const std::string op = lines[0]; std::vector<std::string> args(lines.begin() + 1, lines.end());
        std::string reply;
        try { reply = handle_request(op, args); } catch (const std::exception& error) { reply = std::string("ERR\n") + error.what(); } catch (...) { reply = "ERR\nunexpected failure"; }
        auto response = path; response.replace_filename(L"resp_" + path.filename().wstring().substr(4));
        auto temporary = response; temporary += L".tmp";
        { std::ofstream out(temporary, std::ios::binary | std::ios::trunc); out << reply; }
        std::filesystem::rename(temporary, response, ignored);
    }
}

void process_gui_commands() {
    if (directory.empty()) return;
    process_requests();
    std::ifstream file(directory / L"cmd.txt");
    if (!file) return;
    std::string line; std::vector<std::string> lines;
    while (std::getline(file, line)) lines.push_back(line);
    file.close();
    if (lines.empty()) return;
    { std::ofstream clear(directory / L"cmd.txt", std::ios::trunc); }
    for (const auto& command : lines) {
        if (command.rfind("goto ", 0) != 0) continue;
        const auto address = std::strtoull(command.c_str() + 5, nullptr, 16);
        if (g_database && address_is_mapped(address)) navigate_to_address(g_main_window, address, 1);
    }
}

LRESULT CALLBACK input_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_CHAR && wparam == L'\r') return 0;
    if (message == WM_KEYDOWN) {
        if (wparam == VK_RETURN) { submit_line(); return 0; }
        if ((wparam == VK_UP || wparam == VK_DOWN) && !history.empty()) {
            if (wparam == VK_UP && history_pos > 0) --history_pos;
            else if (wparam == VK_DOWN && history_pos < history.size()) ++history_pos;
            SetWindowTextW(hwnd, history_pos < history.size() ? history[history_pos].c_str() : L"");
            SendMessageW(hwnd, EM_SETSEL, 100000, 100000);
            return 0;
        }
    }
    return CallWindowProcW(input_proc_old, hwnd, message, wparam, lparam);
}

LRESULT CALLBACK console_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    static HBRUSH background = CreateSolidBrush(THEMED_RGB(24, 27, 32));
    switch (message) {
    case WM_CREATE: {
        output = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 0, 0, 0, 0, hwnd, nullptr, g_instance, nullptr);
        input = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, nullptr, g_instance, nullptr);
        SendMessageW(output, WM_SETFONT, reinterpret_cast<WPARAM>(g_code_font), TRUE);
        SendMessageW(input, WM_SETFONT, reinterpret_cast<WPARAM>(g_code_font), TRUE);
        SendMessageW(output, EM_SETLIMITTEXT, 0x7FFFFFFF, 0);
        input_proc_old = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(input, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(input_proc)));
        SetTimer(hwnd, TIMER_COMMANDS, 40, nullptr);
        return 0;
    }
    case WM_SIZE: {
        const int width = LOWORD(lparam), height = HIWORD(lparam), input_height = 26;
        MoveWindow(output, 0, 0, width, (std::max)(0, height - input_height), TRUE);
        MoveWindow(input, 0, (std::max)(0, height - input_height), width, input_height, TRUE);
        return 0;
    }
    case WM_SETFOCUS: SetFocus(input); return 0;
    case WM_ACTIVATE: if (LOWORD(wparam) != WA_INACTIVE) SetFocus(input); return 0;
    case WM_TIMER: if (wparam == TIMER_COMMANDS) process_gui_commands(); return 0;
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wparam);
        SetTextColor(dc, g_light_theme ? RGB(0, 0, 0) : RGB(221, 221, 221));
        SetBkColor(dc, THEMED_RGB(24, 27, 32));
        return reinterpret_cast<LRESULT>(background);
    }
    case WM_PY_OUTPUT: {
        auto* text = reinterpret_cast<std::wstring*>(wparam);
        if (!text) { append_output(L"\n[python process ended]\n"); return 0; }
        append_output(*text); delete text; return 0;
    }
    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_DESTROY: {
        KillTimer(hwnd, TIMER_COMMANDS);
        stop_process();
        std::error_code ignored; if (!directory.empty()) std::filesystem::remove_all(directory, ignored);
        window = output = input = nullptr;
        return 0;
    }
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}
} // namespace pyconsole

// GUI -> console direction: anything that happens in the program is echoed into the open Python console.
// Safe to call from any thread (the text is posted to the console window).
void py_console_log(const std::wstring& text) {
    using namespace pyconsole;
    if (!window || !IsWindow(window)) return;
    auto* copy = new std::wstring(L"\n[gui] " + text + L"\n");
    if (!PostMessageW(window, WM_PY_OUTPUT, reinterpret_cast<WPARAM>(copy), 0)) delete copy;
}

void py_console_log_command(int id) {
    if (!pyconsole::window) return;
    for (const auto& action : pyconsole::kActions)
        if (action.id == id) {
            wchar_t address[40]{}; swprintf_s(address, L"  @0x%llX", static_cast<unsigned long long>(g_current_address));
            py_console_log(L"action " + wide(action.name) + (g_current_address ? address : L""));
            return;
        }
}

// ---------------------------------------------------------------------------
// Docking: panels live in the left / right / bottom areas (tabbed) or float in their own window
// ---------------------------------------------------------------------------
namespace dock {
enum Area { kLeft = 0, kRight = 1, kBottom = 2, kFloat = 3 };
constexpr int kBarHeight = 24, kSplit = 5;

struct Panel {
    std::wstring id, title;
    HWND content{}, frame{};
    Area area{kBottom}, last_docked{kBottom};
    bool visible{false}, title_from_window{false};
    std::function<HWND(HWND)> factory;
    RECT float_rect{140, 140, 780, 540};
};
std::vector<std::unique_ptr<Panel>> panels;
int sizes[3] = {290, 360, 150};
HWND bars[3]{}, splitters[3]{};
std::wstring active_id[3];
RECT central{};
bool ready = false;
HWND host{};
void save();

Panel* find(const std::wstring& id) { for (auto& p : panels) if (p->id == id) return p.get(); return nullptr; }
int index_of(const Panel* panel) { for (std::size_t i = 0; i < panels.size(); ++i) if (panels[i].get() == panel) return static_cast<int>(i); return -1; }
std::wstring title_of(const Panel& p) {
    if (p.title_from_window && p.content) { wchar_t buffer[160]{}; GetWindowTextW(p.content, buffer, 160); if (*buffer) return buffer; }
    return p.title;
}
std::vector<Panel*> docked(Area area) {
    std::vector<Panel*> list;
    for (auto& p : panels) if (p->visible && p->area == area && p->content) list.push_back(p.get());
    return list;
}
Panel* active(Area area) {
    const auto list = docked(area);
    for (auto* p : list) if (p->id == active_id[area]) return p;
    return list.empty() ? nullptr : list.front();
}

void relayout() {
    if (!host) return;
    RECT client{}; GetClientRect(host, &client);
    SendMessageW(host, WM_SIZE, SIZE_RESTORED, MAKELPARAM(client.right, client.bottom));
}

// Positions the areas inside `work` and returns the rectangle left for the central views.
RECT layout(const RECT& work) {
    const int width = work.right - work.left, height = work.bottom - work.top;
    bool shown[3]{};
    for (int a = 0; a < 3; ++a) shown[a] = active(static_cast<Area>(a)) != nullptr;
    const int left_w = shown[kLeft] ? (std::min)(sizes[kLeft], (std::max)(80, width / 2)) : 0;
    const int right_w = shown[kRight] ? (std::min)(sizes[kRight], (std::max)(80, width / 2)) : 0;
    const int bottom_h = shown[kBottom] ? (std::min)(sizes[kBottom], (std::max)(60, height / 2)) : 0;
    central = {work.left + (left_w ? left_w + kSplit : 0), work.top, work.right - (right_w ? right_w + kSplit : 0), work.bottom - (bottom_h ? bottom_h + kSplit : 0)};
    RECT area[3] = {{work.left, work.top, work.left + left_w, work.bottom},
                    {work.right - right_w, work.top, work.right, work.bottom},
                    {central.left, work.bottom - bottom_h, central.right, work.bottom}};
    RECT split[3] = {{area[kLeft].right, work.top, area[kLeft].right + kSplit, work.bottom},
                     {area[kRight].left - kSplit, work.top, area[kRight].left, work.bottom},
                     {central.left, area[kBottom].top - kSplit, central.right, area[kBottom].top}};
    for (int a = 0; a < 3; ++a) {
        Panel* current = shown[a] ? active(static_cast<Area>(a)) : nullptr;
        if (bars[a]) {
            if (shown[a]) { SetWindowPos(bars[a], nullptr, area[a].left, area[a].top, area[a].right - area[a].left, kBarHeight, SWP_NOZORDER | SWP_SHOWWINDOW); InvalidateRect(bars[a], nullptr, FALSE); }
            else ShowWindow(bars[a], SW_HIDE);
        }
        if (splitters[a]) {
            if (shown[a]) SetWindowPos(splitters[a], nullptr, split[a].left, split[a].top, split[a].right - split[a].left, split[a].bottom - split[a].top, SWP_NOZORDER | SWP_SHOWWINDOW);
            else ShowWindow(splitters[a], SW_HIDE);
        }
        for (auto& p : panels) {
            if (!p->content || p->area != a || p->area == kFloat) continue;
            if (p.get() == current && p->visible) {
                SetWindowPos(p->content, nullptr, area[a].left, area[a].top + kBarHeight, area[a].right - area[a].left, (std::max)(0L, area[a].bottom - area[a].top - kBarHeight), SWP_NOZORDER | SWP_SHOWWINDOW);
            } else ShowWindow(p->content, SW_HIDE);
        }
    }
    return central;
}

HWND preview{};
void dock_to(Panel& p, Area area);
// Docking destroys the floating frame, so it must not happen inside that frame's own message handler.
void dock_to_deferred(Panel& p, int zone) { PostMessageW(host, WM_APP + 77, reinterpret_cast<WPARAM>(&p), static_cast<LPARAM>(zone)); }

void hide_preview() { if (preview) ShowWindow(preview, SW_HIDE); }

void show_preview(const RECT& screen_rect) {
    if (!preview) {
        static bool registered = false;
        if (!registered) {
            WNDCLASSW cls{}; cls.hInstance = g_instance; cls.lpfnWndProc = DefWindowProcW; cls.lpszClassName = L"GandonDockPreview";
            cls.hbrBackground = CreateSolidBrush(RGB(0, 122, 204)); RegisterClassW(&cls); registered = true;
        }
        preview = CreateWindowExW(WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT, L"GandonDockPreview", nullptr, WS_POPUP,
                                  0, 0, 10, 10, host, nullptr, g_instance, nullptr);
        if (preview) SetLayeredWindowAttributes(preview, 0, 90, LWA_ALPHA);
    }
    if (!preview) return;
    SetWindowPos(preview, HWND_TOPMOST, screen_rect.left, screen_rect.top, screen_rect.right - screen_rect.left, screen_rect.bottom - screen_rect.top, SWP_NOACTIVATE | SWP_SHOWWINDOW);
}

// Where would a panel dropped at `screen` end up?  Returns -1 for "nowhere special".
// Inside the window the outer edges are drop targets; elsewhere a drop floats the panel.
int drop_zone(POINT screen, RECT* preview_rect, bool allow_float) {
    RECT window{}; GetWindowRect(host, &window);
    RECT client{}; GetClientRect(host, &client);
    POINT origin{0, 0}; ClientToScreen(host, &origin);
    RECT status{}; if (g_status) GetWindowRect(g_status, &status);
    const int work_left = origin.x, work_right = origin.x + client.right, work_top = origin.y + 28, work_bottom = status.top ? status.top : origin.y + client.bottom;
    const bool inside = screen.x >= window.left && screen.x < window.right && screen.y >= window.top && screen.y < window.bottom;
    if (!inside) {
        if (!allow_float) return -1;
        *preview_rect = {screen.x - 120, screen.y - 12, screen.x + 360, screen.y + 300};
        return kFloat;
    }
    const int width = work_right - work_left, height = work_bottom - work_top;
    const int edge_x = (std::max)(70, width / 5), edge_y = (std::max)(60, height / 4);
    if (screen.x < work_left + edge_x) { *preview_rect = {work_left, work_top, work_left + (std::max)(sizes[kLeft], 200), work_bottom}; return kLeft; }
    if (screen.x >= work_right - edge_x) { *preview_rect = {work_right - (std::max)(sizes[kRight], 200), work_top, work_right, work_bottom}; return kRight; }
    if (screen.y >= work_bottom - edge_y) { *preview_rect = {work_left, work_bottom - (std::max)(sizes[kBottom], 120), work_right, work_bottom}; return kBottom; }
    return -1;
}

LRESULT CALLBACK frame_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* panel = reinterpret_cast<Panel*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    static int pending_zone = -1;
    switch (message) {
    case WM_ENTERSIZEMOVE: pending_zone = -1; return 0;
    case WM_MOVING: {
        POINT cursor{}; GetCursorPos(&cursor);
        RECT preview_rect{};
        pending_zone = drop_zone(cursor, &preview_rect, false);
        if (pending_zone >= 0) show_preview(preview_rect); else hide_preview();
        break;
    }
    case WM_SIZE: if (panel && panel->content) MoveWindow(panel->content, 0, 0, LOWORD(lparam), HIWORD(lparam), TRUE); return 0;
    case WM_EXITSIZEMOVE:
        hide_preview();
        if (panel && !IsIconic(hwnd)) GetWindowRect(hwnd, &panel->float_rect);
        if (panel && pending_zone >= 0 && pending_zone <= 2) { const int zone = pending_zone; pending_zone = -1; dock_to_deferred(*panel, zone); }
        pending_zone = -1;
        return 0;
    case WM_MOVE: if (panel && !IsIconic(hwnd)) GetWindowRect(hwnd, &panel->float_rect); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_SETFOCUS: if (panel && panel->content) SetFocus(panel->content); return 0;
    case WM_CLOSE:
        if (panel) { panel->visible = false; ShowWindow(hwnd, SW_HIDE); if (panel->content) ShowWindow(panel->content, SW_HIDE); }
        return 0;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

void make_floating(Panel& p) {
    if (!p.content) return;
    if (!p.frame) {
        p.frame = CreateWindowExW(WS_EX_TOOLWINDOW, L"GandonDockFloat", title_of(p).c_str(), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                                  p.float_rect.left, p.float_rect.top, p.float_rect.right - p.float_rect.left, p.float_rect.bottom - p.float_rect.top, host, nullptr, g_instance, nullptr);
        if (!p.frame) return;
        SetWindowLongPtrW(p.frame, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&p));
        dark_title_bar(p.frame);
    }
    if (p.area != kFloat) p.last_docked = p.area;
    p.area = kFloat; p.visible = true;
    SetParent(p.content, p.frame);
    RECT rc{}; GetClientRect(p.frame, &rc);
    SetWindowPos(p.content, nullptr, 0, 0, rc.right, rc.bottom, SWP_NOZORDER | SWP_SHOWWINDOW);
    SetWindowTextW(p.frame, title_of(p).c_str());
    ShowWindow(p.frame, SW_SHOWNOACTIVATE);
    relayout(); save();
}

void dock_to(Panel& p, Area area) {
    if (!p.content) return;
    if (p.frame) { SetParent(p.content, host); DestroyWindow(p.frame); p.frame = nullptr; }
    p.area = area; p.last_docked = area; p.visible = true; active_id[area] = p.id;
    ShowWindow(p.content, SW_SHOW);
    relayout(); save();
}

void close_panel(Panel& p) {
    p.visible = false;
    if (p.frame) ShowWindow(p.frame, SW_HIDE);
    if (p.content) ShowWindow(p.content, SW_HIDE);
    relayout(); save();
}

void show(const std::wstring& id) {
    Panel* p = find(id);
    if (!p) return;
    if (!p->content && p->factory) p->content = p->factory(host);
    if (!p->content) return;
    if (p->area == kFloat) { make_floating(*p); SetForegroundWindow(p->frame); }
    else { dock_to(*p, p->area); }
    SetFocus(p->content);
}

void toggle(const std::wstring& id) {
    Panel* p = find(id);
    if (p && p->visible) close_panel(*p); else show(id);
}

void set_content(const std::wstring& id, HWND content) { if (Panel* p = find(id)) { p->content = content; } }

LRESULT CALLBACK bar_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    const Area area = static_cast<Area>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    struct Hit { RECT rect; Panel* panel; };
    static std::vector<Hit> hits[3];
    static Panel* drag_panel = nullptr; static bool drag_active = false; static POINT drag_start{}; static int drag_zone = -1;
    const auto hit_at = [&](int x, int y) -> Panel* { for (const auto& h : hits[area]) if (x >= h.rect.left && x < h.rect.right && y >= h.rect.top && y < h.rect.bottom) return h.panel; return nullptr; };
    switch (message) {
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps{}; HDC dc = BeginPaint(hwnd, &ps);
        RECT client{}; GetClientRect(hwnd, &client);
        HBRUSH background = CreateSolidBrush(THEMED_RGB(24, 27, 32)); FillRect(dc, &client, background); DeleteObject(background);
        HGDIOBJ old_font = SelectObject(dc, g_ui_font); SetBkMode(dc, TRANSPARENT);
        hits[area].clear();
        int x = 0;
        Panel* current = active(area);
        for (auto* p : docked(area)) {
            const std::wstring text = title_of(*p);
            SIZE extent{}; GetTextExtentPoint32W(dc, text.c_str(), static_cast<int>(text.size()), &extent);
            RECT tab{x, 0, x + extent.cx + 28, client.bottom};
            const bool is_active = p == current;
            HBRUSH fill = CreateSolidBrush(is_active ? THEMED_RGB(30, 34, 40) : THEMED_RGB(24, 27, 32)); FillRect(dc, &tab, fill); DeleteObject(fill);
            if (is_active) { RECT line{tab.left, tab.bottom - 2, tab.right, tab.bottom}; HBRUSH accent = CreateSolidBrush(THEMED_RGB(0, 122, 204)); FillRect(dc, &line, accent); DeleteObject(accent); }
            SetTextColor(dc, is_active ? THEMED_RGB(225, 235, 242) : THEMED_RGB(155, 170, 184));
            RECT text_rect = tab; DrawTextW(dc, text.c_str(), -1, &text_rect, DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_NOPREFIX);
            RECT sep{tab.right - 1, 5, tab.right, client.bottom - 5}; HBRUSH sep_brush = CreateSolidBrush(THEMED_RGB(52, 64, 74)); FillRect(dc, &sep, sep_brush); DeleteObject(sep_brush);
            hits[area].push_back({tab, p});
            x = tab.right;
        }
        SelectObject(dc, old_font);
        EndPaint(hwnd, &ps); return 0;
    }
    case WM_LBUTTONDOWN:
        if (Panel* p = hit_at(GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam))) {
            active_id[area] = p->id; relayout(); SetFocus(p->content);
            drag_panel = p; drag_active = false; drag_start = {GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)}; SetCapture(hwnd);
        }
        return 0;
    case WM_MOUSEMOVE:
        if (drag_panel && (wparam & MK_LBUTTON)) {
            const int dx = GET_X_LPARAM(lparam) - drag_start.x, dy = GET_Y_LPARAM(lparam) - drag_start.y;
            if (!drag_active && dx * dx + dy * dy > 64) drag_active = true;
            if (drag_active) {
                POINT cursor{}; GetCursorPos(&cursor);
                RECT preview_rect{};
                drag_zone = drop_zone(cursor, &preview_rect, true);
                if (drag_zone >= 0) show_preview(preview_rect); else hide_preview();
            }
        }
        return 0;
    case WM_LBUTTONUP:
        if (drag_panel) {
            Panel* p = drag_panel; const bool was_dragging = drag_active; const int zone = drag_zone;
            drag_panel = nullptr; drag_active = false; drag_zone = -1;
            ReleaseCapture(); hide_preview();
            if (was_dragging && zone >= 0) {
                if (zone == kFloat) {
                    POINT cursor{}; GetCursorPos(&cursor);
                    p->float_rect = {cursor.x - 120, cursor.y - 12, cursor.x + 520, cursor.y + 388};
                    if (p->frame) SetWindowPos(p->frame, nullptr, p->float_rect.left, p->float_rect.top, 640, 400, SWP_NOZORDER);
                    make_floating(*p);
                } else if (zone != static_cast<int>(p->area)) dock_to(*p, static_cast<Area>(zone));
            }
        }
        return 0;
    case WM_CAPTURECHANGED: drag_panel = nullptr; drag_active = false; hide_preview(); return 0;
    case WM_LBUTTONDBLCLK: if (Panel* p = hit_at(GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam))) make_floating(*p); return 0;
    case WM_MBUTTONUP: if (Panel* p = hit_at(GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam))) close_panel(*p); return 0;
    case WM_RBUTTONUP: {
        Panel* p = hit_at(GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam));
        if (!p) return 0;
        HMENU menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, 1, L"Float"); AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING | (p->area == kLeft ? MF_CHECKED : 0), 2, L"Dock left"); AppendMenuW(menu, MF_STRING | (p->area == kRight ? MF_CHECKED : 0), 3, L"Dock right");
        AppendMenuW(menu, MF_STRING | (p->area == kBottom ? MF_CHECKED : 0), 4, L"Dock bottom"); AppendMenuW(menu, MF_SEPARATOR, 0, nullptr); AppendMenuW(menu, MF_STRING, 5, L"Close");
        POINT point{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)}; ClientToScreen(hwnd, &point);
        const int command = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, point.x, point.y, 0, hwnd, nullptr); DestroyMenu(menu);
        if (command == 1) make_floating(*p); else if (command == 2) dock_to(*p, kLeft); else if (command == 3) dock_to(*p, kRight);
        else if (command == 4) dock_to(*p, kBottom); else if (command == 5) close_panel(*p);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

LRESULT CALLBACK splitter_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    const Area area = static_cast<Area>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    static bool dragging = false;
    switch (message) {
    case WM_ERASEBKGND: { RECT rc{}; GetClientRect(hwnd, &rc); HBRUSH brush = CreateSolidBrush(THEMED_RGB(30, 34, 40)); FillRect(reinterpret_cast<HDC>(wparam), &rc, brush); DeleteObject(brush); return 1; }
    case WM_SETCURSOR: SetCursor(LoadCursorW(nullptr, area == kBottom ? IDC_SIZENS : IDC_SIZEWE)); return TRUE;
    case WM_LBUTTONDOWN: dragging = true; SetCapture(hwnd); return 0;
    case WM_LBUTTONUP: dragging = false; ReleaseCapture(); save(); return 0;
    case WM_MOUSEMOVE:
        if (dragging && (wparam & MK_LBUTTON)) {
            POINT point{}; GetCursorPos(&point); ScreenToClient(host, &point);
            RECT client{}; GetClientRect(host, &client);
            RECT status{}; GetWindowRect(g_status, &status);
            const int bottom = client.bottom - (status.bottom - status.top);
            if (area == kLeft) sizes[kLeft] = (std::clamp)(static_cast<int>(point.x), 120, (std::max)(160, static_cast<int>(client.right) - 300));
            else if (area == kRight) sizes[kRight] = (std::clamp)(static_cast<int>(client.right - point.x), 120, (std::max)(160, static_cast<int>(client.right) - 300));
            else sizes[kBottom] = (std::clamp)(bottom - static_cast<int>(point.y), 60, (std::max)(100, bottom - 200));
            relayout();
        }
        return 0;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

void add(const wchar_t* id, const wchar_t* title, Area area, bool visible, std::function<HWND(HWND)> factory = {}, bool title_from_window = false) {
    auto panel = std::make_unique<Panel>();
    panel->id = id; panel->title = title; panel->area = area; panel->last_docked = area == kFloat ? kBottom : area;
    panel->visible = visible; panel->factory = std::move(factory); panel->title_from_window = title_from_window;
    panels.push_back(std::move(panel));
}

void init(HWND main) {
    host = main;
    if (ready) return;
    ready = true;
    WNDCLASSW bar{}; bar.hInstance = g_instance; bar.lpfnWndProc = bar_proc; bar.lpszClassName = L"GandonDockBar"; bar.hCursor = LoadCursorW(nullptr, IDC_ARROW); bar.style = CS_DBLCLKS; RegisterClassW(&bar);
    WNDCLASSW splitter{}; splitter.hInstance = g_instance; splitter.lpfnWndProc = splitter_proc; splitter.lpszClassName = L"GandonDockSplitter"; splitter.hCursor = LoadCursorW(nullptr, IDC_SIZEWE); RegisterClassW(&splitter);
    WNDCLASSW frame{}; frame.hInstance = g_instance; frame.lpfnWndProc = frame_proc; frame.lpszClassName = L"GandonDockFloat"; frame.hCursor = LoadCursorW(nullptr, IDC_ARROW); frame.hbrBackground = g_panel; RegisterClassW(&frame);
    for (int a = 0; a < 3; ++a) {
        bars[a] = CreateWindowExW(0, L"GandonDockBar", nullptr, WS_CHILD | WS_CLIPSIBLINGS, 0, 0, 0, 0, main, nullptr, g_instance, nullptr);
        splitters[a] = CreateWindowExW(0, L"GandonDockSplitter", nullptr, WS_CHILD | WS_CLIPSIBLINGS, 0, 0, 0, 0, main, nullptr, g_instance, nullptr);
        SetWindowLongPtrW(bars[a], GWLP_USERDATA, a); SetWindowLongPtrW(splitters[a], GWLP_USERDATA, a);
    }
    add(L"navigator", L"Navigator", kLeft, true);
    add(L"functions", L"Functions", kLeft, false, [](HWND parent) { return funcwin_create(parent); }, true);
    add(L"output", L"Output", kBottom, true);
    add(L"python", L"Python", kBottom, false, [](HWND parent) { return pyconsole_create(parent); });
    add(L"types", L"Local Types Editor", kFloat, false, [](HWND parent) { return typewin_create(parent); });
    add(L"diff", L"Diff", kBottom, false, [](HWND parent) { return diffwin_create(parent); }, true);
}

void reset_defaults() {
    sizes[kLeft] = 290; sizes[kRight] = 360; sizes[kBottom] = 150;
    struct Default { const wchar_t* id; Area area; bool visible; };
    const Default defaults[] = {{L"navigator", kLeft, true}, {L"functions", kLeft, false}, {L"output", kBottom, true}, {L"python", kBottom, false}, {L"types", kFloat, false}, {L"diff", kBottom, false}};
    for (const auto& d : defaults) {
        Panel* p = find(d.id);
        if (!p) continue;
        if (p->frame) { SetParent(p->content, host); DestroyWindow(p->frame); p->frame = nullptr; }
        p->area = d.area; p->last_docked = d.area == kFloat ? kBottom : d.area; p->visible = d.visible && p->content != nullptr;
        if (!p->visible && p->content) ShowWindow(p->content, SW_HIDE);
        if (p->visible) active_id[d.area] = p->id;
    }
    for (auto& a : active_id) a.clear();
    for (const auto& d : defaults) if (d.visible && d.area != kFloat && active_id[d.area].empty()) active_id[d.area] = d.id;
}

std::filesystem::path layout_file() {
    wchar_t base[MAX_PATH]{};
    if (!GetEnvironmentVariableW(L"APPDATA", base, MAX_PATH)) return {};
    std::filesystem::path folder = std::filesystem::path(base) / L"Gandon-PRO";
    std::error_code ignored; std::filesystem::create_directories(folder, ignored);
    return folder / L"layout.ini";
}

void save() {
    const auto file = layout_file();
    if (file.empty()) return;
    const auto number = [](long long v) { return std::to_wstring(v); };
    const std::wstring path = file.wstring();
    WritePrivateProfileStringW(L"areas", L"left", number(sizes[kLeft]).c_str(), path.c_str());
    WritePrivateProfileStringW(L"areas", L"right", number(sizes[kRight]).c_str(), path.c_str());
    WritePrivateProfileStringW(L"areas", L"bottom", number(sizes[kBottom]).c_str(), path.c_str());
    for (auto& p : panels) {
        if (p->frame && IsWindow(p->frame)) GetWindowRect(p->frame, &p->float_rect);
        const std::wstring section = L"panel_" + p->id;
        WritePrivateProfileStringW(section.c_str(), L"area", number(p->area).c_str(), path.c_str());
        WritePrivateProfileStringW(section.c_str(), L"docked", number(p->last_docked).c_str(), path.c_str());
        WritePrivateProfileStringW(section.c_str(), L"visible", p->visible ? L"1" : L"0", path.c_str());
        WritePrivateProfileStringW(section.c_str(), L"rect", (number(p->float_rect.left) + L"," + number(p->float_rect.top) + L"," + number(p->float_rect.right) + L"," + number(p->float_rect.bottom)).c_str(), path.c_str());
        WritePrivateProfileStringW(L"active", p->id.c_str(), L"", path.c_str());
    }
    for (int a = 0; a < 3; ++a) WritePrivateProfileStringW(L"active", number(a).c_str(), active_id[a].c_str(), path.c_str());
}

void load() {
    const auto file = layout_file();
    if (file.empty() || !std::filesystem::exists(file)) return;
    const std::wstring path = file.wstring();
    sizes[kLeft] = (std::clamp)(static_cast<int>(GetPrivateProfileIntW(L"areas", L"left", sizes[kLeft], path.c_str())), 120, 900);
    sizes[kRight] = (std::clamp)(static_cast<int>(GetPrivateProfileIntW(L"areas", L"right", sizes[kRight], path.c_str())), 120, 900);
    sizes[kBottom] = (std::clamp)(static_cast<int>(GetPrivateProfileIntW(L"areas", L"bottom", sizes[kBottom], path.c_str())), 60, 700);
    for (auto& p : panels) {
        const std::wstring section = L"panel_" + p->id;
        const int area = static_cast<int>(GetPrivateProfileIntW(section.c_str(), L"area", -1, path.c_str()));
        if (area < 0 || area > 3) continue;
        p->area = static_cast<Area>(area);
        p->last_docked = static_cast<Area>((std::clamp)(static_cast<int>(GetPrivateProfileIntW(section.c_str(), L"docked", p->last_docked, path.c_str())), 0, 2));
        p->visible = GetPrivateProfileIntW(section.c_str(), L"visible", p->visible ? 1 : 0, path.c_str()) != 0;
        wchar_t rect[96]{}; GetPrivateProfileStringW(section.c_str(), L"rect", L"", rect, 96, path.c_str());
        long l, t2, r, b;
        if (swscanf_s(rect, L"%ld,%ld,%ld,%ld", &l, &t2, &r, &b) == 4 && r - l > 200 && b - t2 > 120) p->float_rect = {l, t2, r, b};
    }
    for (int a = 0; a < 3; ++a) { wchar_t id[64]{}; GetPrivateProfileStringW(L"active", std::to_wstring(a).c_str(), L"", id, 64, path.c_str()); active_id[a] = id; }
}

// Called once the main window has its children: create the panels that were open last time.
void materialise() {
    for (auto& p : panels) {
        if (!p->visible) continue;
        if (!p->content && p->factory) p->content = p->factory(host);
        if (!p->content) { p->visible = false; continue; }
        if (p->area == kFloat) make_floating(*p); else ShowWindow(p->content, SW_SHOW);
    }
}

void append_menu(HMENU menu) {
    HMENU sub = CreatePopupMenu();
    for (std::size_t i = 0; i < panels.size(); ++i) AppendMenuW(sub, MF_STRING, ID_PANEL_BASE + static_cast<UINT>(i), panels[i]->title.c_str());
    AppendMenuW(sub, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(sub, MF_STRING, ID_PANEL_RESET, L"Reset panel layout");
    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(sub), L"Panels");
}

void update_menu(HMENU menu) {
    for (std::size_t i = 0; i < panels.size(); ++i) CheckMenuItem(menu, ID_PANEL_BASE + static_cast<UINT>(i), MF_BYCOMMAND | (panels[i]->visible ? MF_CHECKED : MF_UNCHECKED));
}

bool command(int id) {
    if (id == ID_PANEL_RESET) { reset_defaults(); relayout(); return true; }
    if (id >= ID_PANEL_BASE && id < ID_PANEL_BASE + static_cast<int>(panels.size())) { toggle(panels[static_cast<std::size_t>(id - ID_PANEL_BASE)]->id); return true; }
    return false;
}
} // namespace dock

HWND pyconsole_create(HWND parent) {
    using namespace pyconsole;
    static bool registered = false;
    if (!registered) {
        WNDCLASSW console_class{}; console_class.hInstance = g_instance; console_class.lpfnWndProc = console_proc; console_class.lpszClassName = L"GandonPyConsole";
        console_class.hCursor = LoadCursorW(nullptr, IDC_ARROW); console_class.hbrBackground = g_panel; RegisterClassW(&console_class); registered = true;
    }
    window = CreateWindowExW(0, L"GandonPyConsole", L"Python Console", WS_CHILD | WS_CLIPCHILDREN, 0, 0, 400, 200, parent, nullptr, g_instance, nullptr);
    if (!window) return nullptr;
    if (!start_process()) append_output(L"Не удалось запустить Python (python.exe / py -3 не найден).\n");
    return window;
}

void python_console(HWND owner) {
    (void)owner;
    dock::show(L"python");
    if (pyconsole::input) SetFocus(pyconsole::input);
}

// ---------------------------------------------------------------------------
// Functions window: sortable / filterable table (name, address, size, xrefs, calls, instructions)
// ---------------------------------------------------------------------------
void dark_title_bar(HWND hwnd) {
    if (g_light_theme) return;
    if (const auto dwm = LoadLibraryW(L"dwmapi.dll")) {
        using Fn = HRESULT(WINAPI*)(HWND, DWORD, LPCVOID, DWORD);
        if (const auto set_attribute = reinterpret_cast<Fn>(reinterpret_cast<void*>(GetProcAddress(dwm, "DwmSetWindowAttribute")))) { const BOOL on = TRUE; set_attribute(hwnd, 20, &on, sizeof(on)); }
    }
}

namespace funcwin {
HWND window{}, list{}, filter{};
struct Row { std::uint64_t start{}; std::wstring name; std::uint64_t size{}; std::size_t xrefs{}, calls{}, instructions{}; std::uint64_t locals{}; int args{}; };
std::vector<Row> all_rows, shown;
int sort_column = 1; bool sort_descending = false;

// Cache of (frame alloc, argument count) per function, rebuilt when the
// database changes, so the Functions list stays responsive on large binaries.
std::unordered_map<std::uint64_t, std::pair<std::uint64_t, int>> frame_cache;
std::wstring frame_cache_stamp;
std::wstring last_stamp;
constexpr UINT_PTR TIMER_REFRESH = 5;

std::wstring database_stamp() {
    if (!g_database) return L"";
    std::size_t h = g_custom_labels.size();
    for (const auto& [a, n] : g_custom_labels) h ^= static_cast<std::size_t>(a) * 31u + std::hash<std::wstring>{}(n);
    return std::to_wstring(g_database->functions().size()) + L"|" + std::to_wstring(g_database->xrefs().size()) + L"|" + std::to_wstring(h);
}

std::wstring hex_text(std::uint64_t value) { wchar_t b[24]{}; swprintf_s(b, L"%llX", static_cast<unsigned long long>(value)); return b; }

void rebuild() {
    all_rows.clear(); shown.clear();
    if (g_database) {
        const auto stamp = database_stamp();
        if (stamp != frame_cache_stamp) { frame_cache.clear(); frame_cache_stamp = stamp; }
        const bool arm64 = g_database->image().architecture == gandon::MachineArchitecture::ARM64;
        const bool win = g_database->image().format == gandon::BinaryFormat::PE;
        std::unordered_map<std::uint64_t, std::size_t> incoming;
        for (const auto& xref : g_database->xrefs()) ++incoming[xref.to];
        for (const auto& function : g_database->functions()) {
            Row row; row.start = function.start;
            row.name = g_custom_labels.contains(function.start) ? g_custom_labels[function.start] : wide(function.name);
            if (row.name.empty()) row.name = L"sub_" + hex_text(function.start);
            std::uint64_t end = function.end;
            if (!end && !function.instructions.empty()) end = function.instructions.back().address + function.instructions.back().size;
            row.size = end > function.start ? end - function.start : 0;
            row.xrefs = incoming.contains(function.start) ? incoming[function.start] : 0;
            row.calls = function.callees.size(); row.instructions = function.instructions.size();
            auto cached = frame_cache.find(function.start);
            if (cached == frame_cache.end()) {
                const auto frame = gandon::analyze_stack_frame(function, g_database->image().is_64_bit, arm64, win);
                int total_args = frame.reg_args;
                for (const auto& v : frame.vars) if (v.is_arg && !(win && !arm64 && v.offset >= 0 && v.offset < 0x20)) ++total_args;
                cached = frame_cache.emplace(function.start, std::make_pair(frame.alloc, total_args)).first;
            }
            row.locals = cached->second.first; row.args = cached->second.second;
            all_rows.push_back(std::move(row));
        }
    }
    wchar_t buffer[256]{}; GetWindowTextW(filter, buffer, 256);
    std::wstring needle = buffer; for (auto& ch : needle) ch = static_cast<wchar_t>(std::towlower(ch));
    for (const auto& row : all_rows) {
        if (!needle.empty()) {
            std::wstring name = row.name; for (auto& ch : name) ch = static_cast<wchar_t>(std::towlower(ch));
            std::wstring address = hex_text(row.start); for (auto& ch : address) ch = static_cast<wchar_t>(std::towlower(ch));
            if (name.find(needle) == std::wstring::npos && address.find(needle) == std::wstring::npos) continue;
        }
        shown.push_back(row);
    }
    std::stable_sort(shown.begin(), shown.end(), [](const Row& a, const Row& b) {
        auto less = [&]() -> bool {
            switch (sort_column) {
            case 0: return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0;
            case 2: return a.size < b.size;
            case 3: return a.locals < b.locals;
            case 4: return a.args < b.args;
            case 5: return a.xrefs < b.xrefs;
            case 6: return a.calls < b.calls;
            case 7: return a.instructions < b.instructions;
            default: return a.start < b.start;
            }
        };
        auto greater = [&]() -> bool {
            switch (sort_column) {
            case 0: return _wcsicmp(a.name.c_str(), b.name.c_str()) > 0;
            case 2: return a.size > b.size;
            case 3: return a.locals > b.locals;
            case 4: return a.args > b.args;
            case 5: return a.xrefs > b.xrefs;
            case 6: return a.calls > b.calls;
            case 7: return a.instructions > b.instructions;
            default: return a.start > b.start;
            }
        };
        return sort_descending ? greater() : less();
    });
    ListView_SetItemCountEx(list, static_cast<int>(shown.size()), LVSICF_NOINVALIDATEALL);
    InvalidateRect(list, nullptr, TRUE);
    wchar_t title[128]{}; swprintf_s(title, L"Functions  (%zu of %zu)", shown.size(), all_rows.size());
    SetWindowTextW(window, title);
    last_stamp = database_stamp();
}

void go(int index) {
    if (index < 0 || index >= static_cast<int>(shown.size()) || !g_database) return;
    navigate_to_address(g_main_window, shown[static_cast<std::size_t>(index)].start, g_tabs && TabCtrl_GetCurSel(g_tabs) == 0 ? 0 : 1);
}

LRESULT CALLBACK header_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam, UINT_PTR, DWORD_PTR) {
    if (message == WM_ERASEBKGND) return 1;
    if (message == WM_PAINT) {
        PAINTSTRUCT ps{}; HDC dc = BeginPaint(hwnd, &ps);
        RECT client{}; GetClientRect(hwnd, &client);
        HBRUSH fill = CreateSolidBrush(THEMED_RGB(30, 34, 40)); FillRect(dc, &client, fill); DeleteObject(fill);
        HGDIOBJ old_font = SelectObject(dc, g_ui_font); SetBkMode(dc, TRANSPARENT); SetTextColor(dc, THEMED_RGB(215, 228, 238));
        HPEN pen = CreatePen(PS_SOLID, 1, THEMED_RGB(52, 64, 74)); HGDIOBJ old_pen = SelectObject(dc, pen);
        const int count = Header_GetItemCount(hwnd);
        for (int i = 0; i < count; ++i) {
            RECT cell{}; Header_GetItemRect(hwnd, i, &cell);
            wchar_t label[64]{}; HDITEMW item{}; item.mask = HDI_TEXT | HDI_FORMAT; item.pszText = label; item.cchTextMax = 64; Header_GetItem(hwnd, i, &item);
            MoveToEx(dc, cell.right - 1, cell.top + 3, nullptr); LineTo(dc, cell.right - 1, cell.bottom - 3);
            RECT text = cell; text.left += 8; text.right -= 8;
            DrawTextW(dc, label, -1, &text, DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX | ((item.fmt & HDF_RIGHT) ? DT_RIGHT : DT_LEFT));
        }
        MoveToEx(dc, client.left, client.bottom - 1, nullptr); LineTo(dc, client.right, client.bottom - 1);
        SelectObject(dc, old_pen); DeleteObject(pen); SelectObject(dc, old_font);
        EndPaint(hwnd, &ps); return 0;
    }
    return DefSubclassProc(hwnd, message, wparam, lparam);
}

LRESULT CALLBACK proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    static HBRUSH background = CreateSolidBrush(THEMED_RGB(24, 27, 32));
    switch (message) {
    case WM_CREATE: {
        filter = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(2)), g_instance, nullptr);
        SendMessageW(filter, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        SendMessageW(filter, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"Filter by name or address..."));
        list = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_OWNERDATA | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(1)), g_instance, nullptr);
        ListView_SetExtendedListViewStyle(list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP);
        SendMessageW(list, WM_SETFONT, reinterpret_cast<WPARAM>(g_code_font), TRUE);
        ListView_SetBkColor(list, THEMED_RGB(24, 27, 32)); ListView_SetTextBkColor(list, THEMED_RGB(24, 27, 32)); ListView_SetTextColor(list, THEMED_RGB(215, 228, 238));
        if (const auto uxtheme = GetModuleHandleW(L"uxtheme.dll")) {
            using Fn = HRESULT(WINAPI*)(HWND, LPCWSTR, LPCWSTR);
            if (const auto set_theme = reinterpret_cast<Fn>(reinterpret_cast<void*>(GetProcAddress(uxtheme, "SetWindowTheme")))) { set_theme(list, L"DarkMode_ItemsView", nullptr);  set_theme(filter, L"DarkMode_CFD", nullptr); }
        }
        const wchar_t* names[] = {L"Function name", L"Address", L"Size", L"Locals", L"Args", L"Xrefs", L"Calls", L"Instr."};
        const int widths[] = {300, 150, 80, 70, 60, 70, 70, 70};
        for (int i = 0; i < 8; ++i) { LVCOLUMNW column{}; column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT; column.pszText = const_cast<wchar_t*>(names[i]); column.cx = widths[i]; column.fmt = i >= 2 ? LVCFMT_RIGHT : LVCFMT_LEFT; ListView_InsertColumn(list, i, &column); }
        if (!g_light_theme) if (const auto header = ListView_GetHeader(list)) SetWindowSubclass(header, header_proc, 1, 0);
        SetTimer(hwnd, TIMER_REFRESH, 800, nullptr);
        return 0;
    }
    case WM_SIZE: {
        const int width = LOWORD(lparam), height = HIWORD(lparam);
        MoveWindow(filter, 0, 0, width, 24, TRUE);
        MoveWindow(list, 0, 24, width, (std::max)(0, height - 24), TRUE);
        return 0;
    }
    case WM_SETFOCUS: SetFocus(list); return 0;
    case WM_COMMAND:
        if (LOWORD(wparam) == 2 && HIWORD(wparam) == EN_CHANGE) rebuild();
        return 0;
    case WM_TIMER:
        if (wparam == TIMER_REFRESH && database_stamp() != last_stamp) rebuild();
        return 0;
    case WM_NOTIFY: {
        auto* header = reinterpret_cast<LPNMHDR>(lparam);
        if (header->hwndFrom == list) {
            if (header->code == LVN_GETDISPINFOW) {
                auto* info = reinterpret_cast<NMLVDISPINFOW*>(lparam);
                if ((info->item.mask & LVIF_TEXT) && info->item.iItem >= 0 && info->item.iItem < static_cast<int>(shown.size())) {
                    const auto& row = shown[static_cast<std::size_t>(info->item.iItem)];
                    static thread_local std::wstring text;
                    switch (info->item.iSubItem) {
                    case 0: text = row.name; break;
                    case 1: text = hex_text(row.start); break;
                    case 2: text = std::to_wstring(row.size); break;
                    case 3: text = row.locals ? hex_text(row.locals) : L""; break;
                    case 4: text = row.args ? std::to_wstring(row.args) : L""; break;
                    case 5: text = std::to_wstring(row.xrefs); break;
                    case 6: text = std::to_wstring(row.calls); break;
                    default: text = std::to_wstring(row.instructions); break;
                    }
                    info->item.pszText = text.data();
                }
            } else if (header->code == LVN_COLUMNCLICK) {
                const int column = reinterpret_cast<NMLISTVIEW*>(lparam)->iSubItem;
                if (column == sort_column) sort_descending = !sort_descending; else { sort_column = column; sort_descending = column >= 2; }
                rebuild();
            } else if (header->code == NM_DBLCLK) {
                go(reinterpret_cast<NMITEMACTIVATE*>(lparam)->iItem);
            } else if (header->code == LVN_KEYDOWN && reinterpret_cast<NMLVKEYDOWN*>(lparam)->wVKey == VK_RETURN) {
                go(ListView_GetNextItem(list, -1, LVNI_SELECTED));
            }
        }
        return 0;
    }
    case WM_CTLCOLOREDIT: { auto dc = reinterpret_cast<HDC>(wparam); SetTextColor(dc, THEMED_RGB(215, 228, 238)); SetBkColor(dc, THEMED_RGB(24, 27, 32)); return reinterpret_cast<LRESULT>(background); }
    case WM_ERASEBKGND: return 1;
    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_DESTROY: KillTimer(hwnd, TIMER_REFRESH); window = list = filter = nullptr; return 0;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}
} // namespace funcwin

HWND funcwin_create(HWND parent) {
    using namespace funcwin;
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES}; InitCommonControlsEx(&controls);
    static bool registered = false;
    if (!registered) {
        WNDCLASSW cls{}; cls.hInstance = g_instance; cls.lpfnWndProc = proc; cls.lpszClassName = L"GandonFunctions";
        cls.hCursor = LoadCursorW(nullptr, IDC_ARROW); cls.hbrBackground = g_panel; RegisterClassW(&cls); registered = true;
    }
    window = CreateWindowExW(0, L"GandonFunctions", L"Functions", WS_CHILD | WS_CLIPCHILDREN, 0, 0, 300, 300, parent, nullptr, g_instance, nullptr);
    if (window) rebuild();
    return window;
}

void functions_window(HWND owner) {
    (void)owner;
    dock::show(L"functions");
    if (funcwin::window) funcwin::rebuild();
}

// ---------------------------------------------------------------------------
// Local types: structure offsets (T), enum constants (M), function prototypes (Y), types editor
// ---------------------------------------------------------------------------
void refresh_types_views(HWND window) { ++g_types_version; g_session_dirty = true; refresh_views(window); }

void apply_struct_offset(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Select an instruction with a [reg+offset] operand first.", L"Structure Offset", MB_ICONINFORMATION); return; }
    ensure_types(g_database->image().is_64_bit);
    const auto current = g_struct_ops.contains(g_current_address) ? wide(g_struct_ops[g_current_address]) : L"";
    const auto value = prompt_text(window, L"Structure Offset", L"Struct type (empty removes):", current, L"e.g. RECT, UNICODE_STRING, IMAGE_DOS_HEADER or your own struct (Shift+F1)");
    if (!value) return;
    const std::string name = utf8_from_wide(*value);
    if (name.empty()) { g_struct_ops.erase(g_current_address); }
    else {
        const auto resolved = g_types.resolve(name);
        if (!resolved || (resolved->kind != gandon::TypeDef::Kind::Struct && resolved->kind != gandon::TypeDef::Kind::Union)) { MessageBoxW(window, L"Unknown struct / union. Declare it first with Shift+F1.", L"Structure Offset", MB_ICONWARNING); return; }
        g_struct_ops[g_current_address] = name;
    }
    refresh_types_views(window);
    py_console_log(L"struct offset " + std::wstring(value->empty() ? L"removed" : L"-> " + *value));
}

void apply_enum_operand(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Select an instruction with an immediate operand first.", L"Enum Constant", MB_ICONINFORMATION); return; }
    ensure_types(g_database->image().is_64_bit);
    const auto current = g_enum_ops.contains(g_current_address) ? wide(g_enum_ops[g_current_address]) : L"";
    const auto value = prompt_text(window, L"Enum Constant", L"Enum type (empty removes):", current, L"e.g. PAGE_PROTECTION, MEM_FLAGS, ACCESS_RIGHTS, WIN_ERROR");
    if (!value) return;
    const std::string name = utf8_from_wide(*value);
    if (name.empty()) { g_enum_ops.erase(g_current_address); }
    else {
        const auto resolved = g_types.resolve(name);
        if (!resolved || resolved->kind != gandon::TypeDef::Kind::Enum) { MessageBoxW(window, L"Unknown enum. Declare it first with Shift+F1.", L"Enum Constant", MB_ICONWARNING); return; }
        g_enum_ops[g_current_address] = name;
    }
    refresh_types_views(window);
    py_console_log(L"enum constant " + std::wstring(value->empty() ? L"removed" : L"-> " + *value));
}

void set_function_prototype(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Select a function first.", L"Function Prototype", MB_ICONINFORMATION); return; }
    const auto function = g_database->function_at(g_current_address);
    if (!function) { MessageBoxW(window, L"The current address is not inside a function.", L"Function Prototype", MB_ICONINFORMATION); return; }
    const auto start = function->get().start;
    const auto current = g_prototypes.contains(start) ? wide(g_prototypes[start]) : L"int __fastcall func(int a1, int a2)";
    const auto value = prompt_text(window, L"Function Prototype", L"Declaration (empty removes):", current, L"e.g. BOOL __stdcall CheckKey(const char *key, int len)");
    if (!value) return;
    const std::string text = utf8_from_wide(*value);
    if (text.empty()) g_prototypes.erase(start);
    else {
        const auto proto = gandon::parse_prototype(text);
        if (!proto) { MessageBoxW(window, L"Cannot parse the declaration. Expected: return_type [convention] name(type arg, ...)", L"Function Prototype", MB_ICONWARNING); return; }
        g_prototypes[start] = proto->text();
        if (g_custom_labels.find(start) == g_custom_labels.end() && proto->name != "func") { record_text_edit(false, start, wide(proto->name)); g_custom_labels[start] = wide(proto->name); }
    }
    refresh_types_views(window);
    py_console_log(L"prototype " + std::wstring(text.empty() ? L"removed" : L": " + wide(g_prototypes[start])));
}

namespace typewin {
HWND window{}, edit{}, apply{}, info{};
LRESULT CALLBACK proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    static HBRUSH background = CreateSolidBrush(THEMED_RGB(24, 27, 32));
    switch (message) {
    case WM_CREATE: {
        edit = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_WANTRETURN, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(1)), g_instance, nullptr);
        apply = CreateWindowExW(0, L"BUTTON", L"Apply  (Ctrl+Enter)", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(2)), g_instance, nullptr);
        info = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0, hwnd, nullptr, g_instance, nullptr);
        SendMessageW(edit, WM_SETFONT, reinterpret_cast<WPARAM>(g_code_font), TRUE);
        SendMessageW(apply, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        SendMessageW(info, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        SendMessageW(edit, EM_SETLIMITTEXT, 0x7FFFFFFF, 0);
        SendMessageW(edit, EM_SETTABSTOPS, 0, 0);
        std::wstring source = g_type_source.empty()
            ? L"// Your own C declarations. Press Apply; Local Types and operands update.\r\n// struct Player { int id; char name[32]; float pos[3]; struct Player *next; };\r\n// enum Mode { Idle, Run = 5, Stop };\r\n// typedef unsigned int u32;\r\n"
            : wide(g_type_source);
        std::wstring fixed; for (std::size_t i = 0; i < source.size(); ++i) { if (source[i] == L'\n' && (i == 0 || source[i - 1] != L'\r')) fixed += L"\r\n"; else fixed += source[i]; }
        SetWindowTextW(edit, fixed.c_str());
        SetWindowTextW(info, g_type_error.empty() ? L"Built-in Windows types are always available (POINT, RECT, GUID, UNICODE_STRING, IMAGE_*, ...)." : wide("Error: " + g_type_error).c_str());
        return 0;
    }
    case WM_SIZE: {
        const int width = LOWORD(lparam), height = HIWORD(lparam), bar = 30;
        MoveWindow(edit, 0, 0, width, (std::max)(0, height - bar), TRUE);
        MoveWindow(apply, 6, height - bar + 3, 150, bar - 6, TRUE);
        MoveWindow(info, 166, height - bar + 7, (std::max)(0, width - 172), bar - 10, TRUE);
        return 0;
    }
    case WM_SETFOCUS: SetFocus(edit); return 0;
    case WM_COMMAND:
        if (LOWORD(wparam) == 2) {
            const int length = GetWindowTextLengthW(edit);
            std::wstring text(static_cast<std::size_t>(length) + 1, L'\0'); GetWindowTextW(edit, text.data(), length + 1); text.resize(static_cast<std::size_t>(length));
            std::string source = utf8_from_wide(text); std::string cleaned; for (const char ch : source) if (ch != '\r') cleaned += ch;
            g_type_source = cleaned;
            if (g_database) ensure_types(g_database->image().is_64_bit); else reload_type_library(true);
            SetWindowTextW(info, g_type_error.empty() ? L"Applied." : wide("Error: " + g_type_error).c_str());
            g_session_dirty = true;
            if (g_main_window) refresh_views(g_main_window);
            py_console_log(g_type_error.empty() ? L"types applied" : L"types error: " + wide(g_type_error));
        }
        return 0;
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: { auto dc = reinterpret_cast<HDC>(wparam); SetTextColor(dc, THEMED_RGB(215, 228, 238)); SetBkColor(dc, THEMED_RGB(24, 27, 32)); return reinterpret_cast<LRESULT>(background); }
    case WM_KEYDOWN: return 0;
    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_DESTROY: window = edit = apply = info = nullptr; return 0;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}
} // namespace typewin

HWND typewin_create(HWND parent) {
    using namespace typewin;
    static bool registered = false;
    if (!registered) {
        WNDCLASSW cls{}; cls.hInstance = g_instance; cls.lpfnWndProc = proc; cls.lpszClassName = L"GandonTypesEditor";
        cls.hCursor = LoadCursorW(nullptr, IDC_ARROW); cls.hbrBackground = g_panel; RegisterClassW(&cls); registered = true;
    }
    window = CreateWindowExW(0, L"GandonTypesEditor", L"Local Types Editor", WS_CHILD | WS_CLIPCHILDREN, 0, 0, 400, 300, parent, nullptr, g_instance, nullptr);
    return window;
}

void types_editor_window(HWND owner) {
    (void)owner;
    dock::show(L"types");
}

// ---------------------------------------------------------------------------
// Function-level binary diff
// ---------------------------------------------------------------------------
namespace diffwin {
HWND window{}, list{}, filter{};
auto& result = diffdata::result;
auto& other_name = diffdata::other_name;
std::vector<const gandon::FunctionDiffEntry*> shown;
int sort_column = 0; bool sort_descending = false;

std::wstring hex_text(std::uint64_t value) { if (!value) return L""; wchar_t b[24]{}; swprintf_s(b, L"%llX", static_cast<unsigned long long>(value)); return b; }

void rebuild() {
    shown.clear();
    if (!list) return;
    wchar_t buffer[256]{}; GetWindowTextW(filter, buffer, 256);
    std::wstring needle = buffer; for (auto& ch : needle) ch = static_cast<wchar_t>(std::towlower(ch));
    for (const auto& e : result.entries) {
        if (!needle.empty()) {
            std::wstring text = wide(std::string(gandon::diff_kind_name(e.kind)) + " " + e.a_name + " " + e.b_name + " " + e.matched_by);
            for (auto& ch : text) ch = static_cast<wchar_t>(std::towlower(ch));
            if (text.find(needle) == std::wstring::npos) continue;
        }
        shown.push_back(&e);
    }
    const auto key = [](const gandon::FunctionDiffEntry* e, int column) -> std::wstring {
        switch (column) {
        case 0: return wide(gandon::diff_kind_name(e->kind));
        case 2: return wide(e->a_name);
        case 4: return wide(e->b_name);
        default: return L"";
        }
    };
    if (sort_column != 0 || sort_descending) {   // column 0 keeps the engine's own order (changed first)
        std::stable_sort(shown.begin(), shown.end(), [&](const auto* l, const auto* r) {
            bool less;
            switch (sort_column) {
            case 1: less = l->similarity < r->similarity; break;
            case 3: less = l->a_start < r->a_start; break;
            case 5: less = l->b_start < r->b_start; break;
            case 6: less = l->a_instructions < r->a_instructions; break;
            case 7: less = l->b_instructions < r->b_instructions; break;
            default: less = _wcsicmp(key(l, sort_column).c_str(), key(r, sort_column).c_str()) < 0; break;
            }
            return sort_descending ? !less && (key(l, sort_column) != key(r, sort_column) || l->similarity != r->similarity) : less;
        });
    }
    ListView_SetItemCountEx(list, static_cast<int>(shown.size()), LVSICF_NOINVALIDATEALL);
    InvalidateRect(list, nullptr, TRUE);
    if (window) {
        const std::wstring title = L"Diff vs " + other_name + L"  (" + wide(result.summary()) + L")";
        SetWindowTextW(window, title.c_str());
    }
}

LRESULT CALLBACK proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    static HBRUSH background = CreateSolidBrush(THEMED_RGB(24, 27, 32));
    switch (message) {
    case WM_CREATE: {
        filter = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(2)), g_instance, nullptr);
        SendMessageW(filter, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        SendMessageW(filter, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"Filter: changed, added, removed, name..."));
        list = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_OWNERDATA | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(1)), g_instance, nullptr);
        ListView_SetExtendedListViewStyle(list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        SendMessageW(list, WM_SETFONT, reinterpret_cast<WPARAM>(g_code_font), TRUE);
        ListView_SetBkColor(list, THEMED_RGB(24, 27, 32)); ListView_SetTextBkColor(list, THEMED_RGB(24, 27, 32)); ListView_SetTextColor(list, THEMED_RGB(215, 228, 238));
        if (const auto uxtheme = GetModuleHandleW(L"uxtheme.dll")) {
            using Fn = HRESULT(WINAPI*)(HWND, LPCWSTR, LPCWSTR);
            if (const auto set_theme = reinterpret_cast<Fn>(reinterpret_cast<void*>(GetProcAddress(uxtheme, "SetWindowTheme")))) { set_theme(list, L"DarkMode_ItemsView", nullptr); set_theme(filter, L"DarkMode_CFD", nullptr); }
        }
        const wchar_t* names[] = {L"Status", L"Similar", L"Function A", L"Address A", L"Function B", L"Address B", L"Instr A", L"Instr B", L"Matched by"};
        const int widths[] = {80, 70, 200, 120, 200, 120, 70, 70, 90};
        for (int i = 0; i < 9; ++i) { LVCOLUMNW column{}; column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT; column.pszText = const_cast<wchar_t*>(names[i]); column.cx = widths[i]; column.fmt = (i == 1 || i == 6 || i == 7) ? LVCFMT_RIGHT : LVCFMT_LEFT; ListView_InsertColumn(list, i, &column); }
        if (!g_light_theme) if (const auto header = ListView_GetHeader(list)) SetWindowSubclass(header, funcwin::header_proc, 1, 0);
        return 0;
    }
    case WM_SIZE: {
        const int width = LOWORD(lparam), height = HIWORD(lparam);
        MoveWindow(filter, 0, 0, width, 24, TRUE);
        MoveWindow(list, 0, 24, width, (std::max)(0, height - 24), TRUE);
        return 0;
    }
    case WM_SETFOCUS: SetFocus(list); return 0;
    case WM_COMMAND: if (LOWORD(wparam) == 2 && HIWORD(wparam) == EN_CHANGE) rebuild(); return 0;
    case WM_NOTIFY: {
        auto* header = reinterpret_cast<LPNMHDR>(lparam);
        if (header->hwndFrom != list) return 0;
        if (header->code == NM_CUSTOMDRAW) {
            auto* draw = reinterpret_cast<NMLVCUSTOMDRAW*>(lparam);
            if (draw->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (draw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                const auto index = static_cast<std::size_t>(draw->nmcd.dwItemSpec);
                if (index < shown.size()) {
                    switch (shown[index]->kind) {
                    case gandon::FunctionDiffEntry::Kind::Changed: draw->clrText = THEMED_RGB(255, 190, 90); break;
                    case gandon::FunctionDiffEntry::Kind::Added: draw->clrText = THEMED_RGB(120, 220, 130); break;
                    case gandon::FunctionDiffEntry::Kind::Removed: draw->clrText = THEMED_RGB(240, 110, 110); break;
                    default: draw->clrText = THEMED_RGB(140, 150, 160); break;
                    }
                }
                return CDRF_DODEFAULT;
            }
            return CDRF_DODEFAULT;
        }
        if (header->code == LVN_GETDISPINFOW) {
            auto* info = reinterpret_cast<NMLVDISPINFOW*>(lparam);
            if ((info->item.mask & LVIF_TEXT) && info->item.iItem >= 0 && info->item.iItem < static_cast<int>(shown.size())) {
                const auto& e = *shown[static_cast<std::size_t>(info->item.iItem)];
                static thread_local std::wstring text;
                switch (info->item.iSubItem) {
                case 0: text = wide(gandon::diff_kind_name(e.kind)); break;
                case 1: { wchar_t b[24]{}; if (e.a_start && e.b_start) swprintf_s(b, L"%.0f%%", e.similarity * 100.0); text = b; break; }
                case 2: text = wide(e.a_name); break;
                case 3: text = hex_text(e.a_start); break;
                case 4: text = wide(e.b_name); break;
                case 5: text = hex_text(e.b_start); break;
                case 6: text = e.a_start ? std::to_wstring(e.a_instructions) : L""; break;
                case 7: text = e.b_start ? std::to_wstring(e.b_instructions) : L""; break;
                default: text = wide(e.matched_by); break;
                }
                info->item.pszText = text.data();
            }
        } else if (header->code == LVN_COLUMNCLICK) {
            const int column = reinterpret_cast<NMLISTVIEW*>(lparam)->iSubItem;
            if (column == sort_column) sort_descending = !sort_descending; else { sort_column = column; sort_descending = false; }
            rebuild();
        } else if (header->code == NM_DBLCLK) {
            const int index = reinterpret_cast<NMITEMACTIVATE*>(lparam)->iItem;
            if (index >= 0 && index < static_cast<int>(shown.size()) && g_database) {
                const auto& e = *shown[static_cast<std::size_t>(index)];
                if (e.a_start) navigate_to_address(g_main_window, e.a_start, g_tabs && TabCtrl_GetCurSel(g_tabs) == 0 ? 0 : 1);
            }
        }
        return 0;
    }
    case WM_CTLCOLOREDIT: { auto dc = reinterpret_cast<HDC>(wparam); SetTextColor(dc, THEMED_RGB(215, 228, 238)); SetBkColor(dc, THEMED_RGB(24, 27, 32)); return reinterpret_cast<LRESULT>(background); }
    case WM_ERASEBKGND: return 1;
    case WM_DESTROY: window = list = filter = nullptr; return 0;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}
} // namespace diffwin

HWND diffwin_create(HWND parent) {
    using namespace diffwin;
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES}; InitCommonControlsEx(&controls);
    static bool registered = false;
    if (!registered) {
        WNDCLASSW cls{}; cls.hInstance = g_instance; cls.lpfnWndProc = proc; cls.lpszClassName = L"GandonDiff";
        cls.hCursor = LoadCursorW(nullptr, IDC_ARROW); cls.hbrBackground = g_panel; RegisterClassW(&cls); registered = true;
    }
    window = CreateWindowExW(0, L"GandonDiff", L"Diff", WS_CHILD | WS_CLIPCHILDREN, 0, 0, 400, 200, parent, nullptr, g_instance, nullptr);
    if (window) rebuild();
    return window;
}

// Loads another binary, runs the same auto-analysis as for the open one and compares the functions.
bool run_function_diff(const std::filesystem::path& other_path, std::string& error) {
    if (!g_database) { error = "no binary is open"; return false; }
    gandon::BinaryImage image;
    if (!image.load(other_path, error)) return false;
    gandon::AnalysisDatabase other(std::move(image));
    other.discover_basic_xrefs();
    gandon::run_auto_analysis(other);
    diffwin::result = gandon::diff_functions(*g_database, other);
    diffwin::other_name = other_path.filename().wstring();
    output_log(L"Diff vs " + diffwin::other_name + L": " + wide(diffwin::result.summary()) + L"\r\n");
    dock::show(L"diff");
    diffwin::rebuild();
    return true;
}

void diff_with_binary(HWND window) {
    if (!g_database) { MessageBoxW(window, L"Open a binary first.", L"Diff functions", MB_ICONINFORMATION); return; }
    wchar_t file_name[MAX_PATH]{}; OPENFILENAMEW dialog{sizeof(dialog)}; dialog.hwndOwner = window;
    dialog.lpstrFilter = L"Binaries (*.exe;*.dll;*.so;*.sys)\0*.exe;*.dll;*.so;*.sys\0All files (*.*)\0*.*\0"; dialog.lpstrFile = file_name; dialog.nMaxFile = MAX_PATH; dialog.Flags = OFN_FILEMUSTEXIST;
    if (!GetOpenFileNameW(&dialog)) return;
    SetWindowTextW(g_status, L"Analysing the second binary...");
    std::string error;
    if (!run_function_diff(file_name, error)) MessageBoxW(window, wide(error).c_str(), L"Diff functions", MB_ICONERROR);
    else SetWindowTextW(g_status, wide("Function diff: " + diffwin::result.summary()).c_str());
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

std::atomic<bool> g_hide_debugger{false};

struct SavedPebFlags { std::uint64_t address{}; unsigned flag_offset{}; BYTE being_debugged{}; DWORD flags{}; };
std::mutex g_peb_mutex;
std::map<DWORD, std::vector<SavedPebFlags>> g_saved_pebs;

// PEB offsets are undocumented Windows implementation details. No heap flags,
// kernel debug objects, system callbacks or executable API code are patched.
bool hide_debugger_in_process(HANDLE process) {
    using Query = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    const auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!process || !query) return false;
    const DWORD pid = GetProcessId(process);
    BOOL wow64 = FALSE;
    if (!pid || !IsWow64Process(process, &wow64)) return false;
    SYSTEM_INFO system{}; GetNativeSystemInfo(&system);
    const bool native64 = system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
    if (system.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 && system.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_INTEL) return false;
    if (sizeof(void*) == 4 && native64 && !wow64) return false;
    struct Basic { PVOID reserved; PVOID peb; PVOID reserved2[2]; ULONG_PTR pid; PVOID reserved3; } basic{};
    if (query(process, 0, &basic, sizeof(basic), nullptr) < 0 || !basic.peb) return false;
    std::vector<SavedPebFlags> pebs;
    pebs.push_back({reinterpret_cast<std::uintptr_t>(basic.peb), sizeof(void*) == 8 && native64 ? 0xBCu : 0x68u, 0, 0});
    if (sizeof(void*) == 8 && wow64) {
        ULONG_PTR peb32{};
        if (query(process, 26, &peb32, sizeof(peb32), nullptr) < 0 || !peb32) return false;
        pebs.push_back({peb32, 0x68, 0, 0});
    }
    std::lock_guard lock(g_peb_mutex);
    if (g_saved_pebs.contains(pid)) return true;
    for (auto& peb : pebs) {
        SIZE_T count{};
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(peb.address + 2), &peb.being_debugged, 1, &count) || count != 1 ||
            !ReadProcessMemory(process, reinterpret_cast<LPCVOID>(peb.address + peb.flag_offset), &peb.flags, sizeof(peb.flags), &count) || count != sizeof(peb.flags)) return false;
    }
    bool ok = true;
    for (const auto& peb : pebs) {
        const BYTE zero = 0; const DWORD flags = peb.flags & ~0x70u; SIZE_T count{};
        if (!WriteProcessMemory(process, reinterpret_cast<LPVOID>(peb.address + 2), &zero, 1, &count) || count != 1 ||
            !WriteProcessMemory(process, reinterpret_cast<LPVOID>(peb.address + peb.flag_offset), &flags, sizeof(flags), &count) || count != sizeof(flags)) { ok = false; break; }
        BYTE verified_byte = 1; DWORD verified_flags{};
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(peb.address + 2), &verified_byte, 1, &count) || count != 1 || verified_byte != 0 ||
            !ReadProcessMemory(process, reinterpret_cast<LPCVOID>(peb.address + peb.flag_offset), &verified_flags, sizeof(verified_flags), &count) || count != sizeof(verified_flags) || verified_flags != flags) { ok = false; break; }
    }
    if (!ok) {
        // Roll back both PEBs if one write/verification failed.
        for (const auto& peb : pebs) {
            SIZE_T count{};
            WriteProcessMemory(process, reinterpret_cast<LPVOID>(peb.address + 2), &peb.being_debugged, 1, &count);
            WriteProcessMemory(process, reinterpret_cast<LPVOID>(peb.address + peb.flag_offset), &peb.flags, sizeof(peb.flags), &count);
        }
        return false;
    }
    g_saved_pebs.emplace(pid, std::move(pebs)); return true;
}

bool restore_debugger_pebs(HANDLE process) {
    std::lock_guard lock(g_peb_mutex);
    const auto it = g_saved_pebs.find(GetProcessId(process));
    if (it == g_saved_pebs.end()) return true;
    bool ok = true;
    for (const auto& peb : it->second) {
        SIZE_T count{}; DWORD flags{};
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(peb.address + peb.flag_offset), &flags, sizeof(flags), &count) || count != sizeof(flags)) { ok = false; continue; }
        flags = (flags & ~0x70u) | (peb.flags & 0x70u);
        if (!WriteProcessMemory(process, reinterpret_cast<LPVOID>(peb.address + 2), &peb.being_debugged, 1, &count) || count != 1 ||
            !WriteProcessMemory(process, reinterpret_cast<LPVOID>(peb.address + peb.flag_offset), &flags, sizeof(flags), &count) || count != sizeof(flags)) ok = false;
    }
    if (ok) g_saved_pebs.erase(it);
    return ok;
}

void toggle_hide_debugger(HWND window) {
    const auto process = g_debug_process.load();
    if (process && !g_debug_paused.load()) { SetWindowTextW(g_status, L"Pause the debuggee before changing anti-anti-debug settings."); return; }
    const bool enable = !g_hide_debugger.load();
    if (process && !(enable ? hide_debugger_in_process(process) : restore_debugger_pebs(process))) {
        SetWindowTextW(g_status, L"PEB update failed; settings were not changed."); return;
    }
    g_hide_debugger.store(enable); g_stealth_applied.store(enable && process);
    CheckMenuItem(GetMenu(window), ID_ANTI_DEBUG, MF_BYCOMMAND | (enable ? MF_CHECKED : MF_UNCHECKED));
    SetWindowTextW(g_status, enable ? L"PEB anti-anti-debug ON (native/WOW64). Kernel debug state remains visible." : L"PEB anti-anti-debug OFF; saved PEB flags restored.");
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

void show_antidebug_status(HWND window) {
    const auto process = g_debug_process.load();
    if (!process) { SetWindowTextW(g_status, L"No debug process."); return; }
    std::wostringstream report;
    report << L"Anti-anti-debug status\r\nPEB profile: " << (g_stealth_applied.load() ? L"applied" : L"not applied")
           << L"\r\nReversible BeingDebugged and NtGlobalFlag debug-bit masking; native and WOW64 PEBs.\r\n"
           << L"No API prologue patching. Direct syscalls, debug ports, timing, heap and kernel checks can still detect debugging.\r\n";
    using Query = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    const auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (query) {
        ULONG_PTR port{}; ULONG flags{};
        const auto a = query(process, 7, &port, sizeof(port), nullptr);
        const auto b = query(process, 31, &flags, sizeof(flags), nullptr);
        report << L"ProcessDebugPort: status=0x" << std::hex << static_cast<ULONG>(a) << L" value=0x" << port
               << L"\r\nProcessDebugFlags: status=0x" << static_cast<ULONG>(b) << L" value=0x" << flags << L"\r\n";
    }
    g_listing = report.str(); select_view(window, 1);
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
            if (g_hide_debugger.load()) {
                const bool applied = hide_debugger_in_process(process); g_stealth_applied.store(applied);
                log_debug_event(applied ? L"Anti-anti-debug: PEB flags masked" : L"Anti-anti-debug: PEB masking failed");
            }
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
    { std::lock_guard lock(g_peb_mutex); g_saved_pebs.erase(pid); }
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

bool initialize_emulation_session(HWND window) {
    if (!g_database) {
        MessageBoxW(window, L"Сначала открой PE/ELF бинарник.", L"CPU Emulation", MB_ICONINFORMATION);
        return false;
    }
    const auto start = g_current_address ? g_current_address : g_database->image().entry_point;
    std::string error;
    auto session = std::make_unique<gandon::Emulator>(g_database->image());
    if (!session->ready()) {
        MessageBoxW(window, wide(session->error()).c_str(), L"CPU Emulation", MB_ICONWARNING);
        return false;
    }
    const auto pc_name = g_database->image().architecture == gandon::MachineArchitecture::ARM64
        ? "PC" : g_database->image().is_64_bit ? "RIP" : "EIP";
    if (!session->set_register(pc_name, start, error)) {
        MessageBoxW(window, wide(error).c_str(), L"CPU Emulation", MB_ICONERROR);
        return false;
    }
    g_emulator = std::move(session);
    return true;
}

// ---------------------------------------------------------------------------
// Unpacking & protection analysis. These are static/dynamic RE aids for the
// user's own target: dump an unpacked module, rebuild its imports, locate a VM
// dispatcher, and run a decryptor to recover plaintext. They do not defeat
// anti-cheat protections or help build a cheat.
// ---------------------------------------------------------------------------

// Map every named export of every module loaded in the debugged process to its
// absolute address, so a dumped IAT of resolved pointers can be named again.
void collect_remote_exports(HANDLE process, std::map<std::uint64_t, std::string>& out) {
    if (!process) return;
    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, g_debug_pid.load());
    if (snapshot == INVALID_HANDLE_VALUE) return;
    const auto rd = [&](std::uint64_t addr, void* dst, std::size_t n) -> bool {
        SIZE_T got = 0; return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(addr), dst, n, &got) && got == n;
    };
    MODULEENTRY32W entry{}; entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) do {
        const auto base = reinterpret_cast<std::uint64_t>(entry.modBaseAddr);
        const std::string dll = utf8(entry.szModule);
        std::uint8_t hdr[0x400];
        if (!rd(base, hdr, sizeof hdr) || hdr[0] != 'M' || hdr[1] != 'Z') continue;
        const std::uint32_t pe = *reinterpret_cast<std::uint32_t*>(hdr + 0x3c);
        if (pe + 0x88 > sizeof hdr || hdr[pe] != 'P' || hdr[pe + 1] != 'E') continue;
        const bool is64 = *reinterpret_cast<std::uint16_t*>(hdr + pe + 24) == 0x20b;
        const std::size_t dir = pe + 24 + (is64 ? 112 : 96);           // export directory = data dir 0
        const std::uint32_t exp_rva = *reinterpret_cast<std::uint32_t*>(hdr + dir);
        const std::uint32_t exp_size = *reinterpret_cast<std::uint32_t*>(hdr + dir + 4);
        if (!exp_rva || !exp_size) continue;
        std::uint8_t ed[40];
        if (!rd(base + exp_rva, ed, sizeof ed)) continue;
        const std::uint32_t n_funcs = *reinterpret_cast<std::uint32_t*>(ed + 20);
        const std::uint32_t n_names = *reinterpret_cast<std::uint32_t*>(ed + 24);
        const std::uint32_t funcs_rva = *reinterpret_cast<std::uint32_t*>(ed + 28);
        const std::uint32_t names_rva = *reinterpret_cast<std::uint32_t*>(ed + 32);
        const std::uint32_t ords_rva = *reinterpret_cast<std::uint32_t*>(ed + 36);
        if (n_funcs > 200000 || n_names > 200000) continue;
        std::vector<std::uint32_t> funcs(n_funcs), names(n_names);
        std::vector<std::uint16_t> ords(n_names);
        if (n_funcs && !rd(base + funcs_rva, funcs.data(), funcs.size() * 4)) continue;
        if (n_names && !rd(base + names_rva, names.data(), names.size() * 4)) continue;
        if (n_names && !rd(base + ords_rva, ords.data(), ords.size() * 2)) continue;
        for (std::uint32_t i = 0; i < n_names; ++i) {
            char nm[256]{}; if (!rd(base + names[i], nm, sizeof nm - 1)) continue; nm[255] = 0;
            if (ords[i] >= n_funcs) continue;
            const std::uint32_t frva = funcs[ords[i]];
            if (!frva || (frva >= exp_rva && frva < exp_rva + exp_size)) continue;   // skip empty / forwarders
            out[base + frva] = dll + "!" + nm;
        }
    } while (Module32NextW(snapshot, &entry));
    CloseHandle(snapshot);
}

void dump_process_module(HWND window) {
    const auto process = g_debug_process.load();
    const auto base = g_debug_base.load();
    if (!process || !base) { MessageBoxW(window, L"Сначала запусти цель под отладчиком (Run) и поставь на паузу после распаковки.", L"Dump Module", MB_ICONINFORMATION); return; }
    std::uint8_t hdr[0x1000];
    SIZE_T got = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base), hdr, sizeof hdr, &got) || got < 0x400 || hdr[0] != 'M' || hdr[1] != 'Z') {
        MessageBoxW(window, L"Не удалось прочитать заголовки модуля из процесса.", L"Dump Module", MB_ICONERROR); return;
    }
    const std::uint32_t pe = *reinterpret_cast<std::uint32_t*>(hdr + 0x3c);
    const std::uint32_t size_of_image = *reinterpret_cast<std::uint32_t*>(hdr + pe + 24 + 56);
    if (!size_of_image || size_of_image > 512u * 1024 * 1024) { MessageBoxW(window, L"Некорректный SizeOfImage в заголовке.", L"Dump Module", MB_ICONERROR); return; }
    std::vector<std::uint8_t> mem(size_of_image, 0);
    for (std::uint32_t off = 0; off < size_of_image; off += 0x1000) {
        SIZE_T n = 0;
        ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base + off), mem.data() + off,
                          (std::min<std::uint32_t>)(0x1000, size_of_image - off), &n);  // tolerate unreadable pages
    }
    auto dumped = gandon::pe_dump::build_pe_from_memory(mem);
    if (!dumped.ok) { MessageBoxW(window, wide(dumped.error).c_str(), L"Dump Module", MB_ICONERROR); return; }
    std::map<std::uint64_t, std::string> exports;
    collect_remote_exports(process, exports);
    const auto resolver = [&](std::uint64_t p) -> std::string { const auto it = exports.find(p); return it == exports.end() ? std::string() : it->second; };
    auto rebuilt = gandon::pe_dump::rebuild_imports(dumped.bytes, base, resolver);
    const std::vector<std::uint8_t>* final_bytes = &dumped.bytes;
    std::wstring status;
    if (rebuilt.ok) { final_bytes = &rebuilt.bytes; status = L"IAT rebuilt: " + std::to_wstring(rebuilt.resolved) + L" import(s) across " + std::to_wstring(rebuilt.dll_count) + L" dll(s)."; }
    else status = L"Dumped (no IAT rebuild: " + wide(rebuilt.error) + L").";
    wchar_t file_name[MAX_PATH] = L"dumped.exe";
    OPENFILENAMEW dlg{sizeof(dlg)}; dlg.hwndOwner = window; dlg.lpstrFilter = L"Executables (*.exe;*.dll)\0*.exe;*.dll\0All files (*.*)\0*.*\0"; dlg.lpstrFile = file_name; dlg.nMaxFile = MAX_PATH; dlg.Flags = OFN_OVERWRITEPROMPT;
    if (!GetSaveFileNameW(&dlg)) return;
    std::ofstream out(file_name, std::ios::binary);
    out.write(reinterpret_cast<const char*>(final_bytes->data()), static_cast<std::streamsize>(final_bytes->size()));
    if (!out) { MessageBoxW(window, L"Не удалось записать файл.", L"Dump Module", MB_ICONERROR); return; }
    MessageBoxW(window, (L"Модуль сдамплен (" + std::to_wstring(size_of_image) + L" байт).\r\n" + status).c_str(), L"Dump Module", MB_ICONINFORMATION);
    SetWindowTextW(g_status, status.c_str());
}

void detect_vm_here(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Выбери функцию.", L"Detect VM", MB_ICONINFORMATION); return; }
    const auto fn = g_database->function_at(g_current_address);
    if (!fn) { MessageBoxW(window, L"Текущий адрес вне функции.", L"Detect VM", MB_ICONINFORMATION); return; }
    const auto vm = gandon::detect_vm_dispatch(g_database->image(), fn->get().start, fn->get().instructions);
    const auto flat = gandon::detect_flattening(g_database->image(), fn->get().start, fn->get().instructions);
    std::wostringstream r;
    r << L"VM / obfuscation scan @ 0x" << std::hex << std::uppercase << fn->get().start << L"\r\n\r\n";
    r << L"control-flow: " << wide(flat.note) << L"\r\n";
    if (flat.flattened) r << L"  dispatcher 0x" << flat.dispatcher << L"  in-degree " << std::dec << flat.dispatcher_in_degree << L"\r\n";
    r << L"\r\n";
    if (!vm.found) {
        r << wide(vm.note) << L"\r\n\r\nПримечание: VMProtect/Virbox обычно диспетчеризуют через регистр (jmp rax после вычисления адреса хендлера), это ловится только динамической трассировкой хендлеров, а не статическим сканом таблиц.\r\n";
    } else {
        r << L"dispatch site : 0x" << vm.dispatch_site << L"\r\nhandler table : 0x" << vm.table_va << L"  (index*" << std::dec << vm.scale << L")\r\nhandlers      : " << vm.handlers.size() << L"\r\n\r\n";
        std::size_t i = 0; for (const auto h : vm.handlers) { r << L"  handler[" << std::dec << i << L"] = 0x" << std::hex << std::uppercase << h << L"\r\n"; if (++i >= 64) { r << L"  ... (" << std::dec << (vm.handlers.size() - i) << L" more)\r\n"; break; } }
    }
    g_listing = r.str(); select_view(window, 1);
    SetWindowTextW(g_status, vm.found ? L"VM dispatcher found." : flat.flattened ? L"Control-flow flattening detected." : L"No table-based VM dispatcher here.");
}

void trace_vm_here(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Выбери точку входа VM.", L"Trace VM", MB_ICONINFORMATION); return; }
    const auto fn = g_database->function_at(g_current_address);
    const std::uint64_t start = fn ? fn->get().start : g_current_address;
    const auto& insns = fn ? fn->get().instructions : std::vector<gandon::Instruction>{};
    const auto vm = gandon::detect_vm_dispatch(g_database->image(), start, insns);
    if (!vm.found) { MessageBoxW(window, L"В этой функции не найден табличный VM-диспетчер — трассировать нечего.", L"Trace VM", MB_ICONINFORMATION); return; }
    SetWindowTextW(g_status, L"Emulating VM handler trace...");
    const auto trace = gandon::trace_vm_handlers(g_database->image(), g_current_address, vm);
    std::wostringstream r;
    r << L"VM handler trace from 0x" << std::hex << std::uppercase << g_current_address << L"\r\n\r\n";
    if (!trace.ok) {
        r << L"Трассировка не удалась: " << wide(trace.error) << L"\r\n\r\n"
          << L"Причина обычно в анти-эмуляции/защите (VMProtect/Virbox): эмулятор без реальной ОС и обхода anti-debug не проходит далеко. На простых/кастомных VM работает.\r\n";
    } else {
        r << L"handlers executed: " << std::dec << trace.handler_sequence.size() << (trace.truncated ? L" (truncated)" : L"") << L"\r\n\r\n";
        std::size_t i = 0;
        for (const auto h : trace.handler_sequence) { r << L"  " << std::dec << i << L": 0x" << std::hex << std::uppercase << h << L"\r\n"; if (++i >= 200) { r << L"  ...\r\n"; break; } }
    }
    g_listing = r.str(); select_view(window, 1);
    SetWindowTextW(g_status, trace.ok ? L"VM handler trace done." : L"VM handler trace failed (protection?).");
}

void analyze_dotnet_here(HWND window) {
    if (!g_database) { MessageBoxW(window, L"Сначала открой бинарь.", L"Analyze .NET", MB_ICONINFORMATION); return; }
    const auto info = gandon::parse_dotnet(g_database->image());
    std::wostringstream r;
    if (!info.is_dotnet) { r << L".NET: " << wide(info.error) << L"\r\n"; g_listing = r.str(); select_view(window, 1); SetWindowTextW(g_status, L"Not a .NET assembly."); return; }
    r << L".NET assembly\r\n  runtime: " << wide(info.runtime_version) << L"\r\n  entry token: 0x" << std::hex << std::uppercase << info.entry_point_token
      << L"\r\n  IL-only: " << (info.il_only ? L"yes" : L"no") << L"\r\n\r\n  metadata tables:\r\n";
    for (const auto& [name, rows] : info.table_rows) r << L"    " << wide(name) << L" : " << std::dec << rows << L"\r\n";
    r << L"\r\n  names (#Strings): " << std::dec << info.names.size() << L", user strings (#US): " << info.user_strings.size() << L"\r\n\r\n";
    r << L"  user strings:\r\n";
    std::size_t shown = 0;
    for (const auto& s : info.user_strings) { r << L"    \"" << wide(s) << L"\"\r\n"; if (++shown >= 200) { r << L"    ... (" << std::dec << (info.user_strings.size() - shown) << L" more)\r\n"; break; } }
    g_listing = r.str(); select_view(window, 1);
    SetWindowTextW(g_status, (L".NET: " + std::to_wstring(info.names.size()) + L" names, " + std::to_wstring(info.user_strings.size()) + L" strings.").c_str());
}

void recover_rtti_here(HWND window) {
    if (!g_database) { MessageBoxW(window, L"Сначала открой бинарь.", L"RTTI", MB_ICONINFORMATION); return; }
    const auto classes = gandon::recover_rtti(g_database->image());
    std::wostringstream r;
    r << L"MSVC RTTI / C++ classes: " << std::dec << classes.size() << L"\r\n\r\n";
    if (classes.empty()) r << L"RTTI не найдено (бинарь без RTTI, не-MSVC, или стрипнут).\r\n";
    for (const auto& c : classes) {
        r << L"  " << wide(c.name) << L"\r\n      vtable 0x" << std::hex << std::uppercase << c.vtable_va
          << L"  methods " << std::dec << c.method_count;
        if (!c.base_classes.empty()) { r << L"  : "; for (std::size_t i = 0; i < c.base_classes.size(); ++i) r << (i ? L", " : L"") << wide(c.base_classes[i]); }
        r << L"\r\n";
    }
    g_listing = r.str(); select_view(window, 1);
    SetWindowTextW(g_status, (std::to_wstring(classes.size()) + L" RTTI class(es) recovered.").c_str());
}

void analyze_driver_here(HWND window) {
    if (!g_database) { MessageBoxW(window, L"Сначала открой бинарь.", L"Driver", MB_ICONINFORMATION); return; }
    const auto info = gandon::analyze_driver(g_database->image());
    std::wostringstream r;
    if (!info.is_driver) { r << L"driver: " << wide(info.error) << L"\r\n"; g_listing = r.str(); select_view(window, 1); SetWindowTextW(g_status, L"Not a kernel driver."); return; }
    r << L"Kernel driver\r\n  DriverEntry: 0x" << std::hex << std::uppercase << info.driver_entry << L"\r\n\r\n  IRP dispatch routines:\r\n";
    for (const auto& h : info.handlers) r << L"    " << wide(h.name) << L" -> 0x" << h.handler << L"\r\n";
    r << L"\r\n  IOCTL codes (" << std::dec << info.ioctls.size() << L"):\r\n";
    for (const auto c : info.ioctls) { wchar_t buf[16]; swprintf_s(buf, L"0x%08X", c); r << L"    " << buf << L"\r\n"; }
    g_listing = r.str(); select_view(window, 1);
    SetWindowTextW(g_status, L"Driver analysis done.");
}

void devirtualize_vm_here(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Выбери функцию с VM.", L"Devirtualize", MB_ICONINFORMATION); return; }
    const auto fn = g_database->function_at(g_current_address);
    const std::uint64_t start = fn ? fn->get().start : g_current_address;
    const auto& insns = fn ? fn->get().instructions : std::vector<gandon::Instruction>{};
    const auto vm = gandon::detect_vm_dispatch(g_database->image(), start, insns);
    if (!vm.found) { MessageBoxW(window, L"Табличный VM-диспетчер не найден в этой функции.", L"Devirtualize", MB_ICONINFORMATION); return; }
    const auto classes = gandon::classify_vm_handlers(g_database->image(), vm);
    std::wostringstream r;
    r << L"VM devirtualization (semi-automatic) @ 0x" << std::hex << std::uppercase << start << L"\r\n"
      << L"handler table 0x" << vm.table_va << L", " << std::dec << vm.handlers.size() << L" handlers\r\n\r\n";
    std::size_t shown = 0;
    for (const auto& hc : classes) {
        r << L"=== handler[" << std::dec << shown << L"] 0x" << std::hex << std::uppercase << hc.address << L"  [" << wide(hc.classification) << L"]\r\n";
        const auto dr = gandon::decompile_function_at(*g_database, hc.address);
        if (dr.ok) r << wide(dr.text) << L"\r\n";
        else r << L"    (decompile: " << wide(dr.error) << L")\r\n";
        if (++shown >= 24) { r << L"... (" << std::dec << (classes.size() - shown) << L" more handlers)\r\n"; break; }
    }
    g_listing = r.str(); select_view(window, 1);
    SetWindowTextW(g_status, L"VM handlers decompiled.");
}

// Pull printable ASCII and UTF-16LE strings (>= 4 chars) out of a byte buffer.
void extract_strings(const std::vector<std::uint8_t>& buf, std::vector<std::wstring>& out) {
    std::string run;
    for (std::size_t i = 0; i <= buf.size(); ++i) {
        const int c = i < buf.size() ? buf[i] : -1;
        if (c >= 0x20 && c <= 0x7e) run.push_back(static_cast<char>(c));
        else { if (run.size() >= 4) out.push_back(wide(run)); run.clear(); }
    }
    std::wstring wrun;
    for (std::size_t i = 0; i + 1 < buf.size(); i += 2) {
        const int c = buf[i]; const int hi = buf[i + 1];
        if (hi == 0 && c >= 0x20 && c <= 0x7e) wrun.push_back(static_cast<wchar_t>(c));
        else { if (wrun.size() >= 4) out.push_back(wrun); wrun.clear(); }
    }
    if (wrun.size() >= 4) out.push_back(wrun);
}

void emulate_decryptor(HWND window) {
    if (!g_database || !g_current_address) { MessageBoxW(window, L"Выбери функцию-декриптор.", L"Emulate Decryptor", MB_ICONINFORMATION); return; }
    gandon::Emulator emu(g_database->image());
    if (!emu.ready()) { MessageBoxW(window, wide(emu.error()).c_str(), L"Emulate Decryptor", MB_ICONWARNING); return; }
    std::string err;
    const char* pc = g_database->image().architecture == gandon::MachineArchitecture::ARM64 ? "PC" : g_database->image().is_64_bit ? "RIP" : "EIP";
    emu.set_register(pc, g_current_address, err);
    const auto result = emu.run(200'000, 2'000'000);
    std::map<std::uint64_t, std::uint8_t> written;
    for (const auto& a : emu.memory_accesses()) {
        if (!a.write || !a.value_captured || a.size == 0 || a.size > 8) continue;
        for (std::uint32_t k = 0; k < a.size; ++k) written[a.address + k] = static_cast<std::uint8_t>(a.value >> (8 * k));
    }
    // Rebuild contiguous regions from the sparse write map and scan each for strings.
    std::vector<std::wstring> strings;
    std::vector<std::uint8_t> region; std::uint64_t prev = 0; bool have = false;
    for (const auto& [addr, byte] : written) {
        if (have && addr != prev + 1) { extract_strings(region, strings); region.clear(); }
        region.push_back(byte); prev = addr; have = true;
    }
    if (!region.empty()) extract_strings(region, strings);
    std::sort(strings.begin(), strings.end());
    strings.erase(std::unique(strings.begin(), strings.end()), strings.end());

    std::wostringstream r;
    r << L"Decryptor emulation @ 0x" << std::hex << std::uppercase << g_current_address << L"\r\n";
    r << L"instructions executed: " << std::dec << result.instructions_executed
      << L", memory writes: " << written.size() << L"\r\n\r\n";
    if (strings.empty()) r << L"Строк не восстановлено. Возможно, декриптору нужны аргументы (поставь RCX/RDX на зашифрованные данные через эмулятор) или мешает защита.\r\n";
    else { r << L"Recovered strings (" << std::dec << strings.size() << L"):\r\n"; for (const auto& s : strings) r << L"  " << s << L"\r\n"; }
    g_listing = r.str(); select_view(window, 1);
    SetWindowTextW(g_status, strings.empty() ? L"Decryptor: no strings recovered." : (std::to_wstring(strings.size()) + L" string(s) recovered.").c_str());
}

void prepare_emulation_session(HWND window) {
    if (g_emulator) {
        MessageBoxW(window, L"Сессия эмуляции уже подготовлена. Чтобы начать с другого адреса, сначала выбери Reset Emulation Session.",
                    L"CPU Emulation", MB_ICONINFORMATION);
        return;
    }
    if (!initialize_emulation_session(window)) return;
    const auto start = g_current_address ? g_current_address : g_database->image().entry_point;
    std::wostringstream message;
    message << L"Сессия подготовлена на адресе 0x" << std::hex << std::uppercase << start
            << L". До запуска можно выставить аргументы в регистрах, записать память и поставить breakpoint/watchpoint.";
    SetWindowTextW(g_status, message.str().c_str());
    MessageBoxW(window, message.str().c_str(), L"CPU Emulation — Ready", MB_ICONINFORMATION);
}

void emulate_current_code(HWND window, bool single_step = false, bool step_over = false, bool step_out = false) {
    if (!g_database) {
        MessageBoxW(window, L"Сначала открой PE/ELF бинарник.", L"CPU Emulation", MB_ICONINFORMATION);
        return;
    }
    const bool new_session = !g_emulator;
    const auto start = g_current_address ? g_current_address : g_database->image().entry_point;
    std::string error;
    if (new_session && !initialize_emulation_session(window)) return;

    gandon::EmulationResult result;
    if (step_out) {
        result = g_emulator->step_out(100'000, 1'000'000);
    } else if (step_over) {
        result = g_emulator->step_over(100'000, 1'000'000);
    } else {
        result = single_step ? g_emulator->step() : g_emulator->run(100'000, 1'000'000);
    }
    const bool pc_mapped = g_database->image().va_to_file_offset(result.program_counter).has_value();
    std::wostringstream report;
    report << (new_session ? L"New emulation session from " : L"Emulation session at ")
           << L"0x" << std::hex << std::uppercase << (new_session ? start : result.program_counter) << L"\r\n"
           << L"Stop: ";
    switch (result.stop) {
    case gandon::EmulationStop::Returned: report << L"RET / function returned"; break;
    case gandon::EmulationStop::Exited: report << L"guest process exited with code " << std::dec << g_emulator->exit_code(); break;
    case gandon::EmulationStop::Breakpoint: report << L"breakpoint hit"; break;
    case gandon::EmulationStop::Watchpoint: report << L"watchpoint hit: " << wide(result.error); break;
    case gandon::EmulationStop::InstructionLimit: report << L"instruction limit reached"; break;
    case gandon::EmulationStop::TimedOut: report << L"time limit reached"; break;
    case gandon::EmulationStop::MemoryFault: report << L"memory fault: " << wide(result.error); break;
    case gandon::EmulationStop::Paused: report << L"paused"; break;
    case gandon::EmulationStop::Error: report << L"emulation error: " << wide(result.error); break;
    }
    const auto append_guest_output = [&](const wchar_t* label, const std::string& output) {
        if (output.empty()) return;
        report << L"\r\n" << label << L" (" << std::dec << output.size() << L" bytes): ";
        constexpr std::size_t display_limit = 4096;
        const auto count = (std::min)(display_limit, output.size());
        for (std::size_t index = 0; index < count; ++index) {
            const auto byte = static_cast<unsigned char>(output[index]);
            if (byte == '\n') report << L"\\n";
            else if (byte == '\r') report << L"\\r";
            else if (byte == '\t') report << L"\\t";
            else if (byte >= 0x20 && byte <= 0x7e) report << static_cast<wchar_t>(byte);
            else report << L"\\x" << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<unsigned>(byte)
                        << std::dec << std::setfill(L' ');
        }
        if (output.size() > count) report << L"... (display capped)";
        report << L"\r\n";
    };
    append_guest_output(L"Guest stdout", g_emulator->standard_output());
    append_guest_output(L"Guest stderr", g_emulator->standard_error());
    report << L"\r\nInstructions executed this action: " << std::dec << result.instructions_executed
           << L"\r\nTrace entries: " << g_emulator->trace().size()
           << L"\r\nPC: 0x" << std::hex << std::uppercase << result.program_counter << L"\r\n";
    const bool arm64 = g_database->image().architecture == gandon::MachineArchitecture::ARM64;
    const auto register_names = arm64
        ? std::vector<const char*>{"X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7", "X8", "X9", "X10", "X11", "X12", "X13", "X14", "X15", "X16", "X17", "X18", "X19", "X20", "X21", "X22", "X23", "X24", "X25", "X26", "X27", "X28", "X29", "X30", "SP", "PC", "NZCV"}
        : (g_database->image().is_64_bit
            ? std::vector<const char*>{"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "EFLAGS"}
            : std::vector<const char*>{"EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP", "EFLAGS"});
    for (const auto* name : register_names) {
        std::uint64_t value{};
        if (g_emulator->register_value(name, value, error))
            report << name << L" = 0x" << std::hex << std::uppercase << value << L"\r\n";
    }
    report << L"\r\nRecent trace (up to 120):\r\n";
    const auto trace_start = g_emulator->trace().size() > 120 ? g_emulator->trace().size() - 120 : 0;
    const auto shown = g_emulator->trace().size() - trace_start;
    const auto& register_deltas = g_emulator->register_deltas();
    auto delta_cursor = static_cast<std::size_t>(std::lower_bound(register_deltas.begin(), register_deltas.end(), trace_start,
        [](const gandon::EmulationRegisterDelta& delta, std::size_t index) { return delta.trace_index < index; }) - register_deltas.begin());
    static constexpr const wchar_t* registers64[]{L"RAX", L"RBX", L"RCX", L"RDX", L"RSI", L"RDI", L"RBP", L"RSP",
        L"R8", L"R9", L"R10", L"R11", L"R12", L"R13", L"R14", L"R15", L"EFLAGS"};
    static constexpr const wchar_t* registers32[]{L"EAX", L"EBX", L"ECX", L"EDX", L"ESI", L"EDI", L"EBP", L"ESP",
        L"R8", L"R9", L"R10", L"R11", L"R12", L"R13", L"R14", L"R15", L"EFLAGS"};
    static constexpr const wchar_t* registers_arm64[]{L"X0", L"X1", L"X2", L"X3", L"X4", L"X5", L"X6", L"X7", L"X8", L"X9", L"X10", L"X11", L"X12", L"X13", L"X14", L"X15", L"X16", L"X17", L"X18", L"X19", L"X20", L"X21", L"X22", L"X23", L"X24", L"X25", L"X26", L"X27", L"X28", L"X29", L"X30", L"SP", L"PC", L"NZCV"};
    for (std::size_t index = trace_start; index < g_emulator->trace().size(); ++index) {
        const auto& entry = g_emulator->trace()[index];
        const auto address = entry.address;
        report << L"0x" << std::hex << std::uppercase << address;
        if (entry.byte_count) {
            report << L"  [";
            for (std::size_t byte = 0; byte < entry.byte_count; ++byte)
                report << std::setfill(L'0') << std::setw(2) << std::hex << static_cast<unsigned>(entry.bytes[byte]) << L" ";
            report << L"]" << std::setfill(L' ');
        }
        const auto decoded_arm64 = arm64 ? gandon::decode_arm64_instruction(entry.bytes.data(), entry.byte_count, address) : std::optional<gandon::Instruction>{};
        const auto decoded_x86 = arm64 ? std::optional<gandon::Instruction>{} : gandon::decode_x86_instruction(
            entry.bytes.data(), entry.byte_count, address, g_database->image().is_64_bit);
        if (decoded_arm64) report << L"  " << wide(decoded_arm64->mnemonic + (decoded_arm64->operands.empty() ? "" : " " + decoded_arm64->operands));
        else if (decoded_x86) report << L"  " << wide(decoded_x86->mnemonic + (decoded_x86->operands.empty() ? "" : " " + decoded_x86->operands));
        else if (entry.byte_count) report << L"  [runtime decode unavailable]";
        if (!entry.annotation.empty()) report << L"  ; " << wide(entry.annotation);
        while (delta_cursor < register_deltas.size() && register_deltas[delta_cursor].trace_index == index) {
            const auto& delta = register_deltas[delta_cursor++];
            report << L"  ; Δ";
            std::size_t value_index = 0;
            const auto* names = arm64 ? registers_arm64 : g_database->image().is_64_bit ? registers64 : registers32;
            const auto register_count = arm64 ? std::size(registers_arm64) : std::size(registers64);
            for (std::size_t register_index = 0; register_index < register_count; ++register_index) {
                if (!(delta.changed_mask & (std::uint64_t{1} << register_index))) continue;
                report << L" " << names[register_index] << L"=";
                if (value_index < delta.value_count)
                    report << L"0x" << std::hex << std::uppercase << delta.values[value_index++];
                else
                    report << L"<not captured>";
            }
            if (delta.values_truncated) report << L" [additional register values omitted]";
        }
        report << L"\r\n";
    }
    if (trace_start || g_emulator->trace_truncated()) report << L"... older trace entries omitted ...\r\n";
    if (g_emulator->register_deltas_truncated()) report << L"... register-delta capture limit reached ...\r\n";
    report << L"\r\nRecent memory accesses (up to 40):\r\n";
    const auto& accesses = g_emulator->memory_accesses();
    const auto access_start = accesses.size() > 40 ? accesses.size() - 40 : 0;
    for (std::size_t index = access_start; index < accesses.size(); ++index) {
        const auto& access = accesses[index];
        report << L"0x" << std::hex << std::uppercase << access.instruction_address
               << (access.write ? L"  WRITE " : L"  READ  ") << access.size
               << L" byte(s) @ 0x" << access.address;
        if (access.value_captured) report << L" = 0x" << access.value;
        else report << L" = [value wider than 8 bytes / unavailable]";
        report << L"\r\n";
    }
    if (access_start || g_emulator->memory_accesses_truncated()) report << L"... older memory events omitted ...\r\n";
    report << L"\r\nEmulated call stack (return addresses, newest last):\r\n";
    const auto& call_stack = g_emulator->call_stack();
    if (g_emulator->call_stack_truncated())
        report << L"  [call stack depth exceeded 4096; older/untracked frames are omitted]\r\n";
    const auto frame_start = call_stack.size() > 64 ? call_stack.size() - 64 : 0;
    for (std::size_t index = frame_start; index < call_stack.size(); ++index)
        report << L"  [" << std::dec << index << L"] 0x" << std::hex << std::uppercase << call_stack[index] << L"\r\n";
    if (frame_start) report << L"... older frames omitted ...\r\n";
    MessageBoxW(window, report.str().c_str(), step_over ? L"CPU Emulation — Step Over" : single_step ? L"CPU Emulation — Step" : L"CPU Emulation — Run", MB_ICONINFORMATION);
    if (pc_mapped) navigate_to_address(window, result.program_counter, 1);
}

void clear_llil_state() {
    g_llil_emulator.reset();
    g_llil_program.reset();
    g_llil_status.clear();
    g_llil_memory_status.clear();
}

bool initialize_llil_emulator(std::wstring& error) {
    if (!g_llil_program) { error = L"Сначала подними функцию в LLIL."; return false; }
    auto emulator = std::make_unique<gandon::LowLevelIlEmulator>(*g_llil_program);
    if (!emulator->ready()) { error = wide(emulator->error()); return false; }
    bool memory_truncated = false;
    std::string memory_error;
    try {
        if (g_database && !emulator->map_image_sections(g_database->image(), memory_truncated, memory_error)) {
            error = wide(memory_error);
            return false;
        }
    } catch (const std::bad_alloc&) {
        error = L"Недостаточно памяти для отображения секций бинарника в LLIL.";
        return false;
    }
    std::wostringstream memory_status;
    memory_status << L"Auto-mapped " << std::dec << emulator->mapped_memory_bytes() << L" image byte(s)";
    if (memory_truncated) memory_status << L"; section data omitted at the 64 MiB limit or unavailable in the file";
    g_llil_memory_status = memory_status.str() + L".";
    std::set<std::string> registers;
    for (const auto& expression : g_llil_program->expressions)
        if (expression.operation == gandon::IlExpressionOp::Register && !expression.register_name.empty())
            registers.insert(expression.register_name);
    for (const auto& statement : g_llil_program->statements) {
        if ((statement.operation == gandon::IlStatementOp::SetRegister ||
             statement.operation == gandon::IlStatementOp::PopRegister) && !statement.register_name.empty())
            registers.insert(statement.register_name);
        if (statement.operation == gandon::IlStatementOp::Push ||
            statement.operation == gandon::IlStatementOp::PopRegister)
            registers.insert("rsp");
    }
    std::string register_error;
    for (const auto& name : registers) {
        if (!emulator->set_register(name, 0, register_error)) {
            error = wide(register_error);
            return false;
        }
    }
    if (registers.contains("rsp") && !emulator->set_register("rsp", 0x00007FFF00001000ull, register_error)) {
        error = wide(register_error);
        return false;
    }
    g_llil_emulator = std::move(emulator);
    error.clear();
    return true;
}

void lift_current_function_to_llil(HWND window) {
    if (!g_database) {
        MessageBoxW(window, L"Сначала открой PE/ELF файл.", L"LLIL Emulator", MB_ICONINFORMATION);
        return;
    }
    if (g_database->image().architecture != gandon::MachineArchitecture::X64) {
        MessageBoxW(window, L"Первый LLIL-лифтер пока поддерживает только x86-64.", L"LLIL Emulator", MB_ICONINFORMATION);
        return;
    }

    std::uint64_t start = g_current_address ? g_current_address : g_database->image().entry_point;
    std::vector<gandon::Instruction> decoded;
    const std::vector<gandon::Instruction>* instructions = nullptr;
    if (const auto function = g_database->function_at(start)) {
        start = function->get().start;
        if (!function->get().instructions.empty()) instructions = &function->get().instructions;
    }
    if (!instructions) {
        decoded = gandon::decode_x64(g_database->image(), start, 256);
        instructions = &decoded;
    }
    if (instructions->empty()) {
        MessageBoxW(window, L"Не удалось декодировать инструкции по выбранному адресу.", L"LLIL Emulator", MB_ICONWARNING);
        return;
    }
    if (instructions->size() > 50000) {
        MessageBoxW(window, L"Функция содержит больше 50 000 инструкций. Подними LLIL с более узкого участка.",
                    L"LLIL Emulator", MB_ICONWARNING);
        return;
    }

    clear_llil_state();
    std::string lift_error;
    try {
        g_llil_program = gandon::lift_x64_to_low_level_il(*instructions, lift_error);
    } catch (const std::bad_alloc&) {
        lift_error = "Not enough memory while lifting this function to LLIL.";
    } catch (const std::exception& exception) {
        lift_error = exception.what();
    }
    if (!g_llil_program) {
        g_llil_status = L"Lift failed: " + wide(lift_error);
        SetWindowTextW(g_status, g_llil_status.c_str());
        select_view(window, 14);
        MessageBoxW(window, g_llil_status.c_str(), L"LLIL Lift", MB_ICONWARNING);
        return;
    }

    std::wstring initialize_error;
    if (!initialize_llil_emulator(initialize_error)) {
        clear_llil_state();
        MessageBoxW(window, initialize_error.c_str(), L"LLIL Emulator", MB_ICONERROR);
        return;
    }
    g_llil_status = L"Lifted " + std::to_wstring(instructions->size()) + L" instruction(s) from 0x";
    {
        std::wostringstream address;
        address << std::hex << std::uppercase << start;
        g_llil_status += address.str() + L". Other registers start at zero; RSP uses a synthetic stack. Set function arguments before running. " + g_llil_memory_status;
    }
    select_view(window, 14);
    SetWindowTextW(g_status, g_llil_status.c_str());
}

void execute_llil(HWND window, bool single_step) {
    if (!g_llil_emulator) {
        if (!g_llil_program) lift_current_function_to_llil(window);
        if (!g_llil_emulator) return;
    }
    const auto result = single_step ? g_llil_emulator->step() : g_llil_emulator->run(100'000);
    std::wostringstream status;
    if (result.stop == gandon::IlEmulationStop::Paused)
        status << L"LLIL paused at statement " << std::dec << g_llil_emulator->statement_index();
    else if (result.stop == gandon::IlEmulationStop::Returned)
        status << L"LLIL returned after " << std::dec << result.statements_executed << L" statement(s)";
    else if (result.stop == gandon::IlEmulationStop::InstructionLimit)
        status << L"LLIL statement limit reached (" << std::dec << result.statements_executed << L")";
    else
        status << L"LLIL error: " << wide(result.error);
    if (result.return_value) status << L"; value=0x" << std::hex << std::uppercase << *result.return_value;
    g_llil_status = status.str();
    select_view(window, 14);
    SetWindowTextW(g_status, g_llil_status.c_str());
}

void set_llil_register(HWND window) {
    if (!g_llil_emulator) {
        MessageBoxW(window, L"Сначала подними функцию в LLIL.", L"LLIL Emulator", MB_ICONINFORMATION);
        return;
    }
    const auto register_name = prompt_text(window, L"Set LLIL Register", L"Register name (for example RDI or RAX):");
    if (!register_name || register_name->empty()) return;
    const auto value_text = prompt_text(window, L"Set LLIL Register", L"Integer value (decimal or 0x-prefixed hexadecimal):");
    if (!value_text || value_text->empty()) return;
    std::string name;
    name.reserve(register_name->size());
    for (const auto character : *register_name) {
        if (character > 0x7f) {
            MessageBoxW(window, L"Имя регистра должно быть ASCII (например, RDI или RAX).", L"LLIL Emulator", MB_ICONWARNING);
            return;
        }
        name.push_back(static_cast<char>(character));
    }
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    std::string value_ascii;
    value_ascii.reserve(value_text->size());
    for (const auto character : *value_text) {
        if (character > 0x7f) {
            MessageBoxW(window, L"Число должно содержать только ASCII-символы.", L"LLIL Emulator", MB_ICONWARNING);
            return;
        }
        value_ascii.push_back(static_cast<char>(character));
    }
    std::uint64_t value = 0;
    try {
        std::size_t parsed = 0;
        value = std::stoull(value_ascii, &parsed, 0);
        if (parsed != value_ascii.size()) throw std::invalid_argument("trailing characters");
    } catch (...) {
        MessageBoxW(window, L"Некорректное целое число.", L"LLIL Emulator", MB_ICONWARNING);
        return;
    }
    std::string error;
    if (!g_llil_emulator->set_register(name, value, error)) {
        MessageBoxW(window, wide(error).c_str(), L"LLIL Emulator", MB_ICONWARNING);
        return;
    }
    g_llil_status = L"Set " + wide(name) + L" = 0x";
    std::wostringstream value_out;
    value_out << std::hex << std::uppercase << value;
    g_llil_status += value_out.str();
    select_view(window, 14);
    SetWindowTextW(g_status, g_llil_status.c_str());
}

void write_llil_memory(HWND window) {
    if (!g_llil_emulator) {
        MessageBoxW(window, L"Сначала подними функцию в LLIL.", L"LLIL Emulator", MB_ICONINFORMATION);
        return;
    }
    const auto input = prompt_text(window, L"Set LLIL Memory", L"0xADDRESS: hex bytes (example: 0x5000: 48 69 00):");
    if (!input) return;
    const auto colon = input->find(L':');
    if (colon == std::wstring::npos) {
        MessageBoxW(window, L"Ожидается формат 0xADDRESS: HEX BYTES.", L"LLIL Emulator", MB_ICONWARNING);
        return;
    }
    try {
        const auto address_text = utf8(input->substr(0, colon));
        std::size_t parsed = 0;
        const auto address = std::stoull(address_text, &parsed, 0);
        if (parsed != address_text.size()) throw std::invalid_argument("Invalid address.");
        std::istringstream tokens(utf8(input->substr(colon + 1)));
        std::vector<std::uint8_t> bytes;
        std::string token;
        while (tokens >> token) {
            if (token.size() != 2 || token.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
                throw std::invalid_argument("Bytes must be two-digit hexadecimal values separated by spaces.");
            bytes.push_back(static_cast<std::uint8_t>(std::stoul(token, nullptr, 16)));
            if (bytes.size() > gandon::LowLevelIlEmulator::maximum_mapped_bytes)
                throw std::invalid_argument("LLIL input memory is limited to 64 MiB.");
        }
        if (bytes.empty()) throw std::invalid_argument("Enter at least one byte.");
        std::string error;
        if (!g_llil_emulator->write_memory(address, bytes.data(), bytes.size(), error)) throw std::runtime_error(error);
        std::wostringstream status;
        status << L"Wrote " << std::dec << bytes.size() << L" LLIL memory byte(s) at 0x"
               << std::hex << std::uppercase << address;
        g_llil_status = status.str();
        select_view(window, 14);
        SetWindowTextW(g_status, g_llil_status.c_str());
    } catch (const std::exception& exception) {
        MessageBoxW(window, wide(exception.what()).c_str(), L"LLIL Emulator", MB_ICONWARNING);
    }
}

void reset_llil_emulation(HWND window) {
    if (!g_llil_program) {
        lift_current_function_to_llil(window);
        return;
    }
    std::wstring error;
    if (!initialize_llil_emulator(error)) {
        MessageBoxW(window, error.c_str(), L"LLIL Emulator", MB_ICONERROR);
        return;
    }
    g_llil_status = L"LLIL reset. Other registers start at zero; RSP uses a synthetic stack. Set function arguments before running. " + g_llil_memory_status;
    select_view(window, 14);
    SetWindowTextW(g_status, g_llil_status.c_str());
}

void reset_emulation_session(HWND window) {
    g_emulator.reset();
    SetWindowTextW(g_status, L"Emulation state cleared; next run starts at the selected address.");
    MessageBoxW(window, L"Эмулятор сброшен. Следующий запуск начнётся с текущего выбранного адреса.",
                L"CPU Emulation", MB_ICONINFORMATION);
}

void toggle_emulation_breakpoint(HWND window) {
    if (!g_emulator || !g_database || !g_current_address) {
        MessageBoxW(window, L"Сначала запусти эмуляцию, затем выбери адрес инструкции.",
                    L"CPU Emulation", MB_ICONINFORMATION);
        return;
    }
    const bool remove = g_emulator->has_breakpoint(g_current_address);
    if (remove) {
        g_emulator->remove_breakpoint(g_current_address);
    } else {
        g_emulator->add_breakpoint(g_current_address);
    }
    std::wostringstream status;
    status << L"Emulation breakpoint " << (remove ? L"removed" : L"added")
           << L" at 0x" << std::hex << std::uppercase << g_current_address;
    SetWindowTextW(g_status, status.str().c_str());
}

void add_emulation_watchpoint(HWND window) {
    if (!g_emulator || !g_current_address) {
        MessageBoxW(window, L"Сначала запусти эмуляцию и выбери адрес памяти.", L"CPU Emulation", MB_ICONINFORMATION);
        return;
    }
    const auto size_text = prompt_text(window, L"Add Emulation Watchpoint", L"Range size in bytes (decimal or 0x-prefixed):", L"8");
    if (!size_text) return;
    const auto mode = prompt_text(window, L"Watchpoint Access", L"Type R, W, or RW:", L"RW");
    if (!mode) return;
    try {
        std::size_t parsed = 0;
        const auto size = std::stoull(*size_text, &parsed, 0);
        if (parsed != size_text->size() || !size) throw std::invalid_argument("invalid size");
        const auto normalized = [&] { auto value = *mode; for (auto& ch : value) ch = static_cast<wchar_t>(std::towupper(ch)); return value; }();
        const bool read = normalized == L"R" || normalized == L"RW";
        const bool write = normalized == L"W" || normalized == L"RW";
        if ((!read && !write) || !g_emulator->add_watchpoint(g_current_address, size, read, write)) {
            MessageBoxW(window, L"Неверный тип/диапазон либо достигнут лимит watchpoint’ов (256).", L"CPU Emulation", MB_ICONWARNING);
            return;
        }
        std::wostringstream status;
        status << L"Emulation watchpoint " << normalized << L" set at 0x" << std::hex << std::uppercase << g_current_address
               << L" (" << std::dec << size << L" bytes).";
        SetWindowTextW(g_status, status.str().c_str());
    } catch (...) {
        MessageBoxW(window, L"Размер должен быть положительным целым числом.", L"CPU Emulation", MB_ICONWARNING);
    }
}

void clear_emulation_watchpoints(HWND window) {
    if (!g_emulator) { MessageBoxW(window, L"Сначала запусти сессию эмуляции.", L"CPU Emulation", MB_ICONINFORMATION); return; }
    g_emulator->clear_watchpoints();
    SetWindowTextW(g_status, L"All emulation watchpoints cleared.");
}

void clear_emulation_history(HWND window) {
    if (!g_emulator) {
        MessageBoxW(window, L"Сначала запусти сессию эмуляции.", L"CPU Emulation", MB_ICONINFORMATION);
        return;
    }
    g_emulator->clear_trace();
    SetWindowTextW(g_status, L"Emulation trace, register deltas, and memory-access history cleared; buffers released.");
}

void toggle_emulation_register_deltas(HWND window) {
    if (!g_emulator) {
        MessageBoxW(window, L"Сначала запусти сессию эмуляции.", L"CPU Emulation", MB_ICONINFORMATION);
        return;
    }
    const bool enabled = !g_emulator->register_delta_capture_enabled();
    g_emulator->set_register_delta_capture(enabled);
    SetWindowTextW(g_status, enabled ? L"Emulation register-delta capture enabled (bounded)." :
                                      L"Emulation register-delta capture disabled.");
}

void edit_emulated_register(HWND window) {
    if (!g_emulator) { MessageBoxW(window, L"Сначала запусти сессию эмуляции.", L"CPU Emulation", MB_ICONINFORMATION); return; }
    const auto input = prompt_text(window, L"Set Emulated Register", L"REGISTER=value (example: RAX=0x1234):");
    if (!input) return;
    const auto equal = input->find(L'=');
    if (equal == std::wstring::npos) { MessageBoxW(window, L"Ожидается формат REGISTER=value.", L"CPU Emulation", MB_ICONWARNING); return; }
    auto name = utf8(input->substr(0, equal));
    auto value_text = utf8(input->substr(equal + 1));
    const auto trim = [](std::string& value) {
        const auto first = value.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) { value.clear(); return; }
        value = value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
    };
    trim(name); trim(value_text);
    try {
        std::size_t parsed = 0;
        const auto value = std::stoull(value_text, &parsed, 0);
        if (name.empty() || parsed != value_text.size()) throw std::invalid_argument("invalid");
        std::string error;
        if (!g_emulator->set_register(name, value, error)) throw std::runtime_error(error);
        SetWindowTextW(g_status, (wide(name) + L" updated in emulation state.").c_str());
    } catch (const std::exception& exception) {
        MessageBoxW(window, wide(exception.what()).c_str(), L"CPU Emulation", MB_ICONWARNING);
    }
}

void write_emulated_memory(HWND window) {
    if (!g_emulator) { MessageBoxW(window, L"Сначала запусти сессию эмуляции.", L"CPU Emulation", MB_ICONINFORMATION); return; }
    const auto input = prompt_text(window, L"Write Emulated Memory", L"0xADDRESS: hex bytes (example: 0x401000: 90 C3):");
    if (!input) return;
    const auto colon = input->find(L':');
    if (colon == std::wstring::npos) { MessageBoxW(window, L"Ожидается формат 0xADDRESS: HEX BYTES.", L"CPU Emulation", MB_ICONWARNING); return; }
    try {
        const auto address_text = utf8(input->substr(0, colon));
        std::size_t parsed = 0;
        const auto address = std::stoull(address_text, &parsed, 0);
        if (parsed != address_text.size()) throw std::invalid_argument("Invalid address.");
        const auto bytes_text = utf8(input->substr(colon + 1));
        std::istringstream tokens(bytes_text);
        std::vector<std::uint8_t> bytes;
        std::string token;
        while (tokens >> token) {
            if (token.size() != 2 || token.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
                throw std::invalid_argument("Bytes must be two-digit hexadecimal values separated by spaces.");
            bytes.push_back(static_cast<std::uint8_t>(std::stoul(token, nullptr, 16)));
        }
        if (bytes.empty()) throw std::invalid_argument("Enter at least one byte.");
        std::string error;
        if (!g_emulator->write_memory(address, bytes.data(), bytes.size(), error)) throw std::runtime_error(error);
        std::wostringstream status;
        status << L"Wrote " << std::dec << bytes.size() << L" emulated byte(s) at 0x" << std::hex << std::uppercase << address;
        SetWindowTextW(g_status, status.str().c_str());
    } catch (const std::exception& exception) {
        MessageBoxW(window, wide(exception.what()).c_str(), L"CPU Emulation", MB_ICONWARNING);
    }
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

// ---------------------------------------------------------------------------
// Dark menu bar / popup menus and flat dark frames (no white 3D edges)
// ---------------------------------------------------------------------------
constexpr UINT WM_UAHDRAWMENU = 0x0091, WM_UAHDRAWMENUITEM = 0x0092;
struct UAHMENU { HMENU hmenu; HDC hdc; DWORD flags; };
struct UAHMENUITEMMETRICS { DWORD cx, cy; };
struct UAHMENUITEM { int position; UAHMENUITEMMETRICS bar[2]; UAHMENUITEMMETRICS popup[4]; DWORD popup_widths[4]; DWORD update_max_widths; };
struct UAHDRAWMENUITEM { DRAWITEMSTRUCT dis; UAHMENU menu; UAHMENUITEM item; };

COLORREF dark_menu_color() { return RGB(43, 43, 43); }

void enable_dark_popup_menus() {
    if (g_light_theme) return;
    if (const auto uxtheme = LoadLibraryW(L"uxtheme.dll")) {
        using SetPreferredAppModeFn = int(WINAPI*)(int);
        using FlushMenuThemesFn = void(WINAPI*)();
        if (const auto set_mode = reinterpret_cast<SetPreferredAppModeFn>(reinterpret_cast<void*>(GetProcAddress(uxtheme, MAKEINTRESOURCEA(135))))) set_mode(2); // ForceDark
        if (const auto flush = reinterpret_cast<FlushMenuThemesFn>(reinterpret_cast<void*>(GetProcAddress(uxtheme, MAKEINTRESOURCEA(136))))) flush();
    }
}

void paint_menu_bar_line(HWND window) {
    MENUBARINFO info{sizeof(info)};
    if (!GetMenuBarInfo(window, OBJID_MENU, 0, &info)) return;
    RECT client{}, outer{}; GetClientRect(window, &client);
    MapWindowPoints(window, nullptr, reinterpret_cast<POINT*>(&client), 2);
    GetWindowRect(window, &outer); OffsetRect(&client, -outer.left, -outer.top);
    RECT line = client; line.bottom = line.top; line.top = line.top - 1;
    HDC dc = GetWindowDC(window);
    HBRUSH brush = CreateSolidBrush(dark_menu_color()); FillRect(dc, &line, brush); DeleteObject(brush);
    ReleaseDC(window, dc);
}

bool handle_dark_menu_message(HWND window, UINT message, WPARAM, LPARAM lparam, LRESULT& result) {
    if (g_light_theme) return false;
    if (message == WM_UAHDRAWMENU) {
        auto* menu = reinterpret_cast<UAHMENU*>(lparam);
        MENUBARINFO info{sizeof(info)};
        if (!GetMenuBarInfo(window, OBJID_MENU, 0, &info)) return false;
        RECT outer{}; GetWindowRect(window, &outer);
        RECT bar = info.rcBar; OffsetRect(&bar, -outer.left, -outer.top);
        HBRUSH brush = CreateSolidBrush(dark_menu_color()); FillRect(menu->hdc, &bar, brush); DeleteObject(brush);
        result = 1; return true;
    }
    if (message == WM_UAHDRAWMENUITEM) {
        auto* item = reinterpret_cast<UAHDRAWMENUITEM*>(lparam);
        wchar_t text[128]{};
        MENUITEMINFOW info{sizeof(info)}; info.fMask = MIIM_STRING; info.dwTypeData = text; info.cch = 127;
        GetMenuItemInfoW(item->menu.hmenu, static_cast<UINT>(item->item.position), TRUE, &info);
        const bool hot = (item->dis.itemState & (ODS_HOTLIGHT | ODS_SELECTED)) != 0;
        HBRUSH brush = CreateSolidBrush(hot ? RGB(72, 72, 72) : dark_menu_color());
        FillRect(item->menu.hdc, &item->dis.rcItem, brush); DeleteObject(brush);
        SetBkMode(item->menu.hdc, TRANSPARENT);
        SetTextColor(item->menu.hdc, (item->dis.itemState & ODS_GRAYED) ? RGB(120, 120, 120) : RGB(221, 221, 221));
        DWORD flags = DT_CENTER | DT_SINGLELINE | DT_VCENTER;
        if (item->dis.itemState & ODS_NOACCEL) flags |= DT_HIDEPREFIX;
        HFONT old_font = reinterpret_cast<HFONT>(SelectObject(item->menu.hdc, g_ui_font));
        DrawTextW(item->menu.hdc, text, -1, &item->dis.rcItem, flags);
        SelectObject(item->menu.hdc, old_font);
        result = 1; return true;
    }
    return false;
}

LRESULT CALLBACK dark_border_subclass(HWND window, UINT message, WPARAM wparam, LPARAM lparam, UINT_PTR, DWORD_PTR) {
    if (message == WM_NCPAINT) {
        const LRESULT result = DefSubclassProc(window, message, wparam, lparam);
        RECT rect{}; GetWindowRect(window, &rect); OffsetRect(&rect, -rect.left, -rect.top);
        HDC dc = GetWindowDC(window);
        HBRUSH brush = CreateSolidBrush(g_light_theme ? RGB(160, 160, 160) : RGB(78, 78, 78));
        FrameRect(dc, &rect, brush); DeleteObject(brush);
        ReleaseDC(window, dc);
        return result;
    }
    return DefSubclassProc(window, message, wparam, lparam);
}

void flatten_client_edges() {
    for (HWND control : {g_tree, g_view, g_minimap, g_editor, g_output}) {
        if (!control) continue;
        SetWindowLongPtrW(control, GWL_EXSTYLE, GetWindowLongPtrW(control, GWL_EXSTYLE) & ~static_cast<LONG_PTR>(WS_EX_CLIENTEDGE));
        SetWindowLongPtrW(control, GWL_STYLE, GetWindowLongPtrW(control, GWL_STYLE) | WS_BORDER);
        SetWindowPos(control, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
        SetWindowSubclass(control, dark_border_subclass, 3, 0);
    }
}

LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    {
        LRESULT menu_result = 0;
        if (handle_dark_menu_message(window, message, wparam, lparam, menu_result)) return menu_result;
    }
    if (!g_light_theme && (message == WM_NCPAINT || message == WM_NCACTIVATE)) {
        const LRESULT result = DefWindowProcW(window, message, wparam, lparam);
        paint_menu_bar_line(window);
        return result;
    }
    switch (message) {
    case WM_CREATE: {
        dock::init(window);
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
        AppendMenuW(edit, MF_STRING, ID_STRUCT_OFFSET, L"Structure Offset...\tT"); AppendMenuW(edit, MF_STRING, ID_ENUM_OPERAND, L"Enum Constant...\tM");
        AppendMenuW(edit, MF_STRING, ID_SET_PROTOTYPE, L"Function Prototype...\tY"); AppendMenuW(edit, MF_STRING, ID_TYPES_EDITOR, L"Local Types Editor...\tShift+F1");
        AppendMenuW(edit, MF_STRING, ID_NOP_BLOCK, L"NOP Current Block\tCtrl+F2"); AppendMenuW(edit, MF_STRING, ID_EDIT_INSTRUCTION, L"Edit Instruction\tCtrl+E");
        AppendMenuW(edit, MF_POPUP, reinterpret_cast<UINT_PTR>(build_patch_submenu()), L"Patch Branch / Stub");
        AppendMenuW(edit, MF_STRING, ID_UNDO_PATCH, L"Undo Patch\tCtrl+Z"); AppendMenuW(edit, MF_STRING, ID_REDO_PATCH, L"Redo Patch\tCtrl+Y");
        HMENU jump = CreatePopupMenu();
        AppendMenuW(jump, MF_STRING, ID_JUMP_ADDR, L"Jump to Address / Label...\tCtrl+G");
        AppendMenuW(jump, MF_STRING, ID_JUMP_BACK, L"Jump Back\tEsc");
        AppendMenuW(jump, MF_STRING, ID_JUMP_FORWARD, L"Jump Forward\tCtrl+Enter");
        AppendMenuW(jump, MF_STRING, ID_TOGGLE_BOOKMARK, L"Toggle Bookmark");
        AppendMenuW(jump, MF_STRING, ID_NEXT_BOOKMARK, L"Next Bookmark");
        AppendMenuW(jump, MF_STRING, ID_LIST_XREFS, L"List XREFs");
        AppendMenuW(jump, MF_STRING, ID_FIND_FUNCTION, L"Find Function...	Ctrl+G");
        AppendMenuW(jump, MF_STRING, ID_CALL_GRAPH, L"Call Graph");
        AppendMenuW(jump, MF_STRING, ID_PATHFINDER, L"Find Call Path...");
        HMENU tools = CreatePopupMenu();
        AppendMenuW(tools, MF_STRING, ID_DECOMPILE, L"Decompile to Pseudocode\tF5"); AppendMenuW(tools, MF_STRING, ID_SIGMAKER, L"SigMaker: Generate Gandon Signature\tCtrl+B");
        AppendMenuW(tools, MF_STRING, ID_SEARCH_SIGNATURE, L"Search Gandon Signature Pattern...\tCtrl+Shift+F"); AppendMenuW(tools, MF_STRING, ID_CALL_GRAPH, L"Call Graph");
        AppendMenuW(tools, MF_STRING, ID_MEMORY_VIEW, L"Memory View"); AppendMenuW(tools, MF_STRING, ID_MEMORY_SNAPSHOT, L"Memory Snapshot"); AppendMenuW(tools, MF_STRING, ID_MEMORY_COMPARE, L"Compare Memory Snapshot"); AppendMenuW(tools, MF_STRING, ID_WATCH_LOCALS, L"Watch / Locals"); AppendMenuW(tools, MF_STRING, ID_CALL_STACK, L"Threads / Call Stack");
        AppendMenuW(tools, MF_STRING, ID_COMPARE, L"Compare Binary..."); AppendMenuW(tools, MF_STRING, ID_DIFF_FUNCTIONS, L"Diff Functions with Binary..."); AppendMenuW(tools, MF_STRING, ID_PLUGIN_LOAD, L"Load Python Plugin..."); AppendMenuW(tools, MF_STRING, ID_PY_CONSOLE, L"Python Console"); AppendMenuW(tools, MF_STRING, ID_SEARCH, L"Search Text / Address...\tCtrl+F");
        AppendMenuW(tools, MF_STRING, ID_EXPORT_DEBUG_LOG, L"Export Debug Event Log...");
        AppendMenuW(tools, MF_STRING | MF_UNCHECKED, ID_TRACE_TOGGLE, L"Trace Debug Events");
        AppendMenuW(tools, MF_STRING, ID_EXPORT_TRACE, L"Export Trace...");
        AppendMenuW(tools, MF_STRING, ID_SEARCH_PROCESS_MEMORY, L"Search Process Memory...");
        AppendMenuW(tools, MF_STRING, ID_POINTER_SCAN, L"Pointer Scan (Live Process)...");
        AppendMenuW(tools, MF_STRING, ID_POINTER_RESCAN, L"Re-scan Pointer Chains...");
        AppendMenuW(tools, MF_STRING, ID_STRUCT_DUMP, L"Dump Live Structure...");
        AppendMenuW(tools, MF_STRING, ID_LIVE_EXPORT, L"Export Live Result...");
        AppendMenuW(tools, MF_STRING, ID_LIVE_CANCEL, L"Cancel Live Operation");
        AppendMenuW(tools, MF_STRING | MF_UNCHECKED, ID_KERNEL_BACKEND, L"Use Kernel Memory Reader (signed driver required)");
        AppendMenuW(tools, MF_STRING, ID_EMULATE_PREPARE, L"Prepare Emulation at Current Address...");
        AppendMenuW(tools, MF_STRING, ID_EMULATE, L"Run / Continue Emulation (Unicorn)...");
        AppendMenuW(tools, MF_STRING, ID_EMULATE_STEP, L"Step Emulation");
        AppendMenuW(tools, MF_STRING, ID_EMULATE_STEP_OVER, L"Step Over Call (Emulation)");
        AppendMenuW(tools, MF_STRING, ID_EMULATE_STEP_OUT, L"Step Out of Function (Emulation)");
        AppendMenuW(tools, MF_STRING, ID_EMULATE_BREAKPOINT, L"Toggle Emulation Breakpoint at Current Address");
        AppendMenuW(tools, MF_STRING, ID_EMULATE_WATCHPOINT, L"Add Emulation Watchpoint at Current Address...");
        AppendMenuW(tools, MF_STRING, ID_EMULATE_CLEAR_WATCHPOINTS, L"Clear Emulation Watchpoints");
        AppendMenuW(tools, MF_STRING, ID_EMULATE_REGISTER_DELTAS, L"Toggle Emulation Register-Delta Trace");
        AppendMenuW(tools, MF_STRING, ID_EMULATE_CLEAR_HISTORY, L"Clear Emulation Trace / Memory History");
        AppendMenuW(tools, MF_STRING, ID_EMULATE_SET_REGISTER, L"Set Emulated Register...");
        AppendMenuW(tools, MF_STRING, ID_EMULATE_WRITE_MEMORY, L"Write Emulated Memory...");
        AppendMenuW(tools, MF_STRING, ID_EMULATE_RESET, L"Reset Emulation Session");
        AppendMenuW(tools, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(tools, MF_STRING, ID_LLIL_LIFT, L"Lift Current Function to LLIL (Experimental)...");
        AppendMenuW(tools, MF_STRING, ID_LLIL_STEP, L"Step LLIL");
        AppendMenuW(tools, MF_STRING, ID_LLIL_RUN, L"Run LLIL (100,000 statement limit)");
        AppendMenuW(tools, MF_STRING, ID_LLIL_SET_REGISTER, L"Set LLIL Register...");
        AppendMenuW(tools, MF_STRING, ID_LLIL_WRITE_MEMORY, L"Set LLIL Memory...");
        AppendMenuW(tools, MF_STRING, ID_LLIL_RESET, L"Reset LLIL Emulator");
        AppendMenuW(tools, MF_STRING, ID_HIDDEN_SYMBOLS, L"Hidden Symbols...");
        AppendMenuW(tools, MF_STRING, ID_RESTORE_HIDDEN, L"Restore All Hidden Symbols");
        AppendMenuW(tools, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(tools, MF_STRING, ID_DUMP_MODULE, L"Dump Unpacked Module + Rebuild IAT...");
        AppendMenuW(tools, MF_STRING, ID_DETECT_VM, L"Detect VM Dispatcher / Flattening (current function)");
        AppendMenuW(tools, MF_STRING, ID_TRACE_VM, L"Trace VM Handlers (emulate from current address)");
        AppendMenuW(tools, MF_STRING, ID_DEVIRT_VM, L"Devirtualize VM Handlers (decompile)");
        AppendMenuW(tools, MF_STRING, ID_EMULATE_DECRYPT, L"Emulate String Decryptor (current function)");
        AppendMenuW(tools, MF_STRING, ID_ANALYZE_DOTNET, L"Analyze .NET Metadata");
        AppendMenuW(tools, MF_STRING, ID_RECOVER_RTTI, L"Recover RTTI / C++ Classes");
        AppendMenuW(tools, MF_STRING, ID_ANALYZE_DRIVER, L"Analyze Kernel Driver (IRP / IOCTL)");
        HMENU debugger = CreatePopupMenu();
        AppendMenuW(debugger, MF_STRING, ID_RUN, L"Start / Continue Process\tF9"); AppendMenuW(debugger, MF_STRING, ID_PAUSE, L"Pause Process\tF6"); AppendMenuW(debugger, MF_STRING, ID_STEP_INTO, L"Step Into\tF7"); AppendMenuW(debugger, MF_STRING, ID_STEP_OVER, L"Step Over\tF8");
        AppendMenuW(debugger, MF_STRING, ID_ANTI_DEBUG, L"Anti-anti-debug: PEB flags (reversible)");
        AppendMenuW(debugger, MF_STRING, ID_ANTIDEBUG_STATUS, L"Anti-anti-debug Status");
        AppendMenuW(debugger, MF_STRING, ID_TOGGLE_BP, L"Toggle Breakpoint\tF2"); AppendMenuW(debugger, MF_STRING, ID_COND_BP, L"Set Conditional Breakpoint..."); AppendMenuW(debugger, MF_STRING, ID_CONFIG_BP, L"Configure Breakpoint..."); AppendMenuW(debugger, MF_STRING, ID_BP_MANAGER, L"Breakpoint Manager...");
        AppendMenuW(debugger, MF_STRING, ID_HW_BP, L"Toggle Hardware Breakpoint"); AppendMenuW(debugger, MF_STRING, ID_DELETE_BP, L"Delete Selected Breakpoint\tDel"); AppendMenuW(debugger, MF_STRING, ID_STOP, L"Stop Process");
        HMENU view = CreatePopupMenu();
        AppendMenuW(view, MF_STRING, ID_TOGGLE_GRAPH_LIST, L"Switch Graph / Text Listing	Space");
        AppendMenuW(view, MF_STRING, ID_FIT_GRAPH, L"Fit Graph	Home");
        AppendMenuW(view, MF_STRING | MF_CHECKED, ID_TOGGLE_MINIMAP, L"Graph Minimap");
        AppendMenuW(view, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(view, MF_STRING, ID_VIEW_GRAPH, L"Gandon View-A (Graph)\tSpace"); AppendMenuW(view, MF_STRING, ID_VIEW_LISTING, L"Gandon Text Listing"); AppendMenuW(view, MF_STRING, ID_VIEW_PSEUDO, L"Pseudocode-A (F5)"); AppendMenuW(view, MF_STRING, ID_VIEW_DEBUGGER, L"Debugger Win32"); AppendMenuW(view, MF_STRING, ID_VIEW_HEX, L"Hex View-1");
        AppendMenuW(view, MF_STRING, ID_VIEW_LLIL, L"Experimental LLIL Emulation");
        AppendMenuW(view, MF_STRING, ID_VIEW_FUNCTIONS, L"Functions window\tShift+F3");
        dock::append_menu(view);
        AppendMenuW(view, MF_SEPARATOR, 0, nullptr); AppendMenuW(view, MF_STRING, ID_VIEW_TYPES, L"Local Types"); AppendMenuW(view, MF_STRING, ID_VIEW_IMPORTS, L"Imports"); AppendMenuW(view, MF_STRING, ID_VIEW_EXPORTS, L"Exports"); AppendMenuW(view, MF_STRING, ID_VIEW_STRINGS, L"Strings\tShift+F12"); AppendMenuW(view, MF_STRING, ID_VIEW_RESOURCES, L"Resources"); AppendMenuW(view, MF_STRING, ID_VIEW_SYMBOLS, L"Symbols / Debug Info"); AppendMenuW(view, MF_STRING, ID_VIEW_MEMORY, L"Memory Map"); AppendMenuW(view, MF_STRING, ID_VIEW_PROBLEMS, L"Problems / Events");
        HMENU help = CreatePopupMenu(); AppendMenuW(help, MF_STRING, ID_ABOUT, L"About Gandon-PRO...");
        HMENU plugins = CreatePopupMenu();
        AppendMenuW(plugins, MF_STRING, ID_PLUGIN_LOAD, L"Load Python Plugin...");
        AppendMenuW(plugins, MF_STRING, ID_PYTHON_PLUGIN_UNLOAD, L"Unload Python Plugin Actions");
        AppendMenuW(plugins, MF_STRING, ID_PLUGIN_FOLDER, L"Open Plugins Folder");
        AppendMenuW(plugins, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(plugins, MF_STRING, ID_NATIVE_PLUGIN_LOAD, L"Load Native DLL Plugins");
        g_plugins_menu = plugins;
        HMENU search_menu = CreatePopupMenu();
        AppendMenuW(search_menu, MF_STRING, ID_JUMP_ADDR, L"Jump to Address / Label...\tCtrl+G");
        AppendMenuW(search_menu, MF_STRING, ID_FIND_FUNCTION, L"Find Function...\tCtrl+Shift+G");
        AppendMenuW(search_menu, MF_STRING, ID_SEARCH_SIGNATURE, L"Signature Pattern...\tCtrl+Shift+F");
        AppendMenuW(search_menu, MF_STRING, ID_SEARCH_PROCESS_MEMORY, L"Process Memory...");
        AppendMenuW(search_menu, MF_STRING, ID_LIST_XREFS, L"List XREFs");
        HMENU options_menu = CreatePopupMenu();
        AppendMenuW(options_menu, MF_STRING, ID_HIDDEN_SYMBOLS, L"Hidden Symbols...");
        AppendMenuW(options_menu, MF_STRING, ID_RESTORE_HIDDEN, L"Restore All Hidden Symbols");
        AppendMenuW(options_menu, MF_STRING | MF_CHECKED, ID_TOGGLE_MINIMAP, L"Graph Overview");
        HMENU windows_menu = CreatePopupMenu();
        AppendMenuW(windows_menu, MF_STRING, ID_VIEW_GRAPH, L"Gandon View-A (graph)");
        AppendMenuW(windows_menu, MF_STRING, ID_VIEW_LISTING, L"Text Listing");
        AppendMenuW(windows_menu, MF_STRING, ID_VIEW_PSEUDO, L"Pseudocode-A");
        AppendMenuW(windows_menu, MF_STRING, ID_VIEW_HEX, L"Hex View-1");
        AppendMenuW(windows_menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(windows_menu, MF_STRING, ID_VIEW_IMPORTS, L"Imports");
        AppendMenuW(windows_menu, MF_STRING, ID_VIEW_EXPORTS, L"Exports");
        AppendMenuW(windows_menu, MF_STRING, ID_VIEW_STRINGS, L"Strings");
        AppendMenuW(windows_menu, MF_STRING, ID_VIEW_RESOURCES, L"Resources");
        AppendMenuW(windows_menu, MF_STRING, ID_VIEW_SYMBOLS, L"Names");
        AppendMenuW(windows_menu, MF_STRING, ID_VIEW_MEMORY, L"Segments");
        AppendMenuW(windows_menu, MF_STRING, ID_VIEW_PROBLEMS, L"Problems");
        AppendMenuW(windows_menu, MF_STRING, ID_VIEW_TYPES, L"Local Types");
        AppendMenuW(windows_menu, MF_STRING, ID_VIEW_LLIL, L"Experimental LLIL");
        AppendMenuW(windows_menu, MF_STRING, ID_VIEW_FUNCTIONS, L"Functions\tShift+F3");
        AppendMenuW(windows_menu, MF_STRING, ID_VIEW_DEBUGGER, L"Debugger");
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(file), L"File");
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(edit), L"Edit");
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(jump), L"Jump");
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(search_menu), L"Search");
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(view), L"View");
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(debugger), L"Debugger");
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(tools), L"Tools");
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(options_menu), L"Options");
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(windows_menu), L"Windows");
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(plugins), L"Plugins");
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(help), L"Help");
        SetMenu(window, menu);
        g_tree = CreateWindowExW(WS_EX_CLIENTEDGE, WC_TREEVIEWW, nullptr, WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS, 0, 0, 0, 0, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_TREE)), g_instance, nullptr);
        g_tabs = CreateWindowExW(0, WC_TABCONTROLW, nullptr, WS_CHILD | WS_VISIBLE | TCS_TABS | TCS_OWNERDRAWFIXED, 0, 0, 0, 0, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_TABS)), g_instance, nullptr);
        const wchar_t* labels[] = {L"Gandon View-A", L"Gandon Text Listing", L"Pseudocode-A", L"XREFs", L"Debugger Win32", L"Hex View-1", L"Local Types", L"Imports", L"Exports", L"Strings", L"Resources", L"Symbols / Debug Info", L"Memory Map", L"Problems / Events", L"Experimental LLIL"};
        for (const auto* label : labels) { TCITEMW item{TCIF_TEXT, 0, 0, const_cast<wchar_t*>(label), 0, 0, 0}; TabCtrl_InsertItem(g_tabs, TabCtrl_GetItemCount(g_tabs), &item); }
        g_view = CreateWindowExW(WS_EX_CLIENTEDGE, L"GandonGraphView", nullptr, WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL, 0, 0, 0, 0, window, nullptr, g_instance, nullptr);
        g_minimap = CreateWindowExW(WS_EX_CLIENTEDGE, L"GandonMiniMap", nullptr, WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, 0, 0, 0, 0, window, nullptr, g_instance, nullptr);
        g_navband = CreateWindowExW(0, L"GandonNavBand", nullptr, WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, window, nullptr, g_instance, nullptr);
        SetWindowSubclass(g_tabs, dark_background_subclass, 2, 0);
        SendMessageW(g_tabs, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), FALSE);
        TabCtrl_SetPadding(g_tabs, 14, 5);
        TreeView_SetBkColor(g_tree, THEMED_RGB(24, 27, 32)); TreeView_SetTextColor(g_tree, THEMED_RGB(215, 228, 238));
        if (LoadLibraryW(L"Msftedit.dll"))
            g_editor = CreateWindowExW(WS_EX_CLIENTEDGE, L"RICHEDIT50W", L"Open EXE file from File -> Open EXE file...", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL, 0, 0, 0, 0, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_EDITOR)), g_instance, nullptr);
        if (!g_editor)
            g_editor = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"Open EXE file from File -> Open EXE file...", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 0, 0, 0, 0, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_EDITOR)), g_instance, nullptr);
        {
            wchar_t editor_class[32] = {};
            GetClassNameW(g_editor, editor_class, 32);
            if (wcscmp(editor_class, L"RICHEDIT50W") == 0) {
                SendMessageW(g_editor, EM_SETBKGNDCOLOR, 0, THEMED_RGB(24, 27, 32));
                SendMessageW(g_editor, EM_SETTARGETDEVICE, 0, 1); // no word wrap, like IDA
                CHARFORMAT2W format{}; format.cbSize = sizeof format; format.dwMask = CFM_COLOR; format.crTextColor = THEMED_RGB(215, 228, 238);
                SendMessageW(g_editor, EM_SETCHARFORMAT, SCF_DEFAULT, reinterpret_cast<LPARAM>(&format));
            }
        }
        g_output = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"Gandon-PRO ready.\r\nOpen a binary with File -> Open EXE file...\r\n", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 0, 0, 0, 0, window, nullptr, g_instance, nullptr);
        SendMessageW(g_output, WM_SETFONT, reinterpret_cast<WPARAM>(g_code_font), TRUE);
        flatten_client_edges();
        if (!g_light_theme) {
            if (const auto uxtheme = LoadLibraryW(L"uxtheme.dll")) {
                using SetWindowThemeFn = HRESULT(WINAPI*)(HWND, LPCWSTR, LPCWSTR);
                if (const auto set_theme = reinterpret_cast<SetWindowThemeFn>(reinterpret_cast<void*>(GetProcAddress(uxtheme, "SetWindowTheme")))) {
                    for (HWND control : {g_view, g_editor, g_output, g_tree, g_tabs}) if (control) set_theme(control, L"DarkMode_Explorer", nullptr);
                }
            }
        }
        SendMessageW(g_tree, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        dock::set_content(L"navigator", g_tree); dock::set_content(L"output", g_output);
        dock::load();
        SendMessageW(g_tabs, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        SendMessageW(g_editor, WM_SETFONT, reinterpret_cast<WPARAM>(g_code_font), TRUE);
        g_status = CreateWindowExW(0, STATUSCLASSNAMEW, L"Ready", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_STATUS)), g_instance, nullptr);
        SetWindowSubclass(g_status, [](HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR) -> LRESULT {
            if (m == WM_SETTEXT && l) {
                static std::wstring last;
                const std::wstring text = reinterpret_cast<const wchar_t*>(l);
                if (!text.empty() && text != last && text != L"Ready") { last = text; py_console_log(L"status: " + text); }
            }
            return DefSubclassProc(h, m, w, l);
        }, 91, 0);
        SendMessageW(g_status, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
        g_toolbar = CreateWindowExW(0, TOOLBARCLASSNAMEW, nullptr, WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT | TBSTYLE_TOOLTIPS | CCS_NODIVIDER | CCS_NORESIZE, 0, 0, 0, 0, window, nullptr, g_instance, nullptr);
        if (g_toolbar) {
            SendMessageW(g_toolbar, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
            SendMessageW(g_toolbar, TB_SETMAXTEXTROWS, 0, 0); // tooltips only, no captions under the icons
            SetWindowSubclass(g_toolbar, dark_background_subclass, 1, 0);
            SendMessageW(g_toolbar, TB_SETIMAGELIST, 0, reinterpret_cast<LPARAM>(make_ida_toolbar_images()));
            const TBBUTTON buttons[] = {
                {0, ID_OPEN, TBSTATE_ENABLED, BTNS_BUTTON, {}, 0, reinterpret_cast<INT_PTR>(L"Open")},
                {1, ID_SAVE_DB, TBSTATE_ENABLED, BTNS_BUTTON, {}, 0, reinterpret_cast<INT_PTR>(L"Save database")},
                {0, 0, TBSTATE_ENABLED, BTNS_SEP, {}, 0, 0},
                {2, ID_JUMP_BACK, TBSTATE_ENABLED, BTNS_BUTTON, {}, 0, reinterpret_cast<INT_PTR>(L"Jump back (Esc)")},
                {3, ID_JUMP_FORWARD, TBSTATE_ENABLED, BTNS_BUTTON, {}, 0, reinterpret_cast<INT_PTR>(L"Jump forward (Ctrl+Enter)")},
                {0, 0, TBSTATE_ENABLED, BTNS_SEP, {}, 0, 0},
                {4, ID_JUMP_ADDR, TBSTATE_ENABLED, BTNS_BUTTON, {}, 0, reinterpret_cast<INT_PTR>(L"Jump to address")},
                {5, ID_DECOMPILE, TBSTATE_ENABLED, BTNS_BUTTON, {}, 0, reinterpret_cast<INT_PTR>(L"Pseudocode (F5)")},
                {0, 0, TBSTATE_ENABLED, BTNS_SEP, {}, 0, 0},
                {6, ID_TOGGLE_GRAPH_LIST, TBSTATE_ENABLED, BTNS_BUTTON, {}, 0, reinterpret_cast<INT_PTR>(L"Graph / text")},
            };
            SendMessageW(g_toolbar, TB_ADDBUTTONSW, static_cast<WPARAM>(sizeof(buttons) / sizeof(buttons[0])), reinterpret_cast<LPARAM>(buttons));
        }
        TabCtrl_SetCurSel(g_tabs, 0);
        set_editor_text();
        SetTimer(window, ID_SESSION_TIMER, 3000, nullptr);
        dock::materialise();
        return 0;
    }
    case WM_SIZE: {
        RECT client{}; GetClientRect(window, &client); SendMessageW(g_status, WM_SIZE, 0, 0); RECT status_rect{}; GetWindowRect(g_status, &status_rect); const int status_height = status_rect.bottom - status_rect.top; const int width = client.right, height = client.bottom - status_height;
        const bool dock_minimap = g_minimap_visible && TabCtrl_GetCurSel(g_tabs) == 0;
        const int minimap_width = dock_minimap ? 230 : 0;
        constexpr int toolbar_height = 28;
        if (g_toolbar) MoveWindow(g_toolbar, 0, 0, width, toolbar_height - 2, TRUE);
        {
            const int parts[] = {(std::max)(120, width - 200), (std::max)(180, width - 110), -1};
            SendMessageW(g_status, SB_SETPARTS, 3, reinterpret_cast<LPARAM>(parts));
            SendMessageW(g_status, SB_SETTEXTW, 1, reinterpret_cast<LPARAM>(L"AU: idle"));
            SendMessageW(g_status, SB_SETTEXTW, 2, reinterpret_cast<LPARAM>(L"Down"));
        }
        const RECT central = dock::layout({0, toolbar_height, width, height});
        const int cl = central.left, cr = central.right, cb = central.bottom;
        MoveWindow(g_tabs, cl + 6, 6 + toolbar_height, cr - cl - 12, 30, TRUE);
        { RECT last{}; const int n = TabCtrl_GetItemCount(g_tabs); if (n > 0 && TabCtrl_GetItemRect(g_tabs, n - 1, &last)) MoveWindow(g_tabs, cl + 6, 6 + toolbar_height, (std::min<int>)(cr - cl - 12, last.right + 1), 30, TRUE); }
        constexpr int band_height = 18, content_top = 38 + toolbar_height + band_height + 4;
        const int view_width_docked = (std::max)(120, cr - cl - 12 - minimap_width);
        const int content_height = (std::max)(40, cb - content_top - 6);
        MoveWindow(g_navband, cl + 6, 38 + toolbar_height, cr - cl - 12, band_height, TRUE);
        InvalidateRect(g_navband, nullptr, FALSE);
        MoveWindow(g_view, cl + 6, content_top, view_width_docked, content_height, TRUE);
        MoveWindow(g_editor, cl + 6, content_top, cr - cl - 12, content_height, TRUE);
        MoveWindow(g_minimap, cl + 12 + view_width_docked, content_top, minimap_width - 8, content_height, TRUE);
        ShowWindow(g_minimap, dock_minimap ? SW_SHOW : SW_HIDE);
        update_graph_scrollbars(g_view); InvalidateRect(g_minimap, nullptr, TRUE); return 0;
    }
    case WM_INITMENUPOPUP: dock::update_menu(reinterpret_cast<HMENU>(wparam)); break;
    case WM_APP + 77: if (auto* panel = reinterpret_cast<dock::Panel*>(wparam)) dock::dock_to(*panel, static_cast<dock::Area>(lparam)); return 0;
    case WM_TIMER:
        if (wparam == ID_SESSION_TIMER) save_session_backup();
        return 0;
    case WM_COMMAND: {
        const auto id = LOWORD(wparam);
        // Menu commands can be invoked while the read-only listing editor has
        // focus.  Keep the selected line as the command target instead of
        // silently reusing the previously selected address.
        if (GetFocus() == g_editor) sync_current_address_from_editor();
        if (lparam == 0) py_console_log_command(id);
        if (invoke_native_plugin_action(window, id)) return 0;
        if (invoke_python_plugin_action(window, id)) return 0;
        if (dock::command(id)) return 0;
        // Unpacking / protection analysis — handled up front to keep the large
        // else-if chain below within the compiler's block-nesting limit.
        if (id == ID_DUMP_MODULE) { dump_process_module(window); return 0; }
        if (id == ID_DETECT_VM) { detect_vm_here(window); return 0; }
        if (id == ID_TRACE_VM) { trace_vm_here(window); return 0; }
        if (id == ID_DEVIRT_VM) { devirtualize_vm_here(window); return 0; }
        if (id == ID_EMULATE_DECRYPT) { emulate_decryptor(window); return 0; }
        if (id == ID_ANALYZE_DOTNET) { analyze_dotnet_here(window); return 0; }
        if (id == ID_RECOVER_RTTI) { recover_rtti_here(window); return 0; }
        if (id == ID_ANALYZE_DRIVER) { analyze_driver_here(window); return 0; }
        // Live-memory commands use flat dispatch to avoid MSVC's nested-block limit.
        if (id == ID_POINTER_SCAN) { live_pointer_scan(window, false); return 0; }
        if (id == ID_POINTER_RESCAN) { live_pointer_scan(window, true); return 0; }
        if (id == ID_STRUCT_DUMP) { live_structure_dump(window); return 0; }
        if (id == ID_LIVE_EXPORT) { export_live_result(window); return 0; }
        if (id == ID_LIVE_CANCEL) { g_live_cancel.store(true); SetWindowTextW(g_status, L"Cancellation requested."); return 0; }
        if (id == ID_KERNEL_BACKEND) {
            g_live_kernel = !g_live_kernel;
            CheckMenuItem(GetMenu(window), ID_KERNEL_BACKEND, MF_BYCOMMAND | (g_live_kernel ? MF_CHECKED : MF_UNCHECKED));
            SetWindowTextW(g_status, g_live_kernel ? L"New live operations use the kernel reader; normal process access rights still apply." : L"New live operations use ReadProcessMemory.");
            return 0;
        }
        if (id == ID_ANTIDEBUG_STATUS) { show_antidebug_status(window); return 0; }
        if (id == ID_OPEN) open_binary(window);
        else if (id == ID_SAVE_DB) save_database(window);
        else if (id == ID_LOAD_DB) load_database(window);
        else if (id == ID_REFRESH) refresh_views(window);
        else if (id == ID_APPLY_PATCHES) apply_patches_to_file(window);
        else if (id == ID_NOP_BLOCK) nop_current_function(window);
        else if (id == ID_EDIT_INSTRUCTION) edit_instruction(window);
        else if (id == ID_INVERT_BRANCH) invert_branch(window);
        else if (id == ID_FORCE_BRANCH) force_branch(window);
        else if (id == ID_NOP_BRANCH) never_branch(window);
        else if (id == ID_STUB_RET0) stub_return(window, false);
        else if (id == ID_STUB_RET1) stub_return(window, true);
        else if (id == ID_UNDO_PATCH) undo_patch(window);
        else if (id == ID_REDO_PATCH) redo_patch(window);
        else if (id == ID_EXPORT_GRAPH) export_graph_png(window);
        else if (id == ID_EXPORT_JSON) export_analysis_json(window);
        else if (id == ID_EXPORT_BREAKPOINTS) export_breakpoints_csv(window);
        else if (id == ID_EXPORT_DEBUG_LOG) export_debug_log(window);
        else if (id == ID_COLOR_DEFAULT) set_color_tag(window, THEMED_RGB(32, 39, 47), true);
        else if (id == ID_COLOR_GREEN) set_color_tag(window, THEMED_RGB(35, 83, 64), false);
        else if (id == ID_COLOR_RED) set_color_tag(window, THEMED_RGB(94, 45, 50), false);
        else if (id == ID_COLOR_BLUE) set_color_tag(window, THEMED_RGB(37, 62, 91), false);
        else if (id == ID_SEARCH) search_binary(window);
        else if (id == ID_JUMP_ADDR) jump_to_address(window);
        else if (id == ID_JUMP_BACK) jump_back(window);
        else if (id == ID_JUMP_FORWARD) jump_forward(window);
        else if (id == ID_GRAPH_COLLAPSE) { if (g_current_address) toggle_block_collapse(g_current_address); }
        else if (id == ID_GRAPH_EXPAND_ALL) expand_all_blocks();
        else if (id == ID_GRAPH_GROUP) group_selected_nodes();
        else if (id == ID_GRAPH_UNGROUP) { if (g_current_address) ungroup_at(g_current_address); }
        else if (id == ID_GRAPH_CLEAR_SELECTION) clear_graph_selection();
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
        else if (id == ID_PATHFINDER) find_call_path(window);
        else if (id == ID_MEMORY_VIEW) show_memory_view(window);
        else if (id == ID_EMULATE_PREPARE) prepare_emulation_session(window);
        else if (id == ID_EMULATE) emulate_current_code(window);
        else if (id == ID_EMULATE_STEP) emulate_current_code(window, true);
        else if (id == ID_EMULATE_STEP_OVER) emulate_current_code(window, false, true);
        else if (id == ID_EMULATE_STEP_OUT) emulate_current_code(window, false, false, true);
        else if (id == ID_EMULATE_BREAKPOINT) toggle_emulation_breakpoint(window);
        else if (id == ID_EMULATE_WATCHPOINT) add_emulation_watchpoint(window);
        else if (id == ID_EMULATE_CLEAR_WATCHPOINTS) clear_emulation_watchpoints(window);
        else if (id == ID_EMULATE_CLEAR_HISTORY) clear_emulation_history(window);
        else if (id == ID_EMULATE_REGISTER_DELTAS) toggle_emulation_register_deltas(window);
        else if (id == ID_EMULATE_SET_REGISTER) edit_emulated_register(window);
        else if (id == ID_EMULATE_WRITE_MEMORY) write_emulated_memory(window);
        else if (id == ID_EMULATE_RESET) reset_emulation_session(window);
        else if (id == ID_LLIL_LIFT) lift_current_function_to_llil(window);
        else if (id == ID_LLIL_STEP) execute_llil(window, true);
        else if (id == ID_LLIL_RUN) execute_llil(window, false);
        else if (id == ID_LLIL_SET_REGISTER) set_llil_register(window);
        else if (id == ID_LLIL_WRITE_MEMORY) write_llil_memory(window);
        else if (id == ID_LLIL_RESET) reset_llil_emulation(window);
        else if (id == ID_MEMORY_SNAPSHOT) capture_memory_snapshot(window);
        else if (id == ID_MEMORY_COMPARE) compare_memory_snapshot(window);
        else if (id == ID_COMPARE) compare_binary(window);
        else if (id == ID_ABOUT) MessageBoxW(window, L"Gandon-PRO Native\r\nCapstone x86/x64 analysis\r\nPython plugin bridge", L"About Gandon-PRO", MB_ICONINFORMATION);
        else if (id == ID_RUN) start_debugger(window);
        else if (id == ID_PAUSE) pause_debugger(window);
        else if (id == ID_ANTI_DEBUG) toggle_hide_debugger(window);
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
        else if (id == ID_VIEW_LLIL) select_view(window, 14);
        else if (id == ID_VIEW_FUNCTIONS) functions_window(window);
        else if (id == ID_DIFF_FUNCTIONS) diff_with_binary(window);
        else if (id == ID_STRUCT_OFFSET) apply_struct_offset(window);
        else if (id == ID_ENUM_OPERAND) apply_enum_operand(window);
        else if (id == ID_SET_PROTOTYPE) set_function_prototype(window);
        else if (id == ID_TYPES_EDITOR) types_editor_window(window);
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
            AppendMenuW(context, MF_POPUP, reinterpret_cast<UINT_PTR>(build_patch_submenu()), L"Patch");
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
        } else if (wparam == 2) { SetWindowTextW(g_status, L"Debug process initialized."); if (g_database && TabCtrl_GetCurSel(g_tabs) == 12) set_editor_text(); }
        else if (wparam == 3) { wchar_t text[64]{}; swprintf_s(text, L"Debug process exited: %llu", static_cast<unsigned long long>(lparam)); SetWindowTextW(g_status, text); }
        else if (wparam == 4) { SetWindowTextW(g_status, L"Debug process stopped."); if (g_database && TabCtrl_GetCurSel(g_tabs) == 12) set_editor_text(); }
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
    case WM_APPCOMMAND: {
        // Mouse back/forward (X1/X2) buttons bubble up here from any child view.
        const int cmd = GET_APPCOMMAND_LPARAM(lparam);
        if (cmd == APPCOMMAND_BROWSER_BACKWARD) { jump_back(window); return TRUE; }
        if (cmd == APPCOMMAND_BROWSER_FORWARD) { jump_forward(window); return TRUE; }
        return DefWindowProcW(window, message, wparam, lparam);
    }
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
            HBRUSH fill = CreateSolidBrush(active ? THEMED_RGB(30, 34, 40) : THEMED_RGB(24, 27, 32));
            FillRect(draw->hDC, &draw->rcItem, fill); DeleteObject(fill);
            if (active) {
                RECT underline = draw->rcItem; underline.top = underline.bottom - 2;
                HBRUSH accent = CreateSolidBrush(THEMED_RGB(0, 122, 204)); FillRect(draw->hDC, &underline, accent); DeleteObject(accent);
            }
            SetBkMode(draw->hDC, TRANSPARENT); SetTextColor(draw->hDC, active ? THEMED_RGB(225, 235, 242) : THEMED_RGB(155, 170, 184));
            HFONT old_font = reinterpret_cast<HFONT>(SelectObject(draw->hDC, g_ui_font));
            RECT text = draw->rcItem; text.left += 9; DrawTextW(draw->hDC, label, -1, &text, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX);
            SelectObject(draw->hDC, old_font);
            return TRUE;
        }
        break;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: { auto dc = reinterpret_cast<HDC>(wparam); SetTextColor(dc, THEMED_RGB(215, 228, 238)); SetBkColor(dc, THEMED_RGB(24, 27, 32)); return reinterpret_cast<LRESULT>(g_panel); }
    case WM_NOTIFY: {
        auto* header = reinterpret_cast<LPNMHDR>(lparam);
        if (header->idFrom == ID_TREE && header->code == TVN_KEYDOWN) {
            const auto* key = reinterpret_cast<const NMTVKEYDOWN*>(lparam);
            if (key->wVKey == VK_F2) {
                if (const auto record = selected_tree_import()) toggle_import_disable(window, record->iat_va);
                return 0;
            }
        }
        if (header->idFrom == ID_TREE && header->code == TVN_ITEMEXPANDINGW && g_database) {
            const auto* change = reinterpret_cast<const NMTREEVIEWW*>(lparam);
            if (change->action & TVE_EXPAND) {
                const auto range = g_lazy_function_ranges.find(change->itemNew.hItem);
                if (range != g_lazy_function_ranges.end()) {
                    const auto [begin, end] = range->second;
                    g_lazy_function_ranges.erase(range);
                    for (auto child = TreeView_GetChild(g_tree, change->itemNew.hItem); child;) {
                        const auto next = TreeView_GetNextSibling(g_tree, child);
                        TreeView_DeleteItem(g_tree, child);
                        child = next;
                    }
                    const auto& discovered_functions = g_database->functions();
                    TVINSERTSTRUCTW insert{};
                    insert.hParent = change->itemNew.hItem;
                    insert.item.mask = TVIF_TEXT | TVIF_PARAM;
                    for (std::size_t index = begin; index < end; ++index) {
                        const auto& function = discovered_functions[index];
                        if (g_hidden_functions.contains(function.start)) continue;
                        auto name = g_custom_labels.contains(function.start) ? g_custom_labels[function.start] : wide(function.name);
                        insert.item.pszText = name.data();
                        insert.item.lParam = static_cast<LPARAM>(function.start);
                        TreeView_InsertItem(g_tree, &insert);
                    }
                }
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
            if (draw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) { draw->clrText = THEMED_RGB(215, 228, 238); draw->clrTextBk = THEMED_RGB(30, 34, 40); return CDRF_DODEFAULT; }
        }
        if (header->idFrom == ID_TABS && header->code == NM_CUSTOMDRAW) {
            auto* draw = reinterpret_cast<LPNMCUSTOMDRAW>(lparam);
            if (draw->dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (draw->dwDrawStage == CDDS_ITEMPREPAINT) { SetTextColor(draw->hdc, THEMED_RGB(215, 228, 238)); SetBkColor(draw->hdc, THEMED_RGB(30, 34, 40)); return CDRF_DODEFAULT; }
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
            SetBkMode(dc, TRANSPARENT); SetTextColor(dc, THEMED_RGB(170, 239, 207));
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
                    HBRUSH fill = CreateSolidBrush(THEMED_RGB(32, 39, 47)); FillRect(dc, &box, fill); DeleteObject(fill);
                    HPEN pen = CreatePen(PS_SOLID, 1, THEMED_RGB(62, 78, 91)); HGDIOBJ old_pen = SelectObject(dc, pen); HGDIOBJ old_brush = SelectObject(dc, GetStockObject(NULL_BRUSH)); Rectangle(dc, box.left, box.top, box.right, box.bottom); SelectObject(dc, old_brush); SelectObject(dc, old_pen); DeleteObject(pen);
                    const auto& function = g_database->functions()[i]; auto name = g_custom_labels.contains(function.start) ? g_custom_labels[function.start] : wide(function.name); TextOutW(dc, x + 12, y + 12, name.c_str(), static_cast<int>(name.size()));
                    wchar_t address[40]{}; swprintf_s(address, L"0x%llX", static_cast<unsigned long long>(function.start)); SetTextColor(dc, THEMED_RGB(125, 191, 231)); TextOutW(dc, x + 12, y + 40, address, static_cast<int>(wcslen(address))); SetTextColor(dc, THEMED_RGB(170, 239, 207));
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
                    HPEN edge = CreatePen(PS_SOLID, 2, xref.kind == "call" ? THEMED_RGB(54, 157, 220) : THEMED_RGB(231, 76, 60));
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
                    HBRUSH fill = CreateSolidBrush(THEMED_RGB(32, 39, 47)); FillRect(dc, &box, fill); DeleteObject(fill);
                    HPEN pen = CreatePen(PS_SOLID, 1, THEMED_RGB(62, 78, 91)); HGDIOBJ old_pen = SelectObject(dc, pen); HGDIOBJ old_brush = SelectObject(dc, GetStockObject(NULL_BRUSH)); Rectangle(dc, box.left, box.top, box.right, box.bottom); SelectObject(dc, old_brush); SelectObject(dc, old_pen); DeleteObject(pen);
                    const auto& function = g_database->functions()[i];
                    auto name = g_custom_labels.contains(function.start) ? g_custom_labels[function.start] : wide(function.name); SetTextColor(dc, THEMED_RGB(170, 239, 207)); TextOutW(dc, x + 12, y + 12, name.c_str(), static_cast<int>(name.size()));
                    wchar_t address[40]{}; swprintf_s(address, L"0x%llX", static_cast<unsigned long long>(function.start)); SetTextColor(dc, THEMED_RGB(125, 191, 231)); TextOutW(dc, x + 12, y + 40, address, static_cast<int>(wcslen(address)));
                    if (g_custom_comments.contains(function.start) && !g_custom_comments[function.start].empty()) { SetTextColor(dc, THEMED_RGB(180, 180, 180)); TextOutW(dc, x + 12, y + 62, g_custom_comments[function.start].c_str(), static_cast<int>(g_custom_comments[function.start].size())); }
                }
                RECT mini{client.right - 225, client.bottom - 185, client.right - 24, client.bottom - 24};
                HBRUSH mini_fill = CreateSolidBrush(THEMED_RGB(18, 29, 38)); FillRect(dc, &mini, mini_fill); DeleteObject(mini_fill);
                HPEN mini_pen = CreatePen(PS_SOLID, 1, THEMED_RGB(62, 78, 91)); HGDIOBJ old_mini_pen = SelectObject(dc, mini_pen); HGDIOBJ old_mini_brush = SelectObject(dc, GetStockObject(NULL_BRUSH)); Rectangle(dc, mini.left, mini.top, mini.right, mini.bottom); SelectObject(dc, old_mini_brush); SelectObject(dc, old_mini_pen); DeleteObject(mini_pen);
                for (std::size_t i = 0; i < count; ++i) {
                    const int mx = mini.left + 10 + static_cast<int>((i % 3) * 58);
                    const int my = mini.top + 10 + static_cast<int>((i / 3) * 24);
                    RECT dot{mx, my, mx + 40, my + 11};
                    HBRUSH dot_fill = CreateSolidBrush(i == 0 ? THEMED_RGB(43, 104, 139) : THEMED_RGB(48, 48, 52)); FillRect(dc, &dot, dot_fill); DeleteObject(dot_fill);
                }
            }
            SelectObject(dc, old_font);
        }
        EndPaint(window, &paint); return 0;
    }
    case WM_ERASEBKGND: { RECT rect{}; GetClientRect(window, &rect); FillRect(reinterpret_cast<HDC>(wparam), &rect, g_background); return 1; }
    case WM_CLOSE: {
        if (g_live_busy) { g_live_cancel.store(true); SetWindowTextW(g_status, L"Cancelling live operation. Close again after it completes."); return 0; }
        if (g_live_worker.joinable()) g_live_worker.join();
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
        dock::save();
        DestroyWindow(window); return 0;
    }
    case WM_DESTROY: KillTimer(window, ID_SESSION_TIMER); PostQuitMessage(0); return 0;
    case WM_LIVE_RESULT: {
        std::unique_ptr<LiveTaskResult> result(reinterpret_cast<LiveTaskResult*>(lparam));
        if (g_live_worker.joinable()) g_live_worker.join();
        g_live_busy = false;
        if (result) {
            g_live_last_pid = result->pid; g_live_last_report = result->report;
            if (result->scan) { g_live_last_scan = std::move(result->pointers); g_live_last_structure = {}; }
            else g_live_last_structure = std::move(result->structure);
            g_listing = wide(g_live_last_report); select_view(window, 1);
            SetWindowTextW(g_status, g_live_cancel.load() ? L"Live operation cancelled; partial result shown." : L"Live operation completed; Tools > Export Live Result saves it.");
        }
        return 0;
    }
    case WM_RUN_ON_UI: {
        // A plugin's background thread (e.g. the MCP server plugin) marshals a
        // job onto the UI thread this way: SendMessageW blocks the caller until
        // this handler returns, so the job can safely touch g_database and every
        // other UI-thread-owned global without its own locking.
        auto* job = reinterpret_cast<std::function<void()>*>(lparam);
        if (job && *job) (*job)();
        return 0;
    }
    }
    return DefWindowProcW(window, message, wparam, lparam);
}
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR command_line, int show_command) {
    if (const auto user32 = GetModuleHandleW(L"user32.dll")) {
        using SetDpiContextFn = BOOL(WINAPI*)(HANDLE);
        if (const auto fn = reinterpret_cast<SetDpiContextFn>(reinterpret_cast<void*>(GetProcAddress(user32, "SetProcessDpiAwarenessContext"))))
            fn(reinterpret_cast<HANDLE>(-4)); // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
    }
    std::wstring raw_command_line = command_line ? command_line : L"";
    if (const auto flag = raw_command_line.find(L"--light"); flag != std::wstring::npos) {
        g_light_theme = true;
        raw_command_line.erase(flag, 7);
        command_line = raw_command_line.data();
    }
    g_instance = instance; enable_dark_popup_menus(); INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_TREEVIEW_CLASSES | ICC_TAB_CLASSES | ICC_BAR_CLASSES}; InitCommonControlsEx(&controls);
    g_background = CreateSolidBrush(THEMED_RGB(30, 34, 40)); g_panel = CreateSolidBrush(THEMED_RGB(24, 27, 32));
    g_ui_font = CreateFontW(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    const auto plugin_font = python_plugin_font();
    const wchar_t* code_font_name = plugin_font.empty() ? L"Consolas" : plugin_font.c_str();
    g_code_font = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_DONTCARE, code_font_name);
    g_code_font_owned = true;
    const wchar_t class_name[] = L"GandonProNativeWindow"; WNDCLASSW window_class{}; window_class.hInstance = instance; window_class.lpfnWndProc = window_proc; window_class.lpszClassName = class_name; window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW); window_class.hbrBackground = g_background;
    window_class.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(1)); RegisterClassW(&window_class);
    if (HICON small_icon = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(1), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0))) g_small_icon = small_icon;
    WNDCLASSW graph_class{}; graph_class.hInstance = instance; graph_class.lpfnWndProc = graph_proc; graph_class.lpszClassName = L"GandonGraphView"; graph_class.hCursor = LoadCursorW(nullptr, IDC_ARROW); graph_class.hbrBackground = g_panel; graph_class.style = CS_DBLCLKS; RegisterClassW(&graph_class);
    WNDCLASSW navband_class{}; navband_class.hInstance = instance; navband_class.lpfnWndProc = navband_proc; navband_class.lpszClassName = L"GandonNavBand"; navband_class.hCursor = LoadCursorW(nullptr, IDC_HAND); RegisterClassW(&navband_class);
    WNDCLASSW minimap_class{}; minimap_class.hInstance = instance; minimap_class.lpfnWndProc = minimap_proc; minimap_class.lpszClassName = L"GandonMiniMap"; minimap_class.hCursor = LoadCursorW(nullptr, IDC_CROSS); minimap_class.hbrBackground = g_panel; RegisterClassW(&minimap_class);
    HWND window = CreateWindowExW(0, class_name, L"Gandon-PRO - Native Disassembler [ui build 32]", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_CLIPSIBLINGS, CW_USEDEFAULT, CW_USEDEFAULT, 1400, 850, nullptr, nullptr, instance, nullptr); if (!window) return 1;
    g_main_window = window;
    if (g_small_icon) SendMessageW(window, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(g_small_icon));
    const BOOL dark = g_light_theme ? FALSE : TRUE;
    DwmSetWindowAttribute(window, 20, &dark, sizeof(dark));
    const COLORREF caption = THEMED_RGB(30, 34, 40);
    DwmSetWindowAttribute(window, 35, &caption, sizeof(caption));
    ShowWindow(window, show_command); UpdateWindow(window);
    g_live_kernel = gandon::offer_memory_driver_setup(window);
    CheckMenuItem(GetMenu(window), ID_KERNEL_BACKEND, MF_BYCOMMAND | (g_live_kernel ? MF_CHECKED : MF_UNCHECKED));
    SetWindowTextW(g_status, g_live_kernel ? L"Kernel memory reader connected." : L"Using ReadProcessMemory; driver is optional.");
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
        {FVIRTKEY | FCONTROL, 'G', ID_JUMP_ADDR},
        {FVIRTKEY | FCONTROL | FSHIFT, 'G', ID_FIND_FUNCTION},
        {FVIRTKEY | FCONTROL, 'E', ID_EDIT_INSTRUCTION},
        {FVIRTKEY, VK_OEM_1, ID_ADD_COMMENT},
        {FVIRTKEY, 'N', ID_RENAME_LABEL},
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
        {FVIRTKEY, VK_ESCAPE, ID_JUMP_BACK},
        {FVIRTKEY | FCONTROL, VK_RETURN, ID_JUMP_FORWARD},
        {FVIRTKEY | FSHIFT, VK_F12, ID_VIEW_STRINGS},
        {FVIRTKEY | FSHIFT, VK_F3, ID_VIEW_FUNCTIONS},
        {FVIRTKEY, 'T', ID_STRUCT_OFFSET},
        {FVIRTKEY, 'M', ID_ENUM_OPERAND},
        {FVIRTKEY, 'Y', ID_SET_PROTOTYPE},
        {FVIRTKEY | FSHIFT, VK_F1, ID_TYPES_EDITOR},
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
