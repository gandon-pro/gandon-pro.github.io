// Gandon-PRO MCP plugin: an in-process MCP server, the same idea as
// ida-multi-mcp's IDA-side plugin - it lives inside the already-running,
// already-analyzed GUI process and exposes the LIVE database (the user's
// renames, comments, patches, auto-analysis) over the network, rather than
// re-loading the binary from scratch per call the way the standalone
// gandon_mcp_backend.exe / gandon_mcp_server.py bridge does.
//
// Load it from the running GUI: Tools -> Plugins -> Load Native DLL Plugins
// (it must sit next to gandon_gui.exe). It starts listening immediately;
// Tools -> Plugins also gets an "MCP Server Status" action that reports the
// URL and whether a client has connected yet.
//
// Protocol: MCP 2024-11-05, Streamable HTTP transport (one JSON-RPC object
// per POST to /mcp; GET /health is a plain liveness check). No external
// dependencies: hand-rolled HTTP parsing, JSON parsing and JSON writing,
// winsock2 sockets.
#include "gandon/plugin_api.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace {

constexpr const char* SERVER_NAME = "gandon-pro-plugin";
constexpr const char* SERVER_VERSION = "1.1.0";
constexpr const char* PROTOCOL_VERSION = "2024-11-05";
constexpr int DEFAULT_PORT = 8766; // different default from the standalone server (8765), so both can run together

const GandonPluginHost* g_host = nullptr;
std::atomic<bool> g_running{false};
std::thread g_server_thread;
SOCKET g_listen_socket = INVALID_SOCKET;
std::string g_token;      // empty = no auth required (127.0.0.1-only is the default bind)
std::string g_bind_host = "127.0.0.1";
int g_port = DEFAULT_PORT;
std::atomic<unsigned> g_requests_served{0};

// Background auto-analysis: run_auto_analysis() on the host can take minutes
// on a large binary. Running it on the request-handling thread would hold up
// that one HTTP connection for the whole run (tolerable) AND, since the
// server accepts one connection at a time, every other client until it's
// done. `gandon_auto_analysis(async=true)` instead hands the call to its own
// detached thread and returns immediately; gandon_analysis_status/_wait poll
// it, the same shape as ida-multi-mcp's analysis_status/analysis_wait.
std::mutex g_analysis_mutex;
std::atomic<bool> g_analysis_running{false};
std::string g_analysis_summary;    // guarded by g_analysis_mutex
bool g_analysis_has_result{false}; // guarded by g_analysis_mutex
std::thread g_analysis_thread;

// ---------------------------------------------------------------------------
// Minimal JSON value type + parser (just enough for JSON-RPC requests: an
// object of strings/numbers/bools/null/nested objects/arrays).
// ---------------------------------------------------------------------------

struct JsonValue {
    enum class Type { Null, Bool, Number, String, Array, Object } type{Type::Null};
    bool boolean{false};
    double number{0};
    std::string str;
    std::vector<JsonValue> array;
    std::vector<std::pair<std::string, JsonValue>> object;

    bool is_string() const { return type == Type::String; }
    bool is_object() const { return type == Type::Object; }
    bool is_null() const { return type == Type::Null; }

    const JsonValue* find(const std::string& key) const {
        for (const auto& [k, v] : object) if (k == key) return &v;
        return nullptr;
    }
    std::string as_string(const std::string& fallback = {}) const { return type == Type::String ? str : fallback; }
    long long as_int(long long fallback = 0) const { return type == Type::Number ? static_cast<long long>(number) : fallback; }
    bool as_bool(bool fallback = false) const { return type == Type::Bool ? boolean : fallback; }
};

class JsonParser {
public:
    explicit JsonParser(const std::string& text) : text_(text) {}

    bool parse(JsonValue& out) {
        skip_ws();
        if (!parse_value(out)) return false;
        skip_ws();
        return true; // trailing content is ignored (tolerant of a stray newline)
    }

private:
    const std::string& text_;
    std::size_t pos_{0};

    char peek() const { return pos_ < text_.size() ? text_[pos_] : '\0'; }
    char take() { return pos_ < text_.size() ? text_[pos_++] : '\0'; }
    void skip_ws() { while (pos_ < text_.size() && (text_[pos_] == ' ' || text_[pos_] == '\t' || text_[pos_] == '\r' || text_[pos_] == '\n')) ++pos_; }
    bool consume(char expected) { skip_ws(); if (peek() != expected) return false; ++pos_; return true; }

    bool parse_value(JsonValue& out) {
        skip_ws();
        switch (peek()) {
        case '{': return parse_object(out);
        case '[': return parse_array(out);
        case '"': return parse_string_value(out);
        case 't': return consume_literal("true") && (out.type = JsonValue::Type::Bool, out.boolean = true, true);
        case 'f': return consume_literal("false") && (out.type = JsonValue::Type::Bool, out.boolean = false, true);
        case 'n': return consume_literal("null") && (out.type = JsonValue::Type::Null, true);
        default: return parse_number(out);
        }
    }

    bool consume_literal(const char* literal) {
        const auto length = std::strlen(literal);
        if (text_.compare(pos_, length, literal) != 0) return false;
        pos_ += length;
        return true;
    }

    bool parse_object(JsonValue& out) {
        if (!consume('{')) return false;
        out.type = JsonValue::Type::Object;
        skip_ws();
        if (peek() == '}') { ++pos_; return true; }
        while (true) {
            skip_ws();
            JsonValue key;
            if (!parse_string_value(key)) return false;
            if (!consume(':')) return false;
            JsonValue value;
            if (!parse_value(value)) return false;
            out.object.emplace_back(key.str, std::move(value));
            skip_ws();
            if (peek() == ',') { ++pos_; continue; }
            if (peek() == '}') { ++pos_; break; }
            return false;
        }
        return true;
    }

    bool parse_array(JsonValue& out) {
        if (!consume('[')) return false;
        out.type = JsonValue::Type::Array;
        skip_ws();
        if (peek() == ']') { ++pos_; return true; }
        while (true) {
            JsonValue value;
            if (!parse_value(value)) return false;
            out.array.push_back(std::move(value));
            skip_ws();
            if (peek() == ',') { ++pos_; continue; }
            if (peek() == ']') { ++pos_; break; }
            return false;
        }
        return true;
    }

    bool parse_string_value(JsonValue& out) {
        if (!consume('"')) return false;
        std::string value;
        while (true) {
            if (pos_ >= text_.size()) return false;
            const char ch = text_[pos_++];
            if (ch == '"') break;
            if (ch == '\\') {
                if (pos_ >= text_.size()) return false;
                const char esc = text_[pos_++];
                switch (esc) {
                case '"': value += '"'; break;
                case '\\': value += '\\'; break;
                case '/': value += '/'; break;
                case 'n': value += '\n'; break;
                case 't': value += '\t'; break;
                case 'r': value += '\r'; break;
                case 'b': value += '\b'; break;
                case 'f': value += '\f'; break;
                case 'u': {
                    if (pos_ + 4 > text_.size()) return false;
                    const auto code = static_cast<unsigned>(std::strtoul(text_.substr(pos_, 4).c_str(), nullptr, 16));
                    pos_ += 4;
                    // Encode as UTF-8 (surrogate pairs are not handled; fine for our tool arguments).
                    if (code < 0x80) value += static_cast<char>(code);
                    else if (code < 0x800) { value += static_cast<char>(0xC0 | (code >> 6)); value += static_cast<char>(0x80 | (code & 0x3F)); }
                    else { value += static_cast<char>(0xE0 | (code >> 12)); value += static_cast<char>(0x80 | ((code >> 6) & 0x3F)); value += static_cast<char>(0x80 | (code & 0x3F)); }
                    break;
                }
                default: return false;
                }
            } else value += ch;
        }
        out.type = JsonValue::Type::String;
        out.str = std::move(value);
        return true;
    }

    bool parse_number(JsonValue& out) {
        const auto start = pos_;
        if (peek() == '-') ++pos_;
        while (std::isdigit(static_cast<unsigned char>(peek()))) ++pos_;
        if (peek() == '.') { ++pos_; while (std::isdigit(static_cast<unsigned char>(peek()))) ++pos_; }
        if (peek() == 'e' || peek() == 'E') { ++pos_; if (peek() == '+' || peek() == '-') ++pos_; while (std::isdigit(static_cast<unsigned char>(peek()))) ++pos_; }
        if (pos_ == start) return false;
        out.type = JsonValue::Type::Number;
        out.number = std::strtod(text_.substr(start, pos_ - start).c_str(), nullptr);
        return true;
    }
};

std::string json_escape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (unsigned char ch : value) {
        switch (ch) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (ch < 0x20) { char buf[8]; std::snprintf(buf, sizeof(buf), "\\u%04x", ch); out += buf; }
            else out += static_cast<char>(ch);
        }
    }
    return out;
}

std::string json_number_literal(double value) {
    if (value == static_cast<long long>(value)) return std::to_string(static_cast<long long>(value));
    std::ostringstream out; out << value; return out.str();
}

// Re-serializes a parsed id (number, string or null) back to JSON for the response envelope.
std::string id_literal(const JsonValue* id) {
    if (!id || id->is_null()) return "null";
    if (id->type == JsonValue::Type::String) return "\"" + json_escape(id->str) + "\"";
    if (id->type == JsonValue::Type::Number) return json_number_literal(id->number);
    return "null";
}

std::string hex_u64(unsigned long long value) { std::ostringstream out; out << "0x" << std::hex << value; return out.str(); }

unsigned long long parse_u64(const std::string& text) {
    try { return std::stoull(text, nullptr, 0); } catch (...) { return 0; }
}

struct ToolError : std::runtime_error { using std::runtime_error::runtime_error; };

uint64_t resolve_or_throw(const std::string& text) {
    if (!g_host || !g_host->resolve_address) throw ToolError("host does not support resolve_address");
    uint64_t address = 0;
    if (!g_host->resolve_address(g_host->user_data, text.c_str(), &address)) throw ToolError("could not resolve address/name: " + text);
    return address;
}

std::string require_text(const char* value, const char* what) {
    if (!value) throw ToolError(std::string("no binary is open, or ") + what + " could not be computed");
    return value;
}

// ---------------------------------------------------------------------------
// Tool implementations: each returns the JSON *value* (already-escaped text)
// to embed as the tool result, built directly from the live host callbacks.
// ---------------------------------------------------------------------------

std::string tool_info(const JsonValue&) {
    return require_text(g_host->info_json ? g_host->info_json(g_host->user_data) : nullptr, "info");
}

std::string tool_resolve(const JsonValue& args) {
    const auto text = args.find("address") ? args.find("address")->as_string() : std::string();
    if (text.empty()) throw ToolError("'address' is required");
    const auto address = resolve_or_throw(text);
    return "{\"address\":\"" + hex_u64(address) + "\"}";
}

std::string tool_listing(const JsonValue& args) {
    const auto text = args.find("address") ? args.find("address")->as_string() : std::string();
    if (text.empty()) throw ToolError("'address' is required");
    const auto address = resolve_or_throw(text);
    const auto listing = require_text(g_host->listing_at ? g_host->listing_at(g_host->user_data, address) : nullptr, "listing");
    return "{\"address\":\"" + hex_u64(address) + "\",\"listing\":\"" + json_escape(listing) + "\"}";
}

std::string tool_decompile(const JsonValue& args) {
    const auto text = args.find("address") ? args.find("address")->as_string() : std::string();
    if (text.empty()) throw ToolError("'address' is required");
    const auto address = resolve_or_throw(text);
    const bool comments = args.find("address_comments") && args.find("address_comments")->as_bool();
    int ok = 0;
    const auto result = g_host->decompile_at ? g_host->decompile_at(g_host->user_data, address, comments ? 1 : 0, &ok) : nullptr;
    if (!result) throw ToolError("no binary is open");
    std::ostringstream out;
    out << "{\"address\":\"" << hex_u64(address) << "\",\"decompiled\":" << (ok ? "true" : "false") << ",";
    out << (ok ? "\"pseudocode\":\"" : "\"error\":\"") << json_escape(result) << "\"}";
    return out.str();
}

std::string tool_hex(const JsonValue& args) {
    const auto text = args.find("address") ? args.find("address")->as_string() : std::string();
    if (text.empty()) throw ToolError("'address' is required");
    const auto address = resolve_or_throw(text);
    const auto rows = args.find("rows") ? static_cast<uint64_t>(args.find("rows")->as_int(16)) : 16;
    const auto dump = require_text(g_host->hex_dump_at ? g_host->hex_dump_at(g_host->user_data, address, rows) : nullptr, "hex dump");
    return "{\"address\":\"" + hex_u64(address) + "\",\"hex\":\"" + json_escape(dump) + "\"}";
}

std::string tool_strings(const JsonValue& args) {
    const auto min_len = args.find("min_length") ? static_cast<uint64_t>(args.find("min_length")->as_int(5)) : 5;
    return "{\"text\":\"" + json_escape(require_text(g_host->strings ? g_host->strings(g_host->user_data, min_len) : nullptr, "strings")) + "\"}";
}

std::string tool_imports(const JsonValue&) { return "{\"text\":\"" + json_escape(require_text(g_host->imports_text ? g_host->imports_text(g_host->user_data) : nullptr, "imports")) + "\"}"; }
std::string tool_exports(const JsonValue&) { return "{\"text\":\"" + json_escape(require_text(g_host->exports_text ? g_host->exports_text(g_host->user_data) : nullptr, "exports")) + "\"}"; }
std::string tool_resources(const JsonValue&) { return "{\"text\":\"" + json_escape(require_text(g_host->resources_text ? g_host->resources_text(g_host->user_data) : nullptr, "resources")) + "\"}"; }
std::string tool_segments(const JsonValue&) { return "{\"text\":\"" + json_escape(require_text(g_host->segments_text ? g_host->segments_text(g_host->user_data) : nullptr, "segments")) + "\"}"; }

std::string tool_xrefs(const JsonValue& args) {
    const auto text = args.find("address") ? args.find("address")->as_string() : std::string();
    if (text.empty()) throw ToolError("'address' is required");
    const auto address = resolve_or_throw(text);
    const auto direction = args.find("direction") ? args.find("direction")->as_string("to") : std::string("to");
    const bool want_to = direction != "from";
    if (!g_host->xref_count || !g_host->xref_at) throw ToolError("host does not support xref enumeration");
    const auto count = g_host->xref_count(g_host->user_data);
    std::ostringstream out;
    out << "{\"address\":\"" << hex_u64(address) << "\",\"xrefs\":[";
    bool first = true;
    for (uint64_t i = 0; i < count; ++i) {
        GandonXrefView xref{};
        if (!g_host->xref_at(g_host->user_data, i, &xref)) continue;
        if ((want_to && xref.to != address) || (!want_to && xref.from != address)) continue;
        if (!first) out << ','; first = false;
        out << "{\"from\":\"" << hex_u64(xref.from) << "\",\"to\":\"" << hex_u64(xref.to) << "\",\"kind\":\"" << json_escape(xref.kind ? xref.kind : "") << "\"}";
    }
    out << "]}";
    return out.str();
}

std::string tool_functions(const JsonValue& args) {
    const auto offset = args.find("offset") ? static_cast<uint64_t>(args.find("offset")->as_int(0)) : 0;
    const auto limit = args.find("limit") ? static_cast<uint64_t>(args.find("limit")->as_int(200)) : 200;
    if (!g_host->function_count || !g_host->function_at) throw ToolError("host does not support function enumeration");
    const auto count = g_host->function_count(g_host->user_data);
    std::ostringstream out;
    out << "{\"total\":" << count << ",\"offset\":" << offset << ",\"functions\":[";
    bool first = true;
    uint64_t emitted = 0;
    for (uint64_t i = offset; i < count && emitted < limit; ++i) {
        GandonFunctionView function{};
        if (!g_host->function_at(g_host->user_data, i, &function)) continue;
        if (!first) out << ','; first = false;
        out << "{\"start\":\"" << hex_u64(function.start) << "\",\"name\":\"" << json_escape(function.name ? function.name : "") << "\"}";
        ++emitted;
    }
    out << "],\"truncated\":" << ((offset + emitted) < count ? "true" : "false") << "}";
    return out.str();
}

// Decompiles a contiguous slice of the function table straight to a file on
// disk, instead of returning it over HTTP as one giant JSON blob the MCP
// client would have to hold in context - the same reason ida-multi-mcp has
// decompile_to_file. The plugin is an in-process DLL, so it just opens the
// file itself; no host callback is needed for this part.
std::string tool_decompile_to_file(const JsonValue& args) {
    const auto path = args.find("path") ? args.find("path")->as_string() : std::string();
    if (path.empty()) throw ToolError("'path' is required");
    if (!g_host->function_count || !g_host->function_at || !g_host->decompile_at) throw ToolError("host does not support decompilation");
    const auto offset = args.find("offset") ? static_cast<uint64_t>(args.find("offset")->as_int(0)) : 0;
    const auto requested_limit = args.find("limit") ? args.find("limit")->as_int(0) : 0;
    const uint64_t limit = requested_limit > 0 ? static_cast<uint64_t>(requested_limit) : UINT64_MAX; // 0/absent = no limit
    const bool comments = args.find("address_comments") && args.find("address_comments")->as_bool();
    const auto count = g_host->function_count(g_host->user_data);
    std::ofstream file(path, std::ios::trunc);
    if (!file) throw ToolError("could not create file: " + path);
    uint64_t written = 0, failed = 0, emitted = 0;
    for (uint64_t i = offset; i < count && emitted < limit; ++i, ++emitted) {
        GandonFunctionView function{};
        if (!g_host->function_at(g_host->user_data, i, &function)) continue;
        int ok = 0;
        const auto pseudocode = g_host->decompile_at(g_host->user_data, function.start, comments ? 1 : 0, &ok);
        file << "// ---- " << hex_u64(function.start) << " " << (function.name ? function.name : "") << " ----\n";
        if (ok && pseudocode) { file << pseudocode << "\n\n"; ++written; }
        else { file << "// (decompilation failed)\n\n"; ++failed; }
    }
    file.flush();
    if (!file) throw ToolError("error writing file: " + path);
    std::ostringstream out;
    out << "{\"path\":\"" << json_escape(path) << "\",\"functions_written\":" << written << ",\"functions_failed\":" << failed << "}";
    return out.str();
}

std::string tool_disasm(const JsonValue& args) {
    const auto text = args.find("address") ? args.find("address")->as_string() : std::string();
    if (text.empty()) throw ToolError("'address' is required");
    const auto address = resolve_or_throw(text);
    const auto count = args.find("count") ? static_cast<uint64_t>(args.find("count")->as_int(40)) : 40;
    if (!g_host->function_count || !g_host->function_at || !g_host->function_instruction_count || !g_host->function_instruction_at)
        throw ToolError("host does not support instruction enumeration");
    // Find which function index owns `address` (functions are address-sorted).
    const auto function_total = g_host->function_count(g_host->user_data);
    uint64_t function_index = UINT64_MAX, best_start = 0;
    for (uint64_t i = 0; i < function_total; ++i) {
        GandonFunctionView function{};
        if (!g_host->function_at(g_host->user_data, i, &function)) continue;
        if (function.start <= address && function.start >= best_start) { best_start = function.start; function_index = i; }
    }
    if (function_index == UINT64_MAX) throw ToolError("address is not inside any discovered function");
    const auto instruction_total = g_host->function_instruction_count(g_host->user_data, function_index);
    std::ostringstream out;
    out << "{\"address\":\"" << hex_u64(address) << "\",\"instructions\":[";
    bool first = true;
    uint64_t emitted = 0;
    bool seen_start = false;
    for (uint64_t i = 0; i < instruction_total && emitted < count; ++i) {
        GandonInstructionView instruction{};
        if (!g_host->function_instruction_at(g_host->user_data, function_index, i, &instruction)) continue;
        if (!seen_start) { if (instruction.address != address) continue; seen_start = true; }
        if (!first) out << ','; first = false;
        out << "{\"address\":\"" << hex_u64(instruction.address) << "\",\"size\":" << instruction.size
            << ",\"text\":\"" << json_escape(std::string(instruction.mnemonic ? instruction.mnemonic : "") + " " + (instruction.operands ? instruction.operands : "")) << "\"}";
        ++emitted;
    }
    out << "]}";
    return out.str();
}

std::string tool_search_bytes(const JsonValue& args) {
    const auto pattern = args.find("pattern") ? args.find("pattern")->as_string() : std::string();
    if (pattern.empty()) throw ToolError("'pattern' is required, e.g. '55 8B EC ?? ??'");
    if (!g_host->search_bytes) throw ToolError("host does not support search_bytes");
    const char* result = g_host->search_bytes(g_host->user_data, pattern.c_str());
    if (!result) throw ToolError("no binary is open");
    std::ostringstream out;
    out << "{\"matches\":[";
    std::istringstream tokens(result);
    std::string token; bool first = true;
    while (tokens >> token) { if (!first) out << ','; first = false; out << "\"" << json_escape(token) << "\""; }
    out << "]}";
    return out.str();
}

std::string tool_search_text(const JsonValue& args) {
    const auto text = args.find("text") ? args.find("text")->as_string() : std::string();
    if (text.empty()) throw ToolError("'text' is required");
    if (!g_host->search_text) throw ToolError("host does not support search_text");
    const char* result = g_host->search_text(g_host->user_data, text.c_str());
    if (!result) throw ToolError("no binary is open");
    std::ostringstream out;
    out << "{\"matches\":[";
    std::istringstream tokens(result);
    std::string token; bool first = true;
    while (tokens >> token) { if (!first) out << ','; first = false; out << "\"" << json_escape(token) << "\""; }
    out << "]}";
    return out.str();
}

std::string tool_auto_analysis(const JsonValue& args) {
    if (!g_host->run_auto_analysis) throw ToolError("host does not support run_auto_analysis");
    const bool async = args.find("async") && args.find("async")->as_bool();
    if (!async) {
        const auto summary = require_text(g_host->run_auto_analysis(g_host->user_data), "auto-analysis");
        return "{\"summary\":\"" + json_escape(summary) + "\",\"async\":false}";
    }
    {
        std::lock_guard<std::mutex> lock(g_analysis_mutex);
        if (g_analysis_running.load()) return "{\"started\":false,\"already_running\":true}";
        g_analysis_running = true;
        g_analysis_has_result = false;
        g_analysis_summary.clear();
    }
    if (g_analysis_thread.joinable()) g_analysis_thread.join(); // previous run already finished
    g_analysis_thread = std::thread([] {
        // run_auto_analysis() itself marshals onto the UI thread and blocks
        // this thread until it finishes, exactly like every other v2 host
        // callback - it is just being called from the plugin's own thread
        // instead of a request-handling thread, so new HTTP connections can
        // still be accepted and served while it runs.
        const char* result = g_host->run_auto_analysis(g_host->user_data);
        std::lock_guard<std::mutex> lock(g_analysis_mutex);
        g_analysis_summary = result ? result : "no binary open";
        g_analysis_has_result = true;
        g_analysis_running = false;
    });
    return "{\"started\":true,\"async\":true}";
}

std::string analysis_state_json() {
    std::lock_guard<std::mutex> lock(g_analysis_mutex);
    std::ostringstream out;
    out << "{\"running\":" << (g_analysis_running.load() ? "true" : "false")
        << ",\"has_result\":" << (g_analysis_has_result ? "true" : "false");
    if (g_analysis_has_result) out << ",\"summary\":\"" << json_escape(g_analysis_summary) << "\"";
    out << "}";
    return out.str();
}

std::string tool_analysis_status(const JsonValue&) { return analysis_state_json(); }

std::string tool_analysis_wait(const JsonValue& args) {
    const auto timeout_ms = args.find("timeout_seconds") ? static_cast<long long>(args.find("timeout_seconds")->as_int(30)) * 1000 : 30000;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (g_analysis_running.load() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    return analysis_state_json();
}

std::string tool_save_database(const JsonValue& args) {
    const auto path = args.find("path") ? args.find("path")->as_string() : std::string();
    if (path.empty()) throw ToolError("'path' is required");
    if (!g_host->save_database) throw ToolError("host does not support save_database");
    if (!g_host->save_database(g_host->user_data, path.c_str())) {
        const auto reason = g_host->last_database_error ? g_host->last_database_error(g_host->user_data) : nullptr;
        throw ToolError(std::string("save_database failed: ") + (reason && *reason ? reason : "unknown error"));
    }
    return "{\"path\":\"" + json_escape(path) + "\",\"saved\":true}";
}

std::string tool_load_database(const JsonValue& args) {
    const auto path = args.find("path") ? args.find("path")->as_string() : std::string();
    if (path.empty()) throw ToolError("'path' is required");
    if (!g_host->load_database) throw ToolError("host does not support load_database");
    if (!g_host->load_database(g_host->user_data, path.c_str())) {
        const auto reason = g_host->last_database_error ? g_host->last_database_error(g_host->user_data) : nullptr;
        throw ToolError(std::string("load_database failed: ") + (reason && *reason ? reason : "unknown error"));
    }
    return "{\"path\":\"" + json_escape(path) + "\",\"loaded\":true}";
}

std::string tool_rename(const JsonValue& args) {
    const auto text = args.find("address") ? args.find("address")->as_string() : std::string();
    const auto name = args.find("name") ? args.find("name")->as_string() : std::string();
    if (text.empty() || name.empty()) throw ToolError("'address' and 'name' are both required");
    const auto address = resolve_or_throw(text);
    if (!g_host->rename || !g_host->rename(g_host->user_data, address, name.c_str())) throw ToolError("rename failed");
    return "{\"address\":\"" + hex_u64(address) + "\",\"name\":\"" + json_escape(name) + "\"}";
}

std::string tool_comment(const JsonValue& args) {
    const auto text = args.find("address") ? args.find("address")->as_string() : std::string();
    const auto comment = args.find("comment") ? args.find("comment")->as_string() : std::string();
    if (text.empty()) throw ToolError("'address' is required");
    const auto address = resolve_or_throw(text);
    if (!g_host->add_comment || !g_host->add_comment(g_host->user_data, address, comment.c_str())) throw ToolError("add_comment failed");
    return "{\"address\":\"" + hex_u64(address) + "\",\"comment\":\"" + json_escape(comment) + "\"}";
}

std::string tool_patch(const JsonValue& args) {
    const auto text = args.find("address") ? args.find("address")->as_string() : std::string();
    const auto bytes_text = args.find("bytes") ? args.find("bytes")->as_string() : std::string();
    if (text.empty() || bytes_text.empty()) throw ToolError("'address' and 'bytes' are both required, e.g. bytes='90 90'");
    const auto address = resolve_or_throw(text);
    std::vector<uint8_t> bytes;
    std::istringstream tokens(bytes_text);
    std::string token;
    while (tokens >> token) {
        try { bytes.push_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16))); } catch (...) { throw ToolError("bad byte token: " + token); }
    }
    if (bytes.empty()) throw ToolError("empty replacement bytes");
    if (!g_host->patch_bytes || !g_host->patch_bytes(g_host->user_data, address, bytes.data(), bytes.size())) throw ToolError("patch failed");
    return "{\"address\":\"" + hex_u64(address) + "\",\"patched_bytes\":" + std::to_string(bytes.size()) +
           ",\"note\":\"applied to the live, open database - Undo Patch (Ctrl+Z) reverts it\"}";
}

std::string tool_navigate(const JsonValue& args) {
    const auto text = args.find("address") ? args.find("address")->as_string() : std::string();
    if (text.empty()) throw ToolError("'address' is required");
    const auto address = resolve_or_throw(text);
    if (g_host->navigate) g_host->navigate(g_host->user_data, address);
    return "{\"address\":\"" + hex_u64(address) + "\",\"navigated\":true}";
}

struct Tool {
    const char* description;
    const char* schema; // raw JSON Schema object text
    std::string (*handler)(const JsonValue&);
};

const char* ADDR_SCHEMA_REQ =
    "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Hex/decimal address, function/import/export name, or renamed label.\"}},\"required\":[\"address\"]}";

const std::map<std::string, Tool>& tools() {
    static const std::map<std::string, Tool> table = {
        {"gandon_info", {"Live binary info: format, architecture, entry point, sections, function/xref counts of the currently open database.", "{\"type\":\"object\",\"properties\":{}}", tool_info}},
        {"gandon_resolve_address", {"Resolve a name/label/hex/decimal text to an address, the same way Jump to Address does.", ADDR_SCHEMA_REQ, tool_resolve}},
        {"gandon_list_functions", {"List discovered functions (start, name), paginated for large binaries. Response includes 'total' and 'truncated'.", "{\"type\":\"object\",\"properties\":{\"offset\":{\"type\":\"integer\",\"description\":\"Index of the first function to return (default 0).\"},\"limit\":{\"type\":\"integer\",\"description\":\"Max functions to return (default 200).\"}}}", tool_functions}},
        {"gandon_decompile_to_file", {"Decompile a range of functions straight to a file on disk instead of returning them over the wire - use this instead of looping gandon_decompile on a large binary.", "{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\",\"description\":\"Output file path, written by the plugin process.\"},\"offset\":{\"type\":\"integer\"},\"limit\":{\"type\":\"integer\",\"description\":\"Max functions to decompile (default: all remaining).\"},\"address_comments\":{\"type\":\"boolean\"}},\"required\":[\"path\"]}", tool_decompile_to_file}},
        {"gandon_disasm", {"Disassemble instructions starting at an address.", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\"},\"count\":{\"type\":\"integer\"}},\"required\":[\"address\"]}", tool_disasm}},
        {"gandon_listing", {"Full IDA-style text listing of the function containing an address.", ADDR_SCHEMA_REQ, tool_listing}},
        {"gandon_decompile", {"Decompile one function (x86/x64) to C-like pseudocode, using the live database (your renames/comments are reflected).", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\"},\"address_comments\":{\"type\":\"boolean\"}},\"required\":[\"address\"]}", tool_decompile}},
        {"gandon_xrefs", {"Cross-references to or from an address.", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\"},\"direction\":{\"type\":\"string\",\"enum\":[\"to\",\"from\"]}},\"required\":[\"address\"]}", tool_xrefs}},
        {"gandon_strings", {"Strings embedded in the binary.", "{\"type\":\"object\",\"properties\":{\"min_length\":{\"type\":\"integer\"}}}", tool_strings}},
        {"gandon_imports", {"Imported functions.", "{\"type\":\"object\",\"properties\":{}}", tool_imports}},
        {"gandon_exports", {"Exported functions.", "{\"type\":\"object\",\"properties\":{}}", tool_exports}},
        {"gandon_resources", {"PE resource directory as text.", "{\"type\":\"object\",\"properties\":{}}", tool_resources}},
        {"gandon_segments", {"Memory segments/sections overview.", "{\"type\":\"object\",\"properties\":{}}", tool_segments}},
        {"gandon_hex", {"Hex dump starting at an address.", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\"},\"rows\":{\"type\":\"integer\"}},\"required\":[\"address\"]}", tool_hex}},
        {"gandon_search_bytes", {"Search the open file for a byte pattern ('??' wildcard byte).", "{\"type\":\"object\",\"properties\":{\"pattern\":{\"type\":\"string\"}},\"required\":[\"pattern\"]}", tool_search_bytes}},
        {"gandon_search_text", {"Search the open file for an ASCII substring.", "{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\"}},\"required\":[\"text\"]}", tool_search_text}},
        {"gandon_auto_analysis", {"Run recursive-descent auto-analysis on the live database (same as the menu action). With 'async':true, starts it on a background thread and returns immediately - poll with gandon_analysis_status or gandon_analysis_wait (this can take minutes on a large binary and otherwise would hold up the connection, like IDA's analysis).", "{\"type\":\"object\",\"properties\":{\"async\":{\"type\":\"boolean\"}}}", tool_auto_analysis}},
        {"gandon_analysis_status", {"Non-blocking check of a background auto-analysis started with gandon_auto_analysis(async=true).", "{\"type\":\"object\",\"properties\":{}}", tool_analysis_status}},
        {"gandon_analysis_wait", {"Block (up to timeout_seconds) until a background auto-analysis finishes, then return its result.", "{\"type\":\"object\",\"properties\":{\"timeout_seconds\":{\"type\":\"integer\"}}}", tool_analysis_wait}},
        {"gandon_rename", {"Rename a function/label at an address in the live database (visible in the GUI immediately).", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\"},\"name\":{\"type\":\"string\"}},\"required\":[\"address\",\"name\"]}", tool_rename}},
        {"gandon_add_comment", {"Set a comment at an address in the live database.", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\"},\"comment\":{\"type\":\"string\"}},\"required\":[\"address\"]}", tool_comment}},
        {"gandon_patch_bytes", {"Patch bytes at an address IN THE OPEN GUI SESSION (pushes an undo entry; Ctrl+Z reverts it). 'bytes' is space-separated hex, e.g. '90 90'.", "{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\"},\"bytes\":{\"type\":\"string\"}},\"required\":[\"address\",\"bytes\"]}", tool_patch}},
        {"gandon_navigate", {"Jump the GUI's current view to an address (like clicking it), for visual follow-along.", ADDR_SCHEMA_REQ, tool_navigate}},
        {"gandon_save_database", {"Save the live session (renames, comments, patches, bookmarks, graph layout) to a .gnd file, like File > Save Database - checkpoint before closing the GUI.", "{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}},\"required\":[\"path\"]}", tool_save_database}},
        {"gandon_load_database", {"Replace the live session from a .gnd file saved earlier with gandon_save_database or File > Save Database (native format only, not the legacy Python JSON one).", "{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}},\"required\":[\"path\"]}", tool_load_database}},
    };
    return table;
}

std::string tools_list_json() {
    std::ostringstream out;
    out << "[";
    bool first = true;
    for (const auto& [name, tool] : tools()) {
        if (!first) out << ','; first = false;
        out << "{\"name\":\"" << name << "\",\"description\":\"" << json_escape(tool.description) << "\",\"inputSchema\":" << tool.schema << "}";
    }
    out << "]";
    return out.str();
}

// ---------------------------------------------------------------------------
// JSON-RPC dispatch
// ---------------------------------------------------------------------------

std::string dispatch(const std::string& body) {
    JsonValue message;
    if (!JsonParser(body).parse(message) || !message.is_object()) {
        return "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}";
    }
    const auto* method_value = message.find("method");
    const auto* id_value = message.find("id");
    const std::string method = method_value ? method_value->as_string() : std::string();
    const std::string id_text = id_literal(id_value);
    const bool is_notification = !id_value;

    if (method == "initialize") {
        return "{\"jsonrpc\":\"2.0\",\"id\":" + id_text + ",\"result\":{\"protocolVersion\":\"" + PROTOCOL_VERSION +
               "\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"" + SERVER_NAME + "\",\"version\":\"" + SERVER_VERSION + "\"}}}";
    }
    if (method == "notifications/initialized") return {}; // no response
    if (method == "ping") return "{\"jsonrpc\":\"2.0\",\"id\":" + id_text + ",\"result\":{}}";
    if (method == "tools/list") {
        return "{\"jsonrpc\":\"2.0\",\"id\":" + id_text + ",\"result\":{\"tools\":" + tools_list_json() + "}}";
    }
    if (method == "tools/call") {
        const auto* params = message.find("params");
        const auto name = params && params->find("name") ? params->find("name")->as_string() : std::string();
        const auto* arguments = params ? params->find("arguments") : nullptr;
        static const JsonValue empty_args{};
        const auto& args = arguments ? *arguments : empty_args;
        const auto found = tools().find(name);
        if (found == tools().end()) {
            return "{\"jsonrpc\":\"2.0\",\"id\":" + id_text + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"Unknown tool: " + json_escape(name) + "\"}],\"isError\":true}}";
        }
        ++g_requests_served;
        try {
            const auto result = found->second.handler(args);
            return "{\"jsonrpc\":\"2.0\",\"id\":" + id_text + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":" + "\"" + json_escape(result) + "\"" + "}],\"isError\":false}}";
        } catch (const std::exception& exc) {
            return "{\"jsonrpc\":\"2.0\",\"id\":" + id_text + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + json_escape(exc.what()) + "\"}],\"isError\":true}}";
        }
    }
    if (is_notification) return {};
    return "{\"jsonrpc\":\"2.0\",\"id\":" + id_text + ",\"error\":{\"code\":-32601,\"message\":\"Method not found: " + json_escape(method) + "\"}}";
}

// ---------------------------------------------------------------------------
// Minimal blocking HTTP/1.1 server (one request per connection; good enough
// for a local analysis tool, keeps the implementation small and robust).
// ---------------------------------------------------------------------------

std::string read_line(SOCKET socket, std::string& residual) {
    for (;;) {
        const auto newline = residual.find("\r\n");
        if (newline != std::string::npos) {
            std::string line = residual.substr(0, newline);
            residual.erase(0, newline + 2);
            return line;
        }
        char buffer[4096];
        const auto received = recv(socket, buffer, sizeof(buffer), 0);
        if (received <= 0) return {};
        residual.append(buffer, static_cast<std::size_t>(received));
    }
}

bool send_all(SOCKET socket, const std::string& data) {
    std::size_t sent = 0;
    while (sent < data.size()) {
        const auto result = send(socket, data.data() + sent, static_cast<int>(data.size() - sent), 0);
        if (result <= 0) return false;
        sent += static_cast<std::size_t>(result);
    }
    return true;
}

void send_response(SOCKET socket, int status, const char* status_text, const std::string& content_type, const std::string& body) {
    std::ostringstream head;
    head << "HTTP/1.1 " << status << " " << status_text << "\r\n"
         << "Content-Type: " << content_type << "\r\n"
         << "Content-Length: " << body.size() << "\r\n"
         << "Access-Control-Allow-Origin: *\r\n"
         << "Connection: close\r\n\r\n";
    send_all(socket, head.str());
    if (!body.empty()) send_all(socket, body);
}

void handle_connection(SOCKET socket) {
    std::string residual;
    const auto request_line = read_line(socket, residual);
    if (request_line.empty()) { closesocket(socket); return; }
    std::istringstream request_stream(request_line);
    std::string method, path, http_version;
    request_stream >> method >> path >> http_version;

    std::size_t content_length = 0;
    std::string authorization;
    for (;;) {
        const auto header_line = read_line(socket, residual);
        if (header_line.empty()) break;
        const auto colon = header_line.find(':');
        if (colon == std::string::npos) continue;
        std::string key = header_line.substr(0, colon);
        std::string value = header_line.substr(colon + 1);
        while (!value.empty() && value.front() == ' ') value.erase(0, 1);
        for (auto& ch : key) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (key == "content-length") content_length = static_cast<std::size_t>(std::strtoull(value.c_str(), nullptr, 10));
        else if (key == "authorization") authorization = value;
    }

    std::string body = residual; // whatever was already buffered past the headers
    while (body.size() < content_length) {
        char buffer[8192];
        const auto received = recv(socket, buffer, static_cast<int>((std::min)(sizeof(buffer), content_length - body.size())), 0);
        if (received <= 0) break;
        body.append(buffer, static_cast<std::size_t>(received));
    }

    if (method == "OPTIONS") {
        std::ostringstream head;
        head << "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                "Access-Control-Allow-Headers: Content-Type, Authorization\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send_all(socket, head.str());
    } else if (method == "GET" && path.rfind("/health", 0) == 0) {
        std::ostringstream body_out;
        body_out << "{\"status\":\"ok\",\"server\":\"" << SERVER_NAME << "\",\"version\":\"" << SERVER_VERSION
                 << "\",\"requests_served\":" << g_requests_served.load() << "}";
        send_response(socket, 200, "OK", "application/json", body_out.str());
    } else if (method == "POST" && path.rfind("/mcp", 0) == 0) {
        if (!g_token.empty() && authorization != ("Bearer " + g_token)) {
            send_response(socket, 401, "Unauthorized", "application/json", "{\"error\":\"missing or invalid bearer token\"}");
        } else {
            const auto response = dispatch(body);
            if (response.empty()) send_response(socket, 202, "Accepted", "application/json", {});
            else send_response(socket, 200, "OK", "application/json", response);
        }
    } else {
        send_response(socket, 404, "Not Found", "application/json", "{\"error\":\"unknown endpoint; POST JSON-RPC to /mcp, GET /health\"}");
    }
    shutdown(socket, SD_SEND);
    closesocket(socket);
}

void server_loop() {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { if (g_host && g_host->log) g_host->log(g_host->user_data, "[mcp] WSAStartup failed"); return; }

    g_listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listen_socket == INVALID_SOCKET) { WSACleanup(); return; }
    BOOL reuse = TRUE;
    setsockopt(g_listen_socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<u_short>(g_port));
    if (InetPtonA(AF_INET, g_bind_host.c_str(), &address.sin_addr) != 1) address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(g_listen_socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR ||
        listen(g_listen_socket, 8) == SOCKET_ERROR) {
        if (g_host && g_host->log) {
            char message[160];
            std::snprintf(message, sizeof(message), "[mcp] Could not bind %s:%d (error %d) - is the port already in use?", g_bind_host.c_str(), g_port, WSAGetLastError());
            g_host->log(g_host->user_data, message);
        }
        closesocket(g_listen_socket);
        g_listen_socket = INVALID_SOCKET;
        WSACleanup();
        return;
    }

    if (g_host && g_host->log) {
        char message[160];
        std::snprintf(message, sizeof(message), "[mcp] Listening on http://%s:%d/mcp%s", g_bind_host.c_str(), g_port, g_token.empty() ? " (no token)" : " (token required)");
        g_host->log(g_host->user_data, message);
    }
    if (g_host && g_host->status) {
        char message[160];
        std::snprintf(message, sizeof(message), "MCP plugin listening on http://%s:%d/mcp", g_bind_host.c_str(), g_port);
        g_host->status(g_host->user_data, message);
    }

    while (g_running.load()) {
        sockaddr_in client{};
        int client_len = sizeof(client);
        const SOCKET client_socket = accept(g_listen_socket, reinterpret_cast<sockaddr*>(&client), &client_len);
        if (client_socket == INVALID_SOCKET) { if (!g_running.load()) break; continue; }
        handle_connection(client_socket); // one request at a time: simple and safe against concurrent host calls
    }

    closesocket(g_listen_socket);
    g_listen_socket = INVALID_SOCKET;
    WSACleanup();
}

void show_status(void*) {
    if (!g_host || !g_host->status) return;
    char message[192];
    std::snprintf(message, sizeof(message), "MCP plugin: %s on http://%s:%d/mcp, %u request(s) served",
                  g_running.load() ? "running" : "stopped", g_bind_host.c_str(), g_port, g_requests_served.load());
    g_host->status(g_host->user_data, message);
    if (g_host->log) g_host->log(g_host->user_data, message);
}

} // namespace

extern "C" GANDON_PLUGIN_EXPORT int GandonPluginInit(const GandonPluginHost* host, GandonPluginInfo* info) {
    if (!host || !info || host->api_version != GANDON_PLUGIN_API_VERSION) return 0;
    g_host = host;
    info->api_version = GANDON_PLUGIN_API_VERSION;
    info->name = "MCP Server";
    info->version = SERVER_VERSION;

    // Optional overrides via environment variables, set before launching
    // gandon_gui.exe, e.g.:  set GANDON_MCP_PORT=9000 && gandon_gui.exe
    if (const char* port_env = std::getenv("GANDON_MCP_PORT")) g_port = std::atoi(port_env);
    if (const char* host_env = std::getenv("GANDON_MCP_HOST")) g_bind_host = host_env;
    if (const char* token_env = std::getenv("GANDON_MCP_TOKEN")) g_token = token_env;

    if (host->register_action) host->register_action(host->user_data, "Plugins", "MCP Server Status", show_status, nullptr);

    g_running = true;
    g_server_thread = std::thread(server_loop);
    return 1;
}

extern "C" GANDON_PLUGIN_EXPORT void GandonPluginShutdown() {
    g_running = false;
    if (g_listen_socket != INVALID_SOCKET) {
        // Unblock accept() by connecting to ourselves once.
        SOCKET nudge = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (nudge != INVALID_SOCKET) {
            sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(static_cast<u_short>(g_port));
            InetPtonA(AF_INET, "127.0.0.1", &address.sin_addr);
            connect(nudge, reinterpret_cast<sockaddr*>(&address), sizeof(address));
            closesocket(nudge);
        }
    }
    if (g_server_thread.joinable()) g_server_thread.join();
    if (g_analysis_thread.joinable()) g_analysis_thread.join();
    g_host = nullptr;
}
