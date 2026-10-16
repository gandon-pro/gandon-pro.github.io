// Gandon-PRO MCP backend: a one-shot CLI that loads a binary, runs one
// analysis command against it and prints a single JSON object to stdout.
// This is the thin bridge the Python MCP server (mcp/gandon_mcp_server.py)
// shells out to; it exists so the MCP server does not need to re-implement
// any analysis logic - everything comes from gandon_core / ida_views /
// decompiler / auto_analysis, the same code the GUI uses.
#include "gandon/core.hpp"
#include "gandon/ida_views.hpp"
#include "gandon/image_tables.hpp"
#include "gandon/decompiler.hpp"
#include "gandon/auto_analysis.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace {

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

std::string hex_u64(std::uint64_t value) {
    std::ostringstream out; out << "0x" << std::hex << value; return out.str();
}

std::string json_string(const std::string& value) { return "\"" + json_escape(value) + "\""; }

// A tiny streaming JSON array/object builder so this file does not need a
// JSON library dependency.
class JsonWriter {
public:
    explicit JsonWriter(std::ostream& out) : out_(out) {}
    void begin_object() { comma(); out_ << '{'; state_.push_back({true, false}); }
    void end_object() { out_ << '}'; state_.pop_back(); }
    void begin_array() { comma(); out_ << '['; state_.push_back({false, false}); }
    void end_array() { out_ << ']'; state_.pop_back(); }
    void key(const std::string& name) { comma(); out_ << json_string(name) << ':'; suppress_comma_ = true; }
    void value(const std::string& text) { comma(); out_ << json_string(text); }
    void raw(const std::string& text) { comma(); out_ << text; }
    void value(std::uint64_t number) { comma(); out_ << number; }
    void value(std::int64_t number) { comma(); out_ << number; }
    void value(bool flag) { comma(); out_ << (flag ? "true" : "false"); }
    void value(const char* text) { value(std::string(text)); }
    void value_hex(std::uint64_t address) { value(hex_u64(address)); }

private:
    struct Scope { bool is_object; bool first_written; };
    std::ostream& out_;
    std::vector<Scope> state_;
    bool suppress_comma_{false};

    void comma() {
        if (suppress_comma_) { suppress_comma_ = false; return; }
        if (state_.empty()) return;
        if (state_.back().first_written) out_ << ',';
        state_.back().first_written = true;
    }
};

int fail(const std::string& message) {
    std::cout << "{\"ok\":false,\"error\":" << json_string(message) << "}\n";
    return 1;
}

std::optional<std::uint64_t> parse_address(const std::string& text) {
    if (text.empty()) return std::nullopt;
    try {
        std::size_t used = 0;
        const auto value = std::stoull(text, &used, 0);
        if (used != text.size()) return std::nullopt;
        return value;
    } catch (...) { return std::nullopt; }
}

std::string read_all_stdin_arg(int argc, char** argv, int index) {
    return index < argc ? argv[index] : std::string();
}

// Finds the address for a name: a custom/renamed label, a function name, an
// import or an export. Falls back to parsing the text as a hex/decimal number.
std::optional<std::uint64_t> resolve_target(const gandon::AnalysisDatabase& db, const std::string& text) {
    if (const auto address = parse_address(text)) {
        if (db.image().va_to_file_offset(*address) || db.function_at(*address)) return address;
    }
    for (const auto& function : db.functions()) if (function.name == text) return function.start;
    for (const auto& symbol : db.image().symbols) if (symbol.name == text) return symbol.address;
    for (const auto& entry : gandon::parse_imports(db.image())) if (entry.name == text) return entry.iat;
    for (const auto& entry : gandon::parse_exports(db.image())) if (entry.name == text) return entry.address;
    return parse_address(text);
}

void write_functions(JsonWriter& json, const gandon::AnalysisDatabase& db, std::size_t limit) {
    json.key("functions"); json.begin_array();
    std::size_t count = 0;
    for (const auto& function : db.functions()) {
        if (count++ >= limit) break;
        json.begin_object();
        json.key("start"); json.value_hex(function.start);
        json.key("name"); json.value(function.name);
        json.key("instruction_count"); json.value(static_cast<std::uint64_t>(function.instructions.size()));
        if (function.end) { json.key("end"); json.value_hex(function.end); }
        json.end_object();
    }
    json.end_array();
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: gandon_mcp_backend <binary> <command> [args...]\n"
                     "commands: info | functions [limit] | disasm <addr> [count] | listing <addr> |\n"
                     "          decompile <addr|name> [address_comments] | xrefs_to <addr> | xrefs_from <addr> |\n"
                     "          strings [min_len] | imports | exports | resources | segments | hex <addr> [rows] |\n"
                     "          search_bytes <hexpattern> | search_text <text> | search_regex <pattern> |\n"
                     "          patch_bytes <addr> <hexbytes> <out_path> | auto_analysis | call_graph <addr> [depth]\n";
        return 2;
    }
    const std::string binary_path = argv[1];
    const std::string command = argv[2];

    gandon::BinaryImage image;
    std::string error;
    if (!image.load(binary_path, error)) return fail("could not load binary: " + error);
    gandon::AnalysisDatabase db(std::move(image));
    db.discover_basic_xrefs();

    std::ostringstream buffer;
    JsonWriter json(buffer);
    json.begin_object();
    json.key("ok"); json.value(true);

    if (command == "info") {
        const auto& img = db.image();
        json.key("path"); json.value(img.path.string());
        json.key("format"); json.value(img.format == gandon::BinaryFormat::PE ? "PE" : img.format == gandon::BinaryFormat::ELF ? "ELF" : "unknown");
        json.key("architecture"); json.value(img.architecture == gandon::MachineArchitecture::X64 ? "x64" : img.architecture == gandon::MachineArchitecture::X86 ? "x86" : img.architecture == gandon::MachineArchitecture::ARM64 ? "arm64" : "unknown");
        json.key("is_64_bit"); json.value(img.is_64_bit);
        json.key("image_base"); json.value_hex(img.image_base);
        json.key("entry_point"); json.value_hex(img.entry_point);
        json.key("size"); json.value(static_cast<std::uint64_t>(img.bytes.size()));
        json.key("function_count"); json.value(static_cast<std::uint64_t>(db.functions().size()));
        json.key("xref_count"); json.value(static_cast<std::uint64_t>(db.xrefs().size()));
        json.key("sections"); json.begin_array();
        for (const auto& section : img.sections) {
            json.begin_object();
            json.key("name"); json.value(section.name);
            json.key("rva"); json.value_hex(section.rva);
            json.key("virtual_size"); json.value(static_cast<std::uint64_t>(section.virtual_size));
            json.key("raw_size"); json.value(static_cast<std::uint64_t>(section.raw_size));
            json.end_object();
        }
        json.end_array();
    } else if (command == "functions") {
        const auto limit_text = read_all_stdin_arg(argc, argv, 3);
        const std::size_t limit = limit_text.empty() ? 2000 : static_cast<std::size_t>(std::strtoull(limit_text.c_str(), nullptr, 10));
        write_functions(json, db, limit);
    } else if (command == "disasm") {
        if (argc < 4) return fail("disasm needs an address");
        const auto target = resolve_target(db, argv[3]);
        if (!target) return fail("could not resolve address/name: " + std::string(argv[3]));
        const auto count_text = read_all_stdin_arg(argc, argv, 4);
        const std::size_t count = count_text.empty() ? 40 : static_cast<std::size_t>(std::strtoull(count_text.c_str(), nullptr, 10));
        const auto instructions = gandon::decode_x64(db.image(), *target, count);
        gandon::IdaViews views(db);
        json.key("address"); json.value_hex(*target);
        json.key("instructions"); json.begin_array();
        for (const auto& instruction : instructions) {
            json.begin_object();
            json.key("address"); json.value_hex(instruction.address);
            json.key("symbol"); json.value(views.symbolic(instruction.address));
            json.key("bytes"); {
                std::ostringstream hex; for (int i = 0; i < instruction.size; ++i) { if (i) hex << ' '; char b[4]; std::snprintf(b, sizeof(b), "%02X", instruction.bytes[i]); hex << b; }
                json.value(hex.str());
            }
            json.key("text"); json.value(views.format_instruction(instruction));
            json.end_object();
        }
        json.end_array();
    } else if (command == "listing") {
        if (argc < 4) return fail("listing needs an address");
        const auto target = resolve_target(db, argv[3]);
        if (!target) return fail("could not resolve address/name: " + std::string(argv[3]));
        gandon::IdaViews views(db);
        json.key("address"); json.value_hex(*target);
        json.key("listing"); json.value(views.listing(*target));
    } else if (command == "decompile") {
        if (argc < 4) return fail("decompile needs an address or function name");
        const auto target = resolve_target(db, argv[3]);
        if (!target) return fail("could not resolve address/name: " + std::string(argv[3]));
        const bool comments = argc > 4 && std::string(argv[4]) == "1";
        const auto result = gandon::decompile_function_at(db, *target, comments);
        json.key("address"); json.value_hex(*target);
        json.key("decompiled"); json.value(result.ok);
        if (!result.ok) { json.key("error"); json.value(result.error); }
        else {
            json.key("pseudocode"); json.value(result.text);
            json.key("block_count"); json.value(static_cast<std::uint64_t>(result.block_count));
            json.key("goto_count"); json.value(static_cast<std::uint64_t>(result.goto_count));
        }
    } else if (command == "xrefs_to" || command == "xrefs_from") {
        if (argc < 4) return fail(command + " needs an address");
        const auto target = resolve_target(db, argv[3]);
        if (!target) return fail("could not resolve address/name: " + std::string(argv[3]));
        gandon::IdaViews views(db);
        json.key("address"); json.value_hex(*target);
        json.key("xrefs"); json.begin_array();
        for (const auto& xref : db.xrefs()) {
            const bool match = command == "xrefs_to" ? xref.to == *target : xref.from == *target;
            if (!match) continue;
            json.begin_object();
            json.key("from"); json.value_hex(xref.from);
            json.key("from_symbol"); json.value(views.symbolic(xref.from));
            json.key("to"); json.value_hex(xref.to);
            json.key("to_symbol"); json.value(views.symbolic(xref.to));
            json.key("kind"); json.value(xref.kind);
            json.end_object();
        }
        json.end_array();
    } else if (command == "strings") {
        const auto min_text = read_all_stdin_arg(argc, argv, 3);
        const std::size_t min_len = min_text.empty() ? 5 : static_cast<std::size_t>(std::strtoull(min_text.c_str(), nullptr, 10));
        gandon::IdaViews views(db);
        json.key("text"); json.value(views.strings(min_len));
    } else if (command == "imports") {
        json.key("imports"); json.begin_array();
        for (const auto& entry : gandon::parse_imports(db.image())) {
            json.begin_object();
            json.key("library"); json.value(entry.library);
            json.key("name"); json.value(entry.name);
            json.key("ordinal"); json.value(static_cast<std::uint64_t>(entry.ordinal));
            json.key("iat"); json.value_hex(entry.iat);
            json.end_object();
        }
        json.end_array();
    } else if (command == "exports") {
        json.key("exports"); json.begin_array();
        for (const auto& entry : gandon::parse_exports(db.image())) {
            json.begin_object();
            json.key("name"); json.value(entry.name);
            json.key("address"); json.value_hex(entry.address);
            json.key("ordinal"); json.value(static_cast<std::uint64_t>(entry.ordinal));
            if (!entry.forwarder.empty()) { json.key("forwarder"); json.value(entry.forwarder); }
            json.end_object();
        }
        json.end_array();
    } else if (command == "resources") {
        gandon::IdaViews views(db);
        json.key("text"); json.value(views.resources());
    } else if (command == "segments") {
        gandon::IdaViews views(db);
        json.key("text"); json.value(views.segments());
    } else if (command == "hex") {
        if (argc < 4) return fail("hex needs an address");
        const auto target = resolve_target(db, argv[3]);
        if (!target) return fail("could not resolve address/name: " + std::string(argv[3]));
        const auto rows_text = read_all_stdin_arg(argc, argv, 4);
        const std::size_t rows = rows_text.empty() ? 16 : static_cast<std::size_t>(std::strtoull(rows_text.c_str(), nullptr, 10));
        gandon::IdaViews views(db);
        json.key("address"); json.value_hex(*target);
        json.key("hex"); json.value(views.hex_view(*target, rows));
    } else if (command == "search_bytes") {
        if (argc < 4) return fail("search_bytes needs a hex pattern, e.g. \"55 8B EC ?? ??\"");
        std::vector<std::optional<std::uint8_t>> pattern;
        std::istringstream tokens(argv[3]);
        std::string token;
        while (tokens >> token) {
            if (token == "??" || token == "?") { pattern.push_back(std::nullopt); continue; }
            try { pattern.push_back(static_cast<std::uint8_t>(std::stoul(token, nullptr, 16))); }
            catch (...) { return fail("bad byte token: " + token); }
        }
        if (pattern.empty()) return fail("empty pattern");
        bool truncated = false;
        const auto matches = db.image().find_pattern(pattern, 500, &truncated);
        json.key("truncated"); json.value(truncated);
        json.key("matches"); json.begin_array();
        for (const auto address : matches) json.value_hex(address);
        json.end_array();
    } else if (command == "search_text") {
        if (argc < 4) return fail("search_text needs text to search for");
        const std::string needle = argv[3];
        std::vector<std::uint8_t> pattern(needle.begin(), needle.end());
        const auto matches = db.image().find_bytes(pattern);
        json.key("matches"); json.begin_array();
        for (std::size_t i = 0; i < matches.size() && i < 500; ++i) json.value_hex(matches[i]);
        json.end_array();
    } else if (command == "auto_analysis") {
        const auto before = db.functions().size();
        const auto report = gandon::run_auto_analysis(db);
        json.key("functions_before"); json.value(static_cast<std::uint64_t>(before));
        json.key("functions_after"); json.value(static_cast<std::uint64_t>(db.functions().size()));
        json.key("functions_added"); json.value(static_cast<std::uint64_t>(report.functions_added));
        json.key("functions_renamed"); json.value(static_cast<std::uint64_t>(report.functions_renamed));
        json.key("import_thunks"); json.value(static_cast<std::uint64_t>(report.import_thunks));
        json.key("noreturn_functions"); json.value(static_cast<std::uint64_t>(report.noreturn_functions));
        json.key("new_names"); json.begin_array();
        for (const auto& [address, name] : report.new_names) {
            json.begin_object();
            json.key("address"); json.value_hex(address);
            json.key("name"); json.value(name);
            json.end_object();
        }
        json.end_array();
        write_functions(json, db, 2000);
    } else if (command == "call_graph") {
        if (argc < 4) return fail("call_graph needs an address");
        const auto target = resolve_target(db, argv[3]);
        if (!target) return fail("could not resolve address/name: " + std::string(argv[3]));
        const auto depth_text = read_all_stdin_arg(argc, argv, 4);
        const int max_depth = depth_text.empty() ? 2 : static_cast<int>(std::strtoul(depth_text.c_str(), nullptr, 10));
        gandon::IdaViews views(db);
        json.key("address"); json.value_hex(*target);
        json.key("edges"); json.begin_array();
        std::vector<std::pair<std::uint64_t, int>> queue{{*target, 0}};
        std::set<std::uint64_t> seen{*target};
        while (!queue.empty()) {
            auto [address, depth] = queue.back(); queue.pop_back();
            if (depth >= max_depth) continue;
            const auto function = db.function_at(address);
            if (!function) continue;
            for (const auto callee : function->get().callees) {
                json.begin_object();
                json.key("from"); json.value_hex(address);
                json.key("from_symbol"); json.value(views.symbolic(address));
                json.key("to"); json.value_hex(callee);
                json.key("to_symbol"); json.value(views.symbolic(callee));
                json.end_object();
                if (seen.insert(callee).second) queue.push_back({callee, depth + 1});
            }
        }
        json.end_array();
    } else if (command == "patch_bytes") {
        if (argc < 6) return fail("patch_bytes needs: <address> <hexbytes> <out_path>");
        const auto target = resolve_target(db, argv[3]);
        if (!target) return fail("could not resolve address/name: " + std::string(argv[3]));
        std::vector<std::uint8_t> replacement;
        std::istringstream tokens(argv[4]);
        std::string token;
        while (tokens >> token) {
            try { replacement.push_back(static_cast<std::uint8_t>(std::stoul(token, nullptr, 16))); }
            catch (...) { return fail("bad byte token: " + token); }
        }
        if (replacement.empty()) return fail("empty replacement bytes");
        std::vector<std::uint8_t> original;
        std::string patch_error;
        if (!db.patch_bytes(*target, replacement, original, patch_error)) return fail("patch failed: " + patch_error);
        std::string write_error;
        if (!db.write_patched_file(argv[5], write_error)) return fail("could not write patched file: " + write_error);
        json.key("address"); json.value_hex(*target);
        json.key("original_bytes"); {
            std::ostringstream hex; for (std::size_t i = 0; i < original.size(); ++i) { if (i) hex << ' '; char b[4]; std::snprintf(b, sizeof(b), "%02X", original[i]); hex << b; }
            json.value(hex.str());
        }
        json.key("new_bytes"); json.value(argv[4]);
        json.key("output_file"); json.value(argv[5]);
    } else {
        return fail("unknown command: " + command);
    }

    json.end_object();
    std::cout << buffer.str() << "\n";
    return 0;
}
