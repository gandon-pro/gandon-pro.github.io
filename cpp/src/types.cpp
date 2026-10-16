#include "gandon/types.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>

namespace gandon {
namespace {

// ---------------------------------------------------------------- tokens
struct Token {
    enum Kind { End, Ident, Number, Punct } kind{End};
    std::string text;
    int line{1};
};

std::vector<Token> tokenize(const std::string& source) {
    std::vector<Token> out;
    int line = 1;
    std::size_t i = 0;
    const std::size_t n = source.size();
    while (i < n) {
        const char c = source[i];
        if (c == '\n') { ++line; ++i; continue; }
        if (std::isspace(static_cast<unsigned char>(c))) { ++i; continue; }
        if (c == '/' && i + 1 < n && source[i + 1] == '/') { while (i < n && source[i] != '\n') ++i; continue; }
        if (c == '/' && i + 1 < n && source[i + 1] == '*') {
            i += 2;
            while (i + 1 < n && !(source[i] == '*' && source[i + 1] == '/')) { if (source[i] == '\n') ++line; ++i; }
            i += 2; continue;
        }
        if (c == '#') { while (i < n && source[i] != '\n') ++i; continue; }  // preprocessor lines are ignored
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
            std::size_t j = i;
            while (j < n && (std::isalnum(static_cast<unsigned char>(source[j])) || source[j] == '_')) ++j;
            out.push_back({Token::Ident, source.substr(i, j - i), line}); i = j; continue;
        }
        if (std::isdigit(static_cast<unsigned char>(c))) {
            std::size_t j = i;
            while (j < n && (std::isalnum(static_cast<unsigned char>(source[j])))) ++j;
            out.push_back({Token::Number, source.substr(i, j - i), line}); i = j; continue;
        }
        if (c == '.' && i + 2 < n && source[i + 1] == '.' && source[i + 2] == '.') { out.push_back({Token::Punct, "...", line}); i += 3; continue; }
        out.push_back({Token::Punct, std::string(1, c), line}); ++i;
    }
    out.push_back({Token::End, "", line});
    return out;
}

bool parse_number(const std::string& text, std::int64_t& value) {
    try {
        std::string t = text;
        while (!t.empty() && (t.back() == 'u' || t.back() == 'U' || t.back() == 'l' || t.back() == 'L')) t.pop_back();
        if (t.empty()) return false;
        value = static_cast<std::int64_t>(std::stoull(t, nullptr, 0));
        return true;
    } catch (...) { return false; }
}

struct Builtin { const char* name; std::uint64_t size; };
const Builtin kBuiltins[] = {
    {"char", 1}, {"signed char", 1}, {"unsigned char", 1}, {"short", 2}, {"unsigned short", 2}, {"int", 4}, {"unsigned int", 4},
    {"long", 4}, {"unsigned long", 4}, {"long long", 8}, {"unsigned long long", 8}, {"float", 4}, {"double", 8}, {"long double", 8},
    {"void", 1}, {"bool", 1}, {"wchar_t", 2},
    {"int8_t", 1}, {"uint8_t", 1}, {"int16_t", 2}, {"uint16_t", 2}, {"int32_t", 4}, {"uint32_t", 4}, {"int64_t", 8}, {"uint64_t", 8},
    {"__int8", 1}, {"__int16", 2}, {"__int32", 4}, {"__int64", 8},
    {"BYTE", 1}, {"CHAR", 1}, {"UCHAR", 1}, {"BOOLEAN", 1}, {"WORD", 2}, {"WCHAR", 2}, {"SHORT", 2}, {"USHORT", 2}, {"DWORD", 4}, {"UINT", 4},
    {"INT", 4}, {"LONG", 4}, {"ULONG", 4}, {"BOOL", 4}, {"FLOAT", 4}, {"DWORD32", 4}, {"INT32", 4}, {"UINT32", 4}, {"QWORD", 8},
    {"DWORD64", 8}, {"INT64", 8}, {"UINT64", 8}, {"LONGLONG", 8}, {"ULONGLONG", 8}, {"DOUBLE", 8},
};

bool is_qualifier(const std::string& s) {
    return s == "const" || s == "volatile" || s == "static" || s == "extern" || s == "register" || s == "inline" || s == "__declspec" ||
           s == "__unaligned" || s == "__restrict" || s == "restrict";
}

// ---------------------------------------------------------------- parser
class Parser {
public:
    Parser(TypeLibrary& library, std::vector<Token> tokens) : lib_(library), t_(std::move(tokens)) {}
    bool run(std::map<std::string, TypeDef>& types, std::vector<std::string>& order, std::string& error);

private:
    struct Decl { std::string base; int pointers{0}; std::string name; std::vector<std::uint64_t> dims; bool ok{false}; };

    const Token& peek(std::size_t ahead = 0) const { return t_[std::min(pos_ + ahead, t_.size() - 1)]; }
    bool is(const char* punct) const { return peek().kind == Token::Punct && peek().text == punct; }
    bool is_ident(const char* word) const { return peek().kind == Token::Ident && peek().text == word; }
    bool accept(const char* punct) { if (is(punct)) { ++pos_; return true; } return false; }
    void fail(const std::string& message) { if (error_.empty()) error_ = "line " + std::to_string(peek().line) + ": " + message; }
    void skip_to_semicolon() { while (peek().kind != Token::End && !is(";")) ++pos_; accept(";"); }

    std::string parse_specifiers();  // returns base type name ("" on failure)
    bool parse_declarator(const std::string& base, Decl& decl);
    bool parse_body(TypeDef& def, TypeDef::Kind kind);
    bool parse_enum_body(TypeDef& def);
    bool parse_top();
    void add_type(TypeDef def);
    std::string synthetic_name() { return "__anon_" + std::to_string(++anon_); }

public:
    TypeLibrary& lib_;
    std::vector<Token> t_;
    std::size_t pos_{0};
    std::string error_;
    int anon_{0};
    std::vector<TypeDef> parsed_;
};

void Parser::add_type(TypeDef def) { parsed_.push_back(std::move(def)); }

std::string Parser::parse_specifiers() {
    std::vector<std::string> words;
    bool saw_tag_type = false;
    std::string result;
    while (peek().kind == Token::Ident) {
        const std::string word = peek().text;
        if (is_qualifier(word)) {
            ++pos_;
            if (word == "__declspec") { if (accept("(")) { int depth = 1; while (depth && peek().kind != Token::End) { if (is("(")) ++depth; else if (is(")")) --depth; ++pos_; } } }
            continue;
        }
        if (word == "struct" || word == "union" || word == "enum") {
            ++pos_;
            const auto kind = word == "struct" ? TypeDef::Kind::Struct : word == "union" ? TypeDef::Kind::Union : TypeDef::Kind::Enum;
            std::string tag;
            if (peek().kind == Token::Ident) { tag = peek().text; ++pos_; }
            if (is("{")) {
                if (tag.empty()) tag = synthetic_name();
                TypeDef def; def.kind = kind; def.name = tag;
                ++pos_;
                const bool ok = kind == TypeDef::Kind::Enum ? parse_enum_body(def) : parse_body(def, kind);
                if (!ok) return "";
                add_type(std::move(def));
            }
            if (tag.empty()) { fail("expected a type name"); return ""; }
            result = tag; saw_tag_type = true;
            continue;
        }
        if (word == "unsigned" || word == "signed" || word == "long" || word == "short" || word == "int" || word == "char" || word == "double" || word == "float") {
            words.push_back(word); ++pos_; continue;
        }
        if (!words.empty() || saw_tag_type) break;
        if (!result.empty()) break;
        result = word; ++pos_;
        // typedef names (and builtins like uint32_t) are a single identifier
        if (peek().kind == Token::Ident && !is_qualifier(peek().text)) {
            // "NAME declarator" -> stop; the next identifier is the declarator name
        }
        break;
    }
    if (!words.empty()) {
        bool is_unsigned = false, is_signed = false; int longs = 0; std::string core;
        for (const auto& w : words) {
            if (w == "unsigned") is_unsigned = true; else if (w == "signed") is_signed = true;
            else if (w == "long") ++longs; else core = w;
        }
        std::string name;
        if (core == "double" && longs) name = "long double";
        else if (core == "double" || core == "float") name = core;
        else if (core == "char") name = is_unsigned ? "unsigned char" : is_signed ? "signed char" : "char";
        else if (core == "short") name = is_unsigned ? "unsigned short" : "short";
        else if (longs >= 2) name = is_unsigned ? "unsigned long long" : "long long";
        else if (longs == 1) name = is_unsigned ? "unsigned long" : "long";
        else name = is_unsigned ? "unsigned int" : "int";
        if (core == "short" && longs) name = is_unsigned ? "unsigned short" : "short";
        return name;
    }
    if (result.empty()) fail("expected a type");
    return result;
}

bool Parser::parse_declarator(const std::string& base, Decl& decl) {
    decl = Decl{}; decl.base = base;
    while (true) {
        if (accept("*")) { ++decl.pointers; continue; }
        if (peek().kind == Token::Ident && is_qualifier(peek().text)) { ++pos_; continue; }
        if (peek().kind == Token::Ident && (peek().text == "__cdecl" || peek().text == "__stdcall" || peek().text == "__fastcall" || peek().text == "__ptr64")) { ++pos_; continue; }
        break;
    }
    if (peek().kind != Token::Ident) { fail("expected a name"); return false; }
    decl.name = peek().text; ++pos_;
    while (accept("[")) {
        std::int64_t value = 0;
        if (peek().kind == Token::Number && parse_number(peek().text, value)) { ++pos_; decl.dims.push_back(static_cast<std::uint64_t>(value)); }
        else if (accept("]")) { decl.dims.push_back(0); continue; }
        else { fail("array size must be a number"); return false; }
        if (!accept("]")) { fail("expected ']'"); return false; }
    }
    if (accept(":")) { std::int64_t bits = 0; if (peek().kind == Token::Number) parse_number(peek().text, bits); ++pos_; }  // bit-fields keep the declared type
    decl.ok = true;
    return true;
}

bool Parser::parse_body(TypeDef& def, TypeDef::Kind) {
    while (!is("}")) {
        if (peek().kind == Token::End) { fail("unterminated struct"); return false; }
        const std::string base = parse_specifiers();
        if (base.empty()) return false;
        while (true) {
            Decl decl;
            if (!parse_declarator(base, decl)) return false;
            TypeMember member; member.name = decl.name; member.type = decl.base; member.pointer_depth = decl.pointers; member.dims = decl.dims;
            def.members.push_back(std::move(member));
            if (accept(",")) continue;
            break;
        }
        if (!accept(";")) { fail("expected ';'"); return false; }
    }
    ++pos_;  // }
    return true;
}

bool Parser::parse_enum_body(TypeDef& def) {
    std::int64_t next = 0;
    while (!is("}")) {
        if (peek().kind != Token::Ident) { fail("expected an enumerator name"); return false; }
        const std::string name = peek().text; ++pos_;
        if (accept("=")) {
            bool negative = accept("-");
            std::int64_t value = 0;
            if (peek().kind == Token::Number && parse_number(peek().text, value)) { ++pos_; next = negative ? -value : value; }
            else if (peek().kind == Token::Ident) {  // reference to an earlier enumerator
                bool found = false;
                for (const auto& e : def.enumerators) if (e.first == peek().text) { next = e.second; found = true; }
                if (!found) { fail("unknown enumerator '" + peek().text + "'"); return false; }
                ++pos_;
            } else { fail("expected a number"); return false; }
            // simple "A | B" / "1 << n" expressions
            while (is("|") || is("<")) {
                if (accept("<")) { accept("<"); std::int64_t shift = 0; if (peek().kind == Token::Number) { parse_number(peek().text, shift); ++pos_; } next <<= shift; }
                else { ++pos_; std::int64_t other = 0; if (peek().kind == Token::Number) { parse_number(peek().text, other); ++pos_; }
                       else if (peek().kind == Token::Ident) { for (const auto& e : def.enumerators) if (e.first == peek().text) other = e.second; ++pos_; }
                       next |= other; }
            }
        }
        def.enumerators.emplace_back(name, next++);
        if (!accept(",")) break;
    }
    if (!accept("}")) { fail("expected '}'"); return false; }
    return true;
}

bool Parser::parse_top() {
    if (accept(";")) return true;
    const bool is_typedef = is_ident("typedef");
    if (is_typedef) ++pos_;
    const std::size_t before = parsed_.size();
    const std::string base = parse_specifiers();
    if (base.empty()) return false;
    if (accept(";")) return true;  // plain "struct X { ... };"
    // function declarations / globals are skipped
    while (true) {
        Decl decl;
        if (is("(")) { skip_to_semicolon(); return true; }
        if (!parse_declarator(base, decl)) return false;
        if (is("(")) { skip_to_semicolon(); return true; }
        if (is_typedef) {
            TypeDef alias; alias.kind = TypeDef::Kind::Alias; alias.name = decl.name; alias.alias_of = decl.base;
            alias.alias_pointer_depth = decl.pointers; alias.alias_dims = decl.dims;
            // "typedef struct _X {..} X;" - when the tag is already the same name there is nothing to add
            if (!(decl.pointers == 0 && decl.dims.empty() && decl.base == decl.name)) add_type(std::move(alias));
        }
        if (accept(",")) continue;
        break;
    }
    (void)before;
    if (!accept(";")) { fail("expected ';'"); return false; }
    return true;
}

bool Parser::run(std::map<std::string, TypeDef>&, std::vector<std::string>&, std::string& error) {
    while (peek().kind != Token::End) {
        const auto start = pos_;
        if (!parse_top()) {
            error = error_;
            return false;
        }
        if (pos_ == start) ++pos_;
    }
    return true;
}

} // namespace

// ------------------------------------------------------------ TypeMember
std::string TypeMember::declaration() const {
    std::string out = type;
    out += ' ';
    out += std::string(static_cast<std::size_t>(pointer_depth), '*');
    out += name;
    for (const auto d : dims) out += "[" + std::to_string(d) + "]";
    return out;
}

// ----------------------------------------------------------- TypeLibrary
TypeLibrary::TypeLibrary(int pointer_size) : pointer_size_(pointer_size == 4 ? 4 : 8) {}

void TypeLibrary::clear() { types_.clear(); order_.clear(); }

const TypeDef* TypeLibrary::find(const std::string& name) const {
    const auto it = types_.find(name);
    return it == types_.end() ? nullptr : &it->second;
}

const TypeDef* TypeLibrary::resolve(const std::string& name) const {
    const TypeDef* def = find(name);
    for (int guard = 0; def && def->kind == TypeDef::Kind::Alias && guard < 16; ++guard) {
        if (def->alias_pointer_depth || !def->alias_dims.empty()) return nullptr;
        def = find(def->alias_of);
    }
    return def && def->kind != TypeDef::Kind::Alias ? def : nullptr;
}

std::vector<std::string> TypeLibrary::names() const { return order_; }

std::optional<std::pair<std::uint64_t, std::uint64_t>> TypeLibrary::layout_of(const std::string& type, int pointer_depth) const {
    if (pointer_depth > 0) return std::make_pair<std::uint64_t, std::uint64_t>(static_cast<std::uint64_t>(pointer_size_), static_cast<std::uint64_t>(pointer_size_));
    if (const auto it = types_.find(type); it != types_.end()) {
        const TypeDef& def = it->second;
        if (def.kind == TypeDef::Kind::Alias) {
            auto inner = layout_of(def.alias_of, def.alias_pointer_depth);
            if (!inner) return std::nullopt;
            std::uint64_t count = 1; for (const auto d : def.alias_dims) count *= d ? d : 1;
            return std::make_pair(inner->first * count, inner->second);
        }
        if (def.kind == TypeDef::Kind::Enum) return std::make_pair<std::uint64_t, std::uint64_t>(4, 4);
        return std::make_pair(def.size, def.alignment);
    }
    for (const auto& builtin : kBuiltins)
        if (type == builtin.name) return std::make_pair(builtin.size, std::min<std::uint64_t>(builtin.size, 8));
    // Win32 pointer typedefs: HANDLE, LPVOID, PXXX, LPXXX, size_t, ...
    if (type == "size_t" || type == "ssize_t" || type == "uintptr_t" || type == "intptr_t" || type == "ptrdiff_t" || type == "SIZE_T" || type == "ULONG_PTR" ||
        type == "LONG_PTR" || type == "DWORD_PTR" || type == "UINT_PTR" || type == "INT_PTR" || type == "WPARAM" || type == "LPARAM" || type == "LRESULT" ||
        type == "HANDLE" || type == "HWND" || type == "HMODULE" || type == "HINSTANCE" || type == "HDC" || type == "HKEY" || type == "PVOID" || type == "LPVOID" ||
        type == "LPCVOID" || type == "LPSTR" || type == "LPCSTR" || type == "LPWSTR" || type == "LPCWSTR" || type == "PWSTR" || type == "PSTR")
        return std::make_pair<std::uint64_t, std::uint64_t>(static_cast<std::uint64_t>(pointer_size_), static_cast<std::uint64_t>(pointer_size_));
    return std::nullopt;
}

std::optional<std::uint64_t> TypeLibrary::size_of(const std::string& type, int pointer_depth) const {
    const auto layout = layout_of(type, pointer_depth);
    if (!layout) return std::nullopt;
    return layout->first;
}

void TypeLibrary::layout(TypeDef& def) const {
    if (def.kind != TypeDef::Kind::Struct && def.kind != TypeDef::Kind::Union) return;
    std::uint64_t offset = 0, max_align = 1, max_size = 0;
    for (auto& member : def.members) {
        const auto info = layout_of(member.type, member.pointer_depth);
        const std::uint64_t element = info ? info->first : 0;
        const std::uint64_t align = info ? std::max<std::uint64_t>(info->second, 1) : 1;
        std::uint64_t count = 1; for (const auto d : member.dims) count *= d ? d : 1;
        member.size = element * count;
        max_align = std::max(max_align, align);
        if (def.kind == TypeDef::Kind::Struct) {
            offset = (offset + align - 1) / align * align;
            member.offset = offset;
            offset += member.size;
        } else {
            member.offset = 0;
            max_size = std::max(max_size, member.size);
        }
    }
    def.alignment = max_align;
    const std::uint64_t raw = def.kind == TypeDef::Kind::Struct ? offset : max_size;
    def.size = (raw + max_align - 1) / max_align * max_align;
}

bool TypeLibrary::parse(const std::string& source, std::string& error) {
    error.clear();
    Parser parser(*const_cast<TypeLibrary*>(this), tokenize(source));
    std::map<std::string, TypeDef> unused_types; std::vector<std::string> unused_order;
    const bool ok = parser.run(unused_types, unused_order, error);
    for (auto& def : parser.parsed_) {
        layout(def);
        if (!types_.contains(def.name)) order_.push_back(def.name);
        types_[def.name] = std::move(def);
        // types are laid out as they appear, so later members can refer to earlier ones
    }
    // second pass: members that referenced types declared later
    for (auto& [name, def] : types_) layout(def);
    return ok;
}

std::string TypeLibrary::field_at(const std::string& type, std::uint64_t offset) const {
    auto resolved = [&](std::string name) {
        for (int guard = 0; guard < 16; ++guard) {
            const auto it = types_.find(name);
            if (it == types_.end() || it->second.kind != TypeDef::Kind::Alias || it->second.alias_pointer_depth) break;
            name = it->second.alias_of;
        }
        return name;
    };
    const std::string name = resolved(type);
    const auto it = types_.find(name);
    if (it == types_.end() || (it->second.kind != TypeDef::Kind::Struct && it->second.kind != TypeDef::Kind::Union)) return "";
    const TypeDef& def = it->second;
    if (offset >= def.size && def.size != 0) return "";
    const TypeMember* best = nullptr;
    for (const auto& member : def.members)
        if (offset >= member.offset && offset < member.offset + std::max<std::uint64_t>(member.size, 1)) { best = &member; if (def.kind == TypeDef::Kind::Struct) break; }
    if (!best) return "";
    std::string text = best->name;
    std::uint64_t inside = offset - best->offset;
    std::uint64_t element = best->size;
    if (!best->dims.empty()) {
        std::uint64_t count = 1; for (const auto d : best->dims) count *= d ? d : 1;
        element = count ? best->size / count : best->size;
        if (element) {
            if (inside / element != 0) text += "[" + std::to_string(inside / element) + "]";
            inside %= element;
        }
    }
    if (best->pointer_depth == 0) {
        const std::string nested = inside || types_.contains(resolved(best->type)) ? field_at(best->type, inside) : "";
        if (!nested.empty()) return text + "." + nested;
    }
    if (inside) text += "+" + std::to_string(inside);
    return text;
}

std::string TypeLibrary::enum_name(const std::string& type, std::uint64_t value) const {
    const auto it = types_.find(type);
    if (it == types_.end() || it->second.kind != TypeDef::Kind::Enum) return "";
    for (const auto& e : it->second.enumerators) if (static_cast<std::uint64_t>(e.second) == value) return e.first;
    // bit flags
    std::string text; std::uint64_t remaining = value;
    for (const auto& e : it->second.enumerators) {
        const auto v = static_cast<std::uint64_t>(e.second);
        if (v && (v & (v - 1)) == 0 && (remaining & v)) { if (!text.empty()) text += "|"; text += e.first; remaining &= ~v; }
    }
    return remaining == 0 ? text : "";
}

std::string TypeLibrary::format(const TypeDef& def) const {
    std::ostringstream out;
    char buffer[64];
    switch (def.kind) {
    case TypeDef::Kind::Alias: {
        out << "typedef " << def.alias_of << ' ' << std::string(static_cast<std::size_t>(def.alias_pointer_depth), '*') << def.name;
        for (const auto d : def.alias_dims) out << '[' << d << ']';
        out << ";\n";
        break;
    }
    case TypeDef::Kind::Enum: {
        out << "enum " << def.name << "\n{\n";
        for (const auto& e : def.enumerators) {
            std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(e.second));
            out << "  " << e.first << " = " << buffer << ",\n";
        }
        out << "};\n";
        break;
    }
    default: {
        std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(def.size));
        out << (def.kind == TypeDef::Kind::Struct ? "struct " : "union ") << def.name << "  // size " << buffer << "\n{\n";
        for (const auto& member : def.members) {
            std::snprintf(buffer, sizeof(buffer), "  /*0x%02llX*/ ", static_cast<unsigned long long>(member.offset));
            out << buffer << member.declaration() << ";\n";
        }
        out << "};\n";
        break;
    }
    }
    return out.str();
}

std::string TypeLibrary::format() const {
    std::string out;
    for (const auto& name : order_) {
        const auto it = types_.find(name);
        if (it == types_.end() || name.rfind("__anon_", 0) == 0) continue;
        if (it->second.kind == TypeDef::Kind::Alias && resolve(name) && it->second.alias_pointer_depth == 0 && it->second.alias_dims.empty()) {
            out += "typedef " + it->second.alias_of + " " + name + ";\n\n"; continue;
        }
        out += format(it->second);
        out += '\n';
    }
    return out;
}

// ---------------------------------------------------------- prototypes
std::string FunctionPrototype::text() const {
    std::string out = return_type;
    if (!calling_convention.empty()) out += " " + calling_convention;
    out += " " + name + "(";
    for (std::size_t i = 0; i < arguments.size(); ++i) {
        if (i) out += ", ";
        out += arguments[i].first;
        if (!arguments[i].second.empty()) out += (arguments[i].first.empty() || arguments[i].first.back() == '*' ? "" : " ") + arguments[i].second;
    }
    if (variadic) out += arguments.empty() ? "..." : ", ...";
    else if (arguments.empty()) out += "void";
    return out + ")";
}

std::optional<FunctionPrototype> parse_prototype(const std::string& text) {
    const auto tokens = tokenize(text);
    std::size_t open = 0;
    while (open < tokens.size() && !(tokens[open].kind == Token::Punct && tokens[open].text == "(")) ++open;
    if (open == 0 || open >= tokens.size()) return std::nullopt;
    FunctionPrototype proto;
    // tokens before '(' : return type, calling convention, name
    std::vector<std::string> head;
    for (std::size_t i = 0; i < open; ++i) head.push_back(tokens[i].text);
    if (head.size() < 2) return std::nullopt;
    proto.name = head.back(); head.pop_back();
    static const char* conventions[] = {"__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall", "WINAPI", "APIENTRY", "CALLBACK", "NTAPI"};
    std::string rt;
    for (const auto& word : head) {
        bool conv = false;
        for (const auto* c : conventions) if (word == c) { conv = true; proto.calling_convention = word; }
        if (conv || is_qualifier(word)) continue;
        if (!rt.empty() && word != "*") rt += ' ';
        rt += word;
    }
    proto.return_type = rt;
    if (proto.return_type.empty()) return std::nullopt;
    std::size_t i = open + 1;
    std::vector<std::vector<std::string>> args(1);
    int depth = 1;
    for (; i < tokens.size() && tokens[i].kind != Token::End; ++i) {
        const auto& token = tokens[i];
        if (token.kind == Token::Punct && token.text == "(") ++depth;
        if (token.kind == Token::Punct && token.text == ")") { if (--depth == 0) break; }
        if (token.kind == Token::Punct && token.text == "," && depth == 1) { args.emplace_back(); continue; }
        args.back().push_back(token.text);
    }
    if (depth != 0) return std::nullopt;
    for (auto& arg : args) {
        if (arg.empty()) continue;
        if (arg.size() == 1 && arg[0] == "void") continue;
        if (arg.size() == 1 && arg[0] == "...") { proto.variadic = true; continue; }
        std::string type, name;
        std::size_t last = arg.size();
        // the last identifier is the name when something other than '*' / qualifiers precedes it
        std::size_t idents = 0;
        for (const auto& word : arg) if (!word.empty() && (std::isalpha(static_cast<unsigned char>(word[0])) || word[0] == '_') && !is_qualifier(word)) ++idents;
        if (idents >= 2 && !arg.empty() && (std::isalpha(static_cast<unsigned char>(arg.back()[0])) || arg.back()[0] == '_')) { name = arg.back(); last = arg.size() - 1; }
        for (std::size_t k = 0; k < last; ++k) {
            if (arg[k] == "__declspec") continue;
            if (arg[k] == "*") { type += type.empty() || type.back() == '*' ? "*" : " *"; continue; }
            if (!type.empty() && type.back() != '*') type += ' ';
            type += arg[k];
        }
        proto.arguments.emplace_back(type, name);
    }
    return proto;
}

const char* default_type_declarations() {
    return R"TYPES(
typedef struct _POINT { LONG x; LONG y; } POINT;
typedef struct _SIZE { LONG cx; LONG cy; } SIZE;
typedef struct _RECT { LONG left; LONG top; LONG right; LONG bottom; } RECT;
typedef struct _GUID { DWORD Data1; WORD Data2; WORD Data3; BYTE Data4[8]; } GUID;
typedef struct _FILETIME { DWORD dwLowDateTime; DWORD dwHighDateTime; } FILETIME;
typedef struct _SYSTEMTIME { WORD wYear; WORD wMonth; WORD wDayOfWeek; WORD wDay; WORD wHour; WORD wMinute; WORD wSecond; WORD wMilliseconds; } SYSTEMTIME;
typedef union _LARGE_INTEGER { struct { DWORD LowPart; LONG HighPart; } u; LONGLONG QuadPart; } LARGE_INTEGER;
typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink; struct _LIST_ENTRY *Blink; } LIST_ENTRY;
typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING;
typedef struct _STRING { USHORT Length; USHORT MaximumLength; PSTR Buffer; } STRING;
typedef struct _OVERLAPPED { ULONG_PTR Internal; ULONG_PTR InternalHigh; DWORD Offset; DWORD OffsetHigh; HANDLE hEvent; } OVERLAPPED;
typedef struct _SECURITY_ATTRIBUTES { DWORD nLength; LPVOID lpSecurityDescriptor; BOOL bInheritHandle; } SECURITY_ATTRIBUTES;
typedef struct _PROCESS_INFORMATION { HANDLE hProcess; HANDLE hThread; DWORD dwProcessId; DWORD dwThreadId; } PROCESS_INFORMATION;
typedef struct _STARTUPINFOW {
  DWORD cb; LPWSTR lpReserved; LPWSTR lpDesktop; LPWSTR lpTitle; DWORD dwX; DWORD dwY; DWORD dwXSize; DWORD dwYSize;
  DWORD dwXCountChars; DWORD dwYCountChars; DWORD dwFillAttribute; DWORD dwFlags; WORD wShowWindow; WORD cbReserved2;
  BYTE *lpReserved2; HANDLE hStdInput; HANDLE hStdOutput; HANDLE hStdError;
} STARTUPINFOW;
typedef struct _MEMORY_BASIC_INFORMATION {
  PVOID BaseAddress; PVOID AllocationBase; DWORD AllocationProtect; SIZE_T RegionSize; DWORD State; DWORD Protect; DWORD Type;
} MEMORY_BASIC_INFORMATION;
typedef struct _MSG { HWND hwnd; UINT message; WPARAM wParam; LPARAM lParam; DWORD time; POINT pt; } MSG;
typedef struct _WNDCLASSW {
  UINT style; PVOID lpfnWndProc; int cbClsExtra; int cbWndExtra; HINSTANCE hInstance; HANDLE hIcon; HANDLE hCursor; HANDLE hbrBackground;
  LPCWSTR lpszMenuName; LPCWSTR lpszClassName;
} WNDCLASSW;
typedef struct _EXCEPTION_RECORD {
  DWORD ExceptionCode; DWORD ExceptionFlags; struct _EXCEPTION_RECORD *ExceptionRecord; PVOID ExceptionAddress;
  DWORD NumberParameters; ULONG_PTR ExceptionInformation[15];
} EXCEPTION_RECORD;
typedef struct _IMAGE_DOS_HEADER {
  WORD e_magic; WORD e_cblp; WORD e_cp; WORD e_crlc; WORD e_cparhdr; WORD e_minalloc; WORD e_maxalloc; WORD e_ss; WORD e_sp;
  WORD e_csum; WORD e_ip; WORD e_cs; WORD e_lfarlc; WORD e_ovno; WORD e_res[4]; WORD e_oemid; WORD e_oeminfo; WORD e_res2[10]; LONG e_lfanew;
} IMAGE_DOS_HEADER;
typedef struct _IMAGE_FILE_HEADER {
  WORD Machine; WORD NumberOfSections; DWORD TimeDateStamp; DWORD PointerToSymbolTable; DWORD NumberOfSymbols; WORD SizeOfOptionalHeader; WORD Characteristics;
} IMAGE_FILE_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY { DWORD VirtualAddress; DWORD Size; } IMAGE_DATA_DIRECTORY;
typedef struct _IMAGE_SECTION_HEADER {
  BYTE Name[8]; DWORD VirtualSize; DWORD VirtualAddress; DWORD SizeOfRawData; DWORD PointerToRawData; DWORD PointerToRelocations;
  DWORD PointerToLinenumbers; WORD NumberOfRelocations; WORD NumberOfLinenumbers; DWORD Characteristics;
} IMAGE_SECTION_HEADER;
typedef struct _IMAGE_IMPORT_DESCRIPTOR { DWORD OriginalFirstThunk; DWORD TimeDateStamp; DWORD ForwarderChain; DWORD Name; DWORD FirstThunk; } IMAGE_IMPORT_DESCRIPTOR;
typedef struct _IMAGE_EXPORT_DIRECTORY {
  DWORD Characteristics; DWORD TimeDateStamp; WORD MajorVersion; WORD MinorVersion; DWORD Name; DWORD Base; DWORD NumberOfFunctions;
  DWORD NumberOfNames; DWORD AddressOfFunctions; DWORD AddressOfNames; DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;
enum PAGE_PROTECTION { PAGE_NOACCESS = 0x01, PAGE_READONLY = 0x02, PAGE_READWRITE = 0x04, PAGE_WRITECOPY = 0x08, PAGE_EXECUTE = 0x10,
  PAGE_EXECUTE_READ = 0x20, PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE_WRITECOPY = 0x80, PAGE_GUARD = 0x100 };
enum MEM_FLAGS { MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, MEM_DECOMMIT = 0x4000, MEM_RELEASE = 0x8000, MEM_RESET = 0x80000, MEM_TOP_DOWN = 0x100000 };
enum ACCESS_RIGHTS { DELETE = 0x10000, READ_CONTROL = 0x20000, SYNCHRONIZE = 0x100000, GENERIC_ALL = 0x10000000, GENERIC_EXECUTE = 0x20000000,
  GENERIC_WRITE = 0x40000000, GENERIC_READ = 0x80000000 };
enum FILE_SHARE { FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, FILE_SHARE_DELETE = 4 };
enum CREATE_DISPOSITION { CREATE_NEW = 1, CREATE_ALWAYS = 2, OPEN_EXISTING = 3, OPEN_ALWAYS = 4, TRUNCATE_EXISTING = 5 };
enum SHOW_WINDOW { SW_HIDE = 0, SW_SHOWNORMAL = 1, SW_SHOWMINIMIZED = 2, SW_SHOWMAXIMIZED = 3, SW_SHOW = 5, SW_MINIMIZE = 6, SW_RESTORE = 9 };
enum PROCESS_ACCESS { PROCESS_TERMINATE = 1, PROCESS_CREATE_THREAD = 2, PROCESS_VM_OPERATION = 8, PROCESS_VM_READ = 0x10, PROCESS_VM_WRITE = 0x20,
  PROCESS_QUERY_INFORMATION = 0x400, PROCESS_ALL_ACCESS = 0x1FFFFF };
enum WAIT_RESULT { WAIT_OBJECT_0 = 0, WAIT_ABANDONED = 0x80, WAIT_TIMEOUT = 0x102, WAIT_FAILED = 0xFFFFFFFF };
enum WIN_ERROR { ERROR_SUCCESS = 0, ERROR_FILE_NOT_FOUND = 2, ERROR_PATH_NOT_FOUND = 3, ERROR_ACCESS_DENIED = 5, ERROR_INVALID_HANDLE = 6,
  ERROR_NOT_ENOUGH_MEMORY = 8, ERROR_INVALID_PARAMETER = 87, ERROR_INSUFFICIENT_BUFFER = 122, ERROR_MORE_DATA = 234 };
)TYPES";
}

} // namespace gandon
