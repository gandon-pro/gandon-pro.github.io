#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace gandon {

// A small C type library: struct / union / enum / typedef declarations parsed
// from C source text, with natural-alignment layout like MSVC/GCC x64 (or x86
// when pointer_size == 4). Used for "Local Types", struct offsets on operands,
// enum constants on immediates and function prototypes.
struct TypeMember {
    std::string name;
    std::string type;          // base type name without pointer / array suffixes
    int pointer_depth{0};
    std::vector<std::uint64_t> dims;  // array dimensions
    std::uint64_t offset{0};
    std::uint64_t size{0};     // total size of the member (including arrays)
    std::string declaration() const;  // "char name[16]"
};

struct TypeDef {
    enum class Kind { Struct, Union, Enum, Alias };
    Kind kind{Kind::Struct};
    std::string name;
    std::vector<TypeMember> members;                         // struct/union
    std::vector<std::pair<std::string, std::int64_t>> enumerators;  // enum
    std::string alias_of;      // Alias: target base type
    int alias_pointer_depth{0};
    std::vector<std::uint64_t> alias_dims;
    std::uint64_t size{0};
    std::uint64_t alignment{1};
};

struct FunctionPrototype {
    std::string return_type;
    std::string calling_convention;
    std::string name;
    std::vector<std::pair<std::string, std::string>> arguments;  // {type, name}
    bool variadic{false};
    std::string text() const;  // normalised "int __fastcall name(HWND hwnd, int x)"
};

class TypeLibrary {
public:
    explicit TypeLibrary(int pointer_size = 8);

    // Parses declarations and adds / replaces types. Returns false and fills
    // `error` (with a line number) on a syntax error; types parsed before the
    // error are kept.
    bool parse(const std::string& source, std::string& error);
    void clear();

    const TypeDef* find(const std::string& name) const;
    // Follows typedef aliases ("POINT" -> struct _POINT); null when unknown or when it ends in a pointer / array.
    const TypeDef* resolve(const std::string& name) const;
    std::vector<std::string> names() const;
    std::optional<std::uint64_t> size_of(const std::string& type, int pointer_depth = 0) const;

    // "field.sub[2]" for a byte offset inside `type` ("" if out of range).
    // A remainder inside a scalar is appended as "+N".
    std::string field_at(const std::string& type, std::uint64_t offset) const;
    // Enumerator name for a value ("" when not found). Bit-flag enums are
    // rendered as "A|B" when every set bit has a name.
    std::string enum_name(const std::string& type, std::uint64_t value) const;

    // Pretty IDA-like listing of every type with offsets.
    std::string format() const;
    std::string format(const TypeDef& type) const;

    int pointer_size() const noexcept { return pointer_size_; }

private:
    std::optional<std::pair<std::uint64_t, std::uint64_t>> layout_of(const std::string& type, int pointer_depth) const;  // size, alignment
    void layout(TypeDef& type) const;

    int pointer_size_{8};
    std::map<std::string, TypeDef> types_;
    std::vector<std::string> order_;
};

// Parses "int __fastcall name(HWND hwnd, int x, ...)" (a trailing ';' is allowed).
std::optional<FunctionPrototype> parse_prototype(const std::string& text);

// Declarations shipped by default (common Windows structs and enums).
const char* default_type_declarations();

} // namespace gandon
