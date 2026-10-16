#include "gandon/types.hpp"
#include <cstdio>
#include <cstdlib>
using namespace gandon;
static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { std::printf("FAIL line %d: %s\n", __LINE__, #cond); ++failures; } } while (0)
int main() {
    TypeLibrary lib(8);
    std::string error;
    CHECK(lib.parse(default_type_declarations(), error));
    if (!error.empty()) std::printf("default decls: %s\n", error.c_str());
    CHECK(lib.size_of("RECT").value_or(0) == 16);
    CHECK(lib.size_of("GUID").value_or(0) == 16);
    CHECK(lib.size_of("LARGE_INTEGER").value_or(0) == 8);
    CHECK(lib.size_of("UNICODE_STRING").value_or(0) == 16);   // 2+2+pad4+ptr8
    CHECK(lib.size_of("LIST_ENTRY").value_or(0) == 16);
    CHECK(lib.size_of("STARTUPINFOW").value_or(0) == 104);
    CHECK(lib.size_of("IMAGE_DOS_HEADER").value_or(0) == 64);
    CHECK(lib.size_of("IMAGE_SECTION_HEADER").value_or(0) == 40);
    CHECK(lib.field_at("RECT", 4) == "top");
    CHECK(lib.field_at("RECT", 6) == "top+2");
    CHECK(lib.field_at("UNICODE_STRING", 8) == "Buffer");
    CHECK(lib.field_at("GUID", 9) == "Data4[1]");
    CHECK(lib.field_at("LARGE_INTEGER", 4) == "QuadPart+4" || lib.field_at("LARGE_INTEGER", 4) == "u.HighPart");
    CHECK(lib.field_at("RECT", 99).empty());
    CHECK(lib.enum_name("PAGE_PROTECTION", 0x40) == "PAGE_EXECUTE_READWRITE");
    CHECK(lib.enum_name("MEM_FLAGS", 0x3000) == "MEM_COMMIT|MEM_RESERVE");
    CHECK(lib.enum_name("MEM_FLAGS", 0x5) .empty());
    TypeLibrary mine(8);
    CHECK(mine.parse("struct Node { int id; struct Node *next; char name[20]; double w; unsigned char flag; };\n"
                     "typedef struct Node Node_t; enum Color { Red, Green = 5, Blue };\n"
                     "typedef struct { short a; long long b; } Pair;", error));
    CHECK(error.empty());
    CHECK(mine.size_of("Node").value_or(0) == 56);   // 4+pad4+8+20+pad4+8+1+pad7
    CHECK(mine.field_at("Node_t", 8) == "next");
    CHECK(mine.field_at("Node", 16) == "name" && mine.field_at("Node", 20) == "name[4]");
    CHECK(mine.enum_name("Color", 6) == "Blue");
    CHECK(mine.size_of("Pair").value_or(0) == 16);
    TypeLibrary bad(8);
    CHECK(!bad.parse("struct X { int a; ", error));
    CHECK(!error.empty());
    std::printf("error sample: %s\n", error.c_str());
    TypeLibrary x86(4);
    CHECK(x86.parse("struct S { char c; void *p; };", error));
    CHECK(x86.size_of("S").value_or(0) == 8);
    auto proto = parse_prototype("int __fastcall CreateThing(HWND hwnd, const char *name, int flags, ...);");
    CHECK(proto.has_value());
    if (proto) {
        CHECK(proto->name == "CreateThing");
        CHECK(proto->calling_convention == "__fastcall");
        CHECK(proto->return_type == "int");
        CHECK(proto->arguments.size() == 3);
        CHECK(proto->variadic);
        std::printf("proto: %s\n", proto->text().c_str());
    }
    auto empty = parse_prototype("void foo(void)");
    CHECK(empty && empty->arguments.empty());
    std::printf("%s\n", lib.format(*lib.resolve("UNICODE_STRING")).c_str());
    std::printf(failures ? "%d failure(s)\n" : "all type tests passed\n", failures);
    return failures ? 1 : 0;
}
