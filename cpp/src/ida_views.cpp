#include "gandon/ida_views.hpp"

#include "gandon/image_tables.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace gandon {
namespace {

constexpr const char* kUp = "\xE2\x86\x91";   // ↑
constexpr const char* kDown = "\xE2\x86\x93"; // ↓

std::string hex(std::uint64_t value, int width = 0) {
    char buffer[40];
    std::snprintf(buffer, sizeof buffer, "%0*llX", width, static_cast<unsigned long long>(value));
    return buffer;
}

// IDA number style: 0..9 decimal, otherwise upper-case hex with trailing 'h'
// and a leading 0 when the first digit is a letter.
std::string ida_number(std::uint64_t value) {
    if (value < 10) return std::to_string(value);
    auto text = hex(value);
    if (std::isalpha(static_cast<unsigned char>(text[0]))) text.insert(text.begin(), '0');
    return text + "h";
}

std::string pad(std::string text, std::size_t width) {
    if (text.size() < width) text.append(width - text.size(), ' ');
    return text;
}

bool is_hex_literal(const std::string& s, std::size_t pos, std::size_t& end) {
    if (pos + 2 >= s.size() + 0 || s[pos] != '0' || (s[pos + 1] != 'x' && s[pos + 1] != 'X')) return false;
    end = pos + 2;
    while (end < s.size() && std::isxdigit(static_cast<unsigned char>(s[end]))) ++end;
    return end > pos + 2;
}

bool parse_hex_literal(const std::string& s, std::uint64_t& value) {
    std::size_t end = 0;
    if (!is_hex_literal(s, 0, end) || end != s.size()) return false;
    value = std::strtoull(s.c_str() + 2, nullptr, 16);
    return true;
}

std::vector<std::string> split_operands(const std::string& text) {
    std::vector<std::string> out;
    int depth = 0;
    std::string current;
    for (char c : text) {
        if (c == '[') ++depth;
        if (c == ']') --depth;
        if (c == ',' && depth == 0) { out.push_back(current); current.clear(); continue; }
        current.push_back(c);
    }
    if (!current.empty() || !out.empty()) out.push_back(current);
    for (auto& item : out) {
        const auto first = item.find_first_not_of(' ');
        const auto last = item.find_last_not_of(' ');
        item = first == std::string::npos ? std::string() : item.substr(first, last - first + 1);
    }
    return out;
}

bool is_register_name(const std::string& s) {
    static const std::unordered_set<std::string> names = {
        "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","eax","ebx","ecx","edx","esi","edi","ebp","esp",
        "ax","bx","cx","dx","si","di","bp","sp","al","bl","cl","dl","ah","bh","ch","dh","sil","dil","bpl","spl",
        "cs","ds","es","fs","gs","ss","rip"};
    if (names.count(s)) return true;
    if (s.size() >= 2 && s[0] == 'r' && std::isdigit(static_cast<unsigned char>(s[1]))) return true; // r8..r15(d/w/b)
    if (s.rfind("xmm", 0) == 0 || s.rfind("ymm", 0) == 0 || s.rfind("zmm", 0) == 0 || s.rfind("st", 0) == 0) return true;
    return false;
}

int ptr_size_of(const std::string& operand) {
    static const std::pair<const char*, int> table[] = {
        {"byte ptr", 1}, {"word ptr", 2}, {"dword ptr", 4}, {"qword ptr", 8}, {"xmmword ptr", 16},
        {"ymmword ptr", 32}, {"tbyte ptr", 10}};
    for (const auto& [prefix, size] : table)
        if (operand.rfind(prefix, 0) == 0) return size;
    return 0;
}

bool is_branch_mnemonic(const std::string& m) {
    return m == "call" || m == "jmp" || (m.size() >= 2 && m[0] == 'j') || m.rfind("loop", 0) == 0;
}

struct StringEntry {
    std::uint64_t address{0};
    std::size_t length{0};     // characters
    std::size_t bytes{0};      // storage including terminator
    bool wide{false};
    std::string text;          // escaped display text (UTF-8/ASCII)
    std::string raw;           // original characters (ASCII-only subset for naming)
    std::string name;          // aXxx
};

} // namespace

struct IdaViews::Impl {
    const AnalysisDatabase& db;
    IdaViewConfig cfg;
    bool wide_addresses{true};

    struct Row {
        std::uint64_t address;
        std::uint64_t end;
        const Instruction* instruction;
        std::size_t function;
    };
    std::vector<Row> rows;                                  // sorted by address, unique
    std::vector<std::pair<std::uint64_t, std::uint64_t>> function_ranges; // [start,end)
    std::unordered_map<std::uint64_t, std::size_t> function_by_start;
    std::map<std::uint64_t, std::vector<const Xref*>> xrefs_by_target;
    std::unordered_set<std::uint64_t> labels;               // jump targets
    std::vector<ImportEntry> import_table;
    std::unordered_map<std::uint64_t, std::size_t> import_by_slot;
    std::unordered_map<std::uint64_t, std::string> thunk_names;   // function start -> imported name
    std::unordered_map<std::uint64_t, std::string> symbol_names;
    std::vector<StringEntry> string_table;
    std::map<std::uint64_t, std::size_t> string_by_address;
    std::map<std::uint64_t, int> data_hints;                // address -> element size
    std::set<std::uint64_t> marks;                          // layout boundaries for data walking

    Impl(const AnalysisDatabase& database, IdaViewConfig config) : db(database), cfg(std::move(config)) {
        wide_addresses = db.image().is_64_bit;
        build();
    }

    // ---------- naming ----------
    std::string section_name(std::uint64_t address) const {
        for (const auto& s : db.image().sections) {
            const auto begin = db.image().image_base + s.rva;
            const auto size = std::max<std::uint64_t>(s.virtual_size, s.raw_size);
            if (address >= begin && address < begin + size) return s.name.empty() ? "seg" : s.name;
        }
        return "";
    }
    const BinaryImage::Section* section_of(std::uint64_t address) const {
        for (const auto& s : db.image().sections) {
            const auto begin = db.image().image_base + s.rva;
            const auto size = std::max<std::uint64_t>(s.virtual_size, s.raw_size);
            if (address >= begin && address < begin + size) return &s;
        }
        return nullptr;
    }
    std::string addr(std::uint64_t a) const { return hex(a, wide_addresses ? 16 : 8); }
    std::string addr_text(std::uint64_t a) const {
        auto seg = section_name(a);
        if (seg.empty()) seg = "seg";
        return seg + ":" + addr(a);
    }

    const Function* function_at_address(std::uint64_t a) const {
        const auto row = row_containing(a);
        if (!row) return nullptr;
        return &db.functions()[row->function];
    }

    const Row* row_containing(std::uint64_t a) const {
        auto it = std::upper_bound(rows.begin(), rows.end(), a, [](std::uint64_t v, const Row& r) { return v < r.address; });
        if (it == rows.begin()) return nullptr;
        --it;
        return a < it->end ? &*it : nullptr;
    }
    const Row* row_at(std::uint64_t a) const {
        auto it = std::lower_bound(rows.begin(), rows.end(), a, [](const Row& r, std::uint64_t v) { return r.address < v; });
        return it != rows.end() && it->address == a ? &*it : nullptr;
    }

    std::string function_name(std::size_t index) const {
        const auto& f = db.functions()[index];
        const auto user = cfg.user_names.find(f.start);
        if (user != cfg.user_names.end()) return user->second;
        const auto thunk = thunk_names.find(f.start);
        if (thunk != thunk_names.end() && (f.name.empty() || f.name.rfind("sub_", 0) == 0)) return thunk->second;
        if (!f.name.empty()) return f.name;
        return "sub_" + hex(f.start);
    }

    std::string exact_name(std::uint64_t a) const {
        const auto user = cfg.user_names.find(a);
        if (user != cfg.user_names.end()) return user->second;
        const auto fi = function_by_start.find(a);
        if (fi != function_by_start.end()) return function_name(fi->second);
        const auto sym = symbol_names.find(a);
        if (sym != symbol_names.end()) return sym->second;
        const auto imp = import_by_slot.find(a);
        if (imp != import_by_slot.end()) {
            const auto& e = import_table[imp->second];
            return db.image().format == BinaryFormat::PE ? "__imp_" + e.name : e.name;
        }
        const auto str = string_by_address.find(a);
        if (str != string_by_address.end()) return string_table[str->second].name;
        if (labels.count(a) && row_at(a)) return "loc_" + hex(a);
        const auto hint = data_hints.find(a);
        if (hint != data_hints.end()) {
            const char* prefix = hint->second == 1 ? "byte_" : hint->second == 2 ? "word_" :
                                 hint->second == 4 ? "dword_" : hint->second == 8 ? "qword_" : "unk_";
            return prefix + hex(a);
        }
        return "";
    }

    std::string symbolic_name(std::uint64_t a) const {
        auto n = exact_name(a);
        if (!n.empty()) return n;
        if (const auto* row = row_containing(a)) {
            const auto& f = db.functions()[row->function];
            const auto off = a - f.start;
            return function_name(row->function) + (off ? "+" + hex(off) : "");
        }
        const auto before = marks_before(a);
        if (before) {
            const auto bn = exact_name(*before);
            if (!bn.empty() && a - *before < 0x1000) return bn + "+" + hex(a - *before);
        }
        return "";
    }
    std::optional<std::uint64_t> marks_before(std::uint64_t a) const {
        auto it = marks.upper_bound(a);
        if (it == marks.begin()) return std::nullopt;
        return *--it;
    }

    // ---------- construction ----------
    void build() {
        const auto& image = db.image();
        const auto& functions = db.functions();
        for (std::size_t i = 0; i < functions.size(); ++i) {
            const auto& f = functions[i];
            std::uint64_t end = f.end > f.start ? f.end : f.start;
            for (const auto& ins : f.instructions) {
                end = std::max<std::uint64_t>(end, ins.address + ins.size);
                rows.push_back({ins.address, ins.address + std::max<std::uint8_t>(ins.size, 1), &ins, i});
            }
            function_ranges.push_back({f.start, end});
            function_by_start.emplace(f.start, i);
            marks.insert(f.start);
        }
        std::stable_sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) { return a.address < b.address; });
        rows.erase(std::unique(rows.begin(), rows.end(), [](const Row& a, const Row& b) { return a.address == b.address; }), rows.end());

        for (const auto& s : image.sections) {
            marks.insert(image.image_base + s.rva);
            marks.insert(image.image_base + s.rva + std::max<std::uint64_t>(s.virtual_size, s.raw_size));
        }
        for (const auto& sym : image.symbols)
            if (!sym.name.empty() && sym.address) { symbol_names.emplace(sym.address, sym.name); marks.insert(sym.address); }

        import_table = parse_imports(image);
        if (import_table.empty()) {
            for (const auto& i : image.imports) {
                ImportEntry e;
                e.name = i.name;
                e.iat = i.address;
                import_table.push_back(e);
            }
        }
        for (std::size_t i = 0; i < import_table.size(); ++i) {
            import_by_slot.emplace(import_table[i].iat, i);
            marks.insert(import_table[i].iat);
        }

        // Import thunks: a function that is only "jmp [slot]".
        for (const auto& f : functions) {
            if (f.instructions.empty() || f.instructions.size() > 2) continue;
            const auto& ins = f.instructions.front();
            if (ins.mnemonic != "jmp") continue;
            std::uint64_t target = 0;
            if (rip_target(ins, target)) {
                const auto imp = import_by_slot.find(target);
                if (imp != import_by_slot.end()) thunk_names.emplace(f.start, import_table[imp->second].name);
            }
        }

        for (const auto& x : db.xrefs()) {
            xrefs_by_target[x.to].push_back(&x);
            if (x.kind == "jmp" || x.kind == "jcc") labels.insert(x.to);
        }
        for (auto& [to, list] : xrefs_by_target)
            std::sort(list.begin(), list.end(), [](const Xref* a, const Xref* b) { return a->from < b->from; });

        // Data size hints from RIP-relative operands.
        for (const auto& row : rows) {
            const auto& ins = *row.instruction;
            if (ins.operands.find("[rip") == std::string::npos || ins.mnemonic == "lea") continue;
            std::uint64_t target = 0;
            if (!rip_target(ins, target)) continue;
            if (section_of(target) == nullptr || (section_of(target)->characteristics & 0x20000000u)) continue;
            int size = 0;
            for (const auto& op : split_operands(ins.operands))
                if (op.find('[') != std::string::npos) size = ptr_size_of(op);
            auto& slot = data_hints[target];
            if (slot == 0) slot = size ? size : 0;
            marks.insert(target);
        }
        // Targets of data / offset references without a hint become unk_.
        for (const auto& [to, list] : xrefs_by_target) {
            for (const auto* x : list) {
                if ((x->kind == "data" || x->kind == "offset") && !row_at(to) && !function_by_start.count(to) && section_of(to)) {
                    data_hints.emplace(to, 0);
                    marks.insert(to);
                    break;
                }
            }
        }
        scan_strings(5);
        for (const auto& s : string_table) { marks.insert(s.address); marks.insert(s.address + s.bytes); }
        for (const auto l : labels) marks.insert(l);
    }

    bool rip_target(const Instruction& ins, std::uint64_t& target) const {
        const auto p = ins.operands.find("[rip");
        if (p == std::string::npos) return false;
        auto q = p + 4;
        while (q < ins.operands.size() && ins.operands[q] == ' ') ++q;
        long long sign = 1;
        if (q < ins.operands.size() && (ins.operands[q] == '+' || ins.operands[q] == '-')) {
            sign = ins.operands[q] == '-' ? -1 : 1;
            ++q;
        } else {
            target = ins.address + ins.size;
            return true;
        }
        while (q < ins.operands.size() && ins.operands[q] == ' ') ++q;
        std::size_t end = 0;
        if (!is_hex_literal(ins.operands, q, end)) return false;
        const auto disp = std::strtoull(ins.operands.c_str() + q + 2, nullptr, 16);
        target = ins.address + ins.size + static_cast<std::uint64_t>(sign * static_cast<long long>(disp));
        return true;
    }

    static std::string escape_display(const std::string& raw) {
        std::string out;
        for (unsigned char c : raw) {
            if (c == '\n') out += "\\n";
            else if (c == '\r') out += "\\r";
            else if (c == '\t') out += "\\t";
            else out.push_back(static_cast<char>(c));
        }
        return out;
    }

    static std::string make_string_name(const std::string& raw, bool wide, std::set<std::string>& used) {
        std::string base = wide ? "u" : "a";
        bool upper = true;
        std::size_t kept = 0;
        for (unsigned char c : raw) {
            if (std::isalnum(c)) {
                base.push_back(upper ? static_cast<char>(std::toupper(c)) : static_cast<char>(c));
                upper = false;
                if (++kept >= 16) break;
            } else {
                upper = true;
            }
        }
        if (kept == 0) base += "Str";
        auto name = base;
        for (int n = 1; used.count(name); ++n) name = base + "_" + std::to_string(n);
        used.insert(name);
        return name;
    }

    void scan_strings(std::size_t minimum) {
        string_table.clear();
        string_by_address.clear();
        const auto& image = db.image();
        std::set<std::string> used;
        for (const auto& s : image.sections) {
            if (s.raw_size == 0 || s.raw_offset >= image.bytes.size()) continue;
            if (s.characteristics & 0x20000000u) continue; // code
            const auto begin = static_cast<std::size_t>(s.raw_offset);
            const auto end = std::min<std::size_t>(image.bytes.size(), begin + s.raw_size);
            const auto base = image.image_base + s.rva;
            std::size_t i = begin;
            while (i < end) {
                const auto c = image.bytes[i];
                const bool printable = (c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r';
                if (i + 1 < end && printable && image.bytes[i + 1] == 0 && i + 3 < end && image.bytes[i + 2] >= 0x20 &&
                    image.bytes[i + 2] < 0x7f && image.bytes[i + 3] == 0) {
                    std::size_t j = i;
                    std::string raw;
                    while (j + 1 < end && image.bytes[j + 1] == 0 &&
                           ((image.bytes[j] >= 0x20 && image.bytes[j] < 0x7f) || image.bytes[j] == '\t' || image.bytes[j] == '\n' ||
                            image.bytes[j] == '\r')) {
                        raw.push_back(static_cast<char>(image.bytes[j]));
                        j += 2;
                    }
                    if (raw.size() >= minimum && (j + 1 >= end || (image.bytes[j] == 0 && image.bytes[j + 1] == 0)) && raw.size() < 4096) {
                        StringEntry e;
                        e.address = base + (i - begin);
                        e.wide = true;
                        e.length = raw.size();
                        e.bytes = raw.size() * 2 + 2;
                        e.raw = raw;
                        e.text = escape_display(raw);
                        e.name = make_string_name(raw, true, used);
                        string_by_address[e.address] = string_table.size();
                        string_table.push_back(std::move(e));
                        i = j + 2;
                        continue;
                    }
                    i = j > i ? j : i + 1;
                    continue;
                }
                if (printable) {
                    std::size_t j = i;
                    while (j < end && ((image.bytes[j] >= 0x20 && image.bytes[j] < 0x7f) || image.bytes[j] == '\t' ||
                                       image.bytes[j] == '\n' || image.bytes[j] == '\r'))
                        ++j;
                    const bool terminated = j >= end || image.bytes[j] == 0;
                    if (j - i >= minimum && terminated && j - i < 4096 && (i == begin || image.bytes[i - 1] == 0 || true)) {
                        StringEntry e;
                        e.address = base + (i - begin);
                        e.length = j - i;
                        e.bytes = e.length + (j < end ? 1 : 0);
                        e.raw.assign(reinterpret_cast<const char*>(&image.bytes[i]), e.length);
                        e.text = escape_display(e.raw);
                        e.name = make_string_name(e.raw, false, used);
                        string_by_address[e.address] = string_table.size();
                        string_table.push_back(std::move(e));
                    }
                    i = j + 1;
                    continue;
                }
                ++i;
            }
        }
    }

    // ---------- operand / instruction formatting ----------
    std::string number_in_text(const std::string& text) const {
        std::string out;
        for (std::size_t i = 0; i < text.size();) {
            std::size_t end = 0;
            if (is_hex_literal(text, i, end) && (i == 0 || !std::isalnum(static_cast<unsigned char>(text[i - 1])))) {
                out += ida_number(std::strtoull(text.c_str() + i + 2, nullptr, 16));
                i = end;
            } else {
                out.push_back(text[i++]);
            }
        }
        return out;
    }

    std::string compact_brackets(const std::string& inside) const {
        // "rbp - 0x8" -> "rbp-8h" style: no spaces around + and -.
        std::string out;
        for (std::size_t i = 0; i < inside.size(); ++i) {
            if (inside[i] == ' ') continue;
            out.push_back(inside[i]);
        }
        return number_in_text(out);
    }

    std::string memory_operand(const Instruction& ins, const std::string& operand, bool keep_size) const {
        std::string size_prefix;
        std::string rest = operand;
        const auto ptr = rest.find(" ptr ");
        if (ptr != std::string::npos) { size_prefix = rest.substr(0, ptr + 5); rest = rest.substr(ptr + 5); }
        std::string segment;
        const auto colon = rest.find(':');
        if (colon != std::string::npos && colon < rest.find('[')) { segment = rest.substr(0, colon + 1); rest = rest.substr(colon + 1); }
        const auto open = rest.find('['), close = rest.rfind(']');
        if (open == std::string::npos || close == std::string::npos || close < open) return number_in_text(operand);
        std::string inside = rest.substr(open + 1, close - open - 1);
        std::string result;
        std::uint64_t target = 0;
        if (rest.compare(open, 4, "[rip") == 0 && rip_target(ins, target)) {
            auto name = exact_name(target);
            if (name.empty()) name = symbolic_name(target);
            if (name.empty()) name = "loc_" + hex(target);
            return "cs:" + name;
        }
        // Stack frame variables: [rbp - N] / [rbp + N] without an index.
        std::string compact;
        for (char c : inside) if (c != ' ') compact.push_back(c);
        if (compact.rfind("rbp", 0) == 0 && compact.find('*') == std::string::npos && compact.find('+', 3) == std::string::npos
            && compact.size() > 4 && (compact[3] == '-' || compact[3] == '+')) {
            std::size_t end = 0;
            if (is_hex_literal(compact, 4, end) && end == compact.size()) {
                const auto disp = std::strtoull(compact.c_str() + 6, nullptr, 16);
                if (compact[3] == '-') result = "[rbp+var_" + hex(disp) + "]";
                else if (disp >= 0x10) result = "[rbp+arg_" + hex(disp - 0x10) + "]";
            }
        }
        if (result.empty() && cfg.types) {
            // "Structure offset" applied by the user: [rcx+0x8] -> [rcx+RECT.top]
            const auto applied = cfg.struct_offsets.find(ins.address);
            if (applied != cfg.struct_offsets.end()) {
                std::uint64_t disp = 0; std::string base = compact;
                const auto plus = compact.rfind('+');
                std::size_t end = 0;
                if (plus != std::string::npos && is_hex_literal(compact, plus + 1, end) && end == compact.size()) {
                    disp = std::strtoull(compact.c_str() + plus + 3, nullptr, 16); base = compact.substr(0, plus);
                }
                const auto field = cfg.types->field_at(applied->second, disp);
                const auto resolved = cfg.types->resolve(applied->second);
                if (!field.empty() && resolved) result = "[" + base + "+" + resolved->name + "." + field + "]";
            }
        }
        if (result.empty()) result = "[" + compact_brackets(inside) + "]";
        result += rest.substr(close + 1);   // AArch64 pre-index writeback: "!"
        if (keep_size && !size_prefix.empty()) return size_prefix + segment + result;
        return segment + result;
    }

    std::string target_name(std::uint64_t t, bool is_call) const {
        auto n = exact_name(t);
        if (!n.empty()) return n;
        if (const auto* f = function_at_address(t)) {
            (void)f;
            return "loc_" + hex(t);
        }
        (void)is_call;
        return section_of(t) ? "loc_" + hex(t) : ida_number(t);
    }

    std::string format_instruction(const Instruction& ins) const {
        std::string mnemonic = ins.mnemonic;
        auto ops = split_operands(ins.operands);
        const bool branch = is_branch_mnemonic(mnemonic);
        bool other_register = false;
        for (const auto& op : ops) if (is_register_name(op)) other_register = true;
        const bool keep_size = !other_register || mnemonic.rfind("movz", 0) == 0 || mnemonic.rfind("movs", 0) == 0 ||
                               mnemonic.rfind("cvt", 0) == 0;
        std::string text;
        for (std::size_t i = 0; i < ops.size(); ++i) {
            const auto& op = ops[i];
            std::string rendered;
            std::uint64_t value = 0;
            if (op.find('[') != std::string::npos) {
                rendered = mnemonic == "lea" ? memory_operand(ins, op, false) : memory_operand(ins, op, keep_size);
                // A call/jmp through an import slot prints as cs:__imp_name.
            } else if (parse_hex_literal(op, value)) {
                if (branch) {
                    rendered = target_name(value, mnemonic == "call");
                    if (mnemonic != "call" && ins.size == 2) rendered = "short " + rendered;
                } else {
                    const auto name = (mnemonic == "mov" || mnemonic == "push" || mnemonic == "cmp") && value >= 0x1000 ? symbolic_exact(value) : std::string();
                    rendered = name.empty() ? ida_number(value) : "offset " + name;
                    if (cfg.types && name.empty()) {
                        if (const auto applied = cfg.enum_operands.find(ins.address); applied != cfg.enum_operands.end()) {
                            const auto symbol = cfg.types->enum_name(applied->second, value);
                            if (!symbol.empty()) rendered = symbol;
                        }
                    }
                }
            } else if (!op.empty() && op[0] == '-' && parse_hex_literal(op.substr(1), value)) {
                rendered = "-" + ida_number(value);
            } else {
                rendered = number_in_text(op);
            }
            if (i) text += ", ";
            text += rendered;
        }
        return text.empty() ? mnemonic : pad(mnemonic, 7) + " " + text;
    }

    std::string symbolic_exact(std::uint64_t a) const {
        if (!section_of(a)) return "";
        return exact_name(a);
    }

    std::string comment_for(std::uint64_t a) const {
        const auto it = cfg.user_comments.find(a);
        return it == cfg.user_comments.end() ? std::string() : it->second;
    }

    // ---------- xref comment text ----------
    static char xref_letter(const Xref& x) {
        if (x.kind == "call") return 'p';
        if (x.kind == "jmp" || x.kind == "jcc") return 'j';
        if (x.kind == "offset" || x.kind == "string") return 'o';
        return 'r';
    }

    std::vector<std::string> xref_items(std::uint64_t target, bool code) const {
        std::vector<std::string> items;
        const auto it = xrefs_by_target.find(target);
        if (it == xrefs_by_target.end()) return items;
        for (const auto* x : it->second) {
            const bool is_code = x->kind == "call" || x->kind == "jmp" || x->kind == "jcc";
            if (is_code != code) continue;
            items.push_back(symbolic_name(x->from).empty() ? addr(x->from) : symbolic_name(x->from));
            items.back() += (x->from <= target ? kDown : kUp);
            items.back().push_back(xref_letter(*x));
        }
        return items;
    }

    // Emits a line: [prefix addr] content [pad ; comment...] with wrapped xref lines.
    void emit_with_xrefs(std::ostringstream& out, std::size_t& lines, std::uint64_t address, const std::string& content,
                         const std::vector<std::string>& items, const char* label, const std::string& tail_comment = {}) const {
        const auto prefix = addr_text(address) + " ";
        constexpr std::size_t column = 40;
        std::string line = prefix + pad(content, column);
        if (content.size() >= column) line = prefix + content + " ";
        if (items.empty() && tail_comment.empty()) {
            out << prefix << content << '\n';
            ++lines;
            return;
        }
        std::vector<std::string> comments;
        if (!items.empty()) {
            std::string current = std::string("; ") + label + ": ";
            bool first = true;
            std::size_t shown = 0;
            for (const auto& item : items) {
                if (shown >= 8) { comments.push_back(current); current = "; ..."; break; }
                if (!first) current += ", ";
                if (current.size() > 70 && !first) { current.resize(current.size() - 2); comments.push_back(current); current = "; "; first = true; }
                if (!first) {} // separator already added
                current += item;
                first = false;
                ++shown;
            }
            comments.push_back(current);
        }
        if (!tail_comment.empty()) comments.push_back("; " + tail_comment);
        out << line << comments.front() << '\n';
        ++lines;
        for (std::size_t i = 1; i < comments.size(); ++i) {
            out << prefix << std::string(column, ' ') << comments[i] << '\n';
            ++lines;
        }
    }

    // ---------- data rendering ----------
    std::optional<std::uint8_t> byte_at(std::uint64_t a) const {
        const auto off = db.image().va_to_file_offset(a);
        if (!off || *off >= db.image().bytes.size()) return std::nullopt;
        return db.image().bytes[*off];
    }

    static std::string db_text(const std::string& raw, bool wide) {
        // 'Hello',0Ah,0 style
        std::string out;
        bool in_quote = false;
        auto close_quote = [&] { if (in_quote) { out += "'"; in_quote = false; } };
        for (unsigned char c : raw) {
            if (c >= 0x20 && c < 0x7f && c != '\'') {
                if (!in_quote) { if (!out.empty()) out += ","; out += "'"; in_quote = true; }
                out.push_back(static_cast<char>(c));
            } else {
                close_quote();
                if (!out.empty()) out += ",";
                out += ida_number(c);
            }
        }
        close_quote();
        if (!out.empty()) out += ",";
        out += "0";
        (void)wide;
        return out;
    }

    std::uint64_t next_mark(std::uint64_t a, std::uint64_t limit) const {
        auto it = marks.upper_bound(a);
        std::uint64_t next = limit;
        if (it != marks.end()) next = std::min(next, *it);
        auto row = std::upper_bound(rows.begin(), rows.end(), a, [](std::uint64_t v, const Row& r) { return v < r.address; });
        if (row != rows.end()) next = std::min(next, row->address);
        return next;
    }

    void emit_segment_header(std::ostringstream& out, std::size_t& lines, const BinaryImage::Section& s) const {
        const auto a = db.image().image_base + s.rva;
        const char* type = (s.characteristics & 0x20000000u) ? "Pure code" : (s.raw_size == 0 ? "Uninitialized" : "Pure data");
        std::string perm;
        if (s.characteristics & 0x40000000u) perm += "Read";
        if (s.characteristics & 0x80000000u) perm += (perm.empty() ? "" : "/") + std::string("Write");
        if (s.characteristics & 0x20000000u) perm += (perm.empty() ? "" : "/") + std::string("Execute");
        const auto p = addr_text(a) + " ";
        out << p << '\n' << p << "; Segment type: " << type << '\n' << p << "; Segment permissions: " << perm << '\n';
        lines += 3;
    }

    std::string list(std::uint64_t start) const {
        std::ostringstream out;
        std::size_t lines = 0;
        const auto& image = db.image();
        std::uint64_t cur = start;
        if (const auto* row = row_containing(start)) cur = db.functions()[row->function].start;
        std::uint64_t last_section_start = ~0ull;
        auto sec_start = [&](std::uint64_t a) -> const BinaryImage::Section* {
            const auto* s = section_of(a);
            return s;
        };
        while (lines < cfg.max_lines) {
            const auto* sec = sec_start(cur);
            if (!sec) {
                // jump to the next section start
                std::uint64_t next = ~0ull;
                for (const auto& s : image.sections) {
                    const auto b = image.image_base + s.rva;
                    if (b > cur) next = std::min(next, b);
                }
                if (next == ~0ull) break;
                cur = next;
                continue;
            }
            const auto sec_begin = image.image_base + sec->rva;
            const auto sec_end = sec_begin + std::max<std::uint64_t>(sec->virtual_size, sec->raw_size);
            if (cur == sec_begin && last_section_start != sec_begin) {
                emit_segment_header(out, lines, *sec);
                last_section_start = sec_begin;
            }
            if (const auto* row = row_at(cur)) {
                cur = emit_instruction(out, lines, *row);
                continue;
            }
            // Skip overlapping rows that start inside the previous instruction.
            cur = emit_data(out, lines, cur, sec_end);
        }
        if (lines >= cfg.max_lines) out << "; ... listing truncated at " << cfg.max_lines << " lines, continues at " << addr_text(cur) << '\n';
        return out.str();
    }

    std::uint64_t emit_instruction(std::ostringstream& out, std::size_t& lines, const Row& row) const {
        const auto& ins = *row.instruction;
        const auto& f = db.functions()[row.function];
        const auto prefix = addr_text(ins.address) + " ";
        const bool is_start = ins.address == f.start;
        if (is_start) {
            const auto name = function_name(row.function);
            out << prefix << "; =============== S U B R O U T I N E =======================================\n";
            out << prefix << '\n';
            lines += 2;
            if (cfg.noreturn.count(ins.address)) { out << prefix << "; Attributes: noreturn\n" << prefix << '\n'; lines += 2; }
            if (const auto proto = cfg.prototypes.find(ins.address); proto != cfg.prototypes.end()) { out << prefix << "; " << proto->second << "\n"; ++lines; }
            emit_with_xrefs(out, lines, ins.address, pad(name, 15) + " proc near", xref_items(ins.address, true), "CODE XREF");
            const auto data_items = xref_items(ins.address, false);
            if (!data_items.empty()) emit_with_xrefs(out, lines, ins.address, "", data_items, "DATA XREF");
        } else if (labels.count(ins.address)) {
            emit_with_xrefs(out, lines, ins.address, exact_name(ins.address).empty() ? "loc_" + hex(ins.address) + ":" : exact_name(ins.address) + ":",
                            xref_items(ins.address, true), "CODE XREF");
        }
        std::string line = prefix;
        if (cfg.show_opcode_bytes) {
            std::string bytes;
            for (std::size_t i = 0; i < ins.size && i < 8; ++i) bytes += hex(ins.bytes[i], 2) + " ";
            line += pad(bytes, 25);
        } else {
            line += std::string(17, ' ');
        }
        line += format_instruction(ins);
        const auto comment = comment_for(ins.address);
        if (!comment.empty()) line = pad(line, prefix.size() + 17 + 40) + "; " + comment;
        out << line << '\n';
        ++lines;
        const auto end = ins.address + std::max<std::uint8_t>(ins.size, 1);
        // endp after the last instruction of a function
        const auto range_end = function_ranges[row.function].second;
        if (end >= range_end) {
            const auto next = std::upper_bound(rows.begin(), rows.end(), ins.address, [](std::uint64_t v, const Row& r) { return v < r.address; });
            if (next == rows.end() || next->function != row.function || next->address >= range_end) {
                out << addr_text(ins.address) << " " << pad(function_name(row.function), 15) << " endp\n"
                    << addr_text(ins.address) << " \n";
                lines += 2;
            }
        }
        return end;
    }

    // Length of one compiler alignment-filler item at `a` (int3, nop, or a
    // multi-byte `[66|2E]* 0F 1F /0` nop), or 0 when the bytes are not padding.
    std::uint64_t padding_length(std::uint64_t a, std::uint64_t limit) const {
        const auto b = byte_at(a);
        if (!b) return 0;
        if (*b == 0xCC || *b == 0x90) return 1;
        std::uint64_t p = a;
        while (p < limit && p - a < 4 && (byte_at(p) == std::optional<std::uint8_t>(0x66) || byte_at(p) == std::optional<std::uint8_t>(0x2E))) ++p;
        if (p >= limit) return 0;
        if (byte_at(p) == std::optional<std::uint8_t>(0x90) && p > a) return p + 1 - a;   // 66 90
        if (p + 2 >= limit) return 0;
        if (byte_at(p) != std::optional<std::uint8_t>(0x0F) || byte_at(p + 1) != std::optional<std::uint8_t>(0x1F)) return 0;
        const auto modrm = byte_at(p + 2);
        if (!modrm) return 0;
        std::uint64_t length = p + 3 - a;
        const unsigned mod = *modrm >> 6, rm = *modrm & 7;
        if (mod != 3 && rm == 4) ++length;                       // SIB
        if (mod == 1) length += 1;
        else if (mod == 2) length += 4;
        else if (mod == 0 && rm == 5) length += 4;
        return a + length <= limit ? length : 0;
    }

    std::uint64_t emit_data(std::ostringstream& out, std::size_t& lines, std::uint64_t cur, std::uint64_t sec_end) const {
        const auto prefix = addr_text(cur) + " ";
        const auto name = exact_name(cur);
        // string
        const auto s = string_by_address.find(cur);
        if (s != string_by_address.end()) {
            const auto& e = string_table[s->second];
            std::string body;
            if (e.wide) {
                body = "unicode 0, <" + e.raw + ">,0";
            } else {
                body = "db " + db_text(e.raw, false);
            }
            emit_with_xrefs(out, lines, cur, pad(e.name, 15) + " " + body, xref_items(cur, false), "DATA XREF");
            return std::min<std::uint64_t>(cur + std::max<std::size_t>(e.bytes, 1), sec_end);
        }
        const auto imp = import_by_slot.find(cur);
        if (imp != import_by_slot.end()) {
            const auto& e = import_table[imp->second];
            const auto width = db.image().is_64_bit ? 8 : 4;
            emit_with_xrefs(out, lines, cur, pad(exact_name(cur), 15) + (width == 8 ? " dq ?" : " dd ?"), xref_items(cur, false), "DATA XREF",
                            e.library.empty() ? "" : "Imported from " + e.library);
            return cur + width;
        }
        const auto next = std::min(next_mark(cur, sec_end), sec_end);
        // Alignment padding after code.
        const auto first = byte_at(cur);
        if (first && name.empty() && padding_length(cur, next) > 0) {
            std::uint64_t end = cur;
            while (end < next) {
                const auto step = padding_length(end, next);
                if (!step) break;
                end += step;
            }
            if (end % 16 == 0 || end == next) {
                out << prefix << std::string(17, ' ') << "align " << (end % 16 == 0 ? "10h" : ida_number(end - cur)) << '\n';
                ++lines;
                return end;
            }
        }
        const auto hint = data_hints.find(cur);
        const int element = hint == data_hints.end() ? 0 : hint->second;
        std::string label_text = name.empty() ? std::string(16, ' ') : pad(name, 15) + " ";
        const auto items = name.empty() ? std::vector<std::string>() : xref_items(cur, false);
        if (!first) {
            // uninitialised run
            std::uint64_t end = std::min(next, sec_end);
            if (end <= cur) end = cur + 1;
            const auto count = end - cur;
            emit_with_xrefs(out, lines, cur, label_text + "db " + (count == 1 ? std::string("?") : ida_number(count) + " dup(?)"), items, "DATA XREF");
            return end;
        }
        if (element == 1 || element == 2 || element == 4 || element == 8) {
            std::uint64_t value = 0;
            bool ok = true;
            for (int i = 0; i < element; ++i) {
                const auto b = byte_at(cur + i);
                if (!b) { ok = false; break; }
                value |= static_cast<std::uint64_t>(*b) << (8 * i);
            }
            if (ok) {
                const char* directive = element == 1 ? "db" : element == 2 ? "dw" : element == 4 ? "dd" : "dq";
                std::string rendered = ida_number(value);
                if (element >= 4 && value >= 0x1000 && section_of(value) && !exact_name(value).empty()) rendered = "offset " + exact_name(value);
                emit_with_xrefs(out, lines, cur, label_text + directive + " " + rendered, items, "DATA XREF");
                return cur + element;
            }
        }
        // Zero run.
        {
            std::uint64_t end = cur;
            while (end < next && byte_at(end) == std::optional<std::uint8_t>(0)) ++end;
            if (end - cur >= 4) {
                emit_with_xrefs(out, lines, cur, label_text + "db " + ida_number(end - cur) + " dup(0)", items, "DATA XREF");
                return end;
            }
        }
        std::string body = "db ";
        std::uint64_t end = cur;
        const std::uint64_t limit = std::min<std::uint64_t>(next, cur + 16);
        for (; end < limit; ++end) {
            const auto b = byte_at(end);
            if (!b) break;
            if (end != cur) body += ", ";
            body += ida_number(*b);
        }
        if (end == cur) end = cur + 1;
        emit_with_xrefs(out, lines, cur, label_text + body, items, "DATA XREF");
        return end;
    }
};

// ---------------------------------------------------------------------------

IdaViews::IdaViews(const AnalysisDatabase& database, IdaViewConfig config)
    : impl_(std::make_unique<Impl>(database, std::move(config))) {}
IdaViews::~IdaViews() = default;

std::string IdaViews::segment_name(std::uint64_t address) const { return impl_->section_name(address); }
std::string IdaViews::address_text(std::uint64_t address) const { return impl_->addr_text(address); }
std::string IdaViews::symbolic(std::uint64_t address) const { return impl_->symbolic_name(address); }
std::string IdaViews::name_at(std::uint64_t address) const { return impl_->exact_name(address); }
std::string IdaViews::format_instruction(const Instruction& instruction) const { return impl_->format_instruction(instruction); }
std::string IdaViews::listing(std::uint64_t start) const { return impl_->list(start); }

std::vector<IdaViews::ItemRange> IdaViews::item_ranges() const {
    const auto& d = *impl_;
    std::vector<ItemRange> result;
    result.reserve(d.function_ranges.size() + d.string_table.size() + d.import_table.size());
    for (const auto& [begin, end] : d.function_ranges)
        if (end > begin) result.push_back({begin, end, 'F'});
    for (const auto& s : d.string_table)
        if (s.bytes) result.push_back({s.address, s.address + s.bytes, 'S'});
    const std::uint64_t slot = d.db.image().is_64_bit ? 8 : 4;
    for (const auto& e : d.import_table)
        if (e.iat) result.push_back({e.iat, e.iat + slot, 'I'});
    return result;
}

std::string IdaViews::xrefs_to(std::uint64_t address) const {
    std::ostringstream out;
    const auto name = impl_->symbolic_name(address);
    out << "Xrefs to " << (name.empty() ? impl_->addr(address) : name) << " (" << impl_->addr_text(address) << ")\n\n";
    out << pad("Direction", 10) << pad("Type", 6) << pad("Address", 34) << "Text\n";
    out << std::string(100, '-') << '\n';
    const auto it = impl_->xrefs_by_target.find(address);
    if (it == impl_->xrefs_by_target.end() || it->second.empty()) {
        out << "(no cross-references)\n";
        return out.str();
    }
    for (const auto* x : it->second) {
        const char* dir = x->from < address ? "Down" : "Up";
        std::string text;
        if (const auto* row = impl_->row_containing(x->from)) text = impl_->format_instruction(*row->instruction);
        std::string where = impl_->symbolic_name(x->from);
        if (where.empty()) where = impl_->addr(x->from);
        out << pad(dir, 10) << pad(std::string(1, Impl::xref_letter(*x)), 6) << pad(where, 34) << text << '\n';
    }
    out << "\nLine 1 of " << it->second.size() << '\n';
    return out.str();
}

std::string IdaViews::xrefs_overview(std::size_t max_rows) const {
    std::ostringstream out;
    out << pad("Direction", 10) << pad("Type", 6) << pad("From", 34) << pad("To", 34) << "Text\n";
    out << std::string(120, '-') << '\n';
    std::size_t n = 0;
    for (const auto& x : impl_->db.xrefs()) {
        if (n++ >= max_rows) { out << "... truncated at " << max_rows << " rows\n"; break; }
        std::string from = impl_->symbolic_name(x.from), to = impl_->symbolic_name(x.to);
        if (from.empty()) from = impl_->addr(x.from);
        if (to.empty()) to = impl_->addr(x.to);
        std::string text;
        if (const auto* row = impl_->row_containing(x.from)) text = impl_->format_instruction(*row->instruction);
        out << pad(x.from < x.to ? "Down" : "Up", 10) << pad(std::string(1, Impl::xref_letter(x)), 6) << pad(from, 34) << pad(to, 34) << text << '\n';
    }
    return out.str();
}

std::string IdaViews::hex_view(std::uint64_t address, std::size_t rows) const {
    std::ostringstream out;
    const auto start = address & ~std::uint64_t{15};
    for (std::size_t r = 0; r < rows; ++r) {
        const auto a = start + r * 16;
        std::string bytes, ascii;
        bool any = false;
        for (int i = 0; i < 16; ++i) {
            const auto b = impl_->byte_at(a + i);
            if (i == 8) bytes += " ";
            if (b) { any = true; bytes += hex(*b, 2) + " "; ascii.push_back(*b >= 0x20 && *b < 0x7f ? static_cast<char>(*b) : '.'); }
            else { bytes += "?? "; ascii.push_back(' '); }
        }
        if (!any && impl_->section_name(a).empty()) continue;
        out << impl_->addr_text(a) << "  " << bytes << " " << ascii << '\n';
    }
    return out.str();
}

std::string IdaViews::imports() const {
    std::ostringstream out;
    out << pad("Address", 20) << pad("Ordinal", 9) << pad("Name", 44) << "Library\n" << std::string(100, '-') << '\n';
    for (const auto& e : impl_->import_table)
        out << pad(impl_->addr(e.iat), 20) << pad(e.by_ordinal ? std::to_string(e.ordinal) : "", 9) << pad(e.name, 44)
            << (e.library.empty() ? "" : e.library) << '\n';
    if (impl_->import_table.empty()) out << "(no imports)\n";
    return out.str();
}

std::string IdaViews::exports() const {
    std::ostringstream out;
    out << pad("Name", 44) << pad("Address", 20) << "Ordinal\n" << std::string(80, '-') << '\n';
    auto list = parse_exports(impl_->db.image());
    bool has_entry = false;
    for (const auto& e : list) if (e.address == impl_->db.image().entry_point) has_entry = true;
    for (const auto& e : list) {
        out << pad(e.name.empty() ? "(ordinal only)" : e.name, 44) << pad(impl_->addr(e.address), 20) << e.ordinal;
        if (!e.forwarder.empty()) out << "  -> " << e.forwarder;
        out << '\n';
    }
    if (!has_entry && impl_->db.image().entry_point)
        out << pad("start", 44) << pad(impl_->addr(impl_->db.image().entry_point), 20) << "[main entry]\n";
    return out.str();
}

std::string IdaViews::strings(std::size_t minimum_length, std::size_t max_rows) const {
    std::ostringstream out;
    out << pad("Address", 34) << pad("Length", 10) << pad("Type", 6) << "String\n" << std::string(100, '-') << '\n';
    std::size_t n = 0;
    auto emit = [&](const StringEntry& e) {
        if (e.length < minimum_length) return;
        if (n++ >= max_rows) return;
        out << pad(impl_->addr_text(e.address), 34) << pad(hex(e.length, 8), 10) << pad(e.wide ? "C16" : "C", 6) << e.text << '\n';
    };
    if (minimum_length >= 5) {
        for (const auto& e : impl_->string_table) emit(e);
    } else {
        Impl copy(impl_->db, impl_->cfg);
        copy.scan_strings(minimum_length);
        for (const auto& e : copy.string_table) emit(e);
    }
    if (n > max_rows) out << "... truncated at " << max_rows << " rows\n";
    return out.str();
}

std::string IdaViews::resources() const {
    std::ostringstream out;
    out << pad("Resource", 56) << pad("RVA", 12) << pad("Size", 12) << "File offset\n" << std::string(100, '-') << '\n';
    const auto list = parse_resources(impl_->db.image());
    for (const auto& r : list)
        out << pad(r.path, 56) << pad(hex(r.rva, 8), 12) << pad(hex(r.size, 8), 12)
            << (r.file_offset ? hex(*r.file_offset, 8) : std::string("-")) << '\n';
    if (list.empty()) out << "(no resources)\n";
    return out.str();
}

std::string IdaViews::names() const {
    struct Entry { std::string name; std::uint64_t address; char type; };
    std::vector<Entry> entries;
    const auto& d = *impl_;
    for (std::size_t i = 0; i < d.db.functions().size(); ++i)
        entries.push_back({d.function_name(i), d.db.functions()[i].start, 'F'});
    for (const auto& e : d.import_table) entries.push_back({d.exact_name(e.iat), e.iat, 'I'});
    for (const auto& s : d.string_table) entries.push_back({s.name, s.address, 'A'});
    for (const auto& [a, size] : d.data_hints) { (void)size; if (!d.string_by_address.count(a)) entries.push_back({d.exact_name(a), a, 'D'}); }
    for (const auto& [a, n] : d.symbol_names) if (!d.function_by_start.count(a)) entries.push_back({n, a, 'S'});
    for (const auto& [a, n] : d.cfg.user_names) if (!d.function_by_start.count(a)) entries.push_back({n, a, 'N'});
    // The same (name, address) can be reported by several sources (e.g. an import
    // slot is also a data hint). Keep the most specific type deterministically.
    const auto rank = [](char type) { const char* order = "FIASND"; const auto* p = std::strchr(order, type); return p ? static_cast<int>(p - order) : 99; };
    std::sort(entries.begin(), entries.end(), [&](const Entry& a, const Entry& b) {
        if (a.name != b.name) return a.name < b.name;
        if (a.address != b.address) return a.address < b.address;
        return rank(a.type) < rank(b.type);
    });
    entries.erase(std::unique(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) { return a.name == b.name && a.address == b.address; }), entries.end());
    std::ostringstream out;
    out << pad("Name", 48) << pad("Address", 34) << "Type\n" << std::string(96, '-') << '\n';
    for (const auto& e : entries) out << pad(e.name, 48) << pad(d.addr_text(e.address), 34) << e.type << '\n';
    out << "\nF function  I import  A string  D data  S symbol  N user name\n";
    return out.str();
}

std::string IdaViews::segments() const {
    const auto& d = *impl_;
    std::ostringstream out;
    out << pad("Name", 20) << pad("Start", 20) << pad("End", 20) << "R W X  " << pad("Class", 8) << pad("Size", 12) << "File offset\n"
        << std::string(96, '-') << '\n';
    for (const auto& s : d.db.image().sections) {
        const auto start = d.db.image().image_base + s.rva;
        const auto size = std::max<std::uint64_t>(s.virtual_size, s.raw_size);
        const bool r = s.characteristics & 0x40000000u, w = s.characteristics & 0x80000000u, x = s.characteristics & 0x20000000u;
        const char* cls = x ? "CODE" : (s.raw_size == 0 ? "BSS" : "DATA");
        out << pad(s.name, 20) << pad(d.addr(start), 20) << pad(d.addr(start + size), 20) << (r ? "R " : ". ") << (w ? "W " : ". ")
            << (x ? "X  " : ".  ") << pad(cls, 8) << pad(hex(size, 8), 12) << (s.raw_size ? hex(s.raw_offset, 8) : "-") << '\n';
    }
    out << "\nImage base: " << d.addr(d.db.image().image_base) << "   Entry point: " << d.addr(d.db.image().entry_point) << '\n';
    return out.str();
}

std::string IdaViews::problems(const std::vector<std::string>& debugger_events) const {
    const auto& d = *impl_;
    struct Problem { std::uint64_t address; std::string type; std::string text; };
    std::vector<Problem> items;
    constexpr std::size_t cap = 2000;
    for (const auto& x : d.db.xrefs()) {
        if (items.size() >= cap) break;
        if (x.kind != "call" && x.kind != "jmp" && x.kind != "jcc") continue;
        if (!d.section_of(x.to)) {
            items.push_back({x.from, "Bad reference", "branch target " + d.addr(x.to) + " is outside every segment"});
        } else if (!d.row_at(x.to) && d.row_containing(x.to)) {
            items.push_back({x.from, "Misaligned branch", "target " + d.addr(x.to) + " is inside an instruction"});
        } else if (!d.row_at(x.to) && !(d.section_of(x.to)->characteristics & 0x20000000u)) {
            items.push_back({x.from, "Branch to data", "target " + d.addr(x.to) + " lies in non-executable " + d.section_name(x.to)});
        }
    }
    std::size_t indirect = 0;
    for (const auto& row : d.rows) {
        if (items.size() >= cap) break;
        const auto& ins = *row.instruction;
        if (ins.mnemonic == "jmp" && !ins.operands.empty() && ins.operands.find("0x") != 0 && ins.operands.find("[rip") == std::string::npos &&
            ++indirect <= 500)
            items.push_back({ins.address, "Indirect jump", "unresolved jump target: " + d.format_instruction(ins)});
    }
    if (d.db.functions_truncated()) items.push_back({0, "Analysis limit", "function list was truncated; raise the analysis limits to see everything"});
    if (d.db.xrefs_truncated()) items.push_back({0, "Analysis limit", "cross-reference list was truncated"});
    std::stable_sort(items.begin(), items.end(), [](const Problem& a, const Problem& b) { return a.address < b.address; });
    std::ostringstream out;
    out << pad("Address", 34) << pad("Type", 20) << "Description\n" << std::string(100, '-') << '\n';
    for (const auto& p : items) out << pad(p.address ? d.addr_text(p.address) : "-", 34) << pad(p.type, 20) << p.text << '\n';
    if (items.empty()) out << "(no problems)\n";
    out << "\nDebugger events\n" << std::string(100, '-') << '\n';
    if (debugger_events.empty()) out << "(none)\n";
    for (const auto& e : debugger_events) out << e << '\n';
    return out.str();
}

} // namespace gandon
