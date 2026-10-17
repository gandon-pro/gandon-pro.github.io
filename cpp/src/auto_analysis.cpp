#include "gandon/auto_analysis.hpp"

#include "gandon/image_tables.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace gandon {
namespace {

bool parse_hex(const std::string& text, std::uint64_t& value) {
    if (text.size() < 3 || text[0] != '0' || (text[1] != 'x' && text[1] != 'X')) return false;
    for (std::size_t i = 2; i < text.size(); ++i) if (!std::isxdigit(static_cast<unsigned char>(text[i]))) return false;
    value = std::strtoull(text.c_str() + 2, nullptr, 16);
    return true;
}

std::string strip_prefix(std::string m) {
    for (const char* prefix : {"bnd ", "notrack ", "rep ", "repne ", "lock "})
        if (m.rfind(prefix, 0) == 0) m = m.substr(std::string(prefix).size());
    return m;
}

bool is_conditional_jump(const std::string& m) {
    return m.size() >= 2 && m[0] == 'j' && m != "jmp";
}

std::optional<std::uint64_t> rip_target(const Instruction& ins) {
    const auto p = ins.operands.find("[rip");
    if (p == std::string::npos) return std::nullopt;
    auto q = p + 4;
    while (q < ins.operands.size() && ins.operands[q] == ' ') ++q;
    if (q >= ins.operands.size() || ins.operands[q] == ']') return ins.address + ins.size;
    const long long sign = ins.operands[q] == '-' ? -1 : 1;
    if (ins.operands[q] != '+' && ins.operands[q] != '-') return std::nullopt;
    ++q;
    while (q < ins.operands.size() && ins.operands[q] == ' ') ++q;
    std::size_t end = q + 2;
    if (end > ins.operands.size() || ins.operands[q] != '0') return std::nullopt;
    while (end < ins.operands.size() && std::isxdigit(static_cast<unsigned char>(ins.operands[end]))) ++end;
    const auto disp = std::strtoull(ins.operands.c_str() + q + 2, nullptr, 16);
    return ins.address + ins.size + static_cast<std::uint64_t>(sign * static_cast<long long>(disp));
}

thread_local bool g_arm64 = false;

bool direct_target(const Instruction& ins, std::uint64_t& target) {
    if (!g_arm64) return parse_hex(ins.operands, target);
    // AArch64: the branch target is the last operand ("#0x400100", "w0, #0x400120", "x1, #3, #0x400130").
    std::string last = ins.operands;
    if (const auto p = last.rfind(','); p != std::string::npos) last = last.substr(p + 1);
    while (!last.empty() && last.front() == ' ') last.erase(last.begin());
    if (!last.empty() && last.front() == '#') last.erase(last.begin());
    if (last.find('[') != std::string::npos) return false;
    return parse_hex(last, target);
}

bool m_is_call(const std::string& m) { return g_arm64 ? m == "bl" : m == "call"; }
bool m_is_uncond(const std::string& m) { return g_arm64 ? m == "b" : m == "jmp"; }
bool m_is_cond(const std::string& m) {
    if (!g_arm64) return is_conditional_jump(m) || m.rfind("loop", 0) == 0 || m == "jrcxz" || m == "jecxz";
    return m.rfind("b.", 0) == 0 || m == "cbz" || m == "cbnz" || m == "tbz" || m == "tbnz";
}
bool m_is_ret(const std::string& m) {
    if (g_arm64) return m == "ret" || m == "eret" || m == "retaa" || m == "retab";
    return m == "ret" || m == "retn" || m == "iretq" || m == "iret";
}
bool m_is_halt(const std::string& m) {
    if (g_arm64) return m == "brk" || m == "udf" || m == "hlt";
    return m == "hlt" || m == "ud2" || m == "int3";
}
bool m_is_indirect_branch(const std::string& m) { return g_arm64 && (m == "br" || m == "braa" || m == "brab" || m == "braaz" || m == "brabz"); }

bool is_exec(const BinaryImage& image, std::uint64_t address) {
    for (const auto& s : image.sections) {
        const auto begin = image.image_base + s.rva;
        if (address >= begin && address < begin + std::max<std::uint64_t>(s.virtual_size, s.raw_size))
            return (s.characteristics & 0x20000000u) != 0;
    }
    return false;
}

// Recover the case targets of an indirect `jmp` through a jump table (x86/x64).
// Conservative by design: every candidate target must land in an executable
// section, and the first failure stops the scan, so a misidentified pattern
// yields few or no targets rather than corrupting the function body. Handles the
// three dominant compiler shapes:
//   * x64 PIC rel32:  lea base,[rip+d] ; movsxd r,[base+idx*4] ; add r,base ; jmp r
//                     table at `base`, entries are int32 offsets from `base`.
//   * x64 absolute:   lea base,[rip+d] ; jmp qword ptr [base+idx*8]
//                     table at `base`, entries are 64-bit absolute addresses.
//   * x86 absolute:   jmp dword ptr [table+idx*4]   (table is an absolute imm)
std::vector<std::uint64_t> resolve_switch(const BinaryImage& image, const Instruction& jmp,
                                          const std::vector<Instruction>& body,
                                          std::size_t* slot_count = nullptr) {
    std::vector<std::uint64_t> targets;
    if (slot_count) *slot_count = 0;
    if (jmp.operands.empty()) return targets;
    const bool is64 = image.is_64_bit;
    const std::size_t ptr = is64 ? 8 : 4;

    auto read = [&](std::uint64_t va, std::size_t n, std::uint64_t& out) -> bool {
        const auto off = image.va_to_file_offset(va);
        if (!off || *off + n > image.bytes.size()) return false;
        out = 0;
        for (std::size_t i = 0; i < n; ++i) out |= static_cast<std::uint64_t>(image.bytes[*off + i]) << (8 * i);
        return true;
    };

    // Instructions in the small window just before the jump, address-sorted.
    std::vector<const Instruction*> recent;
    for (const auto& i : body)
        if (i.address < jmp.address && i.address + 0x80 >= jmp.address) recent.push_back(&i);
    std::sort(recent.begin(), recent.end(), [](auto a, auto b) { return a->address < b->address; });

    // Parse a memory operand "[reg + idx*scale + disp]": optionally require it to
    // mention `reg`; return the index scale and the signed displacement.
    auto parse_mem = [](const std::string& operand, const std::string& reg,
                        int& scale, long long& disp) -> bool {
        const auto lb = operand.find('[');
        if (lb == std::string::npos) return false;
        const auto rb = operand.find(']', lb);
        if (rb == std::string::npos) return false;
        const std::string inner = operand.substr(lb + 1, rb - lb - 1);
        if (!reg.empty() && inner.find(reg) == std::string::npos) return false;
        scale = 1; disp = 0;
        if (const auto star = inner.find('*'); star != std::string::npos) scale = std::atoi(inner.c_str() + star + 1);
        for (std::size_t i = 0; i + 1 < inner.size(); ++i) {
            if (inner[i] == '0' && (inner[i + 1] == 'x' || inner[i + 1] == 'X')) {
                char* endp = nullptr;
                const auto v = std::strtoull(inner.c_str() + i, &endp, 16);
                std::size_t j = i; while (j > 0 && inner[j - 1] == ' ') --j;
                disp = (j > 0 && inner[j - 1] == '-') ? -static_cast<long long>(v) : static_cast<long long>(v);
                i = static_cast<std::size_t>(endp - inner.c_str()) - 1;
            }
        }
        return true;
    };
    auto first_reg = [](const std::string& operands) -> std::string {
        const auto comma = operands.find(',');
        std::string r = comma == std::string::npos ? operands : operands.substr(0, comma);
        const auto s = r.find_first_not_of(' '); if (s != std::string::npos) r = r.substr(s);
        const auto e = r.find_first_of(" ,"); if (e != std::string::npos) r = r.substr(0, e);
        return r;
    };

    // Table base + its register from the most recent `lea reg, [rip+disp]`.
    std::uint64_t base = 0; bool have_base = false; std::string base_reg;
    for (auto it = recent.rbegin(); it != recent.rend(); ++it)
        if (strip_prefix((*it)->mnemonic) == "lea")
            if (const auto t = rip_target(**it)) { base = *t; have_base = true; base_reg = first_reg((*it)->operands); break; }

    // Case count from a preceding compare against an immediate upper bound.
    std::uint64_t count = 0;
    for (auto it = recent.rbegin(); it != recent.rend(); ++it) {
        const auto m = strip_prefix((*it)->mnemonic);
        if (m != "cmp" && m != "sub") continue;
        const auto comma = (*it)->operands.rfind(',');
        if (comma == std::string::npos) continue;
        std::string t = (*it)->operands.substr(comma + 1);
        const auto s = t.find_first_not_of(' ');
        if (s != std::string::npos) t = t.substr(s);
        std::uint64_t v = 0;
        if (parse_hex(t, v) || (v = std::strtoull(t.c_str(), nullptr, 0)) != 0) { count = v + 1; break; }
    }
    const std::uint64_t cap = (count && count <= 4096) ? count : 1024;

    const std::string& ops = jmp.operands;
    const bool memory = ops.find('[') != std::string::npos;

    std::uint64_t table = 0; bool have_table = false; std::size_t stride = 0; bool rel32 = false;
    int scale = 0; long long disp = 0;
    if (!memory) {
        // Register-indirect jump (x64 PIC rel32): a separate load reads the table
        // as [base + idx*scale + disp]; entries are int32 offsets from base.
        if (!have_base) return targets;
        bool found_load = false;
        for (auto it = recent.rbegin(); it != recent.rend(); ++it) {
            if ((*it)->operands.find('*') == std::string::npos) continue;
            if (parse_mem((*it)->operands, base_reg, scale, disp)) { found_load = true; break; }
        }
        if (!found_load) { scale = 4; disp = 0; }
        table = base + static_cast<std::uint64_t>(disp);
        have_table = true; stride = (scale == 8 ? 8 : 4); rel32 = true;
    } else {
        // Memory-indirect jump: entries are absolute pointers. Table = base+disp
        // (x64 PIC) or the absolute displacement itself (x86 jmp [imm+idx*scale]).
        parse_mem(ops, std::string(), scale, disp);
        if (have_base && ops.find(base_reg) != std::string::npos) table = base + static_cast<std::uint64_t>(disp);
        else if (disp != 0) table = static_cast<std::uint64_t>(disp);
        else return targets;
        have_table = true; stride = (scale == 4 ? 4 : ptr); rel32 = false;
    }
    (void)have_table;

    for (std::uint64_t i = 0; i < cap; ++i) {
        std::uint64_t entry = 0;
        if (!read(table + i * stride, stride, entry)) break;
        std::uint64_t target;
        if (rel32) {
            const auto off32 = static_cast<std::int32_t>(static_cast<std::uint32_t>(entry));
            target = base + static_cast<std::uint64_t>(static_cast<std::int64_t>(off32));
        } else {
            target = entry;
        }
        if (!is_exec(image, target)) break;
        targets.push_back(target);
    }
    if (targets.size() < 2) { targets.clear(); return targets; }   // a lone "case" is almost always a false positive
    if (slot_count) *slot_count = targets.size();                   // total table entries = source-level cases
    // Collapse to distinct successor blocks: many table slots routinely route to
    // the same case body (shared handlers, fall-through groups). The CFG has one
    // edge per distinct target, so duplicates here would inflate the edge count
    // and plant duplicate xrefs / graph edges.
    std::vector<std::uint64_t> distinct;
    distinct.reserve(targets.size());
    for (const auto t : targets)
        if (std::find(distinct.begin(), distinct.end(), t) == distinct.end()) distinct.push_back(t);
    return distinct;
}

const std::unordered_set<std::string>& noreturn_names() {
    static const std::unordered_set<std::string> names = {
        "exit", "_exit", "_Exit", "abort", "quick_exit", "ExitProcess", "ExitThread", "RtlExitUserProcess", "RtlExitUserThread",
        "FatalExit", "FatalAppExitA", "FatalAppExitW", "__stack_chk_fail", "__chk_fail", "__assert_fail", "__assert", "_wassert",
        "longjmp", "_longjmp", "siglongjmp", "__longjmp_chk", "pthread_exit", "__cxa_throw", "__cxa_rethrow", "_CxxThrowException",
        "terminate", "_invalid_parameter_noinfo_noreturn", "__fortify_fail", "__cxa_bad_cast", "__cxa_bad_typeid", "_Unwind_Resume",
        "__cxa_pure_virtual", "_amsg_exit", "__fastfail", "__report_gsfailure", "_abort", "__libc_fatal", "__GI_abort"};
    return names;
}

std::string clean_import_name(std::string name) {
    if (name.rfind("__imp_", 0) == 0) name = name.substr(6);
    const auto at = name.find('@');
    if (at != std::string::npos && at > 0) name.resize(at);
    return name;
}

} // namespace

// ---------------------------------------------------------------- signatures
void SignatureSet::add(Entry entry) {
    if (entry.pattern.empty() || !entry.pattern.front()) return;
    by_first_byte_.emplace(*entry.pattern.front(), entries_.size());
    entries_.push_back(std::move(entry));
}

std::uint16_t flirt_crc16(const std::uint8_t* data, std::size_t length) {
    if (length == 0) return 0;
    std::uint32_t crc = 0xFFFF;
    for (std::size_t i = 0; i < length; ++i) {
        std::uint32_t byte = data[i];
        for (int bit = 0; bit < 8; ++bit) {
            if ((crc ^ byte) & 1) crc = (crc >> 1) ^ 0x8408; else crc >>= 1;
            byte >>= 1;
        }
    }
    crc = ~crc & 0xFFFF;
    crc = ((crc << 8) | (crc >> 8)) & 0xFFFF;
    return static_cast<std::uint16_t>(crc);
}

bool SignatureSet::load_pat_file(const std::filesystem::path& file, std::string& error) {
    std::ifstream in(file);
    if (!in) { error = "cannot open pattern file"; return false; }
    std::string line;
    std::size_t loaded = 0;
    while (std::getline(in, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (line.empty() || line == "---" || line[0] == '#') continue;
        std::istringstream tokens(line);
        std::string leading, crc_length, crc, total;
        if (!(tokens >> leading >> crc_length >> crc >> total)) continue;
        if (leading.size() % 2 != 0) continue;
        Entry entry;
        bool ok = true;
        for (std::size_t i = 0; i + 1 < leading.size() && ok; i += 2) {
            if (leading[i] == '.' && leading[i + 1] == '.') entry.pattern.push_back(std::nullopt);
            else if (std::isxdigit(static_cast<unsigned char>(leading[i])) && std::isxdigit(static_cast<unsigned char>(leading[i + 1])))
                entry.pattern.push_back(static_cast<std::uint8_t>(std::strtoul(leading.substr(i, 2).c_str(), nullptr, 16)));
            else ok = false;
        }
        if (!ok || entry.pattern.empty()) continue;
        entry.crc_length = std::strtoul(crc_length.c_str(), nullptr, 16);
        entry.crc = static_cast<std::uint16_t>(std::strtoul(crc.c_str(), nullptr, 16));
        entry.total_length = std::strtoul(total.c_str(), nullptr, 16);
        std::string token;
        while (tokens >> token) {   // ":0000 name" - the module name at offset 0 names the function
            if (token.size() >= 5 && token[0] == ':' && token.find_first_not_of("0123456789ABCDEF", 1) == std::string::npos && token.size() == 5) {
                std::string name;
                if (!(tokens >> name)) break;
                if (token == ":0000" && entry.name.empty() && name != "?") entry.name = name;
            } else if (token[0] == '^') { std::string ignored; tokens >> ignored; }
        }
        if (entry.name.empty() || !entry.pattern.front()) continue;
        add(std::move(entry)); ++loaded;
    }
    if (!loaded) { error = "no usable pattern lines"; return false; }
    return true;
}

bool SignatureSet::load_file(const std::filesystem::path& file, std::string& error) {
    {
        std::string extension = file.extension().string();
        for (auto& ch : extension) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (extension == ".pat") return load_pat_file(file, error);
    }
    std::ifstream in(file);
    if (!in) { error = "cannot open signature file"; return false; }
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        Entry entry;
        entry.name = line.substr(0, colon);
        while (!entry.name.empty() && std::isspace(static_cast<unsigned char>(entry.name.back()))) entry.name.pop_back();
        std::istringstream bytes(line.substr(colon + 1));
        std::string token;
        while (bytes >> token) {
            if (token == "??" || token == "?") entry.pattern.push_back(std::nullopt);
            else entry.pattern.push_back(static_cast<std::uint8_t>(std::strtoul(token.c_str(), nullptr, 16)));
        }
        add(std::move(entry));
    }
    return true;
}

std::string SignatureSet::match(const BinaryImage& image, std::uint64_t address) const {
    const auto offset = image.va_to_file_offset(address);
    if (!offset) return {};
    const std::uint8_t* data = image.bytes.data() + *offset;
    const auto available = image.bytes.size() - *offset;
    const auto range = by_first_byte_.equal_range(*data);
    const Entry* best = nullptr;
    for (auto it = range.first; it != range.second; ++it) {
        const auto& entry = entries_[it->second];
        if (entry.pattern.size() > available) continue;
        bool ok = true;
        for (std::size_t i = 0; i < entry.pattern.size() && ok; ++i)
            if (entry.pattern[i] && *entry.pattern[i] != data[i]) ok = false;
        if (ok && entry.crc_length) {   // FLIRT: CRC16 of the relocation-free bytes after the leading 32
            const std::size_t start = 32;
            if (available < start + entry.crc_length || flirt_crc16(data + start, entry.crc_length) != entry.crc) ok = false;
        }
        const auto weight = [](const Entry& e) { return e.pattern.size() + e.crc_length * 2; };
        if (ok && (!best || weight(entry) > weight(*best))) best = &entry;
    }
    return best ? best->name : std::string();
}

std::string SignatureSet::to_text() const {
    std::ostringstream out;
    out << "# gandon signatures: name: bytes (?? = wildcard)\n";
    static const char* digits = "0123456789ABCDEF";
    for (const auto& e : entries_) {
        out << e.name << ":";
        for (const auto& b : e.pattern) {
            out << ' ';
            if (b) out << digits[*b >> 4] << digits[*b & 15]; else out << "??";
        }
        out << '\n';
    }
    return out.str();
}

std::string SignatureSet::to_pat_text() const {
    std::ostringstream out;
    static const char* digits = "0123456789ABCDEF";
    for (const auto& e : entries_) {
        std::string leading;
        for (std::size_t i = 0; i < 32; ++i) {
            if (i < e.pattern.size() && e.pattern[i]) { leading += digits[*e.pattern[i] >> 4]; leading += digits[*e.pattern[i] & 15]; }
            else leading += "..";
        }
        std::vector<std::uint8_t> crc_bytes;
        for (std::size_t i = 32; i < e.pattern.size() && e.pattern[i] && crc_bytes.size() < 255; ++i) crc_bytes.push_back(*e.pattern[i]);
        char tail[96];
        std::snprintf(tail, sizeof tail, " %02X %04X %04X :0000 ", static_cast<unsigned>(crc_bytes.size()),
                      static_cast<unsigned>(flirt_crc16(crc_bytes.data(), crc_bytes.size())), static_cast<unsigned>(e.pattern.size()));
        out << leading << tail << e.name << "\r\n";
    }
    out << "---\r\n";
    return out.str();
}

SignatureSet make_signatures(const AnalysisDatabase& database, std::size_t max_bytes) {
    SignatureSet set;
    std::set<std::vector<int>> seen;
    for (const auto& f : database.functions()) {
        if (f.name.empty() || f.name.rfind("sub_", 0) == 0 || f.name.rfind("loc_", 0) == 0) continue;
        auto instructions = f.instructions;
        std::sort(instructions.begin(), instructions.end(), [](const Instruction& a, const Instruction& b) { return a.address < b.address; });
        if (instructions.empty() || instructions.front().address != f.start) continue;
        SignatureSet::Entry entry;
        entry.name = f.name;
        std::uint64_t expected = f.start;
        const bool arm = database.image().architecture == MachineArchitecture::ARM64;
        for (const auto& ins : instructions) {
            if (ins.address != expected || entry.pattern.size() + ins.size > max_bytes) break;
            std::vector<bool> mask(ins.size, false);
            auto mask_value = [&](std::uint64_t v) {
                for (std::size_t i = 0; i + 4 <= ins.size; ++i) {
                    const std::uint32_t le = ins.bytes[i] | (ins.bytes[i + 1] << 8) | (ins.bytes[i + 2] << 16) |
                                             (static_cast<std::uint32_t>(ins.bytes[i + 3]) << 24);
                    if (le == static_cast<std::uint32_t>(v)) { for (int k = 0; k < 4; ++k) mask[i + k] = true; return; }
                }
            };
            std::uint64_t target = 0;
            const auto m = strip_prefix(ins.mnemonic);
            if (arm) {
                // pc-relative encodings change with the position: wildcard the whole 32-bit word
                const bool relative = m == "bl" || m == "b" || m.rfind("b.", 0) == 0 || m == "cbz" || m == "cbnz" || m == "tbz" || m == "tbnz" ||
                                      m == "adrp" || m == "adr" || (m.rfind("ldr", 0) == 0 && ins.operands.find('[') == std::string::npos);
                if (relative) std::fill(mask.begin(), mask.end(), true);
            } else if ((m == "call" || m == "jmp" || is_conditional_jump(m)) && direct_target(ins, target)) {
                mask_value(target - (ins.address + ins.size));
            } else if (const auto rt = rip_target(ins)) {
                mask_value(*rt - (ins.address + ins.size));
            } else {
                std::istringstream ops(ins.operands);
                std::string token;
                std::string text = ins.operands;
                for (char& c : text) if (c == ',' || c == '[' || c == ']' || c == '+' || c == '-' || c == '*') c = ' ';
                std::istringstream parts(text);
                while (parts >> token) {
                    std::uint64_t value = 0;
                    if (parse_hex(token, value) && value >= 0x1000) mask_value(value);
                }
            }
            for (std::size_t i = 0; i < ins.size; ++i)
                entry.pattern.push_back(mask[i] ? std::nullopt : std::optional<std::uint8_t>(ins.bytes[i]));
            expected += ins.size;
        }
        std::size_t literal = 0;
        for (const auto& b : entry.pattern) literal += b ? 1 : 0;
        if (literal < 8 || entry.pattern.size() < 12) continue;
        std::vector<int> key;
        for (const auto& b : entry.pattern) key.push_back(b ? *b : -1);
        if (!seen.insert(key).second) continue;
        set.add(std::move(entry));
    }
    return set;
}

// ------------------------------------------------------------- auto-analysis
AutoAnalysisReport run_auto_analysis(AnalysisDatabase& db, const AutoAnalysisOptions& options) {
    AutoAnalysisReport report;
    const auto& image = db.image();
    if (image.architecture != MachineArchitecture::X64 && image.architecture != MachineArchitecture::X86 && image.architecture != MachineArchitecture::ARM64) {
        report.log.push_back("auto-analysis supports x86/x64/ARM64 only");
        return report;
    }
    g_arm64 = image.architecture == MachineArchitecture::ARM64;
    const std::size_t step_alignment = g_arm64 ? 4 : 1;

    std::unordered_set<std::uint64_t> known_instructions;
    std::unordered_set<std::uint64_t> function_starts;
    for (const auto& f : db.functions()) {
        function_starts.insert(f.start);
        for (const auto& ins : f.instructions) known_instructions.insert(ins.address);
    }

    // ---- 1. recursive descent from call targets and code pointers
    if (options.discover_functions) {
        for (std::size_t round = 0; round < 24; ++round) {
            std::set<std::uint64_t> candidates;
            for (const auto& x : db.xrefs()) {
                if (!is_exec(image, x.to) || function_starts.count(x.to) || known_instructions.count(x.to)) continue;
                if (g_arm64 && x.to % step_alignment) continue;
                if (x.kind == "call") {
                    candidates.insert(x.to);
                } else if (x.kind == "offset" || x.kind == "data") {
                    if (g_arm64) {
                        // A code pointer is a function when it follows a terminator (ret / b / br / brk) or padding.
                        const auto previous = decode_instructions(image, x.to - 4, 1);
                        const bool after_end = !previous.empty() && (m_is_ret(previous[0].mnemonic) || m_is_uncond(previous[0].mnemonic) ||
                                                                      m_is_indirect_branch(previous[0].mnemonic) || m_is_halt(previous[0].mnemonic) || previous[0].mnemonic == "nop");
                        if (after_end || x.to % 16 == 0) candidates.insert(x.to);
                        continue;
                    }
                    const auto before = image.va_to_file_offset(x.to - 1);
                    const bool aligned = x.to % 16 == 0;
                    const bool padded = before && (image.bytes[*before] == 0xCC || image.bytes[*before] == 0xC3 || image.bytes[*before] == 0x90);
                    if (aligned || padded) candidates.insert(x.to);
                }
            }
            if (g_arm64 && round == 0) {
                // Stripped AArch64 code: look for typical prologues (stp x29, x30, [sp, #-N]! / sub sp + stp) after a terminator.
                const auto word_at = [&](std::uint64_t address) -> std::optional<std::uint32_t> {
                    const auto o = image.va_to_file_offset(address);
                    if (!o || *o + 4 > image.bytes.size()) return std::nullopt;
                    return static_cast<std::uint32_t>(image.bytes[*o]) | (static_cast<std::uint32_t>(image.bytes[*o + 1]) << 8) |
                           (static_cast<std::uint32_t>(image.bytes[*o + 2]) << 16) | (static_cast<std::uint32_t>(image.bytes[*o + 3]) << 24);
                };
                const auto is_stp_fp_lr = [](std::uint32_t w) { return (w & 0xFFC07FFFu) == 0xA9807BFDu || (w & 0xFFC07FFFu) == 0xA9007BFDu; };
                const auto is_sub_sp = [](std::uint32_t w) { return (w & 0xFF8003FFu) == 0xD10003FFu; };
                const auto is_pac = [](std::uint32_t w) { return w == 0xD503233Fu || w == 0xD503245Fu || w == 0xD503249Fu; };
                const auto is_end = [](std::uint32_t w) { return w == 0xD65F03C0u || (w & 0xFC000000u) == 0x14000000u || (w & 0xFFFFFC1Fu) == 0xD61F0000u || (w & 0xFFE0001Fu) == 0xD4200000u || w == 0xD503201Fu || w == 0u; };
                std::size_t found_prologues = 0;
                for (const auto& section : image.sections) {
                    if (!(section.characteristics & 0x20000000u)) continue;
                    const auto begin = image.image_base + section.rva;
                    const auto end = begin + std::max<std::uint64_t>(section.virtual_size, section.raw_size);
                    for (std::uint64_t a = begin + 4; a + 12 < end && found_prologues < options.max_new_functions; a += 4) {
                        if (function_starts.count(a) || known_instructions.count(a)) continue;
                        const auto w0 = word_at(a), previous = word_at(a - 4);
                        if (!w0 || !previous || !is_end(*previous)) continue;
                        bool prologue = false;
                        std::uint64_t cursor = a;
                        auto w = w0;
                        if (w && is_pac(*w)) { cursor += 4; w = word_at(cursor); }
                        if (w && is_stp_fp_lr(*w)) prologue = true;
                        else if (w && is_sub_sp(*w)) {
                            const auto w1 = word_at(cursor + 4), w2 = word_at(cursor + 8);
                            prologue = (w1 && is_stp_fp_lr(*w1)) || (w2 && is_stp_fp_lr(*w2));
                        }
                        if (prologue) { candidates.insert(a); ++found_prologues; }
                    }
                }
                if (found_prologues) report.log.push_back("prologue scan: " + std::to_string(found_prologues) + " candidate(s)");
            }
            if (candidates.empty()) break;
            std::size_t added_this_round = 0;
            for (const auto start : candidates) {
                if (report.functions_added >= options.max_new_functions) break;
                const auto first = decode_instructions(image, start, 1);
                if (first.empty() || first[0].mnemonic.empty() || (!g_arm64 && (first[0].mnemonic == "int3" || (first[0].mnemonic == "add" && first[0].operands == "byte ptr [rax], al")))) continue;
                if (g_arm64 && (first[0].mnemonic == "nop" || first[0].mnemonic == "udf")) continue;

                Function f;
                f.start = start;
                char name[32];
                std::snprintf(name, sizeof name, "sub_%llX", static_cast<unsigned long long>(start));
                f.name = name;
                std::set<std::uint64_t> seen;
                std::vector<std::uint64_t> work{start};
                std::vector<Instruction> body;
                while (!work.empty() && body.size() < 6000) {
                    auto a = work.back();
                    work.pop_back();
                    while (body.size() < 6000) {
                        if (seen.count(a) || (known_instructions.count(a) && a != start)) break;
                        const auto decoded = decode_instructions(image, a, 1);
                        if (decoded.empty()) break;
                        const auto& ins = decoded[0];
                        seen.insert(a);
                        body.push_back(ins);
                        const auto m = strip_prefix(ins.mnemonic);
                        std::uint64_t target = 0;
                        const bool direct = direct_target(ins, target);
                        if (m_is_ret(m) || m_is_halt(m) || m_is_indirect_branch(m)) break;
                        if (m_is_uncond(m)) {
                            if (direct && target >= start && target < start + 0x8000 && is_exec(image, target) && !function_starts.count(target))
                                work.push_back(target);
                            else if (!direct && !g_arm64) {
                                // Indirect jmp: recover switch/jump-table case targets.
                                std::size_t slots = 0;
                                const auto cases = resolve_switch(image, ins, body, &slots);
                                if (!cases.empty()) { ++report.switches; report.switch_edges += cases.size(); report.switch_cases += slots; }
                                for (const auto t : cases)
                                    if (is_exec(image, t) && !function_starts.count(t) &&
                                        t + 0x40000 >= start && t < start + 0x40000) {
                                        work.push_back(t);
                                        db.add_xref({ins.address, t, "jmp"});
                                    }
                            }
                            break;
                        }
                        if (m_is_cond(m)) {
                            if (direct && is_exec(image, target) && target >= start && target < start + 0x8000 && !function_starts.count(target))
                                work.push_back(target);
                        }
                        a += std::max<std::uint8_t>(ins.size, 1);
                    }
                }
                if (body.empty()) continue;
                std::sort(body.begin(), body.end(), [](const Instruction& l, const Instruction& r) { return l.address < r.address; });
                std::uint64_t end = start;
                for (const auto& ins : body) {
                    end = std::max<std::uint64_t>(end, ins.address + ins.size);
                    known_instructions.insert(ins.address);
                    std::uint64_t target = 0;
                    const auto m = strip_prefix(ins.mnemonic);
                    if (direct_target(ins, target) && (m_is_call(m) || m_is_uncond(m) || m_is_cond(m))) {
                        db.add_xref({ins.address, target, m_is_call(m) ? "call" : m_is_uncond(m) ? "jmp" : "jcc"});
                        if (m_is_call(m)) f.callees.push_back(target);
                    }
                }
                std::sort(f.callees.begin(), f.callees.end());
                f.callees.erase(std::unique(f.callees.begin(), f.callees.end()), f.callees.end());
                f.instructions = std::move(body);
                f.end = end;
                function_starts.insert(start);
                db.add_function(std::move(f));
                ++report.functions_added;
                ++added_this_round;
            }
            ++report.rounds;
            if (!added_this_round) break;
        }
        if (report.functions_added) db.sort_functions();
        report.log.push_back("recursive descent: " + std::to_string(report.functions_added) + " new function(s) in " + std::to_string(report.rounds) + " round(s)");
        // Second pass: resolve switch tables in every function body (including
        // those loaded before analysis, e.g. exports), recording the case edges
        // as xrefs so the CFG, graph and decompiler see them.
        if (!g_arm64) {
            std::vector<Xref> switch_xrefs;
            for (const auto& f : db.functions()) {
                for (const auto& ins : f.instructions) {
                    if (!m_is_uncond(strip_prefix(ins.mnemonic))) continue;
                    std::uint64_t direct = 0;
                    if (direct_target(ins, direct)) continue;        // only indirect jumps
                    bool already = false;
                    for (const auto& xr : db.xrefs_at(ins.address))
                        if (xr.get().kind == "jmp" || xr.get().kind == "switch") { already = true; break; }
                    if (already) continue;
                    std::size_t slots = 0;
                    const auto cases = resolve_switch(image, ins, f.instructions, &slots);
                    if (cases.empty()) continue;
                    ++report.switches; report.switch_edges += cases.size(); report.switch_cases += slots;
                    for (const auto t : cases) switch_xrefs.push_back({ins.address, t, "switch"});
                }
            }
            for (const auto& x : switch_xrefs) db.add_xref(x);
        }
        if (report.switches)
            report.log.push_back("switch tables: " + std::to_string(report.switches) + " resolved, " +
                                 std::to_string(report.switch_cases) + " case(s) -> " +
                                 std::to_string(report.switch_edges) + " distinct edge(s)");
    }

    // ---- 2. names: imports + thunks + signatures
    std::unordered_map<std::uint64_t, std::string> import_slots;
    for (const auto& i : image.imports) import_slots[i.address] = clean_import_name(i.name);
    for (const auto& i : parse_imports(image)) import_slots[i.iat] = clean_import_name(i.name);

    std::unordered_map<std::uint64_t, std::string> thunk_target_name; // function start -> import name
    for (const auto& f : db.functions()) {
        const Instruction* sole = nullptr;
        int count = 0;
        for (const auto& ins : f.instructions) {
            const auto m = strip_prefix(ins.mnemonic);
            if (m == "endbr64" || m == "nop") continue;
            sole = &ins;
            ++count;
        }
        if (g_arm64) {
            // PLT stub: adrp x16, page ; ldr x17, [x16, #off] ; add x16, x16, #off ; br x17
            if (f.instructions.size() > 6 || f.instructions.empty() || !m_is_indirect_branch(f.instructions.back().mnemonic)) continue;
            for (const auto& ins : f.instructions) {
                bool named = false;
                for (const auto& xr : db.xrefs_at(ins.address)) {
                    const auto& kind = xr.get().kind;
                    const auto bang = kind.find('!');
                    if (kind.rfind("import:", 0) == 0 && bang != std::string::npos) { thunk_target_name[f.start] = clean_import_name(kind.substr(bang + 1)); named = true; break; }
                }
                if (named) break;
            }
            continue;
        }
        if (count != 1 || !sole || strip_prefix(sole->mnemonic) != "jmp") continue;
        const auto slot = rip_target(*sole);
        if (!slot) continue;
        const auto found = import_slots.find(*slot);
        if (found != import_slots.end()) thunk_target_name[f.start] = found->second;
    }
    for (const auto& [start, name] : thunk_target_name) {
        const auto* fn = [&]() -> const Function* { auto o = db.function_at(start); return o ? &o->get() : nullptr; }();
        if (fn && fn->name.rfind("sub_", 0) == 0 && db.rename_function(start, name)) {
            report.new_names[start] = name;
            ++report.import_thunks;
        }
    }
    if (options.signatures && options.signatures->size()) {
        std::vector<std::pair<std::uint64_t, std::string>> renames;
        for (const auto& f : db.functions()) {
            if (f.name.rfind("sub_", 0) != 0) continue;
            const auto matched = options.signatures->match(image, f.start);
            if (!matched.empty()) renames.push_back({f.start, matched});
        }
        for (const auto& [start, name] : renames)
            if (db.rename_function(start, name)) { report.new_names[start] = name; ++report.functions_renamed; }
    }
    report.log.push_back("names: " + std::to_string(report.import_thunks) + " import thunk(s), " + std::to_string(report.functions_renamed) + " signature match(es)");

    // ---- 3. noreturn propagation
    if (options.detect_noreturn) {
        auto name_of_function = [&](const Function& f) {
            const auto thunk = thunk_target_name.find(f.start);
            return thunk != thunk_target_name.end() ? thunk->second : f.name;
        };
        auto& noret = report.noreturn;
        for (const auto& f : db.functions())
            if (noreturn_names().count(clean_import_name(name_of_function(f)))) noret.insert(f.start);
        for (const auto& [slot, name] : import_slots) (void)slot, (void)name;

        auto callee_is_noreturn = [&](const Instruction& ins) {
            std::uint64_t target = 0;
            if (direct_target(ins, target)) return noret.count(target) != 0;
            if (const auto slot = rip_target(ins)) {
                const auto found = import_slots.find(*slot);
                return found != import_slots.end() && noreturn_names().count(found->second) != 0;
            }
            return false;
        };
        bool changed = true;
        for (int pass = 0; changed && pass < 32; ++pass) {
            changed = false;
            for (const auto& f : db.functions()) {
                if (noret.count(f.start) || f.instructions.empty()) continue;
                std::uint64_t end = f.end;
                for (const auto& ins : f.instructions) end = std::max<std::uint64_t>(end, ins.address + ins.size);
                bool saw = false, ok = true;
                for (const auto& ins : f.instructions) {
                    const auto m = strip_prefix(ins.mnemonic);
                    if (m_is_ret(m)) { ok = false; break; }
                    if (m_is_halt(m)) saw = true;
                    else if (m_is_call(m)) { if (callee_is_noreturn(ins)) saw = true; }
                    else if (m_is_indirect_branch(m)) { ok = false; break; }
                    else if (m_is_uncond(m)) {
                        std::uint64_t target = 0;
                        if (direct_target(ins, target)) {
                            if (target >= f.start && target < end) continue;
                            if (noret.count(target)) saw = true; else { ok = false; break; }
                        } else if (callee_is_noreturn(ins)) saw = true;
                        else { ok = false; break; }
                    }
                }
                if (ok && saw) { noret.insert(f.start); changed = true; }
            }
        }
        report.noreturn_functions = noret.size();
        report.log.push_back("noreturn: " + std::to_string(noret.size()) + " function(s)");
    }
    return report;
}

} // namespace gandon
