#pragma once

#include "gandon/core.hpp"
#include "gandon/types.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace gandon {

// Text renderers that follow the layout of IDA Pro's windows (IDA View-A text
// mode, Xrefs, Hex View-1, Imports, Exports, Strings, Names, Segments,
// Problems). Output is UTF-8 with '\n' line endings.
struct IdaViewConfig {
    std::map<std::uint64_t, std::string> user_names;     // renamed labels / functions
    std::map<std::uint64_t, std::string> user_comments;  // comment text per address
    std::set<std::uint64_t> noreturn;                    // function starts flagged by auto-analysis
    const TypeLibrary* types{nullptr};                   // local type library (optional)
    std::map<std::uint64_t, std::string> struct_offsets; // instruction address -> struct applied to its [reg+disp] operand
    std::map<std::uint64_t, std::string> enum_operands;  // instruction address -> enum applied to its immediate
    std::map<std::uint64_t, std::string> prototypes;     // function start -> declaration text shown above the function
    bool show_opcode_bytes{false};
    std::size_t max_lines{1500};
};

class IdaViews {
public:
    explicit IdaViews(const AnalysisDatabase& database, IdaViewConfig config = {});
    ~IdaViews();
    IdaViews(const IdaViews&) = delete;
    IdaViews& operator=(const IdaViews&) = delete;

    // Disassembly listing beginning at `start` (function start preferred).
    std::string listing(std::uint64_t start) const;
    // "Xrefs to" window for one address.
    std::string xrefs_to(std::uint64_t address) const;
    // Every cross-reference, one row each (capped).
    std::string xrefs_overview(std::size_t max_rows = 20000) const;
    std::string hex_view(std::uint64_t address, std::size_t rows = 256) const;
    std::string imports() const;
    std::string exports() const;
    std::string strings(std::size_t minimum_length = 5, std::size_t max_rows = 50000) const;
    std::string resources() const;
    std::string names() const;
    std::string segments() const;
    std::string problems(const std::vector<std::string>& debugger_events = {}) const;

    // Classified address ranges for the navigation band: 'F' function code,
    // 'S' string literal, 'I' import slot. Everything else is plain data.
    struct ItemRange { std::uint64_t begin{0}, end{0}; char kind{'D'}; };
    std::vector<ItemRange> item_ranges() const;

    // Helpers exposed for the GUI and tests.
    std::string segment_name(std::uint64_t address) const;
    std::string address_text(std::uint64_t address) const;          // ".text:0000000140001000"
    std::string symbolic(std::uint64_t address) const;              // "sub_140001000+4"
    std::string name_at(std::uint64_t address) const;               // "" when unnamed
    std::string format_instruction(const Instruction& instruction) const; // IDA-style mnemonic + operands

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace gandon
