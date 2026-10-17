#pragma once

#include "gandon/core.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace gandon {

// FLIRT-like byte signatures: the first bytes of a function with relocation
// dependent bytes wildcarded. Text format, one per line:
//     name: 55 48 89 E5 ?? ?? ?? ?? 5D C3
class SignatureSet {
public:
    // pattern: the leading bytes (nullopt = relocated / wildcard). FLIRT .pat entries add a CRC16 over the
    // relocation-free bytes that follow the leading 32 (crc_length == 0: no CRC check).
    struct Entry { std::string name; std::vector<std::optional<std::uint8_t>> pattern; std::size_t crc_length{0}; std::uint16_t crc{0}; std::size_t total_length{0}; };
    // Loads the native text format or, for *.pat files, IDA FLAIR pattern files.
    bool load_file(const std::filesystem::path& file, std::string& error);
    bool load_pat_file(const std::filesystem::path& file, std::string& error);
    void add(Entry entry);
    std::size_t size() const noexcept { return entries_.size(); }
    // Returns the matching name for the bytes at `address`, or "".
    std::string match(const BinaryImage& image, std::uint64_t address) const;
    std::string to_text() const;
    std::string to_pat_text() const;   // IDA FLAIR .pat lines (leading 32 bytes + CRC16 of the relocation-free bytes after them)
    const std::vector<Entry>& entries() const noexcept { return entries_; }
private:
    std::vector<Entry> entries_;
    std::multimap<std::uint8_t, std::size_t> by_first_byte_;
};

struct AutoAnalysisOptions {
    bool discover_functions{true};
    bool detect_noreturn{true};
    const SignatureSet* signatures{nullptr};
    std::size_t max_new_functions{20000};
};

struct AutoAnalysisReport {
    std::size_t functions_added{0};
    std::size_t functions_renamed{0};
    std::size_t import_thunks{0};
    std::size_t noreturn_functions{0};
    std::size_t rounds{0};
    std::size_t switches{0};        // indirect jumps resolved as jump tables
    std::size_t switch_edges{0};    // distinct case targets (= CFG successor edges)
    std::size_t switch_cases{0};    // total table slots (= source-level case labels)
    std::set<std::uint64_t> noreturn;                 // function starts
    std::map<std::uint64_t, std::string> new_names;   // address -> name chosen by signatures / import thunks
    std::vector<std::string> log;
};

// Recursive-descent function discovery from call targets and code pointers,
// import-thunk naming, signature matching and noreturn propagation.
// Mutates the database (adds functions / xrefs, renames sub_ functions).
AutoAnalysisReport run_auto_analysis(AnalysisDatabase& database, const AutoAnalysisOptions& options = {});

// Builds signatures from every named (non sub_) function of the database.
// IDA FLIRT CRC16 (reflected 0x8408, init 0xFFFF, complemented, bytes swapped).
std::uint16_t flirt_crc16(const std::uint8_t* data, std::size_t length);

SignatureSet make_signatures(const AnalysisDatabase& database, std::size_t max_bytes = 32);

} // namespace gandon
