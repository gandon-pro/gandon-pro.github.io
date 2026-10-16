#include "gandon/binary_diff.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <map>
#include <unordered_map>
#include <unordered_set>

namespace gandon {
namespace {

struct Features {
    std::size_t index{0};
    std::uint64_t hash{0};
    std::vector<std::uint64_t> grams;        // sorted, unique 2-gram hashes of normalised instructions
    std::size_t size{0};
    std::vector<std::uint64_t> callees;      // call targets in order
    std::vector<std::pair<std::uint64_t, int>> histogram;   // mnemonic -> count (sorted by hash)
    double norm{0};
    bool named{false};
    bool matched{false};
};

std::uint64_t fnv(const std::string& text, std::uint64_t seed = 1469598103934665603ull) {
    std::uint64_t h = seed;
    for (const unsigned char c : text) { h ^= c; h *= 1099511628211ull; }
    return h;
}

// "mov dword ptr [rsp + 0x58], 0x140001000" -> "mov dword ptr [rsp + 0x58], K": large numbers are addresses or
// relocation-dependent constants and must not make two otherwise identical functions differ.
std::string normalise(const Instruction& ins) {
    std::string out = ins.mnemonic;
    out += ' ';
    const std::string& s = ins.operands;
    for (std::size_t i = 0; i < s.size();) {
        if (s[i] == '0' && i + 1 < s.size() && (s[i + 1] == 'x' || s[i + 1] == 'X') && (i == 0 || !std::isalnum(static_cast<unsigned char>(s[i - 1])))) {
            std::size_t j = i + 2;
            while (j < s.size() && std::isxdigit(static_cast<unsigned char>(s[j]))) ++j;
            const unsigned long long value = std::strtoull(s.c_str() + i + 2, nullptr, 16);
            if (value >= 0x1000 || j - i - 2 >= 5) out += 'K'; else out.append(s, i, j - i);
            i = j;
        } else out += s[i++];
    }
    return out;
}

Features features_of(const Function& f, std::size_t index) {
    Features x; x.index = index;
    std::vector<Instruction> instructions = f.instructions;
    std::sort(instructions.begin(), instructions.end(), [](const Instruction& l, const Instruction& r) { return l.address < r.address; });
    x.size = instructions.size();
    std::uint64_t whole = 1469598103934665603ull;
    std::vector<std::uint64_t> items;
    items.reserve(instructions.size());
    for (const auto& ins : instructions) {
        const std::string n = normalise(ins);
        const std::uint64_t h = fnv(n);
        items.push_back(h);
        whole = fnv(n + "\n", whole);
    }
    x.hash = whole;
    {
        std::map<std::uint64_t, int> counts;
        for (const auto& ins : instructions) ++counts[fnv(ins.mnemonic)];
        double sum = 0;
        for (const auto& [h, c] : counts) { x.histogram.emplace_back(h, c); sum += static_cast<double>(c) * c; }
        x.norm = std::sqrt(sum);
    }
    for (std::size_t i = 0; i + 1 < items.size(); ++i) x.grams.push_back(items[i] * 1315423911ull ^ items[i + 1]);
    if (items.size() == 1) x.grams.push_back(items[0]);
    std::sort(x.grams.begin(), x.grams.end());
    x.grams.erase(std::unique(x.grams.begin(), x.grams.end()), x.grams.end());
    x.callees = f.callees;
    x.named = !f.name.empty() && f.name.rfind("sub_", 0) != 0 && f.name.rfind("loc_", 0) != 0 && f.name.rfind("unk_", 0) != 0 && f.name.find("EntryPoint") == std::string::npos;
    return x;
}

double histogram_similarity(const Features& a, const Features& b) {
    if (a.norm == 0 || b.norm == 0) return 0;
    std::size_t i = 0, j = 0; double dot = 0;
    while (i < a.histogram.size() && j < b.histogram.size()) {
        if (a.histogram[i].first == b.histogram[j].first) { dot += static_cast<double>(a.histogram[i].second) * b.histogram[j].second; ++i; ++j; }
        else if (a.histogram[i].first < b.histogram[j].first) ++i; else ++j;
    }
    return dot / (a.norm * b.norm);
}

double jaccard(const std::vector<std::uint64_t>& a, const std::vector<std::uint64_t>& b) {
    if (a.empty() && b.empty()) return 1.0;
    std::size_t i = 0, j = 0, common = 0;
    while (i < a.size() && j < b.size()) {
        if (a[i] == b[j]) { ++common; ++i; ++j; }
        else if (a[i] < b[j]) ++i; else ++j;
    }
    const std::size_t total = a.size() + b.size() - common;
    return total ? static_cast<double>(common) / static_cast<double>(total) : 1.0;
}

} // namespace

const char* diff_kind_name(FunctionDiffEntry::Kind kind) {
    switch (kind) {
    case FunctionDiffEntry::Kind::Identical: return "identical";
    case FunctionDiffEntry::Kind::Changed: return "changed";
    case FunctionDiffEntry::Kind::Added: return "added";
    default: return "removed";
    }
}

std::string FunctionDiffResult::summary() const {
    char buffer[160];
    std::snprintf(buffer, sizeof buffer, "%zu identical, %zu changed, %zu added, %zu removed", identical, changed, added, removed);
    return buffer;
}

FunctionDiffResult diff_functions(const AnalysisDatabase& a, const AnalysisDatabase& b) {
    const auto& fa = a.functions();
    const auto& fb = b.functions();
    std::vector<Features> xa, xb;
    xa.reserve(fa.size()); xb.reserve(fb.size());
    for (std::size_t i = 0; i < fa.size(); ++i) xa.push_back(features_of(fa[i], i));
    for (std::size_t i = 0; i < fb.size(); ++i) xb.push_back(features_of(fb[i], i));

    std::unordered_map<std::uint64_t, std::size_t> a_index_by_start, b_index_by_start;
    for (std::size_t i = 0; i < fa.size(); ++i) a_index_by_start[fa[i].start] = i;
    for (std::size_t i = 0; i < fb.size(); ++i) b_index_by_start[fb[i].start] = i;

    struct Pair { std::size_t a, b; std::string by; };
    std::vector<Pair> pairs;
    const auto link = [&](std::size_t ia, std::size_t ib, const char* by) {
        if (xa[ia].matched || xb[ib].matched) return false;
        xa[ia].matched = xb[ib].matched = true;
        pairs.push_back({ia, ib, by});
        return true;
    };

    // 1. same (non-generated) name
    {
        std::unordered_multimap<std::string, std::size_t> by_name;
        for (std::size_t i = 0; i < fb.size(); ++i) if (xb[i].named) by_name.emplace(fb[i].name, i);
        for (std::size_t i = 0; i < fa.size(); ++i) {
            if (!xa[i].named) continue;
            const auto range = by_name.equal_range(fa[i].name);
            if (std::distance(range.first, range.second) == 1) link(i, range.first->second, "name");
        }
    }
    // 2. identical normalised instruction stream (unique on both sides)
    {
        std::unordered_map<std::uint64_t, std::vector<std::size_t>> ga, gb;
        for (std::size_t i = 0; i < xa.size(); ++i) if (!xa[i].matched && xa[i].size >= 3) ga[xa[i].hash].push_back(i);
        for (std::size_t i = 0; i < xb.size(); ++i) if (!xb[i].matched && xb[i].size >= 3) gb[xb[i].hash].push_back(i);
        for (const auto& [hash, left] : ga) {
            const auto it = gb.find(hash);
            if (it == gb.end()) continue;
            if (left.size() == 1 && it->second.size() == 1) link(left[0], it->second[0], "hash");
            else {   // duplicates: pair in address order
                const std::size_t n = (std::min)(left.size(), it->second.size());
                for (std::size_t k = 0; k < n; ++k) link(left[k], it->second[k], "hash");
            }
        }
    }
    // 3. call-graph propagation: callees of matched pairs line up by position
    for (int round = 0; round < 6; ++round) {
        bool progress = false;
        const auto snapshot = pairs;
        for (const auto& p : snapshot) {
            const auto& ca = xa[p.a].callees; const auto& cb = xb[p.b].callees;
            if (ca.size() != cb.size()) continue;
            for (std::size_t k = 0; k < ca.size(); ++k) {
                const auto ia = a_index_by_start.find(ca[k]); const auto ib = b_index_by_start.find(cb[k]);
                if (ia == a_index_by_start.end() || ib == b_index_by_start.end()) continue;
                const double s = jaccard(xa[ia->second].grams, xb[ib->second].grams);
                if (s >= 0.45 && link(ia->second, ib->second, "callgraph")) progress = true;
            }
        }
        if (!progress) break;
    }
    // 4. similarity of the remaining functions (greedy best match above a threshold)
    {
        struct Candidate { double score; std::size_t a, b; };
        std::vector<Candidate> candidates;
        std::vector<std::size_t> rest_b;
        for (std::size_t i = 0; i < xb.size(); ++i) if (!xb[i].matched && xb[i].size >= 4) rest_b.push_back(i);
        for (std::size_t i = 0; i < xa.size(); ++i) {
            if (xa[i].matched || xa[i].size < 4) continue;
            for (const std::size_t j : rest_b) {
                const double ratio = static_cast<double>((std::min)(xa[i].size, xb[j].size)) / static_cast<double>((std::max)(xa[i].size, xb[j].size));
                if (ratio < 0.5) continue;
                const double s = 0.5 * jaccard(xa[i].grams, xb[j].grams) + 0.5 * histogram_similarity(xa[i], xb[j]);
                if (s < 0.62) continue;
                const double position = 1.0 - std::fabs(static_cast<double>(i) / static_cast<double>(xa.size()) - static_cast<double>(j) / static_cast<double>(xb.size()));
                candidates.push_back({s + 0.05 * position, i, j});
            }
        }
        std::sort(candidates.begin(), candidates.end(), [](const Candidate& l, const Candidate& r) { return l.score > r.score; });
        for (const auto& c : candidates) link(c.a, c.b, "similarity");
    }

    // 5. left-overs that sit at the same address (tiny functions, thunks) belong together
    for (std::size_t i = 0; i < xa.size(); ++i) {
        if (xa[i].matched) continue;
        const auto it = b_index_by_start.find(fa[i].start);
        if (it != b_index_by_start.end() && !xb[it->second].matched) link(i, it->second, "address");
    }

    FunctionDiffResult result;
    for (const auto& p : pairs) {
        FunctionDiffEntry e;
        e.a_start = fa[p.a].start; e.b_start = fb[p.b].start; e.a_name = fa[p.a].name; e.b_name = fb[p.b].name;
        e.a_instructions = xa[p.a].size; e.b_instructions = xb[p.b].size; e.matched_by = p.by;
        const bool same_stream = xa[p.a].hash == xb[p.b].hash;
        e.similarity = same_stream ? 1.0 : 0.5 * jaccard(xa[p.a].grams, xb[p.b].grams) + 0.5 * histogram_similarity(xa[p.a], xb[p.b]);
        if (same_stream) { e.kind = FunctionDiffEntry::Kind::Identical; ++result.identical; }
        else { e.kind = FunctionDiffEntry::Kind::Changed; ++result.changed; }
        result.entries.push_back(std::move(e));
    }
    for (std::size_t i = 0; i < xa.size(); ++i) {
        if (xa[i].matched) continue;
        FunctionDiffEntry e; e.kind = FunctionDiffEntry::Kind::Removed; e.a_start = fa[i].start; e.a_name = fa[i].name; e.a_instructions = xa[i].size;
        result.entries.push_back(std::move(e)); ++result.removed;
    }
    for (std::size_t i = 0; i < xb.size(); ++i) {
        if (xb[i].matched) continue;
        FunctionDiffEntry e; e.kind = FunctionDiffEntry::Kind::Added; e.b_start = fb[i].start; e.b_name = fb[i].name; e.b_instructions = xb[i].size;
        result.entries.push_back(std::move(e)); ++result.added;
    }
    // changed functions first (most similar last = least interesting), then added / removed, identical at the end
    std::stable_sort(result.entries.begin(), result.entries.end(), [](const FunctionDiffEntry& l, const FunctionDiffEntry& r) {
        const auto rank = [](const FunctionDiffEntry& e) { return e.kind == FunctionDiffEntry::Kind::Changed ? 0 : e.kind == FunctionDiffEntry::Kind::Removed ? 1 : e.kind == FunctionDiffEntry::Kind::Added ? 2 : 3; };
        if (rank(l) != rank(r)) return rank(l) < rank(r);
        if (l.kind == FunctionDiffEntry::Kind::Changed) return l.similarity < r.similarity;
        return (l.a_start ? l.a_start : l.b_start) < (r.a_start ? r.a_start : r.b_start);
    });
    return result;
}

} // namespace gandon
