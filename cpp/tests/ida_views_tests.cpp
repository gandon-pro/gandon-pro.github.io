#include "gandon/ida_views.hpp"
#include <cstdio>
#include <cstdlib>
#include <iostream>
int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s binary [view]\n", argv[0]); return 2; }
    gandon::BinaryImage image; std::string err;
    if (!image.load(argv[1], err)) { std::cerr << err << "\n"; return 1; }
    gandon::AnalysisDatabase db(std::move(image));
    db.discover_basic_xrefs();
    auto entry = db.image().entry_point;
    // reuse the CLI discovery through decode: add the entry function if empty
    gandon::IdaViews v(db);
    std::string which = argc > 2 ? argv[2] : "listing";
    std::string t;
    if (which == "listing") t = v.listing(argc > 3 ? std::strtoull(argv[3], nullptr, 16) : entry);
    else if (which == "xrefs") t = v.xrefs_overview(50);
    else if (which == "hex") t = v.hex_view(entry, 8);
    else if (which == "imports") t = v.imports();
    else if (which == "exports") t = v.exports();
    else if (which == "strings") t = v.strings();
    else if (which == "resources") t = v.resources();
    else if (which == "names") t = v.names();
    else if (which == "segments") t = v.segments();
    else if (which == "problems") t = v.problems({"Process started"});
    std::fputs(t.c_str(), stdout);
}
