#include "gandon/core.hpp"

#include <iostream>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cout << "Gandon-PRO native analysis CLI\n"
                     "Usage: gandon_cli <binary>\n"
                     "Example: gandon_cli C:\\path\\program.exe\n";
        std::cout << "Press Enter to close...\n";
        std::cin.get();
        return 2;
    }
    gandon::BinaryImage image;
    std::string error;
    if (!image.load(argv[1], error)) {
        std::cerr << error << '\n';
        return 1;
    }
    std::cout << "Loaded " << image.path.string() << " ("
              << (image.format == gandon::BinaryFormat::PE ? "PE" : "ELF")
              << ", " << image.bytes.size() << " bytes, base 0x"
              << std::hex << image.image_base << ", entry 0x" << image.entry_point << std::dec << ")\n";
    gandon::AnalysisDatabase database(std::move(image));
    database.discover_basic_xrefs();
    std::cout << "Sections: " << database.image().sections.size()
              << ", functions discovered: " << database.functions().size()
              << ", xrefs: " << database.xrefs().size() << "\n";
    const auto instructions = gandon::decode_x64(database.image(), database.image().entry_point, 16);
    std::cout << "Entry instructions: " << instructions.size() << "\n";
    for (const auto& instruction : instructions) {
        std::cout << "  0x" << std::hex << instruction.address << "  "
                  << instruction.mnemonic << " " << instruction.operands << std::dec << "\n";
    }
    return 0;
}
