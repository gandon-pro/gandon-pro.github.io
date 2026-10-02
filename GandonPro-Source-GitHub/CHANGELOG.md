# Changelog

All notable changes to Gandon-PRO are documented in this file.

## [2.2] — 2026-09-20

### Native C++ Migration

- Added a C++20 core foundation under `cpp/`.
- Added a stable C plugin ABI for native DLL plugins.
- Added a native plugin host and example plugin.
- Added a dependency-light binary loader, byte search, function/XREF data model, and CLI smoke target.
- Documented the staged migration strategy while retaining Python plugins and the existing Python UI as the behavior reference.

### Disassembler and Analysis

- Added PE, ELF, and SO file loading.
- Added x86, x86-64, ARM, and ARM64 support through Capstone.
- Added automatic function discovery and a navigation tree.
- Added basic-block graphs, CFG navigation, and call graphs.
- Added XREFs, address/label navigation, and jump history.
- Added label renaming, comments, and block color tags.
- Added Imports, Exports, Strings, Resources, and Local Types views.
- Added PE CodeView/PDB and ELF symbol/DWARF information discovery.
- Added ASCII text, hex pattern, and address search.
- Added SigMaker-style signature search with a results table.
- Added binary comparison and JSON analysis export.
- Added graph export to PNG.
- Added typed pseudocode inference for byte/word/dword/qword operands, pointers, registers, and memory references.
- Added regex search over decoded mnemonics, operands, and inline comments (`Ctrl+Alt+F`).
- Extended XREF records for RIP-relative globals, strings, and imported IAT addresses.

### Editing and Patching

- Added instruction editing with `Ctrl+E`.
- Added NOP for the current block.
- Added patched-file export and byte-change history.
- Added patch Undo/Redo with `Ctrl+Z` and `Ctrl+Y`.
- Added `Patch Function...` to Pseudocode-A, Gandon View-A, and Text Listing context menus.
- Function patching can NOP all decoded instructions or open the entry instruction editor.
- Added `Patch Instruction...` to individual instruction context menus in all code views.
- The selected instruction is assembled in place, padded with NOPs to its original size, and added to Undo/Redo.
- Fixed graph text context-menu interception so `Patch Instruction...` is shown instead of only `Copy / Select All`.
- Added visual markers for modified blocks.

### Win32 Debugger

- Reworked the Win32 debug-event loop with correct `ContinueDebugEvent` handling.
- Fixed F9 Continue, F7 Step Into, and F8 Step Over.
- Added working software INT3 breakpoints.
- Added automatic INT3 reinsertion after single-step.
- Added conditional breakpoints with safe register expressions.
- Added hardware execute breakpoints using DR0–DR3.
- Added breakpoint deletion and a breakpoint manager.
- Fixed false hits from the initial loader breakpoint.
- Fixed current-function and current-instruction tracking after a breakpoint hit.
- Added registers, memory, watched locals, threads, and call-stack views.
- Added a debug event log and log export.
- Fixed process cleanup when closing the application.
- Added reliable startup of a new debug session after stopping the previous one.

### Imports and Symbols

- Added analysis-only hiding of functions and imports through the context menu.
- Added restore-one and restore-all actions for hidden symbols.
- Persisted hidden symbols in `.gnd` project files.
- F2 on a selected import now disables that import through the IAT in the running process.
- Pressing F2 again restores the import.
- F2 in the graph and text listing continues to work as a normal breakpoint.
- Fixed stale import selections intercepting F2 after switching back to the graph.

### Plugins

- Added a Python Plugin API.
- Plugins can add menu actions, read file bytes, and navigate to addresses.
- Added Python plugin loading and unloading.
- Fixed duplicate plugin menus.
- Added the `Binary Summary` example plugin.
- Kept ScyllaHide as a separate, manually loaded plugin.
- Added ScyllaHide profile selection from `scylla_hide.ini`, profile editing, and InjectorCLI launching.

### UI and Theme

- Applied a consistent dark theme to the main window and auxiliary dialogs.
- Fixed white Memory View, Watch / Locals, Call Graph, XREF, About, and other dialogs.
- Added dark Windows title-bar integration where supported.
- Fixed context-menu labels and shortcut text.
- Restored the breakpoint dialog with an OK button and a standard close button.
- Improved reuse of Memory View, Watch / Locals, and Threads / Call Stack windows after closing.

### Project Database

- Added `.gnd` project database save and load.
- Persisted labels, comments, colors, breakpoints, conditions, hardware breakpoints, bookmarks, local types, and hidden symbols.
- Added automatic project saving next to the analyzed binary.
- Project sidecars are now loaded automatically when the binary is opened again.
- Persisted watched memory addresses, current address, selected tab, window geometry, and splitter layout.
- Restored the last analysis location after loading a project.
- Added periodic crash-recovery backups as `<binary>.gnd.bak`.
- Added an IDA-style Save / Discard / Cancel prompt on application exit.
- Save writes `<binary>.gnd` and removes the backup; Discard removes the backup without saving.
- Added backup recovery prompt when no regular project sidecar exists.
- Added debugger watch expressions such as `RAX+0x20`, `[RAX+0x20]`, and `[[RAX+0x20]]`.
- Persisted graph zoom and scroll position.

### Python Console

- Added an IDA-style Python Console.
- Added the `app`, `self`, and `api` namespace objects.
- Added expression evaluation through `eval` and statement execution through `exec`.
- Added logging of UI actions, file loading, navigation, breakpoints, patches, and debugger events.
- Preserved the action history after closing and reopening the console.
- Added persistence for manually entered `>>>` commands.
- Added persistent watched-address state so Watch / Locals survives closing and reopening.
