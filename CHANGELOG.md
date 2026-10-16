# Changelog

All notable changes to Gandon-PRO are documented in this file.

## [3.0] — 2026-10-16

### IDA-style look and feel

- Reworked the whole window to an IDA Pro 9-style dark theme (`--light` flag
  switches to a light palette).
- Custom-painted flat tab strip, toolbar, navigation band and graph overview
  minimap, matching IDA's own chrome instead of stock Win32 controls.
- Dark title bars, dark scrollbars, dark context menus throughout.
- New toolbar with GDI-drawn icons (Open, Save DB, Jump back, Redo patch,
  Jump to address, Decompile, Graph/Text) and a status bar with analysis
  progress ("AU: idle", debugger state).
- Fixed the stray light artifact after the last tab and a double white
  border around the tab row.

### Views (IDA parity)

- Added Gandon View-A (graph), Gandon Text Listing, Pseudocode-A, XREFs,
  Debugger Win32, Hex View-1, Local Types, Imports, Exports, Strings,
  Resources, Symbols/Debug Info, Memory Map, Problems/Events and an
  experimental LLIL emulation view.
- Rewrote all of these as proper IDA-style text renderers
  (`gandon::IdaViews`): addresses as `.text:0000000140001000`, xref comments
  with ↑/↓ and p/j/r/o markers, symbolic operands, `offset`/`cs:` prefixes,
  stack-frame `var_`/`arg_` naming.
- New IDA-style navigation band (coloured strip across the whole image) and
  a graph overview minimap with correct, aspect-preserving scaling.

### Docking and panels

- Added a real docking system: panels live tabbed in the left/right/bottom
  areas or float in their own window.
- Drag a panel's tab to an edge of the main window to dock it there (a blue
  preview shows where it will land); drag out to float it; double-click a
  tab to float it; right-click for Float / Dock left / right / bottom /
  Close.
- Panel layout (sizes, docked area, floating position) is saved to
  `%APPDATA%\Gandon-PRO\layout.ini` and restored on next launch.
  View → Panels → "Reset panel layout" restores the defaults.
- Converted the Functions window, the Python console, the Local Types
  editor and the new Diff window into dockable panels.

### Functions window

- New sortable, filterable Functions list (name, address, size, xrefs,
  calls, instruction count) with dark themed headers, opened from
  View → Functions window (Shift+F3). Double-click / Enter jumps to the
  function.

### Decompiler

- Added `switch` statement recovery from compiler-generated jump tables,
  for both the GCC/clang (`adr`/`ldrb`+`add`+`br`) and MSVC x86-64 forms;
  case bodies are decoded from the table even when the linear sweep missed
  them.
- Added SSE/AVX scalar floating point: arithmetic, compares, conversions,
  FMA (`vfmadd*`/`vfmsub*` 132/213/231), sign/abs via constant masks.
  Floating-point return values and parameters are now typed `float`/
  `double` in the generated signature.
- Added a full x87 model: the ST(i) register stack, `fld`/`fst(p)`/
  `fist(p)`/`fadd..fdivr` (plain, `p` and `fi` forms), `fxch`, `fabs`,
  `fsqrt`, `fsin`/`fcos`, `fcom(p)(p)`/`fcomi(p)`, `fnstsw`+`sahf`;
  `long double` in the output.
- Added AArch64 (ARM64) support to the structured decompiler: full
  instruction coverage (data movement, arithmetic/logic, shifts, mul/div,
  bitfields, `csel`/`cset`/`cinc` family, loads/stores incl. pre/post
  index, `ccmp`/`ccmn` condition chains, `svc` syscalls, FP/SIMD scalar
  moves and `fcmp`), plus ARM64 jump-table recovery.
- Added structure-offset (`T`) and enum-constant (`M`) rendering on
  operands and user-settable function prototypes (`Y`), driven by a new C
  type-declaration parser (`struct`/`union`/`enum`/`typedef`) with
  MSVC-style layout and a built-in set of common Windows types
  (`RECT`, `GUID`, `UNICODE_STRING`, `IMAGE_*`, ...). Editable from the new
  Local Types Editor panel (Shift+F1).
- Common shared-tail and shared-region duplication instead of `goto` where
  it's safe, cutting the number of functions that still contain a `goto`
  by roughly two-thirds on typical binaries.
- Fixed a signature bug where call arguments could leak into the
  decompiled function's own parameter list.

### Auto-analysis and FLIRT

- Extended auto-analysis (recursive descent, import-thunk naming, noreturn
  propagation) to AArch64, including a stripped-binary prologue scan
  (`stp x29,x30`/`sub sp` after a terminator) for ELF binaries with no
  symbols.
- Added loading of IDA FLIRT `.pat` pattern files (`signatures\*.pat`
  next to the executable): leading-byte pattern plus FLIRT CRC16 over the
  bytes that follow, matching IDA's own matcher.
- `gandon_auto --make-pat` generates a `.pat` from a binary's own named
  functions; `--verify-pat` checks how well a pattern file re-identifies
  them.

### Binary diff

- Added function-level binary diff (`gandon::diff_functions`): functions
  are paired by name, by identical normalised instruction stream, by
  call-graph neighbours and finally by instruction-histogram similarity.
  Reported as identical / changed (with a similarity %) / added / removed.
  Available from Tools → "Diff Functions with Binary..." (opens a
  dockable Diff panel, colour-coded, double-click to jump) and as a
  standalone `gandon_diff` CLI.

### Editing

- Added a single unified Undo/Redo timeline: renames and comments now undo
  and redo in the same Ctrl+Z/Ctrl+Y stream as byte patches, in the exact
  order they were made, instead of patches-only.
- Fixed Add Comment (`;`) and Rename (`N`) hotkeys, which were not wired
  up; comments on non-entry instructions are now also drawn in the graph.

### Python console

- The console now controls the whole program, not just the database:
  navigation (`goto`, `resolve`, `view`), every read-only view
  (`disasm`, `listing`, `decompile`, `hexview`, `imports`, `exports`,
  `resources`, `segments`, `find_bytes`/`find_text`), editing (`rename`,
  `comment`, `patch`, `nop`, `undo`/`redo`, `bookmark`), the debugger
  (`bp`, `run`, `pause`, `step_into`, `step_over`, `stop`,
  `registers`, `readmem`/`readqword`/`readdword` for live process memory),
  the type library (`types_add`, `sizeof`, `field_at`, `apply_struct`,
  `apply_enum`, `set_prototype`), panels (`act("panel_...")`), binary diff
  (`diff`), and `act(name)`/`actions()` to drive any of the ~90 menu and
  toolbar commands by name.
- Added two-way logging: everything done in the GUI (menu actions,
  navigation, renames, comments, status-bar messages incl. debugger
  events) is now echoed into the open console as `[gui] ...` lines.
- The console is faster (40 ms poll instead of 250 ms) and now runs as a
  proper dockable panel instead of a floating-only window.

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
