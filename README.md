# Gandon-PRO

Interactive PE/ELF disassembler and Win32 debugger with an IDA-style dark interface.

## Included

- PE/ELF/SO loading with x86/x64/ARM/ARM64 Capstone disassembly.
- Function navigation, graph view, flat listing, pseudocode and call graph.
- XREFs, labels, comments, bookmarks, strings, imports, exports, resources and local types.
- Instruction editing with Keystone, NOP patching, patch export and patch markers.
- Reliable Win32 debug loop with F9 continue, F7 step into and F8 step over.
- Software, conditional and x64 hardware breakpoints with deletion and persistence.
- Register view, Memory View, Watch / Locals, raw stack and frame-pointer call stack.
- Binary diff, multi-match signature search, JSON analysis export and CSV breakpoint export.
- Python plugin API and debugger event log.
- Dark styling for all application dialogs and auxiliary windows.
- WOW64/x86 context structures for stepping, registers, conditions and hardware points.

## Requirements

```text
PyQt6
capstone
pefile
keystone-engine   # optional: instruction assembly/editing
pyelftools        # optional: ELF symbols and DWARF section parsing
```

Run on Windows with:

```powershell
python outputs\disassembler_working.py
```

The main implementation is [`outputs/disassembler_working.py`](outputs/disassembler_working.py).

## Main shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl+O` | Open binary |
| `F2` | Toggle software breakpoint |
| `F7` | Step into |
| `F8` | Step over |
| `F9` | Start/continue process |
| `Ctrl+E` | Edit instruction |
| `Ctrl+F2` | NOP current block |
| `Ctrl+Z` / `Ctrl+Y` | Undo / redo patch |
| `F5` | Pseudocode |
| `Ctrl+G` | Find function |
| `Home` | Fit graph |
| `X` | XREFs |
| `Ctrl+B` | Generate signature |
| `Ctrl+Shift+F` | Search signature |
| `Ctrl+S` | Save project database |

## Verification

The current source passes Python compilation, AST parsing, offscreen Qt UI smoke tests and real Windows x64 breakpoint/continue tests. WOW64/x86 context support is implemented through the native WOW64 context API.

See [`CHANGELOG.md`](CHANGELOG.md) for the development history and [`CONVERSATION_HANDOFF.md`](CONVERSATION_HANDOFF.md) for continuation context.
