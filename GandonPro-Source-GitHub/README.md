# Gandon-PRO Native

Native C++ disassembler, control-flow graph viewer and Win32 debugger for PE binaries. The project contains a Win32 GUI, a command-line frontend, a small plugin API and optional Python plugins.

## Features

- PE analysis and x86/x64 disassembly.
- Interactive control-flow graph and text listing.
- Functions, imports, exports, strings, resources and XREF views.
- Labels, comments, bookmarks, type assignments and instruction patching.
- PNG graph export, memory map/snapshot tools and project persistence.
- Win32 debugger with start/continue, pause, software breakpoints, step into and step over.
- Native and Python plugin support.
- Optional Qt frontend.

## Requirements

- Windows 10 or Windows 11.
- Visual Studio 2022 with the **Desktop development with C++** workload.
- CMake 3.25 or newer.
- Optional: Capstone for full disassembly support. Without it, the built-in decoder is used.
- Optional: Qt 6 Widgets to build `gandon_qt`.
- Python 3 for Python plugins.

## Build with the included preset

Open a Developer PowerShell for Visual Studio in the repository directory and run:

```powershell
cmake --preset windows-msvc-x64
cmake --build --preset windows-msvc-x64-release
```

The main executable will be created at:

```text
build-local/Release/gandon_gui.exe
```

The command-line executable is `gandon_cli.exe`. The sample native plugin is `gandon_example_plugin.dll`.

## Build without presets

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

## Optional Capstone through vcpkg

```powershell
vcpkg install capstone:x64-windows
cmake -S . -B build -A x64 `
  -DCMAKE_TOOLCHAIN_FILE=C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

## Main shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl+O` | Open a binary |
| `F2` | Toggle breakpoint |
| `F6` | Pause process |
| `F7` | Step into |
| `F8` | Step over |
| `F9` | Start/continue process |
| `Ctrl+S` | Save project database |
| `Ctrl+L` | Load project database |
| `Home` | Fit graph |

## Repository layout

```text
include/gandon/    Public C++ headers and plugin API
src/               Core, GUI, CLI and optional Qt sources
plugins/           Native example plugin and Python plugins
CMakeLists.txt      Build configuration
CMakePresets.json  Visual Studio x64 preset
```

## Notice

This project is intended for education, debugging software you own, and authorized reverse engineering. No license file is included yet; add the license you want before publishing if other people should be allowed to copy or redistribute the code.
