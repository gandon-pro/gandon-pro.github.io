# Gandon-PRO Software Reverse Engineering Toolkit

Gandon-PRO is a native C++20 software reverse engineering toolkit for Windows. It brings together binary analysis, disassembly, C-like decompilation, control-flow graphs, a Win32 debugger, scripting, and live-process inspection in a desktop interface. The same analysis engine is available through command-line tools and an MCP interface for automated workflows.

The project is designed for investigating compiled programs, understanding their structure, inspecting runtime behavior, and developing custom analysis tools. Users can extend the application with native plugins and Python scripts, maintain local type declarations, annotate functions, and export analysis or patched binaries.

Gandon-PRO reads PE and ELF files. Capstone provides instruction decoding for supported architectures, including x86, x86-64, ARM, and ARM64. Architecture support varies between disassembly, decompilation, emulation, and live debugging; the Windows debugger and live-memory tools target x86/x64 processes.

[Download](https://github.com/gandon-pro/gandon-pro.github.io/releases) · [Source](https://github.com/gandon-pro/gandon-pro.github.io/tree/main/cpp) · [Changelog](CHANGELOG.md) · [Report an issue](https://github.com/gandon-pro/gandon-pro.github.io/issues)

## Capabilities

- **Binary analysis:** PE/ELF loading, sections, imports, exports, symbols, resources, strings, signatures, and cross-references.
- **Disassembly and navigation:** instruction listings, control-flow and call graphs, address navigation, bookmarks, labels, and comments.
- **Decompilation:** C-like pseudocode, control-flow reconstruction, local types, structure offsets, enums, and function prototypes.
- **Additional analysis:** RTTI and C++ class information, .NET metadata, function-level binary comparison, and VM-dispatcher analysis helpers.
- **Editing:** instruction and byte patching, undo/redo, and export of modified binaries.
- **Debugging:** process launch, pause/continue, single-step, software and hardware breakpoints, registers, memory inspection, and call-stack views.
- **Live-process inspection:** bounded pointer-chain scanning, chain re-scanning, and typed or raw structure snapshots with readable-byte masks.
- **Emulation:** optional Unicorn-backed execution with instruction limits, register and memory inspection, breakpoints, and watchpoints.
- **Extensibility:** a native plugin API, Python plugin support, command-line analysis tools, and MCP integration.

## Install

To install a pre-built Windows x64 release:

1. Install the Microsoft Visual C++ x64 runtime if it is not already available.
2. Download `gandon-pro-<version>-win64.zip` from the [Releases page](https://github.com/gandon-pro/gandon-pro.github.io/releases).
3. Extract the archive into a new directory, keeping its folder structure intact.
4. Launch `gandon_gui.exe` and approve the Windows administrator prompt.
5. Choose whether to use the optional GandonMemory driver. Select **No** to continue with ordinary process-memory access.

> The GitHub-generated **Source code** archives contain source files, not the ready-to-run application. Use the `win64.zip` asset for a pre-built installation.

Keep `capstone.dll` beside the executable. Preserve the `plugins`, `ScyllaHide`, `drivers`, and `kernel` folders when moving the installation.

Python is optional for the native GUI. Python-based plugins require Python 3 and PyQt6:

```powershell
python -m pip install PyQt6
```

### Optional ScyllaHide integration

The Windows release includes a manually loaded integration plugin and upstream ScyllaHide 1.4 components.

1. Use **Load Python Plugin** in the GUI to open `plugins\python\scyllahide_loader.py`.
2. Start and pause the process being debugged.
3. Use the plugin's **Configure Profiles** action to select `ScyllaHide\scylla_hide.ini` and edit a profile.
4. Use **Inject into Current Process** and select the matching InjectorCLI executable and HookLibrary DLL from `ScyllaHide`.

Use the x64 components for an x64 target and the x86 components for an x86 target. Injection is requested only through the explicit plugin action. ScyllaHide operates in user mode and is separate from the GandonMemory driver.

See the [upstream ScyllaHide project](https://github.com/x64dbg/ScyllaHide) for its documentation and supported options.

### Optional GandonMemory driver

GandonMemory provides an additional read-only channel for live-process memory inspection. Pointer scanning and structure dumps can also use `ReadProcessMemory` without installing the driver.

The driver validates the caller's process-handle access rights and reads user virtual memory. It does not provide kernel-memory writes or conceal kernel debug state.

The included development driver has a **test signature**, not a Microsoft production signature. Its setup requires installing the test certificate, disabling Secure Boot for ordinary test signing, enabling Windows test mode, and restarting the computer. The application does not change these boot settings automatically.

Read the [test-signing and rollback instructions](cpp/kernel/out/TEST-SIGNING.md) before using it. The same guide is included under `kernel\out` in the binary release. Private signing keys are not distributed.

## Build

### Requirements

- Windows with an x64 MSVC toolchain, provided by Visual Studio or Visual Studio Build Tools.
- The **Desktop development with C++** components and a Windows SDK.
- CMake 3.21 or newer, with support for your installed Visual Studio version.
- Capstone headers and libraries for the full instruction decoder.
- An internet connection when fetching Unicorn through CMake.

The 3.2 release was built with MSVC 2026, Capstone 5.0.9, and Unicorn 2.1.4. The Windows Driver Kit is needed only when building the optional kernel driver.

### Get the source

```powershell
git clone https://github.com/gandon-pro/gandon-pro.github.io.git
cd gandon-pro.github.io
```

Alternatively, download and extract a source archive from GitHub, then open a terminal in its root directory.

### Configure dependencies

Capstone can be supplied through a CMake package or this directory layout:

```text
cpp/third_party/capstone/
├── include/capstone/
└── lib/
    ├── capstone.lib
    └── capstone.dll
```

For another location, set `GANDON_CAPSTONE_ROOT` during configuration. If Capstone is unavailable, CMake can use the limited built-in decoder; it does not provide the same architecture coverage or decoding quality.

Set `GANDON_FETCH_UNICORN=ON` to fetch the pinned Unicorn engine. Leave it off when building without that optional backend.

### Create a development build

From the repository root:

```powershell
cmake -S cpp -B build -A x64 -DGANDON_FETCH_UNICORN=ON -DBUILD_TESTING=ON
cmake --build build --config Release --parallel
```

The executables are produced under `build\Release`. When found through the bundled dependency layout, CMake copies `capstone.dll` and the Python plugin files into the output directory.

The optional driver is built separately with [`cpp/kernel/build-driver.ps1`](cpp/kernel/build-driver.ps1). Building the GUI does not compile, sign, or load a kernel driver. If a pre-built driver is available in `cpp/kernel/out`, CMake copies it into the GUI's `drivers` directory.

### Run the tests

```powershell
ctest --test-dir build -C Release --output-on-failure
.\build\Release\gandon_types_tests.exe
```

The CTest suite covers core analysis, decompilation, unpacking/RTTI helpers, and live-process scanning and structure-dump logic. Kernel deployment and interactive plugin behavior require separate runtime validation.

## Develop

### Command-line tools

| Executable | Purpose |
|---|---|
| `gandon_gui` | Native Windows desktop interface. |
| `gandon_cli` | Binary loading, basic analysis information, and entry-point disassembly. |
| `gandon_decompile` | Command-line decompilation. |
| `gandon_auto` | Automated analysis and signature-related workflows. |
| `gandon_diff` | Function-level comparison between binaries. |
| `gandon_ida_views` | Text representations of analysis results. |
| `gandon_mcp_backend` | Native backend used by the MCP integration. |

For example:

```powershell
.\build\Release\gandon_cli.exe C:\path\to\program.exe
```

### Scripts and plugins

Native extensions use the [plugin API](cpp/include/gandon/plugin_api.h). An [example plugin](cpp/plugins/example_plugin.cpp) is included in the source tree.

Python plugins live under [`cpp/plugins/python`](cpp/plugins/python). Plugins that use Qt interfaces run through the separate Python plugin host rather than embedding a Python runtime into the native executable.

For MCP tools and configuration, see the [MCP documentation](cpp/mcp/README.md).

### Source layout

```text
cpp/
├── assets/              Application resources
├── include/gandon/      Analysis, debugger integration, and plugin interfaces
├── kernel/              Optional driver source, build scripts, and test-signing guide
├── mcp/                 MCP server and documentation
├── plugins/             Native and Python extensions
├── src/                 Analysis engine, CLI tools, and desktop interfaces
├── tests/               Analysis and regression tests
└── CMakeLists.txt
```

## Project status

Gandon-PRO is under active development. Instruction coverage and analysis results depend on the input architecture and binary. Decompiled output is an analysis aid and should be checked against the disassembly.

For release 3.2, the x64 GUI and CLI compiled successfully; all four CTest cases and the separate type tests passed. CLI/text-view smoke checks and the embedded administrator manifest were also verified. Interactive GUI operation, ScyllaHide injection, and live kernel-driver loading were not runtime-tested during release preparation.

## Contribute

Bug reports, reproducible examples, and focused fixes are welcome through [GitHub Issues](https://github.com/gandon-pro/gandon-pro.github.io/issues) and pull requests.

When reporting a problem, include the application version, Windows version, target architecture, expected behavior, and the relevant error output. For code changes, describe the problem being fixed and the checks used to validate it.

## Third-party components and licensing

Gandon-PRO uses components with their own licenses:

- **Capstone:** see the [Capstone license](cpp/third_party/licenses/Capstone-LICENSE.txt).
- **Unicorn:** see its [license notice](cpp/third_party/licenses/Unicorn-COPYING) and [LGPL text](cpp/third_party/licenses/Unicorn-COPYING.LGPL2).
- **ScyllaHide:** [GNU GPL v3](cpp/third_party/licenses/ScyllaHide-GPL-3.0.txt).

The 3.2 release includes corresponding ScyllaHide and Unicorn source archives, plus application objects for relinking with a modified Unicorn engine.

A project-wide license for Gandon-PRO itself has not yet been specified in this repository. The third-party license notices do not grant a license to unrelated project code.
