# Gandon-PRO 3.2 (Windows x64)

Run `gandon_gui.exe`. Windows requests administrator approval through its embedded manifest.
The startup dialog offers the optional GandonMemory driver. No skips all installation/start actions.
Pointer scanning and structure dumps also work without a driver through ReadProcessMemory.

Added: bounded/cancellable pointer-chain scan and re-scan, typed/raw structure snapshots,
reversible native/WOW64 PEB flag masking, optional read-only kernel transport, and driver setup.
Includes the current decompiler, RTTI, PE dump/IAT and VM-analysis changes.

## ScyllaHide (optional, manual)

ScyllaHide 1.4 binaries/configuration are in `ScyllaHide/` and the integration is
`plugins/python/scyllahide_loader.py`. Install Python 3 with PyQt6 for the Python plugin host
(`python -m pip install PyQt6`). Load the plugin through the GUI's Load Python Plugin command.
Start and pause your debuggee. In its ScyllaHide menu, choose the configuration/profile and
select the matching InjectorCLI and HookLibrary from `ScyllaHide/`: x64 for an x64 target,
x86 for an x86 target. Injection is requested only by the explicit menu action; nothing is
injected at application startup. End-to-end injection has not been runtime-tested in this release.
This is user-mode integration, separate from the optional kernel reader.

## Test-signed driver

The optional driver is a development build, not Microsoft production-signed.
See `kernel/out/TEST-SIGNING.md` for certificate installation, test-mode setup and rollback.
Secure Boot must be off for this ordinary test-signing setup; enabling test mode needs a reboot.
The program does not change these boot settings. No private signing key is distributed.

The driver checks the caller's process-handle access and only reads user virtual memory.
It does not hide kernel debug state, remove protections or provide kernel memory writes.
The kernel path has not been loaded or tested on a live machine.

## Requirements / validation

Microsoft Visual C++ x64 runtime; Python/PyQt6 only for Python plugins.
Release x64 GUI and CLI compiled with MSVC 2026, Capstone 5.0.9 and Unicorn 2.1.4.
CTest: 4/4 passed (live process, core, decompiler, unpack/RTTI); type tests passed separately.
CLI and text views processed the new GUI executable; embedded UAC manifest verified.
GUI interactive startup and kernel loading have not been tested.

## Source and third-party notices

Main source: https://github.com/gandon-pro/gandon-pro.github.io/tree/v3.2/cpp
ScyllaHide (GPL-3.0): https://github.com/x64dbg/ScyllaHide/tree/v1.4
Capstone license: licenses/Capstone-LICENSE.txt
Unicorn licenses: licenses/Unicorn-*
Corresponding ScyllaHide/Unicorn source archives and Gandon relink objects are downloadable
alongside this release. Relinking/reverse engineering needed to modify the LGPL components
is permitted. No license restrictions on the main project override these third-party rights.

## Build from source

Use CMake 3.21+ and MSVC x64; enable `GANDON_FETCH_UNICORN=ON` for the engine.
Supply Capstone headers/library under `cpp/third_party/capstone` or via vcpkg.
The optional driver has its own `cpp/kernel/build-driver.ps1` script and is not rebuilt by the GUI target.
