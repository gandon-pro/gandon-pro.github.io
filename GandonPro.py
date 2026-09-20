import sys
import os
import re
import json
import csv
import struct
import threading
import ctypes
import importlib.util
from datetime import datetime
from ctypes import wintypes
import urllib.request
import pefile
from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_64, CS_MODE_32, CS_MODE_ARM
from capstone.x86 import X86_GRP_JUMP, X86_GRP_CALL, X86_GRP_RET, X86_OP_MEM, X86_REG_RIP
try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64
except ImportError:
    Ks = None

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
    QTreeWidget, QTreeWidgetItem, QSplitter, QStatusBar, QTabWidget,
    QPlainTextEdit, QGraphicsView, QGraphicsScene, QGraphicsRectItem,
    QGraphicsTextItem, QGraphicsItem, QGraphicsPathItem, QGraphicsPolygonItem,
    QDialog, QLabel, QPushButton, QInputDialog, QMessageBox, QMenu
)
from PyQt6.QtGui import (
    QFont, QColor, QAction, QKeySequence, QPen, QBrush,
    QPainter, QPainterPath, QPolygonF, QCursor, QPixmap, QIcon, QPalette
)
from PyQt6.QtCore import Qt, QRectF, QPointF, pyqtSignal, QObject, QEvent


def apply_windows_dark_titlebar(widget):
    """Enable the native dark title bar on Windows 10/11 when available."""
    try:
        dwmapi = ctypes.WinDLL("dwmapi")
        dwmapi.DwmSetWindowAttribute.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32
        ]
        dwmapi.DwmSetWindowAttribute.restype = ctypes.c_long
        # DWMWA_USE_IMMERSIVE_DARK_MODE (20; 19 on older Windows 10 builds).
        use_dark = ctypes.c_int(1)
        hwnd = int(widget.winId())
        result = dwmapi.DwmSetWindowAttribute(
            ctypes.c_void_p(hwnd), 20,
            ctypes.byref(use_dark), ctypes.sizeof(use_dark)
        )
        if result != 0:
            dwmapi.DwmSetWindowAttribute(
                ctypes.c_void_p(hwnd), 19,
                ctypes.byref(use_dark), ctypes.sizeof(use_dark)
            )
        # Match the content background (#1e1e1e) instead of the default
        # almost-black dark title bar. DWMWA_CAPTION_COLOR is available on
        # current Windows 11 builds and is harmless on older systems.
        caption_color = ctypes.c_uint32(0x001E1E1E)
        text_color = ctypes.c_uint32(0x00FFFFFF)
        dwmapi.DwmSetWindowAttribute(
            ctypes.c_void_p(hwnd), 35,
            ctypes.byref(caption_color), ctypes.sizeof(caption_color)
        )
        dwmapi.DwmSetWindowAttribute(
            ctypes.c_void_p(hwnd), 36,
            ctypes.byref(text_color), ctypes.sizeof(text_color)
        )
    except Exception:
        pass


class DarkMessageBoxFilter(QObject):
    def eventFilter(self, watched, event):
        if event.type() == QEvent.Type.Show and isinstance(watched, QDialog):
            apply_windows_dark_titlebar(watched)
        return False


# =====================================================================
#             WIN32 DEBUGGER ENGINE (CTYPES BACKEND)
# =====================================================================

DEBUG_PROCESS = 0x00000001
CREATE_NEW_CONSOLE = 0x00000010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2
CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10

PAGE_EXECUTE_READWRITE = 0x40

class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_uint64), ("High", ctypes.c_int64)]

class CONTEXT64(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64), ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
        ("ContextFlags", ctypes.c_uint32), ("MxCsr", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint16), ("SegDs", ctypes.c_uint16),
        ("SegEs", ctypes.c_uint16), ("SegFs", ctypes.c_uint16),
        ("SegGs", ctypes.c_uint16), ("SegSs", ctypes.c_uint16),
        ("EFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64), ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64), ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64), ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64), ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64), ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64),  ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64), ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64), ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64), ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("Header", M128A * 2),
        ("Legacy", M128A * 8),
        ("Xmm0", M128A), ("Xmm1", M128A), ("Xmm2", M128A), ("Xmm3", M128A),
        ("Xmm4", M128A), ("Xmm5", M128A), ("Xmm6", M128A), ("Xmm7", M128A),
        ("Xmm8", M128A), ("Xmm9", M128A), ("Xmm10", M128A), ("Xmm11", M128A),
        ("Xmm12", M128A), ("Xmm13", M128A), ("Xmm14", M128A), ("Xmm15", M128A),
    ]


class WOW64_FLOATING_SAVE(ctypes.Structure):
    _fields_ = [("ControlWord", ctypes.c_uint32), ("StatusWord", ctypes.c_uint32),
                ("TagWord", ctypes.c_uint32), ("ErrorOffset", ctypes.c_uint32),
                ("ErrorSelector", ctypes.c_uint32), ("DataOffset", ctypes.c_uint32),
                ("DataSelector", ctypes.c_uint32), ("RegisterArea", ctypes.c_ubyte * 80),
                ("Cr0NpxState", ctypes.c_uint32)]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint32), ("Dr1", ctypes.c_uint32),
        ("Dr2", ctypes.c_uint32), ("Dr3", ctypes.c_uint32),
        ("Dr6", ctypes.c_uint32), ("Dr7", ctypes.c_uint32),
        ("FloatSave", WOW64_FLOATING_SAVE),
        ("SegGs", ctypes.c_uint32), ("SegFs", ctypes.c_uint32),
        ("SegEs", ctypes.c_uint32), ("SegDs", ctypes.c_uint32),
        ("Edi", ctypes.c_uint32), ("Esi", ctypes.c_uint32),
        ("Ebx", ctypes.c_uint32), ("Edx", ctypes.c_uint32),
        ("Ecx", ctypes.c_uint32), ("Eax", ctypes.c_uint32),
        ("Ebp", ctypes.c_uint32), ("Eip", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint32), ("EFlags", ctypes.c_uint32),
        ("Esp", ctypes.c_uint32), ("SegSs", ctypes.c_uint32),
        ("ExtendedRegisters", ctypes.c_ubyte * 512),
    ]

class EXCEPTION_RECORD(ctypes.Structure):
    pass
EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", ctypes.c_uint32),
    ("ExceptionFlags", ctypes.c_uint32),
    ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", ctypes.c_void_p),
    ("NumberParameters", ctypes.c_uint32),
    ("ExceptionInformation", ctypes.c_size_t * 15)
]

class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", ctypes.c_uint32)
    ]

class DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO)]

class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", ctypes.c_uint32),
        ("dwProcessId", ctypes.c_uint32),
        ("dwThreadId", ctypes.c_uint32),
        ("u", DEBUG_EVENT_UNION)
    ]

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_uint32), ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
        ("dwX", ctypes.c_uint32), ("dwY", ctypes.c_uint32),
        ("dwXSize", ctypes.c_uint32), ("dwYSize", ctypes.c_uint32),
        ("dwXCountChars", ctypes.c_uint32), ("dwYCountChars", ctypes.c_uint32),
        ("dwFillAttribute", ctypes.c_uint32), ("dwFlags", ctypes.c_uint32),
        ("wShowWindow", ctypes.c_uint16), ("cbReserved2", ctypes.c_uint16),
        ("lpReserved2", ctypes.c_char_p), ("hStdInput", ctypes.c_void_p),
        ("hStdOutput", ctypes.c_void_p), ("hStdError", ctypes.c_void_p)
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.c_void_p), ("hThread", ctypes.c_void_p),
        ("dwProcessId", ctypes.c_uint32), ("dwThreadId", ctypes.c_uint32)
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

class DebuggerSignals(QObject):
    state_changed = pyqtSignal(str)
    registers_updated = pyqtSignal(dict)
    breakpoint_hit = pyqtSignal(int)
    step_finished = pyqtSignal(int)

class Win32Debugger:
    def __init__(self, signals):
        self.signals = signals
        self.k32 = ctypes.windll.kernel32
        self.psapi = ctypes.WinDLL("psapi")
        self.process_info = None
        self.is_running = False
        self.target_path = ""
        self.target_is_64 = True
        self.worker_thread = None
        self.requested_breakpoints = set()
        self.requested_disabled_imports = {}
        self.disabled_imports = {}
        self.breakpoint_conditions = {}
        # Runtime breakpoint policy is owned by the debugger worker because
        # breakpoint exceptions are handled on that thread.
        self.breakpoint_hits = {}
        self.breakpoint_hit_limits = {}
        self.breakpoint_log_only = set()
        self.requested_hardware_breakpoints = set()
        self.hardware_breakpoints = {}
        self.runtime_breakpoints = {}
        self.pending_reinsert = None
        self.resume_event = threading.Event()
        self.resume_event.set()
        self.thread_handles = {}
        self.step_mode = False
        self.paused_thread_id = None
        self.step_over_runtime = None
        self.last_registers = {}
        self.trace_enabled = False
        self.trace_records = []
        self.k32.FlushInstructionCache.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t]
        self.k32.FlushInstructionCache.restype = wintypes.BOOL

        self.k32.CreateProcessW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
            ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD,
            ctypes.c_void_p, wintypes.LPCWSTR,
            ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)
        ]
        self.k32.CreateProcessW.restype = wintypes.BOOL
        self.k32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), wintypes.DWORD]
        self.k32.WaitForDebugEvent.restype = wintypes.BOOL
        self.k32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
        self.k32.ContinueDebugEvent.restype = wintypes.BOOL
        self.k32.VirtualProtectEx.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
        ]
        self.k32.VirtualProtectEx.restype = wintypes.BOOL
        self.k32.VirtualAllocEx.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
            wintypes.DWORD, wintypes.DWORD
        ]
        self.k32.VirtualAllocEx.restype = ctypes.c_void_p
        self.k32.VirtualFreeEx.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD
        ]
        self.k32.VirtualFreeEx.restype = wintypes.BOOL
        self.k32.WriteProcessMemory.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.c_void_p
        ]
        self.k32.WriteProcessMemory.restype = wintypes.BOOL
        self.k32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.c_void_p
        ]
        self.k32.ReadProcessMemory.restype = wintypes.BOOL
        self.k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
        self.k32.VirtualQueryEx.restype = ctypes.c_size_t
        self.k32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        self.k32.GetThreadContext.restype = wintypes.BOOL
        self.k32.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        self.k32.SetThreadContext.restype = wintypes.BOOL
        self.wow64_get_context = getattr(self.k32, "Wow64GetThreadContext", None)
        self.wow64_set_context = getattr(self.k32, "Wow64SetThreadContext", None)
        if self.wow64_get_context is not None:
            self.wow64_get_context.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
            self.wow64_get_context.restype = wintypes.BOOL
        if self.wow64_set_context is not None:
            self.wow64_set_context.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
            self.wow64_set_context.restype = wintypes.BOOL
        self.k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.k32.OpenThread.restype = wintypes.HANDLE
        # Toolhelp declarations are important on Win64: without restype,
        # ctypes assumes a 32-bit integer and truncates the snapshot HANDLE.
        self.k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        self.k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        self.k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        self.k32.Module32FirstW.restype = wintypes.BOOL
        self.k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        self.k32.Module32NextW.restype = wintypes.BOOL
        self.k32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.k32.CloseHandle.restype = wintypes.BOOL
        self.psapi.EnumProcessModulesEx.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), wintypes.DWORD
        ]
        self.psapi.EnumProcessModulesEx.restype = wintypes.BOOL
        self.psapi.GetModuleBaseNameW.argtypes = [
            wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD
        ]
        self.psapi.GetModuleBaseNameW.restype = wintypes.DWORD

    def start_process(self, path):
        if self.is_running:
            self.signals.state_changed.emit("Debugger is already running.")
            return False
        self.target_path = path
        self.runtime_breakpoints.clear()
        self.hardware_breakpoints.clear()
        self.pending_reinsert = None
        self.step_over_runtime = None
        self.paused_thread_id = None
        self.last_registers = {}
        self.trace_records.clear()
        self.resume_event.set()
        try:
            probe = pefile.PE(path, fast_load=True)
            self.target_is_64 = probe.FILE_HEADER.Machine == 0x8664
        except Exception:
            self.target_is_64 = True
        self.worker_thread = threading.Thread(target=self._run_debugger, daemon=True)
        self.worker_thread.start()
        return True

    def _run_debugger(self):
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(STARTUPINFOW)
        pi = PROCESS_INFORMATION()

        formatted_cmd = f'"{os.path.abspath(self.target_path)}"'

        success = self.k32.CreateProcessW(
            None, formatted_cmd, None, None, False,
            DEBUG_PROCESS | CREATE_NEW_CONSOLE, None, None,
            ctypes.byref(si), ctypes.byref(pi)
        )
        if not success:
            err_code = self.k32.GetLastError()
            self.signals.state_changed.emit(f"CreateProcess Error: {err_code}")
            return

        self.process_info = pi
        self.is_running = True
        self.thread_handles = {pi.dwThreadId: pi.hThread}
        self.signals.state_changed.emit(f"Debugger attached: PID {pi.dwProcessId}")

        debug_event = DEBUG_EVENT()
        first_bp = True

        while self.is_running:
            if not self.k32.WaitForDebugEvent(ctypes.byref(debug_event), 100):
                continue

            # A debug event is owned by this loop until ContinueDebugEvent is
            # called exactly once for it.  In particular, never fall through
            # to WaitForDebugEvent while a breakpoint event is still pending:
            # that leaves the debuggee suspended forever and makes F9 look as
            # if it worked while nothing actually continues.
            continue_status = DBG_CONTINUE
            wait_for_user = False
            event_pid = debug_event.dwProcessId
            event_tid = debug_event.dwThreadId
            if self.trace_enabled:
                code_name = {1: "EXCEPTION", 2: "CREATE_THREAD", 4: "EXIT_THREAD", 5: "EXIT_PROCESS"}.get(debug_event.dwDebugEventCode, str(debug_event.dwDebugEventCode))
                self.trace_records.append({"event": code_name, "thread": int(event_tid), "address": int(debug_event.u.Exception.ExceptionRecord.ExceptionAddress or 0) if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT else 0})
                self.trace_records = self.trace_records[-10000:]

            if debug_event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT:
                thread_id = debug_event.dwThreadId
                if thread_id not in self.thread_handles:
                    handle = self.k32.OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, False, thread_id)
                    if handle:
                        self.thread_handles[thread_id] = handle
                        self._install_requested_hardware_breakpoints(handle)

            if debug_event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT:
                thread_id = debug_event.dwThreadId
                handle = self.thread_handles.pop(thread_id, None)
                if handle and handle != pi.hThread:
                    self.k32.CloseHandle(handle)

            if debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                self.is_running = False
                self.runtime_breakpoints.clear()
                self.disabled_imports.clear()
                self.pending_reinsert = None
                self.step_over_runtime = None
                self.paused_thread_id = None
                # Acknowledge the exit event while the debug event is still
                # valid.  Only then release the handles held by this object.
                self.k32.ContinueDebugEvent(event_pid, event_tid, DBG_CONTINUE)
                if self.process_info:
                    self.k32.CloseHandle(self.process_info.hProcess)
                    self.k32.CloseHandle(self.process_info.hThread)
                    self.process_info = None
                self.thread_handles.clear()
                self.signals.state_changed.emit("Debug process exited.")
                continue

            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                thread_handle = self.thread_handles.get(
                    debug_event.dwThreadId, pi.hThread
                )
                code = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                addr = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                if code == EXCEPTION_BREAKPOINT:
                    if first_bp:
                        first_bp = False
                        self._install_requested_breakpoints()
                        self._install_requested_import_disables()
                        self._install_requested_hardware_breakpoints(thread_handle)
                        # On some WOW64 systems the initial debug exception is
                        # delivered at the image entry point itself. If a user
                        # breakpoint was installed there, do not discard that
                        # first event as a loader trap.
                        initial_runtime = int(addr or 0)
                        initial_hit = self.runtime_breakpoints.get(initial_runtime)
                        if initial_hit:
                            original, user_va = initial_hit
                            self._write_byte(initial_runtime, original)
                            resume_at = initial_runtime + 1 if original == 0xCC else initial_runtime
                            self._prepare_single_step(thread_handle, resume_at)
                            self.pending_reinsert = (initial_runtime, original)
                            self.resume_event.clear()
                            self.paused_thread_id = event_tid
                            wait_for_user = True
                            self.signals.breakpoint_hit.emit(user_va)
                        else:
                            self._read_context(thread_handle)
                    else:
                        hit_runtime = int(addr or 0)
                        if self.step_over_runtime and hit_runtime == self.step_over_runtime[0]:
                            temp_addr, temp_original, temp_static = self.step_over_runtime
                            self._write_byte(temp_addr, temp_original)
                            self._set_context_rip(thread_handle, temp_addr, trap=False)
                            self.step_over_runtime = None
                            self.step_mode = False
                            self.pending_reinsert = None
                            self.resume_event.clear()
                            self.paused_thread_id = event_tid
                            wait_for_user = True
                            # The UI converts runtime addresses back to the
                            # static image VA. Emit the runtime address here;
                            # passing temp_static would apply ASLR conversion
                            # twice when image and runtime bases coincide.
                            self.signals.step_finished.emit(temp_addr)
                            self._read_context(thread_handle)
                            continue_status = DBG_CONTINUE
                            # Do not treat the temporary step-over trap as a
                            # user breakpoint and do not show a popup.
                            hit_runtime = 0
                        if not hit_runtime:
                            pass
                        else:
                            hit = self.runtime_breakpoints.get(hit_runtime)
                            if hit:
                                original, user_va = hit
                                self._write_byte(hit_runtime, original)
                                # If the original byte was already INT3, this is
                                # a native breakpoint rather than an instruction
                                # replaced by our F2 point. Skip it instead of
                                # restoring RIP to the same trap forever.
                                resume_at = hit_runtime + 1 if original == 0xCC else hit_runtime
                                self._prepare_single_step(thread_handle, resume_at)
                                self.pending_reinsert = (hit_runtime, original)
                                hit_count = self.breakpoint_hits.get(user_va, 0) + 1
                                self.breakpoint_hits[user_va] = hit_count
                                hit_limit = self.breakpoint_hit_limits.get(user_va, 0)
                                condition = self.breakpoint_conditions.get(user_va, "").strip()
                                if condition and not self._condition_matches(thread_handle, condition):
                                    # Conditional breakpoint did not match: keep the
                                    # one-instruction reinsertion dance, but do not
                                    # stop the target or show a false hit popup.
                                    self.signals.state_changed.emit(
                                        f"Conditional breakpoint skipped at 0x{user_va:X} ({condition})."
                                    )
                                elif hit_limit and hit_count < hit_limit:
                                    self.signals.state_changed.emit(
                                        f"Breakpoint 0x{user_va:X}: hit {hit_count}/{hit_limit}; continuing."
                                    )
                                elif user_va in self.breakpoint_log_only:
                                    self.signals.state_changed.emit(
                                        f"Log breakpoint hit at 0x{user_va:X} (#{hit_count})."
                                    )
                                else:
                                    self.resume_event.clear()
                                    self.paused_thread_id = event_tid
                                    wait_for_user = True
                                    self.signals.breakpoint_hit.emit(user_va)
                            else:
                                # Do not turn an unregistered/native INT3 into a
                                # fake user breakpoint. Initial loader/runtime
                                # traps and embedded INT3 instructions are not
                                # breakpoints created through the F2 UI.
                                self.signals.state_changed.emit(
                                    f"Ignored unregistered INT3 at runtime 0x{hit_runtime:X}."
                                )
                            self._read_context(thread_handle)

                elif code == EXCEPTION_SINGLE_STEP:
                    hardware_hit = self._hardware_breakpoint_hit(thread_handle)
                    if hardware_hit is None and self.hardware_breakpoints:
                        # Some Windows builds report an execute debug-register
                        # trap with a cleared DR6 in the debug event payload.
                        # ExceptionAddress is still the precise instruction
                        # address, so use it as a reliable fallback.
                        for runtime, info in self.hardware_breakpoints.items():
                            if int(addr or 0) == runtime:
                                hardware_hit = info[1]
                                break
                    if self.pending_reinsert:
                        bp_addr, original = self.pending_reinsert
                        self._write_byte(bp_addr, 0xCC)
                        self.pending_reinsert = None
                    self._read_context(thread_handle)
                    if self.step_mode:
                        self.step_mode = False
                        self.paused_thread_id = event_tid
                        self.resume_event.clear()
                        wait_for_user = True
                        self.signals.step_finished.emit(int(addr or 0))
                    elif hardware_hit is not None:
                        self.resume_event.clear()
                        self.paused_thread_id = event_tid
                        wait_for_user = True
                        self.signals.breakpoint_hit.emit(hardware_hit)

                else:
                    # Let the target's exception handlers process exceptions
                    # that were not caused by our breakpoint/step machinery.
                    continue_status = DBG_EXCEPTION_NOT_HANDLED

            if wait_for_user:
                # The debuggee is intentionally stopped at the breakpoint.
                # F9 sets this event.  The current DEBUG_EVENT is then
                # continued below, which is the operation that actually
                # releases the Windows debuggee.
                self.resume_event.wait()
                if not self.is_running:
                    break

            continued = self.k32.ContinueDebugEvent(
                event_pid,
                event_tid,
                continue_status
            )
            if not continued:
                self.signals.state_changed.emit(
                    f"ContinueDebugEvent failed: Win32 error {self.k32.GetLastError()}"
                )
            elif self.pending_reinsert is None:
                self.signals.state_changed.emit("Debug event continued.")
            if wait_for_user and continued:
                self.paused_thread_id = None

    def set_user_breakpoint(self, va, image_base):
        self.requested_breakpoints.add((va, image_base))
        if self.is_running:
            ok = self._install_breakpoint(va, image_base)
            if not ok:
                self.signals.state_changed.emit(
                    f"Breakpoint install failed at 0x{va:X}; Win32 error {self.k32.GetLastError()}"
                )
            return ok
        return True

    def set_import_disabled(self, dll, name, iat_va, image_base):
        """Replace one PE import thunk with a small FALSE-returning stub."""
        key = (str(dll).casefold(), str(name).casefold())
        self.requested_disabled_imports[key] = (str(dll), str(name), int(iat_va), int(image_base))
        if self.is_running:
            return self._install_import_disable(key)
        return True

    def remove_import_disabled(self, dll, name):
        key = (str(dll).casefold(), str(name).casefold())
        self.requested_disabled_imports.pop(key, None)
        installed = self.disabled_imports.pop(key, None)
        if not installed or not self.process_info:
            return True
        iat_runtime, original, stub = installed
        pointer_size = 8 if self.target_is_64 else 4
        data = int(original).to_bytes(pointer_size, "little")
        ok = self._write_remote(iat_runtime, data)
        if stub:
            self.k32.VirtualFreeEx(self.process_info.hProcess, ctypes.c_void_p(stub), 0, 0x8000)
        return ok

    def _install_requested_import_disables(self):
        for key in list(self.requested_disabled_imports):
            self._install_import_disable(key)

    def _install_import_disable(self, key):
        if not self.process_info or not self.is_running:
            return True
        if key in self.disabled_imports:
            return True
        record = self.requested_disabled_imports.get(key)
        if not record:
            return False
        dll, name, iat_va, image_base = record
        module_base = self._remote_module_base(os.path.basename(self.target_path))
        if not module_base:
            self.signals.state_changed.emit(f"Import disable failed: target module not found for {name}.")
            return False
        iat_runtime = module_base + (iat_va - image_base)
        pointer_size = 8 if self.target_is_64 else 4
        raw = self.read_process_bytes(iat_runtime, pointer_size)
        if not raw or len(raw) != pointer_size:
            self.signals.state_changed.emit(f"Import disable failed: cannot read IAT for {dll}!{name}.")
            return False
        original = int.from_bytes(raw, "little")
        # xor eax,eax; ret => a safe FALSE/0 return for common Win32 APIs.
        stub_code = b"\x31\xC0\xC3"
        stub = self.k32.VirtualAllocEx(
            self.process_info.hProcess, None, len(stub_code), 0x3000, 0x40
        )
        stub = ctypes.cast(stub, ctypes.c_void_p).value if stub else 0
        if not stub or not self._write_remote(stub, stub_code):
            if stub:
                self.k32.VirtualFreeEx(self.process_info.hProcess, ctypes.c_void_p(stub), 0, 0x8000)
            self.signals.state_changed.emit(f"Import disable failed: cannot create stub for {dll}!{name}.")
            return False
        if not self._write_remote(iat_runtime, int(stub).to_bytes(pointer_size, "little")):
            self.k32.VirtualFreeEx(self.process_info.hProcess, ctypes.c_void_p(stub), 0, 0x8000)
            self.signals.state_changed.emit(f"Import disable failed: cannot patch IAT for {dll}!{name}.")
            return False
        self.disabled_imports[key] = (iat_runtime, original, stub)
        self.signals.state_changed.emit(f"Import disabled: {dll}!{name} (returns FALSE).")
        return True

    def set_breakpoint_condition(self, va, expression):
        expression = (expression or "").strip()
        if expression:
            self.breakpoint_conditions[int(va)] = expression
        else:
            self.breakpoint_conditions.pop(int(va), None)

    def set_hardware_breakpoint(self, va, image_base):
        """Request an execute hardware breakpoint using an available DR slot."""
        point = (int(va), int(image_base))
        self.requested_hardware_breakpoints.add(point)
        if not self.is_running:
            return True
        ok = False
        for handle in list(self.thread_handles.values()):
            ok = self._install_hardware_breakpoint(va, image_base, handle) or ok
        if not ok:
            self.signals.state_changed.emit("No paused thread available for a hardware breakpoint.")
        return ok

    def remove_hardware_breakpoint(self, va, image_base):
        self.requested_hardware_breakpoints.discard((int(va), int(image_base)))
        for runtime, info in list(self.hardware_breakpoints.items()):
            if info[1] == int(va):
                self._clear_hardware_slot(info[0])
                self.hardware_breakpoints.pop(runtime, None)

    def remove_user_breakpoint(self, va, image_base):
        self.requested_breakpoints.discard((va, image_base))
        for runtime, (original, saved_va) in list(self.runtime_breakpoints.items()):
            if saved_va == va:
                self._write_byte(runtime, original)
                del self.runtime_breakpoints[runtime]
                if self.pending_reinsert and self.pending_reinsert[0] == runtime:
                    # The current stop may be waiting for a single-step.  Do
                    # not let that single-step put a deleted breakpoint back.
                    self.pending_reinsert = None
                return True
        return True

    def _install_requested_breakpoints(self):
        for va, image_base in list(self.requested_breakpoints):
            self._install_breakpoint(va, image_base)

    def _install_requested_hardware_breakpoints(self, thread_handle):
        for va, image_base in list(self.requested_hardware_breakpoints):
            self._install_hardware_breakpoint(va, image_base, thread_handle)

    def _install_hardware_breakpoint(self, va, image_base, h_thread):
        if not self.process_info or not h_thread:
            return False
        module = self._remote_module_base(os.path.basename(self.target_path))
        if not module:
            return False
        runtime = module + (int(va) - int(image_base))
        if runtime in self.hardware_breakpoints:
            return True
        ctx = CONTEXT64() if self.target_is_64 else WOW64_CONTEXT()
        ctx.ContextFlags = (CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS) if self.target_is_64 else 0x00010007
        if not self._get_thread_context(h_thread, ctx):
            return False
        used = {info[0] for info in self.hardware_breakpoints.values()}
        slot = next((candidate for candidate in range(4) if candidate not in used), None)
        if slot is None:
            self.signals.state_changed.emit("Hardware breakpoint limit reached (4 slots).")
            return False
        setattr(ctx, f"Dr{slot}", runtime)
        ctx.Dr7 |= (1 << (slot * 2))  # local enable, execute/length 1 byte
        ctx.Dr7 &= ~(0xF << (16 + slot * 4))
        ctx.Dr6 = 0
        if not self._set_thread_context(h_thread, ctx):
            return False
        self.hardware_breakpoints[runtime] = (slot, int(va), int(image_base))
        self.signals.state_changed.emit(f"Hardware breakpoint installed: 0x{int(va):X}")
        return True

    def _clear_hardware_slot(self, slot):
        for handle in list(self.thread_handles.values()):
            ctx = CONTEXT64() if self.target_is_64 else WOW64_CONTEXT()
            ctx.ContextFlags = (CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS) if self.target_is_64 else 0x00010007
            if self._get_thread_context(handle, ctx):
                ctx.Dr7 &= ~(1 << (slot * 2))
                setattr(ctx, f"Dr{slot}", 0)
                self._set_thread_context(handle, ctx)

    def _hardware_breakpoint_hit(self, h_thread):
        if not self.hardware_breakpoints or not h_thread:
            return None
        ctx = CONTEXT64() if self.target_is_64 else WOW64_CONTEXT()
        ctx.ContextFlags = (CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS) if self.target_is_64 else 0x00010007
        if not self._get_thread_context(h_thread, ctx):
            return None
        for runtime, info in self.hardware_breakpoints.items():
            if ctx.Dr6 & (1 << info[0]):
                ctx.Dr6 = 0
                self._set_thread_context(h_thread, ctx)
                return info[1]
        return None

    def _condition_matches(self, h_thread, expression):
        """Evaluate a deliberately small, safe register condition language."""
        ctx = CONTEXT64() if self.target_is_64 else WOW64_CONTEXT()
        ctx.ContextFlags = (CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS) if self.target_is_64 else 0x00010007
        if not self._get_thread_context(h_thread, ctx):
            return False
        if self.target_is_64:
            regs = {name: int(getattr(ctx, name.title(), 0))
                    for name in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip")}
        else:
            regs = {name: int(getattr(ctx, {"eax": "Eax", "ebx": "Ebx", "ecx": "Ecx", "edx": "Edx", "esi": "Esi", "edi": "Edi", "esp": "Esp", "ebp": "Ebp", "eip": "Eip"}[name], 0))
                    for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eip")}
        memory_match = re.fullmatch(r"\s*(?:MEM|MEMORY)\s*\[\s*(0x[0-9a-fA-F]+|[0-9]+)\s*\]\s*(==|!=|<=|>=|<|>)\s*(0x[0-9a-fA-F]+|[0-9]+)\s*", expression, re.IGNORECASE)
        if memory_match:
            address_text, op, right = memory_match.groups()
            data = self.read_memory(int(address_text, 0), 8)
            if not data:
                return False
            lhs = int.from_bytes(data, "little")
            rhs = int(right, 0)
            return {"==": lhs == rhs, "!=": lhs != rhs, "<": lhs < rhs, "<=": lhs <= rhs, ">": lhs > rhs, ">=": lhs >= rhs}[op]
        match = re.fullmatch(r"\s*([A-Za-z][A-Za-z0-9]*)\s*(==|!=|<=|>=|<|>)\s*(0x[0-9a-fA-F]+|[0-9]+)\s*", expression)
        if not match:
            self.signals.state_changed.emit("Condition syntax: REG == 0x123 (also !=, <, <=, >, >=).")
            return False
        left, op, right = match.groups()
        key = left.lower()
        if key not in regs:
            return False
        rhs = int(right, 0)
        lhs = regs[key]
        return {"==": lhs == rhs, "!=": lhs != rhs, "<": lhs < rhs,
                "<=": lhs <= rhs, ">": lhs > rhs, ">=": lhs >= rhs}[op]

    def _install_breakpoint(self, va, image_base):
        if not self.process_info:
            return False
        module = self._remote_module_base(os.path.basename(self.target_path))
        if not module:
            self.signals.state_changed.emit(
                f"Breakpoint failed: target module not found ({os.path.basename(self.target_path)})"
            )
            return False
        runtime = module + (va - image_base)
        if runtime in self.runtime_breakpoints:
            return True
        original = ctypes.c_ubyte()
        if not self.k32.ReadProcessMemory(
            self.process_info.hProcess, ctypes.c_void_p(runtime),
            ctypes.byref(original), 1, None
        ):
            self.signals.state_changed.emit(
                f"Breakpoint read failed at 0x{runtime:X}; Win32 error {self.k32.GetLastError()}"
            )
            return False
        if not self._write_byte(runtime, 0xCC):
            self.signals.state_changed.emit(
                f"Breakpoint write failed at 0x{runtime:X}; Win32 error {self.k32.GetLastError()}"
            )
            return False
        self.runtime_breakpoints[runtime] = (original.value, va)
        self.signals.state_changed.emit(
            f"Breakpoint installed: VA 0x{va:X} -> runtime 0x{runtime:X}"
        )
        return True

    def _write_byte(self, address, value):
        data = (ctypes.c_ubyte * 1)(value)
        old_protection = wintypes.DWORD()
        process = self.process_info.hProcess
        if not self.k32.VirtualProtectEx(
            process, ctypes.c_void_p(address), 1,
            PAGE_EXECUTE_READWRITE, ctypes.byref(old_protection)
        ):
            return False
        try:
            written = bool(self.k32.WriteProcessMemory(
                process, ctypes.c_void_p(address), data, 1, None
            ))
            if not written:
                return False
            verify = ctypes.c_ubyte()
            return bool(self.k32.ReadProcessMemory(
                process, ctypes.c_void_p(address), ctypes.byref(verify), 1, None
            )) and verify.value == value
        finally:
            self.k32.VirtualProtectEx(
                process, ctypes.c_void_p(address), 1,
                old_protection.value, ctypes.byref(old_protection)
            )

    def _get_thread_context(self, h_thread, context):
        if self.target_is_64:
            return bool(self.k32.GetThreadContext(h_thread, ctypes.byref(context)))
        return bool(self.wow64_get_context and self.wow64_get_context(h_thread, ctypes.byref(context)))

    def _set_thread_context(self, h_thread, context):
        if self.target_is_64:
            return bool(self.k32.SetThreadContext(h_thread, ctypes.byref(context)))
        return bool(self.wow64_set_context and self.wow64_set_context(h_thread, ctypes.byref(context)))

    def _prepare_single_step(self, h_thread, resume_address):
        ctx = CONTEXT64() if self.target_is_64 else WOW64_CONTEXT()
        ctx.ContextFlags = CONTEXT_FULL if self.target_is_64 else 0x00010007
        if not self._get_thread_context(h_thread, ctx):
            return False
        if self.target_is_64:
            ctx.Rip = resume_address
        else:
            ctx.Eip = int(resume_address) & 0xFFFFFFFF
        ctx.EFlags |= 0x100
        return self._set_thread_context(h_thread, ctx)

    def _set_context_rip(self, h_thread, address, trap=False):
        ctx = CONTEXT64() if self.target_is_64 else WOW64_CONTEXT()
        ctx.ContextFlags = CONTEXT_FULL if self.target_is_64 else 0x00010007
        if not self._get_thread_context(h_thread, ctx):
            return False
        if self.target_is_64:
            ctx.Rip = int(address)
        else:
            ctx.Eip = int(address) & 0xFFFFFFFF
        if trap:
            ctx.EFlags |= 0x100
        else:
            ctx.EFlags &= ~0x100
        return self._set_thread_context(h_thread, ctx)

    def _read_context(self, h_thread):
        ctx = CONTEXT64() if self.target_is_64 else WOW64_CONTEXT()
        ctx.ContextFlags = CONTEXT_FULL if self.target_is_64 else 0x00010007
        if self._get_thread_context(h_thread, ctx):
            if self.target_is_64:
                regs = {
                    "RAX": hex(ctx.Rax), "RBX": hex(ctx.Rbx),
                    "RCX": hex(ctx.Rcx), "RDX": hex(ctx.Rdx),
                    "RSI": hex(ctx.Rsi), "RDI": hex(ctx.Rdi),
                    "RSP": hex(ctx.Rsp), "RBP": hex(ctx.Rbp),
                    "RIP": hex(ctx.Rip), "EFLAGS": hex(ctx.EFlags)
                }
            else:
                regs = {
                    "EAX": hex(ctx.Eax), "EBX": hex(ctx.Ebx),
                    "ECX": hex(ctx.Ecx), "EDX": hex(ctx.Edx),
                    "ESI": hex(ctx.Esi), "EDI": hex(ctx.Edi),
                    "ESP": hex(ctx.Esp), "EBP": hex(ctx.Ebp),
                    "EIP": hex(ctx.Eip), "EFLAGS": hex(ctx.EFlags)
                }
            self.last_registers = regs
            self.signals.registers_updated.emit(regs)

    def frame_rows(self, count=32):
        """Walk a conventional RBP chain when frame pointers are present."""
        try:
            is64 = self.target_is_64
            rbp = int(self.last_registers.get("RBP" if is64 else "EBP", "0"), 16)
        except (TypeError, ValueError):
            return []
        rows = []
        seen = set()
        word_size = 8 if self.target_is_64 else 4
        for index in range(max(1, int(count))):
            if not rbp or rbp in seen or rbp % 8:
                break
            data = self.read_memory(rbp, word_size * 2)
            if len(data) < word_size * 2:
                break
            previous = int.from_bytes(data[:word_size], "little")
            ret = int.from_bytes(data[word_size:word_size * 2], "little")
            rows.append((index, rbp, ret))
            seen.add(rbp)
            if previous <= rbp or previous - rbp > 0x100000:
                break
            rbp = previous
        return rows

    def thread_rows(self):
        paused = self.paused_thread_id
        return [(tid, "paused" if tid == paused else "running")
                for tid in sorted(self.thread_handles)]

    def stack_rows(self, count=32):
        try:
            rsp = int(self.last_registers.get("RSP" if self.target_is_64 else "ESP", "0"), 16)
        except (TypeError, ValueError):
            return []
        word_size = 8 if self.target_is_64 else 4
        data = self.read_memory(rsp, count * word_size)
        rows = []
        for offset in range(0, len(data) - word_size + 1, word_size):
            value = int.from_bytes(data[offset:offset + word_size], "little")
            rows.append((rsp + offset, value))
        return rows

    def _remote_module_base(self, module_name):
        """Return a module base in the debuggee, or None on lookup failure."""
        # PSAPI handles native 64-bit module enumeration without relying on
        # a snapshot HANDLE whose size differs between Python architectures.
        h_proc = self.process_info.hProcess
        capacity = 1024
        modules = (wintypes.HMODULE * capacity)()
        needed = wintypes.DWORD()
        if self.psapi.EnumProcessModulesEx(
            h_proc, modules, ctypes.sizeof(modules), ctypes.byref(needed), 0x03
        ):
            count = min(needed.value // ctypes.sizeof(wintypes.HMODULE), capacity)
            for index in range(count):
                name_buf = ctypes.create_unicode_buffer(260)
                self.psapi.GetModuleBaseNameW(
                    h_proc, modules[index], name_buf, len(name_buf)
                )
                if name_buf.value.lower() == module_name.lower():
                    return ctypes.cast(modules[index], ctypes.c_void_p).value

        # Fallback for systems where PSAPI enumeration is restricted.
        snap = self.k32.CreateToolhelp32Snapshot(0x00000008, self.process_info.dwProcessId)
        if snap == ctypes.c_void_p(-1).value:
            return None
        class MODULEENTRY32W(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD), ("GlblcntUsage", wintypes.DWORD),
                        ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.POINTER(ctypes.c_ubyte)),
                        ("modBaseSize", wintypes.DWORD), ("hModule", wintypes.HMODULE),
                        ("szModule", wintypes.WCHAR * 256), ("szExePath", wintypes.WCHAR * 260)]
        entry = MODULEENTRY32W(); entry.dwSize = ctypes.sizeof(entry)
        try:
            ok = self.k32.Module32FirstW(snap, ctypes.byref(entry))
            while ok:
                if entry.szModule.lower() == module_name.lower():
                    return ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value
                ok = self.k32.Module32NextW(snap, ctypes.byref(entry))
        finally:
            self.k32.CloseHandle(snap)
        return None

    def stop(self):
        self.is_running = False
        self.step_mode = False
        self.step_over_runtime = None
        self.paused_thread_id = None
        self.resume_event.set()
        if self.process_info:
            process_handle = self.process_info.hProcess
            thread_handle = self.process_info.hThread
            self.k32.TerminateProcess(process_handle, 0)
            self.k32.CloseHandle(process_handle)
            self.k32.CloseHandle(thread_handle)
            self.process_info = None
            for handle in self.thread_handles.values():
                if handle and handle != thread_handle:
                    self.k32.CloseHandle(handle)
            self.thread_handles.clear()
            self.runtime_breakpoints.clear()
            self.disabled_imports.clear()
            self.pending_reinsert = None
            self.signals.state_changed.emit("Debug process terminated.")

    def resume(self):
        self.step_mode = False
        self.resume_event.set()

    def step_into(self):
        if not self.is_running or self.paused_thread_id is None:
            self.signals.state_changed.emit("Step requires a paused debug event.")
            return False
        self.step_mode = True
        self.resume_event.set()
        return True

    def step_over(self):
        # GandonPRO tries the temporary-after-call breakpoint first. This is
        # the fallback for non-call instructions.
        return self.step_into()

    def arm_step_over(self, runtime_address, static_address):
        """Run over a call by stopping at the instruction after it."""
        if not self.is_running or self.paused_thread_id is None:
            self.signals.state_changed.emit("Step over requires a paused debug event.")
            return False
        if not self.process_info or runtime_address in self.runtime_breakpoints:
            return False
        thread_handle = self.thread_handles.get(self.paused_thread_id, self.process_info.hThread)
        if self.pending_reinsert:
            current_bp, current_original = self.pending_reinsert
            self._write_byte(current_bp, 0xCC)
            self.pending_reinsert = None
            self._set_context_rip(thread_handle, current_bp, trap=False)
        original = ctypes.c_ubyte()
        if not self.k32.ReadProcessMemory(
            self.process_info.hProcess, ctypes.c_void_p(runtime_address),
            ctypes.byref(original), 1, None
        ):
            return False
        if not self._write_byte(runtime_address, 0xCC):
            return False
        self._set_context_rip(thread_handle, runtime_address, trap=False)
        self.step_over_runtime = (runtime_address, original.value, static_address)
        self.step_mode = False
        self.resume_event.set()
        return True

    def enumerate_memory_regions(self):
        if not self.process_info or not self.is_running:
            return []
        regions = []
        mbi = MEMORY_BASIC_INFORMATION()
        address = 0
        max_address = 0x7FFFFFFFFFFF if self.target_is_64 else 0xFFFFFFFF
        while address < max_address:
            queried = self.k32.VirtualQueryEx(
                self.process_info.hProcess, ctypes.c_void_p(address),
                ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not queried or not mbi.RegionSize:
                break
            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize)
            if mbi.State == MEM_COMMIT and not (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)):
                protection_names = {
                    0x02: "R", 0x04: "RW", 0x08: "RWX", 0x10: "X",
                    0x20: "RX", 0x40: "RWX", 0x80: "X"
                }
                protection = protection_names.get(mbi.Protect & 0xFF, f"0x{mbi.Protect:X}")
                regions.append({"name": "Private/Image", "base": base, "end": base + size,
                                "size": size, "state": "COMMIT", "protection": protection})
            next_address = base + size
            if next_address <= address:
                break
            address = next_address
        return regions

    def read_memory(self, address, size=128):
        if not self.is_running or not self.process_info:
            return b""
        try:
            size = max(1, min(int(size), 0x10000))
            buffer = (ctypes.c_ubyte * size)()
            read = ctypes.c_size_t(0)
            ok = self.k32.ReadProcessMemory(
                self.process_info.hProcess, ctypes.c_void_p(int(address)),
                buffer, size, ctypes.byref(read)
            )
            return bytes(buffer[:read.value]) if ok else b""
        except (TypeError, ValueError, OverflowError):
            return b""

    def read_process_bytes(self, address, size):
        return self.read_memory(address, size)

    def _write_remote(self, address, data):
        if not self.process_info or not data:
            return False
        raw = bytes(data)
        buffer = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
        old_protection = wintypes.DWORD()
        process = self.process_info.hProcess
        if not self.k32.VirtualProtectEx(
            process, ctypes.c_void_p(int(address)), len(raw),
            PAGE_EXECUTE_READWRITE, ctypes.byref(old_protection)
        ):
            return False
        try:
            written = ctypes.c_size_t(0)
            ok = self.k32.WriteProcessMemory(
                process, ctypes.c_void_p(int(address)), buffer, len(raw), ctypes.byref(written)
            )
            if not ok or written.value != len(raw):
                return False
            self.k32.FlushInstructionCache(process, ctypes.c_void_p(int(address)), len(raw))
            return True
        finally:
            self.k32.VirtualProtectEx(
                process, ctypes.c_void_p(int(address)), len(raw),
                old_protection.value, ctypes.byref(old_protection)
            )


# =====================================================================
#                         ABOUT DIALOG (FIXED)
# =====================================================================

class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        apply_windows_dark_titlebar(self)
        self.setWindowTitle("About Gandon-PRO")
        self.setFixedSize(600, 230)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)

        card_widget = QWidget()
        card_widget.setStyleSheet("""
            QWidget {
                background-color: #252526;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
            }
        """)
        card_layout = QHBoxLayout(card_widget)
        card_layout.setContentsMargins(15, 15, 15, 15)
        card_layout.setSpacing(18)

        img_url = "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSXUZJKTeH1k3qfSP61Rui3VuQrGMQ5zlMmmAz4F5x3NN1QRFZq"
        pixmap = QPixmap()
        try:
            req = urllib.request.Request(img_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=2) as response:
                pixmap.loadFromData(response.read())
        except Exception:
            pass

        if pixmap.isNull():
            pixmap = QPixmap(130, 130)
            pixmap.fill(QColor("#252526"))
            p = QPainter(pixmap)
            p.setPen(QColor("#4EC9B0"))
            p.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
            p.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "GANDON\nPRO")
            p.end()

        self.img_label = QLabel()
        scaled = pixmap.scaled(130, 130, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        self.img_label.setPixmap(scaled)
        self.img_label.setFixedSize(scaled.size())
        self.img_label.setStyleSheet("border: none; background: transparent;")
        self.img_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setWindowIcon(QIcon(scaled))
        card_layout.addWidget(self.img_label, alignment=Qt.AlignmentFlag.AlignVCenter)

        info_layout = QVBoxLayout()
        info_layout.setSpacing(6)

        title_label = QLabel("Gandon: The Interactive Disassembler & Debugger")
        title_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #ffffff; border: none;")
        title_label.setWordWrap(True)
        info_layout.addWidget(title_label)

        ver_label = QLabel("Version Beta 2.2 (PE/ELF + Win32 Debugger)")
        ver_label.setFont(QFont("Segoe UI", 10))
        ver_label.setStyleSheet("color: #cccccc; border: none;")
        ver_label.setWordWrap(True)
        info_layout.addWidget(ver_label)

        url_label = QLabel("<a href='https://gandon-pro.github.io' style='color: #4EC9B0; text-decoration: underline;'>gandon-pro.github.io</a>")
        url_label.setFont(QFont("Segoe UI", 10))
        url_label.setStyleSheet("border: none;")
        info_layout.addWidget(url_label)

        copy_label = QLabel("© 2026 Gandon-PRO Team")
        copy_label.setFont(QFont("Segoe UI", 9))
        copy_label.setStyleSheet("color: #888888; border: none;")
        info_layout.addWidget(copy_label)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        ok_btn = QPushButton("OK")
        ok_btn.setFixedWidth(80)
        ok_btn.clicked.connect(self.accept)
        ok_btn.setStyleSheet("""
            QPushButton {
                background-color: #333333;
                color: #ffffff;
                border: 1px solid #555555;
                padding: 4px 12px;
                border-radius: 2px;
            }
            QPushButton:hover {
                background-color: #007acc;
                border-color: #007acc;
            }
        """)
        btn_layout.addWidget(ok_btn)
        info_layout.addLayout(btn_layout)

        card_layout.addLayout(info_layout)
        main_layout.addWidget(card_widget)
        self.setStyleSheet("QDialog { background-color: #1e1e1e; }")

    def showEvent(self, event):
        super().showEvent(event)
        apply_windows_dark_titlebar(self)


# =====================================================================
#                         XREFS DIALOG (KEY X)
# =====================================================================

class XrefsDialog(QDialog):
    def __init__(self, target_name, xrefs, parent=None):
        super().__init__(parent)
        apply_windows_dark_titlebar(self)
        self.setWindowTitle(f"xrefs to {target_name}")
        self.resize(640, 360)
        self.target_address = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Direction", "Type", "Address / Target"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setFont(QFont("Consolas", 9))
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setStyleSheet("""
            QTableWidget { background-color: #252526; color: #d4d4d4; gridline-color: #333333; }
            QHeaderView::section { background-color: #2d2d2d; color: #9cdcfe; }
        """)

        self.table.setRowCount(len(xrefs))
        for row, (dir_str, xtype, src_addr, text) in enumerate(xrefs):
            self.table.setItem(row, 0, QTableWidgetItem(dir_str))
            self.table.setItem(row, 1, QTableWidgetItem(xtype))
            self.table.setItem(row, 2, QTableWidgetItem(f"0x{src_addr:08X}  {text}"))

        self.table.itemDoubleClicked.connect(self.on_select)
        layout.addWidget(self.table)

        btn_box = QHBoxLayout()
        btn_box.addStretch()
        jump_btn = QPushButton("Jump")
        jump_btn.clicked.connect(self.on_select_btn)
        jump_btn.setStyleSheet("background-color: #007acc; color: white; padding: 5px 16px; border: none; border-radius: 2px;")
        btn_box.addWidget(jump_btn)
        layout.addLayout(btn_box)

        self.xrefs_data = xrefs
        self.setStyleSheet("""
            QDialog { background-color: #1e1e1e; color: #d4d4d4; }
            QLabel { color: #d4d4d4; }
            QTableWidget {
                background-color: #252526; color: #d4d4d4;
                gridline-color: #3c3c3c; border: 1px solid #3c3c3c;
                selection-background-color: #264f78;
            }
            QHeaderView::section {
                background-color: #2d2d2d; color: #9CDCFE;
                border: 1px solid #3c3c3c; padding: 5px;
            }
            QPushButton {
                background-color: #2d2d2d; color: #d4d4d4;
                border: 1px solid #505050; padding: 5px 16px;
            }
            QPushButton:hover { background-color: #007acc; color: white; }
        """)

    def on_select(self, item):
        row = item.row()
        self.target_address = self.xrefs_data[row][2]
        self.accept()

    def on_select_btn(self):
        row = self.table.currentRow()
        if row >= 0:
            self.target_address = self.xrefs_data[row][2]
            self.accept()


class CallGraphDialog(QDialog):
    def __init__(self, call_graph, parent=None):
        super().__init__(parent)
        apply_windows_dark_titlebar(self)
        self.setWindowTitle("Call Graph")
        self.resize(760, 460)
        theme = """
            QDialog { background-color: #1e1e1e; color: #d4d4d4; }
            QTableWidget {
                background-color: #252526; color: #d4d4d4;
                alternate-background-color: #2a2a2a;
                gridline-color: #3c3c3c; border: 1px solid #3c3c3c;
                selection-background-color: #264f78;
            }
            QHeaderView::section {
                background-color: #2d2d2d; color: #9CDCFE;
                border: 1px solid #3c3c3c; padding: 5px;
            }
            QTableCornerButton::section {
                background-color: #2d2d2d; border: 1px solid #3c3c3c;
            }
        """
        layout = QVBoxLayout(self)
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["Caller", "Callee"])
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        table.setRowCount(sum(len(targets) for targets in call_graph.values()))
        row = 0
        for caller in sorted(call_graph):
            for callee in sorted(call_graph[caller]):
                table.setItem(row, 0, QTableWidgetItem(f"0x{caller:016X}"))
                table.setItem(row, 1, QTableWidgetItem(f"0x{callee:016X}"))
                row += 1
        table.itemDoubleClicked.connect(
            lambda item: self.parent().jump_to_address(int(table.item(item.row(), 1).text(), 16))
        )
        layout.addWidget(table)
        self.setStyleSheet(theme)


# =====================================================================
#             SIGMAKER DIALOG (SIGNATURE GENERATOR)
# =====================================================================

class SigMakerDialog(QDialog):
    def __init__(self, sig_gandon, sig_cpp_mask, count_matches, parent=None):
        super().__init__(parent)
        apply_windows_dark_titlebar(self)
        self.setWindowTitle("Signature Generator (SigMaker)")
        self.resize(600, 240)
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel(f"<b>Uniqueness Status:</b> {'UNIQUE (1 Match found)' if count_matches == 1 else f'Collisions: {count_matches} Matches'}"))

        layout.addWidget(QLabel("Gandon Pattern:"))
        self.gandon_edit = QLineEdit(sig_gandon)
        self.gandon_edit.setReadOnly(True)
        layout.addWidget(self.gandon_edit)

        layout.addWidget(QLabel("C++ Pattern & Mask:"))
        self.cpp_edit = QLineEdit(sig_cpp_mask)
        self.cpp_edit.setReadOnly(True)
        layout.addWidget(self.cpp_edit)

        btn_box = QHBoxLayout()
        btn_box.addStretch()
        copy_btn = QPushButton("Copy Gandon Pattern")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(sig_gandon))
        btn_box.addWidget(copy_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_box.addWidget(close_btn)

        layout.addLayout(btn_box)
        self.setStyleSheet("""
            QDialog { background-color: #1e1e1e; color: #d4d4d4; }
            QLabel { color: #d4d4d4; }
            QLineEdit { background-color: #252526; color: #4EC9B0; border: 1px solid #3c3c3c; padding: 5px; font-family: Consolas; }
            QPushButton { background-color: #333; color: white; border: 1px solid #555; padding: 5px 12px; }
            QPushButton:hover { background-color: #007acc; }
        """)


# =====================================================================
#             МАРШРУТИЗАЦИЯ СТРЕЛОК И ГРАФИЧЕСКИЕ ЭЛЕМЕНТЫ
# =====================================================================

class EdgeHandleItem(QGraphicsRectItem):
    def __init__(self, edge):
        super().__init__(-3, -3, 6, 6)
        self.edge = edge
        self.is_updating = False
        self.setPen(QPen(QColor("#007acc"), 1))
        self.setBrush(QBrush(QColor(255, 255, 255, 120)))
        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsMovable |
            QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges
        )
        self.setCursor(QCursor(Qt.CursorShape.SizeVerCursor))
        self.setZValue(6)

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionChange and self.scene():
            if not self.is_updating:
                self.edge.on_handle_moved(value.y())
            return QPointF(self.pos().x(), value.y())
        return super().itemChange(change, value)


class EdgeItem:
    def __init__(self, scene, graph_view, n_from, n_to, color_hex, edge_type="uncond"):
        self.scene = scene
        self.graph_view = graph_view
        self.n_from = n_from
        self.n_to = n_to
        self.color = QColor(color_hex)
        self.edge_type = edge_type
        self.custom_mid_y = None

        self.path_item = QGraphicsPathItem()
        self.path_item.setPen(QPen(self.color, 1.8))
        self.path_item.setZValue(2)
        self.scene.addItem(self.path_item)

        self.arrow_item = QGraphicsPolygonItem()
        self.arrow_item.setPen(QPen(self.color, 1))
        self.arrow_item.setBrush(QBrush(self.color))
        self.arrow_item.setZValue(3)
        self.scene.addItem(self.arrow_item)

        self.handle = EdgeHandleItem(self)
        self.scene.addItem(self.handle)

        self.n_from.add_outgoing_edge(self)
        self.n_to.add_incoming_edge(self)
        self.update_path()

    def on_handle_moved(self, new_y):
        self.custom_mid_y = new_y
        self.update_path(move_handle=False)

    def update_path(self, move_handle=True):
        if self.edge_type == "true":
            from_x = self.n_from.pos().x() + self.n_from.width * 0.25
        elif self.edge_type == "false":
            from_x = self.n_from.pos().x() + self.n_from.width * 0.75
        else:
            from_x = self.n_from.pos().x() + self.n_from.width * 0.5

        p_from = QPointF(from_x, self.n_from.pos().y() + self.n_from.height)
        p_to = QPointF(self.n_to.pos().x() + self.n_to.width * 0.5, self.n_to.pos().y())

        obstacles = []
        min_y = min(p_from.y(), p_to.y()) + 10
        max_y = max(p_from.y(), p_to.y()) - 10

        for node in self.graph_view.nodes.values():
            if node == self.n_from or node == self.n_to:
                continue
            nr = QRectF(node.pos().x(), node.pos().y(), node.width, node.height)
            if nr.bottom() > min_y and nr.top() < max_y:
                obstacles.append(nr)

        path = QPainterPath(p_from)

        has_direct_block = False
        track_x = (p_from.x() + p_to.x()) / 2
        for o in obstacles:
            if (o.left() - 25) <= track_x <= (o.right() + 25) or (o.left() - 25) <= p_from.x() <= (o.right() + 25):
                has_direct_block = True
                break

        if has_direct_block and obstacles:
            left_bound = min(o.left() for o in obstacles) - 45
            right_bound = max(o.right() for o in obstacles) + 45
            detour_x = left_bound if abs(p_from.x() - left_bound) < abs(p_from.x() - right_bound) else right_bound

            y_exit = p_from.y() + 35
            y_entry = p_to.y() - 35
            path.lineTo(p_from.x(), y_exit)
            path.lineTo(detour_x, y_exit)
            path.lineTo(detour_x, y_entry)
            path.lineTo(p_to.x(), y_entry)
            path.lineTo(p_to.x(), p_to.y())
            if move_handle:
                self.handle.is_updating = True
                self.handle.setPos(detour_x, (y_exit + y_entry) / 2)
                self.handle.is_updating = False
        else:
            mid_y = p_from.y() + (p_to.y() - p_from.y()) * 0.5 if self.custom_mid_y is None else self.custom_mid_y
            path.lineTo(p_from.x(), mid_y)
            path.lineTo(p_to.x(), mid_y)
            path.lineTo(p_to.x(), p_to.y())
            if move_handle:
                self.handle.is_updating = True
                self.handle.setPos((p_from.x() + p_to.x()) / 2, mid_y)
                self.handle.is_updating = False

        self.path_item.setPath(path)
        arrow = QPolygonF([p_to, p_to + QPointF(-4, -7), p_to + QPointF(4, -7)])
        self.arrow_item.setPolygon(arrow)


class BasicBlockItem(QGraphicsRectItem):
    def __init__(self, addr, instructions, x, y, main_window):
        super().__init__()
        self.addr = addr
        self.instructions = instructions
        self.main_window = main_window
        self.incoming_edges = []
        self.outgoing_edges = []

        self.setPos(x, y)
        self.setFlags(
            QGraphicsItem.GraphicsItemFlag.ItemIsMovable |
            QGraphicsItem.GraphicsItemFlag.ItemIsSelectable |
            QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges
        )

        font = QFont("Consolas", 9)
        self.text_item = QGraphicsTextItem(self)
        self.text_item.setFont(font)

        self.update_content()
        self.setPen(QPen(QColor("#454545"), 1.5))
        self.setZValue(1)

    def get_color(self):
        hex_c = self.main_window.custom_colors.get(self.addr, "#252526")
        return QColor(hex_c)

    def update_content(self, highlight_token=""):
        self.setBrush(QBrush(self.get_color()))
        name = self.main_window.label_for(self.addr)
        user_comment = self.main_window.custom_comments.get(self.addr, "")

        html = f"<div style='font-family: Consolas; font-size: 11px; color: #d4d4d4;'>"
        html += f"<b style='color: #4EC9B0;'>{name}:</b>"
        if user_comment:
            html += f"<span style='color: #6A9955;'> &nbsp;// {user_comment}</span>"
        html += "<hr style='border: 0.5px solid #3c3c3c; margin: 3px 0;'/>"

        instruction_addresses = self.main_window.block_instruction_addresses.get(self.addr, [])
        for index, (mnem, op, comm) in enumerate(self.instructions):
            c_mnem = "#569CD6" if mnem.startswith("j") or mnem in ("call", "ret", "b", "bx", "bl") else "#9CDCFE"
            disp_op = op
            if highlight_token and highlight_token.lower() in op.lower():
                pattern = re.compile(re.escape(highlight_token), re.IGNORECASE)
                disp_op = pattern.sub(f"<span style='background-color:#515c6b; color:#FFE792;'>{highlight_token}</span>", op)

            is_current = index < len(instruction_addresses) and instruction_addresses[index] == self.main_window.current_instruction_va
            row_style = "background-color:#264F78;" if is_current else ""
            html += f"<div style='{row_style}'><span style='color:{c_mnem}; font-weight:bold;'>{mnem:<6}</span> "
            html += f"<span>{disp_op}</span>"
            if comm:
                html += f" &nbsp;<span style='color:#6A9955;'>; {comm}</span>"
            html += "</div>"
        html += "</div>"

        self.text_item.setHtml(html)
        self.text_item.setPos(6, 4)
        rect = self.text_item.boundingRect()
        self.width = max(rect.width() + 22, 280)
        self.height = rect.height() + 8
        self.setRect(0, 0, self.width, self.height)
        patched = False
        if self.main_window.patch_history:
            try:
                base_offset = (self.addr - self.main_window.image_base) if self.main_window.is_elf else self.main_window.pe.get_offset_from_rva(self.addr - self.main_window.image_base)
                # The block model stores display tuples rather than raw
                # instruction objects; a conservative 16-byte/instruction
                # span still gives a useful visual marker without altering
                # the disassembly data model.
                span = max(1, len(self.instructions) * 16)
                patched = any(base_offset <= offset < base_offset + span for offset in self.main_window.patch_history)
            except Exception:
                patched = self.addr in self.main_window.patch_history
        if self.addr in self.main_window.breakpoints:
            border_color, border_width = "#F44747", 2.5
        elif patched:
            border_color, border_width = "#DCDCAA", 2.0
        else:
            border_color, border_width = "#454545", 1.5
        self.setPen(QPen(QColor(border_color), border_width))

    def add_incoming_edge(self, edge):
        self.incoming_edges.append(edge)

    def add_outgoing_edge(self, edge):
        self.outgoing_edges.append(edge)

    def contextMenuEvent(self, event):
        menu = QMenu()
        act_decompile = menu.addAction("View Pseudocode (F5)")
        act_bp = menu.addAction("Toggle Breakpoint (F2)")
        act_cond_bp = menu.addAction("Set Conditional Breakpoint...")
        act_hw_bp = menu.addAction("Toggle Hardware Breakpoint")
        act_rename = menu.addAction("Rename Label (N)")
        act_comment = menu.addAction("Add Comment (;)")
        act_sig = menu.addAction("Generate SigMaker Pattern (Ctrl+B)")
        act_edit = menu.addAction("Edit Instruction (Ctrl+E)")
        act_nop = menu.addAction("NOP Entire Block")
        col_menu = menu.addMenu("Set Color Tag")
        act_c_default = col_menu.addAction("Default Dark")
        act_c_green = col_menu.addAction("Success / True (Green)")
        act_c_red = col_menu.addAction("Failure / Detection (Red)")
        act_c_blue = col_menu.addAction("Info (Blue)")

        action = menu.exec(event.screenPos())
        if action == act_decompile:
            self.main_window.action_decompile_pseudocode()
        elif action == act_bp:
            self.main_window.toggle_breakpoint(self.addr)
        elif action == act_cond_bp:
            self.main_window.set_conditional_breakpoint_at(self.addr)
        elif action == act_hw_bp:
            self.main_window.toggle_hardware_breakpoint_at(self.addr)
        elif action == act_rename:
            self.main_window.action_rename_node()
        elif action == act_comment:
            self.main_window.action_add_comment()
        elif action == act_sig:
            self.main_window.action_generate_signature()
        elif action == act_nop:
            self.main_window.action_patch_nop()
        elif action == act_edit:
            self.main_window.action_edit_instruction(self)
        elif action == act_c_default:
            self.main_window.custom_colors.pop(self.addr, None)
            self.update_content()
        elif action == act_c_green:
            self.main_window.custom_colors[self.addr] = "#1e3a29"
            self.update_content()
        elif action == act_c_red:
            self.main_window.custom_colors[self.addr] = "#3d1f1f"
            self.update_content()
        elif action == act_c_blue:
            self.main_window.custom_colors[self.addr] = "#1e2c3d"
            self.update_content()

    def mouseDoubleClickEvent(self, event):
        for mnem, op, _ in self.instructions:
            for hex_m in re.findall(r"0x[0-9a-fA-F]+", op):
                try:
                    val = int(hex_m, 16)
                    if val in self.main_window.graph_view.nodes:
                        self.main_window.jump_to_address(val)
                        return
                except ValueError:
                    pass
        super().mouseDoubleClickEvent(event)

    def mousePressEvent(self, event):
        cursor = self.text_item.textCursor()
        if cursor.hasSelection():
            txt = cursor.selectedText().strip()
            if txt:
                self.main_window.set_token_highlight(txt)
        super().mousePressEvent(event)

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self.incoming_edges:
                edge.update_path()
            for edge in self.outgoing_edges:
                edge.update_path()
            if hasattr(self.main_window, "overview"):
                self.main_window.overview.update_viewport()
        return super().itemChange(change, value)


class GraphView(QGraphicsView):
    def __init__(self, main_window):
        super().__init__(main_window)
        self.main_window = main_window
        self.scene = QGraphicsScene(self)
        self.scene.setSceneRect(-50000, -50000, 100000, 100000)
        self.setScene(self.scene)

        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setBackgroundBrush(QBrush(QColor("#1e1e1e")))

        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)

        self.nodes = {}
        self.edges = []
        self.is_panning = False
        self.pan_start_pos = None

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.RightButton:
            item = self.itemAt(event.pos())
            if not isinstance(item, BasicBlockItem):
                self.is_panning = True
                self.pan_start_pos = event.pos()
                self.setCursor(Qt.CursorShape.ClosedHandCursor)
                event.accept()
                return
        elif event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        else:
            self.setDragMode(QGraphicsView.DragMode.NoDrag)
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self.is_panning and self.pan_start_pos is not None:
            delta = event.pos() - self.pan_start_pos
            self.pan_start_pos = event.pos()
            self.horizontalScrollBar().setValue(self.horizontalScrollBar().value() - delta.x())
            self.verticalScrollBar().setValue(self.verticalScrollBar().value() - delta.y())
            event.accept()
            if hasattr(self.main_window, "overview"):
                self.main_window.overview.update_viewport()
            return
        super().mouseMoveEvent(event)
        if hasattr(self.main_window, "overview"):
            self.main_window.overview.update_viewport()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.RightButton and self.is_panning:
            self.is_panning = False
            self.setCursor(Qt.CursorShape.ArrowCursor)
            event.accept()
            if hasattr(self.main_window, "overview"):
                self.main_window.overview.update_viewport()
            return
        elif event.button() == Qt.MouseButton.MiddleButton:
            self.setDragMode(QGraphicsView.DragMode.NoDrag)
        super().mouseReleaseEvent(event)
        if hasattr(self.main_window, "overview"):
            self.main_window.overview.update_viewport()

    def wheelEvent(self, event):
        zoom_factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(zoom_factor, zoom_factor)
        if hasattr(self.main_window, "overview"):
            self.main_window.overview.update_viewport()

    def scrollContentsBy(self, dx, dy):
        super().scrollContentsBy(dx, dy)
        if hasattr(self.main_window, "overview"):
            self.main_window.overview.update_viewport()

    def clear_graph(self):
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()

    def add_node(self, addr, instructions, x, y):
        node = BasicBlockItem(addr, instructions, x, y, self.main_window)
        self.scene.addItem(node)
        self.nodes[addr] = node
        return node

    def add_edge(self, from_addr, to_addr, color_hex, edge_type="uncond"):
        if from_addr not in self.nodes or to_addr not in self.nodes:
            return
        edge = EdgeItem(self.scene, self, self.nodes[from_addr], self.nodes[to_addr], color_hex, edge_type)
        self.edges.append(edge)


class GraphOverview(QGraphicsView):
    def __init__(self, main_view, parent=None):
        super().__init__(parent)
        self.main_view = main_view
        self.mini_scene = QGraphicsScene(self)
        self.setScene(self.mini_scene)
        self.setFixedSize(180, 140)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setStyleSheet("background: #181818; border: 1px solid #3c3c3c; border-radius: 4px;")
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.in_update = False

        self.cam_rect_item = QGraphicsRectItem()
        self.cam_rect_item.setPen(QPen(QColor("#007acc"), 2))
        self.cam_rect_item.setBrush(QBrush(QColor(0, 122, 204, 40)))
        self.cam_rect_item.setZValue(1000)
        self.mini_scene.addItem(self.cam_rect_item)

    def update_viewport(self):
        if self.in_update or not self.main_view:
            return
        self.in_update = True
        try:
            for item in list(self.mini_scene.items()):
                if item != self.cam_rect_item:
                    self.mini_scene.removeItem(item)

            for n in self.main_view.nodes.values():
                r = self.mini_scene.addRect(n.pos().x(), n.pos().y(), n.width, n.height)
                r.setPen(QPen(QColor("#555555"), 1))
                r.setBrush(QBrush(QColor("#2e2e2e")))

            items_rect = self.mini_scene.itemsBoundingRect()
            if items_rect.isValid() and items_rect.width() > 10 and items_rect.height() > 10:
                self.fitInView(items_rect, Qt.AspectRatioMode.KeepAspectRatio)

            vis_poly = self.main_view.mapToScene(self.main_view.viewport().rect())
            self.cam_rect_item.setRect(vis_poly.boundingRect())
        except Exception:
            pass
        finally:
            self.in_update = False

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        if event.button() == Qt.MouseButton.LeftButton:
            scene_pos = self.mapToScene(event.pos())
            self.main_view.centerOn(scene_pos)
            self.update_viewport()

    def mouseMoveEvent(self, event):
        super().mouseMoveEvent(event)
        scene_pos = self.mapToScene(event.pos())
        self.main_view.centerOn(scene_pos)
        self.update_viewport()


class FlatDisasmWidget(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.editor = QPlainTextEdit()
        self.editor.setReadOnly(True)
        self.editor.setFont(QFont("Consolas", 10))
        self.editor.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3c3c3c;
                selection-background-color: #264f78;
            }
        """)
        self.editor.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: none;
                font-family: Consolas, monospace;
            }
        """)
        layout.addWidget(self.editor)

    def populate(self, blocks):
        lines = []
        for addr in sorted(blocks.keys()):
            name = self.main_window.label_for(addr)
            comm = self.main_window.custom_comments.get(addr, "")
            lines.append(f"; ---------------------------------------------------------------------------")
            lines.append(f"{name}:" + (f"  ; {comm}" if comm else ""))
            for mnem, op, c in blocks[addr]:
                comm_str = f" ; {c}" if c else ""
                lines.append(f"    {mnem:<8} {op:<30}{comm_str}")
            lines.append("")
        self.editor.setPlainText("\n".join(lines))


class PseudocodeWidget(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.editor = QPlainTextEdit()
        self.editor.setReadOnly(True)
        self.editor.setFont(QFont("Consolas", 10))
        self.editor.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: none;
                font-family: Consolas, monospace;
            }
        """)
        layout.addWidget(self.editor)

    def decompile(self, blocks, start_va):
        if not blocks:
            self.editor.setPlainText("// No active function to decompile.")
            return

        func_name = self.main_window.label_for(start_va, "sub")
        lines = []
        lines.append(f"// ==========================================================================")
        lines.append(f"// Decompiled by Gandon-PRO Pseudocode Engine")
        lines.append(f"// Function Entry: 0x{start_va:08X} - {func_name}")
        lines.append(f"// ==========================================================================\n")
        lines.append(f"__int64 __fastcall {func_name}(__int64 a1, __int64 a2, __int64 a3, __int64 a4)")
        lines.append("{")
        lines.append("    __int64 result = 0;")
        lines.append("    __int64 v0, v1, v2, v3;")
        lines.append("    // control-flow and stack effects are reconstructed from the available machine code")
        lines.append("")

        cond_map = {
            "je": "==", "jz": "==", "jne": "!=", "jnz": "!=",
            "jg": ">", "jge": ">=", "jl": "<", "jle": "<=",
            "ja": ">", "jae": ">=", "jb": "<", "jbe": "<="
        }
        last_cmp = ("v0", "0", "==")
        stack_depth = 0

        for addr in sorted(blocks.keys()):
            b_name = self.main_window.label_for(addr)
            comm = self.main_window.custom_comments.get(addr, "")
            lines.append(f" {b_name}:" + (f" // {comm}" if comm else ""))

            for mnem, op, c in blocks[addr]:
                parts = [p.strip() for p in op.split(",")] if op else []

                if mnem == "push":
                    stack_depth += 1
                    lines.append(f"    /* push {parts[0] if parts else 'value'} */")

                elif mnem == "pop":
                    stack_depth = max(0, stack_depth - 1)
                    lines.append(f"    /* pop {parts[0] if parts else 'value'} */")

                elif mnem in ("mov", "movsxd", "movzx", "movsx"):
                    if len(parts) == 2:
                        dst = parts[0].replace("dword ptr ", "").replace("qword ptr ", "")
                        src = parts[1]
                        lines.append(f"    {dst} = {src};" + (f" // {c}" if c else ""))

                elif mnem == "lea":
                    if len(parts) == 2:
                        dst = parts[0]
                        src = parts[1].replace("[", "&(").replace("]", ")")
                        lines.append(f"    {dst} = {src};" + (f" // {c}" if c else ""))

                elif mnem in ("add", "sub", "xor", "and", "or", "shl", "shr"):
                    op_sym = {"add": "+=", "sub": "-=", "xor": "^=", "and": "&=", "or": "|=", "shl": "<<=", "shr": ">>="}[mnem]
                    if len(parts) == 2:
                        lines.append(f"    {parts[0]} {op_sym} {parts[1]};")

                elif mnem in ("cmp", "test"):
                    if len(parts) == 2:
                        last_cmp = (parts[0], parts[1], "==" if mnem == "test" else "==")

                elif mnem.startswith("j") and mnem != "jmp":
                    cond_op = cond_map.get(mnem, "!=")
                    target = parts[0] if parts else "loc_???"
                    try:
                        t_val = int(target, 16)
                        t_lbl = self.main_window.label_for(t_val)
                    except ValueError:
                        t_lbl = target
                    lines.append(f"    if ({last_cmp[0]} {cond_op} {last_cmp[1]})")
                    lines.append(f"        goto {t_lbl};")

                elif mnem == "jmp":
                    target = parts[0] if parts else "loc_???"
                    try:
                        t_val = int(target, 16)
                        t_lbl = self.main_window.label_for(t_val)
                    except ValueError:
                        t_lbl = target
                    lines.append(f"    goto {t_lbl};")

                elif mnem == "call":
                    target = parts[0] if parts else "sub_???"
                    call_label = f"/* {c} */" if c else ""
                    lines.append(f"    result = ((__int64 (*)(...)){target})({call_label});")

                elif mnem in ("ret", "bx lr"):
                    if stack_depth:
                        lines.append(f"    /* restore stack depth ({stack_depth}) */")
                    lines.append("    return result;")

                elif mnem in ("nop", "int3"):
                    lines.append(f"    /* {mnem} */")

                else:
                    # Preserve instructions that the small native backend
                    # cannot safely translate instead of silently dropping
                    # them from the decompiler output.
                    rendered = f"{mnem} {op}".strip()
                    lines.append(f"    /* {rendered} */" + (f" // {c}" if c else ""))

            lines.append("")

        lines.append("    return result;")
        lines.append("}")
        self.editor.setPlainText("\n".join(lines))


class HexViewWidget(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.raw_data = b""
        self.image_base = 0
        self.target_va = 0
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Address:"))
        self.address_edit = QLineEdit()
        self.address_edit.setPlaceholderText("0x140001000")
        self.address_edit.returnPressed.connect(self.go_to_address)
        controls.addWidget(self.address_edit, stretch=1)
        go_button = QPushButton("Go")
        go_button.clicked.connect(self.go_to_address)
        controls.addWidget(go_button)
        layout.addLayout(controls)

        self.editor = QPlainTextEdit()
        self.editor.setReadOnly(True)
        self.editor.setFont(QFont("Consolas", 10))
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.editor.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #4EC9B0;
                border: none;
                font-family: Consolas, monospace;
            }
        """)
        layout.addWidget(self.editor)

    def load_hex(self, raw_data, image_base, target_va, num_lines=512):
        if not raw_data:
            return
        self.raw_data = raw_data
        self.image_base = image_base
        self.target_va = target_va
        self.address_edit.setText(f"0x{target_va:X}")
        offset = max(0, min(len(raw_data), target_va - image_base))
        data = raw_data[offset: offset + num_lines * 16]
        lines = []
        for idx in range(0, len(data), 16):
            chunk = data[idx: idx + 16]
            curr_va = target_va + idx
            p1 = " ".join([f"{b:02X}" for b in chunk[:8]]).ljust(23)
            p2 = " ".join([f"{b:02X}" for b in chunk[8:]]).ljust(23)
            ascii_str = "".join([chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk])
            lines.append(f"{curr_va:016X}  {p1}  {p2}  {ascii_str}")
        self.editor.setPlainText("\n".join(lines))

    def go_to_address(self):
        text = self.address_edit.text().strip()
        try:
            value = int(text, 16) if text.lower().startswith("0x") else int(text, 16)
        except ValueError:
            self.main_window.status_bar.showMessage("Invalid hex address.")
            return
        self.load_hex(self.raw_data, self.image_base, value)
        self.main_window.status_bar.showMessage(f"Hex view: 0x{value:X}")


class StringsWidget(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.raw_strings = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Filter strings...")
        self.search_bar.textChanged.connect(self.filter_strings)
        layout.addWidget(self.search_bar)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Address", "Length", "Type", "String"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setFont(QFont("Consolas", 10))
        self.table.itemDoubleClicked.connect(self.on_double_click)
        layout.addWidget(self.table)

    def extract_strings(self, raw_data, image_base, min_len=4):
        self.raw_strings.clear()
        if not raw_data:
            return
        ascii_regex = re.compile(rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}")
        for match in ascii_regex.finditer(raw_data):
            va = image_base + match.start()
            text = match.group().decode("ascii", errors="ignore")
            self.raw_strings.append((va, len(text), "ASCII", text))
        self.populate_table(self.raw_strings)

    def populate_table(self, items):
        self.table.setRowCount(0)
        for row, (va, l, t, s) in enumerate(items):
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(f"0x{va:08X}"))
            self.table.setItem(row, 1, QTableWidgetItem(str(l)))
            self.table.setItem(row, 2, QTableWidgetItem(t))
            self.table.setItem(row, 3, QTableWidgetItem(s))

    def filter_strings(self, query):
        q = query.lower()
        self.populate_table([s for s in self.raw_strings if q in s[3].lower()])

    def on_double_click(self, item):
        row = item.row()
        addr_str = self.table.item(row, 0).text()
        self.main_window.switch_to_gandon_view(int(addr_str, 16))


class ResourcesWidget(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Resource", "Language", "RVA", "Size"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.setFont(QFont("Consolas", 9))
        layout.addWidget(self.tree)

    def load_resources(self, pe):
        self.tree.clear()
        if not pe or not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return

        def label(entry):
            if entry.name is not None:
                return str(entry.name)
            return str(entry.id)

        def walk(entries, parent):
            for entry in entries:
                item = QTreeWidgetItem([label(entry), "", "", ""])
                parent.addChild(item)
                if hasattr(entry, "directory"):
                    walk(entry.directory.entries, item)
                elif hasattr(entry, "data"):
                    try:
                        data = entry.data.struct
                        item.setText(1, str(getattr(entry, "id", "")))
                        item.setText(2, f"0x{data.OffsetToData:X}")
                        item.setText(3, str(data.Size))
                    except Exception:
                        item.setText(3, "unavailable")

        root = QTreeWidgetItem(["PE Resources", "", "", ""])
        self.tree.addTopLevelItem(root)
        walk(pe.DIRECTORY_ENTRY_RESOURCE.entries, root)
        root.setExpanded(True)


class SymbolsWidget(QWidget):
    """Unified exports/imports and native debug-symbol metadata view."""
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.info = QLabel("No symbols loaded.")
        layout.addWidget(self.info)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Source", "Name", "Address", "Details"])
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setFont(QFont("Consolas", 9))
        self.table.cellDoubleClicked.connect(self.jump_to_symbol)
        layout.addWidget(self.table)

    def clear(self):
        self.table.setRowCount(0)
        self.info.setText("No symbols loaded.")

    def add(self, source, name, address="", details=""):
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, value in enumerate((source, name, address, details)):
            self.table.setItem(row, col, QTableWidgetItem(str(value)))

    def jump_to_symbol(self, row, _column):
        item = self.table.item(row, 2)
        if item and item.text().startswith("0x"):
            try:
                self.main_window.jump_to_address(int(item.text(), 16))
            except ValueError:
                pass

    def load_pe(self, pe, image_base):
        self.clear()
        if not pe:
            return
        count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode(errors="ignore") if exp.name else f"ordinal_{exp.ordinal}"
                self.add("PE export", name, f"0x{image_base + exp.address:X}", f"ordinal {exp.ordinal}")
                count += 1
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore")
                for imp in entry.imports:
                    name = imp.name.decode(errors="ignore") if imp.name else f"ordinal_{imp.ordinal}"
                    address = f"0x{imp.address:X}" if imp.address else ""
                    self.add("PE import", name, address, dll)
                    count += 1
        pdb_paths = []
        for debug in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            entry = getattr(debug, "entry", debug)
            raw_name = getattr(entry, "PdbFileName", b"")
            if isinstance(raw_name, bytes):
                raw_name = raw_name.split(b"\x00", 1)[0].decode(errors="ignore")
            if raw_name:
                pdb_paths.append(str(raw_name))
        for pdb_path in dict.fromkeys(pdb_paths):
            self.add("CodeView/PDB", os.path.basename(pdb_path), "", pdb_path)
        note = f"{count} PE symbols"
        if pdb_paths:
            note += f" | PDB metadata: {len(pdb_paths)}"
        self.info.setText(note + ". Double-click an address to jump.")

    def load_elf(self, raw_data, image_base):
        self.clear()
        if not raw_data:
            return
        debug_sections = []
        try:
            from elftools.elf.elffile import ELFFile
            import io
            elf = ELFFile(io.BytesIO(bytes(raw_data)))
            for section in elf.iter_sections():
                name = section.name or ""
                if name in (".symtab", ".dynsym"):
                    for symbol in section.iter_symbols():
                        if not symbol.name:
                            continue
                        address = int(symbol.entry["st_value"])
                        self.add("ELF symbol", symbol.name, f"0x{address:X}", name)
                elif name.startswith(".debug_"):
                    debug_sections.append(name)
            self.info.setText(
                f"ELF symbols loaded; DWARF sections: {', '.join(debug_sections) or 'none'}."
            )
        except ImportError:
            self.info.setText("ELF symbols require optional package: pyelftools.")
        except Exception as exc:
            self.info.setText(f"ELF symbol parsing error: {exc}")


class MemoryMapWidget(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        controls = QHBoxLayout()
        refresh_process = QPushButton("Refresh Process Regions")
        refresh_process.clicked.connect(self.load_process)
        controls.addWidget(refresh_process)
        controls.addStretch()
        layout.addLayout(controls)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Name", "Base", "End", "Size", "RVA / State", "Permissions"])
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.setFont(QFont("Consolas", 9))
        layout.addWidget(self.table)

    def load_binary(self, pe, image_base):
        self.table.setRowCount(0)
        if not pe:
            return
        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip("\x00")
            base = image_base + section.VirtualAddress
            size = max(section.Misc_VirtualSize, section.SizeOfRawData)
            end = base + size
            chars = section.Characteristics
            perms = ("R" if chars & 0x40000000 else "-") + ("W" if chars & 0x80000000 else "-") + ("X" if chars & 0x20000000 else "-")
            row = self.table.rowCount(); self.table.insertRow(row)
            values = [name, f"0x{base:X}", f"0x{end:X}", f"0x{size:X}", f"0x{section.VirtualAddress:X}", perms]
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(value))

    def load_process(self):
        self.table.setRowCount(0)
        regions = self.main_window.dbg.enumerate_memory_regions()
        for region in regions:
            row = self.table.rowCount(); self.table.insertRow(row)
            values = [region["name"], f"0x{region['base']:X}", f"0x{region['end']:X}",
                      f"0x{region['size']:X}", region["state"], region["protection"]]
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(str(value)))
        self.main_window.status_bar.showMessage(f"Process regions: {len(regions)}")

    def clear(self):
        self.table.setRowCount(0)


class ProblemsEventsWidget(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        controls = QHBoxLayout()
        clear = QPushButton("Clear")
        clear.clicked.connect(self.clear)
        controls.addWidget(clear); controls.addStretch()
        layout.addLayout(controls)
        self.editor = QPlainTextEdit()
        self.editor.setReadOnly(True)
        self.editor.setFont(QFont("Consolas", 9))
        layout.addWidget(self.editor)

    def append(self, message):
        self.editor.appendPlainText(str(message))

    def clear(self):
        self.editor.clear()


class BreakpointManagerDialog(QDialog):
    def __init__(self, main_window, parent=None):
        super().__init__(parent or main_window)
        self.main_window = main_window
        apply_windows_dark_titlebar(self)
        self.setWindowTitle("Breakpoint Manager")
        self.resize(720, 420)
        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Address", "Kind", "Hits", "Condition", "Mode"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.table)
        buttons = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        buttons.addWidget(refresh)
        configure = QPushButton("Configure")
        configure.clicked.connect(self.configure)
        buttons.addWidget(configure)
        remove = QPushButton("Remove")
        remove.clicked.connect(self.remove)
        buttons.addWidget(remove)
        buttons.addStretch()
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        buttons.addWidget(close)
        layout.addLayout(buttons)
        self.refresh()

    def refresh(self):
        self.table.setRowCount(0)
        entries = [(va, "Software INT3") for va in sorted(self.main_window.breakpoints)]
        entries += [(va, "Hardware execute") for va, _ in sorted(self.main_window.dbg.requested_hardware_breakpoints)]
        for va, kind in entries:
            row = self.table.rowCount(); self.table.insertRow(row)
            hits = self.main_window.breakpoint_hits.get(va, 0)
            limit = self.main_window.breakpoint_hit_limits.get(va, 0)
            condition = self.main_window.dbg.breakpoint_conditions.get(va, "")
            mode = "Log only" if va in self.main_window.breakpoint_log_only else "Stop"
            values = [f"0x{va:X}", kind, f"{hits}/{limit or '∞'}", condition, mode]
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(value))

    def selected_address(self):
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        try:
            return int(item.text(), 16) if item else None
        except ValueError:
            return None

    def configure(self):
        va = self.selected_address()
        if va:
            self.main_window.current_va = va
            self.main_window.configure_breakpoint()
            self.refresh()

    def remove(self):
        va = self.selected_address()
        if va:
            self.main_window.remove_breakpoint_at(va)
            self.refresh()


class PythonConsoleDialog(QDialog):
    def __init__(self, main_window, parent=None):
        super().__init__(parent or main_window)
        self.main_window = main_window
        apply_windows_dark_titlebar(self)
        self.setWindowTitle("Python Console")
        self.resize(780, 520)
        layout = QVBoxLayout(self)
        self.output = QPlainTextEdit(); self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 9)); layout.addWidget(self.output)
        row = QHBoxLayout()
        self.input = QLineEdit(); self.input.setPlaceholderText("self.current_va, api.read_file_bytes(0, 16)")
        self.input.returnPressed.connect(self.execute)
        row.addWidget(self.input, 1)
        run = QPushButton("Run"); run.clicked.connect(self.execute); row.addWidget(run)
        layout.addLayout(row)
        self.namespace = {"app": main_window, "self": main_window, "api": PluginAPI(main_window)}
        self.load_action_history()

    def load_action_history(self):
        self.output.clear()
        for line in self.main_window.action_history:
            self.output.appendPlainText(line)

    def append_action(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"# [{timestamp}] {message}"
        self.main_window.action_history.append(line)
        self.main_window.action_history = self.main_window.action_history[-2000:]
        self.output.appendPlainText(line)

    def execute(self):
        source = self.input.text().strip()
        if not source:
            return
        try:
            try:
                result = eval(source, {"__builtins__": {}}, self.namespace)
            except SyntaxError:
                exec(source, {"__builtins__": {}}, self.namespace)
                result = None
            line = f">>> {source}\n{result!r}" if result is not None else f">>> {source}\nOK"
            self.output.appendPlainText(line)
            self.main_window.action_history.append(line)
        except Exception as exc:
            line = f">>> {source}\nERROR: {exc}"
            self.output.appendPlainText(line)
            self.main_window.action_history.append(line)
        self.main_window.action_history = self.main_window.action_history[-2000:]
        self.input.clear()


class LocalTypesWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.types_definitions = {
            "_GUID": "struct _GUID { unsigned int Data1; unsigned short Data2; unsigned short Data3; unsigned char Data4[8]; };",
            "RUNTIME_FUNCTION": "struct RUNTIME_FUNCTION {\n    void *__ptr32 FunctionStart;\n    void *__ptr32 FunctionEnd;\n    void *__ptr32 UnwindInfo;\n};",
            "IMAGE_DOS_HEADER": "struct IMAGE_DOS_HEADER {\n    WORD e_magic;\n    WORD e_lfanew;\n};",
            "IMAGE_NT_HEADERS64": "struct IMAGE_NT_HEADERS64 {\n    DWORD Signature;\n    IMAGE_FILE_HEADER FileHeader;\n    IMAGE_OPTIONAL_HEADER64 OptionalHeader;\n};"
        }
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Type Name"])
        for k in self.types_definitions:
            self.tree.addTopLevelItem(QTreeWidgetItem([k]))
        self.editor = QPlainTextEdit()
        self.editor.setReadOnly(True)
        self.editor.setFont(QFont("Consolas", 10))
        self.editor.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3c3c3c;
                selection-background-color: #264f78;
            }
        """)
        self.tree.itemClicked.connect(lambda it, c: self.editor.setPlainText(self.types_definitions.get(it.text(0), "")))
        add_type = QPushButton("Add Type")
        add_type.clicked.connect(self.add_type)
        splitter.addWidget(self.tree)
        editor_panel = QWidget()
        editor_layout = QVBoxLayout(editor_panel)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        editor_layout.addWidget(self.editor)
        editor_layout.addWidget(add_type)
        splitter.addWidget(editor_panel)
        layout.addWidget(splitter)

    def add_type(self):
        name, ok = QInputDialog.getText(self, "Add Type", "Type name:")
        if not ok or not name.strip():
            return
        definition, ok = QInputDialog.getMultiLineText(
            self, "Add Type", "C/C++ definition:", "struct Example {\n    int value;\n};"
        )
        if not ok or not definition.strip():
            return
        name = name.strip()
        self.types_definitions[name] = definition.strip()
        item = QTreeWidgetItem([name])
        self.tree.addTopLevelItem(item)
        self.tree.setCurrentItem(item)
        self.editor.setPlainText(definition.strip())

    def set_definitions(self, definitions):
        self.types_definitions = dict(definitions)
        self.tree.clear()
        for name in self.types_definitions:
            self.tree.addTopLevelItem(QTreeWidgetItem([name]))


class ImportsWidget(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Address", "Module (DLL)", "Function Name"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setFont(QFont("Consolas", 10))
        layout.addWidget(self.table)

    def load_imports(self, pe):
        self.table.setRowCount(0)
        if not pe or not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return
        row = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="ignore")
            for imp in entry.imports:
                addr = f"0x{imp.address:08X}" if imp.address else "N/A"
                name = imp.name.decode(errors="ignore") if imp.name else f"Ordinal({imp.ordinal})"
                if (dll.casefold(), name.casefold()) in self.main_window.hidden_imports:
                    continue
                self.table.insertRow(row)
                self.table.setItem(row, 0, QTableWidgetItem(addr))
                self.table.setItem(row, 1, QTableWidgetItem(dll))
                self.table.setItem(row, 2, QTableWidgetItem(name))
                row += 1


class ExportsWidget(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Target Address", "Ordinal", "Function Name"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setFont(QFont("Consolas", 10))
        layout.addWidget(self.table)

    def load_exports(self, pe, image_base):
        self.table.setRowCount(0)
        if not pe:
            return
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for row, exp in enumerate(pe.DIRECTORY_ENTRY_EXPORT.symbols):
                self.table.insertRow(row)
                addr = f"0x{image_base + exp.address:08X}"
                name = exp.name.decode(errors="ignore") if exp.name else "N/A"
                self.table.setItem(row, 0, QTableWidgetItem(addr))
                self.table.setItem(row, 1, QTableWidgetItem(str(exp.ordinal)))
                self.table.setItem(row, 2, QTableWidgetItem(name))


class MemoryViewDialog(QDialog):
    def __init__(self, main_window, address=0, parent=None):
        super().__init__(parent or main_window)
        self.main_window = main_window
        apply_windows_dark_titlebar(self)
        self.setWindowTitle("Memory View")
        self.resize(760, 520)
        self.setStyleSheet("""
            QDialog { background-color: #1e1e1e; color: #d4d4d4; }
            QLabel { color: #d4d4d4; }
            QLineEdit {
                background-color: #252526; color: #d4d4d4;
                border: 1px solid #3c3c3c; padding: 5px;
                selection-background-color: #264f78;
            }
            QPushButton {
                background-color: #2d2d2d; color: #d4d4d4;
                border: 1px solid #505050; padding: 5px 12px;
            }
            QPushButton:hover { background-color: #3e3e3e; }
            QPlainTextEdit {
                background-color: #1e1e1e; color: #4EC9B0;
                border: 1px solid #3c3c3c;
                font-family: Consolas, monospace;
            }
        """)
        layout = QVBoxLayout(self)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Address:"))
        self.address_edit = QLineEdit(f"0x{address:X}" if address else "")
        self.address_edit.setPlaceholderText("0x7FF...")
        controls.addWidget(self.address_edit, stretch=1)
        controls.addWidget(QLabel("Bytes:"))
        self.size_edit = QLineEdit("256")
        self.size_edit.setMaximumWidth(80)
        controls.addWidget(self.size_edit)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        controls.addWidget(refresh)
        snapshot = QPushButton("Snapshot")
        snapshot.clicked.connect(self.take_snapshot)
        controls.addWidget(snapshot)
        compare = QPushButton("Compare")
        compare.clicked.connect(self.compare_snapshot)
        controls.addWidget(compare)
        layout.addLayout(controls)

        self.editor = QPlainTextEdit()
        self.editor.setReadOnly(True)
        self.editor.setFont(QFont("Consolas", 10))
        layout.addWidget(self.editor)
        self.last_snapshot = None
        self.last_data = b""
        if address:
            self.refresh()

    def refresh(self):
        try:
            text = self.address_edit.text().strip()
            address = int(text, 16) if text.lower().startswith("0x") else int(text, 16)
            size = max(1, min(int(self.size_edit.text()), 0x10000))
        except ValueError:
            self.editor.setPlainText("Invalid address or byte count.")
            return
        runtime_address = self.main_window.resolve_runtime_address(address)
        data = self.main_window.dbg.read_memory(runtime_address, size)
        self.last_data = bytes(data or b"")
        if not data:
            self.editor.setPlainText(
                "No bytes read. Start the debuggee and pause it first.\n"
                f"Requested: 0x{address:X} | Runtime: 0x{runtime_address:X}"
            )
            return
        lines = []
        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk).ljust(47)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{runtime_address + offset:016X}  {hex_part}  {ascii_part}")
        self.editor.setPlainText("\n".join(lines))

    def take_snapshot(self):
        if self.last_data:
            self.last_snapshot = self.last_data
            self.editor.appendPlainText(f"\n[Snapshot saved: {len(self.last_snapshot)} bytes]")

    def compare_snapshot(self):
        if not self.last_snapshot:
            self.editor.appendPlainText("\n[No snapshot. Click Snapshot first.]")
            return
        self.refresh()
        changed = [i for i, (a, b) in enumerate(zip(self.last_snapshot, self.last_data)) if a != b]
        if len(self.last_data) != len(self.last_snapshot):
            changed.extend(range(min(len(self.last_data), len(self.last_snapshot)), max(len(self.last_data), len(self.last_snapshot))))
        if not changed:
            self.editor.appendPlainText("\n[Compare: no changes]")
        else:
            preview = ", ".join(f"+0x{i:X}" for i in changed[:128])
            self.editor.appendPlainText(f"\n[Compare: {len(changed)} changed byte(s): {preview}]")

    def set_address(self, address):
        if address:
            self.address_edit.setText(f"0x{int(address):X}")


class WatchDialog(QDialog):
    def __init__(self, main_window, parent=None):
        super().__init__(parent or main_window)
        self.main_window = main_window
        self.watches = []
        apply_windows_dark_titlebar(self)
        self.setWindowTitle("Watch / Locals")
        self.resize(700, 520)
        self.setStyleSheet("""
            QDialog { background-color: #1e1e1e; color: #d4d4d4; }
            QLabel { color: #d4d4d4; }
            QLineEdit {
                background-color: #252526; color: #d4d4d4;
                border: 1px solid #3c3c3c; padding: 5px;
                selection-background-color: #264f78;
            }
            QPushButton {
                background-color: #2d2d2d; color: #d4d4d4;
                border: 1px solid #505050; padding: 5px 12px;
            }
            QPushButton:hover { background-color: #3e3e3e; }
            QTableWidget {
                background-color: #1e1e1e; color: #d4d4d4;
                gridline-color: #3c3c3c; border: 1px solid #3c3c3c;
                selection-background-color: #264f78;
            }
            QHeaderView::section {
                background-color: #2d2d2d; color: #9CDCFE;
                border: 1px solid #3c3c3c; padding: 5px;
            }
        """)
        layout = QVBoxLayout(self)

        controls = QHBoxLayout()
        self.address_edit = QLineEdit()
        self.address_edit.setPlaceholderText("Address, e.g. 0x7FF000001000")
        controls.addWidget(self.address_edit, stretch=1)
        add = QPushButton("Add Watch")
        add.clicked.connect(self.add_watch)
        controls.addWidget(add)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        controls.addWidget(refresh)
        layout.addLayout(controls)

        layout.addWidget(QLabel("Registers / Locals"))
        self.reg_table = QTableWidget(0, 2)
        self.reg_table.setHorizontalHeaderLabels(["Name", "Value"])
        self.reg_table.verticalHeader().setVisible(False)
        self.reg_table.horizontalHeader().setStretchLastSection(True)
        self.reg_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.reg_table)

        layout.addWidget(QLabel("Watched memory (8 bytes)"))
        self.watch_table = QTableWidget(0, 3)
        self.watch_table.setHorizontalHeaderLabels(["Address", "Value (hex)", "Status"])
        self.watch_table.verticalHeader().setVisible(False)
        self.watch_table.setColumnWidth(0, 190)
        self.watch_table.setColumnWidth(2, 120)
        self.watch_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.watch_table)

    def add_watch(self):
        text = self.address_edit.text().strip()
        try:
            address = int(text, 16) if text.lower().startswith("0x") else int(text, 16)
        except ValueError:
            return
        if address not in self.watches:
            self.watches.append(address)
        self.address_edit.clear()
        self.refresh()

    def update_registers(self, registers):
        self.reg_table.setRowCount(len(registers))
        for row, (name, value) in enumerate(registers.items()):
            self.reg_table.setItem(row, 0, QTableWidgetItem(name))
            self.reg_table.setItem(row, 1, QTableWidgetItem(value))

    def refresh(self):
        self.watch_table.setRowCount(len(self.watches))
        for row, address in enumerate(self.watches):
            runtime_address = self.main_window.resolve_runtime_address(address)
            data = self.main_window.dbg.read_memory(runtime_address, 8)
            self.watch_table.setItem(row, 0, QTableWidgetItem(f"0x{address:016X}"))
            self.watch_table.setItem(row, 1, QTableWidgetItem(data.hex(" ") if data else "—"))
            self.watch_table.setItem(row, 2, QTableWidgetItem("OK" if data else "unavailable"))


class ThreadStackDialog(QDialog):
    def __init__(self, main_window, parent=None):
        super().__init__(parent or main_window)
        self.main_window = main_window
        apply_windows_dark_titlebar(self)
        self.setWindowTitle("Threads / Call Stack")
        self.resize(760, 520)
        self.setStyleSheet("""
            QDialog { background-color: #1e1e1e; color: #d4d4d4; }
            QLabel { color: #d4d4d4; }
            QTableWidget {
                background-color: #252526; color: #d4d4d4;
                gridline-color: #3c3c3c; border: 1px solid #3c3c3c;
                selection-background-color: #264f78;
            }
            QHeaderView::section {
                background-color: #2d2d2d; color: #9CDCFE;
                border: 1px solid #3c3c3c; padding: 5px;
            }
            QPushButton {
                background-color: #2d2d2d; color: #d4d4d4;
                border: 1px solid #505050; padding: 5px 12px;
            }
        """)
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        top.addWidget(QLabel("Threads"))
        top.addStretch()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        top.addWidget(refresh)
        layout.addLayout(top)

        self.threads = QTableWidget(0, 2)
        self.threads.setHorizontalHeaderLabels(["Thread ID", "State"])
        self.threads.verticalHeader().setVisible(False)
        self.threads.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.threads)

        layout.addWidget(QLabel("Current thread stack (raw 8-byte words)"))
        self.stack = QTableWidget(0, 3)
        self.stack.setHorizontalHeaderLabels(["Stack Address", "Value", "Symbol / Note"])
        self.stack.verticalHeader().setVisible(False)
        self.stack.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.stack)
        layout.addWidget(QLabel("Call stack (frame-pointer unwind)"))
        self.call_stack = QTableWidget(0, 3)
        self.call_stack.setHorizontalHeaderLabels(["Frame", "Frame pointer", "Return address"])
        self.call_stack.verticalHeader().setVisible(False)
        self.call_stack.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.call_stack)
        self.refresh()

    def refresh(self):
        rows = self.main_window.dbg.thread_rows()
        self.threads.setRowCount(len(rows))
        for row, (tid, state) in enumerate(rows):
            self.threads.setItem(row, 0, QTableWidgetItem(str(tid)))
            self.threads.setItem(row, 1, QTableWidgetItem(state))

        stack_rows = self.main_window.dbg.stack_rows()
        self.stack.setRowCount(len(stack_rows))
        for row, (address, value) in enumerate(stack_rows):
            self.stack.setItem(row, 0, QTableWidgetItem(f"0x{address:016X}"))
            self.stack.setItem(row, 1, QTableWidgetItem(f"0x{value:016X}"))
            label = self.main_window.label_for(value) if value in self.main_window.functions else ""
            self.stack.setItem(row, 2, QTableWidgetItem(label))
        frames = self.main_window.dbg.frame_rows()
        self.call_stack.setRowCount(len(frames))
        for row, (index, frame, ret) in enumerate(frames):
            self.call_stack.setItem(row, 0, QTableWidgetItem(str(index)))
            self.call_stack.setItem(row, 1, QTableWidgetItem(f"0x{frame:016X}"))
            label = self.main_window.label_for(ret) if ret in self.main_window.functions else ""
            text = f"0x{ret:016X}" + (f"  {label}" if label else "")
            self.call_stack.setItem(row, 2, QTableWidgetItem(text))


class BinaryDiffDialog(QDialog):
    def __init__(self, main_window, parent=None):
        super().__init__(parent or main_window)
        self.main_window = main_window
        apply_windows_dark_titlebar(self)
        self.setWindowTitle("Binary Diff")
        self.resize(820, 560)
        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Select a second PE/ELF file")
        controls.addWidget(self.path_edit, stretch=1)
        browse = QPushButton("Browse")
        browse.clicked.connect(self.browse)
        controls.addWidget(browse)
        compare = QPushButton("Compare")
        compare.clicked.connect(self.compare)
        controls.addWidget(compare)
        layout.addLayout(controls)
        self.summary = QLabel("No comparison performed.")
        layout.addWidget(self.summary)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Offset", "Current", "Other"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        layout.addWidget(self.table)

    def browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose binary", "", "All files (*)")
        if path:
            self.path_edit.setText(path)

    def compare(self):
        other_path = self.path_edit.text().strip()
        if not other_path or not self.main_window.current_binary_path:
            self.summary.setText("Load the current binary and choose another file first.")
            return
        try:
            with open(self.main_window.current_binary_path, "rb") as handle:
                current = handle.read()
            with open(other_path, "rb") as handle:
                other = handle.read()
        except OSError as exc:
            self.summary.setText(f"Read error: {exc}")
            return
        limit = min(len(current), len(other))
        differences = [index for index in range(limit) if current[index] != other[index]]
        differences.extend(range(limit, max(len(current), len(other))))
        self.summary.setText(
            f"Current: {len(current):,} bytes | Other: {len(other):,} bytes | "
            f"Different offsets: {len(differences):,}"
        )
        self.table.setRowCount(min(len(differences), 5000))
        for row, offset in enumerate(differences[:5000]):
            left = f"{current[offset]:02X}" if offset < len(current) else "--"
            right = f"{other[offset]:02X}" if offset < len(other) else "--"
            self.table.setItem(row, 0, QTableWidgetItem(f"0x{offset:X}"))
            self.table.setItem(row, 1, QTableWidgetItem(left))
            self.table.setItem(row, 2, QTableWidgetItem(right))


class PluginAPI:
    def __init__(self, main_window, plugin_record=None):
        self.main_window = main_window
        self.plugin_record = plugin_record

    def add_action(self, title, callback, menu="Plugins"):
        # Do not use dict.setdefault here: Python evaluates its default
        # argument eagerly, which used to create a duplicate top-level menu
        # every time a second action was registered in the same plugin menu.
        target = self.main_window.plugin_menus.get(menu)
        if target is None:
            target = self.main_window.menuBar().addMenu(menu)
            self.main_window.plugin_menus[menu] = target
        action = QAction(title, self.main_window)
        action.triggered.connect(lambda _checked=False: callback(self))
        target.addAction(action)
        if self.plugin_record is not None:
            self.plugin_record["actions"].append(action)
            self.plugin_record["menus"].add(menu)
        return action

    def jump_to(self, address):
        self.main_window.jump_to_address(int(address))

    def read_file_bytes(self, offset, size):
        return bytes(self.main_window.raw_data[int(offset):int(offset) + int(size)])

    @property
    def current_file(self):
        return self.main_window.current_binary_path


class PatternResultsDialog(QDialog):
    def __init__(self, main_window, results, pattern, parent=None):
        super().__init__(parent or main_window)
        self.main_window = main_window
        apply_windows_dark_titlebar(self)
        self.setWindowTitle(f"Pattern Results ({len(results)})")
        self.resize(620, 420)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"Matches for: {pattern}"))
        self.table = QTableWidget(len(results), 3)
        self.table.setHorizontalHeaderLabels(["#", "File offset", "Virtual address"])
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for row, (offset, va) in enumerate(results):
            self.table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
            self.table.setItem(row, 1, QTableWidgetItem(f"0x{offset:X}"))
            self.table.setItem(row, 2, QTableWidgetItem(f"0x{va:X}"))
        self.table.cellDoubleClicked.connect(self.jump_to_row)
        layout.addWidget(self.table)
        layout.addWidget(QLabel("Double-click a result to jump to it."))

    def jump_to_row(self, row, _column):
        item = self.table.item(row, 2)
        if item:
            self.main_window.jump_to_address(int(item.text(), 16))
            self.accept()


class DebuggerWidget(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.previous_registers = {}
        layout = QHBoxLayout(self)

        self.reg_table = QTableWidget()
        self.reg_table.setColumnCount(2)
        self.reg_table.setHorizontalHeaderLabels(["Register", "Value (Hex)"])
        self.reg_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.reg_table.setStyleSheet("background: #252526; color: #4EC9B0; font-family: Consolas;")
        layout.addWidget(self.reg_table, stretch=1)

        ctrl_panel = QWidget()
        ctrl_layout = QVBoxLayout(ctrl_panel)

        self.btn_run = QPushButton("Run / Continue (F9)")
        self.btn_run.clicked.connect(self.main_window.dbg_continue)
        self.btn_run.setStyleSheet("background: #007acc; color: white; padding: 6px; font-weight: bold;")
        ctrl_layout.addWidget(self.btn_run)

        step_row = QHBoxLayout()
        self.btn_step_into = QPushButton("Step Into (F7)")
        self.btn_step_into.clicked.connect(self.main_window.dbg_step_into)
        step_row.addWidget(self.btn_step_into)
        self.btn_step_over = QPushButton("Step Over (F8)")
        self.btn_step_over.clicked.connect(self.main_window.dbg_step_over)
        step_row.addWidget(self.btn_step_over)
        ctrl_layout.addLayout(step_row)

        self.btn_stop = QPushButton("Terminate Process")
        self.btn_stop.clicked.connect(self.main_window.dbg_stop)
        self.btn_stop.setStyleSheet("background: #A1260D; color: white; padding: 6px;")
        ctrl_layout.addWidget(self.btn_stop)

        ctrl_layout.addWidget(QLabel("<b>Breakpoints:</b>"))
        self.bp_list = QTreeWidget()
        self.bp_list.setHeaderLabels(["Address", "Type"])
        ctrl_layout.addWidget(self.bp_list)
        ctrl_layout.addWidget(QLabel("F2: toggle  |  Delete: remove selected"))
        ctrl_layout.addWidget(QLabel("Debug event log:"))
        self.event_log = QPlainTextEdit()
        self.event_log.setReadOnly(True)
        self.event_log.setMaximumHeight(135)
        self.event_log.setFont(QFont("Consolas", 8))
        ctrl_layout.addWidget(self.event_log)

        layout.addWidget(ctrl_panel, stretch=2)

    def update_registers(self, regs_dict):
        self.reg_table.setRowCount(len(regs_dict))
        for row, (k, v) in enumerate(regs_dict.items()):
            name_item = QTableWidgetItem(k)
            value_item = QTableWidgetItem(v)
            if k in self.previous_registers and self.previous_registers[k] != v:
                name_item.setForeground(QBrush(QColor("#FCE38A")))
                value_item.setForeground(QBrush(QColor("#FCE38A")))
                value_item.setToolTip(f"Previous: {self.previous_registers[k]}")
            self.reg_table.setItem(row, 0, name_item)
            self.reg_table.setItem(row, 1, value_item)
        self.previous_registers = dict(regs_dict)

    def append_event(self, message):
        self.event_log.appendPlainText(message)


class GandonPRO(QMainWindow):
    def __init__(self):
        super().__init__()
        apply_windows_dark_titlebar(self)
        self._dark_message_filter = DarkMessageBoxFilter(self)
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self._dark_message_filter)
        self.setWindowTitle("Gandon-PRO - The Interactive Disassembler & Debugger")
        self.resize(1400, 880)

        self.current_binary_path = ""
        self.raw_data = bytearray()
        self.is_elf = False
        self.pe = None
        self.cs = None
        self.image_base = 0
        self.current_va = 0
        self.entry_va = 0
        self.current_instruction_va = 0
        self.block_instruction_addresses = {}
        self.string_lookup = {}
        self.blocks = {}
        self.edges = []
        self.xrefs_db = {}
        self.functions = set()
        # Analysis-only visibility filters; the loaded binary is never changed.
        self.hidden_functions = set()
        self.hidden_imports = set()
        self.call_graph = {}
        self.history = []
        self.patch_history = {}
        self.patch_undo_stack = []
        self.patch_redo_stack = []
        self.current_instruction_va = 0
        self.debug_event_log = []
        self.action_history = []
        self.autosave_path = ""
        self.breakpoints = set()
        self.breakpoint_hits = {}
        self.breakpoint_hit_limits = {}
        self.breakpoint_log_only = set()
        self.bookmarks = {}
        self.breakpoint_box = None
        self.memory_dialog = None
        self.watch_dialog = None
        self.thread_stack_dialog = None
        self.plugin_menus = {}
        self.plugins = {}

        self.dbg_signals = DebuggerSignals()
        self.dbg = Win32Debugger(self.dbg_signals)
        # Keep the UI and worker looking at the same live containers. This
        # prevents a worker-thread AttributeError and keeps hit counters in
        # the breakpoint panel accurate.
        self.breakpoint_hits = self.dbg.breakpoint_hits
        self.breakpoint_hit_limits = self.dbg.breakpoint_hit_limits
        self.breakpoint_log_only = self.dbg.breakpoint_log_only
        self.dbg_signals.registers_updated.connect(self.on_dbg_registers)
        self.dbg_signals.state_changed.connect(self.on_dbg_state)
        self.dbg_signals.breakpoint_hit.connect(self.on_dbg_bp_hit)
        self.dbg_signals.step_finished.connect(self.on_dbg_step_finished)

        self.custom_names = {}
        self.auto_names = {}
        self.custom_comments = {}
        self.custom_colors = {}

        self.init_ui()
        self.apply_dark_theme()

    def showEvent(self, event):
        super().showEvent(event)
        apply_windows_dark_titlebar(self)

    def init_ui(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("File")
        open_act = QAction("Open Binary (PE/ELF/SO)...", self)
        open_act.setShortcut(QKeySequence("Ctrl+O"))
        open_act.triggered.connect(self.open_file_dialog)
        file_menu.addAction(open_act)

        save_db_act = QAction("Save Database (.gnd)...", self)
        save_db_act.setShortcut(QKeySequence("Ctrl+S"))
        save_db_act.triggered.connect(self.save_database)
        file_menu.addAction(save_db_act)

        load_db_act = QAction("Load Database (.gnd)...", self)
        load_db_act.setShortcut(QKeySequence("Ctrl+L"))
        load_db_act.triggered.connect(self.load_database)
        file_menu.addAction(load_db_act)

        apply_patch_act = QAction("Apply Patches to File...", self)
        apply_patch_act.setShortcut(QKeySequence("Ctrl+Alt+P"))
        apply_patch_act.triggered.connect(self.action_export_patched_file)
        file_menu.addAction(apply_patch_act)

        export_png_act = QAction("Export Graph to PNG...", self)
        export_png_act.triggered.connect(self.export_graph_png)
        file_menu.addAction(export_png_act)

        file_menu.addSeparator()
        exit_act = QAction("Exit", self)
        exit_act.triggered.connect(self.close)
        file_menu.addAction(exit_act)

        edit_menu = menubar.addMenu("Edit")
        rename_act = QAction("Rename Label", self)
        rename_act.setShortcut(QKeySequence("N"))
        rename_act.triggered.connect(self.action_rename_node)
        edit_menu.addAction(rename_act)

        comment_act = QAction("Add Comment", self)
        comment_act.setShortcut(QKeySequence(";"))
        comment_act.triggered.connect(self.action_add_comment)
        edit_menu.addAction(comment_act)

        patch_nop_act = QAction("NOP Current Block", self)
        patch_nop_act.setShortcut(QKeySequence("Ctrl+F2"))
        patch_nop_act.triggered.connect(self.action_patch_nop)
        edit_menu.addAction(patch_nop_act)

        edit_instruction_act = QAction("Edit Instruction", self)
        edit_instruction_act.setShortcut(QKeySequence("Ctrl+E"))
        # QAction.triggered sends a boolean checked argument.  Do not pass it
        # as the optional `block` parameter of action_edit_instruction().
        edit_instruction_act.triggered.connect(lambda _checked=False: self.action_edit_instruction())
        edit_menu.addAction(edit_instruction_act)

        undo_act = QAction("Undo Patch", self)
        undo_act.setShortcut(QKeySequence("Ctrl+Z"))
        undo_act.triggered.connect(self.undo_patch)
        edit_menu.addAction(undo_act)

        redo_act = QAction("Redo Patch", self)
        redo_act.setShortcut(QKeySequence("Ctrl+Y"))
        redo_act.triggered.connect(self.redo_patch)
        edit_menu.addAction(redo_act)

        jump_menu = menubar.addMenu("Jump")
        jump_act = QAction("Jump to Address / Label", self)
        jump_act.setShortcut(QKeySequence("G"))
        jump_act.triggered.connect(self.action_jump_dialog)
        jump_menu.addAction(jump_act)

        jump_back_act = QAction("Jump Back", self)
        jump_back_act.setShortcut(QKeySequence("Esc"))
        jump_back_act.triggered.connect(self.action_jump_back)
        jump_menu.addAction(jump_back_act)

        xrefs_act = QAction("List Cross References (XREFs)", self)
        xrefs_act.setShortcut(QKeySequence("X"))
        xrefs_act.triggered.connect(self.action_show_xrefs)
        jump_menu.addAction(xrefs_act)

        bookmark_act = QAction("Toggle Bookmark", self)
        bookmark_act.setShortcut(QKeySequence("Ctrl+Shift+B"))
        bookmark_act.triggered.connect(lambda _checked=False: self.toggle_bookmark())
        jump_menu.addAction(bookmark_act)

        next_bookmark_act = QAction("Next Bookmark", self)
        next_bookmark_act.setShortcut(QKeySequence("F6"))
        next_bookmark_act.triggered.connect(lambda _checked=False: self.next_bookmark())
        jump_menu.addAction(next_bookmark_act)

        find_function_act = QAction("Find Function...", self)
        find_function_act.setShortcut(QKeySequence("Ctrl+G"))
        find_function_act.triggered.connect(self.action_find_function)
        jump_menu.addAction(find_function_act)

        tools_menu = menubar.addMenu("Tools")
        decompile_act = QAction("Decompile to Pseudocode", self)
        decompile_act.setShortcut(QKeySequence("F5"))
        decompile_act.triggered.connect(self.action_decompile_pseudocode)
        tools_menu.addAction(decompile_act)

        sig_act = QAction("SigMaker: Generate Gandon Signature", self)
        sig_act.setShortcut(QKeySequence("Ctrl+B"))
        sig_act.triggered.connect(self.action_generate_signature)
        tools_menu.addAction(sig_act)

        search_sig_act = QAction("Search Gandon Signature Pattern...", self)
        search_sig_act.setShortcut(QKeySequence("Ctrl+Shift+F"))
        search_sig_act.triggered.connect(self.action_search_pattern)
        tools_menu.addAction(search_sig_act)

        call_graph_act = QAction("Call Graph", self)
        call_graph_act.triggered.connect(self.action_show_call_graph)
        tools_menu.addAction(call_graph_act)

        memory_act = QAction("Memory View", self)
        memory_act.triggered.connect(self.show_memory_view)
        tools_menu.addAction(memory_act)

        watch_act = QAction("Watch / Locals", self)
        watch_act.triggered.connect(self.show_watch_view)
        tools_menu.addAction(watch_act)

        thread_stack_act = QAction("Threads / Call Stack", self)
        thread_stack_act.triggered.connect(self.show_thread_stack)
        tools_menu.addAction(thread_stack_act)

        diff_act = QAction("Compare Binary...", self)
        diff_act.triggered.connect(self.show_binary_diff)
        tools_menu.addAction(diff_act)

        plugin_act = QAction("Load Python Plugin...", self)
        plugin_act.triggered.connect(self.load_plugin)
        tools_menu.addAction(plugin_act)
        unload_plugin_act = QAction("Unload Python Plugin...", self)
        unload_plugin_act.triggered.connect(self.unload_plugin)
        tools_menu.addAction(unload_plugin_act)

        export_log_act = QAction("Export Debug Event Log...", self)
        export_log_act.triggered.connect(self.export_debug_event_log)
        tools_menu.addAction(export_log_act)

        search_all_act = QAction("Search Text / Address...", self)
        search_all_act.setShortcut(QKeySequence("Ctrl+F"))
        search_all_act.triggered.connect(self.action_search_text)
        tools_menu.addAction(search_all_act)

        export_analysis_act = QAction("Export Analysis JSON...", self)
        export_analysis_act.triggered.connect(self.export_analysis_json)
        tools_menu.addAction(export_analysis_act)

        export_bp_act = QAction("Export Breakpoints CSV...", self)
        export_bp_act.triggered.connect(self.export_breakpoints_csv)
        tools_menu.addAction(export_bp_act)

        memory_map_act = QAction("Memory Map", self)
        memory_map_act.triggered.connect(lambda: self.tab_widget.setCurrentIndex(11))
        tools_menu.addAction(memory_map_act)
        problems_act = QAction("Problems / Events", self)
        problems_act.triggered.connect(lambda: self.tab_widget.setCurrentIndex(12))
        tools_menu.addAction(problems_act)
        python_console_act = QAction("Python Console", self)
        python_console_act.triggered.connect(self.show_python_console)
        tools_menu.addAction(python_console_act)
        self.trace_act = QAction("Trace Debug Events", self, checkable=True)
        self.trace_act.toggled.connect(self.toggle_trace)
        tools_menu.addAction(self.trace_act)
        export_trace_act = QAction("Export Trace...", self)
        export_trace_act.triggered.connect(self.export_trace)
        tools_menu.addAction(export_trace_act)
        search_memory_act = QAction("Search Process Memory...", self)
        search_memory_act.triggered.connect(self.search_process_memory)
        tools_menu.addAction(search_memory_act)

        hidden_symbols_act = QAction("Hidden Symbols...", self)
        hidden_symbols_act.triggered.connect(self.show_hidden_symbols)
        tools_menu.addAction(hidden_symbols_act)

        restore_hidden_act = QAction("Restore All Hidden Symbols", self)
        restore_hidden_act.triggered.connect(self.restore_all_hidden_symbols)
        tools_menu.addAction(restore_hidden_act)

        dbg_menu = menubar.addMenu("Debugger")
        dbg_run_act = QAction("Start / Continue Process", self)
        dbg_run_act.setShortcut(QKeySequence("F9"))
        dbg_run_act.setShortcutContext(Qt.ShortcutContext.ApplicationShortcut)
        dbg_run_act.triggered.connect(lambda _checked=False: self.dbg_continue())
        dbg_menu.addAction(dbg_run_act)

        dbg_step_into_act = QAction("Step Into", self)
        dbg_step_into_act.setShortcut(QKeySequence("F7"))
        dbg_step_into_act.setShortcutContext(Qt.ShortcutContext.ApplicationShortcut)
        dbg_step_into_act.triggered.connect(lambda _checked=False: self.dbg_step_into())
        dbg_menu.addAction(dbg_step_into_act)

        dbg_step_over_act = QAction("Step Over", self)
        dbg_step_over_act.setShortcut(QKeySequence("F8"))
        dbg_step_over_act.setShortcutContext(Qt.ShortcutContext.ApplicationShortcut)
        dbg_step_over_act.triggered.connect(lambda _checked=False: self.dbg_step_over())
        dbg_menu.addAction(dbg_step_over_act)

        dbg_bp_act = QAction("Toggle Breakpoint", self)
        dbg_bp_act.setShortcut(QKeySequence("F2"))
        dbg_bp_act.triggered.connect(lambda _checked=False: self.toggle_selected_breakpoint_or_import())
        dbg_menu.addAction(dbg_bp_act)

        dbg_cond_bp_act = QAction("Set Conditional Breakpoint...", self)
        dbg_cond_bp_act.triggered.connect(self.set_conditional_breakpoint)
        dbg_menu.addAction(dbg_cond_bp_act)

        dbg_config_bp_act = QAction("Configure Breakpoint...", self)
        dbg_config_bp_act.triggered.connect(self.configure_breakpoint)
        dbg_menu.addAction(dbg_config_bp_act)
        dbg_manager_act = QAction("Breakpoint Manager...", self)
        dbg_manager_act.triggered.connect(self.show_breakpoint_manager)
        dbg_menu.addAction(dbg_manager_act)

        dbg_hw_bp_act = QAction("Toggle Hardware Breakpoint", self)
        dbg_hw_bp_act.triggered.connect(self.toggle_hardware_breakpoint)
        dbg_menu.addAction(dbg_hw_bp_act)

        dbg_del_bp_act = QAction("Delete Selected Breakpoint", self)
        dbg_del_bp_act.setShortcut(QKeySequence("Delete"))
        dbg_del_bp_act.triggered.connect(self.remove_selected_breakpoint)
        dbg_menu.addAction(dbg_del_bp_act)

        dbg_stop_act = QAction("Stop Process", self)
        dbg_stop_act.triggered.connect(self.dbg_stop)
        dbg_menu.addAction(dbg_stop_act)

        view_menu = menubar.addMenu("View")
        toggle_view_act = QAction("Switch Graph / Text Listing", self)
        toggle_view_act.setShortcut(QKeySequence(Qt.Key.Key_Space))
        toggle_view_act.triggered.connect(self.toggle_graph_flat_view)
        view_menu.addAction(toggle_view_act)

        fit_graph_act = QAction("Fit Graph", self)
        fit_graph_act.setShortcut(QKeySequence("Home"))
        fit_graph_act.triggered.connect(self.fit_graph)
        view_menu.addAction(fit_graph_act)

        view_menu.addSeparator()
        act_gandon = QAction("Gandon View-A (Graph)", self)
        act_gandon.triggered.connect(lambda: self.tab_widget.setCurrentIndex(0))
        view_menu.addAction(act_gandon)

        act_flat = QAction("Gandon Text Listing", self)
        act_flat.triggered.connect(lambda: self.tab_widget.setCurrentIndex(1))
        view_menu.addAction(act_flat)

        act_pseudo = QAction("Pseudocode-A (F5)", self)
        act_pseudo.triggered.connect(self.action_decompile_pseudocode)
        view_menu.addAction(act_pseudo)

        act_dbg_tab = QAction("Debugger Win32", self)
        act_dbg_tab.triggered.connect(lambda: self.tab_widget.setCurrentIndex(3))
        view_menu.addAction(act_dbg_tab)

        act_hex = QAction("Hex View-1", self)
        act_hex.triggered.connect(lambda: self.tab_widget.setCurrentIndex(4))
        view_menu.addAction(act_hex)

        act_types = QAction("Local Types", self)
        act_types.triggered.connect(lambda: self.tab_widget.setCurrentIndex(5))
        view_menu.addAction(act_types)

        act_imports = QAction("Imports", self)
        act_imports.triggered.connect(lambda: self.tab_widget.setCurrentIndex(6))
        view_menu.addAction(act_imports)

        act_exports = QAction("Exports", self)
        act_exports.triggered.connect(lambda: self.tab_widget.setCurrentIndex(7))
        view_menu.addAction(act_exports)

        act_strings = QAction("Strings", self)
        act_strings.setShortcut(QKeySequence("Shift+F12"))
        act_strings.triggered.connect(lambda: self.tab_widget.setCurrentIndex(8))
        view_menu.addAction(act_strings)

        act_resources = QAction("Resources", self)
        act_resources.triggered.connect(lambda: self.tab_widget.setCurrentIndex(9))
        view_menu.addAction(act_resources)

        act_symbols = QAction("Symbols / Debug Info", self)
        act_symbols.triggered.connect(lambda: self.tab_widget.setCurrentIndex(10))
        view_menu.addAction(act_symbols)

        act_memory_map = QAction("Memory Map", self)
        act_memory_map.triggered.connect(lambda: self.tab_widget.setCurrentIndex(11))
        view_menu.addAction(act_memory_map)
        act_problems = QAction("Problems / Events", self)
        act_problems.triggered.connect(lambda: self.tab_widget.setCurrentIndex(12))
        view_menu.addAction(act_problems)

        help_menu = menubar.addMenu("Help")
        about_act = QAction("About Gandon-PRO...", self)
        about_act.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_act)

        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)

        self.nav_tree = QTreeWidget()
        self.nav_tree.setHeaderLabels(["Functions / Symbols", "Address"])
        self.nav_tree.setMinimumWidth(220)
        self.nav_tree.header().resizeSection(0, 150)
        self.nav_tree.itemDoubleClicked.connect(self.on_nav_item_clicked)
        self.nav_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.nav_tree.customContextMenuRequested.connect(self.show_navigation_context_menu)
        self.main_splitter.addWidget(self.nav_tree)

        self.tab_widget = QTabWidget()
        self.tab_widget.setMovable(True)

        self.graph_container = QWidget()
        g_layout = QVBoxLayout(self.graph_container)
        g_layout.setContentsMargins(0, 0, 0, 0)
        self.graph_view = GraphView(self)
        g_layout.addWidget(self.graph_view)

        self.overview = GraphOverview(self.graph_view, self.graph_view)
        self.overview.move(15, 15)

        self.tab_widget.addTab(self.graph_container, "Gandon View-A")
        self.flat_view = FlatDisasmWidget(self)
        self.tab_widget.addTab(self.flat_view, "Gandon Text Listing")
        self.pseudocode_view = PseudocodeWidget(self)
        self.tab_widget.addTab(self.pseudocode_view, "Pseudocode-A")
        self.dbg_widget = DebuggerWidget(self)
        self.tab_widget.addTab(self.dbg_widget, "Debugger Win32")
        self.hex_view = HexViewWidget(self)
        self.tab_widget.addTab(self.hex_view, "Hex View-1")
        self.local_types_view = LocalTypesWidget()
        self.tab_widget.addTab(self.local_types_view, "Local Types")
        self.imports_view = ImportsWidget(self)
        self.tab_widget.addTab(self.imports_view, "Imports")
        self.exports_view = ExportsWidget(self)
        self.tab_widget.addTab(self.exports_view, "Exports")
        self.strings_view = StringsWidget(self)
        self.tab_widget.addTab(self.strings_view, "Strings")
        self.resources_view = ResourcesWidget(self)
        self.tab_widget.addTab(self.resources_view, "Resources")
        self.symbols_view = SymbolsWidget(self)
        self.tab_widget.addTab(self.symbols_view, "Symbols / Debug Info")
        self.memory_map_view = MemoryMapWidget(self)
        self.tab_widget.addTab(self.memory_map_view, "Memory Map")
        self.problems_view = ProblemsEventsWidget(self)
        self.tab_widget.addTab(self.problems_view, "Problems / Events")
        self.python_console = None

        self.main_splitter.addWidget(self.tab_widget)
        self.main_splitter.setStretchFactor(0, 0)
        self.main_splitter.setStretchFactor(1, 1)
        self.main_splitter.setSizes([260, 1660])

        self.setCentralWidget(self.main_splitter)
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.messageChanged.connect(self._log_status_action)
        self.status_bar.showMessage("Ready. Shortcuts: F5 Pseudocode, F7 Step Into, F8 Step Over, F9 Continue, X XREFs, Ctrl+B SigMaker, Space Switch")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "overview") and hasattr(self, "graph_view"):
            w = self.graph_view.width()
            h = self.graph_view.height()
            self.overview.move(max(10, w - 200), max(10, h - 160))

    def apply_dark_theme(self):
        theme = """
            QMainWindow { background-color: #1e1e1e; }
            QMenuBar { background-color: #2d2d2d; color: #cccccc; }
            QMenuBar::item:selected { background-color: #3e3e3e; }
            QMenu { 
                background-color: #252526; 
                color: #cccccc; 
                border: 1px solid #3c3c3c; 
                padding: 4px; 
            }
            QMenu::item { 
                padding: 4px 38px 4px 14px; 
                min-width: 180px;
            }
            QMenu::item:selected { background-color: #007acc; color: #ffffff; }
            QTreeWidget { background-color: #252526; color: #d4d4d4; border: 1px solid #3c3c3c; }
            QTableWidget { background-color: #1e1e1e; color: #d4d4d4; border: none; gridline-color: #2a2a2a; }
            QLineEdit { background-color: #252526; color: #d4d4d4; border: 1px solid #3c3c3c; padding: 4px; font-family: Consolas; }
            QHeaderView::section { background-color: #2d2d2d; color: #9cdcfe; border: 1px solid #3c3c3c; padding: 4px; }
            QTabWidget::pane { border: 1px solid #3c3c3c; background-color: #1e1e1e; }
            QTabBar::tab { 
                background: #252526; 
                color: #969696; 
                padding: 6px 10px; 
                border: 1px solid #333333; 
                border-bottom: none;
            }
            QTabBar::tab:selected { 
                background: #1e1e1e; 
                color: #ffffff; 
                border-top: 2px solid #007acc; 
            }
            QSplitter::handle { background-color: #2d2d2d; width: 4px; }
            QSplitter::handle:hover { background-color: #007acc; }
            QScrollBar:vertical, QScrollBar:horizontal { background: #1e1e1e; border: none; }
            QScrollBar::handle:vertical, QScrollBar::handle:horizontal { background: #3e3e3e; min-height: 20px; min-width: 20px; }
            QStatusBar { background-color: #007acc; color: #ffffff; }
            QMessageBox { background-color: #1e1e1e; color: #d4d4d4; }
            QMessageBox QLabel { color: #d4d4d4; }
            QMessageBox QPushButton {
                background-color: #2d2d2d; color: #d4d4d4;
                border: 1px solid #505050; padding: 5px 18px;
                min-width: 70px;
            }
            QMessageBox QPushButton:hover { background-color: #3e3e3e; }
        """
        self.setStyleSheet(theme)
        app = QApplication.instance()
        if app is not None:
            # Force Qt's native dialogs/widgets onto the same dark palette.
            # A stylesheet alone leaves QInputDialog/QFileDialog controls
            # using the Windows light palette on some Windows builds.
            app.setStyle("Fusion")
            palette = QPalette()
            palette.setColor(QPalette.ColorRole.Window, QColor("#1e1e1e"))
            palette.setColor(QPalette.ColorRole.WindowText, QColor("#d4d4d4"))
            palette.setColor(QPalette.ColorRole.Base, QColor("#1e1e1e"))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#252526"))
            palette.setColor(QPalette.ColorRole.Text, QColor("#d4d4d4"))
            palette.setColor(QPalette.ColorRole.Button, QColor("#2d2d2d"))
            palette.setColor(QPalette.ColorRole.ButtonText, QColor("#d4d4d4"))
            palette.setColor(QPalette.ColorRole.Highlight, QColor("#264f78"))
            palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
            palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#252526"))
            palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#d4d4d4"))
            app.setPalette(palette)
            app.setStyleSheet(theme)

    def show_about_dialog(self):
        dialog = AboutDialog(self)
        if self.geometry().isValid():
            geo = self.geometry()
            x = geo.x() + (geo.width() - dialog.width()) // 2
            y = geo.y() + (geo.height() - dialog.height()) // 2
            dialog.move(x, y)
        dialog.exec()

    def action_decompile_pseudocode(self):
        self.pseudocode_view.decompile(self.blocks, self.current_va)
        self.tab_widget.setCurrentIndex(2)

    def toggle_graph_flat_view(self):
        curr = self.tab_widget.currentIndex()
        if curr == 0:
            self.tab_widget.setCurrentIndex(1)
        elif curr == 1:
            self.tab_widget.setCurrentIndex(0)

    def action_jump_dialog(self):
        text, ok = QInputDialog.getText(self, "Jump to Address / Label", "Enter Target Address or Symbol (e.g. 0x1800AEA21):")
        if ok and text:
            target_va = None
            text = text.strip()
            for addr, name in self.custom_names.items():
                if name.lower() == text.lower():
                    target_va = addr
                    break
            if target_va is None:
                try:
                    target_va = int(text, 16) if text.startswith("0x") else int(text)
                except ValueError:
                    QMessageBox.warning(self, "Invalid Address", f"Cannot resolve address: {text}")
                    return
            self.jump_to_address(target_va)

    def action_find_function(self):
        visible_functions = sorted(self.functions - self.hidden_functions)
        if not visible_functions:
            QMessageBox.information(self, "Find Function", "No functions have been discovered yet.")
            return
        values = [f"{self.label_for(addr, 'sub')}  (0x{addr:X})" for addr in visible_functions]
        choice, ok = QInputDialog.getItem(self, "Find Function", "Function:", values, 0, False)
        if ok and choice:
            try:
                address = int(choice.rsplit("0x", 1)[1].rstrip(")"), 16)
                self.jump_to_address(address)
            except (IndexError, ValueError):
                pass

    def fit_graph(self):
        if not self.graph_view.scene.items():
            return
        rect = self.graph_view.scene.itemsBoundingRect()
        if rect.isValid() and rect.width() > 0 and rect.height() > 0:
            self.graph_view.fitInView(rect.adjusted(-30, -30, 30, 30), Qt.AspectRatioMode.KeepAspectRatio)
            self.overview.update_viewport()

    def jump_to_address(self, addr):
        if self.current_va:
            self.history.append(self.current_va)
        self.current_va = addr

        if addr in self.graph_view.nodes:
            node = self.graph_view.nodes[addr]
            self.graph_view.centerOn(node)
            node.setSelected(True)
            for graph_node in self.graph_view.nodes.values():
                graph_node.update_content()
        else:
            self.build_cfg_graph(addr)

    def set_current_instruction(self, addr):
        self.current_instruction_va = int(addr or 0)
        for node in self.graph_view.nodes.values():
            node.update_content()

    def function_for_address(self, address):
        """Return the closest discovered function start at or before address."""
        image_end = self.image_base + int(getattr(self.pe.OPTIONAL_HEADER, "SizeOfImage", 0)) if self.pe else None
        candidates = [value for value in self.functions
                      if value <= address and (image_end is None or self.image_base <= value < image_end)]
        return max(candidates) if candidates else None

    def normalize_breakpoint_address(self, address):
        """Normalize a breakpoint address to the static image address space."""
        address = int(address)
        image_end = self.image_base + int(getattr(self.pe.OPTIONAL_HEADER, "SizeOfImage", 0)) if self.pe else 0
        if self.image_base <= address < image_end:
            return address
        if self.dbg.is_running and self.dbg.process_info and self.pe:
            remote_base = self.dbg._remote_module_base(os.path.basename(self.current_binary_path))
            if remote_base and remote_base <= address < remote_base + (image_end - self.image_base):
                return self.image_base + (address - remote_base)
        return address

    def show_debug_location(self, address):
        """Show an instruction without replacing the function currently displayed."""
        function_start = self.function_for_address(address)
        if function_start is None:
            self.jump_to_address(address)
        else:
            if self.current_va != function_start:
                if self.current_va:
                    self.history.append(self.current_va)
                self.current_va = function_start
                self.build_cfg_graph(function_start)
            node = next(
                (item for item in self.graph_view.nodes.values()
                 if address in self.block_instruction_addresses.get(item.addr, [])),
                None
            )
            if node is None and address not in self.graph_view.nodes:
                # A stripped binary can contain an approximate auto-detected
                # function start. Decode from the exact trap address as a
                # fallback so a breakpoint can never leave the graph blank.
                self.build_cfg_graph(address)
                node = next(
                    (item for item in self.graph_view.nodes.values()
                     if address in self.block_instruction_addresses.get(item.addr, [])),
                    None
                )
            if node is not None:
                self.graph_view.centerOn(node)
                node.setSelected(True)
                for graph_node in self.graph_view.nodes.values():
                    graph_node.update_content()
        self.set_current_instruction(address)

    def action_jump_back(self):
        if self.history:
            prev_va = self.history.pop()
            self.current_va = prev_va
            if prev_va in self.graph_view.nodes:
                self.graph_view.centerOn(self.graph_view.nodes[prev_va])
            else:
                self.build_cfg_graph(prev_va)

    def toggle_bookmark(self):
        address = self.current_va
        if not address:
            self.status_bar.showMessage("Select an address before adding a bookmark.")
            return
        if address in self.bookmarks:
            del self.bookmarks[address]
            self.status_bar.showMessage(f"Bookmark removed: 0x{address:X}")
            return
        name, ok = QInputDialog.getText(
            self, "Add Bookmark", "Label:",
            text=self.label_for(address)
        )
        if ok:
            self.bookmarks[address] = name.strip() or self.label_for(address)
            self.status_bar.showMessage(f"Bookmark added: 0x{address:X}")

    def next_bookmark(self):
        if not self.bookmarks:
            self.status_bar.showMessage("No bookmarks saved.")
            return
        addresses = sorted(self.bookmarks)
        next_address = next((value for value in addresses if value > self.current_va), addresses[0])
        self.jump_to_address(next_address)
        self.status_bar.showMessage(
            f"Bookmark: {self.bookmarks[next_address]} (0x{next_address:X})"
        )

    def action_show_xrefs(self):
        target_addr = None
        current_node = None

        selected_nodes = self.graph_view.scene.selectedItems()
        for item in selected_nodes:
            if isinstance(item, BasicBlockItem):
                current_node = item
                cursor = item.text_item.textCursor()
                if cursor.hasSelection():
                    txt = cursor.selectedText().strip()
                    for m in re.findall(r"0x[0-9a-fA-F]+", txt):
                        try:
                            target_addr = int(m, 16)
                            break
                        except ValueError:
                            pass
                if target_addr is None:
                    target_addr = item.addr
                break

        if target_addr is None:
            target_addr = self.current_va

        if not target_addr:
            QMessageBox.information(self, "XREFs", "No block or target selected for cross-references.")
            return

        xrefs = list(self.xrefs_db.get(target_addr, []))

        if current_node and current_node.addr == target_addr:
            for mnem, op, comm in current_node.instructions:
                for hex_m in re.findall(r"0x[0-9a-fA-F]+", op):
                    try:
                        dst_val = int(hex_m, 16)
                        if dst_val != target_addr:
                            xrefs.append(("Down", "Call/Jump", dst_val, f"{mnem} {op}"))
                    except ValueError:
                        pass

        seen = set()
        unique_xrefs = []
        for x in xrefs:
            key = (x[0], x[1], x[2])
            if key not in seen:
                seen.add(key)
                unique_xrefs.append(x)

        if not unique_xrefs:
            QMessageBox.information(self, "XREFs", f"No cross-references found for 0x{target_addr:08X}.")
            return

        name = self.label_for(target_addr)
        dlg = XrefsDialog(name, unique_xrefs, self)
        if dlg.exec() and dlg.target_address:
            self.jump_to_address(dlg.target_address)

    def action_show_call_graph(self):
        if not self.call_graph:
            QMessageBox.information(self, "Call Graph", "No direct calls discovered yet.")
            return
        CallGraphDialog(self.call_graph, self).exec()

    def show_memory_view(self):
        address = self.current_va or self.image_base
        if self.memory_dialog is None:
            self.memory_dialog = MemoryViewDialog(self, address, self)
        else:
            self.memory_dialog.set_address(address)
            self.memory_dialog.refresh()
        self.memory_dialog.show()
        self.memory_dialog.raise_()
        self.memory_dialog.activateWindow()

    def show_watch_view(self):
        if self.watch_dialog is None:
            self.watch_dialog = WatchDialog(self, self)
        else:
            self.watch_dialog.refresh()
        self.watch_dialog.show()
        self.watch_dialog.raise_()
        self.watch_dialog.activateWindow()

    def show_thread_stack(self):
        if self.thread_stack_dialog is None:
            self.thread_stack_dialog = ThreadStackDialog(self, self)
        else:
            self.thread_stack_dialog.refresh()
        self.thread_stack_dialog.show()
        self.thread_stack_dialog.raise_()
        self.thread_stack_dialog.activateWindow()

    def show_binary_diff(self):
        dialog = BinaryDiffDialog(self, self)
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def show_python_console(self):
        if self.python_console is None:
            self.python_console = PythonConsoleDialog(self, self)
        self.python_console.show()
        self.python_console.raise_()
        self.python_console.activateWindow()

    def _log_status_action(self, message):
        message = str(message).strip()
        if not message:
            return
        if hasattr(self, "python_console") and self.python_console is not None:
            self.python_console.append_action(message)
        else:
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.action_history.append(f"# [{timestamp}] {message}")
            self.action_history = self.action_history[-2000:]

    def show_breakpoint_manager(self):
        dialog = BreakpointManagerDialog(self, self)
        dialog.exec()

    def toggle_trace(self, enabled):
        self.dbg.trace_enabled = bool(enabled)
        if enabled:
            self.dbg.trace_records.clear()
        self.status_bar.showMessage("Debug event trace enabled." if enabled else "Debug event trace disabled.")

    def export_trace(self):
        if not self.dbg.trace_records:
            QMessageBox.information(self, "Trace", "The trace is empty. Enable Trace Debug Events and run the debugger.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Trace", "debug-trace.json", "JSON files (*.json)")
        if path:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(self.dbg.trace_records, handle, indent=2)
            self.status_bar.showMessage(f"Trace exported: {path}")

    def search_process_memory(self):
        pattern, ok = QInputDialog.getText(
            self, "Search Process Memory", "Hex bytes (use ?? as wildcard):",
            text="90 90"
        )
        if not ok or not pattern.strip():
            return
        tokens = pattern.split()
        try:
            needle = [None if token in ("?", "??") else int(token, 16) for token in tokens]
            if not needle or any(value is not None and not 0 <= value <= 255 for value in needle):
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Memory Search", "Use space-separated hex bytes, for example: 48 8B ?? 90")
            return
        if not self.dbg.is_running:
            QMessageBox.information(self, "Memory Search", "Start and pause the debuggee first.")
            return
        results = []
        if self.pe:
            for section in self.pe.sections:
                base = self.image_base + int(section.VirtualAddress)
                size = min(max(int(section.Misc_VirtualSize), len(section.get_data())), 0x1000000)
                data = self.dbg.read_memory(self.resolve_runtime_address(base), size)
                for offset in range(max(0, len(data) - len(needle) + 1)):
                    if all(expected is None or data[offset + i] == expected for i, expected in enumerate(needle)):
                        results.append(self.resolve_runtime_address(base + offset))
                        if len(results) >= 1000:
                            break
                if len(results) >= 1000:
                    break
        if results:
            self.status_bar.showMessage(f"Memory matches: {len(results)}")
            QMessageBox.information(self, "Memory Search", "\n".join(f"0x{address:X}" for address in results[:100]))
        else:
            QMessageBox.information(self, "Memory Search", "No matches found in mapped PE sections.")

    def configure_breakpoint(self):
        va = self._selected_breakpoint_address()
        if not va:
            self.status_bar.showMessage("Select an instruction first.")
            return
        if va not in self.breakpoints:
            self.toggle_breakpoint(va)
        limit, ok = QInputDialog.getInt(
            self, "Breakpoint Hit Count", "Stop after N hits (0 = every hit):",
            self.breakpoint_hit_limits.get(va, 0), 0, 1000000, 1
        )
        if not ok:
            return
        mode, ok = QInputDialog.getItem(
            self, "Breakpoint Mode", "Action:", ["Stop", "Log only"],
            1 if va in self.breakpoint_log_only else 0, False
        )
        if not ok:
            return
        self.breakpoint_hit_limits[va] = limit
        if mode == "Log only":
            self.breakpoint_log_only.add(va)
        else:
            self.breakpoint_log_only.discard(va)
        self.refresh_breakpoint_list()
        self.status_bar.showMessage(f"Breakpoint configured: 0x{va:08X}")

    def load_plugin(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Python Plugin", "", "Python files (*.py)"
        )
        if not path:
            return
        try:
            name = f"gandon_plugin_{len(self.plugins)}_{os.path.basename(path).replace('.', '_')}"
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                raise RuntimeError("Could not create a plugin loader")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            register = getattr(module, "register", None)
            if not callable(register):
                raise RuntimeError("Plugin must expose register(api)")
            record = {"module": module, "path": path, "actions": [], "menus": set()}
            register(PluginAPI(self, record))
            self.plugins[name] = record
            self.status_bar.showMessage(f"Plugin loaded: {os.path.basename(path)}")
        except Exception as exc:
            QMessageBox.warning(self, "Plugin Error", str(exc))

    def unload_plugin(self):
        if not self.plugins:
            QMessageBox.information(self, "Plugins", "No Python plugins are loaded.")
            return
        names = [f"{key}: {os.path.basename(record['path'])}" for key, record in self.plugins.items()]
        choice, ok = QInputDialog.getItem(self, "Unload Python Plugin", "Plugin:", names, 0, False)
        if not ok or not choice:
            return
        key = choice.split(":", 1)[0]
        record = self.plugins.pop(key, None)
        if record is None:
            return
        for action in record["actions"]:
            for menu_name in record["menus"]:
                menu = self.plugin_menus.get(menu_name)
                if menu is not None:
                    menu.removeAction(action)
            action.deleteLater()
        for menu_name in record["menus"]:
            menu = self.plugin_menus.get(menu_name)
            if menu is not None and not menu.actions():
                self.menuBar().removeAction(menu.menuAction())
                menu.deleteLater()
                self.plugin_menus.pop(menu_name, None)
        sys.modules.pop(key, None)
        self.status_bar.showMessage(f"Plugin unloaded: {os.path.basename(record['path'])}")

    def dbg_step_into(self):
        if self.dbg.step_into():
            self.status_bar.showMessage("Single-step armed. F7/F8 will stop after one instruction.")

    def dbg_step_over(self):
        # Prefer a temporary breakpoint after a direct call. Other
        # instructions use the debugger's one-instruction trap.
        if self.dbg.paused_thread_id and self.current_va and self.raw_data and self.cs:
            try:
                offset = (self.current_va - self.image_base) if self.is_elf else self.pe.get_offset_from_rva(self.current_va - self.image_base)
                insn = next(iter(self.cs.disasm(bytes(self.raw_data[offset:offset + 16]), self.current_va)), None)
                if insn and insn.mnemonic.lower() in ("call", "bl", "blr"):
                    next_va = insn.address + insn.size
                    runtime = self.resolve_runtime_address(next_va)
                    if self.dbg.arm_step_over(runtime, next_va):
                        self.status_bar.showMessage(
                            f"Step over armed: stop at 0x{next_va:X}."
                        )
                        return
            except (ValueError, TypeError, StopIteration):
                pass
        if self.dbg.step_over():
            self.status_bar.showMessage("Step-over command armed.")

    def action_rename_node(self):
        for item in self.graph_view.scene.selectedItems():
            if isinstance(item, BasicBlockItem):
                old_name = self.label_for(item.addr)
                new_name, ok = QInputDialog.getText(self, "Rename Label", "New Label Name:", text=old_name)
                if ok and new_name:
                    self.custom_names[item.addr] = new_name.strip()
                    item.update_content()
                    self.flat_view.populate(self.blocks)
                return

    def action_add_comment(self):
        for item in self.graph_view.scene.selectedItems():
            if isinstance(item, BasicBlockItem):
                old_comm = self.custom_comments.get(item.addr, "")
                comm, ok = QInputDialog.getText(self, "Add Block Comment", "Comment:", text=old_comm)
                if ok:
                    self.custom_comments[item.addr] = comm.strip()
                    item.update_content()
                    self.flat_view.populate(self.blocks)
                return

    def action_edit_instruction(self, block=None):
        """Assemble and replace one instruction in the selected block."""
        if Ks is None:
            QMessageBox.warning(
                self, "Assembler unavailable",
                "Install Keystone first:\n\npy -m pip install keystone-engine"
            )
            return
        if self.is_elf or not self.pe or not self.raw_data:
            QMessageBox.information(
                self, "Inline assembler", "Inline editing currently supports PE x86/x64 files."
            )
            return

        if block is None:
            selected = [x for x in self.graph_view.scene.selectedItems()
                        if isinstance(x, BasicBlockItem)]
            if not selected:
                QMessageBox.information(self, "Inline assembler", "Select a basic block first.")
                return
            block = selected[0]

        offset = self.pe.get_offset_from_rva(block.addr - self.image_base)
        raw = bytes(self.raw_data[offset:offset + 2048])
        instructions = list(self.cs.disasm(raw, block.addr))
        if not instructions:
            QMessageBox.warning(self, "Inline assembler", "Could not decode this block.")
            return

        labels = [f"0x{i.address:016X}: {i.mnemonic} {i.op_str}".strip()
                  for i in instructions]
        chosen, ok = QInputDialog.getItem(
            self, "Edit instruction", "Instruction:", labels, 0, False
        )
        if not ok:
            return
        index = labels.index(chosen)
        old_insn = instructions[index]
        new_text, ok = QInputDialog.getText(
            self, "Edit instruction",
            f"Assembly at 0x{old_insn.address:X}:",
            text=f"{old_insn.mnemonic} {old_insn.op_str}".strip()
        )
        if not ok or not new_text.strip():
            return

        mode = KS_MODE_64 if self.cs.mode & CS_MODE_64 else KS_MODE_32
        try:
            assembler = Ks(KS_ARCH_X86, mode)
            encoded, _ = assembler.asm(new_text.strip(), old_insn.address)
            new_bytes = bytes(encoded)
        except Exception as exc:
            QMessageBox.warning(self, "Assembly error", str(exc))
            return

        if len(new_bytes) > old_insn.size:
            QMessageBox.warning(
                self, "Instruction too large",
                f"New instruction is {len(new_bytes)} bytes; available space is {old_insn.size}."
            )
            return

        file_offset = offset + (old_insn.address - block.addr)
        replacement = new_bytes + b"\x90" * (old_insn.size - len(new_bytes))
        changes = []
        for index, value in enumerate(replacement):
            position = file_offset + index
            old_value = self.raw_data[position]
            self.raw_data[position] = value
            self.patch_history[position] = (old_value, value)
            changes.append((position, old_value, value))
        self._record_patch(changes)

        self.pe.__data__ = bytes(self.raw_data)
        self.status_bar.showMessage(
            f"Patched 0x{old_insn.address:X}: {new_text.strip()} | Ctrl+Alt+P to save."
        )
        self.build_cfg_graph(self.current_va)

    def action_patch_nop(self):
        for item in self.graph_view.scene.selectedItems():
            if isinstance(item, BasicBlockItem):
                try:
                    offset = (item.addr - self.image_base) if self.is_elf else self.pe.get_offset_from_rva(item.addr - self.image_base)
                    changes = []
                    for i in range(min(15, len(item.instructions) * 3)):
                        if offset + i < len(self.raw_data):
                            old = self.raw_data[offset + i]
                            self.raw_data[offset + i] = 0x90
                            self.patch_history[offset + i] = (old, 0x90)
                            changes.append((offset + i, old, 0x90))
                    self._record_patch(changes)
                    if self.pe:
                        self.pe.__data__ = bytes(self.raw_data)
                    self.status_bar.showMessage(f"Patched block 0x{item.addr:08X} with NOPs. Ctrl+Alt+P to save.")
                    self.build_cfg_graph(self.current_va)
                except Exception as e:
                    QMessageBox.warning(self, "Patch Error", str(e))
                return

    def _record_patch(self, changes):
        changes = [tuple(change) for change in changes if change[1] != change[2]]
        if changes:
            self.patch_undo_stack.append(changes)
            self.patch_redo_stack.clear()

    def _refresh_after_patch(self):
        if self.pe:
            self.pe.__data__ = bytes(self.raw_data)
        for node in self.graph_view.nodes.values():
            node.update_content()
        self.flat_view.populate(self.blocks)
        if self.current_va:
            self.build_cfg_graph(self.current_va)
        self.status_bar.showMessage("Patch state updated.")

    def undo_patch(self):
        if not self.patch_undo_stack:
            self.status_bar.showMessage("Nothing to undo.")
            return
        changes = self.patch_undo_stack.pop()
        for position, old, new in changes:
            self.raw_data[position] = old
            if position in self.patch_history:
                original, _current = self.patch_history[position]
                if old == original:
                    self.patch_history.pop(position, None)
                else:
                    self.patch_history[position] = (original, old)
        self.patch_redo_stack.append(changes)
        self._refresh_after_patch()
        self.status_bar.showMessage("Patch undone. Ctrl+Y to redo.")

    def redo_patch(self):
        if not self.patch_redo_stack:
            self.status_bar.showMessage("Nothing to redo.")
            return
        changes = self.patch_redo_stack.pop()
        for position, old, new in changes:
            self.raw_data[position] = new
            self.patch_history[position] = (old, new)
        self.patch_undo_stack.append(changes)
        self._refresh_after_patch()
        self.status_bar.showMessage("Patch redone. Ctrl+Z to undo.")

    def action_export_patched_file(self):
        if not self.patch_history:
            QMessageBox.information(self, "Patcher", "No patches have been applied to this binary.")
            return

        out_path, _ = QFileDialog.getSaveFileName(self, "Export Patched Binary", "", "Executables (*.exe *.dll *.so);;All (*)")
        if not out_path:
            return

        if self.pe:
            try:
                temp_pe = pefile.PE(data=bytes(self.raw_data))
                temp_pe.OPTIONAL_HEADER.CheckSum = temp_pe.generate_checksum()
                patched_bytes = temp_pe.write()
            except Exception:
                patched_bytes = bytes(self.raw_data)
        else:
            patched_bytes = bytes(self.raw_data)

        with open(out_path, "wb") as f:
            f.write(patched_bytes)

        QMessageBox.information(self, "Patcher", f"Successfully saved {len(self.patch_history)} patched bytes to:\n{out_path}")

    def action_generate_signature(self):
        selected_node = None
        for item in self.graph_view.scene.selectedItems():
            if isinstance(item, BasicBlockItem):
                selected_node = item
                break

        if not selected_node or not self.raw_data:
            QMessageBox.information(self, "SigMaker", "Select a block to generate a signature.")
            return

        try:
            offset = (selected_node.addr - self.image_base) if self.is_elf else self.pe.get_offset_from_rva(selected_node.addr - self.image_base)
            raw = self.raw_data[offset: offset + 64]
            disasm_list = list(self.cs.disasm(raw, selected_node.addr))
        except Exception:
            return

        gandon_tokens = []
        mask_chars = []
        cpp_bytes = []

        for insn in disasm_list[:6]:
            b = insn.bytes
            if insn.group(X86_GRP_JUMP) or insn.group(X86_GRP_CALL):
                gandon_tokens.append(f"{b[0]:02X}")
                mask_chars.append("x")
                cpp_bytes.append(f"\\x{b[0]:02X}")
                for _ in range(len(b) - 1):
                    gandon_tokens.append("?")
                    mask_chars.append("?")
                    cpp_bytes.append("\\x00")
            else:
                for byte_val in b:
                    gandon_tokens.append(f"{byte_val:02X}")
                    mask_chars.append("x")
                    cpp_bytes.append(f"\\x{byte_val:02X}")

        sig_gandon = " ".join(gandon_tokens)
        sig_cpp = f"\"{ ''.join(cpp_bytes) }\", \"{ ''.join(mask_chars) }\""

        count_matches = self.count_pattern_matches(sig_gandon)
        dlg = SigMakerDialog(sig_gandon, sig_cpp, count_matches, self)
        dlg.exec()

    def count_pattern_matches(self, pattern_str):
        try:
            regex_parts = []
            for token in pattern_str.split():
                if token == "?":
                    regex_parts.append(b".")
                else:
                    regex_parts.append(re.escape(bytes.fromhex(token)))
            reg = re.compile(b"".join(regex_parts), re.DOTALL)
            return len(reg.findall(self.raw_data))
        except Exception:
            return 0

    def action_search_pattern(self):
        if not self.raw_data:
            QMessageBox.information(self, "Pattern Search", "Please load a binary file first.")
            return

        sig, ok = QInputDialog.getText(self, "Search Pattern", "Enter Gandon signature (e.g. 48 89 5C 24 ? 57 or single byte 01):")
        if not (ok and sig.strip()):
            return

        raw_str = sig.strip()
        if " " not in raw_str and "?" not in raw_str:
            cleaned = "".join(c for c in raw_str if c in "0123456789abcdefABCDEF")
            if len(cleaned) % 2 != 0:
                cleaned = "0" + cleaned
            tokens = [cleaned[i:i+2] for i in range(0, len(cleaned), 2)]
        else:
            tokens = raw_str.split()

        regex_parts = []
        for t in tokens:
            if t in ("?", "??"):
                regex_parts.append(b".")
            else:
                hex_val = t.zfill(2) if len(t) == 1 else t
                try:
                    b_val = bytes.fromhex(hex_val)
                    regex_parts.append(re.escape(b_val))
                except ValueError:
                    QMessageBox.warning(self, "Invalid Pattern", f"Invalid hex byte: '{t}'.")
                    return

        if not regex_parts:
            return

        try:
            reg = re.compile(b"".join(regex_parts), re.DOTALL)
            matches = list(reg.finditer(self.raw_data))
            if not matches:
                QMessageBox.information(self, "Pattern Search", "Pattern not found.")
                return
            results = []
            for match in matches:
                found_offset = match.start()
                if self.is_elf:
                    target_va = self.image_base + found_offset
                else:
                    found_rva = self.pe.get_rva_from_offset(found_offset)
                    target_va = self.image_base + found_rva
                results.append((found_offset, target_va))
            self.jump_to_address(results[0][1])
            if len(results) == 1:
                self.status_bar.showMessage(f"Pattern found at 0x{results[0][1]:08X}")
            else:
                self.status_bar.showMessage(f"Pattern matches: {len(results)}")
                PatternResultsDialog(self, results, sig.strip(), self).exec()
        except Exception as e:
            QMessageBox.warning(self, "Search Error", str(e))

    def set_token_highlight(self, token):
        for node in self.graph_view.nodes.values():
            node.update_content(highlight_token=token)

    def export_graph_png(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Graph to Image", "cfg_graph.png", "PNG Images (*.png)")
        if file_path:
            rect = self.graph_view.scene.itemsBoundingRect()
            pix = QPixmap(int(rect.width() + 40), int(rect.height() + 40))
            pix.fill(QColor("#1e1e1e"))
            painter = QPainter(pix)
            self.graph_view.scene.render(painter, target=QRectF(pix.rect()), source=rect)
            painter.end()
            pix.save(file_path)
            self.status_bar.showMessage(f"Graph exported to {file_path}")

    def save_database(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Project DB", "project.gnd", "Gandon DB (*.gnd)")
        if file_path:
            db_data = self.project_payload()
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(db_data, f, indent=4)
            self.status_bar.showMessage("Project database saved successfully.")

    def project_payload(self):
        return {
                "custom_names": {str(k): v for k, v in self.custom_names.items()},
                "auto_names": {str(k): v for k, v in self.auto_names.items()},
                "custom_comments": {str(k): v for k, v in self.custom_comments.items()},
                "custom_colors": {str(k): v for k, v in self.custom_colors.items()},
                "hidden_functions": [f"0x{value:X}" for value in sorted(self.hidden_functions)],
                "hidden_imports": [[dll, name] for dll, name in sorted(self.hidden_imports)],
                "disabled_imports": [
                    [dll, name, f"0x{iat_va:X}", f"0x{image_base:X}"]
                    for dll, name, iat_va, image_base in self.dbg.requested_disabled_imports.values()
                ],
                "breakpoints": [f"0x{value:X}" for value in sorted(self.breakpoints)],
                "breakpoint_conditions": {str(k): v for k, v in self.dbg.breakpoint_conditions.items()},
                "breakpoint_hit_limits": {str(k): v for k, v in self.breakpoint_hit_limits.items()},
                "breakpoint_log_only": [f"0x{value:X}" for value in sorted(self.breakpoint_log_only)],
                "hardware_breakpoints": [f"0x{value:X}" for value, _base in sorted(self.dbg.requested_hardware_breakpoints)],
                "bookmarks": {str(k): v for k, v in self.bookmarks.items()},
                "types": self.local_types_view.types_definitions
            }

    def autosave_project(self):
        if not self.current_binary_path:
            return
        try:
            self.autosave_path = self.current_binary_path + ".gnd"
            with open(self.autosave_path, "w", encoding="utf-8") as handle:
                json.dump(self.project_payload(), handle, indent=2)
            self.debug_event_log.append(f"Project autosaved: {self.autosave_path}")
        except OSError as exc:
            self.debug_event_log.append(f"Project autosave failed: {exc}")

    def load_database(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Project DB", "", "Gandon DB (*.gnd)")
        if file_path:
            with open(file_path, "r", encoding="utf-8") as f:
                db_data = json.load(f)
                self.custom_names = {int(k): v for k, v in db_data.get("custom_names", {}).items()}
                self.auto_names.update({int(k): v for k, v in db_data.get("auto_names", {}).items()})
                self.custom_comments = {int(k): v for k, v in db_data.get("custom_comments", {}).items()}
                self.custom_colors = {int(k): v for k, v in db_data.get("custom_colors", {}).items()}
                self.hidden_functions = {
                    int(value, 16) if isinstance(value, str) else int(value)
                    for value in db_data.get("hidden_functions", [])
                }
                self.hidden_imports = {
                    (str(value[0]).casefold(), str(value[1]).casefold())
                    for value in db_data.get("hidden_imports", [])
                    if isinstance(value, (list, tuple)) and len(value) == 2
                }
                self.dbg.requested_disabled_imports.clear()
                for value in db_data.get("disabled_imports", []):
                    if isinstance(value, (list, tuple)) and len(value) == 4:
                        dll, name, iat_va, image_base = value
                        self.dbg.set_import_disabled(
                            str(dll), str(name),
                            int(iat_va, 16) if isinstance(iat_va, str) else int(iat_va),
                            int(image_base, 16) if isinstance(image_base, str) else int(image_base),
                        )
                self.breakpoints = {
                    int(value, 16) if isinstance(value, str) else int(value)
                    for value in db_data.get("breakpoints", [])
                }
                self.dbg.requested_breakpoints = {
                    (value, self.image_base) for value in self.breakpoints
                }
                self.dbg.breakpoint_conditions = {
                    int(k): str(v) for k, v in db_data.get("breakpoint_conditions", {}).items()
                }
                self.breakpoint_hit_limits.clear()
                self.breakpoint_hit_limits.update({
                    int(k): int(v) for k, v in db_data.get("breakpoint_hit_limits", {}).items()
                })
                self.breakpoint_log_only.clear()
                self.breakpoint_log_only.update({
                    int(value, 16) if isinstance(value, str) else int(value)
                    for value in db_data.get("breakpoint_log_only", [])
                })
                self.dbg.requested_hardware_breakpoints = {
                    (int(value, 16) if isinstance(value, str) else int(value), self.image_base)
                    for value in db_data.get("hardware_breakpoints", [])
                }
                self.bookmarks = {
                    int(k): str(v) for k, v in db_data.get("bookmarks", {}).items()
                }
                if db_data.get("types"):
                    self.local_types_view.set_definitions(db_data["types"])
                self.refresh_breakpoint_list()
            for node in self.graph_view.nodes.values():
                node.update_content()
            self.flat_view.populate(self.blocks)
            self.pseudocode_view.decompile(self.blocks, self.current_va)
            self.status_bar.showMessage("Database loaded.")

    def open_file_dialog(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Binary", "", "Executables (*.exe *.dll *.so *.elf);;All Files (*)"
        )
        if file_path:
            self.load_binary(file_path)

    def cache_strings(self):
        self.string_lookup.clear()
        if not self.raw_data:
            return
        ascii_regex = re.compile(rb"[\x20-\x7E]{4,}")
        for match in ascii_regex.finditer(self.raw_data):
            va = self.image_base + match.start()
            self.string_lookup[va] = match.group().decode("ascii", errors="ignore")

    def auto_detect_functions(self):
        """Discover likely internal functions from executable PE code bytes."""
        if not self.pe:
            return
        discovered = set(self.functions)
        image_end = self.image_base + int(getattr(self.pe.OPTIONAL_HEADER, "SizeOfImage", 0))
        for section in self.pe.sections:
            characteristics = int(getattr(section, "Characteristics", 0))
            if not (characteristics & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
                continue
            data = section.get_data()
            base = self.image_base + int(section.VirtualAddress)
            for pattern in (b"\x55\x48\x89\xe5", b"\x40\x53", b"\x48\x83\xec"):
                start = 0
                while True:
                    offset = data.find(pattern, start)
                    if offset < 0:
                        break
                    discovered.add(base + offset)
                    start = offset + 1
                    if len(discovered) > 20000:
                        break
            if self.cs and self.cs.arch == CS_ARCH_X86:
                for match in re.finditer(rb"\xe8(.{4})", data, re.DOTALL):
                    target = base + match.start() + 5 + struct.unpack("<i", match.group(1))[0]
                    if self.image_base <= target < image_end:
                        discovered.add(target)
        self.functions.update(discovered)

    def load_binary(self, path: str):
        if self.dbg.is_running:
            self.dbg.stop()
        self.current_binary_path = path
        try:
            with open(path, "rb") as f:
                self.raw_data = bytearray(f.read())
        except Exception as e:
            self.status_bar.showMessage(f"File Read Error: {e}")
            return

        self.patch_history.clear()
        self.patch_undo_stack.clear()
        self.patch_redo_stack.clear()
        self.functions.clear()
        self.hidden_functions.clear()
        self.hidden_imports.clear()
        self.dbg.requested_disabled_imports.clear()
        self.dbg.disabled_imports.clear()
        self.call_graph.clear()
        self.auto_names.clear()
        self.breakpoints.clear()
        self.breakpoint_hits.clear()
        self.breakpoint_hit_limits.clear()
        self.breakpoint_log_only.clear()
        self.dbg.breakpoint_conditions.clear()
        self.dbg.requested_hardware_breakpoints.clear()
        self.dbg.hardware_breakpoints.clear()
        self.dbg.requested_breakpoints.clear()
        self.dbg.runtime_breakpoints.clear()
        self.dbg.pending_reinsert = None
        self.refresh_breakpoint_list()

        if self.raw_data.startswith(b"MZ"):
            self.is_elf = False
            self.pe = pefile.PE(data=bytes(self.raw_data), fast_load=False)
            machine = getattr(self.pe.FILE_HEADER, "Machine", 0x8664)
            if machine == 0x8664:
                self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
                arch_str = "x86-64"
            else:
                self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
                arch_str = "x86-32"

            self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
            ep_rva = getattr(self.pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)
            entry_va = self.image_base + ep_rva if ep_rva else self.image_base

            if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        self.auto_names[self.image_base + exp.address] = (
                            exp.name.decode(errors="ignore")
                        )
            self.auto_detect_functions()

        elif self.raw_data.startswith(b"\x7fELF"):
            self.is_elf = True
            self.pe = None
            is_64 = self.raw_data[4] == 2
            e_machine = struct.unpack("<H", self.raw_data[18:20])[0]

            if e_machine == 0xB7:
                self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
                arch_str = "ARM64"
            elif e_machine == 0x28:
                self.cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
                arch_str = "ARM32"
            else:
                self.cs = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
                arch_str = "x86-64" if is_64 else "x86-32"

            self.image_base = 0x0
            entry_va = struct.unpack("<Q" if is_64 else "<I", self.raw_data[24: 24 + (8 if is_64 else 4)])[0]
        else:
            QMessageBox.critical(self, "Format Error", "Unrecognized binary header.")
            return

        self.cs.detail = True
        self.status_bar.showMessage(f"Loaded: {os.path.basename(path)} | {arch_str} | Base: 0x{self.image_base:X}")
        self.entry_va = entry_va

        self.cache_strings()
        if self.pe:
            self.memory_map_view.load_binary(self.pe, self.image_base)
        else:
            self.memory_map_view.clear()
        self.populate_navigation(entry_va)

        self.hex_view.load_hex(self.raw_data, self.image_base, entry_va)
        if self.pe:
            self.imports_view.load_imports(self.pe)
            self.exports_view.load_exports(self.pe, self.image_base)
            self.resources_view.load_resources(self.pe)
            self.symbols_view.load_pe(self.pe, self.image_base)
        else:
            self.symbols_view.load_elf(self.raw_data, self.image_base)
        self.strings_view.extract_strings(self.raw_data, self.image_base)

        self.switch_to_gandon_view(entry_va)

    def label_for(self, address, default_prefix="loc"):
        return self.custom_names.get(
            address,
            self.auto_names.get(address, f"{default_prefix}_{address:08X}")
        )

    def resolve_runtime_address(self, address):
        """Translate a PE image VA to its ASLR-adjusted process address."""
        address = int(address)
        if not self.dbg.is_running or not self.dbg.process_info or self.is_elf:
            return address
        if address < self.image_base:
            return address
        remote_base = self.dbg._remote_module_base(
            os.path.basename(self.current_binary_path)
        )
        if not remote_base:
            return address
        if address >= remote_base:
            return address
        return remote_base + (address - self.image_base)

    def switch_to_gandon_view(self, target_va: int):
        self.tab_widget.setCurrentIndex(0)
        self.jump_to_address(target_va)

    def build_cfg_graph(self, start_va: int, max_depth: int = 35):
        if not self.raw_data or not self.cs:
            return

        try:
            start_offset = (start_va - self.image_base) if self.is_elf else self.pe.get_offset_from_rva(start_va - self.image_base)
        except (AttributeError, TypeError, ValueError, OverflowError):
            self.status_bar.showMessage(f"Cannot map address 0x{int(start_va):X} to file bytes.")
            return
        if start_offset < 0 or start_offset >= len(self.raw_data):
            self.status_bar.showMessage(f"Address 0x{int(start_va):X} is outside the loaded image.")
            return

        worklist = [start_va]
        visited = set()
        self.blocks = {}
        self.edges = []
        self.xrefs_db = {}
        self.block_instruction_addresses = {}
        self.functions.add(start_va)

        while worklist and len(self.blocks) < max_depth:
            curr_va = worklist.pop(0)
            if curr_va in visited:
                continue

            try:
                offset = (curr_va - self.image_base) if self.is_elf else self.pe.get_offset_from_rva(curr_va - self.image_base)
            except (AttributeError, TypeError, ValueError, OverflowError):
                continue
            if offset < 0 or offset >= len(self.raw_data):
                continue

            raw = bytes(self.raw_data[offset: offset + 2048])
            if not raw:
                continue

            insns = []
            instruction_addresses = []
            visited.add(curr_va)

            try:
                disasm_iter = list(self.cs.disasm(raw, curr_va))
            except Exception:
                continue

            for insn in disasm_iter:
                op = insn.op_str
                comment = ""

                for operand in insn.operands:
                    if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                        resolved_va = insn.address + insn.size + operand.mem.disp
                        if resolved_va in self.string_lookup:
                            comment = f'"{self.string_lookup[resolved_va]}"'
                        self.xrefs_db.setdefault(resolved_va, []).append(("Up", "Data Ref", insn.address, f"{insn.mnemonic} {op}"))

                if not comment:
                    for hex_m in re.findall(r"0x[0-9a-fA-F]+", op):
                        try:
                            val = int(hex_m, 16)
                            if val in self.string_lookup:
                                comment = f'"{self.string_lookup[val]}"'
                                break
                        except ValueError:
                            continue

                insns.append((insn.mnemonic, op, comment))
                instruction_addresses.append(insn.address)

                if insn.group(X86_GRP_CALL):
                    call_target = None
                    try:
                        if hasattr(insn, "operands") and insn.operands and insn.operands[0].type == 2:
                            call_target = insn.operands[0].imm
                    except Exception:
                        call_target = None
                    if call_target:
                        self.call_graph.setdefault(curr_va, set()).add(call_target)
                        self.functions.add(call_target)
                        self.xrefs_db.setdefault(call_target, []).append(
                            ("Up", "Call", insn.address, f"{insn.mnemonic} {op}")
                        )

                for hex_m in re.findall(r"0x[0-9a-fA-F]+", op):
                    try:
                        ref_val = int(hex_m, 16)
                        xtype = "Call" if insn.group(X86_GRP_CALL) else "Jump" if insn.group(X86_GRP_JUMP) else "Ref"
                        self.xrefs_db.setdefault(ref_val, []).append(("Up", xtype, insn.address, f"{insn.mnemonic} {op}"))
                    except ValueError:
                        pass

                if insn.group(X86_GRP_JUMP) or insn.mnemonic in ("b", "bx"):
                    target = None
                    try:
                        if hasattr(insn, 'operands') and len(insn.operands) > 0:
                            if insn.operands[0].type == 2:
                                target = insn.operands[0].imm
                        if target is None and op.startswith("0x"):
                            target = int(op, 16)
                    except Exception:
                        target = None

                    if insn.mnemonic in ("jmp", "b"):
                        if target and target != curr_va:
                            self.edges.append((curr_va, target, "#569CD6", "uncond"))
                            self.xrefs_db.setdefault(target, []).append(("Up", "Jump", insn.address, f"{insn.mnemonic} loc_{target:08X}"))
                            if target not in visited:
                                worklist.append(target)
                    else:
                        fallthrough = insn.address + insn.size
                        if target and target != curr_va:
                            self.edges.append((curr_va, target, "#4EC9B0", "true"))
                            self.xrefs_db.setdefault(target, []).append(("Up", "Cond Jump", insn.address, f"{insn.mnemonic} loc_{target:08X}"))
                            if target not in visited:
                                worklist.append(target)
                        self.edges.append((curr_va, fallthrough, "#F44747", "false"))
                        self.xrefs_db.setdefault(fallthrough, []).append(("Up", "Fallthrough", insn.address, f"loc_{fallthrough:08X}"))
                        if fallthrough not in visited:
                            worklist.append(fallthrough)
                    break

                elif insn.group(X86_GRP_RET) or insn.mnemonic in ("ret", "bx lr"):
                    break

            if insns:
                self.blocks[curr_va] = insns
                self.block_instruction_addresses[curr_va] = instruction_addresses

        if not self.blocks:
            self.status_bar.showMessage(f"No instructions decoded at 0x{int(start_va):X}; keeping current CFG.")
            return

        # Replace the scene only after decoding produced at least one block.
        # A failed breakpoint navigation can therefore never erase the view.
        self.graph_view.clear_graph()

        levels = {addr: 0 for addr in self.blocks}
        for _ in range(len(self.blocks)):
            for src, dst, _, _ in self.edges:
                if src in levels and dst in levels:
                    if levels[dst] <= levels[src]:
                        levels[dst] = levels[src] + 1

        layer_blocks = {}
        for addr, lvl in levels.items():
            layer_blocks.setdefault(lvl, []).append(addr)

        temp_items = {}
        for addr, insns in self.blocks.items():
            temp_items[addr] = BasicBlockItem(addr, insns, 0, 0, self)

        curr_y = 0.0
        for lvl in sorted(layer_blocks.keys()):
            row_addrs = layer_blocks[lvl]
            row_heights = [temp_items[a].height for a in row_addrs]
            max_h = max(row_heights) if row_heights else 100

            total_row_w = sum(temp_items[a].width for a in row_addrs) + (len(row_addrs) - 1) * 110
            curr_x = -total_row_w / 2.0

            for a in row_addrs:
                node = self.graph_view.add_node(a, self.blocks[a], curr_x, curr_y)
                curr_x += node.width + 110

            curr_y += max_h + 100

        for src, dst, col, e_type in self.edges:
            self.graph_view.add_edge(src, dst, col, e_type)

        self.flat_view.populate(self.blocks)
        self.pseudocode_view.decompile(self.blocks, start_va)
        self.populate_navigation(start_va)

        if start_va in self.graph_view.nodes:
            self.graph_view.centerOn(self.graph_view.nodes[start_va])

        self.overview.update_viewport()

        for node in self.graph_view.nodes.values():
            node.update_content()

    def populate_navigation(self, entry_va: int):
        self.nav_tree.clear()
        ep_item = QTreeWidgetItem(["_start (EntryPoint)", f"0x{entry_va:08X}"])
        ep_item.setForeground(0, QColor("#4EC9B0"))
        self.nav_tree.addTopLevelItem(ep_item)

        visible_functions = sorted(self.functions - self.hidden_functions)
        if visible_functions:
            fn_root = QTreeWidgetItem(["Functions", ""])
            for fn_va in visible_functions:
                fn_name = self.label_for(fn_va, "sub")
                fn_root.addChild(QTreeWidgetItem([fn_name, f"0x{fn_va:08X}"]))
            self.nav_tree.addTopLevelItem(fn_root)

        if self.pe and hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            imp_root = QTreeWidgetItem(["Imports", ""])
            visible_imports = 0
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore")
                d_item = QTreeWidgetItem([dll, ""])
                for imp in entry.imports:
                    name = imp.name.decode(errors="ignore") if imp.name else f"Ordinal({imp.ordinal})"
                    if (dll.casefold(), name.casefold()) in self.hidden_imports:
                        continue
                    addr = f"0x{imp.address:08X}" if imp.address else ""
                    d_item.addChild(QTreeWidgetItem([name, addr]))
                if d_item.childCount():
                    imp_root.addChild(d_item)
                    visible_imports += d_item.childCount()
            if visible_imports:
                self.nav_tree.addTopLevelItem(imp_root)

        if self.pe:
            sec_root = QTreeWidgetItem(["Sections", ""])
            for sec in self.pe.sections:
                s_name = sec.Name.decode(errors="ignore").strip('\x00')
                s_va = f"0x{(self.image_base + sec.VirtualAddress):08X}"
                sec_root.addChild(QTreeWidgetItem([s_name, s_va]))
            self.nav_tree.addTopLevelItem(sec_root)

        self.nav_tree.expandAll()

    def _nav_import_key(self, item):
        parent = item.parent()
        if parent is None or parent.parent() is None:
            return None
        if parent.parent().text(0) != "Imports":
            return None
        return parent.text(0), item.text(0)

    def show_navigation_context_menu(self, position):
        item = self.nav_tree.itemAt(position)
        if item is None:
            return
        menu = QMenu(self)
        action_added = False
        addr_text = item.text(1)
        if addr_text.startswith("0x"):
            try:
                address = int(addr_text, 16)
            except ValueError:
                address = 0
            if address in self.functions:
                hide_action = menu.addAction("Hide Function from Analysis")
                hide_action.triggered.connect(lambda _checked=False, va=address: self.hide_function(va))
                action_added = True
        import_key = self._nav_import_key(item)
        if import_key is not None:
            disable_import_action = menu.addAction("Disable Import at Runtime (F2)")
            disable_import_action.triggered.connect(
                lambda _checked=False, key=import_key, item=item: self.toggle_import_disable_from_item(item, key)
            )
            hide_import_action = menu.addAction("Hide Import from Analysis")
            hide_import_action.triggered.connect(
                lambda _checked=False, key=import_key: self.hide_import(*key)
            )
            action_added = True
        if action_added:
            menu.addSeparator()
        restore_action = menu.addAction("Hidden Symbols...")
        restore_action.triggered.connect(self.show_hidden_symbols)
        menu.exec(self.nav_tree.viewport().mapToGlobal(position))

    def _refresh_symbol_visibility(self):
        self.populate_navigation(self.entry_va or self.current_va or self.image_base)
        if self.pe:
            self.imports_view.load_imports(self.pe)

    def hide_function(self, address):
        self.hidden_functions.add(int(address))
        self._refresh_symbol_visibility()
        self.status_bar.showMessage(f"Function hidden from analysis: 0x{address:X}")

    def hide_import(self, dll, name):
        self.hidden_imports.add((str(dll).casefold(), str(name).casefold()))
        self._refresh_symbol_visibility()
        self.status_bar.showMessage(f"Import hidden from analysis: {dll}!{name}")

    def show_hidden_symbols(self):
        entries = [("function", value, f"Function 0x{value:X} ({self.label_for(value, 'sub')})")
                   for value in sorted(self.hidden_functions)]
        entries += [("import", key, f"Import {key[0]}!{key[1]}")
                    for key in sorted(self.hidden_imports)]
        if not entries:
            QMessageBox.information(self, "Hidden Symbols", "No hidden functions or imports.")
            return
        labels = [entry[2] for entry in entries]
        choice, ok = QInputDialog.getItem(
            self, "Hidden Symbols", "Select a symbol to restore:", labels, 0, False
        )
        if ok and choice:
            kind, value, _label = entries[labels.index(choice)]
            if kind == "function":
                self.hidden_functions.discard(value)
            else:
                self.hidden_imports.discard(value)
            self._refresh_symbol_visibility()
            self.status_bar.showMessage(f"Restored: {choice}")

    def restore_all_hidden_symbols(self):
        if not self.hidden_functions and not self.hidden_imports:
            return
        self.hidden_functions.clear()
        self.hidden_imports.clear()
        self._refresh_symbol_visibility()
        self.status_bar.showMessage("All hidden symbols restored.")

    def _selected_import(self):
        # When the Imports tab is active, F2 must use the selected table row,
        # not the last graph address.
        if self.tab_widget.currentWidget() is self.imports_view:
            row = self.imports_view.table.currentRow()
            if row >= 0:
                address_item = self.imports_view.table.item(row, 0)
                dll_item = self.imports_view.table.item(row, 1)
                name_item = self.imports_view.table.item(row, 2)
                if address_item and dll_item and name_item:
                    try:
                        return None, (dll_item.text(), name_item.text()), int(address_item.text(), 16)
                    except ValueError:
                        pass
        # A graph block takes precedence after leaving the Imports tab. This
        # prevents a stale import-row selection from hijacking F2.
        if any(isinstance(item, BasicBlockItem) for item in self.graph_view.scene.selectedItems()):
            return None
        if not self.nav_tree.hasFocus():
            return None
        item = self.nav_tree.currentItem()
        if item is None:
            return None
        key = self._nav_import_key(item)
        if key is None:
            return None
        address_text = item.text(1)
        try:
            iat_va = int(address_text, 16)
        except ValueError:
            return None
        return item, key, iat_va

    def toggle_import_disable_from_item(self, item, key=None, iat_va=None):
        key = key or self._nav_import_key(item)
        if key is None:
            return
        if iat_va is None:
            try:
                iat_va = int(item.text(1), 16)
            except (AttributeError, ValueError):
                self.status_bar.showMessage("This import has no usable IAT address.")
                return
        dll, name = key
        normalized_key = (str(dll).casefold(), str(name).casefold())
        if normalized_key in self.dbg.requested_disabled_imports:
            self.dbg.remove_import_disabled(dll, name)
            self.status_bar.showMessage(f"Import enabled: {dll}!{name}")
        else:
            ok = self.dbg.set_import_disabled(dll, name, iat_va, self.image_base)
            if ok:
                self.status_bar.showMessage(f"Import queued for disable: {dll}!{name}")
            else:
                self.status_bar.showMessage(f"Could not disable import: {dll}!{name}")

    def toggle_selected_breakpoint_or_import(self):
        selected_import = self._selected_import()
        if selected_import is not None:
            self.toggle_import_disable_from_item(
                selected_import[0], selected_import[1], selected_import[2]
            )
            return
        self.toggle_breakpoint(self._selected_breakpoint_address())

    def on_nav_item_clicked(self, item, col):
        addr_str = item.text(1)
        if addr_str.startswith("0x"):
            self.jump_to_address(int(addr_str, 16))

    def toggle_breakpoint(self, va):
        if not va:
            self.status_bar.showMessage("Select an instruction or block first.")
            return
        if va in self.breakpoints:
            self.breakpoints.remove(va)
            self.breakpoint_hits.pop(va, None)
            self.breakpoint_hit_limits.pop(va, None)
            self.breakpoint_log_only.discard(va)
            self.dbg.remove_user_breakpoint(va, self.image_base)
            self.status_bar.showMessage(f"Breakpoint removed: 0x{va:08X}")
        else:
            if not self.dbg.set_user_breakpoint(va, self.image_base):
                self.status_bar.showMessage(f"Could not install breakpoint: 0x{va:08X}")
                return
            self.breakpoints.add(va)
            self.status_bar.showMessage(f"Breakpoint added: 0x{va:08X}")

        self.refresh_breakpoint_list()
        for node in self.graph_view.nodes.values():
            node.update_content()

    def set_conditional_breakpoint(self):
        self.set_conditional_breakpoint_at(self._selected_breakpoint_address())

    def set_conditional_breakpoint_at(self, va):
        if not va:
            self.status_bar.showMessage("Select an instruction first.")
            return
        current = self.dbg.breakpoint_conditions.get(va, "RIP == 0x0")
        expression, ok = QInputDialog.getText(
            self, "Conditional Breakpoint", "Condition (example: RAX == 0x1):", text=current
        )
        if not ok:
            return
        if va not in self.breakpoints:
            self.toggle_breakpoint(va)
        self.dbg.set_breakpoint_condition(va, expression)
        self.refresh_breakpoint_list()
        self.status_bar.showMessage(f"Condition set at 0x{va:08X}: {expression or 'always'}")

    def toggle_hardware_breakpoint(self):
        self.toggle_hardware_breakpoint_at(self._selected_breakpoint_address())

    def toggle_hardware_breakpoint_at(self, va):
        if not va:
            self.status_bar.showMessage("Select an instruction first.")
            return
        key = (va, self.image_base)
        if key in self.dbg.requested_hardware_breakpoints:
            self.dbg.remove_hardware_breakpoint(va, self.image_base)
            self.status_bar.showMessage(f"Hardware breakpoint removed: 0x{va:08X}")
        else:
            self.dbg.set_hardware_breakpoint(va, self.image_base)
            self.status_bar.showMessage(f"Hardware breakpoint requested: 0x{va:08X}")
        self.refresh_breakpoint_list()

    def _selected_breakpoint_address(self):
        """Use the selected graph block, not a stale entry-point current_va."""
        for item in self.graph_view.scene.selectedItems():
            if isinstance(item, BasicBlockItem):
                return item.addr
        return self.current_va

    def refresh_breakpoint_list(self):
        self.dbg_widget.bp_list.clear()
        for bp in sorted(self.breakpoints):
            condition = self.dbg.breakpoint_conditions.get(bp, "")
            kind = "Software INT3" + (f" [{condition}]" if condition else "")
            hits = self.breakpoint_hits.get(bp, 0)
            limit = self.breakpoint_hit_limits.get(bp, 0)
            if hits or limit:
                kind += f" hits={hits}/{limit or '∞'}"
            if bp in self.breakpoint_log_only:
                kind += " [log]"
            item = QTreeWidgetItem([f"0x{bp:08X}", kind])
            self.dbg_widget.bp_list.addTopLevelItem(item)
        for va, _base in sorted(self.dbg.requested_hardware_breakpoints):
            self.dbg_widget.bp_list.addTopLevelItem(
                QTreeWidgetItem([f"0x{va:08X}", "Hardware execute"])
            )

    def remove_selected_breakpoint(self):
        item = self.dbg_widget.bp_list.currentItem()
        if not item:
            self.status_bar.showMessage("Select a breakpoint to delete.")
            return
        try:
            va = int(item.text(0), 16)
        except ValueError:
            return
        self.remove_breakpoint_at(va)
        self.dbg_widget.bp_list.takeTopLevelItem(
            self.dbg_widget.bp_list.indexOfTopLevelItem(item)
        )
        self.status_bar.showMessage(f"Breakpoint removed: 0x{va:08X}")

    def remove_breakpoint_at(self, va):
        self.breakpoints.discard(va)
        self.breakpoint_hits.pop(va, None)
        self.breakpoint_hit_limits.pop(va, None)
        self.breakpoint_log_only.discard(va)
        self.dbg.breakpoint_conditions.pop(va, None)
        self.dbg.remove_user_breakpoint(va, self.image_base)
        self.dbg.remove_hardware_breakpoint(va, self.image_base)
        self.refresh_breakpoint_list()
        for node in self.graph_view.nodes.values():
            node.update_content()

    def dbg_continue(self):
        if not self.current_binary_path:
            QMessageBox.warning(self, "Debugger", "Please load an executable (.exe) first via File -> Open.")
            return

        if not self.dbg.is_running:
            if not self.current_binary_path.lower().endswith(".exe"):
                QMessageBox.warning(self, "Debugger", "Win32 Debugger only supports launching .exe files.")
                return
            self.tab_widget.setCurrentIndex(3)
            self.dbg.start_process(self.current_binary_path)
        else:
            if self.breakpoint_box is not None:
                self.breakpoint_box.close()
                self.breakpoint_box = None
            self.dbg.resume()
            self.status_bar.showMessage("Continuing process execution...")

    def dbg_stop(self):
        self.dbg.stop()

    def closeEvent(self, event):
        # Closing the UI must also terminate the debuggee and release the
        # debug handles; otherwise the next F9 run remains attached to the
        # stale worker/process until Terminate Process is pressed manually.
        self.autosave_project()
        self.dbg.stop()
        event.accept()

    def on_dbg_state(self, message):
        message = str(message)
        self.debug_event_log.append(message)
        self.debug_event_log = self.debug_event_log[-1000:]
        if hasattr(self, "dbg_widget"):
            self.dbg_widget.append_event(message)
        if hasattr(self, "problems_view"):
            self.problems_view.append(message)
        self.status_bar.showMessage(message)

    def export_debug_event_log(self):
        if not self.debug_event_log:
            QMessageBox.information(self, "Debug Event Log", "The event log is empty.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Debug Event Log", "debug-events.log", "Log files (*.log *.txt);;All files (*)"
        )
        if path:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(self.debug_event_log) + "\n")
            self.status_bar.showMessage(f"Debug event log exported: {path}")

    def export_analysis_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Analysis", "analysis.json", "JSON files (*.json)")
        if not path:
            return
        payload = {
            "file": self.current_binary_path,
            "image_base": f"0x{self.image_base:X}",
            "functions": [
                {"address": f"0x{addr:X}", "name": self.label_for(addr, "sub")}
                for addr in sorted(self.functions)
            ],
            "breakpoints": [
                {"address": f"0x{addr:X}", "type": "software", "condition": self.dbg.breakpoint_conditions.get(addr, "")}
                for addr in sorted(self.breakpoints)
            ] + [
                {"address": f"0x{addr:X}", "type": "hardware", "condition": ""}
                for addr, _base in sorted(self.dbg.requested_hardware_breakpoints)
            ],
            "bookmarks": {f"0x{addr:X}": name for addr, name in self.bookmarks.items()},
            "call_graph": {
                f"0x{src:X}": [f"0x{dst:X}" for dst in sorted(targets)]
                for src, targets in self.call_graph.items()
            }
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        self.status_bar.showMessage(f"Analysis exported: {path}")

    def export_breakpoints_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Breakpoints", "breakpoints.csv", "CSV files (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["address", "type", "condition"])
            for addr in sorted(self.breakpoints):
                writer.writerow([f"0x{addr:X}", "software", self.dbg.breakpoint_conditions.get(addr, "")])
            for addr, _base in sorted(self.dbg.requested_hardware_breakpoints):
                writer.writerow([f"0x{addr:X}", "hardware", ""])
        self.status_bar.showMessage(f"Breakpoints exported: {path}")

    def action_search_text(self):
        if not self.raw_data:
            QMessageBox.information(self, "Search", "Please load a binary file first.")
            return
        query, ok = QInputDialog.getText(
            self, "Search Text / Address", "ASCII text, hex bytes or address:"
        )
        if not ok or not query.strip():
            return
        query = query.strip()
        matches = []
        try:
            if re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", query) and len(query.replace("0x", "")) >= 4:
                address = int(query, 16)
                self.jump_to_address(address)
                self.status_bar.showMessage(f"Address search: 0x{address:X}")
                return
            if re.fullmatch(r"(?:[0-9a-fA-F]{2}\s*)+", query):
                needle = bytes.fromhex(query)
            else:
                needle = query.encode("utf-8")
            start = 0
            while needle:
                offset = self.raw_data.find(needle, start)
                if offset < 0:
                    break
                va = self.image_base + (offset if self.is_elf else self.pe.get_rva_from_offset(offset))
                matches.append((offset, va))
                start = offset + 1
        except Exception as exc:
            QMessageBox.warning(self, "Search Error", str(exc))
            return
        if not matches:
            QMessageBox.information(self, "Search", "No matches found.")
            return
        self.jump_to_address(matches[0][1])
        self.status_bar.showMessage(f"Search matches: {len(matches)}")
        PatternResultsDialog(self, matches, query, self).exec()

    def on_dbg_registers(self, regs):
        self.dbg_widget.update_registers(regs)
        if self.watch_dialog is not None:
            self.watch_dialog.update_registers(regs)

    def on_dbg_step_finished(self, addr):
        if addr:
            display_addr = addr
            if self.dbg.is_running and self.dbg.process_info:
                remote_base = self.dbg._remote_module_base(
                    os.path.basename(self.current_binary_path)
                )
                if remote_base and addr >= remote_base:
                    display_addr = self.image_base + (addr - remote_base)
            self.show_debug_location(display_addr)
            self.status_bar.showMessage(
                f"Single-step stopped at 0x{display_addr:X}. Press F7/F8 or F9."
            )

    def on_dbg_bp_hit(self, addr):
        # The first loader breakpoint is filtered in the debugger loop. Any
        # later non-zero address is a real target INT3 or user breakpoint.
        if not addr:
            return
        # Win32Debugger emits the user breakpoint's static image VA here.
        # It is already in the address space used by the disassembly, so
        # applying ASLR conversion again would point at the wrong function.
        display_addr = self.normalize_breakpoint_address(addr)
        self.tab_widget.setCurrentIndex(0)
        self.show_debug_location(display_addr)
        if self.breakpoint_box is not None:
            self.breakpoint_box.close()
        self.breakpoint_box = QMessageBox(self)
        self.breakpoint_box.setIcon(QMessageBox.Icon.Information)
        self.breakpoint_box.setWindowTitle("Breakpoint")
        self.breakpoint_box.setText(
            f"Breakpoint hit at address: 0x{display_addr:08X}\nPress F9 to continue."
        )
        self.breakpoint_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        self.breakpoint_box.setModal(False)
        self.breakpoint_box.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.breakpoint_box.finished.connect(
            lambda _result: setattr(self, "breakpoint_box", None)
        )
        self.breakpoint_box.open()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = GandonPRO()
    win.showMaximized()
    app.processEvents()
    win.show_about_dialog()
    sys.exit(app.exec())
