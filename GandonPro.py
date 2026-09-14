import sys
import os
import re
import json
import struct
import threading
import ctypes
from ctypes import wintypes
import urllib.request
import pefile
from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_64, CS_MODE_32, CS_MODE_ARM
from capstone.x86 import X86_GRP_JUMP, X86_GRP_CALL, X86_GRP_RET, X86_OP_MEM, X86_REG_RIP

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
    QTreeWidget, QTreeWidgetItem, QSplitter, QStatusBar, QTabWidget,
    QPlainTextEdit, QGraphicsView, QGraphicsScene, QGraphicsRectItem,
    QGraphicsTextItem, QGraphicsItem, QGraphicsPathItem, QGraphicsPolygonItem,
    QDialog, QLabel, QPushButton, QInputDialog, QMessageBox, QMenu, QCheckBox
)
from PyQt6.QtGui import (
    QFont, QColor, QAction, QKeySequence, QPen, QBrush,
    QPainter, QPainterPath, QPolygonF, QCursor, QPixmap, QIcon
)
from PyQt6.QtCore import Qt, QRectF, QPointF, pyqtSignal, QObject


# =====================================================================
#             WIN32 DEBUGGER ENGINE (CTYPES BACKEND)
# =====================================================================

DEBUG_PROCESS = 0x00000001
CREATE_NEW_CONSOLE = 0x00000010
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_DEBUG_EVENT = 1
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2
CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER

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

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", ctypes.c_ulonglong),
        ("PebBaseAddress", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_ulonglong),
        ("BasePriority", ctypes.c_ulonglong),
        ("UniqueProcessId", ctypes.c_ulonglong),
        ("InheritedFromUniqueProcessId", ctypes.c_ulonglong)
    ]

class DebuggerSignals(QObject):
    state_changed = pyqtSignal(str)
    registers_updated = pyqtSignal(dict)
    breakpoint_hit = pyqtSignal(int)

class Win32Debugger:
    def __init__(self, signals):
        self.signals = signals
        self.k32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll
        self.process_info = None
        self.is_running = False
        self.target_path = ""
        self.worker_thread = None
        self.stealth_mode = True

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

    def start_process(self, path):
        self.target_path = path
        self.worker_thread = threading.Thread(target=self._run_debugger, daemon=True)
        self.worker_thread.start()

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
        self.signals.state_changed.emit(f"Debugger attached: PID {pi.dwProcessId}")

        debug_event = DEBUG_EVENT()
        first_bp = True

        while self.is_running:
            if not self.k32.WaitForDebugEvent(ctypes.byref(debug_event), 100):
                continue

            continue_status = DBG_CONTINUE

            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                code = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                addr = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                if self.stealth_mode:
                    self.apply_stealth_hooks()

                if code == EXCEPTION_BREAKPOINT:
                    if first_bp:
                        first_bp = False
                        self.signals.state_changed.emit("Stealth mode active: PEB & API hooks applied.")
                        self._read_context(pi.hThread)
                    else:
                        self.signals.breakpoint_hit.emit(addr or 0)
                        self._read_context(pi.hThread)

                elif code == EXCEPTION_SINGLE_STEP:
                    self._read_context(pi.hThread)

            self.k32.ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                continue_status
            )

    def _read_context(self, h_thread):
        ctx = CONTEXT64()
        ctx.ContextFlags = CONTEXT_FULL
        if self.k32.GetThreadContext(h_thread, ctypes.byref(ctx)):
            regs = {
                "RAX": hex(ctx.Rax), "RBX": hex(ctx.Rbx),
                "RCX": hex(ctx.Rcx), "RDX": hex(ctx.Rdx),
                "RSI": hex(ctx.Rsi), "RDI": hex(ctx.Rdi),
                "RSP": hex(ctx.Rsp), "RBP": hex(ctx.Rbp),
                "RIP": hex(ctx.Rip), "EFLAGS": hex(ctx.EFlags)
            }
            self.signals.registers_updated.emit(regs)

    def apply_stealth_hooks(self):
        if not self.process_info or not self.is_running:
            return False, "Target process is not running."

        h_proc = self.process_info.hProcess
        pbi = PROCESS_BASIC_INFORMATION()
        ret_len = ctypes.c_ulong(0)
        status = self.ntdll.NtQueryInformationProcess(
            h_proc, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len)
        )

        logs = []
        if status == 0 and pbi.PebBaseAddress:
            peb_addr = pbi.PebBaseAddress
            zero_byte = (ctypes.c_ubyte * 1)(0)
            zero_dword = (ctypes.c_uint32 * 1)(0)
            self.k32.WriteProcessMemory(h_proc, ctypes.c_void_p(peb_addr + 2), zero_byte, 1, None)
            self.k32.WriteProcessMemory(h_proc, ctypes.c_void_p(peb_addr + 0xBC), zero_dword, 4, None)
            logs.append("PEB.BeingDebugged -> 0")
            logs.append("PEB.NtGlobalFlag -> 0")

        patch = (ctypes.c_ubyte * 3)(0x31, 0xC0, 0xC3)
        old_prot = ctypes.c_uint32()

        for mod_name in [b"kernel32.dll", b"kernelbase.dll"]:
            h_mod = self.k32.GetModuleHandleA(mod_name)
            if h_mod:
                p_func = self.k32.GetProcAddress(h_mod, b"IsDebuggerPresent")
                if p_func:
                    self.k32.VirtualProtectEx(h_proc, ctypes.c_void_p(p_func), 3, PAGE_EXECUTE_READWRITE, ctypes.byref(old_prot))
                    self.k32.WriteProcessMemory(h_proc, ctypes.c_void_p(p_func), patch, 3, None)
                    self.k32.VirtualProtectEx(h_proc, ctypes.c_void_p(p_func), 3, old_prot.value, ctypes.byref(old_prot))

        h_k32 = self.k32.GetModuleHandleA(b"kernel32.dll")
        p_chk = self.k32.GetProcAddress(h_k32, b"CheckRemoteDebuggerPresent")
        if p_chk:
            patch_chk = (ctypes.c_ubyte * 7)(0xC7, 0x02, 0x00, 0x00, 0x00, 0x00, 0xC3)
            self.k32.VirtualProtectEx(h_proc, ctypes.c_void_p(p_chk), 7, PAGE_EXECUTE_READWRITE, ctypes.byref(old_prot))
            self.k32.WriteProcessMemory(h_proc, ctypes.c_void_p(p_chk), patch_chk, 7, None)
            self.k32.VirtualProtectEx(h_proc, ctypes.c_void_p(p_chk), 7, old_prot.value, ctypes.byref(old_prot))

        return True, "Stealth applied."

    def stop(self):
        self.is_running = False
        if self.process_info:
            self.k32.TerminateProcess(self.process_info.hProcess, 0)
            self.signals.state_changed.emit("Debug process terminated.")


# =====================================================================
#                         ABOUT DIALOG (FIXED)
# =====================================================================

class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
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

        ver_label = QLabel("Version Beta 2.0 (PE/ELF + Win32 Debugger + Anti-Debug)")
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


# =====================================================================
#                         XREFS DIALOG (KEY X)
# =====================================================================

class XrefsDialog(QDialog):
    def __init__(self, target_name, xrefs, parent=None):
        super().__init__(parent)
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
        self.setStyleSheet("QDialog { background-color: #1e1e1e; }")

    def on_select(self, item):
        row = item.row()
        self.target_address = self.xrefs_data[row][2]
        self.accept()

    def on_select_btn(self):
        row = self.table.currentRow()
        if row >= 0:
            self.target_address = self.xrefs_data[row][2]
            self.accept()


# =====================================================================
#             SIGMAKER DIALOG (SIGNATURE GENERATOR)
# =====================================================================

class SigMakerDialog(QDialog):
    def __init__(self, sig_gandon, sig_cpp_mask, count_matches, parent=None):
        super().__init__(parent)
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
        name = self.main_window.custom_names.get(self.addr, f"loc_{self.addr:08X}")
        user_comment = self.main_window.custom_comments.get(self.addr, "")

        html = f"<div style='font-family: Consolas; font-size: 11px; color: #d4d4d4;'>"
        html += f"<b style='color: #4EC9B0;'>{name}:</b>"
        if user_comment:
            html += f"<span style='color: #6A9955;'> &nbsp;// {user_comment}</span>"
        html += "<hr style='border: 0.5px solid #3c3c3c; margin: 3px 0;'/>"

        for mnem, op, comm in self.instructions:
            c_mnem = "#569CD6" if mnem.startswith("j") or mnem in ("call", "ret", "b", "bx", "bl") else "#9CDCFE"
            disp_op = op
            if highlight_token and highlight_token.lower() in op.lower():
                pattern = re.compile(re.escape(highlight_token), re.IGNORECASE)
                disp_op = pattern.sub(f"<span style='background-color:#515c6b; color:#FFE792;'>{highlight_token}</span>", op)

            html += f"<div><span style='color:{c_mnem}; font-weight:bold;'>{mnem:<6}</span> "
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

    def add_incoming_edge(self, edge):
        self.incoming_edges.append(edge)

    def add_outgoing_edge(self, edge):
        self.outgoing_edges.append(edge)

    def contextMenuEvent(self, event):
        menu = QMenu()
        act_decompile = menu.addAction("View Pseudocode (F5)")
        act_bp = menu.addAction("Toggle Breakpoint (F2)")
        act_rename = menu.addAction("Rename Label (N)")
        act_comment = menu.addAction("Add Comment (;)")
        act_sig = menu.addAction("Generate SigMaker Pattern (Ctrl+B)")
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
        elif action == act_rename:
            self.main_window.action_rename_node()
        elif action == act_comment:
            self.main_window.action_add_comment()
        elif action == act_sig:
            self.main_window.action_generate_signature()
        elif action == act_nop:
            self.main_window.action_patch_nop()
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
                border: none;
                font-family: Consolas, monospace;
            }
        """)
        layout.addWidget(self.editor)

    def populate(self, blocks):
        lines = []
        for addr in sorted(blocks.keys()):
            name = self.main_window.custom_names.get(addr, f"loc_{addr:08X}")
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

        func_name = self.main_window.custom_names.get(start_va, f"sub_{start_va:08X}")
        lines = []
        lines.append(f"// ==========================================================================")
        lines.append(f"// Decompiled by Gandon-PRO Pseudocode Engine")
        lines.append(f"// Function Entry: 0x{start_va:08X} - {func_name}")
        lines.append(f"// ==========================================================================\n")
        lines.append(f"__int64 __fastcall {func_name}(__int64 a1, __int64 a2, __int64 a3, __int64 a4)")
        lines.append("{")
        lines.append("    __int64 result = 0;")
        lines.append("    __int64 v0, v1, v2, v3;\n")

        cond_map = {
            "je": "==", "jz": "==", "jne": "!=", "jnz": "!=",
            "jg": ">", "jge": ">=", "jl": "<", "jle": "<=",
            "ja": ">", "jae": ">=", "jb": "<", "jbe": "<="
        }
        last_cmp = ("v0", "0", "==")

        for addr in sorted(blocks.keys()):
            b_name = self.main_window.custom_names.get(addr, f"loc_{addr:08X}")
            comm = self.main_window.custom_comments.get(addr, "")
            lines.append(f" {b_name}:" + (f" // {comm}" if comm else ""))

            for mnem, op, c in blocks[addr]:
                parts = [p.strip() for p in op.split(",")] if op else []

                if mnem in ("mov", "movsxd", "movzx"):
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
                        t_lbl = self.main_window.custom_names.get(t_val, f"loc_{t_val:08X}")
                    except ValueError:
                        t_lbl = target
                    lines.append(f"    if ({last_cmp[0]} {cond_op} {last_cmp[1]})")
                    lines.append(f"        goto {t_lbl};")

                elif mnem == "jmp":
                    target = parts[0] if parts else "loc_???"
                    try:
                        t_val = int(target, 16)
                        t_lbl = self.main_window.custom_names.get(t_val, f"loc_{t_val:08X}")
                    except ValueError:
                        t_lbl = target
                    lines.append(f"    goto {t_lbl};")

                elif mnem == "call":
                    target = parts[0] if parts else "sub_???"
                    call_label = f"/* {c} */" if c else ""
                    lines.append(f"    result = ((__int64 (*)(...)){target})({call_label});")

                elif mnem in ("ret", "bx lr"):
                    lines.append("    return result;")

            lines.append("")

        lines.append("    return result;")
        lines.append("}")
        self.editor.setPlainText("\n".join(lines))


class HexViewWidget(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

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
        offset = max(0, target_va - image_base)
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
        self.tree.itemClicked.connect(lambda it, c: self.editor.setPlainText(self.types_definitions.get(it.text(0), "")))
        splitter.addWidget(self.tree)
        splitter.addWidget(self.editor)
        layout.addWidget(splitter)


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
                self.table.insertRow(row)
                addr = f"0x{imp.address:08X}" if imp.address else "N/A"
                name = imp.name.decode(errors="ignore") if imp.name else f"Ordinal({imp.ordinal})"
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


class DebuggerWidget(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        layout = QHBoxLayout(self)

        self.reg_table = QTableWidget()
        self.reg_table.setColumnCount(2)
        self.reg_table.setHorizontalHeaderLabels(["Register", "Value (Hex)"])
        self.reg_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.reg_table.setStyleSheet("background: #252526; color: #4EC9B0; font-family: Consolas;")
        layout.addWidget(self.reg_table, stretch=1)

        ctrl_panel = QWidget()
        ctrl_layout = QVBoxLayout(ctrl_panel)

        self.chk_auto_antidebug = QCheckBox("Auto-Apply Anti-Debug on Start")
        self.chk_auto_antidebug.setChecked(True)
        self.chk_auto_antidebug.toggled.connect(self.on_toggle_auto_antidebug)
        self.chk_auto_antidebug.setStyleSheet("color: #4EC9B0; font-weight: bold;")
        ctrl_layout.addWidget(self.chk_auto_antidebug)

        self.btn_run = QPushButton("Run / Continue (F9)")
        self.btn_run.clicked.connect(self.main_window.dbg_continue)
        self.btn_run.setStyleSheet("background: #007acc; color: white; padding: 6px; font-weight: bold;")
        ctrl_layout.addWidget(self.btn_run)

        self.btn_antidebug = QPushButton("Apply Anti-Debug Bypass Now")
        self.btn_antidebug.clicked.connect(self.main_window.action_apply_antidebug)
        self.btn_antidebug.setStyleSheet("background: #388A34; color: white; padding: 6px;")
        ctrl_layout.addWidget(self.btn_antidebug)

        self.btn_stop = QPushButton("Terminate Process")
        self.btn_stop.clicked.connect(self.main_window.dbg_stop)
        self.btn_stop.setStyleSheet("background: #A1260D; color: white; padding: 6px;")
        ctrl_layout.addWidget(self.btn_stop)

        ctrl_layout.addWidget(QLabel("<b>Breakpoints:</b>"))
        self.bp_list = QTreeWidget()
        self.bp_list.setHeaderLabels(["Address", "Type"])
        ctrl_layout.addWidget(self.bp_list)

        layout.addWidget(ctrl_panel, stretch=2)

    def on_toggle_auto_antidebug(self, checked):
        self.main_window.dbg.stealth_mode = checked
        if hasattr(self.main_window, "act_stealth_toggle"):
            self.main_window.act_stealth_toggle.setChecked(checked)
        self.main_window.status_bar.showMessage(f"Auto Anti-Debug on start: {'ENABLED' if checked else 'DISABLED'}")

    def update_registers(self, regs_dict):
        self.reg_table.setRowCount(len(regs_dict))
        for row, (k, v) in enumerate(regs_dict.items()):
            self.reg_table.setItem(row, 0, QTableWidgetItem(k))
            self.reg_table.setItem(row, 1, QTableWidgetItem(v))


class GandonPRO(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gandon-PRO - The Interactive Disassembler & Debugger")
        self.resize(1400, 880)

        self.current_binary_path = ""
        self.raw_data = bytearray()
        self.is_elf = False
        self.pe = None
        self.cs = None
        self.image_base = 0
        self.current_va = 0
        self.string_lookup = {}
        self.blocks = {}
        self.edges = []
        self.xrefs_db = {}
        self.history = []
        self.patch_history = {}
        self.breakpoints = set()

        self.dbg_signals = DebuggerSignals()
        self.dbg = Win32Debugger(self.dbg_signals)
        self.dbg_signals.registers_updated.connect(self.on_dbg_registers)
        self.dbg_signals.state_changed.connect(lambda msg: self.status_bar.showMessage(msg))
        self.dbg_signals.breakpoint_hit.connect(self.on_dbg_bp_hit)

        self.custom_names = {}
        self.custom_comments = {}
        self.custom_colors = {}

        self.init_ui()
        self.apply_dark_theme()

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
        patch_nop_act.setShortcut(QKeySequence("F2"))
        patch_nop_act.triggered.connect(self.action_patch_nop)
        edit_menu.addAction(patch_nop_act)

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

        dbg_menu = menubar.addMenu("Debugger")
        dbg_run_act = QAction("Start / Continue Process", self)
        dbg_run_act.setShortcut(QKeySequence("F9"))
        dbg_run_act.triggered.connect(self.dbg_continue)
        dbg_menu.addAction(dbg_run_act)

        dbg_bp_act = QAction("Toggle Breakpoint", self)
        dbg_bp_act.triggered.connect(lambda: self.toggle_breakpoint(self.current_va))
        dbg_menu.addAction(dbg_bp_act)

        self.act_stealth_toggle = QAction("Auto-Stealth on Startup", self, checkable=True)
        self.act_stealth_toggle.setChecked(True)
        self.act_stealth_toggle.toggled.connect(self.on_menu_stealth_toggle)
        dbg_menu.addAction(self.act_stealth_toggle)

        antidebug_act = QAction("Apply Anti-Debug Bypass Now", self)
        antidebug_act.triggered.connect(self.action_apply_antidebug)
        dbg_menu.addAction(antidebug_act)

        dbg_stop_act = QAction("Stop Process", self)
        dbg_stop_act.triggered.connect(self.dbg_stop)
        dbg_menu.addAction(dbg_stop_act)

        view_menu = menubar.addMenu("View")
        toggle_view_act = QAction("Switch Graph / Text Listing", self)
        toggle_view_act.setShortcut(QKeySequence(Qt.Key.Key_Space))
        toggle_view_act.triggered.connect(self.toggle_graph_flat_view)
        view_menu.addAction(toggle_view_act)

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

        self.main_splitter.addWidget(self.tab_widget)
        self.main_splitter.setStretchFactor(0, 0)
        self.main_splitter.setStretchFactor(1, 1)
        self.main_splitter.setSizes([260, 1660])

        self.setCentralWidget(self.main_splitter)
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready. Shortcuts: F5 (Pseudocode), F9 (Debug Run), X (XREFs), Ctrl+B (SigMaker), Space (Switch)")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "overview") and hasattr(self, "graph_view"):
            w = self.graph_view.width()
            h = self.graph_view.height()
            self.overview.move(max(10, w - 200), max(10, h - 160))

    def apply_dark_theme(self):
        self.setStyleSheet("""
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
        """)

    def show_about_dialog(self):
        dialog = AboutDialog(self)
        if self.geometry().isValid():
            geo = self.geometry()
            x = geo.x() + (geo.width() - dialog.width()) // 2
            y = geo.y() + (geo.height() - dialog.height()) // 2
            dialog.move(x, y)
        dialog.exec()

    def on_menu_stealth_toggle(self, checked):
        self.dbg.stealth_mode = checked
        if hasattr(self, "dbg_widget"):
            self.dbg_widget.chk_auto_antidebug.setChecked(checked)

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

    def jump_to_address(self, addr):
        if self.current_va:
            self.history.append(self.current_va)
        self.current_va = addr

        if addr in self.graph_view.nodes:
            node = self.graph_view.nodes[addr]
            self.graph_view.centerOn(node)
            node.setSelected(True)
        else:
            self.build_cfg_graph(addr)

    def action_jump_back(self):
        if self.history:
            prev_va = self.history.pop()
            self.current_va = prev_va
            if prev_va in self.graph_view.nodes:
                self.graph_view.centerOn(self.graph_view.nodes[prev_va])
            else:
                self.build_cfg_graph(prev_va)

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

        name = self.custom_names.get(target_addr, f"loc_{target_addr:08X}")
        dlg = XrefsDialog(name, unique_xrefs, self)
        if dlg.exec() and dlg.target_address:
            self.jump_to_address(dlg.target_address)

    def action_rename_node(self):
        for item in self.graph_view.scene.selectedItems():
            if isinstance(item, BasicBlockItem):
                old_name = self.custom_names.get(item.addr, f"loc_{item.addr:08X}")
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

    def action_patch_nop(self):
        for item in self.graph_view.scene.selectedItems():
            if isinstance(item, BasicBlockItem):
                try:
                    offset = (item.addr - self.image_base) if self.is_elf else self.pe.get_offset_from_rva(item.addr - self.image_base)
                    for i in range(min(15, len(item.instructions) * 3)):
                        if offset + i < len(self.raw_data):
                            old = self.raw_data[offset + i]
                            self.raw_data[offset + i] = 0x90
                            self.patch_history[offset + i] = (old, 0x90)
                    if self.pe:
                        self.pe.__data__ = bytes(self.raw_data)
                    self.status_bar.showMessage(f"Patched block 0x{item.addr:08X} with NOPs. Ctrl+Alt+P to save.")
                    self.build_cfg_graph(self.current_va)
                except Exception as e:
                    QMessageBox.warning(self, "Patch Error", str(e))
                return

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
            match = reg.search(self.raw_data)
            if match:
                found_offset = match.start()
                if self.is_elf:
                    target_va = self.image_base + found_offset
                else:
                    found_rva = self.pe.get_rva_from_offset(found_offset)
                    target_va = self.image_base + found_rva
                self.jump_to_address(target_va)
                self.status_bar.showMessage(f"Pattern found at 0x{target_va:08X}")
            else:
                QMessageBox.information(self, "Pattern Search", "Pattern not found.")
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
            db_data = {
                "custom_names": {str(k): v for k, v in self.custom_names.items()},
                "custom_comments": {str(k): v for k, v in self.custom_comments.items()},
                "custom_colors": {str(k): v for k, v in self.custom_colors.items()}
            }
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(db_data, f, indent=4)
            self.status_bar.showMessage("Project database saved successfully.")

    def load_database(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Project DB", "", "Gandon DB (*.gnd)")
        if file_path:
            with open(file_path, "r", encoding="utf-8") as f:
                db_data = json.load(f)
                self.custom_names = {int(k): v for k, v in db_data.get("custom_names", {}).items()}
                self.custom_comments = {int(k): v for k, v in db_data.get("custom_comments", {}).items()}
                self.custom_colors = {int(k): v for k, v in db_data.get("custom_colors", {}).items()}
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

    def load_binary(self, path: str):
        self.current_binary_path = path
        try:
            with open(path, "rb") as f:
                self.raw_data = bytearray(f.read())
        except Exception as e:
            self.status_bar.showMessage(f"File Read Error: {e}")
            return

        self.patch_history.clear()

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

        self.cache_strings()
        self.populate_navigation(entry_va)

        self.hex_view.load_hex(self.raw_data, self.image_base, entry_va)
        if self.pe:
            self.imports_view.load_imports(self.pe)
            self.exports_view.load_exports(self.pe, self.image_base)
        self.strings_view.extract_strings(self.raw_data, self.image_base)

        self.switch_to_gandon_view(entry_va)

    def switch_to_gandon_view(self, target_va: int):
        self.tab_widget.setCurrentIndex(0)
        self.jump_to_address(target_va)

    def build_cfg_graph(self, start_va: int, max_depth: int = 35):
        self.graph_view.clear_graph()
        if not self.raw_data or not self.cs:
            return

        worklist = [start_va]
        visited = set()
        self.blocks = {}
        self.edges = []
        self.xrefs_db = {}

        while worklist and len(self.blocks) < max_depth:
            curr_va = worklist.pop(0)
            if curr_va in visited:
                continue

            offset = (curr_va - self.image_base) if self.is_elf else self.pe.get_offset_from_rva(curr_va - self.image_base)
            if offset >= len(self.raw_data):
                continue

            raw = bytes(self.raw_data[offset: offset + 2048])
            if not raw:
                continue

            insns = []
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

        if start_va in self.graph_view.nodes:
            self.graph_view.centerOn(self.graph_view.nodes[start_va])

        self.overview.update_viewport()

    def populate_navigation(self, entry_va: int):
        self.nav_tree.clear()
        ep_item = QTreeWidgetItem(["_start (EntryPoint)", f"0x{entry_va:08X}"])
        ep_item.setForeground(0, QColor("#4EC9B0"))
        self.nav_tree.addTopLevelItem(ep_item)

        if self.pe and hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            imp_root = QTreeWidgetItem(["Imports", ""])
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                d_item = QTreeWidgetItem([entry.dll.decode(errors="ignore"), ""])
                for imp in entry.imports:
                    name = imp.name.decode(errors="ignore") if imp.name else f"Ordinal({imp.ordinal})"
                    addr = f"0x{imp.address:08X}" if imp.address else ""
                    d_item.addChild(QTreeWidgetItem([name, addr]))
                imp_root.addChild(d_item)
            self.nav_tree.addTopLevelItem(imp_root)

        if self.pe:
            sec_root = QTreeWidgetItem(["Sections", ""])
            for sec in self.pe.sections:
                s_name = sec.Name.decode(errors="ignore").strip('\x00')
                s_va = f"0x{(self.image_base + sec.VirtualAddress):08X}"
                sec_root.addChild(QTreeWidgetItem([s_name, s_va]))
            self.nav_tree.addTopLevelItem(sec_root)

        self.nav_tree.expandAll()

    def on_nav_item_clicked(self, item, col):
        addr_str = item.text(1)
        if addr_str.startswith("0x"):
            self.jump_to_address(int(addr_str, 16))

    def toggle_breakpoint(self, va):
        if va in self.breakpoints:
            self.breakpoints.remove(va)
            self.status_bar.showMessage(f"Breakpoint removed: 0x{va:08X}")
        else:
            self.breakpoints.add(va)
            self.status_bar.showMessage(f"Breakpoint added: 0x{va:08X}")

        self.dbg_widget.bp_list.clear()
        for bp in self.breakpoints:
            self.dbg_widget.bp_list.addTopLevelItem(QTreeWidgetItem([f"0x{bp:08X}", "Software INT3"]))

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
            if self.dbg.stealth_mode:
                self.dbg.apply_stealth_hooks()
            self.status_bar.showMessage("Continuing process execution...")

    def dbg_stop(self):
        self.dbg.stop()

    def action_apply_antidebug(self):
        success, msg = self.dbg.apply_stealth_hooks()
        if success:
            QMessageBox.information(self, "Anti-Debug Bypass", f"Applied successfully:\n\n{msg}")
        else:
            QMessageBox.warning(self, "Anti-Debug Bypass", msg)

    def on_dbg_registers(self, regs):
        self.dbg_widget.update_registers(regs)

    def on_dbg_bp_hit(self, addr):
        self.tab_widget.setCurrentIndex(0)
        self.jump_to_address(addr)
        QMessageBox.information(self, "Breakpoint", f"Breakpoint Hit at address: 0x{addr:08X}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = GandonPRO()
    win.showMaximized()
    app.processEvents()
    win.show_about_dialog()
    sys.exit(app.exec())
