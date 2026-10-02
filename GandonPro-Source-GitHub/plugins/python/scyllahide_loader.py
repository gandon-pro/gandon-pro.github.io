"""Optional ScyllaHide integration for Gandon-PRO.

This is kept as a separate, manually loaded plugin. It is intentionally not
part of the core debugger startup path.
"""

import configparser
import os
import subprocess
import tempfile

from PyQt6.QtWidgets import (
    QFileDialog, QInputDialog, QMessageBox, QDialog, QVBoxLayout,
    QHBoxLayout, QLabel, QPushButton, QCheckBox, QScrollArea, QWidget, QComboBox
)


OPTIONS = [
    ("PEB", [
        ("PebBeingDebugged", "BeingDebugged"),
        ("PebHeapFlags", "Heap flags"),
        ("PebNtGlobalFlag", "NtGlobalFlag"),
        ("PebStartupInfo", "Startup info"),
        ("PebOsBuildNumber", "OS build number"),
    ]),
    ("NT API hooks", [
        ("NtQueryInformationProcessHook", "NtQueryInformationProcess"),
        ("NtQuerySystemInformationHook", "NtQuerySystemInformation"),
        ("NtQueryObjectHook", "NtQueryObject"),
        ("NtSetInformationThreadHook", "NtSetInformationThread"),
        ("NtSetInformationProcessHook", "NtSetInformationProcess"),
        ("NtCreateThreadExHook", "NtCreateThreadEx"),
        ("NtGetContextThreadHook", "NtGetContextThread"),
        ("NtSetContextThreadHook", "NtSetContextThread"),
        ("NtCloseHook", "NtClose"),
        ("NtContinueHook", "NtContinue"),
        ("NtYieldExecutionHook", "NtYieldExecution"),
        ("NtSetDebugFilterStateHook", "NtSetDebugFilterState"),
    ]),
    ("Timing / UI", [
        ("GetTickCountHook", "GetTickCount"),
        ("GetTickCount64Hook", "GetTickCount64"),
        ("GetLocalTimeHook", "GetLocalTime"),
        ("GetSystemTimeHook", "GetSystemTime"),
        ("NtQueryPerformanceCounterHook", "NtQueryPerformanceCounter"),
        ("OutputDebugStringHook", "OutputDebugString"),
        ("NtUserBlockInputHook", "BlockInput"),
        ("NtUserBuildHwndListHook", "BuildHwndList"),
        ("NtUserFindWindowExHook", "FindWindowEx"),
        ("NtUserQueryWindowHook", "QueryWindow"),
        ("NtUserGetForegroundWindowHook", "ForegroundWindow"),
    ]),
]


def choose_file(parent, title, file_filter):
    path, _ = QFileDialog.getOpenFileName(parent, title, "", file_filter)
    return path


class SettingsDialog(QDialog):
    def __init__(self, parent, ini_path):
        super().__init__(parent)
        self.setWindowTitle("ScyllaHide Options")
        self.resize(520, 620)
        self.ini_path = ini_path
        self.parser = configparser.ConfigParser()
        self.parser.optionxform = str
        self.parser.read(ini_path, encoding="utf-8")
        self.profile_names = [
            section for section in self.parser.sections()
            if section.upper() != "SETTINGS"
        ]
        self.checks = {}
        layout = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("Profile:"))
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(self.profile_names)
        current = self.parser.get("SETTINGS", "CurrentProfile", fallback="") if self.parser.has_section("SETTINGS") else ""
        if current in self.profile_names:
            self.profile_combo.setCurrentText(current)
        self.profile_combo.currentTextChanged.connect(self.load_profile)
        row.addWidget(self.profile_combo, 1)
        layout.addLayout(row)
        layout.addWidget(QLabel(f"Config: {ini_path}"))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        self.content_layout = QVBoxLayout(content)
        scroll.setWidget(content)
        layout.addWidget(scroll)
        self.load_profile(self.profile_combo.currentText())

        buttons = QHBoxLayout()
        save = QPushButton("Save Profile")
        save.clicked.connect(self.save)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        buttons.addStretch()
        buttons.addWidget(save)
        buttons.addWidget(cancel)
        layout.addLayout(buttons)

    def load_profile(self, profile_name):
        while self.content_layout.count():
            item = self.content_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self.checks.clear()
        if not profile_name or not self.parser.has_section(profile_name):
            self.content_layout.addWidget(QLabel("No ScyllaHide profiles found in this file."))
            self.content_layout.addStretch()
            return
        for section, options in OPTIONS:
            self.content_layout.addWidget(QLabel(f"<b>{section}</b>"))
            for key, label in options:
                box = QCheckBox(label)
                box.setChecked(self.parser.getboolean(profile_name, key, fallback=False))
                self.checks[key] = box
                self.content_layout.addWidget(box)
        self.content_layout.addStretch()

    def save(self):
        profile_name = self.profile_combo.currentText()
        if not profile_name:
            return
        if not self.parser.has_section("SETTINGS"):
            self.parser.add_section("SETTINGS")
        self.parser.set("SETTINGS", "CurrentProfile", profile_name)
        for key, box in self.checks.items():
            self.parser.set(profile_name, key, "1" if box.isChecked() else "0")
        with open(self.ini_path, "w", encoding="utf-8") as handle:
            self.parser.write(handle)
        self.accept()

def configure_profiles(api):
    app = api.main_window
    ini = choose_file(app, "Select scylla_hide.ini", "ScyllaHide settings (*.ini)")
    if not ini:
        return
    try:
        if SettingsDialog(app, ini).exec():
            app.status_bar.showMessage(f"ScyllaHide profile saved: {os.path.basename(ini)}")
    except OSError as exc:
        QMessageBox.warning(app, "ScyllaHide", f"Could not save settings: {exc}")


def inject_current_process(api):
    app = api.main_window
    pid = getattr(getattr(app, "dbg", None), "process_info", None)
    pid = getattr(pid, "dwProcessId", 0)
    if not pid:
        # The native GUI and this out-of-process plugin host do not share the
        # debugger object. Refresh the PID at click time so loading the plugin
        # before F9 still works.
        pid_file = os.path.join(tempfile.gettempdir(), "gandon-pro-debug.pid")
        try:
            with open(pid_file, encoding="ascii") as handle:
                pid = int(handle.read().strip(), 0)
        except (OSError, ValueError):
            pid = 0
    if not pid:
        QMessageBox.information(app, "ScyllaHide", "Start and pause the debuggee first.")
        return
    injector = choose_file(app, "Select ScyllaHide Injector", "Executable files (*.exe)")
    if not injector:
        return
    hook = choose_file(app, "Select ScyllaHide HookLibrary", "DLL files (*.dll)")
    if not hook:
        return
    try:
        result = subprocess.run(
            [injector, f"pid:{pid}", hook, "nowait"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        output = (result.stdout or result.stderr).strip()
        app.status_bar.showMessage(f"ScyllaHide injection requested for PID {pid}.")
        QMessageBox.information(app, "ScyllaHide", output or "Injection requested.")
    except (OSError, subprocess.SubprocessError) as exc:
        QMessageBox.warning(app, "ScyllaHide", f"Could not start InjectorCLI: {exc}")


def register(api):
    api.add_action("Configure Profiles...", configure_profiles, menu="ScyllaHide")
    api.add_action("Inject into Current Process...", inject_current_process, menu="ScyllaHide")
