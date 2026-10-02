"""Small out-of-process Qt host for Python plugins.

The native GUI uses a line-oriented plugin protocol for analysis helpers.  A
plugin written for the Python GUI instead exposes register(api) and creates
Qt actions/dialogs.  This host supplies that API in a separate process so the
plugin can still have a real window without embedding Python into the native
disassembler.
"""

import importlib.util
import os
import sys
import traceback
from types import SimpleNamespace

from PyQt6.QtCore import QSettings
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton,
    QStatusBar, QVBoxLayout, QWidget,
)


class ScyllaProfileDialog(QDialog):
    def __init__(self, parent, ini_path="", injector_path="", hook_path=""):
        super().__init__(parent)
        self.setWindowTitle("ScyllaHide Profile")
        self.resize(720, 210)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.ini_edit = self._path_row(
            form, "CFG (.ini):", ini_path, self._browse_ini
        )
        self.injector_edit = self._path_row(
            form, "Injector (.exe):", injector_path, self._browse_injector
        )
        self.hook_edit = self._path_row(
            form, "Hook library (.dll):", hook_path, self._browse_hook
        )
        layout.addLayout(form)
        self.validation_label = QLabel()
        self.validation_label.setWordWrap(True)
        layout.addWidget(self.validation_label)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._validate(show_success=False)

    def _path_row(self, form, label, value, browse_callback):
        edit = QLineEdit(value)
        button = QPushButton("Browse...")
        button.clicked.connect(browse_callback)
        row = QHBoxLayout()
        row.addWidget(edit, 1)
        row.addWidget(button)
        form.addRow(label, row)
        edit.textChanged.connect(lambda _text: self._validate(show_success=False))
        return edit

    def _browse_ini(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select ScyllaHide CFG", self.ini_edit.text(),
            "ScyllaHide settings (*.ini)"
        )
        if path:
            self.ini_edit.setText(path)

    def _browse_injector(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Injector", self.injector_edit.text(),
            "Executable files (*.exe)"
        )
        if path:
            self.injector_edit.setText(path)

    def _browse_hook(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Hook DLL", self.hook_edit.text(),
            "Dynamic libraries (*.dll)"
        )
        if path:
            self.hook_edit.setText(path)

    def values(self):
        return tuple(
            os.path.normpath(edit.text().strip())
            for edit in (self.ini_edit, self.injector_edit, self.hook_edit)
        )

    def _validate(self, show_success=True):
        paths = self.values()
        expected = (".ini", ".exe", ".dll")
        labels = ("CFG", "Injector", "Hook DLL")
        errors = []
        for label, path, suffix in zip(labels, paths, expected):
            if not path:
                errors.append(f"{label}: path is empty")
            elif not os.path.isfile(path):
                errors.append(f"{label}: file does not exist")
            elif os.path.splitext(path)[1].lower() != suffix:
                errors.append(f"{label}: expected {suffix}")
        if errors:
            self.validation_label.setStyleSheet("color: #d05050")
            self.validation_label.setText("\n".join(errors))
            return False
        self.validation_label.setStyleSheet("color: #48a868")
        self.validation_label.setText("All three files are valid." if show_success else "")
        return True

    def _save(self):
        if not self._validate():
            QMessageBox.warning(
                self, "ScyllaHide Profile",
                "Correct the invalid paths before saving the profile."
            )
            return
        self.accept()


class PluginAPI:
    def __init__(self, window):
        self.main_window = window
        self.plugin_record = {"actions": []}

    def add_action(self, title, callback, menu="Plugins"):
        target = self.main_window.menuBar().addMenu(menu) if menu not in self.main_window.plugin_menus else self.main_window.plugin_menus[menu]
        self.main_window.plugin_menus.setdefault(menu, target)
        action = QAction(title, self.main_window)
        action.triggered.connect(lambda _checked=False, cb=callback: cb(self))
        target.addAction(action)
        self.plugin_record["actions"].append(action)
        return action


class PluginWindow(QMainWindow):
    def __init__(self, module_name, plugin_path):
        super().__init__()
        self.plugin_menus = {}
        self.settings = QSettings("Gandon-PRO", "NativePluginHost")
        self.scylla_ini = self.settings.value("scyllahide/cfg", "", str)
        self.scylla_injector = self.settings.value("scyllahide/injector", "", str)
        self.scylla_hook = self.settings.value("scyllahide/hook", "", str)
        self.setWindowTitle(f"Gandon-PRO Python Plugin — {os.path.basename(plugin_path)}")
        self.resize(760, 460)
        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self.dbg = SimpleNamespace(process_info=None)
        body = QWidget(self)
        layout = QVBoxLayout(body)
        layout.addWidget(QLabel(f"Python plugin loaded: {os.path.basename(plugin_path)}"))
        layout.addWidget(QLabel("Use the plugin menu above to open its tools."))
        self.setCentralWidget(body)
        self.status_bar.showMessage("Plugin host ready")
        self.module_name = module_name

    def configure_scylla_profile(self):
        dialog = ScyllaProfileDialog(
            self, self.scylla_ini, self.scylla_injector, self.scylla_hook
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self.scylla_ini, self.scylla_injector, self.scylla_hook = dialog.values()
        self.settings.setValue("scyllahide/cfg", self.scylla_ini)
        self.settings.setValue("scyllahide/injector", self.scylla_injector)
        self.settings.setValue("scyllahide/hook", self.scylla_hook)
        self.settings.sync()
        self.status_bar.showMessage("ScyllaHide profile validated and saved.")

    def show_scylla_profile(self):
        if not all((self.scylla_ini, self.scylla_injector, self.scylla_hook)):
            QMessageBox.information(
                self, "ScyllaHide Profile", "No complete profile has been saved yet."
            )
            return
        QMessageBox.information(
            self, "ScyllaHide Profile",
            f"CFG: {self.scylla_ini}\n\n"
            f"Injector: {self.scylla_injector}\n\n"
            f"Hook DLL: {self.scylla_hook}"
        )

    def add_scyllahide_selection_menu(self):
        menu = self.plugin_menus.get("ScyllaHide")
        if menu is None:
            menu = self.menuBar().addMenu("ScyllaHide")
            self.plugin_menus["ScyllaHide"] = menu
        menu.addSeparator()
        profile_action = QAction("Configure Native Profile...", self)
        profile_action.triggered.connect(self.configure_scylla_profile)
        menu.addAction(profile_action)
        show_action = QAction("Show Selected Files...", self)
        show_action.triggered.connect(self.show_scylla_profile)
        menu.addAction(show_action)


def load_plugin(path):
    name = f"gandon_native_plugin_{abs(hash(os.path.abspath(path)))}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not create a Python plugin loader")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    register = getattr(module, "register", None)
    if not callable(register):
        raise RuntimeError("Plugin must expose register(api)")
    window = PluginWindow(name, path)
    register(PluginAPI(window))
    return window


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--query-font":
        print("font=Cascadia Mono")
        return 0
    if len(sys.argv) not in (2, 4, 6) or sys.argv[2] != "--pid":
        raise SystemExit("usage: plugin_window_host.py PLUGIN.py --pid PID [--pid-file PATH]")
    try:
        debug_pid = int(sys.argv[3], 0)
    except ValueError:
        raise SystemExit("PID must be an integer")
    pid_file = sys.argv[5] if len(sys.argv) == 6 and sys.argv[4] == "--pid-file" else ""
    if len(sys.argv) == 6 and not pid_file:
        raise SystemExit("usage: plugin_window_host.py PLUGIN.py --pid PID [--pid-file PATH]")
    if not debug_pid and pid_file:
        try:
            with open(pid_file, encoding="ascii") as handle:
                debug_pid = int(handle.read().strip(), 0)
        except (OSError, ValueError):
            debug_pid = 0
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    try:
        window = load_plugin(sys.argv[1])
        window.dbg.process_info = SimpleNamespace(dwProcessId=debug_pid)
    except Exception as exc:
        QMessageBox.critical(None, "Python Plugin", f"Could not load plugin:\n{exc}")
        traceback.print_exc()
        return 2
    if "scyllahide" in sys.argv[1].lower():
        window.add_scyllahide_selection_menu()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
