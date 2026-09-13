import sys
import os
import re
import json
import urllib.request
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from capstone.x86 import X86_GRP_JUMP, X86_GRP_CALL, X86_GRP_RET

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
    QTreeWidget, QTreeWidgetItem, QSplitter, QStatusBar, QTabWidget,
    QPlainTextEdit, QGraphicsView, QGraphicsScene, QGraphicsRectItem,
    QGraphicsTextItem, QGraphicsItem, QGraphicsPathItem, QGraphicsPolygonItem,
    QDialog, QLabel, QPushButton, QInputDialog, QMessageBox
)
from PyQt6.QtGui import (
    QFont, QColor, QAction, QKeySequence, QPen, QBrush,
    QPainter, QPainterPath, QPolygonF, QCursor, QPixmap, QIcon
)
from PyQt6.QtCore import Qt, QRectF, QPointF


# =====================================================================
#                         ABOUT DIALOG
# =====================================================================

class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About")
        self.setFixedSize(520, 220)
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
            req = urllib.request.Request(
                img_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            with urllib.request.urlopen(req, timeout=3) as response:
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

        title_label = QLabel("Gandon: The Interactive Disassembler")
        title_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #ffffff; border: none;")
        info_layout.addWidget(title_label)

        ver_label = QLabel("Version Beta Windows x64")
        ver_label.setFont(QFont("Segoe UI", 10))
        ver_label.setStyleSheet("color: #cccccc; border: none;")
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
        self.resize(580, 320)
        self.target_address = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Direction", "Type", "Address / Instruction"])
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
        jump_btn.setStyleSheet("background-color: #007acc; color: white; padding: 4px 14px; border: none; border-radius: 2px;")
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
        self.setBrush(QBrush(QColor("#252526")))
        self.setZValue(1)

    def update_content(self, highlight_token=""):
        name = self.main_window.custom_names.get(self.addr, f"loc_{self.addr:08X}")
        user_comment = self.main_window.custom_comments.get(self.addr, "")

        html = f"<div style='font-family: Consolas; font-size: 11px; color: #d4d4d4;'>"
        html += f"<b style='color: #4EC9B0;'>{name}:</b>"
        if user_comment:
            html += f"<span style='color: #6A9955;'> &nbsp;// {user_comment}</span>"
        html += "<hr style='border: 0.5px solid #3c3c3c; margin: 3px 0;'/>"

        for mnem, op, comm in self.instructions:
            c_mnem = "#569CD6" if mnem.startswith("j") or mnem in ("call", "ret") else "#9CDCFE"
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


# =====================================================================
#                 GRAPH OVERVIEW (СЛЕДЯЩАЯ МИНИ-КАРТА)
# =====================================================================

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


# =====================================================================
#                 GANDON TEXT LISTING (SPACE KEY)
# =====================================================================

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


# =====================================================================
#                         HEX VIEW
# =====================================================================

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

    def load_hex(self, pe, image_base, target_va, num_lines=512):
        if not pe:
            return
        try:
            offset = pe.get_offset_from_rva(target_va - image_base)
        except Exception:
            offset = 0
            target_va = image_base

        data = pe.__data__[offset: offset + num_lines * 16]
        lines = []
        for idx in range(0, len(data), 16):
            chunk = data[idx: idx + 16]
            curr_va = target_va + idx
            p1 = " ".join([f"{b:02X}" for b in chunk[:8]]).ljust(23)
            p2 = " ".join([f"{b:02X}" for b in chunk[8:]]).ljust(23)
            ascii_str = "".join([chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk])
            lines.append(f"{curr_va:016X}  {p1}  {p2}  {ascii_str}")
        self.editor.setPlainText("\n".join(lines))


# =====================================================================
#                         САБВЬЮ ВКЛАДОК
# =====================================================================

class StringsWidget(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.raw_strings = []
        self.init_ui()

    def init_ui(self):
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

    def extract_strings(self, pe, image_base, min_len=4):
        self.raw_strings.clear()
        if not pe:
            return
        ascii_regex = re.compile(rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}")
        for section in pe.sections:
            try:
                sec_data = section.get_data()
                sec_rva = section.VirtualAddress
                for match in ascii_regex.finditer(sec_data):
                    va = image_base + sec_rva + match.start()
                    text = match.group().decode("ascii", errors="ignore")
                    self.raw_strings.append((va, len(text), "ASCII", text))
            except Exception:
                continue
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
        else:
            ep = getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)
            if ep:
                self.table.insertRow(0)
                self.table.setItem(0, 0, QTableWidgetItem(f"0x{image_base + ep:08X}"))
                self.table.setItem(0, 1, QTableWidgetItem("[main entry]"))
                self.table.setItem(0, 2, QTableWidgetItem("DllEntryPoint"))


# =====================================================================
#                         ГЛАВНОЕ ОКНО
# =====================================================================

class GandonPRO(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gandon-PRO - Disassembler")
        self.resize(1280, 800)

        self.pe = None
        self.cs = None
        self.image_base = 0
        self.current_va = 0
        self.string_lookup = {}
        self.blocks = {}
        self.edges = []
        self.xrefs_db = {}
        self.history = []

        self.custom_names = {}
        self.custom_comments = {}

        self.init_ui()
        self.apply_dark_theme()

    def init_ui(self):
        menubar = self.menuBar()

        # Меню File
        file_menu = menubar.addMenu("File")
        open_act = QAction("Open PE File...", self)
        open_act.setShortcut(QKeySequence("Ctrl+O"))
        open_act.triggered.connect(self.open_file_dialog)
        file_menu.addAction(open_act)

        save_db_act = QAction("Save Database (.gnd)...", self)
        save_db_act.setShortcut(QKeySequence("Ctrl+S"))
        save_db_act.triggered.connect(self.save_database)
        file_menu.addAction(save_db_act)

        load_db_act = QAction("Load Database (.gnd)...", self)
        load_db_act.triggered.connect(self.load_database)
        file_menu.addAction(load_db_act)

        export_png_act = QAction("Export Graph to PNG...", self)
        export_png_act.triggered.connect(self.export_graph_png)
        file_menu.addAction(export_png_act)

        file_menu.addSeparator()
        exit_act = QAction("Exit", self)
        exit_act.triggered.connect(self.close)
        file_menu.addAction(exit_act)

        # Меню Edit
        edit_menu = menubar.addMenu("Edit")
        rename_act = QAction("Rename Label", self)
        rename_act.setShortcut(QKeySequence("N"))
        rename_act.triggered.connect(self.action_rename_node)
        edit_menu.addAction(rename_act)

        comment_act = QAction("Add Comment", self)
        comment_act.setShortcut(QKeySequence(";"))
        comment_act.triggered.connect(self.action_add_comment)
        edit_menu.addAction(comment_act)

        # Меню Jump
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

        # Меню View
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

        act_hex = QAction("Hex View-1", self)
        act_hex.triggered.connect(lambda: self.tab_widget.setCurrentIndex(2))
        view_menu.addAction(act_hex)

        act_types = QAction("Local Types", self)
        act_types.triggered.connect(lambda: self.tab_widget.setCurrentIndex(3))
        view_menu.addAction(act_types)

        act_imports = QAction("Imports", self)
        act_imports.triggered.connect(lambda: self.tab_widget.setCurrentIndex(4))
        view_menu.addAction(act_imports)

        act_exports = QAction("Exports", self)
        act_exports.triggered.connect(lambda: self.tab_widget.setCurrentIndex(5))
        view_menu.addAction(act_exports)

        act_strings = QAction("Strings", self)
        act_strings.setShortcut(QKeySequence("Shift+F12"))
        act_strings.triggered.connect(lambda: self.tab_widget.setCurrentIndex(6))
        view_menu.addAction(act_strings)

        # Меню Help
        help_menu = menubar.addMenu("Help")
        about_act = QAction("About...", self)
        about_act.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_act)

        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)

        self.nav_tree = QTreeWidget()
        self.nav_tree.setHeaderLabels(["Functions / Labels", "Address"])
        self.nav_tree.setMinimumWidth(210)
        self.nav_tree.header().resizeSection(0, 150)
        self.nav_tree.itemDoubleClicked.connect(self.on_nav_item_clicked)
        self.main_splitter.addWidget(self.nav_tree)

        self.tab_widget = QTabWidget()
        self.tab_widget.setMovable(True)
        self.tab_widget.tabBar().setExpanding(True)

        self.graph_container = QWidget()
        g_layout = QVBoxLayout(self.graph_container)
        g_layout.setContentsMargins(0, 0, 0, 0)
        self.graph_view = GraphView(self)
        g_layout.addWidget(self.graph_view)

        # Интерактивная мини-карта
        self.overview = GraphOverview(self.graph_view, self.graph_view)
        self.overview.move(15, 15)

        self.tab_widget.addTab(self.graph_container, "Gandon View-A")

        self.flat_view = FlatDisasmWidget(self)
        self.tab_widget.addTab(self.flat_view, "Gandon Text Listing")

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
        self.status_bar.showMessage("Ready. Shortcuts: Space (Switch), G (Jump), X (XREFs), N (Rename), ; (Comment)")

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
            QMenu { background-color: #252526; color: #cccccc; border: 1px solid #3c3c3c; padding: 4px; }
            QMenu::item { padding: 4px 24px 4px 12px; }
            QMenu::item:selected { background-color: #007acc; color: #ffffff; }
            QMenu::shortcut { padding-left: 15px; color: #9cdcfe; }
            QTreeWidget { background-color: #252526; color: #d4d4d4; border: 1px solid #3c3c3c; }
            QTableWidget { background-color: #1e1e1e; color: #d4d4d4; border: none; gridline-color: #2a2a2a; }
            QLineEdit { background-color: #252526; color: #d4d4d4; border: 1px solid #3c3c3c; padding: 4px; font-family: Consolas; }
            QHeaderView::section { background-color: #2d2d2d; color: #9cdcfe; border: 1px solid #3c3c3c; padding: 4px; }
            QTabWidget::pane { border: 1px solid #3c3c3c; background-color: #1e1e1e; }
            QTabBar::tab { 
                background: #252526; 
                color: #969696; 
                padding: 6px 4px; 
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

    # =====================================================================
    #                         ДЕЙСТВИЯ И ХОТКЕИ
    # =====================================================================

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
        selected_nodes = self.graph_view.scene.selectedItems()
        for item in selected_nodes:
            if isinstance(item, BasicBlockItem):
                target_addr = item.addr
                break

        if target_addr is None:
            target_addr = self.current_va

        if not target_addr:
            QMessageBox.information(self, "XREFs", "Select a block to inspect cross-references.")
            return

        xrefs = self.xrefs_db.get(target_addr, [])
        name = self.custom_names.get(target_addr, f"loc_{target_addr:08X}")
        dlg = XrefsDialog(name, xrefs, self)
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
                "custom_comments": {str(k): v for k, v in self.custom_comments.items()}
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
            for node in self.graph_view.nodes.values():
                node.update_content()
            self.flat_view.populate(self.blocks)
            self.status_bar.showMessage("Database loaded.")

    # =====================================================================
    #              ПАРСИНГ PE И БЕЗОПАСНАЯ ТОЧКА ВХОДА
    # =====================================================================

    def open_file_dialog(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Windows Binary", "", "Executables (*.exe *.dll *.sys);;All Files (*)"
        )
        if file_path:
            self.load_binary(file_path)

    def is_valid_executable_va(self, va: int) -> bool:
        if not va or va <= self.image_base:
            return False
        rva = va - self.image_base
        for sec in self.pe.sections:
            v_size = getattr(sec, "Misc_VirtualSize", sec.SizeOfRawData)
            if sec.VirtualAddress <= rva < sec.VirtualAddress + v_size:
                return bool(sec.Characteristics & 0x20000000)
        return False

    def find_fallback_code_va(self) -> int:
        for sec in self.pe.sections:
            if sec.Characteristics & 0x20000000:
                return self.image_base + sec.VirtualAddress
        if self.pe.sections:
            return self.image_base + self.pe.sections[0].VirtualAddress
        return self.image_base

    def cache_strings(self):
        self.string_lookup.clear()
        if not self.pe:
            return
        ascii_regex = re.compile(rb"[\x20-\x7E]{4,}")
        for section in self.pe.sections:
            try:
                sec_data = section.get_data()
                sec_rva = section.VirtualAddress
                for match in ascii_regex.finditer(sec_data):
                    va = self.image_base + sec_rva + match.start()
                    self.string_lookup[va] = match.group().decode("ascii", errors="ignore")
            except Exception:
                continue

    def load_binary(self, path: str):
        try:
            self.pe = pefile.PE(path, fast_load=False)
        except Exception as e:
            self.status_bar.showMessage(f"PE Error: {str(e)}")
            return

        machine = getattr(self.pe.FILE_HEADER, "Machine", 0x8664)
        if machine == 0x8664:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            arch_str = "x86-64"
        else:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            arch_str = "x86-32"
        self.cs.detail = True

        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        ep_rva = getattr(self.pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)

        entry_va = self.image_base + ep_rva if ep_rva else 0
        if not self.is_valid_executable_va(entry_va):
            entry_va = self.find_fallback_code_va()

        self.status_bar.showMessage(f"Loaded: {os.path.basename(path)} | Arch: {arch_str} | Base: 0x{self.image_base:X}")

        self.cache_strings()
        self.populate_navigation(entry_va)

        self.hex_view.load_hex(self.pe, self.image_base, entry_va if entry_va else self.image_base)
        self.imports_view.load_imports(self.pe)
        self.exports_view.load_exports(self.pe, self.image_base)
        self.strings_view.extract_strings(self.pe, self.image_base)

        if entry_va:
            self.switch_to_gandon_view(entry_va)

    def switch_to_gandon_view(self, target_va: int):
        self.tab_widget.setCurrentIndex(0)
        self.jump_to_address(target_va)

    def build_cfg_graph(self, start_va: int, max_depth: int = 30):
        self.graph_view.clear_graph()
        if not self.pe or not self.cs:
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

            try:
                offset = self.pe.get_offset_from_rva(curr_va - self.image_base)
            except Exception:
                continue

            if offset >= len(self.pe.__data__):
                continue

            raw = self.pe.__data__[offset: offset + 2048]
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
                for hex_m in re.findall(r"0x[0-9a-fA-F]+", op):
                    try:
                        val = int(hex_m, 16)
                        if val in self.string_lookup:
                            comment = f'"{self.string_lookup[val]}"'
                            break
                    except ValueError:
                        continue

                insns.append((insn.mnemonic, op, comment))

                # Таблица XREFs
                for hex_m in re.findall(r"0x[0-9a-fA-F]+", op):
                    try:
                        ref_val = int(hex_m, 16)
                        xtype = "Call" if insn.group(X86_GRP_CALL) else "Jump" if insn.group(X86_GRP_JUMP) else "Data"
                        self.xrefs_db.setdefault(ref_val, []).append(("Down", xtype, insn.address, f"{insn.mnemonic} {op}"))
                    except ValueError:
                        pass

                if insn.group(X86_GRP_JUMP):
                    target = None
                    try:
                        if hasattr(insn, 'operands') and len(insn.operands) > 0:
                            if insn.operands[0].type == 2:
                                target = insn.operands[0].imm
                        if target is None and op.startswith("0x"):
                            target = int(op, 16)
                    except Exception:
                        target = None

                    if insn.mnemonic == "jmp":
                        if target and target != curr_va:
                            self.edges.append((curr_va, target, "#569CD6", "uncond"))
                            if target not in visited:
                                worklist.append(target)
                    else:
                        fallthrough = insn.address + insn.size
                        if target and target != curr_va:
                            self.edges.append((curr_va, target, "#4EC9B0", "true"))
                            if target not in visited:
                                worklist.append(target)
                        self.edges.append((curr_va, fallthrough, "#F44747", "false"))
                        if fallthrough not in visited:
                            worklist.append(fallthrough)
                    break

                elif insn.group(X86_GRP_RET):
                    break

            if insns:
                self.blocks[curr_va] = insns

        # Поуровневая раскладка
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
        coords = {}
        for lvl in sorted(layer_blocks.keys()):
            row_addrs = layer_blocks[lvl]
            row_heights = [temp_items[a].height for a in row_addrs]
            max_h = max(row_heights) if row_heights else 100

            total_row_w = sum(temp_items[a].width for a in row_addrs) + (len(row_addrs) - 1) * 110
            curr_x = -total_row_w / 2.0

            for a in row_addrs:
                node = self.graph_view.add_node(a, self.blocks[a], curr_x, curr_y)
                coords[a] = (curr_x, curr_y)
                curr_x += node.width + 110

            curr_y += max_h + 100

        for src, dst, col, e_type in self.edges:
            self.graph_view.add_edge(src, dst, col, e_type)

        self.flat_view.populate(self.blocks)

        if start_va in self.graph_view.nodes:
            self.graph_view.centerOn(self.graph_view.nodes[start_va])

        self.overview.update_viewport()

    def populate_navigation(self, entry_va: int):
        self.nav_tree.clear()
        ep_item = QTreeWidgetItem(["_start (EntryPoint)", f"0x{entry_va:08X}"])
        ep_item.setForeground(0, QColor("#4EC9B0"))
        self.nav_tree.addTopLevelItem(ep_item)

        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            imp_root = QTreeWidgetItem(["Imports", ""])
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                d_item = QTreeWidgetItem([entry.dll.decode(errors="ignore"), ""])
                for imp in entry.imports:
                    name = imp.name.decode(errors="ignore") if imp.name else f"Ordinal({imp.ordinal})"
                    addr = f"0x{imp.address:08X}" if imp.address else ""
                    d_item.addChild(QTreeWidgetItem([name, addr]))
                imp_root.addChild(d_item)
            self.nav_tree.addTopLevelItem(imp_root)

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


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = GandonPRO()
    window.showMaximized()
    app.processEvents()
    window.show_about_dialog()
    sys.exit(app.exec())
