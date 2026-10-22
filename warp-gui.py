#!/usr/bin/env python3
import json
from http.client import HTTPException
import re
import subprocess
import sys
import time
import urllib.request
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QSystemTrayIcon, QMenu,
    QFrame, QDialog, QLineEdit, QMessageBox
)
from PyQt6.QtCore import (
    Qt, QTimer, pyqtSignal, QObject, QPropertyAnimation,
    pyqtProperty, pyqtSlot, QThread, QEasingCurve, QRectF, QPointF
)
from PyQt6.QtGui import (
    QIcon, QPixmap, QPainter, QColor, QFont, QBrush, QPen,
    QAction, QLinearGradient, QRadialGradient, QPainterPath
)

WARP_CLI = "warp-cli"
DETAILS_INTERVAL = 60
TRACE_INTERVAL = 60


def normalize_mode(mode):
    """Map the daemon's mode text to one of the GUI's supported modes."""
    if not isinstance(mode, str):
        return None

    mode = mode.strip()
    if not mode:
        return None

    if re.fullmatch(r"warpproxy\s+on\s+port\s+\d+", mode, re.IGNORECASE):
        return "Proxy"

    mode_key = mode.casefold()
    return {
        "warp": "Warp", "doh": "Doh", "dnsoverhttps": "Doh",
        "proxy": "Proxy", "warpproxy": "Proxy",
        "warp+doh": "Warp+Doh", "dot": "Dot", "dnsovertls": "Dot",
        "warp+dot": "Warp+Dot", "tunnel_only": "TunnelOnly",
        "tunnelonly": "TunnelOnly",
    }.get(mode_key)


MODE_COMMANDS = {
    "Warp": "warp", "Doh": "doh", "Proxy": "proxy",
    "Warp+Doh": "warp+doh", "Dot": "dot", "Warp+Dot": "warp+dot",
    "TunnelOnly": "tunnel_only",
}


def connection_description(mode):
    if mode in {"Doh", "Dot"}:
        return "DNS is encrypted; traffic does not use a WARP tunnel", "DNS only"
    if mode == "Proxy":
        return "Only apps using the local proxy use the WARP tunnel", "Proxy"
    if mode == "TunnelOnly":
        return "WARP tunnel is active; WARP does not manage DNS", "Tunnel"
    if mode in {"Warp", "Warp+Doh", "Warp+Dot"}:
        return "WARP tunnel is active for traffic routed through it", "Tunnel"
    return "Connected; encryption scope is unknown", "Unknown mode"


class WarpWorker(QObject):
    status_updated = pyqtSignal(dict)
    action_finished = pyqtSignal(str, bool, str)
    refresh_finished = pyqtSignal()
    trace_finished = pyqtSignal(int, dict)

    def __init__(self, cli=WARP_CLI):
        super().__init__()
        self.cli = cli
        self._details = {}
        self._details_errors = []
        self._details_checked = None

    def run_cmd(self, args, as_json=False):
        cmd = [self.cli, "--no-ansi", "--no-paginate"]
        if as_json:
            cmd.append("--json")
        cmd.extend(args)
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        except subprocess.TimeoutExpired:
            return "WARP command timed out after 8 seconds", False
        except OSError as error:
            return str(error), False
        output = res.stdout.strip()
        if res.returncode:
            return res.stderr.strip() or output or f"WARP command exited with code {res.returncode}", False
        return output, True

    def query(self, args):
        output, ok = self.run_cmd(args, as_json=True)
        if not ok:
            return {}, output
        try:
            data = json.loads(output)
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object")
            return data, ""
        except ValueError:
            return {}, "WARP returned an invalid JSON response"

    def read_status(self, force=False):
        status, error = self.query(["status"])
        state = status.get("status")
        if not isinstance(state, str) or not state:
            state = "Unknown"
            error = error or "WARP response did not include a connection status"

        if force or self._details_checked is None or time.monotonic() - self._details_checked >= DETAILS_INTERVAL:
            # Clear failed fields rather than presenting stale settings as current.
            registration, reg_error = self.query(["registration", "show"])
            settings_response, settings_error = self.query(["settings"])
            settings = settings_response.get("settings", {})
            account = registration.get("account", {})
            if not isinstance(settings, dict):
                settings = {}
            if not isinstance(account, dict):
                account = {}
            account_type = account.get("type")
            protocol = settings.get("warp_tunnel_protocol")
            self._details = {
                "account_type": account_type if isinstance(account_type, str) else None,
                "mode": normalize_mode(settings.get("operation_mode")),
                "protocol": {"masque": "MASQUE", "wireguard": "WireGuard"}.get(str(protocol).casefold()),
                "switch_locked": settings.get("switch_locked") is True,
            }
            self._details_errors = [message for message in (reg_error, settings_error) if message]
            self._details_checked = time.monotonic()

        return {**self._details, "status": state, "error": error,
                "details_error": "\n".join(self._details_errors)}

    @pyqtSlot(bool)
    def fetch_status(self, force=False):
        try:
            self.status_updated.emit(self.read_status(force))
        finally:
            self.refresh_finished.emit()

    @pyqtSlot(str, str)
    def perform_action(self, action, value):
        if action in {"connect", "disconnect"}:
            args = [action]
        elif action == "set_mode" and value in MODE_COMMANDS:
            args = ["mode", MODE_COMMANDS[value]]
        elif action == "set_protocol" and value in {"MASQUE", "WireGuard"}:
            args = ["tunnel", "protocol", "set", value]
        elif action == "license" and value.strip():
            args = ["registration", "license", value.strip()]
        else:
            self.action_finished.emit(action, False, "Invalid WARP action")
            return
        output, ok = self.run_cmd(args)
        if action == "license":
            output = output.replace(value.strip(), "[redacted]")
        self.status_updated.emit(self.read_status(force=True))
        self.action_finished.emit(action, ok, output)

    @pyqtSlot(int)
    def fetch_trace(self, generation):
        try:
            request = urllib.request.Request("https://www.cloudflare.com/cdn-cgi/trace", headers={"User-Agent": "Warp-GUI"})
            with urllib.request.urlopen(request, timeout=4) as response:
                content = response.read(16384).decode("utf-8")
            data = dict(line.split("=", 1) for line in content.splitlines() if "=" in line)
            result = {key: data.get(key, "") for key in ("colo", "ip", "warp")}
            if not result["colo"]:
                result = {"error": "Trace response did not include an edge location"}
        except (OSError, ValueError, HTTPException) as error:
            result = {"error": str(error)}
        self.trace_finished.emit(generation, result)


class CloudflareCloudIcon(QWidget):
    """Clean vector painted Cloudflare cloud symbol."""
    def __init__(self, size=32, parent=None):
        super().__init__(parent)
        self.size_val = size
        self.setFixedSize(size, int(size * 0.78))

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = float(self.width()), float(self.height())
        p.scale(w / 32.0, h / 24.0)

        path = QPainterPath()
        path.moveTo(6.5, 18.5)
        path.lineTo(25.5, 18.5)
        path.cubicTo(29.0, 18.5, 31.0, 16.0, 30.0, 13.0)
        path.cubicTo(29.5, 10.5, 27.5, 9.2, 25.0, 9.2)
        path.cubicTo(24.0, 5.5, 20.5, 3.2, 16.2, 3.2)
        path.cubicTo(12.2, 3.2, 9.2, 5.8, 8.2, 9.2)
        path.cubicTo(5.2, 9.5, 2.5, 12.0, 2.5, 14.8)
        path.cubicTo(2.5, 17.0, 4.2, 18.5, 6.5, 18.5)
        path.closeSubpath()

        grad = QLinearGradient(0, 0, 32, 24)
        grad.setColorAt(0.0, QColor("#F6821F"))
        grad.setColorAt(1.0, QColor("#FA541C"))

        p.setBrush(QBrush(grad))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawPath(path)
        p.end()


class WarpToggle(QWidget):
    """Modern smooth animated sliding toggle switch."""
    toggled = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(120, 64)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._checked = False
        self._thumb_pos = 0.0

        self._anim = QPropertyAnimation(self, b"thumb_pos", self)
        self._anim.setDuration(240)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutCubic)

    def get_thumb_pos(self) -> float:
        return self._thumb_pos

    def set_thumb_pos(self, pos: float) -> None:
        self._thumb_pos = pos
        self.update()

    thumb_pos = pyqtProperty(float, fget=get_thumb_pos, fset=set_thumb_pos)

    def isChecked(self):
        return self._checked

    def setChecked(self, checked, animate=True):
        if self._checked == checked:
            return
        self._checked = checked
        if animate:
            self._anim.stop()
            self._anim.setStartValue(self._thumb_pos)
            self._anim.setEndValue(1.0 if checked else 0.0)
            self._anim.start()
        else:
            self.thumb_pos = 1.0 if checked else 0.0

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.toggled.emit(not self._checked)
        super().mouseReleaseEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = float(self.width()), float(self.height())
        radius = h / 2.0
        thumb_radius = radius - 5.5
        t = self._thumb_pos

        off_c1 = QColor("#282B3B")
        off_c2 = QColor("#1C1E2A")
        on_c1 = QColor("#F6821F")
        on_c2 = QColor("#FA541C")

        r1 = int(off_c1.red() * (1 - t) + on_c1.red() * t)
        g1 = int(off_c1.green() * (1 - t) + on_c1.green() * t)
        b1 = int(off_c1.blue() * (1 - t) + on_c1.blue() * t)

        r2 = int(off_c2.red() * (1 - t) + on_c2.red() * t)
        g2 = int(off_c2.green() * (1 - t) + on_c2.green() * t)
        b2 = int(off_c2.blue() * (1 - t) + on_c2.blue() * t)

        gradient = QLinearGradient(0, 0, w, h)
        gradient.setColorAt(0.0, QColor(r1, g1, b1))
        gradient.setColorAt(1.0, QColor(r2, g2, b2))

        border_alpha = int(25 + 40 * t)
        painter.setBrush(QBrush(gradient))
        painter.setPen(QPen(QColor(255, 255, 255, border_alpha), 1.5))
        painter.drawRoundedRect(QRectF(1, 1, w - 2, h - 2), radius, radius)

        font = QFont("-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif", 10, QFont.Weight.Bold)
        painter.setFont(font)

        if t > 0.5:
            alpha = int(255 * (t - 0.5) * 2)
            painter.setPen(QColor(255, 255, 255, alpha))
            painter.drawText(QRectF(18, 0, radius * 1.4, h), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, "ON")
        elif t < 0.5:
            alpha = int(180 * (0.5 - t) * 2)
            painter.setPen(QColor(140, 146, 172, alpha))
            painter.drawText(QRectF(w - radius * 1.4 - 18, 0, radius * 1.4, h), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, "OFF")

        min_x = 5.5 + thumb_radius
        max_x = w - 5.5 - thumb_radius
        curr_x = min_x + (max_x - min_x) * t
        curr_y = h / 2.0

        shadow = QRadialGradient(curr_x, curr_y + 1.5, thumb_radius + 4.0)
        shadow.setColorAt(0.0, QColor(0, 0, 0, 100))
        shadow.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.setBrush(QBrush(shadow))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(QPointF(curr_x, curr_y + 1.5), thumb_radius + 3.0, thumb_radius + 3.0)

        painter.setBrush(QBrush(QColor("#FFFFFF")))
        painter.setPen(QPen(QColor(240, 240, 245), 1.0))
        painter.drawEllipse(QPointF(curr_x, curr_y), thumb_radius, thumb_radius)

        if t > 0.05:
            dot_alpha = int(230 * t)
            painter.setBrush(QBrush(QColor(246, 130, 31, dot_alpha)))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(QPointF(curr_x, curr_y), 4.5, 4.5)

        painter.end()


def make_icon(status="Disconnected", size=64):
    """Render modern transparent vector Cloudflare cloud icon for tray bar."""
    if isinstance(status, bool):
        status = "Connected" if status else "Disconnected"

    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Cloud bounding box is from x: 2.5 to 30.25 (w ~27.76), y: 3.2 to 18.5 (h ~15.3)
    target_w = size * 0.82
    scale = target_w / 27.7574
    orig_center_x = 2.5 + 27.7574 / 2.0
    orig_center_y = 3.2 + 15.3 / 2.0
    trans_x = (size / 2.0) - (orig_center_x * scale)
    trans_y = (size / 2.0) - (orig_center_y * scale) - (size * 0.02)

    p.translate(trans_x, trans_y)
    p.scale(scale, scale)

    path = QPainterPath()
    path.moveTo(6.5, 18.5)
    path.lineTo(25.5, 18.5)
    path.cubicTo(29.0, 18.5, 31.0, 16.0, 30.0, 13.0)
    path.cubicTo(29.5, 10.5, 27.5, 9.2, 25.0, 9.2)
    path.cubicTo(24.0, 5.5, 20.5, 3.2, 16.2, 3.2)
    path.cubicTo(12.2, 3.2, 9.2, 5.8, 8.2, 9.2)
    path.cubicTo(5.2, 9.5, 2.5, 12.0, 2.5, 14.8)
    path.cubicTo(2.5, 17.0, 4.2, 18.5, 6.5, 18.5)
    path.closeSubpath()

    p.setPen(Qt.PenStyle.NoPen)

    if status == "Connected":
        grad = QLinearGradient(0, 3, 32, 19)
        grad.setColorAt(0.0, QColor("#F6821F"))
        grad.setColorAt(1.0, QColor("#FA541C"))
        p.setBrush(QBrush(grad))
        p.drawPath(path)

        # Status badge indicator (emerald green)
        p.resetTransform()
        dot_r = size * 0.12
        dot_x = size - dot_r * 2 - (size * 0.04)
        dot_y = size - dot_r * 2 - (size * 0.04)
        p.setBrush(QBrush(QColor("#10B981")))
        p.setPen(QPen(QColor("#10121A"), size * 0.04))
        p.drawEllipse(QRectF(dot_x, dot_y, dot_r * 2, dot_r * 2))

    elif status == "Connecting":
        grad = QLinearGradient(0, 3, 32, 19)
        grad.setColorAt(0.0, QColor("#FBBF24"))
        grad.setColorAt(1.0, QColor("#D97706"))
        p.setBrush(QBrush(grad))
        p.drawPath(path)

        # Status badge indicator (amber)
        p.resetTransform()
        dot_r = size * 0.12
        dot_x = size - dot_r * 2 - (size * 0.04)
        dot_y = size - dot_r * 2 - (size * 0.04)
        p.setBrush(QBrush(QColor("#FBBF24")))
        p.setPen(QPen(QColor("#10121A"), size * 0.04))
        p.drawEllipse(QRectF(dot_x, dot_y, dot_r * 2, dot_r * 2))

    else:
        p.setBrush(QBrush(QColor(160, 166, 188, 175)))
        p.drawPath(path)

    p.end()
    return QIcon(pix)


class LicenseDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("WARP+ License Activation")
        self.setMinimumSize(420, 240)
        self.setStyleSheet("""
            QDialog {
                background-color: #12141D;
                color: #E2E8F0;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            }
            QLabel {
                color: #E2E8F0;
                font-size: 13px;
            }
            QLineEdit {
                background-color: #1B1E2B;
                color: #FFFFFF;
                border: 1px solid #2F3346;
                border-radius: 9px;
                padding: 10px 14px;
                font-size: 13px;
                font-family: monospace;
            }
            QLineEdit:focus {
                border: 1px solid #F6821F;
                background-color: #202434;
            }
            QPushButton#saveBtn {
                background-color: #F6821F;
                color: #FFFFFF;
                border: none;
                border-radius: 9px;
                font-weight: 700;
                padding: 9px 20px;
                font-size: 13px;
            }
            QPushButton#saveBtn:hover {
                background-color: #FA933C;
            }
            QPushButton#saveBtn:pressed {
                background-color: #DE6E0D;
            }
            QPushButton#cancelBtn {
                background-color: #1B1E2B;
                color: #9499AD;
                border: 1px solid #2F3346;
                border-radius: 9px;
                font-weight: 600;
                padding: 9px 16px;
                font-size: 13px;
            }
            QPushButton#cancelBtn:hover {
                background-color: #282C3D;
                color: #E2E8F0;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        title = QLabel("Activate WARP+ Key")
        title.setStyleSheet("font-size: 15px; font-weight: 700; color: #FFFFFF;")

        desc = QLabel("Enter your WARP+ license key:")
        desc.setStyleSheet("color: #8E95AA; font-size: 12px;")

        self.entry = QLineEdit()
        self.entry.setPlaceholderText("WARP+ license key")
        self.entry.setEchoMode(QLineEdit.EchoMode.Password)

        btn_box = QHBoxLayout()
        btn_box.setSpacing(10)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("cancelBtn")
        cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel_btn.clicked.connect(self.reject)

        save_btn = QPushButton("Activate")
        save_btn.setObjectName("saveBtn")
        save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        save_btn.clicked.connect(self.accept)

        btn_box.addStretch()
        btn_box.addWidget(cancel_btn)
        btn_box.addWidget(save_btn)

        layout.addWidget(title)
        layout.addWidget(desc)
        layout.addWidget(self.entry)
        layout.addStretch()
        layout.addLayout(btn_box)

    def get_key(self):
        return self.entry.text().strip()


class WarpMainWindow(QMainWindow):
    refresh_requested = pyqtSignal(bool)
    action_requested = pyqtSignal(str, str)
    trace_requested = pyqtSignal(int)

    def __init__(self):
        super().__init__()
        self.worker_thread = QThread(self)
        self.worker = WarpWorker()
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.finished.connect(self.worker.deleteLater)
        self.current_status = "Unknown"
        self.is_busy = False
        self._fetch_pending = False
        self._data = {}
        self._rendered_state = None
        self._rendered_account = None
        self._icon_status = None
        self._trace_generation = 0
        self._trace_pending = False
        self._trace_context = None
        self._trace_checked = None
        self._shutting_down = False

        self.init_ui()
        self.init_tray()
        self.init_signals()
        self.worker_thread.start()
        QApplication.instance().aboutToQuit.connect(self.shutdown)

        self.poll_timer = QTimer(self)
        self.poll_timer.timeout.connect(self.trigger_fetch_status)
        self.update_poll_interval()
        self.handle_status_update({"status": "Unknown"})
        self.trigger_fetch_status(force=True)

    def init_ui(self):
        self.setWindowTitle("Cloudflare WARP")
        self.setFixedSize(390, 620)
        self.setWindowIcon(make_icon("Disconnected"))

        self.setStyleSheet("""
            QMainWindow {
                background-color: #10121A;
            }
            QWidget {
                color: #CDD6F4;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            }
            QFrame#heroCard {
                background-color: #161823;
                border-radius: 20px;
                border: 1px solid #232737;
            }
            QFrame#heroCard[state="connected"] {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1E1720, stop:0.5 #281916, stop:1 #2F1B12);
                border: 1px solid #F6821F55;
            }
            QFrame#heroCard[state="connecting"] {
                background-color: #1A1D2B;
                border: 1px solid #F6821F88;
            }
            QFrame#infoCard {
                background-color: #161823;
                border-radius: 16px;
                border: 1px solid #232737;
            }
            QComboBox {
                background-color: #202434;
                color: #FFFFFF;
                border: 1px solid #2E3347;
                border-radius: 8px;
                padding: 5px 12px;
                font-size: 13px;
                font-weight: 600;
                min-width: 105px;
            }
            QComboBox:hover {
                border: 1px solid #4D5677;
                background-color: #262B3D;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox QAbstractItemView {
                background-color: #1A1D2B;
                color: #CDD6F4;
                selection-background-color: #F6821F;
                selection-color: #FFFFFF;
                border: 1px solid #2E3347;
                border-radius: 8px;
                padding: 6px;
                outline: none;
            }
            QPushButton.secondaryBtn {
                background-color: #1A1D2B;
                color: #A6ADC8;
                border-radius: 10px;
                padding: 9px 16px;
                font-size: 12px;
                font-weight: 600;
                border: 1px solid #262A3C;
            }
            QPushButton.secondaryBtn:hover {
                background-color: #24283C;
                border-color: #3B425E;
                color: #FFFFFF;
            }
            QPushButton.secondaryBtn:pressed {
                background-color: #161824;
            }
        """)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(22, 22, 22, 22)
        main_layout.setSpacing(16)

        # 1. Top Header Bar
        header = QHBoxLayout()
        header.setContentsMargins(2, 0, 2, 0)
        header.setSpacing(10)

        cloud_icon = CloudflareCloudIcon(30)

        logo_lbl = QLabel("1.1.1.1")
        logo_lbl.setStyleSheet("font-size: 24px; font-weight: 900; color: #FFFFFF; letter-spacing: 0.5px;")

        warp_badge = QLabel("WARP")
        warp_badge.setFixedHeight(20)
        warp_badge.setStyleSheet("""
            font-size: 11px;
            font-weight: 900;
            color: #FFFFFF;
            background-color: #F6821F;
            border-radius: 5px;
            padding: 2px 7px;
        """)

        header.addWidget(cloud_icon, alignment=Qt.AlignmentFlag.AlignVCenter)
        header.addWidget(logo_lbl, alignment=Qt.AlignmentFlag.AlignVCenter)
        header.addWidget(warp_badge, alignment=Qt.AlignmentFlag.AlignVCenter)
        header.addStretch()

        self.status_pill = QLabel("●  Offline")
        self.status_pill.setStyleSheet("""
            background-color: #1C1F2D;
            color: #8E95AA;
            border: 1px solid #262A3C;
            border-radius: 12px;
            padding: 4px 12px;
            font-size: 11px;
            font-weight: 700;
        """)
        header.addWidget(self.status_pill, alignment=Qt.AlignmentFlag.AlignVCenter)
        main_layout.addLayout(header)

        # 2. Main Hero Switch Card
        self.hero_card = QFrame()
        self.hero_card.setObjectName("heroCard")
        self.hero_card.setProperty("state", "disconnected")
        hero_layout = QVBoxLayout(self.hero_card)
        hero_layout.setContentsMargins(24, 28, 24, 28)
        hero_layout.setSpacing(14)
        hero_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.toggle_switch = WarpToggle()
        self.toggle_switch.toggled.connect(self.on_switch_toggled)

        self.status_title = QLabel("DISCONNECTED")
        self.status_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_title.setStyleSheet("font-size: 21px; font-weight: 900; color: #E2E8F0; letter-spacing: 1.5px;")

        self.status_desc = QLabel("Checking WARP status...")
        self.status_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_desc.setWordWrap(True)
        self.status_desc.setStyleSheet("font-size: 13px; color: #7B829A; font-weight: 500;")

        hero_layout.addWidget(self.toggle_switch, alignment=Qt.AlignmentFlag.AlignCenter)
        hero_layout.addWidget(self.status_title)
        hero_layout.addWidget(self.status_desc)
        main_layout.addWidget(self.hero_card)

        # 3. Details & Diagnostics Card
        info_card = QFrame()
        info_card.setObjectName("infoCard")
        info_layout = QVBoxLayout(info_card)
        info_layout.setContentsMargins(18, 14, 18, 14)
        info_layout.setSpacing(10)

        # Row 1: Account
        row1 = QHBoxLayout()
        lbl_acc = QLabel("Account")
        lbl_acc.setStyleSheet("color: #7B829A; font-size: 13px; font-weight: 500;")
        self.val_acc = QLabel("Unknown")
        self.val_acc.setStyleSheet("""
            background-color: #202434;
            color: #CDD6F4;
            border-radius: 6px;
            padding: 3px 10px;
            font-size: 12px;
            font-weight: 700;
            border: 1px solid #2A2F44;
        """)
        row1.addWidget(lbl_acc)
        row1.addStretch()
        row1.addWidget(self.val_acc)
        info_layout.addLayout(row1)

        sep1 = QFrame()
        sep1.setFixedHeight(1)
        sep1.setStyleSheet("background-color: #1F2232;")
        info_layout.addWidget(sep1)

        # Row 2: Mode Selector
        row2 = QHBoxLayout()
        lbl_mode = QLabel("Mode")
        lbl_mode.setStyleSheet("color: #7B829A; font-size: 13px; font-weight: 500;")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(list(MODE_COMMANDS))
        self.mode_combo.setCurrentIndex(-1)
        self.mode_combo.setPlaceholderText("Unknown")
        self.mode_combo.setCursor(Qt.CursorShape.PointingHandCursor)
        self.mode_combo.currentTextChanged.connect(self.on_mode_changed)
        row2.addWidget(lbl_mode)
        row2.addStretch()
        row2.addWidget(self.mode_combo)
        info_layout.addLayout(row2)

        sep2 = QFrame()
        sep2.setFixedHeight(1)
        sep2.setStyleSheet("background-color: #1F2232;")
        info_layout.addWidget(sep2)

        # Row 3: Protocol Selector (MASQUE vs WireGuard)
        row3 = QHBoxLayout()
        lbl_proto = QLabel("Protocol")
        lbl_proto.setStyleSheet("color: #7B829A; font-size: 13px; font-weight: 500;")
        self.proto_combo = QComboBox()
        self.proto_combo.addItems(["MASQUE", "WireGuard"])
        self.proto_combo.setCurrentIndex(-1)
        self.proto_combo.setPlaceholderText("Unknown")
        self.proto_combo.setCursor(Qt.CursorShape.PointingHandCursor)
        self.proto_combo.currentTextChanged.connect(self.on_proto_changed)
        row3.addWidget(lbl_proto)
        row3.addStretch()
        row3.addWidget(self.proto_combo)
        info_layout.addLayout(row3)

        sep3 = QFrame()
        sep3.setFixedHeight(1)
        sep3.setStyleSheet("background-color: #1F2232;")
        info_layout.addWidget(sep3)

        # Row 4: Cloudflare Trace / Edge Colo
        row4 = QHBoxLayout()
        lbl_ip = QLabel("Edge Server")
        lbl_ip.setStyleSheet("color: #7B829A; font-size: 13px; font-weight: 500;")
        self.val_ip = QLabel("Unknown")
        self.val_ip.setStyleSheet("color: #A6ADC8; font-size: 12px; font-weight: 600;")
        row4.addWidget(lbl_ip)
        row4.addStretch()
        row4.addWidget(self.val_ip)
        info_layout.addLayout(row4)

        main_layout.addWidget(info_card)

        # 4. Action Buttons Footer
        actions_layout = QHBoxLayout()
        actions_layout.setSpacing(10)

        self.license_btn = QPushButton("🔑  WARP+ License")
        self.license_btn.setProperty("class", "secondaryBtn")
        self.license_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.license_btn.clicked.connect(self.on_license_clicked)

        self.refresh_btn = QPushButton("🔄  Refresh")
        self.refresh_btn.setProperty("class", "secondaryBtn")
        self.refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.refresh_btn.clicked.connect(lambda: self.trigger_fetch_status(force=True))

        actions_layout.addWidget(self.license_btn)
        actions_layout.addWidget(self.refresh_btn)
        main_layout.addLayout(actions_layout)

    def init_tray(self):
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(make_icon("Disconnected"))
        self.tray.setToolTip("Cloudflare WARP: Disconnected")

        tray_menu = QMenu()
        tray_menu.setStyleSheet("""
            QMenu {
                background-color: #161823;
                color: #CDD6F4;
                border: 1px solid #2B2F42;
                border-radius: 10px;
                padding: 6px;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            }
            QMenu::item {
                padding: 7px 24px;
                border-radius: 6px;
                font-size: 12px;
            }
            QMenu::item:selected {
                background-color: #F6821F;
                color: #FFFFFF;
            }
            QMenu::separator {
                height: 1px;
                background: #232737;
                margin: 5px 8px;
            }
        """)

        self.tray_status_action = QAction("Status: Disconnected", self)
        self.tray_status_action.setEnabled(False)

        self.tray_toggle_action = QAction("Connect", self)
        self.tray_toggle_action.triggered.connect(self.on_tray_toggle_clicked)

        show_action = QAction("Open WARP", self)
        show_action.triggered.connect(self.show_normal)

        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(QApplication.instance().quit)

        tray_menu.addAction(self.tray_status_action)
        tray_menu.addSeparator()
        tray_menu.addAction(self.tray_toggle_action)
        tray_menu.addAction(show_action)
        tray_menu.addSeparator()
        tray_menu.addAction(quit_action)

        self.tray.setContextMenu(tray_menu)
        self.tray.activated.connect(self.on_tray_activated)
        self.tray.show()

    def init_signals(self):
        self.refresh_requested.connect(self.worker.fetch_status, Qt.ConnectionType.QueuedConnection)
        self.action_requested.connect(self.worker.perform_action, Qt.ConnectionType.QueuedConnection)
        self.trace_requested.connect(self.worker.fetch_trace, Qt.ConnectionType.QueuedConnection)
        self.worker.status_updated.connect(self.handle_status_update)
        self.worker.action_finished.connect(self.handle_action_finished)
        self.worker.refresh_finished.connect(self.handle_refresh_finished)
        self.worker.trace_finished.connect(self.handle_trace_finished)

    def update_poll_interval(self):
        interval = 1000 if self.current_status in {"Connecting", "Disconnecting"} else (5000 if self.isVisible() else 10000)
        self.poll_timer.start(interval)

    def trigger_fetch_status(self, force=False):
        if self._shutting_down or self._fetch_pending or self.is_busy:
            return
        if force:
            self.invalidate_trace()
        self._fetch_pending = True
        self.refresh_requested.emit(force)

    @pyqtSlot()
    def handle_refresh_finished(self):
        self._fetch_pending = False

    def update_controls(self):
        known = self.current_status in {"Connected", "Disconnected", "Connecting", "Disconnecting"}
        unlocked = not self._data.get("switch_locked", False)
        can_toggle = not self.is_busy and known and unlocked
        self.toggle_switch.setEnabled(can_toggle)
        self.tray_toggle_action.setEnabled(can_toggle)
        self.mode_combo.setEnabled(not self.is_busy and unlocked)
        self.proto_combo.setEnabled(not self.is_busy and unlocked)
        self.license_btn.setEnabled(not self.is_busy)
        self.refresh_btn.setEnabled(not self.is_busy)

    @pyqtSlot(dict)
    def handle_status_update(self, data):
        self._data = data
        if self.is_busy or self._shutting_down:
            return
        st = data.get("status") or "Unknown"
        error = data.get("error", "")
        mode = normalize_mode(data.get("mode"))
        self.current_status = st
        connected = st == "Connected" and not error
        connecting = st in {"Connecting", "Disconnecting"} and not error
        state_key = "connected" if connected else ("connecting" if connecting else "disconnected")
        render_key = (st, mode, error)
        if render_key != self._rendered_state:
            self._rendered_state = render_key
            if self.hero_card.property("state") != state_key:
                self.hero_card.setProperty("state", state_key)
                self.hero_card.style().unpolish(self.hero_card)
                self.hero_card.style().polish(self.hero_card)
            self.toggle_switch.setChecked(connected or st == "Connecting", animate=True)

            if connected:
                description, pill = connection_description(mode)
                title, color, desc_color = "CONNECTED", "#FFFFFF", "#FFD2B8"
                background, foreground, border = "#064E3B", "#34D399", "#059669"
            elif connecting:
                title = "CONNECTING..." if st == "Connecting" else "DISCONNECTING..."
                description, pill = "Updating network state...", st
                color, desc_color = "#F6821F", "#A6ADC8"
                background, foreground, border = "#451A03", "#FBBF24", "#D97706"
            elif st == "Disconnected" and not error:
                title, description, pill = "DISCONNECTED", "WARP is disconnected", "Offline"
                color, desc_color = "#E2E8F0", "#7B829A"
                background, foreground, border = "#1C1F2D", "#8E95AA", "#262A3C"
            else:
                title = "STATUS UNAVAILABLE" if error else "UNKNOWN STATUS"
                description = "Could not query the WARP service" if error else f"WARP reported: {st}"
                pill = "Unavailable" if error else "Unknown"
                color, desc_color = "#E2E8F0", "#7B829A"
                background, foreground, border = "#1C1F2D", "#8E95AA", "#262A3C"

            self.status_title.setText(title)
            self.status_title.setStyleSheet(f"font-size: 21px; font-weight: 900; color: {color}; letter-spacing: 1.5px;")
            self.status_desc.setText(description)
            self.status_desc.setToolTip(error)
            self.status_desc.setStyleSheet(f"font-size: 13px; color: {desc_color}; font-weight: 500;")
            self.status_pill.setText(f"●  {pill}")
            self.status_pill.setStyleSheet(f"background-color: {background}; color: {foreground}; border: 1px solid {border}; border-radius: 12px; padding: 4px 12px; font-size: 11px; font-weight: 700;")
            self.tray_toggle_action.setText("Disconnect" if connected or st == "Connecting" else "Connect")
            self.tray_status_action.setText(f"Status: {st}")
            self.tray.setToolTip(f"Cloudflare WARP: {st}" + (f" ({pill})" if connected else ""))
            self.update_poll_interval()

        icon_status = st if st in {"Connected", "Connecting"} and not error else "Disconnected"
        if icon_status != self._icon_status:
            self._icon_status = icon_status
            icon = make_icon(icon_status)
            self.setWindowIcon(icon)
            self.tray.setIcon(icon)

        account = data.get("account_type") or "Unknown"
        account = {"free": "Free", "unlimited": "WARP+"}.get(account.casefold(), account)
        if account != self._rendered_account:
            self._rendered_account = account
            self.val_acc.setText(account)
            paid = any(value in account.casefold() for value in ("warp+", "team", "unlimited"))
            background, foreground, border = ("#451A03", "#FBBF24", "#D97706") if paid else ("#202434", "#CDD6F4", "#2A2F44")
            self.val_acc.setStyleSheet(f"background-color: {background}; color: {foreground}; border-radius: 6px; padding: 3px 10px; font-size: 12px; font-weight: 700; border: 1px solid {border};")

        for combo, value in ((self.mode_combo, mode), (self.proto_combo, data.get("protocol"))):
            index = combo.findText(value, Qt.MatchFlag.MatchFixedString) if value else -1
            if combo.currentIndex() != index:
                combo.blockSignals(True)
                try:
                    combo.setCurrentIndex(index)
                finally:
                    combo.blockSignals(False)
            combo.setToolTip(data.get("details_error", ""))
        self.val_acc.setToolTip(data.get("details_error", ""))
        self.update_controls()

        context = (st, mode, data.get("protocol"), error)
        if context != self._trace_context:
            self.invalidate_trace()
            self._trace_context = context
        # A direct HTTP request does not measure traffic inside a SOCKS proxy.
        if connected and mode in {"Warp", "Warp+Doh", "Warp+Dot", "TunnelOnly"}:
            if not self._trace_pending and (self._trace_checked is None or time.monotonic() - self._trace_checked >= TRACE_INTERVAL):
                self._trace_pending = True
                self.val_ip.setText("Checking...")
                self.trace_requested.emit(self._trace_generation)
        elif connected:
            self.val_ip.setText("Direct / DNS only" if mode in {"Doh", "Dot"} else ("Local proxy" if mode == "Proxy" else "Unknown"))
        else:
            self.val_ip.setText("Offline / Direct" if st == "Disconnected" and not error else "Unknown")

    def invalidate_trace(self):
        self._trace_generation += 1
        self._trace_checked = None
        self.val_ip.setToolTip("")

    @pyqtSlot(int, dict)
    def handle_trace_finished(self, generation, result):
        self._trace_pending = False
        if generation != self._trace_generation or self.current_status != "Connected" or self.is_busy or self._shutting_down:
            # Let the current context request a fresh trace after an obsolete job.
            if not self.is_busy and not self._shutting_down:
                self.handle_status_update(self._data)
            return
        self._trace_checked = time.monotonic()
        if result.get("error"):
            self.val_ip.setText("Trace unavailable")
            self.val_ip.setToolTip(result["error"])
        else:
            label = f"{result.get('colo', 'CF')} ({result.get('ip') or 'IP unknown'})"
            self.val_ip.setText(label)
            self.val_ip.setToolTip(f"HTTP trace: warp={result.get('warp') or 'unknown'}")

    def on_switch_toggled(self, checked):
        self.trigger_toggle(checked)

    def on_tray_toggle_clicked(self):
        self.trigger_toggle(self.current_status not in {"Connected", "Connecting"})

    def begin_action(self, action, value=""):
        if self.is_busy or self._shutting_down:
            return
        self.is_busy = True
        self.invalidate_trace()
        self._rendered_state = None
        self.update_controls()
        self.status_title.setText({"connect": "CONNECTING...", "disconnect": "DISCONNECTING..."}.get(action, "UPDATING..."))
        self.status_desc.setText("Updating network state...")
        self.action_requested.emit(action, value)

    def trigger_toggle(self, should_connect):
        if self.toggle_switch.isEnabled():
            self.begin_action("connect" if should_connect else "disconnect")

    def on_mode_changed(self, mode_text):
        if mode_text in MODE_COMMANDS:
            self.begin_action("set_mode", mode_text)

    def on_proto_changed(self, proto_text):
        if proto_text in {"MASQUE", "WireGuard"}:
            self.begin_action("set_protocol", proto_text)

    def on_license_clicked(self):
        dlg = LicenseDialog(self)
        if dlg.exec() and dlg.get_key():
            self.begin_action("license", dlg.get_key())

    @pyqtSlot(str, bool, str)
    def handle_action_finished(self, action_type, success, output):
        self.is_busy = False
        if self._shutting_down:
            return
        self.handle_status_update(self._data)
        if not success:
            QMessageBox.warning(self, "WARP Action", f"Action {action_type} failed:\n{output or 'Unknown error'}")

    def shutdown(self):
        self._shutting_down = True
        self.poll_timer.stop()
        self.worker_thread.quit()
        self.worker_thread.wait()

    def showEvent(self, event):
        super().showEvent(event)
        self.update_poll_interval()
        self.trigger_fetch_status()

    def hideEvent(self, event):
        super().hideEvent(event)
        self.update_poll_interval()

    def on_tray_activated(self, reason):
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            if self.isVisible():
                self.hide()
            else:
                self.show_normal()

    def show_normal(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event):
        event.ignore()
        self.hide()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("warp-gui")
    app.setDesktopFileName("cloudflare-warp")
    app.setQuitOnLastWindowClosed(False)
    win = WarpMainWindow()
    if len(sys.argv) > 1 and sys.argv[1] == "--tray":
        pass
    else:
        win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
