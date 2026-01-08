from __future__ import annotations

import os
import time
import shutil
import string
import sys
import uuid
import subprocess
import stat
import re
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, NamedTuple
from bisect import bisect_left, bisect_right
from collections import deque

import lief
import capstone

from PySide6.QtCore import Qt, QObject, QThread, Signal, Slot, QUrl, QTimer, QItemSelectionModel, QPoint, QEventLoop
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLineEdit,
    QFileDialog,
    QMessageBox,
    QListWidget,
    QListWidgetItem,
    QInputDialog,
    QLabel,
    QSplitter,
    QTabWidget,
    QAbstractItemView,
    QMenu,
    QPlainTextEdit,
    QDialog,
    QDialogButtonBox,
    QProgressBar,
    QProgressDialog,
    QCheckBox,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QSizePolicy,
    QStackedWidget,
    QSpinBox,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QGroupBox,
)
from PySide6.QtGui import QDesktopServices, QAction, QFont, QColor, QIcon, QPainter, QPixmap

from controllers.runner import RunnerController
from config_manager import AppConfig, ConfigManager, ProjectConfig, DEFAULT_LOG_PATH
from models.run_entry import RunEntry
from models.sanitized_output import SanitizedBinaryOutput
from services.history_store import HistoryStore
from services import parser
from services.log_analyzer import collect_executed_addresses, compute_address_segments
from services.binary_sanitizer import (
    BinarySanitizer,
    InstructionMismatch,
    PreviewCancelled,
    SanitizationResult,
)


def _docker_revng_instructions(image: str = "revng/revng") -> str:
    repo = image or "revng/revng"
    return (
        "rev.ng CLI is required for sanitization but was not found on your PATH.\n\n"
        "Quick Docker-based setup using your configured image:\n"
        f"  docker pull {repo}\n"
        f"  docker run --rm -it {repo} revng --version\n\n"
        "Create a helper script (e.g., ~/bin/revng) that wraps the docker run command, then add it to PATH."
    )


HONEY_SEGMENT_MAX_GAP = 0x20
SEGMENT_EDGE_PREVIEW_LIMIT = 500
SANITIZATION_PREVIEW_ADDRESS_LIMIT = 0
SANITIZE_SEGMENT_PADDING = 0x200
SANITIZE_RUNNABLE_FIRST_SEGMENT_GAP = 0x200000
SANITIZE_RUNNABLE_FIRST_SEGMENT_PADDING = 0x2000
SANITIZE_RUNNABLE_FIRST_ICF_WINDOW = 0x400
SANITIZE_RUNNABLE_FIRST_JUMPTABLE_WINDOW = 0x800
SANITIZE_DEFAULT_ICF_WINDOW = 0x200
SANITIZE_DEFAULT_JUMPTABLE_WINDOW = 0x400
SEQUENCE_ANALYZER_MAX_BINARY_INSTRUCTIONS = 20000
SEQUENCE_ANALYZER_MAX_TRACE_MATCHES = 5000
SEQUENCE_ANALYZER_MAX_NGRAM_RESULTS = 200
PROGRESS_DIALOG_MIN_VISIBLE_SECONDS = 0.3
SEGMENT_TABLE_BATCH_SIZE = 250
SEGMENT_TABLE_BATCH_INTERVAL_MS = 5
RUN_BATCH_OUTPUT_FLUSH_INTERVAL_MS = 75
RUN_BATCH_OUTPUT_MAX_LINES_PER_FLUSH = 200
RUN_BATCH_OUTPUT_MAX_BUFFERED_LINES = 4000


_WHITESPACE_RE = re.compile(r"\s+")
_HEX_PADDING_RE = re.compile(r"0x0*([0-9a-f]+)", re.IGNORECASE)
_DECIMAL_PADDING_RE = re.compile(r"\b0+([0-9]+)\b")
_SMALL_HEX_RE = re.compile(r"0x([0-9])\b", re.IGNORECASE)


def _normalize_instruction_text(text: str | None) -> str:
    if not text:
        return ""
    lowered = text.lower()
    collapsed = _WHITESPACE_RE.sub(" ", lowered).strip()
    collapsed = re.sub(r"\s*,\s*", ",", collapsed)

    def _hex_repl(match: re.Match[str]) -> str:
        digits = match.group(1)
        stripped = digits.lstrip("0") or "0"
        return f"0x{stripped}"

    def _decimal_repl(match: re.Match[str]) -> str:
        digits = match.group(1)
        stripped = digits.lstrip("0") or "0"
        return stripped

    collapsed = _HEX_PADDING_RE.sub(_hex_repl, collapsed)
    collapsed = _DECIMAL_PADDING_RE.sub(_decimal_repl, collapsed)
    collapsed = _SMALL_HEX_RE.sub(lambda match: match.group(1), collapsed)
    # Drop all whitespace so matching logic is insensitive to spacing differences.
    collapsed = _WHITESPACE_RE.sub("", collapsed)
    return collapsed


def _yield_gui_events(counter: int, *, interval: int = 256) -> None:
    if counter % max(1, interval) != 0:
        return
    app = QApplication.instance()
    if app is None:
        return
    if QThread.currentThread() is app.thread():
        QApplication.processEvents()


def _resize_widget_to_screen(
    widget: QWidget,
    *,
    width_ratio: float = 0.8,
    height_ratio: float = 0.8,
    min_width: int = 960,
    min_height: int = 600,
) -> None:
    """Resize a dialog-scale widget to occupy a large portion of the current screen."""
    screen = widget.screen() or QApplication.primaryScreen()
    if screen is None:
        widget.resize(min_width, min_height)
        return
    geometry = screen.availableGeometry()
    width = max(int(geometry.width() * width_ratio), min_width)
    height = max(int(geometry.height() * height_ratio), min_height)
    widget.resize(width, height)


class LogIndicator(NamedTuple):
    color: str
    tooltip: str
    state: str


class ClickableIndicator(QLabel):
    clicked = Signal()

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.setCursor(Qt.PointingHandCursor)

    def mouseReleaseEvent(self, event) -> None:  # type: ignore[override]
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class BusyProgressDialog(QProgressDialog):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._pulse_timer = QTimer(self)
        self._pulse_timer.setInterval(150)
        self._pulse_timer.timeout.connect(self._pulse)
        self._pulsing = False

    def start_pulsing(self) -> None:
        if not self._pulsing:
            self._pulse_timer.start()
            self._pulsing = True

    def stop_pulsing(self) -> None:
        if self._pulsing:
            self._pulse_timer.stop()
            self._pulsing = False

    def setRange(self, minimum: int, maximum: int) -> None:  # type: ignore[override]
        super().setRange(minimum, maximum)
        if maximum <= 0:
            self.start_pulsing()
        elif self._pulsing:
            self.stop_pulsing()

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self.stop_pulsing()
        super().closeEvent(event)

    def _pulse(self) -> None:
        if self.maximum() <= 0:
            value = (self.value() + 1) % 10
            super().setValue(value)
            return
        value = (self.value() + 1) % (self.maximum() + 1)
        super().setValue(value)


class RunWorker(QObject):
    output = Signal(str)
    succeeded = Signal(str)
    failed = Signal(str)

    def __init__(
        self,
        controller: RunnerController,
        binary_path: str,
        log_path: str | None,
        module_filters: list[str] | None = None,
        unique_only: bool = False,
        use_sudo: bool = False,
        sudo_password: str | None = None,
        extra_target_args: list[str] | None = None,
        pre_run_command: str | None = None,
    ) -> None:
        super().__init__()
        self.controller = controller
        self.binary_path = binary_path
        self.log_path = log_path
        self.module_filters = list(module_filters) if module_filters else None
        self.unique_only = bool(unique_only)
        self.use_sudo = bool(use_sudo)
        self.sudo_password = sudo_password
        self.extra_target_args = list(extra_target_args) if extra_target_args else None
        self.pre_run_command = pre_run_command or None

    def run(self) -> None:  # pragma: no cover - runs in worker thread
        try:
            # Execute optional pre-run command or script before launching PIN
            if self.pre_run_command:
                from pathlib import Path as _Path
                import subprocess as _subprocess
                import os as _os
                cmd: list[str]
                try:
                    _p = _Path(self.pre_run_command)
                    if _p.exists() and _p.is_file():
                        cmd = ["bash", str(_p)]
                    else:
                        cmd = ["bash", "-lc", self.pre_run_command]
                except Exception:
                    cmd = ["bash", "-lc", self.pre_run_command]
                if self.use_sudo and self.sudo_password:
                    cmd = ["sudo", "-S", "-p", "", *cmd]
                proc = _subprocess.Popen(
                    cmd,
                    stdout=_subprocess.PIPE,
                    stderr=_subprocess.STDOUT,
                    stdin=_subprocess.PIPE if (self.use_sudo and self.sudo_password) else None,
                    text=True,
                    bufsize=1,
                    cwd=_os.getcwd(),
                )
                if self.use_sudo and self.sudo_password and proc.stdin is not None:
                    try:
                        proc.stdin.write(self.sudo_password + "\n")
                        proc.stdin.flush()
                    except BrokenPipeError:
                        pass
                    finally:
                        try:
                            proc.stdin.close()
                        except OSError:
                            pass
                assert proc.stdout is not None
                for line in proc.stdout:
                    clean = line.rstrip()
                    if clean:
                        self.output.emit(clean)
                proc.wait()
                if proc.returncode != 0:
                    raise RuntimeError("Pre-run command failed with non-zero exit status")
            result = self.controller.run_binary(
                self.binary_path,
                log_path=self.log_path,
                module_filters=self.module_filters,
                unique_only=self.unique_only,
                use_sudo=self.use_sudo,
                sudo_password=self.sudo_password,
                on_output=self.output.emit,
                extra_target_args=self.extra_target_args,
            )
            self.succeeded.emit(str(result))
        except Exception as exc:
            self.failed.emit(str(exc))


class RunProgressDialog(QDialog):
    def __init__(self, parent: QWidget, binary_label: str, on_stop: Callable[[], None] | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Creating Log")
        self.setModal(True)
        self._running = True
        self._stop_callback = on_stop
        layout = QVBoxLayout(self)
        self.status_label = QLabel(f"Running {binary_label}...", self)
        self.output_view = QPlainTextEdit(self)
        self.output_view.setReadOnly(True)
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 0)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Close, self)
        self.close_button = self.buttons.button(QDialogButtonBox.Close)
        if self.close_button:
            self.close_button.setEnabled(False)
        self.stop_button = QPushButton("Stop", self)
        self.buttons.addButton(self.stop_button, QDialogButtonBox.ActionRole)
        self.stop_button.setEnabled(on_stop is not None)
        self.stop_button.clicked.connect(self._handle_stop_clicked)
        self.buttons.rejected.connect(self.reject)

        layout.addWidget(self.status_label)
        layout.addWidget(self.output_view)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.buttons)
        # Ensure stop button reflects callback availability
        if self.stop_button:
            self.stop_button.setEnabled(on_stop is not None and self._running)

    def append_output(self, text: str) -> None:
        """Append a line of text to the output view."""
        self.output_view.appendPlainText(text)

    def set_running_label(self, binary_label: str) -> None:
        """Update the dialog for a new run and prevent closing while active."""
        self._running = True
        self.status_label.setText(f"Running {binary_label}...")
        self.progress_bar.setRange(0, 0)
        if self.close_button:
            self.close_button.setEnabled(False)
        if self.stop_button:
            self.stop_button.setEnabled(self._stop_callback is not None)

    def mark_finished(self, success: bool) -> None:
        """Mark the run as finished and enable the close button."""
        self._running = False
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(1)
        if self.close_button:
            self.close_button.setEnabled(True)
        if self.stop_button:
            self.stop_button.setEnabled(False)
        if success:
            self.status_label.setText("Run completed successfully.")
        else:
            self.status_label.setText("Run failed or was stopped.")

    def reject(self) -> None:  # type: ignore[override]
        if self._running:
            return
        super().reject()

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self._running:
            event.ignore()
            return
        super().closeEvent(event)

    def _handle_stop_clicked(self) -> None:
        if not self._stop_callback:
            return
        self.stop_button.setEnabled(False)
        self.status_label.setText("Stopping run...")
        self.append_output("Stop requested. Attempting to terminate run...")
        self._stop_callback()


class ModuleSelectionDialog(QDialog):
    def __init__(
        self,
        parent: QWidget,
        binary_label: str,
        modules: list[str],
        *,
        default_log_label: str,
        filename_builder: Callable[[str], str] | None = None,
        previous_selection: list[str] | None = None,
        default_unique_only: bool = False,
        default_run_with_sudo: bool = False,
        default_pre_run_command: str | None = None,
        invocation_args: list[str] | None = None,
        is_sanitized_run: bool = False,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Select Modules — {binary_label}")
        self._previous = list(previous_selection or [])
        # Ensure any previously-recorded module filters are visible/selectable.
        extras: list[str] = []
        lowered_existing = {str(m).lower() for m in modules}
        for name in self._previous:
            if not name:
                continue
            if name.lower() in {"*", "all"}:
                continue
            if name.lower() not in lowered_existing:
                extras.append(name)
                lowered_existing.add(name.lower())
        self._modules = list(modules) + extras
        self._filename_builder = filename_builder
        self._default_pre_run_command = default_pre_run_command or ""
        self._invocation_args = list(invocation_args or [])
        self._is_sanitized_run = bool(is_sanitized_run)
        layout = QVBoxLayout(self)
        description = QLabel(
            "Choose which modules to monitor while collecting the instruction log. "
            "Capturing more modules may slow down execution but provides broader coverage.",
            self,
        )
        description.setWordWrap(True)
        layout.addWidget(description)

        invocation_group = QGroupBox("Invocation", self)
        invocation_layout = QVBoxLayout(invocation_group)
        invocation_layout.setContentsMargins(8, 8, 8, 8)
        args_text = " ".join(self._invocation_args) if self._invocation_args else "(none)"
        self.args_value = QLabel(f"Arguments: {args_text}", invocation_group)
        self.args_value.setWordWrap(True)
        invocation_layout.addWidget(self.args_value)

        self.copy_relative_checkbox: QCheckBox | None = None
        if not self._is_sanitized_run:
            self.copy_relative_checkbox = QCheckBox("Copy binary to relative path", invocation_group)
            self.copy_relative_checkbox.setToolTip(
                "Copies the target binary into this project's storage folder and runs the copied binary."
            )
            invocation_layout.addWidget(self.copy_relative_checkbox)
        layout.addWidget(invocation_group)

        name_container = QVBoxLayout()
        name_label = QLabel("Log output name", self)
        self.log_label_input = QLineEdit(default_log_label, self)
        name_container.addWidget(name_label)
        name_container.addWidget(self.log_label_input)
        self.log_filename_value = QLabel(self)
        self.log_filename_value.setStyleSheet("color: #666;")
        name_container.addWidget(self.log_filename_value)
        layout.addLayout(name_container)

        self.trace_all_checkbox = QCheckBox("Capture instructions from every loaded module (slow)", self)
        layout.addWidget(self.trace_all_checkbox)

        self.unique_only_checkbox = QCheckBox("Record each instruction address only once", self)
        self.unique_only_checkbox.setToolTip(
            "Skips duplicate addresses to keep the log focused on unique instructions."
        )
        self.unique_only_checkbox.setChecked(default_unique_only)
        layout.addWidget(self.unique_only_checkbox)

        self.run_with_sudo_checkbox = QCheckBox("Run with sudo", self)
        self.run_with_sudo_checkbox.setChecked(bool(default_run_with_sudo))
        self.run_with_sudo_checkbox.setToolTip(
            "Run the target under sudo (PIN + target as root). You will be prompted for your sudo password."
        )
        layout.addWidget(self.run_with_sudo_checkbox)

        prerun_group = QGroupBox("Pre-Run Setup", self)
        prerun_layout = QVBoxLayout(prerun_group)
        prerun_layout.setContentsMargins(8, 8, 8, 8)
        prerun_help = QLabel(
            "Pre-run setup command inherited from the project/config.",
            prerun_group,
        )
        prerun_help.setWordWrap(True)
        self._selected_pre_run_command = (self._default_pre_run_command or "").strip() or None
        self.prerun_input = QLabel(prerun_group)
        self.prerun_input.setWordWrap(True)
        self.prerun_input.setText(self._selected_pre_run_command or "(none)")
        self.prerun_input.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.prerun_input.setStyleSheet("color: #666;")
        prerun_layout.addWidget(prerun_help)
        prerun_layout.addWidget(self.prerun_input)
        layout.addWidget(prerun_group)

        self.module_list = QListWidget(self)
        self.module_list.setSelectionMode(QAbstractItemView.NoSelection)
        layout.addWidget(self.module_list)

        controls_row = QHBoxLayout()
        self.select_all_button = QPushButton("Select All", self)
        self.clear_button = QPushButton("Clear", self)
        controls_row.addWidget(self.select_all_button)
        controls_row.addWidget(self.clear_button)
        controls_row.addStretch(1)
        layout.addLayout(controls_row)

        add_row = QHBoxLayout()
        self.custom_input = QLineEdit(self)
        self.custom_input.setPlaceholderText("Add custom module name (e.g., libc.so.6)")
        self.add_button = QPushButton("Add", self)
        add_row.addWidget(self.custom_input, 1)
        add_row.addWidget(self.add_button)
        layout.addLayout(add_row)

        buttons = QDialogButtonBox(QDialogButtonBox.Cancel | QDialogButtonBox.Ok, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.log_label_input.textChanged.connect(self._handle_log_label_changed)
        self.trace_all_checkbox.toggled.connect(self._handle_trace_all_toggled)
        self.select_all_button.clicked.connect(lambda: self._set_all_items(Qt.Checked))
        self.clear_button.clicked.connect(lambda: self._set_all_items(Qt.Unchecked))
        self.add_button.clicked.connect(self._handle_add_custom)

        self._populate_list()
        self._restore_previous_selection()
        self._handle_log_label_changed(self.log_label_input.text())

        if self._is_sanitized_run:
            # Sanitized replays must mirror the recorded invocation.
            self.trace_all_checkbox.setEnabled(False)
            self.unique_only_checkbox.setEnabled(False)
            self.run_with_sudo_checkbox.setEnabled(False)
            self.module_list.setEnabled(False)
            self.select_all_button.setEnabled(False)
            self.clear_button.setEnabled(False)
            self.custom_input.setEnabled(False)
            self.add_button.setEnabled(False)

        self.resize(760, 560)

    def _populate_list(self) -> None:
        seen: set[str] = set()
        for name in self._modules:
            normalized = self._normalize_entry(name)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            item = QListWidgetItem(normalized, self.module_list)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)

    def _restore_previous_selection(self) -> None:
        if not self._previous:
            if self.module_list.count() > 0:
                self.module_list.item(0).setCheckState(Qt.Checked)
            return
        lowered = {entry.lower() for entry in self._previous}
        if any(entry in {"*", "all"} for entry in lowered):
            self.trace_all_checkbox.setChecked(True)
            return
        for row in range(self.module_list.count()):
            item = self.module_list.item(row)
            if item.text().lower() in lowered:
                item.setCheckState(Qt.Checked)

    def _set_all_items(self, state: Qt.CheckState) -> None:
        for row in range(self.module_list.count()):
            item = self.module_list.item(row)
            item.setCheckState(state)

    def _handle_trace_all_toggled(self, checked: bool) -> None:
        self.module_list.setEnabled(not checked)
        self.select_all_button.setEnabled(not checked)
        self.clear_button.setEnabled(not checked)
        self.custom_input.setEnabled(not checked)
        self.add_button.setEnabled(not checked)

    def _handle_add_custom(self) -> None:
        entry = self._normalize_entry(self.custom_input.text())
        if not entry:
            return
        if not any(self.module_list.item(row).text().lower() == entry.lower() for row in range(self.module_list.count())):
            item = QListWidgetItem(entry, self.module_list)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked)
        self.custom_input.clear()

    @staticmethod
    def _normalize_entry(value: str | None) -> str:
        text = (value or "").strip()
        return text

    def selected_modules(self) -> list[str]:
        if self.trace_all_checkbox.isChecked():
            return ["*"]
        selection: list[str] = []
        for row in range(self.module_list.count()):
            item = self.module_list.item(row)
            if item.checkState() == Qt.Checked:
                selection.append(item.text())
        return selection

    def selected_log_label(self) -> str:
        return self.log_label_input.text().strip()

    def unique_only(self) -> bool:
        return self.unique_only_checkbox.isChecked()

    def run_with_sudo(self) -> bool:
        return self.run_with_sudo_checkbox.isChecked()

    def selected_pre_run_command(self) -> str | None:
        return getattr(self, "_selected_pre_run_command", None)

    def copy_binary_to_relative_path(self) -> bool:
        if self._is_sanitized_run or self.copy_relative_checkbox is None:
            return False
        return bool(self.copy_relative_checkbox.isChecked())

    def accept(self) -> None:  # type: ignore[override]
        if not self.trace_all_checkbox.isChecked() and not self.selected_modules():
            QMessageBox.warning(self, "No modules selected", "Select at least one module or enable 'Capture every module'.")
            return
        if not self.selected_log_label():
            QMessageBox.warning(self, "Missing log name", "Provide a log output name before continuing.")
            return
        super().accept()

    def _handle_log_label_changed(self, text: str) -> None:
        if not self._filename_builder:
            self.log_filename_value.setText(text.strip() or "")
            return
        try:
            formatted = self._filename_builder(text)
        except Exception:
            formatted = text.strip()
        self.log_filename_value.setText(formatted or "")

class LogPreviewWorker(QObject):
    chunk_ready = Signal(object)
    progress = Signal(object)
    finished = Signal(bool)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(
        self,
        path: Path,
        *,
        mode: str,
        max_chars: int,
        segments: list[tuple[int, int]],
        per_segment_limit: int,
    ) -> None:
        super().__init__()
        self._path = path
        self._mode = mode
        self._max_chars = max_chars
        self._segments = list(segments)
        self._per_segment_limit = per_segment_limit
        self._stop_requested = False
        self._chunk_size = 200
        self._segment_sample_counts: dict[int, int] = {}
        self.job_id: int | None = None

    def cancel(self) -> None:
        self._stop_requested = True

    def run(self) -> None:  # pragma: no cover - executes in worker threads
        try:
            self._run_segments_mode() if self._mode == "segments" else self._run_raw_mode()
        except Exception as exc:
            if self._stop_requested:
                self.cancelled.emit()
            else:
                self.failed.emit(str(exc))

    def _run_raw_mode(self) -> None:
        lines_read = 0
        total_chars = 0
        chunk: list[str] = []
        truncated = False
        with self._path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                if self._stop_requested:
                    self.cancelled.emit()
                    return
                line = raw_line.rstrip("\n")
                chunk.append(line)
                lines_read += 1
                total_chars += len(line) + 1
                if len(chunk) >= self._chunk_size:
                    self.chunk_ready.emit(list(chunk))
                    chunk.clear()
                    self.progress.emit({"lines": lines_read})
                if self._max_chars > 0 and total_chars >= self._max_chars:
                    truncated = True
                    break
        if chunk:
            self.chunk_ready.emit(list(chunk))
            self.progress.emit({"lines": lines_read})
        self.finished.emit(truncated)

    def _run_segments_mode(self) -> None:
        segments = self._segments
        if not segments:
            self.finished.emit(False)
            return
        per_segment_limit = max(self._per_segment_limit, 1)
        pending: set[int] = set(range(len(segments)))
        headers_emitted: set[int] = set()
        starts_cache = [start for start, _ in segments]
        segment_progress = 0

        def emit_header(idx: int) -> None:
            nonlocal segment_progress
            start, end = segments[idx]
            self.chunk_ready.emit([f"Segment {idx + 1}: 0x{start:x} - 0x{end:x}"])
            segment_progress += 1
            self.progress.emit({"segments": segment_progress})

        try:
            iterator = parser.iter_log_entries(self._path)
        except Exception as exc:
            self.failed.emit(str(exc))
            return

        for parsed in iterator:
            if self._stop_requested:
                self.cancelled.emit()
                return
            address_text = parsed.get("address") if isinstance(parsed, dict) else None
            if not address_text:
                continue
            try:
                address_value = int(address_text, 16)
            except ValueError:
                continue
            pos = bisect_right(starts_cache, address_value) - 1
            if pos not in pending:
                continue
            start, end = segments[pos]
            if not (start <= address_value <= end):
                continue
            if pos not in headers_emitted:
                emit_header(pos)
                headers_emitted.add(pos)
            instruction = (parsed.get("instruction", "") if isinstance(parsed, dict) else "").strip()
            display = f"{address_text}: {instruction}" if instruction else address_text
            self.chunk_ready.emit([f"    {display}"])
            if per_segment_limit <= 1:
                pending.discard(pos)
            else:
                self._track_segment_sample(pos, per_segment_limit, pending)
            if not pending:
                break

        if self._stop_requested:
            self.cancelled.emit()
            return

        for idx in range(len(segments)):
            if idx in headers_emitted:
                continue
            emit_header(idx)
            self.chunk_ready.emit(["    <no matching instructions in this preview>"])
        self.finished.emit(False)

    def _track_segment_sample(self, idx: int, limit: int, pending: set[int]) -> None:
        current = self._segment_sample_counts.get(idx, 0) + 1
        self._segment_sample_counts[idx] = current
        if current >= limit:
            pending.discard(idx)


class SanitizationPreviewWorker(QObject):
    progress = Signal(int, int)
    info = Signal(str)
    failed = Signal(str)
    succeeded = Signal(object)
    cancelled = Signal()

    def __init__(self, log_path: Path, binary_path: Path, *, address_limit: int = 0) -> None:
        super().__init__()
        self._log_path = log_path
        self._binary_path = binary_path
        self._address_limit = max(0, address_limit)
        self._stop_requested = False

    def cancel(self) -> None:
        self._stop_requested = True

    def run(self) -> None:  # pragma: no cover - worker thread
        try:
            addresses, logged_lookup, truncated = _collect_preview_addresses(str(self._log_path), self._address_limit)
        except Exception as exc:
            self.failed.emit(f"Unable to collect preview addresses: {exc}")
            return
        if self._stop_requested:
            self.cancelled.emit()
            return
        if not addresses:
            self.info.emit("The instruction log did not contain any recognizable addresses.")
            return
        total = len(addresses)
        self.progress.emit(0, total)
        try:
            binary_obj = lief.parse(str(self._binary_path))
        except Exception as exc:
            self.failed.emit(f"Unable to parse binary for preview: {exc}")
            return
        sanitizer = BinarySanitizer()
        progress_interval = max(total // 200, 1) if total else 1
        try:
            preview_rows = sanitizer.preview_instructions(
                binary_obj,
                addresses,
                on_progress=self.progress.emit,
                should_cancel=lambda: self._stop_requested,
                progress_interval=progress_interval,
            )
        except PreviewCancelled:
            self.cancelled.emit()
            return
        except Exception as exc:
            self.failed.emit(f"Unable to disassemble preview instructions: {exc}")
            return
        combined_rows = [
            (address, binary_text, logged_lookup.get(address, "")) for address, binary_text in preview_rows
        ]
        self.succeeded.emit(
            {
                "rows": combined_rows,
                "truncated": truncated,
                "limit": self._address_limit,
                "total": total,
            }
        )


class ParentComparisonPreviewWorker(QObject):
    progress = Signal(int, int)
    info = Signal(str)
    failed = Signal(str)
    succeeded = Signal(object)
    cancelled = Signal()

    def __init__(
        self,
        log_path: Path,
        sanitized_binary_path: Path,
        parent_binary_path: Path,
        *,
        address_limit: int = 0,
        binary_offset: int = 0,
    ) -> None:
        super().__init__()
        self._log_path = log_path
        self._sanitized_path = sanitized_binary_path
        self._parent_path = parent_binary_path
        self._address_limit = max(0, address_limit)
        self._binary_offset = int(binary_offset or 0)
        self._stop_requested = False

    def cancel(self) -> None:
        self._stop_requested = True

    def run(self) -> None:  # pragma: no cover - background thread
        try:
            addresses, _, truncated = _collect_preview_addresses(str(self._log_path), self._address_limit)
        except Exception as exc:
            self.failed.emit(f"Unable to collect comparison addresses: {exc}")
            return
        if self._stop_requested:
            self.cancelled.emit()
            return
        if not addresses:
            self.info.emit("The instruction log did not contain any recognizable addresses to compare.")
            return
        trace_addresses = list(addresses)
        if self._binary_offset:
            parent_addresses = [addr - self._binary_offset for addr in trace_addresses]
        else:
            parent_addresses = trace_addresses
        total_addresses = len(trace_addresses)
        combined_total = max(total_addresses * 2, 1)
        self.progress.emit(0, combined_total)
        try:
            sanitized_binary = lief.parse(str(self._sanitized_path))
        except Exception as exc:
            self.failed.emit(f"Unable to parse sanitized binary for comparison: {exc}")
            return
        try:
            parent_binary = lief.parse(str(self._parent_path))
        except Exception as exc:
            self.failed.emit(f"Unable to parse parent binary for comparison: {exc}")
            return
        sanitizer = BinarySanitizer()
        progress_interval = max(total_addresses // 200, 1)

        def _stage_progress(offset: int):
            def _handler(processed: int, total: int) -> None:
                if self._stop_requested:
                    return
                combined = min(offset + processed, combined_total)
                self.progress.emit(combined, combined_total)

            return _handler

        try:
            sanitized_rows = sanitizer.preview_instructions(
                sanitized_binary,
                trace_addresses,
                on_progress=_stage_progress(0),
                should_cancel=lambda: self._stop_requested,
                progress_interval=progress_interval,
            )
        except PreviewCancelled:
            self.cancelled.emit()
            return
        except Exception as exc:
            self.failed.emit(f"Unable to disassemble sanitized binary for comparison: {exc}")
            return
        if self._stop_requested:
            self.cancelled.emit()
            return
        try:
            parent_rows = sanitizer.preview_instructions(
                parent_binary,
                parent_addresses,
                on_progress=_stage_progress(total_addresses),
                should_cancel=lambda: self._stop_requested,
                progress_interval=progress_interval,
            )
        except PreviewCancelled:
            self.cancelled.emit()
            return
        except Exception as exc:
            self.failed.emit(f"Unable to disassemble parent binary for comparison: {exc}")
            return
        if self._stop_requested:
            self.cancelled.emit()
            return
        sanitized_lookup = {addr: text for addr, text in sanitized_rows}
        parent_lookup = {addr: text for addr, text in parent_rows}
        parent_by_trace: dict[int, str] = {}
        for idx, trace_addr in enumerate(trace_addresses):
            parent_addr = parent_addresses[idx] if idx < len(parent_addresses) else trace_addr
            parent_by_trace[trace_addr] = parent_lookup.get(parent_addr, "<unavailable>")
        combined_rows: list[tuple[int, str, str]] = []
        for address in trace_addresses:
            sanitized_text = sanitized_lookup.get(address, "<unavailable>")
            parent_text = parent_by_trace.get(address, "<unavailable>")
            combined_rows.append((address, sanitized_text, parent_text))
        self.progress.emit(combined_total, combined_total)
        self.succeeded.emit(
            {
                "rows": combined_rows,
                "truncated": truncated,
                "limit": self._address_limit,
                "total": total_addresses,
                "parent_addresses": parent_addresses,
            }
        )


class TraceComparisonPreviewWorker(QObject):
    progress = Signal(int, int)
    info = Signal(str)
    failed = Signal(str)
    succeeded = Signal(object)
    cancelled = Signal()

    def __init__(
        self,
        sanitized_log_path: Path,
        original_log_path: Path,
        *,
        sanitized_offset: int = 0,
        original_offset: int = 0,
        address_limit: int = 0,
    ) -> None:
        super().__init__()
        self._sanitized_log_path = sanitized_log_path
        self._original_log_path = original_log_path
        self._sanitized_offset = int(sanitized_offset or 0)
        self._original_offset = int(original_offset or 0)
        self._address_limit = max(0, address_limit)
        self._stop_requested = False

    def cancel(self) -> None:
        self._stop_requested = True

    def run(self) -> None:  # pragma: no cover - background thread
        try:
            sanitized_addresses, sanitized_lookup, sanitized_truncated = _collect_preview_addresses(
                str(self._sanitized_log_path),
                self._address_limit,
            )
        except Exception as exc:
            self.failed.emit(f"Unable to collect sanitized trace addresses: {exc}")
            return
        if self._stop_requested:
            self.cancelled.emit()
            return
        if not sanitized_addresses:
            self.info.emit("The sanitized log did not contain any recognizable instruction addresses.")
            return
        try:
            original_addresses, original_lookup, original_truncated = _collect_preview_addresses(
                str(self._original_log_path),
                self._address_limit,
            )
        except Exception as exc:
            self.failed.emit(f"Unable to collect original trace addresses: {exc}")
            return
        if self._stop_requested:
            self.cancelled.emit()
            return
        normalized_original: dict[int, str] = {}
        for address in original_addresses:
            if self._stop_requested:
                self.cancelled.emit()
                return
            normalized = address - self._original_offset
            if normalized in normalized_original:
                continue
            original_text = (original_lookup.get(address, "") or "").strip()
            normalized_original[normalized] = original_text
        total = len(sanitized_addresses)
        combined_rows: list[tuple[int, str, str]] = []
        missing_original = 0
        progress_interval = max(total // 200, 1)
        for idx, address in enumerate(sanitized_addresses, start=1):
            if self._stop_requested:
                self.cancelled.emit()
                return
            sanitized_text = (sanitized_lookup.get(address, "") or "").strip() or "<trace unavailable>"
            normalized = address - self._sanitized_offset
            original_entry = normalized_original.get(normalized)
            if original_entry is not None:
                original_text = original_entry.strip() or "<trace unavailable>"
            else:
                original_text = "<not recorded>"
                missing_original += 1
            combined_rows.append((address, sanitized_text, original_text))
            if idx == total or idx % progress_interval == 0:
                self.progress.emit(idx, total)
        self.progress.emit(total, total)
        self.succeeded.emit(
            {
                "rows": combined_rows,
                "total": total,
                "limit": self._address_limit,
                "sanitized_truncated": sanitized_truncated,
                "original_truncated": original_truncated,
                "missing_original": missing_original,
            }
        )

class GuiInvoker(QObject):
    invoke = Signal(object)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.invoke.connect(self._run_callback, Qt.QueuedConnection)

    @Slot(object)
    def _run_callback(self, callback: object) -> None:
        if callable(callback):
            callback()


class SegmentPreviewWorker(QObject):
    result_ready = Signal(object)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(
        self,
        path: Path,
        *,
        start: int,
        end: int,
        limit: int,
    ) -> None:
        super().__init__()
        self._path = path
        self._start = start
        self._end = end
        self._limit = max(limit, 1)
        self._stop_requested = False
        self.job_id: int | None = None

    def cancel(self) -> None:
        self._stop_requested = True

    def run(self) -> None:  # pragma: no cover - worker thread
        try:
            head: list[str] = []
            tail: deque[str] = deque(maxlen=self._limit)
            total = 0
            for parsed in parser.iter_log_entries(self._path):
                if self._stop_requested:
                    self.cancelled.emit()
                    return
                address_text = parsed.get("address") if isinstance(parsed, dict) else None
                if not address_text:
                    continue
                try:
                    address_value = int(address_text, 16)
                except ValueError:
                    continue
                if not (self._start <= address_value <= self._end):
                    continue
                instruction = (parsed.get("instruction", "") if isinstance(parsed, dict) else "").strip()
                display = f"{address_text}: {instruction}" if instruction else address_text
                total += 1
                if total <= self._limit:
                    head.append(display)
                else:
                    tail.append(display)
            tail_list = list(tail)
            if total <= self._limit:
                combined = head
                truncated = False
            elif total <= self._limit * 2:
                combined = head + tail_list
                truncated = False
            else:
                combined = head + ["..."] + tail_list
                truncated = True
            if self._stop_requested:
                self.cancelled.emit()
                return
            self.result_ready.emit(
                {
                    "lines": combined,
                    "total": total,
                    "truncated": truncated,
                    "start": self._start,
                    "end": self._end,
                }
            )
        except Exception as exc:
            if self._stop_requested:
                self.cancelled.emit()


class SequenceAnalyzerFindWorker(QObject):
    progress = Signal(int, int)
    succeeded = Signal(object)
    cancelled = Signal()
    failed = Signal(str)

    def __init__(
        self,
        *,
        trace_rows: list[tuple[int, str, str]],
        trace_norm: list[str],
        binary_rows: list[dict[str, object]],
        binary_start_row: int,
        sequence: list[str],
        total_positions: int,
        progress_interval: int = 256,
        max_matches: int | None = None,
    ) -> None:
        super().__init__()
        self._trace_rows = list(trace_rows)
        self._trace_norm = list(trace_norm)
        self._binary_rows = list(binary_rows)
        self._binary_start_row = binary_start_row
        self._needle = [text or "" for text in sequence]
        self._total_positions = max(total_positions, 0)
        self._progress_interval = max(progress_interval, 1)
        self._max_matches = max_matches if max_matches and max_matches > 0 else None
        self._cancel_requested = False
        if not (0 <= self._binary_start_row < len(self._binary_rows)):
            raise ValueError("Binary start row is out of range.")
        self._binary_start_addr = int(self._binary_rows[self._binary_start_row]["display"])

    def cancel(self) -> None:
        self._cancel_requested = True

    def run(self) -> None:  # pragma: no cover - worker thread
        try:
            needle = self._needle
            needle_len = len(needle)
            haystack = self._trace_norm
            matches: list[dict[str, object]] = []
            truncated = False
            if needle_len == 0 or len(haystack) < needle_len:
                self.succeeded.emit({"matches": matches, "truncated": truncated})
                return
            total_possible = max(len(haystack) - needle_len + 1, 0)
            if total_possible <= 0:
                self.succeeded.emit({"matches": matches, "truncated": truncated})
                return
            total = min(self._total_positions, total_possible) if self._total_positions else total_possible
            binary_start_addr = self._binary_start_addr
            processed = 0
            for idx in range(total):
                if self._cancel_requested:
                    self.cancelled.emit()
                    return
                window = haystack[idx : idx + needle_len]
                if window == needle:
                    trace_start_addr = int(self._trace_rows[idx][0])
                    offset = trace_start_addr - binary_start_addr
                    preview_instrs = [
                        self._trace_rows[idx + delta][2] or ""
                        for delta in range(min(needle_len, 4))
                        if idx + delta < len(self._trace_rows)
                    ]
                    preview_text = " | ".join(text or "<blank>" for text in preview_instrs)
                    matches.append(
                        {
                            "trace_row": idx,
                            "trace_start": trace_start_addr,
                            "offset": offset,
                            "preview": preview_text,
                        }
                    )
                    if self._max_matches and len(matches) >= self._max_matches:
                        truncated = True
                        processed = idx + 1
                        self.progress.emit(processed, total)
                        break
                processed = idx + 1
                if processed % self._progress_interval == 0 or processed == total:
                    self.progress.emit(processed, total)
            if processed < total:
                self.progress.emit(total, total)
            self.succeeded.emit({"matches": matches, "truncated": truncated})
        except Exception as exc:
            self.failed.emit(str(exc))


def _build_trace_preview_snippet(
    trace_rows: list[tuple[int, str, str]],
    trace_start_index: int,
    length: int,
) -> str:
    if trace_start_index < 0 or trace_start_index >= len(trace_rows):
        return ""
    limit = min(trace_start_index + max(1, length), len(trace_rows))
    parts: list[str] = []
    for idx in range(trace_start_index, limit):
        _addr, _binary, logged = trace_rows[idx]
        snippet = (logged or "").strip()
        if not snippet:
            snippet = (trace_rows[idx][1] or "").strip()
        parts.append(snippet or "<missing>")
    preview = " | ".join(parts)
    return preview[:200]


class SequenceAnalyzerNgramSelectionWorker(QObject):
    progress = Signal(int, int)
    succeeded = Signal(object)
    cancelled = Signal()
    failed = Signal(str)

    def __init__(
        self,
        *,
        matches: list[dict[str, object]],
        trace_rows: list[tuple[int, str, str]],
        binary_start_index: int,
        default_length: int,
        trace_address_filter: int | None = None,
    ) -> None:
        super().__init__()
        self._matches = list(matches)
        self._trace_rows = trace_rows
        self._start_index = binary_start_index
        self._default_length = max(1, int(default_length))
        self._trace_filter = trace_address_filter
        self._cancel_requested = False

    def cancel(self) -> None:
        self._cancel_requested = True

    def run(self) -> None:  # pragma: no cover - worker thread
        try:
            relevant = [
                match
                for match in self._matches
                if int(match.get("binary_start_index", -1)) == self._start_index
            ]
            if self._trace_filter is not None:
                target = int(self._trace_filter)
                relevant = [
                    match
                    for match in relevant
                    if int(match.get("trace_address", -1)) == target
                ]
            total = len(relevant)
            if total == 0:
                self.succeeded.emit({
                    "formatted": [],
                    "count": 0,
                    "trace_address": self._trace_filter,
                })
                return
            formatted: list[dict[str, object]] = []
            for idx, match in enumerate(relevant, start=1):
                if self._cancel_requested:
                    self.cancelled.emit()
                    return
                trace_start_idx = int(match.get("trace_start_index", -1))
                if trace_start_idx < 0:
                    if idx == total:
                        self.progress.emit(idx, total)
                    continue
                length = int(match.get("length", self._default_length))
                preview = _build_trace_preview_snippet(self._trace_rows, trace_start_idx, max(1, length))
                formatted.append(
                    {
                        "trace_start": int(match.get("trace_address", 0)),
                        "offset": int(match.get("offset", 0)),
                        "preview": preview,
                    }
                )
                if idx == total or idx % 16 == 0:
                    self.progress.emit(idx, total)
            if formatted:
                self.succeeded.emit({
                    "formatted": formatted,
                    "count": len(formatted),
                    "trace_address": self._trace_filter,
                })
            else:
                self.succeeded.emit({
                    "formatted": [],
                    "count": 0,
                    "trace_address": self._trace_filter,
                })
        except Exception as exc:
            if self._cancel_requested:
                self.cancelled.emit()
                return
            self.failed.emit(str(exc))


def _collect_preview_addresses(log_path: str, limit: int = 0) -> tuple[list[int], dict[int, str], bool]:
    address_order: list[int] = []
    logged_lookup: dict[int, str] = {}
    truncated = False
    for entry in parser.iter_log_entries(Path(log_path)):
        raw_address = entry.get("address") if isinstance(entry, dict) else None
        if not raw_address:
            continue
        try:
            address = int(raw_address, 16)
        except ValueError:
            continue
        if address in logged_lookup:
            continue
        address_order.append(address)
        instruction = entry.get("instruction", "") if isinstance(entry, dict) else ""
        logged_lookup[address] = instruction.strip()
        if limit and len(address_order) >= limit:
            truncated = True
            break
    return address_order, logged_lookup, truncated


class OffsetRecalcWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(int, int)

    def __init__(
        self,
        *,
        raw_rows: list[tuple[int, str, str]],
        segments: list[tuple[int, int]],
        offset: int,
        raw_addresses: list[int],
        sorted_values: list[int],
        sorted_pairs: list[tuple[int, int]],
    ) -> None:
        super().__init__()
        self._raw_rows = list(raw_rows)
        self._segments = list(segments)
        self._offset = offset
        self._raw_addresses = list(raw_addresses)
        self._sorted_values = list(sorted_values)
        self._sorted_pairs = list(sorted_pairs)

    def run(self) -> None:
        try:
            total = len(self._raw_rows)
            self.progress.emit(0, total)
            rows: list[tuple[int, str, str]] = []
            progress_interval = max(total // 200, 1) if total else 1
            for idx, (addr, binary_text, logged_text) in enumerate(self._raw_rows):
                rows.append((addr + self._offset, binary_text, logged_text))
                processed = idx + 1
                if processed % progress_interval == 0 or processed == total:
                    self.progress.emit(processed, total)
            match_rows = sum(
                1 for row in rows if InstructionPreviewDialog._row_state(row) == "match"
            )
            sections = InstructionPreviewDialog._build_sections(
                rows,
                self._segments,
                offset=self._offset,
                raw_addresses=self._raw_addresses,
                sorted_values=self._sorted_values,
                sorted_pairs=self._sorted_pairs,
            )
            self.finished.emit(
                {
                    "rows": rows,
                    "match_rows": match_rows,
                    "sections": sections,
                }
            )
        except Exception as exc:  # pragma: no cover - background thread
            self.failed.emit(str(exc))


class BinaryResolveWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(int, int)

    def __init__(
        self,
        rows: list[tuple[int, str, str]],
        detail_resolver: Callable[[int, str | None], str],
    ) -> None:
        super().__init__()
        self._rows = list(rows)
        self._detail_resolver = detail_resolver
        self._cancel_requested = False

    def cancel(self) -> None:
        self._cancel_requested = True

    def run(self) -> None:
        try:
            total = len(self._rows)
            updated: list[tuple[int, str, str]] = []
            interval = max(total // 200, 1) if total else 1
            self.progress.emit(0, total)
            for idx, (address, binary_text, logged_text) in enumerate(self._rows, start=1):
                if self._cancel_requested:
                    updated.extend(self._rows[idx - 1 :])
                    self.finished.emit(updated)
                    return
                resolved = self._detail_resolver(address, binary_text)
                updated.append((address, resolved, logged_text))
                if idx == total or idx % interval == 0:
                    self.progress.emit(idx, total)
            self.finished.emit(updated)
        except Exception as exc:  # pragma: no cover - defensive background work
            self.failed.emit(str(exc))


class SectionBuildWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(int, int)

    def __init__(
        self,
        rows: list[tuple[int, str, str]],
        segments: list[tuple[int, int]] | None,
        *,
        offset: int,
        raw_addresses: list[int],
        sorted_values: list[int],
        sorted_pairs: list[tuple[int, int]],
    ) -> None:
        super().__init__()
        self._rows = list(rows)
        self._segments = list(segments or [])
        self._offset = offset
        self._raw_addresses = list(raw_addresses)
        self._sorted_values = list(sorted_values)
        self._sorted_pairs = list(sorted_pairs)
        self._progress_total = len(self._segments) if self._segments else len(self._rows)

    def run(self) -> None:
        try:
            match_rows = sum(
                1 for row in self._rows if InstructionPreviewDialog._row_state(row) == "match"
            )
            def _progress_callback(current: int, total: int) -> None:
                self.progress.emit(current, max(total, 1))

            sections = InstructionPreviewDialog._build_sections(
                self._rows,
                self._segments,
                offset=self._offset,
                raw_addresses=self._raw_addresses,
                sorted_values=self._sorted_values,
                sorted_pairs=self._sorted_pairs,
                progress_callback=_progress_callback,
                progress_total=self._progress_total,
            )
            self.finished.emit({"match_rows": match_rows, "sections": sections})
        except Exception as exc:  # pragma: no cover - defensive background work
            self.failed.emit(str(exc))


class HoneyPreparationWorker(QObject):
    progress = Signal(str)
    progress_counts = Signal(int, int)
    succeeded = Signal(object)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, log_path: Path, *, max_gap: int) -> None:
        super().__init__()
        self._log_path = Path(log_path)
        self._max_gap = max_gap
        self._cancel_requested = False
        self._last_progress_report = 0

    def cancel(self) -> None:
        self._cancel_requested = True

    def run(self) -> None:
        try:
            total_entries = self._estimate_total_entries()
            if self._cancel_requested:
                self.cancelled.emit()
                return
            self.progress_counts.emit(0, total_entries)
            addresses, segments = self._collect_segments(total_entries=total_entries)
            if self._cancel_requested:
                self.cancelled.emit()
                return
            if self._cancel_requested:
                self.cancelled.emit()
                return
            self.succeeded.emit({"addresses": addresses, "segments": segments})
        except Exception as exc:  # pragma: no cover - background thread
            if self._cancel_requested:
                self.cancelled.emit()
                return
            self.failed.emit(str(exc))

    def _estimate_total_entries(self) -> int:
        try:
            total = 0
            for _ in parser.iter_log_entries(self._log_path):
                if self._cancel_requested:
                    return 0
                total += 1
                if total % 20000 == 0:
                    self.progress.emit(f"Counting instruction rows ({total} discovered)...")
            return total
        except Exception:
            return 0

    def _collect_segments(self, *, total_entries: int = 0) -> tuple[list[int], list[tuple[int, int]]]:
        self.progress.emit("Parsing instruction log...")
        seen: set[int] = set()
        addresses: list[int] = []
        processed = 0
        for entry in parser.iter_log_entries(self._log_path):
            if self._cancel_requested:
                break
            raw_address = entry.get("address") if isinstance(entry, dict) else None
            if not raw_address:
                processed += 1
                continue
            try:
                address_int = int(raw_address, 16)
            except (TypeError, ValueError):
                processed += 1
                continue
            if address_int in seen:
                processed += 1
                continue
            seen.add(address_int)
            addresses.append(address_int)
            processed += 1
            if processed % 5000 == 0:
                self.progress.emit(f"Parsed {processed} instruction rows...")
                self._emit_count_progress(processed, total_entries)
        if self._cancel_requested:
            return [], []
        self._emit_count_progress(processed, total_entries, force=True)
        addresses.sort()
        self.progress.emit("Computing contiguous segments...")
        segments: list[tuple[int, int]] = []
        if addresses:
            start = prev = addresses[0]
            for address in addresses[1:]:
                if address - prev > self._max_gap:
                    segments.append((start, prev))
                    start = address
                prev = address
            segments.append((start, prev))
        return addresses, segments

    def _emit_count_progress(self, processed: int, total: int, *, force: bool = False) -> None:
        if self._cancel_requested:
            return
        total = max(total, 0)
        if not force and processed <= self._last_progress_report:
            return
        self._last_progress_report = processed
        self.progress_counts.emit(processed, total)

class BuildWorker(QObject):
    output = Signal(str)
    succeeded = Signal()
    failed = Signal(str)

    def __init__(self, controller: RunnerController) -> None:
        super().__init__()
        self.controller = controller

    def run(self) -> None:
        try:
            self.controller.build_tool(on_output=self.output.emit)
            self.succeeded.emit()
        except Exception as exc:  # pragma: no cover - GUI background task
            self.failed.emit(str(exc))


class SanitizeWorker(QObject):
    progress = Signal(str)
    succeeded = Signal(SanitizationResult)
    failed = Signal(str)

    def __init__(
        self,
        entry_id: str,
        binary_path: Path,
        log_path: Path,
        output_path: Path,
        options: "SanitizeOptions",
        *,
        executed_addresses: set[int],
        parsed_rows: int,
        instruction_samples: list[tuple[int, str]],
        binary_offset: int = 0,
        preserve_segments: list[tuple[int, int]] | None = None,
        segment_padding: int = SANITIZE_RUNNABLE_FIRST_SEGMENT_PADDING,
    ) -> None:
        super().__init__()
        self.entry_id = entry_id
        self.binary_path = binary_path
        self.log_path = log_path
        self.output_path = output_path
        self.options = options
        self.executed_addresses = set(executed_addresses)
        self.parsed_rows = parsed_rows
        self.instruction_samples = list(instruction_samples)
        self.binary_offset = int(binary_offset or 0)
        self._preserve_segments = self._normalize_segments(preserve_segments)
        self._segment_padding = max(0, int(segment_padding or 0))

    @staticmethod
    def _apply_binary_offset_to_addresses(
        addresses: Iterable[int],
        offset: int,
    ) -> set[int]:
        """Translate trace-relative addresses into the binary's VA space."""
        if not offset:
            return set(addresses)
        return {address - offset for address in addresses}

    @staticmethod
    def _apply_binary_offset_to_samples(
        samples: Iterable[tuple[int, str]],
        offset: int,
    ) -> list[tuple[int, str]]:
        if not offset:
            return list(samples)
        return [(address - offset, text) for address, text in samples]

    @staticmethod
    def _normalize_segments(segments: list[tuple[int, int]] | None) -> list[tuple[int, int]]:
        if not segments:
            return []
        normalized: list[tuple[int, int]] = []
        for entry in segments:
            if isinstance(entry, dict):
                start = entry.get("start")
                end = entry.get("end")
            else:
                try:
                    start, end = entry
                except (TypeError, ValueError):
                    continue
            if start is None or end is None:
                continue
            start_int = int(start)
            end_int = int(end)
            if start_int > end_int:
                start_int, end_int = end_int, start_int
            normalized.append((start_int, end_int))
        return normalized

    @staticmethod
    def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
        if not ranges:
            return []
        merged: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1]:
                prev_start, prev_end = merged[-1]
                merged[-1] = (prev_start, max(prev_end, end))
            else:
                merged.append((start, end))
        return merged

    @staticmethod
    def _segments_from_addresses(addresses: Iterable[int], *, gap: int) -> list[tuple[int, int]]:
        values: list[int] = []
        seen: set[int] = set()
        for addr in addresses:
            try:
                addr_int = int(addr)
            except (TypeError, ValueError):
                continue
            if addr_int in seen:
                continue
            seen.add(addr_int)
            values.append(addr_int)
        if not values:
            return []
        values.sort()
        gap = max(1, int(gap))
        segments: list[tuple[int, int]] = []
        start = prev = values[0]
        for addr in values[1:]:
            if addr - prev > gap:
                segments.append((start, prev))
                start = addr
            prev = addr
        segments.append((start, prev))
        return segments

    def _protected_ranges(self, offset: int) -> list[tuple[int, int]]:
        if not self._preserve_segments:
            return []
        padding = self._segment_padding
        padded: list[tuple[int, int]] = []
        for start, end in self._preserve_segments:
            adj_start = start - offset if offset else start
            adj_end = end - offset if offset else end
            if adj_start > adj_end:
                adj_start, adj_end = adj_end, adj_start
            adj_start = max(0, adj_start - padding)
            adj_end = max(adj_start, adj_end + padding)
            padded.append((adj_start, adj_end))
        return self._merge_ranges(padded)

    @staticmethod
    def _infer_dynlink_protected_ranges(binary: "lief.Binary") -> list[tuple[int, int]]:
        names = [
            ".interp",
            ".dynamic",
            ".got",
            ".got.plt",
            ".data.rel.ro",
            ".rela.dyn",
            ".rela.plt",
            ".dynsym",
            ".dynstr",
            ".gnu.hash",
            ".gnu.version",
            ".gnu.version_r",
        ]
        ranges: list[tuple[int, int]] = []
        for section in getattr(binary, "sections", []) or []:
            name = str(getattr(section, "name", ""))
            if name not in names:
                continue
            start = int(getattr(section, "virtual_address", 0) or 0)
            size = int(getattr(section, "size", 0) or 0)
            if size <= 0:
                continue
            ranges.append((start, start + size))
        return SanitizeWorker._merge_ranges(ranges)

    @staticmethod
    def _infer_unwind_protected_ranges(binary: "lief.Binary") -> list[tuple[int, int]]:
        names = [".eh_frame_hdr", ".eh_frame", ".gcc_except_table"]
        ranges: list[tuple[int, int]] = []
        for section in getattr(binary, "sections", []) or []:
            name = str(getattr(section, "name", ""))
            if name not in names:
                continue
            start = int(getattr(section, "virtual_address", 0) or 0)
            size = int(getattr(section, "size", 0) or 0)
            if size <= 0:
                continue
            ranges.append((start, start + size))
        return SanitizeWorker._merge_ranges(ranges)

    def _mismatch_log_path(self) -> Path:
        base = self.output_path
        filename = f"{base.name}.mismatches.log"
        return base.parent / filename

    def _write_mismatch_log(self, mismatches: list[InstructionMismatch]) -> Path:
        log_path = self._mismatch_log_path()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().isoformat(sep=" ", timespec="seconds")
        lines = [
            "Instruction mismatches detected during sanitization",
            f"Entry: {self.entry_id}",
            f"Binary: {self.binary_path}",
            f"Log: {self.log_path}",
            f"Generated: {timestamp}",
            "",
            "Address\tExpected\tActual",
        ]
        for mismatch in mismatches:
            lines.append(
                f"0x{mismatch.address:x}\t{mismatch.expected or '<empty>'}\t{mismatch.actual or '<empty>'}"
            )
        log_path.write_text("\n".join(lines), encoding="utf-8")
        return log_path

    def _sanitize(self) -> SanitizationResult:
        executed = set(self.executed_addresses)
        samples = list(self.instruction_samples)
        offset = self.binary_offset
        if offset:
            # Convert trace-relative addresses into the binary's virtual address space for verification/patching.
            executed = self._apply_binary_offset_to_addresses(executed, offset)
            samples = self._apply_binary_offset_to_samples(samples, offset)

        # Apply GUI-selected knobs (defaults are conservative when runnable-first is enabled).
        desired_padding = max(0, int(getattr(self.options, "segment_padding", 0) or 0))
        if desired_padding:
            self._segment_padding = desired_padding

        desired_gap = max(0, int(getattr(self.options, "segment_gap", 0) or 0))
        if not desired_gap:
            desired_gap = (
                SANITIZE_RUNNABLE_FIRST_SEGMENT_GAP if self.options.runnable_first else HONEY_SEGMENT_MAX_GAP
            )

        # Derive a conservative protected region from what we *actually* saw execute.
        # NOTE: This intentionally uses a larger gap in runnable-first mode to reduce
        # the risk of corrupting in-.text data (e.g., jump tables) that may be read but
        # never executed.
        segments = self._segments_from_addresses(executed, gap=desired_gap)
        padding = self._segment_padding
        protected_ranges: list[tuple[int, int]] = []
        if segments:
            padded = []
            for start, end in segments:
                if start > end:
                    start, end = end, start
                start = max(0, start - padding)
                end = max(start, end + padding)
                padded.append((start, end))
            protected_ranges = self._merge_ranges(padded)

        self.progress.emit(f"Using segment gap: 0x{desired_gap:x}; segment padding: 0x{padding:x}.")

        # Merge in any explicitly preserved ranges/segments (if available).
        extra_protected = self._protected_ranges(offset)
        if extra_protected:
            protected_ranges = self._merge_ranges(protected_ranges + extra_protected)
        parsed_rows = self.parsed_rows
        self.progress.emit(f"Parsed {parsed_rows} instruction rows; {len(executed)} unique addresses will be preserved.")
        if not executed:
            raise ValueError(
                "No executed instructions were discovered in the log. "
                f"Checked {parsed_rows} instruction rows from {self.log_path}."
            )

        sanitizer = BinarySanitizer()
        binary_obj = None

        # These require parsing the binary; do it once and reuse.
        if (
            self.options.protect_dynlinks
            or self.options.protect_unwind
            or self.options.protect_indirect
            or (self.options.sanity_check and samples)
        ):
            if binary_obj is None:
                binary_obj = lief.parse(str(self.binary_path))

        if self.options.protect_dynlinks:
            dyn = self._infer_dynlink_protected_ranges(binary_obj)
            if dyn:
                protected_ranges = self._merge_ranges(protected_ranges + dyn)
                self.progress.emit(f"Added {len(dyn)} dynamic-linker protected range(s).")

        if self.options.protect_unwind:
            unwind = self._infer_unwind_protected_ranges(binary_obj)
            if unwind:
                protected_ranges = self._merge_ranges(protected_ranges + unwind)
                self.progress.emit(f"Added {len(unwind)} unwind/exception protected range(s).")

        if self.options.protect_indirect:
            icf_window = max(0, int(getattr(self.options, "icf_window", 0) or 0))
            jt_window = max(0, int(getattr(self.options, "jumptable_window", 0) or 0))
            try:
                from scripts.sanitize_from_logs import infer_indirect_protected_ranges

                icf = infer_indirect_protected_ranges(
                    binary=binary_obj,
                    icf_window=icf_window,
                    jumptable_window=jt_window,
                )
            except Exception:
                icf = []
            if icf:
                protected_ranges = self._merge_ranges(protected_ranges + icf)
                self.progress.emit(f"Added {len(icf)} heuristic indirect-control-flow protected range(s).")

        if self.options.sanity_check and samples:
            self.progress.emit("Validating logged instructions against binary...")
            if binary_obj is None:
                binary_obj = lief.parse(str(self.binary_path))
            stop_on_mismatch = not bool(self.options.replace_mismatched_instructions)
            mismatches = sanitizer.verify_logged_instructions(
                binary_obj,
                samples,
                stop_on_mismatch=stop_on_mismatch,
            )
            if self.options.replace_mismatched_instructions and mismatches:
                replaced = 0
                for mismatch in mismatches:
                    if mismatch.address in executed:
                        executed.discard(mismatch.address)
                        replaced += 1
                log_message = None
                if mismatches:
                    try:
                        log_path = self._write_mismatch_log(mismatches)
                        log_message = f"Logged {len(mismatches)} mismatched instruction(s) to {log_path}."
                    except Exception as log_exc:  # pragma: no cover - defensive
                        log_message = f"Failed to write mismatch log: {log_exc}"
                if replaced:
                    self.progress.emit(
                        f"Detected {len(mismatches)} mismatched instruction(s); replacing {replaced} before sanitization."
                    )
                if log_message:
                    self.progress.emit(log_message)

        self.progress.emit("Running sanitizer...")
        result = sanitizer.sanitize(
            self.binary_path,
            executed,
            self.output_path,
            forced_mode=self.options.permissions_mask,
            only_text_section=self.options.only_text_section,
            binary=binary_obj,
            preserve_trampolines=self.options.preserve_trampoline_sections,
            protected_ranges=protected_ranges,
        )
        self.progress.emit(f"Wrote sanitized binary to {result.output_path}.")
        if self.options.sanity_check:
            self.progress.emit("Running sanity check on sanitized binary...")
            sanitizer.sanity_check(result.output_path)
            self.progress.emit("Sanity check passed.")
        return result

    def run(self) -> None:
        try:
            result = self._sanitize()
            self.succeeded.emit(result)
        except Exception as exc:  # pragma: no cover - GUI background task
            self.failed.emit(f"Sanitization failed for log '{self.log_path}': {exc}")


class SanitizeSweepWorker(QObject):
    progress = Signal(str)
    progress_counts = Signal(int, int)
    variant_succeeded = Signal(object)
    finished = Signal(object)

    def __init__(
        self,
        entry_id: str,
        binary_path: Path,
        log_path: Path,
        output_template: Path,
        base_options: SanitizeOptions,
        *,
        executed_addresses: set[int],
        parsed_rows: int,
        instruction_samples: list[tuple[int, str]],
        binary_offset: int = 0,
        preserve_segments: list[tuple[int, int]] | None = None,
        sweep_variants: list[tuple[int, int, int, int]],
    ) -> None:
        super().__init__()
        self.entry_id = entry_id
        self.binary_path = Path(binary_path)
        self.log_path = Path(log_path)
        self.output_template = Path(output_template)
        self.base_options = base_options
        self.executed_addresses = set(executed_addresses)
        self.parsed_rows = int(parsed_rows or 0)
        self.instruction_samples = list(instruction_samples)
        self.binary_offset = int(binary_offset or 0)
        self.preserve_segments = list(preserve_segments or [])
        self.sweep_variants = list(sweep_variants)

    def run(self) -> None:  # pragma: no cover - worker thread
        total = len(self.sweep_variants)
        successes = 0
        failures = 0
        self.progress_counts.emit(0, total)
        for idx, (gap, padding, icf_window, jumptable_window) in enumerate(self.sweep_variants, start=1):
            try:
                self.progress_counts.emit(idx, total)
                suffix = self.output_template.suffix
                stem = self.output_template.stem
                candidate = self.output_template.with_name(
                    f"{stem}_gap{gap:x}_pad{padding:x}_icf{icf_window:x}_jt{jumptable_window:x}{suffix}"
                )
                counter = 1
                while candidate.exists():
                    candidate = self.output_template.with_name(
                        f"{stem}_gap{gap:x}_pad{padding:x}_icf{icf_window:x}_jt{jumptable_window:x}_{counter}{suffix}"
                    )
                    counter += 1
                opts = self.base_options._replace(
                    segment_gap=int(gap),
                    segment_padding=int(padding),
                    icf_window=int(icf_window),
                    jumptable_window=int(jumptable_window),
                )
                worker = SanitizeWorker(
                    self.entry_id,
                    self.binary_path,
                    self.log_path,
                    candidate,
                    opts,
                    executed_addresses=self.executed_addresses,
                    parsed_rows=self.parsed_rows,
                    instruction_samples=self.instruction_samples,
                    binary_offset=self.binary_offset,
                    preserve_segments=self.preserve_segments,
                    segment_padding=int(padding),
                )
                worker.progress.connect(self.progress.emit)
                self.progress.emit(
                    f"Sweep {idx}/{total}: gap=0x{gap:x} pad=0x{padding:x} icf=0x{icf_window:x} jt=0x{jumptable_window:x}"
                )
                result = worker._sanitize()
                successes += 1
                self.variant_succeeded.emit(
                    {
                        "entry_id": self.entry_id,
                        "output_path": str(result.output_path),
                        "segment_gap": int(gap),
                        "segment_padding": int(padding),
                        "icf_window": int(icf_window),
                        "jumptable_window": int(jumptable_window),
                        "total_instructions": int(result.total_instructions or 0),
                        "preserved_instructions": int(result.preserved_instructions or 0),
                        "nopped_instructions": int(result.nopped_instructions or 0),
                    }
                )
            except Exception as exc:
                failures += 1
                self.progress.emit(
                    f"Sweep {idx}/{total} failed: gap=0x{gap:x} pad=0x{padding:x} icf=0x{icf_window:x} jt=0x{jumptable_window:x}: {exc}"
                )
        self.progress_counts.emit(total, total)
        self.finished.emit({"successes": successes, "failures": failures, "total": total})


class SanitizeOptions(NamedTuple):
    sanity_check: bool
    output_name: str | None
    permissions_mask: int | None
    only_text_section: bool
    replace_mismatched_instructions: bool
    preserve_trampoline_sections: bool
    runnable_first: bool
    protect_dynlinks: bool
    protect_unwind: bool
    protect_indirect: bool
    segment_padding: int
    icf_window: int
    jumptable_window: int
    segment_gap: int


class RunSanitizedOptions(NamedTuple):
    run_with_pin: bool
    collect_cpu_metrics: bool
    collect_memory_metrics: bool
    collect_timing_metrics: bool
    run_with_sudo: bool
    pre_run_command: str | None
    copy_to_original_path: bool
    assume_works_if_running: bool
    assume_works_after_ms: int


class BuildProgressDialog(QDialog):
    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setWindowTitle("Building PIN Tool")
        self.setModal(True)
        self._running = True
        layout = QVBoxLayout(self)
        self.status_label = QLabel("Building PIN tool...", self)
        self.output_view = QPlainTextEdit(self)
        self.output_view.setReadOnly(True)
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 0)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Close, self)
        self.close_button = self.buttons.button(QDialogButtonBox.Close)
        if self.close_button:
            self.close_button.setEnabled(False)
        self.buttons.rejected.connect(self.reject)

        layout.addWidget(self.status_label)
        layout.addWidget(self.output_view)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.buttons)
        self.resize(720, 500)

    def append_output(self, text: str) -> None:
        self.output_view.appendPlainText(text)

    def mark_finished(self, success: bool) -> None:
        self._running = False
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(1)
        state = "completed" if success else "failed"
        self.status_label.setText(f"Build {state}.")
        if self.close_button:
            self.close_button.setEnabled(True)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self._running:
            event.ignore()
            return
        super().closeEvent(event)


class SanitizeProgressDialog(QDialog):
    def __init__(self, parent: QWidget, binary_label: str) -> None:
        super().__init__(parent)
        self.setWindowTitle("Generating Sanitized Binary")
        self.setModal(True)
        self._finished = False
        layout = QVBoxLayout(self)
        self.status_label = QLabel(f"Processing {binary_label}...", self)
        self.output_view = QPlainTextEdit(self)
        self.output_view.setReadOnly(True)
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 0)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Close, self)
        self.close_button = self.buttons.button(QDialogButtonBox.Close)
        if self.close_button:
            self.close_button.setEnabled(False)
        self.buttons.rejected.connect(self.reject)

        layout.addWidget(self.status_label)
        layout.addWidget(self.output_view)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.buttons)
        self.resize(720, 500)

    def append_output(self, text: str) -> None:
        self.output_view.appendPlainText(text)

    def update_status(self, text: str) -> None:
        self.status_label.setText(text)

    def update_generation_progress(self, current: int, total: int) -> None:
        total_value = max(0, int(total or 0))
        current_value = max(0, int(current or 0))
        if total_value <= 0:
            self.progress_bar.setRange(0, 0)
            return
        current_value = min(current_value, total_value)
        if self.progress_bar.maximum() != total_value:
            self.progress_bar.setRange(0, total_value)
        self.progress_bar.setValue(current_value)
        self.status_label.setText(f"Generating {current_value}/{total_value}.")

    def mark_finished(self, message: str) -> None:
        self._finished = True
        self.status_label.setText(message)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(1)
        if self.close_button:
            self.close_button.setEnabled(True)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if not self._finished:
            event.ignore()
            return
        super().closeEvent(event)


class SanitizeConfigDialog(QDialog):
    def __init__(
        self,
        parent: QWidget,
        *,
        default_name: str,
        default_permissions: int,
        sanity_allowed: bool,
        initial: dict[str, object] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Sanitize Options")
        self.setModal(True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        self.sanity_checkbox = QCheckBox("Sanity check", self)
        self.sanity_checkbox.setEnabled(sanity_allowed)
        if not sanity_allowed:
            self.sanity_checkbox.setChecked(False)
            self.sanity_checkbox.setToolTip("Sanity check unavailable: no executed instructions detected.")

        options_group = QGroupBox("Sanitization behavior", self)
        options_layout = QVBoxLayout(options_group)
        options_layout.setContentsMargins(12, 12, 12, 12)
        options_layout.setSpacing(6)
        options_layout.addWidget(self.sanity_checkbox)

        self.replace_mismatch_checkbox = QCheckBox("Replace mismatched instructions", self)
        self.replace_mismatch_checkbox.setChecked(True)
        self.replace_mismatch_checkbox.setToolTip(
            "When enabled, any sample that no longer matches the binary will be replaced during sanitization instead of aborting."
        )
        options_layout.addWidget(self.replace_mismatch_checkbox)

        self.only_text_checkbox = QCheckBox("Only .text section", self)
        self.only_text_checkbox.setToolTip("Restrict sanitization to instructions located in the binary's .text sections.")
        options_layout.addWidget(self.only_text_checkbox)

        self.runnable_first_checkbox = QCheckBox("Runnability first (conservative)", self)
        self.runnable_first_checkbox.setChecked(True)
        self.runnable_first_checkbox.setToolTip(
            "Favor correctness over size reduction by preserving more code/data around traced regions and protecting dynamic-linking/unwind/indirect plumbing."
        )
        options_layout.addWidget(self.runnable_first_checkbox)

        advanced_group = QGroupBox("Advanced preservation", self)
        advanced_layout = QVBoxLayout(advanced_group)
        advanced_layout.setContentsMargins(12, 12, 12, 12)
        advanced_layout.setSpacing(6)

        self.protect_dynlinks_checkbox = QCheckBox("Protect dynamic-linking sections (.got/.dynamic/.rela.*)", advanced_group)
        self.protect_dynlinks_checkbox.setChecked(True)
        advanced_layout.addWidget(self.protect_dynlinks_checkbox)

        self.protect_unwind_checkbox = QCheckBox("Protect unwind/exception metadata (.eh_frame*)", advanced_group)
        self.protect_unwind_checkbox.setChecked(True)
        advanced_layout.addWidget(self.protect_unwind_checkbox)

        self.protect_indirect_checkbox = QCheckBox("Protect indirect control-flow neighborhoods", advanced_group)
        self.protect_indirect_checkbox.setChecked(True)
        advanced_layout.addWidget(self.protect_indirect_checkbox)

        knobs_group = QGroupBox("Advanced knobs", self)
        knobs_layout = QVBoxLayout(knobs_group)
        knobs_layout.setContentsMargins(12, 12, 12, 12)
        knobs_layout.setSpacing(6)

        def _range_row(label: str, default_value: int) -> tuple[QHBoxLayout, QLineEdit, QLineEdit]:
            row = QHBoxLayout()
            row.addWidget(QLabel(label, knobs_group))
            range_input = QLineEdit(f"0x{default_value:x}-0x{default_value:x}", knobs_group)
            range_input.setToolTip(
                "Range in the form start-end (supports hex like 0x2000-0x4000). Use a single value for a fixed knob."
            )
            range_input.setMaximumWidth(270)
            interval_input = QLineEdit("0x0", knobs_group)
            interval_input.setToolTip(
                "Interval/step between range values (0 means single value; if start!=end and interval=0, start+end will be used)."
            )
            interval_input.setMaximumWidth(160)
            row.addWidget(QLabel("Range", knobs_group))
            row.addWidget(range_input)
            row.addWidget(QLabel("Interval", knobs_group))
            row.addWidget(interval_input)
            row.addStretch(1)
            return row, range_input, interval_input

        default_gap = SANITIZE_RUNNABLE_FIRST_SEGMENT_GAP
        default_pad = SANITIZE_RUNNABLE_FIRST_SEGMENT_PADDING
        default_icf = SANITIZE_RUNNABLE_FIRST_ICF_WINDOW
        default_jt = SANITIZE_RUNNABLE_FIRST_JUMPTABLE_WINDOW
        gap_row, self.gap_range_input, self.gap_interval_input = _range_row(
            "Segment gap (bytes):",
            default_gap,
        )
        pad_row, self.pad_range_input, self.pad_interval_input = _range_row(
            "Segment padding (bytes):",
            default_pad,
        )
        icf_row, self.icf_range_input, self.icf_interval_input = _range_row(
            "Indirect CF window (bytes):",
            default_icf,
        )
        jt_row, self.jt_range_input, self.jt_interval_input = _range_row(
            "Jump-table window (bytes):",
            default_jt,
        )
        knobs_layout.addLayout(gap_row)
        knobs_layout.addLayout(pad_row)
        knobs_layout.addLayout(icf_row)
        knobs_layout.addLayout(jt_row)

        layout.addWidget(knobs_group)

        layout.addWidget(advanced_group)

        self.preserve_sections_checkbox = QCheckBox("Preserve PLT/.init/.fini sections", self)
        self.preserve_sections_checkbox.setChecked(True)
        self.preserve_sections_checkbox.setToolTip(
            "Keep dynamic loader trampolines intact even if they never executed in the trace. Disable only if you intentionally recorded those sections and want them sanitized."
        )
        options_layout.addWidget(self.preserve_sections_checkbox)

        def _sync_runnable_first_state() -> None:
            # Runnable-first sets conservative defaults, but users may still want to tune knobs.
            for cb in (
                self.protect_dynlinks_checkbox,
                self.protect_unwind_checkbox,
                self.protect_indirect_checkbox,
            ):
                cb.setEnabled(True)
            for entry in (
                self.gap_range_input,
                self.gap_interval_input,
                self.pad_range_input,
                self.pad_interval_input,
                self.icf_range_input,
                self.icf_interval_input,
                self.jt_range_input,
                self.jt_interval_input,
            ):
                entry.setEnabled(True)

        self.runnable_first_checkbox.toggled.connect(_sync_runnable_first_state)
        _sync_runnable_first_state()

        if isinstance(initial, dict):
            # Conservative defaults already applied above; override with persisted values when present.
            rf = initial.get("runnable_first")
            if isinstance(rf, bool):
                self.runnable_first_checkbox.setChecked(rf)
            ot = initial.get("only_text")
            if isinstance(ot, bool):
                self.only_text_checkbox.setChecked(ot)
            pt = initial.get("preserve_trampolines")
            if isinstance(pt, bool):
                self.preserve_sections_checkbox.setChecked(pt)
            pd = initial.get("protect_dynlinks")
            if isinstance(pd, bool):
                self.protect_dynlinks_checkbox.setChecked(pd)
            pu = initial.get("protect_unwind")
            if isinstance(pu, bool):
                self.protect_unwind_checkbox.setChecked(pu)
            pi = initial.get("protect_indirect")
            if isinstance(pi, bool):
                self.protect_indirect_checkbox.setChecked(pi)
            sg = initial.get("segment_gap")
            if isinstance(sg, str) and sg.strip():
                self.gap_range_input.setText(f"{sg.strip()}-{sg.strip()}")
            sp = initial.get("segment_padding")
            if isinstance(sp, str) and sp.strip():
                self.pad_range_input.setText(f"{sp.strip()}-{sp.strip()}")
            iw = initial.get("icf_window")
            if isinstance(iw, str) and iw.strip():
                self.icf_range_input.setText(f"{iw.strip()}-{iw.strip()}")
            jw = initial.get("jumptable_window")
            if isinstance(jw, str) and jw.strip():
                self.jt_range_input.setText(f"{jw.strip()}-{jw.strip()}")
            _sync_runnable_first_state()
        options_layout.addStretch(1)
        layout.addWidget(options_group)

        filename_row = QHBoxLayout()
        filename_row.addWidget(QLabel("Output filename:", self))
        self.filename_input = QLineEdit(default_name, self)
        filename_row.addWidget(self.filename_input)
        layout.addLayout(filename_row)

        permissions_label = QLabel("Permissions:", self)
        layout.addWidget(permissions_label)
        permissions_row = QHBoxLayout()
        self.read_checkbox = QCheckBox("Read (r)", self)
        self.write_checkbox = QCheckBox("Write (w)", self)
        self.exec_checkbox = QCheckBox("Execute (x)", self)
        permissions_row.addWidget(self.read_checkbox)
        permissions_row.addWidget(self.write_checkbox)
        permissions_row.addWidget(self.exec_checkbox)
        permissions_row.addStretch(1)
        layout.addLayout(permissions_row)
        layout.addStretch(1)

        self._apply_default_permissions(default_permissions)

        reset_row = QHBoxLayout()
        reset_row.addStretch(1)
        self.reset_conservative_button = QPushButton("Reset to conservative defaults", self)
        self.reset_conservative_button.setToolTip(
            "Restore the safest sanitization settings (runnability-first and conservative knobs)."
        )
        reset_row.addWidget(self.reset_conservative_button)
        layout.addLayout(reset_row)

        def _reset_conservative_defaults() -> None:
            self.runnable_first_checkbox.setChecked(True)
            self.preserve_sections_checkbox.setChecked(True)
            self.protect_dynlinks_checkbox.setChecked(True)
            self.protect_unwind_checkbox.setChecked(True)
            self.protect_indirect_checkbox.setChecked(True)
            self.gap_range_input.setText(
                f"0x{SANITIZE_RUNNABLE_FIRST_SEGMENT_GAP:x}-0x{SANITIZE_RUNNABLE_FIRST_SEGMENT_GAP:x}"
            )
            self.pad_range_input.setText(
                f"0x{SANITIZE_RUNNABLE_FIRST_SEGMENT_PADDING:x}-0x{SANITIZE_RUNNABLE_FIRST_SEGMENT_PADDING:x}"
            )
            self.icf_range_input.setText(
                f"0x{SANITIZE_RUNNABLE_FIRST_ICF_WINDOW:x}-0x{SANITIZE_RUNNABLE_FIRST_ICF_WINDOW:x}"
            )
            self.jt_range_input.setText(
                f"0x{SANITIZE_RUNNABLE_FIRST_JUMPTABLE_WINDOW:x}-0x{SANITIZE_RUNNABLE_FIRST_JUMPTABLE_WINDOW:x}"
            )
            for w in (
                self.gap_interval_input,
                self.pad_interval_input,
                self.icf_interval_input,
                self.jt_interval_input,
            ):
                w.setText("0x0")

        self.reset_conservative_button.clicked.connect(_reset_conservative_defaults)

        buttons = QDialogButtonBox(QDialogButtonBox.Cancel | QDialogButtonBox.Ok, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.resize(600, 420)

    def _apply_default_permissions(self, mode: int) -> None:
        self.read_checkbox.setChecked(bool(mode & stat.S_IRUSR))
        self.write_checkbox.setChecked(bool(mode & stat.S_IWUSR))
        self.exec_checkbox.setChecked(bool(mode & stat.S_IXUSR))

    def selected_options(self) -> SanitizeOptions:
        name = self.filename_input.text().strip()
        safe_name = Path(name).name if name else None
        permissions = self._build_permissions_mask()

        def _parse_int(text: str, *, fallback: int) -> int:
            raw = (text or "").strip()
            if not raw:
                return int(fallback)
            try:
                return int(raw, 0)
            except ValueError:
                return int(fallback)

        def _parse_range(text: str, *, fallback: int) -> tuple[int, int]:
            raw = (text or "").strip()
            if not raw:
                value = int(fallback)
                return value, value
            for sep in ("..", "-", ",", ":"):
                if sep in raw:
                    left, right = raw.split(sep, 1)
                    start = _parse_int(left.strip(), fallback=fallback)
                    end = _parse_int(right.strip(), fallback=start)
                    return int(start), int(end)
            value = _parse_int(raw, fallback=fallback)
            return int(value), int(value)

        def _expand(start: int, end: int, step: int) -> list[int]:
            start = max(0, int(start))
            end = max(0, int(end))
            step = max(0, int(step))
            if end < start:
                start, end = end, start
            if step <= 0:
                if start == end:
                    return [start]
                return [start, end]
            values: list[int] = []
            current = start
            while current <= end:
                values.append(current)
                current += step
            return values or [start]

        runnable_first = self.runnable_first_checkbox.isChecked()
        default_padding = SANITIZE_RUNNABLE_FIRST_SEGMENT_PADDING if runnable_first else SANITIZE_SEGMENT_PADDING
        default_icf = SANITIZE_RUNNABLE_FIRST_ICF_WINDOW if runnable_first else SANITIZE_DEFAULT_ICF_WINDOW
        default_jt = SANITIZE_RUNNABLE_FIRST_JUMPTABLE_WINDOW if runnable_first else SANITIZE_DEFAULT_JUMPTABLE_WINDOW
        default_gap = SANITIZE_RUNNABLE_FIRST_SEGMENT_GAP if runnable_first else HONEY_SEGMENT_MAX_GAP

        gap_start, gap_end = _parse_range(self.gap_range_input.text(), fallback=default_gap)
        gap_step = _parse_int(self.gap_interval_input.text(), fallback=0)
        pad_start, pad_end = _parse_range(self.pad_range_input.text(), fallback=default_padding)
        pad_step = _parse_int(self.pad_interval_input.text(), fallback=0)
        icf_start, icf_end = _parse_range(self.icf_range_input.text(), fallback=default_icf)
        icf_step = _parse_int(self.icf_interval_input.text(), fallback=0)
        jt_start, jt_end = _parse_range(self.jt_range_input.text(), fallback=default_jt)
        jt_step = _parse_int(self.jt_interval_input.text(), fallback=0)

        # For the single-output path we take the first expanded value; the multi-output
        # path uses sweep_variants().
        segment_gap = _expand(gap_start, gap_end, gap_step)[0]
        segment_padding = _expand(pad_start, pad_end, pad_step)[0]
        icf_window = _expand(icf_start, icf_end, icf_step)[0]
        jumptable_window = _expand(jt_start, jt_end, jt_step)[0]
        return SanitizeOptions(
            sanity_check=self.sanity_checkbox.isChecked(),
            output_name=safe_name,
            permissions_mask=permissions,
            only_text_section=self.only_text_checkbox.isChecked(),
            replace_mismatched_instructions=self.replace_mismatch_checkbox.isChecked(),
            preserve_trampoline_sections=self.preserve_sections_checkbox.isChecked(),
            runnable_first=runnable_first,
            protect_dynlinks=self.protect_dynlinks_checkbox.isChecked(),
            protect_unwind=self.protect_unwind_checkbox.isChecked(),
            protect_indirect=self.protect_indirect_checkbox.isChecked(),
            segment_padding=segment_padding,
            icf_window=icf_window,
            jumptable_window=jumptable_window,
            segment_gap=segment_gap,
        )

    def sweep_enabled(self) -> bool:
        # Sweep is implicit: if any knob expands to multiple values, generate multiple outputs.
        variants = self.sweep_variants()
        return len(variants) > 1

    def sweep_variants(self) -> list[tuple[int, int, int, int]]:
        def _parse_int(text: str, *, fallback: int) -> int:
            raw = (text or "").strip()
            if not raw:
                return int(fallback)
            try:
                return int(raw, 0)
            except ValueError:
                return int(fallback)

        def _parse_range(text: str, *, fallback: int) -> tuple[int, int]:
            raw = (text or "").strip()
            if not raw:
                value = int(fallback)
                return value, value
            for sep in ("..", "-", ",", ":"):
                if sep in raw:
                    left, right = raw.split(sep, 1)
                    start = _parse_int(left.strip(), fallback=fallback)
                    end = _parse_int(right.strip(), fallback=start)
                    return int(start), int(end)
            value = _parse_int(raw, fallback=fallback)
            return int(value), int(value)

        def _expand(start: int, end: int, step: int) -> list[int]:
            start = max(0, int(start))
            end = max(0, int(end))
            step = max(0, int(step))
            if end < start:
                start, end = end, start
            if step <= 0:
                if start == end:
                    return [start]
                return [start, end]
            values: list[int] = []
            current = start
            while current <= end:
                values.append(current)
                current += step
            return values or [start]

        gap_start, gap_end = _parse_range(self.gap_range_input.text(), fallback=SANITIZE_RUNNABLE_FIRST_SEGMENT_GAP)
        gap_step = _parse_int(self.gap_interval_input.text(), fallback=0)
        pad_start, pad_end = _parse_range(self.pad_range_input.text(), fallback=SANITIZE_RUNNABLE_FIRST_SEGMENT_PADDING)
        pad_step = _parse_int(self.pad_interval_input.text(), fallback=0)
        icf_start, icf_end = _parse_range(self.icf_range_input.text(), fallback=SANITIZE_RUNNABLE_FIRST_ICF_WINDOW)
        icf_step = _parse_int(self.icf_interval_input.text(), fallback=0)
        jt_start, jt_end = _parse_range(self.jt_range_input.text(), fallback=SANITIZE_RUNNABLE_FIRST_JUMPTABLE_WINDOW)
        jt_step = _parse_int(self.jt_interval_input.text(), fallback=0)

        gaps = _expand(gap_start, gap_end, gap_step)
        pads = _expand(pad_start, pad_end, pad_step)
        icfs = _expand(icf_start, icf_end, icf_step)
        jts = _expand(jt_start, jt_end, jt_step)
        return [(gap, pad, icf, jt) for gap in gaps for pad in pads for icf in icfs for jt in jts]

    def _build_permissions_mask(self) -> int:
        mask = 0
        if self.read_checkbox.isChecked():
            mask |= stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
        if self.write_checkbox.isChecked():
            mask |= stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
        if self.exec_checkbox.isChecked():
            mask |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        return mask


class RunSanitizedOptionsDialog(QDialog):
    def __init__(self, parent: QWidget, *, default_run_with_sudo: bool = False) -> None:
        super().__init__(parent)
        self.setWindowTitle("Execute Sanitized Binary")
        self.setModal(True)
        self._selected_pre_run_command: str | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        execution_group = QGroupBox("Execution", self)
        execution_layout = QVBoxLayout(execution_group)
        execution_layout.setContentsMargins(12, 12, 12, 12)
        self.pin_checkbox = QCheckBox("Run with PIN (recommended)", execution_group)
        self.pin_checkbox.setChecked(True)
        self.pin_checkbox.setToolTip("Disable if you only want to launch the sanitized binary without collecting a new trace.")
        execution_layout.addWidget(self.pin_checkbox)

        self.sudo_checkbox = QCheckBox("Run with sudo", execution_group)
        self.sudo_checkbox.setChecked(bool(default_run_with_sudo))
        self.sudo_checkbox.setToolTip("Run the target under sudo. You will be prompted for your sudo password if needed.")
        execution_layout.addWidget(self.sudo_checkbox)

        self.copy_to_original_checkbox = QCheckBox(
            "Copy binary to original binary path (rename-required)",
            execution_group,
        )
        self.copy_to_original_checkbox.setToolTip(
            "Copies the sanitized binary into the original binary's directory with a new name and runs that copy."
        )
        execution_layout.addWidget(self.copy_to_original_checkbox)

        assume_row = QHBoxLayout()
        self.assume_works_checkbox = QCheckBox("Assume works if running after time", execution_group)
        self.assume_works_checkbox.setToolTip(
            "If enabled, the selected sanitized binary will be marked as working if it is still running after the specified time, then the run will be terminated."
        )
        self.assume_works_ms_spin = QSpinBox(execution_group)
        self.assume_works_ms_spin.setRange(1, 10000)
        self.assume_works_ms_spin.setSingleStep(50)
        self.assume_works_ms_spin.setValue(3000)
        self.assume_works_ms_spin.setSuffix(" ms")
        self.assume_works_ms_spin.setToolTip("Delay (1-10000ms) after launch before marking as working if still running.")
        assume_row.addWidget(self.assume_works_checkbox)
        assume_row.addStretch(1)
        assume_row.addWidget(QLabel("After", execution_group))
        assume_row.addWidget(self.assume_works_ms_spin)
        execution_layout.addLayout(assume_row)

        def _sync_assume_enabled() -> None:
            self.assume_works_ms_spin.setEnabled(bool(self.assume_works_checkbox.isChecked()))

        self.assume_works_checkbox.toggled.connect(_sync_assume_enabled)
        self.assume_works_checkbox.setChecked(False)
        _sync_assume_enabled()
        layout.addWidget(execution_group)

        # Pre-run setup group to run commands or a script before launching
        self.prerun_group = QGroupBox("Pre-Run Setup", self)
        prerun_layout = QVBoxLayout(self.prerun_group)
        prerun_layout.setContentsMargins(12, 8, 12, 12)
        self.prerun_help = QLabel(
            "Pre-run setup command inherited from the original run/config.",
            self.prerun_group,
        )
        self.prerun_help.setWordWrap(True)
        self.prerun_input = QLabel(self.prerun_group)
        self.prerun_input.setWordWrap(True)
        self.prerun_input.setText("(none)")
        self.prerun_input.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.prerun_input.setStyleSheet("color: #666;")
        prerun_layout.addWidget(self.prerun_help)
        prerun_layout.addWidget(self.prerun_input)
        layout.addWidget(self.prerun_group)

        # Invocation preview group shows inherited args/filters/sudo
        self.invocation_group = QGroupBox("Invocation Preview", self)
        invocation_layout = QVBoxLayout(self.invocation_group)
        invocation_layout.setContentsMargins(12, 12, 12, 12)
        self.args_label = QLabel("Args: (none)", self.invocation_group)
        self.filters_label = QLabel("Module Filters: (none)", self.invocation_group)
        self.sudo_label = QLabel("Sudo: off", self.invocation_group)
        for w in (self.args_label, self.filters_label, self.sudo_label):
            w.setWordWrap(True)
            invocation_layout.addWidget(w)
        layout.addWidget(self.invocation_group)

        metrics_group = QGroupBox("Collect Metrics", self)
        metrics_layout = QVBoxLayout(metrics_group)
        metrics_layout.setContentsMargins(12, 12, 12, 12)
        metrics_layout.setSpacing(6)
        metrics_help = QLabel("Choose runtime metrics to gather.", metrics_group)
        metrics_help.setWordWrap(True)
        metrics_layout.addWidget(metrics_help)
        self.cpu_checkbox = QCheckBox("CPU usage", metrics_group)
        self.memory_checkbox = QCheckBox("Memory utilization", metrics_group)
        self.timing_checkbox = QCheckBox("Timing information", metrics_group)
        for checkbox in (self.cpu_checkbox, self.memory_checkbox, self.timing_checkbox):
            metrics_layout.addWidget(checkbox)
        layout.addWidget(metrics_group)

        buttons = QDialogButtonBox(QDialogButtonBox.Cancel | QDialogButtonBox.Ok, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.resize(520, 320)

    def set_invocation_preview(
        self,
        *,
        args: list[str] | None = None,
        module_filters: list[str] | None = None,
        use_sudo: bool | None = None,
        pre_run_command: str | None = None,
    ) -> None:
        args_text = " ".join(args) if args else "(none)"
        filters_text = ", ".join(module_filters) if module_filters else "(none)"
        sudo_text = "on" if use_sudo else "off"
        self.args_label.setText(f"Args: {args_text}")
        self.filters_label.setText(f"Module Filters: {filters_text}")
        self.sudo_label.setText(f"Sudo: {sudo_text}")
        self.sudo_checkbox.setChecked(bool(use_sudo))
        self.sudo_checkbox.setEnabled(False)
        self._selected_pre_run_command = (pre_run_command or "").strip() or None
        self.prerun_input.setText(self._selected_pre_run_command or "(none)")

    def selected_options(self) -> RunSanitizedOptions:
        return RunSanitizedOptions(
            run_with_pin=self.pin_checkbox.isChecked(),
            collect_cpu_metrics=self.cpu_checkbox.isChecked(),
            collect_memory_metrics=self.memory_checkbox.isChecked(),
            collect_timing_metrics=self.timing_checkbox.isChecked(),
            run_with_sudo=self.sudo_checkbox.isChecked(),
            pre_run_command=self._selected_pre_run_command,
            copy_to_original_path=bool(self.copy_to_original_checkbox.isChecked()),
            assume_works_if_running=bool(self.assume_works_checkbox.isChecked()),
            assume_works_after_ms=int(self.assume_works_ms_spin.value()),
        )


class _BinaryInstructionResolver:
    def __init__(self, binary_path: Path) -> None:
        self._path = Path(binary_path)
        self._binary: lief.Binary | None = None
        self._disassembler: capstone.Cs | None = None
        self._sanitizer = BinarySanitizer()
        self._cache: dict[int, str | None] = {}
        self._error: str | None = None

    def resolve(self, address: int) -> str | None:
        if address in self._cache:
            return self._cache[address]
        result = self._read_instruction(address)
        self._cache[address] = result
        return result

    def _read_instruction(self, address: int) -> str | None:
        if address < 0:
            return None
        if not self._ensure_ready():
            return None
        assert self._binary is not None
        assert self._disassembler is not None
        try:
            raw = self._binary.get_content_from_virtual_address(address, 16)
        except Exception:
            return None
        data = bytes(raw)
        if not data:
            return None
        instruction = next(self._disassembler.disasm(data, address), None)
        if instruction is None:
            return None
        text = f"{instruction.mnemonic} {instruction.op_str}".strip()
        return text or None

    def _ensure_ready(self) -> bool:
        if self._binary is not None and self._disassembler is not None:
            return True
        if self._error:
            return False
        try:
            binary = lief.parse(str(self._path))
            arch, mode, _ = self._sanitizer._capstone_config(binary)
            disassembler = capstone.Cs(arch, mode)
            disassembler.detail = False
        except Exception as exc:
            self._error = str(exc)
            return False
        self._binary = binary
        self._disassembler = disassembler
        return True


class InstructionPreviewDialog(QDialog):
    def __init__(
        self,
        parent: QWidget,
        entry_label: str,
        rows: list[tuple[int, str, str]],
        segments: list[tuple[int, int]] | None = None,
        binary_path: Path | None = None,
        *,
        saved_offset: int = 0,
        save_offset_callback: Callable[[int], bool | None] | None = None,
        warn_on_unsaved: bool = False,
        enable_offset_save: bool = False,
        progress_callback: Callable[[str], None] | None = None,
        description_text: str | None = None,
        window_title: str | None = None,
        overview_binary_label: str = "Binary Range",
        overview_trace_label: str = "Trace Range",
        detail_binary_label: str = "Binary Instruction",
        detail_trace_label: str = "Logged Instruction",
        no_sections_text: str | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(window_title or f"Sanitization Preview — {entry_label}")
        self._init_progress_callback = progress_callback
        self._segments = list(segments or [])
        self._raw_rows = list(rows)
        self._binary_path = Path(binary_path) if binary_path else None
        self._binary_instruction_resolver = (
            _BinaryInstructionResolver(self._binary_path)
            if self._binary_path is not None
            else None
        )
        self._raw_addresses = [addr for addr, _, _ in self._raw_rows]
        self._sorted_row_addresses = sorted((addr, idx) for idx, addr in enumerate(self._raw_addresses))
        self._sorted_address_values = [addr for addr, _ in self._sorted_row_addresses]
        self._binary_offset = int(saved_offset or 0)
        self._saved_offset_value = int(saved_offset or 0)
        self._offset_dirty = False
        self._offset_save_handler = save_offset_callback if enable_offset_save and save_offset_callback else None
        self._offset_save_enabled = self._offset_save_handler is not None
        self._warn_on_unsaved_close = bool(warn_on_unsaved and self._offset_save_enabled)
        self._report_init_progress("Applying binary offset...")
        self._rows = self._rows_with_offset(self._binary_offset)
        self._total_rows = len(self._rows)
        self._match_rows = 0
        self._sections: list[dict[str, object]] = []
        self._report_init_progress("Resolving binary instructions...")
        self._resolve_binary_rows()
        self._report_init_progress("Computing preview sections...")
        self._recompute_sections()
        self._current_section_index: int | None = None
        self._offset_thread: QThread | None = None
        self._offset_worker: OffsetRecalcWorker | None = None
        self._offset_progress_dialog: QProgressDialog | None = None
        self._overview_binary_label = overview_binary_label
        self._overview_trace_label = overview_trace_label
        self._detail_binary_label = detail_binary_label
        self._detail_trace_label = detail_trace_label
        self._no_sections_text = (
            no_sections_text
            or "No instruction samples were found in the trace for preview."
        )

        layout = QVBoxLayout(self)

        description = QLabel(
            description_text
            or (
                "Start with the overview to compare binary and trace address ranges. Click a section to inspect the"
                " underlying instructions."
            ),
            self,
        )
        description.setWordWrap(True)
        layout.addWidget(description)

        nav_bar = QHBoxLayout()
        self.view_label = QLabel("Overview", self)
        nav_bar.addWidget(self.view_label)
        self.offset_label = QLabel("Binary offset: +0x0", self)
        self.offset_label.setStyleSheet("color: #666; font-size: 11px;")
        nav_bar.addWidget(self.offset_label)
        nav_bar.addStretch(1)
        self.analyze_button = QPushButton("Analyze Adjust Offset", self)
        self.analyze_button.clicked.connect(self._open_sequence_analyzer)
        nav_bar.addWidget(self.analyze_button)
        self.adjust_offset_button = QPushButton("Manual Adjust Offset", self)
        self.adjust_offset_button.clicked.connect(self._prompt_binary_offset)
        nav_bar.addWidget(self.adjust_offset_button)
        self.save_offset_button: QPushButton | None = None
        if self._offset_save_enabled:
            self.save_offset_button = QPushButton("Save Offset", self)
            self.save_offset_button.setEnabled(False)
            self.save_offset_button.clicked.connect(self._handle_save_offset_clicked)
            self.save_offset_button.setToolTip("Persist the current offset for sanitization runs.")
            nav_bar.addWidget(self.save_offset_button)
        self.zoom_out_button = QPushButton("Zoom Out", self)
        self.zoom_out_button.clicked.connect(self._show_overview)
        self.zoom_out_button.hide()
        nav_bar.addWidget(self.zoom_out_button)
        layout.addLayout(nav_bar)

        self.stack = QStackedWidget(self)
        self.overview_widget = self._build_overview_widget()
        self.detail_widget = self._build_detail_widget()
        self.stack.addWidget(self.overview_widget)
        self.stack.addWidget(self.detail_widget)
        layout.addWidget(self.stack)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)
        self._update_progress_bar()

        buttons = QDialogButtonBox(QDialogButtonBox.Close, self)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._report_init_progress("Building overview...")
        self._populate_overview_table(
            progress_callback=progress_callback,
            with_progress=progress_callback is None,
        )
        self._update_offset_action_state()
        self._show_overview()
        _resize_widget_to_screen(self)

    @staticmethod
    def _monospace_font(font):
        adjusted = QFont(font)
        # Prefer a monospace face while falling back gracefully on the system default.
        adjusted.setFamilies(["Monospace", "Courier New", adjusted.defaultFamily()])
        adjusted.setStyleHint(QFont.StyleHint.Monospace)
        return adjusted

    def _report_init_progress(self, message: str) -> None:
        callback = getattr(self, "_init_progress_callback", None)
        if callback:
            try:
                callback(message)
            except Exception:
                pass
        QApplication.processEvents()

    def _build_overview_widget(self) -> QWidget:
        widget = QWidget(self)
        layout = QVBoxLayout(widget)
        table = QTableWidget(0, 4, widget)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.verticalHeader().setVisible(False)
        table.setHorizontalHeaderLabels(["Section", self._overview_binary_label, self._overview_trace_label, "Status"])
        header = table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)

        table.cellDoubleClicked.connect(self._handle_overview_activation)
        layout.addWidget(table)
        self.overview_table = table
        empty_label = QLabel(self._no_sections_text, widget)
        empty_label.setWordWrap(True)
        empty_label.hide()
        layout.addWidget(empty_label)
        self.no_sections_label = empty_label
        return widget

    def _populate_overview_table(
        self,
        *,
        progress_callback: Callable[[str], None] | None = None,
        done_callback: Callable[[], None] | None = None,
        with_progress: bool = False,
    ) -> None:
        table = getattr(self, "overview_table", None)
        if table is None:
            return
        sections = list(self._sections)
        table.setRowCount(len(sections))
        if hasattr(self, "no_sections_label"):
            has_sections = len(sections) > 0
            self.no_sections_label.setVisible(not has_sections)
            table.setVisible(has_sections)
        if not sections:
            table.clearContents()
            if done_callback:
                QTimer.singleShot(0, done_callback)
            return

        progress_dialog: BusyProgressDialog | None = None
        show_internal_progress = bool(with_progress and progress_callback is None)
        if show_internal_progress and len(sections) >= 200:
            progress_dialog = BusyProgressDialog("Building overview...", "Skip", 0, len(sections), self)
            progress_dialog.setWindowTitle("Preparing Preview")
            progress_dialog.setWindowModality(Qt.ApplicationModal if self.isVisible() else Qt.WindowModal)
            progress_dialog.setMinimumDuration(0)
            progress_dialog.setAutoClose(True)
            progress_dialog.setAutoReset(True)
            progress_dialog.setValue(0)
            progress_dialog.start_pulsing()

        def _finish() -> None:
            nonlocal progress_dialog
            if progress_dialog:
                progress_dialog.close()
                progress_dialog = None
            self._finalize_overview_selection()
            if progress_callback and sections:
                total = len(sections)
                progress_callback(f"Overview rows ready ({total}/{total})")
            if done_callback:
                done_callback()

        use_async = bool(done_callback is not None or progress_dialog is not None or progress_callback is not None)
        if not use_async:
            for row_idx, section in enumerate(sections):
                self._set_overview_row(row_idx, section)
            _finish()
            return

        total = len(sections)
        chunk = max(total // 20, 20) if total else 1

        def _process(start: int = 0) -> None:
            nonlocal progress_dialog
            end = min(start + chunk, total)
            for row_idx in range(start, end):
                self._set_overview_row(row_idx, sections[row_idx])
            if progress_callback:
                progress_callback(f"Populating overview rows ({end}/{total})")
            if progress_dialog:
                progress_dialog.setLabelText(f"Building overview ({end}/{total})")
                progress_dialog.setValue(end)
                QApplication.processEvents()
                if progress_dialog.wasCanceled():
                    progress_dialog.close()
                    progress_dialog = None
                    for row_idx in range(end, total):
                        self._set_overview_row(row_idx, sections[row_idx])
                    _finish()
                    return
            if end < total:
                QTimer.singleShot(0, lambda: _process(end))
            else:
                _finish()

        _process(0)

    def _set_overview_row(self, row_idx: int, section: dict[str, object]) -> None:
        table = getattr(self, "overview_table", None)
        if table is None:
            return
        label_text = section.get("label") or str(row_idx + 1)
        section_item = QTableWidgetItem(label_text)
        binary_range_item = QTableWidgetItem(self._format_range(section, key="binary"))
        trace_range_item = QTableWidgetItem(self._format_range(section, key="trace"))
        status_item = QTableWidgetItem(self._section_label(section))
        for item in (section_item, binary_range_item, trace_range_item, status_item):
            self._apply_section_color(item, section["state"])
        table.setItem(row_idx, 0, section_item)
        table.setItem(row_idx, 1, binary_range_item)
        table.setItem(row_idx, 2, trace_range_item)
        table.setItem(row_idx, 3, status_item)

    def _finalize_overview_selection(self) -> None:
        table = getattr(self, "overview_table", None)
        if table is None:
            return
        sections = list(self._sections)
        if self._current_section_index is not None and self._current_section_index < len(sections):
            table.selectRow(self._current_section_index)
        else:
            table.clearSelection()

    def _build_detail_widget(self) -> QWidget:
        widget = QWidget(self)
        layout = QVBoxLayout(widget)
        table = QTableWidget(0, 3, widget)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        table.verticalHeader().setVisible(False)
        table.setHorizontalHeaderLabels(["Address", self._detail_binary_label, self._detail_trace_label])
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(self._show_detail_context_menu)
        header = table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        layout.addWidget(table)
        self.detail_table = table
        return widget

    @staticmethod
    def _build_sections(
        rows: list[tuple[int, str, str]],
        segments: list[tuple[int, int]] | None = None,
        *,
        offset: int = 0,
        raw_addresses: list[int] | None = None,
        sorted_values: list[int] | None = None,
        sorted_pairs: list[tuple[int, int]] | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
        progress_total: int | None = None,
    ) -> list[dict[str, object]]:
        if segments:
            return InstructionPreviewDialog._build_segment_sections(
                rows,
                segments,
                offset=offset,
                raw_addresses=raw_addresses or [],
                sorted_values=sorted_values or [],
                sorted_pairs=sorted_pairs or [],
                progress_callback=progress_callback,
                progress_total=progress_total,
            )
        if not rows:
            return []
        sections: list[dict[str, object]] = []
        start = 0
        current_state = InstructionPreviewDialog._row_state(rows[0])
        total = progress_total if progress_total is not None else len(rows)
        for idx in range(1, len(rows)):
            state = InstructionPreviewDialog._row_state(rows[idx])
            if state != current_state:
                sections.append(InstructionPreviewDialog._make_section(rows, start, idx, current_state))
                start = idx
                current_state = state
            _yield_gui_events(idx)
            if progress_callback:
                progress_callback(min(idx, total), total or len(rows))
        sections.append(InstructionPreviewDialog._make_section(rows, start, len(rows), current_state))
        if progress_callback:
            progress_callback(total or len(rows), total or len(rows))
        for section in sections:
            start_idx = int(section.get("start", 0))
            end_idx = int(section.get("end", start_idx))
            subset = rows[start_idx:end_idx]
            section.update(InstructionPreviewDialog._section_match_summary(subset))
        return sections

    @staticmethod
    def _build_segment_sections(
        rows: list[tuple[int, str, str]],
        segments: list[tuple[int, int]],
        *,
        offset: int,
        raw_addresses: list[int],
        sorted_values: list[int],
        sorted_pairs: list[tuple[int, int]],
        progress_callback: Callable[[int, int], None] | None = None,
        progress_total: int | None = None,
    ) -> list[dict[str, object]]:
        sections: list[dict[str, object]] = []
        if not segments:
            return sections
        total_rows = len(rows)
        total = progress_total if progress_total is not None else len(segments)
        for seg_index, (seg_start, seg_end) in enumerate(segments):
            lo = bisect_left(sorted_values, seg_start)
            hi = bisect_right(sorted_values, seg_end)
            idxs = [sorted_pairs[i][1] for i in range(lo, hi)] if hi > lo else []
            if idxs:
                start_idx = min(idxs)
                end_idx = max(idxs) + 1
                subset = rows[start_idx:end_idx]
                trace_start = min(raw_addresses[i] for i in idxs)
                trace_end = max(raw_addresses[i] for i in idxs)
            else:
                start_idx = total_rows
                end_idx = total_rows
                subset = []
                trace_start = seg_start
                trace_end = seg_end
            state = InstructionPreviewDialog._section_state_for_subset(subset)
            sections.append(
                {
                    "start": start_idx,
                    "end": end_idx,
                    "state": state,
                    "binary_start": seg_start + offset,
                    "binary_end": seg_end + offset,
                    "trace_start": trace_start,
                    "trace_end": trace_end,
                    "segment_index": seg_index,
                    "label": f"Segment {seg_index + 1}",
                }
            )
            subset_rows = subset if subset else []
            _yield_gui_events(seg_index + 1)
            sections[-1].update(InstructionPreviewDialog._section_match_summary(subset_rows))
            if progress_callback:
                progress_callback(min(seg_index + 1, total), total or len(segments))
        return sections

    @staticmethod
    def _section_state_for_subset(subset: list[tuple[int, str, str]]) -> str:
        if not subset:
            return "missing"
        states = {InstructionPreviewDialog._row_state(row) for row in subset}
        if len(states) == 1:
            return states.pop()
        return "mismatch"

    @staticmethod
    def _section_match_summary(subset: list[tuple[int, str, str]]) -> dict[str, int]:
        total = len(subset)
        match_count = sum(1 for row in subset if InstructionPreviewDialog._row_state(row) == "match")
        return {"match_count": match_count, "total_rows": total}

    @staticmethod
    def _row_state(row: tuple[int, str, str]) -> str:
        _, binary_text, logged_text = row
        binary_clean = _normalize_instruction_text(binary_text)
        logged_clean = _normalize_instruction_text(logged_text)
        if not binary_clean or binary_clean.startswith("<"):
            return "missing"
        if not logged_clean:
            return "missing"
        return "match" if binary_clean == logged_clean else "mismatch"

    @staticmethod
    def _make_section(
        rows: list[tuple[int, str, str]],
        start: int,
        end: int,
        state: str,
    ) -> dict[str, object]:
        start_addr = rows[start][0]
        end_addr = rows[end - 1][0] if end - 1 >= start else start_addr
        return {
            "start": start,
            "end": end,
            "state": state,
            "binary_start": start_addr,
            "binary_end": end_addr,
            "trace_start": start_addr,
            "trace_end": end_addr,
        }

    def _section_label(self, section: dict[str, object]) -> str:
        match_count = int(section.get("match_count", 0) or 0)
        total = int(section.get("total_rows", 0) or 0)
        return f"{match_count}/{total} match"

    def _apply_section_color(self, item: QTableWidgetItem, state: str) -> None:
        colors = {
            "match": QColor("#c8e6c9"),
            "mismatch": QColor("#ffcdd2"),
            "missing": QColor("#ffe0b2"),
        }
        color = colors.get(state)
        if color:
            item.setBackground(color)

    def _format_range(self, section: dict[str, object], key: str = "binary") -> str:
        start_addr = section.get(f"{key}_start", 0)
        end_addr = section.get(f"{key}_end", 0)
        return f"0x{int(start_addr):x} – 0x{int(end_addr):x}"

    def _handle_overview_activation(self, row: int, _column: int) -> None:
        self._show_section(row)

    def _set_zoom_state(self, zoomed_in: bool) -> None:
        analyze_button = getattr(self, "analyze_button", None)
        if analyze_button is not None:
            analyze_button.setVisible(not zoomed_in)
        zoom_button = getattr(self, "zoom_out_button", None)
        if zoom_button is not None:
            zoom_button.setText("Back" if zoomed_in else "Zoom Out")
            zoom_button.setVisible(zoomed_in)

    def _show_section(
        self,
        index: int,
        *,
        progress_callback: Callable[[str], None] | None = None,
        done_callback: Callable[[], None] | None = None,
    ) -> None:
        if index < 0 or index >= len(self._sections):
            return
        section = self._sections[index]
        subset = self._rows[int(section["start"]): int(section["end"])]
        label_text = section.get("label") or f"Section {index + 1}"
        self.view_label.setText(f"{label_text}: {self._format_range(section)}")
        self._set_zoom_state(True)
        self.stack.setCurrentWidget(self.detail_widget)
        self._current_section_index = index
        if done_callback is None:
            self._populate_detail_table(subset, progress_callback=progress_callback)
            return

        def _finish_section() -> None:
            if done_callback:
                done_callback()

        self._populate_detail_table(
            subset,
            progress_callback=progress_callback,
            done_callback=_finish_section,
        )

    def _finalize_overview_selection(self) -> None:
        table = getattr(self, "overview_table", None)
        if table is None:
            return
        sections = list(self._sections)
        if self._current_section_index is not None and self._current_section_index < len(sections):
            table.selectRow(self._current_section_index)
        else:
            table.clearSelection()

    def _update_progress_bar(self) -> None:
        total = max(1, self._total_rows)
        value = min(self._match_rows, total)
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(value)
        percentage = (value / total) * 100 if total else 0
        self.progress_bar.setFormat(f"Matching instructions: {value}/{total} ({percentage:.1f}%)")

    def _prompt_binary_offset(self) -> None:
        default_text = self._format_offset(self._binary_offset)
        text, ok = QInputDialog.getText(
            self,
            "Adjust Binary Offset",
            "Enter the offset applied to binary addresses (hex values may use 0x prefix):",
            text=default_text,
        )
        if not ok:
            return
        value = self._parse_offset_input(text)
        if value is None:
            QMessageBox.warning(self, "Invalid offset", "Please enter a valid decimal or hexadecimal integer.")
            return
        self._apply_binary_offset(value)

    def _open_sequence_analyzer(self) -> None:
        if not self._raw_rows:
            QMessageBox.information(self, "No data", "Load a preview before analyzing sequences.")
            return
        dialog = SequenceAnalyzerDialog(
            self,
            self._raw_rows,
            binary_offset=self._binary_offset,
            binary_path=self._binary_path,
        )
        selected_offset: dict[str, int | None] = {"value": None}

        def _remember_offset(value: object) -> None:
            if selected_offset["value"] is not None:
                return
            try:
                numeric = int(value)
            except Exception:
                return
            selected_offset["value"] = numeric
            QTimer.singleShot(0, lambda: self._show_pending_offset_dialog(numeric))

        dialog.offset_selected.connect(_remember_offset)
        dialog.trace_address_requested.connect(self._focus_trace_address_from_analyzer)
        dialog.exec()
        if selected_offset["value"] is not None:
            self._apply_binary_offset(selected_offset["value"] or 0)

    def _focus_trace_address_from_analyzer(self, address: object) -> None:
        try:
            numeric_address = int(address)
        except Exception:
            return
        row_index = self._row_index_for_trace_address(numeric_address)
        if row_index is None:
            return
        section_index = self._section_index_for_row(row_index)
        if section_index is not None:
            self._show_section(section_index)
            section = self._sections[section_index]
            relative_index = row_index - int(section["start"])
        else:
            self._set_zoom_state(True)
            self.stack.setCurrentWidget(self.detail_widget)
            self.view_label.setText("Detail View")
            relative_index = row_index
        table = getattr(self, "detail_table", None)
        if table is None or relative_index < 0 or relative_index >= table.rowCount():
            return
        table.clearSelection()
        table.selectRow(relative_index)
        target_item = table.item(relative_index, 0)
        if target_item:
            table.scrollToItem(target_item, QAbstractItemView.PositionAtCenter)

    def _row_index_for_trace_address(self, address: int) -> int | None:
        if not self._sorted_address_values:
            return None
        pos = bisect_left(self._sorted_address_values, address)
        if pos < len(self._sorted_address_values) and self._sorted_address_values[pos] == address:
            return self._sorted_row_addresses[pos][1]
        return None

    def _show_pending_offset_dialog(self, offset_value: int) -> None:
        total_rows = len(self._raw_rows)
        label = (
            self._format_progress_status(
                f"Applying offset {self._format_offset(offset_value)}",
                0,
                total_rows,
            )
            if total_rows
            else "Applying offset (no rows)"
        )
        self._ensure_offset_progress_dialog(total_rows, label)

    def _ensure_offset_progress_dialog(self, total_rows: int, label: str) -> QProgressDialog:
        max_value = max(total_rows, 1)
        self.raise_()
        self.activateWindow()
        dialog = self._offset_progress_dialog
        if dialog is None:
            dialog = QProgressDialog("Applying binary offset...", None, 0, max_value, self)
            dialog.setWindowTitle("Applying Binary Offset")
            dialog.setWindowModality(Qt.WindowModal)
            dialog.setCancelButton(None)
            dialog.setMinimumDuration(0)
            dialog.setAutoClose(False)
            dialog.setAutoReset(False)
            dialog.resize(520, 200)
            self._offset_progress_dialog = dialog
        dialog.setRange(0, max_value)
        dialog.setValue(0)
        dialog.setLabelText(label)
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        QApplication.processEvents()
        return dialog

    def _update_offset_progress_label(self, text: str) -> None:
        dialog = self._offset_progress_dialog
        if not dialog:
            return
        dialog.setLabelText(text)
        QApplication.processEvents()

    @staticmethod
    def _format_progress_status(prefix: str, completed: int, total: int) -> str:
        if total <= 0:
            return prefix
        bounded_total = max(total, 1)
        bounded_completed = max(0, min(completed, bounded_total))
        percent = (bounded_completed / bounded_total) * 100 if bounded_total else 0.0
        return f"{prefix} ({bounded_completed}/{bounded_total}, {percent:.1f}%)"

    def _parse_offset_input(self, raw: str | None) -> int | None:
        if raw is None:
            return None
        text = raw.strip()
        if not text:
            return 0
        try:
            return int(text, 0)
        except ValueError:
            return None

    def _apply_binary_offset(self, offset: int) -> None:
        if offset == self._binary_offset:
            return
        if getattr(self, "_offset_thread", None):
            return
        if hasattr(self, "adjust_offset_button"):
            self.adjust_offset_button.setEnabled(False)
        total_rows = len(self._raw_rows)
        label = (
            self._format_progress_status("Updating preview", 0, total_rows)
            if total_rows
            else "Updating preview (no rows)"
        )
        self._ensure_offset_progress_dialog(total_rows, label)

        worker = OffsetRecalcWorker(
            raw_rows=self._raw_rows,
            segments=self._segments,
            offset=offset,
            raw_addresses=self._raw_addresses,
            sorted_values=self._sorted_address_values,
            sorted_pairs=self._sorted_row_addresses,
        )
        thread = QThread(self)
        worker.moveToThread(thread)
        self._offset_worker = worker
        self._offset_thread = thread

        def _cleanup() -> None:
            if hasattr(self, "adjust_offset_button"):
                self.adjust_offset_button.setEnabled(True)
            if self._offset_progress_dialog:
                self._offset_progress_dialog.close()
                self._offset_progress_dialog.deleteLater()
                self._offset_progress_dialog = None
            if self._offset_thread:
                self._offset_thread.quit()
                self._offset_thread.wait()
                self._offset_thread.deleteLater()
                self._offset_thread = None
            if self._offset_worker:
                self._offset_worker.deleteLater()
                self._offset_worker = None

        def _handle_finished(payload: dict[str, object]) -> None:
            steps: deque[tuple[str, bool, Callable[..., None]]] = deque()

            def enqueue(
                label: str,
                func: Callable[[], None] | Callable[[Callable[[], None]], None],
                *,
                async_step: bool = False,
            ) -> None:
                steps.append((label, async_step, func))

            enqueue("Applying new rows...", lambda: self._assign_offset_payload(payload, offset))
            enqueue(
                "Refreshing overview table...",
                lambda done: self._populate_overview_table(
                    progress_callback=self._update_offset_progress_label,
                    done_callback=done,
                ),
                async_step=True,
            )
            if (
                self._current_section_index is not None
                and self._current_section_index < len(self._sections)
            ):
                enqueue(
                    "Refreshing section view...",
                    lambda done: self._show_section(
                        self._current_section_index,
                        progress_callback=self._update_offset_progress_label,
                        done_callback=done,
                    ),
                    async_step=True,
                )
            else:
                enqueue("Showing overview...", self._show_overview)
            enqueue("Updating summary widgets...", self._update_progress_bar)
            enqueue("Updating offset label...", self._update_offset_label)

            steps_total = len(steps)
            progress_dialog = self._offset_progress_dialog
            if progress_dialog:
                if steps_total:
                    progress_dialog.setRange(0, steps_total)
                    progress_dialog.setValue(0)
                    progress_dialog.setLabelText(
                        self._format_progress_status("Finalizing preview", 0, steps_total)
                    )
                else:
                    progress_dialog.setRange(0, 0)
                    progress_dialog.setLabelText("Finalizing preview...")
                QApplication.processEvents()

            def _run_next_step() -> None:
                if not steps:
                    _cleanup()
                    return
                progress_dialog = self._offset_progress_dialog
                completed = steps_total - len(steps)
                label, async_step, func = steps.popleft()
                if progress_dialog:
                    if steps_total:
                        progress_dialog.setValue(min(completed, steps_total))
                        progress_dialog.setLabelText(
                            self._format_progress_status(label, completed, steps_total)
                        )
                    else:
                        progress_dialog.setLabelText(label)
                    QApplication.processEvents()

                def _continue(completed_so_far: int = completed) -> None:
                    progress_dialog = self._offset_progress_dialog
                    if progress_dialog and steps_total:
                        progress_dialog.setValue(min(completed_so_far + 1, steps_total))
                    QApplication.processEvents()
                    QTimer.singleShot(0, _run_next_step)

                if async_step:
                    func(_continue)
                else:
                    func()
                    _continue()

            QTimer.singleShot(0, _run_next_step)

        def _handle_failed(message: str) -> None:
            QMessageBox.warning(self, "Offset update failed", message)
            _cleanup()

        def _handle_progress(processed: int, total: int) -> None:
            current_total = total if total else total_rows
            current_total = max(current_total, 1)
            clamped = max(0, min(processed, current_total))
            progress_dialog = self._offset_progress_dialog
            if not progress_dialog:
                return
            if progress_dialog.maximum() != current_total:
                progress_dialog.setRange(0, current_total)
            progress_dialog.setValue(clamped)
            if not total_rows:
                self._update_offset_progress_label("Updating preview...")
                return
            if clamped >= current_total:
                finalize_text = self._format_progress_status(
                    "Updating preview",
                    current_total,
                    current_total,
                )
                self._update_offset_progress_label(f"{finalize_text} — finalizing preview...")
                return
            self._update_offset_progress_label(
                self._format_progress_status("Updating preview", clamped, current_total)
            )

        worker.progress.connect(_handle_progress)
        worker.finished.connect(_handle_finished)
        worker.failed.connect(_handle_failed)
        thread.started.connect(worker.run)
        thread.start()

    def _assign_offset_payload(self, payload: dict[str, object], offset: int) -> None:
        self._binary_offset = offset
        self._rows = list(payload.get("rows", []))
        self._total_rows = len(self._rows)
        self._match_rows = 0
        self._sections = []
        self._resolve_binary_rows()
        self._recompute_sections()
        self._offset_dirty = self._binary_offset != self._saved_offset_value
        self._update_offset_action_state()

    def _update_offset_label(self) -> None:
        if hasattr(self, "offset_label"):
            suffix = ""
            if self._offset_save_enabled and getattr(self, "_offset_dirty", False):
                suffix = " (unsaved)"
            self.offset_label.setText(f"Binary offset: {self._format_offset(self._binary_offset)}{suffix}")

    def _update_offset_action_state(self) -> None:
        button = getattr(self, "save_offset_button", None)
        if button is not None:
            handler_available = self._offset_save_handler is not None
            enabled = handler_available and getattr(self, "_offset_dirty", False)
            button.setEnabled(enabled)
            button.setStyleSheet("" if enabled else "color: #888;")
        self._update_offset_label()

    @staticmethod
    def _format_offset(value: int) -> str:
        return f"{value:+#x}"

    def _rows_with_offset(self, offset: int) -> list[tuple[int, str, str]]:
        if not self._raw_rows:
            return []
        if not offset:
            return list(self._raw_rows)
        adjusted: list[tuple[int, str, str]] = []
        for idx, (addr, binary_text, logged_text) in enumerate(self._raw_rows, start=1):
            adjusted.append((addr + offset, binary_text, logged_text))
            _yield_gui_events(idx)
        return adjusted

    def _handle_save_offset_clicked(self) -> None:
        if not self._offset_save_enabled or not self._offset_dirty:
            return
        self._perform_save()

    def _perform_save(self) -> bool:
        handler = self._offset_save_handler
        if handler is None:
            QMessageBox.information(
                self,
                "Saving unavailable",
                "This preview is not associated with a HoneyProc entry, so the offset cannot be saved.",
            )
            return False
        try:
            result = handler(int(self._binary_offset))
        except Exception as exc:
            QMessageBox.critical(self, "Unable to save offset", str(exc))
            return False
        if result is False:
            return False
        self._saved_offset_value = int(self._binary_offset)
        self._offset_dirty = False
        self._update_offset_action_state()
        return True

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if getattr(self, "_offset_dirty", False) and self._should_prompt_unsaved_close():
            decision = self._prompt_unsaved_changes()
            if decision == QMessageBox.Cancel:
                event.ignore()
                return
            if decision == QMessageBox.Save:
                if not self._perform_save():
                    event.ignore()
                    return
        super().closeEvent(event)

    def _should_prompt_unsaved_close(self) -> bool:
        return bool(getattr(self, "_warn_on_unsaved_close", False))

    def _prompt_unsaved_changes(self) -> QMessageBox.StandardButton:
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Unsaved offset")
        dialog.setIcon(QMessageBox.Warning)
        dialog.setText("Binary offset changes have not been saved.")
        dialog.setInformativeText("Save the updated offset before closing?")
        dialog.setStandardButtons(QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel)
        dialog.setDefaultButton(QMessageBox.Save)
        return QMessageBox.StandardButton(dialog.exec())

    def _resolve_binary_rows(self) -> None:
        resolver = getattr(self, "_binary_instruction_resolver", None)
        if resolver is None:
            return
        total = len(self._rows)
        if total == 0:
            return
        worker = BinaryResolveWorker(self._rows, self._detail_binary_text)
        thread = QThread(self)
        worker.moveToThread(thread)

        progress_dialog: BusyProgressDialog | None = None
        use_internal_progress = bool(total >= 500 and self._init_progress_callback is None)
        if use_internal_progress:
            progress_dialog = BusyProgressDialog("Resolving binary instructions...", "Skip", 0, total, self)
            progress_dialog.setWindowTitle("Preparing Preview")
            progress_dialog.setWindowModality(Qt.ApplicationModal if self.isVisible() else Qt.WindowModal)
            progress_dialog.setMinimumDuration(0)
            progress_dialog.setAutoClose(True)
            progress_dialog.setAutoReset(True)
            progress_dialog.setValue(0)
            progress_dialog.start_pulsing()

        loop = QEventLoop()
        updated_rows: list[tuple[int, str, str]] | None = None
        error_message: str | None = None

        def _handle_progress(processed: int, total_count: int) -> None:
            dialog = progress_dialog
            if dialog is None:
                self._report_init_progress(
                    f"Resolving binary instructions ({processed}/{max(total_count, 1)})"
                )
                return
            dialog.blockSignals(True)
            try:
                if dialog.maximum() != max(total_count, 1):
                    dialog.setRange(0, max(total_count, 1))
                dialog.setValue(processed)
                dialog.setLabelText(f"Resolving binary instructions ({processed}/{total_count})")
            finally:
                dialog.blockSignals(False)
                QApplication.processEvents()

        def _handle_finished(rows: object) -> None:
            nonlocal updated_rows
            if isinstance(rows, list):
                updated_rows = rows
            loop.quit()

        def _handle_failed(message: str) -> None:
            nonlocal error_message
            error_message = message
            loop.quit()

        worker.progress.connect(_handle_progress)
        worker.finished.connect(_handle_finished)
        worker.failed.connect(_handle_failed)
        if progress_dialog is not None:
            progress_dialog.canceled.connect(worker.cancel)

        thread.started.connect(worker.run)
        thread.start()
        loop.exec()

        worker.progress.disconnect()
        worker.finished.disconnect()
        worker.failed.disconnect()
        if progress_dialog is not None:
            progress_dialog.canceled.disconnect(worker.cancel)
            progress_dialog.close()

        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()

        if error_message:
            QMessageBox.warning(
                self,
                "Binary instructions unavailable",
                f"Unable to resolve binary instructions: {error_message}",
            )
            return
        if updated_rows is not None:
            self._rows = updated_rows

    def _recompute_sections(self) -> None:
        rows = list(self._rows)
        worker = SectionBuildWorker(
            rows,
            self._segments,
            offset=self._binary_offset,
            raw_addresses=self._raw_addresses,
            sorted_values=self._sorted_address_values,
            sorted_pairs=self._sorted_row_addresses,
        )
        thread = QThread(self)
        worker.moveToThread(thread)

        progress_dialog: BusyProgressDialog | None = None
        progress_total = len(self._segments) if self._segments else len(rows)
        show_internal_progress = bool(
            len(rows) >= 500 and progress_total > 0 and self._init_progress_callback is None
        )
        if show_internal_progress:
            progress_dialog = BusyProgressDialog("Computing preview sections...", None, 0, progress_total, self)
            progress_dialog.setWindowTitle("Preparing Preview")
            progress_dialog.setWindowModality(Qt.ApplicationModal if self.isVisible() else Qt.WindowModal)
            progress_dialog.setMinimumDuration(0)
            progress_dialog.setCancelButton(None)
            progress_dialog.setLabelText(f"Computing preview sections (0/{progress_total})")
            progress_dialog.setValue(0)
            progress_dialog.show()

        loop = QEventLoop()
        result: dict[str, object] | None = None
        error: str | None = None

        def _handle_finished(payload: object) -> None:
            nonlocal result
            if isinstance(payload, dict):
                result = payload
            loop.quit()

        def _handle_failed(message: str) -> None:
            nonlocal error
            error = message
            loop.quit()

        def _handle_progress(processed: int, total_count: int) -> None:
            dialog = progress_dialog
            total_value = max(total_count, 1)
            clamped = max(0, min(processed, total_value))
            if dialog is None:
                self._report_init_progress(
                    f"Computing preview sections ({clamped}/{total_value})"
                )
                return
            dialog.setRange(0, total_value)
            dialog.setValue(clamped)
            dialog.setLabelText(f"Computing preview sections ({clamped}/{total_value})")
            QApplication.processEvents()

        worker.finished.connect(_handle_finished)
        worker.failed.connect(_handle_failed)
        worker.progress.connect(_handle_progress)
        thread.started.connect(worker.run)
        thread.start()
        loop.exec()

        worker.finished.disconnect(_handle_finished)
        worker.failed.disconnect(_handle_failed)
        worker.progress.disconnect(_handle_progress)
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()

        if progress_dialog is not None:
            progress_dialog.close()

        if error:
            QMessageBox.warning(
                self,
                "Unable to compute sections",
                f"Failed to compute preview sections: {error}",
            )
            self._sections = []
            self._match_rows = 0
            return
        if result is None:
            self._sections = []
            self._match_rows = 0
            return
        self._match_rows = int(result.get("match_rows", 0) or 0)
        self._sections = list(result.get("sections", []) or [])

    def _populate_detail_table(
        self,
        rows: list[tuple[int, str, str]],
        *,
        progress_callback: Callable[[str], None] | None = None,
        done_callback: Callable[[], None] | None = None,
    ) -> None:
        table = getattr(self, "detail_table", None)
        if table is None:
            if done_callback:
                done_callback()
            return
        total_rows = len(rows)
        table.clearContents()
        table.setRowCount(total_rows)
        if total_rows == 0:
            table.resizeRowsToContents()
            if progress_callback:
                progress_callback("No detail rows to populate.")
            if done_callback:
                done_callback()
            return

        chunk = max(total_rows // 50, 50) if total_rows else 1

        def _process_range(start: int, end: int) -> None:
            for row_idx in range(start, end):
                address, binary_text, logged_text = rows[row_idx]
                self._set_detail_row(row_idx, address, binary_text, logged_text)

        def _finalize_rows() -> None:
            table.resizeRowsToContents()
            if progress_callback:
                progress_callback(f"Detail rows ready ({total_rows}/{total_rows})")
            if done_callback:
                done_callback()

        if done_callback is None:
            for start in range(0, total_rows, chunk):
                end = min(start + chunk, total_rows)
                _process_range(start, end)
                if progress_callback:
                    progress_callback(f"Populating detail rows ({end}/{total_rows})")
            _finalize_rows()
            return

        def _process_async(start: int = 0) -> None:
            end = min(start + chunk, total_rows)
            _process_range(start, end)
            if progress_callback:
                progress_callback(f"Populating detail rows ({end}/{total_rows})")
            if end < total_rows:
                QTimer.singleShot(0, lambda: _process_async(end))
            else:
                _finalize_rows()

        _process_async(0)

    def _detail_binary_text(self, address: int, stored_text: str | None) -> str:
        cleaned = (stored_text or "").strip()
        if cleaned and not cleaned.startswith("<"):
            return cleaned
        looked_up = self._lookup_binary_instruction(address)
        if looked_up:
            return looked_up
        return cleaned or "<unavailable>"

    def _lookup_binary_instruction(self, adjusted_address: int) -> str | None:
        resolver = getattr(self, "_binary_instruction_resolver", None)
        if resolver is None:
            return None
        if self._binary_offset:
            binary_address = adjusted_address - (2 * self._binary_offset)
        else:
            binary_address = adjusted_address
        if binary_address < 0:
            return None
        return resolver.resolve(binary_address)

    def _set_detail_row(
        self,
        row_idx: int,
        address: int,
        binary_text: str | None,
        logged_text: str | None,
    ) -> None:
        table = getattr(self, "detail_table", None)
        if table is None:
            return
        addr_item = QTableWidgetItem(f"0x{address:x}")
        addr_item.setFont(self._monospace_font(addr_item.font()))
        table.setItem(row_idx, 0, addr_item)
        resolved_binary = self._detail_binary_text(address, binary_text)
        table.setItem(row_idx, 1, QTableWidgetItem(resolved_binary))
        table.setItem(row_idx, 2, QTableWidgetItem(logged_text or ""))
        state = self._row_state((address, resolved_binary, logged_text))
        self._apply_section_color(addr_item, state)
        self._apply_section_color(table.item(row_idx, 1), state)
        self._apply_section_color(table.item(row_idx, 2), state)

    def _detail_has_selection(self) -> bool:
        table = getattr(self, "detail_table", None)
        if table is None:
            return False
        selection = table.selectionModel()
        return bool(selection and selection.hasSelection())

    def _show_detail_context_menu(self, point: QPoint) -> None:
        table = getattr(self, "detail_table", None)
        if table is None or self.stack.currentWidget() != self.detail_widget:
            return
        menu = QMenu(self)
        copy_action = menu.addAction("Copy Selection")
        copy_action.setEnabled(self._detail_has_selection())
        global_point = table.viewport().mapToGlobal(point)
        result = menu.exec(global_point)
        if result == copy_action:
            self._copy_selected_rows()

    def _copy_selected_rows(self) -> None:
        if self.stack.currentWidget() != self.detail_widget or not self._detail_has_selection():
            QApplication.clipboard().setText("")
            return
        table = self.detail_table
        selection = table.selectionModel()
        if selection is None:
            QApplication.clipboard().setText("")
            return
        rows = sorted({index.row() for index in selection.selectedIndexes()})
        parts: list[str] = []
        for row in rows:
            address = table.item(row, 0).text() if table.item(row, 0) else ""
            binary_text = table.item(row, 1).text() if table.item(row, 1) else ""
            logged_text = table.item(row, 2).text() if table.item(row, 2) else ""
            parts.append(f"{address}\t{binary_text}\t{logged_text}")
        QApplication.clipboard().setText("\n".join(parts))

    def _show_overview(self) -> None:
        if hasattr(self, "stack"):
            self.stack.setCurrentWidget(self.overview_widget)
        self.view_label.setText("Overview")
        self._set_zoom_state(False)
        self._current_section_index = None


class SanitizationPreviewDialog(InstructionPreviewDialog):
    def __init__(
        self,
        parent: QWidget,
        entry_label: str,
        rows: list[tuple[int, str, str]],
        segments: list[tuple[int, int]] | None = None,
        binary_path: Path | None = None,
        *,
        saved_offset: int = 0,
        save_offset_callback: Callable[[int], bool | None] | None = None,
        warn_on_unsaved: bool = False,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(
            parent,
            entry_label,
            rows,
            segments,
            binary_path,
            saved_offset=saved_offset,
            save_offset_callback=save_offset_callback,
            warn_on_unsaved=warn_on_unsaved,
            enable_offset_save=True,
            progress_callback=progress_callback,
        )

    def _should_prompt_unsaved_close(self) -> bool:
        if super()._should_prompt_unsaved_close():
            return True
        button = getattr(self, "save_offset_button", None)
        return bool(button and button.isEnabled())


class ParentComparisonPreviewDialog(InstructionPreviewDialog):
    def __init__(
        self,
        parent: QWidget,
        entry_label: str,
        rows: list[tuple[int, str, str]],
        segments: list[tuple[int, int]] | None = None,
        binary_path: Path | None = None,
        *,
        saved_offset: int = 0,
        progress_callback: Callable[[str], None] | None = None,
        parent_binary_addresses: list[int] | None = None,
        save_offset_callback: Callable[[int], bool | None] | None = None,
        warn_on_unsaved: bool = False,
    ) -> None:
        self._parent_binary_addresses = list(parent_binary_addresses or [])
        description = (
            "Compare sanitized instructions against their parent binary. Use the overview to locate segments and"
            " inspect mismatches in detail."
        )
        super().__init__(
            parent,
            entry_label,
            rows,
            segments,
            binary_path,
            saved_offset=saved_offset,
            save_offset_callback=save_offset_callback,
            warn_on_unsaved=warn_on_unsaved,
            enable_offset_save=save_offset_callback is not None,
            progress_callback=progress_callback,
            description_text=description,
            window_title=f"Compare to Parent — {entry_label}",
            overview_binary_label="Sanitized Range",
            overview_trace_label="Parent Range",
            detail_binary_label="Sanitized Instruction",
            detail_trace_label="Parent Instruction",
            no_sections_text="No instruction samples were found in the parent binary for comparison.",
        )
        self._apply_parent_ranges()

    def _should_prompt_unsaved_close(self) -> bool:
        if super()._should_prompt_unsaved_close():
            return True
        button = getattr(self, "save_offset_button", None)
        return bool(button and button.isEnabled())

    def _apply_parent_ranges(self) -> None:
        addresses = getattr(self, "_parent_binary_addresses", None)
        if not addresses or not self._sections:
            return
        total = len(addresses)
        for section in self._sections:
            start_idx = int(section.get("start", 0) or 0)
            end_idx = int(section.get("end", start_idx) or start_idx)
            if start_idx >= total:
                continue
            end_idx = min(max(start_idx + 1, end_idx), total)
            subset = addresses[start_idx:end_idx]
            if not subset:
                continue
            section["trace_start"] = subset[0]
            section["trace_end"] = subset[-1]


class TraceComparisonPreviewDialog(InstructionPreviewDialog):
    def __init__(
        self,
        parent: QWidget,
        entry_label: str,
        rows: list[tuple[int, str, str]],
        *,
        segments: list[tuple[int, int]] | None = None,
        sanitized_label: str,
        original_label: str,
    ) -> None:
        description = (
            "Review the sanitized run trace alongside the original trace. Use the overview to locate divergent"
            " sections, then drill into specific instructions to inspect mismatches."
        )
        super().__init__(
            parent,
            entry_label,
            rows,
            segments,
            binary_path=None,
            saved_offset=0,
            progress_callback=None,
            description_text=description,
            window_title=f"Compare Logs — {sanitized_label} vs {original_label}",
            overview_binary_label="Sanitized Trace Range",
            overview_trace_label="Original Trace Range",
            detail_binary_label="Sanitized Trace Instruction",
            detail_trace_label="Original Trace Instruction",
            enable_offset_save=False,
        )
        self._disable_offset_controls()

    def _disable_offset_controls(self) -> None:
        if hasattr(self, "analyze_button") and self.analyze_button:
            self.analyze_button.hide()
        if hasattr(self, "adjust_offset_button") and self.adjust_offset_button:
            self.adjust_offset_button.hide()
        offset_label = getattr(self, "offset_label", None)
        if offset_label:
            offset_label.hide()
        save_button = getattr(self, "save_offset_button", None)
        if save_button:
            save_button.hide()


class SequenceAnalyzerDialog(QDialog):
    offset_selected = Signal(object)
    trace_address_requested = Signal(object)

    def __init__(
        self,
        parent: QWidget,
        rows: list[tuple[int, str, str]],
        *,
        binary_offset: int = 0,
        binary_path: Path | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Instruction Sequence Analyzer")
        self._trace_rows = list(rows)
        self._binary_offset = binary_offset
        self._binary_path = Path(binary_path) if binary_path else None
        self._binary_rows = self._build_binary_rows()
        self._trace_norm = [self._normalize_instruction(row[2]) for row in self._trace_rows]
        self._find_thread: QThread | None = None
        self._find_worker: SequenceAnalyzerFindWorker | None = None
        self._find_progress_dialog: BusyProgressDialog | None = None
        self._find_total_positions = 0
        self._matches: list[dict[str, object]] = []
        self._trace_ngram_cache: dict[int, dict[tuple[str, ...], list[int]]] = {}
        self._ngram_matches: list[dict[str, object]] = []
        self._ngram_thread: QThread | None = None
        self._ngram_worker: SequenceAnalyzerNgramSelectionWorker | None = None
        self._ngram_progress_dialog: BusyProgressDialog | None = None
        self._pending_ngram_request: dict[str, object] | None = None

        layout = QVBoxLayout(self)
        description = QLabel(
            "Select sequential binary instructions, then search the trace for the same sequence to infer the offset.",
            self,
        )
        description.setWordWrap(True)
        layout.addWidget(description)

        content_row = QHBoxLayout()
        layout.addLayout(content_row)

        left_panel = QVBoxLayout()
        binary_label = QLabel("Binary Instructions", self)
        binary_label.setStyleSheet("font-weight: bold;")
        left_panel.addWidget(binary_label)
        search_row = QHBoxLayout()
        self.binary_filter_input = QLineEdit(self)
        self.binary_filter_input.setPlaceholderText("Search addresses or instructions...")
        self.binary_filter_input.setClearButtonEnabled(True)
        self.binary_filter_input.textChanged.connect(self._apply_binary_filter)
        search_row.addWidget(self.binary_filter_input)
        left_panel.addLayout(search_row)
        self.binary_table = QTableWidget(len(self._binary_rows), 3, self)
        self.binary_table.setHorizontalHeaderLabels(["#", "Binary Address", "Binary Instruction"])
        self.binary_table.verticalHeader().setVisible(False)
        self.binary_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.binary_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        header = self.binary_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        self._populate_binary_table()
        selection_model = self.binary_table.selectionModel()
        if selection_model:
            selection_model.selectionChanged.connect(self._update_find_button_state)
        left_panel.addWidget(self.binary_table)

        self.find_button = QPushButton("Find in Trace", self)
        self.find_button.setEnabled(False)
        self.find_button.clicked.connect(self._handle_find_sequence)
        left_panel.addWidget(self.find_button)
        content_row.addLayout(left_panel, 2)

        right_panel = QVBoxLayout()
        matches_label = QLabel("Trace Matches", self)
        matches_label.setStyleSheet("font-weight: bold;")
        right_panel.addWidget(matches_label)
        self.results_table = QTableWidget(0, 3, self)
        self.results_table.setHorizontalHeaderLabels(["Trace Start", "Offset", "Preview"])
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        results_header = self.results_table.horizontalHeader()
        results_header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        results_header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        results_header.setSectionResizeMode(2, QHeaderView.Stretch)
        right_panel.addWidget(self.results_table)
        self.set_offset_button = QPushButton("Set Binary Offset", self)
        self.set_offset_button.setEnabled(False)
        self.set_offset_button.clicked.connect(self._handle_set_offset_clicked)
        right_panel.addWidget(self.set_offset_button)
        self.results_status = QLabel("Select instructions to begin.", self)
        self.results_status.setStyleSheet("color: #666;")
        right_panel.addWidget(self.results_status)
        content_row.addLayout(right_panel, 3)

        self.results_table.itemSelectionChanged.connect(self._update_set_offset_button_state)

        ngram_row = QHBoxLayout()
        self.ngram_label = QLabel("N-gram length:", self)
        ngram_row.addWidget(self.ngram_label)
        self.ngram_input = QSpinBox(self)
        max_ngram = max(2, min(64, len(self._binary_rows) if self._binary_rows else 64))
        self.ngram_input.setRange(2, max_ngram)
        self.ngram_input.setValue(min(5, max_ngram))
        self.ngram_input.setToolTip("Number of consecutive binary instructions to search for in the trace.")
        ngram_row.addWidget(self.ngram_input)
        self.ngram_search_button = QPushButton("Find N-gram Matches", self)
        self.ngram_search_button.clicked.connect(self._handle_ngram_search)
        ngram_row.addWidget(self.ngram_search_button)
        ngram_row.addStretch(1)
        layout.addLayout(ngram_row)

        self.ngram_results_container = QWidget(self)
        ngram_container_layout = QVBoxLayout(self.ngram_results_container)
        ngram_container_layout.setContentsMargins(0, 0, 0, 0)
        header_row = QHBoxLayout()
        self.ngram_results_label = QLabel("N-gram Matches", self.ngram_results_container)
        header_row.addWidget(self.ngram_results_label)
        header_row.addStretch(1)
        self.ngram_close_button = QToolButton(self.ngram_results_container)
        self.ngram_close_button.setText("×")
        self.ngram_close_button.setToolTip("Hide n-gram matches list")
        self.ngram_close_button.clicked.connect(self._hide_ngram_results)
        header_row.addWidget(self.ngram_close_button)
        ngram_container_layout.addLayout(header_row)
        self.ngram_results_tree = QTreeWidget(self.ngram_results_container)
        self.ngram_results_tree.setHeaderLabels(["Location", "Details"])
        self.ngram_results_tree.setAlternatingRowColors(True)
        self.ngram_results_tree.setRootIsDecorated(True)
        ngram_header = self.ngram_results_tree.header()
        if ngram_header is not None:
            ngram_header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
            ngram_header.setSectionResizeMode(1, QHeaderView.Stretch)
        self.ngram_results_tree.itemActivated.connect(self._handle_ngram_item_activated)
        self.ngram_results_tree.itemClicked.connect(self._handle_ngram_item_activated)
        self.ngram_results_tree.itemExpanded.connect(self._handle_ngram_item_expanded)
        ngram_container_layout.addWidget(self.ngram_results_tree)
        self.ngram_results_container.hide()
        layout.addWidget(self.ngram_results_container)

        buttons = QDialogButtonBox(QDialogButtonBox.Close, self)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        if not self._binary_rows:
            self.results_status.setText(
                "No binary instructions were resolved for this preview. Adjust the binary offset and reopen Analyze."
            )
            self.find_button.setEnabled(False)

        _resize_widget_to_screen(self)

    def _build_binary_rows(self) -> list[dict[str, object]]:
        rows = self._load_binary_instructions_from_binary()
        if rows:
            return rows
        return self._build_rows_from_trace_preview()

    def _load_binary_instructions_from_binary(self) -> list[dict[str, object]]:
        if not self._binary_path:
            return []
        try:
            binary = lief.parse(str(self._binary_path))
        except Exception:
            return []
        sanitizer = BinarySanitizer()
        try:
            arch, mode, _ = sanitizer._capstone_config(binary)
        except Exception:
            return []
        import capstone  # defer heavy import until needed

        md = capstone.Cs(arch, mode)
        md.detail = False
        rows: list[dict[str, object]] = []
        remaining = SEQUENCE_ANALYZER_MAX_BINARY_INSTRUCTIONS
        for section in sanitizer._executable_sections(binary):
            data = bytes(section.content)
            if not data:
                continue
            for instruction in md.disasm(data, section.virtual_address):
                text = f"{instruction.mnemonic} {instruction.op_str}".strip()
                if not self._has_binary_instruction(text):
                    continue
                raw_addr = int(instruction.address)
                rows.append({
                    "raw": raw_addr,
                    "display": raw_addr + self._binary_offset,
                    "text": text,
                })
                remaining -= 1
                if remaining <= 0:
                    rows.sort(key=lambda row: row["raw"])
                    return rows
        rows.sort(key=lambda row: row["raw"])
        return rows

    def _build_rows_from_trace_preview(self) -> list[dict[str, object]]:
        if not self._trace_rows:
            return []
        rows: list[dict[str, object]] = []
        for addr, binary_text, _logged in self._trace_rows:
            if not self._has_binary_instruction(binary_text):
                continue
            raw_addr = int(addr)
            rows.append({
                "raw": raw_addr,
                "display": raw_addr + self._binary_offset,
                "text": binary_text,
            })
        return rows

    def _populate_binary_table(self) -> None:
        for idx, row in enumerate(self._binary_rows):
            address = row["display"]
            binary_text = row["text"]
            index_item = QTableWidgetItem(str(idx + 1))
            addr_item = QTableWidgetItem(f"0x{int(address):x}")
            instr_item = QTableWidgetItem(binary_text or "<unavailable>")
            for item in (index_item, addr_item, instr_item):
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self.binary_table.setItem(idx, 0, index_item)
            self.binary_table.setItem(idx, 1, addr_item)
            self.binary_table.setItem(idx, 2, instr_item)

    def _apply_binary_filter(self, text: str) -> None:
        table = self.binary_table
        if table is None:
            return
        raw_query = (text or "").strip()
        terms = [part.lower() for part in (segment.strip() for segment in raw_query.split("|")) if part]
        total_rows = table.rowCount()
        if not terms:
            selected_rows = self._selected_binary_rows()
            selected_row = selected_rows[0] if selected_rows else None
            for row in range(total_rows):
                table.setRowHidden(row, False)
            if selected_row is not None and 0 <= selected_row < total_rows:
                table.selectRow(selected_row)
                target_item = table.item(selected_row, 0) or table.item(selected_row, 1)
                if target_item:
                    table.scrollToItem(target_item, QAbstractItemView.PositionAtCenter)
            self._update_find_button_state()
            return
        for row in range(total_rows):
            addr_item = table.item(row, 1)
            instr_item = table.item(row, 2)
            addr_text = (addr_item.text() if addr_item else "").lower()
            instr_text = (instr_item.text() if instr_item else "").lower()
            match = any(term in addr_text or term in instr_text for term in terms)
            table.setRowHidden(row, not match)
        table.clearSelection()
        self._update_find_button_state()

    def _update_find_button_state(self) -> None:
        selection = self._selected_binary_rows()
        self.find_button.setEnabled(bool(selection))

    def _selected_binary_rows(self) -> list[int]:
        selection = self.binary_table.selectionModel()
        if selection is None:
            return []
        rows = sorted({index.row() for index in selection.selectedRows()})
        return [row for row in rows if not self.binary_table.isRowHidden(row)]

    def _handle_find_sequence(self) -> None:
        if self._find_worker is not None:
            QMessageBox.information(
                self,
                "Search running",
                "A trace search is already running. Cancel it before starting a new one.",
            )
            return
        rows = self._selected_binary_rows()
        if not rows:
            QMessageBox.information(self, "No selection", "Select sequential binary instructions to search.")
            return
        if not self._binary_rows:
            QMessageBox.warning(self, "No data", "Unable to analyze without preview rows.")
            return
        if any(rows[idx] + 1 != rows[idx + 1] for idx in range(len(rows) - 1)):
            QMessageBox.warning(self, "Selection not sequential", "Please select sequential rows with no gaps.")
            return
        if any(not self._has_binary_instruction(self._binary_rows[idx]["text"]) for idx in rows):
            QMessageBox.warning(
                self,
                "Missing instructions",
                "One or more selected rows do not have binary instructions. Adjust the binary offset or select different rows.",
            )
            return
        sequence = [self._normalize_instruction(self._binary_rows[idx]["text"]) for idx in rows]
        if not any(sequence):
            QMessageBox.information(self, "Empty instructions", "Selected rows do not contain binary instructions.")
            return
        needle_len = len(sequence)
        search_space = max(len(self._trace_norm) - needle_len + 1, 0)
        if search_space <= 0:
            QMessageBox.information(self, "Trace too short", "Trace does not contain enough instructions to search.")
            return
        self.results_status.setText("Searching trace...")
        progress_dialog = BusyProgressDialog("Scanning trace...", "Cancel", 0, search_space, self)
        progress_dialog.setWindowTitle("Searching Trace")
        progress_dialog.setWindowModality(Qt.WindowModal)
        progress_dialog.setMinimumDuration(0)
        progress_dialog.setAutoClose(False)
        progress_dialog.setAutoReset(False)
        progress_dialog.setValue(0)
        progress_dialog.setLabelText(f"Scanning trace (0/{search_space})")
        progress_dialog.resize(580, 220)

        worker = SequenceAnalyzerFindWorker(
            trace_rows=self._trace_rows,
            trace_norm=self._trace_norm,
            binary_rows=self._binary_rows,
            binary_start_row=rows[0],
            sequence=sequence,
            total_positions=search_space,
            max_matches=SEQUENCE_ANALYZER_MAX_TRACE_MATCHES,
        )
        thread = QThread(self)
        worker.moveToThread(thread)
        worker.progress.connect(self._update_find_progress)
        worker.succeeded.connect(self._handle_find_succeeded)
        worker.cancelled.connect(self._handle_find_cancelled)
        worker.failed.connect(self._handle_find_failed)
        thread.started.connect(worker.run)
        progress_dialog.canceled.connect(worker.cancel)

        self._find_worker = worker
        self._find_thread = thread
        self._find_progress_dialog = progress_dialog
        self._find_total_positions = search_space
        self.find_button.setEnabled(False)
        progress_dialog.show()
        thread.start()

    def _handle_ngram_search(self) -> None:
        length = int(self.ngram_input.value())
        if length <= 0:
            QMessageBox.information(self, "Invalid length", "Choose an n-gram length greater than zero.")
            return
        if len(self._binary_rows) < length:
            QMessageBox.information(
                self,
                "Not enough binary instructions",
                f"Only {len(self._binary_rows)} binary instructions are available, which is less than the requested length.",
            )
            return
        if len(self._trace_norm) < length:
            QMessageBox.information(
                self,
                "Trace too short",
                "Trace preview does not contain enough instructions for this n-gram length.",
            )
            return
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            matches = self._find_ngram_matches(length)
        finally:
            QApplication.restoreOverrideCursor()
        if not matches:
            QMessageBox.information(
                self,
                "No matches found",
                f"No {length}-instruction sequences from the binary were located in the trace.",
            )
            self._hide_ngram_results()
            return
        self._ngram_matches = matches
        self._show_ngram_results(matches, length)

    def _find_ngram_matches(self, length: int) -> list[dict[str, object]]:
        index = self._trace_ngram_index(length)
        if not index:
            return []
        matches: list[dict[str, object]] = []
        total = len(self._binary_rows)
        for start in range(total - length + 1):
            gram = self._binary_ngram_sequence(start, length)
            if gram is None:
                continue
            trace_positions = index.get(gram)
            if not trace_positions:
                continue
            binary_address = int(self._binary_rows[start]["display"])
            for trace_pos in trace_positions:
                trace_address = int(self._trace_rows[trace_pos][0])
                matches.append(
                    {
                        "binary_start_index": start,
                        "trace_start_index": trace_pos,
                        "binary_address": binary_address,
                        "trace_address": trace_address,
                        "offset": trace_address - binary_address,
                        "length": length,
                    }
                )
                if len(matches) >= SEQUENCE_ANALYZER_MAX_NGRAM_RESULTS:
                    return matches
        return matches

    def _trace_ngram_index(self, length: int) -> dict[tuple[str, ...], list[int]]:
        if length <= 0:
            return {}
        cached = self._trace_ngram_cache.get(length)
        if cached is not None:
            return cached
        total = len(self._trace_norm)
        if length > total:
            return {}
        index: dict[tuple[str, ...], list[int]] = {}
        for start in range(total - length + 1):
            gram_slice = self._trace_norm[start : start + length]
            if any(not part for part in gram_slice):
                continue
            gram = tuple(gram_slice)
            index.setdefault(gram, []).append(start)
        self._trace_ngram_cache[length] = index
        return index

    def _binary_ngram_sequence(self, start: int, length: int) -> tuple[str, ...] | None:
        gram: list[str] = []
        for offset in range(length):
            row = self._binary_rows[start + offset]
            normalized = self._normalize_instruction(row["text"])
            if not normalized:
                return None
            gram.append(normalized)
        return tuple(gram)

    def _show_ngram_results(self, matches: list[dict[str, object]], length: int) -> None:
        if not matches:
            self._hide_ngram_results()
            return
        label = f"N-gram Matches — length {length} ({len(matches)} result{'s' if len(matches) != 1 else ''})"
        self.ngram_results_label.setText(label)
        self.ngram_results_tree.clear()
        grouped: dict[int, list[dict[str, object]]] = {}
        for match in matches:
            start_idx = int(match.get("binary_start_index", -1))
            if start_idx < 0:
                continue
            grouped.setdefault(start_idx, []).append(match)
        for start_idx in sorted(grouped.keys()):
            binary_row = self._binary_rows[start_idx]
            binary_addr = int(binary_row["display"])
            instruction = str(binary_row["text"] or "<unavailable>")
            match_list = grouped[start_idx]
            top_item = QTreeWidgetItem(self.ngram_results_tree)
            top_item.setText(0, f"Binary 0x{binary_addr:x}")
            detail_text = f"{instruction} — {len(match_list)} trace match"
            if len(match_list) != 1:
                detail_text += "es"
            detail_text += f" (rows {start_idx + 1}-{start_idx + length})"
            top_item.setText(1, detail_text)
            top_item.setData(0, Qt.UserRole, {
                "type": "binary",
                "binary_start_index": start_idx,
                "length": length,
            })
            for match in match_list:
                trace_addr = int(match.get("trace_address", 0))
                offset_text = self._format_offset(int(match.get("offset", 0)))
                child = QTreeWidgetItem(top_item)
                child.setText(0, f"Trace 0x{trace_addr:x}")
                child.setText(1, f"Offset {offset_text}")
                child.setData(0, Qt.UserRole, {
                    "type": "trace",
                    "binary_start_index": start_idx,
                    "trace_address": trace_addr,
                    "length": length,
                })
        self.ngram_results_container.show()

    def _hide_ngram_results(self) -> None:
        self.ngram_results_tree.clear()
        self.ngram_results_label.setText("N-gram Matches")
        self.ngram_results_container.hide()
        self._ngram_matches = []

    def _show_ngram_matches_in_results(self, start_index: int, length: int, *, trace_address: int | None = None) -> None:
        if start_index < 0 or length <= 0:
            return
        request: dict[str, object] = {
            "start_index": start_index,
            "length": length,
            "trace_address": trace_address,
        }
        if self._ngram_worker is not None:
            self._pending_ngram_request = request
            self._ngram_worker.cancel()
            return
        self._launch_ngram_selection_task(start_index, length, trace_address=trace_address)

    def _launch_ngram_selection_task(
        self,
        start_index: int,
        length: int,
        *,
        trace_address: int | None = None,
    ) -> None:
        if not self._ngram_matches:
            self._populate_results([], truncated=False)
            self.results_status.setText("No n-gram matches are available for selection.")
            return
        worker = SequenceAnalyzerNgramSelectionWorker(
            matches=list(self._ngram_matches),
            trace_rows=self._trace_rows,
            binary_start_index=start_index,
            default_length=length,
            trace_address_filter=trace_address,
        )
        thread = QThread(self)
        worker.moveToThread(thread)
        worker.progress.connect(self._update_ngram_progress)
        worker.succeeded.connect(self._handle_ngram_selection_succeeded)
        worker.failed.connect(self._handle_ngram_selection_failed)
        worker.cancelled.connect(self._handle_ngram_selection_cancelled)
        thread.started.connect(worker.run)

        dialog = BusyProgressDialog("Preparing n-gram matches...", "Cancel", 0, len(self._ngram_matches), self)
        dialog.setWindowTitle("Loading N-gram Matches")
        dialog.setWindowModality(Qt.WindowModal)
        dialog.setMinimumDuration(0)
        dialog.setAutoClose(False)
        dialog.setAutoReset(False)
        if len(self._ngram_matches) == 0:
            dialog.setRange(0, 0)
        dialog.setValue(0)
        dialog.setLabelText("Preparing n-gram matches...")
        dialog.canceled.connect(worker.cancel)

        self.results_status.setText("Loading n-gram matches for selection...")
        self._ngram_worker = worker
        self._ngram_thread = thread
        self._ngram_progress_dialog = dialog
        dialog.show()
        thread.start()

    def _update_ngram_progress(self, processed: int, total: int) -> None:
        dialog = self._ngram_progress_dialog
        if not dialog:
            return
        total = max(total, 0)
        if total:
            dialog.setRange(0, total)
            dialog.setValue(min(processed, total))
            dialog.setLabelText(f"Preparing n-gram matches ({min(processed, total)}/{total})")
        else:
            dialog.setRange(0, 0)
            dialog.setLabelText("Preparing n-gram matches...")

    def _handle_ngram_selection_succeeded(self, payload: object) -> None:
        formatted: list[dict[str, object]] = []
        trace_address: int | None = None
        count = 0
        if isinstance(payload, dict):
            formatted = list(payload.get("formatted", []))
            raw_address = payload.get("trace_address")
            trace_address = int(raw_address) if raw_address is not None else None
            count = int(payload.get("count", len(formatted)))
        self._populate_results(formatted, truncated=False)
        if count:
            self.results_status.setText(
                f"Showing {count} n-gram trace match{'es' if count != 1 else ''} for selection."
            )
        else:
            self.results_status.setText("No n-gram matches are available for the selected row.")
        if trace_address is not None:
            self._select_trace_result(trace_address)
        self._cleanup_ngram_worker()

    def _handle_ngram_selection_failed(self, message: str) -> None:
        QMessageBox.warning(self, "Failed to load n-gram matches", message)
        self._cleanup_ngram_worker()

    def _handle_ngram_selection_cancelled(self) -> None:
        if not self._pending_ngram_request:
            self.results_status.setText("N-gram selection cancelled.")
        self._cleanup_ngram_worker()

    def _cleanup_ngram_worker(self) -> None:
        if self._ngram_progress_dialog:
            self._ngram_progress_dialog.close()
            self._ngram_progress_dialog.deleteLater()
            self._ngram_progress_dialog = None
        if self._ngram_thread:
            self._ngram_thread.quit()
            self._ngram_thread.wait()
        if self._ngram_worker:
            self._ngram_worker.deleteLater()
            self._ngram_worker = None
        if self._ngram_thread:
            self._ngram_thread.deleteLater()
            self._ngram_thread = None
        pending = self._pending_ngram_request
        self._pending_ngram_request = None
        if pending:
            next_request = dict(pending)
            QTimer.singleShot(0, lambda: self._show_ngram_matches_in_results(**next_request))

    def _select_trace_result(self, trace_address: int) -> None:
        table = self.results_table
        if table is None:
            return
        try:
            target = int(trace_address)
        except Exception:
            return
        for idx, match in enumerate(self._matches):
            try:
                current = int(match.get("trace_start", 0)) if isinstance(match, dict) else None
            except Exception:
                current = None
            if current is None:
                continue
            if current == target:
                table.selectRow(idx)
                item = table.item(idx, 0)
                if item:
                    table.scrollToItem(item, QAbstractItemView.PositionAtCenter)
                break

    def _handle_ngram_item_activated(self, item: QTreeWidgetItem, _column: int) -> None:
        if item is None:
            return
        payload = item.data(0, Qt.UserRole)
        if not isinstance(payload, dict):
            return
        start_index = int(payload.get("binary_start_index", -1))
        length = int(payload.get("length", 0))
        if start_index >= 0 and length > 0:
            self._focus_binary_rows(start_index, length)
        trace_filter: int | None = None
        if payload.get("type") == "trace":
            trace_address = payload.get("trace_address")
            if trace_address is not None:
                numeric = int(trace_address)
                self._request_trace_navigation(numeric)
                trace_filter = numeric
        if start_index >= 0 and length > 0:
            self._show_ngram_matches_in_results(start_index, length, trace_address=trace_filter)

    def _handle_ngram_item_expanded(self, item: QTreeWidgetItem) -> None:
        if item is None:
            return
        self._handle_ngram_item_activated(item, 0)

    def _focus_binary_rows(self, start_index: int, length: int) -> None:
        table = self.binary_table
        if table is None or start_index < 0 or length <= 0:
            return
        total_rows = table.rowCount()
        if total_rows == 0:
            return
        end_index = min(start_index + length - 1, total_rows - 1)
        selection_model = table.selectionModel()
        model = table.model()
        if selection_model is None or model is None:
            return
        selection_model.clearSelection()
        for row in range(start_index, end_index + 1):
            index = model.index(row, 0)
            selection_model.select(index, QItemSelectionModel.Select | QItemSelectionModel.Rows)
        target_item = table.item(start_index, 0) or table.item(start_index, 1)
        if target_item:
            table.scrollToItem(target_item, QAbstractItemView.PositionAtCenter)
        self._update_find_button_state()

    def _request_trace_navigation(self, trace_address: int) -> None:
        self.results_status.setText(f"Selected trace start 0x{trace_address:x} from n-gram matches.")
        self.trace_address_requested.emit(trace_address)

    def _populate_results(self, matches: list[dict[str, object]], *, truncated: bool = False) -> None:
        table = self.results_table
        table.setUpdatesEnabled(False)
        try:
            self._matches = list(matches)
            table.clearContents()
            table.setRowCount(len(self._matches))
            for row_idx, match in enumerate(self._matches):
                trace_start = int(match.get("trace_start", 0)) if isinstance(match, dict) else 0
                offset_value = int(match.get("offset", 0)) if isinstance(match, dict) else 0
                preview_text = str(match.get("preview", "")) if isinstance(match, dict) else ""
                trace_item = QTableWidgetItem(f"0x{trace_start:x}")
                offset_item = QTableWidgetItem(self._format_offset(offset_value))
                preview_item = QTableWidgetItem(preview_text or "")
                table.setItem(row_idx, 0, trace_item)
                table.setItem(row_idx, 1, offset_item)
                table.setItem(row_idx, 2, preview_item)
        finally:
            table.setUpdatesEnabled(True)
        table.resizeRowsToContents()
        if self._matches:
            status = f"Found {len(self._matches)} match"
            if len(self._matches) != 1:
                status += "es"
            if truncated:
                status += (
                    f". Showing first {len(self._matches)} due to the {SEQUENCE_ANALYZER_MAX_TRACE_MATCHES} result limit."
                )
            else:
                status += ". Select a row and choose Set Binary Offset to apply."
        else:
            status = "No matches found in the trace."
        self.results_status.setText(status)
        self._update_set_offset_button_state()

    def _selected_match_row(self) -> int | None:
        selection = self.results_table.selectionModel()
        if selection is None or not selection.hasSelection():
            return None
        rows = sorted({index.row() for index in selection.selectedRows()})
        if not rows:
            return None
        row = rows[0]
        if row >= len(self._matches):
            return None
        return row

    def _update_set_offset_button_state(self) -> None:
        enabled = self._selected_match_row() is not None
        if hasattr(self, "set_offset_button"):
            self.set_offset_button.setEnabled(enabled)

    def _handle_set_offset_clicked(self) -> None:
        row = self._selected_match_row()
        if row is None:
            return
        match = self._matches[row]
        try:
            offset_value = int(match.get("offset", 0))
        except Exception:
            QMessageBox.warning(self, "Invalid offset", "Unable to determine offset for the selected match.")
            return
        self.results_status.setText(
            f"Selected offset {self._format_offset(offset_value)}. Preview will update when this window closes."
        )
        self.offset_selected.emit(int(offset_value))
        self.accept()

    def _update_find_progress(self, processed: int, total: int) -> None:
        dialog = self._find_progress_dialog
        if not dialog:
            return
        total_value = total if total > 0 else max(self._find_total_positions, 0)
        processed_value = max(0, min(processed, total_value)) if total_value else processed
        dialog.setRange(0, max(total_value, 0))
        dialog.setValue(processed_value)
        if total_value:
            dialog.setLabelText(f"Scanning trace ({processed_value}/{total_value})")
        else:
            dialog.setLabelText("Scanning trace...")

    def _handle_find_succeeded(self, payload: object) -> None:
        if isinstance(payload, dict):
            matches = list(payload.get("matches", []))
            truncated = bool(payload.get("truncated", False))
        else:
            matches = list(payload) if isinstance(payload, list) else []
            truncated = False
        self._populate_results(matches, truncated=truncated)
        self._cleanup_find_worker()

    def _handle_find_cancelled(self) -> None:
        self.results_status.setText("Trace search cancelled.")
        self._cleanup_find_worker()

    def _handle_find_failed(self, message: str) -> None:
        QMessageBox.warning(self, "Trace search failed", message)
        self._cleanup_find_worker()

    def _cleanup_find_worker(self) -> None:
        if self._find_progress_dialog:
            self._find_progress_dialog.close()
            self._find_progress_dialog.deleteLater()
            self._find_progress_dialog = None
        if self._find_thread:
            self._find_thread.quit()
            self._find_thread.wait()
        if self._find_worker:
            self._find_worker.deleteLater()
            self._find_worker = None
        if self._find_thread:
            self._find_thread.deleteLater()
            self._find_thread = None
        self._find_total_positions = 0
        self._update_find_button_state()

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self._find_worker:
            self._find_worker.cancel()
            self._cleanup_find_worker()
        if self._ngram_worker:
            self._pending_ngram_request = None
            self._ngram_worker.cancel()
            self._cleanup_ngram_worker()
        super().closeEvent(event)

    @staticmethod
    def _normalize_instruction(text: str | None) -> str:
        return _normalize_instruction_text(text)

    @staticmethod
    def _format_offset(value: int) -> str:
        sign = "+" if value >= 0 else "-"
        return f"{sign}0x{abs(value):x}"

    @staticmethod
    def _has_binary_instruction(text: str | None) -> bool:
        clean = (text or "").strip()
        return bool(clean) and not clean.startswith("<")


class BinaryInstructionStats(NamedTuple):
    total: int
    nop: int
    other: int


class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PIN Instruction Logger")
        self.resize(1280, 800)
        self.config_manager = ConfigManager()
        self.config: AppConfig = self.config_manager.load()
        self.active_project: str = self.config.active_project or self.config.projects[0]
        self.config.active_project = self.active_project
        self._default_tool_path_value = self._compute_default_tool_path()
        self._ensure_tool_path_default()
        self._repo_root = Path(__file__).resolve().parents[1]
        self._projects_root_migrated = False
        self.history_store = HistoryStore()
        # Merge any projects found in history into the config's projects list
        try:
            history_projects = self.history_store.list_projects()
            added = False
            for name in history_projects:
                if name and name not in self.config.projects:
                    self.config.projects.append(name)
                    # Ensure default project settings for the new project
                    if name not in self.config.project_settings:
                        self.config.project_settings[name] = ProjectConfig(
                            pin_root=self.config.pin_root,
                            log_path=self.config.log_path,
                            binary_path=self.config.binary_path,
                            tool_path=self.config.tool_path,
                            revng_docker_image=self.config.revng_docker_image,
                            default_pre_run_command="",
                            default_target_args="",
                        )
                    added = True
            if added:
                # Persist the updated projects list so it shows in the UI consistently
                self.config_manager.save(self.config)
        except Exception:
            pass
        self._legacy_projects_root: Path | None = None
        self.selected_binary: str | None = self._project_config(self.active_project).binary_path or None
        self.run_entries: list[RunEntry] = []
        self._selection_syncing = False
        self._current_run_thread: QThread | None = None
        self._current_run_worker: RunWorker | None = None
        self._current_run_dialog: RunProgressDialog | None = None
        self._current_run_params: dict | None = None
        self._sanitized_batch_queue: list[dict[str, object]] | None = None
        self._sanitized_batch_dialog: RunProgressDialog | None = None
        self._sanitized_batch_options: RunSanitizedOptions | None = None
        self._sanitized_batch_cancelled = False
        self._sanitized_batch_total = 0
        self._sanitized_batch_completed = 0
        self._current_batch_output_timer: QTimer | None = None
        self._current_batch_output_buffer: deque[str] = deque()
        self._current_batch_output_dropped = 0
        self._batch_continue_pending = False
        self._current_build_thread: QThread | None = None
        self._current_build_worker: BuildWorker | None = None
        self._current_build_dialog: BuildProgressDialog | None = None
        self._current_sanitize_thread: QThread | None = None
        self._current_sanitize_worker: SanitizeWorker | None = None
        self._current_sanitize_dialog: SanitizeProgressDialog | None = None
        self._current_sanitize_entry_id: str | None = None
        self._run_stop_requested = False
        self._run_stop_reason: str | None = None
        self._log_preview_max_chars = 50000
        self._cached_log_lines: list[str] = []
        self._cached_log_entry_id: str | None = None
        self._cached_log_truncated = False
        self._cached_log_path: Path | None = None
        self._cached_preview_processed = False
        self._cached_preview_segment_count = 0
        self._preview_cache: dict[tuple[object, ...], dict[str, object]] = {}
        self._preview_jobs: dict[int, dict[str, object]] = {}
        self._preview_live_lines: list[str] = []
        self._preview_view_has_content = False
        self._preview_job_counter = 0
        self._current_preview_job_id: int | None = None
        self._current_preview_key: tuple[object, ...] | None = None
        self._current_preview_thread: QThread | None = None
        self._current_preview_worker: LogPreviewWorker | None = None
        self._preview_context: dict[str, object] | None = None
        self._preview_progress: dict[str, int] = {}
        self._preview_progress_dialog: BusyProgressDialog | None = None
        self._preview_progress_dialog_job: int | None = None
        self._preview_progress_dialog_shown_at: float = 0.0
        self._preview_progress_dialog_pending_close = False
        self._log_selection_timer = QTimer(self)
        self._log_selection_timer.setSingleShot(True)
        self._log_selection_timer.timeout.connect(self._apply_pending_log_selection)
        self._pending_log_selection: tuple[QListWidgetItem | None, QListWidgetItem | None] | None = None
        self._segment_preview_job_counter = 0
        self._segment_preview_jobs: dict[int, dict[str, object]] = {}
        self._current_segment_job_id: int | None = None
        self._segment_preview_context: dict[str, object] | None = None
        self._segment_preview_dialog: BusyProgressDialog | None = None
        self._segment_preview_dialog_job: int | None = None
        self._segment_preview_dialog_shown_at: float = 0.0
        self._segment_preview_dialog_pending_close = False
        self._segment_selection_timer = QTimer(self)
        self._segment_selection_timer.setSingleShot(True)
        self._segment_selection_timer.timeout.connect(self._apply_pending_segment_selection)
        self._pending_segment_selection: tuple[RunEntry, Path, int] | None = None
        self._segment_selection_updating = False
        self._segments_loaded_entry_id: str | None = None
        self._segment_table_loader: dict[str, object] | None = None
        self._segment_table_source: dict[str, object] | None = None
        # Populate heavy segment tables incrementally to keep the GUI responsive.
        self._segment_table_timer = QTimer(self)
        self._segment_table_timer.setSingleShot(False)
        self._segment_table_timer.setInterval(SEGMENT_TABLE_BATCH_INTERVAL_MS)
        self._segment_table_timer.timeout.connect(self._process_segment_table_batch)
        self._segment_table_progress_dialog: QProgressDialog | None = None
        self._active_segment_entry_id: str | None = None
        self._active_segment_row: int | None = None
        self._segment_preview_cache: dict[tuple[str, int, float], dict[str, object]] = {}
        self._sanitization_preview_thread: QThread | None = None
        self._sanitization_preview_worker: SanitizationPreviewWorker | None = None
        self._sanitization_preview_dialog: QProgressDialog | None = None
        self._parent_comparison_thread: QThread | None = None
        self._parent_comparison_worker: ParentComparisonPreviewWorker | None = None
        self._parent_comparison_dialog: QProgressDialog | None = None
        self._trace_comparison_thread: QThread | None = None
        self._trace_comparison_worker: TraceComparisonPreviewWorker | None = None
        self._trace_comparison_dialog: QProgressDialog | None = None
        self._honey_prepare_thread: QThread | None = None
        self._honey_prepare_worker: HoneyPreparationWorker | None = None
        self._honey_prepare_dialog: BusyProgressDialog | None = None
        self._binary_instruction_count_cache: dict[str, int] = {}
        self._binary_instruction_breakdown_cache: dict[str, BinaryInstructionStats] = {}
        self._counts_dirty = False
        self._console_collapsed = False
        self._console_saved_size = 180
        self._console_header_only_height = 48
        self._console_default_max_height = None
        self._revng_cli_available = False
        self._revng_cli_message = "rev.ng CLI not checked."
        self._revng_container_running = False
        self._revng_container_message = "rev.ng container not checked."
        self._revng_status_summary = "rev.ng status not checked."
        self._revng_status_detail = "rev.ng status not checked."
        self._cached_sudo_password: str | None = None
        self._status_icon_cache: dict[str, QIcon] = {}
        self._last_module_filters: list[str] | None = None
        self._last_unique_only: bool = False
        self._last_run_with_sudo: bool = False
        self._gui_invoker = GuiInvoker(self)
        self._setup_ui()
        self._refresh_project_config_ui()
        self._apply_global_styles()
        initial_log_path = self._project_log_path(self.active_project)
        active_settings = self._project_config(self.active_project)
        self.controller = RunnerController(
            self,
            pin_root=active_settings.pin_root or None,
            log_path=initial_log_path,
            tool_path=active_settings.tool_path or None,
        )
        self._sync_log_destination_ui()
        self._load_history_for_active_project()

    def _refresh_projects_from_history(self) -> None:
        try:
            history_projects = self.history_store.list_projects()
        except Exception as exc:
            self._append_console(f"Unable to read history projects: {exc}")
            return
        added = False
        for name in history_projects:
            if name and name not in self.config.projects:
                self.config.projects.append(name)
                if name not in self.config.project_settings:
                    self.config.project_settings[name] = ProjectConfig(
                        pin_root=self.config.pin_root,
                        log_path=self.config.log_path,
                        binary_path=self.config.binary_path,
                        tool_path=self.config.tool_path,
                        revng_docker_image=self.config.revng_docker_image,
                        default_pre_run_command="",
                        default_target_args="",
                    )
                added = True
        if added:
            self.config_manager.save(self.config)
            # Rebuild the UI list
            self.project_list.blockSignals(True)
            self.project_list.clear()
            self.project_list.addItems(self.config.projects)
            try:
                current_index = self.config.projects.index(self.active_project)
            except ValueError:
                current_index = 0
            self.project_list.setCurrentRow(current_index)
            self.project_list.blockSignals(False)
            self._append_console("Projects refreshed from history.")
        else:
            self._append_console("No new projects found in history.")

    def _apply_global_styles(self) -> None:
        app = QApplication.instance()
        if app is None:
            return
        base = "#f4f4f4"
        border = "#b0b0b0"
        app.setStyleSheet(
            f"""
            QWidget {{
                background-color: {base};
            }}
            QPlainTextEdit,
            QLineEdit,
            QListWidget,
            QTableWidget,
            QTextEdit,
            QTreeWidget {{
                background-color: #ffffff;
            }}
            QDialog {{
                background-color: {base};
                border: 1px solid {border};
                border-radius: 6px;
            }}
            QProgressDialog {{
                background-color: {base};
                border: 1px solid {border};
                border-radius: 6px;
            }}
            QMessageBox {{
                background-color: {base};
                border: 1px solid {border};
                border-radius: 6px;
            }}
            QGroupBox {{
                border: 1px solid {border};
                border-radius: 6px;
                margin-top: 6px;
                background-color: {base};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 4px 0 4px;
            }}
            """
        )

    def _setup_ui(self) -> None:
        content_splitter = QSplitter(Qt.Horizontal, self)

        # Left project panel
        left_panel = QWidget(content_splitter)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(8, 8, 8, 8)
        projects_label = QLabel("Projects", left_panel)
        self.project_list = QListWidget(left_panel)
        self.project_list.addItems(self.config.projects)
        self.project_list.setCurrentRow(
            self.config.projects.index(self.active_project)
            if self.active_project in self.config.projects
            else 0
        )
        self.project_list.setContextMenuPolicy(Qt.CustomContextMenu)
        left_layout.addWidget(projects_label)
        left_layout.addWidget(self.project_list)
        # Refresh projects from history without restarting
        self.refresh_projects_button = QPushButton("Refresh Projects from History", left_panel)
        self.refresh_projects_button.setToolTip("Scan history and add any missing project names to the list.")
        self.refresh_projects_button.clicked.connect(self._refresh_projects_from_history)
        left_layout.addWidget(self.refresh_projects_button)

        # Right tab area
        right_panel = QWidget(content_splitter)
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(8, 8, 8, 8)
        self.tabs = QTabWidget(right_panel)
        right_layout.addWidget(self.tabs)

        content_splitter.addWidget(left_panel)
        content_splitter.addWidget(right_panel)
        content_splitter.setStretchFactor(0, 1)
        content_splitter.setStretchFactor(1, 3)

        console_container = QWidget(self)
        self.console_container = console_container
        console_layout = QVBoxLayout(console_container)
        console_layout.setContentsMargins(8, 4, 8, 8)
        console_header = QHBoxLayout()
        console_header.addWidget(QLabel("Console", console_container))
        console_header.addStretch(1)
        self.console_toggle_button = QPushButton("Hide Console", console_container)
        self.console_toggle_button.setCheckable(True)
        self.console_toggle_button.setChecked(False)
        self.console_toggle_button.toggled.connect(self._toggle_console_visibility)
        self.console_toggle_button.setText("Hide Console")
        console_header.addWidget(self.console_toggle_button)
        console_layout.addLayout(console_header)
        self.console_output = QPlainTextEdit(console_container)
        self.console_output.setReadOnly(True)
        self.console_output.setPlaceholderText("Runtime output and status messages will appear here.")
        console_layout.addWidget(self.console_output)

        self.main_splitter = QSplitter(Qt.Vertical, self)
        self.main_splitter.addWidget(content_splitter)
        self.main_splitter.addWidget(console_container)
        self.main_splitter.setStretchFactor(0, 5)
        self.main_splitter.setStretchFactor(1, 1)
        self.main_splitter.setSizes([620, 180])
        self.setCentralWidget(self.main_splitter)
        self._console_default_max_height = console_container.maximumHeight()
        self._console_header_only_height = max(
            self._console_header_only_height,
            self.console_toggle_button.sizeHint().height() + 20,
        )

        view_menu = self.menuBar().addMenu("View")
        self.show_console_action = QAction("Show Console", self)
        self.show_console_action.setEnabled(False)
        self.show_console_action.triggered.connect(self._restore_console_from_menu)
        view_menu.addAction(self.show_console_action)

        # Configuration tab
        config_tab = QWidget()
        config_layout = QVBoxLayout(config_tab)
        def _build_config_row(label_text: str, widget: QWidget, button: QPushButton | None = None) -> QHBoxLayout:
            row = QHBoxLayout()
            label = QLabel(label_text, config_tab)
            label.setMinimumWidth(150)
            row.addWidget(label)
            row.addWidget(widget, 1)
            if button is not None:
                row.addWidget(button)
            return row

        def _add_config_header(text: str) -> QLabel:
            header = QLabel(text, config_tab)
            header.setStyleSheet("font-weight: bold; margin-top: 12px;")
            config_layout.addWidget(header)
            return header

        def _prepare_header_for_autosize(header: QHeaderView | None, *, stretch_last: bool = False) -> None:
            if header is None:
                return
            header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            header.setStretchLastSection(stretch_last)
            header.setSectionsClickable(True)
            header.resizeSections(QHeaderView.ResizeMode.ResizeToContents)

        project_settings = self._project_config()

        self.pin_path = QLineEdit(config_tab)
        self.pin_path.setPlaceholderText("Set the Intel PIN directory")
        self.pin_path.setText(project_settings.pin_root)
        self.pin_path.setReadOnly(True)
        self.pin_button = QPushButton("Select", config_tab)
        _add_config_header("Intel PIN Directory")
        config_layout.addLayout(_build_config_row("Selected path", self.pin_path, self.pin_button))

        self.binary_path = QLineEdit(config_tab)
        self.binary_path.setPlaceholderText("Select target binary")
        self.binary_path.setText(project_settings.binary_path)
        self.binary_path.setReadOnly(True)
        self.binary_button = QPushButton("Select", config_tab)
        _add_config_header("Target Binary")
        config_layout.addLayout(_build_config_row("Selected binary", self.binary_path, self.binary_button))

        # Default Pre-Run Setup command/script
        self.pre_run_command_input = QLineEdit(config_tab)
        self.pre_run_command_input.setPlaceholderText(
            "Default shell command or script to run before launching the target"
        )
        self.pre_run_command_input.setText(project_settings.default_pre_run_command or "")
        self.test_pre_run_button = QPushButton("Test", config_tab)
        _add_config_header("Pre-Run Setup (Default)")
        config_layout.addLayout(_build_config_row("Command/script", self.pre_run_command_input, self.test_pre_run_button))

        # Default Target Arguments
        self.default_target_args_input = QLineEdit(config_tab)
        self.default_target_args_input.setPlaceholderText(
            "Default command-line arguments (e.g., -D -f /tmp/sshd_config_honeypot -p 2222)"
        )
        self.default_target_args_input.setText(project_settings.default_target_args or "")
        _add_config_header("Target Arguments (Default)")
        config_layout.addLayout(_build_config_row("Arguments", self.default_target_args_input))

        self.tool_path = QLineEdit(config_tab)
        self.tool_path.setPlaceholderText("Intel PIN tool shared library path")
        self.tool_path.setText(project_settings.tool_path)
        self.tool_button = QPushButton("Select", config_tab)
        self.build_tool_button = QPushButton("Build Tool", config_tab)
        tool_row = QHBoxLayout()
        label_tool = QLabel("Library path", config_tab)
        label_tool.setMinimumWidth(150)
        tool_row.addWidget(label_tool)
        tool_row.addWidget(self.tool_path, 1)
        tool_row.addWidget(self.tool_button)
        tool_row.addWidget(self.build_tool_button)
        _add_config_header("Intel PIN Tool")
        config_layout.addLayout(tool_row)

        self.revng_image_input = QLineEdit(config_tab)
        self.revng_image_input.setPlaceholderText("revng/revng")
        self.revng_image_input.setText(project_settings.revng_docker_image or "revng/revng")
        self.revng_image_reset_button = QPushButton("Reset", config_tab)
        revng_row = QHBoxLayout()
        revng_label = QLabel("Image tag", config_tab)
        revng_label.setMinimumWidth(150)
        revng_row.addWidget(revng_label)
        revng_row.addWidget(self.revng_image_input, 1)
        revng_row.addWidget(self.revng_image_reset_button)
        _add_config_header("rev.ng Docker Image")
        config_layout.addLayout(revng_row)
        config_layout.addStretch()

        # Logs tab
        logs_tab = QWidget()
        logs_layout = QVBoxLayout(logs_tab)
        self.logs_exec_label = QLabel("Execution Logs for: None", logs_tab)
        self.logs_list = QListWidget(logs_tab)
        self.logs_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.logs_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.create_log_button = QPushButton("Execute Binary", logs_tab)
        self.prepare_honey_button = QPushButton("Prepare for HoneyProc", logs_tab)
        self.prepare_honey_button.setEnabled(False)
        self.delete_log_button = QPushButton("Delete Selected Log", logs_tab)
        self.log_preview_label = QLabel("Instruction Trace", logs_tab)
        self.log_preview = QPlainTextEdit(logs_tab)
        self.log_preview.setReadOnly(True)
        self.log_preview.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        preview_font = self.log_preview.font()
        preview_font.setFamilies(["Monospace", "Courier New", preview_font.defaultFamily()])
        preview_font.setStyleHint(QFont.StyleHint.Monospace)
        self.log_preview.setFont(preview_font)
        self.log_preview.setContextMenuPolicy(Qt.CustomContextMenu)
        self.log_preview.customContextMenuRequested.connect(self._show_log_preview_context_menu)
        self.log_preview_status = QLabel("", logs_tab)
        self.log_preview_status.setObjectName("logPreviewStatus")
        self.log_preview_status.setStyleSheet("color: #666; font-size: 11px;")
        header_row = QHBoxLayout()
        header_row.addWidget(self.logs_exec_label)
        header_row.addStretch(1)
        header_row.addWidget(self.create_log_button)
        header_row.addWidget(self.prepare_honey_button)
        header_row.addWidget(self.delete_log_button)
        list_panel = QWidget(logs_tab)
        list_panel_layout = QVBoxLayout(list_panel)
        list_panel_layout.setContentsMargins(0, 0, 0, 0)
        list_panel_layout.addLayout(header_row)
        list_panel_layout.addWidget(self.logs_list)

        preview_panel = QWidget(logs_tab)
        preview_layout = QVBoxLayout(preview_panel)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        preview_layout.addWidget(self.log_preview_label)
        # Invocation details label
        self.log_invocation_label = QLabel("", preview_panel)
        self.log_invocation_label.setObjectName("logInvocationLabel")
        self.log_invocation_label.setStyleSheet("color: #666; font-size: 11px;")
        preview_layout.addWidget(self.log_invocation_label)
        self.log_segments_label = QLabel("Segments", preview_panel)
        self.log_segments_label.setStyleSheet("font-weight: bold;")
        self.show_segments_button = QPushButton("Show Segments", preview_panel)
        self.show_segments_button.setEnabled(False)
        self.show_segments_button.clicked.connect(self._handle_show_segments_clicked)
        self.log_segments_table = QTableWidget(0, 4, preview_panel)
        self.log_segments_table.setHorizontalHeaderLabels(["#", "Start", "End", "Length"])
        _prepare_header_for_autosize(self.log_segments_table.horizontalHeader())
        self.log_segments_table.verticalHeader().setVisible(False)
        self.log_segments_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.log_segments_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.log_segments_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.log_segments_table.itemSelectionChanged.connect(self._handle_segment_selection_changed)
        self.log_segments_table.setVisible(False)
        self.log_segments_label.setVisible(False)
        segments_header = QHBoxLayout()
        segments_header.addWidget(self.log_segments_label)
        segments_header.addStretch(1)
        segments_header.addWidget(self.show_segments_button)
        preview_layout.addLayout(segments_header)
        preview_layout.addWidget(self.log_segments_table)
        preview_layout.addWidget(self.log_preview)
        preview_layout.addWidget(self.log_preview_status)

        self.logs_splitter = QSplitter(Qt.Vertical, logs_tab)
        self.logs_splitter.addWidget(list_panel)
        self.logs_splitter.addWidget(preview_panel)
        self.logs_splitter.setStretchFactor(0, 1)
        self.logs_splitter.setStretchFactor(1, 3)
        self.logs_splitter.setSizes([160, 520])
        logs_layout.addWidget(self.logs_splitter)

        # HoneyProc tab
        honey_tab = QWidget()
        honey_layout = QVBoxLayout(honey_tab)
        self.honey_entries_label = QLabel("", honey_tab)
        self.honey_list = QTreeWidget(honey_tab)
        self.honey_list.setColumnCount(7)
        self.honey_list.setHeaderLabels(
            [
                "Entry",
                "Trace Range",
                "Binary Range",
                "Binary Instructions",
                "Trace Instructions",
                "NOP Count",
                "Other Instructions",
            ]
        )
        self.honey_list.setRootIsDecorated(False)
        self.honey_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.honey_list.setAlternatingRowColors(True)
        _prepare_header_for_autosize(self.honey_list.header(), stretch_last=True)
        honey_buttons = QHBoxLayout()
        indicator_widget = QWidget(honey_tab)
        indicator_layout = QHBoxLayout(indicator_widget)
        indicator_layout.setContentsMargins(0, 0, 0, 0)
        indicator_layout.setSpacing(6)
        self.revng_status_indicator = ClickableIndicator("\u25CF", indicator_widget)
        self.revng_status_indicator.setStyleSheet("color: #b00020; font-size: 16px;")
        self.revng_status_indicator.setToolTip("rev.ng status not checked.")
        self.revng_status_indicator.clicked.connect(self._show_revng_status_popup)
        indicator_layout.addWidget(self.revng_status_indicator)
        indicator_layout.addStretch(1)
        indicator_widget.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Preferred)
        self.honey_preview_button = QPushButton("Preview Sanitization", honey_tab)
        self.honey_sanitize_button = QPushButton("Generate Sanitized Binary", honey_tab)
        self.honey_run_sanitized_button = QPushButton("Execute Sanitized", honey_tab)
        self.honey_reveal_button = QPushButton("Reveal Sanitized", honey_tab)
        self.honey_compare_button = QPushButton("Compare Logs", honey_tab)
        honey_buttons.addWidget(indicator_widget)
        honey_buttons.addWidget(self.honey_preview_button)
        honey_buttons.addWidget(self.honey_sanitize_button)
        honey_buttons.addStretch(1)

        honey_layout.addWidget(self.honey_entries_label)
        honey_layout.addWidget(self.honey_list)
        honey_layout.addLayout(honey_buttons)
        self.honey_prepared_status = QLabel("Preparation: Select an entry.", honey_tab)
        self.honey_prepared_status.setWordWrap(True)
        honey_layout.addWidget(self.honey_prepared_status)
        self.honey_sanitized_status = QLabel("Sanitized binary: Not generated.", honey_tab)
        self.honey_sanitized_status.setWordWrap(True)
        self.honey_parent_status = QLabel("Parent linkage: N/A", honey_tab)
        self.honey_parent_status.setWordWrap(True)
        self.honey_sanitized_status.hide()
        self.honey_parent_status.hide()
        # Invocation details for current entry and parent
        self.honey_invocation_status = QLabel("", honey_tab)
        self.honey_invocation_status.setWordWrap(True)
        self.honey_invocation_status.setStyleSheet("color: #666; font-size: 11px;")
        self.honey_parent_invocation_status = QLabel("", honey_tab)
        self.honey_parent_invocation_status.setWordWrap(True)
        self.honey_parent_invocation_status.setStyleSheet("color: #666; font-size: 11px;")
        honey_layout.addWidget(self.honey_invocation_status)
        honey_layout.addWidget(self.honey_parent_invocation_status)
        self.honey_sanitized_list_label = QLabel("Generated Sanitized Binaries", honey_tab)
        self.honey_sanitized_list_label.setStyleSheet("font-weight: bold;")
        self.honey_sanitized_list = QTreeWidget(honey_tab)
        self.honey_sanitized_list.setColumnCount(12)
        self.honey_sanitized_list.setHeaderLabels([
            "Sanitized Binary",
            "Parent Entry",
            "Offset",
            "Total Instructions",
            "Replaced Instructions",
            "NOP Count",
            "Other Instructions",
            "Segment Gap",
            "Segment Padding",
            "ICF Window",
            "Jump Table Window",
            "Works",
        ])
        _prepare_header_for_autosize(self.honey_sanitized_list.header(), stretch_last=True)
        self.honey_sanitized_list.setRootIsDecorated(False)
        self.honey_sanitized_list.setAlternatingRowColors(True)
        self.honey_sanitized_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.honey_sanitized_list.setUniformRowHeights(True)
        self.honey_sanitized_list.itemSelectionChanged.connect(self._update_sanitized_action_state)
        self.honey_sanitized_list.itemChanged.connect(self._handle_sanitized_output_item_changed)
        honey_layout.addWidget(self.honey_sanitized_list_label)
        honey_layout.addWidget(self.honey_sanitized_list)
        self.honey_delete_sanitized_button = QPushButton("Delete Sanitized", honey_tab)
        self.honey_compare_parent_button = QPushButton("Compare to Parent", honey_tab)
        sanitized_actions = QHBoxLayout()
        sanitized_actions.addStretch(1)
        sanitized_actions.addWidget(self.honey_delete_sanitized_button)
        sanitized_actions.addWidget(self.honey_compare_parent_button)
        sanitized_actions.addWidget(self.honey_reveal_button)
        sanitized_actions.addWidget(self.honey_run_sanitized_button)
        sanitized_actions.addWidget(self.honey_compare_button)
        honey_layout.addLayout(sanitized_actions)
        honey_layout.addStretch()

        self.tabs.addTab(config_tab, "Configuration")
        self.tabs.addTab(logs_tab, "Logs")
        self.tabs.addTab(honey_tab, "HoneyProc")

        self.pin_button.clicked.connect(self.select_pin_root)
        self.binary_button.clicked.connect(self.select_binary)
        self.tool_button.clicked.connect(self.select_tool)
        self.tool_path.editingFinished.connect(self._handle_tool_path_edit)
        self.build_tool_button.clicked.connect(self.build_tool)
        self.revng_image_input.editingFinished.connect(self._handle_revng_image_edit)
        self.pre_run_command_input.editingFinished.connect(self._handle_pre_run_command_edit)
        self.default_target_args_input.editingFinished.connect(self._handle_default_target_args_edit)
        self.test_pre_run_button.clicked.connect(self._handle_test_pre_run_command)
        self.revng_image_reset_button.clicked.connect(self._reset_revng_image)
        self.project_list.currentTextChanged.connect(self.change_active_project)
        self.project_list.customContextMenuRequested.connect(self._show_project_context_menu)
        self.create_log_button.clicked.connect(self.create_new_log_entry)
        self.delete_log_button.clicked.connect(self.delete_log_entry)
        self.prepare_honey_button.clicked.connect(self.prepare_log_for_honeyproc)
        self.logs_list.customContextMenuRequested.connect(
            lambda pos: self._show_logs_list_context_menu(self.logs_list, pos)
        )
        self.logs_list.currentItemChanged.connect(self._handle_logs_selection_change)
        self.honey_list.currentItemChanged.connect(self._handle_honey_selection_change)
        self.honey_preview_button.clicked.connect(self.preview_sanitization)
        self.honey_sanitize_button.clicked.connect(self.sanitize_honey_entry)
        self.honey_run_sanitized_button.clicked.connect(self.execute_sanitized_binary)
        self.honey_reveal_button.clicked.connect(self.reveal_sanitized_binary)
        self.honey_compare_button.clicked.connect(self.compare_sanitized_logs)
        self.honey_delete_sanitized_button.clicked.connect(self.delete_sanitized_binary)
        self.honey_compare_parent_button.clicked.connect(self.compare_sanitized_to_parent)
        self._update_sanitized_action_state()
        self._update_honey_buttons()
        self._refresh_revng_status()
        self._refresh_revng_container_status()
        self._update_log_preview(None)
        self._update_honey_entries_label()

        self._current_sweep_thread: QThread | None = None
        self._current_sweep_worker: SanitizeSweepWorker | None = None
        self._current_sweep_dialog: SanitizeProgressDialog | None = None

    def _log_template_path(self) -> Path:
        raw = (self.config.log_path or "").strip()
        if raw:
            template = Path(raw).expanduser()
            if not template.is_absolute():
                template = Path(__file__).resolve().parents[1] / template
        else:
            template = DEFAULT_LOG_PATH
        return template

    def _projects_root(self, *, ensure_exists: bool = True) -> Path:
        root = self._repo_root / "projects"
        if not self._projects_root_migrated:
            self._projects_root_migrated = True
            raw_legacy_root = self._log_template_path().parent / "projects"
            try:
                legacy_root = raw_legacy_root.resolve()
            except OSError:
                legacy_root = raw_legacy_root
            self._legacy_projects_root = legacy_root
            try:
                root_resolved = root.resolve()
            except OSError:
                root_resolved = root
            if legacy_root.exists() and legacy_root != root_resolved:
                root.parent.mkdir(parents=True, exist_ok=True)
                if root.exists():
                    for child in legacy_root.iterdir():
                        target = root / child.name
                        if target.exists():
                            if child.is_dir():
                                shutil.rmtree(target, ignore_errors=True)
                            else:
                                target.unlink(missing_ok=True)
                        shutil.move(str(child), str(target))
                    shutil.rmtree(legacy_root, ignore_errors=True)
                else:
                    shutil.move(str(legacy_root), str(root))
        if ensure_exists:
            root.mkdir(parents=True, exist_ok=True)
        return root

    def _sanitize_identifier(self, raw: str, fallback: str) -> str:
        base = raw.strip() or fallback
        allowed = set(string.ascii_letters + string.digits + "-_")
        sanitized_chars: list[str] = []
        last_char = ""
        for char in base:
            if char in allowed:
                sanitized_chars.append(char)
                last_char = char
                continue
            replacement = "_"
            if last_char != replacement:
                sanitized_chars.append(replacement)
            last_char = replacement
        sanitized = "".join(sanitized_chars).strip("_")
        return sanitized or fallback

    def _sanitize_project_name(self, name: str) -> str:
        return self._sanitize_identifier(name, "project")

    def _sanitize_run_label(self, label: str) -> str:
        return self._sanitize_identifier(label, "run")

    def _project_storage_root(self, project: str | None = None, *, ensure_exists: bool = True) -> Path:
        label = project or self.active_project or (self.config.projects[0] if self.config.projects else "project")
        safe = self._sanitize_project_name(label)
        root = self._projects_root(ensure_exists=ensure_exists) / safe
        if ensure_exists:
            root.mkdir(parents=True, exist_ok=True)
        return root

    def _clone_project_settings(self, source: ProjectConfig | None = None) -> ProjectConfig:
        if source is None:
            return ProjectConfig()
        return ProjectConfig(
            pin_root=source.pin_root,
            log_path=source.log_path,
            binary_path=source.binary_path,
            tool_path=source.tool_path,
            revng_docker_image=source.revng_docker_image,
            default_pre_run_command=source.default_pre_run_command,
            default_target_args=source.default_target_args,
        )

    def _project_config(self, project: str | None = None) -> ProjectConfig:
        active_name = self.active_project or self.config.active_project or (
            self.config.projects[0] if self.config.projects else "Default Project"
        )
        if not self.config.project_settings:
            self.config.project_settings[active_name] = ProjectConfig(
                pin_root=self.config.pin_root,
                log_path=self.config.log_path,
                binary_path=self.config.binary_path,
                tool_path=self.config.tool_path,
                revng_docker_image=self.config.revng_docker_image,
                default_pre_run_command="",
                default_target_args="",
            )
        name = project or self.active_project or active_name
        settings = self.config.project_settings.get(name)
        if settings is None:
            template = self.config.project_settings.get(self.active_project) or ProjectConfig(
                pin_root=self.config.pin_root,
                log_path=self.config.log_path,
                binary_path=self.config.binary_path,
                tool_path=self.config.tool_path,
                revng_docker_image=self.config.revng_docker_image,
                default_pre_run_command="",
                default_target_args="",
            )
            settings = self._clone_project_settings(template)
            self.config.project_settings[name] = settings
            self.config_manager.save(self.config)
        return settings

    def _refresh_project_config_ui(self) -> None:
        settings = self._project_config()
        if hasattr(self, "pin_path"):
            self.pin_path.setText(settings.pin_root)
        if hasattr(self, "binary_path"):
            self.binary_path.setText(settings.binary_path)
        if hasattr(self, "tool_path"):
            self.tool_path.blockSignals(True)
            self.tool_path.setText(settings.tool_path)
            self.tool_path.blockSignals(False)
        if hasattr(self, "revng_image_input"):
            self.revng_image_input.blockSignals(True)
            self.revng_image_input.setText(settings.revng_docker_image or "revng/revng")
            self.revng_image_input.blockSignals(False)
        if hasattr(self, "pre_run_command_input"):
            self.pre_run_command_input.blockSignals(True)
            self.pre_run_command_input.setText(settings.default_pre_run_command or "")
            self.pre_run_command_input.blockSignals(False)
        if hasattr(self, "default_target_args_input"):
            self.default_target_args_input.blockSignals(True)
            self.default_target_args_input.setText(settings.default_target_args or "")
            self.default_target_args_input.blockSignals(False)
        self.selected_binary = settings.binary_path or None
        self._update_honey_entries_label()

    def _apply_project_settings_to_controller(self) -> None:
        settings = self._project_config()
        if hasattr(self, "controller") and self.controller:
            if settings.pin_root:
                self.controller.set_pin_root(settings.pin_root)
            if settings.tool_path:
                self.controller.set_tool_path(settings.tool_path)
            self.controller.set_log_path(str(self._project_log_path(self.active_project)))

    def _handle_pre_run_command_edit(self) -> None:
        settings = self._project_config()
        text = (self.pre_run_command_input.text() if hasattr(self, "pre_run_command_input") else "")
        settings.default_pre_run_command = (text or "").strip()
        self.config.project_settings[self.active_project] = self._clone_project_settings(settings)
        self.config_manager.save(self.config)
        # Reload config to ensure it's persisted and consistent
        self.config = self.config_manager.load()
        self._append_console(
            f"Default pre-run command updated for project '{self.active_project}' ."
        )

    def _handle_default_target_args_edit(self) -> None:
        settings = self._project_config()
        text = (self.default_target_args_input.text() if hasattr(self, "default_target_args_input") else "")
        settings.default_target_args = (text or "").strip()
        self.config.project_settings[self.active_project] = self._clone_project_settings(settings)
        self.config_manager.save(self.config)
        # Reload config to ensure it's persisted and consistent
        self.config = self.config_manager.load()
        self._append_console(
            f"Default target arguments updated for project '{self.active_project}': {settings.default_target_args}"
        )
        self._append_console(
            f"Default target arguments updated for project '{self.active_project}'."
        )

    def _handle_tool_path_edit(self) -> None:
        settings = self._project_config()
        text = (self.tool_path.text() if hasattr(self, "tool_path") else "").strip()
        if text:
            settings.tool_path = text
            self.config.tool_path = text
            self.config.project_settings[self.active_project] = self._clone_project_settings(settings)
            self.config_manager.save(self.config)
            # Reload config to ensure it's persisted and consistent
            self.config = self.config_manager.load()
            self.controller.set_tool_path(text)
            self._append_console(f"PIN tool path updated for project '{self.active_project}'.")

    def _handle_test_pre_run_command(self) -> None:
        # Runs the configured pre-run command/script and streams output to the console
        text = (self.pre_run_command_input.text() if hasattr(self, "pre_run_command_input") else "").strip()
        if not text:
            QMessageBox.information(self, "No command", "Enter a pre-run command/script first.")
            return
        # Ask if sudo is needed
        run_with_sudo = False
        prompt = QMessageBox.question(
            self,
            "Run with sudo?",
            "Execute the pre-run using sudo?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        run_with_sudo = prompt == QMessageBox.Yes
        sudo_password: str | None = None
        if run_with_sudo:
            sudo_password = self._obtain_sudo_password("Enter sudo password to run the pre-run command:")
            if not sudo_password:
                self._append_console("Pre-run test cancelled; sudo password not provided.")
                return
        self._append_console("Testing pre-run command...")
        try:
            from pathlib import Path as _Path
            import subprocess as _subprocess
            import os as _os
            cmd: list[str]
            try:
                _p = _Path(text)
                if _p.exists() and _p.is_file():
                    cmd = ["bash", str(_p)]
                else:
                    cmd = ["bash", "-lc", text]
            except Exception:
                cmd = ["bash", "-lc", text]
            if run_with_sudo and sudo_password:
                cmd = ["sudo", "-S", "-p", "", *cmd]
            proc = _subprocess.Popen(
                cmd,
                stdout=_subprocess.PIPE,
                stderr=_subprocess.STDOUT,
                stdin=_subprocess.PIPE if (run_with_sudo and sudo_password) else None,
                text=True,
                bufsize=1,
                cwd=_os.getcwd(),
            )
            if run_with_sudo and sudo_password and proc.stdin is not None:
                try:
                    proc.stdin.write(sudo_password + "\n")
                    proc.stdin.flush()
                except BrokenPipeError:
                    pass
                finally:
                    try:
                        proc.stdin.close()
                    except OSError:
                        pass
            assert proc.stdout is not None
            for line in proc.stdout:
                clean = line.rstrip()
                if clean:
                    self._append_console(clean)
            proc.wait()
            if proc.returncode != 0:
                raise RuntimeError("Pre-run command exited with non-zero status")
            QMessageBox.information(self, "Pre-run succeeded", "The pre-run command executed successfully.")
        except Exception as exc:
            QMessageBox.critical(self, "Pre-run failed", str(exc))
            self._append_console(f"Pre-run test failed: {exc}")

    def _project_log_filename(self, run_label: str | None = None) -> str:
        template = self._log_template_path()
        suffix = template.suffix or ".txt"
        base = "instruction_log"
        if run_label:
            base = f"{base}_{self._sanitize_run_label(run_label)}"
        return f"{base}{suffix}"

    def _project_log_path(self, project: str | None = None, *, run_label: str | None = None) -> Path:
        return self._project_storage_root(project) / self._project_log_filename(run_label=run_label)

    def _default_run_label(self, binary_path: str | None = None) -> str:
        binary_name = Path(binary_path).name if binary_path else "Run"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"{binary_name or 'Run'} @ {timestamp}"

    def _scripts_dir(self) -> Path:
        scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        return scripts_dir

    def _revng_wrapper_path(self) -> Path:
        return self._scripts_dir() / "revng"

    def _legacy_revng_wrapper_path(self) -> Path:
        return self._scripts_dir() / "revng-docker.sh"

    def _available_revng_script(self) -> Path | None:
        script_path = self._revng_wrapper_path()
        if script_path.exists():
            return script_path
        legacy_path = self._legacy_revng_wrapper_path()
        if not legacy_path.exists():
            return None
        try:
            legacy_path.rename(script_path)
            script_path.chmod(0o755)
            self._append_console(f"Moved legacy rev.ng helper to {script_path}")
            return script_path
        except OSError:
            try:
                shutil.copy2(legacy_path, script_path)
                script_path.chmod(0o755)
                legacy_path.unlink(missing_ok=True)
                self._append_console(f"Copied legacy rev.ng helper to {script_path}")
                return script_path
            except OSError as exc:
                self._append_console(f"Unable to migrate legacy rev.ng helper: {exc}")
                return legacy_path if legacy_path.exists() else None

    def _ensure_revng_path_registered(self, script_path: Path | None = None) -> None:
        script = script_path or self._available_revng_script()
        if not script:
            return
        script_dir = str(script.parent)
        current_path = os.environ.get("PATH", "")
        segments = [segment for segment in current_path.split(os.pathsep) if segment]
        if script_dir not in segments:
            new_path = os.pathsep.join([script_dir, *segments]) if segments else script_dir
            os.environ["PATH"] = new_path
            self._append_console(f"Added {script_dir} to PATH for rev.ng helper")

    def _request_sudo_password(self, *, prompt: str | None = None) -> str | None:
        password, ok = QInputDialog.getText(
            self,
            "Docker Requires Privileges",
            prompt or "Enter sudo password to run docker:",
            QLineEdit.Password,
        )
        if not ok or not password:
            return None
        return password

    def _obtain_sudo_password(self, prompt: str) -> str | None:
        if self._cached_sudo_password:
            return self._cached_sudo_password
        password = self._request_sudo_password(prompt=prompt)
        if password:
            self._cached_sudo_password = password
        return password

    def _clear_cached_sudo_password(self) -> None:
        self._cached_sudo_password = None

    def _password_error_requires_retry(self, message: str) -> bool:
        lowered = message.lower()
        error_markers = (
            "sorry, try again",
            "incorrect password",
            "authentication failure",
            "a password is required",
            "sudo: password is incorrect",
        )
        return any(marker in lowered for marker in error_markers)

    def _execute_command_with_progress(
        self,
        command: list[str],
        *,
        title: str,
        password: str | None = None,
        timeout: int = 600,
    ) -> tuple[int, str, str, str | None]:
        dialog = QProgressDialog(title, None, 0, 0, self)
        dialog.setCancelButton(None)
        dialog.setWindowTitle(title)
        dialog.setWindowModality(Qt.ApplicationModal)
        dialog.setMinimumDuration(0)
        dialog.setLabelText(title)
        dialog.resize(520, 200)
        dialog.show()
        QApplication.processEvents()

        process: subprocess.Popen[str] | None = None
        aggregated: list[str] = []
        last_line = ""
        error_message: str | None = None
        try:
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.PIPE if password is not None else None,
                    text=True,
                    bufsize=1,
                )
            except FileNotFoundError as exc:
                error_message = f"Executable not found: {command[0]}"
                return -1, last_line, "", error_message
            except OSError as exc:
                error_message = f"Failed to run {' '.join(command)}: {exc}"
                return -1, last_line, "", error_message

            if password is not None and process.stdin:
                try:
                    process.stdin.write(password + "\n")
                    process.stdin.flush()
                except BrokenPipeError:
                    pass
                finally:
                    process.stdin.close()

            assert process.stdout is not None
            for line in process.stdout:
                clean = line.rstrip()
                if clean:
                    aggregated.append(clean)
                    last_line = clean
                    self._append_console(clean)
                    dialog.setLabelText(clean[:160])
                QApplication.processEvents()
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                error_message = f"{' '.join(command)} timed out."
                return -1, last_line, "\n".join(aggregated).strip(), error_message
            return process.returncode or 0, last_line, "\n".join(aggregated).strip(), None
        finally:
            if process and process.stdout:
                try:
                    process.stdout.close()
                except OSError:
                    pass
            dialog.close()

    def _configured_revng_image(self) -> str:
        settings = self._project_config()
        return settings.revng_docker_image or "revng/revng"

    def _revng_container_name(self) -> str:
        return "revng-honeyproc"

    def _revng_wrapper_script(self, image: str) -> str:
        return (
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "TTY_FLAGS=-i\n"
            "if [ -t 0 ] && [ -t 1 ]; then\n"
            "  TTY_FLAGS=-it\n"
            "fi\n"
            "docker run --rm $TTY_FLAGS \\\n"
            "  -v \"$PWD\":\"$PWD\" \\\n"
            "  -w \"$PWD\" \\\n"
            f"  {image} revng \"$@\"\n"
        )

    def _write_revng_wrapper(self) -> Path:
        image = self._configured_revng_image()
        script_path = self._revng_wrapper_path()
        script_content = self._revng_wrapper_script(image)
        script_path.write_text(script_content, encoding="utf-8")
        script_path.chmod(0o755)
        legacy_path = self._legacy_revng_wrapper_path()
        if legacy_path.exists() and legacy_path != script_path:
            legacy_path.unlink(missing_ok=True)
        self._append_console(f"Wrote rev.ng Docker wrapper to {script_path}")
        return script_path

    def _pull_revng_image(self) -> tuple[bool, str]:
        image = self._configured_revng_image()
        self._append_console(f"Pulling rev.ng Docker image: {image}")
        success, message, returncode, output = self._run_docker_pull(image)
        if success:
            self._append_console(f"Docker pull succeeded: {message}")
            self._refresh_revng_container_status()
            return True, message or "Image pulled or already up to date."

        needs_sudo = "permission denied" in (output or message).lower()
        if needs_sudo:
            password = self._request_sudo_password(prompt="Enter sudo password to run docker pull:")
            if not password:
                cancel_msg = "Docker pull cancelled; sudo password not provided."
                self._append_console(cancel_msg)
                self._refresh_revng_container_status()
                return False, cancel_msg
            self._append_console("Retrying docker pull with sudo...")
            sudo_success, sudo_message, _, sudo_output = self._run_docker_pull(
                image,
                use_sudo=True,
                password=password,
            )
            if sudo_success:
                self._append_console(f"Docker pull (sudo) succeeded: {sudo_message}")
                self._refresh_revng_container_status()
                return True, sudo_message or "Image pulled or already up to date."
            failure_msg = sudo_message or sudo_output or "Docker pull failed under sudo."
            self._append_console(failure_msg)
            self._refresh_revng_container_status()
            return False, failure_msg

        failure_message = message or output or f"Docker pull exited with code {returncode}."
        self._append_console(failure_message)
        self._refresh_revng_container_status()
        return False, failure_message

    def _run_docker_pull(
        self,
        image: str,
        *,
        use_sudo: bool = False,
        password: str | None = None,
    ) -> tuple[bool, str, int, str]:
        command = ["docker", "pull", image]
        title = f"Pulling Docker image: {image}"
        if use_sudo:
            command = ["sudo", "-S", *command]
            title = f"Running sudo docker pull {image}"
            if password is None:
                return False, "Sudo password not provided.", -1, ""

        returncode, summary, output, error = self._execute_command_with_progress(
            command,
            title=title,
            password=password if use_sudo else None,
        )
        if error:
            return False, error, returncode, output
        if returncode != 0:
            details = summary or output or "no diagnostic output"
            message = f"'{' '.join(command)}' exited with {returncode}: {details}"
            return False, message, returncode, output
        success_message = summary or "Image pulled or already up to date."
        return True, success_message, returncode, output

    def _run_docker_command_once(
        self,
        command: list[str],
        *,
        title: str,
        use_sudo: bool = False,
        password: str | None = None,
    ) -> tuple[bool, str, bool]:
        final_command = ["sudo", "-S", *command] if use_sudo else list(command)
        self._append_console(f"Running docker command: {' '.join(final_command)}")
        returncode, summary, output, error = self._execute_command_with_progress(
            final_command,
            title=title,
            password=password if use_sudo else None,
        )
        combined_parts = [part for part in (summary, output) if part]
        combined_message = "\n".join(combined_parts).strip()
        message = combined_message or (error or "")
        if not message:
            message = "Command completed." if returncode == 0 else "Command failed."
        lowered = " ".join(part for part in [combined_message, error or ""] if part).lower()
        permission_markers = ("permission denied", "operation not permitted", "got permission denied")
        needs_sudo = not use_sudo and any(marker in lowered for marker in permission_markers)
        success = error is None and returncode == 0
        if success:
            self._append_console(f"Docker command succeeded: {' '.join(command)}")
        else:
            self._append_console(
                f"Docker command failed ({returncode}): {' '.join(command)} | {summary or error or output}"
            )
        return success, message, needs_sudo

    def _run_docker_command_with_optional_sudo(
        self,
        command: list[str],
        *,
        title: str,
        sudo_prompt: str = "Enter sudo password to run docker:",
    ) -> tuple[bool, str]:
        success, message, needs_sudo = self._run_docker_command_once(command, title=title)
        if success or not needs_sudo:
            return success, message

        password = self._obtain_sudo_password(sudo_prompt)
        if not password:
            cancel_msg = "Docker command cancelled; sudo password not provided."
            self._append_console(cancel_msg)
            return False, cancel_msg

        attempt = 0
        while attempt < 2:
            attempt += 1
            self._append_console("Retrying docker command with sudo...")
            success, sudo_message, _ = self._run_docker_command_once(
                command,
                title=title,
                use_sudo=True,
                password=password,
            )
            if success:
                return True, sudo_message
            if not self._password_error_requires_retry(sudo_message or ""):
                return False, sudo_message
            # Password likely wrong; clear cache and ask again once.
            self._clear_cached_sudo_password()
            password = self._obtain_sudo_password(sudo_prompt)
            if not password:
                cancel_msg = "Docker command cancelled; sudo password not provided."
                self._append_console(cancel_msg)
                return False, cancel_msg
        return False, sudo_message

    def _run_docker_command_with_sudo(
        self,
        command: list[str],
        *,
        title: str,
        sudo_prompt: str,
    ) -> tuple[bool, str]:
        password = self._obtain_sudo_password(sudo_prompt)
        if not password:
            cancel_msg = "Docker command cancelled; sudo password not provided."
            self._append_console(cancel_msg)
            return False, cancel_msg
        attempts = 0
        last_message = ""
        while attempts < 2:
            attempts += 1
            success, last_message, _ = self._run_docker_command_once(
                command,
                title=title,
                use_sudo=True,
                password=password,
            )
            if success:
                return True, last_message
            if not self._password_error_requires_retry(last_message or ""):
                return False, last_message
            self._clear_cached_sudo_password()
            password = self._obtain_sudo_password(sudo_prompt)
            if not password:
                cancel_msg = "Docker command cancelled; sudo password not provided."
                self._append_console(cancel_msg)
                return False, cancel_msg
        return False, last_message

    def _run_simple_subprocess(
        self,
        command: list[str],
        *,
        timeout: int = 30,
        use_sudo: bool = False,
        password: str | None = None,
    ) -> tuple[int, str, str]:
        final_command = ["sudo", "-S", "-p", "", *command] if use_sudo else list(command)
        prefix = "sudo " if use_sudo else ""
        self._append_console(f"Running docker command: {prefix}{' '.join(command)}")
        try:
            completed = subprocess.run(
                final_command,
                input=(password + "\n") if use_sudo and password else None,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError:
            return -1, "", f"Executable not found: {command[0]}"
        except subprocess.TimeoutExpired:
            return -1, "", f"{' '.join(command)} timed out."
        except subprocess.SubprocessError as exc:
            return -1, "", str(exc)
        if completed.returncode == 0:
            self._append_console("Docker command succeeded.")
        else:
            self._append_console(
                f"Docker command failed ({completed.returncode}): {completed.stderr.strip() or completed.stdout.strip()}"
            )
        return completed.returncode, completed.stdout or "", completed.stderr or ""

    def _run_command_with_optional_sudo_simple(
        self,
        command: list[str],
        *,
        prompt: str,
        permission_markers: tuple[str, ...] = ("permission denied",),
        timeout: int = 30,
        allow_prompt: bool = True,
    ) -> tuple[int, str, str]:
        code, stdout, stderr = self._run_simple_subprocess(command, timeout=timeout)
        if code == 0:
            return code, stdout, stderr
        combined = f"{stdout}\n{stderr}".lower()
        if not any(marker in combined for marker in permission_markers):
            return code, stdout, stderr
        if not allow_prompt:
            return code, stdout, stderr
        password = self._obtain_sudo_password(prompt)
        if not password:
            return code, stdout, stderr
        attempts = 0
        last_stdout, last_stderr = stdout, stderr
        while attempts < 2:
            attempts += 1
            code, last_stdout, last_stderr = self._run_simple_subprocess(
                command,
                timeout=timeout,
                use_sudo=True,
                password=password,
            )
            if code == 0:
                return code, last_stdout, last_stderr
            combined = f"{last_stdout}\n{last_stderr}".lower()
            if not self._password_error_requires_retry(combined):
                return code, last_stdout, last_stderr
            self._clear_cached_sudo_password()
            password = self._obtain_sudo_password(prompt)
            if not password:
                return code, last_stdout, last_stderr
        return code, last_stdout, last_stderr

    def _read_aslr_state(self) -> tuple[bool, int | None]:
        aslr_file = Path("/proc/sys/kernel/randomize_va_space")
        try:
            value_str = aslr_file.read_text(encoding="utf-8").strip()
            return True, int(value_str)
        except (OSError, ValueError) as exc:
            self._append_console(f"Unable to read ASLR state: {exc}")
            return False, None

    def _ensure_aslr_disabled_for_execution(self, binary_label: str, *, allow_prompt: bool = True) -> bool:
        ok, value = self._read_aslr_state()
        if not ok or value is None:
            return True
        if value == 0:
            return True
        if not allow_prompt:
            self._append_console(
                f"ASLR is enabled (kernel.randomize_va_space={value}); continuing without prompting (batch mode)."
            )
            return True
        prompt_text = (
            "Kernel ASLR is currently enabled (kernel.randomize_va_space != 0).\n\n"
            "This can cause the recorded instruction addresses for"
            f" '{binary_label}' to shift and break sanitization.\n\n"
            "Disable ASLR now? HoneyProc can run 'sysctl -w kernel.randomize_va_space=0' with sudo."
        )
        choice = QMessageBox.question(
            self,
            "ASLR detected",
            prompt_text,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        if choice != QMessageBox.Yes:
            self._append_console("ASLR remains enabled; continuing run per user choice.")
            return True
        if self._disable_system_aslr():
            return True
        self._append_console("Run cancelled: Unable to disable ASLR.")
        return False

    def _disable_system_aslr(self) -> bool:
        password = self._obtain_sudo_password("Enter sudo password to disable ASLR (sysctl -w kernel.randomize_va_space=0):")
        if not password:
            self._append_console("ASLR disable cancelled; sudo password not provided.")
            return False
        command = ["sysctl", "-w", "kernel.randomize_va_space=0"]
        code, stdout, stderr = self._run_simple_subprocess(command, use_sudo=True, password=password)
        if code == 0:
            self._append_console("ASLR disabled (kernel.randomize_va_space set to 0).")
            return True
        combined = "\n".join(part for part in (stdout.strip(), stderr.strip()) if part)
        if self._password_error_requires_retry(combined):
            self._clear_cached_sudo_password()
        message = combined or "Failed to disable ASLR via sysctl."
        QMessageBox.critical(self, "Unable to disable ASLR", message)
        return False

    def _start_revng_container(self) -> tuple[bool, str]:
        image = self._configured_revng_image()
        container_name = self._revng_container_name()
        start_command = ["docker", "start", container_name]
        self._append_console(
            f"Attempting to start rev.ng container '{container_name}' using image {image}."
        )
        success, message, needs_sudo = self._run_docker_command_once(start_command, title=f"Starting rev.ng container '{container_name}'")
        if not success and needs_sudo:
            success, message = self._run_docker_command_with_sudo(
                start_command,
                title=f"Starting rev.ng container '{container_name}'",
                sudo_prompt="Enter sudo password to start the rev.ng container:",
            )
        if success:
            return True, message or f"rev.ng container '{container_name}' started."
        lowered = (message or "").lower()
        missing = "no such container" in lowered
        if not missing:
            return False, message or f"Failed to start rev.ng container '{container_name}'."
        self._append_console(
            f"rev.ng container '{container_name}' not found; creating a new instance from {image}."
        )
        run_command = [
            "docker",
            "run",
            "-d",
            "--name",
            container_name,
            image,
            "tail",
            "-f",
            "/dev/null",
        ]
        success, run_message, needs_sudo = self._run_docker_command_once(run_command, title=f"Launching rev.ng container from {image}")
        if not success and needs_sudo:
            success, run_message = self._run_docker_command_with_sudo(
                run_command,
                title=f"Launching rev.ng container from {image}",
                sudo_prompt="Enter sudo password to launch the rev.ng container:",
            )
        if success:
            return True, run_message or f"Launched rev.ng container '{container_name}'."
        conflict = "already in use" in (run_message or "").lower()
        if conflict:
            self._append_console(
                f"rev.ng container name '{container_name}' already in use; attempting cleanup."
            )
            remove_command = ["docker", "rm", "-f", container_name]
            removed, remove_message, needs_sudo = self._run_docker_command_once(
                remove_command,
                title=f"Removing stale rev.ng container '{container_name}'",
            )
            if not removed and needs_sudo:
                removed, remove_message = self._run_docker_command_with_sudo(
                    remove_command,
                    title=f"Removing stale rev.ng container '{container_name}'",
                    sudo_prompt="Enter sudo password to remove the rev.ng container:",
                )
            if not removed:
                return False, run_message or remove_message or "Failed to remove stale rev.ng container."
            success, rerun_message, needs_sudo = self._run_docker_command_once(
                run_command,
                title=f"Launching rev.ng container from {image}",
            )
            if not success and needs_sudo:
                success, rerun_message = self._run_docker_command_with_sudo(
                    run_command,
                    title=f"Launching rev.ng container from {image}",
                    sudo_prompt="Enter sudo password to launch the rev.ng container:",
                )
            if success:
                return True, rerun_message or f"Launched rev.ng container '{container_name}'."
            return False, rerun_message or "Failed to launch rev.ng container after cleanup."
        return False, run_message or f"Failed to launch rev.ng container '{container_name}'."

    def _ensure_revng_wrapper_exists(self, *, quiet_if_current: bool = False) -> tuple[bool, Path | None, str]:
        image = self._configured_revng_image()
        desired_content = self._revng_wrapper_script(image)
        script_path = self._available_revng_script()
        if script_path and script_path.exists():
            try:
                current_content = script_path.read_text(encoding="utf-8")
            except OSError as exc:
                message = f"Failed to read rev.ng wrapper: {exc}"
                self._append_console(message)
                return False, None, message
            if current_content != desired_content:
                try:
                    script_path.write_text(desired_content, encoding="utf-8")
                    script_path.chmod(0o755)
                except OSError as exc:
                    message = f"Failed to update rev.ng wrapper: {exc}"
                    self._append_console(message)
                    return False, None, message
                update_message = f"Updated rev.ng wrapper at {script_path}"
                self._append_console(update_message)
                self._ensure_revng_path_registered(script_path)
                return True, script_path, "Wrapper updated."
            if not quiet_if_current:
                self._append_console(f"Wrapper already present at {script_path}")
            self._ensure_revng_path_registered(script_path)
            return True, script_path, "Wrapper already exists."
        try:
            created_path = self._write_revng_wrapper()
            self._ensure_revng_path_registered(created_path)
            return True, created_path, f"Wrapper created at {created_path}"
        except OSError as exc:
            message = f"Failed to write rev.ng wrapper: {exc}"
            self._append_console(message)
            return False, None, message

    def _sanitized_output_path(self, entry: RunEntry) -> Path:
        project_root = self._project_storage_root(self.active_project)
        run_slug = self._sanitize_run_label(entry.name)
        return project_root / run_slug / "sanitized" / Path(entry.binary_path).name

    def _sync_log_destination_ui(self) -> None:
        actual_path = str(self._project_log_path())
        if hasattr(self, "log_path"):
            self.log_path.setText(actual_path)
        if hasattr(self, "controller") and self.controller:
            self.controller.set_log_path(actual_path)

    def _relocate_log_path(self, existing: str | None) -> str | None:
        if not existing:
            return existing
        try:
            path_obj = Path(existing).expanduser().resolve()
        except OSError:
            path_obj = Path(existing).expanduser()
        new_root = self._projects_root(ensure_exists=True)
        try:
            new_root_resolved = new_root.resolve()
        except OSError:
            new_root_resolved = new_root
        try:
            path_obj.relative_to(new_root_resolved)
            return str(path_obj)
        except ValueError:
            pass
        legacy_root = self._legacy_projects_root
        if not legacy_root:
            return str(path_obj)
        try:
            legacy_resolved = legacy_root.resolve()
        except OSError:
            legacy_resolved = legacy_root
        try:
            relative = path_obj.relative_to(legacy_resolved)
        except ValueError:
            return str(path_obj)
        return str(new_root / relative)

    def _upgrade_entry_paths(self) -> bool:
        updated = False
        for entry in self.run_entries:
            new_path = self._relocate_log_path(entry.log_path)
            if new_path and new_path != entry.log_path:
                entry.log_path = new_path
                updated = True
        return updated

    def _delete_project_storage(self, project: str) -> None:
        root = self._project_storage_root(project, ensure_exists=False)
        if root.exists():
            shutil.rmtree(root, ignore_errors=True)

    def _rename_project_storage(self, old_name: str, new_name: str) -> None:
        old_root = self._project_storage_root(old_name, ensure_exists=False)
        new_root = self._project_storage_root(new_name, ensure_exists=False)
        if not old_root.exists() or old_root == new_root:
            return
        new_root.parent.mkdir(parents=True, exist_ok=True)
        if new_root.exists():
            for child in old_root.iterdir():
                target = new_root / child.name
                if target.exists():
                    if child.is_dir():
                        shutil.rmtree(target, ignore_errors=True)
                    else:
                        target.unlink(missing_ok=True)
                shutil.move(str(child), str(new_root))
            shutil.rmtree(old_root, ignore_errors=True)
        else:
            shutil.move(str(old_root), str(new_root))

    def _toggle_console_visibility(self, collapsed: bool) -> None:
        self._console_collapsed = collapsed
        if hasattr(self, "console_output"):
            self.console_output.setVisible(not collapsed)
        if hasattr(self, "console_toggle_button"):
            self.console_toggle_button.setText("Show Console" if collapsed else "Hide Console")
        if not hasattr(self, "main_splitter"):
            return
        header_height = getattr(self, "_console_header_only_height", 48)
        if hasattr(self, "console_container"):
            default_max = self._console_default_max_height or self.console_container.maximumHeight()
            if collapsed:
                self.console_container.setMinimumHeight(header_height)
                self.console_container.setMaximumHeight(header_height)
            else:
                self.console_container.setMinimumHeight(0)
                self.console_container.setMaximumHeight(default_max)
        sizes = self.main_splitter.sizes()
        if len(sizes) < 2:
            return
        total = max(sum(sizes), 1)
        if collapsed:
            self._console_saved_size = sizes[1] if sizes[1] > 0 else self._console_saved_size
            header_only = min(header_height, total - 200) if total > 200 else header_height
            sizes[1] = max(header_only, header_height)
            sizes[0] = max(total - sizes[1], 200)
        else:
            restore = self._console_saved_size or max(total // 4, 150)
            restore = min(restore, total - 200) if total > 200 else restore
            sizes[1] = max(restore, 120)
            sizes[0] = max(total - sizes[1], 200)
        self.main_splitter.setSizes(sizes)
        if hasattr(self, "show_console_action"):
            self.show_console_action.setEnabled(collapsed)

    def _restore_console_from_menu(self) -> None:
        if hasattr(self, "console_toggle_button") and self.console_toggle_button.isChecked():
            self.console_toggle_button.setChecked(False)
            return
        self._toggle_console_visibility(False)

    def _compute_default_tool_path(self) -> Path:
        return Path(__file__).resolve().parents[1] / "pin-tool" / "obj-intel64" / "ins_logger.so"

    def _ensure_tool_path_default(self, project: str | None = None) -> None:
        settings = self._project_config(project)
        if settings.tool_path:
            return
        default_tool = self._default_tool_path_value
        settings.tool_path = str(default_tool)
        self.config.tool_path = str(default_tool)
        self.config_manager.save(self.config)

    def _apply_tool_path(self, path: Path) -> None:
        tool_str = str(path)
        self.tool_path.setText(tool_str)
        settings = self._project_config()
        settings.tool_path = tool_str
        self.config.tool_path = tool_str
        self.config_manager.save(self.config)
        if hasattr(self, "controller"):
            self.controller.set_tool_path(path)

    def _update_tool_path_if_default_exists(self) -> None:
        default_tool = self._default_tool_path_value
        if default_tool.exists():
            self._apply_tool_path(default_tool)

    def select_pin_root(self) -> None:
        current_dir = self._project_config().pin_root or ""
        directory = QFileDialog.getExistingDirectory(self, "Select Intel PIN directory", current_dir)
        if not directory:
            return
        settings = self._project_config()
        settings.pin_root = directory
        self.config.pin_root = directory
        self.config_manager.save(self.config)
        self.pin_path.setText(directory)
        self.controller.set_pin_root(directory)
        self._append_console(f"PIN directory set to: {directory}")

    def select_binary(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select target binary")
        if not path:
            return
        self.selected_binary = path
        self.binary_path.setText(path)
        settings = self._project_config()
        settings.binary_path = path
        self.config.binary_path = path
        self.config_manager.save(self.config)
        self.logs_exec_label.setText(f"Execution Logs for: {Path(path).name}")
        self._append_console(f"Selected binary: {path}")
        self._update_honey_entries_label()

    def select_tool(self) -> None:
        current_tool = self.tool_path.text().strip() or str(self._default_tool_path_value)
        path, _ = QFileDialog.getOpenFileName(self, "Select PIN Tool", current_tool, "Shared objects (*.so)")
        if not path:
            return
        new_tool = Path(path)
        self._apply_tool_path(new_tool)
        self._append_console(f"PIN tool set to: {new_tool}")

    def sanitize_honey_entry(self) -> None:
        if self._has_active_sanitization():
            QMessageBox.information(
                self,
                "Sanitization in progress",
                "Please wait for the current sanitization job to finish before starting another.",
            )
            return
        prep_dialog = self._show_busy_dialog("Checking rev.ng environment...", title="Preparing Sanitization")
        try:
            if not self._ensure_revng_cli_available():
                return
            if not self._ensure_revng_container_running():
                return
        finally:
            prep_dialog.close()
        entry = self._current_honey_entry()
        if not entry:
            QMessageBox.information(self, "No entry selected", "Select a HoneyProc entry to sanitize.")
            return
        if not entry.log_path:
            QMessageBox.warning(self, "Missing log", "This entry does not have an instruction log to analyze.")
            return
        log_path = Path(entry.log_path)
        if not log_path.exists():
            QMessageBox.warning(
                self,
                "Log not found",
                f"The instruction log could not be found at {log_path}. Re-run the entry to regenerate it.",
            )
            return
        if not entry.binary_path:
            QMessageBox.warning(self, "Missing binary", "This entry is missing its binary path.")
            return
        binary_path = Path(entry.binary_path)
        if not binary_path.exists():
            QMessageBox.warning(
                self,
                "Binary not found",
                f"The binary referenced by this entry was not found at {binary_path}.",
            )
            return

        default_output_path = self._sanitized_output_path(entry)
        report = None
        analyze_dialog = self._show_busy_dialog("Analyzing instruction log...", title="Preparing Sanitization")
        try:
            try:
                report = collect_executed_addresses(log_path)
            except Exception as exc:
                QMessageBox.critical(
                    self,
                    "Unable to analyze log",
                    f"Failed to parse instruction log before sanitization:\n{exc}",
                )
                self._append_console(f"Sanitization aborted: {exc}")
                return
        finally:
            analyze_dialog.close()
        if not report or not report.addresses:
            QMessageBox.warning(
                self,
                "No instructions",
                "The selected log does not contain any executed instruction entries.",
            )
            return
        sanity_allowed = bool(report.sampled_instructions)
        settings = self._project_config()
        initial_prefs = {
            "runnable_first": bool(getattr(settings, "sanitize_runnable_first", True)),
            "only_text": bool(getattr(settings, "sanitize_only_text", False)),
            "preserve_trampolines": bool(getattr(settings, "sanitize_preserve_trampolines", True)),
            "protect_dynlinks": bool(getattr(settings, "sanitize_protect_dynlinks", True)),
            "protect_unwind": bool(getattr(settings, "sanitize_protect_unwind", True)),
            "protect_indirect": bool(getattr(settings, "sanitize_protect_indirect", True)),
            "segment_padding": str(getattr(settings, "sanitize_segment_padding", "0x2000")),
            "segment_gap": str(getattr(settings, "sanitize_segment_gap", f"0x{SANITIZE_RUNNABLE_FIRST_SEGMENT_GAP:x}")),
            "icf_window": str(getattr(settings, "sanitize_icf_window", "0x400")),
            "jumptable_window": str(getattr(settings, "sanitize_jumptable_window", "0x800")),
        }
        config_dialog = SanitizeConfigDialog(
            self,
            default_name=default_output_path.name,
            default_permissions=binary_path.stat().st_mode,
            sanity_allowed=sanity_allowed,
            initial=initial_prefs,
        )
        if config_dialog.exec() != QDialog.Accepted:
            self._append_console("Sanitization cancelled before launch.")
            return
        sanitize_options = config_dialog.selected_options()

        if config_dialog.sweep_enabled():
            if self._current_sweep_thread and self._current_sweep_thread.isRunning():
                QMessageBox.information(self, "Sweep in progress", "Please wait for the current sweep to finish.")
                return
            sweep_variants = config_dialog.sweep_variants()
            if not sweep_variants:
                QMessageBox.warning(self, "Invalid sweep", "No sweep values were generated from the provided ranges.")
                return

        # Persist preferences for future runs.
        settings.sanitize_runnable_first = bool(sanitize_options.runnable_first)
        settings.sanitize_only_text = bool(sanitize_options.only_text_section)
        settings.sanitize_preserve_trampolines = bool(sanitize_options.preserve_trampoline_sections)
        settings.sanitize_protect_dynlinks = bool(sanitize_options.protect_dynlinks)
        settings.sanitize_protect_unwind = bool(sanitize_options.protect_unwind)
        settings.sanitize_protect_indirect = bool(sanitize_options.protect_indirect)
        settings.sanitize_segment_padding = f"0x{int(sanitize_options.segment_padding):x}"
        settings.sanitize_segment_gap = f"0x{int(sanitize_options.segment_gap):x}"
        settings.sanitize_icf_window = f"0x{int(sanitize_options.icf_window):x}"
        settings.sanitize_jumptable_window = f"0x{int(sanitize_options.jumptable_window):x}"
        self.config_manager.save(self.config)
        output_path = default_output_path
        if sanitize_options.output_name:
            output_path = default_output_path.with_name(sanitize_options.output_name)
        self._ensure_directory(output_path)

        if config_dialog.sweep_enabled():
            # Generate multiple variants instead of a single sanitized output.
            dialog = SanitizeProgressDialog(self, f"{binary_path.name or entry.name} (Sweep)")
            thread = QThread(self)
            worker = SanitizeSweepWorker(
                entry.entry_id,
                binary_path,
                log_path,
                output_path,
                sanitize_options,
                executed_addresses=report.addresses,
                parsed_rows=report.parsed_rows,
                instruction_samples=report.sampled_instructions,
                binary_offset=int(entry.binary_offset or 0),
                preserve_segments=self._entry_segments(entry),
                sweep_variants=sweep_variants,
            )
            worker.moveToThread(thread)

            worker.progress.connect(dialog.append_output)
            worker.progress.connect(dialog.update_status)
            worker.progress.connect(self._append_console)
            worker.progress_counts.connect(dialog.update_generation_progress)

            def _on_variant(payload: object) -> None:
                if not isinstance(payload, dict):
                    return
                target = self._entry_by_id(payload.get("entry_id"))
                if target is None:
                    return
                result = SanitizationResult(
                    total_instructions=int(payload.get("total_instructions", 0) or 0),
                    preserved_instructions=int(payload.get("preserved_instructions", 0) or 0),
                    nopped_instructions=int(payload.get("nopped_instructions", 0) or 0),
                    output_path=Path(str(payload.get("output_path") or "")),
                )
                opts = sanitize_options._replace(
                    segment_gap=int(payload.get("segment_gap", 0) or 0),
                    segment_padding=int(payload.get("segment_padding", 0) or 0),
                    icf_window=int(payload.get("icf_window", 0) or 0),
                    jumptable_window=int(payload.get("jumptable_window", 0) or 0),
                )
                self._add_sanitized_output(target, result, opts)
                self._refresh_entry_views(target.entry_id)

            def _on_finished(payload: object) -> None:
                dialog.mark_finished("Sweep complete.")
                summary = payload if isinstance(payload, dict) else {}
                QMessageBox.information(
                    self,
                    "Sweep complete",
                    f"Generated {int(summary.get('successes', 0) or 0)} binary(ies); {int(summary.get('failures', 0) or 0)} failed.",
                )
                self._cleanup_sweep_worker()

            worker.variant_succeeded.connect(_on_variant, Qt.QueuedConnection)
            worker.finished.connect(_on_finished, Qt.QueuedConnection)
            thread.finished.connect(self._cleanup_sweep_worker)
            dialog.finished.connect(self._cleanup_sweep_worker)
            thread.started.connect(worker.run)

            self._current_sweep_thread = thread
            self._current_sweep_worker = worker
            self._append_console(
                f"Starting sanitization sweep for '{entry.name}'. Output template: {output_path}"
            )
            thread.start()
            dialog.exec()
            self._cleanup_sweep_worker()
            return

        dialog = SanitizeProgressDialog(self, binary_path.name or entry.name)
        worker = SanitizeWorker(
            entry.entry_id,
            binary_path,
            log_path,
            output_path,
            sanitize_options,
            executed_addresses=report.addresses,
            parsed_rows=report.parsed_rows,
            instruction_samples=report.sampled_instructions,
            binary_offset=int(entry.binary_offset or 0),
            preserve_segments=self._entry_segments(entry),
            segment_padding=int(sanitize_options.segment_padding),
        )
        thread = QThread(self)
        worker.moveToThread(thread)

        worker.progress.connect(dialog.append_output)
        worker.progress.connect(dialog.update_status)
        worker.progress.connect(self._append_console)
        worker.succeeded.connect(self._handle_sanitize_success)
        worker.failed.connect(self._handle_sanitize_failure)
        thread.finished.connect(self._cleanup_sanitize_worker)
        dialog.finished.connect(self._cleanup_sanitize_worker)
        thread.started.connect(worker.run)

        self._current_sanitize_thread = thread
        self._current_sanitize_worker = worker
        self._current_sanitize_dialog = dialog
        self._current_sanitize_entry_id = entry.entry_id
        self._update_honey_buttons()

        self._append_console(
            f"Starting sanitization for '{entry.name}'. Output will be saved to: {output_path}"
        )
        self._append_console(f"Instruction log source: {log_path}")
        thread.start()
        dialog.exec()
        self._cleanup_sanitize_worker()

    def _handle_revng_image_edit(self) -> None:
        if not hasattr(self, "revng_image_input"):
            return
        value = self.revng_image_input.text().strip()
        self._apply_revng_image_value(value)

    def _reset_revng_image(self) -> None:
        self._apply_revng_image_value("revng/revng")

    def _apply_revng_image_value(self, value: str) -> None:
        new_value = value or "revng/revng"
        settings = self._project_config()
        current_value = settings.revng_docker_image or "revng/revng"
        self.revng_image_input.setText(new_value)
        if new_value == current_value:
            return
        settings.revng_docker_image = new_value
        self.config.revng_docker_image = new_value
        self.config_manager.save(self.config)
        # Reload config to ensure it's persisted and consistent
        self.config = self.config_manager.load()
        self._append_console(f"rev.ng Docker image set to: {new_value}")

    def delete_current_project(self) -> None:
        if len(self.config.projects) <= 1:
            QMessageBox.information(self, "Cannot delete", "At least one project must remain.")
            return
        project = self.active_project
        if not project:
            return
        confirm = QMessageBox.question(
            self,
            "Delete project",
            f"Delete project '{project}' and its run history?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        self.history_store.delete_project(project)
        try:
            project_index = self.config.projects.index(project)
        except ValueError:
            return

        self.config.projects.pop(project_index)
        self.config.project_settings.pop(project, None)
        next_index = min(project_index, len(self.config.projects) - 1)
        next_project = self.config.projects[next_index]

        self.project_list.blockSignals(True)
        self.project_list.takeItem(project_index)
        self.project_list.setCurrentRow(next_index)
        self.project_list.blockSignals(False)

        self.active_project = next_project
        self.config.active_project = next_project
        self._ensure_tool_path_default(next_project)
        self.config_manager.save(self.config)
        self.run_entries = self.history_store.load_project(next_project)
        self._refresh_entry_views(None)
        self._delete_project_storage(project)
        self._sync_log_destination_ui()
        self._refresh_project_config_ui()
        self._apply_project_settings_to_controller()
        self._append_console(f"Deleted project: {project}")

    def build_tool(self) -> None:
        if self._current_build_thread and self._current_build_thread.isRunning():
            QMessageBox.information(self, "Build in progress", "Please wait for the current build to finish.")
            return

        dialog = BuildProgressDialog(self)
        worker = BuildWorker(self.controller)
        thread = QThread(self)
        worker.moveToThread(thread)

        worker.output.connect(dialog.append_output)
        worker.output.connect(self._append_console)

        self._current_build_thread = thread
        self._current_build_worker = worker
        self._current_build_dialog = dialog

        worker.succeeded.connect(self._handle_build_worker_success)
        worker.failed.connect(self._handle_build_worker_failure)
        thread.finished.connect(self._cleanup_build_worker)
        dialog.finished.connect(self._cleanup_build_worker)

        thread.started.connect(worker.run)

        self.build_tool_button.setEnabled(False)
        self._append_console("Starting PIN tool build...")
        thread.start()
        dialog.exec()
        self._cleanup_build_worker()

    def run_selected_binary(self) -> None:
        if not self.selected_binary:
            QMessageBox.warning(self, "No binary", "Please select a binary before running.")
            return
        dialog_result = self._prompt_module_selection(
            self.selected_binary,
            default_log_label=self._default_run_label(self.selected_binary),
        )
        if dialog_result is None:
            return
        module_filters, log_label, unique_only, run_with_sudo, pre_run_command, copy_to_relative = dialog_result
        log_path = str(self._project_log_path(run_label=log_label))
        self._run_and_record(
            self.selected_binary,
            log_path,
            run_label=log_label,
            module_filters=module_filters,
            unique_only=unique_only,
            run_with_sudo=run_with_sudo,
            pre_run_command=pre_run_command,
            copy_binary_to_relative_path=copy_to_relative,
        )

    def create_new_log_entry(self) -> None:
        if self._current_run_thread and self._current_run_thread.isRunning():
            QMessageBox.information(self, "Run in progress", "Please wait for the current log creation to finish.")
            return
        binary = (self._project_config().binary_path or "").strip()
        if not binary:
            QMessageBox.warning(self, "No binary configured", "Set a binary in the Configuration tab first.")
            return
        self.selected_binary = binary
        self.binary_path.setText(binary)
        self._update_honey_entries_label()
        default_label = self._default_run_label(binary)
        dialog_result = self._prompt_module_selection(binary, default_log_label=default_label)
        if dialog_result is None:
            return
        module_filters, log_label, unique_only, run_with_sudo, pre_run_command, copy_to_relative = dialog_result
        log_path = str(self._project_log_path(run_label=log_label))
        self._run_with_progress(
            binary,
            log_path,
            run_label=log_label,
            dialog_label=log_label,
            module_filters=module_filters,
            unique_only=unique_only,
            run_with_sudo=run_with_sudo,
            pre_run_command=pre_run_command,
            copy_binary_to_relative_path=copy_to_relative,
        )

    def delete_log_entry(self) -> None:
        entry = self._current_log_entry()
        if not entry:
            QMessageBox.information(self, "No log selected", "Select a log entry to delete.")
            return
        confirm = QMessageBox.question(
            self,
            "Delete log entry",
            f"Delete log '{entry.name}'?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        self.run_entries = [candidate for candidate in self.run_entries if candidate.entry_id != entry.entry_id]
        self._refresh_entry_views(None)
        self._persist_current_history()
        self._append_console(f"Deleted log entry: {entry.name}")

    def prepare_log_for_honeyproc(self) -> None:
        if self._honey_prepare_thread is not None:
            QMessageBox.information(
                self,
                "Preparation running",
                "HoneyProc preparation is already in progress. Please wait for it to finish before starting another.",
            )
            return
        entry = self._current_log_entry()
        if not entry:
            QMessageBox.information(self, "No log selected", "Select a log entry to prepare.")
            return
        if entry.is_sanitized_run:
            QMessageBox.information(
                self,
                "Preparation unavailable",
                "Sanitized replay entries inherit preparation from their parent and do not need this step.",
            )
            return
        if self._entry_prepared(entry):
            QMessageBox.information(
                self,
                "Already prepared",
                f"'{entry.name}' is already ready for HoneyProc.",
            )
            self._update_prepare_button_state(entry)
            return
        log_path_value = self._entry_field(entry, "log_path")
        if not log_path_value:
            QMessageBox.warning(self, "Missing log", "This entry does not reference a log file to prepare.")
            return
        log_path = Path(log_path_value)
        if not log_path.exists():
            QMessageBox.warning(
                self,
                "Log not found",
                f"The instruction log could not be found at {log_path}. Re-run the entry to regenerate it.",
            )
            return

        button = getattr(self, "prepare_honey_button", None)
        if button is not None:
            button.setEnabled(False)

        dialog = BusyProgressDialog("Preparing HoneyProc data...", "Cancel", 0, 0, self)
        dialog.setWindowTitle("Prepare for HoneyProc")
        dialog.setWindowModality(Qt.ApplicationModal)
        dialog.setMinimumDuration(0)
        dialog.setLabelText("Parsing instruction log...")
        dialog.resize(600, 240)
        dialog.start_pulsing()
        dialog.show()

        worker = HoneyPreparationWorker(log_path, max_gap=HONEY_SEGMENT_MAX_GAP)
        thread = QThread(self)
        worker.moveToThread(thread)

        self._honey_prepare_thread = thread
        self._honey_prepare_worker = worker
        self._honey_prepare_dialog = dialog

        target_entry_id = entry.entry_id
        entry_name = entry.name

        def _cleanup(enable_button: bool = True) -> None:
            progress_dialog = self._honey_prepare_dialog
            if progress_dialog is not None:
                progress_dialog.hide()
                progress_dialog.close()
                progress_dialog.deleteLater()
            self._honey_prepare_dialog = None

            worker_obj = self._honey_prepare_worker
            if worker_obj is not None:
                worker_obj.deleteLater()
            self._honey_prepare_worker = None

            thread_obj = self._honey_prepare_thread
            if thread_obj is not None:
                if thread_obj.isRunning():
                    thread_obj.quit()
                    thread_obj.wait()
                thread_obj.deleteLater()
            self._honey_prepare_thread = None

            if enable_button:
                button_ref = getattr(self, "prepare_honey_button", None)
                if button_ref is not None:
                    button_ref.setEnabled(True)

        def _handle_progress(message: str) -> None:
            progress_dialog = self._honey_prepare_dialog
            if progress_dialog is None:
                return
            progress_dialog.setLabelText(message)
            QApplication.processEvents()

        def _handle_progress_counts(processed: int, total: int) -> None:
            progress_dialog = self._honey_prepare_dialog
            if progress_dialog is None:
                return
            processed = max(0, processed)
            total = max(0, total)
            if total > 0:
                progress_dialog.setRange(0, total)
                progress_dialog.setValue(min(processed, total))
                progress_dialog.setLabelText(
                    f"Parsing instruction log ({processed}/{total})"
                )
            else:
                progress_dialog.setRange(0, 0)
                progress_dialog.setLabelText(
                    f"Parsing instruction log ({processed} rows)..." if processed else "Parsing instruction log..."
                )
            QApplication.processEvents()

        def _handle_cancelled() -> None:
            _cleanup()
            QMessageBox.information(self, "Preparation cancelled", "HoneyProc preparation was cancelled.")
            self._update_prepare_button_state(self._entry_by_id(target_entry_id))

        def _handle_failed(message: str) -> None:
            _cleanup()
            QMessageBox.critical(
                self,
                "Unable to parse log",
                f"Failed to load the instruction log for preparation:\n{message}",
            )
            self._update_prepare_button_state(self._entry_by_id(target_entry_id))

        def _handle_succeeded(payload: object) -> None:
            _cleanup()
            data = payload if isinstance(payload, dict) else {}
            addresses = list(data.get("addresses", []) or [])
            segments = list(data.get("segments", []) or [])
            target_entry = self._entry_by_id(target_entry_id)
            if target_entry is None:
                return
            if not addresses:
                QMessageBox.information(
                    self,
                    "Empty log",
                    "No instruction entries were discovered in the log. Nothing to prepare.",
                )
                self._update_prepare_button_state(target_entry)
                return
            if not segments:
                QMessageBox.information(
                    self,
                    "No contiguous segments",
                    "Unable to derive contiguous memory segments from this log.",
                )
                self._update_prepare_button_state(target_entry)
                return
            target_entry.prepared_segments = segments
            target_entry.prepared_at = datetime.now()
            target_entry.trace_address_count = len(addresses)
            binary_path_obj = Path(target_entry.binary_path) if target_entry.binary_path else None
            if binary_path_obj and binary_path_obj.exists():
                target_entry.binary_instruction_count = self._estimate_binary_instruction_count(binary_path_obj)
            else:
                target_entry.binary_instruction_count = 0
            self._persist_current_history()
            self._refresh_entry_views(target_entry.entry_id)
            segment_count = len(segments)
            address_count = len(addresses)
            self._append_console(
                f"Prepared '{target_entry.name}' for HoneyProc: {segment_count} segment(s) covering {address_count} addresses."
            )
            QMessageBox.information(
                self,
                "HoneyProc ready",
                (
                    f"'{entry_name}' is ready for HoneyProc.\n"
                    f"Segments detected: {segment_count}. Unique addresses: {address_count}."
                ),
            )
            self._update_prepare_button_state(target_entry)

        worker.progress.connect(_handle_progress)
        worker.progress_counts.connect(_handle_progress_counts)
        worker.succeeded.connect(_handle_succeeded)
        worker.failed.connect(_handle_failed)
        worker.cancelled.connect(_handle_cancelled)
        dialog.canceled.connect(worker.cancel)
        thread.started.connect(worker.run)
        thread.start()

    def change_active_project(self, project_name: str) -> None:
        if not project_name or project_name == self.active_project:
            return
        self._persist_current_history()
        self.active_project = project_name
        self.config.active_project = project_name
        self._ensure_tool_path_default(project_name)
        self.config_manager.save(self.config)
        self._append_console(f"Active project switched to: {project_name}")
        self._refresh_project_config_ui()
        self._apply_project_settings_to_controller()
        self._load_history_for_active_project()
        self._sync_log_destination_ui()

    def _show_project_context_menu(self, pos) -> None:
        menu = QMenu(self)
        add_action = menu.addAction("Add Project")
        rename_action = menu.addAction("Rename Project")
        rename_action.setEnabled(self.project_list.currentItem() is not None)
        delete_action = menu.addAction("Delete Project")
        delete_action.setEnabled(self.project_list.currentItem() is not None and len(self.config.projects) > 1)
        action = menu.exec(self.project_list.viewport().mapToGlobal(pos))
        if action == add_action:
            self.add_new_project()
        elif action == rename_action:
            self.rename_project()
        elif action == delete_action:
            self.delete_current_project()

    def add_new_project(self) -> None:
        name, ok = QInputDialog.getText(self, "New Project", "Project name:")
        project_name = name.strip()
        if not ok or not project_name:
            return
        if project_name in self.config.projects:
            QMessageBox.information(self, "Project exists", "Project name already present.")
            return
        self.config.projects.append(project_name)
        self.config.project_settings[project_name] = self._clone_project_settings(self._project_config())
        self.config.active_project = project_name
        self.config_manager.save(self.config)
        self.project_list.addItem(project_name)
        items = self.project_list.findItems(project_name, Qt.MatchExactly)
        if items:
            self.project_list.setCurrentItem(items[0])

    def rename_project(self) -> None:
        current_item = self.project_list.currentItem()
        if not current_item:
            QMessageBox.information(self, "No project selected", "Select a project to rename.")
            return
        old_name = current_item.text()
        name, ok = QInputDialog.getText(self, "Rename Project", "New project name:", text=old_name)
        project_name = name.strip()
        if not ok or not project_name or project_name == old_name:
            return
        if project_name in self.config.projects:
            QMessageBox.information(self, "Project exists", "Project name already present.")
            return
        self._persist_current_history()
        self.history_store.rename_project(old_name, project_name)
        index = self.config.projects.index(old_name)
        self.config.projects[index] = project_name
        self.config.active_project = project_name
        self.active_project = project_name
        if old_name in self.config.project_settings:
            self.config.project_settings[project_name] = self.config.project_settings.pop(old_name)
        self._ensure_tool_path_default(project_name)
        self.config_manager.save(self.config)
        current_item.setText(project_name)
        self._persist_current_history()
        self._rename_project_storage(old_name, project_name)
        self._sync_log_destination_ui()
        self._append_console(f"Project renamed to: {project_name}")
        self._refresh_project_config_ui()
        self._apply_project_settings_to_controller()

    def update_log_detail_from_selection(self, current: QListWidgetItem | None, _: QListWidgetItem | None) -> None:
        entry = self._entry_from_item(current)
        if entry:
            name = Path(entry.binary_path).name or entry.binary_path
            self.logs_exec_label.setText(f"Execution Logs for: {name}")
        else:
            self.logs_exec_label.setText("Execution Logs for: None")
        self._update_log_preview(entry)

    def _record_run_entry(
        self,
        binary_path: str,
        log_path: str | None,
        *,
        run_label: str | None = None,
        parent_entry_id: str | None = None,
        sanitized_binary_path: str | None = None,
        is_sanitized_run: bool = False,
        target_args: list[str] | None = None,
        use_sudo: bool = False,
        module_filters: list[str] | None = None,
        pre_run_command: str | None = None,
    ) -> None:
        actual_log = log_path or str(self._project_log_path())
        timestamp = datetime.now()
        label = run_label.strip() if run_label and run_label.strip() else timestamp.strftime("%Y-%m-%d %H:%M:%S")
        entry = RunEntry(
            entry_id=str(uuid.uuid4()),
            name=label,
            binary_path=binary_path,
            log_path=actual_log,
            timestamp=timestamp,
            sanitized_binary_path=sanitized_binary_path,
            parent_entry_id=parent_entry_id,
            is_sanitized_run=is_sanitized_run,
            target_args=target_args,
            use_sudo=use_sudo,
            module_filters=module_filters,
            pre_run_command=pre_run_command,
        )
        self.run_entries.append(entry)
        self._refresh_entry_views(entry.entry_id)
        self.logs_exec_label.setText(f"Execution Logs for: {Path(binary_path).name}")
        self._persist_current_history()

    def _refresh_entry_views(self, newly_added_id: str | None = None) -> None:
        log_list = getattr(self, "logs_list", None)
        sanitized_list = getattr(self, "honey_sanitized_list", None)
        sanitized_label = getattr(self, "honey_sanitized_list_label", None)
        current_entry = self._current_log_entry()
        preferred_id = newly_added_id or (current_entry.entry_id if current_entry else None)

        if log_list is not None:
            log_list.blockSignals(True)
            log_list.clear()
        if sanitized_list is not None:
            sanitized_list.blockSignals(True)
            sanitized_list.clear()
        self.honey_list.blockSignals(True)
        self.honey_list.clear()

        for entry in self.run_entries:
            label = entry.label()
            if log_list is not None:
                log_item = QListWidgetItem(label)
                log_item.setData(Qt.UserRole, entry.entry_id)
                self._apply_log_item_indicator(log_item, entry)
                log_list.addItem(log_item)
            if entry.is_sanitized_run:
                continue
            if self._entry_is_honey_ready(entry):
                trace_range = self._format_address_range(self._entry_trace_bounds(entry))
                binary_range = self._format_address_range(self._entry_binary_bounds(entry))
                binary_count_text, trace_count_text = self._instruction_count_texts(entry)
                nop_text, other_text = self._format_original_instruction_breakdown(entry)
                honey_item = QTreeWidgetItem(
                    [
                        label,
                        trace_range,
                        binary_range,
                        binary_count_text,
                        trace_count_text,
                        nop_text,
                        other_text,
                    ]
                )
                honey_item.setData(0, Qt.UserRole, entry.entry_id)
                honey_item.setToolTip(1, trace_range)
                honey_item.setToolTip(2, binary_range)
                honey_item.setToolTip(3, binary_count_text)
                honey_item.setToolTip(4, trace_count_text)
                honey_item.setToolTip(5, nop_text)
                honey_item.setToolTip(6, other_text)
                self.honey_list.addTopLevelItem(honey_item)

        if sanitized_list is not None:
            rows: list[tuple[datetime, RunEntry, SanitizedBinaryOutput]] = []
            for entry in self.run_entries:
                if entry.is_sanitized_run:
                    continue
                outputs = list(getattr(entry, "sanitized_outputs", None) or [])
                if not outputs and entry.sanitized_binary_path:
                    outputs = [
                        SanitizedBinaryOutput(
                            output_id="legacy",
                            output_path=str(entry.sanitized_binary_path),
                            works=None,
                            segment_gap=0,
                            segment_padding=0,
                            icf_window=0,
                            jumptable_window=0,
                            total_instructions=int(getattr(entry, "sanitized_total_instructions", 0) or 0),
                            preserved_instructions=int(getattr(entry, "sanitized_preserved_instructions", 0) or 0),
                            nopped_instructions=int(getattr(entry, "sanitized_nopped_instructions", 0) or 0),
                            generated_at=None,
                        )
                    ]
                for output in outputs:
                    stamp = output.generated_at or entry.timestamp
                    rows.append((stamp, entry, output))

            if rows:
                rows.sort(key=lambda item: item[0], reverse=True)
                for _, entry, output in rows:
                    binary_spec = output.output_path or ""
                    binary_path = Path(binary_spec) if binary_spec else None
                    binary_label = binary_path.name if binary_path and binary_path.name else (binary_spec or "(unsaved)")
                    counts_text = self._format_instruction_counts(entry)
                    parent_label = entry.label()
                    nop_count = int(getattr(output, "nopped_instructions", 0) or 0)
                    preserved_count = int(getattr(output, "preserved_instructions", 0) or 0)
                    total_count = int(getattr(output, "total_instructions", 0) or 0)
                    replaced_text = "—"
                    nop_text = "—"
                    if nop_count:
                        percent = (nop_count / total_count * 100) if total_count else None
                        if percent is not None:
                            replaced_text = f"{nop_count:,} ({percent:.1f}%)"
                        else:
                            replaced_text = f"{nop_count:,}"
                        nop_text = f"{nop_count:,}"
                    other_text = f"{preserved_count:,}" if preserved_count else "—"
                    total_text = f"{total_count:,}" if total_count else counts_text
                    effective_offset = self._entry_effective_offset(entry)
                    offset_text = f"{effective_offset:+#x}"
                    gap_value = int(getattr(output, "segment_gap", 0) or 0)
                    pad_value = int(getattr(output, "segment_padding", 0) or 0)
                    gap_text = f"0x{gap_value:x}" if gap_value else "—"
                    pad_text = f"0x{pad_value:x}" if pad_value else "—"
                    icf_value = int(getattr(output, "icf_window", 0) or 0)
                    jt_value = int(getattr(output, "jumptable_window", 0) or 0)
                    icf_text = f"0x{icf_value:x}" if icf_value else "—"
                    jt_text = f"0x{jt_value:x}" if jt_value else "—"
                    works_value = getattr(output, "works", None)
                    works_text = "—" if works_value is None else ""
                    item = QTreeWidgetItem(
                        [
                            binary_label or "(unnamed)",
                            parent_label,
                            offset_text,
                            total_text,
                            replaced_text,
                            nop_text,
                            other_text,
                            gap_text,
                            pad_text,
                            icf_text,
                            jt_text,
                            works_text,
                        ]
                    )
                    item.setData(0, Qt.UserRole, {"entry_id": entry.entry_id, "output_id": output.output_id})
                    item.setFlags(item.flags() | Qt.ItemIsUserCheckable | Qt.ItemIsUserTristate)
                    if works_value is True:
                        item.setCheckState(11, Qt.Checked)
                        item.setToolTip(11, "Marked as working")
                    elif works_value is False:
                        item.setCheckState(11, Qt.Unchecked)
                        item.setToolTip(11, "Marked as not working")
                    else:
                        item.setCheckState(11, Qt.PartiallyChecked)
                        item.setToolTip(11, "Not yet tested")
                    tooltip_path = str(binary_path) if binary_path else "(unsaved)"
                    item.setToolTip(0, tooltip_path)
                    item.setToolTip(1, parent_label)
                    item.setToolTip(2, offset_text)
                    item.setToolTip(3, total_text)
                    item.setToolTip(4, replaced_text)
                    item.setToolTip(5, nop_text)
                    item.setToolTip(6, other_text)
                    item.setToolTip(7, gap_text)
                    item.setToolTip(8, pad_text)
                    item.setToolTip(9, icf_text)
                    item.setToolTip(10, jt_text)
                    if item.toolTip(11) == "":
                        item.setToolTip(11, "Not yet tested")
                    if binary_path and not binary_path.exists():
                        item.setForeground(0, QColor("#b00020"))
                        item.setToolTip(0, f"Missing on disk: {binary_path}")
                    sanitized_list.addTopLevelItem(item)
                if sanitized_list.topLevelItemCount() > 0 and sanitized_list.currentItem() is None:
                    sanitized_list.setCurrentItem(sanitized_list.topLevelItem(0))
            else:
                placeholder = QTreeWidgetItem([
                    "No sanitized binaries yet",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                ])
                placeholder.setFlags(placeholder.flags() & ~Qt.ItemIsSelectable)
                placeholder.setFirstColumnSpanned(True)
                sanitized_list.addTopLevelItem(placeholder)
                sanitized_list.clearSelection()
            sanitized_list.blockSignals(False)
            if sanitized_label is not None:
                sanitized_label.setVisible(True)

        if log_list is not None:
            if log_list.count() > 0 and log_list.currentRow() == -1:
                log_list.setCurrentRow(0)
            log_list.blockSignals(False)
        if self.honey_list.topLevelItemCount() > 0 and self.honey_list.currentItem() is None:
            self.honey_list.setCurrentItem(self.honey_list.topLevelItem(0))
        self.honey_list.blockSignals(False)

        self._sync_log_lists_to_entry(preferred_id)
        self.update_log_detail_from_selection(self._current_log_item(), None)
        self._update_honey_buttons()
        self._update_honey_detail(self._current_honey_entry())
        self._update_sanitized_action_state()
        if getattr(self, "_counts_dirty", False):
            self._persist_current_history()
            self._counts_dirty = False

    def _entry_from_item(self, item: QListWidgetItem | QTreeWidgetItem | None) -> RunEntry | None:
        if not item:
            return None
        if isinstance(item, QTreeWidgetItem):
            entry_id = item.data(0, Qt.UserRole)
        else:
            entry_id = item.data(Qt.UserRole)
        return next((entry for entry in self.run_entries if entry.entry_id == entry_id), None)

    def _selected_sanitized_output(self) -> tuple[RunEntry, SanitizedBinaryOutput] | None:
        selections = self._selected_sanitized_outputs()
        if len(selections) != 1:
            return None
        return selections[0]

    def _selected_sanitized_outputs(self) -> list[tuple[RunEntry, SanitizedBinaryOutput]]:
        sanitized_list = getattr(self, "honey_sanitized_list", None)
        if sanitized_list is None:
            return []
        items = list(sanitized_list.selectedItems() or [])
        resolved: list[tuple[int, RunEntry, SanitizedBinaryOutput]] = []
        for item in items:
            payload = item.data(0, Qt.UserRole)
            if not isinstance(payload, dict):
                continue
            entry_id = payload.get("entry_id")
            output_id = payload.get("output_id")
            if not entry_id or not output_id:
                continue
            entry = self._entry_by_id(str(entry_id))
            if entry is None:
                continue
            for output in (getattr(entry, "sanitized_outputs", None) or []):
                if output.output_id == output_id:
                    try:
                        row_index = sanitized_list.indexOfTopLevelItem(item)
                    except Exception:
                        row_index = -1
                    resolved.append((row_index, entry, output))
                    break
        resolved.sort(key=lambda t: t[0])
        return [(entry, output) for _, entry, output in resolved]

    def _has_multi_selected_sanitized_outputs(self) -> bool:
        return len(self._selected_sanitized_outputs()) > 1

    def _update_sanitized_action_state(self) -> None:
        delete_button = getattr(self, "honey_delete_sanitized_button", None)
        compare_button = getattr(self, "honey_compare_parent_button", None)
        reveal_button = getattr(self, "honey_reveal_button", None)
        run_button = getattr(self, "honey_run_sanitized_button", None)
        compare_logs_button = getattr(self, "honey_compare_button", None)

        selections = self._selected_sanitized_outputs()
        multi = len(selections) > 1
        single = len(selections) == 1

        busy = self._has_active_sanitization() or bool(self._current_run_thread and self._current_run_thread.isRunning())

        selected_entry: RunEntry | None = selections[0][0] if single else None
        selected_output: SanitizedBinaryOutput | None = selections[0][1] if single else None

        can_delete = any(bool(out.output_path) for _, out in selections) and not busy
        can_execute = False
        if selections and not busy:
            for _, out in selections:
                if out.output_path and Path(out.output_path).exists():
                    can_execute = True
                    break

        if delete_button is not None:
            delete_button.setEnabled(bool(selections) and can_delete)
        if run_button is not None:
            run_button.setEnabled(bool(selections) and can_execute)

        if multi:
            if compare_button is not None:
                compare_button.setEnabled(False)
            if reveal_button is not None:
                reveal_button.setEnabled(False)
            if compare_logs_button is not None:
                compare_logs_button.setEnabled(False)
            return

        if compare_button is not None:
            compare_button.setEnabled(self._can_compare_parent_preview(selected_entry, selected_output) and not busy)
        if reveal_button is not None:
            reveal_button.setEnabled(bool(selected_output and selected_output.output_path and Path(selected_output.output_path).exists()) and not busy)
        if compare_logs_button is not None:
            entry = self._current_honey_entry()
            compare_ready = self._resolve_compare_pair(entry) is not None
            compare_logs_button.setEnabled(bool(entry and compare_ready) and not busy)

    def _handle_sanitized_output_item_changed(self, item: QTreeWidgetItem, column: int) -> None:
        if item is None or column != 11:
            return
        payload = item.data(0, Qt.UserRole)
        if not isinstance(payload, dict):
            return
        entry_id = payload.get("entry_id")
        output_id = payload.get("output_id")
        if not entry_id or not output_id:
            return
        entry = self._entry_by_id(str(entry_id))
        if entry is None:
            return
        state = item.checkState(11)
        if state == Qt.Checked:
            works: bool | None = True
            item.setText(11, "")
            item.setToolTip(11, "Marked as working")
        elif state == Qt.Unchecked:
            works = False
            item.setText(11, "")
            item.setToolTip(11, "Marked as not working")
        else:
            works = None
            item.setText(11, "—")
            item.setToolTip(11, "Not yet tested")

        updated = False
        outputs = list(getattr(entry, "sanitized_outputs", None) or [])
        for output in outputs:
            if getattr(output, "output_id", None) == output_id:
                output.works = works
                updated = True
                break
        if updated:
            self._persist_current_history()

    def _can_compare_parent_preview(self, entry: RunEntry | None, output: SanitizedBinaryOutput | None) -> bool:
        if entry is None or output is None:
            return False
        sanitized_path = output.output_path
        parent_path = entry.binary_path
        log_path = entry.log_path
        if not sanitized_path or not parent_path or not log_path:
            return False
        try:
            sanitized_exists = Path(sanitized_path).exists()
        except OSError:
            sanitized_exists = False
        try:
            parent_exists = Path(parent_path).exists()
        except OSError:
            parent_exists = False
        try:
            log_exists = Path(log_path).exists()
        except OSError:
            log_exists = False
        return sanitized_exists and parent_exists and log_exists

    def _entry_by_id(self, entry_id: str | None) -> RunEntry | None:
        if not entry_id:
            return None
        return next((entry for entry in self.run_entries if entry.entry_id == entry_id), None)

    def _entry_field(self, entry: RunEntry | dict | None, attr: str, default=None):
        if entry is None:
            return default
        if hasattr(entry, attr):
            return getattr(entry, attr)
        if isinstance(entry, dict):
            return entry.get(attr, default)
        return default

    def _entry_segments(self, entry: RunEntry | None) -> list[tuple[int, int]]:
        if entry is None:
            return []
        if entry.prepared_segments:
            return list(entry.prepared_segments)
        if entry.is_sanitized_run and entry.parent_entry_id:
            parent = self._entry_by_id(entry.parent_entry_id)
            if parent and parent.prepared_segments:
                return list(parent.prepared_segments)
        return []

    def _entry_trace_bounds(self, entry: RunEntry | None) -> tuple[int, int] | None:
        segments = self._entry_segments(entry)
        if not segments:
            return None
        start = min(segment[0] for segment in segments)
        end = max(segment[1] for segment in segments)
        return start, end

    def _entry_effective_offset(self, entry: RunEntry | None) -> int:
        if not entry:
            return 0
        if entry.binary_offset:
            return int(entry.binary_offset)
        if entry.is_sanitized_run and entry.parent_entry_id:
            parent = self._entry_by_id(entry.parent_entry_id)
            if parent and parent.binary_offset:
                return int(parent.binary_offset)
        return 0

    def _entry_binary_bounds(self, entry: RunEntry | None) -> tuple[int, int] | None:
        bounds = self._entry_trace_bounds(entry)
        if not bounds:
            return None
        offset = self._entry_effective_offset(entry)
        if not offset:
            return bounds
        start, end = bounds
        return start + offset, end + offset

    def _entry_trace_address_count(self, entry: RunEntry | None) -> int:
        if entry is None:
            return 0
        count = int(getattr(entry, "trace_address_count", 0) or 0)
        if count:
            return count
        if entry.is_sanitized_run and entry.parent_entry_id:
            parent = self._entry_by_id(entry.parent_entry_id)
            parent_count = self._entry_trace_address_count(parent)
            if parent_count and not getattr(entry, "trace_address_count", 0):
                entry.trace_address_count = parent_count
                self._counts_dirty = True
            return parent_count
        log_path = Path(entry.log_path) if entry.log_path else None
        if log_path and log_path.exists():
            try:
                report = collect_executed_addresses(log_path)
            except Exception:
                return 0
            count = len(report.addresses)
            entry.trace_address_count = count
            self._counts_dirty = True
            return count
        return 0

    def _entry_binary_instruction_count(self, entry: RunEntry | None) -> int:
        if entry is None:
            return 0
        count = int(getattr(entry, "binary_instruction_count", 0) or 0)
        if count:
            return count
        if entry.is_sanitized_run and entry.parent_entry_id:
            parent = self._entry_by_id(entry.parent_entry_id)
            parent_count = self._entry_binary_instruction_count(parent)
            if parent_count and not getattr(entry, "binary_instruction_count", 0):
                entry.binary_instruction_count = parent_count
                self._counts_dirty = True
            return parent_count
        binary_path = Path(entry.binary_path) if entry.binary_path else None
        if binary_path and binary_path.exists():
            count = self._estimate_binary_instruction_count(binary_path)
            if count:
                entry.binary_instruction_count = count
                self._counts_dirty = True
            return count
        return 0

    def _instruction_count_values(self, entry: RunEntry | None) -> tuple[int, int]:
        return (
            self._entry_binary_instruction_count(entry),
            self._entry_trace_address_count(entry),
        )

    def _instruction_count_texts(self, entry: RunEntry | None) -> tuple[str, str]:
        binary_count, trace_count = self._instruction_count_values(entry)
        binary_text = f"{binary_count:,}" if binary_count else "—"
        trace_text = f"{trace_count:,}" if trace_count else "—"
        return binary_text, trace_text

    def _format_instruction_counts(self, entry: RunEntry | None) -> str:
        binary_count, trace_count = self._instruction_count_values(entry)
        if not binary_count and not trace_count:
            return "—"
        if binary_count and trace_count:
            return f"Binary: {binary_count:,} | Trace: {trace_count:,}"
        if binary_count:
            return f"Binary: {binary_count:,}"
        return f"Trace: {trace_count:,}"

    def _sanitized_count_values(self, entry: RunEntry | None, *, use_parent_for_sanitized: bool = False) -> tuple[int, int]:
        if entry is None:
            return (0, 0)
        source = entry
        if use_parent_for_sanitized and entry.is_sanitized_run and entry.parent_entry_id:
            parent = self._entry_by_id(entry.parent_entry_id)
            if parent:
                source = parent
        nop_count = int(getattr(source, "sanitized_nopped_instructions", 0) or 0)
        preserved = int(getattr(source, "sanitized_preserved_instructions", 0) or 0)
        return nop_count, preserved

    def _format_original_instruction_breakdown(self, entry: RunEntry | None) -> tuple[str, str]:
        nop_count, other_count = self._entry_original_instruction_breakdown(entry)
        nop_text = f"{nop_count:,}" if nop_count else "—"
        other_text = f"{other_count:,}" if other_count else "—"
        return nop_text, other_text

    def _format_sanitized_breakdown(self, entry: RunEntry | None, *, use_parent: bool = False) -> tuple[str, str]:
        nop_count, preserved = self._sanitized_count_values(entry, use_parent_for_sanitized=use_parent)
        nop_text = f"{nop_count:,}" if nop_count else "—"
        other_text = f"{preserved:,}" if preserved else "—"
        return nop_text, other_text

    def _entry_original_instruction_breakdown(self, entry: RunEntry | None) -> tuple[int, int]:
        if entry is None:
            return (0, 0)
        base = entry
        if base.is_sanitized_run and base.parent_entry_id:
            parent = self._entry_by_id(base.parent_entry_id)
            if parent:
                base = parent
        binary_path = Path(base.binary_path) if base.binary_path else None
        if not binary_path:
            return (0, 0)
        stats = self._binary_instruction_stats(binary_path)
        if stats is None:
            return (0, 0)
        return stats.nop, stats.other

    def _binary_instruction_stats(self, binary_path: Path) -> BinaryInstructionStats | None:
        try:
            cache_key = str(binary_path.resolve())
        except Exception:
            cache_key = str(binary_path)
        cached = self._binary_instruction_breakdown_cache.get(cache_key)
        if cached is not None:
            return cached
        if not binary_path.exists():
            stats = BinaryInstructionStats(0, 0, 0)
            self._binary_instruction_breakdown_cache[cache_key] = stats
            self._binary_instruction_count_cache[cache_key] = 0
            return stats
        try:
            binary = lief.parse(str(binary_path))
        except Exception:
            stats = BinaryInstructionStats(0, 0, 0)
            self._binary_instruction_breakdown_cache[cache_key] = stats
            self._binary_instruction_count_cache[cache_key] = 0
            return stats
        sanitizer = BinarySanitizer()
        try:
            arch, mode, _ = sanitizer._capstone_config(binary)
        except Exception:
            stats = BinaryInstructionStats(0, 0, 0)
            self._binary_instruction_breakdown_cache[cache_key] = stats
            self._binary_instruction_count_cache[cache_key] = 0
            return stats
        md = capstone.Cs(arch, mode)
        md.detail = False
        total = 0
        nop_count = 0
        try:
            for section in sanitizer._executable_sections(binary):
                data = bytes(section.content)
                if not data:
                    continue
                start = section.virtual_address
                try:
                    for insn in md.disasm(data, start):
                        total += 1
                        if (insn.mnemonic or "").lower() == "nop":
                            nop_count += 1
                except Exception:
                    continue
        except Exception:
            total = total
        other_count = max(total - nop_count, 0)
        stats = BinaryInstructionStats(total, nop_count, other_count)
        self._binary_instruction_breakdown_cache[cache_key] = stats
        self._binary_instruction_count_cache[cache_key] = total
        return stats

    def _estimate_binary_instruction_count(self, binary_path: Path) -> int:
        stats = self._binary_instruction_stats(binary_path)
        return stats.total if stats else 0

    @staticmethod
    def _format_address_range(bounds: tuple[int, int] | None) -> str:
        if not bounds:
            return "—"
        start, end = bounds
        if start == end:
            return f"0x{start:x}"
        return f"0x{start:x} – 0x{end:x}"

    def _entry_is_processed(self, entry: RunEntry | None) -> bool:
        return bool(self._entry_segments(entry))

    def _log_indicator_for_entry(self, entry: RunEntry) -> LogIndicator:
        segments = self._entry_segments(entry)
        if segments:
            tip = f"Processed for HoneyProc with {len(segments)} segment(s)."
            return LogIndicator("#2e7d32", tip, "processed")
        log_path = Path(entry.log_path) if entry.log_path else None
        if log_path is None:
            return LogIndicator("#c62828", "No log path recorded for this run.", "error")
        if not log_path.exists():
            return LogIndicator("#c62828", f"Log missing on disk: {log_path}", "error")
        return LogIndicator("#fbc02d", "Not processed yet. Use 'Prepare for HoneyProc'.", "pending")

    def _status_icon_for_color(self, color: str) -> QIcon:
        icon = self._status_icon_cache.get(color)
        if icon is not None:
            return icon
        pixmap = QPixmap(14, 14)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(QColor(color))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(2, 2, 10, 10)
        painter.end()
        icon = QIcon(pixmap)
        self._status_icon_cache[color] = icon
        return icon

    def _apply_log_item_indicator(self, item: QListWidgetItem, entry: RunEntry) -> None:
        indicator = self._log_indicator_for_entry(entry)
        item.setIcon(self._status_icon_for_color(indicator.color))
        item.setToolTip(indicator.tooltip)
        item.setData(Qt.UserRole + 1, indicator.state)

    def _current_log_item(self) -> QListWidgetItem | None:
        widget = getattr(self, "logs_list", None)
        if widget is None:
            return None
        return widget.currentItem()

    def _sync_log_lists_to_entry(self, entry_id: str | None) -> None:
        widget = getattr(self, "logs_list", None)
        if widget is None:
            return
        self._sync_selection_to_entry(widget, entry_id)

    def _entry_prepared(self, entry: RunEntry | dict | None) -> bool:
        segments = self._entry_field(entry, "prepared_segments")
        return bool(segments)

    def _entry_is_honey_ready(self, entry: RunEntry | None) -> bool:
        if not entry:
            return False
        if entry.is_sanitized_run:
            return True
        return self._entry_prepared(entry)

    def _preview_cache_key(
        self,
        entry: RunEntry,
        *,
        processed: bool,
        segments: list[tuple[int, int]],
        path: Path,
    ) -> tuple[object, ...]:
        try:
            stat_info = path.stat()
            mtime = int(getattr(stat_info, "st_mtime_ns", int(stat_info.st_mtime * 1_000_000_000)))
        except OSError:
            mtime = 0
        segment_fingerprint: tuple[tuple[int, int], ...]
        if processed:
            segment_fingerprint = tuple(segments)
        else:
            segment_fingerprint = tuple()
        return (entry.entry_id, processed, segment_fingerprint, mtime)

    def _apply_cached_preview(self, cache_entry: dict[str, object]) -> None:
        lines = list(cache_entry.get("lines", []))
        truncated = bool(cache_entry.get("truncated", False))
        processed = bool(cache_entry.get("processed", False))
        segments = int(cache_entry.get("segments", 0) or 0)
        path = cache_entry.get("path")
        self._preview_live_lines = list(lines)
        self._cached_log_lines = list(lines)
        self._cached_log_truncated = truncated
        self._cached_preview_processed = processed
        self._cached_preview_segment_count = segments
        self._preview_context = None
        self._preview_progress = {}
        self._preview_view_has_content = True
        if hasattr(self, "log_preview"):
            self.log_preview.setPlainText("\n".join(lines))
        actual_path = path if isinstance(path, Path) else None
        self._update_log_preview_status(
            truncated,
            actual_path,
            len(lines),
            processed=processed,
            segments=segments,
        )

    def _cancel_active_preview_job(self) -> None:
        job_id = self._current_preview_job_id
        if job_id is None:
            return
        job = self._preview_jobs.get(job_id)
        if not job:
            self._current_preview_job_id = None
            self._current_preview_key = None
            self._preview_context = None
            self._preview_progress = {}
            return
        worker = job.get("worker")
        self._current_preview_job_id = None
        self._current_preview_key = None
        self._preview_context = None
        self._preview_progress = {}
        if isinstance(worker, LogPreviewWorker):
            worker.cancel()
        self._close_preview_progress_dialog(force=True)

    def _cancel_preview_job(self, job_id: int) -> None:
        job = self._preview_jobs.get(job_id)
        if not job:
            return
        worker = job.get("worker")
        if isinstance(worker, LogPreviewWorker):
            worker.cancel()

    def _present_busy_dialog(self, dialog: QProgressDialog) -> None:
        dialog.raise_()
        dialog.activateWindow()
        QApplication.processEvents(QEventLoop.AllEvents, 50)

    def _show_preview_progress_dialog(self, job_id: int, path: Path, *, mode: str) -> None:
        self._close_preview_progress_dialog(force=True)
        dialog = BusyProgressDialog("Loading instruction trace...", "Cancel", 0, 0, self)
        dialog.setWindowTitle("Loading Log Preview")
        dialog.setWindowModality(Qt.ApplicationModal)
        dialog.setMinimumDuration(0)
        dialog.setAutoClose(False)
        dialog.setAutoReset(False)
        if mode == "segments":
            dialog.setLabelText(f"Collecting segment previews from {path.name}...")
        else:
            dialog.setLabelText(f"Streaming instruction log from {path.name}...")
        dialog.resize(560, 200)
        dialog.start_pulsing()

        def _handle_cancel() -> None:
            if self._preview_progress_dialog_job != job_id:
                return
            self._cancel_preview_job(job_id)

        dialog.canceled.connect(_handle_cancel)
        dialog.show()
        self._present_busy_dialog(dialog)
        self._preview_progress_dialog = dialog
        self._preview_progress_dialog_job = job_id
        self._preview_progress_dialog_shown_at = time.monotonic()
        self._preview_progress_dialog_pending_close = False

    def _update_preview_progress_dialog_state(
        self,
        message: str,
        *,
        value: int | None = None,
        total: int | None = None,
    ) -> None:
        dialog = self._preview_progress_dialog
        if dialog is None or self._preview_progress_dialog_job != self._current_preview_job_id:
            return
        total = max(total or 0, 0)
        value = max(value or 0, 0)
        if total > 0:
            dialog.setRange(0, total)
            dialog.setValue(min(value, total))
        else:
            dialog.setRange(0, 0)
        dialog.setLabelText(message)

    def _close_preview_progress_dialog(self, *, force: bool = False) -> None:
        dialog = self._preview_progress_dialog
        if dialog is None:
            return
        if not force and self._preview_progress_dialog_shown_at > 0:
            elapsed = time.monotonic() - self._preview_progress_dialog_shown_at
            remaining = PROGRESS_DIALOG_MIN_VISIBLE_SECONDS - elapsed
            if remaining > 0:
                if not self._preview_progress_dialog_pending_close:
                    self._preview_progress_dialog_pending_close = True
                    delay_ms = max(int(remaining * 1000), 50)
                    job_marker = self._preview_progress_dialog_job
                    QTimer.singleShot(
                        delay_ms,
                        lambda job_id=job_marker: self._complete_preview_dialog_close(job_id),
                    )
                return
        self._preview_progress_dialog_pending_close = False
        dialog.hide()
        dialog.close()
        dialog.deleteLater()
        self._preview_progress_dialog = None
        self._preview_progress_dialog_job = None
        self._preview_progress_dialog_shown_at = 0.0

    def _complete_preview_dialog_close(self, job_id: int | None) -> None:
        if job_id is None or job_id != self._preview_progress_dialog_job:
            self._preview_progress_dialog_pending_close = False
            return
        self._close_preview_progress_dialog(force=True)


    def _cancel_segment_preview_job(self, job_id: int) -> None:
        job = self._segment_preview_jobs.get(job_id)
        if not job:
            return
        worker = job.get("worker")
        if isinstance(worker, SegmentPreviewWorker):
            worker.cancel()

    def _show_segment_preview_dialog(self, job_id: int, path: Path, row: int) -> None:
        self._close_segment_preview_dialog(force=True)
        dialog = BusyProgressDialog("Loading segment preview...", "Cancel", 0, 0, self)
        dialog.setWindowTitle("Loading Segment Preview")
        dialog.setWindowModality(Qt.ApplicationModal)
        dialog.setMinimumDuration(0)
        dialog.setAutoClose(False)
        dialog.setAutoReset(False)
        dialog.setLabelText(f"Loading segment {row + 1} from {path.name}...")
        dialog.resize(520, 180)
        dialog.start_pulsing()

        def _handle_cancel() -> None:
            if self._segment_preview_dialog_job != job_id:
                return
            self._cancel_segment_preview_job(job_id)

        dialog.canceled.connect(_handle_cancel)
        dialog.show()
        self._present_busy_dialog(dialog)
        self._segment_preview_dialog = dialog
        self._segment_preview_dialog_job = job_id
        self._segment_preview_dialog_shown_at = time.monotonic()
        self._segment_preview_dialog_pending_close = False

    def _close_segment_preview_dialog(self, *, force: bool = False) -> None:
        dialog = self._segment_preview_dialog
        if dialog is None:
            return
        if not force and self._segment_preview_dialog_shown_at > 0:
            elapsed = time.monotonic() - self._segment_preview_dialog_shown_at
            remaining = PROGRESS_DIALOG_MIN_VISIBLE_SECONDS - elapsed
            if remaining > 0:
                if not self._segment_preview_dialog_pending_close:
                    self._segment_preview_dialog_pending_close = True
                    delay_ms = max(int(remaining * 1000), 50)
                    job_marker = self._segment_preview_dialog_job
                    QTimer.singleShot(
                        delay_ms,
                        lambda job_id=job_marker: self._complete_segment_dialog_close(job_id),
                    )
                return
        self._segment_preview_dialog_pending_close = False
        dialog.hide()
        dialog.close()
        dialog.deleteLater()
        self._segment_preview_dialog = None
        self._segment_preview_dialog_job = None
        self._segment_preview_dialog_shown_at = 0.0

    def _complete_segment_dialog_close(self, job_id: int | None) -> None:
        if job_id is None or job_id != self._segment_preview_dialog_job:
            self._segment_preview_dialog_pending_close = False
            return
        self._close_segment_preview_dialog(force=True)

    def _cleanup_preview_job(self, job_id: int) -> None:
        job = self._preview_jobs.pop(job_id, None)
        if not job:
            return
        thread = job.get("thread")
        worker = job.get("worker")
        if isinstance(worker, LogPreviewWorker):
            worker.deleteLater()
        if isinstance(thread, QThread):
            thread.quit()
            thread.wait()
            thread.deleteLater()
        if self._current_preview_job_id == job_id:
            self._current_preview_job_id = None
            self._current_preview_key = None
            self._preview_context = None
            self._preview_progress = {}
        if self._preview_progress_dialog_job == job_id:
            self._close_preview_progress_dialog()

    def _update_preview_loading_status(self) -> None:
        label = getattr(self, "log_preview_status", None)
        if label is None:
            return
        context = self._preview_context
        if not context:
            return
        path = context.get("path")
        path_name = path.name if isinstance(path, Path) else "log"
        mode = context.get("mode")
        message: str
        progress_value = 0
        progress_total = 0
        if mode == "segments":
            total = int(context.get("segments", 0) or 0)
            done = int(self._preview_progress.get("segments", 0) or 0)
            suffix = "segment" if total == 1 else "segments"
            message = f"Collecting segment previews ({done}/{total} {suffix}) from {path_name}..."
            progress_value = done
            progress_total = total
        else:
            lines = int(self._preview_progress.get("lines", 0) or 0)
            message = f"Streaming {path_name}: {lines} line(s) buffered..."
            progress_value = lines
            progress_total = 0
        label.setText(message)
        self._update_preview_progress_dialog_state(
            message,
            value=progress_value,
            total=progress_total,
        )

    def _preview_job_id_from_sender(self) -> int | None:
        sender = self.sender()
        if isinstance(sender, LogPreviewWorker) and isinstance(sender.job_id, int):
            return sender.job_id
        if sender is None:
            return None
        for job_id, payload in self._preview_jobs.items():
            if payload.get("worker") is sender:
                return job_id
        return None

    @Slot(object)
    def _on_preview_chunk(self, payload: object) -> None:
        job_id = self._preview_job_id_from_sender()
        if job_id is None or not isinstance(payload, list):
            return
        self._handle_preview_chunk(job_id, payload)

    @Slot(object)
    def _on_preview_progress(self, payload: object) -> None:
        job_id = self._preview_job_id_from_sender()
        if job_id is None or not isinstance(payload, dict):
            return
        self._handle_preview_progress(job_id, payload)

    @Slot(bool)
    def _on_preview_finished(self, truncated: bool) -> None:
        job_id = self._preview_job_id_from_sender()
        if job_id is None:
            return
        self._handle_preview_finished(job_id, truncated)

    @Slot(str)
    def _on_preview_failed(self, message: str) -> None:
        job_id = self._preview_job_id_from_sender()
        if job_id is None:
            return
        self._handle_preview_failed(job_id, message)

    @Slot()
    def _on_preview_cancelled(self) -> None:
        job_id = self._preview_job_id_from_sender()
        if job_id is None:
            return
        self._handle_preview_cancelled(job_id)

    def _handle_preview_chunk(self, job_id: int, lines: list[str]) -> None:
        if job_id != self._current_preview_job_id:
            return
        if not lines or not hasattr(self, "log_preview"):
            return
        self._preview_live_lines.extend(lines)
        self._cached_log_lines = list(self._preview_live_lines)
        block = "\n".join(lines)
        if not self._preview_view_has_content:
            self.log_preview.setPlainText(block)
            self._preview_view_has_content = True
        else:
            self.log_preview.appendPlainText(block)
        if self._preview_context and self._preview_context.get("mode") != "segments":
            self._preview_progress["lines"] = len(self._preview_live_lines)
            self._update_preview_loading_status()

    def _handle_preview_progress(self, job_id: int, payload: dict | None) -> None:
        if job_id != self._current_preview_job_id or payload is None:
            return
        if not isinstance(payload, dict):
            return
        self._preview_progress.update(payload)
        self._update_preview_loading_status()

    def _finalize_preview_job(
        self,
        job_id: int,
        *,
        truncated: bool,
        success: bool,
        message: str | None = None,
    ) -> None:
        if job_id != self._current_preview_job_id:
            self._cleanup_preview_job(job_id)
            return
        path = None
        if self._preview_context:
            path = self._preview_context.get("path")
        processed = bool(self._preview_context and self._preview_context.get("mode") == "segments")
        segments = int(self._preview_context.get("segments", 0) or 0) if processed else 0
        if success:
            self._cached_log_lines = list(self._preview_live_lines)
            self._cached_log_truncated = truncated
            self._cached_preview_processed = processed
            self._cached_preview_segment_count = segments
            cache_key = self._current_preview_key
            if cache_key is not None:
                self._preview_cache[cache_key] = {
                    "lines": list(self._preview_live_lines),
                    "truncated": truncated,
                    "processed": processed,
                    "segments": segments,
                    "path": path,
                }
            self._update_log_preview_status(
                truncated,
                path if isinstance(path, Path) else None,
                len(self._preview_live_lines),
                processed=processed,
                segments=segments,
            )
        else:
            status = getattr(self, "log_preview_status", None)
            if status is not None and message:
                status.setText(message)
        self._cleanup_preview_job(job_id)

    def _handle_preview_finished(self, job_id: int, truncated: bool) -> None:
        self._finalize_preview_job(job_id, truncated=truncated, success=True)

    def _handle_preview_failed(self, job_id: int, message: str) -> None:
        detail = f"Unable to load instruction log: {message}" if message else "Unable to load instruction log."
        self._finalize_preview_job(job_id, truncated=False, success=False, message=detail)

    def _handle_preview_cancelled(self, job_id: int) -> None:
        if job_id == self._current_preview_job_id:
            status = getattr(self, "log_preview_status", None)
            if status is not None:
                status.setText("Preview cancelled.")
        self._cleanup_preview_job(job_id)

    def _cancel_active_segment_job(self) -> None:
        job_id = self._current_segment_job_id
        if job_id is None:
            return
        job = self._segment_preview_jobs.get(job_id)
        self._current_segment_job_id = None
        self._segment_preview_context = None
        if not job:
            self._close_segment_preview_dialog(force=True)
            return
        self._cancel_segment_preview_job(job_id)
        self._close_segment_preview_dialog(force=True)

    def _cleanup_segment_job(self, job_id: int) -> None:
        job = self._segment_preview_jobs.pop(job_id, None)
        if not job:
            return
        thread = job.get("thread")
        worker = job.get("worker")
        if isinstance(worker, SegmentPreviewWorker):
            worker.deleteLater()
        if isinstance(thread, QThread):
            thread.quit()
            thread.wait()
            thread.deleteLater()
        if self._current_segment_job_id == job_id:
            self._current_segment_job_id = None
            self._segment_preview_context = None
        if self._segment_preview_dialog_job == job_id:
            self._close_segment_preview_dialog()
        self._resume_segment_table_loader()

    def _segment_job_id_from_sender(self) -> int | None:
        sender = self.sender()
        if isinstance(sender, SegmentPreviewWorker) and isinstance(sender.job_id, int):
            return sender.job_id
        if sender is None:
            return None
        for job_id, payload in self._segment_preview_jobs.items():
            if payload.get("worker") is sender:
                return job_id
        return None

    @Slot(object)
    def _on_segment_preview_ready(self, payload: object) -> None:
        job_id = self._segment_job_id_from_sender()
        if job_id is None:
            return
        self._handle_segment_preview_result(job_id, payload)

    @Slot(str)
    def _on_segment_preview_failed(self, message: str) -> None:
        job_id = self._segment_job_id_from_sender()
        if job_id is None:
            return
        self._handle_segment_preview_failed(job_id, message)

    @Slot()
    def _on_segment_preview_cancelled(self) -> None:
        job_id = self._segment_job_id_from_sender()
        if job_id is None:
            return
        self._cleanup_segment_job(job_id)

    def _begin_segment_preview_job(
        self,
        entry: RunEntry,
        path: Path,
        row: int,
        start: int,
        end: int,
        cache_key: tuple[str, int, float],
    ) -> None:
        self._cancel_active_segment_job()
        self._pause_segment_table_loader()
        self._segment_preview_job_counter += 1
        job_id = self._segment_preview_job_counter
        worker = SegmentPreviewWorker(path, start=start, end=end, limit=SEGMENT_EDGE_PREVIEW_LIMIT)
        thread = QThread(self)
        worker.moveToThread(thread)
        worker.job_id = job_id
        connection_type = Qt.ConnectionType.QueuedConnection
        worker.result_ready.connect(self._on_segment_preview_ready, connection_type)
        worker.failed.connect(self._on_segment_preview_failed, connection_type)
        worker.cancelled.connect(self._on_segment_preview_cancelled, connection_type)
        thread.started.connect(worker.run)
        self._segment_preview_jobs[job_id] = {
            "thread": thread,
            "worker": worker,
            "cache_key": cache_key,
            "entry_id": entry.entry_id,
            "row": row,
        }
        self._current_segment_job_id = job_id
        self._segment_preview_context = {
            "entry_id": entry.entry_id,
            "row": row,
            "path": path,
            "start": start,
            "end": end,
            "cache_key": cache_key,
            "job_id": job_id,
        }
        viewer = getattr(self, "log_preview", None)
        status_label = getattr(self, "log_preview_status", None)
        if viewer is not None:
            viewer.clear()
        if status_label is not None:
            status_label.setText(f"Loading segment {row + 1} preview...")
        self._show_segment_preview_dialog(job_id, path, row)
        thread.start()

    def _apply_segment_preview_lines(
        self,
        *,
        entry: RunEntry,
        path: Path,
        row: int,
        start: int,
        end: int,
        lines: list[str],
        total: int,
        truncated: bool,
    ) -> None:
        viewer = getattr(self, "log_preview", None)
        status_label = getattr(self, "log_preview_status", None)
        label = getattr(self, "log_preview_label", None)
        if viewer is None or status_label is None or label is None:
            return
        if not lines:
            viewer.clear()
            status_label.setText(
                f"No instructions matched segment {row + 1} (0x{start:x} - 0x{end:x}) in {path.name}."
            )
            return
        viewer.setPlainText("\n".join(lines))
        label.setText(f"Segment {row + 1}: 0x{start:x} - 0x{end:x}")
        status_bits = []
        if truncated:
            status_bits.append("Preview truncated")
        if total:
            status_bits.append(f"Showing {len(lines)} of {total} instructions")
        status_label.setText("; ".join(status_bits) if status_bits else "Preview ready.")

    def _handle_segment_preview_result(self, job_id: int, payload: object) -> None:
        if job_id != self._current_segment_job_id:
            self._cleanup_segment_job(job_id)
            return
        context = self._segment_preview_context or {}
        if context.get("job_id") != job_id:
            self._cleanup_segment_job(job_id)
            return
        if not isinstance(payload, dict):
            self._cleanup_segment_job(job_id)
            return
        lines = list(payload.get("lines", [])) if isinstance(payload.get("lines"), list) else []
        total = int(payload.get("total", 0) or 0)
        truncated = bool(payload.get("truncated", False))
        start = int(payload.get("start", context.get("start", 0)) or 0)
        end = int(payload.get("end", context.get("end", 0)) or 0)
        entry = self._current_log_entry()
        if entry is None or entry.entry_id != context.get("entry_id"):
            self._cleanup_segment_job(job_id)
            return
        row = context.get("row")
        path = context.get("path")
        cache_key = context.get("cache_key")
        if not isinstance(row, int) or not isinstance(path, Path):
            self._cleanup_segment_job(job_id)
            return
        if cache_key:
            self._segment_preview_cache[cache_key] = {
                "lines": list(lines),
                "total": total,
                "truncated": truncated,
            }
        self._apply_segment_preview_lines(
            entry=entry,
            path=path,
            row=row,
            start=start,
            end=end,
            lines=lines,
            total=total,
            truncated=truncated,
        )
        self._cleanup_segment_job(job_id)

    def _handle_segment_preview_failed(self, job_id: int, message: str | None = None) -> None:
        if job_id == self._current_segment_job_id:
            status = getattr(self, "log_preview_status", None)
            if status is not None:
                detail = message or "Unable to load segment preview."
                status.setText(detail)
        self._cleanup_segment_job(job_id)

    def _begin_preview_loading(
        self,
        entry: RunEntry,
        path: Path,
        segments: list[tuple[int, int]],
        processed: bool,
        cache_key: tuple[object, ...],
    ) -> None:
        self._cancel_active_preview_job()
        self._preview_job_counter += 1
        job_id = self._preview_job_counter
        mode = "segments" if processed else "raw"
        self._preview_context = {"mode": mode, "path": path, "segments": len(segments)}
        self._preview_progress = {"segments": 0} if processed else {"lines": 0}
        self._preview_live_lines = []
        self._preview_view_has_content = False
        self._cached_preview_processed = processed
        self._cached_preview_segment_count = len(segments) if processed else 0
        worker = LogPreviewWorker(
            path,
            mode=mode,
            max_chars=self._log_preview_max_chars,
            segments=segments,
            per_segment_limit=SEGMENT_EDGE_PREVIEW_LIMIT,
        )
        thread = QThread(self)
        worker.moveToThread(thread)
        connection_type = Qt.ConnectionType.QueuedConnection
        worker.job_id = job_id
        thread.started.connect(worker.run)
        worker.chunk_ready.connect(self._on_preview_chunk, connection_type)
        worker.progress.connect(self._on_preview_progress, connection_type)
        worker.finished.connect(self._on_preview_finished, connection_type)
        worker.failed.connect(self._on_preview_failed, connection_type)
        worker.cancelled.connect(self._on_preview_cancelled, connection_type)
        self._preview_jobs[job_id] = {"thread": thread, "worker": worker}
        self._current_preview_job_id = job_id
        self._current_preview_key = cache_key
        self._show_preview_progress_dialog(job_id, path, mode=mode)
        self._update_preview_loading_status()
        thread.start()

    def _update_prepare_button_state(self, entry: RunEntry | None) -> None:
        button = getattr(self, "prepare_honey_button", None)
        if button is None:
            return
        can_prepare = (
            entry is not None
            and not entry.is_sanitized_run
            and not self._entry_prepared(entry)
        )
        button.setEnabled(can_prepare)

    def _current_log_entry(self) -> RunEntry | None:
        item = self._current_log_item()
        return self._entry_from_item(item)

    def _open_log_directory(self, entry: RunEntry | None = None) -> None:
        candidate = entry or self._current_log_entry()
        if not candidate or not candidate.log_path:
            QMessageBox.information(self, "Log unavailable", "Select a log entry with a saved log path.")
            return
        path = Path(candidate.log_path)
        if path.exists():
            target = path if path.is_dir() else path.parent
        else:
            target = path.parent
            if not target.exists():
                QMessageBox.warning(
                    self,
                    "Log missing",
                    f"Expected log at {path}, but it and its parent directory are missing.",
                )
                return
            self._append_console(f"Log file missing, opening parent directory instead: {target}")
        opened = QDesktopServices.openUrl(QUrl.fromLocalFile(str(target)))
        if not opened:
            QMessageBox.warning(self, "Unable to open", "The operating system rejected the request to open the log directory.")

    def _has_active_sanitization(self) -> bool:
        thread = self._current_sanitize_thread
        return thread is not None and thread.isRunning()

    def _find_sanitized_child(self, entry: RunEntry | None) -> RunEntry | None:
        if not entry:
            return None
        sanitized = [candidate for candidate in self.run_entries if candidate.is_sanitized_run and candidate.parent_entry_id == entry.entry_id]
        if not sanitized:
            return None
        sanitized.sort(key=lambda run: run.timestamp)
        return sanitized[-1]

    def _sanitized_binary_ready(self, entry: RunEntry | None = None) -> bool:
        if entry is None:
            entry = self._current_honey_entry()
        if not entry or not entry.sanitized_binary_path:
            return False
        return Path(entry.sanitized_binary_path).exists()

    def _resolve_compare_pair(self, entry: RunEntry | None) -> tuple[RunEntry, RunEntry] | None:
        if not entry:
            return None
        if entry.is_sanitized_run:
            original = self._entry_by_id(entry.parent_entry_id)
            sanitized = entry
        else:
            sanitized = self._find_sanitized_child(entry)
            original = entry
        if not sanitized or not original:
            return None
        sanitized_log = Path(sanitized.log_path) if sanitized.log_path else None
        original_log = Path(original.log_path) if original.log_path else None
        if not sanitized_log or not original_log:
            return None
        if not sanitized_log.exists() or not original_log.exists():
            return None
        return sanitized, original

    def _current_honey_entry(self) -> RunEntry | None:
        return self._entry_from_item(self.honey_list.currentItem())

    def _update_honey_detail(self, entry: RunEntry | None) -> None:
        if not hasattr(self, "honey_sanitized_status"):
            return
        prepared_label = getattr(self, "honey_prepared_status", None)
        # Reset invocation labels by default
        if hasattr(self, "honey_invocation_status"):
            self.honey_invocation_status.setText("")
        if hasattr(self, "honey_parent_invocation_status"):
            self.honey_parent_invocation_status.setText("")
        if not entry:
            self.honey_sanitized_status.setText("Sanitized binary: Select an entry.")
            if hasattr(self, "honey_parent_status"):
                self.honey_parent_status.setText("Parent linkage: Select an entry.")
            if prepared_label is not None:
                prepared_label.setText("Preparation: Select an entry and run 'Prepare for HoneyProc' from the Logs tab.")
            return
        sanitized_path = entry.sanitized_binary_path
        if sanitized_path:
            path_obj = Path(sanitized_path)
            if path_obj.exists():
                self.honey_sanitized_status.setText(f"Sanitized binary ready: {path_obj}")
            else:
                self.honey_sanitized_status.setText(f"Sanitized binary missing on disk: {path_obj}")
        else:
            self.honey_sanitized_status.setText("Sanitized binary: Not generated.")

        if hasattr(self, "honey_parent_status"):
            if entry.is_sanitized_run:
                parent = self._entry_by_id(entry.parent_entry_id)
                if parent:
                    self.honey_parent_status.setText(f"Parent run: {parent.name} ({Path(parent.binary_path).name})")
                    # Show parent invocation details
                    args = " ".join(parent.target_args) if parent.target_args else "(none)"
                    mods = ", ".join(parent.module_filters) if parent.module_filters else "(none)"
                    sudo = "on" if getattr(parent, "use_sudo", False) else "off"
                    pre = parent.pre_run_command or "(none)"
                    if hasattr(self, "honey_parent_invocation_status"):
                        self.honey_parent_invocation_status.setText(
                            f"Parent Invocation — Args: {args} · Modules: {mods} · Sudo: {sudo} · Pre-Run: {pre}"
                        )
                else:
                    self.honey_parent_status.setText("Parent run: Not found in history.")
                    if hasattr(self, "honey_parent_invocation_status"):
                        self.honey_parent_invocation_status.setText("")
            else:
                sanitized_child = self._find_sanitized_child(entry)
                if sanitized_child:
                    self.honey_parent_status.setText(
                        f"Sanitized replay: {sanitized_child.name} ({sanitized_child.log_path or 'no log'})"
                    )
                else:
                    self.honey_parent_status.setText("Sanitized replay: Not generated.")
                if hasattr(self, "honey_parent_invocation_status"):
                    self.honey_parent_invocation_status.setText("")
        if prepared_label is not None:
            if entry.is_sanitized_run:
                prepared_label.setText("Preparation: Inherited from parent entry.")
            elif self._entry_prepared(entry):
                segments = len(entry.prepared_segments or [])
                timestamp = entry.prepared_at.strftime("%Y-%m-%d %H:%M:%S") if entry.prepared_at else "unknown time"
                prepared_label.setText(
                    f"Prepared for HoneyProc with {segments} segment(s) (last run: {timestamp})."
                )
            else:
                prepared_label.setText("Preparation required: Use 'Prepare for HoneyProc' from the Logs tab.")
            self._update_honey_entries_label()

        # Show current entry invocation details
        args = " ".join(entry.target_args) if entry.target_args else "(none)"
        mods = ", ".join(entry.module_filters) if entry.module_filters else "(none)"
        sudo = "on" if getattr(entry, "use_sudo", False) else "off"
        pre = entry.pre_run_command or "(none)"
        if hasattr(self, "honey_invocation_status"):
            self.honey_invocation_status.setText(
                f"Invocation — Args: {args} · Modules: {mods} · Sudo: {sudo} · Pre-Run: {pre}"
            )

    def _detect_revng(self, *, allow_prompt: bool = True) -> tuple[bool, str]:
        self._ensure_revng_wrapper_exists(quiet_if_current=True)
        executable = shutil.which("revng")
        if not executable:
            script_path = self._available_revng_script()
            if script_path and script_path.exists():
                executable = str(script_path)
        if not executable:
            return False, "rev.ng CLI not found on PATH."
        permission_markers = (
            "permission denied",
            "dial unix /var/run/docker.sock",
            "got permission denied",
            "connect: permission denied",
        )
        returncode, stdout, stderr = self._run_command_with_optional_sudo_simple(
            [executable, "--version"],
            prompt="Enter sudo password to run rev.ng:",
            permission_markers=permission_markers,
            timeout=40,
            allow_prompt=allow_prompt,
        )
        output = (stdout or stderr or "").strip()
        if returncode != 0:
            details = output or "no diagnostic output"
            return False, f"rev.ng exited with {returncode}: {details}"
        first_line = output.splitlines()[0] if output else "rev.ng detected"
        return True, f"{first_line} — {executable}"

    def _set_indicator_state(self, indicator: QLabel | None, *, active: bool) -> None:
        if indicator is None:
            return
        color = "#2e7d32" if active else "#b00020"
        indicator.setStyleSheet(f"color: {color}; font-size: 16px;")
        indicator.setToolTip("Ready" if active else "Unavailable")

    def _apply_revng_indicator_state(self) -> None:
        indicator = getattr(self, "revng_status_indicator", None)
        if indicator is None:
            return
        cli_ok = getattr(self, "_revng_cli_available", False)
        cli_msg = getattr(self, "_revng_cli_message", "rev.ng CLI not checked.")
        container_ok = getattr(self, "_revng_container_running", False)
        container_msg = getattr(self, "_revng_container_message", "rev.ng container not checked.")
        if not cli_ok:
            self._set_indicator_state(indicator, active=False)
            message = cli_msg
        elif not container_ok:
            self._set_indicator_state(indicator, active=False)
            message = container_msg
        else:
            self._set_indicator_state(indicator, active=True)
            message = container_msg or "rev.ng container running."
        indicator.setToolTip(message)
        self._revng_status_summary = message
        self._revng_status_detail = (
            f"rev.ng CLI: {cli_msg}\nrev.ng container: {container_msg}"
        )

    def _refresh_revng_status(self, verbose: bool = False, *, allow_prompt: bool = False) -> None:
        available, message = self._detect_revng(allow_prompt=allow_prompt)
        self._revng_cli_available = available
        self._revng_cli_message = message
        if verbose:
            prefix = "rev.ng check" if available else "rev.ng missing"
            self._append_console(f"{prefix}: {message}")
        self._refresh_revng_container_status(verbose=verbose, allow_prompt=allow_prompt)

    def _detect_revng_container(self, *, allow_prompt: bool = True) -> tuple[bool, str]:
        image = self._configured_revng_image()
        command = [
            "docker",
            "ps",
            "--filter",
            f"ancestor={image}",
            "--format",
            "{{.ID}}",
        ]
        permission_markers = (
            "permission denied",
            "operation not permitted",
            "got permission denied",
            "connect: permission denied",
        )
        returncode, stdout, stderr = self._run_command_with_optional_sudo_simple(
            command,
            prompt="Enter sudo password to check the rev.ng container:",
            permission_markers=permission_markers,
            timeout=15,
            allow_prompt=allow_prompt,
        )
        output = (stdout or "").strip()
        if returncode != 0:
            details = output or (stderr or "permission denied").strip() or "no diagnostic output"
            return False, f"docker ps exited with {returncode}: {details}"
        if output:
            return True, f"rev.ng container running ({image})"
        return False, "rev.ng container not running."

    def _refresh_revng_container_status(self, verbose: bool = False, *, allow_prompt: bool = False) -> None:
        running, message = self._detect_revng_container(allow_prompt=allow_prompt)
        self._revng_container_running = running
        self._revng_container_message = message
        self._apply_revng_indicator_state()
        if verbose:
            prefix = "rev.ng container running" if running else "rev.ng container stopped"
            self._append_console(f"{prefix}: {message}")

    def _ensure_revng_cli_available(self) -> bool:
        self._ensure_revng_path_registered()
        available, message = self._detect_revng(allow_prompt=True)
        if available:
            return True
        image = self._configured_revng_image()
        wrapper_path = self._revng_wrapper_path()
        wrapper_exists = wrapper_path.exists()
        wrapper_text = (
            f"confirm the helper script at {wrapper_path}"
            if wrapper_exists
            else f"create a helper script at {wrapper_path}"
        )
        question_text = (
            f"{message}\n\n"
            "rev.ng powers HoneyProc sanitization. HoneyProc can:\n"
            f"  - run 'docker pull {image}' to download/update the container image\n"
            f"  - {wrapper_text}\n\n"
            "Docker may prompt for your sudo password if elevated privileges are required.\n\n"
            "Would you like to run these steps now?"
        )
        choice = QMessageBox.question(
            self,
            "rev.ng CLI required",
            question_text,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        if choice != QMessageBox.Yes:
            QMessageBox.information(self, "rev.ng instructions", _docker_revng_instructions(image))
            self._append_console(f"Sanitization aborted: {message}")
            return False
        pull_ok, pull_msg = self._pull_revng_image()
        wrapper_ok, _, wrapper_msg = self._ensure_revng_wrapper_exists()
        status_lines = [
            f"Docker pull {'succeeded' if pull_ok else 'failed'}: {pull_msg}",
            f"Helper script {'ready' if wrapper_ok else 'not ready'}: {wrapper_msg}",
        ]
        if wrapper_ok:
            status_lines.append("rev.ng helper directory registered on PATH for this session.")
        summary = "\n".join(status_lines)
        if pull_ok and wrapper_ok:
            QMessageBox.information(self, "rev.ng helper prepared", summary)
        else:
            instructions = _docker_revng_instructions(image)
            QMessageBox.warning(self, "rev.ng setup incomplete", summary + "\n\n" + instructions)
        self._refresh_revng_status(verbose=True, allow_prompt=True)
        available, retry_message = self._detect_revng(allow_prompt=True)
        if available:
            self._append_console(f"rev.ng ready: {retry_message}")
            return True
        QMessageBox.critical(
            self,
            "rev.ng unavailable",
            (
                "rev.ng still was not detected after running the setup steps.\n"
                f"Docker reported: {pull_msg}\nHelper: {wrapper_msg}"
            ),
        )
        self._append_console(f"Sanitization aborted: {retry_message}")
        return False

    def _ensure_revng_container_running(self) -> bool:
        container_running, container_message = self._detect_revng_container(allow_prompt=True)
        if container_running:
            return True
        prompt_text = (
            f"{container_message}\n\n"
            "HoneyProc needs the rev.ng Docker container running before sanitization can continue.\n"
            "Start the configured container now?"
        )
        choice = QMessageBox.question(
            self,
            "rev.ng container required",
            prompt_text,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        if choice != QMessageBox.Yes:
            self._append_console("Sanitization aborted: rev.ng container not running.")
            return False
        started, start_message = self._start_revng_container()
        self._refresh_revng_container_status(verbose=True, allow_prompt=True)
        if not started:
            error_text = start_message or "Failed to start the rev.ng container."
            QMessageBox.critical(self, "rev.ng container unavailable", error_text)
            self._append_console(f"Sanitization aborted: {error_text}")
            return False
        follow_up_running, follow_up_message = self._detect_revng_container(allow_prompt=True)
        if not follow_up_running:
            error_text = (
                "rev.ng container did not report as running after the start attempt.\n"
                f"Docker reported: {follow_up_message}"
            )
            QMessageBox.critical(self, "rev.ng container unavailable", error_text)
            self._append_console(error_text)
            return False
        self._append_console(start_message or follow_up_message)
        return True

    def _show_revng_status_popup(self) -> None:
        summary = getattr(self, "_revng_status_summary", "rev.ng status not checked.")
        detail = getattr(
            self,
            "_revng_status_detail",
            "rev.ng CLI and container have not been checked yet.",
        )
        if self._revng_cli_available and self._revng_container_running:
            QMessageBox.information(
                self,
                "rev.ng ready",
                f"{summary}\n\n{detail}",
            )
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("rev.ng unavailable")
        layout = QVBoxLayout(dialog)
        message_view = QPlainTextEdit(dialog)
        message_view.setReadOnly(True)
        message_view.setMinimumHeight(150)
        layout.addWidget(message_view)
        status_label = QLabel("", dialog)
        layout.addWidget(status_label)
        progress_bar = QProgressBar(dialog)
        progress_bar.setRange(0, 0)
        progress_bar.hide()
        layout.addWidget(progress_bar)

        buttons = QDialogButtonBox(QDialogButtonBox.Close, dialog)
        start_button = QPushButton("Run rev.ng", dialog)
        start_button.setAutoDefault(False)
        buttons.addButton(start_button, QDialogButtonBox.ActionRole)
        layout.addWidget(buttons)

        def refresh_labels() -> None:
            latest_summary = getattr(self, "_revng_status_summary", summary)
            latest_detail = getattr(self, "_revng_status_detail", detail)
            message_view.setPlainText(f"{latest_summary}\n\n{latest_detail}")

        def handle_start() -> None:
            start_button.setEnabled(False)
            progress_bar.show()
            status_label.setText("Starting rev.ng container…")
            QApplication.setOverrideCursor(Qt.WaitCursor)
            try:
                started, message = self._start_revng_container()
            finally:
                QApplication.restoreOverrideCursor()
            status_label.setText(message or "Rev.ng container start attempted.")
            status_label.repaint()

            QApplication.setOverrideCursor(Qt.WaitCursor)
            status_label.setText("Refreshing rev.ng status…")
            try:
                self._refresh_revng_status(verbose=True, allow_prompt=True)
            finally:
                QApplication.restoreOverrideCursor()
            refresh_labels()

            ready = self._revng_cli_available and self._revng_container_running
            progress_bar.hide()
            if ready:
                status_label.setText("rev.ng CLI and container are ready.")
                dialog.accept()
                return

            if started:
                status_label.setText(
                    (message or "rev.ng container started.")
                    + " but CLI is still unavailable."
                )
            else:
                status_label.setText(message or "Failed to start rev.ng container.")
            QMessageBox.critical(dialog, "rev.ng", status_label.text())
            start_button.setEnabled(True)

        start_button.clicked.connect(handle_start)
        buttons.rejected.connect(dialog.reject)
        dialog.finished.connect(lambda *_: self._apply_revng_indicator_state())
        refresh_labels()
        dialog.resize(640, 360)
        dialog.exec()

    def _update_honey_buttons(self, *_: object) -> None:
        entry = self._current_honey_entry()
        has_entry = entry is not None
        busy = self._has_active_sanitization()
        enabled = has_entry and not busy
        preview_ready = (
            has_entry
            and entry is not None
            and bool((entry.log_path or "").strip())
            and bool((entry.binary_path or "").strip())
            and not busy
        )
        if hasattr(self, "honey_sanitize_button"):
            self.honey_sanitize_button.setEnabled(enabled)
        if hasattr(self, "honey_preview_button"):
            self.honey_preview_button.setEnabled(preview_ready)
        self._update_sanitized_action_state()

    def _honey_entries_heading(self) -> str:
        entry = self._current_honey_entry()
        candidate: str | None = None
        if entry and entry.binary_path:
            candidate = entry.binary_path
        elif entry and entry.name:
            candidate = entry.name
        elif getattr(self, "selected_binary", None):
            candidate = self.selected_binary
        elif getattr(self, "config", None):
            candidate = (self._project_config().binary_path or "").strip() or None
        if candidate:
            try:
                display = Path(candidate).name or candidate
            except Exception:
                display = candidate
        else:
            display = "HoneyPot"
        return f"HoneyProc entries for {display}"

    def _update_honey_entries_label(self) -> None:
        label = getattr(self, "honey_entries_label", None)
        if label is None:
            return
        label.setText(f"{self._honey_entries_heading()} (prepared runs)")

    def _show_logs_list_context_menu(self, source_list: QListWidget | None, position) -> None:
        if source_list is None:
            return
        item = source_list.itemAt(position)
        if item is not None:
            source_list.setCurrentItem(item)
        entry = self._entry_from_item(item or source_list.currentItem())
        menu = QMenu(self)
        open_dir_action = menu.addAction("Open dir with complete log")
        open_dir_action.setEnabled(entry is not None and bool(entry and entry.log_path))
        action = menu.exec(source_list.viewport().mapToGlobal(position))
        if action == open_dir_action:
            self._open_log_directory(entry)

    def _show_log_preview_context_menu(self, position) -> None:
        if not hasattr(self, "log_preview"):
            return
        entry = self._current_log_entry()
        menu = QMenu(self)
        open_dir_action = menu.addAction("Open dir with complete log")
        open_dir_action.setEnabled(entry is not None and bool(entry and entry.log_path))
        action = menu.exec(self.log_preview.viewport().mapToGlobal(position))
        if action == open_dir_action:
            self._open_log_directory(entry)

    def _handle_logs_selection_change(
        self,
        current: QListWidgetItem | None,
        previous: QListWidgetItem | None,
    ) -> None:
        entry = self._entry_from_item(current)
        self._pending_log_selection = (current, previous)
        if self._log_selection_timer.isActive():
            self._log_selection_timer.stop()
        self._log_selection_timer.start(120)

    def _apply_pending_log_selection(self) -> None:
        payload = self._pending_log_selection
        self._pending_log_selection = None
        if payload is None:
            return
        current, previous = payload
        self.update_log_detail_from_selection(current, previous)
        entry = self._entry_from_item(current)
        entry_id = entry.entry_id if entry else None
        self._sync_selection_to_entry(self.honey_list, entry_id)
        if hasattr(self, "delete_log_button"):
            self.delete_log_button.setEnabled(entry is not None)
        self._update_prepare_button_state(entry)
        self._update_log_preview(entry)

    def _handle_honey_selection_change(self, current: QListWidgetItem | None, _: QListWidgetItem | None) -> None:
        self._update_honey_buttons()
        entry = self._entry_from_item(current)
        entry_id = entry.entry_id if entry else None
        self._sync_log_lists_to_entry(entry_id)
        self._update_honey_detail(entry)
        self._update_honey_entries_label()

    def _refresh_log_preview_only(self) -> None:
        entry = self._current_log_entry()
        if self._cached_log_lines:
            self._display_cached_log_lines()
            self._update_log_preview_status(
                self._cached_log_truncated,
                self._cached_log_path,
                len(self._cached_log_lines),
                processed=self._cached_preview_processed,
                segments=self._cached_preview_segment_count,
            )
            return
        self._update_log_preview(entry)

    def _update_log_preview(self, entry: RunEntry | None) -> None:
        if not hasattr(self, "log_preview"):
            return
        self._cancel_active_preview_job()
        self._cancel_active_segment_job()
        self._preview_live_lines = []
        self._preview_view_has_content = False
        self._preview_context = None
        self._preview_progress = {}
        self._cached_log_lines = []
        self._cached_log_truncated = False
        self._cached_preview_processed = False
        self._cached_preview_segment_count = 0
        if hasattr(self, "log_preview"):
            self.log_preview.clear()
        if hasattr(self, "delete_log_button"):
            self.delete_log_button.setEnabled(entry is not None)
        self._update_prepare_button_state(entry)
        if entry and entry.binary_path:
            binary_name = Path(entry.binary_path).name or entry.binary_path
            self.logs_exec_label.setText(f"Execution Logs for: {binary_name}")
        else:
            self.logs_exec_label.setText("Execution Logs for: None")
        # Update invocation label
        inv_label = getattr(self, "log_invocation_label", None)
        if inv_label is not None:
            if entry:
                args = " ".join(entry.target_args) if entry.target_args else "(none)"
                mods = ", ".join(entry.module_filters) if entry.module_filters else "(none)"
                sudo = "on" if getattr(entry, "use_sudo", False) else "off"
                pre = (entry.pre_run_command or "(none)")
                inv_label.setText(
                    f"Invocation — Args: {args} · Modules: {mods} · Sudo: {sudo} · Pre-Run: {pre}"
                )
            else:
                inv_label.setText("")
        self.log_preview_label.setText("Instruction Trace")
        self._reset_segments_view(entry)
        if not entry or not entry.log_path:
            self._cached_log_entry_id = None
            self._cached_log_path = None
            self._update_log_preview_status(False, None, 0, processed=False)
            return
        path = Path(entry.log_path)
        if not path.exists():
            self._cached_log_entry_id = entry.entry_id
            self._cached_log_path = path
            self._update_log_preview_status(False, path, 0, processed=False)
            return
        segments = self._entry_segments(entry)
        self._cached_log_entry_id = entry.entry_id
        self._cached_log_path = path
        if segments:
            self._cached_preview_processed = True
            self._cached_preview_segment_count = len(segments)
            self._update_log_preview_status(False, path, 0, processed=True, segments=len(segments))
            table = getattr(self, "log_segments_table", None)
            if table is not None and table.rowCount() > 0:
                if (
                    self._active_segment_entry_id != entry.entry_id
                    or self._active_segment_row is None
                    or self._active_segment_row >= len(segments)
                    or self._active_segment_row < 0
                ):
                    table.selectRow(0)
                else:
                    self._load_segment_preview(entry, path, self._active_segment_row)
            else:
                self.log_preview.clear()
            return
        cache_key = self._preview_cache_key(entry, processed=False, segments=segments, path=path)
        if cache_key in self._preview_cache:
            self._apply_cached_preview(self._preview_cache[cache_key])
            return
        self._begin_preview_loading(entry, path, segments, False, cache_key)

    def _stream_log_lines(self, path: Path, max_chars: int) -> tuple[list[str], bool]:
        lines: list[str] = []
        total_chars = 0
        truncated = False
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.rstrip("\n")
                total_chars += len(line) + 1
                lines.append(line)
                if total_chars >= max_chars:
                    truncated = True
                    break
        return lines, truncated

    def _read_log_lines_for_diff(self, path: Path, max_lines: int = 5000) -> tuple[list[str], bool]:
        lines: list[str] = []
        truncated = False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for idx, raw_line in enumerate(handle):
                    if idx >= max_lines:
                        truncated = True
                        break
                    lines.append(raw_line.rstrip("\n"))
        except OSError as exc:
            raise RuntimeError(f"Unable to read log at {path}: {exc}") from exc
        return lines, truncated

    def _display_cached_log_lines(self) -> None:
        viewer = getattr(self, "log_preview", None)
        if viewer is None:
            return
        content = "\n".join(self._cached_log_lines)
        viewer.setPlainText(content)

    def _update_log_preview_status(
        self,
        truncated: bool,
        path: Path | None,
        line_count: int,
        *,
        processed: bool = False,
        segments: int = 0,
    ) -> None:
        if not hasattr(self, "log_preview_status"):
            return
        if path is None:
            self.log_preview_status.setText("Select an entry to view its instruction trace.")
            return
        if not path.exists():
            self.log_preview_status.setText(f"Instruction log not found: {path}")
            return
        if processed and segments:
            suffix = "segment" if segments == 1 else "segments"
            self.log_preview_status.setText(
                f"{segments} {suffix} available in {path.name}. Click 'Show Segments' to load them and preview the boundaries."
            )
            return
        if truncated:
            approx_kb = max(self._log_preview_max_chars // 1024, 1)
            self.log_preview_status.setText(
                f"Showing first {line_count} lines (~{approx_kb} KB). Preview truncated for performance."
            )
        else:
            if line_count == 0:
                self.log_preview_status.setText("Log file empty.")
            else:
                self.log_preview_status.setText(f"Showing {line_count} lines from {path.name}.")

    def _reset_segments_view(self, entry: RunEntry | None) -> None:
        table = getattr(self, "log_segments_table", None)
        label = getattr(self, "log_segments_label", None)
        button = getattr(self, "show_segments_button", None)
        if table is None or label is None:
            return
        self._segments_loaded_entry_id = None
        self._cancel_segment_table_loader()
        current_entry_id = entry.entry_id if entry else None
        if current_entry_id != self._active_segment_entry_id:
            self._active_segment_row = None
            self._active_segment_entry_id = current_entry_id
        self._segment_preview_context = None
        self._segment_selection_updating = True
        try:
            table.setRowCount(0)
            table.clearSelection()
        finally:
            self._segment_selection_updating = False
        table.hide()
        label.hide()
        has_segments = bool(self._entry_segments(entry))
        if isinstance(button, QPushButton):
            button.show()
            button.setEnabled(has_segments)
            button.setText("Show Segments" if has_segments else "No Segments")
            button.setToolTip("" if has_segments else "This log has no prepared segments.")

    def _update_segments_view(self, entry: RunEntry | None) -> None:
        table = getattr(self, "log_segments_table", None)
        label = getattr(self, "log_segments_label", None)
        button = getattr(self, "show_segments_button", None)
        if table is None or label is None:
            return
        segments = self._entry_segments(entry)
        if entry is None or not segments:
            self._reset_segments_view(entry)
            return
        self._segments_loaded_entry_id = None
        self._cancel_segment_table_loader()
        self._close_segment_table_progress_dialog()
        current_entry_id = entry.entry_id
        if current_entry_id != self._active_segment_entry_id:
            self._active_segment_row = None
            self._active_segment_entry_id = current_entry_id
        if isinstance(button, QPushButton):
            button.show()
            button.setEnabled(False)
            button.setText("Loading Segments...")
            button.setToolTip("Populating segment ranges, please wait.")
        self._segment_selection_updating = True
        try:
            table.clearSelection()
        finally:
            self._segment_selection_updating = False
        total_segments = len(segments)
        self._show_segment_table_progress_dialog(total_segments)
        QApplication.processEvents(QEventLoop.AllEvents)
        table.setUpdatesEnabled(False)
        try:
            table.clearContents()
            table.setRowCount(total_segments)
        finally:
            table.setUpdatesEnabled(True)
        label.show()
        table.show()
        self._segment_table_loader = {
            "entry_id": current_entry_id,
            "segments": segments,
            "table": table,
            "label": label,
            "next_row": 0,
            "paused": False,
            "total": total_segments,
        }
        if not self._segment_table_timer.isActive():
            self._segment_table_timer.start()

    def _handle_show_segments_clicked(self) -> None:
        entry = self._current_log_entry()
        if entry is None or not self._entry_segments(entry):
            return
        self._update_segments_view(entry)

    def _cancel_segment_table_loader(self) -> None:
        if self._segment_table_timer.isActive():
            self._segment_table_timer.stop()
        self._close_segment_table_progress_dialog()
        loader = self._segment_table_loader
        if not loader:
            button = getattr(self, "show_segments_button", None)
            if isinstance(button, QPushButton):
                current_entry = self._current_log_entry()
                has_segments = bool(self._entry_segments(current_entry))
                button.show()
                button.setEnabled(has_segments)
                button.setText("Show Segments" if has_segments else "No Segments")
                button.setToolTip("" if has_segments else "This log has no prepared segments.")
            return
        table = loader.get("table")
        if isinstance(table, QTableWidget):
            table.setUpdatesEnabled(True)
        self._segment_table_loader = None
        button = getattr(self, "show_segments_button", None)
        if isinstance(button, QPushButton):
            current_entry = self._current_log_entry()
            has_segments = bool(self._entry_segments(current_entry))
            button.show()
            button.setEnabled(has_segments)
            button.setText("Show Segments" if has_segments else "No Segments")
            button.setToolTip("" if has_segments else "This log has no prepared segments.")

    def _pause_segment_table_loader(self) -> None:
        loader = self._segment_table_loader
        if not loader or loader.get("paused"):
            return
        loader["paused"] = True
        if self._segment_table_timer.isActive():
            self._segment_table_timer.stop()

    def _resume_segment_table_loader(self) -> None:
        loader = self._segment_table_loader
        if not loader or not loader.get("paused"):
            return
        loader["paused"] = False
        segments: list[tuple[int, int]] = loader.get("segments", [])  # type: ignore[assignment]
        next_row = int(loader.get("next_row", 0) or 0)
        if next_row >= len(segments):
            self._finalize_segment_table_loader()
            return
        if not self._segment_table_timer.isActive():
            self._segment_table_timer.start()

    def _show_segment_table_progress_dialog(self, total: int) -> None:
        total = max(int(total or 0), 1)
        dialog = self._segment_table_progress_dialog
        if dialog is None:
            dialog = QProgressDialog(f"Loading segments (0/{total})...", "Cancel", 0, total, self)
            dialog.setWindowTitle("Loading Segments")
            dialog.setWindowModality(Qt.ApplicationModal)
            dialog.setMinimumDuration(0)
            dialog.setAutoClose(False)
            dialog.setAutoReset(False)
            dialog.canceled.connect(self._cancel_segment_table_loader)
            self._segment_table_progress_dialog = dialog
        else:
            dialog.setRange(0, total)
        dialog.setValue(0)
        dialog.setLabelText(f"Loading segments (0/{total})...")
        dialog.show()

    def _update_segment_table_progress(self, processed: int, total: int) -> None:
        dialog = self._segment_table_progress_dialog
        if dialog is None:
            return
        total = max(int(total or 0), 1)
        if dialog.maximum() != total:
            dialog.setRange(0, total)
        dialog.setValue(min(max(int(processed), 0), total))
        dialog.setLabelText(f"Loading segments ({processed}/{total})...")

    def _close_segment_table_progress_dialog(self) -> None:
        dialog = self._segment_table_progress_dialog
        if dialog is None:
            return
        dialog.blockSignals(True)
        dialog.hide()
        dialog.close()
        dialog.deleteLater()
        self._segment_table_progress_dialog = None

    def _process_segment_table_batch(self) -> None:
        loader = self._segment_table_loader
        if not loader:
            if self._segment_table_timer.isActive():
                self._segment_table_timer.stop()
            return
        if loader.get("paused"):
            if self._segment_table_timer.isActive():
                self._segment_table_timer.stop()
            return
        current_entry = self._current_log_entry()
        if current_entry is None or loader.get("entry_id") != current_entry.entry_id:
            self._cancel_segment_table_loader()
            return
        segments: list[tuple[int, int]] = loader.get("segments", [])  # type: ignore[assignment]
        table = loader.get("table")
        if not isinstance(table, QTableWidget):
            self._cancel_segment_table_loader()
            return
        next_row = int(loader.get("next_row", 0) or 0)
        if next_row >= len(segments):
            self._finalize_segment_table_loader()
            return
        max_row = min(next_row + SEGMENT_TABLE_BATCH_SIZE, len(segments))
        table.setUpdatesEnabled(False)
        try:
            while next_row < max_row:
                start, end = segments[next_row]
                index_item = QTableWidgetItem(str(next_row + 1))
                start_item = QTableWidgetItem(f"0x{start:x}")
                end_item = QTableWidgetItem(f"0x{end:x}")
                length_value = max((end - start) + 1, 1)
                length_item = QTableWidgetItem(f"{length_value:,}")
                length_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                table.setItem(next_row, 0, index_item)
                table.setItem(next_row, 1, start_item)
                table.setItem(next_row, 2, end_item)
                table.setItem(next_row, 3, length_item)
                next_row += 1
        finally:
            table.setUpdatesEnabled(True)
        loader["next_row"] = next_row
        total = int(loader.get("total", len(segments)) or len(segments))
        self._update_segment_table_progress(next_row, total)
        if next_row >= len(segments):
            self._finalize_segment_table_loader()

    def _finalize_segment_table_loader(self) -> None:
        loader = self._segment_table_loader
        if not loader:
            return
        if self._segment_table_timer.isActive():
            self._segment_table_timer.stop()
        table = loader.get("table")
        label = loader.get("label")
        button = getattr(self, "show_segments_button", None)
        if isinstance(table, QTableWidget):
            table.setUpdatesEnabled(True)
            table.show()
        if isinstance(label, QLabel):
            label.show()
        entry_id = loader.get("entry_id")
        total = int(loader.get("total", table.rowCount() if isinstance(table, QTableWidget) else 0) or 0)
        if total:
            self._update_segment_table_progress(total, total)
        self._close_segment_table_progress_dialog()
        if isinstance(entry_id, str):
            self._segments_loaded_entry_id = entry_id
        self._segment_table_loader = None
        current_entry = self._current_log_entry()
        if isinstance(button, QPushButton):
            if current_entry and current_entry.entry_id == entry_id:
                button.show()
                button.setEnabled(True)
                button.setText("Reload Segments")
                button.setToolTip("Segments loaded; click to refresh if needed.")
            else:
                has_segments = bool(self._entry_segments(current_entry))
                button.show()
                button.setEnabled(has_segments)
                button.setText("Show Segments" if has_segments else "No Segments")
                button.setToolTip("" if has_segments else "This log has no prepared segments.")
        target_row = self._active_segment_row
        if (
            entry_id == self._active_segment_entry_id
            and target_row is not None
            and isinstance(table, QTableWidget)
            and 0 <= target_row < table.rowCount()
        ):
            self._segment_selection_updating = True
            try:
                table.selectRow(target_row)
            finally:
                self._segment_selection_updating = False

    def _handle_segment_selection_changed(self) -> None:
        if self._segment_selection_updating:
            return
        table = getattr(self, "log_segments_table", None)
        if table is None or table.selectionModel() is None:
            return
        selection = table.selectionModel().selectedRows()
        if not selection:
            self._active_segment_row = None
            self._pending_segment_selection = None
            return
        row = selection[0].row()
        entry = self._current_log_entry()
        if entry is None or not entry.log_path:
            self._active_segment_row = None
            self._pending_segment_selection = None
            return
        self._active_segment_entry_id = entry.entry_id
        self._active_segment_row = row
        path = Path(entry.log_path)
        self._pending_segment_selection = (entry, path, row)
        if self._segment_selection_timer.isActive():
            self._segment_selection_timer.stop()
        self._segment_selection_timer.start(100)

    def _apply_pending_segment_selection(self) -> None:
        payload = self._pending_segment_selection
        self._pending_segment_selection = None
        if not payload:
            return
        entry, path, row = payload
        current = self._current_log_entry()
        if current is None or current.entry_id != entry.entry_id:
            return
        self._active_segment_entry_id = entry.entry_id
        self._active_segment_row = row
        self._load_segment_preview(entry, path, row)

    def _segment_preview_cache_key(self, entry: RunEntry, row: int, path: Path) -> tuple[str, int, float]:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = 0.0
        return (entry.entry_id, row, mtime)

    def _load_segment_preview(self, entry: RunEntry, path: Path, row: int) -> None:
        viewer = getattr(self, "log_preview", None)
        status_label = getattr(self, "log_preview_status", None)
        label = getattr(self, "log_preview_label", None)
        if viewer is None or status_label is None or label is None:
            return
        if not path.exists():
            viewer.clear()
            status_label.setText(f"Instruction log not found: {path}")
            return
        segments = self._entry_segments(entry)
        if not segments or row < 0 or row >= len(segments):
            viewer.clear()
            status_label.setText("Select a segment to view its instructions.")
            return
        start, end = segments[row]
        label.setText(f"Segment {row + 1}: 0x{start:x} - 0x{end:x}")
        cache_key = self._segment_preview_cache_key(entry, row, path)
        cache_entry = self._segment_preview_cache.get(cache_key)
        if cache_entry:
            lines = list(cache_entry.get("lines", []))
            total = int(cache_entry.get("total", 0) or 0)
            truncated = bool(cache_entry.get("truncated", False))
            self._apply_segment_preview_lines(
                entry=entry,
                path=path,
                row=row,
                start=start,
                end=end,
                lines=lines,
                total=total,
                truncated=truncated,
            )
            return
        self._begin_segment_preview_job(entry, path, row, start, end, cache_key)

    def _cancel_sanitization_preview(self) -> None:
        if self._sanitization_preview_worker:
            self._sanitization_preview_worker.cancel()

    def _cleanup_sanitization_preview_worker(self, *, wait: bool = True, close_dialog: bool = True) -> None:
        # Ensure dialog/thread cleanup always runs on the GUI thread to avoid Qt warnings
        if QThread.currentThread() is not self.thread():
            self._gui_invoker.invoke.emit(
                lambda wait_flag=wait, close_flag=close_dialog: self._cleanup_sanitization_preview_worker(
                    wait=wait_flag, close_dialog=close_flag
                )
            )
            return
        dialog = self._sanitization_preview_dialog
        if close_dialog and dialog is not None:
            dialog.blockSignals(True)
            dialog.hide()
            dialog.close()
            dialog.deleteLater()
            self._sanitization_preview_dialog = None
        thread = self._sanitization_preview_thread
        worker = self._sanitization_preview_worker
        if worker is not None:
            worker.deleteLater()
        if thread is not None:
            if thread.isRunning() and thread is not QThread.currentThread():
                thread.requestInterruption()
                thread.quit()
                if wait:
                    thread.wait()
            thread.deleteLater()
        self._sanitization_preview_thread = None
        self._sanitization_preview_worker = None

    def _cancel_parent_comparison_preview(self) -> None:
        if self._parent_comparison_worker:
            self._parent_comparison_worker.cancel()

    def _cleanup_parent_comparison_worker(self, *, wait: bool = True, close_dialog: bool = True) -> None:
        if QThread.currentThread() is not self.thread():
            self._gui_invoker.invoke.emit(
                lambda wait_flag=wait, close_flag=close_dialog: self._cleanup_parent_comparison_worker(
                    wait=wait_flag,
                    close_dialog=close_flag,
                )
            )
            return
        dialog = self._parent_comparison_dialog
        if dialog is not None and close_dialog:
            dialog.blockSignals(True)
            dialog.hide()
            dialog.close()
            dialog.deleteLater()
            self._parent_comparison_dialog = None
        thread = self._parent_comparison_thread
        worker = self._parent_comparison_worker
        if worker is not None:
            worker.deleteLater()
        if thread is not None:
            if thread.isRunning() and thread is not QThread.currentThread():
                thread.requestInterruption()
                thread.quit()
                if wait:
                    thread.wait()
            thread.deleteLater()
        self._parent_comparison_thread = None
        self._parent_comparison_worker = None

    def _cancel_trace_comparison_preview(self) -> None:
        if self._trace_comparison_worker:
            self._trace_comparison_worker.cancel()

    def _cleanup_trace_comparison_worker(self, *, wait: bool = True, close_dialog: bool = True) -> None:
        if QThread.currentThread() is not self.thread():
            self._gui_invoker.invoke.emit(
                lambda wait_flag=wait, close_flag=close_dialog: self._cleanup_trace_comparison_worker(
                    wait=wait_flag,
                    close_dialog=close_flag,
                )
            )
            return
        dialog = self._trace_comparison_dialog
        if dialog is not None and close_dialog:
            dialog.blockSignals(True)
            dialog.hide()
            dialog.close()
            dialog.deleteLater()
            self._trace_comparison_dialog = None
        thread = self._trace_comparison_thread
        worker = self._trace_comparison_worker
        if worker is not None:
            worker.deleteLater()
        if thread is not None:
            if thread.isRunning() and thread is not QThread.currentThread():
                thread.requestInterruption()
                thread.quit()
                if wait:
                    thread.wait()
            thread.deleteLater()
        self._trace_comparison_thread = None
        self._trace_comparison_worker = None

    def _sync_selection_to_entry(self, target_list: QAbstractItemView, entry_id: str | None) -> None:
        if self._selection_syncing:
            return
        self._selection_syncing = True
        try:
            if not entry_id:
                target_list.clearSelection()
                return
            if isinstance(target_list, QListWidget):
                for index in range(target_list.count()):
                    item = target_list.item(index)
                    if item.data(Qt.UserRole) == entry_id:
                        target_list.setCurrentItem(item)
                        break
            elif isinstance(target_list, QTreeWidget):
                def _find_item(item: QTreeWidgetItem | None) -> QTreeWidgetItem | None:
                    if item is None:
                        return None
                    if item.data(0, Qt.UserRole) == entry_id:
                        return item
                    for child_index in range(item.childCount()):
                        found = _find_item(item.child(child_index))
                        if found is not None:
                            return found
                    return None

                for index in range(target_list.topLevelItemCount()):
                    item = target_list.topLevelItem(index)
                    found_item = _find_item(item)
                    if found_item is not None:
                        target_list.setCurrentItem(found_item)
                        break
        finally:
            self._selection_syncing = False

    def preview_sanitization(self) -> None:
        if self._has_active_sanitization():
            QMessageBox.information(
                self,
                "Sanitization in progress",
                "Please wait for the current sanitization job to finish before previewing instructions.",
            )
            return
        entry = self._current_honey_entry()
        if not entry:
            QMessageBox.information(self, "No entry selected", "Select a HoneyProc entry to preview.")
            return
        if not entry.is_sanitized_run and not self._entry_prepared(entry):
            QMessageBox.information(
                self,
                "Preparation required",
                "Run 'Prepare for HoneyProc' from the Logs tab before previewing this entry.",
            )
            return
        log_path_value = self._entry_field(entry, "log_path")
        if not log_path_value:
            QMessageBox.warning(self, "Missing log", "This entry does not have an instruction log to analyze.")
            return
        log_path = Path(log_path_value)
        if not log_path.exists():
            QMessageBox.warning(
                self,
                "Log not found",
                f"The instruction log could not be found at {log_path}. Re-run the entry to regenerate it.",
            )
            return
        binary_path_value = self._entry_field(entry, "binary_path")
        if not binary_path_value:
            QMessageBox.warning(self, "Missing binary", "This entry is missing its binary path.")
            return
        binary_path = Path(binary_path_value)
        if not binary_path.exists():
            QMessageBox.warning(
                self,
                "Binary not found",
                f"The binary referenced by this entry was not found at {binary_path}.",
            )
            return
        if self._sanitization_preview_thread is not None:
            QMessageBox.information(
                self,
                "Preview already running",
                "Please wait for the current preview to finish before starting another.",
            )
            return

        preview_segments = self._entry_segments(entry)
        progress_dialog = QProgressDialog("Collecting instruction addresses...\nThis may take a while.", "Cancel", 0, 0, self)
        progress_dialog.setWindowTitle("Preparing Preview")
        progress_dialog.setWindowModality(Qt.ApplicationModal)
        progress_dialog.setMinimumDuration(0)
        progress_dialog.setAutoClose(False)
        progress_dialog.setAutoReset(False)
        progress_dialog.setValue(0)
        progress_dialog.setLabelText(
            "Collecting instruction addresses for preview.\nThis may take a while; use Cancel to stop."
        )
        progress_dialog.resize(600, 240)
        progress_dialog.canceled.connect(self._cancel_sanitization_preview)
        progress_dialog.show()
        QApplication.processEvents()

        worker = SanitizationPreviewWorker(
            log_path,
            binary_path,
            address_limit=SANITIZATION_PREVIEW_ADDRESS_LIMIT,
        )
        thread = QThread(self)
        worker.moveToThread(thread)
        self._sanitization_preview_thread = thread
        self._sanitization_preview_worker = worker
        self._sanitization_preview_dialog = progress_dialog

        last_progress_update = 0.0

        def _invoke_on_gui(callback: Callable[[], None]) -> None:
            if QThread.currentThread() is self.thread():
                callback()
            else:
                self._gui_invoker.invoke.emit(callback)

        def _update_progress_dialog(processed: int, total: int) -> None:
            dialog = self._sanitization_preview_dialog
            if dialog is None:
                return
            if total <= 0:
                dialog.setRange(0, 0)
                dialog.setLabelText(
                    "Collecting instruction addresses for preview.\nThis may take a while; use Cancel to stop."
                )
                return
            dialog.setUpdatesEnabled(False)
            try:
                if dialog.maximum() != total:
                    dialog.setRange(0, total)
                dialog.setValue(processed)
                dialog.setLabelText(
                    f"Disassembling preview instructions ({processed}/{total}).\n"
                    "Processing the entire log may take a while; use Cancel to stop."
                )
            finally:
                dialog.setUpdatesEnabled(True)

        def _handle_progress(processed: int, total: int) -> None:
            nonlocal last_progress_update
            now = time.monotonic()
            if processed < total and (now - last_progress_update) < 0.05:
                return
            last_progress_update = now
            _invoke_on_gui(lambda proc=processed, tot=total: _update_progress_dialog(proc, tot))

        def _finalize_preview() -> None:
            self._cleanup_sanitization_preview_worker()

        def _handle_info(message: str) -> None:
            def _run() -> None:
                _finalize_preview()
                QMessageBox.information(self, "Preview unavailable", message)

            _invoke_on_gui(_run)

        def _handle_failed(message: str) -> None:
            def _run() -> None:
                _finalize_preview()
                QMessageBox.critical(self, "Unable to prepare preview", message)

            _invoke_on_gui(_run)

        def _handle_cancelled() -> None:
            def _run() -> None:
                _finalize_preview()
                QMessageBox.information(self, "Preview cancelled", "Instruction preview was cancelled.")

            _invoke_on_gui(_run)

        def _handle_succeeded(payload: object) -> None:
            def _run() -> None:
                _cleanup = lambda close_dialog=True: self._cleanup_sanitization_preview_worker(close_dialog=close_dialog)
                _cleanup(close_dialog=False)
                if not isinstance(payload, dict):
                    QMessageBox.critical(
                        self,
                        "Unable to prepare preview",
                        "Unexpected preview payload format.",
                    )
                    _cleanup(close_dialog=True)
                    return
                combined_rows = list(payload.get("rows", []))
                if not combined_rows:
                    QMessageBox.information(
                        self,
                        "Preview unavailable",
                        "No instructions were returned for preview.",
                    )
                    _cleanup(close_dialog=True)
                    return
                if payload.get("truncated") and payload.get("limit"):
                    limit_value = payload["limit"]
                    QMessageBox.information(
                        self,
                        "Preview truncated",
                        f"Showing the first {limit_value} unique instruction address(es).",
                    )
                entry_name = self._entry_field(entry, "name") or self._entry_field(entry, "label") or "Log Preview"
                label = Path(binary_path).name if binary_path_value else entry_name
                saved_offset = int(getattr(entry, "binary_offset", 0) or 0)
                entry_id_value = entry.entry_id if entry else None
                progress_dialog = self._sanitization_preview_dialog
                total_addresses = int(payload.get("total", len(combined_rows)) or len(combined_rows))
                if progress_dialog is not None:
                    progress_dialog.setCancelButton(None)
                    progress_value = max(total_addresses, 1)
                    progress_dialog.setRange(0, progress_value)
                    progress_dialog.setValue(progress_value)
                    progress_dialog.setLabelText(
                        f"Disassembly complete ({progress_value}/{progress_value}). Finalizing preview..."
                    )
                    QApplication.processEvents()

                def _update_progress(message: str) -> None:
                    dialog_ref = self._sanitization_preview_dialog
                    if dialog_ref is None:
                        return
                    dialog_ref.setRange(0, 0)
                    dialog_ref.setLabelText(message)
                    QApplication.processEvents()

                try:
                    dialog = SanitizationPreviewDialog(
                        self,
                        label,
                        combined_rows,
                        segments=preview_segments,
                        binary_path=binary_path,
                        saved_offset=saved_offset,
                        save_offset_callback=lambda value, entry_id=entry_id_value: self._save_entry_offset(entry_id, value),
                        progress_callback=_update_progress,
                    )
                finally:
                    _cleanup(close_dialog=True)
                dialog.exec()

            _invoke_on_gui(_run)

        worker.progress.connect(_handle_progress, Qt.QueuedConnection)
        worker.info.connect(_handle_info, Qt.QueuedConnection)
        worker.failed.connect(_handle_failed, Qt.QueuedConnection)
        worker.cancelled.connect(_handle_cancelled, Qt.QueuedConnection)
        worker.succeeded.connect(_handle_succeeded, Qt.QueuedConnection)
        thread.started.connect(worker.run)
        thread.start()

    def sanitize_honey_entry(self) -> None:
        if self._has_active_sanitization():
            QMessageBox.information(
                self,
                "Sanitization in progress",
                "Please wait for the current sanitization job to finish before starting another.",
            )
            return
        self._ensure_revng_path_registered()
        revng_available, revng_message = self._detect_revng(allow_prompt=True)
        if not revng_available:
            image = self._configured_revng_image()
            wrapper_path = self._revng_wrapper_path()
            wrapper_exists = wrapper_path.exists()
            wrapper_text = (
                f"confirm the helper script at {wrapper_path}"
                if wrapper_exists
                else f"create a helper script at {wrapper_path}"
            )
            question_text = (
                f"{revng_message}\n\n"
                "rev.ng powers HoneyProc sanitization. HoneyProc can:\n"
                f"  - run 'docker pull {image}' to download/update the container image\n"
                f"  - {wrapper_text}\n\n"
                "Docker may prompt for your sudo password if elevated privileges are required.\n\n"
                "Would you like to run these steps now?"
            )
            choice = QMessageBox.question(
                self,
                "rev.ng CLI required",
                question_text,
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if choice == QMessageBox.Yes:
                pull_ok, pull_msg = self._pull_revng_image()
                wrapper_ok, _, wrapper_msg = self._ensure_revng_wrapper_exists()
                status_lines = [
                    f"Docker pull {'succeeded' if pull_ok else 'failed'}: {pull_msg}",
                    f"Helper script {'ready' if wrapper_ok else 'not ready'}: {wrapper_msg}",
                ]
                if wrapper_ok:
                    status_lines.append("rev.ng helper directory registered on PATH for this session.")
                status_lines.append("Retry sanitization once setup completes.")
                summary = "\n".join(status_lines)
                if pull_ok and wrapper_ok:
                    QMessageBox.information(self, "rev.ng helper prepared", summary)
                else:
                    instructions = _docker_revng_instructions(image)
                    QMessageBox.warning(self, "rev.ng setup incomplete", summary + "\n\n" + instructions)
                self._refresh_revng_status(verbose=True, allow_prompt=True)
            else:
                QMessageBox.information(self, "rev.ng instructions", _docker_revng_instructions(image))
            self._append_console(f"Sanitization aborted: {revng_message}")
            return
        container_running, container_message = self._detect_revng_container(allow_prompt=True)
        if not container_running:
            prompt_text = (
                f"{container_message}\n\n"
                "HoneyProc needs the rev.ng Docker container running before sanitization can continue.\n"
                "Start the configured container now?"
            )
            choice = QMessageBox.question(
                self,
                "rev.ng container required",
                prompt_text,
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if choice != QMessageBox.Yes:
                self._append_console("Sanitization aborted: rev.ng container not running.")
                return
            started, start_message = self._start_revng_container()
            self._refresh_revng_container_status(verbose=True, allow_prompt=True)
            if not started:
                error_text = start_message or "Failed to start the rev.ng container."
                QMessageBox.critical(self, "rev.ng container unavailable", error_text)
                self._append_console(f"Sanitization aborted: {error_text}")
                return
            follow_up_running, follow_up_message = self._detect_revng_container(allow_prompt=True)
            if not follow_up_running:
                error_text = (
                    "rev.ng container did not report as running after the start attempt.\n"
                    f"Docker reported: {follow_up_message}"
                )
                QMessageBox.critical(self, "rev.ng container unavailable", error_text)
                self._append_console(error_text)
                return
            self._append_console(start_message or "rev.ng container started successfully.")
        entry = self._current_honey_entry()
        if not entry:
            QMessageBox.information(self, "No entry selected", "Select a HoneyProc entry to sanitize.")
            return
        if not entry.log_path:
            QMessageBox.warning(self, "Missing log", "This entry does not have an instruction log to analyze.")
            return
        log_path = Path(entry.log_path)
        if not log_path.exists():
            QMessageBox.warning(
                self,
                "Log not found",
                f"The instruction log could not be found at {log_path}. Re-run the entry to regenerate it.",
            )
            return
        if not entry.binary_path:
            QMessageBox.warning(self, "Missing binary", "This entry is missing its binary path.")
            return
        binary_path = Path(entry.binary_path)
        if not binary_path.exists():
            QMessageBox.warning(
                self,
                "Binary not found",
                f"The binary referenced by this entry was not found at {binary_path}.",
            )
            return

        default_output_path = self._sanitized_output_path(entry)
        report = None
        analyze_dialog = self._show_busy_dialog("Analyzing instruction log...", title="Preparing Sanitization")
        try:
            try:
                report = collect_executed_addresses(log_path)
            except Exception as exc:
                QMessageBox.critical(
                    self,
                    "Unable to analyze log",
                    f"Failed to parse instruction log before sanitization:\n{exc}",
                )
                self._append_console(f"Sanitization aborted: {exc}")
                return
        finally:
            analyze_dialog.close()
        if not report or not report.addresses:
            QMessageBox.warning(
                self,
                "No instructions",
                "The selected log does not contain any executed instruction entries.",
            )
            return
        sanity_allowed = bool(report.sampled_instructions)
        settings = self._project_config()
        initial_prefs = {
            "runnable_first": bool(getattr(settings, "sanitize_runnable_first", True)),
            "only_text": bool(getattr(settings, "sanitize_only_text", False)),
            "preserve_trampolines": bool(getattr(settings, "sanitize_preserve_trampolines", True)),
            "protect_dynlinks": bool(getattr(settings, "sanitize_protect_dynlinks", True)),
            "protect_unwind": bool(getattr(settings, "sanitize_protect_unwind", True)),
            "protect_indirect": bool(getattr(settings, "sanitize_protect_indirect", True)),
            "segment_padding": str(getattr(settings, "sanitize_segment_padding", "0x2000")),
            "segment_gap": str(getattr(settings, "sanitize_segment_gap", f"0x{SANITIZE_RUNNABLE_FIRST_SEGMENT_GAP:x}")),
            "icf_window": str(getattr(settings, "sanitize_icf_window", "0x400")),
            "jumptable_window": str(getattr(settings, "sanitize_jumptable_window", "0x800")),
        }
        config_dialog = SanitizeConfigDialog(
            self,
            default_name=default_output_path.name,
            default_permissions=binary_path.stat().st_mode,
            sanity_allowed=sanity_allowed,
            initial=initial_prefs,
        )
        if config_dialog.exec() != QDialog.Accepted:
            self._append_console("Sanitization cancelled before launch.")
            return
        sanitize_options = config_dialog.selected_options()

        if config_dialog.sweep_enabled():
            if self._current_sweep_thread and self._current_sweep_thread.isRunning():
                QMessageBox.information(self, "Sweep in progress", "Please wait for the current sweep to finish.")
                return
            sweep_variants = config_dialog.sweep_variants()
            if not sweep_variants:
                QMessageBox.warning(self, "Invalid sweep", "No sweep values were generated from the provided ranges.")
                return

        settings.sanitize_runnable_first = bool(sanitize_options.runnable_first)
        settings.sanitize_only_text = bool(sanitize_options.only_text_section)
        settings.sanitize_preserve_trampolines = bool(sanitize_options.preserve_trampoline_sections)
        settings.sanitize_protect_dynlinks = bool(sanitize_options.protect_dynlinks)
        settings.sanitize_protect_unwind = bool(sanitize_options.protect_unwind)
        settings.sanitize_protect_indirect = bool(sanitize_options.protect_indirect)
        settings.sanitize_segment_padding = f"0x{int(sanitize_options.segment_padding):x}"
        settings.sanitize_segment_gap = f"0x{int(sanitize_options.segment_gap):x}"
        settings.sanitize_icf_window = f"0x{int(sanitize_options.icf_window):x}"
        settings.sanitize_jumptable_window = f"0x{int(sanitize_options.jumptable_window):x}"
        self.config_manager.save(self.config)
        output_path = default_output_path
        if sanitize_options.output_name:
            output_path = default_output_path.with_name(sanitize_options.output_name)
        self._ensure_directory(output_path)

        if config_dialog.sweep_enabled():
            dialog = SanitizeProgressDialog(self, f"{binary_path.name or entry.name} (Sweep)")
            thread = QThread(self)
            worker = SanitizeSweepWorker(
                entry.entry_id,
                binary_path,
                log_path,
                output_path,
                sanitize_options,
                executed_addresses=report.addresses,
                parsed_rows=report.parsed_rows,
                instruction_samples=report.sampled_instructions,
                binary_offset=int(entry.binary_offset or 0),
                preserve_segments=self._entry_segments(entry),
                sweep_variants=sweep_variants,
            )
            worker.moveToThread(thread)

            worker.progress.connect(dialog.append_output)
            worker.progress.connect(dialog.update_status)
            worker.progress.connect(self._append_console)
            worker.progress_counts.connect(dialog.update_generation_progress)

            def _on_variant(payload: object) -> None:
                if not isinstance(payload, dict):
                    return
                target = self._entry_by_id(payload.get("entry_id"))
                if target is None:
                    return
                result = SanitizationResult(
                    total_instructions=int(payload.get("total_instructions", 0) or 0),
                    preserved_instructions=int(payload.get("preserved_instructions", 0) or 0),
                    nopped_instructions=int(payload.get("nopped_instructions", 0) or 0),
                    output_path=Path(str(payload.get("output_path") or "")),
                )
                opts = sanitize_options._replace(
                    segment_gap=int(payload.get("segment_gap", 0) or 0),
                    segment_padding=int(payload.get("segment_padding", 0) or 0),
                    icf_window=int(payload.get("icf_window", 0) or 0),
                    jumptable_window=int(payload.get("jumptable_window", 0) or 0),
                )
                self._add_sanitized_output(target, result, opts)
                self._refresh_entry_views(target.entry_id)

            def _on_finished(payload: object) -> None:
                dialog.mark_finished("Sweep complete.")
                summary = payload if isinstance(payload, dict) else {}
                QMessageBox.information(
                    self,
                    "Sweep complete",
                    f"Generated {int(summary.get('successes', 0) or 0)} binary(ies); {int(summary.get('failures', 0) or 0)} failed.",
                )
                self._cleanup_sweep_worker()

            worker.variant_succeeded.connect(_on_variant, Qt.QueuedConnection)
            worker.finished.connect(_on_finished, Qt.QueuedConnection)
            thread.finished.connect(self._cleanup_sweep_worker)
            dialog.finished.connect(self._cleanup_sweep_worker)
            thread.started.connect(worker.run)

            self._current_sweep_thread = thread
            self._current_sweep_worker = worker
            self._current_sweep_dialog = dialog

            thread.start()
            dialog.exec()
            return

        dialog = SanitizeProgressDialog(self, binary_path.name or entry.name)
        worker = SanitizeWorker(
            entry.entry_id,
            binary_path,
            log_path,
            output_path,
            sanitize_options,
            executed_addresses=report.addresses,
            parsed_rows=report.parsed_rows,
            instruction_samples=report.sampled_instructions,
            binary_offset=int(entry.binary_offset or 0),
            preserve_segments=self._entry_segments(entry),
            segment_padding=int(sanitize_options.segment_padding),
        )
        thread = QThread(self)
        worker.moveToThread(thread)

        worker.progress.connect(dialog.append_output)
        worker.progress.connect(dialog.update_status)
        worker.progress.connect(self._append_console)
        worker.succeeded.connect(self._handle_sanitize_success)
        worker.failed.connect(self._handle_sanitize_failure)
        thread.finished.connect(self._cleanup_sanitize_worker)
        dialog.finished.connect(self._cleanup_sanitize_worker)
        thread.started.connect(worker.run)

        self._current_sanitize_thread = thread
        self._current_sanitize_worker = worker
        self._current_sanitize_dialog = dialog
        self._current_sanitize_entry_id = entry.entry_id
        self._update_honey_buttons()

        self._append_console(
            f"Starting sanitization for '{entry.name}'. Output will be saved to: {output_path}"
        )
        self._append_console(f"Instruction log source: {log_path}")
        thread.start()
        dialog.exec()
        self._cleanup_sanitize_worker()

    def execute_sanitized_binary(self) -> None:
        if self._current_run_thread and self._current_run_thread.isRunning():
            QMessageBox.information(self, "Run in progress", "Please wait for the current run to finish.")
            return

        selections = self._selected_sanitized_outputs()
        if not selections:
            QMessageBox.information(
                self,
                "No sanitized binary selected",
                "Select a sanitized binary in the list to execute it.",
            )
            return

        if len(selections) > 1:
            self._execute_sanitized_binaries_batch(selections)
            return

        entry, output = selections[0]
        sanitized_path = output.output_path
        if not sanitized_path:
            QMessageBox.information(self, "No sanitized binary", "Generate a sanitized binary before executing it.")
            return
        path_obj = Path(sanitized_path)
        if not path_obj.exists():
            QMessageBox.warning(
                self,
                "Sanitized binary missing",
                f"The sanitized binary was expected at {path_obj}, but it no longer exists.",
            )
            entry.sanitized_binary_path = None
            self._persist_current_history()
            self._refresh_entry_views(entry.entry_id)
            self._update_honey_detail(entry)
            self._update_honey_buttons()
            return

        parent_args: list[str] | None = None
        try:
            parent_args = list(entry.target_args) if entry.target_args else None
        except Exception:
            parent_args = None
        if parent_args is None:
            config_args = (getattr(self._project_config(), "default_target_args", "") or "").strip()
            if config_args:
                import shlex

                try:
                    parent_args = shlex.split(config_args)
                except Exception:
                    parent_args = [config_args]

        parent_filters: list[str] = []
        try:
            parent_filters = list(entry.module_filters or [])
        except Exception:
            parent_filters = []

        parent_sudo = bool(getattr(entry, "use_sudo", False))
        parent_prerun = getattr(entry, "pre_run_command", None)
        if not parent_prerun:
            parent_prerun = (getattr(self._project_config(), "default_pre_run_command", "") or "").strip() or None

        options_dialog = RunSanitizedOptionsDialog(self, default_run_with_sudo=parent_sudo)
        options_dialog.set_invocation_preview(
            args=parent_args,
            module_filters=parent_filters,
            use_sudo=parent_sudo,
            pre_run_command=parent_prerun,
        )
        if options_dialog.exec() != QDialog.Accepted:
            self._append_console("Sanitized execution cancelled before launch.")
            return
        run_options = options_dialog.selected_options()
        if not run_options.run_with_pin:
            QMessageBox.information(
                self,
                "PIN execution required",
                "Sanitized runs currently depend on the PIN tracer. Continuing with PIN instrumentation enabled.",
            )

        default_label = f"{entry.name} (Sanitized)"
        builder = lambda label: self._project_log_filename(label)
        module_dialog = ModuleSelectionDialog(
            self,
            path_obj.name or default_label,
            self._discover_binary_modules(str(path_obj)),
            default_log_label=default_label,
            filename_builder=builder,
            previous_selection=parent_filters,
            default_unique_only=self._last_unique_only,
            default_run_with_sudo=parent_sudo,
            default_pre_run_command=parent_prerun or "",
            invocation_args=parent_args,
            is_sanitized_run=True,
        )
        if module_dialog.exec() != QDialog.Accepted:
            self._append_console("Sanitized execution cancelled before launch.")
            return
        log_label = module_dialog.selected_log_label()
        unique_only = module_dialog.unique_only()
        log_path = str(self._project_log_path(run_label=log_label))

        self._last_unique_only = bool(unique_only)
        self._last_run_with_sudo = bool(parent_sudo)

        self._run_with_progress(
            str(path_obj),
            log_path,
            record_entry=True,
            entry_to_refresh=None,
            dialog_label=log_label,
            run_label=log_label,
            parent_entry_id=entry.entry_id,
            sanitized_binary_path=str(path_obj),
            is_sanitized_run=True,
            module_filters=parent_filters,
            unique_only=unique_only,
            run_with_sudo=parent_sudo,
            metrics_options=run_options,
            pre_run_command=parent_prerun,
            target_args=parent_args,
            original_binary_path=entry.binary_path,
            copy_sanitized_to_original_path=bool(getattr(run_options, "copy_to_original_path", False)),
            assume_works_entry_id=entry.entry_id if getattr(run_options, "assume_works_if_running", False) else None,
            assume_works_output_id=output.output_id if getattr(run_options, "assume_works_if_running", False) else None,
            assume_works_after_ms=int(getattr(run_options, "assume_works_after_ms", 0) or 0)
            if getattr(run_options, "assume_works_if_running", False)
            else None,
        )

    def _execute_sanitized_binaries_batch(self, selections: list[tuple[RunEntry, SanitizedBinaryOutput]]) -> None:
        if self._current_run_thread and self._current_run_thread.isRunning():
            QMessageBox.information(self, "Run in progress", "Please wait for the current run to finish.")
            return
        if not selections:
            return
        if self._sanitized_batch_queue:
            QMessageBox.information(self, "Batch in progress", "Please wait for the current batch to finish.")
            return

        first_entry, _ = selections[0]
        parent_sudo = bool(getattr(first_entry, "use_sudo", False))
        parent_prerun = getattr(first_entry, "pre_run_command", None)
        if not parent_prerun:
            parent_prerun = (getattr(self._project_config(), "default_pre_run_command", "") or "").strip() or None

        parent_args: list[str] | None = None
        try:
            parent_args = list(first_entry.target_args) if first_entry.target_args else None
        except Exception:
            parent_args = None
        if parent_args is None:
            config_args = (getattr(self._project_config(), "default_target_args", "") or "").strip()
            if config_args:
                import shlex

                try:
                    parent_args = shlex.split(config_args)
                except Exception:
                    parent_args = [config_args]

        parent_filters: list[str] = []
        try:
            parent_filters = list(first_entry.module_filters or [])
        except Exception:
            parent_filters = []

        options_dialog = RunSanitizedOptionsDialog(self, default_run_with_sudo=parent_sudo)
        options_dialog.set_invocation_preview(
            args=parent_args,
            module_filters=parent_filters,
            use_sudo=parent_sudo,
            pre_run_command=parent_prerun,
        )
        if options_dialog.exec() != QDialog.Accepted:
            self._append_console("Sanitized batch execution cancelled before launch.")
            return
        run_options = options_dialog.selected_options()
        if not run_options.run_with_pin:
            QMessageBox.information(
                self,
                "PIN execution required",
                "Sanitized runs currently depend on the PIN tracer. Continuing with PIN instrumentation enabled.",
            )

        queue: list[dict[str, object]] = []
        missing: list[str] = []
        for entry, output in selections:
            if not output.output_path:
                continue
            path_obj = Path(output.output_path)
            if not path_obj.exists():
                missing.append(str(path_obj))
                continue
            queue.append(
                {
                    "entry_id": entry.entry_id,
                    "output_id": output.output_id,
                    "binary_path": str(path_obj),
                    "original_binary_path": entry.binary_path,
                }
            )
        if missing:
            self._append_console(f"Skipping {len(missing)} missing sanitized binary(ies).")
        if not queue:
            QMessageBox.information(self, "Nothing to execute", "No selected sanitized binaries exist on disk.")
            return

        self._sanitized_batch_queue = queue
        self._sanitized_batch_options = run_options
        self._sanitized_batch_cancelled = False
        self._sanitized_batch_total = len(queue)
        self._sanitized_batch_completed = 0

        dialog = RunProgressDialog(self, f"Sanitized Batch ({len(queue)} run(s))", on_stop=self._request_stop_current_run)
        dialog.setWindowTitle("Executing Sanitized Binaries")
        dialog.append_output(f"Starting batch: {len(queue)} sanitized binary(ies).")
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        self._sanitized_batch_dialog = dialog
        self._run_next_sanitized_batch()

    def _run_next_sanitized_batch(self) -> None:
        if not self._sanitized_batch_queue or self._sanitized_batch_cancelled:
            dialog = self._sanitized_batch_dialog
            if dialog is not None:
                dialog.append_output("Batch complete." if not self._sanitized_batch_cancelled else "Batch cancelled.")
                dialog.mark_finished(not self._sanitized_batch_cancelled)
            self._sanitized_batch_queue = None
            self._sanitized_batch_options = None
            self._sanitized_batch_dialog = None
            self._sanitized_batch_total = 0
            self._sanitized_batch_completed = 0
            self._update_sanitized_action_state()
            return

        item = self._sanitized_batch_queue.pop(0)
        entry_id = str(item.get("entry_id"))
        output_id = str(item.get("output_id"))
        binary_path = str(item.get("binary_path"))
        original_binary_path = str(item.get("original_binary_path") or "")
        entry = self._entry_by_id(entry_id)
        if entry is None:
            QTimer.singleShot(0, self._run_next_sanitized_batch)
            return

        # Reuse the parent entry invocation values (args/modules/sudo/pre-run) and only reuse the sanitized-run options dialog values.
        try:
            target_args = list(entry.target_args) if entry.target_args else None
        except Exception:
            target_args = None
        try:
            module_filters = list(entry.module_filters or [])
        except Exception:
            module_filters = []
        run_with_sudo = bool(getattr(entry, "use_sudo", False))
        pre_run_command = getattr(entry, "pre_run_command", None)
        if not pre_run_command:
            pre_run_command = (getattr(self._project_config(), "default_pre_run_command", "") or "").strip() or None

        self._sanitized_batch_completed += 1
        batch_total = max(1, int(self._sanitized_batch_total or 1))
        batch_index = max(1, min(batch_total, int(self._sanitized_batch_completed or 1)))

        base_label = f"{entry.name} (Sanitized)"
        suffix = Path(binary_path).stem
        log_label = f"{base_label} - {suffix} ({batch_index})"
        log_path = str(self._project_log_path(run_label=log_label))

        dialog = self._sanitized_batch_dialog
        if dialog is not None:
            dialog.set_running_label(f"{Path(binary_path).name} ({batch_index}/{batch_total})")
            dialog.append_output(f"\n[{batch_index}/{batch_total}] Running: {binary_path}")

        run_options = self._sanitized_batch_options
        self._run_with_progress(
            binary_path,
            log_path,
            record_entry=True,
            entry_to_refresh=None,
            dialog_label=f"{Path(binary_path).name} ({batch_index}/{batch_total})",
            run_label=log_label,
            parent_entry_id=entry.entry_id,
            sanitized_binary_path=binary_path,
            is_sanitized_run=True,
            module_filters=module_filters,
            unique_only=bool(getattr(self, "_last_unique_only", False)),
            run_with_sudo=run_with_sudo,
            metrics_options=run_options,
            pre_run_command=pre_run_command,
            target_args=target_args,
            original_binary_path=original_binary_path,
            copy_sanitized_to_original_path=bool(getattr(run_options, "copy_to_original_path", False)) if run_options else False,
            assume_works_entry_id=entry.entry_id if (run_options and getattr(run_options, "assume_works_if_running", False)) else None,
            assume_works_output_id=output_id if (run_options and getattr(run_options, "assume_works_if_running", False)) else None,
            assume_works_after_ms=int(getattr(run_options, "assume_works_after_ms", 0) or 0)
            if (run_options and getattr(run_options, "assume_works_if_running", False))
            else None,
            block=False,
            dialog=dialog,
            suppress_failure_dialog=True,
            batch_mode=True,
        )

    def reveal_sanitized_binary(self) -> None:
        selection = self._selected_sanitized_output()
        if selection is None:
            QMessageBox.information(self, "No sanitized binary", "Generate a sanitized binary to reveal it.")
            return
        _, output = selection
        path_obj = Path(output.output_path)
        if not path_obj.exists():
            QMessageBox.warning(
                self,
                "Sanitized binary missing",
                f"Expected sanitized binary at {path_obj}, but it is not on disk.",
            )
            return
        target = path_obj if path_obj.is_dir() else path_obj.parent
        opened = QDesktopServices.openUrl(QUrl.fromLocalFile(str(target)))
        if not opened:
            QMessageBox.warning(
                self,
                "Unable to open",
                "The operating system rejected the request to open the sanitized binary location.",
            )

    def compare_sanitized_to_parent(self) -> None:
        selection = self._selected_sanitized_output()
        if selection is None:
            QMessageBox.information(
                self,
                "No sanitized binary selected",
                "Select a sanitized binary from the list before comparing it to its parent.",
            )
            return
        entry, output = selection
        sanitized_path_value = output.output_path
        if not sanitized_path_value:
            QMessageBox.information(
                self,
                "Sanitized binary unavailable",
                "Generate a sanitized binary for this entry before performing a comparison.",
            )
            return
        sanitized_path = Path(sanitized_path_value)
        if not sanitized_path.exists():
            QMessageBox.warning(
                self,
                "Sanitized binary missing",
                f"Expected sanitized binary at {sanitized_path}, but it no longer exists.",
            )
            entry.sanitized_binary_path = None
            self._persist_current_history()
            self._refresh_entry_views(entry.entry_id)
            self._update_honey_detail(entry)
            return
        project_settings = self._project_config()
        config_parent_path = (project_settings.binary_path or "").strip()
        parent_path_value = config_parent_path or entry.binary_path or ""
        if not parent_path_value:
            QMessageBox.warning(
                self,
                "Missing parent binary",
                "Set a target binary in the Configuration tab before comparing to parent.",
            )
            return
        parent_path = Path(parent_path_value)
        if not parent_path.exists():
            source_label = "configured" if config_parent_path else "recorded"
            QMessageBox.warning(
                self,
                "Parent binary missing",
                f"The {source_label} parent binary at {parent_path} could not be found on disk.",
            )
            return
        log_path_value = entry.log_path
        if not log_path_value:
            QMessageBox.warning(
                self,
                "Missing instruction log",
                "This entry does not have an instruction log to drive the comparison.",
            )
            return
        log_path = Path(log_path_value)
        if not log_path.exists():
            QMessageBox.warning(
                self,
                "Instruction log missing",
                f"The instruction log was not found at {log_path}. Re-run the entry to regenerate it.",
            )
            return
        if self._parent_comparison_thread is not None:
            QMessageBox.information(
                self,
                "Comparison already running",
                "Please wait for the current comparison to finish before starting another.",
            )
            return
        binary_offset = self._entry_effective_offset(entry)

        preview_segments = self._entry_segments(entry)
        progress_dialog = QProgressDialog(
            "Collecting instruction addresses for comparison...\nThis may take a while.",
            "Cancel",
            0,
            0,
            self,
        )
        progress_dialog.setWindowTitle("Compare to Parent")
        progress_dialog.setWindowModality(Qt.ApplicationModal)
        progress_dialog.setMinimumDuration(0)
        progress_dialog.setAutoClose(False)
        progress_dialog.setAutoReset(False)
        progress_dialog.setValue(0)
        progress_dialog.setLabelText(
            "Collecting instruction addresses for comparison.\nThis may take a while; use Cancel to stop."
        )
        progress_dialog.resize(600, 240)
        progress_dialog.canceled.connect(self._cancel_parent_comparison_preview)
        progress_dialog.show()
        QApplication.processEvents()

        worker = ParentComparisonPreviewWorker(
            log_path,
            sanitized_path,
            parent_path,
            address_limit=SANITIZATION_PREVIEW_ADDRESS_LIMIT,
            binary_offset=binary_offset,
        )
        thread = QThread(self)
        worker.moveToThread(thread)
        self._parent_comparison_thread = thread
        self._parent_comparison_worker = worker
        self._parent_comparison_dialog = progress_dialog

        last_progress_update = 0.0

        def _invoke_on_gui(callback: Callable[[], None]) -> None:
            if QThread.currentThread() is self.thread():
                callback()
            else:
                self._gui_invoker.invoke.emit(callback)

        def _update_progress_dialog(processed: int, total: int) -> None:
            dialog_ref = self._parent_comparison_dialog
            if dialog_ref is None:
                return
            if total <= 0:
                dialog_ref.setRange(0, 0)
                dialog_ref.setLabelText(
                    "Collecting instruction addresses for comparison.\nThis may take a while; use Cancel to stop."
                )
                return
            dialog_ref.setUpdatesEnabled(False)
            try:
                if dialog_ref.maximum() != total:
                    dialog_ref.setRange(0, total)
                dialog_ref.setValue(processed)
                dialog_ref.setLabelText(
                    f"Disassembling sanitized and parent instructions ({processed}/{total}).\n"
                    "Processing may take a while; use Cancel to stop."
                )
            finally:
                dialog_ref.setUpdatesEnabled(True)

        def _handle_progress(processed: int, total: int) -> None:
            nonlocal last_progress_update
            now = time.monotonic()
            if processed < total and (now - last_progress_update) < 0.05:
                return
            last_progress_update = now
            _invoke_on_gui(lambda proc=processed, tot=total: _update_progress_dialog(proc, tot))

        def _finalize() -> None:
            self._cleanup_parent_comparison_worker()

        def _handle_info(message: str) -> None:
            def _run() -> None:
                _finalize()
                QMessageBox.information(self, "Comparison unavailable", message)

            _invoke_on_gui(_run)

        def _handle_failed(message: str) -> None:
            def _run() -> None:
                _finalize()
                QMessageBox.critical(self, "Unable to compare", message)

            _invoke_on_gui(_run)

        def _handle_cancelled() -> None:
            def _run() -> None:
                _finalize()
                QMessageBox.information(self, "Comparison cancelled", "Instruction comparison was cancelled.")

            _invoke_on_gui(_run)

        def _handle_succeeded(payload: object) -> None:
            def _run() -> None:
                _cleanup = lambda close_dialog=True: self._cleanup_parent_comparison_worker(close_dialog=close_dialog)
                _cleanup(close_dialog=False)
                if not isinstance(payload, dict):
                    QMessageBox.critical(
                        self,
                        "Unable to compare",
                        "Unexpected comparison payload format.",
                    )
                    _cleanup(close_dialog=True)
                    return
                combined_rows = list(payload.get("rows", []))
                if not combined_rows:
                    QMessageBox.information(
                        self,
                        "Comparison unavailable",
                        "No instructions were returned for comparison.",
                    )
                    _cleanup(close_dialog=True)
                    return
                if payload.get("truncated") and payload.get("limit"):
                    QMessageBox.information(
                        self,
                        "Comparison truncated",
                        f"Showing the first {payload['limit']} unique instruction address(es).",
                    )
                entry_label = entry.label() or entry.name or sanitized_path.name
                parent_addresses = list(payload.get("parent_addresses", []))
                saved_offset = binary_offset
                entry_id_value = entry.entry_id if entry else None
                save_offset_callback = (
                    (lambda value, entry_id=entry_id_value: self._save_entry_offset(entry_id, value))
                    if entry_id_value
                    else None
                )
                comparison_dialog = self._parent_comparison_dialog
                total_addresses = int(payload.get("total", len(combined_rows)) or len(combined_rows))
                if comparison_dialog is not None:
                    comparison_dialog.setCancelButton(None)
                    progress_value = max(total_addresses * 2, 1)
                    comparison_dialog.setRange(0, progress_value)
                    comparison_dialog.setValue(progress_value)
                    comparison_dialog.setLabelText(
                        f"Disassembly complete ({progress_value}/{progress_value}). Finalizing comparison..."
                    )
                    QApplication.processEvents()

                def _update_preview_progress(message: str) -> None:
                    dialog_ref = self._parent_comparison_dialog
                    if dialog_ref is None:
                        return
                    dialog_ref.setRange(0, 0)
                    dialog_ref.setLabelText(message)
                    QApplication.processEvents()

                try:
                    dialog = ParentComparisonPreviewDialog(
                        self,
                        entry_label,
                        combined_rows,
                        segments=preview_segments,
                        binary_path=sanitized_path,
                        saved_offset=saved_offset,
                        progress_callback=_update_preview_progress,
                        parent_binary_addresses=parent_addresses,
                        save_offset_callback=save_offset_callback,
                    )
                finally:
                    _cleanup(close_dialog=True)
                dialog.exec()

            _invoke_on_gui(_run)

        worker.progress.connect(_handle_progress, Qt.QueuedConnection)
        worker.info.connect(_handle_info, Qt.QueuedConnection)
        worker.failed.connect(_handle_failed, Qt.QueuedConnection)
        worker.cancelled.connect(_handle_cancelled, Qt.QueuedConnection)
        worker.succeeded.connect(_handle_succeeded, Qt.QueuedConnection)
        thread.started.connect(worker.run)
        thread.start()

    def compare_sanitized_logs(self) -> None:
        entry = self._current_honey_entry()
        pair = self._resolve_compare_pair(entry)
        if not pair:
            QMessageBox.information(
                self,
                "Comparison unavailable",
                "Need both an original and sanitized log on disk to compute a diff.",
            )
            return
        if self._trace_comparison_thread is not None:
            QMessageBox.information(
                self,
                "Comparison running",
                "A log comparison is already running. Please wait for it to finish before starting another.",
            )
            return
        sanitized, original = pair
        sanitized_path = Path(sanitized.log_path)
        original_path = Path(original.log_path)
        preview_segments = self._entry_segments(sanitized)
        progress_dialog = BusyProgressDialog("Collecting trace data...", "Cancel", 0, 0, self)
        progress_dialog.setWindowTitle("Compare Logs")
        progress_dialog.setWindowModality(Qt.ApplicationModal)
        progress_dialog.setMinimumDuration(0)
        progress_dialog.setAutoClose(False)
        progress_dialog.setAutoReset(False)
        progress_dialog.setValue(0)
        progress_dialog.setLabelText("Collecting trace addresses from the sanitized run...")
        progress_dialog.resize(600, 240)
        progress_dialog.start_pulsing()
        progress_dialog.canceled.connect(self._cancel_trace_comparison_preview)
        progress_dialog.show()

        worker = TraceComparisonPreviewWorker(
            sanitized_path,
            original_path,
            sanitized_offset=self._entry_effective_offset(sanitized),
            original_offset=self._entry_effective_offset(original),
            address_limit=SANITIZATION_PREVIEW_ADDRESS_LIMIT,
        )
        thread = QThread(self)
        worker.moveToThread(thread)
        self._trace_comparison_thread = thread
        self._trace_comparison_worker = worker
        self._trace_comparison_dialog = progress_dialog

        def _cleanup(close_dialog: bool = True) -> None:
            self._cleanup_trace_comparison_worker(close_dialog=close_dialog)

        def _handle_progress(processed: int, total: int) -> None:
            dialog = self._trace_comparison_dialog
            if dialog is None:
                return
            if total <= 0:
                dialog.setRange(0, 0)
                dialog.setLabelText("Collecting trace addresses from the sanitized run...")
                return
            current = max(0, min(processed, total))
            if dialog.maximum() != total:
                dialog.setRange(0, total)
            dialog.setValue(current)
            dialog.setLabelText(f"Comparing traces ({current}/{total})")

        def _handle_info(message: str) -> None:
            _cleanup()
            QMessageBox.information(self, "Comparison unavailable", message)

        def _handle_failed(message: str) -> None:
            _cleanup()
            QMessageBox.critical(self, "Comparison failed", message)

        def _handle_cancelled() -> None:
            self._append_console("Trace comparison cancelled.")
            _cleanup(close_dialog=True)

        def _handle_succeeded(payload: object) -> None:
            _cleanup()
            if not isinstance(payload, dict):
                QMessageBox.information(self, "Comparison unavailable", "No data was returned for comparison.")
                return
            rows = list(payload.get("rows", []))
            if not rows:
                QMessageBox.information(
                    self,
                    "Comparison unavailable",
                    "The sanitized log did not yield any comparable trace entries.",
                )
                return
            notices: list[str] = []
            if payload.get("sanitized_truncated"):
                notices.append("Sanitized log was truncated while collecting trace addresses.")
            if payload.get("original_truncated"):
                notices.append("Original log was truncated while collecting trace addresses.")
            missing = int(payload.get("missing_original", 0) or 0)
            if missing:
                notices.append(f"{missing} sanitized trace address(es) were not found in the original log.")
            if notices:
                QMessageBox.information(self, "Comparison notes", "\n".join(notices))
            sanitized_label = sanitized.label() or sanitized.name or sanitized_path.name
            original_label = original.label() or original.name or original_path.name
            entry_label = sanitized_label
            dialog = TraceComparisonPreviewDialog(
                self,
                entry_label,
                rows,
                segments=preview_segments,
                sanitized_label=sanitized_label,
                original_label=original_label,
            )
            dialog.exec()

        worker.progress.connect(_handle_progress, Qt.QueuedConnection)
        worker.info.connect(_handle_info, Qt.QueuedConnection)
        worker.failed.connect(_handle_failed, Qt.QueuedConnection)
        worker.cancelled.connect(_handle_cancelled, Qt.QueuedConnection)
        worker.succeeded.connect(_handle_succeeded, Qt.QueuedConnection)
        thread.started.connect(worker.run)
        thread.start()

    def delete_sanitized_binary(self) -> None:
        selections = self._selected_sanitized_outputs()
        if not selections:
            QMessageBox.information(
                self,
                "No sanitized binary selected",
                "Select a sanitized binary in the list to delete it.",
            )
            return
        busy = bool(self._current_run_thread and self._current_run_thread.isRunning())
        if busy:
            QMessageBox.information(self, "Run in progress", "Please wait for the current run to finish.")
            return

        multiple = len(selections) > 1
        prompt = "This will remove the sanitized binary reference"
        if multiple:
            prompt = f"This will remove {len(selections)} sanitized binary reference(s) and delete any files found on disk. Continue?"
        else:
            _, output = selections[0]
            if not output.output_path:
                return
            binary_path = Path(output.output_path)
            has_file = binary_path.exists()
            if has_file:
                prompt += f" and delete the file at {binary_path}?"
            else:
                prompt += "?"
        confirm = QMessageBox.question(
            self,
            "Delete sanitized binary",
            prompt,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        errors: list[str] = []
        touched_entries: set[str] = set()
        for entry, output in selections:
            if not output.output_path:
                continue
            binary_path = Path(output.output_path)
            has_file = False
            try:
                has_file = binary_path.exists()
            except OSError:
                has_file = False
            if has_file:
                try:
                    if binary_path.is_dir():
                        shutil.rmtree(binary_path)
                    else:
                        binary_path.unlink()
                except OSError as exc:
                    errors.append(f"{binary_path}: {exc}")
                    continue

            entry.sanitized_outputs = [
                item for item in (getattr(entry, "sanitized_outputs", None) or []) if item.output_id != output.output_id
            ]
            if entry.sanitized_outputs:
                latest = max(
                    entry.sanitized_outputs,
                    key=lambda out: out.generated_at or datetime.min,
                )
                entry.sanitized_binary_path = latest.output_path
                entry.sanitized_total_instructions = int(latest.total_instructions or 0)
                entry.sanitized_preserved_instructions = int(latest.preserved_instructions or 0)
                entry.sanitized_nopped_instructions = int(latest.nopped_instructions or 0)
            else:
                entry.sanitized_binary_path = None
                entry.sanitized_total_instructions = 0
                entry.sanitized_preserved_instructions = 0
                entry.sanitized_nopped_instructions = 0
            touched_entries.add(entry.entry_id)

        if touched_entries:
            self._persist_current_history()
            self._refresh_entry_views(next(iter(touched_entries)))
            self._update_honey_detail(self._current_honey_entry())

        if errors:
            QMessageBox.warning(
                self,
                "Unable to delete",
                "Failed to delete one or more sanitized binaries:\n" + "\n".join(errors[:10]),
            )
        else:
            self._append_console(f"Removed {len(touched_entries)} sanitized binary reference(s).")

    def _load_history_for_active_project(self) -> None:
        self.run_entries = self.history_store.load_project(self.active_project)
        if self._upgrade_entry_paths():
            self._persist_current_history()
        self._refresh_entry_views(None)

    def _persist_current_history(self) -> None:
        self.history_store.save_project(self.active_project, self.run_entries)

    def _save_entry_offset(self, entry_id: str | None, offset: int) -> bool:
        if not entry_id:
            QMessageBox.warning(self, "Unable to save offset", "Entry is no longer available.")
            return False
        entry = self._entry_by_id(entry_id)
        if not entry:
            QMessageBox.warning(self, "Unable to save offset", "Entry is no longer available.")
            return False
        numeric_offset = int(offset)
        if entry.binary_offset == numeric_offset:
            return True
        entry.binary_offset = numeric_offset
        self._persist_current_history()
        self._append_console(
            f"Saved binary offset {InstructionPreviewDialog._format_offset(numeric_offset)} for {entry.name}."
        )
        return True

    def _append_console(self, message: str) -> None:
        if not hasattr(self, "console_output"):
            return
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console_output.appendPlainText(f"[{timestamp}] {message}")

    def _discover_binary_modules(self, binary_path: str) -> list[str]:
        modules: list[str] = []
        name = Path(binary_path).name
        if name:
            modules.append(name)
        try:
            binary = lief.parse(str(binary_path))
            libraries = sorted({Path(lib).name or lib for lib in getattr(binary, "libraries", []) if lib})
            for lib in libraries:
                if lib not in modules:
                    modules.append(lib)
        except Exception:
            pass
        return modules

    def _prompt_module_selection(
        self,
        binary_path: str,
        *,
        default_log_label: str | None = None,
        is_sanitized_run: bool = False,
    ) -> tuple[list[str], str, bool, bool, str | None, bool] | None:
        modules = self._discover_binary_modules(binary_path)
        default_label = default_log_label or self._default_run_label(binary_path)
        display_name = Path(binary_path).name or str(binary_path)
        builder = lambda label: self._project_log_filename(label)

        default_prerun = (getattr(self._project_config(), "default_pre_run_command", "") or "").strip() or None
        invocation_args: list[str] | None = None
        config_args = (getattr(self._project_config(), "default_target_args", "") or "").strip()
        if config_args:
            import shlex

            try:
                invocation_args = shlex.split(config_args)
            except Exception:
                invocation_args = [config_args]

        dialog = ModuleSelectionDialog(
            self,
            display_name,
            modules,
            default_log_label=default_label,
            filename_builder=builder,
            previous_selection=self._last_module_filters,
            default_unique_only=self._last_unique_only,
            default_run_with_sudo=self._last_run_with_sudo,
            default_pre_run_command=default_prerun,
            invocation_args=invocation_args,
            is_sanitized_run=is_sanitized_run,
        )
        result = dialog.exec()
        if result != QDialog.Accepted:
            self._append_console("Run cancelled before launch.")
            return None
        selection = dialog.selected_modules()
        log_label = dialog.selected_log_label()
        unique_only = dialog.unique_only()
        run_with_sudo = bool(dialog.run_with_sudo())
        pre_run_command = dialog.selected_pre_run_command()
        copy_to_relative = bool(dialog.copy_binary_to_relative_path())
        if not selection or not log_label:
            return None
        self._last_module_filters = selection
        self._last_unique_only = bool(unique_only)
        self._last_run_with_sudo = run_with_sudo
        self._last_pre_run_command = pre_run_command
        return selection, log_label, bool(unique_only), run_with_sudo, pre_run_command, copy_to_relative

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._cancel_sanitization_preview()
        self._cleanup_sanitization_preview_worker()
        self._cancel_parent_comparison_preview()
        self._cleanup_parent_comparison_worker()
        super().closeEvent(event)

    def _cleanup_sanitize_worker(self) -> None:
        thread = self._current_sanitize_thread
        worker = self._current_sanitize_worker
        dialog = self._current_sanitize_dialog
        if thread:
            if thread.isRunning():
                thread.quit()
                thread.wait()
            thread.deleteLater()
        if worker:
            worker.deleteLater()
        self._current_sanitize_thread = None
        self._current_sanitize_worker = None
        self._current_sanitize_dialog = None
        self._current_sanitize_entry_id = None
        self._update_honey_buttons()
        self._update_honey_detail(self._current_honey_entry())

    def _ensure_directory(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)

    def _show_busy_dialog(self, message: str, *, title: str = "Preparing") -> QProgressDialog:
        dialog = QProgressDialog(message, None, 0, 0, self)
        dialog.setCancelButton(None)
        dialog.setWindowTitle(title)
        dialog.setWindowModality(Qt.NonModal)
        dialog.setMinimumDuration(0)
        dialog.setLabelText(message)
        dialog.resize(460, 180)
        dialog.show()
        QApplication.processEvents()
        return dialog

    def _handle_sanitize_success(self, result: SanitizationResult) -> None:
        dialog = self._current_sanitize_dialog
        entry = self._entry_by_id(self._current_sanitize_entry_id)
        if dialog:
            dialog.append_output(
                "Sanitization complete. Writing patched binary to disk..."
            )
            dialog.mark_finished("Sanitization complete.")
        self._append_console(
            "Sanitized binary saved to "
            f"{result.output_path} (NOPed {result.nopped_instructions} / {result.total_instructions})."
        )
        if entry:
            worker = self._current_sanitize_worker
            options = worker.options if worker is not None else None
            self._add_sanitized_output(entry, result, options)
        self._refresh_entry_views(entry.entry_id if entry else None)
        QMessageBox.information(
            self,
            "Sanitization complete",
            (
                "Generated sanitized binary at:\n"
                f"{result.output_path}\n\n"
                f"NOPed {result.nopped_instructions} instructions; preserved {result.preserved_instructions}."
            ),
        )
        self._cleanup_sanitize_worker()

    def _add_sanitized_output(
        self,
        entry: RunEntry,
        result: SanitizationResult,
        options: SanitizeOptions | None,
    ) -> None:
        output = SanitizedBinaryOutput(
            output_id=str(uuid.uuid4()),
            output_path=str(result.output_path),
            works=None,
            segment_gap=int(getattr(options, "segment_gap", 0) or 0) if options else 0,
            segment_padding=int(getattr(options, "segment_padding", 0) or 0) if options else 0,
            icf_window=int(getattr(options, "icf_window", 0) or 0) if options else 0,
            jumptable_window=int(getattr(options, "jumptable_window", 0) or 0) if options else 0,
            total_instructions=int(result.total_instructions or 0),
            preserved_instructions=int(result.preserved_instructions or 0),
            nopped_instructions=int(result.nopped_instructions or 0),
            generated_at=datetime.now(),
        )
        entry.sanitized_outputs = list(getattr(entry, "sanitized_outputs", None) or []) + [output]
        entry.sanitized_binary_path = output.output_path
        entry.sanitized_total_instructions = int(output.total_instructions or 0)
        entry.sanitized_preserved_instructions = int(output.preserved_instructions or 0)
        entry.sanitized_nopped_instructions = int(output.nopped_instructions or 0)
        self._persist_current_history()

    def _cleanup_sweep_worker(self) -> None:
        thread = self._current_sweep_thread
        worker = self._current_sweep_worker
        dialog = self._current_sweep_dialog
        if thread:
            if thread.isRunning():
                thread.quit()
                thread.wait()
            thread.deleteLater()
        if worker:
            worker.deleteLater()
        self._current_sweep_thread = None
        self._current_sweep_worker = None
        self._current_sweep_dialog = None

    def _handle_sanitize_failure(self, message: str) -> None:
        dialog = self._current_sanitize_dialog
        if dialog:
            dialog.append_output(f"Error: {message}")
            dialog.mark_finished("Sanitization failed.")
        self._append_console(f"Sanitization failed: {message}")
        QMessageBox.critical(self, "Sanitization failed", message)
        self._cleanup_sanitize_worker()

    def _handle_build_worker_success(self) -> None:
        dialog = self._current_build_dialog
        if dialog:
            dialog.append_output("Build completed successfully.")
            dialog.mark_finished(True)
        self._update_tool_path_if_default_exists()
        self._append_console("PIN tool build completed successfully.")
        self._cleanup_build_worker()

    def _handle_build_worker_failure(self, error_message: str) -> None:
        dialog = self._current_build_dialog
        if dialog:
            dialog.append_output(f"Error: {error_message}")
            dialog.mark_finished(False)
        self._append_console(f"Error building PIN tool: {error_message}")
        QMessageBox.critical(self, "Build failed", error_message)
        self._cleanup_build_worker()

    def _cleanup_build_worker(self) -> None:
        thread = self._current_build_thread
        worker = self._current_build_worker
        dialog = self._current_build_dialog
        if thread is None and worker is None and dialog is None:
            return
        if thread:
            if thread.isRunning():
                thread.quit()
                thread.wait()
            thread.deleteLater()
        if worker:
            worker.deleteLater()
        self._current_build_thread = None
        self._current_build_worker = None
        self._current_build_dialog = None
        if hasattr(self, "build_tool_button"):
            self.build_tool_button.setEnabled(True)

    def _run_and_record(
        self,
        binary_path: str,
        log_path: str | None,
        *,
        run_label: str | None = None,
        module_filters: list[str] | None = None,
        unique_only: bool = False,
        run_with_sudo: bool = False,
        pre_run_command: str | None = None,
        copy_binary_to_relative_path: bool = False,
    ) -> None:
        if copy_binary_to_relative_path:
            try:
                source = Path(binary_path)
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                dest_dir = self._project_storage_root(ensure_exists=True) / "binaries"
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest = dest_dir / f"{source.name}_{stamp}"
                shutil.copy2(source, dest)
                dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                self._append_console(f"Copied target binary to {dest} and will run the copy.")
                binary_path = str(dest)
            except Exception as exc:
                QMessageBox.critical(self, "Copy failed", f"Failed to copy binary to a relative path: {exc}")
                return
        binary_label = Path(binary_path).name or binary_path
        if not self._ensure_aslr_disabled_for_execution(binary_label):
            return
        sudo_password: str | None = None
        if run_with_sudo:
            sudo_password = self._obtain_sudo_password(f"Enter sudo password to run {binary_label}:")
            if not sudo_password:
                self._append_console("Run cancelled; sudo password not provided.")
                return
        extra_args: list[str] | None = None
        # Use configured default args from project settings
        config_args = self._project_config().default_target_args
        if config_args and config_args.strip():
            import shlex
            try:
                extra_args = shlex.split(config_args)
            except Exception:
                extra_args = [config_args]
        try:
            # Execute optional pre-run command or script before launching PIN
            if pre_run_command:
                from pathlib import Path as _Path
                import subprocess as _subprocess
                import os as _os
                cmd: list[str]
                try:
                    _p = _Path(pre_run_command)
                    if _p.exists() and _p.is_file():
                        cmd = ["bash", str(_p)]
                    else:
                        cmd = ["bash", "-lc", pre_run_command]
                except Exception:
                    cmd = ["bash", "-lc", pre_run_command]
                if run_with_sudo and sudo_password:
                    cmd = ["sudo", "-S", "-p", "", *cmd]
                proc = _subprocess.Popen(
                    cmd,
                    stdout=_subprocess.PIPE,
                    stderr=_subprocess.STDOUT,
                    stdin=_subprocess.PIPE if (run_with_sudo and sudo_password) else None,
                    text=True,
                    bufsize=1,
                    cwd=_os.getcwd(),
                )
                if run_with_sudo and sudo_password and proc.stdin is not None:
                    try:
                        proc.stdin.write(sudo_password + "\n")
                        proc.stdin.flush()
                    except BrokenPipeError:
                        pass
                    finally:
                        try:
                            proc.stdin.close()
                        except OSError:
                            pass
                assert proc.stdout is not None
                for line in proc.stdout:
                    clean = line.rstrip()
                    if clean:
                        self._append_console(clean)
                proc.wait()
                if proc.returncode != 0:
                    raise RuntimeError("Pre-run command failed with non-zero exit status")
            result_path = self.controller.run_binary(
                binary_path,
                log_path=log_path,
                module_filters=module_filters,
                unique_only=unique_only,
                use_sudo=bool(run_with_sudo),
                sudo_password=sudo_password,
                extra_target_args=extra_args,
            )
            self._on_run_success(
                binary_path,
                str(result_path),
                run_label=run_label,
                target_args=extra_args,
                use_sudo=bool(run_with_sudo),
                module_filters=module_filters,
                pre_run_command=pre_run_command,
            )
        except Exception as exc:
            self._on_run_failure(exc)

    def _run_with_progress(
        self,
        binary_path: str,
        log_path: str | None,
        *,
        record_entry: bool = True,
        entry_to_refresh: RunEntry | None = None,
        dialog_label: str | None = None,
        run_label: str | None = None,
        parent_entry_id: str | None = None,
        sanitized_binary_path: str | None = None,
        is_sanitized_run: bool = False,
        module_filters: list[str] | None = None,
        unique_only: bool = False,
        run_with_sudo: bool = False,
        metrics_options: RunSanitizedOptions | None = None,
        pre_run_command: str | None = None,
        target_args: list[str] | None = None,
        original_binary_path: str | None = None,
        copy_binary_to_relative_path: bool = False,
        copy_sanitized_to_original_path: bool = False,
        assume_works_entry_id: str | None = None,
        assume_works_output_id: str | None = None,
        assume_works_after_ms: int | None = None,
        block: bool = True,
        dialog: RunProgressDialog | None = None,
        suppress_failure_dialog: bool = False,
        batch_mode: bool = False,
    ) -> bool:
        # Optional: copy original target binary into project-relative storage before running.
        if copy_binary_to_relative_path and not is_sanitized_run:
            try:
                source = Path(binary_path)
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                dest_dir = self._project_storage_root(ensure_exists=True) / "binaries"
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest = dest_dir / f"{source.name}_{stamp}"
                shutil.copy2(source, dest)
                dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                self._append_console(f"Copied target binary to {dest} and will run the copy.")
                binary_path = str(dest)
            except Exception as exc:
                message = f"Failed to copy binary to a relative path: {exc}"
                if batch_mode:
                    self._append_console(message)
                    if dialog:
                        dialog.append_output(f"{message}\n")
                    return False
                QMessageBox.critical(self, "Copy failed", message)
                return False

        binary_label = Path(binary_path).name or binary_path
        if not self._ensure_aslr_disabled_for_execution(binary_label, allow_prompt=not bool(batch_mode)):
            if batch_mode:
                if dialog:
                    dialog.append_output("Skipping run: unable to disable ASLR.\n")
                return False
            return False
        sudo_password: str | None = None
        if run_with_sudo:
            sudo_password = self._obtain_sudo_password(f"Enter sudo password to run {binary_label}:")
            if not sudo_password:
                self._append_console("Run cancelled; sudo password not provided.")
                if batch_mode:
                    # Batch cannot proceed without sudo; treat this as user cancellation.
                    self._sanitized_batch_cancelled = True
                    try:
                        if self._sanitized_batch_queue is not None:
                            self._sanitized_batch_queue.clear()
                    except Exception:
                        pass
                return False

        # Optional: for sanitized runs, copy the sanitized binary into the original binary's directory.
        if is_sanitized_run and copy_sanitized_to_original_path:
            if not original_binary_path:
                message = "Original binary path is unknown; cannot copy sanitized binary."
                if batch_mode:
                    self._append_console(message)
                    if dialog:
                        dialog.append_output(f"{message}\n")
                    return False
                QMessageBox.critical(self, "Copy failed", message)
                return False
            try:
                src = Path(binary_path)
                orig = Path(original_binary_path)
                dest_dir = orig.parent
                base_name = orig.name + ".sanitized"
                dest = dest_dir / base_name
                counter = 1
                while dest.exists():
                    dest = dest_dir / f"{base_name}.{counter}"
                    counter += 1

                def _copy_with_sudo(src_path: Path, dest_path: Path) -> None:
                    import subprocess as _subprocess

                    if not sudo_password:
                        raise PermissionError("Destination requires sudo but sudo is disabled for this run.")
                    cmd = ["sudo", "-S", "-p", "", "cp", "-p", str(src_path), str(dest_path)]
                    _subprocess.run(
                        cmd,
                        input=sudo_password + "\n",
                        text=True,
                        stdout=_subprocess.PIPE,
                        stderr=_subprocess.STDOUT,
                        check=True,
                    )

                try:
                    shutil.copy2(src, dest)
                except PermissionError:
                    _copy_with_sudo(src, dest)

                self._append_console(f"Copied sanitized binary to {dest} and will run that copy.")
                binary_path = str(dest)
                binary_label = Path(binary_path).name or binary_path
            except Exception as exc:
                message = f"Failed to copy sanitized binary to the original path: {exc}"
                if batch_mode:
                    self._append_console(message)
                    if dialog:
                        dialog.append_output(f"{message}\n")
                    return False
                QMessageBox.critical(self, "Copy failed", message)
                return False
        extra_args: list[str] | None = None
        # Use configured default args from project settings
        config_args = self._project_config().default_target_args
        if config_args and config_args.strip():
            import shlex
            try:
                extra_args = shlex.split(config_args)
            except Exception:
                extra_args = [config_args]

        # Use provided target_args for sanitized runs, or extra_args for new runs
        final_args = target_args if (target_args and is_sanitized_run) else extra_args
        self._run_stop_requested = False
        self._run_stop_reason = None
        dialog = dialog or RunProgressDialog(
            self,
            dialog_label or Path(binary_path).name or binary_path,
            on_stop=self._request_stop_current_run,
        )
        dialog.set_running_label(dialog_label or Path(binary_path).name or binary_path)
        worker = RunWorker(
            self.controller,
            binary_path,
            log_path,
            module_filters=module_filters,
            unique_only=unique_only,
            use_sudo=bool(run_with_sudo),
            sudo_password=sudo_password,
            extra_target_args=final_args,
            pre_run_command=pre_run_command,
        )
        thread = QThread(self)
        worker.moveToThread(thread)

        # During batch execution, per-line UI updates can overwhelm the Qt event loop and
        # make the GUI appear frozen. Buffer and flush output periodically instead.
        if batch_mode:
            self._setup_batch_output_buffer(dialog)
            worker.output.connect(self._enqueue_batch_output)
        else:
            worker.output.connect(dialog.append_output)
            worker.output.connect(self._append_console)

        self._current_run_thread = thread
        self._current_run_worker = worker
        self._current_run_dialog = dialog
        self._current_run_params = {
            "binary_path": binary_path,
            "record_entry": record_entry,
            "entry_to_refresh": entry_to_refresh,
            "run_label": run_label,
            "parent_entry_id": parent_entry_id,
            "sanitized_binary_path": sanitized_binary_path,
            "is_sanitized_run": is_sanitized_run,
            "module_filters": module_filters,
            "unique_only": unique_only,
            "metrics_options": metrics_options,
            "target_args": final_args,
            "use_sudo": bool(run_with_sudo),
            "pre_run_command": pre_run_command,
            "assume_works_entry_id": assume_works_entry_id,
            "assume_works_output_id": assume_works_output_id,
            "assume_works_after_ms": int(assume_works_after_ms) if assume_works_after_ms is not None else None,
            "assume_works_started_at": time.monotonic(),
            "suppress_failure_dialog": bool(suppress_failure_dialog),
            "batch_mode": bool(batch_mode),
        }

        # Optional: if the sanitized run is still running after a short delay, mark it as working.
        try:
            if (
                is_sanitized_run
                and assume_works_entry_id
                and assume_works_output_id
                and assume_works_after_ms is not None
                and int(assume_works_after_ms) > 0
            ):
                delay_ms = max(1, min(10000, int(assume_works_after_ms)))

                timer = QTimer(self)
                timer.setSingleShot(True)

                def _mark_if_still_running() -> None:
                    if self._run_stop_requested:
                        return
                    current_thread = self._current_run_thread
                    if current_thread is None or not current_thread.isRunning():
                        return

                    try:
                        entry = self._entry_by_id(str(assume_works_entry_id))
                        if entry is not None:
                            outputs = list(getattr(entry, "sanitized_outputs", None) or [])
                            for out in outputs:
                                if getattr(out, "output_id", None) == assume_works_output_id:
                                    if getattr(out, "works", None) is not True:
                                        out.works = True
                                        self._persist_current_history()
                                        self._refresh_entry_views(entry.entry_id)
                                        self._append_console(
                                            f"Set Works=True (still running after {delay_ms}ms)."
                                        )
                                    break
                    finally:
                        # Always stop the run after the threshold if it's still running.
                        self._append_console(f"Assume-works threshold reached ({delay_ms}ms); terminating run.")
                        self._request_terminate_current_run(reason="assume_works")

                timer.timeout.connect(_mark_if_still_running)
                timer.start(delay_ms)
                self._current_assume_works_timer = timer
        except Exception:
            # Best-effort UX feature; never block execution.
            self._current_assume_works_timer = None

        worker.succeeded.connect(self._handle_run_worker_success)
        worker.failed.connect(self._handle_run_worker_failure)
        thread.finished.connect(self._cleanup_run_worker)
        dialog.finished.connect(self._cleanup_run_worker)

        thread.started.connect(worker.run)
        thread.start()
        if block:
            dialog.exec()
            self._cleanup_run_worker()
        else:
            dialog.show()
        return True

    def _request_stop_current_run(self) -> None:
        self._request_stop_current_run_internal(reason="user", cancel_batch=True)

    def _request_terminate_current_run(self, *, reason: str) -> None:
        self._request_stop_current_run_internal(reason=reason, cancel_batch=False)

    def _request_stop_current_run_internal(self, *, reason: str, cancel_batch: bool) -> None:
        if self._run_stop_requested:
            return
        self._run_stop_requested = True
        self._run_stop_reason = (reason or "user").strip() or "user"
        if cancel_batch and self._sanitized_batch_queue is not None:
            self._sanitized_batch_cancelled = True
            try:
                self._sanitized_batch_queue.clear()
            except Exception:
                pass
        if self._run_stop_reason == "assume_works":
            console_msg = "Terminating current run (assume-works threshold)."
            dialog_msg = "Assume-works threshold reached. Attempting to terminate run..."
        else:
            console_msg = "Stop requested for current run."
            dialog_msg = "Stop requested. Attempting to terminate run..."
        self._append_console(console_msg)
        if self._current_run_dialog:
            self._current_run_dialog.append_output(dialog_msg)
        try:
            self.controller.stop_logging()
        except Exception as exc:  # pragma: no cover - defensive stop
            self._append_console(f"Unable to stop run: {exc}")

    def _handle_run_worker_success(self, log_path: str) -> None:
        params = self._current_run_params or {}
        binary_path = params.get("binary_path")
        record_entry = params.get("record_entry", True)
        entry_to_refresh = params.get("entry_to_refresh")
        run_label = params.get("run_label")
        parent_entry_id = params.get("parent_entry_id")
        sanitized_binary_path = params.get("sanitized_binary_path")
        is_sanitized_run = params.get("is_sanitized_run", False)
        target_args = params.get("target_args")
        use_sudo = bool(params.get("use_sudo", False))
        pre_run_command = params.get("pre_run_command")
        metrics_options: RunSanitizedOptions | None = params.get("metrics_options")
        dialog = self._current_run_dialog
        if dialog and not bool(params.get("batch_mode", False)):
            dialog.append_output("Run completed successfully.")
            dialog.mark_finished(True)
        elif dialog:
            dialog.append_output("Run completed successfully.")

        if bool(params.get("batch_mode", False)) and dialog is not None:
            # Flush any buffered output so the last lines are visible.
            try:
                self._flush_batch_output(dialog)
            except Exception:
                pass

        # If assume-works was enabled and we exited *before* the threshold, mark as not working.
        try:
            if is_sanitized_run:
                assume_entry_id = params.get("assume_works_entry_id")
                assume_output_id = params.get("assume_works_output_id")
                assume_after_ms = params.get("assume_works_after_ms")
                started_at = params.get("assume_works_started_at")
                if assume_entry_id and assume_output_id and assume_after_ms and started_at:
                    elapsed_ms = int(max(0.0, (time.monotonic() - float(started_at)) * 1000.0))
                    threshold_ms = max(1, min(10000, int(assume_after_ms)))
                    if elapsed_ms < threshold_ms:
                        entry = self._entry_by_id(str(assume_entry_id))
                        if entry is not None:
                            for out in list(getattr(entry, "sanitized_outputs", None) or []):
                                if getattr(out, "output_id", None) == assume_output_id:
                                    if getattr(out, "works", None) is not False:
                                        out.works = False
                                        self._persist_current_history()
                                        self._refresh_entry_views(entry.entry_id)
                                        self._append_console(
                                            f"Set Works=False (exited before {threshold_ms}ms)."
                                        )
                                    break
        except Exception:
            pass
        if binary_path:
            self._on_run_success(
                binary_path,
                log_path,
                record_entry=record_entry,
                run_label=run_label,
                parent_entry_id=parent_entry_id,
                sanitized_binary_path=sanitized_binary_path,
                is_sanitized_run=is_sanitized_run,
                target_args=target_args,
                use_sudo=use_sudo,
                module_filters=params.get("module_filters"),
                pre_run_command=pre_run_command,
            )
        if metrics_options and any(
            [
                metrics_options.collect_cpu_metrics,
                metrics_options.collect_memory_metrics,
                metrics_options.collect_timing_metrics,
            ]
        ):
            self._append_console(
                "Metric collection was requested for this run. (Detailed capture hooks not implemented yet.)"
            )
        if entry_to_refresh:
            entry_to_refresh.log_path = log_path
            self._refresh_entry_views(entry_to_refresh.entry_id)
        self._run_stop_requested = False
        if bool(params.get("batch_mode", False)):
            # Schedule continuation only after the worker thread has finished and cleanup runs.
            self._batch_continue_pending = True
            return

        self._run_stop_requested = False
        self._cleanup_run_worker()

    def _handle_run_worker_failure(self, error_message: str) -> None:
        dialog = self._current_run_dialog
        params = self._current_run_params or {}
        stop_reason = getattr(self, "_run_stop_reason", None)
        if dialog:
            if self._run_stop_requested and stop_reason == "assume_works":
                dialog.append_output("Run terminated after assume-works threshold.")
                if not bool(params.get("batch_mode", False)):
                    dialog.mark_finished(True)
            elif self._run_stop_requested:
                dialog.append_output("Run stopped by user.")
                if not bool(params.get("batch_mode", False)):
                    dialog.mark_finished(False)
            else:
                dialog.append_output(f"Error: {error_message}")
                if not bool(params.get("batch_mode", False)):
                    dialog.mark_finished(False)

        if self._run_stop_requested and stop_reason == "assume_works":
            self._append_console("Run terminated after assume-works threshold.")
        elif self._run_stop_requested:
            self._append_console("Run stopped by user.")
            if not bool(params.get("batch_mode", False)):
                QMessageBox.information(self, "Run stopped", "Execution was stopped before completion.")
        else:
            if bool(params.get("suppress_failure_dialog", False)):
                self._append_console(f"Error running binary: {error_message}")
            else:
                self._on_run_failure(error_message)

        # If assume-works was enabled and we exited *before* the threshold, mark as not working.
        try:
            params = self._current_run_params or {}
            is_sanitized_run = bool(params.get("is_sanitized_run", False))
            if is_sanitized_run:
                assume_entry_id = params.get("assume_works_entry_id")
                assume_output_id = params.get("assume_works_output_id")
                assume_after_ms = params.get("assume_works_after_ms")
                started_at = params.get("assume_works_started_at")
                if assume_entry_id and assume_output_id and assume_after_ms and started_at:
                    elapsed_ms = int(max(0.0, (time.monotonic() - float(started_at)) * 1000.0))
                    threshold_ms = max(1, min(10000, int(assume_after_ms)))
                    if elapsed_ms < threshold_ms:
                        entry = self._entry_by_id(str(assume_entry_id))
                        if entry is not None:
                            for out in list(getattr(entry, "sanitized_outputs", None) or []):
                                if getattr(out, "output_id", None) == assume_output_id:
                                    if getattr(out, "works", None) is not False:
                                        out.works = False
                                        self._persist_current_history()
                                        self._refresh_entry_views(entry.entry_id)
                                        self._append_console(
                                            f"Set Works=False (exited before {threshold_ms}ms)."
                                        )
                                    break
        except Exception:
            pass
        self._run_stop_requested = False
        self._run_stop_reason = None
        if bool(params.get("batch_mode", False)):
            # Schedule continuation only after the worker thread has finished and cleanup runs.
            self._batch_continue_pending = True
            return

        self._run_stop_requested = False
        self._cleanup_run_worker()

    def _cleanup_run_worker(self) -> None:
        thread = self._current_run_thread
        worker = self._current_run_worker
        dialog = self._current_run_dialog
        timer = getattr(self, "_current_assume_works_timer", None)
        batch_timer = getattr(self, "_current_batch_output_timer", None)
        if timer is not None:
            try:
                timer.stop()
            except Exception:
                pass
            try:
                timer.deleteLater()
            except Exception:
                pass
        self._current_assume_works_timer = None
        if batch_timer is not None:
            try:
                batch_timer.stop()
            except Exception:
                pass
            try:
                batch_timer.deleteLater()
            except Exception:
                pass
        self._current_batch_output_timer = None
        try:
            self._current_batch_output_buffer.clear()
        except Exception:
            self._current_batch_output_buffer = deque()
        self._current_batch_output_dropped = 0
        if thread is None and worker is None and dialog is None:
        if thread is None and worker is None and dialog is None:
            return
        if thread:
            # Never block the GUI thread waiting for a worker thread to exit.
            if thread.isRunning():
                try:
                    thread.quit()
                except Exception:
                    pass
                return
            thread.deleteLater()
        if worker:
            worker.deleteLater()
        self._current_run_thread = None
        self._current_run_worker = None
        self._current_run_dialog = None
        self._current_run_params = None
        self._run_stop_requested = False
        self._run_stop_reason = None

        if self._batch_continue_pending:
            self._batch_continue_pending = False
            if self._sanitized_batch_queue is not None:
                QTimer.singleShot(0, self._run_next_sanitized_batch)

    def _setup_batch_output_buffer(self, dialog: RunProgressDialog) -> None:
        # Reset per-run buffer.
        self._current_batch_output_buffer.clear()
        self._current_batch_output_dropped = 0

        timer = QTimer(self)
        timer.setInterval(max(10, int(RUN_BATCH_OUTPUT_FLUSH_INTERVAL_MS)))

        def _flush() -> None:
            self._flush_batch_output(dialog)

        timer.timeout.connect(_flush)
        timer.start()
        self._current_batch_output_timer = timer

    def _enqueue_batch_output(self, text: str) -> None:
        # Called on the GUI thread via Qt queued connection.
        if text is None:
            return
        line = str(text)
        buf = self._current_batch_output_buffer
        if len(buf) >= int(RUN_BATCH_OUTPUT_MAX_BUFFERED_LINES):
            self._current_batch_output_dropped += 1
            return
        buf.append(line)

    def _flush_batch_output(self, dialog: RunProgressDialog) -> None:
        buf = self._current_batch_output_buffer
        if not buf:
            return
        take = max(1, int(RUN_BATCH_OUTPUT_MAX_LINES_PER_FLUSH))
        parts: list[str] = []
        for _ in range(min(take, len(buf))):
            try:
                parts.append(buf.popleft())
            except IndexError:
                break
        if not parts:
            return
        combined = "".join(parts)
        try:
            dialog.append_output(combined)
        except Exception:
            pass
        if self._current_batch_output_dropped:
            dropped = self._current_batch_output_dropped
            self._current_batch_output_dropped = 0
            try:
                dialog.append_output(f"(output throttled; {dropped} line(s) dropped to keep UI responsive)\n")
            except Exception:
                pass

    def _on_run_success(
        self,
        binary_path: str,
        destination: str,
        *,
        record_entry: bool = True,
        run_label: str | None = None,
        parent_entry_id: str | None = None,
        sanitized_binary_path: str | None = None,
        is_sanitized_run: bool = False,
        target_args: list[str] | None = None,
        use_sudo: bool = False,
        module_filters: list[str] | None = None,
        pre_run_command: str | None = None,
    ) -> None:
        binary_name = Path(binary_path).name or binary_path
        self._append_console(
            f"[{self.active_project}] {binary_name} run completed. Log written to: {destination}"
        )
        if record_entry:
            self._record_run_entry(
                binary_path,
                destination,
                run_label=run_label,
                parent_entry_id=parent_entry_id,
                sanitized_binary_path=sanitized_binary_path,
                is_sanitized_run=is_sanitized_run,
                target_args=target_args,
                use_sudo=use_sudo,
                module_filters=module_filters,
                pre_run_command=pre_run_command,
            )

    def _on_run_failure(self, error: Exception | str) -> None:
        message = str(error)
        if self._password_error_requires_retry(message):
            self._clear_cached_sudo_password()
        self._append_console(f"Error running binary: {message}")
        QMessageBox.critical(self, "Run failed", message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = App()
    window.show()
    sys.exit(app.exec())