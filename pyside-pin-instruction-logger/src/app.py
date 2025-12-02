from __future__ import annotations

import os
import time
import shutil
import string
import sys
import uuid
import subprocess
import difflib
import stat
from datetime import datetime
from pathlib import Path
from typing import Callable, NamedTuple
from bisect import bisect_left, bisect_right
from collections import deque

import lief
import capstone

from PySide6.QtCore import Qt, QObject, QThread, Signal, Slot, QUrl, QTimer
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
)
from PySide6.QtGui import QDesktopServices, QAction, QFont, QColor, QIcon, QPainter, QPixmap

from controllers.runner import RunnerController
from config_manager import AppConfig, ConfigManager, DEFAULT_LOG_PATH
from models.run_entry import RunEntry
from services.history_store import HistoryStore
from services import parser
from services.log_analyzer import collect_executed_addresses, compute_address_segments
from services.binary_sanitizer import BinarySanitizer, SanitizationResult, PreviewCancelled


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
SEQUENCE_ANALYZER_MAX_BINARY_INSTRUCTIONS = 20000
SEQUENCE_ANALYZER_MAX_TRACE_MATCHES = 5000


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
    ) -> None:
        super().__init__()
        self.controller = controller
        self.binary_path = binary_path
        self.log_path = log_path
        self.module_filters = list(module_filters) if module_filters else None

    def run(self) -> None:
        try:
            result = self.controller.run_binary(
                self.binary_path,
                log_path=self.log_path,
                module_filters=self.module_filters,
                on_output=self.output.emit,
            )
            self.succeeded.emit(str(result))
        except Exception as exc:  # pragma: no cover - GUI background task
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
        self.resize(760, 520)

    def append_output(self, text: str) -> None:
        self.output_view.appendPlainText(text)

    def mark_finished(self, success: bool) -> None:
        self._running = False
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(1)
        state = "completed" if success else "failed"
        self.status_label.setText(f"Run {state}.")
        if self.close_button:
            self.close_button.setEnabled(True)
        if self.stop_button:
            self.stop_button.setEnabled(False)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self._running:
            event.ignore()
            return
        super().closeEvent(event)

    def set_stop_callback(self, callback: Callable[[], None] | None) -> None:
        self._stop_callback = callback
        if self.stop_button:
            self.stop_button.setEnabled(callback is not None and self._running)

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
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Select Modules — {binary_label}")
        self._modules = modules
        self._previous = list(previous_selection or [])
        self._filename_builder = filename_builder
        layout = QVBoxLayout(self)
        description = QLabel(
            "Choose which modules to monitor while collecting the instruction log. "
            "Capturing more modules may slow down execution but provides broader coverage.",
            self,
        )
        description.setWordWrap(True)
        layout.addWidget(description)

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
    ) -> None:
        super().__init__()
        self.entry_id = entry_id
        self.binary_path = binary_path
        self.log_path = log_path
        self.output_path = output_path
        self.options = options
        self.executed_addresses = set(executed_addresses)
        self.parsed_rows = parsed_rows
        self.instruction_samples = instruction_samples

    def run(self) -> None:
        try:
            executed = set(self.executed_addresses)
            parsed_rows = self.parsed_rows
            self.progress.emit(
                f"Parsed {parsed_rows} instruction rows; {len(executed)} unique addresses will be preserved."
            )
            if not executed:
                self.failed.emit(
                    (
                        "No executed instructions were discovered in the log. "
                        f"Checked {parsed_rows} instruction rows from {self.log_path}."
                    )
                )
                return
            sanitizer = BinarySanitizer()
            binary_obj = None
            if self.options.sanity_check and self.instruction_samples:
                self.progress.emit("Validating logged instructions against binary...")
                binary_obj = lief.parse(str(self.binary_path))
                sanitizer.verify_logged_instructions(binary_obj, self.instruction_samples)
            self.progress.emit("Running sanitizer...")
            result = sanitizer.sanitize(
                self.binary_path,
                executed,
                self.output_path,
                forced_mode=self.options.permissions_mask,
                only_text_section=self.options.only_text_section,
                binary=binary_obj,
            )
            if self.options.sanity_check:
                self.progress.emit("Running sanity check on sanitized binary...")
                sanitizer.sanity_check(result.output_path)
                self.progress.emit("Sanity check passed.")
            self.succeeded.emit(result)
        except Exception as exc:  # pragma: no cover - GUI background task
            self.failed.emit(f"Sanitization failed for log '{self.log_path}': {exc}")


class SanitizeOptions(NamedTuple):
    sanity_check: bool
    output_name: str | None
    permissions_mask: int | None
    only_text_section: bool


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
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Sanitize Options")
        self.setModal(True)
        layout = QVBoxLayout(self)

        self.sanity_checkbox = QCheckBox("Sanity check", self)
        self.sanity_checkbox.setEnabled(sanity_allowed)
        if not sanity_allowed:
            self.sanity_checkbox.setChecked(False)
            self.sanity_checkbox.setToolTip("Sanity check unavailable: no executed instructions detected.")
        layout.addWidget(self.sanity_checkbox)

        self.only_text_checkbox = QCheckBox("Only .text section", self)
        self.only_text_checkbox.setToolTip("Restrict sanitization to instructions located in the binary's .text sections.")
        layout.addWidget(self.only_text_checkbox)

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

        self._apply_default_permissions(default_permissions)

        buttons = QDialogButtonBox(QDialogButtonBox.Cancel | QDialogButtonBox.Ok, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.resize(560, 380)

    def _apply_default_permissions(self, mode: int) -> None:
        self.read_checkbox.setChecked(bool(mode & stat.S_IRUSR))
        self.write_checkbox.setChecked(bool(mode & stat.S_IWUSR))
        self.exec_checkbox.setChecked(bool(mode & stat.S_IXUSR))

    def selected_options(self) -> SanitizeOptions:
        name = self.filename_input.text().strip()
        safe_name = Path(name).name if name else None
        permissions = self._build_permissions_mask()
        return SanitizeOptions(
            sanity_check=self.sanity_checkbox.isChecked(),
            output_name=safe_name,
            permissions_mask=permissions,
            only_text_section=self.only_text_checkbox.isChecked(),
        )

    def _build_permissions_mask(self) -> int:
        mask = 0
        if self.read_checkbox.isChecked():
            mask |= stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
        if self.write_checkbox.isChecked():
            mask |= stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
        if self.exec_checkbox.isChecked():
            mask |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        return mask


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
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Sanitization Preview — {entry_label}")
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
        self._binary_offset = 0
        self._rows = list(self._raw_rows)
        self._total_rows = len(self._rows)
        self._match_rows = 0
        self._sections: list[dict[str, object]] = []
        self._resolve_binary_rows()
        self._recompute_sections()
        self._current_section_index: int | None = None
        self._offset_thread: QThread | None = None
        self._offset_worker: OffsetRecalcWorker | None = None
        self._offset_progress_dialog: QProgressDialog | None = None

        layout = QVBoxLayout(self)

        description = QLabel(
            "Start with the overview to compare binary and trace address ranges. Click a section to inspect the"
            " underlying instructions.",
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
        self.copy_button = buttons.addButton("Copy Selection", QDialogButtonBox.ActionRole)
        self.copy_button.clicked.connect(self._copy_selected_rows)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._populate_overview_table()
        self._update_offset_label()
        self._show_overview()
        _resize_widget_to_screen(self)

    @staticmethod
    def _monospace_font(font):
        adjusted = QFont(font)
        # Prefer a monospace face while falling back gracefully on the system default.
        adjusted.setFamilies(["Monospace", "Courier New", adjusted.defaultFamily()])
        adjusted.setStyleHint(QFont.StyleHint.Monospace)
        return adjusted

    def _build_overview_widget(self) -> QWidget:
        widget = QWidget(self)
        layout = QVBoxLayout(widget)
        table = QTableWidget(0, 4, widget)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.verticalHeader().setVisible(False)
        table.setHorizontalHeaderLabels(["Section", "Binary Range", "Trace Range", "Status"])
        header = table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)

        table.cellDoubleClicked.connect(self._handle_overview_activation)
        layout.addWidget(table)
        self.overview_table = table
        empty_label = QLabel("No instruction samples were found in the trace for preview.", widget)
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

        def _finish() -> None:
            self._finalize_overview_selection()
            if progress_callback and sections:
                total = len(sections)
                progress_callback(f"Overview rows ready ({total}/{total})")
            if done_callback:
                done_callback()

        if done_callback is None:
            for row_idx, section in enumerate(sections):
                self._set_overview_row(row_idx, section)
            _finish()
            return

        total = len(sections)
        chunk = max(total // 20, 20) if total else 1

        def _process(start: int = 0) -> None:
            end = min(start + chunk, total)
            for row_idx in range(start, end):
                self._set_overview_row(row_idx, sections[row_idx])
            if progress_callback:
                progress_callback(f"Populating overview rows ({end}/{total})")
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
        status_item = QTableWidgetItem(self._section_label(section["state"]))
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
        table.setHorizontalHeaderLabels(["Address", "Binary Instruction", "Logged Instruction"])
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
    ) -> list[dict[str, object]]:
        if segments:
            return InstructionPreviewDialog._build_segment_sections(
                rows,
                segments,
                offset=offset,
                raw_addresses=raw_addresses or [],
                sorted_values=sorted_values or [],
                sorted_pairs=sorted_pairs or [],
            )
        if not rows:
            return []
        sections: list[dict[str, object]] = []
        start = 0
        current_state = InstructionPreviewDialog._row_state(rows[0])
        for idx in range(1, len(rows)):
            state = InstructionPreviewDialog._row_state(rows[idx])
            if state != current_state:
                sections.append(InstructionPreviewDialog._make_section(rows, start, idx, current_state))
                start = idx
                current_state = state
        sections.append(InstructionPreviewDialog._make_section(rows, start, len(rows), current_state))
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
    ) -> list[dict[str, object]]:
        sections: list[dict[str, object]] = []
        if not segments:
            return sections
        total_rows = len(rows)
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
    def _row_state(row: tuple[int, str, str]) -> str:
        _, binary_text, logged_text = row
        binary_clean = (binary_text or "").strip()
        logged_clean = (logged_text or "").strip()
        if not binary_clean or binary_clean.startswith("<"):
            return "missing"
        if not logged_clean:
            return "missing"
        return "match" if binary_clean.lower() == logged_clean.lower() else "mismatch"

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

    def _section_label(self, state: str) -> str:
        return {
            "match": "Binary and trace match",
            "mismatch": "Differences detected",
            "missing": "Instruction unavailable",
        }.get(state, "Unknown")

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
        self.zoom_out_button.show()
        self.stack.setCurrentWidget(self.detail_widget)
        self._current_section_index = index
        self._update_copy_button_state()
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
            self._show_pending_offset_dialog(numeric)

        dialog.offset_selected.connect(_remember_offset)
        dialog.exec()
        if selected_offset["value"] is not None:
            self._apply_binary_offset(selected_offset["value"] or 0)

    def _show_pending_offset_dialog(self, offset_value: int) -> None:
        total_rows = len(self._raw_rows)
        label = (
            f"Applying offset {self._format_offset(offset_value)} (0/{total_rows})"
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
            f"Updating preview (0/{total_rows})"
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
            progress_dialog = self._offset_progress_dialog
            if progress_dialog:
                progress_dialog.setRange(0, 0)
                progress_dialog.setLabelText("Finalizing preview...")
                QApplication.processEvents()

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

            def _run_next_step() -> None:
                if not steps:
                    _cleanup()
                    return
                progress_dialog = self._offset_progress_dialog
                completed = steps_total - len(steps)
                label, async_step, func = steps.popleft()
                if progress_dialog:
                    suffix = f" ({completed + 1}/{steps_total})" if steps_total else ""
                    progress_dialog.setLabelText(f"{label}{suffix}")
                    QApplication.processEvents()

                def _continue() -> None:
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
            progress_dialog.setMaximum(current_total)
            progress_dialog.setValue(clamped)
            if total_rows:
                if clamped >= current_total:
                    self._update_offset_progress_label("Update complete. Finalizing preview...")
                else:
                    self._update_offset_progress_label(f"Updating preview ({clamped}/{current_total})")
            else:
                self._update_offset_progress_label("Updating preview...")

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

    def _update_offset_label(self) -> None:
        if hasattr(self, "offset_label"):
            self.offset_label.setText(f"Binary offset: {self._format_offset(self._binary_offset)}")

    @staticmethod
    def _format_offset(value: int) -> str:
        return f"{value:+#x}"

    def _resolve_binary_rows(self) -> None:
        resolver = getattr(self, "_binary_instruction_resolver", None)
        if resolver is None:
            return
        updated: list[tuple[int, str, str]] = []
        for address, binary_text, logged_text in self._rows:
            resolved = self._detail_binary_text(address, binary_text)
            updated.append((address, resolved, logged_text))
        self._rows = updated

    def _recompute_sections(self) -> None:
        self._match_rows = sum(1 for row in self._rows if self._row_state(row) == "match")
        self._sections = self._build_sections(
            self._rows,
            self._segments,
            offset=self._binary_offset,
            raw_addresses=self._raw_addresses,
            sorted_values=self._sorted_address_values,
            sorted_pairs=self._sorted_row_addresses,
        )

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
        looked_up = self._lookup_binary_instruction(address)
        if looked_up:
            return looked_up
        cleaned = (stored_text or "").strip()
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

    def _show_overview(self) -> None:
        if hasattr(self, "stack"):
            self.stack.setCurrentWidget(self.overview_widget)
        self.view_label.setText("Overview")
        self.zoom_out_button.hide()
        self._current_section_index = None
        self._update_copy_button_state()

    def _copy_selected_rows(self) -> None:
        if self.stack.currentWidget() != self.detail_widget:
            QApplication.clipboard().setText("")
            return
        table = self.detail_table
        selection = table.selectionModel()
        if selection is None or not selection.hasSelection():
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

    def _update_copy_button_state(self) -> None:
        if hasattr(self, "copy_button"):
            self.copy_button.setEnabled(self.stack.currentWidget() == self.detail_widget)


class SequenceAnalyzerDialog(QDialog):
    offset_selected = Signal(object)

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
        self._find_progress_dialog: QProgressDialog | None = None
        self._find_total_positions = 0
        self._matches: list[dict[str, object]] = []

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
        progress_dialog = QProgressDialog("Scanning trace...", "Cancel", 0, search_space, self)
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
        super().closeEvent(event)

    @staticmethod
    def _normalize_instruction(text: str | None) -> str:
        if not text:
            return ""
        return " ".join(text.lower().split())

    @staticmethod
    def _format_offset(value: int) -> str:
        sign = "+" if value >= 0 else "-"
        return f"{sign}0x{abs(value):x}"

    @staticmethod
    def _has_binary_instruction(text: str | None) -> bool:
        clean = (text or "").strip()
        return bool(clean) and not clean.startswith("<")


class DiffDialog(QDialog):
    def __init__(self, parent: QWidget, title: str, content: str) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        layout = QVBoxLayout(self)
        self.view = QPlainTextEdit(self)
        self.view.setReadOnly(True)
        self.view.setPlainText(content)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Close, self)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.view)
        layout.addWidget(self.buttons)
        self.resize(720, 520)


class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PIN Instruction Logger")
        self.resize(1280, 800)
        self.config_manager = ConfigManager()
        self.config: AppConfig = self.config_manager.load()
        self._default_tool_path_value = self._compute_default_tool_path()
        self._ensure_tool_path_default()
        self._repo_root = Path(__file__).resolve().parents[1]
        self._projects_root_migrated = False
        self.history_store = HistoryStore()
        self._legacy_projects_root: Path | None = None
        self.selected_binary: str | None = self.config.binary_path or None
        self.active_project: str = self.config.active_project or self.config.projects[0]
        self.run_entries: list[RunEntry] = []
        self._selection_syncing = False
        self._current_run_thread: QThread | None = None
        self._current_run_worker: RunWorker | None = None
        self._current_run_dialog: RunProgressDialog | None = None
        self._current_run_params: dict | None = None
        self._current_build_thread: QThread | None = None
        self._current_build_worker: BuildWorker | None = None
        self._current_build_dialog: BuildProgressDialog | None = None
        self._current_sanitize_thread: QThread | None = None
        self._current_sanitize_worker: SanitizeWorker | None = None
        self._current_sanitize_dialog: SanitizeProgressDialog | None = None
        self._current_sanitize_entry_id: str | None = None
        self._run_stop_requested = False
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
        self._segment_preview_job_counter = 0
        self._segment_preview_jobs: dict[int, dict[str, object]] = {}
        self._current_segment_job_id: int | None = None
        self._segment_preview_context: dict[str, object] | None = None
        self._segment_selection_updating = False
        self._active_segment_entry_id: str | None = None
        self._active_segment_row: int | None = None
        self._segment_preview_cache: dict[tuple[str, int, float], dict[str, object]] = {}
        self._sanitization_preview_thread: QThread | None = None
        self._sanitization_preview_worker: SanitizationPreviewWorker | None = None
        self._sanitization_preview_dialog: QProgressDialog | None = None
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
        self._gui_invoker = GuiInvoker(self)
        self._setup_ui()
        initial_log_path = self._project_log_path(self.active_project)
        self.controller = RunnerController(
            self,
            pin_root=self.config.pin_root,
            log_path=initial_log_path,
            tool_path=self.config.tool_path or None,
        )
        self._sync_log_destination_ui()
        self._load_history_for_active_project()

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

        self.pin_path = QLineEdit(config_tab)
        self.pin_path.setPlaceholderText("Set the Intel PIN directory")
        self.pin_path.setText(self.config.pin_root)
        self.pin_path.setReadOnly(True)
        self.pin_button = QPushButton("Select", config_tab)
        config_layout.addLayout(_build_config_row("Intel PIN directory", self.pin_path, self.pin_button))

        self.binary_path = QLineEdit(config_tab)
        self.binary_path.setPlaceholderText("Select target binary")
        self.binary_path.setText(self.config.binary_path)
        self.binary_path.setReadOnly(True)
        self.binary_button = QPushButton("Select", config_tab)
        config_layout.addLayout(_build_config_row("Target binary", self.binary_path, self.binary_button))

        self.tool_path = QLineEdit(config_tab)
        self.tool_path.setPlaceholderText("Intel PIN tool shared library path")
        self.tool_path.setText(self.config.tool_path)
        self.tool_button = QPushButton("Select", config_tab)
        self.build_tool_button = QPushButton("Build Tool", config_tab)
        tool_row = QHBoxLayout()
        label_tool = QLabel("PIN tool library", config_tab)
        label_tool.setMinimumWidth(150)
        tool_row.addWidget(label_tool)
        tool_row.addWidget(self.tool_path, 1)
        tool_row.addWidget(self.tool_button)
        tool_row.addWidget(self.build_tool_button)
        config_layout.addLayout(tool_row)

        self.revng_image_input = QLineEdit(config_tab)
        self.revng_image_input.setPlaceholderText("revng/revng")
        self.revng_image_input.setText(getattr(self.config, "revng_docker_image", "revng/revng"))
        self.revng_image_reset_button = QPushButton("Reset", config_tab)
        revng_row = QHBoxLayout()
        revng_label = QLabel("rev.ng Docker image", config_tab)
        revng_label.setMinimumWidth(150)
        revng_row.addWidget(revng_label)
        revng_row.addWidget(self.revng_image_input, 1)
        revng_row.addWidget(self.revng_image_reset_button)
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
        self.log_segments_label = QLabel("Segments", preview_panel)
        self.log_segments_label.setStyleSheet("font-weight: bold;")
        self.log_segments_table = QTableWidget(0, 4, preview_panel)
        self.log_segments_table.setHorizontalHeaderLabels(["#", "Start", "End", "Length"])
        header = self.log_segments_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.log_segments_table.verticalHeader().setVisible(False)
        self.log_segments_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.log_segments_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.log_segments_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.log_segments_table.itemSelectionChanged.connect(self._handle_segment_selection_changed)
        self.log_segments_table.setVisible(False)
        self.log_segments_label.setVisible(False)
        preview_layout.addWidget(self.log_segments_label)
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
        self.honey_list = QListWidget(honey_tab)
        self.honey_list.setSelectionMode(QAbstractItemView.SingleSelection)
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
        honey_buttons.addWidget(self.honey_run_sanitized_button)
        honey_buttons.addWidget(self.honey_reveal_button)
        honey_buttons.addWidget(self.honey_compare_button)

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
        honey_layout.addStretch()

        self.tabs.addTab(config_tab, "Configuration")
        self.tabs.addTab(logs_tab, "Logs")
        self.tabs.addTab(honey_tab, "HoneyProc")

        self.pin_button.clicked.connect(self.select_pin_root)
        self.binary_button.clicked.connect(self.select_binary)
        self.tool_button.clicked.connect(self.select_tool)
        self.build_tool_button.clicked.connect(self.build_tool)
        self.revng_image_input.editingFinished.connect(self._handle_revng_image_edit)
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
        self._update_honey_buttons()
        self._refresh_revng_status()
        self._refresh_revng_container_status()
        self._update_log_preview(None)
        self._update_honey_entries_label()

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
        return getattr(self.config, "revng_docker_image", "revng/revng") or "revng/revng"

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

    def _ensure_aslr_disabled_for_execution(self, binary_label: str) -> bool:
        ok, value = self._read_aslr_state()
        if not ok or value is None:
            return True
        if value == 0:
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

    def _ensure_tool_path_default(self) -> None:
        if self.config.tool_path:
            return
        default_tool = self._default_tool_path_value
        self.config.tool_path = str(default_tool)
        self.config_manager.save(self.config)

    def _apply_tool_path(self, path: Path) -> None:
        tool_str = str(path)
        self.tool_path.setText(tool_str)
        self.config.tool_path = tool_str
        self.config_manager.save(self.config)
        if hasattr(self, "controller"):
            self.controller.set_tool_path(path)

    def _update_tool_path_if_default_exists(self) -> None:
        default_tool = self._default_tool_path_value
        if default_tool.exists():
            self._apply_tool_path(default_tool)

    def select_pin_root(self) -> None:
        current_dir = self.config.pin_root or ""
        directory = QFileDialog.getExistingDirectory(self, "Select Intel PIN directory", current_dir)
        if not directory:
            return
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
        config_dialog = SanitizeConfigDialog(
            self,
            default_name=default_output_path.name,
            default_permissions=binary_path.stat().st_mode,
            sanity_allowed=sanity_allowed,
        )
        if config_dialog.exec() != QDialog.Accepted:
            self._append_console("Sanitization cancelled before launch.")
            return
        sanitize_options = config_dialog.selected_options()
        output_path = default_output_path
        if sanitize_options.output_name:
            output_path = default_output_path.with_name(sanitize_options.output_name)
        self._ensure_directory(output_path)

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
        current_value = getattr(self.config, "revng_docker_image", "revng/revng") or "revng/revng"
        self.revng_image_input.setText(new_value)
        if new_value == current_value:
            return
        self.config.revng_docker_image = new_value
        self.config_manager.save(self.config)
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
        next_index = min(project_index, len(self.config.projects) - 1)
        next_project = self.config.projects[next_index]

        self.project_list.blockSignals(True)
        self.project_list.takeItem(project_index)
        self.project_list.setCurrentRow(next_index)
        self.project_list.blockSignals(False)

        self.active_project = next_project
        self.config.active_project = next_project
        self.config_manager.save(self.config)
        self.run_entries = self.history_store.load_project(next_project)
        self._refresh_entry_views(None)
        self._delete_project_storage(project)
        self._sync_log_destination_ui()
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
        module_filters, log_label = dialog_result
        log_path = str(self._project_log_path(run_label=log_label))
        self._run_and_record(
            self.selected_binary,
            log_path,
            run_label=log_label,
            module_filters=module_filters,
        )

    def create_new_log_entry(self) -> None:
        if self._current_run_thread and self._current_run_thread.isRunning():
            QMessageBox.information(self, "Run in progress", "Please wait for the current log creation to finish.")
            return
        binary = (self.config.binary_path or "").strip()
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
        module_filters, log_label = dialog_result
        log_path = str(self._project_log_path(run_label=log_label))
        self._run_with_progress(
            binary,
            log_path,
            run_label=log_label,
            dialog_label=log_label,
            module_filters=module_filters,
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
        progress = QProgressDialog("Preparing HoneyProc data...", None, 0, 3, self)
        progress.setWindowTitle("Prepare for HoneyProc")
        progress.setCancelButton(None)
        progress.setWindowModality(Qt.ApplicationModal)
        progress.setMinimumDuration(0)
        progress.setValue(0)
        progress.setLabelText("Validating log selection...")
        progress.resize(580, 240)
        progress.show()
        QApplication.processEvents()

        button = getattr(self, "prepare_honey_button", None)
        if button is not None:
            button.setEnabled(False)

        def advance(step: int, label: str) -> None:
            progress.setValue(step)
            progress.setLabelText(label)
            QApplication.processEvents()

        try:
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
            advance(1, "Parsing instruction log...")
            try:
                parsed_entries = parser.parse_log(log_path)
            except Exception as exc:
                QMessageBox.critical(
                    self,
                    "Unable to parse log",
                    f"Failed to load the instruction log for preparation:\n{exc}",
                )
                return
            if not parsed_entries:
                QMessageBox.information(
                    self,
                    "Empty log",
                    "No instruction entries were discovered in the log. Nothing to prepare.",
                )
                return
            advance(2, "Computing contiguous segments...")
            addresses, segments = compute_address_segments(parsed_entries, max_gap=HONEY_SEGMENT_MAX_GAP)
            if not segments:
                QMessageBox.information(
                    self,
                    "No contiguous segments",
                    "Unable to derive contiguous memory segments from this log.",
                )
                return
            entry.prepared_segments = segments
            entry.prepared_at = datetime.now()
            self._persist_current_history()
            self._refresh_entry_views(entry.entry_id)
            segment_count = len(segments)
            address_count = len(addresses)
            self._append_console(
                f"Prepared '{entry.name}' for HoneyProc: {segment_count} segment(s) covering {address_count} addresses."
            )
            QMessageBox.information(
                self,
                "HoneyProc ready",
                (
                    f"'{entry.name}' is ready for HoneyProc.\n"
                    f"Segments detected: {segment_count}. Unique addresses: {address_count}."
                ),
            )
        finally:
            progress.setValue(progress.maximum())
            progress.close()
            self._update_prepare_button_state(self._current_log_entry())

    def change_active_project(self, project_name: str) -> None:
        if not project_name or project_name == self.active_project:
            return
        self._persist_current_history()
        self.active_project = project_name
        self.config.active_project = project_name
        self.config_manager.save(self.config)
        self._append_console(f"Active project switched to: {project_name}")
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
        self.config_manager.save(self.config)
        current_item.setText(project_name)
        self._persist_current_history()
        self._rename_project_storage(old_name, project_name)
        self._sync_log_destination_ui()
        self._append_console(f"Project renamed to: {project_name}")

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
        )
        self.run_entries.append(entry)
        self._refresh_entry_views(entry.entry_id)
        self.logs_exec_label.setText(f"Execution Logs for: {Path(binary_path).name}")
        self._persist_current_history()

    def _refresh_entry_views(self, newly_added_id: str | None = None) -> None:
        log_list = getattr(self, "logs_list", None)
        current_entry = self._current_log_entry()
        preferred_id = newly_added_id or (current_entry.entry_id if current_entry else None)

        if log_list is not None:
            log_list.blockSignals(True)
            log_list.clear()
        self.honey_list.blockSignals(True)
        self.honey_list.clear()

        for entry in self.run_entries:
            label = entry.label()
            if log_list is not None:
                log_item = QListWidgetItem(label)
                log_item.setData(Qt.UserRole, entry.entry_id)
                self._apply_log_item_indicator(log_item, entry)
                log_list.addItem(log_item)
            if self._entry_is_honey_ready(entry):
                honey_item = QListWidgetItem(label)
                honey_item.setData(Qt.UserRole, entry.entry_id)
                self.honey_list.addItem(honey_item)

        if log_list is not None:
            if log_list.count() > 0 and log_list.currentRow() == -1:
                log_list.setCurrentRow(0)
            log_list.blockSignals(False)
        if self.honey_list.count() > 0 and self.honey_list.currentRow() == -1:
            self.honey_list.setCurrentRow(0)
        self.honey_list.blockSignals(False)

        self._sync_log_lists_to_entry(preferred_id)
        self.update_log_detail_from_selection(self._current_log_item(), None)
        self._update_honey_buttons()
        self._update_honey_detail(self._current_honey_entry())

    def _entry_from_item(self, item: QListWidgetItem | None) -> RunEntry | None:
        if not item:
            return None
        entry_id = item.data(Qt.UserRole)
        return next((entry for entry in self.run_entries if entry.entry_id == entry_id), None)

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
        if mode == "segments":
            total = int(context.get("segments", 0) or 0)
            done = int(self._preview_progress.get("segments", 0) or 0)
            suffix = "segment" if total == 1 else "segments"
            label.setText(f"Collecting segment previews ({done}/{total} {suffix}) from {path_name}...")
        else:
            lines = int(self._preview_progress.get("lines", 0) or 0)
            label.setText(f"Streaming {path_name}: {lines} line(s) buffered...")

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
            return
        worker = job.get("worker")
        if isinstance(worker, SegmentPreviewWorker):
            worker.cancel()

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
                else:
                    self.honey_parent_status.setText("Parent run: Not found in history.")
            else:
                sanitized_child = self._find_sanitized_child(entry)
                if sanitized_child:
                    self.honey_parent_status.setText(
                        f"Sanitized replay: {sanitized_child.name} ({sanitized_child.log_path or 'no log'})"
                    )
                else:
                    self.honey_parent_status.setText("Sanitized replay: Not generated.")
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
        sanitized_ready = has_entry and self._sanitized_binary_ready(entry)
        sanitized_action_enabled = sanitized_ready and not busy
        compare_ready = self._resolve_compare_pair(entry) is not None
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
        if hasattr(self, "honey_run_sanitized_button"):
            self.honey_run_sanitized_button.setEnabled(sanitized_action_enabled)
        if hasattr(self, "honey_reveal_button"):
            self.honey_reveal_button.setEnabled(sanitized_action_enabled)
        if hasattr(self, "honey_compare_button"):
            self.honey_compare_button.setEnabled(has_entry and compare_ready and not busy)

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
            candidate = (self.config.binary_path or "").strip() or None
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
        self.update_log_detail_from_selection(current, previous)
        entry = self._entry_from_item(current)
        entry_id = entry.entry_id if entry else None
        self._sync_selection_to_entry(self.honey_list, entry_id)
        if hasattr(self, "delete_log_button"):
            self.delete_log_button.setEnabled(entry is not None)
        self._update_prepare_button_state(entry)

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
        self.log_preview_label.setText("Instruction Trace")
        self._update_segments_view(entry)
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
                f"Select one of {segments} {suffix} to view the first and last {SEGMENT_EDGE_PREVIEW_LIMIT} instruction(s) in {path.name}."
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

    def _update_segments_view(self, entry: RunEntry | None) -> None:
        table = getattr(self, "log_segments_table", None)
        label = getattr(self, "log_segments_label", None)
        if table is None or label is None:
            return
        current_entry_id = entry.entry_id if entry else None
        if current_entry_id != self._active_segment_entry_id:
            self._active_segment_row = None
            self._active_segment_entry_id = current_entry_id
        segments = self._entry_segments(entry)
        if not segments:
            self._segment_selection_updating = True
            try:
                table.setRowCount(0)
                table.clearSelection()
            finally:
                self._segment_selection_updating = False
            table.hide()
            label.hide()
            self._segment_preview_context = None
            return
        table.setRowCount(len(segments))
        for row, (start, end) in enumerate(segments):
            index_item = QTableWidgetItem(str(row + 1))
            start_item = QTableWidgetItem(f"0x{start:x}")
            end_item = QTableWidgetItem(f"0x{end:x}")
            length_value = max((end - start) + 1, 1)
            length_item = QTableWidgetItem(f"{length_value:,}")
            length_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            table.setItem(row, 0, index_item)
            table.setItem(row, 1, start_item)
            table.setItem(row, 2, end_item)
            table.setItem(row, 3, length_item)
        label.show()
        table.show()

    def _handle_segment_selection_changed(self) -> None:
        if self._segment_selection_updating:
            return
        table = getattr(self, "log_segments_table", None)
        if table is None or table.selectionModel() is None:
            return
        selection = table.selectionModel().selectedRows()
        if not selection:
            self._active_segment_row = None
            return
        row = selection[0].row()
        entry = self._current_log_entry()
        if entry is None or not entry.log_path:
            self._active_segment_row = None
            return
        self._active_segment_entry_id = entry.entry_id
        self._active_segment_row = row
        path = Path(entry.log_path)
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

    def _cleanup_sanitization_preview_worker(self, *, wait: bool = True) -> None:
        # Ensure dialog/thread cleanup always runs on the GUI thread to avoid Qt warnings
        if QThread.currentThread() is not self.thread():
            self._gui_invoker.invoke.emit(lambda wait_flag=wait: self._cleanup_sanitization_preview_worker(wait=wait_flag))
            return
        dialog = self._sanitization_preview_dialog
        if dialog is not None:
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

    def _sync_selection_to_entry(self, target_list: QListWidget, entry_id: str | None) -> None:
        if self._selection_syncing:
            return
        self._selection_syncing = True
        try:
            if not entry_id:
                target_list.clearSelection()
                return
            for index in range(target_list.count()):
                item = target_list.item(index)
                if item.data(Qt.UserRole) == entry_id:
                    target_list.setCurrentItem(item)
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
                _finalize_preview()
                if not isinstance(payload, dict):
                    QMessageBox.critical(
                        self,
                        "Unable to prepare preview",
                        "Unexpected preview payload format.",
                    )
                    return
                combined_rows = list(payload.get("rows", []))
                if not combined_rows:
                    QMessageBox.information(
                        self,
                        "Preview unavailable",
                        "No instructions were returned for preview.",
                    )
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
                dialog = InstructionPreviewDialog(
                    self,
                    label,
                    combined_rows,
                    segments=preview_segments,
                    binary_path=binary_path,
                )
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
        config_dialog = SanitizeConfigDialog(
            self,
            default_name=default_output_path.name,
            default_permissions=binary_path.stat().st_mode,
            sanity_allowed=sanity_allowed,
        )
        if config_dialog.exec() != QDialog.Accepted:
            self._append_console("Sanitization cancelled before launch.")
            return
        sanitize_options = config_dialog.selected_options()
        output_path = default_output_path
        if sanitize_options.output_name:
            output_path = default_output_path.with_name(sanitize_options.output_name)
        self._ensure_directory(output_path)

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
            QMessageBox.information(self, "Run in progress", "Please wait for the current log creation to finish.")
            return
        entry = self._current_honey_entry()
        if not entry:
            QMessageBox.information(self, "No entry selected", "Select a HoneyProc entry first.")
            return
        sanitized_path = entry.sanitized_binary_path
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
            self._update_honey_detail(entry)
            self._update_honey_buttons()
            return

        default_label = f"{entry.name} (Sanitized)"
        dialog_result = self._prompt_module_selection(
            str(path_obj),
            default_log_label=default_label,
        )
        if dialog_result is None:
            return
        module_filters, log_label = dialog_result
        log_path = str(self._project_log_path(run_label=log_label))
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
            module_filters=module_filters,
        )

    def reveal_sanitized_binary(self) -> None:
        entry = self._current_honey_entry()
        if not entry or not entry.sanitized_binary_path:
            QMessageBox.information(self, "No sanitized binary", "Generate a sanitized binary to reveal it.")
            return
        path_obj = Path(entry.sanitized_binary_path)
        if not path_obj.exists():
            QMessageBox.warning(
                self,
                "Sanitized binary missing",
                f"Expected sanitized binary at {path_obj}, but it is not on disk.",
            )
            entry.sanitized_binary_path = None
            self._persist_current_history()
            self._update_honey_detail(entry)
            self._update_honey_buttons()
            return
        target = path_obj if path_obj.is_dir() else path_obj.parent
        opened = QDesktopServices.openUrl(QUrl.fromLocalFile(str(target)))
        if not opened:
            QMessageBox.warning(
                self,
                "Unable to open",
                "The operating system rejected the request to open the sanitized binary location.",
            )

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
        sanitized, original = pair
        sanitized_path = Path(sanitized.log_path)
        original_path = Path(original.log_path)
        try:
            sanitized_lines, sanitized_truncated = self._read_log_lines_for_diff(sanitized_path)
            original_lines, original_truncated = self._read_log_lines_for_diff(original_path)
        except RuntimeError as exc:
            QMessageBox.critical(self, "Unable to read logs", str(exc))
            return
        diff_lines = list(
            difflib.unified_diff(
                original_lines,
                sanitized_lines,
                fromfile=f"original:{original_path.name}",
                tofile=f"sanitized:{sanitized_path.name}",
                lineterm="",
                n=3,
            )
        )
        if not diff_lines:
            QMessageBox.information(
                self,
                "Logs match",
                "No differences detected between the original and sanitized logs (within sampled lines).",
            )
            return

        max_lines = 4000
        diff_truncated = False
        if len(diff_lines) > max_lines:
            diff_lines = diff_lines[:max_lines]
            diff_truncated = True
        footer: list[str] = []
        if original_truncated or sanitized_truncated:
            footer.append("Note: logs truncated while loading; diff may be partial.")
        if diff_truncated:
            footer.append("Diff output truncated for readability.")
        if footer:
            diff_lines.append("")
            diff_lines.extend(footer)

        content = "\n".join(diff_lines)
        title = f"Diff: {original.name} vs {sanitized.name}"
        dialog = DiffDialog(self, title, content)
        dialog.resize(900, 600)
        dialog.exec()

    def _load_history_for_active_project(self) -> None:
        self.run_entries = self.history_store.load_project(self.active_project)
        if self._upgrade_entry_paths():
            self._persist_current_history()
        self._refresh_entry_views(None)

    def _persist_current_history(self) -> None:
        self.history_store.save_project(self.active_project, self.run_entries)

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
    ) -> tuple[list[str], str] | None:
        modules = self._discover_binary_modules(binary_path)
        default_label = default_log_label or self._default_run_label(binary_path)
        builder = lambda value: str(self._project_log_path(run_label=(value.strip() or None)))
        display_name = Path(binary_path).name or str(binary_path)
        dialog = ModuleSelectionDialog(
            self,
            display_name,
            modules,
            default_log_label=default_label,
            filename_builder=builder,
            previous_selection=self._last_module_filters,
        )
        result = dialog.exec()
        if result != QDialog.Accepted:
            self._append_console("Run cancelled before launch.")
            return None
        selection = dialog.selected_modules()
        log_label = dialog.selected_log_label()
        if not selection or not log_label:
            return None
        self._last_module_filters = selection
        return selection, log_label

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._cancel_sanitization_preview()
        self._cleanup_sanitization_preview_worker()
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
            entry.sanitized_binary_path = str(result.output_path)
            self._persist_current_history()
            self._refresh_entry_views(entry.entry_id)
        else:
            self._refresh_entry_views(None)
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
    ) -> None:
        binary_label = Path(binary_path).name or binary_path
        if not self._ensure_aslr_disabled_for_execution(binary_label):
            return
        try:
            result_path = self.controller.run_binary(
                binary_path,
                log_path=log_path,
                module_filters=module_filters,
            )
            self._on_run_success(binary_path, str(result_path), run_label=run_label)
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
    ) -> None:
        binary_label = Path(binary_path).name or binary_path
        if not self._ensure_aslr_disabled_for_execution(binary_label):
            return
        self._run_stop_requested = False
        dialog = RunProgressDialog(
            self,
            dialog_label or Path(binary_path).name or binary_path,
            on_stop=self._request_stop_current_run,
        )
        worker = RunWorker(self.controller, binary_path, log_path, module_filters=module_filters)
        thread = QThread(self)
        worker.moveToThread(thread)

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
        }

        worker.succeeded.connect(self._handle_run_worker_success)
        worker.failed.connect(self._handle_run_worker_failure)
        thread.finished.connect(self._cleanup_run_worker)
        dialog.finished.connect(self._cleanup_run_worker)

        thread.started.connect(worker.run)
        thread.start()
        dialog.exec()
        self._cleanup_run_worker()

    def _request_stop_current_run(self) -> None:
        if self._run_stop_requested:
            return
        self._run_stop_requested = True
        self._append_console("Stop requested for current run.")
        if self._current_run_dialog:
            self._current_run_dialog.append_output("Stop requested. Attempting to terminate run...")
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
        dialog = self._current_run_dialog
        if dialog:
            dialog.append_output("Run completed successfully.")
            dialog.mark_finished(True)
        if binary_path:
            self._on_run_success(
                binary_path,
                log_path,
                record_entry=record_entry,
                run_label=run_label,
                parent_entry_id=parent_entry_id,
                sanitized_binary_path=sanitized_binary_path,
                is_sanitized_run=is_sanitized_run,
            )
        if entry_to_refresh:
            entry_to_refresh.log_path = log_path
            self._refresh_entry_views(entry_to_refresh.entry_id)
        self._run_stop_requested = False
        self._cleanup_run_worker()

    def _handle_run_worker_failure(self, error_message: str) -> None:
        dialog = self._current_run_dialog
        if dialog:
            if self._run_stop_requested:
                dialog.append_output("Run stopped by user.")
            else:
                dialog.append_output(f"Error: {error_message}")
            dialog.mark_finished(False)
        if self._run_stop_requested:
            self._append_console("Run stopped by user.")
            QMessageBox.information(self, "Run stopped", "Execution was stopped before completion.")
        else:
            self._on_run_failure(error_message)
        self._run_stop_requested = False
        self._cleanup_run_worker()

    def _cleanup_run_worker(self) -> None:
        thread = self._current_run_thread
        worker = self._current_run_worker
        dialog = self._current_run_dialog
        if thread is None and worker is None and dialog is None:
            return
        if thread:
            if thread.isRunning():
                thread.quit()
                thread.wait()
            thread.deleteLater()
        if worker:
            worker.deleteLater()
        self._current_run_thread = None
        self._current_run_worker = None
        self._current_run_dialog = None
        self._current_run_params = None
        self._run_stop_requested = False

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
            )

    def _on_run_failure(self, error: Exception | str) -> None:
        message = str(error)
        self._append_console(f"Error running binary: {message}")
        QMessageBox.critical(self, "Run failed", message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = App()
    window.show()
    sys.exit(app.exec())