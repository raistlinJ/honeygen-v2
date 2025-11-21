from __future__ import annotations

import os
import shutil
import string
import sys
import uuid
import subprocess
import difflib
from datetime import datetime
from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt, QObject, QThread, Signal, QUrl
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
)
from PySide6.QtGui import QDesktopServices, QAction

from controllers.runner import RunnerController
from config_manager import AppConfig, ConfigManager, DEFAULT_LOG_PATH
from models.run_entry import RunEntry
from services.history_store import HistoryStore
from services.log_analyzer import collect_executed_addresses, ExecutedAddressReport
from services.binary_sanitizer import BinarySanitizer, SanitizationResult


def _docker_revng_instructions(image: str = "revng/revng") -> str:
    repo = image or "revng/revng"
    return (
        "rev.ng CLI is required for sanitization but was not found on your PATH.\n\n"
        "Quick Docker-based setup using your configured image:\n"
        f"  docker pull {repo}\n"
        f"  docker run --rm -it {repo} revng --version\n\n"
        "Create a helper script (e.g., ~/bin/revng) that wraps the docker run command, then add it to PATH."
    )


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

    def __init__(self, controller: RunnerController, binary_path: str, log_path: str | None) -> None:
        super().__init__()
        self.controller = controller
        self.binary_path = binary_path
        self.log_path = log_path

    def run(self) -> None:
        try:
            result = self.controller.run_binary(
                self.binary_path,
                log_path=self.log_path,
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

    def __init__(self, entry_id: str, binary_path: Path, log_path: Path, output_path: Path) -> None:
        super().__init__()
        self.entry_id = entry_id
        self.binary_path = binary_path
        self.log_path = log_path
        self.output_path = output_path

    def run(self) -> None:
        try:
            self.progress.emit(f"Opening instruction log at: {self.log_path}")
            report: ExecutedAddressReport = collect_executed_addresses(self.log_path)
            executed = report.addresses
            parsed_rows = report.parsed_rows
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
            self.progress.emit("Running sanitizer...")
            sanitizer = BinarySanitizer()
            result = sanitizer.sanitize(self.binary_path, executed, self.output_path)
            self.succeeded.emit(result)
        except Exception as exc:  # pragma: no cover - GUI background task
            self.failed.emit(f"Sanitization failed for log '{self.log_path}': {exc}")


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


class ApplyOptionsDialog(QDialog):
    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setWindowTitle("Apply Options")
        layout = QVBoxLayout(self)

        self.remove_duplicates_checkbox = QCheckBox("Remove duplicate rows", self)
        layout.addWidget(self.remove_duplicates_checkbox)

        self.sort_checkbox = QCheckBox("Sort output", self)
        layout.addWidget(self.sort_checkbox)

        sort_row = QHBoxLayout()
        sort_row.addWidget(QLabel("Order:", self))
        self.sort_order_combo = QComboBox(self)
        self.sort_order_combo.addItem("Ascending", True)
        self.sort_order_combo.addItem("Descending", False)
        self.sort_order_combo.setEnabled(False)
        sort_row.addWidget(self.sort_order_combo)
        sort_row.addStretch()
        layout.addLayout(sort_row)

        self.uniform_checkbox = QCheckBox("Force row uniformity", self)
        self.uniform_checkbox.setEnabled(False)
        self.uniform_checkbox.setToolTip("Enable by reducing the preview to a single column.")
        layout.addWidget(self.uniform_checkbox)

        self.sort_checkbox.toggled.connect(self.sort_order_combo.setEnabled)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def set_uniform_available(self, available: bool) -> None:
        self.uniform_checkbox.setEnabled(available)
        if not available:
            self.uniform_checkbox.setChecked(False)
            self.uniform_checkbox.setToolTip("Enable by reducing the preview to a single column.")
        else:
            self.uniform_checkbox.setToolTip("Rows that differ from the majority length will be saved separately.")

    def selected_options(self) -> dict[str, object]:
        return {
            "remove_duplicates": self.remove_duplicates_checkbox.isChecked(),
            "sort_enabled": self.sort_checkbox.isChecked(),
            "sort_ascending": bool(self.sort_order_combo.currentData()),
            "force_uniform": self.uniform_checkbox.isChecked(),
        }
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
        self._current_column_mapping: list[int] = []
        self._explicit_removed_columns: set[int] = set()
        self._column_offset_adjustments: dict[int, int] = {}
        self._current_sort: tuple[int, bool] | None = None
        self._action_history: list[str] = []
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

        self.ghidra_path = QLineEdit(config_tab)
        self.ghidra_path.setPlaceholderText("Ghidra AnalyzeHeadless executable path")
        self.ghidra_path.setText(self.config.ghidra_path)
        self.ghidra_path.setReadOnly(True)
        self.ghidra_button = QPushButton("Select", config_tab)
        config_layout.addLayout(_build_config_row("Ghidra AnalyzeHeadless", self.ghidra_path, self.ghidra_button))

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
        self.logs_exec_label = QLabel("Executable: None", logs_tab)
        self.logs_list = QListWidget(logs_tab)
        self.logs_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.create_log_button = QPushButton("Execute Binary", logs_tab)
        self.delete_log_button = QPushButton("Delete Selected Log", logs_tab)
        self.log_preview_label = QLabel("Instruction Trace", logs_tab)
        self.log_preview = QTableWidget(logs_tab)
        self.log_preview.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.log_preview.setSelectionBehavior(QAbstractItemView.SelectColumns)
        self.log_preview.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.log_preview.verticalHeader().setVisible(False)
        header = self.log_preview.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionsClickable(True)
        header.setHighlightSections(True)
        self.log_preview_status = QLabel("", logs_tab)
        self.log_preview_status.setObjectName("logPreviewStatus")
        self.log_preview_status.setStyleSheet("color: #666; font-size: 11px;")
        preview_options = QHBoxLayout()
        self.log_delimiter_input = QLineEdit(logs_tab)
        self.log_delimiter_input.setPlaceholderText("Delimiter (space by default)")
        self.log_delimiter_input.setText(" ")
        preview_options.addWidget(QLabel("Delimiter:", logs_tab))
        preview_options.addWidget(self.log_delimiter_input)
        self.apply_delimiter_button = QPushButton("Apply", logs_tab)
        self.reset_columns_button = QPushButton("Reset Columns", logs_tab)
        self.apply_actions_button = QPushButton("Apply To File", logs_tab)
        preview_options.addWidget(self.apply_delimiter_button)
        preview_options.addWidget(self.reset_columns_button)
        preview_options.addWidget(self.apply_actions_button)
        self.log_actions_indicator = ClickableIndicator("Fix Actions: 0", logs_tab)
        self.log_actions_indicator.setToolTip("No fix actions recorded yet.")
        self.log_actions_indicator.setEnabled(False)
        self.log_actions_indicator.setStyleSheet("color: #1976d2; text-decoration: underline;")
        self.log_actions_indicator.clicked.connect(self._show_log_actions_popup)
        preview_options.addWidget(self.log_actions_indicator)
        preview_options.addStretch(1)
        header_row = QHBoxLayout()
        header_row.addWidget(self.logs_exec_label)
        header_row.addStretch(1)
        header_row.addWidget(self.create_log_button)
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
        preview_layout.addWidget(self.log_preview)
        preview_layout.addWidget(self.log_preview_status)
        preview_layout.addLayout(preview_options)

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
        entries_label = QLabel("HoneyProc Entries", honey_tab)
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
        self.honey_sanitize_button = QPushButton("Generate Sanitized Binary", honey_tab)
        self.honey_run_sanitized_button = QPushButton("Execute Sanitized", honey_tab)
        self.honey_reveal_button = QPushButton("Reveal Sanitized", honey_tab)
        self.honey_compare_button = QPushButton("Compare Logs", honey_tab)
        honey_buttons.addWidget(indicator_widget)
        honey_buttons.addWidget(self.honey_sanitize_button)
        honey_buttons.addWidget(self.honey_run_sanitized_button)
        honey_buttons.addWidget(self.honey_reveal_button)
        honey_buttons.addWidget(self.honey_compare_button)

        honey_layout.addWidget(entries_label)
        honey_layout.addWidget(self.honey_list)
        honey_layout.addLayout(honey_buttons)
        self.honey_sanitized_status = QLabel("Sanitized binary: Not generated.", honey_tab)
        self.honey_sanitized_status.setWordWrap(True)
        self.honey_parent_status = QLabel("Parent linkage: N/A", honey_tab)
        self.honey_parent_status.setWordWrap(True)
        honey_layout.addWidget(self.honey_sanitized_status)
        honey_layout.addWidget(self.honey_parent_status)
        honey_layout.addStretch()

        self.tabs.addTab(config_tab, "Configuration")
        self.tabs.addTab(logs_tab, "Logs")
        self.tabs.addTab(honey_tab, "HoneyProc")

        self.pin_button.clicked.connect(self.select_pin_root)
        self.binary_button.clicked.connect(self.select_binary)
        self.tool_button.clicked.connect(self.select_tool)
        self.build_tool_button.clicked.connect(self.build_tool)
        self.ghidra_button.clicked.connect(self.select_ghidra_path)
        self.revng_image_input.editingFinished.connect(self._handle_revng_image_edit)
        self.revng_image_reset_button.clicked.connect(self._reset_revng_image)
        self.log_delimiter_input.editingFinished.connect(self._refresh_log_preview_only)
        self.apply_delimiter_button.clicked.connect(self._refresh_log_preview_only)
        self.reset_columns_button.clicked.connect(self._reset_removed_columns)
        header.setContextMenuPolicy(Qt.CustomContextMenu)
        header.customContextMenuRequested.connect(self._show_header_context_menu)
        self.apply_actions_button.clicked.connect(self._persist_column_cuts_to_file)
        self.project_list.currentTextChanged.connect(self.change_active_project)
        self.project_list.customContextMenuRequested.connect(self._show_project_context_menu)
        self.create_log_button.clicked.connect(self.create_new_log_entry)
        self.delete_log_button.clicked.connect(self.delete_log_entry)
        self.logs_list.currentItemChanged.connect(self._handle_logs_selection_change)
        self.honey_list.currentItemChanged.connect(self._handle_honey_selection_change)
        self.honey_sanitize_button.clicked.connect(self.sanitize_honey_entry)
        self.honey_run_sanitized_button.clicked.connect(self.execute_sanitized_binary)
        self.honey_reveal_button.clicked.connect(self.reveal_sanitized_binary)
        self.honey_compare_button.clicked.connect(self.compare_sanitized_logs)
        self._update_honey_buttons()
        self._refresh_revng_status()
        self._refresh_revng_container_status()
        self._update_log_preview(None)

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
        self.logs_exec_label.setText(f"Executable: {Path(path).name}")
        self._append_console(f"Selected binary: {path}")

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

        output_path = self._sanitized_output_path(entry)
        self._ensure_directory(output_path)

        dialog = SanitizeProgressDialog(self, binary_path.name or entry.name)
        worker = SanitizeWorker(entry.entry_id, binary_path, log_path, output_path)
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

    def select_ghidra_path(self) -> None:
        current = self.ghidra_path.text().strip() or str(Path.home())
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Ghidra AnalyzeHeadless",
            current,
            "Executable files (*)",
        )
        if not path:
            return
        self.ghidra_path.setText(path)
        self.config.ghidra_path = path
        self.config_manager.save(self.config)
        self._append_console(f"Ghidra AnalyzeHeadless set to: {path}")

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
        log_path = str(self._project_log_path())
        self._run_and_record(self.selected_binary, log_path)

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
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        default_name = f"{Path(binary).name} @ {timestamp}"
        name, ok = QInputDialog.getText(self, "Execute Binary", "Run name:", text=default_name)
        run_label = name.strip()
        if not ok or not run_label:
            return
        log_path = str(self._project_log_path(run_label=run_label))
        self._run_with_progress(binary, log_path, run_label=run_label, dialog_label=run_label)

    def delete_log_entry(self) -> None:
        current_item = self.logs_list.currentItem()
        entry = self._entry_from_item(current_item)
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
            self.logs_exec_label.setText(f"Executable: {name}")
        else:
            self.logs_exec_label.setText("Executable: None")
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
        self.logs_exec_label.setText(f"Executable: {Path(binary_path).name}")
        self._persist_current_history()

    def _refresh_entry_views(self, newly_added_id: str | None = None) -> None:
        self.logs_list.blockSignals(True)
        self.honey_list.blockSignals(True)
        self.logs_list.clear()
        self.honey_list.clear()
        for entry in self.run_entries:
            label = entry.label()
            log_item = QListWidgetItem(label)
            log_item.setData(Qt.UserRole, entry.entry_id)
            honey_item = QListWidgetItem(label)
            honey_item.setData(Qt.UserRole, entry.entry_id)
            self.logs_list.addItem(log_item)
            self.honey_list.addItem(honey_item)
            if newly_added_id and entry.entry_id == newly_added_id:
                self.logs_list.setCurrentItem(log_item)
                self.honey_list.setCurrentItem(honey_item)
        if self.logs_list.count() > 0 and self.logs_list.currentRow() == -1:
            self.logs_list.setCurrentRow(0)
        if self.honey_list.count() > 0 and self.honey_list.currentRow() == -1:
            self.honey_list.setCurrentRow(0)
        self.logs_list.blockSignals(False)
        self.honey_list.blockSignals(False)
        self.update_log_detail_from_selection(self.logs_list.currentItem(), None)
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
        if not entry:
            self.honey_sanitized_status.setText("Sanitized binary: Select an entry.")
            if hasattr(self, "honey_parent_status"):
                self.honey_parent_status.setText("Parent linkage: Select an entry.")
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
            self._refresh_revng_container_status(verbose=True, allow_prompt=True)
            refresh_labels()
            if started:
                progress_bar.hide()
                status_label.setText(message or "rev.ng container started.")
                if self._revng_cli_available and self._revng_container_running:
                    dialog.accept()
                    return
            else:
                progress_bar.hide()
                status_label.setText(message or "Failed to start rev.ng container.")
                QMessageBox.critical(dialog, "rev.ng", status_label.text())
            start_button.setEnabled(True)

        start_button.clicked.connect(handle_start)
        buttons.rejected.connect(dialog.reject)
        dialog.finished.connect(lambda *_: self._apply_revng_indicator_state())
        refresh_labels()
        dialog.resize(460, 260)
        dialog.exec()

    def _update_honey_buttons(self, *_: object) -> None:
        entry = self._current_honey_entry()
        has_entry = entry is not None
        busy = self._has_active_sanitization()
        enabled = has_entry and not busy
        sanitized_ready = has_entry and self._sanitized_binary_ready(entry)
        sanitized_action_enabled = sanitized_ready and not busy
        compare_ready = self._resolve_compare_pair(entry) is not None
        if hasattr(self, "honey_sanitize_button"):
            self.honey_sanitize_button.setEnabled(enabled)
        if hasattr(self, "honey_run_sanitized_button"):
            self.honey_run_sanitized_button.setEnabled(sanitized_action_enabled)
        if hasattr(self, "honey_reveal_button"):
            self.honey_reveal_button.setEnabled(sanitized_action_enabled)
        if hasattr(self, "honey_compare_button"):
            self.honey_compare_button.setEnabled(has_entry and compare_ready and not busy)

    def _handle_logs_selection_change(self, current: QListWidgetItem | None, previous: QListWidgetItem | None) -> None:
        self.update_log_detail_from_selection(current, previous)
        entry = self._entry_from_item(current)
        entry_id = entry.entry_id if entry else None
        self._sync_selection_to_entry(self.honey_list, entry_id)
        if hasattr(self, "delete_log_button"):
            self.delete_log_button.setEnabled(entry is not None)

    def _handle_honey_selection_change(self, current: QListWidgetItem | None, _: QListWidgetItem | None) -> None:
        self._update_honey_buttons()
        entry = self._entry_from_item(current)
        entry_id = entry.entry_id if entry else None
        self._sync_selection_to_entry(self.logs_list, entry_id)
        self._update_honey_detail(entry)

    def _refresh_log_preview_only(self) -> None:
        if self._cached_log_lines:
            self._render_log_table()
            self._update_log_preview_status(
                self._cached_log_truncated,
                self._cached_log_path,
                len(self._cached_log_lines),
            )
            return
        entry = self._entry_from_item(self.logs_list.currentItem())
        self._update_log_preview(entry)

    def _update_log_preview(self, entry: RunEntry | None) -> None:
        if not hasattr(self, "log_preview"):
            return
        if hasattr(self, "delete_log_button"):
            self.delete_log_button.setEnabled(entry is not None)
        if entry and entry.binary_path:
            binary_name = Path(entry.binary_path).name or entry.binary_path
            self.logs_exec_label.setText(f"Executable: {binary_name}")
        else:
            self.logs_exec_label.setText("Executable: None")
        if entry and entry.log_path:
            path = Path(entry.log_path)
            self.log_preview_label.setText("Instruction Trace")
            need_reload = (
                entry.entry_id != self._cached_log_entry_id
                or path != self._cached_log_path
                or not self._cached_log_lines
            )
            if need_reload:
                if not path.exists():
                    self.log_preview.clear()
                    self._cached_log_lines = []
                    self._cached_log_entry_id = entry.entry_id
                    self._cached_log_path = path
                    self._cached_log_truncated = False
                    self._update_log_preview_status(False, path, 0)
                    return
                try:
                    lines, truncated = self._stream_log_lines(path, self._log_preview_max_chars)
                except OSError as exc:
                    self.log_preview.clear()
                    self._cached_log_lines = []
                    self._cached_log_entry_id = entry.entry_id
                    self._cached_log_path = path
                    self._cached_log_truncated = False
                    self._update_log_preview_status(False, path, 0)
                    self.log_preview_status.setText(f"Unable to read instruction log: {exc}")
                    return
                self._cached_log_lines = lines
                self._cached_log_truncated = truncated
                self._cached_log_path = path
                self._cached_log_entry_id = entry.entry_id
                self._explicit_removed_columns.clear()
                self._column_offset_adjustments.clear()
                self._current_sort = None
                self._reset_action_history()
            self._render_log_table()
            self._update_log_preview_status(
                self._cached_log_truncated,
                self._cached_log_path,
                len(self._cached_log_lines),
            )
        else:
            self.log_preview_label.setText("Instruction Trace")
            self._cached_log_lines = []
            self._cached_log_entry_id = None
            self._cached_log_path = None
            self._cached_log_truncated = False
            self._explicit_removed_columns.clear()
            self._column_offset_adjustments.clear()
            self._current_sort = None
            self._current_column_mapping = []
            self.log_preview.clear()
            self.log_preview.setRowCount(0)
            self.log_preview.setColumnCount(0)
            self._update_log_preview_status(False, None, 0)
            self._reset_action_history()
            self._refresh_transform_controls()

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

    def _render_log_table(self) -> None:
        if not hasattr(self, "log_preview"):
            return
        table = self.log_preview
        lines = getattr(self, "_cached_log_lines", [])
        if not lines:
            table.clear()
            table.setRowCount(0)
            table.setColumnCount(0)
            self._current_column_mapping = []
            self._refresh_transform_controls()
            return

        delimiter = self._effective_delimiter()
        remove_columns = set(self._explicit_removed_columns)

        raw_rows: list[list[str]] = []
        max_cols = 0
        for line in lines:
            columns = self._split_columns(line, delimiter)
            raw_rows.append(columns)
            if len(columns) > max_cols:
                max_cols = len(columns)

        if max_cols == 0:
            table.clear()
            table.setRowCount(0)
            table.setColumnCount(0)
            self._current_column_mapping = []
            self._refresh_transform_controls()
            return

        display_columns = [idx for idx in range(1, max_cols + 1) if idx not in remove_columns]
        if not display_columns:
            table.clear()
            table.setRowCount(0)
            table.setColumnCount(0)
            self._current_column_mapping = []
            self._refresh_transform_controls()
            return

        processed_rows: list[list[str]] = []
        for columns in raw_rows:
            adjusted = self._apply_offsets_to_row(columns)
            display_row: list[str] = []
            for original_index in display_columns:
                value = adjusted[original_index - 1] if original_index - 1 < len(adjusted) else ""
                display_row.append(value)
            processed_rows.append(display_row)

        sort_position: int | None = None
        if self._current_sort:
            try:
                sort_position = display_columns.index(self._current_sort[0])
            except ValueError:
                sort_position = None

        if sort_position is not None and processed_rows:
            ascending = self._current_sort[1]
            processed_rows.sort(
                key=lambda row: self._sort_key_for_value(row[sort_position]),
                reverse=not ascending,
            )

        self._current_column_mapping = display_columns
        table.setRowCount(len(processed_rows))
        table.setColumnCount(len(display_columns))
        header_labels = [f"Col {idx}" for idx in display_columns]
        table.setHorizontalHeaderLabels(header_labels)

        for row_idx, display_row in enumerate(processed_rows):
            for col_pos, value in enumerate(display_row):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                table.setItem(row_idx, col_pos, item)
        table.resizeColumnsToContents()
        self._refresh_transform_controls()

    def _refresh_transform_controls(self) -> None:
        if not hasattr(self, "apply_actions_button"):
            return
        has_columns = bool(self._current_column_mapping)
        self.apply_actions_button.setEnabled(has_columns)
        if hasattr(self, "reset_columns_button"):
            self.reset_columns_button.setEnabled(has_columns and bool(self._explicit_removed_columns))

    def _selected_column_indices(self) -> list[int]:
        table = getattr(self, "log_preview", None)
        if table is None or not self._current_column_mapping:
            return []
        selection_model = table.selectionModel()
        if selection_model is None:
            return []
        selected_columns = selection_model.selectedColumns()
        if selected_columns:
            columns = {index.column() for index in selected_columns}
        else:
            columns = {index.column() for index in selection_model.selectedIndexes()}
        original_indices: list[int] = []
        for col in sorted(columns):
            if 0 <= col < len(self._current_column_mapping):
                original_indices.append(self._current_column_mapping[col])
        return original_indices

    def _remove_columns_batch(self, original_indices: list[int]) -> None:
        new_indices = [idx for idx in original_indices if idx not in self._explicit_removed_columns]
        if not new_indices:
            return
        self._explicit_removed_columns.update(new_indices)
        if len(new_indices) == 1:
            self._record_action(f"Removed column {new_indices[0]}")
        else:
            joined = ", ".join(str(idx) for idx in sorted(new_indices))
            self._record_action(f"Removed columns {joined}")
        self._render_log_table()
        self._update_log_preview_status(
            self._cached_log_truncated,
            self._cached_log_path,
            len(self._cached_log_lines),
        )

    def _record_action(self, description: str) -> None:
        self._action_history.append(description)
        self._update_log_actions_indicator()
        self._refresh_transform_controls()

    def _reset_action_history(self) -> None:
        self._action_history.clear()
        self._update_log_actions_indicator()
        self._refresh_transform_controls()

    def _reload_current_log_preview(self) -> None:
        current_entry = self._entry_from_item(self.logs_list.currentItem()) if hasattr(self, "logs_list") else None
        self._update_log_preview(current_entry)

    def _show_header_context_menu(self, position):
        if not self._current_column_mapping:
            return
        header = self.log_preview.horizontalHeader()
        logical_index = header.logicalIndexAt(position)
        if logical_index < 0 or logical_index >= len(self._current_column_mapping):
            return
        original_idx = self._current_column_mapping[logical_index]
        selected_indices = self._selected_column_indices()
        if not selected_indices or original_idx not in selected_indices:
            selected_indices = [original_idx]
        menu = QMenu(self)
        remove_selected_action = menu.addAction(
            f"Remove Selected Columns ({len(selected_indices)})"
        )
        apply_offset_action = menu.addAction("Apply Offset…")
        clear_offset_action = None
        if original_idx in self._column_offset_adjustments:
            clear_offset_action = menu.addAction("Clear Offset")
        menu.addSeparator()
        sort_asc_action = menu.addAction("Sort Ascending")
        sort_desc_action = menu.addAction("Sort Descending")
        clear_sort_action = None
        if self._current_sort is not None:
            clear_sort_action = menu.addAction("Clear Sort")
        menu.addSeparator()
        clear_offsets_action = None
        if self._column_offset_adjustments:
            clear_offsets_action = menu.addAction("Clear All Offsets")

        action = menu.exec(header.mapToGlobal(position))
        if action is None:
            return
        if action == remove_selected_action:
            self._remove_columns_batch(selected_indices)
        elif action == apply_offset_action:
            self._apply_offset_for_column(original_idx)
        elif clear_offset_action and action == clear_offset_action:
            self._clear_offset_for_column(original_idx)
        elif action == sort_asc_action:
            self._apply_sort_for_column(original_idx, True)
        elif action == sort_desc_action:
            self._apply_sort_for_column(original_idx, False)
        elif clear_sort_action and action == clear_sort_action:
            self._clear_sort_transform()
        elif clear_offsets_action and action == clear_offsets_action:
            self._clear_offsets()

    def _apply_offset_for_column(self, original_idx: int) -> None:
        prompt = f"Hex delta for Col {original_idx} (e.g., 0x100 or -0x20):"
        value, ok = QInputDialog.getText(self, "Apply Offset", prompt)
        if not ok or not value.strip():
            return
        try:
            delta = self._parse_offset_delta(value.strip())
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid offset", str(exc))
            return
        self._column_offset_adjustments[original_idx] = delta
        self._record_action(f"Offset column {original_idx} by {value.strip()}")
        self._render_log_table()

    def _clear_offset_for_column(self, original_idx: int) -> None:
        if original_idx not in self._column_offset_adjustments:
            return
        self._column_offset_adjustments.pop(original_idx, None)
        self._record_action(f"Cleared offset for column {original_idx}")
        self._render_log_table()

    def _clear_offsets(self) -> None:
        if not self._column_offset_adjustments:
            return
        self._column_offset_adjustments.clear()
        self._record_action("Cleared all offsets")
        self._render_log_table()

    def _apply_sort_for_column(self, original_idx: int, ascending: bool) -> None:
        self._current_sort = (original_idx, ascending)
        direction = "ascending" if ascending else "descending"
        self._record_action(f"Sorted column {original_idx} {direction}")
        self._render_log_table()

    def _clear_sort_transform(self) -> None:
        if not self._current_sort:
            return
        self._current_sort = None
        self._record_action("Cleared sort")
        self._render_log_table()

    def _reset_removed_columns(self) -> None:
        if not self._explicit_removed_columns:
            return
        self._explicit_removed_columns.clear()
        self._record_action("Reset columns")
        self._render_log_table()
        self._update_log_preview_status(
            self._cached_log_truncated,
            self._cached_log_path,
            len(self._cached_log_lines),
        )

    def _has_active_transforms(self) -> bool:
        return bool(self._explicit_removed_columns or self._column_offset_adjustments or self._current_sort)

    def _export_current_log(
        self,
        destination: Path,
        *,
        overwrite_source: bool,
        remove_duplicates: bool = False,
        sort_override: tuple[int, bool] | None = None,
        force_uniform: bool = False,
    ) -> tuple[bool, Path | None, int]:
        if not self._cached_log_path:
            return False
        source_path = self._cached_log_path
        delimiter = self._effective_delimiter()
        removed = set(self._explicit_removed_columns)
        offsets = dict(self._column_offset_adjustments)
        sort_spec = sort_override if sort_override is not None else self._current_sort
        deduplicate = remove_duplicates
        joiner = delimiter if delimiter and delimiter != " " else " "
        if not source_path.exists():
            QMessageBox.warning(self, "Missing file", f"Instruction log not found: {source_path}")
            return False, None, 0
        try:
            total_bytes = max(source_path.stat().st_size, 1)
        except OSError as exc:
            QMessageBox.critical(self, "Unable to read", f"Failed to inspect log file: {exc}")
            return False, None, 0

        if force_uniform and len(self._current_column_mapping) != 1:
            force_uniform = False

        uniform_target: int | None = None
        if force_uniform:
            uniform_target = self._determine_uniform_length(source_path, delimiter, offsets, removed, joiner)
            if uniform_target is None:
                QMessageBox.information(self, "No data", "No rows available to enforce uniformity.")
                return False, None, 0

        rejected_path: Path | None = None
        rejected_count = 0

        action_label = "Applying fixes to log..." if overwrite_source else "Saving ready file..."
        progress_dialog = QProgressDialog(action_label, None, 0, 100, self)
        progress_dialog.setCancelButton(None)
        progress_dialog.setMinimumDuration(0)
        progress_dialog.setWindowTitle("Processing Log")
        progress_dialog.setWindowModality(Qt.ApplicationModal)
        progress_dialog.setValue(0)
        progress_dialog.show()

        temp_target = (
            source_path.with_suffix(source_path.suffix + ".tmp")
            if overwrite_source
            else destination.with_suffix(destination.suffix + ".tmp")
        )
        temp_target.parent.mkdir(parents=True, exist_ok=True)

        bytes_processed = 0
        update_counter = 0
        need_sort = sort_spec is not None
        processed_rows: list[tuple[tuple[int, object], int, str]] = []
        row_counter = 0

        try:
            with source_path.open("r", encoding="utf-8", errors="replace") as source:
                if not need_sort:
                    with temp_target.open("w", encoding="utf-8") as dest:
                        seen_rows: set[str] = set()
                        reject_handle = None
                        for raw_line in source:
                            line = raw_line.rstrip("\n")
                            adjusted, row_text = self._process_line(line, delimiter, offsets, removed, joiner)
                            row_length = len(row_text)
                            if force_uniform and row_length != uniform_target:
                                if reject_handle is None:
                                    rejected_path = destination.with_name(
                                        f"{destination.stem}_nonuniform{destination.suffix or '.txt'}"
                                    )
                                    reject_handle = rejected_path.open("w", encoding="utf-8")
                                reject_handle.write(row_text + "\n")
                                rejected_count += 1
                            else:
                                if deduplicate:
                                    if row_text in seen_rows:
                                        bytes_processed += len(raw_line.encode("utf-8"))
                                        update_counter += 1
                                        if update_counter % 200 == 0 or bytes_processed >= total_bytes:
                                            progress = min(int(bytes_processed * 100 / total_bytes), 100)
                                            progress_dialog.setValue(progress)
                                            QApplication.processEvents()
                                        continue
                                    seen_rows.add(row_text)
                                dest.write(row_text + "\n")
                                row_counter += 1
                            bytes_processed += len(raw_line.encode("utf-8"))
                            update_counter += 1
                            if update_counter % 200 == 0 or bytes_processed >= total_bytes:
                                progress = min(int(bytes_processed * 100 / total_bytes), 100)
                                progress_dialog.setValue(progress)
                                QApplication.processEvents()
                        if reject_handle:
                            reject_handle.close()
                else:
                    progress_share = 70
                    sort_column, ascending = sort_spec
                    for raw_line in source:
                        line = raw_line.rstrip("\n")
                        adjusted, row_text = self._process_line(line, delimiter, offsets, removed, joiner)
                        target_value = adjusted[sort_column - 1] if sort_column - 1 < len(adjusted) else ""
                        key = self._sort_key_for_value(target_value)
                        processed_rows.append((key, row_counter, row_text, len(row_text)))
                        bytes_processed += len(raw_line.encode("utf-8"))
                        row_counter += 1
                        update_counter += 1
                        if update_counter % 200 == 0 or bytes_processed >= total_bytes:
                            progress = min(int(bytes_processed * progress_share / total_bytes), progress_share)
                            progress_dialog.setValue(progress)
                            QApplication.processEvents()
                    if processed_rows:
                        progress_dialog.setLabelText("Sorting rows...")
                        QApplication.processEvents()
                        processed_rows.sort(key=lambda item: (item[0], item[1]), reverse=not ascending)
                    if deduplicate:
                        deduped: list[tuple[tuple[int, object], int, str, int]] = []
                        seen_rows_sort: set[str] = set()
                        for entry in processed_rows:
                            row_text = entry[2]
                            if row_text in seen_rows_sort:
                                continue
                            seen_rows_sort.add(row_text)
                            deduped.append(entry)
                        processed_rows = deduped
                    if force_uniform:
                        reject_handle = None
                        kept_rows: list[tuple[tuple[int, object], int, str, int]] = []
                        for entry in processed_rows:
                            if entry[3] != uniform_target:
                                if reject_handle is None:
                                    rejected_path = destination.with_name(
                                        f"{destination.stem}_nonuniform{destination.suffix or '.txt'}"
                                    )
                                    reject_handle = rejected_path.open("w", encoding="utf-8")
                                reject_handle.write(entry[2] + "\n")
                                rejected_count += 1
                                continue
                            kept_rows.append(entry)
                        processed_rows = kept_rows
                        if reject_handle:
                            reject_handle.close()
                    progress_dialog.setLabelText("Writing ready file...")
                    with temp_target.open("w", encoding="utf-8") as dest:
                        total_rows = max(len(processed_rows), 1)
                        for idx, (_, _, row_text, _) in enumerate(processed_rows, start=1):
                            dest.write(row_text + "\n")
                            if idx % 1000 == 0 or idx == total_rows:
                                base = 85
                                progress = base + int(idx * 15 / total_rows)
                                progress_dialog.setValue(min(progress, 100))
                                QApplication.processEvents()
            target_path = source_path if overwrite_source else destination
            temp_target.replace(target_path)
            progress_dialog.setValue(100)
            if rejected_path and rejected_count == 0 and rejected_path.exists():
                try:
                    rejected_path.unlink()
                    rejected_path = None
                except OSError:
                    pass
            return True, rejected_path, rejected_count
        except OSError as exc:
            QMessageBox.critical(self, "Unable to write", f"Failed to write log file: {exc}")
            if temp_target.exists():
                try:
                    temp_target.unlink()
                except OSError:
                    pass
            if rejected_path and rejected_path.exists():
                try:
                    rejected_path.unlink()
                except OSError:
                    pass
            return False, None, 0
        finally:
            progress_dialog.close()

    def _apply_offsets_to_row(self, columns: list[str], offsets: dict[int, int] | None = None) -> list[str]:
        if not offsets:
            return list(columns)
        result = list(columns)
        for original_idx, delta in offsets.items():
            pos = original_idx - 1
            if 0 <= pos < len(result):
                new_value = self._offset_value(result[pos], delta)
                if new_value is not None:
                    result[pos] = new_value
        return result

    def _process_line(
        self,
        line: str,
        delimiter: str,
        offsets: dict[int, int],
        removed: set[int],
        joiner: str,
    ) -> tuple[list[str], str]:
        columns = self._split_columns(line, delimiter)
        adjusted = self._apply_offsets_to_row(columns, offsets)
        filtered = [value for idx, value in enumerate(adjusted, start=1) if idx not in removed]
        row_text = joiner.join(filtered) if filtered else ""
        return adjusted, row_text

    def _determine_uniform_length(
        self,
        source_path: Path,
        delimiter: str,
        offsets: dict[int, int],
        removed: set[int],
        joiner: str,
    ) -> int | None:
        counts: dict[int, int] = {}
        try:
            with source_path.open("r", encoding="utf-8", errors="replace") as source:
                for raw_line in source:
                    line = raw_line.rstrip("\n")
                    _, row_text = self._process_line(line, delimiter, offsets, removed, joiner)
                    counts[len(row_text)] = counts.get(len(row_text), 0) + 1
        except OSError:
            return None
        if not counts:
            return None
        return max(counts.items(), key=lambda item: (item[1], item[0]))[0]

    def _offset_value(self, raw_value: str, delta: int) -> str | None:
        parsed = self._try_parse_numeric_value(raw_value)
        if parsed is None:
            return None
        updated = parsed + delta
        return self._format_numeric_value(raw_value, updated)

    def _parse_offset_delta(self, text: str) -> int:
        cleaned = text.strip()
        if not cleaned:
            raise ValueError("Offset cannot be empty.")
        if cleaned.lower().startswith("0x") or cleaned.lower().startswith("-0x") or cleaned.lower().startswith("+0x"):
            return int(cleaned, 16)
        try:
            return int(cleaned, 16)
        except ValueError as exc:
            raise ValueError("Offsets must be hexadecimal values (e.g., 0x40 or -0x10).") from exc

    def _try_parse_numeric_value(self, value: str) -> int | None:
        stripped = value.strip()
        if not stripped:
            return None
        sign = 1
        if stripped[0] in "+-":
            sign = -1 if stripped[0] == "-" else 1
            stripped = stripped[1:]
        if not stripped:
            return None
        base = 10
        if stripped.lower().startswith("0x"):
            base = 16
            stripped = stripped[2:]
        elif any(ch in string.hexdigits[10:] for ch in stripped):
            base = 16
        if not stripped:
            return None
        try:
            number = int(stripped, base)
        except ValueError:
            return None
        return sign * number

    def _format_numeric_value(self, original: str, value: int) -> str:
        stripped = original.strip()
        if not stripped:
            return str(value)
        has_sign = stripped[0] in "+-"
        prefix = stripped[0] if has_sign else ""
        remainder = stripped[1:] if has_sign else stripped
        remainder_lower = remainder.lower()
        negative = value < 0
        abs_value = abs(value)
        if remainder_lower.startswith("0x"):
            formatted = f"0x{abs_value:x}"
        elif all(ch in string.hexdigits for ch in remainder) and any(ch.isalpha() for ch in remainder):
            digits = f"{abs_value:x}"
            if any(ch.isalpha() and ch.isupper() for ch in remainder):
                digits = digits.upper()
            formatted = digits
        else:
            formatted = str(abs_value)
        if negative:
            return "-" + formatted
        if prefix == "+":
            return "+" + formatted
        return formatted

    def _sort_key_for_value(self, value: str) -> tuple[int, object]:
        numeric = self._try_parse_numeric_value(value)
        if numeric is not None:
            return (0, numeric)
        return (1, value)

    def _persist_column_cuts_to_file(self) -> None:
        if not self._cached_log_path:
            QMessageBox.information(self, "No log selected", "Select a log entry before applying changes.")
            return
        if not self._current_column_mapping:
            QMessageBox.warning(self, "No columns", "Nothing to write back. Reset the view and try again.")
            return
        options_dialog = ApplyOptionsDialog(self)
        options_dialog.set_uniform_available(len(self._current_column_mapping) == 1)
        if options_dialog.exec() != QDialog.Accepted:
            return
        options = options_dialog.selected_options()
        remove_duplicates = bool(options.get("remove_duplicates"))
        sort_enabled = bool(options.get("sort_enabled"))
        sort_ascending = bool(options.get("sort_ascending", True))
        force_uniform = bool(options.get("force_uniform"))
        sort_override: tuple[int, bool] | None = None
        if sort_enabled:
            column_source = self._current_sort[0] if self._current_sort else None
            if column_source is None and self._current_column_mapping:
                column_source = self._current_column_mapping[0]
            if column_source is not None:
                sort_override = (column_source, sort_ascending)
            else:
                QMessageBox.warning(self, "Cannot sort", "No columns available to sort.")
                return
        if not self._has_active_transforms():
            if not remove_duplicates and sort_override is None:
                QMessageBox.information(
                    self,
                    "No changes",
                    "Select at least one fix (remove columns, offsets, sort, remove duplicates) before applying.",
                )
                return
        path = self._cached_log_path
        if not path.exists():
            QMessageBox.warning(self, "Missing file", f"Instruction log not found: {path}")
            return
        confirm = QMessageBox.question(
            self,
            "Apply column removal",
            "This will overwrite the log file with the current fixes applied. Continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        success, rejected_path, rejected_rows = self._export_current_log(
            path,
            overwrite_source=True,
            remove_duplicates=remove_duplicates,
            sort_override=sort_override,
            force_uniform=force_uniform,
        )
        if success:
            self._append_console(f"Applied fixes to log: {path}")
            self._explicit_removed_columns.clear()
            self._column_offset_adjustments.clear()
            self._current_sort = None
            self._cached_log_lines = []
            self._cached_log_entry_id = None
            self._cached_log_path = None
            self._cached_log_truncated = False
            self._reload_current_log_preview()
            self._reset_action_history()
            if rejected_rows and rejected_path:
                self._append_console(
                    f"Force uniformity removed {rejected_rows} rows. Saved to: {rejected_path}"
                )
                QMessageBox.information(
                    self,
                    "Rows removed",
                    f"{rejected_rows} rows did not match the majority length and were saved to:\n{rejected_path}",
                )

    def _effective_delimiter(self) -> str:
        if hasattr(self, "log_delimiter_input"):
            raw = self.log_delimiter_input.text()
            if raw:
                stripped = raw.rstrip("\n")
                return stripped if stripped.strip() else " "
        return " "

    def _split_columns(self, line: str, delimiter: str) -> list[str]:
        if not delimiter or delimiter == " ":
            return line.split()
        return line.split(delimiter)


    def _update_log_preview_status(self, truncated: bool, path: Path | None, line_count: int) -> None:
        if not hasattr(self, "log_preview_status"):
            return
        if path is None:
            self.log_preview_status.setText("Select an entry to view its instruction trace.")
            return
        if not path.exists():
            self.log_preview_status.setText(f"Instruction log not found: {path}")
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

        output_path = self._sanitized_output_path(entry)
        self._ensure_directory(output_path)

        dialog = SanitizeProgressDialog(self, binary_path.name or entry.name)
        worker = SanitizeWorker(entry.entry_id, binary_path, log_path, output_path)
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

        run_label = f"{entry.name} (Sanitized)"
        log_path = str(self._project_log_path(run_label=run_label))
        self._run_with_progress(
            str(path_obj),
            log_path,
            record_entry=True,
            entry_to_refresh=None,
            dialog_label=run_label,
            run_label=run_label,
            parent_entry_id=entry.entry_id,
            sanitized_binary_path=str(path_obj),
            is_sanitized_run=True,
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
        dialog.show()
        QApplication.processEvents()
        return dialog

    def _update_log_actions_indicator(self) -> None:
        indicator = getattr(self, "log_actions_indicator", None)
        if indicator is None:
            return
        count = len(self._action_history)
        indicator.setText(f"Fix Actions: {count}")
        indicator.setEnabled(count > 0)
        tooltip = "Click to view fix actions" if count else "No fix actions recorded yet."
        indicator.setToolTip(tooltip)

    def _show_log_actions_popup(self) -> None:
        if not self._action_history:
            QMessageBox.information(self, "Fix Actions", "No fix actions recorded yet.")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Fix Actions")
        layout = QVBoxLayout(dialog)
        list_widget = QListWidget(dialog)
        for idx, action in enumerate(self._action_history, start=1):
            list_widget.addItem(f"{idx}. {action}")
        list_widget.setSelectionMode(QAbstractItemView.NoSelection)
        layout.addWidget(list_widget)
        buttons = QDialogButtonBox(QDialogButtonBox.Close, dialog)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.resize(420, 280)
        dialog.exec()

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

    def _run_and_record(self, binary_path: str, log_path: str | None) -> None:
        binary_label = Path(binary_path).name or binary_path
        if not self._ensure_aslr_disabled_for_execution(binary_label):
            return
        try:
            result_path = self.controller.run_binary(binary_path, log_path=log_path)
            self._on_run_success(binary_path, str(result_path))
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
        worker = RunWorker(self.controller, binary_path, log_path)
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
        dialog = self._current_run_dialog
        params = self._current_run_params or {}
        binary_path = params.get("binary_path")
        record_entry = params.get("record_entry", True)
        entry_to_refresh = params.get("entry_to_refresh")
        run_label = params.get("run_label")
        parent_entry_id = params.get("parent_entry_id")
        sanitized_binary_path = params.get("sanitized_binary_path")
        is_sanitized_run = params.get("is_sanitized_run", False)
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