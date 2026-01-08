import pytest

from datetime import datetime, timedelta
from pathlib import Path

import src.app as app_module
from src.config_manager import ConfigManager
from src.services.history_store import HistoryStore
from src.models.run_entry import RunEntry
from src.models.sanitized_output import SanitizedBinaryOutput
from PySide6.QtWidgets import QAbstractItemView

pytestmark = pytest.mark.timeout(15)


def _make_isolated_app(qtbot, tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "ConfigManager", lambda: ConfigManager(path=tmp_path / "app_settings.json"))
    monkeypatch.setattr(app_module, "HistoryStore", lambda: HistoryStore(path=tmp_path / "honey_history.json"))
    monkeypatch.setattr(app_module.App, "_refresh_revng_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module.App, "_refresh_revng_container_status", lambda *args, **kwargs: None)
    app = app_module.App()
    qtbot.addWidget(app)
    # Keep project storage isolated from the repo during tests.
    app._repo_root = tmp_path
    return app


@pytest.mark.qt_no_exception_capture
def test_generated_sanitized_outputs_allows_multiselect_and_disables_other_buttons(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    out1 = tmp_path / "san1"
    out2 = tmp_path / "san2"
    out1.write_text("x")
    out2.write_text("y")

    now = datetime.now()
    entry = RunEntry(
        entry_id="e1",
        name="entry",
        binary_path=str(tmp_path / "parentbin"),
        log_path=str(tmp_path / "parentlog"),
        timestamp=now,
        sanitized_outputs=[
            SanitizedBinaryOutput(output_id="o1", output_path=str(out1), works=None, generated_at=now),
            SanitizedBinaryOutput(output_id="o2", output_path=str(out2), works=None, generated_at=now - timedelta(seconds=1)),
        ],
    )
    app.run_entries = [entry]
    app._refresh_entry_views(None)

    assert app.honey_sanitized_list.selectionMode() == QAbstractItemView.ExtendedSelection

    # Select two rows
    first = app.honey_sanitized_list.topLevelItem(0)
    second = app.honey_sanitized_list.topLevelItem(1)
    assert first is not None and second is not None
    first.setSelected(True)
    second.setSelected(True)

    app._update_sanitized_action_state()

    assert app.honey_delete_sanitized_button.isEnabled()
    assert app.honey_run_sanitized_button.isEnabled()
    assert not app.honey_reveal_button.isEnabled()
    assert not app.honey_compare_parent_button.isEnabled()
    assert not app.honey_compare_button.isEnabled()


@pytest.mark.qt_no_exception_capture
def test_delete_sanitized_binary_deletes_multiple_selected(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    out1 = tmp_path / "san1"
    out2 = tmp_path / "san2"
    out1.write_text("x")
    out2.write_text("y")

    now = datetime.now()
    entry = RunEntry(
        entry_id="e1",
        name="entry",
        binary_path=str(tmp_path / "parentbin"),
        log_path=str(tmp_path / "parentlog"),
        timestamp=now,
        sanitized_outputs=[
            SanitizedBinaryOutput(output_id="o1", output_path=str(out1), works=None, generated_at=now),
            SanitizedBinaryOutput(output_id="o2", output_path=str(out2), works=None, generated_at=now - timedelta(seconds=1)),
        ],
    )
    app.run_entries = [entry]
    app._refresh_entry_views(None)

    first = app.honey_sanitized_list.topLevelItem(0)
    second = app.honey_sanitized_list.topLevelItem(1)
    first.setSelected(True)
    second.setSelected(True)

    monkeypatch.setattr(app_module.QMessageBox, "question", lambda *args, **kwargs: app_module.QMessageBox.Yes)

    app.delete_sanitized_binary()

    assert not out1.exists()
    assert not out2.exists()
    assert entry.sanitized_outputs == []


@pytest.mark.qt_no_exception_capture
def test_execute_sanitized_binary_uses_batch_path_when_multiselect(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    out1 = tmp_path / "san1"
    out2 = tmp_path / "san2"
    out1.write_text("x")
    out2.write_text("y")

    now = datetime.now()
    entry = RunEntry(
        entry_id="e1",
        name="entry",
        binary_path=str(tmp_path / "parentbin"),
        log_path=str(tmp_path / "parentlog"),
        timestamp=now,
        sanitized_outputs=[
            SanitizedBinaryOutput(output_id="o1", output_path=str(out1), works=None, generated_at=now),
            SanitizedBinaryOutput(output_id="o2", output_path=str(out2), works=None, generated_at=now - timedelta(seconds=1)),
        ],
    )
    app.run_entries = [entry]
    app._refresh_entry_views(None)

    first = app.honey_sanitized_list.topLevelItem(0)
    second = app.honey_sanitized_list.topLevelItem(1)
    first.setSelected(True)
    second.setSelected(True)

    called = {"value": False}

    def _fake_batch(selections):
        called["value"] = True

    monkeypatch.setattr(app, "_execute_sanitized_binaries_batch", _fake_batch)

    app.execute_sanitized_binary()

    assert called["value"] is True
