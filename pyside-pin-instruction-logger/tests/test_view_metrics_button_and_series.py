import pytest

from datetime import datetime
from pathlib import Path

import src.app as app_module
from src.config_manager import ConfigManager
from src.services.history_store import HistoryStore
from src.models.run_entry import RunEntry
from src.models.sanitized_output import SanitizedBinaryOutput


pytestmark = pytest.mark.timeout(15)


def _make_isolated_app(qtbot, tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "ConfigManager", lambda: ConfigManager(path=tmp_path / "app_settings.json"))
    monkeypatch.setattr(app_module, "HistoryStore", lambda: HistoryStore(path=tmp_path / "honey_history.json"))
    monkeypatch.setattr(app_module.App, "_refresh_revng_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module.App, "_refresh_revng_container_status", lambda *args, **kwargs: None)
    app = app_module.App()
    qtbot.addWidget(app)
    app._repo_root = tmp_path
    return app


@pytest.mark.qt_no_exception_capture
def test_view_metrics_enabled_for_multiselect_and_series_resolves(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    out1 = tmp_path / "san1"
    out2 = tmp_path / "san2"
    out1.write_text("x")
    out2.write_text("y")

    now = datetime.now()
    parent = RunEntry(
        entry_id="p1",
        name="parent",
        binary_path=str(tmp_path / "parentbin"),
        log_path=str(tmp_path / "parentlog"),
        timestamp=now,
        sanitized_outputs=[
            SanitizedBinaryOutput(output_id="o1", output_path=str(out1), works=None, generated_at=now),
            SanitizedBinaryOutput(output_id="o2", output_path=str(out2), works=None, generated_at=now),
        ],
        run_metrics={"wall_time_ms": 123.0},
    )
    san_run_1 = RunEntry(
        entry_id="s1",
        name="parent (Sanitized)",
        binary_path=str(out1),
        log_path=str(tmp_path / "sanlog1"),
        timestamp=now,
        sanitized_binary_path=str(out1),
        parent_entry_id=parent.entry_id,
        is_sanitized_run=True,
        run_metrics={"wall_time_ms": 456.0, "peak_rss_bytes": 1024 * 1024},
    )

    app.run_entries = [parent, san_run_1]
    app._refresh_entry_views(None)

    first = app.honey_sanitized_list.topLevelItem(0)
    second = app.honey_sanitized_list.topLevelItem(1)
    assert first is not None and second is not None
    first.setSelected(True)
    second.setSelected(True)

    app._update_sanitized_action_state()
    assert app.honey_view_metrics_button.isEnabled()

    selections = app._selected_sanitized_outputs()
    series = app._metrics_series_for_sanitized_selections(selections)
    labels = [item.label for item in series]
    assert any("(Original)" in label for label in labels)
    assert Path(str(out1)).name in labels


@pytest.mark.qt_no_exception_capture
def test_view_metrics_fallback_matches_by_binary_path(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    out1 = tmp_path / "san1"
    out1.write_text("x")
    now = datetime.now()

    parent = RunEntry(
        entry_id="p1",
        name="parent",
        binary_path=str(tmp_path / "parentbin"),
        log_path=str(tmp_path / "parentlog"),
        timestamp=now,
        sanitized_outputs=[SanitizedBinaryOutput(output_id="o1", output_path=str(out1), works=None, generated_at=now)],
        run_metrics={"wall_time_ms": 123.0},
    )

    # Simulate a sanitized run whose sanitized_binary_path metadata doesn't match the selected output
    # (e.g., copy-to-original path), but binary_path points at the selected output.
    san_run = RunEntry(
        entry_id="s1",
        name="parent (Sanitized)",
        binary_path=str(out1),
        log_path=str(tmp_path / "sanlog1"),
        timestamp=now,
        sanitized_binary_path=str(tmp_path / "different_location" / "san1"),
        parent_entry_id=parent.entry_id,
        is_sanitized_run=True,
        run_metrics={"wall_time_ms": 456.0, "peak_rss_bytes": 1024 * 1024},
    )

    app.run_entries = [parent, san_run]
    app._refresh_entry_views(None)

    selections = [(parent, parent.sanitized_outputs[0])]
    series = app._metrics_series_for_sanitized_selections(selections)
    labels = [item.label for item in series]
    assert any("(Original)" in label for label in labels)
    assert Path(str(out1)).name in labels
