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
def test_execute_sanitized_uses_modules_from_dialog(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    out_path = tmp_path / "nginx.sanitized"
    out_path.write_text("x")

    now = datetime.now()
    entry = RunEntry(
        entry_id="e1",
        name="nginx",
        binary_path=str(tmp_path / "nginx"),
        log_path=str(tmp_path / "parentlog"),
        timestamp=now,
        module_filters=["libc.so.6"],
        sanitized_outputs=[SanitizedBinaryOutput(output_id="o1", output_path=str(out_path), works=None, generated_at=now)],
    )
    app.run_entries = [entry]
    app._refresh_entry_views(None)

    # Select the sanitized output row.
    first = app.honey_sanitized_list.topLevelItem(0)
    assert first is not None
    first.setSelected(True)

    # Auto-accept the options dialog.
    class _Options:
        run_with_pin = True
        collect_cpu_metrics = False
        collect_memory_metrics = False
        collect_timing_metrics = False
        run_with_sudo = False
        pre_run_command = None
        copy_to_original_path = False
        assume_works_if_running = False
        assume_works_after_ms = 0

    class _FakeOptionsDialog:
        def __init__(self, *a, **k):
            pass

        def set_invocation_preview(self, **k):
            pass

        def exec(self):
            return app_module.QDialog.Accepted

        def selected_options(self):
            return _Options

    monkeypatch.setattr(app_module, "RunSanitizedOptionsDialog", _FakeOptionsDialog)

    # Fake module dialog that returns a different module list than the entry has.
    desired_modules = ["nginx.sanitized", "libc.so.6"]

    class _FakeModuleDialog:
        def __init__(self, *a, **k):
            pass

        def exec(self):
            return app_module.QDialog.Accepted

        def selected_log_label(self):
            return "run"

        def unique_only(self):
            return False

        def selected_modules(self):
            return list(desired_modules)

    monkeypatch.setattr(app_module, "ModuleSelectionDialog", _FakeModuleDialog)

    captured = {"module_filters": None}

    def _fake_run_with_progress(*args, **kwargs):
        captured["module_filters"] = kwargs.get("module_filters")
        return True

    monkeypatch.setattr(app, "_run_with_progress", _fake_run_with_progress)

    app.execute_sanitized_binary()

    assert captured["module_filters"] == desired_modules
