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
def test_batch_exited_early_but_daemon_exists_marks_working(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    now = datetime.now()
    out_path = tmp_path / "nginx.sanitized"
    out_path.write_text("x")

    entry = RunEntry(
        entry_id="e1",
        name="nginx",
        binary_path=str(tmp_path / "nginx"),
        log_path=str(tmp_path / "parentlog"),
        timestamp=now,
        sanitized_outputs=[SanitizedBinaryOutput(output_id="o1", output_path=str(out_path), works=None, generated_at=now)],
    )
    app.run_entries = [entry]

    # Make ASLR check a no-op.
    monkeypatch.setattr(app, "_ensure_aslr_disabled_for_execution", lambda *a, **k: True)
    # Pretend the daemonized process exists even though the PIN run exited quickly.
    monkeypatch.setattr(app, "_has_running_exe_process", lambda *a, **k: True)
    # Don't actually attempt cleanup.
    monkeypatch.setattr(app, "_terminate_lingering_exe_processes_async", lambda *a, **k: None)

    def _fake_run_binary(*args, **kwargs):
        return tmp_path / "log.txt"

    monkeypatch.setattr(app.controller, "run_binary", _fake_run_binary)

    dialog = app_module.RunProgressDialog(app, "batch-test", on_stop=None)
    qtbot.addWidget(dialog)

    started = app._run_with_progress(
        str(out_path),
        str(tmp_path / "log.txt"),
        record_entry=True,
        is_sanitized_run=True,
        assume_works_entry_id=entry.entry_id,
        assume_works_output_id="o1",
        assume_works_after_ms=5000,
        block=False,
        dialog=dialog,
        suppress_failure_dialog=True,
        batch_mode=True,
    )
    assert started is True

    qtbot.waitUntil(lambda: app._current_run_thread is None, timeout=5000)
    assert entry.sanitized_outputs[0].works is True
