import pytest

from datetime import datetime
from pathlib import Path

import src.app as app_module
from src.config_manager import ConfigManager
from src.services.history_store import HistoryStore


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
def test_stop_requests_lingering_cleanup_for_single_sanitized_run(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    sanitized = tmp_path / "svc.sanitized"
    sanitized.write_text("x")

    called = {}

    def _fake_cleanup(exe_path: str, started_after_epoch: float, *, use_sudo: bool):
        called["exe_path"] = exe_path
        called["started_after_epoch"] = started_after_epoch
        called["use_sudo"] = use_sudo

    monkeypatch.setattr(app, "_terminate_lingering_exe_processes_with_sudo_fallback_async", _fake_cleanup)
    monkeypatch.setattr(app, "_stop_logging_async", lambda: None)

    app._current_run_dialog = app_module.RunProgressDialog(app, "single", on_stop=None)
    qtbot.addWidget(app._current_run_dialog)

    now_epoch = 12345.0
    app._current_run_params = {
        "binary_path": str(sanitized),
        "is_sanitized_run": True,
        "assume_works_started_at_epoch": now_epoch,
        "use_sudo": True,
    }
    app._run_stop_requested = False
    app._run_stop_reason = None

    app._request_stop_current_run()

    assert app._run_stop_requested is True
    assert called.get("exe_path") == str(sanitized)
    assert called.get("started_after_epoch") == now_epoch
    assert called.get("use_sudo") is True


def test_lingering_cleanup_sudo_fallback_uses_pkill(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    sanitized = tmp_path / "svc.sanitized"
    sanitized.write_text("x")
    resolved = str(sanitized.resolve())
    pattern = app_module.re.escape(resolved)

    monkeypatch.setattr(app, "_terminate_lingering_exe_processes", lambda *args, **kwargs: None)
    monkeypatch.setattr(app, "_obtain_sudo_password", lambda prompt: "pw")
    monkeypatch.setattr(app, "_password_error_requires_retry", lambda lowered: False)
    monkeypatch.setattr(app, "_clear_cached_sudo_password", lambda: None)

    console = []
    monkeypatch.setattr(app, "_append_console", lambda msg: console.append(msg))

    calls = []

    class _Completed:
        def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def _fake_run(cmd, input, capture_output, text, check):
        calls.append({"cmd": cmd, "input": input})
        return _Completed(0, "", "")

    monkeypatch.setattr(app_module.subprocess, "run", _fake_run)

    app._terminate_lingering_exe_processes_with_sudo_fallback(str(sanitized), 0.0, use_sudo=True)

    assert len(calls) == 1
    assert calls[0]["cmd"] == ["sudo", "-S", "-p", "", "pkill", "-TERM", "-f", "--", pattern]
    assert calls[0]["input"] == "pw\n"
    assert any("sudo pkill" in m for m in console)
