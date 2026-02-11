from __future__ import annotations

import pytest

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
def test_build_permission_denied_prompts_and_retries_with_sudo(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)
    dialog = app_module.BuildProgressDialog(app)
    qtbot.addWidget(dialog)

    app._current_build_dialog = dialog
    app._current_build_thread = None
    app._current_build_worker = None
    app._current_build_params = {"use_sudo": False, "sudo_retry_attempted": False}

    prompted = {"count": 0}

    def _fake_obtain(prompt: str):
        prompted["count"] += 1
        app._cached_sudo_password = "correct"
        return "correct"

    monkeypatch.setattr(app, "_obtain_sudo_password", _fake_obtain)

    started = {"count": 0, "last": None}

    def _fake_start_build_worker(dialog_arg, *, use_sudo: bool, sudo_password: str | None, sudo_retry_attempted: bool):
        started["count"] += 1
        started["last"] = {
            "use_sudo": bool(use_sudo),
            "sudo_password": sudo_password,
            "sudo_retry_attempted": bool(sudo_retry_attempted),
        }

    monkeypatch.setattr(app, "_start_build_worker", _fake_start_build_worker)

    # Should not pop a QMessageBox when we're retrying; fail the test if called.
    monkeypatch.setattr(app_module.QMessageBox, "critical", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("dialog")))

    app._handle_build_worker_failure("Automatic PIN tool build failed: Permission denied")

    assert prompted["count"] == 1
    assert started["count"] == 1
    assert started["last"]["use_sudo"] is True
    assert started["last"]["sudo_password"] == "correct"
    assert started["last"]["sudo_retry_attempted"] is True
