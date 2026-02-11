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
def test_permission_denied_prompts_and_retries_with_sudo(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    app._current_run_dialog = app_module.RunProgressDialog(app, "target", on_stop=None)
    qtbot.addWidget(app._current_run_dialog)

    app._current_run_params = {
        "binary_path": str(tmp_path / "target"),
        "log_path": str(tmp_path / "log.txt"),
        "record_entry": False,
        "entry_to_refresh": None,
        "run_label": "r",
        "parent_entry_id": None,
        "sanitized_binary_path": None,
        "is_sanitized_run": False,
        "module_filters": None,
        "unique_only": False,
        "metrics_options": None,
        "target_args": None,
        "use_sudo": False,
        "pre_run_command": None,
        "sudo_retry_attempted": False,
        "suppress_failure_dialog": True,
        "batch_mode": False,
        "copy_binary_to_relative_path": False,
        "copy_sanitized_to_original_path": False,
    }

    prompted = {"count": 0}

    def _fake_obtain(prompt: str):
        prompted["count"] += 1
        app._cached_sudo_password = "correct"
        return "correct"

    monkeypatch.setattr(app, "_obtain_sudo_password", _fake_obtain)

    retried = {"called": False, "kwargs": None}

    def _fake_run_with_progress(*args, **kwargs):
        retried["called"] = True
        retried["kwargs"] = dict(kwargs)
        return True

    monkeypatch.setattr(app, "_run_with_progress", _fake_run_with_progress)

    app._handle_run_worker_failure("PIN exited with 1: Permission denied")

    assert prompted["count"] == 1
    assert retried["called"] is True
    assert bool(retried["kwargs"].get("run_with_sudo")) is True


@pytest.mark.qt_no_exception_capture
def test_permission_denied_does_not_prompt_in_batch_mode(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    app._current_run_dialog = app_module.RunProgressDialog(app, "target", on_stop=None)
    qtbot.addWidget(app._current_run_dialog)

    app._current_run_params = {
        "binary_path": str(tmp_path / "target"),
        "log_path": str(tmp_path / "log.txt"),
        "record_entry": False,
        "entry_to_refresh": None,
        "run_label": "r",
        "parent_entry_id": None,
        "sanitized_binary_path": None,
        "is_sanitized_run": False,
        "module_filters": None,
        "unique_only": False,
        "metrics_options": None,
        "target_args": None,
        "use_sudo": False,
        "pre_run_command": None,
        "sudo_retry_attempted": False,
        "suppress_failure_dialog": True,
        "batch_mode": True,
        "copy_binary_to_relative_path": False,
        "copy_sanitized_to_original_path": False,
    }

    monkeypatch.setattr(app, "_obtain_sudo_password", lambda prompt: (_ for _ in ()).throw(AssertionError("prompted")))
    monkeypatch.setattr(app, "_run_with_progress", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("retried")))

    # Should fall through normal failure handling without retry/prompt.
    app._handle_run_worker_failure("Permission denied")
