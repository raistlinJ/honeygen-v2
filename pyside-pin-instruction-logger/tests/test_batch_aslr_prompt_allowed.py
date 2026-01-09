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
def test_batch_run_allows_aslr_prompt(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    seen = {"allow_prompt": None}

    def _fake_ensure(binary_label: str, *, allow_prompt: bool = True) -> bool:
        seen["allow_prompt"] = bool(allow_prompt)
        return True

    monkeypatch.setattr(app, "_ensure_aslr_disabled_for_execution", _fake_ensure)

    # Avoid running the real runner.
    def _fake_run_binary(*args, **kwargs):
        return tmp_path / "log.txt"

    monkeypatch.setattr(app.controller, "run_binary", _fake_run_binary)

    # Should call ASLR check with allow_prompt=True even in batch_mode.
    dialog = app_module.RunProgressDialog(app, "batch-aslr", on_stop=None)
    qtbot.addWidget(dialog)
    started = app._run_with_progress(
        "/bin/true",
        str(tmp_path / "log.txt"),
        record_entry=False,
        is_sanitized_run=True,
        block=False,
        dialog=dialog,
        batch_mode=True,
    )

    assert started is True
    qtbot.waitUntil(lambda: app._current_run_thread is None, timeout=5000)

    assert seen["allow_prompt"] is True
