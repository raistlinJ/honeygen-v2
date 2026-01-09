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
def test_sanitized_batch_schedules_with_default_inter_run_delay(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    calls: list[tuple[int, object]] = []

    def _fake_single_shot(delay_ms, callback):
        calls.append((int(delay_ms), callback))

    monkeypatch.setattr(app_module.QTimer, "singleShot", staticmethod(_fake_single_shot))

    app._sanitized_batch_queue = []
    app._schedule_next_sanitized_batch()

    assert calls == [(2000, app._run_next_sanitized_batch)]
