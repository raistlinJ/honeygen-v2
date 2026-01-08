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
    # Keep project storage isolated from the repo during tests.
    app._repo_root = tmp_path
    return app


@pytest.mark.qt_no_exception_capture
def test_assume_works_termination_does_not_cancel_batch(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    # Fake an in-progress batch.
    app._sanitized_batch_queue = [{"entry_id": "e1", "output_id": "o1", "binary_path": "/bin/true"}]
    app._sanitized_batch_cancelled = False
    app._run_stop_requested = False
    app._run_stop_reason = None

    # Avoid touching real runner state.
    monkeypatch.setattr(app.controller, "stop_logging", lambda: None)

    app._request_terminate_current_run(reason="assume_works")

    assert app._run_stop_requested is True
    assert app._run_stop_reason == "assume_works"
    assert app._sanitized_batch_cancelled is False
    assert app._sanitized_batch_queue is not None
    assert len(app._sanitized_batch_queue) == 1


@pytest.mark.qt_no_exception_capture
def test_user_stop_cancels_batch(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    app._sanitized_batch_queue = [{"entry_id": "e1", "output_id": "o1", "binary_path": "/bin/true"}]
    app._sanitized_batch_cancelled = False
    app._run_stop_requested = False
    app._run_stop_reason = None

    monkeypatch.setattr(app.controller, "stop_logging", lambda: None)

    app._request_stop_current_run()

    assert app._run_stop_requested is True
    assert app._run_stop_reason == "user"
    assert app._sanitized_batch_cancelled is True
    assert app._sanitized_batch_queue == []
