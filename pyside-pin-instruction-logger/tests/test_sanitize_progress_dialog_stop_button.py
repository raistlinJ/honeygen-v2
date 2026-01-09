import pytest
from PySide6.QtCore import Qt

import src.app as app_module
from src.config_manager import ConfigManager
from src.services.history_store import HistoryStore


pytestmark = pytest.mark.timeout(10)


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
def test_sanitize_progress_dialog_has_stop_button_and_emits(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    dialog = app_module.SanitizeProgressDialog(app, "dummy")
    qtbot.addWidget(dialog)

    assert dialog.close_button is not None
    assert dialog.close_button.isEnabled() is False
    assert dialog.stop_button.isEnabled() is True

    fired = {"value": False}

    def _on_stop() -> None:
        fired["value"] = True

    dialog.stop_requested.connect(_on_stop)

    qtbot.mouseClick(dialog.stop_button, Qt.LeftButton)

    qtbot.waitUntil(lambda: fired["value"], timeout=1000)
    assert dialog.stop_button.isEnabled() is False


@pytest.mark.qt_no_exception_capture
def test_stop_button_can_cancel_current_sanitize_worker(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    class _DummyWorker:
        def __init__(self) -> None:
            self.cancel_called = False

        def cancel(self) -> None:
            self.cancel_called = True

    worker = _DummyWorker()
    dialog = app_module.SanitizeProgressDialog(app, "dummy")
    qtbot.addWidget(dialog)

    app._current_sanitize_worker = worker  # type: ignore[assignment]
    app._current_sanitize_dialog = dialog

    dialog.stop_requested.connect(app._request_cancel_current_sanitization)

    qtbot.mouseClick(dialog.stop_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: worker.cancel_called, timeout=1000)
