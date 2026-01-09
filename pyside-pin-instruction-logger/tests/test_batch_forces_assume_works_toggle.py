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
def test_batch_forces_assume_works_toggle(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    dialog = app_module.RunSanitizedOptionsDialog(
        app,
        default_run_with_sudo=False,
        force_assume_works=True,
    )
    qtbot.addWidget(dialog)

    assert dialog.assume_works_checkbox.isChecked() is True
    assert dialog.assume_works_checkbox.isEnabled() is False
    assert dialog.assume_works_ms_spin.isEnabled() is True

    opts = dialog.selected_options()
    assert opts.assume_works_if_running is True
