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


@pytest.mark.qt_no_exception_capture
def test_batch_advances_after_success(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    # Force allow running without interactive prompts.
    monkeypatch.setattr(app, "_ensure_aslr_disabled_for_execution", lambda *a, **k: True)

    # Fake a still-active batch so cleanup will schedule the next item.
    app._sanitized_batch_queue = [{"entry_id": "e1", "output_id": "o1", "binary_path": "/bin/true"}]
    app._sanitized_batch_cancelled = False

    next_called = {"value": False}

    def _next() -> None:
        next_called["value"] = True

    monkeypatch.setattr(app, "_run_next_sanitized_batch", _next)

    def _fake_run_binary(*args, **kwargs):
        on_output = kwargs.get("on_output")
        if callable(on_output):
            on_output("hello\n")
        return tmp_path / "log.txt"

    monkeypatch.setattr(app.controller, "run_binary", _fake_run_binary)

    dialog = app_module.RunProgressDialog(app, "batch-test", on_stop=None)
    qtbot.addWidget(dialog)

    started = app._run_with_progress(
        "/bin/true",
        str(tmp_path / "log.txt"),
        record_entry=False,
        dialog_label="batch-test",
        is_sanitized_run=True,
        run_with_sudo=False,
        block=False,
        dialog=dialog,
        suppress_failure_dialog=True,
        batch_mode=True,
    )
    assert started is True

    qtbot.waitUntil(lambda: next_called["value"], timeout=5000)


@pytest.mark.qt_no_exception_capture
def test_batch_prints_summary_on_completion(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    class _DummyDialog:
        def __init__(self) -> None:
            self.outputs: list[str] = []
            self.finished: bool | None = None

        def append_output(self, text: str) -> None:
            self.outputs.append(str(text))

        def mark_finished(self, success: bool) -> None:
            self.finished = bool(success)

    dummy = _DummyDialog()
    app._sanitized_batch_dialog = dummy  # type: ignore[assignment]
    app._sanitized_batch_cancelled = False
    app._sanitized_batch_queue = []
    app._sanitized_batch_results = [
        app_module.BatchRunResult(binary_path="/tmp/a", outcome="OK", log_path="/tmp/a.log"),
        app_module.BatchRunResult(binary_path="/tmp/b", outcome="FAILED", log_path=None),
    ]

    app._run_next_sanitized_batch()

    combined = "".join(dummy.outputs)
    assert "Batch summary" in combined
    assert "- OK: /tmp/a -> /tmp/a.log" in combined
    assert "- FAILED: /tmp/b" in combined
    assert dummy.finished is True


@pytest.mark.qt_no_exception_capture
def test_assume_works_does_not_auto_terminate_single_run(qtbot, tmp_path, monkeypatch):
    import time as _time

    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    # Force allow running without interactive prompts.
    monkeypatch.setattr(app, "_ensure_aslr_disabled_for_execution", lambda *a, **k: True)

    terminate_called = {"value": False}

    def _fake_terminate(*args, **kwargs):
        terminate_called["value"] = True

    monkeypatch.setattr(app, "_request_terminate_current_run", _fake_terminate)
    monkeypatch.setattr(app.controller, "stop_logging", lambda: None)

    def _fake_run_binary(*args, **kwargs):
        on_output = kwargs.get("on_output")
        if callable(on_output):
            on_output("started")
        # Sleep long enough for the assume-works timer to fire.
        _time.sleep(0.15)
        return tmp_path / "log.txt"

    monkeypatch.setattr(app.controller, "run_binary", _fake_run_binary)

    dialog = app_module.RunProgressDialog(app, "single-assume-works", on_stop=None)
    qtbot.addWidget(dialog)

    started = app._run_with_progress(
        "/bin/true",
        str(tmp_path / "log.txt"),
        record_entry=False,
        dialog_label="single-assume-works",
        is_sanitized_run=True,
        assume_works_entry_id="missing",
        assume_works_output_id="missing",
        assume_works_after_ms=50,
        run_with_sudo=False,
        block=False,
        dialog=dialog,
        suppress_failure_dialog=True,
        batch_mode=False,
    )
    assert started is True

    qtbot.waitUntil(lambda: app._current_run_thread is None, timeout=5000)
    assert terminate_called["value"] is False
