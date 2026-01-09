import threading
import time

import pytest


pytestmark = pytest.mark.timeout(10)


def test_stop_terminates_inflight_prerun_subprocess(monkeypatch):
    # Import inside test so module-level Qt imports don't impact collection.
    from src.app import RunWorker

    class _DummyController:
        def __init__(self) -> None:
            self.stop_called = False

        def run_binary(self, *args, **kwargs):  # pragma: no cover - should not be reached
            raise AssertionError("run_binary should not be reached when prerun is stopped")

        def stop_logging(self) -> None:
            self.stop_called = True

    controller = _DummyController()
    worker = RunWorker(
        controller,  # type: ignore[arg-type]
        "/bin/true",
        None,
        pre_run_command="sleep 30",
    )

    t = threading.Thread(target=worker.run, daemon=True)
    t.start()

    # Wait until the pre-run process has been started.
    deadline = time.time() + 2.0
    while time.time() < deadline:
        if getattr(worker, "_active_prerun_process", None) is not None:
            break
        time.sleep(0.01)
    assert getattr(worker, "_active_prerun_process", None) is not None

    worker.request_stop()
    t.join(timeout=2.0)
    assert t.is_alive() is False
    assert controller.stop_called is True
