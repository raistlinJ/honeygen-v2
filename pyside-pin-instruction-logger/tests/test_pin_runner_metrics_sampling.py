from __future__ import annotations

from pathlib import Path
import time

import pytest

from src.services.pin_runner import PinRunner


pytestmark = pytest.mark.timeout(10)


class _FakeStdout:
    def __init__(self, trace_path: Path):
        self._trace_path = trace_path

    def __iter__(self):
        # Keep the process alive long enough for the sampler to run a few times.
        self._trace_path.write_text("trace")
        yield "hello\n"
        time.sleep(0.35)
        yield "done\n"


class _FakePopen:
    def __init__(self, trace_path: Path):
        self.pid = 4242
        self.stdout = _FakeStdout(trace_path)
        self.stdin = None
        self.returncode = 0
        self._poll_count = 0

    def poll(self):
        # Make the sampler see a running process briefly.
        self._poll_count += 1
        return None if self._poll_count < 4 else 0

    def wait(self, timeout=None):
        self.returncode = 0
        return 0


class _FakeStdoutWithTime:
    def __init__(self, trace_path: Path):
        self._trace_path = trace_path

    def __iter__(self):
        self._trace_path.write_text("trace")
        yield "User time (seconds): 1.25\n"
        yield "System time (seconds): 0.75\n"
        yield "Maximum resident set size (kbytes): 2048\n"


class _FakePopenWithTime:
    def __init__(self, trace_path: Path):
        self.pid = 4343
        self.stdout = _FakeStdoutWithTime(trace_path)
        self.stdin = None
        self.returncode = 0

    def poll(self):
        return 0

    def wait(self, timeout=None):
        self.returncode = 0
        return 0


def test_pin_runner_emits_cpu_load_series_even_for_short_run(tmp_path, monkeypatch):
    runner = PinRunner(pin_bin=tmp_path / "pin", tool_path=tmp_path / "tool.so")

    # Isolate runner paths to the tmp dir so the test doesn't write into the repo.
    runner.project_root = tmp_path
    runner.default_log = tmp_path / "pin_logs" / "instruction_log.txt"

    # Bypass filesystem/tool checks.
    monkeypatch.setattr(runner, "_ensure_pin_executable", lambda: Path("/bin/true"))
    monkeypatch.setattr(runner, "_ensure_tool_exists", lambda: Path("/bin/true"))

    # Fake out process creation.
    import src.services.pin_runner as pin_runner_module

    trace_path = runner.project_root / "instruction_log.txt"
    monkeypatch.setattr(
        pin_runner_module.subprocess,
        "Popen",
        lambda *args, **kwargs: _FakePopen(trace_path),
    )

    # Provide deterministic increasing CPU times for snapshots.
    seq = [(0.0, 0.0, 1000), (0.05, 0.01, 2000), (0.12, 0.03, 1500)]

    def _next_snapshot(pid: int):
        if seq:
            return seq.pop(0)
        return (0.12, 0.03, 1500)

    monkeypatch.setattr(runner, "_collect_process_tree_snapshot", _next_snapshot)

    out_log = tmp_path / "out.txt"
    target = tmp_path / "target.bin"
    target.write_text("x")

    runner.run(
        target,
        log_path=out_log,
        collect_cpu_metrics=True,
        collect_timing_metrics=True,
        collect_memory_metrics=True,
    )

    metrics = runner.last_metrics
    assert isinstance(metrics, dict)

    # Total CPU times should come from sampler-captured values.
    assert metrics.get("cpu_user_s") is not None
    assert metrics.get("cpu_system_s") is not None

    # Series should always exist when CPU metrics are enabled.
    series = metrics.get("cpu_load_1s")
    assert isinstance(series, list)
    assert len(series) >= 1
    assert series[0].get("t_s") == 0.0
    assert "cpu_percent" in series[0]


def test_pin_runner_parses_time_v_metrics_for_sudo_runs(tmp_path, monkeypatch):
    runner = PinRunner(pin_bin=tmp_path / "pin", tool_path=tmp_path / "tool.so")
    runner.project_root = tmp_path
    runner.default_log = tmp_path / "pin_logs" / "instruction_log.txt"

    # Bypass filesystem/tool checks.
    monkeypatch.setattr(runner, "_ensure_pin_executable", lambda: Path("/bin/true"))
    monkeypatch.setattr(runner, "_ensure_tool_exists", lambda: Path("/bin/true"))

    import src.services.pin_runner as pin_runner_module

    trace_path = runner.project_root / "instruction_log.txt"
    monkeypatch.setattr(
        pin_runner_module.subprocess,
        "Popen",
        lambda *args, **kwargs: _FakePopenWithTime(trace_path),
    )

    out_log = tmp_path / "out.txt"
    target = tmp_path / "target.bin"
    target.write_text("x")

    runner.run(
        target,
        log_path=out_log,
        use_sudo=True,
        sudo_password="pw",
        collect_cpu_metrics=True,
        collect_memory_metrics=True,
        collect_timing_metrics=True,
    )

    metrics = runner.last_metrics
    assert isinstance(metrics, dict)
    assert float(metrics.get("cpu_user_s") or 0.0) == pytest.approx(1.25)
    assert float(metrics.get("cpu_system_s") or 0.0) == pytest.approx(0.75)
    assert int(metrics.get("peak_rss_bytes") or 0) == 2048 * 1024
