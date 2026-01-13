from __future__ import annotations

from pathlib import Path
import sys
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


class _FakeStdin:
    def __init__(self):
        self.writes: list[str] = []

    def write(self, data: str):
        self.writes.append(data)

    def flush(self):
        return None

    def close(self):
        return None


class _FakeSidecarStdout:
    def __iter__(self):
        # Emit a few JSON samples (cumulative counters).
        yield '{"t_s": 0.00, "cpu_user_s": 0.00, "cpu_system_s": 0.00, "rss_bytes": 1000, "io_read_bytes": 0, "io_write_bytes": 0, "net_sent_bytes": 0, "net_recv_bytes": 0, "tracked_pids": 1, "alive_pids": 1}\n'
        yield '{"t_s": 0.20, "cpu_user_s": 0.05, "cpu_system_s": 0.01, "rss_bytes": 2000, "io_read_bytes": 128, "io_write_bytes": 64, "net_sent_bytes": 10, "net_recv_bytes": 20, "tracked_pids": 1, "alive_pids": 1}\n'
        yield '{"t_s": 0.40, "cpu_user_s": 0.12, "cpu_system_s": 0.03, "rss_bytes": 1500, "io_read_bytes": 256, "io_write_bytes": 160, "net_sent_bytes": 25, "net_recv_bytes": 45, "tracked_pids": 2, "alive_pids": 2}\n'


class _FakeSidecarStdoutNoPids:
    def __iter__(self):
        # Sidecar runs but fails to attach to any target processes.
        yield '{"t_s": 0.00, "cpu_user_s": 0.00, "cpu_system_s": 0.00, "rss_bytes": 0, "io_read_bytes": 0, "io_write_bytes": 0, "net_sent_bytes": 0, "net_recv_bytes": 0, "tracked_pids": 0, "alive_pids": 0}\n'
        yield '{"t_s": 0.20, "cpu_user_s": 0.00, "cpu_system_s": 0.00, "rss_bytes": 0, "io_read_bytes": 0, "io_write_bytes": 0, "net_sent_bytes": 0, "net_recv_bytes": 0, "tracked_pids": 0, "alive_pids": 0}\n'


class _FakeSidecarPopen:
    def __init__(self):
        self.pid = 5555
        self.stdout = _FakeSidecarStdout()
        self.stderr = None
        self.stdin = _FakeStdin()
        self.returncode = 0
        self._polls = 0

    def poll(self):
        self._polls += 1
        return None if self._polls < 3 else 0

    def terminate(self):
        self.returncode = 0

    def kill(self):
        self.returncode = 0

    def wait(self, timeout=None):
        self.returncode = 0
        return 0


class _FakeSidecarPopenNoPids(_FakeSidecarPopen):
    def __init__(self):
        super().__init__()
        self.stdout = _FakeSidecarStdoutNoPids()


class _FakeSudoStdout:
    def __init__(self, trace_path: Path):
        self._trace_path = trace_path

    def __iter__(self):
        self._trace_path.write_text("trace")
        yield "hello\n"
        time.sleep(0.25)
        yield "done\n"


class _FakeSudoPopen:
    def __init__(self, trace_path: Path):
        self.pid = 6666
        self.stdout = _FakeSudoStdout(trace_path)
        self.stderr = None
        self.stdin = _FakeStdin()
        self.returncode = 0
        self._poll_count = 0

    def poll(self):
        self._poll_count += 1
        return None if self._poll_count < 4 else 0

    def terminate(self):
        self.returncode = 0

    def kill(self):
        self.returncode = 0

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

    rss_series = metrics.get("rss_bytes_1s")
    assert isinstance(rss_series, list)
    assert len(rss_series) >= 1
    assert rss_series[0].get("t_s") == 0.0
    assert "rss_bytes" in rss_series[0]


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


def test_pin_runner_sudo_sidecar_emits_time_series_metrics(tmp_path, monkeypatch):
    runner = PinRunner(pin_bin=tmp_path / "pin", tool_path=tmp_path / "tool.so")
    runner.project_root = tmp_path
    runner.default_log = tmp_path / "pin_logs" / "instruction_log.txt"

    # Create a placeholder sidecar script so PinRunner enables the sidecar path.
    (tmp_path / "scripts").mkdir(parents=True, exist_ok=True)
    (tmp_path / "scripts" / "sudo_metrics_sidecar.py").write_text("# placeholder\n")

    monkeypatch.setattr(runner, "_ensure_pin_executable", lambda: Path("/bin/true"))
    monkeypatch.setattr(runner, "_ensure_tool_exists", lambda: Path("/bin/true"))

    import src.services.pin_runner as pin_runner_module

    trace_path = runner.project_root / "instruction_log.txt"
    popen_calls: list[list[str]] = []

    def _fake_popen(cmd, *args, **kwargs):
        # cmd is a list[str]
        popen_calls.append(list(cmd))
        if list(cmd[:4]) == ["sudo", "-S", "-p", ""] and len(cmd) >= 6 and cmd[4] == sys.executable:
            # Sidecar
            return _FakeSidecarPopen()
        # Main PIN process (also sudo-prefixed)
        return _FakeSudoPopen(trace_path)

    monkeypatch.setattr(pin_runner_module.subprocess, "Popen", _fake_popen)

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

    # /usr/bin/time -v may be enabled as a fallback even when the sidecar is running.
    assert any("/usr/bin/time" in " ".join(call) for call in popen_calls)

    metrics = runner.last_metrics
    assert isinstance(metrics, dict)

    series = metrics.get("cpu_load_1s")
    assert isinstance(series, list)
    assert len(series) >= 1

    rss_series = metrics.get("rss_bytes_1s")
    assert isinstance(rss_series, list)
    assert len(rss_series) >= 1
    assert "rss_bytes" in rss_series[0]

    # Sidecar-derived aggregate counters should exist.
    assert float(metrics.get("cpu_user_s") or 0.0) == pytest.approx(0.12)
    assert float(metrics.get("cpu_system_s") or 0.0) == pytest.approx(0.03)
    assert int(metrics.get("peak_rss_bytes") or 0) == 2000

    # Best-effort rate series should exist.
    assert isinstance(metrics.get("io_read_bps_1s"), list)
    assert isinstance(metrics.get("io_write_bps_1s"), list)
    assert isinstance(metrics.get("net_sent_bps_1s"), list)
    assert isinstance(metrics.get("net_recv_bps_1s"), list)


def test_pin_runner_sudo_sidecar_no_pids_falls_back_to_time_and_synthesizes_cpu_series(tmp_path, monkeypatch):
    runner = PinRunner(pin_bin=tmp_path / "pin", tool_path=tmp_path / "tool.so")
    runner.project_root = tmp_path
    runner.default_log = tmp_path / "pin_logs" / "instruction_log.txt"

    (tmp_path / "scripts").mkdir(parents=True, exist_ok=True)
    (tmp_path / "scripts" / "sudo_metrics_sidecar.py").write_text("# placeholder\n")

    monkeypatch.setattr(runner, "_ensure_pin_executable", lambda: Path("/bin/true"))
    monkeypatch.setattr(runner, "_ensure_tool_exists", lambda: Path("/bin/true"))

    import src.services.pin_runner as pin_runner_module

    trace_path = runner.project_root / "instruction_log.txt"
    popen_calls: list[list[str]] = []

    def _fake_popen(cmd, *args, **kwargs):
        popen_calls.append(list(cmd))
        if list(cmd[:4]) == ["sudo", "-S", "-p", ""] and len(cmd) >= 6 and cmd[4] == sys.executable:
            return _FakeSidecarPopenNoPids()
        return _FakePopenWithTime(trace_path)

    monkeypatch.setattr(pin_runner_module.subprocess, "Popen", _fake_popen)

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

    assert any("/usr/bin/time" in " ".join(call) for call in popen_calls)

    metrics = runner.last_metrics
    assert isinstance(metrics, dict)
    assert float(metrics.get("cpu_user_s") or 0.0) == pytest.approx(1.25)
    assert float(metrics.get("cpu_system_s") or 0.0) == pytest.approx(0.75)

    series = metrics.get("cpu_load_1s")
    assert isinstance(series, list)
    assert len(series) >= 1
    assert float(series[0].get("cpu_percent") or 0.0) > 0.0
