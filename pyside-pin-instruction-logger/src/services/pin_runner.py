"""Helpers for invoking Intel PIN with the bundled instruction logger."""

from __future__ import annotations

from pathlib import Path
import subprocess
import os
import shutil
import sys
from typing import Callable, Sequence
import signal
import threading
import time
import json

PIN_ROOT_DEFAULT = Path("/home/researchdev/Downloads/pin4")


class PinRunner:
    """Run the bundled PIN tool against arbitrary binaries."""

    def __init__(
        self,
        pin_bin: Path | str | None = None,
        tool_path: Path | str | None = None,
        default_log: Path | str | None = None,
    ) -> None:
        project_root = Path(__file__).resolve().parents[2]
        self.project_root = project_root
        self.pin_bin = Path(pin_bin or PIN_ROOT_DEFAULT / "pin")
        self.pin_root = self.pin_bin.parent
        obj_dir = project_root / "pin-tool" / "obj-intel64"
        fallback_tool = obj_dir / "ins_logger.so"
        self.tool_path = Path(tool_path or fallback_tool)
        self.default_log = Path(default_log or (project_root / "pin_logs" / "instruction_log.txt"))
        self.default_log.parent.mkdir(parents=True, exist_ok=True)
        self._tool_trace_name = "instruction_log.txt"
        self._process: subprocess.Popen[str] | None = None
        self._pgid: int | None = None
        self.last_metrics: dict[str, object] | None = None
        self._sampler_stop: threading.Event | None = None
        self._sampler_thread: threading.Thread | None = None
        self._sudo_metrics_process: subprocess.Popen[str] | None = None
        self._sudo_metrics_stop: threading.Event | None = None
        self._sudo_metrics_thread: threading.Thread | None = None

    def _collect_process_tree_snapshot(self, pid: int) -> tuple[float, float, int]:
        """Return (cpu_user_s, cpu_system_s, rss_bytes_sum) for pid + children (best-effort)."""
        try:
            import psutil  # type: ignore
        except Exception:
            return 0.0, 0.0, 0

        try:
            root = psutil.Process(int(pid))
        except Exception:
            return 0.0, 0.0, 0

        procs = [root]
        try:
            procs.extend(root.children(recursive=True))
        except Exception:
            pass

        user_s = 0.0
        system_s = 0.0
        rss_sum = 0
        for proc in procs:
            try:
                times = proc.cpu_times()
                user_s += float(getattr(times, "user", 0.0) or 0.0)
                system_s += float(getattr(times, "system", 0.0) or 0.0)
            except Exception:
                pass
            try:
                mem = proc.memory_info()
                rss_sum += int(getattr(mem, "rss", 0) or 0)
            except Exception:
                pass
        return user_s, system_s, rss_sum

    def run(
        self,
        binary_path: Path | str,
        *,
        log_path: Path | str | None = None,
        modules: Sequence[str] | None = None,
        extra_target_args: Sequence[str] | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        on_output: Callable[[str], None] | None = None,
        unique_only: bool = False,
        use_sudo: bool = False,
        sudo_password: str | None = None,
        collect_cpu_metrics: bool = False,
        collect_memory_metrics: bool = False,
        collect_timing_metrics: bool = False,
    ) -> Path:
        binary = Path(binary_path)
        if not binary.exists():
            raise FileNotFoundError(f"Target binary '{binary}' was not found")

        pin_exe = self._ensure_pin_executable()
        tool = self._ensure_tool_exists()
        log_file = Path(log_path or self.default_log)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        instruction_trace = self.project_root / self._tool_trace_name
        if instruction_trace.exists():
            try:
                instruction_trace.unlink()
            except OSError:
                pass

        tool_args: list[str] = []
        if modules:
            joined = ",".join(part.strip() for part in modules if part and part.strip())
            if joined:
                tool_args.extend(["-modules", joined])
        if unique_only:
            tool_args.extend(["-unique_only", "1"])

        effective_target_args = list(extra_target_args or [])

        command: list[str] = [str(pin_exe), "-t", str(tool), *tool_args, "--", str(binary)]
        if effective_target_args:
            command.extend(effective_target_args)

        if on_output:
            on_output(f"Launching PIN for {binary.name}...")

        if on_output:
            on_output(f"[debug] cwd={self.project_root}")
            on_output(f"[debug] pin={pin_exe}")
            on_output(f"[debug] tool={tool}")
            on_output(f"[debug] target={binary}")
            on_output(f"[debug] command={' '.join(command)}")

            # If the target args include an sshd-style config flag, report file diagnostics.
            config_path: Path | None = None
            args_list = list(effective_target_args or [])
            for idx, token in enumerate(args_list):
                if token == "-f" and (idx + 1) < len(args_list):
                    config_path = Path(args_list[idx + 1])
                    break
                if token.startswith("-f") and len(token) > 2:
                    config_path = Path(token[2:])
                    break
            if config_path is not None:
                # Resolve relative paths against the runner cwd (project root).
                resolved = (self.project_root / config_path).resolve() if not config_path.is_absolute() else config_path
                try:
                    if str(config_path) == "/tmp/sshd_config_honeypot":
                        readable = resolved.exists() and os.access(str(resolved), os.R_OK)
                        if not readable:
                            on_output(
                                "[debug] warning: legacy sshd config '/tmp/sshd_config_honeypot' is not readable; "
                                "runner will not remap args (use the original-location run option or update args)."
                            )
                except Exception:
                    pass
                try:
                    st = resolved.stat()
                    on_output(
                        "[debug] sshd_config="
                        f"{resolved} mode={oct(st.st_mode & 0o777)} uid={st.st_uid} gid={st.st_gid} size={st.st_size}"
                    )
                except Exception as exc:
                    on_output(f"[debug] sshd_config={resolved} stat_failed={exc}")
                try:
                    data = resolved.read_bytes()
                    line1 = data.splitlines()[0] if data.splitlines() else b""
                    nul_count = data.count(b"\x00")
                    # Keep output short but useful.
                    preview = line1[:200]
                    on_output(f"[debug] sshd_config_line1={preview!r} nul_count={nul_count}")
                except Exception as exc:
                    on_output(f"[debug] sshd_config_read_failed={exc}")

        combined_env = os.environ.copy()
        combined_env.setdefault("PIN_ROOT", str(self.pin_root))
        if env:
            combined_env.update(env)

        def _preexec() -> None:
            os.setsid()
            try:
                import resource

                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except Exception:
                pass

        self.last_metrics = None
        want_metrics = bool(collect_cpu_metrics or collect_memory_metrics or collect_timing_metrics)
        start_monotonic = time.monotonic()
        start_epoch = time.time()

        use_sudo_sidecar_metrics = False
        sudo_sidecar_lines: list[str] = []
        sudo_sidecar_stop = threading.Event()
        sudo_sidecar_thread: threading.Thread | None = None
        sudo_sidecar_proc: subprocess.Popen[str] | None = None

        sidecar_script = self.project_root / "scripts" / "sudo_metrics_sidecar.py"
        if want_metrics and use_sudo and sudo_password and sidecar_script.exists():
            try:
                sidecar_cmd = [
                    "sudo",
                    "-S",
                    "-p",
                    "",
                    sys.executable,
                    str(sidecar_script),
                    "--exe",
                    str(binary.resolve()),
                    "--start-epoch",
                    str(float(start_epoch)),
                    "--interval",
                    "0.2",
                ]
                sudo_sidecar_proc = subprocess.Popen(
                    sidecar_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    cwd=self.project_root,
                    env=combined_env,
                    preexec_fn=_preexec,
                )
                self._sudo_metrics_process = sudo_sidecar_proc
                self._sudo_metrics_stop = sudo_sidecar_stop

                if sudo_sidecar_proc.stdin is not None:
                    try:
                        sudo_sidecar_proc.stdin.write(sudo_password + "\n")
                        sudo_sidecar_proc.stdin.flush()
                    except BrokenPipeError:
                        pass
                    finally:
                        try:
                            sudo_sidecar_proc.stdin.close()
                        except OSError:
                            pass

                def _drain_sidecar() -> None:
                    if sudo_sidecar_proc is None or sudo_sidecar_proc.stdout is None:
                        return
                    try:
                        for line in sudo_sidecar_proc.stdout:
                            if sudo_sidecar_stop.is_set():
                                break
                            clean = line.strip()
                            if clean:
                                sudo_sidecar_lines.append(clean)
                    except Exception:
                        return

                sudo_sidecar_thread = threading.Thread(target=_drain_sidecar, daemon=True)
                sudo_sidecar_thread.start()
                self._sudo_metrics_thread = sudo_sidecar_thread
                use_sudo_sidecar_metrics = True
            except Exception:
                use_sudo_sidecar_metrics = False
                sudo_sidecar_proc = None
                sudo_sidecar_thread = None
                self._sudo_metrics_process = None
                self._sudo_metrics_stop = None
                self._sudo_metrics_thread = None

        # When running under sudo, psutil often cannot read the target (root) process tree.
        # In that case, fall back to parsing `/usr/bin/time -v` output for aggregate CPU/RSS.
        use_time_metrics = False
        time_exe = Path("/usr/bin/time")
        if want_metrics and (collect_cpu_metrics or collect_memory_metrics):
            if use_sudo:
                # Even if a sudo sidecar is enabled, keep `/usr/bin/time -v` available as a
                # reliable aggregate fallback when the sidecar cannot attach.
                use_time_metrics = time_exe.exists()
            else:
                try:
                    import psutil  # type: ignore

                    _ = psutil
                except Exception:
                    use_time_metrics = time_exe.exists()

        if use_time_metrics:
            command = [str(time_exe), "-v", *command]

        if use_sudo:
            if not sudo_password:
                raise RuntimeError("Sudo password not provided.")
            command = ["sudo", "-S", "-p", "", *command]

        self._process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE if use_sudo else None,
            text=True,
            bufsize=1,
            env=combined_env,
            cwd=self.project_root,
            preexec_fn=_preexec,
        )

        peak_rss_bytes = 0
        last_cpu_user_s = 0.0
        last_cpu_system_s = 0.0
        cpu_load_buckets: dict[int, tuple[float, int]] = {}
        rss_buckets: dict[int, int] = {}
        time_user_s: float | None = None
        time_system_s: float | None = None
        time_max_rss_kb: int | None = None
        stop_sampler = threading.Event()
        sampler_thread: threading.Thread | None = None
        # Expose sampler handles so stop() can halt sampling before termination.
        self._sampler_stop = stop_sampler
        self._sampler_thread = None
        if want_metrics and self._process is not None and not use_time_metrics and not use_sudo:
            try:
                def _sample() -> None:
                    nonlocal peak_rss_bytes
                    nonlocal last_cpu_user_s
                    nonlocal last_cpu_system_s
                    pid = int(self._process.pid)

                    prev_t = time.monotonic()
                    prev_user_s = 0.0
                    prev_system_s = 0.0
                    try:
                        prev_user_s, prev_system_s, rss_sum = self._collect_process_tree_snapshot(pid)
                        if rss_sum > peak_rss_bytes:
                            peak_rss_bytes = rss_sum
                        last_cpu_user_s = prev_user_s
                        last_cpu_system_s = prev_system_s
                    except Exception:
                        pass

                    while not stop_sampler.is_set():
                        if self._process.poll() is not None:
                            break
                        now_t = time.monotonic()
                        user_s, system_s, rss_sum = self._collect_process_tree_snapshot(pid)
                        if rss_sum > peak_rss_bytes:
                            peak_rss_bytes = rss_sum
                        last_cpu_user_s = float(user_s or 0.0)
                        last_cpu_system_s = float(system_s or 0.0)

                        if collect_memory_metrics:
                            bucket = int(max(0.0, now_t - start_monotonic))
                            rss_buckets[bucket] = max(rss_buckets.get(bucket, 0), int(rss_sum or 0))

                        if collect_cpu_metrics:
                            dt = float(now_t - prev_t)
                            if dt > 0:
                                delta_cpu = (last_cpu_user_s + last_cpu_system_s) - (
                                    float(prev_user_s or 0.0) + float(prev_system_s or 0.0)
                                )
                                if delta_cpu >= 0:
                                    cpu_percent = float(delta_cpu / dt) * 100.0
                                    bucket = int(max(0.0, now_t - start_monotonic))
                                    prev_sum, prev_count = cpu_load_buckets.get(bucket, (0.0, 0))
                                    cpu_load_buckets[bucket] = (prev_sum + cpu_percent, prev_count + 1)

                            prev_t = now_t
                            prev_user_s = last_cpu_user_s
                            prev_system_s = last_cpu_system_s
                        stop_sampler.wait(0.2)

                sampler_thread = threading.Thread(target=_sample, daemon=True)
                sampler_thread.start()
                self._sampler_thread = sampler_thread
            except Exception:
                sampler_thread = None
                self._sampler_thread = None

        timeout_timer: threading.Timer | None = None
        timed_out = False
        if timeout and timeout > 0:
            def _expire() -> None:
                nonlocal timed_out
                timed_out = True
                try:
                    self.stop()
                except Exception:
                    pass

            timeout_timer = threading.Timer(float(timeout), _expire)
            timeout_timer.daemon = True
            timeout_timer.start()

        try:
            self._pgid = os.getpgid(self._process.pid)
        except Exception:
            self._pgid = None

        if use_sudo and self._process.stdin is not None:
            try:
                self._process.stdin.write(sudo_password + "\n")
                self._process.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                try:
                    self._process.stdin.close()
                except OSError:
                    pass
        stdout_lines: list[str] = []
        assert self._process.stdout is not None
        try:
            for line in self._process.stdout:
                clean_line = line.rstrip()
                if clean_line:
                    stdout_lines.append(clean_line)
                if on_output and clean_line:
                    on_output(clean_line)
        finally:
            if timeout_timer is not None:
                try:
                    timeout_timer.cancel()
                except Exception:
                    pass
            stop_sampler.set()
            if sampler_thread is not None:
                try:
                    sampler_thread.join(timeout=1.0)
                except Exception:
                    pass
            self._sampler_stop = None
            self._sampler_thread = None

            sudo_sidecar_stop.set()
            if sudo_sidecar_proc is not None:
                try:
                    sudo_sidecar_proc.terminate()
                except Exception:
                    pass
                try:
                    sudo_sidecar_proc.wait(timeout=1.0)
                except Exception:
                    try:
                        sudo_sidecar_proc.kill()
                    except Exception:
                        pass
            if sudo_sidecar_thread is not None:
                try:
                    sudo_sidecar_thread.join(timeout=1.0)
                except Exception:
                    pass
            self._sudo_metrics_process = None
            self._sudo_metrics_stop = None
            self._sudo_metrics_thread = None

        self._process.wait()

        if use_time_metrics and stdout_lines:
            for line in stdout_lines:
                stripped = line.strip()
                if stripped.startswith("User time (seconds):"):
                    try:
                        time_user_s = float(stripped.split(":", 1)[1].strip())
                    except Exception:
                        pass
                elif stripped.startswith("System time (seconds):"):
                    try:
                        time_system_s = float(stripped.split(":", 1)[1].strip())
                    except Exception:
                        pass
                elif stripped.startswith("Maximum resident set size (kbytes):"):
                    try:
                        time_max_rss_kb = int(float(stripped.split(":", 1)[1].strip()))
                    except Exception:
                        pass

        # Best-effort metrics capture.
        if want_metrics and self._process is not None:
            end_monotonic = time.monotonic()
            end_epoch = time.time()
            metrics: dict[str, object] = {
                "started_at": float(start_epoch),
                "ended_at": float(end_epoch),
            }
            if collect_timing_metrics:
                metrics["wall_time_ms"] = int(max(0.0, (end_monotonic - start_monotonic) * 1000.0))
            if collect_cpu_metrics:
                if use_time_metrics and (time_user_s is not None or time_system_s is not None):
                    metrics["cpu_user_s"] = float(time_user_s or 0.0)
                    metrics["cpu_system_s"] = float(time_system_s or 0.0)
                else:
                    metrics["cpu_user_s"] = float(last_cpu_user_s)
                    metrics["cpu_system_s"] = float(last_cpu_system_s)

                elapsed_s = max(0.0, float(end_monotonic - start_monotonic))
                # Round up to ensure a short run still has at least one bucket.
                duration_s = int(elapsed_s) if float(int(elapsed_s)) == elapsed_s else int(elapsed_s) + 1
                duration_s = max(1, duration_s)
                load_series: list[dict[str, float]] = []
                for second in range(0, duration_s):
                    sum_val, count_val = cpu_load_buckets.get(second, (0.0, 0))
                    avg = float(sum_val / count_val) if count_val else 0.0
                    load_series.append({"t_s": float(second), "cpu_percent": float(avg)})
                metrics["cpu_load_1s"] = load_series
            if collect_memory_metrics:
                if use_time_metrics and time_max_rss_kb is not None:
                    metrics["peak_rss_bytes"] = int(max(0, int(time_max_rss_kb) * 1024))
                else:
                    metrics["peak_rss_bytes"] = int(max(0, int(peak_rss_bytes)))

                # Provide an RSS time series for non-sudo psutil sampling.
                if (not use_time_metrics) and (not use_sudo):
                    elapsed_s = max(0.0, float(end_monotonic - start_monotonic))
                    duration_s = int(elapsed_s) if float(int(elapsed_s)) == elapsed_s else int(elapsed_s) + 1
                    duration_s = max(1, duration_s)
                    rss_series: list[dict[str, float]] = []
                    for second in range(0, duration_s):
                        rss_series.append({"t_s": float(second), "rss_bytes": float(rss_buckets.get(second, 0))})
                    metrics["rss_bytes_1s"] = rss_series

            if use_sudo_sidecar_metrics and sudo_sidecar_lines:
                sidecar_samples: list[dict[str, float | int]] = []
                sidecar_max_alive = 0
                sidecar_max_tracked = 0
                for line in sudo_sidecar_lines:
                    try:
                        data = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(data, dict):
                        continue
                    if "t_s" not in data:
                        continue
                    try:
                        t_s = float(data.get("t_s") or 0.0)
                    except Exception:
                        continue
                    try:
                        cpu_user_s = float(data.get("cpu_user_s") or 0.0)
                        cpu_system_s = float(data.get("cpu_system_s") or 0.0)
                        rss_bytes = int(data.get("rss_bytes") or 0)
                        io_read_bytes = int(data.get("io_read_bytes") or 0)
                        io_write_bytes = int(data.get("io_write_bytes") or 0)
                        net_sent_bytes = int(data.get("net_sent_bytes") or 0)
                        net_recv_bytes = int(data.get("net_recv_bytes") or 0)
                        tracked_pids = int(data.get("tracked_pids") or 0)
                        alive_pids = int(data.get("alive_pids") or 0)
                    except Exception:
                        continue

                    sidecar_max_tracked = max(sidecar_max_tracked, max(0, tracked_pids))
                    sidecar_max_alive = max(sidecar_max_alive, max(0, alive_pids))

                    sidecar_samples.append(
                        {
                            "t_s": float(max(0.0, t_s)),
                            "cpu_user_s": float(max(0.0, cpu_user_s)),
                            "cpu_system_s": float(max(0.0, cpu_system_s)),
                            "rss_bytes": int(max(0, rss_bytes)),
                            "io_read_bytes": int(max(0, io_read_bytes)),
                            "io_write_bytes": int(max(0, io_write_bytes)),
                            "net_sent_bytes": int(max(0, net_sent_bytes)),
                            "net_recv_bytes": int(max(0, net_recv_bytes)),
                            "tracked_pids": int(max(0, tracked_pids)),
                            "alive_pids": int(max(0, alive_pids)),
                        }
                    )

                sidecar_samples.sort(key=lambda item: float(item.get("t_s") or 0.0))
                sidecar_valid = (sidecar_max_alive > 0) or (sidecar_max_tracked > 0)
                if sidecar_samples and sidecar_valid:
                    # Override aggregate CPU/memory with sudo sidecar values when available.
                    last = sidecar_samples[-1]
                    if collect_cpu_metrics:
                        metrics["cpu_user_s"] = float(last.get("cpu_user_s") or 0.0)
                        metrics["cpu_system_s"] = float(last.get("cpu_system_s") or 0.0)

                        cpu_buckets: dict[int, tuple[float, int]] = {}
                        prev = sidecar_samples[0]
                        for cur in sidecar_samples[1:]:
                            dt = float(cur["t_s"] - prev["t_s"])
                            if dt <= 0:
                                prev = cur
                                continue
                            prev_total = float(prev["cpu_user_s"] + prev["cpu_system_s"])
                            cur_total = float(cur["cpu_user_s"] + cur["cpu_system_s"])
                            delta_cpu = float(cur_total - prev_total)
                            if delta_cpu < 0:
                                prev = cur
                                continue
                            cpu_percent = float(delta_cpu / dt) * 100.0
                            bucket = int(max(0.0, float(cur["t_s"])))
                            sum_val, count_val = cpu_buckets.get(bucket, (0.0, 0))
                            cpu_buckets[bucket] = (sum_val + cpu_percent, count_val + 1)
                            prev = cur

                        elapsed_s = max(0.0, float(end_monotonic - start_monotonic))
                        duration_s = int(elapsed_s) if float(int(elapsed_s)) == elapsed_s else int(elapsed_s) + 1
                        duration_s = max(1, duration_s)
                        load_series = []
                        for second in range(0, duration_s):
                            sum_val, count_val = cpu_buckets.get(second, (0.0, 0))
                            avg = float(sum_val / count_val) if count_val else 0.0
                            load_series.append({"t_s": float(second), "cpu_percent": float(avg)})
                        metrics["cpu_load_1s"] = load_series

                    if collect_memory_metrics:
                        peak = int(max(int(item.get("rss_bytes") or 0) for item in sidecar_samples))
                        metrics["peak_rss_bytes"] = int(max(0, peak))

                        rss_buckets: dict[int, int] = {}
                        for item in sidecar_samples:
                            bucket = int(max(0.0, float(item.get("t_s") or 0.0)))
                            rss = int(item.get("rss_bytes") or 0)
                            rss_buckets[bucket] = max(rss_buckets.get(bucket, 0), rss)

                        elapsed_s = max(0.0, float(end_monotonic - start_monotonic))
                        duration_s = int(elapsed_s) if float(int(elapsed_s)) == elapsed_s else int(elapsed_s) + 1
                        duration_s = max(1, duration_s)
                        rss_series: list[dict[str, float]] = []
                        for second in range(0, duration_s):
                            rss_series.append({"t_s": float(second), "rss_bytes": float(rss_buckets.get(second, 0))})
                        metrics["rss_bytes_1s"] = rss_series

                    # Best-effort I/O + network deltas (note: network is system-wide).
                    try:
                        metrics["io_read_bytes"] = int(last.get("io_read_bytes") or 0)
                        metrics["io_write_bytes"] = int(last.get("io_write_bytes") or 0)
                        metrics["net_sent_bytes"] = int(last.get("net_sent_bytes") or 0)
                        metrics["net_recv_bytes"] = int(last.get("net_recv_bytes") or 0)
                    except Exception:
                        pass

                    def _rate_series(key: str, out_key: str) -> None:
                        buckets: dict[int, tuple[float, int]] = {}
                        prev = sidecar_samples[0]
                        for cur in sidecar_samples[1:]:
                            dt = float(cur["t_s"] - prev["t_s"])
                            if dt <= 0:
                                prev = cur
                                continue
                            delta = float(int(cur.get(key) or 0) - int(prev.get(key) or 0))
                            if delta < 0:
                                prev = cur
                                continue
                            rate = float(delta / dt)
                            bucket = int(max(0.0, float(cur["t_s"])))
                            sum_val, count_val = buckets.get(bucket, (0.0, 0))
                            buckets[bucket] = (sum_val + rate, count_val + 1)
                            prev = cur

                        elapsed_s = max(0.0, float(end_monotonic - start_monotonic))
                        duration_s = int(elapsed_s) if float(int(elapsed_s)) == elapsed_s else int(elapsed_s) + 1
                        duration_s = max(1, duration_s)
                        series: list[dict[str, float]] = []
                        for second in range(0, duration_s):
                            sum_val, count_val = buckets.get(second, (0.0, 0))
                            avg = float(sum_val / count_val) if count_val else 0.0
                            series.append({"t_s": float(second), "bytes_per_s": float(avg)})
                        metrics[out_key] = series

                    _rate_series("io_read_bytes", "io_read_bps_1s")
                    _rate_series("io_write_bytes", "io_write_bps_1s")
                    _rate_series("net_sent_bytes", "net_sent_bps_1s")
                    _rate_series("net_recv_bytes", "net_recv_bps_1s")

            # If we only have aggregate CPU (e.g., /usr/bin/time -v) or the time-series bucket
            # calculation produced no usable non-zero points, synthesize a simple per-second series.
            if collect_cpu_metrics:
                series = metrics.get("cpu_load_1s")
                cpu_user_s = float(metrics.get("cpu_user_s") or 0.0)
                cpu_system_s = float(metrics.get("cpu_system_s") or 0.0)
                total_cpu_s = max(0.0, cpu_user_s + cpu_system_s)
                elapsed_s = max(0.0, float(end_monotonic - start_monotonic))
                has_nonzero = False
                if isinstance(series, list):
                    for pt in series:
                        try:
                            if float(pt.get("cpu_percent") or 0.0) > 0.0:
                                has_nonzero = True
                                break
                        except Exception:
                            continue

                if isinstance(series, list) and (not has_nonzero) and total_cpu_s > 0.0 and elapsed_s > 0.0:
                    cpu_percent = float(total_cpu_s / elapsed_s) * 100.0
                    for pt in series:
                        try:
                            pt["cpu_percent"] = float(cpu_percent)
                        except Exception:
                            continue
            self.last_metrics = metrics

        if timed_out:
            stdout_msg = "\n".join(stdout_lines) if stdout_lines else "(no output)"
            raise RuntimeError(f"PIN run timed out after {timeout}s. Output so far:\n{stdout_msg}")

        if self._process.returncode != 0:
            stdout_msg = "\n".join(stdout_lines) if stdout_lines else "Unknown error"
            raise RuntimeError(f"PIN exited with {self._process.returncode}: {stdout_msg}")

        if not instruction_trace.exists():
            raise FileNotFoundError(
                f"Instruction trace not found at '{instruction_trace}'. Ensure the PIN tool writes to this file."
            )

        try:
            if instruction_trace.resolve() != log_file.resolve():
                shutil.copy2(instruction_trace, log_file)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise RuntimeError(f"Failed to copy instruction trace to {log_file}: {exc}") from exc

        if on_output:
            on_output(f"PIN run finished. Instruction trace saved to {log_file}")

        return log_file

    def stop(self) -> None:
        # If metrics sampling is active, stop it first to avoid psutil/native races
        # while we are tearing down the process tree.
        try:
            if self._sampler_stop is not None:
                self._sampler_stop.set()
            if self._sampler_thread is not None and self._sampler_thread.is_alive():
                self._sampler_thread.join(timeout=0.5)
        except Exception:
            pass
        try:
            if self._sudo_metrics_stop is not None:
                self._sudo_metrics_stop.set()
            if self._sudo_metrics_process is not None and self._sudo_metrics_process.poll() is None:
                try:
                    self._sudo_metrics_process.terminate()
                except Exception:
                    pass
        except Exception:
            pass
        proc = self._process
        if not proc:
            return
        if proc.poll() is not None:
            return
        # Try graceful stop of the whole process group first.
        pgid = self._pgid
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        else:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Escalate to SIGKILL on the process group, then the process.
            if pgid is not None:
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=3)
            except Exception:
                pass

    def _ensure_pin_executable(self) -> Path:
        if not self.pin_bin.exists():
            raise FileNotFoundError(
                f"Intel PIN binary not found at '{self.pin_bin}'. Update the path or install PIN."
            )
        if not self.pin_bin.is_file():
            raise FileNotFoundError(f"'{self.pin_bin}' is not a file")
        return self.pin_bin

    def _ensure_tool_exists(self) -> Path:
        if not self.tool_path.exists():
            self._build_pin_tool()
            if not self.tool_path.exists():
                raise FileNotFoundError(
                    "PIN tool build failed. Check scripts/build_tool.sh output for details."
                )
        return self.tool_path

    def build_tool(self, *, on_output: Callable[[str], None] | None = None) -> None:
        self._build_pin_tool(on_output=on_output)

    def _build_pin_tool(self, *, on_output: Callable[[str], None] | None = None) -> None:
        build_script = self.project_root / "scripts" / "build_tool.sh"
        if not build_script.exists():
            raise FileNotFoundError(f"Build script not found at {build_script}")

        env = os.environ.copy()
        env.setdefault("PIN_ROOT", str(self.pin_root))

        process = subprocess.Popen(
            ["bash", str(build_script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=self.project_root / "scripts",
            env=env,
        )

        assert process.stdout is not None
        captured: list[str] = []
        for line in process.stdout:
            clean_line = line.rstrip()
            if not clean_line:
                continue
            captured.append(clean_line)
            if on_output:
                on_output(clean_line)

        process.wait()
        if process.returncode != 0:
            details = "\n".join(captured[-20:]) if captured else "Unknown error"
            raise RuntimeError(f"Automatic PIN tool build failed: {details}")
        if on_output:
            on_output("PIN tool build finished.")