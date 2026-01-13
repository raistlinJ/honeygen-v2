#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path


_STOP = False


def _handle_stop(signum: int, frame) -> None:  # type: ignore[no-untyped-def]
    global _STOP
    _STOP = True


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="sudo/root metrics sidecar sampler")
    parser.add_argument("--exe", required=True, help="Resolved path to target executable")
    parser.add_argument("--start-epoch", required=True, type=float, help="Start time (time.time())")
    parser.add_argument("--interval", type=float, default=0.2, help="Sampling interval seconds")
    parser.add_argument("--max-seconds", type=float, default=3600.0, help="Failsafe max runtime")

    args = parser.parse_args(argv)

    try:
        import psutil  # type: ignore
    except Exception as exc:
        sys.stderr.write(f"psutil unavailable: {exc}\n")
        return 2

    exe = str(Path(args.exe).resolve())
    start_epoch = float(args.start_epoch)
    interval = max(0.05, float(args.interval))
    max_seconds = max(1.0, float(args.max_seconds))

    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    start_monotonic = time.monotonic()

    # Track pids discovered for this run.
    tracked_pids: set[int] = set()

    # Keep last-seen cumulative counters for monotonic totals.
    last_cpu: dict[int, tuple[float, float]] = {}
    last_io: dict[int, tuple[int, int]] = {}

    try:
        net0 = psutil.net_io_counters()
        base_sent = int(getattr(net0, "bytes_sent", 0) or 0)
        base_recv = int(getattr(net0, "bytes_recv", 0) or 0)
    except Exception:
        base_sent = 0
        base_recv = 0

    # Allow some slack around the requested start time.
    create_time_floor = start_epoch - 1.0

    while not _STOP:
        now = time.monotonic()
        t_s = float(max(0.0, now - start_monotonic))
        if t_s > max_seconds:
            break

        # Discover new roots by executable path + start time.
        try:
            for proc in psutil.process_iter(attrs=["pid", "exe", "create_time"]):
                try:
                    info = proc.info
                    pid = int(info.get("pid") or 0)
                    if pid <= 0:
                        continue
                    proc_exe = info.get("exe")
                    if not proc_exe:
                        continue
                    if str(Path(proc_exe).resolve()) != exe:
                        continue
                    ct = float(info.get("create_time") or 0.0)
                    if ct and ct < create_time_floor:
                        continue
                    tracked_pids.add(pid)
                except Exception:
                    continue
        except Exception:
            pass

        # Expand to descendants of already tracked processes.
        # This helps include helpers/subprocesses that exec a different binary.
        try:
            for pid in list(tracked_pids):
                try:
                    parent = psutil.Process(pid)
                except Exception:
                    continue
                try:
                    for child in parent.children(recursive=True):
                        try:
                            tracked_pids.add(int(child.pid))
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception:
            pass

        rss_sum_alive = 0

        alive_pids: list[int] = []
        for pid in list(tracked_pids):
            try:
                proc = psutil.Process(pid)
            except Exception:
                continue

            try:
                if not proc.is_running():
                    continue
            except Exception:
                pass

            alive_pids.append(pid)

            try:
                times = proc.cpu_times()
                user_s = float(getattr(times, "user", 0.0) or 0.0)
                system_s = float(getattr(times, "system", 0.0) or 0.0)
                last_cpu[pid] = (user_s, system_s)
            except Exception:
                pass

            try:
                mem = proc.memory_info()
                rss_sum_alive += int(getattr(mem, "rss", 0) or 0)
            except Exception:
                pass

            try:
                io = proc.io_counters()
                read_b = int(getattr(io, "read_bytes", 0) or 0)
                write_b = int(getattr(io, "write_bytes", 0) or 0)
                last_io[pid] = (read_b, write_b)
            except Exception:
                pass

        cpu_user_total = float(sum(val[0] for val in last_cpu.values()))
        cpu_system_total = float(sum(val[1] for val in last_cpu.values()))
        io_read_total = int(sum(val[0] for val in last_io.values()))
        io_write_total = int(sum(val[1] for val in last_io.values()))

        try:
            net = psutil.net_io_counters()
            net_sent = int(getattr(net, "bytes_sent", 0) or 0) - base_sent
            net_recv = int(getattr(net, "bytes_recv", 0) or 0) - base_recv
            net_sent = max(0, net_sent)
            net_recv = max(0, net_recv)
        except Exception:
            net_sent = 0
            net_recv = 0

        payload = {
            "t_s": t_s,
            "cpu_user_s": cpu_user_total,
            "cpu_system_s": cpu_system_total,
            "rss_bytes": int(max(0, rss_sum_alive)),
            "io_read_bytes": int(max(0, io_read_total)),
            "io_write_bytes": int(max(0, io_write_total)),
            "net_sent_bytes": int(max(0, net_sent)),
            "net_recv_bytes": int(max(0, net_recv)),
            "tracked_pids": int(len(tracked_pids)),
            "alive_pids": int(len(alive_pids)),
        }
        sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
        sys.stdout.flush()

        time.sleep(interval)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
