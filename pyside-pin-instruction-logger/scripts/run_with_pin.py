"""Convenience CLI to execute binaries through Intel PIN."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from services.pin_runner import PIN_ROOT_DEFAULT, PinRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a target binary with Intel PIN")
    parser.add_argument(
        "--pin-root",
        default=str(PIN_ROOT_DEFAULT),
        help="Path to the Intel PIN kit root (defaults to /home/researchdev/Downloads/pin4)",
    )
    parser.add_argument(
        "--tool",
        default=None,
        help="Override the instrumentation tool path (defaults to pin-tool/obj-intel64/ins_logger.so)",
    )
    parser.add_argument(
        "--log",
        default=None,
        help="Path to the log file produced by the run (defaults to pin_logs/instruction_log.txt)",
    )
    parser.add_argument(
        "--unique-only",
        action="store_true",
        help="Only record the first execution of each instruction address",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Maximum runtime in seconds before the run is terminated (optional)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args, rest = parser.parse_known_args(argv)

    if not rest:
        parser.error("Missing target binary path")

    target = rest[0]
    extra_args = list(rest[1:])
    # Common convention: allow `--` to separate script options from target args.
    if extra_args and extra_args[0] == "--":
        extra_args = extra_args[1:]

    pin_bin = Path(args.pin_root) / "pin"
    runner = PinRunner(pin_bin=pin_bin, tool_path=args.tool, default_log=args.log)

    try:
        log_file = runner.run(
            target,
            extra_target_args=extra_args,
            unique_only=args.unique_only,
            timeout=args.timeout,
        )
    except Exception as exc:  # pragma: no cover - CLI feedback path
        parser.error(str(exc))

    print(f"PIN execution complete. Log written to: {log_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())