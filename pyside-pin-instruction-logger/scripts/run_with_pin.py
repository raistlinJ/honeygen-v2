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
    parser.add_argument("target", help="Path to the binary you want to instrument")
    parser.add_argument(
        "target_args",
        nargs=argparse.REMAINDER,
        help="Arguments passed verbatim to the target (prefix them with -- to stop parsing)",
    )
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
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    pin_bin = Path(args.pin_root) / "pin"
    runner = PinRunner(pin_bin=pin_bin, tool_path=args.tool, default_log=args.log)

    try:
        log_file = runner.run(args.target, extra_target_args=args.target_args)
    except Exception as exc:  # pragma: no cover - CLI feedback path
        parser.error(str(exc))

    print(f"PIN execution complete. Log written to: {log_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())