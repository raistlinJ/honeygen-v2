#!/usr/bin/env python3
"""Compare outputs/exit codes between an original and sanitized binary.

This is a tiny harness to formalize the project requirement:
"sanitized behaves like original given the same arguments".

It runs a set of argument vectors against both binaries and diffs:
- exit code
- stdout
- stderr

Usage:
  python scripts/compare_runs.py --orig /bin/pwd --san ./sanitized/pwd_fixed14_unwind -- --help

Provide multiple cases by repeating --case, or omit to use defaults.
"""

from __future__ import annotations

import argparse
import difflib
import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RunResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str


def _run(binary: Path, argv: list[str], timeout: float) -> RunResult:
    proc = subprocess.run(
        [str(binary), *argv],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=os.environ.copy(),
        timeout=timeout,
    )
    return RunResult(argv=argv, returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


def _diff(label: str, a: str, b: str) -> str:
    if a == b:
        return ""
    a_lines = a.splitlines(keepends=True)
    b_lines = b.splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(
            a_lines,
            b_lines,
            fromfile=f"orig:{label}",
            tofile=f"san:{label}",
        )
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Compare original vs sanitized binary behavior")
    p.add_argument("--orig", type=Path, required=True, help="Path to original binary")
    p.add_argument("--san", type=Path, required=True, help="Path to sanitized binary")
    p.add_argument(
        "--san-function",
        default=None,
        help=(
            "If set, prepend this function name to every sanitized invocation. "
            "Useful when the sanitized artifact is a multicall binary (e.g. 'pwd')."
        ),
    )
    p.add_argument(
        "--normalize-version",
        action="store_true",
        help=(
            "Normalize cosmetic name/path differences in '--version' output (e.g. '/bin/pwd' vs 'pwd'). "
            "Only applied for cases whose argv contains '--version' or '-V'."
        ),
    )
    p.add_argument(
        "--case",
        action="append",
        default=[],
        help=(
            "Argument vector to test, as a shell-like string (e.g. '--list' or '-P'). "
            "Repeat to add multiple cases. If omitted, uses a small default set."
        ),
    )
    p.add_argument("--timeout", type=float, default=10.0, help="Timeout per run (seconds)")
    p.add_argument(
        "--",
        dest="_ddash",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return p.parse_args()


def _normalize_version_stdout(stdout: str) -> str:
    """Normalize uutils/coreutils-style version banners.

    This is intentionally conservative: it only rewrites the *leading* program
    token on the first line from an absolute path to its basename.
    """

    lines = stdout.splitlines(keepends=True)
    if not lines:
        return stdout
    first = lines[0]
    stripped = first.strip("\r\n")
    if not stripped:
        return stdout
    parts = stripped.split(" ", 1)
    program = parts[0]
    if program.startswith("/"):
        program = os.path.basename(program)
    rebuilt = program if len(parts) == 1 else f"{program} {parts[1]}"
    lines[0] = rebuilt + ("\n" if first.endswith("\n") else "")
    return "".join(lines)


def main() -> int:
    args = parse_args()
    orig: Path = args.orig
    san: Path = args.san
    san_function: str | None = args.san_function

    if not orig.exists():
        raise SystemExit(f"Original binary not found: {orig}")
    if not san.exists():
        raise SystemExit(f"Sanitized binary not found: {san}")

    cases = args.case
    if not cases:
        cases = ["", "-P", "-L", "--help", "--version"]

    any_mismatch = False

    for case in cases:
        argv = shlex.split(case)
        try:
            r_orig = _run(orig, argv, timeout=args.timeout)
        except Exception as exc:
            print(f"[orig] FAILED to run case {case!r}: {exc}")
            any_mismatch = True
            continue

        try:
            san_argv = argv
            if san_function:
                san_argv = [san_function, *argv]

            r_san = _run(san, san_argv, timeout=args.timeout)
        except Exception as exc:
            print(f"[san] FAILED to run case {case!r}: {exc}")
            any_mismatch = True
            continue

        norm = bool(args.normalize_version) and ("--version" in argv or "-V" in argv)
        stdout_orig = _normalize_version_stdout(r_orig.stdout) if norm else r_orig.stdout
        stdout_san = _normalize_version_stdout(r_san.stdout) if norm else r_san.stdout
        stderr_orig = r_orig.stderr
        stderr_san = r_san.stderr

        mismatch = False
        if r_orig.returncode != r_san.returncode:
            mismatch = True
        if stdout_orig != stdout_san:
            mismatch = True
        if stderr_orig != stderr_san:
            mismatch = True

        status = "OK" if not mismatch else "MISMATCH"
        print(f"\n=== CASE {case!r}: {status} ===")
        print(f"exit: orig={r_orig.returncode} san={r_san.returncode}")

        d = _diff("stdout", stdout_orig, stdout_san)
        if d:
            print(d, end="" if d.endswith("\n") else "\n")

        d = _diff("stderr", stderr_orig, stderr_san)
        if d:
            print(d, end="" if d.endswith("\n") else "\n")

        if mismatch:
            any_mismatch = True

    return 1 if any_mismatch else 0


if __name__ == "__main__":
    raise SystemExit(main())
