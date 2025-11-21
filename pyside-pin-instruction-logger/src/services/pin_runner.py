"""Helpers for invoking Intel PIN with the bundled instruction logger."""

from __future__ import annotations

from pathlib import Path
import subprocess
import os
import shutil
from typing import Callable, Sequence

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

    def run(
        self,
        binary_path: Path | str,
        *,
        log_path: Path | str | None = None,
        extra_target_args: Sequence[str] | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        on_output: Callable[[str], None] | None = None,
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

        command: list[str] = [str(pin_exe), "-t", str(tool), "--", str(binary)]
        if extra_target_args:
            command.extend(list(extra_target_args))

        if on_output:
            on_output(f"Launching PIN for {binary.name}...")

        combined_env = os.environ.copy()
        combined_env.setdefault("PIN_ROOT", str(self.pin_root))
        if env:
            combined_env.update(env)

        self._process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=combined_env,
            cwd=self.project_root,
        )
        stdout_lines: list[str] = []
        assert self._process.stdout is not None
        for line in self._process.stdout:
            clean_line = line.rstrip()
            if clean_line:
                stdout_lines.append(clean_line)
            if on_output and clean_line:
                on_output(clean_line)
        self._process.wait(timeout=timeout)

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
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()

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