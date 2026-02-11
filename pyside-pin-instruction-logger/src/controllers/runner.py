from pathlib import Path
import subprocess
from typing import Callable, Sequence

from services.pin_runner import PinRunner


class RunnerController:
    def __init__(
        self,
        ui,
        pin_root: str | Path | None = None,
        log_path: str | Path | None = None,
        tool_path: str | Path | None = None,
    ):
        self.ui = ui
        self._pin_root = Path(pin_root) if pin_root else None
        self._default_log = Path(log_path) if log_path else None
        self._tool_path = Path(tool_path) if tool_path else None
        self.pin_runner = self._build_runner()

    def _build_runner(self) -> PinRunner:
        pin_bin = None
        if self._pin_root:
            pin_bin = self._pin_root / "pin"
        tool = self._tool_path
        return PinRunner(pin_bin=pin_bin, default_log=self._default_log, tool_path=tool)

    def set_pin_root(self, pin_root: str | Path) -> None:
        self._pin_root = Path(pin_root)
        self.pin_runner = self._build_runner()

    def set_log_path(self, log_path: str | Path) -> None:
        self._default_log = Path(log_path)
        self.pin_runner = self._build_runner()

    def set_tool_path(self, tool_path: str | Path) -> None:
        self._tool_path = Path(tool_path)
        self.pin_runner = self._build_runner()

    def run_binary(
        self,
        binary_path: str,
        *,
        log_path: str | None = None,
        module_filters: Sequence[str] | None = None,
        unique_only: bool = False,
        use_sudo: bool = False,
        sudo_password: str | None = None,
        on_output: Callable[[str], None] | None = None,
        extra_target_args: Sequence[str] | None = None,
        collect_cpu_metrics: bool = False,
        collect_memory_metrics: bool = False,
        collect_timing_metrics: bool = False,
    ) -> Path:
        return self.pin_runner.run(
            binary_path,
            log_path=log_path,
            modules=module_filters,
            extra_target_args=extra_target_args,
            unique_only=unique_only,
            use_sudo=use_sudo,
            sudo_password=sudo_password,
            on_output=on_output,
            collect_cpu_metrics=bool(collect_cpu_metrics),
            collect_memory_metrics=bool(collect_memory_metrics),
            collect_timing_metrics=bool(collect_timing_metrics),
        )

    def stop_logging(self) -> None:
        self.pin_runner.stop()

    def build_tool(
        self,
        on_output: Callable[[str], None] | None = None,
        *,
        use_sudo: bool = False,
        sudo_password: str | None = None,
    ) -> None:
        self.pin_runner.build_tool(on_output=on_output, use_sudo=use_sudo, sudo_password=sudo_password)