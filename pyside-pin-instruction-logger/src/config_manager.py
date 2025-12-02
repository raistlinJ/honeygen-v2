"""Lightweight persistence for user-configurable settings."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any

DEFAULT_PIN_ROOT = Path("/home/researchdev/Downloads/pin4")
DEFAULT_LOG_PATH = Path(__file__).resolve().parents[1] / "pin_logs" / "instruction_log.txt"
DEFAULT_TOOL_PATH = Path(__file__).resolve().parents[1] / "pin-tool" / "obj-intel64" / "ins_logger.so"
CONFIG_PATH = Path(__file__).resolve().parent / "config" / "app_settings.json"


@dataclass
class AppConfig:
    pin_root: str = str(DEFAULT_PIN_ROOT)
    log_path: str = str(DEFAULT_LOG_PATH)
    binary_path: str = ""
    tool_path: str = str(DEFAULT_TOOL_PATH)
    projects: list[str] = field(default_factory=lambda: ["Default Project"])
    active_project: str | None = None
    revng_docker_image: str = "revng/revng"


class ConfigManager:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or CONFIG_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> AppConfig:
        if not self.path.exists():
            return self._save_default()

        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return self._save_default()

        merged: dict[str, Any] = asdict(AppConfig())
        merged.update({k: v for k, v in data.items() if k in merged})
        config = AppConfig(**merged)
        if not config.projects:
            config.projects = ["Default Project"]
        if not config.active_project or config.active_project not in config.projects:
            config.active_project = config.projects[0]
        return config

    def save(self, config: AppConfig) -> None:
        self.path.write_text(json.dumps(asdict(config), indent=2), encoding="utf-8")

    def _save_default(self) -> AppConfig:
        config = AppConfig()
        self.save(config)
        return config
