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
class ProjectConfig:
    pin_root: str = str(DEFAULT_PIN_ROOT)
    log_path: str = str(DEFAULT_LOG_PATH)
    binary_path: str = ""
    tool_path: str = str(DEFAULT_TOOL_PATH)
    revng_docker_image: str = "revng/revng"
    # Default pre-run command/script to execute before target launch
    default_pre_run_command: str = ""

    # Sanitization preferences (GUI defaults). Keep conservative values by default.
    sanitize_runnable_first: bool = True
    sanitize_only_text: bool = False
    sanitize_preserve_trampolines: bool = True
    sanitize_protect_dynlinks: bool = True
    sanitize_protect_unwind: bool = True
    sanitize_protect_indirect: bool = True
    sanitize_segment_padding: str = "0x2000"
    sanitize_icf_window: str = "0x400"
    sanitize_jumptable_window: str = "0x800"


@dataclass
class AppConfig:
    pin_root: str = str(DEFAULT_PIN_ROOT)
    log_path: str = str(DEFAULT_LOG_PATH)
    binary_path: str = ""
    tool_path: str = str(DEFAULT_TOOL_PATH)
    projects: list[str] = field(default_factory=lambda: ["Default Project"])
    active_project: str | None = None
    revng_docker_image: str = "revng/revng"
    project_settings: dict[str, ProjectConfig] = field(default_factory=dict)


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

        config = AppConfig()
        for key, value in data.items():
            if key == "project_settings":
                continue
            if hasattr(config, key):
                setattr(config, key, value)

        raw_settings = data.get("project_settings")
        config.project_settings = self._parse_project_settings(raw_settings, config)
        self._ensure_project_settings(config)

        if not config.projects:
            config.projects = ["Default Project"]
        if not config.active_project or config.active_project not in config.projects:
            config.active_project = config.projects[0]
        return config

    def save(self, config: AppConfig) -> None:
        payload = asdict(config)
        payload["project_settings"] = {
            name: asdict(settings) for name, settings in config.project_settings.items()
        }
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _save_default(self) -> AppConfig:
        config = AppConfig()
        self._ensure_project_settings(config)
        self.save(config)
        return config

    def _parse_project_settings(self, raw: Any, fallback: AppConfig) -> dict[str, ProjectConfig]:
        if not isinstance(raw, dict):
            return {}
        project_settings: dict[str, ProjectConfig] = {}
        for name, value in raw.items():
            project_settings[name] = self._build_project_config(value, fallback)
        return project_settings

    def _build_project_config(self, raw: Any, fallback: AppConfig) -> ProjectConfig:
        base = ProjectConfig(
            pin_root=fallback.pin_root,
            log_path=fallback.log_path,
            binary_path=fallback.binary_path,
            tool_path=fallback.tool_path,
            revng_docker_image=fallback.revng_docker_image,
            default_pre_run_command="",
        )
        if isinstance(raw, dict):
            for key, value in raw.items():
                if hasattr(base, key):
                    setattr(base, key, value)
        return base

    def _ensure_project_settings(self, config: AppConfig) -> None:
        if not config.projects:
            config.projects = ["Default Project"]
        for name in config.projects:
            if name not in config.project_settings:
                config.project_settings[name] = ProjectConfig(
                    pin_root=config.pin_root,
                    log_path=config.log_path,
                    binary_path=config.binary_path,
                    tool_path=config.tool_path,
                    revng_docker_image=config.revng_docker_image,
                )
