from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


def _display_name(binary_path: str) -> str:
    name = Path(binary_path).name
    return name or binary_path


@dataclass
class RunEntry:
    entry_id: str
    name: str
    binary_path: str
    log_path: str
    timestamp: datetime
    sanitized_binary_path: str | None = None
    parent_entry_id: str | None = None
    is_sanitized_run: bool = False

    def label(self) -> str:
        prefix = "[SAN] " if self.is_sanitized_run else ""
        return f"{prefix}{_display_name(self.binary_path)} · {self.name}"
