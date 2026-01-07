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
    prepared_segments: list[tuple[int, int]] | None = None
    prepared_at: datetime | None = None
    binary_offset: int = 0
    trace_address_count: int = 0
    binary_instruction_count: int = 0
    sanitized_total_instructions: int = 0
    sanitized_preserved_instructions: int = 0
    sanitized_nopped_instructions: int = 0
    # Invocation details
    target_args: list[str] | None = None
    use_sudo: bool = False
    module_filters: list[str] | None = None
    # Optional pre-run setup command or script path
    pre_run_command: str | None = None

    def label(self) -> str:
        prefix = "[SAN] " if self.is_sanitized_run else ""
        return f"{prefix}{_display_name(self.binary_path)} · {self.name}"
