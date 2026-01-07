from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from models.run_entry import RunEntry

HISTORY_PATH = Path(__file__).resolve().parents[1] / "config" / "honey_history.json"


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


class HistoryStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or HISTORY_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load_project(self, project: str) -> list[RunEntry]:
        data = self._read_all()
        raw_entries = data.get(project, [])
        entries: list[RunEntry] = []
        for raw in raw_entries:
            try:
                timestamp = datetime.fromisoformat(raw.get("timestamp", ""))
            except ValueError:
                timestamp = datetime.now()
            prepared_segments = self._parse_segments(raw.get("prepared_segments"))
            prepared_at_raw = raw.get("prepared_at")
            prepared_at = None
            if prepared_at_raw:
                try:
                    prepared_at = datetime.fromisoformat(prepared_at_raw)
                except ValueError:
                    prepared_at = None
            binary_offset = raw.get("binary_offset", 0)
            try:
                binary_offset = int(binary_offset)
            except (TypeError, ValueError):
                binary_offset = 0
            trace_count = _as_int(raw.get("trace_address_count", 0))
            binary_count = _as_int(raw.get("binary_instruction_count", 0))
            sanitized_total = _as_int(raw.get("sanitized_total_instructions", 0))
            sanitized_preserved = _as_int(raw.get("sanitized_preserved_instructions", 0))
            sanitized_nopped = _as_int(raw.get("sanitized_nopped_instructions", 0))
            entries.append(
                RunEntry(
                    entry_id=raw.get("entry_id") or str(uuid4()),
                    name=raw.get("name", ""),
                    binary_path=raw.get("binary_path", ""),
                    log_path=raw.get("log_path", ""),
                    timestamp=timestamp,
                    sanitized_binary_path=raw.get("sanitized_binary_path"),
                    parent_entry_id=raw.get("parent_entry_id"),
                    is_sanitized_run=raw.get("is_sanitized_run", False),
                    prepared_segments=prepared_segments or None,
                    prepared_at=prepared_at,
                    binary_offset=binary_offset,
                    trace_address_count=trace_count,
                    binary_instruction_count=binary_count,
                    sanitized_total_instructions=sanitized_total,
                    sanitized_preserved_instructions=sanitized_preserved,
                    sanitized_nopped_instructions=sanitized_nopped,
                    target_args=raw.get("target_args") or None,
                    use_sudo=bool(raw.get("use_sudo", False)),
                    module_filters=raw.get("module_filters") or None,
                    pre_run_command=raw.get("pre_run_command") or None,
                )
            )
        return entries

    def list_projects(self) -> list[str]:
        data = self._read_all()
        if not isinstance(data, dict):
            return []
        return list(data.keys())

    def save_project(self, project: str, entries: list[RunEntry]) -> None:
        data = self._read_all()
        data[project] = [self._entry_to_dict(entry) for entry in entries]
        self._write_all(data)

    def rename_project(self, old_name: str, new_name: str) -> None:
        if not old_name or not new_name or old_name == new_name:
            return
        data = self._read_all()
        if old_name not in data:
            if new_name not in data:
                data[new_name] = []
            self._write_all(data)
            return
        if new_name in data:
            # Merge entries if destination already exists.
            data[new_name].extend(data[old_name])
        else:
            data[new_name] = data[old_name]
        del data[old_name]
        self._write_all(data)

    def delete_project(self, project: str) -> None:
        if not project:
            return
        data = self._read_all()
        if project in data:
            del data[project]
            self._write_all(data)

    def _entry_to_dict(self, entry: RunEntry) -> dict[str, Any]:
        return {
            "entry_id": entry.entry_id,
            "name": entry.name,
            "binary_path": entry.binary_path,
            "log_path": entry.log_path,
            "timestamp": entry.timestamp.isoformat(),
            "sanitized_binary_path": entry.sanitized_binary_path,
            "parent_entry_id": entry.parent_entry_id,
            "is_sanitized_run": entry.is_sanitized_run,
            "prepared_segments": self._format_segments(entry.prepared_segments),
            "prepared_at": entry.prepared_at.isoformat() if entry.prepared_at else None,
            "binary_offset": int(entry.binary_offset or 0),
            "trace_address_count": int(getattr(entry, "trace_address_count", 0) or 0),
            "binary_instruction_count": int(getattr(entry, "binary_instruction_count", 0) or 0),
            "sanitized_total_instructions": int(getattr(entry, "sanitized_total_instructions", 0) or 0),
            "sanitized_preserved_instructions": int(getattr(entry, "sanitized_preserved_instructions", 0) or 0),
            "sanitized_nopped_instructions": int(getattr(entry, "sanitized_nopped_instructions", 0) or 0),
            "target_args": list(entry.target_args) if entry.target_args else None,
            "use_sudo": bool(getattr(entry, "use_sudo", False)),
            "module_filters": list(entry.module_filters) if entry.module_filters else None,
            "pre_run_command": entry.pre_run_command or None,
        }

    def _read_all(self) -> dict[str, list[dict[str, Any]]]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _write_all(self, data: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _parse_segments(self, raw_segments: Any) -> list[tuple[int, int]]:
        segments: list[tuple[int, int]] = []
        if not raw_segments:
            return segments
        for item in raw_segments:
            if isinstance(item, dict):
                start = item.get("start")
                end = item.get("end")
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                start, end = item
            else:
                continue
            try:
                start_int = int(start)
                end_int = int(end)
            except (TypeError, ValueError):
                continue
            segments.append((start_int, end_int))
        return segments

    def _format_segments(self, segments: list[tuple[int, int]] | None) -> list[dict[str, int]]:
        formatted: list[dict[str, int]] = []
        if not segments:
            return formatted
        for start, end in segments:
            formatted.append({"start": int(start), "end": int(end)})
        return formatted
