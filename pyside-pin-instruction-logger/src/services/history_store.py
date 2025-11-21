from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from models.run_entry import RunEntry

HISTORY_PATH = Path(__file__).resolve().parents[1] / "config" / "honey_history.json"


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
                )
            )
        return entries

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
