from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from models.run_entry import RunEntry
from models.sanitized_output import SanitizedBinaryOutput

HISTORY_PATH = Path(__file__).resolve().parents[1] / "config" / "honey_history.json"


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _as_optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"", "none", "null", "unknown", "-", "—"}:
            return None
        if lowered in {"true", "yes", "y", "1", "works", "ok", "pass"}:
            return True
        if lowered in {"false", "no", "n", "0", "broken", "fail"}:
            return False
    return None


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

            sanitized_outputs: list[SanitizedBinaryOutput] = []
            for output in (raw.get("sanitized_outputs") or []):
                if not isinstance(output, dict):
                    continue
                generated_at = None
                generated_at_raw = output.get("generated_at")
                if generated_at_raw:
                    try:
                        generated_at = datetime.fromisoformat(str(generated_at_raw))
                    except ValueError:
                        generated_at = None
                sanitized_outputs.append(
                    SanitizedBinaryOutput(
                        output_id=str(output.get("output_id") or uuid4()),
                        output_path=str(output.get("output_path") or ""),
                        works=_as_optional_bool(output.get("works")),
                        segment_gap=_as_int(output.get("segment_gap", 0)),
                        segment_padding=_as_int(output.get("segment_padding", 0)),
                        icf_window=_as_int(output.get("icf_window", 0)),
                        jumptable_window=_as_int(output.get("jumptable_window", 0)),
                        total_instructions=_as_int(output.get("total_instructions", 0)),
                        preserved_instructions=_as_int(output.get("preserved_instructions", 0)),
                        nopped_instructions=_as_int(output.get("nopped_instructions", 0)),
                        generated_at=generated_at,
                    )
                )

            legacy_sanitized_path = raw.get("sanitized_binary_path")
            if legacy_sanitized_path and not sanitized_outputs:
                sanitized_outputs.append(
                    SanitizedBinaryOutput(
                        output_id=str(uuid4()),
                        output_path=str(legacy_sanitized_path),
                        works=None,
                        segment_gap=0,
                        segment_padding=0,
                        icf_window=0,
                        jumptable_window=0,
                        total_instructions=sanitized_total,
                        preserved_instructions=sanitized_preserved,
                        nopped_instructions=sanitized_nopped,
                        generated_at=None,
                    )
                )
            entries.append(
                RunEntry(
                    entry_id=raw.get("entry_id") or str(uuid4()),
                    name=raw.get("name", ""),
                    binary_path=raw.get("binary_path", ""),
                    log_path=raw.get("log_path", ""),
                    timestamp=timestamp,
                    sanitized_binary_path=raw.get("sanitized_binary_path"),
                    sanitized_outputs=sanitized_outputs,
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
            "sanitized_outputs": [
                {
                    "output_id": output.output_id,
                    "output_path": output.output_path,
                    "works": getattr(output, "works", None),
                    "segment_gap": int(output.segment_gap or 0),
                    "segment_padding": int(output.segment_padding or 0),
                    "icf_window": int(getattr(output, "icf_window", 0) or 0),
                    "jumptable_window": int(getattr(output, "jumptable_window", 0) or 0),
                    "total_instructions": int(output.total_instructions or 0),
                    "preserved_instructions": int(output.preserved_instructions or 0),
                    "nopped_instructions": int(output.nopped_instructions or 0),
                    "generated_at": output.generated_at.isoformat() if output.generated_at else None,
                }
                for output in (getattr(entry, "sanitized_outputs", None) or [])
                if getattr(output, "output_path", None)
            ],
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
