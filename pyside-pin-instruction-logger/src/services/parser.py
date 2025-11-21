from __future__ import annotations

from pathlib import Path
import re
from typing import Iterable


HEX_CAPTURE = r"(?P<address>(?:0x)?[0-9a-fA-F]+)"
EXEC_PATTERN = re.compile(rf"Executed instruction at:\s*{HEX_CAPTURE}\s*-\s*(?P<instruction>.+)")
COLON_PATTERN = re.compile(rf"\s*{HEX_CAPTURE}\s*:\s*(?P<instruction>.+)")


def _line_source(log_input: str | Path) -> Iterable[str]:
    candidate = Path(str(log_input))
    if candidate.exists():
        with candidate.open("r", encoding="utf-8", errors="replace") as handle:
            yield from handle
        return
    # Treat argument as in-memory log content when the file path does not exist
    for line in str(log_input).splitlines():
        yield line


def parse_log(log_input: str | Path) -> list[dict[str, str]]:
    instructions: list[dict[str, str]] = []

    for raw_line in _line_source(log_input):
        line = raw_line.strip()
        if not line:
            continue
        match = EXEC_PATTERN.match(line) or COLON_PATTERN.match(line)
        if not match:
            continue
        address = _normalize_address(match.group("address"))
        instruction = match.group("instruction").strip()
        instructions.append({"address": address, "instruction": instruction})

    return instructions


def _normalize_address(raw: str) -> str:
    text = raw.strip()
    if not text.lower().startswith("0x"):
        text = f"0x{text}"
    return text.lower()