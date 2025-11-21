from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from . import parser


@dataclass
class ExecutedAddressReport:
    addresses: set[int]
    parsed_rows: int


def collect_executed_addresses(log_path: Path | str) -> ExecutedAddressReport:
    """Return the set of instruction addresses present in a PIN log alongside basic stats."""
    instructions = parser.parse_log(log_path)
    executed: set[int] = set()
    for entry in instructions:
        raw_address = entry.get("address")
        if not raw_address:
            continue
        try:
            executed.add(int(raw_address, 16))
        except ValueError:
            continue
    return ExecutedAddressReport(addresses=executed, parsed_rows=len(instructions))
