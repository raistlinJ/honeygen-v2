from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Tuple

from . import parser


SAMPLE_LIMIT = 32


@dataclass
class ExecutedAddressReport:
    addresses: set[int]
    parsed_rows: int
    sampled_instructions: list[tuple[int, str]]


def collect_executed_addresses(log_path: Path | str) -> ExecutedAddressReport:
    """Return the set of instruction addresses present in a PIN log alongside basic stats."""
    instructions = parser.parse_log(log_path)
    executed: set[int] = set()
    sampled: list[tuple[int, str]] = []
    for entry in instructions:
        raw_address = entry.get("address")
        if not raw_address:
            continue
        try:
            address_int = int(raw_address, 16)
        except ValueError:
            continue
        executed.add(address_int)
        if len(sampled) < SAMPLE_LIMIT:
            instruction = entry.get("instruction", "").strip()
            if instruction:
                sampled.append((address_int, instruction))
    return ExecutedAddressReport(addresses=executed, parsed_rows=len(instructions), sampled_instructions=sampled)
