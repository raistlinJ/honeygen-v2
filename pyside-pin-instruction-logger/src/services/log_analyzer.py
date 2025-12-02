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


def compute_address_segments(
    entries: Iterable[dict[str, str]],
    *,
    max_gap: int = 16,
) -> tuple[list[int], list[tuple[int, int]]]:
    """Return sorted addresses and contiguous segments derived from parsed log entries."""
    seen: set[int] = set()
    addresses: list[int] = []
    for entry in entries:
        raw_address = entry.get("address") if isinstance(entry, dict) else None
        if not raw_address:
            continue
        try:
            address_int = int(raw_address, 16)
        except (TypeError, ValueError):
            continue
        if address_int in seen:
            continue
        seen.add(address_int)
        addresses.append(address_int)
    addresses.sort()
    segments = _contiguous_segments_from_sorted(addresses, max_gap=max_gap)
    return addresses, segments


def _contiguous_segments_from_sorted(addresses: list[int], *, max_gap: int) -> list[tuple[int, int]]:
    if not addresses:
        return []
    segments: list[tuple[int, int]] = []
    start = prev = addresses[0]
    for address in addresses[1:]:
        if address - prev > max_gap:
            segments.append((start, prev))
            start = address
        prev = address
    segments.append((start, prev))
    return segments
