from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class SanitizedBinaryOutput:
    output_id: str
    output_path: str
    works: bool | None = None
    segment_gap: int = 0
    segment_padding: int = 0
    icf_window: int = 0
    jumptable_window: int = 0
    total_instructions: int = 0
    preserved_instructions: int = 0
    nopped_instructions: int = 0
    generated_at: datetime | None = None
