import os
import sys
from pathlib import Path
from typing import List, Tuple

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (str(SRC), str(ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

PreviewRow = Tuple[int, str, str]


@pytest.fixture
def sample_preview_rows() -> List[PreviewRow]:
    return [
        (0x1000, "mov eax, ebx", "mov eax, ebx"),
        (0x1004, "add eax, 1", "add eax, 2"),
        (0x1008, "jmp 0x2000", "jmp 0x2000"),
        (0x100C, "sub eax, ecx", "sub eax, ecx"),
    ]


@pytest.fixture
def many_preview_rows() -> List[PreviewRow]:
    rows: List[PreviewRow] = []
    for idx in range(240):
        address = 0x2000 + idx * 4
        binary = f"op_{idx} r0, r1"
        logged = binary if idx % 5 else f"op_{idx} r0, r2"
        rows.append((address, binary, logged))
    return rows
