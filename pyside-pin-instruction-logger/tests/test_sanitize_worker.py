from pathlib import Path

from src.app import SanitizeOptions, SanitizeWorker
from src.services.binary_sanitizer import InstructionMismatch


def test_apply_binary_offset_to_addresses_subtracts_runtime_base() -> None:
    addresses = {0x555555658AF0, 0x555555648000}
    offset = 0x555555554000

    adjusted = SanitizeWorker._apply_binary_offset_to_addresses(addresses, offset)

    assert adjusted == {0x104AF0, 0xF4000}


def test_apply_binary_offset_to_samples_with_zero_offset_returns_copy() -> None:
    samples = [(0x1000, "mov eax, ebx"), (0x2000, "ret")]

    adjusted = SanitizeWorker._apply_binary_offset_to_samples(samples, 0)

    assert adjusted == samples
    assert adjusted is not samples


def test_apply_binary_offset_to_samples_subtracts_offset() -> None:
    samples = [(0x555555658AF0, "nop edx, edi"), (0x555555648000, "sub rsp, 0x8")]
    offset = 0x555555554000

    adjusted = SanitizeWorker._apply_binary_offset_to_samples(samples, offset)

    assert adjusted == [(0x104AF0, "nop edx, edi"), (0xF4000, "sub rsp, 0x8")]


def test_write_mismatch_log_includes_all_entries(tmp_path) -> None:
    worker = SanitizeWorker(
        entry_id="entry",
        binary_path=Path("/tmp/binary"),
        log_path=Path("/tmp/log"),
        output_path=tmp_path / "sanitized.bin",
        options=SanitizeOptions(False, None, None, False, True, True, False, True, True, True, 0x2000, 0x400, 0x800, 0, False),
        executed_addresses=set(),
        parsed_rows=0,
        instruction_samples=[],
        binary_offset=0,
    )
    mismatches = [
        InstructionMismatch(0x1000, "mov eax, ebx", "mov eax, eax"),
        InstructionMismatch(0x2000, "ret", "nop"),
    ]

    log_path = worker._write_mismatch_log(mismatches)

    content = log_path.read_text(encoding="utf-8")
    assert "0x1000" in content
    assert "mov eax, ebx" in content
    assert "0x2000" in content


def test_protected_ranges_expand_segments_with_offset() -> None:
    worker = SanitizeWorker(
        entry_id="entry",
        binary_path=Path("/tmp/binary"),
        log_path=Path("/tmp/log"),
        output_path=Path("/tmp/out"),
        options=SanitizeOptions(False, None, None, False, True, True, False, True, True, True, 0x2000, 0x400, 0x800, 0, False),
        executed_addresses={0x2000},
        parsed_rows=1,
        instruction_samples=[(0x2000, "ret")],
        binary_offset=0,
        preserve_segments=[(0x1500, 0x1510)],
        segment_padding=0x10,
    )

    protected = worker._protected_ranges(offset=0x100)

    assert protected == [(0x13F0, 0x1420)]
