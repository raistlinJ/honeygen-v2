#!/usr/bin/env python3
"""Utility to sanitize a binary from one or more PIN instruction logs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dataclasses import dataclass
import hashlib

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from services.binary_sanitizer import BinarySanitizer
from services.log_analyzer import collect_executed_addresses

DEFAULT_SEGMENT_GAP = 0x20
DEFAULT_SEGMENT_PADDING = 0x200
DEFAULT_PROTECT_RADIUS = 0x40
DEFAULT_ICF_WINDOW = 0x200
DEFAULT_JUMPTABLE_WINDOW = 0x400
DEFAULT_UNIQUE_LOG_DIRNAME = ".unique_logs"

RUNNABLE_FIRST_SEGMENT_GAP = 0x4000
RUNNABLE_FIRST_SEGMENT_PADDING = 0x2000
RUNNABLE_FIRST_ICF_WINDOW = 0x400
RUNNABLE_FIRST_JUMPTABLE_WINDOW = 0x800


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sanitize a binary using instruction logs")
    parser.add_argument("binary", type=Path, help="Path to the ELF binary to sanitize")
    parser.add_argument("output", type=Path, help="Destination path for the sanitized binary")
    parser.add_argument(
        "--log",
        dest="logs",
        action="append",
        type=Path,
        required=True,
        help="Instruction log produced by the PIN tool (accepts multiple).",
    )
    parser.add_argument(
        "--make-unique-logs",
        action="store_true",
        default=False,
        help=(
            "Preprocess each --log into a compact unique-address log (one hex address per line) and reuse it. "
            "Greatly speeds up repeated iterations with huge logs."
        ),
    )
    parser.add_argument(
        "--unique-log-dir",
        type=Path,
        default=None,
        help=(
            "Directory to store cached unique logs (default: <repo>/.unique_logs). "
            "Only used with --make-unique-logs."
        ),
    )
    parser.add_argument(
        "--runnable-first",
        action="store_true",
        default=False,
        help=(
            "Conservative preset that favors runnability over size reduction: increases protected segment "
            "gap/padding and enables --keep-trampolines, --protect-dynlinks, --protect-unwind, and --protect-indirect."
        ),
    )
    parser.add_argument(
        "--offset",
        type=lambda value: int(value, 0),
        default=None,
        help="Override the PIE load offset used in the logs (defaults to inferred value).",
    )
    parser.add_argument(
        "--segment-gap",
        type=lambda value: int(value, 0),
        default=DEFAULT_SEGMENT_GAP,
        help="Maximum gap (in bytes) between logged addresses to keep them in the same protected segment.",
    )
    parser.add_argument(
        "--segment-padding",
        type=lambda value: int(value, 0),
        default=DEFAULT_SEGMENT_PADDING,
        help="How many bytes of padding to keep on both sides of each protected segment.",
    )
    parser.add_argument(
        "--protect-range",
        dest="protect_ranges",
        action="append",
        default=[],
        help=(
            "Absolute runtime address range to always preserve. Accepts start:end or start+length (hex allowed). "
            "May be supplied multiple times."
        ),
    )
    parser.add_argument(
        "--protect-address",
        dest="protect_addresses",
        action="append",
        type=lambda value: int(value, 0),
        default=[],
        help="Absolute runtime address to preserve with --protect-radius padding on each side (hex allowed).",
    )
    parser.add_argument(
        "--protect-radius",
        type=lambda value: int(value, 0),
        default=DEFAULT_PROTECT_RADIUS,
        help="Radius in bytes applied around each --protect-address entry (default: 0x40).",
    )
    parser.add_argument(
        "--keep-trampolines",
        action="store_true",
        default=False,
        help="Preserve .plt/.init/.fini sections even if not executed (default: off).",
    )
    parser.add_argument(
        "--protect-dynlinks",
        action="store_true",
        default=False,
        help=(
            "Protect dynamic linker / relocation-sensitive sections (e.g., .got, .data.rel.ro, .dynamic, .rela.*). "
            "Recommended when indirect calls/jumps go through relocated tables (default: off)."
        ),
    )
    parser.add_argument(
        "--protect-unwind",
        action="store_true",
        default=False,
        help=(
            "Protect unwind/exception metadata sections (e.g., .eh_frame*, .gcc_except_table). "
            "Recommended for binaries with Rust/C++-like unwinding or stack checks (default: off)."
        ),
    )
    parser.add_argument(
        "--protect-indirect",
        action="store_true",
        default=False,
        help=(
            "Heuristically preserve neighborhoods around indirect call/jmp sites and nearby jump-table bases "
            "found in .text. Helps prevent crashes from sanitized-away dispatch plumbing (default: off)."
        ),
    )
    parser.add_argument(
        "--icf-window",
        type=lambda value: int(value, 0),
        default=DEFAULT_ICF_WINDOW,
        help="Bytes to preserve on both sides of each indirect call/jmp site (default: 0x200).",
    )
    parser.add_argument(
        "--jumptable-window",
        type=lambda value: int(value, 0),
        default=DEFAULT_JUMPTABLE_WINDOW,
        help="Bytes to preserve starting at any inferred jump-table base (default: 0x400).",
    )
    parser.add_argument(
        "--only-text",
        action="store_true",
        default=False,
        help="Restrict sanitization to .text sections only.",
    )
    args = parser.parse_args()

    if getattr(args, "runnable_first", False):
        # Only override when the user didn't explicitly provide a non-default.
        if args.segment_gap == DEFAULT_SEGMENT_GAP:
            args.segment_gap = RUNNABLE_FIRST_SEGMENT_GAP
        if args.segment_padding == DEFAULT_SEGMENT_PADDING:
            args.segment_padding = RUNNABLE_FIRST_SEGMENT_PADDING
        if args.icf_window == DEFAULT_ICF_WINDOW:
            args.icf_window = RUNNABLE_FIRST_ICF_WINDOW
        if args.jumptable_window == DEFAULT_JUMPTABLE_WINDOW:
            args.jumptable_window = RUNNABLE_FIRST_JUMPTABLE_WINDOW

        args.keep_trampolines = True
        args.protect_dynlinks = True
        args.protect_unwind = True
        args.protect_indirect = True

    return args


def _section_range(binary, name: str) -> tuple[int, int] | None:
    for section in getattr(binary, "sections", []) or []:
        if getattr(section, "name", "") != name:
            continue
        start = int(getattr(section, "virtual_address", 0) or 0)
        size = int(getattr(section, "size", 0) or 0)
        if size <= 0:
            return None
        return start, start + size
    return None


def _section_containing_va(binary, va: int) -> tuple[str, int, int] | None:
    for section in getattr(binary, "sections", []) or []:
        start = int(getattr(section, "virtual_address", 0) or 0)
        size = int(getattr(section, "size", 0) or 0)
        if size <= 0:
            continue
        end = start + size
        if start <= va < end:
            return str(getattr(section, "name", "")), start, end
    return None


def infer_dynlink_protected_ranges(binary) -> list[tuple[int, int]]:
    """Protect sections commonly involved in dynamic relocation and indirect calls."""

    names = [
        ".interp",
        ".dynamic",
        ".got",
        ".got.plt",
        ".data.rel.ro",
        ".rela.dyn",
        ".rela.plt",
        ".dynsym",
        ".dynstr",
        ".gnu.hash",
        ".gnu.version",
        ".gnu.version_r",
    ]
    ranges: list[tuple[int, int]] = []
    for name in names:
        r = _section_range(binary, name)
        if r:
            ranges.append(r)
    return merge_ranges(ranges)


def infer_unwind_protected_ranges(binary) -> list[tuple[int, int]]:
    """Protect unwind/exception metadata sections.

    These sections are typically data-only but are consulted by runtime unwinding
    and some stack overflow/panic paths.
    """

    names = [
        ".eh_frame_hdr",
        ".eh_frame",
        ".gcc_except_table",
    ]
    ranges: list[tuple[int, int]] = []
    for name in names:
        r = _section_range(binary, name)
        if r:
            ranges.append(r)
    return merge_ranges(ranges)


@dataclass(frozen=True)
class TextRange:
    start: int
    end: int


def _clamp_range(start: int, end: int, *, low: int, high: int) -> tuple[int, int]:
    start = max(low, start)
    end = min(high, end)
    if end < start:
        return start, start
    return start, end


def _iter_text_sections(binary) -> list[TextRange]:
    ranges: list[TextRange] = []
    for section in getattr(binary, "sections", []) or []:
        if getattr(section, "name", "") != ".text":
            continue
        start = int(getattr(section, "virtual_address", 0) or 0)
        size = int(getattr(section, "size", 0) or 0)
        if size <= 0:
            continue
        ranges.append(TextRange(start=start, end=start + size))
    return ranges


def _read_text_bytes(binary, text_start: int, text_end: int) -> bytes:
    size = max(0, int(text_end - text_start))
    if size <= 0:
        return b""
    return bytes(binary.get_content_from_virtual_address(text_start, size))


def _find_all(data: bytes, needle: bytes) -> list[int]:
    if not data or not needle:
        return []
    out: list[int] = []
    i = 0
    while True:
        j = data.find(needle, i)
        if j < 0:
            return out
        out.append(j)
        i = j + 1


def _sign_extend_32(value: int) -> int:
    value &= 0xFFFFFFFF
    if value & 0x80000000:
        return value - 0x100000000
    return value


def infer_indirect_protected_ranges(
    *,
    binary,
    icf_window: int,
    jumptable_window: int,
) -> list[tuple[int, int]]:
    """Heuristically protect indirect call/jmp neighborhoods and jump-table bases.

    This is intentionally conservative: it is better to preserve a bit more `.text`
    than to crash due to an unsanitized indirect-dispatch path.
    """

    icf_window = max(0, int(icf_window))
    jumptable_window = max(0, int(jumptable_window))
    if icf_window == 0 and jumptable_window == 0:
        return []

    ranges: list[tuple[int, int]] = []
    text_ranges = _iter_text_sections(binary)
    for tr in text_ranges:
        blob = _read_text_bytes(binary, tr.start, tr.end)
        if not blob:
            continue

        # Indirect call/jmp opcodes (very coarse):
        # - `FF D0..D7`: call rax..rdi
        # - `41 FF D0..D7`: call r8..r15
        # - `FF E0..E7`: jmp  rax..rdi
        # - `41 FF E0..E7`: jmp  r8..r15
        if icf_window > 0:
            for base_opcode, second_range in (
                (b"\xff", range(0xD0, 0xD8)),
                (b"\xff", range(0xE0, 0xE8)),
            ):
                for second in second_range:
                    for off in _find_all(blob, base_opcode + bytes([second])):
                        va = tr.start + off
                        start, end = va - icf_window, va + icf_window
                        start, end = _clamp_range(start, end, low=tr.start, high=tr.end)
                        ranges.append((start, end))

                    needle = b"\x41" + base_opcode + bytes([second])
                    for off in _find_all(blob, needle):
                        va = tr.start + off
                        start, end = va - icf_window, va + icf_window
                        start, end = _clamp_range(start, end, low=tr.start, high=tr.end)
                        ranges.append((start, end))

            # RIP-relative indirect call/jmp through a pointer table:
            # - `FF 15 disp32`: call qword ptr [rip+disp32]
            # - `FF 25 disp32`: jmp  qword ptr [rip+disp32]
            # These are common in PIC code and can go through GOT-like pointer slots.
            # Protect both around the callsite and around the referenced pointer slot.
            for op2 in (0x15, 0x25):
                needle = b"\xff" + bytes([op2])
                for off in _find_all(blob, needle):
                    # Need 6 bytes total to read disp32
                    if off + 6 > len(blob):
                        continue
                    disp = int.from_bytes(blob[off + 2 : off + 6], "little", signed=False)
                    disp = _sign_extend_32(disp)
                    call_va = tr.start + off
                    next_insn = call_va + 6
                    slot_va = next_insn + disp

                    cs, ce = call_va - icf_window, call_va + icf_window
                    cs, ce = _clamp_range(cs, ce, low=tr.start, high=tr.end)
                    ranges.append((cs, ce))

                    # The pointer slot is often in .got/.data.rel.ro. Protect it only if it
                    # resolves to a real section, clamping to that section bounds.
                    containing = _section_containing_va(binary, slot_va)
                    if containing is not None:
                        _, s_start, s_end = containing
                        slot_lo, slot_hi = slot_va - 0x80, slot_va + 0x80
                        slot_lo, slot_hi = _clamp_range(slot_lo, slot_hi, low=s_start, high=s_end)
                        ranges.append((slot_lo, slot_hi))

        # Jump-table pattern support:
        # Look for `movslq disp32(%rcx,%r8,4),%rdx` (exact bytes: 4A 63 14 81)
        # preceded nearby by a `lea disp32(%rip), %rcx` (48 8D 0D + disp32).
        # This matches the `pwd` block we observed at RVA 0x1fd8c5.
        jt_needle = b"\x4a\x63\x14\x81"
        lea_rcx_prefix = b"\x48\x8d\x0d"
        if jumptable_window > 0 or icf_window > 0:
            for jt_off in _find_all(blob, jt_needle):
                jt_va = tr.start + jt_off
                # search backwards up to 0x80 bytes for lea rcx, [rip+disp32]
                back_start = max(0, jt_off - 0x80)
                back_blob = blob[back_start:jt_off]
                lea_pos = back_blob.rfind(lea_rcx_prefix)
                if lea_pos < 0:
                    continue
                lea_off = back_start + lea_pos
                if lea_off + 7 > len(blob):
                    continue
                disp = int.from_bytes(blob[lea_off + 3 : lea_off + 7], "little", signed=False)
                disp = _sign_extend_32(disp)
                lea_va = tr.start + lea_off
                next_insn = lea_va + 7
                table_base = next_insn + disp

                # protect around the jump table base; clamp to .text
                if jumptable_window > 0:
                    start = table_base
                    end = table_base + jumptable_window
                    start, end = _clamp_range(start, end, low=tr.start, high=tr.end)
                    ranges.append((start, end))
                # also protect around the dispatch site
                if icf_window > 0:
                    start, end = jt_va - icf_window, jt_va + icf_window
                    start, end = _clamp_range(start, end, low=tr.start, high=tr.end)
                    ranges.append((start, end))

    return merge_ranges(ranges)


def merge_log_reports(log_paths: list[Path]) -> tuple[set[int], int]:
    executed: set[int] = set()
    total_rows = 0
    for log_path in log_paths:
        report = _fast_collect_executed_addresses(log_path)
        executed.update(report.addresses)
        total_rows += report.parsed_rows
    return executed, total_rows


@dataclass(frozen=True)
class AddressReport:
    addresses: set[int]
    parsed_rows: int


def _fast_collect_executed_addresses(log_path: Path) -> AddressReport:
    """Fast path for extracting executed addresses from large logs.

    Supports common formats produced by this repo:
    - "Executed instruction at 0x..."
    - "0x..." (raw hex address lines)
    - "...: 0x..." (colon-separated)
    
    Falls back to the slower regex-based implementation if parsing yields nothing.
    """

    addresses: set[int] = set()
    parsed_rows = 0

    # Keep parsing very simple and fast: mostly splits and int(..., 16).
    with log_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            parsed_rows += 1

            try:
                if "0x" in line:
                    idx = line.find("0x")
                    token = line[idx:]
                    # stop token at first non-hex char
                    j = 2
                    while j < len(token) and token[j] in "0123456789abcdefABCDEF":
                        j += 1
                    token = token[:j]
                    if len(token) > 2:
                        addresses.add(int(token, 16))
                        continue

                # raw decimal? some tools emit plain integers
                if line.isdigit():
                    addresses.add(int(line, 10))
                    continue
            except ValueError:
                continue

    # If nothing parsed, use the slower (but more flexible) analyzer.
    if not addresses:
        report = collect_executed_addresses(log_path)
        return AddressReport(addresses=set(report.addresses), parsed_rows=int(report.parsed_rows))

    return AddressReport(addresses=addresses, parsed_rows=parsed_rows)


def _unique_log_cache_path(log_path: Path, cache_dir: Path) -> Path:
    stat = log_path.stat()
    key = f"{log_path.resolve()}|{stat.st_size}|{int(stat.st_mtime)}"
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
    return cache_dir / f"{log_path.name}.{digest}.unique.txt"


def _write_unique_log(src_log: Path, dst_log: Path) -> None:
    dst_log.parent.mkdir(parents=True, exist_ok=True)
    addresses: set[int] = set()
    report = _fast_collect_executed_addresses(src_log)
    addresses = report.addresses
    with dst_log.open("w", encoding="utf-8") as handle:
        for addr in sorted(addresses):
            handle.write(f"0x{addr:x}\n")


def materialize_unique_logs(log_paths: list[Path], cache_dir: Path) -> list[Path]:
    unique_paths: list[Path] = []
    for log_path in log_paths:
        cached = _unique_log_cache_path(log_path, cache_dir)
        if not cached.exists():
            print(f"Creating unique log: {cached} (from {log_path})")
            _write_unique_log(log_path, cached)
        unique_paths.append(cached)
    return unique_paths


def infer_offset(addresses: set[int], binary) -> int:
    if not addresses:
        raise ValueError("Instruction logs are empty; nothing to sanitize.")
    entrypoint = int(getattr(binary, "entrypoint", 0) or 0)
    if entrypoint == 0:
        raise ValueError("Unable to determine binary entrypoint for offset inference.")
    # Use the smallest logged address as the basis for PIE offset inference.
    lowest_address = min(addresses)
    inferred = lowest_address - entrypoint
    if inferred <= 0:
        raise ValueError(
            "Inferred PIE offset is not positive. Pass --offset explicitly to override this value."
        )
    return inferred


def compute_segments(addresses: set[int], gap: int) -> list[tuple[int, int]]:
    if not addresses:
        return []
    gap = max(1, int(gap))
    sorted_addrs = sorted(addresses)
    segments: list[tuple[int, int]] = []
    start = prev = sorted_addrs[0]
    for address in sorted_addrs[1:]:
        if address - prev > gap:
            segments.append((start, prev))
            start = address
        prev = address
    segments.append((start, prev))
    return segments


def pad_segments(segments: list[tuple[int, int]], padding: int) -> list[tuple[int, int]]:
    if not segments:
        return []
    padding = max(0, int(padding))
    padded: list[tuple[int, int]] = []
    for start, end in segments:
        adj_start = max(0, start - padding)
        adj_end = max(adj_start, end + padding)
        padded.append((adj_start, adj_end))
    return merge_ranges(padded)


def merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not ranges:
        return []
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            prev_start, prev_end = merged[-1]
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def apply_offset(addresses: set[int], offset: int) -> set[int]:
    if not offset:
        return set(addresses)
    return {address - offset for address in addresses}


def parse_range_text(text: str) -> tuple[int, int]:
    raw = text.strip()
    if not raw:
        raise ValueError("Empty protect range entry")
    if ":" in raw:
        start_text, end_text = raw.split(":", 1)
        start = int(start_text, 0)
        end = int(end_text, 0)
    elif "+" in raw:
        start_text, length_text = raw.split("+", 1)
        start = int(start_text, 0)
        length = int(length_text, 0)
        if length < 0:
            raise ValueError("Range length must be non-negative")
        end = start + max(0, length)
    else:
        # treat single value as a zero-length range (single instruction)
        start = end = int(raw, 0)
    if start > end:
        start, end = end, start
    return start, end


def normalize_manual_ranges(
    *,
    range_texts: list[str],
    addresses: list[int],
    radius: int,
) -> list[tuple[int, int]]:
    manual: list[tuple[int, int]] = []
    for text in range_texts:
        try:
            manual.append(parse_range_text(text))
        except ValueError as exc:
            raise SystemExit(f"Invalid --protect-range '{text}': {exc}") from exc
    padding = max(0, int(radius or 0))
    for address in addresses:
        start = max(0, address - padding)
        end = address + padding
        manual.append((start, end))
    return manual


def main() -> int:
    args = parse_args()
    if not args.logs:
        raise SystemExit("At least one --log must be provided")
    binary_path = args.binary
    if not binary_path.exists():
        raise SystemExit(f"Binary not found: {binary_path}")
    log_paths = [path for path in args.logs if path.exists()]
    if not log_paths:
        raise SystemExit("None of the provided logs exist on disk.")

    if args.make_unique_logs:
        cache_dir = args.unique_log_dir
        if cache_dir is None:
            cache_dir = PROJECT_ROOT / DEFAULT_UNIQUE_LOG_DIRNAME
        log_paths = materialize_unique_logs(log_paths, cache_dir)

    executed_abs, total_rows = merge_log_reports(log_paths)
    if not executed_abs:
        raise SystemExit("The combined logs did not contain any executed instructions.")

    import lief

    binary = lief.parse(str(binary_path))
    offset = args.offset if args.offset is not None else infer_offset(executed_abs, binary)
    executed_rel = apply_offset(executed_abs, offset)
    segments_rel = compute_segments(executed_rel, args.segment_gap)
    protected_ranges = pad_segments(segments_rel, args.segment_padding)

    if args.protect_dynlinks:
        dyn_ranges = infer_dynlink_protected_ranges(binary)
        if dyn_ranges:
            protected_ranges = merge_ranges(protected_ranges + dyn_ranges)
            print(f"Added {len(dyn_ranges)} dynamic-linker protected range(s).")

    if args.protect_unwind:
        unwind_ranges = infer_unwind_protected_ranges(binary)
        if unwind_ranges:
            protected_ranges = merge_ranges(protected_ranges + unwind_ranges)
            print(f"Added {len(unwind_ranges)} unwind/exception protected range(s).")

    if args.protect_indirect:
        icf_extra = infer_indirect_protected_ranges(
            binary=binary,
            icf_window=args.icf_window,
            jumptable_window=args.jumptable_window,
        )
        if icf_extra:
            protected_ranges = merge_ranges(protected_ranges + icf_extra)
            print(f"Added {len(icf_extra)} heuristic indirect-control-flow protected range(s).")
    manual_ranges_abs = normalize_manual_ranges(
        range_texts=args.protect_ranges,
        addresses=args.protect_addresses,
        radius=args.protect_radius,
    )
    if manual_ranges_abs:
        manual_rel = [
            (max(0, start - offset), max(0, end - offset)) for start, end in manual_ranges_abs
        ]
        protected_ranges = merge_ranges(protected_ranges + manual_rel)
        print(
            f"Added {len(manual_ranges_abs)} manual protect range(s) spanning {len(manual_rel)} translated span(s)."
        )

    sanitizer = BinarySanitizer()
    result = sanitizer.sanitize(
        binary_path,
        executed_rel,
        args.output,
        forced_mode=None,
        only_text_section=args.only_text,
        binary=binary,
        preserve_trampolines=args.keep_trampolines,
        protected_ranges=protected_ranges,
    )
    print(
        f"Sanitization complete. Total instructions: {result.total_instructions}, preserved: {result.preserved_instructions}, "
        f"nopped: {result.nopped_instructions}. Output: {result.output_path}"
    )
    print(f"Processed {total_rows} instruction rows across {len(log_paths)} log(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
