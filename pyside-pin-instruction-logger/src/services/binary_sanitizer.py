from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import capstone
import lief


@dataclass
class SanitizationResult:
    total_instructions: int
    preserved_instructions: int
    nopped_instructions: int
    output_path: Path


class BinarySanitizer:
    """Replace non-executed instructions with architecture-appropriate NOPs."""

    def __init__(self) -> None:
        self._elf_execinstr_flag = self._resolve_elf_execinstr_flag()

    def sanitize(
        self,
        binary_path: Path,
        executed_addresses: set[int],
        output_path: Path,
        *,
        forced_mode: int | None = None,
        only_text_section: bool = False,
        binary: lief.Binary | None = None,
    ) -> SanitizationResult:
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        if not executed_addresses:
            raise ValueError("No executed instructions were found in the supplied log.")

        try:
            original_mode = os.stat(binary_path).st_mode
        except OSError as exc:
            raise OSError(f"Unable to inspect permissions for {binary_path}: {exc}") from exc

        binary_obj = binary if binary is not None else lief.parse(str(binary_path))
        arch, mode, nop_generator = self._capstone_config(binary_obj)
        md = capstone.Cs(arch, mode)
        md.detail = False

        total = 0
        patched = 0

        sections = list(self._executable_sections(binary_obj))
        if only_text_section:
            text_sections = [section for section in sections if self._is_text_section(section)]
            if not text_sections:
                raise ValueError("No executable .text sections found in the binary for sanitization.")
            sections = text_sections

        for section in sections:
            data = bytes(section.content)
            if not data:
                continue
            for instruction in md.disasm(data, section.virtual_address):
                total += 1
                address = int(instruction.address)
                if address in executed_addresses:
                    continue
                nop_bytes = nop_generator(instruction.size)
                self._patch_bytes(binary_obj, address, nop_bytes)
                patched += 1

        output_path.parent.mkdir(parents=True, exist_ok=True)
        binary_obj.write(str(output_path))
        target_mode = stat.S_IMODE(forced_mode if forced_mode is not None else original_mode)
        try:
            os.chmod(output_path, target_mode)
        except OSError as exc:
            raise OSError(
                f"Failed to apply executable permissions to sanitized binary {output_path}: {exc}"
            ) from exc
        preserved = total - patched
        return SanitizationResult(total, preserved, patched, output_path)

    def _capstone_config(self, binary: lief.Binary):
        if isinstance(binary, lief.ELF.Binary):
            machine = getattr(binary.header, "machine_type", None)
            if machine is None:
                raise NotImplementedError("ELF machine type unavailable; cannot determine architecture")
            if machine == lief.ELF.ARCH.X86_64:
                return capstone.CS_ARCH_X86, capstone.CS_MODE_64, self._nop_x86
            if machine == lief.ELF.ARCH.X86:
                return capstone.CS_ARCH_X86, capstone.CS_MODE_32, self._nop_x86
            if machine == lief.ELF.ARCH.AARCH64:
                return capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM, self._nop_arm64
        raise NotImplementedError(f"Unsupported binary architecture for sanitization: {machine}")

    def _nop_x86(self, size: int) -> bytes:
        return b"\x90" * size

    def _nop_arm64(self, size: int) -> bytes:
        pattern = b"\x1f\x20\x03\xd5"
        repeats = (size + len(pattern) - 1) // len(pattern)
        data = pattern * repeats
        return data[:size]

    def _executable_sections(self, binary: lief.Binary) -> Iterable[lief.Section]:
        if isinstance(binary, lief.ELF.Binary):
            exec_flag = self._elf_execinstr_flag
            for section in binary.sections:
                try:
                    flags_value = int(section.flags)
                except (TypeError, ValueError):
                    continue
                if flags_value & exec_flag:
                    yield section
        else:
            raise NotImplementedError("Executable section detection only supports ELF binaries at the moment")

    def _is_text_section(self, section: lief.Section) -> bool:
        name = getattr(section, "name", "") or ""
        return name.lower().startswith(".text")

    def _patch_bytes(self, binary: lief.Binary, address: int, data: bytes) -> None:
        binary.patch_address(address, list(data))

    def sanity_check(self, binary_path: Path) -> None:
        if not binary_path.exists():
            raise FileNotFoundError(f"Sanitized binary not found at {binary_path}")
        try:
            lief.parse(str(binary_path))
        except Exception as exc:  # pragma: no cover - defensive
            raise RuntimeError(f"Unable to parse sanitized binary via LIEF: {exc}") from exc
        if not os.access(binary_path, os.X_OK):
            raise PermissionError(f"Sanitized binary is not executable: {binary_path}")

    def verify_logged_instructions(
        self,
        binary: lief.Binary,
        samples: list[tuple[int, str]],
        *,
        max_bytes: int = 16,
    ) -> None:
        if not samples:
            return
        arch, mode, _ = self._capstone_config(binary)
        md = capstone.Cs(arch, mode)
        md.detail = False
        for address, expected in samples:
            expected_clean = (expected or "").strip()
            if not expected_clean:
                continue
            try:
                raw = binary.get_content_from_virtual_address(address, max_bytes)
            except Exception as exc:  # pragma: no cover - defensive
                raise RuntimeError(f"Unable to read bytes at 0x{address:x}: {exc}") from exc
            data = bytes(raw)
            if not data:
                raise RuntimeError(f"No bytes available at 0x{address:x} for verification")
            insn_iter = md.disasm(data, address)
            instruction = next(insn_iter, None)
            if instruction is None:
                raise RuntimeError(f"Unable to disassemble instruction at 0x{address:x}")
            actual = f"{instruction.mnemonic} {instruction.op_str}".strip()
            if actual.lower() != expected_clean.lower():
                raise RuntimeError(
                    f"Instruction mismatch at 0x{address:x}: expected '{expected_clean}', got '{actual}'"
                )

    def _resolve_elf_execinstr_flag(self) -> int:
        elf_module = getattr(lief, "ELF", None)
        if elf_module is None:
            raise NotImplementedError("Current lief build does not expose ELF helpers")

        section_flags = getattr(elf_module, "SECTION_FLAGS", None)
        if section_flags is not None and hasattr(section_flags, "EXECINSTR"):
            return int(section_flags.EXECINSTR)

        section_class = getattr(elf_module, "Section", None)
        flag_enum = getattr(section_class, "FLAGS", None) if section_class else None
        if flag_enum is not None and hasattr(flag_enum, "EXECINSTR"):
            return int(flag_enum.EXECINSTR)

        raise NotImplementedError(
            "Unable to determine ELF EXECINSTR section flag from the installed lief version"
        )
