import sys
import unittest
from pathlib import Path

import lief

from src.services.binary_sanitizer import BinarySanitizer


class TestBinarySanitizerVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.binary_path = Path(sys.executable)
        cls.binary = lief.parse(str(cls.binary_path))
        cls.sanitizer = BinarySanitizer()
        arch, mode, _ = cls.sanitizer._capstone_config(cls.binary)
        cls._disassembler = cls._make_disassembler(arch, mode)
        cls._reference_instruction = cls._locate_first_instruction()

    @classmethod
    def _make_disassembler(cls, arch, mode):
        import capstone

        engine = capstone.Cs(arch, mode)
        engine.detail = False
        return engine

    @classmethod
    def _locate_first_instruction(cls):
        for section in cls.sanitizer._executable_sections(cls.binary):
            data = bytes(section.content)
            if not data:
                continue
            for instruction in cls._disassembler.disasm(data, section.virtual_address):
                text = f"{instruction.mnemonic} {instruction.op_str}".strip()
                if text:
                    return instruction.address, text
        raise RuntimeError("Unable to locate an executable instruction for verification tests")

    def test_verify_logged_instructions_passes_for_matching_sample(self) -> None:
        address, text = self._reference_instruction
        self.sanitizer.verify_logged_instructions(self.binary, [(address, text)])

    def test_verify_logged_instructions_raises_for_mismatch(self) -> None:
        address, text = self._reference_instruction
        mismatched_text = text + " /* mismatch */"
        with self.assertRaises(RuntimeError):
            self.sanitizer.verify_logged_instructions(self.binary, [(address, mismatched_text)])


if __name__ == "__main__":
    unittest.main()
