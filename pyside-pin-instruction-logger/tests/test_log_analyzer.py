import tempfile
import unittest

from src.services.log_analyzer import collect_executed_addresses


class TestLogAnalyzer(unittest.TestCase):
    def test_collect_executed_addresses_samples_unique_entries(self) -> None:
        lines = []
        for idx in range(40):
            address = 0x401000 + (idx * 4)
            lines.append(f"Executed instruction at: 0x{address:08x} - mov eax, {idx}")
        log_blob = "\n".join(lines)

        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.write(log_blob)
            tmp_path = tmp.name

        report = collect_executed_addresses(tmp_path)

        self.assertEqual(report.parsed_rows, 40)
        self.assertEqual(len(report.addresses), 40)
        self.assertEqual(len(report.sampled_instructions), 32)
        first_address, first_instruction = report.sampled_instructions[0]
        self.assertEqual(first_address, 0x401000)
        self.assertEqual(first_instruction, "mov eax, 0")


if __name__ == "__main__":
    unittest.main()
