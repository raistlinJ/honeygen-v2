import tempfile
import unittest

from src.services.log_analyzer import collect_executed_addresses, compute_address_segments


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

    def test_compute_address_segments_groups_by_gap(self) -> None:
        entries = [
            {"address": "0x401000", "instruction": "mov"},
            {"address": "0x401004", "instruction": "add"},
            {"address": "0x401050", "instruction": "sub"},
            {"address": "0x401058", "instruction": "cmp"},
            {"address": "0x401060", "instruction": "jmp"},
        ]
        addresses, segments = compute_address_segments(entries, max_gap=8)
        self.assertEqual(addresses, [0x401000, 0x401004, 0x401050, 0x401058, 0x401060])
        # Expect two segments: first two addresses contiguous, remaining three within gap.
        self.assertEqual(segments, [(0x401000, 0x401004), (0x401050, 0x401060)])


if __name__ == "__main__":
    unittest.main()
