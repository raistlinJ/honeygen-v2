import tempfile
import unittest

from src.services.parser import parse_log


class TestParser(unittest.TestCase):
    def test_parse_pin_logger_format(self) -> None:
        log_data = """\
Executed instruction at: 0x00400500 - mov eax, ebx
Executed instruction at: 0x00400504 - add eax, 1
Executed instruction at: 0x00400508 - sub ebx, eax
"""
        expected_output = [
            {"address": "0x00400500", "instruction": "mov eax, ebx"},
            {"address": "0x00400504", "instruction": "add eax, 1"},
            {"address": "0x00400508", "instruction": "sub ebx, eax"},
        ]
        result = parse_log(log_data)
        self.assertEqual(result, expected_output)

    def test_parse_pin_logger_without_prefix(self) -> None:
        log_data = """\
Executed instruction at: 7c5473fc3140 - mov rdi, rsp
Executed instruction at: 7c5473fc3143 - call 0x7c5473fc3ca0
"""
        expected_output = [
            {"address": "0x7c5473fc3140", "instruction": "mov rdi, rsp"},
            {"address": "0x7c5473fc3143", "instruction": "call 0x7c5473fc3ca0"},
        ]
        result = parse_log(log_data)
        self.assertEqual(result, expected_output)

    def test_parse_pin_logger_with_metadata_block(self) -> None:
        log_data = """\
Executed instruction at: 0x401000 [pid=123 tid=1] - mov eax, ebx
Executed instruction at: 0x401002 [pid=123 tid=1] - add eax, 1
"""
        expected_output = [
            {"address": "0x401000", "instruction": "mov eax, ebx"},
            {"address": "0x401002", "instruction": "add eax, 1"},
        ]
        result = parse_log(log_data)
        self.assertEqual(result, expected_output)

    def test_parse_colon_format_from_file(self) -> None:
        log_data = """\
0x00400500: mov eax, ebx
0x00400504: add eax, 1
"""
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.write(log_data)
            tmp_path = tmp.name
        expected_output = [
            {"address": "0x00400500", "instruction": "mov eax, ebx"},
            {"address": "0x00400504", "instruction": "add eax, 1"},
        ]
        result = parse_log(tmp_path)
        self.assertEqual(result, expected_output)

    def test_parse_colon_format_without_prefix(self) -> None:
        log_data = """\
7c5473fc3140: mov rdi, rsp
7c5473fc3143: call 0x7c5473fc3ca0
"""
        expected_output = [
            {"address": "0x7c5473fc3140", "instruction": "mov rdi, rsp"},
            {"address": "0x7c5473fc3143", "instruction": "call 0x7c5473fc3ca0"},
        ]
        result = parse_log(log_data)
        self.assertEqual(result, expected_output)

    def test_ignores_invalid_lines(self) -> None:
        log_data = """\
random noise

Executed instruction at: 0x00400500 - mov eax, ebx
no colon here either
"""
        result = parse_log(log_data)
        self.assertEqual(result, [{"address": "0x00400500", "instruction": "mov eax, ebx"}])


if __name__ == "__main__":
    unittest.main()