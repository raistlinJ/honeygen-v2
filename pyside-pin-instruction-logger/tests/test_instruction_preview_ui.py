import pytest

from src.app import InstructionPreviewDialog

pytestmark = pytest.mark.timeout(15)

@pytest.mark.qt_no_exception_capture
def test_instruction_preview_applies_offset_without_freezing(qtbot, sample_preview_rows):
    dialog = InstructionPreviewDialog(None, "Test Entry", sample_preview_rows)
    qtbot.addWidget(dialog)
    dialog.show()

    dialog._apply_binary_offset(0x40)

    qtbot.wait_until(lambda: dialog._binary_offset == 0x40, timeout=3000)
    qtbot.wait_until(lambda: dialog._offset_thread is None, timeout=3000)

    shifted_first = dialog._rows[0][0]
    assert shifted_first == sample_preview_rows[0][0] + 0x40
    assert dialog._offset_progress_dialog is None
    assert dialog.overview_table.rowCount() == len(dialog._sections)
    assert dialog.offset_label.text().endswith("+0x40")


@pytest.mark.qt_no_exception_capture
def test_detail_population_async_reports_progress(qtbot, sample_preview_rows, many_preview_rows):
    dialog = InstructionPreviewDialog(None, "Test Entry", sample_preview_rows)
    qtbot.addWidget(dialog)
    rows = many_preview_rows
    progress_messages: list[str] = []
    done: list[bool] = []

    dialog._populate_detail_table(
        rows,
        progress_callback=progress_messages.append,
        done_callback=lambda: done.append(True),
    )

    qtbot.wait_until(lambda: bool(done), timeout=3000)

    assert progress_messages, "Expected progress updates while populating detail rows"
    assert dialog.detail_table.rowCount() == len(rows)


def test_detail_rows_resolve_binary_instruction_relative_to_offset(qtbot):
    raw_rows = [(0x2100, "<no-instruction>", "mov eax, ebx")]
    dialog = InstructionPreviewDialog(None, "Test Entry", raw_rows)
    qtbot.addWidget(dialog)
    offset = 0x100

    class DummyResolver:
        def __init__(self) -> None:
            self.calls: list[int] = []

        def resolve(self, address: int) -> str | None:
            self.calls.append(address)
            return "mov eax, [rbp]" if address == 0x2000 else None

    resolver = DummyResolver()
    dialog._binary_instruction_resolver = resolver

    payload = {
        "rows": [(raw_rows[0][0] + offset, raw_rows[0][1], raw_rows[0][2])],
        "match_rows": 0,
        "sections": [],
    }
    dialog._assign_offset_payload(payload, offset)

    dialog._populate_detail_table(dialog._rows)

    assert resolver.calls and set(resolver.calls) == {0x2000}
    assert dialog.detail_table.item(0, 1).text() == "mov eax, [rbp]"
