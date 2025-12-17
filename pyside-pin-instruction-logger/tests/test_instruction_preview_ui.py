import pytest

from src.app import (
    InstructionPreviewDialog,
    SanitizationPreviewDialog,
    SectionBuildWorker,
    _normalize_instruction_text,
)

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
    assert "+0x40" in dialog.offset_label.text()


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


@pytest.mark.qt_no_exception_capture
def test_save_button_only_enabled_when_dirty(qtbot, sample_preview_rows):
    saved_values: list[int] = []

    def _saver(value: int) -> bool:
        saved_values.append(value)
        return True

    dialog = SanitizationPreviewDialog(
        None,
        "Test Entry",
        sample_preview_rows,
        save_offset_callback=_saver,
        warn_on_unsaved=True,
    )
    qtbot.addWidget(dialog)

    assert not dialog.save_offset_button.isEnabled()
    assert "#888" in dialog.save_offset_button.styleSheet()

    offset = 0x30
    payload = {
        "rows": [(addr + offset, binary, logged) for addr, binary, logged in sample_preview_rows],
    }
    dialog._assign_offset_payload(payload, offset)

    assert dialog.save_offset_button.isEnabled()
    assert dialog.save_offset_button.styleSheet() == ""
    assert "unsaved" in dialog.offset_label.text().lower()

    dialog._handle_save_offset_clicked()

    assert saved_values == [offset]
    assert not dialog.save_offset_button.isEnabled()
    assert "#888" in dialog.save_offset_button.styleSheet()
    assert "unsaved" not in dialog.offset_label.text().lower()


@pytest.mark.qt_no_exception_capture
def test_sanitization_preview_prompts_when_save_enabled(qtbot, sample_preview_rows):
    dialog = SanitizationPreviewDialog(
        None,
        "Test Entry",
        sample_preview_rows,
        save_offset_callback=lambda value: True,
        warn_on_unsaved=False,
    )
    qtbot.addWidget(dialog)

    payload_offset = 0x25
    payload = {
        "rows": [(addr + payload_offset, binary, logged) for addr, binary, logged in sample_preview_rows],
    }
    dialog._assign_offset_payload(payload, payload_offset)

    assert dialog.save_offset_button.isEnabled()
    assert dialog._should_prompt_unsaved_close()


def test_instruction_normalization_ignores_whitespace_and_padding():
    left = "  MOV   eax ,   0x000010  "
    right = "mov eax,0x10"
    assert _normalize_instruction_text(left) == _normalize_instruction_text(right)
    assert _normalize_instruction_text("add eax,0x5") == _normalize_instruction_text("add eax,5")
    state = InstructionPreviewDialog._row_state((0x1000, left, right))
    assert state == "match"


@pytest.mark.qt_no_exception_capture
def test_overview_status_displays_match_counts(qtbot, sample_preview_rows):
    dialog = InstructionPreviewDialog(None, "Test Entry", sample_preview_rows)
    qtbot.addWidget(dialog)
    table = dialog.overview_table
    assert table.rowCount() >= 3
    statuses = [table.item(row, 3).text() for row in range(table.rowCount())]
    assert "1/1 match" in statuses
    assert "0/1 match" in statuses
    assert "2/2 match" in statuses


def test_build_sections_reports_custom_progress_total(sample_preview_rows):
    progress_updates: list[tuple[int, int]] = []

    InstructionPreviewDialog._build_sections(
        sample_preview_rows,
        progress_callback=lambda processed, total: progress_updates.append((processed, total)),
        progress_total=10,
    )

    assert progress_updates, "Expected at least one progress update"
    assert progress_updates[-1] == (10, 10)


def test_section_build_worker_handles_missing_segments(sample_preview_rows):
    worker = SectionBuildWorker(
        sample_preview_rows,
        None,
        offset=0,
        raw_addresses=[],
        sorted_values=[],
        sorted_pairs=[],
    )
    progress_updates: list[tuple[int, int]] = []
    payloads: list[dict[str, object]] = []

    worker.progress.connect(lambda processed, total: progress_updates.append((processed, total)))
    worker.finished.connect(lambda payload: payloads.append(payload if isinstance(payload, dict) else {}))

    worker.run()

    assert progress_updates, "Expected SectionBuildWorker to emit progress"
    final_processed, final_total = progress_updates[-1]
    assert final_total == len(sample_preview_rows)
    assert final_processed == len(sample_preview_rows)
    assert payloads and len(payloads[0].get("sections", [])) >= 1


def test_progress_status_includes_percentage():
    text = InstructionPreviewDialog._format_progress_status("Testing", 5, 10)
    assert "5/10" in text
    assert "50.0%" in text
