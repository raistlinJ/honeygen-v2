import pytest

from src.app import SequenceAnalyzerDialog

pytestmark = pytest.mark.timeout(15)

def _make_matches() -> list[dict[str, object]]:
	return [
		{
			"trace_row": 0,
			"trace_start": 0x5000,
			"offset": 0x10,
			"preview": "trace_0 | trace_1",
		},
		{
			"trace_row": 4,
			"trace_start": 0x5010,
			"offset": 0x20,
			"preview": "trace_4 | trace_5",
		},
	]


@pytest.mark.qt_no_exception_capture
def test_sequence_analyzer_populates_results_table(qtbot, sample_preview_rows):
	dialog = SequenceAnalyzerDialog(None, sample_preview_rows)
	qtbot.addWidget(dialog)

	matches = _make_matches()
	dialog._populate_results(matches, truncated=False)

	assert dialog.results_table.rowCount() == len(matches)
	assert dialog.results_table.item(0, 0).text() == "0x5000"
	assert dialog.results_table.item(0, 1).text() == dialog._format_offset(0x10)
	assert "Found" in dialog.results_status.text()
	assert not dialog.set_offset_button.isEnabled()


@pytest.mark.qt_no_exception_capture
def test_sequence_analyzer_truncated_message(qtbot, sample_preview_rows):
	dialog = SequenceAnalyzerDialog(None, sample_preview_rows)
	qtbot.addWidget(dialog)

	dialog._populate_results(_make_matches(), truncated=True)

	status = dialog.results_status.text()
	assert "Showing first" in status
	assert str(len(_make_matches())) in status


@pytest.mark.qt_no_exception_capture
def test_sequence_analyzer_emits_offset_when_row_selected(qtbot, sample_preview_rows):
	dialog = SequenceAnalyzerDialog(None, sample_preview_rows)
	qtbot.addWidget(dialog)

	matches = _make_matches()
	dialog._populate_results(matches, truncated=False)
	dialog.results_table.selectRow(1)

	with qtbot.waitSignal(dialog.offset_selected, timeout=1000) as blocker:
		dialog._handle_set_offset_clicked()

	assert blocker.args == [matches[1]["offset"]]
	assert not dialog.isVisible() or dialog.result() == dialog.Accepted


@pytest.mark.qt_no_exception_capture
def test_ngram_tree_emits_trace_navigation(qtbot, sample_preview_rows):
	dialog = SequenceAnalyzerDialog(None, sample_preview_rows)
	qtbot.addWidget(dialog)
	assert dialog._binary_rows, "Binary rows should be available for analyzer test."
	length = 2 if len(dialog._binary_rows) >= 2 else 1
	binary_addr = int(dialog._binary_rows[0]["display"])
	trace_addr = int(sample_preview_rows[1][0]) if len(sample_preview_rows) > 1 else int(sample_preview_rows[0][0])
	match = {
		"binary_start_index": 0,
		"trace_start_index": 1,
		"binary_address": binary_addr,
		"trace_address": trace_addr,
		"offset": trace_addr - binary_addr,
		"length": length,
	}
	dialog._show_ngram_results([match], length)
	top_item = dialog.ngram_results_tree.topLevelItem(0)
	assert top_item is not None
	child = top_item.child(0)
	assert child is not None
	with qtbot.waitSignal(dialog.trace_address_requested, timeout=1000) as blocker:
		dialog._handle_ngram_item_activated(child, 0)
	assert blocker.args == [trace_addr]


@pytest.mark.qt_no_exception_capture
def test_ngram_tree_populates_results_table(qtbot, sample_preview_rows):
	dialog = SequenceAnalyzerDialog(None, sample_preview_rows)
	qtbot.addWidget(dialog)
	assert dialog._binary_rows
	length = 2 if len(dialog._binary_rows) >= 2 else 1
	trace_addr = int(sample_preview_rows[0][0])
	match = {
		"binary_start_index": 0,
		"trace_start_index": 0,
		"binary_address": int(dialog._binary_rows[0]["display"]),
		"trace_address": trace_addr,
		"offset": trace_addr - int(dialog._binary_rows[0]["display"]),
		"length": length,
	}
	dialog._ngram_matches = [match]
	dialog._show_ngram_results([match], length)
	top_item = dialog.ngram_results_tree.topLevelItem(0)
	assert top_item is not None
	dialog._handle_ngram_item_activated(top_item, 0)
	qtbot.waitUntil(lambda: dialog.results_table.rowCount() == 1, timeout=2000)
	assert dialog.results_table.item(0, 0).text() == f"0x{trace_addr:x}"


def test_instruction_normalization_strips_padding():
	text = "ADD  eax , 00042"
	assert SequenceAnalyzerDialog._normalize_instruction(text) == "addeax,42"
	assert SequenceAnalyzerDialog._normalize_instruction("add eax,0x5") == "addeax,5"