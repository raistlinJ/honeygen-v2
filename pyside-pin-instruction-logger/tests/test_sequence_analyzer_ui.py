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