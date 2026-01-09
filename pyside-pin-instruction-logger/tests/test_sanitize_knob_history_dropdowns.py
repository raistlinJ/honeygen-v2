import pytest

from src.app import SanitizeConfigDialog


pytestmark = pytest.mark.timeout(15)


@pytest.mark.qt_no_exception_capture
def test_sanitize_knob_dropdowns_populate_from_history(qtbot):
    initial = {
        "segment_gap_start": "0x10",
        "segment_gap_end": "0x20",
        "segment_gap_interval": "0x2",
        "segment_gap_history": ["0x30", "0x40"],
        "segment_gap_interval_history": ["0x1"],
    }
    dialog = SanitizeConfigDialog(
        None,
        default_name="out.bin",
        default_permissions=0o755,
        sanity_allowed=True,
        initial=initial,
    )
    qtbot.addWidget(dialog)

    assert dialog.gap_start_combo.currentText() == "0x10"
    assert dialog.gap_end_combo.currentText() == "0x20"
    assert dialog.gap_interval_combo.currentText() == "0x2"

    assert dialog.gap_start_combo.count() >= 10
    assert dialog.gap_end_combo.count() >= 10
    assert dialog.gap_interval_combo.count() >= 10

    items = [dialog.gap_start_combo.itemText(i) for i in range(dialog.gap_start_combo.count())]
    assert "0x30" in items
    assert "0x40" in items

    interval_items = [dialog.gap_interval_combo.itemText(i) for i in range(dialog.gap_interval_combo.count())]
    assert "0x1" in interval_items
