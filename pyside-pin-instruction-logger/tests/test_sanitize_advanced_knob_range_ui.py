import pytest

from src.app import SanitizeConfigDialog


pytestmark = pytest.mark.timeout(15)


@pytest.mark.qt_no_exception_capture
def test_sanitize_advanced_knob_rows_have_separate_start_end_and_base_dropdown(qtbot):
    dialog = SanitizeConfigDialog(
        None,
        default_name="out.bin",
        default_permissions=0o755,
        sanity_allowed=True,
        initial=None,
    )
    qtbot.addWidget(dialog)

    # Verify separate dropdown fields exist
    for prefix in ("gap", "pad", "icf", "jt"):
        assert hasattr(dialog, f"{prefix}_start_combo")
        assert hasattr(dialog, f"{prefix}_end_combo")
        assert hasattr(dialog, f"{prefix}_interval_combo")

        start_combo = getattr(dialog, f"{prefix}_start_combo")
        end_combo = getattr(dialog, f"{prefix}_end_combo")
        interval_combo = getattr(dialog, f"{prefix}_interval_combo")
        assert start_combo.count() >= 10
        assert end_combo.count() >= 10
        assert interval_combo.count() >= 10

    assert not hasattr(dialog, "gap_base_combo")

    dialog.gap_start_combo.setCurrentText("0x10")
    dialog.gap_end_combo.setCurrentText("0x20")
    dialog.gap_interval_combo.setCurrentText("0x2")

    assert dialog.gap_start_combo.currentText() == "0x10"
    assert dialog.gap_end_combo.currentText() == "0x20"
    assert dialog.gap_interval_combo.currentText() == "0x2"


@pytest.mark.qt_no_exception_capture
def test_sanitize_selected_options_parses_start_end_interval(qtbot):
    dialog = SanitizeConfigDialog(
        None,
        default_name="out.bin",
        default_permissions=0o755,
        sanity_allowed=True,
        initial=None,
    )
    qtbot.addWidget(dialog)

    dialog.gap_start_combo.setCurrentText("0x10")
    dialog.gap_end_combo.setCurrentText("0x10")
    dialog.gap_interval_combo.setCurrentText("0x0")

    opts = dialog.selected_options()
    assert opts.segment_gap == 0x10
