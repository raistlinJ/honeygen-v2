import pytest

from src.app import ModuleSelectionDialog


@pytest.mark.qt_no_exception_capture
def test_unique_only_checkbox_tracks_state(qtbot):
	dialog = ModuleSelectionDialog(
		None,
		"Binary",
		["moduleA", "moduleB"],
		default_log_label="run",
		default_unique_only=True,
	)
	qtbot.addWidget(dialog)

	assert dialog.unique_only() is True

	dialog.unique_only_checkbox.setChecked(False)
	assert dialog.unique_only() is False


@pytest.mark.qt_no_exception_capture
def test_run_with_sudo_checkbox_tracks_state(qtbot):
	dialog = ModuleSelectionDialog(
		None,
		"Binary",
		["moduleA", "moduleB"],
		default_log_label="run",
		default_run_with_sudo=False,
	)
	qtbot.addWidget(dialog)

	assert dialog.run_with_sudo() is False

	dialog.run_with_sudo_checkbox.setChecked(True)
	assert dialog.run_with_sudo() is True