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


@pytest.mark.qt_no_exception_capture
def test_sanitized_run_forces_main_binary_module_selected(qtbot):
	dialog = ModuleSelectionDialog(
		None,
		"nginx.sanitized",
		["nginx.sanitized", "libc.so.6"],
		default_log_label="run",
		previous_selection=["libc.so.6"],
		is_sanitized_run=True,
	)
	qtbot.addWidget(dialog)

	selected = [m.lower() for m in dialog.selected_modules()]
	assert "nginx.sanitized" in selected
	assert "libc.so.6" in selected