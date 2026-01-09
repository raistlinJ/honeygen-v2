import pytest

from datetime import datetime
from pathlib import Path

import src.app as app_module
from src.app import SanitizeConfigDialog, SanitizeOptions
from src.config_manager import ConfigManager
from src.models.run_entry import RunEntry
from src.models.sanitized_output import SanitizedBinaryOutput
from src.services.binary_sanitizer import SanitizationResult
from src.services.history_store import HistoryStore


pytestmark = pytest.mark.timeout(15)


def _make_isolated_app(qtbot, tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "ConfigManager", lambda: ConfigManager(path=tmp_path / "app_settings.json"))
    monkeypatch.setattr(app_module, "HistoryStore", lambda: HistoryStore(path=tmp_path / "honey_history.json"))
    monkeypatch.setattr(app_module.App, "_refresh_revng_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module.App, "_refresh_revng_container_status", lambda *args, **kwargs: None)
    app = app_module.App()
    qtbot.addWidget(app)
    app._repo_root = tmp_path
    return app


@pytest.mark.qt_no_exception_capture
def test_sanitize_config_dialog_exposes_keep_only_one_per_nop_checkbox(qtbot):
    dialog = SanitizeConfigDialog(
        None,
        default_name="out.bin",
        default_permissions=0o755,
        sanity_allowed=True,
        initial={"keep_only_one_per_nop_count": True},
    )
    qtbot.addWidget(dialog)

    assert hasattr(dialog, "keep_only_one_per_nop_checkbox")
    assert dialog.keep_only_one_per_nop_checkbox.isChecked() is True

    opts = dialog.selected_options()
    assert isinstance(opts, SanitizeOptions)
    assert opts.keep_only_one_per_nop_count is True


@pytest.mark.qt_no_exception_capture
def test_add_sanitized_output_can_dedupe_by_nop_count(qtbot, tmp_path, monkeypatch):
    app = _make_isolated_app(qtbot, tmp_path, monkeypatch)

    existing_path = tmp_path / "existing.bin"
    existing_path.write_text("x")
    new_path = tmp_path / "new.bin"
    new_path.write_text("y")

    now = datetime.now()
    entry = RunEntry(
        entry_id="e1",
        name="entry",
        binary_path=str(tmp_path / "parentbin"),
        log_path=str(tmp_path / "parentlog"),
        timestamp=now,
        sanitized_outputs=[
            SanitizedBinaryOutput(
                output_id="o1",
                output_path=str(existing_path),
                works=None,
                nopped_instructions=10,
                preserved_instructions=90,
                total_instructions=100,
                generated_at=now,
            )
        ],
    )
    app.run_entries = [entry]

    options = SanitizeOptions(
        sanity_check=False,
        output_name=None,
        permissions_mask=None,
        only_text_section=False,
        replace_mismatched_instructions=True,
        preserve_trampoline_sections=True,
        runnable_first=True,
        protect_dynlinks=True,
        protect_unwind=True,
        protect_indirect=True,
        segment_padding=0x2000,
        icf_window=0x400,
        jumptable_window=0x800,
        segment_gap=0,
        keep_only_one_per_nop_count=True,
    )

    # Same NOP count => do not add.
    skipped = app._add_sanitized_output(
        entry,
        SanitizationResult(
            total_instructions=100,
            preserved_instructions=90,
            nopped_instructions=10,
            output_path=Path(new_path),
        ),
        options,
    )
    assert skipped is False
    assert len(entry.sanitized_outputs) == 1

    # Different NOP count => add.
    added = app._add_sanitized_output(
        entry,
        SanitizationResult(
            total_instructions=100,
            preserved_instructions=89,
            nopped_instructions=11,
            output_path=Path(tmp_path / "new2.bin"),
        ),
        options,
    )
    assert added is True
    assert len(entry.sanitized_outputs) == 2
