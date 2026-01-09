from __future__ import annotations

import json
from datetime import datetime

from models.run_entry import RunEntry
from models.sanitized_output import SanitizedBinaryOutput
from services.history_store import HistoryStore


def test_history_store_round_trips_sanitized_output_works(tmp_path):
    store = HistoryStore(path=tmp_path / "history.json")
    project = "p"

    entry = RunEntry(
        entry_id="e1",
        name="run",
        binary_path="/bin/true",
        log_path="/tmp/log.txt",
        timestamp=datetime(2026, 1, 1, 0, 0, 0),
        sanitized_outputs=[
            SanitizedBinaryOutput(output_id="o1", output_path="/tmp/s1", works=None),
            SanitizedBinaryOutput(output_id="o2", output_path="/tmp/s2", works=True),
            SanitizedBinaryOutput(output_id="o3", output_path="/tmp/s3", works=False),
        ],
    )

    store.save_project(project, [entry])
    loaded = store.load_project(project)
    assert len(loaded) == 1

    outputs = {o.output_id: o for o in loaded[0].sanitized_outputs}
    assert outputs["o1"].works is None
    assert outputs["o2"].works is True
    assert outputs["o3"].works is False


def test_history_store_defaults_missing_works_to_none(tmp_path):
    store = HistoryStore(path=tmp_path / "history.json")

    raw = {
        "p": [
            {
                "entry_id": "e1",
                "name": "run",
                "binary_path": "/bin/true",
                "log_path": "/tmp/log.txt",
                "timestamp": "2026-01-01T00:00:00",
                "sanitized_outputs": [
                    {
                        "output_id": "o1",
                        "output_path": "/tmp/s1",
                        "segment_gap": 0,
                        "segment_padding": 0,
                        "icf_window": 0,
                        "jumptable_window": 0,
                        "total_instructions": 0,
                        "preserved_instructions": 0,
                        "nopped_instructions": 0,
                        "generated_at": None,
                    }
                ],
            }
        ]
    }
    store.path.write_text(json.dumps(raw), encoding="utf-8")

    loaded = store.load_project("p")
    assert len(loaded) == 1
    assert len(loaded[0].sanitized_outputs) == 1
    assert loaded[0].sanitized_outputs[0].works is None


def test_history_store_round_trips_run_metrics(tmp_path):
    store = HistoryStore(path=tmp_path / "history.json")
    project = "p"

    entry = RunEntry(
        entry_id="e1",
        name="run",
        binary_path="/bin/true",
        log_path="/tmp/log.txt",
        timestamp=datetime(2026, 1, 1, 0, 0, 0),
        run_metrics={
            "wall_time_ms": 123,
            "cpu_user_s": 0.25,
            "cpu_system_s": 0.1,
            "peak_rss_bytes": 1024,
        },
    )

    store.save_project(project, [entry])
    loaded = store.load_project(project)
    assert len(loaded) == 1
    assert loaded[0].run_metrics is not None
    assert loaded[0].run_metrics.get("wall_time_ms") == 123
    assert loaded[0].run_metrics.get("peak_rss_bytes") == 1024
