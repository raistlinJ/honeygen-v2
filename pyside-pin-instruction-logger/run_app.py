#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent
    src_dir = root / "src"
    sys.path.insert(0, str(src_dir))

    # Import after sys.path adjustment so `controllers`, `services`, etc. resolve.
    import app as gui_app  # type: ignore

    # `src/app.py` is designed to be executed as a script; forward to it.
    if getattr(gui_app, "__name__", "") == "app" and hasattr(gui_app, "QApplication"):
        # Execute the same bottom-of-file logic as `python src/app.py`.
        from PySide6.QtWidgets import QApplication

        qt_app = QApplication(sys.argv)
        window = gui_app.App()
        window.show()
        return int(qt_app.exec())

    raise RuntimeError("Unexpected app module layout; cannot launch GUI.")


if __name__ == "__main__":
    raise SystemExit(main())
