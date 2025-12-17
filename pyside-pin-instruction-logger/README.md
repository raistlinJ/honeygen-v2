# pyside-pin-instruction-logger

This project is a PySide application that utilizes Intel PIN to log instructions executed by a specified binary file. It provides a user-friendly interface for running binaries with the Intel PIN tool and viewing the logged instructions.

## Project Structure

```
pyside-pin-instruction-logger
├── src
│   ├── app.py                  # Main entry point of the application
│   ├── ui
│   │   └── main_window.ui      # UI layout for the main window
│   ├── controllers
│   │   └── runner.py           # Controller for managing execution of the Intel PIN tool
│   ├── services
│   │   ├── pin_runner.py       # Service for executing the Intel PIN tool
│   │   └── parser.py           # Service for parsing log output
│   ├── models
│   │   └── log_entry.py        # Model representing a log entry
│   └── (additional modules)
├── pin-tool
│   ├── makefile                # Build instructions for the Intel PIN tool
│   └── ins_logger.cpp          # Implementation of logging functionality
├── scripts
│   ├── build_tool.sh           # Script to automate the build process
│   └── run_with_pin.py         # Script to run the binary with Intel PIN
├── tests
│   └── test_parser.py          # Unit tests for the parser functionality
├── pyproject.toml              # Project configuration file
├── requirements.txt            # Python dependencies
└── README.md                   # Project documentation
```

## Setup Instructions

1. **Clone the repository:**
   ```
   git clone <repository-url>
   cd pyside-pin-instruction-logger
   ```

2. **Install dependencies with uv:**
   ```
   uv sync
   ```

3. **Ensure the Intel PIN kit is installed:**
   Extract Intel PIN 4 to `/home/researchdev/Downloads/pin4` (or set `PIN_ROOT` to another location). The helper scripts default to that path.

4. **Build the Intel PIN tool:**
   ```
   bash scripts/build_tool.sh
   ```

5. **Run the application:**
   ```
   uv run python src/app.py
   ```

## Usage

- Use the application interface to specify the Intel PIN directory once, choose the log destination, and pick the binary you want to run; the app remembers your selections between sessions.
- The bundled CLI mirrors the UI workflow for quick tests:
   ```
   uv run python scripts/run_with_pin.py ./path/to/binary -- --arg1 --arg2
   ```
- By default both the GUI and CLI call `/home/researchdev/Downloads/pin4/pin`. Override by setting `PIN_ROOT=/custom/pin` before running.
- When preparing a log that will later drive sanitization, make sure lazy-binding stubs (PLT entries) actually execute. The quickest way is to set `LD_BIND_NOW=1` for that run (in the GUI, add it under “Environment Overrides”; via CLI run `LD_BIND_NOW=1 uv run python scripts/run_with_pin.py …`). This forces glibc to resolve every PLT slot up front so the trace covers those addresses and the sanitizer leaves them intact. If you can’t rerun with that flag, leave the **Preserve PLT/.init/.fini sections** toggle (enabled by default) turned on so the sanitizer skips those trampolines for you.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.