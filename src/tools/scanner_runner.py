import json
import shutil
import subprocess
from typing import Any


class ScannerCommandError(Exception):
    def __init__(self, scanner: str, message: str, returncode: int | None = None):
        self.scanner = scanner
        self.message = message
        self.returncode = returncode
        super().__init__(message)


def find_executable(name: str) -> str | None:
    return shutil.which(name)


def run_scanner(
    scanner: str,
    command: list[str],
    *,
    timeout: int = 180,
) -> dict[str, Any]:
    executable = find_executable(command[0])
    if executable is None:
        raise ScannerCommandError(scanner, f"{command[0]} not found in PATH")

    completed = subprocess.run(
        [executable, *command[1:]],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )

    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()

    if not stdout:
        detail = stderr or f"{scanner} returned no output (exit {completed.returncode})"
        raise ScannerCommandError(scanner, detail, completed.returncode)

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ScannerCommandError(
            scanner,
            f"Failed to parse {scanner} JSON output: {exc}",
            completed.returncode,
        ) from exc

    return payload
