#!/usr/bin/env python3
"""Generate committed PASS/FAIL sample dashboards from ci_gate runs."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN_PY = ROOT / "src" / "main.py"
PASS_OUT = ROOT / "reports" / "SAMPLE_DASHBOARD.html"
FAIL_OUT = ROOT / "reports" / "SAMPLE_DASHBOARD_FAIL.html"
LIVE_OUT = ROOT / "reports" / "SECOPS_DASHBOARD.html"

_DEMO_FAIL_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
_DEMO_FAIL_LINE = f'_DEMO_CI_FAIL_KEY = "{_DEMO_FAIL_KEY}"  # demo-only: remove after CI evidence\n'
_DEMO_FAIL_MARKER = "demo-only: remove after CI evidence"


def main() -> int:
    env = {**dict(__import__("os").environ), "PYTHONPATH": "src", "SECOPS_SAST_ENGINE": "regex"}

    print("== PASS sample (main, no app blockers) ==")
    pass_code = _run_ci_gate(env)
    if pass_code != 0:
        print(f"ERROR: expected ci_gate exit 0 for PASS sample, got {pass_code}", file=sys.stderr)
        return 1
    _copy_dashboard(PASS_OUT)
    print(f"Wrote {PASS_OUT.relative_to(ROOT)}")

    print("\n== FAIL sample (demo secret in src/main.py) ==")
    original = MAIN_PY.read_text(encoding="utf-8")
    if _DEMO_FAIL_MARKER not in original:
        MAIN_PY.write_text(_DEMO_FAIL_LINE + original, encoding="utf-8")
    try:
        fail_code = _run_ci_gate(env)
        if fail_code == 0:
            print("ERROR: expected ci_gate exit 1 for FAIL sample", file=sys.stderr)
            return 1
        _copy_dashboard(FAIL_OUT)
        print(f"Wrote {FAIL_OUT.relative_to(ROOT)}")
    finally:
        restored = MAIN_PY.read_text(encoding="utf-8")
        if _DEMO_FAIL_MARKER in restored:
            MAIN_PY.write_text(restored.replace(_DEMO_FAIL_LINE, "", 1), encoding="utf-8")

    print("\nDone. Open:")
    print(f"  PASS: {PASS_OUT}")
    print(f"  FAIL: {FAIL_OUT}")
    return 0


def _run_ci_gate(env: dict[str, str]) -> int:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "ci_gate.py")],
        cwd=ROOT,
        env=env,
        check=False,
    )
    return result.returncode


def _copy_dashboard(target: Path) -> None:
    if not LIVE_OUT.is_file():
        raise FileNotFoundError(f"Missing {LIVE_OUT}")
    target.write_text(LIVE_OUT.read_text(encoding="utf-8"), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
