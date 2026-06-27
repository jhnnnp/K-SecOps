# Intentional insecure patterns for SAST regression (fixture only — do not import).
import subprocess

def run_user_input(payload: str) -> None:
    eval(payload)  # noqa: S307 — demo-only SAST target
    subprocess.run(f"echo {payload}", shell=True)
