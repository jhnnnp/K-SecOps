# Intentional insecure patterns for SAST regression (fixture only — do not import).
import os
import pickle
import subprocess

def run_user_input(payload: str) -> None:
    eval(payload)  # noqa: S307 — demo-only SAST target
    exec(payload)  # noqa: S102 — demo-only SAST target
    os.system(payload)
    pickle.loads(payload)
    subprocess.run(f"echo {payload}", shell=True)
