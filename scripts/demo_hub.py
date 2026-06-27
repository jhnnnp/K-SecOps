#!/usr/bin/env python3
"""Local web demo hub: scenario buttons → code change → PR/CI → live dashboard."""

from __future__ import annotations

import sys
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from demo_progress import LOCAL_STEP_DEFS, PR_STEP_DEFS, PipelineProgress  # noqa: E402
from demo_scenarios import (  # noqa: E402
    DEMO_LIVE_DIR,
    PR_SCENARIOS,
    publish_live,
    run_full_pr_pipeline,
    run_local_gate,
)

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles
except ImportError as exc:
    raise SystemExit("Install dependencies: pip install fastapi uvicorn") from exc

DEMO_DIR = ROOT / "docs" / "demo"
JOBS: dict[str, "JobRecord"] = {}
JOBS_LOCK = threading.Lock()

app = FastAPI(title="K-SecOps Demo Hub", version="1.0.0")


@dataclass
class JobRecord:
    status: str = "running"
    message: str = ""
    error: str = ""
    scenario: str = ""
    conclusion: str = ""
    pr_url: str = ""
    run_url: str = ""
    dashboard_url: str = ""
    steps: list[dict[str, Any]] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    progress_pct: int = 0


@app.get("/")
def index() -> FileResponse:
    return FileResponse(DEMO_DIR / "index.html")


@app.get("/api/scenarios")
def list_scenarios() -> list[dict[str, Any]]:
    from dataclasses import asdict

    from demo_scenarios import SCENARIOS  # noqa: WPS433

    return [asdict(item) for item in SCENARIOS]


@app.post("/api/scenarios/{scenario_id}/run")
def run_scenario(scenario_id: str) -> dict[str, str]:
    if scenario_id not in {"2", "3", *PR_SCENARIOS}:
        raise HTTPException(status_code=400, detail=f"Unsupported scenario: {scenario_id}")

    job_id = str(uuid.uuid4())
    with JOBS_LOCK:
        JOBS[job_id] = JobRecord(status="running", scenario=scenario_id, message="Starting…")

    thread = threading.Thread(target=_execute_job, args=(job_id, scenario_id), daemon=True)
    thread.start()
    return {"job_id": job_id, "scenario": scenario_id}


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str) -> dict[str, Any]:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return _job_payload(job)


@app.get("/api/active")
def active_status() -> dict[str, Any]:
    """Latest status.json plus any in-flight job snapshot."""
    path = DEMO_DIR / "status.json"
    payload: dict[str, Any] = {"hub": {}, "running_jobs": []}
    if path.is_file():
        import json

        payload["hub"] = json.loads(path.read_text(encoding="utf-8"))
    with JOBS_LOCK:
        for job in JOBS.values():
            if job.status == "running":
                payload["running_jobs"].append(_job_payload(job))
    return payload


def _job_payload(job: JobRecord) -> dict[str, Any]:
    return {
        "status": job.status,
        "message": job.message,
        "error": job.error,
        "scenario": job.scenario,
        "conclusion": job.conclusion,
        "pr_url": job.pr_url,
        "run_url": job.run_url,
        "dashboard_url": job.dashboard_url,
        "steps": job.steps,
        "logs": job.logs,
        "details": job.details,
        "progress_pct": job.progress_pct,
    }


def _execute_job(job_id: str, scenario_id: str) -> None:
    step_defs = PR_STEP_DEFS if scenario_id in PR_SCENARIOS else LOCAL_STEP_DEFS

    def on_progress(snapshot: dict[str, Any]) -> None:
        _set_job(
            job_id,
            steps=snapshot.get("steps", []),
            logs=snapshot.get("logs", []),
            details=snapshot.get("details", {}),
            progress_pct=snapshot.get("progress_pct", 0),
            message=_current_step_message(snapshot),
        )

    progress = PipelineProgress(step_defs, on_update=on_progress)

    try:
        if scenario_id in PR_SCENARIOS:
            result = run_full_pr_pipeline(scenario_id, progress=progress)
            _set_job(
                job_id,
                status="done",
                message="PR pipeline complete",
                conclusion=result.get("conclusion", ""),
                pr_url=result.get("pr_url", ""),
                run_url=result.get("run_url", ""),
                dashboard_url=f"/live/scenario-{scenario_id}.html",
            )
            return

        inject_fail = scenario_id == "3"
        code, dashboard = run_local_gate(inject_fail=inject_fail, progress=progress)
        conclusion = "failure" if code != 0 else "success"
        progress.start("publish", "docs/demo/live/ 에 게시")
        publish_live(scenario_id, dashboard, conclusion=conclusion)
        progress.done("publish", f"scenario-{scenario_id}.html")

        _set_job(
            job_id,
            status="done",
            message="Local gate finished",
            conclusion=conclusion,
            dashboard_url=f"/live/scenario-{scenario_id}.html",
        )
    except Exception as exc:  # noqa: BLE001 — surface job errors to UI
        failed_step = next((s for s in progress.steps if s.status == "running"), None)
        if failed_step:
            progress.fail(failed_step.id, str(exc))
        _set_job(job_id, status="failed", error=str(exc))


def _current_step_message(snapshot: dict[str, Any]) -> str:
    for step in snapshot.get("steps", []):
        if step.get("status") == "running":
            msg = step.get("message") or step.get("label")
            return f"{step.get('label')}: {msg}"
    for step in reversed(snapshot.get("steps", [])):
        if step.get("status") == "done":
            return step.get("message") or step.get("label", "")
    return "Running…"


def _set_job(job_id: str, **kwargs: Any) -> None:
    with JOBS_LOCK:
        job = JOBS[job_id]
        for key, value in kwargs.items():
            setattr(job, key, value)


@app.get("/status.json")
def status_json() -> FileResponse:
    path = DEMO_DIR / "status.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="status.json not found")
    return FileResponse(path)


app.mount("/live", StaticFiles(directory=DEMO_LIVE_DIR, html=True), name="live")


def main() -> None:
    import argparse
    import socket

    import uvicorn

    parser = argparse.ArgumentParser(description="K-SecOps interactive demo hub")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    def port_in_use(host: str, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            return sock.connect_ex((host, port)) == 0

    port = args.port
    if port_in_use(args.host, port):
        print(f"Port {port} is already in use.")
        print(f"  Stop it: lsof -ti :{port} | xargs kill -9")
        print(f"  Or run:  python3 scripts/demo_hub.py --port {port + 1}")
        raise SystemExit(1)

    DEMO_LIVE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"K-SecOps Demo Hub → http://{args.host}:{port}")
    print("PR scenarios require: gh auth login")
    uvicorn.run(app, host=args.host, port=port, log_level="info")


if __name__ == "__main__":
    main()
