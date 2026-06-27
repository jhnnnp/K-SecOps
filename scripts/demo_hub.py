#!/usr/bin/env python3
"""Local web demo hub: scenario buttons → code change → PR/CI → live dashboard."""

from __future__ import annotations

import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

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


@app.get("/")
def index() -> FileResponse:
    return FileResponse(DEMO_DIR / "index.html")


@app.get("/api/scenarios")
def list_scenarios() -> list[dict[str, Any]]:
    from demo_scenarios import SCENARIOS, asdict  # noqa: WPS433

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
def job_status(job_id: str) -> dict[str, str]:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "status": job.status,
        "message": job.message,
        "error": job.error,
        "scenario": job.scenario,
        "conclusion": job.conclusion,
        "pr_url": job.pr_url,
        "run_url": job.run_url,
        "dashboard_url": job.dashboard_url,
    }


def _execute_job(job_id: str, scenario_id: str) -> None:
    try:
        if scenario_id in PR_SCENARIOS:
            _set_job(job_id, message="Applying patch, pushing PR…")
            result = run_full_pr_pipeline(scenario_id)
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

        if scenario_id == "2":
            _set_job(job_id, message="Running local PASS gate…")
            code, dashboard = run_local_gate(inject_fail=False)
            target = _publish_local(scenario_id, dashboard, "success" if code == 0 else "failure")
            _set_job(
                job_id,
                status="done",
                message="Local gate finished",
                conclusion="success" if code == 0 else "failure",
                dashboard_url=f"/live/scenario-{scenario_id}.html",
            )
            return

        if scenario_id == "3":
            _set_job(job_id, message="Running local FAIL gate…")
            code, dashboard = run_local_gate(inject_fail=True)
            target = _publish_local(scenario_id, dashboard, "failure" if code != 0 else "success")
            _set_job(
                job_id,
                status="done",
                message="Local FAIL simulation finished",
                conclusion="failure" if code != 0 else "success",
                dashboard_url=f"/live/scenario-{scenario_id}.html",
            )
            return

        raise ValueError(f"Unhandled scenario {scenario_id}")
    except Exception as exc:  # noqa: BLE001 — surface job errors to UI
        _set_job(job_id, status="failed", error=str(exc))


def _publish_local(scenario_id: str, dashboard: Path, conclusion: str) -> Path:
    return publish_live(scenario_id, dashboard, conclusion=conclusion)


def _set_job(job_id: str, **kwargs: str) -> None:
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
    import uvicorn

    DEMO_LIVE_DIR.mkdir(parents=True, exist_ok=True)
    print("K-SecOps Demo Hub → http://127.0.0.1:8765")
    print("PR scenarios require: gh auth login")
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")


if __name__ == "__main__":
    main()
