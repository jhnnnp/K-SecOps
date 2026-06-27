"""Step-by-step progress tracking for demo hub pipelines."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

ProgressCallback = Callable[[dict[str, Any]], None]

LOCAL_STEP_DEFS: list[tuple[str, str]] = [
    ("patch", "코드 패치 적용"),
    ("scan", "6트랙 스캔 (ci_gate.py)"),
    ("gate", "게이트 판정"),
    ("publish", "Live Dashboard 게시"),
]

PR_STEP_DEFS: list[tuple[str, str]] = [
    ("precheck", "Git 작업 트리 확인"),
    ("patch", "시나리오 코드 패치"),
    ("commit", "Commit"),
    ("push", "Push → GitHub"),
    ("pr", "PR 생성/갱신"),
    ("ci", "SecOps Gate CI 대기"),
    ("artifact", "CI Artifact 다운로드"),
    ("publish", "Live Dashboard 게시"),
]


@dataclass
class StepState:
    id: str
    label: str
    status: str = "pending"  # pending | running | done | failed
    message: str = ""
    updated_at: str = ""


@dataclass
class PipelineProgress:
    step_defs: list[tuple[str, str]]
    on_update: ProgressCallback | None = None
    steps: list[StepState] = field(init=False)
    logs: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.steps = [StepState(id=sid, label=label) for sid, label in self.step_defs]

    def log(self, message: str) -> None:
        stamp = _now()
        line = f"[{stamp}] {message}"
        self.logs.append(line)
        if len(self.logs) > 80:
            self.logs = self.logs[-80:]
        self._emit()

    def set_detail(self, key: str, value: Any) -> None:
        self.details[key] = value
        self._emit()

    def start(self, step_id: str, message: str = "") -> None:
        step = self._step(step_id)
        step.status = "running"
        step.message = message
        step.updated_at = _now()
        if message:
            self.log(f"{step.label}: {message}")
        self._emit()

    def done(self, step_id: str, message: str = "", **details: Any) -> None:
        step = self._step(step_id)
        step.status = "done"
        step.message = message
        step.updated_at = _now()
        self.details.update(details)
        if message:
            self.log(f"{step.label} — {message}")
        self._emit()

    def fail(self, step_id: str, message: str) -> None:
        step = self._step(step_id)
        step.status = "failed"
        step.message = message
        step.updated_at = _now()
        self.log(f"FAILED {step.label}: {message}")
        self._emit()

    def progress_pct(self) -> int:
        if not self.steps:
            return 0
        done = sum(1 for s in self.steps if s.status in {"done", "failed"})
        running = sum(1 for s in self.steps if s.status == "running")
        partial = running * 0.5
        return min(100, int((done + partial) / len(self.steps) * 100))

    def snapshot(self) -> dict[str, Any]:
        return {
            "steps": [
                {
                    "id": s.id,
                    "label": s.label,
                    "status": s.status,
                    "message": s.message,
                    "updated_at": s.updated_at,
                }
                for s in self.steps
            ],
            "logs": list(self.logs),
            "details": dict(self.details),
            "progress_pct": self.progress_pct(),
        }

    def _step(self, step_id: str) -> StepState:
        for step in self.steps:
            if step.id == step_id:
                return step
        raise KeyError(step_id)

    def _emit(self) -> None:
        if self.on_update:
            self.on_update(self.snapshot())


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")
