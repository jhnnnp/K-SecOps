#!/usr/bin/env python3
"""Scenario definitions and orchestration for PR demos and live dashboard publishing."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from demo_progress import PipelineProgress

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

_DEMO_FAIL_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
_DEMO_FAIL_LINE = f'_DEMO_CI_FAIL_KEY = "{_DEMO_FAIL_KEY}"  # demo-only: remove after CI evidence\n'
_DEMO_FAIL_MARKER = "demo-only: remove after CI evidence"

DEMO_LIVE_DIR = ROOT / "docs" / "demo" / "live"
STATUS_PATH = ROOT / "docs" / "demo" / "status.json"
GATE_WORKFLOW = "secops-gate.yml"


@dataclass(frozen=True)
class ScenarioDef:
    number: str
    title: str
    description: str
    kind: str  # local | pr | actions
    branch: str | None = None
    pr_title: str = ""
    pr_body: str = ""


SCENARIOS: list[ScenarioDef] = [
    ScenarioDef("1", "Local — demo report", "dummy-infra 스캔 → Lab 리포트", "local"),
    ScenarioDef("2", "Local — CI gate PASS", "main 기준 gate → PASS 대시보드", "local"),
    ScenarioDef("3", "Local — FAIL simulation", "src/ 시크릿 주입 gate 차단 확인", "local"),
    ScenarioDef("4", "Local — all", "1 → 2 → 3 일괄", "local"),
    ScenarioDef(
        "5",
        "PR — PASS demo",
        "docs-only 변경 → push → PR → SecOps Gate 초록",
        "pr",
        branch="demo/ci-pass",
        pr_title="demo: CI gate PASS",
        pr_body="SecOps Gate PASS demo. Safe docs-only change on dummy-infra.",
    ),
    ScenarioDef(
        "6",
        "PR — FAIL demo",
        "src/ 예시 키 추가 → push → PR → merge 차단",
        "pr",
        branch="demo/ci-fail-secret",
        pr_title="demo: CI gate FAIL (intentional secret)",
        pr_body="Intentional AWS docs example key in src/main.py for SecOps Gate FAIL demo. Do not merge.",
    ),
    ScenarioDef("7", "Sync CI evidence", "GitHub API → README 증거 갱신", "actions"),
    ScenarioDef("8", "Actions — SecOps Gate", "workflow_dispatch 원격 gate", "actions"),
    ScenarioDef("9", "Actions — Sync CI Evidence", "workflow_dispatch 증거 sync", "actions"),
]

PR_SCENARIOS = {"5", "6"}


def get_scenario(number: str) -> ScenarioDef:
    for item in SCENARIOS:
        if item.number == number:
            return item
    raise ValueError(f"Unknown scenario: {number}")


def apply_scenario(number: str) -> list[str]:
    """Apply file changes for a scenario. Returns list of changed relative paths."""
    if number == "5":
        return _apply_pr_pass()
    if number == "6":
        return _apply_pr_fail()
    raise ValueError(f"Scenario {number} has no apply patch (kind={get_scenario(number).kind})")


def _apply_pr_pass() -> list[str]:
    readme = ROOT / "dummy-infra" / "README.md"
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    original = readme.read_text(encoding="utf-8")
    marker = "<!-- ci-pass-demo:"
    if marker not in original:
        readme.write_text(original.rstrip() + f"\n\n<!-- ci-pass-demo: {stamp} -->\n", encoding="utf-8")
    return ["dummy-infra/README.md"]


def _apply_pr_fail() -> list[str]:
    main_py = ROOT / "src" / "main.py"
    original = main_py.read_text(encoding="utf-8")
    if _DEMO_FAIL_MARKER not in original:
        main_py.write_text(_DEMO_FAIL_LINE + original, encoding="utf-8")
    return ["src/main.py"]


def restore_application_code() -> None:
    """Remove demo-only secret line from src/main.py if present."""
    main_py = ROOT / "src" / "main.py"
    if not main_py.is_file():
        return
    content = main_py.read_text(encoding="utf-8")
    if _DEMO_FAIL_MARKER in content:
        main_py.write_text(content.replace(_DEMO_FAIL_LINE, "", 1), encoding="utf-8")


def orchestrate_pr(
    number: str,
    *,
    repository: str = "",
    progress: PipelineProgress | None = None,
) -> dict[str, Any]:
    """Apply patch, commit, push branch, open/update PR."""
    scenario = get_scenario(number)
    if scenario.kind != "pr" or not scenario.branch:
        raise ValueError(f"Scenario {number} is not a PR scenario")

    if progress:
        progress.start("precheck", "커밋되지 않은 변경 확인")
    _require_git_clean()
    if progress:
        progress.done("precheck", "작업 트리 clean")

    if os.getenv("GITHUB_ACTIONS") == "true":
        _run_git("config", "user.name", "github-actions[bot]")
        _run_git("config", "user.email", "github-actions[bot]@users.noreply.github.com")

    _run_git("checkout", "main")
    _run_git_optional("pull", "--ff-only", "origin", "main")
    _run_git("checkout", "-B", scenario.branch)

    if progress:
        progress.start("patch", f"브랜치 {scenario.branch} 에 시나리오 {number} 패치")
    changed = apply_scenario(number)
    if progress:
        progress.done("patch", f"변경 파일: {', '.join(changed)}", changed_files=changed, branch=scenario.branch)
        progress.set_detail("branch", scenario.branch)
        progress.set_detail("changed_files", changed)

    for path in changed:
        _run_git("add", path)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    message = f"demo: scenario {number} ({stamp})"
    if progress:
        progress.start("commit", message)
    _run_git("commit", "-m", message)
    head = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if progress:
        progress.done("commit", f"commit {head}", commit=message, head_sha=head)
        progress.set_detail("head_sha", head)

    if progress:
        progress.start("push", f"origin/{scenario.branch}")
    _run_git("push", "--force-with-lease", "-u", "origin", scenario.branch)
    if progress:
        progress.done("push", "push 완료 — GitHub에서 SecOps Gate 트리거됨")

    if progress:
        progress.start("pr", scenario.pr_title)
    pr_url = _gh_pr_upsert(
        branch=scenario.branch,
        title=scenario.pr_title,
        body=scenario.pr_body,
    )
    if progress:
        progress.done("pr", pr_url, pr_url=pr_url)
        progress.set_detail("pr_url", pr_url)

    return {
        "scenario": number,
        "branch": scenario.branch,
        "pr_url": pr_url,
        "repository": repository or os.getenv("GITHUB_REPOSITORY", ""),
        "started_at": stamp,
        "head_sha": head,
    }


def wait_for_gate(
    number: str,
    *,
    timeout_sec: int = 900,
    progress: PipelineProgress | None = None,
) -> dict[str, Any]:
    """Wait until SecOps Gate completes on the scenario PR branch."""
    scenario = get_scenario(number)
    if not scenario.branch:
        raise ValueError(f"Scenario {number} has no branch")

    _require_gh()
    deadline = time.time() + timeout_sec
    conclusion = ""
    run_id = ""
    run_url = ""
    head_sha = ""

    if progress:
        progress.start("ci", f"PR Checks · {scenario.branch}")

    poll = 0
    while time.time() < deadline:
        poll += 1
        checks = subprocess.run(
            [
                "gh",
                "pr",
                "checks",
                scenario.branch,
                "--json",
                "name,state,link,workflow",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if checks.returncode == 0 and checks.stdout.strip():
            rows = json.loads(checks.stdout)
            gate = next((r for r in rows if "devsecops" in r.get("name", "").lower()), None)
            if gate:
                state = gate.get("state", "PENDING")
                if progress:
                    progress.start("ci", f"devsecops-gate: {state} (poll #{poll})")
                if state in {"SUCCESS", "FAILURE", "CANCELLED", "SKIPPED"}:
                    conclusion = state.lower()
                    run_url = gate.get("link", "")
                    break
        elif progress:
            progress.start("ci", f"Checks 대기 중… (poll #{poll})")
        time.sleep(15)

    if not conclusion:
        if progress:
            progress.fail("ci", f"SecOps Gate timeout ({timeout_sec}s)")
        raise TimeoutError(f"SecOps Gate did not finish within {timeout_sec}s for {scenario.branch}")

    runs = subprocess.run(
        [
            "gh",
            "run",
            "list",
            "--workflow",
            GATE_WORKFLOW,
            "--branch",
            scenario.branch,
            "--limit",
            "1",
            "--json",
            "databaseId,url,conclusion,headSha",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    run_rows = json.loads(runs.stdout)
    if run_rows:
        run_id = str(run_rows[0].get("databaseId", ""))
        run_url = run_rows[0].get("url", run_url)
        head_sha = run_rows[0].get("headSha", "")

    if progress:
        progress.done("ci", conclusion.upper(), run_url=run_url, run_id=run_id)
        progress.set_detail("run_url", run_url)
        progress.set_detail("conclusion", conclusion)

    return {
        "scenario": number,
        "branch": scenario.branch,
        "conclusion": conclusion,
        "run_id": run_id,
        "run_url": run_url,
        "head_sha": head_sha,
    }


def fetch_dashboard(run_id: str, output_dir: Path) -> Path:
    """Download devsecops-reports artifact and return dashboard path."""
    _require_gh()
    output_dir.mkdir(parents=True, exist_ok=True)
    for child in output_dir.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()

    subprocess.run(
        ["gh", "run", "download", run_id, "-n", "devsecops-reports", "-D", str(output_dir)],
        cwd=ROOT,
        check=True,
    )
    dashboard = output_dir / "reports" / "SECOPS_DASHBOARD.html"
    if not dashboard.is_file():
        dashboard = output_dir / "SECOPS_DASHBOARD.html"
    if not dashboard.is_file():
        raise FileNotFoundError(f"Dashboard not found in artifact for run {run_id}")
    return dashboard


def publish_live(
    number: str,
    dashboard_path: Path,
    *,
    pr_url: str = "",
    run_url: str = "",
    conclusion: str = "",
    head_sha: str = "",
) -> Path:
    """Copy dashboard to docs/demo/live and update status.json."""
    scenario = get_scenario(number)
    DEMO_LIVE_DIR.mkdir(parents=True, exist_ok=True)
    target = DEMO_LIVE_DIR / f"scenario-{number}.html"
    html_text = dashboard_path.read_text(encoding="utf-8")
    html_text = _inject_provenance(
        html_text,
        scenario=number,
        title=scenario.title,
        pr_url=pr_url,
        run_url=run_url,
        head_sha=head_sha,
        conclusion=conclusion,
    )
    target.write_text(html_text, encoding="utf-8")

    status = _load_status()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    entry = {
        "scenario": number,
        "title": scenario.title,
        "kind": scenario.kind,
        "branch": scenario.branch,
        "conclusion": conclusion,
        "pr_url": pr_url,
        "run_url": run_url,
        "head_sha": head_sha,
        "dashboard_path": f"live/scenario-{number}.html",
        "updated_at": now,
    }
    status["active_scenario"] = number
    status["last_updated"] = now
    status["scenarios"][number] = entry
    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATUS_PATH.write_text(json.dumps(status, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return target


def run_local_gate(
    *,
    inject_fail: bool = False,
    progress: PipelineProgress | None = None,
) -> tuple[int, Path]:
    """Run ci_gate locally; optionally inject fail key first."""
    if inject_fail:
        if progress:
            progress.start("patch", "src/main.py에 AWS docs 예시 키 1줄 주입")
        changed = _apply_pr_fail()
        if progress:
            progress.done("patch", f"변경: {', '.join(changed)}", changed_files=changed)
            progress.set_detail("changed_files", changed)
    elif progress:
        progress.start("patch", "main 기준 — 앱 코드 변경 없음")
        progress.done("patch", "PASS 경로 (패치 없음)")

    if progress:
        progress.start("scan", "Trivy · Semgrep · Secrets · SCA · Checkov 실행 중…")
    result = subprocess.run(
        [PYTHON, str(ROOT / "scripts" / "ci_gate.py")],
        cwd=ROOT,
        env=ENV,
        capture_output=True,
        text=True,
        check=False,
    )
    code = result.returncode
    if progress:
        for line in (result.stdout or "").strip().splitlines()[-4:]:
            progress.log(line)
        progress.done("scan", f"exit code {code}")

    gate_info: dict[str, Any] = {}
    gate_path = ROOT / "reports" / "GATE_RESULT.json"
    if gate_path.is_file():
        gate_info = json.loads(gate_path.read_text(encoding="utf-8"))

    if progress:
        verdict = "PASSED" if code == 0 else "FAILED"
        progress.start("gate", "GATE_RESULT.json 읽는 중")
        progress.done(
            "gate",
            verdict,
            passed=gate_info.get("passed"),
            blockers=gate_info.get("risk_blockers", 0),
            reasons=(gate_info.get("reasons") or [])[:3],
            risk_score=gate_info.get("risk_score"),
        )
        progress.set_detail("conclusion", "success" if code == 0 else "failure")
        progress.set_detail("gate", gate_info)

    dashboard = ROOT / "reports" / "SECOPS_DASHBOARD.html"
    try:
        return code, dashboard
    finally:
        if inject_fail:
            restore_application_code()
            if progress:
                progress.log("src/main.py 데모 키 제거 (로컬 복원)")


def run_full_pr_pipeline(
    number: str,
    progress: PipelineProgress | None = None,
) -> dict[str, Any]:
    """Local/GitHub CLI: apply → push PR → wait gate → download → publish."""
    meta = orchestrate_pr(number, progress=progress)
    gate = wait_for_gate(number, progress=progress)
    if not gate.get("run_id"):
        raise RuntimeError("Could not resolve SecOps Gate run id")
    tmp = ROOT / "reports" / "_demo_fetch"
    if progress:
        progress.start("artifact", f"run {gate['run_id']}")
    dashboard = fetch_dashboard(gate["run_id"], tmp)
    if progress:
        progress.done("artifact", str(dashboard.name))
    if progress:
        progress.start("publish", "docs/demo/live/ 에 게시")
    publish_live(
        number,
        dashboard,
        pr_url=meta.get("pr_url", ""),
        run_url=gate.get("run_url", ""),
        conclusion=gate.get("conclusion", ""),
        head_sha=gate.get("head_sha", ""),
    )
    if progress:
        progress.done("publish", f"scenario-{number}.html")
    return {**meta, **gate, "dashboard": str(DEMO_LIVE_DIR / f"scenario-{number}.html")}


def _inject_provenance(
    html_text: str,
    *,
    scenario: str,
    title: str,
    pr_url: str,
    run_url: str,
    head_sha: str,
    conclusion: str,
) -> str:
    links: list[str] = []
    if pr_url:
        links.append(f'<a class="text-sky-400 hover:underline" href="{pr_url}">PR</a>')
    if run_url:
        links.append(f'<a class="text-sky-400 hover:underline" href="{run_url}">CI Run</a>')
    if head_sha:
        links.append(f'<span class="font-mono text-slate-400">{head_sha[:12]}</span>')
    link_html = " · ".join(links) if links else "로컬 실행"
    badge = conclusion.upper() if conclusion else "—"
    block = f"""
    <section class="rounded-xl border border-indigo-800/60 bg-indigo-950/30 px-4 py-3 text-sm text-indigo-100/90">
      <p><strong class="text-indigo-200">Live Demo</strong> · Scenario {scenario} — {title}</p>
      <p class="mt-1 text-xs text-indigo-200/80">Gate: {badge} · {link_html}</p>
    </section>
"""
    marker = "</header>"
    if marker in html_text:
        return html_text.replace(marker, block + "\n    " + marker, 1)
    return block + html_text


def _load_status() -> dict[str, Any]:
    if STATUS_PATH.is_file():
        return json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    return {
        "last_updated": "",
        "active_scenario": "",
        "scenarios": {},
    }


def _require_gh() -> None:
    from gh_auth import require_gh_auth

    require_gh_auth()


def _require_git_clean() -> None:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    dirty = [line for line in result.stdout.splitlines() if line.strip()]
    if dirty:
        files = ", ".join(line[3:] for line in dirty[:5])
        raise RuntimeError(f"Uncommitted changes block PR demo: {files}")


def _run_git(*args: str) -> None:
    subprocess.run(["git", *args], cwd=ROOT, check=True)


def _run_git_optional(*args: str) -> None:
    subprocess.run(["git", *args], cwd=ROOT, check=False)


def _gh_pr_upsert(*, branch: str, title: str, body: str) -> str:
    existing = subprocess.run(
        ["gh", "pr", "list", "--head", branch, "--json", "url", "--jq", ".[0].url"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    url = existing.stdout.strip()
    if url and url != "null":
        subprocess.run(
            ["gh", "pr", "edit", branch, "--title", title, "--body", body],
            cwd=ROOT,
            check=False,
        )
        return url

    subprocess.run(
        ["gh", "pr", "create", "--base", "main", "--head", branch, "--title", title, "--body", body],
        cwd=ROOT,
        check=True,
    )
    created = subprocess.run(
        ["gh", "pr", "view", branch, "--json", "url", "--jq", ".url"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return created.stdout.strip()


def _cmd_orchestrate(args: argparse.Namespace) -> int:
    meta = orchestrate_pr(args.scenario, repository=args.repository or "")
    print(json.dumps(meta, indent=2, ensure_ascii=False))
    return 0


def _cmd_wait_gate(args: argparse.Namespace) -> int:
    gate = wait_for_gate(args.scenario, timeout_sec=args.timeout)
    print(json.dumps(gate, indent=2, ensure_ascii=False))
    return 0


def _cmd_fetch_dashboard(args: argparse.Namespace) -> int:
    dashboard = fetch_dashboard(args.run_id, Path(args.output))
    print(str(dashboard))
    return 0


def _cmd_publish(args: argparse.Namespace) -> int:
    source = Path(args.source)
    dashboard = source / "reports" / "SECOPS_DASHBOARD.html"
    if not dashboard.is_file():
        dashboard = source / "SECOPS_DASHBOARD.html"
    target = publish_live(
        args.scenario,
        dashboard,
        pr_url=args.pr_url,
        run_url=args.run_url,
        conclusion=args.conclusion,
        head_sha=args.head_sha,
    )
    print(str(target))
    return 0


def _cmd_run_all(args: argparse.Namespace) -> int:
    result = run_full_pr_pipeline(args.scenario)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def _cmd_list(_args: argparse.Namespace) -> int:
    payload = [asdict(item) for item in SCENARIOS]
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def _cmd_apply(args: argparse.Namespace) -> int:
    apply_scenario(args.scenario)
    print("applied")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="K-SecOps demo scenario orchestration")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="List scenario definitions")
    p_list.set_defaults(func=_cmd_list)

    p_apply = sub.add_parser("apply", help="Apply scenario file patch only")
    p_apply.add_argument("--scenario", required=True)
    p_apply.set_defaults(func=_cmd_apply)

    p_orch = sub.add_parser("orchestrate", help="Apply, commit, push, open PR")
    p_orch.add_argument("--scenario", required=True)
    p_orch.add_argument("--repository", default="")
    p_orch.set_defaults(func=_cmd_orchestrate)

    p_wait = sub.add_parser("wait-gate", help="Wait for SecOps Gate on scenario branch")
    p_wait.add_argument("--scenario", required=True)
    p_wait.add_argument("--timeout", type=int, default=900)
    p_wait.set_defaults(func=_cmd_wait_gate)

    p_fetch = sub.add_parser("fetch-dashboard", help="Download gate artifact dashboard")
    p_fetch.add_argument("--run-id", required=True)
    p_fetch.add_argument("--output", required=True)
    p_fetch.set_defaults(func=_cmd_fetch_dashboard)

    p_pub = sub.add_parser("publish", help="Publish dashboard to docs/demo/live")
    p_pub.add_argument("--scenario", required=True)
    p_pub.add_argument("--source", required=True)
    p_pub.add_argument("--pr-url", default="")
    p_pub.add_argument("--run-url", default="")
    p_pub.add_argument("--conclusion", default="")
    p_pub.add_argument("--head-sha", default="")
    p_pub.set_defaults(func=_cmd_publish)

    p_all = sub.add_parser("run-all", help="Full PR pipeline (local gh CLI)")
    p_all.add_argument("--scenario", required=True, choices=sorted(PR_SCENARIOS))
    p_all.set_defaults(func=_cmd_run_all)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (RuntimeError, TimeoutError, ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
