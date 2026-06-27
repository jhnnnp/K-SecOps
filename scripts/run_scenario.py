#!/usr/bin/env python3
"""Interactive scenario runner: local scans, GitHub PR demos, Actions dispatch."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

sys.path.insert(0, str(ROOT / "scripts"))
from demo_scenarios import (  # noqa: E402
    SCENARIOS,
    get_scenario,
    run_full_pr_pipeline,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="K-SecOps numbered scenario runner")
    parser.add_argument(
        "scenario",
        nargs="?",
        help="시나리오 번호 (1-9). 생략 시 메뉴 표시",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="PR/Actions 시나리오에서 실행할 명령만 출력",
    )
    args = parser.parse_args()

    if args.scenario is None:
        _print_menu()
        choice = input("\n번호 입력 (1-9, q=종료): ").strip().lower()
        if choice in {"q", "quit", "exit"}:
            return 0
        args.scenario = choice

    handlers = {
        "1": _run_local_demo,
        "2": _run_local_gate,
        "3": _run_local_fail_sim,
        "4": _run_local_all,
        "5": lambda dry: _run_pr_pass(dry_run=dry),
        "6": lambda dry: _run_pr_fail(dry_run=dry),
        "7": lambda dry: _run_sync_evidence(dry_run=dry),
        "8": lambda dry: _run_actions_gate(dry_run=dry),
        "9": lambda dry: _run_actions_sync(dry_run=dry),
    }

    handler = handlers.get(args.scenario)
    if handler is None:
        print(f"알 수 없는 번호: {args.scenario}")
        _print_menu()
        return 1

    print(f"\n== Scenario {args.scenario} ==", flush=True)
    scenario = get_scenario(args.scenario)
    print(scenario.title, flush=True)
    print(scenario.description, flush=True)
    print(flush=True)

    try:
        return handler(args.dry_run)
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        return 1


def _print_menu() -> None:
    print("K-SecOps Scenario Runner")
    print("=" * 50)
    print("\n[ LOCAL — 내 컴퓨터, GitHub 반응 없음 ]")
    for item in SCENARIOS[:4]:
        print(f"  {item.number}. {item.title}")
        print(f"     {item.description}")
    print("\n[ PR — push 후 GitHub Checks / 코멘트 ]")
    for item in SCENARIOS[4:7]:
        print(f"  {item.number}. {item.title}")
        print(f"     {item.description}")
    print("\n[ ACTIONS — GitHub 서버에서 workflow 실행 ]")
    for item in SCENARIOS[7:]:
        print(f"  {item.number}. {item.title}")
        print(f"     {item.description}")
    print("\n예: python3 scripts/run_scenario.py 2")
    print("    python3 scripts/demo_hub.py   # 웹 UI")
    print("    python3 scripts/run_scenario.py 6 --dry-run")


def _run_local_demo(_dry_run: bool = False) -> int:
    return _run_script("scripts/run_demo.py")


def _run_local_gate(_dry_run: bool = False) -> int:
    code = _run_script("scripts/ci_gate.py")
    _print_local_outputs(
        [
            ROOT / "reports" / "CI_SUMMARY.md",
            ROOT / "reports" / "CI_AUDIT_REPORT.md",
            ROOT / "reports" / "GATE_RESULT.json",
            ROOT / "reports" / "SECOPS_DASHBOARD.html",
        ],
    )
    return code


def _run_local_fail_sim(_dry_run: bool = False) -> int:
    return _run_script("scripts/demo_intentional_fail.py")


def _run_local_all(_dry_run: bool = False) -> int:
    for fn in (_run_local_demo, _run_local_gate, _run_local_fail_sim):
        code = fn()
        if code != 0:
            return code
        print()
    return 0


def _run_pr_pass(*, dry_run: bool) -> int:
    return _run_pr_demo("5", dry_run=dry_run)


def _run_pr_fail(*, dry_run: bool) -> int:
    return _run_pr_demo("6", dry_run=dry_run)


def _run_pr_demo(number: str, *, dry_run: bool) -> int:
    scenario = get_scenario(number)
    commands = [
        ["python3", "scripts/demo_scenarios.py", "run-all", "--scenario", number],
    ]
    if dry_run:
        print(f"[dry-run] branch={scenario.branch}")
        _print_commands(commands)
        return 0

    _require_gh()
    result = run_full_pr_pipeline(number)
    print(f"\nPR: {result.get('pr_url', '')}")
    print(f"Gate: {result.get('conclusion', '')}")
    print(f"Dashboard: {result.get('dashboard', '')}")
    print("웹 UI: python3 scripts/demo_hub.py → http://127.0.0.1:8765")
    return 0 if result.get("conclusion") == "success" else 1


def _run_sync_evidence(*, dry_run: bool) -> int:
    _require_gh(dry_run)
    if dry_run:
        print("[dry-run] python3 scripts/sync_ci_evidence.py")
        return 0
    token = _gh_token()
    env = {**ENV, "GH_TOKEN": token}
    return subprocess.run(
        [PYTHON, str(ROOT / "scripts" / "sync_ci_evidence.py")],
        cwd=ROOT,
        env=env,
        check=False,
    ).returncode


def _run_actions_gate(*, dry_run: bool) -> int:
    _require_gh(dry_run)
    cmd = ["gh", "workflow", "run", "SecOps Gate", "--ref", "main"]
    if dry_run:
        _print_commands([cmd])
        return 0
    subprocess.run(cmd, cwd=ROOT, check=True)
    print("GitHub → Actions → SecOps Gate 에서 실행 상태 확인")
    return 0


def _run_actions_sync(*, dry_run: bool) -> int:
    _require_gh(dry_run)
    cmd = ["gh", "workflow", "run", "Sync CI Evidence", "--ref", "main"]
    if dry_run:
        _print_commands([cmd])
        return 0
    subprocess.run(cmd, cwd=ROOT, check=True)
    print("GitHub → Actions → Sync CI Evidence 에서 실행 상태 확인")
    return 0


def _run_script(relative: str) -> int:
    path = ROOT / relative
    result = subprocess.run([PYTHON, str(path)], cwd=ROOT, env=ENV, check=False)
    return result.returncode


def _print_local_outputs(paths: list[Path]) -> None:
    print("\n로컬 결과 파일 (GitHub에는 자동 업로드 안 됨):")
    for path in paths:
        if path.exists():
            print(f"  - {path.relative_to(ROOT)}")
        else:
            print(f"  - {path.relative_to(ROOT)} (not created)")


def _require_gh(dry_run: bool = False) -> None:
    if dry_run:
        return
    if shutil.which("gh") is None:
        raise RuntimeError("gh CLI 없음. 설치 후 `gh auth login` 실행")
    result = subprocess.run(
        ["gh", "auth", "status"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("`gh auth login` 필요 — PR/Actions 시나리오는 GitHub 인증 후 실행")


def _gh_token() -> str:
    result = subprocess.run(
        ["gh", "auth", "token"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _print_commands(commands: list[list[str]]) -> None:
    for cmd in commands:
        print("  $", " ".join(cmd))


if __name__ == "__main__":
    raise SystemExit(main())
