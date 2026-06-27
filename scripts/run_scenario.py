#!/usr/bin/env python3
"""Interactive scenario runner: local scans, GitHub PR demos, Actions dispatch."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

# AWS documentation example key — built at runtime so repo-wide scan does not flag this file.
_DEMO_FAIL_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
_DEMO_FAIL_LINE = f'_DEMO_CI_FAIL_KEY = "{_DEMO_FAIL_KEY}"  # demo-only: remove after CI evidence\n'
_DEMO_FAIL_MARKER = "demo-only: remove after CI evidence"


@dataclass(frozen=True)
class Scenario:
    number: str
    title: str
    description: str


SCENARIOS: list[Scenario] = [
    Scenario("1", "Local — demo report", "dummy-infra 스캔 → reports/SAMPLE_AUDIT_REPORT.md"),
    Scenario("2", "Local — CI gate", "repo 전체 gate (ci_gate.py) → PASSED/FAILED"),
    Scenario("3", "Local — FAIL simulation", "src/ 시크릿 있을 때 gate 차단 로직 확인"),
    Scenario("4", "Local — all", "1 → 2 → 3 순서 실행"),
    Scenario("5", "PR — PASS demo", "브랜치 push + PR 생성 (SecOps Gate 초록 예상)"),
    Scenario("6", "PR — FAIL demo", "src/에 예시 키 추가 + PR (merge 차단 예상)"),
    Scenario("7", "PR — sync evidence", "GitHub API로 README CI 증거 동기화"),
    Scenario("8", "Actions — SecOps Gate", "workflow_dispatch로 원격 gate 실행"),
    Scenario("9", "Actions — Sync CI Evidence", "workflow_dispatch로 증거 동기화"),
]


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
    for item in SCENARIOS:
        if item.number == args.scenario:
            print(item.title, flush=True)
            print(item.description, flush=True)
            break
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
    _require_gh(dry_run)
    branch = "demo/ci-pass"
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    readme = ROOT / "dummy-infra" / "README.md"

    commands = [
        ["git", "checkout", "main"],
        ["git", "pull", "--ff-only", "origin", "main"],
        ["git", "checkout", "-B", branch],
        ["git", "commit"],
        ["git", "push", "-u", "origin", branch],
        ["gh", "pr", "create"],
    ]
    if dry_run:
        print("[dry-run] would update dummy-infra/README.md with ci-pass-demo comment")
        _print_commands(commands)
        return 0

    _ensure_clean_enough_for_pr()
    _run_git("checkout", "main")
    _run_git_optional("pull", "--ff-only", "origin", "main")
    _run_git("checkout", "-B", branch)

    original = readme.read_text(encoding="utf-8")
    if f"<!-- ci-pass-demo:" not in original:
        readme.write_text(original.rstrip() + f"\n\n<!-- ci-pass-demo: {stamp} -->\n", encoding="utf-8")

    _run_git("add", "dummy-infra/README.md")
    _run_git("commit", "-m", f"docs: ci pass demo ({stamp})")
    _run_git("push", "--force-with-lease", "-u", "origin", branch)

    pr_url = _gh_pr_create(
        branch=branch,
        title="demo: CI gate PASS",
        body="SecOps Gate PASS demo. Safe docs-only change.",
    )
    print(f"\nPR opened: {pr_url}")
    print("GitHub → PR → Checks 탭에서 SecOps Gate 초록 확인")
    return 0


def _run_pr_fail(*, dry_run: bool) -> int:
    _require_gh(dry_run)
    branch = "demo/ci-fail-secret"
    main_py = ROOT / "src" / "main.py"

    commands = [
        ["git", "checkout", "main"],
        ["git", "checkout", "-B", branch],
        ["git", "commit"],
        ["git", "push", "-u", "origin", branch],
        ["gh", "pr", "create"],
    ]
    if dry_run:
        print("[dry-run] would prepend demo fail key line to src/main.py")
        _print_commands(commands)
        return 0

    _ensure_clean_enough_for_pr()
    _run_git("checkout", "main")
    _run_git_optional("pull", "--ff-only", "origin", "main")
    _run_git("checkout", "-B", branch)

    original = main_py.read_text(encoding="utf-8")
    if _DEMO_FAIL_MARKER not in original:
        main_py.write_text(_DEMO_FAIL_LINE + original, encoding="utf-8")

    _run_git("add", "src/main.py")
    _run_git("commit", "-m", "demo: intentional secret fail for CI evidence")
    _run_git("push", "--force-with-lease", "-u", "origin", branch)

    pr_url = _gh_pr_create(
        branch=branch,
        title="demo: CI gate FAIL (intentional secret)",
        body=(
            "Intentional AWS docs example key in src/main.py for SecOps Gate FAIL demo. "
            "Do not merge."
        ),
    )
    print(f"\nPR opened: {pr_url}")
    print("GitHub → PR → Checks 탭에서 SecOps Gate 빨강 확인")
    print("데모 후: main에서 src/main.py 데모 줄 제거, PR close")
    return 0


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


def _require_gh(dry_run: bool) -> None:
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


def _ensure_clean_enough_for_pr() -> None:
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
        raise RuntimeError(
            "커밋되지 않은 변경이 있습니다. PR 시나리오 전에 commit 또는 stash 하세요: "
            + files
        )


def _run_git(*args: str) -> None:
    subprocess.run(["git", *args], cwd=ROOT, check=True)


def _run_git_optional(*args: str) -> None:
    subprocess.run(["git", *args], cwd=ROOT, check=False)


def _gh_pr_create(*, branch: str, title: str, body: str) -> str:
    existing = subprocess.run(
        ["gh", "pr", "list", "--head", branch, "--json", "url", "--jq", ".[0].url"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    url = existing.stdout.strip()
    if url and url != "null":
        print(f"기존 PR 재사용: {url}")
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


def _print_commands(commands: list[list[str]]) -> None:
    for cmd in commands:
        print("  $", " ".join(cmd))


if __name__ == "__main__":
    raise SystemExit(main())
