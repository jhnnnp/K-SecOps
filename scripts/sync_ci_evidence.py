#!/usr/bin/env python3
"""Fetch GitHub PR check status and generate CI evidence markdown for README."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPO = "jhnnnp/K-SecOps"
PASS_PR = int(os.getenv("SECOPS_PASS_PR", "1"))
FAIL_PR = int(os.getenv("SECOPS_FAIL_PR", "2"))
OUTPUT_PATH = ROOT / "docs" / "CI_EVIDENCE_LATEST.md"
README_PATH = ROOT / "README.md"

MARKER_START = "<!-- CI_EVIDENCE_AUTO_START -->"
MARKER_END = "<!-- CI_EVIDENCE_AUTO_END -->"


@dataclass
class PrEvidence:
    number: int
    title: str
    url: str
    state: str
    check_name: str
    check_conclusion: str
    check_url: str
    gate_snippet: str


def main() -> int:
    repo = os.getenv("GITHUB_REPOSITORY", DEFAULT_REPO)
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")

    if not token:
        print("GITHUB_TOKEN or GH_TOKEN required for API access.", file=sys.stderr)
        print("Local: gh auth login  OR  export GH_TOKEN=...", file=sys.stderr)
        return 1

    try:
        pass_ev = _fetch_pr_evidence(repo, PASS_PR, token)
        fail_ev = _fetch_pr_evidence(repo, FAIL_PR, token)
    except urllib.error.HTTPError as exc:
        print(f"GitHub API error: {exc.code} {exc.reason}", file=sys.stderr)
        body = exc.read().decode("utf-8", errors="replace")
        print(body[:500], file=sys.stderr)
        return 1

    markdown = _render_evidence(repo, pass_ev, fail_ev)
    OUTPUT_PATH.write_text(markdown, encoding="utf-8")
    _patch_readme(markdown)

    print(f"Wrote {OUTPUT_PATH.relative_to(ROOT)}")
    print(f"Patched {README_PATH.relative_to(ROOT)} ({MARKER_START})")
    print(f"PR #{PASS_PR} check: {pass_ev.check_conclusion}")
    print(f"PR #{FAIL_PR} check: {fail_ev.check_conclusion}")
    return 0


def _api_get(url: str, token: str) -> dict:
    if shutil.which("gh"):
        api_path = url.replace("https://api.github.com/", "")
        result = subprocess.run(
            ["gh", "api", api_path],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)

    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def _fetch_pr_evidence(repo: str, pr_number: int, token: str) -> PrEvidence:
    base = f"https://api.github.com/repos/{repo}"
    pr = _api_get(f"{base}/pulls/{pr_number}", token)
    head_sha = pr["head"]["sha"]

    checks_payload = _api_get(f"{base}/commits/{head_sha}/check-runs?per_page=20", token)
    check_runs = checks_payload.get("check_runs", [])

    gate_run = _pick_gate_run(check_runs)
    gate_snippet = _fetch_gate_snippet(base, pr_number, token)

    return PrEvidence(
        number=pr_number,
        title=pr.get("title", ""),
        url=pr.get("html_url", ""),
        state=pr.get("state", ""),
        check_name=gate_run.get("name", "devsecops-gate") if gate_run else "devsecops-gate",
        check_conclusion=(gate_run or {}).get("conclusion", "unknown"),
        check_url=(gate_run or {}).get("html_url", ""),
        gate_snippet=gate_snippet,
    )


def _pick_gate_run(check_runs: list[dict]) -> dict | None:
    for run in check_runs:
        name = (run.get("name") or "").lower()
        if "secops" in name or "devsecops" in name or name == "devsecops-gate":
            return run
    return check_runs[0] if check_runs else None


def _fetch_gate_snippet(base: str, pr_number: int, token: str) -> str:
    comments = _api_get(f"{base}/issues/{pr_number}/comments?per_page=100", token)
    for comment in reversed(comments):
        body = comment.get("body") or ""
        if "devsecops-gate" in body or "DevSecOps CI Gate" in body:
            lines = [line for line in body.splitlines() if line.strip()][:12]
            return "\n".join(lines)
    return "_No gate comment found yet._"


def _render_evidence(repo: str, pass_ev: PrEvidence, fail_ev: PrEvidence) -> str:
    owner, name = repo.split("/", 1)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    workflow_badge = (
        f"https://img.shields.io/github/actions/workflow/status/"
        f"{owner}/{name}/secops-gate.yml?branch=main&label=SecOps%20Gate"
    )

    pass_icon = "PASS" if pass_ev.check_conclusion == "success" else pass_ev.check_conclusion.upper()
    fail_icon = "FAIL" if fail_ev.check_conclusion == "failure" else fail_ev.check_conclusion.upper()

    return f"""# CI Evidence (auto-synced)

_Last updated: {now}_

![SecOps Gate workflow]({workflow_badge})

## Demo PR status

| Demo | PR | Check | Expected | Actual |
|------|-----|-------|----------|--------|
| PASSED | [#{pass_ev.number}]({pass_ev.url}) | `{pass_ev.check_name}` | success | **{pass_icon}** |
| FAILED (intentional) | [#{fail_ev.number}]({fail_ev.url}) | `{fail_ev.check_name}` | failure | **{fail_icon}** |

- PASSED run: {pass_ev.check_url or "n/a"}
- FAILED run: {fail_ev.check_url or "n/a"}

## Gate comment snapshot (FAILED PR)

```text
{fail_ev.gate_snippet}
```

## Validation

- PR #{PASS_PR} should be **green** (baseline dummy-infra only).
- PR #{FAIL_PR} should be **red** (`src/main.py` intentional secret). Do not merge.

Regenerate locally:

```bash
export GH_TOKEN=$(gh auth token)   # after gh auth login
python3 scripts/sync_ci_evidence.py
```
"""


def _patch_readme(evidence_md: str) -> None:
    if not README_PATH.is_file():
        return

    content = README_PATH.read_text(encoding="utf-8")
    block = (
        f"{MARKER_START}\n"
        f"_Auto-generated by `scripts/sync_ci_evidence.py`. Do not edit manually._\n\n"
        f"{evidence_md.strip()}\n"
        f"{MARKER_END}"
    )

    pattern = re.compile(
        re.escape(MARKER_START) + r".*?" + re.escape(MARKER_END),
        re.DOTALL,
    )
    if pattern.search(content):
        content = pattern.sub(block, content)
    else:
        placeholder = "### CI Evidence (portfolio)"
        if placeholder in content:
            content = content.replace(
                placeholder,
                f"### CI Evidence (portfolio)\n\n{block}",
                1,
            )
        else:
            content = content + f"\n\n{block}\n"

    README_PATH.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
