"""GitHub CLI (gh) authentication helpers for demo hub."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

LOGIN_LOCK = threading.Lock()
LOGIN_IN_PROGRESS = False
LOGIN_LAST_OUTPUT = ""
LOGIN_STARTED_AT = 0.0
LOGIN_TIMEOUT_SEC = 120
REQUIRED_SCOPES = ("repo",)
OPTIONAL_SCOPES = ("read:org", "gist")
FIX_SCOPE_CMD = "gh auth refresh -h github.com -s repo,read:org,gist"
FIX_LOGIN_CMD = "gh auth login -h github.com -s repo,read:org,gist"
NOTE_BROWSER_VS_CLI = (
    "GitHub 웹사이트(github.com) 로그인과 gh CLI 인증은 별개입니다. "
    "PR push에는 gh CLI 로그인(repo scope)이 필요합니다."
)


def check_gh_auth() -> dict[str, Any]:
    """Return GitHub CLI auth status for demo hub UI."""
    if shutil.which("gh") is None:
        return _fail(
            reason="missing_cli",
            message="GitHub CLI(gh)가 설치되어 있지 않습니다.",
            login_command="brew install gh && gh auth login -s repo,read:org,gist",
            install_hint="macOS: brew install gh · https://cli.github.com",
        )

    result = subprocess.run(
        ["gh", "auth", "status"],
        capture_output=True,
        text=True,
        check=False,
    )
    combined = (result.stdout or "") + (result.stderr or "")
    username = _parse_username(combined) or _parse_failed_username(combined)

    if result.returncode != 0:
        if _is_invalid_token(combined):
            return _fail(
                reason="invalid_token",
                message=f"gh CLI 토큰이 만료되었거나 무효합니다{f' (@{username})' if username else ''}.",
                username=username,
                login_command=FIX_LOGIN_CMD,
                raw_tail=_tail(combined),
            )
        return _fail(
            reason="not_logged_in",
            message="gh CLI에 GitHub가 연결되어 있지 않습니다.",
            username=username,
            login_command=FIX_LOGIN_CMD,
            raw_tail=_tail(combined),
        )

    verify = subprocess.run(
        ["gh", "api", "user", "--jq", ".login"],
        capture_output=True,
        text=True,
        check=False,
    )
    if verify.returncode != 0:
        return _fail(
            reason="invalid_token",
            message=f"gh 토큰 검증 실패{f' (@{username})' if username else ''}. 재로그인이 필요합니다.",
            username=username,
            login_command=FIX_LOGIN_CMD,
            raw_tail=_tail(verify.stderr or verify.stdout),
        )

    api_user = verify.stdout.strip()
    scopes = _parse_scopes(combined)

    if _has_repo_access():
        return {
            "ok": True,
            "reason": "authenticated",
            "message": f"gh CLI 연결됨 (@{api_user or username}) · repo push 가능",
            "username": api_user or username,
            "hostname": _parse_hostname(combined) or "github.com",
            "scopes": scopes,
            "login_command": "",
            "install_hint": "",
            "note": "",
            "missing_scopes": [],
        }

    missing = [s for s in REQUIRED_SCOPES if s not in scopes]

    if missing or not scopes:
        return _fail(
            reason="insufficient_scopes",
            message=(
                f"로그인은 됐지만 repo 권한 없음 (현재 scope: {', '.join(scopes) or 'unknown'}). "
                "PR push에 repo scope 필요."
            ),
            username=api_user or username,
            scopes=scopes,
            login_command=FIX_SCOPE_CMD,
            missing_scopes=missing or ["repo"],
            fix_hint="터미널: gh auth login 할 때 -s repo,read:org,gist 옵션 필수",
        )

    return {
        "ok": True,
        "reason": "authenticated",
        "message": f"gh CLI 연결됨 (@{api_user or username})",
        "username": api_user or username,
        "hostname": _parse_hostname(combined) or "github.com",
        "scopes": scopes,
        "login_command": "",
        "install_hint": "",
        "note": "",
        "missing_scopes": [],
    }


def check_git_status() -> dict[str, Any]:
    """Working tree status for PR demo preflight."""
    branch = _current_branch()
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    dirty = [line[3:] for line in result.stdout.splitlines() if line.strip()]
    return {
        "ok": len(dirty) == 0,
        "branch": branch,
        "dirty_count": len(dirty),
        "dirty_files": dirty[:12],
        "message": "작업 트리 clean — PR 시나리오 실행 가능"
        if not dirty
        else f"커밋되지 않은 변경 {len(dirty)}개 — PR 전 commit 또는 stash 필요",
    }


def require_gh_auth() -> None:
    status = check_gh_auth()
    if status["ok"]:
        return
    extra = f" ({NOTE_BROWSER_VS_CLI})"
    reason = status.get("reason", "")
    if reason == "missing_cli":
        raise RuntimeError(f"{status['message']} {status.get('install_hint', '')}")
    if reason in {"insufficient_scopes", "invalid_token"}:
        raise RuntimeError(f"{status['message']} 실행: `{status.get('login_command')}`{extra}")
    raise RuntimeError(f"{status['message']} `{status.get('login_command')}`{extra}")


def start_web_login() -> dict[str, Any]:
    global LOGIN_IN_PROGRESS, LOGIN_LAST_OUTPUT

    if shutil.which("gh") is None:
        return {"started": False, "error": "gh CLI not installed"}

    current = check_gh_auth()
    if current["ok"]:
        return {"started": False, "already_authenticated": True, "status": current}

    return _start_auth_command(
        [
            "gh",
            "auth",
            "login",
            "--web",
            "--git-protocol",
            "https",
            "--skip-ssh-key",
            "-h",
            "github.com",
            "-s",
            "repo,read:org,gist",
        ],
        message="브라우저에서 GitHub 로그인을 완료하세요 (repo scope 포함).",
    )


def refresh_scopes() -> dict[str, Any]:
    """Refresh gh token scopes via browser if needed."""
    if shutil.which("gh") is None:
        return {"started": False, "error": "gh CLI not installed"}

    return _start_auth_command(
        [
            "gh",
            "auth",
            "refresh",
            "-h",
            "github.com",
            "-s",
            "repo,read:org,gist",
        ],
        message="브라우저에서 scope 갱신(repo)을 승인하세요.",
    )


def login_with_token(token: str) -> dict[str, Any]:
    token = token.strip()
    if not token:
        return {"ok": False, "error": "token is empty"}
    if shutil.which("gh") is None:
        return {"ok": False, "error": "gh CLI not installed"}

    proc = subprocess.run(
        ["gh", "auth", "login", "--with-token"],
        input=token + "\n",
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or proc.stdout or "login failed").strip()}

    status = check_gh_auth()
    if not status["ok"]:
        return {"ok": False, "error": status.get("message", "token logged in but scopes insufficient")}
    return {"ok": True, "status": status}


def logout_gh() -> dict[str, Any]:
    if shutil.which("gh") is None:
        return {"ok": False, "error": "gh CLI not installed"}
    subprocess.run(["gh", "auth", "logout", "-h", "github.com"], cwd=ROOT, check=False)
    return {"ok": True, "status": check_gh_auth()}


def cancel_auth_flow() -> dict[str, Any]:
    """Clear stuck in-progress flag (e.g. after terminal login or timed-out browser flow)."""
    global LOGIN_IN_PROGRESS, LOGIN_LAST_OUTPUT, LOGIN_STARTED_AT
    with LOGIN_LOCK:
        LOGIN_IN_PROGRESS = False
        LOGIN_STARTED_AT = 0.0
    return {"ok": True, "status": login_status()}


def login_status() -> dict[str, Any]:
    global LOGIN_IN_PROGRESS, LOGIN_STARTED_AT
    _maybe_clear_stale_login()
    gh = check_gh_auth()
    git = check_git_status()
    with LOGIN_LOCK:
        in_progress = LOGIN_IN_PROGRESS
        last_output = LOGIN_LAST_OUTPUT[-800:] if LOGIN_LAST_OUTPUT else ""
        started_at = LOGIN_STARTED_AT

    if gh.get("ok"):
        with LOGIN_LOCK:
            LOGIN_IN_PROGRESS = False
            LOGIN_STARTED_AT = 0.0
        in_progress = False

    return {
        **gh,
        "git": git,
        "login_in_progress": in_progress,
        "login_started_at": started_at,
        "login_output_tail": last_output,
        "note": gh.get("note") or NOTE_BROWSER_VS_CLI,
    }


def _maybe_clear_stale_login() -> None:
    global LOGIN_IN_PROGRESS, LOGIN_STARTED_AT
    with LOGIN_LOCK:
        if not LOGIN_IN_PROGRESS:
            return
        if LOGIN_STARTED_AT and (time.time() - LOGIN_STARTED_AT) > LOGIN_TIMEOUT_SEC:
            LOGIN_IN_PROGRESS = False
            LOGIN_STARTED_AT = 0.0


def _start_auth_command(cmd: list[str], *, message: str) -> dict[str, Any]:
    global LOGIN_IN_PROGRESS, LOGIN_LAST_OUTPUT, LOGIN_STARTED_AT

    with LOGIN_LOCK:
        if LOGIN_IN_PROGRESS:
            elapsed = int(time.time() - LOGIN_STARTED_AT) if LOGIN_STARTED_AT else 0
            return {
                "started": False,
                "in_progress": True,
                "message": f"인증 진행 중 ({elapsed}s)… 완료 후 「상태 확인」 또는 「인증 초기화」",
            }
        LOGIN_IN_PROGRESS = True
        LOGIN_LAST_OUTPUT = ""
        LOGIN_STARTED_AT = time.time()

    def _run() -> None:
        global LOGIN_IN_PROGRESS, LOGIN_LAST_OUTPUT, LOGIN_STARTED_AT
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                cwd=ROOT,
                timeout=LOGIN_TIMEOUT_SEC,
                env={**os.environ, "GH_PROMPT_DISABLED": "1"},
            )
            LOGIN_LAST_OUTPUT = (proc.stdout or "") + (proc.stderr or "")
        except subprocess.TimeoutExpired:
            LOGIN_LAST_OUTPUT = f"Timeout ({LOGIN_TIMEOUT_SEC}s). 터미널에서 직접 실행하세요: {' '.join(cmd)}"
        finally:
            with LOGIN_LOCK:
                LOGIN_IN_PROGRESS = False
                LOGIN_STARTED_AT = 0.0

    threading.Thread(target=_run, daemon=True).start()
    return {"started": True, "in_progress": True, "message": message}


def _fail(**kwargs: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "ok": False,
        "username": "",
        "hostname": "github.com",
        "scopes": kwargs.pop("scopes", []),
        "install_hint": kwargs.pop("install_hint", ""),
        "note": NOTE_BROWSER_VS_CLI,
        "missing_scopes": kwargs.pop("missing_scopes", []),
        "raw_tail": kwargs.pop("raw_tail", ""),
    }
    base.update(kwargs)
    if "login_command" not in base:
        base["login_command"] = "gh auth login -s repo,read:org,gist"
    return base


def _is_invalid_token(text: str) -> bool:
    lowered = text.lower()
    return "invalid" in lowered or "failed to log in" in lowered or "re-authenticate" in lowered


def _parse_username(text: str) -> str:
    match = re.search(r"Logged in to .+ as (\S+)", text)
    return match.group(1) if match else ""


def _parse_failed_username(text: str) -> str:
    match = re.search(r"account (\S+)", text)
    return match.group(1) if match else ""


def _parse_hostname(text: str) -> str:
    match = re.search(r"Logged in to (\S+)", text)
    return match.group(1) if match else ""


def _has_repo_access() -> bool:
    """True if gh can read the current repository (repo scope effective)."""
    proc = subprocess.run(
        ["gh", "repo", "view", "--json", "nameWithOwner"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def _parse_scopes(text: str) -> list[str]:
    match = re.search(r"Token scopes:\s*'([^']*)'", text)
    if not match:
        match = re.search(r"Token scopes:\s*(.+)", text)
    if not match:
        return []
    return [s.strip() for s in match.group(1).replace("'", "").split(",") if s.strip()]


def _current_branch() -> str:
    result = subprocess.run(
        ["git", "branch", "--show-current"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() or "unknown"


def _tail(text: str, limit: int = 200) -> str:
    compact = " ".join(text.split())
    return compact[:limit]
