"""GitHub CLI (gh) authentication helpers for demo hub."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
from typing import Any

LOGIN_LOCK = threading.Lock()
LOGIN_IN_PROGRESS = False
LOGIN_LAST_OUTPUT = ""


def check_gh_auth() -> dict[str, Any]:
    """Return GitHub CLI auth status for demo hub UI."""
    if shutil.which("gh") is None:
        return {
            "ok": False,
            "reason": "missing_cli",
            "message": "GitHub CLI(gh)가 설치되어 있지 않습니다.",
            "username": "",
            "hostname": "github.com",
            "scopes": [],
            "login_command": "brew install gh && gh auth login",
            "install_hint": "macOS: brew install gh · https://cli.github.com",
        }

    result = subprocess.run(
        ["gh", "auth", "status"],
        capture_output=True,
        text=True,
        check=False,
    )
    combined = (result.stdout or "") + (result.stderr or "")

    if result.returncode != 0:
        return {
            "ok": False,
            "reason": "not_logged_in",
            "message": "GitHub에 로그인되어 있지 않습니다. PR 시나리오(5·6)를 위해 로그인이 필요합니다.",
            "username": "",
            "hostname": "github.com",
            "scopes": [],
            "login_command": "gh auth login",
            "install_hint": "",
        }

    username = _parse_username(combined)
    hostname = _parse_hostname(combined) or "github.com"
    scopes = _parse_scopes(combined)

    missing = [s for s in ("repo",) if s not in scopes]
    if missing and scopes:
        return {
            "ok": False,
            "reason": "insufficient_scopes",
            "message": f"토큰 scope 부족: {', '.join(missing)} 필요 (현재: {', '.join(scopes)})",
            "username": username,
            "hostname": hostname,
            "scopes": scopes,
            "login_command": "gh auth refresh -s repo,read:org,gist",
            "install_hint": "",
        }

    return {
        "ok": True,
        "reason": "authenticated",
        "message": f"GitHub 로그인됨 (@{username})" if username else "GitHub 로그인됨",
        "username": username,
        "hostname": hostname,
        "scopes": scopes,
        "login_command": "",
        "install_hint": "",
    }


def require_gh_auth() -> None:
    """Raise RuntimeError with actionable message if gh is not ready for PR demos."""
    status = check_gh_auth()
    if status["ok"]:
        return
    reason = status.get("reason", "")
    if reason == "missing_cli":
        hint = status.get("install_hint", "https://cli.github.com")
        raise RuntimeError(f"{status['message']} 설치: {hint}")
    if reason == "insufficient_scopes":
        raise RuntimeError(f"{status['message']} 실행: {status.get('login_command')}")
    raise RuntimeError(
        f"{status['message']} Demo Hub 「GitHub 로그인」 버튼 또는 터미널 `{status.get('login_command')}`."
    )


def start_web_login() -> dict[str, Any]:
    """Start `gh auth login --web` in background; user completes in browser."""
    global LOGIN_IN_PROGRESS, LOGIN_LAST_OUTPUT

    if shutil.which("gh") is None:
        return {"started": False, "error": "gh CLI not installed"}

    current = check_gh_auth()
    if current["ok"]:
        return {"started": False, "already_authenticated": True, "status": current}

    with LOGIN_LOCK:
        if LOGIN_IN_PROGRESS:
            return {
                "started": True,
                "in_progress": True,
                "message": "로그인 진행 중… 브라우저에서 GitHub 인증을 완료하세요.",
            }
        LOGIN_IN_PROGRESS = True
        LOGIN_LAST_OUTPUT = ""

    def _run() -> None:
        global LOGIN_IN_PROGRESS, LOGIN_LAST_OUTPUT
        try:
            proc = subprocess.run(
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
                ],
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "GH_PROMPT_DISABLED": "1"},
            )
            LOGIN_LAST_OUTPUT = (proc.stdout or "") + (proc.stderr or "")
        finally:
            with LOGIN_LOCK:
                LOGIN_IN_PROGRESS = False

    threading.Thread(target=_run, daemon=True).start()
    return {
        "started": True,
        "in_progress": True,
        "message": "브라우저가 열리면 GitHub 로그인을 완료하세요. 완료 후 「상태 확인」을 누르세요.",
    }


def login_with_token(token: str) -> dict[str, Any]:
    """Non-interactive login via PAT (local demo hub only)."""
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
        err = (proc.stderr or proc.stdout or "login failed").strip()
        return {"ok": False, "error": err}

    return {"ok": True, "status": check_gh_auth()}


def login_status() -> dict[str, Any]:
    """Combined auth check + in-progress login flag."""
    status = check_gh_auth()
    with LOGIN_LOCK:
        in_progress = LOGIN_IN_PROGRESS
        last_output = LOGIN_LAST_OUTPUT[-500:] if LOGIN_LAST_OUTPUT else ""
    return {
        **status,
        "login_in_progress": in_progress,
        "login_output_tail": last_output,
    }


def _parse_username(text: str) -> str:
    match = re.search(r"account\s+(\S+)\s+\(", text)
    if match:
        return match.group(1)
    match = re.search(r"Logged in to .+ as (\S+)", text)
    return match.group(1) if match else ""


def _parse_hostname(text: str) -> str:
    match = re.search(r"Logged in to (\S+)", text)
    return match.group(1) if match else ""


def _parse_scopes(text: str) -> list[str]:
    match = re.search(r"Token scopes:\s*'([^']*)'", text)
    if not match:
        match = re.search(r"Token scopes:\s*(.+)", text)
    if not match:
        return []
    return [s.strip() for s in match.group(1).replace("'", "").split(",") if s.strip()]
