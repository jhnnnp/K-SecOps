from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ALLOWED_ROOTS = (
    PROJECT_ROOT / "dummy-infra",
    PROJECT_ROOT / "reports",
)


class PathSandboxError(ValueError):
    """Raised when a path escapes the allowed sandbox roots."""


def is_repo_scan_mode() -> bool:
    """True when CI/scripts request repository-wide read access (not MCP agent mode)."""
    return os.getenv("SECOPS_REPO_SCAN", "0") == "1" or os.getenv("CI", "").lower() == "true"


def resolve_sandbox_path(user_path: str, *, strict: bool | None = None) -> Path:
    """
    Resolve user_path under the project.

    strict=True (default for MCP): only dummy-infra/ and reports/.
    strict=False or SECOPS_REPO_SCAN=1: any path under PROJECT_ROOT (still blocks .. traversal).
    """
    if strict is None:
        strict = not is_repo_scan_mode()

    if not user_path or not user_path.strip():
        raise PathSandboxError("Path must not be empty.")

    normalized = user_path.strip().replace("\\", "/")
    if normalized.startswith("/") or ".." in Path(normalized).parts:
        raise PathSandboxError(f"Path traversal is not allowed: {user_path!r}")

    candidate = (PROJECT_ROOT / normalized).resolve()
    project_root = PROJECT_ROOT.resolve()

    try:
        candidate.relative_to(project_root)
    except ValueError as exc:
        raise PathSandboxError(f"Access denied: {user_path!r} is outside the project root.") from exc

    if not strict:
        return candidate

    for root in ALLOWED_ROOTS:
        resolved_root = root.resolve()
        try:
            candidate.relative_to(resolved_root)
            return candidate
        except ValueError:
            continue

    allowed = ", ".join(str(r.relative_to(PROJECT_ROOT)) for r in ALLOWED_ROOTS)
    raise PathSandboxError(
        f"Access denied: {user_path!r}. Allowed roots: {allowed}"
    )
