from __future__ import annotations

from pathlib import Path

from tools.sandbox import PROJECT_ROOT, resolve_sandbox_path


def resolve_sandbox_target(user_path: str, *, strict: bool | None = None) -> Path:
    """Resolve a file or directory path for scanning or reading."""
    resolved = resolve_sandbox_path(user_path, strict=strict)
    if not resolved.exists():
        raise FileNotFoundError(f"Path not found: {user_path}")
    return resolved


def relative_project_path(resolved: Path) -> str:
    return str(resolved.relative_to(PROJECT_ROOT))
