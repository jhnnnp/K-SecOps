from pathlib import Path

from pydantic import BaseModel, Field

from tools.sandbox import PathSandboxError, resolve_sandbox_path


class ReadLogFileResult(BaseModel):
    content: str
    line_count: int
    truncated: bool
    path: str


def read_log_file(path: str, max_lines: int = 500) -> ReadLogFileResult:
    """
    Read a text file from sandboxed directories (dummy-infra/, reports/).

    Args:
        path: Relative path under an allowed root.
        max_lines: Maximum number of lines to return (default 500).
    """
    if max_lines < 1:
        raise ValueError("max_lines must be at least 1.")

    resolved = resolve_sandbox_path(path, strict=True)

    if not resolved.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    text = resolved.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    truncated = len(lines) > max_lines
    selected = lines[:max_lines]

    return ReadLogFileResult(
        content="\n".join(selected),
        line_count=len(selected),
        truncated=truncated,
        path=_relative_path(resolved),
    )


def _relative_path(resolved: Path) -> str:
    from tools.sandbox import PROJECT_ROOT

    return str(resolved.relative_to(PROJECT_ROOT))


__all__ = ["ReadLogFileResult", "read_log_file", "PathSandboxError"]
