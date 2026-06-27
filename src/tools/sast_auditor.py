from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from re import Pattern

from tools.models import AuditSastResult, SastFinding
from tools.path_utils import relative_project_path, resolve_sandbox_target
from tools.sandbox import PROJECT_ROOT, is_repo_scan_mode

SAST_SUFFIXES = {".py", ".js", ".ts", ".jsx", ".tsx"}
REPO_IGNORE_DIRS = {".git", ".venv", "__pycache__", "node_modules", "tests", "reports", ".pytest_cache"}


@dataclass(frozen=True)
class SastRule:
    finding_type: str
    title: str
    pattern: Pattern[str]
    severity: str


SAST_RULES: tuple[SastRule, ...] = (
    SastRule(
        "sast.unsafe_eval",
        "Dynamic code execution (eval)",
        re.compile(r"\beval\s*\("),
        "CRITICAL",
    ),
    SastRule(
        "sast.shell_injection",
        "Subprocess with shell=True",
        re.compile(r"subprocess\.(?:run|call|Popen)\([^)]*shell\s*=\s*True"),
        "HIGH",
    ),
    SastRule(
        "sast.hardcoded_password",
        "Hardcoded password assignment",
        re.compile(r"(?i)(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]"),
        "HIGH",
    ),
    SastRule(
        "sast.sql_concat",
        "SQL string concatenation / f-string query",
        re.compile(r'(?i)(?:execute|query|cursor\.execute)\s*\(\s*f?["\']SELECT .*\{'),
        "HIGH",
    ),
)


def audit_sast(
    target_path: str = "src",
    *,
    repo_wide: bool | None = None,
) -> AuditSastResult:
    """Lightweight SAST: dangerous patterns in application source files."""
    use_repo_wide = repo_wide if repo_wide is not None else is_repo_scan_mode()
    strict = not use_repo_wide
    resolved = resolve_sandbox_target(target_path, strict=strict)
    relative_target = relative_project_path(resolved)

    findings: list[SastFinding] = []
    files_scanned = 0
    repo_wide_scan = use_repo_wide and resolved.resolve() == PROJECT_ROOT.resolve()

    for file_path in _iter_source_files(resolved, repo_wide=repo_wide_scan):
        files_scanned += 1
        findings.extend(_scan_file(file_path))

    return AuditSastResult(
        findings=_dedupe(findings),
        files_scanned=files_scanned,
        target_path=relative_target,
    )


def _iter_source_files(root: Path, *, repo_wide: bool = False):
    if root.is_file():
        if root.suffix.lower() in SAST_SUFFIXES:
            yield root
        return

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in SAST_SUFFIXES:
            continue
        if any(part in REPO_IGNORE_DIRS or part.startswith(".") for part in path.parts):
            continue
        if repo_wide and "dummy-infra" not in path.parts and "src" not in path.parts:
            continue
        yield path


def _scan_file(file_path: Path) -> list[SastFinding]:
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    resource = relative_project_path(file_path)
    findings: list[SastFinding] = []

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for rule in SAST_RULES:
            if not rule.pattern.search(line):
                continue
            findings.append(
                SastFinding(
                    id=f"SAST-{rule.finding_type.upper()}-{line_no}",
                    finding_type=rule.finding_type,
                    resource=resource,
                    line=line_no,
                    severity=rule.severity,
                    title=rule.title,
                    description=line.strip()[:120],
                )
            )
    return findings


def _dedupe(findings: list[SastFinding]) -> list[SastFinding]:
    seen: set[tuple[str, str, int]] = set()
    unique: list[SastFinding] = []
    for finding in findings:
        key = (finding.finding_type, finding.resource, finding.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
