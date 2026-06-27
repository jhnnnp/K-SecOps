from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from re import Pattern

from tools.models import AuditSastResult, SastFinding, ScannerError
from tools.path_utils import relative_project_path, resolve_sandbox_target
from tools.sandbox import PROJECT_ROOT, is_repo_scan_mode
from tools.sast_semgrep import run_semgrep_scan

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
    SastRule(
        "sast.os_system",
        "OS command via os.system",
        re.compile(r"\bos\.system\s*\("),
        "CRITICAL",
    ),
    SastRule(
        "sast.unsafe_pickle",
        "Unsafe deserialization (pickle.loads)",
        re.compile(r"\bpickle\.loads\s*\("),
        "CRITICAL",
    ),
    SastRule(
        "sast.unsafe_exec",
        "Dynamic code execution (exec)",
        re.compile(r"\bexec\s*\("),
        "CRITICAL",
    ),
)


def audit_sast(
    target_path: str = "src",
    *,
    repo_wide: bool | None = None,
    engine: str | None = None,
) -> AuditSastResult:
    """
    SAST for application source files.

    Engines (SECOPS_SAST_ENGINE):
    - auto: Semgrep if installed, else regex fallback
    - semgrep: Semgrep OWASP auto rules (--config auto)
    - regex: lightweight pattern scan (local PoC / offline)
    - both: merge Semgrep + regex findings
    """
    use_repo_wide = repo_wide if repo_wide is not None else is_repo_scan_mode()
    strict = not use_repo_wide
    resolved = resolve_sandbox_target(target_path, strict=strict)
    relative_target = relative_project_path(resolved)
    selected_engine = (engine or os.getenv("SECOPS_SAST_ENGINE", "auto")).lower()
    scan_roots = _resolve_scan_roots(resolved, repo_wide=use_repo_wide)

    findings: list[SastFinding] = []
    errors: list[ScannerError] = []
    files_scanned = 0
    engines_used: list[str] = []

    if selected_engine in {"auto", "semgrep", "both"}:
        semgrep_findings, semgrep_errors, semgrep_files = _audit_with_semgrep(scan_roots)
        if semgrep_findings or not semgrep_errors:
            engines_used.append("semgrep")
            findings.extend(semgrep_findings)
            files_scanned = max(files_scanned, semgrep_files)
        errors.extend(semgrep_errors)
        if selected_engine == "semgrep" and semgrep_errors:
            return AuditSastResult(
                findings=[],
                files_scanned=0,
                target_path=relative_target,
                engine="semgrep",
                errors=errors,
            )
        semgrep_unavailable = bool(semgrep_errors) and selected_engine == "auto"

    else:
        semgrep_unavailable = False

    use_regex = selected_engine in {"regex", "both"} or (
        selected_engine == "auto" and (semgrep_unavailable or not engines_used)
    )
    if use_regex:
        regex_findings, regex_files = _audit_with_regex(scan_roots)
        engines_used.append("regex")
        findings.extend(regex_findings)
        files_scanned = max(files_scanned, regex_files)

    engine_label = "+".join(engines_used) if engines_used else selected_engine
    return AuditSastResult(
        findings=_dedupe(findings),
        files_scanned=files_scanned,
        target_path=relative_target,
        engine=engine_label,
        errors=errors,
    )


def _resolve_scan_roots(resolved: Path, *, repo_wide: bool) -> list[Path]:
    if resolved.is_file():
        return [resolved]
    if repo_wide and resolved.resolve() == PROJECT_ROOT.resolve():
        roots = [PROJECT_ROOT / "src", PROJECT_ROOT / "dummy-infra"]
        return [path for path in roots if path.exists()]
    return [resolved]


def _audit_with_semgrep(scan_roots: list[Path]) -> tuple[list[SastFinding], list[ScannerError], int]:
    from tools.scanner_runner import find_executable

    if find_executable("semgrep") is None:
        return [], [ScannerError(scanner="semgrep", message="semgrep not found in PATH")], 0
    return run_semgrep_scan(scan_roots)


def _audit_with_regex(scan_roots: list[Path]) -> tuple[list[SastFinding], int]:
    findings: list[SastFinding] = []
    files_scanned = 0
    for root in scan_roots:
        for file_path in _iter_source_files(root, repo_wide=False):
            files_scanned += 1
            findings.extend(_scan_file(file_path))
    return findings, files_scanned


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
