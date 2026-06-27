from __future__ import annotations

import os
import re
from pathlib import Path
from re import Pattern

from tools.models import AuditSecretsResult, SecretFinding
from tools.path_utils import relative_project_path, resolve_sandbox_target
from tools.sandbox import PROJECT_ROOT, is_repo_scan_mode

SECRET_PATTERNS: list[tuple[str, str, Pattern[str], str]] = [
    (
        "secret.aws_access_key",
        "AWS Access Key ID",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "CRITICAL",
    ),
    (
        "secret.aws_secret_key",
        "AWS Secret Access Key",
        re.compile(r"(?i)\baws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})\b"),
        "CRITICAL",
    ),
    (
        "secret.api_key",
        "Generic API Key",
        re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"),
        "CRITICAL",
    ),
    (
        "secret.private_key",
        "Private Key Block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "CRITICAL",
    ),
]

IGNORE_DIR_NAMES = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".eggs",
    "htmlcov",
}

REPO_SCAN_IGNORE_DIR_NAMES = IGNORE_DIR_NAMES | {"tests", "reports"}

SCANNABLE_SUFFIXES = {
    ".txt",
    ".log",
    ".env",
    ".yaml",
    ".yml",
    ".json",
    ".sh",
    ".py",
    ".md",
    ".ini",
    ".toml",
    ".properties",
    ".dockerfile",
    ".cfg",
    ".conf",
}


def audit_secrets(
    target_path: str = "dummy-infra",
    *,
    repo_wide: bool | None = None,
) -> AuditSecretsResult:
    """
    Scan files for plaintext secrets and credentials.

    repo_wide=False (default, MCP): sandboxed target under dummy-infra/ or reports/.
    repo_wide=True (CI): scan entire repository from target_path (usually ".").
    """
    use_repo_wide = repo_wide if repo_wide is not None else is_repo_scan_mode()
    strict = not use_repo_wide
    resolved = resolve_sandbox_target(target_path, strict=strict)
    relative_target = relative_project_path(resolved)

    findings: list[SecretFinding] = []
    files_scanned = 0
    ignore_dirs = REPO_SCAN_IGNORE_DIR_NAMES if use_repo_wide else IGNORE_DIR_NAMES

    for file_path in _iter_target_files(resolved, ignore_dirs=ignore_dirs):
        files_scanned += 1
        findings.extend(_scan_file(file_path))

    return AuditSecretsResult(
        findings=_dedupe_secret_findings(findings),
        files_scanned=files_scanned,
        target_path=relative_target,
    )


def _iter_target_files(root, *, ignore_dirs: set[str]):
    if root.is_file():
        if _is_scannable_file(root):
            yield root
        return

    scan_root = root.resolve()
    project_root = PROJECT_ROOT.resolve()

    for dirpath, dirnames, filenames in os.walk(scan_root, topdown=True, followlinks=False):
        current = Path(dirpath)
        try:
            current.relative_to(project_root)
        except ValueError:
            dirnames.clear()
            continue

        dirnames[:] = [
            name
            for name in dirnames
            if name not in ignore_dirs and not name.startswith(".ruff_cache")
        ]

        for filename in filenames:
            file_path = current / filename
            if _is_scannable_file(file_path):
                yield file_path


def _is_scannable_file(path: Path) -> bool:
    name = path.name
    suffix = path.suffix.lower()
    return (
        suffix in SCANNABLE_SUFFIXES
        or name.startswith(".env")
        or name == "Dockerfile"
    )


def _scan_file(file_path) -> list[SecretFinding]:
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    resource = relative_project_path(file_path)
    findings: list[SecretFinding] = []

    for finding_type, label, pattern, severity in SECRET_PATTERNS:
        for line_no, line in enumerate(content.splitlines(), start=1):
            match = pattern.search(line)
            if not match:
                continue
            secret_prefix = _extract_prefix(match)
            findings.append(
                SecretFinding(
                    id=f"SECRET-{finding_type.upper()}-{line_no}",
                    secret_type=label,
                    resource=resource,
                    line=line_no,
                    secret_prefix=secret_prefix,
                    severity=severity,
                    finding_type=finding_type,
                )
            )
    return findings


def _extract_prefix(match: re.Match[str]) -> str:
    if match.lastindex:
        value = match.group(1)
        return value[:4] if len(value) >= 4 else value
    return "----"


def _dedupe_secret_findings(findings: list[SecretFinding]) -> list[SecretFinding]:
    seen: set[tuple[str, str, int, str]] = set()
    unique: list[SecretFinding] = []
    for finding in findings:
        key = (finding.finding_type, finding.resource, finding.line, finding.secret_prefix)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
