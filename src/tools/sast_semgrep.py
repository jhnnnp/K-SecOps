from __future__ import annotations

import os
import re
from pathlib import Path

from tools.models import SastFinding, ScannerError
from tools.path_utils import relative_project_path
from tools.scanner_runner import ScannerCommandError, run_scanner

SEMGREP_CONFIG = os.getenv("SECOPS_SEMGREP_CONFIG", "auto")

SEMGREP_SEVERITY_MAP = {
    "ERROR": "CRITICAL",
    "WARNING": "HIGH",
    "INFO": "MEDIUM",
}

# Map Semgrep registry check_id suffixes to internal finding types (compliance rules).
SEMGREP_CHECK_ID_MAP: dict[str, str] = {
    "eval-detected": "sast.unsafe_eval",
    "exec-detected": "sast.unsafe_exec",
    "subprocess-shell-true": "sast.shell_injection",
    "os-system": "sast.os_system",
    "dangerous-pickle-use": "sast.unsafe_pickle",
    "hardcoded-password": "sast.hardcoded_password",
    "sql-injection": "sast.sql_concat",
}

SEMGREP_SOURCE_SUFFIXES = {".py", ".js", ".ts", ".jsx", ".tsx"}


def run_semgrep_scan(scan_paths: list[Path]) -> tuple[list[SastFinding], list[ScannerError], int]:
    """Run Semgrep with OWASP-oriented auto rules; return findings, errors, files_scanned."""
    if not scan_paths:
        return [], [], 0

    command = [
        "semgrep",
        "scan",
        "--config",
        SEMGREP_CONFIG,
        "--json",
        "--quiet",
    ]
    # --config auto requires Semgrep metrics; pin a ruleset via SECOPS_SEMGREP_CONFIG to disable.
    if SEMGREP_CONFIG != "auto":
        command.extend(["--metrics", "off"])
    for path in scan_paths:
        command.append(str(path))

    try:
        payload = run_scanner("semgrep", command, timeout=300)
    except ScannerCommandError as exc:
        return [], [ScannerError(scanner="semgrep", message=exc.message)], 0

    findings = _parse_semgrep_payload(payload)
    files_scanned = _count_scanned_files(scan_paths)
    return findings, [], files_scanned


def _parse_semgrep_payload(payload: dict) -> list[SastFinding]:
    results = payload.get("results", [])
    if not isinstance(results, list):
        return []

    findings: list[SastFinding] = []
    for index, item in enumerate(results, start=1):
        if not isinstance(item, dict):
            continue
        check_id = str(item.get("check_id", "unknown"))
        path = str(item.get("path", ""))
        if not path:
            continue

        start = item.get("start") or {}
        line = int(start.get("line", 0) or 0)
        extra = item.get("extra") or {}
        message = str(extra.get("message", check_id))
        raw_severity = str(extra.get("severity", "WARNING")).upper()
        severity = SEMGREP_SEVERITY_MAP.get(raw_severity, "HIGH")
        finding_type = _map_check_id(check_id)
        slug = _slugify_check_id(check_id)

        findings.append(
            SastFinding(
                id=f"SEMGREP-{slug}-{line or index}",
                finding_type=finding_type,
                resource=_normalize_resource(path),
                line=line or 1,
                severity=severity,
                title=check_id.rsplit(".", 1)[-1],
                description=message[:200],
            )
        )
    return _dedupe(findings)


def _normalize_resource(path: str) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        return relative_project_path(candidate)
    return path.replace("\\", "/")


def _map_check_id(check_id: str) -> str:
    for suffix, finding_type in SEMGREP_CHECK_ID_MAP.items():
        if check_id.endswith(suffix) or suffix in check_id:
            return finding_type
    return "sast.semgrep.generic"


def _slugify_check_id(check_id: str) -> str:
    slug = check_id.rsplit(".", 1)[-1]
    return re.sub(r"[^a-zA-Z0-9]+", "-", slug).strip("-").upper()[:40] or "RULE"


def _count_scanned_files(scan_paths: list[Path]) -> int:
    total = 0
    for root in scan_paths:
        if root.is_file():
            if root.suffix.lower() in SEMGREP_SOURCE_SUFFIXES:
                total += 1
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SEMGREP_SOURCE_SUFFIXES:
                total += 1
    return total


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
