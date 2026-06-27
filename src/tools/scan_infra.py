from __future__ import annotations

from pathlib import Path

from tools.models import (
    Finding,
    ScanInfrastructureResult,
    ScannerError,
    summarize_findings,
)
from tools.parsers.checkov_parser import parse_checkov_report
from tools.parsers.trivy_parser import parse_trivy_report
from tools.path_utils import relative_project_path, resolve_sandbox_target
from tools.scanner_runner import ScannerCommandError, run_scanner

DEFAULT_SCANNERS = ("trivy", "checkov")


def scan_infrastructure(
    target_path: str | list[str] = "dummy-infra",
    scanners: list[str] | None = None,
    *,
    strict: bool | None = None,
) -> ScanInfrastructureResult:
    """
    Scan infrastructure with Trivy and/or Checkov.

    Accepts a single path or a list (e.g. ["dummy-infra", "Dockerfile"]).
    Returns normalized findings even when individual scanners fail or are missing.
    """
    selected = _normalize_scanners(scanners)
    targets = [target_path] if isinstance(target_path, str) else list(target_path)

    findings: list[Finding] = []
    errors: list[ScannerError] = []
    scanners_run: list[str] = []
    scanned_paths: list[str] = []

    for raw_target in targets:
        resolved = resolve_sandbox_target(raw_target, strict=strict)
        relative_target = relative_project_path(resolved)
        scanned_paths.append(relative_target)
        target_findings, target_errors, target_scanners = _scan_target(resolved, selected)
        findings.extend(target_findings)
        errors.extend(target_errors)
        for scanner in target_scanners:
            if scanner not in scanners_run:
                scanners_run.append(scanner)

    deduped = _dedupe_findings(findings)
    return ScanInfrastructureResult(
        findings=deduped,
        summary=summarize_findings(deduped),
        errors=errors,
        target_path=", ".join(scanned_paths),
        scanners_run=scanners_run,
    )


def _scan_target(
    resolved: Path,
    selected: tuple[str, ...],
) -> tuple[list[Finding], list[ScannerError], list[str]]:
    findings: list[Finding] = []
    errors: list[ScannerError] = []
    scanners_run: list[str] = []

    if "trivy" in selected:
        scanners_run.append("trivy")
        try:
            payload = run_scanner(
                "trivy",
                [
                    "trivy",
                    "fs",
                    str(resolved),
                    "--format",
                    "json",
                    "--scanners",
                    "vuln,secret,misconfig",
                    "--quiet",
                ],
            )
            findings.extend(parse_trivy_report(payload))
        except ScannerCommandError as exc:
            errors.append(ScannerError(scanner="trivy", message=exc.message))

    if "checkov" in selected:
        scanners_run.append("checkov")
        checkov_args = [
            "checkov",
            "-f" if resolved.is_file() else "-d",
            str(resolved),
            "--output",
            "json",
            "--quiet",
            "--compact",
        ]
        try:
            payload = run_scanner("checkov", checkov_args)
            findings.extend(parse_checkov_report(payload))
        except ScannerCommandError as exc:
            errors.append(ScannerError(scanner="checkov", message=exc.message))

    return findings, errors, scanners_run


def _normalize_scanners(scanners: list[str] | None) -> tuple[str, ...]:
    if scanners is None:
        return DEFAULT_SCANNERS

    normalized: list[str] = []
    for scanner in scanners:
        key = scanner.strip().lower()
        if key not in DEFAULT_SCANNERS:
            allowed = ", ".join(DEFAULT_SCANNERS)
            raise ValueError(f"Unknown scanner {scanner!r}. Allowed: {allowed}")
        if key not in normalized:
            normalized.append(key)
    return tuple(normalized)


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.scanner, finding.id, finding.resource)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
