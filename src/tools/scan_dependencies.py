from __future__ import annotations

from pathlib import Path

from tools.models import Finding, ScanDependenciesResult, ScannerError, summarize_findings
from tools.parsers.trivy_parser import parse_trivy_report
from tools.path_utils import relative_project_path, resolve_sandbox_target
from tools.sandbox import PROJECT_ROOT
from tools.scanner_runner import ScannerCommandError, run_scanner

DEFAULT_DEPS_TARGETS = ("requirements.txt", "dummy-infra/deps")
APP_MANIFEST_SKIP_DIRS = (
    "dummy-infra",
    ".git",
    ".venv",
    "tests",
    "node_modules",
    "reports",
    "htmlcov",
)


def scan_dependencies(
    target_paths: str | list[str] | None = None,
    *,
    strict: bool | None = None,
) -> ScanDependenciesResult:
    """
    SCA (Software Composition Analysis) via Trivy vulnerability scanner.

    Queries the NVD-backed vulnerability database for pinned package versions
    in requirements.txt (and related manifests). HIGH/CRITICAL CVEs in the
    application manifest block the CI gate; fixture CVEs under dummy-infra/deps/
    are regression targets only.
    """
    if strict is None:
        from tools.sandbox import is_repo_scan_mode

        strict = not is_repo_scan_mode()
    raw_targets = _normalize_targets(target_paths)
    findings: list[Finding] = []
    errors: list[ScannerError] = []
    scanned: list[str] = []

    for raw_target in raw_targets:
        resolved = resolve_sandbox_target(raw_target, strict=strict)
        scan_roots = _dependency_scan_roots(resolved, raw_target=raw_target)
        if not scan_roots:
            continue
        for root, skip_dirs in scan_roots:
            relative = relative_project_path(root)
            scanned.append(relative)
            root_findings, root_errors = _trivy_vuln_scan(root, skip_dirs=skip_dirs)
            findings.extend(root_findings)
            errors.extend(root_errors)

    deduped = _dedupe(findings)
    return ScanDependenciesResult(
        findings=deduped,
        summary=summarize_findings(deduped),
        errors=errors,
        target_path=", ".join(scanned) or "none",
    )


def _normalize_targets(target_paths: str | list[str] | None) -> list[str]:
    if target_paths is None:
        return list(DEFAULT_DEPS_TARGETS)
    if isinstance(target_paths, str):
        return [part.strip() for part in target_paths.split(",") if part.strip()]
    return list(target_paths)


def _dependency_scan_roots(resolved: Path, *, raw_target: str) -> list[tuple[Path, tuple[str, ...]]]:
    normalized = raw_target.strip().replace("\\", "/")
    if normalized == "requirements.txt":
        return [(PROJECT_ROOT, APP_MANIFEST_SKIP_DIRS)]
    if resolved.is_file():
        return [(resolved.parent, ())]
    if (resolved / "requirements.txt").is_file():
        return [(resolved, ())]
    manifest_files = sorted(resolved.glob("*requirements*.txt"))
    if manifest_files:
        return [(resolved, ())]
    return [(resolved, ())]


def _trivy_vuln_scan(root: Path, *, skip_dirs: tuple[str, ...] = ()) -> tuple[list[Finding], list[ScannerError]]:
    command = [
        "trivy",
        "fs",
        str(root),
        "--format",
        "json",
        "--scanners",
        "vuln",
        "--quiet",
    ]
    for directory in skip_dirs:
        command.extend(["--skip-dirs", directory])
    try:
        payload = run_scanner("trivy", command, timeout=240)
    except ScannerCommandError as exc:
        return [], [ScannerError(scanner="trivy", message=exc.message)]

    parsed = parse_trivy_report(payload)
    root_label = relative_project_path(root)
    findings: list[Finding] = []
    for item in parsed:
        if item.severity not in {"CRITICAL", "HIGH"}:
            continue
        resource = _normalize_dependency_resource(item.resource, root_label)
        finding_type = (
            "dependency.critical_cve"
            if item.severity == "CRITICAL"
            else "dependency.high_cve"
        )
        findings.append(
            item.model_copy(
                update={
                    "resource": resource,
                    "scanner": "scan_dependencies",
                    "finding_type": finding_type,
                }
            )
        )
    return findings, []


def _normalize_dependency_resource(resource: str, root_label: str) -> str:
    normalized = resource.replace("\\", "/")
    if normalized in {"requirements.txt", "go.mod", "Pipfile", "poetry.lock"}:
        if root_label in {".", ""}:
            return normalized
        return f"{root_label}/{normalized}"
    if root_label not in {".", ""} and not normalized.startswith(f"{root_label}/"):
        return f"{root_label}/{normalized}"
    return normalized


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.id, finding.resource, finding.title)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
