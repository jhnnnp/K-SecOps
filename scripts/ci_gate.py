#!/usr/bin/env python3
"""CI gate: run DevSecOps scans, evaluate baseline, emit summary for GitHub Actions."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# Enable repository-wide secret scanning for CI scripts (MCP agents stay sandboxed).
os.environ.setdefault("SECOPS_REPO_SCAN", "1")

from tools.aws_auditor import audit_aws_config  # noqa: E402
from tools.compliance_report import generate_compliance_report  # noqa: E402
from tools.sast_auditor import audit_sast  # noqa: E402
from tools.scan_dependencies import scan_dependencies  # noqa: E402
from tools.scan_infra import scan_infrastructure  # noqa: E402
from tools.secret_auditor import audit_secrets  # noqa: E402

BASELINE_PATH = ROOT / "config" / "secops-baseline.json"
REPORT_PATH = ROOT / "reports" / "CI_AUDIT_REPORT.md"
SUMMARY_PATH = ROOT / "reports" / "CI_SUMMARY.md"
GATE_RESULT_PATH = ROOT / "reports" / "GATE_RESULT.json"


@dataclass
class GateResult:
    passed: bool = True
    reasons: list[str] = field(default_factory=list)


def main() -> int:
    infra_targets = _parse_targets(
        os.getenv("SECOPS_INFRA_TARGETS", "dummy-infra,Dockerfile"),
    )
    deps_targets = _parse_targets(
        os.getenv("SECOPS_DEPS_TARGETS", "requirements.txt,dummy-infra/deps"),
    )
    compliance_target = os.getenv("SECOPS_TARGET", "dummy-infra")
    secrets_target = os.getenv("SECOPS_SECRETS_TARGET", ".")
    sast_target = os.getenv("SECOPS_SAST_TARGET", ".")
    result = GateResult()

    scan = scan_infrastructure(infra_targets, strict=False)
    secrets = audit_secrets(secrets_target, repo_wide=True)
    aws = audit_aws_config(compliance_target, live_scan=os.getenv("SECOPS_AWS_LIVE", "0") == "1")
    deps = scan_dependencies(deps_targets, strict=False)
    sast = audit_sast(sast_target, repo_wide=True)

    report = generate_compliance_report(
        target_path=compliance_target,
        output_path=str(REPORT_PATH.relative_to(ROOT)),
        scan_result=scan.model_dump(),
        secrets_result=secrets.model_dump(),
        aws_result=aws.model_dump(),
        deps_result=deps.model_dump(),
        sast_result=sast.model_dump(),
        auto_collect=True,
    )

    baseline = _load_baseline()
    _evaluate_gate(result, baseline, scan, secrets, aws, deps, sast)

    summary = _build_summary(
        result,
        scan,
        secrets,
        aws,
        deps,
        sast,
        report,
        infra_targets=infra_targets,
        secrets_target=secrets_target,
        deps_targets=deps_targets,
        sast_target=sast_target,
    )
    SUMMARY_PATH.write_text(summary, encoding="utf-8")
    _write_gate_result(result, secrets_target=secrets_target)

    print(summary)
    return 0 if result.passed else 1


def _write_gate_result(result: GateResult, *, secrets_target: str) -> None:
    payload = {
        "passed": result.passed,
        "reasons": result.reasons,
        "summary_path": str(SUMMARY_PATH.relative_to(ROOT)),
        "report_path": str(REPORT_PATH.relative_to(ROOT)),
        "repository": os.getenv("GITHUB_REPOSITORY", ""),
        "ref": os.getenv("GITHUB_REF", ""),
        "secrets_target": secrets_target,
    }
    GATE_RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    GATE_RESULT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _parse_targets(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


def _is_app_dependency_manifest(resource: str, manifests: list[str]) -> bool:
    normalized = resource.replace("\\", "/")
    return normalized == "requirements.txt"


def _load_baseline() -> dict:
    if not BASELINE_PATH.is_file():
        return {}
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


def _finding_key(scanner: str, finding_type: str, resource: str) -> str:
    return f"{scanner}|{finding_type}|{resource}"


def _evaluate_gate(result: GateResult, baseline: dict, scan, secrets, aws, deps, sast) -> None:
    if baseline.get("fail_on_scanner_errors") and scan.errors:
        result.passed = False
        result.reasons.append(f"Scanner errors: {[e.scanner for e in scan.errors]}")

    if baseline.get("fail_on_scanner_errors") and deps.errors:
        result.passed = False
        result.reasons.append(f"Dependency scanner errors: {[e.scanner for e in deps.errors]}")

    if baseline.get("fail_on_scanner_errors") and sast.errors:
        result.passed = False
        result.reasons.append(f"SAST scanner errors: {[e.scanner for e in sast.errors]}")

    allowed_keys = set(baseline.get("allowed_finding_keys", []))
    fixture_prefixes = baseline.get("fixture_secret_prefixes", ["dummy-infra/"])
    infra_baseline_prefixes = baseline.get("infra_baseline_prefixes", ["dummy-infra/"])
    sast_fixture_prefixes = baseline.get("sast_fixture_prefixes", ["dummy-infra/"])
    deps_fixture_prefixes = baseline.get("deps_fixture_prefixes", ["dummy-infra/deps/"])
    app_manifests = baseline.get("app_dependency_manifests", ["requirements.txt"])

    for secret in secrets.findings:
        in_fixture = any(secret.resource.startswith(prefix) for prefix in fixture_prefixes)
        if not in_fixture:
            result.passed = False
            result.reasons.append(
                f"CRITICAL: plaintext secret in application code: {secret.resource}:{secret.line} "
                f"({secret.finding_type})"
            )
            continue

        key = _finding_key("audit_secrets", secret.finding_type, secret.resource)
        if allowed_keys and key not in allowed_keys:
            result.passed = False
            result.reasons.append(f"Unbaseline secret finding: {key}")

    for sast_finding in sast.findings:
        in_fixture = any(sast_finding.resource.startswith(prefix) for prefix in sast_fixture_prefixes)
        if not in_fixture:
            result.passed = False
            result.reasons.append(
                f"{sast_finding.severity}: SAST in application code: "
                f"{sast_finding.resource}:{sast_finding.line} ({sast_finding.finding_type})"
            )

    for dep in deps.findings:
        if dep.severity not in {"CRITICAL", "HIGH"}:
            continue
        in_fixture = any(dep.resource.startswith(prefix) for prefix in deps_fixture_prefixes)
        is_app_manifest = _is_app_dependency_manifest(dep.resource, app_manifests)
        if is_app_manifest and not in_fixture:
            result.passed = False
            result.reasons.append(
                f"{dep.severity}: dependency CVE in application manifest: {dep.id} @ {dep.resource}"
            )

    for aws_finding in aws.findings:
        key = _finding_key("audit_aws", aws_finding.finding_type, aws_finding.resource)
        if allowed_keys and key not in allowed_keys:
            result.passed = False
            result.reasons.append(f"Unbaseline AWS finding: {key}")

    if not baseline.get("fail_on_scan_critical", True):
        return

    for finding in scan.findings:
        if finding.severity != "CRITICAL":
            continue
        if not any(finding.resource.startswith(prefix) for prefix in infra_baseline_prefixes):
            continue
        key = _finding_key("scan_infrastructure", finding.id, finding.resource)
        if allowed_keys and key not in allowed_keys:
            result.passed = False
            result.reasons.append(f"Critical misconfig: {finding.id} @ {finding.resource}")


def _build_summary(
    result: GateResult,
    scan,
    secrets,
    aws,
    deps,
    sast,
    report,
    *,
    infra_targets: list[str],
    secrets_target: str,
    deps_targets: list[str],
    sast_target: str,
) -> str:
    status = "PASSED" if result.passed else "FAILED"
    app_secrets = [
        s for s in secrets.findings
        if not s.resource.startswith("dummy-infra/")
    ]
    app_sast = [
        s for s in sast.findings
        if not s.resource.startswith("dummy-infra/")
    ]
    app_deps = [
        d for d in deps.findings
        if d.severity in {"CRITICAL", "HIGH"}
        and _is_app_dependency_manifest(d.resource, ["requirements.txt"])
    ]
    lines = [
        f"# DevSecOps CI Gate: {status}",
        "",
        "## Multi-Track Scope",
        f"- Secrets scan (repo-wide): `{secrets_target}`",
        f"- SAST scan (`{sast.engine}`): `{sast_target}`",
        f"- SCA / Dependency CVE scan (Trivy vuln DB): `{', '.join(deps_targets)}`",
        f"- Infrastructure scan (fixture + self): `{', '.join(infra_targets)}`",
        "",
        "## Scan Summary",
        f"- Infrastructure findings: **{len(scan.findings)}** (critical={scan.summary.critical}, high={scan.summary.high})",
        f"- Secret findings: **{len(secrets.findings)}** (application code: **{len(app_secrets)}**)",
        f"- SAST findings ({sast.engine}): **{len(sast.findings)}** (application code: **{len(app_sast)}**)",
        f"- SCA CVEs — Trivy HIGH+ (NVD): **{len([d for d in deps.findings if d.severity in {'CRITICAL', 'HIGH'}])}** (app manifest: **{len(app_deps)}**)",
        f"- AWS config findings: **{len(aws.findings)}** (live={aws.live_scan})",
        f"- Compliance violations: **{report.summary.total_violations}**",
        f"- Report: `{report.report_path}`",
        "",
    ]

    if app_secrets:
        lines.extend(["## Application Code Secrets (BLOCKED)", ""])
        for item in app_secrets:
            lines.append(
                f"- [{item.severity}] `{item.finding_type}` @ {item.resource}:{item.line}"
            )
        lines.append("")

    if app_sast:
        lines.extend(["## Application SAST (BLOCKED)", ""])
        for item in app_sast:
            lines.append(
                f"- [{item.severity}] `{item.finding_type}` @ {item.resource}:{item.line} — {item.title}"
            )
        lines.append("")

    if app_deps:
        lines.extend(["## Application Dependency CVEs (BLOCKED)", ""])
        for item in app_deps:
            lines.append(f"- [{item.severity}] `{item.id}` @ {item.resource}")
        lines.append("")

    if aws.errors:
        lines.append("## AWS Live Scan Notes")
        for err in aws.errors:
            lines.append(f"- {err}")
        lines.append("")

    if aws.findings:
        lines.extend(["## AWS Findings", ""])
        for item in aws.findings:
            lines.append(f"- [{item.severity}] `{item.finding_type}` @ {item.resource} ({item.source})")
        lines.append("")

    if not result.passed:
        lines.extend(["## Gate Failure Reasons", ""])
        for reason in result.reasons:
            lines.append(f"- {reason}")
        lines.append("")

    lines.append("> Full Lab report attached as workflow artifact / `reports/CI_AUDIT_REPORT.md`")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
