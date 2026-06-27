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
from tools.scan_infra import scan_infrastructure  # noqa: E402
from tools.secret_auditor import audit_secrets  # noqa: E402

BASELINE_PATH = ROOT / "config" / "secops-baseline.json"
REPORT_PATH = ROOT / "reports" / "CI_AUDIT_REPORT.md"
SUMMARY_PATH = ROOT / "reports" / "CI_SUMMARY.md"


@dataclass
class GateResult:
    passed: bool = True
    reasons: list[str] = field(default_factory=list)


def main() -> int:
    infra_targets = _parse_targets(
        os.getenv("SECOPS_INFRA_TARGETS", "dummy-infra,Dockerfile"),
    )
    compliance_target = os.getenv("SECOPS_TARGET", "dummy-infra")
    secrets_target = os.getenv("SECOPS_SECRETS_TARGET", ".")
    result = GateResult()

    scan = scan_infrastructure(infra_targets, strict=False)
    secrets = audit_secrets(secrets_target, repo_wide=True)
    aws = audit_aws_config(compliance_target, live_scan=os.getenv("SECOPS_AWS_LIVE", "0") == "1")

    report = generate_compliance_report(
        target_path=compliance_target,
        output_path=str(REPORT_PATH.relative_to(ROOT)),
        scan_result=scan.model_dump(),
        secrets_result=secrets.model_dump(),
        aws_result=aws.model_dump(),
        auto_collect=True,
    )

    baseline = _load_baseline()
    _evaluate_gate(result, baseline, scan, secrets, aws)

    summary = _build_summary(
        result,
        scan,
        secrets,
        aws,
        report,
        infra_targets=infra_targets,
        secrets_target=secrets_target,
    )
    SUMMARY_PATH.write_text(summary, encoding="utf-8")

    print(summary)
    return 0 if result.passed else 1


def _parse_targets(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


def _load_baseline() -> dict:
    if not BASELINE_PATH.is_file():
        return {}
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


def _finding_key(scanner: str, finding_type: str, resource: str) -> str:
    return f"{scanner}|{finding_type}|{resource}"


def _evaluate_gate(result: GateResult, baseline: dict, scan, secrets, aws) -> None:
    if baseline.get("fail_on_scanner_errors") and scan.errors:
        result.passed = False
        result.reasons.append(f"Scanner errors: {[e.scanner for e in scan.errors]}")

    allowed_keys = set(baseline.get("allowed_finding_keys", []))
    fixture_prefixes = baseline.get("fixture_secret_prefixes", ["dummy-infra/"])
    infra_baseline_prefixes = baseline.get("infra_baseline_prefixes", ["dummy-infra/"])

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
    report,
    *,
    infra_targets: list[str],
    secrets_target: str,
) -> str:
    status = "PASSED" if result.passed else "FAILED"
    app_secrets = [
        s for s in secrets.findings
        if not s.resource.startswith("dummy-infra/")
    ]
    lines = [
        f"# DevSecOps CI Gate: {status}",
        "",
        "## Dual-Target Scope",
        f"- Secrets scan (repo-wide): `{secrets_target}`",
        f"- Infrastructure scan (fixture + self): `{', '.join(infra_targets)}`",
        "",
        "## Scan Summary",
        f"- Infrastructure findings: **{len(scan.findings)}** (critical={scan.summary.critical}, high={scan.summary.high})",
        f"- Secret findings: **{len(secrets.findings)}** (application code: **{len(app_secrets)}**)",
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
