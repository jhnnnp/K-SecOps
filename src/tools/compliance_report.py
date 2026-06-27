from __future__ import annotations

from datetime import datetime, timezone

from compliance.mapper import build_violations
from tools.file_reader import read_log_file
from tools.aws_auditor import audit_aws_config
from tools.models import (
    AuditAwsResult,
    AuditSastResult,
    AuditSecretsResult,
    GenerateComplianceReportResult,
    NormalizedInput,
    ScanDependenciesResult,
    ScanInfrastructureResult,
)
from tools.scan_dependencies import scan_dependencies
from tools.sast_auditor import audit_sast
from tools.pii_masker import MaskPiiResult
from tools.path_utils import relative_project_path, resolve_sandbox_path
from tools.pii_masker import mask_pii
from tools.report_renderer import render_report_markdown, summarize_report
from tools.scan_infra import scan_infrastructure
from tools.secret_auditor import audit_secrets


def generate_compliance_report(
    target_path: str = "dummy-infra",
    output_path: str | None = None,
    scan_result: dict | None = None,
    pii_result: dict | None = None,
    secrets_result: dict | None = None,
    aws_result: dict | None = None,
    deps_result: dict | None = None,
    sast_result: dict | None = None,
    pii_log_path: str | None = None,
    auto_collect: bool = True,
) -> GenerateComplianceReportResult:
    """
    Map findings to ISMS-P / EFT controls via finding_rules.json and write a Markdown report.

    When auto_collect is True, missing scan/pii/secrets inputs are gathered automatically.
    """
    normalized = _normalize_inputs(
        target_path=target_path,
        scan_result=scan_result,
        pii_result=pii_result,
        secrets_result=secrets_result,
        aws_result=aws_result,
        deps_result=deps_result,
        sast_result=sast_result,
        pii_log_path=pii_log_path,
        auto_collect=auto_collect,
    )
    violations = build_violations(normalized)
    summary = summarize_report(
        violations,
        scan_summary=normalized.scan_summary.model_dump() if normalized.scan_summary else None,
    )

    report_path = output_path or _default_output_path()
    resolved_output = resolve_sandbox_path(report_path)
    resolved_output.parent.mkdir(parents=True, exist_ok=True)

    scanners = list(normalized.scanners_run)
    if normalized.pii_findings:
        scanners.append("mask_pii")
    if normalized.secret_findings:
        scanners.append("audit_secrets")
    if normalized.sast_findings:
        scanners.append("audit_sast")
    if normalized.dependency_findings:
        scanners.append("scan_dependencies")
    if normalized.aws_findings:
        scanners.append("audit_aws")

    markdown = render_report_markdown(
        target_path=normalized.target_path,
        violations=violations,
        summary=summary,
        scanners=sorted(set(scanners)),
    )
    resolved_output.write_text(markdown, encoding="utf-8")

    return GenerateComplianceReportResult(
        report_path=relative_project_path(resolved_output),
        violations=violations,
        summary=summary,
        target_path=normalized.target_path,
    )


def _normalize_inputs(
    *,
    target_path: str,
    scan_result: dict | None,
    pii_result: dict | None,
    secrets_result: dict | None,
    aws_result: dict | None,
    deps_result: dict | None,
    sast_result: dict | None,
    pii_log_path: str | None,
    auto_collect: bool,
) -> NormalizedInput:
    scan_summary = None
    scan_findings = []
    scanners_run: list[str] = []

    if scan_result is None and auto_collect:
        scan_result = scan_infrastructure(target_path).model_dump()

    if scan_result:
        parsed = ScanInfrastructureResult.model_validate(scan_result)
        scan_findings = parsed.findings
        scan_summary = parsed.summary
        scanners_run = parsed.scanners_run

    secret_findings = []
    if secrets_result is None and auto_collect:
        secrets_result = audit_secrets(target_path).model_dump()
    if secrets_result:
        secret_findings = AuditSecretsResult.model_validate(secrets_result).findings

    aws_findings = []
    if aws_result is None and auto_collect:
        aws_result = audit_aws_config(target_path).model_dump()
    if aws_result:
        aws_findings = AuditAwsResult.model_validate(aws_result).findings

    dependency_findings = []
    if deps_result is None and auto_collect:
        deps_result = scan_dependencies(["dummy-infra/deps"], strict=True).model_dump()
    if deps_result:
        dependency_findings = ScanDependenciesResult.model_validate(deps_result).findings

    sast_findings = []
    if sast_result is None and auto_collect:
        sast_result = audit_sast(target_path, repo_wide=False).model_dump()
    if sast_result:
        sast_findings = AuditSastResult.model_validate(sast_result).findings

    pii_findings: list[dict] = []
    pii_resource = pii_log_path
    if pii_result is None and auto_collect:
        log_path = pii_log_path or _default_log_path(target_path)
        try:
            log = read_log_file(log_path)
            pii_result = mask_pii(log.content).model_dump()
            pii_resource = log.path
        except FileNotFoundError:
            pii_result = None

    if pii_result:
        parsed_pii = MaskPiiResult.model_validate(pii_result)
        pii_findings = [item.model_dump() for item in parsed_pii.findings]

    return NormalizedInput(
        target_path=target_path,
        scan_findings=scan_findings,
        scan_summary=scan_summary,
        scanners_run=scanners_run,
        secret_findings=secret_findings,
        sast_findings=sast_findings,
        dependency_findings=dependency_findings,
        aws_findings=aws_findings,
        pii_findings=pii_findings,
        pii_resource=pii_resource,
    )


def _default_output_path() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"reports/AUDIT_{stamp}.md"


def _default_log_path(target_path: str) -> str:
    if target_path.endswith(".txt") or target_path.endswith(".log"):
        return target_path
    base = target_path.rstrip("/")
    preferred = f"{base}/logs/app.log"
    fallback = f"{base}/test_log.txt"
    from tools.sandbox import PROJECT_ROOT

    if (PROJECT_ROOT / preferred).is_file():
        return preferred
    return fallback
