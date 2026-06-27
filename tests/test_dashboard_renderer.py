from tools.dashboard_renderer import build_dashboard_context, render_secops_dashboard_html
from tools.models import (
    AuditAwsResult,
    AuditSastResult,
    AuditSecretsResult,
    ComplianceViolation,
    ReportSummary,
    ScanDependenciesResult,
    ScanInfrastructureResult,
    SecretFinding,
    summarize_findings,
)
from tools.risk_score import RiskScoreBreakdown, RiskScoreResult
from tools.sbom_gate import SbomGateResult


def test_dashboard_renders_gate_status_and_risk_gauge():
    ctx = build_dashboard_context(
        passed=False,
        target_path="dummy-infra",
        risk=RiskScoreResult(
            score=85,
            level="CRITICAL",
            breakdown=RiskScoreBreakdown(secrets_app=1),
            blockers=["secret:src/main.py:1"],
        ),
        report_summary=ReportSummary(total_violations=2, non_compliant_controls=1),
        gate_reasons=["CRITICAL: plaintext secret in application code: src/main.py:1"],
        scan=ScanInfrastructureResult(
            findings=[],
            summary=summarize_findings([]),
            errors=[],
            target_path="dummy-infra",
            scanners_run=["checkov"],
        ),
        secrets=AuditSecretsResult(
            findings=[
                SecretFinding(
                    id="S1",
                    secret_type="AWS Access Key ID",
                    resource="src/main.py",
                    line=1,
                    secret_prefix="AKIA",
                    severity="CRITICAL",
                    finding_type="secret.aws_access_key",
                ),
                SecretFinding(
                    id="S2",
                    secret_type="AWS Access Key ID",
                    resource="dummy-infra/.env.leaked",
                    line=1,
                    secret_prefix="AKIA",
                    severity="CRITICAL",
                    finding_type="secret.aws_access_key",
                ),
            ],
            files_scanned=2,
            target_path=".",
        ),
        sast=AuditSastResult(findings=[], files_scanned=0, target_path=".", engine="regex"),
        deps=ScanDependenciesResult(
            findings=[],
            summary=summarize_findings([]),
            errors=[],
            target_path="requirements.txt",
        ),
        aws=AuditAwsResult(findings=[], target_path="dummy-infra", live_scan=False),
        sbom_drift=SbomGateResult(
            manifest="requirements.txt",
            allowed_count=5,
            current_count=5,
            passed=True,
        ),
        violations=[
            ComplianceViolation(
                violation_id="F-001",
                finding_type="secret.aws_access_key",
                severity="CRITICAL",
                resource="src/main.py",
                scanner="audit_secrets",
                control_id="ISMS-2.7.2",
                framework="ISMS-P",
                control_title="암호키 관리",
                category="2.7. 암호화",
                checklist_question="암호키는 안전하게 관리되는가?",
                compliance_status="미흡",
                deficiency_reason="암호키 평문 노출",
                deficiency_detail="src/main.py",
                recommended_action="rotate",
                action_priority="즉시",
                evidence_required="scan",
                tool_reference="audit_secrets",
            )
        ],
    )

    html_out = render_secops_dashboard_html(ctx)

    assert "실패 — Merge 차단" in html_out
    assert "통과 — Merge 가능" not in html_out
    assert "복합 위험 점수" in html_out
    assert "85" in html_out
    assert "앱 코드 차단" in html_out
    assert "src/main.py" in html_out
    assert "픽스처 허용" in html_out
    assert "dummy-infra/.env.leaked" in html_out
    assert "ISMS-2.7.2" in html_out
    assert "왜 탐지는 많은데 통과인가요" in html_out
    assert "Merge 차단" in html_out
    assert ctx.baseline_total == 1
    assert "cdn.tailwindcss.com" in html_out


def test_dashboard_passed_state():
    ctx = build_dashboard_context(
        passed=True,
        target_path="dummy-infra",
        risk=RiskScoreResult(score=0, level="LOW", breakdown=RiskScoreBreakdown(), blockers=[]),
        report_summary=ReportSummary(),
        gate_reasons=[],
        scan=ScanInfrastructureResult(
            findings=[],
            summary=summarize_findings([]),
            errors=[],
            target_path="dummy-infra",
            scanners_run=[],
        ),
        secrets=AuditSecretsResult(findings=[], files_scanned=0, target_path="."),
        sast=AuditSastResult(findings=[], files_scanned=0, target_path=".", engine="regex"),
        deps=ScanDependenciesResult(
            findings=[],
            summary=summarize_findings([]),
            errors=[],
            target_path="none",
        ),
        aws=AuditAwsResult(findings=[], target_path="dummy-infra", live_scan=False),
        sbom_drift=SbomGateResult(manifest="requirements.txt", allowed_count=5, current_count=5, passed=True),
        violations=[],
    )
    html_out = render_secops_dashboard_html(ctx)
    assert "통과 — Merge 가능" in html_out
    assert "앱 코드 차단 항목 없음" in html_out
    assert "전체 스캔 탐지" in html_out
