from tools.compliance_report import generate_compliance_report
from tools.report_badges import severity_badge, status_badge
from tools.report_renderer import render_report_markdown, summarize_report
from tools.models import ComplianceViolation, ReportSummary


def test_report_contains_badges_and_lab_fields():
    violation = ComplianceViolation(
        violation_id="F-001",
        finding_type="secret.aws_access_key",
        severity="CRITICAL",
        resource="dummy-infra/.env.leaked",
        scanner="audit_secrets",
        control_id="ISMS-2.9.2",
        framework="ISMS-P",
        control_title="암호키 관리",
        category="2.9. 암호화",
        checklist_question="암호키는 생성·보관·폐기 등 생명주기 전반에 걸쳐 안전하게 관리되고 있는가?",
        compliance_status="미흡",
        deficiency_reason="암호키( AWS Access Key ) 평문 저장·노출",
        deficiency_detail="dummy-infra/.env.leaked에서 AWS Access Key (AKIA***) 평문 탐지.",
        recommended_action="노출 키 즉시 deactivate·rotate",
        action_priority="즉시",
        evidence_required="IAM 키 rotate 이력",
        tool_reference="audit_secrets",
    )
    summary = summarize_report([violation])
    markdown = render_report_markdown(
        target_path="dummy-infra",
        violations=[violation],
        summary=summary,
        scanners=["audit_secrets"],
    )
    assert "img.shields.io" in markdown
    assert severity_badge("CRITICAL") in markdown
    assert status_badge("미흡") in markdown
    assert "**결함 사유**" in markdown
    assert "**권고 조치**" in markdown
    assert "finding_rules.json" in markdown


def test_generate_compliance_report_e2e(tmp_path, monkeypatch):
    output = "reports/TEST_AUDIT.md"
    result = generate_compliance_report(
        target_path="dummy-infra",
        output_path=output,
        auto_collect=True,
    )
    assert result.report_path == output
    assert result.summary.total_violations > 0
    assert result.summary.immediate_actions > 0

    from tools.sandbox import PROJECT_ROOT

    report_text = (PROJECT_ROOT / output).read_text(encoding="utf-8")
    assert "# Security Audit Report" in report_text
    assert "ISMS-2.9.2" in report_text or "ISMS-2.10.1" in report_text
    assert "img.shields.io" in report_text
