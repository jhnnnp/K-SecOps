from pathlib import Path

from tools.models import SastFinding
from tools.sarif_exporter import sast_findings_to_sarif
from tools.sbom_gate import check_sbom_drift
from tools.risk_score import compute_risk_score
from tools.models import (
    AuditAwsResult,
    AuditSastResult,
    AuditSecretsResult,
    ScanDependenciesResult,
    ScanInfrastructureResult,
    summarize_findings,
)


def test_check_sbom_drift_passes_on_approved_manifest():
    result = check_sbom_drift("requirements.txt")
    assert result.passed is True
    assert result.current_count == 5
    assert result.new_components == []


def test_check_sbom_drift_detects_unauthorized_package():
    baseline = Path(__file__).resolve().parents[1] / "config" / "test-sbom-baseline.json"
    result = check_sbom_drift("tests/fixtures/requirements-drift.txt", baseline_path=baseline)
    assert result.passed is False
    assert any(item.component == "unauthorized-package" for item in result.new_components)


def test_sarif_exporter_maps_findings():
    findings = [
        SastFinding(
            id="SAST-1",
            finding_type="sast.unsafe_eval",
            resource="src/app.py",
            line=10,
            severity="CRITICAL",
            title="eval-detected",
            description="eval in use",
        )
    ]
    sarif = sast_findings_to_sarif(findings)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "sast.unsafe_eval"


def test_risk_score_zero_when_no_blockers():
    empty = AuditSecretsResult(findings=[], files_scanned=0, target_path=".")
    sast = AuditSastResult(findings=[], files_scanned=0, target_path=".", engine="regex")
    deps = ScanDependenciesResult(findings=[], summary=summarize_findings([]), target_path=".")
    scan = ScanInfrastructureResult(
        findings=[],
        summary=summarize_findings([]),
        target_path="dummy-infra",
    )
    aws = AuditAwsResult(findings=[], target_path="dummy-infra")
    risk = compute_risk_score(secrets=empty, sast=sast, deps=deps, scan=scan, aws=aws)
    assert risk.score == 0
    assert risk.level == "LOW"
    assert risk.blockers == []
