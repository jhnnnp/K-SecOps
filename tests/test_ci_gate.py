import importlib.util
import subprocess
import sys
from pathlib import Path

from tools.models import (
    AuditAwsResult,
    AuditSastResult,
    AuditSecretsResult,
    SastFinding,
    ScanDependenciesResult,
    ScanInfrastructureResult,
    SecretFinding,
    summarize_findings,
)
from tools.sbom_gate import SbomGateResult


def _load_ci_gate_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("ci_gate", root / "scripts" / "ci_gate.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["ci_gate"] = module
    spec.loader.exec_module(module)
    return module


def test_ci_gate_passes_on_baseline_dummy_infra():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(root / "scripts" / "ci_gate.py")],
        cwd=root,
        env={**dict(__import__("os").environ), "PYTHONPATH": "src", "SECOPS_AWS_LIVE": "0", "SECOPS_SAST_ENGINE": "regex"},
        capture_output=True,
        text=True,
        timeout=240,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "DevSecOps CI Gate: PASSED" in result.stdout
    assert "Multi-Track Scope" in result.stdout
    assert "SAST findings" in result.stdout
    assert "SCA CVEs" in result.stdout
    assert "SBOM drift gate" in result.stdout
    assert "Risk Score" in result.stdout
    dashboard = root / "reports" / "SECOPS_DASHBOARD.html"
    assert dashboard.is_file(), "SECOPS_DASHBOARD.html should be generated"
    assert "통과 — Merge 가능" in dashboard.read_text(encoding="utf-8")


def test_gate_fails_on_secret_outside_fixture():
    ci_gate = _load_ci_gate_module()
    gate = ci_gate.GateResult()
    baseline = _empty_baseline()
    secrets = AuditSecretsResult(
        findings=[
            SecretFinding(
                id="SECRET-1",
                secret_type="AWS Access Key ID",
                resource="src/main.py",
                line=42,
                secret_prefix="AKIA",
                severity="CRITICAL",
                finding_type="secret.aws_access_key",
            )
        ],
        files_scanned=1,
        target_path=".",
    )
    scan, aws, deps, sast = _empty_scan_bundle()

    ci_gate._evaluate_gate(gate, baseline, scan, secrets, aws, deps, sast, _empty_sbom_drift())
    assert gate.passed is False
    assert any("application code" in reason for reason in gate.reasons)


def test_gate_fails_on_os_system_in_application_code():
    ci_gate = _load_ci_gate_module()
    gate = ci_gate.GateResult()
    baseline = _empty_baseline()
    sast = AuditSastResult(
        findings=[
            SastFinding(
                id="SAST-OS",
                finding_type="sast.os_system",
                resource="src/utils.py",
                line=3,
                severity="CRITICAL",
                title="os.system",
                description='os.system("rm -rf /")',
            )
        ],
        files_scanned=1,
        target_path=".",
    )
    scan, aws, deps, _ = _empty_scan_bundle()
    secrets = AuditSecretsResult(findings=[], files_scanned=0, target_path=".")

    ci_gate._evaluate_gate(gate, baseline, scan, secrets, aws, deps, sast, _empty_sbom_drift())
    assert gate.passed is False
    assert any("sast.os_system" in reason for reason in gate.reasons)


def test_gate_fails_on_sast_in_application_code():
    ci_gate = _load_ci_gate_module()
    gate = ci_gate.GateResult()
    baseline = _empty_baseline()
    sast = AuditSastResult(
        findings=[
            SastFinding(
                id="SAST-1",
                finding_type="sast.unsafe_eval",
                resource="src/main.py",
                line=10,
                severity="CRITICAL",
                title="eval",
                description="eval(x)",
            )
        ],
        files_scanned=1,
        target_path=".",
    )
    scan, aws, deps, _ = _empty_scan_bundle()
    secrets = AuditSecretsResult(findings=[], files_scanned=0, target_path=".")

    ci_gate._evaluate_gate(gate, baseline, scan, secrets, aws, deps, sast, _empty_sbom_drift())
    assert gate.passed is False
    assert any("SAST in application code" in reason for reason in gate.reasons)


def _empty_baseline() -> dict:
    return {
        "fixture_secret_prefixes": ["dummy-infra/"],
        "sast_fixture_prefixes": ["dummy-infra/"],
        "deps_fixture_prefixes": ["dummy-infra/deps/"],
        "app_dependency_manifests": ["requirements.txt"],
        "infra_baseline_prefixes": ["dummy-infra/"],
        "allowed_finding_keys": [],
        "fail_on_scan_critical": True,
        "fail_on_scanner_errors": True,
    }


def _empty_sbom_drift() -> SbomGateResult:
    return SbomGateResult(
        manifest="requirements.txt",
        allowed_count=5,
        current_count=5,
        passed=True,
    )


def _empty_scan_bundle():
    scan = ScanInfrastructureResult(
        findings=[],
        summary=summarize_findings([]),
        errors=[],
        target_path="dummy-infra",
        scanners_run=[],
    )
    aws = AuditAwsResult(findings=[], target_path="dummy-infra", live_scan=False, errors=[])
    deps = ScanDependenciesResult(
        findings=[],
        summary=summarize_findings([]),
        errors=[],
        target_path="none",
    )
    sast = AuditSastResult(findings=[], files_scanned=0, target_path=".")
    return scan, aws, deps, sast
