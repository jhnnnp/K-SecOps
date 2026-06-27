import importlib.util
import subprocess
import sys
from pathlib import Path

from tools.models import AuditAwsResult, AuditSecretsResult, ScanInfrastructureResult, SecretFinding, summarize_findings


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
        env={**dict(__import__("os").environ), "PYTHONPATH": "src", "SECOPS_AWS_LIVE": "0"},
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "DevSecOps CI Gate: PASSED" in result.stdout
    assert "Dual-Target Scope" in result.stdout


def test_gate_fails_on_secret_outside_fixture():
    ci_gate = _load_ci_gate_module()
    gate = ci_gate.GateResult()
    baseline = {
        "fixture_secret_prefixes": ["dummy-infra/"],
        "infra_baseline_prefixes": ["dummy-infra/"],
        "allowed_finding_keys": [],
        "fail_on_scan_critical": True,
        "fail_on_scanner_errors": True,
    }
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
    scan = ScanInfrastructureResult(
        findings=[],
        summary=summarize_findings([]),
        errors=[],
        target_path="dummy-infra",
        scanners_run=[],
    )
    aws = AuditAwsResult(findings=[], target_path="dummy-infra", live_scan=False, errors=[])

    ci_gate._evaluate_gate(gate, baseline, scan, secrets, aws)
    assert gate.passed is False
    assert any("application code" in reason for reason in gate.reasons)
