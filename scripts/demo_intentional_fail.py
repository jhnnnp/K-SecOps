#!/usr/bin/env python3
"""Local proof: simulate CI gate FAIL when a secret appears outside dummy-infra/."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tools.models import (
    AuditAwsResult,
    AuditSastResult,
    AuditSecretsResult,
    ScanDependenciesResult,
    ScanInfrastructureResult,
    SecretFinding,
    summarize_findings,
)


def main() -> int:
    # Load gate evaluator from ci_gate without running full scan
    import importlib.util

    spec = importlib.util.spec_from_file_location("ci_gate", ROOT / "scripts" / "ci_gate.py")
    ci_gate = importlib.util.module_from_spec(spec)
    sys.modules["ci_gate"] = ci_gate
    assert spec.loader is not None
    spec.loader.exec_module(ci_gate)

    baseline = ci_gate._load_baseline()
    gate = ci_gate.GateResult()

    secrets = AuditSecretsResult(
        findings=[
            SecretFinding(
                id="SECRET-DEMO",
                secret_type="AWS Access Key ID",
                resource="src/main.py",
                line=1,
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
    deps = ScanDependenciesResult(
        findings=[],
        summary=summarize_findings([]),
        errors=[],
        target_path="none",
    )
    sast = AuditSastResult(findings=[], files_scanned=0, target_path=".")

    ci_gate._evaluate_gate(gate, baseline, scan, secrets, aws, deps, sast)

    print("== Intentional Fail Demo (local simulation) ==")
    print(f"Gate passed: {gate.passed}")
    for reason in gate.reasons:
        print(f"  - {reason}")

    if gate.passed:
        print("ERROR: expected FAILED when secret is in src/")
        return 1

    print("\nOK: gate correctly blocks secrets in application code.")
    print("Next: push a PR with AWS docs example key in src/main.py (see docs/CI_EVIDENCE.md).")
    print("Guide: docs/CI_EVIDENCE.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
