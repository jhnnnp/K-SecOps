#!/usr/bin/env python3
"""One-shot demo: scan dummy-infra and generate compliance report."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tools.aws_auditor import audit_aws_config  # noqa: E402
from tools.secret_auditor import audit_secrets  # noqa: E402
from tools.compliance_report import generate_compliance_report  # noqa: E402
from tools.scan_infra import scan_infrastructure  # noqa: E402


def main() -> int:
    target = "dummy-infra"
    output = "reports/SAMPLE_AUDIT_REPORT.md"

    print("== Agentic K-SecOps Demo ==")
    print(f"Target: {target}")
    print()

    scan = scan_infrastructure(target)
    print(f"[scan_infrastructure] findings={len(scan.findings)} errors={len(scan.errors)}")
    print(f"  critical={scan.summary.critical} high={scan.summary.high}")

    secrets = audit_secrets(target)
    print(f"[audit_secrets] findings={len(secrets.findings)} files={secrets.files_scanned}")

    aws = audit_aws_config(target)
    print(f"[audit_aws] findings={len(aws.findings)} live={aws.live_scan}")

    report = generate_compliance_report(
        target_path=target,
        output_path=output,
        scan_result=scan.model_dump(),
        secrets_result=secrets.model_dump(),
        aws_result=aws.model_dump(),
        auto_collect=True,
    )
    print(f"[generate_compliance_report] violations={report.summary.total_violations}")
    print(f"  controls={report.summary.non_compliant_controls} immediate={report.summary.immediate_actions}")
    print()
    print(f"Report written: {report.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
