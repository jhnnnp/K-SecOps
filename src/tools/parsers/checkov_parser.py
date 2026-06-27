from typing import Any

from tools.models import Finding
from tools.parsers.trivy_parser import _normalize_severity

CHECKOV_FINDING_TYPES: dict[str, str] = {
    # Official names: https://www.checkov.io/5.Policy%20Index/kubernetes.html
    "CKV_K8S_16": "k8s.privileged_container",
    "CKV_K8S_20": "k8s.allow_privilege_escalation",
    "CKV_K8S_23": "k8s.root_container",
    "CKV_K8S_28": "k8s.net_raw_capability",
    "CKV_K8S_29": "k8s.missing_security_context",
    "CKV_K8S_38": "k8s.automount_sa_token",
    "CKV_K8S_22": "k8s.read_only_rootfs",
    "CKV_AWS_20": "aws.s3_public_acl",
    "CKV_AWS_53": "aws.s3_block_public_acls",
    "CKV_DOCKER_3": "container.run_as_root",
    "CKV_DOCKER_2": "container.run_as_root",
}


def parse_checkov_report(payload: list[Any] | dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    reports = payload if isinstance(payload, list) else [payload]

    for report in reports:
        if not isinstance(report, dict):
            continue
        failed_checks = (report.get("results") or {}).get("failed_checks") or []
        for check in failed_checks:
            check_id = check.get("check_id", "CHECKOV-UNKNOWN")
            file_path = (check.get("file_path") or check.get("repo_file_path") or "unknown").replace("\\", "/")
            line_range = check.get("file_line_range") or []
            line = int(line_range[0]) if line_range else None
            findings.append(
                Finding(
                    id=check_id,
                    severity=_checkov_severity(check),
                    resource=file_path,
                    title=check.get("check_name") or check_id,
                    description=check.get("guideline") or check.get("check_result", {}).get("entity", ""),
                    scanner="checkov",
                    finding_type=CHECKOV_FINDING_TYPES.get(check_id),
                    line=line,
                )
            )
    return findings


def _checkov_severity(check: dict[str, Any]) -> str:
    explicit = check.get("severity")
    if explicit:
        return _normalize_severity(str(explicit))

    check_id = check.get("check_id", "")
    high_ids = {
        "CKV_K8S_16",
        "CKV_K8S_20",
        "CKV_K8S_23",
        "CKV_K8S_28",
        "CKV_K8S_29",
        "CKV_K8S_38",
        "CKV_DOCKER_2",
        "CKV_DOCKER_3",
    }
    if check_id in high_ids:
        return "HIGH"
    return "MEDIUM"
