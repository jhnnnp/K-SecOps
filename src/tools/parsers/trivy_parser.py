from typing import Any

from tools.models import Finding

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def parse_trivy_report(payload: dict[str, Any], project_root_prefix: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for result in payload.get("Results") or []:
        target = _normalize_resource(result.get("Target", "unknown"), project_root_prefix)
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(
                Finding(
                    id=f"TRIVY-{vuln.get('VulnerabilityID', 'UNKNOWN')}",
                    severity=_normalize_severity(vuln.get("Severity", "UNKNOWN")),
                    resource=target,
                    title=vuln.get("Title") or vuln.get("VulnerabilityID", "Unknown vulnerability"),
                    description=vuln.get("Description") or "",
                    scanner="trivy",
                    finding_type="container.critical_cve"
                    if _normalize_severity(vuln.get("Severity", "")) in {"CRITICAL", "HIGH"}
                    else None,
                )
            )
        for misconfig in result.get("Misconfigurations") or []:
            check_id = misconfig.get("ID", "MISCONFIG")
            findings.append(
                Finding(
                    id=f"TRIVY-{check_id}",
                    severity=_normalize_severity(misconfig.get("Severity", "MEDIUM")),
                    resource=target,
                    title=misconfig.get("Title") or check_id,
                    description=misconfig.get("Description") or "",
                    scanner="trivy",
                    finding_type=_map_trivy_misconfig_type(check_id, misconfig.get("Title", "")),
                    line=_first_line(misconfig.get("CauseMetadata")),
                )
            )
        for secret in result.get("Secrets") or []:
            rule_id = secret.get("RuleID", "SECRET")
            findings.append(
                Finding(
                    id=f"TRIVY-SECRET-{rule_id}",
                    severity="CRITICAL",
                    resource=target,
                    title=secret.get("Title") or "Hardcoded secret detected",
                    description=secret.get("Match") or "",
                    scanner="trivy",
                    finding_type=_map_secret_type(rule_id, secret.get("Category", "")),
                    line=_first_line(secret.get("CauseMetadata")),
                )
            )
    return findings


def _map_trivy_misconfig_type(check_id: str, title: str) -> str | None:
    title_lower = title.lower()
    if "privileged" in title_lower:
        return "k8s.privileged_container"
    if "root" in title_lower:
        return "container.run_as_root"
    return None


def _map_secret_type(rule_id: str, category: str) -> str:
    combined = f"{rule_id} {category}".lower()
    if "aws" in combined and "access" in combined:
        return "secret.aws_access_key"
    if "api" in combined:
        return "secret.api_key"
    return "secret.api_key"


def _first_line(cause_metadata: dict[str, Any] | None) -> int | None:
    if not cause_metadata:
        return None
    start_line = cause_metadata.get("StartLine")
    return int(start_line) if start_line is not None else None


def _normalize_resource(target: str, prefix: str) -> str:
    if prefix and target.startswith(prefix):
        return target[len(prefix) :].lstrip("/")
    return target.replace("\\", "/")


def _normalize_severity(value: str) -> str:
    normalized = (value or "INFO").upper()
    if normalized in SEVERITY_ORDER:
        return normalized
    if normalized == "UNKNOWN":
        return "MEDIUM"
    return "INFO"
