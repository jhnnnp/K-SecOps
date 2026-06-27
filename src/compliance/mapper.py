from __future__ import annotations

from compliance.loader import get_control, get_rule
from tools.models import AuditAwsResult, AwsFinding, ComplianceViolation, NormalizedInput

PII_ENTITY_TO_FINDING_TYPE: dict[str, str] = {
    "KR_RRN": "pii.korean_rrn",
    "ACCOUNT": "pii.account_number",
    "KR_PHONE": "pii.korean_rrn",
    "EMAIL": "pii.korean_rrn",
}

FINDING_TYPE_ALIASES: dict[str, str] = {
    "secret.aws_secret_key": "secret.aws_access_key",
}

REPORTABLE_SEVERITIES = {"CRITICAL", "HIGH"}


def build_violations(inputs: NormalizedInput) -> list[ComplianceViolation]:
    violations: list[ComplianceViolation] = []

    for secret in inputs.secret_findings:
        finding_type = FINDING_TYPE_ALIASES.get(secret.finding_type, secret.finding_type)
        context = {
            "resource": secret.resource,
            "line": secret.line,
            "secret_prefix": secret.secret_prefix,
            "count": 1,
        }
        violations.extend(
            _violations_from_rule(
                finding_type=finding_type,
                severity=secret.severity,
                resource=secret.resource,
                scanner="audit_secrets",
                source_finding_id=secret.id,
                context=context,
            )
        )

    for aws_finding in inputs.aws_findings:
        context = {
            "resource": aws_finding.resource,
            "line": aws_finding.line or "",
            "count": 1,
        }
        violations.extend(
            _violations_from_rule(
                finding_type=aws_finding.finding_type,
                severity=aws_finding.severity,
                resource=aws_finding.resource,
                scanner="audit_aws",
                source_finding_id=aws_finding.id,
                context=context,
            )
        )

    if inputs.pii_findings:
        resource = inputs.pii_resource or inputs.target_path
        for pii in inputs.pii_findings:
            finding_type = PII_ENTITY_TO_FINDING_TYPE.get(pii["type"])
            if not finding_type:
                continue
            context = {
                "resource": resource,
                "count": pii.get("count", 1),
                "entity_type": pii["type"],
            }
            violations.extend(
                _violations_from_rule(
                    finding_type=finding_type,
                    severity="HIGH",
                    resource=resource,
                    scanner="mask_pii",
                    source_finding_id=f"PII-{pii['type']}",
                    context=context,
                )
            )

    for finding in inputs.scan_findings:
        if not finding.finding_type:
            continue
        if finding.severity not in REPORTABLE_SEVERITIES:
            continue
        cve_id = finding.id.replace("TRIVY-", "") if "CVE" in finding.id else finding.id
        context = {
            "resource": finding.resource,
            "line": finding.line or "",
            "cve_id": cve_id,
            "count": 1,
        }
        violations.extend(
            _violations_from_rule(
                finding_type=finding.finding_type,
                severity=finding.severity,
                resource=finding.resource,
                scanner=finding.scanner,
                source_finding_id=finding.id,
                context=context,
            )
        )

    deduped = _dedupe_violations(violations)
    for index, violation in enumerate(deduped, start=1):
        violation.violation_id = f"F-{index:03d}"
    return deduped


def _violations_from_rule(
    *,
    finding_type: str,
    severity: str,
    resource: str,
    scanner: str,
    source_finding_id: str,
    context: dict[str, object],
) -> list[ComplianceViolation]:
    rule = get_rule(finding_type)
    if rule is None:
        return []

    violations: list[ComplianceViolation] = []
    for control_entry in rule["controls"]:
        control_id = control_entry["control_id"]
        control = get_control(control_id)
        if control is None:
            continue

        deficiency = control_entry["deficiency"]
        violations.append(
            ComplianceViolation(
                violation_id="F-000",
                finding_type=finding_type,
                severity=severity,
                resource=resource,
                scanner=scanner,
                control_id=control_id,
                framework=control["framework"],
                control_title=control["title"],
                category=control["category"],
                checklist_question=control["checklist_question"],
                compliance_status=deficiency["compliance_status"],
                deficiency_reason=deficiency["deficiency_reason"],
                deficiency_detail=_render_template(deficiency["deficiency_detail_template"], context),
                recommended_action=_render_template(deficiency["recommended_action"], context),
                action_priority=deficiency["action_priority"],
                evidence_required=deficiency["evidence_required"],
                tool_reference=deficiency.get("tool_reference", ""),
                source_finding_id=source_finding_id,
            )
        )
    return violations


def _render_template(template: str, context: dict[str, object]) -> str:
    rendered = template
    for key, value in context.items():
        rendered = rendered.replace(f"{{{key}}}", str(value))
    return rendered


def _dedupe_violations(violations: list[ComplianceViolation]) -> list[ComplianceViolation]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[ComplianceViolation] = []
    for violation in violations:
        key = (violation.control_id, violation.resource, violation.deficiency_reason)
        if key in seen:
            continue
        seen.add(key)
        unique.append(violation)
    return unique
