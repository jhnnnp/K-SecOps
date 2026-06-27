from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class Finding(BaseModel):
    id: str
    severity: Severity
    resource: str
    title: str
    description: str
    scanner: str
    finding_type: str | None = None
    line: int | None = None


class ScannerError(BaseModel):
    scanner: str
    message: str


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanInfrastructureResult(BaseModel):
    findings: list[Finding]
    summary: ScanSummary
    errors: list[ScannerError] = Field(default_factory=list)
    target_path: str
    scanners_run: list[str] = Field(default_factory=list)


class SecretFinding(BaseModel):
    id: str
    secret_type: str
    resource: str
    line: int
    secret_prefix: str
    severity: Severity = "CRITICAL"
    finding_type: str


class AuditSecretsResult(BaseModel):
    findings: list[SecretFinding]
    files_scanned: int
    target_path: str


class SastFinding(BaseModel):
    id: str
    finding_type: str
    resource: str
    line: int
    severity: Severity
    title: str
    description: str


class AuditSastResult(BaseModel):
    findings: list[SastFinding]
    files_scanned: int
    target_path: str
    engine: str = "regex"
    errors: list[ScannerError] = Field(default_factory=list)


class ScanDependenciesResult(BaseModel):
    findings: list[Finding]
    summary: ScanSummary
    errors: list[ScannerError] = Field(default_factory=list)
    target_path: str


class AwsFinding(BaseModel):
    id: str
    finding_type: str
    resource: str
    line: int | None = None
    title: str
    description: str
    severity: Severity
    source: str = "local"


class AuditAwsResult(BaseModel):
    findings: list[AwsFinding]
    target_path: str
    live_scan: bool = False
    errors: list[str] = Field(default_factory=list)


class ComplianceViolation(BaseModel):
    violation_id: str
    finding_type: str
    severity: Severity
    resource: str
    scanner: str
    control_id: str
    framework: str
    control_title: str
    category: str
    checklist_question: str
    compliance_status: str
    deficiency_reason: str
    deficiency_detail: str
    recommended_action: str
    action_priority: str
    evidence_required: str
    tool_reference: str
    source_finding_id: str | None = None


class ReportSummary(BaseModel):
    critical: int = 0
    high: int = 0
    non_compliant_controls: int = 0
    immediate_actions: int = 0
    total_violations: int = 0


class NormalizedInput(BaseModel):
    target_path: str
    scan_findings: list[Finding] = Field(default_factory=list)
    scan_summary: ScanSummary | None = None
    scanners_run: list[str] = Field(default_factory=list)
    secret_findings: list[SecretFinding] = Field(default_factory=list)
    sast_findings: list[SastFinding] = Field(default_factory=list)
    dependency_findings: list[Finding] = Field(default_factory=list)
    aws_findings: list[AwsFinding] = Field(default_factory=list)
    pii_findings: list[dict] = Field(default_factory=list)
    pii_resource: str | None = None


class GenerateComplianceReportResult(BaseModel):
    report_path: str
    violations: list[ComplianceViolation]
    summary: ReportSummary
    target_path: str


def summarize_findings(findings: list[Finding]) -> ScanSummary:
    summary = ScanSummary()
    for finding in findings:
        severity = finding.severity.lower()
        if severity == "critical":
            summary.critical += 1
        elif severity == "high":
            summary.high += 1
        elif severity == "medium":
            summary.medium += 1
        elif severity == "low":
            summary.low += 1
        else:
            summary.info += 1
    return summary
