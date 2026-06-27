from __future__ import annotations

from pydantic import BaseModel, Field

from tools.models import AuditAwsResult, AuditSastResult, AuditSecretsResult, ScanDependenciesResult, ScanInfrastructureResult

SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

TRACK_WEIGHTS = {
    "secrets_app": 15,
    "sast_app": 12,
    "sca_app": 10,
    "infra_critical": 8,
    "aws": 8,
    "sbom_drift": 10,
}


class RiskScoreBreakdown(BaseModel):
    secrets_app: int = 0
    sast_app: int = 0
    sca_app: int = 0
    infra_critical: int = 0
    aws_unbaseline: int = 0
    sbom_drift: int = 0


class RiskScoreResult(BaseModel):
    score: int
    max_score: int = 100
    level: str
    breakdown: RiskScoreBreakdown
    blockers: list[str] = Field(default_factory=list)


def compute_risk_score(
    *,
    secrets: AuditSecretsResult,
    sast: AuditSastResult,
    deps: ScanDependenciesResult,
    scan: ScanInfrastructureResult,
    aws: AuditAwsResult,
    sbom_new_count: int = 0,
    sast_fixture_prefix: str = "dummy-infra/",
    deps_fixture_prefix: str = "dummy-infra/deps/",
) -> RiskScoreResult:
    breakdown = RiskScoreBreakdown()
    blockers: list[str] = []

    for item in secrets.findings:
        if item.resource.startswith("dummy-infra/"):
            continue
        breakdown.secrets_app += SEVERITY_WEIGHTS.get(item.severity, 5)
        blockers.append(f"secret:{item.resource}:{item.line}")

    for item in sast.findings:
        if item.resource.startswith(sast_fixture_prefix):
            continue
        breakdown.sast_app += SEVERITY_WEIGHTS.get(item.severity, 5)
        blockers.append(f"sast:{item.resource}:{item.line}")

    for item in deps.findings:
        if item.severity not in {"CRITICAL", "HIGH"}:
            continue
        if item.resource.replace("\\", "/") != "requirements.txt":
            continue
        breakdown.sca_app += SEVERITY_WEIGHTS.get(item.severity, 5)
        blockers.append(f"sca:{item.id}")

    for item in scan.findings:
        if item.severity != "CRITICAL":
            continue
        if not item.resource.startswith("dummy-infra/"):
            breakdown.infra_critical += 1

    for item in aws.findings:
        breakdown.aws_unbaseline += 1

    if sbom_new_count:
        breakdown.sbom_drift = sbom_new_count
        blockers.append(f"sbom:unauthorized_deps={sbom_new_count}")

    if not blockers:
        return RiskScoreResult(score=0, level="LOW", breakdown=breakdown, blockers=[])

    raw = (
        breakdown.secrets_app * TRACK_WEIGHTS["secrets_app"]
        + breakdown.sast_app * TRACK_WEIGHTS["sast_app"]
        + breakdown.sca_app * TRACK_WEIGHTS["sca_app"]
        + breakdown.sbom_drift * TRACK_WEIGHTS["sbom_drift"]
    )
    score = min(100, max(10, raw))

    if score >= 60 or blockers:
        level = "CRITICAL"
    elif score >= 30:
        level = "HIGH"
    elif score >= 10:
        level = "MEDIUM"
    else:
        level = "LOW"

    return RiskScoreResult(score=score, level=level, breakdown=breakdown, blockers=blockers)
