"""Static HTML executive dashboard for DevSecOps gate results (Tailwind CDN, single file)."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from tools.models import (
    AuditAwsResult,
    AuditSastResult,
    AuditSecretsResult,
    ComplianceViolation,
    Finding,
    ReportSummary,
    ScanDependenciesResult,
    ScanInfrastructureResult,
)
from tools.risk_score import RiskScoreBreakdown, RiskScoreResult
from tools.sbom_gate import SbomDriftFinding, SbomGateResult

FIXTURE_PREFIX = "dummy-infra/"
DEPS_FIXTURE_PREFIX = "dummy-infra/deps/"
BASELINE_SAMPLE_LIMIT = 24


@dataclass
class DashboardRow:
    track: str
    severity: str
    finding_type: str
    resource: str
    detail: str
    zone: str  # blocker | baseline


@dataclass
class ComplianceRow:
    control_id: str
    framework: str
    title: str
    category: str
    count: int
    max_severity: str


@dataclass
class DashboardContext:
    passed: bool
    generated_at: str
    target_path: str
    risk: RiskScoreResult
    report_summary: ReportSummary
    gate_reasons: list[str]
    blockers: list[DashboardRow] = field(default_factory=list)
    baseline: list[DashboardRow] = field(default_factory=list)
    compliance: list[ComplianceRow] = field(default_factory=list)
    scan_totals: dict[str, int] = field(default_factory=dict)
    sbom_drift: SbomGateResult | None = None
    repository: str = ""
    ref: str = ""


def build_dashboard_context(
    *,
    passed: bool,
    target_path: str,
    risk: RiskScoreResult,
    report_summary: ReportSummary,
    gate_reasons: list[str],
    scan: ScanInfrastructureResult,
    secrets: AuditSecretsResult,
    sast: AuditSastResult,
    deps: ScanDependenciesResult,
    aws: AuditAwsResult,
    sbom_drift: SbomGateResult,
    violations: list[ComplianceViolation],
    repository: str = "",
    ref: str = "",
) -> DashboardContext:
    blockers: list[DashboardRow] = []
    baseline: list[DashboardRow] = []

    for item in secrets.findings:
        row = DashboardRow(
            track="Secrets",
            severity=item.severity,
            finding_type=item.finding_type,
            resource=item.resource,
            detail=f"line {item.line} ({item.secret_prefix}***)",
            zone="baseline" if item.resource.startswith(FIXTURE_PREFIX) else "blocker",
        )
        (baseline if row.zone == "baseline" else blockers).append(row)

    for item in sast.findings:
        row = DashboardRow(
            track="SAST",
            severity=item.severity,
            finding_type=item.finding_type,
            resource=item.resource,
            detail=f"line {item.line}: {item.title}",
            zone="baseline" if item.resource.startswith(FIXTURE_PREFIX) else "blocker",
        )
        (baseline if row.zone == "baseline" else blockers).append(row)

    for item in deps.findings:
        if item.severity not in {"CRITICAL", "HIGH"}:
            continue
        resource = item.resource.replace("\\", "/")
        in_fixture = resource.startswith(DEPS_FIXTURE_PREFIX) or resource.startswith(f"{FIXTURE_PREFIX}deps/")
        is_app = resource == "requirements.txt" or resource.endswith("/requirements.txt")
        zone = "blocker" if is_app and not in_fixture else "baseline"
        row = DashboardRow(
            track="SCA",
            severity=item.severity,
            finding_type=item.finding_type or "dependency.cve",
            resource=resource,
            detail=item.id,
            zone=zone,
        )
        (baseline if zone == "baseline" else blockers).append(row)

    for item in aws.findings:
        baseline.append(
            DashboardRow(
                track="AWS",
                severity=item.severity,
                finding_type=item.finding_type,
                resource=item.resource,
                detail=item.title,
                zone="baseline",
            )
        )

    for item in scan.findings:
        baseline.append(
            DashboardRow(
                track="Infra",
                severity=item.severity,
                finding_type=item.finding_type or item.id,
                resource=item.resource,
                detail=item.title,
                zone="baseline",
            )
        )

    for drift in sbom_drift.new_components:
        blockers.append(
            DashboardRow(
                track="SBOM",
                severity="CRITICAL",
                finding_type="sbom.unauthorized_dependency",
                resource=sbom_drift.manifest,
                detail=drift.component,
                zone="blocker",
            )
        )

    baseline.sort(key=lambda row: (_severity_rank(row.severity), row.track, row.resource))
    blockers.sort(key=lambda row: (_severity_rank(row.severity), row.track, row.resource))

    return DashboardContext(
        passed=passed,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        target_path=target_path,
        risk=risk,
        report_summary=report_summary,
        gate_reasons=gate_reasons,
        blockers=blockers,
        baseline=baseline[:BASELINE_SAMPLE_LIMIT],
        compliance=_summarize_compliance(violations),
        scan_totals={
            "infra": len(scan.findings),
            "secrets": len(secrets.findings),
            "sast": len(sast.findings),
            "sca": len([d for d in deps.findings if d.severity in {"CRITICAL", "HIGH"}]),
            "aws": len(aws.findings),
            "violations": report_summary.total_violations,
        },
        sbom_drift=sbom_drift,
        repository=repository,
        ref=ref,
    )


def render_secops_dashboard_html(ctx: DashboardContext) -> str:
    status_label = "PASSED: Safe to Merge" if ctx.passed else "FAILED: Merge Blocked"
    status_classes = (
        "bg-emerald-600/20 border-emerald-500 text-emerald-300"
        if ctx.passed
        else "bg-rose-600/20 border-rose-500 text-rose-200"
    )
    risk_color = _risk_bar_color(ctx.risk.score)
    gauge_offset = _gauge_stroke_offset(ctx.risk.score)

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>K-SecOps Dashboard — {html.escape(status_label)}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-slate-950 text-slate-100 antialiased">
  <div class="mx-auto max-w-6xl px-4 py-8 space-y-8">
    <header class="space-y-2">
      <p class="text-xs uppercase tracking-widest text-slate-500">Agentic K-SecOps · Executive Dashboard</p>
      <h1 class="text-2xl font-semibold text-white">DevSecOps Gate Visibility</h1>
      <p class="text-sm text-slate-400">Target <code class="text-slate-300">{html.escape(ctx.target_path)}</code> · {html.escape(ctx.generated_at)}</p>
    </header>

    <section class="rounded-2xl border-2 px-6 py-8 text-center {status_classes}">
      <p class="text-sm uppercase tracking-wider opacity-80">Gate Status</p>
      <p class="mt-2 text-3xl font-bold tracking-tight md:text-4xl">{html.escape(status_label)}</p>
      {_render_gate_reasons(ctx)}
    </section>

    <section class="grid gap-6 md:grid-cols-2">
      <div class="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <h2 class="text-lg font-semibold text-white">Composite Risk Score</h2>
        <p class="mt-1 text-sm text-slate-400">Application-path blockers only (fixtures excluded)</p>
        <div class="mt-6 flex flex-col items-center">
          <svg viewBox="0 0 120 70" class="h-32 w-48" aria-hidden="true">
            <path d="M 12 60 A 48 48 0 0 1 108 60" fill="none" stroke="#334155" stroke-width="10" stroke-linecap="round" />
            <path d="M 12 60 A 48 48 0 0 1 108 60" fill="none" stroke="{risk_color}" stroke-width="10" stroke-linecap="round"
              stroke-dasharray="150.8" stroke-dashoffset="{gauge_offset}" />
          </svg>
          <p class="text-4xl font-bold text-white">{ctx.risk.score}<span class="text-lg text-slate-500">/100</span></p>
          <p class="mt-1 text-sm font-medium text-slate-300">{html.escape(ctx.risk.level)} · {len(ctx.risk.blockers)} blocker(s)</p>
        </div>
        <div class="mt-4 h-2 w-full overflow-hidden rounded-full bg-slate-800">
          <div class="h-full rounded-full transition-all" style="width:{ctx.risk.score}%;background:{risk_color}"></div>
        </div>
      </div>

      <div class="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <h2 class="text-lg font-semibold text-white">Multi-Track Scan Totals</h2>
        <p class="mt-1 text-sm text-slate-400">Raw findings before gate baseline filtering</p>
        <dl class="mt-6 grid grid-cols-2 gap-4 text-sm">
          {_metric_cell("Infrastructure", ctx.scan_totals.get("infra", 0))}
          {_metric_cell("Secrets", ctx.scan_totals.get("secrets", 0))}
          {_metric_cell("SAST", ctx.scan_totals.get("sast", 0))}
          {_metric_cell("SCA (HIGH+)", ctx.scan_totals.get("sca", 0))}
          {_metric_cell("AWS", ctx.scan_totals.get("aws", 0))}
          {_metric_cell("Compliance rows", ctx.scan_totals.get("violations", 0))}
        </dl>
        {_render_sbom_status(ctx)}
      </div>
    </section>

    <section class="grid gap-6 lg:grid-cols-2">
      <div class="rounded-2xl border border-rose-900/50 bg-rose-950/20 p-6">
        <h2 class="text-lg font-semibold text-rose-200">Application Blockers (Strict)</h2>
        <p class="mt-1 text-sm text-rose-300/70">Findings outside <code>dummy-infra/</code> — merge gate targets</p>
        {_render_finding_table(ctx.blockers, empty_message="No application blockers detected.")}
      </div>

      <div class="rounded-2xl border border-amber-900/40 bg-amber-950/10 p-6">
        <h2 class="text-lg font-semibold text-amber-100">Baseline Fixtures (Allowed)</h2>
        <p class="mt-1 text-sm text-amber-200/60">Regression targets under <code>dummy-infra/</code> (sample {len(ctx.baseline)} shown)</p>
        {_render_finding_table(ctx.baseline, empty_message="No fixture findings in this run.", muted=True)}
      </div>
    </section>

    <section class="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
      <h2 class="text-lg font-semibold text-white">Compliance Mapping Summary</h2>
      <p class="mt-1 text-sm text-slate-400">ISMS-P · 전자금융감독규정 · 개보법 controls linked to findings</p>
      {_render_compliance_table(ctx.compliance)}
      <p class="mt-4 text-xs text-slate-500">Full Lab fields: see <code>reports/CI_AUDIT_REPORT.md</code> workflow artifact.</p>
    </section>

    <footer class="border-t border-slate-800 pt-4 text-xs text-slate-600">
      <p>Generated by <code>tools/dashboard_renderer.py</code> · Static HTML (Tailwind CDN) · No application server required.</p>
      {_render_meta(ctx)}
    </footer>
  </div>
</body>
</html>
"""


def write_secops_dashboard(
    output_path: str | Path,
    ctx: DashboardContext,
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_secops_dashboard_html(ctx), encoding="utf-8")
    return path


def write_dashboard_from_gate_payload(
    output_path: str | Path,
    gate_payload_path: str | Path,
    *,
    violations: list[ComplianceViolation] | None = None,
) -> Path | None:
    """Regenerate dashboard from GATE_RESULT.json plus optional compliance violations."""
    gate_path = Path(gate_payload_path)
    if not gate_path.is_file():
        return None
    payload = json.loads(gate_path.read_text(encoding="utf-8"))
    risk = RiskScoreResult(
        score=int(payload.get("risk_score", 0)),
        level=str(payload.get("risk_level", "LOW")),
        breakdown=RiskScoreBreakdown(),
        blockers=list(payload.get("risk_blockers", [])),
    )
    sbom_raw = payload.get("sbom_drift") or {}
    new_deps = [
        SbomDriftFinding(component=name, reason="unauthorized")
        for name in sbom_raw.get("new_dependencies", [])
    ]
    sbom = SbomGateResult(
        manifest="requirements.txt",
        allowed_count=0,
        current_count=0,
        new_components=new_deps,
        passed=bool(sbom_raw.get("passed", True)),
    )
    ctx = DashboardContext(
        passed=bool(payload.get("passed", False)),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        target_path=".",
        risk=risk,
        report_summary=ReportSummary(total_violations=len(violations or [])),
        gate_reasons=list(payload.get("reasons", [])),
        blockers=_blockers_from_reasons(payload.get("reasons", [])),
        baseline=[],
        compliance=_summarize_compliance(violations or []),
        repository=str(payload.get("repository", "")),
        ref=str(payload.get("ref", "")),
    )
    if sbom.new_components:
        for item in sbom.new_components:
            ctx.blockers.append(
                DashboardRow(
                    track="SBOM",
                    severity="CRITICAL",
                    finding_type="sbom.unauthorized_dependency",
                    resource=sbom.manifest,
                    detail=item.component,
                    zone="blocker",
                )
            )
    return write_secops_dashboard(output_path, ctx)


def _blockers_from_reasons(reasons: list[str]) -> list[DashboardRow]:
    rows: list[DashboardRow] = []
    for reason in reasons:
        rows.append(
            DashboardRow(
                track="Gate",
                severity="CRITICAL",
                finding_type="gate.reason",
                resource="ci_gate",
                detail=reason,
                zone="blocker",
            )
        )
    return rows


def _summarize_compliance(violations: list[ComplianceViolation]) -> list[ComplianceRow]:
    buckets: dict[str, ComplianceRow] = {}
    for item in violations:
        key = item.control_id
        if key not in buckets:
            buckets[key] = ComplianceRow(
                control_id=item.control_id,
                framework=item.framework,
                title=item.control_title,
                category=item.category,
                count=0,
                max_severity=item.severity,
            )
        row = buckets[key]
        row.count += 1
        if _severity_rank(item.severity) < _severity_rank(row.max_severity):
            row.max_severity = item.severity
    return sorted(buckets.values(), key=lambda row: (_severity_rank(row.max_severity), row.control_id))


def _severity_rank(severity: str) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return order.get(severity.upper(), 5)


def _risk_bar_color(score: int) -> str:
    if score >= 60:
        return "#f43f5e"
    if score >= 30:
        return "#f59e0b"
    if score > 0:
        return "#eab308"
    return "#10b981"


def _gauge_stroke_offset(score: int) -> str:
    clamped = max(0, min(100, score))
    return f"{150.8 * (1 - clamped / 100):.1f}"


def _metric_cell(label: str, value: int) -> str:
    return f"""<div class="rounded-lg bg-slate-800/80 px-3 py-2">
        <dt class="text-slate-500">{html.escape(label)}</dt>
        <dd class="text-xl font-semibold text-white">{value}</dd>
      </div>"""


def _render_gate_reasons(ctx: DashboardContext) -> str:
    if ctx.passed or not ctx.gate_reasons:
        return ""
    items = "".join(f"<li class='text-left text-sm'>{html.escape(r)}</li>" for r in ctx.gate_reasons[:6])
    extra = ""
    if len(ctx.gate_reasons) > 6:
        extra = f"<li class='text-left text-sm text-slate-400'>+ {len(ctx.gate_reasons) - 6} more (see CI summary)</li>"
    return f"<ul class='mx-auto mt-4 max-w-2xl list-disc space-y-1 pl-5 text-rose-100/90'>{items}{extra}</ul>"


def _render_sbom_status(ctx: DashboardContext) -> str:
    if ctx.sbom_drift is None:
        return ""
    status = "PASS" if ctx.sbom_drift.passed else "DRIFT"
    color = "text-emerald-400" if ctx.sbom_drift.passed else "text-rose-400"
    return (
        f"<p class='mt-4 text-sm text-slate-400'>SBOM drift: "
        f"<span class='font-medium {color}'>{status}</span> "
        f"({ctx.sbom_drift.current_count} direct deps / baseline {ctx.sbom_drift.allowed_count})</p>"
    )


def _render_finding_table(rows: list[DashboardRow], *, empty_message: str, muted: bool = False) -> str:
    if not rows:
        return f"<p class='mt-4 text-sm text-slate-500'>{html.escape(empty_message)}</p>"
    body = []
    row_class = "border-slate-800/80 text-slate-400" if muted else "border-slate-800 text-slate-200"
    for row in rows:
        body.append(
            f"<tr class='border-t {row_class}'>"
            f"<td class='py-2 pr-2 text-xs uppercase text-slate-500'>{html.escape(row.track)}</td>"
            f"<td class='py-2 pr-2'><span class='rounded px-1.5 py-0.5 text-xs font-medium {_severity_badge(row.severity)}'>{html.escape(row.severity)}</span></td>"
            f"<td class='py-2 pr-2 font-mono text-xs'>{html.escape(row.finding_type)}</td>"
            f"<td class='py-2 pr-2 text-xs break-all'>{html.escape(row.resource)}</td>"
            f"<td class='py-2 text-xs text-slate-500'>{html.escape(row.detail)}</td>"
            f"</tr>"
        )
    return f"""<div class="mt-4 overflow-x-auto">
      <table class="w-full text-left text-sm">
        <thead class="text-xs uppercase text-slate-500">
          <tr><th class="pb-2">Track</th><th class="pb-2">Sev</th><th class="pb-2">Type</th><th class="pb-2">Resource</th><th class="pb-2">Detail</th></tr>
        </thead>
        <tbody>{"".join(body)}</tbody>
      </table>
    </div>"""


def _severity_badge(severity: str) -> str:
    mapping = {
        "CRITICAL": "bg-rose-600/30 text-rose-200",
        "HIGH": "bg-orange-600/30 text-orange-200",
        "MEDIUM": "bg-amber-600/20 text-amber-200",
        "LOW": "bg-slate-700 text-slate-300",
    }
    return mapping.get(severity.upper(), "bg-slate-700 text-slate-300")


def _render_compliance_table(rows: list[ComplianceRow]) -> str:
    if not rows:
        return "<p class='mt-4 text-sm text-slate-500'>No compliance violations mapped in this run.</p>"
    body = []
    for row in rows:
        fw_class = "text-blue-300" if row.framework == "ISMS-P" else "text-orange-300"
        body.append(
            f"<tr class='border-t border-slate-800'>"
            f"<td class='py-2 pr-3 font-mono text-sm text-white'>{html.escape(row.control_id)}</td>"
            f"<td class='py-2 pr-3 text-sm {fw_class}'>{html.escape(row.framework)}</td>"
            f"<td class='py-2 pr-3 text-sm text-slate-200'>{html.escape(row.title)}</td>"
            f"<td class='py-2 pr-3 text-xs text-slate-500'>{html.escape(row.category)}</td>"
            f"<td class='py-2 pr-3'><span class='rounded px-1.5 py-0.5 text-xs {_severity_badge(row.max_severity)}'>{html.escape(row.max_severity)}</span></td>"
            f"<td class='py-2 text-sm text-slate-400'>{row.count}</td>"
            f"</tr>"
        )
    return f"""<div class="mt-4 overflow-x-auto">
      <table class="w-full text-left">
        <thead class="text-xs uppercase text-slate-500">
          <tr>
            <th class="pb-2">Control</th><th class="pb-2">Framework</th><th class="pb-2">Title</th>
            <th class="pb-2">Category</th><th class="pb-2">Max Sev</th><th class="pb-2">Findings</th>
          </tr>
        </thead>
        <tbody>{"".join(body)}</tbody>
      </table>
    </div>"""


def _render_meta(ctx: DashboardContext) -> str:
    parts = []
    if ctx.repository:
        parts.append(html.escape(ctx.repository))
    if ctx.ref:
        parts.append(html.escape(ctx.ref))
    if not parts:
        return ""
    return f"<p class='mt-1'>{' · '.join(parts)}</p>"
