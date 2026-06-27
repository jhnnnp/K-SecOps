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
    ReportSummary,
    ScanDependenciesResult,
    ScanInfrastructureResult,
)
from tools.risk_score import RiskScoreBreakdown, RiskScoreResult
from tools.sbom_gate import SbomDriftFinding, SbomGateResult

FIXTURE_PREFIX = "dummy-infra/"
DEPS_FIXTURE_PREFIX = "dummy-infra/deps/"
BASELINE_SAMPLE_LIMIT = 40

TRACK_LABELS = {
    "Secrets": "시크릿",
    "SAST": "정적분석",
    "SCA": "의존성 CVE",
    "Infra": "인프라",
    "AWS": "AWS 설정",
    "SBOM": "SBOM",
    "Gate": "게이트",
}

SEVERITY_LABELS = {
    "CRITICAL": "치명",
    "HIGH": "높음",
    "MEDIUM": "중간",
    "LOW": "낮음",
    "INFO": "정보",
}

RISK_LEVEL_LABELS = {
    "LOW": "낮음",
    "MEDIUM": "중간",
    "HIGH": "높음",
    "CRITICAL": "치명",
}


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
    baseline_total: int = 0
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
        row = _make_row(
            track="Secrets",
            severity=item.severity,
            finding_type=item.finding_type,
            resource=item.resource,
            detail=f"{item.line}행 ({item.secret_prefix}***)",
            in_fixture=item.resource.startswith(FIXTURE_PREFIX),
        )
        (baseline if row.zone == "baseline" else blockers).append(row)

    for item in sast.findings:
        row = _make_row(
            track="SAST",
            severity=item.severity,
            finding_type=item.finding_type,
            resource=item.resource,
            detail=f"{item.line}행: {item.title}",
            in_fixture=item.resource.startswith(FIXTURE_PREFIX),
        )
        (baseline if row.zone == "baseline" else blockers).append(row)

    for item in deps.findings:
        if item.severity not in {"CRITICAL", "HIGH"}:
            continue
        resource = _normalize_resource_path(item.resource)
        in_fixture = resource.startswith(DEPS_FIXTURE_PREFIX) or "/deps/" in resource
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
            _make_row(
                track="AWS",
                severity=item.severity,
                finding_type=item.finding_type,
                resource=item.resource,
                detail=item.title,
                in_fixture=True,
            )
        )

    for item in scan.findings:
        baseline.append(
            _make_row(
                track="Infra",
                severity=item.severity,
                finding_type=item.finding_type or item.id,
                resource=item.resource,
                detail=item.title,
                in_fixture=True,
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
    baseline_total = len(baseline)

    return DashboardContext(
        passed=passed,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        target_path=target_path,
        risk=risk,
        report_summary=report_summary,
        gate_reasons=gate_reasons,
        blockers=blockers,
        baseline=baseline[:BASELINE_SAMPLE_LIMIT],
        baseline_total=baseline_total,
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


def _make_row(
    *,
    track: str,
    severity: str,
    finding_type: str,
    resource: str,
    detail: str,
    in_fixture: bool,
) -> DashboardRow:
    return DashboardRow(
        track=track,
        severity=severity,
        finding_type=finding_type,
        resource=_normalize_resource_path(resource),
        detail=detail,
        zone="baseline" if in_fixture else "blocker",
    )


def _normalize_resource_path(resource: str) -> str:
    normalized = resource.replace("\\", "/")
    marker = "dummy-infra/"
    if marker in normalized:
        return normalized[normalized.find(marker) :]
    if normalized.startswith("/") or "/Users/" in normalized:
        parts = normalized.strip("/").split("/")
        if parts:
            name = parts[-1]
            if len(parts) >= 2 and parts[-2] in {"docker", "k8s", "terraform", "aws", "code", "deps", "logs"}:
                return f"{parts[-2]}/{name}"
            if name == "Dockerfile":
                return name
            return name
    if normalized.startswith(FIXTURE_PREFIX):
        return normalized
    if normalized.startswith(".env") or normalized in {"Dockerfile", "requirements.txt"}:
        return f"{FIXTURE_PREFIX}{normalized.lstrip('/')}"
    return normalized


def render_secops_dashboard_html(ctx: DashboardContext) -> str:
    if ctx.passed:
        status_label = "통과 — Merge 가능"
        status_hint = "앱 코드(src/, requirements.txt)에 차단 대상 없음"
    else:
        status_label = "실패 — Merge 차단"
        status_hint = "아래 <strong>앱 코드 차단</strong> 항목을 먼저 해결하세요"

    status_classes = (
        "bg-emerald-600/20 border-emerald-500 text-emerald-300"
        if ctx.passed
        else "bg-rose-600/20 border-rose-500 text-rose-200"
    )
    risk_color = _risk_bar_color(ctx.risk.score)
    gauge_offset = _gauge_stroke_offset(ctx.risk.score)
    risk_level_ko = RISK_LEVEL_LABELS.get(ctx.risk.level.upper(), ctx.risk.level)
    total_detected = sum(ctx.scan_totals.values()) - ctx.scan_totals.get("violations", 0)

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>K-SecOps 보안 대시보드 — {html.escape(status_label)}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-slate-950 text-slate-100 antialiased">
  <div class="mx-auto max-w-6xl px-4 py-8 space-y-8">
    <header class="space-y-2">
      <p class="text-xs tracking-widest text-slate-500">Agentic K-SecOps · 경영진/감사용 대시보드</p>
      <h1 class="text-2xl font-semibold text-white">DevSecOps 게이트 가시화</h1>
      <p class="text-sm text-slate-400">스캔 대상 <code class="text-slate-300">{html.escape(ctx.target_path)}</code> · {html.escape(ctx.generated_at)}</p>
    </header>

    <section class="rounded-2xl border-2 px-6 py-8 text-center {status_classes}">
      <p class="text-sm tracking-wider opacity-80">게이트 판정</p>
      <p class="mt-2 text-3xl font-bold tracking-tight md:text-4xl">{html.escape(status_label)}</p>
      <p class="mt-3 text-sm opacity-90">{status_hint}</p>
      {_render_gate_reasons(ctx)}
    </section>

    {_render_verdict_summary(ctx, total_detected)}

    <section class="rounded-xl border border-sky-900/40 bg-sky-950/20 px-5 py-4 text-sm text-sky-100/90">
      <p class="font-medium text-sky-200">왜 탐지는 많은데 통과인가요?</p>
      <p class="mt-1 leading-relaxed text-sky-100/80">
        이 파이프라인은 <strong>이중 게이트</strong>입니다.
        <code class="text-sky-200">dummy-infra/</code>의 취약점은 회귀 테스트 픽스처로
        <span class="text-amber-300">리포트·대시보드에 기록</span>되지만 merge는 막지 않습니다.
        <code class="text-sky-200">src/</code>·<code class="text-sky-200">requirements.txt</code>만
        <span class="text-rose-300">실제 차단</span> 대상입니다.
      </p>
    </section>

    <section class="grid gap-6 md:grid-cols-2">
      <div class="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <h2 class="text-lg font-semibold text-white">복합 위험 점수</h2>
        <p class="mt-1 text-sm text-slate-400">앱 코드 차단만 반영 (픽스처 제외)</p>
        <div class="mt-6 flex flex-col items-center">
          <svg viewBox="0 0 120 70" class="h-32 w-48" aria-hidden="true">
            <path d="M 12 60 A 48 48 0 0 1 108 60" fill="none" stroke="#334155" stroke-width="10" stroke-linecap="round" />
            <path d="M 12 60 A 48 48 0 0 1 108 60" fill="none" stroke="{risk_color}" stroke-width="10" stroke-linecap="round"
              stroke-dasharray="150.8" stroke-dashoffset="{gauge_offset}" />
          </svg>
          <p class="text-4xl font-bold text-white">{ctx.risk.score}<span class="text-lg text-slate-500">/100</span></p>
          <p class="mt-1 text-sm font-medium text-slate-300">{html.escape(risk_level_ko)} · 차단 {len(ctx.risk.blockers)}건</p>
        </div>
        <div class="mt-4 h-2 w-full overflow-hidden rounded-full bg-slate-800">
          <div class="h-full rounded-full transition-all" style="width:{ctx.risk.score}%;background:{risk_color}"></div>
        </div>
      </div>

      <div class="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <h2 class="text-lg font-semibold text-white">6트랙 스캔 집계</h2>
        <p class="mt-1 text-sm text-slate-400">게이트 필터 적용 전 원시 탐지 건수</p>
        <dl class="mt-6 grid grid-cols-2 gap-4 text-sm">
          {_metric_cell("인프라", ctx.scan_totals.get("infra", 0))}
          {_metric_cell("시크릿", ctx.scan_totals.get("secrets", 0))}
          {_metric_cell("정적분석(SAST)", ctx.scan_totals.get("sast", 0))}
          {_metric_cell("의존성 CVE", ctx.scan_totals.get("sca", 0))}
          {_metric_cell("AWS", ctx.scan_totals.get("aws", 0))}
          {_metric_cell("규정 매핑", ctx.scan_totals.get("violations", 0))}
        </dl>
        {_render_sbom_status(ctx)}
      </div>
    </section>

    <section class="grid gap-6 lg:grid-cols-2">
      <div class="rounded-2xl border border-rose-900/50 bg-rose-950/20 p-6">
        <div class="flex items-center justify-between gap-2">
          <h2 class="text-lg font-semibold text-rose-200">앱 코드 차단 (Strict)</h2>
          <span class="rounded-full bg-rose-600/30 px-3 py-0.5 text-sm font-semibold text-rose-200">{len(ctx.blockers)}건</span>
        </div>
        <p class="mt-1 text-sm text-rose-300/70"><code>dummy-infra/</code> 밖 — PR merge를 막는 항목</p>
        {_render_finding_table(ctx.blockers, empty_message="앱 코드 차단 항목 없음 — merge 조건 충족")}
      </div>

      <div class="rounded-2xl border border-amber-900/40 bg-amber-950/10 p-6">
        <div class="flex items-center justify-between gap-2">
          <h2 class="text-lg font-semibold text-amber-100">픽스처 허용 (Baseline)</h2>
          <span class="rounded-full bg-amber-600/20 px-3 py-0.5 text-sm font-semibold text-amber-200">{ctx.baseline_total}건</span>
        </div>
        <p class="mt-1 text-sm text-amber-200/60">
          <code>dummy-infra/</code> 의도적 취약점 — 탐지·리포트 O, merge X
          {_baseline_sample_note(ctx)}
        </p>
        {_render_finding_table(ctx.baseline, empty_message="픽스처 탐지 없음", muted=True)}
      </div>
    </section>

    <section class="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
      <div class="flex items-center justify-between gap-2">
        <h2 class="text-lg font-semibold text-white">규정 매핑 요약</h2>
        <span class="text-sm text-slate-400">{len(ctx.compliance)}개 통제 · {ctx.scan_totals.get('violations', 0)}건 위반</span>
      </div>
      <p class="mt-1 text-sm text-slate-400">ISMS-P · 전자금융감독규정 · 개인정보보호법</p>
      {_render_compliance_table(ctx.compliance)}
      <p class="mt-4 text-xs text-slate-500">상세 결함·권고 조치: <code>reports/CI_AUDIT_REPORT.md</code> (CI 아티팩트)</p>
    </section>

    <footer class="border-t border-slate-800 pt-4 text-xs text-slate-600">
      <p><code>tools/dashboard_renderer.py</code> 생성 · 정적 HTML (Tailwind CDN) · 웹서버 불필요</p>
      {_render_meta(ctx)}
    </footer>
  </div>
</body>
</html>
"""


def _render_verdict_summary(ctx: DashboardContext, total_detected: int) -> str:
    return f"""<section class="grid gap-4 sm:grid-cols-3">
      <div class="rounded-xl border border-slate-700 bg-slate-900/80 p-4 text-center">
        <p class="text-xs text-slate-500">전체 스캔 탐지</p>
        <p class="mt-1 text-3xl font-bold text-white">{total_detected}</p>
        <p class="mt-1 text-xs text-slate-500">6트랙 합계 (규정행 제외)</p>
      </div>
      <div class="rounded-xl border border-rose-800/60 bg-rose-950/30 p-4 text-center">
        <p class="text-xs text-rose-400">Merge 차단</p>
        <p class="mt-1 text-3xl font-bold text-rose-200">{len(ctx.blockers)}</p>
        <p class="mt-1 text-xs text-rose-400/80">앱 코드·SBOM drift</p>
      </div>
      <div class="rounded-xl border border-amber-800/50 bg-amber-950/20 p-4 text-center">
        <p class="text-xs text-amber-400">픽스처 허용</p>
        <p class="mt-1 text-3xl font-bold text-amber-100">{ctx.baseline_total}</p>
        <p class="mt-1 text-xs text-amber-400/80">dummy-infra 회귀 테스트</p>
      </div>
    </section>"""


def _baseline_sample_note(ctx: DashboardContext) -> str:
    if ctx.baseline_total <= len(ctx.baseline):
        return ""
    return f" · 아래 {len(ctx.baseline)}건 표시 (전체 {ctx.baseline_total}건, 스크롤)"


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
        baseline_total=0,
        compliance=_summarize_compliance(violations or []),
        repository=str(payload.get("repository", "")),
        ref=str(payload.get("ref", "")),
        sbom_drift=sbom,
    )
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
    return [
        DashboardRow(
            track="Gate",
            severity="CRITICAL",
            finding_type="gate.reason",
            resource="ci_gate",
            detail=reason,
            zone="blocker",
        )
        for reason in reasons
    ]


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
    items = "".join(f"<li class='text-left text-sm'>{html.escape(r)}</li>" for r in ctx.gate_reasons[:8])
    extra = ""
    if len(ctx.gate_reasons) > 8:
        extra = f"<li class='text-left text-sm text-slate-400'>외 {len(ctx.gate_reasons) - 8}건 (CI_SUMMARY 참고)</li>"
    return f"<ul class='mx-auto mt-4 max-w-2xl list-disc space-y-1 pl-5 text-rose-100/90'>{items}{extra}</ul>"


def _render_sbom_status(ctx: DashboardContext) -> str:
    if ctx.sbom_drift is None:
        return ""
    status = "통과" if ctx.sbom_drift.passed else "드리프트"
    color = "text-emerald-400" if ctx.sbom_drift.passed else "text-rose-400"
    return (
        f"<p class='mt-4 text-sm text-slate-400'>SBOM 드리프트: "
        f"<span class='font-medium {color}'>{status}</span> "
        f"(직접 의존성 {ctx.sbom_drift.current_count}개 / baseline {ctx.sbom_drift.allowed_count}개)</p>"
    )


def _render_finding_table(rows: list[DashboardRow], *, empty_message: str, muted: bool = False) -> str:
    if not rows:
        return f"<p class='mt-4 text-sm text-slate-500'>{html.escape(empty_message)}</p>"
    body = []
    row_class = "border-slate-800/80 text-slate-400" if muted else "border-slate-800 text-slate-200"
    for row in rows:
        track_ko = TRACK_LABELS.get(row.track, row.track)
        sev_ko = SEVERITY_LABELS.get(row.severity.upper(), row.severity)
        body.append(
            f"<tr class='border-t {row_class}'>"
            f"<td class='py-2 pr-2 text-xs text-slate-500'>{html.escape(track_ko)}</td>"
            f"<td class='py-2 pr-2'><span class='rounded px-1.5 py-0.5 text-xs font-medium {_severity_badge(row.severity)}'>{html.escape(sev_ko)}</span></td>"
            f"<td class='py-2 pr-2 font-mono text-xs'>{html.escape(row.finding_type)}</td>"
            f"<td class='py-2 pr-2 text-xs break-all'>{html.escape(row.resource)}</td>"
            f"<td class='py-2 text-xs text-slate-500'>{html.escape(row.detail)}</td>"
            f"</tr>"
        )
    return f"""<div class="mt-4 max-h-96 overflow-y-auto overflow-x-auto rounded-lg border border-slate-800/60">
      <table class="w-full text-left text-sm">
        <thead class="sticky top-0 bg-slate-900 text-xs uppercase text-slate-500">
          <tr><th class="p-2">트랙</th><th class="p-2">심각도</th><th class="p-2">유형</th><th class="p-2">위치</th><th class="p-2">내용</th></tr>
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
        return "<p class='mt-4 text-sm text-slate-500'>이번 실행에서 매핑된 규정 위반 없음.</p>"
    body = []
    for row in rows:
        fw_class = "text-blue-300" if row.framework == "ISMS-P" else "text-orange-300"
        sev_ko = SEVERITY_LABELS.get(row.max_severity.upper(), row.max_severity)
        body.append(
            f"<tr class='border-t border-slate-800'>"
            f"<td class='py-2 pr-3 font-mono text-sm text-white'>{html.escape(row.control_id)}</td>"
            f"<td class='py-2 pr-3 text-sm {fw_class}'>{html.escape(row.framework)}</td>"
            f"<td class='py-2 pr-3 text-sm text-slate-200'>{html.escape(row.title)}</td>"
            f"<td class='py-2 pr-3 text-xs text-slate-500'>{html.escape(row.category)}</td>"
            f"<td class='py-2 pr-3'><span class='rounded px-1.5 py-0.5 text-xs {_severity_badge(row.max_severity)}'>{html.escape(sev_ko)}</span></td>"
            f"<td class='py-2 text-sm text-slate-400'>{row.count}</td>"
            f"</tr>"
        )
    return f"""<div class="mt-4 max-h-80 overflow-y-auto overflow-x-auto rounded-lg border border-slate-800/60">
      <table class="w-full text-left">
        <thead class="sticky top-0 bg-slate-900 text-xs uppercase text-slate-500">
          <tr>
            <th class="p-2">통제 ID</th><th class="p-2">프레임워크</th><th class="p-2">통제명</th>
            <th class="p-2">분류</th><th class="p-2">최고 심각도</th><th class="p-2">건수</th>
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
