# JD Competency Mapping (1-Pager)

카카오뱅크 JD — Agentic K-SecOps 증명 매트릭스 (면접용)

---

## One-liner

> MCP Tool Chain + GitHub Actions CI Gate로 배포 전 인프라·AWS 설정을 스캔하고, ISMS-P·전자금융감독규정 Lab 형식 진단 리포트를 자동 생성하는 Zero Trust SecOps 파이프라인

---

## 필수 역량

| JD | 증거 (Repo) | Demo Point |
|----|-------------|------------|
| Python 보안 자동화 | `src/tools/`, FastAPI MCP, subprocess Trivy/Checkov | `scripts/run_demo.py` |
| AWS / Docker | `audit_aws_config` (boto3 S3 PAB), Trivy Dockerfile scan | `dummy-infra/aws/*.json` CRITICAL 2건 |
| Kubernetes | `k8s/*.yaml` Checkov misconfig | privileged, NodePort |
| CI/CD 보안 검증 | `secops-gate.yml`, `ci_gate.py`, [CI_EVIDENCE.md](./CI_EVIDENCE.md) | Dual-target + PR screenshot evidence |

## Multi-Track Scope (면접 핵심)

| Track | Target | Gate |
|-------|--------|------|
| Secrets (`audit_secrets`) | `.` 전역 (`src/` 포함) | `dummy-infra/` 외 시크릿 → **무조건 FAIL** |
| SAST (`audit_sast`) | `.` (`src/` + fixtures) | CI: **Semgrep** `--config auto` (OWASP rules); local: regex fallback |
| SCA (`scan_dependencies`) | `requirements.txt`, `dummy-infra/deps` | **Trivy vuln scanner** (NVD DB) — root manifest HIGH+ CVE → **FAIL** |
| Infra (`scan_infrastructure`) | `dummy-infra`, `Dockerfile` | `dummy-infra/` CRITICAL만 baseline 회귀 검사 |

> "시크릿은 레포 전체를 봅니다. 인프라는 회귀 테스트 픽스처 + 자기 Dockerfile로 엔진을 검증합니다."

## 우대 역량

| JD | 증거 | Demo Point |
|----|------|------------|
| Agentic AI | 6 MCP Tools, `docs/AGENT_PROMPT.md` workflow | Cursor one-line prompt |
| Zero Trust | MCP strict sandbox + CI repo-wide secret gate | `SECOPS_REPO_SCAN`, `config/secops-baseline.json` |
| 전자금융감독규정 | `eft_controls.json`, `finding_rules.json` | EFT-SEC-01 AWS/S3 mapping |
| ISMS-P | `isms_p_controls.json`, 101 Lab fields | ISMS-2.7.1 S3, ISMS-2.5.1 IAM |
| E2EE / 시크릿 (우대) | `audit_secrets`, OPAQUE checklist in spec | `.env.leaked` 탐지 |
| RAG / 문서 (우대) | JSON lookup now, RAG extension in PROJECT_SPEC Post-MVP | schema.json 101 expand |

---

## End-to-End Flow (30 sec pitch)

```
PR push / Prompt
    → scan_infrastructure → audit_secrets → audit_aws_config → mask_pii
    → generate_compliance_report → CI_SUMMARY.md (PR comment)
    → reports/SAMPLE_AUDIT_REPORT.md
```

6 Tools, 1 Agent, baseline-aware CI gate.

---

## Numbers (dummy-infra live run)

| Metric | Typical |
|--------|---------|
| Scan findings | 40+ (Trivy + Checkov) |
| AWS config findings | 2 (local policy) |
| Compliance violations | 30+ (Lab mapped) |
| Controls (미흡) | 13+ |
| Immediate actions | 19+ |

---

## Links

| Asset | Path |
|-------|------|
| Sample Report | [reports/SAMPLE_AUDIT_REPORT.md](../reports/SAMPLE_AUDIT_REPORT.md) |
| CI Workflow | [.github/workflows/secops-gate.yml](../.github/workflows/secops-gate.yml) |
| CI Evidence | [docs/CI_EVIDENCE.md](./CI_EVIDENCE.md) |
| AWS Live Scan | [docs/AWS_LIVE_SCAN.md](./AWS_LIVE_SCAN.md) |
| Architecture | [README.md#architecture](../README.md) |
| Demo Script | [docs/DEMO_SCRIPT.md](./DEMO_SCRIPT.md) |
| Full Spec | [docs/PROJECT_SPEC.md](./PROJECT_SPEC.md) |

---

## Interview Q&A Prep

**Q: LLM이 규정 조항을 hallucinate하지 않나요?**  
A: `deficiency_reason`, `recommended_action`은 `finding_rules.json`에서 verbatim. LLM은 Executive Summary 서술만.

**Q: 더미만 스캔하는 껍데기 아닌가요?**  
A: 이중 타겟. `audit_secrets`는 CI에서 레포 전역(`.`) 스캔 — `src/`에 AKIA 넣으면 baseline 없이 즉시 FAIL. `scan_infrastructure`만 `dummy-infra`+`Dockerfile` 픽스처로 엔진 회귀 검증.

**Q: CI에서 의도적 취약점(dummy-infra)은 어떻게 처리하나요?**  
A: `config/secops-baseline.json` allowlist. 알려진 데모 finding은 통과, `src/` 등 샌드박스 밖 시크릿·baseline 외 CRITICAL은 merge 차단.

**Q: AWS live scan은?**  
A: `SECOPS_AWS_LIVE=1` + ReadOnly credentials → boto3로 **S3 PublicAccessBlock + IAM wildcard policy** API 조회. finding은 `source=boto3`. fixture JSON은 회귀 테스트용.

**Q: Go-lang / Alerting?**  
A: `cmd/alert-worker` (Go)가 gate FAIL 시 Slack/Discord webhook 알림. Python gate + Go alert worker 분리.

**Q: 101통제 전체 커버?**  
A: MVP 25개 통제, schema 동일 — bulk import + RAG hybrid 확장 설계.

**Q: Production 적용?**  
A: Post-MVP — AWS ReadOnly IAM role, OPA admission, branch protection required check.
