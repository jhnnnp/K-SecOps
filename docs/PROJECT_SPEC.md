# Agentic K-SecOps

**Agentic AI 기반 제로트러스트 인프라 보안 및 금융 컴플라이언스 자동 진단 파이프라인**

| 항목 | 내용 |
|------|------|
| 프로젝트명 (가칭) | Agentic K-SecOps |
| 목적 | 배포 전 인프라를 AI 에이전트가 자율 감사하고, 금융 규정 위반 여부를 자동 매핑하는 포트폴리오 |
| 타깃 JD | 카카오뱅크 — Python 보안 자동화, AWS/컨테이너, Agentic AI, 제로트러스트, 전자금융감독규정 |
| 문서 버전 | v0.2 (기획 + Lab Lookup + Report Design) |
| 최종 수정 | 2026-06-27 |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [문제 정의 및 가치 제안](#2-문제-정의-및-가치-제안)
3. [프로젝트 범위 (In / Out of Scope)](#3-프로젝트-범위-in--out-of-scope)
4. [시스템 아키텍처](#4-시스템-아키텍처)
5. [기술 스택 및 선정 근거](#5-기술-스택-및-선정-근거)
6. [MCP Tool 명세](#6-mcp-tool-명세)
7. [컴플라이언스 매핑 프레임워크](#7-컴플라이언스-매핑-프레임워크)
8. [단계별 구현 계획 (Phase 1–4)](#8-단계별-구현-계획-phase-14)
9. [데모 시나리오 및 산출물](#9-데모-시나리오-및-산출물)
10. [JD 역량 매핑 매트릭스](#10-jd-역량-매핑-매트릭스)
11. [리스크 및 완화 전략](#11-리스크-및-완화-전략)
12. [성공 기준 (Definition of Done)](#12-성공-기준-definition-of-done)
13. [향후 확장 (Post-MVP)](#13-향후-확장-post-mvp)

---

## 1. Executive Summary

Agentic K-SecOps는 **취약점 스캐너를 돌리는 도구**가 아니라, **AI 에이전트가 보안 감사자(Auditor) 역할을 수행**하는 자동 진단 파이프라인이다.

배포 직전 인프라(AWS, Kubernetes, Docker)에 대해 에이전트가 Tool Calling을 통해 다음을 수행한다.

| 단계 | 작업 | 산출물 |
|------|------|--------|
| 1 | 설정 오류·취약점 탐지 | Trivy/Checkov 기반 CVE·Misconfiguration 목록 |
| 2 | PII 탐지 및 마스킹 | 로그/덤프 내 주민번호·계좌번호 등 마스킹 결과 |
| 3 | 컴플라이언스 번역 | 전자금융감독규정·ISMS-P 통제항목 매핑 리포트 |

최종 산출물은 **"어떤 규정을 위반했는가"**를 한눈에 보여주는 Markdown/HTML 보안 진단 리포트이며, 카카오뱅크 JD의 필수·우대 역량을 하나의 End-to-End 흐름으로 증명한다.

---

## 2. 문제 정의 및 가치 제안

### 2.1 현재 Pain Point

| 문제 | 설명 |
|------|------|
| 도구 결과의 파편화 | Trivy, Checkov, 로그 분석 도구가 각각 JSON/텍스트를 뱉지만, 감사관이 읽을 수 있는 형태로 통합되지 않음 |
| 컴플라이언스 갭 | CVE ID와 ISMS-P 통제항목·전자금융감독규정 조항 사이의 매핑이 수작업 |
| PII 노출 지연 | 배포 후 로그에서 PII가 발견되면 사후 대응 — Shift-Left 필요 |
| 시크릿 노출 | 매니페스트·Dockerfile·Git에 평문 API Key가 남는 경우가 반복 |

### 2.2 가치 제안 (Why Agentic?)

- **자율 워크플로우**: 에이전트가 `scan → mask → map → report` 순서를 스스로 결정
- **금융 맥락 해석**: Raw CVE를 "전자금융감독규정 XX조 위반 가능"으로 번역
- **제로트러스트 관점**: "신뢰하지 않고 검증한다" — 모든 아티팩트를 배포 전 강제 검증
- **재현 가능한 감사**: 동일 입력 → 동일 Tool Chain → 구조화된 리포트

---

## 3. 프로젝트 범위 (In / Out of Scope)

### 3.1 In Scope (MVP)

- FastAPI 기반 MCP 서버 (Tool Provider)
- `read_log_file`, `mask_pii`, `scan_infrastructure`, `generate_compliance_report` Tool
- Trivy (컨테이너/이미지), Checkov (IaC/K8s YAML) 연동
- Presidio 또는 Regex 기반 PII 탐지·마스킹 (한국형 패턴 포함)
- ISMS-P·전자금융감독규정 **핵심 통제항목** 서브셋 매핑 (약 15–20개 선별)
- 의도적 취약점이 포함된 더미 인프라 + 시연 스크립트
- Markdown 진단 리포트 생성

### 3.2 Out of Scope (MVP 이후)

- 실제 AWS 계정 Live Scan (비용·권한 이슈)
- OPAQUE 프로토콜 풀 구현 (개념·체크리스트 수준만)
- ISMS-P 101개 전항목 완전 커버
- 프로덕션 CI/CD 파이프라인 통합 (GitHub Actions 훅은 Post-MVP)
- 실시간 SIEM 연동

---

## 4. 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                     AI Agent (Orchestrator)                      │
│          Claude Desktop / Cursor Agent / LangChain               │
│   System Prompt: 금융권 보안 감사관 + Tool Calling Policy        │
└───────────────────────────┬─────────────────────────────────────┘
                            │ MCP Protocol (stdio / SSE)
┌───────────────────────────▼─────────────────────────────────────┐
│              MCP Server (Python / FastAPI)                       │
│  ┌─────────────┐ ┌─────────────┐ ┌──────────────────────────┐   │
│  │ read_log    │ │ mask_pii    │ │ scan_infrastructure      │   │
│  │ _file       │ │             │ │  ├─ Trivy subprocess     │   │
│  └─────────────┘ └─────────────┘ │  └─ Checkov subprocess   │   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ generate_compliance_report (규정 매핑 + Markdown 렌더)   │   │
│  └─────────────────────────────────────────────────────────┘   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                    Security Targets (Local)                      │
│  dummy-infra/                                                    │
│    ├── k8s/deployment-vulnerable.yaml                            │
│    ├── docker/Dockerfile.insecure                                │
│    ├── logs/app.log (PII 포함)                                   │
│    └── .env.leaked (평문 시크릿 — 시연용)                         │
└─────────────────────────────────────────────────────────────────┘
```

### 4.1 데이터 흐름 (Happy Path)

```
User Prompt
  → Agent: scan_infrastructure(path="dummy-infra/")
  → Agent: read_log_file(path="dummy-infra/logs/app.log")
  → Agent: mask_pii(content=...)
  → Agent: generate_compliance_report(findings=[...])
  → Output: SECURITY_AUDIT_REPORT.md
```

### 4.2 디렉터리 구조 (목표)

```
kakao/
├── docs/
│   ├── PROJECT_SPEC.md          # 본 기획서
│   └── COMPLIANCE_MAPPING.md    # 규정-Finding 매핑 테이블
├── src/
│   ├── mcp_server/
│   │   ├── main.py              # FastAPI + MCP entry
│   │   ├── tools/
│   │   │   ├── read_log.py
│   │   │   ├── mask_pii.py
│   │   │   ├── scan_infra.py
│   │   │   └── compliance.py
│   │   └── parsers/
│   │       ├── trivy_parser.py
│   │       └── checkov_parser.py
│   └── compliance/
│       ├── schema.json
│       ├── isms_p_controls.json
│       ├── eft_controls.json
│       └── finding_rules.json
├── dummy-infra/                 # 시연용 취약 인프라
├── reports/                     # 생성된 진단 리포트
├── tests/
├── pyproject.toml
├── .env.example
└── README.md
```

---

## 5. 기술 스택 및 선정 근거

| 계층 | 기술 | 선정 근거 |
|------|------|-----------|
| MCP Server | Python 3.11+, FastAPI | JD 필수 Python, async API, MCP SDK 호환 |
| MCP Protocol | `mcp` Python SDK | Cursor/Claude Desktop 네이티브 연동 |
| Container Scan | Trivy | SPDX 라이선스, 금융권 Docker 스캔 de facto |
| IaC Scan | Checkov | K8s YAML, Dockerfile, Terraform 지원 |
| PII Detection | Microsoft Presidio + 커스텀 Regex | 한국 주민번호·계좌번호 패턴 확장 용이 |
| Agent | Claude (Cursor Agent / Desktop) | Tool Use 성숙도, 긴 컨텍스트 |
| Report | Jinja2 + Markdown | 템플릿 기반 재현 가능 리포트 |
| CI (Post-MVP) | GitHub Actions | PR 시 자동 스캔 훅 |

---

## 6. MCP Tool 명세

### 6.1 `read_log_file`

| 항목 | 내용 |
|------|------|
| 입력 | `path: str`, `max_lines: int = 500` |
| 출력 | `{ "content": str, "line_count": int, "truncated": bool }` |
| 제약 | `dummy-infra/` 및 `reports/` 하위만 허용 (Path Traversal 방지) |

### 6.2 `mask_pii`

| 항목 | 내용 |
|------|------|
| 입력 | `content: str`, `entities: list[str] = ["KR_RRN", "KR_PHONE", "ACCOUNT", "EMAIL"]` |
| 출력 | `{ "masked_content": str, "findings": [{ "type", "count", "sample_locations" }] }` |
| 구현 | Presidio Analyzer + 한국형 Regex fallback |

**한국형 PII 패턴 (Regex)**

| Entity | Pattern (개념) |
|--------|----------------|
| KR_RRN | `\d{6}-[1-4]\d{6}` |
| KR_PHONE | `01[0-9]-\d{3,4}-\d{4}` |
| ACCOUNT | `\d{3,6}-\d{2,6}-\d{4,8}` |
| EMAIL | RFC5322 simplified |

### 6.3 `scan_infrastructure`

| 항목 | 내용 |
|------|------|
| 입력 | `target_path: str`, `scanners: list[str] = ["trivy", "checkov"]` |
| 출력 | `{ "findings": [...], "summary": { "critical": n, "high": n, ... } }` |
| 내부 | `subprocess.run(["trivy", "fs", "--format", "json", ...])` |

**Finding 스키마 (정규화)**

```json
{
  "id": "TRIVY-CVE-2024-XXXX",
  "severity": "CRITICAL",
  "resource": "dummy-infra/docker/Dockerfile.insecure",
  "title": "OS package vulnerability",
  "description": "...",
  "scanner": "trivy",
  "raw": {}
}
```

### 6.4 `generate_compliance_report`

| 항목 | 내용 |
|------|------|
| 입력 | `findings: list`, `pii_findings: list`, `output_path: str` |
| 출력 | `{ "report_path": str, "violations": [...] }` |
| 로직 | Finding type → ISMS-P / 전자금융 규정 조항 lookup → Markdown 표 렌더 |

### 6.5 `audit_secrets` (Phase 2.5)

| 항목 | 내용 |
|------|------|
| 입력 | `target_path: str` |
| 출력 | 평문 API Key, AWS Access Key, Private Key 패턴 탐지 결과 |
| 규정 매핑 | 전자금융감독규정 — 암호화 및 키 관리 관련 조항 |

---

## 7. 컴플라이언스 매핑 프레임워크

### 7.1 매핑 원칙

1. **Finding → Control**: 하나의 Finding이 여러 통제항목에 해당할 수 있음 (N:M)
2. **Lab-grade Lookup**: 조항 번호·제목만이 아니라 **결함 사유·권고 조치·필요 증적**까지 JSON에서 verbatim 출력
3. **LLM Role Split**: LLM은 Executive Summary 서술만. 규정 매핑 텍스트는 `finding_rules.json` lookup 전용
4. **Evidence Chain**: 리포트에 원본 파일 경로·라인 번호·스캐너 Raw Output (Appendix collapsed)

### 7.2 101통제 셀프진단 Lab 수준 JSON Lookup

| Lab 필드 | JSON Source |
|----------|-------------|
| 진단 질문 | `isms_p_controls.json` → `checklist_question` |
| 진단 결과 (적정/미흡) | `finding_rules.json` → `compliance_status` |
| 결함 사유 | `finding_rules.json` → `deficiency_reason` |
| 권고 조치 | `finding_rules.json` → `recommended_action` |
| 조치 우선순위 | `finding_rules.json` → `action_priority` |
| 필요 증적 | `finding_rules.json` → `evidence_required` |

**예시 (PII in logs)**:

| 단순 매핑 (Before) | Lab Lookup (After) |
|------------------|-------------------|
| ISMS-2.10.1 개인정보 처리 | 결함: 로그 내 PII 평문 저장 |
| | 권고: mask_pii 실시간 마스킹 파이프라인 적용 |
| | 증적: 재스캔 0건 + 파이프라인 diff |

상세 스키마: `src/compliance/schema.json` · 샘플 리포트: `reports/SAMPLE_AUDIT_REPORT.md`

### 7.3 MVP 매핑 테이블 (Finding Index)

| finding_type | ISMS-P | 전자금융 | Lab deficiency_reason (요약) |
|--------------|--------|----------|------------------------------|
| `pii.korean_rrn` | 2.10.1 | SEC-08 | 로그 내 PII 평문 저장 |
| `secret.aws_access_key` | 2.9.2 | SEC-04 | AWS Key 평문 노출 |
| `k8s.privileged_container` | 2.7.2 | SEC-01 | privileged 모드 사용 |
| `container.critical_cve` | 2.11.1 | SEC-06 | Critical CVE 미패치 |

> 전체 101개 ISMS-P 항목은 동일 schema로 확장. MVP 25개 (ISMS 15 + EFT 10). See `docs/COMPLIANCE_MAPPING.md`.

### 7.3 Agent System Prompt (핵심 룰셋)

```
Role: 금융권 인프라 보안 감사관 (ISMS-P + 전자금융감독규정)

Workflow:
1. scan_infrastructure로 대상 경로 전체 스캔
2. read_log_file + mask_pii로 로그 PII 확인
3. audit_secrets로 평문 시크릿 검색
4. generate_compliance_report로 최종 리포트 생성

Output Format:
- Executive Summary (Critical/High 건수)
- Findings Table: | Severity | Resource | Finding | ISMS-P | 전자금융 | Remediation |
- PII Exposure Section (마스킹 전후 비교 금지 — 마스킹된 결과만)
- Recommended Actions (우선순위순)
```

---

## 8. 단계별 구현 계획 (Phase 1–4)

### Phase 1: 기초 공사 (예상 3–4일)

| # | Task | 완료 기준 |
|---|------|-----------|
| 1.1 | `pyproject.toml`, FastAPI MCP 서버 부트스트랩 | `uvicorn` 기동, health check 200 |
| 1.2 | `read_log_file` Tool | 더미 로그 읽기 성공 |
| 1.3 | `mask_pii` Tool (Regex MVP) | 주민번호·계좌번호 `***` 치환 |
| 1.4 | Path sandbox middleware | `/etc/passwd` 접근 차단 테스트 통과 |
| 1.5 | 단위 테스트 | `tests/test_mask_pii.py` green |

### Phase 2: 보안 엔진 장착 (예상 3–4일)

| # | Task | 완료 기준 |
|---|------|-----------|
| 2.1 | Trivy CLI 연동 | JSON 파싱 → 정규화 Finding |
| 2.2 | Checkov CLI 연동 | K8s YAML misconfig 탐지 |
| 2.3 | `scan_infrastructure` Tool 통합 | 단일 API로 두 스캐너 결과 merge |
| 2.4 | `audit_secrets` Tool | AWS Key·API Key 패턴 탐지 |
| 2.5 | Parser 테스트 | 샘플 JSON fixture 기반 |

### Phase 3: 두뇌 완성 (예상 2–3일)

| # | Task | 완료 기준 |
|---|------|-----------|
| 3.1 | `isms_p_controls.json` / `eft_controls.json` | 15–20개 통제항목 정의 |
| 3.2 | `generate_compliance_report` Tool | Markdown 리포트 파일 생성 |
| 3.3 | Agent System Prompt 작성 | `docs/AGENT_PROMPT.md` |
| 3.4 | Cursor MCP 설정 | `.cursor/mcp.json` 등록 |
| 3.5 | E2E 시나리오 1회 성공 | Prompt → Report 전체 흐름 |

### Phase 4: 포트폴리오화 (예상 2–3일)

| # | Task | 완료 기준 |
|---|------|-----------|
| 4.1 | `dummy-infra/` 시나리오 5종 | CVE, PII, Secret, K8s misconfig, Root container |
| 4.2 | README.md (실구현 기준) | 설치·실행·데모 명령어 |
| 4.3 | 시연 녹화 스크립트 | 3–5분 데모 영상 |
| 4.4 | Sample Report | `reports/SAMPLE_AUDIT_REPORT.md` |
| 4.5 | Architecture diagram | 본 문서 또는 README 내 Mermaid |

**총 예상 기간: 10–14일 (1인 풀타임 기준)**

---

## 9. 데모 시나리오 및 산출물

### 9.1 시연 시나리오 (면접/포트폴리오용)

**사용자 Prompt (예시)**

> 현재 `dummy-infra/`에 배포 대기 중인 인프라 파일들을 검토하고, ISMS-P 및 전자금융감독규정 기준으로 보안 진단 리포트를 생성해줘.

**에이전트 Expected Behavior**

1. `scan_infrastructure("dummy-infra/")` 호출 → Trivy/Checkov 결과 수집
2. `read_log_file("dummy-infra/logs/app.log")` → PII 존재 확인
3. `mask_pii(...)` → PII 건수·유형 보고 (원문 미노출)
4. `audit_secrets("dummy-infra/")` → `.env.leaked` 탐지
5. `generate_compliance_report(...)` → `reports/AUDIT_YYYYMMDD.md` 생성
6. 사용자에게 Executive Summary + Critical 항목 3건 요약

### 9.2 포트폴리오 시각화 (Minimal & Professional)

- **리포트**: shields.io Badge + Lab format 표. Raw scanner log는 Appendix `<details>` 접기
- **README**: Hero badge row + Sample Report 링크. 장문 로그 금지
- **시연 영상 (3분)**: Prompt 1줄 → Tool 3개 카드 → Report 스크롤. Trivy JSON scroll 금지
- **가이드**: `docs/REPORT_DESIGN.md`
- **샘플**: `reports/SAMPLE_AUDIT_REPORT.md`

### 9.3 의도적 취약점 목록 (dummy-infra)

| 파일 | 의도적 취약점 | 기대 Finding |
|------|---------------|--------------|
| `docker/Dockerfile.insecure` | `USER root`, outdated base image | CVE, privilege escalation |
| `k8s/deployment-vulnerable.yaml` | `privileged: true`, hostPath mount | K8s misconfig CRITICAL |
| `logs/app.log` | 주민번호·계좌번호 평문 | PII → ISMS-P 2.10 |
| `.env.leaked` | `AWS_ACCESS_KEY_ID=AKIA...` | Secret → 암호화 지침 위반 |
| `k8s/service-nodeport.yaml` | 불필요한 NodePort expose | 네트워크 접근통제 |

### 9.4 최종 산출물 체크리스트

- [ ] GitHub Public Repository
- [ ] README with demo GIF/영상 링크
- [ ] Sample Audit Report (Markdown)
- [ ] MCP Server 로컬 실행 가이드
- [ ] Architecture Diagram
- [ ] JD 역량 매핑 1-pager (면접용)

---

## 10. JD 역량 매핑 매트릭스

| JD 요구사항 | 본 프로젝트 증명 방법 | 구현 Phase |
|-------------|----------------------|------------|
| Python 보안 자동화 | FastAPI MCP Server, subprocess 스캐너 연동 | 1, 2 |
| AWS/ Docker 이해 | Dockerfile 스캔, 컨테이너 CVE, AWS Key 탐지 | 2, 4 |
| Kubernetes | Checkov K8s YAML misconfig | 2, 4 |
| Agentic AI | MCP Tool Calling 기반 자율 감사 워크플로우 | 3 |
| 제로트러스트 | 배포 전 강제 검증, default deny path sandbox | 1, 3 |
| 전자금융감독규정 | Finding → 규정 조항 매핑 리포트 | 3 |
| ISMS-P | 통제항목 매핑 테이블 | 3 |
| E2EE/시크릿 관리 (우대) | `audit_secrets` + OPAQUE 개념 체크리스트 | 2.5 |
| RAG/문서 파싱 (우대) | Compliance JSON lookup + 향후 RAG 확장 | 3, 13 |

---

## 11. 리스크 및 완화 전략

| 리스크 | 영향 | 완화 |
|--------|------|------|
| Trivy/Checkov 미설치 | 스캔 실패 | Docker Compose로 스캐너 번들 또는 설치 스크립트 |
| LLM Hallucination (규정 매핑) | 잘못된 조항 인용 | JSON lookup 우선, LLM은 서술·요약만 |
| PII 시연 데이터 | 윤리·법적 이슈 | Faker 기반 가짜 데이터만 사용 |
| MCP SDK 변경 | 호환성 | 버전 pin, integration test |
| 과도한 Scope | 일정 지연 | MVP 15–20 통제항목, OPAQUE는 개념만 |

---

## 12. 성공 기준 (Definition of Done)

MVP는 아래 **5가지 모두** 충족 시 완료로 정의한다.

1. **Tool Chain E2E**: 단일 Agent Prompt → Markdown Report 자동 생성 (5분 이내)
2. **Scanner Coverage**: Trivy + Checkov 최소 1건 이상 Critical Finding 탐지 (dummy-infra)
3. **PII Masking**: 4종 Entity (RRN, Phone, Account, Email) 탐지율 100% (dummy log)
4. **Compliance Mapping**: Finding당 최소 1개 ISMS-P + 1개 전자금융 조항 매핑
5. **Portfolio Ready**: README + Sample Report + 3분 시연 영상

---

## 13. 향후 확장 (Post-MVP)

| 확장 | 설명 |
|------|------|
| GitHub Actions Gate | PR merge 전 `scan_infrastructure` 필수 |
| AWS Live Scan | IAM Role 기반 ReadOnly 스캔 |
| OPA/Gatekeeper | K8s Admission Policy 연동 |
| RAG Compliance | ISMS-P 전문 PDF → Vector DB → 조항 검색 |
| OPAQUE PoC | 시크릿 교환 프로토콜 미니 구현 |
| SARIF Export | GitHub Security Tab 연동 |

---

## Appendix A: Sample Report Outline

```markdown
# Security Audit Report — dummy-infra/
Generated: 2026-06-27 | Scanner: Trivy 0.x, Checkov 3.x

## Executive Summary
- Critical: 2 | High: 3 | Medium: 1
- PII Entities Found: 4 (masked)
- Compliance Violations: 5

## Findings

| Severity | Resource | Finding | ISMS-P | 전자금융 | Remediation |
|----------|----------|---------|--------|----------|-------------|
| CRITICAL | k8s/deployment-vulnerable.yaml | privileged: true | 2.7.1 | 접근통제 | privileged: false |
| CRITICAL | .env.leaked | AWS Access Key plaintext | 2.9.1 | 암호화·키관리 | Secrets Manager 사용 |
| HIGH | logs/app.log | KR_RRN detected (3) | 2.10.1 | 개인정보보호 | 로그 마스킹 적용 |

## Recommended Actions
1. [Immediate] Remove `.env.leaked`, rotate AWS keys
2. [Immediate] Set privileged: false in deployment
3. [Short-term] Apply Presidio masking in log pipeline
```

---

## Appendix B: 현재 프로젝트 상태

| 구분 | 상태 |
|------|------|
| 코드베이스 | Greenfield (2026-06-27 기준 미착수) |
| Git | 미초기화 |
| 본 문서 | v0.1 기획 확정본 |

**Next Action**: Phase 1.1 — `pyproject.toml` + FastAPI MCP 서버 부트스트랩
