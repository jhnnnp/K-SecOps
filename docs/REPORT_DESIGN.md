# Report Design Guide

Agentic K-SecOps 포트폴리오 산출물(리포트·README·시연)의 시각적 가이드.

원칙: **미니멀, 프로페셔널, 스캔 로그 최소화, Finding·규정 매핑 최대화**

---

## 1. 디자인 원칙

| 원칙 | 적용 |
|------|------|
| Log-less | Trivy/Checkov raw JSON은 Appendix로 접기. 본문에는 정규화 Finding만 |
| Badge-first | Severity·Compliance Status는 shields.io 뱃지로 즉시 인지 |
| Table-driven | 한 화면에 Finding + ISMS-P + 전자금융 + 권고 조치 |
| Lab-grade copy | 결함 사유·권고 조치는 `finding_rules.json`에서만 — LLM 재작성 금지 |
| Dark-neutral | GitHub Dark / Notion 스타일. 과한 컬러·장식 없음 |

---

## 2. Severity Badge (shields.io)

Markdown/HTML 공통. README·리포트·GitHub 모두 렌더링됨.

```markdown
![CRITICAL](https://img.shields.io/badge/Severity-CRITICAL-D32F2F?style=flat-square)
![HIGH](https://img.shields.io/badge/Severity-HIGH-F57C00?style=flat-square)
![MEDIUM](https://img.shields.io/badge/Severity-MEDIUM-FBC02D?style=flat-square)
![LOW](https://img.shields.io/badge/Severity-LOW-388E3C?style=flat-square)
```

## 3. Compliance Status Badge

```markdown
![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square)
![적정](https://img.shields.io/badge/진단결과-적정-388E3C?style=flat-square)
![점검필요](https://img.shields.io/badge/진단결과-점검필요-757575?style=flat-square)
```

## 4. Action Priority Badge

```markdown
![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square)
![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square)
![중기](https://img.shields.io/badge/조치우선순위-중기-FBC02D?style=flat-square)
```

## 5. Framework Badge

```markdown
![ISMS-P](https://img.shields.io/badge/Framework-ISMS--P-1565C0?style=flat-square)
![EFT](https://img.shields.io/badge/Framework-전자금융-E65100?style=flat-square)
```

---

## 6. Report Section Structure

```
1. Header (프로젝트명, 대상, 일시, 스캐너 버전)
2. Executive Summary (뱃지 4개: Critical/High/미흡/즉시조치)
3. Compliance Overview Table (통제항목별 적정/미흡)
4. Findings Detail Table (핵심 — Lab 수준 결함·권고)
5. Recommended Actions (우선순위 그룹)
6. Appendix (raw scanner output — collapsed)
```

---

## 7. 시연 영상 구성 (3분)

| 구간 | 화면 | Narration |
|------|------|-----------|
| 0:00–0:20 | README hero + architecture diagram | "배포 전 AI가 ISMS-P·전자금융 기준으로 자동 감사" |
| 0:20–0:50 | Cursor Agent에 Prompt 1줄 입력 | "한 줄 명령으로 전체 파이프라인 가동" |
| 0:50–1:30 | Tool call 카드 3개만 (scan → mask → report) | "로그 덤프 없이 Tool 진행만" |
| 1:30–2:30 | SAMPLE_AUDIT_REPORT.md 스크롤 | "101통제 Lab 수준 결함·권고 조치" |
| 2:30–3:00 | Executive Summary + Critical 3건 | "현업 감사 리포트와 동일 구조" |

**녹화 시 금지**: Trivy JSON 전체 출력, 터미널 scroll spam, PII 원문

---

## 8. README Hero Layout

```markdown
# Agentic K-SecOps

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![MCP](https://img.shields.io/badge/Protocol-MCP-512BD4?style=flat-square)
![ISMS-P](https://img.shields.io/badge/Compliance-ISMS--P-1565C0?style=flat-square)
![EFT](https://img.shields.io/badge/Compliance-전자금융-E65100?style=flat-square)

> Agentic AI 기반 제로트러스트 인프라 보안 · 금융 컴플라이언스 자동 진단

[Demo Video](./docs/demo.mp4) · [Sample Report](./reports/SAMPLE_AUDIT_REPORT.md)
```

---

## 9. Jinja2 Report Template Variables

`generate_compliance_report`가 주입하는 변수:

| Variable | Source |
|----------|--------|
| `finding.severity_badge` | severity → shields URL |
| `finding.compliance_status_badge` | finding_rules.json |
| `finding.deficiency_reason` | finding_rules.json (verbatim) |
| `finding.recommended_action` | finding_rules.json (verbatim) |
| `control.checklist_question` | isms_p_controls.json / eft_controls.json |
| `control.title` | controls JSON |

---

## 10. HTML Export (Optional Post-MVP)

Markdown → HTML 시 `<details>` 로 Appendix 접기:

```html
<details>
<summary>Raw Trivy Output (click to expand)</summary>
<pre>...</pre>
</details>
```

GitHub Pages 배포 시 `reports/index.html` 단일 페이지로 포트폴리오 링크 가능.
