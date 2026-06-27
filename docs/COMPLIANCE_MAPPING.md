# Compliance Mapping Reference

Agentic K-SecOps Finding → 규정 매핑. **101통제 셀프진단 Lab 수준** 필드를 JSON Lookup으로 제공한다.

---

## Lookup Architecture

```
Finding (mask_pii / trivy / checkov / audit_secrets)
    │
    ▼
finding_rules.json          ← 결함 사유, 권고 조치, 우선순위, 필요 증적
    │
    ├──► isms_p_controls.json   ← 진단 질문, pass_criteria, assessment_method
    └──► eft_controls.json      ← 전자금융 진단 질문, pass_criteria
    │
    ▼
generate_compliance_report → SAMPLE_AUDIT_REPORT.md (Badge + Lab format)
```

**핵심 원칙**: LLM은 lookup 결과를 **서술·요약만** 한다. `deficiency_reason`, `recommended_action`은 JSON verbatim 출력.

---

## JSON 파일 역할

| File | 역할 |
|------|------|
| `src/compliance/schema.json` | Lab 필드 JSON Schema 정의 |
| `src/compliance/isms_p_controls.json` | ISMS-P 15개 MVP 통제 (101개 확장 가능) |
| `src/compliance/eft_controls.json` | 전자금융 10개 MVP 통제 |
| `src/compliance/finding_rules.json` | Finding type → 통제 + Lab 수준 결함·권고 |

---

## Lab 필드 매핑 (101통제 셀프진단 ↔ JSON)

| Lab UI 필드 | JSON 필드 | 위치 |
|-------------|-----------|------|
| 진단 질문 | `checklist_question` | controls JSON |
| 증적 방법 | `assessment_method` | controls JSON |
| 적정 기준 | `pass_criteria` | controls JSON |
| 진단 결과 | `compliance_status` | finding_rules.deficiency |
| 미흡 사유 | `deficiency_reason` | finding_rules.deficiency |
| 미흡 상세 | `deficiency_detail_template` | finding_rules.deficiency |
| 개선 권고 | `recommended_action` | finding_rules.deficiency |
| 조치 우선순위 | `action_priority` | finding_rules.deficiency |
| 필요 증적 | `evidence_required` | finding_rules.deficiency |
| 연계 Tool | `tool_reference` | finding_rules.deficiency |

---

## Finding Type Index (MVP)

| finding_type | Scanner | Default Severity | Controls |
|--------------|---------|------------------|----------|
| `pii.korean_rrn` | mask_pii | HIGH | ISMS-2.10.1, EFT-SEC-08, EFT-SEC-07 |
| `pii.account_number` | mask_pii | HIGH | ISMS-2.10.1, EFT-SEC-08 |
| `secret.aws_access_key` | audit_secrets | CRITICAL | ISMS-2.9.2, ISMS-2.9.1, EFT-SEC-04 |
| `secret.api_key` | audit_secrets | CRITICAL | ISMS-2.5.1, EFT-SEC-03 |
| `k8s.privileged_container` | checkov | CRITICAL | ISMS-2.7.2, ISMS-2.5.2, EFT-SEC-01 |
| `container.run_as_root` | checkov/trivy | HIGH | ISMS-2.5.2, EFT-SEC-01 |
| `container.critical_cve` | trivy | CRITICAL | ISMS-2.11.1, ISMS-2.7.3, EFT-SEC-06 |
| `k8s.missing_network_policy` | checkov | HIGH | ISMS-2.7.1, EFT-SEC-05 |
| `k8s.exposed_nodeport` | checkov | HIGH | ISMS-2.7.1, EFT-SEC-01 |

---

## Lookup 예시 (pii.korean_rrn)

**Before (단순 매핑)**:
```
ISMS-2.10.1 개인정보 수집·이용 — HIGH
```

**After (Lab 수준 Lookup)**:

```json
{
  "control_id": "ISMS-2.10.1",
  "checklist_question": "개인정보는 수집·이용 목적에 필요한 최소한의 범위 내에서 처리하고 있는가?",
  "compliance_status": "미흡",
  "deficiency_reason": "로그 내 PII(주민등록번호) 평문 저장",
  "deficiency_detail": "dummy-infra/logs/app.log에서 주민등록번호 3건 평문 확인.",
  "recommended_action": "정규식·Presidio 기반 실시간 마스킹 파이프라인(mask_pii) 적용",
  "action_priority": "즉시",
  "evidence_required": "mask_pii 재스캔 결과(0건), 로그 파이프라인 설정 diff"
}
```

---

## 101통제 전체 확장 전략

| Phase | Controls | 방법 |
|-------|----------|------|
| MVP | 25 (ISMS 15 + EFT 10) | Hand-crafted JSON |
| v1.1 | 50 | KISA 101통제 공개 자료 기반 bulk import |
| v2.0 | 101 | RAG (PDF → Vector DB) + JSON fallback |

MVP JSON 구조는 101개 확장 시 **동일 schema** 유지. `control_id`만 추가하면 리포트 템플릿 변경 없음.

---

## Report Output

- Sample: [`reports/SAMPLE_AUDIT_REPORT.md`](../reports/SAMPLE_AUDIT_REPORT.md)
- Design: [`docs/REPORT_DESIGN.md`](./REPORT_DESIGN.md)
