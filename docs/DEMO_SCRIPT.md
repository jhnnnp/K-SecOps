# Demo Recording Script (3 min)

Agentic K-SecOps 포트폴리오 시연용 녹화 가이드. **Trivy JSON scroll 금지.**

---

## Pre-flight

```bash
cd kakao
source .venv/bin/activate   # optional
brew install trivy checkov  # if not installed
python3 scripts/run_demo.py # report pre-generated check
```

Cursor MCP: `.cursor/mcp.json` reload, `agentic-k-secops` green.

---

## Timeline

### 0:00 - 0:20 | Hook

**Screen**: README.md (GitHub or local preview)

**Narration**:
> 배포 전 AI 에이전트가 ISMS-P와 전자금융감독규정 기준으로 인프라를 자동 감사하는 Agentic K-SecOps입니다.

**Show**: Badge row, Architecture diagram, Sample Report link.

---

### 0:20 - 0:45 | Problem

**Screen**: `dummy-infra/README.md` scenario table (5종)

**Narration**:
> 의도적 취약점 5종 — PII 로그, 평문 시크릿, privileged Pod, root Dockerfile, NodePort.

---

### 0:45 - 1:15 | Agent Prompt

**Screen**: Cursor Agent chat (clean, no terminal noise)

**Type**:
```
dummy-infra/에 배포 대기 중인 인프라를 ISMS-P·전자금융 기준으로 전수 감사하고 Markdown 진단 리포트를 생성해줘.
```

**Narration**:
> 한 줄 Prompt로 전체 파이프라인을 가동합니다.

---

### 1:15 - 2:00 | Tool Calls (3 cards only)

**Screen**: MCP tool invocation cards — do NOT expand raw JSON

Expected sequence:
1. `scan_infrastructure("dummy-infra")`
2. `audit_secrets("dummy-infra")`
3. `mask_pii` / `read_log_file` (PII masked summary only)
4. `generate_compliance_report(...)`

**Narration**:
> 스캔, 시크릿, PII 마스킹, 컴플라이언스 리포트 — 네 단계가 자동 연결됩니다.

---

### 2:00 - 2:40 | Report Walkthrough

**Screen**: `reports/SAMPLE_AUDIT_REPORT.md` on GitHub preview

Scroll slowly through:
- Executive Summary (badges)
- Compliance Overview table
- One Finding Detail block (결함 사유 / 권고 조치)

**Narration**:
> 101통제 셀프진단 Lab과 동일한 필드 — 결함 사유, 권고 조치, 필요 증적이 JSON lookup으로 생성됩니다.

---

### 2:40 - 3:00 | Close

**Screen**: Executive Summary + Recommended Actions (Immediate 3건)

**Narration**:
> Python MCP 서버, Trivy/Checkov, ISMS-P·전자금융 매핑까지 End-to-End. GitHub 링크는 README 참고.

---

## Do / Don't

| Do | Don't |
|----|-------|
| Badge + table focused report scroll | Trivy JSON full dump |
| Tool name cards | Terminal pytest output |
| Masked PII counts only | Raw 주민번호/계좌번호 |
| 3 min total | 10 min code walkthrough |

---

## Fallback (MCP offline)

```bash
PYTHONPATH=src python3 scripts/run_demo.py
open reports/SAMPLE_AUDIT_REPORT.md
```

Narrate CLI output summary lines only.

---

## Bonus: Intentional Fail Demo (면접용 스크린샷)

### 시나리오 A — PASSED (baseline)

`dummy-infra/`만 취약한 상태로 PR → GitHub Actions **초록색**, PR 코멘트 `DevSecOps CI Gate: PASSED`.

### 시나리오 B — FAILED (strict secret gate)

1. 브랜치 생성 후 `src/main.py` 상단에 주석 추가 (AWS docs example key — **한 줄에 공백 없이**):

   ```python
   # demo-only: <AKIA + IOSFODNN7EXAMPLE as single token>
   ```
2. PR 생성 → Actions **빨간색**, 코멘트에 `CRITICAL: plaintext secret in application code: src/main.py`.
3. Merge blocked 확인 후 해당 줄 삭제.

**캡처 2장:** PASSED PR + FAILED PR → README 상단 또는 포트폴리오 PDF에 배치.
