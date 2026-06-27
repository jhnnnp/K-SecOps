# GitHub Actions CI Evidence Checklist

면접용 **PASSED / FAILED** 스크린샷 2장을 확보하는 절차입니다.

---

## 번호로 실행 (추천)

```bash
python3 scripts/run_scenario.py
```

| 번호 | 시나리오 | GitHub 반응 |
|------|----------|-------------|
| 1 | Local demo report | 없음 (로컬 리포트만) |
| 2 | Local CI gate | 없음 |
| 3 | Local FAIL simulation | 없음 |
| 4 | Local all (1+2+3) | 없음 |
| 5 | PR PASS demo | Checks 초록 + PR 코멘트 |
| 6 | PR FAIL demo | Checks 빨강 + merge 차단 |
| 7 | Sync CI evidence | README 자동 갱신 |
| 8 | Actions SecOps Gate | Actions 탭 실행 |
| 9 | Actions Sync Evidence | Actions 탭 실행 |

PR/Actions(5~9)는 `gh auth login` 필요. 미리 보기: `python3 scripts/run_scenario.py 6 --dry-run`

---

## 사전 준비

1. GitHub 레포지토리 생성 후 push
2. Settings → Branches → `main` → **Require status check**: `SecOps Gate` / `devsecops-gate`
3. Workflow 파일: [`.github/workflows/secops-gate.yml`](../.github/workflows/secops-gate.yml)

---

## 시나리오 A — PASSED (baseline 동작)

```bash
git checkout -b demo/ci-pass
# dummy-infra/README.md 등 무해한 변경 1줄
git commit -am "docs: ci pass demo"
git push -u origin demo/ci-pass
```

GitHub에서 PR 생성 → **Checks 탭 초록색** + PR 코멘트:

```text
CI Gate: SUCCESS
DevSecOps CI Gate: PASSED
```

**캡처 (선택):** `docs/assets/ci-evidence/ci-pass.png` — 또는 아래 자동 동기화 사용

---

## 자동 동기화 (스크린샷 없이 API 증거)

GitHub API로 PR 체크 상태·봇 코멘트를 가져와 README/README에 반영합니다.

```bash
# 로컬 (gh 로그인 후)
export GH_TOKEN=$(gh auth token)
python3 scripts/sync_ci_evidence.py
# -> docs/CI_EVIDENCE_LATEST.md + README 자동 패치
```

GitHub Actions [`ci-evidence-sync.yml`](../.github/workflows/ci-evidence-sync.yml)이 **SecOps Gate** 실행 후 자동 커밋합니다.

- [x] Demo PASSED PR opened 2026-06-27

---

## 시나리오 B — FAILED (strict secret gate) — 핵심

```bash
git checkout -b demo/ci-fail-secret
```

`src/main.py` 상단에 **한 줄만** 추가 (커밋 후 반드시 revert):

```python
# demo-only-intentional-fail: paste AKIA + IOSFODNN7EXAMPLE as one contiguous token (AWS docs example key)
```

실제 PR에서는 위 주석 안에 **공백 없이** 20자 AWS 예시 Access Key ID를 넣습니다. (문서 파일에는 분리 표기해 repo-wide scan 오탐을 방지합니다.)

```bash
git commit -am "demo: intentional secret fail for CI evidence"
git push -u origin demo/ci-fail-secret
```

PR 생성 → **Checks 빨간색 X** + Merge blocked + PR 코멘트:

```text
CI Gate: FAILURE
CRITICAL: plaintext secret in application code: src/main.py:...
```

**캡처:** `docs/assets/ci-evidence/ci-fail-secret.png`

데모 PR은 merge하지 말고 close. `main`에서 해당 줄 제거.

---

## 로컬 사전 검증 (push 전)

```bash
# PASSED (현재 baseline)
PYTHONPATH=src python3 scripts/ci_gate.py

# FAIL 로직 확인 (전체 스캔 없이 gate만)
PYTHONPATH=src python3 scripts/demo_intentional_fail.py
```

---

## README에 넣을 위치

README 상단 Dual-Target 다이어그램 아래:

```markdown
| CI Gate PASSED | CI Gate FAILED (secret in src/) |
|----------------|----------------------------------|
| ![](./docs/assets/ci-evidence/ci-pass.png) | ![](./docs/assets/ci-evidence/ci-fail-secret.png) |
```

스크린샷 촬영 전까지는 placeholder 텍스트로 `[캡처 예정]` 표시.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Workflow 미실행 | `main`/`master` 대상 PR인지 확인 |
| 코멘트 없음 | `pull-requests: write` permission 확인 |
| Trivy/Checkov slow | 첫 run 2~3분, 이후 cache |
| PASSED인데 secret 넣었음 | `SECOPS_REPO_SCAN=1` workflow env 확인 |
