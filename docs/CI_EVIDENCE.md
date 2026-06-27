# GitHub Actions CI Evidence Checklist

면접용 **PASSED / FAILED** 스크린샷 2장을 확보하는 절차입니다.

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

**캡처:** `docs/assets/ci-evidence/ci-pass.png` (Checks + PR 코멘트)

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
