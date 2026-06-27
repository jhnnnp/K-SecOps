# AWS Live Scan (boto3)

JD **「AWS 이해와 경험」** 방어용 — 실제 AWS API로 S3 PublicAccessBlock을 조회합니다.

로컬 policy JSON 분석(`dummy-infra/aws/*.json`)과 **별도**로, live scan은 **본인 AWS 프리티어 계정**에서 1회 실행 후 결과를 스크린샷으로 보관하세요.

---

## 1. IAM ReadOnly 유저 생성

AWS Console → IAM → Users → Create user

- User name: `secops-readonly-demo`
- Attach policy: **`ReadOnlyAccess`** (또는 최소 S3 `ListAllMyBuckets`, `GetPublicAccessBlock`)

Access key 발급 → **`.env`에만 저장, Git에 커밋 금지**

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=ap-northeast-2
export SECOPS_AWS_LIVE=1
```

---

## 2. Live scan 실행

```bash
cd kakao
source .venv/bin/activate
pip install boto3

PYTHONPATH=src SECOPS_AWS_LIVE=1 python3 -c "
from tools.aws_auditor import audit_aws_config
r = audit_aws_config('dummy-infra', live_scan=True)
print(f'live={r.live_scan} findings={len(r.findings)} errors={r.errors}')
for f in r.findings:
    print(f'  [{f.severity}] {f.finding_type} @ {f.resource} ({f.source})')
"
```

또는:

```bash
PYTHONPATH=src SECOPS_AWS_LIVE=1 python3 scripts/run_demo.py
```

---

## 3. 무엇을 검사하나

| Check | API | Finding |
|-------|-----|---------|
| S3 PublicAccessBlock 4종 미적용 | `s3.get_public_access_block` | `aws.s3_public_access` (HIGH, source=boto3) |

Credentials 없으면 graceful skip: `errors[]`에 `"AWS credentials not configured"`.

---

## 4. 면접 멘트

> "정적 IAM/S3 policy JSON 분석에 더해, boto3로 실제 계정의 S3 PublicAccessBlock을 조회합니다. CI 기본값은 live off이고, 로컬/스테이징에서 ReadOnly credentials로 dynamic misconfiguration scan을 수행합니다."

---

## 5. 증거물

터미널 출력 또는 리포트 스크린샷 → `docs/assets/aws-live-scan.png`

**주의:** live finding이 baseline에 없으면 CI gate FAIL. CI workflow는 `SECOPS_AWS_LIVE=0` 유지.

---

## 6. (선택) GitHub Actions live scan

Repository secrets에 `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` 설정 후  
`secops-gate.yml`에서 `SECOPS_AWS_LIVE` 주석 해제.

프로덕션 레포에서는 ReadOnly + baseline allowlist 필수.
