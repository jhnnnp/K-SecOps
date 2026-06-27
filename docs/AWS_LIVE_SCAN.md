# AWS Live Scan (boto3) — Cloud Asset Diagnosis

JD **「AWS 이해와 경험」** 방어용. 로컬 JSON fixture는 **회귀 테스트**, live scan은 **실제 클라우드 자산 진단**입니다.

---

## Architecture

| Mode | Trigger | Data source | Use case |
|------|---------|-------------|----------|
| **Local** | default / CI | `dummy-infra/aws/*.json` | deterministic regression |
| **Live** | `SECOPS_AWS_LIVE=1` + credentials | **AWS API (boto3)** | real account misconfiguration |

Live findings are tagged `source=boto3` in reports and gate summary.

---

## Live checks (boto3)

| Asset | API | Finding |
|-------|-----|---------|
| S3 buckets | `s3.list_buckets`, `get_public_access_block` | `aws.s3_public_access` (HIGH) |
| IAM customer policies | `iam.list_policies`, `get_policy_version` | `aws.iam_overprivileged` (CRITICAL) |
| IAM inline role policies | `iam.list_roles`, `get_role_policy` | `aws.iam_overprivileged` (CRITICAL) |

---

## Setup (ReadOnly IAM)

1. AWS Console → IAM → user `secops-readonly-demo`
2. Attach **`ReadOnlyAccess`** (or custom: `s3:List*`, `s3:GetPublicAccessBlock`, `iam:List*`, `iam:Get*`)

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=ap-northeast-2
export SECOPS_AWS_LIVE=1
```

---

## Run

```bash
cd kakao
source .venv/bin/activate
pip install boto3

PYTHONPATH=src SECOPS_AWS_LIVE=1 python3 -c "
from tools.aws_auditor import audit_aws_config
r = audit_aws_config('dummy-infra', live_scan=True)
print(f'live={r.live_scan} findings={len(r.findings)} errors={r.errors}')
for f in r.findings:
    print(f'  [{f.severity}] {f.finding_type} @ {f.resource} source={f.source}')
"
```

Full pipeline with live AWS:

```bash
PYTHONPATH=src SECOPS_AWS_LIVE=1 python3 scripts/ci_gate.py
```

---

## Interview pitch

> "Fixture JSON proves the mapper locally. Live mode uses boto3 ReadOnly to scan **real S3 PublicAccessBlock and IAM wildcard policies** in my AWS account. Findings appear as `source=boto3` in the Lab report."

---

## CI note

Default CI keeps `SECOPS_AWS_LIVE=0` (no credentials required).  
Optional: set repository secrets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, enable live in workflow.

Live findings **outside baseline** will fail the gate — use a dedicated demo account or extend `secops-baseline.json`.

---

## Evidence

Save terminal output or report excerpt with `source=boto3` lines to `docs/assets/aws-live-scan.png` (optional).
