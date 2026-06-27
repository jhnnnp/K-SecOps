# CI Evidence (auto-synced)

_Last updated: 2026-06-27 13:48 UTC_

![SecOps Gate workflow](https://img.shields.io/github/actions/workflow/status/jhnnnp/K-SecOps/secops-gate.yml?branch=main&label=SecOps%20Gate)

## Demo PR status

| Demo | PR | Check | Expected | Actual |
|------|-----|-------|----------|--------|
| PASSED | [#1](https://github.com/jhnnnp/K-SecOps/pull/1) | `devsecops-gate` | success | **PASS** |
| FAILED (intentional) | [#2](https://github.com/jhnnnp/K-SecOps/pull/2) | `devsecops-gate` | failure | **FAIL** |

- PASSED run: https://github.com/jhnnnp/K-SecOps/actions/runs/28287049032/job/83812730099
- FAILED run: https://github.com/jhnnnp/K-SecOps/actions/runs/28287049733/job/83812731991

## Gate comment snapshot (FAILED PR)

```text
<!-- devsecops-gate -->
**CI Gate:** FAILURE
# DevSecOps CI Gate: FAILED
## Dual-Target Scope
- Secrets scan (repo-wide): `.`
- Infrastructure scan (fixture + self): `dummy-infra, Dockerfile`
## Scan Summary
- Infrastructure findings: **47** (critical=0, high=13)
- Secret findings: **4** (application code: **1**)
- AWS config findings: **2** (live=False)
- Compliance violations: **37**
- Report: `reports/CI_AUDIT_REPORT.md`
```

## Validation

- PR #1 should be **green** (baseline dummy-infra only).
- PR #2 should be **red** (`src/main.py` intentional secret). Do not merge.

Regenerate locally:

```bash
export GH_TOKEN=$(gh auth token)   # after gh auth login
python3 scripts/sync_ci_evidence.py
```
