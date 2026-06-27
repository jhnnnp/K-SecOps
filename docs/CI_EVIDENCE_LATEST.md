# CI Evidence (auto-synced)

_Last updated: 2026-06-27 13:51 UTC_

![SecOps Gate workflow](https://img.shields.io/github/actions/workflow/status/jhnnnp/K-SecOps/secops-gate.yml?branch=main&label=SecOps%20Gate)

## Demo PR status

| Demo | PR | Check | Expected | Actual |
|------|-----|-------|----------|--------|
| PASSED | [#1](https://github.com/jhnnnp/K-SecOps/pull/1) | `devsecops-gate` | success | **PASS** |
| FAILED (intentional) | [#2](https://github.com/jhnnnp/K-SecOps/pull/2) | `devsecops-gate` | failure | **FAIL** |

- PASSED run: https://github.com/jhnnnp/K-SecOps/actions/runs/28291110142/job/83823148793
- FAILED run: https://github.com/jhnnnp/K-SecOps/actions/runs/28291145916/job/83823239141

## Gate comment snapshot (FAILED PR)

```text
<!-- devsecops-gate -->
**CI Gate:** FAILURE
# DevSecOps CI Gate: FAILED
## Multi-Track Scope
- Secrets scan (repo-wide): `.`
- SAST scan: `.`
- Dependency CVE scan: `requirements.txt, dummy-infra/deps`
- Infrastructure scan (fixture + self): `dummy-infra, Dockerfile`
## Scan Summary
- Infrastructure findings: **61** (critical=2, high=19)
- Secret findings: **8** (application code: **1**)
- SAST findings: **2** (application code: **0**)
```

## Validation

- PR #1 should be **green** (baseline dummy-infra only).
- PR #2 should be **red** (`src/main.py` intentional secret). Do not merge.

Regenerate locally:

```bash
export GH_TOKEN=$(gh auth token)   # after gh auth login
python3 scripts/sync_ci_evidence.py
```
