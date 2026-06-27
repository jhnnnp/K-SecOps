# CI Evidence (auto-synced)

_Last updated: 2026-06-27 15:33 UTC_

![SecOps Gate workflow](https://img.shields.io/github/actions/workflow/status/jhnnnp/K-SecOps/secops-gate.yml?branch=main&label=SecOps%20Gate)

## Demo PR status

| Demo | PR | Check | Expected | Actual |
|------|-----|-------|----------|--------|
| PASSED | [#1](https://github.com/jhnnnp/K-SecOps/pull/1) | `K-SecOps-SAST` | success | **PASS** |
| FAILED (intentional) | [#2](https://github.com/jhnnnp/K-SecOps/pull/2) | `K-SecOps-SAST` | failure | **SUCCESS** |

- PASSED run: https://github.com/jhnnnp/K-SecOps/runs/83829555281
- FAILED run: https://github.com/jhnnnp/K-SecOps/runs/83829611500

## Gate comment snapshot (FAILED PR)

```text
<!-- devsecops-gate -->
**CI Gate:** FAILURE
# DevSecOps CI Gate: FAILED
## Multi-Track Scope
- Secrets scan (repo-wide): `.`
- SAST scan (`semgrep`): `.`
- SCA / Dependency CVE scan (Trivy vuln DB): `requirements.txt, dummy-infra/deps`
- SBOM drift gate: `requirements.txt` (5 direct deps, baseline 5)
- Infrastructure scan (fixture + self): `dummy-infra, Dockerfile`
## Risk Score
- Composite risk: **100/100** (CRITICAL)
- Blockers: **1**
```

## Validation

- PR #1 should be **green** (baseline dummy-infra only).
- PR #2 should be **red** (`src/main.py` intentional secret). Do not merge.

Regenerate locally:

```bash
export GH_TOKEN=$(gh auth token)   # after gh auth login
python3 scripts/sync_ci_evidence.py
```
