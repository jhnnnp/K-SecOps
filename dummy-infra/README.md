# dummy-infra

의도적 취약점이 포함된 시연용 인프라 아티팩트. **실제 자격증명·PII가 아닌 Faker 스타일 더미 데이터만 사용.**

## Scenario Map (5종)

| # | 파일 | 취약점 | 기대 Tool | 규정 매핑 |
|---|------|--------|-----------|-----------|
| 1 | `docker/Dockerfile.insecure` | USER root, outdated base | `scan_infrastructure` (Trivy) | ISMS-2.5.5, container.run_as_root |
| 2 | `k8s/deployment-vulnerable.yaml` | privileged (CKV_K8S_16), root (CKV_K8S_23), hostPath | `scan_infrastructure` (Checkov) | ISMS-2.5.5, k8s.privileged_container |
| 3 | `k8s/service-nodeport.yaml` | NodePort 외부 노출 (CIS/K8s hardening) | `scan_infrastructure` (Checkov) | ISMS-2.6.1 |
| 4 | `logs/app.log` | PII 평문 (RRN, 계좌, 전화, 이메일) | `mask_pii` | ISMS-3.2.3, EFT-SEC-08 |
| 5 | `.env.leaked` | AWS Key, API Key, GitHub PAT, JWT, DB URL, Slack webhook | `audit_secrets` | ISMS-2.7.2, EFT-SEC-04 |
| 6 | `deps/requirements.txt` | Known HIGH/CRITICAL CVEs (urllib3 pin) | `scan_dependencies` | ISMS-2.11.2 |
| 7 | `code/unsafe_sast.py` | eval(), exec(), os.system, pickle.loads, shell=True | `audit_sast` | EFT-SEC-05 |
| 8 | `code/banking_api.py` | SQLi, SSRF, weak crypto, pickle, PII logging | `audit_sast` (Semgrep) | EFT-SEC-05 |
| 9 | `terraform/s3-insecure.tf` | public S3 ACL, open SG, no PAB | `scan_infrastructure` (Checkov) | ISMS-2.6.1 |

## Quick verify

```bash
PYTHONPATH=src python3 scripts/run_demo.py
```

## Notes

- `test_log.txt`는 Phase 1.1 호환용 별칭 (내용 동일)
- 배포·커밋 금지 — 로컬 시연 전용
