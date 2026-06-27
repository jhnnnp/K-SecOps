# Security Audit Report

**Agentic K-SecOps** · Compliance Self-Assessment (101통제 Lab Format)

| | |
|---|---|
| **Target** | `dummy-infra` |
| **Generated** | 2026-06-27 15:13 UTC |
| **Scanners** | audit_aws · audit_sast · audit_secrets · checkov · mask_pii · scan_dependencies · trivy |
| **Auditor** | Agentic K-SecOps MCP Pipeline |

---

## Executive Summary

| Metric | Value |
|--------|-------|
| ![Critical](https://img.shields.io/badge/Critical-3-D32F2F?style=flat-square) | **3** |
| ![High](https://img.shields.io/badge/High-25-F57C00?style=flat-square) | **25** |
| ![미흡_통제](https://img.shields.io/badge/미흡_통제-16-D32F2F?style=flat-square) | **16** controls |
| ![즉시_조치](https://img.shields.io/badge/즉시_조치-32-D32F2F?style=flat-square) | **32** actions |

> 배포 전 검증 결과, **즉시 조치 32건**이 확인되었습니다.

---

## Compliance Overview

| Status | Control | Framework | Category |
|--------|---------|-----------|----------|
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-2.7.2 암호키 관리 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 2.7. 암호화 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-2.7.1 암호정책 적용 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 2.7. 암호화 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | EFT-SEC-04 계정·접근 모니터링 | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) | 정보처리시스템 보호대책 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-2.5.1 사용자 계정 관리 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 2.5. 인증 및 권한관리 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | EFT-SEC-03 전송 구간 암호화 | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) | 해킹 등 방지대책 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-2.6.1 네트워크 접근통제 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 2.6. 접근통제 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | EFT-SEC-01 망분리·외부 접속 차단 | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) | 해킹 등 방지대책 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | EFT-SEC-05 정보보호시스템·침입방지 | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) | 해킹 등 방지대책 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-2.11.2 취약점 점검 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 2.11. 보안사고 예방 및 대응 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-3.2.3 개인정보 표시제한 및 이용 시 보호 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 3.2. 개인정보 보유 및 이용 시 보호조치 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | EFT-SEC-08 개인정보 안전조치 | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) | 개인정보보호 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | EFT-SEC-07 보호시스템 운영기록 보존 | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) | 로그·접속기록 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-2.10.9 악성코드 통제 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 2.10. 보안시스템 운영 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | EFT-SEC-06 취약점 분석·평가·패치 | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) | 취약점·패치 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-2.5.5 특권 계정 관리 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 2.5. 인증 및 권한관리 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-2.6.2 시스템 접근통제 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 2.6. 접근통제 |

---

## Findings Detail

101통제 셀프진단 Lab 형식: **진단 질문 → 결함 사유 → 권고 조치 → 필요 증적**

### F-001 · 암호키( AWS Access Key ) 평문 저장·노출

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/.env.leaked` |
| Scanner | `audit_secrets` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.7.2** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
암호키는 생성·보관·폐기 등 생명주기 전반에 걸쳐 안전하게 관리되고 있는가?

**결함 사유**  
암호키( AWS Access Key ) 평문 저장·노출

**결함 상세**  
dummy-infra/.env.leaked에서 AWS Access Key (AKIA***) 평문 탐지. Git·설정 파일 내 키 생명주기 관리 미준수.

**권고 조치**  
노출 키 즉시 deactivate·rotate. 이후 OPAQUE 프로토콜·E2EE 기반 Zero-Knowledge Vault(Envelo 아키텍처)로 시크릿 중앙화, 런타임 attested fetch만 허용 — env/소스코드 하드코딩 금지. audit_secrets CI gate 유지

**필요 증적**  
IAM 키 rotate 이력, Secrets Manager 마이그레이션 PR, git history purge 기록

---

### F-002 · 중요 정보 암호화·보호조치 미적용

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/.env.leaked` |
| Scanner | `audit_secrets` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.7.1** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
중요 정보는 저장·전송 시 암호화 등 보호조치를 적용하고 있는가?

**결함 사유**  
중요 정보 암호화·보호조치 미적용

**결함 상세**  
인증 자격증명이 dummy-infra/.env.leaked에 암호화 없이 저장됨.

**권고 조치**  
평문 env 주입 폐지. OPAQUE 기반 E2EE Vault에서 런타임 secret retrieval, KMS envelope는 Vault 내부 계층으로만 사용

**필요 증적**  
KMS 키 정책, SealedSecret/ESO manifest

---

### F-003 · 전자금융 암호키 관리 기준 미준수

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/.env.leaked` |
| Scanner | `audit_secrets` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-04** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
암호키·인증정보·관리자 계정이 안전하게 관리·모니터링되고 있는가?

**결함 사유**  
전자금융 암호키 관리 기준 미준수

**결함 상세**  
전산자원 접근 자격증명이 dummy-infra/.env.leaked에 평문 노출.

**권고 조치**  
Envelo-style E2EE secret vault 도입, git pre-commit(gitleaks)+CI dual-target gate. 평문 키는 rotate 후 vault migration ticket 생성

**필요 증적**  
키 관리 대장, gitleaks CI 통과 로그

---

### F-004 · 접근 자격증명 최소권한·안전 저장 미준수

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/.env.leaked` |
| Scanner | `audit_secrets` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.5.1** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
사용자 계정은 업무 수행에 필요한 최소한의 범위로 부여·관리되고 있는가?

**결함 사유**  
접근 자격증명 최소권한·안전 저장 미준수

**결함 상세**  
API Key가 dummy-infra/.env.leaked에 하드코딩. 접근권한 중앙 관리·회수 절차 미적용.

**권고 조치**  
API Key를 OPAQUE/E2EE Vault에 등록하고 scoped runtime fetch로 전환. audit_secrets gate + Envelo vault migration runbook

**필요 증적**  
키 rotate·폐기 이력, scoped key 정책

---

### F-005 · 인증 정보 암호화 저장 미적용

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/.env.leaked` |
| Scanner | `audit_secrets` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-03** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
중요 정보 저장·전송 시 암호화 등 보안대책이 수립되어 있는가?

**결함 사유**  
인증 정보 암호화 저장 미적용

**결함 상세**  
dummy-infra/.env.leaked에 API Key 평문 저장.

**권고 조치**  
Vault-at-rest E2EE + OPAQUE handshake 기반 secret delivery. 파일·env 직접 커밋 금지, CI repo-wide scan

**필요 증적**  
암호화 저장 설정 스크린샷, CI secret scan 통과

---

### F-006 · GitHub PAT 평문 저장·노출

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/.env.leaked` |
| Scanner | `audit_secrets` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.7.2** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
암호키는 생성·보관·폐기 등 생명주기 전반에 걸쳐 안전하게 관리되고 있는가?

**결함 사유**  
GitHub PAT 평문 저장·노출

**결함 상세**  
dummy-infra/.env.leaked에서 GitHub Personal Access Token (ghp_***) 평문 탐지.

**권고 조치**  
PAT 즉시 revoke·rotate. GitHub OIDC 또는 fine-grained token + Vault 저장, CI secret scan gate 유지

**필요 증적**  
PAT revoke 이력, OIDC 마이그레이션 PR

---

### F-007 · DB 접속 URL·비밀번호 평문 노출

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/.env.leaked` |
| Scanner | `audit_secrets` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.7.2** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
암호키는 생성·보관·폐기 등 생명주기 전반에 걸쳐 안전하게 관리되고 있는가?

**결함 사유**  
DB 접속 URL·비밀번호 평문 노출

**결함 상세**  
dummy-infra/.env.leaked에서 DB connection string with credentials 탐지.

**권고 조치**  
Secrets Manager / Vault로 credential 분리, connection string env 주입 금지

**필요 증적**  
Vault 마이그레이션 PR, audit_secrets 0건

---

### F-008 · S3 버킷 퍼블릭 접근 허용

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/aws/s3-public-bucket-policy.json` |
| Scanner | `audit_aws` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.6.1** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
네트워크 접근은 업무상 필요한 범위로 제한하고 있는가?

**결함 사유**  
S3 버킷 퍼블릭 접근 허용

**결함 상세**  
dummy-infra/aws/s3-public-bucket-policy.json에서 Principal:* 또는 PublicAccessBlock 미적용 확인.

**권고 조치**  
S3 Block Public Access 4종 활성화, bucket policy에서 Principal:* 제거

**필요 증적**  
PublicAccessBlock 설정 스크린샷, policy diff

---

### F-009 · 전산자원(스토리지) 외부 노출

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/aws/s3-public-bucket-policy.json` |
| Scanner | `audit_aws` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
내부 업무용시스템이 외부통신망과 분리·차단되어 있는가?

**결함 사유**  
전산자원(스토리지) 외부 노출

**결함 상세**  
AWS S3 dummy-infra/aws/s3-public-bucket-policy.json 외부 접근 가능 구성.

**권고 조치**  
Private bucket + CloudFront OAC 또는 VPC endpoint 경유

**필요 증적**  
bucket ACL/policy 재스캔 0건

---

### F-010 · IAM 정책 과다 권한 (Action:* Resource:*)

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/aws/iam-admin-policy.json` |
| Scanner | `audit_aws` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.5.1** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
사용자 계정은 업무 수행에 필요한 최소한의 범위로 부여·관리되고 있는가?

**결함 사유**  
IAM 정책 과다 권한 (Action:* Resource:*)

**결함 상세**  
dummy-infra/aws/iam-admin-policy.json IAM policy에 wildcard admin 권한 존재.

**권고 조치**  
Least privilege IAM, permission boundary 및 SCP 적용

**필요 증적**  
IAM policy simulator 결과, 최소권한 policy PR

---

### F-011 · AWS 접근통제

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/aws/iam-admin-policy.json` |
| Scanner | `audit_aws` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
내부 업무용시스템이 외부통신망과 분리·차단되어 있는가?

**결함 사유**  
AWS 접근통제 — 관리자 권한 과다

**결함 상세**  
dummy-infra/aws/iam-admin-policy.json에서 admin equivalent IAM policy 탐지.

**권고 조치**  
Role 분리, MFA 필수, admin role break-glass only

**필요 증적**  
IAM Access Analyzer finding closed

---

### F-012 · pickle.loads()

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/code/banking_api.py` |
| Scanner | `audit_sast` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-05** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
침입 시도 탐지·차단을 위한 정보보호시스템이 운영되고 있는가?

**결함 사유**  
pickle.loads() — unsafe deserialization (RCE)

**결함 상세**  
dummy-infra/code/banking_api.py:36에서 pickle.loads() 탐지.

**권고 조치**  
JSON/msgpack 등 안전한 직렬화 포맷 사용, 신뢰 경계 밖 데이터 역직렬화 금지

**필요 증적**  
audit_sast 재스캔 0건

---

### F-013 · 동적 코드 실행(eval) 사용

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/code/unsafe_sast.py` |
| Scanner | `audit_sast` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-05** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
침입 시도 탐지·차단을 위한 정보보호시스템이 운영되고 있는가?

**결함 사유**  
동적 코드 실행(eval) 사용

**결함 상세**  
dummy-infra/code/unsafe_sast.py:7에서 eval() 호출 탐지 — 코드 인젝션 위험.

**권고 조치**  
eval/exec 제거, allowlist 기반 파서 또는 AST safe literal eval로 대체

**필요 증적**  
SAST 재스캔 0건, 코드 리뷰 승인

---

### F-014 · exec()

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/code/unsafe_sast.py` |
| Scanner | `audit_sast` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-05** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
침입 시도 탐지·차단을 위한 정보보호시스템이 운영되고 있는가?

**결함 사유**  
exec() — dynamic code execution

**결함 상세**  
dummy-infra/code/unsafe_sast.py:8에서 exec() 호출 탐지.

**권고 조치**  
exec/eval 제거, allowlist 기반 파서로 대체

**필요 증적**  
audit_sast 재스캔 0건

---

### F-015 · os.system()

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/code/unsafe_sast.py` |
| Scanner | `audit_sast` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-05** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
침입 시도 탐지·차단을 위한 정보보호시스템이 운영되고 있는가?

**결함 사유**  
os.system() — OS command injection sink

**결함 상세**  
dummy-infra/code/unsafe_sast.py:9에서 os.system() 호출 탐지.

**권고 조치**  
subprocess.run(shell=False, argv list)로 대체, 입력값 검증

**필요 증적**  
audit_sast 재스캔 0건

---

### F-016 · pickle.loads()

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/code/unsafe_sast.py` |
| Scanner | `audit_sast` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-05** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
침입 시도 탐지·차단을 위한 정보보호시스템이 운영되고 있는가?

**결함 사유**  
pickle.loads() — unsafe deserialization (RCE)

**결함 상세**  
dummy-infra/code/unsafe_sast.py:10에서 pickle.loads() 탐지.

**권고 조치**  
JSON/msgpack 등 안전한 직렬화 포맷 사용, 신뢰 경계 밖 데이터 역직렬화 금지

**필요 증적**  
audit_sast 재스캔 0건

---

### F-017 · subprocess shell=True

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `dummy-infra/code/unsafe_sast.py` |
| Scanner | `audit_sast` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-05** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
침입 시도 탐지·차단을 위한 정보보호시스템이 운영되고 있는가?

**결함 사유**  
subprocess shell=True — OS command injection 위험

**결함 상세**  
dummy-infra/code/unsafe_sast.py:11에서 shell=True subprocess 탐지.

**권고 조치**  
shell=False + argv list, 입력값 shlex.quote 또는 allowlist 검증

**필요 증적**  
audit_sast 재스캔 0건

---

### F-018 · 애플리케이션 의존성 HIGH CVE 미패치

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `dummy-infra/deps/requirements.txt` |
| Scanner | `scan_dependencies` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.11.2** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
보안 취약점을 정기 점검하고 신속히 조치하고 있는가?

**결함 사유**  
애플리케이션 의존성 HIGH CVE 미패치

**결함 상세**  
dummy-infra/deps/requirements.txt에서 CVE-2019-11324 HIGH 취약점 탐지.

**권고 조치**  
pip-audit/Trivy CI gate 연동, 패치 버전 pin 및 Dependabot PR

**필요 증적**  
requirements lockfile diff, Trivy 0 HIGH 리포트

---

### F-019 · 로그 내 PII(주민등록번호) 평문 저장

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `dummy-infra/logs/app.log` |
| Scanner | `mask_pii` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-3.2.3** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
개인정보는 수집·이용 목적에 필요한 최소한의 범위 내에서 처리하고 있는가?

**결함 사유**  
로그 내 PII(주민등록번호) 평문 저장

**결함 상세**  
dummy-infra/logs/app.log에서 주민등록번호 1건 평문 확인. 수집·이용 목적 대비 과다 보관 및 마스킹 미적용.

**권고 조치**  
정규식·Presidio 기반 실시간 마스킹 파이프라인(mask_pii)을 로그 수집 단계(Fluent Bit/Filebeat)에 적용하고, 기존 로그 1건 로테이션·파기

**필요 증적**  
mask_pii 재스캔 결과(0건), 로그 파이프라인 설정 diff, 파기 이력

---

### F-020 · 개인정보 기술적 보호조치 미적용

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `dummy-infra/logs/app.log` |
| Scanner | `mask_pii` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-08** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
개인정보 기술적·관리적 보호조치가 적용되어 있는가?

**결함 사유**  
개인정보 기술적 보호조치 미적용

**결함 상세**  
애플리케이션 로그(dummy-infra/logs/app.log)에 식별 가능한 개인정보(주민등록번호) 1건 노출.

**권고 조치**  
저장·전송 구간 AES-256 암호화 및 로그 마스킹 정책 수립. mask_pii Tool 연동 CI gate 추가

**필요 증적**  
암호화·마스킹 정책서, 재스캔 0건 리포트

---

### F-021 · 접속·처리기록 내 개인정보 미마스킹

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `dummy-infra/logs/app.log` |
| Scanner | `mask_pii` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-07** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
접속·처리 기록이 생성·보관·보호되고 있는가?

**결함 사유**  
접속·처리기록 내 개인정보 미마스킹

**결함 상세**  
접속기록성 로그 dummy-infra/logs/app.log에 PII 1건 포함. 기록 보존 시 개인정보 보호 미흡.

**권고 조치**  
로그 적재 전 mask_pii 전처리 필수화, 보존 기간 경과분 자동 파기 cron 적용

**필요 증적**  
로그 파이프라인 아키텍처, 파기 스케줄 설정

---

### F-022 · 로그 내 금융 식별정보(계좌번호) 평문 저장

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `dummy-infra/logs/app.log` |
| Scanner | `mask_pii` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-3.2.3** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
개인정보는 수집·이용 목적에 필요한 최소한의 범위 내에서 처리하고 있는가?

**결함 사유**  
로그 내 금융 식별정보(계좌번호) 평문 저장

**결함 상세**  
dummy-infra/logs/app.log에서 계좌번호 패턴 1건 탐지. 금융권 로그 보관 기준 위반 가능.

**권고 조치**  
계좌번호 마스킹 규칙(앞 3자리+****+뒤 3자리) 적용 및 mask_pii entity ACCOUNT 활성화

**필요 증적**  
마스킹 규칙 문서, 재스캔 0건

---

### F-023 · 금융거래정보 보호조치 미흡

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `dummy-infra/logs/app.log` |
| Scanner | `mask_pii` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-08** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
개인정보 기술적·관리적 보호조치가 적용되어 있는가?

**결함 사유**  
금융거래정보 보호조치 미흡

**결함 상세**  
계좌번호 1건이 로그(dummy-infra/logs/app.log)에 평문 존재.

**권고 조치**  
전자금융거래정보 분류·마스킹 정책 수립, SIEM 적재 전 필터링

**필요 증적**  
정보 분류표, 마스킹 적용 증적

---

### F-024 · Critical CVE 미패치

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `deps/requirements.txt` |
| Scanner | `trivy` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.11.2** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
보안 취약점을 정기 점검하고 신속히 조치하고 있는가?

**결함 사유**  
Critical CVE 미패치 — 보안사고 예방 조치 미흡

**결함 상세**  
deps/requirements.txt에서 CVE-2019-11324 (CRITICAL) 탐지. 알려진 exploit 존재 가능.

**권고 조치**  
베이스 이미지 최신 LTS로 업데이트, trivy image CI gate (CRITICAL=0) 적용

**필요 증적**  
패치된 image digest, trivy 재스캔 리포트

---

### F-025 · 악성코드·취약점 통제

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `deps/requirements.txt` |
| Scanner | `trivy` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.10.9** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
악성코드 감염 예방·탐지·대응 절차가 수립·운영되고 있는가?

**결함 사유**  
악성코드·취약점 통제 — OS 패키지 취약

**결함 상세**  
deps/requirements.txt OS layer CVE-2019-11324 미패치.

**권고 조치**  
apt/yum upgrade in Dockerfile, distroless 또는 chainguard minimal base 전환

**필요 증적**  
SBOM, 패치 Dockerfile PR

---

### F-026 · 전자금융 취약점 관리 SLA 미준수

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `deps/requirements.txt` |
| Scanner | `trivy` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-06** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
보안 취약점을 정기 점검하고 신속히 조치하고 있는가?

**결함 사유**  
전자금융 취약점 관리 SLA 미준수

**결함 상세**  
Critical CVE CVE-2019-11324가 deps/requirements.txt에 잔존. 24h 이내 조치 기준 위반.

**권고 조치**  
CVE 대응 runbook 가동, emergency patch 배포, scan_infrastructure 일 1회 cron

**필요 증적**  
CVE ticket, 패치 배포 이력

---

### F-027 · 컨테이너 root(UID 0) 실행

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `docker/Dockerfile.insecure` |
| Scanner | `trivy` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.5.5** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
특권 계정은 최소화하고 사용·변경·모니터링 절차를 운영하고 있는가?

**결함 사유**  
컨테이너 root(UID 0) 실행

**결함 상세**  
docker/Dockerfile.insecure에서 USER root 또는 runAsUser: 0 확인. 침해 시 lateral movement 확대.

**권고 조치**  
Dockerfile USER 65534(nonroot), K8s runAsNonRoot: true + allowPrivilegeEscalation: false

**필요 증적**  
수정 Dockerfile/Deployment, 재스캔 통과

---

### F-028 · 워크로드 최소 권한 원칙 미적용

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `docker/Dockerfile.insecure` |
| Scanner | `trivy` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
내부 업무용시스템이 외부통신망과 분리·차단되어 있는가?

**결함 사유**  
워크로드 최소 권한 원칙 미적용

**결함 상세**  
docker/Dockerfile.insecure root 실행으로 파일시스템·프로세스 전체 접근 가능.

**권고 조치**  
readOnlyRootFilesystem: true, fsGroup·runAsUser non-zero 설정

**필요 증적**  
Pod spec diff

---

### F-029 · 컨테이너 root(UID 0) 실행

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `k8s/deployment-vulnerable.yaml` |
| Scanner | `trivy` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.5.5** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
특권 계정은 최소화하고 사용·변경·모니터링 절차를 운영하고 있는가?

**결함 사유**  
컨테이너 root(UID 0) 실행

**결함 상세**  
k8s/deployment-vulnerable.yaml에서 USER root 또는 runAsUser: 0 확인. 침해 시 lateral movement 확대.

**권고 조치**  
Dockerfile USER 65534(nonroot), K8s runAsNonRoot: true + allowPrivilegeEscalation: false

**필요 증적**  
수정 Dockerfile/Deployment, 재스캔 통과

---

### F-030 · 워크로드 최소 권한 원칙 미적용

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `k8s/deployment-vulnerable.yaml` |
| Scanner | `trivy` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
내부 업무용시스템이 외부통신망과 분리·차단되어 있는가?

**결함 사유**  
워크로드 최소 권한 원칙 미적용

**결함 상세**  
k8s/deployment-vulnerable.yaml root 실행으로 파일시스템·프로세스 전체 접근 가능.

**권고 조치**  
readOnlyRootFilesystem: true, fsGroup·runAsUser non-zero 설정

**필요 증적**  
Pod spec diff

---

### F-031 · 컨테이너 privileged 모드 사용

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `k8s/deployment-vulnerable.yaml` |
| Scanner | `trivy` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.6.2** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
정보시스템에 대한 비인가 접근을 방지하기 위한 통제가 적용되어 있는가?

**결함 사유**  
컨테이너 privileged 모드 사용 — 호스트 커널 접근 가능

**결함 상세**  
k8s/deployment-vulnerable.yaml에서 securityContext.privileged: true 설정. 컨테이너 탈출 시 호스트 전체 장악 위험.

**권고 조치**  
privileged: false 강제, Pod Security Standards 'restricted' enforce, scan_infrastructure CI gate

**필요 증적**  
수정된 manifest, Checkov 재스캔 0건

---

### F-032 · 특권(Privileged) 워크로드 미통제

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `k8s/deployment-vulnerable.yaml` |
| Scanner | `trivy` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.5.5** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
특권 계정은 최소화하고 사용·변경·모니터링 절차를 운영하고 있는가?

**결함 사유**  
특권(Privileged) 워크로드 미통제

**결함 상세**  
Pod(k8s/deployment-vulnerable.yaml)가 host-level capability 보유. 특권 계정 최소화 원칙 위반.

**권고 조치**  
capabilities drop ALL, allowlist 최소 capability만 부여

**필요 증적**  
securityContext diff, PSS audit log

---

### F-033 · 전산자원 접근통제

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `k8s/deployment-vulnerable.yaml` |
| Scanner | `trivy` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
내부 업무용시스템이 외부통신망과 분리·차단되어 있는가?

**결함 사유**  
전산자원 접근통제 — 컨테이너 격리 수준 미달

**결함 상세**  
k8s/deployment-vulnerable.yaml privileged 설정으로 namespace 경계 우회 가능.

**권고 조치**  
Gatekeeper/OPA policy: privileged 컨테이너 admission deny

**필요 증적**  
OPA policy manifest, 거부 테스트 로그

---

### F-034 · 접근 자격증명 최소권한·안전 저장 미준수

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `.env.leaked` |
| Scanner | `trivy` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.5.1** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
사용자 계정은 업무 수행에 필요한 최소한의 범위로 부여·관리되고 있는가?

**결함 사유**  
접근 자격증명 최소권한·안전 저장 미준수

**결함 상세**  
API Key가 .env.leaked에 하드코딩. 접근권한 중앙 관리·회수 절차 미적용.

**권고 조치**  
API Key를 OPAQUE/E2EE Vault에 등록하고 scoped runtime fetch로 전환. audit_secrets gate + Envelo vault migration runbook

**필요 증적**  
키 rotate·폐기 이력, scoped key 정책

---

### F-035 · 인증 정보 암호화 저장 미적용

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `.env.leaked` |
| Scanner | `trivy` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-03** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
중요 정보 저장·전송 시 암호화 등 보안대책이 수립되어 있는가?

**결함 사유**  
인증 정보 암호화 저장 미적용

**결함 상세**  
.env.leaked에 API Key 평문 저장.

**권고 조치**  
Vault-at-rest E2EE + OPAQUE handshake 기반 secret delivery. 파일·env 직접 커밋 금지, CI repo-wide scan

**필요 증적**  
암호화 저장 설정 스크린샷, CI secret scan 통과

---

### F-036 · 컨테이너 privileged 모드 사용

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/k8s/deployment-vulnerable.yaml` |
| Scanner | `checkov` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.6.2** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
정보시스템에 대한 비인가 접근을 방지하기 위한 통제가 적용되어 있는가?

**결함 사유**  
컨테이너 privileged 모드 사용 — 호스트 커널 접근 가능

**결함 상세**  
/k8s/deployment-vulnerable.yaml에서 securityContext.privileged: true 설정. 컨테이너 탈출 시 호스트 전체 장악 위험.

**권고 조치**  
privileged: false 강제, Pod Security Standards 'restricted' enforce, scan_infrastructure CI gate

**필요 증적**  
수정된 manifest, Checkov 재스캔 0건

---

### F-037 · 특권(Privileged) 워크로드 미통제

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/k8s/deployment-vulnerable.yaml` |
| Scanner | `checkov` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.5.5** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
특권 계정은 최소화하고 사용·변경·모니터링 절차를 운영하고 있는가?

**결함 사유**  
특권(Privileged) 워크로드 미통제

**결함 상세**  
Pod(/k8s/deployment-vulnerable.yaml)가 host-level capability 보유. 특권 계정 최소화 원칙 위반.

**권고 조치**  
capabilities drop ALL, allowlist 최소 capability만 부여

**필요 증적**  
securityContext diff, PSS audit log

---

### F-038 · 전산자원 접근통제

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/k8s/deployment-vulnerable.yaml` |
| Scanner | `checkov` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
내부 업무용시스템이 외부통신망과 분리·차단되어 있는가?

**결함 사유**  
전산자원 접근통제 — 컨테이너 격리 수준 미달

**결함 상세**  
/k8s/deployment-vulnerable.yaml privileged 설정으로 namespace 경계 우회 가능.

**권고 조치**  
Gatekeeper/OPA policy: privileged 컨테이너 admission deny

**필요 증적**  
OPA policy manifest, 거부 테스트 로그

---

### F-039 · 컨테이너 root(UID 0) 실행

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/docker/Dockerfile.insecure` |
| Scanner | `checkov` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.5.5** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
특권 계정은 최소화하고 사용·변경·모니터링 절차를 운영하고 있는가?

**결함 사유**  
컨테이너 root(UID 0) 실행

**결함 상세**  
/docker/Dockerfile.insecure에서 USER root 또는 runAsUser: 0 확인. 침해 시 lateral movement 확대.

**권고 조치**  
Dockerfile USER 65534(nonroot), K8s runAsNonRoot: true + allowPrivilegeEscalation: false

**필요 증적**  
수정 Dockerfile/Deployment, 재스캔 통과

---

### F-040 · 워크로드 최소 권한 원칙 미적용

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/docker/Dockerfile.insecure` |
| Scanner | `checkov` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
내부 업무용시스템이 외부통신망과 분리·차단되어 있는가?

**결함 사유**  
워크로드 최소 권한 원칙 미적용

**결함 상세**  
/docker/Dockerfile.insecure root 실행으로 파일시스템·프로세스 전체 접근 가능.

**권고 조치**  
readOnlyRootFilesystem: true, fsGroup·runAsUser non-zero 설정

**필요 증적**  
Pod spec diff

---

## Recommended Actions

### Immediate

| # | Action | Control | Tool |
|---|--------|---------|------|
| 1 | 노출 키 즉시 deactivate·rotate. 이후 OPAQUE 프로토콜·E2EE 기반 Zero-Knowledge Vault(Envelo 아키텍처)로 시크릿 중앙화 | ISMS-2.7.2 | `audit_secrets` |
| 2 | 평문 env 주입 폐지. OPAQUE 기반 E2EE Vault에서 런타임 secret retrieval | ISMS-2.7.1 | `audit_secrets` |
| 3 | Envelo-style E2EE secret vault 도입 | EFT-SEC-04 | `audit_secrets` |
| 4 | API Key를 OPAQUE/E2EE Vault에 등록하고 scoped runtime fetch로 전환. audit_secrets gate + Envelo vault migration runbook | ISMS-2.5.1 | `audit_secrets` |
| 5 | Vault-at-rest E2EE + OPAQUE handshake 기반 secret delivery. 파일·env 직접 커밋 금지 | EFT-SEC-03 | `audit_secrets` |
| 6 | PAT 즉시 revoke·rotate. GitHub OIDC 또는 fine-grained token + Vault 저장 | ISMS-2.7.2 | `audit_secrets` |
| 7 | Secrets Manager / Vault로 credential 분리 | ISMS-2.7.2 | `audit_secrets` |
| 8 | S3 Block Public Access 4종 활성화 | ISMS-2.6.1 | `audit_aws` |
| 9 | Private bucket + CloudFront OAC 또는 VPC endpoint 경유 | EFT-SEC-01 | `audit_aws` |
| 10 | Least privilege IAM | ISMS-2.5.1 | `audit_aws` |
| 11 | Role 분리 | EFT-SEC-01 | `audit_aws` |
| 12 | JSON/msgpack 등 안전한 직렬화 포맷 사용 | EFT-SEC-05 | `audit_sast` |
| 13 | eval/exec 제거 | EFT-SEC-05 | `audit_sast` |
| 14 | exec/eval 제거 | EFT-SEC-05 | `audit_sast` |
| 15 | subprocess.run(shell=False | EFT-SEC-05 | `audit_sast` |
| 16 | JSON/msgpack 등 안전한 직렬화 포맷 사용 | EFT-SEC-05 | `audit_sast` |
| 17 | shell=False + argv list | EFT-SEC-05 | `audit_sast` |
| 18 | 정규식·Presidio 기반 실시간 마스킹 파이프라인(mask_pii)을 로그 수집 단계(Fluent Bit/Filebeat)에 적용하고 | ISMS-3.2.3 | `mask_pii` |
| 19 | 저장·전송 구간 AES-256 암호화 및 로그 마스킹 정책 수립. mask_pii Tool 연동 CI gate 추가 | EFT-SEC-08 | `mask_pii` |
| 20 | 계좌번호 마스킹 규칙(앞 3자리+****+뒤 3자리) 적용 및 mask_pii entity ACCOUNT 활성화 | ISMS-3.2.3 | `mask_pii` |
| 21 | 전자금융거래정보 분류·마스킹 정책 수립 | EFT-SEC-08 | `mask_pii` |
| 22 | 베이스 이미지 최신 LTS로 업데이트 | ISMS-2.11.2 | `scan_infrastructure` |
| 23 | apt/yum upgrade in Dockerfile | ISMS-2.10.9 | `scan_infrastructure` |
| 24 | CVE 대응 runbook 가동 | EFT-SEC-06 | `scan_infrastructure` |
| 25 | privileged: false 강제 | ISMS-2.6.2 | `scan_infrastructure` |
| 26 | capabilities drop ALL | ISMS-2.5.5 | `scan_infrastructure` |
| 27 | Gatekeeper/OPA policy: privileged 컨테이너 admission deny | EFT-SEC-01 | `scan_infrastructure` |
| 28 | API Key를 OPAQUE/E2EE Vault에 등록하고 scoped runtime fetch로 전환. audit_secrets gate + Envelo vault migration runbook | ISMS-2.5.1 | `audit_secrets` |
| 29 | Vault-at-rest E2EE + OPAQUE handshake 기반 secret delivery. 파일·env 직접 커밋 금지 | EFT-SEC-03 | `audit_secrets` |
| 30 | privileged: false 강제 | ISMS-2.6.2 | `scan_infrastructure` |
| 31 | capabilities drop ALL | ISMS-2.5.5 | `scan_infrastructure` |
| 32 | Gatekeeper/OPA policy: privileged 컨테이너 admission deny | EFT-SEC-01 | `scan_infrastructure` |

### Short-term

| # | Action | Control | Tool |
|---|--------|---------|------|
| 1 | pip-audit/Trivy CI gate 연동 | ISMS-2.11.2 | `scan_dependencies` |
| 2 | 로그 적재 전 mask_pii 전처리 필수화 | EFT-SEC-07 | `mask_pii` |
| 3 | Dockerfile USER 65534(nonroot) | ISMS-2.5.5 | `scan_infrastructure` |
| 4 | readOnlyRootFilesystem: true | EFT-SEC-01 | `scan_infrastructure` |
| 5 | Dockerfile USER 65534(nonroot) | ISMS-2.5.5 | `scan_infrastructure` |
| 6 | readOnlyRootFilesystem: true | EFT-SEC-01 | `scan_infrastructure` |
| 7 | Dockerfile USER 65534(nonroot) | ISMS-2.5.5 | `scan_infrastructure` |
| 8 | readOnlyRootFilesystem: true | EFT-SEC-01 | `scan_infrastructure` |

---

*Report generated by Agentic K-SecOps. Deficiency reasons and recommended actions are sourced verbatim from `src/compliance/finding_rules.json`.*
