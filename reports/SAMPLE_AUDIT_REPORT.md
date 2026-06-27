# Security Audit Report

**Agentic K-SecOps** · Compliance Self-Assessment (101통제 Lab Format)

| | |
|---|---|
| **Target** | `dummy-infra` |
| **Generated** | 2026-06-27 13:05 UTC |
| **Scanners** | audit_aws · audit_secrets · checkov · mask_pii · trivy |
| **Auditor** | Agentic K-SecOps MCP Pipeline |

---

## Executive Summary

| Metric | Value |
|--------|-------|
| ![Critical](https://img.shields.io/badge/Critical-0-D32F2F?style=flat-square) | **0** |
| ![High](https://img.shields.io/badge/High-12-F57C00?style=flat-square) | **12** |
| ![미흡_통제](https://img.shields.io/badge/미흡_통제-13-D32F2F?style=flat-square) | **13** controls |
| ![즉시_조치](https://img.shields.io/badge/즉시_조치-19-D32F2F?style=flat-square) | **19** actions |

> 배포 전 검증 결과, **즉시 조치 19건**이 확인되었습니다.

---

## Compliance Overview

| Status | Control | Framework | Category |
|--------|---------|-----------|----------|
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-2.9.2 암호키 관리 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 2.9. 암호화 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-2.9.1 암호화 정책 수립 및 적용 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 2.9. 암호화 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | EFT-SEC-04 암호키·인증서 관리 | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) | 키관리 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-2.5.1 정보시스템 접근권한 관리 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 2.5. 접근통제 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | EFT-SEC-03 암호화 적용 | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) | 암호화 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-2.7.1 네트워크 접근통제 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 2.7. 침입방지 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | EFT-SEC-01 전산자원 접근통제 | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) | 접근통제 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-2.10.1 개인정보 수집·이용 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 2.10. 개인정보 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | EFT-SEC-08 개인정보보호 | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) | 개인정보 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | EFT-SEC-07 로그·접속기록 관리 | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) | 로그 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-2.5.2 특권(Privileged) 계정 관리 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 2.5. 접근통제 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | ISMS-2.7.2 시스템 접근통제 | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) | 2.7. 침입방지 |
| ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) | EFT-SEC-05 침입탐지·방지 | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) | 침입방지 |

---

## Findings Detail

101통제 셀프진단 Lab 형식: **진단 질문 → 결함 사유 → 권고 조치 → 필요 증적**

### F-001 · 암호키( AWS Access Key ) 평문 저장·노출

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/.env.leaked` |
| Scanner | `audit_secrets` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.9.2** |
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
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.9.1** |
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
암호키·인증서는 안전하게 생성·보관·갱신·폐기하고 있는가?

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
정보시스템 접근권한은 업무 수행에 필요한 최소한의 범위로 부여·관리되고 있는가?

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
중요 정보의 저장·전송 시 업무상 허용 가능한 암호알고리즘으로 암호화하고 있는가?

**결함 사유**  
인증 정보 암호화 저장 미적용

**결함 상세**  
dummy-infra/.env.leaked에 API Key 평문 저장.

**권고 조치**  
Vault-at-rest E2EE + OPAQUE handshake 기반 secret delivery. 파일·env 직접 커밋 금지, CI repo-wide scan

**필요 증적**  
암호화 저장 설정 스크린샷, CI secret scan 통과

---

### F-006 · S3 버킷 퍼블릭 접근 허용

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/aws/s3-public-bucket-policy.json` |
| Scanner | `audit_aws` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.7.1** |
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

### F-007 · 전산자원(스토리지) 외부 노출

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/aws/s3-public-bucket-policy.json` |
| Scanner | `audit_aws` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
전산자원에 대한 접근은 승인된 자만, 필요한 범위 내에서 가능하도록 통제하고 있는가?

**결함 사유**  
전산자원(스토리지) 외부 노출

**결함 상세**  
AWS S3 dummy-infra/aws/s3-public-bucket-policy.json 외부 접근 가능 구성.

**권고 조치**  
Private bucket + CloudFront OAC 또는 VPC endpoint 경유

**필요 증적**  
bucket ACL/policy 재스캔 0건

---

### F-008 · IAM 정책 과다 권한 (Action:* Resource:*)

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/aws/iam-admin-policy.json` |
| Scanner | `audit_aws` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.5.1** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
정보시스템 접근권한은 업무 수행에 필요한 최소한의 범위로 부여·관리되고 있는가?

**결함 사유**  
IAM 정책 과다 권한 (Action:* Resource:*)

**결함 상세**  
dummy-infra/aws/iam-admin-policy.json IAM policy에 wildcard admin 권한 존재.

**권고 조치**  
Least privilege IAM, permission boundary 및 SCP 적용

**필요 증적**  
IAM policy simulator 결과, 최소권한 policy PR

---

### F-009 · AWS 접근통제

| Field | Detail |
|-------|--------|
| Severity | ![CRITICAL](https://img.shields.io/badge/CRITICAL-D32F2F?style=flat-square) |
| Resource | `dummy-infra/aws/iam-admin-policy.json` |
| Scanner | `audit_aws` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
전산자원에 대한 접근은 승인된 자만, 필요한 범위 내에서 가능하도록 통제하고 있는가?

**결함 사유**  
AWS 접근통제 — 관리자 권한 과다

**결함 상세**  
dummy-infra/aws/iam-admin-policy.json에서 admin equivalent IAM policy 탐지.

**권고 조치**  
Role 분리, MFA 필수, admin role break-glass only

**필요 증적**  
IAM Access Analyzer finding closed

---

### F-010 · 로그 내 PII(주민등록번호) 평문 저장

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `dummy-infra/logs/app.log` |
| Scanner | `mask_pii` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.10.1** |
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

### F-011 · 개인정보 기술적 보호조치 미적용

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `dummy-infra/logs/app.log` |
| Scanner | `mask_pii` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-08** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
개인정보를 안전하게 처리하기 위한 기술적·관리적 보호조치를 적용하고 있는가?

**결함 사유**  
개인정보 기술적 보호조치 미적용

**결함 상세**  
애플리케이션 로그(dummy-infra/logs/app.log)에 식별 가능한 개인정보(주민등록번호) 1건 노출.

**권고 조치**  
저장·전송 구간 AES-256 암호화 및 로그 마스킹 정책 수립. mask_pii Tool 연동 CI gate 추가

**필요 증적**  
암호화·마스킹 정책서, 재스캔 0건 리포트

---

### F-012 · 접속·처리기록 내 개인정보 미마스킹

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `dummy-infra/logs/app.log` |
| Scanner | `mask_pii` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-07** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
전산자원 접속·처리 기록을 생성·보관·보호하고 있는가?

**결함 사유**  
접속·처리기록 내 개인정보 미마스킹

**결함 상세**  
접속기록성 로그 dummy-infra/logs/app.log에 PII 1건 포함. 기록 보존 시 개인정보 보호 미흡.

**권고 조치**  
로그 적재 전 mask_pii 전처리 필수화, 보존 기간 경과분 자동 파기 cron 적용

**필요 증적**  
로그 파이프라인 아키텍처, 파기 스케줄 설정

---

### F-013 · 로그 내 금융 식별정보(계좌번호) 평문 저장

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `dummy-infra/logs/app.log` |
| Scanner | `mask_pii` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.10.1** |
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

### F-014 · 금융거래정보 보호조치 미흡

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `dummy-infra/logs/app.log` |
| Scanner | `mask_pii` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-08** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
개인정보를 안전하게 처리하기 위한 기술적·관리적 보호조치를 적용하고 있는가?

**결함 사유**  
금융거래정보 보호조치 미흡

**결함 상세**  
계좌번호 1건이 로그(dummy-infra/logs/app.log)에 평문 존재.

**권고 조치**  
전자금융거래정보 분류·마스킹 정책 수립, SIEM 적재 전 필터링

**필요 증적**  
정보 분류표, 마스킹 적용 증적

---

### F-015 · 컨테이너 root(UID 0) 실행

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `docker/Dockerfile.insecure` |
| Scanner | `trivy` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.5.2** |
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

### F-016 · 워크로드 최소 권한 원칙 미적용

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `docker/Dockerfile.insecure` |
| Scanner | `trivy` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
전산자원에 대한 접근은 승인된 자만, 필요한 범위 내에서 가능하도록 통제하고 있는가?

**결함 사유**  
워크로드 최소 권한 원칙 미적용

**결함 상세**  
docker/Dockerfile.insecure root 실행으로 파일시스템·프로세스 전체 접근 가능.

**권고 조치**  
readOnlyRootFilesystem: true, fsGroup·runAsUser non-zero 설정

**필요 증적**  
Pod spec diff

---

### F-017 · 컨테이너 root(UID 0) 실행

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `k8s/deployment-vulnerable.yaml` |
| Scanner | `trivy` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.5.2** |
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

### F-018 · 워크로드 최소 권한 원칙 미적용

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `k8s/deployment-vulnerable.yaml` |
| Scanner | `trivy` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
전산자원에 대한 접근은 승인된 자만, 필요한 범위 내에서 가능하도록 통제하고 있는가?

**결함 사유**  
워크로드 최소 권한 원칙 미적용

**결함 상세**  
k8s/deployment-vulnerable.yaml root 실행으로 파일시스템·프로세스 전체 접근 가능.

**권고 조치**  
readOnlyRootFilesystem: true, fsGroup·runAsUser non-zero 설정

**필요 증적**  
Pod spec diff

---

### F-019 · 컨테이너 privileged 모드 사용

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `k8s/deployment-vulnerable.yaml` |
| Scanner | `trivy` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.7.2** |
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

### F-020 · 특권(Privileged) 워크로드 미통제

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `k8s/deployment-vulnerable.yaml` |
| Scanner | `trivy` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.5.2** |
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

### F-021 · 전산자원 접근통제

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `k8s/deployment-vulnerable.yaml` |
| Scanner | `trivy` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
전산자원에 대한 접근은 승인된 자만, 필요한 범위 내에서 가능하도록 통제하고 있는가?

**결함 사유**  
전산자원 접근통제 — 컨테이너 격리 수준 미달

**결함 상세**  
k8s/deployment-vulnerable.yaml privileged 설정으로 namespace 경계 우회 가능.

**권고 조치**  
Gatekeeper/OPA policy: privileged 컨테이너 admission deny

**필요 증적**  
OPA policy manifest, 거부 테스트 로그

---

### F-022 · Kubernetes NetworkPolicy 미적용

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/k8s/deployment-vulnerable.yaml` |
| Scanner | `checkov` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.7.1** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
네트워크 접근은 업무상 필요한 범위로 제한하고 있는가?

**결함 사유**  
Kubernetes NetworkPolicy 미적용 — default allow

**결함 상세**  
Namespace(/k8s/deployment-vulnerable.yaml)에 NetworkPolicy 없음. Pod 간 lateral movement 제한 불가.

**권고 조치**  
default deny ingress/egress NetworkPolicy 적용, 필요 트래픽만 allowlist

**필요 증적**  
NetworkPolicy YAML, connectivity test 결과

---

### F-023 · 마이크로세그멘테이션·침입방지 미적용

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/k8s/deployment-vulnerable.yaml` |
| Scanner | `checkov` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-05** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
침입 시도를 탐지·차단하기 위한 기술적·관리적 보호조치를 적용하고 있는가?

**결함 사유**  
마이크로세그멘테이션·침입방지 미적용

**결함 상세**  
/k8s/deployment-vulnerable.yaml 전 구간 open. 침입 시 확산 경로 차단 불가.

**권고 조치**  
Cilium/Calico network policy, service mesh mTLS 병행

**필요 증적**  
망분리 아키텍처, policy audit

---

### F-024 · 컨테이너 root(UID 0) 실행

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/k8s/deployment-vulnerable.yaml` |
| Scanner | `checkov` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.5.2** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
특권 계정은 최소화하고 사용·변경·모니터링 절차를 운영하고 있는가?

**결함 사유**  
컨테이너 root(UID 0) 실행

**결함 상세**  
/k8s/deployment-vulnerable.yaml에서 USER root 또는 runAsUser: 0 확인. 침해 시 lateral movement 확대.

**권고 조치**  
Dockerfile USER 65534(nonroot), K8s runAsNonRoot: true + allowPrivilegeEscalation: false

**필요 증적**  
수정 Dockerfile/Deployment, 재스캔 통과

---

### F-025 · 워크로드 최소 권한 원칙 미적용

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/k8s/deployment-vulnerable.yaml` |
| Scanner | `checkov` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
전산자원에 대한 접근은 승인된 자만, 필요한 범위 내에서 가능하도록 통제하고 있는가?

**결함 사유**  
워크로드 최소 권한 원칙 미적용

**결함 상세**  
/k8s/deployment-vulnerable.yaml root 실행으로 파일시스템·프로세스 전체 접근 가능.

**권고 조치**  
readOnlyRootFilesystem: true, fsGroup·runAsUser non-zero 설정

**필요 증적**  
Pod spec diff

---

### F-026 · 컨테이너 privileged 모드 사용

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/k8s/deployment-vulnerable.yaml` |
| Scanner | `checkov` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.7.2** |
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

### F-027 · 특권(Privileged) 워크로드 미통제

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/k8s/deployment-vulnerable.yaml` |
| Scanner | `checkov` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.5.2** |
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

### F-028 · 전산자원 접근통제

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/k8s/deployment-vulnerable.yaml` |
| Scanner | `checkov` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![즉시](https://img.shields.io/badge/조치우선순위-즉시-D32F2F?style=flat-square) |

**진단 질문 (Lab)**  
전산자원에 대한 접근은 승인된 자만, 필요한 범위 내에서 가능하도록 통제하고 있는가?

**결함 사유**  
전산자원 접근통제 — 컨테이너 격리 수준 미달

**결함 상세**  
/k8s/deployment-vulnerable.yaml privileged 설정으로 namespace 경계 우회 가능.

**권고 조치**  
Gatekeeper/OPA policy: privileged 컨테이너 admission deny

**필요 증적**  
OPA policy manifest, 거부 테스트 로그

---

### F-029 · 불필요한 NodePort Service 노출

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/k8s/deployment-vulnerable.yaml` |
| Scanner | `checkov` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.7.1** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
네트워크 접근은 업무상 필요한 범위로 제한하고 있는가?

**결함 사유**  
불필요한 NodePort Service 노출

**결함 상세**  
/k8s/deployment-vulnerable.yaml NodePort type Service로 호스트 포트 직접 바인딩.

**권고 조치**  
ClusterIP + Ingress(TLS) 전환, NodePort 사용 시 IP allowlist

**필요 증적**  
Service spec diff, port scan 결과

---

### F-030 · 전산자원 외부 노출 범위 과다

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/k8s/deployment-vulnerable.yaml` |
| Scanner | `checkov` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
전산자원에 대한 접근은 승인된 자만, 필요한 범위 내에서 가능하도록 통제하고 있는가?

**결함 사유**  
전산자원 외부 노출 범위 과다

**결함 상세**  
/k8s/deployment-vulnerable.yaml 불필요 외부 접점 존재.

**권고 조치**  
WAF·API Gateway 경유, 내부 전용 서비스는 headless ClusterIP

**필요 증적**  
노출 포트 inventory, WAF rule

---

### F-031 · 컨테이너 root(UID 0) 실행

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/docker/Dockerfile.insecure` |
| Scanner | `checkov` |
| Framework | ![ISMS-P](https://img.shields.io/badge/-ISMS--P-1565C0?style=flat-square) **ISMS-2.5.2** |
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

### F-032 · 워크로드 최소 권한 원칙 미적용

| Field | Detail |
|-------|--------|
| Severity | ![HIGH](https://img.shields.io/badge/HIGH-F57C00?style=flat-square) |
| Resource | `/docker/Dockerfile.insecure` |
| Scanner | `checkov` |
| Framework | ![EFT](https://img.shields.io/badge/-전자금융-E65100?style=flat-square) **EFT-SEC-01** |
| Status | ![미흡](https://img.shields.io/badge/진단결과-미흡-D32F2F?style=flat-square) |
| Priority | ![단기](https://img.shields.io/badge/조치우선순위-단기-F57C00?style=flat-square) |

**진단 질문 (Lab)**  
전산자원에 대한 접근은 승인된 자만, 필요한 범위 내에서 가능하도록 통제하고 있는가?

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
| 1 | 노출 키 즉시 deactivate·rotate. 이후 OPAQUE 프로토콜·E2EE 기반 Zero-Knowledge Vault(Envelo 아키텍처)로 시크릿 중앙화 | ISMS-2.9.2 | `audit_secrets` |
| 2 | 평문 env 주입 폐지. OPAQUE 기반 E2EE Vault에서 런타임 secret retrieval | ISMS-2.9.1 | `audit_secrets` |
| 3 | Envelo-style E2EE secret vault 도입 | EFT-SEC-04 | `audit_secrets` |
| 4 | API Key를 OPAQUE/E2EE Vault에 등록하고 scoped runtime fetch로 전환. audit_secrets gate + Envelo vault migration runbook | ISMS-2.5.1 | `audit_secrets` |
| 5 | Vault-at-rest E2EE + OPAQUE handshake 기반 secret delivery. 파일·env 직접 커밋 금지 | EFT-SEC-03 | `audit_secrets` |
| 6 | S3 Block Public Access 4종 활성화 | ISMS-2.7.1 | `audit_aws` |
| 7 | Private bucket + CloudFront OAC 또는 VPC endpoint 경유 | EFT-SEC-01 | `audit_aws` |
| 8 | Least privilege IAM | ISMS-2.5.1 | `audit_aws` |
| 9 | Role 분리 | EFT-SEC-01 | `audit_aws` |
| 10 | 정규식·Presidio 기반 실시간 마스킹 파이프라인(mask_pii)을 로그 수집 단계(Fluent Bit/Filebeat)에 적용하고 | ISMS-2.10.1 | `mask_pii` |
| 11 | 저장·전송 구간 AES-256 암호화 및 로그 마스킹 정책 수립. mask_pii Tool 연동 CI gate 추가 | EFT-SEC-08 | `mask_pii` |
| 12 | 계좌번호 마스킹 규칙(앞 3자리+****+뒤 3자리) 적용 및 mask_pii entity ACCOUNT 활성화 | ISMS-2.10.1 | `mask_pii` |
| 13 | 전자금융거래정보 분류·마스킹 정책 수립 | EFT-SEC-08 | `mask_pii` |
| 14 | privileged: false 강제 | ISMS-2.7.2 | `scan_infrastructure` |
| 15 | capabilities drop ALL | ISMS-2.5.2 | `scan_infrastructure` |
| 16 | Gatekeeper/OPA policy: privileged 컨테이너 admission deny | EFT-SEC-01 | `scan_infrastructure` |
| 17 | privileged: false 강제 | ISMS-2.7.2 | `scan_infrastructure` |
| 18 | capabilities drop ALL | ISMS-2.5.2 | `scan_infrastructure` |
| 19 | Gatekeeper/OPA policy: privileged 컨테이너 admission deny | EFT-SEC-01 | `scan_infrastructure` |

### Short-term

| # | Action | Control | Tool |
|---|--------|---------|------|
| 1 | 로그 적재 전 mask_pii 전처리 필수화 | EFT-SEC-07 | `mask_pii` |
| 2 | Dockerfile USER 65534(nonroot) | ISMS-2.5.2 | `scan_infrastructure` |
| 3 | readOnlyRootFilesystem: true | EFT-SEC-01 | `scan_infrastructure` |
| 4 | Dockerfile USER 65534(nonroot) | ISMS-2.5.2 | `scan_infrastructure` |
| 5 | readOnlyRootFilesystem: true | EFT-SEC-01 | `scan_infrastructure` |
| 6 | default deny ingress/egress NetworkPolicy 적용 | ISMS-2.7.1 | `scan_infrastructure` |
| 7 | Cilium/Calico network policy | EFT-SEC-05 | `scan_infrastructure` |
| 8 | Dockerfile USER 65534(nonroot) | ISMS-2.5.2 | `scan_infrastructure` |
| 9 | readOnlyRootFilesystem: true | EFT-SEC-01 | `scan_infrastructure` |
| 10 | ClusterIP + Ingress(TLS) 전환 | ISMS-2.7.1 | `scan_infrastructure` |
| 11 | WAF·API Gateway 경유 | EFT-SEC-01 | `scan_infrastructure` |
| 12 | Dockerfile USER 65534(nonroot) | ISMS-2.5.2 | `scan_infrastructure` |
| 13 | readOnlyRootFilesystem: true | EFT-SEC-01 | `scan_infrastructure` |

---

*Report generated by Agentic K-SecOps. Deficiency reasons and recommended actions are sourced verbatim from `src/compliance/finding_rules.json`.*
