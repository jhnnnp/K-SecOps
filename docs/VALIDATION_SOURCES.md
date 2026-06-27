# Validation Sources — 팩트 검증 근거

프로젝트의 취약점·스캔 결과·규정 매핑이 **실제 가이드/DB/사례**와 어떻게 대응하는지 정리한다.  
면접 스크립트가 아니라 **출처 기반 검증 문서**다.

---

## 1. 스캐너 탐지 — 검증됨 (실제 CVE/룰/정책)

### SCA / CVE (`dummy-infra/deps/requirements.txt`)

| Fixture | 검증 방법 | 공식 근거 |
|---------|-----------|-----------|
| `urllib3==1.24.1` | 로컬 Trivy 스캔 → HIGH+ 6건 | [NVD CVE-2019-11324](https://nvd.nist.gov/vuln/detail/CVE-2019-11324), [CVE-2019-11236](https://nvd.nist.gov/vuln/detail/CVE-2019-11236), [OSV urllib3](https://osv.dev/list?ecosystem=PyPI&name=urllib3) |

실행 확인:
```bash
PYTHONPATH=src python3 -c "from tools.scan_dependencies import scan_dependencies; ..."
# → TRIVY-CVE-2019-11324 HIGH, CVE-2023-43804 HIGH, ...
```

### SAST — Semgrep (`dummy-infra/code/`)

| 패턴 | Semgrep rule ID | 표준 매핑 |
|------|-----------------|-----------|
| `eval()` | `python.lang.security.audit.eval-detected.eval-detected` | OWASP A03 Injection, CWE-95 |
| `exec()` | `python.lang.security.audit.exec-detected.exec-detected` | [Semgrep Python injection cheat sheet](https://semgrep.dev/docs/cheat-sheets/python-code-injection) |
| `subprocess shell=True` | `subprocess-shell-true` | OWASP A03, CWE-78 OS Command Injection |
| `pickle.loads()` | `avoid-pickle` (generic) | CWE-502 Deserialization |

### IaC — Checkov

| Fixture | Checkov ID | 공식 정책명 | 근거 |
|---------|------------|-------------|------|
| `k8s/deployment-vulnerable.yaml` `privileged: true` | **CKV_K8S_16** | Container should not be privileged | [Checkov K8s index](https://www.checkov.io/5.Policy%20Index/kubernetes.html) |
| same file `runAsUser: 0` | **CKV_K8S_23** | Minimize admission of root containers | 동일 |
| `terraform/s3-insecure.tf` `acl = "public-read"` | **CKV_AWS_20** | S3 public READ ACL | [Checkov Terraform index](https://www.checkov.io/5.Policy%20Index/terraform.html) |
| PAB all `false` | **CKV_AWS_53~56** | Block public access | [AWS CodeGuru detector](https://docs.aws.amazon.com/codeguru/detector-library/terraform/public-read-bucket-acl-terraform/) |

### AWS 정책 JSON

| Fixture | 실제 위험 | 근거 |
|---------|-----------|------|
| `s3-public-bucket-policy.json` `Principal: "*"` | 익명 S3 객체 읽기 허용 | [AWS S3 bucket policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html), CIS AWS Benchmark |
| `iam-admin-policy.json` `Action: "*"` | IAM 과권한 | AWS IAM best practices, least privilege |

### 앱 취약 패턴 (`banking_api.py`)

| 코드 | CWE | 실제 사례 유형 |
|------|-----|----------------|
| f-string SQL `execute(query)` | CWE-89 SQL Injection | OWASP Top 10 A03 |
| `requests.get(user_url)` | CWE-918 SSRF | OWASP API Security |
| `hashlib.md5(pin)` | CWE-328 weak hash | NIST SP 800-131A (MD5 금지) |
| `pickle.loads(token)` | CWE-502 | Python RCE via pickle (공개 CVE 다수) |
| 로그에 RRN/계좌 | CWE-532 log injection / PII exposure | 개인정보보호법, 금융권 로그 가이드 |

---

## 2. 공급망 / 표준 포맷 — 검증됨

| 기능 | 표준 | 근거 |
|------|------|------|
| CycloneDX SBOM (`generate_sbom.py`) | CycloneDX 1.x | [CycloneDX spec](https://cyclonedx.org/), Trivy `sbom` subcommand |
| SARIF export (`sarif_exporter.py`) | SARIF 2.1.0 | [OASIS SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/), GitHub Code Scanning |
| SBOM drift gate | 허가 목록 기반 dep 추가 차단 | NIST SSDF / SLSA "known dependencies" 원칙 (조직 정책 패턴) |

---

## 3. 규정 매핑 — 공식 출처 기반 (2026-06 갱신)

### ISMS-P (`isms_p_controls.json`)

| 항목 | 상태 | 설명 |
|------|------|------|
| 통제 번호 (`ISMS-2.6.1`, `ISMS-2.7.2` 등) | **공식 구조** | KISA **ISMS-P 2022 인증제 안내서** 장·절·항목 번호 (2.5 인증·권한, 2.6 접근통제, 2.7 암호화, 2.10 보안시스템, 2.11 사고예방, 3.2 개인정보) |
| `official_citation`, `official_text` | **안내서 요지 반영** | 102개 전수가 아닌 **스캐너 매핑에 쓰이는 MVP 12개**만 포함 |
| `checklist_question`, `pass_criteria` | **감사 실무 톤** | 인증기준을 요약·재구성. 법률 자문·공식 인증 문서 대체 아님 |

근거: [KISA ISMS-P 인증 안내](https://isms.kisa.or.kr/) · 본 repo는 **finding_rules에 연결된 통제만** 카탈로그화.

**이전 오류 수정:** `2.7.x`=침입방지, `2.9.x`=암호화, `2.10.x`=개인정보로 잘못 쓰이던 ID를 공식 구조에 맞게 정정함.

### 전자금융 (`eft_controls.json`)

| 항목 | 상태 | 설명 |
|------|------|------|
| `EFT-SEC-01` ~ `EFT-SEC-10` | **내부 키 + 공식 조문** | 파이프라인 안정용 ID. 각 항목에 `official_citation`, `official_text`, `source_url`(law.go.kr) 포함 |
| 제15조의2 등 가상 조문 | **삭제** | 실제 **제14조·제15조·제21조의3**(전자금융거래법) 등으로 교체 |
| `finding_rules.json` 결함/조치 문구 | **템플릿** | Lab 리포트 필드 구조. 금감원 공식 서식 아님 |

근거: [전자금융감독규정](https://www.law.go.kr/LSW/admRulLsInfoP.do?admRulSeq=2000000053644) · [전자금융거래법 제21조의3](https://www.law.go.kr/LSW/lsLink.do?lsNm=%EC%A0%84%EC%9E%90%EA%B8%88%EC%9C%B5%EA%B1%B0%EB%9E%98%EB%B2%95&joNo=0021030000)

### 개인정보보호법 (`pipa_controls.json`)

| 항목 | 상태 | 설명 |
|------|------|------|
| `PIPA-29` | **법 조문** | 제29조 안전조치의무 — PII 로그 노출 시 법적 근거로 병행 참조 가능 |
| ISMS `3.2.3` | **인증 통제** | 개인정보 표시제한 — 스캐너 매핑의 1차 ISMS 통제 |

---

## 4. 프로젝트에서 틀리거나 단순화된 부분 (솔직히)

| 이전 표기 | 실제 | 조치 |
|-----------|------|------|
| CKV_K8S_23 = "privileged" | CKV_K8S_23 = **root container** | `checkov_parser.py` 수정 완료. privileged는 **CKV_K8S_16** |
| CKV_K8S_38 = "NodePort" | CKV_K8S_38 = **automount SA token** | parser 수정. NodePort 노출은 별도 CIS/K8s 가이드 주제 |
| `EFT-SEC-05` = 공식 조항번호 | **내부 키** — `official_citation`에 제15조 제1항 제1호 등 실조문 명시 | `eft_controls.json` 갱신 |
| ISMS `2.7`=침입방지, `2.9`=암호화 (구버전) | 공식: **2.6** 접근통제, **2.7** 암호화, **3.2** 개인정보 | `isms_p_controls.json`·`finding_rules.json` ID 정정 |
| Semgrep `os.system` | auto 룰셋에 항상 잡히지 않을 수 있음 | regex 백업 룰 유지 |
| `dummy-infra` = 실제 은행 인프라 | **회귀 테스트 픽스처** | 실제 사고 재현이 아님 |

---

## 5. 실제 사례와의 유사성 (뉴스/사고 유형)

직접 재현한 사고는 없다. 다만 **동일 유형**은 금융권에서 반복된다:

| 우리 fixture | 업계 유사 사례 유형 |
|--------------|---------------------|
| `.env` AKIA 유출 | GitHub public repo secret leak (TruffleHog/GitGuardian 연간 수천 건) |
| S3 `Principal: *` | Capital One 2019 (Misconfigured S3/WAF), 다수 클라우드 데이터 유출 |
| `urllib3` 구버전 | Log4Shell 이후 SCA/dependabot 의무화 트렌드 |
| K8s privileged + hostPath | 컨테이너 탈출 → 노드 침해 (MITRE ATT&CK T1611) |
| 로그 PII 평문 | 금융권 개인정보 과다수집·미마스킹 과태료 사례 (개보법) |

---

## 6. 로컬 재검증 커맨드

```bash
# CVE (Trivy NVD)
PYTHONPATH=src python3 -c "from tools.scan_dependencies import scan_dependencies; print(scan_dependencies(['dummy-infra/deps'], strict=True).findings)"

# Semgrep
semgrep scan --config auto dummy-infra/code/

# Checkov
checkov -d dummy-infra --quiet

# 전체 게이트
PYTHONPATH=src SECOPS_SAST_ENGINE=regex python3 scripts/ci_gate.py
```

---

## 7. 한 줄 요약

- **스캐너 결과(CVE, Checkov, Semgrep)**: NVD·공식 룰셋 기반 — **팩트**
- **취약 패턴(fixture)**: OWASP/CWE 실재 유형 — **팩트**
- **ISMS-P/전자금융/개보법 매핑**: 공식 조문·통제번호 **인용 + MVP 범위** — 자동화 PoC, 법적 자문 아님
- **사고 재현**: 없음 — **유형만 동일**
