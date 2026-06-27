from tools.sast_semgrep import _parse_semgrep_payload, run_semgrep_scan


def test_parse_semgrep_payload_maps_eval():
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval-detected.eval-detected",
                "path": "dummy-infra/code/unsafe_sast.py",
                "start": {"line": 8},
                "extra": {
                    "message": "Detected use of eval",
                    "severity": "ERROR",
                },
            }
        ],
        "errors": [],
    }
    findings = _parse_semgrep_payload(payload)
    assert len(findings) == 1
    assert findings[0].finding_type == "sast.unsafe_eval"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].line == 8


def test_parse_semgrep_payload_generic_rule():
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.weak-crypto.weak-md5",
                "path": "src/app.py",
                "start": {"line": 2},
                "extra": {"message": "weak md5", "severity": "WARNING"},
            }
        ],
    }
    findings = _parse_semgrep_payload(payload)
    assert findings[0].finding_type == "sast.semgrep.generic"
    assert findings[0].severity == "HIGH"


def test_audit_sast_auto_uses_available_engine(monkeypatch):
    monkeypatch.delenv("SECOPS_SAST_ENGINE", raising=False)
    from tools.sast_auditor import audit_sast

    result = audit_sast("dummy-infra/code/unsafe_sast.py", repo_wide=False, engine="auto")
    assert result.engine in {"regex", "semgrep", "semgrep+regex"}
    assert len(result.findings) > 0


def test_run_semgrep_scan_no_binary():
    findings, errors, files = run_semgrep_scan([])
    assert findings == []
    assert errors == []
    assert files == 0
