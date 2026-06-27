from tools.sast_auditor import audit_sast


def test_audit_sast_finds_unsafe_patterns():
    result = audit_sast("dummy-infra/code/unsafe_sast.py", repo_wide=False)
    types = {item.finding_type for item in result.findings}
    assert "sast.unsafe_eval" in types
    assert "sast.shell_injection" in types


def test_audit_sast_skips_comments():
    result = audit_sast("dummy-infra/code/unsafe_sast.py", repo_wide=False)
    assert all(item.line != 1 for item in result.findings)
