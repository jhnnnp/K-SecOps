from tools.secret_auditor import audit_secrets


def test_audit_secrets_finds_leaked_env():
    result = audit_secrets("dummy-infra")
    types = {item.finding_type for item in result.findings}
    assert "secret.aws_access_key" in types
    assert "secret.api_key" in types
    assert "secret.github_pat" in types
    assert "secret.database_url" in types
    assert result.files_scanned >= 1


def test_audit_secrets_masks_prefix_only():
    result = audit_secrets("dummy-infra/.env.leaked")
    aws = next(item for item in result.findings if item.finding_type == "secret.aws_access_key")
    assert aws.secret_prefix == "AKIA"
    assert "IOSF" not in aws.secret_prefix


def test_audit_secrets_single_file():
    result = audit_secrets("dummy-infra/.env.leaked")
    assert result.files_scanned == 1
    assert len(result.findings) >= 2


def test_repo_wide_scan_finds_fixture_secrets(monkeypatch):
    monkeypatch.setenv("SECOPS_REPO_SCAN", "1")
    result = audit_secrets(".", repo_wide=True)
    types = {item.finding_type for item in result.findings}
    assert "secret.aws_access_key" in types
    assert result.files_scanned > 1
    assert all("tests/" not in item.resource for item in result.findings)


def test_repo_wide_scan_skips_venv(monkeypatch):
    monkeypatch.setenv("SECOPS_REPO_SCAN", "1")
    result = audit_secrets(".", repo_wide=True)
    assert all(".venv/" not in item.resource for item in result.findings)

