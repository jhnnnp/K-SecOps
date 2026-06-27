from tools.aws_auditor import audit_aws_config


def test_detects_local_s3_public_policy():
    result = audit_aws_config("dummy-infra/aws")
    types = {f.finding_type for f in result.findings}
    assert "aws.s3_public_access" in types
    assert any(f.resource.endswith("s3-public-bucket-policy.json") for f in result.findings)


def test_detects_local_iam_overprivileged():
    result = audit_aws_config("dummy-infra/aws")
    types = {f.finding_type for f in result.findings}
    assert "aws.iam_overprivileged" in types
    assert any(f.severity == "CRITICAL" for f in result.findings)


def test_live_scan_skipped_without_credentials(monkeypatch):
    monkeypatch.delenv("SECOPS_AWS_LIVE", raising=False)
    result = audit_aws_config("dummy-infra/aws", live_scan=False)
    assert result.live_scan is False
    assert len(result.findings) >= 2
