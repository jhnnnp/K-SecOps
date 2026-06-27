from compliance.mapper import build_violations
from tools.models import NormalizedInput, SecretFinding


def test_maps_secret_to_lab_violations():
    inputs = NormalizedInput(
        target_path="dummy-infra",
        secret_findings=[
            SecretFinding(
                id="SECRET-1",
                secret_type="AWS Access Key ID",
                resource="dummy-infra/.env.leaked",
                line=1,
                secret_prefix="AKIA",
                finding_type="secret.aws_access_key",
            )
        ],
    )
    violations = build_violations(inputs)
    assert len(violations) >= 3
    assert any("암호키" in v.deficiency_reason for v in violations)
    assert all(v.compliance_status == "미흡" for v in violations)
    assert violations[0].violation_id == "F-001"


def test_maps_pii_to_lab_violations():
    inputs = NormalizedInput(
        target_path="dummy-infra",
        pii_resource="dummy-infra/test_log.txt",
        pii_findings=[{"type": "KR_RRN", "count": 1, "sample_locations": [2]}],
    )
    violations = build_violations(inputs)
    assert any(v.control_id == "ISMS-3.2.3" for v in violations)
    assert any("mask_pii" in v.tool_reference for v in violations)


def test_maps_aws_to_lab_violations():
    from tools.models import AwsFinding

    inputs = NormalizedInput(
        target_path="dummy-infra",
        aws_findings=[
            AwsFinding(
                id="AWS-1",
                finding_type="aws.s3_public_access",
                resource="dummy-infra/aws/s3-public-bucket-policy.json",
                line=5,
                title="Public S3",
                description="Public principal",
                severity="CRITICAL",
                source="local",
            )
        ],
    )
    violations = build_violations(inputs)
    assert any(v.control_id == "ISMS-2.6.1" for v in violations)
    assert any("audit_aws" in v.tool_reference for v in violations)


def test_dedupes_same_control_and_resource():
    inputs = NormalizedInput(
        target_path="dummy-infra",
        secret_findings=[
            SecretFinding(
                id="SECRET-1",
                secret_type="AWS Access Key ID",
                resource="dummy-infra/.env.leaked",
                line=1,
                secret_prefix="AKIA",
                finding_type="secret.aws_access_key",
            ),
            SecretFinding(
                id="SECRET-2",
                secret_type="AWS Secret Access Key",
                resource="dummy-infra/.env.leaked",
                line=2,
                secret_prefix="wJal",
                finding_type="secret.aws_secret_key",
            ),
        ],
    )
    violations = build_violations(inputs)
    isms_272 = [v for v in violations if v.control_id == "ISMS-2.7.2"]
    assert len(isms_272) == 1
