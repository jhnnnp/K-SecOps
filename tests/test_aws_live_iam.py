from tools.aws_auditor import policy_document_has_admin_wildcard


def test_policy_document_detects_admin_wildcard():
    document = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        },
    }
    assert policy_document_has_admin_wildcard(document) is True


def test_policy_document_ignores_non_admin():
    document = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::example/*",
        },
    }
    assert policy_document_has_admin_wildcard(document) is False
