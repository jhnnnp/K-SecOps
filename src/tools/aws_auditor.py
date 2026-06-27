"""AWS configuration and secret exposure checks (local policy files + optional boto3 live scan)."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from tools.models import AuditAwsResult, AwsFinding
from tools.path_utils import relative_project_path, resolve_sandbox_target

IAM_WILDCARD_ACTION = re.compile(r'"\s*Action\s*"\s*:\s*"\*"')
IAM_WILDCARD_RESOURCE = re.compile(r'"\s*Resource\s*"\s*:\s*"\*"')
S3_PUBLIC_PRINCIPAL = re.compile(r'"\s*Principal\s*"\s*:\s*"\*"')
S3_PUBLIC_GET = re.compile(r"s3:GetObject", re.IGNORECASE)

AWS_JSON_SUFFIXES = {".json"}


def audit_aws_config(target_path: str = "dummy-infra", live_scan: bool | None = None) -> AuditAwsResult:
    """
    Scan AWS-related misconfigurations in sandboxed policy files.

    When live_scan is True (or SECOPS_AWS_LIVE=1) and credentials exist, queries live AWS via boto3
    (S3 PublicAccessBlock, IAM wildcard policies).
    """
    resolved = resolve_sandbox_target(target_path)
    relative_target = relative_project_path(resolved)

    findings: list[AwsFinding] = []
    errors: list[str] = []

    findings.extend(_scan_local_policy_files(resolved))

    should_live = live_scan if live_scan is not None else os.getenv("SECOPS_AWS_LIVE", "0") == "1"
    if should_live:
        live_findings, live_errors = _scan_live_aws()
        findings.extend(live_findings)
        errors.extend(live_errors)

    return AuditAwsResult(
        findings=_dedupe(findings),
        target_path=relative_target,
        live_scan=should_live,
        errors=errors,
    )


def _scan_local_policy_files(root: Path) -> list[AwsFinding]:
    findings: list[AwsFinding] = []
    files = [root] if root.is_file() else list(root.rglob("*.json"))

    for file_path in files:
        if "aws" not in file_path.parts and file_path.suffix.lower() not in AWS_JSON_SUFFIXES:
            continue
        try:
            content = file_path.read_text(encoding="utf-8")
            payload = json.loads(content)
        except (OSError, json.JSONDecodeError):
            continue

        resource = relative_project_path(file_path)
        findings.extend(_analyze_policy_document(resource, content, payload))

    return findings


def _analyze_policy_document(resource: str, content: str, payload: dict[str, Any]) -> list[AwsFinding]:
    findings: list[AwsFinding] = []
    text = json.dumps(payload)

    if IAM_WILDCARD_ACTION.search(content) and IAM_WILDCARD_RESOURCE.search(content):
        findings.append(
            AwsFinding(
                id=f"AWS-IAM-WILDCARD-{resource}",
                finding_type="aws.iam_overprivileged",
                resource=resource,
                line=_line_number(content, '"Action"'),
                title="IAM policy allows Action:* on Resource:*",
                description="Over-privileged IAM policy detected in local policy file.",
                severity="CRITICAL",
                source="local",
            )
        )

    if S3_PUBLIC_PRINCIPAL.search(content) and S3_PUBLIC_GET.search(text):
        findings.append(
            AwsFinding(
                id=f"AWS-S3-PUBLIC-{resource}",
                finding_type="aws.s3_public_access",
                resource=resource,
                line=_line_number(content, '"Principal"'),
                title="S3 bucket policy allows public GetObject",
                description="Public principal can read S3 objects according to policy file.",
                severity="CRITICAL",
                source="local",
            )
        )

    return findings


def _line_number(content: str, needle: str) -> int | None:
    for index, line in enumerate(content.splitlines(), start=1):
        if needle in line:
            return index
    return None


def _scan_live_aws() -> tuple[list[AwsFinding], list[str]]:
    findings: list[AwsFinding] = []
    errors: list[str] = []

    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
    except ImportError:
        return [], ["boto3 not installed; skip live AWS scan"]

    try:
        session = boto3.session.Session()
        credentials = session.get_credentials()
        if credentials is None:
            return [], ["AWS credentials not configured; skip live AWS scan"]

        s3 = session.client("s3")
        iam = session.client("iam")

        s3_findings, s3_errors = _scan_live_s3(s3)
        iam_findings, iam_errors = _scan_live_iam(iam)
        findings.extend(s3_findings)
        findings.extend(iam_findings)
        errors.extend(s3_errors)
        errors.extend(iam_errors)

    except NoCredentialsError:
        errors.append("AWS credentials not configured; skip live AWS scan")
    except (BotoCoreError, ClientError) as exc:
        errors.append(f"Live AWS scan failed: {exc}")

    return findings, errors


def _scan_live_s3(s3) -> tuple[list[AwsFinding], list[str]]:
    findings: list[AwsFinding] = []
    errors: list[str] = []

    from botocore.exceptions import ClientError

    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            public_block = s3.get_public_access_block(Bucket=name)
            config = public_block.get("PublicAccessBlockConfiguration", {})
            if not all(
                config.get(key, False)
                for key in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            ):
                findings.append(
                    AwsFinding(
                        id=f"AWS-LIVE-S3-PAB-{name}",
                        finding_type="aws.s3_public_access",
                        resource=f"aws:s3://{name}",
                        line=None,
                        title="S3 bucket public access block incomplete",
                        description="Live boto3 scan: weak S3 PublicAccessBlockConfiguration.",
                        severity="HIGH",
                        source="boto3",
                    )
                )
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code not in {"NoSuchPublicAccessBlockConfiguration", "AccessDenied"}:
                errors.append(f"S3 PublicAccessBlock check failed for {name}: {error_code}")

    return findings, errors


def _scan_live_iam(iam) -> tuple[list[AwsFinding], list[str]]:
    findings: list[AwsFinding] = []
    errors: list[str] = []

    from botocore.exceptions import ClientError

    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local", OnlyAttached=True):
        for policy in page.get("Policies", []):
            arn = policy.get("Arn", "")
            version_id = policy.get("DefaultVersionId", "")
            if not arn or not version_id:
                continue
            try:
                document = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)[
                    "PolicyVersion"
                ]["Document"]
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                errors.append(f"IAM get_policy_version failed for {arn}: {code}")
                continue

            if policy_document_has_admin_wildcard(document):
                findings.append(
                    AwsFinding(
                        id=f"AWS-LIVE-IAM-WILDCARD-{policy.get('PolicyName', 'policy')}",
                        finding_type="aws.iam_overprivileged",
                        resource=arn,
                        line=None,
                        title="IAM policy allows Action:* on Resource:*",
                        description="Live boto3 scan: customer-managed IAM policy has admin wildcard.",
                        severity="CRITICAL",
                        source="boto3",
                    )
                )

    role_paginator = iam.get_paginator("list_roles")
    for page in role_paginator.paginate():
        for role in page.get("Roles", []):
            role_name = role.get("RoleName", "")
            if not role_name:
                continue
            try:
                inline = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                errors.append(f"IAM list_role_policies failed for {role_name}: {code}")
                continue

            for policy_name in inline:
                try:
                    document = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)[
                        "PolicyDocument"
                    ]
                except ClientError:
                    continue
                if policy_document_has_admin_wildcard(document):
                    resource = f"aws:iam:role/{role_name}/inline/{policy_name}"
                    findings.append(
                        AwsFinding(
                            id=f"AWS-LIVE-IAM-INLINE-{role_name}-{policy_name}",
                            finding_type="aws.iam_overprivileged",
                            resource=resource,
                            line=None,
                            title="Inline IAM policy allows Action:* on Resource:*",
                            description="Live boto3 scan: inline role policy has admin wildcard.",
                            severity="CRITICAL",
                            source="boto3",
                        )
                    )

    return findings, errors


def policy_document_has_admin_wildcard(document: dict[str, Any]) -> bool:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            return True
    return False


def _dedupe(findings: list[AwsFinding]) -> list[AwsFinding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[AwsFinding] = []
    for finding in findings:
        key = (finding.finding_type, finding.resource, finding.source)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
