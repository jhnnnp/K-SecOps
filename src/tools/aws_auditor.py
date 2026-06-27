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

    When live_scan is True (or SECOPS_AWS_LIVE=1) and credentials exist, also checks S3 public access via boto3.
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
                            description="Live scan detected weak S3 PublicAccessBlockConfiguration.",
                            severity="HIGH",
                            source="boto3",
                        )
                    )
            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code", "")
                if error_code not in {"NoSuchPublicAccessBlockConfiguration", "AccessDenied"}:
                    errors.append(f"S3 PublicAccessBlock check failed for {name}: {error_code}")

    except NoCredentialsError:
        errors.append("AWS credentials not configured; skip live AWS scan")
    except (BotoCoreError, ClientError) as exc:
        errors.append(f"Live AWS scan failed: {exc}")

    return findings, errors


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
