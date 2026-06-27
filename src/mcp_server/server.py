from mcp.server.fastmcp import FastMCP

from tools.compliance_report import generate_compliance_report as _generate_compliance_report
from tools.aws_auditor import audit_aws_config as _audit_aws_config
from tools.file_reader import read_log_file as _read_log_file
from tools.pii_masker import mask_pii as _mask_pii
from tools.scan_infra import scan_infrastructure as _scan_infrastructure
from tools.secret_auditor import audit_secrets as _audit_secrets

mcp = FastMCP("Agentic K-SecOps", json_response=True)


@mcp.tool()
def read_log_file(path: str, max_lines: int = 500) -> dict:
    """Read a log or text file from allowed directories (dummy-infra/, reports/)."""
    return _read_log_file(path, max_lines).model_dump()


@mcp.tool()
def mask_pii(content: str, entities: list[str] | None = None) -> dict:
    """Detect and mask PII (KR_RRN, KR_PHONE, ACCOUNT, EMAIL) in text content."""
    return _mask_pii(content, entities).model_dump()


@mcp.tool()
def scan_infrastructure(target_path: str = "dummy-infra", scanners: list[str] | None = None) -> dict:
    """Scan infrastructure with Trivy and Checkov; return normalized security findings."""
    return _scan_infrastructure(target_path, scanners).model_dump()


@mcp.tool()
def audit_secrets(target_path: str = "dummy-infra") -> dict:
    """Detect plaintext secrets (AWS keys, API keys, private keys) in sandboxed files."""
    return _audit_secrets(target_path).model_dump()


@mcp.tool()
def audit_aws_config(target_path: str = "dummy-infra", live_scan: bool = False) -> dict:
    """Detect AWS misconfigurations in policy files and optionally via boto3 live S3 scan."""
    return _audit_aws_config(target_path, live_scan=live_scan).model_dump()


@mcp.tool()
def generate_compliance_report(
    target_path: str = "dummy-infra",
    output_path: str | None = None,
    scan_result: dict | None = None,
    pii_result: dict | None = None,
    secrets_result: dict | None = None,
    aws_result: dict | None = None,
    pii_log_path: str | None = None,
    auto_collect: bool = True,
) -> dict:
    """Map findings to ISMS-P/EFT controls and write a Lab-format Markdown audit report."""
    return _generate_compliance_report(
        target_path=target_path,
        output_path=output_path,
        scan_result=scan_result,
        pii_result=pii_result,
        secrets_result=secrets_result,
        aws_result=aws_result,
        pii_log_path=pii_log_path,
        auto_collect=auto_collect,
    ).model_dump()
