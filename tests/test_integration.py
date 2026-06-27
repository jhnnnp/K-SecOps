import pytest

from tools.file_reader import read_log_file
from tools.pii_masker import mask_pii


def test_read_and_mask_e2e():
    """Simulates agent workflow: read_log_file -> mask_pii."""
    log = read_log_file("dummy-infra/test_log.txt")
    masked = mask_pii(log.content)

    assert log.line_count == 6
    assert masked.total_detected >= 4
    assert "900101-1234567" not in masked.masked_content
    assert "110-123-456789" not in masked.masked_content
    assert "010-9876-5432" not in masked.masked_content
    assert "test.user@example.com" not in masked.masked_content

    entity_types = {item.type for item in masked.findings}
    assert entity_types == {"KR_RRN", "KR_PHONE", "ACCOUNT", "EMAIL"}


def test_mcp_tools_registered():
    pytest.importorskip("mcp")
    from mcp_server.server import mcp

    tool_names = {tool.name for tool in mcp._tool_manager.list_tools()}
    expected = {
        "read_log_file",
        "mask_pii",
        "scan_infrastructure",
        "audit_secrets",
        "audit_aws_config",
        "generate_compliance_report",
    }
    assert expected.issubset(tool_names)


def test_full_audit_pipeline_generates_report():
    from tools.compliance_report import generate_compliance_report

    result = generate_compliance_report(
        target_path="dummy-infra",
        output_path="reports/TEST_PIPELINE.md",
        auto_collect=True,
    )
    assert result.summary.total_violations > 0
    assert result.report_path.endswith(".md")
