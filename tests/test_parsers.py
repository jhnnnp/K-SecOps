import json
from pathlib import Path

import pytest

from tools.parsers.checkov_parser import parse_checkov_report
from tools.parsers.trivy_parser import parse_trivy_report

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_trivy_fixture():
    payload = json.loads((FIXTURES / "trivy_sample.json").read_text())
    findings = parse_trivy_report(payload)
    assert len(findings) == 2
    assert any(item.id == "TRIVY-CVE-2024-1234" for item in findings)
    assert any(item.finding_type == "container.critical_cve" for item in findings)


def test_parse_checkov_fixture():
    payload = json.loads((FIXTURES / "checkov_sample.json").read_text())
    findings = parse_checkov_report(payload)
    assert len(findings) == 2
    assert any(item.finding_type == "k8s.privileged_container" for item in findings)
    assert any(item.finding_type == "k8s.exposed_nodeport" for item in findings)
