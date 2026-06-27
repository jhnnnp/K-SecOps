import pytest

from tools.scanner_runner import find_executable
from tools.scan_infra import scan_infrastructure


def test_scan_infrastructure_returns_structure_without_scanners():
    result = scan_infrastructure("dummy-infra", scanners=[])
    assert result.target_path == "dummy-infra"
    assert result.findings == []
    assert result.scanners_run == []


def test_scan_infrastructure_graceful_when_missing(monkeypatch):
    monkeypatch.setattr("tools.scanner_runner.find_executable", lambda name: None)
    result = scan_infrastructure("dummy-infra")
    assert len(result.errors) == 2
    assert {error.scanner for error in result.errors} == {"trivy", "checkov"}


@pytest.mark.skipif(find_executable("trivy") is None, reason="trivy not installed")
def test_scan_infrastructure_with_trivy():
    result = scan_infrastructure("dummy-infra", scanners=["trivy"])
    assert "trivy" in result.scanners_run
    assert not any(error.scanner == "trivy" for error in result.errors)


@pytest.mark.skipif(find_executable("checkov") is None, reason="checkov not installed")
def test_scan_infrastructure_with_checkov():
    result = scan_infrastructure("dummy-infra", scanners=["checkov"])
    assert "checkov" in result.scanners_run
    assert not any(error.scanner == "checkov" for error in result.errors)


def test_scan_infrastructure_invalid_scanner():
    with pytest.raises(ValueError, match="Unknown scanner"):
        scan_infrastructure("dummy-infra", scanners=["nmap"])
