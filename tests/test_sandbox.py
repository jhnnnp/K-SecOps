import os

import pytest

from tools.sandbox import PathSandboxError, is_repo_scan_mode, resolve_sandbox_path


def test_allows_dummy_infra_file():
    resolved = resolve_sandbox_path("dummy-infra/test_log.txt")
    assert resolved.name == "test_log.txt"
    assert "dummy-infra" in str(resolved)


def test_allows_reports_path():
    resolved = resolve_sandbox_path("reports/SAMPLE_AUDIT_REPORT.md")
    assert resolved.name == "SAMPLE_AUDIT_REPORT.md"


def test_blocks_path_traversal():
    with pytest.raises(PathSandboxError):
        resolve_sandbox_path("dummy-infra/../../etc/passwd")


def test_blocks_absolute_path_outside_roots():
    with pytest.raises(PathSandboxError):
        resolve_sandbox_path("/etc/passwd")


def test_blocks_empty_path():
    with pytest.raises(PathSandboxError):
        resolve_sandbox_path("")


def test_repo_scan_mode_allows_src(monkeypatch):
    monkeypatch.setenv("SECOPS_REPO_SCAN", "1")
    resolved = resolve_sandbox_path("src/main.py", strict=False)
    assert resolved.name == "main.py"


def test_strict_mode_blocks_src_even_in_ci(monkeypatch):
    monkeypatch.setenv("SECOPS_REPO_SCAN", "1")
    with pytest.raises(PathSandboxError):
        resolve_sandbox_path("src/main.py", strict=True)


def test_is_repo_scan_mode_reads_ci_env(monkeypatch):
    monkeypatch.delenv("SECOPS_REPO_SCAN", raising=False)
    monkeypatch.setenv("CI", "true")
    assert is_repo_scan_mode() is True
