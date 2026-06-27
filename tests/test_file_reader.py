import pytest

from tools.file_reader import read_log_file
from tools.sandbox import PathSandboxError


def test_read_dummy_log():
    result = read_log_file("dummy-infra/test_log.txt")
    assert result.line_count > 0
    assert "payment-service" in result.content
    assert result.truncated is False
    assert result.path == "dummy-infra/test_log.txt"


def test_read_with_max_lines():
    result = read_log_file("dummy-infra/test_log.txt", max_lines=2)
    assert result.line_count == 2
    assert result.truncated is True


def test_read_missing_file():
    with pytest.raises(FileNotFoundError):
        read_log_file("dummy-infra/missing.txt")


def test_read_blocked_path():
    with pytest.raises(PathSandboxError):
        read_log_file("src/main.py")
