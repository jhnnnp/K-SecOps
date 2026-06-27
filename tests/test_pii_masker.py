import pytest

from tools.pii_masker import mask_pii


SAMPLE_LOG = """\
2026-06-27 DEBUG rrn=900101-1234567 phone=010-9876-5432
transfer account=110-123-456789 email=test.user@example.com
"""


def test_masks_all_default_entities():
    result = mask_pii(SAMPLE_LOG)
    assert "900101-1234567" not in result.masked_content
    assert "010-9876-5432" not in result.masked_content
    assert "110-123-456789" not in result.masked_content
    assert "test.user@example.com" not in result.masked_content
    assert result.total_detected == 4
    assert len(result.findings) == 4


def test_finding_metadata():
    result = mask_pii(SAMPLE_LOG)
    rrn = next(item for item in result.findings if item.type == "KR_RRN")
    assert rrn.count == 1
    assert rrn.sample_locations == [1]


def test_selective_entities():
    result = mask_pii(SAMPLE_LOG, entities=["EMAIL"])
    assert "test.user@example.com" not in result.masked_content
    assert "900101-1234567" in result.masked_content
    assert result.total_detected == 1


def test_unknown_entity_raises():
    with pytest.raises(ValueError, match="Unknown entity"):
        mask_pii("hello", entities=["INVALID"])


def test_no_pii_returns_empty_findings():
    result = mask_pii("no sensitive data here")
    assert result.findings == []
    assert result.total_detected == 0
