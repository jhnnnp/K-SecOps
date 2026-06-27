import re
from re import Pattern

from pydantic import BaseModel, Field

DEFAULT_ENTITIES = ("KR_RRN", "KR_PHONE", "ACCOUNT", "EMAIL")
MASK_TOKEN = "***"

PII_PATTERNS: dict[str, Pattern[str]] = {
    "KR_RRN": re.compile(r"\b\d{6}-[1-4]\d{6}\b"),
    "KR_PHONE": re.compile(r"\b01[016789]-?\d{3,4}-?\d{4}\b"),
    "ACCOUNT": re.compile(r"\b(?!01[0-9])\d{3,6}-\d{2,6}-\d{4,8}\b"),
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
}


class PiiFinding(BaseModel):
    type: str
    count: int
    sample_locations: list[int] = Field(
        description="1-based line numbers where entity was detected (max 5 samples)"
    )


class MaskPiiResult(BaseModel):
    masked_content: str
    findings: list[PiiFinding]
    total_detected: int


def mask_pii(content: str, entities: list[str] | None = None) -> MaskPiiResult:
    """
    Detect and mask PII entities in text using regex patterns.

    Supported entities: KR_RRN, KR_PHONE, ACCOUNT, EMAIL.
    """
    selected = _normalize_entities(entities)
    lines = content.splitlines()
    masked_lines = list(lines)
    findings_map: dict[str, list[int]] = {entity: [] for entity in selected}

    for entity in selected:
        pattern = PII_PATTERNS[entity]
        for line_idx, line in enumerate(lines):
            if pattern.search(line):
                findings_map[entity].append(line_idx + 1)
                masked_lines[line_idx] = pattern.sub(MASK_TOKEN, masked_lines[line_idx])

    findings = [
        PiiFinding(
            type=entity,
            count=len(locations),
            sample_locations=locations[:5],
        )
        for entity, locations in findings_map.items()
        if locations
    ]

    return MaskPiiResult(
        masked_content="\n".join(masked_lines),
        findings=findings,
        total_detected=sum(item.count for item in findings),
    )


def _normalize_entities(entities: list[str] | None) -> tuple[str, ...]:
    if entities is None:
        return DEFAULT_ENTITIES

    normalized: list[str] = []
    for entity in entities:
        key = entity.strip().upper()
        if key not in PII_PATTERNS:
            allowed = ", ".join(PII_PATTERNS)
            raise ValueError(f"Unknown entity {entity!r}. Allowed: {allowed}")
        if key not in normalized:
            normalized.append(key)

    return tuple(normalized)
