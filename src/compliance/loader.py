from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

COMPLIANCE_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=1)
def load_finding_rules() -> dict[str, Any]:
    return json.loads((COMPLIANCE_DIR / "finding_rules.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_isms_controls() -> dict[str, dict[str, Any]]:
    payload = json.loads((COMPLIANCE_DIR / "isms_p_controls.json").read_text(encoding="utf-8"))
    return {item["control_id"]: item for item in payload["controls"]}


@lru_cache(maxsize=1)
def load_eft_controls() -> dict[str, dict[str, Any]]:
    payload = json.loads((COMPLIANCE_DIR / "eft_controls.json").read_text(encoding="utf-8"))
    return {item["control_id"]: item for item in payload["controls"]}


def get_control(control_id: str) -> dict[str, Any] | None:
    if control_id.startswith("ISMS-"):
        return load_isms_controls().get(control_id)
    if control_id.startswith("EFT-"):
        return load_eft_controls().get(control_id)
    return None


def get_rule(finding_type: str) -> dict[str, Any] | None:
    for rule in load_finding_rules()["rules"]:
        if rule["finding_type"] == finding_type:
            return rule
    return None


def list_rule_finding_types() -> set[str]:
    return {rule["finding_type"] for rule in load_finding_rules()["rules"]}
