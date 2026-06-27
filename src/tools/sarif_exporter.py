from __future__ import annotations

import json
from pathlib import Path

from tools.models import SastFinding
from tools.sandbox import PROJECT_ROOT


def sast_findings_to_sarif(
    findings: list[SastFinding],
    *,
    tool_name: str = "K-SecOps-SAST",
    tool_version: str = "1.0.0",
) -> dict:
    """Convert SAST findings to SARIF 2.1.0 for GitHub Code Scanning upload."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for finding in findings:
        rule_id = finding.finding_type
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {"level": _sarif_level(finding.severity)},
            }

        uri = finding.resource.replace("\\", "/")
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": finding.line},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/jhnnnp/K-SecOps",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(findings: list[SastFinding], output_path: str | Path) -> Path:
    path = Path(output_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = sast_findings_to_sarif(findings)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _sarif_level(severity: str) -> str:
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    return mapping.get(severity.upper(), "warning")
