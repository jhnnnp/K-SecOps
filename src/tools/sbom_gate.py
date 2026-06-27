from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import BaseModel, Field

from tools.generate_sbom import generate_sbom, write_sbom_json
from tools.path_utils import relative_project_path, resolve_sandbox_target
from tools.sandbox import PROJECT_ROOT


class SbomDriftFinding(BaseModel):
    component: str
    version: str | None = None
    reason: str


class SbomGateResult(BaseModel):
    manifest: str
    allowed_count: int
    current_count: int
    new_components: list[SbomDriftFinding] = Field(default_factory=list)
    removed_components: list[SbomDriftFinding] = Field(default_factory=list)
    passed: bool = True
    errors: list[str] = Field(default_factory=list)


def check_sbom_drift(
    manifest_path: str = "requirements.txt",
    baseline_path: str | Path = "config/sbom-baseline.json",
) -> SbomGateResult:
    """
    Supply-chain drift gate: fail when app manifest gains direct deps outside baseline.

    Compares top-level requirements.txt package names against an approved list.
    Full CycloneDX SBOM is generated separately for compliance artifacts.
    """
    baseline_file = Path(baseline_path)
    if not baseline_file.is_file():
        baseline_file = PROJECT_ROOT / baseline_path

    resolved = resolve_sandbox_target(manifest_path, strict=False)
    relative_manifest = relative_project_path(resolved)
    direct_deps = _parse_direct_requirements(resolved)
    allowed = _load_allowed_names(baseline_file)
    allowed_set = {name.lower() for name in allowed}
    current_set = {name.lower() for name in direct_deps}

    new_items = [
        SbomDriftFinding(
            component=name,
            reason="unauthorized direct dependency — not in SBOM baseline",
        )
        for name in sorted(current_set)
        if name not in allowed_set
    ]
    removed_items = [
        SbomDriftFinding(component=name, reason="approved direct dependency no longer declared")
        for name in sorted(allowed_set)
        if name not in current_set
    ]

    return SbomGateResult(
        manifest=relative_manifest,
        allowed_count=len(allowed_set),
        current_count=len(current_set),
        new_components=new_items,
        removed_components=removed_items,
        passed=len(new_items) == 0,
    )


def export_sbom_artifact(
    manifest_path: str = "requirements.txt",
    output_path: str = "reports/SBOM.json",
) -> Path | None:
    """Generate CycloneDX SBOM artifact; returns path or None on failure."""
    sbom = generate_sbom(manifest_path, strict=False)
    if sbom.errors:
        return None
    out = PROJECT_ROOT / output_path
    write_sbom_json(sbom, out)
    return out


def _parse_direct_requirements(path: Path) -> list[str]:
    names: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return names
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name = re.split(r"[<>=!~\[\];]", stripped)[0].strip()
        if name:
            names.append(name)
    return names


def _load_allowed_names(path: Path) -> list[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    names = payload.get("allowed_dependencies", [])
    if not isinstance(names, list):
        return []
    return [str(name).strip() for name in names if str(name).strip()]
