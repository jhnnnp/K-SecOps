from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from tools.models import ScannerError
from tools.path_utils import relative_project_path, resolve_sandbox_target
from tools.scanner_runner import ScannerCommandError, run_scanner


class SbomComponent(BaseModel):
    name: str
    version: str | None = None
    purl: str | None = None
    type: str = "library"


class SbomResult(BaseModel):
    manifest: str
    format: str = "CycloneDX"
    components: list[SbomComponent] = Field(default_factory=list)
    output_path: str | None = None
    errors: list[ScannerError] = Field(default_factory=list)


def generate_sbom(
    manifest_path: str = "requirements.txt",
    *,
    output_path: str | None = None,
    strict: bool = False,
) -> SbomResult:
    """Generate CycloneDX SBOM from a Python manifest via Trivy."""
    resolved = resolve_sandbox_target(manifest_path, strict=strict)
    relative_manifest = relative_project_path(resolved)
    out = Path(output_path) if output_path else None

    command = [
        "trivy",
        "sbom",
        str(resolved),
        "--format",
        "cyclonedx",
    ]

    try:
        payload = run_scanner("trivy", command, timeout=180)
    except ScannerCommandError as exc:
        return SbomResult(
            manifest=relative_manifest,
            errors=[ScannerError(scanner="trivy", message=exc.message)],
        )

    components = _parse_cyclonedx(payload)
    out_path: str | None = None
    if output_path:
        out = Path(output_path)
        if not out.is_absolute():
            from tools.sandbox import PROJECT_ROOT
            out = PROJECT_ROOT / out
        write_sbom_json(
            SbomResult(manifest=relative_manifest, components=components),
            out,
        )
        out_path = relative_project_path(out)

    return SbomResult(
        manifest=relative_manifest,
        components=components,
        output_path=out_path,
    )


def _parse_cyclonedx(payload: dict) -> list[SbomComponent]:
    raw_components = payload.get("components", [])
    if not isinstance(raw_components, list):
        return []

    components: list[SbomComponent] = []
    for item in raw_components:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        components.append(
            SbomComponent(
                name=name,
                version=item.get("version"),
                purl=item.get("purl"),
                type=str(item.get("type", "library")),
            )
        )
    return _dedupe_components(components)


def write_sbom_json(result: SbomResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "manifest": result.manifest,
                "format": result.format,
                "component_count": len(result.components),
                "components": [c.model_dump() for c in result.components],
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _dedupe_components(components: list[SbomComponent]) -> list[SbomComponent]:
    seen: set[str] = set()
    unique: list[SbomComponent] = []
    for component in components:
        key = component.purl or f"{component.name}@{component.version or ''}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(component)
    return unique
