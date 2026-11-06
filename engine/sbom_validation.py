
"""Fail-closed validation of PipelineGuard CycloneDX inventories."""

import json
from pathlib import Path

from engine.lockfile_sbom import generate_sbom, parse_lockfile


class SBOMValidationError(ValueError):
    """Raised when a software inventory cannot be trusted."""


def validate_sbom(lockfile_path: Path, sbom_path: Path) -> int:
    """Verify that a CycloneDX SBOM matches the locked dependencies."""

    try:
        packages = parse_lockfile(lockfile_path)
        actual = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SBOMValidationError(
            f"Cannot load lockfile or SBOM: {exc}"
        ) from exc

    if not isinstance(actual, dict):
        raise SBOMValidationError("SBOM must be a JSON object")

    expected = generate_sbom(packages)

    if actual.get("bomFormat") != "CycloneDX":
        raise SBOMValidationError("Invalid SBOM format")

    if actual.get("specVersion") != "1.6":
        raise SBOMValidationError("Unsupported CycloneDX version")

    actual_components = actual.get("components")

    if not isinstance(actual_components, list):
        raise SBOMValidationError("Missing SBOM components")

    if len(actual_components) != len(packages):
        raise SBOMValidationError(
            "SBOM component count differs from lockfile"
        )

    expected_components = {
        component["purl"]: component
        for component in expected["components"]
    }

    actual_purls = []

    for component in actual_components:
        if not isinstance(component, dict):
            raise SBOMValidationError("Invalid SBOM component")

        purl = component.get("purl")

        if not isinstance(purl, str):
            raise SBOMValidationError("Missing component purl")

        actual_purls.append(purl)

        expected_component = expected_components.get(purl)

        if expected_component is None:
            raise SBOMValidationError(
                f"Unexpected SBOM component: {purl}"
            )

        if component != expected_component:
            raise SBOMValidationError(
                f"Component metadata mismatch: {purl}"
            )

    if len(set(actual_purls)) != len(actual_purls):
        raise SBOMValidationError("Duplicate SBOM components")

    if set(actual_purls) != set(expected_components):
        raise SBOMValidationError("Incomplete SBOM inventory")

    return len(packages)

def validate_trivy_report(report_path: Path) -> int:
    """Require a structurally valid Trivy Python dependency scan."""

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SBOMValidationError(
            f"Cannot load Trivy report: {exc}"
        ) from exc

    if not isinstance(report, dict):
        raise SBOMValidationError("Trivy report must be an object")

    if report.get("ArtifactType") != "cyclonedx":
        raise SBOMValidationError("Expected CycloneDX scan")

    results = report.get("Results")

    if not isinstance(results, list) or not results:
        raise SBOMValidationError("Missing Trivy scan results")

    python_results = [
        result for result in results
        if isinstance(result, dict)
        and result.get("Type") == "python-pkg"
    ]

    if not python_results:
        raise SBOMValidationError(
            "No Python dependency coverage detected"
        )

    for result in python_results:
        vulnerabilities = result.get("Vulnerabilities", [])

        if not isinstance(vulnerabilities, list):
            raise SBOMValidationError(
                "Invalid vulnerability list"
            )

    return len(python_results)
