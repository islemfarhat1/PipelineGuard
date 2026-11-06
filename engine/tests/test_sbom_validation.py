
import json

import pytest

from engine.lockfile_sbom import generate_sbom, parse_lockfile
from engine.sbom_validation import (
    SBOMValidationError,
    validate_sbom,
    validate_trivy_report,
)


@pytest.fixture
def valid_inventory(tmp_path):
    lockfile = tmp_path / "requirements.lock"
    lockfile.write_text(
        "fastapi==0.100.0 \\\n"
        "    --hash=sha256:" + "a" * 64 + "\n",
        encoding="utf-8",
    )

    sbom = generate_sbom(parse_lockfile(lockfile))
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(json.dumps(sbom), encoding="utf-8")

    return lockfile, sbom_path


def test_valid_sbom(valid_inventory):
    lockfile, sbom_path = valid_inventory
    assert validate_sbom(lockfile, sbom_path) == 1


def test_missing_sbom_component(valid_inventory):
    lockfile, sbom_path = valid_inventory
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    sbom["components"] = []
    sbom_path.write_text(json.dumps(sbom), encoding="utf-8")

    with pytest.raises(SBOMValidationError):
        validate_sbom(lockfile, sbom_path)


def test_modified_component_hash(valid_inventory):
    lockfile, sbom_path = valid_inventory
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    sbom["components"][0]["hashes"][0]["content"] = "b" * 64
    sbom_path.write_text(json.dumps(sbom), encoding="utf-8")

    with pytest.raises(SBOMValidationError):
        validate_sbom(lockfile, sbom_path)


def test_valid_trivy_report(tmp_path):
    report_path = tmp_path / "trivy.json"
    report_path.write_text(
        json.dumps({
            "ArtifactType": "cyclonedx",
            "Results": [{
                "Target": "Python",
                "Type": "python-pkg",
                "Vulnerabilities": [],
            }],
        }),
        encoding="utf-8",
    )

    assert validate_trivy_report(report_path) == 1


def test_missing_python_coverage(tmp_path):
    report_path = tmp_path / "trivy.json"
    report_path.write_text(
        json.dumps({
            "ArtifactType": "cyclonedx",
            "Results": [],
        }),
        encoding="utf-8",
    )

    with pytest.raises(SBOMValidationError):
        validate_trivy_report(report_path)


def test_invalid_trivy_vulnerabilities(tmp_path):
    report_path = tmp_path / "trivy.json"
    report_path.write_text(
        json.dumps({
            "ArtifactType": "cyclonedx",
            "Results": [{
                "Type": "python-pkg",
                "Vulnerabilities": "invalid",
            }],
        }),
        encoding="utf-8",
    )

    with pytest.raises(SBOMValidationError):
        validate_trivy_report(report_path)
