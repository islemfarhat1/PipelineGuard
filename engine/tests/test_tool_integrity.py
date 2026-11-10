"""
Guard the integrity of the third-party tools run by the workflows.

A tag (e.g. aquasec/trivy:0.69.3 or trivy-action@0.34.2) can be moved to
other content, as happened in the March 2026 Trivy compromise
(CVE-2026-33634). Every tool must be pinned by an immutable hash.
"""

import re
from pathlib import Path

import pytest


WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
WORKFLOW_FILES = sorted(WORKFLOWS.glob("*.yml"))

SHA256 = r"[0-9a-f]{64}"


def read(path):
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("workflow", WORKFLOW_FILES, ids=lambda p: p.name)
def test_actions_are_pinned_by_commit_sha(workflow):
    for action in re.findall(r"uses:\s*(\S+)", read(workflow)):
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", action), action


@pytest.mark.parametrize("workflow", WORKFLOW_FILES, ids=lambda p: p.name)
def test_container_images_are_pinned_by_digest(workflow):
    text = read(workflow)
    images = re.findall(r"\b(?:aquasec/trivy|semgrep/semgrep)\S*", text)

    for image in images:
        if image.startswith("$"):
            continue
        assert re.search(rf"@sha256:{SHA256}$", image), image


@pytest.mark.parametrize("workflow", WORKFLOW_FILES, ids=lambda p: p.name)
def test_semgrep_is_not_installed_from_pip(workflow):
    assert "pip install semgrep" not in read(workflow)


@pytest.mark.parametrize("workflow", WORKFLOW_FILES, ids=lambda p: p.name)
def test_gitleaks_download_is_checksum_verified(workflow):
    text = read(workflow)

    if "gitleaks/releases/download" not in text:
        pytest.skip("workflow does not download Gitleaks")

    download = text.index("gitleaks/releases/download")
    check = text.find("sha256sum --check", download)
    extract = text.find("tar -xzf", download)

    assert re.search(SHA256, text), "expected Gitleaks SHA-256 is missing"
    assert check != -1, "Gitleaks archive is never verified"
    assert check < extract, "Gitleaks archive is extracted before verification"
