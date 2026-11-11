import json
from pathlib import Path

from engine.models import Scanner, SecurityFinding
from engine.normalizer import (
    normalize_gitleaks,
    normalize_semgrep,
    normalize_trivy,
    validate_repository_path,
)

REDACTED = "[REDACTED]"
# Values that Gitleaks writes when it already redacted the secret.
ALREADY_REDACTED = {"", "REDACTED"}
# Shorter strings would be replaced everywhere in the text by mistake.
MIN_SECRET_LENGTH = 4


def _read_json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_findings(semgrep: str | None = None, gitleaks: str | None = None,
                  trivy: str | None = None):
    """
    Load reports with the V2 normalizers.

    Returns (findings, secrets, secret_locations). Invalid reports raise
    ValueError, exactly as they do in the V2 engine.
    """

    findings: list[SecurityFinding] = []
    secrets: set[str] = set()
    secret_locations: set[tuple[str, int]] = set()

    if semgrep:
        findings += normalize_semgrep(_read_json(semgrep))

    if gitleaks:
        raw = _read_json(gitleaks)
        gitleaks_findings = normalize_gitleaks(raw)
        findings += gitleaks_findings

        for entry in raw:
            for field in ("Secret", "Match"):
                value = entry.get(field)
                if (
                    isinstance(value, str)
                    and value.strip() not in ALREADY_REDACTED
                    and len(value.strip()) >= MIN_SECRET_LENGTH
                ):
                    secrets.add(value.strip())

        for finding in gitleaks_findings:
            secret_locations.add(split_location(finding.location))

    if trivy:
        findings += normalize_trivy(_read_json(trivy))

    return findings, secrets, secret_locations


def split_location(location: str) -> tuple[str, int]:
    """Split "demo-app/app.py:12" into ("demo-app/app.py", 12)."""

    path, _, line = location.rpartition(":")
    return validate_repository_path(path), int(line)


def redact(text: str, secrets: set[str]) -> str:
    # Longest first, so a secret that contains another one is fully hidden.
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, REDACTED)
    return text


def read_code_context(finding: SecurityFinding, repo_root: str,
                      secrets: set[str],
                      secret_locations: set[tuple[str, int]],
                      radius: int = 3) -> str:
    """
    Return a few numbered lines around a Semgrep finding.

    Gitleaks findings get no code at all: the line is the secret.
    Trivy findings point to a package, not to a line of code.
    """

    if finding.scanner != Scanner.SEMGREP:
        return ""

    path, line = split_location(finding.location)

    root = Path(repo_root).resolve()
    file_path = (root / path).resolve()

    # The path comes from a report: never read outside the repository.
    if not file_path.is_relative_to(root):
        raise ValueError(f"Finding path escapes the repository: {path}")

    if not file_path.is_file():
        return ""

    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()

    start = max(1, line - radius)
    end = min(len(lines), line + radius)

    numbered = []
    for number in range(start, end + 1):
        content = lines[number - 1]
        if (path, number) in secret_locations:
            content = REDACTED
        marker = ">>" if number == line else "  "
        numbered.append(f"{marker} {number:4d} | {content}")

    return redact("\n".join(numbered), secrets)
