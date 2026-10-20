import hashlib
from pathlib import Path
import json
import re

def calculate_report_sha256(report_path: str) -> str:
    path = Path(report_path)

    if not path.is_file():
        raise ValueError(f"Report not found: {report_path}")

    digest = hashlib.sha256()

    try:
        with path.open("rb") as report:
            for chunk in iter(lambda: report.read(65536), b""):
                digest.update(chunk)
    except OSError as error:
        raise ValueError(f"Cannot read report: {error}") from error

    return digest.hexdigest()
SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
SCANNERS = ("trivy", "semgrep", "gitleaks")
REVISIONS = ("baseline", "current")


def create_provenance_manifest(
    baseline_sha: str,
    head_sha: str,
    reports: dict,
) -> dict:
    for name, sha in (
        ("baseline", baseline_sha),
        ("head", head_sha),
    ):
        if not isinstance(sha, str) or not SHA_PATTERN.fullmatch(sha):
            raise ValueError(f"Invalid {name} SHA")

    if not isinstance(reports, dict) or set(reports) != set(REVISIONS):
        raise ValueError("Invalid report revisions")

    manifest = {
        "baseline_sha": baseline_sha.lower(),
        "head_sha": head_sha.lower(),
        "reports": {},
    }

    for revision in REVISIONS:
        paths = reports[revision]

        if not isinstance(paths, dict) or set(paths) != set(SCANNERS):
            raise ValueError(f"Invalid {revision} scanner reports")

        manifest["reports"][revision] = {}

        for scanner in SCANNERS:
            path = paths[scanner]

            if not isinstance(path, str) or not path:
                raise ValueError(f"Invalid {revision} {scanner} path")

            manifest["reports"][revision][scanner] = {
                "path": path,
                "sha256": calculate_report_sha256(path),
            }

    return manifest


def verify_provenance_manifest(
    manifest: dict,
    baseline_sha: str,
    head_sha: str,
    reports: dict,
) -> bool:
    try:
        expected = create_provenance_manifest(
            baseline_sha,
            head_sha,
            reports,
        )
        return manifest == expected
    except (ValueError, TypeError, OSError):
        return False