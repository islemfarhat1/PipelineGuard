
import json
from pathlib import Path

from engine.models import Scanner, ScanResult, ScanStatus
from engine.normalizer import (
    normalize_trivy,
    normalize_semgrep,
    normalize_gitleaks,
)


def load_scan_report(
    scanner: Scanner,
    file_path: str
) -> ScanResult:

    try:
        # Read and decode the JSON report
        path = Path(file_path)
        report = json.loads(
            path.read_text(encoding="utf-8")
        )

        # Normalize according to the scanner
        if scanner == Scanner.TRIVY:
            findings = normalize_trivy(report)

        elif scanner == Scanner.SEMGREP:
            findings = normalize_semgrep(report)

        elif scanner == Scanner.GITLEAKS:
            findings = normalize_gitleaks(report)

        else:
            raise ValueError("Unsupported scanner")

        return ScanResult(
            scanner=scanner,
            status=ScanStatus.SUCCESS,
            findings=findings
        )

    except (OSError, ValueError, TypeError, KeyError) as error:
        return ScanResult(
            scanner=scanner,
            status=ScanStatus.FAILED,
            findings=[],
            error_message=str(error)
        )
