
from engine.models import ScanResult, ScanStatus


def validate_gitleaks_exit_code(
    scan: ScanResult,
    exit_code: int
) -> ScanResult:

    if scan.status == ScanStatus.FAILED:
        return scan

    if exit_code not in (0, 1):
        return ScanResult(
            scanner=scan.scanner,
            status=ScanStatus.FAILED,
            findings=[],
            error_message=f"Unexpected Gitleaks exit code: {exit_code}"
        )

    has_findings = len(scan.findings) > 0

    if (exit_code == 0 and has_findings) or (
        exit_code == 1 and not has_findings
    ):
        return ScanResult(
            scanner=scan.scanner,
            status=ScanStatus.FAILED,
            findings=[],
            error_message="Inconsistent Gitleaks exit code and report"
        )

    return scan
