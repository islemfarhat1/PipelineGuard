
from engine.models import Scanner, ScanResult, ScanStatus, SecurityFinding, Severity
from engine.scan_validation import validate_gitleaks_exit_code


def make_scan(with_secret: bool) -> ScanResult:
    findings = []

    if with_secret:
        findings.append(
            SecurityFinding(
                scanner=Scanner.GITLEAKS,
                severity=Severity.CRITICAL,
                title="Simulated secret",
                identifier="test-secret",
                location="config.py:10"
            )
        )

    return ScanResult(
        scanner=Scanner.GITLEAKS,
        status=ScanStatus.SUCCESS,
        findings=findings
    )


def test_gitleaks_no_secret_success():
    scan = make_scan(with_secret=False)

    result = validate_gitleaks_exit_code(scan, 0)

    assert result.status == ScanStatus.SUCCESS


def test_gitleaks_secret_detected_success():
    scan = make_scan(with_secret=True)

    result = validate_gitleaks_exit_code(scan, 1)

    assert result.status == ScanStatus.SUCCESS


def test_gitleaks_inconsistent_exit_code_zero():
    scan = make_scan(with_secret=True)

    result = validate_gitleaks_exit_code(scan, 0)

    assert result.status == ScanStatus.FAILED


def test_gitleaks_inconsistent_exit_code_one():
    scan = make_scan(with_secret=False)

    result = validate_gitleaks_exit_code(scan, 1)

    assert result.status == ScanStatus.FAILED
