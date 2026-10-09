
from engine.models import Scanner, ScanResult, ScanStatus
from engine.policy import Decision, evaluate_scans


def test_all_scanners_success_pass():
    scans = [
        ScanResult(Scanner.TRIVY, ScanStatus.SUCCESS, []),
        ScanResult(Scanner.SEMGREP, ScanStatus.SUCCESS, []),
        ScanResult(Scanner.GITLEAKS, ScanStatus.SUCCESS, []),
    ]

    result = evaluate_scans(scans)

    assert result.decision == Decision.PASS


def test_failed_scanner_blocks():
    scans = [
        ScanResult(
            Scanner.TRIVY,
            ScanStatus.FAILED,
            [],
            "Database download failed"
        ),
        ScanResult(Scanner.SEMGREP, ScanStatus.SUCCESS, []),
        ScanResult(Scanner.GITLEAKS, ScanStatus.SUCCESS, []),
    ]

    result = evaluate_scans(scans)

    assert result.decision == Decision.BLOCK
    assert "trivy failed" in result.reasons[0]


def test_missing_scanner_blocks():
    scans = [
        ScanResult(Scanner.TRIVY, ScanStatus.SUCCESS, []),
        ScanResult(Scanner.SEMGREP, ScanStatus.SUCCESS, []),
    ]

    result = evaluate_scans(scans)

    assert result.decision == Decision.BLOCK
    assert "Missing scanner: gitleaks" in result.reasons


def test_duplicate_scanner_blocks():
    scans = [
        ScanResult(Scanner.TRIVY, ScanStatus.SUCCESS, []),
        ScanResult(Scanner.TRIVY, ScanStatus.SUCCESS, []),
        ScanResult(Scanner.SEMGREP, ScanStatus.SUCCESS, []),
        ScanResult(Scanner.GITLEAKS, ScanStatus.SUCCESS, []),
    ]

    result = evaluate_scans(scans)

    assert result.decision == Decision.BLOCK
    assert "Duplicate scanner results detected" in result.reasons
