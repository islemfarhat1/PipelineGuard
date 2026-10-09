
from engine.models import SecurityFinding, Scanner, Severity
from engine.policy import Decision, evaluate_policy


def test_no_findings_pass():
    result = evaluate_policy([])

    assert result.decision == Decision.PASS


def test_high_vulnerability_pass():
    finding = SecurityFinding(
        scanner=Scanner.TRIVY,
        severity=Severity.HIGH,
        title="High vulnerability",
        identifier="CVE-TEST-0001",
        location="demo-app"
    )

    result = evaluate_policy([finding])

    assert result.decision == Decision.PASS


def test_critical_vulnerability_block():
    finding = SecurityFinding(
        scanner=Scanner.TRIVY,
        severity=Severity.CRITICAL,
        title="Critical vulnerability",
        identifier="CVE-TEST-0002",
        location="demo-app"
    )

    result = evaluate_policy([finding])

    assert result.decision == Decision.BLOCK
    assert len(result.reasons) > 0


def test_secret_detection_block():
    finding = SecurityFinding(
        scanner=Scanner.GITLEAKS,
        severity=Severity.HIGH,
        title="Exposed secret",
        identifier="test-secret",
        location="config.py"
    )

    result = evaluate_policy([finding])

    assert result.decision == Decision.BLOCK
