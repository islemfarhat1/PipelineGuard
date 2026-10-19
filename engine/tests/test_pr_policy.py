import pytest
from engine.differential import DifferentialResult
from engine.models import Scanner, SecurityFinding, Severity
from engine.policy import Decision, evaluate_pr_policy


def test_new_high_blocks_pr():
    new_finding = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval",
        identifier="dangerous-eval",
        location="app.py:15",
    )

    differential = DifferentialResult(
        new=[new_finding],
        existing=[],
        fixed=[],
    )

    result = evaluate_pr_policy(differential)

    assert result.decision == Decision.BLOCK


def test_existing_high_does_not_block_pr():
    existing_finding = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Existing dangerous eval",
        identifier="dangerous-eval",
        location="app.py:15",
    )

    differential = DifferentialResult(
        new=[],
        existing=[existing_finding],
        fixed=[],
    )

    result = evaluate_pr_policy(differential)

    assert result.decision == Decision.PASS

    import pytest


@pytest.mark.parametrize(
    "scanner,severity,category,expected",
    [
        (Scanner.SEMGREP, Severity.CRITICAL, "new", Decision.BLOCK),
        (Scanner.SEMGREP, Severity.CRITICAL, "existing", Decision.BLOCK),
        (Scanner.GITLEAKS, Severity.CRITICAL, "new", Decision.BLOCK),
        (Scanner.GITLEAKS, Severity.CRITICAL, "existing", Decision.BLOCK),
        (Scanner.TRIVY, Severity.MEDIUM, "new", Decision.PASS),
        (Scanner.SEMGREP, Severity.HIGH, "fixed", Decision.PASS),
    ],
)
def test_pr_policy_security_cases(
    scanner, severity, category, expected
):
    finding = SecurityFinding(
        scanner=scanner,
        severity=severity,
        title="Test security finding",
        identifier="TEST-001",
        location="app.py:10",
    )

    differential = DifferentialResult(
        new=[finding] if category == "new" else [],
        existing=[finding] if category == "existing" else [],
        fixed=[finding] if category == "fixed" else [],
    )

    result = evaluate_pr_policy(differential)

    assert result.decision == expected


def test_new_high_blocks_even_with_existing_high():
    existing = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Existing issue",
        identifier="OLD-001",
        location="app.py:10",
    )

    new = SecurityFinding(
        scanner=Scanner.TRIVY,
        severity=Severity.HIGH,
        title="New issue",
        identifier="NEW-001",
        location="requirements.txt",
    )

    differential = DifferentialResult(
        new=[new],
        existing=[existing],
        fixed=[],
    )

    result = evaluate_pr_policy(differential)

    assert result.decision == Decision.BLOCK
    assert any("NEW-001" in reason for reason in result.reasons)