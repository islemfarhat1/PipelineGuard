from engine.differential import compare_findings
from engine.models import Scanner, SecurityFinding, Severity
import pytest

def test_compare_findings_new_existing_fixed():
    # Vulnérabilité présente dans main et dans la PR
    existing = SecurityFinding(
        scanner=Scanner.TRIVY,
        severity=Severity.HIGH,
        title="Existing vulnerability",
        identifier="CVE-TEST-001",
        location="app:package-a",
    )

    # Nouvelle vulnérabilité introduite par la PR
    new = SecurityFinding(
        scanner=Scanner.TRIVY,
        severity=Severity.CRITICAL,
        title="New vulnerability",
        identifier="CVE-TEST-002",
        location="app:package-b",
    )

    # Vulnérabilité corrigée dans la PR
    fixed = SecurityFinding(
        scanner=Scanner.TRIVY,
        severity=Severity.HIGH,
        title="Fixed vulnerability",
        identifier="CVE-TEST-003",
        location="app:package-c",
    )

    baseline = [existing, fixed]  # Résultats de main
    current = [existing, new]     # Résultats de la PR

    result = compare_findings(baseline, current)

    assert result.new == [new]
    assert result.existing == [existing]
    assert result.fixed == [fixed]

@pytest.mark.xfail(
    strict=True,
    reason="Line-shift matching not implemented yet"
)
def test_semgrep_line_shift_should_remain_existing():
    baseline = [
        SecurityFinding(
            scanner=Scanner.SEMGREP,
            severity=Severity.HIGH,
            title="Dangerous eval",
            identifier="pipelineguard-dangerous-eval",
            location="demo-app/app.py:15",
        )
    ]

    current = [
        SecurityFinding(
            scanner=Scanner.SEMGREP,
            severity=Severity.HIGH,
            title="Dangerous eval",
            identifier="pipelineguard-dangerous-eval",
            location="demo-app/app.py:20",
        )
    ]

    result = compare_findings(baseline, current)

    assert len(result.new) == 0
    assert len(result.fixed) == 0
    assert len(result.existing) == 1
def test_duplicate_findings_are_not_silently_lost():
    finding_a = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval A",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:15",
    )

    finding_b = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval B",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:15",
    )

    result = compare_findings(
        baseline=[],
        current=[finding_a, finding_b],
    )

    assert len(result.new) == 2
def test_additional_occurrence_is_new():
    existing = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:15",
    )

    added = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Another dangerous eval",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:15",
    )

    result = compare_findings(
        baseline=[existing],
        current=[existing, added],
    )

    assert len(result.existing) == 1
    assert len(result.new) == 1
    assert len(result.fixed) == 0
    assert result.new[0] == added

def test_removed_occurrence_is_fixed():
    existing = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:15",
    )

    removed = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Another dangerous eval",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:15",
    )

    result = compare_findings(
        baseline=[existing, removed],
        current=[existing],
    )

    assert len(result.new) == 0
    assert len(result.existing) == 1
    assert len(result.fixed) == 1
    assert result.fixed[0] == removed

def test_severity_escalation_must_not_be_ignored():
    baseline_finding = SecurityFinding(
        scanner=Scanner.TRIVY,
        severity=Severity.HIGH,
        title="Vulnerable dependency",
        identifier="CVE-TEST-001",
        location="app:package-a",
    )

    current_finding = SecurityFinding(
        scanner=Scanner.TRIVY,
        severity=Severity.CRITICAL,
        title="Vulnerable dependency",
        identifier="CVE-TEST-001",
        location="app:package-a",
    )

    result = compare_findings(
        baseline=[baseline_finding],
        current=[current_finding],
    )

    assert len(result.new) == 1
    assert len(result.existing) == 0
    assert len(result.fixed) == 1