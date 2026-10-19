from engine.differential import compare_findings
from engine.models import Scanner, SecurityFinding, Severity
from engine.differential import (
    compare_findings,
    compare_scan_results,
    compare_all_scans,
    semgrep_location_is_unchanged,
)

from engine.models import (
    Scanner,
    SecurityFinding,
    Severity,
    ScanResult,
    ScanStatus,
)

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

    # Simulate five inserted lines before the vulnerability
    git_diff = (
        "diff --git a/demo-app/app.py b/demo-app/app.py\n"
        "--- a/demo-app/app.py\n"
        "+++ b/demo-app/app.py\n"
        "@@ -10,0 +11,5 @@\n"
        "+# Added comment 1\n"
        "+# Added comment 2\n"
        "+# Added comment 3\n"
        "+# Added comment 4\n"
        "+# Added comment 5\n"
    )

    result = compare_findings(
        baseline,
        current,
        git_diff=git_diff,
    )

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

def test_line_shift_does_not_hide_new_occurrence():
    old = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:15",
    )

    moved = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:20",
    )

    added = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:30",
    )

    git_diff = (
        "diff --git a/demo-app/app.py b/demo-app/app.py\n"
        "--- a/demo-app/app.py\n"
        "+++ b/demo-app/app.py\n"
        "@@ -10,0 +11,5 @@\n"
        "+# Added comment 1\n"
        "+# Added comment 2\n"
        "+# Added comment 3\n"
        "+# Added comment 4\n"
        "+# Added comment 5\n"
    )

    result = compare_findings(
        baseline=[old],
        current=[moved, added],
        git_diff=git_diff,
    )

    assert result.existing == [moved]
    assert result.new == [added]
    assert result.fixed == []

def test_modified_vulnerable_line_is_not_automatically_existing():
    old = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:15",
    )

    new = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:15",
    )

    git_diff = (
        "diff --git a/demo-app/app.py b/demo-app/app.py\n"
        "--- a/demo-app/app.py\n"
        "+++ b/demo-app/app.py\n"
        "@@ -15 +15 @@\n"
        "-eval(user_input)\n"
        "+eval(untrusted_data)\n"
    )

    result = compare_findings(
        baseline=[old],
        current=[new],
        git_diff=git_diff,
    )

    assert len(result.new) == 1
    assert len(result.existing) == 0
    assert len(result.fixed) == 1

def test_modified_semgrep_location_is_not_unchanged():
    git_diff = (
        "diff --git a/demo-app/app.py b/demo-app/app.py\n"
        "--- a/demo-app/app.py\n"
        "+++ b/demo-app/app.py\n"
        "@@ -15 +15 @@\n"
        "-eval(user_input)\n"
        "+eval(untrusted_data)\n"
    )

    result = semgrep_location_is_unchanged(
        "demo-app/app.py:15",
        git_diff,
    )

    assert result is False

def test_unchanged_semgrep_location_is_recognized():
    git_diff = (
        "diff --git a/demo-app/app.py b/demo-app/app.py\n"
        "--- a/demo-app/app.py\n"
        "+++ b/demo-app/app.py\n"
        "@@ -30,0 +31 @@\n"
        "+# New comment\n"
    )

    result = semgrep_location_is_unchanged(
        "demo-app/app.py:15",
        git_diff,
    )

    assert result is True

def test_incomplete_git_diff_does_not_hide_new_finding():
    old = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:15",
    )

    current = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:20",
    )

    git_diff = (
        "diff --git a/demo-app/app.py b/demo-app/app.py\n"
        "--- a/demo-app/app.py\n"
        "+++ b/demo-app/app.py\n"
        "@@ -10,0 +11,5 @@\n"
        "+# Comment 1\n"
        "+# Comment 2\n"
    )

    result = compare_findings(
        baseline=[old],
        current=[current],
        git_diff=git_diff,
    )

    assert result.new == [current]
    assert result.existing == []
    assert result.fixed == [old]

def test_missing_file_diff_keeps_exact_match():
    old = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:15",
    )

    git_diff = (
        "diff --git a/README.md b/README.md\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1 +1 @@\n"
        "-Old documentation\n"
        "+New documentation\n"
    )

    result = compare_findings(
        baseline=[old],
        current=[old],
        git_diff=git_diff,
    )

    assert result.existing == [old]
    assert result.new == []
    assert result.fixed == []

def test_compare_scan_results_passes_git_diff():
    old = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:15",
    )

    moved = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval",
        identifier="pipelineguard-dangerous-eval",
        location="demo-app/app.py:20",
    )

    baseline = ScanResult(
        scanner=Scanner.SEMGREP,
        status=ScanStatus.SUCCESS,
        findings=[old],
    )

    current = ScanResult(
        scanner=Scanner.SEMGREP,
        status=ScanStatus.SUCCESS,
        findings=[moved],
    )

    git_diff = (
        "diff --git a/demo-app/app.py b/demo-app/app.py\n"
        "--- a/demo-app/app.py\n"
        "+++ b/demo-app/app.py\n"
        "@@ -10,0 +11,5 @@\n"
        "+# Comment 1\n"
        "+# Comment 2\n"
        "+# Comment 3\n"
        "+# Comment 4\n"
        "+# Comment 5\n"
    )

    result = compare_scan_results(
        baseline,
        current,
        git_diff=git_diff,
    )

    assert result.existing == [moved]
    assert result.new == []
    assert result.fixed == []

def test_compare_all_scans_with_git_diff():
    old_semgrep = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval",
        identifier="dangerous-eval",
        location="demo-app/app.py:15",
    )

    moved_semgrep = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="Dangerous eval",
        identifier="dangerous-eval",
        location="demo-app/app.py:20",
    )

    new_trivy = SecurityFinding(
        scanner=Scanner.TRIVY,
        severity=Severity.HIGH,
        title="Vulnerable dependency",
        identifier="CVE-2026-TEST",
        location="requirements.txt",
    )

    old_secret = SecurityFinding(
        scanner=Scanner.GITLEAKS,
        severity=Severity.CRITICAL,
        title="Exposed secret",
        identifier="generic-api-key",
        location="config.py:8",
    )

    def scan(scanner, findings):
        return ScanResult(
            scanner=scanner,
            status=ScanStatus.SUCCESS,
            findings=findings,
        )

    baseline = [
        scan(Scanner.SEMGREP, [old_semgrep]),
        scan(Scanner.TRIVY, []),
        scan(Scanner.GITLEAKS, [old_secret]),
    ]

    current = [
        scan(Scanner.SEMGREP, [moved_semgrep]),
        scan(Scanner.TRIVY, [new_trivy]),
        scan(Scanner.GITLEAKS, []),
    ]

    git_diff = (
        "diff --git a/demo-app/app.py b/demo-app/app.py\n"
        "--- a/demo-app/app.py\n"
        "+++ b/demo-app/app.py\n"
        "@@ -10,0 +11,5 @@\n"
        "+# Comment 1\n"
        "+# Comment 2\n"
        "+# Comment 3\n"
        "+# Comment 4\n"
        "+# Comment 5\n"
    )

    result = compare_all_scans(
        baseline,
        current,
        git_diff=git_diff,
    )

    assert result.existing == [moved_semgrep]
    assert result.new == [new_trivy]
    assert result.fixed == [old_secret]