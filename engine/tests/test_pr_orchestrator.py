import pytest

from engine.models import (
    Scanner,
    Severity,
    SecurityFinding,
    ScanResult,
    ScanStatus,
)
from engine.orchestrator import run_pipelineguard_pr
from engine.policy import Decision


VALID_DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,1 +1,2 @@
 print("hello")
+print("world")
"""


def make_scans(
    findings=None,
    failed_scanner=None,
):
    findings = findings or []

    return [
        ScanResult(
            scanner=scanner,
            status=(
                ScanStatus.FAILED
                if scanner == failed_scanner
                else ScanStatus.SUCCESS
            ),
            findings=[
                finding
                for finding in findings
                if finding.scanner == scanner
            ],
            error_message=(
                "Scanner execution failed"
                if scanner == failed_scanner
                else ""
            ),
        )
        for scanner in Scanner
    ]


@pytest.mark.parametrize(
    "invalid_input",
    [
        "missing",
        "duplicate",
        "failed",
    ],
)
def test_invalid_current_scans_block(invalid_input):
    baseline = make_scans()
    current = make_scans()

    if invalid_input == "missing":
        current.pop()

    elif invalid_input == "duplicate":
        current.append(current[0])

    elif invalid_input == "failed":
        current = make_scans(
            failed_scanner=Scanner.SEMGREP
        )

    result = run_pipelineguard_pr(
        baseline,
        current,
        VALID_DIFF,
    )

    assert result.decision == Decision.BLOCK


@pytest.mark.parametrize(
    "invalid_input",
    [
        "missing",
        "duplicate",
        "failed",
    ],
)
def test_invalid_baseline_scans_block(invalid_input):
    baseline = make_scans()
    current = make_scans()

    if invalid_input == "missing":
        baseline.pop()

    elif invalid_input == "duplicate":
        baseline.append(baseline[0])

    elif invalid_input == "failed":
        baseline = make_scans(
            failed_scanner=Scanner.TRIVY
        )

    result = run_pipelineguard_pr(
        baseline,
        current,
        VALID_DIFF,
    )

    assert result.decision == Decision.BLOCK


@pytest.mark.parametrize(
    "invalid_diff",
    [
        "",
        "   ",
        None,
    ],
)
def test_missing_git_diff_blocks(invalid_diff):
    result = run_pipelineguard_pr(
        make_scans(),
        make_scans(),
        invalid_diff,
    )

    assert result.decision == Decision.BLOCK


def test_new_high_finding_blocks():
    finding = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="SQL Injection",
        identifier="SQLI-001",
        location="app.py:2",
    )

    result = run_pipelineguard_pr(
        baseline_scans=make_scans(),
        current_scans=make_scans([finding]),
        git_diff=VALID_DIFF,
    )

    assert result.decision == Decision.BLOCK
    assert any(
        "SQLI-001" in reason
        for reason in result.reasons
    )


def test_clean_pr_passes():
    result = run_pipelineguard_pr(
        baseline_scans=make_scans(),
        current_scans=make_scans(),
        git_diff=VALID_DIFF,
    )

    assert result.decision == Decision.PASS