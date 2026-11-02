import pytest

from engine.models import (
    Scanner,
    ScanResult,
    ScanStatus,
    SecurityFinding,
    Severity,
)
from engine.orchestrator import run_pipelineguard_pr_from_git
from engine.policy import Decision


BASELINE = "a" * 40
HEAD = "b" * 40


def clean_scans():
    return [
        ScanResult(
            scanner=scanner,
            status=ScanStatus.SUCCESS,
            findings=[],
        )
        for scanner in Scanner
    ]


def test_git_failure_blocks(monkeypatch):
    def fake_diff(**kwargs):
        raise ValueError("Invalid Git revision")

    monkeypatch.setattr(
        "engine.orchestrator.get_verified_git_diff",
        fake_diff,
    )

    result = run_pipelineguard_pr_from_git(
        clean_scans(),
        clean_scans(),
        BASELINE,
        HEAD,
    )

    assert result.decision == Decision.BLOCK


def test_verified_empty_diff_passes(monkeypatch):
    monkeypatch.setattr(
        "engine.orchestrator.get_verified_git_diff",
        lambda **kwargs: "",
    )

    result = run_pipelineguard_pr_from_git(
        clean_scans(),
        clean_scans(),
        BASELINE,
        HEAD,
    )

    assert result.decision == Decision.PASS


def test_new_high_finding_blocks(monkeypatch):
    monkeypatch.setattr(
        "engine.orchestrator.get_verified_git_diff",
        lambda **kwargs: (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        ),
    )

    finding = SecurityFinding(
        scanner=Scanner.SEMGREP,
        severity=Severity.HIGH,
        title="SQL Injection",
        identifier="SQLI-001",
        location="app.py:1",
    )

    current = clean_scans()

    for scan in current:
        if scan.scanner == Scanner.SEMGREP:
            scan.findings.append(finding)

    result = run_pipelineguard_pr_from_git(
        clean_scans(),
        current,
        BASELINE,
        HEAD,
    )

    assert result.decision == Decision.BLOCK


@pytest.mark.parametrize(
    "invalid_case",
    ["missing", "failed"],
)
def test_invalid_scanner_blocks(monkeypatch, invalid_case):
    monkeypatch.setattr(
        "engine.orchestrator.get_verified_git_diff",
        lambda **kwargs: "",
    )

    current = clean_scans()

    if invalid_case == "missing":
        current.pop()
    else:
        current[0].status = ScanStatus.FAILED

    result = run_pipelineguard_pr_from_git(
        clean_scans(),
        current,
        BASELINE,
        HEAD,
    )

    assert result.decision == Decision.BLOCK