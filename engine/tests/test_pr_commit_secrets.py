import pytest

from engine.models import (
    Scanner,
    ScanResult,
    ScanStatus,
    SecurityFinding,
    Severity,
)
from engine.policy import (
    Decision,
    evaluate_pr_commit_secrets,
)


def make_scan(
    scanner=Scanner.GITLEAKS,
    status=ScanStatus.SUCCESS,
    findings=None,
):
    return ScanResult(
        scanner=scanner,
        status=status,
        findings=[] if findings is None else findings,
    )


def test_clean_pr_commits_pass():
    result = evaluate_pr_commit_secrets(make_scan())
    assert result.decision == Decision.PASS


def test_secret_in_pr_commits_blocks():
    finding = SecurityFinding(
        scanner=Scanner.GITLEAKS,
        severity=Severity.CRITICAL,
        title="Exposed test secret",
        identifier="pipelineguard-test-secret",
        location="config.py:10",
    )

    result = evaluate_pr_commit_secrets(
        make_scan(findings=[finding])
    )

    assert result.decision == Decision.BLOCK


def test_failed_pr_scan_blocks():
    result = evaluate_pr_commit_secrets(
        make_scan(status=ScanStatus.FAILED)
    )

    assert result.decision == Decision.BLOCK


def test_wrong_scanner_blocks():
    result = evaluate_pr_commit_secrets(
        make_scan(scanner=Scanner.SEMGREP)
    )

    assert result.decision == Decision.BLOCK