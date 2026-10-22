
from unittest.mock import patch

import pytest

from engine.models import (
    Scanner,
    ScanResult,
    ScanStatus,
    SecurityFinding,
    Severity,
)
from engine.policy import Decision, PolicyResult
from engine.orchestrator import run_pipelineguard_pr_with_commit_scan


BASELINE = "a" * 40
HEAD = "b" * 40


def make_test_manifest():
    """
    Minimal seven-report manifest for mocked integration tests.

    Real SHA-256 verification is covered by provenance
    tests and end-to-end tests.
    """
    reports = {}

    for revision in ("baseline", "current"):
        reports[revision] = {}

        for scanner in ("trivy", "semgrep", "gitleaks"):
            reports[revision][scanner] = {
                "path": f"{revision}-{scanner}.json",
                "sha256": "0" * 64,
            }

    return {
        "baseline_sha": BASELINE,
        "head_sha": HEAD,
        "reports": reports,
        "pr_commit_scan": {
            "gitleaks": {
                "path": "pr-gitleaks.json",
                "sha256": "0" * 64,
            }
        },
    }


@pytest.mark.parametrize(
    "differential_decision,has_secret,expected",
    [
        (Decision.PASS, False, Decision.PASS),
        (Decision.PASS, True, Decision.BLOCK),
        (Decision.BLOCK, False, Decision.BLOCK),
        (Decision.BLOCK, True, Decision.BLOCK),
    ],
)
def test_pr_commit_scan_combined_decision(
    differential_decision,
    has_secret,
    expected,
):
    findings = []

    if has_secret:
        findings.append(
            SecurityFinding(
                scanner=Scanner.GITLEAKS,
                severity=Severity.CRITICAL,
                title="Test secret",
                identifier="pipelineguard-test-secret",
                location="config.py:1",
            )
        )

    scan = ScanResult(
        scanner=Scanner.GITLEAKS,
        status=ScanStatus.SUCCESS,
        findings=findings,
    )

    with (
        patch(
            "engine.orchestrator.verify_pr_provenance_manifest",
            return_value=True,
        ),
        patch(
            "engine.orchestrator.run_pipelineguard_pr_verified",
            return_value=PolicyResult(
                decision=differential_decision,
                reasons=["Differential result"],
            ),
        ),
        patch(
            "engine.orchestrator.load_scan_report",
            return_value=scan,
        ),
    ):
        result = run_pipelineguard_pr_with_commit_scan(
            manifest=make_test_manifest(),
            baseline_sha=BASELINE,
            head_sha=HEAD,
            reports={},
            baseline_gitleaks_exit_code=0,
            current_gitleaks_exit_code=0,
            pr_gitleaks_report="pr-gitleaks.json",
            pr_gitleaks_exit_code=1 if has_secret else 0,
        )

    assert result.decision == expected


def test_pr_commit_scan_invalid_exit_code_blocks():
    scan = ScanResult(
        scanner=Scanner.GITLEAKS,
        status=ScanStatus.SUCCESS,
        findings=[],
    )

    with (
        patch(
            "engine.orchestrator.verify_pr_provenance_manifest",
            return_value=True,
        ),
        patch(
            "engine.orchestrator.run_pipelineguard_pr_verified",
            return_value=PolicyResult(
                decision=Decision.PASS,
                reasons=["OK"],
            ),
        ),
        patch(
            "engine.orchestrator.load_scan_report",
            return_value=scan,
        ),
    ):
        result = run_pipelineguard_pr_with_commit_scan(
            manifest=make_test_manifest(),
            baseline_sha=BASELINE,
            head_sha=HEAD,
            reports={},
            baseline_gitleaks_exit_code=0,
            current_gitleaks_exit_code=0,
            pr_gitleaks_report="pr-gitleaks.json",
            pr_gitleaks_exit_code=2,
        )

    assert result.decision == Decision.BLOCK


def test_invalid_pr_provenance_blocks():
    """
    Invalid provenance must block before the scanners'
    reports are processed.
    """
    with (
        patch(
            "engine.orchestrator.verify_pr_provenance_manifest",
            return_value=False,
        ),
        patch(
            "engine.orchestrator.run_pipelineguard_pr_verified"
        ) as differential_mock,
        patch(
            "engine.orchestrator.load_scan_report"
        ) as loader_mock,
    ):
        result = run_pipelineguard_pr_with_commit_scan(
            manifest=make_test_manifest(),
            baseline_sha=BASELINE,
            head_sha=HEAD,
            reports={},
            baseline_gitleaks_exit_code=0,
            current_gitleaks_exit_code=0,
            pr_gitleaks_report="pr-gitleaks.json",
            pr_gitleaks_exit_code=0,
        )

    assert result.decision == Decision.BLOCK
    differential_mock.assert_not_called()
    loader_mock.assert_not_called()
