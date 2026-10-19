
from dataclasses import dataclass
from enum import Enum
from engine.models import (
    Scanner,
    SecurityFinding,
    Severity,
    ScanResult,
    ScanStatus,
)
from engine.differential import DifferentialResult

class Decision(str, Enum):
    PASS = "PASS"
    BLOCK = "BLOCK"


@dataclass
class PolicyResult:
    decision: Decision
    reasons: list[str]


def evaluate_policy(findings: list[SecurityFinding]) -> PolicyResult:
    reasons = []

    for finding in findings:
        if finding.scanner == Scanner.GITLEAKS:
            reasons.append(
                f"Secret detected: {finding.identifier}"
            )

        elif finding.severity == Severity.CRITICAL:
            reasons.append(
                f"Critical finding detected: {finding.identifier}"
            )

    if reasons:
        return PolicyResult(
            decision=Decision.BLOCK,
            reasons=reasons
        )

    return PolicyResult(
        decision=Decision.PASS,
        reasons=["No blocking security findings detected"]
    )


def evaluate_scans(scans: list[ScanResult]) -> PolicyResult:
    expected_scanners = set(Scanner)
    received_scanners = [scan.scanner for scan in scans]

    # Verify that every required scanner is represented
    missing = expected_scanners - set(received_scanners)

    if missing:
        return PolicyResult(
            decision=Decision.BLOCK,
            reasons=[
                f"Missing scanner: {scanner.value}"
                for scanner in sorted(missing, key=lambda s: s.value)
            ]
        )

    # Reject duplicate scanner results
    if len(received_scanners) != len(set(received_scanners)):
        return PolicyResult(
            decision=Decision.BLOCK,
            reasons=["Duplicate scanner results detected"]
        )

    # Fail closed if a scanner failed
    failed_scans = [
        scan for scan in scans
        if scan.status != ScanStatus.SUCCESS
    ]

    if failed_scans:
        return PolicyResult(
            decision=Decision.BLOCK,
            reasons=[
                f"Scanner {scan.scanner.value} failed: "
                f"{scan.error_message or 'Unknown error'}"
                for scan in failed_scans
            ]
        )

    # All scanners succeeded: evaluate their findings
    all_findings = [
        finding
        for scan in scans
        for finding in scan.findings
    ]

    return evaluate_policy(all_findings)

def evaluate_pr_policy(
    differential: DifferentialResult,
) -> PolicyResult:
    reasons = []

    # Evaluate findings introduced by the PR
    for finding in differential.new:
        if finding.scanner == Scanner.GITLEAKS:
            reasons.append(
                f"New secret detected: {finding.identifier}"
            )

        elif finding.severity in (Severity.HIGH, Severity.CRITICAL):
            reasons.append(
                f"New {finding.severity.value} finding: {finding.identifier}"
            )

    # Preserve V1 protections for existing findings
    for finding in differential.existing:
        if finding.scanner == Scanner.GITLEAKS:
            reasons.append(
                f"Existing secret detected: {finding.identifier}"
            )

        elif finding.severity == Severity.CRITICAL:
            reasons.append(
                f"Existing critical finding: {finding.identifier}"
            )

    if reasons:
        return PolicyResult(
            decision=Decision.BLOCK,
            reasons=reasons,
        )

    return PolicyResult(
        decision=Decision.PASS,
        reasons=["No blocking PR security findings detected"],
    )
