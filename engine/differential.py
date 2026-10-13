from collections import defaultdict
from dataclasses import dataclass

from engine.models import Scanner, SecurityFinding, ScanResult, ScanStatus

@dataclass
class DifferentialResult:
    new: list[SecurityFinding]
    existing: list[SecurityFinding]
    fixed: list[SecurityFinding]


def finding_key(finding: SecurityFinding) -> tuple[str, str, str, str]:
    return (
        finding.scanner.value,
        finding.identifier,
        finding.location,
        finding.severity.value,
    )


def compare_findings(
    baseline: list[SecurityFinding],
    current: list[SecurityFinding],
) -> DifferentialResult:

    baseline_groups = defaultdict(list)
    current_groups = defaultdict(list)

    for finding in baseline:
        baseline_groups[finding_key(finding)].append(finding)

    for finding in current:
        current_groups[finding_key(finding)].append(finding)

    result = DifferentialResult(new=[], existing=[], fixed=[])

    all_keys = sorted(set(baseline_groups) | set(current_groups))

    for key in all_keys:
        old_findings = baseline_groups[key]
        new_findings = current_groups[key]

        common_count = min(len(old_findings), len(new_findings))

        result.existing.extend(new_findings[:common_count])
        result.new.extend(new_findings[common_count:])
        result.fixed.extend(old_findings[common_count:])

    return result

def compare_scan_results(
    baseline: ScanResult,
    current: ScanResult,
) -> DifferentialResult:

    if baseline.scanner != current.scanner:
        raise ValueError(
            "Cannot compare reports from different scanners"
        )

    if baseline.status != ScanStatus.SUCCESS:
        raise ValueError(
            "Baseline scan failed: "
            + (baseline.error_message or "Unknown error")
        )

    if current.status != ScanStatus.SUCCESS:
        raise ValueError(
            "Current scan failed: "
            + (current.error_message or "Unknown error")
        )

    return compare_findings(
        baseline.findings,
        current.findings,
    )

def compare_all_scans(
    baseline: list[ScanResult],
    current: list[ScanResult],
) -> DifferentialResult:

    def validate(scans: list[ScanResult], source: str):
        expected = set(Scanner)
        received = [scan.scanner for scan in scans]

        if set(received) != expected:
            raise ValueError(
                f"{source}: missing or unexpected scanners"
            )

        if len(received) != len(set(received)):
            raise ValueError(
                f"{source}: duplicate scanners"
            )

        if any(scan.status != ScanStatus.SUCCESS for scan in scans):
            raise ValueError(
                f"{source}: one or more scanners failed"
            )

    validate(baseline, "Baseline")
    validate(current, "Current")

    baseline_by_scanner = {
        scan.scanner: scan for scan in baseline
    }

    current_by_scanner = {
        scan.scanner: scan for scan in current
    }

    result = DifferentialResult(
        new=[],
        existing=[],
        fixed=[],
    )

    for scanner in Scanner:
        comparison = compare_scan_results(
            baseline_by_scanner[scanner],
            current_by_scanner[scanner],
        )

        result.new.extend(comparison.new)
        result.existing.extend(comparison.existing)
        result.fixed.extend(comparison.fixed)

    return result

