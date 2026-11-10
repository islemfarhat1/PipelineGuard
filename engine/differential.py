
from collections import defaultdict
from dataclasses import dataclass

from engine.models import Scanner, SecurityFinding, ScanResult, ScanStatus
from engine.line_mapping import extract_file_diff, translate_line


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


def semgrep_locations_match(
    old_location: str,
    new_location: str,
    git_diff: str,
) -> bool:
    """Check whether Git maps an old Semgrep location to a new one."""

    try:
        old_path, old_line_text = old_location.rsplit(":", 1)
        new_path, new_line_text = new_location.rsplit(":", 1)

        old_line = int(old_line_text)
        new_line = int(new_line_text)
    except ValueError:
        return False

    if old_path != new_path:
        return False

    file_diff = extract_file_diff(git_diff, old_path)

    if file_diff is None:
        return False

    translated_line = translate_line(old_line, file_diff)

    return translated_line is not None and translated_line == new_line


def semgrep_location_is_unchanged(
    location: str,
    git_diff: str,
) -> bool:
    """Check whether a Semgrep finding's source line is unchanged."""

    try:
        path, line_text = location.rsplit(":", 1)
        old_line = int(line_text)
    except ValueError:
        return False

    file_diff = extract_file_diff(git_diff, path)

    if file_diff is None:
        return False

    translated_line = translate_line(old_line, file_diff)

    return translated_line == old_line


def semgrep_findings_match(
    old: SecurityFinding,
    new: SecurityFinding,
    git_diff: str,
) -> bool:
    """Check whether two Semgrep findings match after a Git line shift."""

    if old.scanner != Scanner.SEMGREP or new.scanner != Scanner.SEMGREP:
        return False

    if old.identifier != new.identifier:
        return False

    if old.severity != new.severity:
        return False

    return semgrep_locations_match(
        old.location,
        new.location,
        git_diff,
    )


def compare_findings(
    baseline: list[SecurityFinding],
    current: list[SecurityFinding],
    git_diff: str | None = None,
) -> DifferentialResult:
    """Classify findings as NEW, EXISTING or FIXED."""

    baseline_groups = defaultdict(list)
    current_groups = defaultdict(list)

    for finding in baseline:
        baseline_groups[finding_key(finding)].append(finding)

    for finding in current:
        current_groups[finding_key(finding)].append(finding)

    result = DifferentialResult(new=[], existing=[], fixed=[])

    all_keys = sorted(set(baseline_groups) | set(current_groups))

    # Phase 1: Compare findings with identical keys.
    for key in all_keys:
        old_findings = baseline_groups[key]
        new_findings = current_groups[key]

        common_count = min(len(old_findings), len(new_findings))

        for index in range(common_count):
            old_finding = old_findings[index]
            new_finding = new_findings[index]

            # If Git confirms that the Semgrep source line changed,
            # do not automatically classify it as EXISTING.
            if (
                git_diff is not None
                and new_finding.scanner == Scanner.SEMGREP
                and extract_file_diff(
                    git_diff,
                    new_finding.location.rsplit(":", 1)[0],
                ) is not None
                and not semgrep_location_is_unchanged(
                    old_finding.location,
                    git_diff,
                )
            ):
                result.new.append(new_finding)
                result.fixed.append(old_finding)
            else:
                result.existing.append(new_finding)

        result.new.extend(new_findings[common_count:])
        result.fixed.extend(old_findings[common_count:])

    # Phase 2: Match Semgrep findings shifted by Git changes.
    if git_diff is not None:
        remaining_new = []

        for new_finding in result.new:
            matched_old = None

            for old_finding in result.fixed:
                if semgrep_findings_match(
                    old_finding,
                    new_finding,
                    git_diff,
                ):
                    matched_old = old_finding
                    break

            if matched_old is not None:
                result.existing.append(new_finding)
                result.fixed.remove(matched_old)
            else:
                remaining_new.append(new_finding)

        result.new = remaining_new

    return result


def compare_scan_results(
    baseline: ScanResult,
    current: ScanResult,
    git_diff: str | None = None,
) -> DifferentialResult:
    """Compare two successful reports from the same scanner."""

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
    git_diff=git_diff,
)


def compare_all_scans(
    baseline: list[ScanResult],
    current: list[ScanResult],
    git_diff: str | None = None,
) -> DifferentialResult:
    """Compare complete baseline and current scanner reports."""

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

        failed = [
            f"{scan.scanner.value} ({scan.error_message or 'unknown error'})"
            for scan in scans
            if scan.status != ScanStatus.SUCCESS
        ]

        if failed:
            raise ValueError(
                f"{source}: scanner failed: " + "; ".join(failed)
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
            git_diff=git_diff,
        )

        result.new.extend(comparison.new)
        result.existing.extend(comparison.existing)
        result.fixed.extend(comparison.fixed)

    return result
