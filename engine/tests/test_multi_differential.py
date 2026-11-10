import pytest

from engine.models import Scanner, ScanResult, ScanStatus
from engine.differential import compare_all_scans
from engine.models import SecurityFinding, Severity
from pathlib import Path
from engine.loader import load_scan_report

def test_compare_all_scans_with_clean_reports():
    baseline = [
        ScanResult(
            scanner=scanner,
            status=ScanStatus.SUCCESS,
            findings=[],
        )
        for scanner in Scanner
    ]

    current = [
        ScanResult(
            scanner=scanner,
            status=ScanStatus.SUCCESS,
            findings=[],
        )
        for scanner in Scanner
    ]

    result = compare_all_scans(baseline, current)

    assert len(result.new) == 0
    assert len(result.existing) == 0
    assert len(result.fixed) == 0

def test_compare_all_scans_rejects_missing_baseline_scanner():
    baseline = [
        ScanResult(
            scanner=scanner,
            status=ScanStatus.SUCCESS,
            findings=[],
        )
        for scanner in Scanner
        if scanner != Scanner.SEMGREP
    ]

    current = [
        ScanResult(
            scanner=scanner,
            status=ScanStatus.SUCCESS,
            findings=[],
        )
        for scanner in Scanner
    ]

    with pytest.raises(
        ValueError,
        match="Baseline: missing or unexpected scanners",
    ):
        compare_all_scans(baseline, current)

def test_compare_all_scans_rejects_failed_current_scanner():
    baseline = [
        ScanResult(
            scanner=scanner,
            status=ScanStatus.SUCCESS,
            findings=[],
        )
        for scanner in Scanner
    ]

    current = [
        ScanResult(
            scanner=scanner,
            status=(
                ScanStatus.FAILED
                if scanner == Scanner.TRIVY
                else ScanStatus.SUCCESS
            ),
            findings=[],
            error_message=(
                "Trivy execution failed"
                if scanner == Scanner.TRIVY
                else ""
            ),
        )
        for scanner in Scanner
    ]

    with pytest.raises(
        ValueError,
        match=r"Current: scanner failed: trivy \(Trivy execution failed\)",
    ):
        compare_all_scans(baseline, current)

def test_compare_all_scans_rejects_duplicate_current_scanner():
    baseline = [
        ScanResult(
            scanner=scanner,
            status=ScanStatus.SUCCESS,
            findings=[],
        )
        for scanner in Scanner
    ]

    current = [
        ScanResult(
            scanner=scanner,
            status=ScanStatus.SUCCESS,
            findings=[],
        )
        for scanner in Scanner
    ]

    current.append(
        ScanResult(
            scanner=Scanner.TRIVY,
            status=ScanStatus.SUCCESS,
            findings=[],
        )
    )

    with pytest.raises(
        ValueError,
        match="Current: duplicate scanners",
    ):
        compare_all_scans(baseline, current)

def test_compare_all_scans_detects_new_critical_finding():
    baseline = [
        ScanResult(
            scanner=scanner,
            status=ScanStatus.SUCCESS,
            findings=[],
        )
        for scanner in Scanner
    ]

    critical_finding = SecurityFinding(
        scanner=Scanner.TRIVY,
        severity=Severity.CRITICAL,
        title="Critical vulnerability",
        identifier="CVE-TEST-1234",
        location="demo-app:example-package",
    )

    current = [
        ScanResult(
            scanner=scanner,
            status=ScanStatus.SUCCESS,
            findings=(
                [critical_finding]
                if scanner == Scanner.TRIVY
                else []
            ),
        )
        for scanner in Scanner
    ]

    result = compare_all_scans(baseline, current)

    assert len(result.new) == 1
    assert len(result.existing) == 0
    assert len(result.fixed) == 0
    assert result.new[0].identifier == "CVE-TEST-1234"

def test_compare_all_scans_with_json_reports():
    samples = Path(__file__).resolve().parents[1] / "samples"

    baseline = [
        load_scan_report(
            scanner,
            str(samples / f"{scanner.value}_clean.json"),
        )
        for scanner in Scanner
    ]

    current = [
        load_scan_report(
            scanner,
            str(samples / (
                "trivy_sample.json"
                if scanner == Scanner.TRIVY
                else f"{scanner.value}_clean.json"
            )),
        )
        for scanner in Scanner
    ]

    result = compare_all_scans(baseline, current)

    assert len(result.new) == 2
    assert len(result.existing) == 0
    assert len(result.fixed) == 0