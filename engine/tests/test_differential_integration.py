from pathlib import Path

from engine.loader import load_scan_report
from engine.models import Scanner, ScanStatus
from engine.differential import compare_findings
import pytest
from engine.differential import compare_scan_results

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_trivy_json_differential_integration():
    baseline = load_scan_report(
        Scanner.TRIVY,
        str(SAMPLES / "trivy_clean.json"),
    )

    current = load_scan_report(
        Scanner.TRIVY,
        str(SAMPLES / "trivy_sample.json"),
    )

    # Both reports must be loaded successfully.
    assert baseline.status == ScanStatus.SUCCESS
    assert current.status == ScanStatus.SUCCESS

    # Compare the normalized findings.
    result = compare_findings(
        baseline.findings,
        current.findings,
    )

    assert len(result.new) == 2
    assert len(result.existing) == 0
    assert len(result.fixed) == 0

def test_trivy_json_fixed_findings():
    baseline = load_scan_report(
        Scanner.TRIVY,
        str(SAMPLES / "trivy_sample.json"),
    )

    current = load_scan_report(
        Scanner.TRIVY,
        str(SAMPLES / "trivy_clean.json"),
    )

    assert baseline.status == ScanStatus.SUCCESS
    assert current.status == ScanStatus.SUCCESS

    result = compare_findings(
        baseline.findings,
        current.findings,
    )

    assert len(result.new) == 0
    assert len(result.existing) == 0
    assert len(result.fixed) == 2

def test_missing_baseline_report_is_rejected():
    baseline = load_scan_report(
        Scanner.TRIVY,
        str(SAMPLES / "nonexistent_baseline.json"),
    )

    current = load_scan_report(
        Scanner.TRIVY,
        str(SAMPLES / "trivy_sample.json"),
    )

    assert baseline.status == ScanStatus.FAILED
    assert current.status == ScanStatus.SUCCESS

def test_differential_rejects_failed_baseline():
    baseline = load_scan_report(
        Scanner.TRIVY,
        str(SAMPLES / "nonexistent_baseline.json"),
    )

    current = load_scan_report(
        Scanner.TRIVY,
        str(SAMPLES / "trivy_sample.json"),
    )

    with pytest.raises(ValueError):
        compare_scan_results(baseline, current)

def test_differential_rejects_failed_current():
    baseline = load_scan_report(
        Scanner.TRIVY,
        str(SAMPLES / "trivy_clean.json"),
    )

    current = load_scan_report(
        Scanner.TRIVY,
        str(SAMPLES / "nonexistent_current.json"),
    )

    assert baseline.status == ScanStatus.SUCCESS
    assert current.status == ScanStatus.FAILED

    with pytest.raises(ValueError, match="Current scan failed"):
        compare_scan_results(baseline, current)


def test_differential_rejects_different_scanners():
    baseline = load_scan_report(
        Scanner.TRIVY,
        str(SAMPLES / "trivy_clean.json"),
    )

    current = load_scan_report(
        Scanner.SEMGREP,
        str(SAMPLES / "semgrep_sample.json"),
    )

    assert baseline.status == ScanStatus.SUCCESS
    assert current.status == ScanStatus.SUCCESS

    with pytest.raises(
        ValueError,
        match="Cannot compare reports from different scanners",
    ):
        compare_scan_results(baseline, current)