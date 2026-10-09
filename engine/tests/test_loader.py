
from pathlib import Path

from engine.loader import load_scan_report
from engine.models import Scanner, ScanStatus


def test_valid_trivy_report():
    sample_path = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "trivy_sample.json"
    )

    result = load_scan_report(
        Scanner.TRIVY,
        str(sample_path)
    )

    assert result.status == ScanStatus.SUCCESS
    assert len(result.findings) == 2
    assert result.error_message == ""


def test_missing_report():
    result = load_scan_report(
        Scanner.TRIVY,
        "nonexistent-report-12345.json"
    )

    assert result.status == ScanStatus.FAILED
    assert result.findings == []
    assert result.error_message != ""


def test_invalid_json_report(tmp_path):
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text(
        "{ invalid json }",
        encoding="utf-8"
    )

    result = load_scan_report(
        Scanner.TRIVY,
        str(invalid_file)
    )

    assert result.status == ScanStatus.FAILED
    assert result.findings == []
    assert result.error_message != ""
