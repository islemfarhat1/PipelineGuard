
import json
import pytest
from pathlib import Path

from engine.models import Scanner, Severity
from engine.normalizer import (
    normalize_trivy,
    normalize_semgrep,
    normalize_gitleaks,
)
from engine.policy import Decision, evaluate_policy


def test_trivy_normalization():
    sample_path = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "trivy_sample.json"
    )

    report = json.loads(
        sample_path.read_text(encoding="utf-8")
    )

    findings = normalize_trivy(report)

    # Verify normalization
    assert len(findings) == 2

    assert findings[0].scanner == Scanner.TRIVY
    assert findings[0].severity == Severity.HIGH
    assert findings[0].identifier == "CVE-TEST-0001"

    assert findings[1].severity == Severity.CRITICAL
    assert findings[1].identifier == "CVE-TEST-0002"

    # Verify policy decision
    result = evaluate_policy(findings)

    assert result.decision == Decision.BLOCK
    assert "CVE-TEST-0002" in result.reasons[0]


def test_semgrep_normalization():
    report = {
        "results": [
            {
                "check_id": "dangerous-eval",
                "path": "demo-app/app.py",
                "start": {"line": 12},
                "extra": {
                    "severity": "ERROR",
                    "message": "Unsafe eval"
                }
            }
        ]
    }

    findings = normalize_semgrep(report)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.scanner == Scanner.SEMGREP
    assert finding.severity == Severity.HIGH
    assert finding.identifier == "dangerous-eval"
    assert finding.location == "demo-app/app.py:12"
    assert finding.title == "Unsafe eval"


def test_gitleaks_normalization():
    report = [
        {
            "RuleID": "test-secret",
            "Description": "Exposed API key",
            "File": "config.py",
            "StartLine": 8
        }
    ]

    findings = normalize_gitleaks(report)

    # Verify normalization
    assert len(findings) == 1

    finding = findings[0]

    assert finding.scanner == Scanner.GITLEAKS
    assert finding.severity == Severity.CRITICAL
    assert finding.identifier == "test-secret"
    assert finding.location == "config.py:8"

    # Verify security policy
    result = evaluate_policy(findings)

    assert result.decision == Decision.BLOCK
    assert "test-secret" in result.reasons[0]

def test_trivy_invalid_report_rejected():
    invalid_report = {}

    with pytest.raises(
        ValueError,
        match="missing Results list"
    ):
        normalize_trivy(invalid_report)

def test_semgrep_invalid_report_rejected():
    invalid_report = {}

    with pytest.raises(
        ValueError,
        match="missing results list"
    ):
        normalize_semgrep(invalid_report)



def test_gitleaks_invalid_report_rejected():
    invalid_report = {}

    with pytest.raises(
        ValueError,
        match="expected JSON array"
    ):
        normalize_gitleaks(invalid_report)


def test_trivy_invalid_vulnerabilities_rejected():
    invalid_report = {
        "Results": [
            {
                "Target": "Debian",
                "Vulnerabilities": "INVALID_DATA"
            }
        ]
    }

    with pytest.raises(
        ValueError,
        match="Vulnerabilities must be a list"
    ):
        normalize_trivy(invalid_report)



def test_semgrep_unknown_severity_rejected():
    invalid_report = {
        "results": [
            {
                "check_id": "dangerous-eval",
                "path": "app.py",
                "start": {"line": 12},
                "extra": {
                    "severity": "UNKNOWN",
                    "message": "Unsafe eval"
                }
            }
        ]
    }

    with pytest.raises(
        ValueError,
        match="Invalid Semgrep severity"
    ):
        normalize_semgrep(invalid_report)

def test_gitleaks_missing_file_rejected():
    invalid_report = [
        {
            "RuleID": "test-secret",
            "Description": "Exposed API key",
            "StartLine": 8
        }
    ]

    with pytest.raises(
        ValueError,
        match="missing or invalid File"
    ):
        normalize_gitleaks(invalid_report)
