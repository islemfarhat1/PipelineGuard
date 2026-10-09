
from pathlib import Path

from engine.orchestrator import run_pipelineguard
from engine.policy import Decision


SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"


def test_orchestrator_blocks_security_findings():
    result = run_pipelineguard(
        str(SAMPLES_DIR / "trivy_sample.json"),
        str(SAMPLES_DIR / "semgrep_sample.json"),
        str(SAMPLES_DIR / "gitleaks_sample.json"),
        gitleaks_exit_code=1
    )

    assert result.decision == Decision.BLOCK

    assert (
        "Critical finding detected: CVE-TEST-0002"
        in result.reasons
    )

    assert (
        "Secret detected: pipelineguard-test-secret"
        in result.reasons
    )


def test_orchestrator_blocks_missing_reports():
    result = run_pipelineguard(
        str(SAMPLES_DIR / "trivy_sample.json"),
        str(SAMPLES_DIR / "missing-semgrep.json"),
        str(SAMPLES_DIR / "missing-gitleaks.json"),
        gitleaks_exit_code=0
    )

    assert result.decision == Decision.BLOCK

    assert any(
        "semgrep failed" in reason
        for reason in result.reasons
    )

    assert any(
        "gitleaks failed" in reason
        for reason in result.reasons
    )

def test_orchestrator_blocks_inconsistent_gitleaks_result():
    result = run_pipelineguard(
        str(SAMPLES_DIR / "trivy_sample.json"),
        str(SAMPLES_DIR / "semgrep_sample.json"),
        str(SAMPLES_DIR / "gitleaks_sample.json"),
        gitleaks_exit_code=0
    )

    assert result.decision == Decision.BLOCK

    assert any(
        "Inconsistent Gitleaks exit code and report" in reason
        for reason in result.reasons
    )
