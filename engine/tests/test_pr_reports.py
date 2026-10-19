import json

import pytest

from engine.orchestrator import run_pipelineguard_pr_from_reports
from engine.policy import Decision


BASELINE = "a" * 40
HEAD = "b" * 40


def write_reports(tmp_path, prefix):
    paths = {}

    reports = {
        "trivy": {"Results": []},
        "semgrep": {"results": []},
        "gitleaks": [],
    }

    for scanner, report in reports.items():
        path = tmp_path / f"{prefix}-{scanner}.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        paths[scanner] = str(path)

    return paths


def evaluate(tmp_path, monkeypatch, **overrides):
    monkeypatch.setattr(
        "engine.orchestrator.get_verified_git_diff",
        lambda **kwargs: "",
    )

    baseline = write_reports(tmp_path, "baseline")
    current = write_reports(tmp_path, "current")

    arguments = {
        "baseline_trivy": baseline["trivy"],
        "baseline_semgrep": baseline["semgrep"],
        "baseline_gitleaks": baseline["gitleaks"],
        "current_trivy": current["trivy"],
        "current_semgrep": current["semgrep"],
        "current_gitleaks": current["gitleaks"],
        "baseline_gitleaks_exit_code": 0,
        "current_gitleaks_exit_code": 0,
        "baseline_sha": BASELINE,
        "head_sha": HEAD,
    }

    arguments.update(overrides)

    return run_pipelineguard_pr_from_reports(**arguments)


def test_clean_reports_pass(tmp_path, monkeypatch):
    result = evaluate(tmp_path, monkeypatch)
    assert result.decision == Decision.PASS


@pytest.mark.parametrize(
    "report_name",
    [
        "baseline_trivy",
        "baseline_semgrep",
        "baseline_gitleaks",
        "current_trivy",
        "current_semgrep",
        "current_gitleaks",
    ],
)
def test_missing_report_blocks(tmp_path, monkeypatch, report_name):
    result = evaluate(
        tmp_path,
        monkeypatch,
        **{report_name: str(tmp_path / "missing.json")},
    )

    assert result.decision == Decision.BLOCK


@pytest.mark.parametrize(
    "exit_code_name",
    [
        "baseline_gitleaks_exit_code",
        "current_gitleaks_exit_code",
    ],
)
def test_invalid_gitleaks_exit_code_blocks(
    tmp_path,
    monkeypatch,
    exit_code_name,
):
    result = evaluate(
        tmp_path,
        monkeypatch,
        **{exit_code_name: 2},
    )

    assert result.decision == Decision.BLOCK


def test_inconsistent_gitleaks_exit_code_blocks(
    tmp_path,
    monkeypatch,
):
    result = evaluate(
        tmp_path,
        monkeypatch,
        current_gitleaks_exit_code=1,
    )

    assert result.decision == Decision.BLOCK