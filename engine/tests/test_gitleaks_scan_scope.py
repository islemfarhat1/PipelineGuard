"""
Regression tests for the scope of the V2 Gitleaks scans.

The baseline and current scans used a single SHA in --log-opts, which
reads every ancestor commit. One secret that ever reached main was
therefore reported as EXISTING and blocked every later pull request.
"""

import json
from pathlib import Path

import pytest

from engine.normalizer import normalize_gitleaks
from engine.tests.test_pr_e2e import (
    make_git_repo,
    make_manifest,
    make_pr_report,
    run_cli,
)


WORKFLOW = (
    Path(__file__).resolve().parents[2]
    / ".github" / "workflows" / "security-v2.yml"
)


def gitleaks_finding(file="config.py"):
    return {
        "RuleID": "pipelineguard-test-secret",
        "File": file,
        "StartLine": 1,
        "Description": "Simulated secret",
    }


def run_scenario(tmp_path, baseline_findings, current_findings):
    repo, baseline_sha, head_sha = make_git_repo(tmp_path)

    gitleaks = {
        "baseline": baseline_findings,
        "current": current_findings,
    }

    reports = {}

    for revision, findings in gitleaks.items():
        contents = {
            "trivy": {"Results": []},
            "semgrep": {"results": []},
            "gitleaks": findings,
        }
        reports[revision] = {}

        for scanner, content in contents.items():
            report = tmp_path / f"{revision}-{scanner}.json"
            report.write_text(json.dumps(content), encoding="utf-8")
            reports[revision][scanner] = str(report)

    manifest = make_manifest(
        tmp_path,
        baseline_sha,
        head_sha,
        reports,
        make_pr_report(tmp_path),
    )

    return run_cli(
        manifest,
        baseline_sha,
        head_sha,
        repo,
        baseline_exit=1 if baseline_findings else 0,
        current_exit=1 if current_findings else 0,
    )


def test_pr_removing_a_secret_passes(tmp_path, capsys):
    """A secret in the baseline files and gone from the PR is FIXED."""

    exit_code = run_scenario(tmp_path, [gitleaks_finding()], [])
    output = capsys.readouterr().out

    assert exit_code == 0, output
    assert "PipelineGuard PR Decision: PASS" in output


def test_secret_still_in_files_blocks(tmp_path, capsys):
    finding = gitleaks_finding()

    exit_code = run_scenario(tmp_path, [finding], [finding])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "Existing secret detected" in output


def test_absolute_gitleaks_path_fails_closed(tmp_path, capsys):
    exit_code = run_scenario(
        tmp_path,
        [],
        [gitleaks_finding("/home/runner/work/repo/current/config.py")],
    )
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "must be repository-relative" in output


@pytest.mark.parametrize("file", [
    "/home/runner/work/repo/current/config.py",
    "demo-app\\config.py",
    "../config.py",
])
def test_non_canonical_gitleaks_paths_rejected(file):
    with pytest.raises(ValueError):
        normalize_gitleaks([gitleaks_finding(file)])


def test_workflow_scans_files_for_revisions_and_commits_for_pr():
    """Guard the workflow: the engine cannot detect a wrong scan scope."""

    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert 'scan baseline "$GITHUB_WORKSPACE/baseline" dir .' in workflow
    assert 'scan current "$GITHUB_WORKSPACE/current" dir .' in workflow
    assert '--log-opts="${BASELINE_SHA}..${HEAD_SHA}"' in workflow
    assert '--log-opts="$BASELINE_SHA"' not in workflow
    assert '--log-opts="$HEAD_SHA"' not in workflow
