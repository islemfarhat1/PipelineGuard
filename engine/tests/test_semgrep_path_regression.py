"""
Regression tests for the Semgrep differential path bug.

In CI, Semgrep was invoked with absolute targets
($GITHUB_WORKSPACE/baseline/... and $GITHUB_WORKSPACE/current/...).
Reported paths therefore never matched between revisions nor matched
`git diff`, and every pre-existing finding was misclassified as NEW,
blocking unrelated pull requests.
"""

import json

import pytest

from engine.normalizer import normalize_semgrep, validate_repository_path
from engine.tests.test_pr_e2e import (
    git,
    make_manifest,
    make_pr_report,
    run_cli,
)


VULNERABLE_LINE = "result = eval(input())\n"


def semgrep_report(path, line):
    return {
        "results": [{
            "check_id": "pipelineguard-dangerous-eval",
            "path": path,
            "start": {"line": line, "col": 10},
            "end": {"line": line, "col": 23},
            "extra": {
                "severity": "ERROR",
                "message": "Potentially dangerous use of eval()",
            },
        }],
        "errors": [],
    }


def make_shifted_finding_repo(tmp_path):
    """Baseline has eval() on line 1; the PR only adds a comment above."""

    repo = tmp_path / "repo"
    repo.mkdir()

    git(repo, "init")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "PipelineGuard Test")

    app = repo / "app.py"
    app.write_text(VULNERABLE_LINE, encoding="utf-8")
    git(repo, "add", "app.py")
    git(repo, "commit", "-m", "Baseline with existing finding")
    baseline_sha = git(repo, "rev-parse", "HEAD")

    app.write_text("# unrelated comment\n" + VULNERABLE_LINE, encoding="utf-8")
    git(repo, "add", "app.py")
    git(repo, "commit", "-m", "Unrelated PR change")
    head_sha = git(repo, "rev-parse", "HEAD")

    return repo, baseline_sha, head_sha


def write_reports(tmp_path, baseline_path, current_path):
    contents = {
        "baseline": {
            "trivy": {"Results": []},
            "semgrep": semgrep_report(baseline_path, 1),
            "gitleaks": [],
        },
        "current": {
            "trivy": {"Results": []},
            "semgrep": semgrep_report(current_path, 2),
            "gitleaks": [],
        },
    }

    reports = {}

    for revision, scanners in contents.items():
        reports[revision] = {}

        for scanner, content in scanners.items():
            report = tmp_path / f"{revision}-{scanner}.json"
            report.write_text(json.dumps(content), encoding="utf-8")
            reports[revision][scanner] = str(report)

    return reports


def run_scenario(tmp_path, baseline_path, current_path):
    repo, baseline_sha, head_sha = make_shifted_finding_repo(tmp_path)
    reports = write_reports(tmp_path, baseline_path, current_path)
    pr_report = make_pr_report(tmp_path)
    manifest = make_manifest(
        tmp_path, baseline_sha, head_sha, reports, pr_report
    )

    return run_cli(manifest, baseline_sha, head_sha, repo)


def test_existing_shifted_finding_passes(tmp_path, capsys):
    """An untouched pre-existing finding must not block the PR."""

    exit_code = run_scenario(tmp_path, "app.py", "app.py")
    output = capsys.readouterr().out

    assert exit_code == 0, output
    assert "PipelineGuard PR Decision: PASS" in output


def test_absolute_ci_paths_fail_closed(tmp_path, capsys):
    """Reports with workspace-absolute paths must be rejected, not misread."""

    exit_code = run_scenario(
        tmp_path,
        "/home/runner/work/repo/baseline/app.py",
        "/home/runner/work/repo/current/app.py",
    )
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "PipelineGuard PR Decision: BLOCK" in output
    # Must block for the right reason: an invalid report, not a
    # (false) "New HIGH finding" caused by mismatched paths.
    assert "must be repository-relative" in output
    assert "New HIGH finding" not in output


@pytest.mark.parametrize("path", [
    "demo-app/app.py",
    "app.py",
    "src/pkg/module.py",
])
def test_repository_relative_paths_accepted(path):
    assert validate_repository_path(path) == path


@pytest.mark.parametrize("path", [
    "/home/runner/work/repo/current/demo-app/app.py",
    "C:/work/current/demo-app/app.py",
    "demo-app\\app.py",
    "../current/demo-app/app.py",
    "./demo-app/app.py",
    "",
    None,
    42,
])
def test_non_canonical_paths_rejected(path):
    with pytest.raises(ValueError):
        validate_repository_path(path)


@pytest.mark.parametrize("start", [None, {}, {"line": 0}, {"line": "3"}])
def test_semgrep_invalid_start_line_rejected(start):
    report = semgrep_report("app.py", 1)
    report["results"][0]["start"] = start

    with pytest.raises(ValueError):
        normalize_semgrep(report)
