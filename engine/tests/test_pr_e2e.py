
import json
import subprocess

import pytest

from engine.pr_cli import main
from engine.provenance import create_pr_provenance_manifest


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def make_git_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    git(repo, "init")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "PipelineGuard Test")

    app = repo / "app.py"
    app.write_text("print('baseline')\n", encoding="utf-8")

    git(repo, "add", "app.py")
    git(repo, "commit", "-m", "Baseline")
    baseline_sha = git(repo, "rev-parse", "HEAD")

    app.write_text("print('current')\n", encoding="utf-8")

    git(repo, "add", "app.py")
    git(repo, "commit", "-m", "Current")
    head_sha = git(repo, "rev-parse", "HEAD")

    return repo, baseline_sha, head_sha


def make_reports(tmp_path, scenario=None):
    reports = {}

    finding = {
        "check_id": "python-security-test",
        "path": "app.py",
        "start": {"line": 1, "col": 1},
        "end": {"line": 1, "col": 5},
        "extra": {
            "severity": "ERROR",
            "message": "Test security finding",
        },
    }

    for revision in ("baseline", "current"):
        reports[revision] = {}

        semgrep_findings = []

        if scenario == "new_high" and revision == "current":
            semgrep_findings = [finding]

        if scenario == "fixed_high" and revision == "baseline":
            semgrep_findings = [finding]

        contents = {
            "trivy": {"Results": []},
            "semgrep": {"results": semgrep_findings},
            "gitleaks": [],
        }

        for scanner, content in contents.items():
            path = tmp_path / f"{revision}-{scanner}.json"
            path.write_text(
                json.dumps(content),
                encoding="utf-8",
            )
            reports[revision][scanner] = str(path)

    return reports


def make_pr_report(tmp_path, has_secret=False):
    path = tmp_path / "gitleaks-pr-report.json"

    findings = []

    if has_secret:
        findings.append({
            "RuleID": "pipelineguard-test-secret",
            "File": "config.py",
            "StartLine": 1,
            "Commit": "c" * 40,
            "Description": "Simulated secret in PR history",
        })

    path.write_text(
        json.dumps(findings),
        encoding="utf-8",
    )

    return path


def make_manifest(
    tmp_path,
    baseline_sha,
    head_sha,
    reports,
    pr_report,
):
    manifest = create_pr_provenance_manifest(
        baseline_sha,
        head_sha,
        reports,
        str(pr_report),
    )

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    return manifest_path


def run_cli(
    manifest_path,
    baseline_sha,
    head_sha,
    repo,
    baseline_exit=0,
    current_exit=0,
    pr_exit=0,
):
    return main([
        "--manifest", str(manifest_path),
        "--baseline-sha", baseline_sha,
        "--head-sha", head_sha,
        "--repo-path", str(repo),
        "--baseline-gitleaks-exit-code", str(baseline_exit),
        "--current-gitleaks-exit-code", str(current_exit),
        "--pr-gitleaks-exit-code", str(pr_exit),
    ])


def test_clean_pr_end_to_end(tmp_path, capsys):
    repo, baseline_sha, head_sha = make_git_repo(tmp_path)
    reports = make_reports(tmp_path)
    pr_report = make_pr_report(tmp_path)

    manifest_path = make_manifest(
        tmp_path, baseline_sha, head_sha, reports, pr_report
    )

    exit_code = run_cli(
        manifest_path, baseline_sha, head_sha, repo
    )

    output = capsys.readouterr().out

    assert exit_code == 0
    assert "PipelineGuard PR Decision: PASS" in output


@pytest.mark.parametrize(
    "scenario",
    ["tampered_report", "wrong_sha", "scanner_failure"],
)
def test_pr_security_fail_closed(tmp_path, capsys, scenario):
    repo, baseline_sha, head_sha = make_git_repo(tmp_path)
    reports = make_reports(tmp_path)
    pr_report = make_pr_report(tmp_path)

    manifest_path = make_manifest(
        tmp_path, baseline_sha, head_sha, reports, pr_report
    )

    if scenario == "tampered_report":
        path = reports["current"]["semgrep"]

        with open(path, "w", encoding="utf-8") as file:
            json.dump(
                {"results": [{"unexpected": "change"}]},
                file,
            )

    elif scenario == "wrong_sha":
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )
        manifest["head_sha"] = "f" * 40
        manifest_path.write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )

    current_exit = (
        2 if scenario == "scanner_failure" else 0
    )

    exit_code = run_cli(
        manifest_path,
        baseline_sha,
        head_sha,
        repo,
        current_exit=current_exit,
    )

    output = capsys.readouterr().out

    assert exit_code == 1
    assert "PipelineGuard PR Decision: BLOCK" in output


@pytest.mark.parametrize(
    "scenario,expected_decision",
    [
        ("new_high", "BLOCK"),
        ("fixed_high", "PASS"),
    ],
)
def test_pr_finding_policy_end_to_end(
    tmp_path,
    capsys,
    scenario,
    expected_decision,
):
    repo, baseline_sha, head_sha = make_git_repo(tmp_path)
    reports = make_reports(tmp_path, scenario=scenario)
    pr_report = make_pr_report(tmp_path)

    manifest_path = make_manifest(
        tmp_path, baseline_sha, head_sha, reports, pr_report
    )

    exit_code = run_cli(
        manifest_path, baseline_sha, head_sha, repo
    )

    output = capsys.readouterr().out

    expected_exit = (
        0 if expected_decision == "PASS" else 1
    )

    assert exit_code == expected_exit
    assert (
        f"PipelineGuard PR Decision: {expected_decision}"
        in output
    )


def test_secret_in_pr_commits_blocks(tmp_path, capsys):
    repo, baseline_sha, head_sha = make_git_repo(tmp_path)
    reports = make_reports(tmp_path)
    pr_report = make_pr_report(tmp_path, has_secret=True)

    manifest_path = make_manifest(
        tmp_path, baseline_sha, head_sha, reports, pr_report
    )

    exit_code = run_cli(
        manifest_path,
        baseline_sha,
        head_sha,
        repo,
        pr_exit=1,
    )

    output = capsys.readouterr().out

    assert exit_code == 1
    assert "PipelineGuard PR Decision: BLOCK" in output
    assert "Secret detected in PR commits" in output


def test_tampered_pr_report_blocks(tmp_path, capsys):
    repo, baseline_sha, head_sha = make_git_repo(tmp_path)
    reports = make_reports(tmp_path)
    pr_report = make_pr_report(tmp_path)

    manifest_path = make_manifest(
        tmp_path, baseline_sha, head_sha, reports, pr_report
    )

    pr_report.write_text(
        '[{"RuleID": "unexpected-secret"}]',
        encoding="utf-8",
    )

    exit_code = run_cli(
        manifest_path, baseline_sha, head_sha, repo
    )

    output = capsys.readouterr().out

    assert exit_code == 1
    assert "PipelineGuard PR Decision: BLOCK" in output


def test_invalid_pr_gitleaks_exit_code_blocks(tmp_path, capsys):
    repo, baseline_sha, head_sha = make_git_repo(tmp_path)
    reports = make_reports(tmp_path)
    pr_report = make_pr_report(tmp_path)

    manifest_path = make_manifest(
        tmp_path, baseline_sha, head_sha, reports, pr_report
    )

    exit_code = run_cli(
        manifest_path,
        baseline_sha,
        head_sha,
        repo,
        pr_exit=2,
    )

    output = capsys.readouterr().out

    assert exit_code == 1
    assert "PipelineGuard PR Decision: BLOCK" in output
