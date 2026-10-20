import json
import subprocess

from engine.pr_cli import main
from engine.provenance import create_provenance_manifest
import pytest


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_clean_pr_end_to_end(tmp_path, capsys):
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

    reports = {}

    for revision in ("baseline", "current"):
        reports[revision] = {}

        for scanner, content in {
            "trivy": {"Results": []},
            "semgrep": {"results": []},
            "gitleaks": [],
        }.items():
            path = tmp_path / f"{revision}-{scanner}.json"
            path.write_text(
                json.dumps(content),
                encoding="utf-8",
            )
            reports[revision][scanner] = str(path)

    manifest = create_provenance_manifest(
        baseline_sha,
        head_sha,
        reports,
    )

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    exit_code = main([
        "--manifest", str(manifest_path),
        "--baseline-sha", baseline_sha,
        "--head-sha", head_sha,
        "--repo-path", str(repo),
        "--baseline-gitleaks-exit-code", "0",
        "--current-gitleaks-exit-code", "0",
    ])

    output = capsys.readouterr().out

    assert exit_code == 0
    assert "PipelineGuard PR Decision: PASS" in output

@pytest.mark.parametrize(
    "scenario",
    ["tampered_report", "wrong_sha", "scanner_failure"],
)
def test_pr_security_fail_closed(tmp_path, capsys, scenario):
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

    reports = {}

    for revision in ("baseline", "current"):
        reports[revision] = {}

        for scanner, content in {
            "trivy": {"Results": []},
            "semgrep": {"results": []},
            "gitleaks": [],
        }.items():
            path = tmp_path / f"{revision}-{scanner}.json"
            path.write_text(json.dumps(content), encoding="utf-8")
            reports[revision][scanner] = str(path)

    manifest = create_provenance_manifest(
        baseline_sha, head_sha, reports
    )

    if scenario == "tampered_report":
        path = reports["current"]["semgrep"]
        with open(path, "w", encoding="utf-8") as file:
            json.dump({"results": [{"unexpected": "change"}]}, file)

    elif scenario == "wrong_sha":
        manifest["head_sha"] = "f" * 40

    elif scenario == "scanner_failure":
        # Simulate an unsuccessful Gitleaks scan.
        pass

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    current_exit_code = 2 if scenario == "scanner_failure" else 0

    exit_code = main([
        "--manifest", str(manifest_path),
        "--baseline-sha", baseline_sha,
        "--head-sha", head_sha,
        "--repo-path", str(repo),
        "--baseline-gitleaks-exit-code", "0",
        "--current-gitleaks-exit-code", str(current_exit_code),
    ])

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
    tmp_path, capsys, scenario, expected_decision
):
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

    reports = {}

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
            path.write_text(json.dumps(content), encoding="utf-8")
            reports[revision][scanner] = str(path)

    manifest = create_provenance_manifest(
        baseline_sha, head_sha, reports
    )

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest), encoding="utf-8"
    )

    exit_code = main([
        "--manifest", str(manifest_path),
        "--baseline-sha", baseline_sha,
        "--head-sha", head_sha,
        "--repo-path", str(repo),
        "--baseline-gitleaks-exit-code", "0",
        "--current-gitleaks-exit-code", "0",
    ])

    output = capsys.readouterr().out

    assert exit_code == (0 if expected_decision == "PASS" else 1)
    assert f"PipelineGuard PR Decision: {expected_decision}" in output
    