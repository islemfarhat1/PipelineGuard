import json

import pytest

from engine.pr_cli import main
from engine.policy import Decision, PolicyResult


BASELINE = "a" * 40
HEAD = "b" * 40


def make_manifest(tmp_path):
    reports = {}

    for revision in ("baseline", "current"):
        reports[revision] = {}

        for scanner in ("trivy", "semgrep", "gitleaks"):
            reports[revision][scanner] = {
                "path": str(
                    tmp_path / f"{revision}-{scanner}.json"
                ),
                "sha256": "0" * 64,
            }

    manifest = {
        "baseline_sha": BASELINE,
        "head_sha": HEAD,
        "reports": reports,
    }

    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    return path


def run_cli(manifest_path):
    return main([
        "--manifest", str(manifest_path),
        "--baseline-sha", BASELINE,
        "--head-sha", HEAD,
        "--baseline-gitleaks-exit-code", "0",
        "--current-gitleaks-exit-code", "0",
    ])


@pytest.mark.parametrize(
    "decision,expected_code",
    [
        (Decision.PASS, 0),
        (Decision.BLOCK, 1),
    ],
)
def test_cli_decision(
    tmp_path,
    monkeypatch,
    capsys,
    decision,
    expected_code,
):
    manifest = make_manifest(tmp_path)

    monkeypatch.setattr(
        "engine.pr_cli.run_pipelineguard_pr_verified",
        lambda **kwargs: PolicyResult(
            decision=decision,
            reasons=["Test policy result"],
        ),
    )

    exit_code = run_cli(manifest)
    output = capsys.readouterr().out

    assert exit_code == expected_code
    assert f"PipelineGuard PR Decision: {decision.value}" in output
    assert "Test policy result" in output


def test_missing_manifest_blocks(tmp_path, capsys):
    exit_code = run_cli(tmp_path / "missing.json")

    assert exit_code == 1
    assert "BLOCK" in capsys.readouterr().out


def test_invalid_json_blocks(tmp_path, capsys):
    path = tmp_path / "manifest.json"
    path.write_text("{invalid json", encoding="utf-8")

    exit_code = run_cli(path)

    assert exit_code == 1
    assert "BLOCK" in capsys.readouterr().out


def test_incomplete_manifest_blocks(tmp_path, capsys):
    path = tmp_path / "manifest.json"
    path.write_text('{"reports": {}}', encoding="utf-8")

    exit_code = run_cli(path)

    assert exit_code == 1
    assert "BLOCK" in capsys.readouterr().out