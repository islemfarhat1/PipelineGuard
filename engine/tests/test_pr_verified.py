import pytest

from engine.models import Scanner, ScanResult, ScanStatus
from engine.orchestrator import run_pipelineguard_pr_verified
from engine.policy import Decision, PolicyResult
from engine.provenance import create_provenance_manifest


BASELINE = "a" * 40
HEAD = "b" * 40


def make_reports(tmp_path):
    reports = {}

    for revision in ("baseline", "current"):
        reports[revision] = {}

        for scanner in ("trivy", "semgrep", "gitleaks"):
            path = tmp_path / f"{revision}-{scanner}.json"
            path.write_text("{}", encoding="utf-8")
            reports[revision][scanner] = str(path)

    return reports


def evaluate(tmp_path, monkeypatch, change=None):
    reports = make_reports(tmp_path)

    manifest = create_provenance_manifest(
        BASELINE, HEAD, reports
    )

    if change:
        change(manifest, reports)

    monkeypatch.setattr(
        "engine.orchestrator.run_pipelineguard_pr_from_reports",
        lambda **kwargs: PolicyResult(
            decision=Decision.PASS,
            reasons=[],
        ),
    )

    return run_pipelineguard_pr_verified(
        manifest=manifest,
        baseline_sha=BASELINE,
        head_sha=HEAD,
        reports=reports,
        baseline_gitleaks_exit_code=0,
        current_gitleaks_exit_code=0,
    )


def test_valid_manifest_passes(tmp_path, monkeypatch):
    result = evaluate(tmp_path, monkeypatch)
    assert result.decision == Decision.PASS


def test_modified_report_blocks(tmp_path, monkeypatch):
    def modify(manifest, reports):
        with open(
            reports["current"]["semgrep"],
            "w",
            encoding="utf-8",
        ) as file:
            file.write('{"modified": true}')

    result = evaluate(tmp_path, monkeypatch, modify)
    assert result.decision == Decision.BLOCK


def test_wrong_manifest_sha_blocks(tmp_path, monkeypatch):
    def modify(manifest, reports):
        manifest["head_sha"] = "c" * 40

    result = evaluate(tmp_path, monkeypatch, modify)
    assert result.decision == Decision.BLOCK


def test_missing_manifest_report_blocks(tmp_path, monkeypatch):
    def modify(manifest, reports):
        del manifest["reports"]["baseline"]["trivy"]

    result = evaluate(tmp_path, monkeypatch, modify)
    assert result.decision == Decision.BLOCK


def test_wrong_manifest_hash_blocks(tmp_path, monkeypatch):
    def modify(manifest, reports):
        manifest["reports"]["current"]["gitleaks"]["sha256"] = "0" * 64

    result = evaluate(tmp_path, monkeypatch, modify)
    assert result.decision == Decision.BLOCK