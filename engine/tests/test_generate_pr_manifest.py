
import hashlib
import json

import pytest

from engine.generate_pr_manifest import main


BASELINE_SHA = "a" * 40
HEAD_SHA = "b" * 40


def create_reports(tmp_path):
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()

    for revision in ("baseline", "current"):
        for scanner in ("trivy", "semgrep", "gitleaks"):
            path = reports_dir / f"{revision}-{scanner}.json"
            path.write_text("[]", encoding="utf-8")

    (reports_dir / "pr-gitleaks.json").write_text(
        "[]", encoding="utf-8"
    )

    return reports_dir


def run_generator(reports_dir, output):
    main([
        "--baseline-sha", BASELINE_SHA,
        "--head-sha", HEAD_SHA,
        "--reports-dir", str(reports_dir),
        "--output", str(output),
    ])


def test_generates_seven_report_manifest(tmp_path):
    reports_dir = create_reports(tmp_path)
    output = tmp_path / "manifest.json"

    run_generator(reports_dir, output)

    manifest = json.loads(output.read_text(encoding="utf-8"))

    assert manifest["baseline_sha"] == BASELINE_SHA
    assert manifest["head_sha"] == HEAD_SHA

    for revision in ("baseline", "current"):
        for scanner in ("trivy", "semgrep", "gitleaks"):
            entry = manifest["reports"][revision][scanner]
            report = reports_dir / f"{revision}-{scanner}.json"

            assert entry["path"] == str(report)
            assert entry["sha256"] == hashlib.sha256(
                report.read_bytes()
            ).hexdigest()

    pr_entry = manifest["pr_commit_scan"]["gitleaks"]
    pr_report = reports_dir / "pr-gitleaks.json"

    assert pr_entry["path"] == str(pr_report)
    assert pr_entry["sha256"] == hashlib.sha256(
        pr_report.read_bytes()
    ).hexdigest()


def test_missing_report_fails_closed(tmp_path):
    reports_dir = create_reports(tmp_path)
    (reports_dir / "current-trivy.json").unlink()

    output = tmp_path / "manifest.json"

    with pytest.raises(ValueError, match="Report not found"):
        run_generator(reports_dir, output)

    assert not output.exists()


def test_invalid_commit_sha_rejected(tmp_path):
    reports_dir = create_reports(tmp_path)
    output = tmp_path / "manifest.json"

    with pytest.raises(ValueError, match="Invalid baseline SHA"):
        main([
            "--baseline-sha", "invalid",
            "--head-sha", HEAD_SHA,
            "--reports-dir", str(reports_dir),
            "--output", str(output),
        ])

    assert not output.exists()


def test_report_modification_detected(tmp_path):
    from engine.provenance import verify_pr_provenance_manifest

    reports_dir = create_reports(tmp_path)
    output = tmp_path / "manifest.json"

    run_generator(reports_dir, output)
    manifest = json.loads(output.read_text(encoding="utf-8"))

    reports = {
        revision: {
            scanner: str(
                reports_dir / f"{revision}-{scanner}.json"
            )
            for scanner in ("trivy", "semgrep", "gitleaks")
        }
        for revision in ("baseline", "current")
    }

    pr_report = str(reports_dir / "pr-gitleaks.json")

    assert verify_pr_provenance_manifest(
        manifest, BASELINE_SHA, HEAD_SHA, reports, pr_report
    )

    (reports_dir / "pr-gitleaks.json").write_text(
        '[{"modified": true}]', encoding="utf-8"
    )

    assert not verify_pr_provenance_manifest(
        manifest, BASELINE_SHA, HEAD_SHA, reports, pr_report
    )
