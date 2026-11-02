import hashlib

import pytest

from engine.provenance import calculate_report_sha256
from engine.provenance import (
    create_provenance_manifest,
    verify_provenance_manifest,
)
from engine.provenance import (
    create_pr_provenance_manifest,
    verify_pr_provenance_manifest,
)

def test_report_hash_is_correct(tmp_path):
    report = tmp_path / "semgrep.json"
    content = b'{"results": []}'
    report.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()

    assert calculate_report_sha256(str(report)) == expected


def test_modified_report_changes_hash(tmp_path):
    report = tmp_path / "trivy.json"
    report.write_bytes(b'{"Results": []}')

    original_hash = calculate_report_sha256(str(report))

    report.write_bytes(b'{"Results": [{"Target": "app"}]}')

    modified_hash = calculate_report_sha256(str(report))

    assert original_hash != modified_hash


def test_missing_report_is_rejected(tmp_path):
    missing = tmp_path / "missing.json"

    with pytest.raises(ValueError, match="Report not found"):
        calculate_report_sha256(str(missing))


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


def test_create_manifest(tmp_path):
    reports = make_reports(tmp_path)

    manifest = create_provenance_manifest(
        BASELINE,
        HEAD,
        reports,
    )

    assert manifest["baseline_sha"] == BASELINE
    assert manifest["head_sha"] == HEAD
    assert len(manifest["reports"]["baseline"]) == 3
    assert len(manifest["reports"]["current"]) == 3


def test_valid_manifest_passes(tmp_path):
    reports = make_reports(tmp_path)

    manifest = create_provenance_manifest(
        BASELINE,
        HEAD,
        reports,
    )

    assert verify_provenance_manifest(
        manifest, BASELINE, HEAD, reports
    )


def test_modified_report_fails(tmp_path):
    reports = make_reports(tmp_path)

    manifest = create_provenance_manifest(
        BASELINE,
        HEAD,
        reports,
    )

    path = reports["current"]["semgrep"]

    with open(path, "w", encoding="utf-8") as file:
        file.write('{"modified": true}')

    assert not verify_provenance_manifest(
        manifest, BASELINE, HEAD, reports
    )


def test_wrong_head_sha_fails(tmp_path):
    reports = make_reports(tmp_path)

    manifest = create_provenance_manifest(
        BASELINE,
        HEAD,
        reports,
    )

    assert not verify_provenance_manifest(
        manifest, BASELINE, "c" * 40, reports
    )


def test_missing_scanner_rejected(tmp_path):
    reports = make_reports(tmp_path)
    del reports["baseline"]["trivy"]

    with pytest.raises(ValueError, match="scanner reports"):
        create_provenance_manifest(BASELINE, HEAD, reports)


def test_invalid_sha_rejected(tmp_path):
    reports = make_reports(tmp_path)

    with pytest.raises(ValueError, match="Invalid baseline SHA"):
        create_provenance_manifest(
            "invalid",
            HEAD,
            reports,
        )



def make_pr_manifest_data(tmp_path):
    reports = make_reports(tmp_path)

    pr_report = tmp_path / "gitleaks-pr-report.json"
    pr_report.write_text("[]", encoding="utf-8")

    manifest = create_pr_provenance_manifest(
        BASELINE,
        HEAD,
        reports,
        str(pr_report),
    )

    return reports, pr_report, manifest


def test_seven_report_manifest_created(tmp_path):
    reports, pr_report, manifest = make_pr_manifest_data(
        tmp_path
    )

    assert len(manifest["reports"]["baseline"]) == 3
    assert len(manifest["reports"]["current"]) == 3

    assert manifest["pr_commit_scan"]["gitleaks"]["path"] == str(
        pr_report
    )

    assert len(
        manifest["pr_commit_scan"]["gitleaks"]["sha256"]
    ) == 64


def test_seven_report_manifest_verified(tmp_path):
    reports, pr_report, manifest = make_pr_manifest_data(
        tmp_path
    )

    assert verify_pr_provenance_manifest(
        manifest,
        BASELINE,
        HEAD,
        reports,
        str(pr_report),
    )


def test_modified_pr_gitleaks_report_rejected(tmp_path):
    reports, pr_report, manifest = make_pr_manifest_data(
        tmp_path
    )

    pr_report.write_text(
        '[{"RuleID": "test-secret"}]',
        encoding="utf-8",
    )

    assert not verify_pr_provenance_manifest(
        manifest,
        BASELINE,
        HEAD,
        reports,
        str(pr_report),
    )


def test_missing_pr_gitleaks_report_rejected(tmp_path):
    reports, pr_report, manifest = make_pr_manifest_data(
        tmp_path
    )

    pr_report.unlink()

    assert not verify_pr_provenance_manifest(
        manifest,
        BASELINE,
        HEAD,
        reports,
        str(pr_report),
    )


def test_six_report_manifest_rejected_by_v2(tmp_path):
    reports = make_reports(tmp_path)

    pr_report = tmp_path / "gitleaks-pr-report.json"
    pr_report.write_text("[]", encoding="utf-8")

    old_manifest = create_provenance_manifest(
        BASELINE,
        HEAD,
        reports,
    )

    assert not verify_pr_provenance_manifest(
        old_manifest,
        BASELINE,
        HEAD,
        reports,
        str(pr_report),
    )
