"""
Guard that workflow steps deliver the guarantee their names claim.

The SHA-256 manifest used to be generated and verified in the same job,
so the check always passed. It must be sealed in the scan job and only
verified in the decision job.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "security-v2.yml"


def jobs():
    text = WORKFLOW.read_text(encoding="utf-8")
    scan, decision = text.split("\n  decision:\n", 1)
    return scan, decision


def test_manifest_is_sealed_in_scan_job_before_upload():
    scan, _ = jobs()

    seal = scan.index("engine.generate_pr_manifest")
    upload = scan.index("actions/upload-artifact")

    assert seal < upload


def test_decision_job_verifies_but_never_regenerates_the_manifest():
    _, decision = jobs()

    assert "engine.generate_pr_manifest" not in decision
    assert "engine.pr_cli" in decision
    assert "--manifest reports/pr-manifest.json" in decision


def test_full_sbom_comparison_runs_in_scan_job():
    scan, decision = jobs()

    assert "validate_sbom(lockfile, sbom)" in scan
    assert "Revalidate trusted SBOM" not in decision


def test_application_container_does_not_run_as_root():
    dockerfile = (ROOT / "demo-app" / "Dockerfile").read_text(encoding="utf-8")
    runtime = dockerfile.split("AS runtime", 1)[1]

    assert "\nUSER 10001" in runtime
    assert runtime.index("USER 10001") < runtime.index("CMD")
