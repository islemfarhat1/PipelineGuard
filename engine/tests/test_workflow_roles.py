"""
Guard the separation of roles between the two GitHub Actions workflows.

security-v2.yml decides whether a pull request may enter, using the
approved engine from the base commit. ci.yml also runs the engine from
its own checkout, which is only trustworthy for code already on main.
"""

import re
from pathlib import Path


WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"


def read(name):
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def ci_jobs():
    before, after = read("ci.yml").split("  security-posture:\n", 1)
    return before, after


def test_pull_request_job_keeps_tests_and_build():
    ci_job, _ = ci_jobs()

    assert "python -m pytest engine/tests/" in ci_job
    assert "docker build" in ci_job


def test_pull_request_job_does_not_run_the_v1_gate_or_scanners():
    ci_job, _ = ci_jobs()

    for forbidden in ("engine.cli", "trivy", "gitleaks", "semgrep"):
        assert forbidden not in ci_job.lower()


def test_posture_job_runs_only_on_push():
    _, posture = ci_jobs()

    assert "if: github.event_name == 'push'" in posture
    assert "pull_request" not in posture
    assert "python -m engine.cli" in posture


def test_both_workflows_use_the_same_gitleaks_version():
    ci_version = re.search(r'GITLEAKS_VERSION: "([0-9.]+)"', read("ci.yml"))
    v2_version = re.search(r"version=([0-9.]+)", read("security-v2.yml"))

    assert ci_version and v2_version
    assert ci_version.group(1) == v2_version.group(1)
