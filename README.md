# PipelineGuard

**Differential DevSecOps Security Gate for GitHub Pull Requests**

> **Status:** V2.0.0 released — development of V2 is closed.

PipelineGuard is a Python security gate for GitHub pull requests. It combines secret detection (Gitleaks), static analysis (Semgrep) and dependency vulnerability scanning (Trivy on a CycloneDX SBOM), then takes a PASS/BLOCK decision with its own policy engine.

Its main idea is **differential analysis**: a pull request is judged on the findings it introduces, compared with the commit it started from, instead of being blocked by every problem that already exists in the repository.

PipelineGuard is an educational and portfolio project. It is not a production-hardened security boundary (see [Limitations](#limitations)).

## Why a differential gate

A repository with existing findings makes a classic "block on any finding" gate fail on every pull request, even one that only fixes a typo. Teams then disable the gate. PipelineGuard V2 compares two scans of the same pull request:

- **baseline**: the merge-base, where the pull request branch started;
- **current**: the head of the pull request.

The merge-base is used rather than the latest commit on `main`, so that work merged by other people after the branch was created is not attributed to this pull request.

| Present in baseline | Present in current | Classification |
|---|---|---|
| No | Yes | **NEW** |
| Yes | Yes | **EXISTING** |
| Yes | No | **FIXED** |

Semgrep findings whose lines only moved (for example because lines were added above them) are matched through the `git diff` hunks and stay **EXISTING**.

## Decision policy

| Classification | Blocks the pull request |
|---|---|
| NEW | Secrets, HIGH and CRITICAL findings |
| EXISTING | Secrets and CRITICAL findings |
| FIXED | Never |

In addition, **any secret found in the commits of the pull request blocks it**, even if a later commit removed it: once pushed, a secret must be considered exposed and revoked.

Semgrep `ERROR` maps to HIGH, `WARNING` to MEDIUM and `INFO` to INFO.

Every invalid, missing or inconsistent input **blocks** (fail closed): missing scanner, scanner failure, malformed report, non-canonical file path, Gitleaks exit code that contradicts its report, report changed between CI jobs.

## Architecture

```text
                       Pull request to main
                               |
              security-v2.yml  |  (pull_request)
                               v
  +------------------------ V2 Scan job ------------------------+
  |  candidate checkout (PR head)    trusted checkout (base)    |
  |  baseline worktree (merge-base)  current worktree (head)    |
  |                                                             |
  |  Semgrep  files of baseline and current  (pinned image,     |
  |           rules from trusted, no network)                   |
  |  Gitleaks files of baseline and current  (gitleaks dir)     |
  |           commits baseline..head         (gitleaks git)     |
  |  Trivy    CycloneDX SBOMs from the lockfiles (pinned image) |
  |                                                             |
  |  validate reports -> seal them in a SHA-256 manifest        |
  +-----------------------------+-------------------------------+
                                | artifact
                                v
  +---------------------- V2 Decision job ----------------------+
  |  engine and policy from trusted (base commit)               |
  |  verify revisions, report structure and manifest            |
  |  differential analysis -> policy -> PASS / BLOCK            |
  +-------------------------------------------------------------+

                         Push to main
                               |
                ci.yml         v
        ci job: tests, rule tests, Docker build (also on PRs)
        security-posture job (push only): image scan with Trivy,
        Gitleaks on pushed commits, Semgrep, V1 decision
```

The two workflows have separate roles:

- `security-v2.yml` is the **pull request gate**.
- `ci.yml` runs tests and the Docker build on pull requests and pushes. Its `security-posture` job runs **only on pushes to `main`**: it reports the health of code that is already accepted (including OS packages of the container image) and never judges pull requests.

## Security controls

| Control | What it does |
|---|---|
| Trusted engine and rules | The policy engine, Semgrep rules and Gitleaks configuration come from the base commit (`trusted/`). A pull request that edits them does not change its own evaluation. The V2 gate never executes the scanned code (the separate `ci` job does run the project's tests, with read-only permissions). |
| Fail closed | Any invalid or missing evidence produces BLOCK. |
| Canonical paths | Findings must use repository-relative paths (`demo-app/app.py`). Absolute or ambiguous paths are rejected instead of being misclassified. |
| Pinned actions | Every GitHub Action is pinned by commit SHA. |
| Pinned tools | Gitleaks is verified against its official SHA-256 before extraction. Trivy and Semgrep images are pinned by digest. Semgrep runs with `--network none`. |
| Report manifest | Reports are sealed in a SHA-256 manifest in the scan job and verified in the decision job: a report changed between the two jobs blocks the pull request. |
| Locked dependencies | The demo application is installed with `--require-hashes` from `requirements.lock`; the SBOM is checked against that lockfile. |
| Least privilege | Workflows use `contents: read`. The demo container runs as an unprivileged user (uid 10001). |

## Semgrep rules

Project rules live in `semgrep-rules/python-security.yml`. All of them use severity `ERROR` (HIGH).

| Rule | Detects | CWE |
|---|---|---|
| `pipelineguard-dangerous-eval` | `eval(...)` | CWE-95 |
| `pipelineguard-dangerous-exec` | `exec(...)` | CWE-95 |
| `pipelineguard-command-injection` | `subprocess.*(..., shell=True)` and `os.system(...)` with a non-constant command | CWE-78 |
| `pipelineguard-insecure-deserialization` | `pickle.load(...)`, `pickle.loads(...)` | CWE-502 |

Each rule has positive (`ruleid:`) and negative (`ok:`) cases in `semgrep-rules/python-security.py`, checked in CI with `semgrep --test`.

These are **pattern-based rules, not a data-flow analysis**: they do not know where a value comes from. The `eval`, `exec` and `pickle` rules report every call, including safe ones (false positives). A constant shell command is not reported, which reduces injection risk but does not make the command safe.

## Validation

The V2 behaviour was validated on real GitHub Actions runs, in addition to the test suite.

| Scenario | PR | Expected | Result |
|---|---|---|---|
| Differential fixes merged | #20 | PASS, V1 skipped on PR, `security-posture` runs on push | ✅ |
| New `eval` endpoint (code injection) | #21 | BLOCK — `New HIGH finding` | ✅ |
| Fake secret added then removed inside the PR | #22 | BLOCK — `Secret detected in PR commits` | ✅ |
| Existing `eval` moved down by three lines | #23 | PASS (finding stays EXISTING) | ✅ |
| Tool integrity (checksum, digests, offline Semgrep) | #24 | PASS | ✅ |
| New `eval` with the pinned offline Semgrep image | #25 | BLOCK — `New HIGH finding` | ✅ |
| Manifest sealed between jobs, non-root container | #26 | PASS | ✅ |

Test pull requests #21, #22, #23 and #25 were closed without merging. #23 targeted a temporary branch containing a harmless `eval("1 + 1")` fixture, so that no HIGH finding was ever introduced into `main`; its only workflow change was the trigger filter.

Locally verified as well: a modified Gitleaks archive is rejected by `sha256sum --check`; missing, invalid or modified reports and manifests all produce BLOCK; each Semgrep rule test fails when its rule is deliberately broken.

## Running the tests

```bash
# Engine tests (214 at the time of finalization)
python -m pytest engine/tests -q

# Demo application tests
cd demo-app && python -m pytest -q

# Semgrep rule tests (same pinned image as CI)
docker run --rm --network none -v "$PWD:/work" -w /work \
  semgrep/semgrep:1.180.0@sha256:529ee8a277ec8adc5b534d7c74eea0a47e9de21d62852b6ba7ac6ba9566845c3 \
  semgrep --test --metrics=off --disable-version-check semgrep-rules/
```

Note: Semgrep run natively on Windows writes paths with `\`. The engine rejects them on purpose (non-canonical paths); use the Docker image above or a Linux environment.

## Repository structure

```text
.github/workflows/
  security-v2.yml         Pull request gate (scan job + decision job)
  ci.yml                  Tests, rule tests, Docker build; posture scan on main

demo-app/
  app.py                  Demo FastAPI application
  Dockerfile              Multi-stage, hash-locked, non-root image
  requirements.lock       Locked Python dependencies with hashes

engine/
  differential.py         NEW / EXISTING / FIXED classification
  line_mapping.py         Line translation through git diff hunks
  git_comparison.py       Verified git diff between two commits
  normalizer.py           Scanner reports -> common findings
  policy.py               PASS / BLOCK rules
  orchestrator.py         V1 and V2 evaluation flows
  pr_cli.py, cli.py       V2 and V1 command-line entry points
  provenance.py           SHA-256 report manifest (detects reports changed
                          between CI jobs; not an independent proof of origin)
  generate_pr_manifest.py Manifest generation (scan job)
  lockfile_sbom.py        CycloneDX SBOM from the lockfile
  sbom_validation.py      SBOM and Trivy report validation
  tests/                  Engine and workflow guard tests

semgrep-rules/
  python-security.yml     Project Semgrep rules
  python-security.py      Rule test cases (semgrep --test)
```

## Limitations

- **Workflow trust boundary.** With `pull_request`, GitHub runs the workflow file from the pull request. A pull request can modify `security-v2.yml` itself. Branch protection is not configured yet: a red `V2 Security Decision` check informs but does not prevent merging. Planned when the repository is made public: make `V2 Security Decision` a required status check on `main`. Even then, protecting `.github/` with `CODEOWNERS` and mandatory review by a second maintainer would be needed for real enforcement.
- **Report manifest.** It detects reports changed between the scan and decision jobs. It does not prove that a report was correct when written, since both jobs belong to the same workflow. Engine messages still use the word "provenance" for this check.
- **SBOM scope.** The SBOM is derived from the lockfile. It is not an independent inventory of the final container.
- **Container OS packages** are scanned only after merge, by the `security-posture` job on `main`, which runs only when commits are pushed. They are not part of the pull request differential.
- **No exceptions mechanism.** An existing CRITICAL finding, such as a newly published CVE in a locked dependency, blocks every pull request until it is fixed.
- **Gitleaks history.** The pull request gate scans the files of both revisions and the commits of the pull request. History before the merge-base is not rescanned.
- **Detection coverage.** Four pattern-based Semgrep rules, Python only. Scanner databases and configuration limit what can be found. A PASS means the configured controls accepted the change, not that the code is free of vulnerabilities.

## Technology stack

Python · GitHub Actions · Docker · FastAPI · Semgrep · Gitleaks · Trivy · CycloneDX · Pytest

## Project status

**V2.0.0 released.** Development of V2 is closed; no further features are planned for this version.
