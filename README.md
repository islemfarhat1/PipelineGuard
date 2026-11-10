# PipelineGuard

**Differential DevSecOps Security Gate for GitHub Pull Requests**

PipelineGuard is a Python-based security gate that combines static application security testing, secret detection, dependency vulnerability scanning, and policy-driven decisions.

Its V2 workflow evaluates security findings introduced by a pull request relative to a Git baseline, rather than automatically blocking every finding already present in the repository.

## Key Features

- **Semgrep:** Static analysis using project security rules.
- **Gitleaks:** Detection of exposed secrets.
- **Trivy:** Vulnerability scanning of software dependencies.
- **CycloneDX SBOM:** Software inventory generated from the Python lockfile.
- **Differential analysis:** Comparison of baseline and candidate findings.
- **Policy engine:** Automated PASS/BLOCK security decisions.
- **Report validation:** Integrity and structure checks designed to fail closed when required evidence is invalid.
- **GitHub Actions:** Automated security evaluation of pull requests.

## Architecture

```text
                 GitHub Pull Request
                         |
                         v
                 GitHub Actions V2
                         |
             +-----------+-----------+
             |                       |
             v                       v
       Git Baseline              PR Candidate
             |                       |
             +-----------+-----------+
                         |
                         v
                Security Scanners
              /          |          \
         Semgrep      Gitleaks      Trivy
              \          |          /
               Security Scan Reports
                         |
                         v
                Report Validation
                         |
                         v
               Differential Analysis
                         |
                         v
                  Policy Engine
                         |
                         v
                    PASS / BLOCK
```

The V2 workflow also generates CycloneDX SBOMs from locked Python dependencies and validates the corresponding Trivy scan reports.

## Repository Structure

```text
.github/workflows/
  ci.yml                  Original CI workflow
  security-v2.yml         Differential security workflow

demo-app/
  app.py                  Demo FastAPI application
  Dockerfile              Application container
  requirements.lock       Locked Python dependencies
  tests/                  Application tests

engine/
  differential.py         Differential finding analysis
  git_comparison.py       Git comparison utilities
  normalizer.py           Security finding normalization
  policy.py               Policy evaluation
  orchestrator.py         Security evaluation orchestration
  provenance.py           SHA-256 report manifest (detects reports changed
                          between CI jobs; not an independent proof of origin)
  lockfile_sbom.py        CycloneDX SBOM generation
  sbom_validation.py      SBOM and Trivy report validation
  scan_validation.py      Scan report validation
  tests/                  Engine test suite

semgrep-rules/
  python-security.yml     Project Semgrep rules
```

## How It Works

1. A pull request triggers the V2 GitHub Actions workflow.
2. The workflow prepares baseline and candidate security evidence.
3. Security scanners generate findings for evaluation.
4. The pipeline validates required scan reports and their integrity.
5. The differential engine identifies findings introduced by the candidate changes.
6. The policy engine produces an automated security decision.

A **PASS** indicates that the configured security controls accepted the evaluated change. It does not prove that the application is free of vulnerabilities.

## Software Bill of Materials

PipelineGuard generates a CycloneDX 1.6 SBOM from the Python dependency lockfile.

The SBOM represents the locked dependency inventory. It is not an independently verified inventory of every package installed in the running container.

Trivy analyzes the SBOM for known vulnerabilities. The workflow validates the report structure and requires evidence of Python package scanning.

This validation does not independently prove that every locked component was successfully evaluated by Trivy.

## Running Tests

From the repository root:

```bash
python -m pytest engine/tests -q
```

Latest locally verified result:

```text
174 passed in 4.83s
```

## CI/CD

The repository includes two GitHub Actions workflows:

- `ci.yml`: Original continuous integration workflow.
- `security-v2.yml`: Differential pull-request security workflow.

The V2 workflow separates security scanning and security decision processing.

## Security Limitations

PipelineGuard V2 is an educational and portfolio-oriented DevSecOps prototype.

Important limitations include:

- Pull-request workflows may use workflow definitions supplied by the candidate branch. A malicious workflow modification can undermine security controls.
- Trusted engine execution alone does not make the complete workflow tamper-proof.
- Lockfile-derived SBOMs do not independently verify the contents of the final runtime container.
- Validating the presence of Python scan results does not establish complete per-component vulnerability coverage.
- Scanner databases, configuration, and available vulnerability intelligence affect detection.
- Scanner images should be pinned by immutable digest for stronger supply-chain assurance.
- Repository rules, protected branches, and review requirements are necessary for stronger enforcement.

PipelineGuard should not be considered a production-hardened security boundary without additional controls and independent security review.

## Validation

The V2 implementation was validated through:

- Python unit and integration tests.
- GitHub Actions security checks.
- Pull-request integration.
- Negative security test scenarios involving Semgrep and Gitleaks findings.

At the time of V2 integration, the engine test suite completed with **174 passing tests**.

## Technology Stack

Python · GitHub Actions · Docker · FastAPI · Semgrep · Gitleaks · Trivy · CycloneDX · Pytest

## Project Status

**V2 implemented and merged into the main branch.**

Future production hardening would require stronger workflow trust boundaries, repository enforcement controls, and more comprehensive verification of scanner coverage.
