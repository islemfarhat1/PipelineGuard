
# Security Controls and Limitations

[Back to README](../README.md)

## Overview

PipelineGuard applies security controls not only to the application being scanned, but also to the security pipeline itself.

The objective is to reduce the risk of scanner manipulation, report tampering, supply chain compromise and unreliable security decisions.

PipelineGuard remains an educational and portfolio project, not a production-hardened security boundary.

## 1. Threat Model

| Threat | Security control |
|---|---|
| Manipulation of the policy engine | Engine loaded from the base commit |
| Manipulation of scanner rules | Approved scanner configuration |
| Missing or malformed scanner reports | Fail-closed policy |
| Report modification between CI jobs | SHA-256 report manifest |
| Compromised tool distribution | Pinned versions, digests and checksum verification |
| Secret removed after being committed | PR commit history scanning |
| Excessive runtime privileges | Read-only workflow permissions and non-root container |
| LLM prompt injection | Input preprocessing and assistant isolation |

These controls reduce specific risks but do not eliminate all possible attack paths.

## 2. Trusted Execution

The security gate separates candidate code from approved security components.

- Candidate source code is obtained from the pull request head.
- The engine, policy, Semgrep rules and Gitleaks configuration are obtained from the base commit.
- The baseline used for differential analysis is the merge-base.
- The V2 security gate does not execute the scanned application code.

The separate CI job executes application tests with read-only workflow permissions.

### Workflow Trust Boundary

GitHub Actions runs the workflow file from the pull request when using the `pull_request` event.

Consequently, a contributor could attempt to modify the workflow responsible for enforcing the security gate.

The `main` branch is protected by a ruleset requiring:

- Changes through pull requests.
- A successful V2 Security Decision check.
- Branches to be up to date before merging.
- Protection against force pushes and branch deletion.

For stronger production enforcement, workflow files should also be protected through CODEOWNERS and mandatory review by a second maintainer.

This additional review mechanism is not currently implemented.

## 3. Supply Chain Security

PipelineGuard applies the following controls to its security tooling and demo application.

| Control | Implementation |
|---|---|
| GitHub Actions | Pinned by commit SHA |
| Semgrep | Container image pinned by digest |
| Trivy | Container image pinned by digest |
| Gitleaks | Official SHA-256 checksum verified before extraction |
| Semgrep network access | Disabled using `--network none` |
| Python dependencies | Locked versions and hashes |
| Dependency installation | pip with `--require-hashes` |
| Container runtime | Non-root user, UID 10001 |

Pinning improves reproducibility and reduces exposure to unexpected upstream changes. It does not guarantee that the pinned components are vulnerability-free.

## 4. Report Integrity

Scanner reports are sealed using a SHA-256 manifest in the scan job.

The decision job verifies the manifest before evaluating the findings.

A missing, invalid or modified required report results in BLOCK.

The manifest detects modifications between CI jobs. It is not independent proof of report authenticity or scanner correctness.

Both jobs remain within the same workflow trust boundary.

## 5. Fail-Closed Security Policy

PipelineGuard does not interpret missing evidence as a successful security scan.

The following conditions result in BLOCK:

- Missing scanner reports.
- Scanner execution failures.
- Malformed or inconsistent reports.
- Invalid Git revision information.
- Non-canonical file paths.
- Gitleaks exit codes inconsistent with report contents.
- Invalid SBOM inventories or Trivy coverage.
- Report manifest verification failures.

See [Differential Security Engine](engine.md) for the complete decision policy.

## 6. Secret Detection

Gitleaks scans:

- Files in the baseline revision.
- Files in the current revision.
- Commits introduced by the pull request.

A secret detected in PR commits remains blocking even if it is removed in a subsequent commit.

Removing a secret from source code does not revoke the exposed credential.

Git history before the merge-base is not rescanned by the V2 pull request gate.

## 7. Static Analysis Rules

Custom Semgrep rules are defined in `semgrep-rules/python-security.yml`.

All four rules use severity ERROR, which the engine maps to HIGH.

| Rule | Detection | CWE |
|---|---|---|
| `pipelineguard-dangerous-eval` | eval() calls | CWE-95 |
| `pipelineguard-dangerous-exec` | exec() calls | CWE-95 |
| `pipelineguard-command-injection` | subprocess calls with shell=True and non-constant os.system commands | CWE-78 |
| `pipelineguard-insecure-deserialization` | pickle.load() and pickle.loads() | CWE-502 |

Positive and negative rule test cases are maintained in `semgrep-rules/python-security.py` and executed in CI.

### Detection Limitations

These rules are pattern-based rather than data-flow-based.

They do not determine whether a value originates from an untrusted source.

Consequently:

- Safe uses of eval(), exec() or pickle may still be reported.
- A constant shell command is not necessarily safe.
- Vulnerabilities outside the configured patterns may remain undetected.

Source: [Semgrep rules](../semgrep-rules/)

## 8. Dependency and Container Security

The V2 security gate generates CycloneDX SBOMs from the dependency lockfiles.

Trivy scans these inventories for known dependency vulnerabilities.

The SBOM inventory and Trivy package coverage are validated before the security decision.

The lockfile-derived SBOM is not an independent inventory of the final container image.

Container OS packages are scanned separately by the security-posture job on pushes to main. They are not included in the V2 pull request differential analysis.

## 9. LLM Security Boundary

The local LLM assistant is advisory only.

Its security controls include:

- Isolation from the deterministic decision engine.
- Loopback-only Ollama requests.
- System proxy bypass.
- Repository path containment.
- Secret masking and redaction.
- Removal of comments and docstrings from Python code context.
- Strict JSON output validation.

These controls reduce exposure to prompt injection and accidental secret disclosure.

However, instructions embedded in string literals can still influence model responses.

The LLM cannot override the security policy or change a PASS/BLOCK decision.

See [LLM Assistant](llm-assistant.md) for the detailed safeguards and experimental evaluation.

## 10. Known Limitations

| Limitation | Impact |
|---|---|
| Workflow trust boundary | A PR can modify its own workflow definition |
| Report manifest scope | Integrity verification is not independent provenance |
| Lockfile-derived SBOM | Does not represent the complete final container |
| Post-merge OS scanning | Container OS vulnerabilities are outside the V2 differential gate |
| No exception mechanism | Existing CRITICAL findings can block all PRs |
| Limited history scanning | Commits before the merge-base are not rescanned |
| Pattern-based SAST | False positives and false negatives remain possible |
| Scanner coverage | Detection depends on rules, configuration and vulnerability databases |
| LLM reliability | Explanations and false-positive assessments may be incorrect |
| Prompt injection | String literals remain a residual injection channel |

## Security Guarantee

A PASS decision means that the configured security controls accepted the pull request.

It does not guarantee that the application is free of vulnerabilities.

PipelineGuard demonstrates security engineering principles within a controlled educational environment.

## Related Documentation

- [Architecture](architecture.md)
- [Differential Security Engine](engine.md)
- [Local LLM Assistant](llm-assistant.md)
- [Validation](validation.md)
- [Architecture Decisions](../DECISIONS.md)
