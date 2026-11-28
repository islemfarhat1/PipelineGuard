
# Architecture Decision Log

[Back to README](README.md)

This document records the key architectural and security decisions behind PipelineGuard, their rationale and associated trade-offs.

| ID | Decision | Rationale | Trade-off |
|---|---|---|---|
| ADR-001 | Differential security analysis | Prevent new security debt without blocking every PR because of existing findings. | Requires scanning and comparing two revisions. |
| ADR-002 | Use the Git merge-base as the baseline | Avoid attributing unrelated target branch changes to the pull request. | Requires reliable Git revision resolution. |
| ADR-003 | Combine Semgrep, Gitleaks and Trivy | Cover source code, secrets and dependency vulnerabilities through complementary scanners. | Increases pipeline complexity and execution time. |
| ADR-004 | Deterministic PASS/BLOCK policy | Ensure reproducible, explainable and testable security decisions. | Less flexible than contextual human assessment. |
| ADR-005 | Fail-closed enforcement | Prevent missing or invalid security evidence from producing a successful decision. | Infrastructure and scanner failures can block legitimate changes. |
| ADR-006 | Load the engine and rules from the base commit | Reduce the risk of candidate code manipulating its own security evaluation. | Does not eliminate the workflow trust boundary. |
| ADR-007 | Scan PR commit history for secrets | Detect credentials that were committed and subsequently removed. | Additional scanning and potential false positives. |
| ADR-008 | Separate scan and decision jobs | Separate evidence collection from policy enforcement. | Requires artifact transfer and integrity verification. |
| ADR-009 | Seal reports with a SHA-256 manifest | Detect report modifications between CI jobs. | Does not independently prove report authenticity. |
| ADR-010 | Pin security tools and dependencies | Improve reproducibility and reduce supply chain risks. | Requires deliberate dependency and tool updates. |
| ADR-011 | Generate CycloneDX SBOMs from lockfiles | Evaluate dependencies without executing candidate application code. | Does not cover the complete final container inventory. |
| ADR-012 | Use a local LLM through Ollama | Reduce external exposure of security findings and source code. | Requires local computational resources and model setup. |
| ADR-013 | Keep the LLM outside security enforcement | Prevent hallucinations and prompt injection from influencing PASS/BLOCK decisions. | AI-generated assessments cannot automatically override scanner findings. |
| ADR-014 | Apply deterministic prompt preprocessing | Reduce injection opportunities through comments and docstrings. | String literals remain a residual injection channel. |
| ADR-015 | Validate LLM responses against a JSON schema | Ensure predictable and structured explanations. | Structural validity does not guarantee factual correctness. |
| ADR-016 | Select Qwen2.5:7B as the default model | Better security assessment results than the 1.5B model on the evaluated cases. | Higher inference latency and resource consumption. |

## Future Considerations

The following improvements have been identified but are not implemented:

- Publish PipelineGuard as a reusable GitHub Action.
- Package the security engine as a standalone CLI.
- Publish a structured security summary directly on the pull request.
- Automate scanner artifact retrieval for the local assistant.
- Explore LLM-assisted detection of issues missed by conventional scanners.
- Strengthen workflow protection through mandatory independent review.

Any future AI-assisted detection should preserve the separation between model-generated assessments and deterministic security enforcement.

## Supporting Documentation

- [Architecture](docs/architecture.md)
- [Differential Security Engine](docs/engine.md)
- [Security Controls and Limitations](docs/security.md)
- [Local LLM Assistant](docs/llm-assistant.md)
- [Validation and Experimental Results](docs/validation.md)
