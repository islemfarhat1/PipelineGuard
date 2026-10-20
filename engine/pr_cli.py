import argparse
import json
from pathlib import Path

from engine.orchestrator import run_pipelineguard_pr_verified
from engine.policy import Decision


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="PipelineGuard PR-aware Security Gate V2"
    )

    parser.add_argument("--manifest", required=True)
    parser.add_argument("--baseline-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--repo-path", default=".")

    parser.add_argument(
        "--baseline-gitleaks-exit-code",
        type=int,
        required=True,
    )
    parser.add_argument(
        "--current-gitleaks-exit-code",
        type=int,
        required=True,
    )

    args = parser.parse_args(argv)

    try:
        manifest = json.loads(
            Path(args.manifest).read_text(encoding="utf-8")
        )

        if not isinstance(manifest, dict):
            raise ValueError("Manifest must be a JSON object")

        reports = {
            revision: {
                scanner: manifest["reports"][revision][scanner]["path"]
                for scanner in ("trivy", "semgrep", "gitleaks")
            }
            for revision in ("baseline", "current")
        }

        result = run_pipelineguard_pr_verified(
            manifest=manifest,
            baseline_sha=args.baseline_sha,
            head_sha=args.head_sha,
            reports=reports,
            baseline_gitleaks_exit_code=args.baseline_gitleaks_exit_code,
            current_gitleaks_exit_code=args.current_gitleaks_exit_code,
            repo_path=args.repo_path,
        )

    except (OSError, ValueError, KeyError, TypeError) as error:
        print("PipelineGuard PR Decision: BLOCK")
        print(f"- Invalid PR manifest or reports: {error}")
        return 1

    print(f"PipelineGuard PR Decision: {result.decision.value}")

    for reason in result.reasons:
        print(f"- {reason}")

    return 0 if result.decision == Decision.PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())