
import argparse
import json
from pathlib import Path

from engine.orchestrator import run_pipelineguard_pr_with_commit_scan
from engine.policy import Decision


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="PipelineGuard PR-aware Security Gate V2"
    )

    # Provenance and Git revisions
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--baseline-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--repo-path", default=".")

    # Gitleaks exit codes for baseline and current
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

    # Gitleaks exit code for PR commit history
    parser.add_argument(
        "--pr-gitleaks-exit-code",
        type=int,
        required=True,
    )

    args = parser.parse_args(argv)

    try:
        # 1. Load provenance manifest
        manifest = json.loads(
            Path(args.manifest).read_text(encoding="utf-8")
        )

        if not isinstance(manifest, dict):
            raise ValueError(
                "Manifest must be a JSON object"
            )

        # 2. Extract baseline/current reports
        reports = {
            revision: {
                scanner: manifest["reports"][revision][scanner]["path"]
                for scanner in ("trivy", "semgrep", "gitleaks")
            }
            for revision in ("baseline", "current")
        }

        # 3. Extract mandatory PR commit-history report
        pr_gitleaks_report = (
            manifest["pr_commit_scan"]["gitleaks"]["path"]
        )

        if (
            not isinstance(pr_gitleaks_report, str)
            or not pr_gitleaks_report.strip()
        ):
            raise ValueError(
                "Invalid PR Gitleaks report path"
            )

        # 4. Run verified differential and commit-history checks
        result = run_pipelineguard_pr_with_commit_scan(
            manifest=manifest,
            baseline_sha=args.baseline_sha,
            head_sha=args.head_sha,
            reports=reports,
            baseline_gitleaks_exit_code=(
                args.baseline_gitleaks_exit_code
            ),
            current_gitleaks_exit_code=(
                args.current_gitleaks_exit_code
            ),
            pr_gitleaks_report=pr_gitleaks_report,
            pr_gitleaks_exit_code=args.pr_gitleaks_exit_code,
            repo_path=args.repo_path,
        )

    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
    ) as error:
        print("PipelineGuard PR Decision: BLOCK")
        print(f"- Invalid PR manifest or reports: {error}")
        return 1

    # 5. Print final security decision
    print(
        f"PipelineGuard PR Decision: {result.decision.value}"
    )

    for reason in result.reasons:
        print(f"- {reason}")

    # 0 = PASS, 1 = BLOCK
    return 0 if result.decision == Decision.PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
