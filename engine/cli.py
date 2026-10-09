
import argparse

from engine.orchestrator import run_pipelineguard
from engine.policy import Decision


def main():
    parser = argparse.ArgumentParser(
        description="PipelineGuard Security Policy Engine"
    )

    parser.add_argument("--trivy", required=True)
    parser.add_argument("--semgrep", required=True)
    parser.add_argument("--gitleaks", required=True)
    parser.add_argument("--gitleaks-exit-code", type=int, required=True)

    args = parser.parse_args()

    result = run_pipelineguard(
        trivy_path=args.trivy,
        semgrep_path=args.semgrep,
        gitleaks_path=args.gitleaks,
        gitleaks_exit_code=args.gitleaks_exit_code
    )

    print(f"PipelineGuard Decision: {result.decision.value}")

    for reason in result.reasons:
        print(f"- {reason}")

    return 0 if result.decision == Decision.PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
