
import argparse
import json
from pathlib import Path

from engine.provenance import create_pr_provenance_manifest


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate PipelineGuard V2 PR provenance manifest"
    )

    parser.add_argument("--baseline-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--reports-dir", required=True)
    parser.add_argument("--output", required=True)

    args = parser.parse_args(argv)

    reports_dir = Path(args.reports_dir)

    reports = {
        revision: {
            scanner: str(
                reports_dir / f"{revision}-{scanner}.json"
            )
            for scanner in ("trivy", "semgrep", "gitleaks")
        }
        for revision in ("baseline", "current")
    }

    pr_gitleaks_report = str(
        reports_dir / "pr-gitleaks.json"
    )

    manifest = create_pr_provenance_manifest(
        baseline_sha=args.baseline_sha,
        head_sha=args.head_sha,
        reports=reports,
        pr_gitleaks_report=pr_gitleaks_report,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Seven-report manifest generated: {output_path}")


if __name__ == "__main__":
    main()
