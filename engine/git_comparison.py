import re
import subprocess


SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


def get_verified_git_diff(
    baseline_sha: str,
    head_sha: str,
    repo_path: str = ".",
) -> str:
    """
    Generate a Git diff between two verified commits.

    Raises ValueError if verification or Git execution fails.
    """

    for name, sha in (
        ("baseline", baseline_sha),
        ("head", head_sha),
    ):
        if not isinstance(sha, str) or not SHA_PATTERN.fullmatch(sha):
            raise ValueError(f"Invalid {name} SHA")

    def run_git(*arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", repo_path, *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
            check=True,
        )
        return result.stdout

    try:
        for sha in (baseline_sha, head_sha):
            run_git("cat-file", "-e", f"{sha}^{{commit}}")

        merge_base = run_git(
            "merge-base",
            baseline_sha,
            head_sha,
        ).strip()

        if merge_base.lower() != baseline_sha.lower():
            raise ValueError(
                "Baseline must be an ancestor of PR head"
            )

        return run_git(
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--unified=0",
            baseline_sha,
            head_sha,
            "--",
        )

    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        OSError,
    ) as error:
        raise ValueError(
            f"Git comparison failed: {error}"
        ) from error