import ast
import io
import json
import tokenize
from pathlib import Path

from engine.models import Scanner, SecurityFinding
from engine.normalizer import (
    normalize_gitleaks,
    normalize_semgrep,
    normalize_trivy,
    validate_repository_path,
)

REDACTED = "[REDACTED]"
# Values that Gitleaks writes when it already redacted the secret.
ALREADY_REDACTED = {"", "REDACTED"}
# Shorter strings would be replaced everywhere in the text by mistake.
MIN_SECRET_LENGTH = 4


def _read_json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_findings(semgrep: str | None = None, gitleaks: str | None = None,
                  trivy: str | None = None):
    """
    Load reports with the V2 normalizers.

    Returns (findings, secrets, secret_locations). Invalid reports raise
    ValueError, exactly as they do in the V2 engine.
    """

    findings: list[SecurityFinding] = []
    secrets: set[str] = set()
    secret_locations: set[tuple[str, int]] = set()

    if semgrep:
        findings += normalize_semgrep(_read_json(semgrep))

    if gitleaks:
        raw = _read_json(gitleaks)
        gitleaks_findings = normalize_gitleaks(raw)
        findings += gitleaks_findings

        for entry in raw:
            for field in ("Secret", "Match"):
                value = entry.get(field)
                if (
                    isinstance(value, str)
                    and value.strip() not in ALREADY_REDACTED
                    and len(value.strip()) >= MIN_SECRET_LENGTH
                ):
                    secrets.add(value.strip())

        for finding in gitleaks_findings:
            secret_locations.add(split_location(finding.location))

    if trivy:
        findings += normalize_trivy(_read_json(trivy))

    return findings, secrets, secret_locations


def split_location(location: str) -> tuple[str, int]:
    """Split "demo-app/app.py:12" into ("demo-app/app.py", 12)."""

    path, _, line = location.rpartition(":")
    return validate_repository_path(path), int(line)


def redact(text: str, secrets: set[str]) -> str:
    # Longest first, so a secret that contains another one is fully hidden.
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, REDACTED)
    return text


REMOVED_TEXT = '"[text removed]"'


def strip_comments_and_docstrings(source: str) -> list[str] | None:
    """
    Remove comments and standalone string statements (docstrings).

    They are free text that the author of the code controls, and the
    evaluation showed that a model follows instructions written there.
    Line numbers are kept. Returns None if the source is not valid
    Python: then no code is sent at all.
    """

    try:
        tree = ast.parse(source)
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (SyntaxError, tokenize.TokenError, ValueError):
        return None

    lines = source.splitlines()

    # tokenize knows that a "#" inside a string is not a comment.
    for token in tokens:
        if token.type == tokenize.COMMENT:
            row, column = token.start
            lines[row - 1] = lines[row - 1][:column].rstrip()

    # A string used as a statement does nothing at run time: it is text,
    # like a comment (docstrings are the usual case).
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            for row in range(node.lineno, node.end_lineno + 1):
                lines[row - 1] = ""
            lines[node.lineno - 1] = " " * node.col_offset + REMOVED_TEXT

    return lines


def read_code_context(finding: SecurityFinding, repo_root: str,
                      secrets: set[str],
                      secret_locations: set[tuple[str, int]],
                      radius: int = 3) -> str:
    """
    Return a few numbered lines around a Semgrep finding.

    Gitleaks findings get no code at all: the line is the secret.
    Trivy findings point to a package, not to a line of code.
    """

    if finding.scanner != Scanner.SEMGREP:
        return ""

    path, line = split_location(finding.location)

    root = Path(repo_root).resolve()
    file_path = (root / path).resolve()

    # The path comes from a report: never read outside the repository.
    if not file_path.is_relative_to(root):
        raise ValueError(f"Finding path escapes the repository: {path}")

    # Only Python can be cleaned safely; anything else is not sent.
    if not file_path.is_file() or file_path.suffix != ".py":
        return ""

    lines = strip_comments_and_docstrings(
        file_path.read_text(encoding="utf-8", errors="replace")
    )
    if lines is None:
        return ""

    start = max(1, line - radius)
    end = min(len(lines), line + radius)

    numbered = []
    for number in range(start, end + 1):
        content = lines[number - 1]
        if (path, number) in secret_locations:
            content = REDACTED
        marker = ">>" if number == line else "  "
        numbered.append(f"{marker} {number:4d} | {content}")

    return redact("\n".join(numbered), secrets)
