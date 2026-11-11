import ast
import json
from pathlib import Path

import pytest

from assistant import explain
from assistant.explain import (
    explain_findings,
    render_markdown,
    validate_response,
)
from engine.models import Scanner, SecurityFinding, Severity

ROOT = Path(__file__).resolve().parents[2]
SECRET = "sk_FAKE_0000000000000000"

GOOD = {
    "explanation": "eval runs arbitrary code.",
    "risk": "Remote code execution.",
    "fix": "Use ast.literal_eval or explicit parsing.",
    "false_positive_likelihood": "low",
    "confidence": "high",
}


class FakeClient:
    def __init__(self, answers):
        self.answers = list(answers)
        self.prompts = []

    def generate(self, system, prompt, schema):
        self.prompts.append(prompt)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def _finding(location="demo-app/app.py:1"):
    return SecurityFinding(
        Scanner.SEMGREP, Severity.HIGH, "eval", "rule", location
    )


def test_valid_answer_is_accepted():
    assert validate_response(json.dumps(GOOD), set()) == GOOD


@pytest.mark.parametrize("text", [
    "not json",
    "[]",
    json.dumps({**GOOD, "fix": ""}),
    json.dumps({k: v for k, v in GOOD.items() if k != "risk"}),
    json.dumps({**GOOD, "confidence": "certain"}),
    json.dumps({**GOOD, "false_positive_likelihood": None}),
])
def test_invalid_answers_are_rejected(text):
    with pytest.raises(ValueError):
        validate_response(text, set())


def test_secret_repeated_by_the_model_is_redacted():
    answer = validate_response(
        json.dumps({**GOOD, "fix": f"Revoke {SECRET} now"}), {SECRET}
    )
    assert SECRET not in answer["fix"]


def test_one_failure_does_not_hide_other_findings(tmp_path):
    client = FakeClient([
        "broken",
        OSError("connection refused"),
        json.dumps(GOOD),
    ])
    findings = [_finding(), _finding(), _finding()]

    results = explain_findings(findings, client, str(tmp_path), set(), set())

    assert [r.answer is None for r in results] == [True, True, False]
    markdown = render_markdown(results, "fake")
    assert markdown.count("Explanation unavailable") == 2
    assert "Advisory only" in markdown
    assert "Decision:" not in markdown


def test_cli_exit_code_never_reflects_findings(tmp_path, monkeypatch):
    report = tmp_path / "semgrep.json"
    report.write_text(json.dumps({"results": [{
        "check_id": "rule", "path": "demo-app/app.py", "start": {"line": 1},
        "extra": {"severity": "ERROR", "message": "eval"},
    }]}), encoding="utf-8")
    output = tmp_path / "out.md"

    monkeypatch.setattr(
        explain, "OllamaClient",
        lambda model, url: FakeClient([json.dumps(GOOD)]),
    )

    code = explain.main([
        "--semgrep", str(report), "--repo-path", str(tmp_path),
        "--output", str(output),
    ])

    # A HIGH finding was explained, yet the command is not a gate.
    assert code == 0
    assert "Remote code execution." in output.read_text(encoding="utf-8")


def test_cli_refuses_remote_model_and_invalid_reports(tmp_path):
    report = tmp_path / "semgrep.json"
    report.write_text(json.dumps({"results": "bad"}), encoding="utf-8")

    assert explain.main([
        "--semgrep", str(report), "--ollama-url", "http://example.com",
    ]) == 2
    assert explain.main(["--semgrep", str(report)]) == 2


def test_engine_never_imports_the_assistant():
    for path in (ROOT / "engine").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert not name.startswith("assistant"), path


def test_security_gate_workflow_does_not_use_the_llm():
    workflow = (ROOT / ".github/workflows/security-v2.yml").read_text(
        encoding="utf-8"
    ).lower()
    for word in ("assistant", "ollama", "explain"):
        assert word not in workflow
