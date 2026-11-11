import json
import re
from pathlib import Path

from assistant.evaluation import run as evaluation
from assistant.evaluation.cases import (
    CASES,
    FALSE_POSITIVE,
    PROMPT_INJECTION,
    SECRET,
    SECRET_EVAL_LINE,
    SECRET_LINE,
    TRUE_POSITIVE,
    fake_secret,
    secret_case_code,
)

ROOT = Path(__file__).resolve().parents[2]

TRIGGERS = {
    "pipelineguard-dangerous-eval": r"eval\(",
    "pipelineguard-dangerous-exec": r"exec\(",
    "pipelineguard-command-injection": r"(os\.system\(|shell=True)",
    "pipelineguard-insecure-deserialization": r"pickle\.load",
}


def _answer(rating):
    return json.dumps({
        "explanation": "e", "risk": "r", "fix": "f",
        "false_positive_likelihood": rating, "confidence": "medium",
    })


class FixedClient:
    def __init__(self, text):
        self.text = text

    def generate(self, system, prompt, schema):
        return self.text


class EchoPromptClient:
    """A model that repeats its input: it leaks whatever it is sent."""

    def generate(self, system, prompt, schema):
        return prompt


def test_every_case_points_at_the_dangerous_line():
    for case in CASES:
        line = case.code.splitlines()[case.line - 1]
        assert re.search(TRIGGERS[case.rule], line), case.case_id


def test_categories_are_balanced_and_labelled():
    counts = {}
    for case in CASES:
        counts[case.category] = counts.get(case.category, 0) + 1
    assert counts == {TRUE_POSITIVE: 5, FALSE_POSITIVE: 4, PROMPT_INJECTION: 4}
    assert len({case.case_id for case in CASES}) == len(CASES)


def test_fake_secret_is_never_written_in_the_repository():
    secret = fake_secret()
    for path in ROOT.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        if path.suffix not in {".py", ".md", ".json", ".yml", ".yaml", ".txt"}:
            continue
        assert secret not in path.read_text(encoding="utf-8", errors="ignore"), path


def test_secret_case_layout():
    lines = secret_case_code().splitlines()
    assert fake_secret() in lines[SECRET_LINE - 1]
    assert "eval(" in lines[SECRET_EVAL_LINE - 1]
    # The secret line is inside the code context sent for the eval finding.
    assert SECRET_EVAL_LINE - SECRET_LINE <= 3


def test_secret_is_not_sent_even_to_a_model_that_repeats_everything():
    record = evaluation.run_secret_case(EchoPromptClient(), run=1)
    assert record["secret_exposed"] is False
    assert record["correct"] is True


def test_secret_metric_detects_a_leak(monkeypatch):
    # Disable both protections: the metric must then report the exposure.
    monkeypatch.setattr(
        "assistant.explain.read_code_context",
        lambda finding, root, secrets, locations: secret_case_code(),
    )
    record = evaluation.run_secret_case(EchoPromptClient(), run=1)
    assert record["secret_exposed"] is True
    assert record["correct"] is False


def test_correct_and_invalid_answers_are_scored():
    case_tp = next(c for c in CASES if c.category == TRUE_POSITIVE)
    case_fp = next(c for c in CASES if c.category == FALSE_POSITIVE)

    assert evaluation.run_labelled_case(case_tp, FixedClient(_answer("low")), 1)["correct"]
    assert not evaluation.run_labelled_case(case_tp, FixedClient(_answer("high")), 1)["correct"]
    assert evaluation.run_labelled_case(case_fp, FixedClient(_answer("high")), 1)["correct"]

    invalid = evaluation.run_labelled_case(case_tp, FixedClient("not json"), 1)
    assert invalid["valid"] is False
    assert invalid["correct"] is False


def test_score_counts_invalid_as_wrong_and_measures_stability():
    records = [
        {"case_id": "a", "category": TRUE_POSITIVE, "valid": True,
         "rating": "low", "correct": True, "seconds": 1.0},
        {"case_id": "a", "category": TRUE_POSITIVE, "valid": True,
         "rating": "low", "correct": True, "seconds": 3.0},
        {"case_id": "b", "category": FALSE_POSITIVE, "valid": True,
         "rating": "high", "correct": True, "seconds": 1.0},
        {"case_id": "b", "category": FALSE_POSITIVE, "valid": False,
         "rating": None, "correct": False, "seconds": 1.0},
        {"case_id": "s", "category": SECRET, "valid": True,
         "rating": None, "correct": True, "seconds": 2.0},
    ]

    metrics = evaluation.score(records)

    assert metrics["valid_json"] == 4
    assert metrics[TRUE_POSITIVE] == {"correct": 2, "total": 2}
    assert metrics[FALSE_POSITIVE] == {"correct": 1, "total": 2}
    assert metrics[SECRET] == {"correct": 1, "total": 1}
    assert metrics["stable_cases"] == 1
    assert metrics["labelled_cases"] == 2
    assert metrics["average_seconds"] == 1.6


def test_full_evaluation_and_report_with_a_fake_model():
    records = evaluation.evaluate(FixedClient(_answer("low")), runs=2)
    metrics = evaluation.score(records)

    assert metrics["answers"] == 2 * (len(CASES) + 1)
    assert metrics[TRUE_POSITIVE]["correct"] == 10
    assert metrics[FALSE_POSITIVE]["correct"] == 0
    assert metrics[PROMPT_INJECTION]["correct"] == 8

    report = evaluation.render_results(
        {"fake": {"metrics": metrics, "records": records}}, runs=2
    )
    assert "| Valid JSON answers | 28/28 (100%) |" in report
    assert "advisory only" in report
