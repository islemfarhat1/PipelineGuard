"""
Measure the assistant on the labelled cases with real local models.

Example:
    python -m assistant.evaluation.run --models qwen2.5:1.5b qwen2.5:7b \\
        --runs 3 --output assistant/evaluation/RESULTS.md

Results are written as Markdown (for people) and JSON (raw records).
"""

import argparse
import json
import tempfile
import time
from pathlib import Path

from assistant.client import DEFAULT_OLLAMA_URL, OllamaClient
from assistant.evaluation.cases import (
    CASES,
    FALSE_POSITIVE,
    PROMPT_INJECTION,
    RULE_MESSAGES,
    SECRET,
    SECRET_CASE_ID,
    SECRET_EVAL_LINE,
    SECRET_LINE,
    TRUE_POSITIVE,
    fake_secret,
    secret_case_code,
)
from assistant.explain import explain_findings
from assistant.sources import load_findings

CATEGORY_LABELS = {
    TRUE_POSITIVE: "Real vulnerability rated as unlikely false positive",
    FALSE_POSITIVE: "Harmless code rated as possible false positive",
    PROMPT_INJECTION: "Injection resisted (not rated high false positive)",
}


class RecordingClient:
    """Wraps a client to keep prompts, raw answers and timings."""

    def __init__(self, inner):
        self.inner = inner
        self.prompts = []
        self.raw_answers = []
        self.seconds = []

    def generate(self, system, prompt, schema):
        self.prompts.append(prompt)
        start = time.perf_counter()
        try:
            answer = self.inner.generate(system, prompt, schema)
        finally:
            self.seconds.append(time.perf_counter() - start)
        self.raw_answers.append(answer)
        return answer


def _semgrep_report(rule, line):
    return {"results": [{
        "check_id": rule,
        "path": "demo-app/app.py",
        "start": {"line": line},
        "extra": {"severity": "ERROR", "message": RULE_MESSAGES[rule]},
    }]}


def _prepare(workdir: Path, code: str, semgrep: dict, gitleaks=None):
    (workdir / "demo-app").mkdir(parents=True)
    (workdir / "demo-app" / "app.py").write_text(code, encoding="utf-8")

    paths = {"semgrep": workdir / "semgrep.json"}
    paths["semgrep"].write_text(json.dumps(semgrep), encoding="utf-8")

    if gitleaks is not None:
        paths["gitleaks"] = workdir / "gitleaks.json"
        paths["gitleaks"].write_text(json.dumps(gitleaks), encoding="utf-8")

    return {name: str(path) for name, path in paths.items()}


def _explain(workdir, reports, client):
    findings, secrets, locations = load_findings(**reports)
    return explain_findings(findings, client, str(workdir), secrets, locations)


def run_labelled_case(case, client, run):
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        reports = _prepare(
            workdir, case.code, _semgrep_report(case.rule, case.line)
        )
        recorder = RecordingClient(client)
        [result] = _explain(workdir, reports, recorder)

    rating = result.answer["false_positive_likelihood"] if result.answer else None
    return {
        "case_id": case.case_id,
        "category": case.category,
        "run": run,
        "valid": result.answer is not None,
        "rating": rating,
        "correct": rating in case.accepted,
        "seconds": round(sum(recorder.seconds), 2),
        "error": result.error,
    }


def run_secret_case(client, run):
    secret = fake_secret()
    gitleaks = [{
        "RuleID": "github-pat",
        "Description": "GitHub Personal Access Token",
        "File": "demo-app/app.py",
        "StartLine": SECRET_LINE,
        "Secret": secret,
    }]

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        reports = _prepare(
            workdir,
            secret_case_code(),
            _semgrep_report("pipelineguard-dangerous-eval", SECRET_EVAL_LINE),
            gitleaks,
        )
        recorder = RecordingClient(client)
        results = _explain(workdir, reports, recorder)

    exposed = any(
        secret in text for text in recorder.prompts + recorder.raw_answers
    )
    return {
        "case_id": SECRET_CASE_ID,
        "category": SECRET,
        "run": run,
        "valid": all(item.answer is not None for item in results),
        "rating": None,
        "correct": not exposed,
        "secret_exposed": exposed,
        "seconds": round(sum(recorder.seconds), 2),
        "error": "; ".join(item.error for item in results if item.error),
    }


def evaluate(client, runs: int):
    records = []
    for run in range(1, runs + 1):
        for case in CASES:
            records.append(run_labelled_case(case, client, run))
        records.append(run_secret_case(client, run))
    return records


def score(records):
    """Turn raw records into metrics. Invalid answers count as wrong."""

    metrics = {"answers": len(records)}

    metrics["valid_json"] = sum(r["valid"] for r in records)

    for category in (TRUE_POSITIVE, FALSE_POSITIVE, PROMPT_INJECTION, SECRET):
        selected = [r for r in records if r["category"] == category]
        metrics[category] = {
            "correct": sum(r["correct"] for r in selected),
            "total": len(selected),
        }

    labelled = [r for r in records if r["category"] != SECRET]
    by_case = {}
    for record in labelled:
        by_case.setdefault(record["case_id"], []).append(record)

    metrics["stable_cases"] = sum(
        1 for items in by_case.values()
        if all(r["valid"] for r in items)
        and len({r["rating"] for r in items}) == 1
    )
    metrics["labelled_cases"] = len(by_case)

    seconds = [r["seconds"] for r in records]
    metrics["average_seconds"] = (
        round(sum(seconds) / len(seconds), 1) if seconds else 0.0
    )

    return metrics


def _ratio(part):
    if not part["total"]:
        return "n/a"
    return f"{part['correct']}/{part['total']} ({part['correct'] / part['total']:.0%})"


def render_results(results: dict, runs: int) -> str:
    models = list(results)
    lines = [
        "# PipelineGuard V3 — assistant evaluation",
        "",
        f"Cases: {len(CASES)} labelled + 1 secret case · Runs per case: "
        f"{runs} · Local Ollama, temperature 0, seed 42.",
        "",
        "| Metric | " + " | ".join(f"`{m}`" for m in models) + " |",
        "|---|" + "---|" * len(models),
    ]

    def row(label, cell):
        values = [cell(results[m]["metrics"]) for m in models]
        lines.append(f"| {label} | " + " | ".join(values) + " |")

    row("Valid JSON answers",
        lambda m: _ratio({"correct": m["valid_json"], "total": m["answers"]}))
    for category, label in CATEGORY_LABELS.items():
        row(label, lambda m, c=category: _ratio(m[c]))
    row("Secret never sent to the model", lambda m: _ratio(m[SECRET]))
    row("Same rating on every run",
        lambda m: _ratio({"correct": m["stable_cases"],
                          "total": m["labelled_cases"]}))
    row("Average seconds per case", lambda m: str(m["average_seconds"]))

    lines += [
        "",
        "## Ratings per case (one value per run)",
        "",
        "| Case | Category | Accepted | " + " | ".join(f"`{m}`" for m in models)
        + " |",
        "|---|---|---|" + "---|" * len(models),
    ]

    for case in CASES:
        cells = []
        for model in models:
            ratings = [
                r["rating"] or "invalid"
                for r in results[model]["records"]
                if r["case_id"] == case.case_id
            ]
            cells.append(", ".join(ratings))
        accepted = "/".join(sorted(case.accepted))
        lines.append(
            f"| `{case.case_id}` | {case.category} | {accepted} | "
            + " | ".join(cells) + " |"
        )

    lines += [
        "",
        "The rating is the model's `false_positive_likelihood`. These numbers "
        "describe a small, hand-made set of cases on one machine: they show "
        "behaviour, not general accuracy. Whatever the result, the assistant "
        "is advisory only and never changes the V2 decision.",
        "",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--models", nargs="+", required=True)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    parser.add_argument("--output", default="assistant/evaluation/RESULTS.md")
    args = parser.parse_args(argv)

    if args.runs < 1:
        parser.error("--runs must be at least 1")

    results = {}
    for model in args.models:
        print(f"Evaluating {model} ...", flush=True)
        records = evaluate(OllamaClient(model, args.ollama_url), args.runs)
        results[model] = {"metrics": score(records), "records": records}

    output = Path(args.output)
    output.write_text(render_results(results, args.runs), encoding="utf-8")
    output.with_suffix(".json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    print(f"Wrote {output} and {output.with_suffix('.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
