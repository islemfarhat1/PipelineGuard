import pytest

from engine.policy import Decision, PolicyResult
from engine.orchestrator import combine_pr_security_decisions


@pytest.mark.parametrize(
    "differential,commits,expected",
    [
        (Decision.PASS, Decision.PASS, Decision.PASS),
        (Decision.BLOCK, Decision.PASS, Decision.BLOCK),
        (Decision.PASS, Decision.BLOCK, Decision.BLOCK),
        (Decision.BLOCK, Decision.BLOCK, Decision.BLOCK),
    ],
)
def test_combined_security_decision(
    differential,
    commits,
    expected,
):
    result = combine_pr_security_decisions(
        PolicyResult(differential, ["Differential result"]),
        PolicyResult(commits, ["Commit scan result"]),
    )

    assert result.decision == expected


def test_both_blocking_reasons_preserved():
    result = combine_pr_security_decisions(
        PolicyResult(Decision.BLOCK, ["New HIGH vulnerability"]),
        PolicyResult(Decision.BLOCK, ["Secret in PR history"]),
    )

    assert result.decision == Decision.BLOCK
    assert "New HIGH vulnerability" in result.reasons
    assert "Secret in PR history" in result.reasons