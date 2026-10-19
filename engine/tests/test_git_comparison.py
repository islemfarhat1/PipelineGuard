import subprocess

import pytest

from engine.git_comparison import get_verified_git_diff


BASELINE = "a" * 40
HEAD = "b" * 40


def test_invalid_sha_is_rejected():
    with pytest.raises(ValueError, match="Invalid baseline SHA"):
        get_verified_git_diff("invalid", HEAD)


def test_command_injection_is_rejected():
    with pytest.raises(ValueError, match="Invalid head SHA"):
        get_verified_git_diff(
            BASELINE,
            "b" * 40 + "; echo injected",
        )


def test_verified_diff_is_returned(monkeypatch):
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)

        if "merge-base" in command:
            output = BASELINE + "\n"
        elif "diff" in command:
            output = "diff --git a/app.py b/app.py\n"
        else:
            output = ""

        return subprocess.CompletedProcess(
            command,
            0,
            stdout=output,
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = get_verified_git_diff(BASELINE, HEAD)

    assert result.startswith("diff --git")
    assert len(commands) == 4
    assert all(
        command[0] == "git"
        for command in commands
    )


def test_unrelated_baseline_is_rejected(monkeypatch):
    def fake_run(command, **kwargs):
        output = (
            "c" * 40
            if "merge-base" in command
            else ""
        )

        return subprocess.CompletedProcess(
            command,
            0,
            stdout=output,
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(ValueError, match="ancestor"):
        get_verified_git_diff(BASELINE, HEAD)


def test_git_failure_is_rejected(monkeypatch):
    def fake_run(command, **kwargs):
        raise subprocess.CalledProcessError(
            128,
            command,
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(ValueError, match="Git comparison failed"):
        get_verified_git_diff(BASELINE, HEAD)


def test_verified_empty_diff_is_allowed(monkeypatch):
    def fake_run(command, **kwargs):
        output = (
            BASELINE + "\n"
            if "merge-base" in command
            else ""
        )

        return subprocess.CompletedProcess(
            command,
            0,
            stdout=output,
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert get_verified_git_diff(BASELINE, HEAD) == ""