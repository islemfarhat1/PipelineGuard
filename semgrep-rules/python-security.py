# Test cases for python-security.yml, run with: semgrep --test semgrep-rules/
#
# "ruleid:" means the next line MUST be reported by that rule.
# "ok:" means the next line must NOT be reported by that rule.
#
# This file is deliberately unsafe test data. It is never imported or run,
# and the security gates only scan demo-app/.

import json
import os
import pickle
import subprocess


def eval_cases(user_input):
    # ruleid: pipelineguard-dangerous-eval
    eval(user_input)

    # ok: pipelineguard-dangerous-eval
    int(user_input)


def exec_cases(user_input):
    # ruleid: pipelineguard-dangerous-exec
    exec(user_input)

    # ok: pipelineguard-dangerous-exec
    print(user_input)


def command_cases(user_input):
    # ruleid: pipelineguard-command-injection
    os.system("ls " + user_input)

    # ruleid: pipelineguard-command-injection
    subprocess.run(user_input, shell=True)

    # ruleid: pipelineguard-command-injection
    subprocess.call(f"cat {user_input}", shell=True)

    # Argument list without a shell: not reported.
    # ok: pipelineguard-command-injection
    subprocess.run(["ls", user_input])

    # Constant commands are not reported. Not reported does not mean safe:
    # it only means the command text cannot be changed by user input.
    # ok: pipelineguard-command-injection
    os.system("ls")

    # ok: pipelineguard-command-injection
    subprocess.run("ls -l", shell=True)


def deserialization_cases(data, file):
    # ruleid: pipelineguard-insecure-deserialization
    pickle.loads(data)

    # ruleid: pipelineguard-insecure-deserialization
    pickle.load(file)

    # ok: pipelineguard-insecure-deserialization
    json.loads(data)
