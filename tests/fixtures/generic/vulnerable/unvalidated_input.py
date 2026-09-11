# @audit-fixture
# @rule: taint_rce
# @expected: detected
# VULNERABLE : entrée HTTP non validée passée à subprocess(shell=True)
import subprocess

from flask import request


def run_command():
    user_input = request.args.get("cmd")
    subprocess.call(user_input, shell=True)


def read_file():
    filename = request.args.get("f")
    subprocess.Popen(f"cat {filename}", shell=True)


# Multi-ligne : source HTTP puis subprocess.run réparti sur plusieurs lignes
def run_command_multiline():
    user_input = request.args.get("cmd")
    subprocess.run(
        user_input,
        shell=True
    )
