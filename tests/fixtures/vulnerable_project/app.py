# tests/fixtures/vulnerable_project/app.py
#
# SYNTHETIC FIXTURE — NOT A REAL PROJECT
# This file contains deliberately insecure patterns for testing Bandit detection.
# None of these patterns represent real application code.
# Do not use these patterns in production.

import subprocess

# B602 / B603: subprocess call with shell=True — intentionally insecure for testing
# The command is clearly fake and cannot cause harm.
def run_fake_command(cmd):
    """Deliberately uses shell=True so Bandit flags it."""
    result = subprocess.run(cmd, shell=True, capture_output=True)  # noqa: S602
    return result

# B307: use of eval() — intentionally insecure for testing
def parse_fake_config(data):
    """Deliberately uses eval() so Bandit flags it."""
    return eval(data)  # noqa: S307
