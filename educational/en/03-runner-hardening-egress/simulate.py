#!/usr/bin/env python3
"""
Runs the REAL Zenith Engine rule (R1004, in engine/rules/network.py)
against vulnerable.yml and fixed.yml, and also simulates the real effect of
an egress policy: given a list of outbound connections the job tries to
open during execution (some legitimate, one an exfiltration attempt), it
shows what would have happened under each harden-runner configuration.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.network import check_egress_policy_1004

# Connections the job would try to open during a real run, including a
# simulated data exfiltration attempt by a compromised dependency (see
# lesson 01).
SIMULATED_CONNECTIONS = [
    ('github.com:443', 'repository checkout'),
    ('api.github.com:443', 'GitHub Actions API calls'),
    ('registry.npmjs.org:443', 'npm ci / npm publish'),
    ('attacker-exfil.example.com:443', 'ATTACK: compromised dependency sending NPM_TOKEN'),
]


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  line {alert['line']}: {alert['description']}")


def harden_runner_config(job):
    for step in job.get('steps', []):
        if 'step-security/harden-runner' in step.get('uses', ''):
            with_params = step.get('with', {}) or {}
            policy = with_params.get('egress-policy')
            allowed = set((with_params.get('allowed-endpoints', '') or '').split())
            return policy, allowed
    return None, set()


def report_and_simulate(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))

    alerts = check_egress_policy_1004(workflow, lines, lang='en')
    if alerts:
        for alert in sorted(alerts, key=lambda a: a['line']):
            print_alert(alert)
    else:
        print('  No HGW findings.')

    for job_name, job in workflow.get('jobs', {}).items():
        policy, allowed = harden_runner_config(job)
        print(f'\n  Simulated outbound traffic for job "{job_name}" (policy: {policy or "no harden-runner"}):')
        for endpoint, description in SIMULATED_CONNECTIONS:
            blocked = policy == 'block' and endpoint not in allowed
            outcome = 'BLOCKED ✋' if blocked else 'allowed (goes through)'
            marker = '  [!] ' if 'ATTACK' in description else '      '
            print(f'{marker}{endpoint:32s} {outcome:24s}  {description}')


def main():
    base = Path(__file__).parent
    report_and_simulate(base / 'vulnerable.yml')
    report_and_simulate(base / 'fixed.yml')


if __name__ == '__main__':
    sys.exit(main())
