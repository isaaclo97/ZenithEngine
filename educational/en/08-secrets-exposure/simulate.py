#!/usr/bin/env python3
"""
Runs the REAL Zenith Engine rules R1014 / R1019 (in
engine/rules/credentials.py) against vulnerable.yml and fixed.yml, and also
simulates the real execution log GitHub Actions would produce -- including
where automatic secret masking DOES work and where it has known gaps.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.credentials import check_hardcoded_credential_1014, check_secret_in_logs_1019


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  line {alert['line']}: {alert['description']}")


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))
    alerts = check_hardcoded_credential_1014(workflow, lines, lang='en') + check_secret_in_logs_1019(workflow, lines, lang='en')
    if not alerts:
        print('  No SEW findings.')
        return
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)


def mask(text, secret_value):
    """Reproduces GitHub's automatic masking: replaces any LITERAL
    occurrence of the secret's exact value with '***'."""
    return text.replace(secret_value, '***')


def simulate_log():
    print('\n=== Simulation of the real execution log ===')
    real_token = 'ghp_S3cr3tRealDeployToken1234567890'

    print('\n1) vulnerable.yml: hardcoded credential (R1014):')
    hardcoded_line = 'with.api_key: "sk_live_EXAMPLE-not-a-real-key"'
    print('  The value is written directly in the repository\'s .yml, in plain text:')
    print(f'    {hardcoded_line}')
    print('  GitHub cannot mask this in the logs because it was never registered as a secret:')
    print('  anyone with read access to the repository (or to a fork, if the .yml is public) sees it directly.')

    print('\n2) vulnerable.yml: direct printing of a real secret (R1019):')
    log_line = f'echo "Using token: {real_token}"'
    print('  Actual command run: run: echo "Using token: $TOKEN"')
    print(f'  Log WITHOUT masking (what the process would produce):\n    Using token: {real_token}')
    print(f'  Log WITH GitHub\'s automatic masking (matches the secret\'s exact value):\n    {mask(log_line, real_token)}')
    print('  In this simple case, GitHub DOES mask it, but R1019 still flags it as CRITICAL')
    print('  because masking has known, widely documented gaps. For example, if the secret')
    print('  gets transformed before printing, masking no longer recognizes the original value:')

    print('\n3) A variant that DOES evade masking (not in vulnerable.yml, but this is the real reason R1019 exists):')
    print('    run: echo "Token in base64: $(echo -n $TOKEN | base64)"')
    import base64
    encoded = base64.b64encode(real_token.encode()).decode()
    log_line_b64 = f'Token in base64: {encoded}'
    print(f'  Log produced:\n    {log_line_b64}')
    print(f'  Log after GitHub\'s masking (it looks for the literal "{real_token}", not its base64 form):')
    print(f'    {mask(log_line_b64, real_token)}   <- NOT masked: the secret is recoverable with "base64 -d"')

    print('\n4) fixed.yml: only the length is printed, never the value (no R1019 findings):')
    print('    run: echo "TOKEN is set (length: ${#TOKEN})"')
    print(f'  Log produced:\n    TOKEN is set (length: {len(real_token)})')
    print('  There is no sensitive value to mask: it never reached the logs.')


def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')
    simulate_log()


if __name__ == '__main__':
    sys.exit(main())
