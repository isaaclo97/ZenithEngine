#!/usr/bin/env python3
"""
Runs the REAL, project-specific Zenith Engine rules (R1005, R1006, R1009,
R1013, R1015, R1018, R1020; in engine/rules/network.py,
engine/rules/runners.py and engine/rules/triggers.py) against
vulnerable.yml and fixed.yml, and also decodes the simulated
DNS-exfiltration payload (R1015) to show what data would be traveling
hidden inside the subdomain.
"""
import base64
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.network import (
    check_fraudulent_domain_1005,
    check_direct_ip_call_1009,
    check_dns_exfiltration_1015,
    check_github_api_exfiltration_1018,
)
from engine.rules.runners import check_runs_on_self_hosted_1006, check_runner_ec2_without_hardening_1020
from engine.rules.triggers import check_pull_request_without_branch_restriction_1013


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  line {alert['line']}: {alert['description']}")


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))

    alerts = (
        check_fraudulent_domain_1005(workflow, lines, lang='en')
        + check_direct_ip_call_1009(workflow, lines, lang='en')
        + check_dns_exfiltration_1015(workflow, lines, lang='en')
        + check_github_api_exfiltration_1018(workflow, lines, lang='en')
        + check_runs_on_self_hosted_1006(workflow, lines, lang='en')
        + check_runner_ec2_without_hardening_1020(workflow, lines, lang='en')
        + check_pull_request_without_branch_restriction_1013(workflow, lines, lang='en')
    )
    if not alerts:
        print('  No findings.')
        return
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)


def decode_dns_payload():
    print('\n=== Decoding the simulated DNS-exfiltration payload ===')
    subdomain = 'Z2hwX3Byb2REZXBsb3lUb2tlbjc4OQ'
    padded = subdomain + '=' * (-len(subdomain) % 4)
    decoded = base64.b64decode(padded).decode()
    print(f'  Queried subdomain: {subdomain}.attacker-dns.example')
    print(f'  Decoded (base64) -> "{decoded}"')
    print('  A DNS server under the attacker\'s control, authoritative for "attacker-dns.example",')
    print('  sees this query in its logs just like it would see any legitimate DNS resolution.')
    print('  The data traveled in full without needing a single outbound HTTP connection.')


def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')
    decode_dns_payload()


if __name__ == '__main__':
    sys.exit(main())
