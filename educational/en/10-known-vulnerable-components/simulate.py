#!/usr/bin/env python3
"""
Runs the REAL Zenith Engine rule R1025 (engine/rules/vulnerabilities.py)
against vulnerable.yml and fixed.yml. To keep this lesson deterministic and
network-independent, it forces the use of the local snapshot
engine/known_vulnerabilities.json (the same fallback the real application
uses when the GitHub API isn't reachable) instead of attempting the live
call to api.github.com/advisories.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

import engine.rules.vulnerabilities as vulnerabilities_rule
from engine.parser import parse_workflow

# Force the deterministic local fallback instead of the live call to the
# GitHub API, so this lesson doesn't depend on network access or on which
# CVEs have been published since it was written.
vulnerabilities_rule.load_known_vulnerabilities = vulnerabilities_rule._load_local_snapshot


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  line {alert['line']}: {alert['description']}")
    if alert.get('suggestion'):
        print(f"             Suggestion: {alert['suggestion']}")


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))
    alerts = vulnerabilities_rule.check_known_vulnerable_component_1025(workflow, lines, lang='en')
    if not alerts:
        print('  No KVCW findings (using the local snapshot of known CVEs).')
        return
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)


def main():
    base = Path(__file__).parent
    snapshot = vulnerabilities_rule._load_local_snapshot()
    entries = snapshot.get('aquasecurity/trivy-action', [])
    print(f'(using the local snapshot: {len(entries)} known advisory(s) for aquasecurity/trivy-action)')
    for entry in entries:
        print(f"  {entry['id']}: {entry['summary']}  (affected range: {entry['ranges']})")

    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')


if __name__ == '__main__':
    sys.exit(main())
