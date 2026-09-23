#!/usr/bin/env python3
"""
Runs the REAL Zenith Engine rules (R1002 / R1012 / R1017, in
engine/rules/actions.py) against vulnerable.yml and fixed.yml -- not a
reimplementation, the same code the Flask application uses -- and also
simulates why a mutable tag is dangerous by reproducing (with fictional
data) the real pattern of the tj-actions/changed-files compromise
(CVE-2025-30066): the same "@v35" resolving to different commits across two
different pipeline runs.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.actions import (
    check_action_without_hash_1002,
    check_branch_as_version_1012,
    check_latest_as_version_1017,
)


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  line {alert['line']}: {alert['rule']}")
    print(f"             {alert['description']}")


def report(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))

    alerts = (
        check_action_without_hash_1002(workflow, lines, lang='en')
        + check_branch_as_version_1012(workflow, lines, lang='en')
        + check_latest_as_version_1017(workflow, lines, lang='en')
    )
    if not alerts:
        print('  No UDW findings: every action is pinned to a commit hash.')
        return
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)


def simulate_tag_hijack():
    print('\n=== Simulation: what a mutable tag means in practice ===')
    print('Fictional scenario inspired by CVE-2025-30066 (tj-actions/changed-files).')
    print('Your workflow always declares the same line:')
    print('    uses: tj-actions/changed-files@v35\n')

    resolutions = {
        '2025-03-10 09:00 UTC': 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e  (legitimate commit from the maintainer)',
        '2025-03-14 22:41 UTC': '9f8e7d6c5b4a30201f0e0d0c0b0a09080706050  (commit rewritten by the attacker)',
    }

    for moment, commit in resolutions.items():
        print(f'  Pipeline run on {moment}:')
        print(f'    "@v35" resolves to -> {commit}')

    print("\n  The repository's .yml did NOT change between the two runs.")
    print('  The step\'s behavior did, because the tag is a mutable pointer,')
    print('  not immutable content. With a pinned commit hash, the second row')
    print('  would have been impossible: the legitimate commit\'s hash never')
    print('  "turns into" the malicious commit\'s hash.')


def main():
    base = Path(__file__).parent
    report(base / 'vulnerable.yml')
    report(base / 'fixed.yml')
    simulate_tag_hijack()


if __name__ == '__main__':
    sys.exit(main())
