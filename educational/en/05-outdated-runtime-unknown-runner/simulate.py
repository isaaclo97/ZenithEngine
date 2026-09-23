#!/usr/bin/env python3
"""
Runs the REAL Zenith Engine rules R1023 (engine/rules/actions.py) and
R1024 (engine/rules/runners.py) against vulnerable.yml and fixed.yml -- the
same list of outdated actions (engine/outdated_runtime_actions.txt) and the
same list of known runner labels the real application uses.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.actions import check_outdated_action_runtime_1023
from engine.rules.runners import check_unknown_runner_label_1024


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  line {alert['line']}: {alert['description']}")


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))

    alerts = check_outdated_action_runtime_1023(workflow, lines, lang='en') + check_unknown_runner_label_1024(workflow, lines, lang='en')
    if not alerts:
        print('  No GRCW findings.')
        return
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)


def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')


if __name__ == '__main__':
    sys.exit(main())
