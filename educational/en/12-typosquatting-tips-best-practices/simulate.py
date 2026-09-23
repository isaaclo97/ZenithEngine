#!/usr/bin/env python3
"""
Looks for typosquatting and risky install practices in vulnerable.yml and
fixed.yml with the educational detector in educational/tools/typosquat.py (it's
not a Zenith Engine rule), explains how it reasons and, with --online, checks
against GitHub that every pinned hash really is the version in its comment.

    python3 simulate.py            # offline
    python3 simulate.py --online   # also asks GitHub via git ls-remote
"""
import sys
from pathlib import Path

EDUCATIONAL = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(EDUCATIONAL.parent))
sys.path.insert(0, str(EDUCATIONAL))

from engine.parser import parse_workflow
from engine.rules.actions import check_action_without_hash_1002
from tools.typosquat import (
    check_risky_install_patterns, check_typosquatted_actions, check_typosquatted_packages,
    levenshtein, verify_pins_online,
)

EXAMPLES = [
    ('actons/checkout', 'actions/checkout', 'a missing letter'),
    ('actions/setup-pyhton', 'actions/setup-python', 'two swapped letters'),
    ('crossenv', 'cross-env', 'no hyphen; a real npm case, 2017'),
    ('jeIlyfish', 'jellyfish', 'capital I instead of l; a real PyPI case, 2019'),
]


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']:13s} line {alert['line']}: {alert['description']}")


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))
    alerts = (
        check_typosquatted_actions(workflow, lines, 'en')
        + check_typosquatted_packages(workflow, lines, 'en')
        + check_risky_install_patterns(workflow, lines, 'en')
        + check_action_without_hash_1002(workflow, lines, 'en')
    )
    if not alerts:
        print('  No findings.')
    for alert in sorted(alerts, key=lambda a: (a['line'], a['rule_id'])):
        print_alert(alert)


def explain_detector():
    print('\n=== How the detector decides a name is suspicious ===')
    print('  It compares every name with a list of popular actions and packages using the')
    print('  Levenshtein distance: how many letters you have to add, remove or change to go')
    print('  from one to the other. A distance of 1 or 2 from something very popular, without')
    print('  being exactly equal, is the typical fingerprint of a typo... or of someone waiting for one.')
    for found, popular, kind in EXAMPLES:
        print(f'    {found:22s} vs {popular:22s} distance {levenshtein(found.lower(), popular.lower())}  ({kind})')
    print('  Homoglyphs (capital I for l, Cyrillic letters that look Latin) are normalized')
    print('  before comparing: visually they are identical, so they count as 0.')
    print('  Limit: it only knows the popular list. A made-up name that looks like nothing')
    print('  known won\'t trigger; that\'s why the README tips matter more than the tool.')


def check_pins(base, online):
    print('\n=== Is the pinned hash really the version in the comment? ===')
    if not online:
        print('  Offline there\'s no way to know: the "# v4.0.2" comment is just text. Check it with')
        print('    git ls-remote https://github.com/actions/setup-node refs/tags/v4.0.2')
        print('  or run:  python3 simulate.py --online')
        return
    labels = {'ok': 'OK', 'mismatch': 'MISMATCH', 'tag-not-found': 'TAG NOT FOUND', 'error': 'NETWORK ERROR'}
    for name in ('vulnerable.yml', 'fixed.yml'):
        print(f'  {name}:')
        for line, action, sha, tag, status, real in verify_pins_online(base / name):
            print(f'    line {line:3d}  {action}@{sha[:12]}... # {tag:8s} -> {labels[status]}')
            if status == 'mismatch':
                print(f'               {tag} is actually {real}. The pinned hash is something else (or not in that repo at all).')


def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')
    explain_detector()
    check_pins(base, online='--online' in sys.argv)


if __name__ == '__main__':
    sys.exit(main())
