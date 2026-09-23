#!/usr/bin/env python3
"""
Runs the REAL Zenith Engine rules R1000 / R1001 / R1021 (in
engine/rules/triggers.py) against vulnerable.yml and fixed.yml, and also
recreates the timeline of a real TOCTOU attack on "gh pr checkout <number>":
the commit that gets reviewed and approved isn't necessarily the commit
that ends up running with the base repository's secrets.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.triggers import (
    check_pull_request_target_1000,
    check_checkout_without_ref_1001,
    check_toctou_pattern_1021,
)


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  line {alert['line']}: {alert['description']}")


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))

    alerts = (
        check_pull_request_target_1000(workflow, lines, lang='en')
        + check_checkout_without_ref_1001(workflow, lines, lang='en')
        + check_toctou_pattern_1021(workflow, lines, lang='en')
    )
    if not alerts:
        print('  No PTW findings.')
        return
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)


def explain_r1001_limitation():
    print('\n=== A note on R1001 and fixed.yml ===')
    print('  fixed.yml still triggers R1001 on the "test-approved" job, and it is RIGHT to do')
    print('  so: even though it uses github.event.pull_request.head.sha, that job still runs')
    print('  code written by the PR author inside a pull_request_target context. Pinning the')
    print('  SHA only closes the TOCTOU gap (exactly what was reviewed is what runs); it does')
    print('  NOT turn the PR\'s code into trusted code. What makes this job acceptable are')
    print('  controls R1001 cannot see: the prior human review (the "safe-to-test" label), no')
    print('  secrets in the environment, read-only permissions and persist-credentials: false.')
    print('  Moral: an alert that keeps firing after a fix isn\'t necessarily a false positive;')
    print('  you need to understand what risk it points at and whether controls the tool')
    print('  can\'t see actually mitigate it.')


def simulate_toctou_timeline():
    print('\n=== Simulation: timeline of a TOCTOU attack ===')
    events = [
        ('T+0min',  'The author opens PR #42 with commit A (legitimate code).'),
        ('T+3min',  'A maintainer reviews A\'s diff, deems it safe and adds the "safe-to-test" label.'),
        ('T+3min',  'The "labeled" event triggers the "test-approved" job. Its payload pins head.sha = A.'),
        ('T+4min',  'The author pushes a NEW commit B to the same PR #42 (with code that exfiltrates secrets).'),
        ('T+5min',  'The job finally starts (delayed, waiting on the runner queue).'),
        ('T+5min',  '"gh pr checkout 42" runs -> fetches the PR\'s LATEST commit, which is now B, not A.'),
    ]
    for moment, description in events:
        print(f'  {moment:8s} {description}')

    print('\n  Commit reviewed and approved:  A')
    print('  Commit actually executed:      B   (with GH_TOKEN available in the environment)')
    print('  -> The maintainer approved A. The pipeline ran B. That gap is the TOCTOU hole.')
    print('\n  With fixed.yml: the checkout uses github.event.pull_request.head.sha, pinned at the')
    print('  "labeled" event (= A), so A runs even though B already exists. Pushing B produces a')
    print('  "synchronize" event, which doesn\'t trigger "test-approved": the maintainer has to')
    print('  review B and re-label. And even if A turned out to be malicious, the job has no')
    print('  secrets to steal.')

def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')
    explain_r1001_limitation()
    simulate_toctou_timeline()


if __name__ == '__main__':
    sys.exit(main())
