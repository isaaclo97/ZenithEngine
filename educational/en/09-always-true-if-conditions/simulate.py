#!/usr/bin/env python3
"""
Runs the REAL Zenith Engine rule R1022 (engine/rules/triggers.py) against
vulnerable.yml and fixed.yml, and also evaluates the "if:" conditions
exactly as GitHub's runner would, simulating two scenarios (push to main
vs. push to a feature branch) to show which jobs would actually run in
each case.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.triggers import check_always_true_condition_1022, _is_always_true_condition


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  line {alert['line']}: {alert['description']}")


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))
    alerts = check_always_true_condition_1022(workflow, lines, lang='en')
    if not alerts:
        print('  No CFW findings.')
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)
    return workflow


def evaluate_clause(clause, context):
    """Evaluates a single "a.b.c == 'value'" comparison against the
    simulated context. Enough for this lesson's conditions; not a general
    GitHub Actions expression interpreter."""
    if '==' not in clause:
        return None
    left, right = (part.strip() for part in clause.split('==', 1))
    right = right.strip("'\"")
    actual = context.get(left)
    if actual is None:
        return None
    return actual == right


def evaluate_condition(condition, context):
    """Real, simplified evaluation of a GitHub Actions ${{ ... }}
    expression (only supports what appears in this lesson: ==, &&,
    github.*/vars.* refs), without using eval(). If the condition is
    NOT a valid expression per _is_always_true_condition, GitHub treats it
    as a truthy string: True -- the same criterion R1022 applies."""
    if condition is None:
        return True  # no "if:" at all, the job/step always runs
    if _is_always_true_condition(condition):
        return True  # same criterion as R1022: GitHub doesn't evaluate it, it's truthy

    expr = condition.strip()
    if expr.startswith('${{') and expr.endswith('}}'):
        expr = expr[3:-2].strip()

    results = [evaluate_clause(clause, context) for clause in expr.split('&&')]
    if any(r is None for r in results):
        return None  # couldn't evaluate with the simulated context
    return all(results)


def simulate_scenario(path, scenario_name, context):
    print(f'\n--- Scenario: {scenario_name} ({path.name}) ---')
    workflow, _ = parse_workflow(str(path))

    for job_name, job in workflow.get('jobs', {}).items():
        job_if = job.get('if')
        runs = evaluate_condition(job_if, context)
        print(f'  job "{job_name}"  if: {job_if!r}  -> {"RUNS" if runs else "skipped"}')

        if runs:
            for step in job.get('steps', []):
                step_if = step.get('if')
                step_name = step.get('name', step.get('uses', step.get('run', '')[:30]))
                step_runs = evaluate_condition(step_if, context)
                print(f'    step "{step_name}"  if: {step_if!r}  -> {"RUNS" if step_runs else "skipped"}')


def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')

    context_main = {
        "github.ref": 'refs/heads/main', "github.actor": 'trusted-bot',
        "vars.DEPLOY_ENABLED": 'true',
    }
    context_feature_branch = {
        "github.ref": 'refs/heads/feature/random-contributor-branch',
        "github.actor": 'random-external-contributor',
        "vars.DEPLOY_ENABLED": 'false',
    }

    print('\n=== Real-execution simulation ===')
    simulate_scenario(base / 'vulnerable.yml', 'push to an external feature branch', context_feature_branch)
    simulate_scenario(base / 'fixed.yml', 'push to an external feature branch', context_feature_branch)


if __name__ == '__main__':
    sys.exit(main())
