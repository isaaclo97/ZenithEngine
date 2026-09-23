#!/usr/bin/env python3
"""
Draws the "trust map" of example.yml using Zenith Engine's real parser: which
events trigger it and who can cause them, which machine each job runs on, with
which permissions, what third-party code it runs and what data comes in from
outside. It's the way of looking at a workflow that every lesson uses.
"""
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.triggers import DANGEROUS_EXPRESSIONS

EVENTS = {
    'push': ('people with write access', 'yes'),
    'pull_request': ('ANYONE, from a fork', 'NOT from a fork (read-only token, no secrets)'),
    'pull_request_target': ('ANYONE, from a fork', 'YES: runs with the repository\'s privileges'),
    'issue_comment': ('ANYONE who can comment', 'yes'),
    'issues': ('ANYONE who can open issues', 'yes'),
    'workflow_dispatch': ('people with write access', 'yes'),
    'schedule': ('nobody: a clock starts it', 'yes'),
    'workflow_run': ('another workflow (which may have processed fork data)', 'yes'),
}
HASH = re.compile(r'^[0-9a-f]{40}$')
EXPRESSION = re.compile(r'\$\{\{\s*(.*?)\s*\}\}')


def describe_ref(ref):
    if HASH.match(ref):
        return 'commit hash (immutable)'
    if re.match(r'^v?\d+(\.\d+)*$', ref):
        return 'tag (mutable)'
    return 'branch or "latest" (changes with every commit)'


def describe_step(step):
    if 'run' in step:
        return '"run:" script written in this repository'
    uses = step.get('uses', '')
    if uses.startswith('./'):
        return 'local action from this repository'
    owner = uses.split('/')[0]
    action, _, ref = uses.partition('@')
    origin = 'official GitHub action' if owner in ('actions', 'github') else 'THIRD-PARTY action'
    return f'{origin}: {action}, pinned by {describe_ref(ref)}'


def format_permissions(permissions):
    if not permissions:
        return 'the repository DEFAULTS (no permissions: block)'
    if isinstance(permissions, dict):
        return ', '.join(f'{scope}: {level}' for scope, level in permissions.items())
    return str(permissions)


def classify_expression(expression):
    if expression.startswith('secrets.'):
        return 'SECRET'
    if any(dangerous in expression for dangerous in DANGEROUS_EXPRESSIONS):
        return 'UNTRUSTED DATA (written by whoever triggers the event)'
    return 'data controlled by GitHub or the repository'


def main():
    path = Path(__file__).parent / 'example.yml'
    workflow, _ = parse_workflow(str(path))

    print('=== 1. Events: who can start this workflow ===')
    for event in workflow.get('on', {}):
        who, secrets = EVENTS.get(event, ('(check the documentation)', '?'))
        print(f'  {event:20s} caused by: {who:45s} access to secrets: {secrets}')

    global_permissions = workflow.get('permissions')
    print('\n=== 2. Jobs: where they run and with which permissions ===')
    for name, job in workflow.get('jobs', {}).items():
        runner = job.get('runs-on')
        runner_kind = 'self-managed, persistent' if 'self-hosted' in str(runner) else 'GitHub-hosted, ephemeral'
        permissions = format_permissions(job.get('permissions') or global_permissions)
        needs = f', waits for: {job["needs"]}' if 'needs' in job else ''
        print(f'  job "{name}": runner {runner} ({runner_kind}){needs}')
        print(f'      GITHUB_TOKEN: {permissions}')
        for step in job.get('steps', []):
            print(f'      - {step.get("name", "(unnamed)")}: {describe_step(step)}')

    print('\n=== 3. ${{ }} expressions: what data comes into the workflow ===')
    text = path.read_text(encoding='utf-8')
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith('#'):
            continue
        for expression in EXPRESSION.findall(line):
            print(f'  line {number:3d}  {expression:40s} -> {classify_expression(expression)}')

    print('\nThis map answers, at a glance, the questions every lesson asks:')
    print('  who can trigger this?, with which privileges?, what foreign code runs?')
    print('  and what data I don\'t control reaches a script or a secret?')


if __name__ == '__main__':
    sys.exit(main())
