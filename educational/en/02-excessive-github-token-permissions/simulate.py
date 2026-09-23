#!/usr/bin/env python3
"""
Runs the REAL Zenith Engine rules (R1003 / R1011, in
engine/rules/permissions.py) against vulnerable.yml and fixed.yml, and also
builds the "effective" GITHUB_TOKEN permissions table for each job (the
same one you'd see on the "Permissions" tab of a real GitHub run) to show
concretely what a compromised third-party action could do with those
permissions.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.permissions import check_missing_permissions_1003, check_third_party_action_with_token_1011

# Default permissions GitHub grants the GITHUB_TOKEN when the repository
# hasn't been configured in "read-only by default" mode (the factory
# setting for repos created before 2023, and still the default in many
# organizations today).
DEFAULT_PERMISSIVE_TOKEN = {
    'actions': 'write', 'checks': 'write', 'contents': 'write',
    'deployments': 'write', 'issues': 'write', 'packages': 'write',
    'pull-requests': 'write', 'repository-projects': 'write',
    'security-events': 'write', 'statuses': 'write',
}

API_CAPABILITIES = {
    'contents': 'modify or delete repository files/branches',
    'pull-requests': 'comment on, label or close pull requests (and approve them if the organization allows it)',
    'packages': 'publish packages under the repository\'s name',
    'issues': 'create, close, or edit issues',
    'actions': 'cancel or re-trigger workflow runs, delete artifacts',
}


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  line {alert['line']}: {alert['description']}")


def effective_permissions(workflow):
    global_perms = workflow.get('permissions')
    table = {}
    for job_name, job in workflow.get('jobs', {}).items():
        job_perms = job.get('permissions')
        if job_perms is not None:
            table[job_name] = ('declared on the job', job_perms)
        elif global_perms is not None:
            table[job_name] = ('inherited from the workflow', global_perms)
        else:
            table[job_name] = ("REPOSITORY DEFAULT (no permissions: at any level)",
                                DEFAULT_PERMISSIVE_TOKEN)
    return table


def report(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))

    print('Effective GITHUB_TOKEN permissions per job:')
    perms_table = effective_permissions(workflow)
    for job_name, (source, perms) in perms_table.items():
        print(f'  job "{job_name}" -> source: {source}')
        for scope, level in perms.items():
            print(f'      {scope}: {level}')

    alerts = check_missing_permissions_1003(workflow, lines, lang='en') + check_third_party_action_with_token_1011(workflow, lines, lang='en')
    if not alerts:
        print('\nNo EPW findings.')
        return

    print('\nZenith Engine findings:')
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)

    if any(a['rule_id'] == 'R1011' for a in alerts):
        print('\nWhat a compromised third-party action could do with the current token, per job:')
        for job_name, (source, perms) in perms_table.items():
            writable = [s for s, lvl in perms.items() if lvl == 'write' and s in API_CAPABILITIES]
            if writable:
                print(f'  job "{job_name}":')
                for scope in writable:
                    print(f'    - {API_CAPABILITIES[scope]} (permission "{scope}: write")')


def main():
    base = Path(__file__).parent
    report(base / 'vulnerable.yml')
    report(base / 'fixed.yml')


if __name__ == '__main__':
    sys.exit(main())
