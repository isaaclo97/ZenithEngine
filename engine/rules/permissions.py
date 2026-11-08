import os
from engine.create_alert import create_alert
from engine.parser import find_line


def check_missing_permissions_1003(workflow, lines, lang='es'):
    alerts = []

    global_permissions = workflow.get('permissions', None)

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        job_permissions = job.get('permissions', None)

        if global_permissions is None and job_permissions is None:
            line = find_line(lines, job_name)
            if line == 0:
                continue
            alerts.append(create_alert(
                rule_id='R1003',
                category='CICD-SEC-5',
                severity='MEDIUM',
                line=line,
                lang=lang,
                job_name=job_name,
            ))

    return alerts


def load_verified_organizations():
    path = os.path.join(os.path.dirname(__file__), '..', 'verified_organizations.txt')
    with open(path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]


def _effective_permissions(workflow, job):
    """The `permissions` that apply to a job: its own block replaces the
    workflow's entirely. None when neither level declares one."""
    if isinstance(job, dict) and 'permissions' in job:
        return job['permissions']
    return workflow.get('permissions', None)


def _grants_write(permissions):
    """True if the block explicitly gives GITHUB_TOKEN any write scope
    (`write-all` or some `<scope>: write`)."""
    if isinstance(permissions, str):
        return permissions.strip().lower() == 'write-all'
    if isinstance(permissions, dict):
        return any(str(v).strip().lower() == 'write' for v in permissions.values())
    return False


def check_third_party_action_with_token_1011(workflow, lines, lang='es'):
    """A third-party action runs in a job whose GITHUB_TOKEN can write.

    Every action receives the token whether or not the workflow passes it:
    an input can default to `${{ github.token }}` (setup-graalvm, checkout and
    many others do). Passing `secrets.GITHUB_TOKEN` explicitly therefore adds
    no exposure, and omitting it removes none; what limits the damage of a
    compromised action is the token's scope. Jobs without any `permissions`
    block are left to R1003; read-only jobs are not reported.
    """
    alerts = []
    organizations = load_verified_organizations()

    jobs = workflow.get('jobs', {})
    if not isinstance(jobs, dict):
        return alerts
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        if not _grants_write(_effective_permissions(workflow, job)):
            continue

        job_line = find_line(lines, f'{job_name}:')
        steps = job.get('steps', []) or []
        cursor = job_line
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get('uses', '')
            if not isinstance(uses, str) or not uses or uses.startswith('./'):
                continue
            if uses.startswith('docker://') or '/' not in uses:
                continue

            organization = uses.split('/')[0]
            if organization in organizations:
                continue

            line = find_line(lines, uses, after=cursor) or find_line(lines, uses)
            cursor = max(cursor, line)
            alerts.append(create_alert(
                rule_id='R1011',
                category='CICD-SEC-8',
                severity='HIGH',
                line=line,
                lang=lang,
                uses=uses,
                job_name=job_name,
            ))

    return alerts
