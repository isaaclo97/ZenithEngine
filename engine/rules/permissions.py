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


def check_third_party_action_with_token_1011(workflow, lines, lang='es'):
    alerts = []
    organizations = load_verified_organizations()

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            uses = step.get('uses', '')
            if not uses or uses.startswith('./'):
                continue
            if '/' not in uses:
                continue

            organization = uses.split('/')[0]
            if organization in organizations:
                continue

            env = step.get('env', {})
            with_params = step.get('with', {})

            has_token = any(
                'GITHUB_TOKEN' in str(v) or
                'secrets.GITHUB_TOKEN' in str(v)
                for v in list(env.values()) + list(with_params.values())
            )

            if has_token:
                line = find_line(lines, uses)
                alerts.append(create_alert(
                    rule_id='R1011',
                    category='CICD-SEC-8',
                    severity='HIGH',
                    line=line,
                    lang=lang,
                    uses=uses,
                ))

    return alerts
