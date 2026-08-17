import os
import re
import requests
from engine.create_alert import create_alert
from engine.parser import find_line

HASH_PATTERN = re.compile(r'^[0-9a-f]{40}$')


def check_action_without_hash_1002(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            uses = step.get('uses', '')
            if '@' in uses:
                version = uses.split('@')[1]
                if not HASH_PATTERN.match(version):
                    line = find_line(lines, uses)
                    alerts.append(create_alert(
                        rule_id='R1002',
                        category='CICD-SEC-8',
                        severity='MEDIUM',
                        line=line,
                        lang=lang,
                        uses=uses,
                        action=uses.split('@')[0],
                    ))

    return alerts


def load_verified_organizations():
    path = os.path.join(os.path.dirname(__file__), '..', 'verified_organizations.txt')
    with open(path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]


def check_unverified_action_1007(workflow, lines, lang='es'):
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

            if organization not in organizations:
                line = find_line(lines, uses)
                alerts.append(create_alert(
                    rule_id='R1007',
                    category='CICD-SEC-8',
                    severity='MEDIUM',
                    line=line,
                    lang=lang,
                    uses=uses,
                    org=organization,
                ))

    return alerts

def check_action_not_in_marketplace_1008(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            uses = step.get('uses', '')
            if not uses or uses.startswith('./'):
                continue
            if '/' not in uses:
                continue

            action = uses.split('@')[0] if '@' in uses else uses

            try:
                url = f'https://api.github.com/repos/{action}/contents/action.yml'
                response = requests.get(url, timeout=5)

                if response.status_code == 404:
                    url_yaml = f'https://api.github.com/repos/{action}/contents/action.yaml'
                    response_yaml = requests.get(url_yaml, timeout=5)

                    if response_yaml.status_code == 404:
                        line = find_line(lines, uses)
                        alerts.append(create_alert(
                            rule_id='R1008',
                            category='CICD-SEC-8',
                            severity='LOW',
                            line=line,
                            lang=lang,
                            uses=uses,
                        ))
            except requests.exceptions.RequestException:
                pass

    return alerts


HASH_PATTERN = re.compile(r'^[0-9a-f]{40}$')
TAG_PATTERN = re.compile(r'^v?[0-9]+(\.[0-9]+)*$')


def check_branch_as_version_1012(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            uses = step.get('uses', '')
            if not uses or uses.startswith('./'):
                continue
            if '@' not in uses:
                continue

            version = uses.split('@')[1]

            is_hash = HASH_PATTERN.match(version)
            is_tag = TAG_PATTERN.match(version)
            is_latest = version == 'latest'

            if not is_hash and not is_tag and not is_latest:
                line = find_line(lines, uses)
                alerts.append(create_alert(
                    rule_id='R1012',
                    category='CICD-SEC-8',
                    severity='HIGH',
                    line=line,
                    lang=lang,
                    uses=uses,
                    version=version,
                    action=uses.split('@')[0],
                ))

    return alerts


def check_latest_as_version_1017(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            uses = step.get('uses', '')
            if not uses or uses.startswith('./'):
                continue
            if '@' not in uses:
                continue

            version = uses.split('@')[1]

            if version.lower() == 'latest':
                line = find_line(lines, uses)
                alerts.append(create_alert(
                    rule_id='R1017',
                    category='CICD-SEC-8',
                    severity='CRITICAL',
                    line=line,
                    lang=lang,
                    uses=uses,
                    action=uses.split('@')[0],
                ))

    return alerts


def load_outdated_runtime_actions():
    path = os.path.join(os.path.dirname(__file__), '..', 'outdated_runtime_actions.txt')
    with open(path, 'r', encoding='utf-8') as f:
        return {line.strip() for line in f if line.strip() and not line.startswith('#')}


def check_outdated_action_runtime_1023(workflow, lines, lang='es'):
    alerts = []
    outdated_actions = load_outdated_runtime_actions()

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get('steps', [])
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get('uses', '')
            if not uses or uses.startswith('./'):
                continue

            if uses in outdated_actions:
                line = find_line(lines, uses)
                alerts.append(create_alert(
                    rule_id='R1023',
                    category='CICD-SEC-8',
                    severity='MEDIUM',
                    line=line,
                    lang=lang,
                    uses=uses,
                    action=uses.split('@')[0],
                ))

    return alerts
