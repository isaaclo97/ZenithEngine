import os
import re
from engine.create_alert import create_alert
from engine.parser import find_line


def check_egress_policy_1004(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        harden_runner_found = False
        steps = job.get('steps', [])
        for step in steps:
            uses = step.get('uses', '')
            if 'step-security/harden-runner' in uses:
                harden_runner_found = True
                with_params = step.get('with', {})
                egress_policy = with_params.get('egress-policy', None)
                if egress_policy == 'audit':
                    line = find_line(lines, 'egress-policy')
                    alerts.append(create_alert(
                        rule_id='R1004_AUDIT',
                        category='CICD-SEC-10',
                        severity='MEDIUM',
                        line=line,
                        lang=lang,
                    ))

        if not harden_runner_found:
            line = find_line(lines, job_name)
            if line == 0:
                continue
            alerts.append(create_alert(
                rule_id='R1004_MISSING',
                category='CICD-SEC-10',
                severity='LOW',
                line=line,
                lang=lang,
                job_name=job_name,
            ))

    return alerts


def load_fraudulent_domains():
    path = os.path.join(os.path.dirname(__file__), '..', 'fraudulent_domains.txt')
    with open(path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

NETWORK_COMMANDS = ['curl ', 'wget ', 'http://', 'https://']

def check_fraudulent_domain_1005(workflow, lines, lang='es'):
    alerts = []
    domains = load_fraudulent_domains()

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            run = step.get('run', '')
            if not run:
                continue

            for run_line in run.splitlines():
                if not any(cmd in run_line for cmd in NETWORK_COMMANDS):
                    continue
                for domain in domains:
                    if domain in run_line:
                        line = find_line(lines, domain)
                        alerts.append(create_alert(
                            rule_id='R1005',
                            category='CICD-SEC-10',
                            severity='CRITICAL',
                            line=line,
                            lang=lang,
                            domain=domain,
                        ))

    return alerts


IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

IGNORED_IPS = [
    '127.0.0.1',
    '0.0.0.0',
    '169.254.169.254'
]

def is_private_ip(ip):
    return (
        ip.startswith('192.168.') or
        ip.startswith('10.') or
        ip.startswith('172.16.') or
        ip.startswith('172.17.') or
        ip.startswith('172.18.') or
        ip.startswith('172.19.') or
        ip.startswith('172.2') or
        ip.startswith('172.30.') or
        ip.startswith('172.31.')
    )

def check_direct_ip_call_1009(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            run = step.get('run', '')
            if not run:
                continue

            found_ips = IP_PATTERN.findall(run)
            for ip in found_ips:
                if ip in IGNORED_IPS or is_private_ip(ip):
                    continue
                line = find_line(lines, ip)
                alerts.append(create_alert(
                    rule_id='R1009',
                    category='CICD-SEC-10',
                    severity='HIGH',
                    line=line,
                    lang=lang,
                    ip=ip,
                ))

    return alerts

SUSPICIOUS_LENGTH = 20

def check_dns_exfiltration_1015(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            run = step.get('run', '')
            if not run:
                continue

            run_lines = run.splitlines()
            for run_line in run_lines:
                if 'dig ' not in run_line and 'nslookup ' not in run_line:
                    continue

                parts = run_line.strip().split()
                for part in parts:
                    if '.' in part:
                        subdomain = part.split('.')[0]
                        if len(subdomain) >= SUSPICIOUS_LENGTH:
                            line = find_line(lines, subdomain[:20])
                            alerts.append(create_alert(
                                rule_id='R1015',
                                category='CICD-SEC-10',
                                severity='CRITICAL',
                                line=line,
                                lang=lang,
                                length=len(subdomain),
                            ))
                            break

    return alerts


GITHUB_API_PATTERN = re.compile(
    r'api\.github\.com/repos/([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)'
)

def check_github_api_exfiltration_1018(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            run = step.get('run', '')
            if not run:
                continue

            matches = GITHUB_API_PATTERN.findall(run)
            for repo in matches:
                if 'github.repository' in run:
                    continue

                line = find_line(lines, repo)
                alerts.append(create_alert(
                    rule_id='R1018',
                    category='CICD-SEC-10',
                    severity='HIGH',
                    line=line,
                    lang=lang,
                    repo=repo,
                ))

    return alerts
