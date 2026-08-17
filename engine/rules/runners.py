from engine.create_alert import create_alert
from engine.parser import find_line

def check_runs_on_self_hosted_1006(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        runs_on = job.get('runs-on', '')

        if isinstance(runs_on, list):
            is_self_hosted = 'self-hosted' in runs_on
        else:
            is_self_hosted = 'self-hosted' in str(runs_on)

        if is_self_hosted:
            line = find_line(lines, 'self-hosted')
            alerts.append(create_alert(
                rule_id='R1006',
                category='CICD-SEC-7',
                severity='MEDIUM',
                line=line,
                lang=lang,
                job_name=job_name,
            ))

    return alerts


CLOUD_LABELS = [
    'ec2',
    'aws',
    'azure',
    'gcp',
    'cloud',
    'vm',
    'instance'
]

def check_runner_ec2_without_hardening_1020(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        runs_on = job.get('runs-on', '')

        if isinstance(runs_on, list):
            labels = [str(e).lower() for e in runs_on]
        else:
            labels = [str(runs_on).lower()]

        if 'self-hosted' not in labels:
            continue

        found_cloud_labels = [
            label for label in labels
            if any(cloud in label for cloud in CLOUD_LABELS)
        ]

        if not found_cloud_labels:
            continue

        has_harden_runner = False
        steps = job.get('steps', [])
        for step in steps:
            if 'step-security/harden-runner' in step.get('uses', ''):
                has_harden_runner = True
                break

        if not has_harden_runner:
            line = find_line(lines, 'runs-on')
            alerts.append(create_alert(
                rule_id='R1020',
                category='CICD-SEC-7',
                severity='CRITICAL',
                line=line,
                lang=lang,
                job_name=job_name,
                cloud_labels=', '.join(found_cloud_labels),
            ))

    return alerts


KNOWN_RUNNER_LABELS = {
    'ubuntu-latest', 'ubuntu-24.04', 'ubuntu-24.04-arm', 'ubuntu-22.04', 'ubuntu-22.04-arm',
    'ubuntu-20.04',
    'windows-latest', 'windows-2025', 'windows-2022', 'windows-2019', 'windows-11-arm',
    'macos-latest', 'macos-15', 'macos-14', 'macos-13', 'macos-12', 'macos-11',
    'macos-latest-xl', 'macos-14-xlarge', 'macos-latest-large',
    'self-hosted', 'linux', 'macos', 'windows', 'x64', 'arm', 'arm64',
}


def check_unknown_runner_label_1024(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue

        if 'runs-on' not in job:
            # Jobs that call a reusable workflow (jobs.<id>.uses: ...) don't
            # declare runs-on: the runner is decided by the called workflow,
            # not this file.
            continue

        runs_on = job.get('runs-on', '')

        if isinstance(runs_on, list):
            labels = runs_on
        elif isinstance(runs_on, str) and runs_on:
            labels = [runs_on]
        else:
            continue

        if any('self-hosted' in str(e).lower() for e in labels):
            # Custom self-hosted labels can't be verified statically without
            # access to the repository/organization's runner configuration.
            continue

        for label in labels:
            label_str = str(label)
            if '${{' in label_str:
                continue  # dynamic label (e.g. matrix.os), not statically verifiable

            if label_str.lower() not in KNOWN_RUNNER_LABELS:
                line = find_line(lines, label_str)
                alerts.append(create_alert(
                    rule_id='R1024',
                    category='CICD-SEC-7',
                    severity='LOW',
                    line=line,
                    lang=lang,
                    job_name=job_name,
                    label=label_str,
                ))

    return alerts
