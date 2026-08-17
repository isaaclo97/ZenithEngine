from engine.create_alert import create_alert
from engine.parser import find_line

PUBLISH_ACTIONS = [
    'docker/build-push-action',
    'docker/push',
    'goreleaser/goreleaser-action',
    'pypa/gh-action-pypi-publish',
    'softprops/action-gh-release',
]

def job_has_cosign(steps):
    for step in steps:
        uses = step.get('uses', '')
        run = step.get('run', '')
        if 'cosign' in uses or 'cosign' in run:
            return True
    return False

def check_missing_artifact_verification_1010(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        steps = job.get('steps', [])

        for step in steps:
            uses = step.get('uses', '')
            run = step.get('run', '')

            publishes_artifact = any(
                action in uses for action in PUBLISH_ACTIONS
            ) or 'docker push' in run

            if publishes_artifact:
                if not job_has_cosign(steps):
                    line = find_line(lines, uses if uses else 'docker push')
                    alerts.append(create_alert(
                        rule_id='R1010',
                        category='CICD-SEC-9',
                        severity='MEDIUM',
                        line=line,
                        lang=lang,
                        job_name=job_name,
                    ))
                break

    return alerts
