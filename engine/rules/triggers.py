from engine.create_alert import create_alert
from engine.parser import find_line


# Detects workflows triggered by pull_request_target.

def check_pull_request_target_1000(workflow, lines, lang='es'):
    alerts = []

    triggers = workflow.get('on', {})

    if isinstance(triggers, dict) and 'pull_request_target' in triggers:
        line = find_line(lines, 'pull_request_target')
        alerts.append(create_alert(
            rule_id='R1000',
            category='CICD-SEC-4',
            severity='HIGH',
            line=line,
            lang=lang,
        ))

    return alerts


PR_HEAD_REFERENCES = [
    'github.event.pull_request.head',
    'github.head_ref',
]


def check_checkout_without_ref_1001(workflow, lines, lang='es'):
    alerts = []

    triggers = workflow.get('on', {})

    if not (isinstance(triggers, dict) and 'pull_request_target' in triggers):
        return alerts

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
            if 'actions/checkout' not in uses:
                continue

            with_params = step.get('with', {})
            if not isinstance(with_params, dict):
                continue
            ref = with_params.get('ref', '')

            if isinstance(ref, str) and any(pattern in ref for pattern in PR_HEAD_REFERENCES):
                line = find_line(lines, uses)
                alerts.append(create_alert(
                    rule_id='R1001',
                    category='CICD-SEC-4',
                    severity='CRITICAL',
                    line=line,
                    lang=lang,
                    ref=ref,
                ))

    return alerts


def check_pull_request_without_branch_restriction_1013(workflow, lines, lang='es'):
    alerts = []

    triggers = workflow.get('on', {})

    if not isinstance(triggers, dict):
        return alerts

    if 'pull_request' not in triggers:
        return alerts

    pull_request_config = triggers.get('pull_request', {})

    if pull_request_config is None or not isinstance(pull_request_config, dict):
        line = find_line(lines, 'pull_request')
        alerts.append(create_alert(
            rule_id='R1013',
            category='CICD-SEC-1',
            severity='LOW',
            line=line,
            lang=lang,
        ))
        return alerts

    if 'branches' not in pull_request_config and 'branches-ignore' not in pull_request_config:
        line = find_line(lines, 'pull_request')
        alerts.append(create_alert(
            rule_id='R1013',
            category='CICD-SEC-1',
            severity='LOW',
            line=line,
            lang=lang,
        ))

    return alerts


DANGEROUS_EXPRESSIONS = [
    'github.event.pull_request.title',
    'github.event.pull_request.body',
    'github.event.pull_request.head.ref',
    'github.event.pull_request.head.label',
    'github.event.issue.title',
    'github.event.issue.body',
    'github.event.comment.body',
    'github.event.review.body',
    'github.head_ref',
    'github.event.inputs',
    'steps.',
    'needs.',
]


def check_expression_injection_1016(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            run = step.get('run', '')
            if not run:
                continue

            for expression in DANGEROUS_EXPRESSIONS:
                if expression in run:
                    line = find_line(lines, expression)
                    alerts.append(create_alert(
                        rule_id='R1016',
                        category='CICD-SEC-4',
                        severity='CRITICAL',
                        line=line,
                        lang=lang,
                        expression=expression,
                    ))

    return alerts


def check_toctou_pattern_1021(workflow, lines, lang='es'):
    alerts = []

    triggers = workflow.get('on', {})

    if not isinstance(triggers, dict):
        return alerts

    if 'pull_request_target' not in triggers:
        return alerts

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            run = step.get('run', '')
            if not run:
                continue

            if 'gh pr checkout' in run:
                checkout_by_number = (
                    'github.event.pull_request.number' in run or
                    'github.event.number' in run
                )

                if checkout_by_number:
                    line = find_line(lines, 'gh pr checkout')
                    alerts.append(create_alert(
                        rule_id='R1021',
                        category='CICD-SEC-4',
                        severity='CRITICAL',
                        line=line,
                        lang=lang,
                    ))

    return alerts


def _is_always_true_condition(condition):
    if not isinstance(condition, str):
        return False
    if '${{' not in condition:
        return False

    stripped = condition.strip()
    if not stripped.startswith('${{'):
        return True
    if not stripped.endswith('}}'):
        return True
    if condition.count('${{') > 1:
        return True

    return False


def _find_condition_line(lines, condition):
    snippet = str(condition).strip()[:30]
    line = find_line(lines, snippet) if snippet else 0
    if line == 0:
        line = find_line(lines, 'if:')
    return line


def check_always_true_condition_1022(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue

        job_condition = job.get('if')
        if _is_always_true_condition(job_condition):
            line = _find_condition_line(lines, job_condition)
            alerts.append(create_alert(
                rule_id='R1022_JOB',
                category='CICD-SEC-1',
                severity='HIGH',
                line=line,
                lang=lang,
                job_name=job_name,
            ))

        steps = job.get('steps', [])
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            step_condition = step.get('if')
            if _is_always_true_condition(step_condition):
                line = _find_condition_line(lines, step_condition)
                alerts.append(create_alert(
                    rule_id='R1022_STEP',
                    category='CICD-SEC-1',
                    severity='HIGH',
                    line=line,
                    lang=lang,
                    job_name=job_name,
                ))

    return alerts
