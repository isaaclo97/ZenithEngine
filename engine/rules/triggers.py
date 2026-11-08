import re

from engine.create_alert import create_alert
from engine.expressions import is_tautology, iter_expressions, normalize_expression, normalize_fragment
from engine.parser import find_line, find_position

EXPR_BLOCK = re.compile(r'\$\{\{(.*?)\}\}', re.S)


def normalized_triggers(workflow):
    """Return the `on:` triggers as a {name: config} dict. GitHub accepts a
    string ('push'), a list (['push', 'pull_request']) or a mapping, all meaning
    the same set of triggers; the string and list forms carry no per-trigger
    config, so their value is an empty dict."""
    triggers = workflow.get('on', {})
    if isinstance(triggers, str):
        return {triggers: {}}
    if isinstance(triggers, list):
        return {t: {} for t in triggers if isinstance(t, str)}
    if isinstance(triggers, dict):
        return triggers
    return {}


# Detects workflows triggered by pull_request_target.

def check_pull_request_target_1000(workflow, lines, lang='es'):
    alerts = []

    triggers = normalized_triggers(workflow)

    if 'pull_request_target' in triggers:
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
NORMALIZED_PR_HEAD = [normalize_fragment(r) for r in PR_HEAD_REFERENCES]


def check_checkout_without_ref_1001(workflow, lines, lang='es'):
    alerts = []

    triggers = normalized_triggers(workflow)

    if 'pull_request_target' not in triggers:
        return alerts
    # Steps are visited in file order: each checkout is looked up after the
    # previous one, so two identical `uses:` lines get their own line numbers.
    cursor = 0

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
            uses_line = find_line(lines, uses, cursor)
            if uses_line:
                cursor = uses_line

            with_params = step.get('with', {})
            if not isinstance(with_params, dict):
                continue
            ref = with_params.get('ref', '')

            if isinstance(ref, str) and any(norm in expr for expr in iter_expressions(ref)
                                            for norm in NORMALIZED_PR_HEAD):
                line = uses_line or find_line(lines, uses)
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

    triggers = normalized_triggers(workflow)

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


# Patterns are matched against the normalized form of each ${{ }} expression,
# so a dereference written with index syntax or different letter case is still
# caught (see engine/expressions.py).
NORMALIZED_DANGEROUS = [normalize_fragment(e) for e in DANGEROUS_EXPRESSIONS]


# A step's `run:` key with its value on the same line (`run: cmd`, `run: |`);
# `defaults: run:` has nothing after the colon and is skipped.
RUN_KEY = re.compile(r'^\s*(?:-\s+)?run:\s*\S')


def check_expression_injection_1016(workflow, lines, lang='es'):
    alerts = []
    # Steps are visited in file order, so each run: is looked up after the
    # previous one, and each of its expressions after the one before it.
    cursor = 0
    # One alert per (line, expression as GitHub resolves it), however it is written.
    reported = set()

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
            run = step.get('run', '')
            if not isinstance(run, str) or not run:
                continue

            run_line = next((i + 1 for i in range(cursor, len(lines)) if RUN_KEY.match(lines[i])), 0)
            if run_line:
                cursor = run_line
            expr_cursor = (max(run_line - 1, 0), 0)

            for raw_block in EXPR_BLOCK.finditer(run):
                # The expression's own line inside this run:; else the run: line.
                snippet = raw_block.group(0).splitlines()[0]
                position = find_position(lines, snippet, *expr_cursor)
                found = 0
                if position:
                    expr_cursor = position
                    found = position[0] + 1
                normalized = normalize_expression(raw_block.group(1))
                if not any(norm in normalized for norm in NORMALIZED_DANGEROUS):
                    continue
                line = found or run_line or find_line(lines, snippet) or find_line(lines, 'run:')
                if (line, normalized) in reported:
                    continue
                reported.add((line, normalized))
                alerts.append(create_alert(
                    rule_id='R1016',
                    category='CICD-SEC-4',
                    severity='CRITICAL',
                    line=line,
                    lang=lang,
                    expression=' '.join(raw_block.group(1).split()),
                ))

    return alerts


def check_toctou_pattern_1021(workflow, lines, lang='es'):
    alerts = []

    triggers = normalized_triggers(workflow)

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
    # A block scalar (if: > or if: |) keeps a trailing newline, so GitHub sees
    # "${{ ... }}\n": a template string, always truthy, even though the stripped
    # value looks like a single expression.
    if condition != stripped and (condition.endswith('\n') or condition.endswith(' ')):
        return True

    return False


def _always_true_rule(condition, base_id):
    """Alert id for an always-true `if:`, or None: `base_id` when the value is a
    template string (always truthy), `base_id + '_TAUTOLOGY'` when it is a single
    expression that holds whatever the contexts contain (`x || true`)."""
    if _is_always_true_condition(condition):
        return base_id
    if is_tautology(condition):
        return base_id + '_TAUTOLOGY'
    return None


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
        rule_id = _always_true_rule(job_condition, 'R1022_JOB')
        if rule_id:
            line = _find_condition_line(lines, job_condition)
            alerts.append(create_alert(
                rule_id=rule_id,
                category='CICD-SEC-1',
                severity='HIGH',
                line=line,
                lang=lang,
                job_name=job_name,
                condition=str(job_condition).strip(),
            ))

        steps = job.get('steps', [])
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            step_condition = step.get('if')
            rule_id = _always_true_rule(step_condition, 'R1022_STEP')
            if rule_id:
                line = _find_condition_line(lines, step_condition)
                alerts.append(create_alert(
                    rule_id=rule_id,
                    category='CICD-SEC-1',
                    severity='HIGH',
                    line=line,
                    lang=lang,
                    job_name=job_name,
                    condition=str(step_condition).strip(),
                ))

    return alerts
