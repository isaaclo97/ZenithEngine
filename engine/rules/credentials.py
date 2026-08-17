import re
from engine.create_alert import create_alert
from engine.parser import find_line

SENSITIVE_KEYS = [
    'password',
    'token',
    'secret',
    'api_key',
    'access_key',
    'private_key',
    'auth',
    'credential',
    'passwd'
]
'''
# Note: the generic word "key"  matched actions/cache parameters like "key:"/"restore-keys:", which are cache
keys, not credentials, causing a large number of false positives. 
The more specific compounds that do contain "key" (api_key, access_key, private_key) are kept.
'''

GITHUB_EXPRESSION = re.compile(r'^\$\{\{.*\}\}$')
# A line like "NAME=${{ secrets.X }}", the format used by
# docker/build-push-action and docker/bake-action for their multiline
# "secrets:"/"build-args:" parameters.
KEY_VALUE_EXPRESSION_LINE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]*\s*=\s*\$\{\{.*\}\}$')

# Words that contain a SENSITIVE_KEYS substring but aren't credentials
# (e.g. "author"/"authored" contain "auth"): explicitly excluded.
KEY_EXCEPTIONS = ['author']


def is_hardcoded_value(value):
    if not isinstance(value, str):
        return False

    value = value.strip()
    if not value:
        return False  # empty string: nothing to expose

    if GITHUB_EXPRESSION.match(value):
        return False

    # Multiline block where every line is NAME=${{ expression }} (e.g. the
    # "secrets:" parameter of docker/build-push-action): the real value
    # comes from a GitHub Actions secret, it isn't hardcoded, even though
    # the whole block isn't a single ${{ ... }} expression.
    value_lines = [l.strip() for l in value.splitlines() if l.strip()]
    if value_lines and all(KEY_VALUE_EXPRESSION_LINE.match(l) for l in value_lines):
        return False

    return True


def check_hardcoded_credential_1014(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            for field in ['env', 'with']:
                params = step.get(field, {})
                if not isinstance(params, dict):
                    continue
                for key, value in params.items():
                    key_lower = key.lower()
                    if any(exception in key_lower for exception in KEY_EXCEPTIONS):
                        continue
                    if any(sensitive in key_lower for sensitive in SENSITIVE_KEYS):
                        if is_hardcoded_value(value):
                            line = find_line(lines, key)
                            alerts.append(create_alert(
                                rule_id='R1014',
                                category='CICD-SEC-6',
                                severity='CRITICAL',
                                line=line,
                                lang=lang,
                                key=key,
                            ))

    return alerts


EXTRACTION_PATTERN = re.compile(
    r'(\w+)\s*=\s*\$\(.*\$\{?\{?\s*secrets\.'
)

PRINT_COMMANDS = [
    'echo ',
    'print(',
    'printf ',
    'cat ',
    'logger ',
]

def check_secret_in_logs_1019(workflow, lines, lang='es'):
    alerts = []

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        steps = job.get('steps', [])
        for step in steps:
            run = step.get('run', '')
            env = step.get('env', {})
            if not run:
                continue

            secret_variables = set()
            for var_name, value in env.items():
                if isinstance(value, str) and 'secrets.' in value:
                    secret_variables.add(var_name)

            derived_variables = set()
            for run_line in run.splitlines():
                match = EXTRACTION_PATTERN.search(run_line)
                if match:
                    derived_variables.add(match.group(1))
                for var in secret_variables:
                    if var in run_line and '=' in run_line:
                        right_side = run_line.split('=', 1)[1]
                        if var in right_side:
                            new_var = run_line.split('=')[0].strip().lstrip('$').strip()
                            if new_var:
                                derived_variables.add(new_var)

            variables_to_check = secret_variables | derived_variables
            if not variables_to_check:
                continue

            for run_line in run.splitlines():
                for variable in variables_to_check:
                    # Require the variable to appear as a real shell
                    # interpolation ($VAR, ${VAR}, "$VAR"...), not just a
                    # textual mention of its name (e.g. an
                    # echo "FOO_TOKEN secret is configured" doesn't
                    # interpolate $FOO_TOKEN).
                    interpolation_pattern = re.compile(r'\$\{?' + re.escape(variable) + r'\b\}?')
                    if not interpolation_pattern.search(run_line):
                        continue
                    for command in PRINT_COMMANDS:
                        if command in run_line and variable in run_line:
                            # Skip assignment lines
                            if '=' in run_line and run_line.strip().startswith(variable):
                                continue
                            # Skip commands inside a $() subshell
                            if f'$({command.strip()}' in run_line or f'$( {command.strip()}' in run_line:
                                continue
                            line = find_line(lines, run_line.strip()[:30])
                            alerts.append(create_alert(
                                rule_id='R1019',
                                category='CICD-SEC-6',
                                severity='CRITICAL',
                                line=line,
                                lang=lang,
                                variable=variable,
                            ))

    return alerts
