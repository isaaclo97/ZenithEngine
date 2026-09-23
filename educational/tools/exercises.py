"""Checker for the "Tu turno" / "Your turn" exercises.

Each lesson has an exercise workflow (ejercicio.yml / exercise.yml). The
student copies it (mi_solucion.yml / my_solution.yml), fixes it and runs:

    python3 ../comprobar.py            (es)
    python3 ../check.py                (en)

The checker runs the same real Zenith Engine rules the lesson uses, plus a
few sanity checks so the exercise can't be "solved" by deleting the
problematic step. With --all / --todas it runs every engine rule (offline).
With --online it also asks GitHub (git ls-remote) whether every pinned hash is
a published version, and the one named in its comment.
"""
import argparse
import re
import sys
import warnings
from pathlib import Path

# urllib3 v2 (pulled in by the engine through requests) warns on import when
# Python's ssl module is linked against an older SSL library. The checker
# never uses requests (--online goes through git), so it's only noise here.
warnings.filterwarnings('ignore', message='urllib3 v2 only supports OpenSSL')

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import engine.rules.vulnerabilities as vulnerabilities_rule  # noqa: E402
from engine import engine as zenith  # noqa: E402
from engine.parser import WorkflowParseError, find_line, parse_workflow  # noqa: E402
from engine.rules.actions import (  # noqa: E402
    check_action_without_hash_1002, check_branch_as_version_1012, check_latest_as_version_1017,
    check_outdated_action_runtime_1023, check_unverified_action_1007,
)
from engine.rules.artifacts import check_missing_artifact_verification_1010  # noqa: E402
from engine.rules.credentials import check_hardcoded_credential_1014, check_secret_in_logs_1019  # noqa: E402
from engine.rules.network import (  # noqa: E402
    check_direct_ip_call_1009, check_dns_exfiltration_1015, check_egress_policy_1004,
    check_fraudulent_domain_1005, check_github_api_exfiltration_1018,
)
from engine.rules.permissions import check_missing_permissions_1003, check_third_party_action_with_token_1011  # noqa: E402
from engine.rules.runners import (  # noqa: E402
    check_runner_ec2_without_hardening_1020, check_runs_on_self_hosted_1006, check_unknown_runner_label_1024,
)
from engine.rules.triggers import (  # noqa: E402
    DANGEROUS_EXPRESSIONS, check_always_true_condition_1022, check_checkout_without_ref_1001,
    check_expression_injection_1016, check_pull_request_target_1000, check_pull_request_without_branch_restriction_1013,
    check_toctou_pattern_1021,
)
from tools.typosquat import (  # noqa: E402
    PIN, POPULAR_ACTIONS, check_pins_online, check_risky_install_patterns, check_typosquatted_actions,
    check_typosquatted_packages,
)

# Offline and deterministic: R1025 uses the local CVE snapshot and R1008 a
# mock instead of calling the GitHub API.
vulnerabilities_rule.load_known_vulnerabilities = vulnerabilities_rule._load_local_snapshot

KNOWN_EXISTING_ACTIONS = {a.lower() for a in POPULAR_ACTIONS} | {
    'totally-random-dev/dockerfile-lint-action', 'some-org/stripe-config-action', 'some-org/slack-notify',
}

TEXT = {
    'es': {
        'r1008': 'No se encontró "{action}" entre las acciones conocidas (mock offline de R1008). ¿Errata? ¿Typosquatting?',
        'struct_on': 'Falta la clave "on:": el workflow no tiene ningún evento que lo dispare.',
        'struct_jobs': 'Falta "jobs:" o está vacío: no hay nada que ejecutar.',
        'struct_runs_on': 'El job "{job}" no tiene "runs-on:": GitHub no sabe en qué máquina ejecutarlo.',
        'struct_steps': 'El job "{job}" no tiene una lista "steps:".',
        'struct_step_kind': 'El step "{step}" del job "{job}" debe tener "uses:" o "run:" (uno de los dos, no ambos).',
        'struct_step_name': 'Un step del job "{job}" no tiene "name:". Ponle nombre para que el log se entienda.',
        'struct_uses_ref': 'La acción "{uses}" no indica versión: añade @<hash de commit> después del nombre.',
        'struct_needs': 'El job "{job}" depende de "{need}", que no existe.',
        'missing_step': 'Falta el step "{name}" del ejercicio original. Hay que corregirlo, no borrarlo.',
        'missing_if': 'El {where} ha perdido su "if:". La condición tiene que seguir existiendo, bien escrita.',
        'missing_expression': 'El workflow ya no usa "{expr}". El dato tiene que seguir llegando al script, pero de forma segura.',
        'missing_with_key': 'El step "{name}" ya no tiene el parámetro "{key}". Hay que protegerlo, no quitarlo.',
        'job': 'job "{job}"', 'step': 'step "{step}" del job "{job}"',
        'header': 'Lección {lesson} · comprobando {file}',
        'rules': 'Reglas que se comprueban: {rules}',
        'all_rules': 'Modo --todas: además se muestran (informativas) todas las reglas del motor.',
        'online': 'Modo --online: además se comprueba en GitHub que cada hash fijado es una versión publicada.',
        'extra_title': 'Reglas del resto del motor (informativas, van más allá de esta lección; NO cuentan para superarla):',
        'online_tip': 'Consejo: ejecuta también con --online para comprobar en GitHub que tus hashes existen y son la versión que dice el comentario.',
        'alerts_title': 'Hallazgos del motor:',
        'no_alerts': '  Ninguno.',
        'sanity_title': 'Comprobaciones de que el ejercicio se ha corregido, no borrado:',
        'sanity_ok': '  Todo en orden.',
        'pass': 'Resultado: SUPERADO. Buen trabajo.',
        'fail': 'Resultado: AÚN NO. Quedan {n} problema(s) por resolver.',
        'baseline': 'Estás comprobando el enunciado. Cópialo antes de editarlo:  cp {exercise} {solution}',
        'no_file': 'No encuentro "{file}". Ejecuta esto desde la carpeta de una lección, por ejemplo: cd 07-inyeccion-de-expresiones',
        'no_lesson': 'No sé a qué lección pertenece "{file}": la carpeta debe empezar por dos dígitos (01-..., 12-...).',
        'parse_error': 'El fichero no es un YAML válido de workflow: {error}',
        'no_exercise': 'No encuentro el enunciado "{file}" junto a tu solución, así que no puedo comprobar que no hayas borrado steps.',
    },
    'en': {
        'r1008': '"{action}" is not among the known actions (offline R1008 mock). A typo? Typosquatting?',
        'struct_on': 'The "on:" key is missing: nothing triggers this workflow.',
        'struct_jobs': '"jobs:" is missing or empty: there\'s nothing to run.',
        'struct_runs_on': 'Job "{job}" has no "runs-on:": GitHub doesn\'t know which machine to run it on.',
        'struct_steps': 'Job "{job}" has no "steps:" list.',
        'struct_step_kind': 'Step "{step}" in job "{job}" must have "uses:" or "run:" (one of them, not both).',
        'struct_step_name': 'A step in job "{job}" has no "name:". Name it so the log is readable.',
        'struct_uses_ref': 'The action "{uses}" has no version: add @<commit hash> after the name.',
        'struct_needs': 'Job "{job}" depends on "{need}", which doesn\'t exist.',
        'missing_step': 'The step "{name}" from the original exercise is gone. Fix it, don\'t delete it.',
        'missing_if': 'The {where} lost its "if:". The condition still has to exist, written correctly.',
        'missing_expression': 'The workflow no longer uses "{expr}". The data still has to reach the script, just safely.',
        'missing_with_key': 'Step "{name}" no longer has the "{key}" parameter. Protect it, don\'t remove it.',
        'job': 'job "{job}"', 'step': 'step "{step}" in job "{job}"',
        'header': 'Lesson {lesson} · checking {file}',
        'rules': 'Rules being checked: {rules}',
        'all_rules': '--all mode: every other engine rule is also shown (informational).',
        'online': '--online mode: it also checks on GitHub that every pinned hash is a published version.',
        'extra_title': 'Findings from the rest of the engine (informational, beyond this lesson; they do NOT count toward passing):',
        'online_tip': 'Tip: also run with --online to check on GitHub that your hashes exist and are the version their comment claims.',
        'alerts_title': 'Engine findings:',
        'no_alerts': '  None.',
        'sanity_title': 'Checks that the exercise was fixed, not deleted:',
        'sanity_ok': '  All good.',
        'pass': 'Result: PASSED. Nice work.',
        'fail': 'Result: NOT YET. {n} problem(s) left to solve.',
        'baseline': 'You\'re checking the exercise statement itself. Copy it before editing:  cp {exercise} {solution}',
        'no_file': 'Can\'t find "{file}". Run this from a lesson folder, for example: cd 07-expression-injection',
        'no_lesson': 'Can\'t tell which lesson "{file}" belongs to: the folder must start with two digits (01-..., 12-...).',
        'parse_error': 'The file isn\'t a valid workflow YAML: {error}',
        'no_exercise': 'Can\'t find the exercise statement "{file}" next to your solution, so I can\'t check that no steps were deleted.',
    },
}

FILES = {
    'es': {'exercise': 'ejercicio.yml', 'solution': 'mi_solucion.yml'},
    'en': {'exercise': 'exercise.yml', 'solution': 'my_solution.yml'},
}


def check_action_exists_mock_1008(workflow, lines, lang='es'):
    alerts = []
    for job in (workflow.get('jobs') or {}).values():
        for step in (job or {}).get('steps') or []:
            uses = step.get('uses', '') if isinstance(step, dict) else ''
            if not uses or uses.startswith('./') or '/' not in uses:
                continue
            action = '/'.join(uses.split('@')[0].split('/')[:2])
            if action.lower() not in KNOWN_EXISTING_ACTIONS:
                alerts.append({'rule_id': 'R1008', 'severity': 'LOW', 'line': find_line(lines, uses),
                               'description': TEXT[lang]['r1008'].format(action=action)})
    return alerts


def check_structure(workflow, lines, lang='es'):
    """Basic structure checks for lesson 00 (plus R1003 for permissions)."""
    t = TEXT[lang]
    alerts = []

    def add(key, text_to_find, **params):
        alerts.append({'rule_id': 'STRUCT', 'severity': 'HIGH', 'line': find_line(lines, text_to_find) if text_to_find else 0,
                       'description': t[key].format(**params)})

    if 'on' not in workflow:
        add('struct_on', 'name:')
    jobs = workflow.get('jobs')
    if not isinstance(jobs, dict) or not jobs:
        add('struct_jobs', 'jobs')
        return alerts
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            add('struct_steps', job_name, job=job_name)
            continue
        if 'uses' in job:
            continue  # reusable workflow call: no runs-on/steps here
        if not job.get('runs-on'):
            add('struct_runs_on', f'{job_name}:', job=job_name)
        needs = job.get('needs', [])
        for need in [needs] if isinstance(needs, str) else needs or []:
            if need not in jobs:
                add('struct_needs', 'needs', job=job_name, need=need)
        steps = job.get('steps')
        if not isinstance(steps, list) or not steps:
            add('struct_steps', f'{job_name}:', job=job_name)
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            label = step.get('name') or step.get('uses') or str(step.get('run', ''))[:30]
            if not step.get('name'):
                add('struct_step_name', label, job=job_name)
            if ('uses' in step) == ('run' in step):
                add('struct_step_kind', label, job=job_name, step=label)
            uses = step.get('uses', '')
            if uses and not uses.startswith(('./', 'docker://')) and '@' not in uses:
                add('struct_uses_ref', uses, uses=uses)
    return alerts + check_missing_permissions_1003(workflow, lines, lang)


LESSONS = {
    '00': {'rules': [check_structure], 'ids': 'STRUCT, R1003'},
    '01': {'rules': [check_action_without_hash_1002, check_branch_as_version_1012, check_latest_as_version_1017]},
    '02': {'rules': [check_missing_permissions_1003, check_third_party_action_with_token_1011], 'keep_with_keys': True},
    '03': {'rules': [check_egress_policy_1004]},
    '04': {'rules': [check_unverified_action_1007, check_action_exists_mock_1008, check_missing_artifact_verification_1010]},
    '05': {'rules': [check_outdated_action_runtime_1023, check_unknown_runner_label_1024]},
    '06': {'rules': [check_pull_request_target_1000, check_checkout_without_ref_1001, check_toctou_pattern_1021]},
    '07': {'rules': [check_expression_injection_1016], 'keep_expressions': True},
    '08': {'rules': [check_hardcoded_credential_1014, check_secret_in_logs_1019], 'keep_with_keys': True},
    '09': {'rules': [check_always_true_condition_1022], 'keep_ifs': True},
    '10': {'rules': [vulnerabilities_rule.check_known_vulnerable_component_1025]},
    '11': {'rules': [check_fraudulent_domain_1005, check_direct_ip_call_1009, check_dns_exfiltration_1015,
                     check_github_api_exfiltration_1018, check_runs_on_self_hosted_1006,
                     check_runner_ec2_without_hardening_1020, check_pull_request_without_branch_restriction_1013]},
    '12': {'rules': [check_typosquatted_actions, check_typosquatted_packages, check_risky_install_patterns,
                     check_action_without_hash_1002],
           'ids': 'TYPO-ACTION, TYPO-PACKAGE, DEP-CONFUSION, PIPE-TO-SHELL, NO-LOCKFILE, NO-HASHES, R1002'},
}


def all_rules():
    rules = [check_action_exists_mock_1008 if r is zenith.check_action_not_in_marketplace_1008 else r
             for r in zenith.RULES]
    return rules + [check_typosquatted_actions, check_typosquatted_packages, check_risky_install_patterns]


def rule_ids(rules):
    return ', '.join('R' + re.search(r'_(\d{4})$', r.__name__).group(1) for r in rules)


def run_rules(rules, workflow, lines, lang):
    alerts, seen = [], set()
    for rule in rules:
        for alert in rule(workflow, lines, lang):
            key = (alert['rule_id'], alert['line'], alert['description'])
            if key not in seen:
                seen.add(key)
                alerts.append(alert)
    return sorted(alerts, key=lambda a: (a['line'], a['rule_id']))


def _jobs(workflow):
    return {name: job for name, job in (workflow.get('jobs') or {}).items() if isinstance(job, dict)}


def _named_steps(workflow):
    return {step['name']: (job_name, step)
            for job_name, job in _jobs(workflow).items()
            for step in job.get('steps') or [] if isinstance(step, dict) and step.get('name')}


def sanity_checks(config, original, solution, lang):
    t = TEXT[lang]
    problems = []
    original_steps, solution_steps = _named_steps(original), _named_steps(solution)

    for name in original_steps:
        if name not in solution_steps:
            problems.append(t['missing_step'].format(name=name))

    if config.get('keep_ifs'):
        solution_jobs = _jobs(solution)
        for job_name, job in _jobs(original).items():
            if 'if' in job and 'if' not in solution_jobs.get(job_name, {}):
                problems.append(t['missing_if'].format(where=t['job'].format(job=job_name)))
        for name, (job_name, step) in original_steps.items():
            if 'if' in step and name in solution_steps and 'if' not in solution_steps[name][1]:
                problems.append(t['missing_if'].format(where=t['step'].format(step=name, job=job_name)))

    if config.get('keep_expressions'):
        original_text, solution_text = str(original), str(solution)
        for expression in DANGEROUS_EXPRESSIONS:
            if expression.endswith('.'):
                continue  # "steps." / "needs." are prefixes, checked by their full use below
            if expression in original_text and expression not in solution_text:
                problems.append(t['missing_expression'].format(expr=expression))
        for full in sorted(set(re.findall(r'(?:steps|needs)\.[\w-]+\.outputs\.[\w-]+', original_text))):
            if full not in solution_text:
                problems.append(t['missing_expression'].format(expr=full))

    if config.get('keep_with_keys'):
        for name, (_, step) in original_steps.items():
            if name in solution_steps:
                solution_with = solution_steps[name][1].get('with') or {}
                for key in step.get('with') or {}:
                    if key not in solution_with:
                        problems.append(t['missing_with_key'].format(name=name, key=key))
    return problems


def check_file(path, lang='es', use_all_rules=False, out=print, online=False):
    """Returns the number of problems found (0 = exercise passed)."""
    t = TEXT[lang]
    path = Path(path)
    match = re.match(r'^(\d{2})-', path.resolve().parent.name)
    if not match:
        out(t['no_lesson'].format(file=path))
        return 1
    lesson = match.group(1)
    config = LESSONS[lesson]

    try:
        workflow, lines = parse_workflow(str(path))
    except (WorkflowParseError, OSError) as error:
        out(t['parse_error'].format(error=error))
        return 1

    lesson_rules = list(config['rules'])
    if online:
        lesson_rules.append(check_pins_online)
    out(t['header'].format(lesson=lesson, file=path.name))
    out(t['rules'].format(rules=config.get('ids') or rule_ids(config['rules'])))
    if online:
        out(t['online'])
    if use_all_rules:
        out(t['all_rules'])

    exercise_path = path.parent / FILES[lang]['exercise']
    if path.resolve() == exercise_path.resolve():
        out(t['baseline'].format(exercise=FILES[lang]['exercise'], solution=FILES[lang]['solution']))

    # Alerts that count toward pass/fail: only this lesson's rules (+ online).
    alerts = run_rules(lesson_rules, workflow, lines, lang)
    out('\n' + t['alerts_title'])
    for alert in alerts:
        out(f"  [{alert['severity']:8s}] {alert['rule_id']}  L{alert['line']}: {alert['description']}")
    if not alerts:
        out(t['no_alerts'])

    # --todas / --all: show every other engine rule as informational, not counted.
    if use_all_rules:
        counted = {(a['rule_id'], a['line'], a['description']) for a in alerts}
        extra = [a for a in run_rules(all_rules(), workflow, lines, lang)
                 if (a['rule_id'], a['line'], a['description']) not in counted]
        out('\n' + t['extra_title'])
        for alert in extra:
            out(f"  [{alert['severity']:8s}] {alert['rule_id']}  L{alert['line']}: {alert['description']}")
        if not extra:
            out(t['no_alerts'])

    problems = []
    if exercise_path.exists() and path.resolve() != exercise_path.resolve():
        original, _ = parse_workflow(str(exercise_path))
        problems = sanity_checks(config, original, workflow, lang)
        out('\n' + t['sanity_title'])
        for problem in problems:
            out(f'  - {problem}')
        if not problems:
            out(t['sanity_ok'])
    elif not exercise_path.exists():
        out('\n' + t['no_exercise'].format(file=exercise_path.name))

    total = len(alerts) + len(problems)
    out('\n' + (t['pass'] if total == 0 else t['fail'].format(n=total)))
    if total == 0 and not online and any(PIN.search(line) for line in lines):
        out(t['online_tip'])
    return total


def main(argv, lang):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('file', nargs='?', help=f"{FILES[lang]['solution']} / {FILES[lang]['exercise']}")
    parser.add_argument('--all', '--todas', dest='all_rules', action='store_true')
    parser.add_argument('--online', action='store_true')
    args = parser.parse_args(argv)

    path = args.file
    if path is None:
        solution = Path(FILES[lang]['solution'])
        path = solution if solution.exists() else Path(FILES[lang]['exercise'])
    if not Path(path).exists():
        print(TEXT[lang]['no_file'].format(file=path))
        return 2
    return 0 if check_file(path, lang, args.all_rules, online=args.online) == 0 else 1
