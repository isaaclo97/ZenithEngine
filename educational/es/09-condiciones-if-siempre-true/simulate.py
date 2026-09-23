#!/usr/bin/env python3
"""
Ejecuta la regla REAL de Zenith Engine R1022 (engine/rules/triggers.py)
sobre vulnerable.yml y fixed.yml, y ademas evalua las condiciones "if:"
tal y como lo haria el runner de GitHub, simulando dos escenarios
(push a main vs. push a una rama de feature) para mostrar que jobs
se ejecutarian de verdad en cada caso.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.triggers import check_always_true_condition_1022, _is_always_true_condition


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  línea {alert['line']}: {alert['description']}")


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))
    alerts = check_always_true_condition_1022(workflow, lines, lang='es')
    if not alerts:
        print('  Sin hallazgos CFW.')
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)
    return workflow


def evaluate_clause(clause, context):
    """Evalúa una única comparación "a.b.c == 'valor'" contra el contexto
    simulado. Suficiente para las condiciones de esta lección; no es un
    intérprete general de expresiones de GitHub Actions."""
    if '==' not in clause:
        return None
    left, right = (part.strip() for part in clause.split('==', 1))
    right = right.strip("'\"")
    actual = context.get(left)
    if actual is None:
        return None
    return actual == right


def evaluate_condition(condition, context):
    """Evaluación real y simplificada de una expresión ${{ ... }} de GitHub
    Actions (solo soporta lo que aparece en esta lección: ==, &&, refs de
    github.*/vars.*), sin usar eval(). Si la condición NO es una
    expresión válida según _is_always_true_condition, GitHub la trata como
    string truthy: True, con el mismo criterio que aplica R1022."""
    if condition is None:
        return True  # sin "if:", el job/step siempre se ejecuta
    if _is_always_true_condition(condition):
        return True  # mismo criterio que R1022: GitHub no la evalúa, es truthy

    expr = condition.strip()
    if expr.startswith('${{') and expr.endswith('}}'):
        expr = expr[3:-2].strip()

    results = [evaluate_clause(clause, context) for clause in expr.split('&&')]
    if any(r is None for r in results):
        return None  # no se pudo evaluar con el contexto simulado
    return all(results)


def simulate_scenario(path, scenario_name, context):
    print(f'\n--- Escenario: {scenario_name} ({path.name}) ---')
    workflow, _ = parse_workflow(str(path))

    for job_name, job in workflow.get('jobs', {}).items():
        job_if = job.get('if')
        runs = evaluate_condition(job_if, context)
        print(f'  job "{job_name}"  if: {job_if!r}  -> {"SE EJECUTA" if runs else "se salta"}')

        if runs:
            for step in job.get('steps', []):
                step_if = step.get('if')
                step_name = step.get('name', step.get('uses', step.get('run', '')[:30]))
                step_runs = evaluate_condition(step_if, context)
                print(f'    step "{step_name}"  if: {step_if!r}  -> {"SE EJECUTA" if step_runs else "se salta"}')


def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')

    context_main = {
        "github.ref": 'refs/heads/main', "github.actor": 'trusted-bot',
        "vars.DEPLOY_ENABLED": 'true',
    }
    context_feature_branch = {
        "github.ref": 'refs/heads/feature/random-contributor-branch',
        "github.actor": 'random-external-contributor',
        "vars.DEPLOY_ENABLED": 'false',
    }

    print('\n=== Simulación de ejecución real ===')
    simulate_scenario(base / 'vulnerable.yml', 'push a una rama de feature externa', context_feature_branch)
    simulate_scenario(base / 'fixed.yml', 'push a una rama de feature externa', context_feature_branch)


if __name__ == '__main__':
    sys.exit(main())
