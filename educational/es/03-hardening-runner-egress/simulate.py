#!/usr/bin/env python3
"""
Ejecuta la regla REAL de Zenith Engine (R1004, en engine/rules/network.py)
sobre vulnerable.yml y fixed.yml, y ademas simula el efecto real de una
politica de egress: dada una lista de conexiones salientes que el job
intenta abrir durante la ejecucion (algunas legitimas, una de exfiltracion),
muestra que habria pasado con cada configuracion de harden-runner.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.network import check_egress_policy_1004

# Conexiones que el job intentaria abrir durante una ejecucion real,
# incluyendo una simulacion de exfiltracion de datos por parte de una
# dependencia comprometida (ver leccion 01).
SIMULATED_CONNECTIONS = [
    ('github.com:443', 'checkout del repositorio'),
    ('api.github.com:443', 'llamadas a la API de GitHub Actions'),
    ('registry.npmjs.org:443', 'npm ci / npm publish'),
    ('attacker-exfil.example.com:443', 'ATAQUE: dependencia comprometida enviando NPM_TOKEN'),
]


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  línea {alert['line']}: {alert['description']}")


def harden_runner_config(job):
    for step in job.get('steps', []):
        if 'step-security/harden-runner' in step.get('uses', ''):
            with_params = step.get('with', {}) or {}
            policy = with_params.get('egress-policy')
            allowed = set((with_params.get('allowed-endpoints', '') or '').split())
            return policy, allowed
    return None, set()


def report_and_simulate(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))

    alerts = check_egress_policy_1004(workflow, lines, lang='es')
    if alerts:
        for alert in sorted(alerts, key=lambda a: a['line']):
            print_alert(alert)
    else:
        print('  Sin hallazgos HGW.')

    for job_name, job in workflow.get('jobs', {}).items():
        policy, allowed = harden_runner_config(job)
        print(f'\n  Simulación de tráfico saliente real del job "{job_name}" (política: {policy or "sin harden-runner"}):')
        for endpoint, description in SIMULATED_CONNECTIONS:
            blocked = policy == 'block' and endpoint not in allowed
            outcome = 'BLOQUEADA ✋' if blocked else 'permitida (pasa)'
            marker = '  [!] ' if 'ATAQUE' in description else '      '
            print(f'{marker}{endpoint:32s} {outcome:20s}  {description}')


def main():
    base = Path(__file__).parent
    report_and_simulate(base / 'vulnerable.yml')
    report_and_simulate(base / 'fixed.yml')


if __name__ == '__main__':
    sys.exit(main())
