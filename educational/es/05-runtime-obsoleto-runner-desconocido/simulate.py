#!/usr/bin/env python3
"""
Ejecuta las reglas REALES de Zenith Engine GRCW (R1023 / R1024) sobre
vulnerable.yml y fixed.yml -- la misma lista de acciones obsoletas
(engine/outdated_runtime_actions.txt) y la misma lista de etiquetas de
runner conocidas que usa la aplicación real.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.actions import check_outdated_action_runtime_1023
from engine.rules.runners import check_unknown_runner_label_1024


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  línea {alert['line']}: {alert['description']}")


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))

    alerts = check_outdated_action_runtime_1023(workflow, lines, lang='es') + check_unknown_runner_label_1024(workflow, lines, lang='es')
    if not alerts:
        print('  Sin hallazgos GRCW.')
        return
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)


def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')


if __name__ == '__main__':
    sys.exit(main())
