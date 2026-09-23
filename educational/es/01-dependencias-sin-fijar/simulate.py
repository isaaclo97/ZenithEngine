#!/usr/bin/env python3
"""
Ejecuta las reglas REALES de Zenith Engine (R1002 / R1012 / R1017, en
engine/rules/actions.py) sobre vulnerable.yml y fixed.yml -- no una
reimplementacion, sino el mismo codigo que usa la aplicacion Flask -- y
ademas simula por que un tag mutable es peligroso reproduciendo (con datos
ficticios) el patron real del compromiso de tj-actions/changed-files
(CVE-2025-30066): el mismo "@v35" resolviendo a commits distintos en dos
ejecuciones distintas del pipeline.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.actions import (
    check_action_without_hash_1002,
    check_branch_as_version_1012,
    check_latest_as_version_1017,
)


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  línea {alert['line']}: {alert['rule']}")
    print(f"             {alert['description']}")


def report(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))

    alerts = (
        check_action_without_hash_1002(workflow, lines, lang='es')
        + check_branch_as_version_1012(workflow, lines, lang='es')
        + check_latest_as_version_1017(workflow, lines, lang='es')
    )
    if not alerts:
        print('  Sin hallazgos UDW: todas las acciones están fijadas por hash de commit.')
        return
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)


def simulate_tag_hijack():
    print('\n=== Simulación: qué significa un tag mutable en la práctica ===')
    print('Escenario ficticio inspirado en CVE-2025-30066 (tj-actions/changed-files).')
    print('Tu workflow declara siempre la misma línea:')
    print('    uses: tj-actions/changed-files@v35\n')

    resoluciones = {
        '2025-03-10 09:00 UTC': 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e  (commit legítimo del mantenedor)',
        '2025-03-14 22:41 UTC': '9f8e7d6c5b4a30201f0e0d0c0b0a09080706050  (commit reescrito por el atacante)',
    }

    for moment, commit in resoluciones.items():
        print(f'  Ejecución del pipeline el {moment}:')
        print(f'    "@v35" se resuelve a -> {commit}')

    print('\n  El .yml del repositorio NO cambió entre las dos ejecuciones.')
    print('  El comportamiento del step sí, porque el tag es un puntero mutable,')
    print('  no un contenido inmutable. Con un hash de commit fijo, la segunda fila')
    print('  habría sido imposible: el hash del commit legítimo nunca "se convierte"')
    print('  en el hash del commit malicioso.')


def main():
    base = Path(__file__).parent
    report(base / 'vulnerable.yml')
    report(base / 'fixed.yml')
    simulate_tag_hijack()


if __name__ == '__main__':
    sys.exit(main())
