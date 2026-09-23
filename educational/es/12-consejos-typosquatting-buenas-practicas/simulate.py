#!/usr/bin/env python3
"""
Busca typosquatting y prácticas de instalación arriesgadas en vulnerable.yml
y fixed.yml con el detector educativo de educational/tools/typosquat.py (no es
una regla de Zenith Engine), explica cómo razona y, con --online, comprueba
contra GitHub que cada hash fijado corresponde de verdad a la versión de su
comentario.

    python3 simulate.py            # sin red
    python3 simulate.py --online   # además consulta GitHub con git ls-remote
"""
import sys
from pathlib import Path

EDUCATIONAL = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(EDUCATIONAL.parent))
sys.path.insert(0, str(EDUCATIONAL))

from engine.parser import parse_workflow
from engine.rules.actions import check_action_without_hash_1002
from tools.typosquat import (
    check_risky_install_patterns, check_typosquatted_actions, check_typosquatted_packages,
    levenshtein, verify_pins_online,
)

EXAMPLES = [
    ('actons/checkout', 'actions/checkout', 'falta una letra'),
    ('actions/setup-pyhton', 'actions/setup-python', 'dos letras cambiadas de sitio'),
    ('crossenv', 'cross-env', 'sin el guion; caso real en npm, 2017'),
    ('jeIlyfish', 'jellyfish', 'I mayúscula en lugar de l; caso real en PyPI, 2019'),
]


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']:13s} línea {alert['line']}: {alert['description']}")


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))
    alerts = (
        check_typosquatted_actions(workflow, lines, 'es')
        + check_typosquatted_packages(workflow, lines, 'es')
        + check_risky_install_patterns(workflow, lines, 'es')
        + check_action_without_hash_1002(workflow, lines, 'es')
    )
    if not alerts:
        print('  Sin hallazgos.')
    for alert in sorted(alerts, key=lambda a: (a['line'], a['rule_id'])):
        print_alert(alert)


def explain_detector():
    print('\n=== Cómo decide el detector que un nombre es sospechoso ===')
    print('  Compara cada nombre con una lista de acciones y paquetes populares usando la')
    print('  distancia de Levenshtein: cuántas letras hay que añadir, quitar o cambiar para')
    print('  pasar de uno a otro. Una distancia de 1 o 2 respecto a algo muy popular, sin ser')
    print('  exactamente igual, es la huella típica de una errata... o de alguien esperándola.')
    for found, popular, kind in EXAMPLES:
        print(f'    {found:22s} vs {popular:22s} distancia {levenshtein(found.lower(), popular.lower())}  ({kind})')
    print('  Los homoglifos (I mayúscula por l, letras cirílicas que parecen latinas) se')
    print('  normalizan antes de comparar: visualmente son idénticos, así que cuentan como 0.')
    print('  Límite: solo conoce la lista de populares. Un nombre inventado que no se parece a')
    print('  nada conocido no salta; por eso los consejos del README importan más que la herramienta.')


def check_pins(base, online):
    print('\n=== ¿El hash fijado es de verdad la versión del comentario? ===')
    if not online:
        print('  Sin red no se puede saber: el comentario "# v4.0.2" es solo texto. Compruébalo con')
        print('    git ls-remote https://github.com/actions/setup-node refs/tags/v4.0.2')
        print('  o ejecuta:  python3 simulate.py --online')
        return
    labels = {'ok': 'OK', 'mismatch': 'NO COINCIDE', 'tag-not-found': 'TAG INEXISTENTE', 'error': 'ERROR DE RED'}
    for name in ('vulnerable.yml', 'fixed.yml'):
        print(f'  {name}:')
        for line, action, sha, tag, status, real in verify_pins_online(base / name):
            print(f'    línea {line:3d}  {action}@{sha[:12]}... # {tag:8s} -> {labels[status]}')
            if status == 'mismatch':
                print(f'               {tag} es en realidad {real}. El hash fijado es otra cosa (o no existe en ese repo).')


def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')
    explain_detector()
    check_pins(base, online='--online' in sys.argv)


if __name__ == '__main__':
    sys.exit(main())
