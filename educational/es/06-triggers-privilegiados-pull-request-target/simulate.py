#!/usr/bin/env python3
"""
Ejecuta las reglas REALES de Zenith Engine R1000 / R1001 / R1021 (en
engine/rules/triggers.py) sobre vulnerable.yml y fixed.yml, y ademas recrea
la linea de tiempo de un ataque TOCTOU real sobre "gh pr checkout <numero>":
el commit que se revisa y aprueba no es necesariamente el commit que
termina ejecutandose con los secretos del repositorio base.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.triggers import (
    check_pull_request_target_1000,
    check_checkout_without_ref_1001,
    check_toctou_pattern_1021,
)


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  línea {alert['line']}: {alert['description']}")


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))

    alerts = (
        check_pull_request_target_1000(workflow, lines, lang='es')
        + check_checkout_without_ref_1001(workflow, lines, lang='es')
        + check_toctou_pattern_1021(workflow, lines, lang='es')
    )
    if not alerts:
        print('  Sin hallazgos PTW.')
        return
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)


def explain_r1001_limitation():
    print('\n=== Nota sobre R1001 y fixed.yml ===')
    print('  fixed.yml sigue disparando R1001 en el job "test-approved", y es CORRECTO que lo')
    print('  haga: aunque use github.event.pull_request.head.sha, ese job sigue ejecutando')
    print('  código escrito por el autor del PR dentro de un contexto pull_request_target.')
    print('  Fijar el SHA solo cierra el hueco TOCTOU (se ejecuta exactamente lo revisado);')
    print('  NO convierte el código del PR en código de confianza. Lo que hace aceptable este')
    print('  job son controles que R1001 no puede ver: la revisión humana previa (etiqueta')
    print('  "safe-to-test"), la ausencia de secretos en el entorno, permissions de solo')
    print('  lectura y persist-credentials: false. Moraleja: una alerta que sigue saltando')
    print('  tras corregir no es necesariamente un falso positivo; hay que entender qué')
    print('  riesgo señala y si los controles que la herramienta no ve lo mitigan.')


def simulate_toctou_timeline():
    print('\n=== Simulación: línea de tiempo de un ataque TOCTOU ===')
    events = [
        ('T+0min',  'El autor abre el PR #42 con el commit A (código legítimo).'),
        ('T+3min',  'Un mantenedor revisa el diff de A, lo considera seguro y añade la etiqueta "safe-to-test".'),
        ('T+3min',  'El evento "labeled" dispara el job "test-approved". Su payload fija head.sha = A.'),
        ('T+4min',  'El autor hace push de un NUEVO commit B al mismo PR #42 (con código que exfiltra secretos).'),
        ('T+5min',  'El job arranca por fin (con retraso, por cola de runners).'),
        ('T+5min',  '"gh pr checkout 42" se ejecuta -> trae el ÚLTIMO commit del PR, que ya es B, no A.'),
    ]
    for moment, description in events:
        print(f'  {moment:8s} {description}')

    print('\n  Commit revisado y aprobado:  A')
    print('  Commit realmente ejecutado:  B   (con GH_TOKEN disponible en el entorno)')
    print('  -> El mantenedor aprobó A. El pipeline ejecutó B. Esa diferencia es el hueco TOCTOU.')
    print('\n  Con fixed.yml: el checkout usa github.event.pull_request.head.sha, fijado en el evento')
    print('  "labeled" (= A), así que se ejecuta A aunque B ya exista. El push de B genera un evento')
    print('  "synchronize", que no dispara "test-approved": el mantenedor tiene que revisar B y volver')
    print('  a etiquetar. Y aunque A resultara ser malicioso, el job no tiene secretos que robar.')

def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')
    explain_r1001_limitation()
    simulate_toctou_timeline()


if __name__ == '__main__':
    sys.exit(main())
