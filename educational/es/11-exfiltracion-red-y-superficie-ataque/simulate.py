#!/usr/bin/env python3
"""
Ejecuta las reglas REALES de Zenith Engine especificas del proyecto (R1005,
R1006, R1009, R1013, R1015, R1018, R1020; en engine/rules/network.py,
engine/rules/runners.py y engine/rules/triggers.py) sobre vulnerable.yml y
fixed.yml, y ademas decodifica el payload simulado de exfiltracion por DNS
(R1015) para mostrar que dato viajaria oculto en el subdominio.
"""
import base64
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.network import (
    check_fraudulent_domain_1005,
    check_direct_ip_call_1009,
    check_dns_exfiltration_1015,
    check_github_api_exfiltration_1018,
)
from engine.rules.runners import check_runs_on_self_hosted_1006, check_runner_ec2_without_hardening_1020
from engine.rules.triggers import check_pull_request_without_branch_restriction_1013


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  línea {alert['line']}: {alert['description']}")


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))

    alerts = (
        check_fraudulent_domain_1005(workflow, lines, lang='es')
        + check_direct_ip_call_1009(workflow, lines, lang='es')
        + check_dns_exfiltration_1015(workflow, lines, lang='es')
        + check_github_api_exfiltration_1018(workflow, lines, lang='es')
        + check_runs_on_self_hosted_1006(workflow, lines, lang='es')
        + check_runner_ec2_without_hardening_1020(workflow, lines, lang='es')
        + check_pull_request_without_branch_restriction_1013(workflow, lines, lang='es')
    )
    if not alerts:
        print('  Sin hallazgos.')
        return
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)


def decode_dns_payload():
    print('\n=== Decodificando el payload de la exfiltración por DNS simulada ===')
    subdomain = 'Z2hwX3Byb2REZXBsb3lUb2tlbjc4OQ'
    padded = subdomain + '=' * (-len(subdomain) % 4)
    decoded = base64.b64decode(padded).decode()
    print(f'  Subdominio consultado: {subdomain}.attacker-dns.example')
    print(f'  Decodificado (base64) -> "{decoded}"')
    print('  Un servidor DNS bajo control del atacante, autoritativo para "attacker-dns.example",')
    print('  ve esta consulta en sus logs igual que vería cualquier resolución DNS legítima.')
    print('  El dato viajó completo sin necesitar ninguna conexión HTTP saliente.')


def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')
    decode_dns_payload()


if __name__ == '__main__':
    sys.exit(main())
