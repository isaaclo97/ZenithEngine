#!/usr/bin/env python3
"""
Ejecuta las reglas REALES de Zenith Engine R1014 / R1019 (en
engine/rules/credentials.py) sobre vulnerable.yml y fixed.yml, y ademas
simula el log de ejecucion real que produciria GitHub Actions -- incluyendo
donde SI funciona el enmascarado automatico de secretos y donde tiene
huecos conocidos.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.credentials import check_hardcoded_credential_1014, check_secret_in_logs_1019


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  línea {alert['line']}: {alert['description']}")


def analyze(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))
    alerts = check_hardcoded_credential_1014(workflow, lines, lang='es') + check_secret_in_logs_1019(workflow, lines, lang='es')
    if not alerts:
        print('  Sin hallazgos SEW.')
        return
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)


def mask(text, secret_value):
    """Reproduce el enmascarado automático de GitHub: sustituye cualquier
    aparición LITERAL del valor exacto del secreto por '***'."""
    return text.replace(secret_value, '***')


def simulate_log():
    print('\n=== Simulación del log de ejecución real ===')
    real_token = 'ghp_S3cr3tRealDeployToken1234567890'

    print('\n1) vulnerable.yml: credencial hardcodeada (R1014):')
    hardcoded_line = 'with.api_key: "sk_live_EXAMPLE-not-a-real-key"'
    print(f'  El valor está escrito en el propio .yml del repositorio, en texto plano:')
    print(f'    {hardcoded_line}')
    print('  GitHub no puede enmascarar esto en los logs porque nunca lo registró como secreto:')
    print('  cualquiera con acceso de lectura al repositorio (o a un fork, si el .yml es público) lo ve directamente.')

    print('\n2) vulnerable.yml: impresión directa de un secreto real (R1019):')
    log_line = f'echo "Usando token: {real_token}"'
    print(f'  Comando real ejecutado: run: echo "Usando token: $TOKEN"')
    print(f'  Log SIN enmascarar (lo que produciría el proceso):\n    Usando token: {real_token}')
    print(f'  Log CON el enmascarado automático de GitHub (coincide con el valor exacto del secreto):\n    {mask(log_line, real_token)}')
    print('  En este caso simple, GitHub SÍ lo enmascara, pero R1019 sigue marcándolo como CRITICAL')
    print('  porque el enmascarado tiene huecos conocidos y ampliamente documentados. Por ejemplo, si el')
    print('  secreto se transforma antes de imprimirse, el enmascarado ya no reconoce el valor original:')

    print('\n3) Variante que SÍ evade el enmascarado (no está en vulnerable.yml, pero es el motivo real de R1019):')
    print('    run: echo "Token en base64: $(echo -n $TOKEN | base64)"')
    import base64
    encoded = base64.b64encode(real_token.encode()).decode()
    log_line_b64 = f'Token en base64: {encoded}'
    print(f'  Log producido:\n    {log_line_b64}')
    print(f'  Log tras el enmascarado de GitHub (busca "{real_token}" literal, no su base64):')
    print(f'    {mask(log_line_b64, real_token)}   <- NO se enmascaró: el secreto es recuperable con "base64 -d"')

    print('\n4) fixed.yml: no se imprime el valor, solo su longitud (sin hallazgos R1019):')
    print('    run: echo "TOKEN configurado (longitud: ${#TOKEN})"')
    print(f'  Log producido:\n    TOKEN configurado (longitud: {len(real_token)})')
    print('  No hay ningún valor sensible que enmascarar: nunca llegó a los logs.')


def main():
    base = Path(__file__).parent
    analyze(base / 'vulnerable.yml')
    analyze(base / 'fixed.yml')
    simulate_log()


if __name__ == '__main__':
    sys.exit(main())
