#!/usr/bin/env python3
"""
Ejecuta las reglas REALES de Zenith Engine (R1003 / R1011, en
engine/rules/permissions.py) sobre vulnerable.yml y fixed.yml, y ademas
construye la tabla de permisos "efectivos" del GITHUB_TOKEN para cada job
(igual que aparece en la pestana "Permissions" de una ejecucion real en
GitHub) para mostrar concretamente que podria hacer una accion de terceros
comprometida con esos permisos.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.permissions import check_missing_permissions_1003, check_third_party_action_with_token_1011

# Permisos por defecto que GitHub asigna al GITHUB_TOKEN cuando el
# repositorio no ha sido configurado en modo "solo lectura por defecto"
# (el ajuste de fábrica en repos creados antes de 2023 y en muchas
# organizaciones aún hoy).
DEFAULT_PERMISSIVE_TOKEN = {
    'actions': 'write', 'checks': 'write', 'contents': 'write',
    'deployments': 'write', 'issues': 'write', 'packages': 'write',
    'pull-requests': 'write', 'repository-projects': 'write',
    'security-events': 'write', 'statuses': 'write',
}

API_CAPABILITIES = {
    'contents': 'modificar o borrar ficheros/ramas del repositorio',
    'pull-requests': 'comentar, etiquetar o cerrar pull requests (y aprobarlos si la organización lo permite)',
    'packages': 'publicar paquetes bajo el nombre del repositorio',
    'issues': 'crear, cerrar o editar issues',
    'actions': 'cancelar o re-disparar workflows, borrar artefactos',
}


def print_alert(alert):
    print(f"  [{alert['severity']:8s}] {alert['rule_id']}  línea {alert['line']}: {alert['description']}")


def effective_permissions(workflow):
    global_perms = workflow.get('permissions')
    table = {}
    for job_name, job in workflow.get('jobs', {}).items():
        job_perms = job.get('permissions')
        if job_perms is not None:
            table[job_name] = ('declarado en el job', job_perms)
        elif global_perms is not None:
            table[job_name] = ('heredado del workflow', global_perms)
        else:
            table[job_name] = ('POR DEFECTO DEL REPOSITORIO (sin permissions: en ningún nivel)',
                                DEFAULT_PERMISSIVE_TOKEN)
    return table


def report(path):
    print(f'\n=== {path.name} ===')
    workflow, lines = parse_workflow(str(path))

    print('Permisos efectivos del GITHUB_TOKEN por job:')
    perms_table = effective_permissions(workflow)
    for job_name, (source, perms) in perms_table.items():
        print(f'  job "{job_name}" -> origen: {source}')
        for scope, level in perms.items():
            print(f'      {scope}: {level}')

    alerts = check_missing_permissions_1003(workflow, lines, lang='es') + check_third_party_action_with_token_1011(workflow, lines, lang='es')
    if not alerts:
        print('\nSin hallazgos EPW.')
        return

    print('\nHallazgos de Zenith Engine:')
    for alert in sorted(alerts, key=lambda a: a['line']):
        print_alert(alert)

    if any(a['rule_id'] == 'R1011' for a in alerts):
        print('\nQué podría hacer una acción de terceros comprometida con el token actual, por job:')
        for job_name, (source, perms) in perms_table.items():
            writable = [s for s, lvl in perms.items() if lvl == 'write' and s in API_CAPABILITIES]
            if writable:
                print(f'  job "{job_name}":')
                for scope in writable:
                    print(f'    - {API_CAPABILITIES[scope]} (permiso "{scope}: write")')


def main():
    base = Path(__file__).parent
    report(base / 'vulnerable.yml')
    report(base / 'fixed.yml')


if __name__ == '__main__':
    sys.exit(main())
