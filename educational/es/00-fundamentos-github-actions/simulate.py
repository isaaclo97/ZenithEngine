#!/usr/bin/env python3
"""
Dibuja el "mapa de confianza" de ejemplo.yml usando el parser real de Zenith
Engine: qué eventos lo disparan y quién puede provocarlos, en qué máquina corre
cada job, con qué permisos, qué código de terceros ejecuta y qué datos entran
desde fuera. Es la forma de mirar un workflow que usan todas las lecciones.
"""
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from engine.parser import parse_workflow
from engine.rules.triggers import DANGEROUS_EXPRESSIONS

EVENTS = {
    'push': ('personas con permiso de escritura', 'sí'),
    'pull_request': ('CUALQUIERA, desde un fork', 'desde un fork NO (token de solo lectura, sin secretos)'),
    'pull_request_target': ('CUALQUIERA, desde un fork', 'SÍ: corre con los privilegios del repositorio'),
    'issue_comment': ('CUALQUIERA que pueda comentar', 'sí'),
    'issues': ('CUALQUIERA que pueda abrir issues', 'sí'),
    'workflow_dispatch': ('personas con permiso de escritura', 'sí'),
    'schedule': ('nadie: lo lanza el reloj', 'sí'),
    'workflow_run': ('otro workflow (que quizá procesó datos de un fork)', 'sí'),
}
HASH = re.compile(r'^[0-9a-f]{40}$')
EXPRESSION = re.compile(r'\$\{\{\s*(.*?)\s*\}\}')


def describe_ref(ref):
    if HASH.match(ref):
        return 'hash de commit (inmutable)'
    if re.match(r'^v?\d+(\.\d+)*$', ref):
        return 'tag (mutable)'
    return 'rama o "latest" (cambia con cada commit)'


def describe_step(step):
    if 'run' in step:
        return 'script "run:" escrito en este repositorio'
    uses = step.get('uses', '')
    if uses.startswith('./'):
        return 'acción local de este repositorio'
    owner = uses.split('/')[0]
    action, _, ref = uses.partition('@')
    origin = 'acción oficial de GitHub' if owner in ('actions', 'github') else 'acción de TERCEROS'
    return f'{origin}: {action}, fijada por {describe_ref(ref)}'


def format_permissions(permissions):
    if not permissions:
        return 'los POR DEFECTO del repositorio (sin bloque permissions:)'
    if isinstance(permissions, dict):
        return ', '.join(f'{scope}: {level}' for scope, level in permissions.items())
    return str(permissions)


def classify_expression(expression):
    if expression.startswith('secrets.'):
        return 'SECRETO'
    if any(dangerous in expression for dangerous in DANGEROUS_EXPRESSIONS):
        return 'DATO NO CONFIABLE (lo escribe quien dispara el evento)'
    return 'dato controlado por GitHub o por el repositorio'


def main():
    path = Path(__file__).parent / 'ejemplo.yml'
    workflow, _ = parse_workflow(str(path))

    print('=== 1. Eventos: quién puede lanzar este workflow ===')
    for event in workflow.get('on', {}):
        who, secrets = EVENTS.get(event, ('(consulta la documentación)', '?'))
        print(f'  {event:20s} lo provoca: {who:45s} acceso a secretos: {secrets}')

    global_permissions = workflow.get('permissions')
    print('\n=== 2. Jobs: dónde corren y con qué permisos ===')
    for name, job in workflow.get('jobs', {}).items():
        runner = job.get('runs-on')
        runner_kind = 'propio, persistente' if 'self-hosted' in str(runner) else 'hospedado por GitHub, efímero'
        permissions = format_permissions(job.get('permissions') or global_permissions)
        needs = f', espera a: {job["needs"]}' if 'needs' in job else ''
        print(f'  job "{name}": runner {runner} ({runner_kind}){needs}')
        print(f'      GITHUB_TOKEN: {permissions}')
        for step in job.get('steps', []):
            print(f'      - {step.get("name", "(sin nombre)")}: {describe_step(step)}')

    print('\n=== 3. Expresiones ${{ }}: qué datos entran en el workflow ===')
    text = path.read_text(encoding='utf-8')
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith('#'):
            continue
        for expression in EXPRESSION.findall(line):
            print(f'  línea {number:3d}  {expression:40s} -> {classify_expression(expression)}')

    print('\nCon este mapa se ven de un vistazo las preguntas de todas las lecciones:')
    print('  ¿quién puede disparar esto?, ¿con qué privilegios?, ¿qué código ajeno se ejecuta?')
    print('  y ¿qué datos que no controlo llegan a un script o a un secreto?')


if __name__ == '__main__':
    sys.exit(main())
