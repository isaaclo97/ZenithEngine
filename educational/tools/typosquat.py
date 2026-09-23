"""Educational typosquatting detector for GitHub Actions workflows.

This is not a Zenith Engine rule: it lives in educational/tools so lesson 12
and the exercise checker can use it. It looks for:

- actions whose owner/name is one or two characters away from a popular
  action (``actons/checkout``, ``actions/setup-pyhton``) or that only differ
  by look-alike characters (``jeIlyfish`` with a capital I);
- packages installed with pip/npm/yarn/pnpm whose name is close to a popular
  package (``reqeusts``, ``crossenv``);
- risky install patterns: ``--extra-index-url`` (dependency confusion),
  ``curl ... | bash``, ``npm install`` instead of ``npm ci`` and
  ``pip install -r`` without ``--require-hashes``.

It also includes ``verify_pins_online``, which checks with ``git ls-remote``
that every SHA pinned with a ``# vX.Y.Z`` comment really is that tag.
"""
import os
import re
import subprocess

from engine.parser import find_line

POPULAR_ACTIONS = [
    'actions/checkout', 'actions/setup-node', 'actions/setup-python', 'actions/setup-java',
    'actions/setup-go', 'actions/setup-dotnet', 'actions/cache', 'actions/upload-artifact',
    'actions/download-artifact', 'actions/github-script', 'actions/labeler', 'actions/stale',
    'actions/configure-pages', 'actions/upload-pages-artifact', 'actions/deploy-pages',
    'actions/dependency-review-action', 'docker/login-action', 'docker/build-push-action',
    'docker/setup-buildx-action', 'docker/setup-qemu-action', 'docker/metadata-action',
    'aws-actions/configure-aws-credentials', 'azure/login', 'google-github-actions/auth',
    'github/codeql-action', 'step-security/harden-runner', 'sigstore/cosign-installer',
    'softprops/action-gh-release', 'peaceiris/actions-gh-pages', 'codecov/codecov-action',
    'pypa/gh-action-pypi-publish', 'hashicorp/setup-terraform', 'golangci/golangci-lint-action',
    'jamesives/github-pages-deploy-action', 'dorny/paths-filter', 'tj-actions/changed-files',
    'lycheeverse/lychee-action', 'aquasecurity/trivy-action',
]

POPULAR_PACKAGES = {
    'pypi': [
        'requests', 'numpy', 'pandas', 'urllib3', 'setuptools', 'django', 'flask', 'pyyaml',
        'boto3', 'cryptography', 'python-dateutil', 'colorama', 'beautifulsoup4', 'matplotlib',
        'jellyfish', 'pytest', 'black', 'httpx', 'pillow', 'scikit-learn',
    ],
    'npm': [
        'lodash', 'express', 'react', 'axios', 'chalk', 'commander', 'moment', 'webpack',
        'typescript', 'eslint', 'jest', 'cross-env', 'dotenv', 'electron', 'discord.js',
        'prettier', 'nodemon', 'vite', 'mongoose', 'jsonwebtoken',
    ],
}

# Characters that look alike (or that a font can make look alike).
CONFUSABLES = str.maketrans({
    '0': 'o', '1': 'l', 'I': 'l',
    '\u0456': 'i', '\u03bf': 'o', '\u043e': 'o', '\u0430': 'a', '\u0435': 'e',  # Cyrillic/Greek look-alikes
    '\u0455': 's', '\u217c': 'l', '\u0440': 'p', '\u0441': 'c',
})

INSTALLERS = [
    (re.compile(r'\b(?:pip3?|python3? -m pip)\s+install\s+(.+)'), 'pypi'),
    (re.compile(r'\bnpm\s+(?:install|i|add)\s+(.+)'), 'npm'),
    (re.compile(r'\byarn\s+add\s+(.+)'), 'npm'),
    (re.compile(r'\bpnpm\s+add\s+(.+)'), 'npm'),
]
OPTIONS_WITH_VALUE = {'-r', '--requirement', '-i', '--index-url', '--extra-index-url',
                      '-c', '--constraint', '--registry', '-t', '--target'}
PIPE_TO_SHELL = re.compile(r'\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b')

MESSAGES = {
    'es': {
        'action': 'La acción "{found}" se parece mucho a "{popular}" (distancia {distance}). '
                  'Puede ser una errata o typosquatting: una cuenta que registró un nombre casi idéntico para que alguien se equivoque.',
        'homoglyph': 'La acción "{found}" solo se diferencia de "{popular}" en caracteres que se parecen visualmente (homoglifos).',
        'package': 'El paquete "{found}" ({ecosystem}) se parece mucho a "{popular}" (distancia {distance}). Comprueba el nombre exacto en el registro antes de instalarlo.',
        'package_homoglyph': 'El paquete "{found}" ({ecosystem}) solo se diferencia de "{popular}" en caracteres que se parecen visualmente.',
        'extra_index': '--extra-index-url mezcla tu índice privado con PyPI público: si alguien publica en PyPI un paquete con el mismo nombre que uno interno y una versión mayor, pip puede instalar el público (confusión de dependencias). Usa --index-url con un único índice que haga de proxy.',
        'pipe_shell': 'Se descarga un script y se ejecuta directamente con la shell, sin fijar versión ni comprobar su hash. Descárgalo, verifica su checksum o firma y después ejecútalo.',
        'npm_install': '"npm install" en CI puede resolver versiones distintas a las del lockfile. Usa "npm ci", que instala exactamente lo que dice package-lock.json y falla si no coincide.',
        'pip_hashes': '"pip install -r" sin --require-hashes acepta cualquier contenido para esas versiones. Genera el fichero con hashes (pip-compile --generate-hashes) e instala con --require-hashes.',
        'pin_mismatch': 'El hash de {action} no es la versión {tag} que dice el comentario: {tag} es {real}.',
        'pin_no_tag': 'La versión {tag} del comentario no existe en {action}.',
        'pin_unknown': 'El hash {sha} no corresponde a ninguna versión publicada de {action}. ¿Lo has copiado bien?',
        'pin_no_repo': 'El repositorio {action} no existe en GitHub (o es privado).',
        'pin_error': 'No se pudo consultar {action} en GitHub (¿sin conexión?). Sin red, ejecuta el comprobador sin --online.',
    },
    'en': {
        'action': 'The action "{found}" looks a lot like "{popular}" (distance {distance}). '
                  'It may be a typo or typosquatting: an account that registered an almost identical name hoping someone slips.',
        'homoglyph': 'The action "{found}" only differs from "{popular}" by characters that look alike (homoglyphs).',
        'package': 'The package "{found}" ({ecosystem}) looks a lot like "{popular}" (distance {distance}). Check the exact name in the registry before installing it.',
        'package_homoglyph': 'The package "{found}" ({ecosystem}) only differs from "{popular}" by characters that look alike.',
        'extra_index': '--extra-index-url mixes your private index with public PyPI: if someone publishes a package on PyPI with the same name as an internal one and a higher version, pip may install the public one (dependency confusion). Use --index-url with a single index that acts as a proxy.',
        'pipe_shell': 'A script is downloaded and piped straight into the shell, with no pinned version or hash check. Download it, verify its checksum or signature, then run it.',
        'npm_install': '"npm install" in CI can resolve versions different from the lockfile. Use "npm ci", which installs exactly what package-lock.json says and fails if it doesn\'t match.',
        'pip_hashes': '"pip install -r" without --require-hashes accepts any content for those versions. Generate the file with hashes (pip-compile --generate-hashes) and install with --require-hashes.',
        'pin_mismatch': 'The hash for {action} is not the {tag} version its comment claims: {tag} is {real}.',
        'pin_no_tag': 'The {tag} version in the comment doesn\'t exist in {action}.',
        'pin_unknown': 'The hash {sha} doesn\'t match any published version of {action}. Did you copy it correctly?',
        'pin_no_repo': 'The repository {action} doesn\'t exist on GitHub (or is private).',
        'pin_error': 'Couldn\'t query {action} on GitHub (offline?). Without network access, run the checker without --online.',
    },
}


def levenshtein(a, b):
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (char_a != char_b)))
        previous = current
    return previous[-1]


def closest_popular(name, candidates):
    """Returns (popular_name, distance, is_homoglyph) if ``name`` looks like
    a typo of a popular name, or None if it's exact or clearly different."""
    lowered = name.lower()
    if lowered in (c.lower() for c in candidates):
        return None

    normalized = name.translate(CONFUSABLES).lower()
    for candidate in candidates:
        if normalized == candidate.lower():
            return candidate, 0, True

    best = None
    max_distance = 1 if len(lowered) < 6 else 2
    for candidate in candidates:
        distance = levenshtein(lowered, candidate.lower())
        if distance <= max_distance and (best is None or distance < best[1]):
            best = (candidate, distance, False)
    return best


def _alert(rule_id, severity, line, description):
    return {'rule_id': rule_id, 'severity': severity, 'line': line, 'description': description}


def _steps(workflow):
    for job in (workflow.get('jobs') or {}).values():
        if isinstance(job, dict):
            for step in job.get('steps') or []:
                if isinstance(step, dict):
                    yield step


def check_typosquatted_actions(workflow, lines, lang='es'):
    msg = MESSAGES[lang]
    alerts = []
    for step in _steps(workflow):
        uses = step.get('uses', '')
        if not uses or uses.startswith('./') or uses.startswith('docker://') or '/' not in uses:
            continue
        name = '/'.join(uses.split('@')[0].split('/')[:2])
        match = closest_popular(name, POPULAR_ACTIONS)
        if match:
            popular, distance, homoglyph = match
            template = msg['homoglyph'] if homoglyph else msg['action']
            alerts.append(_alert('TYPO-ACTION', 'HIGH', find_line(lines, uses),
                                 template.format(found=name, popular=popular, distance=distance)))
    return alerts


def _strip_comment(command):
    return re.sub(r'(^|\s)#.*$', '', command)


def _installed_packages(command):
    """Yields (package, ecosystem) for every package in an install command."""
    command = _strip_comment(command)
    for pattern, ecosystem in INSTALLERS:
        match = pattern.search(command)
        if not match:
            continue
        arguments = re.split(r'&&|;|\|', match.group(1))[0].split()
        skip_next = False
        for token in arguments:
            if skip_next:
                skip_next = False
                continue
            if token in OPTIONS_WITH_VALUE:
                skip_next = True
                continue
            if token.startswith(('-', '.', '/', '$')) or '://' in token:
                continue  # option, local path, variable or URL: not a registry package name
            if '/' in token and not token.startswith('@'):
                continue  # e.g. "user/repo" (GitHub shorthand in npm), not a registry name
            if ecosystem == 'pypi':
                package = re.split(r'[=<>!~\[;@]', token)[0]
            elif token.startswith('@'):
                package = '@' + token[1:].split('@')[0]
            else:
                package = token.split('@')[0]
            if package:
                yield package.strip('\'"'), ecosystem


def check_typosquatted_packages(workflow, lines, lang='es'):
    msg = MESSAGES[lang]
    alerts = []
    for step in _steps(workflow):
        for command in (step.get('run') or '').splitlines():
            for package, ecosystem in _installed_packages(command):
                match = closest_popular(package, POPULAR_PACKAGES[ecosystem])
                if match:
                    popular, distance, homoglyph = match
                    template = msg['package_homoglyph'] if homoglyph else msg['package']
                    alerts.append(_alert('TYPO-PACKAGE', 'HIGH', find_line(lines, package),
                                         template.format(found=package, popular=popular,
                                                         distance=distance, ecosystem=ecosystem)))
    return alerts


def check_risky_install_patterns(workflow, lines, lang='es'):
    msg = MESSAGES[lang]
    alerts = []
    for step in _steps(workflow):
        for command in (step.get('run') or '').splitlines():
            stripped = _strip_comment(command).strip()
            if '--extra-index-url' in stripped:
                alerts.append(_alert('DEP-CONFUSION', 'HIGH', find_line(lines, '--extra-index-url'), msg['extra_index']))
            if PIPE_TO_SHELL.search(stripped):
                alerts.append(_alert('PIPE-TO-SHELL', 'MEDIUM', find_line(lines, stripped[:30]), msg['pipe_shell']))
            if re.search(r'\bnpm\s+(install|i)\s*($|&&|;)', stripped):
                alerts.append(_alert('NO-LOCKFILE', 'LOW', find_line(lines, stripped[:30]), msg['npm_install']))
            if re.search(r'\bpip3?\s+install\b.*\s(-r|--requirement)\s', stripped) and '--require-hashes' not in stripped:
                alerts.append(_alert('NO-HASHES', 'LOW', find_line(lines, stripped[:30]), msg['pip_hashes']))
    return alerts


PIN = re.compile(r'uses:\s*([\w.-]+/[\w.-]+)(?:/[\w./-]+)?@([0-9a-f]{40})(?:\s*#\s*(v?[\w.-]+))?')
_TAGS_CACHE = {}


def published_tags(action, timeout=20):
    """Returns {tag: commit} for a GitHub repository, using the peeled commit
    of annotated tags. Raises LookupError if the repository doesn't exist and
    OSError on network problems."""
    if action not in _TAGS_CACHE:
        result = subprocess.run(
            ['git', 'ls-remote', '--tags', f'https://github.com/{action}'],
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'},  # never ask for credentials
        )
        if result.returncode != 0:
            error = result.stderr.lower()
            if 'not found' in error or 'username' in error or 'terminal prompts disabled' in error:
                raise LookupError(action)
            raise OSError(result.stderr.strip())
        tags = {}
        for line in result.stdout.splitlines():
            commit, ref = line.split('\t')
            name = ref.replace('refs/tags/', '')
            if name.endswith('^{}'):
                tags[name[:-3]] = commit  # peeled commit wins over the tag object
            else:
                tags.setdefault(name, commit)
        _TAGS_CACHE[action] = tags
    return _TAGS_CACHE[action]


def check_pins_online(workflow, lines, lang='es'):
    """Checks every hash-pinned action against GitHub: the hash must be a
    published version, and the one named in its comment if there is one."""
    msg = MESSAGES[lang]
    alerts = []
    for number, text in enumerate(lines, 1):
        match = PIN.search(text)
        if not match:
            continue
        action, sha, tag = match.groups()
        try:
            tags = published_tags(action)
        except LookupError:
            alerts.append(_alert('PIN-ONLINE', 'HIGH', number, msg['pin_no_repo'].format(action=action)))
            continue
        except (OSError, subprocess.SubprocessError):
            alerts.append(_alert('PIN-ONLINE', 'LOW', number, msg['pin_error'].format(action=action)))
            continue
        if tag and tag in tags and tags[tag] != sha:
            alerts.append(_alert('PIN-ONLINE', 'HIGH', number, msg['pin_mismatch'].format(action=action, tag=tag, real=tags[tag])))
        elif sha not in tags.values():
            if tag and tag not in tags:
                alerts.append(_alert('PIN-ONLINE', 'HIGH', number, msg['pin_no_tag'].format(action=action, tag=tag)))
            alerts.append(_alert('PIN-ONLINE', 'HIGH', number, msg['pin_unknown'].format(action=action, sha=sha[:12] + '...')))
    return alerts


PIN_WITH_COMMENT = re.compile(r'uses:\s*([\w.-]+/[\w.-]+)(?:/[\w./-]+)?@([0-9a-f]{40})\s*#\s*(v?[\w.-]+)')


def verify_pins_online(path, timeout=20):
    """For every ``uses: owner/repo@<sha> # <tag>`` asks GitHub (git ls-remote)
    which commit that tag points to. Returns a list of
    (line, action, sha, tag, status, real_sha) with status in
    'ok', 'mismatch', 'tag-not-found' or 'error'."""
    results = []
    with open(path, encoding='utf-8') as f:
        for number, text in enumerate(f, 1):
            match = PIN_WITH_COMMENT.search(text)
            if not match:
                continue
            action, sha, tag = match.groups()
            try:
                output = subprocess.run(
                    ['git', 'ls-remote', f'https://github.com/{action}', f'refs/tags/{tag}', f'refs/tags/{tag}^{{}}'],
                    capture_output=True, text=True, timeout=timeout, check=True,
                    env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'},
                ).stdout.strip().splitlines()
            except (subprocess.SubprocessError, OSError):
                results.append((number, action, sha, tag, 'error', None))
                continue
            if not output:
                results.append((number, action, sha, tag, 'tag-not-found', None))
                continue
            real_sha = output[-1].split()[0]  # the ^{} line (peeled commit) comes last for annotated tags
            results.append((number, action, sha, tag, 'ok' if real_sha == sha else 'mismatch', real_sha))
    return results
