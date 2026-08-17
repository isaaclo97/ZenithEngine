import json
import os
import re

try:
    import requests
except ImportError:
    requests = None

from engine.create_alert import create_alert
from engine.parser import find_line


VERSION_PATTERN = re.compile(r'^[0-9]+(\.[0-9]+)*$')

GITHUB_ADVISORIES_URL = 'https://api.github.com/advisories'
GITHUB_ADVISORIES_TIMEOUT = 5

_DB_CACHE = None


def _version_tuple(version):
    parts = []
    for part in version.split('.'):
        match = re.match(r'^[0-9]+', part)
        if not match:
            return None
        parts.append(int(match.group(0)))
    return tuple(parts)


def _satisfies_constraint(version, constraint):
    v = _version_tuple(version)
    if v is None:
        return False

    for clause in constraint.split(','):
        clause = clause.strip()
        for operator, compare in (
            ('>=', lambda a, b: a >= b),
            ('<=', lambda a, b: a <= b),
            ('==', lambda a, b: a == b),
            ('=', lambda a, b: a == b),
            ('>', lambda a, b: a > b),
            ('<', lambda a, b: a < b),
        ):
            if not clause.startswith(operator):
                continue

            target = _version_tuple(clause[len(operator):].strip())
            if target is None:
                return False

            if len(v) < len(target):
                # The version referenced by the workflow is less precise
                # than the constraint's bound (e.g. a floating "v4" tag
                # against a "4.1.3" advisory bound). There's no safe way to
                # know which exact version a floating tag resolves to
                # without querying the repository, so the result is
                # discarded instead of assuming the best/worst case. This
                # avoids false positives like flagging
                # "actions/download-artifact@v4" as vulnerable when the tag
                # already points at a patched release today.
                return False

            n = len(v)
            padded_target = target + (0,) * (n - len(target))
            if not compare(v[:n], padded_target):
                return False
            break

    return True


def _convert_github_range(range_str):
    return range_str.replace(', ', ',').replace(' ', '')


def _fetch_advisories_from_github():
    if requests is None:
        raise RuntimeError('The "requests" package is not available')

    db = {}
    url = f'{GITHUB_ADVISORIES_URL}?ecosystem=actions&per_page=100'

    while url:
        response = requests.get(
            url,
            timeout=GITHUB_ADVISORIES_TIMEOUT,
            headers={'Accept': 'application/vnd.github+json'}
        )
        response.raise_for_status()

        for advisory in response.json():
            identifier = advisory.get('cve_id') or advisory.get('ghsa_id')
            for vulnerability in advisory.get('vulnerabilities') or []:
                package = vulnerability.get('package') or {}
                if package.get('ecosystem') != 'actions':
                    continue

                name = package.get('name')
                version_range = vulnerability.get('vulnerable_version_range')
                if not name or not version_range:
                    continue

                entry = {
                    'id': identifier,
                    'reference': advisory.get('html_url', ''),
                    'ranges': [_convert_github_range(version_range)],
                    'summary': (advisory.get('summary') or '')[:300],
                }
                db.setdefault(name, []).append(entry)

        url = None
        for part in response.headers.get('Link', '').split(','):
            if 'rel="next"' in part:
                url = part.split(';')[0].strip().strip('<>')
                break

    if not db:
        raise ValueError('The GitHub API returned no vulnerabilities')

    return db


def _load_local_snapshot():
    path = os.path.join(os.path.dirname(__file__), '..', 'known_vulnerabilities.json')
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    data.pop('_source', None)
    data.pop('_generated_at', None)
    return data


def load_known_vulnerabilities():
    global _DB_CACHE
    if _DB_CACHE is not None:
        return _DB_CACHE

    try:
        _DB_CACHE = _fetch_advisories_from_github()
    except Exception:
        _DB_CACHE = _load_local_snapshot()

    return _DB_CACHE


def check_known_vulnerable_component_1025(workflow, lines, lang='es'):
    alerts = []
    db = load_known_vulnerabilities()

    jobs = workflow.get('jobs', {})
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get('steps', [])
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get('uses', '')
            if not uses or uses.startswith('./') or '@' not in uses:
                continue

            action, version_ref = uses.split('@', 1)
            version = version_ref.lstrip('vV')

            if not VERSION_PATTERN.match(version):
                continue

            for entry in db.get(action, []):
                for constraint in entry.get('ranges', []):
                    if _satisfies_constraint(version, constraint):
                        line = find_line(lines, uses)
                        alerts.append(create_alert(
                            rule_id='R1025',
                            category='CICD-SEC-3',
                            severity='CRITICAL',
                            line=line,
                            lang=lang,
                            uses=uses,
                            action=action,
                            vuln_id=entry.get('id', ''),
                            summary=entry.get('summary', ''),
                            reference=entry.get('reference', ''),
                        ))
                        break

    return alerts
