"""Minimal i18n engine: loads flat JSON translation catalogs (one file per
language) and renders templated strings with named placeholders.

To add a language, drop a new `<code>.json` file in this directory with the
same keys as `es.json`/`en.json`, and add its code to SUPPORTED_LANGUAGES.
"""
import json
import os
from functools import lru_cache

DEFAULT_LANGUAGE = 'es'
SUPPORTED_LANGUAGES = ('es', 'en')

_CATALOG_DIR = os.path.dirname(__file__)


@lru_cache(maxsize=None)
def _load_catalog(lang):
    path = os.path.join(_CATALOG_DIR, f'{lang}.json')
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def normalize_language(lang):
    return lang if lang in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE


def translate(lang, translation_key, **params):
    """Return the translated, formatted string for `translation_key` in
    `lang`.

    Falls back to the default language, then to the raw key, if the key is
    missing from a catalog (keeps the app usable while a translation is
    incomplete instead of crashing). The lookup key is named
    `translation_key` (not `key`) so it never collides with a rule's own
    `key` template parameter (e.g. R1014's hardcoded-field-name param).
    """
    lang = normalize_language(lang)
    template = _load_catalog(lang).get(translation_key)

    if template is None and lang != DEFAULT_LANGUAGE:
        template = _load_catalog(DEFAULT_LANGUAGE).get(translation_key)

    if template is None:
        return translation_key

    try:
        return template.format(**params)
    except (KeyError, IndexError):
        return template
