from engine.i18n import translate


def create_alert(rule_id, category, severity, line, lang='es', **params):
    """Build an alert dict, rendering the rule/description/suggestion text
    for the given language from the i18n catalogs. `params` are the named
    values interpolated into that rule's translation templates."""
    return {
        'rule_id': rule_id,
        'rule': translate(lang, f'{rule_id}.rule', **params),
        'category': category,
        'severity': severity,
        'line': line,
        'description': translate(lang, f'{rule_id}.description', **params),
        'suggestion': translate(lang, f'{rule_id}.suggestion', **params),
    }
