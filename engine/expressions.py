"""Canonical form of GitHub Actions expressions.

Several rules match expression text literally, which lets a semantically
identical but differently written expression slip past. GitHub treats these as
the same lookup:

    github.event.issue.title
    github['event']['issue']['title']
    github.EVENT.issue.title          (contexts/properties are case-insensitive)
    github . event . issue . title    (whitespace between tokens is insignificant)

`normalize_expression` rewrites any of these to a single canonical form:
index syntax becomes dot syntax, identifiers are lower-cased, and insignificant
whitespace is removed. String and number literals are preserved exactly.

`iter_expressions(text)` yields the normalized interior of every `${{ ... }}`
block in `text`, so a rule can match its (also normalized) patterns against the
expression as the runner would resolve it, not against its surface text.
"""
import re

_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<str>'(?:[^']|'')*')
  | (?P<num>0x[0-9a-fA-F]+|\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)
  | (?P<id>[A-Za-z_][A-Za-z0-9_-]*)
  | (?P<op>==|!=|<=|>=|&&|\|\||[<>!.\[\](),*-])
""", re.X)

_IDENT = re.compile(r'[A-Za-z_][A-Za-z0-9_-]*$')
_EXPR_BLOCK = re.compile(r'\$\{\{(.*?)\}\}', re.S)
_KEYWORDS = {'true', 'false', 'null'}


def _tokens(src):
    tokens, pos = [], 0
    while pos < len(src):
        m = _TOKEN.match(src, pos)
        if not m:
            return None
        kind, value = m.lastgroup, m.group()
        if kind == 'ws':
            pass
        elif kind == 'id':
            tokens.append(('id', value.lower()))
        else:
            tokens.append((kind, value))
        pos = m.end()
    return tokens


def normalize_expression(expr):
    """Canonical text of a single expression, or the stripped input unchanged
    if it is not a well-formed expression."""
    tokens = _tokens(expr)
    if tokens is None:
        return expr.strip()

    out, i = [], 0
    while i < len(tokens):
        # x['name'] -> x.name  (only for identifier-shaped keys)
        if (tokens[i] == ('op', '[') and i + 2 < len(tokens) and tokens[i + 1][0] == 'str'
                and tokens[i + 2] == ('op', ']') and _IDENT.match(tokens[i + 1][1][1:-1])):
            out.append('.' + tokens[i + 1][1][1:-1].lower())
            i += 3
        else:
            out.append(tokens[i][1])
            i += 1
    return ''.join(out)


def iter_expressions(text):
    """Yield the normalized interior of each ${{ ... }} block in `text`."""
    if not isinstance(text, str):
        return
    for match in _EXPR_BLOCK.finditer(text):
        yield normalize_expression(match.group(1))


def references_context(text, context):
    """True if some ${{ }} block in `text` reads from `context` (e.g. 'secrets'),
    whatever its notation: secrets.X, (secrets.X), SECRETS.X, secrets['X']..."""
    root = re.compile(r'(?<![\w.-])' + re.escape(context.lower()) + r'\.')
    return any(root.search(expr) for expr in iter_expressions(text))


def normalize_fragment(fragment):
    """Normalize a bare pattern (no ${{ }}) for comparison against the output of
    iter_expressions, e.g. a dangerous-expression pattern from a rule."""
    return normalize_expression(fragment)


# ---------------------------------------------------------------------------
# Syntax tree and abstract evaluation of `if:` conditions.
#
# The parser is the one used by the robustness oracle
# (robustness/scripts/equivalence.py, expr_ast). The evaluator runs it with
# every context lookup unknown, to tell whether a condition is true whatever the
# event, actor or inputs are: `x || true`, `always() || x`, `'a' == 'a'`...

_BINARY_LEVELS = [('||',), ('&&',), ('==', '!='), ('<', '<=', '>', '>=')]
_STATUS_FUNCTIONS = {'success', 'failure', 'cancelled', 'always'}


def _fold_case(tokens):
    """Lower-case identifiers (GitHub resolves them case-insensitively), except
    the name in `env.NAME`, which is case-sensitive on Linux runners."""
    out = []
    for i, (kind, value) in enumerate(tokens):
        if kind == 'id':
            after_env = (i >= 2 and tokens[i - 1] == ('op', '.') and tokens[i - 2][0] == 'id'
                         and tokens[i - 2][1].lower() == 'env'
                         and (i < 3 or tokens[i - 3] != ('op', '.')))
            if not after_env:
                value = value.lower()
        out.append((kind, value))
    return out


def _syntax_tokens(expr):
    tokens, pos = [], 0
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m:
            return None
        if m.lastgroup != 'ws':
            tokens.append((m.lastgroup, m.group()))
        pos = m.end()
    out, i = [], 0
    while i < len(tokens):
        if (tokens[i] == ('op', '[') and i + 2 < len(tokens) and tokens[i + 1][0] == 'str'
                and tokens[i + 2] == ('op', ']') and _IDENT.match(tokens[i + 1][1][1:-1])):
            out += [('op', '.'), ('id', tokens[i + 1][1][1:-1])]
            i += 3
        else:
            out.append(tokens[i])
            i += 1
    return _fold_case(out)


def parse_expression(expr):
    """Syntax tree of one expression (no ${{ }}), or None if it does not parse.

    Nodes: ('str', "'lit'"), ('num', '1'), ('id', name), ('.', obj, name),
    ('[]', obj, index), ('call', name, args), ('!', x), ('neg', x) and
    (op, left, right) for the binary operators. Parentheses leave no node.
    """
    tokens = _syntax_tokens(expr)
    if not tokens:
        return None
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take(expected=None):
        nonlocal pos
        tok = peek()
        if tok is None or (expected is not None and tok != expected):
            raise ValueError
        pos += 1
        return tok

    def binary(level):
        if level == len(_BINARY_LEVELS):
            return unary()
        left = binary(level + 1)
        while peek() is not None and peek()[0] == 'op' and peek()[1] in _BINARY_LEVELS[level]:
            op = take()[1]
            left = (op, left, binary(level + 1))
        return left

    def unary():
        if peek() == ('op', '!'):
            take()
            return ('!', unary())
        if peek() == ('op', '-'):
            take()
            return ('neg', unary())
        return postfix()

    def postfix():
        node = primary()
        while True:
            if peek() == ('op', '.'):
                take()
                tok = take()
                if tok != ('op', '*') and tok[0] != 'id':
                    raise ValueError
                node = ('.', node, tok[1])
            elif peek() == ('op', '['):
                take()
                node = ('[]', node, binary(0))
                take(('op', ']'))
            else:
                return node

    def primary():
        tok = take()
        if tok == ('op', '('):
            node = binary(0)
            take(('op', ')'))
            return node
        if tok[0] in ('str', 'num'):
            return tok
        if tok[0] == 'id':
            if peek() == ('op', '(') and tok[1] not in _KEYWORDS:
                take()
                args = []
                if peek() != ('op', ')'):
                    args.append(binary(0))
                    while peek() == ('op', ','):
                        take()
                        args.append(binary(0))
                take(('op', ')'))
                return ('call', tok[1], tuple(args))
            return tok
        raise ValueError

    try:
        node = binary(0)
    except (ValueError, RecursionError):
        return None
    return node if pos == len(tokens) else None


class _Unknown:
    """A value only known at run time. `truthy` is True/False when every value it
    may take has that truthiness, None otherwise; `key` identifies the lookup
    that produced it, so `x == x` can be decided without knowing x."""
    __slots__ = ('truthy', 'key')

    def __init__(self, truthy=None, key=None):
        self.truthy, self.key = truthy, key


_ANY_BOOL = _Unknown()


def _truthy(value):
    if isinstance(value, _Unknown):
        return value.truthy
    if value is None or value is False or value == '':
        return False
    if isinstance(value, float) and (value == 0 or value != value):
        return False
    return True


def _to_number(value):
    """GitHub's coercion to number (JavaScript-like)."""
    if value is None or value is False:
        return 0.0
    if value is True:
        return 1.0
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        s = value.strip()
        if s == '':
            return 0.0
        try:
            return float(int(s, 16)) if s.lower().startswith('0x') else float(s)
        except ValueError:
            return float('nan')
    return float('nan')


def _compare(op, a, b):
    """Comparison of two known values, as GitHub defines it: same type compares
    directly (strings case-insensitively); otherwise both become numbers."""
    if type(a) is type(b) and isinstance(a, str):
        a, b = a.lower(), b.lower()
    elif type(a) is type(b) and a is not None and not isinstance(a, (bool, float)):
        return a is b if op == '==' else (a is not b if op == '!=' else False)
    elif type(a) is not type(b):
        a, b = _to_number(a), _to_number(b)
    if op == '==':
        return a == b
    if op == '!=':
        return a != b
    if a is None or (isinstance(a, float) and a != a) or (isinstance(b, float) and b != b):
        return False
    return {'<': a < b, '<=': a <= b, '>': a > b, '>=': a >= b}[op]


def _to_string(value):
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else repr(value)
    return value if isinstance(value, str) else None


def _call(name, args, status):
    if name in _STATUS_FUNCTIONS:
        return status[name]
    if any(isinstance(a, _Unknown) for a in args):
        if name in ('contains', 'startswith', 'endswith'):
            return _ANY_BOOL
        return _Unknown()
    try:
        if name in ('contains', 'startswith', 'endswith') and len(args) == 2:
            haystack, needle = args
            if name == 'contains' and isinstance(haystack, list):
                return any(not isinstance(x, (list, dict)) and _compare('==', x, needle) for x in haystack)
            haystack, needle = _to_string(haystack), _to_string(needle)
            if haystack is None or needle is None:
                return False
            haystack, needle = haystack.lower(), needle.lower()
            return {'contains': needle in haystack, 'startswith': haystack.startswith(needle),
                    'endswith': haystack.endswith(needle)}[name]
        if name == 'fromjson' and len(args) == 1 and isinstance(args[0], str):
            import json
            value = json.loads(args[0])
            return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else value
        if name == 'format' and args and isinstance(args[0], str):
            parts = [_to_string(a) for a in args[1:]]
            if None in parts:
                return _Unknown()
            text = args[0].replace('{{', '\0').replace('}}', '\1')
            for i, part in enumerate(parts):
                text = text.replace('{%d}' % i, part)
            return text.replace('\0', '{').replace('\1', '}')
    except (ValueError, TypeError):
        return _Unknown()
    return _Unknown()


def _evaluate(node, status):
    kind = node[0]
    if kind == 'str':
        return node[1][1:-1].replace("''", "'")
    if kind == 'num':
        return _to_number(node[1])
    if kind == 'id':
        if node[1] in _KEYWORDS:
            return {'true': True, 'false': False, 'null': None}[node[1]]
        return _Unknown(key=node)
    if kind in ('.', '[]'):
        return _Unknown(key=node)
    if kind == 'call':
        return _call(node[1], [_evaluate(a, status) for a in node[2]], status)
    if kind == '!':
        t = _truthy(_evaluate(node[1], status))
        return _ANY_BOOL if t is None else not t
    if kind == 'neg':
        value = _evaluate(node[1], status)
        return _Unknown() if isinstance(value, _Unknown) else -_to_number(value)

    left = _evaluate(node[1], status)
    if kind in ('||', '&&'):
        t = _truthy(left)
        if t is (kind == '||'):
            return left
        right = _evaluate(node[2], status)
        if t is not None:
            return right
        # `x || !x` is truthy and `x && !x` falsy, whatever x is.
        if node[2] == ('!', node[1]) or node[1] == ('!', node[2]):
            return _Unknown(truthy=kind == '||')
        # Either operand may be the result: known only if both agree.
        r = _truthy(right)
        return _Unknown(truthy=r if r is (kind == '||') else None)

    right = _evaluate(node[2], status)
    if isinstance(left, _Unknown) or isinstance(right, _Unknown):
        same = (isinstance(left, _Unknown) and isinstance(right, _Unknown)
                and left.key is not None and left.key == right.key)
        if same and kind in ('==', '<=', '>='):
            return True
        if same and kind in ('!=', '<', '>'):
            return False
        return _ANY_BOOL
    return _compare(kind, left, right)


def _restricts_something(node):
    """True if the condition looks like a real check: it reads a context,
    compares values or calls a function other than a status function. Bare
    `true`, `always()` or `!cancelled()` are deliberate and not reported."""
    if not isinstance(node, tuple):
        return False
    kind = node[0]
    if kind in ('.', '[]') or (kind == 'id' and node[1] not in _KEYWORDS):
        return True
    if kind in ('==', '!=', '<', '<=', '>', '>='):
        return True
    if kind == 'call':
        return node[1] not in _STATUS_FUNCTIONS or any(_restricts_something(a) for a in node[2])
    return any(_restricts_something(child) for child in node[1:] if isinstance(child, tuple))


_STATUSES = {
    'success': {'success': True, 'failure': False, 'cancelled': False, 'always': True},
    'failure': {'success': False, 'failure': True, 'cancelled': False, 'always': True},
    'cancelled': {'success': False, 'failure': False, 'cancelled': True, 'always': True},
}


def _mentions_status(node):
    if not isinstance(node, tuple):
        return False
    if node[0] == 'call':
        return node[1] in _STATUS_FUNCTIONS or any(_mentions_status(a) for a in node[2])
    return any(_mentions_status(child) for child in node[1:])


def is_tautology(condition):
    """True if an `if:` condition (one expression, with or without its ${{ }})
    reads contexts but its result never depends on them, and it holds when the
    previous steps succeeded: the check it seems to make never stops anything.

    It is evaluated as the runner does, once per job status (success, failure,
    cancelled) with every context unknown; literals and functions over literals
    are computed. Without a status function GitHub adds `success() &&` in front,
    so only the success status matters then. `success() || (failure() && x)` is
    not reported: x decides the result when something failed. Conditions with no
    real check (`true`, `always()`, `!cancelled()`) are written on purpose and
    are left out.
    """
    if not isinstance(condition, str):
        return False
    expr = condition.strip()
    if expr.startswith('${{') and expr.endswith('}}') and expr.count('${{') == 1:
        expr = expr[3:-2]
    elif '${{' in expr:
        return False
    tree = parse_expression(expr)
    if tree is None or not _restricts_something(tree):
        return False
    statuses = _STATUSES if _mentions_status(tree) else {'success': _STATUSES['success']}
    results = {name: _truthy(_evaluate(tree, status)) for name, status in statuses.items()}
    return results['success'] is True and None not in results.values()
