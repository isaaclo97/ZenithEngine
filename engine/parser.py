import yaml


class WorkflowParseError(Exception):
    """Raised when the uploaded file isn't a valid single-document YAML
    mapping (e.g. malformed YAML, a multi-document stream like a Kubernetes
    manifest, an empty file, or a YAML file whose top level isn't a
    mapping). Callers can catch this to show a user-facing error instead of
    letting the raw parser exception propagate."""


def parse_workflow(file_path):
    """Parse a workflow YAML file into a Python dict plus its raw lines
    (used later to locate the line number of each finding).

    PyYAML reads the bare `on:` key as the boolean True (YAML 1.1 quirk), so
    it's normalized back to the string 'on'.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        raw_text = f.read()

    try:
        content = yaml.safe_load(raw_text)
    except yaml.YAMLError as e:
        raise WorkflowParseError(str(e)) from e

    if not isinstance(content, dict):
        raise WorkflowParseError(
            'The file is not a valid GitHub Actions workflow: '
            'its top level must be a single YAML mapping.'
        )

    if True in content:
        content['on'] = content.pop(True)

    lines = raw_text.splitlines()

    return content, lines


def find_line(lines, text, after=0):
    """Return the 1-indexed line number of the first line containing `text`
    after line `after`, or 0 if not found. Naive substring search: precise for
    unique tokens (a full `uses:` reference), approximate for common ones (a
    bare word)."""
    for i in range(after, len(lines)):
        if text in lines[i]:
            return i + 1
    return 0


def find_position(lines, text, line=0, col=0):
    """(0-indexed line, column just past the match) of the first occurrence of
    `text` at or after (line, col), or None. Lets a caller walk repeated
    occurrences of the same text one by one."""
    for i in range(line, len(lines)):
        j = lines[i].find(text, col if i == line else 0)
        if j != -1:
            return i, j + len(text)
    return None
