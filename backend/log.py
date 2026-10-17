"""Opt-in stdlib logging.

Debug-level logs are off by default — turn them on with `python3 server.py --debug`.
No secrets are ever logged; the settings module masks credentials before they
reach this layer. Free-form strings (URLs, paths, exception messages) are
scrubbed of control characters via `safe()` before being formatted into log
records to prevent log forging.
"""

import logging
import re
import sys


_CONTROL_CHARS = re.compile(r'[\x00-\x08\x0a-\x1f\x7f\x1b]')


def safe(value):
    """Return *value* coerced to str with control chars stripped.

    Use when logging anything that originates outside our process — gh stderr,
    repo names, manifest paths, exception messages, etc.
    """
    s = str(value)
    return _CONTROL_CHARS.sub('?', s)


def setup(debug=False):
    """Configure root logging. Idempotent."""
    root = logging.getLogger()
    if getattr(root, '_depexplorer_configured', False):
        return
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%H:%M:%S',
    ))
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if debug else logging.INFO)
    root._depexplorer_configured = True


def get(name):
    return logging.getLogger(name)
