"""Session-wide test checks."""

import pytest


def pytest_configure(config):
    # GitHub App auth signs JWTs with cryptography. Its tests must run, never
    # skip, so a missing install stops the whole session up front.
    try:
        import cryptography  # noqa: F401
    except ImportError:
        raise pytest.UsageError(
            'The cryptography package is required (GitHub App JWT signing). '
            "Run: pip install -r requirements.txt  (or pip install -e '.[test]')") from None
