"""Keep .dockerignore's enumerated allowlist in sync with the tracked files
it is supposed to ship.

.dockerignore allowlists exact files (not directories) under backend/, css/,
and js/ so an untracked local file in those directories can never reach a
`docker build .` image (see .dockerignore's header comment and
docs/aws-deployment.md's git-archive-based build). That only works if the
enumerated list stays in sync with what git actually tracks: a new tracked
file that's missing from .dockerignore silently ships without, breaking the
app at import/serve time instead of failing this test up front.
"""

import os
import subprocess

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCKERIGNORE = os.path.join(REPO_ROOT, ".dockerignore")

# The exact set of top-level paths the image is supposed to serve/run.
# Mirrors the FROM/COPY contract in Dockerfile + server.py's static roots.
SHIPPED_ROOTS = ["server.py", "index.html", "LICENSE", "NOTICE", "backend", "css", "js"]


def _tracked_files():
    out = subprocess.run(
        ["git", "ls-files"] + SHIPPED_ROOTS,
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=20, check=True,
    ).stdout
    return {line for line in out.splitlines() if line}


def _dockerignore_allowlisted_files():
    """Return the exact-file `!path` entries, ignoring comments and the
    directory-wildcard housekeeping lines (`**/__pycache__`, `**/*.pyc`)."""
    allowed = set()
    with open(DOCKERIGNORE) as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("!"):
                continue
            path = line[1:]
            if path.endswith("/") or path.startswith("**"):
                continue
            allowed.add(path)
    return allowed


def test_dockerignore_allowlists_exactly_the_tracked_shipped_files():
    tracked = _tracked_files()
    allowed = _dockerignore_allowlisted_files()
    missing = tracked - allowed
    extra = allowed - tracked
    assert not missing, (
        f".dockerignore is missing {sorted(missing)}: these tracked files won't "
        f"ship in the image. Add `!<path>` entries for them."
    )
    assert not extra, (
        f".dockerignore allowlists {sorted(extra)}, which git no longer tracks: "
        f"remove the stale `!<path>` entries."
    )


def test_dockerignore_has_no_directory_level_allowlist_entries():
    """A directory-level `!dir/` entry re-includes every file under it by
    path, including untracked ones — the exact gap this allowlist exists to
    close. Only exact files and the pycache/pyc housekeeping globs belong
    here."""
    with open(DOCKERIGNORE) as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("!"):
                continue
            path = line[1:]
            assert not (path.endswith("/") and not path.startswith("**")), (
                f"{line!r} is a directory-level allowlist entry; enumerate exact "
                f"files under it instead so untracked files aren't re-included."
            )
