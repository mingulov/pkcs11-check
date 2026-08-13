"""Self-describing diagnostics for a failed pytest collection (GH #3).

Two collectors run pytest to enumerate tests: ``collection.py`` (item metadata, used by
``test``) and ``_unit_discovery.py`` (node-ids, used by ``list-tests``). Both used to
report a failure as

    pytest metadata collection failed: <stderr or stdout>

which drops one of the two streams and says nothing about the environment. A user hit
"ERROR: found no collectors for ...\\testcases" on Windows and neither of us could tell
whether the path was missing, unreadable, empty, or fine -- the run could not start and
the tool could not say why. This module builds one message that answers those questions
up front, so the next report arrives diagnosable.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

_MAX_STREAM = 4000


def _describe_target(raw_target: str) -> str:
    """One line on a collection target: does it exist, is it readable, what is in it."""
    # A node-id target ("file.py::test") only makes sense as its file part on disk.
    path = Path(raw_target.split("::", 1)[0])
    try:
        if not path.exists():
            return f"  {raw_target}: does not exist"
        if path.is_file():
            return f"  {raw_target}: file, {path.stat().st_size} bytes"
        test_files = list(path.rglob("test_*.py"))
        readable = "readable" if _is_readable(path) else "NOT READABLE"
        return f"  {raw_target}: directory, {readable}, {len(test_files)} test_*.py files"
    except OSError as exc:
        # Permission denied, a vanished mount, an AV/indexer lock on Windows: all are
        # answers to "why did collection fail", so report rather than swallow.
        return f"  {raw_target}: cannot stat ({type(exc).__name__}: {exc})"


def _is_readable(path: Path) -> bool:
    try:
        next(path.iterdir(), None)
    except OSError:
        return False
    return True


def _stream_excerpt(label: str, text: str) -> list[str]:
    stripped = text.strip()
    if not stripped:
        return [f"{label}: (empty)"]
    if len(stripped) > _MAX_STREAM:
        omitted = len(stripped) - _MAX_STREAM
        half = _MAX_STREAM // 2
        # Head AND tail: a traceback's exception is on the last line.
        stripped = f"{stripped[:half]}\n... [{omitted} chars omitted] ...\n{stripped[-half:]}"
    return [f"{label}:", stripped]


def collection_failure_message(
    *,
    returncode: int,
    stdout: str,
    stderr: str,
    targets: Sequence[str],
    pytest_args: Sequence[str],
) -> str:
    """Build a collection-failure message that explains itself.

    Reports BOTH streams (pytest writes collection errors to stdout, so an
    ``stderr or stdout`` choice loses them), the exit code, every target with whether it
    exists / is readable / holds test files, the pytest arguments, and the interpreter.
    """
    target_lines = [_describe_target(target) for target in targets] or ["  (none given)"]
    lines = [
        f"pytest collection failed with exit code {returncode}.",
        "",
        "targets:",
        *target_lines,
        "",
        f"pytest args: {list(pytest_args)}",
        f"interpreter: {sys.executable}",
        f"cwd: {Path.cwd()}",
        "",
        *_stream_excerpt("stdout", stdout),
        *_stream_excerpt("stderr", stderr),
        "",
        "If the target looks fine, retry with PKCS11_CHECK_NO_COLLECTION_CACHE=1 to rule "
        "out the collection cache.",
    ]
    return "\n".join(lines)
