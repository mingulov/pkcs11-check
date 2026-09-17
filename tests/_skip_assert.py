"""Shared assertion helper for "must skip, not xfail" regression tests.

``pytest.raises(pytest.skip.Exception)`` does NOT catch an imperative
``pytest.xfail()`` -- ``XFailed`` is a subclass of ``Failed``, not ``Skipped``, so a
mutated call that xfails instead of skipping escapes the ``with`` block and pytest
silently records the test outcome as "xfailed" rather than failing the assertion.
Use :func:`assert_skips` (or ``pytest.raises(SkipOrGuard.Skipped, match=...)``
manually is not enough) for every "must skip on this CKR" regression so a
reintroduced xfail is a loud hard failure, not a silent xfailed pass.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

import pytest
from _pytest.outcomes import Skipped, XFailed


def assert_skips(
    fn: Callable[..., Any], *args: Any, match: str | None = None, **kwargs: Any
) -> Skipped:
    """Call ``fn(*args, **kwargs)`` and assert it raises ``pytest.skip.Exception``.

    Returns the caught skip exception so callers can assert on its message
    (the ``with ... as exc_info`` equivalent is ``skipped = assert_skips(...)``).

    Fails hard (via ``pytest.fail``) if the call instead raises
    ``pytest.xfail.Exception`` (the classic "escaping XFailed" trap), returns without
    raising, or raises any other exception.
    """
    try:
        fn(*args, **kwargs)
    except pytest.skip.Exception as exc:
        if match is not None and not re.search(match, str(exc)):
            pytest.fail(f"skip message {str(exc)!r} did not match {match!r}")
        return exc
    except pytest.xfail.Exception as exc:
        pytest.fail(f"expected pytest.skip(), got pytest.xfail() instead: {exc}")
    pytest.fail(f"expected {fn} to call pytest.skip(), but it returned normally")


def assert_xfails(
    fn: Callable[..., Any], *args: Any, match: str | None = None, **kwargs: Any
) -> XFailed:
    """Call ``fn(*args, **kwargs)`` and assert it raises ``pytest.xfail.Exception``.

    Mirror of :func:`assert_skips` for the reverse trap: a bare
    ``pytest.raises(pytest.xfail.Exception)`` lets an escaping ``pytest.skip()``
    through, silently recording "skipped" instead of failing the assertion.
    """
    try:
        fn(*args, **kwargs)
    except pytest.xfail.Exception as exc:
        if match is not None and not re.search(match, str(exc)):
            pytest.fail(f"xfail message {str(exc)!r} did not match {match!r}")
        return exc
    except pytest.skip.Exception as exc:
        pytest.fail(f"expected pytest.xfail(), got pytest.skip() instead: {exc}")
    pytest.fail(f"expected {fn} to call pytest.xfail(), but it returned normally")
