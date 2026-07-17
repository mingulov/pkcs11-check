r"""Normalize pytest node-ids to forward-slash form for platform-invariant matching.

pytest emits node-ids as ``<relative/path.py>::<Class>::<test>[<params>]``. On POSIX
the path uses ``/``; disabled-tests files and manifests store that form. To make
node-id comparison robust against any Windows pytest that emits OS-native (``\``)
separators, normalize the PATH portion (before the first ``::``) to ``/``. The test
and parametrization portion after ``::`` is left byte-identical.
"""

from __future__ import annotations


def normalize_nodeid(nodeid: str) -> str:
    """Return ``nodeid`` with backslashes in the file-path portion replaced by ``/``.

    No-op where the path is already POSIX-form. Only the substring before the first
    ``::`` is rewritten, so a backslash inside a parametrization id is preserved.
    """
    head, sep, tail = nodeid.partition("::")
    return head.replace("\\", "/") + sep + tail
