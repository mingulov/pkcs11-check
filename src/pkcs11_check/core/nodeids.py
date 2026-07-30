r"""Normalize pytest node-ids to forward-slash form for platform-invariant matching.

pytest emits node-ids as ``<relative/path.py>::<Class>::<test>[<params>]``. On POSIX
the path uses ``/``; disabled-tests files and manifests store that form. To make
node-id comparison robust against any Windows pytest that emits OS-native (``\``)
separators, normalize the PATH portion (before the first ``::``) to ``/``. The test
and parametrization portion after ``::`` is left byte-identical.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def normalize_nodeid(nodeid: str) -> str:
    """Return ``nodeid`` with backslashes in the file-path portion replaced by ``/``.

    No-op where the path is already POSIX-form. Only the substring before the first
    ``::`` is rewritten, so a backslash inside a parametrization id is preserved.
    """
    head, sep, tail = nodeid.partition("::")
    return head.replace("\\", "/") + sep + tail


def item_nodeid(item: Any) -> str:
    """Normalized node-id for a pytest item, with a lost file path restored.

    pytest derives node-ids relative to ``rootdir``, and rootdir is the common ancestor of
    the CWD and the collection args. On Windows two paths on DIFFERENT DRIVES have no common
    ancestor, and pytest then emits a node-id whose path portion is EMPTY -- measured on
    pytest 9.1.1: collecting ``Z:\\test_demo.py`` with the CWD on ``C:`` yields
    ``::test_case``, while the same file on ``C:`` yields ``ctmp/test_demo.py::test_case``.
    (``bestrelpath`` is not at fault; asked directly it returns the absolute path.)

    That is not cosmetic. A node-id of ``::test_name`` carries no file identity, so every
    same-named test in different files collapses onto one id -- breaking per-test
    scheduling, disabled-tests matching and deselect for any user whose provider or
    installed test tree sits on a different drive from where they run. Windows CI hits it
    because its checkout is on ``D:`` while ``%TEMP%`` is on ``C:``.

    So when pytest gives no path, substitute the item's own absolute path. An absolute
    node-id is longer but unambiguous, which is the property everything downstream needs.
    """
    nodeid = normalize_nodeid(str(getattr(item, "nodeid", "")))
    head, sep, tail = nodeid.partition("::")
    if head or not sep:
        return nodeid
    path = getattr(item, "path", None)
    if path is None:
        return nodeid
    return Path(path).as_posix() + sep + tail
