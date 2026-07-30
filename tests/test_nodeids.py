"""Unit tests for pytest node-id normalization (core/nodeids.py)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from pkcs11_check.core.nodeids import item_nodeid, normalize_nodeid


def test_posix_nodeid_unchanged() -> None:
    nid = "src/pkcs11_check/testcases/test_x.py::TestC::test_m[rsa-2048]"
    assert normalize_nodeid(nid) == nid


def test_windows_separators_converted() -> None:
    win = r"src\pkcs11_check\testcases\test_x.py::TestC::test_m[rsa-2048]"
    assert normalize_nodeid(win) == "src/pkcs11_check/testcases/test_x.py::TestC::test_m[rsa-2048]"


def test_only_path_portion_touched() -> None:
    # A backslash inside a parametrization id (after ::) must NOT be rewritten.
    nid = r"a\b.py::test_p[weird\id]"
    assert normalize_nodeid(nid) == r"a/b.py::test_p[weird\id]"


def test_no_separator_at_all() -> None:
    assert normalize_nodeid("test_x.py") == "test_x.py"
    assert normalize_nodeid("") == ""


def test_item_nodeid_passes_through_a_normal_nodeid() -> None:
    item = SimpleNamespace(nodeid=r"a\b.py::test_m", path=Path("/elsewhere/b.py"))
    # A usable path is present, so the item's own path must NOT override it.
    assert item_nodeid(item) == "a/b.py::test_m"


def test_item_nodeid_restores_a_path_pytest_dropped() -> None:
    """The cross-drive case: pytest emits "::test_m" with no file at all.

    rootdir is the common ancestor of the CWD and the args; two Windows paths on different
    drives have none, and pytest then yields an EMPTY path portion (measured on 9.1.1).
    Left alone, every same-named test in different files collapses onto one node-id.
    """
    item = SimpleNamespace(nodeid="::test_m", path=Path("/tmp/x/test_demo.py"))
    assert item_nodeid(item) == "/tmp/x/test_demo.py::test_m"


def test_item_nodeid_keeps_parametrization_when_restoring() -> None:
    item = SimpleNamespace(nodeid="::test_m[rsa-2048]", path=Path("/tmp/x/test_demo.py"))
    assert item_nodeid(item) == "/tmp/x/test_demo.py::test_m[rsa-2048]"


def test_item_nodeid_without_a_path_attribute_is_left_alone() -> None:
    # Nothing to restore from; degrading loudly beats inventing a path.
    item = SimpleNamespace(nodeid="::test_m", path=None)
    assert item_nodeid(item) == "::test_m"


def test_item_nodeid_does_not_touch_a_bare_file_nodeid() -> None:
    # A collector node (no "::") is a file, not a test; it must pass through untouched.
    item = SimpleNamespace(nodeid="test_x.py", path=Path("/tmp/test_x.py"))
    assert item_nodeid(item) == "test_x.py"
