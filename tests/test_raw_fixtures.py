"""Meta-tests for raw migration infrastructure."""

from __future__ import annotations

from pkcs11_check.fixtures import RawSession, p11_raw_session
from pkcs11_check.raw.recipes import create_object, get_mechanism_list


def test_create_object_importable() -> None:
    """create_object recipe exists and is importable."""
    assert callable(create_object)


def test_get_mechanism_list_importable() -> None:
    """get_mechanism_list recipe exists and is importable."""
    assert callable(get_mechanism_list)


def test_raw_session_importable() -> None:
    """RawSession dataclass exists and is importable."""
    assert RawSession is not None


def test_p11_raw_session_importable() -> None:
    """p11_raw_session fixture exists and is importable."""
    assert callable(p11_raw_session)
