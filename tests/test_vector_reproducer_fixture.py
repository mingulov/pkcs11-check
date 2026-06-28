"""The autouse vector-context helper attaches a parametrized vector's source/vector_id
to the classification context, so every classify() (incl. not_operational/xfail paths)
carries the reproducer handle without per-emission-site wiring."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C
from pkcs11_check.testcases.conftest import set_vector_context_from_node


def _node(**params: Any) -> SimpleNamespace:
    return SimpleNamespace(callspec=SimpleNamespace(params=params))


def test_helper_sets_context_from_vec_dict() -> None:
    C.clear()
    set_vector_context_from_node(
        _node(vec={"_source": "wycheproof:demo_test.json", "_vector_id": "tcId=7", "tcId": 7})
    )
    with pytest.raises(BaseException):  # noqa: B017,PT011 - classify() raises the outcome
        C.classify("not_operational", mechanism="CKM_RSA_PKCS")
    rec = C.serialize(C.get_records())[-1]
    assert rec["source"] == "wycheproof:demo_test.json"
    assert rec["vector_id"] == "tcId=7"


def test_helper_noop_without_vector_dict() -> None:
    C.clear()
    set_vector_context_from_node(_node(vec_id="tc1", n=5))  # no dict-with-_source param
    with pytest.raises(BaseException):  # noqa: B017,PT011
        C.classify("not_operational", mechanism="CKM_RSA_PKCS")
    rec = C.serialize(C.get_records())[-1]
    assert rec["source"] is None and rec["vector_id"] is None


def test_helper_noop_when_no_callspec() -> None:
    C.clear()
    set_vector_context_from_node(SimpleNamespace())  # not parametrized
    assert C.get_records() == []
