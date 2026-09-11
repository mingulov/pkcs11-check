"""Runtime classification meta-test for ckr/test_ckr_spec_compliance sensitive read (policy)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.types_std import CKA_SENSITIVE, CKA_VALUE
from pkcs11_check.testcases.ckr import test_ckr_spec_compliance as tcsc


def _run(monkeypatch: pytest.MonkeyPatch, *, claimed: bool, readable: bool) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(tcsc, "destroy_quietly", lambda *_a, **_k: None)

    def _read(_raw: object, _sh: object, _h: object, attrs: list[int]) -> dict:
        if CKA_SENSITIVE in attrs:
            return {CKA_SENSITIVE: True} if claimed else {CKA_SENSITIVE: False}
        if CKA_VALUE in attrs:
            return {CKA_VALUE: b"\x00" * 32} if readable else {}
        return {}

    monkeypatch.setattr(tcsc, "read_attributes", _read)
    tcsc.TestCKRAttributeCompliance().test_sensitive_value_returns_attribute_sensitive(
        SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda n: True)
    )


def test_claimed_readable_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, claimed=True, readable=True)
    assert not isinstance(ei.value, XFailed)


def test_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, claimed=False, readable=True)


def test_protected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, claimed=True, readable=False)


def test_sensitive_readback_absent_is_recorded_as_policy_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_SENSITIVE absence still feeds the claimed/violated policy oracle via
    the creation-time claim fallback, so the absence record must be
    kind="policy", not the helper's kind="metadata" default.
    """
    from pkcs11_check import classification as C  # noqa: N812

    monkeypatch.setattr(raw_recipes, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(tcsc, "destroy_quietly", lambda *_a, **_k: None)

    def _read(_raw: object, _sh: object, _h: object, attrs: list[int]) -> dict:
        return {}

    monkeypatch.setattr(tcsc, "read_attributes", _read)
    tcsc.TestCKRAttributeCompliance().test_sensitive_value_returns_attribute_sensitive(
        SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda n: True)
    )

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].kind == "policy"
