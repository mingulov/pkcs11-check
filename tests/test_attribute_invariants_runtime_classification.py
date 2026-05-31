"""Runtime classification meta-tests for test_attribute_invariants (Type D).

Type D = derived-attribute invariant. A suite-generated key created with
``CKA_EXTRACTABLE=False`` and never modified MUST read back
``CKA_NEVER_EXTRACTABLE=True`` (PKCS#11 v3.1 Sec.4.9.4); a key created with
``CKA_SENSITIVE=True`` and never modified MUST read back
``CKA_ALWAYS_SENSITIVE=True``.

The classification (3-way):

- precondition holds (the base attribute reads back the protective value) AND
  the derived attribute contradicts it (False) -> ``fail`` (self-contradiction),
- the derived attribute is absent / unsupported -> ``xfail`` (honest non-support),
- the base attribute itself did not take effect (isolated wrong value, not the
  derived-invariant contradiction under test) -> ``xfail``,
- precondition holds and the derived attribute agrees (True) -> ``pass``.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKA_ALWAYS_SENSITIVE,
    CKA_EXTRACTABLE,
    CKA_NEVER_EXTRACTABLE,
    CKA_SENSITIVE,
)
from pkcs11_check.testcases import test_attribute_invariants as tai


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: True)


def _reader(values: dict[int, object]):  # type: ignore[no-untyped-def]
    """read_attributes stub returning only the requested+present attributes."""

    def _read(_raw: object, _sh: object, _handle: object, attr_list: list[int]) -> dict:
        return {a: values[a] for a in attr_list if a in values}

    return _read


def _setup(monkeypatch: pytest.MonkeyPatch, values: dict[int, object]) -> None:
    monkeypatch.setattr(tai, "require_operational_aes_keygen", lambda *_a: None)
    monkeypatch.setattr(tai, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(tai, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tai, "read_attributes", _reader(values))


# --- NEVER_EXTRACTABLE invariant -----------------------------------------


def _run_never_extractable(monkeypatch: pytest.MonkeyPatch, values: dict[int, object]) -> None:
    _setup(monkeypatch, values)
    tai.TestDerivedAttributeInvariants().test_never_extractable_when_created_non_extractable(
        _session()
    )


def test_never_extractable_contradiction_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    # EXTRACTABLE=False (precondition holds) but NEVER_EXTRACTABLE=False -> contradiction.
    with pytest.raises(Failed) as ei:
        _run_never_extractable(
            monkeypatch,
            {CKA_EXTRACTABLE: False, CKA_NEVER_EXTRACTABLE: False},
        )
    assert not isinstance(ei.value, XFailed)


def test_never_extractable_absent_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    # NEVER_EXTRACTABLE not reported (unsupported) -> honest non-support.
    with pytest.raises(pytest.xfail.Exception):
        _run_never_extractable(monkeypatch, {CKA_EXTRACTABLE: False})


def test_never_extractable_base_not_applied_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    # EXTRACTABLE read back True: the module ignored our False request -- an
    # isolated wrong value, not the derived-invariant contradiction under test.
    with pytest.raises(pytest.xfail.Exception):
        _run_never_extractable(
            monkeypatch,
            {CKA_EXTRACTABLE: True, CKA_NEVER_EXTRACTABLE: False},
        )


def test_never_extractable_consistent_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_never_extractable(
        monkeypatch,
        {CKA_EXTRACTABLE: False, CKA_NEVER_EXTRACTABLE: True},
    )


# --- ALWAYS_SENSITIVE invariant ------------------------------------------


def _run_always_sensitive(monkeypatch: pytest.MonkeyPatch, values: dict[int, object]) -> None:
    _setup(monkeypatch, values)
    tai.TestDerivedAttributeInvariants().test_always_sensitive_when_created_sensitive(_session())


def test_always_sensitive_contradiction_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_always_sensitive(
            monkeypatch,
            {CKA_SENSITIVE: True, CKA_ALWAYS_SENSITIVE: False},
        )
    assert not isinstance(ei.value, XFailed)


def test_always_sensitive_absent_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_always_sensitive(monkeypatch, {CKA_SENSITIVE: True})


def test_always_sensitive_base_not_applied_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_always_sensitive(
            monkeypatch,
            {CKA_SENSITIVE: False, CKA_ALWAYS_SENSITIVE: False},
        )


def test_always_sensitive_consistent_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_always_sensitive(
        monkeypatch,
        {CKA_SENSITIVE: True, CKA_ALWAYS_SENSITIVE: True},
    )
