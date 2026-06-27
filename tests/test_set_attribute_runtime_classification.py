"""Runtime classification meta-tests for test_set_attribute read-only writes (lifecycle).

A write to a read-only attribute via C_SetAttributeValue is classified by effect:
- claimed success (no raise) AND the value actually changed -> fail (self-contradiction),
- claimed success but the value is unchanged (no-op) -> xfail (wrong code, no harm),
- rejected -> pass.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_VALUE,
    CKK_RSA,
    CKO_PUBLIC_KEY,
    CKR_ATTRIBUTE_READ_ONLY,
)
from pkcs11_check.testcases import test_set_attribute as tsa


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda n: True)


def _setup(monkeypatch: pytest.MonkeyPatch, *, accepted: bool, readback: dict) -> None:
    monkeypatch.setattr(tsa, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(tsa, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(tsa, "destroy_quietly", lambda *_a, **_k: None)
    if accepted:
        monkeypatch.setattr(tsa, "set_attributes", lambda *_a, **_k: None)
    else:

        def _reject(*_a: object, **_k: object) -> None:
            raise CkrAssertionError("rv", int(CKR_ATTRIBUTE_READ_ONLY))

        monkeypatch.setattr(tsa, "set_attributes", _reject)
    monkeypatch.setattr(tsa, "read_attributes", lambda *_a, **_k: dict(readback))


_CASES = {
    "class": (
        "test_cannot_change_class",
        "TestSetAttributeNegative",
        CKA_CLASS,
        CKO_PUBLIC_KEY,
    ),
    "key_type": (
        "test_cannot_change_key_type",
        "TestSetAttributeNegative",
        CKA_KEY_TYPE,
        CKK_RSA,
    ),
    "modulus": (
        "test_cannot_change_modulus",
        "TestSetAttributeNegative",
        CKA_MODULUS,
        b"\x00" * 256,
    ),
    "value": (
        "test_cannot_set_value_on_sensitive_key",
        "TestSetAttributeNegative",
        CKA_VALUE,
        b"\x00" * 32,
    ),
}


def _run(monkeypatch: pytest.MonkeyPatch, case: str, *, accepted: bool, changed: bool) -> None:
    method, cls, attr, new_val = _CASES[case]
    # When "changed", the read-back returns the new value; otherwise an unrelated
    # original value (use CKA_ID -> never equal to the attempted attr's new value).
    readback = {attr: new_val} if changed else {attr: b"\xff" * 1}
    if not changed:
        readback = {CKA_ID: b"orig"}
    _setup(monkeypatch, accepted=accepted, readback=readback)
    getattr(getattr(tsa, cls)(), method)(_session())


@pytest.mark.parametrize("case", list(_CASES))
def test_changed_fails(monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, case, accepted=True, changed=True)
    assert not isinstance(ei.value, XFailed)


@pytest.mark.parametrize("case", list(_CASES))
def test_noop_xfails(monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, case, accepted=True, changed=False)


@pytest.mark.parametrize("case", list(_CASES))
def test_rejected_passes(monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    _run(monkeypatch, case, accepted=False, changed=False)
