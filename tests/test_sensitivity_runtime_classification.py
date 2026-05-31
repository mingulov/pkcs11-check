"""Runtime classification meta-tests for test_sensitivity Type-B reclassification.

The sensitive-value-read tests were wired inverted: they xfailed the violation
(value readable) and were effectively never able to pass on honest protection
because read_attributes omits unavailable attributes rather than raising. The
Type-B claim/effect-check fixes both directions:

- the key reads back CKA_SENSITIVE=True (claimed) AND the protected value is
  readable (violated) -> fail (claimed then violated),
- the key does not read back CKA_SENSITIVE=True (not claimed) -> xfail,
- claimed and the value is omitted (not readable) -> pass.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKA_PRIVATE_EXPONENT,
    CKA_SENSITIVE,
    CKA_VALUE,
)
from pkcs11_check.testcases import test_sensitivity


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: True)


# --- AES CKA_VALUE --------------------------------------------------------


def _reads_aes(*, claimed: bool, value_readable: bool):  # type: ignore[no-untyped-def]
    def _read(_raw: object, _sh: object, _handle: object, attr_list: list[int]) -> dict:
        if CKA_SENSITIVE in attr_list:
            return {CKA_SENSITIVE: True} if claimed else {CKA_SENSITIVE: False}
        if CKA_VALUE in attr_list:
            return {CKA_VALUE: b"\x00" * 32} if value_readable else {}
        return {}

    return _read


def _run_aes(monkeypatch: pytest.MonkeyPatch, *, claimed: bool, value_readable: bool) -> None:
    monkeypatch.setattr(test_sensitivity, "require_operational_aes_keygen", lambda *_a: None)
    monkeypatch.setattr(test_sensitivity, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_sensitivity, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        test_sensitivity,
        "read_attributes",
        _reads_aes(claimed=claimed, value_readable=value_readable),
    )
    test_sensitivity.TestSensitiveKeyValue().test_sensitive_aes_value_not_readable(_session())


def test_aes_claimed_and_readable_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as excinfo:
        _run_aes(monkeypatch, claimed=True, value_readable=True)
    assert not isinstance(excinfo.value, XFailed)


def test_aes_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_aes(monkeypatch, claimed=False, value_readable=True)


def test_aes_claimed_and_protected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_aes(monkeypatch, claimed=True, value_readable=False)


# --- RSA CKA_PRIVATE_EXPONENT --------------------------------------------


def _reads_rsa(*, claimed: bool, value_readable: bool):  # type: ignore[no-untyped-def]
    def _read(_raw: object, _sh: object, _handle: object, attr_list: list[int]) -> dict:
        if CKA_SENSITIVE in attr_list:
            return {CKA_SENSITIVE: True} if claimed else {CKA_SENSITIVE: False}
        if CKA_PRIVATE_EXPONENT in attr_list:
            return {CKA_PRIVATE_EXPONENT: b"\x00" * 256} if value_readable else {}
        return {}

    return _read


def _run_rsa(monkeypatch: pytest.MonkeyPatch, *, claimed: bool, value_readable: bool) -> None:
    monkeypatch.setattr(test_sensitivity, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(test_sensitivity, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        test_sensitivity,
        "read_attributes",
        _reads_rsa(claimed=claimed, value_readable=value_readable),
    )
    test_sensitivity.TestSensitiveKeyValue().test_sensitive_rsa_private_exponent_not_readable(
        _session()
    )


def test_rsa_claimed_and_readable_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as excinfo:
        _run_rsa(monkeypatch, claimed=True, value_readable=True)
    assert not isinstance(excinfo.value, XFailed)


def test_rsa_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_rsa(monkeypatch, claimed=False, value_readable=True)


def test_rsa_claimed_and_protected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_rsa(monkeypatch, claimed=True, value_readable=False)
