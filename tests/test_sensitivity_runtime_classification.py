"""Runtime classification meta-tests for test_sensitivity policy reclassification.

The sensitive-value-read tests were wired inverted: they xfailed the violation
(value readable) and were effectively never able to pass on honest protection
because read_attributes omits unavailable attributes rather than raising. The
policy claim/effect-check fixes both directions:

- the key reads back CKA_SENSITIVE=True (claimed) AND the protected value is
  readable (violated) -> fail (claimed then violated),
- the key does not read back CKA_SENSITIVE=True (not claimed) -> xfail,
- claimed and the value is omitted (not readable) -> pass.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_UNAVAILABLE_INFORMATION,
    CKA_PRIVATE_EXPONENT,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_GENERAL_ERROR,
)
from pkcs11_check.testcases import test_sensitivity


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: True)


# --- AES CKA_VALUE --------------------------------------------------------


def _reads_aes(*, claimed: bool, value_readable: bool):  # type: ignore[no-untyped-def]
    def _read(_raw: object, _sh: object, _handle: object, attr_list: list[int]) -> dict[int, Any]:
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
    def _read(_raw: object, _sh: object, _handle: object, attr_list: list[int]) -> dict[int, Any]:
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


def test_missing_sensitive_claim_still_runs_raw_value_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[list[int]] = []

    def _read(_raw: object, _sh: object, _handle: object, attrs: list[int]) -> dict[int, Any]:
        reads.append(attrs)
        return {} if CKA_SENSITIVE in attrs else {CKA_VALUE: b"s" * 32}

    monkeypatch.setattr(test_sensitivity, "require_operational_aes_keygen", lambda *_a: None)
    monkeypatch.setattr(test_sensitivity, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_sensitivity, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(test_sensitivity, "read_attributes", _read)

    test_sensitivity.TestSensitiveKeyValue().test_sensitive_aes_value_not_readable(_session())

    assert reads == [[CKA_SENSITIVE], [CKA_VALUE]]
    assert C.get_records()[0].operation == "C_GetAttributeValue"
    assert C.get_records()[0].detail is not None
    detail = C.get_records()[0].detail
    assert detail is not None
    assert detail["attribute"]["id"] == int(CKA_SENSITIVE)


def test_mixed_sensitive_probe_is_not_short_circuited_by_missing_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    label = b"p11chk-mixed-sensitive"

    monkeypatch.setattr(test_sensitivity, "import_secret_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_sensitivity, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(test_sensitivity, "read_attributes", lambda *_a, **_k: {})

    calls = 0

    def _get_attribute(_session: int, _handle: int, attrs: Any, count: int) -> int:
        nonlocal calls
        calls += 1
        assert count == 2
        if calls == 1:
            attrs[0].ulValueLen = CK_UNAVAILABLE_INFORMATION
            attrs[1].ulValueLen = len(label)
            ctypes.memmove(attrs[1].pValue, label, len(label))
            return int(CKR_ATTRIBUTE_SENSITIVE)
        ctypes.memmove(attrs[1].pValue, label, len(label))
        attrs[1].ulValueLen = len(label)
        return int(CKR_ATTRIBUTE_SENSITIVE)

    raw = SimpleNamespace(C_GetAttributeValue=_get_attribute)
    test_sensitivity.TestSensitiveKeyValue().test_get_attribute_value_mixed_sensitive_template_continues(
        _session_with_raw(raw)
    )

    assert C.get_records()[0].operation == "C_GetAttributeValue"


def test_present_malformed_sensitive_flag_is_hard_after_value_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[list[int]] = []

    def _read(_raw: object, _sh: object, _handle: object, attrs: list[int]) -> dict[int, Any]:
        reads.append(attrs)
        if CKA_SENSITIVE in attrs:
            return {CKA_SENSITIVE: 0}
        return {}

    monkeypatch.setattr(test_sensitivity, "require_operational_aes_keygen", lambda *_a: None)
    monkeypatch.setattr(test_sensitivity, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_sensitivity, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(test_sensitivity, "read_attributes", _read)

    with pytest.raises(pytest.fail.Exception):
        test_sensitivity.TestSensitiveKeyValue().test_sensitive_aes_value_not_readable(_session())

    assert reads == [[CKA_SENSITIVE], [CKA_VALUE]]
    assert C.get_records()[-1].reason == "wrong_result"


def test_false_like_non_sensitive_value_is_present_and_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_sensitivity, "require_operational_aes_keygen", lambda *_a: None)
    monkeypatch.setattr(test_sensitivity, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_sensitivity, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        test_sensitivity,
        "read_attributes",
        lambda *_a, **_k: {CKA_VALUE: b""},
    )

    with pytest.raises(pytest.fail.Exception):
        test_sensitivity.TestSensitiveKeyValue().test_non_sensitive_aes_value_readable(_session())

    assert C.get_records()[0].reason == "wrong_result"


def test_rejected_sensitive_read_with_leak_keeps_hard_leak_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = bytes.fromhex("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f")
    monkeypatch.setattr(test_sensitivity, "import_secret_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_sensitivity, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        test_sensitivity,
        "read_attributes",
        lambda *_a, **_k: {CKA_SENSITIVE: True},
    )

    def _get_attribute(_session: int, _handle: int, attrs: Any, _count: int) -> int:
        ctypes.memmove(attrs[0].pValue, secret, len(secret))
        return int(CKR_GENERAL_ERROR)

    raw = SimpleNamespace(C_GetAttributeValue=_get_attribute)
    with pytest.raises(pytest.fail.Exception):
        test_sensitivity.TestSensitiveKeyValue().test_sensitive_value_not_copied_on_rejected_get_attribute(
            _session_with_raw(raw)
        )

    records = C.get_records()
    assert records[-1].reason == "self_contradiction"
    assert records[-1].operation == "C_GetAttributeValue"


@pytest.mark.parametrize("fragment_length", [1, 15])
def test_attribute_sensitive_short_fragment_leak_is_hard_without_claim(
    monkeypatch: pytest.MonkeyPatch,
    fragment_length: int,
) -> None:
    secret = bytes.fromhex("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f")
    monkeypatch.setattr(test_sensitivity, "import_secret_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_sensitivity, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(test_sensitivity, "read_attributes", lambda *_a, **_k: {})

    def _get_attribute(_session: int, _handle: int, attrs: Any, _count: int) -> int:
        ctypes.memmove(attrs[0].pValue, secret, fragment_length)
        return int(CKR_ATTRIBUTE_SENSITIVE)

    raw = SimpleNamespace(C_GetAttributeValue=_get_attribute)
    with pytest.raises(pytest.fail.Exception):
        test_sensitivity.TestSensitiveKeyValue().test_sensitive_value_not_copied_on_rejected_get_attribute(
            _session_with_raw(raw)
        )

    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.actual_ckr == "CKR_ATTRIBUTE_SENSITIVE"
    assert record.detail is not None
    assert record.detail["copied_fragment_length"] == fragment_length


def test_rejected_sensitive_read_zeroed_buffer_is_not_a_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provider zeroing the whole output must not match a secret's leading 00."""
    secret = bytes.fromhex("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f")
    monkeypatch.setattr(test_sensitivity, "import_secret_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_sensitivity, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(test_sensitivity, "read_attributes", lambda *_a, **_k: {})

    def _get_attribute(_session: int, _handle: int, attrs: Any, _count: int) -> int:
        ctypes.memset(attrs[0].pValue, 0, len(secret))
        attrs[0].ulValueLen = CK_UNAVAILABLE_INFORMATION
        return int(CKR_ATTRIBUTE_SENSITIVE)

    raw = SimpleNamespace(C_GetAttributeValue=_get_attribute)
    test_sensitivity.TestSensitiveKeyValue().test_sensitive_value_not_copied_on_rejected_get_attribute(
        _session_with_raw(raw)
    )
    assert not any(record.reason == "self_contradiction" for record in C.get_records())


@pytest.mark.parametrize(
    ("fragment_offset", "fragment_length"),
    [(8, 4), (24, 8)],
    ids=["interior", "suffix"],
)
@pytest.mark.parametrize("zero_first", [False, True])
@pytest.mark.parametrize("claimed", [False, True])
def test_rejected_sensitive_read_offset_fragment_leak_is_hard_without_claim(
    monkeypatch: pytest.MonkeyPatch,
    fragment_offset: int,
    fragment_length: int,
    zero_first: bool,
    claimed: bool,
) -> None:
    """Known bytes copied away from offset zero remain independently detectable."""
    secret = bytes.fromhex("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f")
    monkeypatch.setattr(test_sensitivity, "import_secret_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_sensitivity, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        test_sensitivity,
        "read_attributes",
        lambda *_a, **_k: {CKA_SENSITIVE: True} if claimed else {},
    )

    def _get_attribute(_session: int, _handle: int, attrs: Any, _count: int) -> int:
        if zero_first:
            ctypes.memset(attrs[0].pValue, 0, len(secret))
        destination = int(attrs[0].pValue) + fragment_offset
        ctypes.memmove(
            destination,
            secret[fragment_offset : fragment_offset + fragment_length],
            fragment_length,
        )
        return int(CKR_ATTRIBUTE_SENSITIVE)

    raw = SimpleNamespace(C_GetAttributeValue=_get_attribute)
    with pytest.raises(pytest.fail.Exception):
        test_sensitivity.TestSensitiveKeyValue().test_sensitive_value_not_copied_on_rejected_get_attribute(
            _session_with_raw(raw)
        )

    record = C.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.detail is not None
    assert record.detail["copied_fragment_offset"] == fragment_offset
    assert record.detail["copied_fragment_length"] == fragment_length


@pytest.mark.parametrize("rv", [CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL])
@pytest.mark.parametrize("reported_length", [0, 100, CK_UNAVAILABLE_INFORMATION])
def test_mixed_partial_return_validates_length_before_inspecting_bytes(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
    reported_length: int,
) -> None:
    monkeypatch.setattr(test_sensitivity, "import_secret_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_sensitivity, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        test_sensitivity, "read_attributes", lambda *_a, **_k: {CKA_SENSITIVE: True}
    )

    def _get_attribute(_session: int, _handle: int, attrs: Any, _count: int) -> int:
        attrs[0].ulValueLen = CK_UNAVAILABLE_INFORMATION
        attrs[1].ulValueLen = reported_length
        return int(rv)

    unavailable = reported_length == CK_UNAVAILABLE_INFORMATION
    expected_exception = pytest.xfail.Exception if unavailable else pytest.fail.Exception
    with pytest.raises(expected_exception) as raised:
        test_sensitivity.TestSensitiveKeyValue().test_get_attribute_value_mixed_sensitive_template_continues(
            _session_with_raw(SimpleNamespace(C_GetAttributeValue=_get_attribute))
        )
    records = C.get_records()
    assert any(record.reason == "nonspec_reject" for record in records)
    row_record = next(record for record in records if "safe row" in record.label)
    assert row_record.reason == ("not_operational" if unavailable else "wrong_result")
    assert row_record.operation == "C_GetAttributeValue"
    assert row_record.detail is not None
    assert row_record.detail["actual"] == reported_length
    assert not any(record.label.endswith("safe row value") for record in records)
    if not unavailable:
        assert getattr(raised.value, "_pkcs11_check_classification") == row_record


def test_mixed_probe_keeps_safe_row_independent_when_claim_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    label = b"p11chk-mixed-sensitive"
    monkeypatch.setattr(test_sensitivity, "import_secret_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_sensitivity, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(test_sensitivity, "read_attributes", lambda *_a, **_k: {})

    def _get_attribute(_session: int, _handle: int, attrs: Any, _count: int) -> int:
        attrs[0].ulValueLen = CK_UNAVAILABLE_INFORMATION
        attrs[1].ulValueLen = len(label) - 1
        return int(CKR_ATTRIBUTE_SENSITIVE)

    raw = SimpleNamespace(C_GetAttributeValue=_get_attribute)
    with pytest.raises(pytest.fail.Exception):
        test_sensitivity.TestSensitiveKeyValue().test_get_attribute_value_mixed_sensitive_template_continues(
            _session_with_raw(raw)
        )
    assert any(
        record.label == "C_GetAttributeValue mixed safe row length" for record in C.get_records()
    )


@pytest.mark.parametrize("rv", [CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL])
def test_mixed_partial_return_checks_safe_row_with_claim(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
) -> None:
    label = b"p11chk-mixed-sensitive"
    monkeypatch.setattr(test_sensitivity, "import_secret_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_sensitivity, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        test_sensitivity,
        "read_attributes",
        lambda *_a, **_k: {CKA_SENSITIVE: True},
    )

    def _get_attribute(_session: int, _handle: int, attrs: Any, _count: int) -> int:
        attrs[0].ulValueLen = CK_UNAVAILABLE_INFORMATION
        attrs[1].ulValueLen = len(label)
        ctypes.memmove(attrs[1].pValue, label, len(label))
        return int(rv)

    raw = SimpleNamespace(C_GetAttributeValue=_get_attribute)
    with pytest.raises(pytest.xfail.Exception):
        test_sensitivity.TestSensitiveKeyValue().test_get_attribute_value_mixed_sensitive_template_continues(
            _session_with_raw(raw)
        )
    assert any(
        record.reason == "nonspec_reject" and record.actual_ckr is not None
        for record in C.get_records()
    )


def test_extractable_attribute_type_invalid_is_visible_deviation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_sensitivity, "require_operational_aes_keygen", lambda *_a: None)
    monkeypatch.setattr(test_sensitivity, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_sensitivity, "destroy_quietly", lambda *_a, **_k: None)

    def _read(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise CkrAssertionError("CKA_EXTRACTABLE unsupported", int(CKR_ATTRIBUTE_TYPE_INVALID))

    monkeypatch.setattr(test_sensitivity, "read_attributes", _read)

    with pytest.raises(pytest.xfail.Exception):
        test_sensitivity.TestExtractableEnforcement().test_non_extractable_by_default(_session())

    records = C.get_records()
    assert records[-1].reason == "honest_deviation"
    assert records[-1].operation == "C_GetAttributeValue"
    assert records[-1].mechanism == "CKM_AES_KEY_GEN"
    assert records[-1].actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"


def _session_with_raw(raw: object) -> SimpleNamespace:
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)
