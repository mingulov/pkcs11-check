"""Regression tests for security CVE testcase behavior."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

import pkcs11_check.compliance as compliance
from pkcs11_check import classification as C  # noqa: N812 - matches project convention
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.security import test_cve_regression
from tests._skip_assert import assert_skips

_MISSING = object()

_MISSING = object()


class _EncryptStateRaw:
    def __init__(self) -> None:
        self.active = False
        self.abort_count = 0

    def C_EncryptFinal(self, *_args: Any) -> int:  # noqa: N802 - raw PKCS#11 API shape
        self.active = False
        self.abort_count += 1
        return 0


class _KeygenRejectRaw(_EncryptStateRaw):
    def C_GenerateKey(self, *_args: Any) -> int:  # noqa: N802 - raw PKCS#11 API shape
        return int(CKR_FUNCTION_NOT_SUPPORTED)


def _session(raw: Any, *mechanisms: str) -> SimpleNamespace:
    supported = set(mechanisms) or {
        "AES_ECB",
        "AES_KEY_GEN",
        "RSA_PKCS_KEY_PAIR_GEN",
        "SHA256_RSA_PKCS",
    }
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda name: name in supported)


def _raise_function_not_supported(*_args: Any, **_kwargs: Any) -> int:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
        int(CKR_FUNCTION_NOT_SUPPORTED),
    )


def _run_tookan_sensitive_unwrap_until_wrap(
    monkeypatch: pytest.MonkeyPatch,
    wrap_exc: CkrAssertionError,
) -> None:
    monkeypatch.setattr(test_cve_regression, "gen_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        test_cve_regression,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_SENSITIVE: True, CKA_EXTRACTABLE: True},
    )
    monkeypatch.setattr(
        test_cve_regression,
        "wrap_key_recipe",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(wrap_exc),
    )

    test_cve_regression.TestTookanUnwrapAttrs().test_unwrapped_key_cannot_unset_sensitive(
        _session(_EncryptStateRaw(), "AES_KEY_WRAP", "AES_KEY_GEN")
    )


def test_aes_ecb_boundary_lengths_aborts_after_rejected_invalid_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _EncryptStateRaw()

    def _encrypt_single(_raw: Any, _sh: int, _key: int, _mech: int, data: bytes) -> bytes:
        if raw.active:
            raise AssertionError("Unexpected CK_RV CKR_OPERATION_ACTIVE")
        if len(data) % 16 != 0 or len(data) == 0:
            raw.active = True
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_DATA_LEN_RANGE",
                int(CKR_DATA_LEN_RANGE),
            )
        return data

    monkeypatch.setattr(test_cve_regression, "gen_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_cve_regression, "encrypt_single", _encrypt_single)
    monkeypatch.setattr(test_cve_regression, "decrypt_single", lambda *_args: _args[4])
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_args: None)

    test_cve_regression.TestBoundaryLengthCrypto().test_aes_ecb_boundary_lengths(_session(raw))

    assert raw.abort_count >= 4


def test_aes_ecb_boundary_lengths_fails_when_nonaligned_input_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _EncryptStateRaw()

    def _encrypt_single(_raw: Any, _sh: int, _key: int, _mech: int, data: bytes) -> bytes:
        if len(data) % 16 == 0 and len(data) > 0:
            return data
        if len(data) == 1:
            return b"accepted"
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_DATA_LEN_RANGE",
            int(CKR_DATA_LEN_RANGE),
        )

    monkeypatch.setattr(test_cve_regression, "gen_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_cve_regression, "encrypt_single", _encrypt_single)
    monkeypatch.setattr(test_cve_regression, "decrypt_single", lambda *_args: _args[4])
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="accepted non-block-aligned"):
        test_cve_regression.TestBoundaryLengthCrypto().test_aes_ecb_boundary_lengths(_session(raw))


def test_aes_ecb_boundary_lengths_does_not_mask_non_ckr_assertion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _EncryptStateRaw()
    monkeypatch.setattr(test_cve_regression, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        test_cve_regression,
        "encrypt_single",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("harness oracle failed")),
    )
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_a: None)

    with pytest.raises(AssertionError, match="harness oracle failed"):
        test_cve_regression.TestBoundaryLengthCrypto().test_aes_ecb_boundary_lengths(_session(raw))


def test_aes_ecb_boundary_lengths_surfaces_unexpected_clean_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _EncryptStateRaw()
    monkeypatch.setattr(test_cve_regression, "gen_aes_key", lambda *_a, **_k: 1)

    def _encrypt_single(_raw: Any, _sh: int, _key: int, _mech: int, data: bytes) -> bytes:
        if len(data) % 16 == 0 and data:
            return data
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_INVALID",
            int(CKR_MECHANISM_INVALID),
        )

    monkeypatch.setattr(
        test_cve_regression,
        "encrypt_single",
        _encrypt_single,
    )
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.xfail.Exception, match="AES-ECB non-block-aligned"):
        test_cve_regression.TestBoundaryLengthCrypto().test_aes_ecb_boundary_lengths(_session(raw))


def test_aes_ecb_boundary_lengths_skips_without_aes_ecb(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _EncryptStateRaw()

    def _unexpected_keygen(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("AES setup should not run without AES_ECB")

    monkeypatch.setattr(test_cve_regression, "gen_aes_key", _unexpected_keygen)

    assert_skips(
        test_cve_regression.TestBoundaryLengthCrypto().test_aes_ecb_boundary_lengths,
        _session(raw, "AES_KEY_GEN"),
        match="AES_ECB not supported",
    )


def test_aes_ecb_boundary_lengths_xfails_when_advertised_keygen_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_cve_regression, "gen_aes_key", _raise_function_not_supported)

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_cve_regression.TestBoundaryLengthCrypto().test_aes_ecb_boundary_lengths(
            _session(_EncryptStateRaw(), "AES_ECB", "AES_KEY_GEN")
        )


def test_tookan_sensitive_unwrap_skips_explicit_key_not_wrappable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert_skips(
        _run_tookan_sensitive_unwrap_until_wrap,
        monkeypatch,
        CkrAssertionError(
            "Unexpected CK_RV CKR_KEY_NOT_WRAPPABLE",
            int(CKR_KEY_NOT_WRAPPABLE),
        ),
        match="cannot wrap SENSITIVE=True",
    )


def test_tookan_sensitive_unwrap_xfails_generic_wrap_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="sensitive-key wrap rejected"):
        _run_tookan_sensitive_unwrap_until_wrap(
            monkeypatch,
            CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR)),
        )


def test_tookan_sensitive_unwrap_records_unbound_extraction_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_cve_regression, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(test_cve_regression, "wrap_key_recipe", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(test_cve_regression, "unwrap_key", lambda *_a, **_k: 2)
    monkeypatch.setattr(
        test_cve_regression,
        "classify",
        lambda *_a, **_k: pytest.fail("unbound Tookan path must not classify output control"),
    )
    notes: list[str] = []
    monkeypatch.setattr(
        compliance,
        "note",
        lambda description, *_a, **_k: notes.append(description),
    )
    reads: list[list[int]] = []

    def _read(_raw: object, _sh: object, _handle: object, attrs: list[int]) -> dict[int, object]:
        reads.append(attrs)
        if CKA_VALUE in attrs:
            return {
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_VALUE: b"\x11" * 16,
            }
        return {CKA_SENSITIVE: True, CKA_EXTRACTABLE: True}

    monkeypatch.setattr(test_cve_regression, "read_attributes", _read)
    test_cve_regression.TestTookanUnwrapAttrs().test_unwrapped_key_cannot_unset_sensitive(
        _session(_EncryptStateRaw(), "AES_KEY_WRAP", "AES_KEY_GEN")
    )
    assert reads[0] == [CKA_SENSITIVE, CKA_EXTRACTABLE]
    assert reads[-1] == [CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_VALUE]
    assert notes and "unbound" in notes[0]
    assert "downgrade" in notes[0]
    assert "CKA_SENSITIVE=False" in notes[0]
    assert "CKA_VALUE readable=True" in notes[0]


@pytest.mark.parametrize(
    "reject_rv",
    [
        CKR_TEMPLATE_INCONSISTENT,
        CKR_ATTRIBUTE_VALUE_INVALID,
        CKR_ATTRIBUTE_READ_ONLY,
        CKR_ACTION_PROHIBITED,
    ],
)
def test_tookan_sensitive_unwrap_clean_refusal_is_visible_xfail(
    monkeypatch: pytest.MonkeyPatch,
    reject_rv: int,
) -> None:
    monkeypatch.setattr(test_cve_regression, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        test_cve_regression,
        "read_attributes",
        lambda *_a, **_k: {CKA_SENSITIVE: True, CKA_EXTRACTABLE: True},
    )
    monkeypatch.setattr(test_cve_regression, "wrap_key_recipe", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(
        test_cve_regression,
        "unwrap_key",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError(f"rv={reject_rv}", int(reject_rv))
        ),
    )

    with pytest.raises(pytest.xfail.Exception):
        test_cve_regression.TestTookanUnwrapAttrs().test_unwrapped_key_cannot_unset_sensitive(
            _session(_EncryptStateRaw(), "AES_KEY_WRAP", "AES_KEY_GEN")
        )


def _run_tookan_unbound_result(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sensitive: object = False,
    extractable: object = True,
    value: object = b"\x11" * 16,
) -> list[str]:
    monkeypatch.setattr(test_cve_regression, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(test_cve_regression, "wrap_key_recipe", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(test_cve_regression, "unwrap_key", lambda *_a, **_k: 2)
    notes: list[str] = []
    monkeypatch.setattr(
        compliance,
        "note",
        lambda description, *_a, **_k: notes.append(description),
    )

    def _read(_raw: object, _sh: object, _handle: object, attrs: list[int]) -> dict[int, object]:
        if CKA_VALUE in attrs:
            result: dict[int, object] = {CKA_VALUE: value}
            if sensitive is not _MISSING:
                result[CKA_SENSITIVE] = sensitive
            if extractable is not _MISSING:
                result[CKA_EXTRACTABLE] = extractable
            return result
        return {CKA_SENSITIVE: True, CKA_EXTRACTABLE: True}

    monkeypatch.setattr(test_cve_regression, "read_attributes", _read)
    test_cve_regression.TestTookanUnwrapAttrs().test_unwrapped_key_cannot_unset_sensitive(
        _session(_EncryptStateRaw(), "AES_KEY_WRAP", "AES_KEY_GEN")
    )
    return notes


def _run_tookan_preservation_result(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sensitive: object = True,
    extractable: object = False,
) -> None:
    monkeypatch.setattr(test_cve_regression, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_cve_regression, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(test_cve_regression, "wrap_key_recipe", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(test_cve_regression, "unwrap_key", lambda *_a, **_k: 2)

    def _read(_raw: object, _sh: object, _handle: object, _attrs: list[int]) -> dict[int, object]:
        result: dict[int, object] = {}
        if sensitive is not _MISSING:
            result[CKA_SENSITIVE] = sensitive
        if extractable is not _MISSING:
            result[CKA_EXTRACTABLE] = extractable
        return result

    monkeypatch.setattr(test_cve_regression, "read_attributes", _read)
    test_cve_regression.TestTookanUnwrapAttrs().test_unwrapped_key_preserves_extractable(
        _session(_EncryptStateRaw(), "AES_KEY_WRAP", "AES_KEY_GEN")
    )


def test_tookan_preservation_valid_claims_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_tookan_preservation_result(monkeypatch)


@pytest.mark.parametrize(
    ("sensitive", "extractable"),
    [(False, _MISSING), (_MISSING, True)],
)
def test_tookan_preservation_definitive_mismatch_fails_with_missing_sibling(
    monkeypatch: pytest.MonkeyPatch,
    sensitive: object,
    extractable: object,
) -> None:
    with pytest.raises(Failed, match="result contradicting its requested protection"):
        _run_tookan_preservation_result(
            monkeypatch,
            sensitive=sensitive,
            extractable=extractable,
        )


@pytest.mark.parametrize(
    ("sensitive", "extractable", "expected_labels"),
    [
        (True, _MISSING, ["Tookan unwrapped key CKA_EXTRACTABLE readback"]),
        (_MISSING, False, ["Tookan unwrapped key CKA_SENSITIVE readback"]),
        (
            _MISSING,
            _MISSING,
            [
                "Tookan unwrapped key CKA_EXTRACTABLE readback",
                "Tookan unwrapped key CKA_SENSITIVE readback",
            ],
        ),
    ],
)
def test_tookan_preservation_incomplete_claims_record_each_omission_once(
    monkeypatch: pytest.MonkeyPatch,
    sensitive: object,
    extractable: object,
    expected_labels: list[str],
) -> None:
    """One omission, one record.

    ``attr_or_record`` already emits the omission; the sibling "protection
    readback" classify now fires only for a PRESENT-but-malformed value, so a
    single provider omission is no longer counted as two deviations.
    """
    C.clear()
    try:
        _run_tookan_preservation_result(
            monkeypatch,
            sensitive=sensitive,
            extractable=extractable,
        )
        records = C.get_records()
        assert [r.label for r in records] == expected_labels
        assert all(r.reason == "not_operational" and r.kind == "policy" for r in records)
    finally:
        C.clear()


@pytest.mark.parametrize(("sensitive", "extractable"), [("true", False), (True, "false")])
def test_tookan_preservation_malformed_claims_still_xfail(
    monkeypatch: pytest.MonkeyPatch,
    sensitive: object,
    extractable: object,
) -> None:
    """A PRESENT-but-malformed value keeps its own metadata record."""
    with pytest.raises(XFailed, match="result protection readback"):
        _run_tookan_preservation_result(
            monkeypatch,
            sensitive=sensitive,
            extractable=extractable,
        )


@pytest.mark.parametrize(
    ("sensitive", "extractable"),
    [(True, True), (False, False), (True, _MISSING), (_MISSING, False)],
)
def test_tookan_unbound_definitive_protection_claim_fails(
    monkeypatch: pytest.MonkeyPatch,
    sensitive: bool,
    extractable: bool,
) -> None:
    with pytest.raises(Failed, match="same result key reports protective attributes"):
        _run_tookan_unbound_result(
            monkeypatch,
            sensitive=sensitive,
            extractable=extractable,
        )


@pytest.mark.parametrize(("sensitive", "extractable"), [("true", True)])
def test_tookan_unbound_malformed_protection_readback_xfails(
    monkeypatch: pytest.MonkeyPatch,
    sensitive: object,
    extractable: object,
) -> None:
    with pytest.raises(XFailed, match="result-key protection readback"):
        _run_tookan_unbound_result(
            monkeypatch,
            sensitive=sensitive,
            extractable=extractable,
        )


@pytest.mark.parametrize(
    ("sensitive", "extractable", "expected_label"),
    [
        (_MISSING, True, "Tookan unbound unwrap result CKA_SENSITIVE readback"),
        (False, _MISSING, "Tookan unbound unwrap result CKA_EXTRACTABLE readback"),
    ],
)
def test_tookan_unbound_absent_protection_readback_records_once(
    monkeypatch: pytest.MonkeyPatch,
    sensitive: object,
    extractable: object,
    expected_label: str,
) -> None:
    """One omission, one record: absence no longer ALSO fires the malformed classify."""
    C.clear()
    try:
        _run_tookan_unbound_result(
            monkeypatch,
            sensitive=sensitive,
            extractable=extractable,
        )
        records = C.get_records()
        assert [r.label for r in records] == [expected_label]
        assert records[0].reason == "not_operational"
        assert records[0].kind == "policy"
    finally:
        C.clear()


@pytest.mark.parametrize(
    ("sensitive", "extractable"),
    [(True, True), (False, False), (True, False)],
)
def test_tookan_unbound_different_result_template_xfails(
    monkeypatch: pytest.MonkeyPatch,
    sensitive: bool,
    extractable: bool,
) -> None:
    with pytest.raises(XFailed, match="did not honor the requested output template"):
        _run_tookan_unbound_result(
            monkeypatch,
            sensitive=sensitive,
            extractable=extractable,
            value=b"",
        )


def test_rapid_sign_skips_without_sha256_rsa_pkcs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _unexpected_keypair(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise AssertionError("RSA setup should not run without SHA256_RSA_PKCS")

    monkeypatch.setattr(test_cve_regression, "gen_rsa_keypair", _unexpected_keypair)

    assert_skips(
        test_cve_regression.TestMutexDeadlockRegression().test_rapid_sign_no_deadlock,
        _session(_EncryptStateRaw(), "RSA_PKCS_KEY_PAIR_GEN"),
        match="SHA256_RSA_PKCS not supported",
    )


def test_rapid_sign_xfails_when_advertised_rsa_keygen_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_cve_regression, "gen_rsa_keypair", _raise_function_not_supported)

    with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_KEY_PAIR_GEN advertised"):
        test_cve_regression.TestMutexDeadlockRegression().test_rapid_sign_no_deadlock(
            _session(_EncryptStateRaw(), "RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS")
        )


def test_session_objects_after_logout_xfails_when_advertised_aes_keygen_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_cve_regression, "get_pin_bytes", lambda _config: b"1234")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_cve_regression.TestSessionObjectsAfterLogout().test_session_objects_after_logout(
            _session(_KeygenRejectRaw(), "AES_KEY_GEN"),
            SimpleNamespace(pin="1234"),
        )
