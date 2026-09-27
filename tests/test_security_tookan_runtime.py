"""Regression tests for Tookan security-vector runtime classification."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_DES3,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_UNEXTRACTABLE,
    CKR_WRAPPED_KEY_LEN_RANGE,
)
from pkcs11_check.testcases.security import test_tookan
from tests._skip_assert import assert_skips


def _session(*mechanisms: str) -> SimpleNamespace:
    supported = set(mechanisms) or {"AES_KEY_WRAP", "AES_KEY_GEN"}
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name in supported)


def _run_sensitive_copy(monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> None:
    monkeypatch.setattr(test_tookan, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        test_tookan,
        "read_attributes",
        lambda *_a, **_k: {CKA_SENSITIVE: True},
    )
    monkeypatch.setattr(
        test_tookan,
        "copy_object",
        lambda *_a, **_k: (_ for _ in ()).throw(exc),
    )
    monkeypatch.setattr(test_tookan, "destroy_quietly", lambda *_a: None)
    test_tookan.TestSensitivePreservation().test_sensitive_preserved_on_copy(_session())


def test_sensitive_copy_allows_exact_function_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_sensitive_copy(
        monkeypatch,
        CkrAssertionError("copy unavailable", int(CKR_FUNCTION_NOT_SUPPORTED)),
    )


@pytest.mark.parametrize(
    "exc",
    [
        AssertionError("harness bug mentioning CKR_FUNCTION_NOT_SUPPORTED"),
        CkrAssertionError("misleading CKR_FUNCTION_NOT_SUPPORTED text", 0x12345678),
    ],
)
def test_sensitive_copy_does_not_match_ckr_text(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    with pytest.raises(type(exc)) as caught:
        _run_sensitive_copy(monkeypatch, exc)
    assert caught.value is exc


def _run_key_type_confusion_until_wrap(
    monkeypatch: pytest.MonkeyPatch,
    wrap_exc: CkrAssertionError,
) -> None:
    monkeypatch.setattr(test_tookan, "gen_aes_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_tookan, "destroy_quietly", lambda *_args: None)
    # The valid leg reads the target's CKA_VALUE before the wrap; these two
    # tests only exercise the wrap-reject path (skip / xfail before unwrap), so
    # a stub value is sufficient.
    monkeypatch.setattr(
        test_tookan,
        "read_attributes",
        lambda *_a, **_k: {CKA_VALUE: b"\x00" * 16},
    )
    monkeypatch.setattr(
        test_tookan,
        "wrap_key",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(wrap_exc),
    )

    test_tookan.TestKeyTypeConfusionOnUnwrap().test_unwrap_aes_as_des3_rejected(
        _session(), object()
    )


def test_key_type_confusion_skips_explicit_key_not_wrappable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert_skips(
        _run_key_type_confusion_until_wrap,
        monkeypatch,
        CkrAssertionError(
            "Unexpected CK_RV CKR_KEY_NOT_WRAPPABLE",
            int(CKR_KEY_NOT_WRAPPABLE),
        ),
        match="cannot wrap AES-128 key",
    )


def test_key_type_confusion_xfails_generic_wrap_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_tookan.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="key-type-confusion wrap rejected"):
        _run_key_type_confusion_until_wrap(
            monkeypatch,
            CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR)),
        )


def _run_key_type_confusion_invalid_leg(
    monkeypatch: pytest.MonkeyPatch,
    invalid_leg: CkrAssertionError | int,
    *,
    encrypt_outcome: bytes | BaseException = b"\xc1" * 8,
    decrypt_outcome: bytes | BaseException | None = None,
) -> None:
    """Drive the §3.2 probe past the valid leg into the invalid-leg verdict.

    The valid AES leg verifies (matching 16-byte material); ``invalid_leg`` is
    either the refusal raised by the CKK_DES3 unwrap or the accepted handle. An
    accepted handle reads back a fully proven usable DES3 key.
    ``decrypt_outcome=None`` echoes the encrypt plaintext (roundtrip match).
    """
    monkeypatch.setattr(test_tookan, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_tookan, "destroy_quietly", lambda *_a: None)
    reads = iter(
        [
            {CKA_VALUE: b"\x11" * 16},
            {CKA_VALUE: b"\x11" * 16},
            {
                CKA_KEY_TYPE: CKK_DES3,
                CKA_VALUE_LEN: 24,
                CKA_VALUE: b"\x01" * 24,
            },
        ]
    )
    monkeypatch.setattr(test_tookan, "read_attributes", lambda *_a, **_k: next(reads))
    monkeypatch.setattr(test_tookan, "wrap_key", lambda *_a, **_k: b"\x00" * 24)
    monkeypatch.setattr(test_tookan, "unwrap_key_for_mechanism_roundtrip", lambda *_a, **_k: 2)

    def _unwrap(*_a: object, **_k: object) -> int:
        if isinstance(invalid_leg, BaseException):
            raise invalid_leg
        return int(invalid_leg)

    monkeypatch.setattr(test_tookan, "unwrap_key", _unwrap)
    seen: list[bytes] = []

    def _encrypt(_raw: object, _sh: int, _key: int, _mech: object, data: bytes) -> bytes:
        seen.append(data)
        if isinstance(encrypt_outcome, BaseException):
            raise encrypt_outcome
        return encrypt_outcome

    def _decrypt(_raw: object, _sh: int, _key: int, _mech: object, _data: bytes) -> bytes:
        if isinstance(decrypt_outcome, BaseException):
            raise decrypt_outcome
        if decrypt_outcome is not None:
            return decrypt_outcome
        return seen[-1]

    monkeypatch.setattr(test_tookan, "encrypt_single", _encrypt)
    monkeypatch.setattr(test_tookan, "decrypt_single", _decrypt)

    test_tookan.TestKeyTypeConfusionOnUnwrap().test_unwrap_aes_as_des3_rejected(
        _session("AES_KEY_WRAP", "AES_KEY_GEN", "DES3_ECB"), object()
    )


def test_key_type_confusion_canonical_len_range_rejection_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_tookan.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )
    _run_key_type_confusion_invalid_leg(
        monkeypatch,
        CkrAssertionError(
            "Unexpected CK_RV CKR_WRAPPED_KEY_LEN_RANGE",
            int(CKR_WRAPPED_KEY_LEN_RANGE),
        ),
    )


def test_key_type_confusion_alternative_rejection_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(XFailed, match="must be refused"):
        _run_key_type_confusion_invalid_leg(
            monkeypatch,
            CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR)),
        )


def test_key_type_confusion_undefined_rv_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(Failed) as ei:
        _run_key_type_confusion_invalid_leg(
            monkeypatch,
            CkrAssertionError("Unexpected CK_RV 0x12345678", 0x12345678),
        )
    assert not isinstance(ei.value, XFailed)


def test_key_type_confusion_undefined_usability_rv_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The decrypt half of the DES3 usability probe returns an undefined CK_RV:
    # a return-value-contract violation that must stay FAIL (metadata/HIGH),
    # recorded nonterminally in place before the accepted-invalid finding --
    # not downgraded to not_operational XFAIL like a clean defined refusal.
    with pytest.raises(Failed) as ei:
        _run_key_type_confusion_invalid_leg(
            monkeypatch,
            3,
            decrypt_outcome=CkrAssertionError("Unexpected CK_RV 0x12345678", 0x12345678),
        )
    assert not isinstance(ei.value, XFailed)
    records = C.get_records()
    assert [r.reason for r in records] == ["self_contradiction", "accepted_invalid"]
    assert records[0].outcome == "fail"
    assert records[0].kind == "metadata"
    assert records[0].severity == "HIGH"
    assert records[0].operation == "C_Decrypt"
    assert records[0].mechanism == "CKM_DES3_ECB"
    assert records[0].actual_ckr == "0x12345678"


def test_key_type_confusion_accepted_handle_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A returned handle is failure-like evidence (a type/length contract
    # finding), never success -- even with fully proven DES3 usability.
    with pytest.raises(Failed) as ei:
        _run_key_type_confusion_invalid_leg(monkeypatch, 3)
    assert not isinstance(ei.value, XFailed)


# --- TestWrapExtraction::test_wrap_decrypt_extraction_attempt --------------
#
# Regression for the false positive where a module CORRECTLY refusing to wrap a
# non-extractable/sensitive key (CKR_KEY_UNEXTRACTABLE) surfaced as a hard fail
# because the wrap_key recipe re-raised the refusal.


def _run_wrap_extraction(
    monkeypatch: pytest.MonkeyPatch,
    *,
    wrap_exc: CkrAssertionError | None = None,
    decrypt_exc: BaseException | None = None,
    recovered: bytes = b"",
    claimed_protected: bool = True,
) -> None:
    monkeypatch.setattr(test_tookan, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_tookan, "destroy_quietly", lambda *_a: None)

    def _wrap(*_a: object, **_k: object) -> bytes:
        if wrap_exc is not None:
            raise wrap_exc
        return b"\x00" * 24  # 16-byte AES key + 8-byte KWP prefix

    monkeypatch.setattr(test_tookan, "wrap_key", _wrap)
    monkeypatch.setattr(
        test_tookan,
        "read_attributes",
        lambda *_a, **_k: {CKA_EXTRACTABLE: not claimed_protected},
    )

    def _decrypt(*_a: object, **_k: object) -> bytes:
        if decrypt_exc is not None:
            raise decrypt_exc
        return recovered

    monkeypatch.setattr(test_tookan, "decrypt_single", _decrypt)

    test_tookan.TestWrapExtraction().test_wrap_decrypt_extraction_attempt(_session())


def test_wrap_extraction_refused_unextractable_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    # Module refused to wrap the protected key -> attack blocked -> pass.
    monkeypatch.setattr(
        test_tookan.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )
    _run_wrap_extraction(
        monkeypatch,
        wrap_exc=CkrAssertionError(
            "Unexpected CK_RV CKR_KEY_UNEXTRACTABLE; expected one of: CKR_OK",
            int(CKR_KEY_UNEXTRACTABLE),
        ),
    )


def test_wrap_extraction_refused_not_wrappable_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_wrap_extraction(
        monkeypatch,
        wrap_exc=CkrAssertionError(
            "Unexpected CK_RV CKR_KEY_NOT_WRAPPABLE; expected one of: CKR_OK",
            int(CKR_KEY_NOT_WRAPPABLE),
        ),
    )


def test_wrap_extraction_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(XFailed, match="wrap rejected before the decrypt leg"):
        _run_wrap_extraction(
            monkeypatch,
            wrap_exc=CkrAssertionError(
                "Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK",
                int(CKR_DEVICE_ERROR),
            ),
        )


def test_wrap_extraction_leak_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    # Wrap succeeded AND the decrypt leg recovers >= key-length plaintext from a
    # key claimed non-extractable -> policy self-contradiction -> fail.
    with pytest.raises(Failed) as ei:
        _run_wrap_extraction(monkeypatch, recovered=b"\x11" * 16, claimed_protected=True)
    assert not isinstance(ei.value, XFailed)


def test_wrap_extraction_no_leak_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    # Wrap succeeded but the decrypt leg recovers nothing usable -> no extraction.
    _run_wrap_extraction(monkeypatch, recovered=b"", claimed_protected=True)


def test_wrap_extraction_exact_decrypt_length_reject_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _run_wrap_extraction(
        monkeypatch,
        decrypt_exc=CkrAssertionError(
            "Unexpected CK_RV CKR_DATA_LEN_RANGE",
            int(CKR_DATA_LEN_RANGE),
        ),
    )


def test_wrap_extraction_other_decrypt_reject_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(XFailed, match="decrypt rejected"):
        _run_wrap_extraction(
            monkeypatch,
            decrypt_exc=CkrAssertionError(
                "Unexpected CK_RV CKR_DEVICE_ERROR",
                int(CKR_DEVICE_ERROR),
            ),
        )


def test_wrap_extraction_does_not_mask_decrypt_assertion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(AssertionError, match="harness oracle failed"):
        _run_wrap_extraction(
            monkeypatch,
            decrypt_exc=AssertionError("harness oracle failed"),
        )


@pytest.mark.parametrize(
    "method_name",
    ["test_wrap_and_decrypt_on_same_key", "test_encrypt_and_unwrap_on_same_key"],
)
def test_conflicting_usage_creation_does_not_mask_non_ckr_assertion(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
) -> None:
    monkeypatch.setattr(
        test_tookan,
        "gen_aes_key",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("harness setup failed")),
    )

    with pytest.raises(AssertionError, match="harness setup failed"):
        getattr(test_tookan.TestConflictingUsageAttrs(), method_name)(_session())
