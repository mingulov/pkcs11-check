"""Regression tests for general error-case setup classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
)
from pkcs11_check.testcases import test_errors
from tests._skip_assert import assert_skips


def _session_with_mechanisms(*mechanisms: str, raw: Any | None = None) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=raw if raw is not None else object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def test_invalid_mechanism_param_skips_missing_cbc_pad(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid-parameter checks should skip missing operation mechanisms before setup."""

    def _unexpected_keygen(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("AES keygen should have been capability-guarded")

    monkeypatch.setattr(test_errors, "gen_aes_key", _unexpected_keygen)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    assert_skips(
        test_errors.TestInvalidOperations().test_invalid_mechanism_param,
        rs,
        match="AES_CBC_PAD not supported",
    )

    # A capability skip is not a provider verdict; it must not leave a classification
    # record behind (a mutation that classified before checking the capability would
    # still raise pytest.skip.Exception -- outcome-type alone would not catch it).
    assert C.get_records() == []

    # A capability skip is not a provider verdict; it must not leave a classification
    # record behind (a mutation that classified before checking the capability would
    # still raise pytest.skip.Exception -- outcome-type alone would not catch it).
    assert C.get_records() == []


def test_invalid_key_size_skips_missing_aes_keygen() -> None:
    """Invalid-size AES keygen checks should skip modules without AES_KEY_GEN."""
    rs = _session_with_mechanisms()

    assert_skips(
        test_errors.TestInvalidOperations().test_generate_key_invalid_size,
        rs,
        match="AES_KEY_GEN not supported",
    )

    assert C.get_records() == []

    assert C.get_records() == []


def test_invalid_key_size_advertised_runtime_reject_is_xfail() -> None:
    """Advertised AES_KEY_GEN that rejects even the invalid-size path is non-clean."""

    def _generate_key_reject(*_args: Any) -> int:
        return int(CKR_FUNCTION_NOT_SUPPORTED)

    raw = SimpleNamespace(C_GenerateKey=_generate_key_reject)
    rs = _session_with_mechanisms("AES_KEY_GEN", raw=raw)

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_errors.TestInvalidOperations().test_generate_key_invalid_size(rs)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "not_operational"
    assert record.outcome == "xfail"
    assert record.severity == "LOW"
    assert record.kind is None
    assert record.label == "AES_KEY_GEN:invalid-size key generation"
    assert record.mechanism == "AES_KEY_GEN"
    assert record.operation is None
    assert record.expected_ckr is None
    assert record.actual_ckr == "CKR_FUNCTION_NOT_SUPPORTED"
    assert (
        record.summary
        == "AES_KEY_GEN advertised but invalid-size key generation is not operational: "
        "CKR_FUNCTION_NOT_SUPPORTED"
    )
    assert record.spec_ref == "PKCS#11 v3.2 · AES_KEY_GEN"
    assert record.detail is None


def test_empty_encrypt_aes_setup_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Advertised-but-rejected AES setup should not mask the empty-input check."""

    def _rejected_keygen(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
            int(CKR_FUNCTION_NOT_SUPPORTED),
        )

    monkeypatch.setattr(test_errors, "gen_aes_key", _rejected_keygen)
    rs = _session_with_mechanisms("AES_KEY_GEN", "AES_CBC_PAD")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_errors.TestEmptyInputs().test_encrypt_empty_data(rs)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "not_operational"
    assert record.outcome == "xfail"
    assert record.severity == "LOW"
    assert record.kind is None
    assert record.label == (
        "AES_KEY_GEN advertised but AES-128 key generation for "
        "empty-data encryption is not operational"
    )
    assert record.mechanism is None
    assert record.operation is None
    assert record.expected_ckr is None
    assert record.actual_ckr == "CKR_FUNCTION_NOT_SUPPORTED"
    assert record.summary == (
        "AES_KEY_GEN advertised but AES-128 key generation for empty-data "
        "encryption is not operational: CKR_FUNCTION_NOT_SUPPORTED"
    )
    assert record.detail is None


def test_decrypt_garbage_rsa_setup_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RSA setup rejection should be visible xfail evidence, not a test crash."""

    def _rejected_keypair(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
            int(CKR_ATTRIBUTE_VALUE_INVALID),
        )

    monkeypatch.setattr(test_errors, "gen_rsa_keypair", _rejected_keypair)
    rs = _session_with_mechanisms("RSA_PKCS", "RSA_PKCS_KEY_PAIR_GEN")

    with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_KEY_PAIR_GEN advertised"):
        test_errors.TestInvalidOperations().test_decrypt_garbage(rs)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "not_operational"
    assert record.outcome == "xfail"
    assert record.severity == "LOW"
    assert record.kind is None
    assert record.label == (
        "RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation for "
        "decrypt-garbage check is not operational"
    )
    assert record.mechanism is None
    assert record.operation is None
    assert record.expected_ckr is None
    assert record.actual_ckr == "CKR_ATTRIBUTE_VALUE_INVALID"
    assert record.summary == (
        "RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation for decrypt-garbage "
        "check is not operational: CKR_ATTRIBUTE_VALUE_INVALID"
    )
    assert record.detail is None


# --- Phase 4 N2: standalone negative-reject asserts -> classify_negative_rv ---


def _generate_key_returning(rv: int) -> SimpleNamespace:
    """Session whose C_GenerateKey returns ``rv`` (handle stays 0)."""

    def _gen(*_args: Any) -> int:
        return int(rv)

    raw = SimpleNamespace(C_GenerateKey=_gen)
    return _session_with_mechanisms("AES_KEY_GEN", raw=raw)


def test_invalid_key_size_spec_reject_passes() -> None:
    """The spec-preferred reject code on an invalid key size -> pass."""
    rs = _generate_key_returning(int(CKR_KEY_SIZE_RANGE))
    test_errors.TestInvalidOperations().test_generate_key_invalid_size(rs)


def test_invalid_key_size_other_reject_xfails() -> None:
    """A clean but non-spec reject code on an invalid key size -> xfail."""
    rs = _generate_key_returning(int(CKR_DEVICE_ERROR))
    with pytest.raises(pytest.xfail.Exception):
        test_errors.TestInvalidOperations().test_generate_key_invalid_size(rs)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "nonspec_reject"
    assert record.outcome == "xfail"
    assert record.severity == "LOW"
    assert record.kind is None
    assert record.label == "C_GenerateKey for an invalid AES key size"
    assert record.mechanism is None
    assert record.operation is None
    assert record.expected_ckr == ["CKR_KEY_SIZE_RANGE", "CKR_ATTRIBUTE_VALUE_INVALID"]
    assert record.actual_ckr == "CKR_DEVICE_ERROR"
    assert record.summary == (
        "C_GenerateKey for an invalid AES key size: expected "
        "['CKR_KEY_SIZE_RANGE', 'CKR_ATTRIBUTE_VALUE_INVALID'], got CKR_DEVICE_ERROR"
    )
    assert record.detail is None


def _encrypt_init_returning(rv: int) -> SimpleNamespace:
    """Session whose C_EncryptInit returns ``rv``; RSA keypair stubbed."""

    def _encrypt_init(*_args: Any) -> int:
        return int(rv)

    raw = SimpleNamespace(C_EncryptInit=_encrypt_init)
    return _session_with_mechanisms("RSA_PKCS", "RSA_PKCS_KEY_PAIR_GEN", raw=raw)


def _stub_rsa_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(test_errors, "gen_rsa_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(test_errors, "destroy_quietly", lambda *_a, **_k: None)


def test_decrypt_garbage_uses_repeatable_ciphertext(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_rsa_setup(monkeypatch)
    decrypted_inputs: list[bytes] = []

    def _unexpected_random(*_args: Any) -> int:
        raise AssertionError("C_GenerateRandom must not supply the garbage-decrypt input")

    def _decrypt(
        _session: int,
        encrypted_data: Any,
        encrypted_data_len: int,
        _out: Any,
        _out_len: Any,
    ) -> int:
        decrypted_inputs.append(bytes(encrypted_data[:encrypted_data_len]))
        return int(CKR_ENCRYPTED_DATA_INVALID)

    raw = SimpleNamespace(
        C_GenerateRandom=_unexpected_random,
        C_DecryptInit=lambda *_args: 0,
        C_Decrypt=_decrypt,
    )
    rs = _session_with_mechanisms("RSA_PKCS", "RSA_PKCS_KEY_PAIR_GEN", raw=raw)

    test_errors.TestInvalidOperations().test_decrypt_garbage(rs)

    assert decrypted_inputs == [bytes(256)]


def test_encrypt_with_sign_key_accepted_is_tolerated(monkeypatch: pytest.MonkeyPatch) -> None:
    """Some modules allow EncryptInit on a private key; acceptance stays tolerated."""
    _stub_rsa_setup(monkeypatch)
    rs = _encrypt_init_returning(0)  # CKR_OK
    test_errors.TestInvalidOperations().test_encrypt_with_sign_key(rs)


def test_encrypt_with_sign_key_spec_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_rsa_setup(monkeypatch)
    rs = _encrypt_init_returning(int(CKR_KEY_FUNCTION_NOT_PERMITTED))
    test_errors.TestInvalidOperations().test_encrypt_with_sign_key(rs)


def test_encrypt_with_sign_key_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_rsa_setup(monkeypatch)
    rs = _encrypt_init_returning(int(CKR_DEVICE_ERROR))
    with pytest.raises(pytest.xfail.Exception):
        test_errors.TestInvalidOperations().test_encrypt_with_sign_key(rs)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "nonspec_reject"
    assert record.outcome == "xfail"
    assert record.severity == "LOW"
    assert record.kind is None
    assert record.label == "C_EncryptInit with a sign-only private key"
    assert record.mechanism is None
    assert record.operation is None
    assert record.expected_ckr == ["CKR_KEY_FUNCTION_NOT_PERMITTED", "CKR_KEY_TYPE_INCONSISTENT"]
    assert record.actual_ckr == "CKR_DEVICE_ERROR"
    assert record.summary == (
        "C_EncryptInit with a sign-only private key: expected "
        "['CKR_KEY_FUNCTION_NOT_PERMITTED', 'CKR_KEY_TYPE_INCONSISTENT'], got CKR_DEVICE_ERROR"
    )
    assert record.detail is None


def test_digest_empty_data_skips_missing_sha256(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Digest checks should not invoke SHA256 when the mechanism is absent."""

    def _unexpected_digest(*_args: Any, **_kwargs: Any) -> bytes:
        raise AssertionError("SHA256 digest should have been capability-guarded")

    monkeypatch.setattr(test_errors, "digest_single", _unexpected_digest)
    rs = _session_with_mechanisms()

    assert_skips(
        test_errors.TestEmptyInputs().test_digest_empty_data, rs, match="SHA256 not supported"
    )

    assert C.get_records() == []
