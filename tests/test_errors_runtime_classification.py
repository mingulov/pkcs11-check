"""Regression tests for general error-case setup classification."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_OK,
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


def _generate_key_accepting(*mechanisms: str) -> SimpleNamespace:
    """Session whose C_GenerateKey accepts (writes handle 7, returns CKR_OK)."""

    def _gen(*args: Any) -> int:
        ctypes.cast(args[-1], ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = 7
        return int(CKR_OK)

    raw = SimpleNamespace(C_GenerateKey=_gen)
    return _session_with_mechanisms(*mechanisms, raw=raw)


def test_invalid_key_size_accepted_usable_key_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 1-byte AES key that encrypts is broken crypto (F-11 probe)."""
    monkeypatch.setattr(test_errors, "encrypt_single", lambda *_a, **_k: bytes(16))
    monkeypatch.setattr(test_errors, "destroy_quietly", lambda *_a, **_k: None)
    rs = _generate_key_accepting("AES_KEY_GEN", "AES_ECB")

    with pytest.raises(Failed) as ei:
        test_errors.TestInvalidOperations().test_generate_key_invalid_size(rs)
    assert not isinstance(ei.value, XFailed)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "accepted_invalid"
    assert record.outcome == "fail"
    assert record.severity == "CRITICAL"
    assert record.kind == "crypto"
    assert record.label == "1-byte AES key accepted and usable"
    assert record.mechanism == "AES_ECB"
    assert record.operation == "C_Encrypt"
    assert record.expected_ckr is None
    assert record.actual_ckr == "CKR_OK"
    assert record.summary == ("module generated a 1-byte AES key that encrypts (broken crypto)")
    assert record.spec_ref == "PKCS#11 v3.2 · C_Encrypt · AES_ECB"
    assert record.detail is None


def test_invalid_key_size_accepted_dangling_key_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 1-byte AES key the module itself cannot use is a deviation (F-11)."""

    def _unusable(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_DEVICE_ERROR",
            int(CKR_DEVICE_ERROR),
        )

    monkeypatch.setattr(test_errors, "encrypt_single", _unusable)
    monkeypatch.setattr(test_errors, "destroy_quietly", lambda *_a, **_k: None)
    rs = _generate_key_accepting("AES_KEY_GEN", "AES_ECB")

    with pytest.raises(XFailed):
        test_errors.TestInvalidOperations().test_generate_key_invalid_size(rs)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "honest_deviation"
    assert record.outcome == "xfail"
    assert record.severity == "LOW"
    assert record.kind is None
    assert record.label == "1-byte AES key accepted but unusable"
    assert record.mechanism == "AES_ECB"
    assert record.operation == "C_Encrypt"
    assert record.expected_ckr is None
    assert record.actual_ckr == "CKR_DEVICE_ERROR"
    assert record.summary == (
        "module accepted a 1-byte AES key it cannot encrypt with: CKR_DEVICE_ERROR"
    )
    assert record.spec_ref == "PKCS#11 v3.2 · C_Encrypt · AES_ECB"
    assert record.detail is None


def test_invalid_key_size_accepted_no_ecb_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without AES_ECB the usability probe cannot run; the accept still xfails."""
    monkeypatch.setattr(test_errors, "destroy_quietly", lambda *_a, **_k: None)
    rs = _generate_key_accepting("AES_KEY_GEN")

    with pytest.raises(XFailed):
        test_errors.TestInvalidOperations().test_generate_key_invalid_size(rs)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "honest_deviation"
    assert record.outcome == "xfail"
    assert record.severity == "LOW"
    assert record.label == "1-byte AES key accepted; usability untestable"
    assert record.mechanism == "AES_KEY_GEN"
    assert record.operation == "C_GenerateKey"
    assert record.actual_ckr == "CKR_OK"
    assert record.summary == ("module accepted a 1-byte AES key; no AES_ECB to probe it with")


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


def test_decrypt_garbage_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKR_OK on invalid RSA-PKCS padding bypasses the padding check (F-2)."""
    _stub_rsa_setup(monkeypatch)
    raw = SimpleNamespace(
        C_DecryptInit=lambda *_args: 0,
        C_Decrypt=lambda *_args: 0,
    )
    rs = _session_with_mechanisms("RSA_PKCS", "RSA_PKCS_KEY_PAIR_GEN", raw=raw)

    with pytest.raises(Failed) as ei:
        test_errors.TestInvalidOperations().test_decrypt_garbage(rs)
    assert not isinstance(ei.value, XFailed)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "accepted_invalid"
    assert record.outcome == "fail"
    assert record.severity == "CRITICAL"
    assert record.kind == "crypto"
    assert record.label == "C_Decrypt of random garbage under RSA-PKCS"
    assert record.mechanism == "CKM_RSA_PKCS"
    assert record.operation == "C_Decrypt"
    assert record.expected_ckr is None
    assert record.actual_ckr == "CKR_OK"
    assert record.summary == (
        "module decrypted invalid RSA-PKCS padding with CKR_OK (padding bypass)"
    )
    assert record.spec_ref == "PKCS#11 v3.2 · C_Decrypt · CKM_RSA_PKCS"
    assert record.detail is None


def test_decrypt_garbage_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A clean but non-spec reject of garbage RSA-PKCS ciphertext xfails."""
    _stub_rsa_setup(monkeypatch)
    raw = SimpleNamespace(
        C_DecryptInit=lambda *_args: 0,
        C_Decrypt=lambda *_args: int(CKR_DEVICE_ERROR),
    )
    rs = _session_with_mechanisms("RSA_PKCS", "RSA_PKCS_KEY_PAIR_GEN", raw=raw)

    with pytest.raises(XFailed):
        test_errors.TestInvalidOperations().test_decrypt_garbage(rs)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "nonspec_reject"
    assert record.outcome == "xfail"
    assert record.severity == "LOW"
    assert record.kind is None
    assert record.label == "C_Decrypt of random garbage under RSA-PKCS"
    assert record.mechanism is None
    assert record.operation is None
    assert record.expected_ckr == [
        "CKR_ENCRYPTED_DATA_INVALID",
        "CKR_ENCRYPTED_DATA_LEN_RANGE",
    ]
    assert record.actual_ckr == "CKR_DEVICE_ERROR"
    assert record.summary == (
        "C_Decrypt of random garbage under RSA-PKCS: expected "
        "['CKR_ENCRYPTED_DATA_INVALID', 'CKR_ENCRYPTED_DATA_LEN_RANGE'], "
        "got CKR_DEVICE_ERROR"
    )
    assert record.spec_ref == ""
    assert record.detail is None


def test_encrypt_with_sign_key_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """EncryptInit on a key without CKA_ENCRYPT must be rejected (F-10)."""
    _stub_rsa_setup(monkeypatch)
    rs = _encrypt_init_returning(0)  # CKR_OK
    with pytest.raises(Failed) as ei:
        test_errors.TestInvalidOperations().test_encrypt_with_sign_key(rs)
    assert not isinstance(ei.value, XFailed)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "accepted_invalid"
    assert record.outcome == "fail"
    assert record.severity == "HIGH"
    assert record.kind is None
    assert record.label == "C_EncryptInit with a sign-only private key"
    assert record.mechanism is None
    assert record.operation is None
    assert record.expected_ckr == ["CKR_KEY_FUNCTION_NOT_PERMITTED", "CKR_KEY_TYPE_INCONSISTENT"]
    assert record.actual_ckr == "CKR_OK"
    assert record.summary == (
        "C_EncryptInit with a sign-only private key: accepted invalid (CKR_OK) -- must reject"
    )
    assert record.spec_ref == ""
    assert record.detail is None


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


# --- Group A H-2: empty-input oracles (reject xfails, empty output fails) ---


def _scripted_single_call(script: list[tuple[int, int]]) -> Any:
    """Fake C_Encrypt/C_Sign: pop ``(rv, out_len)`` per call, writing out_len."""

    calls = list(script)

    def _call(*args: Any) -> int:
        rv, length = calls.pop(0)
        ctypes.cast(args[-1], ctypes.POINTER(CK_ULONG)).contents.value = length
        return int(rv)

    return _call


def _stub_aes_empty_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(test_errors, "gen_aes_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_errors, "generate_random", lambda *_a, **_k: bytes(16))
    monkeypatch.setattr(test_errors, "destroy_quietly", lambda *_a, **_k: None)


def test_encrypt_empty_init_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Refusing well-defined empty CBC_PAD input is a deviation, not a pass."""
    _stub_aes_empty_setup(monkeypatch)
    raw = SimpleNamespace(
        C_EncryptInit=lambda *_a: int(CKR_DATA_LEN_RANGE),
        C_Encrypt=_scripted_single_call([(int(CKR_OK), 16)]),
    )
    rs = _session_with_mechanisms("AES_KEY_GEN", "AES_CBC_PAD", raw=raw)

    with pytest.raises(XFailed):
        test_errors.TestEmptyInputs().test_encrypt_empty_data(rs)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "nonspec_reject"
    assert record.outcome == "xfail"
    assert record.severity == "LOW"
    assert record.kind is None
    assert record.label == "C_EncryptInit before empty-data encryption"
    assert record.mechanism == "AES_CBC_PAD"
    assert record.operation == "C_EncryptInit"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_DATA_LEN_RANGE"
    assert record.summary == (
        "C_EncryptInit before empty-data encryption: rejected well-defined "
        "empty input with CKR_DATA_LEN_RANGE, expected CKR_OK"
    )
    assert record.spec_ref == "PKCS#11 v3.2 · C_EncryptInit · AES_CBC_PAD"
    assert record.detail is None


def test_encrypt_empty_zero_length_query_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CBC_PAD CKR_OK with zero-length output drops the padding block (fail)."""
    _stub_aes_empty_setup(monkeypatch)
    raw = SimpleNamespace(
        C_EncryptInit=lambda *_a: 0,
        C_Encrypt=_scripted_single_call([(int(CKR_OK), 0)]),
    )
    rs = _session_with_mechanisms("AES_KEY_GEN", "AES_CBC_PAD", raw=raw)

    with pytest.raises(Failed) as ei:
        test_errors.TestEmptyInputs().test_encrypt_empty_data(rs)
    assert not isinstance(ei.value, XFailed)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "wrong_result"
    assert record.outcome == "fail"
    assert record.severity == "CRITICAL"
    assert record.kind == "crypto"
    assert record.label == "C_Encrypt (length query) of empty data under AES-CBC-PAD"
    assert record.mechanism == "AES_CBC_PAD"
    assert record.operation == "C_Encrypt"
    assert record.expected_ckr is None
    assert record.actual_ckr == "0 bytes"
    assert record.summary == (
        "CBC_PAD length query for empty input must report one 16-byte block, got 0 bytes"
    )
    assert record.spec_ref == "PKCS#11 v3.2 · C_Encrypt · AES_CBC_PAD"
    assert record.detail is None


def test_encrypt_empty_full_block_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """CBC_PAD empty input yielding one 16-byte block is the correct outcome."""
    _stub_aes_empty_setup(monkeypatch)
    raw = SimpleNamespace(
        C_EncryptInit=lambda *_a: 0,
        C_Encrypt=_scripted_single_call([(int(CKR_OK), 16), (int(CKR_OK), 16)]),
    )
    rs = _session_with_mechanisms("AES_KEY_GEN", "AES_CBC_PAD", raw=raw)

    test_errors.TestEmptyInputs().test_encrypt_empty_data(rs)

    assert C.get_records() == []


def test_encrypt_empty_second_call_reject_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A clean reject on the second empty CBC_PAD call is a deviation."""
    _stub_aes_empty_setup(monkeypatch)
    raw = SimpleNamespace(
        C_EncryptInit=lambda *_a: 0,
        C_Encrypt=_scripted_single_call([(int(CKR_OK), 16), (int(CKR_DATA_LEN_RANGE), 16)]),
    )
    rs = _session_with_mechanisms("AES_KEY_GEN", "AES_CBC_PAD", raw=raw)

    with pytest.raises(XFailed):
        test_errors.TestEmptyInputs().test_encrypt_empty_data(rs)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "nonspec_reject"
    assert record.outcome == "xfail"
    assert record.label == "C_Encrypt of empty data under AES-CBC-PAD"
    assert record.mechanism == "AES_CBC_PAD"
    assert record.operation == "C_Encrypt"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_DATA_LEN_RANGE"


def test_sign_empty_init_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Refusing well-defined empty signing input is a deviation, not a pass."""
    _stub_rsa_setup(monkeypatch)
    raw = SimpleNamespace(
        C_SignInit=lambda *_a: int(CKR_DATA_LEN_RANGE),
        C_Sign=_scripted_single_call([(int(CKR_OK), 256)]),
    )
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS", raw=raw)

    with pytest.raises(XFailed):
        test_errors.TestEmptyInputs().test_sign_empty_data(rs)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "nonspec_reject"
    assert record.outcome == "xfail"
    assert record.severity == "LOW"
    assert record.kind is None
    assert record.label == "C_SignInit before empty-data signing"
    assert record.mechanism == "SHA256_RSA_PKCS"
    assert record.operation == "C_SignInit"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_DATA_LEN_RANGE"
    assert record.summary == (
        "C_SignInit before empty-data signing: rejected well-defined "
        "empty input with CKR_DATA_LEN_RANGE, expected CKR_OK"
    )
    assert record.spec_ref == "PKCS#11 v3.2 · C_SignInit · SHA256_RSA_PKCS"
    assert record.detail is None


def test_sign_empty_zero_length_query_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sign CKR_OK with zero-length output is wrong output, not a pass."""
    _stub_rsa_setup(monkeypatch)
    raw = SimpleNamespace(
        C_SignInit=lambda *_a: 0,
        C_Sign=_scripted_single_call([(int(CKR_OK), 0)]),
    )
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS", raw=raw)

    with pytest.raises(Failed) as ei:
        test_errors.TestEmptyInputs().test_sign_empty_data(rs)
    assert not isinstance(ei.value, XFailed)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "wrong_result"
    assert record.outcome == "fail"
    assert record.severity == "CRITICAL"
    assert record.kind == "crypto"
    assert record.label == "C_Sign (length query) of empty data under SHA256-RSA-PKCS"
    assert record.mechanism == "SHA256_RSA_PKCS"
    assert record.operation == "C_Sign"
    assert record.expected_ckr is None
    assert record.actual_ckr == "0 bytes"
    assert record.summary == (
        "signature length query for empty input must report 256 bytes, got 0 bytes"
    )
    assert record.spec_ref == "PKCS#11 v3.2 · C_Sign · SHA256_RSA_PKCS"
    assert record.detail is None


def test_sign_empty_happy_path_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty signing input yielding a 256-byte RSA-2048 signature passes."""
    _stub_rsa_setup(monkeypatch)
    raw = SimpleNamespace(
        C_SignInit=lambda *_a: 0,
        C_Sign=_scripted_single_call([(int(CKR_OK), 256), (int(CKR_OK), 256)]),
    )
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS", raw=raw)

    test_errors.TestEmptyInputs().test_sign_empty_data(rs)

    assert C.get_records() == []
