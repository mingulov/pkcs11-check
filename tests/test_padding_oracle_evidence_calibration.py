"""Regression tests for padding-oracle evidence calibration (Task 9B / F9).

P11C-0198-009: error diversity across merely malformed random ciphertexts and
gross valid/invalid latency are serialized diagnostics, not named
Bleichenbacher/Manger/Lucky13 oracles. Only a controlled category predicate
may carry ``Classification(reason="oracle")``.

P11C-0198-015: the structured Bleichenbacher cat-2 predicate must hold on the
final encoded message representative. Choosing bytes and then reducing
``% n`` can reintroduce a leading zero (even a ``00 02`` prefix), moving the
sample out of the claimed category.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check import classification, compliance
from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKR_DATA_INVALID,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_GENERAL_ERROR,
    CKR_OK,
)
from pkcs11_check.testcases.security import test_padding_oracle

_K = 256
_N = 2**2048 - 159
_E = 65537
_BOUNDARY = 1 << (8 * (_K - 1))


def _rsa_attrs(*_args: Any, **_kwargs: Any) -> dict[int, bytes]:
    return {
        CKA_MODULUS: _N.to_bytes(_K, "big"),
        CKA_PUBLIC_EXPONENT: _E.to_bytes(3, "big"),
    }


def _alternating_decrypt(first: int, second: int) -> Any:
    """A decrypt_single stub alternating two CKRs per call (cat-1/cat-2 legs)."""
    calls = 0

    def _decrypt(*_args: Any, **_kwargs: Any) -> bytes:
        nonlocal calls
        calls += 1
        rv = first if calls % 2 == 1 else second
        raise CkrAssertionError(f"Unexpected CK_RV {rv}", rv)

    return _decrypt


def _stub_rsa_keygen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(test_padding_oracle, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(test_padding_oracle, "destroy_quietly", lambda *_a: None)


# --- Category construction (P11C-0198-015) ---


def test_modular_reduction_can_reintroduce_pkcs1_prefix() -> None:
    """Mechanism demonstration: bytes-then-``% n`` can leave the claimed category.

    ``b"\\x05\\x00\\x00"`` has a nonzero top byte, so the old cat-2 premise
    ("any non-zero high byte → not cat-1") accepted it. Reducing modulo
    ``n = x - 0x205`` moves the final encoding to ``00 02 05`` -- the very
    prefix cat-2 claims to exclude. This pins why the sampler must construct
    the final integer representative directly.
    """
    pre_bytes = b"\x05\x00\x00"
    assert pre_bytes[0] != 0x00
    x = int.from_bytes(pre_bytes, "big")
    n = x - 0x205
    post_bytes = (x % n).to_bytes(3, "big")
    assert post_bytes == b"\x00\x02\x05"


def test_bleichenbacher_cat2_final_bytes_never_have_00_02_prefix() -> None:
    """Cat-2 is sampled as ``B <= m < n``; the final encoding is asserted."""
    for _ in range(200):
        encoded = test_padding_oracle._sample_bleichenbacher_cat2(_N, _K)
        assert len(encoded) == _K
        m = int.from_bytes(encoded, "big")
        assert _BOUNDARY <= m < _N
        assert not (encoded[0] == 0x00 and encoded[1] == 0x02)


def test_bleichenbacher_cat1_final_bytes_keep_prefix_without_separator() -> None:
    """Cat-1 keeps the ``00 02`` prefix with no ``00`` separator, and ``m < n``."""
    for _ in range(200):
        encoded = test_padding_oracle._sample_bleichenbacher_cat1(_N, _K)
        assert len(encoded) == _K
        assert encoded[0] == 0x00 and encoded[1] == 0x02
        assert 0x00 not in encoded[2:]
        assert int.from_bytes(encoded, "big") < _N


def test_manger_intervals_unchanged() -> None:
    """OAEP/Manger categories stay ``[1, B)`` and ``[B, n)`` by construction."""
    for _ in range(200):
        m1 = test_padding_oracle._sample_manger_cat1(_BOUNDARY)
        assert 1 <= m1 < _BOUNDARY
        assert m1.to_bytes(_K, "big")[0] == 0x00
        m2 = test_padding_oracle._sample_manger_cat2(_BOUNDARY, _N)
        assert _BOUNDARY <= m2 < _N
        assert m2.to_bytes(_K, "big")[0] != 0x00


def test_cbc_invalid_corpus_flips_penultimate_block_last_byte() -> None:
    """The CBC invalid sample flips exactly the penultimate block's last byte.

    CBC decryption XORs the previous ciphertext block into the plaintext
    block, so this flips the aligned final-block plaintext byte. With the
    known 105-byte probe plaintext the final byte is ``0x07`` padding, and
    ``0x07 ^ 0xFF = 0xF8`` is not valid PKCS#7 padding under any pad length.
    """
    assert (0x07 ^ 0xFF) > 16
    ciphertext = bytes(range(256)) * 7  # 1792 bytes, multiple of 16
    corrupted = test_padding_oracle._invalidate_cbc_padding_byte(ciphertext)
    assert len(corrupted) == len(ciphertext)
    flip_at = len(ciphertext) - 17
    assert corrupted[flip_at] == ciphertext[flip_at] ^ 0xFF
    assert corrupted[:flip_at] == ciphertext[:flip_at]
    assert corrupted[flip_at + 1 :] == ciphertext[flip_at + 1 :]


# --- Random diversity is diagnostic only (P11C-0198-009, brief item 1) ---


def test_random_pkcs1_diversity_is_diagnostic_not_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two distinct random-ciphertext CKRs emit an EXTENDED note, no oracle."""
    _stub_rsa_keygen(monkeypatch)
    monkeypatch.setattr(test_padding_oracle, "generate_random", lambda *_a: b"\x11" * 256)
    monkeypatch.setattr(
        test_padding_oracle,
        "decrypt_single",
        _alternating_decrypt(CKR_ENCRYPTED_DATA_INVALID, CKR_DATA_INVALID),
    )
    classification.clear()
    compliance.clear_notes()

    test_padding_oracle.TestRSAPaddingOracle().test_pkcs1v15_error_uniformity(
        SimpleNamespace(raw=object(), sh=1)
    )

    assert classification.get_records() == []
    notes = compliance.get_notes()
    assert len(notes) == 1
    assert notes[0].level is ComplianceLevel.EXTENDED
    assert "no controlled" in notes[0].description
    assert "Bleichenbacher" in notes[0].description
    assert "CKR_DATA_INVALID" in notes[0].description
    assert "CKR_ENCRYPTED_DATA_INVALID" in notes[0].description


def test_random_oaep_diversity_is_diagnostic_not_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two distinct random-OAEP CKRs emit an EXTENDED note, no Manger oracle."""
    _stub_rsa_keygen(monkeypatch)
    monkeypatch.setattr(test_padding_oracle, "generate_random", lambda *_a: b"\x11" * 256)
    monkeypatch.setattr(
        test_padding_oracle,
        "decrypt_single",
        _alternating_decrypt(CKR_ENCRYPTED_DATA_INVALID, CKR_DATA_INVALID),
    )
    classification.clear()
    compliance.clear_notes()

    test_padding_oracle.TestRSAPaddingOracle().test_oaep_error_uniformity(
        SimpleNamespace(raw=object(), sh=1)
    )

    assert classification.get_records() == []
    notes = compliance.get_notes()
    assert len(notes) == 1
    assert notes[0].level is ComplianceLevel.EXTENDED
    assert "no controlled" in notes[0].description
    assert "Manger" in notes[0].description


# --- Controlled distinctions stay FAIL oracle, without recovery claims ---


def test_structured_bleichenbacher_distinction_still_fails_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Distinct per-category CKRs still FAIL oracle, minus the query-count claim."""
    _stub_rsa_keygen(monkeypatch)
    monkeypatch.setattr(test_padding_oracle, "read_attributes", _rsa_attrs)
    monkeypatch.setattr(
        test_padding_oracle,
        "decrypt_single",
        _alternating_decrypt(CKR_ENCRYPTED_DATA_INVALID, CKR_DATA_INVALID),
    )
    classification.clear()

    with pytest.raises(Failed) as excinfo:
        test_padding_oracle.TestRSAPaddingOracle().test_pkcs1v15_bleichenbacher_structured_oracle(
            SimpleNamespace(raw=object(), sh=1)
        )

    assert "Bleichenbacher" in str(excinfo.value)
    assert "2^20" not in str(excinfo.value)
    assert "queries" not in str(excinfo.value)
    assert [r.reason for r in classification.get_records()] == ["oracle"]


def test_structured_manger_distinction_still_fails_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Distinct Manger-category CKRs still FAIL oracle, minus the recovery claim."""
    _stub_rsa_keygen(monkeypatch)
    monkeypatch.setattr(test_padding_oracle, "read_attributes", _rsa_attrs)
    monkeypatch.setattr(
        test_padding_oracle,
        "decrypt_single",
        _alternating_decrypt(CKR_ENCRYPTED_DATA_INVALID, CKR_DATA_INVALID),
    )
    classification.clear()

    with pytest.raises(Failed) as excinfo:
        test_padding_oracle.TestRSAPaddingOracle().test_oaep_manger_structured_oracle(
            SimpleNamespace(raw=object(), sh=1)
        )

    assert "Manger" in str(excinfo.value)
    assert "log2" not in str(excinfo.value)
    assert "queries" not in str(excinfo.value)
    assert [r.reason for r in classification.get_records()] == ["oracle"]


# --- Gross timing is a latency diagnostic, not a named oracle (brief item 4) ---


def _stub_rsa_timing(
    monkeypatch: pytest.MonkeyPatch,
    *,
    valid: tuple[float, int],
    invalid: tuple[float, int],
) -> bytes:
    _stub_rsa_keygen(monkeypatch)
    monkeypatch.setattr(test_padding_oracle, "skip_unless_mechanism_flag", lambda *_a, **_k: None)
    valid_ct = b"\xaa" * 256
    monkeypatch.setattr(test_padding_oracle, "encrypt_single", lambda *_a, **_k: valid_ct)
    monkeypatch.setattr(test_padding_oracle, "generate_random", lambda *_a: b"\xbb" * 256)

    def _timed(
        _raw: Any, _sh: int, _key: int, _mech: int, ciphertext: bytes, **_kw: Any
    ) -> tuple[float, int]:
        return valid if ciphertext == valid_ct else invalid

    monkeypatch.setattr(test_padding_oracle, "_timed_decrypt", _timed)
    return valid_ct


def test_rsa_timing_gap_is_diagnostic_not_oracle(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 20x valid/invalid RSA latency gap stays a diagnostic with its ratio."""
    _stub_rsa_timing(
        monkeypatch,
        valid=(0.005, int(CKR_OK)),
        invalid=(0.100, int(CKR_ENCRYPTED_DATA_INVALID)),
    )
    classification.clear()
    compliance.clear_notes()

    test_padding_oracle.TestTimingBasic().test_rsa_decrypt_timing_sanity(
        SimpleNamespace(raw=object(), sh=1)
    )

    assert classification.get_records() == []
    notes = compliance.get_notes()
    assert len(notes) == 1
    assert notes[0].level is ComplianceLevel.EXTENDED
    assert "20.0x" in notes[0].description
    assert "oracle" not in notes[0].description.lower()


def _stub_cbc_timing(
    monkeypatch: pytest.MonkeyPatch,
    *,
    valid: tuple[float, int],
    invalid: tuple[float, int],
) -> bytes:
    monkeypatch.setattr(test_padding_oracle, "require_operational_aes_keygen", lambda *_a: None)
    monkeypatch.setattr(test_padding_oracle, "gen_aes_key_or_xfail", lambda *_a, **_k: 7)
    monkeypatch.setattr(test_padding_oracle, "generate_random", lambda *_a: b"\x11" * 16)
    valid_ct = bytes(range(256))[:112]
    assert len(valid_ct) == 112
    monkeypatch.setattr(test_padding_oracle, "encrypt_single", lambda *_a, **_k: valid_ct)
    monkeypatch.setattr(test_padding_oracle, "destroy_quietly", lambda *_a: None)

    def _timed(
        _raw: Any, _sh: int, _key: int, _mech: int, ciphertext: bytes, **_kw: Any
    ) -> tuple[float, int]:
        return valid if ciphertext == valid_ct else invalid

    monkeypatch.setattr(test_padding_oracle, "_timed_decrypt", _timed)
    return valid_ct


def _cbc_session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


def test_cbc_timing_gap_is_diagnostic_not_lucky13(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 20x CBC latency gap stays a diagnostic; the Lucky13 name is gone."""
    _stub_cbc_timing(
        monkeypatch,
        valid=(0.005, int(CKR_OK)),
        invalid=(0.100, int(CKR_ENCRYPTED_DATA_INVALID)),
    )
    classification.clear()
    compliance.clear_notes()

    test_padding_oracle.TestTimingBasic().test_aes_cbc_pad_decrypt_timing_sanity(_cbc_session())

    assert classification.get_records() == []
    notes = compliance.get_notes()
    assert len(notes) == 1
    assert notes[0].level is ComplianceLevel.EXTENDED
    assert "20.0x" in notes[0].description
    assert "exploitability" in notes[0].description
    assert "lucky13" not in notes[0].description.lower()
    assert "oracle" not in notes[0].description.lower()


def test_cbc_accepted_guaranteed_invalid_padding_fails_accepted_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKR_OK on the guaranteed-invalid CBC sample is hard FAIL accepted_invalid."""
    _stub_cbc_timing(
        monkeypatch,
        valid=(0.005, int(CKR_OK)),
        invalid=(0.001, int(CKR_OK)),
    )
    classification.clear()

    with pytest.raises(Failed, match="guaranteed-invalid"):
        test_padding_oracle.TestTimingBasic().test_aes_cbc_pad_decrypt_timing_sanity(_cbc_session())

    assert [r.reason for r in classification.get_records()] == ["accepted_invalid"]


# --- Preserved adverse behavior (brief item 6) ---


def test_cbc_unexpected_ckr_remains_adverse(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unrelated CKR on the CBC invalid leg stays adverse (nonspec_reject)."""
    _stub_cbc_timing(
        monkeypatch,
        valid=(0.005, int(CKR_OK)),
        invalid=(0.001, int(CKR_GENERAL_ERROR)),
    )
    classification.clear()

    with pytest.raises(pytest.xfail.Exception):
        test_padding_oracle.TestTimingBasic().test_aes_cbc_pad_decrypt_timing_sanity(_cbc_session())

    assert [r.reason for r in classification.get_records()] == ["nonspec_reject"]


def test_cbc_valid_decrypt_failure_remains_adverse_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failing valid CBC leg stays adverse (not_operational), timing void."""
    _stub_cbc_timing(
        monkeypatch,
        valid=(0.005, int(CKR_DEVICE_ERROR)),
        invalid=(0.001, int(CKR_ENCRYPTED_DATA_INVALID)),
    )
    classification.clear()

    with pytest.raises(pytest.xfail.Exception):
        test_padding_oracle.TestTimingBasic().test_aes_cbc_pad_decrypt_timing_sanity(_cbc_session())

    assert [r.reason for r in classification.get_records()] == ["not_operational"]


def test_rsa_timing_setup_refusal_remains_adverse_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An advertised-but-refused RSA setup encrypt stays adverse, not a pass."""
    _stub_rsa_keygen(monkeypatch)
    monkeypatch.setattr(test_padding_oracle, "skip_unless_mechanism_flag", lambda *_a, **_k: None)

    def _refuse(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", CKR_DEVICE_ERROR)

    monkeypatch.setattr(test_padding_oracle, "encrypt_single", _refuse)
    classification.clear()

    with pytest.raises(pytest.xfail.Exception):
        test_padding_oracle.TestTimingBasic().test_rsa_decrypt_timing_sanity(
            SimpleNamespace(raw=object(), sh=1)
        )

    assert [r.reason for r in classification.get_records()] == ["not_operational"]
