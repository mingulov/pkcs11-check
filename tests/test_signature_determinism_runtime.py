"""F8 runtime regressions for deterministic-DSS reframing (P11C-0198-002, P11C-0198-014).

Same-message identical ECDSA/DSA signatures are valid deterministic signing
(RFC 6979 / FIPS 186-5) and PASS; only a repeated valid ``r`` across distinct
messages/digests is a nonce-reuse signal (crypto ``wrong_result`` FAIL worded
as a dangerous repeated/equivalent-nonce signal, never as demonstrated key
recovery). Public-``r`` distribution is a serialized EXTENDED diagnostic.

Scripted providers stand in for tokens: ``_Signer`` answers ``sign_single``
calls from a per-input responder so same-input determinism, varying output,
repeated ``r``, DER shape, and malformed output are each reproducible.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification, compliance
from pkcs11_check.raw.der import ecdsa_sig_to_der
from pkcs11_check.raw.types_std import CKA_SUBPRIME, CKM_ECDSA_SHA1
from pkcs11_check.testcases import test_dsa_complete as tdc
from pkcs11_check.testcases import test_ecdsa_extended as tee
from pkcs11_check.testcases import test_sign as ts
from pkcs11_check.testcases.security import test_nonce_quality as tnq

# secp256r1 group order n (public constant; NIST FIPS 186-5 / SEC 2).
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


@pytest.fixture(autouse=True)
def _clear_state() -> Any:
    classification.clear()
    compliance.clear_notes()
    yield
    classification.clear()
    compliance.clear_notes()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=SimpleNamespace(), sh=1, has_mechanism=lambda _name: True)


def _raw_sig(r: int, s: int, half: int = 32) -> bytes:
    return r.to_bytes(half, "big") + s.to_bytes(half, "big")


class _Signer:
    """Scripted ``sign_single`` replacement answering from a responder."""

    def __init__(self, responder: Callable[[bytes, int], bytes]) -> None:
        self._responder = responder
        self.calls: list[bytes] = []

    def __call__(self, *args: object, **kwargs: object) -> bytes:
        data = args[4]
        assert isinstance(data, bytes)
        self.calls.append(data)
        return self._responder(data, len(self.calls) - 1)


def _deterministic_provider(half: int = 32, order: int = _P256_N) -> _Signer:
    """A deterministic token: same input -> same signature, new input -> fresh one."""
    memo: dict[bytes, bytes] = {}

    def _respond(data: bytes, _index: int) -> bytes:
        if data not in memo:
            k = len(memo) + 1
            memo[data] = _raw_sig(k, order - k, half)
        return memo[data]

    return _Signer(_respond)


def _last_record() -> classification.Classification:
    records = classification.get_records()
    assert len(records) == 1
    return records[0]


def _patch_common(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
    signer: _Signer,
    *,
    keygen_name: str,
) -> None:
    monkeypatch.setattr(module, "sign_single", signer)
    monkeypatch.setattr(module, keygen_name, lambda *_a, **_k: (2, 3))
    monkeypatch.setattr(module, "destroy_quietly", lambda *_a: None)


def test_prehash_same_message_identical_passes_as_deterministic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = _deterministic_provider()
    _patch_common(monkeypatch, tee, signer, keygen_name="gen_ec_keypair")
    tee.TestECDSAPrehash().test_deterministic_signing_distinct_r(
        _session(), "ECDSA_SHA1", CKM_ECDSA_SHA1
    )
    assert classification.get_records() == []
    assert signer.calls[0] == signer.calls[1]
    tail = signer.calls[2:]
    assert len(tail) >= 10
    assert len(set(tail)) == len(tail)
    notes = compliance.get_notes()
    assert len(notes) == 1
    assert notes[0].level is compliance.ComplianceLevel.STANDARD
    assert "deterministic" in notes[0].description.lower()


def test_prehash_same_message_varying_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    def _respond(data: bytes, index: int) -> bytes:
        k = index + 1
        return _raw_sig(k, _P256_N - k)

    signer = _Signer(_respond)
    _patch_common(monkeypatch, tee, signer, keygen_name="gen_ec_keypair")
    tee.TestECDSAPrehash().test_deterministic_signing_distinct_r(
        _session(), "ECDSA_SHA1", CKM_ECDSA_SHA1
    )
    assert classification.get_records() == []
    notes = compliance.get_notes()
    assert len(notes) == 1
    assert notes[0].level is compliance.ComplianceLevel.EXTENDED
    assert "varying" in notes[0].description.lower()


def test_prehash_repeated_r_across_distinct_inputs_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _respond(data: bytes, index: int) -> bytes:
        if index == 2:
            return _raw_sig(4242, 100)
        if index == 5:
            return _raw_sig(4242, 200)
        k = index + 10_000
        return _raw_sig(k, _P256_N - k)

    signer = _Signer(_respond)
    _patch_common(monkeypatch, tee, signer, keygen_name="gen_ec_keypair")
    with pytest.raises(Failed) as exc_info:
        tee.TestECDSAPrehash().test_deterministic_signing_distinct_r(
            _session(), "ECDSA_SHA1", CKM_ECDSA_SHA1
        )
    assert not isinstance(exc_info.value, XFailed)
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert "repeat" in record.summary.lower()
    assert "nonce" in record.summary.lower()
    assert "recoverable" not in record.summary.lower()
    assert "key recovery" not in record.summary.lower()


def test_prehash_der_shaped_output_xfails_before_statistics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = _Signer(lambda data, index: ecdsa_sig_to_der(index + 1, index + 2))
    _patch_common(monkeypatch, tee, signer, keygen_name="gen_ec_keypair")
    with pytest.raises(XFailed):
        tee.TestECDSAPrehash().test_deterministic_signing_distinct_r(
            _session(), "ECDSA_SHA1", CKM_ECDSA_SHA1
        )
    assert _last_record().reason == "honest_deviation"
    assert len(signer.calls) == 1


def test_prehash_malformed_output_fails_without_nonce_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = _Signer(lambda data, index: b"\x01" * 63)
    _patch_common(monkeypatch, tee, signer, keygen_name="gen_ec_keypair")
    with pytest.raises(Failed) as exc_info:
        tee.TestECDSAPrehash().test_deterministic_signing_distinct_r(
            _session(), "ECDSA_SHA1", CKM_ECDSA_SHA1
        )
    assert not isinstance(exc_info.value, XFailed)
    record = _last_record()
    assert record.reason == "wrong_result"
    assert "nonce" not in record.summary.lower()
    assert "recover" not in record.summary.lower()


def test_raw_ecdsa_same_message_identical_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    signer = _deterministic_provider()
    _patch_common(monkeypatch, ts, signer, keygen_name="gen_ec_keypair_or_xfail")
    ts.TestECDSASignature().test_ecdsa_deterministic_signing_distinct_r(_session())
    assert classification.get_records() == []
    assert signer.calls[0] == signer.calls[1]
    tail = signer.calls[2:]
    assert len(set(tail)) == len(tail)


def test_raw_ecdsa_repeated_r_fails_even_when_s_differs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _respond(data: bytes, index: int) -> bytes:
        if index == 2:
            return _raw_sig(777, 11)
        if index == 6:
            return _raw_sig(777, 22)
        k = index + 10_000
        return _raw_sig(k, _P256_N - k)

    signer = _Signer(_respond)
    _patch_common(monkeypatch, ts, signer, keygen_name="gen_ec_keypair_or_xfail")
    with pytest.raises(Failed) as exc_info:
        ts.TestECDSASignature().test_ecdsa_deterministic_signing_distinct_r(_session())
    assert not isinstance(exc_info.value, XFailed)
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert "repeat" in record.summary.lower()


def _patch_dsa(
    monkeypatch: pytest.MonkeyPatch,
    signer: _Signer,
    subprime: bytes,
) -> None:
    monkeypatch.setattr(tdc, "sign_single", signer)
    monkeypatch.setattr(tdc, "_generate_dsa_keypair", lambda _rs: (7, 2, 3))
    monkeypatch.setattr(tdc, "read_attributes", lambda *_a: {int(CKA_SUBPRIME): subprime})
    monkeypatch.setattr(tdc, "destroy_quietly", lambda *_a: None)


def test_raw_dsa_width_derived_from_readback_subprime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    q = int.from_bytes(b"\x11" * 28, "big")
    signer = _deterministic_provider(half=28, order=q)
    _patch_dsa(monkeypatch, signer, b"\x11" * 28)
    tdc.TestDSARaw().test_raw_dsa_deterministic_signing_distinct_r(_session())
    assert classification.get_records() == []
    assert signer.calls[0] == signer.calls[1]


def test_raw_dsa_fixed_64byte_sig_rejected_when_q_is_224bit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = _deterministic_provider()
    _patch_dsa(monkeypatch, signer, b"\x11" * 28)
    with pytest.raises(Failed):
        tdc.TestDSARaw().test_raw_dsa_deterministic_signing_distinct_r(_session())
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.detail is not None
    assert record.detail["expected_length"] == 56
    assert record.detail["actual_length"] == 64


def test_raw_dsa_repeated_r_across_distinct_digests_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    q = int.from_bytes(b"\x22" * 32, "big")

    def _respond(data: bytes, index: int) -> bytes:
        if index == 2:
            return _raw_sig(99, 101, half=32)
        if index == 4:
            return _raw_sig(99, 102, half=32)
        k = index + 10_000
        return _raw_sig(k, q - k, half=32)

    signer = _Signer(_respond)
    _patch_dsa(monkeypatch, signer, b"\x22" * 32)
    with pytest.raises(Failed) as exc_info:
        tdc.TestDSARaw().test_raw_dsa_deterministic_signing_distinct_r(_session())
    assert not isinstance(exc_info.value, XFailed)
    assert _last_record().reason == "wrong_result"


def test_nonce_reuse_p256_signs_50_distinct_digests_and_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = _deterministic_provider()
    _patch_common(monkeypatch, tnq, signer, keygen_name="gen_ec_keypair_or_xfail")
    tnq.TestECDSANonceReuse().test_nonce_reuse_p256(_session())
    assert classification.get_records() == []
    assert len(signer.calls) == 50
    assert len(set(signer.calls)) == 50
    for call in signer.calls:
        assert len(call) == hashlib.sha256().digest_size


def test_nonce_reuse_p256_repeated_r_fails_without_key_recovery_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _respond(data: bytes, index: int) -> bytes:
        if index == 7:
            return _raw_sig(555, 111)
        if index == 42:
            return _raw_sig(555, 222)
        k = index + 10_000
        return _raw_sig(k, _P256_N - k)

    signer = _Signer(_respond)
    _patch_common(monkeypatch, tnq, signer, keygen_name="gen_ec_keypair_or_xfail")
    with pytest.raises(Failed) as exc_info:
        tnq.TestECDSANonceReuse().test_nonce_reuse_p256(_session())
    assert not isinstance(exc_info.value, XFailed)
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_Sign"
    assert record.mechanism == "CKM_ECDSA"
    assert "repeat" in record.summary.lower()
    assert "equivalent-nonce" in record.summary.lower()
    assert "recoverable" not in record.summary.lower()
    assert "key recovery" not in record.summary.lower()
    assert record.detail is not None
    assert record.detail["first_index"] == 7
    assert record.detail["repeat_index"] == 42


def test_nonce_reuse_p256_der_output_xfails_on_first_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = _Signer(lambda data, index: ecdsa_sig_to_der(index + 1, index + 2))
    _patch_common(monkeypatch, tnq, signer, keygen_name="gen_ec_keypair_or_xfail")
    with pytest.raises(XFailed):
        tnq.TestECDSANonceReuse().test_nonce_reuse_p256(_session())
    assert _last_record().reason == "honest_deviation"
    assert len(signer.calls) == 1


def test_nonce_reuse_p256_malformed_output_fails_without_nonce_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = _Signer(lambda data, index: b"\x02" * 63)
    _patch_common(monkeypatch, tnq, signer, keygen_name="gen_ec_keypair_or_xfail")
    with pytest.raises(Failed) as exc_info:
        tnq.TestECDSANonceReuse().test_nonce_reuse_p256(_session())
    assert not isinstance(exc_info.value, XFailed)
    assert _last_record().reason == "wrong_result"
    assert "nonce" not in _last_record().summary.lower()


def test_different_messages_unique_r_passes_with_strict_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = _deterministic_provider()
    _patch_common(monkeypatch, tnq, signer, keygen_name="gen_ec_keypair_or_xfail")
    tnq.TestECDSANonceReuse().test_different_messages_different_r(_session())
    assert classification.get_records() == []
    assert len(signer.calls) == 20
    assert len(set(signer.calls)) == 20


def test_different_messages_der_output_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    signer = _Signer(lambda data, index: ecdsa_sig_to_der(index + 1, index + 2))
    _patch_common(monkeypatch, tnq, signer, keygen_name="gen_ec_keypair_or_xfail")
    with pytest.raises(XFailed):
        tnq.TestECDSANonceReuse().test_different_messages_different_r(_session())
    assert _last_record().reason == "honest_deviation"


def test_different_messages_repeated_r_fails_classified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _respond(data: bytes, index: int) -> bytes:
        if index in (3, 9):
            return _raw_sig(31337, 400 + index)
        k = index + 10_000
        return _raw_sig(k, _P256_N - k)

    signer = _Signer(_respond)
    _patch_common(monkeypatch, tnq, signer, keygen_name="gen_ec_keypair_or_xfail")
    with pytest.raises(Failed) as exc_info:
        tnq.TestECDSANonceReuse().test_different_messages_different_r(_session())
    assert not isinstance(exc_info.value, XFailed)
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"


def test_distribution_skew_is_extended_note_only(monkeypatch: pytest.MonkeyPatch) -> None:
    def _respond(data: bytes, index: int) -> bytes:
        return _raw_sig((1 << 240) + index, (1 << 240) + 2 * index + 1)

    signer = _Signer(_respond)
    _patch_common(monkeypatch, tnq, signer, keygen_name="gen_ec_keypair_or_xfail")
    tnq.TestECDSAPublicRDistribution().test_public_r_distribution(_session())
    assert classification.get_records() == []
    assert len(signer.calls) == 200
    notes = compliance.get_notes()
    assert len(notes) == 1
    assert notes[0].level is compliance.ComplianceLevel.EXTENDED
    assert "public" in notes[0].description.lower()
    assert "200" in notes[0].description
    assert "nonce" not in notes[0].description.lower()
    assert "lattice" not in notes[0].description.lower()
    assert "putty" not in notes[0].description.lower()


def test_distribution_malformed_shape_still_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    def _respond(data: bytes, index: int) -> bytes:
        if index == 3:
            return b"\x03" * 63
        return _raw_sig(index + 1, index + 2)

    signer = _Signer(_respond)
    _patch_common(monkeypatch, tnq, signer, keygen_name="gen_ec_keypair_or_xfail")
    with pytest.raises(Failed):
        tnq.TestECDSAPublicRDistribution().test_public_r_distribution(_session())
    assert _last_record().reason == "wrong_result"


def test_deterministic_check_notes_deterministic_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = _Signer(lambda data, index: _raw_sig(9, 10))
    _patch_common(monkeypatch, tnq, signer, keygen_name="gen_ec_keypair_or_xfail")
    tnq.TestECDSADeterminism().test_deterministic_check(_session())
    assert classification.get_records() == []
    notes = compliance.get_notes()
    assert len(notes) == 1
    assert notes[0].level is compliance.ComplianceLevel.STANDARD
    assert "deterministic" in notes[0].description.lower()


def test_deterministic_check_notes_varying_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    signer = _Signer(lambda data, index: _raw_sig(index + 1, index + 2))
    _patch_common(monkeypatch, tnq, signer, keygen_name="gen_ec_keypair_or_xfail")
    tnq.TestECDSADeterminism().test_deterministic_check(_session())
    assert classification.get_records() == []
    notes = compliance.get_notes()
    assert len(notes) == 1
    assert notes[0].level is compliance.ComplianceLevel.EXTENDED
    assert "varying" in notes[0].description.lower()
