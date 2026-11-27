"""Signature-width and subgroup-order contracts (QC5, issue #57).

Covers the three Task 14 legs with fakes only (no provider, no Docker):

- W1 (QC5a): ECDSA overlong zero-padded halves (1/2/100 bytes per half,
  LEN_RANGE expectation, other clean refusal xfail) plus the fixed P-256
  vector whose halves can both be shortened (Verify permits shorter even
  encodings; Sign must return exactly 2*nLen).
- W2 (QC5b): the even padded-half DSA case in the ordinary (``not slow``)
  profile via a bounded fixed-vector fixture (RFC 6979 A.2.2 DSA-2048);
  slow generation, truncation and odd-length negatives stay distinct nodes.
- W3 (QC5c): trusted subgroup orders stored separately from field sizes
  (sect409k1, secp160r1, secp224k1 with SEC 2 citations), the
  ``ceil(order.bit_length()/8)`` crosscheck, and independent ECDSA
  verification on curves the ``cryptography`` package cannot do.

Style: pure-helper contracts plus fake-driven probes of the real test
methods; pytest outcomes are captured as data so an unexpected xfail fails
the meta-test instead of passing silently.
"""

from __future__ import annotations

import ctypes
import hashlib
import sys
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, Skipped, XFailed
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    encode_dss_signature,
)

from pkcs11_check import classification
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_BASE,
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_PRIME,
    CKA_SUBPRIME,
    CKA_VALUE,
    CKF_SIGN,
    CKK_DSA,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKR_BUFFER_TOO_SMALL,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_KEY_SIZE_RANGE,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
)
from pkcs11_check.testcases import test_dsa_complete as dsa_mod
from pkcs11_check.testcases import test_ec_curves as ec_mod
from pkcs11_check.testcases._ec_export import SECP256R1_ORDER
from pkcs11_check.testcases._import_negotiation import reset_import_negotiation_cache
from pkcs11_check.testcases.ckr import test_ckr_verify as ckr_mod


@pytest.fixture(autouse=True)
def _clear_classifications() -> Any:
    classification.clear()
    reset_import_negotiation_cache()
    yield
    classification.clear()
    reset_import_negotiation_cache()


def _outcome(fn: Any, *args: Any, **kwargs: Any) -> str:
    """Run a real test method, capturing the pytest outcome as data."""
    try:
        fn(*args, **kwargs)
    except XFailed:
        return "xfail"
    except Failed:
        return "fail"
    except Skipped:
        return "skip"
    return "pass"


def _last_record() -> classification.Classification:
    records = classification.get_records()
    assert records
    return records[-1]


def _decode_template(tmpl: Any, count: int) -> dict[int, bytes]:
    """Decode a (CK_ATTRIBUTE * count) array into {type: raw bytes}."""
    out: dict[int, bytes] = {}
    for i in range(count):
        attr = tmpl[i]
        out[int(attr.type)] = bytes(ctypes.string_at(attr.pValue, int(attr.ulValueLen)))
    return out


def _ckr(v: Any) -> int:
    return int(v)


# ---------------------------------------------------------------------------
# W1 fixtures: fixed P-256 vector provenance
# ---------------------------------------------------------------------------
# d = int(sha256(b"QC5a P-256 fixed private")) mod (n-1) + 1; digest =
# sha256(b"QC5a P-256 fixed digest"); k iterated from 1, first k with both
# scalars < 2**248 (k=81953). Independently verified with `cryptography`
# 49.0.0 (Prehashed SHA-256) on 2026-10-24, full and shortened encodings.

_W1_D = bytes.fromhex("8f9406107943901436d1df4869542b662c2a4276bd66220e6efb2fa3cec7522c")
_W1_QX = 0x9C1E48819ADD8B9400B03B0577B56794BBBD8D4C803CAB2BFF254CC88C3C772D
_W1_QY = 0xCC0C0E0C9F9FE37822E9EE3A3502B3C885D034C675929760A5EE5AD3CE98B3F4
_W1_DIGEST = bytes.fromhex("2a285e19f4ad9f1c910f31e0a0cfe5b17b5a2c65224372b64d5a040e12259126")
_W1_R = 0x00BFC7D9A26C4B000FFF24596BE6473D3E0CF038D6E26F516F4629A63E3A0903
_W1_S = 0x0096F21BCA871507F3100EB63974BFCCB5E82FA52638BC726C3AD893906CC10F


def _w1_full_sig() -> bytes:
    return _W1_R.to_bytes(32, "big") + _W1_S.to_bytes(32, "big")


def _w1_short_sig() -> bytes:
    full = _w1_full_sig()
    assert full[0] == 0 and full[32] == 0
    return full[1:32] + full[33:64]


class _W1Raw:
    """In-memory raw boundary for the W1 ECDSA-width legs."""

    def __init__(
        self,
        *,
        sign_payload: bytes = b"",
        verify_rvs: list[int] | None = None,
        create_rv: int = _ckr(CKR_OK),
        generate_rv: int = _ckr(CKR_OK),
        init_rv: int = _ckr(CKR_OK),
        verify_init_script: list[int] | None = None,
    ) -> None:
        self.sign_payload = sign_payload if sign_payload else _w1_full_sig()
        self.verify_rvs = list(verify_rvs) if verify_rvs else [_ckr(CKR_OK)]
        self.create_rv = create_rv
        self.generate_rv = generate_rv
        self.init_rv = init_rv
        self.verify_init_script = (
            list(verify_init_script) if verify_init_script is not None else None
        )
        self.verify_init_calls = 0
        self.sign_inputs: list[bytes] = []
        self.verify_calls: list[tuple[bytes, bytes]] = []
        self.create_templates: list[dict[int, bytes]] = []
        self.generate_curves: list[bytes] = []
        self.destroy_calls: list[int] = []
        self._handle = 100

    def _next_handle(self, handle: Any) -> None:
        self._handle += 1
        handle._obj.value = self._handle

    def C_GenerateKeyPair(  # noqa: N802
        self,
        session: int,
        mechanism: Any,
        public_template: Any,
        public_count: int,
        _private_template: Any,
        _private_count: int,
        public_handle: Any,
        private_handle: Any,
    ) -> int:
        del session, mechanism, _private_template, _private_count
        decoded = _decode_template(public_template, public_count)
        self.generate_curves.append(decoded[_ckr(CKA_EC_PARAMS)])
        if self.generate_rv == _ckr(CKR_OK):
            self._next_handle(public_handle)
            self._next_handle(private_handle)
        return self.generate_rv

    def C_SignInit(self, session: int, mechanism: Any, key: int) -> int:  # noqa: N802
        del session, mechanism, key
        return self.init_rv

    def C_Sign(  # noqa: N802
        self,
        session: int,
        in_buf: Any,
        in_len: int,
        out_buf: Any,
        out_len: Any,
    ) -> int:
        del session
        self.sign_inputs.append(bytes(in_buf[:in_len]))
        if out_buf is None:
            out_len._obj.value = len(self.sign_payload)
            return _ckr(CKR_OK)
        for i, byte in enumerate(self.sign_payload):
            out_buf[i] = byte
        out_len._obj.value = len(self.sign_payload)
        return _ckr(CKR_OK)

    def C_VerifyInit(self, session: int, mechanism: Any, key: int) -> int:  # noqa: N802
        del session, mechanism, key
        self.verify_init_calls += 1
        if self.verify_init_script is None:
            return self.init_rv
        if len(self.verify_init_script) > 1:
            return self.verify_init_script.pop(0)
        return self.verify_init_script[0]

    def C_Verify(  # noqa: N802
        self,
        session: int,
        data_buf: Any,
        data_len: int,
        sig_buf: Any,
        sig_len: int,
    ) -> int:
        del session
        self.verify_calls.append((bytes(data_buf[:data_len]), bytes(sig_buf[:sig_len])))
        if len(self.verify_rvs) > 1:
            return self.verify_rvs.pop(0)
        return self.verify_rvs[0]

    def C_CreateObject(self, session: int, tmpl: Any, count: int, handle: Any) -> int:  # noqa: N802
        del session
        if tmpl is None:
            handle._obj.value = 0
            return _ckr(CKR_OK)
        self.create_templates.append(_decode_template(tmpl, count))
        if self.create_rv == _ckr(CKR_OK):
            self._next_handle(handle)
        return self.create_rv

    def C_DestroyObject(self, session: int, handle: int) -> int:  # noqa: N802
        del session
        self.destroy_calls.append(int(handle))
        return _ckr(CKR_OK)

    def C_SessionCancel(self, session: int, flags: int) -> int:  # noqa: N802
        del session, flags
        return _ckr(CKR_OK)


def _w1_session(raw: _W1Raw) -> SimpleNamespace:
    return SimpleNamespace(
        raw=raw,
        sh=7,
        slot_id=3,
        has_mechanism=lambda name: name in {"EC_KEY_PAIR_GEN", "ECDSA"},
        has_mechanism_flag=lambda _mech, _flag: True,
    )


def _w1_crypto_key() -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicNumbers(_W1_QX, _W1_QY, ec.SECP256R1()).public_key()


def test_w1_production_vector_matches_pinned_independent_values() -> None:
    assert ckr_mod._QC5A_D == _W1_D
    assert ckr_mod._QC5A_QX == _W1_QX
    assert ckr_mod._QC5A_QY == _W1_QY
    assert ckr_mod._QC5A_DIGEST == _W1_DIGEST
    assert ckr_mod._QC5A_R == _W1_R
    assert ckr_mod._QC5A_S == _W1_S
    assert ckr_mod._QC5A_SIG_FULL == _w1_full_sig()
    assert ckr_mod._QC5A_SIG_SHORT == _w1_short_sig()
    assert ckr_mod._QC5A_PAD_LENS == (1, 2, 100)


def test_w1_fixed_vector_verifies_independently() -> None:
    pub = _w1_crypto_key()
    pub.verify(
        encode_dss_signature(_W1_R, _W1_S),
        _W1_DIGEST,
        ec.ECDSA(Prehashed(hashes.SHA256())),
    )


def test_w1_both_halves_are_shortenable_to_a_valid_encoding() -> None:
    full = _w1_full_sig()
    assert full[0] == 0 and full[32] == 0
    short = _w1_short_sig()
    assert len(short) == 62
    assert int.from_bytes(short[:31], "big") == _W1_R
    assert int.from_bytes(short[31:], "big") == _W1_S
    _w1_crypto_key().verify(
        encode_dss_signature(_W1_R, _W1_S),
        _W1_DIGEST,
        ec.ECDSA(Prehashed(hashes.SHA256())),
    )


def test_w1_fixed_vector_scalars_are_in_range() -> None:
    assert 0 < _W1_R < SECP256R1_ORDER
    assert 0 < _W1_S < SECP256R1_ORDER


def _w1_overlong_digest() -> bytes:
    return hashlib.sha256(b"QC5a overlong-half stimulus").digest()


@pytest.mark.parametrize("pad_len", [1, 2, 100])
def test_w1_overlong_halves_len_range_is_pass(pad_len: int) -> None:
    # X4: the token first verifies the UNMODIFIED stimulus (control), then is
    # re-initialized for the padded negative; both calls' inputs are exact.
    raw = _W1Raw(verify_rvs=[_ckr(CKR_OK), _ckr(CKR_SIGNATURE_LEN_RANGE)])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_overlong_zero_padded_halves,
        _w1_session(raw),
        False,
        pad_len,
    )
    assert outcome == "pass"
    assert raw.generate_curves == [encode_named_curve_parameters("secp256r1")]
    assert raw.verify_init_calls == 2
    assert len(raw.verify_calls) == 2
    control_data, control_sig = raw.verify_calls[0]
    assert control_data == _w1_overlong_digest()
    assert control_sig == _w1_full_sig()
    neg_data, padded = raw.verify_calls[1]
    assert neg_data == _w1_overlong_digest()
    assert len(padded) == 2 * (32 + pad_len)
    first, second = padded[: 32 + pad_len], padded[32 + pad_len :]
    assert len(first) == len(second)
    assert first[:pad_len] == b"\x00" * pad_len
    assert second[:pad_len] == b"\x00" * pad_len
    assert int.from_bytes(first, "big") == _W1_R
    assert int.from_bytes(second, "big") == _W1_S


@pytest.mark.parametrize(
    "rv",
    [
        _ckr(CKR_SIGNATURE_INVALID),
        _ckr(CKR_FUNCTION_FAILED),
        _ckr(CKR_DEVICE_ERROR),
    ],
)
def test_w1_overlong_halves_other_clean_refusal_is_xfail(rv: int) -> None:
    raw = _W1Raw(verify_rvs=[_ckr(CKR_OK), rv])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_overlong_zero_padded_halves,
        _w1_session(raw),
        False,
        100,
    )
    assert outcome == "xfail"
    record = _last_record()
    assert record.reason == "nonspec_reject"
    assert record.actual_ckr is not None


def test_w1_overlong_halves_acceptance_is_fail() -> None:
    raw = _W1Raw(verify_rvs=[_ckr(CKR_OK), _ckr(CKR_OK)])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_overlong_zero_padded_halves,
        _w1_session(raw),
        False,
        1,
    )
    assert outcome == "fail"
    record = _last_record()
    assert record.reason == "accepted_invalid"
    # kind rides from the shared ecdsa_signature_len_range expectation (policy).
    assert record.kind == "policy"


def test_w1_overlong_halves_undefined_rv_is_fail() -> None:
    raw = _W1Raw(verify_rvs=[_ckr(CKR_OK), 0x12345678])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_overlong_zero_padded_halves,
        _w1_session(raw),
        False,
        2,
    )
    assert outcome == "fail"


def test_w1_overlong_halves_len_range_passes_strict() -> None:
    raw = _W1Raw(verify_rvs=[_ckr(CKR_OK), _ckr(CKR_SIGNATURE_LEN_RANGE)])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_overlong_zero_padded_halves,
        _w1_session(raw),
        True,
        1,
    )
    assert outcome == "pass"


@pytest.mark.parametrize(
    "control_rv",
    [_ckr(CKR_SIGNATURE_LEN_RANGE), _ckr(CKR_SIGNATURE_INVALID)],
    ids=["len-range", "invalid"],
)
def test_w1_overlong_defective_stimulus_is_fail(control_rv: int) -> None:
    # X4: the fake emits the fixed signature over this node's DIFFERENT
    # digest -- independently invalid (proven below) -- and rejects the
    # padded length. The unmodified-stimulus control must fail the test
    # instead of letting the negative pass on a defective premise.
    stimulus = _w1_overlong_digest()
    assert stimulus != _W1_DIGEST
    with pytest.raises(InvalidSignature):
        _w1_crypto_key().verify(
            encode_dss_signature(_W1_R, _W1_S),
            stimulus,
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
    raw = _W1Raw(verify_rvs=[control_rv, _ckr(CKR_SIGNATURE_LEN_RANGE)])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_overlong_zero_padded_halves,
        _w1_session(raw),
        False,
        1,
    )
    assert outcome == "fail"
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_Verify"
    # The negative never ran: the defective premise terminated the leg.
    assert len(raw.verify_calls) == 1
    assert raw.verify_calls[0] == (stimulus, _w1_full_sig())


def test_w1_overlong_control_refusal_is_xfail() -> None:
    # X4: the control verify refuses without evaluating -> the premise is
    # unestablished, not_operational xfail (original RV preserved).
    raw = _W1Raw(verify_rvs=[_ckr(CKR_DEVICE_ERROR), _ckr(CKR_OK)])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_overlong_zero_padded_halves,
        _w1_session(raw),
        False,
        1,
    )
    assert outcome == "xfail"
    record = _last_record()
    assert record.reason == "not_operational"
    assert record.actual_ckr == "CKR_DEVICE_ERROR"


def test_w1_overlong_control_undefined_rv_is_fail() -> None:
    # X4: an undefined control-verify RV is a metadata failure.
    raw = _W1Raw(verify_rvs=[0x12345678, _ckr(CKR_OK)])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_overlong_zero_padded_halves,
        _w1_session(raw),
        False,
        100,
    )
    assert outcome == "fail"
    assert _last_record().reason == "self_contradiction"


def test_w1_old_short_all_zero_negative_is_unchanged() -> None:
    raw = _W1Raw(verify_rvs=[_ckr(CKR_SIGNATURE_LEN_RANGE)])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_signature_wrong_length,
        _w1_session(raw),
        False,
    )
    assert outcome == "pass"
    assert len(raw.verify_calls) == 1
    _data, sig = raw.verify_calls[0]
    assert sig == b"\x00" * 32
    assert raw.sign_inputs == []


def test_w1_shorter_encoding_both_verify_is_pass() -> None:
    raw = _W1Raw(verify_rvs=[_ckr(CKR_OK), _ckr(CKR_OK)])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_shorter_even_encoding_verifies,
        _w1_session(raw),
    )
    assert outcome == "pass"
    assert len(raw.verify_calls) == 2
    assert raw.verify_calls[0][1] == _w1_full_sig()
    assert raw.verify_calls[1][1] == _w1_short_sig()
    assert raw.verify_calls[0][0] == _W1_DIGEST
    assert raw.verify_calls[1][0] == _W1_DIGEST
    assert len(raw.create_templates) == 1
    point = b"\x04" + _W1_QX.to_bytes(32, "big") + _W1_QY.to_bytes(32, "big")
    assert raw.create_templates[0][_ckr(CKA_EC_POINT)] == bytes([0x04, len(point)]) + point
    assert raw.create_templates[0][_ckr(CKA_EC_PARAMS)] == encode_named_curve_parameters(
        "secp256r1"
    )


@pytest.mark.parametrize(
    "rv",
    [
        _ckr(CKR_SIGNATURE_LEN_RANGE),
        _ckr(CKR_SIGNATURE_INVALID),
        _ckr(CKR_FUNCTION_FAILED),
    ],
)
def test_w1_shorter_encoding_clean_refusal_is_xfail(rv: int) -> None:
    raw = _W1Raw(verify_rvs=[_ckr(CKR_OK), rv])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_shorter_even_encoding_verifies,
        _w1_session(raw),
    )
    assert outcome == "xfail"
    record = _last_record()
    assert record.reason == "honest_deviation"
    assert record.operation == "C_Verify"
    assert record.mechanism == "CKM_ECDSA"


def test_w1_shorter_encoding_undefined_rv_is_fail() -> None:
    raw = _W1Raw(verify_rvs=[_ckr(CKR_OK), 0x12345678])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_shorter_even_encoding_verifies,
        _w1_session(raw),
    )
    assert outcome == "fail"
    assert _last_record().reason == "self_contradiction"


def test_w1_full_vector_rejection_is_fail() -> None:
    raw = _W1Raw(verify_rvs=[_ckr(CKR_SIGNATURE_INVALID), _ckr(CKR_OK)])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_shorter_even_encoding_verifies,
        _w1_session(raw),
    )
    assert outcome == "fail"
    assert _last_record().reason == "wrong_result"


def test_w1_vector_import_curve_unsupported_is_skip() -> None:
    raw = _W1Raw(create_rv=_ckr(CKR_CURVE_NOT_SUPPORTED))
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_shorter_even_encoding_verifies,
        _w1_session(raw),
    )
    assert outcome == "skip"


def test_w1_vector_import_clean_refusal_is_xfail() -> None:
    raw = _W1Raw(create_rv=_ckr(CKR_FUNCTION_FAILED))
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_shorter_even_encoding_verifies,
        _w1_session(raw),
    )
    assert outcome == "xfail"
    assert _last_record().reason == "not_operational"


def test_w1_overlong_verify_init_clean_refusal_is_xfail() -> None:
    # X2: a clean C_VerifyInit refusal after advertised setup is
    # not_operational xfail with the original RV -- never a bare skip.
    raw = _W1Raw(verify_init_script=[_ckr(CKR_DEVICE_ERROR)])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_overlong_zero_padded_halves,
        _w1_session(raw),
        False,
        1,
    )
    assert outcome == "xfail"
    record = _last_record()
    assert record.reason == "not_operational"
    assert record.operation == "C_VerifyInit"
    assert record.mechanism == "CKM_ECDSA"
    assert record.actual_ckr == "CKR_DEVICE_ERROR"
    assert raw.verify_calls == []


def test_w1_overlong_verify_init_undefined_rv_is_fail() -> None:
    # X2: an undefined C_VerifyInit RV is a metadata failure, never a skip.
    raw = _W1Raw(verify_init_script=[0x12345678])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_overlong_zero_padded_halves,
        _w1_session(raw),
        False,
        2,
    )
    assert outcome == "fail"
    record = _last_record()
    assert record.reason == "self_contradiction"
    assert record.operation == "C_VerifyInit"


def test_w1_overlong_verify_init_other_defined_rv_is_xfail() -> None:
    # X2: a defined-but-unrecognized C_VerifyInit RV is a non-spec deviation
    # xfail (original RV preserved), distinct from the recognized refusals.
    raw = _W1Raw(verify_init_script=[_ckr(CKR_BUFFER_TOO_SMALL)])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_overlong_zero_padded_halves,
        _w1_session(raw),
        False,
        100,
    )
    assert outcome == "xfail"
    record = _last_record()
    assert record.reason == "nonspec_reject"
    assert record.actual_ckr == "CKR_BUFFER_TOO_SMALL"


def test_w1_shorter_first_init_clean_refusal_is_xfail() -> None:
    # X2 control: the shorter-encoding leg's FIRST initialization refuses
    # cleanly -> not_operational xfail before any C_Verify runs.
    raw = _W1Raw(verify_init_script=[_ckr(CKR_DEVICE_ERROR), _ckr(CKR_OK)])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_shorter_even_encoding_verifies,
        _w1_session(raw),
    )
    assert outcome == "xfail"
    record = _last_record()
    assert record.reason == "not_operational"
    assert record.operation == "C_VerifyInit"
    assert record.actual_ckr == "CKR_DEVICE_ERROR"
    assert raw.verify_calls == []


def test_w1_shorter_first_init_undefined_rv_is_fail() -> None:
    # X2 control: undefined RV on the first initialization -> metadata fail.
    raw = _W1Raw(verify_init_script=[0x12345678, _ckr(CKR_OK)])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_shorter_even_encoding_verifies,
        _w1_session(raw),
    )
    assert outcome == "fail"
    assert _last_record().reason == "self_contradiction"


def test_w1_shorter_second_init_clean_refusal_is_xfail() -> None:
    # X2 control: the shorter-encoding leg's SECOND initialization (after the
    # verified full-length control) refuses cleanly -> not_operational xfail.
    raw = _W1Raw(
        verify_init_script=[_ckr(CKR_OK), _ckr(CKR_DEVICE_ERROR)],
        verify_rvs=[_ckr(CKR_OK), _ckr(CKR_OK)],
    )
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_shorter_even_encoding_verifies,
        _w1_session(raw),
    )
    assert outcome == "xfail"
    record = _last_record()
    assert record.reason == "not_operational"
    assert record.operation == "C_VerifyInit"
    assert len(raw.verify_calls) == 1


def test_w1_shorter_second_init_undefined_rv_is_fail() -> None:
    # X2 control: undefined RV on the second initialization -> metadata fail.
    raw = _W1Raw(
        verify_init_script=[_ckr(CKR_OK), 0x12345678],
        verify_rvs=[_ckr(CKR_OK), _ckr(CKR_OK)],
    )
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_shorter_even_encoding_verifies,
        _w1_session(raw),
    )
    assert outcome == "fail"
    assert _last_record().reason == "self_contradiction"


def test_w1_sign_exact_width_is_pass() -> None:
    raw = _W1Raw(sign_payload=_w1_full_sig())
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_sign_returns_exact_width,
        _w1_session(raw),
    )
    assert outcome == "pass"
    assert raw.sign_inputs and raw.sign_inputs[0] == _W1_DIGEST
    assert len(raw.create_templates) == 1
    assert raw.create_templates[0][_ckr(CKA_VALUE)] == _W1_D


@pytest.mark.parametrize("sig_len", [62, 63, 65, 104])
def test_w1_sign_wrong_width_is_fail(sig_len: int) -> None:
    raw = _W1Raw(sign_payload=b"\x01" * sig_len)
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_sign_returns_exact_width,
        _w1_session(raw),
    )
    assert outcome == "fail"
    assert _last_record().reason == "wrong_result"


def test_w1_sign_out_of_range_scalar_is_fail() -> None:
    payload = (0).to_bytes(32, "big") + (5).to_bytes(32, "big")
    raw = _W1Raw(sign_payload=payload)
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_sign_returns_exact_width,
        _w1_session(raw),
    )
    assert outcome == "fail"
    assert _last_record().reason == "wrong_result"


def test_w1_sign_crypto_invalid_signature_is_fail() -> None:
    payload = (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
    with pytest.raises(InvalidSignature):
        _w1_crypto_key().verify(
            encode_dss_signature(1, 2),
            _W1_DIGEST,
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
    raw = _W1Raw(sign_payload=payload)
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_sign_returns_exact_width,
        _w1_session(raw),
    )
    assert outcome == "fail"
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"


def test_w1_sign_der_encoding_is_fail() -> None:
    # X1: a valid DER signature where raw 2*nLen is required must FAIL the
    # width rule -- the shared parser's DER leniency (honest_deviation xfail)
    # does not apply to token-created width legs (PKCS#11 v3.2 section 6.3.1).
    der = encode_dss_signature(_W1_R, _W1_S)
    assert len(der) == 70
    assert len(der) != 64
    raw = _W1Raw(sign_payload=der)
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_sign_returns_exact_width,
        _w1_session(raw),
    )
    assert outcome == "fail"
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"


def test_w1_sign_refusal_is_xfail() -> None:
    # X5: a clean Sign refusal produces no output -> not_operational xfail
    # with the original RV, never an escaping CkrAssertionError.
    raw = _W1Raw(init_rv=_ckr(CKR_DEVICE_ERROR))
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_sign_returns_exact_width,
        _w1_session(raw),
    )
    assert outcome == "xfail"
    record = _last_record()
    assert record.reason == "not_operational"
    assert record.actual_ckr == "CKR_DEVICE_ERROR"


def test_w1_overlong_sign_refusal_is_xfail() -> None:
    # X5: same refusal routing on the overlong-stimulus signing call.
    raw = _W1Raw(init_rv=_ckr(CKR_DEVICE_ERROR))
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_overlong_zero_padded_halves,
        _w1_session(raw),
        False,
        1,
    )
    assert outcome == "xfail"
    record = _last_record()
    assert record.reason == "not_operational"
    assert record.actual_ckr == "CKR_DEVICE_ERROR"
    assert raw.verify_calls == []


def test_w1_full_vector_control_refusal_is_xfail() -> None:
    # X5: a clean refusal of the full-vector control (no evaluation) is
    # not_operational xfail -- it demonstrates no wrong signature.
    raw = _W1Raw(verify_rvs=[_ckr(CKR_DEVICE_ERROR), _ckr(CKR_OK)])
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_shorter_even_encoding_verifies,
        _w1_session(raw),
    )
    assert outcome == "xfail"
    record = _last_record()
    assert record.reason == "not_operational"
    assert record.operation == "C_Verify"
    assert record.actual_ckr == "CKR_DEVICE_ERROR"
    assert len(raw.verify_calls) == 1


def test_w1_sign_shortened_fixed_signature_is_fail() -> None:
    # X1: the actual shortened fixed signature (62 bytes, same valid scalars)
    # is not 2*nLen either -- the Sign direction must reject it even though
    # the Verify direction accepts it.
    short = _w1_short_sig()
    assert len(short) == 62
    assert int.from_bytes(short[:31], "big") == _W1_R
    assert int.from_bytes(short[31:], "big") == _W1_S
    raw = _W1Raw(sign_payload=short)
    outcome = _outcome(
        ckr_mod.TestVerifyErrors().test_ecdsa_fixed_vector_sign_returns_exact_width,
        _w1_session(raw),
    )
    assert outcome == "fail"
    assert _last_record().reason == "wrong_result"


# ---------------------------------------------------------------------------
# W2 fixtures: RFC 6979 Appendix A.2.2 DSA-2048 (transcribed by script from
# the fetched RFC text; y == g**x mod p and the SHA-256("sample") signature
# verified during transcription on 2026-10-24).
# ---------------------------------------------------------------------------

_W2_P = bytes.fromhex(
    "9db6fb5951b66bb6fe1e140f1d2ce5502374161fd6538df1648218642f0b5c48"
    "c8f7a41aadfa187324b87674fa1822b00f1ecf8136943d7c55757264e5a1a44f"
    "fe012e9936e00c1d3e9310b01c7d179805d3058b2a9f4bb6f9716bfe6117c6b5"
    "b3cc4d9be341104ad4a80ad6c94e005f4b993e14f091eb51743bf33050c38de2"
    "35567e1b34c3d6a5c0ceaa1a0f368213c3d19843d0b4b09dcb9fc72d39c8de41"
    "f1bf14d4bb4563ca28371621cad3324b6a2d392145bebfac748805236f5ca2fe"
    "92b871cd8f9c36d3292b5509ca8caa77a2adfc7bfd77dda6f71125a7456fea15"
    "3e433256a2261c6a06ed3693797e7995fad5aabbcfbe3eda2741e375404ae25b"
)
_W2_Q = bytes.fromhex("f2c3119374ce76c9356990b465374a17f23f9ed35089bd969f61c6dde9998c1f")
_W2_G = bytes.fromhex(
    "5c7ff6b06f8f143fe8288433493e4769c4d988ace5be25a0e24809670716c613"
    "d7b0cee6932f8faa7c44d2cb24523da53fbe4f6ec3595892d1aa58c4328a06c4"
    "6a15662e7eaa703a1decf8bbb2d05dbe2eb956c142a338661d10461c0d135472"
    "085057f3494309ffa73c611f78b32adbb5740c361c9f35be90997db2014e2ef5"
    "aa61782f52abeb8bd6432c4dd097bc5423b285dafb60dc364e8161f4a2a35aca"
    "3a10b1c4d203cc76a470a33afdcbdd92959859abd8b56e1725252d78eac66e71"
    "ba9ae3f1dd2487199874393cd4d832186800654760e1e34c09e4d155179f9ec0"
    "dc4473f996bdce6eed1cabed8b6f116f7ad9cf505df0f998e34ab27514b0ffe7"
)
_W2_X = bytes.fromhex("69c7548c21d0dfea6b9a51c9ead4e27c33d3b3f180316e5bcab92c933f0e4dbc")
_W2_Y = bytes.fromhex(
    "667098c654426c78d7f8201eac6c203ef030d43605032c2f1fa937e5237dbd94"
    "9f34a0a2564fe126dc8b715c5141802ce0979c8246463c40e6b6bdaa2513fa61"
    "1728716c2e4fd53bc95b89e69949d96512e873b9c8f8dfd499cc312882561ade"
    "cb31f658e934c0c197f2c4d96b05cbad67381e7b768891e4da3843d24d94cdfb"
    "5126e9b8bf21e8358ee0e0a30ef13fd6a664c0dce3731f7fb49a4845a4fd8254"
    "687972a2d382599c9bac4e0ed7998193078913032558134976410b89d2c171d1"
    "23ac35fd977219597aa7d15c1a9a428e59194f75c721ebcbcfae44696a499afa"
    "74e04299f132026601638cb87ab79190d4a0986315da8eec6561c938996beadf"
)
_W2_SAMPLE_R = bytes.fromhex("eace8bdbbe353c432a795d9ec556c6d021f7a03f42c36e9bc87e4ac7932cc809")
_W2_SAMPLE_S = bytes.fromhex("7081e175455f9247b812b74583e9e94f9ea79bd640dc962533b0680793a38d53")
_W2_SAMPLE_DIGEST = hashlib.sha256(b"sample").digest()


def _dsa_verify_test_oracle(p: int, q: int, g: int, y: int, digest: bytes, r: int, s: int) -> bool:
    """Test-side DSA verification oracle (FIPS 186-5 section 6.3)."""
    if not (0 < r < q and 0 < s < q):
        return False
    z = int.from_bytes(digest, "big")
    if len(digest) * 8 > q.bit_length():
        z >>= len(digest) * 8 - q.bit_length()
    w = pow(s, -1, q)
    u1 = (z * w) % q
    u2 = (r * w) % q
    return (pow(g, u1, p) * pow(y, u2, p) % p) % q == r


def test_w2_production_params_match_rfc6979() -> None:
    assert dsa_mod._FIXED_DSA_P == _W2_P
    assert dsa_mod._FIXED_DSA_Q == _W2_Q
    assert dsa_mod._FIXED_DSA_G == _W2_G
    assert dsa_mod._FIXED_DSA_X == _W2_X
    assert dsa_mod._FIXED_DSA_Y == _W2_Y
    assert dsa_mod._FIXED_DSA_HALF_LEN == 32
    assert dsa_mod._FIXED_DSA_Q_INT == int.from_bytes(_W2_Q, "big")
    assert dsa_mod._FIXED_DSA_SAMPLE_DIGEST == _W2_SAMPLE_DIGEST


def test_w2_rfc_keypair_is_consistent() -> None:
    p, q, g, x, y = (int.from_bytes(v, "big") for v in (_W2_P, _W2_Q, _W2_G, _W2_X, _W2_Y))
    assert len(_W2_P) == 256
    assert len(_W2_Q) == 32
    assert len(_W2_G) == 256
    assert len(_W2_X) == 32
    assert len(_W2_Y) == 256
    assert 0 < x < q
    assert pow(g, x, p) == y


def test_w2_rfc_sample_signature_verifies_independently() -> None:
    p, q, g, _x, y = (int.from_bytes(v, "big") for v in (_W2_P, _W2_Q, _W2_G, _W2_X, _W2_Y))
    r = int.from_bytes(_W2_SAMPLE_R, "big")
    s = int.from_bytes(_W2_SAMPLE_S, "big")
    assert _dsa_verify_test_oracle(p, q, g, y, _W2_SAMPLE_DIGEST, r, s)
    tampered = bytearray(_W2_SAMPLE_S)
    tampered[-1] ^= 0x01
    assert not _dsa_verify_test_oracle(
        p, q, g, y, _W2_SAMPLE_DIGEST, r, int.from_bytes(tampered, "big")
    )


class _W2Raw:
    """In-memory raw boundary for the W2 bounded DSA leg.

    Any domain-parameter or keypair *generation* call is a loud error:
    the bounded fixture must never generate.
    """

    def __init__(
        self,
        *,
        sign_payload: bytes | None = None,
        verify_script: list[int | bool] | None = None,
        create_rv: int = _ckr(CKR_OK),
        attr_values: dict[int, bytes] | None = None,
        sign_init_rv: int = _ckr(CKR_OK),
        unavailable: set[int] | None = None,
    ) -> None:
        self.sign_payload = sign_payload if sign_payload is not None else _w2_fresh_sig()
        default_script: list[int | bool] = [True, _ckr(CKR_SIGNATURE_LEN_RANGE)]
        self.verify_script = list(verify_script) if verify_script else default_script
        self.create_rv = create_rv
        self.attr_values = dict(attr_values) if attr_values is not None else _w2_pub_attrs()
        self.sign_init_rv = sign_init_rv
        self.unavailable = set(unavailable) if unavailable else set()
        self.verify_calls: list[tuple[bytes, bytes]] = []
        self.create_templates: list[dict[int, bytes]] = []
        self.destroy_calls: list[int] = []
        self._handle = 200

    def C_GenerateKey(self, *args: Any, **kwargs: Any) -> int:  # noqa: N802
        raise AssertionError("bounded W2 fixture must not generate parameters")

    def C_GenerateKeyPair(self, *args: Any, **kwargs: Any) -> int:  # noqa: N802
        raise AssertionError("bounded W2 fixture must not generate a keypair")

    def C_SignInit(self, session: int, mechanism: Any, key: int) -> int:  # noqa: N802
        del session, mechanism, key
        return self.sign_init_rv

    def C_Sign(  # noqa: N802
        self,
        session: int,
        in_buf: Any,
        in_len: int,
        out_buf: Any,
        out_len: Any,
    ) -> int:
        del session, in_buf, in_len
        if out_buf is None:
            out_len._obj.value = len(self.sign_payload)
            return _ckr(CKR_OK)
        for i, byte in enumerate(self.sign_payload):
            out_buf[i] = byte
        out_len._obj.value = len(self.sign_payload)
        return _ckr(CKR_OK)

    def C_VerifyInit(self, session: int, mechanism: Any, key: int) -> int:  # noqa: N802
        del session, mechanism, key
        return _ckr(CKR_OK)

    def C_Verify(  # noqa: N802
        self,
        session: int,
        data_buf: Any,
        data_len: int,
        sig_buf: Any,
        sig_len: int,
    ) -> int:
        del session
        self.verify_calls.append((bytes(data_buf[:data_len]), bytes(sig_buf[:sig_len])))
        step = self.verify_script.pop(0) if len(self.verify_script) > 1 else self.verify_script[0]
        if step is True:
            return _ckr(CKR_OK)
        assert isinstance(step, int)
        return step

    def C_CreateObject(self, session: int, tmpl: Any, count: int, handle: Any) -> int:  # noqa: N802
        del session
        if tmpl is None:
            handle._obj.value = 0
            return _ckr(CKR_OK)
        self.create_templates.append(_decode_template(tmpl, count))
        if self.create_rv == _ckr(CKR_OK):
            self._handle += 1
            handle._obj.value = self._handle
        return self.create_rv

    def C_GetAttributeValue(self, session: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        del session, handle
        sizing = all(tmpl[i].pValue is None for i in range(count))
        for i in range(count):
            attr_type = int(tmpl[i].type)
            if attr_type in self.unavailable:
                tmpl[i].ulValueLen = ctypes.c_ulong(-1).value
                continue
            value = self.attr_values.get(attr_type, b"")
            if sizing:
                tmpl[i].ulValueLen = len(value)
            elif value:
                ctypes.memmove(tmpl[i].pValue, value, len(value))
                tmpl[i].ulValueLen = len(value)
        return _ckr(CKR_OK)

    def C_DestroyObject(self, session: int, handle: int) -> int:  # noqa: N802
        del session
        self.destroy_calls.append(int(handle))
        return _ckr(CKR_OK)

    def C_SessionCancel(self, session: int, flags: int) -> int:  # noqa: N802
        del session, flags
        return _ckr(CKR_OK)


def _w2_fresh_sig() -> bytes:
    return _W2_SAMPLE_R + _W2_SAMPLE_S


def _w2_pub_attrs() -> dict[int, bytes]:
    return {
        _ckr(CKA_PRIME): _W2_P,
        _ckr(CKA_SUBPRIME): _W2_Q,
        _ckr(CKA_BASE): _W2_G,
        _ckr(CKA_VALUE): _W2_Y,
    }


def _w2_session(raw: _W2Raw, *, dsa: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        raw=raw,
        sh=9,
        slot_id=3,
        has_mechanism=lambda name: dsa and name == "DSA",
    )


def _run_w2(raw: _W2Raw, pad_len: int, *, dsa: bool = True) -> str:
    return _outcome(
        dsa_mod.TestDSABoundedWidth().test_fixed_dsa_even_padded_halves_rejected,
        _w2_session(raw, dsa=dsa),
        pad_len,
    )


@pytest.mark.parametrize("pad_len", [1, 100])
def test_w2_padded_rejection_is_pass(pad_len: int) -> None:
    raw = _W2Raw()
    assert _run_w2(raw, pad_len) == "pass"
    # Bounded fixture: exactly two imports carrying the fixed RFC material.
    assert len(raw.create_templates) == 2
    pub, priv = raw.create_templates
    assert int.from_bytes(pub[_ckr(CKA_CLASS)], sys.byteorder) == _ckr(CKO_PUBLIC_KEY)
    assert int.from_bytes(pub[_ckr(CKA_KEY_TYPE)], sys.byteorder) == _ckr(CKK_DSA)
    assert int.from_bytes(priv[_ckr(CKA_CLASS)], sys.byteorder) == _ckr(CKO_PRIVATE_KEY)
    assert int.from_bytes(priv[_ckr(CKA_KEY_TYPE)], sys.byteorder) == _ckr(CKK_DSA)
    assert pub[_ckr(CKA_PRIME)] == _W2_P
    assert pub[_ckr(CKA_SUBPRIME)] == _W2_Q
    assert pub[_ckr(CKA_BASE)] == _W2_G
    assert pub[_ckr(CKA_VALUE)] == _W2_Y
    assert priv[_ckr(CKA_PRIME)] == _W2_P
    assert priv[_ckr(CKA_SUBPRIME)] == _W2_Q
    assert priv[_ckr(CKA_BASE)] == _W2_G
    assert priv[_ckr(CKA_VALUE)] == _W2_X
    # Control verified unpadded, then the even padded-half stimulus rejected.
    assert len(raw.verify_calls) == 2
    assert raw.verify_calls[0][1] == _w2_fresh_sig()
    padded = raw.verify_calls[1][1]
    assert len(padded) == 2 * (32 + pad_len)
    first, second = padded[: 32 + pad_len], padded[32 + pad_len :]
    assert first[:pad_len] == b"\x00" * pad_len
    assert second[:pad_len] == b"\x00" * pad_len
    assert int.from_bytes(first, "big") == int.from_bytes(_W2_SAMPLE_R, "big")
    assert int.from_bytes(second, "big") == int.from_bytes(_W2_SAMPLE_S, "big")
    assert sorted(raw.destroy_calls) == [201, 202]


def test_w2_padded_signature_invalid_is_pass() -> None:
    raw = _W2Raw(verify_script=[True, _ckr(CKR_SIGNATURE_INVALID)])
    assert _run_w2(raw, 1) == "pass"


def test_w2_padded_acceptance_is_fail() -> None:
    raw = _W2Raw(verify_script=[True, True])
    assert _run_w2(raw, 100) == "fail"
    record = _last_record()
    assert record.reason == "accepted_invalid"
    assert record.kind == "crypto"
    assert record.operation == "C_Verify"
    assert record.mechanism == "CKM_DSA"


def test_w2_padded_non_clean_reject_is_xfail() -> None:
    raw = _W2Raw(verify_script=[True, _ckr(CKR_DEVICE_ERROR)])
    assert _run_w2(raw, 1) == "xfail"


def test_w2_control_rejection_is_fail() -> None:
    raw = _W2Raw(verify_script=[_ckr(CKR_SIGNATURE_INVALID), _ckr(CKR_SIGNATURE_LEN_RANGE)])
    assert _run_w2(raw, 1) == "fail"
    assert _last_record().reason == "wrong_result"


def test_w2_sign_refusal_is_xfail() -> None:
    # X5: a clean Sign refusal produces no output -> not_operational xfail
    # with the original RV, never an escaping CkrAssertionError.
    raw = _W2Raw(sign_init_rv=_ckr(CKR_DEVICE_ERROR))
    assert _run_w2(raw, 1) == "xfail"
    record = _last_record()
    assert record.reason == "not_operational"
    assert record.actual_ckr == "CKR_DEVICE_ERROR"


def test_w2_control_refusal_is_xfail() -> None:
    # X5: a clean refusal of the fresh-signature control (no evaluation) is
    # not_operational xfail -- it demonstrates no wrong signature.
    raw = _W2Raw(verify_script=[_ckr(CKR_DEVICE_ERROR), _ckr(CKR_SIGNATURE_LEN_RANGE)])
    assert _run_w2(raw, 1) == "xfail"
    record = _last_record()
    assert record.reason == "not_operational"
    assert record.actual_ckr == "CKR_DEVICE_ERROR"


def test_w2_coherence_mismatch_is_fail() -> None:
    attrs = _w2_pub_attrs()
    attrs[_ckr(CKA_VALUE)] = b"\x00" * 256
    raw = _W2Raw(attr_values=attrs)
    assert _run_w2(raw, 1) == "fail"
    assert _last_record().reason == "wrong_result"


def test_w2_coherence_mixed_missing_and_mismatch_is_fail() -> None:
    # X6: unavailable CKA_PRIME must not hide the explicitly incorrect
    # all-zero CKA_VALUE -- present siblings are validated BEFORE omissions
    # terminate, so the contradiction fails with the missing evidence kept.
    attrs = _w2_pub_attrs()
    attrs[_ckr(CKA_VALUE)] = b"\x00" * 256
    raw = _W2Raw(attr_values=attrs, unavailable={_ckr(CKA_PRIME)})
    assert _run_w2(raw, 1) == "fail"
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.detail is not None
    assert record.detail["attribute"]["id"] == _ckr(CKA_VALUE)
    missing = record.detail["missing_attributes"]
    assert {entry["id"] for entry in missing} == {_ckr(CKA_PRIME)}


def test_w2_coherence_missing_only_is_xfail() -> None:
    # X6: omissions alone (no contradiction in any sibling) stay
    # not_operational xfail.
    raw = _W2Raw(unavailable={_ckr(CKA_PRIME)})
    assert _run_w2(raw, 1) == "xfail"
    assert _last_record().reason == "not_operational"


def test_w2_import_clean_refusal_is_xfail() -> None:
    raw = _W2Raw(create_rv=_ckr(CKR_FUNCTION_FAILED))
    assert _run_w2(raw, 1) == "xfail"
    assert _last_record().reason == "not_operational"


def test_w2_import_size_policy_is_xfail() -> None:
    raw = _W2Raw(create_rv=_ckr(CKR_KEY_SIZE_RANGE))
    assert _run_w2(raw, 1) == "xfail"


def test_w2_import_domain_params_invalid_is_fail() -> None:
    raw = _W2Raw(create_rv=_ckr(CKR_DOMAIN_PARAMS_INVALID))
    with pytest.raises(CkrAssertionError):
        dsa_mod.TestDSABoundedWidth().test_fixed_dsa_even_padded_halves_rejected(
            _w2_session(raw), 1
        )


def test_w2_no_dsa_mechanism_is_skip() -> None:
    raw = _W2Raw()
    assert _run_w2(raw, 1, dsa=False) == "skip"
    assert raw.create_templates == []


def test_w2_mark_structure_keeps_legacy_slow_and_new_ordinary() -> None:
    import ast
    from pathlib import Path

    path = Path(dsa_mod.__file__ or "")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    module_marks: set[str] = set()
    class_marks: dict[str, set[str]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets
        ):
            items = node.value.elts if isinstance(node.value, ast.List) else [node.value]
            for item in items:
                assert isinstance(item, ast.Attribute)
                module_marks.add(item.attr)
        if isinstance(node, ast.ClassDef):
            marks = set()
            for deco in node.decorator_list:
                if (
                    isinstance(deco, ast.Attribute)
                    and isinstance(deco.value, ast.Attribute)
                    and deco.value.attr == "mark"
                ):
                    marks.add(deco.attr)
            class_marks[node.name] = marks
    assert module_marks == {"sign"}
    assert class_marks["TestDSARaw"] == {"slow"}
    assert class_marks["TestDSAPrehash"] == {"slow"}
    assert class_marks["TestDSAParameterGen"] == {"slow"}
    assert "slow" not in class_marks["TestDSABoundedWidth"]
    bounded_node = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "TestDSABoundedWidth"
    )
    doc = ast.get_docstring(bounded_node)
    assert doc is not None
    assert "test_raw_dsa_overlong_signature_length_fails" in doc


# ---------------------------------------------------------------------------
# W3 fixtures: SEC 2 domain parameters (transcribed from the SECG PDFs;
# cross-checked field-by-field against OpenSSL 3.5.5 explicit parameters
# plus on-curve and n*G == O checks on 2026-10-24).
# ---------------------------------------------------------------------------

_W3_SECP160R1 = {
    "p": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF",
    "a": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC",
    "b": "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45",
    "gx": "4A96B5688EF573284664698968C38BB913CBFC82",
    "gy": "23A628553168947D59DCC912042351377AC5FB32",
    "n": "0100000000000000000001F4C8F927AED3CA752257",
    "field_width": 20,
    "order_width": 21,
    "sec2": "SECG SEC 2 v1.0, section 2.4.2",
}
_W3_SECP224K1 = {
    "p": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D",
    "a": "00" * 28,
    "b": "00" * 27 + "05",
    "gx": "A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C",
    "gy": "7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5",
    "n": "010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7",
    "field_width": 28,
    "order_width": 29,
    "sec2": "SECG SEC 2 v2.0, section 2.3.1",
}
_W3_SECT409K1 = {
    "m": 409,
    "k": 87,
    "a": "00" * 52,
    "b": "00" * 51 + "01",
    "gx": "0060F05F658F49C1AD3AB1890F7184210EFD0987E307C84C27ACCFB8"
    "F9F67CC2C460189EB5AAAA62EE222EB1B35540CFE9023746",
    "gy": "01E369050B7C4E42ACBA1DACBF04299C3460782F918EA427E6325165"
    "E9EA10E3DA5F6C42E9C55215AA9CA27A5863EC48D8E0286B",
    "n": "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5F83B2D4EA"
    "20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCF",
    "field_width": 52,
    "order_width": 51,
    "sec2": "SECG SEC 2 v2.0, section 3.6.1",
}

# OpenSSL 3.5.5 ECDSA signatures (random k, pinned 2026-10-24) that the
# production pure-Python verifier must accept. Each pin signs the exact
# stimulus digest the provider test submits, so the fake-driven method
# probes below exercise the real split/parse/verify path. The
# sect409k1/sha512 row additionally exercises hash truncation on the
# binary path (pure-math contract only).
_W3_OPENSSL_PINS = [
    {
        "curve": "secp160r1",
        "data": b"ECDSA secp160r1 subgroup-order cross-verify",
        "hash": "sha256",
        "digest": "0d25fa1bd319a978756eca6979f01195fec4c45fc8366524428a1db2539cb84f",
        "qx": "d5e4ef953bbf65048eeb4f9e9a13966eb2db9c98",
        "qy": "1a6ab78a1cc5fc140605d7c7cd8478d6faff3c37",
        "r": "71a5c0f59d273abb06e9ee45baca648f29229868",
        "s": "ad318637c106bb3befd318fb6557faedb6ca13c2",
    },
    {
        "curve": "secp224k1",
        "data": b"ECDSA secp224k1 subgroup-order cross-verify",
        "hash": "sha256",
        "digest": "b6bca4a3fa78859e35c712c8c12186f3515a145087565102776d9f53ec7db7f8",
        "qx": "69d698c6fbb47d3eb8deb7b5764269822a563f1b69ac0684e55216e5",
        "qy": "92ecd286e9586e045acedc3319078486f25e5ce2bba33f18b752fca8",
        "r": "85502ba628b169fbd8f8af3812467502ea291a387d2470a926d68d71",
        "s": "be4bdb3e3641ad39456b0391368cb039bbff5fbb16422e633e9dbde4",
    },
    {
        "curve": "sect409k1",
        "data": b"ECDSA sect409k1 subgroup-order cross-verify",
        "hash": "sha384",
        "digest": "59c69c6fe510ae6f9fa6d6e22d886668da9f9929a5b32479aecc348e746f69fc"
        "f901c81aef09aea9faa99f55ef0d2885",
        "qx": "008e95abfd0bf317f6308c9c279e7c6b2ece96030949cb08b23d3838b222b21446"
        "4213ecc8f18b7eb18bb0abc5dc78edd673c6cc",
        "qy": "00870c6b139521468d4e2c2f6de9b9358a361c741d62d37e439c9cf42d69f3875"
        "f81ce7b919edd05cce9de9142ee9f20b72ed405",
        "r": "1c9906baa3da074a17deef90a176c7510c7ee67c95a77cc8680f"
        "e05cec65415157e29aa1e8ad62da7afd712a1c3cb955d60544",
        "s": "4c21bc7cbd12b27ced36fc9a3d8ee1b11622231ae82a57e9964b"
        "1a670acc43a1938551b06baea1d773d6245bddba37e157cdb5",
    },
    {
        "curve": "sect409k1",
        "data": b"QC5c sect409k1 truncation-verify",
        "hash": "sha512",
        "digest": "aa26849ef8e69be345ee37b6afeef4586bc97f0f24a811d2b6383ae371d75072"
        "5b894667a4eea89fe6aabb3b092bb5536b303bc087eed849572bc7104a614772",
        "qx": "01893b4442470dad64dddbeea793e6fdebaf746cebc1ccb04d819ddda2e6de4f7"
        "bd59277a2403a7121b722b7241146c8ef8d049c",
        "qy": "01ac5337041917c5c27515d6e8242fdffba17f596f40ad08f5ca45a1c8b8da20"
        "522ef600bd479fed94fd3d21c1fe19e5a057681d",
        "r": "39320f41904b192231115e0e0ef47731bec9ff36fe8ea9fbd266"
        "7eee599f8bce0bcaedb6479cf2ae203c073353956431a0660b",
        "s": "5dad1b88c156625b3adfbf6d6730cb10a5a4196dc888a3f8fbbe"
        "696ba305b6c36a7d74f09dc4480df0b45c913371161cccc810",
    },
]


def _w3_curve(name: str) -> Any:
    for curve in ec_mod._SUBGROUP_ORDER_CURVES:
        if curve.name == name:
            return curve
    raise AssertionError(f"unknown subgroup curve {name!r}")


def test_w3_production_prime_params_match_sec2() -> None:
    for name, pinned in (("secp160r1", _W3_SECP160R1), ("secp224k1", _W3_SECP224K1)):
        curve = _w3_curve(name)
        assert curve.field_width == pinned["field_width"]
        assert curve.order_width == pinned["order_width"]
        assert curve.order == int(str(pinned["n"]), 16)
        assert curve.sec2_ref == pinned["sec2"]
        assert isinstance(curve.field, ec_mod._PrimeField)
        assert curve.field.p == int(str(pinned["p"]), 16)
        assert curve.field.a == int(str(pinned["a"]), 16)
        assert curve.field.b == int(str(pinned["b"]), 16)
        assert curve.gx == int(str(pinned["gx"]), 16)
        assert curve.gy == int(str(pinned["gy"]), 16)


def test_w3_production_binary_params_match_sec2() -> None:
    curve = _w3_curve("sect409k1")
    pinned = _W3_SECT409K1
    assert curve.field_width == pinned["field_width"]
    assert curve.order_width == pinned["order_width"]
    assert curve.order == int(str(pinned["n"]), 16)
    assert curve.sec2_ref == pinned["sec2"]
    assert isinstance(curve.field, ec_mod._BinaryField)
    assert curve.field.m == pinned["m"]
    assert curve.field.k == pinned["k"]
    assert curve.field.a == int(str(pinned["a"]), 16)
    assert curve.field.b == int(str(pinned["b"]), 16)
    assert curve.gx == int(str(pinned["gx"]), 16)
    assert curve.gy == int(str(pinned["gy"]), 16)


def test_w3_order_width_crosscheck_holds() -> None:
    for curve in ec_mod._SUBGROUP_ORDER_CURVES:
        assert ec_mod._order_octet_length(curve.order) == curve.order_width
        assert curve.order_width == (curve.order.bit_length() + 7) // 8


def test_w3_field_and_order_widths_are_independent() -> None:
    for curve in ec_mod._SUBGROUP_ORDER_CURVES:
        assert curve.field_width != curve.order_width, curve.name
    by_name = {c.name: c for c in ec_mod._SUBGROUP_ORDER_CURVES}
    assert (by_name["secp160r1"].field_width, by_name["secp160r1"].order_width) == (20, 21)
    assert (by_name["secp224k1"].field_width, by_name["secp224k1"].order_width) == (28, 29)
    assert (by_name["sect409k1"].field_width, by_name["sect409k1"].order_width) == (52, 51)
    # Deriving the signature half-length from the field size gives the WRONG
    # width on every fixture curve, so the two must never be conflated.
    assert (160 + 7) // 8 != by_name["secp160r1"].order_width
    assert (224 + 7) // 8 != by_name["secp224k1"].order_width
    assert (409 + 7) // 8 != by_name["sect409k1"].order_width


def test_w3_base_points_are_on_curve() -> None:
    for curve in ec_mod._SUBGROUP_ORDER_CURVES:
        assert ec_mod._subgroup_on_curve(curve, curve.gx, curve.gy), curve.name
        assert not ec_mod._subgroup_on_curve(curve, curve.gx, curve.gy ^ 1), curve.name


def test_w3_prime_order_annihilates_base_point() -> None:
    for name in ("secp160r1", "secp224k1"):
        curve = _w3_curve(name)
        assert isinstance(curve.field, ec_mod._PrimeField)
        assert (
            ec_mod._prime_mul(curve.field.p, curve.field.a, curve.order, (curve.gx, curve.gy))
            is None
        )


def test_w3_binary_order_annihilates_base_point() -> None:
    curve = _w3_curve("sect409k1")
    assert isinstance(curve.field, ec_mod._BinaryField)
    assert (
        ec_mod._binary_mul(
            curve.field.m, curve.field.k, curve.field.a, curve.order, (curve.gx, curve.gy)
        )
        is None
    )


def test_w3_truncation_rule() -> None:
    n160 = _w3_curve("secp160r1").order
    assert n160.bit_length() == 161
    digest = bytes(range(32))
    assert ec_mod._ecdsa_truncate(digest, n160) == int.from_bytes(digest, "big") >> (256 - 161)
    short = b"\x01\x02"
    assert ec_mod._ecdsa_truncate(short, n160) == int.from_bytes(short, "big")
    n409 = _w3_curve("sect409k1").order
    assert n409.bit_length() == 407
    digest48 = bytes(range(48))
    assert ec_mod._ecdsa_truncate(digest48, n409) == int.from_bytes(digest48, "big")


@pytest.mark.parametrize(
    "pin", _W3_OPENSSL_PINS, ids=[f"{p['curve']}/{p['hash']}" for p in _W3_OPENSSL_PINS]
)
def test_w3_openssl_signatures_verify_independently(pin: dict[str, Any]) -> None:
    curve = _w3_curve(str(pin["curve"]))
    digest = bytes.fromhex(str(pin["digest"]))
    assert digest == hashlib.new(str(pin["hash"]), bytes(pin["data"])).digest()
    assert len(bytes.fromhex(str(pin["qx"]))) == curve.field_width
    assert ec_mod._ecdsa_verify_subgroup(
        curve,
        int(str(pin["qx"]), 16),
        int(str(pin["qy"]), 16),
        digest,
        int(str(pin["r"]), 16),
        int(str(pin["s"]), 16),
    )


@pytest.mark.parametrize(
    "pin", _W3_OPENSSL_PINS, ids=[f"{p['curve']}/{p['hash']}" for p in _W3_OPENSSL_PINS]
)
def test_w3_tampered_signatures_do_not_verify(pin: dict[str, Any]) -> None:
    curve = _w3_curve(str(pin["curve"]))
    digest = bytes.fromhex(str(pin["digest"]))
    qx = int(str(pin["qx"]), 16)
    qy = int(str(pin["qy"]), 16)
    r = int(str(pin["r"]), 16)
    s = int(str(pin["s"]), 16)
    assert not ec_mod._ecdsa_verify_subgroup(curve, qx, qy, digest, r ^ 1, s)
    assert not ec_mod._ecdsa_verify_subgroup(curve, qx, qy, digest, r, s ^ 1)
    assert not ec_mod._ecdsa_verify_subgroup(curve, qx, qy, digest, 0, s)
    assert not ec_mod._ecdsa_verify_subgroup(curve, qx, qy, digest, r, curve.order)


def test_w3_point_parser_accepts_raw_and_der() -> None:
    curve = _w3_curve("secp160r1")
    gx = bytes.fromhex(str(_W3_SECP160R1["gx"]))
    gy = bytes.fromhex(str(_W3_SECP160R1["gy"]))
    raw_point = b"\x04" + gx + gy
    assert ec_mod._parse_subgroup_point(raw_point, curve) == (curve.gx, curve.gy)
    der_point = bytes([0x04, len(raw_point)]) + raw_point
    assert ec_mod._parse_subgroup_point(der_point, curve) == (curve.gx, curve.gy)
    with pytest.raises(ValueError):
        ec_mod._parse_subgroup_point(raw_point[:-1], curve)
    with pytest.raises(ValueError):
        ec_mod._parse_subgroup_point(b"\x04\x03\x01\x02\x03", curve)


class _W3Raw:
    """In-memory raw boundary for the W3 subgroup-order legs."""

    def __init__(
        self,
        *,
        sign_payload: bytes = b"\x01\x02",
        point_value: bytes | None = b"",
        generate_rv: int = _ckr(CKR_OK),
        sign_rv: int = _ckr(CKR_OK),
    ) -> None:
        self.sign_payload = sign_payload
        self.point_value = point_value
        self.generate_rv = generate_rv
        self.sign_rv = sign_rv
        self.generate_curves: list[bytes] = []
        self.sign_inputs: list[bytes] = []
        self.destroy_calls: list[int] = []
        self._handle = 300

    def C_GenerateKeyPair(  # noqa: N802
        self,
        session: int,
        mechanism: Any,
        public_template: Any,
        public_count: int,
        _private_template: Any,
        _private_count: int,
        public_handle: Any,
        private_handle: Any,
    ) -> int:
        del session, mechanism, _private_template, _private_count
        decoded = _decode_template(public_template, public_count)
        self.generate_curves.append(decoded[_ckr(CKA_EC_PARAMS)])
        if self.generate_rv == _ckr(CKR_OK):
            self._handle += 1
            public_handle._obj.value = self._handle
            self._handle += 1
            private_handle._obj.value = self._handle
        return self.generate_rv

    def C_SignInit(self, session: int, mechanism: Any, key: int) -> int:  # noqa: N802
        del session, mechanism, key
        return self.sign_rv

    def C_Sign(  # noqa: N802
        self,
        session: int,
        in_buf: Any,
        in_len: int,
        out_buf: Any,
        out_len: Any,
    ) -> int:
        del session
        self.sign_inputs.append(bytes(in_buf[:in_len]))
        if out_buf is None:
            out_len._obj.value = len(self.sign_payload)
            return _ckr(CKR_OK)
        for i, byte in enumerate(self.sign_payload):
            out_buf[i] = byte
        out_len._obj.value = len(self.sign_payload)
        return _ckr(CKR_OK)

    def C_GetAttributeValue(self, session: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        del session, handle
        sizing = all(tmpl[i].pValue is None for i in range(count))
        for i in range(count):
            if self.point_value is None:
                tmpl[i].ulValueLen = ctypes.c_ulong(-1).value
                continue
            assert self.point_value is not None
            if sizing:
                tmpl[i].ulValueLen = len(self.point_value)
            else:
                ctypes.memmove(tmpl[i].pValue, self.point_value, len(self.point_value))
                tmpl[i].ulValueLen = len(self.point_value)
        return _ckr(CKR_OK)

    def C_DestroyObject(self, session: int, handle: int) -> int:  # noqa: N802
        del session
        self.destroy_calls.append(int(handle))
        return _ckr(CKR_OK)

    def C_SessionCancel(self, session: int, flags: int) -> int:  # noqa: N802
        del session, flags
        return _ckr(CKR_OK)


def _w3_session(raw: _W3Raw) -> SimpleNamespace:
    return SimpleNamespace(
        raw=raw,
        sh=11,
        slot_id=3,
        has_mechanism=lambda name: name in {"EC_KEY_PAIR_GEN", "ECDSA"},
    )


def _no_capability_gate(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    calls: list[tuple[Any, ...]] = []

    def _gate(rs: Any, mechanism: int, **kw: Any) -> None:
        calls.append((mechanism, kw))

    monkeypatch.setattr(ec_mod, "skip_unless_capability", _gate)
    return calls


def test_w3_crosscheck_node_passes_without_provider() -> None:
    for curve in ec_mod._SUBGROUP_ORDER_CURVES:
        outcome = _outcome(ec_mod.TestECDSASubgroupOrder().test_order_width_crosscheck, curve)
        assert outcome == "pass", curve.name


@pytest.mark.parametrize("name", ["secp160r1", "secp224k1", "sect409k1"])
def test_w3_width_leg_passes_on_order_sized_output(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    curve = _w3_curve(name)
    payload = (1).to_bytes(curve.order_width, "big") + (2).to_bytes(curve.order_width, "big")
    raw = _W3Raw(sign_payload=payload)
    calls = _no_capability_gate(monkeypatch)
    outcome = _outcome(
        ec_mod.TestECDSASubgroupOrder().test_sign_width_is_two_order_len,
        _w3_session(raw),
        curve,
    )
    assert outcome == "pass"
    assert calls and calls[0][1].get("operation") == CKF_SIGN
    assert raw.generate_curves == [encode_named_curve_parameters(name)]
    assert len(raw.sign_inputs) == 2
    assert len(raw.sign_inputs[0]) == hashlib.new(curve.hash_name).digest_size


@pytest.mark.parametrize("name", ["secp160r1", "secp224k1", "sect409k1"])
def test_w3_width_leg_fails_on_field_sized_output(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    curve = _w3_curve(name)
    payload = (1).to_bytes(curve.field_width, "big") + (2).to_bytes(curve.field_width, "big")
    assert len(payload) != 2 * curve.order_width
    raw = _W3Raw(sign_payload=payload)
    _no_capability_gate(monkeypatch)
    outcome = _outcome(
        ec_mod.TestECDSASubgroupOrder().test_sign_width_is_two_order_len,
        _w3_session(raw),
        curve,
    )
    assert outcome == "fail"
    assert _last_record().reason == "wrong_result"


def test_w3_sect409k1_104_byte_output_is_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    curve = _w3_curve("sect409k1")
    payload = (1).to_bytes(52, "big") + (2).to_bytes(52, "big")
    raw = _W3Raw(sign_payload=payload)
    _no_capability_gate(monkeypatch)
    outcome = _outcome(
        ec_mod.TestECDSASubgroupOrder().test_sign_width_is_two_order_len,
        _w3_session(raw),
        curve,
    )
    assert outcome == "fail"


_W3_DER_WIDTHS = {"secp160r1": 47, "secp224k1": 64, "sect409k1": 108}


@pytest.mark.parametrize(
    "pin", _W3_OPENSSL_PINS[:3], ids=[str(p["curve"]) for p in _W3_OPENSSL_PINS[:3]]
)
def test_w3_width_leg_fails_on_der_encoding(
    monkeypatch: pytest.MonkeyPatch, pin: dict[str, Any]
) -> None:
    # X1: a valid DER signature where raw 2*order_width is required must FAIL
    # the width rule -- the shared parser's DER leniency (honest_deviation
    # xfail) does not apply to token-created width legs.
    curve = _w3_curve(str(pin["curve"]))
    r = int(str(pin["r"]), 16)
    s = int(str(pin["s"]), 16)
    assert 0 < r < curve.order and 0 < s < curve.order
    der = encode_dss_signature(r, s)
    assert len(der) == _W3_DER_WIDTHS[str(pin["curve"])]
    assert len(der) != 2 * curve.order_width
    raw = _W3Raw(sign_payload=der)
    _no_capability_gate(monkeypatch)
    outcome = _outcome(
        ec_mod.TestECDSASubgroupOrder().test_sign_width_is_two_order_len,
        _w3_session(raw),
        curve,
    )
    assert outcome == "fail"
    assert _last_record().reason == "wrong_result"


def test_w3_unsupported_curve_is_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    curve = _w3_curve("sect409k1")
    raw = _W3Raw(generate_rv=_ckr(CKR_CURVE_NOT_SUPPORTED))
    _no_capability_gate(monkeypatch)
    outcome = _outcome(
        ec_mod.TestECDSASubgroupOrder().test_sign_width_is_two_order_len,
        _w3_session(raw),
        curve,
    )
    assert outcome == "skip"
    assert raw.sign_inputs == []


def test_w3_sign_not_operational_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    curve = _w3_curve("secp160r1")
    raw = _W3Raw(sign_rv=_ckr(CKR_FUNCTION_FAILED))
    _no_capability_gate(monkeypatch)
    outcome = _outcome(
        ec_mod.TestECDSASubgroupOrder().test_sign_width_is_two_order_len,
        _w3_session(raw),
        curve,
    )
    assert outcome == "xfail"


@pytest.mark.parametrize("pin", _W3_OPENSSL_PINS[:3])
def test_w3_independent_verify_accepts_openssl_signatures(
    monkeypatch: pytest.MonkeyPatch, pin: dict[str, Any]
) -> None:
    curve = _w3_curve(str(pin["curve"]))
    r = int(str(pin["r"]), 16).to_bytes(curve.order_width, "big")
    s = int(str(pin["s"]), 16).to_bytes(curve.order_width, "big")
    payload = r + s
    point = b"\x04" + bytes.fromhex(str(pin["qx"])) + bytes.fromhex(str(pin["qy"]))
    der_point = bytes([0x04, len(point)]) + point
    raw = _W3Raw(sign_payload=payload, point_value=der_point)
    calls = _no_capability_gate(monkeypatch)
    outcome = _outcome(
        ec_mod.TestECDSASubgroupOrder().test_token_signature_verifies_independently,
        _w3_session(raw),
        curve,
    )
    assert outcome == "pass"
    assert calls
    assert raw.sign_inputs and raw.sign_inputs[0] == bytes.fromhex(str(pin["digest"]))


def test_w3_independent_verify_rejects_tampered_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pin = _W3_OPENSSL_PINS[0]
    curve = _w3_curve(str(pin["curve"]))
    r = (int(str(pin["r"]), 16) ^ 1).to_bytes(curve.order_width, "big")
    s = int(str(pin["s"]), 16).to_bytes(curve.order_width, "big")
    payload = r + s
    point = b"\x04" + bytes.fromhex(str(pin["qx"])) + bytes.fromhex(str(pin["qy"]))
    raw = _W3Raw(sign_payload=payload, point_value=point)
    _no_capability_gate(monkeypatch)
    outcome = _outcome(
        ec_mod.TestECDSASubgroupOrder().test_token_signature_verifies_independently,
        _w3_session(raw),
        curve,
    )
    assert outcome == "fail"
    assert _last_record().reason == "wrong_result"


def test_w3_independent_verify_missing_point_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    curve = _w3_curve("secp224k1")
    payload = (1).to_bytes(curve.order_width, "big") + (2).to_bytes(curve.order_width, "big")
    raw = _W3Raw(sign_payload=payload, point_value=None)
    _no_capability_gate(monkeypatch)
    outcome = _outcome(
        ec_mod.TestECDSASubgroupOrder().test_token_signature_verifies_independently,
        _w3_session(raw),
        curve,
    )
    assert outcome == "xfail"
    assert _last_record().reason == "not_operational"


def test_w3_independent_verify_off_curve_point_is_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    curve = _w3_curve("secp160r1")
    payload = (1).to_bytes(curve.order_width, "big") + (2).to_bytes(curve.order_width, "big")
    bad = b"\x04" + b"\x05" * curve.field_width + b"\x06" * curve.field_width
    assert not ec_mod._subgroup_on_curve(
        curve,
        int.from_bytes(b"\x05" * curve.field_width, "big"),
        int.from_bytes(b"\x06" * curve.field_width, "big"),
    )
    raw = _W3Raw(sign_payload=payload, point_value=bad)
    _no_capability_gate(monkeypatch)
    outcome = _outcome(
        ec_mod.TestECDSASubgroupOrder().test_token_signature_verifies_independently,
        _w3_session(raw),
        curve,
    )
    assert outcome == "fail"
    assert _last_record().reason == "wrong_result"


def _w3_range_fail(
    monkeypatch: pytest.MonkeyPatch, curve: Any, point: bytes, coordinate: str
) -> None:
    payload = (1).to_bytes(curve.order_width, "big") + (2).to_bytes(curve.order_width, "big")
    raw = _W3Raw(sign_payload=payload, point_value=point)
    _no_capability_gate(monkeypatch)
    outcome = _outcome(
        ec_mod.TestECDSASubgroupOrder().test_token_signature_verifies_independently,
        _w3_session(raw),
        curve,
    )
    assert outcome == "fail"
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.detail is not None and record.detail.get("coordinate") == coordinate


def _w3_der_wrap(point: bytes) -> bytes:
    return bytes([0x04, len(point)]) + point


def test_w3_prime_out_of_range_x_raw_is_range_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    # X3: x == p fits the field bytes but is outside Fp. The probe isolates
    # gate ORDER (it fails the equation check too), so only the range gate
    # firing first can produce the coordinate detail.
    curve = _w3_curve("secp160r1")
    assert isinstance(curve.field, ec_mod._PrimeField)
    p = curve.field.p
    assert not ec_mod._subgroup_on_curve(curve, p, curve.gy)
    point = (
        b"\x04" + p.to_bytes(curve.field_width, "big") + curve.gy.to_bytes(curve.field_width, "big")
    )
    _w3_range_fail(monkeypatch, curve, point, "x")


def test_w3_prime_out_of_range_x_der_is_range_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    # X3: same out-of-range x, DER-wrapped representation.
    curve = _w3_curve("secp160r1")
    assert isinstance(curve.field, ec_mod._PrimeField)
    p = curve.field.p
    point = (
        b"\x04" + p.to_bytes(curve.field_width, "big") + curve.gy.to_bytes(curve.field_width, "big")
    )
    _w3_range_fail(monkeypatch, curve, _w3_der_wrap(point), "x")


def _w3_sect409k1_pin() -> dict[str, Any]:
    pin = _W3_OPENSSL_PINS[2]
    assert str(pin["curve"]) == "sect409k1" and str(pin["hash"]) == "sha384"
    return pin


def _w3_aliased_pin_payload_and_point(
    monkeypatch: pytest.MonkeyPatch, coordinate: str, *, der: bool
) -> None:
    # X3: alias the pinned sect409k1 point's coordinate with the modulus
    # polynomial (410 bits) while replaying the pinned VALID signature. The
    # alias passes the equation check AND independent verification, so the
    # whole method passes pre-fix -- only the range gate can fail it.
    curve = _w3_curve("sect409k1")
    assert isinstance(curve.field, ec_mod._BinaryField)
    pin = _w3_sect409k1_pin()
    mod = (1 << curve.field.m) | (1 << curve.field.k) | 1
    qx = int(str(pin["qx"]), 16)
    qy = int(str(pin["qy"]), 16)
    aliased = (qx if coordinate == "x" else qy) ^ mod
    assert aliased.bit_length() == 410
    ax, ay = (aliased, qy) if coordinate == "x" else (qx, aliased)
    assert ec_mod._subgroup_on_curve(curve, ax, ay)
    payload = int(str(pin["r"]), 16).to_bytes(curve.order_width, "big") + int(
        str(pin["s"]), 16
    ).to_bytes(curve.order_width, "big")
    point = b"\x04" + ax.to_bytes(curve.field_width, "big") + ay.to_bytes(curve.field_width, "big")
    if der:
        point = _w3_der_wrap(point)
    raw = _W3Raw(sign_payload=payload, point_value=point)
    _no_capability_gate(monkeypatch)
    outcome = _outcome(
        ec_mod.TestECDSASubgroupOrder().test_token_signature_verifies_independently,
        _w3_session(raw),
        curve,
    )
    assert outcome == "fail"
    record = _last_record()
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.detail is not None and record.detail.get("coordinate") == coordinate


def test_w3_binary_out_of_range_x_raw_is_range_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    _w3_aliased_pin_payload_and_point(monkeypatch, "x", der=False)


def test_w3_binary_out_of_range_x_der_is_range_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    _w3_aliased_pin_payload_and_point(monkeypatch, "x", der=True)


def test_w3_binary_out_of_range_y_raw_is_range_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    _w3_aliased_pin_payload_and_point(monkeypatch, "y", der=False)
