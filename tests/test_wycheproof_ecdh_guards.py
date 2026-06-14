"""Regression tests for Wycheproof ECDH guards."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKA_VALUE, CKR_MECHANISM_PARAM_INVALID
from pkcs11_check.testcases.wycheproof import test_wycheproof_ecdh as ecdh
from pkcs11_check.testcases.wycheproof._key_decoders import ecdh_cofactor1_shared_x

# NIST P-256 generator (SEC 2).
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _p256_point(x: int, y: int) -> bytes:
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


class _EcdhSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "ECDH1_DERIVE"


def _handle(*_args: Any, **_kwargs: Any) -> int:
    return 1


def _fail_if_called(*_args: Any, **_kwargs: Any) -> int:
    raise AssertionError("PKCS#11 import reached for duplicate ECDH vector")


def _read_zeros(_raw: Any, _session: int, _obj: int, attrs: list[int]) -> dict[int, bytes]:
    return {attr: b"\x00" * 32 for attr in attrs}


def test_duplicate_ecdh_container_vector_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PEM/ASN/ECPOINT duplicates should not rerun identical PKCS#11 inputs."""
    monkeypatch.setattr(ecdh, "import_ec_private_key", _fail_if_called)
    vec_id = "ecdh_secp256r1_pem_test.json:tc70-valid"
    vec = next(vec for candidate_id, vec in ecdh._ALL_ECDH_VECTORS if candidate_id == vec_id)

    with pytest.raises(pytest.skip.Exception, match="Duplicate PKCS#11 ECDH operation input"):
        ecdh.test_ecdh(_EcdhSession(), vec_id, vec)


def test_ecdh_curve_mapping_bug_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected curve-mapping bugs must not become capability skips."""
    monkeypatch.setattr(
        ecdh, "ec_params_for_curve", lambda *_args: (_ for _ in ()).throw(RuntimeError("curve bug"))
    )
    vec_id = "ecdh_secp256r1_ecpoint_test.json:tc1-valid"
    vec = next(vec for candidate_id, vec in ecdh._ALL_ECDH_VECTORS if candidate_id == vec_id)

    try:
        ecdh.test_ecdh(_EcdhSession(), vec_id, vec)
    except pytest.skip.Exception as exc:
        pytest.fail(f"ECDH curve-mapping bug was skipped: {exc}")
    except RuntimeError as exc:
        assert "curve bug" in str(exc)
    else:
        pytest.fail("ECDH curve-mapping bug did not propagate")


def test_valid_ecdh_decoder_bug_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected decoder bugs must not become valid-vector capability skips."""
    monkeypatch.setattr(
        ecdh,
        "decode_ec_public_point",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("decoder bug")),
    )
    vec_id = "ecdh_secp256r1_ecpoint_test.json:tc1-valid"
    vec = next(vec for candidate_id, vec in ecdh._ALL_ECDH_VECTORS if candidate_id == vec_id)

    try:
        ecdh.test_ecdh(_EcdhSession(), vec_id, vec)
    except pytest.skip.Exception as exc:
        pytest.fail(f"valid ECDH decoder bug was skipped: {exc}")
    except RuntimeError as exc:
        assert "decoder bug" in str(exc)
    else:
        pytest.fail("valid ECDH decoder bug did not propagate")


def test_invalid_ecdh_decoder_bug_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected decoder bugs must not become invalid-vector skips."""
    monkeypatch.setattr(
        ecdh, "decode_ec_public_point", lambda *_args, **_kwargs: b"\x04" + b"\x01" * 64
    )
    monkeypatch.setattr(
        ecdh,
        "decode_ec_private_scalar",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("decoder bug")),
    )
    vec_id = "ecdh_secp256r1_ecpoint_test.json:tc332-invalid"
    vec = next(vec for candidate_id, vec in ecdh._ALL_ECDH_VECTORS if candidate_id == vec_id)

    try:
        ecdh.test_ecdh(_EcdhSession(), vec_id, vec)
    except pytest.skip.Exception as exc:
        pytest.fail(f"invalid ECDH decoder bug was skipped: {exc}")
    except RuntimeError as exc:
        assert "decoder bug" in str(exc)
    else:
        pytest.fail("invalid ECDH decoder bug did not propagate")


def test_invalid_ecdh_without_shared_secret_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid ECDH public points must fail if a provider derives anyway."""
    monkeypatch.setattr(ecdh, "import_ec_private_key", _handle)
    monkeypatch.setattr(ecdh, "derive_key", _handle)
    monkeypatch.setattr(ecdh, "read_attributes", _read_zeros)
    monkeypatch.setattr(ecdh, "destroy_quietly", lambda *_args: None)

    vec = next(
        vec
        for vec_id, vec in ecdh._ALL_ECDH_VECTORS
        if vec_id == "ecdh_secp256r1_ecpoint_test.json:tc332-invalid"
    )

    with pytest.raises(pytest.fail.Exception, match="invalid-curve attack"):
        ecdh.test_ecdh(_EcdhSession(), "ecdh_secp256r1_ecpoint_test.json:tc332-invalid", vec)


def test_invalid_ecdh_with_shared_secret_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A derive on a parameter-level invalid vector must match the true-curve shared.

    Phase-2 V1 flagged ANY successful derive on an invalid vector. Refined:
    tc352's invalidity (WrongOrder/UnnamedCurve) lives in the ASN.1 curve
    parameters, which CK_ECDH1_DERIVE_PARAMS cannot carry — the module sees a
    valid on-curve point, so the vector reduces to a positive check. A derive
    that does NOT return the true-curve shared secret (here: zeros) must still
    fail — that is the invalid-curve-attack outcome the vector exists to catch.
    """
    vec_id = "ecdh_secp256r1_pem_test.json:tc352-invalid"
    vec = next(vec for candidate_id, vec in ecdh._ALL_ECDH_VECTORS if candidate_id == vec_id)
    assert vec["shared"], "fixture vector must carry a non-empty expected shared secret"

    monkeypatch.setattr(ecdh, "import_ec_private_key", _handle)
    monkeypatch.setattr(ecdh, "derive_key", _handle)
    monkeypatch.setattr(ecdh, "read_attributes", _read_zeros)
    monkeypatch.setattr(ecdh, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="does not match known answer"):
        ecdh.test_ecdh(_EcdhSession(), vec_id, vec)


# --- Parameter-level invalid-vector reduction (on-curve point, true-curve shared) ---
#
# A Wycheproof "invalid" ECDH vector whose invalidity lives in the ASN.1 curve
# parameters (WrongCurve / UnnamedCurve with WrongOrder or ModifiedPrime)
# decodes to a raw point that IS on the private key's curve. The PKCS#11
# operation cannot see that invalidity, so the vector reduces to a positive
# check against the vector's shared secret. Off-curve points never reduce.


def test_shared_x_identity_scalar_returns_point_x() -> None:
    """k=1 on a known on-curve point returns that point's x-coordinate."""
    out = ecdh_cofactor1_shared_x(
        "secp256r1", _p256_point(_P256_GX, _P256_GY), (1).to_bytes(32, "big")
    )
    assert out == _P256_GX.to_bytes(32, "big")


def test_shared_x_off_curve_point_returns_none() -> None:
    """An off-curve point must never reduce (keeps the hard-fail path)."""
    out = ecdh_cofactor1_shared_x(
        "secp256r1", _p256_point(_P256_GX, _P256_GY + 1), (2).to_bytes(32, "big")
    )
    assert out is None


def test_shared_x_unknown_curve_returns_none() -> None:
    """Binary/unknown curves are not reduced — behavior stays unchanged."""
    out = ecdh_cofactor1_shared_x(
        "sect283k1", _p256_point(_P256_GX, _P256_GY), (2).to_bytes(32, "big")
    )
    assert out is None


def test_shared_x_non_uncompressed_or_short_returns_none() -> None:
    """Compressed/garbled encodings are module-visible — not reduced."""
    compressed = b"\x02" + _P256_GX.to_bytes(32, "big")
    assert ecdh_cofactor1_shared_x("secp256r1", compressed, b"\x02") is None
    assert ecdh_cofactor1_shared_x("secp256r1", b"\x04\x01\x02", b"\x02") is None


def test_shared_x_zero_scalar_returns_none() -> None:
    """k=0 yields the point at infinity — no x-coordinate, not reduced."""
    out = ecdh_cofactor1_shared_x(
        "secp256r1", _p256_point(_P256_GX, _P256_GY), (0).to_bytes(32, "big")
    )
    assert out is None


def test_shared_x_matches_wycheproof_wrongcurve_vector() -> None:
    """Real WrongCurve vector: helper reproduces the vector's shared value."""
    vec_id = "ecdh_brainpoolP224r1_test.json:tc517-invalid"
    vec = next(vec for candidate_id, vec in ecdh._ALL_ECDH_VECTORS if candidate_id == vec_id)
    point = ecdh.decode_ec_public_point(vec["public"], vec["_encoding"], vec["_curve"])
    scalar = ecdh.decode_ec_private_scalar(vec["private"], vec["_encoding"], vec["_curve"])
    assert ecdh_cofactor1_shared_x(vec["_curve"], point, scalar) == bytes.fromhex(vec["shared"])


def test_parameter_level_invalid_vector_with_correct_shared_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On-curve WrongCurve vector + true-curve shared secret = pass, not fail."""
    vec_id = "ecdh_brainpoolP224r1_test.json:tc517-invalid"
    vec = next(vec for candidate_id, vec in ecdh._ALL_ECDH_VECTORS if candidate_id == vec_id)
    monkeypatch.setattr(ecdh, "_UNSUPPORTED_CURVES", set())
    monkeypatch.setattr(ecdh, "import_ec_private_key", _handle)
    monkeypatch.setattr(ecdh, "derive_key", _handle)
    monkeypatch.setattr(
        ecdh,
        "read_attributes",
        lambda *_a, **_k: {CKA_VALUE: bytes.fromhex(vec["shared"])},
    )
    monkeypatch.setattr(ecdh, "destroy_quietly", lambda *_args: None)

    ecdh.test_ecdh(_EcdhSession(), vec_id, vec)


def test_parameter_level_invalid_vector_clean_reject_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Clean reject of the (PKCS#11-valid) reduced operation is an xfail, not a pass."""
    vec_id = "ecdh_brainpoolP224r1_test.json:tc517-invalid"
    vec = next(vec for candidate_id, vec in ecdh._ALL_ECDH_VECTORS if candidate_id == vec_id)

    def _reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID",
            int(CKR_MECHANISM_PARAM_INVALID),
        )

    monkeypatch.setattr(ecdh, "_UNSUPPORTED_CURVES", set())
    monkeypatch.setattr(ecdh, "import_ec_private_key", _handle)
    monkeypatch.setattr(ecdh, "derive_key", _reject)
    monkeypatch.setattr(ecdh, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception):
        ecdh.test_ecdh(_EcdhSession(), vec_id, vec)


def test_off_curve_invalid_vector_acceptance_still_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A genuinely off-curve invalid point that derives stays a hard fail."""
    off_curve = _p256_point(_P256_GX, _P256_GY + 1)
    vec = {
        "tcId": 0,
        "public": off_curve.hex(),
        "private": (2).to_bytes(32, "big").hex(),
        "shared": "ab" * 32,
        "result": "invalid",
        "flags": [],
        "_curve": "secp256r1",
        "_encoding": "ecpoint",
        "_file": "synthetic",
        "_group": {},
    }
    monkeypatch.setattr(ecdh, "_UNSUPPORTED_CURVES", set())
    monkeypatch.setattr(ecdh, "import_ec_private_key", _handle)
    monkeypatch.setattr(ecdh, "derive_key", _handle)
    monkeypatch.setattr(ecdh, "read_attributes", lambda *_a, **_k: {CKA_VALUE: b"\xab" * 32})
    monkeypatch.setattr(ecdh, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="invalid-curve attack"):
        ecdh.test_ecdh(_EcdhSession(), "synthetic:tc0-invalid", vec)


def _first_invalid_ecdh() -> tuple[str, dict[str, Any]]:
    hit = next(
        (
            (vid, v)
            for vid, v in ecdh._ALL_ECDH_VECTORS
            if v["result"] == "invalid" and not v.get("_pkcs11_duplicate_of")
        ),
        None,
    )
    if hit is None:
        pytest.skip("Wycheproof ECDH vectors not available (run `fetch-data wycheproof`)")
    return hit


def _wire_successful_derive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ecdh, "import_ec_private_key", _handle)
    monkeypatch.setattr(ecdh, "derive_key", _handle)
    monkeypatch.setattr(ecdh, "read_attributes", _read_zeros)
    monkeypatch.setattr(ecdh, "destroy_quietly", lambda *_a, **_k: None)


def test_ecdh_invalid_derive_on_base_curve_point_is_not_a_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the peer point IS on the base curve, the vector's invalidity lives in
    the X.509 encoding layer that the raw PKCS#11 ECDH path never sees -- a
    correct derive is NOT an invalid-curve attack, so it must not fail."""
    vec_id, vec = _first_invalid_ecdh()
    _wire_successful_derive(monkeypatch)
    monkeypatch.setattr(ecdh, "_point_on_base_curve", lambda *_a: True)

    ecdh.test_ecdh(_EcdhSession(), vec_id, vec)  # no exception


def test_ecdh_invalid_derive_on_off_curve_point_is_a_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the peer point is OFF the base curve, deriving a secret is the genuine
    invalid-curve attack -> must fail (the real finding is preserved)."""
    vec_id, vec = _first_invalid_ecdh()
    _wire_successful_derive(monkeypatch)
    monkeypatch.setattr(ecdh, "_point_on_base_curve", lambda *_a: False)

    with pytest.raises(pytest.fail.Exception, match="invalid-curve"):
        ecdh.test_ecdh(_EcdhSession(), vec_id, vec)


def test_point_on_base_curve_validates_against_cryptography() -> None:
    """The on-curve helper accepts a genuine P-256 point and rejects an
    off-curve one (real cryptography validation, no mock)."""
    on = ecdh._point_on_base_curve(_p256_point(_P256_GX, _P256_GY), "secp256r1")
    assert on is True
    off = ecdh._point_on_base_curve(_p256_point(_P256_GX, _P256_GY ^ 1), "secp256r1")
    assert off is False
