"""Regression tests for Wycheproof ECDH guards."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.wycheproof import test_wycheproof_ecdh as ecdh


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

    with pytest.raises(pytest.fail.Exception, match="invalid-point accepted"):
        ecdh.test_ecdh(_EcdhSession(), "ecdh_secp256r1_ecpoint_test.json:tc332-invalid", vec)


def test_invalid_ecdh_with_shared_secret_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Any successful derive on an invalid vector fails, regardless of shared_expected.

    Phase-2 V1: the previous gate only flagged invalid vectors whose expected
    shared secret was empty; an invalid vector that carries a non-empty
    expected shared secret was accepted silently. This vector has a non-empty
    ``shared`` value, so a successful derive must now fail.
    """
    vec_id = "ecdh_secp256r1_pem_test.json:tc352-invalid"
    vec = next(vec for candidate_id, vec in ecdh._ALL_ECDH_VECTORS if candidate_id == vec_id)
    assert vec["shared"], "fixture vector must carry a non-empty expected shared secret"

    monkeypatch.setattr(ecdh, "import_ec_private_key", _handle)
    monkeypatch.setattr(ecdh, "derive_key", _handle)
    monkeypatch.setattr(ecdh, "read_attributes", _read_zeros)
    monkeypatch.setattr(ecdh, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="invalid-point accepted"):
        ecdh.test_ecdh(_EcdhSession(), vec_id, vec)
