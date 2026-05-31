"""Regression tests for Wycheproof X25519/X448 guards."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.wycheproof import test_wycheproof_x25519 as xdh


class _XdhSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "ECDH1_DERIVE"


def _fail_if_called(*_args: Any, **_kwargs: Any) -> int:
    raise AssertionError("PKCS#11 import reached after invalid public-key decode")


def _fail_if_duplicate_called(*_args: Any, **_kwargs: Any) -> int:
    raise AssertionError("PKCS#11 import reached for duplicate XDH vector")


def _handle(*_args: Any, **_kwargs: Any) -> int:
    return 1


def _raise_device_error(*_args: Any, **_kwargs: Any) -> int:
    raise AssertionError("Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK")


def _read_zeros(_raw: Any, _session: int, _obj: int, attrs: list[int]) -> dict[int, bytes]:
    return {attr: b"\x00" * 56 for attr in attrs}


def test_duplicate_xdh_container_vector_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ASN/PEM/JWK duplicates should not rerun identical PKCS#11 inputs."""
    monkeypatch.setattr(xdh, "import_ec_private_key", _fail_if_duplicate_called)
    vec_id = "x25519_asn_test.json:tc1-valid"
    vec = next(vec for candidate_id, vec in xdh._ALL_XDH_VECTORS if candidate_id == vec_id)

    with pytest.raises(pytest.skip.Exception, match="Duplicate PKCS#11 XDH operation input"):
        xdh.test_xdh(_XdhSession(), vec_id, vec)


def test_invalid_xdh_public_decode_is_accepted_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed invalid public vectors should not become capability skips."""
    monkeypatch.setattr(xdh, "import_ec_private_key", _fail_if_called)
    vec = next(
        vec
        for vec_id, vec in xdh._ALL_XDH_VECTORS
        if vec_id == "x25519_jwk_test.json:tc528-invalid"
    )

    try:
        xdh.test_xdh(_XdhSession(), "x25519_jwk_test.json:tc528-invalid", vec)
    except pytest.skip.Exception as exc:
        pytest.fail(f"invalid XDH public-key decode was skipped: {exc}")


def test_valid_xdh_private_decoder_bug_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected decoder bugs must not become valid-vector capability skips."""
    monkeypatch.setattr(
        xdh,
        "decode_xdh_private_bytes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("decoder bug")),
    )

    vec_id = "x25519_test.json:tc1-valid"
    vec = next(vec for candidate_id, vec in xdh._ALL_XDH_VECTORS if candidate_id == vec_id)

    try:
        xdh.test_xdh(_XdhSession(), vec_id, vec)
    except pytest.skip.Exception as exc:
        pytest.fail(f"valid XDH decoder bug was skipped: {exc}")
    except RuntimeError as exc:
        assert "decoder bug" in str(exc)
    else:
        pytest.fail("valid XDH decoder bug did not propagate")


def test_invalid_xdh_public_decoder_bug_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected decoder bugs must not become invalid-vector passes."""
    monkeypatch.setattr(xdh, "decode_xdh_private_bytes", lambda *_args, **_kwargs: b"\x01" * 32)
    monkeypatch.setattr(
        xdh,
        "decode_xdh_public_bytes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("decoder bug")),
    )

    vec_id = "x25519_jwk_test.json:tc528-invalid"
    vec = next(vec for candidate_id, vec in xdh._ALL_XDH_VECTORS if candidate_id == vec_id)

    with pytest.raises(RuntimeError, match="decoder bug"):
        xdh.test_xdh(_XdhSession(), vec_id, vec)


def test_invalid_xdh_public_length_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed public bytes must fail if a provider derives anyway."""
    monkeypatch.setattr(xdh, "import_ec_private_key", _handle)
    monkeypatch.setattr(xdh, "derive_key", _handle)
    monkeypatch.setattr(xdh, "read_attributes", _read_zeros)
    monkeypatch.setattr(xdh, "destroy_quietly", lambda *_args: None)

    vec = next(
        vec for vec_id, vec in xdh._ALL_XDH_VECTORS if vec_id == "x448_test.json:tc76-invalid"
    )

    with pytest.raises(pytest.fail.Exception, match="invalid-point accepted"):
        xdh.test_xdh(_XdhSession(), "x448_test.json:tc76-invalid", vec)


def test_invalid_xdh_correct_length_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid vector that derives must fail even when the public key length is correct.

    Phase-2 V1: the previous gate only fired when ``len(public_bytes) != key_size``,
    so a low-order / invalid-but-correct-length point that derived a secret was
    accepted silently. Any successful derive on an invalid vector must now fail.
    """
    vec_id = "x25519_jwk_test.json:tc519-invalid"
    vec = next(vec for candidate_id, vec in xdh._ALL_XDH_VECTORS if candidate_id == vec_id)

    monkeypatch.setattr(xdh, "import_ec_private_key", _handle)
    monkeypatch.setattr(xdh, "derive_key", _handle)
    monkeypatch.setattr(xdh, "read_attributes", _read_zeros)
    monkeypatch.setattr(xdh, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="invalid-point accepted"):
        xdh.test_xdh(_XdhSession(), vec_id, vec)


def test_valid_xdh_derive_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid-vector derive CKRs are advertised-but-not-operational evidence."""
    monkeypatch.setattr(xdh, "import_ec_private_key", _handle)
    monkeypatch.setattr(xdh, "derive_key", _raise_device_error)
    monkeypatch.setattr(xdh, "destroy_quietly", lambda *_args: None)

    vec_id = "x25519_test.json:tc1-valid"
    vec = next(vec for candidate_id, vec in xdh._ALL_XDH_VECTORS if candidate_id == vec_id)

    with pytest.raises(pytest.xfail.Exception, match="advertised XDH derive is not operational"):
        xdh.test_xdh(_XdhSession(), vec_id, vec)
