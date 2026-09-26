"""Focused regressions for EdDSA parameter modes by key profile and scheme.

Normative mode table (brief task-6):

- RFC8032 ``edwards25519`` / Ed25519      -> NULL
- RFC8032 ``edwards25519`` / Ed25519ctx   -> structure, phFlag=false, ctx 0-255
- RFC8032 ``edwards25519`` / Ed25519ph    -> structure, phFlag=true,  ctx 0-255
- RFC8032 ``edwards448``   / Ed448        -> structure, phFlag=false, ctx 0-255
- RFC8032 ``edwards448``   / Ed448ph      -> structure, phFlag=true,  ctx 0-255
- RFC8410 ``id-Ed25519``   / pure Ed25519 -> NULL
- RFC8410 ``id-Ed448``     / pure Ed448   -> NULL
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TEST_MECH_NEGATIVE = REPO / "src" / "pkcs11_check" / "testcases" / "test_mech_negative.py"
TEST_EDDSA = REPO / "src" / "pkcs11_check" / "testcases" / "test_eddsa.py"


def test_resolve_mech_eddsa_omitted_params_produce_null() -> None:
    """Omitted CKM_EDDSA parameters must resolve to NULL/zero fields."""
    from pkcs11_check.raw.recipes import _resolve_mech
    from pkcs11_check.raw.types_std import CKM_EDDSA

    mech = _resolve_mech(CKM_EDDSA, None)

    assert mech.ck.mechanism == CKM_EDDSA
    assert mech.ck.pParameter is None
    assert mech.ck.ulParameterLen == 0


def test_resolve_mech_eddsa_explicit_packed_mechanism_unchanged() -> None:
    """Explicit packed CKM_EDDSA mechanisms must pass through untouched."""
    from pkcs11_check.raw.pack import mech_eddsa
    from pkcs11_check.raw.recipes import _resolve_mech
    from pkcs11_check.raw.types_std import CKM_EDDSA

    explicit = mech_eddsa(CKM_EDDSA, context_data=b"ctx", prehash=True)

    assert _resolve_mech(CKM_EDDSA, explicit) is explicit


def test_registry_eddsa_default_profile_is_rfc8410_pure() -> None:
    """The default registry profile is RFC8410 pure Ed25519: optional/none."""
    from pkcs11_check.raw.types_std import CKM_EDDSA
    from pkcs11_check.testcases.mechanism_registry import get_config

    config = get_config(int(CKM_EDDSA))

    assert config is not None
    assert config.param_required is False
    assert config.param_recipe.style == "none"


def test_registry_eddsa_kat_builder_returns_no_parameter() -> None:
    """The registry KAT must actually send NULL, not an eddsa recipe."""
    from pkcs11_check.raw.types_std import CKM_EDDSA
    from pkcs11_check.testcases.mechanism_helpers import (
        build_params_from_vector,
        build_test_params,
    )
    from pkcs11_check.testcases.mechanism_registry import get_config

    config = get_config(int(CKM_EDDSA))
    assert config is not None

    assert build_test_params(int(CKM_EDDSA), config.param_recipe) is None
    assert build_params_from_vector(int(CKM_EDDSA), config.param_recipe, {"params": {}}) is None


def test_edwards_curve_name_der_encoding_edwards25519() -> None:
    from pkcs11_check.raw.ec import encode_edwards_curve_name_parameters

    assert encode_edwards_curve_name_parameters("edwards25519") == bytes.fromhex(
        "130c656477617264733235353139"
    )


def test_edwards_curve_name_der_encoding_edwards448() -> None:
    from pkcs11_check.raw.ec import encode_edwards_curve_name_parameters

    assert encode_edwards_curve_name_parameters("edwards448") == bytes.fromhex(
        "130a65647761726473343438"
    )


def test_edwards_curve_name_encoding_rejects_unknown_name() -> None:
    from pkcs11_check.raw.ec import encode_edwards_curve_name_parameters

    with pytest.raises(ValueError, match="Unknown Edwards curveName"):
        encode_edwards_curve_name_parameters("secp256r1")


def test_rfc8410_oid_encodings_unchanged() -> None:
    """RFC8410 OID encodings must stay byte-identical."""
    from pkcs11_check.raw.ec import encode_named_curve_parameters

    assert encode_named_curve_parameters("ed25519") == bytes([0x06, 0x03, 0x2B, 0x65, 0x70])
    assert encode_named_curve_parameters("ed448") == bytes([0x06, 0x03, 0x2B, 0x65, 0x71])


def test_adaptive_explicit_profile_sends_complete_structure() -> None:
    """The explicit compatibility profile must call mech_eddsa directly (not None)."""
    from typing import Any

    from pkcs11_check.raw.types_std import CK_EDDSA_PARAMS
    from pkcs11_check.testcases import _eddsa_public_key as eddsa_keys

    captured: list[Any] = []

    def fake_verify_single(*args: Any, **kwargs: Any) -> bool:
        captured.append(kwargs["mech_param"])
        return True

    raw = object()
    eddsa_keys.clear_eddsa_public_key_encoding_cache()
    eddsa_keys.remember_eddsa_public_key_profile(raw, b"params", "raw", "explicit")
    try:
        import unittest.mock as mock

        with mock.patch.object(eddsa_keys, "verify_single", fake_verify_single):
            verified = eddsa_keys.verify_eddsa_signature_with_supported_params(
                raw,
                1,
                public_key_handle=7,
                ec_params=b"params",
                message=b"message",
                signature=b"S" * 64,
            )
    finally:
        eddsa_keys.clear_eddsa_public_key_encoding_cache()

    assert verified is True
    assert len(captured) == 1
    assert captured[0] is not None
    assert isinstance(captured[0].params, CK_EDDSA_PARAMS)


def test_adaptive_null_profile_constructs_mech_simple() -> None:
    """The NULL profile must keep constructing mech_simple (NULL/zero)."""
    from typing import Any

    from pkcs11_check.testcases import _eddsa_public_key as eddsa_keys

    captured: list[Any] = []

    def fake_verify_single(*args: Any, **kwargs: Any) -> bool:
        captured.append(kwargs["mech_param"])
        return True

    raw = object()
    eddsa_keys.clear_eddsa_public_key_encoding_cache()
    eddsa_keys.remember_eddsa_public_key_profile(raw, b"params", "raw", "null")
    try:
        import unittest.mock as mock

        with mock.patch.object(eddsa_keys, "verify_single", fake_verify_single):
            eddsa_keys.verify_eddsa_signature_with_supported_params(
                raw,
                1,
                public_key_handle=7,
                ec_params=b"params",
                message=b"message",
                signature=b"S" * 64,
            )
    finally:
        eddsa_keys.clear_eddsa_public_key_encoding_cache()

    assert len(captured) == 1
    assert captured[0] is not None
    assert captured[0].ck.pParameter is None
    assert captured[0].ck.ulParameterLen == 0


# ---------------------------------------------------------------------------
# Node retention / mapping: every prior EdDSA missing/malformed sign/verify
# product node is retained or explicitly mapped. The generic registry tests
# below keep their IDs (EDDSA now skips them as optional-param); the explicit
# EdDSA tests carry the retained coverage with applicable RFC8032 setup.
# ---------------------------------------------------------------------------

_PRIOR_GENERIC_NODES = (
    "test_registry_sign_missing_required_param",
    "test_registry_sign_malformed_required_param",
    "test_registry_verify_missing_required_param",
    "test_registry_verify_malformed_required_param",
)

_NEW_EDDSA_NEGATIVE_NODES = (
    # param_required=True would have given EDDSA these generic nodes; the
    # RFC8410 pure default makes them inapplicable, so coverage moves here:
    "test_eddsa_edwards448_sign_missing_required_param",  # was [EDDSA] sign missing
    "test_eddsa_edwards448_sign_malformed_required_param",  # was [EDDSA] sign malformed
    "test_eddsa_edwards448_verify_missing_required_param",  # was [EDDSA] verify missing
    "test_eddsa_edwards448_verify_malformed_required_param",  # was [EDDSA] verify malformed
)

_NEW_EDDSA_POSITIVE_NODES = (
    "test_edwards25519_curve_name_pure_null_roundtrip",
    "test_edwards25519_ctx_roundtrip",
    "test_edwards25519_ph_roundtrip",
    "test_edwards448_ctx_roundtrip",
    "test_edwards448_ph_roundtrip",
    "test_eddsa_context_mismatch_does_not_verify",
    "test_eddsa_pure_and_ctx_modes_do_not_cross_verify",
)


def test_prior_generic_missing_malformed_nodes_retained() -> None:
    source = TEST_MECH_NEGATIVE.read_text(encoding="utf-8")
    for node in _PRIOR_GENERIC_NODES:
        assert node in source


def test_new_eddsa_negative_nodes_present() -> None:
    source = TEST_MECH_NEGATIVE.read_text(encoding="utf-8")
    for node in _NEW_EDDSA_NEGATIVE_NODES:
        assert node in source


def test_new_eddsa_positive_nodes_present() -> None:
    source = TEST_EDDSA.read_text(encoding="utf-8")
    for node in _NEW_EDDSA_POSITIVE_NODES:
        assert node in source
