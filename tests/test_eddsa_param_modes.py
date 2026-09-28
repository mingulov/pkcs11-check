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
from typing import Any

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
    "test_edwards25519_ctx_null_pointer_roundtrip",
    "test_edwards25519_ctx_empty_bytes_roundtrip",
    "test_edwards25519_ctx_single_byte_roundtrip",
    "test_edwards25519_ctx_max_length_roundtrip",
    "test_eddsa_ph_mode_does_not_cross_verify",
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


# ---------------------------------------------------------------------------
# Context-shape wire pins: NULL-pointer vs empty-bytes vs short vs maximal
# contexts must reach sign and verify with the exact packed representation.
# ---------------------------------------------------------------------------


def _decode_eddsa_wire(mech_param: Any) -> tuple[bool, bool, int, bytes | None]:
    """Decode a captured EdDSA mech_param to
    (is_struct, context_pointer_non_null, context_len, context_bytes)."""
    import ctypes

    assert mech_param is not None
    params = mech_param.params
    if params is None:
        return (False, False, 0, None)
    ptr = params.pContextData
    length = int(params.ulContextDataLen)
    context = bytes(ctypes.string_at(ptr, length)) if ptr else None
    return (True, ptr is not None, length, context)


def _run_mode_roundtrip(node: str) -> tuple[tuple[bool, bool, int, bytes | None], ...]:
    """Drive one product roundtrip node with stubbed sign/verify; return the
    decoded (sign, verify) wire shapes."""
    import unittest.mock as mock
    from types import SimpleNamespace

    from pkcs11_check.testcases import test_eddsa as eddsa

    captured: list[Any] = []

    def _sign(*args: Any, **kwargs: Any) -> bytes:
        captured.append(kwargs["mech_param"])
        return b"S" * 64

    def _verify(*args: Any, **kwargs: Any) -> bool:
        captured.append(kwargs["mech_param"])
        return True

    rs = SimpleNamespace(raw=object(), sh=1)
    node_fn = getattr(eddsa.TestEdDSAParametrizedModes(), node)
    with (
        mock.patch.object(eddsa, "sign_single", _sign),
        mock.patch.object(eddsa, "verify_single", _verify),
    ):
        node_fn(rs, (7, 8))

    assert len(captured) == 2
    return (_decode_eddsa_wire(captured[0]), _decode_eddsa_wire(captured[1]))


def test_ctx_null_pointer_sends_null_pcontext_with_zero_len() -> None:
    """context_data=None packs a structure with NULL pContextData, len 0."""
    sign_shape, verify_shape = _run_mode_roundtrip("test_edwards25519_ctx_null_pointer_roundtrip")
    assert sign_shape == (True, False, 0, None)
    assert verify_shape == (True, False, 0, None)


def test_ctx_empty_bytes_sends_non_null_pcontext_with_zero_len() -> None:
    """context_data=b"" packs a structure with a non-NULL pointer, len 0 --
    the ABI-distinct empty representation."""
    sign_shape, verify_shape = _run_mode_roundtrip("test_edwards25519_ctx_empty_bytes_roundtrip")
    assert sign_shape == (True, True, 0, b"")
    assert verify_shape == (True, True, 0, b"")


def test_ctx_single_byte_roundtrip_carries_exact_byte() -> None:
    """A one-byte context reaches sign and verify byte-identical."""
    sign_shape, verify_shape = _run_mode_roundtrip("test_edwards25519_ctx_single_byte_roundtrip")
    assert sign_shape == (True, True, 1, b"\x42")
    assert verify_shape == (True, True, 1, b"\x42")


def test_ctx_max_length_roundtrip_carries_255_bytes() -> None:
    """A 255-byte context reaches sign and verify byte-identical."""
    expected = bytes(range(255))
    sign_shape, verify_shape = _run_mode_roundtrip("test_edwards25519_ctx_max_length_roundtrip")
    assert sign_shape == (True, True, 255, expected)
    assert verify_shape == (True, True, 255, expected)


def test_ctx_structures_carry_sizeof_eddsa_params() -> None:
    """Structured rows send ulParameterLen == sizeof(CK_EDDSA_PARAMS)."""
    import ctypes
    import unittest.mock as mock
    from types import SimpleNamespace

    from pkcs11_check.raw.types_std import CK_EDDSA_PARAMS
    from pkcs11_check.testcases import test_eddsa as eddsa

    captured: list[Any] = []

    def _sign(*args: Any, **kwargs: Any) -> bytes:
        captured.append(kwargs["mech_param"])
        return b"S" * 64

    def _verify(*args: Any, **kwargs: Any) -> bool:
        captured.append(kwargs["mech_param"])
        return True

    rs = SimpleNamespace(raw=object(), sh=1)
    node = eddsa.TestEdDSAParametrizedModes()
    with (
        mock.patch.object(eddsa, "sign_single", _sign),
        mock.patch.object(eddsa, "verify_single", _verify),
    ):
        node.test_edwards25519_ctx_empty_bytes_roundtrip(rs, (7, 8))

    assert len(captured) == 2
    for mech in captured:
        assert mech.ck.ulParameterLen == ctypes.sizeof(CK_EDDSA_PARAMS)


def test_ph_mode_exercises_all_separation_directions() -> None:
    """The ph separation node must sign ph + NULL + ctx and verify each
    signature under a different mode, all drawing rejection (False)."""
    import unittest.mock as mock
    from types import SimpleNamespace

    from pkcs11_check.testcases import test_eddsa as eddsa

    captured: list[tuple[str, Any]] = []

    def _sign(*args: Any, **kwargs: Any) -> bytes:
        captured.append(("sign", kwargs["mech_param"]))
        return b"S" * 64

    def _verify(*args: Any, **kwargs: Any) -> bool:
        captured.append(("verify", kwargs["mech_param"]))
        return False

    rs = SimpleNamespace(raw=object(), sh=1)
    with (
        mock.patch.object(eddsa, "sign_single", _sign),
        mock.patch.object(eddsa, "verify_single", _verify),
    ):
        eddsa.TestEdDSAParametrizedModes().test_eddsa_ph_mode_does_not_cross_verify(rs, (7, 8))

    kinds = [op for op, _ in captured]
    assert kinds.count("sign") == 3
    assert kinds.count("verify") == 4

    ph_flags: list[bool | None] = []
    for _op, mech in captured:
        params = mech.params
        ph_flags.append(None if params is None else bool(params.phFlag))
    assert True in ph_flags  # ph structures exercised
    assert False in ph_flags  # ctx structures exercised
    assert None in ph_flags  # NULL pure exercised
