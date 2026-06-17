"""Regression test: build_params_from_vector for chacha20_poly1305 must wire the
vector's nonce and AAD into the packed mechanism, not generate a fresh random nonce.

Before the fix, the chacha20_poly1305 style fell through to build_test_params()
which generates a random nonce with aad=None, making KAT vectors unpassable.
"""

from __future__ import annotations

import ctypes

from pkcs11_check.raw.types_std import CKM_CHACHA20_POLY1305
from pkcs11_check.testcases.mechanism_helpers import build_params_from_vector
from pkcs11_check.testcases.mechanism_registry import ParamRecipe

# KAT vector values from chacha20_poly1305.json
_NONCE_HEX = "f427bca889caceaf132bc0db"
_AAD_HEX = "aff3f8dd53d6b941e5a4c788387f8783"
_NONCE_BYTES = bytes.fromhex(_NONCE_HEX)
_AAD_BYTES = bytes.fromhex(_AAD_HEX)

_CHACHA_RECIPE = ParamRecipe("chacha20_poly1305")


def _extract_nonce_and_aad(pm: object) -> tuple[bytes, bytes | None]:
    """Extract nonce and AAD bytes from a PackedMechanism carrying
    CK_SALSA20_CHACHA20_POLY1305_PARAMS.

    The params struct stores pointers (c_void_p) and lengths.  We use ctypes
    to read the bytes at the pointer address.
    """
    params = pm.params  # type: ignore[attr-defined]
    assert params is not None, "params must not be None for chacha20_poly1305"

    nonce_len = int(params.ulNonceLen)
    nonce_ptr = params.pNonce
    assert nonce_ptr is not None, "pNonce must not be None"
    nonce = bytes((ctypes.c_uint8 * nonce_len).from_address(nonce_ptr))

    aad_len = int(params.ulAADLen)
    if aad_len == 0 or params.pAAD is None:
        aad = None
    else:
        aad = bytes((ctypes.c_uint8 * aad_len).from_address(params.pAAD))

    return nonce, aad


def test_build_params_from_vector_chacha20_poly1305_uses_vector_nonce() -> None:
    """build_params_from_vector with chacha20_poly1305 recipe must use the vector's
    nonce, not a freshly generated random one."""
    vec = {
        "params": {
            "iv_hex": _NONCE_HEX,
            "aad_hex": _AAD_HEX,
            "tag_bits": 128,
        }
    }
    pm = build_params_from_vector(int(CKM_CHACHA20_POLY1305), _CHACHA_RECIPE, vec)
    nonce, aad = _extract_nonce_and_aad(pm)
    assert nonce == _NONCE_BYTES, f"nonce mismatch: got {nonce.hex()!r}, expected {_NONCE_HEX!r}"
    assert aad == _AAD_BYTES, (
        f"aad mismatch: got {aad.hex() if aad else None!r}, expected {_AAD_HEX!r}"
    )
    assert len(nonce) == 12, f"expected 12-byte nonce, got {len(nonce)}"


def test_build_params_from_vector_chacha20_poly1305_no_aad() -> None:
    """build_params_from_vector with chacha20_poly1305 recipe and no aad_hex must
    produce empty/None AAD (not crash)."""
    vec = {
        "params": {
            "iv_hex": _NONCE_HEX,
        }
    }
    pm = build_params_from_vector(int(CKM_CHACHA20_POLY1305), _CHACHA_RECIPE, vec)
    nonce, aad = _extract_nonce_and_aad(pm)
    assert nonce == _NONCE_BYTES, f"nonce mismatch: got {nonce.hex()!r}, expected {_NONCE_HEX!r}"
    assert aad is None or aad == b"", f"expected no AAD, got {aad!r}"


def test_build_params_from_vector_chacha20_poly1305_no_iv_falls_back_to_random() -> None:
    """When iv_hex is absent from the vector, build_params_from_vector falls back to
    build_test_params (random nonce generation) — the non-KAT caller path."""
    vec: dict[str, object] = {"params": {}}
    pm = build_params_from_vector(int(CKM_CHACHA20_POLY1305), _CHACHA_RECIPE, vec)
    # Must return a valid PackedMechanism, not crash
    assert pm is not None
    nonce, _aad = _extract_nonce_and_aad(pm)
    assert len(nonce) == 12, f"fallback random nonce should be 12 bytes, got {len(nonce)}"
