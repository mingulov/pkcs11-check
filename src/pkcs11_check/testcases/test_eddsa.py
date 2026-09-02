"""Tests for EdDSA (Ed25519/Ed448) key generation, signing, and properties.

EdDSA is available on some PKCS#11 modules.
Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_bytes
from pkcs11_check.raw.recipes import (
    gen_keypair,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_EC_EDWARDS,
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKM_EDDSA,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.conftest import (
    EC_CURVE_UNSUPPORTED_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    assert_correct,
    is_known_error,
    xfail_if_known_ckr,
)

_EDDSA_RUNTIME_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _sign_eddsa(rs: Any, priv: int, data: bytes) -> bytes:
    """Sign data with CKM_EDDSA, xfail on explicit advertised-path rejects."""
    try:
        return sign_single(rs.raw, rs.sh, priv, CKM_EDDSA, data)
    except CkrAssertionError as exc:
        xfail_if_known_ckr(exc, _EDDSA_RUNTIME_REJECT_RVS, "advertised EdDSA sign rejected")
    raise


def _verify_eddsa(rs: Any, pub: int, data: bytes, sig: bytes) -> bool:
    """Verify EdDSA signature, xfail on explicit advertised-path rejects."""
    try:
        return verify_single(rs.raw, rs.sh, pub, CKM_EDDSA, data, sig)
    except CkrAssertionError as exc:
        xfail_if_known_ckr(exc, _EDDSA_RUNTIME_REJECT_RVS, "advertised EdDSA verify rejected")
    raise


pytestmark = pytest.mark.crossverify

ED25519_OID = encode_named_curve_parameters("ed25519")


def _gen_ed25519(rs: Any) -> tuple[int, int]:
    """Generate Ed25519 keypair via raw C_GenerateKeyPair."""
    return gen_keypair(
        rs.raw,
        rs.sh,
        CKM_EC_EDWARDS_KEY_PAIR_GEN,
        pub_base=[attr_bytes(CKA_EC_PARAMS, ED25519_OID)],
        priv_base=[],
        public_attrs={
            CKA_VERIFY: True,
            CKA_TOKEN: False,
        },
        private_attrs={
            CKA_SIGN: True,
            CKA_TOKEN: False,
        },
        pub_skip={CKA_EC_PARAMS},
    )


def _gen_edwards_or_skip(
    rs: Any, curve_name: str, generator: Callable[[Any], tuple[int, int]]
) -> tuple[int, int]:
    """Skip an explicitly unsupported curve; expose other keygen failures."""
    try:
        return generator(rs)
    except CkrAssertionError as exc:
        if is_known_error(exc, EC_CURVE_UNSUPPORTED_RVS):
            pytest.skip(f"{curve_name} curve not supported")
        xfail_if_known_ckr(
            exc,
            KEYPAIR_RUNTIME_REJECT_RVS,
            f"{curve_name} key generation advertised but not operational",
        )
        raise


@pytest.fixture()
def ed25519_keypair(p11_raw_session: Any) -> tuple[int, int]:
    """Generate Ed25519 keypair, skip if unsupported."""
    rs = p11_raw_session
    if not rs.has_mechanism("EDDSA"):
        pytest.skip("EDDSA mechanism not supported")

    return _gen_edwards_or_skip(rs, "Ed25519", _gen_ed25519)


class TestEdDSAKeyGeneration:
    def test_ed25519_keygen(self, p11_raw_session: Any, ed25519_keypair: tuple[int, int]) -> None:
        """Generate Ed25519 key pair."""
        pub, priv = ed25519_keypair
        assert pub != 0
        assert priv != 0

    def test_ed25519_key_type(self, p11_raw_session: Any, ed25519_keypair: tuple[int, int]) -> None:
        """Ed25519 key should have EC_EDWARDS key type."""
        rs = p11_raw_session
        pub, priv = ed25519_keypair
        pub_kt = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
        priv_kt = read_attributes(rs.raw, rs.sh, priv, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
        assert_correct(
            actual=pub_kt,
            expected=CKK_EC_EDWARDS,
            label="Ed25519:public CKA_KEY_TYPE readback",
            operation="C_GetAttributeValue",
            kind="metadata",
        )
        assert_correct(
            actual=priv_kt,
            expected=CKK_EC_EDWARDS,
            label="Ed25519:private CKA_KEY_TYPE readback",
            operation="C_GetAttributeValue",
            kind="metadata",
        )

    def test_ed25519_ec_params(
        self, p11_raw_session: Any, ed25519_keypair: tuple[int, int]
    ) -> None:
        """Ed25519 key should have correct EC params (OID)."""
        rs = p11_raw_session
        pub, _ = ed25519_keypair
        params = read_attributes(rs.raw, rs.sh, pub, [CKA_EC_PARAMS])[CKA_EC_PARAMS]
        assert_correct(
            actual=params,
            expected=ED25519_OID,
            label="Ed25519:CKA_EC_PARAMS readback",
            operation="C_GetAttributeValue",
            kind="metadata",
        )


class TestEdDSASignVerify:
    def test_sign_verify_roundtrip(
        self, p11_raw_session: Any, ed25519_keypair: tuple[int, int]
    ) -> None:
        """Sign and verify with Ed25519."""
        rs = p11_raw_session
        pub, priv = ed25519_keypair
        data = b"EdDSA sign-verify test data"

        signature = _sign_eddsa(rs, priv, data)
        assert len(signature) == 64  # Ed25519 = 64 bytes

        result = _verify_eddsa(rs, pub, data, signature)
        assert result is True

    def test_wrong_data_fails(self, p11_raw_session: Any, ed25519_keypair: tuple[int, int]) -> None:
        """Verification with wrong data must fail."""
        rs = p11_raw_session
        pub, priv = ed25519_keypair

        sig = _sign_eddsa(rs, priv, b"original data")

        result = _verify_eddsa(rs, pub, b"tampered data", sig)
        assert result is False

    def test_signature_length(self, p11_raw_session: Any, ed25519_keypair: tuple[int, int]) -> None:
        """Ed25519 signatures are always exactly 64 bytes."""
        rs = p11_raw_session
        _, priv = ed25519_keypair
        for data in [b"", b"x", b"a" * 1000]:
            sig = _sign_eddsa(rs, priv, data)
            assert len(sig) == 64

    def test_different_data_different_signatures(
        self, p11_raw_session: Any, ed25519_keypair: tuple[int, int]
    ) -> None:
        """Different messages produce different signatures."""
        rs = p11_raw_session
        _, priv = ed25519_keypair
        sig1 = _sign_eddsa(rs, priv, b"message one")
        sig2 = _sign_eddsa(rs, priv, b"message two")
        if sig1 == sig2:
            classify(
                "wrong_result",
                kind="crypto",
                label="CKM_EDDSA:sign message dependence",
                operation="C_Sign",
                mechanism="CKM_EDDSA",
                summary="different messages produced identical signatures -- "
                "signature does not depend on the message",
            )

    def test_deterministic_signatures(
        self, p11_raw_session: Any, ed25519_keypair: tuple[int, int]
    ) -> None:
        """Ed25519 signatures are deterministic (same key+data -> same sig)."""
        rs = p11_raw_session
        _, priv = ed25519_keypair
        data = b"determinism test"
        sig1 = _sign_eddsa(rs, priv, data)
        sig2 = _sign_eddsa(rs, priv, data)
        assert_correct(
            actual=sig1,
            expected=sig2,
            label="CKM_EDDSA:sign determinism",
            operation="C_Sign",
            mechanism="CKM_EDDSA",
        )

    def test_different_keys_different_signatures(self, p11_raw_session: Any) -> None:
        """Same data signed with different Ed25519 keys gives different sigs."""
        rs = p11_raw_session
        if not rs.has_mechanism("EDDSA"):
            pytest.skip("EDDSA not supported")
        _, priv1 = _gen_edwards_or_skip(rs, "Ed25519", _gen_ed25519)
        _, priv2 = _gen_edwards_or_skip(rs, "Ed25519", _gen_ed25519)

        data = b"key independence test"
        sig1 = _sign_eddsa(rs, priv1, data)
        sig2 = _sign_eddsa(rs, priv2, data)
        if sig1 == sig2:
            classify(
                "wrong_result",
                kind="crypto",
                label="CKM_EDDSA:sign key independence",
                operation="C_Sign",
                mechanism="CKM_EDDSA",
                summary="different keys produced identical signatures -- key not used",
            )


class TestEdDSACrossVerify:
    """Cross-verify Ed25519 signatures with Python cryptography."""

    def test_sign_p11_verify_crypto(
        self, p11_raw_session: Any, ed25519_keypair: tuple[int, int]
    ) -> None:
        """Sign in PKCS#11, verify with cryptography Ed25519."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        rs = p11_raw_session
        pub, priv = ed25519_keypair
        data = b"Ed25519 cross-verify test"

        sig = _sign_eddsa(rs, priv, data)

        # Export the public key point
        ec_point = read_attributes(rs.raw, rs.sh, pub, [CKA_EC_POINT])[CKA_EC_POINT]
        assert isinstance(ec_point, bytes)
        # DER OCTET STRING: 04 <len> <32-byte point>
        if ec_point[0] == 0x04:
            raw_key = ec_point[2:] if ec_point[1] < 128 else ec_point[3:]
        else:
            raw_key = ec_point

        pub_crypto = Ed25519PublicKey.from_public_bytes(raw_key)
        pub_crypto.verify(sig, data)  # raises on failure


# ---------------------------------------------------------------------------
# Ed448 tests
# ---------------------------------------------------------------------------

ED448_OID = encode_named_curve_parameters("ed448")


def _gen_ed448(rs: Any) -> tuple[int, int]:
    """Generate Ed448 keypair via raw C_GenerateKeyPair."""
    return gen_keypair(
        rs.raw,
        rs.sh,
        CKM_EC_EDWARDS_KEY_PAIR_GEN,
        pub_base=[attr_bytes(CKA_EC_PARAMS, ED448_OID)],
        priv_base=[],
        public_attrs={
            CKA_VERIFY: True,
            CKA_TOKEN: False,
        },
        private_attrs={
            CKA_SIGN: True,
            CKA_TOKEN: False,
        },
        pub_skip={CKA_EC_PARAMS},
    )


@pytest.fixture()
def ed448_keypair(p11_raw_session: Any) -> tuple[int, int]:
    """Generate Ed448 keypair, skip if unsupported."""
    rs = p11_raw_session
    if not rs.has_mechanism("EDDSA"):
        pytest.skip("EDDSA mechanism not supported")
    return _gen_edwards_or_skip(rs, "Ed448", _gen_ed448)


class TestEd448:
    """Ed448 key generation, signing, and verification."""

    def test_ed448_keygen(self, p11_raw_session: Any, ed448_keypair: tuple[int, int]) -> None:
        """Generate Ed448 key pair."""
        pub, priv = ed448_keypair
        assert pub != 0
        assert priv != 0

    def test_ed448_key_type(self, p11_raw_session: Any, ed448_keypair: tuple[int, int]) -> None:
        """Ed448 key type is CKK_EC_EDWARDS."""
        rs = p11_raw_session
        pub, _ = ed448_keypair
        attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE])
        assert_correct(
            actual=attrs[CKA_KEY_TYPE],
            expected=int(CKK_EC_EDWARDS),
            label="Ed448:CKA_KEY_TYPE readback",
            operation="C_GetAttributeValue",
            kind="metadata",
        )

    def test_sign_verify_roundtrip(
        self, p11_raw_session: Any, ed448_keypair: tuple[int, int]
    ) -> None:
        """Sign and verify with Ed448."""
        rs = p11_raw_session
        pub, priv = ed448_keypair
        data = b"Ed448 sign-verify test data"
        signature = _sign_eddsa(rs, priv, data)
        assert len(signature) == 114, f"Ed448 signature must be 114 bytes, got {len(signature)}"
        result = _verify_eddsa(rs, pub, data, signature)
        assert result is True

    def test_wrong_data_fails(self, p11_raw_session: Any, ed448_keypair: tuple[int, int]) -> None:
        """Verification with wrong data must fail."""
        rs = p11_raw_session
        pub, priv = ed448_keypair
        sig = _sign_eddsa(rs, priv, b"original data")
        result = _verify_eddsa(rs, pub, b"tampered data", sig)
        assert result is False

    def test_signature_length(self, p11_raw_session: Any, ed448_keypair: tuple[int, int]) -> None:
        """Ed448 signatures are always exactly 114 bytes."""
        rs = p11_raw_session
        _, priv = ed448_keypair
        for data in [b"", b"x", b"a" * 1000]:
            sig = _sign_eddsa(rs, priv, data)
            assert len(sig) == 114
