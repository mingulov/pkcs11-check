"""Tests for EdDSA (Ed25519/Ed448) key generation, signing, and properties.

EdDSA is available on SoftHSM2 2.7.0+, Kryoptic, and NSS.
Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_bytes
from pkcs11_check.raw.recipes import (
    gen_keypair,
    read_attributes,
    sign_single,
    verify_single,
)
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
)

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


@pytest.fixture()
def ed25519_keypair(p11_raw_session: Any) -> tuple[int, int]:
    """Generate Ed25519 keypair, skip if unsupported."""
    rs = p11_raw_session
    if not rs.has_mechanism("EDDSA"):
        pytest.skip("EDDSA mechanism not supported")

    try:
        pub, priv = _gen_ed25519(rs)
        return pub, priv
    except (AssertionError, OSError):
        pytest.skip("Ed25519 keygen not available")
        raise  # unreachable, satisfies mypy


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
        assert pub_kt == CKK_EC_EDWARDS
        assert priv_kt == CKK_EC_EDWARDS

    def test_ed25519_ec_params(
        self, p11_raw_session: Any, ed25519_keypair: tuple[int, int]
    ) -> None:
        """Ed25519 key should have correct EC params (OID)."""
        rs = p11_raw_session
        pub, _ = ed25519_keypair
        params = read_attributes(rs.raw, rs.sh, pub, [CKA_EC_PARAMS])[CKA_EC_PARAMS]
        assert params == ED25519_OID


class TestEdDSASignVerify:
    def test_sign_verify_roundtrip(
        self, p11_raw_session: Any, ed25519_keypair: tuple[int, int]
    ) -> None:
        """Sign and verify with Ed25519."""
        rs = p11_raw_session
        pub, priv = ed25519_keypair
        data = b"EdDSA sign-verify test data"

        signature = sign_single(rs.raw, rs.sh, priv, CKM_EDDSA, data)
        assert len(signature) == 64  # Ed25519 = 64 bytes

        result = verify_single(
            rs.raw,
            rs.sh,
            pub,
            CKM_EDDSA,
            data,
            signature,
        )
        assert result is True

    def test_wrong_data_fails(self, p11_raw_session: Any, ed25519_keypair: tuple[int, int]) -> None:
        """Verification with wrong data must fail."""
        rs = p11_raw_session
        pub, priv = ed25519_keypair

        sig = sign_single(
            rs.raw,
            rs.sh,
            priv,
            CKM_EDDSA,
            b"original data",
        )

        result = verify_single(
            rs.raw,
            rs.sh,
            pub,
            CKM_EDDSA,
            b"tampered data",
            sig,
        )
        assert result is False

    def test_signature_length(self, p11_raw_session: Any, ed25519_keypair: tuple[int, int]) -> None:
        """Ed25519 signatures are always exactly 64 bytes."""
        rs = p11_raw_session
        _, priv = ed25519_keypair
        for data in [b"", b"x", b"a" * 1000]:
            sig = sign_single(rs.raw, rs.sh, priv, CKM_EDDSA, data)
            assert len(sig) == 64

    def test_different_data_different_signatures(
        self, p11_raw_session: Any, ed25519_keypair: tuple[int, int]
    ) -> None:
        """Different messages produce different signatures."""
        rs = p11_raw_session
        _, priv = ed25519_keypair
        sig1 = sign_single(rs.raw, rs.sh, priv, CKM_EDDSA, b"message one")
        sig2 = sign_single(rs.raw, rs.sh, priv, CKM_EDDSA, b"message two")
        assert sig1 != sig2

    def test_deterministic_signatures(
        self, p11_raw_session: Any, ed25519_keypair: tuple[int, int]
    ) -> None:
        """Ed25519 signatures are deterministic (same key+data -> same sig)."""
        rs = p11_raw_session
        _, priv = ed25519_keypair
        data = b"determinism test"
        sig1 = sign_single(rs.raw, rs.sh, priv, CKM_EDDSA, data)
        sig2 = sign_single(rs.raw, rs.sh, priv, CKM_EDDSA, data)
        assert sig1 == sig2

    def test_different_keys_different_signatures(self, p11_raw_session: Any) -> None:
        """Same data signed with different Ed25519 keys gives different sigs."""
        rs = p11_raw_session
        if not rs.has_mechanism("EDDSA"):
            pytest.skip("EDDSA not supported")
        try:
            _, priv1 = _gen_ed25519(rs)
            _, priv2 = _gen_ed25519(rs)
        except (AssertionError, OSError):
            pytest.skip("Ed25519 keygen not available")
            raise  # unreachable

        data = b"key independence test"
        sig1 = sign_single(rs.raw, rs.sh, priv1, CKM_EDDSA, data)
        sig2 = sign_single(rs.raw, rs.sh, priv2, CKM_EDDSA, data)
        assert sig1 != sig2


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

        sig = sign_single(rs.raw, rs.sh, priv, CKM_EDDSA, data)

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
