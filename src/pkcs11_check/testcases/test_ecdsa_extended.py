"""Tests for ECDSA prehash sign/verify variants.

Covers CKM_ECDSA_SHA1, CKM_ECDSA_SHA224, and CKM_ECDSA_SHA3_* mechanisms.
Basic CKM_ECDSA (raw) is tested in test_sign.py.

OASIS spec: elliptic_curves.md
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pkcs11.util.ec
import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import FunctionFailed, SignatureInvalid, SignatureLenRange

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.sign

_ECDSA_HASH_MECHS = [
    pytest.param("ECDSA_SHA1", Mechanism.ECDSA_SHA1, id="SHA1"),
    pytest.param("ECDSA_SHA224", Mechanism.ECDSA_SHA224, id="SHA224"),
    pytest.param("ECDSA_SHA3_224", Mechanism.ECDSA_SHA3_224, id="SHA3-224"),
    pytest.param("ECDSA_SHA3_256", Mechanism.ECDSA_SHA3_256, id="SHA3-256"),
    pytest.param("ECDSA_SHA3_384", Mechanism.ECDSA_SHA3_384, id="SHA3-384"),
    pytest.param("ECDSA_SHA3_512", Mechanism.ECDSA_SHA3_512, id="SHA3-512"),
]

# Specific exceptions acceptable for tampered-data verification failure.
_VERIFY_FAIL_ERRORS = (SignatureInvalid, SignatureLenRange, FunctionFailed)


def _generate_ec_keypair(session: Any, curve: str = "secp256r1") -> tuple[Any, Any]:
    """Generate an EC key pair suitable for signing."""
    ecparams = session.create_domain_parameters(
        KeyType.EC,
        {Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters(curve)},
        local=True,
    )
    return ecparams.generate_keypair()  # type: ignore[no-any-return]


class TestECDSAPrehash:
    """ECDSA prehash sign/verify -- mechanism handles hashing internally."""

    @pytest.mark.parametrize(("mech_name", "mech"), _ECDSA_HASH_MECHS)
    def test_sign_verify_roundtrip(
        self,
        p11_session: Any,
        p11_module: Any,
        mech_name: str,
        mech: Mechanism,
    ) -> None:
        """Sign raw message data and verify succeeds."""
        if not has_mechanism(p11_module, mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")

        public, private = _generate_ec_keypair(p11_session)
        try:
            data = b"ECDSA prehash roundtrip test data"
            signature = private.sign(data, mechanism=mech)
            assert len(signature) > 0

            result = public.verify(data, signature, mechanism=mech)
            assert result is True
        finally:
            public.destroy()
            private.destroy()

    @pytest.mark.parametrize(("mech_name", "mech"), _ECDSA_HASH_MECHS)
    def test_tampered_data_fails(
        self,
        p11_session: Any,
        p11_module: Any,
        mech_name: str,
        mech: Mechanism,
    ) -> None:
        """Verify with wrong data must fail."""
        if not has_mechanism(p11_module, mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")

        public, private = _generate_ec_keypair(p11_session)
        try:
            original = b"original message for ECDSA"
            tampered = b"tampered message for ECDSA"

            sig = private.sign(original, mechanism=mech)
            try:
                result = public.verify(tampered, sig, mechanism=mech)
                # Some modules return False instead of raising.
                assert result is False, f"CKM_{mech_name}: verify with tampered data should fail"
            except _VERIFY_FAIL_ERRORS:
                pass  # Expected: verification correctly rejected
        finally:
            public.destroy()
            private.destroy()

    @pytest.mark.parametrize(("mech_name", "mech"), _ECDSA_HASH_MECHS)
    def test_nondeterministic(
        self,
        p11_session: Any,
        p11_module: Any,
        mech_name: str,
        mech: Mechanism,
    ) -> None:
        """Two signatures of the same data must differ (random nonce)."""
        if not has_mechanism(p11_module, mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")

        public, private = _generate_ec_keypair(p11_session)
        try:
            data = b"nonce uniqueness test for ECDSA prehash"
            sig1 = private.sign(data, mechanism=mech)
            sig2 = private.sign(data, mechanism=mech)
            assert sig1 != sig2, f"CKM_{mech_name}: two ECDSA signatures should differ (random k)"
        finally:
            public.destroy()
            private.destroy()
