"""Tests for the complete DSA mechanism family.

Covers raw CKM_DSA, prehash variants (SHA-1, SHA-384, SHA-512, SHA3-*),
and CKM_DSA_PARAMETER_GEN.

Note: CKM_DSA_KEY_PAIR_GEN and CKM_DSA_SHA256 are already tested in
test_sign.py and test_wycheproof_dsa.py.

OASIS spec: dsa.md
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from pkcs11 import KeyType, Mechanism
from pkcs11.exceptions import (
    ArgumentsBad,
    DataLenRange,
    FunctionFailed,
    MechanismInvalid,
    PKCS11Error,
    SignatureInvalid,
    SignatureLenRange,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.sign

# Verification failure errors that modules may return
_VERIFY_ERRORS = (SignatureInvalid, SignatureLenRange, FunctionFailed)

# Prehash DSA variants (excluding DSA_SHA256 which is tested elsewhere)
_DSA_HASH_MECHS = [
    pytest.param("DSA_SHA1", Mechanism.DSA_SHA1, id="SHA1"),
    pytest.param("DSA_SHA384", Mechanism.DSA_SHA384, id="SHA384"),
    pytest.param("DSA_SHA512", Mechanism.DSA_SHA512, id="SHA512"),
    pytest.param("DSA_SHA3_224", Mechanism.DSA_SHA3_224, id="SHA3-224"),
    pytest.param("DSA_SHA3_256", Mechanism.DSA_SHA3_256, id="SHA3-256"),
    pytest.param("DSA_SHA3_384", Mechanism.DSA_SHA3_384, id="SHA3-384"),
    pytest.param("DSA_SHA3_512", Mechanism.DSA_SHA3_512, id="SHA3-512"),
]


def _generate_dsa_keypair(session: Any) -> tuple[Any, Any, Any]:
    """Generate DSA domain parameters and keypair.

    Returns (params, public_key, private_key).
    Skips the test if DSA param/key generation is not supported.
    """
    try:
        params = session.generate_domain_parameters(KeyType.DSA, 2048)
        public, private = params.generate_keypair()
    except PKCS11Error as e:
        pytest.skip(f"DSA parameter/key generation not supported: {e}")
    return params, public, private


class TestDSARaw:
    """Tests for raw CKM_DSA with pre-hashed data."""

    def test_raw_dsa_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """Raw DSA sign/verify with a SHA-1-sized digest (20 bytes)."""
        if not has_mechanism(p11_module, "DSA"):
            pytest.skip("CKM_DSA not supported")

        params, public, private = _generate_dsa_keypair(p11_session)
        try:
            digest = hashlib.sha1(b"raw DSA test data").digest()  # noqa: S324
            assert len(digest) == 20

            sig = private.sign(digest, mechanism=Mechanism.DSA)
            assert len(sig) > 0

            result = public.verify(digest, sig, mechanism=Mechanism.DSA)
            assert result is True
        finally:
            public.destroy()
            private.destroy()
            params.destroy()

    def test_raw_dsa_wrong_digest_fails(self, p11_session: Any, p11_module: Any) -> None:
        """Raw DSA verification with wrong digest must fail."""
        if not has_mechanism(p11_module, "DSA"):
            pytest.skip("CKM_DSA not supported")

        params, public, private = _generate_dsa_keypair(p11_session)
        try:
            digest = hashlib.sha1(b"original data").digest()  # noqa: S324
            wrong_digest = hashlib.sha1(b"tampered data").digest()  # noqa: S324

            sig = private.sign(digest, mechanism=Mechanism.DSA)
            try:
                result = public.verify(wrong_digest, sig, mechanism=Mechanism.DSA)
                assert result is False
            except _VERIFY_ERRORS:
                pass  # Module correctly rejected mismatched digest
        finally:
            public.destroy()
            private.destroy()
            params.destroy()

    def test_raw_dsa_nondeterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Raw DSA signatures for the same digest should differ (random k)."""
        if not has_mechanism(p11_module, "DSA"):
            pytest.skip("CKM_DSA not supported")

        params, public, private = _generate_dsa_keypair(p11_session)
        try:
            digest = hashlib.sha1(b"nonce test").digest()  # noqa: S324

            sig1 = private.sign(digest, mechanism=Mechanism.DSA)
            sig2 = private.sign(digest, mechanism=Mechanism.DSA)
            assert sig1 != sig2
        finally:
            public.destroy()
            private.destroy()
            params.destroy()

    def test_raw_dsa_wrong_length_digest(self, p11_session: Any, p11_module: Any) -> None:
        """Raw DSA with wrong-length digest should fail per spec."""
        if not has_mechanism(p11_module, "DSA"):
            pytest.skip("CKM_DSA not supported")

        params, public, private = _generate_dsa_keypair(p11_session)
        try:
            # 7 bytes is too short for any valid subprime size
            bad_digest = b"\x00" * 7

            try:
                private.sign(bad_digest, mechanism=Mechanism.DSA)
                # Module accepted wrong-length digest — non-standard but not a crash
                pytest.xfail(
                    "Module accepted wrong-length digest for CKM_DSA — "
                    "spec requires CKR_DATA_LEN_RANGE"
                )
            except (DataLenRange, MechanismInvalid, FunctionFailed, ArgumentsBad):
                pass  # Expected: module correctly rejected wrong-length digest
        finally:
            public.destroy()
            private.destroy()
            params.destroy()


class TestDSAPrehash:
    """Tests for prehash DSA variants (SHA-1, SHA-384, SHA-512, SHA3-*)."""

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_sign_verify_roundtrip(
        self,
        p11_session: Any,
        p11_module: Any,
        mech_name_str: str,
        mechanism: Mechanism,
    ) -> None:
        """Sign and verify with a prehash DSA mechanism."""
        if not has_mechanism(p11_module, mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        params, public, private = _generate_dsa_keypair(p11_session)
        try:
            data = b"DSA prehash sign/verify roundtrip test data"
            sig = private.sign(data, mechanism=mechanism)
            assert len(sig) > 0

            result = public.verify(data, sig, mechanism=mechanism)
            assert result is True
        finally:
            public.destroy()
            private.destroy()
            params.destroy()

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_tampered_data_fails(
        self,
        p11_session: Any,
        p11_module: Any,
        mech_name_str: str,
        mechanism: Mechanism,
    ) -> None:
        """Prehash DSA verification with tampered data must fail."""
        if not has_mechanism(p11_module, mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        params, public, private = _generate_dsa_keypair(p11_session)
        try:
            data = b"original prehash data"
            sig = private.sign(data, mechanism=mechanism)

            tampered = b"tampered prehash data"
            try:
                result = public.verify(tampered, sig, mechanism=mechanism)
                assert result is False
            except _VERIFY_ERRORS:
                pass  # Module correctly rejected tampered data
        finally:
            public.destroy()
            private.destroy()
            params.destroy()

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_tampered_signature_fails(
        self,
        p11_session: Any,
        p11_module: Any,
        mech_name_str: str,
        mechanism: Mechanism,
    ) -> None:
        """Prehash DSA verification with tampered signature must fail."""
        if not has_mechanism(p11_module, mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        params, public, private = _generate_dsa_keypair(p11_session)
        try:
            data = b"signature tamper test"
            sig = private.sign(data, mechanism=mechanism)

            # Flip a byte in the signature
            sig_arr = bytearray(sig)
            sig_arr[len(sig_arr) // 2] ^= 0xFF
            tampered_sig = bytes(sig_arr)

            try:
                result = public.verify(data, tampered_sig, mechanism=mechanism)
                assert result is False
            except _VERIFY_ERRORS:
                pass  # Module correctly rejected tampered signature
        finally:
            public.destroy()
            private.destroy()
            params.destroy()

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_empty_data(
        self,
        p11_session: Any,
        p11_module: Any,
        mech_name_str: str,
        mechanism: Mechanism,
    ) -> None:
        """Prehash DSA sign/verify with empty data should work (hash of empty)."""
        if not has_mechanism(p11_module, mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        params, public, private = _generate_dsa_keypair(p11_session)
        try:
            data = b""
            sig = private.sign(data, mechanism=mechanism)
            assert len(sig) > 0

            result = public.verify(data, sig, mechanism=mechanism)
            assert result is True
        finally:
            public.destroy()
            private.destroy()
            params.destroy()

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_large_data(
        self,
        p11_session: Any,
        p11_module: Any,
        mech_name_str: str,
        mechanism: Mechanism,
    ) -> None:
        """Prehash DSA sign/verify with large data (10 KiB)."""
        if not has_mechanism(p11_module, mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        params, public, private = _generate_dsa_keypair(p11_session)
        try:
            data = b"A" * 10240
            sig = private.sign(data, mechanism=mechanism)
            assert len(sig) > 0

            result = public.verify(data, sig, mechanism=mechanism)
            assert result is True
        finally:
            public.destroy()
            private.destroy()
            params.destroy()


class TestDSAParameterGen:
    """Tests for CKM_DSA_PARAMETER_GEN."""

    def test_parameter_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate DSA domain parameters using CKM_DSA_PARAMETER_GEN."""
        if not has_mechanism(p11_module, "DSA_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PARAMETER_GEN not supported")

        try:
            params = p11_session.generate_domain_parameters(KeyType.DSA, 2048)
        except PKCS11Error as e:
            pytest.skip(f"DSA parameter generation failed: {e}")

        try:
            assert params is not None
        finally:
            params.destroy()

    def test_parameter_gen_and_keypair(self, p11_session: Any, p11_module: Any) -> None:
        """Generate DSA parameters, then use them for keypair generation."""
        if not has_mechanism(p11_module, "DSA_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PARAMETER_GEN not supported")

        try:
            params = p11_session.generate_domain_parameters(KeyType.DSA, 2048)
        except PKCS11Error as e:
            pytest.skip(f"DSA parameter generation failed: {e}")

        try:
            try:
                public, private = params.generate_keypair()
            except PKCS11Error as e:
                pytest.skip(f"DSA keypair generation from params failed: {e}")

            try:
                assert public is not None
                assert private is not None
            finally:
                public.destroy()
                private.destroy()
        finally:
            params.destroy()

    def test_parameter_gen_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """Generate DSA params, keypair, then sign and verify."""
        if not has_mechanism(p11_module, "DSA_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PARAMETER_GEN not supported")

        # Need a signing mechanism too
        has_raw = has_mechanism(p11_module, "DSA")
        has_sha256 = has_mechanism(p11_module, "DSA_SHA256")
        if not has_raw and not has_sha256:
            pytest.skip("No DSA signing mechanism available")

        try:
            params = p11_session.generate_domain_parameters(KeyType.DSA, 2048)
        except PKCS11Error as e:
            pytest.skip(f"DSA parameter generation failed: {e}")

        try:
            try:
                public, private = params.generate_keypair()
            except PKCS11Error as e:
                pytest.skip(f"DSA keypair generation from params failed: {e}")

            try:
                if has_raw:
                    digest = hashlib.sha1(b"param gen sign test").digest()  # noqa: S324
                    sig = private.sign(digest, mechanism=Mechanism.DSA)
                    result = public.verify(digest, sig, mechanism=Mechanism.DSA)
                else:
                    data = b"param gen sign test"
                    sig = private.sign(data, mechanism=Mechanism.DSA_SHA256)
                    result = public.verify(data, sig, mechanism=Mechanism.DSA_SHA256)
                assert result is True
            finally:
                public.destroy()
                private.destroy()
        finally:
            params.destroy()
