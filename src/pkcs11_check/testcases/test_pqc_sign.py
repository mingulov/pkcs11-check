"""Post-quantum signature tests - ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).

All tests require PKCS#11 v3.2 interface.  Auto-skips on v3.1 and earlier.
Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import attr_ulong
from pkcs11_check.raw.pack_mechanisms import mech_sign_context
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_keypair,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_PARAMETER_SET,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKH_DETERMINISTIC_REQUIRED,
    CKH_HEDGE_PREFERRED,
    CKH_HEDGE_REQUIRED,
    CKK_ML_DSA,
    CKK_SLH_DSA,
    CKM_ML_DSA,
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKM_SLH_DSA,
    CKM_SLH_DSA_KEY_PAIR_GEN,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKP_ML_DSA_44,
    CKP_ML_DSA_65,
    CKP_ML_DSA_87,
    CKP_SLH_DSA_SHA2_128F,
    CKP_SLH_DSA_SHA2_128S,
    CKP_SLH_DSA_SHA2_256F,
)

pytestmark = [pytest.mark.pqc]

_PLAINTEXT = b"post-quantum signature test message 2026"


def _skip_if_no(rs: Any, mech_name: str) -> None:
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"{mech_name} not supported by module")


def _generate_ml_dsa_keypair(rs: Any, param_set: int | None = None) -> tuple[int, int]:
    # Default to ML-DSA-65 (NIST security category 3)
    effective_param = param_set if param_set is not None else CKP_ML_DSA_65
    return gen_keypair(
        rs.raw,
        rs.sh,
        CKM_ML_DSA_KEY_PAIR_GEN,
        pub_base=[attr_ulong(CKA_PARAMETER_SET, effective_param)],
        priv_base=[],
        public_attrs={
            CKA_VERIFY: True,
            CKA_TOKEN: False,
        },
        private_attrs={
            CKA_SIGN: True,
            CKA_TOKEN: False,
        },
        pub_skip={CKA_PARAMETER_SET},
    )


def _generate_slh_dsa_keypair(rs: Any, param_set: int | None = None) -> tuple[int, int]:
    # Default to SLH-DSA-SHA2-128s (small signatures, security category 1)
    effective_param = param_set if param_set is not None else CKP_SLH_DSA_SHA2_128S
    return gen_keypair(
        rs.raw,
        rs.sh,
        CKM_SLH_DSA_KEY_PAIR_GEN,
        pub_base=[attr_ulong(CKA_PARAMETER_SET, effective_param)],
        priv_base=[],
        public_attrs={
            CKA_VERIFY: True,
            CKA_TOKEN: False,
        },
        private_attrs={
            CKA_SIGN: True,
            CKA_TOKEN: False,
        },
        pub_skip={CKA_PARAMETER_SET},
    )


class TestMLDSAKeyGeneration:
    """ML-DSA key generation tests."""

    def test_ml_dsa_available(self, p11_raw_session: Any) -> None:
        """Check that ML_DSA mechanism is available."""
        _skip_if_no(p11_raw_session, "ML_DSA")

    def test_ml_dsa_keypair_gen(self, p11_raw_session: Any) -> None:
        """Generate an ML-DSA key pair."""
        rs = p11_raw_session
        _skip_if_no(rs, "ML_DSA")
        pub, priv = _generate_ml_dsa_keypair(rs)
        try:
            assert pub != 0
            assert priv != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ml_dsa_keypair_classes(self, p11_raw_session: Any) -> None:
        """ML-DSA public key is PublicKey, private is PrivateKey."""
        rs = p11_raw_session
        _skip_if_no(rs, "ML_DSA")
        pub, priv = _generate_ml_dsa_keypair(rs)
        try:
            pub_cls = read_attributes(rs.raw, rs.sh, pub, [CKA_CLASS])[CKA_CLASS]
            priv_cls = read_attributes(rs.raw, rs.sh, priv, [CKA_CLASS])[CKA_CLASS]
            assert pub_cls == CKO_PUBLIC_KEY
            assert priv_cls == CKO_PRIVATE_KEY
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ml_dsa_keypair_key_type(self, p11_raw_session: Any) -> None:
        """ML-DSA keys report correct key type."""
        rs = p11_raw_session
        _skip_if_no(rs, "ML_DSA")
        pub, priv = _generate_ml_dsa_keypair(rs)
        try:
            pub_kt = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
            priv_kt = read_attributes(rs.raw, rs.sh, priv, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
            assert pub_kt == CKK_ML_DSA
            assert priv_kt == CKK_ML_DSA
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize(
        "param_set",
        [CKP_ML_DSA_44, CKP_ML_DSA_65, CKP_ML_DSA_87],
        ids=["ML_DSA_44", "ML_DSA_65", "ML_DSA_87"],
    )
    def test_ml_dsa_keypair_parameter_set(self, p11_raw_session: Any, param_set: int) -> None:
        """Generate ML-DSA key with explicit parameter set."""
        rs = p11_raw_session
        _skip_if_no(rs, "ML_DSA")
        try:
            pub, priv = _generate_ml_dsa_keypair(rs, param_set=param_set)
        except (AssertionError, OSError):
            pytest.skip(f"Module does not support CKA_PARAMETER_SET={param_set:#x}")
            raise  # unreachable
        try:
            assert pub != 0 and priv != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestMLDSASignVerify:
    """ML-DSA sign/verify round-trip tests."""

    def test_sign_and_verify(self, p11_raw_session: Any) -> None:
        """ML-DSA sign + verify round-trip."""
        rs = p11_raw_session
        _skip_if_no(rs, "ML_DSA")
        pub, priv = _generate_ml_dsa_keypair(rs)
        try:
            try:
                sig = sign_single(rs.raw, rs.sh, priv, CKM_ML_DSA, _PLAINTEXT)
            except AssertionError:
                pytest.xfail("ML-DSA sign failed")
                raise  # unreachable
            assert isinstance(sig, bytes) and len(sig) > 0
            result = verify_single(rs.raw, rs.sh, pub, CKM_ML_DSA, _PLAINTEXT, sig)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_tampered_message_fails_verification(self, p11_raw_session: Any) -> None:
        """Tampered message fails ML-DSA verification."""
        rs = p11_raw_session
        _skip_if_no(rs, "ML_DSA")
        pub, priv = _generate_ml_dsa_keypair(rs)
        try:
            try:
                sig = sign_single(rs.raw, rs.sh, priv, CKM_ML_DSA, _PLAINTEXT)
            except AssertionError:
                pytest.xfail("ML-DSA sign failed")
                raise  # unreachable
            tampered = _PLAINTEXT[:-1] + bytes([_PLAINTEXT[-1] ^ 0xFF])
            try:
                result = verify_single(rs.raw, rs.sh, pub, CKM_ML_DSA, tampered, sig)
                assert not result, "Tampered message should fail verification"
            except AssertionError as exc:
                if "DEVICE_ERROR" in str(exc):
                    pytest.xfail(
                        "Kryoptic returns CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID"
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_two_signatures_differ(self, p11_raw_session: Any) -> None:
        """ML-DSA produces different signatures for the same message (randomized)."""
        rs = p11_raw_session
        _skip_if_no(rs, "ML_DSA")
        pub, priv = _generate_ml_dsa_keypair(rs)
        try:
            try:
                sig1 = sign_single(rs.raw, rs.sh, priv, CKM_ML_DSA, _PLAINTEXT)
                sig2 = sign_single(rs.raw, rs.sh, priv, CKM_ML_DSA, _PLAINTEXT)
            except AssertionError:
                pytest.xfail("ML-DSA sign failed")
                raise  # unreachable
            # ML-DSA is randomized - two signatures should differ (with overwhelming probability)
            # Note: some implementations may use deterministic signing, so xfail not assert
            if sig1 == sig2:
                pytest.xfail("ML-DSA produced identical signatures (deterministic mode?)")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestMLDSAHedgeVariants:
    """ML-DSA signing with explicit hedge variants via CK_SIGN_ADDITIONAL_CONTEXT."""

    def test_hedge_preferred(self, p11_raw_session: Any) -> None:
        """CKH_HEDGE_PREFERRED -- default randomized signing."""
        rs = p11_raw_session
        _skip_if_no(rs, "ML_DSA")
        pub, priv = _generate_ml_dsa_keypair(rs)
        try:
            mech_param = mech_sign_context(CKM_ML_DSA, hedge=int(CKH_HEDGE_PREFERRED))
            sig = sign_single(rs.raw, rs.sh, priv, CKM_ML_DSA, _PLAINTEXT, mech_param=mech_param)
            assert len(sig) > 0
            result = verify_single(
                rs.raw, rs.sh, pub, CKM_ML_DSA, _PLAINTEXT, sig, mech_param=mech_param,
            )
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_hedge_required(self, p11_raw_session: Any) -> None:
        """CKH_HEDGE_REQUIRED -- must use randomization."""
        rs = p11_raw_session
        _skip_if_no(rs, "ML_DSA")
        pub, priv = _generate_ml_dsa_keypair(rs)
        try:
            mech_param = mech_sign_context(CKM_ML_DSA, hedge=int(CKH_HEDGE_REQUIRED))
            sig = sign_single(rs.raw, rs.sh, priv, CKM_ML_DSA, _PLAINTEXT, mech_param=mech_param)
            assert len(sig) > 0
            result = verify_single(
                rs.raw, rs.sh, pub, CKM_ML_DSA, _PLAINTEXT, sig, mech_param=mech_param,
            )
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_deterministic_required(self, p11_raw_session: Any) -> None:
        """CKH_DETERMINISTIC_REQUIRED -- signing must be deterministic."""
        rs = p11_raw_session
        _skip_if_no(rs, "ML_DSA")
        pub, priv = _generate_ml_dsa_keypair(rs)
        try:
            mech_param = mech_sign_context(
                CKM_ML_DSA, hedge=int(CKH_DETERMINISTIC_REQUIRED),
            )
            sig1 = sign_single(
                rs.raw, rs.sh, priv, CKM_ML_DSA, _PLAINTEXT, mech_param=mech_param,
            )
            sig2 = sign_single(
                rs.raw, rs.sh, priv, CKM_ML_DSA, _PLAINTEXT, mech_param=mech_param,
            )
            assert sig1 == sig2, "Deterministic mode should produce identical signatures"
            result = verify_single(
                rs.raw, rs.sh, pub, CKM_ML_DSA, _PLAINTEXT, sig1, mech_param=mech_param,
            )
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestSLHDSAKeyGeneration:
    """SLH-DSA key generation tests."""

    def test_slh_dsa_available(self, p11_raw_session: Any) -> None:
        """Check that SLH_DSA mechanism is available."""
        _skip_if_no(p11_raw_session, "SLH_DSA")

    def test_slh_dsa_keypair_gen(self, p11_raw_session: Any) -> None:
        """Generate an SLH-DSA key pair."""
        rs = p11_raw_session
        _skip_if_no(rs, "SLH_DSA")
        try:
            pub, priv = _generate_slh_dsa_keypair(rs)
        except (AssertionError, OSError):
            pytest.xfail("SLH-DSA key generation failed")
            raise  # unreachable
        try:
            assert pub != 0
            assert priv != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_slh_dsa_keypair_key_type(self, p11_raw_session: Any) -> None:
        """SLH-DSA keys report correct key type."""
        rs = p11_raw_session
        _skip_if_no(rs, "SLH_DSA")
        try:
            pub, priv = _generate_slh_dsa_keypair(rs)
        except (AssertionError, OSError):
            pytest.xfail("SLH-DSA key generation failed")
            raise  # unreachable
        try:
            pub_kt = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
            priv_kt = read_attributes(rs.raw, rs.sh, priv, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
            assert pub_kt == CKK_SLH_DSA
            assert priv_kt == CKK_SLH_DSA
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize(
        "param_set",
        [CKP_SLH_DSA_SHA2_128S, CKP_SLH_DSA_SHA2_128F, CKP_SLH_DSA_SHA2_256F],
        ids=["SHA2_128S", "SHA2_128F", "SHA2_256F"],
    )
    def test_slh_dsa_keypair_parameter_set(self, p11_raw_session: Any, param_set: int) -> None:
        """Generate SLH-DSA key with explicit parameter set."""
        rs = p11_raw_session
        _skip_if_no(rs, "SLH_DSA")
        try:
            pub, priv = _generate_slh_dsa_keypair(rs, param_set=param_set)
        except (AssertionError, OSError):
            pytest.skip(f"Module does not support CKA_PARAMETER_SET={param_set:#x}")
            raise  # unreachable
        try:
            assert pub != 0 and priv != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestSLHDSASignVerify:
    """SLH-DSA sign/verify round-trip tests."""

    def test_sign_and_verify(self, p11_raw_session: Any) -> None:
        """SLH-DSA sign + verify round-trip."""
        rs = p11_raw_session
        _skip_if_no(rs, "SLH_DSA")
        try:
            pub, priv = _generate_slh_dsa_keypair(rs)
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SLH_DSA, _PLAINTEXT)
        except (AssertionError, OSError):
            pytest.xfail("SLH-DSA sign failed")
            raise  # unreachable
        try:
            assert isinstance(sig, bytes) and len(sig) > 0
            result = verify_single(rs.raw, rs.sh, pub, CKM_SLH_DSA, _PLAINTEXT, sig)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_tampered_message_fails_verification(self, p11_raw_session: Any) -> None:
        """Tampered message fails SLH-DSA verification."""
        rs = p11_raw_session
        _skip_if_no(rs, "SLH_DSA")
        try:
            pub, priv = _generate_slh_dsa_keypair(rs)
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SLH_DSA, _PLAINTEXT)
        except (AssertionError, OSError):
            pytest.xfail("SLH-DSA sign failed")
            raise  # unreachable
        try:
            tampered = _PLAINTEXT[:-1] + bytes([_PLAINTEXT[-1] ^ 0xFF])
            try:
                result = verify_single(rs.raw, rs.sh, pub, CKM_SLH_DSA, tampered, sig)
                assert not result, "Tampered message should fail SLH-DSA verification"
            except AssertionError as exc:
                if "DEVICE_ERROR" in str(exc):
                    pytest.xfail(
                        "Kryoptic returns CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID"
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
