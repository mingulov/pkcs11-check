"""Stateful hash-based signature tests — HSS, XMSS, XMSS^MT (PKCS#11 v3.2).

Tests three stateful hash-based signature families per OASIS PKCS#11 v3.2:
- CKM_HSS_KEY_PAIR_GEN + CKM_HSS — Hierarchical Signature Scheme (RFC 8554)
- CKM_XMSS_KEY_PAIR_GEN + CKM_XMSS — eXtended Merkle Signature Scheme (RFC 8391)
- CKM_XMSSMT_KEY_PAIR_GEN + CKM_XMSSMT — XMSS Multi-Tree (RFC 8391)

IMPORTANT: These are stateful signatures — each signing operation consumes a
one-time key from a finite pool.  Tests sign minimally to avoid exhaustion.
Key generation can be very slow (minutes for large trees); smallest parameter
sets are used throughout.

All tests require PKCS#11 v3.2 interface.  Auto-skips on v3.1 and earlier.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import (
    DeviceError,
    FunctionFailed,
    MechanismInvalid,
    SignatureInvalid,
    TemplateIncomplete,
    TemplateInconsistent,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = [pytest.mark.pqc, pytest.mark.requires_v32]

_MESSAGE = b"stateful hash signature test message 2026"

# HSS LMS/LMOTS parameter values (from RFC 8554 / NIST SP 800-208).
# Use the smallest tree for fast keygen.
_LMS_SHA256_M32_H5 = 0x05  # LMS_SHA256_M32_H5: height 5, 32 signatures
_LMOTS_SHA256_N32_W8 = 0x04  # LMOTS_SHA256_N32_W8: Winternitz w=8

# XMSS parameter set OIDs (NIST SP 800-208, Table 11).
_XMSS_SHA2_10_256 = 0x00000001  # XMSS-SHA2_10_256: height 10

# XMSSMT parameter set OIDs (NIST SP 800-208, Table 12).
_XMSSMT_SHA2_20_2_256 = 0x00000001  # XMSSMT-SHA2_20/2_256

# Common keygen errors for stateful sigs — modules may reject templates.
_KEYGEN_ERRORS = (
    MechanismInvalid,
    FunctionFailed,
    DeviceError,
    TemplateIncomplete,
    TemplateInconsistent,
)


def _skip_if_no(p11_module: Any, mech_name: str) -> None:
    if not has_mechanism(p11_module, mech_name):
        pytest.skip(f"CKM_{mech_name} not supported by module")


def _destroy_pair(pub: Any, priv: Any) -> None:
    """Destroy a key pair, ignoring errors."""
    for key in (pub, priv):
        try:
            key.destroy()
        except Exception:
            pass


def _generate_hss_keypair(session: Any) -> tuple[Any, Any]:
    """Generate an HSS key pair with the smallest parameter set.

    HSS requires CKA_HSS_LEVELS, CKA_HSS_LMS_TYPES, and CKA_HSS_LMOTS_TYPES
    on the private key template.  The private key MUST be SENSITIVE=True,
    EXTRACTABLE=False, COPYABLE=False per the OASIS spec.
    """
    pub_tmpl: dict[Any, Any] = {
        Attribute.VERIFY: True,
        Attribute.TOKEN: False,
    }
    priv_tmpl: dict[Any, Any] = {
        Attribute.SIGN: True,
        Attribute.TOKEN: False,
        Attribute.SENSITIVE: True,
        Attribute.EXTRACTABLE: False,
        Attribute.HSS_LEVELS: 1,
        # Array attributes: one entry per level.
        Attribute.HSS_LMS_TYPES: [_LMS_SHA256_M32_H5],
        Attribute.HSS_LMOTS_TYPES: [_LMOTS_SHA256_N32_W8],
    }
    return session.generate_keypair(
        KeyType.HSS,
        mechanism=Mechanism.HSS_KEY_PAIR_GEN,
        public_template=pub_tmpl,
        private_template=priv_tmpl,
    )


def _generate_xmss_keypair(session: Any) -> tuple[Any, Any]:
    """Generate an XMSS key pair with XMSS-SHA2_10_256 (smallest)."""
    pub_tmpl: dict[Any, Any] = {
        Attribute.VERIFY: True,
        Attribute.PARAMETER_SET: _XMSS_SHA2_10_256,
        Attribute.TOKEN: False,
    }
    priv_tmpl: dict[Any, Any] = {
        Attribute.SIGN: True,
        Attribute.PARAMETER_SET: _XMSS_SHA2_10_256,
        Attribute.SENSITIVE: True,
        Attribute.EXTRACTABLE: False,
        Attribute.TOKEN: False,
    }
    return session.generate_keypair(
        KeyType.XMSS,
        mechanism=Mechanism.XMSS_KEY_PAIR_GEN,
        public_template=pub_tmpl,
        private_template=priv_tmpl,
    )


def _generate_xmssmt_keypair(session: Any) -> tuple[Any, Any]:
    """Generate an XMSS^MT key pair with XMSSMT-SHA2_20/2_256 (smallest)."""
    pub_tmpl: dict[Any, Any] = {
        Attribute.VERIFY: True,
        Attribute.PARAMETER_SET: _XMSSMT_SHA2_20_2_256,
        Attribute.TOKEN: False,
    }
    priv_tmpl: dict[Any, Any] = {
        Attribute.SIGN: True,
        Attribute.PARAMETER_SET: _XMSSMT_SHA2_20_2_256,
        Attribute.SENSITIVE: True,
        Attribute.EXTRACTABLE: False,
        Attribute.TOKEN: False,
    }
    return session.generate_keypair(
        KeyType.XMSSMT,
        mechanism=Mechanism.XMSSMT_KEY_PAIR_GEN,
        public_template=pub_tmpl,
        private_template=priv_tmpl,
    )


# ---------------------------------------------------------------------------
# HSS tests
# ---------------------------------------------------------------------------


class TestHSSKeyGeneration:
    """CKM_HSS_KEY_PAIR_GEN — HSS key generation (RFC 8554)."""

    def test_mechanism_available(self, p11_module: Any) -> None:
        """Check that CKM_HSS_KEY_PAIR_GEN is advertised by the module."""
        _skip_if_no(p11_module, "HSS_KEY_PAIR_GEN")

    def test_keypair_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an HSS key pair."""
        _skip_if_no(p11_module, "HSS_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_hss_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"HSS key generation failed: {exc!r}")
        try:
            assert pub is not None
            assert priv is not None
        finally:
            _destroy_pair(pub, priv)

    def test_keypair_key_type(self, p11_session: Any, p11_module: Any) -> None:
        """HSS keys report CKK_HSS key type."""
        _skip_if_no(p11_module, "HSS_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_hss_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"HSS key generation failed: {exc!r}")
        try:
            assert pub[Attribute.KEY_TYPE] == KeyType.HSS
            assert priv[Attribute.KEY_TYPE] == KeyType.HSS
        finally:
            _destroy_pair(pub, priv)

    def test_keypair_classes(self, p11_session: Any, p11_module: Any) -> None:
        """HSS public key is PUBLIC_KEY, private is PRIVATE_KEY."""
        _skip_if_no(p11_module, "HSS_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_hss_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"HSS key generation failed: {exc!r}")
        try:
            assert pub[Attribute.CLASS] == ObjectClass.PUBLIC_KEY
            assert priv[Attribute.CLASS] == ObjectClass.PRIVATE_KEY
        finally:
            _destroy_pair(pub, priv)

    def test_private_key_attributes(self, p11_session: Any, p11_module: Any) -> None:
        """HSS private key MUST be SENSITIVE, not EXTRACTABLE per spec."""
        _skip_if_no(p11_module, "HSS_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_hss_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"HSS key generation failed: {exc!r}")
        try:
            assert priv[Attribute.SENSITIVE] is True
            assert priv[Attribute.EXTRACTABLE] is False
        finally:
            _destroy_pair(pub, priv)


class TestHSSSignVerify:
    """CKM_HSS — HSS sign/verify (RFC 8554)."""

    def test_mechanism_available(self, p11_module: Any) -> None:
        """Check that CKM_HSS is advertised by the module."""
        _skip_if_no(p11_module, "HSS")

    def test_sign_verify_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """HSS sign + verify round-trip (single signature)."""
        _skip_if_no(p11_module, "HSS")
        _skip_if_no(p11_module, "HSS_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_hss_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"HSS key generation failed: {exc!r}")
        try:
            try:
                sig = priv.sign(_MESSAGE, mechanism=Mechanism.HSS)
            except (MechanismInvalid, FunctionFailed, DeviceError) as exc:
                pytest.xfail(f"HSS sign failed: {exc!r}")
            assert isinstance(sig, bytes) and len(sig) > 0
            assert pub.verify(_MESSAGE, sig, mechanism=Mechanism.HSS)
        finally:
            _destroy_pair(pub, priv)

    def test_tampered_message_fails(self, p11_session: Any, p11_module: Any) -> None:
        """Tampered message must fail HSS verification."""
        _skip_if_no(p11_module, "HSS")
        _skip_if_no(p11_module, "HSS_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_hss_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"HSS key generation failed: {exc!r}")
        try:
            try:
                sig = priv.sign(_MESSAGE, mechanism=Mechanism.HSS)
            except (MechanismInvalid, FunctionFailed, DeviceError) as exc:
                pytest.xfail(f"HSS sign failed: {exc!r}")
            tampered = _MESSAGE[:-1] + bytes([_MESSAGE[-1] ^ 0xFF])
            try:
                result = pub.verify(tampered, sig, mechanism=Mechanism.HSS)
                assert not result, "Tampered message should fail HSS verification"
            except SignatureInvalid:
                pass  # Correct PKCS#11 behavior
            except DeviceError:
                pytest.xfail("Module returns CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID")
        finally:
            _destroy_pair(pub, priv)


# ---------------------------------------------------------------------------
# XMSS tests
# ---------------------------------------------------------------------------


class TestXMSSKeyGeneration:
    """CKM_XMSS_KEY_PAIR_GEN — XMSS key generation (RFC 8391)."""

    def test_mechanism_available(self, p11_module: Any) -> None:
        """Check that CKM_XMSS_KEY_PAIR_GEN is advertised by the module."""
        _skip_if_no(p11_module, "XMSS_KEY_PAIR_GEN")

    def test_keypair_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an XMSS key pair."""
        _skip_if_no(p11_module, "XMSS_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_xmss_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"XMSS key generation failed: {exc!r}")
        try:
            assert pub is not None
            assert priv is not None
        finally:
            _destroy_pair(pub, priv)

    def test_keypair_key_type(self, p11_session: Any, p11_module: Any) -> None:
        """XMSS keys report CKK_XMSS key type."""
        _skip_if_no(p11_module, "XMSS_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_xmss_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"XMSS key generation failed: {exc!r}")
        try:
            assert pub[Attribute.KEY_TYPE] == KeyType.XMSS
            assert priv[Attribute.KEY_TYPE] == KeyType.XMSS
        finally:
            _destroy_pair(pub, priv)

    def test_keypair_classes(self, p11_session: Any, p11_module: Any) -> None:
        """XMSS public key is PUBLIC_KEY, private is PRIVATE_KEY."""
        _skip_if_no(p11_module, "XMSS_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_xmss_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"XMSS key generation failed: {exc!r}")
        try:
            assert pub[Attribute.CLASS] == ObjectClass.PUBLIC_KEY
            assert priv[Attribute.CLASS] == ObjectClass.PRIVATE_KEY
        finally:
            _destroy_pair(pub, priv)

    def test_private_key_attributes(self, p11_session: Any, p11_module: Any) -> None:
        """XMSS private key MUST be SENSITIVE, not EXTRACTABLE per spec."""
        _skip_if_no(p11_module, "XMSS_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_xmss_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"XMSS key generation failed: {exc!r}")
        try:
            assert priv[Attribute.SENSITIVE] is True
            assert priv[Attribute.EXTRACTABLE] is False
        finally:
            _destroy_pair(pub, priv)


class TestXMSSSignVerify:
    """CKM_XMSS — XMSS sign/verify (RFC 8391)."""

    def test_mechanism_available(self, p11_module: Any) -> None:
        """Check that CKM_XMSS is advertised by the module."""
        _skip_if_no(p11_module, "XMSS")

    def test_sign_verify_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """XMSS sign + verify round-trip (single signature)."""
        _skip_if_no(p11_module, "XMSS")
        _skip_if_no(p11_module, "XMSS_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_xmss_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"XMSS key generation failed: {exc!r}")
        try:
            try:
                sig = priv.sign(_MESSAGE, mechanism=Mechanism.XMSS)
            except (MechanismInvalid, FunctionFailed, DeviceError) as exc:
                pytest.xfail(f"XMSS sign failed: {exc!r}")
            assert isinstance(sig, bytes) and len(sig) > 0
            assert pub.verify(_MESSAGE, sig, mechanism=Mechanism.XMSS)
        finally:
            _destroy_pair(pub, priv)

    def test_tampered_message_fails(self, p11_session: Any, p11_module: Any) -> None:
        """Tampered message must fail XMSS verification."""
        _skip_if_no(p11_module, "XMSS")
        _skip_if_no(p11_module, "XMSS_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_xmss_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"XMSS key generation failed: {exc!r}")
        try:
            try:
                sig = priv.sign(_MESSAGE, mechanism=Mechanism.XMSS)
            except (MechanismInvalid, FunctionFailed, DeviceError) as exc:
                pytest.xfail(f"XMSS sign failed: {exc!r}")
            tampered = _MESSAGE[:-1] + bytes([_MESSAGE[-1] ^ 0xFF])
            try:
                result = pub.verify(tampered, sig, mechanism=Mechanism.XMSS)
                assert not result, "Tampered message should fail XMSS verification"
            except SignatureInvalid:
                pass  # Correct PKCS#11 behavior
            except DeviceError:
                pytest.xfail("Module returns CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID")
        finally:
            _destroy_pair(pub, priv)


# ---------------------------------------------------------------------------
# XMSS^MT tests
# ---------------------------------------------------------------------------


class TestXMSSMTKeyGeneration:
    """CKM_XMSSMT_KEY_PAIR_GEN — XMSS^MT key generation (RFC 8391)."""

    def test_mechanism_available(self, p11_module: Any) -> None:
        """Check that CKM_XMSSMT_KEY_PAIR_GEN is advertised by the module."""
        _skip_if_no(p11_module, "XMSSMT_KEY_PAIR_GEN")

    def test_keypair_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an XMSS^MT key pair."""
        _skip_if_no(p11_module, "XMSSMT_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_xmssmt_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"XMSS^MT key generation failed: {exc!r}")
        try:
            assert pub is not None
            assert priv is not None
        finally:
            _destroy_pair(pub, priv)

    def test_keypair_key_type(self, p11_session: Any, p11_module: Any) -> None:
        """XMSS^MT keys report CKK_XMSSMT key type."""
        _skip_if_no(p11_module, "XMSSMT_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_xmssmt_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"XMSS^MT key generation failed: {exc!r}")
        try:
            assert pub[Attribute.KEY_TYPE] == KeyType.XMSSMT
            assert priv[Attribute.KEY_TYPE] == KeyType.XMSSMT
        finally:
            _destroy_pair(pub, priv)

    def test_keypair_classes(self, p11_session: Any, p11_module: Any) -> None:
        """XMSS^MT public key is PUBLIC_KEY, private is PRIVATE_KEY."""
        _skip_if_no(p11_module, "XMSSMT_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_xmssmt_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"XMSS^MT key generation failed: {exc!r}")
        try:
            assert pub[Attribute.CLASS] == ObjectClass.PUBLIC_KEY
            assert priv[Attribute.CLASS] == ObjectClass.PRIVATE_KEY
        finally:
            _destroy_pair(pub, priv)

    def test_private_key_attributes(self, p11_session: Any, p11_module: Any) -> None:
        """XMSS^MT private key MUST be SENSITIVE, not EXTRACTABLE per spec."""
        _skip_if_no(p11_module, "XMSSMT_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_xmssmt_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"XMSS^MT key generation failed: {exc!r}")
        try:
            assert priv[Attribute.SENSITIVE] is True
            assert priv[Attribute.EXTRACTABLE] is False
        finally:
            _destroy_pair(pub, priv)


class TestXMSSMTSignVerify:
    """CKM_XMSSMT — XMSS^MT sign/verify (RFC 8391)."""

    def test_mechanism_available(self, p11_module: Any) -> None:
        """Check that CKM_XMSSMT is advertised by the module."""
        _skip_if_no(p11_module, "XMSSMT")

    def test_sign_verify_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """XMSS^MT sign + verify round-trip (single signature)."""
        _skip_if_no(p11_module, "XMSSMT")
        _skip_if_no(p11_module, "XMSSMT_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_xmssmt_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"XMSS^MT key generation failed: {exc!r}")
        try:
            try:
                sig = priv.sign(_MESSAGE, mechanism=Mechanism.XMSSMT)
            except (MechanismInvalid, FunctionFailed, DeviceError) as exc:
                pytest.xfail(f"XMSS^MT sign failed: {exc!r}")
            assert isinstance(sig, bytes) and len(sig) > 0
            assert pub.verify(_MESSAGE, sig, mechanism=Mechanism.XMSSMT)
        finally:
            _destroy_pair(pub, priv)

    def test_tampered_message_fails(self, p11_session: Any, p11_module: Any) -> None:
        """Tampered message must fail XMSS^MT verification."""
        _skip_if_no(p11_module, "XMSSMT")
        _skip_if_no(p11_module, "XMSSMT_KEY_PAIR_GEN")
        try:
            pub, priv = _generate_xmssmt_keypair(p11_session)
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"XMSS^MT key generation failed: {exc!r}")
        try:
            try:
                sig = priv.sign(_MESSAGE, mechanism=Mechanism.XMSSMT)
            except (MechanismInvalid, FunctionFailed, DeviceError) as exc:
                pytest.xfail(f"XMSS^MT sign failed: {exc!r}")
            tampered = _MESSAGE[:-1] + bytes([_MESSAGE[-1] ^ 0xFF])
            try:
                result = pub.verify(tampered, sig, mechanism=Mechanism.XMSSMT)
                assert not result, "Tampered message should fail XMSS^MT verification"
            except SignatureInvalid:
                pass  # Correct PKCS#11 behavior
            except DeviceError:
                pytest.xfail("Module returns CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID")
        finally:
            _destroy_pair(pub, priv)
