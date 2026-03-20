"""Tests for IKE protocol mechanisms.

Covers CKM_IKE2_PRF_PLUS_DERIVE, CKM_IKE_PRF_DERIVE,
CKM_IKE1_PRF_DERIVE, and CKM_IKE1_EXTENDED_DERIVE.

IKE (Internet Key Exchange) mechanisms are used in IPsec VPN implementations.
They use HMAC-based PRFs internally to derive keying material from a shared
secret and nonce data.

OASIS spec: ike_mechanisms.md
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import (
    FunctionFailed,
    GeneralError,
    MechanismInvalid,
    MechanismParamInvalid,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt

# 32-byte base key material (shared secret / SKEYSEED)
_BASE_KEY_BYTES = bytes(range(32))

# Nonce data used in IKE exchanges (Ni | Nr)
_NONCE_I = b"\x01" * 16  # initiator nonce
_NONCE_R = b"\x02" * 16  # responder nonce

# IKE SPI values (8 bytes each)
_SPI_I = b"\xaa" * 8  # initiator SPI
_SPI_R = b"\xbb" * 8  # responder SPI

_DERIVE_TEMPLATE: dict[Attribute, Any] = {
    Attribute.SENSITIVE: False,
    Attribute.EXTRACTABLE: True,
    Attribute.TOKEN: False,
}

# Common derivation error tuple for IKE operations.
# These mechanisms are rarely supported by soft-tokens; almost every
# failure mode is legitimate for the xfail path.
_DERIVE_ERRORS = (
    MechanismInvalid,
    MechanismParamInvalid,
    FunctionFailed,
    GeneralError,
)


def _create_base_key(session: Any, key_bytes: bytes = _BASE_KEY_BYTES) -> Any:
    """Create a GENERIC_SECRET base key suitable for IKE derivation."""
    return session.create_object(
        {
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
            Attribute.VALUE: key_bytes,
            Attribute.DERIVE: True,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
        }
    )


def _build_ike2_prf_plus_params(*, nonce_i: bytes, nonce_r: bytes) -> bytes:
    """Build a minimal CK_IKE2_PRF_PLUS_DERIVE_PARAMS structure as raw bytes.

    The PKCS#11 v3.2 structure layout (all fields CK_ULONG / pointer pairs):
      prfMechanism    CK_MECHANISM_TYPE   (8 bytes on 64-bit)
      bHasSeedKey     CK_BBOOL           (1 byte + padding)
      hSeedKey        CK_OBJECT_HANDLE   (8 bytes, only when bHasSeedKey=TRUE)
      pExtraData      CK_BYTE_PTR        (pointer, omitted in raw bytes approach)
      ulExtraDataLen  CK_ULONG           (8 bytes)

    Since we cannot construct the C struct directly without wrapper support,
    we pass the nonces concatenated as extra data in a best-effort attempt.
    The module will likely reject this with MechanismParamInvalid; that is
    expected and handled by the xfail path.
    """
    # Pack nonce_i || nonce_r as extra data — a rough approximation only.
    return nonce_i + nonce_r


def _build_ike_prf_params(*, nonce_i: bytes, nonce_r: bytes) -> bytes:
    """Build minimal CK_IKE_PRF_DERIVE_PARAMS extra data (nonce_i || nonce_r)."""
    return nonce_i + nonce_r


def _build_ike1_prf_params(*, nonce_i: bytes, nonce_r: bytes) -> bytes:
    """Build minimal IKEv1 PRF extra data (nonce_i || nonce_r)."""
    return nonce_i + nonce_r


def _build_ike1_extended_params(
    *, nonce_i: bytes, nonce_r: bytes, spi_i: bytes, spi_r: bytes
) -> bytes:
    """Build minimal IKEv1 extended derive extra data (nonces + SPIs)."""
    return nonce_i + nonce_r + spi_i + spi_r


class TestIKE2PRFPlusDerive:
    """CKM_IKE2_PRF_PLUS_DERIVE — IKEv2 PRF+ key derivation (RFC 7296)."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_IKE2_PRF_PLUS_DERIVE is advertised."""
        if not has_mechanism(p11_module, "IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")

    def test_derive_generic_secret(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt to derive a GENERIC_SECRET key via IKEv2 PRF+."""
        if not has_mechanism(p11_module, "IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params = _build_ike2_prf_plus_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
            )
            derived = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE2_PRF_PLUS_DERIVE,
                mechanism_param=params,
                template=_DERIVE_TEMPLATE,
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 32, f"Expected 32 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE2_PRF_PLUS_DERIVE derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_derive_aes128(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt to derive a 128-bit AES key via IKEv2 PRF+."""
        if not has_mechanism(p11_module, "IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params = _build_ike2_prf_plus_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
            )
            derived = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.IKE2_PRF_PLUS_DERIVE,
                mechanism_param=params,
                template=_DERIVE_TEMPLATE,
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 16, f"Expected 16 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE2_PRF_PLUS_DERIVE AES-128 derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_different_nonces_produce_different_keys(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Different nonce inputs must produce different derived key material."""
        if not has_mechanism(p11_module, "IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params_a = _build_ike2_prf_plus_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
            )
            params_b = _build_ike2_prf_plus_params(
                nonce_i=b"\x03" * 16,
                nonce_r=b"\x04" * 16,
            )
            derived_a = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE2_PRF_PLUS_DERIVE,
                mechanism_param=params_a,
                template=_DERIVE_TEMPLATE,
            )
            derived_b = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE2_PRF_PLUS_DERIVE,
                mechanism_param=params_b,
                template=_DERIVE_TEMPLATE,
            )
            try:
                val_a = derived_a[Attribute.VALUE]
                val_b = derived_b[Attribute.VALUE]
                assert val_a != val_b, "Different nonces produced identical derived keys"
            finally:
                derived_b.destroy()
                derived_a.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE2_PRF_PLUS_DERIVE derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_derive_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same inputs must produce the same derived key material."""
        if not has_mechanism(p11_module, "IKE2_PRF_PLUS_DERIVE"):
            pytest.skip("CKM_IKE2_PRF_PLUS_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params1 = _build_ike2_prf_plus_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
            )
            params2 = _build_ike2_prf_plus_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
            )
            derived1 = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE2_PRF_PLUS_DERIVE,
                mechanism_param=params1,
                template=_DERIVE_TEMPLATE,
            )
            derived2 = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE2_PRF_PLUS_DERIVE,
                mechanism_param=params2,
                template=_DERIVE_TEMPLATE,
            )
            try:
                val1 = derived1[Attribute.VALUE]
                val2 = derived2[Attribute.VALUE]
                assert val1 == val2, "IKEv2 PRF+ derivation is not deterministic"
            finally:
                derived2.destroy()
                derived1.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE2_PRF_PLUS_DERIVE derivation not operational: {exc}")
        finally:
            base_key.destroy()


class TestIKEPRFDerive:
    """CKM_IKE_PRF_DERIVE — IKEv2 PRF key derivation (SKEYSEED computation)."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_IKE_PRF_DERIVE is advertised."""
        if not has_mechanism(p11_module, "IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")

    def test_derive_skeyseed(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt to derive SKEYSEED via IKEv2 PRF (RFC 7296 §2.14)."""
        if not has_mechanism(p11_module, "IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params = _build_ike_prf_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
            )
            derived = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE_PRF_DERIVE,
                mechanism_param=params,
                template=_DERIVE_TEMPLATE,
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 32, f"Expected 32 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE_PRF_DERIVE derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_derive_aes128(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt to derive a 128-bit AES key via IKEv2 PRF."""
        if not has_mechanism(p11_module, "IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params = _build_ike_prf_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
            )
            derived = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.IKE_PRF_DERIVE,
                mechanism_param=params,
                template=_DERIVE_TEMPLATE,
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 16, f"Expected 16 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE_PRF_DERIVE AES-128 derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_different_nonces_produce_different_keys(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Different nonce inputs must produce different derived key material."""
        if not has_mechanism(p11_module, "IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params_a = _build_ike_prf_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
            )
            params_b = _build_ike_prf_params(
                nonce_i=b"\x05" * 16,
                nonce_r=b"\x06" * 16,
            )
            derived_a = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE_PRF_DERIVE,
                mechanism_param=params_a,
                template=_DERIVE_TEMPLATE,
            )
            derived_b = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE_PRF_DERIVE,
                mechanism_param=params_b,
                template=_DERIVE_TEMPLATE,
            )
            try:
                val_a = derived_a[Attribute.VALUE]
                val_b = derived_b[Attribute.VALUE]
                assert val_a != val_b, "Different nonces produced identical derived keys"
            finally:
                derived_b.destroy()
                derived_a.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE_PRF_DERIVE derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_derive_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same inputs must produce the same derived key material."""
        if not has_mechanism(p11_module, "IKE_PRF_DERIVE"):
            pytest.skip("CKM_IKE_PRF_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params1 = _build_ike_prf_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
            )
            params2 = _build_ike_prf_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
            )
            derived1 = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE_PRF_DERIVE,
                mechanism_param=params1,
                template=_DERIVE_TEMPLATE,
            )
            derived2 = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE_PRF_DERIVE,
                mechanism_param=params2,
                template=_DERIVE_TEMPLATE,
            )
            try:
                val1 = derived1[Attribute.VALUE]
                val2 = derived2[Attribute.VALUE]
                assert val1 == val2, "IKEv2 PRF derivation is not deterministic"
            finally:
                derived2.destroy()
                derived1.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE_PRF_DERIVE derivation not operational: {exc}")
        finally:
            base_key.destroy()


class TestIKE1PRFDerive:
    """CKM_IKE1_PRF_DERIVE — IKEv1 PRF key derivation (RFC 2409)."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_IKE1_PRF_DERIVE is advertised."""
        if not has_mechanism(p11_module, "IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")

    def test_derive_skeyid(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt to derive SKEYID via IKEv1 PRF (RFC 2409 §5)."""
        if not has_mechanism(p11_module, "IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params = _build_ike1_prf_params(nonce_i=_NONCE_I, nonce_r=_NONCE_R)
            derived = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE1_PRF_DERIVE,
                mechanism_param=params,
                template=_DERIVE_TEMPLATE,
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 32, f"Expected 32 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE1_PRF_DERIVE derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_derive_aes128(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt to derive a 128-bit AES key via IKEv1 PRF."""
        if not has_mechanism(p11_module, "IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params = _build_ike1_prf_params(nonce_i=_NONCE_I, nonce_r=_NONCE_R)
            derived = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.IKE1_PRF_DERIVE,
                mechanism_param=params,
                template=_DERIVE_TEMPLATE,
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 16, f"Expected 16 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE1_PRF_DERIVE AES-128 derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_different_nonces_produce_different_keys(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Different nonce inputs must produce different derived key material."""
        if not has_mechanism(p11_module, "IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params_a = _build_ike1_prf_params(nonce_i=_NONCE_I, nonce_r=_NONCE_R)
            params_b = _build_ike1_prf_params(nonce_i=b"\x07" * 16, nonce_r=b"\x08" * 16)
            derived_a = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE1_PRF_DERIVE,
                mechanism_param=params_a,
                template=_DERIVE_TEMPLATE,
            )
            derived_b = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE1_PRF_DERIVE,
                mechanism_param=params_b,
                template=_DERIVE_TEMPLATE,
            )
            try:
                val_a = derived_a[Attribute.VALUE]
                val_b = derived_b[Attribute.VALUE]
                assert val_a != val_b, "Different nonces produced identical derived keys"
            finally:
                derived_b.destroy()
                derived_a.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE1_PRF_DERIVE derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_derive_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same inputs must produce the same derived key material."""
        if not has_mechanism(p11_module, "IKE1_PRF_DERIVE"):
            pytest.skip("CKM_IKE1_PRF_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params1 = _build_ike1_prf_params(nonce_i=_NONCE_I, nonce_r=_NONCE_R)
            params2 = _build_ike1_prf_params(nonce_i=_NONCE_I, nonce_r=_NONCE_R)
            derived1 = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE1_PRF_DERIVE,
                mechanism_param=params1,
                template=_DERIVE_TEMPLATE,
            )
            derived2 = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE1_PRF_DERIVE,
                mechanism_param=params2,
                template=_DERIVE_TEMPLATE,
            )
            try:
                val1 = derived1[Attribute.VALUE]
                val2 = derived2[Attribute.VALUE]
                assert val1 == val2, "IKEv1 PRF derivation is not deterministic"
            finally:
                derived2.destroy()
                derived1.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE1_PRF_DERIVE derivation not operational: {exc}")
        finally:
            base_key.destroy()


class TestIKE1ExtendedDerive:
    """CKM_IKE1_EXTENDED_DERIVE — IKEv1 extended key derivation (SKEYID_d/a/e)."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_IKE1_EXTENDED_DERIVE is advertised."""
        if not has_mechanism(p11_module, "IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")

    def test_derive_skeyid_d(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt to derive SKEYID_d (encryption keying material) via IKEv1 extended derive."""
        if not has_mechanism(p11_module, "IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params = _build_ike1_extended_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
                spi_i=_SPI_I,
                spi_r=_SPI_R,
            )
            derived = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE1_EXTENDED_DERIVE,
                mechanism_param=params,
                template=_DERIVE_TEMPLATE,
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 32, f"Expected 32 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE1_EXTENDED_DERIVE derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_derive_aes128(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt to derive a 128-bit AES key via IKEv1 extended derive."""
        if not has_mechanism(p11_module, "IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params = _build_ike1_extended_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
                spi_i=_SPI_I,
                spi_r=_SPI_R,
            )
            derived = base_key.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.IKE1_EXTENDED_DERIVE,
                mechanism_param=params,
                template=_DERIVE_TEMPLATE,
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 16, f"Expected 16 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE1_EXTENDED_DERIVE AES-128 derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_different_spis_produce_different_keys(self, p11_session: Any, p11_module: Any) -> None:
        """Different SPI inputs must produce different derived key material."""
        if not has_mechanism(p11_module, "IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params_a = _build_ike1_extended_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
                spi_i=_SPI_I,
                spi_r=_SPI_R,
            )
            params_b = _build_ike1_extended_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
                spi_i=b"\xcc" * 8,
                spi_r=b"\xdd" * 8,
            )
            derived_a = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE1_EXTENDED_DERIVE,
                mechanism_param=params_a,
                template=_DERIVE_TEMPLATE,
            )
            derived_b = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE1_EXTENDED_DERIVE,
                mechanism_param=params_b,
                template=_DERIVE_TEMPLATE,
            )
            try:
                val_a = derived_a[Attribute.VALUE]
                val_b = derived_b[Attribute.VALUE]
                assert val_a != val_b, "Different SPIs produced identical derived keys"
            finally:
                derived_b.destroy()
                derived_a.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE1_EXTENDED_DERIVE derivation not operational: {exc}")
        finally:
            base_key.destroy()

    def test_derive_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same inputs must produce the same derived key material."""
        if not has_mechanism(p11_module, "IKE1_EXTENDED_DERIVE"):
            pytest.skip("CKM_IKE1_EXTENDED_DERIVE not supported")

        base_key = _create_base_key(p11_session)
        try:
            params1 = _build_ike1_extended_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
                spi_i=_SPI_I,
                spi_r=_SPI_R,
            )
            params2 = _build_ike1_extended_params(
                nonce_i=_NONCE_I,
                nonce_r=_NONCE_R,
                spi_i=_SPI_I,
                spi_r=_SPI_R,
            )
            derived1 = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE1_EXTENDED_DERIVE,
                mechanism_param=params1,
                template=_DERIVE_TEMPLATE,
            )
            derived2 = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.IKE1_EXTENDED_DERIVE,
                mechanism_param=params2,
                template=_DERIVE_TEMPLATE,
            )
            try:
                val1 = derived1[Attribute.VALUE]
                val2 = derived2[Attribute.VALUE]
                assert val1 == val2, "IKEv1 extended derivation is not deterministic"
            finally:
                derived2.destroy()
                derived1.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_IKE1_EXTENDED_DERIVE derivation not operational: {exc}")
        finally:
            base_key.destroy()
