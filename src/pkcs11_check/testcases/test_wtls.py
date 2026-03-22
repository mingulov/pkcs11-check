"""Tests for WTLS protocol mechanisms.

Covers CKM_WTLS_PRE_MASTER_KEY_GEN, CKM_WTLS_MASTER_KEY_DERIVE,
CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC, CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE, and CKM_WTLS_PRF.

WTLS (Wireless Transport Layer Security) is a legacy protocol from the WAP
specification. These mechanisms are rarely supported by modern tokens and tests
will mostly skip. The mechanism parameters (CK_WTLS_RANDOM_DATA,
CK_WTLS_MASTER_KEY_DERIVE_PARAMS, etc.) have no wrapper classes in python-pkcs11,
so derive operations are attempted with no parameter and expected to fail.

OASIS spec: wtls.md
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

# Common error tuple for WTLS operations -- no parameter wrapper available,
# so any of these may be returned when the mechanism is invoked.
_WTLS_ERRORS = (
    MechanismInvalid,
    MechanismParamInvalid,
    FunctionFailed,
    GeneralError,
)

_DERIVE_TEMPLATE: dict[Attribute, Any] = {
    Attribute.SENSITIVE: False,
    Attribute.EXTRACTABLE: True,
    Attribute.TOKEN: False,
}


def _create_generic_secret(session: Any, size: int = 48) -> Any:
    """Create a GENERIC_SECRET key for use as WTLS pre-master secret material."""
    return session.create_object(
        {
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
            Attribute.VALUE: bytes(range(size % 256)) * (size // 256 + 1),
            Attribute.VALUE_LEN: size,
            Attribute.DERIVE: True,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        }
    )


class TestWTLSPreMasterKeyGen:
    """CKM_WTLS_PRE_MASTER_KEY_GEN -- generate a WTLS pre-master secret."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_WTLS_PRE_MASTER_KEY_GEN is advertised."""
        if not has_mechanism(p11_module, "WTLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_WTLS_PRE_MASTER_KEY_GEN not supported")

    def test_generate_pre_master_key(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a WTLS pre-master secret key."""
        if not has_mechanism(p11_module, "WTLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_WTLS_PRE_MASTER_KEY_GEN not supported")

        # WTLS pre-master key length is 20 bytes per the WTLS spec.
        # The mechanism requires a CK_WTLS_PRE_MASTER_SECRET_PARAMS parameter
        # with the WTLS version; without the wrapper we attempt without params
        # and expect a spec-conforming error.
        try:
            key = p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                160,  # 20 bytes = 160 bits
                mechanism=Mechanism.WTLS_PRE_MASTER_KEY_GEN,
                template={
                    Attribute.DERIVE: True,
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                assert key is not None
                assert key[Attribute.KEY_TYPE] == KeyType.GENERIC_SECRET
            finally:
                key.destroy()
        except _WTLS_ERRORS as exc:
            pytest.xfail(f"CKM_WTLS_PRE_MASTER_KEY_GEN not operational: {exc}")

    def test_generate_yields_non_zero_material(self, p11_session: Any, p11_module: Any) -> None:
        """Generated pre-master key must not be all-zero bytes."""
        if not has_mechanism(p11_module, "WTLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_WTLS_PRE_MASTER_KEY_GEN not supported")

        try:
            key = p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                160,
                mechanism=Mechanism.WTLS_PRE_MASTER_KEY_GEN,
                template={
                    Attribute.DERIVE: True,
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                value = key[Attribute.VALUE]
                assert value != bytes(len(value)), "Pre-master key must not be all zeros"
            finally:
                key.destroy()
        except _WTLS_ERRORS as exc:
            pytest.xfail(f"CKM_WTLS_PRE_MASTER_KEY_GEN not operational: {exc}")

    def test_two_generated_keys_differ(self, p11_session: Any, p11_module: Any) -> None:
        """Two independently generated pre-master keys must differ."""
        if not has_mechanism(p11_module, "WTLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_WTLS_PRE_MASTER_KEY_GEN not supported")

        try:
            tmpl = {
                Attribute.DERIVE: True,
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            }
            key1 = p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                160,
                mechanism=Mechanism.WTLS_PRE_MASTER_KEY_GEN,
                template=tmpl,
            )
            key2 = p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                160,
                mechanism=Mechanism.WTLS_PRE_MASTER_KEY_GEN,
                template=tmpl,
            )
            try:
                val1 = key1[Attribute.VALUE]
                val2 = key2[Attribute.VALUE]
                assert val1 != val2, "Two independently generated pre-master keys must differ"
            finally:
                key2.destroy()
                key1.destroy()
        except _WTLS_ERRORS as exc:
            pytest.xfail(f"CKM_WTLS_PRE_MASTER_KEY_GEN not operational: {exc}")


class TestWTLSMasterKeyDerive:
    """CKM_WTLS_MASTER_KEY_DERIVE -- derive WTLS master secret from pre-master secret."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_WTLS_MASTER_KEY_DERIVE is advertised."""
        if not has_mechanism(p11_module, "WTLS_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE not supported")

    def test_derive_master_key(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt to derive a WTLS master key from a pre-master secret.

        CKM_WTLS_MASTER_KEY_DERIVE requires a CK_WTLS_MASTER_KEY_DERIVE_PARAMS
        structure containing CK_WTLS_RANDOM_DATA for client and server randoms
        and a pointer for the WTLS version output.  No python-pkcs11 wrapper
        exists for these structures, so the attempt is expected to fail with
        a parameter-related error.
        """
        if not has_mechanism(p11_module, "WTLS_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE not supported")

        pms = _create_generic_secret(p11_session, 20)
        try:
            # Invoke without mechanism_param -- must raise a parameter error.
            try:
                derived = pms.derive_key(
                    KeyType.GENERIC_SECRET,
                    None,
                    mechanism=Mechanism.WTLS_MASTER_KEY_DERIVE,
                    template=_DERIVE_TEMPLATE,
                )
                # If the token somehow accepts it, verify we got something.
                try:
                    assert derived is not None
                finally:
                    derived.destroy()
            except _WTLS_ERRORS as exc:
                pytest.xfail(
                    f"CKM_WTLS_MASTER_KEY_DERIVE not operational (no param wrapper): {exc}"
                )
        finally:
            pms.destroy()


class TestWTLSMasterKeyDeriveDHECC:
    """CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC -- derive WTLS master secret via DH/ECC."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC is advertised."""
        if not has_mechanism(p11_module, "WTLS_MASTER_KEY_DERIVE_DH_ECC"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC not supported")

    def test_derive_master_key_dh_ecc(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt to derive a WTLS master key using the DH/ECC variant.

        Like CKM_WTLS_MASTER_KEY_DERIVE, this mechanism requires
        CK_WTLS_MASTER_KEY_DERIVE_PARAMS but is used after an ECDH key
        agreement step.  No python-pkcs11 wrapper exists, so the attempt
        is expected to fail with a parameter-related error.
        """
        if not has_mechanism(p11_module, "WTLS_MASTER_KEY_DERIVE_DH_ECC"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC not supported")

        pms = _create_generic_secret(p11_session, 32)
        try:
            try:
                derived = pms.derive_key(
                    KeyType.GENERIC_SECRET,
                    None,
                    mechanism=Mechanism.WTLS_MASTER_KEY_DERIVE_DH_ECC,
                    template=_DERIVE_TEMPLATE,
                )
                try:
                    assert derived is not None
                finally:
                    derived.destroy()
            except _WTLS_ERRORS as exc:
                pytest.xfail(
                    f"CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC not operational (no param wrapper): {exc}"
                )
        finally:
            pms.destroy()


class TestWTLSKeyAndMacDerive:
    """CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE and CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE.

    These mechanisms expand a WTLS master secret into bulk cipher keys and MAC
    keys for server and client directions respectively.  They require a
    CK_WTLS_KEY_MAT_PARAMS structure; no python-pkcs11 wrapper exists.
    """

    def test_server_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE is advertised."""
        if not has_mechanism(p11_module, "WTLS_SERVER_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not supported")

    def test_client_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE is advertised."""
        if not has_mechanism(p11_module, "WTLS_CLIENT_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not supported")

    def test_server_key_and_mac_derive(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE without a param wrapper.

        Expected to fail with a mechanism parameter error since
        CK_WTLS_KEY_MAT_PARAMS is not wrapped in python-pkcs11.
        """
        if not has_mechanism(p11_module, "WTLS_SERVER_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(p11_session, 20)
        try:
            try:
                derived = master.derive_key(
                    KeyType.GENERIC_SECRET,
                    None,
                    mechanism=Mechanism.WTLS_SERVER_KEY_AND_MAC_DERIVE,
                    template=_DERIVE_TEMPLATE,
                )
                try:
                    assert derived is not None
                finally:
                    derived.destroy()
            except _WTLS_ERRORS as exc:
                pytest.xfail(
                    f"CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not operational (no param wrapper): {exc}"
                )
        finally:
            master.destroy()

    def test_client_key_and_mac_derive(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE without a param wrapper.

        Expected to fail with a mechanism parameter error since
        CK_WTLS_KEY_MAT_PARAMS is not wrapped in python-pkcs11.
        """
        if not has_mechanism(p11_module, "WTLS_CLIENT_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(p11_session, 20)
        try:
            try:
                derived = master.derive_key(
                    KeyType.GENERIC_SECRET,
                    None,
                    mechanism=Mechanism.WTLS_CLIENT_KEY_AND_MAC_DERIVE,
                    template=_DERIVE_TEMPLATE,
                )
                try:
                    assert derived is not None
                finally:
                    derived.destroy()
            except _WTLS_ERRORS as exc:
                pytest.xfail(
                    f"CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not operational (no param wrapper): {exc}"
                )
        finally:
            master.destroy()

    def test_server_and_client_differ(self, p11_session: Any, p11_module: Any) -> None:
        """Server and client derivation of the same master must produce different keys.

        Both WTLS_SERVER_KEY_AND_MAC_DERIVE and WTLS_CLIENT_KEY_AND_MAC_DERIVE
        must be available for this test to proceed.
        """
        if not has_mechanism(p11_module, "WTLS_SERVER_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not supported")
        if not has_mechanism(p11_module, "WTLS_CLIENT_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(p11_session, 20)
        try:
            server_derived = None
            client_derived = None
            try:
                server_derived = master.derive_key(
                    KeyType.GENERIC_SECRET,
                    None,
                    mechanism=Mechanism.WTLS_SERVER_KEY_AND_MAC_DERIVE,
                    template=_DERIVE_TEMPLATE,
                )
                client_derived = master.derive_key(
                    KeyType.GENERIC_SECRET,
                    None,
                    mechanism=Mechanism.WTLS_CLIENT_KEY_AND_MAC_DERIVE,
                    template=_DERIVE_TEMPLATE,
                )
                srv_val = server_derived[Attribute.VALUE]
                cli_val = client_derived[Attribute.VALUE]
                assert srv_val != cli_val, (
                    "Server and client key derivation must produce different keys"
                )
            except _WTLS_ERRORS as exc:
                pytest.xfail(
                    f"WTLS key-and-MAC derivation not operational (no param wrapper): {exc}"
                )
            finally:
                if client_derived is not None:
                    client_derived.destroy()
                if server_derived is not None:
                    server_derived.destroy()
        finally:
            master.destroy()


class TestWTLSPRF:
    """CKM_WTLS_PRF -- WTLS pseudo-random function for key material expansion."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_WTLS_PRF is advertised."""
        if not has_mechanism(p11_module, "WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

    def test_prf_derive(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt to use CKM_WTLS_PRF for key derivation.

        CKM_WTLS_PRF requires a CK_WTLS_PRF_PARAMS structure containing a
        seed and label.  No python-pkcs11 wrapper exists for this structure,
        so the attempt is expected to fail with a parameter-related error.
        """
        if not has_mechanism(p11_module, "WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(p11_session, 20)
        try:
            try:
                derived = secret.derive_key(
                    KeyType.GENERIC_SECRET,
                    128,
                    mechanism=Mechanism.WTLS_PRF,
                    template=_DERIVE_TEMPLATE,
                )
                try:
                    assert derived is not None
                    value = derived[Attribute.VALUE]
                    assert len(value) == 16, f"Expected 16 bytes, got {len(value)}"
                finally:
                    derived.destroy()
            except _WTLS_ERRORS as exc:
                pytest.xfail(f"CKM_WTLS_PRF not operational (no param wrapper): {exc}")
        finally:
            secret.destroy()

    def test_prf_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same WTLS PRF inputs must produce the same output.

        If CKM_WTLS_PRF becomes operational (token supplies the wrapper),
        identical seed/label/secret must yield identical output.
        """
        if not has_mechanism(p11_module, "WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(p11_session, 20)
        try:
            derived1 = None
            derived2 = None
            try:
                derived1 = secret.derive_key(
                    KeyType.GENERIC_SECRET,
                    128,
                    mechanism=Mechanism.WTLS_PRF,
                    template=_DERIVE_TEMPLATE,
                )
                derived2 = secret.derive_key(
                    KeyType.GENERIC_SECRET,
                    128,
                    mechanism=Mechanism.WTLS_PRF,
                    template=_DERIVE_TEMPLATE,
                )
                val1 = derived1[Attribute.VALUE]
                val2 = derived2[Attribute.VALUE]
                assert val1 == val2, "CKM_WTLS_PRF must be deterministic for identical inputs"
            except _WTLS_ERRORS as exc:
                pytest.xfail(f"CKM_WTLS_PRF not operational (no param wrapper): {exc}")
            finally:
                if derived2 is not None:
                    derived2.destroy()
                if derived1 is not None:
                    derived1.destroy()
        finally:
            secret.destroy()
