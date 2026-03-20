"""Tests for SSL3 protocol mechanisms.

Covers CKM_SSL3_PRE_MASTER_KEY_GEN, CKM_SSL3_MASTER_KEY_DERIVE,
CKM_SSL3_KEY_AND_MAC_DERIVE, CKM_SSL3_MASTER_KEY_DERIVE_DH,
CKM_SSL3_MD5_MAC, and CKM_SSL3_SHA1_MAC.

These are legacy SSL 3.0 mechanisms. Most modern tokens (SoftHSM2, Kryoptic)
do not support them. Tests skip cleanly via has_mechanism() when unsupported.

CKM_SSL3_MASTER_KEY_DERIVE and CKM_SSL3_KEY_AND_MAC_DERIVE require nested C
parameter structures (CK_SSL3_RANDOM_DATA, CK_SSL3_MASTER_KEY_DERIVE_PARAMS,
CK_SSL3_KEY_MAT_PARAMS) that have no Python-level wrappers in python-pkcs11.
Those tests probe availability only, and xfail on _DERIVE_ERRORS for any
operational attempt using raw bytes as a placeholder parameter.

OASIS spec: ssl.md
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import (
    ArgumentsBad,
    FunctionFailed,
    GeneralError,
    KeyTypeInconsistent,
    MechanismInvalid,
    MechanismParamInvalid,
    TemplateIncomplete,
    TemplateInconsistent,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt

# SSL 3.0 client/server random values (28 bytes each per spec)
_CLIENT_RANDOM = bytes(range(28))
_SERVER_RANDOM = bytes(range(28, 56))

# A 48-byte pre-master secret (SSL3 pre-master key size)
_PRE_MASTER_SECRET = bytes(range(48))

# Errors acceptable for operations using placeholder/unsupported params
_DERIVE_ERRORS = (
    MechanismInvalid,
    MechanismParamInvalid,
    FunctionFailed,
    GeneralError,
    ArgumentsBad,
    TemplateIncomplete,
    TemplateInconsistent,
    KeyTypeInconsistent,
)

# Errors acceptable for MAC sign/verify operations
_MAC_ERRORS = (
    MechanismInvalid,
    MechanismParamInvalid,
    FunctionFailed,
    GeneralError,
    ArgumentsBad,
)


def _create_generic_secret(session: Any, value: bytes) -> Any:
    """Import a GENERIC_SECRET key for use as a pre-master or master secret."""
    return session.create_object(
        {
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
            Attribute.VALUE: value,
            Attribute.DERIVE: True,
            Attribute.SIGN: True,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        }
    )


class TestSSL3PreMasterKeyGen:
    """CKM_SSL3_PRE_MASTER_KEY_GEN — generate an SSL3 pre-master secret."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_SSL3_PRE_MASTER_KEY_GEN is advertised."""
        if not has_mechanism(p11_module, "SSL3_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_SSL3_PRE_MASTER_KEY_GEN not supported")

    def test_generate_pre_master_key(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a 48-byte SSL3 pre-master secret with version (3, 0)."""
        if not has_mechanism(p11_module, "SSL3_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_SSL3_PRE_MASTER_KEY_GEN not supported")

        # The mechanism parameter is the SSL version as a (major, minor) tuple.
        # SSL 3.0 uses (3, 0); the module encodes it as CK_VERSION.
        try:
            key = p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                384,  # 48 bytes = 384 bits (SSL3 pre-master secret size)
                mechanism=Mechanism.SSL3_PRE_MASTER_KEY_GEN,
                mechanism_param=(3, 0),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.TOKEN: False,
                    Attribute.DERIVE: True,
                },
            )
            try:
                raw = key[Attribute.VALUE]
                assert len(raw) == 48, f"Expected 48 bytes, got {len(raw)}"
                # First two bytes must encode the version (3, 0)
                assert raw[0] == 3, f"Expected major version 3, got {raw[0]}"
                assert raw[1] == 0, f"Expected minor version 0, got {raw[1]}"
            finally:
                key.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_SSL3_PRE_MASTER_KEY_GEN not operational: {exc}")

    def test_generate_produces_random_output(self, p11_session: Any, p11_module: Any) -> None:
        """Two separate pre-master key generations must produce different values."""
        if not has_mechanism(p11_module, "SSL3_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_SSL3_PRE_MASTER_KEY_GEN not supported")

        _template: dict[Attribute, Any] = {
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
            Attribute.TOKEN: False,
            Attribute.DERIVE: True,
        }
        try:
            key1 = p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                384,
                mechanism=Mechanism.SSL3_PRE_MASTER_KEY_GEN,
                mechanism_param=(3, 0),
                template=_template,
            )
            key2 = p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                384,
                mechanism=Mechanism.SSL3_PRE_MASTER_KEY_GEN,
                mechanism_param=(3, 0),
                template=_template,
            )
            try:
                val1 = key1[Attribute.VALUE]
                val2 = key2[Attribute.VALUE]
                assert val1 != val2, "Two pre-master key generations produced identical output"
            finally:
                key2.destroy()
                key1.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_SSL3_PRE_MASTER_KEY_GEN not operational: {exc}")


class TestSSL3MasterKeyDerive:
    """CKM_SSL3_MASTER_KEY_DERIVE — derive master secret from pre-master secret.

    This mechanism requires CK_SSL3_MASTER_KEY_DERIVE_PARAMS which embeds
    CK_SSL3_RANDOM_DATA (client_random + server_random) and a CK_VERSION output
    pointer. There are no Python-level wrappers for these C structs in
    python-pkcs11. Tests check availability and xfail on any operational attempt.
    """

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_SSL3_MASTER_KEY_DERIVE is advertised."""
        if not has_mechanism(p11_module, "SSL3_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_SSL3_MASTER_KEY_DERIVE not supported")

    def test_derive_master_secret(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt master secret derivation; xfail without C struct wrappers.

        CKM_SSL3_MASTER_KEY_DERIVE requires CK_SSL3_MASTER_KEY_DERIVE_PARAMS
        (containing CK_SSL3_RANDOM_DATA with 28-byte client/server randoms and
        a CK_VERSION output field). Full integration requires parameter struct
        support in python-pkcs11.
        """
        if not has_mechanism(p11_module, "SSL3_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_SSL3_MASTER_KEY_DERIVE not supported")

        pre_master = _create_generic_secret(p11_session, _PRE_MASTER_SECRET)
        try:
            # Use concatenated randoms as a placeholder — real usage requires
            # CK_SSL3_MASTER_KEY_DERIVE_PARAMS struct.
            derived = pre_master.derive_key(
                KeyType.GENERIC_SECRET,
                384,  # 48-byte master secret
                mechanism=Mechanism.SSL3_MASTER_KEY_DERIVE,
                mechanism_param=_CLIENT_RANDOM + _SERVER_RANDOM,
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.TOKEN: False,
                    Attribute.DERIVE: True,
                },
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 48, f"Expected 48 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(
                f"CKM_SSL3_MASTER_KEY_DERIVE not operational (C struct params needed): {exc}"
            )
        finally:
            pre_master.destroy()


class TestSSL3MasterKeyDeriveDH:
    """CKM_SSL3_MASTER_KEY_DERIVE_DH — DH variant of SSL3 master key derivation.

    Identical parameter requirements to CKM_SSL3_MASTER_KEY_DERIVE but used
    when the pre-master secret was established via Diffie-Hellman. The version
    field in the output params is not set (DH doesn't embed a version).
    """

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_SSL3_MASTER_KEY_DERIVE_DH is advertised."""
        if not has_mechanism(p11_module, "SSL3_MASTER_KEY_DERIVE_DH"):
            pytest.skip("CKM_SSL3_MASTER_KEY_DERIVE_DH not supported")

    def test_derive_master_secret_dh(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt DH-variant master secret derivation; xfail without C struct wrappers.

        CKM_SSL3_MASTER_KEY_DERIVE_DH requires the same CK_SSL3_MASTER_KEY_DERIVE_PARAMS
        as the non-DH variant but the pVersion field is set to NULL_PTR.
        """
        if not has_mechanism(p11_module, "SSL3_MASTER_KEY_DERIVE_DH"):
            pytest.skip("CKM_SSL3_MASTER_KEY_DERIVE_DH not supported")

        pre_master = _create_generic_secret(p11_session, _PRE_MASTER_SECRET)
        try:
            derived = pre_master.derive_key(
                KeyType.GENERIC_SECRET,
                384,
                mechanism=Mechanism.SSL3_MASTER_KEY_DERIVE_DH,
                mechanism_param=_CLIENT_RANDOM + _SERVER_RANDOM,
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.TOKEN: False,
                    Attribute.DERIVE: True,
                },
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 48, f"Expected 48 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(
                f"CKM_SSL3_MASTER_KEY_DERIVE_DH not operational (C struct params needed): {exc}"
            )
        finally:
            pre_master.destroy()


class TestSSL3KeyAndMacDerive:
    """CKM_SSL3_KEY_AND_MAC_DERIVE — derive key material from the SSL3 master secret.

    This mechanism requires CK_SSL3_KEY_MAT_PARAMS which embeds:
    - MacSizeInBits, KeySizeInBits, IVSizeInBits
    - bIsExport flag
    - CK_SSL3_RANDOM_DATA (client/server randoms)
    - CK_SSL3_KEY_MAT_OUT (output handles for client/server keys and IVs)

    There are no Python-level wrappers for these nested C structs in
    python-pkcs11. Tests check availability and xfail on any operational attempt.
    """

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_SSL3_KEY_AND_MAC_DERIVE is advertised."""
        if not has_mechanism(p11_module, "SSL3_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_SSL3_KEY_AND_MAC_DERIVE not supported")

    def test_derive_key_material(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt key material derivation; xfail without C struct wrappers.

        CKM_SSL3_KEY_AND_MAC_DERIVE requires CK_SSL3_KEY_MAT_PARAMS with nested
        CK_SSL3_RANDOM_DATA and CK_SSL3_KEY_MAT_OUT. Full integration requires
        parameter struct support in python-pkcs11.
        """
        if not has_mechanism(p11_module, "SSL3_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_SSL3_KEY_AND_MAC_DERIVE not supported")

        master_secret = _create_generic_secret(p11_session, _PRE_MASTER_SECRET)
        try:
            # Placeholder: real usage requires CK_SSL3_KEY_MAT_PARAMS struct.
            derived = master_secret.derive_key(
                KeyType.AES,
                128,
                mechanism=Mechanism.SSL3_KEY_AND_MAC_DERIVE,
                mechanism_param=_CLIENT_RANDOM + _SERVER_RANDOM,
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                raw = derived[Attribute.VALUE]
                assert len(raw) == 16, f"Expected 16 bytes, got {len(raw)}"
            finally:
                derived.destroy()
        except _DERIVE_ERRORS as exc:
            pytest.xfail(
                f"CKM_SSL3_KEY_AND_MAC_DERIVE not operational (C struct params needed): {exc}"
            )
        finally:
            master_secret.destroy()


class TestSSL3Mac:
    """CKM_SSL3_MD5_MAC and CKM_SSL3_SHA1_MAC — SSL3 MAC mechanisms.

    These are sign/verify mechanisms. The mechanism parameter is the MAC output
    length in bits (as an integer). SSL3 MD5 MAC produces up to 16 bytes;
    SSL3 SHA1 MAC produces up to 20 bytes.
    """

    def test_mechanism_availability_md5_mac(self, p11_module: Any) -> None:
        """Probe whether CKM_SSL3_MD5_MAC is advertised."""
        if not has_mechanism(p11_module, "SSL3_MD5_MAC"):
            pytest.skip("CKM_SSL3_MD5_MAC not supported")

    def test_mechanism_availability_sha1_mac(self, p11_module: Any) -> None:
        """Probe whether CKM_SSL3_SHA1_MAC is advertised."""
        if not has_mechanism(p11_module, "SSL3_SHA1_MAC"):
            pytest.skip("CKM_SSL3_SHA1_MAC not supported")

    def test_md5_mac_sign(self, p11_session: Any, p11_module: Any) -> None:
        """Compute an SSL3 MD5 MAC over test data."""
        if not has_mechanism(p11_module, "SSL3_MD5_MAC"):
            pytest.skip("CKM_SSL3_MD5_MAC not supported")

        key = _create_generic_secret(p11_session, bytes(range(16)))
        try:
            # mechanism_param is the MAC length in bits (16 bytes = 128 bits)
            mac = key.sign(
                b"test handshake data",
                mechanism=Mechanism.SSL3_MD5_MAC,
                mechanism_param=128,
            )
            assert len(mac) == 16, f"Expected 16-byte MD5 MAC, got {len(mac)}"
        except _MAC_ERRORS as exc:
            pytest.xfail(f"CKM_SSL3_MD5_MAC sign not operational: {exc}")
        finally:
            key.destroy()

    def test_md5_mac_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same key and data must produce the same SSL3 MD5 MAC."""
        if not has_mechanism(p11_module, "SSL3_MD5_MAC"):
            pytest.skip("CKM_SSL3_MD5_MAC not supported")

        key = _create_generic_secret(p11_session, bytes(range(16)))
        try:
            data = b"ssl3 mac determinism test"
            mac1 = key.sign(
                data,
                mechanism=Mechanism.SSL3_MD5_MAC,
                mechanism_param=128,
            )
            mac2 = key.sign(
                data,
                mechanism=Mechanism.SSL3_MD5_MAC,
                mechanism_param=128,
            )
            assert mac1 == mac2, "CKM_SSL3_MD5_MAC produced different MACs for identical input"
        except _MAC_ERRORS as exc:
            pytest.xfail(f"CKM_SSL3_MD5_MAC not operational: {exc}")
        finally:
            key.destroy()

    def test_md5_mac_different_data(self, p11_session: Any, p11_module: Any) -> None:
        """Different data must produce different SSL3 MD5 MACs."""
        if not has_mechanism(p11_module, "SSL3_MD5_MAC"):
            pytest.skip("CKM_SSL3_MD5_MAC not supported")

        key = _create_generic_secret(p11_session, bytes(range(16)))
        try:
            mac_a = key.sign(
                b"data-alpha",
                mechanism=Mechanism.SSL3_MD5_MAC,
                mechanism_param=128,
            )
            mac_b = key.sign(
                b"data-bravo",
                mechanism=Mechanism.SSL3_MD5_MAC,
                mechanism_param=128,
            )
            assert mac_a != mac_b, "CKM_SSL3_MD5_MAC produced same MAC for different data"
        except _MAC_ERRORS as exc:
            pytest.xfail(f"CKM_SSL3_MD5_MAC not operational: {exc}")
        finally:
            key.destroy()

    def test_sha1_mac_sign(self, p11_session: Any, p11_module: Any) -> None:
        """Compute an SSL3 SHA1 MAC over test data."""
        if not has_mechanism(p11_module, "SSL3_SHA1_MAC"):
            pytest.skip("CKM_SSL3_SHA1_MAC not supported")

        key = _create_generic_secret(p11_session, bytes(range(20)))
        try:
            # mechanism_param is the MAC length in bits (20 bytes = 160 bits)
            mac = key.sign(
                b"test handshake data",
                mechanism=Mechanism.SSL3_SHA1_MAC,
                mechanism_param=160,
            )
            assert len(mac) == 20, f"Expected 20-byte SHA1 MAC, got {len(mac)}"
        except _MAC_ERRORS as exc:
            pytest.xfail(f"CKM_SSL3_SHA1_MAC sign not operational: {exc}")
        finally:
            key.destroy()

    def test_sha1_mac_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same key and data must produce the same SSL3 SHA1 MAC."""
        if not has_mechanism(p11_module, "SSL3_SHA1_MAC"):
            pytest.skip("CKM_SSL3_SHA1_MAC not supported")

        key = _create_generic_secret(p11_session, bytes(range(20)))
        try:
            data = b"ssl3 sha1 mac determinism test"
            mac1 = key.sign(
                data,
                mechanism=Mechanism.SSL3_SHA1_MAC,
                mechanism_param=160,
            )
            mac2 = key.sign(
                data,
                mechanism=Mechanism.SSL3_SHA1_MAC,
                mechanism_param=160,
            )
            assert mac1 == mac2, "CKM_SSL3_SHA1_MAC produced different MACs for identical input"
        except _MAC_ERRORS as exc:
            pytest.xfail(f"CKM_SSL3_SHA1_MAC not operational: {exc}")
        finally:
            key.destroy()

    def test_sha1_mac_different_data(self, p11_session: Any, p11_module: Any) -> None:
        """Different data must produce different SSL3 SHA1 MACs."""
        if not has_mechanism(p11_module, "SSL3_SHA1_MAC"):
            pytest.skip("CKM_SSL3_SHA1_MAC not supported")

        key = _create_generic_secret(p11_session, bytes(range(20)))
        try:
            mac_a = key.sign(
                b"data-alpha",
                mechanism=Mechanism.SSL3_SHA1_MAC,
                mechanism_param=160,
            )
            mac_b = key.sign(
                b"data-bravo",
                mechanism=Mechanism.SSL3_SHA1_MAC,
                mechanism_param=160,
            )
            assert mac_a != mac_b, "CKM_SSL3_SHA1_MAC produced same MAC for different data"
        except _MAC_ERRORS as exc:
            pytest.xfail(f"CKM_SSL3_SHA1_MAC not operational: {exc}")
        finally:
            key.destroy()

    def test_md5_mac_key_affects_output(self, p11_session: Any, p11_module: Any) -> None:
        """Different keys must produce different SSL3 MD5 MACs for the same data."""
        if not has_mechanism(p11_module, "SSL3_MD5_MAC"):
            pytest.skip("CKM_SSL3_MD5_MAC not supported")

        key1 = _create_generic_secret(p11_session, bytes(range(16)))
        key2 = _create_generic_secret(p11_session, bytes(range(16, 32)))
        try:
            data = b"same data for both keys"
            mac1 = key1.sign(
                data,
                mechanism=Mechanism.SSL3_MD5_MAC,
                mechanism_param=128,
            )
            mac2 = key2.sign(
                data,
                mechanism=Mechanism.SSL3_MD5_MAC,
                mechanism_param=128,
            )
            assert mac1 != mac2, "CKM_SSL3_MD5_MAC produced same MAC for different keys"
        except _MAC_ERRORS as exc:
            pytest.xfail(f"CKM_SSL3_MD5_MAC not operational: {exc}")
        finally:
            key2.destroy()
            key1.destroy()

    def test_sha1_mac_key_affects_output(self, p11_session: Any, p11_module: Any) -> None:
        """Different keys must produce different SSL3 SHA1 MACs for the same data."""
        if not has_mechanism(p11_module, "SSL3_SHA1_MAC"):
            pytest.skip("CKM_SSL3_SHA1_MAC not supported")

        key1 = _create_generic_secret(p11_session, bytes(range(20)))
        key2 = _create_generic_secret(p11_session, bytes(range(20, 40)))
        try:
            data = b"same data for both keys"
            mac1 = key1.sign(
                data,
                mechanism=Mechanism.SSL3_SHA1_MAC,
                mechanism_param=160,
            )
            mac2 = key2.sign(
                data,
                mechanism=Mechanism.SSL3_SHA1_MAC,
                mechanism_param=160,
            )
            assert mac1 != mac2, "CKM_SSL3_SHA1_MAC produced same MAC for different keys"
        except _MAC_ERRORS as exc:
            pytest.xfail(f"CKM_SSL3_SHA1_MAC not operational: {exc}")
        finally:
            key2.destroy()
            key1.destroy()
