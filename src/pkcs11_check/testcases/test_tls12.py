"""Tests for TLS 1.2 protocol mechanisms.

Covers CKM_TLS12_MASTER_KEY_DERIVE, CKM_TLS12_KEY_AND_MAC_DERIVE,
CKM_TLS12_KEY_SAFE_DERIVE, CKM_TLS12_MAC, CKM_TLS12_KDF,
CKM_TLS_MAC, CKM_TLS_KDF, CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH, and legacy TLS 1.0 mechanisms.

These mechanisms derive keys and MAC keys for TLS 1.2 sessions. They require
complex C parameter structures (CK_TLS12_MASTER_KEY_DERIVE_PARAMS, etc.) that
the python-pkcs11 fork provides parameter handlers for. Availability
is tested on all modules; full operational tests are marked xfail because most
tokens do not implement these mechanisms.

OASIS spec: tls_1.2_mechanisms.md
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import (
    AttributeValueInvalid,
    DeviceError,
    FunctionFailed,
    GeneralError,
    KeyFunctionNotPermitted,
    MechanismInvalid,
    MechanismParamInvalid,
    TemplateInconsistent,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt

# 48-byte pre-master secret (standard TLS length for RSA key exchange)
_PRE_MASTER_SECRET = bytes(range(48))

# 32-byte random values for client and server randoms
_CLIENT_RANDOM = bytes(range(32))
_SERVER_RANDOM = bytes(range(32, 64))

# Error tuple for TLS mechanism operations that fail at the module level
_TLS_ERRORS = (
    MechanismInvalid,
    MechanismParamInvalid,
    FunctionFailed,
    GeneralError,
    KeyFunctionNotPermitted,
    AttributeValueInvalid,
    TemplateInconsistent,
    DeviceError,
)


def _create_generic_secret(
    session: Any, data: bytes = _PRE_MASTER_SECRET, **extra: Any,
) -> Any:
    """Create a GENERIC_SECRET key object for use as TLS keying material."""
    template = {
        Attribute.CLASS: ObjectClass.SECRET_KEY,
        Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
        Attribute.VALUE: data,
        Attribute.DERIVE: True,
        Attribute.TOKEN: False,
        Attribute.SENSITIVE: False,
        Attribute.EXTRACTABLE: True,
    }
    template.update(extra)
    return session.create_object(template
    )


def _create_tls_pms(session: Any) -> Any:
    """Create a GENERIC_SECRET key simulating a TLS pre-master secret."""
    return _create_generic_secret(session, _PRE_MASTER_SECRET)


class TestTLS10PreMasterKeyGen:
    """Legacy TLS 1.0 mechanisms - CKM_TLS_PRE_MASTER_KEY_GEN and related."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_TLS_PRE_MASTER_KEY_GEN is advertised."""
        if not has_mechanism(p11_module, "TLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_TLS_PRE_MASTER_KEY_GEN not supported")

    def test_pre_master_key_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a TLS pre-master secret key via CKM_TLS_PRE_MASTER_KEY_GEN."""
        if not has_mechanism(p11_module, "TLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_TLS_PRE_MASTER_KEY_GEN not supported")

        # TLS version encoded as (major, minor): TLS 1.0 = (3, 1)
        tls_version = (3, 1)
        try:
            key = p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                48,
                mechanism=Mechanism.TLS_PRE_MASTER_KEY_GEN,
                mechanism_param=tls_version,
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.DERIVE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                value = key[Attribute.VALUE]
                assert len(value) == 48, f"Expected 48-byte pre-master secret, got {len(value)}"
                # First two bytes must match the requested TLS version
                assert value[0] == 3, f"Expected major version 3, got {value[0]}"
                assert value[1] == 1, f"Expected minor version 1, got {value[1]}"
            finally:
                key.destroy()
        except _TLS_ERRORS as exc:
            pytest.xfail(f"CKM_TLS_PRE_MASTER_KEY_GEN not operational: {exc}")

    def test_tls_master_key_derive_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_TLS_MASTER_KEY_DERIVE is advertised."""
        if not has_mechanism(p11_module, "TLS_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_TLS_MASTER_KEY_DERIVE not supported")

    def test_tls_master_key_derive(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt CKM_TLS_MASTER_KEY_DERIVE - requires complex C params, xfail expected."""
        if not has_mechanism(p11_module, "TLS_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_TLS_MASTER_KEY_DERIVE not supported")

        pms = _create_tls_pms(p11_session)
        try:
            # CKM_TLS_MASTER_KEY_DERIVE requires CK_SSL3_MASTER_KEY_DERIVE_PARAMS
            # which includes client/server randoms and version output buffer.
            # raw bytes as params will fail with MechanismParamInvalid.
            derived = pms.derive_key(
                KeyType.GENERIC_SECRET,
                48,
                mechanism=Mechanism.TLS_MASTER_KEY_DERIVE,
                mechanism_param=(_CLIENT_RANDOM, _SERVER_RANDOM),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.DERIVE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                value = derived[Attribute.VALUE]
                assert len(value) == 48, f"Expected 48-byte master secret, got {len(value)}"
            finally:
                derived.destroy()
        except _TLS_ERRORS as exc:
            pytest.xfail(f"CKM_TLS_MASTER_KEY_DERIVE not operational: {exc}")
        finally:
            pms.destroy()

    def test_tls_key_and_mac_derive_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_TLS_KEY_AND_MAC_DERIVE is advertised."""
        if not has_mechanism(p11_module, "TLS_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_TLS_KEY_AND_MAC_DERIVE not supported")

    def test_tls_master_key_derive_dh_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_TLS_MASTER_KEY_DERIVE_DH is advertised."""
        if not has_mechanism(p11_module, "TLS_MASTER_KEY_DERIVE_DH"):
            pytest.skip("CKM_TLS_MASTER_KEY_DERIVE_DH not supported")

    def test_tls_prf_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_TLS_PRF is advertised."""
        if not has_mechanism(p11_module, "TLS_PRF"):
            pytest.skip("CKM_TLS_PRF not supported")

    def test_tls_prf(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt CKM_TLS_PRF to derive pseudorandom data."""
        if not has_mechanism(p11_module, "TLS_PRF"):
            pytest.skip("CKM_TLS_PRF not supported")

        pms = _create_tls_pms(p11_session)
        try:
            # CKM_TLS_PRF requires CK_TLS_PRF_PARAMS with seed, label, output buffer.
            # Attempt with a bytes param - will fail with MechanismParamInvalid on most tokens.
            derived = pms.derive_key(
                KeyType.GENERIC_SECRET,
                48,
                mechanism=Mechanism.TLS_PRF,
                mechanism_param=(_CLIENT_RANDOM + _SERVER_RANDOM, b"master secret"),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.DERIVE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                value = derived[Attribute.VALUE]
                assert len(value) == 48
            finally:
                derived.destroy()
        except _TLS_ERRORS as exc:
            pytest.xfail(f"CKM_TLS_PRF not operational: {exc}")
        finally:
            pms.destroy()


class TestTLS12MasterKeyDerive:
    """CKM_TLS12_MASTER_KEY_DERIVE and CKM_TLS12_MASTER_KEY_DERIVE_DH."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_TLS12_MASTER_KEY_DERIVE is advertised."""
        if not has_mechanism(p11_module, "TLS12_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_TLS12_MASTER_KEY_DERIVE not supported")

    def test_master_key_derive(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt CKM_TLS12_MASTER_KEY_DERIVE - requires CK_TLS12_MASTER_KEY_DERIVE_PARAMS."""
        if not has_mechanism(p11_module, "TLS12_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_TLS12_MASTER_KEY_DERIVE not supported")

        pms = _create_tls_pms(p11_session)
        try:
            # CKM_TLS12_MASTER_KEY_DERIVE_PARAMS adds a prf_hash_mechanism field
            # (e.g. CKM_SHA256) to the legacy SSL3 parameter structure.
            derived = pms.derive_key(
                KeyType.GENERIC_SECRET,
                48,
                mechanism=Mechanism.TLS12_MASTER_KEY_DERIVE,
                mechanism_param=(_CLIENT_RANDOM, _SERVER_RANDOM, Mechanism.SHA256),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.DERIVE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                value = derived[Attribute.VALUE]
                assert len(value) == 48, f"Expected 48-byte master secret, got {len(value)}"
            finally:
                derived.destroy()
        except _TLS_ERRORS as exc:
            pytest.xfail(f"CKM_TLS12_MASTER_KEY_DERIVE not operational: {exc}")
        finally:
            pms.destroy()

    def test_master_key_derive_dh_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_TLS12_MASTER_KEY_DERIVE_DH is advertised."""
        if not has_mechanism(p11_module, "TLS12_MASTER_KEY_DERIVE_DH"):
            pytest.skip("CKM_TLS12_MASTER_KEY_DERIVE_DH not supported")

    def test_master_key_derive_dh(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt CKM_TLS12_MASTER_KEY_DERIVE_DH for DH-based key exchange."""
        if not has_mechanism(p11_module, "TLS12_MASTER_KEY_DERIVE_DH"):
            pytest.skip("CKM_TLS12_MASTER_KEY_DERIVE_DH not supported")

        # DH pre-master secret is a raw shared secret (32 bytes for P-256)
        dh_pms = _create_generic_secret(p11_session, bytes(range(32)))
        try:
            derived = dh_pms.derive_key(
                KeyType.GENERIC_SECRET,
                48,
                mechanism=Mechanism.TLS12_MASTER_KEY_DERIVE_DH,
                mechanism_param=(_CLIENT_RANDOM, _SERVER_RANDOM, Mechanism.SHA256),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.DERIVE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                value = derived[Attribute.VALUE]
                assert len(value) == 48, f"Expected 48-byte master secret, got {len(value)}"
            finally:
                derived.destroy()
        except _TLS_ERRORS as exc:
            pytest.xfail(
                f"CKM_TLS12_MASTER_KEY_DERIVE_DH not operational: {exc}"
            )
        finally:
            dh_pms.destroy()


class TestTLS12KeyAndMacDerive:
    """CKM_TLS12_KEY_AND_MAC_DERIVE and CKM_TLS12_KEY_SAFE_DERIVE."""

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_TLS12_KEY_AND_MAC_DERIVE is advertised."""
        if not has_mechanism(p11_module, "TLS12_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_TLS12_KEY_AND_MAC_DERIVE not supported")

    def test_key_and_mac_derive(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt CKM_TLS12_KEY_AND_MAC_DERIVE - derives client/server key material."""
        if not has_mechanism(p11_module, "TLS12_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_TLS12_KEY_AND_MAC_DERIVE not supported")

        # Use 48-byte master secret as base key
        master_secret = _create_tls_pms(p11_session)
        try:
            # CKM_TLS12_KEY_AND_MAC_DERIVE_PARAMS includes client/server randoms,
            # key/IV/MAC sizes, and output key handles. No python-pkcs11 wrapper exists.
            derived = master_secret.derive_key(
                KeyType.GENERIC_SECRET,
                16,
                mechanism=Mechanism.TLS12_KEY_AND_MAC_DERIVE,
                mechanism_param=(_CLIENT_RANDOM, _SERVER_RANDOM, Mechanism.SHA256),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.DERIVE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                value = derived[Attribute.VALUE]
                assert len(value) == 16
            finally:
                derived.destroy()
        except _TLS_ERRORS as exc:
            pytest.xfail(
                f"CKM_TLS12_KEY_AND_MAC_DERIVE not operational: {exc}"
            )
        finally:
            master_secret.destroy()

    def test_key_safe_derive_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_TLS12_KEY_SAFE_DERIVE is advertised."""
        if not has_mechanism(p11_module, "TLS12_KEY_SAFE_DERIVE"):
            pytest.skip("CKM_TLS12_KEY_SAFE_DERIVE not supported")

    def test_key_safe_derive(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt CKM_TLS12_KEY_SAFE_DERIVE - safe variant of key-and-MAC derive."""
        if not has_mechanism(p11_module, "TLS12_KEY_SAFE_DERIVE"):
            pytest.skip("CKM_TLS12_KEY_SAFE_DERIVE not supported")

        master_secret = _create_tls_pms(p11_session)
        try:
            derived = master_secret.derive_key(
                KeyType.GENERIC_SECRET,
                16,
                mechanism=Mechanism.TLS12_KEY_SAFE_DERIVE,
                mechanism_param=(_CLIENT_RANDOM, _SERVER_RANDOM, Mechanism.SHA256),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.DERIVE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                value = derived[Attribute.VALUE]
                assert len(value) == 16
            finally:
                derived.destroy()
        except _TLS_ERRORS as exc:
            pytest.xfail(f"CKM_TLS12_KEY_SAFE_DERIVE not operational: {exc}")
        finally:
            master_secret.destroy()


class TestTLS12Mac:
    """CKM_TLS12_MAC and CKM_TLS_MAC - TLS MAC computation mechanisms."""

    def test_tls12_mac_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_TLS12_MAC is advertised."""
        if not has_mechanism(p11_module, "TLS12_MAC"):
            pytest.skip("CKM_TLS12_MAC not supported")

    def test_tls12_mac(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt CKM_TLS12_MAC to compute a TLS 1.2 MAC."""
        if not has_mechanism(p11_module, "TLS12_MAC"):
            pytest.skip("CKM_TLS12_MAC not supported")

        # CKM_TLS12_MAC uses CK_TLS_MAC_PARAMS: {prfHashMechanism, ulMacLength, ulServerOrClient}
        # No python-pkcs11 wrapper - attempt with raw bytes param will fail.
        mac_key = _create_generic_secret(
            p11_session, bytes(range(32)),
            **{Attribute.SIGN: True},
        )
        try:
            result = mac_key.sign(
                b"TLS record data",
                mechanism=Mechanism.TLS12_MAC,
                mechanism_param=(Mechanism.SHA256, 32, 1),
            )
            assert len(result) > 0
        except _TLS_ERRORS as exc:
            pytest.xfail(f"CKM_TLS12_MAC not operational: {exc}")
        finally:
            mac_key.destroy()

    def test_tls_mac_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_TLS_MAC is advertised."""
        if not has_mechanism(p11_module, "TLS_MAC"):
            pytest.skip("CKM_TLS_MAC not supported")

    def test_tls_mac(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt CKM_TLS_MAC to compute a TLS MAC."""
        if not has_mechanism(p11_module, "TLS_MAC"):
            pytest.skip("CKM_TLS_MAC not supported")

        mac_key = _create_generic_secret(
            p11_session, bytes(range(32)),
            **{Attribute.SIGN: True},
        )
        try:
            result = mac_key.sign(
                b"TLS record data",
                mechanism=Mechanism.TLS_MAC,
                mechanism_param=(Mechanism.SHA256, 32, 1),
            )
            assert len(result) > 0
        except _TLS_ERRORS as exc:
            pytest.xfail(f"CKM_TLS_MAC not operational: {exc}")
        finally:
            mac_key.destroy()


class TestTLS12KDF:
    """CKM_TLS12_KDF and CKM_TLS_KDF - TLS key derivation function mechanisms."""

    def test_tls12_kdf_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_TLS12_KDF is advertised."""
        if not has_mechanism(p11_module, "TLS12_KDF"):
            pytest.skip("CKM_TLS12_KDF not supported")

    def test_tls12_kdf(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt CKM_TLS12_KDF to derive keying material."""
        if not has_mechanism(p11_module, "TLS12_KDF"):
            pytest.skip("CKM_TLS12_KDF not supported")

        # CKM_TLS12_KDF requires CK_TLS_KDF_PARAMS with prfMechanism, label, random info.
        # No python-pkcs11 wrapper - attempt will fail with MechanismParamInvalid.
        base_key = _create_tls_pms(p11_session)
        try:
            derived = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                32,
                mechanism=Mechanism.TLS12_KDF,
                mechanism_param=(
                    Mechanism.SHA256,
                    b"key expansion",
                    _CLIENT_RANDOM + _SERVER_RANDOM,
                ),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.DERIVE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                value = derived[Attribute.VALUE]
                assert len(value) == 32
            finally:
                derived.destroy()
        except _TLS_ERRORS as exc:
            pytest.xfail(f"CKM_TLS12_KDF not operational: {exc}")
        finally:
            base_key.destroy()

    def test_tls_kdf_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_TLS_KDF is advertised."""
        if not has_mechanism(p11_module, "TLS_KDF"):
            pytest.skip("CKM_TLS_KDF not supported")

    def test_tls_kdf(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt CKM_TLS_KDF to derive keying material."""
        if not has_mechanism(p11_module, "TLS_KDF"):
            pytest.skip("CKM_TLS_KDF not supported")

        base_key = _create_tls_pms(p11_session)
        try:
            derived = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                32,
                mechanism=Mechanism.TLS_KDF,
                mechanism_param=(
                    Mechanism.SHA256,
                    b"key expansion",
                    _CLIENT_RANDOM + _SERVER_RANDOM,
                ),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.DERIVE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                value = derived[Attribute.VALUE]
                assert len(value) == 32
            finally:
                derived.destroy()
        except _TLS_ERRORS as exc:
            pytest.xfail(f"CKM_TLS_KDF not operational: {exc}")
        finally:
            base_key.destroy()


class TestTLS12Extended:
    """CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE and CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH.

    Extended master secret computation per RFC 7627 prevents triple handshake attacks
    by binding the master secret to the full handshake transcript hash.
    """

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE is advertised."""
        if not has_mechanism(p11_module, "TLS12_EXTENDED_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE not supported")

    def test_extended_master_key_derive(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE with handshake hash."""
        if not has_mechanism(p11_module, "TLS12_EXTENDED_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE not supported")

        pms = _create_tls_pms(p11_session)
        try:
            # CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS includes:
            # - prfHashMechanism (e.g. CKM_SHA256)
            # - pSessionHash: handshake transcript hash (32 bytes for SHA-256)
            # - ulSessionHashLen
            # - pVersion: output TLS version buffer
            # No python-pkcs11 wrapper - attempt will fail.
            session_hash = bytes(range(32))  # simulated SHA-256 handshake hash
            derived = pms.derive_key(
                KeyType.GENERIC_SECRET,
                48,
                mechanism=Mechanism.TLS12_EXTENDED_MASTER_KEY_DERIVE,
                mechanism_param=(Mechanism.SHA256, session_hash),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.DERIVE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                value = derived[Attribute.VALUE]
                assert len(value) == 48, f"Expected 48-byte master secret, got {len(value)}"
            finally:
                derived.destroy()
        except _TLS_ERRORS as exc:
            pytest.xfail(
                f"CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE not operational: {exc}"
            )
        finally:
            pms.destroy()

    def test_extended_master_key_derive_dh_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH is advertised."""
        if not has_mechanism(p11_module, "TLS12_EXTENDED_MASTER_KEY_DERIVE_DH"):
            pytest.skip("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH not supported")

    def test_extended_master_key_derive_dh(self, p11_session: Any, p11_module: Any) -> None:
        """Attempt CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH for DH-based key exchange."""
        if not has_mechanism(p11_module, "TLS12_EXTENDED_MASTER_KEY_DERIVE_DH"):
            pytest.skip("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH not supported")

        # DH shared secret (32 bytes for P-256 ECDH)
        dh_pms = _create_generic_secret(p11_session, bytes(range(32)))
        try:
            session_hash = bytes(range(32))  # simulated SHA-256 handshake hash
            derived = dh_pms.derive_key(
                KeyType.GENERIC_SECRET,
                48,
                mechanism=Mechanism.TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
                mechanism_param=(Mechanism.SHA256, session_hash),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.DERIVE: True,
                    Attribute.TOKEN: False,
                },
            )
            try:
                value = derived[Attribute.VALUE]
                assert len(value) == 48, f"Expected 48-byte master secret, got {len(value)}"
            finally:
                derived.destroy()
        except _TLS_ERRORS as exc:
            pytest.xfail(
                "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH not operational "
                f": {exc}"
            )
        finally:
            dh_pms.destroy()

    def test_different_session_hashes_produce_different_secrets(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Different handshake hashes must yield different extended master secrets."""
        if not has_mechanism(p11_module, "TLS12_EXTENDED_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE not supported")

        pms = _create_tls_pms(p11_session)
        try:
            hash_a = bytes(range(32))
            hash_b = bytes(range(32, 64))
            derive_tmpl = {
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            }
            derived_a = pms.derive_key(
                KeyType.GENERIC_SECRET,
                48,
                mechanism=Mechanism.TLS12_EXTENDED_MASTER_KEY_DERIVE,
                mechanism_param=(Mechanism.SHA256, hash_a),
                template=derive_tmpl,
            )
            try:
                derived_b = pms.derive_key(
                    KeyType.GENERIC_SECRET,
                    48,
                    mechanism=Mechanism.TLS12_EXTENDED_MASTER_KEY_DERIVE,
                    mechanism_param=(Mechanism.SHA256, hash_b),
                    template=derive_tmpl,
                )
                try:
                    val_a = derived_a[Attribute.VALUE]
                    val_b = derived_b[Attribute.VALUE]
                    assert val_a != val_b, "Different session hashes must produce different secrets"
                finally:
                    derived_b.destroy()
            finally:
                derived_a.destroy()
        except _TLS_ERRORS as exc:
            pytest.xfail(
                f"CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE not operational: {exc}"
            )
        finally:
            pms.destroy()



_NEG_ATTR_SCRIPT = """\
import ctypes, sys
from ctypes import byref, cast

from pkcs11_check.raw import CKR_OK
from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, open_session
from pkcs11_check.raw.pack import attr_bool, attr_bytes, attr_ulong, mech_simple, template
from pkcs11_check.raw.types_std import CKF_RW_SESSION, CKF_SERIAL_SESSION, CK_ATTRIBUTE_PTR, CK_OBJECT_HANDLE


def _template_ptr(attrs):
    return cast(attrs.array, CK_ATTRIBUTE_PTR)

raw = RawPKCS11.from_lib("{module}")
raw.C_Initialize(None)
sh = open_session(raw, get_slot_ids(raw)[0], CKF_SERIAL_SESSION | CKF_RW_SESSION)
pin = {pin_arg}
if pin is not None:
    login_user(raw, sh, 1, pin.encode())

{test_code}

raw.C_CloseSession(sh)
raw.C_Finalize(None)
"""


def _run_neg(module: str, pin: str | None, code: str) -> tuple[int, str, str]:
    import os, subprocess, sys, textwrap
    pin_arg = repr(pin) if pin is not None else "None"
    script = _NEG_ATTR_SCRIPT.format(module=module, pin_arg=pin_arg, test_code=textwrap.dedent(code))
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=15,
        env=os.environ.copy(),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestTLSNegativeAttributes:
    """Verify modules reject TLS derive/sign when key attributes are False.

    Uses RawPKCS11 in subprocess to bypass python-pkcs11 wrapper which
    strips derive_key/sign methods from keys with DERIVE=False/SIGN=False.
    """

    @pytest.mark.subprocess
    def test_derive_without_derive_attr(self, p11_config: Any, p11_module: Any) -> None:
        """Key with CKA_DERIVE=False must be rejected by C_DeriveKey."""
        if not has_mechanism(p11_module, "TLS12_MASTER_KEY_DERIVE"):
            if not has_mechanism(p11_module, "TLS_MASTER_KEY_DERIVE"):
                pytest.skip("No TLS master key derive mechanism")

        rc, out, err = _run_neg(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
# Create generic secret key with DERIVE=False
val = bytes(range(48))
attrs = template(
    attr_ulong(0x0000, 4),  # CKA_CLASS = CKO_SECRET_KEY (4)
    attr_ulong(0x0100, 0x10),  # CKA_KEY_TYPE = CKK_GENERIC_SECRET (0x10)
    attr_bytes(0x0011, val),  # CKA_VALUE
    attr_ulong(0x0161, 48),  # CKA_VALUE_LEN
    attr_bool(0x010C, False),  # CKA_DERIVE = FALSE
    attr_bool(0x0001, False),  # CKA_TOKEN = FALSE
    attr_bool(0x0103, False),  # CKA_SENSITIVE = FALSE
    attr_bool(0x0162, True),  # CKA_EXTRACTABLE = TRUE
)
key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(sh, _template_ptr(attrs), attrs.count, byref(key))
if rv != CKR_OK:
    print(f"SKIP:create_failed:0x{rv:08x}")
    sys.exit(0)

# Try C_DeriveKey - should be rejected
mech = mech_simple(0x000003E0)  # CKM_TLS12_MASTER_KEY_DERIVE
out_key = CK_OBJECT_HANDLE(0)
rv = raw.C_DeriveKey(sh, mech.byref(), int(key.value), None, 0, byref(out_key))
print(f"CKR:0x{rv:08x}")
# 0x69 = KEY_FUNCTION_NOT_PERMITTED, 0x70 = MECHANISM_PARAM_INVALID
if rv == 0x69:
    print("OK:KEY_FUNCTION_NOT_PERMITTED")
elif rv == 0:
    print("FAIL:allowed_derive_with_DERIVE_false")
else:
    print(f"REJECTED:0x{rv:08x}")

raw.C_DestroyObject(sh, key.value)
""",
        )
        if "SKIP:" in out:
            pytest.skip(out)
        assert rc == 0, f"Subprocess crashed: {err[-300:]}"
        assert "FAIL:" not in out, f"Module allowed derive with CKA_DERIVE=False"
        # OK or REJECTED with some other CKR - both are acceptable

    @pytest.mark.subprocess
    def test_sign_without_sign_attr(self, p11_config: Any, p11_module: Any) -> None:
        """Key with CKA_SIGN=False must be rejected by C_SignInit."""
        if not has_mechanism(p11_module, "TLS12_MAC"):
            if not has_mechanism(p11_module, "TLS_MAC"):
                pytest.skip("No TLS MAC mechanism")

        rc, out, err = _run_neg(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
# Create generic secret key with SIGN=False
val = bytes(range(32))
attrs = template(
    attr_ulong(0x0000, 4),  # CKA_CLASS = CKO_SECRET_KEY
    attr_ulong(0x0100, 0x10),  # CKA_KEY_TYPE = CKK_GENERIC_SECRET
    attr_bytes(0x0011, val),  # CKA_VALUE
    attr_ulong(0x0161, 32),  # CKA_VALUE_LEN
    attr_bool(0x0108, False),  # CKA_SIGN = FALSE
    attr_bool(0x0001, False),  # CKA_TOKEN = FALSE
    attr_bool(0x0103, False),  # CKA_SENSITIVE = FALSE
    attr_bool(0x0162, True),  # CKA_EXTRACTABLE = TRUE
)
key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(sh, _template_ptr(attrs), attrs.count, byref(key))
if rv != CKR_OK:
    print(f"SKIP:create_failed:0x{rv:08x}")
    sys.exit(0)

# Try C_SignInit with CKA_SIGN=False key
mech = mech_simple(0x000003D8)  # CKM_TLS12_MAC
rv = raw.C_SignInit(sh, mech.byref(), int(key.value))
print(f"CKR:0x{rv:08x}")
if rv == 0x69:
    print("OK:KEY_FUNCTION_NOT_PERMITTED")
elif rv == 0:
    print("FAIL:allowed_sign_with_SIGN_false")
else:
    print(f"REJECTED:0x{rv:08x}")

raw.C_DestroyObject(sh, key.value)
""",
        )
        if "SKIP:" in out:
            pytest.skip(out)
        assert rc == 0, f"Subprocess crashed: {err[-300:]}"
        assert "FAIL:" not in out, f"Module allowed sign with CKA_SIGN=False"
