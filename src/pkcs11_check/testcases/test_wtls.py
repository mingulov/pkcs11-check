"""Tests for WTLS protocol mechanisms.

Covers CKM_WTLS_PRE_MASTER_KEY_GEN, CKM_WTLS_MASTER_KEY_DERIVE,
CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC, CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE, and CKM_WTLS_PRF.

WTLS (Wireless Transport Layer Security) is a legacy protocol from the WAP
specification. These mechanisms are rarely supported by modern tokens and tests
will mostly skip. The raw packers in pkcs11_check.raw.pack provide proper
struct packing for WTLS parameter structures.

OASIS spec: wtls.md
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import (
    attr_ulong,
    mech_simple,
    mech_wtls_key_mat,
    mech_wtls_master_key_derive,
    mech_wtls_prf,
    template,
)
from pkcs11_check.raw.recipes import (
    create_object,
    derive_key,
    destroy_quietly,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_SHA256,
    CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
    CKM_WTLS_MASTER_KEY_DERIVE,
    CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
    CKM_WTLS_PRE_MASTER_KEY_GEN,
    CKM_WTLS_PRF,
    CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
    CKO_SECRET_KEY,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.conftest import destroy_returned_handles, is_known_error

pytestmark = pytest.mark.keymgmt

# Common CKR values for WTLS operations
_WTLS_ERROR_RVS = {
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
}

# WTLS client/server random values (16 bytes each)
_CLIENT_RANDOM = bytes(range(16))
_SERVER_RANDOM = bytes(range(16, 32))


def _create_generic_secret(rs: Any, size: int = 48) -> int:
    """Create a GENERIC_SECRET key for use as WTLS pre-master secret material."""
    value = bytes(range(size % 256)) * (size // 256 + 1)
    return create_object(
        rs.raw,
        rs.sh,
        {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_VALUE: value[:size],
            CKA_VALUE_LEN: size,
            CKA_DERIVE: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
        },
    )


class TestWTLSPreMasterKeyGen:
    """CKM_WTLS_PRE_MASTER_KEY_GEN - generate a WTLS pre-master secret."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_WTLS_PRE_MASTER_KEY_GEN is advertised."""
        if not p11_raw_session.has_mechanism("WTLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_WTLS_PRE_MASTER_KEY_GEN not supported")

    def test_generate_pre_master_key(self, p11_raw_session: Any) -> None:
        """Generate a WTLS pre-master secret key."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_WTLS_PRE_MASTER_KEY_GEN not supported")

        try:
            from ctypes import byref

            from pkcs11_check.raw.rv import expect_rv
            from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE, CKR_OK

            mech = mech_simple(CKM_WTLS_PRE_MASTER_KEY_GEN)
            tmpl = template(
                attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                attr_ulong(CKA_VALUE_LEN, 20),
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_DERIVE, 1),
                attr_ulong(CKA_SENSITIVE, 0),
                attr_ulong(CKA_EXTRACTABLE, 1),
                attr_ulong(CKA_TOKEN, 0),
            )
            key = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(key),
            )
            expect_rv(rv, CKR_OK)
            try:
                assert key.value != 0
                attrs = read_attributes(rs.raw, rs.sh, key.value, [CKA_KEY_TYPE])
                assert attrs[CKA_KEY_TYPE] == CKK_GENERIC_SECRET
            finally:
                destroy_quietly(rs.raw, rs.sh, key.value)
        except AssertionError as exc:
            if is_known_error(exc, _WTLS_ERROR_RVS):
                pytest.xfail(f"CKM_WTLS_PRE_MASTER_KEY_GEN not operational: {exc}")
            raise

    def test_generate_yields_non_zero_material(self, p11_raw_session: Any) -> None:
        """Generated pre-master key must not be all-zero bytes."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_WTLS_PRE_MASTER_KEY_GEN not supported")

        try:
            from ctypes import byref

            from pkcs11_check.raw.rv import expect_rv
            from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE, CKR_OK

            mech = mech_simple(CKM_WTLS_PRE_MASTER_KEY_GEN)
            tmpl = template(
                attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                attr_ulong(CKA_VALUE_LEN, 20),
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_DERIVE, 1),
                attr_ulong(CKA_SENSITIVE, 0),
                attr_ulong(CKA_EXTRACTABLE, 1),
                attr_ulong(CKA_TOKEN, 0),
            )
            key = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(key),
            )
            expect_rv(rv, CKR_OK)
            try:
                value = read_attributes(rs.raw, rs.sh, key.value, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(value, bytes)
                assert value != bytes(len(value)), "Pre-master key must not be all zeros"
            finally:
                destroy_quietly(rs.raw, rs.sh, key.value)
        except AssertionError as exc:
            if is_known_error(exc, _WTLS_ERROR_RVS):
                pytest.xfail(f"CKM_WTLS_PRE_MASTER_KEY_GEN not operational: {exc}")
            raise

    def test_two_generated_keys_differ(self, p11_raw_session: Any) -> None:
        """Two independently generated pre-master keys must differ."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_WTLS_PRE_MASTER_KEY_GEN not supported")

        try:
            from ctypes import byref

            from pkcs11_check.raw.rv import expect_rv
            from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE, CKR_OK

            mech = mech_simple(CKM_WTLS_PRE_MASTER_KEY_GEN)
            tmpl = template(
                attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                attr_ulong(CKA_VALUE_LEN, 20),
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_DERIVE, 1),
                attr_ulong(CKA_SENSITIVE, 0),
                attr_ulong(CKA_EXTRACTABLE, 1),
                attr_ulong(CKA_TOKEN, 0),
            )
            key1 = CK_OBJECT_HANDLE(0)
            key2 = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(key1),
            )
            expect_rv(rv, CKR_OK)
            rv = rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(key2),
            )
            expect_rv(rv, CKR_OK)
            try:
                val1 = read_attributes(rs.raw, rs.sh, key1.value, [CKA_VALUE])[CKA_VALUE]
                val2 = read_attributes(rs.raw, rs.sh, key2.value, [CKA_VALUE])[CKA_VALUE]
                assert val1 != val2, "Two independently generated pre-master keys must differ"
            finally:
                destroy_quietly(rs.raw, rs.sh, key2.value)
                destroy_quietly(rs.raw, rs.sh, key1.value)
        except AssertionError as exc:
            if is_known_error(exc, _WTLS_ERROR_RVS):
                pytest.xfail(f"CKM_WTLS_PRE_MASTER_KEY_GEN not operational: {exc}")
            raise


class TestWTLSMasterKeyDerive:
    """CKM_WTLS_MASTER_KEY_DERIVE - derive WTLS master secret from pre-master secret."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_WTLS_MASTER_KEY_DERIVE is advertised."""
        if not p11_raw_session.has_mechanism("WTLS_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE not supported")

    def test_derive_master_key(self, p11_raw_session: Any) -> None:
        """Attempt to derive a WTLS master key with proper struct params."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE not supported")

        pms = _create_generic_secret(rs, 20)
        try:
            mech = mech_wtls_master_key_derive(
                CKM_WTLS_MASTER_KEY_DERIVE,
                digest_mechanism=CKM_SHA256,
                client_random=_CLIENT_RANDOM,
                server_random=_SERVER_RANDOM,
            )
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    pms,
                    CKM_WTLS_MASTER_KEY_DERIVE,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech_param=mech,
                )
                try:
                    assert derived != 0
                finally:
                    destroy_quietly(rs.raw, rs.sh, derived)
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    pytest.xfail(f"CKM_WTLS_MASTER_KEY_DERIVE not operational: {exc}")
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pms)


class TestWTLSMasterKeyDeriveDHECC:
    """CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC - derive WTLS master secret via DH/ECC."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC is advertised."""
        if not p11_raw_session.has_mechanism("WTLS_MASTER_KEY_DERIVE_DH_ECC"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC not supported")

    def test_derive_master_key_dh_ecc(self, p11_raw_session: Any) -> None:
        """Attempt to derive a WTLS master key using the DH/ECC variant."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_MASTER_KEY_DERIVE_DH_ECC"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC not supported")

        pms = _create_generic_secret(rs, 32)
        try:
            mech = mech_wtls_master_key_derive(
                CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
                digest_mechanism=CKM_SHA256,
                client_random=_CLIENT_RANDOM,
                server_random=_SERVER_RANDOM,
                with_version=False,
            )
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    pms,
                    CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech_param=mech,
                )
                try:
                    assert derived != 0
                finally:
                    destroy_quietly(rs.raw, rs.sh, derived)
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    pytest.xfail(f"CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC not operational: {exc}")
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pms)


class TestWTLSKeyAndMacDerive:
    """CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE and CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE."""

    def test_server_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE is advertised."""
        if not p11_raw_session.has_mechanism("WTLS_SERVER_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not supported")

    def test_client_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE is advertised."""
        if not p11_raw_session.has_mechanism("WTLS_CLIENT_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not supported")

    def test_server_key_and_mac_derive(self, p11_raw_session: Any) -> None:
        """Attempt CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE with proper struct params."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_SERVER_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(rs, 20)
        try:
            mech = mech_wtls_key_mat(
                CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
                digest_mechanism=CKM_SHA256,
                client_random=_CLIENT_RANDOM,
                server_random=_SERVER_RANDOM,
                iv_size_bits=64,
            )
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    master,
                    CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech_param=mech,
                )
                try:
                    out = mech.key_mat_out
                    assert out.hKey != 0
                    assert any(mech.buffer_bytes("iv"))
                    assert derived != 0
                finally:
                    out = mech.key_mat_out
                    destroy_returned_handles(rs, out.hMacSecret, out.hKey)
                    destroy_quietly(rs.raw, rs.sh, derived)
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    pytest.xfail(f"CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not operational: {exc}")
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, master)

    def test_client_key_and_mac_derive(self, p11_raw_session: Any) -> None:
        """Attempt CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE with proper struct params."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_CLIENT_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(rs, 20)
        try:
            mech = mech_wtls_key_mat(
                CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
                digest_mechanism=CKM_SHA256,
                client_random=_CLIENT_RANDOM,
                server_random=_SERVER_RANDOM,
                iv_size_bits=64,
            )
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    master,
                    CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech_param=mech,
                )
                try:
                    out = mech.key_mat_out
                    assert out.hKey != 0
                    assert any(mech.buffer_bytes("iv"))
                    assert derived != 0
                finally:
                    out = mech.key_mat_out
                    destroy_returned_handles(rs, out.hMacSecret, out.hKey)
                    destroy_quietly(rs.raw, rs.sh, derived)
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    pytest.xfail(f"CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not operational: {exc}")
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, master)

    def test_server_and_client_differ(self, p11_raw_session: Any) -> None:
        """Server and client derivation of the same master must produce different keys."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_SERVER_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not supported")
        if not rs.has_mechanism("WTLS_CLIENT_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(rs, 20)
        try:
            server_derived = 0
            client_derived = 0
            try:
                srv_mech = mech_wtls_key_mat(
                    CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
                    digest_mechanism=CKM_SHA256,
                    client_random=_CLIENT_RANDOM,
                    server_random=_SERVER_RANDOM,
                )
                server_derived = derive_key(
                    rs.raw,
                    rs.sh,
                    master,
                    CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech_param=srv_mech,
                )
                cli_mech = mech_wtls_key_mat(
                    CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
                    digest_mechanism=CKM_SHA256,
                    client_random=_CLIENT_RANDOM,
                    server_random=_SERVER_RANDOM,
                )
                client_derived = derive_key(
                    rs.raw,
                    rs.sh,
                    master,
                    CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech_param=cli_mech,
                )
                srv_val = read_attributes(rs.raw, rs.sh, server_derived, [CKA_VALUE])[CKA_VALUE]
                cli_val = read_attributes(rs.raw, rs.sh, client_derived, [CKA_VALUE])[CKA_VALUE]
                assert srv_val != cli_val, (
                    "Server and client key derivation must produce different keys"
                )
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    pytest.xfail(f"WTLS key-and-MAC derivation not operational: {exc}")
                raise
            finally:
                if client_derived:
                    destroy_quietly(rs.raw, rs.sh, client_derived)
                if server_derived:
                    destroy_quietly(rs.raw, rs.sh, server_derived)
        finally:
            destroy_quietly(rs.raw, rs.sh, master)


class TestWTLSPRF:
    """CKM_WTLS_PRF - WTLS pseudo-random function for key material expansion."""

    def _derive_prf_value(self, rs: Any, secret: int, *, seed: bytes) -> tuple[int, bytes]:
        mech = mech_wtls_prf(
            CKM_WTLS_PRF,
            digest_mechanism=CKM_SHA256,
            seed=seed,
            label=b"key expansion",
            output_len=16,
        )
        derived = derive_key(
            rs.raw,
            rs.sh,
            secret,
            CKM_WTLS_PRF,
            attrs={
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_VALUE_LEN: 16,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            },
            mech_param=mech,
        )
        value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
        assert isinstance(value, bytes)
        assert len(value) == 16, f"Expected 16 bytes, got {len(value)}"
        return derived, value

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_WTLS_PRF is advertised."""
        if not p11_raw_session.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

    def test_prf_derive(self, p11_raw_session: Any) -> None:
        """Attempt to use CKM_WTLS_PRF for key derivation with proper struct params."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(rs, 20)
        try:
            mech = mech_wtls_prf(
                CKM_WTLS_PRF,
                digest_mechanism=CKM_SHA256,
                seed=bytes(range(32)),
                label=b"key expansion",
                output_len=16,
            )
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    secret,
                    CKM_WTLS_PRF,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_VALUE_LEN: 16,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech_param=mech,
                )
                try:
                    assert derived != 0
                    value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                    assert isinstance(value, bytes)
                    assert len(value) == 16, f"Expected 16 bytes, got {len(value)}"
                finally:
                    destroy_quietly(rs.raw, rs.sh, derived)
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    pytest.xfail(f"CKM_WTLS_PRF not operational: {exc}")
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, secret)

    def test_prf_seed_affects_output(self, p11_raw_session: Any) -> None:
        """Changing only the WTLS PRF seed must change the derived output."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(rs, 20)
        try:
            derived1 = 0
            derived2 = 0
            try:
                derived1, val1 = self._derive_prf_value(
                    rs,
                    secret,
                    seed=bytes(range(32)),
                )
                derived2, val2 = self._derive_prf_value(
                    rs,
                    secret,
                    seed=bytes(range(1, 33)),
                )
                assert val1 != val2, "WTLS PRF seed change did not affect derived output"
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    pytest.xfail(f"CKM_WTLS_PRF not operational: {exc}")
                raise
            finally:
                if derived2:
                    destroy_quietly(rs.raw, rs.sh, derived2)
                if derived1:
                    destroy_quietly(rs.raw, rs.sh, derived1)
        finally:
            destroy_quietly(rs.raw, rs.sh, secret)

    def test_prf_deterministic(self, p11_raw_session: Any) -> None:
        """Same WTLS PRF inputs must produce the same output."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(rs, 20)
        try:
            derived1 = 0
            derived2 = 0
            try:
                mech1 = mech_wtls_prf(
                    CKM_WTLS_PRF,
                    digest_mechanism=CKM_SHA256,
                    seed=bytes(range(32)),
                    label=b"key expansion",
                    output_len=16,
                )
                derived1 = derive_key(
                    rs.raw,
                    rs.sh,
                    secret,
                    CKM_WTLS_PRF,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_VALUE_LEN: 16,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech_param=mech1,
                )
                mech2 = mech_wtls_prf(
                    CKM_WTLS_PRF,
                    digest_mechanism=CKM_SHA256,
                    seed=bytes(range(32)),
                    label=b"key expansion",
                    output_len=16,
                )
                derived2 = derive_key(
                    rs.raw,
                    rs.sh,
                    secret,
                    CKM_WTLS_PRF,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_VALUE_LEN: 16,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech_param=mech2,
                )
                val1 = read_attributes(rs.raw, rs.sh, derived1, [CKA_VALUE])[CKA_VALUE]
                val2 = read_attributes(rs.raw, rs.sh, derived2, [CKA_VALUE])[CKA_VALUE]
                assert val1 == val2, "CKM_WTLS_PRF must be deterministic for identical inputs"
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    pytest.xfail(f"CKM_WTLS_PRF not operational: {exc}")
                raise
            finally:
                if derived2:
                    destroy_quietly(rs.raw, rs.sh, derived2)
                if derived1:
                    destroy_quietly(rs.raw, rs.sh, derived1)
        finally:
            destroy_quietly(rs.raw, rs.sh, secret)
