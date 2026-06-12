"""Tests for SSL3 protocol mechanisms.

Covers CKM_SSL3_PRE_MASTER_KEY_GEN, CKM_SSL3_MASTER_KEY_DERIVE,
CKM_SSL3_KEY_AND_MAC_DERIVE, CKM_SSL3_MASTER_KEY_DERIVE_DH,
CKM_SSL3_MD5_MAC, and CKM_SSL3_SHA1_MAC.

These are legacy SSL 3.0 mechanisms. Most modern tokens (SoftHSM2, Kryoptic)
do not support them. Tests skip cleanly via has_mechanism() when unsupported.

CKM_SSL3_MASTER_KEY_DERIVE and CKM_SSL3_KEY_AND_MAC_DERIVE require nested C
parameter structures (CK_SSL3_RANDOM_DATA, CK_SSL3_MASTER_KEY_DERIVE_PARAMS,
CK_SSL3_KEY_MAT_PARAMS). The raw packers in pkcs11_check.raw.pack provide
proper struct packing for these.

OASIS spec: ssl.md
"""

from __future__ import annotations

import ctypes
import hashlib
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import (
    attr_ulong,
    mech_bytes,
    mech_ssl3_key_mat,
    mech_ssl3_master_key_derive,
    template,
)
from pkcs11_check.raw.recipes import (
    create_object,
    derive_key,
    destroy_quietly,
    read_attributes,
    sign_single,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_VERSION,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_SSL3_KEY_AND_MAC_DERIVE,
    CKM_SSL3_MASTER_KEY_DERIVE,
    CKM_SSL3_MASTER_KEY_DERIVE_DH,
    CKM_SSL3_MD5_MAC,
    CKM_SSL3_PRE_MASTER_KEY_GEN,
    CKM_SSL3_SHA1_MAC,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import destroy_returned_handles, is_known_error

pytestmark = pytest.mark.keymgmt

# SSL 3.0 client/server random values (28 bytes each per spec)
_CLIENT_RANDOM = bytes(range(28))
_SERVER_RANDOM = bytes(range(28, 56))

# A 48-byte pre-master secret (SSL3 pre-master key size) with version 3.0 prefix.
_PRE_MASTER_SECRET = b"\x03\x00" + bytes(range(2, 48))

# CKR values acceptable for operations using placeholder/unsupported params
_DERIVE_ERROR_RVS = {
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_OBJECT_HANDLE_INVALID,
}

# CKR values acceptable for MAC sign/verify operations
_MAC_ERROR_RVS = {
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_ARGUMENTS_BAD,
}


def _create_generic_secret(rs: Any, value: bytes) -> int:
    """Import a GENERIC_SECRET key for use as a pre-master or master secret."""
    return create_object(
        rs.raw,
        rs.sh,
        {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_VALUE: value,
            CKA_DERIVE: True,
            CKA_SIGN: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
        },
    )


def _ssl3_master_secret_reference(
    pre_master_secret: bytes,
    client_random: bytes,
    server_random: bytes,
) -> bytes:
    """Compute the SSL3 master_secret from RFC 6101 section 6.1."""
    out = bytearray()
    for pad in (b"A", b"BB", b"CCC"):
        sha = hashlib.sha1(
            pad + pre_master_secret + client_random + server_random,
            usedforsecurity=False,
        ).digest()
        out.extend(
            hashlib.md5(
                pre_master_secret + sha,
                usedforsecurity=False,
            ).digest()
        )
    return bytes(out)


class TestSSL3PreMasterKeyGen:
    """CKM_SSL3_PRE_MASTER_KEY_GEN - generate an SSL3 pre-master secret."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_SSL3_PRE_MASTER_KEY_GEN is advertised."""
        if not p11_raw_session.has_mechanism("SSL3_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_SSL3_PRE_MASTER_KEY_GEN not supported")

    def test_generate_pre_master_key(self, p11_raw_session: Any) -> None:
        """Generate a 48-byte SSL3 pre-master secret with version (3, 0)."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_SSL3_PRE_MASTER_KEY_GEN not supported")

        # The mechanism parameter is CK_VERSION with SSL 3.0 = (3, 0).
        ver = CK_VERSION(3, 0)
        mech = mech_bytes(CKM_SSL3_PRE_MASTER_KEY_GEN, bytes(ver))
        tmpl = template(
            attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            attr_ulong(CKA_VALUE_LEN, 48),
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_SENSITIVE, 0),
            attr_ulong(CKA_EXTRACTABLE, 1),
            attr_ulong(CKA_TOKEN, 0),
            attr_ulong(CKA_DERIVE, 1),
        )
        key = CK_OBJECT_HANDLE(0)
        try:
            rv = rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(key),
            )
            expect_rv(rv, CKR_OK)
            try:
                attrs = read_attributes(rs.raw, rs.sh, key.value, [CKA_VALUE])
                raw_val = attrs[CKA_VALUE]
                assert isinstance(raw_val, bytes)
                assert len(raw_val) == 48, f"Expected 48 bytes, got {len(raw_val)}"
                # First two bytes must encode the version (3, 0)
                assert raw_val[0] == 3, f"Expected major version 3, got {raw_val[0]}"
                assert raw_val[1] == 0, f"Expected minor version 0, got {raw_val[1]}"
            finally:
                destroy_quietly(rs.raw, rs.sh, key.value)
        except AssertionError as exc:
            if is_known_error(exc, _DERIVE_ERROR_RVS):
                pytest.xfail(f"CKM_SSL3_PRE_MASTER_KEY_GEN not operational: {exc}")
            raise

    def test_generate_produces_random_output(self, p11_raw_session: Any) -> None:
        """Two separate pre-master key generations must produce different values."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_SSL3_PRE_MASTER_KEY_GEN not supported")

        ver = CK_VERSION(3, 0)
        mech = mech_bytes(CKM_SSL3_PRE_MASTER_KEY_GEN, bytes(ver))
        tmpl = template(
            attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            attr_ulong(CKA_VALUE_LEN, 48),
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_SENSITIVE, 0),
            attr_ulong(CKA_EXTRACTABLE, 1),
            attr_ulong(CKA_TOKEN, 0),
            attr_ulong(CKA_DERIVE, 1),
        )
        try:
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
                assert val1 != val2, "Two pre-master key generations produced identical output"
            finally:
                destroy_quietly(rs.raw, rs.sh, key2.value)
                destroy_quietly(rs.raw, rs.sh, key1.value)
        except AssertionError as exc:
            if is_known_error(exc, _DERIVE_ERROR_RVS):
                pytest.xfail(f"CKM_SSL3_PRE_MASTER_KEY_GEN not operational: {exc}")
            raise


class TestSSL3MasterKeyDerive:
    """CKM_SSL3_MASTER_KEY_DERIVE - derive master secret from pre-master secret."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_SSL3_MASTER_KEY_DERIVE is advertised."""
        if not p11_raw_session.has_mechanism("SSL3_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_SSL3_MASTER_KEY_DERIVE not supported")

    def test_derive_master_secret(self, p11_raw_session: Any) -> None:
        """Attempt master secret derivation with proper CK_SSL3_MASTER_KEY_DERIVE_PARAMS."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_SSL3_MASTER_KEY_DERIVE not supported")

        pre_master = _create_generic_secret(rs, _PRE_MASTER_SECRET)
        try:
            mech = mech_ssl3_master_key_derive(
                CKM_SSL3_MASTER_KEY_DERIVE,
                _CLIENT_RANDOM,
                _SERVER_RANDOM,
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                pre_master,
                CKM_SSL3_MASTER_KEY_DERIVE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 48,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_TOKEN: False,
                    CKA_DERIVE: True,
                },
                mech_param=mech,
            )
            try:
                raw_val = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(raw_val, bytes)
                assert len(raw_val) == 48, f"Expected 48 bytes, got {len(raw_val)}"
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _DERIVE_ERROR_RVS):
                pytest.xfail(f"CKM_SSL3_MASTER_KEY_DERIVE not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pre_master)

    def test_derive_master_secret_exact_vector(self, p11_raw_session: Any) -> None:
        """CKM_SSL3_MASTER_KEY_DERIVE must match the SSL3 master_secret formula."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_SSL3_MASTER_KEY_DERIVE not supported")

        pre_master = _create_generic_secret(rs, _PRE_MASTER_SECRET)
        expected = _ssl3_master_secret_reference(
            _PRE_MASTER_SECRET,
            _CLIENT_RANDOM,
            _SERVER_RANDOM,
        )
        try:
            mech = mech_ssl3_master_key_derive(
                CKM_SSL3_MASTER_KEY_DERIVE,
                _CLIENT_RANDOM,
                _SERVER_RANDOM,
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                pre_master,
                CKM_SSL3_MASTER_KEY_DERIVE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 48,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_TOKEN: False,
                    CKA_DERIVE: True,
                },
                mech_param=mech,
            )
            try:
                raw_val = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(raw_val, bytes)
                assert raw_val == expected
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _DERIVE_ERROR_RVS):
                pytest.xfail(f"CKM_SSL3_MASTER_KEY_DERIVE not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pre_master)


class TestSSL3MasterKeyDeriveDH:
    """CKM_SSL3_MASTER_KEY_DERIVE_DH - DH variant of SSL3 master key derivation."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_SSL3_MASTER_KEY_DERIVE_DH is advertised."""
        if not p11_raw_session.has_mechanism("SSL3_MASTER_KEY_DERIVE_DH"):
            pytest.skip("CKM_SSL3_MASTER_KEY_DERIVE_DH not supported")

    def test_derive_master_secret_dh(self, p11_raw_session: Any) -> None:
        """Attempt DH-variant master secret derivation with proper struct params."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_MASTER_KEY_DERIVE_DH"):
            pytest.skip("CKM_SSL3_MASTER_KEY_DERIVE_DH not supported")

        pre_master = _create_generic_secret(rs, _PRE_MASTER_SECRET)
        try:
            mech = mech_ssl3_master_key_derive(
                CKM_SSL3_MASTER_KEY_DERIVE_DH,
                _CLIENT_RANDOM,
                _SERVER_RANDOM,
                with_version=False,
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                pre_master,
                CKM_SSL3_MASTER_KEY_DERIVE_DH,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 48,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_TOKEN: False,
                    CKA_DERIVE: True,
                },
                mech_param=mech,
            )
            try:
                raw_val = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(raw_val, bytes)
                assert len(raw_val) == 48, f"Expected 48 bytes, got {len(raw_val)}"
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _DERIVE_ERROR_RVS):
                pytest.xfail(f"CKM_SSL3_MASTER_KEY_DERIVE_DH not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pre_master)


class TestSSL3KeyAndMacDerive:
    """CKM_SSL3_KEY_AND_MAC_DERIVE - derive key material from the SSL3 master secret."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_SSL3_KEY_AND_MAC_DERIVE is advertised."""
        if not p11_raw_session.has_mechanism("SSL3_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_SSL3_KEY_AND_MAC_DERIVE not supported")

    def test_derive_key_material(self, p11_raw_session: Any) -> None:
        """Attempt key material derivation with proper CK_SSL3_KEY_MAT_PARAMS."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_SSL3_KEY_AND_MAC_DERIVE not supported")

        master_secret = _create_generic_secret(rs, _PRE_MASTER_SECRET)
        try:
            mech = mech_ssl3_key_mat(
                CKM_SSL3_KEY_AND_MAC_DERIVE,
                _CLIENT_RANDOM,
                _SERVER_RANDOM,
                key_size_bits=128,
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                master_secret,
                CKM_SSL3_KEY_AND_MAC_DERIVE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_TOKEN: False,
                },
                mech_param=mech,
            )
            try:
                out = mech.key_mat_out
                assert out.hClientKey != 0
                assert out.hServerKey != 0
                assert any(mech.buffer_bytes("iv_client"))
                assert any(mech.buffer_bytes("iv_server"))
                raw_val = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(raw_val, bytes)
                assert len(raw_val) == 16, f"Expected 16 bytes, got {len(raw_val)}"
            finally:
                out = mech.key_mat_out
                destroy_returned_handles(
                    rs,
                    out.hClientMacSecret,
                    out.hServerMacSecret,
                    out.hClientKey,
                    out.hServerKey,
                )
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _DERIVE_ERROR_RVS):
                pytest.xfail(f"CKM_SSL3_KEY_AND_MAC_DERIVE not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, master_secret)


class TestSSL3Mac:
    """CKM_SSL3_MD5_MAC and CKM_SSL3_SHA1_MAC - SSL3 MAC mechanisms.

    These are sign/verify mechanisms. The mechanism parameter is the MAC output
    length in bits (as an integer). SSL3 MD5 MAC produces up to 16 bytes;
    SSL3 SHA1 MAC produces up to 20 bytes.
    """

    def test_mechanism_availability_md5_mac(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_SSL3_MD5_MAC is advertised."""
        if not p11_raw_session.has_mechanism("SSL3_MD5_MAC"):
            pytest.skip("CKM_SSL3_MD5_MAC not supported")

    def test_mechanism_availability_sha1_mac(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_SSL3_SHA1_MAC is advertised."""
        if not p11_raw_session.has_mechanism("SSL3_SHA1_MAC"):
            pytest.skip("CKM_SSL3_SHA1_MAC not supported")

    def test_md5_mac_sign(self, p11_raw_session: Any) -> None:
        """Compute an SSL3 MD5 MAC over test data."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_MD5_MAC"):
            pytest.skip("CKM_SSL3_MD5_MAC not supported")

        key = _create_generic_secret(rs, bytes(range(16)))
        try:
            # mechanism_param is the MAC length in bits (16 bytes = 128 bits)
            mac_len_bytes = (128).to_bytes(ctypes.sizeof(ctypes.c_ulong), "little")
            mac = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SSL3_MD5_MAC,
                b"test handshake data",
                mech_param=mech_bytes(CKM_SSL3_MD5_MAC, mac_len_bytes),
            )
            assert len(mac) == 16, f"Expected 16-byte MD5 MAC, got {len(mac)}"
        except AssertionError as exc:
            if is_known_error(exc, _MAC_ERROR_RVS):
                pytest.xfail(f"CKM_SSL3_MD5_MAC sign not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_md5_mac_deterministic(self, p11_raw_session: Any) -> None:
        """Same key and data must produce the same SSL3 MD5 MAC."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_MD5_MAC"):
            pytest.skip("CKM_SSL3_MD5_MAC not supported")

        key = _create_generic_secret(rs, bytes(range(16)))
        try:
            data = b"ssl3 mac determinism test"
            mac_len_bytes = (128).to_bytes(ctypes.sizeof(ctypes.c_ulong), "little")
            mac1 = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SSL3_MD5_MAC,
                data,
                mech_param=mech_bytes(CKM_SSL3_MD5_MAC, mac_len_bytes),
            )
            mac2 = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SSL3_MD5_MAC,
                data,
                mech_param=mech_bytes(CKM_SSL3_MD5_MAC, mac_len_bytes),
            )
            assert mac1 == mac2, "CKM_SSL3_MD5_MAC produced different MACs for identical input"
        except AssertionError as exc:
            if is_known_error(exc, _MAC_ERROR_RVS):
                pytest.xfail(f"CKM_SSL3_MD5_MAC not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_md5_mac_different_data(self, p11_raw_session: Any) -> None:
        """Different data must produce different SSL3 MD5 MACs."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_MD5_MAC"):
            pytest.skip("CKM_SSL3_MD5_MAC not supported")

        key = _create_generic_secret(rs, bytes(range(16)))
        try:
            mac_len_bytes = (128).to_bytes(ctypes.sizeof(ctypes.c_ulong), "little")
            mac_a = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SSL3_MD5_MAC,
                b"data-alpha",
                mech_param=mech_bytes(CKM_SSL3_MD5_MAC, mac_len_bytes),
            )
            mac_b = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SSL3_MD5_MAC,
                b"data-bravo",
                mech_param=mech_bytes(CKM_SSL3_MD5_MAC, mac_len_bytes),
            )
            assert mac_a != mac_b, "CKM_SSL3_MD5_MAC produced same MAC for different data"
        except AssertionError as exc:
            if is_known_error(exc, _MAC_ERROR_RVS):
                pytest.xfail(f"CKM_SSL3_MD5_MAC not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sha1_mac_sign(self, p11_raw_session: Any) -> None:
        """Compute an SSL3 SHA1 MAC over test data."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_SHA1_MAC"):
            pytest.skip("CKM_SSL3_SHA1_MAC not supported")

        key = _create_generic_secret(rs, bytes(range(20)))
        try:
            mac_len_bytes = (160).to_bytes(ctypes.sizeof(ctypes.c_ulong), "little")
            mac = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SSL3_SHA1_MAC,
                b"test handshake data",
                mech_param=mech_bytes(CKM_SSL3_SHA1_MAC, mac_len_bytes),
            )
            assert len(mac) == 20, f"Expected 20-byte SHA1 MAC, got {len(mac)}"
        except AssertionError as exc:
            if is_known_error(exc, _MAC_ERROR_RVS):
                pytest.xfail(f"CKM_SSL3_SHA1_MAC sign not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sha1_mac_deterministic(self, p11_raw_session: Any) -> None:
        """Same key and data must produce the same SSL3 SHA1 MAC."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_SHA1_MAC"):
            pytest.skip("CKM_SSL3_SHA1_MAC not supported")

        key = _create_generic_secret(rs, bytes(range(20)))
        try:
            data = b"ssl3 sha1 mac determinism test"
            mac_len_bytes = (160).to_bytes(ctypes.sizeof(ctypes.c_ulong), "little")
            mac1 = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SSL3_SHA1_MAC,
                data,
                mech_param=mech_bytes(CKM_SSL3_SHA1_MAC, mac_len_bytes),
            )
            mac2 = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SSL3_SHA1_MAC,
                data,
                mech_param=mech_bytes(CKM_SSL3_SHA1_MAC, mac_len_bytes),
            )
            assert mac1 == mac2, "CKM_SSL3_SHA1_MAC produced different MACs for identical input"
        except AssertionError as exc:
            if is_known_error(exc, _MAC_ERROR_RVS):
                pytest.xfail(f"CKM_SSL3_SHA1_MAC not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sha1_mac_different_data(self, p11_raw_session: Any) -> None:
        """Different data must produce different SSL3 SHA1 MACs."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_SHA1_MAC"):
            pytest.skip("CKM_SSL3_SHA1_MAC not supported")

        key = _create_generic_secret(rs, bytes(range(20)))
        try:
            mac_len_bytes = (160).to_bytes(ctypes.sizeof(ctypes.c_ulong), "little")
            mac_a = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SSL3_SHA1_MAC,
                b"data-alpha",
                mech_param=mech_bytes(CKM_SSL3_SHA1_MAC, mac_len_bytes),
            )
            mac_b = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SSL3_SHA1_MAC,
                b"data-bravo",
                mech_param=mech_bytes(CKM_SSL3_SHA1_MAC, mac_len_bytes),
            )
            assert mac_a != mac_b, "CKM_SSL3_SHA1_MAC produced same MAC for different data"
        except AssertionError as exc:
            if is_known_error(exc, _MAC_ERROR_RVS):
                pytest.xfail(f"CKM_SSL3_SHA1_MAC not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_md5_mac_key_affects_output(self, p11_raw_session: Any) -> None:
        """Different keys must produce different SSL3 MD5 MACs for the same data."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_MD5_MAC"):
            pytest.skip("CKM_SSL3_MD5_MAC not supported")

        key1 = _create_generic_secret(rs, bytes(range(16)))
        key2 = _create_generic_secret(rs, bytes(range(16, 32)))
        try:
            data = b"same data for both keys"
            mac_len_bytes = (128).to_bytes(ctypes.sizeof(ctypes.c_ulong), "little")
            mac1 = sign_single(
                rs.raw,
                rs.sh,
                key1,
                CKM_SSL3_MD5_MAC,
                data,
                mech_param=mech_bytes(CKM_SSL3_MD5_MAC, mac_len_bytes),
            )
            mac2 = sign_single(
                rs.raw,
                rs.sh,
                key2,
                CKM_SSL3_MD5_MAC,
                data,
                mech_param=mech_bytes(CKM_SSL3_MD5_MAC, mac_len_bytes),
            )
            assert mac1 != mac2, "CKM_SSL3_MD5_MAC produced same MAC for different keys"
        except AssertionError as exc:
            if is_known_error(exc, _MAC_ERROR_RVS):
                pytest.xfail(f"CKM_SSL3_MD5_MAC not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key2)
            destroy_quietly(rs.raw, rs.sh, key1)

    def test_sha1_mac_key_affects_output(self, p11_raw_session: Any) -> None:
        """Different keys must produce different SSL3 SHA1 MACs for the same data."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_SHA1_MAC"):
            pytest.skip("CKM_SSL3_SHA1_MAC not supported")

        key1 = _create_generic_secret(rs, bytes(range(20)))
        key2 = _create_generic_secret(rs, bytes(range(20, 40)))
        try:
            data = b"same data for both keys"
            mac_len_bytes = (160).to_bytes(ctypes.sizeof(ctypes.c_ulong), "little")
            mac1 = sign_single(
                rs.raw,
                rs.sh,
                key1,
                CKM_SSL3_SHA1_MAC,
                data,
                mech_param=mech_bytes(CKM_SSL3_SHA1_MAC, mac_len_bytes),
            )
            mac2 = sign_single(
                rs.raw,
                rs.sh,
                key2,
                CKM_SSL3_SHA1_MAC,
                data,
                mech_param=mech_bytes(CKM_SSL3_SHA1_MAC, mac_len_bytes),
            )
            assert mac1 != mac2, "CKM_SSL3_SHA1_MAC produced same MAC for different keys"
        except AssertionError as exc:
            if is_known_error(exc, _MAC_ERROR_RVS):
                pytest.xfail(f"CKM_SSL3_SHA1_MAC not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key2)
            destroy_quietly(rs.raw, rs.sh, key1)
