"""Tests for TLS 1.2 protocol mechanisms.

Covers CKM_TLS12_MASTER_KEY_DERIVE, CKM_TLS12_KEY_AND_MAC_DERIVE,
CKM_TLS12_KEY_SAFE_DERIVE, CKM_TLS12_MAC, CKM_TLS12_KDF,
CKM_TLS_MAC, CKM_TLS_KDF, CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH, and legacy TLS 1.0 mechanisms.

These mechanisms derive keys and MAC keys for TLS 1.2 sessions. They require
complex C parameter structures (CK_TLS12_MASTER_KEY_DERIVE_PARAMS, etc.) that
the raw packers in pkcs11_check.raw.pack provide proper struct packing for.
Availability is tested on all modules; full operational tests xfail because
most tokens do not implement these mechanisms.

OASIS spec: tls_1.2_mechanisms.md
"""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
import sys
import textwrap
from collections.abc import Callable, Mapping
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import (
    attr_ulong,
    mech_bytes,
    mech_ssl3_master_key_derive,
    mech_tls12_extended_master_key_derive,
    mech_tls12_key_mat,
    mech_tls12_master_key_derive,
    mech_tls_kdf,
    mech_tls_mac,
    mech_tls_prf,
    template,
    template_ptr_count,
)
from pkcs11_check.raw.recipes import (
    create_object,
    derive_key,
    destroy_quietly,
    pack_attrs,
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
    CKK_GENERIC_SECRET,
    CKM_SHA256,
    CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
    CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
    CKM_TLS12_KDF,
    CKM_TLS12_KEY_AND_MAC_DERIVE,
    CKM_TLS12_KEY_SAFE_DERIVE,
    CKM_TLS12_MAC,
    CKM_TLS12_MASTER_KEY_DERIVE,
    CKM_TLS12_MASTER_KEY_DERIVE_DH,
    CKM_TLS_KDF,
    CKM_TLS_MAC,
    CKM_TLS_MASTER_KEY_DERIVE,
    CKM_TLS_PRE_MASTER_KEY_GEN,
    CKM_TLS_PRF,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import destroy_returned_handles, is_known_error

pytestmark = pytest.mark.keymgmt

# 48-byte pre-master secret (standard TLS length for RSA key exchange)
_PRE_MASTER_SECRET = bytes(range(48))

# 32-byte random values for client and server randoms
_CLIENT_RANDOM = bytes(range(32))
_SERVER_RANDOM = bytes(range(32, 64))

# CKR values for TLS mechanism operations that fail at the module level
_TLS_ERROR_RVS = {
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_DEVICE_ERROR,
}


def _tls12_prf_sha256(
    secret: bytes,
    label: bytes,
    client_random: bytes,
    server_random: bytes,
    output_len: int,
    *,
    context_data: bytes | None = None,
) -> bytes:
    """Compute the TLS 1.2 PRF output used by CKM_TLS12_KDF tests."""
    if output_len <= 0:
        raise ValueError("output_len must be positive")
    seed = label + client_random + server_random
    if context_data is not None:
        seed += len(context_data).to_bytes(2, "big") + context_data

    output = b""
    a_value = seed
    while len(output) < output_len:
        a_value = hmac.new(secret, a_value, hashlib.sha256).digest()
        output += hmac.new(secret, a_value + seed, hashlib.sha256).digest()
    return output[:output_len]


def _p_hash(
    secret: bytes,
    seed: bytes,
    output_len: int,
    digestmod: Callable[[], Any],
) -> bytes:
    output = bytearray()
    a_value = seed
    while len(output) < output_len:
        a_value = hmac.new(secret, a_value, digestmod).digest()
        output.extend(hmac.new(secret, a_value + seed, digestmod).digest())
    return bytes(output[:output_len])


def _tls12_extended_master_secret_reference(
    secret: bytes,
    session_hash: bytes,
    output_len: int,
) -> bytes:
    """Compute the RFC 7627 TLS 1.2 extended master secret PRF output."""
    if output_len <= 0:
        raise ValueError("output_len must be positive")
    return _p_hash(
        secret,
        b"extended master secret" + session_hash,
        output_len,
        hashlib.sha256,
    )


def _tls_prf_legacy_md5_sha1(
    secret: bytes,
    label: bytes,
    client_random: bytes,
    server_random: bytes,
    output_len: int,
) -> bytes:
    """Compute the RFC 2246 TLS 1.0/1.1 PRF used by CKM_TLS_KDF + CKM_TLS_PRF."""
    if output_len <= 0:
        raise ValueError("output_len must be positive")

    seed = label + client_random + server_random
    split_len = (len(secret) + 1) // 2
    s1 = secret[:split_len]
    s2 = secret[len(secret) - split_len :]
    md5_part = _p_hash(
        s1,
        seed,
        output_len,
        lambda: hashlib.md5(usedforsecurity=False),
    )
    sha1_part = _p_hash(
        s2,
        seed,
        output_len,
        lambda: hashlib.sha1(usedforsecurity=False),
    )
    return bytes(a ^ b for a, b in zip(md5_part, sha1_part, strict=True))


def _create_generic_secret(
    rs: Any,
    data: bytes = _PRE_MASTER_SECRET,
    extra: dict[int, Any] | None = None,
) -> int:
    """Create a GENERIC_SECRET key object for use as TLS keying material."""
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_VALUE: data,
        CKA_DERIVE: True,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
    }
    if extra:
        attrs.update(extra)
    return create_object(rs.raw, rs.sh, attrs)


def _create_tls_pms(rs: Any) -> int:
    """Create a GENERIC_SECRET key simulating a TLS pre-master secret."""
    return _create_generic_secret(rs, _PRE_MASTER_SECRET)


def _derive_key_material_to_params(
    rs: Any,
    base_key: int,
    attrs: Mapping[Any, Any],
    mech: Any,
) -> None:
    """Run TLS key-material derive, whose output handles live in mechanism params."""
    packed = pack_attrs(attrs)
    tmpl = template(*packed)
    rv = rs.raw.C_DeriveKey(
        rs.sh,
        mech.byref(),
        base_key,
        *template_ptr_count(tmpl),
        None,
    )
    expect_rv(rv, CKR_OK)


class TestTLS10PreMasterKeyGen:
    """Legacy TLS 1.0 mechanisms - CKM_TLS_PRE_MASTER_KEY_GEN and related."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS_PRE_MASTER_KEY_GEN is advertised."""
        if not p11_raw_session.has_mechanism("TLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_TLS_PRE_MASTER_KEY_GEN not supported")

    def test_pre_master_key_gen(self, p11_raw_session: Any) -> None:
        """Generate a TLS pre-master secret key via CKM_TLS_PRE_MASTER_KEY_GEN."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS_PRE_MASTER_KEY_GEN"):
            pytest.skip("CKM_TLS_PRE_MASTER_KEY_GEN not supported")

        # TLS version encoded as CK_VERSION: TLS 1.0 = (3, 1)
        ver = CK_VERSION(3, 1)
        mech = mech_bytes(CKM_TLS_PRE_MASTER_KEY_GEN, bytes(ver))
        tmpl = template(
            attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            attr_ulong(CKA_VALUE_LEN, 48),
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_SENSITIVE, 0),
            attr_ulong(CKA_EXTRACTABLE, 1),
            attr_ulong(CKA_DERIVE, 1),
            attr_ulong(CKA_TOKEN, 0),
        )
        key = CK_OBJECT_HANDLE(0)
        try:
            from pkcs11_check.raw.rv import expect_rv

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
                assert len(value) == 48, f"Expected 48-byte pre-master secret, got {len(value)}"
                # First two bytes must match the requested TLS version
                assert value[0] == 3, f"Expected major version 3, got {value[0]}"
                assert value[1] == 1, f"Expected minor version 1, got {value[1]}"
            finally:
                destroy_quietly(rs.raw, rs.sh, key.value)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                pytest.xfail(f"CKM_TLS_PRE_MASTER_KEY_GEN not operational: {exc}")
            raise

    def test_tls_master_key_derive_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS_MASTER_KEY_DERIVE is advertised."""
        if not p11_raw_session.has_mechanism("TLS_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_TLS_MASTER_KEY_DERIVE not supported")

    def test_tls_master_key_derive(self, p11_raw_session: Any) -> None:
        """Attempt CKM_TLS_MASTER_KEY_DERIVE with proper struct params."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_TLS_MASTER_KEY_DERIVE not supported")

        pms = _create_tls_pms(rs)
        try:
            mech = mech_ssl3_master_key_derive(
                CKM_TLS_MASTER_KEY_DERIVE,
                _CLIENT_RANDOM,
                _SERVER_RANDOM,
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                pms,
                CKM_TLS_MASTER_KEY_DERIVE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 48,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_DERIVE: True,
                    CKA_TOKEN: False,
                },
                mech_param=mech,
            )
            try:
                value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(value, bytes)
                assert len(value) == 48, f"Expected 48-byte master secret, got {len(value)}"
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                pytest.xfail(f"CKM_TLS_MASTER_KEY_DERIVE not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pms)

    def test_tls_key_and_mac_derive_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS_KEY_AND_MAC_DERIVE is advertised."""
        if not p11_raw_session.has_mechanism("TLS_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_TLS_KEY_AND_MAC_DERIVE not supported")

    def test_tls_master_key_derive_dh_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS_MASTER_KEY_DERIVE_DH is advertised."""
        if not p11_raw_session.has_mechanism("TLS_MASTER_KEY_DERIVE_DH"):
            pytest.skip("CKM_TLS_MASTER_KEY_DERIVE_DH not supported")

    def test_tls_prf_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS_PRF is advertised."""
        if not p11_raw_session.has_mechanism("TLS_PRF"):
            pytest.skip("CKM_TLS_PRF not supported")

    def test_tls_prf(self, p11_raw_session: Any) -> None:
        """Attempt CKM_TLS_PRF to derive pseudorandom data."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS_PRF"):
            pytest.skip("CKM_TLS_PRF not supported")

        pms = _create_tls_pms(rs)
        try:
            mech = mech_tls_prf(
                CKM_TLS_PRF,
                seed=_CLIENT_RANDOM + _SERVER_RANDOM,
                label=b"master secret",
                output_len=48,
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                pms,
                CKM_TLS_PRF,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 48,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_DERIVE: True,
                    CKA_TOKEN: False,
                },
                mech_param=mech,
            )
            try:
                value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(value, bytes)
                assert len(value) == 48
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                pytest.xfail(f"CKM_TLS_PRF not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pms)


class TestTLS12MasterKeyDerive:
    """CKM_TLS12_MASTER_KEY_DERIVE and CKM_TLS12_MASTER_KEY_DERIVE_DH."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS12_MASTER_KEY_DERIVE is advertised."""
        if not p11_raw_session.has_mechanism("TLS12_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_TLS12_MASTER_KEY_DERIVE not supported")

    def test_master_key_derive(self, p11_raw_session: Any) -> None:
        """Attempt CKM_TLS12_MASTER_KEY_DERIVE with proper struct params."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS12_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_TLS12_MASTER_KEY_DERIVE not supported")

        pms = _create_tls_pms(rs)
        try:
            mech = mech_tls12_master_key_derive(
                CKM_TLS12_MASTER_KEY_DERIVE,
                _CLIENT_RANDOM,
                _SERVER_RANDOM,
                hash_mech=CKM_SHA256,
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                pms,
                CKM_TLS12_MASTER_KEY_DERIVE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 48,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_DERIVE: True,
                    CKA_TOKEN: False,
                },
                mech_param=mech,
            )
            try:
                value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(value, bytes)
                assert len(value) == 48, f"Expected 48-byte master secret, got {len(value)}"
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                pytest.xfail(f"CKM_TLS12_MASTER_KEY_DERIVE not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pms)

    def test_master_key_derive_dh_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS12_MASTER_KEY_DERIVE_DH is advertised."""
        if not p11_raw_session.has_mechanism("TLS12_MASTER_KEY_DERIVE_DH"):
            pytest.skip("CKM_TLS12_MASTER_KEY_DERIVE_DH not supported")

    def test_master_key_derive_dh(self, p11_raw_session: Any) -> None:
        """Attempt CKM_TLS12_MASTER_KEY_DERIVE_DH for DH-based key exchange."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS12_MASTER_KEY_DERIVE_DH"):
            pytest.skip("CKM_TLS12_MASTER_KEY_DERIVE_DH not supported")

        dh_pms = _create_generic_secret(rs, bytes(range(32)))
        try:
            mech = mech_tls12_master_key_derive(
                CKM_TLS12_MASTER_KEY_DERIVE_DH,
                _CLIENT_RANDOM,
                _SERVER_RANDOM,
                hash_mech=CKM_SHA256,
                with_version=False,
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                dh_pms,
                CKM_TLS12_MASTER_KEY_DERIVE_DH,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 48,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_DERIVE: True,
                    CKA_TOKEN: False,
                },
                mech_param=mech,
            )
            try:
                value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(value, bytes)
                assert len(value) == 48, f"Expected 48-byte master secret, got {len(value)}"
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                pytest.xfail(f"CKM_TLS12_MASTER_KEY_DERIVE_DH not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, dh_pms)


class TestTLS12KeyAndMacDerive:
    """CKM_TLS12_KEY_AND_MAC_DERIVE and CKM_TLS12_KEY_SAFE_DERIVE."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS12_KEY_AND_MAC_DERIVE is advertised."""
        if not p11_raw_session.has_mechanism("TLS12_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_TLS12_KEY_AND_MAC_DERIVE not supported")

    def test_key_and_mac_derive(self, p11_raw_session: Any) -> None:
        """Attempt CKM_TLS12_KEY_AND_MAC_DERIVE - derives client/server key material."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS12_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_TLS12_KEY_AND_MAC_DERIVE not supported")

        master_secret = _create_tls_pms(rs)
        try:
            mech = mech_tls12_key_mat(
                CKM_TLS12_KEY_AND_MAC_DERIVE,
                _CLIENT_RANDOM,
                _SERVER_RANDOM,
                hash_mech=CKM_SHA256,
                key_size_bits=128,
            )
            _derive_key_material_to_params(
                rs,
                master_secret,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_DERIVE: True,
                    CKA_TOKEN: False,
                },
                mech=mech,
            )
            try:
                out = mech.key_mat_out
                assert out.hClientKey != 0
                assert out.hServerKey != 0
                assert any(mech.buffer_bytes("iv_client"))
                assert any(mech.buffer_bytes("iv_server"))
            finally:
                out = mech.key_mat_out
                destroy_returned_handles(
                    rs,
                    out.hClientMacSecret,
                    out.hServerMacSecret,
                    out.hClientKey,
                    out.hServerKey,
                )
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                pytest.xfail(f"CKM_TLS12_KEY_AND_MAC_DERIVE not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, master_secret)

    def test_key_safe_derive_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS12_KEY_SAFE_DERIVE is advertised."""
        if not p11_raw_session.has_mechanism("TLS12_KEY_SAFE_DERIVE"):
            pytest.skip("CKM_TLS12_KEY_SAFE_DERIVE not supported")

    def test_key_safe_derive(self, p11_raw_session: Any) -> None:
        """Attempt CKM_TLS12_KEY_SAFE_DERIVE - safe variant of key-and-MAC derive."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS12_KEY_SAFE_DERIVE"):
            pytest.skip("CKM_TLS12_KEY_SAFE_DERIVE not supported")

        master_secret = _create_tls_pms(rs)
        try:
            mech = mech_tls12_key_mat(
                CKM_TLS12_KEY_SAFE_DERIVE,
                _CLIENT_RANDOM,
                _SERVER_RANDOM,
                hash_mech=CKM_SHA256,
                key_size_bits=128,
                iv_size_bits=0,
            )
            _derive_key_material_to_params(
                rs,
                master_secret,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_DERIVE: True,
                    CKA_TOKEN: False,
                },
                mech=mech,
            )
            try:
                out = mech.key_mat_out
                assert out.hClientKey != 0
                assert out.hServerKey != 0
            finally:
                out = mech.key_mat_out
                destroy_returned_handles(
                    rs,
                    out.hClientMacSecret,
                    out.hServerMacSecret,
                    out.hClientKey,
                    out.hServerKey,
                )
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                pytest.xfail(f"CKM_TLS12_KEY_SAFE_DERIVE not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, master_secret)


class TestTLS12Mac:
    """CKM_TLS12_MAC and CKM_TLS_MAC - TLS MAC computation mechanisms."""

    def test_tls12_mac_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS12_MAC is advertised."""
        if not p11_raw_session.has_mechanism("TLS12_MAC"):
            pytest.skip("CKM_TLS12_MAC not supported")

    def test_tls12_mac(self, p11_raw_session: Any) -> None:
        """Attempt CKM_TLS12_MAC to compute a TLS 1.2 MAC."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS12_MAC"):
            pytest.skip("CKM_TLS12_MAC not supported")

        mac_key = _create_generic_secret(rs, bytes(range(32)), {CKA_SIGN: True})
        try:
            mech = mech_tls_mac(CKM_TLS12_MAC, CKM_SHA256, 32, 1)
            result = sign_single(
                rs.raw,
                rs.sh,
                mac_key,
                CKM_TLS12_MAC,
                b"TLS record data",
                mech_param=mech,
            )
            assert len(result) > 0
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                pytest.xfail(f"CKM_TLS12_MAC not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, mac_key)

    def test_tls_mac_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS_MAC is advertised."""
        if not p11_raw_session.has_mechanism("TLS_MAC"):
            pytest.skip("CKM_TLS_MAC not supported")

    def test_tls_mac(self, p11_raw_session: Any) -> None:
        """Attempt CKM_TLS_MAC to compute a TLS MAC."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS_MAC"):
            pytest.skip("CKM_TLS_MAC not supported")

        mac_key = _create_generic_secret(rs, bytes(range(32)), {CKA_SIGN: True})
        try:
            mech = mech_tls_mac(CKM_TLS_MAC, CKM_SHA256, 32, 1)
            result = sign_single(
                rs.raw,
                rs.sh,
                mac_key,
                CKM_TLS_MAC,
                b"TLS record data",
                mech_param=mech,
            )
            assert len(result) > 0
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                pytest.xfail(f"CKM_TLS_MAC not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, mac_key)


class TestTLS12KDF:
    """CKM_TLS12_KDF and CKM_TLS_KDF - TLS key derivation function mechanisms."""

    def test_tls12_kdf_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS12_KDF is advertised."""
        if not p11_raw_session.has_mechanism("TLS12_KDF"):
            pytest.skip("CKM_TLS12_KDF not supported")

    def test_tls12_kdf(self, p11_raw_session: Any) -> None:
        """Attempt CKM_TLS12_KDF to derive keying material."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS12_KDF"):
            pytest.skip("CKM_TLS12_KDF not supported")

        base_key = _create_tls_pms(rs)
        try:
            mech = mech_tls_kdf(
                CKM_TLS12_KDF,
                prf_mechanism=CKM_SHA256,
                label=b"key expansion",
                client_random=_CLIENT_RANDOM,
                server_random=_SERVER_RANDOM,
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                base_key,
                CKM_TLS12_KDF,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 32,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_DERIVE: True,
                    CKA_TOKEN: False,
                },
                mech_param=mech,
            )
            try:
                value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(value, bytes)
                expected = _tls12_prf_sha256(
                    _PRE_MASTER_SECRET,
                    b"key expansion",
                    _CLIENT_RANDOM,
                    _SERVER_RANDOM,
                    32,
                )
                assert value == expected, (
                    "CKM_TLS12_KDF output mismatch: "
                    f"got {value.hex()}, expected {expected.hex()}"
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                pytest.xfail(f"CKM_TLS12_KDF not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_tls_kdf_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS_KDF is advertised."""
        if not p11_raw_session.has_mechanism("TLS_KDF"):
            pytest.skip("CKM_TLS_KDF not supported")

    def test_tls_kdf(self, p11_raw_session: Any) -> None:
        """Attempt CKM_TLS_KDF to derive keying material."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS_KDF"):
            pytest.skip("CKM_TLS_KDF not supported")

        base_key = _create_tls_pms(rs)
        try:
            mech = mech_tls_kdf(
                CKM_TLS_KDF,
                prf_mechanism=CKM_SHA256,
                label=b"key expansion",
                client_random=_CLIENT_RANDOM,
                server_random=_SERVER_RANDOM,
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                base_key,
                CKM_TLS_KDF,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 32,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_DERIVE: True,
                    CKA_TOKEN: False,
                },
                mech_param=mech,
            )
            try:
                value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(value, bytes)
                assert len(value) == 32
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                pytest.xfail(f"CKM_TLS_KDF not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_tls_kdf_tls10_prf_exact_vector(self, p11_raw_session: Any) -> None:
        """CKM_TLS_KDF follows the RFC 2246 TLS1.0/1.1 PRF when prfMechanism is TLS_PRF."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS_KDF"):
            pytest.skip("CKM_TLS_KDF not supported")

        base_key = _create_tls_pms(rs)
        try:
            mech = mech_tls_kdf(
                CKM_TLS_KDF,
                prf_mechanism=CKM_TLS_PRF,
                label=b"key expansion",
                client_random=_CLIENT_RANDOM,
                server_random=_SERVER_RANDOM,
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                base_key,
                CKM_TLS_KDF,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 32,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_DERIVE: True,
                    CKA_TOKEN: False,
                },
                mech_param=mech,
            )
            try:
                value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(value, bytes)
                expected = _tls_prf_legacy_md5_sha1(
                    _PRE_MASTER_SECRET,
                    b"key expansion",
                    _CLIENT_RANDOM,
                    _SERVER_RANDOM,
                    32,
                )
                assert value == expected, (
                    "CKM_TLS_KDF TLS1.0/1.1 PRF output mismatch: "
                    f"got {value.hex()}, expected {expected.hex()}"
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                pytest.xfail(f"CKM_TLS_KDF TLS1.0/1.1 exact vector not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)


class TestTLS12Extended:
    """CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE and DH variant.

    Extended master secret computation per RFC 7627 prevents triple handshake
    attacks by binding the master secret to the full handshake transcript hash.
    """

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE is advertised."""
        if not p11_raw_session.has_mechanism("TLS12_EXTENDED_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE not supported")

    def test_extended_master_key_derive(self, p11_raw_session: Any) -> None:
        """Attempt CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE with handshake hash."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS12_EXTENDED_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE not supported")

        pms = _create_tls_pms(rs)
        try:
            session_hash = bytes(range(32))  # simulated SHA-256 handshake hash
            mech = mech_tls12_extended_master_key_derive(
                CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
                hash_mech=CKM_SHA256,
                session_hash=session_hash,
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                pms,
                CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 48,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_DERIVE: True,
                    CKA_TOKEN: False,
                },
                mech_param=mech,
            )
            try:
                value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(value, bytes)
                assert len(value) == 48, f"Expected 48-byte master secret, got {len(value)}"
                expected = _tls12_extended_master_secret_reference(
                    _PRE_MASTER_SECRET,
                    session_hash,
                    48,
                )
                assert value == expected, (
                    "TLS 1.2 extended master secret output mismatch: "
                    f"got {value.hex()}, expected {expected.hex()}"
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                pytest.xfail(f"CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pms)

    def test_extended_master_key_derive_dh_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH is advertised."""
        if not p11_raw_session.has_mechanism("TLS12_EXTENDED_MASTER_KEY_DERIVE_DH"):
            pytest.skip("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH not supported")

    def test_extended_master_key_derive_dh(self, p11_raw_session: Any) -> None:
        """Attempt CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH for DH-based key exchange."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS12_EXTENDED_MASTER_KEY_DERIVE_DH"):
            pytest.skip("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH not supported")

        dh_pms = _create_generic_secret(rs, bytes(range(32)))
        try:
            session_hash = bytes(range(32))
            mech = mech_tls12_extended_master_key_derive(
                CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
                hash_mech=CKM_SHA256,
                session_hash=session_hash,
                with_version=False,
            )
            derived = derive_key(
                rs.raw,
                rs.sh,
                dh_pms,
                CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 48,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_DERIVE: True,
                    CKA_TOKEN: False,
                },
                mech_param=mech,
            )
            try:
                value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
                assert isinstance(value, bytes)
                assert len(value) == 48, f"Expected 48-byte master secret, got {len(value)}"
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                pytest.xfail(f"CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, dh_pms)

    def test_different_session_hashes_produce_different_secrets(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Different handshake hashes must yield different extended master secrets."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS12_EXTENDED_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE not supported")

        pms = _create_tls_pms(rs)
        try:
            hash_a = bytes(range(32))
            hash_b = bytes(range(32, 64))
            derive_attrs: dict[int, Any] = {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_VALUE_LEN: 48,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            }
            mech_a = mech_tls12_extended_master_key_derive(
                CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
                hash_mech=CKM_SHA256,
                session_hash=hash_a,
            )
            derived_a = derive_key(
                rs.raw,
                rs.sh,
                pms,
                CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
                attrs=derive_attrs,
                mech_param=mech_a,
            )
            try:
                mech_b = mech_tls12_extended_master_key_derive(
                    CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
                    hash_mech=CKM_SHA256,
                    session_hash=hash_b,
                )
                derived_b = derive_key(
                    rs.raw,
                    rs.sh,
                    pms,
                    CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
                    attrs=derive_attrs,
                    mech_param=mech_b,
                )
                try:
                    val_a = read_attributes(rs.raw, rs.sh, derived_a, [CKA_VALUE])[CKA_VALUE]
                    val_b = read_attributes(rs.raw, rs.sh, derived_b, [CKA_VALUE])[CKA_VALUE]
                    assert val_a != val_b, "Different session hashes must produce different secrets"
                finally:
                    destroy_quietly(rs.raw, rs.sh, derived_b)
            finally:
                destroy_quietly(rs.raw, rs.sh, derived_a)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                pytest.xfail(f"CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE not operational: {exc}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pms)


_NEG_ATTR_SCRIPT = """\
import ctypes, sys
from ctypes import byref, cast

from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.types_std import CKR_OK
from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, open_session
from pkcs11_check.raw.pack import attr_bool, attr_bytes, attr_ulong, mech_simple, template
from pkcs11_check.raw.types_std import (
    CKF_RW_SESSION, CKF_SERIAL_SESSION, CK_ATTRIBUTE_PTR, CK_OBJECT_HANDLE,
    CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_NOT_WRAPPABLE,
)


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
    pin_arg = repr(pin) if pin is not None else "None"
    script = _NEG_ATTR_SCRIPT.format(
        module=module,
        pin_arg=pin_arg,
        test_code=textwrap.dedent(code),
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=15,
        env=os.environ.copy(),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestTLSNegativeAttributes:
    """Verify modules reject TLS derive/sign when key attributes are False.

    Uses RawPKCS11 in subprocess to bypass python-pkcs11 wrapper which
    strips derive_key/sign methods from keys with DERIVE=False/SIGN=False.
    """

    @pytest.mark.subprocess
    def test_derive_without_derive_attr(self, p11_config: Any, p11_raw_session: Any) -> None:
        """Key with CKA_DERIVE=False must be rejected by C_DeriveKey."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS12_MASTER_KEY_DERIVE"):
            if not rs.has_mechanism("TLS_MASTER_KEY_DERIVE"):
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
rv = raw.C_DeriveKey(sh, mech.byref(), key.value, None, 0, byref(out_key))
print(f"CKR:0x{rv:08x}")
if rv in (CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_NOT_WRAPPABLE):
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
        assert "FAIL:" not in out, "Module allowed derive with CKA_DERIVE=False"

    @pytest.mark.subprocess
    def test_sign_without_sign_attr(self, p11_config: Any, p11_raw_session: Any) -> None:
        """Key with CKA_SIGN=False must be rejected by C_SignInit."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS12_MAC"):
            if not rs.has_mechanism("TLS_MAC"):
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
rv = raw.C_SignInit(sh, mech.byref(), key.value)
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
        assert "FAIL:" not in out, "Module allowed sign with CKA_SIGN=False"
