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

OASIS PKCS#11 v3.2 spec: TLS 1.2 mechanisms.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Mapping
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import (
    attr_ulong,
    mech_bytes,
    mech_ssl3_key_mat,
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
    CKM_TLS_KEY_AND_MAC_DERIVE,
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
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import (
    assert_correct,
    destroy_returned_handles,
    is_known_error,
    reject_or_classify,
)

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

_TLS_TEMPLATE_CONFLICT_REJECT_RVS = (
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ATTRIBUTE_VALUE_INVALID,
)


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


def _tls12_master_secret_reference(
    secret: bytes,
    client_random: bytes,
    server_random: bytes,
    output_len: int,
) -> bytes:
    """Compute the TLS 1.2 master secret PRF output."""
    return _tls12_prf_sha256(
        secret,
        b"master secret",
        client_random,
        server_random,
        output_len,
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


def _derive_tls_key_material_template_conflict(
    rs: Any,
    base_key: int,
    mech: Any,
    *,
    label: str,
) -> None:
    """Verify TLS key material rejects template protection values that differ."""
    exc: AssertionError | None = None
    try:
        _derive_key_material_to_params(
            rs,
            base_key,
            {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_SENSITIVE: True,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            },
            mech,
        )
    except AssertionError as caught:
        exc = caught
    finally:
        out = mech.key_mat_out
        destroy_returned_handles(
            rs,
            out.hClientMacSecret,
            out.hServerMacSecret,
            out.hClientKey,
            out.hServerKey,
        )

    reject_or_classify(
        exc,
        _TLS_TEMPLATE_CONFLICT_REJECT_RVS,
        label=label,
    )


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
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS_PRE_MASTER_KEY_GEN:C_GenerateKey",
                    operation="C_GenerateKey",
                    mechanism="CKM_TLS_PRE_MASTER_KEY_GEN",
                    summary=f"CKM_TLS_PRE_MASTER_KEY_GEN not operational: {exc}",
                )
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
                expected = _tls_prf_legacy_md5_sha1(
                    _PRE_MASTER_SECRET,
                    b"master secret",
                    _CLIENT_RANDOM,
                    _SERVER_RANDOM,
                    48,
                )
                assert_correct(
                    actual=value,
                    expected=expected,
                    label="CKM_TLS_MASTER_KEY_DERIVE:C_DeriveKey KAT (TLS 1.0/1.1 master secret)",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS_MASTER_KEY_DERIVE",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS_MASTER_KEY_DERIVE:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS_MASTER_KEY_DERIVE",
                    summary=f"CKM_TLS_MASTER_KEY_DERIVE not operational: {exc}",
                )
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pms)

    def test_tls_key_and_mac_derive_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_TLS_KEY_AND_MAC_DERIVE is advertised."""
        if not p11_raw_session.has_mechanism("TLS_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_TLS_KEY_AND_MAC_DERIVE not supported")

    def test_tls_key_and_mac_derive(self, p11_raw_session: Any) -> None:
        """Attempt CKM_TLS_KEY_AND_MAC_DERIVE with CK_SSL3_KEY_MAT_PARAMS."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_TLS_KEY_AND_MAC_DERIVE not supported")

        master_secret = _create_tls_pms(rs)
        try:
            mech = mech_ssl3_key_mat(
                CKM_TLS_KEY_AND_MAC_DERIVE,
                _CLIENT_RANDOM,
                _SERVER_RANDOM,
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
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS_KEY_AND_MAC_DERIVE:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS_KEY_AND_MAC_DERIVE",
                    summary=f"CKM_TLS_KEY_AND_MAC_DERIVE not operational: {exc}",
                )
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, master_secret)

    def test_tls_key_and_mac_rejects_template_protection_conflict(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKM_TLS_KEY_AND_MAC_DERIVE rejects template protection overrides."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_TLS_KEY_AND_MAC_DERIVE not supported")

        master_secret = _create_tls_pms(rs)
        try:
            mech = mech_ssl3_key_mat(
                CKM_TLS_KEY_AND_MAC_DERIVE,
                _CLIENT_RANDOM,
                _SERVER_RANDOM,
                key_size_bits=128,
            )
            _derive_tls_key_material_template_conflict(
                rs,
                master_secret,
                mech,
                label="CKM_TLS_KEY_AND_MAC_DERIVE template protection conflict",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, master_secret)

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
                expected = _tls_prf_legacy_md5_sha1(
                    _PRE_MASTER_SECRET,
                    b"master secret",
                    _CLIENT_RANDOM,
                    _SERVER_RANDOM,
                    48,
                )
                assert_correct(
                    actual=value,
                    expected=expected,
                    label="CKM_TLS_PRF:C_DeriveKey KAT",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS_PRF",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS_PRF:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS_PRF",
                    summary=f"CKM_TLS_PRF not operational: {exc}",
                )
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
                expected = _tls12_master_secret_reference(
                    _PRE_MASTER_SECRET,
                    _CLIENT_RANDOM,
                    _SERVER_RANDOM,
                    48,
                )
                assert_correct(
                    actual=value,
                    expected=expected,
                    label="CKM_TLS12_MASTER_KEY_DERIVE:C_DeriveKey KAT (TLS 1.2 master secret)",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_MASTER_KEY_DERIVE",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS12_MASTER_KEY_DERIVE:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_MASTER_KEY_DERIVE",
                    summary=f"CKM_TLS12_MASTER_KEY_DERIVE not operational: {exc}",
                )
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
                expected = _tls12_master_secret_reference(
                    bytes(range(32)),
                    _CLIENT_RANDOM,
                    _SERVER_RANDOM,
                    48,
                )
                assert_correct(
                    actual=value,
                    expected=expected,
                    label=(
                        "CKM_TLS12_MASTER_KEY_DERIVE_DH:C_DeriveKey KAT (TLS 1.2 master secret DH)"
                    ),
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_MASTER_KEY_DERIVE_DH",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS12_MASTER_KEY_DERIVE_DH:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_MASTER_KEY_DERIVE_DH",
                    summary=f"CKM_TLS12_MASTER_KEY_DERIVE_DH not operational: {exc}",
                )
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
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS12_KEY_AND_MAC_DERIVE:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_KEY_AND_MAC_DERIVE",
                    summary=f"CKM_TLS12_KEY_AND_MAC_DERIVE not operational: {exc}",
                )
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, master_secret)

    def test_key_and_mac_rejects_template_protection_conflict(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKM_TLS12_KEY_AND_MAC_DERIVE rejects template protection overrides."""
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
            _derive_tls_key_material_template_conflict(
                rs,
                master_secret,
                mech,
                label="CKM_TLS12_KEY_AND_MAC_DERIVE template protection conflict",
            )
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
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS12_KEY_SAFE_DERIVE:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_KEY_SAFE_DERIVE",
                    summary=f"CKM_TLS12_KEY_SAFE_DERIVE not operational: {exc}",
                )
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, master_secret)

    def test_key_safe_derive_ignores_iv_size_request(self, p11_raw_session: Any) -> None:
        """CKM_TLS12_KEY_SAFE_DERIVE must not return IV material."""
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
                iv_size_bits=128,
            )
            client_sentinel = bytes([0xA5]) * 16
            server_sentinel = bytes([0x5A]) * 16
            client_storage, client_len = mech.buffer_storage("iv_client")
            server_storage, server_len = mech.buffer_storage("iv_server")
            assert client_len == len(client_sentinel)
            assert server_len == len(server_sentinel)
            for idx, value in enumerate(client_sentinel):
                client_storage[idx] = value
            for idx, value in enumerate(server_sentinel):
                server_storage[idx] = value

            try:
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
                out = mech.key_mat_out
                assert out.hClientKey != 0
                assert out.hServerKey != 0
                assert (
                    mech.buffer_bytes("iv_client") == client_sentinel
                    and mech.buffer_bytes("iv_server") == server_sentinel
                ), "CKM_TLS12_KEY_SAFE_DERIVE wrote IV material despite key-safe semantics"
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
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS12_KEY_SAFE_DERIVE:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_KEY_SAFE_DERIVE",
                    summary=f"CKM_TLS12_KEY_SAFE_DERIVE not operational: {exc}",
                )
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, master_secret)

    def test_key_safe_rejects_template_protection_conflict(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKM_TLS12_KEY_SAFE_DERIVE rejects template protection overrides."""
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
            _derive_tls_key_material_template_conflict(
                rs,
                master_secret,
                mech,
                label="CKM_TLS12_KEY_SAFE_DERIVE template protection conflict",
            )
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
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS12_MAC:C_Sign",
                    operation="C_Sign",
                    mechanism="CKM_TLS12_MAC",
                    summary=f"CKM_TLS12_MAC not operational: {exc}",
                )
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
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS_MAC:C_Sign",
                    operation="C_Sign",
                    mechanism="CKM_TLS_MAC",
                    summary=f"CKM_TLS_MAC not operational: {exc}",
                )
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
                assert_correct(
                    actual=value,
                    expected=expected,
                    label="CKM_TLS12_KDF:C_DeriveKey KAT",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_KDF",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS12_KDF:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_KDF",
                    summary=f"CKM_TLS12_KDF not operational: {exc}",
                )
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)

    def test_tls12_kdf_context_data_exact_vector(self, p11_raw_session: Any) -> None:
        """CKM_TLS12_KDF includes RFC 5705 context data in the TLS 1.2 PRF seed."""
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
                context_data=b"context-info",
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
                    context_data=b"context-info",
                )
                assert_correct(
                    actual=value,
                    expected=expected,
                    label="CKM_TLS12_KDF:C_DeriveKey KAT (context-data exact vector)",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_KDF",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS12_KDF:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_KDF",
                    summary=f"CKM_TLS12_KDF context-data exact vector not operational: {exc}",
                )
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
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS_KDF:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS_KDF",
                    summary=f"CKM_TLS_KDF not operational: {exc}",
                )
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
                assert_correct(
                    actual=value,
                    expected=expected,
                    label="CKM_TLS_KDF:C_DeriveKey KAT (TLS 1.0/1.1 PRF exact vector)",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS_KDF",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS_KDF:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS_KDF",
                    summary=f"CKM_TLS_KDF TLS1.0/1.1 exact vector not operational: {exc}",
                )
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
                assert_correct(
                    actual=value,
                    expected=expected,
                    label=(
                        "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE:C_DeriveKey KAT "
                        "(extended master secret)"
                    ),
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE",
                    summary=f"CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE not operational: {exc}",
                )
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
                expected = _tls12_extended_master_secret_reference(
                    bytes(range(32)),
                    session_hash,
                    48,
                )
                assert_correct(
                    actual=value,
                    expected=expected,
                    label=(
                        "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH:C_DeriveKey KAT "
                        "(extended master secret DH)"
                    ),
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, derived)
        except AssertionError as exc:
            if is_known_error(exc, _TLS_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH",
                    summary=f"CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH not operational: {exc}",
                )
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
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE",
                    summary=f"CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE not operational: {exc}",
                )
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pms)


def _run_neg(p11_config: Any, probe: str) -> tuple[int, str, str]:
    """Run a TLS negative-attribute probe; return ``(returncode, stdout, stderr)`` (stripped).

    The child body lives in ``_probes/tls12.py``, dispatched on ``extra["probe"]``.  The PIN
    travels ONLY via ``run_probe(pin=...)`` -> ``_P11CHECK_PIN`` env (Invariant I3); it is
    never embedded in the probe params or source.  Coverage routes to the session accumulator;
    rv-trace is recorded by ``run_probe`` (I7).
    """
    result = run_probe(
        "tls12",
        {"module_path": str(p11_config.module), "probe": probe},
        pin=pin_from_config(p11_config),
        timeout=15,
        coverage="session",
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

        rc, out, err = _run_neg(p11_config, "derive_without_derive_attr")
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

        rc, out, err = _run_neg(p11_config, "sign_without_sign_attr")
        if "SKIP:" in out:
            pytest.skip(out)
        assert rc == 0, f"Subprocess crashed: {err[-300:]}"
        assert "FAIL:" not in out, "Module allowed sign with CKA_SIGN=False"
