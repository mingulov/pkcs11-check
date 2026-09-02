"""Tests for WTLS protocol mechanisms.

Covers CKM_WTLS_PRE_MASTER_KEY_GEN, CKM_WTLS_MASTER_KEY_DERIVE,
CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC, CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE, and CKM_WTLS_PRF.

WTLS (Wireless Transport Layer Security) is a legacy protocol from the WAP
specification. These mechanisms are rarely supported by modern tokens and tests
will mostly skip. The raw packers in pkcs11_check.raw.pack provide proper
struct packing for WTLS parameter structures.

OASIS PKCS#11 v3.2 spec: WTLS.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
from collections.abc import Callable, Mapping
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import (
    attr_ulong,
    mech_simple,
    mech_wtls_key_mat,
    mech_wtls_master_key_derive,
    mech_wtls_prf,
    template,
    template_ptr_count,
)
from pkcs11_check.raw.recipes import (
    create_object,
    derive_key,
    destroy_quietly,
    pack_attrs,
    read_attributes,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_ULONG,
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
    CKM_VENDOR_DEFINED,
    CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
    CKM_WTLS_MASTER_KEY_DERIVE,
    CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
    CKM_WTLS_PRE_MASTER_KEY_GEN,
    CKM_WTLS_PRF,
    CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import (
    assert_correct,
    destroy_returned_handles,
    is_known_error,
    reject_or_classify,
)

pytestmark = pytest.mark.keymgmt

# Common CKR values for WTLS operations
_WTLS_ERROR_RVS = {
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
}

_WTLS_INVALID_DIGEST_REJECT_RVS = (CKR_MECHANISM_PARAM_INVALID,)
_WTLS_TEMPLATE_CONFLICT_REJECT_RVS = (
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ATTRIBUTE_VALUE_INVALID,
)

# WTLS client/server random values (16 bytes each)
_CLIENT_RANDOM = bytes(range(16))
_SERVER_RANDOM = bytes(range(16, 32))
_WTLS_PRF_SECRET = bytes(range(20))
_WTLS_PRF_LABEL = b"key expansion"
_WTLS_PRF_SEED = bytes(range(32))


def _wtls_prf_sha256_reference(
    secret: bytes,
    label: bytes,
    seed: bytes,
    output_len: int,
) -> bytes:
    """Compute the WAP WTLS P_hash PRF using SHA-256 as the selected digest."""
    if output_len <= 0:
        raise ValueError("output_len must be positive")
    seed_data = label + seed
    output = b""
    a_value = seed_data
    while len(output) < output_len:
        a_value = hmac.new(secret, a_value, hashlib.sha256).digest()
        output += hmac.new(secret, a_value + seed_data, hashlib.sha256).digest()
    return output[:output_len]


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


def _wtls_derived_secret_attrs() -> dict[int, Any]:
    return {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_TOKEN: False,
    }


def _derive_key_material_to_params(
    rs: Any,
    base_key: int,
    attrs: Mapping[Any, Any],
    mech: Any,
) -> None:
    """Run WTLS key-material derive, whose output handles live in mechanism params."""
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


def _derive_wtls_prf_output(
    rs: Any,
    secret: int,
    *,
    seed: bytes,
    label: bytes = b"key expansion",
    output_len: int = 16,
    digest_mechanism: int = int(CKM_SHA256),
) -> bytes:
    """Run CKM_WTLS_PRF and return the bytes written to CK_WTLS_PRF_PARAMS.pOutput."""
    mech = mech_wtls_prf(
        CKM_WTLS_PRF,
        digest_mechanism=digest_mechanism,
        seed=seed,
        label=label,
        output_len=output_len,
    )
    rv = rs.raw.C_DeriveKey(rs.sh, mech.byref(), secret, None, 0, None)
    expect_rv(rv, CKR_OK)
    out_len = ctypes.cast(mech.params.pulOutputLen, ctypes.POINTER(CK_ULONG))[0]
    actual_len = int(out_len)
    if actual_len > output_len:
        classify(
            "self_contradiction",
            kind="metadata",
            label="CKM_WTLS_PRF:output-length",
            operation="C_DeriveKey",
            mechanism="CKM_WTLS_PRF",
            summary=(
                f"CKM_WTLS_PRF reported {actual_len} output bytes for a {output_len}-byte buffer"
            ),
        )
    return mech.buffer_bytes("output")[:actual_len]


def _classify_invalid_wtls_digest(operation: Callable[[], int | None], *, label: str) -> None:
    exc: AssertionError | None = None
    try:
        operation()
    except AssertionError as caught:
        exc = caught
    reject_or_classify(
        exc,
        _WTLS_INVALID_DIGEST_REJECT_RVS,
        label=label,
    )


def _derive_wtls_master_key_invalid_digest(
    rs: Any,
    base_key: int,
    mechanism: int,
    *,
    label: str,
    with_version: bool = True,
) -> None:
    mech = mech_wtls_master_key_derive(
        mechanism,
        digest_mechanism=int(CKM_VENDOR_DEFINED),
        client_random=_CLIENT_RANDOM,
        server_random=_SERVER_RANDOM,
        with_version=with_version,
    )
    derived = 0

    def operation() -> int:
        nonlocal derived
        derived = derive_key(
            rs.raw,
            rs.sh,
            base_key,
            mechanism,
            attrs=_wtls_derived_secret_attrs(),
            mech_param=mech,
        )
        return derived

    try:
        _classify_invalid_wtls_digest(operation, label=label)
    finally:
        destroy_quietly(rs.raw, rs.sh, derived)


def _derive_wtls_key_material_invalid_digest(
    rs: Any,
    base_key: int,
    mechanism: int,
    *,
    label: str,
) -> None:
    mech = mech_wtls_key_mat(
        mechanism,
        digest_mechanism=int(CKM_VENDOR_DEFINED),
        client_random=_CLIENT_RANDOM,
        server_random=_SERVER_RANDOM,
        iv_size_bits=64,
    )

    def operation() -> None:
        _derive_key_material_to_params(
            rs,
            base_key,
            _wtls_derived_secret_attrs(),
            mech,
        )

    try:
        _classify_invalid_wtls_digest(operation, label=label)
    finally:
        out = mech.key_mat_out
        destroy_returned_handles(rs, out.hMacSecret, out.hKey)


def _derive_wtls_key_material_template_conflict(
    rs: Any,
    base_key: int,
    mechanism: int,
    *,
    label: str,
) -> None:
    """Verify WTLS key material rejects template protection values that differ."""
    mech = mech_wtls_key_mat(
        mechanism,
        digest_mechanism=CKM_SHA256,
        client_random=_CLIENT_RANDOM,
        server_random=_SERVER_RANDOM,
    )
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
        destroy_returned_handles(rs, out.hMacSecret, out.hKey)

    reject_or_classify(
        exc,
        _WTLS_TEMPLATE_CONFLICT_REJECT_RVS,
        label=label,
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
                assert_correct(
                    actual=attrs[CKA_KEY_TYPE],
                    expected=CKK_GENERIC_SECRET,
                    label="CKM_WTLS_PRE_MASTER_KEY_GEN:CKA_KEY_TYPE readback",
                    operation="C_GenerateKey",
                    mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                    kind="metadata",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, key.value)
        except AssertionError as exc:
            if is_known_error(exc, _WTLS_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_WTLS_PRE_MASTER_KEY_GEN:C_GenerateKey",
                    operation="C_GenerateKey",
                    mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                    summary=f"CKM_WTLS_PRE_MASTER_KEY_GEN not operational: {exc}",
                )
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
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_WTLS_PRE_MASTER_KEY_GEN:C_GenerateKey",
                    operation="C_GenerateKey",
                    mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                    summary=f"CKM_WTLS_PRE_MASTER_KEY_GEN not operational: {exc}",
                )
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
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_WTLS_PRE_MASTER_KEY_GEN:C_GenerateKey",
                    operation="C_GenerateKey",
                    mechanism="CKM_WTLS_PRE_MASTER_KEY_GEN",
                    summary=f"CKM_WTLS_PRE_MASTER_KEY_GEN not operational: {exc}",
                )
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
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_MASTER_KEY_DERIVE:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_MASTER_KEY_DERIVE",
                        summary=f"CKM_WTLS_MASTER_KEY_DERIVE not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pms)

    def test_rejects_invalid_digest_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_WTLS_MASTER_KEY_DERIVE must reject an invalid DigestMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE not supported")

        pms = _create_generic_secret(rs, 20)
        try:
            _derive_wtls_master_key_invalid_digest(
                rs,
                pms,
                int(CKM_WTLS_MASTER_KEY_DERIVE),
                label="WTLS master key derive invalid digest mechanism",
            )
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
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC",
                        summary=f"CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pms)

    def test_rejects_invalid_digest_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC must reject an invalid DigestMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_MASTER_KEY_DERIVE_DH_ECC"):
            pytest.skip("CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC not supported")

        pms = _create_generic_secret(rs, 32)
        try:
            _derive_wtls_master_key_invalid_digest(
                rs,
                pms,
                int(CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC),
                label="WTLS master key derive DH/ECC invalid digest mechanism",
                with_version=False,
            )
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
                _derive_key_material_to_params(
                    rs,
                    master,
                    {
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech,
                )
                try:
                    out = mech.key_mat_out
                    assert out.hKey != 0
                    assert any(mech.buffer_bytes("iv"))
                finally:
                    out = mech.key_mat_out
                    destroy_returned_handles(rs, out.hMacSecret, out.hKey)
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",
                        summary=f"CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, master)

    def test_server_rejects_invalid_digest_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE must reject an invalid DigestMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_SERVER_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(rs, 20)
        try:
            _derive_wtls_key_material_invalid_digest(
                rs,
                master,
                int(CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE),
                label="WTLS server key-and-MAC derive invalid digest mechanism",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, master)

    def test_server_rejects_template_protection_conflict(self, p11_raw_session: Any) -> None:
        """Server key-material derive rejects template protection overrides."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_SERVER_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(rs, 20)
        try:
            _derive_wtls_key_material_template_conflict(
                rs,
                master,
                int(CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE),
                label="WTLS server key-and-MAC derive template protection conflict",
            )
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
                _derive_key_material_to_params(
                    rs,
                    master,
                    {
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech,
                )
                try:
                    out = mech.key_mat_out
                    assert out.hKey != 0
                    assert any(mech.buffer_bytes("iv"))
                finally:
                    out = mech.key_mat_out
                    destroy_returned_handles(rs, out.hMacSecret, out.hKey)
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE",
                        summary=f"CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, master)

    def test_client_rejects_invalid_digest_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE must reject an invalid DigestMechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_CLIENT_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(rs, 20)
        try:
            _derive_wtls_key_material_invalid_digest(
                rs,
                master,
                int(CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE),
                label="WTLS client key-and-MAC derive invalid digest mechanism",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, master)

    def test_client_rejects_template_protection_conflict(self, p11_raw_session: Any) -> None:
        """Client key-material derive rejects template protection overrides."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_CLIENT_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE not supported")

        master = _create_generic_secret(rs, 20)
        try:
            _derive_wtls_key_material_template_conflict(
                rs,
                master,
                int(CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE),
                label="WTLS client key-and-MAC derive template protection conflict",
            )
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
            srv_out: Any | None = None
            cli_out: Any | None = None
            try:
                srv_mech = mech_wtls_key_mat(
                    CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
                    digest_mechanism=CKM_SHA256,
                    client_random=_CLIENT_RANDOM,
                    server_random=_SERVER_RANDOM,
                )
                _derive_key_material_to_params(
                    rs,
                    master,
                    {
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    srv_mech,
                )
                srv_out = srv_mech.key_mat_out
                cli_mech = mech_wtls_key_mat(
                    CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
                    digest_mechanism=CKM_SHA256,
                    client_random=_CLIENT_RANDOM,
                    server_random=_SERVER_RANDOM,
                )
                _derive_key_material_to_params(
                    rs,
                    master,
                    {
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    cli_mech,
                )
                cli_out = cli_mech.key_mat_out
                srv_val = read_attributes(rs.raw, rs.sh, srv_out.hKey, [CKA_VALUE])[CKA_VALUE]
                cli_val = read_attributes(rs.raw, rs.sh, cli_out.hKey, [CKA_VALUE])[CKA_VALUE]
                assert srv_val != cli_val, (
                    "Server and client key derivation must produce different keys"
                )
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_SERVER/CLIENT_KEY_AND_MAC_DERIVE:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE",
                        summary=f"WTLS key-and-MAC derivation not operational: {exc}",
                    )
                raise
            finally:
                if cli_out is not None:
                    destroy_returned_handles(rs, cli_out.hMacSecret, cli_out.hKey)
                if srv_out is not None:
                    destroy_returned_handles(rs, srv_out.hMacSecret, srv_out.hKey)
        finally:
            destroy_quietly(rs.raw, rs.sh, master)


class TestWTLSPRF:
    """CKM_WTLS_PRF - WTLS pseudo-random function for key material expansion."""

    def _derive_prf_value(
        self,
        rs: Any,
        secret: int,
        *,
        seed: bytes,
        label: bytes = b"key expansion",
    ) -> bytes:
        value = _derive_wtls_prf_output(
            rs,
            secret,
            seed=seed,
            label=label,
            output_len=16,
        )
        assert len(value) == 16, f"Expected 16 bytes, got {len(value)}"
        return value

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Probe whether CKM_WTLS_PRF is advertised."""
        if not p11_raw_session.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

    def test_prf_derive(self, p11_raw_session: Any) -> None:
        """Attempt to use CKM_WTLS_PRF for key derivation with proper struct params."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(rs, len(_WTLS_PRF_SECRET))
        try:
            try:
                value = _derive_wtls_prf_output(
                    rs,
                    secret,
                    seed=_WTLS_PRF_SEED,
                    label=_WTLS_PRF_LABEL,
                    output_len=16,
                )
                assert len(value) == 16, f"Expected 16 bytes, got {len(value)}"
                expected = _wtls_prf_sha256_reference(
                    _WTLS_PRF_SECRET,
                    _WTLS_PRF_LABEL,
                    _WTLS_PRF_SEED,
                    16,
                )
                assert_correct(
                    actual=value,
                    expected=expected,
                    label="CKM_WTLS_PRF:C_DeriveKey KAT (16-byte output)",
                    operation="C_DeriveKey",
                    mechanism="CKM_WTLS_PRF",
                )
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_PRF:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_PRF",
                        summary=f"CKM_WTLS_PRF not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, secret)

    def test_prf_rejects_invalid_digest_mechanism(self, p11_raw_session: Any) -> None:
        """CKM_WTLS_PRF must reject a DigestMechanism outside the WTLS digest set."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(rs, 20)
        try:
            exc: AssertionError | None = None
            try:
                _derive_wtls_prf_output(
                    rs,
                    secret,
                    seed=bytes(range(32)),
                    label=b"key expansion",
                    output_len=16,
                    digest_mechanism=int(CKM_VENDOR_DEFINED),
                )
            except AssertionError as caught:
                exc = caught
            reject_or_classify(
                exc,
                _WTLS_INVALID_DIGEST_REJECT_RVS,
                label="WTLS PRF invalid digest mechanism",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, secret)

    def test_prf_seed_affects_output(self, p11_raw_session: Any) -> None:
        """Changing only the WTLS PRF seed must change the derived output."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(rs, 20)
        try:
            try:
                val1 = self._derive_prf_value(
                    rs,
                    secret,
                    seed=bytes(range(32)),
                )
                val2 = self._derive_prf_value(
                    rs,
                    secret,
                    seed=bytes(range(1, 33)),
                )
                assert val1 != val2, "WTLS PRF seed change did not affect derived output"
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_PRF:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_PRF",
                        summary=f"CKM_WTLS_PRF not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, secret)

    def test_prf_label_affects_output(self, p11_raw_session: Any) -> None:
        """Changing only the WTLS PRF label must change the derived output."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(rs, 20)
        try:
            try:
                val1 = self._derive_prf_value(
                    rs,
                    secret,
                    seed=bytes(range(32)),
                    label=b"key expansion",
                )
                val2 = self._derive_prf_value(
                    rs,
                    secret,
                    seed=bytes(range(32)),
                    label=b"client expansion",
                )
                assert val1 != val2, "WTLS PRF label change did not affect derived output"
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_PRF:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_PRF",
                        summary=f"CKM_WTLS_PRF not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, secret)

    def test_prf_output_len_extends_output(self, p11_raw_session: Any) -> None:
        """A longer WTLS PRF request must preserve the shorter output as a prefix."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(rs, len(_WTLS_PRF_SECRET))
        try:
            try:
                short = _derive_wtls_prf_output(
                    rs,
                    secret,
                    seed=_WTLS_PRF_SEED,
                    label=_WTLS_PRF_LABEL,
                    output_len=16,
                )
                long = _derive_wtls_prf_output(
                    rs,
                    secret,
                    seed=_WTLS_PRF_SEED,
                    label=_WTLS_PRF_LABEL,
                    output_len=32,
                )
                assert len(short) == 16, f"Expected 16 bytes, got {len(short)}"
                assert len(long) == 32, f"Expected 32 bytes, got {len(long)}"
                assert_correct(
                    actual=long[: len(short)],
                    expected=short,
                    label="CKM_WTLS_PRF:output-length prefix consistency",
                    operation="C_DeriveKey",
                    mechanism="CKM_WTLS_PRF",
                )
                expected = _wtls_prf_sha256_reference(
                    _WTLS_PRF_SECRET,
                    _WTLS_PRF_LABEL,
                    _WTLS_PRF_SEED,
                    32,
                )
                assert_correct(
                    actual=long,
                    expected=expected,
                    label="CKM_WTLS_PRF:C_DeriveKey KAT (32-byte output)",
                    operation="C_DeriveKey",
                    mechanism="CKM_WTLS_PRF",
                )
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_PRF:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_PRF",
                        summary=f"CKM_WTLS_PRF not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, secret)

    def test_prf_deterministic(self, p11_raw_session: Any) -> None:
        """Same WTLS PRF inputs must produce the same output."""
        rs = p11_raw_session
        if not rs.has_mechanism("WTLS_PRF"):
            pytest.skip("CKM_WTLS_PRF not supported")

        secret = _create_generic_secret(rs, 20)
        try:
            try:
                val1 = _derive_wtls_prf_output(
                    rs,
                    secret,
                    seed=bytes(range(32)),
                    label=b"key expansion",
                    output_len=16,
                )
                val2 = _derive_wtls_prf_output(
                    rs,
                    secret,
                    seed=bytes(range(32)),
                    label=b"key expansion",
                    output_len=16,
                )
                assert_correct(
                    actual=val1,
                    expected=val2,
                    label="CKM_WTLS_PRF:C_DeriveKey determinism",
                    operation="C_DeriveKey",
                    mechanism="CKM_WTLS_PRF",
                )
            except AssertionError as exc:
                if is_known_error(exc, _WTLS_ERROR_RVS):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_WTLS_PRF:C_DeriveKey",
                        operation="C_DeriveKey",
                        mechanism="CKM_WTLS_PRF",
                        summary=f"CKM_WTLS_PRF not operational: {exc}",
                    )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, secret)
