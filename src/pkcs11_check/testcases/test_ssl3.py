"""Tests for SSL3 protocol mechanisms.

Covers CKM_SSL3_PRE_MASTER_KEY_GEN, CKM_SSL3_MASTER_KEY_DERIVE,
CKM_SSL3_KEY_AND_MAC_DERIVE, CKM_SSL3_MASTER_KEY_DERIVE_DH,
CKM_SSL3_MD5_MAC, and CKM_SSL3_SHA1_MAC.

These are legacy SSL 3.0 mechanisms. Most modern modules do not support them.
Tests skip cleanly via has_mechanism() when unsupported.

CKM_SSL3_MASTER_KEY_DERIVE and CKM_SSL3_KEY_AND_MAC_DERIVE require nested C
parameter structures (CK_SSL3_RANDOM_DATA, CK_SSL3_MASTER_KEY_DERIVE_PARAMS,
CK_SSL3_KEY_MAT_PARAMS). The raw packers in pkcs11_check.raw.pack provide
proper struct packing for these.

OASIS PKCS#11 v3.2 spec: SSL.
"""

from __future__ import annotations

import ctypes
import hashlib
from collections.abc import Mapping
from ctypes import byref
from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import (
    attr_ulong,
    mech_bytes,
    mech_ssl3_key_mat,
    mech_ssl3_master_key_derive,
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
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import (
    assert_correct,
    destroy_returned_handles,
    is_known_error,
    reject_or_classify,
)

pytestmark = pytest.mark.keymgmt

# SSL 3.0 client/server random values (28 bytes each per spec)
_CLIENT_RANDOM = bytes(range(28))
_SERVER_RANDOM = bytes(range(28, 56))

# A 48-byte pre-master secret (SSL3 pre-master key size) with version 3.0 prefix.
_PRE_MASTER_SECRET = b"\x03\x00" + bytes(range(2, 48))

# Arbitrary-length pre-master material for the DH master-key derive variant.
_DH_PRE_MASTER_SECRET = bytes(range(32))

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

_SSL3_TEMPLATE_CONFLICT_REJECT_RVS = (
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ATTRIBUTE_VALUE_INVALID,
)

# CKR values acceptable for MAC sign/verify operations
_MAC_ERROR_RVS = {
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_ARGUMENTS_BAD,
}

_KIND_PRIORITY = {"metadata": 1, "lifecycle": 2, "policy": 2, "crypto": 3}
_SEVERITY_PRIORITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class _ClassificationFailureError(Failed, AssertionError):
    """Keep migrated failures compatible with callers expecting AssertionError."""


def _read_attribute(attrs: Mapping[Any, Any], attr: Any, *, label: str, mechanism: str) -> Any:
    """Read an attribute while retaining a structured unavailable-value observation."""
    return attr_or_record(
        attrs,
        attr,
        label=f"{label} (producer_mechanism={mechanism})",
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )


def _read_provider_attribute(
    raw: Any,
    session: int,
    handle: int,
    attr: Any,
    *,
    label: str,
    mechanism: str,
    error_rvs: set[Any] | frozenset[Any] | tuple[Any, ...],
) -> Any:
    """Read one provider attribute and classify typed readback errors accurately."""
    try:
        return _read_attribute(
            read_attributes(raw, session, handle, [attr]),
            attr,
            label=label,
            mechanism=mechanism,
        )
    except AssertionError as exc:
        if is_known_error(exc, error_rvs):
            C.record_as(
                "not_operational",
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                mechanism=mechanism,
                actual=getattr(exc, "rv", None),
                summary=f"{label}: C_GetAttributeValue not operational: {exc}",
            )
            return MISSING_ATTRIBUTE
        raise


def _record_wrong_attribute(
    *,
    label: str,
    expected: Any,
    actual: Any,
    kind: str,
    mechanism: str,
    operation: str,
) -> C.Classification:
    # This defensive branch keeps absence distinct from a provider value even
    # if a future caller bypasses _validate_output's sentinel guard.
    if actual is MISSING_ATTRIBUTE:
        return C.record_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=mechanism,
            summary=f"{label}: provider did not return the requested attribute",
            detail={"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}},
        )
    if mechanism == "CKM_SSL3_KEY_AND_MAC_DERIVE":
        summary_prefix = "SSL3 key material output mismatch"
    elif isinstance(expected, bytes):
        summary_prefix = f"{label} does not match known answer"
    else:
        summary_prefix = label
    return C.record_as(
        "wrong_result",
        kind=kind,
        label=label,
        operation=operation,
        mechanism=mechanism,
        summary=f"{summary_prefix}: provider returned {actual!r}; expected {expected!r}",
        detail={
            "attribute": {
                "name": "CKA_VALUE",
                "id": int(CKA_VALUE),
                "expected": repr(expected),
                "actual": repr(actual),
            }
        },
    )


def _record_parameter_mismatch(
    *, label: str, parameter: str, expected: Any, actual: Any, mechanism: str
) -> C.Classification:
    """Record a mechanism-parameter output mismatch without fabricating CKR evidence."""
    return C.record_as(
        "wrong_result",
        kind="crypto",
        label=label,
        operation="C_DeriveKey",
        mechanism=mechanism,
        summary=f"{label}: provider returned {actual!r}; expected {expected!r}",
        detail={
            "parameter": {
                "name": parameter,
                "expected": repr(expected),
                "actual": repr(actual),
            }
        },
    )


def _record_handle_mismatch(
    *, label: str, actual: Any, mechanism: str, operation: str = "C_DeriveKey"
) -> C.Classification:
    """Record a successful producer that failed to return a required handle."""
    return C.record_as(
        "self_contradiction",
        kind="lifecycle",
        label=label,
        operation=operation,
        mechanism=mechanism,
        actual=CKR_OK,
        summary=f"{label}: {operation} returned CKR_OK with handle {actual!r}",
        detail={"handle": {"actual": actual, "expected": "non-zero"}},
    )


def _validate_output(
    value: Any,
    *,
    label: str,
    mechanism: str,
    operation: str,
    expected_len: int | None = None,
    expected: bytes | None = None,
) -> C.Classification | None:
    """Validate a present CKA_VALUE without terminating independent checks early."""
    if value is MISSING_ATTRIBUTE:
        return None
    if not isinstance(value, bytes):
        return _record_wrong_attribute(
            label=label,
            expected="bytes",
            actual=value,
            kind="crypto",
            mechanism=mechanism,
            operation=operation,
        )
    if expected_len is not None and len(value) != expected_len:
        return _record_wrong_attribute(
            label=label,
            expected=f"{expected_len}-byte bytes",
            actual=value,
            kind="crypto",
            mechanism=mechanism,
            operation=operation,
        )
    if expected is not None and value != expected:
        return _record_wrong_attribute(
            label=label,
            expected=expected,
            actual=value,
            kind="crypto",
            mechanism=mechanism,
            operation=operation,
        )
    return None


def _raise_strongest(records: list[C.Classification]) -> None:
    """Raise the strongest hard output finding after all cleanup has completed."""
    if not records:
        return
    strongest = max(
        records,
        key=lambda record: (
            _KIND_PRIORITY.get(record.kind or "", 0),
            _SEVERITY_PRIORITY.get(record.severity, 0),
        ),
    )
    try:
        C.raise_for_record(strongest)
    except Failed as exc:
        failure = _ClassificationFailureError(str(exc))
        setattr(failure, "_pkcs11_check_classification", strongest)
        raise failure from exc


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


def _ssl3_key_block_reference(
    master_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    block_length: int,
) -> bytes:
    """Compute the SSL3 key_block from RFC 6101 section 6.2.2."""
    out = bytearray()
    i = 1
    while len(out) < block_length:
        pad = bytes([ord("A") + i - 1]) * i
        sha = hashlib.sha1(
            pad + master_secret + server_random + client_random,
            usedforsecurity=False,
        ).digest()
        out.extend(
            hashlib.md5(
                master_secret + sha,
                usedforsecurity=False,
            ).digest()
        )
        i += 1
    return bytes(out[:block_length])


def _derive_key_material_to_params(
    rs: Any,
    base_key: int,
    attrs: Mapping[Any, Any],
    mech: Any,
) -> None:
    """Run SSL3 key-material derive, whose output handles live in mechanism params."""
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


def _derive_ssl3_key_material_template_conflict(
    rs: Any,
    base_key: int,
    mech: Any,
    *,
    label: str,
) -> None:
    """Verify SSL3 key material rejects template protection values that differ."""
    exc: AssertionError | None = None
    try:
        _derive_key_material_to_params(
            rs,
            base_key,
            {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_AES,
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
        _SSL3_TEMPLATE_CONFLICT_REJECT_RVS,
        label=label,
    )


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
        hard_results: list[C.Classification] = []
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
                raw_val = MISSING_ATTRIBUTE
                if key.value == 0:
                    hard_results.append(
                        _record_handle_mismatch(
                            label="CKM_SSL3_PRE_MASTER_KEY_GEN:C_GenerateKey output handle",
                            actual=key.value,
                            mechanism="CKM_SSL3_PRE_MASTER_KEY_GEN",
                            operation="C_GenerateKey",
                        )
                    )
                else:
                    raw_val = _read_provider_attribute(
                        rs.raw,
                        rs.sh,
                        key.value,
                        CKA_VALUE,
                        label="CKM_SSL3_PRE_MASTER_KEY_GEN:CKA_VALUE readback",
                        mechanism="CKM_SSL3_PRE_MASTER_KEY_GEN",
                        error_rvs=_DERIVE_ERROR_RVS,
                    )
                mismatch = _validate_output(
                    raw_val,
                    label="CKM_SSL3_PRE_MASTER_KEY_GEN:CKA_VALUE readback",
                    mechanism="CKM_SSL3_PRE_MASTER_KEY_GEN",
                    operation="C_GenerateKey",
                    expected_len=48,
                )
                if mismatch is not None:
                    hard_results.append(mismatch)
                elif raw_val is not MISSING_ATTRIBUTE and isinstance(raw_val, bytes):
                    # First two bytes must encode the version (3, 0).
                    if raw_val[0] != 3:
                        hard_results.append(
                            _record_wrong_attribute(
                                label="CKM_SSL3_PRE_MASTER_KEY_GEN:version major",
                                expected=3,
                                actual=raw_val[0],
                                kind="crypto",
                                mechanism="CKM_SSL3_PRE_MASTER_KEY_GEN",
                                operation="C_GenerateKey",
                            )
                        )
                    if raw_val[1] != 0:
                        hard_results.append(
                            _record_wrong_attribute(
                                label="CKM_SSL3_PRE_MASTER_KEY_GEN:version minor",
                                expected=0,
                                actual=raw_val[1],
                                kind="crypto",
                                mechanism="CKM_SSL3_PRE_MASTER_KEY_GEN",
                                operation="C_GenerateKey",
                            )
                        )
            finally:
                if key.value != 0:
                    destroy_quietly(rs.raw, rs.sh, key.value)
            _raise_strongest(hard_results)
        except AssertionError as exc:
            if is_known_error(exc, _DERIVE_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_PRE_MASTER_KEY_GEN:C_GenerateKey",
                    operation="C_GenerateKey",
                    mechanism="CKM_SSL3_PRE_MASTER_KEY_GEN",
                    actual=getattr(exc, "rv", None),
                    summary=f"CKM_SSL3_PRE_MASTER_KEY_GEN not operational: {exc}",
                )
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
        hard_results: list[C.Classification] = []
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
            try:
                val1 = MISSING_ATTRIBUTE
                if key1.value == 0:
                    hard_results.append(
                        _record_handle_mismatch(
                            label="CKM_SSL3_PRE_MASTER_KEY_GEN:first output handle",
                            actual=key1.value,
                            mechanism="CKM_SSL3_PRE_MASTER_KEY_GEN",
                            operation="C_GenerateKey",
                        )
                    )
                else:
                    val1 = _read_provider_attribute(
                        rs.raw,
                        rs.sh,
                        key1.value,
                        CKA_VALUE,
                        label="CKM_SSL3_PRE_MASTER_KEY_GEN:first CKA_VALUE readback",
                        mechanism="CKM_SSL3_PRE_MASTER_KEY_GEN",
                        error_rvs=_DERIVE_ERROR_RVS,
                    )
                mismatch = _validate_output(
                    val1,
                    label="CKM_SSL3_PRE_MASTER_KEY_GEN:first CKA_VALUE readback",
                    mechanism="CKM_SSL3_PRE_MASTER_KEY_GEN",
                    operation="C_GenerateKey",
                    expected_len=48,
                )
                if mismatch is not None:
                    hard_results.append(mismatch)

                try:
                    rv = rs.raw.C_GenerateKey(
                        rs.sh,
                        mech.byref(),
                        tmpl.ptr,
                        tmpl.count,
                        byref(key2),
                    )
                    expect_rv(rv, CKR_OK)
                    val2 = MISSING_ATTRIBUTE
                    if key2.value == 0:
                        hard_results.append(
                            _record_handle_mismatch(
                                label="CKM_SSL3_PRE_MASTER_KEY_GEN:second output handle",
                                actual=key2.value,
                                mechanism="CKM_SSL3_PRE_MASTER_KEY_GEN",
                                operation="C_GenerateKey",
                            )
                        )
                    else:
                        val2 = _read_provider_attribute(
                            rs.raw,
                            rs.sh,
                            key2.value,
                            CKA_VALUE,
                            label="CKM_SSL3_PRE_MASTER_KEY_GEN:second CKA_VALUE readback",
                            mechanism="CKM_SSL3_PRE_MASTER_KEY_GEN",
                            error_rvs=_DERIVE_ERROR_RVS,
                        )
                    mismatch = _validate_output(
                        val2,
                        label="CKM_SSL3_PRE_MASTER_KEY_GEN:second CKA_VALUE readback",
                        mechanism="CKM_SSL3_PRE_MASTER_KEY_GEN",
                        operation="C_GenerateKey",
                        expected_len=48,
                    )
                    if mismatch is not None:
                        hard_results.append(mismatch)
                    if (
                        val1 is not MISSING_ATTRIBUTE
                        and val2 is not MISSING_ATTRIBUTE
                        and isinstance(val1, bytes)
                        and isinstance(val2, bytes)
                        and val1 == val2
                    ):
                        hard_results.append(
                            _record_wrong_attribute(
                                label="CKM_SSL3_PRE_MASTER_KEY_GEN:randomness",
                                expected="different outputs for independent generations",
                                actual=val1,
                                kind="crypto",
                                mechanism="CKM_SSL3_PRE_MASTER_KEY_GEN",
                                operation="C_GenerateKey",
                            )
                        )
                finally:
                    if key2.value != 0:
                        destroy_quietly(rs.raw, rs.sh, key2.value)
            finally:
                if key1.value != 0:
                    destroy_quietly(rs.raw, rs.sh, key1.value)
            _raise_strongest(hard_results)
        except AssertionError as exc:
            if is_known_error(exc, _DERIVE_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_PRE_MASTER_KEY_GEN:C_GenerateKey",
                    operation="C_GenerateKey",
                    mechanism="CKM_SSL3_PRE_MASTER_KEY_GEN",
                    actual=getattr(exc, "rv", None),
                    summary=f"CKM_SSL3_PRE_MASTER_KEY_GEN not operational: {exc}",
                )
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
        hard_results: list[C.Classification] = []
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
                raw_val = MISSING_ATTRIBUTE
                if derived == 0:
                    hard_results.append(
                        _record_handle_mismatch(
                            label="CKM_SSL3_MASTER_KEY_DERIVE:C_DeriveKey output handle",
                            actual=derived,
                            mechanism="CKM_SSL3_MASTER_KEY_DERIVE",
                        )
                    )
                else:
                    raw_val = _read_provider_attribute(
                        rs.raw,
                        rs.sh,
                        derived,
                        CKA_VALUE,
                        label="CKM_SSL3_MASTER_KEY_DERIVE:CKA_VALUE readback",
                        mechanism="CKM_SSL3_MASTER_KEY_DERIVE",
                        error_rvs=_DERIVE_ERROR_RVS,
                    )
                mismatch = _validate_output(
                    raw_val,
                    label="CKM_SSL3_MASTER_KEY_DERIVE:CKA_VALUE readback",
                    mechanism="CKM_SSL3_MASTER_KEY_DERIVE",
                    operation="C_DeriveKey",
                    expected_len=48,
                )
                if mismatch is not None:
                    hard_results.append(mismatch)
            finally:
                if derived != 0:
                    destroy_quietly(rs.raw, rs.sh, derived)
            _raise_strongest(hard_results)
        except AssertionError as exc:
            if is_known_error(exc, _DERIVE_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_MASTER_KEY_DERIVE:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_SSL3_MASTER_KEY_DERIVE",
                    summary=f"CKM_SSL3_MASTER_KEY_DERIVE not operational: {exc}",
                )
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pre_master)

    def test_derive_master_secret_exact_vector(self, p11_raw_session: Any) -> None:
        """CKM_SSL3_MASTER_KEY_DERIVE must match the SSL3 master_secret formula."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_MASTER_KEY_DERIVE"):
            pytest.skip("CKM_SSL3_MASTER_KEY_DERIVE not supported")

        pre_master = _create_generic_secret(rs, _PRE_MASTER_SECRET)
        hard_results: list[C.Classification] = []
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
                raw_val = MISSING_ATTRIBUTE
                if derived == 0:
                    hard_results.append(
                        _record_handle_mismatch(
                            label="CKM_SSL3_MASTER_KEY_DERIVE:C_DeriveKey output handle",
                            actual=derived,
                            mechanism="CKM_SSL3_MASTER_KEY_DERIVE",
                        )
                    )
                else:
                    raw_val = _read_provider_attribute(
                        rs.raw,
                        rs.sh,
                        derived,
                        CKA_VALUE,
                        label="CKM_SSL3_MASTER_KEY_DERIVE:CKA_VALUE readback",
                        mechanism="CKM_SSL3_MASTER_KEY_DERIVE",
                        error_rvs=_DERIVE_ERROR_RVS,
                    )
                mismatch = _validate_output(
                    raw_val,
                    label="CKM_SSL3_MASTER_KEY_DERIVE:C_DeriveKey KAT (master secret)",
                    mechanism="CKM_SSL3_MASTER_KEY_DERIVE",
                    operation="C_DeriveKey",
                    expected_len=48,
                    expected=expected,
                )
                if mismatch is not None:
                    hard_results.append(mismatch)
            finally:
                if derived != 0:
                    destroy_quietly(rs.raw, rs.sh, derived)
            _raise_strongest(hard_results)
        except AssertionError as exc:
            if is_known_error(exc, _DERIVE_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_MASTER_KEY_DERIVE:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_SSL3_MASTER_KEY_DERIVE",
                    summary=f"CKM_SSL3_MASTER_KEY_DERIVE not operational: {exc}",
                )
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
        hard_results: list[C.Classification] = []
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
                raw_val = MISSING_ATTRIBUTE
                if derived == 0:
                    hard_results.append(
                        _record_handle_mismatch(
                            label="CKM_SSL3_MASTER_KEY_DERIVE_DH:C_DeriveKey output handle",
                            actual=derived,
                            mechanism="CKM_SSL3_MASTER_KEY_DERIVE_DH",
                        )
                    )
                else:
                    raw_val = _read_provider_attribute(
                        rs.raw,
                        rs.sh,
                        derived,
                        CKA_VALUE,
                        label="CKM_SSL3_MASTER_KEY_DERIVE_DH:CKA_VALUE readback",
                        mechanism="CKM_SSL3_MASTER_KEY_DERIVE_DH",
                        error_rvs=_DERIVE_ERROR_RVS,
                    )
                mismatch = _validate_output(
                    raw_val,
                    label="CKM_SSL3_MASTER_KEY_DERIVE_DH:CKA_VALUE readback",
                    mechanism="CKM_SSL3_MASTER_KEY_DERIVE_DH",
                    operation="C_DeriveKey",
                    expected_len=48,
                )
                if mismatch is not None:
                    hard_results.append(mismatch)
            finally:
                if derived != 0:
                    destroy_quietly(rs.raw, rs.sh, derived)
            _raise_strongest(hard_results)
        except AssertionError as exc:
            if is_known_error(exc, _DERIVE_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_MASTER_KEY_DERIVE_DH:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_SSL3_MASTER_KEY_DERIVE_DH",
                    summary=f"CKM_SSL3_MASTER_KEY_DERIVE_DH not operational: {exc}",
                )
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pre_master)

    def test_derive_master_secret_dh_exact_vector(self, p11_raw_session: Any) -> None:
        """CKM_SSL3_MASTER_KEY_DERIVE_DH must match the SSL3 master_secret formula."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_MASTER_KEY_DERIVE_DH"):
            pytest.skip("CKM_SSL3_MASTER_KEY_DERIVE_DH not supported")

        pre_master = _create_generic_secret(rs, _DH_PRE_MASTER_SECRET)
        hard_results: list[C.Classification] = []
        expected = _ssl3_master_secret_reference(
            _DH_PRE_MASTER_SECRET,
            _CLIENT_RANDOM,
            _SERVER_RANDOM,
        )
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
                raw_val = MISSING_ATTRIBUTE
                if derived == 0:
                    hard_results.append(
                        _record_handle_mismatch(
                            label="CKM_SSL3_MASTER_KEY_DERIVE_DH:C_DeriveKey output handle",
                            actual=derived,
                            mechanism="CKM_SSL3_MASTER_KEY_DERIVE_DH",
                        )
                    )
                else:
                    raw_val = _read_provider_attribute(
                        rs.raw,
                        rs.sh,
                        derived,
                        CKA_VALUE,
                        label="CKM_SSL3_MASTER_KEY_DERIVE_DH:CKA_VALUE readback",
                        mechanism="CKM_SSL3_MASTER_KEY_DERIVE_DH",
                        error_rvs=_DERIVE_ERROR_RVS,
                    )
                mismatch = _validate_output(
                    raw_val,
                    label="CKM_SSL3_MASTER_KEY_DERIVE_DH:C_DeriveKey KAT (master secret DH)",
                    mechanism="CKM_SSL3_MASTER_KEY_DERIVE_DH",
                    operation="C_DeriveKey",
                    expected_len=48,
                    expected=expected,
                )
                if mismatch is not None:
                    hard_results.append(mismatch)
            finally:
                if derived != 0:
                    destroy_quietly(rs.raw, rs.sh, derived)
            _raise_strongest(hard_results)
        except AssertionError as exc:
            if is_known_error(exc, _DERIVE_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_MASTER_KEY_DERIVE_DH:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_SSL3_MASTER_KEY_DERIVE_DH",
                    summary=f"CKM_SSL3_MASTER_KEY_DERIVE_DH not operational: {exc}",
                )
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
        hard_results: list[C.Classification] = []
        try:
            mech = mech_ssl3_key_mat(
                CKM_SSL3_KEY_AND_MAC_DERIVE,
                _CLIENT_RANDOM,
                _SERVER_RANDOM,
                key_size_bits=128,
            )
            try:
                _derive_key_material_to_params(
                    rs,
                    master_secret,
                    {
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech,
                )
                out = mech.key_mat_out
                for handle, label in (
                    (out.hClientKey, "client key"),
                    (out.hServerKey, "server key"),
                ):
                    if handle == 0:
                        hard_results.append(
                            _record_handle_mismatch(
                                label=f"CKM_SSL3_KEY_AND_MAC_DERIVE:{label} output handle",
                                actual=handle,
                                mechanism="CKM_SSL3_KEY_AND_MAC_DERIVE",
                            )
                        )
                iv_client = mech.buffer_bytes("iv_client")
                if not iv_client:
                    hard_results.append(
                        _record_parameter_mismatch(
                            label="CKM_SSL3_KEY_AND_MAC_DERIVE:client IV output",
                            parameter="pIVClient",
                            expected="non-empty bytes",
                            actual=iv_client,
                            mechanism="CKM_SSL3_KEY_AND_MAC_DERIVE",
                        )
                    )
                iv_server = mech.buffer_bytes("iv_server")
                if not iv_server:
                    hard_results.append(
                        _record_parameter_mismatch(
                            label="CKM_SSL3_KEY_AND_MAC_DERIVE:server IV output",
                            parameter="pIVServer",
                            expected="non-empty bytes",
                            actual=iv_server,
                            mechanism="CKM_SSL3_KEY_AND_MAC_DERIVE",
                        )
                    )
            finally:
                out = mech.key_mat_out
                destroy_returned_handles(
                    rs,
                    out.hClientMacSecret,
                    out.hServerMacSecret,
                    out.hClientKey,
                    out.hServerKey,
                )
            _raise_strongest(hard_results)
        except AssertionError as exc:
            if is_known_error(exc, _DERIVE_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_KEY_AND_MAC_DERIVE:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_SSL3_KEY_AND_MAC_DERIVE",
                    actual=getattr(exc, "rv", None),
                    summary=f"CKM_SSL3_KEY_AND_MAC_DERIVE not operational: {exc}",
                )
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, master_secret)

    def test_derive_key_material_exact_vector(self, p11_raw_session: Any) -> None:
        """Verify CKM_SSL3_KEY_AND_MAC_DERIVE produces exact RFC 6101 vectors."""
        rs = p11_raw_session
        if not rs.has_mechanism("SSL3_KEY_AND_MAC_DERIVE"):
            pytest.skip("CKM_SSL3_KEY_AND_MAC_DERIVE not supported")

        master_secret_data = _ssl3_master_secret_reference(
            _PRE_MASTER_SECRET, _CLIENT_RANDOM, _SERVER_RANDOM
        )
        master_secret = _create_generic_secret(rs, master_secret_data)
        hard_results: list[C.Classification] = []
        try:
            # We request 128-bit keys (16 bytes) and two 128-bit MAC secrets (16 bytes each).
            # Key block size = 2 * (16 + 16 + 16) = 96 bytes (for AES-128 with 16-byte IVs).
            key_size_bits = 128
            mech = mech_ssl3_key_mat(
                CKM_SSL3_KEY_AND_MAC_DERIVE,
                _CLIENT_RANDOM,
                _SERVER_RANDOM,
                mac_size_bits=128,
                key_size_bits=key_size_bits,
            )

            # Expected key block for our fixed inputs
            expected_block = _ssl3_key_block_reference(
                master_secret_data,
                _CLIENT_RANDOM,
                _SERVER_RANDOM,
                96,
            )

            out = mech.key_mat_out
            try:
                _derive_key_material_to_params(
                    rs,
                    master_secret,
                    {
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech,
                )
            except BaseException:
                # A provider may write some output handles before returning an
                # error.  The output structure was captured before the call so
                # every such handle is still cleaned up.
                destroy_returned_handles(
                    rs,
                    out.hClientMacSecret,
                    out.hServerMacSecret,
                    out.hClientKey,
                    out.hServerKey,
                )
                raise

            for handle, label in (
                (out.hClientMacSecret, "client MAC secret"),
                (out.hServerMacSecret, "server MAC secret"),
                (out.hClientKey, "client key"),
                (out.hServerKey, "server key"),
            ):
                if handle == 0:
                    hard_results.append(
                        _record_handle_mismatch(
                            label=f"CKM_SSL3_KEY_AND_MAC_DERIVE:{label} output handle",
                            actual=handle,
                            mechanism="CKM_SSL3_KEY_AND_MAC_DERIVE",
                        )
                    )

            try:
                # Client MAC secret (16 bytes), Server MAC secret (16 bytes),
                # Client Key (16 bytes), Server Key (16 bytes),
                # Client IV (16 bytes), Server IV (16 bytes).
                # Total = 96 bytes.
                c_mac = MISSING_ATTRIBUTE
                if out.hClientMacSecret != 0:
                    c_mac = _read_provider_attribute(
                        rs.raw,
                        rs.sh,
                        out.hClientMacSecret,
                        CKA_VALUE,
                        label="CKM_SSL3_KEY_AND_MAC_DERIVE:client MAC CKA_VALUE readback",
                        mechanism="CKM_SSL3_KEY_AND_MAC_DERIVE",
                        error_rvs=_DERIVE_ERROR_RVS,
                    )
                s_mac = MISSING_ATTRIBUTE
                if out.hServerMacSecret != 0:
                    s_mac = _read_provider_attribute(
                        rs.raw,
                        rs.sh,
                        out.hServerMacSecret,
                        CKA_VALUE,
                        label="CKM_SSL3_KEY_AND_MAC_DERIVE:server MAC CKA_VALUE readback",
                        mechanism="CKM_SSL3_KEY_AND_MAC_DERIVE",
                        error_rvs=_DERIVE_ERROR_RVS,
                    )
                c_key = MISSING_ATTRIBUTE
                if out.hClientKey != 0:
                    c_key = _read_provider_attribute(
                        rs.raw,
                        rs.sh,
                        out.hClientKey,
                        CKA_VALUE,
                        label="CKM_SSL3_KEY_AND_MAC_DERIVE:client key CKA_VALUE readback",
                        mechanism="CKM_SSL3_KEY_AND_MAC_DERIVE",
                        error_rvs=_DERIVE_ERROR_RVS,
                    )
                s_key = MISSING_ATTRIBUTE
                if out.hServerKey != 0:
                    s_key = _read_provider_attribute(
                        rs.raw,
                        rs.sh,
                        out.hServerKey,
                        CKA_VALUE,
                        label="CKM_SSL3_KEY_AND_MAC_DERIVE:server key CKA_VALUE readback",
                        mechanism="CKM_SSL3_KEY_AND_MAC_DERIVE",
                        error_rvs=_DERIVE_ERROR_RVS,
                    )
                for label, value, expected in (
                    ("client MAC", c_mac, expected_block[:16]),
                    ("server MAC", s_mac, expected_block[16:32]),
                    ("client key", c_key, expected_block[32:48]),
                    ("server key", s_key, expected_block[48:64]),
                ):
                    mismatch = _validate_output(
                        value,
                        label=f"CKM_SSL3_KEY_AND_MAC_DERIVE:{label} CKA_VALUE readback",
                        mechanism="CKM_SSL3_KEY_AND_MAC_DERIVE",
                        operation="C_DeriveKey",
                        expected_len=16,
                        expected=expected,
                    )
                    if mismatch is not None:
                        hard_results.append(mismatch)
                c_iv = mech.buffer_bytes("iv_client")
                s_iv = mech.buffer_bytes("iv_server")
                if c_iv != expected_block[64:80]:
                    hard_results.append(
                        _record_parameter_mismatch(
                            label="CKM_SSL3_KEY_AND_MAC_DERIVE:client IV output",
                            parameter="pIVClient",
                            expected=expected_block[64:80],
                            actual=c_iv,
                            mechanism="CKM_SSL3_KEY_AND_MAC_DERIVE",
                        )
                    )
                if s_iv != expected_block[80:96]:
                    hard_results.append(
                        _record_parameter_mismatch(
                            label="CKM_SSL3_KEY_AND_MAC_DERIVE:server IV output",
                            parameter="pIVServer",
                            expected=expected_block[80:96],
                            actual=s_iv,
                            mechanism="CKM_SSL3_KEY_AND_MAC_DERIVE",
                        )
                    )
            finally:
                destroy_returned_handles(
                    rs,
                    out.hClientMacSecret,
                    out.hServerMacSecret,
                    out.hClientKey,
                    out.hServerKey,
                )
            _raise_strongest(hard_results)
        except AssertionError as exc:
            if is_known_error(exc, _DERIVE_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_KEY_AND_MAC_DERIVE:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_SSL3_KEY_AND_MAC_DERIVE",
                    actual=getattr(exc, "rv", None),
                    summary=f"CKM_SSL3_KEY_AND_MAC_DERIVE not operational: {exc}",
                )
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, master_secret)

    def test_rejects_template_protection_conflict(self, p11_raw_session: Any) -> None:
        """CKM_SSL3_KEY_AND_MAC_DERIVE rejects template protection overrides."""
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
            _derive_ssl3_key_material_template_conflict(
                rs,
                master_secret,
                mech,
                label="CKM_SSL3_KEY_AND_MAC_DERIVE template protection conflict",
            )
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
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_MD5_MAC:C_Sign",
                    operation="C_Sign",
                    mechanism="CKM_SSL3_MD5_MAC",
                    summary=f"CKM_SSL3_MD5_MAC sign not operational: {exc}",
                )
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
            assert_correct(
                actual=mac1,
                expected=mac2,
                label="CKM_SSL3_MD5_MAC:C_Sign determinism",
                operation="C_Sign",
                mechanism="CKM_SSL3_MD5_MAC",
            )
        except AssertionError as exc:
            if is_known_error(exc, _MAC_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_MD5_MAC:C_Sign",
                    operation="C_Sign",
                    mechanism="CKM_SSL3_MD5_MAC",
                    summary=f"CKM_SSL3_MD5_MAC not operational: {exc}",
                )
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
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_MD5_MAC:C_Sign",
                    operation="C_Sign",
                    mechanism="CKM_SSL3_MD5_MAC",
                    summary=f"CKM_SSL3_MD5_MAC not operational: {exc}",
                )
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
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_SHA1_MAC:C_Sign",
                    operation="C_Sign",
                    mechanism="CKM_SSL3_SHA1_MAC",
                    summary=f"CKM_SSL3_SHA1_MAC sign not operational: {exc}",
                )
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
            assert_correct(
                actual=mac1,
                expected=mac2,
                label="CKM_SSL3_SHA1_MAC:C_Sign determinism",
                operation="C_Sign",
                mechanism="CKM_SSL3_SHA1_MAC",
            )
        except AssertionError as exc:
            if is_known_error(exc, _MAC_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_SHA1_MAC:C_Sign",
                    operation="C_Sign",
                    mechanism="CKM_SSL3_SHA1_MAC",
                    summary=f"CKM_SSL3_SHA1_MAC not operational: {exc}",
                )
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
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_SHA1_MAC:C_Sign",
                    operation="C_Sign",
                    mechanism="CKM_SSL3_SHA1_MAC",
                    summary=f"CKM_SSL3_SHA1_MAC not operational: {exc}",
                )
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
            if mac1 == mac2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_SSL3_MD5_MAC:key must affect output",
                    operation="C_Sign",
                    mechanism="CKM_SSL3_MD5_MAC",
                    summary=(
                        "CKM_SSL3_MD5_MAC produced the same MAC for two different keys "
                        "over identical data -- the key was ignored"
                    ),
                )
        except AssertionError as exc:
            if is_known_error(exc, _MAC_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_MD5_MAC:C_Sign",
                    operation="C_Sign",
                    mechanism="CKM_SSL3_MD5_MAC",
                    summary=f"CKM_SSL3_MD5_MAC not operational: {exc}",
                )
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
            if mac1 == mac2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_SSL3_SHA1_MAC:key must affect output",
                    operation="C_Sign",
                    mechanism="CKM_SSL3_SHA1_MAC",
                    summary=(
                        "CKM_SSL3_SHA1_MAC produced the same MAC for two different keys "
                        "over identical data -- the key was ignored"
                    ),
                )
        except AssertionError as exc:
            if is_known_error(exc, _MAC_ERROR_RVS):
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_SSL3_SHA1_MAC:C_Sign",
                    operation="C_Sign",
                    mechanism="CKM_SSL3_SHA1_MAC",
                    summary=f"CKM_SSL3_SHA1_MAC not operational: {exc}",
                )
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key2)
            destroy_quietly(rs.raw, rs.sh, key1)
