"""Keypair attribute consistency tests.

Verifies that public and private keys in a generated keypair have consistent
attributes - modulus matches for RSA, EC params match for EC.  Catches bugs
where modules produce mathematically inconsistent keypairs.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.core.crash_codes import ctypes_access_violation_code
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    read_attributes,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKK_EC,
    CKR_OK,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import (
    gen_ec_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
)

pytestmark = pytest.mark.keymgmt

_KIND_PRIORITY = {"metadata": 1, "lifecycle": 2, "policy": 2, "crypto": 3}
_SEVERITY_PRIORITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _attribute_info(attr: int) -> dict[str, Any]:
    """Return the stable structured identity for a provider attribute."""
    from pkcs11_check.raw.metadata_std import ATTR_NAMES

    return {"name": ATTR_NAMES.get(int(attr), f"0x{int(attr):08x}"), "id": int(attr)}


def _provider_detail(attr: int, *, leg: str) -> dict[str, Any]:
    return {
        "attribute": _attribute_info(attr),
        "leg": leg,
        "producer_operation": "C_GenerateKeyPair",
        "producer_mechanism": "",
    }


def _with_producer(detail: dict[str, Any], *, mechanism: str) -> dict[str, Any]:
    detail["producer_mechanism"] = mechanism
    return detail


def _read_leg(
    rs: Any,
    handle: int,
    attr: int,
    *,
    leg: str,
    label: str,
    mechanism: str,
) -> tuple[Any, C.Classification | None]:
    """Read one key leg, retaining a non-terminating provider result."""
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [attr])
    except CkrAssertionError as exc:
        reason = (
            "not_operational"
            if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv)
            else "self_contradiction"
        )
        record = C.record_as(
            reason,
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=mechanism,
            expected=CKR_OK,
            actual=exc.rv,
            detail=_with_producer(_provider_detail(attr, leg=leg), mechanism=mechanism),
            summary=(
                f"{label}: attribute read returned {ckr_name(exc.rv)}"
                if reason == "self_contradiction"
                else f"{label}: attribute read was rejected with {ckr_name(exc.rv)}"
            ),
        )
        return MISSING_ATTRIBUTE, record

    before = len(C.get_records())
    value = attr_or_record(
        attrs,
        attr,
        label=label,
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )
    if value is not MISSING_ATTRIBUTE:
        return value, None

    records = C.get_records()
    if len(records) == before:
        raise AssertionError(f"{label}: missing attribute did not produce evidence")
    record = records[-1]
    if record.detail is None:
        record.detail = {}
    record.detail.update(_with_producer(_provider_detail(attr, leg=leg), mechanism=mechanism))
    return value, record


def _record_wrong_attribute(
    *,
    attr: int,
    leg: str,
    label: str,
    expected: str,
    actual: Any,
    mechanism: str,
) -> C.Classification:
    detail = _with_producer(_provider_detail(attr, leg=leg), mechanism=mechanism)
    detail.update({"expected": expected, "actual": repr(actual)})
    return C.record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        mechanism=mechanism,
        detail=detail,
        summary=f"{label}: provider returned malformed {repr(actual)}; expected {expected}",
    )


def _record_pair_mismatch(
    *,
    attr: int,
    label: str,
    public: bytes,
    private: bytes,
    mechanism: str,
) -> C.Classification:
    detail = {
        "attribute": _attribute_info(attr),
        "public_leg": "public",
        "private_leg": "private",
        "expected": "equal provider representations",
        "actual": {"public": repr(public), "private": repr(private)},
        "producer_operation": "C_GenerateKeyPair",
        "producer_mechanism": mechanism,
    }
    return C.record_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        mechanism=mechanism,
        detail=detail,
        summary=f"{label}: public and private provider values differ",
    )


def _check_nonempty_bytes(
    value: Any,
    *,
    attr: int,
    leg: str,
    label: str,
    mechanism: str,
) -> C.Classification | None:
    if value is MISSING_ATTRIBUTE:
        return None
    if type(value) is bytes and len(value) > 0:
        return None
    return _record_wrong_attribute(
        attr=attr,
        leg=leg,
        label=label,
        expected="non-empty bytes",
        actual=value,
        mechanism=mechanism,
    )


def _check_ec_key_type(
    value: Any,
    *,
    leg: str,
    label: str,
    mechanism: str,
) -> C.Classification | None:
    if value is MISSING_ATTRIBUTE:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        expected = "CK_ULONG integer (not bool) equal to CKK_EC"
    elif value != CKK_EC:
        expected = "CKK_EC"
    else:
        return None
    return _record_wrong_attribute(
        attr=CKA_KEY_TYPE,
        leg=leg,
        label=label,
        expected=expected,
        actual=value,
        mechanism=mechanism,
    )


def _read_pair(
    rs: Any,
    pub: int,
    priv: int,
    attr: int,
    *,
    label: str,
    mechanism: str,
) -> tuple[Any, Any, list[C.Classification]]:
    """Read and retain both linked legs before evaluating either value."""
    observations: list[C.Classification] = []
    public, public_read = _read_leg(
        rs,
        pub,
        attr,
        leg="public",
        label=f"{label}:public",
        mechanism=mechanism,
    )
    if public_read is not None:
        observations.append(public_read)
    public_shape = _check_nonempty_bytes(
        public,
        attr=attr,
        leg="public",
        label=f"{label}:public",
        mechanism=mechanism,
    )
    if public_shape is not None:
        observations.append(public_shape)
    private, private_read = _read_leg(
        rs,
        priv,
        attr,
        leg="private",
        label=f"{label}:private",
        mechanism=mechanism,
    )
    if private_read is not None:
        observations.append(private_read)
    private_shape = _check_nonempty_bytes(
        private,
        attr=attr,
        leg="private",
        label=f"{label}:private",
        mechanism=mechanism,
    )
    if private_shape is not None:
        observations.append(private_shape)
    return public, private, observations


def _raise_strongest(records: list[C.Classification]) -> None:
    """Raise the strongest result after every independent observation ran."""
    if not records:
        return
    strongest = max(
        records,
        key=lambda record: (
            1 if record.outcome == "fail" else 0,
            _SEVERITY_PRIORITY.get(record.severity, 0),
            _KIND_PRIORITY.get(record.kind or "", 0),
        ),
    )
    C.raise_for_record(strongest)


def _destroy_pair(rs: Any, pub: int, priv: int) -> None:
    """Destroy both handles once, preferring a provider access violation."""
    first_error: BaseException | None = None
    access_violation: BaseException | None = None
    for handle in (pub, priv):
        try:
            destroy_quietly(rs.raw, rs.sh, handle)
        except BaseException as exc:
            if first_error is None:
                first_error = exc
            if ctypes_access_violation_code(exc) is not None:
                access_violation = exc
    if access_violation is not None:
        raise access_violation
    if first_error is not None:
        raise first_error


class TestRSAKeypairConsistency:
    """Verify RSA keypair attribute consistency."""

    def test_modulus_matches(self, p11_raw_session: Any) -> None:
        """Public and private RSA key have the same modulus."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA key generation not supported")

        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            public, private, records = _read_pair(
                rs,
                pub,
                priv,
                CKA_MODULUS,
                label="RSA CKA_MODULUS",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            if (
                not records
                and public is not MISSING_ATTRIBUTE
                and private is not MISSING_ATTRIBUTE
                and public != private
            ):
                records.append(
                    _record_pair_mismatch(
                        attr=CKA_MODULUS,
                        label="RSA CKA_MODULUS pair consistency",
                        public=public,
                        private=private,
                        mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    )
                )
            _raise_strongest(records)
        finally:
            _destroy_pair(rs, pub, priv)

    def test_public_exponent_matches(self, p11_raw_session: Any) -> None:
        """Public exponent is the same on both keys."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA key generation not supported")

        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            public, private, records = _read_pair(
                rs,
                pub,
                priv,
                CKA_PUBLIC_EXPONENT,
                label="RSA CKA_PUBLIC_EXPONENT",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            if (
                not records
                and public is not MISSING_ATTRIBUTE
                and private is not MISSING_ATTRIBUTE
                and public != private
            ):
                records.append(
                    _record_pair_mismatch(
                        attr=CKA_PUBLIC_EXPONENT,
                        label="RSA CKA_PUBLIC_EXPONENT pair consistency",
                        public=public,
                        private=private,
                        mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    )
                )
            _raise_strongest(records)
        finally:
            _destroy_pair(rs, pub, priv)

    def test_modulus_correct_size(self, p11_raw_session: Any) -> None:
        """RSA-2048 modulus is 256 bytes (2048 bits)."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA key generation not supported")

        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            modulus, read_result = _read_leg(
                rs,
                pub,
                CKA_MODULUS,
                leg="public",
                label="RSA CKA_MODULUS size:public",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            records: list[C.Classification] = []
            if read_result is not None:
                records.append(read_result)
            if modulus is not MISSING_ATTRIBUTE and (
                type(modulus) is not bytes or len(modulus) != 256
            ):
                records.append(
                    _record_wrong_attribute(
                        attr=CKA_MODULUS,
                        leg="public",
                        label="RSA CKA_MODULUS size:public",
                        expected="256-byte bytes",
                        actual=modulus,
                        mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    )
                )
            _raise_strongest(records)
        finally:
            _destroy_pair(rs, pub, priv)


class TestECKeypairConsistency:
    """Verify EC keypair attribute consistency."""

    def test_ec_params_match(self, p11_raw_session: Any) -> None:
        """Public and private EC key have the same CKA_EC_PARAMS."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(rs, curve_oid)
        try:
            public, private, records = _read_pair(
                rs,
                pub,
                priv,
                CKA_EC_PARAMS,
                label="EC CKA_EC_PARAMS",
                mechanism="CKM_EC_KEY_PAIR_GEN",
            )
            if (
                not records
                and public is not MISSING_ATTRIBUTE
                and private is not MISSING_ATTRIBUTE
                and public != private
            ):
                records.append(
                    _record_pair_mismatch(
                        attr=CKA_EC_PARAMS,
                        label="EC CKA_EC_PARAMS pair consistency",
                        public=public,
                        private=private,
                        mechanism="CKM_EC_KEY_PAIR_GEN",
                    )
                )
            _raise_strongest(records)
        finally:
            _destroy_pair(rs, pub, priv)

    def test_ec_point_on_pub_only(self, p11_raw_session: Any) -> None:
        """CKA_EC_POINT is available on the public key and is non-empty."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(rs, curve_oid)
        try:
            point, read_result = _read_leg(
                rs,
                pub,
                CKA_EC_POINT,
                leg="public",
                label="EC CKA_EC_POINT:public",
                mechanism="CKM_EC_KEY_PAIR_GEN",
            )
            records: list[C.Classification] = []
            if read_result is not None:
                records.append(read_result)
            malformed = _check_nonempty_bytes(
                point,
                attr=CKA_EC_POINT,
                leg="public",
                label="EC CKA_EC_POINT:public",
                mechanism="CKM_EC_KEY_PAIR_GEN",
            )
            if malformed is not None:
                records.append(malformed)
            _raise_strongest(records)
        finally:
            _destroy_pair(rs, pub, priv)

    def test_key_type_consistent(self, p11_raw_session: Any) -> None:
        """Both keys report CKK_EC."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(rs, curve_oid)
        try:
            public, public_read = _read_leg(
                rs,
                pub,
                CKA_KEY_TYPE,
                leg="public",
                label="EC CKA_KEY_TYPE:public",
                mechanism="CKM_EC_KEY_PAIR_GEN",
            )
            records: list[C.Classification] = []
            if public_read is not None:
                records.append(public_read)
            public_shape = _check_ec_key_type(
                public,
                leg="public",
                label="EC CKA_KEY_TYPE:public",
                mechanism="CKM_EC_KEY_PAIR_GEN",
            )
            if public_shape is not None:
                records.append(public_shape)
            private, private_read = _read_leg(
                rs,
                priv,
                CKA_KEY_TYPE,
                leg="private",
                label="EC CKA_KEY_TYPE:private",
                mechanism="CKM_EC_KEY_PAIR_GEN",
            )
            if private_read is not None:
                records.append(private_read)
            private_shape = _check_ec_key_type(
                private,
                leg="private",
                label="EC CKA_KEY_TYPE:private",
                mechanism="CKM_EC_KEY_PAIR_GEN",
            )
            if private_shape is not None:
                records.append(private_shape)
            _raise_strongest(records)
        finally:
            _destroy_pair(rs, pub, priv)
