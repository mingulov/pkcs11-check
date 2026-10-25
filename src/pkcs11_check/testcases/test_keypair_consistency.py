"""Keypair attribute consistency tests.

Verifies that public and private keys in a generated keypair have consistent
attributes - modulus matches for RSA, EC params match for EC.  Catches bugs
where modules produce mathematically inconsistent keypairs.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.core.crash_codes import ctypes_access_violation_code
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_bytes, template
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    find_objects,
    pack_attrs,
    read_attributes,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_MODULUS_BITS,
    CKA_PUBLIC_EXPONENT,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_EC,
    CKK_RSA,
    CKO_PUBLIC_KEY,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import (
    gen_ec_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
    require_keygen_key_size,
    skip_unless_create_object_supported,
)

pytestmark = pytest.mark.keymgmt

_KIND_PRIORITY = {"metadata": 1, "lifecycle": 2, "policy": 2, "crypto": 3}
_SEVERITY_PRIORITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _attribute_info(attr: int) -> dict[str, Any]:
    """Return the stable structured identity for a provider attribute."""
    from pkcs11_check.raw.metadata_std import ATTR_NAMES

    return {"name": ATTR_NAMES.get(int(attr), f"0x{int(attr):08x}"), "id": int(attr)}


def _provider_detail(
    attr: int, *, leg: str, producer_operation: str = "C_GenerateKeyPair"
) -> dict[str, Any]:
    return {
        "attribute": _attribute_info(attr),
        "leg": leg,
        "producer_operation": producer_operation,
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
    producer_operation: str = "C_GenerateKeyPair",
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
            inherit_mechanism=False,
            expected=CKR_OK,
            actual=exc.rv,
            detail=_with_producer(
                _provider_detail(attr, leg=leg, producer_operation=producer_operation),
                mechanism=mechanism,
            ),
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
    record.detail.update(
        _with_producer(
            _provider_detail(attr, leg=leg, producer_operation=producer_operation),
            mechanism=mechanism,
        )
    )
    return value, record


def _record_wrong_attribute(
    *,
    attr: int,
    leg: str,
    label: str,
    expected: str,
    actual: Any,
    mechanism: str,
    producer_operation: str = "C_GenerateKeyPair",
) -> C.Classification:
    detail = _with_producer(
        _provider_detail(attr, leg=leg, producer_operation=producer_operation),
        mechanism=mechanism,
    )
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


# --- QC7b (#59.2/.3): always-selected CKA_MODULUS_BITS ------------------------
#
# Table 37 lists CKA_MODULUS_BITS on every RSA public key; it equals the
# integer bit length of CKA_MODULUS (int.from_bytes(...).bit_length(),
# so leading-zero padding does not inflate it). Footnote 2 forbids the
# caller from supplying it to C_CreateObject. The gated ACVP keygen
# coverage is preserved untouched; these nodes are always selected.

_QC7_HANDLE_SENTINEL = 0x51515151
_KNOWN_RSA_CACHE: dict[str, tuple[int, bytes, bytes]] = {}


def _qc7_inventory(rs: Any) -> list[int]:
    """All currently visible object handles (unfiltered FindObjects)."""
    return find_objects(rs.raw, rs.sh)


def _qc7_handle_class(handle_value: int, *, found: list[int], new_handles: list[int]) -> str:
    if handle_value == _QC7_HANDLE_SENTINEL:
        return "sentinel"
    if handle_value == 0:
        return "zero"
    if handle_value in found or handle_value in new_handles:
        return "new-live"
    return "dead-nonzero"


def _known_rsa_public() -> tuple[int, bytes, bytes]:
    """Independent known RSA-2048 public material: (n, n_bytes, e_bytes)."""
    cached = _KNOWN_RSA_CACHE.get("rsa2048")
    if cached is not None:
        return cached
    from cryptography.hazmat.primitives.asymmetric import rsa

    numbers = rsa.generate_private_key(65537, 2048).public_key().public_numbers()
    n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    result = (numbers.n, n_bytes, e_bytes)
    _KNOWN_RSA_CACHE["rsa2048"] = result
    return result


def _check_modulus_bits(
    rs: Any,
    handle: int,
    *,
    expected_bits: int,
    label: str,
    producer_operation: str,
    expected_modulus_int: int | None = None,
) -> list[C.Classification]:
    """Read MODULUS and MODULUS_BITS (both always) and judge bit length."""
    mechanism = "CKM_RSA_PKCS_KEY_PAIR_GEN" if producer_operation == "C_GenerateKeyPair" else ""
    records: list[C.Classification] = []
    modulus, modulus_read = _read_leg(
        rs,
        handle,
        CKA_MODULUS,
        leg="public",
        label=f"{label}:modulus",
        mechanism=mechanism,
        producer_operation=producer_operation,
    )
    if modulus_read is not None:
        records.append(modulus_read)
    bits, bits_read = _read_leg(
        rs,
        handle,
        CKA_MODULUS_BITS,
        leg="public",
        label=f"{label}:modulus-bits",
        mechanism=mechanism,
        producer_operation=producer_operation,
    )
    if bits_read is not None:
        records.append(bits_read)

    if modulus is not MISSING_ATTRIBUTE and (type(modulus) is not bytes or len(modulus) == 0):
        records.append(
            _record_wrong_attribute(
                attr=CKA_MODULUS,
                leg="public",
                label=f"{label}:modulus",
                expected="non-empty bytes",
                actual=modulus,
                mechanism=mechanism,
                producer_operation=producer_operation,
            )
        )
    if (
        modulus is not MISSING_ATTRIBUTE
        and type(modulus) is bytes
        and len(modulus) > 0
        and expected_modulus_int is not None
        and int.from_bytes(modulus, "big") != expected_modulus_int
    ):
        records.append(
            _record_wrong_attribute(
                attr=CKA_MODULUS,
                leg="public",
                label=f"{label}:modulus",
                expected="the imported known modulus integer",
                actual=f"{len(modulus)}-byte modulus with a different integer value",
                mechanism=mechanism,
                producer_operation=producer_operation,
            )
        )
    if bits is not MISSING_ATTRIBUTE:
        if isinstance(bits, bool) or not isinstance(bits, int):
            records.append(
                _record_wrong_attribute(
                    attr=CKA_MODULUS_BITS,
                    leg="public",
                    label=f"{label}:modulus-bits",
                    expected="CK_ULONG integer (not bool/bytes)",
                    actual=bits,
                    mechanism=mechanism,
                    producer_operation=producer_operation,
                )
            )
        elif modulus is not MISSING_ATTRIBUTE and type(modulus) is bytes and len(modulus) > 0:
            bit_length = int.from_bytes(modulus, "big").bit_length()
            if bits != bit_length or bits != expected_bits:
                records.append(
                    _record_wrong_attribute(
                        attr=CKA_MODULUS_BITS,
                        leg="public",
                        label=f"{label}:modulus-bits",
                        expected=(f"integer bit length {bit_length} (requested {expected_bits})"),
                        actual=bits,
                        mechanism=mechanism,
                        producer_operation=producer_operation,
                    )
                )
    return records


def _import_known_rsa_public_or_xfail(
    rs: Any, modulus_bytes: bytes, exponent_bytes: bytes, *, purpose: str
) -> int:
    """Import the known RSA public key omitting MODULUS_BITS (valid control)."""
    try:
        return create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_PUBLIC_KEY,
                CKA_KEY_TYPE: CKK_RSA,
                CKA_MODULUS: modulus_bytes,
                CKA_PUBLIC_EXPONENT: exponent_bytes,
                CKA_TOKEN: False,
                CKA_VERIFY: True,
            },
        )
    except CkrAssertionError as exc:
        if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv):
            C.xfail_as(
                "not_operational",
                kind="metadata",
                label=purpose,
                operation="C_CreateObject",
                inherit_mechanism=False,
                expected=CKR_OK,
                actual=exc.rv,
                detail=_with_producer(
                    _provider_detail(
                        CKA_MODULUS_BITS, leg="public", producer_operation="C_CreateObject"
                    ),
                    mechanism="",
                ),
                summary=f"{purpose}: import refused with {ckr_name(exc.rv)}",
            )
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=purpose,
            operation="C_CreateObject",
            inherit_mechanism=False,
            expected=CKR_OK,
            actual=exc.rv,
            summary=f"{purpose}: import returned undefined CK_RV {ckr_name(exc.rv)}",
        )


class TestRSAModulusBits:
    """QC7b: CKA_MODULUS_BITS on generated/imported RSA public keys."""

    @pytest.mark.parametrize("bits", [2048, 3072])
    def test_generated_modulus_bits_match(self, p11_raw_session: Any, bits: int) -> None:
        """Generated RSA public MODULUS_BITS equals the modulus bit length."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA key generation not supported")
        require_keygen_key_size(rs, "RSA_PKCS_KEY_PAIR_GEN", bits, label=f"RSA-{bits} modulus bits")
        pub, priv = gen_rsa_keypair_or_xfail(rs, bits)
        try:
            records = _check_modulus_bits(
                rs,
                pub,
                expected_bits=bits,
                label=f"RSA-{bits} CKA_MODULUS_BITS",
                producer_operation="C_GenerateKeyPair",
            )
            _raise_strongest(records)
        finally:
            _destroy_pair(rs, pub, priv)

    def test_imported_known_modulus_bits(self, p11_raw_session: Any) -> None:
        """Imported known RSA public key reports MODULUS_BITS (bits omitted)."""
        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
        n, n_bytes, e_bytes = _known_rsa_public()
        handle = _import_known_rsa_public_or_xfail(
            rs, n_bytes, e_bytes, purpose="QC7b known RSA public import"
        )
        try:
            records = _check_modulus_bits(
                rs,
                handle,
                expected_bits=n.bit_length(),
                label="imported RSA CKA_MODULUS_BITS",
                producer_operation="C_CreateObject",
                expected_modulus_int=n,
            )
            _raise_strongest(records)
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)

    def test_imported_leading_zero_modulus_bits(self, p11_raw_session: Any) -> None:
        """Leading-zero-padded modulus template still yields the bit length.

        A clean refusal of the padded encoding xfails with the original
        RV; acceptance requires bits/modulus integer equality.
        """
        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
        n, n_bytes, e_bytes = _known_rsa_public()
        handle = _import_known_rsa_public_or_xfail(
            rs, b"\x00" + n_bytes, e_bytes, purpose="QC7b padded RSA public import"
        )
        try:
            records = _check_modulus_bits(
                rs,
                handle,
                expected_bits=n.bit_length(),
                label="padded imported RSA CKA_MODULUS_BITS",
                producer_operation="C_CreateObject",
                expected_modulus_int=n,
            )
            _raise_strongest(records)
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)

    @pytest.mark.parametrize("supplied", ["correct", "wrong"])
    def test_create_with_modulus_bits_rejected(self, p11_raw_session: Any, supplied: str) -> None:
        """C_CreateObject with forbidden MODULUS_BITS: stored-vs-true tiers.

        Refusal legs judge objects, not handle writes (adjudicated O1).
        Acceptance judges the stored bits against the true modulus bit
        length (O2): stored == true or dropped is an honest deviation,
        stored != true FAILs as false metadata, and CKR_OK with no
        locatable object FAILs as a self-contradiction.
        """
        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
        n, n_bytes, e_bytes = _known_rsa_public()
        true_bits = n.bit_length()
        supplied_bits = true_bits if supplied == "correct" else 1024
        label_text = f"qc7-forbidden-modulus-bits-{supplied}"
        attrs: dict[Any, Any] = {
            CKA_CLASS: CKO_PUBLIC_KEY,
            CKA_KEY_TYPE: CKK_RSA,
            CKA_MODULUS: n_bytes,
            CKA_PUBLIC_EXPONENT: e_bytes,
            CKA_MODULUS_BITS: supplied_bits,
            CKA_TOKEN: False,
            CKA_VERIFY: True,
            CKA_LABEL: label_text,
        }
        tmpl = template(*pack_attrs(attrs))
        handle = CK_OBJECT_HANDLE(_QC7_HANDLE_SENTINEL)
        inventory_before = _qc7_inventory(rs)
        rv = int(rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle)))
        label = f"forbidden CKA_MODULUS_BITS on C_CreateObject ({supplied})"
        records: list[C.Classification] = []
        leaked: list[int] = []
        detail = _with_producer(
            _provider_detail(CKA_MODULUS_BITS, leg="public", producer_operation="C_CreateObject"),
            mechanism="",
        )
        try:
            found = find_objects(
                rs.raw, rs.sh, template(attr_bytes(CKA_LABEL, label_text.encode()))
            )
            inventory_after = _qc7_inventory(rs)
            new_handles = sorted(set(inventory_after) - set(inventory_before))
            handle_after = int(handle.value)
            detail = {
                **detail,
                "handle_after": handle_after,
                "handle_class": _qc7_handle_class(
                    handle_after, found=found, new_handles=new_handles
                ),
                "found_by_label": list(found),
                "new_handles": new_handles,
                "supplied_bits": supplied_bits,
                "true_bits": true_bits,
                "stored_bits": None,
            }
            if rv == int(CKR_OK):
                # Locatable object: the output handle when it names a live
                # object, else the label/inventory-delta evidence. A bare
                # handle naming nothing is never read or destroyed.
                target = 0
                if handle_after in inventory_after:
                    target = handle_after
                elif found:
                    target = found[0]
                elif new_handles:
                    target = new_handles[0]
                leaked.extend(found)
                leaked.extend(h for h in new_handles if h not in leaked)
                stored_bits: int | None = None
                stored_malformed = False
                stored_note = "not-read"
                if target:
                    try:
                        stored_value, _stored_read = _read_leg(
                            rs,
                            target,
                            CKA_MODULUS_BITS,
                            leg="public",
                            label=f"{label}:stored-bits note",
                            mechanism="",
                            producer_operation="C_CreateObject",
                        )
                        if stored_value is MISSING_ATTRIBUTE:
                            stored_note = "caller-value-dropped"
                        elif isinstance(stored_value, bool) or not isinstance(stored_value, int):
                            stored_note = "stored-bits-malformed"
                            stored_malformed = True
                        else:
                            stored_bits = stored_value
                            stored_note = (
                                "stored-equals-supplied"
                                if stored_value == supplied_bits
                                else "caller-value-overwritten"
                            )
                    except CkrAssertionError:
                        stored_note = "stored-bits-unreadable"
                ok_detail = {
                    **detail,
                    "supplied_bits": supplied_bits,
                    "true_bits": true_bits,
                    "stored_bits": stored_bits,
                    "stored": stored_note,
                }
                if target and (
                    stored_malformed or (stored_bits is not None and stored_bits != true_bits)
                ):
                    records.append(
                        C.record_as(
                            "accepted_invalid",
                            kind="metadata",
                            label=label,
                            operation="C_CreateObject",
                            inherit_mechanism=False,
                            expected=(CKR_ATTRIBUTE_READ_ONLY, CKR_TEMPLATE_INCONSISTENT),
                            actual=rv,
                            detail=ok_detail,
                            summary=(
                                f"{label}: forbidden attribute accepted (CKR_OK) and "
                                "false CKA_MODULUS_BITS metadata stored"
                            ),
                        )
                    )
                elif not target:
                    records.append(
                        C.record_as(
                            "self_contradiction",
                            kind="metadata",
                            label=label,
                            operation="C_CreateObject",
                            inherit_mechanism=False,
                            actual=rv,
                            detail=ok_detail,
                            summary=f"{label}: CKR_OK without a created object",
                        )
                    )
                elif stored_bits is not None and stored_bits == true_bits:
                    records.append(
                        C.record_as(
                            "honest_deviation",
                            kind="metadata",
                            label=label,
                            operation="C_CreateObject",
                            inherit_mechanism=False,
                            expected=(CKR_ATTRIBUTE_READ_ONLY, CKR_TEMPLATE_INCONSISTENT),
                            actual=rv,
                            detail=ok_detail,
                            summary=(
                                f"{label}: forbidden attribute accepted (CKR_OK); "
                                "stored CKA_MODULUS_BITS equals the true modulus "
                                "bit length"
                            ),
                        )
                    )
                else:
                    records.append(
                        C.record_as(
                            "honest_deviation",
                            kind="metadata",
                            label=label,
                            operation="C_CreateObject",
                            inherit_mechanism=False,
                            expected=(CKR_ATTRIBUTE_READ_ONLY, CKR_TEMPLATE_INCONSISTENT),
                            actual=rv,
                            detail=ok_detail,
                            summary=(
                                f"{label}: forbidden attribute accepted (CKR_OK) and "
                                "ignored/dropped; no false bits proven"
                            ),
                        )
                    )
            elif found or new_handles:
                leaked.extend(found)
                leaked.extend(h for h in new_handles if h not in leaked)
                records.append(
                    C.record_as(
                        "self_contradiction",
                        kind="metadata",
                        label=label,
                        operation="C_CreateObject",
                        inherit_mechanism=False,
                        actual=rv,
                        detail=detail,
                        summary=f"{label}: refusal {ckr_name(rv)} left an object behind",
                    )
                )
            elif handle_after not in (_QC7_HANDLE_SENTINEL, 0):
                records.append(
                    C.record_as(
                        "honest_deviation",
                        kind="metadata",
                        label=label,
                        operation="C_CreateObject",
                        inherit_mechanism=False,
                        actual=rv,
                        detail=detail,
                        summary=(
                            f"{label}: refusal {ckr_name(rv)} wrote non-invalid output "
                            f"handle {handle_after}; no object created"
                        ),
                    )
                )
            elif rv in (int(CKR_ATTRIBUTE_READ_ONLY), int(CKR_TEMPLATE_INCONSISTENT)):
                pass  # Canonical rejection, no object (sentinel or zero write).
            elif is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
                records.append(
                    C.record_as(
                        "nonspec_reject",
                        kind="metadata",
                        label=label,
                        operation="C_CreateObject",
                        inherit_mechanism=False,
                        expected=(CKR_ATTRIBUTE_READ_ONLY, CKR_TEMPLATE_INCONSISTENT),
                        actual=rv,
                        detail=detail,
                        summary=f"{label}: rejected with {ckr_name(rv)}",
                    )
                )
            else:
                records.append(
                    C.record_as(
                        "self_contradiction",
                        kind="metadata",
                        label=label,
                        operation="C_CreateObject",
                        inherit_mechanism=False,
                        actual=rv,
                        detail=detail,
                        summary=f"{label}: rejected with undefined CK_RV {ckr_name(rv)}",
                    )
                )
        finally:
            for leaked_handle in dict.fromkeys(leaked):
                destroy_quietly(rs.raw, rs.sh, leaked_handle)
        _raise_strongest(records)
