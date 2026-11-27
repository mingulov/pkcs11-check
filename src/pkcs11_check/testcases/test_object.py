"""Tests for PKCS#11 object and key attribute management.

Covers object creation, attribute access, search, labels,
key pair attributes, and object lifecycle.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.metadata_std import ATTR_NAMES
from pkcs11_check.raw.pack import attr_bytes, attr_ulong, template
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    find_objects,
    gen_keypair,
    import_secret_key,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKA_BASE,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PARAMETER_SET,
    CKA_PRIME,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKK_AES,
    CKK_DH,
    CKK_EC,
    CKK_EC_EDWARDS,
    CKK_EC_MONTGOMERY,
    CKK_ML_DSA,
    CKK_RSA,
    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKM_SHA256_RSA_PKCS,
    CKM_SLH_DSA_KEY_PAIR_GEN,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKP_ML_DSA_44,
    CKP_ML_KEM_512,
    CKP_SLH_DSA_SHA2_128S,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases._attribute_values import (
    MISSING_ATTRIBUTE,
    attr_or_record,
    refusal_rv_for,
)
from pkcs11_check.testcases._rsa_export import rsa_public_key_from_attrs_or_xfail
from pkcs11_check.testcases.conftest import (
    EC_CURVE_UNSUPPORTED_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    create_object_negotiated,
    gen_aes_key_or_xfail,
    gen_ec_keypair_or_xfail,
    gen_edwards_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
    import_ec_private_key_negotiated,
    is_known_error,
    skip_unless_create_object_supported,
    skip_unless_mechanism,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.keymgmt


class TestSessionObjects:
    def test_create_secret_key_with_label(self, p11_raw_session: Any) -> None:
        """Create a named AES key and verify its label."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            bits=128,
            attrs={CKA_LABEL: "test-key-object"},
            purpose="object label setup",
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_LABEL])
            label_value = attr_or_record(
                attrs,
                CKA_LABEL,
                label="CKA_LABEL:session AES key",
                reason="not_operational",
                inherit_mechanism=False,
            )
            if label_value is not MISSING_ATTRIBUTE:
                assert label_value == "test-key-object"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_find_objects_by_label(self, p11_raw_session: Any) -> None:
        """Find objects matching a label template."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            bits=128,
            attrs={CKA_LABEL: "findme-obj"},
            purpose="object label search setup",
        )
        try:
            tmpl = template(attr_bytes(CKA_LABEL, b"findme-obj"))
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_key_attributes_readable(self, p11_raw_session: Any) -> None:
        """Key attributes (type, class) are readable."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            bits=128,
            attrs={CKA_LABEL: "attr-test"},
            purpose="object attribute readback setup",
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_KEY_TYPE, CKA_CLASS])
            key_type = attr_or_record(
                attrs,
                CKA_KEY_TYPE,
                label="CKA_KEY_TYPE:session AES key",
                reason="not_operational",
                inherit_mechanism=False,
            )
            obj_class = attr_or_record(
                attrs,
                CKA_CLASS,
                label="CKA_CLASS:session AES key",
                reason="not_operational",
                inherit_mechanism=False,
            )
            if key_type is not MISSING_ATTRIBUTE:
                assert key_type == CKK_AES
            if obj_class is not MISSING_ATTRIBUTE:
                assert obj_class == CKO_SECRET_KEY
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_destroy_session_object(self, p11_raw_session: Any) -> None:
        """Destroying a session object removes it."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            bits=128,
            attrs={CKA_LABEL: "destroy-me"},
            purpose="object destroy setup",
        )
        rs.raw.C_DestroyObject(rs.sh, key)
        tmpl = template(attr_bytes(CKA_LABEL, b"destroy-me"))
        found = find_objects(rs.raw, rs.sh, tmpl)
        assert len(found) == 0

    def test_multiple_keys_same_type(self, p11_raw_session: Any) -> None:
        """Multiple keys of same type coexist."""
        rs = p11_raw_session
        k1 = gen_aes_key_or_xfail(
            rs,
            bits=128,
            attrs={CKA_LABEL: "multi-1"},
            purpose="multi-object setup",
        )
        k2 = gen_aes_key_or_xfail(
            rs,
            bits=128,
            attrs={CKA_LABEL: "multi-2"},
            purpose="multi-object setup",
        )
        try:
            tmpl = template(attr_ulong(CKA_CLASS, CKO_SECRET_KEY))
            found = find_objects(rs.raw, rs.sh, tmpl)
            labels = set()
            label_omitted = False
            for h in found:
                a = read_attributes(rs.raw, rs.sh, h, [CKA_LABEL])
                label_value = attr_or_record(
                    a,
                    CKA_LABEL,
                    label="CKA_LABEL:multi-key search result",
                    reason="not_operational",
                    inherit_mechanism=False,
                )
                if label_value is MISSING_ATTRIBUTE:
                    label_omitted = True
                else:
                    labels.add(label_value)
            # The aggregate membership oracle below depends on EVERY found handle's label
            # having been readable; a single omission means we cannot tell whether the
            # missing label belonged to "multi-1"/"multi-2", so it must disable only this
            # dependent oracle, not surface as a hard AssertionError (contract rule 4).
            if not label_omitted:
                assert "multi-1" in labels
                assert "multi-2" in labels
        finally:
            destroy_quietly(rs.raw, rs.sh, k1)
            destroy_quietly(rs.raw, rs.sh, k2)

    def test_find_by_object_class(self, p11_raw_session: Any) -> None:
        """Search by object class returns correct types."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            bits=128,
            attrs={CKA_LABEL: "class-search"},
            purpose="object class search setup",
        )
        try:
            tmpl = template(attr_ulong(CKA_CLASS, CKO_SECRET_KEY))
            found = find_objects(rs.raw, rs.sh, tmpl)
            for h in found:
                a = read_attributes(rs.raw, rs.sh, h, [CKA_CLASS])
                obj_class = attr_or_record(
                    a,
                    CKA_CLASS,
                    label="CKA_CLASS:class search result",
                    reason="not_operational",
                    inherit_mechanism=False,
                )
                if obj_class is not MISSING_ATTRIBUTE:
                    assert obj_class == CKO_SECRET_KEY
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_empty_search_returns_empty(self, p11_raw_session: Any) -> None:
        """Searching with a nonexistent label returns empty."""
        rs = p11_raw_session
        tmpl = template(attr_bytes(CKA_LABEL, b"nonexistent-xyz-42"))
        found = find_objects(rs.raw, rs.sh, tmpl)
        assert len(found) == 0


class TestKeyPairAttributes:
    def test_rsa_keypair_attributes(self, p11_raw_session: Any) -> None:
        """RSA key pair has correct object classes."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_CLASS, CKA_KEY_TYPE])
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_CLASS, CKA_KEY_TYPE])
            pub_class = attr_or_record(
                pub_attrs,
                CKA_CLASS,
                label="CKA_CLASS:RSA-public",
                reason="not_operational",
                inherit_mechanism=False,
            )
            priv_class = attr_or_record(
                priv_attrs,
                CKA_CLASS,
                label="CKA_CLASS:RSA-private",
                reason="not_operational",
                inherit_mechanism=False,
            )
            pub_key_type = attr_or_record(
                pub_attrs,
                CKA_KEY_TYPE,
                label="CKA_KEY_TYPE:RSA-public",
                reason="not_operational",
                inherit_mechanism=False,
            )
            priv_key_type = attr_or_record(
                priv_attrs,
                CKA_KEY_TYPE,
                label="CKA_KEY_TYPE:RSA-private",
                reason="not_operational",
                inherit_mechanism=False,
            )
            if pub_class is not MISSING_ATTRIBUTE:
                assert pub_class == CKO_PUBLIC_KEY
            if priv_class is not MISSING_ATTRIBUTE:
                assert priv_class == CKO_PRIVATE_KEY
            if pub_key_type is not MISSING_ATTRIBUTE:
                assert pub_key_type == CKK_RSA
            if priv_key_type is not MISSING_ATTRIBUTE:
                assert priv_key_type == CKK_RSA
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_modulus_readable(self, p11_raw_session: Any) -> None:
        """RSA public key modulus is readable and correct size."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_MODULUS])
            modulus = attr_or_record(
                attrs,
                CKA_MODULUS,
                label="CKA_MODULUS:RSA-public",
                reason="not_operational",
                inherit_mechanism=False,
            )
            if modulus is not MISSING_ATTRIBUTE:
                assert len(modulus) == 256  # 2048 bits = 256 bytes
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_public_exponent(self, p11_raw_session: Any) -> None:
        """RSA public exponent is readable and typical value."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_PUBLIC_EXPONENT])
            exp = attr_or_record(
                attrs,
                CKA_PUBLIC_EXPONENT,
                label="CKA_PUBLIC_EXPONENT:RSA-public",
                reason="not_operational",
                inherit_mechanism=False,
            )
            if exp is not MISSING_ATTRIBUTE:
                exp_int = int.from_bytes(exp, "big")
                assert exp_int in (3, 17, 65537)  # Common RSA exponents
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ec_keypair_attributes(self, p11_raw_session: Any) -> None:
        """EC key pair has correct key type and params."""
        rs = p11_raw_session
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(rs, curve_oid)
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE])
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_KEY_TYPE])
            pub_key_type = attr_or_record(
                pub_attrs,
                CKA_KEY_TYPE,
                label="CKA_KEY_TYPE:EC-public",
                reason="not_operational",
                inherit_mechanism=False,
            )
            priv_key_type = attr_or_record(
                priv_attrs,
                CKA_KEY_TYPE,
                label="CKA_KEY_TYPE:EC-private",
                reason="not_operational",
                inherit_mechanism=False,
            )
            if pub_key_type is not MISSING_ATTRIBUTE:
                assert pub_key_type == CKK_EC
            if priv_key_type is not MISSING_ATTRIBUTE:
                assert priv_key_type == CKK_EC
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ec_point_readable(self, p11_raw_session: Any) -> None:
        """EC public key point is readable."""
        rs = p11_raw_session
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(rs, curve_oid)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_EC_POINT])
            point = attr_or_record(
                attrs,
                CKA_EC_POINT,
                label="CKA_EC_POINT:EC-public",
                reason="not_operational",
                inherit_mechanism=False,
            )
            if point is not MISSING_ATTRIBUTE:
                assert len(point) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestKeyImportExport:
    def test_import_aes_key_bytes(self, p11_raw_session: Any) -> None:
        """Import raw AES key material."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        key = import_secret_key(rs.raw, rs.sh, CKK_AES, key_bytes)
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_KEY_TYPE])
            key_type = attr_or_record(
                attrs,
                CKA_KEY_TYPE,
                label="CKA_KEY_TYPE:imported AES key",
                reason="not_operational",
                inherit_mechanism=False,
            )
            if key_type is not MISSING_ATTRIBUTE:
                assert key_type == CKK_AES
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_import_rsa_public_key(self, p11_raw_session: Any) -> None:
        """Import an RSA public key from modulus + exponent."""
        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_MODULUS, CKA_PUBLIC_EXPONENT])
            modulus = attr_or_record(
                attrs,
                CKA_MODULUS,
                label="CKA_MODULUS:RSA-public for import",
                reason="not_operational",
                inherit_mechanism=False,
            )
            exponent = attr_or_record(
                attrs,
                CKA_PUBLIC_EXPONENT,
                label="CKA_PUBLIC_EXPONENT:RSA-public for import",
                reason="not_operational",
                inherit_mechanism=False,
            )
            if modulus is MISSING_ATTRIBUTE or exponent is MISSING_ATTRIBUTE:
                return
            rsa_public_key_from_attrs_or_xfail(
                {CKA_MODULUS: modulus, CKA_PUBLIC_EXPONENT: exponent},
                label="generated RSA public key for import",
            )

            try:
                imported = create_object(
                    rs.raw,
                    rs.sh,
                    {
                        CKA_CLASS: CKO_PUBLIC_KEY,
                        CKA_KEY_TYPE: CKK_RSA,
                        CKA_MODULUS: modulus,
                        CKA_PUBLIC_EXPONENT: exponent,
                        CKA_TOKEN: False,
                        CKA_VERIFY: True,
                    },
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    KEYPAIR_RUNTIME_REJECT_RVS,
                    "RSA public key import not operational",
                )
                raise
            try:
                imp_attrs = read_attributes(rs.raw, rs.sh, imported, [CKA_KEY_TYPE])
                imp_key_type = attr_or_record(
                    imp_attrs,
                    CKA_KEY_TYPE,
                    label="CKA_KEY_TYPE:imported RSA public key",
                    reason="not_operational",
                    inherit_mechanism=False,
                )
                if imp_key_type is not MISSING_ATTRIBUTE:
                    assert imp_key_type == CKK_RSA
            finally:
                destroy_quietly(rs.raw, rs.sh, imported)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_imported_key_verifies_signature(self, p11_raw_session: Any) -> None:
        """Sign with generated key, verify with imported copy of pubkey."""
        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
        skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            private_attrs={CKA_SIGN: True},
        )
        try:
            data = b"import-verify roundtrip"
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)

            # Import a copy of the public key
            orig_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_MODULUS, CKA_PUBLIC_EXPONENT])
            orig_modulus = attr_or_record(
                orig_attrs,
                CKA_MODULUS,
                label="CKA_MODULUS:RSA-public for signature import",
                reason="not_operational",
                inherit_mechanism=False,
            )
            orig_exponent = attr_or_record(
                orig_attrs,
                CKA_PUBLIC_EXPONENT,
                label="CKA_PUBLIC_EXPONENT:RSA-public for signature import",
                reason="not_operational",
                inherit_mechanism=False,
            )
            if orig_modulus is MISSING_ATTRIBUTE or orig_exponent is MISSING_ATTRIBUTE:
                return
            rsa_public_key_from_attrs_or_xfail(
                {CKA_MODULUS: orig_modulus, CKA_PUBLIC_EXPONENT: orig_exponent},
                label="generated RSA public key for import",
            )
            try:
                imported = create_object(
                    rs.raw,
                    rs.sh,
                    {
                        CKA_CLASS: CKO_PUBLIC_KEY,
                        CKA_KEY_TYPE: CKK_RSA,
                        CKA_MODULUS: orig_modulus,
                        CKA_PUBLIC_EXPONENT: orig_exponent,
                        CKA_TOKEN: False,
                        CKA_VERIFY: True,
                    },
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    KEYPAIR_RUNTIME_REJECT_RVS,
                    "RSA public key import not operational",
                )
                raise
            try:
                verify_single(rs.raw, rs.sh, imported, CKM_SHA256_RSA_PKCS, data, sig)
            finally:
                destroy_quietly(rs.raw, rs.sh, imported)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_extractable_key_value(self, p11_raw_session: Any) -> None:
        """Extractable key's VALUE attribute matches imported bytes."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            value = attr_or_record(
                attrs,
                CKA_VALUE,
                label="CKA_VALUE:extractable AES key",
                reason="not_operational",
                inherit_mechanism=False,
            )
            if value is not MISSING_ATTRIBUTE:
                assert value == key_bytes
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# --- QC7a (#59.1): table-specific raw value encodings -----------------------
#
# RSA / Weierstrass EC / Edwards / Montgomery public-key tables have no
# standard CKA_VALUE (PKCS#11 v3.2 Tables 37/64/66/68): the correct read
# is CKR_ATTRIBUTE_TYPE_INVALID (or the unavailable sentinel), never SPKI
# bytes under that ID. DSA/DH/PQC public CKA_VALUE and readable private
# EC-family CKA_VALUE hold the table-defined RAW value, not a DER
# container. CKA_EC_POINT raw-or-DER acceptance (_ec_export) is not a
# precedent for CKA_VALUE and is not re-litigated here. Records carry
# lengths only, never key bytes.

_QC7_KIND_PRIORITY = {"metadata": 1, "lifecycle": 2, "policy": 2, "crypto": 3}
_QC7_SEVERITY_PRIORITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Fixed RFC 3526-style DH private exponent for the known-material leg.
_QC7_DH_PRIVATE_X = bytes.fromhex(
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
)

# FIPS raw public-key lengths, re-pinned here (never derived from the readback):
# ML-DSA-44 ek 1312 (FIPS 204), ML-KEM-512 ek 800 (FIPS 203),
# SLH-DSA-SHA2-128S pk 32 = 2n with n=16 (FIPS 205).
_QC7_PQC_PUBLIC: dict[str, tuple[str, int, int, int, str]] = {
    "ml_dsa_44": (
        "ML_DSA_KEY_PAIR_GEN",
        int(CKM_ML_DSA_KEY_PAIR_GEN),
        int(CKP_ML_DSA_44),
        1312,
        "FIPS 204 ML-DSA-44 public key",
    ),
    "ml_kem_512": (
        "ML_KEM_KEY_PAIR_GEN",
        int(CKM_ML_KEM_KEY_PAIR_GEN),
        int(CKP_ML_KEM_512),
        800,
        "FIPS 203 ML-KEM-512 encapsulation key",
    ),
    "slh_dsa_sha2_128s": (
        "SLH_DSA_KEY_PAIR_GEN",
        int(CKM_SLH_DSA_KEY_PAIR_GEN),
        int(CKP_SLH_DSA_SHA2_128S),
        32,
        "FIPS 205 SLH-DSA-SHA2-128S public key",
    ),
}


def _qc7_raise_strongest(records: list[C.Classification]) -> None:
    if not records:
        return
    strongest = max(
        records,
        key=lambda record: (
            1 if record.outcome == "fail" else 0,
            _QC7_SEVERITY_PRIORITY.get(record.severity, 0),
            _QC7_KIND_PRIORITY.get(record.kind or "", 0),
        ),
    )
    C.raise_for_record(strongest)


def _qc7_detail(attr: int, *, producer_operation: str, **extra: Any) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "attribute": {"name": ATTR_NAMES.get(int(attr), f"0x{int(attr):08x}"), "id": int(attr)},
        "producer_operation": producer_operation,
    }
    detail.update(extra)
    return detail


def _qc7_read_single(
    rs: Any, handle: int, attr: int, *, label: str, producer_operation: str
) -> tuple[str, Any, list[C.Classification]]:
    """Single-attribute read with inverse-oracle-safe polarity.

    Returns ``(status, value, records)`` where status is ``present``,
    ``absent`` (TYPE_INVALID or unavailable sentinel), ``sensitive``,
    ``missing`` (nothing observed), or ``error`` (already recorded).
    A correct TYPE_INVALID produces no record -- ``attr_or_record``
    would record it as a deviation, which is the wrong polarity here.
    """
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
            detail=_qc7_detail(attr, producer_operation=producer_operation),
            summary=f"{label}: attribute read returned {ckr_name(exc.rv)}",
        )
        return "error", None, [record]
    if attr in attrs:
        return "present", attrs[attr], []
    clean_rv = refusal_rv_for(attrs, attr)
    if clean_rv is not None:
        if int(clean_rv) == int(CKR_ATTRIBUTE_TYPE_INVALID):
            return "absent", None, []
        if int(clean_rv) == int(CKR_ATTRIBUTE_SENSITIVE):
            return "sensitive", None, []
        record = C.record_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            actual=clean_rv,
            detail=_qc7_detail(attr, producer_operation=producer_operation),
            summary=f"{label}: attribute refused with {ckr_name(clean_rv)}",
        )
        return "error", None, [record]
    # No clean refusal from a real read_attributes result can only be a
    # refusal-with-data or the CKR_OK-plus-sentinel shape (a plain
    # omission always carries one of those two channels). refusal_rv_for
    # deliberately hides leaked_len, so compose with attr_or_record and
    # sniff its just-emitted records (the documented composition; the
    # optional_if_absent escape hatch is scoped to KCV and not used): a
    # leaked refusal records self_contradiction, the sentinel shape an
    # honest deviation kept as evidence while judged absent here.
    before = len(C.get_records())
    attr_or_record(
        attrs,
        attr,
        label=label,
        reason="honest_deviation",
        kind="metadata",
        inherit_mechanism=False,
    )
    added = C.get_records()[before:]
    if any(record.reason == "self_contradiction" for record in added):
        for record in added:
            if record.detail is None:
                record.detail = {}
            record.detail.setdefault("producer_operation", producer_operation)
        return "error", None, added
    if added:
        return "absent", None, []
    return "missing", None, []


def _qc7_record_missing(
    attr: int, *, label: str, producer_operation: str, status: str
) -> C.Classification:
    return C.record_as(
        "honest_deviation",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        inherit_mechanism=False,
        actual=int(CKR_ATTRIBUTE_TYPE_INVALID) if status == "absent" else None,
        detail=_qc7_detail(attr, producer_operation=producer_operation),
        summary=f"{label}: required attribute unavailable ({status})",
    )


def _qc7_record_wrong_value(
    attr: int, *, label: str, producer_operation: str, summary: str, **extra: Any
) -> C.Classification:
    return C.record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        inherit_mechanism=False,
        detail=_qc7_detail(attr, producer_operation=producer_operation, **extra),
        summary=summary,
    )


def _qc7_is_der_public_key(blob: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        load_der_public_key(blob)
    except Exception:
        return False
    return True


def _qc7_check_public_value_absent(rs: Any, pub: int, *, label: str) -> list[C.Classification]:
    status, value, records = _qc7_read_single(
        rs, pub, CKA_VALUE, label=label, producer_operation="C_GenerateKeyPair"
    )
    if status == "present":
        value_len = len(value) if isinstance(value, (bytes, bytearray)) else None
        records.append(
            _qc7_record_wrong_value(
                CKA_VALUE,
                label=label,
                producer_operation="C_GenerateKeyPair",
                summary=(
                    f"{label}: public key exposes CKA_VALUE ({value_len} bytes) although "
                    "its key table has no standard CKA_VALUE"
                ),
                value_len=value_len,
                is_der_spki=(
                    _qc7_is_der_public_key(bytes(value)) if isinstance(value, bytes) else False
                ),
            )
        )
    elif status in ("sensitive", "missing"):
        records.append(
            C.record_as(
                "honest_deviation",
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                actual=int(CKR_ATTRIBUTE_SENSITIVE) if status == "sensitive" else None,
                detail=_qc7_detail(CKA_VALUE, producer_operation="C_GenerateKeyPair"),
                summary=f"{label}: absent CKA_VALUE reported as {status}, not TYPE_INVALID",
            )
        )
    return records


def _gen_montgomery_pair_or_xfail(rs: Any) -> tuple[int, int]:
    """Generate a Montgomery pair copying the test_sensitivity staging pattern."""
    if not rs.has_mechanism("EC_MONTGOMERY_KEY_PAIR_GEN"):
        pytest.skip("EC_MONTGOMERY_KEY_PAIR_GEN not supported by module")
    curve_rejects: list[BaseException] = []
    for curve_oid in (
        encode_named_curve_parameters("x25519"),
        encode_named_curve_parameters("x448"),
    ):
        try:
            return gen_keypair(
                rs.raw,
                rs.sh,
                int(CKM_EC_MONTGOMERY_KEY_PAIR_GEN),
                pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
                priv_base=[],
                public_attrs={CKA_TOKEN: False, CKA_DERIVE: True},
                private_attrs={CKA_TOKEN: False, CKA_DERIVE: True},
                pub_skip={CKA_EC_PARAMS},
            )
        except CkrAssertionError as exc:
            if is_known_error(exc, EC_CURVE_UNSUPPORTED_RVS):
                curve_rejects.append(exc)
                continue
            xfail_if_known_ckr(
                exc, KEYPAIR_RUNTIME_REJECT_RVS, "Montgomery keypair setup is not operational"
            )
            raise
    detail = "; ".join(str(exc) for exc in curve_rejects)
    pytest.skip(f"Montgomery keypair setup: neither X25519 nor X448 supported ({detail})")


def _gen_pqc_pair_or_xfail(
    rs: Any, *, mech_name: str, mechanism: int, param_set: int, purpose: str
) -> tuple[int, int]:
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"{mech_name} not supported by module")
    try:
        return gen_keypair(
            rs.raw,
            rs.sh,
            mechanism,
            pub_base=[attr_ulong(CKA_PARAMETER_SET, param_set)],
            priv_base=[],
            public_attrs={CKA_TOKEN: False},
            private_attrs={CKA_TOKEN: False},
            pub_skip={CKA_PARAMETER_SET},
        )
    except AssertionError as exc:
        xfail_if_known_ckr(exc, KEYPAIR_RUNTIME_REJECT_RVS, f"{purpose} is not operational")
        raise


def _import_or_xfail(attempt: Any, *, purpose: str) -> int:
    try:
        return int(attempt())
    except AssertionError as exc:
        xfail_if_known_ckr(exc, KEYPAIR_RUNTIME_REJECT_RVS, f"{purpose} is not operational")
        raise


def _qc7_prove_unsealed(
    rs: Any, handle: int, *, label: str, producer_operation: str
) -> tuple[bool, list[C.Classification]]:
    """Prove stored SENSITIVE=False and EXTRACTABLE=True; both always read."""
    records: list[C.Classification] = []
    proven = True
    for attr, expected in ((CKA_SENSITIVE, False), (CKA_EXTRACTABLE, True)):
        status, value, read_records = _qc7_read_single(
            rs, handle, attr, label=f"{label}:claim", producer_operation=producer_operation
        )
        records.extend(read_records)
        if status != "present":
            if not read_records:
                records.append(
                    _qc7_record_missing(
                        attr,
                        label=f"{label}:claim",
                        producer_operation=producer_operation,
                        status=status,
                    )
                )
            proven = False
            continue
        if not isinstance(value, bool):
            records.append(
                _qc7_record_wrong_value(
                    attr,
                    label=f"{label}:claim",
                    producer_operation=producer_operation,
                    summary=f"{label}: claim attribute is not a bool: {type(value).__name__}",
                )
            )
            proven = False
        elif value is not expected:
            records.append(
                C.record_as(
                    "honest_deviation",
                    kind="metadata",
                    label=f"{label}:claim",
                    operation="C_GetAttributeValue",
                    inherit_mechanism=False,
                    detail=_qc7_detail(attr, producer_operation=producer_operation),
                    summary=(
                        f"{label}: requested unsealed claim was overridden by the provider; "
                        "the value leg is not judged"
                    ),
                )
            )
            proven = False
    return proven, records


def _import_unsealed_private_or_xfail(rs: Any, family: str) -> tuple[int, bytes, bytes | None]:
    """Import independent known private material unsealed. Returns (handle, raw, der)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519

    skip_unless_create_object_supported(rs)
    if family == "ml_dsa_44":
        from pkcs11_check.testcases.test_sensitivity import _MATRIX_MLDSA44_SK

        handle = _import_or_xfail(
            lambda: create_object_negotiated(
                rs,
                {
                    CKA_CLASS: CKO_PRIVATE_KEY,
                    CKA_KEY_TYPE: CKK_ML_DSA,
                    CKA_TOKEN: False,
                    CKA_PARAMETER_SET: int(CKP_ML_DSA_44),
                    CKA_VALUE: _MATRIX_MLDSA44_SK,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_SIGN: True,
                },
                purpose="QC7a ML-DSA-44 private import",
                preserve_policy_attrs=True,
            ),
            purpose="QC7a ML-DSA-44 private import",
        )
        return handle, _MATRIX_MLDSA44_SK, None

    der_format = serialization.PrivateFormat.PKCS8
    key: Any
    if family == "ec":
        key = ec.generate_private_key(ec.SECP256R1())
        raw = key.private_numbers().private_value.to_bytes(32, "big")
        ec_params = encode_named_curve_parameters("secp256r1")
        key_type = int(CKK_EC)
    elif family == "edwards":
        key = ed25519.Ed25519PrivateKey.generate()
        raw = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        ec_params = encode_named_curve_parameters("ed25519")
        key_type = int(CKK_EC_EDWARDS)
    elif family == "montgomery":
        key = x25519.X25519PrivateKey.generate()
        raw = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        ec_params = encode_named_curve_parameters("x25519")
        key_type = int(CKK_EC_MONTGOMERY)
    else:
        raise ValueError(f"unknown QC7a private family: {family}")
    der = key.private_bytes(serialization.Encoding.DER, der_format, serialization.NoEncryption())
    handle = _import_or_xfail(
        lambda: import_ec_private_key_negotiated(
            rs,
            ec_params=ec_params,
            value=raw,
            key_type=key_type,
            attrs={CKA_SENSITIVE: False, CKA_EXTRACTABLE: True},
            purpose=f"QC7a {family} private import",
            preserve_policy_attrs=True,
        ),
        purpose=f"QC7a {family} private import",
    )
    return handle, raw, der


class TestAttributeValueEncodings:
    """QC7a: raw CKA_VALUE encodings and the absent-VALUE inverse oracle."""

    @pytest.mark.parametrize("family", ["rsa", "ec", "edwards", "montgomery"])
    def test_public_value_absent(self, p11_raw_session: Any, family: str) -> None:
        """Public tables without CKA_VALUE must refuse it, never serve SPKI."""
        rs = p11_raw_session
        if family == "rsa":
            pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        elif family == "ec":
            pub, priv = gen_ec_keypair_or_xfail(rs, encode_named_curve_parameters("secp256r1"))
        elif family == "edwards":
            pub, priv = gen_edwards_keypair_or_xfail(rs, encode_named_curve_parameters("ed25519"))
        else:
            pub, priv = _gen_montgomery_pair_or_xfail(rs)
        try:
            records = _qc7_check_public_value_absent(
                rs, pub, label=f"CKA_VALUE absent on {family} public key"
            )
            _qc7_raise_strongest(records)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_dsa_public_value_is_raw_y(self, p11_raw_session: Any) -> None:
        """Imported fixed DSA public VALUE is the raw y bytes, not SPKI.

        Pinned rule: byte-exact against the supplied fixed Y (full prime
        width), matching the settled QC6 import-coherence oracle, plus an
        explicit SPKI-inequality discriminator.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import dsa

        from pkcs11_check.testcases.test_dsa_complete import (
            _FIXED_DSA_G,
            _FIXED_DSA_P,
            _FIXED_DSA_Q,
            _FIXED_DSA_Y,
            _import_fixed_dsa_keypair,
        )

        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
        try:
            pub, priv = _import_fixed_dsa_keypair(rs)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc, KEYPAIR_RUNTIME_REJECT_RVS, "fixed DSA import is not operational"
            )
            raise
        try:
            status, value, records = _qc7_read_single(
                rs,
                pub,
                CKA_VALUE,
                label="CKA_VALUE:DSA-public",
                producer_operation="C_CreateObject",
            )
            if status == "present":
                spki = (
                    dsa.DSAPublicNumbers(
                        y=int.from_bytes(_FIXED_DSA_Y, "big"),
                        parameter_numbers=dsa.DSAParameterNumbers(
                            p=int.from_bytes(_FIXED_DSA_P, "big"),
                            q=int.from_bytes(_FIXED_DSA_Q, "big"),
                            g=int.from_bytes(_FIXED_DSA_G, "big"),
                        ),
                    )
                    .public_key()
                    .public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )
                if not isinstance(value, bytes) or value != _FIXED_DSA_Y or value == spki:
                    records.append(
                        _qc7_record_wrong_value(
                            CKA_VALUE,
                            label="CKA_VALUE:DSA-public",
                            producer_operation="C_CreateObject",
                            summary="DSA public CKA_VALUE is not the raw fixed y bytes",
                            expected_len=len(_FIXED_DSA_Y),
                            actual_len=len(value) if isinstance(value, bytes) else None,
                            equals_spki=isinstance(value, bytes) and value == spki,
                        )
                    )
            elif status in ("absent", "sensitive", "missing") and not records:
                records.append(
                    _qc7_record_missing(
                        CKA_VALUE,
                        label="CKA_VALUE:DSA-public",
                        producer_operation="C_CreateObject",
                        status=status,
                    )
                )
            _qc7_raise_strongest(records)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_dh_public_value_is_raw_y(self, p11_raw_session: Any) -> None:
        """Imported known DH public VALUE is raw y for y = g^x mod p.

        Pinned rule: integer equality (leading-zero padding does not
        change the integer) plus SPKI inequality -- a DER container of
        the same integer is not the raw value.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import dh

        from pkcs11_check.testcases.test_dh_key_agreement import DH_GEN, DH_PRIME_2048

        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
        p_int = int.from_bytes(DH_PRIME_2048, "big")
        g_int = int.from_bytes(DH_GEN, "big")
        x_int = int.from_bytes(_QC7_DH_PRIVATE_X, "big")
        y_int = pow(g_int, x_int, p_int)
        y_bytes = y_int.to_bytes(len(DH_PRIME_2048), "big")
        pub = _import_or_xfail(
            lambda: create_object_negotiated(
                rs,
                {
                    CKA_CLASS: CKO_PUBLIC_KEY,
                    CKA_KEY_TYPE: CKK_DH,
                    CKA_TOKEN: False,
                    CKA_PRIME: DH_PRIME_2048,
                    CKA_BASE: DH_GEN,
                    CKA_VALUE: y_bytes,
                    CKA_DERIVE: True,
                },
                purpose="QC7a DH public import",
            ),
            purpose="QC7a DH public import",
        )
        try:
            priv = _import_or_xfail(
                lambda: create_object_negotiated(
                    rs,
                    {
                        CKA_CLASS: CKO_PRIVATE_KEY,
                        CKA_KEY_TYPE: CKK_DH,
                        CKA_TOKEN: False,
                        CKA_PRIME: DH_PRIME_2048,
                        CKA_BASE: DH_GEN,
                        CKA_VALUE: _QC7_DH_PRIVATE_X,
                        CKA_DERIVE: True,
                    },
                    purpose="QC7a DH private import",
                ),
                purpose="QC7a DH private import",
            )
        except BaseException:
            destroy_quietly(rs.raw, rs.sh, pub)
            raise
        try:
            status, value, records = _qc7_read_single(
                rs,
                pub,
                CKA_VALUE,
                label="CKA_VALUE:DH-public",
                producer_operation="C_CreateObject",
            )
            if status == "present":
                spki = (
                    dh.DHPublicNumbers(y_int, dh.DHParameterNumbers(p_int, g_int))
                    .public_key()
                    .public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )
                ok = (
                    isinstance(value, bytes)
                    and int.from_bytes(value, "big") == y_int
                    and value != spki
                )
                if not ok:
                    records.append(
                        _qc7_record_wrong_value(
                            CKA_VALUE,
                            label="CKA_VALUE:DH-public",
                            producer_operation="C_CreateObject",
                            summary="DH public CKA_VALUE is not the raw y integer bytes",
                            expected_len=len(y_bytes),
                            actual_len=len(value) if isinstance(value, bytes) else None,
                            equals_spki=isinstance(value, bytes) and value == spki,
                        )
                    )
            elif status in ("absent", "sensitive", "missing") and not records:
                records.append(
                    _qc7_record_missing(
                        CKA_VALUE,
                        label="CKA_VALUE:DH-public",
                        producer_operation="C_CreateObject",
                        status=status,
                    )
                )
            _qc7_raise_strongest(records)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize("family", ["ml_dsa_44", "ml_kem_512", "slh_dsa_sha2_128s"])
    def test_pqc_public_value_raw_lengths(self, p11_raw_session: Any, family: str) -> None:
        """PQC public CKA_VALUE is the FIPS raw public key (exact length).

        No independent public byte-equality is available in-tree; exact
        FIPS length is the bounded oracle (an SPKI of the same key is
        strictly longer, so length excludes the DER container).
        """
        rs = p11_raw_session
        mech_name, mechanism, param_set, expected_len, fips_label = _QC7_PQC_PUBLIC[family]
        pub, priv = _gen_pqc_pair_or_xfail(
            rs,
            mech_name=mech_name,
            mechanism=mechanism,
            param_set=param_set,
            purpose=f"QC7a {family} keypair setup",
        )
        try:
            label = f"CKA_VALUE:{family}-public"
            status, value, records = _qc7_read_single(
                rs, pub, CKA_VALUE, label=label, producer_operation="C_GenerateKeyPair"
            )
            if status == "present":
                if not isinstance(value, bytes) or len(value) != expected_len:
                    records.append(
                        _qc7_record_wrong_value(
                            CKA_VALUE,
                            label=label,
                            producer_operation="C_GenerateKeyPair",
                            summary=(f"{label}: CKA_VALUE is not the {fips_label} raw length"),
                            expected_len=expected_len,
                            actual_len=len(value) if isinstance(value, bytes) else None,
                        )
                    )
            elif status in ("absent", "sensitive", "missing") and not records:
                records.append(
                    _qc7_record_missing(
                        CKA_VALUE,
                        label=label,
                        producer_operation="C_GenerateKeyPair",
                        status=status,
                    )
                )
            _qc7_raise_strongest(records)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize("family", ["ec", "edwards", "montgomery", "ml_dsa_44"])
    def test_private_ec_family_value_raw_known_material(
        self, p11_raw_session: Any, family: str
    ) -> None:
        """Unsealed imported private VALUE reads back the known raw bytes.

        The unsealed claim is proved by readback first; only then is the
        value leg judged. A PKCS#8/SEC1 container, or a sensitive refusal
        after a proven-unsealed claim, fails. Lengths only in records.
        """
        rs = p11_raw_session
        handle, expected, der = _import_unsealed_private_or_xfail(rs, family)
        try:
            label = f"CKA_VALUE:{family}-private"
            proven, records = _qc7_prove_unsealed(
                rs, handle, label=label, producer_operation="C_CreateObject"
            )
            if not proven:
                _qc7_raise_strongest(records)
                return
            status, value, read_records = _qc7_read_single(
                rs, handle, CKA_VALUE, label=label, producer_operation="C_CreateObject"
            )
            records.extend(read_records)
            if status == "sensitive":
                records.append(
                    C.record_as(
                        "self_contradiction",
                        kind="policy",
                        label=label,
                        operation="C_GetAttributeValue",
                        inherit_mechanism=False,
                        actual=int(CKR_ATTRIBUTE_SENSITIVE),
                        detail=_qc7_detail(CKA_VALUE, producer_operation="C_CreateObject"),
                        summary=(f"{label}: proven-unsealed private value refused as sensitive"),
                    )
                )
            elif status == "present":
                if not isinstance(value, bytes) or value != expected:
                    records.append(
                        _qc7_record_wrong_value(
                            CKA_VALUE,
                            label=label,
                            producer_operation="C_CreateObject",
                            summary=f"{label}: private CKA_VALUE is not the known raw bytes",
                            expected_len=len(expected),
                            actual_len=len(value) if isinstance(value, bytes) else None,
                            equals_pkcs8_der=(
                                der is not None and isinstance(value, bytes) and value == der
                            ),
                        )
                    )
            elif status in ("absent", "missing") and not read_records:
                records.append(
                    _qc7_record_missing(
                        CKA_VALUE,
                        label=label,
                        producer_operation="C_CreateObject",
                        status=status,
                    )
                )
            _qc7_raise_strongest(records)
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)

    def test_private_value_generated_imported_equivalent(self, p11_raw_session: Any) -> None:
        """Same P-256 material reads identically generated and imported.

        GENERATED leg must first be a 32-byte raw scalar (a SEC1/PKCS#8
        container fails here before any re-import is attempted).
        """
        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(
            rs,
            curve_oid,
            private_attrs={CKA_SENSITIVE: False, CKA_EXTRACTABLE: True},
        )
        imported: int | None = None
        try:
            label = "CKA_VALUE:generated-imported P-256 private"
            proven, records = _qc7_prove_unsealed(
                rs, priv, label=label, producer_operation="C_GenerateKeyPair"
            )
            if not proven:
                _qc7_raise_strongest(records)
                return
            status, generated, read_records = _qc7_read_single(
                rs, priv, CKA_VALUE, label=label, producer_operation="C_GenerateKeyPair"
            )
            records.extend(read_records)
            if status == "sensitive":
                records.append(
                    C.record_as(
                        "self_contradiction",
                        kind="policy",
                        label=label,
                        operation="C_GetAttributeValue",
                        inherit_mechanism=False,
                        actual=int(CKR_ATTRIBUTE_SENSITIVE),
                        detail=_qc7_detail(CKA_VALUE, producer_operation="C_GenerateKeyPair"),
                        summary=f"{label}: proven-unsealed value refused as sensitive",
                    )
                )
                _qc7_raise_strongest(records)
                return
            if status != "present" or not isinstance(generated, bytes):
                if not read_records:
                    records.append(
                        _qc7_record_missing(
                            CKA_VALUE,
                            label=label,
                            producer_operation="C_GenerateKeyPair",
                            status=status,
                        )
                    )
                _qc7_raise_strongest(records)
                return
            if len(generated) != 32:
                records.append(
                    _qc7_record_wrong_value(
                        CKA_VALUE,
                        label=label,
                        producer_operation="C_GenerateKeyPair",
                        summary=f"{label}: generated value is not a 32-byte raw scalar",
                        expected_len=32,
                        actual_len=len(generated),
                    )
                )
                _qc7_raise_strongest(records)
                return
            imported = _import_or_xfail(
                lambda: import_ec_private_key_negotiated(
                    rs,
                    ec_params=curve_oid,
                    value=generated,
                    key_type=int(CKK_EC),
                    attrs={CKA_SENSITIVE: False, CKA_EXTRACTABLE: True},
                    purpose="QC7a generated-scalar re-import",
                    preserve_policy_attrs=True,
                ),
                purpose="QC7a generated-scalar re-import",
            )
            proven2, claim_records = _qc7_prove_unsealed(
                rs, imported, label=label, producer_operation="C_CreateObject"
            )
            records.extend(claim_records)
            if proven2:
                status2, imported_value, read2 = _qc7_read_single(
                    rs,
                    imported,
                    CKA_VALUE,
                    label=label,
                    producer_operation="C_CreateObject",
                )
                records.extend(read2)
                if status2 == "sensitive":
                    records.append(
                        C.record_as(
                            "self_contradiction",
                            kind="policy",
                            label=label,
                            operation="C_GetAttributeValue",
                            inherit_mechanism=False,
                            actual=int(CKR_ATTRIBUTE_SENSITIVE),
                            detail=_qc7_detail(CKA_VALUE, producer_operation="C_CreateObject"),
                            summary=f"{label}: imported unsealed value refused as sensitive",
                        )
                    )
                elif status2 == "present":
                    if imported_value != generated:
                        records.append(
                            _qc7_record_wrong_value(
                                CKA_VALUE,
                                label=label,
                                producer_operation="C_CreateObject",
                                summary=(f"{label}: generated and imported readbacks differ"),
                                expected_len=len(generated),
                                actual_len=(
                                    len(imported_value)
                                    if isinstance(imported_value, bytes)
                                    else None
                                ),
                            )
                        )
                elif not read2:
                    records.append(
                        _qc7_record_missing(
                            CKA_VALUE,
                            label=label,
                            producer_operation="C_CreateObject",
                            status=status2,
                        )
                    )
            _qc7_raise_strongest(records)
        finally:
            if imported is not None:
                destroy_quietly(rs.raw, rs.sh, imported)
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
