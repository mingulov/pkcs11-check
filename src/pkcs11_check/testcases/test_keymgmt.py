"""Tests for PKCS#11 key management: import, export, wrap, unwrap, derive, copy.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any, NoReturn

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.classification import xfail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_ecdh
from pkcs11_check.raw.recipes import (
    copy_object,
    decrypt_single,
    derive_key,
    destroy_quietly,
    encrypt_single,
    import_secret_key,
    read_attributes,
    wrap_key,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_COPYABLE,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKD_NULL,
    CKF_EC_COMPRESS,
    CKF_EC_UNCOMPRESS,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP,
    CKM_ECDH1_DERIVE,
    CKO_PRIVATE_KEY,
    CKO_SECRET_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases._copy_mutability import (
    COPY_FORBIDDEN_REFUSE_RVS,
    PROBE_INJECTED_VALUE,
    PROBE_ORIGINAL_VALUE,
    PROBE_PLAINTEXT,
    check_ecb_baseline_or_fail,
    check_material_preserved,
    classify_forbidden_change_refusal,
    classify_ignored_or_mutated,
    classify_rv_validity_or_none,
    read_qc3_attributes,
    row_by_key,
    validate_qc3_shape,
    xfail_qc3_setup_refusal,
)
from pkcs11_check.testcases._ec_export import (
    ConventionalECPoint,
    read_conventional_ec_point_or_xfail,
    read_ec_public_key_or_xfail,
    select_ecdh_point_form,
)
from pkcs11_check.testcases.conftest import (
    gen_aes_key_or_xfail,
    gen_ec_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
    import_secret_key_negotiated,
    skip_unless_create_object_supported,
    skip_unless_mechanism,
    unwrap_key_for_mechanism_roundtrip,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.keymgmt

_KEYMGMT_OPERATION_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _select_ecdh_point_for_target(rs: Any, point: ConventionalECPoint) -> bytes:
    """Select the peer representation supported by the target ECDH mechanism."""
    return select_ecdh_point_form(
        point,
        supports_compressed=rs.has_mechanism_flag(CKM_ECDH1_DERIVE, int(CKF_EC_COMPRESS)),
        supports_uncompressed=rs.has_mechanism_flag(CKM_ECDH1_DERIVE, int(CKF_EC_UNCOMPRESS)),
    )


def _aes_keymgmt_key(rs: Any, *, attrs: dict[Any, Any] | None = None) -> int:
    return gen_aes_key_or_xfail(rs, 128, attrs=attrs, purpose="key-management setup")


def _encrypt_or_xfail(rs: Any, key: int, data: bytes) -> bytes:
    skip_unless_mechanism(rs, "AES_ECB")
    try:
        return encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _KEYMGMT_OPERATION_REJECT_RVS, "AES_ECB encrypt rejected")
    raise


def _decrypt_or_xfail(rs: Any, key: int, data: bytes) -> bytes:
    skip_unless_mechanism(rs, "AES_ECB")
    try:
        return decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _KEYMGMT_OPERATION_REJECT_RVS, "AES_ECB decrypt rejected")
    raise


def _record_wrong_attribute(
    *,
    label: str,
    expected: Any,
    actual: str,
    kind: str = "metadata",
    operation: str = "C_GetAttributeValue",
    mechanism: str | None = None,
) -> C.Classification:
    # Bare-readback shape by default (import/copy observations with no producer
    # mechanism); callers checking a mechanism-produced value pass the producer
    # operation + mechanism explicitly. Ambient mechanisms never attach either
    # way: explicit wins, and inherit stays False for the bare shape.
    return C.record_as(
        "wrong_result",
        kind=kind,
        label=label,
        operation=operation,
        mechanism=mechanism,
        inherit_mechanism=False,
        summary=f"{label}: provider returned {actual}; expected {expected!r}",
        detail={
            "attribute": {
                "expected": repr(expected),
                "actual": actual,
            }
        },
    )


def _wrong_attribute(
    *,
    label: str,
    expected: Any,
    actual: str,
    kind: str = "metadata",
    operation: str = "C_GetAttributeValue",
    mechanism: str | None = None,
) -> NoReturn:
    record = _record_wrong_attribute(
        label=label,
        expected=expected,
        actual=actual,
        kind=kind,
        operation=operation,
        mechanism=mechanism,
    )
    C.raise_for_record(record)


class TestKeyImport:
    @pytest.fixture(autouse=True)
    def _skip_if_no_create_object(self, p11_raw_session: Any) -> None:
        skip_unless_create_object_supported(p11_raw_session)

    def test_import_aes_key(self, p11_raw_session: Any) -> None:
        """Import raw AES key material and verify attributes."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
            },
        )
        try:
            assert key != 0
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_KEY_TYPE])
            key_type = attr_or_record(
                attrs,
                CKA_KEY_TYPE,
                inherit_mechanism=False,
                label="CKA_KEY_TYPE:imported-AES",
                reason="not_operational",
                kind="metadata",
            )
            if key_type is MISSING_ATTRIBUTE:
                return
            if key_type != CKK_AES:
                _wrong_attribute(
                    label="CKA_KEY_TYPE:imported-AES",
                    expected=CKK_AES,
                    actual=f"{key_type!r}",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_import_aes_key_roundtrip(self, p11_raw_session: Any) -> None:
        """Import AES key, encrypt, decrypt, verify roundtrip."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        key_bytes = bytes(range(32))
        key = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
        )
        try:
            plaintext = b"import_rndtrip!!"  # exactly 16 bytes
            ct = _encrypt_or_xfail(rs, key, plaintext)
            pt = _decrypt_or_xfail(rs, key, ct)
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_extractable_key_export(self, p11_raw_session: Any) -> None:
        """Export extractable key and verify material matches."""
        rs = p11_raw_session
        key_bytes = bytes(range(16))
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            exported = attr_or_record(
                attrs,
                CKA_VALUE,
                inherit_mechanism=False,
                label="CKA_VALUE:extractable-AES",
                reason="not_operational",
                kind="metadata",
            )
            if exported is MISSING_ATTRIBUTE:
                return
            if exported != key_bytes:
                _wrong_attribute(
                    label="CKA_VALUE:extractable-AES",
                    expected=key_bytes,
                    actual=f"{exported!r}",
                    kind="crypto",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_import_multiple_sizes(self, p11_raw_session: Any) -> None:
        """Import AES keys at 128, 192, 256 bit sizes."""
        rs = p11_raw_session
        first_mismatch: C.Classification | None = None
        for size_bytes in [16, 24, 32]:
            key_bytes = bytes(size_bytes)
            key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_AES,
                key_bytes,
                attrs={
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                },
            )
            try:
                attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
                exported = attr_or_record(
                    attrs,
                    CKA_VALUE,
                    inherit_mechanism=False,
                    label=f"CKA_VALUE:imported-AES-{size_bytes * 8}",
                    reason="not_operational",
                    kind="metadata",
                )
                if exported is MISSING_ATTRIBUTE:
                    continue
                if exported != key_bytes:
                    mismatch = _record_wrong_attribute(
                        label=f"CKA_VALUE:imported-AES-{size_bytes * 8}",
                        expected=key_bytes,
                        actual=f"{exported!r}",
                        kind="crypto",
                    )
                    if first_mismatch is None:
                        first_mismatch = mismatch
            finally:
                destroy_quietly(rs.raw, rs.sh, key)
        if first_mismatch is not None:
            C.raise_for_record(first_mismatch)


class TestKeyExport:
    def test_rsa_modulus_export(self, p11_raw_session: Any) -> None:
        """Export RSA modulus and exponent."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA key generation not supported")
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_MODULUS, CKA_PUBLIC_EXPONENT])
            modulus = attr_or_record(
                attrs,
                CKA_MODULUS,
                inherit_mechanism=False,
                label="CKA_MODULUS:RSA-public",
                reason="not_operational",
                kind="metadata",
            )
            exponent = attr_or_record(
                attrs,
                CKA_PUBLIC_EXPONENT,
                inherit_mechanism=False,
                label="CKA_PUBLIC_EXPONENT:RSA-public",
                reason="not_operational",
                kind="metadata",
            )
            if modulus is not MISSING_ATTRIBUTE and (
                modulus.__class__ is not bytes or modulus.__len__() != 256
            ):
                first_mismatch = _record_wrong_attribute(
                    label="CKA_MODULUS:RSA-public",
                    expected="256-byte bytes",
                    actual=f"{modulus!r}",
                    kind="crypto",
                    operation="C_GenerateKeyPair",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                )
            else:
                first_mismatch = None
            if exponent is not MISSING_ATTRIBUTE and (
                exponent.__class__ is not bytes or not exponent
            ):
                mismatch = _record_wrong_attribute(
                    label="CKA_PUBLIC_EXPONENT:RSA-public",
                    expected="non-empty bytes",
                    actual=f"{exponent!r}",
                    kind="crypto",
                    operation="C_GenerateKeyPair",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                )
                if first_mismatch is None:
                    first_mismatch = mismatch
            if first_mismatch is not None:
                C.raise_for_record(first_mismatch)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ec_point_export(self, p11_raw_session: Any) -> None:
        """Export EC public key point."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(rs, curve_oid)
        try:
            read_ec_public_key_or_xfail(
                rs,
                pub,
                ec.SECP256R1(),
                label="CKA_EC_POINT:P-256-public",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestKeyCopy:
    def test_copy_preserves_attributes(self, p11_raw_session: Any) -> None:
        """Copy a key and verify attributes are preserved."""
        rs = p11_raw_session
        original = _aes_keymgmt_key(rs, attrs={CKA_LABEL: b"original"})
        copy = 0
        try:
            copy = copy_object(
                rs.raw,
                rs.sh,
                original,
                {CKA_LABEL: b"copy"},
            )
            attrs = read_attributes(rs.raw, rs.sh, copy, [CKA_LABEL, CKA_KEY_TYPE])
            label_value = attr_or_record(
                attrs,
                CKA_LABEL,
                inherit_mechanism=False,
                label="CKA_LABEL:copied-AES",
                reason="not_operational",
                kind="metadata",
            )
            key_type = attr_or_record(
                attrs,
                CKA_KEY_TYPE,
                inherit_mechanism=False,
                label="CKA_KEY_TYPE:copied-AES",
                reason="not_operational",
                kind="metadata",
            )
            first_mismatch: C.Classification | None = None
            if label_value is not MISSING_ATTRIBUTE and label_value not in (b"copy", "copy"):
                first_mismatch = _record_wrong_attribute(
                    label="CKA_LABEL:copied-AES",
                    expected=(b"copy", "copy"),
                    actual=f"{label_value!r}",
                )
            if key_type is not MISSING_ATTRIBUTE and key_type != CKK_AES:
                mismatch = _record_wrong_attribute(
                    label="CKA_KEY_TYPE:copied-AES",
                    expected=CKK_AES,
                    actual=f"{key_type!r}",
                )
                if first_mismatch is None:
                    first_mismatch = mismatch
            if first_mismatch is not None:
                C.raise_for_record(first_mismatch)
        finally:
            destroy_quietly(rs.raw, rs.sh, original)
            if copy:
                destroy_quietly(rs.raw, rs.sh, copy)

    def test_copy_independent(self, p11_raw_session: Any) -> None:
        """Copied key works independently after original is destroyed."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        original = _aes_keymgmt_key(rs, attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True})
        copy = copy_object(
            rs.raw,
            rs.sh,
            original,
            {CKA_LABEL: b"independent"},
        )
        try:
            destroy_quietly(rs.raw, rs.sh, original)
            ct = _encrypt_or_xfail(rs, copy, b"still works here")
            assert len(ct) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, copy)


class TestKeyWrapUnwrap:
    def test_wrap_unwrap_roundtrip(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Wrap and unwrap a key, verify material is preserved."""
        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported")
        key_bytes = bytes(range(16))
        wrapping_key = _aes_keymgmt_key(rs, attrs={CKA_WRAP: True, CKA_UNWRAP: True})
        target = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_TOKEN: False,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            },
        )
        unwrapped = 0
        try:
            wrapped = wrap_key(rs.raw, rs.sh, wrapping_key, target, CKM_AES_KEY_WRAP)
            assert len(wrapped) > 0

            unwrapped = unwrap_key_for_mechanism_roundtrip(
                rs,
                p11_config,
                unwrapping_key=wrapping_key,
                wrapped_key=wrapped,
                mechanism=CKM_AES_KEY_WRAP,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                },
                purpose="AES-KEY-WRAP keymgmt roundtrip",
            )
            attrs = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])
            exported = attr_or_record(
                attrs,
                CKA_VALUE,
                inherit_mechanism=False,
                label="CKA_VALUE:unwrapped-AES",
                reason="not_operational",
                kind="metadata",
            )
            if exported is MISSING_ATTRIBUTE:
                return
            if exported != key_bytes:
                _wrong_attribute(
                    label="CKA_VALUE:unwrapped-AES",
                    expected=key_bytes,
                    actual=f"{exported!r}",
                    kind="crypto",
                    operation="C_UnwrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
            destroy_quietly(rs.raw, rs.sh, target)
            if unwrapped:
                destroy_quietly(rs.raw, rs.sh, unwrapped)


class TestKeyDerive:
    def test_ecdh_derive_produces_key(self, p11_raw_session: Any) -> None:
        """ECDH key derivation produces a usable shared secret."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        _pub_a = priv_a = pub_b = _priv_b = 0
        derived = 0
        try:
            _pub_a, priv_a = gen_ec_keypair_or_xfail(
                rs, curve_oid, private_attrs={CKA_DERIVE: True}
            )
            pub_b, _priv_b = gen_ec_keypair_or_xfail(rs, curve_oid)
            peer_point = read_conventional_ec_point_or_xfail(
                rs,
                pub_b,
                ec.SECP256R1(),
                label="CKA_EC_POINT:ECDH-peer-P-256",
            )
            point_b = _select_ecdh_point_for_target(rs, peer_point)
            ecdh_param = mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=point_b)

            derived = derive_key(
                rs.raw,
                rs.sh,
                priv_a,
                CKM_ECDH1_DERIVE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_TOKEN: False,
                },
                mech_param=ecdh_param,
            )
            assert derived != 0
        finally:
            if _pub_a:
                destroy_quietly(rs.raw, rs.sh, _pub_a)
            if priv_a:
                destroy_quietly(rs.raw, rs.sh, priv_a)
            if pub_b:
                destroy_quietly(rs.raw, rs.sh, pub_b)
            if _priv_b:
                destroy_quietly(rs.raw, rs.sh, _priv_b)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)


_COPY_SOURCE_SETUP_REJECT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_QC3A_IDENTITY_CITATION = (
    "PKCS#11 v3.2 C_CopyObject: object class and key type are not copy-mutable; "
    "an accepted override must have no object effect (#55.2)"
)


def _import_copy_mutability_source(rs: Any) -> int:
    """Import the known-value AES source for the QC3a copy legs.

    The source sets CKA_COPYABLE so the copy premise is explicit; a
    module that cannot provide a copyable source fails setup visibly.
    """
    try:
        return import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            PROBE_ORIGINAL_VALUE,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
                CKA_COPYABLE: True,
                CKA_TOKEN: False,
            },
        )
    except CkrAssertionError as exc:
        # F8: validity first (undefined -> metadata FAIL; vendor -> alternate).
        classify_rv_validity_or_none(
            exc.rv,
            label="copy-mutability source setup",
            operation="C_CreateObject",
            kind="policy",
        )
        # G2: every clean standard setup refusal xfails with the RV preserved
        # (no bare raise); the tuple only selects the summary wording.
        xfail_qc3_setup_refusal(
            exc,
            _COPY_SOURCE_SETUP_REJECT_RVS,
            label="copy-mutability source setup",
        )


def _encrypt_baseline_or_xfail(rs: Any, key: int, *, label: str) -> bytes:
    """Encrypt the probe plaintext as the material-behavior baseline."""
    try:
        baseline = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, PROBE_PLAINTEXT)
    except CkrAssertionError as exc:
        # F8: validity first (undefined -> metadata FAIL; vendor -> alternate).
        classify_rv_validity_or_none(
            exc.rv,
            label=f"{label}: baseline use",
            operation="C_Encrypt",
            mechanism="CKM_AES_ECB",
            kind="policy",
        )
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: baseline use",
            operation="C_Encrypt",
            mechanism="CKM_AES_ECB",
            inherit_mechanism=False,
            actual=exc.rv,
            summary=(
                f"{label}: baseline use refused with {ckr_name(exc.rv)}; material comparison void"
            ),
        )
    # G4/G5: a comparison against an unvalidated baseline is void evidence.
    check_ecb_baseline_or_fail(baseline, label=f"{label}: baseline use")
    return baseline


def _check_copy_identity_override(
    rs: Any,
    copy: int,
    baseline_ct: bytes,
    *,
    override_attr: int,
    original_identity: int,
    override_identity: int,
    label: str,
) -> None:
    """Two-tier verdict for an accepted class/type copy override.

    The class/type readback IS the property: an applied-change FAIL requires
    the readback to SHOW the override value. Use-refusal (or diverged use)
    with an unchanged or unreadable identity leaves the effect unproved; a
    refusal never proves the override was applied.
    """
    attrs = read_qc3_attributes(
        rs,
        copy,
        [CKA_CLASS, CKA_KEY_TYPE],
        label=label,
        premise=False,
        spec_ref=_QC3A_IDENTITY_CITATION,
    )
    identity = attr_or_record(
        attrs,
        override_attr,
        label=f"{label}: copy identity readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    if identity is not MISSING_ATTRIBUTE:
        attr_name = "CKA_KEY_TYPE" if override_attr == int(CKA_KEY_TYPE) else "CKA_CLASS"
        identity = validate_qc3_shape(
            identity,
            "ulong",
            attr_name=attr_name,
            label=label,
            premise=False,
            spec_ref=_QC3A_IDENTITY_CITATION,
        )
    try:
        observed_ct: bytes | None = encrypt_single(
            rs.raw, rs.sh, copy, CKM_AES_ECB, PROBE_PLAINTEXT
        )
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv,
            label=label,
            operation="C_Encrypt",
            mechanism="CKM_AES_ECB",
            kind="policy",
        )
        use_rv: str | None = ckr_name(exc.rv)
        observed_ct = None
    else:
        use_rv = None
    use_matches = observed_ct == baseline_ct if observed_ct is not None else None
    missing = identity is MISSING_ATTRIBUTE
    shows_override = identity is not MISSING_ATTRIBUTE and identity == override_identity
    unchanged = identity is not MISSING_ATTRIBUTE and identity == original_identity
    evidence: dict[str, Any] = {
        "identity_changed": None if missing else not unchanged,
        "identity_shows_override": None if missing else shows_override,
        "observed_identity": None if missing else identity,
        "requested_override": override_identity,
        "original_identity": original_identity,
        "use_matches_baseline": use_matches,
        "use_rv": use_rv,
    }
    if missing:
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation="C_CopyObject",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=_QC3A_IDENTITY_CITATION,
            summary=(
                f"{label}: accepted but the copy identity is unreadable; override effect unproved"
            ),
            detail={"disposition": "unproved-effect", **evidence},
        )
    if shows_override:
        classify_ignored_or_mutated(
            mutated=True,
            label=label,
            operation="C_CopyObject",
            spec_ref=_QC3A_IDENTITY_CITATION,
            ignored_summary="",
            mutated_summary=(
                f"{label}: forbidden object effect from an applied override "
                f"(identity shows the override value, use_matches_baseline={use_matches}, "
                f"use_rv={use_rv})"
            ),
            detail={"disposition": "forbidden-mutation", **evidence},
        )
    if unchanged and use_matches is True:
        classify_ignored_or_mutated(
            mutated=False,
            label=label,
            operation="C_CopyObject",
            spec_ref=_QC3A_IDENTITY_CITATION,
            ignored_summary=(
                f"{label}: accepted but ignored the override (identity unchanged, use intact)"
            ),
            mutated_summary="",
            detail={"disposition": "ignored-input", **evidence},
        )
    # Unchanged identity with refused/diverged use, or an identity matching
    # neither the original nor the override: the override effect is unproved.
    xfail_as(
        "honest_deviation",
        kind="policy",
        label=label,
        operation="C_CopyObject",
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=_QC3A_IDENTITY_CITATION,
        summary=(
            f"{label}: accepted but the override effect is unproved "
            f"(identity_changed={evidence['identity_changed']}, "
            f"use_matches_baseline={use_matches}, use_rv={use_rv})"
        ),
        detail={"disposition": "unproved-effect", **evidence},
    )


class TestCopyForbiddenMutation:
    """QC3a: copies must not mutate material or object identity (#55.1/.2)."""

    def test_copy_different_value_material_ignored_or_refused(self, p11_raw_session: Any) -> None:
        """Copy with a different CKA_VALUE must refuse or preserve material."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        row = row_by_key("value")
        label = "C_CopyObject CKA_VALUE different-value (QC3a material)"
        original = _import_copy_mutability_source(rs)
        try:
            baseline_ct = _encrypt_baseline_or_xfail(rs, original, label=label)
            try:
                copy = copy_object(rs.raw, rs.sh, original, {CKA_VALUE: PROBE_INJECTED_VALUE})
            except CkrAssertionError as exc:
                classify_forbidden_change_refusal(
                    exc,
                    COPY_FORBIDDEN_REFUSE_RVS,
                    label=label,
                    operation="C_CopyObject",
                )
                return
            try:
                check_material_preserved(
                    rs,
                    copy,
                    baseline_ct,
                    original_value=PROBE_ORIGINAL_VALUE,
                    injected_value=PROBE_INJECTED_VALUE,
                    plaintext=PROBE_PLAINTEXT,
                    label=label,
                    spec_ref=row.citation,
                    operation="C_CopyObject",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, copy)
        finally:
            destroy_quietly(rs.raw, rs.sh, original)

    def test_copy_key_type_override_ignored_or_refused(self, p11_raw_session: Any) -> None:
        """Copy with a CKA_KEY_TYPE override must refuse or have no effect."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        label = "C_CopyObject CKA_KEY_TYPE override (QC3a identity)"
        original = _import_copy_mutability_source(rs)
        try:
            baseline_ct = _encrypt_baseline_or_xfail(rs, original, label=label)
            try:
                copy = copy_object(rs.raw, rs.sh, original, {CKA_KEY_TYPE: CKK_GENERIC_SECRET})
            except CkrAssertionError as exc:
                classify_forbidden_change_refusal(
                    exc,
                    COPY_FORBIDDEN_REFUSE_RVS,
                    label=label,
                    operation="C_CopyObject",
                )
                return
            try:
                _check_copy_identity_override(
                    rs,
                    copy,
                    baseline_ct,
                    override_attr=int(CKA_KEY_TYPE),
                    original_identity=int(CKK_AES),
                    override_identity=int(CKK_GENERIC_SECRET),
                    label=label,
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, copy)
        finally:
            destroy_quietly(rs.raw, rs.sh, original)

    def test_copy_class_override_ignored_or_refused(self, p11_raw_session: Any) -> None:
        """Copy with a CKA_CLASS override must refuse or have no effect."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        label = "C_CopyObject CKA_CLASS override (QC3a identity)"
        original = _import_copy_mutability_source(rs)
        try:
            baseline_ct = _encrypt_baseline_or_xfail(rs, original, label=label)
            try:
                copy = copy_object(rs.raw, rs.sh, original, {CKA_CLASS: CKO_PRIVATE_KEY})
            except CkrAssertionError as exc:
                classify_forbidden_change_refusal(
                    exc,
                    COPY_FORBIDDEN_REFUSE_RVS,
                    label=label,
                    operation="C_CopyObject",
                )
                return
            try:
                _check_copy_identity_override(
                    rs,
                    copy,
                    baseline_ct,
                    override_attr=int(CKA_CLASS),
                    original_identity=int(CKO_SECRET_KEY),
                    override_identity=int(CKO_PRIVATE_KEY),
                    label=label,
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, copy)
        finally:
            destroy_quietly(rs.raw, rs.sh, original)

    def test_copy_unchanged_value_template_observation(self, p11_raw_session: Any) -> None:
        """Compatibility observation: copy with an unchanged CKA_VALUE template."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        original = _import_copy_mutability_source(rs)
        try:
            try:
                baseline_ct = encrypt_single(rs.raw, rs.sh, original, CKM_AES_ECB, PROBE_PLAINTEXT)
            except CkrAssertionError as exc:
                classify_rv_validity_or_none(
                    exc.rv,
                    label="unchanged-value copy",
                    operation="C_Encrypt",
                    mechanism="CKM_AES_ECB",
                )
                note(
                    "unchanged-value copy: baseline use refused with "
                    f"{ckr_name(exc.rv)}; copy not attempted",
                    ComplianceLevel.STANDARD,
                    reference="QC3a #55.1 compatibility observation",
                )
                return
            try:
                copy = copy_object(rs.raw, rs.sh, original, {CKA_VALUE: PROBE_ORIGINAL_VALUE})
            except CkrAssertionError as exc:
                classify_rv_validity_or_none(
                    exc.rv, label="unchanged-value copy", operation="C_CopyObject"
                )
                note(
                    "unchanged-value copy refused with "
                    f"{ckr_name(exc.rv)} (no material to compare)",
                    ComplianceLevel.STANDARD,
                    reference="QC3a #55.1 compatibility observation",
                )
                return
            try:
                try:
                    observed_ct = encrypt_single(rs.raw, rs.sh, copy, CKM_AES_ECB, PROBE_PLAINTEXT)
                except CkrAssertionError as exc:
                    classify_rv_validity_or_none(
                        exc.rv,
                        label="copy use observation",
                        operation="C_Encrypt",
                        mechanism="CKM_AES_ECB",
                    )
                    behavior = f"copy use refused with {ckr_name(exc.rv)}"
                else:
                    behavior = f"copy behaves as original: {observed_ct == baseline_ct}"
                note(
                    f"unchanged-value copy accepted (CKR_OK); {behavior}",
                    ComplianceLevel.STANDARD,
                    reference="QC3a #55.1 compatibility observation",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, copy)
        finally:
            destroy_quietly(rs.raw, rs.sh, original)

    def test_copy_empty_template_observation(self, p11_raw_session: Any) -> None:
        """Compatibility observation: copy with an empty template."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        original = _import_copy_mutability_source(rs)
        try:
            try:
                baseline_ct = encrypt_single(rs.raw, rs.sh, original, CKM_AES_ECB, PROBE_PLAINTEXT)
            except CkrAssertionError as exc:
                classify_rv_validity_or_none(
                    exc.rv,
                    label="empty-template copy",
                    operation="C_Encrypt",
                    mechanism="CKM_AES_ECB",
                )
                note(
                    "empty-template copy: baseline use refused with "
                    f"{ckr_name(exc.rv)}; copy not attempted",
                    ComplianceLevel.STANDARD,
                    reference="QC3a #55.2 compatibility observation",
                )
                return
            try:
                copy = copy_object(rs.raw, rs.sh, original, {})
            except CkrAssertionError as exc:
                classify_rv_validity_or_none(
                    exc.rv, label="empty-template copy", operation="C_CopyObject"
                )
                note(
                    f"empty-template copy refused with {ckr_name(exc.rv)} (no material to compare)",
                    ComplianceLevel.STANDARD,
                    reference="QC3a #55.2 compatibility observation",
                )
                return
            try:
                try:
                    observed_ct = encrypt_single(rs.raw, rs.sh, copy, CKM_AES_ECB, PROBE_PLAINTEXT)
                except CkrAssertionError as exc:
                    classify_rv_validity_or_none(
                        exc.rv,
                        label="copy use observation",
                        operation="C_Encrypt",
                        mechanism="CKM_AES_ECB",
                    )
                    behavior = f"copy use refused with {ckr_name(exc.rv)}"
                else:
                    behavior = f"copy behaves as original: {observed_ct == baseline_ct}"
                note(
                    f"empty-template copy accepted (CKR_OK); {behavior}",
                    ComplianceLevel.STANDARD,
                    reference="QC3a #55.2 compatibility observation",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, copy)
        finally:
            destroy_quietly(rs.raw, rs.sh, original)
