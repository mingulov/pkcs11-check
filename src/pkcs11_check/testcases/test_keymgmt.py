"""Tests for PKCS#11 key management: import, export, wrap, unwrap, derive, copy.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, NoReturn

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_ecdh, template_from_dict
from pkcs11_check.raw.recipes import (
    RSAUsage,
    copy_object,
    decrypt_single,
    derive_key,
    destroy_quietly,
    encrypt_single,
    find_objects_exhaustive,
    import_secret_key,
    read_attributes,
    sign_single,
    wrap_key,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_COEFFICIENT,
    CKA_COPYABLE,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_PRIVATE_EXPONENT,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
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
    CKM_SHA256_RSA_PKCS,
    CKO_PRIVATE_KEY,
    CKO_SECRET_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_SENSITIVE,
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
from pkcs11_check.testcases._attribute_values import (
    MISSING_ATTRIBUTE,
    attr_or_record,
    refusal_rv_for,
)
from pkcs11_check.testcases._copy_mutability import (
    COPY_FORBIDDEN_REFUSE_RVS,
    PROBE_INJECTED_VALUE,
    PROBE_ORIGINAL_VALUE,
    PROBE_PLAINTEXT,
    GuessUseOutcome,
    check_ecb_baseline_or_fail,
    check_material_preserved,
    classify_forbidden_change_refusal,
    classify_ignored_or_mutated,
    classify_rv_validity_or_none,
    guess_use_detail,
    judge_guess_confirm,
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
    import_rsa_private_key_negotiated,
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


def _import_copy_mutability_source(rs: Any, *, sealed: bool = False) -> int:
    """Import the known-value AES source for the QC3a copy legs.

    The source sets CKA_COPYABLE so the copy premise is explicit; a
    module that cannot provide a copyable source fails setup visibly.
    ``sealed`` requests CKA_SENSITIVE/!CKA_EXTRACTABLE for the
    guess-confirm legs, which need a genuinely unreadable fixture.
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
                CKA_EXTRACTABLE: not sealed,
                CKA_SENSITIVE: sealed,
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
    attr_name = "CKA_KEY_TYPE" if override_attr == int(CKA_KEY_TYPE) else "CKA_CLASS"
    if identity is not MISSING_ATTRIBUTE:
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
                f"{label}: accepted but ignored the override ({attr_name} unchanged, use intact)"
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


_RSA_GUESS_MESSAGE = b"pkcs11-check guess-confirm probe"


def _inventory_object_set(rs: Any, *, label: str) -> tuple[set[int] | None, int | None]:
    """Exhaustive all-object inventory; (None, rv) when the module refuses it.

    Unfiltered: a refused copy creating a token object must not hide
    behind a session-only filter. A refused inventory classifies
    validity-first (undefined fails, vendor xfails) and otherwise
    yields None: creation is unproved, never assumed absent. The
    refusal RV rides along for the judge's unproved record.
    """
    try:
        handles = find_objects_exhaustive(rs.raw, rs.sh, template_from_dict({}))
        return {int(handle) for handle in handles}, None
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv,
            label=f"{label}: creation inventory",
            operation="C_FindObjects",
            kind="policy",
        )
        return None, exc.rv


def _copy_preserves_aes_material(rs: Any, target: int, baseline_ct: bytes) -> GuessUseOutcome:
    """Material-use evidence for an accepted AES guess leg (B3).

    A refused use rides as preserved=None with its RV: the comparison
    is void, never a mutation claim.
    """
    try:
        observed = encrypt_single(rs.raw, rs.sh, target, CKM_AES_ECB, PROBE_PLAINTEXT)
        preserved = observed == baseline_ct
    except CkrAssertionError as exc:
        return GuessUseOutcome(
            preserved=None, use_rv=exc.rv, operation="C_Encrypt", mechanism="CKM_AES_ECB"
        )
    return GuessUseOutcome(
        preserved=preserved, use_rv=None, operation="C_Encrypt", mechanism="CKM_AES_ECB"
    )


def _copy_preserves_rsa_material(rs: Any, target: int, baseline_sig: bytes) -> GuessUseOutcome:
    """Material-use evidence for an accepted RSA guess leg (B3).

    RSA v1.5 signs deterministically, so a signature comparison is a
    material-equality proof for the private exponent. A refused use
    rides as preserved=None with its RV.
    """
    try:
        preserved = (
            sign_single(rs.raw, rs.sh, target, CKM_SHA256_RSA_PKCS, _RSA_GUESS_MESSAGE)
            == baseline_sig
        )
    except CkrAssertionError as exc:
        return GuessUseOutcome(
            preserved=None,
            use_rv=exc.rv,
            operation="C_Sign",
            mechanism="CKM_SHA256_RSA_PKCS",
        )
    return GuessUseOutcome(
        preserved=preserved,
        use_rv=None,
        operation="C_Sign",
        mechanism="CKM_SHA256_RSA_PKCS",
    )


def _read_rsa_components_or_xfail(rs: Any, key: int, *, label: str) -> dict[str, bytes]:
    """Read the CRT components of a generated unsealed RSA key for re-import."""
    wanted = {
        "n": CKA_MODULUS,
        "e": CKA_PUBLIC_EXPONENT,
        "d": CKA_PRIVATE_EXPONENT,
        "p": CKA_PRIME_1,
        "q": CKA_PRIME_2,
        "dmp1": CKA_EXPONENT_1,
        "dmq1": CKA_EXPONENT_2,
        "iqmp": CKA_COEFFICIENT,
    }
    try:
        read = read_attributes(rs.raw, rs.sh, key, list(wanted.values()))
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv,
            label=f"{label}: component readback",
            operation="C_GetAttributeValue",
            kind="policy",
        )
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: component readback",
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            actual=exc.rv,
            summary=(
                f"{label}: module will not disclose generated RSA components; "
                "cannot build a known-answer sealed fixture"
            ),
        )
    components: dict[str, bytes] = {}
    for name, attr in wanted.items():
        value = attr_or_record(
            read,
            attr,
            label=f"{label}: component {name} readback",
            reason="not_operational",
            kind="policy",
            inherit_mechanism=False,
        )
        if value is MISSING_ATTRIBUTE or not isinstance(value, bytes) or not value:
            xfail_as(
                "not_operational",
                kind="policy",
                label=f"{label}: component readback",
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                summary=(
                    f"{label}: {name} readback is not usable key "
                    "material; cannot build a known-answer sealed fixture"
                ),
            )
        components[name] = value
    return components


def _import_sealed_rsa_or_xfail(rs: Any, components: Mapping[str, bytes], *, label: str) -> int:
    """Import a sealed RSA private key from known CRT components."""
    try:
        return import_rsa_private_key_negotiated(
            rs,
            n=components["n"],
            e=components["e"],
            d=components["d"],
            p=components["p"],
            q=components["q"],
            dmp1=components["dmp1"],
            dmq1=components["dmq1"],
            iqmp=components["iqmp"],
            attrs={
                CKA_SIGN: True,
                CKA_EXTRACTABLE: False,
                CKA_SENSITIVE: True,
                CKA_COPYABLE: True,
                CKA_TOKEN: False,
            },
            purpose="sealed RSA guess-confirm source",
            preserve_policy_attrs=True,
        )
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv,
            label=f"{label}: sealed import",
            operation="C_CreateObject",
            kind="policy",
        )
        xfail_qc3_setup_refusal(
            exc,
            _COPY_SOURCE_SETUP_REJECT_RVS,
            label=f"{label}: sealed import",
        )


def _sealed_value_unreadable_or_skip(rs: Any, key: int, *, label: str) -> None:
    """Prove the sealed AES fixture is genuinely sealed; skip when it is not.

    A guess-confirm leg against a readable value is vacuous (and would
    conflate #55.1 with the #55.2 value-mutation rule), so a readable
    value skips with a pointer at the sensitivity tests that own it.
    """
    try:
        read = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv,
            label=f"{label}: seal premise",
            operation="C_GetAttributeValue",
            kind="policy",
        )
        if exc.rv != int(CKR_ATTRIBUTE_SENSITIVE):
            xfail_as(
                "not_operational",
                kind="policy",
                label=f"{label}: seal premise",
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                actual=exc.rv,
                summary=(
                    f"{label}: seal premise unreadable for a non-sealing reason "
                    f"({ckr_name(exc.rv)}); guess-confirm vacuous"
                ),
            )
        return
    sealed = attr_or_record(
        read,
        CKA_VALUE,
        label=f"{label}: seal premise",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
        sensitive_is_conformant=True,
    )
    if sealed is MISSING_ATTRIBUTE:
        # B3: only an OBSERVED CKR_ATTRIBUTE_SENSITIVE refusal proves the
        # seal; any other absence (unsupported type, plain gap, silent
        # sentinel) leaves it unproved, never assumed sealed.
        refusal_rv = refusal_rv_for(read, CKA_VALUE)
        if refusal_rv is not None and int(refusal_rv) == int(CKR_ATTRIBUTE_SENSITIVE):
            return
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: seal premise",
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=(
                f"{label}: seal premise absent without an observed "
                "CKR_ATTRIBUTE_SENSITIVE refusal; seal unproved, guess-confirm vacuous"
            ),
        )
    if not isinstance(sealed, bytes):
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: seal premise",
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=(
                f"{label}: seal premise readback is unusable; seal unproved, guess-confirm vacuous"
            ),
        )
    pytest.skip(
        f"{label}: module discloses the sealed value; "
        "guess-confirm is vacuous (see sensitivity tests)"
    )


def _sealed_exponent_unreadable_or_skip(rs: Any, key: int, *, label: str) -> None:
    """Prove the sealed fixture is genuinely sealed; skip when it is not.

    A guess-confirm leg against a readable exponent is vacuous (and would
    conflate #55.1 with the #55.2 value-mutation rule), so a readable
    exponent skips with a pointer at the sensitivity tests that own it.
    """
    try:
        read = read_attributes(rs.raw, rs.sh, key, [CKA_PRIVATE_EXPONENT])
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv,
            label=f"{label}: seal premise",
            operation="C_GetAttributeValue",
            kind="policy",
        )
        if exc.rv != int(CKR_ATTRIBUTE_SENSITIVE):
            xfail_as(
                "not_operational",
                kind="policy",
                label=f"{label}: seal premise",
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                actual=exc.rv,
                summary=(
                    f"{label}: seal premise unreadable for a non-sealing reason "
                    f"({ckr_name(exc.rv)}); guess-confirm vacuous"
                ),
            )
        return
    sealed = attr_or_record(
        read,
        CKA_PRIVATE_EXPONENT,
        label=f"{label}: seal premise",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
        sensitive_is_conformant=True,
    )
    if sealed is MISSING_ATTRIBUTE:
        # B3: only an OBSERVED CKR_ATTRIBUTE_SENSITIVE refusal proves the
        # seal; any other absence leaves it unproved, never assumed sealed.
        refusal_rv = refusal_rv_for(read, CKA_PRIVATE_EXPONENT)
        if refusal_rv is not None and int(refusal_rv) == int(CKR_ATTRIBUTE_SENSITIVE):
            return
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: seal premise",
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=(
                f"{label}: seal premise absent without an observed "
                "CKR_ATTRIBUTE_SENSITIVE refusal; seal unproved, guess-confirm vacuous"
            ),
        )
    if not isinstance(sealed, bytes):
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: seal premise",
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=(
                f"{label}: seal premise readback is unusable; seal unproved, guess-confirm vacuous"
            ),
        )
    pytest.skip(
        f"{label}: module discloses the sealed private exponent; "
        "guess-confirm is vacuous (see sensitivity tests)"
    )


def _run_guess_legs(
    rs: Any,
    original: int,
    attr: int,
    guesses: tuple[bytes, bytes],
    baseline: bytes,
    preserves: Callable[[Any, int, bytes], GuessUseOutcome],
    *,
    label: str,
) -> tuple[
    CkrAssertionError | None,
    CkrAssertionError | None,
    GuessUseOutcome | None,
    GuessUseOutcome | None,
    tuple[bool | None, bool | None],
    tuple[int | None, int | None],
]:
    """Run the correct/wrong guess legs for #55.1.

    Returns ``(correct_exc, wrong_exc, correct_use, wrong_use, created,
    inventory_rvs)`` where an ``exc`` of None means the leg accepted
    (with ``use`` carrying the material-use evidence, None for refused
    legs); ``created`` carries per-leg creation evidence (True proved
    creation, False proved none, None a refused inventory) and
    ``inventory_rvs`` the inventory refusal RV per leg (None when the
    inventory succeeded).
    """
    excs: list[CkrAssertionError | None] = []
    uses: list[GuessUseOutcome | None] = []
    created: list[bool | None] = []
    inventory_rvs: list[int | None] = []
    for guess in guesses:
        before, before_rv = _inventory_object_set(rs, label=label)
        try:
            copy = copy_object(rs.raw, rs.sh, original, {attr: guess})
        except CkrAssertionError as exc:
            excs.append(exc)
            uses.append(None)
            if before is None:
                created.append(None)
                inventory_rvs.append(before_rv)
                continue
            after, after_rv = _inventory_object_set(rs, label=label)
            if after is None:
                created.append(None)
                inventory_rvs.append(after_rv)
            else:
                created.append(bool(set(after) - set(before)))
                inventory_rvs.append(None)
            continue
        excs.append(None)
        if not copy or copy == original:
            # A1: an accepted copy aliasing the source is a proved
            # contradiction; fail WITHOUT destroying, or cleanup would
            # delete the sealed source mid-test.
            fail_as(
                "self_contradiction",
                kind="policy",
                label=label,
                operation="C_CopyObject",
                inherit_mechanism=False,
                actual=int(CKR_OK),
                summary=(
                    f"{label}: accepted guess copy returned the source handle "
                    f"({copy}); refusing to destroy it"
                ),
                detail={"source": original, "copy": copy},
            )
        try:
            uses.append(preserves(rs, copy, baseline))
        finally:
            destroy_quietly(rs.raw, rs.sh, copy)
        created.append(False)
        inventory_rvs.append(None)
    correct_exc, wrong_exc = excs
    correct_use, wrong_use = uses
    created_pair = (created[0], created[1])
    inventory_pair = (inventory_rvs[0], inventory_rvs[1])
    return correct_exc, wrong_exc, correct_use, wrong_use, created_pair, inventory_pair


def _copy_unchanged_control_or_skip(
    rs: Any,
    original: int,
    baseline: bytes,
    *,
    label: str,
    preserves: Callable[[Any, int, bytes], GuessUseOutcome] | None = None,
) -> None:
    """Prove a no-op copy of the sealed source works; skip the legs otherwise.

    A module that refuses every copy would let the guess/override legs
    pass vacuously, so an empty-template duplicate (which must succeed)
    plus a use check gates them.
    """
    try:
        control = copy_object(rs.raw, rs.sh, original, {})
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv,
            label=f"{label}: unchanged control",
            operation="C_CopyObject",
            kind="policy",
        )
        pytest.skip(
            f"{label}: empty-template copy refused ({ckr_name(exc.rv)}); verdict would be vacuous"
        )
    if not control or control == original:
        # R2B1: the ownership guard covers the control too; an aliased
        # control duplicate fails WITHOUT destroying the source.
        fail_as(
            "self_contradiction",
            kind="policy",
            label=label,
            operation="C_CopyObject",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            summary=(
                f"{label}: unchanged control copy returned "
                f"{'a null handle' if not control else 'the source handle'} "
                f"({control}); refusing to destroy it"
            ),
            detail={"source": original, "copy": control},
        )
    try:
        if preserves is not None:
            outcome = preserves(rs, control, baseline)
        else:
            outcome = _copy_preserves_aes_material(rs, control, baseline)
        usable, detail = guess_use_detail(outcome)
        if not usable:
            pytest.skip(
                f"{label}: empty-template duplicate is unusable{detail}; verdict would be vacuous"
            )
    finally:
        destroy_quietly(rs.raw, rs.sh, control)


def _copy_value_control_or_skip(
    rs: Any, original: int, attr: int, value: bytes, *, label: str
) -> None:
    """Prove a value-carrying copy is processed; skip the guess legs otherwise.

    A module that refuses every VALUE override would let identical
    guess refusals pass without ever consulting a guess; the empty
    control cannot catch that. Acceptance (then destroy) proves the
    guess templates reach value handling.
    """
    try:
        control = copy_object(rs.raw, rs.sh, original, {attr: value})
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv,
            label=f"{label}: value control",
            operation="C_CopyObject",
            kind="policy",
        )
        pytest.skip(
            f"{label}: value-carrying copy refused ({ckr_name(exc.rv)}); "
            "guesses never consulted, verdict would be vacuous"
        )
    if not control or control == original:
        fail_as(
            "self_contradiction",
            kind="policy",
            label=label,
            operation="C_CopyObject",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            summary=(
                f"{label}: value control copy returned "
                f"{'a null handle' if not control else 'the source handle'} "
                f"({control}); refusing to destroy it"
            ),
            detail={"source": original, "copy": control},
        )
    destroy_quietly(rs.raw, rs.sh, control)


def _rsa_sign_baseline_or_xfail(
    rs: Any, key: int, *, label: str, public_numbers: tuple[bytes, bytes]
) -> bytes:
    """Sign the probe message twice as the RSA material-behavior baseline.

    The double sign proves the v1.5 determinism premise the copy
    comparisons rely on, and the signature must verify under the
    known public half (deterministic garbage is not a baseline); a
    nondeterministic or unverifying signer voids the leg.
    """
    try:
        first = sign_single(rs.raw, rs.sh, key, CKM_SHA256_RSA_PKCS, _RSA_GUESS_MESSAGE)
        second = sign_single(rs.raw, rs.sh, key, CKM_SHA256_RSA_PKCS, _RSA_GUESS_MESSAGE)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv,
            label=f"{label}: baseline use",
            operation="C_Sign",
            mechanism="CKM_SHA256_RSA_PKCS",
            kind="policy",
        )
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: baseline use",
            operation="C_Sign",
            mechanism="CKM_SHA256_RSA_PKCS",
            inherit_mechanism=False,
            actual=exc.rv,
            summary=f"{label}: sealed RSA source will not sign",
        )
    if first != second:
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: baseline use",
            operation="C_Sign",
            mechanism="CKM_SHA256_RSA_PKCS",
            inherit_mechanism=False,
            summary=f"{label}: v1.5 signer nondeterministic; guess comparison void",
        )
    modulus, exponent = public_numbers
    pub = rsa.RSAPublicNumbers(
        int.from_bytes(exponent, "big"), int.from_bytes(modulus, "big")
    ).public_key()
    try:
        pub.verify(first, _RSA_GUESS_MESSAGE, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: baseline use",
            operation="C_Sign",
            mechanism="CKM_SHA256_RSA_PKCS",
            inherit_mechanism=False,
            summary=f"{label}: baseline signature does not verify; guess comparison void",
        )
    return first


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

    def test_copy_sealed_value_guess_confirm_identical(self, p11_raw_session: Any) -> None:
        """Correct and wrong sealed-value guesses must behave identically (#55.1)."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        label = "C_CopyObject sealed CKA_VALUE guess-confirm (QC3a oracle)"
        row = row_by_key("value")
        original = _import_copy_mutability_source(rs, sealed=True)
        try:
            _sealed_value_unreadable_or_skip(rs, original, label=label)
            baseline_ct = _encrypt_baseline_or_xfail(rs, original, label=label)
            _copy_unchanged_control_or_skip(rs, original, baseline_ct, label=label)
            _copy_value_control_or_skip(
                rs, original, CKA_VALUE, bytes(range(0x40, 0x50)), label=label
            )
            out = _run_guess_legs(
                rs,
                original,
                CKA_VALUE,
                (PROBE_ORIGINAL_VALUE, PROBE_INJECTED_VALUE),
                baseline_ct,
                _copy_preserves_aes_material,
                label=label,
            )
            correct_exc, wrong_exc, correct_use, wrong_use, created, inventory_rvs = out
            judge_guess_confirm(
                correct_exc=correct_exc,
                wrong_exc=wrong_exc,
                correct_use=correct_use,
                wrong_use=wrong_use,
                created_on_refusal=created,
                inventory_rvs=inventory_rvs,
                expected_rvs=COPY_FORBIDDEN_REFUSE_RVS,
                label=label,
                operation="C_CopyObject",
                spec_ref=row.citation,
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, original)

    def test_copy_sealed_rsa_exponent_guess_confirm_identical(self, p11_raw_session: Any) -> None:
        """Correct and wrong sealed-exponent guesses must behave identically (#55.1)."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
        label = "C_CopyObject sealed CKA_PRIVATE_EXPONENT guess-confirm (QC3a oracle)"
        row = row_by_key("private_exponent")
        donor_pub, donor = gen_rsa_keypair_or_xfail(
            rs,
            usage=RSAUsage.SIGN,
            private_attrs={CKA_SENSITIVE: False, CKA_EXTRACTABLE: True},
        )
        try:
            components = _read_rsa_components_or_xfail(rs, donor, label=label)
            sealed = _import_sealed_rsa_or_xfail(rs, components, label=label)
        finally:
            destroy_quietly(rs.raw, rs.sh, donor_pub)
            destroy_quietly(rs.raw, rs.sh, donor)
        try:
            _sealed_exponent_unreadable_or_skip(rs, sealed, label=label)
            baseline_sig = _rsa_sign_baseline_or_xfail(
                rs, sealed, label=label, public_numbers=(components["n"], components["e"])
            )
            _copy_unchanged_control_or_skip(
                rs, sealed, baseline_sig, label=label, preserves=_copy_preserves_rsa_material
            )
            correct = components["d"]
            # XOR flips the low bit, so wrong != correct by construction.
            wrong = bytes([correct[0] ^ 0x01]) + correct[1:]
            _copy_value_control_or_skip(
                rs,
                sealed,
                CKA_PRIVATE_EXPONENT,
                bytes([correct[0] ^ 0x02]) + correct[1:],
                label=label,
            )
            out = _run_guess_legs(
                rs,
                sealed,
                CKA_PRIVATE_EXPONENT,
                (correct, wrong),
                baseline_sig,
                _copy_preserves_rsa_material,
                label=label,
            )
            correct_exc, wrong_exc, correct_use, wrong_use, created, inventory_rvs = out
            judge_guess_confirm(
                correct_exc=correct_exc,
                wrong_exc=wrong_exc,
                correct_use=correct_use,
                wrong_use=wrong_use,
                created_on_refusal=created,
                inventory_rvs=inventory_rvs,
                expected_rvs=COPY_FORBIDDEN_REFUSE_RVS,
                label=label,
                operation="C_CopyObject",
                spec_ref=row.citation,
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, sealed)

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

    def test_copy_sealed_key_type_override_ignored_or_refused(self, p11_raw_session: Any) -> None:
        """Sealed copy with a CKA_KEY_TYPE override must refuse or have no effect (#55.2)."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        label = "C_CopyObject sealed CKA_KEY_TYPE override (QC3a identity)"
        original = _import_copy_mutability_source(rs, sealed=True)
        try:
            _sealed_value_unreadable_or_skip(rs, original, label=label)
            baseline_ct = _encrypt_baseline_or_xfail(rs, original, label=label)
            _copy_unchanged_control_or_skip(rs, original, baseline_ct, label=label)
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

    def test_copy_sealed_class_override_ignored_or_refused(self, p11_raw_session: Any) -> None:
        """Sealed copy with a CKA_CLASS override must refuse or have no effect (#55.2)."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        label = "C_CopyObject sealed CKA_CLASS override (QC3a identity)"
        original = _import_copy_mutability_source(rs, sealed=True)
        try:
            _sealed_value_unreadable_or_skip(rs, original, label=label)
            baseline_ct = _encrypt_baseline_or_xfail(rs, original, label=label)
            _copy_unchanged_control_or_skip(rs, original, baseline_ct, label=label)
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
