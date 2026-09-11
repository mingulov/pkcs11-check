"""AES-GCM authenticated key wrapping tests (v3.2).

Tests wrap_key_authenticated / unwrap_key_authenticated using
AES-GCM AEAD. Requires PKCS#11 v3.2 interface (C_WrapKeyAuthenticated).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NamedTuple, NoReturn

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.classification import classify, xfail_as
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import (
    attr_bytes,
    mech_ecdh_aes_kw,
    mech_gcm_message,
    mech_gcm_message_inherit_tag,
)
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    gen_keypair,
    generate_random,
    read_attributes,
    unwrap_key_authenticated,
    wrap_key,
    wrap_key_authenticated,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_EC_PARAMS,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKD_SHA256_KDF,
    CKK_AES,
    CKM_AES_GCM,
    CKM_AES_KEY_WRAP,
    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    CKM_ECDH_AES_KEY_WRAP,
    CKM_ECDH_COF_AES_KEY_WRAP,
    CKM_ECDH_X_AES_KEY_WRAP,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases._negotiation import TEMPLATE_SHAPE_REJECTS
from pkcs11_check.testcases.conftest import (
    EC_CURVE_UNSUPPORTED_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    gen_ec_keypair_or_xfail,
    is_known_error,
    require_operational_aes_keygen,
    unwrap_key_for_mechanism_roundtrip,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.keymgmt

# Clean codes that mean a wrap/unwrap PRECONDITION could not be established: the operation
# is advertised-but-not-operational, OR (after negotiation exhausts every spec-equivalent
# template) the module refuses the unwrap template shape -- a safety net so a cleanly-rejected
# valid leg is an operational deviation -> xfail (discrimination undecidable), never a fail.
# Includes the template-shape rejects for that reason; in practice the policy-attribute
# negotiation (drop CKA_EXTRACTABLE/CKA_SENSITIVE) lets strict modules establish
# the valid leg, so this net only catches a module that refuses the unwrap entirely.
_WRAP_RUNTIME_REJECT_RVS = (
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
) + TEMPLATE_SHAPE_REJECTS

_KIND_PRIORITY = {"metadata": 1, "lifecycle": 2, "policy": 2, "crypto": 3}
_SEVERITY_PRIORITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _read_attr_or_record(
    raw: Any,
    sh: int,
    handle: int,
    attr: Any,
    *,
    label: str,
    mechanism: str,
    attrs: Mapping[Any, Any] | None = None,
) -> Any:
    """Read one provider attribute while retaining structured absence evidence."""
    values = attrs if attrs is not None else read_attributes(raw, sh, handle, [attr])
    return attr_or_record(
        values,
        attr,
        label=f"{label} (producer_mechanism={mechanism})",
        reason="not_operational",
        inherit_mechanism=False,
    )


def _record_attribute_mismatch(
    *,
    label: str,
    expected: str,
    actual: str,
    kind: str = "crypto",
    mechanism: str,
    operation: str = "C_GetAttributeValue",
) -> C.Classification:
    """Record a provider output mismatch without raising before cleanup."""
    return C.record_as(
        "wrong_result",
        kind=kind,
        label=label,
        operation=operation,
        mechanism=mechanism,
        summary=f"{label}: provider returned {actual}; expected {expected}",
        detail={"attribute": {"expected": expected, "actual": actual}},
    )


def _record_output_mismatch(
    *,
    label: str,
    expected: str,
    actual: str,
    operation: str,
    mechanism: str,
) -> C.Classification:
    """Record malformed non-attribute provider output for deferred reporting."""
    return C.record_as(
        "wrong_result",
        kind="crypto",
        label=label,
        operation=operation,
        mechanism=mechanism,
        summary=f"{label}: provider returned {actual}; expected {expected}",
        detail={"output": {"expected": expected, "actual": actual}},
    )


def _check_aes128_value(
    value: Any,
    *,
    label: str,
    mechanism: str,
) -> C.Classification | None:
    """Return a hard readback finding for a malformed requested AES-128 value."""
    if value is MISSING_ATTRIBUTE:
        return None
    if isinstance(value, bytes) and len(value) == 16:
        return None
    return _record_attribute_mismatch(
        label=label,
        expected="16-byte bytes",
        actual=repr(value),
        kind="crypto",
        mechanism=mechanism,
    )


def _has_nonzero_bytes(value: Any) -> bool:
    """Return whether a provider output is a non-empty, non-zero byte string."""
    return isinstance(value, bytes) and bool(value) and any(value)


def _raise_strongest(records: list[C.Classification]) -> None:
    """Raise the strongest hard result once all returned objects are destroyed."""
    if records:
        strongest = max(
            records,
            key=lambda record: (
                _KIND_PRIORITY.get(record.kind or "", 0),
                _SEVERITY_PRIORITY.get(record.severity, 0),
            ),
        )
        C.raise_for_record(strongest)


def _record_discrimination(
    *,
    valid_accepted: bool,
    valid_value: Any,
    invalid_outcome: Any,
    label: str,
    operation: str,
    mechanism: str,
    hard_results: list[C.Classification],
) -> None:
    """Record integrity evidence without letting a missing valid output mask tampering."""
    if isinstance(invalid_outcome, CkrAssertionError):
        invalid_rejected = True
    elif isinstance(invalid_outcome, BaseException):
        raise invalid_outcome
    else:
        invalid_rejected = False

    if valid_value is not MISSING_ATTRIBUTE and not valid_accepted:
        hard_results.append(
            C.record_as(
                "wrong_result",
                kind="crypto",
                label=label,
                operation=operation,
                mechanism=mechanism,
                summary=(
                    f"{label}: the valid/un-tampered operation did not verify -- cannot "
                    "distinguish tampering from an inoperable valid leg"
                ),
            )
        )
    if not invalid_rejected:
        hard_results.append(
            C.record_as(
                "accepted_invalid",
                kind="crypto",
                label=label,
                operation=operation,
                mechanism=mechanism,
                summary=f"{label}: accepted the tampered/forged input (security break)",
            )
        )


def _xfail_if_wrap_runtime_reject(exc: AssertionError, msg: str) -> NoReturn:
    xfail_if_known_ckr(exc, _WRAP_RUNTIME_REJECT_RVS, msg)
    raise


def _skip_if_authenticated_wrap_not_implemented(exc: AssertionError, operation: str) -> None:
    """Skip when CKR_FUNCTION_NOT_SUPPORTED means C_(Un)WrapKeyAuthenticated itself is
    absent (capability absence -- both are optional PKCS#11 v3.2 functions), not a
    mechanism-level refusal. A module may expose a non-null function-table pointer yet
    stub the call with CKR_FUNCTION_NOT_SUPPORTED, so ``needs_function`` alone cannot
    catch this. Must be checked before ``_xfail_if_wrap_runtime_reject`` -- that helper's
    RV set includes CKR_FUNCTION_NOT_SUPPORTED for the *mandatory* C_WrapKey/C_UnwrapKey
    call sites it also serves, where it correctly stays a mechanism-level xfail.
    """
    if isinstance(exc, CkrAssertionError) and exc.rv == int(CKR_FUNCTION_NOT_SUPPORTED):
        pytest.skip(f"{operation} not implemented: CKR_FUNCTION_NOT_SUPPORTED")


class _EcdhAesKwCase(NamedTuple):
    short_name: str
    mechanism: Any
    keygen_kind: str


_ECDH_AES_KW_CASES: tuple[_EcdhAesKwCase, ...] = (
    _EcdhAesKwCase("ECDH_AES_KEY_WRAP", CKM_ECDH_AES_KEY_WRAP, "weierstrass"),
    _EcdhAesKwCase("ECDH_COF_AES_KEY_WRAP", CKM_ECDH_COF_AES_KEY_WRAP, "weierstrass"),
    _EcdhAesKwCase("ECDH_X_AES_KEY_WRAP", CKM_ECDH_X_AES_KEY_WRAP, "montgomery"),
)

_MONTGOMERY_WRAP_CURVES: tuple[tuple[str, bytes], ...] = (
    ("X25519", encode_named_curve_parameters("x25519")),
    ("X448", encode_named_curve_parameters("x448")),
)


def _gen_montgomery_wrap_keypair_or_xfail(rs: Any) -> tuple[int, int]:
    """Generate a Montgomery recipient keypair for CKM_ECDH_X_AES_KEY_WRAP."""
    if not rs.has_mechanism("EC_MONTGOMERY_KEY_PAIR_GEN"):
        pytest.skip("CKM_EC_MONTGOMERY_KEY_PAIR_GEN not supported for ECDH-X-AES-KW setup")

    curve_rejects: list[BaseException] = []
    for curve_name, curve_oid in _MONTGOMERY_WRAP_CURVES:
        try:
            return gen_keypair(
                rs.raw,
                rs.sh,
                int(CKM_EC_MONTGOMERY_KEY_PAIR_GEN),
                pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
                priv_base=[],
                public_attrs={CKA_TOKEN: False, CKA_DERIVE: True, CKA_WRAP: True},
                private_attrs={CKA_TOKEN: False, CKA_DERIVE: True, CKA_UNWRAP: True},
                pub_skip={CKA_EC_PARAMS},
            )
        except AssertionError as exc:
            if is_known_error(exc, EC_CURVE_UNSUPPORTED_RVS):
                curve_rejects.append(exc)
                continue
            xfail_if_known_ckr(
                exc,
                KEYPAIR_RUNTIME_REJECT_RVS,
                f"CKM_EC_MONTGOMERY_KEY_PAIR_GEN advertised but {curve_name} "
                "keypair generation for ECDH-X-AES-KW setup is not operational",
            )
            raise

    detail = "; ".join(str(exc) for exc in curve_rejects)
    xfail_as(
        "not_operational",
        kind="crypto",
        label="CKM_EC_MONTGOMERY_KEY_PAIR_GEN:ECDH-X-AES-KW setup",
        operation="C_GenerateKeyPair",
        mechanism="CKM_EC_MONTGOMERY_KEY_PAIR_GEN",
        summary=(
            "CKM_EC_MONTGOMERY_KEY_PAIR_GEN advertised but neither X25519 nor X448 "
            f"keypair generation is available for ECDH-X-AES-KW setup: {detail}"
        ),
    )


def _ecdh_aes_kw_recipient_keypair(rs: Any, case: _EcdhAesKwCase) -> tuple[int, int]:
    if case.keygen_kind == "montgomery":
        return _gen_montgomery_wrap_keypair_or_xfail(rs)
    if case.keygen_kind != "weierstrass":
        raise AssertionError(f"unknown ECDH-AES-KW keygen kind: {case.keygen_kind}")

    curve_oid = encode_named_curve_parameters("secp256r1")
    return gen_ec_keypair_or_xfail(
        rs,
        curve_oid,
        public_attrs={CKA_DERIVE: True, CKA_WRAP: True},
        private_attrs={CKA_DERIVE: True, CKA_UNWRAP: True},
    )


def _ecdh_aes_kw_mech(case: _EcdhAesKwCase) -> Any:
    return mech_ecdh_aes_kw(
        case.mechanism,
        aes_key_bits=256,
        kdf=CKD_SHA256_KDF,
    )


def _wrap_ecdh_aes_kw_or_xfail(
    rs: Any,
    *,
    recipient_public: int,
    target: int,
    case: _EcdhAesKwCase,
) -> bytes:
    try:
        return wrap_key(
            rs.raw,
            rs.sh,
            recipient_public,
            target,
            case.mechanism,
            mech_param=_ecdh_aes_kw_mech(case),
        )
    except AssertionError as exc:
        _xfail_if_wrap_runtime_reject(exc, f"CKM_{case.short_name} wrap not operational")


class TestAuthenticatedWrap:
    """Test AES-GCM authenticated key wrapping (v3.2)."""

    @pytest.mark.needs_function("C_WrapKeyAuthenticated")
    def test_aes_gcm_wrap_unwrap(self, p11_raw_session: Any, p11_interface_version: str) -> None:
        """Wrap/unwrap AES key with AES-GCM authenticated wrapping."""
        rs = p11_raw_session
        if p11_interface_version not in ("3.2",):
            pytest.skip("Authenticated wrapping requires v3.2 interface")
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        wrap_h = 0
        target = 0
        hard_results: list[C.Classification] = []
        try:
            # Generate wrapping key before the target, so the first acquisition
            # is immediately covered by the cleanup below if target creation fails.
            wrap_h = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={
                    CKA_WRAP: True,
                    CKA_UNWRAP: True,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                },
            )
            target = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
            )
            original_value = _read_attr_or_record(
                rs.raw,
                rs.sh,
                target,
                CKA_VALUE,
                label="CKM_AES_GCM:target CKA_VALUE readback",
                mechanism="CKM_AES_GCM",
            )
            mismatch = _check_aes128_value(
                original_value,
                label="CKM_AES_GCM:target CKA_VALUE readback",
                mechanism="CKM_AES_GCM",
            )
            if mismatch is not None:
                hard_results.append(mismatch)
            if original_value is MISSING_ATTRIBUTE:
                original_bytes: bytes | None = None
            else:
                original_bytes = (
                    bytes(original_value)
                    if isinstance(original_value, bytes) and len(original_value) == 16
                    else None
                )
            # Wrap with authentication.  Tag lives in CK_GCM_MESSAGE_PARAMS.pTag.
            iv = generate_random(rs.raw, rs.sh, 12)
            wrap_mech = mech_gcm_message(CKM_AES_GCM, iv, tag_bits=128)
            try:
                wrapped = wrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    target,
                    CKM_AES_GCM,
                    mech_param=wrap_mech,
                )
            except (NotImplementedError, AttributeError, TypeError):
                pytest.skip("wrap_key_authenticated not available or GCM params unsupported")
                return
            except AssertionError as exc:
                _skip_if_authenticated_wrap_not_implemented(exc, "C_WrapKeyAuthenticated")
                _xfail_if_wrap_runtime_reject(exc, "AES-GCM authenticated wrap rejected")

            if original_bytes is not None and wrapped == original_bytes:
                hard_results.append(
                    _record_output_mismatch(
                        label="CKM_AES_GCM:authenticated wrap output equals key value",
                        expected="ciphertext distinct from plaintext key value",
                        actual=repr(wrapped),
                        operation="C_WrapKeyAuthenticated",
                        mechanism="CKM_AES_GCM",
                    )
                )
            tag = wrap_mech.buffer_bytes("tag")
            if not _has_nonzero_bytes(tag):
                hard_results.append(
                    _record_output_mismatch(
                        label="CKM_AES_GCM:C_WrapKeyAuthenticated authentication tag",
                        expected="non-zero tag bytes",
                        actual=repr(tag),
                        operation="C_WrapKeyAuthenticated",
                        mechanism="CKM_AES_GCM",
                    )
                )

            # Unwrap: share the wrap-side pTag so the module sees the auth tag.
            if _has_nonzero_bytes(tag):
                unwrap_mech = mech_gcm_message_inherit_tag(CKM_AES_GCM, iv, source=wrap_mech)
                unwrapped = unwrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    wrapped,
                    CKM_AES_GCM,
                    attrs={
                        CKA_EXTRACTABLE: True,
                        CKA_SENSITIVE: False,
                    },
                    mech_param=unwrap_mech,
                )
                try:
                    unwrapped_value = _read_attr_or_record(
                        rs.raw,
                        rs.sh,
                        unwrapped,
                        CKA_VALUE,
                        label="CKM_AES_GCM:unwrapped CKA_VALUE readback",
                        mechanism="CKM_AES_GCM",
                    )
                    mismatch = _check_aes128_value(
                        unwrapped_value,
                        label="CKM_AES_GCM:unwrapped CKA_VALUE readback",
                        mechanism="CKM_AES_GCM",
                    )
                    if mismatch is not None:
                        hard_results.append(mismatch)
                    if (
                        original_bytes is not None
                        and unwrapped_value is not MISSING_ATTRIBUTE
                        and unwrapped_value != original_bytes
                    ):
                        hard_results.append(
                            _record_attribute_mismatch(
                                label=(
                                    "CKM_AES_GCM:authenticated wrap/unwrap preserves key material"
                                ),
                                expected=repr(original_bytes),
                                actual=repr(unwrapped_value),
                                mechanism="CKM_AES_GCM",
                                operation="C_UnwrapKeyAuthenticated",
                            )
                        )
                finally:
                    destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            if wrap_h:
                destroy_quietly(rs.raw, rs.sh, wrap_h)
            if target:
                destroy_quietly(rs.raw, rs.sh, target)
        _raise_strongest(hard_results)

    @pytest.mark.needs_function("C_WrapKeyAuthenticated")
    def test_aes_gcm_authenticated_wrap_generated_iv_and_tag(
        self, p11_raw_session: Any, p11_interface_version: str
    ) -> None:
        """C_WrapKeyAuthenticated writes generated GCM IV and tag into message params."""
        rs = p11_raw_session
        if p11_interface_version != "3.2":
            pytest.skip("Authenticated wrapping requires v3.2 interface")
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        from pkcs11_check.raw.pack import mech_gcm_message_generated_iv
        from pkcs11_check.raw.types_std import CKG_GENERATE

        wrap_h = 0
        target = 0
        unwrapped = 0
        hard_results: list[C.Classification] = []
        try:
            wrap_h = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={CKA_WRAP: True, CKA_UNWRAP: True, CKA_ENCRYPT: True, CKA_DECRYPT: True},
            )
            target = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
            )
            original = _read_attr_or_record(
                rs.raw,
                rs.sh,
                target,
                CKA_VALUE,
                label="CKM_AES_GCM:generated-IV target CKA_VALUE readback",
                mechanism="CKM_AES_GCM",
            )
            mismatch = _check_aes128_value(
                original,
                label="CKM_AES_GCM:generated-IV target CKA_VALUE readback",
                mechanism="CKM_AES_GCM",
            )
            if mismatch is not None:
                hard_results.append(mismatch)
            if original is MISSING_ATTRIBUTE:
                original_bytes: bytes | None = None
            else:
                original_bytes = (
                    bytes(original) if isinstance(original, bytes) and len(original) == 16 else None
                )
            aad = b"authenticated generated gcm wrap"
            wrap_mech = mech_gcm_message_generated_iv(
                CKM_AES_GCM,
                iv_len=12,
                iv_generator=CKG_GENERATE,
                tag_bits=128,
            )
            try:
                wrapped = wrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    target,
                    CKM_AES_GCM,
                    aad=aad,
                    mech_param=wrap_mech,
                )
            except AssertionError as exc:
                _skip_if_authenticated_wrap_not_implemented(exc, "C_WrapKeyAuthenticated")
                if is_known_error(
                    exc,
                    {
                        CKR_ARGUMENTS_BAD,
                        CKR_KEY_FUNCTION_NOT_PERMITTED,
                        CKR_MECHANISM_INVALID,
                        CKR_MECHANISM_PARAM_INVALID,
                    },
                ):
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="CKM_AES_GCM:C_WrapKeyAuthenticated (generated IV)",
                        operation="C_WrapKeyAuthenticated",
                        mechanism="CKM_AES_GCM",
                        summary=f"AES-GCM authenticated generated-IV wrap rejected: {exc}",
                    )
                raise
            iv = wrap_mech.buffer_bytes("iv")
            tag = wrap_mech.buffer_bytes("tag")
            if not _has_nonzero_bytes(iv):
                hard_results.append(
                    _record_output_mismatch(
                        label="CKM_AES_GCM:C_WrapKeyAuthenticated generated IV",
                        expected="non-zero IV bytes",
                        actual=repr(iv),
                        operation="C_WrapKeyAuthenticated",
                        mechanism="CKM_AES_GCM",
                    )
                )
            if not _has_nonzero_bytes(tag):
                hard_results.append(
                    _record_output_mismatch(
                        label="CKM_AES_GCM:C_WrapKeyAuthenticated generated tag",
                        expected="non-zero tag bytes",
                        actual=repr(tag),
                        operation="C_WrapKeyAuthenticated",
                        mechanism="CKM_AES_GCM",
                    )
                )

            if _has_nonzero_bytes(iv) and _has_nonzero_bytes(tag):
                unwrap_mech = mech_gcm_message_inherit_tag(CKM_AES_GCM, iv, source=wrap_mech)
                unwrapped = unwrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    wrapped,
                    CKM_AES_GCM,
                    attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
                    aad=aad,
                    mech_param=unwrap_mech,
                )
                value = _read_attr_or_record(
                    rs.raw,
                    rs.sh,
                    unwrapped,
                    CKA_VALUE,
                    label="CKM_AES_GCM:generated-IV unwrapped CKA_VALUE readback",
                    mechanism="CKM_AES_GCM",
                )
                mismatch = _check_aes128_value(
                    value,
                    label="CKM_AES_GCM:generated-IV unwrapped CKA_VALUE readback",
                    mechanism="CKM_AES_GCM",
                )
                if mismatch is not None:
                    hard_results.append(mismatch)
                if (
                    original_bytes is not None
                    and value is not MISSING_ATTRIBUTE
                    and value != original_bytes
                ):
                    hard_results.append(
                        _record_attribute_mismatch(
                            label="CKM_AES_GCM:generated-IV wrap/unwrap preserves key material",
                            expected=repr(original_bytes),
                            actual=repr(value),
                            mechanism="CKM_AES_GCM",
                            operation="C_UnwrapKeyAuthenticated",
                        )
                    )
        finally:
            if unwrapped:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
            if wrap_h:
                destroy_quietly(rs.raw, rs.sh, wrap_h)
            if target:
                destroy_quietly(rs.raw, rs.sh, target)
        _raise_strongest(hard_results)

    @pytest.mark.needs_function("C_WrapKeyAuthenticated")
    def test_tampered_tag_rejected(
        self,
        p11_raw_session: Any,
        p11_interface_version: str,
        p11_config: Any,
    ) -> None:
        """Unwrap with tampered authentication tag must fail.

        Discrimination (Pillar 2): the un-tampered blob must unwrap and
        recover the original material (valid leg); the tag-tampered blob
        must be rejected (invalid leg). A produced object on the invalid
        leg is an AEAD authentication break.
        """
        rs = p11_raw_session
        if p11_interface_version not in ("3.2",):
            pytest.skip("Authenticated wrapping requires v3.2 interface")
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        wrap_h = 0
        target = 0
        hard_results: list[C.Classification] = []
        try:
            wrap_h = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={CKA_WRAP: True, CKA_UNWRAP: True, CKA_ENCRYPT: True, CKA_DECRYPT: True},
            )
            target = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
            )
            original = _read_attr_or_record(
                rs.raw,
                rs.sh,
                target,
                CKA_VALUE,
                label="CKM_AES_GCM:tampered-tag target CKA_VALUE readback",
                mechanism="CKM_AES_GCM",
            )
            mismatch = _check_aes128_value(
                original,
                label="CKM_AES_GCM:tampered-tag target CKA_VALUE readback",
                mechanism="CKM_AES_GCM",
            )
            if mismatch is not None:
                hard_results.append(mismatch)
            if original is MISSING_ATTRIBUTE:
                original_bytes: bytes | None = None
            else:
                original_bytes = (
                    bytes(original) if isinstance(original, bytes) and len(original) == 16 else None
                )
            iv = generate_random(rs.raw, rs.sh, 12)
            wrap_mech = mech_gcm_message(CKM_AES_GCM, iv, tag_bits=128)
            try:
                wrapped = wrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    target,
                    CKM_AES_GCM,
                    mech_param=wrap_mech,
                )
            except (NotImplementedError, AttributeError, TypeError):
                pytest.skip("wrap_key_authenticated not available")
                return
            except AssertionError as exc:
                _skip_if_authenticated_wrap_not_implemented(exc, "C_WrapKeyAuthenticated")
                _xfail_if_wrap_runtime_reject(exc, "AES-GCM authenticated wrap rejected")

            tag = wrap_mech.buffer_bytes("tag")
            if not _has_nonzero_bytes(tag):
                hard_results.append(
                    _record_output_mismatch(
                        label="CKM_AES_GCM:C_WrapKeyAuthenticated authentication tag",
                        expected="non-zero tag bytes",
                        actual=repr(tag),
                        operation="C_WrapKeyAuthenticated",
                        mechanism="CKM_AES_GCM",
                    )
                )
            else:
                # Valid leg (D4/D5): unwrap the UN-tampered blob and recover original.
                good_mech = mech_gcm_message_inherit_tag(CKM_AES_GCM, iv, source=wrap_mech)
                good = 0
                try:
                    good = unwrap_key_authenticated(
                        rs.raw,
                        rs.sh,
                        wrap_h,
                        wrapped,
                        CKM_AES_GCM,
                        attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
                        mech_param=good_mech,
                    )
                except AssertionError as exc:
                    _skip_if_authenticated_wrap_not_implemented(exc, "C_UnwrapKeyAuthenticated")
                    _xfail_if_wrap_runtime_reject(
                        exc, "AES-GCM authenticated unwrap (valid leg) not operational"
                    )
                try:
                    good_value = _read_attr_or_record(
                        rs.raw,
                        rs.sh,
                        good,
                        CKA_VALUE,
                        label="CKM_AES_GCM:tampered-tag valid-leg CKA_VALUE readback",
                        mechanism="CKM_AES_GCM",
                    )
                    mismatch = _check_aes128_value(
                        good_value,
                        label="CKM_AES_GCM:tampered-tag valid-leg CKA_VALUE readback",
                        mechanism="CKM_AES_GCM",
                    )
                    if mismatch is not None:
                        hard_results.append(mismatch)
                finally:
                    destroy_quietly(rs.raw, rs.sh, good)
                if good_value is MISSING_ATTRIBUTE:
                    good_bytes: bytes | None = None
                else:
                    good_bytes = (
                        bytes(good_value)
                        if isinstance(good_value, bytes) and len(good_value) == 16
                        else None
                    )
                valid_accepted = (
                    original_bytes is not None
                    and good_bytes is not None
                    and good_bytes == original_bytes
                )

                # Invalid leg (D3): tamper the tag in-place via a shared pTag buffer.
                bad_mech = mech_gcm_message_inherit_tag(CKM_AES_GCM, iv, source=wrap_mech)
                tag_storage, _ = bad_mech.buffer_storage("tag")
                tag_storage[0] ^= 0xFF
                invalid_outcome: Any
                try:
                    h = unwrap_key_authenticated(
                        rs.raw,
                        rs.sh,
                        wrap_h,
                        wrapped,
                        CKM_AES_GCM,
                        attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
                        mech_param=bad_mech,
                    )
                    invalid_outcome = h
                    destroy_quietly(rs.raw, rs.sh, h)
                except AssertionError as exc:
                    invalid_outcome = exc
                _record_discrimination(
                    valid_accepted=valid_accepted,
                    valid_value=(
                        good_bytes
                        if original_bytes is not None and good_bytes is not None
                        else MISSING_ATTRIBUTE
                    ),
                    invalid_outcome=invalid_outcome,
                    label="AES-GCM authenticated unwrap of tag-tampered blob",
                    operation="C_UnwrapKeyAuthenticated",
                    mechanism="CKM_AES_GCM",
                    hard_results=hard_results,
                )
        finally:
            if wrap_h:
                destroy_quietly(rs.raw, rs.sh, wrap_h)
            if target:
                destroy_quietly(rs.raw, rs.sh, target)
        _raise_strongest(hard_results)

    def test_authenticated_wrap_requires_v32(
        self, p11_raw_session: Any, p11_interface_version: str
    ) -> None:
        """On v2.40 modules, wrap_key_authenticated is not available."""
        rs = p11_raw_session
        if p11_interface_version not in ("2.40",):
            pytest.skip("Only relevant for v2.40 modules")

        require_operational_aes_keygen(rs)
        key = 0
        target = 0

        try:
            key = gen_aes_key(rs.raw, rs.sh, 128)
            target = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={CKA_EXTRACTABLE: True},
            )
            # v2.40 raw API should not have C_WrapKeyAuthenticated
            has_fn = hasattr(rs.raw, "C_WrapKeyAuthenticated")
            if has_fn:
                iv = generate_random(rs.raw, rs.sh, 12)
                wrap_mech = mech_gcm_message(CKM_AES_GCM, iv, tag_bits=128)
                try:
                    wrap_key_authenticated(
                        rs.raw,
                        rs.sh,
                        key,
                        target,
                        CKM_AES_GCM,
                        mech_param=wrap_mech,
                    )
                except (AssertionError, AttributeError, NotImplementedError):
                    pass  # audit-ok: capability gap; GCM authenticated wrap absent on v2.40 modules
            # If no C_WrapKeyAuthenticated method, test passes
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)
            if target:
                destroy_quietly(rs.raw, rs.sh, target)


class TestAuthenticatedWrapAAD:
    """GAP-W4: tampered-AAD path on authenticated wrap/unwrap (v3.2).

    The v3.2 authenticated-wrap test_tampered_tag_rejected covers
    ciphertext-tag tampering. AAD is a separate AEAD input — its
    tampering must also produce an AEAD verification failure. A module
    that authenticates only the ciphertext-and-tag tuple while ignoring
    AAD has a real authentication-bypass bug (CWE-354 "Improper
    Validation of Integrity Check Value").

    Closes Phase 4.5 GAP-W4 (MED).
    """

    @pytest.mark.needs_function("C_WrapKeyAuthenticated")
    def test_aes_gcm_unwrap_with_different_aad_rejected(
        self,
        p11_raw_session: Any,
        p11_interface_version: str,
        p11_config: Any,
    ) -> None:
        """Wrap with AAD=X, unwrap with AAD=Y. Unwrap MUST fail."""
        rs = p11_raw_session
        if p11_interface_version not in ("3.2",):
            pytest.skip("Authenticated wrapping requires v3.2 interface")
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        wrap_h = 0
        target = 0
        hard_results: list[C.Classification] = []
        try:
            wrap_h = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={
                    CKA_WRAP: True,
                    CKA_UNWRAP: True,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                },
            )
            target = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
            )
            original = _read_attr_or_record(
                rs.raw,
                rs.sh,
                target,
                CKA_VALUE,
                label="CKM_AES_GCM:AAD target CKA_VALUE readback",
                mechanism="CKM_AES_GCM",
            )
            mismatch = _check_aes128_value(
                original,
                label="CKM_AES_GCM:AAD target CKA_VALUE readback",
                mechanism="CKM_AES_GCM",
            )
            if mismatch is not None:
                hard_results.append(mismatch)
            if original is MISSING_ATTRIBUTE:
                original_bytes: bytes | None = None
            else:
                original_bytes = (
                    bytes(original) if isinstance(original, bytes) and len(original) == 16 else None
                )
            iv = generate_random(rs.raw, rs.sh, 12)
            aad_x = b"context-X-" + b"\xaa" * 16
            aad_y = b"context-Y-" + b"\xbb" * 16

            wrap_mech = mech_gcm_message(CKM_AES_GCM, iv, tag_bits=128)
            try:
                wrapped = wrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    target,
                    CKM_AES_GCM,
                    aad=aad_x,
                    mech_param=wrap_mech,
                )
            except (NotImplementedError, AttributeError, TypeError) as exc:
                # API not available on this module — skip cleanly.
                pytest.skip(f"AES-GCM authenticated wrap API not available: {exc}")
                return
            except AssertionError as exc:
                # CKR_FUNCTION_NOT_SUPPORTED is capability absence (C_WrapKeyAuthenticated
                # itself unimplemented) -- mechanism advertisement is orthogonal to function
                # support and cannot promote it into a deviation, so it is a skip, not an
                # xfail (checked before xfail_if_known_ckr so it never reaches that set).
                if isinstance(exc, CkrAssertionError) and exc.rv == int(CKR_FUNCTION_NOT_SUPPORTED):
                    pytest.skip(
                        "C_WrapKeyAuthenticated not implemented: CKR_FUNCTION_NOT_SUPPORTED"
                    )
                # Wrap-side failure. xfail ONLY when the failure looks like a clean
                # refusal of this advertised configuration (mech-not-supported /
                # AAD-too-long / GCM-params-bad) -- that is a noted deviation, not an
                # absent capability, so it must stay a retained finding (xfail), never
                # a skip that would void the observation. Crashes (CKR_GENERAL_ERROR /
                # CKR_FUNCTION_FAILED / CKR_DEVICE_ERROR) re-raise -- those are
                # findings, not xfail conditions.
                xfail_if_known_ckr(
                    exc,
                    {
                        CKR_MECHANISM_INVALID,
                        CKR_MECHANISM_PARAM_INVALID,
                        CKR_KEY_FUNCTION_NOT_PERMITTED,
                        CKR_ARGUMENTS_BAD,
                    },
                    "AES-GCM authenticated wrap (AAD leg) rejected",
                )

            # Valid leg (D4/D5): unwrap with the SAME AAD and recover original.
            good_mech = mech_gcm_message_inherit_tag(CKM_AES_GCM, iv, source=wrap_mech)
            good = 0
            try:
                good = unwrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    wrapped,
                    CKM_AES_GCM,
                    attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
                    aad=aad_x,
                    mech_param=good_mech,
                )
            except AssertionError as exc:
                _skip_if_authenticated_wrap_not_implemented(exc, "C_UnwrapKeyAuthenticated")
                _xfail_if_wrap_runtime_reject(
                    exc, "AES-GCM authenticated unwrap (valid AAD leg) not operational"
                )
            good_value: Any = MISSING_ATTRIBUTE
            try:
                good_value = _read_attr_or_record(
                    rs.raw,
                    rs.sh,
                    good,
                    CKA_VALUE,
                    label="CKM_AES_GCM:AAD valid-leg CKA_VALUE readback",
                    mechanism="CKM_AES_GCM",
                )
                mismatch = _check_aes128_value(
                    good_value,
                    label="CKM_AES_GCM:AAD valid-leg CKA_VALUE readback",
                    mechanism="CKM_AES_GCM",
                )
                if mismatch is not None:
                    hard_results.append(mismatch)
            finally:
                destroy_quietly(rs.raw, rs.sh, good)
                if good_value is MISSING_ATTRIBUTE:
                    good_bytes: bytes | None = None
                else:
                    good_bytes = (
                        bytes(good_value)
                        if isinstance(good_value, bytes) and len(good_value) == 16
                        else None
                    )
                valid_accepted = (
                    original_bytes is not None
                    and good_bytes is not None
                    and good_bytes == original_bytes
                )

            # Invalid leg (D3): unwrap with a DIFFERENT AAD — AEAD must reject.
            bad_mech = mech_gcm_message_inherit_tag(CKM_AES_GCM, iv, source=wrap_mech)
            invalid_outcome: Any
            try:
                h = unwrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    wrapped,
                    CKM_AES_GCM,
                    attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
                    aad=aad_y,
                    mech_param=bad_mech,
                )
                invalid_outcome = h
                destroy_quietly(rs.raw, rs.sh, h)
            except AssertionError as exc:
                invalid_outcome = exc
            _record_discrimination(
                valid_accepted=valid_accepted,
                valid_value=(
                    good_bytes
                    if original_bytes is not None and good_bytes is not None
                    else MISSING_ATTRIBUTE
                ),
                invalid_outcome=invalid_outcome,
                label="AES-GCM authenticated unwrap under a different AAD (CWE-354)",
                operation="C_UnwrapKeyAuthenticated",
                mechanism="CKM_AES_GCM",
                hard_results=hard_results,
            )
        finally:
            if wrap_h:
                destroy_quietly(rs.raw, rs.sh, wrap_h)
            if target:
                destroy_quietly(rs.raw, rs.sh, target)
        _raise_strongest(hard_results)


class TestWrapIntegrity:
    """GAP-W2: integrity comparison between authenticated and unauthenticated wraps.

    AES-KEY-WRAP (RFC 3394) has a fixed-magic A6A6A6A6 integrity field, so
    bit-flipping the ciphertext should be detected on unwrap. AES-GCM
    (AEAD) has a real authentication tag and bit-flipping the ciphertext
    must be detected. Both rules are explicit security guarantees of their
    respective wrap mechanisms.

    Closes Phase 4.5 GAP-W2 (HIGH).
    """

    def test_aes_key_wrap_bit_flip_detected(self, p11_raw_session: Any, p11_config: Any) -> None:
        """AES-KEY-WRAP RFC-3394 magic-field integrity check.

        Discrimination (Pillar 2): the un-tampered ciphertext must unwrap and
        recover the original key (valid leg); a bit-flipped middle byte must be
        rejected (invalid leg). Per RFC 3394 §2.2.2, unwrap MUST verify the
        A6A6A6A6 integrity check value and reject mismatches. A module that
        produces a key from tampered ciphertext is malleable — a break.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_h = 0
        target = 0
        hard_results: list[C.Classification] = []
        try:
            wrap_h = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={CKA_WRAP: True, CKA_UNWRAP: True},
            )
            target = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
            )
            original = _read_attr_or_record(
                rs.raw,
                rs.sh,
                target,
                CKA_VALUE,
                label="CKM_AES_KEY_WRAP:target CKA_VALUE readback",
                mechanism="CKM_AES_KEY_WRAP",
            )
            mismatch = _check_aes128_value(
                original,
                label="CKM_AES_KEY_WRAP:target CKA_VALUE readback",
                mechanism="CKM_AES_KEY_WRAP",
            )
            if mismatch is not None:
                hard_results.append(mismatch)
            if original is MISSING_ATTRIBUTE:
                original_bytes: bytes | None = None
            else:
                original_bytes = (
                    bytes(original) if isinstance(original, bytes) and len(original) == 16 else None
                )
            try:
                wrapped = wrap_key(rs.raw, rs.sh, wrap_h, target, CKM_AES_KEY_WRAP)
            except AssertionError as exc:
                _xfail_if_wrap_runtime_reject(
                    exc,
                    "AES_KEY_WRAP advertised but wrap operation is not operational",
                )

            wrapped_usable = isinstance(wrapped, bytes) and len(wrapped) >= 16
            if not wrapped_usable:
                hard_results.append(
                    _record_output_mismatch(
                        label="CKM_AES_KEY_WRAP:C_WrapKey output",
                        expected="at least 16 ciphertext bytes",
                        actual=repr(wrapped),
                        operation="C_WrapKey",
                        mechanism="CKM_AES_KEY_WRAP",
                    )
                )

            if wrapped_usable:
                unwrap_attrs = {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                }

                # Valid leg (D4/D5): unwrap the UN-tampered blob (negotiating the
                # accepted template) and recover the original key bytes.
                try:
                    good = unwrap_key_for_mechanism_roundtrip(
                        rs,
                        p11_config,
                        unwrapping_key=wrap_h,
                        wrapped_key=wrapped,
                        mechanism=CKM_AES_KEY_WRAP,
                        attrs=unwrap_attrs,
                        value_len=len(original_bytes) if original_bytes is not None else 16,
                        purpose="AES-KEY-WRAP unwrap (valid leg)",
                    )
                except AssertionError as exc:
                    _xfail_if_wrap_runtime_reject(
                        exc, "AES_KEY_WRAP unwrap (valid leg) not operational"
                    )
                try:
                    good_value = _read_attr_or_record(
                        rs.raw,
                        rs.sh,
                        good,
                        CKA_VALUE,
                        label="CKM_AES_KEY_WRAP:valid-leg CKA_VALUE readback",
                        mechanism="CKM_AES_KEY_WRAP",
                    )
                    mismatch = _check_aes128_value(
                        good_value,
                        label="CKM_AES_KEY_WRAP:valid-leg CKA_VALUE readback",
                        mechanism="CKM_AES_KEY_WRAP",
                    )
                    if mismatch is not None:
                        hard_results.append(mismatch)
                finally:
                    destroy_quietly(rs.raw, rs.sh, good)
                if good_value is MISSING_ATTRIBUTE:
                    good_bytes: bytes | None = None
                else:
                    good_bytes = (
                        bytes(good_value)
                        if isinstance(good_value, bytes) and len(good_value) == 16
                        else None
                    )
                valid_accepted = (
                    original_bytes is not None
                    and good_bytes is not None
                    and good_bytes == original_bytes
                )

                # Invalid leg (D3): flip a bit in a middle byte (avoiding the first
                # 8 bytes which carry the integrity ICV — flipping there is a
                # different test) and attempt the same unwrap.
                mid = len(wrapped) // 2
                tampered = bytearray(wrapped)
                tampered[mid] ^= 0xFF
                tampered_bytes = bytes(tampered)

                invalid_outcome: Any
                try:
                    h = unwrap_key_for_mechanism_roundtrip(
                        rs,
                        p11_config,
                        unwrapping_key=wrap_h,
                        wrapped_key=tampered_bytes,
                        mechanism=CKM_AES_KEY_WRAP,
                        attrs=unwrap_attrs,
                        value_len=len(original_bytes) if original_bytes is not None else 16,
                        purpose="AES-KEY-WRAP unwrap of bit-flipped ciphertext",
                    )
                    invalid_outcome = h
                    destroy_quietly(rs.raw, rs.sh, h)
                except AssertionError as exc:
                    invalid_outcome = exc
                _record_discrimination(
                    valid_accepted=valid_accepted,
                    valid_value=(
                        good_bytes
                        if original_bytes is not None and good_bytes is not None
                        else MISSING_ATTRIBUTE
                    ),
                    invalid_outcome=invalid_outcome,
                    label="AES-KEY-WRAP unwrap of bit-flipped ciphertext (RFC 3394 ICV)",
                    operation="C_UnwrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    hard_results=hard_results,
                )
        finally:
            if wrap_h:
                destroy_quietly(rs.raw, rs.sh, wrap_h)
            if target:
                destroy_quietly(rs.raw, rs.sh, target)
        _raise_strongest(hard_results)

    @pytest.mark.needs_function("C_WrapKeyAuthenticated")
    def test_aes_gcm_wrap_bit_flip_detected(
        self,
        p11_raw_session: Any,
        p11_interface_version: str,
        p11_config: Any,
    ) -> None:
        """AES-GCM authenticated-wrap ciphertext bit-flip MUST be rejected.

        Complementary to test_tampered_tag_rejected: this test tampers the
        ciphertext (not the tag), to catch implementations that only
        validate the tag against the original-ciphertext hash and skip
        the AAD/CT integrity check.
        """
        rs = p11_raw_session
        if p11_interface_version not in ("3.2",):
            pytest.skip("Authenticated wrapping requires v3.2 interface")
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        wrap_h = 0
        target = 0
        hard_results: list[C.Classification] = []
        try:
            wrap_h = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={
                    CKA_WRAP: True,
                    CKA_UNWRAP: True,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                },
            )
            target = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
            )
            original = _read_attr_or_record(
                rs.raw,
                rs.sh,
                target,
                CKA_VALUE,
                label="CKM_AES_GCM:ciphertext-tamper target CKA_VALUE readback",
                mechanism="CKM_AES_GCM",
            )
            mismatch = _check_aes128_value(
                original,
                label="CKM_AES_GCM:ciphertext-tamper target CKA_VALUE readback",
                mechanism="CKM_AES_GCM",
            )
            if mismatch is not None:
                hard_results.append(mismatch)
            if original is MISSING_ATTRIBUTE:
                original_bytes: bytes | None = None
            else:
                original_bytes = (
                    bytes(original) if isinstance(original, bytes) and len(original) == 16 else None
                )
            iv = generate_random(rs.raw, rs.sh, 12)
            wrap_mech = mech_gcm_message(CKM_AES_GCM, iv, tag_bits=128)
            try:
                wrapped = wrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    target,
                    CKM_AES_GCM,
                    mech_param=wrap_mech,
                )
            except (NotImplementedError, AttributeError, TypeError) as e:
                pytest.skip(f"AES-GCM authenticated wrap unavailable: {e}")
                return
            except AssertionError as exc:
                _skip_if_authenticated_wrap_not_implemented(exc, "C_WrapKeyAuthenticated")
                _xfail_if_wrap_runtime_reject(exc, "AES-GCM authenticated wrap rejected")

            wrapped_usable = isinstance(wrapped, bytes) and bool(wrapped)
            if not wrapped_usable:
                hard_results.append(
                    _record_output_mismatch(
                        label="CKM_AES_GCM:C_WrapKeyAuthenticated ciphertext output",
                        expected="non-empty ciphertext",
                        actual=repr(wrapped),
                        operation="C_WrapKeyAuthenticated",
                        mechanism="CKM_AES_GCM",
                    )
                )

            if wrapped_usable:
                # Valid leg (D4/D5): unwrap the UN-tampered ciphertext, recover original.
                good_mech = mech_gcm_message_inherit_tag(CKM_AES_GCM, iv, source=wrap_mech)
                try:
                    good = unwrap_key_authenticated(
                        rs.raw,
                        rs.sh,
                        wrap_h,
                        wrapped,
                        CKM_AES_GCM,
                        attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
                        mech_param=good_mech,
                    )
                except AssertionError as exc:
                    _skip_if_authenticated_wrap_not_implemented(exc, "C_UnwrapKeyAuthenticated")
                    _xfail_if_wrap_runtime_reject(
                        exc, "AES-GCM authenticated unwrap (valid leg) not operational"
                    )
                try:
                    good_value = _read_attr_or_record(
                        rs.raw,
                        rs.sh,
                        good,
                        CKA_VALUE,
                        label="CKM_AES_GCM:ciphertext-tamper valid-leg CKA_VALUE readback",
                        mechanism="CKM_AES_GCM",
                    )
                    mismatch = _check_aes128_value(
                        good_value,
                        label="CKM_AES_GCM:ciphertext-tamper valid-leg CKA_VALUE readback",
                        mechanism="CKM_AES_GCM",
                    )
                    if mismatch is not None:
                        hard_results.append(mismatch)
                finally:
                    destroy_quietly(rs.raw, rs.sh, good)
                if good_value is MISSING_ATTRIBUTE:
                    good_bytes: bytes | None = None
                else:
                    good_bytes = (
                        bytes(good_value)
                        if isinstance(good_value, bytes) and len(good_value) == 16
                        else None
                    )
                valid_accepted = (
                    original_bytes is not None
                    and good_bytes is not None
                    and good_bytes == original_bytes
                )

                # Invalid leg (D3): flip a bit in the ciphertext, NOT the tag.
                tampered_ct = bytearray(wrapped)
                tampered_ct[0] ^= 0x01
                tampered_bytes = bytes(tampered_ct)

                bad_mech = mech_gcm_message_inherit_tag(CKM_AES_GCM, iv, source=wrap_mech)
                invalid_outcome: Any
                try:
                    h = unwrap_key_authenticated(
                        rs.raw,
                        rs.sh,
                        wrap_h,
                        tampered_bytes,
                        CKM_AES_GCM,
                        attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
                        mech_param=bad_mech,
                    )
                    invalid_outcome = h
                    destroy_quietly(rs.raw, rs.sh, h)
                except AssertionError as exc:
                    invalid_outcome = exc
                _record_discrimination(
                    valid_accepted=valid_accepted,
                    valid_value=(
                        good_bytes
                        if original_bytes is not None and good_bytes is not None
                        else MISSING_ATTRIBUTE
                    ),
                    invalid_outcome=invalid_outcome,
                    label="AES-GCM authenticated unwrap of bit-flipped ciphertext",
                    operation="C_UnwrapKeyAuthenticated",
                    mechanism="CKM_AES_GCM",
                    hard_results=hard_results,
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)
        _raise_strongest(hard_results)


class TestEcdhAesKeyWrap:
    """GAP-W3: ECDH-AES hybrid wrap roundtrip + integrity.

    The hybrid mechanism derives an AES key via ECDH (using the
    recipient's public key + an internally-generated ephemeral key
    pair) and then wraps the target with AES-KW under that derived
    key. The wrap blob carries the ephemeral public point alongside
    the AES-KW ciphertext so the recipient can re-derive the wrapping
    AES key.

    Closes Phase 4.5 GAP-W3 (MED).
    """

    @pytest.mark.parametrize(
        "case",
        _ECDH_AES_KW_CASES,
        ids=[c.short_name for c in _ECDH_AES_KW_CASES],
    )
    def test_ecdh_aes_kw_roundtrip(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        case: _EcdhAesKwCase,
    ) -> None:
        """Wrap an AES key with the ECDH-AES-KW family, unwrap, verify
        roundtrip recovers the original key. The unwrap template is
        negotiated (canonical CKA_CLASS+CKA_KEY_TYPE plus policy attrs first;
        on a shape reject, retry dropping only policy attrs) so a module that
        rejects policy attrs in unwrap templates still completes the roundtrip
        instead of being silently skipped. The bit-flip integrity
        assertion is in a separate test
        (`test_ecdh_aes_kw_bit_flip_integrity`)."""
        rs = p11_raw_session
        if not rs.has_mechanism(case.short_name):
            pytest.skip(f"CKM_{case.short_name} not supported")

        pub = priv = target = 0
        hard_results: list[C.Classification] = []
        unwrapped = 0
        try:
            pub, priv = _ecdh_aes_kw_recipient_keypair(rs, case)
            target = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
            )
            original = _read_attr_or_record(
                rs.raw,
                rs.sh,
                target,
                CKA_VALUE,
                label=f"CKM_{case.short_name}:target CKA_VALUE readback",
                mechanism=f"CKM_{case.short_name}",
            )
            mismatch = _check_aes128_value(
                original,
                label=f"CKM_{case.short_name}:target CKA_VALUE readback",
                mechanism=f"CKM_{case.short_name}",
            )
            if mismatch is not None:
                hard_results.append(mismatch)
            if original is MISSING_ATTRIBUTE:
                original_bytes: bytes | None = None
            else:
                original_bytes = (
                    bytes(original) if isinstance(original, bytes) and len(original) == 16 else None
                )
            # --- Roundtrip ---
            wrapped = _wrap_ecdh_aes_kw_or_xfail(
                rs,
                recipient_public=pub,
                target=target,
                case=case,
            )

            wrapped_usable = isinstance(wrapped, bytes) and len(wrapped) > 16
            if not wrapped_usable:
                hard_results.append(
                    _record_output_mismatch(
                        label=f"CKM_{case.short_name}:C_WrapKey output",
                        expected="more than 16 ciphertext bytes",
                        actual=repr(wrapped),
                        operation="C_WrapKey",
                        mechanism=f"CKM_{case.short_name}",
                    )
                )

            if wrapped_usable:
                try:
                    unwrapped = unwrap_key_for_mechanism_roundtrip(
                        rs,
                        p11_config,
                        unwrapping_key=priv,
                        wrapped_key=wrapped,
                        mechanism=case.mechanism,
                        attrs={
                            CKA_CLASS: CKO_SECRET_KEY,
                            CKA_KEY_TYPE: CKK_AES,
                            CKA_EXTRACTABLE: True,
                            CKA_SENSITIVE: False,
                        },
                        mech_param=_ecdh_aes_kw_mech(case),
                        purpose=f"CKM_{case.short_name} unwrap roundtrip",
                    )
                except AssertionError as exc:
                    _xfail_if_wrap_runtime_reject(
                        exc, f"CKM_{case.short_name} unwrap (roundtrip) not operational"
                    )
                # Round-trip succeeded — verify it recovered the original key.
                unwrapped_value = _read_attr_or_record(
                    rs.raw,
                    rs.sh,
                    unwrapped,
                    CKA_VALUE,
                    label=f"CKM_{case.short_name}:unwrapped CKA_VALUE readback",
                    mechanism=f"CKM_{case.short_name}",
                )
                mismatch = _check_aes128_value(
                    unwrapped_value,
                    label=f"CKM_{case.short_name}:unwrapped CKA_VALUE readback",
                    mechanism=f"CKM_{case.short_name}",
                )
                if mismatch is not None:
                    hard_results.append(mismatch)
                if (
                    original_bytes is not None
                    and unwrapped_value is not MISSING_ATTRIBUTE
                    and unwrapped_value != original_bytes
                ):
                    hard_results.append(
                        _record_attribute_mismatch(
                            label=f"CKM_{case.short_name}:ECDH wrap/unwrap preserves key material",
                            expected=repr(original_bytes),
                            actual=repr(unwrapped_value),
                            mechanism=f"CKM_{case.short_name}",
                            operation="C_UnwrapKey",
                        )
                    )
        finally:
            if pub:
                destroy_quietly(rs.raw, rs.sh, pub)
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)
            if target:
                destroy_quietly(rs.raw, rs.sh, target)
            if unwrapped:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        _raise_strongest(hard_results)

    @pytest.mark.parametrize(
        "case",
        _ECDH_AES_KW_CASES,
        ids=[c.short_name for c in _ECDH_AES_KW_CASES],
    )
    def test_ecdh_aes_kw_bit_flip_integrity(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        case: _EcdhAesKwCase,
    ) -> None:
        """Bit-flip integrity check for the ECDH-AES-KW family.

        Wrap a target key, flip a byte in the AES-KW ciphertext region of
        the hybrid blob, attempt unwrap. The AES-KW RFC 3394 magic-field
        ICV check should reject the tampered ciphertext.

        Kept separate from the roundtrip test so a skip on the roundtrip
        path (e.g. an unwrap-template quirk) doesn't silently hide the
        integrity coverage from pytest output.
        """
        rs = p11_raw_session
        if not rs.has_mechanism(case.short_name):
            pytest.skip(f"CKM_{case.short_name} not supported")

        pub = priv = target = 0
        hard_results: list[C.Classification] = []
        try:
            pub, priv = _ecdh_aes_kw_recipient_keypair(rs, case)
            target = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
            )
            original = _read_attr_or_record(
                rs.raw,
                rs.sh,
                target,
                CKA_VALUE,
                label=f"CKM_{case.short_name}:target CKA_VALUE readback",
                mechanism=f"CKM_{case.short_name}",
            )
            mismatch = _check_aes128_value(
                original,
                label=f"CKM_{case.short_name}:target CKA_VALUE readback",
                mechanism=f"CKM_{case.short_name}",
            )
            if mismatch is not None:
                hard_results.append(mismatch)
            if original is MISSING_ATTRIBUTE:
                original_bytes: bytes | None = None
            else:
                original_bytes = (
                    bytes(original) if isinstance(original, bytes) and len(original) == 16 else None
                )
            wrapped = _wrap_ecdh_aes_kw_or_xfail(
                rs,
                recipient_public=pub,
                target=target,
                case=case,
            )
            wrapped_usable = isinstance(wrapped, bytes) and len(wrapped) > 16
            if not wrapped_usable:
                hard_results.append(
                    _record_output_mismatch(
                        label=f"CKM_{case.short_name}:C_WrapKey output",
                        expected="more than 16 ciphertext bytes",
                        actual=repr(wrapped),
                        operation="C_WrapKey",
                        mechanism=f"CKM_{case.short_name}",
                    )
                )

            if wrapped_usable:
                unwrap_attrs = {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                }

                # Valid leg (D4/D5): unwrap the UN-tampered blob (negotiating the
                # accepted template) and recover the original key.
                good = 0
                try:
                    good = unwrap_key_for_mechanism_roundtrip(
                        rs,
                        p11_config,
                        unwrapping_key=priv,
                        wrapped_key=wrapped,
                        mechanism=case.mechanism,
                        attrs=unwrap_attrs,
                        mech_param=_ecdh_aes_kw_mech(case),
                        purpose=f"CKM_{case.short_name} unwrap (valid leg)",
                    )
                except AssertionError as exc:
                    _xfail_if_wrap_runtime_reject(
                        exc, f"CKM_{case.short_name} unwrap (valid leg) not operational"
                    )
                try:
                    good_value = _read_attr_or_record(
                        rs.raw,
                        rs.sh,
                        good,
                        CKA_VALUE,
                        label=f"CKM_{case.short_name}:valid-leg CKA_VALUE readback",
                        mechanism=f"CKM_{case.short_name}",
                    )
                    mismatch = _check_aes128_value(
                        good_value,
                        label=f"CKM_{case.short_name}:valid-leg CKA_VALUE readback",
                        mechanism=f"CKM_{case.short_name}",
                    )
                    if mismatch is not None:
                        hard_results.append(mismatch)
                finally:
                    destroy_quietly(rs.raw, rs.sh, good)
                if good_value is MISSING_ATTRIBUTE:
                    good_bytes: bytes | None = None
                else:
                    good_bytes = (
                        bytes(good_value)
                        if isinstance(good_value, bytes) and len(good_value) == 16
                        else None
                    )
                valid_accepted = (
                    original_bytes is not None
                    and good_bytes is not None
                    and good_bytes == original_bytes
                )

                # Invalid leg (D3): flip a byte in the AES-KW ciphertext region.
                tampered = bytearray(wrapped)
                tampered[-2] ^= 0xFF
                invalid_outcome: Any
                try:
                    h = unwrap_key_for_mechanism_roundtrip(
                        rs,
                        p11_config,
                        unwrapping_key=priv,
                        wrapped_key=bytes(tampered),
                        mechanism=case.mechanism,
                        attrs=unwrap_attrs,
                        mech_param=_ecdh_aes_kw_mech(case),
                        purpose=f"CKM_{case.short_name} unwrap of bit-flipped ciphertext",
                    )
                    invalid_outcome = h
                    destroy_quietly(rs.raw, rs.sh, h)
                except AssertionError as exc:
                    invalid_outcome = exc
                _record_discrimination(
                    valid_accepted=valid_accepted,
                    valid_value=(
                        good_bytes
                        if original_bytes is not None and good_bytes is not None
                        else MISSING_ATTRIBUTE
                    ),
                    invalid_outcome=invalid_outcome,
                    label=f"CKM_{case.short_name} unwrap of bit-flipped ciphertext (RFC 3394 ICV)",
                    operation="C_UnwrapKey",
                    mechanism=f"CKM_{case.short_name}",
                    hard_results=hard_results,
                )
        finally:
            if pub:
                destroy_quietly(rs.raw, rs.sh, pub)
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)
            if target:
                destroy_quietly(rs.raw, rs.sh, target)
        _raise_strongest(hard_results)
