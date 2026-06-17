"""AES-GCM authenticated key wrapping tests (v3.2).

Tests wrap_key_authenticated / unwrap_key_authenticated using
AES-GCM AEAD. Requires PKCS#11 v3.2 interface (C_WrapKeyAuthenticated).
"""

from __future__ import annotations

from typing import Any, NamedTuple, NoReturn

import pytest

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
from pkcs11_check.testcases._negotiation import TEMPLATE_SHAPE_REJECTS
from pkcs11_check.testcases.conftest import (
    EC_CURVE_UNSUPPORTED_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    assert_correct,
    classify_discrimination,
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
# negotiation (drop CKA_EXTRACTABLE/CKA_SENSITIVE) lets strict modules (opencryptoki) establish
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


def _xfail_if_wrap_runtime_reject(exc: AssertionError, msg: str) -> NoReturn:
    xfail_if_known_ckr(exc, _WRAP_RUNTIME_REJECT_RVS, msg)
    raise


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

        # Generate wrapping key
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

        # Generate target key
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            original_value = read_attributes(rs.raw, rs.sh, target, [CKA_VALUE])[CKA_VALUE]

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
                _xfail_if_wrap_runtime_reject(exc, "AES-GCM authenticated wrap rejected")

            if wrapped == original_value:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_AES_GCM:authenticated wrap output equals key value",
                    operation="C_WrapKeyAuthenticated",
                    mechanism="CKM_AES_GCM",
                    summary=(
                        "AES-GCM authenticated wrap produced output identical to the "
                        "plaintext key value -- wrapping was a no-op (crypto break)"
                    ),
                )
            assert any(wrap_mech.buffer_bytes("tag")), (
                "C_WrapKeyAuthenticated returned CKR_OK but left the auth tag buffer zeroed"
            )

            # Unwrap: share the wrap-side pTag so the module sees the auth tag.
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
                unwrapped_value = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
                assert_correct(
                    actual=unwrapped_value,
                    expected=original_value,
                    label="CKM_AES_GCM:authenticated wrap/unwrap preserves key material",
                    operation="C_UnwrapKeyAuthenticated",
                    mechanism="CKM_AES_GCM",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)

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
        unwrapped = 0
        try:
            original = read_attributes(rs.raw, rs.sh, target, [CKA_VALUE])[CKA_VALUE]
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
                if is_known_error(
                    exc,
                    {
                        CKR_ARGUMENTS_BAD,
                        CKR_FUNCTION_NOT_SUPPORTED,
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
            assert any(iv)
            assert any(tag)

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
            value = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
            assert_correct(
                actual=value,
                expected=original,
                label="CKM_AES_GCM:generated-IV wrap/unwrap preserves key material",
                operation="C_UnwrapKeyAuthenticated",
                mechanism="CKM_AES_GCM",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, unwrapped)
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)

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
        try:
            original = read_attributes(rs.raw, rs.sh, target, [CKA_VALUE])[CKA_VALUE]
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
                _xfail_if_wrap_runtime_reject(exc, "AES-GCM authenticated wrap rejected")

            tag = wrap_mech.buffer_bytes("tag")
            if not any(tag):
                pytest.skip("Module did not write an authentication tag to pTag")
                return

            # Valid leg (D4/D5): unwrap the UN-tampered blob and recover original.
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
                _xfail_if_wrap_runtime_reject(
                    exc, "AES-GCM authenticated unwrap (valid leg) not operational"
                )
            good_value = read_attributes(rs.raw, rs.sh, good, [CKA_VALUE]).get(CKA_VALUE)
            destroy_quietly(rs.raw, rs.sh, good)
            valid_accepted = good_value is not None and good_value == original

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
            classify_discrimination(
                valid_accepted=valid_accepted,
                invalid_outcome=invalid_outcome,
                label="AES-GCM authenticated unwrap of tag-tampered blob",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_authenticated_wrap_requires_v32(
        self, p11_raw_session: Any, p11_interface_version: str
    ) -> None:
        """On v2.40 modules, wrap_key_authenticated is not available."""
        rs = p11_raw_session
        if p11_interface_version not in ("2.40",):
            pytest.skip("Only relevant for v2.40 modules")

        require_operational_aes_keygen(rs)
        key = gen_aes_key(rs.raw, rs.sh, 128)
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True},
        )

        try:
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
                    pass  # Expected on v2.40
            # If no C_WrapKeyAuthenticated method, test passes
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
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
        try:
            original = read_attributes(rs.raw, rs.sh, target, [CKA_VALUE])[CKA_VALUE]
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
                # Wrap-side failure. Skip ONLY when the failure looks
                # like a legitimate "module rejected this configuration"
                # (mech-not-supported / AAD-too-long / GCM-params-bad).
                # Crashes (CKR_GENERAL_ERROR / CKR_FUNCTION_FAILED /
                # CKR_DEVICE_ERROR) re-raise — those are findings, not
                # skip conditions.
                if is_known_error(
                    exc,
                    {
                        CKR_MECHANISM_INVALID,
                        CKR_MECHANISM_PARAM_INVALID,
                        CKR_FUNCTION_NOT_SUPPORTED,
                        CKR_KEY_FUNCTION_NOT_PERMITTED,
                        CKR_ARGUMENTS_BAD,
                    },
                ):
                    pytest.skip(f"AES-GCM authenticated wrap rejected: {exc}")
                    return
                raise

            # Valid leg (D4/D5): unwrap with the SAME AAD and recover original.
            good_mech = mech_gcm_message_inherit_tag(CKM_AES_GCM, iv, source=wrap_mech)
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
                _xfail_if_wrap_runtime_reject(
                    exc, "AES-GCM authenticated unwrap (valid AAD leg) not operational"
                )
            good_value = read_attributes(rs.raw, rs.sh, good, [CKA_VALUE]).get(CKA_VALUE)
            destroy_quietly(rs.raw, rs.sh, good)
            valid_accepted = good_value is not None and good_value == original

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
            classify_discrimination(
                valid_accepted=valid_accepted,
                invalid_outcome=invalid_outcome,
                label="AES-GCM authenticated unwrap under a different AAD (CWE-354)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)


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
        try:
            original = read_attributes(rs.raw, rs.sh, target, [CKA_VALUE])[CKA_VALUE]
            try:
                wrapped = wrap_key(rs.raw, rs.sh, wrap_h, target, CKM_AES_KEY_WRAP)
            except AssertionError as exc:
                _xfail_if_wrap_runtime_reject(
                    exc,
                    "AES_KEY_WRAP advertised but wrap operation is not operational",
                )

            assert len(wrapped) >= 16, "Unexpectedly short wrap output"

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
                    value_len=len(original),
                    purpose="AES-KEY-WRAP unwrap (valid leg)",
                )
            except AssertionError as exc:
                _xfail_if_wrap_runtime_reject(
                    exc, "AES_KEY_WRAP unwrap (valid leg) not operational"
                )
            good_value = read_attributes(rs.raw, rs.sh, good, [CKA_VALUE]).get(CKA_VALUE)
            destroy_quietly(rs.raw, rs.sh, good)
            valid_accepted = good_value is not None and good_value == original

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
                    value_len=len(original),
                    purpose="AES-KEY-WRAP unwrap of bit-flipped ciphertext",
                )
                invalid_outcome = h
                destroy_quietly(rs.raw, rs.sh, h)
            except AssertionError as exc:
                invalid_outcome = exc
            classify_discrimination(
                valid_accepted=valid_accepted,
                invalid_outcome=invalid_outcome,
                label="AES-KEY-WRAP unwrap of bit-flipped ciphertext (RFC 3394 ICV)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)

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
        try:
            original = read_attributes(rs.raw, rs.sh, target, [CKA_VALUE])[CKA_VALUE]
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
                _xfail_if_wrap_runtime_reject(exc, "AES-GCM authenticated wrap rejected")

            assert len(wrapped) >= 1, "Unexpectedly empty wrap ciphertext"

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
                _xfail_if_wrap_runtime_reject(
                    exc, "AES-GCM authenticated unwrap (valid leg) not operational"
                )
            good_value = read_attributes(rs.raw, rs.sh, good, [CKA_VALUE]).get(CKA_VALUE)
            destroy_quietly(rs.raw, rs.sh, good)
            valid_accepted = good_value is not None and good_value == original

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
            classify_discrimination(
                valid_accepted=valid_accepted,
                invalid_outcome=invalid_outcome,
                label="AES-GCM authenticated unwrap of bit-flipped ciphertext",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)


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

        pub, priv = _ecdh_aes_kw_recipient_keypair(rs, case)

        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            original = read_attributes(rs.raw, rs.sh, target, [CKA_VALUE])[CKA_VALUE]

            # --- Roundtrip ---
            wrapped = _wrap_ecdh_aes_kw_or_xfail(
                rs,
                recipient_public=pub,
                target=target,
                case=case,
            )

            assert len(wrapped) > 16, f"CKM_{case.short_name} output unexpectedly short"

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
            unwrapped_value = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE]).get(CKA_VALUE)
            destroy_quietly(rs.raw, rs.sh, unwrapped)
            assert_correct(
                actual=unwrapped_value,
                expected=original,
                label=f"CKM_{case.short_name}:ECDH wrap/unwrap preserves key material",
                operation="C_UnwrapKey",
                mechanism=f"CKM_{case.short_name}",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, target)

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

        pub, priv = _ecdh_aes_kw_recipient_keypair(rs, case)

        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            original = read_attributes(rs.raw, rs.sh, target, [CKA_VALUE])[CKA_VALUE]
            wrapped = _wrap_ecdh_aes_kw_or_xfail(
                rs,
                recipient_public=pub,
                target=target,
                case=case,
            )

            unwrap_attrs = {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_AES,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            }

            # Valid leg (D4/D5): unwrap the UN-tampered blob (negotiating the
            # accepted template) and recover the original key.
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
            good_value = read_attributes(rs.raw, rs.sh, good, [CKA_VALUE]).get(CKA_VALUE)
            destroy_quietly(rs.raw, rs.sh, good)
            valid_accepted = good_value is not None and good_value == original

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
            classify_discrimination(
                valid_accepted=valid_accepted,
                invalid_outcome=invalid_outcome,
                label=f"CKM_{case.short_name} unwrap of bit-flipped ciphertext (RFC 3394 ICV)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, target)
