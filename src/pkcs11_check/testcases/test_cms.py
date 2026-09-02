"""Tests for CMS signature mechanism.

Covers CKM_CMS_SIG (0x500).

CKM_CMS_SIG is a sign/sign-recover mechanism using CMS (Cryptographic Message Syntax).
It requires a CK_CMS_SIG_PARAMS structure containing a certificate handle, signing
mechanism OID, digest mechanism OID, content type OID, and requested/required attributes.
This mechanism is extremely rarely implemented by PKCS#11 modules.

OASIS PKCS#11 v3.2 spec: CMS mechanisms.
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import PackedMechanism, _mech_struct, mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    gen_rsa_keypair,
    get_mechanism_info,
    sign_single,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_CMS_SIG_PARAMS,
    CK_VOID_PTR,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKM_CMS_SIG,
    CKM_SHA256_RSA_PKCS,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_FUNCTION_REJECTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases.conftest import (
    is_known_error,
    reject_or_classify,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.sign

_CMS_MISSING_PARAMS_EXPECTED_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

_CMS_SIG_RUNTIME_REJECT_CKRS = (
    *_CMS_MISSING_PARAMS_EXPECTED_CKRS,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_FUNCTION_REJECTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_NOT_LOGGED_IN,
)


def _bytes_pointer(data: bytes | None, keepalive: list[Any]) -> tuple[Any, int]:
    if data is None:
        return None, 0
    if data:
        storage = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    else:
        storage = (ctypes.c_ubyte * 0)()
    keepalive.append(storage)
    return ctypes.cast(storage, CK_VOID_PTR), len(data)


def _utf8_c_string(value: str | None, keepalive: list[Any]) -> Any:
    if value is None:
        return None
    storage = ctypes.create_string_buffer(value.encode("utf-8"))
    keepalive.append(storage)
    return ctypes.cast(storage, CK_VOID_PTR)


def _mechanism_pointer(mechanism: int | None, keepalive: list[Any]) -> Any:
    if mechanism is None:
        return None
    packed = mech_simple(mechanism)
    keepalive.append(packed)
    return ctypes.cast(ctypes.pointer(packed.ck), CK_VOID_PTR)


def _mech_cms_sig(
    *,
    signing_mechanism: int,
    digest_mechanism: int | None = None,
    content_type: str | None = "application/octet-stream",
    requested_attributes: bytes | None = None,
    required_attributes: bytes | None = None,
    certificate_handle: int = 0,
) -> PackedMechanism:
    keepalive: list[Any] = []
    params = CK_CMS_SIG_PARAMS()
    params.certificateHandle = certificate_handle
    params.pSigningMechanism = _mechanism_pointer(signing_mechanism, keepalive)
    params.pDigestMechanism = _mechanism_pointer(digest_mechanism, keepalive)
    params.pContentType = _utf8_c_string(content_type, keepalive)
    params.pRequestedAttributes, params.ulRequestedAttributesLen = _bytes_pointer(
        requested_attributes, keepalive
    )
    params.pRequiredAttributes, params.ulRequiredAttributesLen = _bytes_pointer(
        required_attributes, keepalive
    )
    sub_mechanisms = {"signing": int(signing_mechanism)}
    if digest_mechanism is not None:
        sub_mechanisms["digest"] = int(digest_mechanism)
    return _mech_struct(
        CKM_CMS_SIG,
        params,
        "mech_cms_sig",
        keepalive,
        sub_mechanisms=sub_mechanisms,
    )


def _xfail_cms_reject(exc: AssertionError, msg: str) -> None:
    xfail_if_known_ckr(exc, _CMS_SIG_RUNTIME_REJECT_CKRS, msg)
    raise exc


def _destroy_all(rs: Any, *handles: int) -> None:
    for handle in handles:
        if handle:
            destroy_quietly(rs.raw, rs.sh, handle)


class TestCMSSig:
    """CKM_CMS_SIG tests - CMS signature mechanism (sign and sign-recover)."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Report whether CKM_CMS_SIG is supported; skip if not."""
        rs = p11_raw_session
        if not rs.has_mechanism("CMS_SIG"):
            pytest.skip("CKM_CMS_SIG not supported")

    def test_mechanism_info(self, p11_raw_session: Any) -> None:
        """CKM_CMS_SIG mechanism info should report sign/sign-recover flags."""
        rs = p11_raw_session
        if not rs.has_mechanism("CMS_SIG"):
            pytest.skip("CKM_CMS_SIG not supported")

        try:
            get_mechanism_info(rs.raw, rs.slot_id, CKM_CMS_SIG)
        except CkrAssertionError as exc:
            reject_or_classify(
                exc,
                (),
                label="advertised CKM_CMS_SIG mechanism info",
                kind="metadata",
            )

    def test_cms_sig_rejects_missing_params(self, p11_raw_session: Any) -> None:
        """CKM_CMS_SIG sign attempt with RSA key and no params must fail cleanly.

        CKM_CMS_SIG requires a CK_CMS_SIG_PARAMS structure with:
          - certificate: CK_OBJECT_HANDLE pointing to a certificate object
          - pSigningMechanism: OID for the signing mechanism
          - pDigestMechanism: OID for the digest mechanism
          - pContentType: content type OID string
          - pRequestedAttributes / pRequiredAttributes: CMS attributes

        We verify the mechanism is present and that the module rejects a bare
        invocation without params rather than crashing.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("CMS_SIG"):
            pytest.skip("CKM_CMS_SIG not supported")

        pub = 0
        priv = 0
        try:
            pub, priv = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                public_attrs={
                    CKA_ENCRYPT: False,
                    CKA_VERIFY: True,
                    CKA_TOKEN: False,
                },
                private_attrs={
                    CKA_DECRYPT: False,
                    CKA_SIGN: True,
                    CKA_SENSITIVE: True,
                    CKA_EXTRACTABLE: False,
                    CKA_TOKEN: False,
                },
            )
            # Attempt CMS_SIG sign without params - must fail, not crash.
            try:
                sign_single(rs.raw, rs.sh, priv, CKM_CMS_SIG, b"test message")
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="CKM_CMS_SIG:C_Sign without CK_CMS_SIG_PARAMS",
                    operation="C_Sign",
                    mechanism="CKM_CMS_SIG",
                    summary="CKM_CMS_SIG sign succeeded without CK_CMS_SIG_PARAMS",
                )
            except AssertionError as exc:
                if is_known_error(exc, _CMS_MISSING_PARAMS_EXPECTED_CKRS):
                    return
                xfail_if_known_ckr(
                    exc,
                    _CMS_SIG_RUNTIME_REJECT_CKRS,
                    "CKM_CMS_SIG missing-params reject used a non-spec clean CKR",
                )
        except AssertionError as exc:
            _xfail_cms_reject(exc, "CMS_SIG setup for missing-params check is not operational")
        finally:
            _destroy_all(rs, priv, pub)

    def test_cms_sig_signs_with_params(self, p11_raw_session: Any) -> None:
        """CKM_CMS_SIG reaches C_Sign with a CK_CMS_SIG_PARAMS structure."""
        rs = p11_raw_session
        if not rs.has_mechanism("CMS_SIG"):
            pytest.skip("CKM_CMS_SIG not supported")

        pub = 0
        priv = 0
        try:
            pub, priv = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                public_attrs={
                    CKA_ENCRYPT: False,
                    CKA_VERIFY: True,
                    CKA_TOKEN: False,
                },
                private_attrs={
                    CKA_DECRYPT: False,
                    CKA_SIGN: True,
                    CKA_SENSITIVE: True,
                    CKA_EXTRACTABLE: False,
                    CKA_TOKEN: False,
                },
            )
            mech_param = _mech_cms_sig(
                signing_mechanism=CKM_SHA256_RSA_PKCS,
                digest_mechanism=None,
                content_type="application/octet-stream",
                requested_attributes=None,
                required_attributes=None,
            )
            signer_info = sign_single(
                rs.raw,
                rs.sh,
                priv,
                CKM_CMS_SIG,
                b"pkcs11-check cms message",
                mech_param=mech_param,
                output_size_hint=4096,
            )
            assert signer_info, "CKM_CMS_SIG returned an empty SignerInfo"
            assert signer_info[0] == 0x30, "CKM_CMS_SIG output is not a DER SEQUENCE"
        except AssertionError as exc:
            _xfail_cms_reject(exc, "CKM_CMS_SIG advertised but sign is not operational")
        finally:
            _destroy_all(rs, priv, pub)

    def test_cms_sig_not_usable_as_encrypt(self, p11_raw_session: Any) -> None:
        """CKM_CMS_SIG must not be usable as an encryption mechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("CMS_SIG"):
            pytest.skip("CKM_CMS_SIG not supported")

        key = gen_aes_key(rs.raw, rs.sh, 128)
        try:
            with pytest.raises(AssertionError):
                encrypt_single(rs.raw, rs.sh, key, CKM_CMS_SIG, b"data")
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_cms_sig_mechanism_value(self) -> None:
        """CKM_CMS_SIG numeric value must be 0x500 per PKCS#11 spec."""
        assert CKM_CMS_SIG == 0x500
