"""Read-only session restriction enforcement tests.

Verifies that RO sessions correctly reject write operations on token objects
while allowing session-scoped operations, per PKCS#11 spec section 5.6.
"""

from __future__ import annotations

import os
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify, xfail_as
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
)
from pkcs11_check.raw.bootstrap import (
    open_session as _raw_open_session,
)
from pkcs11_check.raw.pack import mech_bytes, mech_simple, template_from_dict
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    find_objects,
    import_secret_key,
    set_attributes,
    sign_single,
    unwrap_key,
    verify_single,
    wrap_key,
)
from pkcs11_check.raw.recipes import (
    gen_aes_key as _raw_gen_aes_key,
)
from pkcs11_check.raw.recipes import (
    gen_rsa_keypair as _raw_gen_rsa_keypair,
)
from pkcs11_check.raw.rv import ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_UTF8CHAR,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKF_SERIAL_SESSION,
    CKK_AES,
    CKM_AES_CBC_PAD,
    CKM_AES_KEY_GEN,
    CKM_AES_KEY_WRAP,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SHA256_RSA_PKCS,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_SESSION_COUNT,
    CKR_SESSION_READ_ONLY,
    CKR_SESSION_READ_ONLY_EXISTS,
    CKR_TOKEN_WRITE_PROTECTED,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    classify_negative_rv,
    get_pin_bytes,
    is_known_error,
    reject_or_classify,
    require_operational_aes_keygen,
    skip_if_token_write_protected,
    skip_unless_create_object_supported,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.access

# RO write-restriction guards classify 3-way via classify_negative_rv: a write
# accepted on a read-only session (CKR_OK) -> fail, the spec code
# CKR_SESSION_READ_ONLY -> pass, any other clean reject (CKR_ACTION_PROHIBITED,
# CKR_SESSION_READ_ONLY_EXISTS, template/write-protected pre-checks) -> xfail.

# Broader set including unsupported
_RO_OR_UNSUPPORTED_RVS = (
    CKR_SESSION_READ_ONLY,
    CKR_ACTION_PROHIBITED,
    CKR_SESSION_READ_ONLY_EXISTS,
    CKR_TOKEN_WRITE_PROTECTED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
)

_RO_MUTATION_REJECT_RVS = (
    CKR_SESSION_READ_ONLY,
    CKR_ACTION_PROHIBITED,
    CKR_SESSION_READ_ONLY_EXISTS,
    CKR_TOKEN_WRITE_PROTECTED,
    CKR_ATTRIBUTE_READ_ONLY,
)


def raw_open_session(raw: Any, slot_id: int, flags: int) -> int:
    """Open an extra RO/RW session needed by RO-session restriction tests."""
    try:
        return _raw_open_session(raw, slot_id, flags)
    except AssertionError as exc:
        if is_known_error(exc, (CKR_SESSION_COUNT,)):
            pytest.skip(
                "Cannot open additional RO session required by RO-session test: "
                f"{ckr_name(int(CKR_SESSION_COUNT))}"
            )
        raise


def _skip_unless_mechanism(rs: Any, name: str) -> None:
    if not rs.has_mechanism(name):
        pytest.skip(f"{name} not supported by module")


def _xfail_if_aes_keygen_rv(rv: int, context: str) -> None:
    if rv in AES_KEYGEN_RUNTIME_REJECT_RVS:
        classify(
            "not_operational",
            label=context,
            operation="C_GenerateKey",
            actual=rv,
            summary=f"{context}: {ckr_name(rv)}",
        )


def _gen_ro_setup_aes_key(
    rs: Any,
    sh: int,
    bits: int = 128,
    *,
    attrs: dict[Any, Any] | None = None,
    purpose: str = "RO-session setup",
) -> int:
    """Generate an AES setup key without hiding actual RO-session findings."""
    _skip_unless_mechanism(rs, "AES_KEY_GEN")
    require_operational_aes_keygen(rs)
    try:
        return _raw_gen_aes_key(rs.raw, sh, bits, attrs=attrs)
    except AssertionError as exc:
        _xfail_if_session_object_rejected_readonly(exc)
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            f"AES_KEY_GEN advertised but {purpose} key generation is not operational",
        )
    raise


def _gen_ro_setup_generic_key(
    rs: Any,
    sh: int,
    bits: int = 256,
    *,
    attrs: dict[Any, Any] | None = None,
) -> int:
    """Generate a generic-secret setup key for RO-session HMAC tests."""
    from pkcs11_check.raw.types_std import CKM_GENERIC_SECRET_KEY_GEN

    _skip_unless_mechanism(rs, "GENERIC_SECRET_KEY_GEN")
    try:
        return _raw_gen_aes_key(
            rs.raw,
            sh,
            bits,
            attrs=attrs,
            mechanism=CKM_GENERIC_SECRET_KEY_GEN,
        )
    except AssertionError as exc:
        _xfail_if_session_object_rejected_readonly(exc)
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            "GENERIC_SECRET_KEY_GEN advertised but RO-session setup key generation "
            "is not operational",
        )
    raise


def _gen_ro_setup_rsa_keypair(
    rs: Any,
    sh: int,
    bits: int = 2048,
    *,
    public_attrs: dict[Any, Any] | None = None,
    private_attrs: dict[Any, Any] | None = None,
    purpose: str = "RO-session setup",
) -> tuple[int, int]:
    """Generate an RSA setup keypair without hiding actual RO-session findings."""
    _skip_unless_mechanism(rs, "RSA_PKCS_KEY_PAIR_GEN")
    try:
        return _raw_gen_rsa_keypair(
            rs.raw,
            sh,
            bits,
            public_attrs=public_attrs,
            private_attrs=private_attrs,
        )
    except AssertionError as exc:
        _xfail_if_session_object_rejected_readonly(exc)
        xfail_if_known_ckr(
            exc,
            KEYPAIR_RUNTIME_REJECT_RVS,
            f"RSA_PKCS_KEY_PAIR_GEN advertised but {purpose} keypair generation is not operational",
        )
    raise


def _login_ro(raw: Any, sh: int, pin_bytes: bytes | None) -> None:
    """Login to a session, handling already-logged-in state."""
    if pin_bytes is None:
        return
    pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
    rv = raw.C_Login(sh, CKU_USER, pin_buf, len(pin_bytes))
    if rv not in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN, CKR_USER_TYPE_INVALID):
        expect_rv(rv, CKR_OK)


class TestROTokenObjectCreation:
    """RO sessions must reject creation of token-persistent objects."""

    def test_create_token_object_in_ro_fails(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_CreateObject with CKA_TOKEN=True in RO session must fail."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            from pkcs11_check.raw.pack import template_from_dict as _tfd

            tmpl = _tfd(
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_VALUE: os.urandom(16),
                    CKA_TOKEN: True,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                }
            )
            obj_h = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_CreateObject(ro_sh, tmpl.ptr, tmpl.count, byref(obj_h))
            classify_negative_rv(
                rv,
                (CKR_SESSION_READ_ONLY,),
                label="C_CreateObject with CKA_TOKEN=True on a read-only session",
            )
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_generate_key_token_true_in_ro_fails(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """generate_key with TOKEN=True in RO session must fail."""
        rs = p11_raw_session
        _skip_unless_mechanism(rs, "AES_KEY_GEN")
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            from pkcs11_check.raw.pack import attr_bool, attr_ulong, template

            tmpl = template(
                attr_ulong(CKA_VALUE_LEN, 16),
                attr_bool(CKA_TOKEN, True),
            )
            mech = mech_simple(CKM_AES_KEY_GEN)
            key_h = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_GenerateKey(ro_sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key_h))
            _xfail_if_aes_keygen_rv(
                rv,
                "AES_KEY_GEN advertised but RO restriction AES key generation is not operational",
            )
            classify_negative_rv(
                rv,
                (CKR_SESSION_READ_ONLY,),
                label="C_GenerateKey with CKA_TOKEN=True on a read-only session",
            )
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_generate_keypair_token_true_in_ro_fails(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """generate_keypair with TOKEN=True in RO session must fail."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            from pkcs11_check.raw.pack import attr_bool, attr_bytes, attr_ulong, template
            from pkcs11_check.raw.types_std import (
                CKA_MODULUS_BITS,
                CKA_PUBLIC_EXPONENT,
            )

            # Provide a complete RSA template so modules that validate
            # templates before checking session type still reach the RO check.
            # Some modules require CKA_PUBLIC_EXPONENT; without it, they return
            # CKR_TEMPLATE_INCOMPLETE before the session-type check.
            pub_tmpl = template(
                attr_ulong(CKA_MODULUS_BITS, 2048),
                attr_bytes(CKA_PUBLIC_EXPONENT, b"\x01\x00\x01"),
                attr_bool(CKA_TOKEN, True),
                attr_bool(CKA_VERIFY, True),
                attr_bool(CKA_ENCRYPT, True),
            )
            priv_tmpl = template(
                attr_bool(CKA_TOKEN, True),
                attr_bool(CKA_SIGN, True),
                attr_bool(CKA_DECRYPT, True),
            )
            mech = mech_simple(CKM_RSA_PKCS_KEY_PAIR_GEN)
            pub_h = CK_OBJECT_HANDLE(0)
            priv_h = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_GenerateKeyPair(
                ro_sh,
                mech.byref(),
                pub_tmpl.ptr,
                pub_tmpl.count,
                priv_tmpl.ptr,
                priv_tmpl.count,
                byref(pub_h),
                byref(priv_h),
            )
            # Spec-preferred reject on a read-only session is CKR_SESSION_READ_ONLY.
            # Some modules validate the template before checking session type and
            # reject earlier (CKR_TEMPLATE_INCOMPLETE / CKR_TOKEN_WRITE_PROTECTED) --
            # an honest non-spec reject -> xfail, not a finding.
            classify_negative_rv(
                rv,
                (CKR_SESSION_READ_ONLY,),
                label="C_GenerateKeyPair with CKA_TOKEN=True on a read-only session",
            )
        finally:
            close_session_quietly(rs.raw, ro_sh)


def _xfail_if_session_object_rejected_readonly(exc: AssertionError) -> None:
    """CKR_SESSION_READ_ONLY for a SESSION object is a deviation, not a finding
    to hard-fail: the spec defines that code for token-object writes in R/O
    sessions; session-scoped objects are legal there but some modules reject them
    anyway. The module still refused cleanly -> recorded xfail."""
    if is_known_error(exc, (CKR_SESSION_READ_ONLY,)):
        classify(
            "not_operational",
            label="RO-session:create-session-object",
            operation="C_CreateObject",
            summary=(
                f"session object rejected in RO session (deviation; "
                f"CKR_SESSION_READ_ONLY is specified for token objects): {exc}"
            ),
        )


class TestROSessionObjectsAllowed:
    """RO sessions must allow session-scoped (TOKEN=False) operations."""

    def test_create_session_object_in_ro_succeeds(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """C_CreateObject with CKA_TOKEN=False in RO session succeeds."""
        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            try:
                obj_h = import_secret_key(
                    rs.raw,
                    ro_sh,
                    CKK_AES,
                    os.urandom(16),
                    attrs={
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                    },
                )
            except AssertionError as exc:
                _xfail_if_session_object_rejected_readonly(exc)
                raise
            assert obj_h != 0
            destroy_quietly(rs.raw, ro_sh, obj_h)
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_generate_key_token_false_in_ro_succeeds(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """generate_key with TOKEN=False in RO session succeeds."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            key_h = _gen_ro_setup_aes_key(
                rs,
                ro_sh,
                128,
                attrs={CKA_LABEL: "ro-genkey-session"},
                purpose="RO-session TOKEN=False setup",
            )
            assert key_h != 0
            destroy_quietly(rs.raw, ro_sh, key_h)
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_generate_keypair_session_in_ro_succeeds(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """generate_keypair with store=False in RO session succeeds."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            pub_h, priv_h = _gen_ro_setup_rsa_keypair(
                rs,
                ro_sh,
                2048,
                purpose="RO-session TOKEN=False setup",
            )
            assert pub_h != 0
            assert priv_h != 0
            destroy_quietly(rs.raw, ro_sh, pub_h)
            destroy_quietly(rs.raw, ro_sh, priv_h)
        finally:
            close_session_quietly(rs.raw, ro_sh)


class TestROTokenObjectMutation:
    """RO sessions must reject mutation of token objects."""

    def test_destroy_token_object_in_ro_fails(self, p11_raw_session: Any) -> None:
        """C_DestroyObject of token object in RO session must fail."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        label = "ro-destroy-test"
        key_h = _gen_ro_setup_aes_key(
            rs,
            rs.sh,
            128,
            attrs={CKA_TOKEN: True, CKA_LABEL: label},
            purpose="RO-session token-object setup",
        )
        try:
            ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
            try:
                tmpl = template_from_dict({CKA_LABEL: label})
                found = find_objects(rs.raw, ro_sh, tmpl)
                assert len(found) >= 1, "Token object not found in RO session"
                rv = rs.raw.C_DestroyObject(ro_sh, found[0])
                classify_negative_rv(
                    rv,
                    (CKR_SESSION_READ_ONLY,),
                    label="C_DestroyObject of a token object on a read-only session",
                )
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_set_attribute_token_object_in_ro_fails(self, p11_raw_session: Any) -> None:
        """C_SetAttributeValue on token object in RO session must fail."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        label = "ro-setattr-test"
        key_h = _gen_ro_setup_aes_key(
            rs,
            rs.sh,
            128,
            attrs={
                CKA_TOKEN: True,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
                CKA_LABEL: label,
            },
        )
        try:
            ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
            try:
                tmpl = template_from_dict({CKA_LABEL: label})
                found = find_objects(rs.raw, ro_sh, tmpl)
                assert len(found) >= 1, "Token object not found in RO session"
                try:
                    set_attributes(rs.raw, ro_sh, found[0], {CKA_LABEL: "ro-setattr-changed"})
                    # Should not succeed
                    assert False, "C_SetAttributeValue succeeded on token object in RO session"
                except AssertionError as e:
                    if "C_SetAttributeValue succeeded" in str(e):
                        raise
                    if not is_known_error(e, _RO_MUTATION_REJECT_RVS):
                        raise
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_copy_token_object_in_ro_as_token_fails(self, p11_raw_session: Any) -> None:
        """C_CopyObject of token object to another token object in RO fails."""
        from pkcs11_check.raw.recipes import copy_object

        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        label = "ro-copy-test"
        key_h = _gen_ro_setup_aes_key(
            rs,
            rs.sh,
            128,
            attrs={
                CKA_TOKEN: True,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
                CKA_LABEL: label,
            },
        )
        try:
            ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
            try:
                tmpl = template_from_dict({CKA_LABEL: label})
                found = find_objects(rs.raw, ro_sh, tmpl)
                assert len(found) >= 1, "Token object not found in RO session"
                try:
                    copy_object(
                        rs.raw,
                        ro_sh,
                        found[0],
                        {CKA_LABEL: "ro-copy-result", CKA_TOKEN: True},
                    )
                    assert False, "C_CopyObject succeeded on token object in RO session"
                except AssertionError as e:
                    if "C_CopyObject succeeded" in str(e):
                        raise
                    if not is_known_error(e, _RO_MUTATION_REJECT_RVS):
                        raise
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestROCryptoOperations:
    """Crypto operations (no token writes) must work in RO sessions."""

    def test_digest_in_ro_session(self, p11_raw_session: Any, p11_config: Any) -> None:
        """SHA-256 digest works in RO session."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            digest = digest_single(rs.raw, ro_sh, CKM_SHA256, b"RO session restriction test data")
            assert len(digest) == 32
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_encrypt_decrypt_session_key_in_ro(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Encrypt/decrypt with session key works in RO session."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_PAD"):
            pytest.skip("CKM_AES_CBC_PAD not supported")
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            key_h = _gen_ro_setup_aes_key(
                rs,
                ro_sh,
                128,
                attrs={
                    CKA_TOKEN: False,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                },
            )
            iv = os.urandom(16)
            plaintext = b"RO encrypt test!"
            ct = encrypt_single(
                rs.raw,
                ro_sh,
                key_h,
                CKM_AES_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            pt = decrypt_single(
                rs.raw,
                ro_sh,
                key_h,
                CKM_AES_CBC_PAD,
                ct,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            assert pt == plaintext
            destroy_quietly(rs.raw, ro_sh, key_h)
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_sign_verify_session_key_in_ro(self, p11_raw_session: Any, p11_config: Any) -> None:
        """HMAC sign/verify with session key works in RO session."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            key_h = _gen_ro_setup_generic_key(
                rs,
                ro_sh,
                256,
                attrs={
                    CKA_TOKEN: False,
                    CKA_SIGN: True,
                    CKA_VERIFY: True,
                },
            )
            data = b"RO session HMAC test"
            sig = sign_single(rs.raw, ro_sh, key_h, CKM_SHA256_HMAC, data)
            assert len(sig) > 0
            result = verify_single(rs.raw, ro_sh, key_h, CKM_SHA256_HMAC, data, sig)
            assert result is True
            destroy_quietly(rs.raw, ro_sh, key_h)
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_verify_token_key_in_ro(self, p11_raw_session: Any) -> None:
        """Verification with a token key works in RO session."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        label = "ro-verify-rsa-test"
        pub_h, priv_h = _gen_ro_setup_rsa_keypair(
            rs,
            rs.sh,
            2048,
            public_attrs={CKA_TOKEN: True, CKA_LABEL: label},
            private_attrs={CKA_TOKEN: True, CKA_LABEL: label},
        )
        data = b"verify in read-only session"
        sig = sign_single(rs.raw, rs.sh, priv_h, CKM_SHA256_RSA_PKCS, data)
        try:
            ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
            try:
                tmpl = template_from_dict(
                    {
                        CKA_CLASS: CKO_PUBLIC_KEY,
                        CKA_LABEL: label,
                    }
                )
                found = find_objects(rs.raw, ro_sh, tmpl)
                assert len(found) >= 1, "Public key not found in RO session"
                result = verify_single(rs.raw, ro_sh, found[0], CKM_SHA256_RSA_PKCS, data, sig)
                assert result is True
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_h)
            destroy_quietly(rs.raw, rs.sh, priv_h)


class TestROExactCKR:
    """Verify the exact CKR code returned for RO restriction violations."""

    def test_create_token_object_returns_session_read_only(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Primary expected CKR is CKR_SESSION_READ_ONLY."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            from pkcs11_check.raw.pack import template_from_dict as _tfd

            tmpl = _tfd(
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_VALUE: os.urandom(16),
                    CKA_TOKEN: True,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                }
            )
            obj_h = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_CreateObject(ro_sh, tmpl.ptr, tmpl.count, byref(obj_h))
            classify_negative_rv(
                rv,
                (CKR_SESSION_READ_ONLY,),
                label="C_CreateObject with CKA_TOKEN=True on a read-only session "
                "(spec-preferred CKR_SESSION_READ_ONLY)",
            )
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_destroy_token_object_returns_session_read_only(self, p11_raw_session: Any) -> None:
        """Destroy of token object in RO returns CKR_SESSION_READ_ONLY."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        label = "ro-ckr-destroy-test"
        key_h = _gen_ro_setup_aes_key(
            rs,
            rs.sh,
            128,
            attrs={CKA_TOKEN: True, CKA_LABEL: label},
            purpose="RO-session exact-CKR token-object setup",
        )
        try:
            ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
            try:
                tmpl = template_from_dict({CKA_LABEL: label})
                found = find_objects(rs.raw, ro_sh, tmpl)
                assert len(found) >= 1, "Token object not found in RO session"
                rv = rs.raw.C_DestroyObject(ro_sh, found[0])
                classify_negative_rv(
                    rv,
                    (CKR_SESSION_READ_ONLY,),
                    label="C_DestroyObject of a token object on a read-only session "
                    "(spec-preferred CKR_SESSION_READ_ONLY)",
                )
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_generate_key_token_returns_session_read_only(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Key generation with TOKEN=True in RO returns CKR_SESSION_READ_ONLY."""
        rs = p11_raw_session
        _skip_unless_mechanism(rs, "AES_KEY_GEN")
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            from pkcs11_check.raw.pack import attr_bool, attr_ulong, template

            tmpl = template(
                attr_ulong(CKA_VALUE_LEN, 32),
                attr_bool(CKA_TOKEN, True),
            )
            mech = mech_simple(CKM_AES_KEY_GEN)
            key_h = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_GenerateKey(ro_sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key_h))
            _xfail_if_aes_keygen_rv(
                rv,
                "AES_KEY_GEN advertised but RO restriction exact-CKR key generation "
                "is not operational",
            )
            classify_negative_rv(
                rv,
                (CKR_SESSION_READ_ONLY,),
                label="C_GenerateKey with CKA_TOKEN=True on a read-only session "
                "(spec-preferred CKR_SESSION_READ_ONLY)",
            )
        finally:
            close_session_quietly(rs.raw, ro_sh)


class TestROWrapUnwrapRestrictions:
    """Unwrap creating TOKEN=True key in RO session must fail."""

    def test_unwrap_to_token_object_in_ro_fails(self, p11_raw_session: Any) -> None:
        """Unwrap with TOKEN=True template in RO session must fail."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        skip_unless_create_object_supported(rs)
        if not rs.has_mechanism("AES_KEY_WRAP"):
            if not rs.has_mechanism("AES_CBC_PAD"):
                pytest.skip("No AES wrap mechanism supported")

        # Create wrapping key and target in RW session
        wrapping_key_h = _gen_ro_setup_aes_key(
            rs,
            rs.sh,
            128,
            attrs={
                CKA_TOKEN: True,
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
                CKA_LABEL: "ro-unwrap-wrapkey",
            },
        )
        target_h = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            os.urandom(16),
            attrs={
                CKA_TOKEN: False,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            },
        )
        try:
            try:
                wrapped = wrap_key(rs.raw, rs.sh, wrapping_key_h, target_h, CKM_AES_KEY_WRAP)
            except AssertionError as exc:
                if not is_known_error(exc, _RO_OR_UNSUPPORTED_RVS):
                    raise
                pytest.skip("Module does not support wrap/unwrap")
            assert len(wrapped) > 0

            # Open RO session, find wrapping key, try unwrap with TOKEN=True
            ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
            try:
                tmpl = template_from_dict({CKA_LABEL: "ro-unwrap-wrapkey"})
                found = find_objects(rs.raw, ro_sh, tmpl)
                assert len(found) >= 1, "Wrapping key not found in RO session"
                try:
                    unwrap_key(
                        rs.raw,
                        ro_sh,
                        found[0],
                        wrapped,
                        CKM_AES_KEY_WRAP,
                        attrs={
                            CKA_TOKEN: True,
                            CKA_SENSITIVE: False,
                            CKA_EXTRACTABLE: True,
                        },
                    )
                    assert False, "Unwrap to TOKEN=True succeeded in RO session"
                except AssertionError as e:
                    if "Unwrap to TOKEN=True succeeded" in str(e):
                        raise  # crypto-correctness acceptance must hard-fail
                    reject_or_classify(
                        e,
                        _RO_OR_UNSUPPORTED_RVS,
                        label="C_UnwrapKey to TOKEN=True in RO session",
                    )
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, target_h)
            destroy_quietly(rs.raw, rs.sh, wrapping_key_h)

    def test_unwrap_to_session_object_in_ro_succeeds(self, p11_raw_session: Any) -> None:
        """Unwrap with TOKEN=False template in RO session succeeds."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        skip_unless_create_object_supported(rs)
        if not rs.has_mechanism("AES_KEY_WRAP"):
            if not rs.has_mechanism("AES_CBC_PAD"):
                pytest.skip("No AES wrap mechanism supported")

        wrapping_key_h = _gen_ro_setup_aes_key(
            rs,
            rs.sh,
            128,
            attrs={
                CKA_TOKEN: True,
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
                CKA_LABEL: "ro-unwrap-session-wrapkey",
            },
        )
        key_bytes = os.urandom(16)
        target_h = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_TOKEN: False,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            },
        )
        try:
            try:
                wrapped = wrap_key(rs.raw, rs.sh, wrapping_key_h, target_h, CKM_AES_KEY_WRAP)
            except AssertionError as exc:
                if not is_known_error(exc, _RO_OR_UNSUPPORTED_RVS):
                    raise
                pytest.skip("Module does not support wrap/unwrap")

            ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
            try:
                tmpl = template_from_dict({CKA_LABEL: "ro-unwrap-session-wrapkey"})
                found = find_objects(rs.raw, ro_sh, tmpl)
                assert len(found) >= 1, "Wrapping key not found in RO session"
                try:
                    unwrapped_h = unwrap_key(
                        rs.raw,
                        ro_sh,
                        found[0],
                        wrapped,
                        CKM_AES_KEY_WRAP,
                        attrs={
                            CKA_TOKEN: False,
                            CKA_SENSITIVE: False,
                            CKA_EXTRACTABLE: True,
                        },
                    )
                    assert unwrapped_h != 0
                    destroy_quietly(rs.raw, ro_sh, unwrapped_h)
                except AssertionError as exc:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "Module rejects C_UnwrapKey with TOKEN=False in RO session "
                        f"({exc}); PKCS#11 spec permits session-object "
                        "creation via C_UnwrapKey in RO sessions",
                        ComplianceLevel.NOT_RECOMMENDED,
                    )
                    xfail_as(
                        "not_operational",
                        label="RO-session:unwrap-session-object",
                        operation="C_UnwrapKey",
                        summary=f"Module overly restricts RO session unwrap ({exc})",
                    )
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, target_h)
            destroy_quietly(rs.raw, rs.sh, wrapping_key_h)
