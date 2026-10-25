"""QC3 copy-mutability and defaults contracts (#55).

Behavioral contracts for the copy-mutability provider nodes: every
production leg is driven through its real test method against a
scriptable fake token at the raw ``C_*`` layer. Fakes only; no provider
is loaded and no Docker is used.

Covered production behavior:

- ``TestCopyForbiddenMutation`` (QC3a, ``test_keymgmt.py``): copy with a
  different ``CKA_VALUE`` refuses cleanly (pass) or is accepted and then
  inspected (read back the copy's value) plus independently used
  (encrypt/decrypt round-trip; the copy must behave as the ORIGINAL
  material). Class/type overrides refuse or are inspected (read back
  class/type) plus independently used. Unchanged-value and empty
  templates are separate compatibility observations with no required RV
  equality. Sources set ``CKA_COPYABLE``; refused setup xfails.
- ``TestCopySetMutability`` (QC3b, ``security/test_api_security.py``),
  driven by the ``_copy_mutability`` table: each forbidden row is
  attempted via Copy and via Set. Clean refusal passes; success with
  ignored input xfails (ignored-input deviation, original RV
  preserved); actual forbidden mutation fails, proved by an independent
  functional leg (no-reauth use, formerly excluded mechanism, or
  independently verified material). The label control row must succeed
  where supported.
- ``TestExtractableDefaultThroughCopy`` (QC3c, ``security/test_tookan.py``):
  source omits ``CKA_EXTRACTABLE``; the actual default is read; a
  false-claiming source requires the copy to preserve
  non-extractability, with a passing extractable wrap control in the
  same run. A broken control skips the negative leg, never passes it.
"""

from __future__ import annotations

import ctypes
import hashlib
import sys
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, Skipped, XFailed
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap

from pkcs11_check import classification as C  # noqa: N812 - matches project convention
from pkcs11_check.raw.recipes import gen_aes_key, import_secret_key, wrap_key
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_ALLOWED_MECHANISMS,
    CKA_ALWAYS_AUTHENTICATE,
    CKA_BASE,
    CKA_CLASS,
    CKA_COPYABLE,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PRIME,
    CKA_PRIVATE,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_SUBPRIME,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_WRAP,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKK_RSA,
    CKM_AES_CBC,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP,
    CKM_DSA,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256_RSA_PKCS,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_KEY_UNEXTRACTABLE,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_SIGNATURE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TOKEN_NOT_PRESENT,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
    CKR_WRAPPED_KEY_INVALID,
    CKU_CONTEXT_SPECIFIC,
)
from pkcs11_check.testcases import test_dsa_complete as tdsa
from pkcs11_check.testcases import test_keymgmt as tkeymgmt
from pkcs11_check.testcases.security import test_api_security as tapi
from pkcs11_check.testcases.security import test_tookan as ttookan
from tests._skip_assert import assert_skips, assert_xfails

_OK = int(CKR_OK)
_SENSITIVE_RV = int(CKR_ATTRIBUTE_SENSITIVE)
_TYPE_INVALID = int(CKR_ATTRIBUTE_TYPE_INVALID)
_ATTR_READ_ONLY = int(CKR_ATTRIBUTE_READ_ONLY)
_ATTR_VALUE_INVALID = int(CKR_ATTRIBUTE_VALUE_INVALID)
_ACTION_PROHIBITED = int(CKR_ACTION_PROHIBITED)
_TEMPLATE_INCONSISTENT = int(CKR_TEMPLATE_INCONSISTENT)
_NOT_SUPPORTED = int(CKR_FUNCTION_NOT_SUPPORTED)
_DEVICE_ERROR = int(CKR_DEVICE_ERROR)
_FUNCTION_FAILED = int(CKR_FUNCTION_FAILED)
_MECHANISM_INVALID = int(CKR_MECHANISM_INVALID)
_KEY_UNEXTRACTABLE = int(CKR_KEY_UNEXTRACTABLE)
_KEY_NOT_PERMITTED = int(CKR_KEY_FUNCTION_NOT_PERMITTED)
_KEY_TYPE_INCONSISTENT = int(CKR_KEY_TYPE_INCONSISTENT)
_NOT_LOGGED_IN = int(CKR_USER_NOT_LOGGED_IN)
_TOKEN_NOT_PRESENT = int(CKR_TOKEN_NOT_PRESENT)
_WRAPPED_INVALID = int(CKR_WRAPPED_KEY_INVALID)
_USER_TYPE_INVALID = int(CKR_USER_TYPE_INVALID)
_CONTEXT_SPECIFIC = int(CKU_CONTEXT_SPECIFIC)
_OP_NOT_INITIALIZED = int(CKR_OPERATION_NOT_INITIALIZED)
_SIGNATURE_INVALID = int(CKR_SIGNATURE_INVALID)
_DSA_MECH = int(CKM_DSA)
_UNDEFINED_RV = 0x7FFFFFFF
_U64 = 0xFFFFFFFFFFFFFFFF

_ECB = int(CKM_AES_ECB)
_CBC = int(CKM_AES_CBC)

_ORIG_VALUE = bytes(range(0x10, 0x20))
_INJECTED_VALUE = bytes(range(0xA0, 0xB0))

_BOOL_ATTRS = frozenset(
    {
        int(CKA_SENSITIVE),
        int(CKA_EXTRACTABLE),
        int(CKA_ALWAYS_AUTHENTICATE),
        int(CKA_COPYABLE),
        int(CKA_ENCRYPT),
        int(CKA_DECRYPT),
        int(CKA_WRAP),
        int(CKA_UNWRAP),
        int(CKA_TOKEN),
        int(CKA_PRIVATE),
    }
)
_ULONG_ATTRS = frozenset({int(CKA_CLASS), int(CKA_KEY_TYPE), int(CKA_VALUE_LEN)})
_ARRAY_ATTRS = frozenset({int(CKA_ALLOWED_MECHANISMS)})


@pytest.fixture(autouse=True)
def _isolated() -> Any:
    C.clear()
    yield
    C.clear()


def _fill_ulong(out: Any, value: int) -> None:
    """Write an out-scalar passed as ``byref(ctypes_scalar)``."""
    ctypes.cast(out, ctypes.POINTER(ctypes.c_ulong)).contents.value = value


def _decode_template(tmpl: Any, count: int) -> dict[int, bytes]:
    """Decode a captured template ptr + count into {attr_type: raw bytes}."""
    decoded: dict[int, bytes] = {}
    for i in range(count):
        atype = int(tmpl[i].type)
        alen = int(tmpl[i].ulValueLen)
        addr = tmpl[i].pValue
        decoded[atype] = bytes(ctypes.string_at(addr, alen)) if addr and alen > 0 else b""
    return decoded


def _decode_bool(raw: bytes) -> bool:
    assert len(raw) == 1, raw
    return raw[0] != 0


def _decode_ulong(raw: bytes) -> int:
    return int.from_bytes(raw, sys.byteorder)


def _decode_array(raw: bytes) -> list[int]:
    width = ctypes.sizeof(ctypes.c_ulong)
    assert len(raw) % width == 0, raw
    return [int.from_bytes(raw[i : i + width], sys.byteorder) for i in range(0, len(raw), width)]


def _encode_value(attr: int, value: Any) -> bytes:
    if attr in _BOOL_ATTRS:
        return b"\x01" if value else b"\x00"
    if attr in _ULONG_ATTRS:
        return int(value).to_bytes(ctypes.sizeof(ctypes.c_ulong), sys.byteorder)
    if attr in _ARRAY_ATTRS:
        width = ctypes.sizeof(ctypes.c_ulong)
        return b"".join(int(v).to_bytes(width, sys.byteorder) for v in value)
    assert isinstance(value, bytes), (attr, value)
    return value


def _decode_mech(mech: Any) -> tuple[int, bytes]:
    ck = mech._obj
    addr = ck.pParameter
    length = int(ck.ulParameterLen)
    param = bytes(ctypes.string_at(addr, length)) if addr and length > 0 else b""
    return int(ck.mechanism), param


class _StoredObject:
    """One fake-token object: decoded attributes plus crypto behavior."""

    def __init__(self, attrs: dict[int, Any], *, role: str) -> None:
        self.attrs = attrs
        self.role = role  # "gen" (C_GenerateKey), "create" (C_CreateObject), "copy"
        self.destroyed = False
        self.crypto_value: bytes | None = None  # override for split-brain seeds


class _CopyFake:
    """Scriptable fake token for the QC3 copy-mutability legs.

    ``copy_mode``/``set_mode`` select uniform template handling: ``refuse``
    answers ``copy_refuse_rv``/``set_refuse_rv`` and creates nothing,
    ``ignore`` accepts while dropping every template change, ``apply``
    accepts while applying every template change. Readback and crypto
    legs then observe the stored object genuinely.
    """

    # noqa comments below: raw PKCS#11 entry-point names are mandated.

    def __init__(
        self,
        *,
        copy_mode: str = "refuse",
        copy_refuse_rv: int = _TEMPLATE_INCONSISTENT,
        set_mode: str = "refuse",
        set_refuse_rv: int = _ATTR_READ_ONLY,
        gen_script: list[int] | None = None,
        create_script: list[int] | None = None,
        copy_crypto_follows_source: bool = False,
        copy_crypto_value: bytes | None = None,
        gen_hide: set[int] | None = None,
        create_hide: set[int] | None = None,
        copy_hide: set[int] | None = None,
        extractable_default: bool | None = True,
        copy_force_extractable: bool | None = None,
        wrap_mode: str = "healthy",
        wrap_refuse_rv: int = _MECHANISM_INVALID,
        wrap_negative_refuse_rv: int | None = None,
        get_attr_script: list[int | None] | None = None,
        raw_readback: dict[tuple[str, int], bytes] | None = None,
        encrypt_rv: dict[tuple[str, int], int] | None = None,
        decrypt_rv: dict[tuple[str, int], int] | None = None,
        decrypt_corrupt: bool = False,
        ignore_allowed: set[str] | None = None,
        post_set_encrypt_rv: dict[tuple[str, int], int] | None = None,
        wrap_empty_for: set[str] | None = None,
        wrap_ignore_extractable: set[str] | None = None,
        unwrap_script: list[int | None] | None = None,
        unwrap_crypto_script: list[bytes | None] | None = None,
        keypair_script: list[int | None] | None = None,
        login_script: list[int | None] | None = None,
        sign_init_script: list[int | None] | None = None,
        sign_script: list[int | None] | None = None,
        sign_corrupt: bool = False,
        reauth_single_use: bool = True,
        require_explicit_private: bool = False,
        unwrap_default: bool = True,
        encrypt_constant: bytes | None = None,
        wrap_constant_for: set[str] | None = None,
        wrap_constant_blob: bytes | None = None,
        encrypt_output_for: dict[tuple[str, int], bytes] | None = None,
        decrypt_output_for: dict[tuple[str, int], bytes] | None = None,
        cbc_as_ecb_for: set[str] | None = None,
        dsa_verify_refuse_roles: set[str] | None = None,
    ) -> None:
        self._copy_mode = copy_mode
        self._copy_refuse_rv = copy_refuse_rv
        self._set_mode = set_mode
        self._set_refuse_rv = set_refuse_rv
        self._gen_script = list(gen_script or [])
        self._create_script = list(create_script or [])
        self._copy_crypto_follows_source = copy_crypto_follows_source
        self._copy_crypto_value = copy_crypto_value
        self._gen_hide = gen_hide or set()
        self._create_hide = create_hide or set()
        self._copy_hide = copy_hide or set()
        self._extractable_default = extractable_default
        self._copy_force_extractable = copy_force_extractable
        self._wrap_mode = wrap_mode
        self._wrap_refuse_rv = wrap_refuse_rv
        self._wrap_negative_refuse_rv = wrap_negative_refuse_rv
        self._get_attr_script = list(get_attr_script or [])
        self._raw_readback = dict(raw_readback or {})
        self.get_attr_calls = 0
        self._encrypt_rv = dict(encrypt_rv or {})
        self._decrypt_rv = dict(decrypt_rv or {})
        self._decrypt_corrupt = decrypt_corrupt
        self._ignore_allowed = set(ignore_allowed or ())
        self._post_set_encrypt_rv = dict(post_set_encrypt_rv or {})
        self._wrap_empty_for = set(wrap_empty_for or ())
        self._wrap_ignore_extractable = set(wrap_ignore_extractable or ())
        self._unwrap_script = list(unwrap_script or [])
        self._unwrap_crypto_script = list(unwrap_crypto_script or [])
        self._keypair_script = list(keypair_script or [])
        self._login_script = list(login_script or [])
        self._sign_init_script = list(sign_init_script or [])
        self._sign_script = list(sign_script or [])
        self._sign_corrupt = sign_corrupt
        self._reauth_single_use = reauth_single_use
        self._require_explicit_private = require_explicit_private
        self._unwrap_default = unwrap_default
        self._encrypt_constant = encrypt_constant
        self._wrap_constant_for = set(wrap_constant_for or ())
        self._wrap_constant_blob = wrap_constant_blob
        self._encrypt_output_for = dict(encrypt_output_for or {})
        self._decrypt_output_for = dict(decrypt_output_for or {})
        self._cbc_as_ecb_for = set(cbc_as_ecb_for or ())
        self._dsa_verify_refuse_roles = set(dsa_verify_refuse_roles or ())
        self._sign_mech: int | None = None
        self._verify_op: int | None = None
        self.op_sequence: list[str] = []
        self._context_authed = False
        self._rsa_key: Any = None
        self._rsa_keys: dict[int, Any] = {}
        self.keypair_calls: list[tuple[dict[int, bytes], dict[int, bytes]]] = []
        self.login_calls: list[int] = []
        self.sign_attempts = 0
        self._next_handle = 100
        self.objects: dict[int, _StoredObject] = {}
        self.created: list[int] = []
        self.destroyed: list[int] = []
        self.create_templates: list[dict[int, bytes]] = []
        self.copy_calls: list[dict[int, bytes]] = []
        self.set_calls: list[dict[int, bytes]] = []
        self._enc_op: tuple[int, bytes, bytes, str] | None = None
        self._dec_op: tuple[int, bytes, bytes, str] | None = None
        self._sign_op: int | None = None

    def _issue(self) -> int:
        handle = self._next_handle
        self._next_handle += 1
        return handle

    def _store(self, attrs: dict[int, Any], *, role: str) -> int:
        handle = self._issue()
        self.objects[handle] = _StoredObject(attrs, role=role)
        self.created.append(handle)
        return handle

    @staticmethod
    def _decoded_value(attr: int, raw: bytes) -> Any:
        if attr in _BOOL_ATTRS:
            return _decode_bool(raw)
        if attr in _ULONG_ATTRS:
            return _decode_ulong(raw)
        if attr in _ARRAY_ATTRS:
            return _decode_array(raw)
        return raw

    def _template_attrs(self, raw_attrs: dict[int, bytes]) -> dict[int, Any]:
        return {attr: self._decoded_value(attr, blob) for attr, blob in raw_attrs.items()}

    def C_GenerateKey(self, _sh: int, _mech: Any, tmpl: Any, count: int, out: Any) -> int:  # noqa: N802
        rv = self._gen_script.pop(0) if self._gen_script else _OK
        if rv != _OK:
            return rv
        raw_attrs = _decode_template(tmpl, count)
        self.create_templates.append(raw_attrs)
        attrs = self._template_attrs(raw_attrs)
        length = int(attrs.get(int(CKA_VALUE_LEN), 16))
        attrs[int(CKA_CLASS)] = int(CKO_SECRET_KEY)
        attrs.setdefault(int(CKA_KEY_TYPE), int(CKK_AES))
        attrs[int(CKA_VALUE)] = bytes([(self._next_handle + i) % 251 + 1 for i in range(length)])
        if int(CKA_EXTRACTABLE) not in attrs and self._extractable_default is not None:
            attrs[int(CKA_EXTRACTABLE)] = self._extractable_default
        handle = self._store(attrs, role="gen")
        _fill_ulong(out, handle)
        return _OK

    def C_CreateObject(self, _sh: int, tmpl: Any, count: int, out: Any) -> int:  # noqa: N802
        rv = self._create_script.pop(0) if self._create_script else _OK
        if rv != _OK:
            return rv
        raw_attrs = _decode_template(tmpl, count)
        self.create_templates.append(raw_attrs)
        attrs = self._template_attrs(raw_attrs)
        # F6a: imported keys omitting EXTRACTABLE still receive the provider
        # default (read back as the actual default, as with C_GenerateKey).
        if int(CKA_EXTRACTABLE) not in attrs and self._extractable_default is not None:
            # Only secret-key imports participate in the QC3 default premise;
            # other objects keep the omission as-is.
            if int(attrs.get(int(CKA_CLASS), int(CKO_SECRET_KEY))) == int(CKO_SECRET_KEY):
                attrs[int(CKA_EXTRACTABLE)] = self._extractable_default
        handle = self._store(attrs, role="create")
        _fill_ulong(out, handle)
        return _OK

    def C_CopyObject(  # noqa: N802
        self, _sh: int, handle: int, tmpl: Any, count: int, out: Any
    ) -> int:
        raw_attrs = _decode_template(tmpl, count) if count else {}
        self.copy_calls.append(raw_attrs)
        if self._copy_mode == "refuse":
            return self._copy_refuse_rv
        source = self.objects[int(handle)]
        assert not source.destroyed, "copy from destroyed handle"
        attrs = dict(source.attrs)
        if self._copy_mode == "apply":
            attrs.update(self._template_attrs(raw_attrs))
        if self._copy_force_extractable is not None:
            attrs[int(CKA_EXTRACTABLE)] = self._copy_force_extractable
        new_handle = self._store(attrs, role="copy")
        if self._copy_crypto_follows_source:
            stored_value = source.attrs.get(int(CKA_VALUE))
            assert isinstance(stored_value, bytes)
            self.objects[new_handle].crypto_value = stored_value
        if self._copy_crypto_value is not None:
            self.objects[new_handle].crypto_value = self._copy_crypto_value
        if int(handle) in self._rsa_keys:
            self._rsa_keys[new_handle] = self._rsa_keys[int(handle)]
        _fill_ulong(out, new_handle)
        return _OK

    def C_SetAttributeValue(self, _sh: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        raw_attrs = _decode_template(tmpl, count) if count else {}
        self.set_calls.append(raw_attrs)
        if self._set_mode == "refuse":
            return self._set_refuse_rv
        stored = self.objects[int(handle)]
        assert not stored.destroyed, "set on destroyed handle"
        if self._set_mode == "apply":
            stored.attrs.update(self._template_attrs(raw_attrs))
        return _OK

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        stored = self.objects.get(int(handle))
        if stored is not None:
            stored.destroyed = True
        self.destroyed.append(int(handle))
        return _OK

    def C_GenerateKeyPair(  # noqa: N802
        self,
        _sh: int,
        mech: Any,
        pub_tmpl: Any,
        pub_count: int,
        priv_tmpl: Any,
        priv_count: int,
        pub_out: Any,
        priv_out: Any,
    ) -> int:
        mech_id, _ = _decode_mech(mech)
        assert mech_id == int(CKM_RSA_PKCS_KEY_PAIR_GEN), mech_id
        if self._keypair_script:
            scripted = self._keypair_script.pop(0)
            if scripted is not None:
                return scripted
        pub_raw = _decode_template(pub_tmpl, pub_count) if pub_count else {}
        priv_raw = _decode_template(priv_tmpl, priv_count) if priv_count else {}
        self.keypair_calls.append((pub_raw, priv_raw))
        # F1: false-PRIVATE-default provider refuses an ALWAYS_AUTHENTICATE
        # template without explicit CKA_PRIVATE=True (spec: TRUE only when
        # CKA_PRIVATE also TRUE).
        if self._require_explicit_private:
            decoded_priv = self._template_attrs(priv_raw)
            if decoded_priv.get(int(CKA_PRIVATE)) is not True:
                return _TEMPLATE_INCONSISTENT
        if self._rsa_key is None:
            self._rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = self._rsa_key.public_key().public_numbers()
        modulus = int(numbers.n).to_bytes(256, "big")
        exp_len = (int(numbers.e).bit_length() + 7) // 8
        exponent = int(numbers.e).to_bytes(exp_len, "big")
        pub_attrs = {
            **self._template_attrs(pub_raw),
            int(CKA_CLASS): int(CKO_PUBLIC_KEY),
            int(CKA_KEY_TYPE): int(CKK_RSA),
            int(CKA_MODULUS): modulus,
            int(CKA_PUBLIC_EXPONENT): exponent,
        }
        priv_attrs = {
            **self._template_attrs(priv_raw),
            int(CKA_CLASS): int(CKO_PRIVATE_KEY),
            int(CKA_KEY_TYPE): int(CKK_RSA),
            int(CKA_PRIVATE): True,
            # F10: real RSA private objects carry the public components for
            # post-change signature verification from the target handle.
            int(CKA_MODULUS): modulus,
            int(CKA_PUBLIC_EXPONENT): exponent,
        }
        pub_handle = self._store(pub_attrs, role="create")
        priv_handle = self._store(priv_attrs, role="create")
        self._rsa_keys[priv_handle] = self._rsa_key
        _fill_ulong(pub_out, pub_handle)
        _fill_ulong(priv_out, priv_handle)
        return _OK

    def C_SignInit(self, _sh: int, mech: Any, handle: int) -> int:  # noqa: N802
        mech_id, _ = _decode_mech(mech)
        if mech_id == _DSA_MECH:
            # QC6b DSA public-copy legs: genuine DSA math over stored attrs.
            self._sign_mech = mech_id
            self._sign_op = int(handle)
            return _OK
        assert mech_id == int(CKM_SHA256_RSA_PKCS), mech_id
        self.op_sequence.append("init")
        if self._sign_init_script:
            scripted = self._sign_init_script.pop(0)
            if scripted is not None:
                if scripted == _OK:
                    self._sign_op = int(handle)
                    # F1/F9: a fresh Init starts a new op requiring fresh auth;
                    # a re-Init after login consumes the login (no lingering).
                    if self._reauth_single_use:
                        self._context_authed = False
                else:
                    self._sign_op = None
                return scripted
        self._sign_op = int(handle)
        # F1/F9: auth binds to the active op; a new Init clears any prior login.
        if self._reauth_single_use:
            self._context_authed = False
        return _OK

    def _dsa_params(self, stored: _StoredObject) -> tuple[int, int, int]:
        prime = int.from_bytes(stored.attrs[int(CKA_PRIME)], "big")
        subprime = int.from_bytes(stored.attrs[int(CKA_SUBPRIME)], "big")
        base = int.from_bytes(stored.attrs[int(CKA_BASE)], "big")
        return prime, subprime, base

    def _dsa_sign(self, stored: _StoredObject, data: bytes) -> bytes:
        prime, subprime, base = self._dsa_params(stored)
        private = int.from_bytes(stored.attrs[int(CKA_VALUE)], "big")
        z = int.from_bytes(data, "big")
        half = (subprime.bit_length() + 7) // 8
        nonce_src = hashlib.sha256(stored.attrs[int(CKA_VALUE)] + data).digest()
        nonce = int.from_bytes(nonce_src, "big") % (subprime - 1) + 1
        while True:
            r = pow(base, nonce, prime) % subprime
            if r:
                s = pow(nonce, -1, subprime) * (z + private * r) % subprime
                if s:
                    return r.to_bytes(half, "big") + s.to_bytes(half, "big")
            nonce = nonce % (subprime - 1) + 1

    def _dsa_verify(self, stored: _StoredObject, data: bytes, sig: bytes) -> bool:
        prime, subprime, base = self._dsa_params(stored)
        public_bytes = stored.crypto_value
        if public_bytes is None:
            raw_value = stored.attrs.get(int(CKA_VALUE))
            assert isinstance(raw_value, bytes), raw_value
            public_bytes = raw_value
        public = int.from_bytes(public_bytes, "big")
        half = (subprime.bit_length() + 7) // 8
        if len(sig) != 2 * half:
            return False
        r = int.from_bytes(sig[:half], "big")
        s = int.from_bytes(sig[half:], "big")
        if not (0 < r < subprime and 0 < s < subprime):
            return False
        z = int.from_bytes(data, "big")
        w = pow(s, -1, subprime)
        v = pow(base, z * w % subprime, prime) * pow(public, r * w % subprime, prime)
        return v % prime % subprime == r

    def C_VerifyInit(self, _sh: int, mech: Any, handle: int) -> int:  # noqa: N802
        mech_id, _ = _decode_mech(mech)
        assert mech_id == _DSA_MECH, mech_id
        stored = self.objects.get(int(handle))
        assert stored is not None, f"verify on unknown handle {handle}"
        if stored.role in self._dsa_verify_refuse_roles:
            return _FUNCTION_FAILED
        self._verify_op = int(handle)
        return _OK

    def C_Verify(  # noqa: N802
        self, _sh: int, in_buf: Any, in_len: int, sig_buf: Any, sig_len: int
    ) -> int:
        if self._verify_op is None:
            return _OP_NOT_INITIALIZED
        stored = self.objects.get(self._verify_op)
        assert stored is not None, f"verify on unknown handle {self._verify_op}"
        self._verify_op = None
        data = bytes(in_buf[:in_len])
        sig = bytes(sig_buf[:sig_len])
        return _OK if self._dsa_verify(stored, data, sig) else _SIGNATURE_INVALID

    def C_Sign(  # noqa: N802
        self, _sh: int, in_buf: Any, in_len: int, out: Any, out_len: Any
    ) -> int:
        if self._sign_mech == _DSA_MECH:
            if out is None:
                _fill_ulong(out_len, 64)
                return _OK
            if self._sign_op is None:
                return _OP_NOT_INITIALIZED
            stored = self.objects.get(self._sign_op)
            assert stored is not None, f"DSA sign on unknown handle {self._sign_op}"
            self._sign_op = None
            self._sign_mech = None
            payload = self._dsa_sign(stored, bytes(in_buf[:in_len]))
            ctypes.memmove(out, payload, len(payload))
            _fill_ulong(out_len, len(payload))
            return _OK
        self.sign_attempts += 1
        if out is None:
            _fill_ulong(out_len, 256)
            return _OK
        self.op_sequence.append("sign")
        if self._sign_script:
            scripted = self._sign_script.pop(0)
            if scripted is not None:
                # F1/F9: every Sign ends the op, scripted or not; a successful
                # Sign consumes single-use auth.
                self._sign_op = None
                if scripted == _OK and self._reauth_single_use:
                    self._context_authed = False
                return scripted
        # F1/F9: Sign without an active op is OPERATION_NOT_INITIALIZED (the
        # failed Sign that ended the prior op must be followed by a fresh Init).
        if self._sign_op is None:
            return _OP_NOT_INITIALIZED
        stored = self.objects.get(self._sign_op)
        assert stored is not None, f"sign on unknown handle {self._sign_op}"
        if stored.attrs.get(int(CKA_ALWAYS_AUTHENTICATE), False) is True:
            if not self._context_authed:
                # F1: a failed Sign ends the op.
                self._sign_op = None
                return _NOT_LOGGED_IN
        key = self._rsa_keys.get(self._sign_op)
        assert key is not None, f"sign on non-RSA handle {self._sign_op}"
        payload = key.sign(bytes(in_buf[:in_len]), padding.PKCS1v15(), hashes.SHA256())
        if self._sign_corrupt:
            payload = bytes([payload[0] ^ 0xFF]) + payload[1:]
        # F1/F9: a completed Sign ends the op and consumes single-use auth.
        self._sign_op = None
        if self._reauth_single_use:
            self._context_authed = False
        ctypes.memmove(out, payload, len(payload))
        _fill_ulong(out_len, len(payload))
        return _OK

    def C_Login(self, _sh: int, user_type: int, _pin: Any, _pin_len: int) -> int:  # noqa: N802
        self.login_calls.append(int(user_type))
        self.op_sequence.append("login")
        if self._login_script:
            scripted = self._login_script.pop(0)
            if scripted is not None:
                if scripted == _OK and int(user_type) == _CONTEXT_SPECIFIC:
                    self._context_authed = True
                return scripted
        if int(user_type) == _CONTEXT_SPECIFIC:
            # F1/F9: context login requires an active op (Init already done,
            # completion not yet attempted); otherwise OPERATION_NOT_INITIALIZED.
            if self._sign_op is None:
                return _OP_NOT_INITIALIZED
            self._context_authed = True
            return _OK
        return _USER_TYPE_INVALID

    def _hidden(self, stored: _StoredObject) -> set[int]:
        if stored.role == "gen":
            return self._gen_hide
        if stored.role == "create":
            return self._create_hide
        return self._copy_hide

    def C_GetAttributeValue(self, _sh: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        self.get_attr_calls += 1
        if self._get_attr_script:
            scripted = self._get_attr_script.pop(0)
            if scripted is not None:
                return scripted
        stored = self.objects.get(int(handle))
        assert stored is not None, f"read from unknown handle {handle}"
        hidden = self._hidden(stored)
        row_rvs: list[int] = []
        for i in range(count):
            attr = int(tmpl[i].type)
            cap = int(tmpl[i].ulValueLen)
            addr = tmpl[i].pValue
            blob = self._raw_readback.get((stored.role, attr))
            if blob is not None:
                if addr:
                    ctypes.memmove(addr, blob, min(len(blob), cap))
                tmpl[i].ulValueLen = len(blob)
                row_rvs.append(_OK)
                continue
            value = stored.attrs.get(attr)
            if attr in hidden or value is None:
                rv, length, fill = _TYPE_INVALID, _U64, None
            elif attr == int(CKA_VALUE) and (
                stored.attrs.get(int(CKA_SENSITIVE), False) is True
                or stored.attrs.get(int(CKA_EXTRACTABLE), True) is False
            ):
                rv, length, fill = _SENSITIVE_RV, _U64, None
            else:
                blob = _encode_value(attr, value)
                rv, length, fill = _OK, len(blob), blob
            if fill is not None and addr:
                ctypes.memmove(addr, fill, min(len(fill), cap))
            tmpl[i].ulValueLen = length
            row_rvs.append(rv)
        if _SENSITIVE_RV in row_rvs:
            return _SENSITIVE_RV
        if _TYPE_INVALID in row_rvs:
            return _TYPE_INVALID
        return _OK

    def _crypto_key(self, handle: int, mech_id: int, *, op: str) -> tuple[bytes, bytes] | int:
        """Return (key_bytes, iv_or_empty) or a refusal RV for a crypto op."""
        stored = self.objects.get(int(handle))
        assert stored is not None, f"crypto on unknown handle {handle}"
        if stored.attrs.get(int(CKA_ALWAYS_AUTHENTICATE), False) is True:
            return _NOT_LOGGED_IN
        allowed = stored.attrs.get(int(CKA_ALLOWED_MECHANISMS))
        if (
            allowed is not None
            and mech_id not in allowed
            and stored.role not in self._ignore_allowed
        ):
            return _KEY_NOT_PERMITTED
        if stored.attrs.get(int(CKA_CLASS), int(CKO_SECRET_KEY)) != int(CKO_SECRET_KEY):
            return _KEY_TYPE_INCONSISTENT
        if stored.attrs.get(int(CKA_KEY_TYPE), int(CKK_AES)) != int(CKK_AES):
            return _KEY_TYPE_INCONSISTENT
        flag = int(CKA_ENCRYPT) if op == "encrypt" else int(CKA_DECRYPT)
        if stored.attrs.get(flag, True) is False:
            return _KEY_NOT_PERMITTED
        value = stored.crypto_value
        if value is None:
            raw_value = stored.attrs.get(int(CKA_VALUE))
            assert isinstance(raw_value, bytes), raw_value
            value = raw_value
        return value, b""

    @staticmethod
    def _aes(mech_id: int, key: bytes, param: bytes, data: bytes, *, encrypt: bool) -> bytes:
        mode: Any
        if mech_id == _ECB:
            mode = modes.ECB()  # nosec B305
        else:
            assert mech_id == _CBC, mech_id
            assert len(param) == 16, param
            mode = modes.CBC(param)
        cipher = Cipher(algorithms.AES(key), mode)
        worker = cipher.encryptor() if encrypt else cipher.decryptor()
        return worker.update(data) + worker.finalize()

    def C_EncryptInit(self, _sh: int, mech: Any, handle: int) -> int:  # noqa: N802
        mech_id, param = _decode_mech(mech)
        assert mech_id in (_ECB, _CBC), mech_id
        stored = self.objects.get(int(handle))
        if stored is not None and self.set_calls:
            post_set = self._post_set_encrypt_rv.get((stored.role, mech_id))
            if post_set is not None:
                return post_set
        scripted = self._encrypt_rv.get((stored.role, mech_id)) if stored is not None else None
        if scripted is not None:
            return scripted
        outcome = self._crypto_key(int(handle), mech_id, op="encrypt")
        if isinstance(outcome, int):
            return outcome
        key_bytes, _ = outcome
        assert stored is not None, f"crypto on unknown handle {handle}"
        self._enc_op = (mech_id, key_bytes, param, stored.role)
        return _OK

    def C_Encrypt(  # noqa: N802
        self, _sh: int, in_buf: Any, in_len: int, out: Any, out_len: Any
    ) -> int:
        assert self._enc_op is not None, "C_Encrypt without C_EncryptInit"
        mech_id, key_bytes, param, role = self._enc_op
        override = self._encrypt_output_for.get((role, mech_id))
        # F6: broken-constant Encrypt returns the same output for every key
        # (reference-mode false-validation counterexample; oracle ignores it).
        if override is not None:
            # G5: scripted successful output (exact bytes, including malformed
            # lengths); the size probe and the real call agree.
            payload = override
        elif self._encrypt_constant is not None and mech_id == _ECB:
            payload = self._encrypt_constant
        elif mech_id == _CBC and role in self._cbc_as_ecb_for:
            # G4: broken dispatch -- a CBC request answered with genuine ECB
            # output under the same key, still returning CKR_OK.
            payload = self._aes(_ECB, key_bytes, param, bytes(in_buf[:in_len]), encrypt=True)
        else:
            payload = self._aes(mech_id, key_bytes, param, bytes(in_buf[:in_len]), encrypt=True)
        if out is None:
            _fill_ulong(out_len, len(payload))
            return _OK
        self._enc_op = None
        ctypes.memmove(out, payload, len(payload))
        _fill_ulong(out_len, len(payload))
        return _OK

    def C_DecryptInit(self, _sh: int, mech: Any, handle: int) -> int:  # noqa: N802
        mech_id, param = _decode_mech(mech)
        assert mech_id in (_ECB, _CBC), mech_id
        stored = self.objects.get(int(handle))
        scripted = self._decrypt_rv.get((stored.role, mech_id)) if stored is not None else None
        if scripted is not None:
            return scripted
        outcome = self._crypto_key(int(handle), mech_id, op="decrypt")
        if isinstance(outcome, int):
            return outcome
        key_bytes, _ = outcome
        assert stored is not None, f"crypto on unknown handle {handle}"
        self._dec_op = (mech_id, key_bytes, param, stored.role)
        return _OK

    def C_Decrypt(  # noqa: N802
        self, _sh: int, in_buf: Any, in_len: int, out: Any, out_len: Any
    ) -> int:
        assert self._dec_op is not None, "C_Decrypt without C_DecryptInit"
        mech_id, key_bytes, param, role = self._dec_op
        override = self._decrypt_output_for.get((role, mech_id))
        if override is not None:
            # G5: scripted successful output (exact bytes, including malformed
            # lengths); the size probe and the real call agree.
            payload = override
        else:
            payload = self._aes(mech_id, key_bytes, param, bytes(in_buf[:in_len]), encrypt=False)
            if self._decrypt_corrupt:
                payload = bytes(b ^ 0xFF for b in payload)
        if out is None:
            _fill_ulong(out_len, len(payload))
            return _OK
        self._dec_op = None
        ctypes.memmove(out, payload, len(payload))
        _fill_ulong(out_len, len(payload))
        return _OK

    def C_WrapKey(  # noqa: N802
        self, _sh: int, mech: Any, wrapping: int, target: int, out: Any, out_len: Any
    ) -> int:
        mech_id, _ = _decode_mech(mech)
        assert mech_id == int(CKM_AES_KEY_WRAP), mech_id
        if self._wrap_mode == "refuse_all":
            return self._wrap_refuse_rv
        wrapper = self.objects.get(int(wrapping))
        stored = self.objects.get(int(target))
        assert wrapper is not None and stored is not None, (wrapping, target)
        if self._wrap_negative_refuse_rv is not None and stored.role == "copy":
            return self._wrap_negative_refuse_rv
        if wrapper.attrs.get(int(CKA_WRAP), True) is False:
            return _KEY_NOT_PERMITTED
        if stored.attrs.get(int(CKA_EXTRACTABLE), True) is False:
            if stored.role in self._wrap_ignore_extractable:
                pass
            else:
                return _KEY_UNEXTRACTABLE
        if stored.role in self._wrap_empty_for:
            payload = b""
        elif stored.role in self._wrap_constant_for and self._wrap_constant_blob is not None:
            # F6: unrelated-constant wrap (genuine KW of unrelated material).
            payload = self._wrap_constant_blob
        else:
            kek = wrapper.attrs.get(int(CKA_VALUE))
            material = stored.attrs.get(int(CKA_VALUE))
            assert isinstance(kek, bytes) and isinstance(material, bytes), (kek, material)
            payload = aes_key_wrap(kek, material)
        if out is None:
            _fill_ulong(out_len, len(payload))
            return _OK
        ctypes.memmove(out, payload, len(payload))
        _fill_ulong(out_len, len(payload))
        return _OK

    def C_UnwrapKey(  # noqa: N802
        self,
        _sh: int,
        mech: Any,
        unwrapping: int,
        in_buf: Any,
        in_len: int,
        tmpl: Any,
        count: int,
        out: Any,
    ) -> int:
        mech_id, _ = _decode_mech(mech)
        assert mech_id == int(CKM_AES_KEY_WRAP), mech_id
        if self._unwrap_script:
            scripted = self._unwrap_script.pop(0)
            if scripted is not None:
                return scripted
        wrapper = self.objects.get(int(unwrapping))
        assert wrapper is not None, unwrapping
        # F5/F9: enforce CKA_UNWRAP permission (false-default providers treat
        # an omitted UNWRAP as False and refuse with KEY_FUNCTION_NOT_PERMITTED).
        unwrap_allowed = wrapper.attrs.get(int(CKA_UNWRAP), self._unwrap_default)
        if unwrap_allowed is False:
            return _KEY_NOT_PERMITTED
        kek = wrapper.attrs.get(int(CKA_VALUE))
        assert isinstance(kek, bytes), kek
        try:
            material = aes_key_unwrap(kek, bytes(in_buf[:in_len]))
        except InvalidUnwrap:
            return _WRAPPED_INVALID
        raw_attrs = _decode_template(tmpl, count) if count else {}
        handle = self._store(self._template_attrs(raw_attrs), role="unwrap")
        crypto_override = self._unwrap_crypto_script.pop(0) if self._unwrap_crypto_script else None
        if crypto_override is not None:
            self.objects[handle].crypto_value = crypto_override
        else:
            self.objects[handle].crypto_value = material
        self.objects[handle].attrs[int(CKA_VALUE)] = material
        _fill_ulong(out, handle)
        return _OK


_ALL_MECHS = {"AES_ECB", "AES_CBC", "AES_KEY_GEN", "AES_KEY_WRAP"}


def _rs(fake: _CopyFake, *, mechs: set[str] | None = None) -> SimpleNamespace:
    advertised = _ALL_MECHS if mechs is None else mechs
    return SimpleNamespace(raw=fake, sh=1, has_mechanism=lambda name: name in advertised)


def _qc3a_material(rs: SimpleNamespace) -> None:
    cls = getattr(tkeymgmt, "TestCopyForbiddenMutation")
    cls().test_copy_different_value_material_ignored_or_refused(rs)


def _qc3a_keytype(rs: SimpleNamespace) -> None:
    cls = getattr(tkeymgmt, "TestCopyForbiddenMutation")
    cls().test_copy_key_type_override_ignored_or_refused(rs)


def _qc3a_class(rs: SimpleNamespace) -> None:
    cls = getattr(tkeymgmt, "TestCopyForbiddenMutation")
    cls().test_copy_class_override_ignored_or_refused(rs)


def _qc3a_unchanged(rs: SimpleNamespace) -> None:
    cls = getattr(tkeymgmt, "TestCopyForbiddenMutation")
    cls().test_copy_unchanged_value_template_observation(rs)


def _qc3a_empty(rs: SimpleNamespace) -> None:
    cls = getattr(tkeymgmt, "TestCopyForbiddenMutation")
    cls().test_copy_empty_template_observation(rs)


_PIN_CONFIG = SimpleNamespace(pin=SimpleNamespace(get_secret_value=lambda: "1234"))
_NO_PIN_CONFIG = SimpleNamespace(pin=None)
_RSA_MECHS = {"RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS"}


def _qc3b(op: str, probe: str, rs: SimpleNamespace, config: Any = _PIN_CONFIG) -> None:
    cls = getattr(tapi, "TestCopySetMutability")
    method = getattr(cls(), f"test_{op}_table_change")
    method(rs, config, probe)


def _qc3c(rs: SimpleNamespace) -> None:
    cls = getattr(ttookan, "TestExtractableDefaultThroughCopy")
    cls().test_copy_preserves_omitted_extractable_default(rs)


def _run_must_fail(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
    """Run ``fn`` requiring ``pytest.fail``; an xfail or skip here is a false pass."""
    try:
        with pytest.raises(Failed) as exc_info:
            fn(*args, **kwargs)
    except Skipped as exc:
        pytest.fail(f"expected fail, got skip instead: {exc}")
    assert not isinstance(exc_info.value, XFailed), f"expected fail, got xfail: {exc_info.value}"


def _terminal_record() -> Any:
    records = C.get_records()
    assert records, "expected at least one classification record"
    return records[-1]


def _assert_fail_record(reason: str, kind: str | None) -> Any:
    record = _terminal_record()
    assert record.reason == reason, record.summary
    assert record.kind == kind, record.summary
    assert record.outcome == "fail", record.summary
    return record


def _assert_xfail_record(reason: str) -> Any:
    record = _terminal_record()
    assert record.reason == reason, record.summary
    assert record.outcome == "xfail", record.summary
    return record


def _assert_pass_records() -> None:
    records = C.get_records()
    assert records, "expected pass evidence records"
    assert [record.outcome for record in records] == ["pass"] * len(records), [
        record.summary for record in records
    ]


def _assert_cleaned_up(fake: _CopyFake) -> None:
    assert fake.created, "fake created no objects at all"
    assert set(fake.destroyed) >= set(fake.created), (fake.created, fake.destroyed)


def _copy_template_of(fake: _CopyFake, index: int = 0) -> dict[int, Any]:
    return {
        attr: _CopyFake._decoded_value(attr, blob) for attr, blob in fake.copy_calls[index].items()
    }


def _set_template_of(fake: _CopyFake, index: int = 0) -> dict[int, Any]:
    return {
        attr: _CopyFake._decoded_value(attr, blob) for attr, blob in fake.set_calls[index].items()
    }


def _mutability_table() -> Any:
    """Import the QC3b data table (absent on BASE)."""
    from pkcs11_check.testcases import _copy_mutability as table_mod

    return table_mod


def test_table_has_required_rows_with_rules_and_citations() -> None:
    """Every mandated attribute has a copy rule, a set rule, and a citation."""
    mod = _mutability_table()
    rows = {row.key: row for row in mod.COPY_MUTABILITY_TABLE}
    assert set(rows) >= {
        "value",
        "allowed_mechanisms",
        "always_authenticate",
        "sensitive",
        "extractable",
        "label",
    }
    for key, row in rows.items():
        assert row.copy_rule in ("forbidden", "no_downgrade", "allowed"), key
        assert row.set_rule in ("forbidden", "no_downgrade", "allowed"), key
        assert row.citation, key
        assert row.attr_name.startswith("CKA_"), key
    assert rows["value"].copy_rule == "forbidden"
    assert rows["value"].set_rule == "forbidden"
    assert rows["label"].copy_rule == "allowed"
    assert rows["label"].set_rule == "allowed"
    assert rows["extractable"].copy_rule == "no_downgrade"


def test_table_pins_allowed_mechanisms_both_directions_under_413() -> None:
    """The Table 26 row forbids tightening AND widening under §4.1.3."""
    mod = _mutability_table()
    row = mod.row_by_key("allowed_mechanisms")
    assert row.copy_rule == "forbidden"
    assert row.set_rule == "forbidden"
    assert "4.1.3" in row.citation
    assert "Table 26" in row.citation
    assert "footnote 8" in row.citation


def test_table_probes_all_cite_a_row() -> None:
    """Every provider probe cites its table row; widen/narrow share one row."""
    mod = _mutability_table()
    assert set(mod.TABLE_PROBES) == {
        "value",
        "allowed_mechanisms_widen",
        "allowed_mechanisms_narrow",
        "always_authenticate",
        "sensitive_downgrade",
        "extractable_escalate",
        "label_control",
    }
    for probe in mod.TABLE_PROBES:
        mod.row_by_key(mod.PROBE_ROW[probe])
    assert (
        mod.PROBE_ROW["allowed_mechanisms_widen"]
        == mod.PROBE_ROW["allowed_mechanisms_narrow"]
        == "allowed_mechanisms"
    )
    with pytest.raises(KeyError):
        mod.row_by_key("no_such_row")


_COPY_REFUSE_RVS = [
    _ACTION_PROHIBITED,
    _ATTR_READ_ONLY,
    _ATTR_VALUE_INVALID,
    _TEMPLATE_INCONSISTENT,
]
_SET_REFUSE_RVS = [
    _ATTR_READ_ONLY,
    _ACTION_PROHIBITED,
    _ATTR_VALUE_INVALID,
    _TEMPLATE_INCONSISTENT,
]


def test_qc3a_material_refusals_pass() -> None:
    """Each plausible copy refusal of a different-value template passes."""
    for rv in _COPY_REFUSE_RVS:
        fake = _CopyFake(copy_refuse_rv=rv)
        _qc3a_material(_rs(fake))
        record = _terminal_record()
        assert record.reason == "sanctioned_refusal", record.summary
        assert record.outcome == "pass", record.summary
        assert record.actual_ckr == ckr_name(rv), record.summary
        _assert_pass_records()
        _assert_cleaned_up(fake)
        C.clear()


def test_qc3a_material_ignored_xfails() -> None:
    """Accepted-but-ignored material change xfails as an ignored-input deviation."""
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc3a_material, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert "ignored" in (record.summary or "").lower(), record.summary
    assert (record.detail or {}).get("disposition") == "ignored-input", record.detail
    assert _copy_template_of(fake)[int(CKA_VALUE)] == _INJECTED_VALUE


def test_qc3a_material_mutated_fails() -> None:
    """Readback-changed plus behaves-as-injected material fails."""
    fake = _CopyFake(copy_mode="apply")
    _run_must_fail(_qc3a_material, _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert (record.detail or {}).get("behaves_as_injected") is True, record.detail


def test_qc3a_material_use_proves_despite_hidden_readback() -> None:
    """Behaves-as-injected fails even when the copy value readback is hidden."""
    fake = _CopyFake(copy_mode="apply", copy_hide={int(CKA_VALUE)})
    _run_must_fail(_qc3a_material, _rs(fake))
    _assert_fail_record("self_contradiction", "policy")


def test_qc3a_material_readback_only_divergence_is_unproved() -> None:
    """I3 re-verdict: readback-injected but behaves-as-original leaves mutation unproved."""
    fake = _CopyFake(copy_mode="apply", copy_crypto_follows_source=True)
    assert_xfails(_qc3a_material, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("behaves_as_original") is True, record.detail
    assert (record.detail or {}).get("behaves_as_injected") is False, record.detail
    assert (record.detail or {}).get("readback_matches_injected") is True, record.detail
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


def test_qc3a_material_behaves_as_neither_fails() -> None:
    """I3+I5 re-verdict: copy diverging from both oracles is a crypto wrong_result FAIL."""
    fake = _CopyFake(copy_mode="apply", copy_crypto_value=bytes(range(0x30, 0x40)))
    _run_must_fail(_qc3a_material, _rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert (record.detail or {}).get("behaves_as_original") is False, record.detail
    assert (record.detail or {}).get("behaves_as_injected") is False, record.detail


def test_qc3a_material_setup_refusal_xfails_with_rv() -> None:
    """A refused copyable source setup xfails with the refusal RV preserved."""
    fake = _CopyFake(create_script=[_ATTR_VALUE_INVALID])
    assert_xfails(_qc3a_material, _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_ATTRIBUTE_VALUE_INVALID", record.actual_ckr


def test_qc3a_source_sets_copyable() -> None:
    """Sources request CKA_COPYABLE so the copy premise is explicit."""
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc3a_material, _rs(fake))
    C.clear()
    assert fake.create_templates, "source creation was never attempted"
    decoded = {
        attr: _CopyFake._decoded_value(attr, blob)
        for attr, blob in fake.create_templates[0].items()
    }
    assert decoded.get(int(CKA_COPYABLE)) is True, decoded


def test_qc3a_keytype_refusal_passes() -> None:
    """Refusing a key-type override passes."""
    fake = _CopyFake(copy_refuse_rv=_TEMPLATE_INCONSISTENT)
    _qc3a_keytype(_rs(fake))
    _assert_pass_records()
    assert _copy_template_of(fake)[int(CKA_KEY_TYPE)] == int(CKK_GENERIC_SECRET)
    _assert_cleaned_up(fake)


def test_qc3a_keytype_ignored_xfails() -> None:
    """Accepted-but-ignored key-type override xfails."""
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc3a_keytype, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert "ignored" in (record.summary or "").lower(), record.summary


def test_qc3a_keytype_applied_fails() -> None:
    """An applied key-type override fails via readback and refused use."""
    fake = _CopyFake(copy_mode="apply")
    _run_must_fail(_qc3a_keytype, _rs(fake))
    _assert_fail_record("self_contradiction", "policy")


def test_qc3a_class_refusal_passes() -> None:
    """Refusing a class override passes."""
    fake = _CopyFake(copy_refuse_rv=_ATTR_READ_ONLY)
    _qc3a_class(_rs(fake))
    _assert_pass_records()
    assert _copy_template_of(fake)[int(CKA_CLASS)] == int(CKO_PRIVATE_KEY)
    _assert_cleaned_up(fake)


def test_qc3a_class_ignored_xfails() -> None:
    """Accepted-but-ignored class override xfails."""
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc3a_class, _rs(fake))
    _assert_xfail_record("honest_deviation")


def test_qc3a_class_applied_fails() -> None:
    """An applied class override fails."""
    fake = _CopyFake(copy_mode="apply")
    _run_must_fail(_qc3a_class, _rs(fake))
    _assert_fail_record("self_contradiction", "policy")


def test_qc3a_unchanged_template_accepted_passes() -> None:
    """An accepted unchanged-value copy is a passing compatibility observation."""
    fake = _CopyFake(copy_mode="apply")
    _qc3a_unchanged(_rs(fake))
    assert C.get_records() == [], "observation notes emit no classifications"
    _assert_cleaned_up(fake)
    assert _copy_template_of(fake)[int(CKA_VALUE)] == _ORIG_VALUE


def test_qc3a_empty_template_refused_passes() -> None:
    """A refused empty-template copy is a passing compatibility observation."""
    fake = _CopyFake(copy_refuse_rv=_TEMPLATE_INCONSISTENT)
    _qc3a_empty(_rs(fake))
    assert C.get_records() == [], "observation notes emit no classifications"
    _assert_cleaned_up(fake)
    assert fake.copy_calls[0] == {}, fake.copy_calls


def test_qc3a_observations_allow_rv_inequality() -> None:
    """Unchanged-value and empty-template RVs are never cross-compared.

    The two observation legs diverge (one accepts, the other refuses) and
    both still pass; either direction of divergence is accepted.
    """
    accept_unchanged = _CopyFake(copy_mode="apply")
    _qc3a_unchanged(_rs(accept_unchanged))
    assert C.get_records() == []
    C.clear()
    refuse_empty = _CopyFake(copy_refuse_rv=_TEMPLATE_INCONSISTENT)
    _qc3a_empty(_rs(refuse_empty))
    assert C.get_records() == []
    C.clear()
    refuse_unchanged = _CopyFake(copy_refuse_rv=_ACTION_PROHIBITED)
    _qc3a_unchanged(_rs(refuse_unchanged))
    assert C.get_records() == []
    C.clear()
    accept_empty = _CopyFake(copy_mode="apply")
    _qc3a_empty(_rs(accept_empty))
    assert C.get_records() == []


def test_qc3b_copy_refusals_pass() -> None:
    """Each plausible copy refusal of a forbidden change passes."""
    for rv in _COPY_REFUSE_RVS:
        fake = _CopyFake(copy_refuse_rv=rv)
        _qc3b("copy", "value", _rs(fake))
        record = _terminal_record()
        assert record.reason == "sanctioned_refusal", record.summary
        assert record.outcome == "pass", record.summary
        assert record.actual_ckr == ckr_name(rv), record.summary
        _assert_pass_records()
        _assert_cleaned_up(fake)
        C.clear()


def test_qc3b_set_refusals_pass() -> None:
    """Each plausible set refusal of a forbidden change passes."""
    for rv in _SET_REFUSE_RVS:
        fake = _CopyFake(set_refuse_rv=rv)
        _qc3b("set", "value", _rs(fake))
        record = _terminal_record()
        assert record.reason == "sanctioned_refusal", record.summary
        assert record.outcome == "pass", record.summary
        assert record.actual_ckr == ckr_name(rv), record.summary
        _assert_pass_records()
        _assert_cleaned_up(fake)
        C.clear()


def test_qc3b_copy_unsupported_skips() -> None:
    """An unsupported C_CopyObject skips instead of passing or failing."""
    fake = _CopyFake(copy_refuse_rv=_NOT_SUPPORTED)
    assert_skips(_qc3b, "copy", "value", _rs(fake))


def test_qc3b_set_unsupported_skips() -> None:
    """An unsupported C_SetAttributeValue skips instead of passing or failing."""
    fake = _CopyFake(set_refuse_rv=_NOT_SUPPORTED)
    assert_skips(_qc3b, "set", "value", _rs(fake))


def test_qc3b_implausible_clean_refusal_xfails() -> None:
    """A clean but implausible refusal RV xfails with the RV preserved."""
    fake = _CopyFake(copy_refuse_rv=_FUNCTION_FAILED)
    assert_xfails(_qc3b, "copy", "value", _rs(fake))
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == "CKR_FUNCTION_FAILED", record.actual_ckr


def test_qc3b_undefined_refusal_rv_fails() -> None:
    """An undefined refusal RV fails the return-value contract."""
    fake = _CopyFake(copy_refuse_rv=_UNDEFINED_RV)
    _run_must_fail(_qc3b, "copy", "value", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_value_copy_ignored_xfails() -> None:
    """Accepted-but-ignored different-value copy xfails as ignored-input."""
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc3b, "copy", "value", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert "ignored" in (record.summary or "").lower(), record.summary
    assert (record.detail or {}).get("disposition") == "ignored-input", record.detail
    assert "4.1.3" not in (record.spec_ref or ""), record.spec_ref  # cites its own row
    assert _copy_template_of(fake)[int(CKA_VALUE)] == _INJECTED_VALUE


def test_qc3b_value_copy_mutated_fails() -> None:
    """Accepted-and-applied different-value copy fails on proved material change."""
    fake = _CopyFake(copy_mode="apply")
    _run_must_fail(_qc3b, "copy", "value", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert (record.detail or {}).get("behaves_as_injected") is True, record.detail


def test_qc3b_value_set_ignored_xfails() -> None:
    """Accepted-but-ignored different-value set xfails as ignored-input."""
    fake = _CopyFake(set_mode="ignore")
    assert_xfails(_qc3b, "set", "value", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "ignored-input", record.detail
    assert _set_template_of(fake)[int(CKA_VALUE)] == _INJECTED_VALUE


def test_qc3b_value_set_mutated_fails() -> None:
    """Accepted-and-applied different-value set fails on proved material change."""
    fake = _CopyFake(set_mode="apply")
    _run_must_fail(_qc3b, "set", "value", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert (record.detail or {}).get("behaves_as_injected") is True, record.detail


def test_qc3b_widen_copy_ignored_xfails() -> None:
    """Accepted-but-ignored widening xfails; the excluded mechanism stays refused."""
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert "ignored" in (record.summary or "").lower(), record.summary
    assert "4.1.3" in (record.spec_ref or ""), record.spec_ref
    assert sorted(_copy_template_of(fake)[int(CKA_ALLOWED_MECHANISMS)]) == [_ECB, _CBC]


def test_qc3b_widen_copy_effective_fails() -> None:
    """A widening that completes the formerly excluded mechanism fails."""
    fake = _CopyFake(copy_mode="apply")
    _run_must_fail(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "4.1.3" in (record.spec_ref or ""), record.spec_ref


def test_qc3b_widen_set_ignored_xfails() -> None:
    """Accepted-but-ignored widening via Set xfails."""
    fake = _CopyFake(set_mode="ignore")
    assert_xfails(_qc3b, "set", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert "4.1.3" in (record.spec_ref or ""), record.spec_ref
    assert sorted(_set_template_of(fake)[int(CKA_ALLOWED_MECHANISMS)]) == [_ECB, _CBC]


def test_qc3b_widen_set_effective_fails() -> None:
    """A widening via Set that completes the excluded mechanism fails."""
    fake = _CopyFake(set_mode="apply")
    _run_must_fail(_qc3b, "set", "allowed_mechanisms_widen", _rs(fake))
    _assert_fail_record("self_contradiction", "policy")


def test_qc3b_narrow_copy_ignored_xfails() -> None:
    """Accepted-but-ignored narrowing xfails; the excluded mechanism still works."""
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert "ignored" in (record.summary or "").lower(), record.summary
    assert "4.1.3" in (record.spec_ref or ""), record.spec_ref
    assert _copy_template_of(fake)[int(CKA_ALLOWED_MECHANISMS)] == [_ECB]


def test_qc3b_narrow_copy_effective_fails() -> None:
    """A narrowing that actually excludes the mechanism fails."""
    fake = _CopyFake(copy_mode="apply")
    _run_must_fail(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "4.1.3" in (record.spec_ref or ""), record.spec_ref


def test_qc3b_narrow_set_ignored_xfails() -> None:
    """Accepted-but-ignored narrowing via Set xfails."""
    fake = _CopyFake(set_mode="ignore")
    assert_xfails(_qc3b, "set", "allowed_mechanisms_narrow", _rs(fake))
    _assert_xfail_record("honest_deviation")


def test_qc3b_narrow_set_effective_fails() -> None:
    """A narrowing via Set that actually excludes the mechanism fails."""
    fake = _CopyFake(set_mode="apply")
    _run_must_fail(_qc3b, "set", "allowed_mechanisms_narrow", _rs(fake))
    _assert_fail_record("self_contradiction", "policy")


def test_qc3b_always_auth_copy_ignored_xfails() -> None:
    """I1 re-verdict: RSA rebuild — an ignored change still demands C_Sign re-auth."""
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc3b, "copy", "always_authenticate", _rs(fake, mechs=_RSA_MECHS))
    record = _assert_xfail_record("honest_deviation")
    assert "ignored" in (record.summary or "").lower(), record.summary
    assert (record.detail or {}).get("disposition") == "ignored-input", record.detail
    assert _copy_template_of(fake)[int(CKA_ALWAYS_AUTHENTICATE)] is False
    assert len(fake.keypair_calls) == 1, "source must be a generated RSA keypair"
    assert fake.login_calls == [_CONTEXT_SPECIFIC], "premise control must context-login"


def test_qc3b_always_auth_copy_bypass_fails() -> None:
    """I1 re-verdict: RSA rebuild — C_Sign without re-auth after the applied change fails."""
    fake = _CopyFake(copy_mode="apply")
    _run_must_fail(_qc3b, "copy", "always_authenticate", _rs(fake, mechs=_RSA_MECHS))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "C_Sign" in (record.summary or ""), record.summary
    assert (record.detail or {}).get("no_reauth_use_completed") is True, record.detail
    assert (record.detail or {}).get("sig_len") == 256, record.detail
    assert len(fake.keypair_calls) == 1, "source must be a generated RSA keypair"


def test_qc3b_always_auth_set_ignored_xfails() -> None:
    """I1 re-verdict: RSA rebuild — an ignored Set change still demands C_Sign re-auth."""
    fake = _CopyFake(set_mode="ignore")
    assert_xfails(_qc3b, "set", "always_authenticate", _rs(fake, mechs=_RSA_MECHS))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "ignored-input", record.detail
    assert _set_template_of(fake)[int(CKA_ALWAYS_AUTHENTICATE)] is False
    assert len(fake.keypair_calls) == 1, "source must be a generated RSA keypair"


def test_qc3b_always_auth_set_bypass_fails() -> None:
    """I1 re-verdict: RSA rebuild — C_Sign without re-auth after the applied Set fails."""
    fake = _CopyFake(set_mode="apply")
    _run_must_fail(_qc3b, "set", "always_authenticate", _rs(fake, mechs=_RSA_MECHS))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "C_Sign" in (record.summary or ""), record.summary
    assert (record.detail or {}).get("no_reauth_use_completed") is True, record.detail


def test_qc3b_sensitive_copy_ignored_xfails() -> None:
    """Accepted-but-ignored SENSITIVE downgrade keeps the value sealed."""
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert "ignored" in (record.summary or "").lower(), record.summary
    assert _copy_template_of(fake)[int(CKA_SENSITIVE)] is False


def test_qc3b_sensitive_copy_exposed_fails() -> None:
    """A downgrade that exposes verified material fails."""
    fake = _CopyFake(copy_mode="apply")
    _run_must_fail(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    _assert_fail_record("self_contradiction", "policy")


def test_qc3b_sensitive_set_ignored_xfails() -> None:
    """Accepted-but-ignored SENSITIVE downgrade via Set xfails."""
    fake = _CopyFake(set_mode="ignore")
    assert_xfails(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    _assert_xfail_record("honest_deviation")


def test_qc3b_sensitive_set_exposed_fails() -> None:
    """A Set downgrade that exposes verified material fails."""
    fake = _CopyFake(set_mode="apply")
    _run_must_fail(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    _assert_fail_record("self_contradiction", "policy")


def test_qc3b_extractable_copy_ignored_xfails() -> None:
    """Accepted-but-ignored EXTRACTABLE escalation keeps wrap refused."""
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert "ignored" in (record.summary or "").lower(), record.summary
    assert _copy_template_of(fake)[int(CKA_EXTRACTABLE)] is True


def test_qc3b_extractable_copy_wrappable_fails() -> None:
    """An escalation that makes the copy wrappable fails."""
    fake = _CopyFake(copy_mode="apply")
    _run_must_fail(_qc3b, "copy", "extractable_escalate", _rs(fake))
    _assert_fail_record("self_contradiction", "policy")


def test_qc3b_extractable_set_ignored_xfails() -> None:
    """Accepted-but-ignored EXTRACTABLE escalation via Set xfails."""
    fake = _CopyFake(set_mode="ignore")
    assert_xfails(_qc3b, "set", "extractable_escalate", _rs(fake))
    _assert_xfail_record("honest_deviation")


def test_qc3b_extractable_set_wrappable_fails() -> None:
    """A Set escalation that makes the key wrappable fails."""
    fake = _CopyFake(set_mode="apply")
    _run_must_fail(_qc3b, "set", "extractable_escalate", _rs(fake))
    _assert_fail_record("self_contradiction", "policy")


def test_qc3b_label_copy_applied_passes() -> None:
    """The label control copy succeeds and reads back the new label."""
    fake = _CopyFake(copy_mode="apply")
    _qc3b("copy", "label_control", _rs(fake))
    assert C.get_records() == [], "the applied control records nothing"
    _assert_cleaned_up(fake)


def test_qc3b_label_copy_refused_xfails() -> None:
    """A refused legal label change xfails with the RV preserved."""
    fake = _CopyFake(copy_refuse_rv=_ACTION_PROHIBITED)
    assert_xfails(_qc3b, "copy", "label_control", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == "CKR_ACTION_PROHIBITED", record.actual_ckr


def test_qc3b_label_copy_ignored_xfails() -> None:
    """An accepted-but-ignored label change xfails as ignored-input."""
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc3b, "copy", "label_control", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert "ignored" in (record.summary or "").lower(), record.summary
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


def test_qc3b_label_set_applied_passes() -> None:
    """The label control set succeeds and reads back the new label."""
    fake = _CopyFake(set_mode="apply")
    _qc3b("set", "label_control", _rs(fake))
    assert C.get_records() == [], "the applied control records nothing"
    _assert_cleaned_up(fake)


def test_qc3b_label_set_refused_xfails() -> None:
    """A refused legal label set xfails with the RV preserved."""
    fake = _CopyFake(set_refuse_rv=_ATTR_READ_ONLY)
    assert_xfails(_qc3b, "set", "label_control", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == "CKR_ATTRIBUTE_READ_ONLY", record.actual_ckr


def test_qc3c_default_false_preserved_wrap_refused_passes() -> None:
    """False default preserved through copy with a refused wrap passes."""
    fake = _CopyFake(copy_mode="apply", extractable_default=False)
    _qc3c(_rs(fake))
    records = C.get_records()
    assert [r.outcome for r in records] == ["pass"], [r.reason for r in records]
    assert records[-1].reason == "sanctioned_refusal", records[-1].summary
    _assert_cleaned_up(fake)


def test_qc3c_default_false_copy_true_wrap_exposes_fails() -> None:
    """A copy that escalates the false default and exposes material fails."""
    fake = _CopyFake(copy_mode="apply", extractable_default=False, copy_force_extractable=True)
    _run_must_fail(_qc3c, _rs(fake))
    _assert_fail_record("self_contradiction", "policy")


def test_qc3c_default_false_copy_true_wrap_refused_xfails() -> None:
    """Copy claims extractable but wrap still refused: visible contradiction."""
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        copy_force_extractable=True,
        wrap_negative_refuse_rv=_KEY_UNEXTRACTABLE,
    )
    assert_xfails(_qc3c, _rs(fake))
    _assert_xfail_record("honest_deviation")


def test_qc3c_default_false_unreadable_copy_claim_passes() -> None:
    """I14: the unreadable-copy leg reports its xfail record even as it returns.

    The real report hook converts the intermediate not_operational record
    into an xfail outcome; the contract pins that reported outcome sequence.
    """
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        copy_hide={int(CKA_EXTRACTABLE)},
    )
    _qc3c(_rs(fake))
    records = C.get_records()
    assert [r.outcome for r in records] == ["xfail", "pass"], [
        (r.reason, r.outcome) for r in records
    ]
    assert records[0].reason == "not_operational", records[0].summary
    assert records[-1].reason == "sanctioned_refusal", records[-1].summary
    _assert_cleaned_up(fake)


def test_qc3c_default_true_copy_preserved_passes() -> None:
    """A true default preserved through copy passes without wrap legs."""
    fake = _CopyFake(copy_mode="apply", extractable_default=True)
    _qc3c(_rs(fake))
    assert C.get_records() == [], "the true-default note path records nothing"
    _assert_cleaned_up(fake)


def test_qc3c_default_true_copy_tightened_passes() -> None:
    """True-to-False tightening through an omitting copy is legal and passes."""
    fake = _CopyFake(copy_mode="apply", extractable_default=True, copy_force_extractable=False)
    _qc3c(_rs(fake))
    assert C.get_records() == [], "the true-default note path records nothing"
    _assert_cleaned_up(fake)


def test_qc3c_source_unreadable_claims_true_passes() -> None:
    """I14: the unreadable-source leg reports its xfail record even as it returns.

    The real report hook converts the intermediate not_operational record
    into an xfail outcome; the contract pins that reported outcome.
    """
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=None,
        gen_hide={int(CKA_EXTRACTABLE)},
    )
    _qc3c(_rs(fake))
    records = C.get_records()
    assert [r.outcome for r in records] == ["xfail", "xfail"], [
        (r.reason, r.outcome) for r in records
    ]
    assert [r.reason for r in records] == ["not_operational", "not_operational"]
    _assert_cleaned_up(fake)


def test_qc3c_control_broken_skips_negative() -> None:
    """A broken wrap control skips the negative leg instead of passing it."""
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        wrap_mode="refuse_all",
        wrap_refuse_rv=_MECHANISM_INVALID,
    )
    assert_skips(_qc3c, _rs(fake))


def test_qc3c_empty_copy_refused_xfails() -> None:
    """A refused empty-template copy voids the copy premise visibly."""
    fake = _CopyFake(copy_refuse_rv=_ACTION_PROHIBITED, extractable_default=False)
    assert_xfails(_qc3c, _rs(fake))
    _assert_xfail_record("not_operational")


def test_qc3c_empty_copy_unsupported_skips() -> None:
    """An unsupported C_CopyObject skips the default-preservation leg."""
    fake = _CopyFake(copy_refuse_rv=_NOT_SUPPORTED, extractable_default=False)
    assert_skips(_qc3c, _rs(fake))


def test_tookan_copy_unsupported_xfails_not_operational() -> None:
    """The pre-existing quiet pass on unsupported copy is a visible xfail."""
    fake = _CopyFake(copy_refuse_rv=_NOT_SUPPORTED)
    assert_xfails(ttookan.TestSensitivePreservation().test_sensitive_preserved_on_copy, _rs(fake))
    _assert_xfail_record("not_operational")


# --- Fix round 1 (QC3 review NEEDS-REPAIR) ---


def test_table_extractable_rule_is_directional_on_both_operations() -> None:
    """I2: EXTRACTABLE tightening is legal via copy AND set; only escalation is forbidden."""
    mod = _mutability_table()
    row = mod.row_by_key("extractable")
    assert row.copy_rule == "no_downgrade", row
    assert row.set_rule == "no_downgrade", row
    assert "Table 13" in row.citation, row.citation
    assert "footnote 8" in row.citation, row.citation
    assert "footnote 12" in row.citation, row.citation
    assert "True->False" in row.citation, row.citation
    assert "False->True" in row.citation, row.citation


def test_table_sensitive_rule_cites_freeze_once_true() -> None:
    """I2: SENSITIVE cites Table 13 footnotes 8 + 11 (frozen once TRUE)."""
    mod = _mutability_table()
    row = mod.row_by_key("sensitive")
    assert row.copy_rule == "no_downgrade", row
    assert row.set_rule == "no_downgrade", row
    assert "Table 13" in row.citation, row.citation
    assert "footnote 8" in row.citation, row.citation
    assert "footnote 11" in row.citation, row.citation


def test_table_always_auth_cites_table29_and_fn8_absence() -> None:
    """I2: ALWAYS_AUTHENTICATE immutability follows from lacking footnote 8 (Table 29)."""
    mod = _mutability_table()
    row = mod.row_by_key("always_authenticate")
    assert row.copy_rule == "forbidden", row
    assert row.set_rule == "forbidden", row
    assert "Table 29" in row.citation, row.citation
    assert "footnote 8" in row.citation, row.citation


def test_table_label_cites_table19_and_copy_path() -> None:
    """I2: the LABEL control cites Table 19 (only post-creation mutable attr) + §4.1.3."""
    mod = _mutability_table()
    row = mod.row_by_key("label")
    assert "Table 19" in row.citation, row.citation
    assert "4.1.3" in row.citation, row.citation


def test_accepted_ignored_record_carries_established_accept() -> None:
    """M1: accepted-but-ignored records carry actual=CKR_OK (the established accept)."""
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc3b, "copy", "value", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


def test_accepted_mutated_record_carries_established_accept() -> None:
    """M1: accepted-and-mutated FAIL records carry actual=CKR_OK; legs stay in detail."""
    fake = _CopyFake(copy_mode="apply")
    _run_must_fail(_qc3b, "copy", "value", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    assert (record.detail or {}).get("behaves_as_injected") is True, record.detail


_VENDOR_RV = 0x80000042


def test_rv_validity_standard_returns_none() -> None:
    """I13: a standard RV passes the validity gate (caller proceeds on the normal path)."""
    mod = _mutability_table()
    assert mod.classify_rv_validity_or_none(_FUNCTION_FAILED, label="t", operation="C_X") is None


def test_rv_validity_vendor_xfails_nonspec_reject() -> None:
    """I13: a vendor-defined RV becomes a visible alternate-refusal xfail, never a FAIL."""
    mod = _mutability_table()
    assert_xfails(mod.classify_rv_validity_or_none, _VENDOR_RV, label="t", operation="C_X")
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == ckr_name(_VENDOR_RV), record.actual_ckr


def test_rv_validity_undefined_fails_metadata() -> None:
    """I13: an undefined RV fails the return-value contract (metadata self-contradiction)."""
    mod = _mutability_table()
    _run_must_fail(mod.classify_rv_validity_or_none, _UNDEFINED_RV, label="t", operation="C_X")
    _assert_fail_record("self_contradiction", "metadata")


def test_label_control_vendor_refusal_xfails_not_fails() -> None:
    """I13: a vendor-defined control refusal is an alternate xfail, not an undefined-FAIL."""
    fake = _CopyFake(copy_refuse_rv=_VENDOR_RV)
    assert_xfails(_qc3b, "copy", "label_control", _rs(fake))
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == ckr_name(_VENDOR_RV), record.actual_ckr


def test_label_control_undefined_refusal_fails() -> None:
    """I13: an undefined control refusal fails the return-value contract."""
    fake = _CopyFake(copy_refuse_rv=_UNDEFINED_RV)
    _run_must_fail(_qc3b, "copy", "label_control", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_shape_bool_accepts_genuine_bool() -> None:
    """I12: a genuine CK_BBOOL readback passes shape validation unchanged."""
    mod = _mutability_table()
    assert mod.validate_qc3_shape(True, "bool", attr_name="CKA_X", label="t", premise=False) is True


def test_shape_bool_rejects_wrong_length_bytes() -> None:
    """I12: a 2-byte false-looking flag is malformed (unproved), never a False."""
    mod = _mutability_table()
    assert_xfails(
        mod.validate_qc3_shape,
        b"\x00\x00",
        "bool",
        attr_name="CKA_X",
        label="t",
        premise=False,
    )
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


def test_shape_ulong_rejects_garbage_bytes() -> None:
    """I12/F11: a non-int class/type readback is malformed (type+length evidence, redacted)."""
    mod = _mutability_table()
    assert mod.validate_qc3_shape(1, "ulong", attr_name="CKA_X", label="t", premise=False) == 1
    assert_xfails(
        mod.validate_qc3_shape, b"\x07", "ulong", attr_name="CKA_X", label="t", premise=False
    )
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("actual_type") == "bytes", record.detail
    assert (record.detail or {}).get("actual_len") == 1, record.detail
    assert "malformed_repr" not in (record.detail or {}), record.detail


def test_shape_mech_list_requires_list_of_int() -> None:
    """I12: mechanism-list readbacks must be list-of-int (decoder remainder-drop aside)."""
    mod = _mutability_table()
    assert mod.validate_qc3_shape(
        [1, 2], "mech_list", attr_name="CKA_X", label="t", premise=False
    ) == [1, 2]
    assert_xfails(
        mod.validate_qc3_shape, "nope", "mech_list", attr_name="CKA_X", label="t", premise=False
    )
    _assert_xfail_record("honest_deviation")


def test_shape_value_requires_bytes_of_expected_length() -> None:
    """I12: value readbacks must be bytes of the expected length; length-only evidence."""
    mod = _mutability_table()
    assert (
        mod.validate_qc3_shape(
            b"0123456789abcdef",
            "value",
            attr_name="CKA_VALUE",
            label="t",
            premise=False,
            expected_len=16,
        )
        == b"0123456789abcdef"
    )
    assert_xfails(
        mod.validate_qc3_shape,
        b"short",
        "value",
        attr_name="CKA_VALUE",
        label="t",
        premise=False,
        expected_len=16,
    )
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("value_len") == 5, record.detail
    assert "malformed_repr" not in (record.detail or {}), record.detail


def test_shape_premise_malformed_voids_without_accept() -> None:
    """I12: premise-leg malformation voids (not_operational) and claims no accept."""
    mod = _mutability_table()
    assert_xfails(
        mod.validate_qc3_shape, b"\x00\x00", "bool", attr_name="CKA_X", label="t", premise=True
    )
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr is None, record.actual_ckr


def test_shape_unknown_shape_is_programmer_error() -> None:
    """I12: an unknown shape name fails loud (no silent pass-through)."""
    mod = _mutability_table()
    with pytest.raises(ValueError, match="unknown QC3 shape"):
        mod.validate_qc3_shape(True, "nope", attr_name="CKA_X", label="t", premise=False)


def test_qc3a_material_readback_device_error_xfails_unproved() -> None:
    """I12: a DEVICE_ERROR material readback is an unproved xfail, never unclassified."""
    fake = _CopyFake(copy_mode="ignore", get_attr_script=[_DEVICE_ERROR])
    assert_xfails(_qc3a_material, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("readback_rv") == "CKR_DEVICE_ERROR", record.detail
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


def test_qc3a_material_readback_undefined_rv_fails() -> None:
    """I12/I13: an undefined-RV readback refusal fails the return-value contract."""
    fake = _CopyFake(copy_mode="ignore", get_attr_script=[_UNDEFINED_RV])
    _run_must_fail(_qc3a_material, _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3a_material_readback_vendor_rv_xfails() -> None:
    """I12/I13: a vendor-RV readback refusal is a visible alternate xfail."""
    fake = _CopyFake(copy_mode="ignore", get_attr_script=[_VENDOR_RV])
    assert_xfails(_qc3a_material, _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3a_identity_garbage_key_type_xfails_unproved() -> None:
    """I12: a 1-byte garbage key-type readback is malformed (unproved), never a crash."""
    fake = _CopyFake(copy_mode="apply", raw_readback={("copy", int(CKA_KEY_TYPE)): b"\x07"})
    assert_xfails(_qc3a_keytype, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3c_copy_wrong_length_flag_xfails_unproved() -> None:
    """I12/F11: a 2-byte EXTRACTABLE readback voids with redacted type+length evidence."""
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        raw_readback={("copy", int(CKA_EXTRACTABLE)): b"\x00\x00"},
    )
    assert_xfails(_qc3c, _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert (record.detail or {}).get("actual_type") == "bytes", record.detail
    assert (record.detail or {}).get("actual_len") == 2, record.detail
    assert "malformed_repr" not in (record.detail or {}), record.detail


_GARBAGE_VALUE = bytes(range(0x30, 0x40))


def test_qc3a_material_garbage_readback_behaves_original_is_unproved() -> None:
    """I3: garbage readback with behaves-as-original leaves mutation unproved (length-only)."""
    fake = _CopyFake(copy_mode="ignore", raw_readback={("copy", int(CKA_VALUE)): _GARBAGE_VALUE})
    assert_xfails(_qc3a_material, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("behaves_as_original") is True, record.detail
    assert (record.detail or {}).get("readback_matches_original") is False, record.detail
    assert (record.detail or {}).get("readback_matches_injected") is False, record.detail
    assert (record.detail or {}).get("readback_len") == 16, record.detail


def test_qc3a_material_incoherent_roundtrip_fails_wrong_result() -> None:
    """I5: encrypt OK + decrypt OK + wrong plaintext is a crypto wrong_result FAIL."""
    fake = _CopyFake(copy_mode="ignore", decrypt_corrupt=True)
    _run_must_fail(_qc3a_material, _rs(fake))
    _assert_fail_record("wrong_result", "crypto")


def test_qc3b_value_copy_incoherent_roundtrip_fails_wrong_result() -> None:
    """I5 (shared helper): the QC3b copy value leg reports the same crypto FAIL."""
    fake = _CopyFake(copy_mode="ignore", decrypt_corrupt=True)
    _run_must_fail(_qc3b, "copy", "value", _rs(fake))
    _assert_fail_record("wrong_result", "crypto")


def test_qc3b_value_set_incoherent_roundtrip_fails_wrong_result() -> None:
    """I5 (shared helper): the QC3b set value leg reports the same crypto FAIL."""
    fake = _CopyFake(set_mode="ignore", decrypt_corrupt=True)
    _run_must_fail(_qc3b, "set", "value", _rs(fake))
    _assert_fail_record("wrong_result", "crypto")


def test_qc3a_material_behaves_injected_despite_original_readback_fails() -> None:
    """I3 guard: injected behavior governs (mutated FAIL) even when readback claims original."""
    fake = _CopyFake(copy_mode="apply", raw_readback={("copy", int(CKA_VALUE)): _ORIG_VALUE})
    _run_must_fail(_qc3a_material, _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert (record.detail or {}).get("behaves_as_injected") is True, record.detail
    assert (record.detail or {}).get("readback_matches_original") is True, record.detail


def test_qc3a_material_use_refused_is_unproved() -> None:
    """I3/I13: refused post-accept use leaves the effect unproved with the RV preserved."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _ECB): _DEVICE_ERROR})
    assert_xfails(_qc3a_material, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("use_rv") == "CKR_DEVICE_ERROR", record.detail
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


def test_qc3a_material_decrypt_refused_is_unproved() -> None:
    """I3/I13: refused post-accept decrypt leaves the effect unproved with the RV preserved."""
    fake = _CopyFake(copy_mode="ignore", decrypt_rv={("copy", _ECB): _DEVICE_ERROR})
    assert_xfails(_qc3a_material, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("use_rv") == "CKR_DEVICE_ERROR", record.detail
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


def test_qc3a_material_use_vendor_refusal_xfails_nonspec() -> None:
    """I13: a vendor-RV use refusal on the copy is a visible alternate xfail."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _ECB): _VENDOR_RV})
    assert_xfails(_qc3a_material, _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3a_material_decrypt_undefined_refusal_fails() -> None:
    """I13: an undefined-RV decrypt refusal fails the return-value contract."""
    fake = _CopyFake(copy_mode="ignore", decrypt_rv={("copy", _ECB): _UNDEFINED_RV})
    _run_must_fail(_qc3a_material, _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def _ulong_bytes(value: int) -> bytes:
    return int(value).to_bytes(ctypes.sizeof(ctypes.c_ulong), sys.byteorder)


def test_qc3a_keytype_use_refused_with_unchanged_identity_is_unproved() -> None:
    """I4: use-refusal with an unchanged identity never proves an applied override."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _ECB): _KEY_NOT_PERMITTED})
    assert_xfails(_qc3a_keytype, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("identity_changed") is False, record.detail
    assert (record.detail or {}).get("use_rv") == "CKR_KEY_FUNCTION_NOT_PERMITTED", record.detail
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


def test_qc3a_keytype_use_transient_refusal_is_unproved() -> None:
    """I4: a transient use-refusal with unchanged identity is likewise unproved."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _ECB): _DEVICE_ERROR})
    assert_xfails(_qc3a_keytype, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3a_class_use_refused_with_unchanged_identity_is_unproved() -> None:
    """I4: the class leg applies the same refusal-does-not-prove rule."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _ECB): _KEY_NOT_PERMITTED})
    assert_xfails(_qc3a_class, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3a_keytype_use_diverged_with_unchanged_identity_is_unproved() -> None:
    """I4: diverged use output with an unchanged identity is unattributed (unproved)."""
    fake = _CopyFake(copy_mode="ignore", copy_crypto_value=bytes(range(0x30, 0x40)))
    assert_xfails(_qc3a_keytype, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("identity_changed") is False, record.detail
    assert (record.detail or {}).get("use_matches_baseline") is False, record.detail


def test_qc3a_keytype_override_shown_with_intact_use_fails() -> None:
    """I4 guard: the readback showing the override value IS the applied effect (FAIL)."""
    fake = _CopyFake(
        copy_mode="ignore",
        raw_readback={("copy", int(CKA_KEY_TYPE)): _ulong_bytes(CKK_GENERIC_SECRET)},
    )
    _run_must_fail(_qc3a_keytype, _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert (record.detail or {}).get("identity_shows_override") is True, record.detail
    assert (record.detail or {}).get("use_matches_baseline") is True, record.detail


def test_qc3a_keytype_third_value_identity_is_unproved() -> None:
    """I4: an identity matching neither original nor override is unattributed (unproved)."""
    from pkcs11_check.raw.types_std import CKK_DES3

    fake = _CopyFake(
        copy_mode="ignore", raw_readback={("copy", int(CKA_KEY_TYPE)): _ulong_bytes(CKK_DES3)}
    )
    assert_xfails(_qc3a_keytype, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("observed_identity") == int(CKK_DES3), record.detail


def test_qc3a_keytype_missing_identity_is_unproved() -> None:
    """I4: an unreadable identity cannot show the override (unproved even when use matches)."""
    fake = _CopyFake(copy_mode="ignore", copy_hide={int(CKA_KEY_TYPE)})
    assert_xfails(_qc3a_keytype, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3a_identity_readback_device_error_xfails_unproved() -> None:
    """I12 guard: a refused identity readback is an unproved xfail with the RV preserved."""
    fake = _CopyFake(copy_mode="ignore", get_attr_script=[_DEVICE_ERROR])
    assert_xfails(_qc3a_keytype, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("readback_rv") == "CKR_DEVICE_ERROR", record.detail


def test_qc3b_widen_premise_transient_refusal_voids() -> None:
    """I6: a transient excluded-mechanism refusal proves no restriction (premise void)."""
    fake = _CopyFake(encrypt_rv={("create", _CBC): _DEVICE_ERROR})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert "CKR_DEVICE_ERROR" in (record.summary or ""), record.summary


def test_qc3b_widen_premise_action_prohibited_counts_as_policy() -> None:
    """F2 re-verdict: ACTION_PROHIBITED never proves a CBC restriction (premise void)."""
    fake = _CopyFake(encrypt_rv={("create", _CBC): _ACTION_PROHIBITED})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_ACTION_PROHIBITED", record.actual_ckr
    assert "restriction unproved" in (record.summary or ""), record.summary


def test_qc3b_widen_premise_vendor_refusal_xfails_nonspec() -> None:
    """I13: a vendor-RV premise refusal is a visible alternate xfail."""
    fake = _CopyFake(encrypt_rv={("create", _CBC): _VENDOR_RV})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_widen_premise_undefined_refusal_fails() -> None:
    """I13: an undefined-RV premise refusal fails the return-value contract."""
    fake = _CopyFake(encrypt_rv={("create", _CBC): _UNDEFINED_RV})
    _run_must_fail(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_widen_premise_ecb_refused_voids() -> None:
    """I6 guard: a refused premise ECB voids the widening leg (standard RV preserved)."""
    fake = _CopyFake(encrypt_rv={("create", _ECB): _DEVICE_ERROR})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.actual_ckr


def test_qc3b_widen_premise_ecb_vendor_refusal_xfails_nonspec() -> None:
    """I13: a vendor-RV premise ECB refusal is a visible alternate xfail."""
    fake = _CopyFake(encrypt_rv={("create", _ECB): _VENDOR_RV})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_widen_premise_ecb_undefined_refusal_fails() -> None:
    """I13: an undefined-RV premise ECB refusal fails the return-value contract."""
    fake = _CopyFake(encrypt_rv={("create", _ECB): _UNDEFINED_RV})
    _run_must_fail(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_widen_premise_already_completes_voids() -> None:
    """I6 guard: an already-completing excluded mechanism voids the widening leg."""
    fake = _CopyFake(ignore_allowed={"create"})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    _assert_xfail_record("not_operational")


def test_qc3b_narrow_premise_refused_voids() -> None:
    """I6 guard: a refused premise CBC voids the narrowing leg (standard RV preserved)."""
    fake = _CopyFake(encrypt_rv={("create", _CBC): _DEVICE_ERROR})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.actual_ckr


def test_qc3b_narrow_premise_vendor_refusal_xfails_nonspec() -> None:
    """I13: a vendor-RV narrow-premise refusal is a visible alternate xfail."""
    fake = _CopyFake(encrypt_rv={("create", _CBC): _VENDOR_RV})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_narrow_premise_undefined_refusal_fails() -> None:
    """I13: an undefined-RV narrow-premise refusal fails the return-value contract."""
    fake = _CopyFake(encrypt_rv={("create", _CBC): _UNDEFINED_RV})
    _run_must_fail(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_widen_copy_transient_post_refusal_with_unchanged_list_is_unproved() -> None:
    """I6/I8: transient post-change refusal with an unchanged list proves no ignoring."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _CBC): _DEVICE_ERROR})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("refusal_policy_shaped") is False, record.detail


def test_qc3b_widen_copy_bypass_despite_unchanged_list_fails() -> None:
    """I8/A6: CBC completing despite an unchanged [ECB] list is a bypass FAIL (not widening)."""
    fake = _CopyFake(copy_mode="ignore", ignore_allowed={"copy"})
    _run_must_fail(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "bypassed" in (record.summary or ""), record.summary
    assert "unchanged" in (record.summary or ""), record.summary
    assert "took effect" not in (record.summary or ""), record.summary
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


def test_qc3b_widen_copy_widened_but_refused_is_unproved() -> None:
    """I8: a widened list with a refused excluded mechanism is inconclusive (unproved)."""
    fake = _CopyFake(copy_mode="apply", encrypt_rv={("copy", _CBC): _KEY_NOT_PERMITTED})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3b_widen_copy_third_value_list_is_unproved() -> None:
    """I8: a list matching neither endpoint leaves the widening effect unproved."""
    fake = _CopyFake(
        copy_mode="ignore", raw_readback={("copy", int(CKA_ALLOWED_MECHANISMS)): _ulong_bytes(_CBC)}
    )
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("readback") == [_CBC], record.detail


def test_qc3b_widen_copy_missing_list_is_unproved() -> None:
    """I8: an unreadable list cannot govern the widening verdict (unproved)."""
    fake = _CopyFake(copy_mode="ignore", copy_hide={int(CKA_ALLOWED_MECHANISMS)})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3b_widen_copy_readback_device_error_xfails_unproved() -> None:
    """I12: a refused widening list readback is an unproved xfail with the RV preserved."""
    fake = _CopyFake(copy_mode="ignore", get_attr_script=[_DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("readback_rv") == "CKR_DEVICE_ERROR", record.detail


def test_qc3b_widen_copy_ecb_sanity_refused_is_unproved() -> None:
    """I8: refused post-accept ECB sanity leaves the widening effect unproved."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _ECB): _DEVICE_ERROR})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


def test_qc3b_widen_copy_vendor_post_refusal_xfails_nonspec() -> None:
    """I13: a vendor-RV post-change CBC refusal is a visible alternate xfail."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _CBC): _VENDOR_RV})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_widen_copy_undefined_post_refusal_fails() -> None:
    """I13: an undefined-RV post-change CBC refusal fails the return-value contract."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _CBC): _UNDEFINED_RV})
    _run_must_fail(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_narrow_copy_transient_post_refusal_is_unproved() -> None:
    """I6: post-change DEVICE_ERROR never proves narrowing took effect (reviewer repro)."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _CBC): _DEVICE_ERROR})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3b_narrow_set_transient_post_refusal_is_unproved() -> None:
    """I6: the set leg applies the same shaped-verdict rule (reviewer repro)."""
    fake = _CopyFake(set_mode="ignore", post_set_encrypt_rv={("create", _CBC): _DEVICE_ERROR})
    assert_xfails(_qc3b, "set", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3b_narrow_copy_refused_despite_unchanged_list_is_unproved() -> None:
    """I8: policy-shaped refusal with an unchanged permissive list is unattributed."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _CBC): _KEY_NOT_PERMITTED})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("refusal_policy_shaped") is True, record.detail


def test_qc3b_narrow_copy_narrowed_but_completes_is_unproved() -> None:
    """I8: a narrowed list with a completing excluded mechanism is inconclusive (unproved)."""
    fake = _CopyFake(copy_mode="apply", ignore_allowed={"copy"})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3b_narrow_copy_narrowed_transient_refusal_is_unproved() -> None:
    """I6: a narrowed list with a transient refusal still leaves narrowing unproved."""
    fake = _CopyFake(copy_mode="apply", encrypt_rv={("copy", _CBC): _DEVICE_ERROR})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3b_narrow_copy_third_value_list_is_unproved() -> None:
    """I8: a list matching neither endpoint leaves the narrowing effect unproved."""
    fake = _CopyFake(
        copy_mode="ignore", raw_readback={("copy", int(CKA_ALLOWED_MECHANISMS)): _ulong_bytes(_CBC)}
    )
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3b_narrow_copy_missing_list_is_unproved() -> None:
    """I8: an unreadable list cannot govern the narrowing verdict (unproved)."""
    fake = _CopyFake(copy_mode="ignore", copy_hide={int(CKA_ALLOWED_MECHANISMS)})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3b_narrow_copy_readback_device_error_xfails_unproved() -> None:
    """I12: a refused narrowing list readback is an unproved xfail with the RV preserved."""
    fake = _CopyFake(copy_mode="ignore", get_attr_script=[_DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("readback_rv") == "CKR_DEVICE_ERROR", record.detail


def test_qc3b_narrow_copy_ecb_sanity_refused_is_unproved() -> None:
    """I8: refused post-accept ECB sanity leaves the narrowing effect unproved."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _ECB): _DEVICE_ERROR})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


def test_qc3b_narrow_copy_vendor_post_refusal_xfails_nonspec() -> None:
    """I13: a vendor-RV post-change CBC refusal is a visible alternate xfail."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _CBC): _VENDOR_RV})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_narrow_copy_undefined_post_refusal_fails() -> None:
    """I13: an undefined-RV post-change CBC refusal fails the return-value contract."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _CBC): _UNDEFINED_RV})
    _run_must_fail(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


_PROBE_PT = b"qc3probe-block16"


def _wrap_pair(
    fake: _CopyFake, *, target_value: bytes = _ORIG_VALUE, target_extractable: bool = True
) -> tuple[Any, int, int]:
    """Create (rs, wrapper, target) handles on the fake for wrap-chain contracts."""
    rs = _rs(fake)
    # F5: validation wrappers carry both WRAP and UNWRAP (operable chain).
    wrapper = gen_aes_key(
        rs.raw, rs.sh, 128, attrs={CKA_WRAP: True, CKA_UNWRAP: True, CKA_EXTRACTABLE: True}
    )
    target = import_secret_key(
        rs.raw,
        rs.sh,
        CKK_AES,
        target_value,
        attrs={CKA_EXTRACTABLE: target_extractable, CKA_ENCRYPT: True, CKA_DECRYPT: True},
    )
    return rs, wrapper, target


def test_qc3b_sensitive_set_exposed_setup_fails_with_setup_attribution() -> None:
    """I7: a pre-exposed sensitive source fails at the premise (change never attempted)."""
    fake = _CopyFake(set_mode="ignore", raw_readback={("create", int(CKA_VALUE)): _ORIG_VALUE})
    _run_must_fail(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "setup observation" in (record.summary or ""), record.summary
    assert "CKA_SENSITIVE=True" in (record.summary or ""), record.summary
    assert "downgrade exposed" not in (record.summary or ""), record.summary
    assert fake.set_calls == [], "premise must fail before the change is attempted"


def test_qc3b_sensitive_set_garbage_setup_fails_with_setup_attribution() -> None:
    """F4a re-verdict: unrelated premise value without a witness voids (never FAILs)."""
    fake = _CopyFake(set_mode="ignore", raw_readback={("create", int(CKA_VALUE)): _GARBAGE_VALUE})
    assert_xfails(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert "premise void" in (record.summary or ""), record.summary
    assert fake.set_calls == []


def test_qc3b_sensitive_set_flag_not_persisted_voids() -> None:
    """I7: a source not persisting SENSITIVE=True voids the downgrade premise."""
    fake = _CopyFake(set_mode="ignore", raw_readback={("create", int(CKA_SENSITIVE)): b"\x00"})
    assert_xfails(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert "premise void" in (record.summary or ""), record.summary
    assert fake.set_calls == []


def test_qc3b_sensitive_set_flag_unreadable_voids() -> None:
    """I7: an unreadable premise flag cannot confirm the setup (premise void)."""
    fake = _CopyFake(set_mode="ignore", create_hide={int(CKA_SENSITIVE)})
    assert_xfails(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    _assert_xfail_record("not_operational")


def test_qc3b_sensitive_set_premise_read_refused_voids() -> None:
    """I12: a refused premise read voids the downgrade leg with the RV preserved."""
    fake = _CopyFake(set_mode="ignore", get_attr_script=[_DEVICE_ERROR])
    assert_xfails(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert (record.detail or {}).get("readback_rv") == "CKR_DEVICE_ERROR", record.detail


def test_qc3b_sensitive_set_premise_vendor_read_xfails_nonspec() -> None:
    """I13: a vendor-RV premise read is a visible alternate xfail."""
    fake = _CopyFake(set_mode="ignore", get_attr_script=[_VENDOR_RV])
    assert_xfails(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_sensitive_set_premise_undefined_read_fails() -> None:
    """I13: an undefined-RV premise read fails the return-value contract."""
    fake = _CopyFake(set_mode="ignore", get_attr_script=[_UNDEFINED_RV])
    _run_must_fail(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_sensitive_copy_empty_value_is_unproved() -> None:
    """I9: an empty readback is malformed evidence (unproved), never 'exposed material'."""
    fake = _CopyFake(copy_mode="apply", raw_readback={("copy", int(CKA_VALUE)): b""})
    assert_xfails(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3b_sensitive_copy_unrelated_value_mismatch_is_unproved() -> None:
    """I9: an unrelated value failing the functional witness is unproved (never exposed)."""
    fake = _CopyFake(copy_mode="apply", raw_readback={("copy", int(CKA_VALUE)): _GARBAGE_VALUE})
    assert_xfails(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("value_matches_original") is False, record.detail
    assert (record.detail or {}).get("witness_match") is False, record.detail


def test_qc3b_sensitive_copy_witness_match_fails() -> None:
    """I9: a read value reproducing the module ciphertext is proved exposure (FAIL)."""
    fake = _CopyFake(
        copy_mode="apply",
        copy_crypto_value=_GARBAGE_VALUE,
        raw_readback={("copy", int(CKA_VALUE)): _GARBAGE_VALUE},
    )
    _run_must_fail(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "witness" in (record.summary or ""), record.summary
    assert (record.detail or {}).get("value_matches_original") is False, record.detail
    assert (record.detail or {}).get("witness_match") is True, record.detail


def test_qc3b_sensitive_copy_bypass_despite_true_flag_fails() -> None:
    """I8: known material readable despite an unchanged True flag is a bypass FAIL."""
    fake = _CopyFake(copy_mode="apply", raw_readback={("copy", int(CKA_SENSITIVE)): b"\x01"})
    _run_must_fail(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "bypassed" in (record.summary or ""), record.summary
    assert "unchanged SENSITIVE=True" in (record.summary or ""), record.summary


def test_qc3b_sensitive_copy_exposed_flag_unreadable_fails() -> None:
    """I8: verified exposure with an unreadable flag still fails (accurate summary)."""
    fake = _CopyFake(copy_mode="apply", copy_hide={int(CKA_SENSITIVE)})
    _run_must_fail(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "unreadable" in (record.summary or ""), record.summary


def test_qc3b_sensitive_copy_sealed_flag_shows_applied_is_unproved() -> None:
    """I8: a False-showing flag with a sealed value is inconclusive (unproved)."""
    fake = _CopyFake(copy_mode="ignore", raw_readback={("copy", int(CKA_SENSITIVE)): b"\x00"})
    assert_xfails(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("value_readable") is False, record.detail
    assert (record.detail or {}).get("flag_readback") is False, record.detail


def test_qc3b_sensitive_copy_sealed_flag_unreadable_is_unproved() -> None:
    """I8: a sealed value with an unreadable flag cannot prove ignoring (unproved)."""
    fake = _CopyFake(copy_mode="ignore", copy_hide={int(CKA_SENSITIVE)})
    assert_xfails(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3b_sensitive_copy_witness_unavailable_is_unproved() -> None:
    """I9: an unrelated value with refused use cannot be witnessed (unproved)."""
    fake = _CopyFake(
        copy_mode="apply",
        raw_readback={("copy", int(CKA_VALUE)): _GARBAGE_VALUE},
        encrypt_rv={("copy", _ECB): _DEVICE_ERROR},
    )
    assert_xfails(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("use_rv") == "CKR_DEVICE_ERROR", record.detail
    assert (record.detail or {}).get("witness_match") is None, record.detail


def test_qc3b_sensitive_copy_readback_device_error_xfails_unproved() -> None:
    """I12: a refused sensitive verify read is an unproved xfail with the RV preserved."""
    fake = _CopyFake(copy_mode="ignore", get_attr_script=[_DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("readback_rv") == "CKR_DEVICE_ERROR", record.detail


def test_qc3b_sensitive_copy_wrong_length_flag_is_unproved() -> None:
    """I12: a 2-byte SENSITIVE readback is malformed (unproved), never a bool."""
    fake = _CopyFake(copy_mode="ignore", raw_readback={("copy", int(CKA_SENSITIVE)): b"\x00\x00"})
    assert_xfails(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3b_sensitive_copy_verify_vendor_read_xfails_nonspec() -> None:
    """I13: a vendor-RV verify read is a visible alternate xfail."""
    fake = _CopyFake(copy_mode="ignore", get_attr_script=[_VENDOR_RV])
    assert_xfails(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_sensitive_copy_verify_undefined_read_fails() -> None:
    """I13: an undefined-RV verify read fails the return-value contract."""
    fake = _CopyFake(copy_mode="ignore", get_attr_script=[_UNDEFINED_RV])
    _run_must_fail(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_extractable_set_wrappable_setup_fails_with_setup_attribution() -> None:
    """I7: a pre-wrappable non-extractable source fails at the premise (change never tried)."""
    fake = _CopyFake(set_mode="ignore", wrap_ignore_extractable={"create"})
    _run_must_fail(_qc3b, "set", "extractable_escalate", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "setup observation" in (record.summary or ""), record.summary
    assert "CKA_EXTRACTABLE=False" in (record.summary or ""), record.summary
    assert "escalation took effect" not in (record.summary or ""), record.summary
    assert fake.set_calls == [], "premise must fail before the change is attempted"


def test_qc3b_extractable_set_unvalidated_setup_wrap_is_unproved() -> None:
    """I7/I10: a completed-but-unvalidated setup wrap voids without claiming an accept."""
    fake = _CopyFake(
        set_mode="ignore", wrap_ignore_extractable={"create"}, wrap_empty_for={"create"}
    )
    assert_xfails(_qc3b, "set", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert record.actual_ckr is None, record.actual_ckr
    assert fake.set_calls == []


def test_qc3b_extractable_set_flag_not_persisted_voids() -> None:
    """I7: a source not persisting EXTRACTABLE=False voids the escalation premise."""
    fake = _CopyFake(set_mode="ignore", raw_readback={("create", int(CKA_EXTRACTABLE)): b"\x01"})
    assert_xfails(_qc3b, "set", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert "premise void" in (record.summary or ""), record.summary
    assert fake.set_calls == []


def test_qc3b_extractable_set_flag_unreadable_voids() -> None:
    """I7: an unreadable premise flag cannot confirm the setup (premise void)."""
    fake = _CopyFake(set_mode="ignore", create_hide={int(CKA_EXTRACTABLE)})
    assert_xfails(_qc3b, "set", "extractable_escalate", _rs(fake))
    _assert_xfail_record("not_operational")


def test_qc3b_extractable_set_nonsealing_premise_refusal_voids() -> None:
    """I7: a non-KEY_UNEXTRACTABLE premise wrap refusal leaves sealed-ness unproved."""
    fake = _CopyFake(set_mode="ignore", wrap_mode="refuse_all", wrap_refuse_rv=_DEVICE_ERROR)
    assert_xfails(_qc3b, "set", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert "CKR_DEVICE_ERROR" in (record.summary or ""), record.summary


def test_qc3b_extractable_set_premise_vendor_wrap_xfails_nonspec() -> None:
    """I13: a vendor-RV premise wrap refusal is a visible alternate xfail."""
    fake = _CopyFake(set_mode="ignore", wrap_mode="refuse_all", wrap_refuse_rv=_VENDOR_RV)
    assert_xfails(_qc3b, "set", "extractable_escalate", _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_extractable_set_premise_undefined_wrap_fails() -> None:
    """I13: an undefined-RV premise wrap refusal fails the return-value contract."""
    fake = _CopyFake(set_mode="ignore", wrap_mode="refuse_all", wrap_refuse_rv=_UNDEFINED_RV)
    _run_must_fail(_qc3b, "set", "extractable_escalate", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_extractable_set_premise_read_refused_voids() -> None:
    """I12: a refused premise flag read voids the escalation leg with the RV preserved."""
    fake = _CopyFake(set_mode="ignore", get_attr_script=[_DEVICE_ERROR])
    assert_xfails(_qc3b, "set", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert (record.detail or {}).get("readback_rv") == "CKR_DEVICE_ERROR", record.detail


def test_qc3b_extractable_copy_empty_wrap_is_unproved() -> None:
    """I10: a CKR_OK wrap with empty output never proves exposure (unproved)."""
    fake = _CopyFake(copy_mode="apply", wrap_empty_for={"copy"})
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("stage") == "empty-output", record.detail


def test_qc3b_extractable_copy_unwrap_refused_is_unproved() -> None:
    """F6b repurposed: a blob failing local unwrap is unproved (never exposure)."""
    fake = _CopyFake(
        copy_mode="apply",
        wrap_constant_for={"copy"},
        wrap_constant_blob=b"\x00" * 24,
    )
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("stage") == "unwrap-failed", record.detail


def test_qc3b_extractable_copy_unwrapped_use_refused_is_unproved() -> None:
    """F6b/c repurposed: KW of an unrelated constant never validates (unproved)."""
    unrelated = aes_key_wrap(_KEK_KNOWN, _UNRELATED_CONST)
    fake = _CopyFake(
        copy_mode="apply",
        wrap_constant_for={"copy"},
        wrap_constant_blob=unrelated,
    )
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("key_match") is False, record.detail


def test_qc3b_extractable_copy_wrap_mismatch_is_unproved() -> None:
    """F6d repurposed: a malformed-length KW blob is unvalidated (never exposure)."""
    fake = _CopyFake(
        copy_mode="apply",
        wrap_constant_for={"copy"},
        wrap_constant_blob=b"\x00" * 10,
    )
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("stage") == "malformed-output", record.detail


def test_qc3b_extractable_copy_nonsealing_refusal_is_unproved() -> None:
    """I8: a non-UNEXTRACTABLE wrap refusal with an unchanged flag proves no ignoring."""
    fake = _CopyFake(copy_mode="ignore", wrap_negative_refuse_rv=_DEVICE_ERROR)
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("refusal_sealing_shaped") is False, record.detail


def test_qc3b_extractable_copy_refused_flag_shows_applied_is_unproved() -> None:
    """I8: a True-showing flag with a refused wrap is inconclusive (unproved)."""
    fake = _CopyFake(copy_mode="apply", wrap_negative_refuse_rv=_KEY_UNEXTRACTABLE)
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("flag_readback") is True, record.detail


def test_qc3b_extractable_copy_refused_flag_unreadable_is_unproved() -> None:
    """I8: a refused wrap with an unreadable flag cannot prove ignoring (unproved)."""
    fake = _CopyFake(copy_mode="ignore", copy_hide={int(CKA_EXTRACTABLE)})
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3b_extractable_copy_bypass_despite_false_flag_fails() -> None:
    """I8: a validated wrap despite an unchanged False flag is a bypass FAIL."""
    fake = _CopyFake(copy_mode="apply", raw_readback={("copy", int(CKA_EXTRACTABLE)): b"\x00"})
    _run_must_fail(_qc3b, "copy", "extractable_escalate", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "bypassed" in (record.summary or ""), record.summary
    assert "unchanged EXTRACTABLE=False" in (record.summary or ""), record.summary


def test_qc3b_extractable_copy_validated_flag_unreadable_fails() -> None:
    """I8: a validated wrap with an unreadable flag still fails (accurate summary)."""
    fake = _CopyFake(copy_mode="apply", copy_hide={int(CKA_EXTRACTABLE)})
    _run_must_fail(_qc3b, "copy", "extractable_escalate", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "unreadable" in (record.summary or ""), record.summary
    assert (record.detail or {}).get("blob_len") == 24, record.detail


def test_qc3b_extractable_copy_readback_device_error_xfails_unproved() -> None:
    """I12: a refused extractable verify read is an unproved xfail with the RV preserved."""
    fake = _CopyFake(copy_mode="ignore", get_attr_script=[_DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("readback_rv") == "CKR_DEVICE_ERROR", record.detail


def test_qc3b_extractable_copy_wrong_length_flag_is_unproved() -> None:
    """I12: a 2-byte EXTRACTABLE readback is malformed (unproved), never a bool."""
    fake = _CopyFake(copy_mode="ignore", raw_readback={("copy", int(CKA_EXTRACTABLE)): b"\x00\x00"})
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3b_extractable_copy_verify_vendor_read_xfails_nonspec() -> None:
    """I13: a vendor-RV verify read is a visible alternate xfail."""
    fake = _CopyFake(copy_mode="ignore", get_attr_script=[_VENDOR_RV])
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_extractable_copy_verify_undefined_read_fails() -> None:
    """I13: an undefined-RV verify read fails the return-value contract."""
    fake = _CopyFake(copy_mode="ignore", get_attr_script=[_UNDEFINED_RV])
    _run_must_fail(_qc3b, "copy", "extractable_escalate", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_extractable_copy_wrap_vendor_refusal_xfails_nonspec() -> None:
    """I13: a vendor-RV verify wrap refusal is a visible alternate xfail."""
    fake = _CopyFake(copy_mode="ignore", wrap_negative_refuse_rv=_VENDOR_RV)
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_extractable_copy_wrap_undefined_refusal_fails() -> None:
    """I13: an undefined-RV verify wrap refusal fails the return-value contract."""
    fake = _CopyFake(copy_mode="ignore", wrap_negative_refuse_rv=_UNDEFINED_RV)
    _run_must_fail(_qc3b, "copy", "extractable_escalate", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3c_negative_action_prohibited_xfails_nonspec() -> None:
    """I11: ACTION_PROHIBITED is an alternate refusal (visible xfail), never a pass."""
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        wrap_negative_refuse_rv=_ACTION_PROHIBITED,
    )
    assert_xfails(_qc3c, _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3c_negative_not_permitted_xfails_nonspec() -> None:
    """I11: KEY_FUNCTION_NOT_PERMITTED is an alternate refusal (visible xfail), not a pass."""
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        wrap_negative_refuse_rv=_KEY_NOT_PERMITTED,
    )
    assert_xfails(_qc3c, _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3c_negative_vendor_refusal_xfails_nonspec() -> None:
    """I11/I13 guard: a vendor-RV negative refusal stays a visible alternate xfail."""
    fake = _CopyFake(
        copy_mode="apply", extractable_default=False, wrap_negative_refuse_rv=_VENDOR_RV
    )
    assert_xfails(_qc3c, _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3c_negative_undefined_refusal_fails() -> None:
    """I11/I13 guard: an undefined-RV negative refusal fails the RV contract."""
    fake = _CopyFake(
        copy_mode="apply", extractable_default=False, wrap_negative_refuse_rv=_UNDEFINED_RV
    )
    _run_must_fail(_qc3c, _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3c_control_refused_undefined_fails() -> None:
    """I13: an undefined-RV control wrap refusal fails (never a quiet skip)."""
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        wrap_mode="refuse_all",
        wrap_refuse_rv=_UNDEFINED_RV,
    )
    _run_must_fail(_qc3c, _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3c_control_refused_vendor_xfails_nonspec() -> None:
    """I13: a vendor-RV control wrap refusal is a visible alternate xfail (never a skip)."""
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        wrap_mode="refuse_all",
        wrap_refuse_rv=_VENDOR_RV,
    )
    assert_xfails(_qc3c, _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3c_control_empty_wrap_skips_negative() -> None:
    """F6a: an empty control wrap cannot qualify the wrap path (negative skipped)."""
    # Control is an imported (role "create") target after F6a, not generated.
    fake = _CopyFake(copy_mode="apply", extractable_default=False, wrap_empty_for={"create"})
    assert_skips(_qc3c, _rs(fake), match="unvalidated")


def test_qc3c_control_mismatch_skips_negative() -> None:
    """F6b/c repurposed: control KW of unrelated material cannot qualify (skipped)."""
    # Matches production _QC3C_WRAPPER_VALUE (0x80..0x90); the oracle unwraps
    # to unrelated (mismatch) and the negative is inapplicable, never passed.
    _qc3c_kek = bytes(range(0x80, 0x90))
    unrelated = aes_key_wrap(_qc3c_kek, bytes(range(0x01, 0x11)))
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        wrap_constant_for={"create"},
        wrap_constant_blob=unrelated,
    )
    assert_skips(_qc3c, _rs(fake), match="unvalidated")


def test_qc3c_negative_empty_wrap_is_unproved() -> None:
    """I10: a CKR_OK negative wrap with empty output never proves exposure (unproved)."""
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        copy_force_extractable=True,
        wrap_empty_for={"copy"},
    )
    assert_xfails(_qc3c, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("stage") == "empty-output", record.detail


def test_qc3c_negative_unwrap_refused_is_unproved() -> None:
    """F6b repurposed: negative blob failing local unwrap is unproved (never exposure)."""
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        copy_force_extractable=True,
        wrap_constant_for={"copy"},
        wrap_constant_blob=b"\x00" * 24,
    )
    assert_xfails(_qc3c, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("stage") == "unwrap-failed", record.detail


def test_qc3c_negative_mismatch_is_unproved() -> None:
    """F6b/c repurposed: negative KW of unrelated material is unproved (never exposed)."""
    _qc3c_kek = bytes(range(0x80, 0x90))
    unrelated = aes_key_wrap(_qc3c_kek, bytes(range(0x01, 0x11)))
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        copy_force_extractable=True,
        wrap_constant_for={"copy"},
        wrap_constant_blob=unrelated,
    )
    assert_xfails(_qc3c, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("key_match") is False, record.detail


def test_qc3c_negative_reference_use_refused_is_unproved() -> None:
    """F6d repurposed: malformed-length negative blob is unvalidated (never exposure)."""
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        copy_force_extractable=True,
        wrap_constant_for={"copy"},
        wrap_constant_blob=b"\x00" * 10,
    )
    assert_xfails(_qc3c, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("stage") == "malformed-output", record.detail


def test_qc3c_escalated_vendor_wrap_xfails_nonspec() -> None:
    """I13: an escalated copy with a vendor-RV wrap refusal is an alternate xfail."""
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        copy_force_extractable=True,
        wrap_negative_refuse_rv=_VENDOR_RV,
    )
    assert_xfails(_qc3c, _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3c_escalated_undefined_wrap_fails() -> None:
    """I13: an escalated copy with an undefined-RV wrap refusal fails the RV contract."""
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        copy_force_extractable=True,
        wrap_negative_refuse_rv=_UNDEFINED_RV,
    )
    _run_must_fail(_qc3c, _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3c_empty_copy_vendor_refusal_xfails_nonspec() -> None:
    """I13: a vendor-RV empty-copy refusal is a visible alternate xfail."""
    fake = _CopyFake(copy_refuse_rv=_VENDOR_RV, extractable_default=False)
    assert_xfails(_qc3c, _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3c_empty_copy_undefined_refusal_fails() -> None:
    """I13: an undefined-RV empty-copy refusal fails the return-value contract."""
    fake = _CopyFake(copy_refuse_rv=_UNDEFINED_RV, extractable_default=False)
    _run_must_fail(_qc3c, _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def _reauth_rs(fake: _CopyFake) -> Any:
    return _rs(fake, mechs=_RSA_MECHS)


def test_qc3b_reauth_no_pin_skips_before_keygen() -> None:
    """I1: without a PIN the re-auth leg skips before generating anything."""
    fake = _CopyFake(copy_mode="ignore")
    assert_skips(_qc3b, "copy", "always_authenticate", _reauth_rs(fake), _NO_PIN_CONFIG)
    assert fake.keypair_calls == [], "no keygen without a PIN"


def test_qc3b_reauth_missing_rsa_mechanism_skips() -> None:
    """I1: without RSA keygen/sign mechanisms the re-auth leg skips."""
    fake = _CopyFake(copy_mode="ignore")
    assert_skips(_qc3b, "copy", "always_authenticate", _rs(fake))
    assert fake.keypair_calls == [], "no keygen without RSA mechanisms"


def test_qc3b_reauth_keygen_refused_voids() -> None:
    """I1: a refused RSA keygen voids the leg (sanctioned setup shape)."""
    fake = _CopyFake(copy_mode="ignore", keypair_script=[_ATTR_VALUE_INVALID])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.kind == "metadata", record.kind


def test_qc3b_reauth_keygen_undefined_fails() -> None:
    """I1/I13: an undefined-RV keygen refusal fails the return-value contract."""
    fake = _CopyFake(copy_mode="ignore", keypair_script=[_UNDEFINED_RV])
    _run_must_fail(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_reauth_setup_dropped_flag_fails() -> None:
    """F7 re-verdict: a dropped setup flag voids (unproved xfail, never wrong_result)."""
    fake = _CopyFake(
        copy_mode="ignore", raw_readback={("create", int(CKA_ALWAYS_AUTHENTICATE)): b"\x00"}
    )
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("not_operational")


def test_qc3b_reauth_setup_unreadable_skips() -> None:
    """F7 re-verdict: an unreadable setup flag voids via xfail (never a quiet skip)."""
    fake = _CopyFake(copy_mode="ignore", create_hide={int(CKA_ALWAYS_AUTHENTICATE)})
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("not_operational")
    assert len(fake.keypair_calls) == 1, "keygen attempted before the setup read"


def test_qc3b_reauth_premise_use_completes_voids() -> None:
    """I1: source use completing without re-auth voids the bypass premise."""
    fake = _CopyFake(copy_mode="ignore", sign_script=[_OK])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("not_operational")
    assert "without re-authentication" in (record.summary or ""), record.summary
    assert fake.login_calls == [], "no login attempted once the premise voids"


def test_qc3b_reauth_premise_transient_refusal_voids() -> None:
    """I1/I6: a non-auth premise refusal proves no re-auth demand (premise void)."""
    fake = _CopyFake(copy_mode="ignore", sign_script=[_DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("not_operational")
    assert "CKR_DEVICE_ERROR" in (record.summary or ""), record.summary


def test_qc3b_reauth_premise_init_shaped_refusal_proceeds() -> None:
    """I1: an auth-shaped refusal at C_SignInit also proves the re-auth demand."""
    fake = _CopyFake(copy_mode="ignore", sign_init_script=[_NOT_LOGGED_IN])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "ignored-input", record.detail


def test_qc3b_reauth_premise_init_transient_refusal_voids() -> None:
    """I1: a transient C_SignInit refusal voids the premise like a C_Sign one."""
    fake = _CopyFake(copy_mode="ignore", sign_init_script=[_DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("not_operational")


def test_qc3b_reauth_premise_vendor_refusal_xfails_nonspec() -> None:
    """I13: a vendor-RV premise refusal is a visible alternate xfail."""
    fake = _CopyFake(copy_mode="ignore", sign_script=[_VENDOR_RV])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_reauth_premise_undefined_refusal_fails() -> None:
    """I13: an undefined-RV premise refusal fails the return-value contract."""
    fake = _CopyFake(copy_mode="ignore", sign_script=[_UNDEFINED_RV])
    _run_must_fail(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_reauth_login_unsupported_voids() -> None:
    """I1: unsupported context login voids the leg visibly, never passes it."""
    fake = _CopyFake(copy_mode="ignore", login_script=[_NOT_SUPPORTED])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("not_operational")
    assert "unsupported" in (record.summary or ""), record.summary


def test_qc3b_reauth_login_user_type_invalid_voids() -> None:
    """I1: CKU_CONTEXT_SPECIFIC rejected as a user type likewise voids the leg."""
    fake = _CopyFake(copy_mode="ignore", login_script=[_USER_TYPE_INVALID])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("not_operational")


def test_qc3b_reauth_login_other_refusal_voids() -> None:
    """I1: any other login refusal voids the control (leg void)."""
    fake = _CopyFake(copy_mode="ignore", login_script=[_DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("not_operational")
    assert "CKR_DEVICE_ERROR" in (record.summary or ""), record.summary


def test_qc3b_reauth_login_vendor_refusal_xfails_nonspec() -> None:
    """I13: a vendor-RV login refusal is a visible alternate xfail."""
    fake = _CopyFake(copy_mode="ignore", login_script=[_VENDOR_RV])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_reauth_login_undefined_refusal_fails() -> None:
    """I13: an undefined-RV login refusal fails the return-value contract."""
    fake = _CopyFake(copy_mode="ignore", login_script=[_UNDEFINED_RV])
    _run_must_fail(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_reauth_control_refused_voids() -> None:
    """I1: a control sign refused after login voids the leg (control unproved)."""
    fake = _CopyFake(copy_mode="ignore", sign_script=[None, _DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("not_operational")
    assert "control" in (record.summary or ""), record.summary


def test_qc3b_reauth_control_bad_signature_voids() -> None:
    """F10 re-verdict: an invalid control signature is crypto wrong_result (never void)."""
    fake = _CopyFake(copy_mode="ignore", sign_corrupt=True)
    _run_must_fail(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert "verification" in (record.summary or ""), record.summary


def test_qc3b_reauth_control_pubkey_unreadable_voids() -> None:
    """I1: an unreadable control pubkey cannot verify the control (leg void)."""
    fake = _CopyFake(copy_mode="ignore", create_hide={int(CKA_MODULUS)})
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("not_operational")


def test_qc3b_reauth_control_pubkey_malformed_voids() -> None:
    """I1: a malformed control pubkey cannot verify the control (leg void)."""
    fake = _CopyFake(copy_mode="ignore", raw_readback={("create", int(CKA_MODULUS)): b"short"})
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("not_operational")


def test_qc3b_reauth_set_single_use_violation_voids() -> None:
    """I1: re-auth reuse on a SET leg makes bypass unattributable (leg void)."""
    fake = _CopyFake(set_mode="ignore", reauth_single_use=False)
    assert_xfails(_qc3b, "set", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("not_operational")
    assert "single-use" in (record.summary or ""), record.summary
    assert fake.set_calls == [], "premise must void before the change is attempted"


def test_qc3b_reauth_set_single_use_transient_voids() -> None:
    """I1: a transient second-sign refusal leaves single-use unproved (leg void)."""
    fake = _CopyFake(set_mode="ignore", sign_script=[None, None, _DEVICE_ERROR])
    assert_xfails(_qc3b, "set", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("not_operational")


def test_qc3b_reauth_copy_bypass_despite_true_flag_fails() -> None:
    """F10 re-verdict: scripted-OK (all-zero invalid) post-change sig is wrong_result."""
    fake = _CopyFake(copy_mode="ignore", sign_script=[None, None, _OK])
    _run_must_fail(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert "bypassed" not in (record.summary or "").lower(), record.summary
    assert "invalid" in (record.summary or "").lower(), record.summary


def test_qc3b_reauth_copy_bypass_flag_unreadable_fails() -> None:
    """F10 re-verdict: invalid post-change sig with unreadable flag is wrong_result."""
    fake = _CopyFake(
        copy_mode="ignore",
        copy_hide={int(CKA_ALWAYS_AUTHENTICATE)},
        sign_script=[None, None, _OK],
    )
    _run_must_fail(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert "bypassed" not in (record.summary or "").lower(), record.summary
    assert "invalid" in (record.summary or "").lower(), record.summary


def test_qc3b_reauth_copy_post_nonauth_refusal_is_unproved() -> None:
    """I8: a non-auth post-change refusal with an unchanged flag is unproved."""
    fake = _CopyFake(copy_mode="ignore", sign_script=[None, None, _DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("refusal_auth_shaped") is False, record.detail


def test_qc3b_reauth_copy_refused_flag_shows_applied_is_unproved() -> None:
    """I8: an auth-shaped refusal with a False-showing flag is inconclusive (unproved)."""
    fake = _CopyFake(copy_mode="apply", sign_script=[None, None, _NOT_LOGGED_IN])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("flag_readback") is False, record.detail


def test_qc3b_reauth_copy_refused_flag_unreadable_is_unproved() -> None:
    """I8: an auth-shaped refusal with an unreadable flag cannot prove ignoring."""
    fake = _CopyFake(copy_mode="ignore", copy_hide={int(CKA_ALWAYS_AUTHENTICATE)})
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3b_reauth_copy_post_vendor_refusal_xfails_nonspec() -> None:
    """I13: a vendor-RV post-change sign refusal is a visible alternate xfail."""
    fake = _CopyFake(copy_mode="ignore", sign_script=[None, None, _VENDOR_RV])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_reauth_copy_post_undefined_refusal_fails() -> None:
    """I13: an undefined-RV post-change sign refusal fails the return-value contract."""
    fake = _CopyFake(copy_mode="ignore", sign_script=[None, None, _UNDEFINED_RV])
    _run_must_fail(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_reauth_copy_flag_read_device_error_is_unproved() -> None:
    """I12: a refused post-accept flag read is an unproved xfail with the RV preserved."""
    fake = _CopyFake(copy_mode="ignore", get_attr_script=[None, None, None, None, _DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("readback_rv") == "CKR_DEVICE_ERROR", record.detail


def test_qc3b_reauth_copy_wrong_length_flag_is_unproved() -> None:
    """I12: a 2-byte ALWAYS_AUTHENTICATE readback is malformed (unproved), never a bool."""
    fake = _CopyFake(
        copy_mode="ignore", raw_readback={("copy", int(CKA_ALWAYS_AUTHENTICATE)): b"\x00\x00"}
    )
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_qc3b_label_copy_readback_device_error_xfails_unproved() -> None:
    """I12: a refused label verify read is an unproved xfail with the RV preserved."""
    fake = _CopyFake(copy_mode="apply", get_attr_script=[_DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "label_control", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("readback_rv") == "CKR_DEVICE_ERROR", record.detail
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


def test_qc3b_label_copy_verify_vendor_read_xfails_nonspec() -> None:
    """I13: a vendor-RV label verify read is a visible alternate xfail."""
    fake = _CopyFake(copy_mode="apply", get_attr_script=[_VENDOR_RV])
    assert_xfails(_qc3b, "copy", "label_control", _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_label_copy_verify_undefined_read_fails() -> None:
    """I13: an undefined-RV label verify read fails the return-value contract."""
    fake = _CopyFake(copy_mode="apply", get_attr_script=[_UNDEFINED_RV])
    _run_must_fail(_qc3b, "copy", "label_control", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_label_copy_unexpected_value_xfails_unproved() -> None:
    """I14: a wrong-label readback after an accepted label change is unproved (M1 actual)."""
    fake = _CopyFake(copy_mode="apply", raw_readback={("copy", int(CKA_LABEL)): b"weird"})
    assert_xfails(_qc3b, "copy", "label_control", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


def test_qc3b_label_copy_unreadable_xfails_unproved() -> None:
    """I14: an unreadable label readback after an accepted label change is unproved."""
    fake = _CopyFake(copy_mode="apply", copy_hide={int(CKA_LABEL)})
    assert_xfails(_qc3b, "copy", "label_control", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


def test_qc3a_unchanged_baseline_refused_note_passes() -> None:
    """I13/I14 guard: a standard-RV baseline refusal stays a note-passed observation."""
    fake = _CopyFake(encrypt_rv={("create", _ECB): _DEVICE_ERROR})
    _qc3a_unchanged(_rs(fake))
    assert C.get_records() == [], "notes ride the compliance channel, not classifications"


def test_qc3a_unchanged_copy_refused_note_passes() -> None:
    """I13/I14 guard: a standard-RV copy refusal stays a note-passed observation."""
    fake = _CopyFake(copy_refuse_rv=_DEVICE_ERROR)
    _qc3a_unchanged(_rs(fake))
    assert C.get_records() == []


def test_qc3a_unchanged_copy_use_refused_note_passes() -> None:
    """I13/I14 guard: a standard-RV copy-use refusal stays a note-passed observation."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _ECB): _DEVICE_ERROR})
    _qc3a_unchanged(_rs(fake))
    assert C.get_records() == []


def test_qc3a_unchanged_baseline_vendor_refusal_xfails_nonspec() -> None:
    """I13: a vendor-RV observation refusal is a visible alternate xfail (never noted)."""
    fake = _CopyFake(encrypt_rv={("create", _ECB): _VENDOR_RV})
    assert_xfails(_qc3a_unchanged, _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3a_unchanged_copy_use_undefined_refusal_fails() -> None:
    """I13: an undefined-RV observation refusal fails the return-value contract."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _ECB): _UNDEFINED_RV})
    _run_must_fail(_qc3a_unchanged, _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3a_empty_baseline_refused_note_passes() -> None:
    """I13/I14 guard: a standard-RV baseline refusal stays a note-passed observation."""
    fake = _CopyFake(encrypt_rv={("create", _ECB): _DEVICE_ERROR})
    _qc3a_empty(_rs(fake))
    assert C.get_records() == []


def test_qc3a_empty_copy_refused_note_passes() -> None:
    """I13/I14 guard: a standard-RV copy refusal stays a note-passed observation."""
    fake = _CopyFake(copy_refuse_rv=_DEVICE_ERROR)
    _qc3a_empty(_rs(fake))
    assert C.get_records() == []


def test_qc3a_empty_copy_use_refused_note_passes() -> None:
    """I13/I14 guard: a standard-RV copy-use refusal stays a note-passed observation."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _ECB): _DEVICE_ERROR})
    _qc3a_empty(_rs(fake))
    assert C.get_records() == []


def test_qc3a_empty_copy_vendor_refusal_xfails_nonspec() -> None:
    """I13: a vendor-RV observation refusal is a visible alternate xfail (never noted)."""
    fake = _CopyFake(copy_refuse_rv=_VENDOR_RV)
    assert_xfails(_qc3a_empty, _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3a_empty_baseline_undefined_refusal_fails() -> None:
    """I13: an undefined-RV observation refusal fails the return-value contract."""
    fake = _CopyFake(encrypt_rv={("create", _ECB): _UNDEFINED_RV})
    _run_must_fail(_qc3a_empty, _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3c_source_readback_refused_voids() -> None:
    """I12/I14: a refused QC3c source read voids the premise with the RV preserved."""
    fake = _CopyFake(copy_mode="apply", extractable_default=False, get_attr_script=[_DEVICE_ERROR])
    assert_xfails(_qc3c, _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert (record.detail or {}).get("readback_rv") == "CKR_DEVICE_ERROR", record.detail


def test_qc3a_identity_use_vendor_refusal_xfails_nonspec() -> None:
    """I13/I14: a vendor-RV identity-leg use refusal is a visible alternate xfail."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _ECB): _VENDOR_RV})
    assert_xfails(_qc3a_keytype, _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3a_identity_use_undefined_refusal_fails() -> None:
    """I13/I14: an undefined-RV identity-leg use refusal fails the RV contract."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _ECB): _UNDEFINED_RV})
    _run_must_fail(_qc3a_keytype, _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_sensitive_witness_vendor_refusal_xfails_nonspec() -> None:
    """I13/I14: a vendor-RV witness-use refusal is a visible alternate xfail."""
    fake = _CopyFake(
        copy_mode="apply",
        raw_readback={("copy", int(CKA_VALUE)): _GARBAGE_VALUE},
        encrypt_rv={("copy", _ECB): _VENDOR_RV},
    )
    assert_xfails(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_sensitive_witness_undefined_refusal_fails() -> None:
    """I13/I14: an undefined-RV witness-use refusal fails the RV contract."""
    fake = _CopyFake(
        copy_mode="apply",
        raw_readback={("copy", int(CKA_VALUE)): _GARBAGE_VALUE},
        encrypt_rv={("copy", _ECB): _UNDEFINED_RV},
    )
    _run_must_fail(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_reauth_control_vendor_refusal_xfails_nonspec() -> None:
    """I13/I14: a vendor-RV control-sign refusal is a visible alternate xfail."""
    fake = _CopyFake(copy_mode="ignore", sign_script=[None, _VENDOR_RV])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_reauth_control_undefined_refusal_fails() -> None:
    """I13/I14: an undefined-RV control-sign refusal fails the RV contract."""
    fake = _CopyFake(copy_mode="ignore", sign_script=[None, _UNDEFINED_RV])
    _run_must_fail(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_reauth_single_use_vendor_refusal_xfails_nonspec() -> None:
    """I13/I14: a vendor-RV second-sign refusal is a visible alternate xfail."""
    fake = _CopyFake(set_mode="ignore", sign_script=[None, None, _VENDOR_RV])
    assert_xfails(_qc3b, "set", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_qc3b_reauth_single_use_undefined_refusal_fails() -> None:
    """I13/I14: an undefined-RV second-sign refusal fails the RV contract."""
    fake = _CopyFake(set_mode="ignore", sign_script=[None, None, _UNDEFINED_RV])
    _run_must_fail(_qc3b, "set", "always_authenticate", _reauth_rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_qc3b_reauth_pubkey_read_refused_voids() -> None:
    """I12/I14: a refused control-pubkey read voids the leg with the RV preserved."""
    fake = _CopyFake(copy_mode="ignore", get_attr_script=[None, None, _DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("not_operational")
    assert (record.detail or {}).get("readback_rv") == "CKR_DEVICE_ERROR", record.detail


def test_qc3b_value_copy_baseline_refused_voids() -> None:
    """I14: a refused value baseline voids the leg with the RV preserved (primary gap)."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("create", _ECB): _DEVICE_ERROR})
    assert_xfails(_qc3b, "copy", "value", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.actual_ckr


# ---------------------------------------------------------------------------
# Fix round 2 RED contracts (F1-F13). Each asserts the corrected verdict; they
# RED on the pre-fix production code and GREEN after the corresponding fix.
# ---------------------------------------------------------------------------


def test_f1_control_sequence_is_init_login_sign() -> None:
    """F1: control MUST be Init -> context-login -> Sign (no re-Init after login)."""
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "ignored-input", record.detail
    # Premise Init+Sign, control Init+login+Sign, post-change Init+Sign.
    assert fake.op_sequence == [
        "init",
        "sign",
        "init",
        "login",
        "sign",
        "init",
        "sign",
    ], fake.op_sequence


def test_f1_private_template_explicit() -> None:
    """F1: the QC3 RSA private template requests CKA_PRIVATE=True explicitly."""
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    assert fake.keypair_calls, "keygen never attempted"
    _pub_raw, priv_raw = fake.keypair_calls[0]
    decoded = {attr: _CopyFake._decoded_value(attr, blob) for attr, blob in priv_raw.items()}
    assert decoded.get(int(CKA_PRIVATE)) is True, decoded


def test_f1_false_private_default_proceeds_with_explicit() -> None:
    """F1: a false-PRIVATE-default provider proceeds only with explicit PRIVATE=True."""
    fake = _CopyFake(copy_mode="ignore", require_explicit_private=True)
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "ignored-input", record.detail


def test_f1_fake_lifecycle_login_without_op_returns_not_initialized() -> None:
    """F1/F9: failed Sign ends the op; login without an active op is rejected."""
    from pkcs11_check.raw.pack import mech_simple
    from pkcs11_check.raw.recipes import gen_rsa_keypair

    fake = _CopyFake()
    rs = _reauth_rs(fake)
    _pub, priv = gen_rsa_keypair(
        rs.raw, rs.sh, bits=2048, private_attrs={CKA_SIGN: True, CKA_ALWAYS_AUTHENTICATE: True}
    )
    # Init -> Sign without login fails auth-shaped and ends the op.
    mech = mech_simple(CKM_SHA256_RSA_PKCS)
    assert int(rs.raw.C_SignInit(rs.sh, mech.byref(), priv)) == _OK
    msg = b"lifecycle-probe"
    msg_buf = (ctypes.c_ubyte * len(msg))(*msg)
    sig_buf = (ctypes.c_ubyte * 256)()
    sig_len = ctypes.c_ulong(256)
    rv = int(rs.raw.C_Sign(rs.sh, msg_buf, len(msg), sig_buf, ctypes.byref(sig_len)))
    assert rv == _NOT_LOGGED_IN, ckr_name(rv)
    # Login without a fresh Init is OPERATION_NOT_INITIALIZED.
    pin_buf = (ctypes.c_ubyte * 4)(*b"1234")
    rv_login = int(rs.raw.C_Login(rs.sh, _CONTEXT_SPECIFIC, pin_buf, 4))
    assert rv_login == _OP_NOT_INITIALIZED, ckr_name(rv_login)
    # Fresh Init -> login -> Sign succeeds.
    assert int(rs.raw.C_SignInit(rs.sh, mech.byref(), priv)) == _OK
    assert int(rs.raw.C_Login(rs.sh, _CONTEXT_SPECIFIC, pin_buf, 4)) == _OK
    sig_len2 = ctypes.c_ulong(256)
    assert int(rs.raw.C_Sign(rs.sh, msg_buf, len(msg), sig_buf, ctypes.byref(sig_len2))) == _OK


def test_f2_widen_premise_action_prohibited_is_unproved() -> None:
    """F2: ACTION_PROHIBITED never proves a CBC restriction (premise void, RV kept)."""
    fake = _CopyFake(encrypt_rv={("create", _CBC): _ACTION_PROHIBITED})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_ACTION_PROHIBITED", record.actual_ckr
    assert "restriction unproved" in (record.summary or ""), record.summary


def test_f2_narrow_verdict_action_prohibited_is_unproved() -> None:
    """F2: narrowed list + ACTION_PROHIBITED is unproved (never forbidden-mutation)."""
    fake = _CopyFake(copy_mode="apply", encrypt_rv={("copy", _CBC): _ACTION_PROHIBITED})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("refusal_policy_shaped") is False, record.detail


def test_f2_widen_ignored_action_prohibited_is_unproved() -> None:
    """F2: unchanged list + ACTION_PROHIBITED is unproved (never ignored-input)."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("copy", _CBC): _ACTION_PROHIBITED})
    assert_xfails(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert "ignored" not in (record.summary or "").lower(), record.summary


def test_f3_qc3a_missing_readback_behaves_original_is_unproved() -> None:
    """F3: missing readback + behaves-original is unproved (never 'readback unchanged')."""
    fake = _CopyFake(copy_mode="ignore", copy_hide={int(CKA_VALUE)})
    assert_xfails(_qc3a_material, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert "unchanged" not in (record.summary or ""), record.summary


def test_f3_qc3b_value_copy_missing_readback_is_unproved() -> None:
    """F3 (shared helper): the QC3b value leg applies the same present-readback rule."""
    fake = _CopyFake(copy_mode="ignore", copy_hide={int(CKA_VALUE)})
    assert_xfails(_qc3b, "copy", "value", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


_WITNESS_24 = bytes(range(0x40, 0x58))
assert len(_WITNESS_24) == 24


def test_f4_empty_premise_value_voids() -> None:
    """F4a: an empty SET-premise value voids (never a source-exposure FAIL)."""
    fake = _CopyFake(set_mode="ignore", raw_readback={("create", int(CKA_VALUE)): b""})
    assert_xfails(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert "premise void" in (record.summary or ""), record.summary
    assert fake.set_calls == []


def test_f4_unrelated_premise_value_voids() -> None:
    """F4a: an unrelated premise value without a witness voids (never FAILs)."""
    fake = _CopyFake(set_mode="ignore", raw_readback={("create", int(CKA_VALUE)): _GARBAGE_VALUE})
    assert_xfails(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert "premise void" in (record.summary or ""), record.summary
    assert fake.set_calls == []


def test_f4_24byte_witness_post_change_fails() -> None:
    """F4b: a 24-byte read value reproducing ciphertext is proved exposure (FAIL)."""
    fake = _CopyFake(
        copy_mode="apply",
        copy_crypto_value=_WITNESS_24,
        raw_readback={("copy", int(CKA_VALUE)): _WITNESS_24},
    )
    _run_must_fail(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert (record.detail or {}).get("witness_match") is True, record.detail
    assert (record.detail or {}).get("value_len") == 24, record.detail


def _decoded_create_template(fake: _CopyFake, index: int) -> dict[int, Any]:
    return {
        attr: _CopyFake._decoded_value(attr, blob)
        for attr, blob in fake.create_templates[index].items()
    }


def test_f5_qc3b_wrapper_requests_unwrap() -> None:
    """F5: the QC3b wrapper import requests CKA_UNWRAP=True (operable chain)."""
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    assert len(fake.create_templates) >= 2, fake.create_templates
    wrapper = _decoded_create_template(fake, 1)
    assert wrapper.get(int(CKA_UNWRAP)) is True, wrapper
    assert wrapper.get(int(CKA_WRAP)) is True, wrapper


def test_f5_qc3c_wrapper_requests_unwrap() -> None:
    """F5: the QC3c wrapper import requests CKA_UNWRAP=True (operable control)."""
    fake = _CopyFake(copy_mode="apply", extractable_default=False)
    try:
        _qc3c(_rs(fake))
    except (XFailed, Failed, Skipped):
        pass
    assert len(fake.create_templates) >= 2, fake.create_templates
    # The wrapper is the second creation (source, wrapper, control).
    wrapper = _decoded_create_template(fake, 1)
    assert wrapper.get(int(CKA_UNWRAP)) is True, wrapper


def test_f5_fake_unwrap_enforces_permission() -> None:
    """F5/F9: C_UnwrapKey enforces CKA_UNWRAP (explicit False or false default)."""
    from pkcs11_check.raw.recipes import unwrap_key as _unwrap

    # Explicit False always refuses.
    fake = _CopyFake()
    rs = _rs(fake)
    kek_holder = gen_aes_key(
        rs.raw, rs.sh, 128, attrs={CKA_WRAP: True, CKA_UNWRAP: False, CKA_EXTRACTABLE: True}
    )
    target = import_secret_key(rs.raw, rs.sh, CKK_AES, _ORIG_VALUE, attrs={CKA_EXTRACTABLE: True})
    blob = wrap_key(rs.raw, rs.sh, kek_holder, target, CKM_AES_KEY_WRAP)
    # Flip the wrapper to UNWRAP=False is already the case; unwrap must refuse.
    from pkcs11_check.raw.rv import CkrAssertionError as _CkrErr

    try:
        _unwrap(
            rs.raw,
            rs.sh,
            kek_holder,
            blob,
            CKM_AES_KEY_WRAP,
            attrs={CKA_CLASS: CKO_SECRET_KEY, CKA_KEY_TYPE: CKK_AES},
        )
        raise AssertionError("unwrap with UNWRAP=False must refuse")
    except _CkrErr as exc:
        assert exc.rv == _KEY_NOT_PERMITTED, ckr_name(exc.rv)
    # Omitted UNWRAP with a false default refuses as well.
    strict = _CopyFake(unwrap_default=False)
    rs2 = _rs(strict)
    holder2 = gen_aes_key(rs2.raw, rs2.sh, 128, attrs={CKA_WRAP: True, CKA_EXTRACTABLE: True})
    target2 = import_secret_key(
        rs2.raw, rs2.sh, CKK_AES, _ORIG_VALUE, attrs={CKA_EXTRACTABLE: True}
    )
    blob2 = wrap_key(rs2.raw, rs2.sh, holder2, target2, CKM_AES_KEY_WRAP)
    try:
        _unwrap(
            rs2.raw,
            rs2.sh,
            holder2,
            blob2,
            CKM_AES_KEY_WRAP,
            attrs={CKA_CLASS: CKO_SECRET_KEY, CKA_KEY_TYPE: CKK_AES},
        )
        raise AssertionError("unwrap with omitted UNWRAP on false-default must refuse")
    except _CkrErr as exc:
        assert exc.rv == _KEY_NOT_PERMITTED, ckr_name(exc.rv)


_KEK_KNOWN = bytes(range(0x70, 0x80))
_UNRELATED_CONST = bytes(range(0x01, 0x11))


def test_f6_oracle_validates_genuine() -> None:
    """F6b: local KW unwrap under the known KEK proving K'==target validates."""
    mod = _mutability_table()
    blob = aes_key_wrap(_KEK_KNOWN, _ORIG_VALUE)
    result = mod.validate_wrap_chain(blob, kek=_KEK_KNOWN, expected_key=_ORIG_VALUE, label="t")
    assert result.validated is True, result.evidence
    assert result.evidence.get("key_match") is True, result.evidence


def test_f6_oracle_rejects_unrelated_constant() -> None:
    """F6b/c: KW of an unrelated constant never validates (no provider agreement)."""
    mod = _mutability_table()
    blob = aes_key_wrap(_KEK_KNOWN, _UNRELATED_CONST)
    result = mod.validate_wrap_chain(blob, kek=_KEK_KNOWN, expected_key=_ORIG_VALUE, label="t")
    assert result.validated is False, result.evidence
    assert result.evidence.get("key_match") is False, result.evidence


def test_f6_oracle_rejects_empty() -> None:
    """F6b/d: an empty blob never validates (no unwrap attempted)."""
    mod = _mutability_table()
    result = mod.validate_wrap_chain(b"", kek=_KEK_KNOWN, expected_key=_ORIG_VALUE, label="t")
    assert result.validated is False, result.evidence
    assert result.evidence.get("blob_len") == 0, result.evidence


def test_f6_oracle_rejects_malformed_kw_length() -> None:
    """F6d: KW blobs must be non-empty multiples of 8 (malformed -> unvalidated)."""
    mod = _mutability_table()
    result = mod.validate_wrap_chain(
        b"\x00" * 10, kek=_KEK_KNOWN, expected_key=_ORIG_VALUE, label="t"
    )
    assert result.validated is False, result.evidence
    assert result.evidence.get("blob_len") == 10, result.evidence


def test_f6_oracle_rejects_invalid_wrap() -> None:
    """F6b: a well-formed-length blob failing local unwrap never validates."""
    mod = _mutability_table()
    result = mod.validate_wrap_chain(
        b"\x00" * 24, kek=_KEK_KNOWN, expected_key=_ORIG_VALUE, label="t"
    )
    assert result.validated is False, result.evidence


def test_f6_qc3c_unrelated_wrap_with_broken_encrypt_is_unproved() -> None:
    """F6c: unrelated wrap + broken-constant Encrypt is unproved (never exposure)."""
    # Pre-fix wrapper KEK is the deterministic GenerateKey value for handle 102
    # (source 100, copy 101, wrapper 102): bytes 103..118. Wrapping the
    # unrelated constant under it makes the old reference mode unwrap honestly
    # and then falsely validate via broken-Encrypt agreement (FAIL). Post-fix
    # the oracle uses the known import KEK, so this blob fails local unwrap
    # (different KEK) and correctly unproves. Either way the verdict must be
    # unproved, never exposure.
    prefix_wrapper_kek = bytes([(102 + i) % 251 + 1 for i in range(16)])
    unrelated_blob = aes_key_wrap(prefix_wrapper_kek, _UNRELATED_CONST)
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        copy_force_extractable=True,
        wrap_constant_for={"copy"},
        wrap_constant_blob=unrelated_blob,
        encrypt_constant=b"\x11" * 16,
    )
    assert_xfails(_qc3c, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def test_f6_qc3b_genuine_with_broken_encrypt_still_fails() -> None:
    """F6b: genuine exposure proves via local oracle despite broken provider use."""
    fake = _CopyFake(copy_mode="apply", encrypt_constant=b"\x22" * 16)
    _run_must_fail(_qc3b, "copy", "extractable_escalate", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "wrap validated" in (record.summary or "") or "escalation" in (record.summary or ""), (
        record.summary
    )


def test_f6_ecb_malformed_length_fails_wrong_result() -> None:
    """G5 re-verdict of F6d: a 32-byte successful ECB output is wrong_result FAIL."""
    fake = _CopyFake(copy_mode="ignore", encrypt_constant=b"\x33" * 32)
    _run_must_fail(_qc3a_material, _rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert "malformed" in (record.summary or ""), record.summary
    assert (record.detail or {}).get("baseline_len") == 32, record.detail


def test_f7_two_byte_flag_is_unproved() -> None:
    """F7: a 2-byte ALWAYS_AUTHENTICATE setup readback voids (never wrong_result)."""
    fake = _CopyFake(
        copy_mode="ignore", raw_readback={("create", int(CKA_ALWAYS_AUTHENTICATE)): b"\x00\x00"}
    )
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("not_operational")
    assert "premise void" in (record.summary or "") or "malformed" in (record.summary or ""), (
        record.summary
    )


def test_f7_dropped_flag_voids() -> None:
    """F7: a setup persisting ALWAYS_AUTHENTICATE=False voids (never FAILs)."""
    fake = _CopyFake(
        copy_mode="ignore", raw_readback={("create", int(CKA_ALWAYS_AUTHENTICATE)): b"\x00"}
    )
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("not_operational")


def test_f7_unreadable_setup_voids() -> None:
    """F7: an unreadable setup flag voids via xfail (never a quiet skip)."""
    fake = _CopyFake(copy_mode="ignore", create_hide={int(CKA_ALWAYS_AUTHENTICATE)})
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("not_operational")


def test_f8_keymgmt_baseline_undefined_fails() -> None:
    """F8: a QC3a baseline with an undefined RV fails the RV contract (never void)."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("create", _ECB): _UNDEFINED_RV})
    _run_must_fail(_qc3a_material, _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_f8_keymgmt_baseline_vendor_xfails_nonspec() -> None:
    """F8: a QC3a baseline with a vendor RV is an alternate xfail (never void)."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("create", _ECB): _VENDOR_RV})
    assert_xfails(_qc3a_material, _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_f8_table_baseline_undefined_fails() -> None:
    """F8: a QC3b value baseline with an undefined RV fails (never void)."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("create", _ECB): _UNDEFINED_RV})
    _run_must_fail(_qc3b, "copy", "value", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_f8_table_baseline_vendor_xfails_nonspec() -> None:
    """F8: a QC3b value baseline with a vendor RV is an alternate xfail."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("create", _ECB): _VENDOR_RV})
    assert_xfails(_qc3b, "copy", "value", _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_f8_copy_source_undefined_fails() -> None:
    """F8: a QC3a source creator with an undefined RV fails (never unclassified)."""
    fake = _CopyFake(create_script=[_UNDEFINED_RV])
    _run_must_fail(_qc3a_material, _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_f8_copy_source_vendor_xfails_nonspec() -> None:
    """F8: a QC3a source creator with a vendor RV is an alternate xfail."""
    fake = _CopyFake(create_script=[_VENDOR_RV])
    assert_xfails(_qc3a_material, _rs(fake))
    _assert_xfail_record("nonspec_reject")


def test_f8_table_source_undefined_fails() -> None:
    """F8: a QC3b table source creator with an undefined RV fails."""
    fake = _CopyFake(create_script=[_UNDEFINED_RV])
    _run_must_fail(_qc3b, "copy", "value", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_f8_table_wrapper_undefined_fails() -> None:
    """F8: a QC3b wrapper creator with an undefined RV fails (never unclassified)."""
    fake = _CopyFake(create_script=[_OK, _UNDEFINED_RV])
    _run_must_fail(_qc3b, "copy", "extractable_escalate", _rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_f8_rsa_setup_undefined_fails() -> None:
    """F8: a QC3 RSA setup with an undefined RV fails the RV contract."""
    fake = _CopyFake(copy_mode="ignore", keypair_script=[_UNDEFINED_RV])
    _run_must_fail(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_fail_record("self_contradiction", "metadata")


def test_f9_keymgmt_baseline_refusal_voids() -> None:
    """F9/I14: a refused QC3a baseline voids with the RV preserved (terminal)."""
    fake = _CopyFake(copy_mode="ignore", encrypt_rv={("create", _ECB): _DEVICE_ERROR})
    assert_xfails(_qc3a_material, _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.actual_ckr


def test_f9_control_refusal_standard_is_deviation() -> None:
    """F9/I14: a standard-RV label refusal is a control-deviation xfail (terminal)."""
    fake = _CopyFake(copy_refuse_rv=_DEVICE_ERROR)
    assert_xfails(_qc3b, "copy", "label_control", _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.actual_ckr


def test_f9_control_refusal_not_supported_skips() -> None:
    """F9/I14: a NOT_SUPPORTED label refusal skips (unsupported control, terminal)."""
    from tests._skip_assert import assert_skips as _assert_skips

    fake = _CopyFake(copy_refuse_rv=_NOT_SUPPORTED)
    _assert_skips(_qc3b, "copy", "label_control", _rs(fake))


def test_f9_set_reauth_no_pin_skips() -> None:
    """F9/I14: set re-auth without a PIN skips before keygen (terminal branch)."""
    from tests._skip_assert import assert_skips as _assert_skips

    fake = _CopyFake(set_mode="ignore")
    _assert_skips(_qc3b, "set", "always_authenticate", _reauth_rs(fake), _NO_PIN_CONFIG)
    assert fake.keypair_calls == [], "no keygen without a PIN"


def test_f10_corrupt_control_sig_fails_wrong_result() -> None:
    """F10/N1: an invalid successful control signature is crypto wrong_result (never void)."""
    fake = _CopyFake(copy_mode="ignore", sign_corrupt=True)
    _run_must_fail(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert "verification" in (record.summary or "") or "signature" in (record.summary or ""), (
        record.summary
    )


def test_f10_corrupt_post_change_sig_fails_wrong_result_not_bypass() -> None:
    """F10/N1: an invalid post-change signature is wrong_result (must NOT claim bypass)."""
    fake = _CopyFake(copy_mode="ignore", sign_script=[None, None, _OK])
    _run_must_fail(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert "bypassed" not in (record.summary or "").lower(), record.summary
    assert "invalid" in (record.summary or "").lower(), record.summary


def test_f10_valid_bypass_still_fails_bypass() -> None:
    """F10 guard: a VALID post-change signature without re-auth is still a bypass FAIL."""
    fake = _CopyFake(copy_mode="ignore", reauth_single_use=False)
    _run_must_fail(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "bypassed" in (record.summary or ""), record.summary


_PLANTED_KEY = b"PLANTED-KEY-1234"
assert len(_PLANTED_KEY) == 16


def _all_record_text() -> str:
    parts: list[str] = []
    for rec in C.get_records():
        parts.append(repr(rec.summary))
        parts.append(repr(rec.detail))
        parts.append(repr(rec))
    return "\n".join(parts)


def test_f11_planted_key_bytes_in_malformed_extractable_redacted() -> None:
    """F11/N2: malformed EXTRACTABLE evidence never interpolates value bytes (SECRET LEAK)."""
    fake = _CopyFake(
        copy_mode="ignore", raw_readback={("copy", int(CKA_EXTRACTABLE)): _PLANTED_KEY}
    )
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    _assert_xfail_record("honest_deviation")
    haystack = _all_record_text()
    assert _PLANTED_KEY.decode("latin1") not in haystack, haystack
    assert repr(_PLANTED_KEY) not in haystack, haystack


def test_f11_planted_key_bytes_in_malformed_flag_redacted() -> None:
    """F11/N2: malformed flag evidence never interpolates value bytes (SECRET LEAK)."""
    fake = _CopyFake(copy_mode="ignore", raw_readback={("copy", int(CKA_SENSITIVE)): _PLANTED_KEY})
    assert_xfails(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    _assert_xfail_record("honest_deviation")
    haystack = _all_record_text()
    assert _PLANTED_KEY.decode("latin1") not in haystack, haystack
    assert repr(_PLANTED_KEY) not in haystack, haystack


def test_f11_always_auth_malformed_redacted() -> None:
    """F11/N2: the shared malformed-flag path redacts to type+length (minimal edit)."""
    from pkcs11_check.testcases import test_always_authenticate as _tauth

    fake = _CopyFake(raw_readback={("create", int(CKA_ALWAYS_AUTHENTICATE)): _PLANTED_KEY})
    rs = _reauth_rs(fake)
    _run_must_fail(_tauth._try_gen_always_auth_keypair, rs)
    _assert_fail_record("wrong_result", "policy")
    haystack = _all_record_text()
    assert _PLANTED_KEY.decode("latin1") not in haystack, haystack
    assert repr(_PLANTED_KEY) not in haystack, haystack


def test_f12_zero_prefixed_modulus_proceeds() -> None:
    """F12/N3: a zero-prefixed legal 2048-bit modulus does NOT void the leg."""
    fake = _CopyFake(copy_mode="ignore")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fake._rsa_key = key  # pre-seed so the control signature verifies
    numbers = key.public_key().public_numbers()
    modulus = int(numbers.n).to_bytes(256, "big")
    fake._raw_readback[("create", int(CKA_MODULUS))] = b"\x00" + modulus
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "ignored-input", record.detail


def test_f12_degenerate_zero_modulus_voids() -> None:
    """F12/N3: a zero modulus voids (degenerate numeric value, never verified)."""
    fake = _CopyFake(copy_mode="ignore", raw_readback={("create", int(CKA_MODULUS)): b"\x00"})
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("not_operational")


def test_f12_degenerate_tiny_modulus_voids() -> None:
    """F12/N3: a tiny modulus voids (bit_length far below 2048-class bounds)."""
    fake = _CopyFake(
        copy_mode="ignore", raw_readback={("create", int(CKA_MODULUS)): b"\x01\x00\x01"}
    )
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    _assert_xfail_record("not_operational")


def test_f13_qc3c_unproved_carries_ok() -> None:
    """F13/M1: accepted-wrap unproved records carry actual=CKR_OK (validation in detail)."""
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        copy_force_extractable=True,
        wrap_empty_for={"copy"},
    )
    assert_xfails(_qc3c, _rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


def test_f13_qc3c_exposure_carries_ok() -> None:
    """F13/M1: accepted-wrap exposure FAIL records carry actual=CKR_OK."""
    fake = _CopyFake(copy_mode="apply", extractable_default=False, copy_force_extractable=True)
    _run_must_fail(_qc3c, _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert record.actual_ckr == "CKR_OK", record.actual_ckr


# ---------------------------------------------------------------------------
# Fix round 3 (re-review #2 NEEDS-REPAIR: G1-G5). Every contract below drives
# its production leg through the real provider function against the fake.
# ---------------------------------------------------------------------------


def _round3_local_ecb(key: bytes, block: bytes) -> bytes:
    """Local AES-ECB oracle for round-3 seeds (independent of the fake)."""
    worker = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # nosec B305
    return worker.update(block) + worker.finalize()


def _round3_flip_first(block: bytes) -> bytes:
    """Return *block* with the first byte flipped (a guaranteed oracle miss)."""
    return bytes([block[0] ^ 0xFF]) + block[1:]


def test_g1_zero_exponent_premise_voids_unproved() -> None:
    """G1/N1: a zero-exponent control oracle voids unproved (never invalid-sig)."""
    fake = _CopyFake(
        copy_mode="ignore", raw_readback={("create", int(CKA_PUBLIC_EXPONENT)): b"\x00"}
    )
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.kind == "policy", record.kind
    assert "invalid signature" not in (record.summary or "").lower(), record.summary
    assert "invalid" not in (record.summary or "").lower(), record.summary
    assert "unverifiable" in (record.summary or ""), record.summary
    # H1 re-verdict: lengths + booleans only, never the integer.
    assert (record.detail or {}).get("exponent_len") == 1, record.detail
    assert (record.detail or {}).get("usable_oracle") is False, record.detail
    _assert_cleaned_up(fake)


def test_g1_zero_exponent_post_change_unproved() -> None:
    """G1/N1: a zero-exponent post-change oracle unproves (never invalid, never bypass)."""
    fake = _CopyFake(copy_mode="apply", raw_readback={("copy", int(CKA_PUBLIC_EXPONENT)): b"\x00"})
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert "invalid signature" not in (record.summary or "").lower(), record.summary
    assert "invalid" not in (record.summary or "").lower(), record.summary
    assert "bypass unproved" in (record.summary or ""), record.summary
    # H1 re-verdict: lengths + booleans only, never the integer.
    assert (record.detail or {}).get("exponent_len") == 1, record.detail
    assert (record.detail or {}).get("usable_oracle") is False, record.detail
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    _assert_cleaned_up(fake)


def test_g2_qc3a_source_device_error_xfails() -> None:
    """G2/I13: a QC3a source CKR_DEVICE_ERROR is a classified xfail (never escape)."""
    fake = _CopyFake(create_script=[_DEVICE_ERROR])
    assert_xfails(_qc3a_material, _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.actual_ckr
    assert "clean unavailable setup" in (record.summary or ""), record.summary


def test_g2_qc3a_source_function_failed_xfails() -> None:
    """G2/I13: a QC3a source CKR_FUNCTION_FAILED is a classified xfail (never escape)."""
    fake = _CopyFake(create_script=[_FUNCTION_FAILED])
    assert_xfails(_qc3a_material, _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_FUNCTION_FAILED", record.actual_ckr
    assert "clean unavailable setup" in (record.summary or ""), record.summary


def test_g2_table_source_device_error_xfails() -> None:
    """G2/I13: a QC3b table-source CKR_DEVICE_ERROR is a classified xfail (tuple member)."""
    fake = _CopyFake(create_script=[_DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "value", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.actual_ckr
    assert "expected-setup-refusal" in (record.summary or ""), record.summary


def test_g2_table_source_nontuple_refusal_xfails() -> None:
    """G2/I13: a non-tuple QC3b table-source refusal is a classified generic xfail."""
    fake = _CopyFake(create_script=[_TOKEN_NOT_PRESENT])
    assert_xfails(_qc3b, "copy", "value", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_TOKEN_NOT_PRESENT", record.actual_ckr
    assert "clean unavailable setup" in (record.summary or ""), record.summary


def test_g2_table_source_tuple_refusal_keeps_expected_wording() -> None:
    """G2/I13: a tuple-member setup refusal xfails with expected-refusal wording."""
    fake = _CopyFake(create_script=[_TEMPLATE_INCONSISTENT])
    assert_xfails(_qc3b, "copy", "value", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_TEMPLATE_INCONSISTENT", record.actual_ckr
    assert "expected-setup-refusal" in (record.summary or ""), record.summary


def test_g2_table_wrapper_device_error_xfails() -> None:
    """G2/I13: a QC3b wrapper CKR_DEVICE_ERROR is a classified xfail (tuple member)."""
    fake = _CopyFake(create_script=[_OK, _DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.actual_ckr
    assert "expected-setup-refusal" in (record.summary or ""), record.summary


def test_g2_table_wrapper_nontuple_refusal_xfails() -> None:
    """G2/I13: a non-tuple QC3b wrapper refusal is a classified generic xfail."""
    fake = _CopyFake(create_script=[_OK, _TOKEN_NOT_PRESENT])
    assert_xfails(_qc3b, "copy", "extractable_escalate", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_TOKEN_NOT_PRESENT", record.actual_ckr
    assert "clean unavailable setup" in (record.summary or ""), record.summary


def test_g2_qc3c_source_device_error_xfails() -> None:
    """G2/I13: a QC3c source CKR_DEVICE_ERROR is a classified xfail (never escape)."""
    fake = _CopyFake(create_script=[_DEVICE_ERROR])
    assert_xfails(_qc3c, _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.actual_ckr
    assert "clean unavailable setup" in (record.summary or ""), record.summary


def test_g2_qc3c_source_function_failed_xfails() -> None:
    """G2/I13: a QC3c source CKR_FUNCTION_FAILED is a classified xfail (never escape)."""
    fake = _CopyFake(create_script=[_FUNCTION_FAILED])
    assert_xfails(_qc3c, _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_FUNCTION_FAILED", record.actual_ckr
    assert "clean unavailable setup" in (record.summary or ""), record.summary


def test_g2_qc3c_wrapper_device_error_xfails() -> None:
    """G2/I13: a QC3c wrapper CKR_DEVICE_ERROR is a classified xfail (never escape)."""
    fake = _CopyFake(
        copy_mode="apply", extractable_default=False, create_script=[_OK, _DEVICE_ERROR]
    )
    assert_xfails(_qc3c, _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.actual_ckr
    assert "clean unavailable setup" in (record.summary or ""), record.summary


def test_g2_qc3c_wrapper_function_failed_xfails() -> None:
    """G2/I13: a QC3c wrapper CKR_FUNCTION_FAILED is a classified xfail (never escape)."""
    fake = _CopyFake(
        copy_mode="apply", extractable_default=False, create_script=[_OK, _FUNCTION_FAILED]
    )
    assert_xfails(_qc3c, _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_FUNCTION_FAILED", record.actual_ckr
    assert "clean unavailable setup" in (record.summary or ""), record.summary


def test_g2_qc3c_control_device_error_xfails() -> None:
    """G2/I13: a QC3c control CKR_DEVICE_ERROR is a classified xfail (never escape)."""
    fake = _CopyFake(
        copy_mode="apply", extractable_default=False, create_script=[_OK, _OK, _DEVICE_ERROR]
    )
    assert_xfails(_qc3c, _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.actual_ckr
    assert "clean unavailable setup" in (record.summary or ""), record.summary


def test_g2_qc3c_control_function_failed_xfails() -> None:
    """G2/I13: a QC3c control CKR_FUNCTION_FAILED is a classified xfail (never escape)."""
    fake = _CopyFake(
        copy_mode="apply",
        extractable_default=False,
        create_script=[_OK, _OK, _FUNCTION_FAILED],
    )
    assert_xfails(_qc3c, _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == "CKR_FUNCTION_FAILED", record.actual_ckr
    assert "clean unavailable setup" in (record.summary or ""), record.summary


def test_g2_rsa_setup_device_error_xfails() -> None:
    """G2/I13 audit: a QC3 RSA-setup CKR_DEVICE_ERROR is a classified metadata xfail."""
    fake = _CopyFake(copy_mode="ignore", keypair_script=[_DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.kind == "metadata", record.kind
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.actual_ckr


def test_g2_rsa_setup_function_failed_xfails() -> None:
    """G2/I13 audit: a QC3 RSA-setup CKR_FUNCTION_FAILED is a classified metadata xfail."""
    fake = _CopyFake(copy_mode="ignore", keypair_script=[_FUNCTION_FAILED])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.kind == "metadata", record.kind
    assert record.actual_ckr == "CKR_FUNCTION_FAILED", record.actual_ckr


def test_g3a_fresh_control_init_refusal_voids() -> None:
    """G3/I14(a): a refused fresh control Init voids with the RV preserved (terminal)."""
    fake = _CopyFake(copy_mode="ignore", sign_init_script=[None, _DEVICE_ERROR])
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.kind == "policy", record.kind
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.actual_ckr
    assert "control Init" in (record.summary or ""), record.summary
    assert "CKR_DEVICE_ERROR" in (record.summary or ""), record.summary
    assert fake.login_calls == [], "control Init refusal voids before any login"
    _assert_cleaned_up(fake)


def test_g3b_witness_use_refusal_voids() -> None:
    """G3/I14(b): a refused premise witness use voids with RV evidence (terminal)."""
    fake = _CopyFake(
        set_mode="ignore",
        raw_readback={("create", int(CKA_VALUE)): _GARBAGE_VALUE},
        encrypt_rv={("create", _ECB): _DEVICE_ERROR},
    )
    assert_xfails(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.kind == "policy", record.kind
    assert "witness unavailable" in (record.summary or ""), record.summary
    assert "CKR_DEVICE_ERROR" in (record.summary or ""), record.summary
    assert (record.detail or {}).get("value_len") == 16, record.detail
    assert (record.detail or {}).get("matches_original") is False, record.detail
    assert (record.detail or {}).get("witness_match") is None, record.detail
    assert (record.detail or {}).get("use_rv") == "CKR_DEVICE_ERROR", record.detail
    assert fake.set_calls == [], "premise must void before the change is attempted"
    _assert_cleaned_up(fake)


def test_g3c_witness_match_premise_fails_with_setup_attribution() -> None:
    """G3/I14(c): a matching premise witness fails with setup attribution (terminal)."""
    witness = bytes(range(0x60, 0x70))
    assert witness != _ORIG_VALUE
    fake = _CopyFake(
        set_mode="ignore",
        raw_readback={("create", int(CKA_VALUE)): witness},
        encrypt_constant=_round3_local_ecb(witness, _PROBE_PT),
    )
    _run_must_fail(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "setup observation" in (record.summary or ""), record.summary
    assert "not caused by the attempted change" in (record.summary or ""), record.summary
    assert (record.detail or {}).get("value_len") == 16, record.detail
    assert (record.detail or {}).get("matches_original") is False, record.detail
    assert (record.detail or {}).get("witness_match") is True, record.detail
    assert fake.set_calls == [], "premise must fail before the change is attempted"
    _assert_cleaned_up(fake)


def test_g3d_post_sign_missing_pubkey_unproved() -> None:
    """G3/I14(d): post-sign missing pubkey attributes unprove the bypass (terminal)."""
    fake = _CopyFake(copy_mode="apply", copy_hide={int(CKA_MODULUS), int(CKA_PUBLIC_EXPONENT)})
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert record.kind == "policy", record.kind
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("no_reauth_use_completed") is True, record.detail
    assert (record.detail or {}).get("sig_len") == 256, record.detail
    assert "unreadable" in (record.summary or ""), record.summary
    assert "bypass unproved" in (record.summary or ""), record.summary
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    _assert_cleaned_up(fake)


def test_g3e_post_sign_malformed_pubkey_unproved() -> None:
    """G3/I14(e): post-sign malformed pubkey attributes unprove the bypass (terminal)."""
    fake = _CopyFake(copy_mode="apply", raw_readback={("copy", int(CKA_MODULUS)): b"short"})
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert record.kind == "policy", record.kind
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("no_reauth_use_completed") is True, record.detail
    assert (record.detail or {}).get("sig_len") == 256, record.detail
    assert "malformed" in (record.summary or ""), record.summary
    assert "bypass unproved" in (record.summary or ""), record.summary
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    _assert_cleaned_up(fake)


def _round3_wrong_ecb() -> bytes:
    """A well-formed-length ECB block the known-key oracle must reject."""
    return _round3_flip_first(_round3_local_ecb(_ORIG_VALUE, _PROBE_PT))


def test_g4a_widen_verify_cbc_dispatch_fails_wrong_result() -> None:
    """G4: CBC-dispatched-to-ECB output is wrong_result (must NOT claim bypass)."""
    fake = _CopyFake(copy_mode="apply", cbc_as_ecb_for={"copy"})
    _run_must_fail(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert "bypass" not in (record.summary or "").lower(), record.summary
    assert "took effect" not in (record.summary or ""), record.summary
    assert "wrong output" in (record.summary or ""), record.summary
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    _assert_cleaned_up(fake)


def test_g4b_narrow_verify_cbc_dispatch_fails_wrong_result() -> None:
    """G4: a dispatched CBC completion is wrong_result (never ignored-input)."""
    fake = _CopyFake(copy_mode="ignore", cbc_as_ecb_for={"copy"})
    _run_must_fail(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert "ignored" not in (record.summary or "").lower(), record.summary
    assert "wrong output" in (record.summary or ""), record.summary
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    _assert_cleaned_up(fake)


def test_g4c_narrow_premise_cbc_dispatch_fails_wrong_result() -> None:
    """G4: a dispatched narrow-premise CBC control is wrong_result (never control)."""
    fake = _CopyFake(copy_mode="ignore", cbc_as_ecb_for={"create"})
    _run_must_fail(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert "wrong output" in (record.summary or ""), record.summary
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    assert fake.copy_calls == [], "premise must fail before the change is attempted"
    _assert_cleaned_up(fake)


def test_g4d_widen_premise_cbc_dispatch_fails_wrong_result() -> None:
    """G4: a dispatched widen-premise CBC completion is wrong_result (never void)."""
    fake = _CopyFake(copy_mode="ignore", ignore_allowed={"create"}, cbc_as_ecb_for={"create"})
    _run_must_fail(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert "wrong output" in (record.summary or ""), record.summary
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    assert fake.copy_calls == [], "premise must fail before the change is attempted"
    _assert_cleaned_up(fake)


def test_g4e_widen_verify_ecb_sanity_mismatch_fails() -> None:
    """G4: a mismatching widen-verify ECB sanity output is crypto wrong_result."""
    fake = _CopyFake(copy_mode="ignore", encrypt_output_for={("copy", _ECB): _round3_wrong_ecb()})
    _run_must_fail(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert "wrong output" in (record.summary or ""), record.summary
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    _assert_cleaned_up(fake)


def test_g4f_narrow_verify_ecb_sanity_mismatch_fails() -> None:
    """G4: a mismatching narrow-verify ECB sanity output is crypto wrong_result."""
    fake = _CopyFake(copy_mode="ignore", encrypt_output_for={("copy", _ECB): _round3_wrong_ecb()})
    _run_must_fail(_qc3b, "copy", "allowed_mechanisms_narrow", _rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert "wrong output" in (record.summary or ""), record.summary
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    _assert_cleaned_up(fake)


def test_g4g_widen_premise_ecb_mismatch_fails() -> None:
    """G4: a mismatching widen-premise ECB output is crypto wrong_result (never void)."""
    fake = _CopyFake(copy_mode="ignore", encrypt_output_for={("create", _ECB): _round3_wrong_ecb()})
    _run_must_fail(_qc3b, "copy", "allowed_mechanisms_widen", _rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert "wrong output" in (record.summary or ""), record.summary
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    assert fake.copy_calls == [], "premise must fail before the change is attempted"
    _assert_cleaned_up(fake)


def test_g4h_qc3a_baseline_mismatch_fails() -> None:
    """G4: a QC3a baseline the oracle rejects is crypto wrong_result (void comparison)."""
    fake = _CopyFake(copy_mode="ignore", encrypt_output_for={("create", _ECB): _round3_wrong_ecb()})
    _run_must_fail(_qc3a_material, _rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert "wrong output" in (record.summary or ""), record.summary
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    assert fake.copy_calls == [], "baseline must fail before the change is attempted"
    _assert_cleaned_up(fake)


def test_g4i_qc3b_value_baseline_mismatch_fails() -> None:
    """G4: a QC3b value baseline the oracle rejects is crypto wrong_result."""
    fake = _CopyFake(copy_mode="ignore", encrypt_output_for={("create", _ECB): _round3_wrong_ecb()})
    _run_must_fail(_qc3b, "copy", "value", _rs(fake))
    record = _assert_fail_record("wrong_result", "crypto")
    assert "wrong output" in (record.summary or ""), record.summary
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    assert fake.copy_calls == [], "baseline must fail before the change is attempted"
    _assert_cleaned_up(fake)


_G5_EMPTY = b""
_G5_SHORT = b"\x44" * 8
_G5_LONG = b"\x44" * 32


def _assert_malformed_ecb_fail() -> Any:
    """The G5 terminal shape: crypto wrong_result FAIL with length-only evidence."""
    record = _assert_fail_record("wrong_result", "crypto")
    assert "malformed" in (record.summary or ""), record.summary
    assert "unproved" not in (record.summary or "").lower(), record.summary
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    for value in (record.detail or {}).values():
        assert not isinstance(value, (bytes, bytearray)), record.detail
    return record


def test_g5a_qc3a_baseline_empty_fails() -> None:
    """G5/I5: a QC3a source encrypt returning empty output is wrong_result (never unproved)."""
    fake = _CopyFake(copy_mode="ignore", encrypt_output_for={("create", _ECB): _G5_EMPTY})
    _run_must_fail(_qc3a_material, _rs(fake))
    _assert_malformed_ecb_fail()
    _assert_cleaned_up(fake)


def test_g5b_qc3a_baseline_short_fails() -> None:
    """G5/I5: a QC3a source encrypt returning 8 bytes is wrong_result (never unproved)."""
    fake = _CopyFake(copy_mode="ignore", encrypt_output_for={("create", _ECB): _G5_SHORT})
    _run_must_fail(_qc3a_material, _rs(fake))
    _assert_malformed_ecb_fail()
    _assert_cleaned_up(fake)


def test_g5c_qc3a_baseline_long_fails() -> None:
    """G5/I5: a QC3a source encrypt returning 32 bytes is wrong_result (never unproved)."""
    fake = _CopyFake(copy_mode="ignore", encrypt_output_for={("create", _ECB): _G5_LONG})
    _run_must_fail(_qc3a_material, _rs(fake))
    _assert_malformed_ecb_fail()
    _assert_cleaned_up(fake)


def test_g5d_qc3a_copy_encrypt_empty_fails() -> None:
    """G5/I5: round-1 repro -- copy encrypt OK + empty output FAILs wrong_result again."""
    fake = _CopyFake(copy_mode="ignore", encrypt_output_for={("copy", _ECB): _G5_EMPTY})
    _run_must_fail(_qc3a_material, _rs(fake))
    record = _assert_malformed_ecb_fail()
    assert (record.detail or {}).get("observed_len") == 0, record.detail
    _assert_cleaned_up(fake)


def test_g5e_qc3a_copy_encrypt_short_fails() -> None:
    """G5/I5: copy encrypt OK + 8-byte output is crypto wrong_result (never unproved)."""
    fake = _CopyFake(copy_mode="ignore", encrypt_output_for={("copy", _ECB): _G5_SHORT})
    _run_must_fail(_qc3a_material, _rs(fake))
    record = _assert_malformed_ecb_fail()
    assert (record.detail or {}).get("observed_len") == 8, record.detail
    _assert_cleaned_up(fake)


def test_g5f_qc3a_copy_encrypt_long_fails() -> None:
    """G5/I5: copy encrypt OK + 32-byte output is crypto wrong_result (never unproved)."""
    fake = _CopyFake(copy_mode="ignore", encrypt_output_for={("copy", _ECB): _G5_LONG})
    _run_must_fail(_qc3a_material, _rs(fake))
    record = _assert_malformed_ecb_fail()
    assert (record.detail or {}).get("observed_len") == 32, record.detail
    _assert_cleaned_up(fake)


def test_g5g_qc3a_copy_decrypt_empty_fails() -> None:
    """G5/I5: copy decrypt OK + empty output is malformed wrong_result (never unproved)."""
    fake = _CopyFake(copy_mode="ignore", decrypt_output_for={("copy", _ECB): _G5_EMPTY})
    _run_must_fail(_qc3a_material, _rs(fake))
    record = _assert_malformed_ecb_fail()
    assert (record.detail or {}).get("round_trip_len") == 0, record.detail
    _assert_cleaned_up(fake)


def test_g5h_qc3a_copy_decrypt_short_fails() -> None:
    """G5/I5: copy decrypt OK + 8-byte output is malformed wrong_result (never unproved)."""
    fake = _CopyFake(copy_mode="ignore", decrypt_output_for={("copy", _ECB): _G5_SHORT})
    _run_must_fail(_qc3a_material, _rs(fake))
    record = _assert_malformed_ecb_fail()
    assert (record.detail or {}).get("round_trip_len") == 8, record.detail
    _assert_cleaned_up(fake)


def test_g5i_qc3a_copy_decrypt_long_fails() -> None:
    """G5/I5: copy decrypt OK + 32-byte output is malformed wrong_result (never unproved)."""
    fake = _CopyFake(copy_mode="ignore", decrypt_output_for={("copy", _ECB): _G5_LONG})
    _run_must_fail(_qc3a_material, _rs(fake))
    record = _assert_malformed_ecb_fail()
    assert (record.detail or {}).get("round_trip_len") == 32, record.detail
    _assert_cleaned_up(fake)


def test_g5j_qc3b_copy_value_encrypt_empty_fails() -> None:
    """G5/I5 (shared helper): the QC3b copy value leg reports the same crypto FAIL."""
    fake = _CopyFake(copy_mode="ignore", encrypt_output_for={("copy", _ECB): _G5_EMPTY})
    _run_must_fail(_qc3b, "copy", "value", _rs(fake))
    _assert_malformed_ecb_fail()
    _assert_cleaned_up(fake)


def test_g5k_qc3b_set_value_decrypt_empty_fails() -> None:
    """G5/I5 (shared helper): the QC3b set value leg reports the same crypto FAIL."""
    fake = _CopyFake(set_mode="ignore", decrypt_output_for={("create", _ECB): _G5_EMPTY})
    _run_must_fail(_qc3b, "set", "value", _rs(fake))
    record = _assert_malformed_ecb_fail()
    assert (record.detail or {}).get("round_trip_len") == 0, record.detail
    _assert_cleaned_up(fake)


# ---------------------------------------------------------------------------
# Fix round 4 (re-review #3 NEEDS-REPAIR: H1-H2). Every contract below drives
# its production leg through the real provider function against the fake.
# ---------------------------------------------------------------------------

_H1_OVERSIZED_EXPONENT = b"\x44" * 2048
assert len(_H1_OVERSIZED_EXPONENT) == 2048


def _assert_unusable_oracle_shape(record: Any, *, exponent_len: int) -> None:
    """The H1 terminal shape: lengths + validation booleans only, never the integer."""
    detail = record.detail or {}
    assert "exponent" not in detail, detail
    assert detail.get("exponent_len") == exponent_len, detail
    assert detail.get("modulus_len") == 256, detail
    assert detail.get("usable_oracle") is False, detail
    assert isinstance(detail.get("modulus_bits"), int), detail
    assert 2000 <= detail["modulus_bits"] <= 2064, detail
    for value in detail.values():
        assert not isinstance(value, (bytes, bytearray)), detail
        assert not isinstance(value, int) or abs(value) < 10000, detail
    assert "unusable for verification" in (record.summary or ""), record.summary
    assert "unverifiable" in (record.summary or ""), record.summary


def test_h1_premise_planted_exponent_redacted() -> None:
    """H1/N1+N2: a planted-secret premise exponent leaks nowhere (lengths only)."""
    secret = _PLANTED_KEY
    secret_int = int.from_bytes(secret, "big")
    fake = _CopyFake(
        copy_mode="ignore", raw_readback={("create", int(CKA_PUBLIC_EXPONENT)): secret}
    )
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.kind == "policy", record.kind
    assert "invalid" not in (record.summary or "").lower(), record.summary
    _assert_unusable_oracle_shape(record, exponent_len=len(secret))
    assert secret_int not in (record.detail or {}).values(), record.detail
    haystack = _all_record_text()
    assert secret.decode("latin1") not in haystack, haystack
    assert repr(secret) not in haystack, haystack
    assert str(secret_int) not in haystack, haystack
    _assert_cleaned_up(fake)


def test_h1_premise_oversized_exponent_unproved() -> None:
    """H1/N1+N2: a 2048-byte premise exponent xfails unproved (must not crash)."""
    fake = _CopyFake(
        copy_mode="ignore",
        raw_readback={("create", int(CKA_PUBLIC_EXPONENT)): _H1_OVERSIZED_EXPONENT},
    )
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("not_operational")
    assert record.kind == "policy", record.kind
    assert "invalid" not in (record.summary or "").lower(), record.summary
    _assert_unusable_oracle_shape(record, exponent_len=2048)
    assert len(record.summary or "") < 2000, record.summary
    _assert_cleaned_up(fake)


def test_h1_post_change_planted_exponent_redacted() -> None:
    """H1/N1+N2: a planted-secret post-change exponent leaks nowhere (lengths only)."""
    secret = _PLANTED_KEY
    secret_int = int.from_bytes(secret, "big")
    fake = _CopyFake(copy_mode="apply", raw_readback={("copy", int(CKA_PUBLIC_EXPONENT)): secret})
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert "invalid" not in (record.summary or "").lower(), record.summary
    assert "bypass unproved" in (record.summary or ""), record.summary
    _assert_unusable_oracle_shape(record, exponent_len=len(secret))
    assert secret_int not in (record.detail or {}).values(), record.detail
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    haystack = _all_record_text()
    assert secret.decode("latin1") not in haystack, haystack
    assert repr(secret) not in haystack, haystack
    assert str(secret_int) not in haystack, haystack
    _assert_cleaned_up(fake)


def test_h1_post_change_oversized_exponent_unproved() -> None:
    """H1/N1+N2: a 2048-byte post-change exponent unproves (must not crash)."""
    fake = _CopyFake(
        copy_mode="apply",
        raw_readback={("copy", int(CKA_PUBLIC_EXPONENT)): _H1_OVERSIZED_EXPONENT},
    )
    assert_xfails(_qc3b, "copy", "always_authenticate", _reauth_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert "invalid" not in (record.summary or "").lower(), record.summary
    assert "bypass unproved" in (record.summary or ""), record.summary
    _assert_unusable_oracle_shape(record, exponent_len=2048)
    assert record.actual_ckr == "CKR_OK", record.actual_ckr
    assert len(record.summary or "") < 2000, record.summary
    _assert_cleaned_up(fake)


def test_h2_premise_empty_output_fails() -> None:
    """H2/I5+G5: a SET-premise ECB use returning 0 bytes is crypto wrong_result."""
    fake = _CopyFake(
        set_mode="ignore",
        raw_readback={("create", int(CKA_VALUE)): _GARBAGE_VALUE},
        encrypt_output_for={("create", _ECB): _G5_EMPTY},
    )
    _run_must_fail(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    record = _assert_malformed_ecb_fail()
    assert (record.detail or {}).get("observed_len") == 0, record.detail
    assert fake.set_calls == [], "premise must fail before the change is attempted"
    _assert_cleaned_up(fake)


def test_h2_premise_short_output_fails() -> None:
    """H2/I5+G5: a SET-premise ECB use returning 8 bytes is crypto wrong_result."""
    fake = _CopyFake(
        set_mode="ignore",
        raw_readback={("create", int(CKA_VALUE)): _GARBAGE_VALUE},
        encrypt_output_for={("create", _ECB): _G5_SHORT},
    )
    _run_must_fail(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    record = _assert_malformed_ecb_fail()
    assert (record.detail or {}).get("observed_len") == 8, record.detail
    assert fake.set_calls == [], "premise must fail before the change is attempted"
    _assert_cleaned_up(fake)


def test_h2_premise_long_output_fails() -> None:
    """H2/I5+G5: a SET-premise ECB use returning 32 bytes is crypto wrong_result."""
    fake = _CopyFake(
        set_mode="ignore",
        raw_readback={("create", int(CKA_VALUE)): _GARBAGE_VALUE},
        encrypt_output_for={("create", _ECB): _G5_LONG},
    )
    _run_must_fail(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    record = _assert_malformed_ecb_fail()
    assert (record.detail or {}).get("observed_len") == 32, record.detail
    assert fake.set_calls == [], "premise must fail before the change is attempted"
    _assert_cleaned_up(fake)


def test_h2_post_change_empty_output_fails() -> None:
    """H2/I5+G5: a post-change witness ECB use returning 0 bytes is wrong_result."""
    fake = _CopyFake(
        copy_mode="apply",
        raw_readback={("copy", int(CKA_VALUE)): _GARBAGE_VALUE},
        encrypt_output_for={("copy", _ECB): _G5_EMPTY},
    )
    _run_must_fail(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    record = _assert_malformed_ecb_fail()
    assert (record.detail or {}).get("observed_len") == 0, record.detail
    _assert_cleaned_up(fake)


def test_h2_post_change_short_output_fails() -> None:
    """H2/I5+G5: a post-change witness ECB use returning 8 bytes is wrong_result."""
    fake = _CopyFake(
        copy_mode="apply",
        raw_readback={("copy", int(CKA_VALUE)): _GARBAGE_VALUE},
        encrypt_output_for={("copy", _ECB): _G5_SHORT},
    )
    _run_must_fail(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    record = _assert_malformed_ecb_fail()
    assert (record.detail or {}).get("observed_len") == 8, record.detail
    _assert_cleaned_up(fake)


def test_h2_post_change_long_output_fails() -> None:
    """H2/I5+G5: a post-change witness ECB use returning 32 bytes is wrong_result."""
    fake = _CopyFake(
        copy_mode="apply",
        raw_readback={("copy", int(CKA_VALUE)): _GARBAGE_VALUE},
        encrypt_output_for={("copy", _ECB): _G5_LONG},
    )
    _run_must_fail(_qc3b, "copy", "sensitive_downgrade", _rs(fake))
    record = _assert_malformed_ecb_fail()
    assert (record.detail or {}).get("observed_len") == 32, record.detail
    _assert_cleaned_up(fake)


def test_h2_premise_24byte_witness_still_fails() -> None:
    """H2 guard: a 24-byte premise value reproducing ciphertext is still exposure."""
    fake = _CopyFake(
        set_mode="ignore",
        raw_readback={("create", int(CKA_VALUE)): _WITNESS_24},
        encrypt_constant=_round3_local_ecb(_WITNESS_24, _PROBE_PT),
    )
    _run_must_fail(_qc3b, "set", "sensitive_downgrade", _rs(fake))
    record = _assert_fail_record("self_contradiction", "policy")
    assert "setup observation" in (record.summary or ""), record.summary
    assert (record.detail or {}).get("value_len") == 24, record.detail
    assert (record.detail or {}).get("matches_original") is False, record.detail
    assert (record.detail or {}).get("witness_match") is True, record.detail
    assert fake.set_calls == [], "premise must fail before the change is attempted"
    _assert_cleaned_up(fake)


# ---------------------------------------------------------------------------
# QC6b (#58.3): DSA public-value copy observations. The fake token performs
# genuine DSA sign/verify over the stored object attributes (fixed RFC 6979
# pair), so an applied CKA_VALUE template changes verification behaviour
# while an ignored one preserves it -- the two-tier oracle observes both.
# ---------------------------------------------------------------------------


def _qc6b_rs(fake: _CopyFake) -> SimpleNamespace:
    return _rs(fake, mechs={"DSA"})


def _qc6b_patch(monkeypatch: pytest.MonkeyPatch) -> None:
    # The create-supported probe would mint a stray fake object; the premise
    # guard is staging only, never part of the copy verdict under test.
    monkeypatch.setattr(tdsa, "skip_unless_create_object_supported", lambda _rs: None)


def _qc6b_empty(rs: SimpleNamespace) -> None:
    cls = getattr(tdsa, "TestDSAPublicCopyObservations")
    cls().test_fixed_dsa_public_copy_empty_template_observation(rs)


def _qc6b_unchanged(rs: SimpleNamespace) -> None:
    cls = getattr(tdsa, "TestDSAPublicCopyObservations")
    cls().test_fixed_dsa_public_copy_unchanged_value_observation(rs)


def _qc6b_different(rs: SimpleNamespace) -> None:
    cls = getattr(tdsa, "TestDSAPublicCopyObservations")
    cls().test_fixed_dsa_public_copy_different_value_ignored_or_refused(rs)


def test_qc6b_public_empty_and_unchanged_rvs_not_cross_compared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty and unchanged-value DSA public copies are separate observations.

    Either direction of RV divergence (one accepts, the other refuses)
    still passes both nodes: no RV cross-equality is ever asserted.
    """
    _qc6b_patch(monkeypatch)
    accept_unchanged = _CopyFake(copy_mode="apply")
    _qc6b_unchanged(_qc6b_rs(accept_unchanged))
    assert C.get_records() == [], "observation notes emit no classifications"
    _assert_cleaned_up(accept_unchanged)
    assert _copy_template_of(accept_unchanged)[int(CKA_VALUE)] == tdsa._FIXED_DSA_Y
    C.clear()
    refuse_empty = _CopyFake(copy_refuse_rv=_TEMPLATE_INCONSISTENT)
    _qc6b_empty(_qc6b_rs(refuse_empty))
    assert C.get_records() == []
    _assert_cleaned_up(refuse_empty)
    assert refuse_empty.copy_calls[0] == {}, refuse_empty.copy_calls
    C.clear()
    refuse_unchanged = _CopyFake(copy_refuse_rv=_ACTION_PROHIBITED)
    _qc6b_unchanged(_qc6b_rs(refuse_unchanged))
    assert C.get_records() == []
    _assert_cleaned_up(refuse_unchanged)
    C.clear()
    accept_empty = _CopyFake(copy_mode="apply")
    _qc6b_empty(_qc6b_rs(accept_empty))
    assert C.get_records() == []
    _assert_cleaned_up(accept_empty)


def test_qc6b_public_different_value_refused_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each plausible refusal of a forbidden DSA public-value copy passes."""
    _qc6b_patch(monkeypatch)
    for rv in _COPY_REFUSE_RVS:
        fake = _CopyFake(copy_refuse_rv=rv)
        _qc6b_different(_qc6b_rs(fake))
        record = _terminal_record()
        assert record.reason == "sanctioned_refusal", record.summary
        assert record.outcome == "pass", record.summary
        assert record.actual_ckr == ckr_name(rv), record.summary
        _assert_pass_records()
        _assert_cleaned_up(fake)
        C.clear()


def test_qc6b_public_different_value_ignored_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accepted-but-ignored different Y xfails as an ignored-input deviation."""
    _qc6b_patch(monkeypatch)
    fake = _CopyFake(copy_mode="ignore")
    assert_xfails(_qc6b_different, _qc6b_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "ignored-input", record.detail
    _assert_cleaned_up(fake)


def test_qc6b_public_different_value_mutated_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Applied different Y (readback changed, verify flips) fails."""
    _qc6b_patch(monkeypatch)
    fake = _CopyFake(copy_mode="apply")
    _run_must_fail(_qc6b_different, _qc6b_rs(fake))
    _assert_fail_record("self_contradiction", "policy")
    _assert_cleaned_up(fake)


def test_qc6b_public_different_value_unproved_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Readback changed but verify still original is unproved, never mutated."""
    _qc6b_patch(monkeypatch)
    fake = _CopyFake(copy_mode="apply", copy_crypto_follows_source=True)
    assert_xfails(_qc6b_different, _qc6b_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc6b_public_different_value_verify_refused_unproved_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused verify-under-copy leaves the accepted change unproved."""
    _qc6b_patch(monkeypatch)
    fake = _CopyFake(copy_mode="apply", dsa_verify_refuse_roles={"copy"})
    assert_xfails(_qc6b_different, _qc6b_rs(fake))
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)
