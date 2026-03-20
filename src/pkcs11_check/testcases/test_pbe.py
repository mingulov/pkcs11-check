"""Tests for password-based encryption and key derivation mechanisms.

Covers CKM_PBE_SHA1_DES3_EDE_CBC, CKM_PBE_SHA1_DES2_EDE_CBC,
CKM_PBA_SHA1_WITH_SHA1_HMAC, and CKM_PKCS5_PBKD2.

CKM_PBE_SHA1_DES3_EDE_CBC / CKM_PBE_SHA1_DES2_EDE_CBC / CKM_PBA_SHA1_WITH_SHA1_HMAC
use CK_PBE_PARAMS, which python-pkcs11 does not wrap natively; these tests pass
the struct as raw bytes via ctypes and xfail on MechanismParamInvalid.

CKM_PKCS5_PBKD2 uses CK_PKCS5_PBKD2_PARAMS2, which IS natively supported
via a dict ``mechanism_param`` in the python-pkcs11 fork.

OASIS spec: password-based_encryption.md,
            pkcs12_password-based_encryption-authentication.md
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import (
    FunctionFailed,
    GeneralError,
    MechanismInvalid,
    MechanismParamInvalid,
)
from pkcs11.mechanisms import PBKDF2PRF

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt

# ---------------------------------------------------------------------------
# Common error tuple for PBE operations.
#
# Most modules do not implement the legacy PBE mechanisms.  Any of these
# exceptions is treated as "not operational" — the test xfails rather than
# errors, since the mechanism enum is valid but support is absent.
# ---------------------------------------------------------------------------
_PBE_ERRORS = (
    MechanismInvalid,
    MechanismParamInvalid,
    FunctionFailed,
    GeneralError,
)

# CKP_PKCS5_PBKD2_HMAC_SHA256 constant — used directly to avoid import confusion
_CKP_HMAC_SHA256 = int(PBKDF2PRF.HMAC_SHA256)  # 0x00000004
_CKP_HMAC_SHA1 = int(PBKDF2PRF.HMAC_SHA1)  # 0x00000001

# ---------------------------------------------------------------------------
# CK_PBE_PARAMS ctypes layout
#
# typedef struct CK_PBE_PARAMS {
#   CK_BYTE_PTR      pInitVector;   /* output IV buffer (8 bytes for DES) */
#   CK_UTF8CHAR_PTR  pPassword;
#   CK_ULONG         ulPasswordLen;
#   CK_BYTE_PTR      pSalt;
#   CK_ULONG         ulSaltLen;
#   CK_ULONG         ulIteration;
# } CK_PBE_PARAMS;
#
# python-pkcs11 does not wrap CK_PBE_PARAMS natively, so we build it with
# ctypes and pass the raw bytes as mechanism_param.
# ---------------------------------------------------------------------------

_CK_ULONG = ctypes.c_ulong
_CK_BYTE_PTR = ctypes.POINTER(ctypes.c_ubyte)


class _CkPbeParams(ctypes.Structure):
    """CK_PBE_PARAMS per PKCS#11 v2.40 / v3.0 spec."""

    _fields_ = [
        ("pInitVector", _CK_BYTE_PTR),
        ("pPassword", _CK_BYTE_PTR),
        ("ulPasswordLen", _CK_ULONG),
        ("pSalt", _CK_BYTE_PTR),
        ("ulSaltLen", _CK_ULONG),
        ("ulIteration", _CK_ULONG),
    ]


def _make_pbe_params(
    password: bytes,
    salt: bytes,
    iterations: int,
    iv_len: int = 8,
) -> tuple[_CkPbeParams, Any, Any, Any]:
    """Build a CK_PBE_PARAMS ctypes struct.

    Returns (params, iv_buf, pw_arr, salt_arr) — caller must keep all alive
    until C_GenerateKey returns.  The IV buffer is allocated by the caller
    and passed to the token; the token writes the derived IV into it.
    """
    iv_buf = (ctypes.c_ubyte * iv_len)()  # zero-filled IV output buffer
    pw_arr = (ctypes.c_ubyte * len(password))(*password)
    salt_arr = (ctypes.c_ubyte * len(salt))(*salt)

    params = _CkPbeParams()
    params.pInitVector = ctypes.cast(iv_buf, _CK_BYTE_PTR)
    params.pPassword = ctypes.cast(pw_arr, _CK_BYTE_PTR)
    params.ulPasswordLen = len(password)
    params.pSalt = ctypes.cast(salt_arr, _CK_BYTE_PTR)
    params.ulSaltLen = len(salt)
    params.ulIteration = iterations

    return params, iv_buf, pw_arr, salt_arr


def _pbe_params_to_bytes(params: _CkPbeParams) -> bytes:
    """Serialize CK_PBE_PARAMS struct to raw bytes for mechanism_param."""
    return bytes(ctypes.string_at(ctypes.addressof(params), ctypes.sizeof(params)))


# ---------------------------------------------------------------------------
# Shared key-gen template helpers
# ---------------------------------------------------------------------------

_DES3_TEMPLATE: dict[Attribute, Any] = {
    Attribute.CLASS: ObjectClass.SECRET_KEY,
    Attribute.KEY_TYPE: KeyType.DES3,
    Attribute.TOKEN: False,
    Attribute.SENSITIVE: False,
    Attribute.EXTRACTABLE: True,
    Attribute.ENCRYPT: True,
    Attribute.DECRYPT: True,
}

_DES2_TEMPLATE: dict[Attribute, Any] = {
    Attribute.CLASS: ObjectClass.SECRET_KEY,
    Attribute.KEY_TYPE: KeyType.DES2,
    Attribute.TOKEN: False,
    Attribute.SENSITIVE: False,
    Attribute.EXTRACTABLE: True,
    Attribute.ENCRYPT: True,
    Attribute.DECRYPT: True,
}

# Test password and salt
_PASSWORD = b"TestPassword123!"
_SALT = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
_ITERATIONS = 1024


class TestPBESHA1DES3:
    """CKM_PBE_SHA1_DES3_EDE_CBC — SHA-1 + 3-key Triple-DES PBE key generation.

    Defined in PKCS#12 (RFC 7292).  Derives a 3DES key and an 8-byte IV
    from a password and salt using SHA-1.  Very few modern tokens implement
    this legacy mechanism.
    """

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_PBE_SHA1_DES3_EDE_CBC is advertised."""
        if not has_mechanism(p11_module, "PBE_SHA1_DES3_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES3_EDE_CBC not supported")

    def test_generate_key(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a DES3 key via CKM_PBE_SHA1_DES3_EDE_CBC."""
        if not has_mechanism(p11_module, "PBE_SHA1_DES3_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES3_EDE_CBC not supported")

        params, _iv_buf, _pw_arr, _salt_arr = _make_pbe_params(
            _PASSWORD,
            _SALT,
            _ITERATIONS,
            iv_len=8,
        )
        param_bytes = _pbe_params_to_bytes(params)
        try:
            key = p11_session.generate_key(
                KeyType.DES3,
                192,
                mechanism=Mechanism.PBE_SHA1_DES3_EDE_CBC,
                mechanism_param=param_bytes,
                template=_DES3_TEMPLATE,
            )
            try:
                assert key is not None
                assert key[Attribute.KEY_TYPE] == KeyType.DES3
            finally:
                key.destroy()
        except _PBE_ERRORS as exc:
            pytest.xfail(f"CKM_PBE_SHA1_DES3_EDE_CBC not operational: {exc}")

    def test_generate_key_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same password/salt/iterations must yield the same DES3 key."""
        if not has_mechanism(p11_module, "PBE_SHA1_DES3_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES3_EDE_CBC not supported")

        def _gen() -> Any:
            params, _iv_buf, _pw_arr, _salt_arr = _make_pbe_params(
                _PASSWORD, _SALT, _ITERATIONS, iv_len=8
            )
            return p11_session.generate_key(
                KeyType.DES3,
                192,
                mechanism=Mechanism.PBE_SHA1_DES3_EDE_CBC,
                mechanism_param=_pbe_params_to_bytes(params),
                template=_DES3_TEMPLATE,
            )

        try:
            key1 = _gen()
            key2 = _gen()
            try:
                val1 = key1[Attribute.VALUE]
                val2 = key2[Attribute.VALUE]
                assert val1 == val2, "PBE_SHA1_DES3_EDE_CBC must be deterministic"
            finally:
                key2.destroy()
                key1.destroy()
        except _PBE_ERRORS as exc:
            pytest.xfail(f"CKM_PBE_SHA1_DES3_EDE_CBC not operational: {exc}")

    def test_different_salt_different_key(self, p11_session: Any, p11_module: Any) -> None:
        """Different salts must produce different DES3 keys."""
        if not has_mechanism(p11_module, "PBE_SHA1_DES3_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES3_EDE_CBC not supported")

        salt_a = b"\x00" * 8
        salt_b = b"\xff" * 8

        def _gen(salt: bytes) -> Any:
            params, _iv_buf, _pw_arr, _salt_arr = _make_pbe_params(
                _PASSWORD, salt, _ITERATIONS, iv_len=8
            )
            return p11_session.generate_key(
                KeyType.DES3,
                192,
                mechanism=Mechanism.PBE_SHA1_DES3_EDE_CBC,
                mechanism_param=_pbe_params_to_bytes(params),
                template=_DES3_TEMPLATE,
            )

        try:
            key_a = _gen(salt_a)
            key_b = _gen(salt_b)
            try:
                val_a = key_a[Attribute.VALUE]
                val_b = key_b[Attribute.VALUE]
                assert val_a != val_b, "Different salts must produce different keys"
            finally:
                key_b.destroy()
                key_a.destroy()
        except _PBE_ERRORS as exc:
            pytest.xfail(f"CKM_PBE_SHA1_DES3_EDE_CBC not operational: {exc}")

    def test_different_password_different_key(self, p11_session: Any, p11_module: Any) -> None:
        """Different passwords must produce different DES3 keys."""
        if not has_mechanism(p11_module, "PBE_SHA1_DES3_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES3_EDE_CBC not supported")

        pw_a = b"PasswordAlpha"
        pw_b = b"PasswordBravo"

        def _gen(pw: bytes) -> Any:
            params, _iv_buf, _pw_arr, _salt_arr = _make_pbe_params(pw, _SALT, _ITERATIONS, iv_len=8)
            return p11_session.generate_key(
                KeyType.DES3,
                192,
                mechanism=Mechanism.PBE_SHA1_DES3_EDE_CBC,
                mechanism_param=_pbe_params_to_bytes(params),
                template=_DES3_TEMPLATE,
            )

        try:
            key_a = _gen(pw_a)
            key_b = _gen(pw_b)
            try:
                val_a = key_a[Attribute.VALUE]
                val_b = key_b[Attribute.VALUE]
                assert val_a != val_b, "Different passwords must produce different keys"
            finally:
                key_b.destroy()
                key_a.destroy()
        except _PBE_ERRORS as exc:
            pytest.xfail(f"CKM_PBE_SHA1_DES3_EDE_CBC not operational: {exc}")


class TestPBESHA1DES2:
    """CKM_PBE_SHA1_DES2_EDE_CBC — SHA-1 + 2-key Triple-DES PBE key generation.

    Two-key (112-bit) variant of the PKCS#12 PBE mechanisms.  Even rarer
    in modern tokens than the 3-key variant.
    """

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_PBE_SHA1_DES2_EDE_CBC is advertised."""
        if not has_mechanism(p11_module, "PBE_SHA1_DES2_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES2_EDE_CBC not supported")

    def test_generate_key(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a DES2 key via CKM_PBE_SHA1_DES2_EDE_CBC."""
        if not has_mechanism(p11_module, "PBE_SHA1_DES2_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES2_EDE_CBC not supported")

        params, _iv_buf, _pw_arr, _salt_arr = _make_pbe_params(
            _PASSWORD,
            _SALT,
            _ITERATIONS,
            iv_len=8,
        )
        param_bytes = _pbe_params_to_bytes(params)
        try:
            key = p11_session.generate_key(
                KeyType.DES2,
                128,
                mechanism=Mechanism.PBE_SHA1_DES2_EDE_CBC,
                mechanism_param=param_bytes,
                template=_DES2_TEMPLATE,
            )
            try:
                assert key is not None
                assert key[Attribute.KEY_TYPE] == KeyType.DES2
            finally:
                key.destroy()
        except _PBE_ERRORS as exc:
            pytest.xfail(f"CKM_PBE_SHA1_DES2_EDE_CBC not operational: {exc}")

    def test_generate_key_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same password/salt/iterations must yield the same DES2 key."""
        if not has_mechanism(p11_module, "PBE_SHA1_DES2_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES2_EDE_CBC not supported")

        def _gen() -> Any:
            params, _iv_buf, _pw_arr, _salt_arr = _make_pbe_params(
                _PASSWORD, _SALT, _ITERATIONS, iv_len=8
            )
            return p11_session.generate_key(
                KeyType.DES2,
                128,
                mechanism=Mechanism.PBE_SHA1_DES2_EDE_CBC,
                mechanism_param=_pbe_params_to_bytes(params),
                template=_DES2_TEMPLATE,
            )

        try:
            key1 = _gen()
            key2 = _gen()
            try:
                val1 = key1[Attribute.VALUE]
                val2 = key2[Attribute.VALUE]
                assert val1 == val2, "PBE_SHA1_DES2_EDE_CBC must be deterministic"
            finally:
                key2.destroy()
                key1.destroy()
        except _PBE_ERRORS as exc:
            pytest.xfail(f"CKM_PBE_SHA1_DES2_EDE_CBC not operational: {exc}")

    def test_different_password_different_key(self, p11_session: Any, p11_module: Any) -> None:
        """Different passwords must produce different DES2 keys."""
        if not has_mechanism(p11_module, "PBE_SHA1_DES2_EDE_CBC"):
            pytest.skip("CKM_PBE_SHA1_DES2_EDE_CBC not supported")

        def _gen(pw: bytes) -> Any:
            params, _iv_buf, _pw_arr, _salt_arr = _make_pbe_params(pw, _SALT, _ITERATIONS, iv_len=8)
            return p11_session.generate_key(
                KeyType.DES2,
                128,
                mechanism=Mechanism.PBE_SHA1_DES2_EDE_CBC,
                mechanism_param=_pbe_params_to_bytes(params),
                template=_DES2_TEMPLATE,
            )

        try:
            key_a = _gen(b"PasswordAlpha")
            key_b = _gen(b"PasswordBravo")
            try:
                val_a = key_a[Attribute.VALUE]
                val_b = key_b[Attribute.VALUE]
                assert val_a != val_b, "Different passwords must produce different keys"
            finally:
                key_b.destroy()
                key_a.destroy()
        except _PBE_ERRORS as exc:
            pytest.xfail(f"CKM_PBE_SHA1_DES2_EDE_CBC not operational: {exc}")


class TestPBASHA1:
    """CKM_PBA_SHA1_WITH_SHA1_HMAC — password-based SHA-1 HMAC key generation.

    Derives an HMAC key for use with CKM_SHA_1_HMAC.  Defined in PKCS#12.
    The generated key length is SHA-1 output size (20 bytes / 160 bits).
    """

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_PBA_SHA1_WITH_SHA1_HMAC is advertised."""
        if not has_mechanism(p11_module, "PBA_SHA1_WITH_SHA1_HMAC"):
            pytest.skip("CKM_PBA_SHA1_WITH_SHA1_HMAC not supported")

    def test_generate_key(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an HMAC key via CKM_PBA_SHA1_WITH_SHA1_HMAC."""
        if not has_mechanism(p11_module, "PBA_SHA1_WITH_SHA1_HMAC"):
            pytest.skip("CKM_PBA_SHA1_WITH_SHA1_HMAC not supported")

        # PKCS#12 PBA mechanism for SHA1-HMAC: key is 20-byte (160-bit) HMAC key
        hmac_template: dict[Attribute, Any] = {
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.SHA_1_HMAC,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
            Attribute.SIGN: True,
            Attribute.VERIFY: True,
        }
        params, _iv_buf, _pw_arr, _salt_arr = _make_pbe_params(
            _PASSWORD, _SALT, _ITERATIONS, iv_len=20
        )
        param_bytes = _pbe_params_to_bytes(params)
        try:
            key = p11_session.generate_key(
                KeyType.SHA_1_HMAC,
                160,
                mechanism=Mechanism.PBA_SHA1_WITH_SHA1_HMAC,
                mechanism_param=param_bytes,
                template=hmac_template,
            )
            try:
                assert key is not None
                assert key[Attribute.KEY_TYPE] == KeyType.SHA_1_HMAC
            finally:
                key.destroy()
        except _PBE_ERRORS as exc:
            pytest.xfail(f"CKM_PBA_SHA1_WITH_SHA1_HMAC not operational: {exc}")

    def test_generate_key_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same password/salt/iterations must yield the same HMAC key."""
        if not has_mechanism(p11_module, "PBA_SHA1_WITH_SHA1_HMAC"):
            pytest.skip("CKM_PBA_SHA1_WITH_SHA1_HMAC not supported")

        hmac_template: dict[Attribute, Any] = {
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.SHA_1_HMAC,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
            Attribute.SIGN: True,
            Attribute.VERIFY: True,
        }

        def _gen() -> Any:
            params, _iv_buf, _pw_arr, _salt_arr = _make_pbe_params(
                _PASSWORD, _SALT, _ITERATIONS, iv_len=20
            )
            return p11_session.generate_key(
                KeyType.SHA_1_HMAC,
                160,
                mechanism=Mechanism.PBA_SHA1_WITH_SHA1_HMAC,
                mechanism_param=_pbe_params_to_bytes(params),
                template=hmac_template,
            )

        try:
            key1 = _gen()
            key2 = _gen()
            try:
                val1 = key1[Attribute.VALUE]
                val2 = key2[Attribute.VALUE]
                assert val1 == val2, "PBA_SHA1_WITH_SHA1_HMAC must be deterministic"
            finally:
                key2.destroy()
                key1.destroy()
        except _PBE_ERRORS as exc:
            pytest.xfail(f"CKM_PBA_SHA1_WITH_SHA1_HMAC not operational: {exc}")

    def test_different_salt_different_key(self, p11_session: Any, p11_module: Any) -> None:
        """Different salts must produce different HMAC keys."""
        if not has_mechanism(p11_module, "PBA_SHA1_WITH_SHA1_HMAC"):
            pytest.skip("CKM_PBA_SHA1_WITH_SHA1_HMAC not supported")

        hmac_template: dict[Attribute, Any] = {
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.SHA_1_HMAC,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
            Attribute.SIGN: True,
            Attribute.VERIFY: True,
        }

        def _gen(salt: bytes) -> Any:
            params, _iv_buf, _pw_arr, _salt_arr = _make_pbe_params(
                _PASSWORD, salt, _ITERATIONS, iv_len=20
            )
            return p11_session.generate_key(
                KeyType.SHA_1_HMAC,
                160,
                mechanism=Mechanism.PBA_SHA1_WITH_SHA1_HMAC,
                mechanism_param=_pbe_params_to_bytes(params),
                template=hmac_template,
            )

        try:
            key_a = _gen(b"\x00" * 8)
            key_b = _gen(b"\xff" * 8)
            try:
                val_a = key_a[Attribute.VALUE]
                val_b = key_b[Attribute.VALUE]
                assert val_a != val_b, "Different salts must produce different HMAC keys"
            finally:
                key_b.destroy()
                key_a.destroy()
        except _PBE_ERRORS as exc:
            pytest.xfail(f"CKM_PBA_SHA1_WITH_SHA1_HMAC not operational: {exc}")


class TestPKCS5PBKD2:
    """CKM_PKCS5_PBKD2 — PKCS#5 v2 password-based key derivation (PBKDF2).

    Derives a symmetric key from a password and salt using a configurable
    PRF (HMAC-SHA1/256/384/512) and iteration count.  Natively supported
    by the python-pkcs11 fork via a dict ``mechanism_param``.

    SoftHSM2 supports this mechanism.
    """

    # Common error tuple for PBKD2: stricter than _PBE_ERRORS since the
    # mechanism_param is well-formed here — unexpected errors should fail.
    _DERIVE_ERRORS = (MechanismInvalid, MechanismParamInvalid, FunctionFailed)

    def test_mechanism_availability(self, p11_module: Any) -> None:
        """Probe whether CKM_PKCS5_PBKD2 is advertised."""
        if not has_mechanism(p11_module, "PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")

    def test_derive_generic_secret_sha256(self, p11_session: Any, p11_module: Any) -> None:
        """Derive a 256-bit GENERIC_SECRET key using PBKDF2-HMAC-SHA256."""
        if not has_mechanism(p11_module, "PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")

        pbkdf2_params = {
            "password": _PASSWORD,
            "salt": _SALT,
            "iterations": _ITERATIONS,
            "prf": _CKP_HMAC_SHA256,
        }
        try:
            key = p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.PKCS5_PBKD2,
                mechanism_param=pbkdf2_params,
                template={
                    Attribute.TOKEN: False,
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                },
            )
            try:
                assert key is not None
                value = key[Attribute.VALUE]
                assert len(value) == 32, f"Expected 32 bytes, got {len(value)}"
                assert value != bytes(32), "Derived key must not be all zeros"
            finally:
                key.destroy()
        except self._DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_PKCS5_PBKD2 (HMAC-SHA256) not operational: {exc}")

    def test_derive_generic_secret_sha1(self, p11_session: Any, p11_module: Any) -> None:
        """Derive a 160-bit GENERIC_SECRET key using PBKDF2-HMAC-SHA1."""
        if not has_mechanism(p11_module, "PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")

        pbkdf2_params = {
            "password": _PASSWORD,
            "salt": _SALT,
            "iterations": _ITERATIONS,
            "prf": _CKP_HMAC_SHA1,
        }
        try:
            key = p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                160,
                mechanism=Mechanism.PKCS5_PBKD2,
                mechanism_param=pbkdf2_params,
                template={
                    Attribute.TOKEN: False,
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                },
            )
            try:
                value = key[Attribute.VALUE]
                assert len(value) == 20, f"Expected 20 bytes, got {len(value)}"
            finally:
                key.destroy()
        except self._DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_PKCS5_PBKD2 (HMAC-SHA1) not operational: {exc}")

    def test_derive_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same password/salt/iterations/PRF must produce the same key material."""
        if not has_mechanism(p11_module, "PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")

        pbkdf2_params = {
            "password": _PASSWORD,
            "salt": _SALT,
            "iterations": _ITERATIONS,
            "prf": _CKP_HMAC_SHA256,
        }
        derive_template = {
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        }
        try:
            key1 = p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.PKCS5_PBKD2,
                mechanism_param=pbkdf2_params,
                template=derive_template,
            )
            key2 = p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.PKCS5_PBKD2,
                mechanism_param=pbkdf2_params,
                template=derive_template,
            )
            try:
                val1 = key1[Attribute.VALUE]
                val2 = key2[Attribute.VALUE]
                assert val1 == val2, "PBKDF2 must be deterministic"
            finally:
                key2.destroy()
                key1.destroy()
        except self._DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_PKCS5_PBKD2 not operational: {exc}")

    def test_different_salt_different_key(self, p11_session: Any, p11_module: Any) -> None:
        """Different salts must produce different derived key material."""
        if not has_mechanism(p11_module, "PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")

        derive_template = {
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        }

        def _derive(salt: bytes) -> Any:
            return p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.PKCS5_PBKD2,
                mechanism_param={
                    "password": _PASSWORD,
                    "salt": salt,
                    "iterations": _ITERATIONS,
                    "prf": _CKP_HMAC_SHA256,
                },
                template=derive_template,
            )

        try:
            key_a = _derive(b"\x00" * 16)
            key_b = _derive(b"\xff" * 16)
            try:
                val_a = key_a[Attribute.VALUE]
                val_b = key_b[Attribute.VALUE]
                assert val_a != val_b, "Different salts must produce different keys"
            finally:
                key_b.destroy()
                key_a.destroy()
        except self._DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_PKCS5_PBKD2 not operational: {exc}")

    def test_different_password_different_key(self, p11_session: Any, p11_module: Any) -> None:
        """Different passwords must produce different derived key material."""
        if not has_mechanism(p11_module, "PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")

        derive_template = {
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        }

        def _derive(pw: bytes) -> Any:
            return p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.PKCS5_PBKD2,
                mechanism_param={
                    "password": pw,
                    "salt": _SALT,
                    "iterations": _ITERATIONS,
                    "prf": _CKP_HMAC_SHA256,
                },
                template=derive_template,
            )

        try:
            key_a = _derive(b"PasswordAlpha")
            key_b = _derive(b"PasswordBravo")
            try:
                val_a = key_a[Attribute.VALUE]
                val_b = key_b[Attribute.VALUE]
                assert val_a != val_b, "Different passwords must produce different keys"
            finally:
                key_b.destroy()
                key_a.destroy()
        except self._DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_PKCS5_PBKD2 not operational: {exc}")

    def test_more_iterations_produces_different_key(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Different iteration counts must produce different derived key material."""
        if not has_mechanism(p11_module, "PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")

        derive_template = {
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        }

        def _derive(iterations: int) -> Any:
            return p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.PKCS5_PBKD2,
                mechanism_param={
                    "password": _PASSWORD,
                    "salt": _SALT,
                    "iterations": iterations,
                    "prf": _CKP_HMAC_SHA256,
                },
                template=derive_template,
            )

        try:
            key_1k = _derive(1000)
            key_2k = _derive(2000)
            try:
                val_1k = key_1k[Attribute.VALUE]
                val_2k = key_2k[Attribute.VALUE]
                assert val_1k != val_2k, "Different iteration counts must produce different keys"
            finally:
                key_2k.destroy()
                key_1k.destroy()
        except self._DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_PKCS5_PBKD2 not operational: {exc}")

    def test_derive_aes_key(self, p11_session: Any, p11_module: Any) -> None:
        """Derive a 256-bit AES key using PBKDF2-HMAC-SHA256."""
        if not has_mechanism(p11_module, "PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")

        try:
            key = p11_session.generate_key(
                KeyType.AES,
                256,
                mechanism=Mechanism.PKCS5_PBKD2,
                mechanism_param={
                    "password": _PASSWORD,
                    "salt": _SALT,
                    "iterations": _ITERATIONS,
                    "prf": _CKP_HMAC_SHA256,
                },
                template={
                    Attribute.TOKEN: False,
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.ENCRYPT: True,
                    Attribute.DECRYPT: True,
                },
            )
            try:
                assert key is not None
                assert key[Attribute.KEY_TYPE] == KeyType.AES
                value = key[Attribute.VALUE]
                assert len(value) == 32, f"Expected 32 bytes AES key, got {len(value)}"
            finally:
                key.destroy()
        except self._DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_PKCS5_PBKD2 AES key derivation not operational: {exc}")

    def test_string_password_accepted(self, p11_session: Any, p11_module: Any) -> None:
        """String passwords are accepted (converted to UTF-8 bytes by the fork)."""
        if not has_mechanism(p11_module, "PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")

        # The python-pkcs11 fork auto-encodes str passwords to UTF-8
        try:
            key = p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.PKCS5_PBKD2,
                mechanism_param={
                    "password": "StringPassword",
                    "salt": _SALT,
                    "iterations": _ITERATIONS,
                    "prf": _CKP_HMAC_SHA256,
                },
                template={
                    Attribute.TOKEN: False,
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                },
            )
            try:
                assert key is not None
            finally:
                key.destroy()
        except self._DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_PKCS5_PBKD2 with string password not operational: {exc}")
