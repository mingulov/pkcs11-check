"""Canonical operability probes for Wycheproof AES suites (CMAC, KW, KWP, GMAC, XTS).

Each probe runs ONE canonical known-answer operation per (mechanism, direction)
per process to decide how clean invalid-vector rejections classify: a rejection
on a NOT_OPERATIONAL mechanism never evaluated the input -> vacuous (xfail),
not a genuine pass. See :mod:`testcases._operability` for the framework.
"""

from __future__ import annotations

from typing import Any

from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    encrypt_single,
    read_attributes,
    sign_single,
    unwrap_key,
    verify_single,
    wrap_key,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKK_AES,
    CKK_AES_XTS,
    CKK_GENERIC_SECRET,
    CKM_AES_CMAC,
    CKM_AES_GMAC,
    CKM_AES_KEY_WRAP,
    CKM_AES_KEY_WRAP_KWP,
    CKM_AES_XTS,
    CKO_SECRET_KEY,
)
from pkcs11_check.testcases._operability import (
    Operability,
    OperabilityResult,
    probe_operability,
)
from pkcs11_check.testcases.conftest import import_secret_key_negotiated

# Canonical probe constants (same key/plaintext pattern as the AEAD probe).
_PROBE_KEY = bytes(range(16))  # AES-128
_PROBE_KEY2 = bytes(range(16, 32))  # second AES-128 (target for KW wrap)
_PROBE_MSG = bytes(range(24))  # 24-byte message (8-aligned for KW)
_PROBE_IV_12 = bytes(range(12))  # 12-byte IV for GMAC
_PROBE_AAD = bytes(range(16))  # 16-byte AAD for GMAC
_PROBE_XTS_KEY = bytes(range(32))  # AES-XTS double-size key (two AES-128)
_PROBE_XTS_TWEAK = bytes(range(16))  # 16-byte tweak for XTS


def cmac_operability(rs: Any) -> OperabilityResult:
    """Canonical AES-CMAC sign+verify self-roundtrip probe."""

    def probe() -> OperabilityResult:
        key = 0
        try:
            try:
                key = import_secret_key_negotiated(
                    rs,
                    CKK_AES,
                    _PROBE_KEY,
                    attrs={
                        CKA_SIGN: True,
                        CKA_VERIFY: True,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                    },
                )
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.INCONCLUSIVE, f"CMAC key staging failed: {exc}"
                )
            try:
                tag = sign_single(rs.raw, rs.sh, key, CKM_AES_CMAC, _PROBE_MSG)
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, f"canonical CMAC sign rejected: {exc}"
                )
            try:
                ok = verify_single(rs.raw, rs.sh, key, CKM_AES_CMAC, _PROBE_MSG, tag)
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, f"canonical CMAC verify rejected: {exc}"
                )
            if not ok:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, "own CMAC tag verifies False"
                )
            return OperabilityResult(Operability.OPERATIONAL, "CMAC sign+verify OK")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)

    return probe_operability("AES_CMAC:sign-verify", probe)


def gmac_operability(rs: Any) -> OperabilityResult:
    """Canonical AES-GMAC sign+verify self-roundtrip probe."""

    def probe() -> OperabilityResult:
        key = 0
        try:
            try:
                key = import_secret_key_negotiated(
                    rs,
                    CKK_AES,
                    _PROBE_KEY,
                    attrs={
                        CKA_SIGN: True,
                        CKA_VERIFY: True,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                    },
                )
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.INCONCLUSIVE, f"GMAC key staging failed: {exc}"
                )
            param = mech_bytes(CKM_AES_GMAC, _PROBE_IV_12)
            try:
                tag = sign_single(
                    rs.raw, rs.sh, key, CKM_AES_GMAC, _PROBE_AAD, mech_param=param
                )
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, f"canonical GMAC sign rejected: {exc}"
                )
            try:
                ok = verify_single(
                    rs.raw, rs.sh, key, CKM_AES_GMAC, _PROBE_AAD, tag, mech_param=param
                )
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, f"canonical GMAC verify rejected: {exc}"
                )
            if not ok:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, "own GMAC tag verifies False"
                )
            return OperabilityResult(Operability.OPERATIONAL, "GMAC sign+verify OK")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)

    return probe_operability("AES_GMAC:sign-verify", probe)


def kwp_encrypt_operability(rs: Any) -> OperabilityResult:
    """Canonical AES-KWP (RFC 5649) encrypt probe with ground-truth check."""

    def probe() -> OperabilityResult:
        key = 0
        try:
            try:
                key = import_secret_key_negotiated(
                    rs,
                    CKK_AES,
                    _PROBE_KEY,
                    attrs={
                        CKA_ENCRYPT: True,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                    },
                )
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.INCONCLUSIVE, f"KWP key staging failed: {exc}"
                )
            try:
                wrapped = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_KEY_WRAP_KWP,
                    _PROBE_MSG,
                    output_overhead=16,
                )
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, f"canonical KWP encrypt rejected: {exc}"
                )
            try:
                from cryptography.hazmat.primitives.keywrap import (
                    aes_key_wrap_with_padding,
                )

                expected = aes_key_wrap_with_padding(_PROBE_KEY, _PROBE_MSG)
            except Exception:
                return OperabilityResult(
                    Operability.OPERATIONAL, "KWP encrypt OK (ground-truth skipped)"
                )
            if wrapped != expected:
                return OperabilityResult(
                    Operability.WRONG_OUTPUT, "canonical KWP output mismatch"
                )
            return OperabilityResult(Operability.OPERATIONAL, "KWP encrypt OK")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)

    return probe_operability("AES_KEY_WRAP_KWP:encrypt", probe)


def xts_encrypt_operability(rs: Any) -> OperabilityResult:
    """Canonical AES-XTS encrypt probe with ground-truth check."""

    def probe() -> OperabilityResult:
        key = 0
        try:
            try:
                key = import_secret_key_negotiated(
                    rs,
                    CKK_AES_XTS,
                    _PROBE_XTS_KEY,
                    attrs={
                        CKA_ENCRYPT: True,
                        CKA_DECRYPT: True,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                    },
                )
            except (CkrAssertionError, AttributeError) as exc:
                return OperabilityResult(
                    Operability.INCONCLUSIVE, f"XTS key staging failed: {exc}"
                )
            param = mech_bytes(CKM_AES_XTS, _PROBE_XTS_TWEAK)
            try:
                ct = encrypt_single(
                    rs.raw, rs.sh, key, CKM_AES_XTS, _PROBE_MSG, mech_param=param
                )
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, f"canonical XTS encrypt rejected: {exc}"
                )
            try:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

                cipher = Cipher(algorithms.AES(_PROBE_XTS_KEY), modes.XTS(_PROBE_XTS_TWEAK))
                enc = cipher.encryptor()
                expected = enc.update(_PROBE_MSG) + enc.finalize()
            except Exception:
                return OperabilityResult(
                    Operability.OPERATIONAL, "XTS encrypt OK (ground-truth skipped)"
                )
            if ct != expected:
                return OperabilityResult(
                    Operability.WRONG_OUTPUT, "canonical XTS output mismatch"
                )
            return OperabilityResult(Operability.OPERATIONAL, "XTS encrypt OK")
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)

    return probe_operability("AES_XTS:encrypt", probe)


def kw_unwrap_operability(rs: Any) -> OperabilityResult:
    """Canonical AES-KW (RFC 3394) wrap+unwrap self-roundtrip probe."""

    def probe() -> OperabilityResult:
        wrap_key_h = 0
        target = 0
        recovered = 0
        try:
            try:
                wrap_key_h = import_secret_key_negotiated(
                    rs,
                    CKK_AES,
                    _PROBE_KEY,
                    attrs={
                        CKA_WRAP: True,
                        CKA_UNWRAP: True,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                    },
                )
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.INCONCLUSIVE, f"KW wrapping key staging failed: {exc}"
                )
            try:
                target = import_secret_key_negotiated(
                    rs,
                    CKK_AES,
                    _PROBE_KEY2,
                    attrs={
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                    },
                )
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.INCONCLUSIVE, f"KW target key staging failed: {exc}"
                )
            try:
                blob = wrap_key(rs.raw, rs.sh, wrap_key_h, target, CKM_AES_KEY_WRAP)
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL, f"canonical KW wrap rejected: {exc}"
                )
            base_attrs: dict[int, Any] = {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
                CKA_TOKEN: False,
            }
            # Try both with and without CKA_VALUE_LEN (mirrors the test's adaptive unwrap).
            for variant_attrs in (base_attrs, {**base_attrs, CKA_VALUE_LEN: len(_PROBE_KEY2)}):
                try:
                    recovered = unwrap_key(
                        rs.raw, rs.sh, wrap_key_h, blob, CKM_AES_KEY_WRAP, attrs=variant_attrs
                    )
                    break
                except CkrAssertionError:
                    continue
            else:
                return OperabilityResult(
                    Operability.NOT_OPERATIONAL,
                    "canonical KW unwrap rejected (both template variants)",
                )
            try:
                recovered_attrs = read_attributes(rs.raw, rs.sh, recovered, [CKA_VALUE])
            except CkrAssertionError as exc:
                return OperabilityResult(
                    Operability.INCONCLUSIVE, f"KW recovered value read failed: {exc}"
                )
            if recovered_attrs.get(CKA_VALUE) != _PROBE_KEY2:
                return OperabilityResult(
                    Operability.WRONG_OUTPUT, "KW roundtrip value mismatch"
                )
            return OperabilityResult(Operability.OPERATIONAL, "KW wrap+unwrap OK")
        finally:
            if wrap_key_h:
                destroy_quietly(rs.raw, rs.sh, wrap_key_h)
            if target:
                destroy_quietly(rs.raw, rs.sh, target)
            if recovered:
                destroy_quietly(rs.raw, rs.sh, recovered)

    return probe_operability("AES_KEY_WRAP:wrap-unwrap", probe)
