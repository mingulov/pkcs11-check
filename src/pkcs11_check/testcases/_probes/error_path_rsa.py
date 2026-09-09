"""Crash-isolated RSA decrypt and verify error-path probes.

The child emits a small versioned JSON-lines protocol. Every observation carries
the exact case selected by the parent so a marker from a different probe cannot be
silently interpreted as this test's evidence. The parent owns protocol validation
and classification; this module only performs PKCS#11 calls and emits observations.
"""

from __future__ import annotations  # noqa: I001

import ctypes
import json
import os
from collections.abc import Callable
from typing import Any

from pkcs11_check.core.crash_codes import ctypes_access_violation_code

# isort: split
from pkcs11_check.raw.recipes import read_attributes  # noqa: I001
from pkcs11_check.raw.recipes import (  # noqa: I001
    RSAUsage,
    destroy_quietly,
    gen_rsa_keypair,
    sign_single,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_RSA_PKCS_OAEP_PARAMS,
    CK_ULONG,
    CKA_MODULUS,
    CKA_TOKEN,
    CKG_MGF1_SHA256,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKZ_DATA_SPECIFIED,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main

_SCHEMA = 1
_RSA_KEY_BITS = 2048
_RSA_KEY_BYTES = _RSA_KEY_BITS // 8


def _case_id(extra: dict[str, Any]) -> str:
    """Return the canonical case identity shared by all child markers."""
    probe = extra.get("probe")
    if probe == "decrypt":
        return f"decrypt:{extra['mech']}:{extra['variant']}"
    if probe == "verify":
        return "verify:sha256_rsa_pkcs:bitflip"
    raise ValueError(f"error_path_rsa probe: unknown 'probe' value {probe!r}")


def _emit(marker: str, payload: dict[str, Any]) -> None:
    """Emit one strict protocol marker without exposing provider secrets."""
    print(f"{marker}:" + json.dumps(payload, separators=(",", ":")), flush=True)


def _emit_attribute(case: str, *, state: str, **fields: Any) -> None:
    _emit(
        "RSA_ATTRIBUTE",
        {
            "schema": _SCHEMA,
            "case": case,
            "operation": "C_GetAttributeValue",
            "attribute": {"name": "CKA_MODULUS", "id": int(CKA_MODULUS)},
            "state": state,
            **fields,
        },
    )


def _emit_rv(
    case: str,
    *,
    stage: str,
    operation: str | None,
    mechanism: str,
    rv: int,
    value_len: int | None = None,
) -> None:
    payload: dict[str, Any] = {
        "schema": _SCHEMA,
        "case": case,
        "stage": stage,
        "operation": operation,
        "mechanism": mechanism,
        "rv": int(rv),
    }
    if value_len is not None:
        payload["value_len"] = value_len
    _emit("RSA_RV", payload)


def _emit_done(case: str, status: str) -> None:
    _emit("RSA_DONE", {"schema": _SCHEMA, "case": case, "status": status})


def _destroy_pair(raw: Any, sh: int, pub: int, priv: int) -> None:
    """Destroy both RSA handles, preferring a provider access violation."""
    first: BaseException | None = None
    access_violation: BaseException | None = None
    for handle in (pub, priv):
        try:
            destroy_quietly(raw, sh, handle)
        except BaseException as exc:
            if first is None:
                first = exc
            if ctypes_access_violation_code(exc) is not None:
                access_violation = exc
    if access_violation is not None:
        raise access_violation
    if first is not None:
        raise first


def _read_modulus_or_emit_missing(raw: Any, sh: int, pub: int, case: str) -> tuple[bool, Any]:
    attrs = read_attributes(raw, sh, pub, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute

        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return False, None
    return True, attrs[CKA_MODULUS]


def _make_bad_ct(variant: str, modulus: bytes, mod_len: int) -> bytes:
    """Build malformed ciphertext; ``random`` is a guaranteed ``c >= n`` case."""
    modulus_int = int.from_bytes(modulus, "big")
    if variant == "random":
        # c=n is in [n, 256**k), so it is outside the RSA representative domain
        # while retaining the exact modulus length.
        return modulus_int.to_bytes(mod_len, "big")
    if variant == "truncated":
        return os.urandom(max(1, mod_len // 2))
    if variant == "extended":
        return os.urandom(mod_len + 16)
    if variant == "all_zeros":
        return bytes(mod_len)
    if variant == "all_ff":
        return b"\xff" * mod_len
    raise ValueError(f"error_path_rsa probe: unknown decrypt 'variant' value {variant!r}")


def _pkcs_decrypt(raw: Any, sh: int, priv: int, bad_ct: bytes, mod_len: int, case: str) -> None:
    """C_DecryptInit(CKM_RSA_PKCS) + C_Decrypt on malformed ciphertext."""
    mech = CK_MECHANISM()
    mech.mechanism = CKM_RSA_PKCS
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_DecryptInit(sh, ctypes.byref(mech), priv)
    if rv != 0:
        _emit_rv(
            case,
            stage="decrypt_init",
            operation="C_DecryptInit",
            mechanism="CKM_RSA_PKCS",
            rv=int(rv),
        )
        return
    _emit_rv(
        case,
        stage="decrypt_init",
        operation="C_DecryptInit",
        mechanism="CKM_RSA_PKCS",
        rv=0,
    )
    ct_buf = (ctypes.c_ubyte * len(bad_ct))(*bad_ct)
    out_buf = (ctypes.c_ubyte * (mod_len + 16))()
    out_len = CK_ULONG(mod_len + 16)
    rv = raw.C_Decrypt(sh, ct_buf, len(bad_ct), out_buf, ctypes.byref(out_len))
    _emit_rv(
        case,
        stage="decrypt",
        operation="C_Decrypt",
        mechanism="CKM_RSA_PKCS",
        rv=int(rv),
    )


def _oaep_decrypt(raw: Any, sh: int, priv: int, bad_ct: bytes, mod_len: int, case: str) -> None:
    """C_DecryptInit(CKM_RSA_PKCS_OAEP) + C_Decrypt on malformed ciphertext."""
    params = CK_RSA_PKCS_OAEP_PARAMS()
    params.hashAlg = CKM_SHA256
    params.mgf = CKG_MGF1_SHA256
    params.source = CKZ_DATA_SPECIFIED
    params.pSourceData = None
    params.ulSourceDataLen = 0

    mech = CK_MECHANISM()
    mech.mechanism = CKM_RSA_PKCS_OAEP
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    rv = raw.C_DecryptInit(sh, ctypes.byref(mech), priv)
    if rv != 0:
        _emit_rv(
            case,
            stage="decrypt_init",
            operation="C_DecryptInit",
            mechanism="CKM_RSA_PKCS_OAEP",
            rv=int(rv),
        )
        return
    _emit_rv(
        case,
        stage="decrypt_init",
        operation="C_DecryptInit",
        mechanism="CKM_RSA_PKCS_OAEP",
        rv=0,
    )
    ct_buf = (ctypes.c_ubyte * len(bad_ct))(*bad_ct)
    out_buf = (ctypes.c_ubyte * (mod_len + 16))()
    out_len = CK_ULONG(mod_len + 16)
    rv = raw.C_Decrypt(sh, ct_buf, len(bad_ct), out_buf, ctypes.byref(out_len))
    _emit_rv(
        case,
        stage="decrypt",
        operation="C_Decrypt",
        mechanism="CKM_RSA_PKCS_OAEP",
        rv=int(rv),
    )


def _run_decrypt(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    """Generate a decrypt-only RSA pair, then exercise one malformed ciphertext."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    case = _case_id(extra)

    try:
        pub, priv = gen_rsa_keypair(
            raw,
            sh,
            _RSA_KEY_BITS,
            usage=RSAUsage.DECRYPT,
            private_attrs={int(CKA_TOKEN): False},
            public_attrs={int(CKA_TOKEN): False},
        )
    except CkrAssertionError as exc:
        _emit_rv(
            case,
            stage="keygen",
            operation="C_GenerateKeyPair",
            mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            rv=int(exc.rv),
        )
        _emit_done(case, "setup_refused")
        return
    try:
        try:
            modulus_present, mod_bytes = _read_modulus_or_emit_missing(raw, sh, pub, case)
        except CkrAssertionError as exc:
            _emit_rv(
                case,
                stage="attribute_read",
                operation="C_GetAttributeValue",
                mechanism="CKM_RSA_PKCS" if extra["mech"] == "pkcs" else "CKM_RSA_PKCS_OAEP",
                rv=int(exc.rv),
            )
            _emit_done(case, "oracle_disabled")
            return
        if not modulus_present:
            _emit_done(case, "omitted")
            return
        if not isinstance(mod_bytes, bytes) or not mod_bytes:
            _emit_attribute(
                case,
                state="malformed",
                value_type=type(mod_bytes).__name__[:64],
                value_repr=repr(mod_bytes)[:256],
            )
            _emit_done(case, "malformed")
            return
        modulus_int = int.from_bytes(mod_bytes, "big")
        modulus_bits = modulus_int.bit_length()
        if modulus_int <= 0:
            _emit_attribute(
                case,
                state="malformed",
                value_type="bytes",
                value_repr="zero modulus",
                value_len=len(mod_bytes),
                modulus_bits=modulus_bits,
            )
            _emit_done(case, "malformed")
            return
        if len(mod_bytes) != _RSA_KEY_BYTES or modulus_bits != _RSA_KEY_BITS:
            _emit_attribute(
                case,
                state="inconsistent",
                value_len=len(mod_bytes),
                modulus_bits=modulus_bits,
                expected_bits=_RSA_KEY_BITS,
            )
            _emit_done(case, "malformed")
            return

        _emit_attribute(
            case,
            state="present",
            value_len=len(mod_bytes),
            modulus_bits=modulus_bits,
        )

        modulus_len = (modulus_bits + 7) // 8
        bad_ct = _make_bad_ct(extra["variant"], mod_bytes, modulus_len)
        if extra["mech"] == "pkcs":
            _pkcs_decrypt(raw, sh, priv, bad_ct, modulus_len, case)
        else:
            _oaep_decrypt(raw, sh, priv, bad_ct, modulus_len, case)
        _emit_done(case, "complete")
    finally:
        _destroy_pair(raw, sh, pub, priv)


def _run_verify(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """Sign valid data, flip one signature bit, and call C_Verify."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    case = "verify:sha256_rsa_pkcs:bitflip"

    try:
        pub, priv = gen_rsa_keypair(
            raw,
            sh,
            _RSA_KEY_BITS,
            usage=RSAUsage.SIGN,
            private_attrs={int(CKA_TOKEN): False},
            public_attrs={int(CKA_TOKEN): False},
        )
    except CkrAssertionError as exc:
        _emit_rv(
            case,
            stage="keygen",
            operation="C_GenerateKeyPair",
            mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            rv=int(exc.rv),
        )
        _emit_done(case, "setup_refused")
        return
    try:
        try:
            sig = sign_single(raw, sh, priv, CKM_SHA256_RSA_PKCS, b"test data for verification")
        except CkrAssertionError as exc:
            # This is setup/operability evidence, not a C_Verify result. In
            # particular, never invent C_Sign as the operation when setup failed.
            _emit_rv(
                case,
                stage="sign_setup",
                operation=None,
                mechanism="CKM_SHA256_RSA_PKCS",
                rv=int(exc.rv),
            )
            _emit_done(case, "setup_refused")
            return

        _emit_rv(
            case,
            stage="sign",
            operation="C_Sign",
            mechanism="CKM_SHA256_RSA_PKCS",
            rv=0,
            value_len=len(sig),
        )
        if not sig:
            _emit_done(case, "malformed")
            return

        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0x01
        data = b"test data for verification"
        mech = CK_MECHANISM()
        mech.mechanism = CKM_SHA256_RSA_PKCS
        mech.pParameter = None
        mech.ulParameterLen = 0

        # First prove that this provider can verify its own successful signature.
        # The mutation oracle is valid only when this baseline succeeds, but the
        # mutated leg remains independently useful if baseline verification fails.
        rv = raw.C_VerifyInit(sh, ctypes.byref(mech), pub)
        if rv != 0:
            _emit_rv(
                case,
                stage="verify_baseline_init",
                operation="C_VerifyInit",
                mechanism="CKM_SHA256_RSA_PKCS",
                rv=int(rv),
            )
        else:
            _emit_rv(
                case,
                stage="verify_baseline_init",
                operation="C_VerifyInit",
                mechanism="CKM_SHA256_RSA_PKCS",
                rv=0,
            )
            data_buf = (ctypes.c_ubyte * len(data))(*data)
            sig_buf = (ctypes.c_ubyte * len(sig))(*sig)
            rv = raw.C_Verify(sh, data_buf, len(data), sig_buf, len(sig))
            _emit_rv(
                case,
                stage="verify_baseline",
                operation="C_Verify",
                mechanism="CKM_SHA256_RSA_PKCS",
                rv=int(rv),
            )

        # Re-initialize before the actual corrupted-signature check. Providers
        # are allowed to terminate the baseline operation, but the second leg
        # must be an explicit independent observation.
        rv = raw.C_VerifyInit(sh, ctypes.byref(mech), pub)
        _emit_rv(
            case,
            stage="verify_init",
            operation="C_VerifyInit",
            mechanism="CKM_SHA256_RSA_PKCS",
            rv=int(rv),
        )
        if rv == 0:
            data_buf = (ctypes.c_ubyte * len(data))(*data)
            sig_buf = (ctypes.c_ubyte * len(bad_sig))(*bad_sig)
            rv = raw.C_Verify(sh, data_buf, len(data), sig_buf, len(bad_sig))
            _emit_rv(
                case,
                stage="verify",
                operation="C_Verify",
                mechanism="CKM_SHA256_RSA_PKCS",
                rv=int(rv),
            )
        _emit_done(case, "complete")
    finally:
        _destroy_pair(raw, sh, pub, priv)


_DISPATCH: dict[str, Callable[[ProbeContext, dict[str, Any]], None]] = {
    "decrypt": _run_decrypt,
    "verify": _run_verify,
}


def _main(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe: str = extra["probe"]
    handler = _DISPATCH.get(probe)
    if handler is None:
        raise ValueError(f"error_path_rsa probe: unknown 'probe' value {probe!r}")
    handler(ctx, extra)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
