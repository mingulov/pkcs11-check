"""Readability recipes on top of pkcs11_check.raw.

These helpers simplify common test patterns without hiding the underlying
PKCS#11 operations. A recipe must be mentally expandable to its raw calls.
"""

from __future__ import annotations

import ctypes
import sys
from collections.abc import Callable, Mapping
from ctypes import byref
from enum import Flag, auto
from typing import Any

from .api import RawPKCS11
from .attr_metadata import ATTR_VALUE_TYPES
from .bootstrap import get_slot_ids, login_user, open_session
from .pack import (
    PackedMechanism,
    attr_bytes,
    attr_ulong,
    mech_eddsa,
    mech_simple,
    template,
    template_ptr_count,
)
from .rv import expect_rv
from .types_std import (
    CK_ATTRIBUTE,
    CK_BBOOL,
    CK_MECHANISM_INFO,
    CK_OBJECT_HANDLE,
    CK_SESSION_INFO,
    CK_SLOT_INFO,
    CK_ULONG,
    CKA,
    CKA_BASE,
    CKA_CLASS,
    CKA_COEFFICIENT,
    CKA_DECRYPT,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_EXTRACTABLE,
    CKA_GOSTR3410_PARAMS,
    CKA_GOSTR3411_PARAMS,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_MODULUS_BITS,
    CKA_PARAMETER_SET,
    CKA_PRIME,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_PRIVATE_EXPONENT,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_SUBPRIME,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKF_DECRYPT,
    CKF_DIGEST,
    CKF_ENCRYPT,
    CKF_MESSAGE_DECRYPT,
    CKF_MESSAGE_ENCRYPT,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKF_SIGN,
    CKF_SIGN_RECOVER,
    CKF_VERIFY,
    CKF_VERIFY_RECOVER,
    CKK,
    CKK_AES,
    CKK_DSA,
    CKK_EC,
    CKK_GOSTR3410,
    CKK_RSA,
    CKM,
    CKM_AES_KEY_GEN,
    CKM_EC_KEY_PAIR_GEN,
    CKM_EDDSA,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
)

_VERIFY_FAIL_RVS = (CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE)


def to_ubyte_buf(data: bytes) -> ctypes.Array[ctypes.c_ubyte]:
    """Convert bytes to a ctypes c_ubyte array.

    Uses ``from_buffer_copy`` so large payloads (AEAD plaintext, wrapped keys,
    signed data) copy at memcpy speed instead of per-byte Python conversion
    that ``(c_ubyte * N)(*data)`` would impose.
    """
    n = len(data)
    if n == 0:
        return (ctypes.c_ubyte * 0)()
    return (ctypes.c_ubyte * n).from_buffer_copy(data)


def _alloc_module_output(size: int, *, what: str) -> ctypes.Array[ctypes.c_ubyte]:
    """Allocate a ``CK_BYTE * size`` output buffer sized from a module-reported length.

    A conformant module reports its real output length; a module that reports an absurd
    length (e.g. an error sentinel left in the length out-param) would make the allocation
    raise an opaque ``OverflowError``/``MemoryError`` that surfaces as a cryptic harness
    error and masks the real finding.  Re-raise it as a legible ``ValueError`` naming the
    reported size and call so the module's bad length report stays diagnosable.  No upper
    cap is imposed, so a genuinely-large legitimate output is never rejected.
    """
    try:
        return (ctypes.c_ubyte * size)()
    except (OverflowError, MemoryError) as exc:
        raise ValueError(
            f"{what}: module reported an implausible output length ({size} bytes)"
        ) from exc


def _cancel_operation(raw: RawPKCS11, session: int, flags: int) -> None:
    """Best-effort cancel of a dangling active operation on ``session``.

    Used by single-shot recipes when the terminal call raises after a
    successful ``*Init``: without this, the session is left with an active
    operation and a later op may return a spurious ``CKR_OPERATION_ACTIVE``,
    mis-attributing a finding to the wrong call.

    Uses ``C_SessionCancel`` (PKCS#11 v3.0+, the spec-blessed way to abort an
    in-progress operation). Behaviour-based, not version-based: it simply tries
    the call. A module that does not expose ``C_SessionCancel`` (pre-v3.0, or a
    v3.x module whose function pointer is NULL) raises ``AttributeError`` from
    the binding; a malformed invocation raises ``OSError`` / ``ctypes.ArgumentError``.
    All are swallowed because this is best-effort teardown -- it must never mask
    the original error on the terminal-failure path, nor turn a failed cancel on
    the recovery path into a hard error (the caller re-checks the actual
    operation state and escalates to a session reopen if it is still active). The
    cancel's own return value is likewise ignored: the effect is verified by the
    caller, never the cancel's claim.
    """
    try:
        raw.C_SessionCancel(session, flags)
    except (AttributeError, OSError, ctypes.ArgumentError):
        # C_SessionCancel absent (pre-v3.0 / NULL pointer) or the call failed.
        # Nothing portable to do here; the caller's retry + reopen fallback (or
        # the per-test/subprocess session teardown) still bounds the leak.
        pass


# Every single-shot crypto operation class -- the mask used when recovering from
# a stale operation whose class we do not know (it may differ from the init we
# are retrying, e.g. a leftover verify op blocking a later init on a buggy module).
_ALL_OP_FLAGS = (
    CKF_ENCRYPT
    | CKF_DECRYPT
    | CKF_DIGEST
    | CKF_SIGN
    | CKF_SIGN_RECOVER
    | CKF_VERIFY
    | CKF_VERIFY_RECOVER
)


# Set when a single-shot recipe meets a CKR_OPERATION_ACTIVE it cannot clear in
# place (e.g. a v2.40 module with no C_SessionCancel, whose NULL-mechanism
# C_VerifyInit does not cancel either -- only closing+reopening the session clears
# the stale op). The module-scoped session holder consumes this on the next handout
# and reopens, so the cascade stops at one collateral failure instead of running to
# the end of the file. Process-global is safe under the per-file subprocess runner
# (one session, one thread); a spurious reopen for a function-scoped session is
# harmless.
_SESSION_REOPEN_REQUESTED = False


def request_session_reopen() -> None:
    """Ask the shared-session holder to reopen before the next handout."""
    global _SESSION_REOPEN_REQUESTED
    _SESSION_REOPEN_REQUESTED = True


def consume_session_reopen_request() -> bool:
    """Return whether a reopen was requested since the last call, and clear it."""
    global _SESSION_REOPEN_REQUESTED
    requested = _SESSION_REOPEN_REQUESTED
    _SESSION_REOPEN_REQUESTED = False
    return requested


def _init_or_recover(raw: RawPKCS11, session: int, init_fn: Callable[[], int]) -> int:
    """Run a single-shot ``C_*Init``; recover from a non-compliant provider's stale op.

    A ``C_*Init`` returns ``CKR_OPERATION_ACTIVE`` when an operation of that class
    is already active on the session. Some modules violate the spec by leaving
    a verify operation active after ``C_Verify`` rejects a signature ("a call to
    C_Verify always terminates the active verification operation"); on a shared
    module-scoped session that makes
    the NEXT test's ``C_*Init`` return ``CKR_OPERATION_ACTIVE`` and cascade onto
    every following test.

    Recovery is tiered and fires ONLY on ``CKR_OPERATION_ACTIVE`` (the common clean
    path runs the init exactly once, so this does not regress RPC-bound modules):

    1. ``C_SessionCancel`` the stale op and retry the init once (works on
       PKCS#11 v3.0+ modules -- cheap, same session handle).
    2. If the init still reports the op active (e.g. a v2.40 module with no
       ``C_SessionCancel``, and no other in-place cancel works), request a session
       reopen via :func:`request_session_reopen`. The recipe cannot reopen itself
       (that would change the handle the caller holds), so the current call still
       surfaces ``CKR_OPERATION_ACTIVE``; the holder reopens before the next test,
       stopping the cascade at a single collateral failure.

    The return value is surfaced unchanged (never looped, never masked); the
    genuine provider bug is reported as a FAIL by
    ``testcases/test_operation_termination.py``.
    """
    rv = init_fn()
    if rv == CKR_OPERATION_ACTIVE:
        _cancel_operation(raw, session, _ALL_OP_FLAGS)
        rv = init_fn()
        if rv == CKR_OPERATION_ACTIVE:
            request_session_reopen()
    return rv


def _resolve_mech(
    mechanism: CKM | int,
    mech_param: PackedMechanism | None,
) -> PackedMechanism:
    """Return mech_param if given, otherwise wrap mechanism as mech_simple.

    For CKM_EDDSA, always use mech_eddsa() with pure mode (no context)
    since some modules require explicit params even for pure EdDSA.
    """
    if mech_param is not None:
        return mech_param
    if mechanism == CKM_EDDSA:
        return mech_eddsa(mechanism)
    return mech_simple(mechanism)


def _two_call_output(
    raw: RawPKCS11,
    call_fn: str,
    *args: Any,
    output_size_hint: int = 0,
    retry_on_buffer_too_small: bool = False,
) -> bytes:
    """Execute a PKCS#11 function using the standard two-call size pattern.

    ``args`` are ALL arguments before the output (buffer_ptr, buffer_len_ptr) pair,
    including session. The function appends the buffer pair automatically.

    Works for: C_Encrypt, C_Sign, C_Decrypt, C_Digest, C_WrapKey, C_GetOperationState,
    C_SignFinal, C_DigestFinal.

    NOT suitable for:
    - C_EncryptUpdate / C_DecryptUpdate (conditional zero-length output, use _multipart_output)
    - C_EncryptMessage / C_DecryptMessage (extra aad args, use _message_crypto)
    - C_EncapsulateKey (output buffer not the last arg, extra handle output after it)
    - C_GetMechanismList / C_GetSlotList / C_GetAttributeValue (non-byte array types)

    ``output_size_hint`` enables single-call mode for modules that do not support the
    NULL-buffer size-query pass (e.g. for AES-GCM / AES-KEY-WRAP-KWP on some modules).
    When provided, the NULL-buffer query is skipped entirely and a single call is made
    with a pre-allocated buffer of ``output_size_hint`` bytes.  The output is truncated
    to the length reported by the module after the call.

    ``retry_on_buffer_too_small`` when True, if the second call returns
    CKR_BUFFER_TOO_SMALL and the module provides a larger required size,
    re-allocates and retries once.  Needed for modules that under-report the
    required size on the NULL-buffer query (returning plaintext length without
    AEAD tag overhead).

    Per PKCS#11 spec section 5.2, the standard two-call pattern is used when
    ``output_size_hint`` is 0: first call with NULL buffer to obtain the required size,
    then second call with a properly allocated buffer.
    """
    fn = getattr(raw, call_fn)
    if output_size_hint > 0:
        # Single-call mode: allocate upfront and call once.
        # Required for modules where passing NULL on the first
        # call either fails to set the output length or consumes the operation state.
        out_len = CK_ULONG(output_size_hint)
        out_buf = (ctypes.c_ubyte * output_size_hint)()
        rv = fn(*args, out_buf, byref(out_len))
        if (
            retry_on_buffer_too_small
            and rv == CKR_BUFFER_TOO_SMALL
            and out_len.value > output_size_hint
        ):
            # The hint under-estimated the output; the module reported the true
            # size in out_len on the failing call. Re-allocate and retry once.
            # This keeps callers that pass an exact-size hint (e.g. CFB/OFB,
            # where ciphertext length == plaintext length) correct even if a
            # module unexpectedly needs more space — the size query is skipped
            # for speed, but a wrong guess is recovered, never silently dropped.
            size = out_len.value
            out_buf = _alloc_module_output(size, what=call_fn)
            out_len = CK_ULONG(size)
            rv = fn(*args, out_buf, byref(out_len))
        expect_rv(rv, CKR_OK)
        return bytes(out_buf[: out_len.value])
    # Standard two-call pattern: query size with NULL, then allocate and call again.
    out_len = CK_ULONG(0)
    rv = fn(*args, None, byref(out_len))
    expect_rv(rv, CKR_OK, CKR_BUFFER_TOO_SMALL)
    size = out_len.value
    out_buf = _alloc_module_output(size, what=call_fn)
    out_len = CK_ULONG(size)
    rv = fn(*args, out_buf, byref(out_len))
    if retry_on_buffer_too_small and rv == CKR_BUFFER_TOO_SMALL and out_len.value > size:
        # Module under-reported the required size but set out_len to the
        # correct value on failure.  Re-allocate and retry.
        size = out_len.value
        out_buf = _alloc_module_output(size, what=call_fn)
        out_len = CK_ULONG(size)
        rv = fn(*args, out_buf, byref(out_len))
    expect_rv(rv, CKR_OK)
    return bytes(out_buf[: out_len.value])


def quick_session(
    raw: RawPKCS11,
    slot_id: int | None = None,
    flags: int = CKF_SERIAL_SESSION | CKF_RW_SESSION,
    pin: bytes | None = None,
    user_type: int = 1,  # CKU_USER
) -> int:
    """Open a session and optionally login in one call.

    If slot_id is None, the first available slot with a token is used.
    """
    if slot_id is None:
        slots = get_slot_ids(raw)
        if not slots:
            raise RuntimeError("No slots with tokens found")
        slot_id = slots[0]

    sh = open_session(raw, slot_id, flags)

    if pin is not None:
        login_user(raw, sh, user_type, pin)

    return sh


def pack_attrs(
    attrs: Mapping[Any, Any] | None,
    *,
    skip: set[Any] | frozenset[Any] | None = None,
) -> list[Any]:
    """Convert a {attr_type: value} dict to a list of PackedAttributes.

    Uses attr_auto for spec-correct type packing based on ATTR_VALUE_TYPES.
    Skips attr types in skip set. Both `attrs` keys and `skip` members are
    treated as integers internally (CKA values are `int` subclasses); the
    parameter types are intentionally `Mapping[Any, Any]` / `set[Any]`
    because `dict`/`set` type parameters are invariant — narrower types
    would reject `dict[CKA, ...]` / `set[CKA]` at every callsite.
    """
    if not attrs:
        return []
    from .pack import attr_auto

    return [
        attr_auto(attr_type, value)
        for attr_type, value in attrs.items()
        if not (skip and attr_type in skip)
    ]


def gen_aes_key(
    raw: RawPKCS11,
    sh: int,
    bits: int = 256,
    attrs: Mapping[Any, Any] | None = None,
    mechanism: int = CKM_AES_KEY_GEN,
) -> int:
    """Generate an AES key with explicit attributes."""
    _defaults: dict[int, Any] = {
        CKA_ENCRYPT: True,
        CKA_DECRYPT: True,
    }
    if mechanism == CKM_AES_KEY_GEN:
        _defaults[CKA_KEY_TYPE] = CKK_AES
    if attrs:
        _defaults.update(attrs)
    packed = [attr_ulong(CKA_VALUE_LEN, bits // 8)]
    packed.extend(pack_attrs(_defaults, skip={CKA_VALUE_LEN}))
    tmpl = template(*packed)
    mech = mech_simple(mechanism)
    key = CK_OBJECT_HANDLE(0)

    rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key))
    expect_rv(rv, CKR_OK)
    return key.value


def gen_keypair(
    raw: RawPKCS11,
    session: int,
    mechanism: int,
    pub_base: list[Any],
    priv_base: list[Any],
    public_attrs: Mapping[Any, Any] | None,
    private_attrs: Mapping[Any, Any] | None,
    pub_skip: set[Any] | frozenset[Any] | None = None,
) -> tuple[int, int]:
    """Shared keypair generation logic."""
    pub_packed = pub_base + pack_attrs(public_attrs, skip=pub_skip)
    priv_packed = priv_base + pack_attrs(private_attrs)
    pub_tmpl = template(*pub_packed)
    priv_tmpl = template(*priv_packed)
    mech = mech_simple(mechanism)
    pub_handle = CK_OBJECT_HANDLE(0)
    priv_handle = CK_OBJECT_HANDLE(0)

    rv = raw.C_GenerateKeyPair(
        session,
        mech.byref(),
        pub_tmpl.ptr,
        pub_tmpl.count,
        priv_tmpl.ptr,
        priv_tmpl.count,
        byref(pub_handle),
        byref(priv_handle),
    )
    expect_rv(rv, CKR_OK)
    return pub_handle.value, priv_handle.value


class RSAUsage(Flag):
    """Declared purpose of an RSA key pair, mapped to capability attributes.

    Purpose is a *crypto-visible* attribute: it changes what the key is and
    which operation may use it, so it must be declared explicitly by the caller
    rather than inferred or silently negotiated. Single-purpose providers
    (Cloud-KMS-class) back keys that are sign-only XOR decrypt-only
    and reject the multi-purpose combination with CKR_TEMPLATE_INCONSISTENT;
    pass ``RSAUsage.SIGN`` or ``RSAUsage.DECRYPT`` to target them.
    """

    SIGN = auto()  # private CKA_SIGN / public CKA_VERIFY
    DECRYPT = auto()  # private CKA_DECRYPT / public CKA_ENCRYPT


def rsa_usage_attrs(usage: RSAUsage) -> tuple[dict[CKA, Any], dict[CKA, Any]]:
    """Map an RSAUsage to ``(public_attrs, private_attrs)`` capability flags."""
    pub: dict[CKA, Any] = {}
    priv: dict[CKA, Any] = {}
    if RSAUsage.SIGN in usage:
        priv[CKA_SIGN] = True
        pub[CKA_VERIFY] = True
    if RSAUsage.DECRYPT in usage:
        priv[CKA_DECRYPT] = True
        pub[CKA_ENCRYPT] = True
    return pub, priv


def gen_rsa_keypair(
    raw: RawPKCS11,
    session: int,
    bits: int = 2048,
    *,
    usage: RSAUsage = RSAUsage.SIGN | RSAUsage.DECRYPT,
    public_attrs: Mapping[Any, Any] | None = None,
    private_attrs: Mapping[Any, Any] | None = None,
) -> tuple[int, int]:
    """Generate an RSA key pair. Returns (pub_handle, priv_handle).

    ``usage`` declares the key's purpose (default: multi-purpose sign+decrypt,
    preserving legacy behaviour). Pass ``RSAUsage.SIGN`` / ``RSAUsage.DECRYPT``
    for a single-purpose key on Cloud-KMS-class providers. ``public_attrs`` /
    ``private_attrs`` remain an explicit per-attribute override (escape hatch).
    """
    pub_caps, priv_caps = rsa_usage_attrs(usage)
    _pub_defaults: dict[CKA, Any] = {
        **pub_caps,
        CKA_PUBLIC_EXPONENT: b"\x01\x00\x01",  # 65537 (standard RSA public exponent)
    }
    _priv_defaults: dict[CKA, Any] = {**priv_caps}
    if public_attrs:
        _pub_defaults.update(public_attrs)
    if private_attrs:
        _priv_defaults.update(private_attrs)
    return gen_keypair(
        raw,
        session,
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        pub_base=[attr_ulong(CKA_MODULUS_BITS, bits)],
        priv_base=[],
        public_attrs=_pub_defaults,
        private_attrs=_priv_defaults,
        pub_skip={CKA_MODULUS_BITS},
    )


def gen_ec_keypair(
    raw: RawPKCS11,
    session: int,
    curve_oid: bytes,
    public_attrs: Mapping[Any, Any] | None = None,
    private_attrs: Mapping[Any, Any] | None = None,
) -> tuple[int, int]:
    """Generate an EC key pair. Returns (pub_handle, priv_handle)."""
    _pub_defaults: dict[CKA, Any] = {CKA_VERIFY: True}
    _priv_defaults: dict[CKA, Any] = {CKA_SIGN: True}
    if public_attrs:
        _pub_defaults.update(public_attrs)
    if private_attrs:
        _priv_defaults.update(private_attrs)
    return gen_keypair(
        raw,
        session,
        CKM_EC_KEY_PAIR_GEN,
        pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
        priv_base=[],
        public_attrs=_pub_defaults,
        private_attrs=_priv_defaults,
        pub_skip={CKA_EC_PARAMS},
    )


def import_secret_key(
    raw: RawPKCS11,
    session: int,
    key_type: CKK | int,
    value: bytes,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import a secret key by value using C_CreateObject."""
    base = {CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE}
    packed = [
        attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
        attr_ulong(CKA_KEY_TYPE, key_type),
        attr_bytes(CKA_VALUE, value),
    ]
    packed.extend(pack_attrs(attrs, skip=base))

    tmpl = template(*packed)
    handle = CK_OBJECT_HANDLE(0)

    rv = raw.C_CreateObject(session, tmpl.ptr, tmpl.count, byref(handle))
    expect_rv(rv, CKR_OK)

    return handle.value


def import_rsa_private_key(
    raw: Any,
    session: int,
    *,
    n: bytes,
    e: bytes,
    d: bytes,
    p: bytes,
    q: bytes,
    dmp1: bytes,
    dmq1: bytes,
    iqmp: bytes,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import RSA private key from CRT components."""
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PRIVATE_KEY,
        CKA_KEY_TYPE: CKK_RSA,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_MODULUS: n,
        CKA_PUBLIC_EXPONENT: e,
        CKA_PRIVATE_EXPONENT: d,
        CKA_PRIME_1: p,
        CKA_PRIME_2: q,
        CKA_EXPONENT_1: dmp1,
        CKA_EXPONENT_2: dmq1,
        CKA_COEFFICIENT: iqmp,
    }
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def import_rsa_public_key(
    raw: Any,
    session: int,
    *,
    n: bytes,
    e: bytes,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import RSA public key from modulus + exponent."""
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_KEY_TYPE: CKK_RSA,
        CKA_TOKEN: False,
        CKA_MODULUS: n,
        CKA_PUBLIC_EXPONENT: e,
    }
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def import_ec_private_key(
    raw: Any,
    session: int,
    *,
    ec_params: bytes,
    value: bytes,
    key_type: int = int(CKK_EC),
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import EC/Edwards/Montgomery private key from scalar.

    ``ec_params``: DER-encoded curve OID.
    ``value``: raw big-endian private scalar (or seed for EdDSA).
    ``key_type``: CKK_EC (default), CKK_EC_EDWARDS, or CKK_EC_MONTGOMERY.
    """
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PRIVATE_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_EC_PARAMS: ec_params,
        CKA_VALUE: value,
    }
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def import_ec_public_key(
    raw: Any,
    session: int,
    *,
    ec_params: bytes,
    ec_point: bytes,
    key_type: int = int(CKK_EC),
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import EC/Edwards/Montgomery public key from point.

    ``ec_params``: DER-encoded curve OID.
    ``ec_point``: for CKK_EC, DER-wrapped ANSI X9.62 point; for Edwards and
        Montgomery keys, raw public key bytes as defined by their RFCs.
    ``key_type``: CKK_EC (default), CKK_EC_EDWARDS, or CKK_EC_MONTGOMERY.
    """
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_TOKEN: False,
        CKA_EC_PARAMS: ec_params,
        CKA_EC_POINT: ec_point,
    }
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def import_pqc_private_key(
    raw: Any,
    session: int,
    *,
    key_type: int,
    value: bytes,
    parameter_set: int,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import PQC private key (ML-DSA, ML-KEM, SLH-DSA).

    ``key_type``: CKK_ML_DSA, CKK_ML_KEM, or CKK_SLH_DSA.
    ``value``: raw private key bytes.
    ``parameter_set``: CKP_* parameter set constant.
    """
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PRIVATE_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_VALUE: value,
        CKA_PARAMETER_SET: parameter_set,
    }
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def import_pqc_public_key(
    raw: Any,
    session: int,
    *,
    key_type: int,
    value: bytes,
    parameter_set: int,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import PQC public key (ML-DSA, SLH-DSA)."""
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_TOKEN: False,
        CKA_VALUE: value,
        CKA_PARAMETER_SET: parameter_set,
    }
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def import_dsa_public_key(
    raw: Any,
    session: int,
    *,
    prime: bytes,
    subprime: bytes,
    base_g: bytes,
    value: bytes,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import DSA public key from domain parameters + public value.

    ``prime``: p. ``subprime``: q. ``base_g``: g. ``value``: y.
    """
    base_attrs: dict[int, Any] = {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_KEY_TYPE: CKK_DSA,
        CKA_TOKEN: False,
        CKA_PRIME: prime,
        CKA_SUBPRIME: subprime,
        CKA_BASE: base_g,
        CKA_VALUE: value,
    }
    if attrs:
        base_attrs.update(attrs)
    return create_object(raw, session, base_attrs)


def import_gost_private_key(
    raw: Any,
    session: int,
    *,
    gostr3410_params: bytes,
    value: bytes,
    gostr3411_params: bytes | None = None,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import GOST R 34.10-2012 private key.

    ``gostr3410_params``: DER-encoded OID for the curve parameters.
    ``value``: raw big-endian private key scalar.
    ``gostr3411_params``: optional DER-encoded hash parameter OID.
    """
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PRIVATE_KEY,
        CKA_KEY_TYPE: CKK_GOSTR3410,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_GOSTR3410_PARAMS: gostr3410_params,
        CKA_VALUE: value,
    }
    if gostr3411_params is not None:
        base[CKA_GOSTR3411_PARAMS] = gostr3411_params
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def import_gost_public_key(
    raw: Any,
    session: int,
    *,
    gostr3410_params: bytes,
    value: bytes,
    gostr3411_params: bytes | None = None,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Import GOST R 34.10-2012 public key."""
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_KEY_TYPE: CKK_GOSTR3410,
        CKA_TOKEN: False,
        CKA_GOSTR3410_PARAMS: gostr3410_params,
        CKA_VALUE: value,
    }
    if gostr3411_params is not None:
        base[CKA_GOSTR3411_PARAMS] = gostr3411_params
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)


def create_object(
    raw: RawPKCS11,
    session: int,
    attrs: dict[int, Any],
) -> int:
    """Create a PKCS#11 object with arbitrary attributes. Returns handle.

    attrs maps CKA_* int constants to values (bool, int, bytes, or str).
    str values auto-encode to UTF-8. For secret key import, prefer
    import_secret_key() which handles CKA_CLASS/CKA_KEY_TYPE/CKA_VALUE.
    """
    packed = pack_attrs(attrs)
    tmpl = template(*packed)
    handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(session, tmpl.ptr, tmpl.count, byref(handle))
    expect_rv(rv, CKR_OK)
    return handle.value


def destroy_quietly(raw: RawPKCS11, session: int, handle: int) -> None:
    """Destroy an object, silently ignoring any errors."""
    try:
        raw.C_DestroyObject(session, handle)
    except (AttributeError, OSError, ctypes.ArgumentError):
        pass


def encrypt_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    plaintext: bytes,
    *,
    mech_param: PackedMechanism | None = None,
    output_overhead: int = 0,
    output_size_hint: int = 0,
    retry_on_buffer_too_small: bool = False,
) -> bytes:
    """Encrypt data in a single operation. Returns ciphertext.

    ``output_overhead`` is the number of bytes the mechanism appends beyond the
    plaintext length (e.g. 16 for AES-GCM with a 128-bit tag).  This is only
    needed for modules that do not set the output length
    when called with a NULL buffer pointer during the size-query pass.

    ``output_size_hint`` (> 0) skips the NULL-buffer size-query pass entirely
    and goes straight to a single call with a pre-allocated buffer of that
    size.  Pass it for stream/feedback modes where the ciphertext length equals
    the plaintext length exactly (CFB/OFB) to halve the per-op round-trips on
    transport-bound modules.  It takes precedence over ``output_overhead``.

    ``retry_on_buffer_too_small`` when True, if the (single or post-probe) call
    returns CKR_BUFFER_TOO_SMALL with an updated size, re-allocates and retries
    once — the safety net that makes a too-small ``output_size_hint`` correct
    rather than a hard failure.
    """
    mech = _resolve_mech(mechanism, mech_param)
    rv = _init_or_recover(raw, session, lambda: raw.C_EncryptInit(session, mech.byref(), key))
    expect_rv(rv, CKR_OK)
    in_buf = to_ubyte_buf(plaintext)
    hint = output_size_hint or ((len(plaintext) + output_overhead) if output_overhead > 0 else 0)
    try:
        return _two_call_output(
            raw,
            "C_Encrypt",
            session,
            in_buf,
            len(plaintext),
            output_size_hint=hint,
            retry_on_buffer_too_small=retry_on_buffer_too_small,
        )
    except BaseException:
        # Terminal call failed after C_EncryptInit succeeded: cancel the
        # dangling operation so it does not leak into the next op on a reused
        # session, then re-raise the original error unchanged.
        _cancel_operation(raw, session, int(CKF_ENCRYPT))
        raise


def sign_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    data: bytes,
    *,
    mech_param: PackedMechanism | None = None,
    output_size_hint: int = 0,
) -> bytes:
    """Sign data in a single operation. Returns signature.

    ``output_size_hint`` skips the NULL-buffer size-query and pre-allocates a
    fixed-size buffer.  Useful for fixed-length signatures (ECDSA, Ed25519)
    on modules that fail the NULL probe.
    """
    mech = _resolve_mech(mechanism, mech_param)
    rv = _init_or_recover(raw, session, lambda: raw.C_SignInit(session, mech.byref(), key))
    expect_rv(rv, CKR_OK)
    in_buf = to_ubyte_buf(data)
    try:
        return _two_call_output(
            raw,
            "C_Sign",
            session,
            in_buf,
            len(data),
            output_size_hint=output_size_hint,
        )
    except BaseException:
        _cancel_operation(raw, session, int(CKF_SIGN))
        raise


def decrypt_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    ciphertext: bytes,
    *,
    mech_param: PackedMechanism | None = None,
    retry_on_buffer_too_small: bool = False,
    output_size_hint: int = 0,
) -> bytes:
    """Decrypt data in a single operation. Returns plaintext.

    The two output-sizing kwargs are independent and combine cleanly:

    - ``output_size_hint > 0`` skips the NULL-buffer size probe and goes
      straight to a single call with a pre-allocated ``output_size_hint``-byte
      buffer.  Needed for modules that fail the NULL
      probe or consume operation state during it.  Pass ``len(ciphertext)``
      for AEAD (plaintext is at most that size).
    - ``retry_on_buffer_too_small`` when True, if the (single or post-probe)
      call returns CKR_BUFFER_TOO_SMALL with an updated size, re-allocates
      and retries once.  Useful as a safety net when ``output_size_hint``
      might under-estimate the real output (e.g. AEAD with unknown padding).
    """
    mech = _resolve_mech(mechanism, mech_param)
    rv = _init_or_recover(raw, session, lambda: raw.C_DecryptInit(session, mech.byref(), key))
    expect_rv(rv, CKR_OK)
    in_buf = to_ubyte_buf(ciphertext)
    try:
        return _two_call_output(
            raw,
            "C_Decrypt",
            session,
            in_buf,
            len(ciphertext),
            retry_on_buffer_too_small=retry_on_buffer_too_small,
            output_size_hint=output_size_hint,
        )
    except BaseException:
        _cancel_operation(raw, session, int(CKF_DECRYPT))
        raise


def verify_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    data: bytes,
    signature: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bool:
    """Verify a signature in a single operation.

    Returns True if verification succeeds (CKR_OK), False if CKR_SIGNATURE_INVALID
    or CKR_SIGNATURE_LEN_RANGE. Other errors raise AssertionError.
    """
    mech = _resolve_mech(mechanism, mech_param)
    rv = _init_or_recover(raw, session, lambda: raw.C_VerifyInit(session, mech.byref(), key))
    expect_rv(rv, CKR_OK)

    data_buf = to_ubyte_buf(data)
    sig_buf = to_ubyte_buf(signature)
    rv = raw.C_Verify(session, data_buf, len(data), sig_buf, len(signature))

    if rv == CKR_OK:
        return True
    if rv in _VERIFY_FAIL_RVS:
        # Per spec a completed C_Verify terminates the operation, including the
        # signature-mismatch outcomes -- no cancel needed here.
        return False
    # Unexpected CKR: the operation may still be active (C_Verify did not
    # complete). Cancel before surfacing the wrong-code finding.
    try:
        expect_rv(rv, CKR_OK)
    except BaseException:
        _cancel_operation(raw, session, int(CKF_VERIFY))
        raise
    return False  # unreachable


def sign_recover_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    data: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Sign and recover data in a single operation (C_SignRecoverInit + C_SignRecover)."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = _init_or_recover(raw, session, lambda: raw.C_SignRecoverInit(session, mech.byref(), key))
    if rv == CKR_FUNCTION_NOT_SUPPORTED:
        raise NotImplementedError("C_SignRecover not supported by this module")
    expect_rv(rv, CKR_OK)
    in_buf = to_ubyte_buf(data)
    return _two_call_output(raw, "C_SignRecover", session, in_buf, len(data))


def verify_recover_single(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    signature: bytes,
) -> tuple[bool, bytes]:
    """Verify and recover data (C_VerifyRecoverInit + C_VerifyRecover).

    Returns (True, recovered_data) on valid signature,
    (False, b"") on CKR_SIGNATURE_INVALID or CKR_SIGNATURE_LEN_RANGE.
    Raises on unexpected CKR values.

    Per PKCS#11 spec, CKR_SIGNATURE_INVALID has higher priority than
    CKR_BUFFER_TOO_SMALL for C_VerifyRecover.
    """
    mech = _resolve_mech(mechanism, None)
    rv = _init_or_recover(raw, session, lambda: raw.C_VerifyRecoverInit(session, mech.byref(), key))
    if rv == CKR_FUNCTION_NOT_SUPPORTED:
        raise NotImplementedError("C_VerifyRecover not supported by this module")
    expect_rv(rv, CKR_OK)
    sig_buf = to_ubyte_buf(signature)
    rec_len = CK_ULONG(0)
    rv = raw.C_VerifyRecover(session, sig_buf, len(signature), None, byref(rec_len))
    if rv in _VERIFY_FAIL_RVS:
        return False, b""
    expect_rv(rv, CKR_OK)
    rec_buf = _alloc_module_output(rec_len.value, what="C_VerifyRecover")
    rv = raw.C_VerifyRecover(session, sig_buf, len(signature), rec_buf, byref(rec_len))
    if rv in _VERIFY_FAIL_RVS:
        return False, b""
    expect_rv(rv, CKR_OK)
    return True, bytes(rec_buf[: rec_len.value])


def digest_single(
    raw: RawPKCS11,
    session: int,
    mechanism: CKM | int,
    data: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Digest data in a single operation. Returns digest."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = _init_or_recover(raw, session, lambda: raw.C_DigestInit(session, mech.byref()))
    expect_rv(rv, CKR_OK)
    in_buf = to_ubyte_buf(data)
    return _two_call_output(raw, "C_Digest", session, in_buf, len(data))


def digest_single_with_key(
    raw: RawPKCS11,
    session: int,
    mechanism: CKM | int,
    key: int,
) -> bytes:
    """Digest a secret key value (C_DigestInit + C_DigestKey + C_DigestFinal).

    The key material is digested directly without exposing it outside the token.
    """
    mech = _resolve_mech(mechanism, None)
    rv = _init_or_recover(raw, session, lambda: raw.C_DigestInit(session, mech.byref()))
    expect_rv(rv, CKR_OK)
    rv = raw.C_DigestKey(session, key)
    if rv == CKR_FUNCTION_NOT_SUPPORTED:
        raise NotImplementedError("C_DigestKey not supported by this module")
    expect_rv(rv, CKR_OK)
    return _two_call_output(raw, "C_DigestFinal", session)


def read_attributes(
    raw: RawPKCS11,
    session: int,
    handle: int,
    attr_types: list[int] | tuple[int, ...] | set[int] | frozenset[int],
) -> dict[int, Any]:
    """Read attribute values from an object.

    Returns a dict mapping attribute type to its value. Uses the generated
    ATTR_VALUE_TYPES table for spec-correct decoding: bool attrs as bool,
    ulong attrs as int, str attrs as str, date attrs as 'YYYYMMDD' str,
    ulong_array attrs as list[int], template and unknown attrs as bytes.

    Returns `dict[int, Any]` (not the precise union) because callers
    typically know the expected attribute type and call type-specific
    methods (`.hex()`, `len()`, etc.); a precise union would force
    `isinstance` narrowing at every callsite without adding safety.
    """
    count = len(attr_types)
    tmpl = (CK_ATTRIBUTE * count)()
    for i, at in enumerate(attr_types):
        tmpl[i].type = at
        tmpl[i].pValue = None
        tmpl[i].ulValueLen = 0

    # CK_UNAVAILABLE_INFORMATION sentinel: ulValueLen set to (CK_ULONG)-1 for
    # sensitive or type-invalid attributes. Some modules return 0xFFFFFFFF
    # (32-bit sentinel) even on 64-bit platforms.
    _ck_unavailable_64 = ctypes.c_ulong(-1).value  # 0xFFFFFFFFFFFFFFFF on 64-bit
    _ck_unavailable_32 = 0xFFFFFFFF

    def _is_unavailable(val: int) -> bool:
        return val == _ck_unavailable_64 or val == _ck_unavailable_32

    # First call: query sizes
    rv = raw.C_GetAttributeValue(session, handle, tmpl, count)
    expect_rv(rv, CKR_OK, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID)

    # Allocate buffers (skip unavailable attributes)
    buffers: list[Any] = []
    for i in range(count):
        size = tmpl[i].ulValueLen
        if _is_unavailable(size):
            buffers.append(None)
            continue
        buf = _alloc_module_output(size, what="C_GetAttributeValue")
        tmpl[i].pValue = ctypes.cast(buf, ctypes.c_void_p)
        tmpl[i].ulValueLen = size
        buffers.append(buf)

    # Second call: read values
    rv = raw.C_GetAttributeValue(session, handle, tmpl, count)
    expect_rv(rv, CKR_OK, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID)

    result: dict[int, bytes | int | bool | str | list[int]] = {}
    for i, at in enumerate(attr_types):
        size = tmpl[i].ulValueLen
        if _is_unavailable(size) or buffers[i] is None:
            continue  # Attribute sensitive or type invalid -- skip
        raw_bytes = bytes(buffers[i][:size])
        vtype = ATTR_VALUE_TYPES.get(at, "bytes")
        if vtype == "bool" and size == ctypes.sizeof(CK_BBOOL):
            result[at] = raw_bytes[0] != 0
        elif vtype == "ulong" and size == ctypes.sizeof(CK_ULONG):
            result[at] = int.from_bytes(raw_bytes, byteorder=sys.byteorder)
        elif vtype == "str":
            result[at] = raw_bytes.decode("utf-8")
        elif vtype == "date":
            # Return as str 'YYYYMMDD' -- callers can parse if needed
            result[at] = raw_bytes.decode("ascii") if raw_bytes else ""
        elif vtype == "ulong_array":
            # Decode CK_ULONG array
            ulong_size = ctypes.sizeof(CK_ULONG)
            count_elems = size // ulong_size
            result[at] = [
                int.from_bytes(
                    raw_bytes[j * ulong_size : (j + 1) * ulong_size],
                    byteorder=sys.byteorder,
                )
                for j in range(count_elems)
            ]
        elif vtype == "template":
            # Template attributes are complex -- return raw bytes
            # Proper decoding requires recursive CK_ATTRIBUTE parsing
            result[at] = raw_bytes
        else:
            # 'bytes' or any unrecognized type
            result[at] = raw_bytes
    return result


def get_object_size(
    raw: RawPKCS11,
    session: int,
    handle: int,
) -> int:
    """Return the size of an object in bytes."""
    size = CK_ULONG(0)
    rv = raw.C_GetObjectSize(session, handle, byref(size))
    expect_rv(rv, CKR_OK)
    return size.value


def find_objects(
    raw: RawPKCS11,
    session: int,
    tmpl: Any = None,
    *,
    max_count: int = 256,
) -> list[int]:
    """Find objects matching a template.

    tmpl can be a TemplateArg from pack.py, or None for all objects.
    Returns a list of object handles.
    """
    if tmpl is not None:
        rv = raw.C_FindObjectsInit(session, tmpl.ptr, tmpl.count)
    else:
        rv = raw.C_FindObjectsInit(session, None, 0)
    expect_rv(rv, CKR_OK)

    handles = (CK_OBJECT_HANDLE * max_count)()
    found = CK_ULONG(0)
    try:
        rv = raw.C_FindObjects(session, handles, max_count, byref(found))
        expect_rv(rv, CKR_OK)
    except BaseException:
        # C_FindObjects raised after C_FindObjectsInit succeeded: release the
        # active search operation (its terminator is C_FindObjectsFinal) so a
        # later op on a reused session is not blocked, then re-raise.
        try:
            raw.C_FindObjectsFinal(session)
        except AttributeError:
            pass
        raise

    rv = raw.C_FindObjectsFinal(session)
    expect_rv(rv, CKR_OK)

    return [handles[i] for i in range(found.value)]


def wrap_key(
    raw: RawPKCS11,
    session: int,
    wrapping_key: int,
    target_key: int,
    mechanism: CKM | int,
    *,
    mech_param: PackedMechanism | None = None,
    output_size_hint: int = 0,
) -> bytes:
    """Wrap a key using C_WrapKey (two-call output pattern). Returns wrapped key.

    ``output_size_hint`` is used as the buffer allocation size when the module
    does not set the output length during the NULL-buffer size-query pass (e.g.
    for AES-KEY-WRAP-KWP on some modules).  It should be at least as large as the
    actual wrapped-key output.
    """
    mech = _resolve_mech(mechanism, mech_param)
    return _two_call_output(
        raw,
        "C_WrapKey",
        session,
        mech.byref(),
        wrapping_key,
        target_key,
        output_size_hint=output_size_hint,
    )


def unwrap_key(
    raw: RawPKCS11,
    session: int,
    unwrapping_key: int,
    wrapped_key: bytes,
    mechanism: CKM | int,
    attrs: Mapping[Any, Any] | None = None,
    *,
    mech_param: PackedMechanism | None = None,
) -> int:
    """Unwrap a key using C_UnwrapKey. Returns new key handle."""
    mech = _resolve_mech(mechanism, mech_param)
    packed = pack_attrs(attrs)
    tmpl = template(*packed) if packed else None
    in_buf = to_ubyte_buf(wrapped_key)
    handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_UnwrapKey(
        session,
        mech.byref(),
        unwrapping_key,
        in_buf,
        len(wrapped_key),
        *template_ptr_count(tmpl),
        byref(handle),
    )
    expect_rv(rv, CKR_OK)
    return handle.value


def derive_key(
    raw: RawPKCS11,
    session: int,
    base_key: int,
    mechanism: CKM | int,
    attrs: Mapping[Any, Any] | None = None,
    *,
    mech_param: PackedMechanism | None = None,
) -> int:
    """Derive a key using C_DeriveKey. Returns new key handle."""
    mech = _resolve_mech(mechanism, mech_param)
    packed = pack_attrs(attrs)
    tmpl = template(*packed)
    handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        session,
        mech.byref(),
        base_key,
        *template_ptr_count(tmpl),
        byref(handle),
    )
    expect_rv(rv, CKR_OK)
    return handle.value


def generate_random(raw: RawPKCS11, session: int, length: int) -> bytes:
    """Generate random bytes using C_GenerateRandom."""
    buf = (ctypes.c_ubyte * length)()
    rv = raw.C_GenerateRandom(session, buf, length)
    expect_rv(rv, CKR_OK)
    return bytes(buf)


def copy_object(
    raw: RawPKCS11,
    session: int,
    handle: int,
    attrs: Mapping[Any, Any] | None = None,
) -> int:
    """Copy an object using C_CopyObject. Returns new handle."""
    packed = pack_attrs(attrs)
    tmpl = template(*packed) if packed else None
    new_handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_CopyObject(
        session,
        handle,
        *template_ptr_count(tmpl),
        byref(new_handle),
    )
    expect_rv(rv, CKR_OK)
    return new_handle.value


def set_attributes(
    raw: RawPKCS11,
    session: int,
    handle: int,
    attrs: dict[int, Any],
) -> None:
    """Set attribute values on an object using C_SetAttributeValue."""
    packed = pack_attrs(attrs)
    tmpl = template(*packed)
    rv = raw.C_SetAttributeValue(session, handle, tmpl.ptr, tmpl.count)
    expect_rv(rv, CKR_OK)


# --- Multipart operation helpers ---


def _multipart_output(
    raw: RawPKCS11,
    session: int,
    init_fn: str,
    update_fn: str,
    final_fn: str,
    init_args: tuple[Any, ...],
    chunks: list[bytes] | tuple[bytes, ...],
    *,
    cancel_flag: int,
) -> bytes:
    """Shared Init -> Update(chunks) -> Final for encrypt/decrypt.

    Only for operations where Update produces output (C_EncryptUpdate,
    C_DecryptUpdate). Sign/Digest Update calls do not produce output --
    use the manual Init+Update+_two_call_output(Final) pattern instead.

    ``cancel_flag`` is the operation-class flag (e.g. ``CKF_ENCRYPT``) used to
    cancel the dangling operation if an Update or Final call raises after the
    ``*Init`` succeeded -- mirroring the single-shot cancel-on-error fix
    (commit c509013) so a reused session is not left with an active op that
    would mis-attribute a spurious ``CKR_OPERATION_ACTIVE`` to a later call.
    """
    rv = getattr(raw, init_fn)(session, *init_args)
    expect_rv(rv, CKR_OK)
    try:
        parts: list[bytes] = []
        for chunk in chunks:
            in_buf = to_ubyte_buf(chunk)
            # Allocate a conservative output buffer upfront (chunk + 256 bytes for
            # block cipher expansion). Do NOT use the two-call size-probe pattern for
            # Update functions -- probing feeds the same chunk twice, corrupting cipher
            # state. The Final two-call pattern remains correct.
            max_out = len(chunk) + 256
            out_buf = (ctypes.c_ubyte * max_out)()
            out_len = CK_ULONG(max_out)
            rv = getattr(raw, update_fn)(
                session,
                in_buf,
                len(chunk),
                out_buf,
                byref(out_len),
            )
            expect_rv(rv, CKR_OK)
            if out_len.value > 0:
                parts.append(bytes(out_buf[: out_len.value]))
        parts.append(_two_call_output(raw, final_fn, session))
        return b"".join(parts)
    except BaseException:
        # An Update or Final call raised after *Init succeeded: cancel the
        # dangling operation so it does not leak into the next op on a reused
        # session, then re-raise the original error unchanged.
        _cancel_operation(raw, session, cancel_flag)
        raise


def encrypt_multipart(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    chunks: list[bytes] | tuple[bytes, ...],
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Encrypt data in multiple parts. Returns ciphertext."""
    mech = _resolve_mech(mechanism, mech_param)
    return _multipart_output(
        raw,
        session,
        "C_EncryptInit",
        "C_EncryptUpdate",
        "C_EncryptFinal",
        (mech.byref(), key),
        chunks,
        cancel_flag=int(CKF_ENCRYPT),
    )


def decrypt_multipart(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    chunks: list[bytes] | tuple[bytes, ...],
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Decrypt data in multiple parts. Returns plaintext."""
    mech = _resolve_mech(mechanism, mech_param)
    return _multipart_output(
        raw,
        session,
        "C_DecryptInit",
        "C_DecryptUpdate",
        "C_DecryptFinal",
        (mech.byref(), key),
        chunks,
        cancel_flag=int(CKF_DECRYPT),
    )


def sign_multipart(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    chunks: list[bytes] | tuple[bytes, ...],
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Sign data in multiple parts. Returns signature."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = _init_or_recover(raw, session, lambda: raw.C_SignInit(session, mech.byref(), key))
    expect_rv(rv, CKR_OK)
    for chunk in chunks:
        in_buf = to_ubyte_buf(chunk)
        rv = raw.C_SignUpdate(session, in_buf, len(chunk))
        expect_rv(rv, CKR_OK)
    return _two_call_output(raw, "C_SignFinal", session)


def verify_multipart(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    chunks: list[bytes] | tuple[bytes, ...],
    signature: bytes,
    *,
    mech_param: PackedMechanism | None = None,
) -> bool:
    """Verify a signature over multiple data parts.

    Returns True if valid, False if CKR_SIGNATURE_INVALID/CKR_SIGNATURE_LEN_RANGE.
    """
    mech = _resolve_mech(mechanism, mech_param)
    rv = _init_or_recover(raw, session, lambda: raw.C_VerifyInit(session, mech.byref(), key))
    expect_rv(rv, CKR_OK)
    for chunk in chunks:
        in_buf = to_ubyte_buf(chunk)
        rv = raw.C_VerifyUpdate(session, in_buf, len(chunk))
        expect_rv(rv, CKR_OK)
    sig_buf = to_ubyte_buf(signature)
    rv = raw.C_VerifyFinal(session, sig_buf, len(signature))
    if rv == CKR_OK:
        return True
    if rv in _VERIFY_FAIL_RVS:
        return False
    expect_rv(rv, CKR_OK)
    return False  # unreachable


def digest_multipart(
    raw: RawPKCS11,
    session: int,
    mechanism: CKM | int,
    chunks: list[bytes] | tuple[bytes, ...],
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Digest data in multiple parts. Returns digest."""
    mech = _resolve_mech(mechanism, mech_param)
    rv = _init_or_recover(raw, session, lambda: raw.C_DigestInit(session, mech.byref()))
    expect_rv(rv, CKR_OK)
    for chunk in chunks:
        in_buf = to_ubyte_buf(chunk)
        rv = raw.C_DigestUpdate(session, in_buf, len(chunk))
        expect_rv(rv, CKR_OK)
    return _two_call_output(raw, "C_DigestFinal", session)


# --- Operation state ---


def save_operation_state(raw: RawPKCS11, session: int) -> bytes:
    """C_GetOperationState -- two-call output pattern."""
    return _two_call_output(raw, "C_GetOperationState", session)


def restore_operation_state(
    raw: RawPKCS11,
    session: int,
    state: bytes,
    encrypt_key: int = 0,
    auth_key: int = 0,
) -> None:
    """C_SetOperationState -- restore previously saved operation state."""
    buf = to_ubyte_buf(state)
    rv = raw.C_SetOperationState(session, buf, len(state), encrypt_key, auth_key)
    expect_rv(rv, CKR_OK)


# --- Token/PIN management ---


def init_token(raw: RawPKCS11, slot_id: int, so_pin: bytes, label: str) -> None:
    """Initialize a token with C_InitToken. Label is padded to 32 bytes with spaces."""
    label_bytes = label.encode().ljust(32)[:32]
    label_buf = to_ubyte_buf(label_bytes)
    pin_buf = to_ubyte_buf(so_pin)
    rv = raw.C_InitToken(slot_id, pin_buf, len(so_pin), label_buf)
    expect_rv(rv, CKR_OK)


def init_pin(raw: RawPKCS11, session: int, pin: bytes) -> None:
    """Set user PIN with C_InitPIN."""
    pin_buf = to_ubyte_buf(pin)
    rv = raw.C_InitPIN(session, pin_buf, len(pin))
    expect_rv(rv, CKR_OK)


def set_pin(raw: RawPKCS11, session: int, old_pin: bytes, new_pin: bytes) -> None:
    """Change PIN with C_SetPIN."""
    old_buf = to_ubyte_buf(old_pin)
    new_buf = to_ubyte_buf(new_pin)
    rv = raw.C_SetPIN(session, old_buf, len(old_pin), new_buf, len(new_pin))
    expect_rv(rv, CKR_OK)


def seed_random(
    raw: RawPKCS11, session: int, seed: bytes, *, extra_ok: tuple[int, ...] = ()
) -> int:
    """Seed the RNG with C_SeedRandom.  Returns the raw CK_RV."""
    buf = to_ubyte_buf(seed)
    rv = raw.C_SeedRandom(session, buf, len(seed))
    expect_rv(rv, CKR_OK, *extra_ok)  # type: ignore[arg-type]
    return int(rv)


def get_mechanism_list(raw: RawPKCS11, slot_id: int) -> list[int]:
    """Get mechanisms supported by a slot. Returns list of CKM_* ints."""
    count = CK_ULONG(0)
    rv = raw.C_GetMechanismList(slot_id, None, byref(count))
    expect_rv(rv, CKR_OK)
    if count.value == 0:
        return []
    from .types_std import CK_MECHANISM_TYPE

    mechs = (CK_MECHANISM_TYPE * count.value)()
    rv = raw.C_GetMechanismList(slot_id, mechs, byref(count))
    expect_rv(rv, CKR_OK)
    return [mechs[i] for i in range(count.value)]


def get_session_info(raw: RawPKCS11, session: int) -> dict[str, int]:
    """C_GetSessionInfo -- returns session info as dict."""
    info = CK_SESSION_INFO()
    expect_rv(raw.C_GetSessionInfo(session, byref(info)), CKR_OK)
    return {
        "slot_id": info.slotID,
        "state": info.state,
        "flags": info.flags,
        "device_error": info.ulDeviceError,
    }


def get_mechanism_info(raw: RawPKCS11, slot_id: int, mechanism: CKM | int) -> dict[str, int]:
    """C_GetMechanismInfo -- returns mechanism info as dict."""
    info = CK_MECHANISM_INFO()
    expect_rv(raw.C_GetMechanismInfo(slot_id, mechanism, byref(info)), CKR_OK)
    return {
        "min_key_size": info.ulMinKeySize,
        "max_key_size": info.ulMaxKeySize,
        "flags": info.flags,
    }


def get_slot_info(raw: RawPKCS11, slot_id: int) -> dict[str, Any]:
    """C_GetSlotInfo -- returns slot info as dict."""
    info = CK_SLOT_INFO()
    expect_rv(raw.C_GetSlotInfo(slot_id, byref(info)), CKR_OK)
    return {
        "description": bytes(info.slotDescription).decode("utf-8", errors="replace").rstrip("\x00"),
        "manufacturer": bytes(info.manufacturerID).decode("utf-8", errors="replace").rstrip("\x00"),
        "flags": info.flags,
        "hardware_version": (info.hardwareVersion.major, info.hardwareVersion.minor),
        "firmware_version": (info.firmwareVersion.major, info.firmwareVersion.minor),
    }


# --- v3.0 Message-based crypto ---


def _message_crypto(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    data: bytes,
    init_fn: str,
    msg_fn: str,
    *,
    cancel_flag: int,
    aad: bytes | None = None,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Shared Init + two-call Message pattern for encrypt/decrypt.

    ``cancel_flag`` is the message operation-class flag (e.g.
    ``CKF_MESSAGE_ENCRYPT``) used to cancel the dangling operation if a
    ``C_*Message`` call raises after ``C_Message*Init`` succeeded -- mirroring
    the single-shot cancel-on-error fix (commit c509013) so a reused session is
    not left with an active op that would mis-attribute a spurious
    ``CKR_OPERATION_ACTIVE`` to a later call.
    """
    mech = _resolve_mech(mechanism, mech_param)
    rv = getattr(raw, init_fn)(session, mech.byref(), key)
    expect_rv(rv, CKR_OK)
    try:
        aad_buf = to_ubyte_buf(aad) if aad else None
        aad_len = len(aad) if aad else 0
        in_buf = to_ubyte_buf(data)

        out_len = CK_ULONG(0)
        fn = getattr(raw, msg_fn)
        rv = fn(
            session,
            None,
            0,
            aad_buf,
            aad_len,
            in_buf,
            len(data),
            None,
            byref(out_len),
        )
        expect_rv(rv, CKR_OK)
        out_buf = (ctypes.c_ubyte * out_len.value)()
        rv = fn(
            session,
            None,
            0,
            aad_buf,
            aad_len,
            in_buf,
            len(data),
            out_buf,
            byref(out_len),
        )
        expect_rv(rv, CKR_OK)
        return bytes(out_buf[: out_len.value])
    except BaseException:
        # A C_*Message call raised after C_Message*Init succeeded: cancel the
        # dangling operation so it does not leak into the next op on a reused
        # session, then re-raise the original error unchanged.
        _cancel_operation(raw, session, cancel_flag)
        raise


def message_encrypt(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    data: bytes,
    *,
    aad: bytes | None = None,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Single-message encrypt via C_MessageEncryptInit + C_EncryptMessage."""
    return _message_crypto(
        raw,
        session,
        key,
        mechanism,
        data,
        "C_MessageEncryptInit",
        "C_EncryptMessage",
        cancel_flag=int(CKF_MESSAGE_ENCRYPT),
        aad=aad,
        mech_param=mech_param,
    )


def message_decrypt(
    raw: RawPKCS11,
    session: int,
    key: int,
    mechanism: CKM | int,
    ciphertext: bytes,
    *,
    aad: bytes | None = None,
    mech_param: PackedMechanism | None = None,
) -> bytes:
    """Single-message decrypt via C_MessageDecryptInit + C_DecryptMessage."""
    return _message_crypto(
        raw,
        session,
        key,
        mechanism,
        ciphertext,
        "C_MessageDecryptInit",
        "C_DecryptMessage",
        cancel_flag=int(CKF_MESSAGE_DECRYPT),
        aad=aad,
        mech_param=mech_param,
    )


# --- v3.2 KEM operations ---


def encapsulate_key(
    raw: RawPKCS11,
    session: int,
    pub_key: int,
    mechanism: CKM | int,
    attrs: Mapping[Any, Any] | None = None,
    *,
    mech_param: PackedMechanism | None = None,
) -> tuple[int, bytes]:
    """C_EncapsulateKey -- returns (secret_key_handle, ciphertext).

    Uses the two-call pattern: first call with pCiphertext=NULL to get the required buffer
    size, second call with a properly allocated buffer.

    Some modules return CKR_BUFFER_TOO_SMALL (not CKR_OK) on the first NULL-buffer call,
    which is valid PKCS#11 behavior analogous to C_Encrypt.  Others may create the key on
    the first call and return CKR_OK -- we preserve that handle and reuse it on the second
    call.
    """
    mech = _resolve_mech(mechanism, mech_param)
    packed = pack_attrs(attrs)
    tmpl = template(*packed) if packed else None

    # First call: query ciphertext buffer size.
    # Accept both CKR_OK (some modules create the key already) and
    # CKR_BUFFER_TOO_SMALL (the standard two-pass indicator).
    ct_len = CK_ULONG(0)
    key_handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_EncapsulateKey(
        session,
        mech.byref(),
        pub_key,
        *template_ptr_count(tmpl),
        None,  # pCiphertext -- NULL signals size query
        byref(ct_len),
        byref(key_handle),  # some modules require non-NULL even for size query
    )
    if rv not in (CKR_OK, CKR_BUFFER_TOO_SMALL):
        expect_rv(rv, CKR_OK)  # raises with descriptive error

    # Second call: pass properly sized buffer.
    # If the first call already created the key (CKR_OK + non-zero handle),
    # reset the handle so the second call can overwrite it safely.
    first_call_handle = key_handle.value
    if rv == CKR_BUFFER_TOO_SMALL:
        key_handle = CK_OBJECT_HANDLE(0)  # key not yet created
    ct_buf = (ctypes.c_ubyte * ct_len.value)()
    rv = raw.C_EncapsulateKey(
        session,
        mech.byref(),
        pub_key,
        *template_ptr_count(tmpl),
        ct_buf,
        byref(ct_len),
        byref(key_handle),
    )
    expect_rv(rv, CKR_OK)
    # Use the handle returned by whichever call actually created the key.
    final_handle = key_handle.value if key_handle.value else first_call_handle
    return final_handle, bytes(ct_buf[: ct_len.value])


def decapsulate_key(
    raw: RawPKCS11,
    session: int,
    priv_key: int,
    mechanism: CKM | int,
    ciphertext: bytes,
    attrs: Mapping[Any, Any] | None = None,
    *,
    mech_param: PackedMechanism | None = None,
) -> int:
    """C_DecapsulateKey -- returns secret_key_handle."""
    mech = _resolve_mech(mechanism, mech_param)
    packed = pack_attrs(attrs)
    tmpl = template(*packed)
    ct_buf = to_ubyte_buf(ciphertext)
    key_handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_DecapsulateKey(
        session,
        mech.byref(),
        priv_key,
        *template_ptr_count(tmpl),
        ct_buf,
        len(ciphertext),
        byref(key_handle),
    )
    expect_rv(rv, CKR_OK)
    return key_handle.value


# --- v3.2 Authenticated wrapping ---


def wrap_key_authenticated(
    raw: RawPKCS11,
    session: int,
    wrapping_key: int,
    target_key: int,
    mechanism: CKM | int,
    *,
    aad: bytes = b"",
    mech_param: PackedMechanism | None = None,
    output_size_hint: int = 0,
) -> bytes:
    """C_WrapKeyAuthenticated — wrap ``target_key`` and return wrapped bytes.

    PKCS#11 v3.2 §5.13 signature:
        (hSession, pMechanism, hWrappingKey, hKey,
         pAssociatedData, ulAssociatedDataLen,
         pWrappedKey,      pulWrappedKeyLen)

    The C function does NOT return the authentication tag.  For AEAD modes
    (AES-GCM, AES-CCM) the tag is written into a buffer inside the mechanism
    parameter struct (e.g. ``CK_GCM_MESSAGE_PARAMS.pTag``).  Build the
    mech_param with a packer that registers a "tag" buffer (e.g.
    ``mech_gcm_message``) and retrieve it via
    ``mech_param.buffer_bytes("tag")`` after the call.  The classical
    ``mech_gcm`` packer has no pTag field and is NOT a valid mech_param for
    this function.

    ``output_size_hint`` skips the NULL-buffer size-query first call and
    issues a single call with a pre-allocated buffer of that size.  Needed
    for modules that either fail to report the required
    size on a NULL probe or consume operation state during it.
    """
    mech = _resolve_mech(mechanism, mech_param)
    aad_buf = to_ubyte_buf(aad) if aad else None
    return _two_call_output(
        raw,
        "C_WrapKeyAuthenticated",
        session,
        mech.byref(),
        wrapping_key,
        target_key,
        aad_buf,
        len(aad),
        output_size_hint=output_size_hint,
    )


def unwrap_key_authenticated(
    raw: RawPKCS11,
    session: int,
    unwrapping_key: int,
    wrapped_key: bytes,
    mechanism: CKM | int,
    attrs: Mapping[Any, Any] | None = None,
    *,
    aad: bytes = b"",
    mech_param: PackedMechanism | None = None,
) -> int:
    """C_UnwrapKeyAuthenticated — returns key handle.

    PKCS#11 v3.2 §5.13 signature:
        (hSession, pMechanism, hUnwrappingKey,
         pWrappedKey, ulWrappedKeyLen,
         pTemplate,   ulAttributeCount,
         pAssociatedData, ulAssociatedDataLen,
         phKey)

    The ``aad`` argument is the same AAD that was supplied to the corresponding
    ``wrap_key_authenticated`` call; AEAD modes cross-verify it.  The
    authentication tag is conveyed via the mechanism parameter struct
    (e.g. ``CK_GCM_MESSAGE_PARAMS.pTag``), not via this argument.
    """
    mech = _resolve_mech(mechanism, mech_param)
    packed = pack_attrs(attrs)
    tmpl = template(*packed) if packed else None
    wrapped_buf = to_ubyte_buf(wrapped_key)
    aad_buf = to_ubyte_buf(aad) if aad else None
    key_handle = CK_OBJECT_HANDLE(0)
    rv = raw.C_UnwrapKeyAuthenticated(
        session,
        mech.byref(),
        unwrapping_key,
        wrapped_buf,
        len(wrapped_key),
        *template_ptr_count(tmpl),
        aad_buf,
        len(aad),
        byref(key_handle),
    )
    expect_rv(rv, CKR_OK)
    return key_handle.value


__all__ = [
    "copy_object",
    "create_object",
    "decapsulate_key",
    "decrypt_multipart",
    "decrypt_single",
    "derive_key",
    "destroy_quietly",
    "digest_multipart",
    "digest_single",
    "encapsulate_key",
    "encrypt_multipart",
    "encrypt_single",
    "find_objects",
    "gen_aes_key",
    "gen_ec_keypair",
    "gen_keypair",
    "gen_rsa_keypair",
    "generate_random",
    "get_mechanism_list",
    "get_object_size",
    "import_dsa_public_key",
    "import_ec_private_key",
    "import_ec_public_key",
    "import_gost_private_key",
    "import_gost_public_key",
    "import_pqc_private_key",
    "import_pqc_public_key",
    "import_rsa_private_key",
    "import_rsa_public_key",
    "import_secret_key",
    "init_pin",
    "init_token",
    "message_decrypt",
    "message_encrypt",
    "pack_attrs",
    "quick_session",
    "read_attributes",
    "restore_operation_state",
    "save_operation_state",
    "seed_random",
    "set_attributes",
    "set_pin",
    "sign_multipart",
    "sign_recover_single",
    "sign_single",
    "to_ubyte_buf",
    "unwrap_key",
    "unwrap_key_authenticated",
    "verify_multipart",
    "verify_recover_single",
    "verify_single",
    "wrap_key",
    "wrap_key_authenticated",
]
