"""Shared fixtures and helpers for pkcs11-check PKCS#11 test cases.

Note: Static skips such as missing-module and destructive gating are handled in
plugin.py collection hooks. Dynamic version/mechanism skips are handled from the
collection-safe capability manifest before test setup.
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Mapping
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
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
from pkcs11_check.testcases._error_tuples import MECH_PARAM_UNSUPPORTED_ERRORS

AES_KEYGEN_RUNTIME_REJECT_RVS = (
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
)

KEYPAIR_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

EC_CURVE_UNSUPPORTED_RVS = (
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
)

# Phase 5 P1b: clean codes a module may return at a cipher/MAC *use* site when
# the mechanism is advertised but not operational for the given key/params.
# A first (produce) leg returning one of these -> xfail (advertised-but-not-
# operational); a dependent roundtrip second leg (decrypt of a just-produced
# output) is NOT routed here -- that stays a hard failure (self-contradiction).
CIPHER_OP_RUNTIME_REJECT_RVS = (
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


def needs_mechanism(name: str) -> Callable[[Any], Any]:
    """Decorator that skips the test if the mechanism is not supported."""

    def decorator(func: Any) -> Any:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            rs = kwargs.get("p11_raw_session")
            if rs is not None and not rs.has_mechanism(name):
                pytest.skip(f"{name} not supported")
            return func(*args, **kwargs)

        return wrapper

    return decorator


def skip_unless_mechanism(rs: Any, name: str) -> None:
    if not rs.has_mechanism(name):
        pytest.skip(f"{name} not supported")


def require_operational_aes_keygen(rs: Any) -> None:
    """Skip or xfail when AES_KEY_GEN cannot provide setup keys for a test."""
    if not rs.has_mechanism("AES_KEY_GEN"):
        pytest.skip("AES_KEY_GEN not supported by module")

    from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key

    key = 0
    try:
        key = gen_aes_key(rs.raw, rs.sh, 128)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            "AES_KEY_GEN advertised but key generation is not operational",
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


def gen_aes_key_or_xfail(
    rs: Any,
    bits: int = 128,
    attrs: Mapping[Any, Any] | None = None,
    *,
    purpose: str = "setup",
) -> int:
    """Generate an AES key, xfail-ing explicit setup rejection CKRs."""
    if not rs.has_mechanism("AES_KEY_GEN"):
        pytest.skip("AES_KEY_GEN not supported by module")

    from pkcs11_check.raw.recipes import gen_aes_key

    try:
        return gen_aes_key(rs.raw, rs.sh, bits, attrs=attrs)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            f"AES_KEY_GEN advertised but AES-{bits} key generation for {purpose} "
            "is not operational",
        )
    raise


def unwrap_key_for_mechanism_roundtrip(
    rs: Any,
    p11_config: Any,
    *,
    unwrapping_key: int,
    wrapped_key: bytes,
    mechanism: Any,
    attrs: Mapping[Any, Any],
    mech_param: Any | None = None,
    value_len: int | None = None,
    purpose: str = "mechanism unwrap roundtrip",
) -> int:
    """Unwrap for mechanism-level crypto checks, negotiating the accepted template.

    The canonical template (variant 0) carries both CKA_CLASS and CKA_KEY_TYPE.
    CKA_KEY_TYPE is spec-mandatory on C_UnwrapKey and is never dropped; only
    CKA_CLASS may be relaxed for modules that reject it in an unwrap template, so a
    second variant omitting CKA_CLASS is tried only if the module shape-rejects the
    canonical one. Mechanism-level tests care about the cryptographic roundtrip;
    stricter attribute-template behavior belongs in dedicated attribute/security
    tests. No provider identity is consulted.
    """
    from pkcs11_check.raw.recipes import unwrap_key
    from pkcs11_check.testcases._negotiation import negotiate_request, value_len_variant_allowed

    base = dict(attrs)
    variants = [base]
    relaxed = {k: v for k, v in base.items() if k != CKA_CLASS}  # keep CKA_KEY_TYPE
    if relaxed != base:
        variants.append(relaxed)
    if (
        value_len is not None
        and CKA_KEY_TYPE in base
        and value_len_variant_allowed(base[CKA_KEY_TYPE], int(mechanism))
    ):
        variants = [{**v, CKA_VALUE_LEN: value_len} for v in variants] + variants

    def attempt(delta: Mapping[Any, Any]) -> int:
        return unwrap_key(
            rs.raw,
            rs.sh,
            unwrapping_key,
            wrapped_key,
            mechanism,
            attrs=delta,
            mech_param=mech_param,
        )

    result, _idx = negotiate_request(attempt, variants, label=purpose)
    return result


def gen_rsa_keypair_or_xfail(
    rs: Any,
    bits: int = 2048,
    public_attrs: Mapping[Any, Any] | None = None,
    private_attrs: Mapping[Any, Any] | None = None,
) -> tuple[int, int]:
    """Generate an RSA keypair, xfail-ing explicit setup rejection CKRs."""
    if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
        pytest.skip("RSA_PKCS_KEY_PAIR_GEN not supported by module")

    from pkcs11_check.raw.recipes import gen_rsa_keypair

    try:
        return gen_rsa_keypair(
            rs.raw,
            rs.sh,
            bits,
            public_attrs=public_attrs,
            private_attrs=private_attrs,
        )
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            KEYPAIR_RUNTIME_REJECT_RVS,
            "RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational",
        )
    raise


def gen_ec_keypair_or_xfail(
    rs: Any,
    curve_oid: bytes,
    public_attrs: Mapping[Any, Any] | None = None,
    private_attrs: Mapping[Any, Any] | None = None,
) -> tuple[int, int]:
    """Generate an EC keypair, xfail-ing explicit setup rejection CKRs."""
    if not (rs.has_mechanism("EC_KEY_PAIR_GEN") or rs.has_mechanism("ECDSA_KEY_PAIR_GEN")):
        pytest.skip("EC_KEY_PAIR_GEN not supported by module")

    from pkcs11_check.raw.recipes import gen_ec_keypair

    try:
        return gen_ec_keypair(
            rs.raw,
            rs.sh,
            curve_oid,
            public_attrs=public_attrs,
            private_attrs=private_attrs,
        )
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            KEYPAIR_RUNTIME_REJECT_RVS,
            "EC_KEY_PAIR_GEN advertised but keypair generation is not operational",
        )
    raise


def gen_edwards_keypair_or_xfail(
    rs: Any,
    curve_oid: bytes,
    public_attrs: Mapping[Any, Any] | None = None,
    private_attrs: Mapping[Any, Any] | None = None,
) -> tuple[int, int]:
    """Generate an Edwards-curve keypair, xfail-ing explicit setup rejects."""
    if not rs.has_mechanism("EC_EDWARDS_KEY_PAIR_GEN"):
        pytest.skip("EC_EDWARDS_KEY_PAIR_GEN not supported by module")

    from pkcs11_check.raw.pack import attr_bytes
    from pkcs11_check.raw.recipes import gen_keypair

    pub_defaults: dict[Any, Any] = {CKA_VERIFY: True}
    priv_defaults: dict[Any, Any] = {CKA_SIGN: True}
    if public_attrs:
        pub_defaults.update(public_attrs)
    if private_attrs:
        priv_defaults.update(private_attrs)

    try:
        return gen_keypair(
            rs.raw,
            rs.sh,
            int(CKM_EC_EDWARDS_KEY_PAIR_GEN),
            pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
            priv_base=[],
            public_attrs=pub_defaults,
            private_attrs=priv_defaults,
            pub_skip={CKA_EC_PARAMS},
        )
    except AssertionError as exc:
        if is_known_error(exc, EC_CURVE_UNSUPPORTED_RVS):
            rv = getattr(exc, "rv", None)
            detail = ckr_name(rv) if rv is not None else str(exc)
            pytest.skip(f"Edwards curve not supported by module: {detail}")
        xfail_if_known_ckr(
            exc,
            KEYPAIR_RUNTIME_REJECT_RVS,
            "EC_EDWARDS_KEY_PAIR_GEN advertised but keypair generation is not operational",
        )
    raise


def get_pin_bytes(p11_config: Any) -> bytes | None:
    """Extract PIN as bytes from config, or None if no PIN configured."""
    if p11_config.pin is None:
        return None
    pin = p11_config.pin
    pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)
    return pin_str.encode("utf-8")


def extract_ec_point(ec_point_der: Any) -> Any:
    """Extract raw uncompressed EC point from DER OCTET STRING wrapper.

    PKCS#11 EC_POINT attribute is DER-encoded: 0x04 <length> <point_bytes>.
    Returns the raw point bytes (starting with 0x04 uncompressed prefix).
    """
    from pkcs11_check.raw.der import decode_ec_point

    data = bytes(ec_point_der)
    if not data or data[0] != 0x04:
        return ec_point_der
    return decode_ec_point(data)


def skip_if_token_write_protected(raw: Any, slot_id: int) -> None:
    """Skip test if the token is write-protected (cannot create token objects)."""
    from ctypes import byref

    from pkcs11_check.raw.types_std import CK_TOKEN_INFO, CKF_WRITE_PROTECTED, CKR_OK

    info = CK_TOKEN_INFO()
    rv = raw.C_GetTokenInfo(slot_id, byref(info))
    if rv != CKR_OK:
        return  # Can't determine, let the test try
    if info.flags & CKF_WRITE_PROTECTED:
        pytest.skip("Token is write-protected -- cannot create token objects")


def _actual_rv_portion(msg: str) -> str:
    """Return only the ACTUAL-rv portion of an ``expect_rv`` message.

    ``expect_rv`` raises ``CkrAssertionError`` with a message shaped like
    ``"Unexpected CK_RV <ACTUAL>; expected one of: <EXPECTED...>"``.  The tail
    after ``"; expected one of:"`` lists the EXPECTED CKR names — substring
    matching against it would wrongly classify a genuine failure as "known"
    (the prefix/substring hazard documented on ``CkrAssertionError``).  This
    drops that tail so only the actual-return portion is matched.
    """
    head, sep, _tail = msg.partition("; expected one of:")
    return head if sep else msg


def is_known_error(
    exc: BaseException,
    error_rvs: set[Any] | frozenset[Any] | tuple[Any, ...],
) -> bool:
    """Return True if ``exc`` corresponds to one of ``error_rvs``.

    Prefers exact integer equality via ``CkrAssertionError.rv`` (set by
    ``expect_rv``).  When ``.rv`` is absent, falls back to substring matching
    against ONLY the actual-return portion of the message (the text before
    ``"; expected one of:"``), so an EXPECTED CKR name listed in the message
    cannot be mistaken for the actual return — which would otherwise mis-route
    a real failure to skip/xfail.
    """
    rv = getattr(exc, "rv", None)
    if rv is not None:
        return rv in error_rvs
    msg = _actual_rv_portion(str(exc))
    return any(ckr_name(r) in msg for r in error_rvs)


def _matched_ckr_name(exc: BaseException, known_ckrs: Any) -> str | None:
    """Return the CKR name that matched ``exc``, or None if no match.

    Mirrors :func:`is_known_error`: exact ``.rv`` when present, otherwise a
    substring match constrained to the actual-return portion of the message so
    an EXPECTED name in the message cannot produce a false match.
    """
    rv = getattr(exc, "rv", None)
    if rv is not None:
        return ckr_name(rv) if rv in known_ckrs else None
    msg = _actual_rv_portion(str(exc))
    for ckr in known_ckrs:
        if ckr_name(ckr) in msg:
            return ckr_name(ckr)
    return None


def xfail_if_known_ckr(
    exc: Exception,
    known_ckrs: set[Any] | tuple[Any, ...] | frozenset[Any],
    msg: str,
) -> None:
    """xfail if ``exc`` corresponds to a known CKR, otherwise re-raise.

    Prefers exact ``CkrAssertionError.rv`` matching (via ``is_known_error``);
    falls back to substring matching for assertions raised by other call paths.

    Use this instead of ``except (AssertionError, Exception): pytest.xfail(...)``
    so that only specific CKR failures become expected failures, while
    Python coding bugs and wrong-output assertions propagate as real failures.

    Args:
        exc: The caught exception.
        known_ckrs: Iterable of CKR integer values to match against.
        msg: Message for pytest.xfail if a known CKR is matched.
    """
    matched = _matched_ckr_name(exc, known_ckrs)
    if matched is not None:
        pytest.xfail(f"{msg}: {matched}")
    raise  # Not a known CKR -- propagate as real failure


def classify_negative_rv(
    rv: int,
    expected_rvs: tuple[Any, ...] | set[Any] | frozenset[Any],
    *,
    label: str,
    allow_ok: bool = False,
) -> None:
    """Raw-rv negative classifier (provider-general 3-way).

    For negative ops at sites NOT in the ckr/ table that carry the raw return
    value directly:

    - ``CKR_OK`` -> ``fail`` (the module accepted an invalid/forbidden op),
      unless ``allow_ok`` is set for the rare case where success is tolerable.
    - ``rv in expected_rvs`` -> ``pass`` (spec-correct rejection).
    - any other clean reject code -> ``xfail`` (honest non-spec deviation,
      noted for later investigation).

    Per the classification model: only a crypto-correctness break or
    self-contradiction warrants ``fail``; a different honest reject code is
    ``xfail``. This helper decides direction by the model, never to silence a
    finding.
    """
    if rv == CKR_OK:
        if allow_ok:
            return
        pytest.fail(f"{label}: accepted invalid (CKR_OK) -- must reject")
    if rv in expected_rvs:
        return
    pytest.xfail(
        f"{label}: rejected with {ckr_name(rv)}, expected {[ckr_name(c) for c in expected_rvs]}"
    )


def reject_or_classify(
    exc: BaseException | None,
    expected_rvs: tuple[Any, ...] | set[Any] | frozenset[Any],
    *,
    label: str,
) -> None:
    """Recipe-site negative classifier (exception-shaped, provider-general 3-way).

    For recipe call sites that *raise* a ``CkrAssertionError`` on reject and
    *return* on success (so there is no raw ``rv`` to inspect):

    - ``exc is None`` means the operation SUCCEEDED (accepted the invalid /
      forbidden input) -> ``fail``.
    - a caught error whose ``rv`` is in ``expected_rvs`` -> ``pass`` (spec-correct
      rejection).
    - any other clean reject code -> ``xfail`` (honest non-spec deviation).

    Mirrors ``classify_negative_rv`` for the exception path, reusing
    ``is_known_error`` for the match.
    """
    if exc is None:
        pytest.fail(f"{label}: accepted invalid (CKR_OK) -- must reject")
    if is_known_error(exc, expected_rvs):
        return
    rv = getattr(exc, "rv", None)
    name = ckr_name(rv) if rv is not None else str(exc)
    pytest.xfail(f"{label}: rejected with {name}, expected {[ckr_name(c) for c in expected_rvs]}")


def classify_policy_enforcement(*, claimed: bool, violated: bool, label: str) -> None:
    """Type-B attribute/permission self-contradiction classifier.

    Args:
        claimed: the module reported the protective attribute back (e.g. a
            ``CKA_SENSITIVE=True`` key reads back ``CKA_SENSITIVE=True``).
        violated: the protection was breached (e.g. the sensitive value was
            readable, or an escalation was reflected).

    - not ``claimed`` -> ``xfail`` (honest non-support of an optional protection;
      provider-dependent, noted for later).
    - ``claimed`` and ``violated`` -> ``fail`` (the module claimed the protection
      then violated it -- a self-contradiction, broken for any provider).
    - ``claimed`` and not ``violated`` -> ``pass``.
    """
    if not claimed:
        pytest.xfail(f"{label}: module does not claim the protection (honest non-support)")
    if violated:
        pytest.fail(f"{label}: claimed the protection then violated it (self-contradiction)")


def classify_lifecycle_effect(*, claimed_success: bool, effect_observed: bool, label: str) -> None:
    """Type-C lifecycle/state self-contradiction classifier.

    Args:
        claimed_success: the prior operation returned ``CKR_OK`` (e.g. a
            ``C_DestroyObject`` claimed the object destroyed, or a read-only
            ``C_SetAttributeValue`` claimed the write succeeded).
        effect_observed: the contradicting effect was seen (e.g. the destroyed
            object's tagged content survived, or the read-only value actually
            changed).

    - not ``claimed_success`` -> ``xfail`` (prior op did not claim success; the
      module honestly declined, so no contradiction).
    - ``claimed_success`` and ``effect_observed`` -> ``fail`` (success claimed then
      contradicted -- a self-contradiction).
    - ``claimed_success`` and not ``effect_observed`` -> ``pass``.
    """
    if not claimed_success:
        pytest.xfail(f"{label}: prior operation did not claim success")
    if effect_observed:
        pytest.fail(f"{label}: success claimed then contradicted (self-contradiction)")


def classify_discrimination(*, valid_accepted: bool, invalid_outcome: Any, label: str) -> None:
    """Outcome-based discrimination classifier (Pillar 2, guardrails D1-D5).

    For integrity/forgery/type-confusion negative tests where the spec mandates no
    specific failure code: the verdict is the security EFFECT, not the CKR named.

    Args:
        valid_accepted: the un-tampered operation succeeded AND its result was verified
            (a real, material-checked positive leg). Advertised-but-not-operational
            positive legs are routed to xfail by the caller BEFORE this call (D5); a
            ``False`` here means CKR_OK-but-wrong/unverifiable output -- a real break.
        invalid_outcome: the invalid leg's outcome -- either the caught exception, or the
            produced object (handle/bytes) when the module ACCEPTED the bad input.
            A ``CkrAssertionError`` (clean ``.rv``) -> rejected (any code, D3). Any other
            exception (no ``.rv``) -> re-raised (D2: a harness/ctypes bug, not detection).
            A produced object (not an exception) -> accepted -> break.
    """
    if isinstance(invalid_outcome, CkrAssertionError):
        invalid_rejected = True
    elif isinstance(invalid_outcome, BaseException):
        raise invalid_outcome
    else:
        invalid_rejected = False

    if not valid_accepted:
        pytest.fail(
            f"{label}: the valid/un-tampered operation did not verify -- cannot "
            "distinguish 'detected tampering' from 'cannot do the operation'"
        )
    if not invalid_rejected:
        pytest.fail(f"{label}: accepted the tampered/forged/confused input (security break)")


def destroy_returned_handles(rs: Any, *handles: int) -> None:
    """Destroy a sequence of object handles, silently skipping zeros and errors."""
    from pkcs11_check.raw.recipes import destroy_quietly

    for handle in handles:
        if handle:
            destroy_quietly(rs.raw, rs.sh, int(handle))


def skip_if_mech_param_unsupported(exc: BaseException, context: str) -> None:
    """pytest.skip if ``exc`` carries one of MECH_PARAM_UNSUPPORTED_ERRORS, else re-raise.

    Provider-generated IV / nonce / wrap-output parameter conventions are
    allowed to be rejected even when the base mechanism is advertised; this
    helper turns those rejections into a clean skip while letting other
    failures propagate as real findings.

    Prefers exact ``CkrAssertionError.rv`` matching when present (via
    ``is_known_error``).
    """
    if is_known_error(exc, MECH_PARAM_UNSUPPORTED_ERRORS):
        pytest.skip(f"{context} not supported: {exc}")
    raise exc
