"""Shared fixtures and helpers for pkcs11-check PKCS#11 test cases.

Note: Static skips such as missing-module and destructive gating are handled in
plugin.py collection hooks. Dynamic version/mechanism skips are handled from the
collection-safe capability manifest before test setup.
"""

from __future__ import annotations

import functools
import itertools
from collections.abc import Callable, Mapping
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError, ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKK_EC,
    CKK_RSA,
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DATA_LEN_RANGE,
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
    # Clean length-range reject of spec-valid input (opencryptoki CTR with a
    # 32B/17B payload, triage H5): advertised-but-not-operational deviation.
    CKR_DATA_LEN_RANGE,
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

# Clean codes a module may return at an HMAC *sign/verify* use site when the
# HMAC mechanism is advertised but the operation is not operational (tpm2
# advertises CKM_SHA*_HMAC but C_Sign returns CKR_GENERAL_ERROR). A produce
# (sign) leg returning one of these -> xfail (advertised-but-not-operational);
# the cross-verify comparison against a reference MAC stays a hard failure.
# Mirrors the established local tuple in test_generic_secret.py (promoted here
# so the sign-op guard is shared, not duplicated per file).
HMAC_OP_RUNTIME_REJECT_RVS = (
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
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
    sh: int | None = None,
) -> int:
    """Generate an AES key, xfail-ing explicit setup rejection CKRs.

    ``sh`` overrides the session the key is generated in (defaults to ``rs.sh``);
    a few setup sites generate the key in a freshly opened session on the same
    token, where the advertised-but-not-operational reject is identical.
    """
    if not rs.has_mechanism("AES_KEY_GEN"):
        pytest.skip("AES_KEY_GEN not supported by module")

    from pkcs11_check.raw.recipes import gen_aes_key

    session = rs.sh if sh is None else sh
    try:
        return gen_aes_key(rs.raw, session, bits, attrs=attrs)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            f"AES_KEY_GEN advertised but AES-{bits} key generation for {purpose} "
            "is not operational",
        )
    raise


def hmac_sign_or_xfail(
    rs: Any,
    key_handle: int,
    mechanism: int,
    data: bytes,
    *,
    label: str,
) -> bytes:
    """C_Sign an HMAC, skipping when not advertised, xfail-ing op rejects.

    label must be the mechanism name (e.g. "SHA256_HMAC") — it is used both
    for the has_mechanism gate and for the xfail/skip messages.

    tpm2-pkcs11 advertises CKM_SHA*_HMAC yet C_Sign returns CKR_GENERAL_ERROR.
    * mechanism NOT advertised → pytest.skip (capability genuinely absent)
    * advertised + HMAC_OP_RUNTIME_REJECT_RVS → xfail (advertised-but-not-operational)
    * any other failure (incl. wrong-MAC comparison by the caller) → hard fail
    Provider-general: no provider identity consulted.
    """
    if not rs.has_mechanism(label):
        pytest.skip(f"{label} not advertised")

    from pkcs11_check.raw.recipes import sign_single

    try:
        return sign_single(rs.raw, rs.sh, key_handle, mechanism, data)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            HMAC_OP_RUNTIME_REJECT_RVS,
            f"{label} advertised but sign is not operational",
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

    The canonical template (variant 0) carries CKA_CLASS, CKA_KEY_TYPE and whatever
    policy attributes the caller supplied. Both CKA_CLASS and CKA_KEY_TYPE are kept in
    every variant (opencryptoki requires CKA_CLASS on C_UnwrapKey and CKA_KEY_TYPE is
    spec-mandatory). What modules disagree on is the *policy* attributes: opencryptoki
    rejects CKA_EXTRACTABLE/CKA_SENSITIVE in an unwrap template (CKR_ATTRIBUTE_READ_ONLY)
    whereas lenient modules (softhsm2) need CKA_EXTRACTABLE for the unwrapped value to be
    readable. So on a clean template-shape reject, a second variant drops those policy
    attributes. Provider-general: a module that accepts the policy attrs succeeds on
    variant 0 and never retries; no provider identity is consulted. (Probed 2026-06-09.)
    """
    from pkcs11_check.raw.recipes import unwrap_key
    from pkcs11_check.testcases._negotiation import negotiate_request, value_len_variant_allowed

    base = dict(attrs)
    variants = [base]
    relaxed = {k: v for k, v in base.items() if k not in (CKA_EXTRACTABLE, CKA_SENSITIVE)}
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


# C_CreateObject storage-shape rejects: the template rejects plus the clean codes
# storage-oriented modules use for storage-model constraints (probed corePKCS11
# 2026-06-09: missing CKA_LABEL -> CKR_ARGUMENTS_BAD, CKA_TOKEN=False ->
# CKR_ATTRIBUTE_VALUE_INVALID, CKA_SENSITIVE unknown to the HMAC key parser ->
# CKR_ATTRIBUTE_TYPE_INVALID). Import-site only: at other sites these codes stay
# real findings (see negotiate_request).
IMPORT_STORAGE_SHAPE_REJECTS: tuple[int, ...] = (
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
)

# Benign policy attributes a storage variant may DROP on a clean shape reject
# (mirrors unwrap_key_for_mechanism_roundtrip): their absence does not change
# what the KAT asserts. Crypto-visible attributes are never touched.
_IMPORT_DROPPABLE_POLICY_ATTRS: tuple[Any, ...] = (CKA_SENSITIVE, CKA_EXTRACTABLE)

_import_label_counter = itertools.count(1)

# Winning storage-variant cache, keyed by template shape (class, key type,
# attr-type set). One negotiation walk per shape per process; subsequent
# imports go straight to the learned variant instead of re-rejecting the
# canonical thousands of times. A cached winner that stops working falls back
# to the full canonical-first sequence and re-learns.
_IMPORT_SHAPE_WINNERS: dict[tuple[Any, ...], int] = {}


def reset_import_negotiation_cache() -> None:
    """Test hook: forget learned storage-variant winners."""
    _IMPORT_SHAPE_WINNERS.clear()


def _next_import_label() -> bytes:
    """Unique short label for label-keyed object stores (max 32 bytes)."""
    return f"p11chk-import-{next(_import_label_counter)}".encode()


def _storage_variants(base: dict[Any, Any]) -> list[dict[Any, Any]]:
    """Spec-equivalent storage variants, canonical-minimal first (G1)."""
    variants: list[dict[Any, Any]] = [base]
    labeled = base if CKA_LABEL in base else {**base, CKA_LABEL: _next_import_label()}
    if labeled is not base:
        variants.append(labeled)
    tokened = labeled if base.get(CKA_TOKEN, False) else {**labeled, CKA_TOKEN: True}
    if tokened is not labeled:
        variants.append(tokened)
    dropped = {k: v for k, v in tokened.items() if k not in _IMPORT_DROPPABLE_POLICY_ATTRS}
    if dropped != tokened:
        variants.append(dropped)
    return variants


def _import_shape_key(base: Mapping[Any, Any]) -> tuple[Any, ...]:
    return (
        base.get(CKA_CLASS),
        base.get(CKA_KEY_TYPE),
        tuple(sorted(int(k) for k in base)),
    )


def create_object_negotiated(
    rs: Any,
    attrs: Mapping[Any, Any],
    *,
    purpose: str = "key import",
) -> int:
    """Create an object, negotiating storage-shape requirements (label / token).

    Variant 0 is the caller's spec-minimal template. Storage-oriented modules reject
    it cleanly: corePKCS11 requires CKA_LABEL on every key object (CKR_ARGUMENTS_BAD
    when absent), supports only token objects (CKR_ATTRIBUTE_VALUE_INVALID for
    CKA_TOKEN=False) and rejects policy attributes its parsers do not know
    (CKR_ATTRIBUTE_TYPE_INVALID for CKA_SENSITIVE). Retry variants add a unique
    CKA_LABEL, then CKA_TOKEN=True, then drop the benign policy attrs -- storage
    shape only; crypto-visible attributes are never changed and no provider
    identity is consulted. The winning variant is cached per template shape per
    process (see _IMPORT_SHAPE_WINNERS); callers destroy the object in their
    cleanup path regardless of which variant won.
    """
    from pkcs11_check.raw.recipes import create_object
    from pkcs11_check.raw.rv import CkrAssertionError as _CkrError
    from pkcs11_check.testcases._negotiation import negotiate_request

    base = dict(attrs)
    variants = _storage_variants(base)
    shape_key = _import_shape_key(base)

    def attempt(delta: Mapping[Any, Any]) -> int:
        return create_object(rs.raw, rs.sh, dict(delta))

    cached = _IMPORT_SHAPE_WINNERS.get(shape_key)
    if cached is not None and 0 < cached < len(variants):
        try:
            return attempt(variants[cached])
        except _CkrError as exc:
            if exc.rv not in IMPORT_STORAGE_SHAPE_REJECTS:
                raise
            # The learned winner stopped working: re-learn from canonical.

    result, idx = negotiate_request(
        attempt, variants, label=purpose, shape_rejects=IMPORT_STORAGE_SHAPE_REJECTS
    )
    _IMPORT_SHAPE_WINNERS[shape_key] = idx
    return result


def import_rsa_public_key_negotiated(
    rs: Any,
    *,
    n: bytes,
    e: bytes,
    attrs: Mapping[Any, Any] | None = None,
    purpose: str = "RSA public key import",
) -> int:
    """Import an RSA public key, negotiating storage-shape template requirements.

    Same canonical template as ``raw.recipes.import_rsa_public_key``; clean
    storage-shape rejects retry via ``create_object_negotiated`` variants.
    """
    base: dict[Any, Any] = {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_KEY_TYPE: CKK_RSA,
        CKA_TOKEN: False,
        CKA_MODULUS: n,
        CKA_PUBLIC_EXPONENT: e,
    }
    if attrs:
        base.update(attrs)
    return create_object_negotiated(rs, base, purpose=purpose)


def import_rsa_private_key_negotiated(
    rs: Any,
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
    purpose: str = "RSA private key import",
) -> int:
    """Import an RSA private key from CRT components, negotiating storage shape.

    Same canonical template as ``raw.recipes.import_rsa_private_key``; clean
    storage-shape rejects retry via ``create_object_negotiated`` variants.
    """
    from pkcs11_check.raw.types_std import (
        CKA_COEFFICIENT,
        CKA_EXPONENT_1,
        CKA_EXPONENT_2,
        CKA_PRIME_1,
        CKA_PRIME_2,
        CKA_PRIVATE_EXPONENT,
        CKO_PRIVATE_KEY,
    )

    base: dict[Any, Any] = {
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
    return create_object_negotiated(rs, base, purpose=purpose)


def ec_public_key_binding_defect(rs: Any, handle: int, requested_params: bytes) -> str | None:
    """Effect-check a just-created EC public key: is it bound to the requested curve?

    Some modules accept a foreign-curve import with CKR_OK but bind the key to
    their only supported group (corePKCS11 binds everything to P-256; the object
    is then incoherent -- attribute readback returns CKR_OBJECT_HANDLE_INVALID --
    or reports different CKA_EC_PARAMS). Verify the effect, not the return code:
    a CKR_OK whose object does not round-trip the requested curve is a defect.
    Returns None when coherent, else a reason string. KAT suites skip vectors of
    a defective curve (capability genuinely absent); the self-contradiction
    itself is surfaced by the dedicated object-coherence conformance test.
    """
    from pkcs11_check.raw.recipes import read_attributes

    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [int(CKA_EC_PARAMS)])
    except CkrAssertionError as exc:
        return f"object incoherent after CKR_OK create: {exc}"
    got = attrs.get(int(CKA_EC_PARAMS))
    if got is None:
        return "CKA_EC_PARAMS unavailable after CKR_OK create"
    if bytes(got) != bytes(requested_params):
        return (
            f"module silently rebound curve: requested CKA_EC_PARAMS "
            f"{bytes(requested_params).hex()}, object reports {bytes(got).hex()}"
        )
    return None


def import_secret_key_negotiated(
    rs: Any,
    key_type: int,
    value: bytes,
    *,
    attrs: Mapping[Any, Any] | None = None,
    purpose: str = "secret key import",
) -> int:
    """Import a secret key by value, negotiating storage-shape requirements.

    Same canonical template as ``raw.recipes.import_secret_key``; on a clean
    storage-shape reject it retries via ``create_object_negotiated`` variants
    (unique CKA_LABEL, then CKA_TOKEN=TRUE -- corePKCS11-style label-keyed
    token-only stores).
    """
    base: dict[Any, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_VALUE: value,
    }
    if attrs:
        base.update(attrs)
    return create_object_negotiated(rs, base, purpose=purpose)


def import_ec_public_key_negotiated(
    rs: Any,
    *,
    ec_params: bytes,
    ec_point: bytes,
    key_type: int = int(CKK_EC),
    attrs: Mapping[Any, Any] | None = None,
    purpose: str = "EC public key import",
) -> int:
    """Import an EC public key, negotiating storage-shape template requirements.

    Same canonical template as ``raw.recipes.import_ec_public_key``; on a clean
    storage-shape reject it retries via ``create_object_negotiated`` variants.
    """
    base: dict[Any, Any] = {
        CKA_CLASS: CKO_PUBLIC_KEY,
        CKA_KEY_TYPE: key_type,
        CKA_TOKEN: False,
        CKA_EC_PARAMS: ec_params,
        CKA_EC_POINT: ec_point,
    }
    if attrs:
        base.update(attrs)
    return create_object_negotiated(rs, base, purpose=purpose)


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
        from pkcs11_check import classification as C

        rv = getattr(exc, "rv", None)
        C.classify(
            "not_operational",
            label=msg,
            actual=rv if rv is not None else matched,
            summary=f"{msg}: {matched}",
        )
        return  # classify() raises XFailed; defensive
    raise  # Not a known CKR -- propagate as real failure


def classify_negative_rv(
    rv: int,
    expected_rvs: tuple[Any, ...] | set[Any] | frozenset[Any],
    *,
    label: str,
    allow_ok: bool = False,
    kind: str | None = None,
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
    from pkcs11_check import classification as C

    if rv == CKR_OK:
        if allow_ok:
            return
        C.classify(
            "accepted_invalid",
            kind=kind,
            label=label,
            actual=rv,
            expected=tuple(expected_rvs),
            summary=f"{label}: accepted invalid (CKR_OK) -- must reject",
        )
        return
    if rv in expected_rvs:
        return
    _classify_unexpected_clean_rv(rv, expected_rvs, label=label, kind=kind)


def _classify_unexpected_clean_rv(
    rv: int,
    expected_rvs: tuple[Any, ...] | set[Any] | frozenset[Any],
    *,
    label: str,
    kind: str | None = None,
) -> None:
    from pkcs11_check import classification as C

    expected_names = [ckr_name(c) for c in expected_rvs]
    if is_vendor_defined_ckr(rv):
        C.classify(
            "nonspec_reject",
            kind=kind,
            label=label,
            actual=rv,
            expected=tuple(expected_rvs),
            summary=f"{label}: rejected with vendor-defined CK_RV {ckr_name(rv)}, "
            f"expected {expected_names}",
        )
        return
    if not is_standard_ckr(rv):
        # An undefined CK_RV is a return-value-contract violation: the module returned
        # a value outside the defined PKCS#11 CK_RV enum (metadata-class
        # self-inconsistency).  Force kind="metadata" so the verdict is fail/HIGH
        # (not escalated to CRITICAL by a crypto kind), and never emit the reserved
        # backlog-gate marker (that reason belongs only to the plugin runtime gate).
        C.classify(
            "self_contradiction",
            kind="metadata",
            label=label,
            actual=rv,
            expected=tuple(expected_rvs),
            summary=f"{label}: rejected with undefined CK_RV {ckr_name(rv)}, "
            f"expected {expected_names}",
        )
        return
    C.classify(
        "nonspec_reject",
        kind=kind,
        label=label,
        actual=rv,
        expected=tuple(expected_rvs),
    )


def _xfail_or_fail_unexpected_clean_rv(
    rv: int,
    expected_rvs: tuple[Any, ...] | set[Any] | frozenset[Any],
    *,
    label: str,
) -> None:
    _classify_unexpected_clean_rv(rv, expected_rvs, label=label)


def reject_or_classify(
    exc: BaseException | None,
    expected_rvs: tuple[Any, ...] | set[Any] | frozenset[Any],
    *,
    label: str,
    kind: str | None = None,
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
    from pkcs11_check import classification as C

    if exc is None:
        C.classify(
            "accepted_invalid",
            kind=kind,
            label=label,
            actual="CKR_OK",
            expected=tuple(expected_rvs),
            summary=f"{label}: accepted invalid (CKR_OK) -- must reject",
        )
        return
    if is_known_error(exc, expected_rvs):
        return
    rv = getattr(exc, "rv", None)
    if rv is not None:
        _classify_unexpected_clean_rv(rv, expected_rvs, label=label, kind=kind)
        return
    C.classify(
        "nonspec_reject",
        kind=kind,
        label=label,
        summary=f"{label}: rejected with {type(exc).__name__}, expected {list(expected_rvs)}",
    )


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
    from pkcs11_check import classification as C

    if claimed and not violated:
        return
    if not claimed:
        C.classify(
            "honest_deviation",
            kind="policy",
            label=label,
            summary=f"{label}: module does not claim the protection (honest non-support)",
        )
        return
    C.classify(
        "self_contradiction",
        kind="policy",
        label=label,
        summary=f"{label}: claimed the protection then violated it (self-contradiction)",
    )


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
    from pkcs11_check import classification as C

    if claimed_success and not effect_observed:
        return
    if not claimed_success:
        C.classify(
            "honest_deviation",
            kind="lifecycle",
            label=label,
            summary=f"{label}: prior operation did not claim success",
        )
        return
    C.classify(
        "self_contradiction",
        kind="lifecycle",
        label=label,
        summary=f"{label}: success claimed then contradicted (self-contradiction)",
    )


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
        from pkcs11_check import classification as C

        C.classify(
            "accepted_invalid",
            kind="crypto",
            label=label,
            summary=(
                f"{label}: the valid/un-tampered operation did not verify -- cannot "
                "distinguish 'detected tampering' from 'cannot do the operation'"
            ),
        )
    if not invalid_rejected:
        from pkcs11_check import classification as C

        C.classify(
            "accepted_invalid",
            kind="crypto",
            label=label,
            summary=f"{label}: accepted the tampered/forged/confused input (security break)",
        )


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


def assert_correct(
    *,
    actual: object,
    expected: object,
    label: str,
    operation: str | None = None,
    mechanism: str | None = None,
    source: str | None = None,
    vector_id: str | None = None,
) -> None:
    """KAT correctness check: equal values pass; a mismatch is wrong_result (crypto).

    On mismatch, emits a ``wrong_result``/``crypto``/``CRITICAL`` classification
    record and raises ``pytest.fail`` via :func:`pkcs11_check.classification.classify`.
    On match, returns normally with no side effects.
    """
    from pkcs11_check import classification as C

    if actual == expected:
        return
    C.classify(
        "wrong_result",
        kind="crypto",
        label=label,
        operation=operation,
        mechanism=mechanism,
        source=source,
        vector_id=vector_id,
        summary=f"{label}: output does not match known answer",
    )
