"""At-source test-outcome classification for pkcs11-check.

Tests emit a structured :class:`Classification` record at the moment they decide
``fail``/``xfail``/``pass``, instead of flattening everything into a free-text
``pytest.fail``/``pytest.xfail`` string.  This is the foundation of the migration
to at-source classification and is a sibling of :mod:`pkcs11_check.compliance`.

The model table is encoded once in :func:`derive_verdict`: given a provider-general
``reason`` (and an optional finding ``kind``) it returns the ``(outcome, severity)``
pair.  :func:`classify` is the emit API used by tests — it builds the record, stores
it in the per-test collector, and raises ``pytest.fail``/``pytest.xfail`` as needed.

Usage in tests::

    from pkcs11_check import classification as C

    C.classify("accepted_invalid", kind="crypto", label="RSA:decrypt",
               operation="C_Decrypt", expected=[CKR_ENCRYPTED_DATA_INVALID],
               actual=rv)
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import Any, Literal, NoReturn, cast

import pytest

from pkcs11_check.raw.rv import ckr_name

Outcome = Literal["pass", "xfail", "fail"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_REASON_OUTCOME: dict[str, Outcome] = {
    "wrong_result": "fail",
    "accepted_invalid": "fail",
    "self_contradiction": "fail",
    "oracle": "fail",
    "crash": "fail",
    "not_operational": "xfail",
    "nonspec_reject": "xfail",
    "honest_deviation": "xfail",
    "undeclared_capability": "xfail",  # over-advertised: performed more than advertised, benign
    "sanctioned_refusal": "pass",
    "unclassified": "fail",
    # Not a provider verdict: OUR code broke (GH #9/#11). Still a fail so it is loud and
    # can never pass silently, but reports must not count it against the module.
    "harness_error": "fail",
}

# Reasons that describe the harness rather than the module under test. Report surfaces
# use this to keep them out of provider finding counts.
HARNESS_REASONS = frozenset({"harness_error"})


def _severity(reason: str, kind: str | None) -> Severity:
    if reason == "wrong_result":
        return "CRITICAL" if kind == "crypto" else "MEDIUM"
    if reason in ("accepted_invalid", "self_contradiction"):
        return "CRITICAL" if kind in ("crypto", "policy") else "HIGH"
    if reason in ("oracle", "crash", "unclassified", "harness_error"):
        return "HIGH"
    if reason in ("not_operational", "nonspec_reject", "honest_deviation", "undeclared_capability"):
        return "LOW"
    if reason == "sanctioned_refusal":
        return "INFO"
    # guards a reason present in _REASON_OUTCOME but missing a severity rule here
    raise ValueError(f"unknown reason: {reason!r}")


def derive_verdict(reason: str, kind: str | None) -> tuple[Outcome, Severity]:
    """Return the ``(outcome, severity)`` for a ``reason``/``kind`` pair.

    Raises ``ValueError`` for an unknown ``reason``.
    """
    if reason not in _REASON_OUTCOME:
        raise ValueError(f"unknown reason: {reason!r}")
    return _REASON_OUTCOME[reason], _severity(reason, kind)


@dataclass
class Classification:
    """A single at-source classification record emitted by a test."""

    reason: str
    outcome: str
    severity: str
    kind: str | None = None
    label: str = ""
    summary: str = ""
    operation: str | None = None
    mechanism: str | None = None
    expected_ckr: list[str] | None = None
    actual_ckr: str | None = None
    spec_ref: str = ""
    source: str | None = None
    vector_id: str | None = None
    params: dict[str, str] | None = None
    detail: dict[str, Any] | None = None
    schema: int = 1


# Global collector for the current test run.
_records: list[Classification] = []

# Params (curve/key-size/hash) attached to every classification from the current
# test; set once per test and cleared by clear() between tests.
_active_params: dict[str, str] | None = None

# Reproducer identity (vector file + case id) for the current vector-replay test;
# set once per test, inherited by every classify(), cleared by clear().
_active_source: str | None = None
_active_vector_id: str | None = None

# Operation identity (mechanism + C_* op) for the current test; set once, inherited by
# every classify() (incl. the not_operational/xfail paths), cleared by clear().
_active_mechanism: str | None = None
_active_operation: str | None = None
# Whether a PASS of this test implies the operation ran productively (returned CKR_OK).
# True only for positive/expect-success tests; a negative (rejection) vector passes WITHOUT
# any CKR_OK, so it must not count as a productive claim for the hollow-pass oracle.
_active_expect_success: bool = False


# Curve aliases: NIST P-* and ACVP ED-* names map to the canonical secp*/ed*
# forms, and all curves lower-case, so equivalent curves from different vector
# families share one report bucket instead of fragmenting.
_CURVE_ALIASES: dict[str, str] = {
    "p-192": "secp192r1",
    "p-224": "secp224r1",
    "p-256": "secp256r1",
    "p-256k": "secp256k1",
    "p-384": "secp384r1",
    "p-521": "secp521r1",
    "ed-25519": "ed25519",
    "ed-448": "ed448",
}

# Hash aliases: the CKM/CKK HMAC mechanism spellings map to the bare digest in the
# canonical dash form, so a digest named in HMAC form (SHA512_HMAC) and the same
# digest from an RSA/ECDSA vector (SHA-512) share one report bucket. Already-canonical
# dash forms (SHA-512, SHA3-256, SHA-512/256) only need lower-casing.
_HASH_ALIASES: dict[str, str] = {
    "sha_1_hmac": "sha-1",
    "sha224_hmac": "sha-224",
    "sha256_hmac": "sha-256",
    "sha384_hmac": "sha-384",
    "sha512_hmac": "sha-512",
    "sha512_224_hmac": "sha-512/224",
    "sha512_256_hmac": "sha-512/256",
    "sha3_224_hmac": "sha3-224",
    "sha3_256_hmac": "sha3-256",
    "sha3_384_hmac": "sha3-384",
    "sha3_512_hmac": "sha3-512",
}


def normalize_param(key: str, value: str) -> str:
    """Canonicalize a param value so equivalent forms share one report bucket.

    The single source of truth for param-value canonicalization, applied at emission
    (:func:`set_params`) and defensively in the report extractor. The high-cardinality
    discriminating axes - ``curve`` and ``hash`` - are normalized to one vocabulary;
    other keys (the ``*_bits`` sizes, ``mlkem``/``mldsa`` levels) are already consistent
    decimal/level strings and pass through unchanged.
    """
    if key == "curve":
        lowered = value.lower()
        return _CURVE_ALIASES.get(lowered, lowered)
    if key == "hash":
        lowered = value.lower()
        return _HASH_ALIASES.get(lowered, lowered)
    return value


def set_params(params: dict[str, str] | None) -> None:
    """Declare the discriminating params for the current test (curve/size/hash).

    Every classify() emitted afterwards inherits these unless it passes its own
    ``params``. Cleared per-test by clear(), so it cannot leak across tests.
    """
    global _active_params
    if params:
        cleaned = {k: normalize_param(k, v) for k, v in params.items() if v}
        _active_params = cleaned or None
    else:
        _active_params = None


def set_vector(source: str | None, vector_id: str | None) -> None:
    """Declare the reproducer identity (vector file + case id) for the current test.

    Every classify() afterwards inherits ``source``/``vector_id`` unless it passes its
    own. Set once per vector-replay test (e.g. by the autouse vector-context fixture);
    cleared by clear() so it cannot leak across tests.
    """
    global _active_source, _active_vector_id
    _active_source = source or None
    _active_vector_id = vector_id or None


def set_mechanism(
    mechanism: str | None, operation: str | None = None, *, expect_success: bool = False
) -> None:
    """Declare the operation identity (mechanism + C_* op) for the current test.

    Every classify() afterwards inherits ``mechanism``/``operation`` unless it passes
    its own. Set once per vector-replay test where the operation is constant, so the
    not_operational/xfail paths carry the mechanism; cleared by clear().

    ``expect_success`` declares that a PASS of this test requires ``operation`` to have
    run productively (returned CKR_OK) -- i.e. this is a positive vector. It gates the
    hollow-pass oracle's productive claim (``current_claimed_op``): a negative/rejection
    vector passes without any CKR_OK, so it must leave ``expect_success`` False (the
    default) and never count toward claimed_passes. It does NOT affect the ``operation``
    metadata carried on classify() records.
    """
    global _active_mechanism, _active_operation, _active_expect_success
    _active_mechanism = mechanism or None
    _active_operation = operation or None
    _active_expect_success = bool(expect_success) and _active_operation is not None


def record(rec: Classification) -> None:
    """Record a classification for the current test."""
    _records.append(rec)


def get_records() -> list[Classification]:
    """Return all classification records collected so far."""
    return list(_records)


def current_operation() -> str | None:
    """The C_* operation the current test declared via set_mechanism(), or None.

    This is operation *metadata* (carried on classify() records regardless of outcome).
    For the hollow-pass oracle's productive claim, use current_claimed_op(), which is
    gated on expect_success. Cleared by clear() between tests."""
    return _active_operation


def current_claimed_op() -> str | None:
    """The operation a PASS of this test claims to have run productively (CKR_OK), or None.

    Returns the declared operation only when set_mechanism(..., expect_success=True) was
    used (a positive vector). Negative/rejection vectors return None so their passes do not
    inflate the hollow-pass oracle's claimed_passes. Cleared by clear() between tests."""
    return _active_operation if _active_expect_success else None


def clear() -> None:
    """Clear collected records and active context (call between tests)."""
    global _active_params, _active_source, _active_vector_id
    global _active_mechanism, _active_operation, _active_expect_success
    _records.clear()
    _active_params = None
    _active_source = None
    _active_vector_id = None
    _active_mechanism = None
    _active_operation = None
    _active_expect_success = False


def serialize(records: list[Classification]) -> list[dict[str, Any]]:
    """Serialize classification records into JSON-safe artifact dicts."""
    return [asdict(r) for r in records]


def _ckr_names(codes: object) -> list[str] | None:
    if codes is None:
        return None
    if isinstance(codes, int):
        return [ckr_name(codes)]
    items = cast("Iterable[object]", codes)
    return [ckr_name(c) if isinstance(c, int) else str(c) for c in items]


def _ckr_name(code: object) -> str | None:
    if code is None:
        return None
    return ckr_name(code) if isinstance(code, int) else str(code)


def _template_summary(
    label: str, expected: list[str] | None, actual: str | None, reason: str
) -> str:
    head = label or reason
    if actual and expected:
        return f"{head}: expected {expected}, got {actual}"
    if actual:
        return f"{head}: got {actual}"
    if expected:
        return f"{head}: expected {expected}"
    return f"{head}: {reason}"


def classify(
    reason: str,
    *,
    kind: str | None = None,
    label: str = "",
    operation: str | None = None,
    mechanism: str | None = None,
    expected: object = None,
    actual: object = None,
    spec_ref: str | None = None,
    source: str | None = None,
    vector_id: str | None = None,
    params: dict[str, str] | None = None,
    summary: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Emit a classification: record it, then raise the matching pytest outcome.

    ``actual``/``expected`` may be ints (real CKR codes, resolved via ``ckr_name``)
    or strings (passed through unchanged).  A ``fail`` raises ``pytest.fail`` and an
    ``xfail`` raises ``pytest.xfail``; ``pass`` returns normally.
    """
    if params is None and _active_params is not None:
        params = dict(_active_params)
    if source is None:
        source = _active_source
    if vector_id is None:
        vector_id = _active_vector_id
    if mechanism is None:
        mechanism = _active_mechanism
    if operation is None:
        operation = _active_operation
    outcome, severity = derive_verdict(reason, kind)
    expected_names = _ckr_names(expected)
    actual_name = _ckr_name(actual)
    if summary is None:
        summary = _template_summary(label, expected_names, actual_name, reason)
    if spec_ref is None:
        from pkcs11_check.spec_refs import lookup

        spec_ref = lookup(operation, mechanism, expected)
    record(
        Classification(
            reason=reason,
            outcome=outcome,
            severity=severity,
            kind=kind,
            label=label,
            summary=summary,
            operation=operation,
            mechanism=mechanism,
            expected_ckr=expected_names,
            actual_ckr=actual_name,
            spec_ref=spec_ref or "",
            source=source,
            vector_id=vector_id,
            params=params,
            detail=detail,
        )
    )
    if outcome == "fail":
        pytest.fail(summary)
    if outcome == "xfail":
        pytest.xfail(summary)


def fail_as(reason: str, **kw: Any) -> NoReturn:
    """Emit a ``fail`` classification; raises ``ValueError`` if *reason* is not a fail reason."""
    if derive_verdict(reason, kw.get("kind"))[0] != "fail":
        raise ValueError(f"fail_as requires a fail reason, got {reason!r}")
    classify(reason, **kw)
    raise AssertionError("unreachable: classify() with a fail reason must raise")


def xfail_as(reason: str, **kw: Any) -> NoReturn:
    """Emit an ``xfail`` classification.

    Raises ``ValueError`` if *reason* does not map to an xfail outcome.
    """
    if derive_verdict(reason, kw.get("kind"))[0] != "xfail":
        raise ValueError(f"xfail_as requires an xfail reason, got {reason!r}")
    classify(reason, **kw)
    raise AssertionError("unreachable: classify() with an xfail reason must raise")
