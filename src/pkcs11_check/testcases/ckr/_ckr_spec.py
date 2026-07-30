"""Centralized PKCS#11 CKR spec assertion helpers.

The per-family spec DATA TABLES live in _ckr_spec_tables.py and the shared primitives
(CkrExpectation / full_compat / universals) in _ckr_spec_base.py; both are re-exported
here so the public import surface (`from ._ckr_spec import CKR_ENCRYPT, assert_ckr, ...`)
is unchanged. Source of truth: OASIS PKCS#11 v3.2. CKR codes are ints; tests check raw
CK_RV values, not exception types.
"""

from __future__ import annotations

from pkcs11_check import classification as C
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import CKR_OK
from pkcs11_check.testcases.ckr._ckr_spec_base import (
    _SESSION_UNIVERSAL,
    _TOKEN_UNIVERSAL,
    _UNIVERSAL,
    CkrExpectation,
    full_compat,
)
from pkcs11_check.testcases.ckr._ckr_spec_tables import (
    CKR_ASYNC,
    CKR_DECRYPT,
    CKR_DERIVE,
    CKR_DIGEST,
    CKR_ENCRYPT,
    CKR_GENERAL,
    CKR_KEM,
    CKR_KEYGEN,
    CKR_MSG_DECRYPT,
    CKR_MSG_ENCRYPT,
    CKR_MSG_SIGN,
    CKR_MSG_VERIFY,
    CKR_OBJECT,
    CKR_RANDOM,
    CKR_SESSION,
    CKR_SIGN,
    CKR_SLOT_TOKEN,
    CKR_STATE,
    CKR_UNTESTABLE,
    CKR_VERIFY,
    CKR_VERIFY_SIGNATURE,
    CKR_WRAP,
    CKR_WRAP_AUTH,
)

# ---------------------------------------------------------------------------
# assert_ckr - the single validation point
# ---------------------------------------------------------------------------


def _ckr_summary_prefix(expectation: CkrExpectation) -> str:
    """Build the summary prefix string: ``function(condition)``."""
    return f"{expectation.function}({expectation.condition})"


def _classify_outside_acceptable_set(
    expectation: CkrExpectation,
    actual: int,
    spec_codes: tuple[int, ...],
    full: tuple[int, ...],
) -> None:
    """Emit a Classification (always fail) for a code outside the full acceptable set.

    Mirrors the ``_classify_unexpected_clean_rv`` logic in testcases/conftest.py:
    - vendor-defined CK_RV      -> self_contradiction (fail) to preserve pre-refactor
                                   pytest.fail outcome [flagged for review].
    - undefined (not standard)  -> self_contradiction(kind="metadata") -> fail/HIGH.
    - defined standard code     -> self_contradiction(kind=expectation.kind) -> fail;
                                   NOTE: flagged for design review — see assert_ckr docstring.

    All branches here currently produce ``fail`` outcomes (this function is only reached
    when the existing code called ``pytest.fail``).  The nonspec_reject reason maps to
    xfail, which would change the outcome; hence vendor-defined codes here also use
    self_contradiction so the fail outcome is preserved.
    """
    prefix = _ckr_summary_prefix(expectation)
    accepted = list(dict.fromkeys(ckr_name(c) for c in full))
    summary = (
        f"{prefix}: got {ckr_name(actual)}, "
        f"not in acceptable set {accepted} "
        f"[{expectation.spec_ref}]"
    )
    if not is_standard_ckr(actual) and not is_vendor_defined_ckr(actual):
        # Completely undefined CK_RV: return-value-contract violation.
        C.classify(
            "self_contradiction",
            kind="metadata",
            label=expectation.condition,
            operation=expectation.function,
            actual=actual,
            expected=spec_codes,
            spec_ref=expectation.spec_ref,
            summary=f"{prefix}: rejected with undefined CK_RV {ckr_name(actual)}, "
            f"not in acceptable set {accepted} [{expectation.spec_ref}]",
        )
        return
    # Vendor-defined or standard-but-outside-set: both are outside the gate, so both
    # produce fail here (consistent with the pre-refactor pytest.fail call).
    # REVIEW NOTE: a vendor-defined code might arguably be nonspec_reject (xfail) in a
    # future design iteration; a standard-but-outside-set code might also be nonspec_reject
    # if the acceptable-set definition is widened.  For now both stay as fail (outcome
    # preserved from pre-refactor) via self_contradiction(kind=expectation.kind).
    C.classify(
        "self_contradiction",
        kind=expectation.kind,
        label=expectation.condition,
        operation=expectation.function,
        actual=actual,
        expected=spec_codes,
        spec_ref=expectation.spec_ref,
        summary=summary,
    )


def assert_ckr(
    expectation: CkrExpectation,
    actual: int,
    strict: bool,
) -> None:
    """Validate a negative-op CKR three ways (compat) or exactly (strict).

    actual is a raw CK_RV integer (e.g. from raw.C_EncryptInit()).

    - Strict mode: rv must match spec_ckr exactly. Deviation = test failure.
    - Compat mode (the provider-general classifier):
        * rv == CKR_OK            -> fail (accepted invalid; must reject),
                                     unless allow_success is set -> pass.
        * rv not in full_compat   -> fail (rejected with a code outside the
                                     acceptable set).
        * rv in spec_codes        -> pass (spec-preferred rejection).
        * rv in full_compat but
          not in spec_codes       -> xfail (clean but non-spec rejection;
                                     a noted deviation to investigate later).

    Each decision point emits a structured :class:`~pkcs11_check.classification.Classification`
    record via :func:`~pkcs11_check.classification.classify` (emit-only refactor: outcomes
    are unchanged from pre-refactor behavior).

    Design note — branches flagged for review:
    - Compat "not in acceptable set" with a vendor-defined OR a defined-standard-but-outside-set
      code: both remain ``fail`` (via ``self_contradiction``) to preserve the pre-refactor
      ``pytest.fail`` outcome.  A future revision might treat vendor-defined or
      standard-but-outside-set codes as ``nonspec_reject`` (xfail) if the acceptable-set
      definition is widened.
    - Strict "not in spec_codes" with a non-CKR_OK code: also ``fail`` (via
      ``self_contradiction(kind="metadata")``) to preserve the strict-mode fail outcome
      for compat-acceptable deviations.
    """
    spec_codes = (
        expectation.spec_ckr if isinstance(expectation.spec_ckr, tuple) else (expectation.spec_ckr,)
    )
    prefix = _ckr_summary_prefix(expectation)

    if strict:
        # A permissive op (allow_success) returning CKR_OK is a pass in both modes;
        # CKR_OK is never in spec_codes, so this short-circuit is required for strict
        # mode to agree with the compat branch (audit M-CLASS-3).
        if actual == CKR_OK and expectation.allow_success:
            return
        if actual not in spec_codes:
            if actual == CKR_OK:
                # Accepted when it must reject (strict mode, no allow_success).
                C.classify(
                    "accepted_invalid",
                    kind=expectation.kind,
                    label=expectation.condition,
                    operation=expectation.function,
                    actual=actual,
                    expected=spec_codes,
                    spec_ref=expectation.spec_ref,
                    summary=f"{prefix}: accepted (CKR_OK) but must reject [{expectation.spec_ref}]",
                )
            else:
                # Non-CKR_OK deviation from spec in strict mode: preserve fail outcome.
                # REVIEW NOTE: compat-acceptable codes (e.g. CKR_FUNCTION_FAILED) that are
                # not spec-mandated land here in strict mode and stay as fail/self_contradiction
                # rather than xfail/nonspec_reject — consistent with pre-refactor behavior.
                C.classify(
                    "self_contradiction",
                    kind="metadata",
                    label=expectation.condition,
                    operation=expectation.function,
                    actual=actual,
                    expected=spec_codes,
                    spec_ref=expectation.spec_ref,
                    summary=(
                        f"{prefix}: spec requires {[ckr_name(c) for c in spec_codes]}, "
                        f"got {ckr_name(actual)} [{expectation.spec_ref}]"
                    ),
                )
    else:
        if actual == CKR_OK:
            if expectation.allow_success:
                return
            C.classify(
                "accepted_invalid",
                kind=expectation.kind,
                label=expectation.condition,
                operation=expectation.function,
                actual=actual,
                expected=spec_codes,
                spec_ref=expectation.spec_ref,
                summary=f"{prefix}: accepted (CKR_OK) but must reject [{expectation.spec_ref}]",
            )
            return
        full = full_compat(expectation.compat_tuple)
        if actual not in full:
            _classify_outside_acceptable_set(expectation, actual, spec_codes, full)
            return
        if actual not in spec_codes:
            C.classify(
                "nonspec_reject",
                kind=expectation.kind,
                label=expectation.condition,
                operation=expectation.function,
                actual=actual,
                expected=spec_codes,
                spec_ref=expectation.spec_ref,
                summary=(
                    f"{prefix}: rejected with {ckr_name(actual)}, "
                    f"spec prefers {[ckr_name(c) for c in spec_codes]} "
                    f"[{expectation.spec_ref}]"
                ),
            )


__all__ = [
    "CkrExpectation",
    "assert_ckr",
    "full_compat",
    "_UNIVERSAL",
    "_SESSION_UNIVERSAL",
    "_TOKEN_UNIVERSAL",
    "CKR_ENCRYPT",
    "CKR_DECRYPT",
    "CKR_SIGN",
    "CKR_VERIFY",
    "CKR_DIGEST",
    "CKR_KEYGEN",
    "CKR_DERIVE",
    "CKR_KEM",
    "CKR_WRAP",
    "CKR_OBJECT",
    "CKR_SESSION",
    "CKR_RANDOM",
    "CKR_STATE",
    "CKR_SLOT_TOKEN",
    "CKR_GENERAL",
    "CKR_VERIFY_SIGNATURE",
    "CKR_MSG_ENCRYPT",
    "CKR_MSG_DECRYPT",
    "CKR_MSG_SIGN",
    "CKR_MSG_VERIFY",
    "CKR_WRAP_AUTH",
    "CKR_ASYNC",
    "CKR_UNTESTABLE",
]
