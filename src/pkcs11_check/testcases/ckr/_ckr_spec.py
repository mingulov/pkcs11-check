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
    """Emit a Classification for a code outside the full acceptable set.

    Mirrors the ``_classify_unexpected_clean_rv`` directional rule in
    testcases/conftest.py (F-023):
    - undefined (neither standard nor vendor-defined) -> self_contradiction
      (kind="metadata") -> fail/HIGH: an arbitrary integer is not a
      recognized clean CKR.
    - vendor-defined CK_RV      -> nonspec_reject -> xfail.
    - defined standard code     -> nonspec_reject -> xfail.
    """
    prefix = _ckr_summary_prefix(expectation)
    accepted = list(dict.fromkeys(ckr_name(c) for c in full))
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
    # F-023: a recognized (vendor-defined or standard) code outside the
    # acceptable set is a clean non-spec rejection -- a noted deviation,
    # not a self-contradiction.
    C.classify(
        "nonspec_reject",
        kind=expectation.kind,
        label=expectation.condition,
        operation=expectation.function,
        actual=actual,
        expected=spec_codes,
        spec_ref=expectation.spec_ref,
        summary=(
            f"{prefix}: got {ckr_name(actual)}, "
            f"not in acceptable set {accepted} "
            f"[{expectation.spec_ref}]"
        ),
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
        * rv not in full_compat   -> xfail for a recognized (standard or
                                     vendor-defined) code (clean non-spec
                                     rejection; a noted deviation);
                                     fail only for an undefined CK_RV
                                     (return-value-contract violation).
        * rv in spec_codes        -> pass (spec-preferred rejection).
        * rv in full_compat but
          not in spec_codes       -> xfail (clean but non-spec rejection;
                                     a noted deviation to investigate later).

    Each decision point emits a structured :class:`~pkcs11_check.classification.Classification`
    record via :func:`~pkcs11_check.classification.classify`.

    Design note: strict mode keeps its separate, exact meaning -- any
    non-spec code (including compat-acceptable deviations) is a fail there
    (via ``self_contradiction(kind="metadata")``). Only the compat path
    follows the directional rule above.
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
