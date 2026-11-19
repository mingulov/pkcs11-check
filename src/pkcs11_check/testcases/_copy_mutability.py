"""QC3 copy/set mutability table and shared two-tier verdict helpers (#55).

The table pins, per attribute, whether a different-value change via
``C_CopyObject`` / ``C_SetAttributeValue`` is forbidden, tightening-only,
or allowed, with the normative citation each provider verdict references.
No generic "copy must reject all changes" oracle may be inferred: every
verdict cites its own row.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, NoReturn

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.classification import fail_as, raise_for_record, record_as, xfail_as
from pkcs11_check.raw.recipes import (
    copy_object,
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    read_attributes,
)
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CKA_ALLOWED_MECHANISMS,
    CKA_ALWAYS_AUTHENTICATE,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_PRIVATE_EXPONENT,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKM_AES_ECB,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_UNEXTRACTABLE,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import reject_or_classify

#: Fixed probe vectors shared by the QC3a/QC3b material legs (pinned by contract).
PROBE_ORIGINAL_VALUE = bytes(range(0x10, 0x20))
PROBE_INJECTED_VALUE = bytes(range(0xA0, 0xB0))
PROBE_PLAINTEXT = b"qc3probe-block16"


@dataclass(frozen=True)
class CopyMutabilityRow:
    """One attribute row: copy/set rules plus the normative citation."""

    key: str
    attr: int
    attr_name: str
    copy_rule: str  # "forbidden" | "no_downgrade" | "allowed"
    set_rule: str  # "forbidden" | "no_downgrade" | "allowed"
    citation: str


COPY_MUTABILITY_TABLE: tuple[CopyMutabilityRow, ...] = (
    CopyMutabilityRow(
        key="value",
        attr=int(CKA_VALUE),
        attr_name="CKA_VALUE",
        copy_rule="forbidden",
        set_rule="forbidden",
        citation=(
            "PKCS#11 v3.2 C_CopyObject / C_SetAttributeValue: secret key material "
            "(CKA_VALUE) is never different-value mutable via copy or set"
        ),
    ),
    CopyMutabilityRow(
        key="allowed_mechanisms",
        attr=int(CKA_ALLOWED_MECHANISMS),
        attr_name="CKA_ALLOWED_MECHANISMS",
        copy_rule="forbidden",
        set_rule="forbidden",
        citation=(
            "PKCS#11 v3.2 §4.1.3: Table 26 lacks footnote 8, so "
            "CKA_ALLOWED_MECHANISMS different-value changes are forbidden, both "
            "tightening and widening"
        ),
    ),
    CopyMutabilityRow(
        key="always_authenticate",
        attr=int(CKA_ALWAYS_AUTHENTICATE),
        attr_name="CKA_ALWAYS_AUTHENTICATE",
        copy_rule="forbidden",
        set_rule="forbidden",
        citation=(
            "PKCS#11 v3.2 Table 29: CKA_ALWAYS_AUTHENTICATE carries no footnote 8, "
            "so different-value changes are forbidden via copy and set (§4.1.2/"
            "§4.1.3 'described as being modifiable' rule)"
        ),
    ),
    CopyMutabilityRow(
        key="sensitive",
        attr=int(CKA_SENSITIVE),
        attr_name="CKA_SENSITIVE",
        copy_rule="no_downgrade",
        set_rule="no_downgrade",
        citation=(
            "PKCS#11 v3.2 Table 13 footnote 8 + footnote 11: CKA_SENSITIVE "
            "True->False downgrade forbidden on copy and set (frozen once TRUE)"
        ),
    ),
    CopyMutabilityRow(
        key="extractable",
        attr=int(CKA_EXTRACTABLE),
        attr_name="CKA_EXTRACTABLE",
        copy_rule="no_downgrade",
        set_rule="no_downgrade",
        citation=(
            "PKCS#11 v3.2 Table 13 footnote 8 + footnote 12: CKA_EXTRACTABLE "
            "True->False tightening legal via copy and set; False->True "
            "forbidden (frozen once FALSE)"
        ),
    ),
    CopyMutabilityRow(
        key="private_exponent",
        attr=int(CKA_PRIVATE_EXPONENT),
        attr_name="CKA_PRIVATE_EXPONENT",
        copy_rule="forbidden",
        set_rule="forbidden",
        citation=(
            "PKCS#11 v3.2 §4.1.2/§4.1.3 'described as being modifiable' rule: "
            "RSA private key material (CKA_PRIVATE_EXPONENT) carries no "
            "modifiable marking, so different-value changes are forbidden "
            "via copy and set"
        ),
    ),
    CopyMutabilityRow(
        key="label",
        attr=int(CKA_LABEL),
        attr_name="CKA_LABEL",
        copy_rule="allowed",
        set_rule="allowed",
        citation=(
            "Control: PKCS#11 v3.2 Table 19 discussion (§2183: 'Only the CKA_LABEL "
            "attribute can be modified after the object is created') + §4.1.3 for "
            "the copy path; copy-with-new-label and set-new-label must succeed "
            "where supported"
        ),
    ),
)

_ROWS_BY_KEY = {row.key: row for row in COPY_MUTABILITY_TABLE}

#: Provider probes; the two ALLOWED_MECHANISMS directions share one table row.
TABLE_PROBES: tuple[str, ...] = (
    "value",
    "allowed_mechanisms_widen",
    "allowed_mechanisms_narrow",
    "always_authenticate",
    "sensitive_downgrade",
    "extractable_escalate",
    "private_exponent",
    "label_control",
)

PROBE_ROW: dict[str, str] = {
    "value": "value",
    "allowed_mechanisms_widen": "allowed_mechanisms",
    "allowed_mechanisms_narrow": "allowed_mechanisms",
    "always_authenticate": "always_authenticate",
    "sensitive_downgrade": "sensitive",
    "extractable_escalate": "extractable",
    "private_exponent": "private_exponent",
    "label_control": "label",
}

#: Plausible policy refusals of a forbidden copy-template change.
COPY_FORBIDDEN_REFUSE_RVS: tuple[Any, ...] = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)

#: Plausible policy refusals of a forbidden set-attribute change.
SET_FORBIDDEN_REFUSE_RVS: tuple[Any, ...] = (
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)

#: Policy-shaped refusals proving CKA_ALLOWED_MECHANISMS exclusion (I6/F2).
#:
#: CKR_KEY_FUNCTION_NOT_PERMITTED ("use a key for a cryptographic purpose
#: that the key's attributes are not set to allow") is the SOLE
#: attribute-shaped proof for cryptographic operations. CKR_ACTION_PROHIBITED
#: is excluded by spec (§5.1.6: "can only be returned by C_CopyObject,
#: C_SetAttributeValue and C_DestroyObject"): a refusal with it routes to
#: alternate/unproved with the RV preserved, never "restriction effective".
#: COPY/SET refusal sets keep it (legal there). A transient/device-shaped
#: refusal never proves a policy effect.
POLICY_SHAPED_REFUSE_RVS: frozenset[int] = frozenset({int(CKR_KEY_FUNCTION_NOT_PERMITTED)})

#: Key-management twin of POLICY_SHAPED_REFUSE_RVS (0.3.1 #56 adjudication).
#:
#: CKR_MECHANISM_INVALID joins the attribute-shaped proof ONLY for
#: key-management operations (Derive/Wrap/Unwrap/Encapsulate/Decapsulate):
#: all five key-management return lists name it while omitting
#: FUNCTION_NOT_PERMITTED, and §5.1 expressly allows return-list gaps
#: (either code credited, raw preserved). Cryptographic operations
#: (Encrypt/Decrypt/Sign/...) keep the narrow set: a MECHANISM_INVALID
#: there evidences capability, not policy. Re-review round 2 adjudicates
#: this split (A4).
KEYMGMT_POLICY_SHAPED_REFUSE_RVS: frozenset[int] = frozenset(
    {int(CKR_KEY_FUNCTION_NOT_PERMITTED), int(CKR_MECHANISM_INVALID)}
)

#: Authentication-shaped refusal: the ONLY RV proving re-authentication is
#: demanded (PKCS#11 v3.2 §4.10: omitting re-auth "will result in
#: CKR_USER_NOT_LOGGED_IN to be returned from calls using the key").
AUTH_SHAPED_REFUSE_RV: int = int(CKR_USER_NOT_LOGGED_IN)

#: The specified non-extractability refusal (PKCS#11 v3.2: a key "can't be
#: wrapped because its CKA_EXTRACTABLE is CK_FALSE"): the ONLY RV proving
#: sealed-ness against wrap.
SEALED_WRAP_REFUSE_RV: int = int(CKR_KEY_UNEXTRACTABLE)


def classify_rv_validity_or_none(
    rv: int,
    *,
    label: str,
    operation: str,
    kind: str | None = None,
    mechanism: str | None = None,
    expected: Any = None,
) -> None:
    """Mirror ``reject_or_classify``'s standard/vendor/undefined arms (I13).

    A standard RV returns None (the caller proceeds on its normal path); a
    vendor-defined RV xfails as a visible alternate refusal; an undefined RV
    fails the metadata return-value contract. Every new QC3 catch path routes
    through this helper; no ad-hoc ``is_standard_ckr`` checks in new code.
    """
    if is_standard_ckr(rv):
        return None
    if is_vendor_defined_ckr(rv):
        xfail_as(
            "nonspec_reject",
            kind=kind,
            label=label,
            operation=operation,
            mechanism=mechanism,
            inherit_mechanism=False,
            actual=rv,
            expected=expected,
            summary=(
                f"{label}: refused with vendor-defined {ckr_name(rv)} "
                "(alternate refusal; standard outcome unproved)"
            ),
        )
    fail_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        mechanism=mechanism,
        inherit_mechanism=False,
        actual=rv,
        expected=expected,
        summary=(
            f"{label}: refused with undefined {ckr_name(rv)} (return-value contract violation)"
        ),
    )


def _record_rv_validity(
    rv: int,
    *,
    label: str,
    operation: str,
    kind: str | None = None,
) -> Any | None:
    """Non-raising twin of ``classify_rv_validity_or_none`` (N7).

    Mirrors the shared helper's reason/kind mapping exactly (vendor ->
    ``nonspec_reject``, undefined -> ``self_contradiction``/metadata,
    same summaries) but RECORDS without terminating, so the caller can
    collect every leg's RV first and then terminate with the strongest
    retained outcome. A standard RV records nothing and returns None.
    """
    if is_standard_ckr(rv):
        return None
    if is_vendor_defined_ckr(rv):
        return record_as(
            "nonspec_reject",
            kind=kind,
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=rv,
            summary=(
                f"{label}: refused with vendor-defined {ckr_name(rv)} "
                "(alternate refusal; standard outcome unproved)"
            ),
        )
    return record_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        actual=rv,
        summary=(
            f"{label}: refused with undefined {ckr_name(rv)} (return-value contract violation)"
        ),
    )


def _strongest_record(records: list[Any]) -> Any:
    """The strongest retained outcome: first FAIL, else first xfail (N7)."""
    for record in records:
        if record.outcome == "fail":
            return record
    return records[0]


def read_qc3_attributes(
    rs: Any,
    handle: int,
    attr_types: list[int],
    *,
    label: str,
    premise: bool,
    spec_ref: str | None = None,
) -> Any:
    """``read_attributes`` with QC3 readback-refusal classification (I12a/I13).

    A refused readback is classified with its original RV: premise-leg
    refusals void the leg (not_operational); post-accept refusals leave the
    accepted change's effect unproved (honest_deviation + unproved-effect,
    actual=CKR_OK per M1, the refusal RV in the summary and detail).
    Vendor-defined and undefined RVs route through the shared validity arms.
    """
    try:
        return read_attributes(rs.raw, rs.sh, handle, attr_types)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv,
            label=f"{label}: readback",
            operation="C_GetAttributeValue",
            kind="policy",
        )
        if premise:
            xfail_as(
                "not_operational",
                kind="policy",
                label=f"{label}: readback",
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                actual=exc.rv,
                spec_ref=spec_ref,
                summary=(f"{label}: readback refused with {ckr_name(exc.rv)}; premise void"),
                detail={"readback_rv": ckr_name(exc.rv)},
            )
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=f"{label}: readback",
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: accepted but readback refused with {ckr_name(exc.rv)}; effect unproved"
            ),
            detail={"disposition": "unproved-effect", "readback_rv": ckr_name(exc.rv)},
        )


def validate_qc3_shape(
    value: Any,
    shape: str,
    *,
    attr_name: str,
    label: str,
    premise: bool,
    spec_ref: str | None = None,
    expected_len: int = 0,
) -> Any:
    """Validate a present QC3 readback against its decoder shape (I12b/F11).

    Shapes (defined by the ``read_attributes`` decoder): "bool" (genuine
    bool only -- a wrong-length flag decodes to bytes, never to False),
    "ulong" (genuine int, never bool), "mech_list" (list of genuine ints),
    "value" (bytes of ``expected_len``). Callers pass MISSING_ATTRIBUTE-free
    values (absence is governed by ``attr_or_record`` upstream). Malformed
    values xfail: premise legs void (not_operational), post-accept legs
    report unproved-effect (actual=CKR_OK per M1). Malformed evidence is
    type + length + expected shape only, never value bytes (F11/N2 SECRET
    LEAK: planted key bytes as malformed flag data must not appear in any
    record); summaries likewise redact to type/length/shape.
    """
    if shape == "bool":
        well_formed = type(value) is bool
        expected_desc = "CK_BBOOL"
    elif shape == "ulong":
        well_formed = isinstance(value, int) and not isinstance(value, bool)
        expected_desc = "CK_ULONG"
    elif shape == "mech_list":
        well_formed = isinstance(value, list) and all(
            isinstance(item, int) and not isinstance(item, bool) for item in value
        )
        expected_desc = "CK_ULONG array"
    elif shape == "value":
        well_formed = isinstance(value, bytes) and len(value) == expected_len
        expected_desc = f"{expected_len}-byte value"
    else:
        raise ValueError(f"unknown QC3 shape: {shape!r}")
    if well_formed:
        return value
    if shape == "value":
        evidence: dict[str, Any] = {
            "expected_len": expected_len,
            "value_len": len(value) if isinstance(value, bytes) else None,
        }
        malformed_desc = f"length {evidence['value_len']} (expected {expected_len})"
    else:
        # F11/N2: redact to type + length + expected shape; never interpolate
        # value bytes (mechanism/identity ints, lengths, booleans, RV names are
        # fine; bytes/repr(value) are not).
        if isinstance(value, (bytes, bytearray)):
            actual_len: int | None = len(value)
        elif isinstance(value, (list, tuple, str)):
            actual_len = len(value)
        else:
            actual_len = None
        evidence = {
            "expected_shape": expected_desc,
            "actual_type": type(value).__name__,
            "actual_len": actual_len,
        }
        malformed_desc = (
            f"type {type(value).__name__}, length {actual_len} (expected {expected_desc})"
        )
    if premise:
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: {attr_name} readback",
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            spec_ref=spec_ref,
            summary=(f"{label}: malformed {attr_name} readback ({malformed_desc}); premise void"),
            detail=evidence,
        )
    xfail_as(
        "honest_deviation",
        kind="policy",
        label=f"{label}: {attr_name} readback",
        operation="C_GetAttributeValue",
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=spec_ref,
        summary=(
            f"{label}: accepted but {attr_name} reads back malformed ({malformed_desc}); "
            "effect unproved"
        ),
        detail={"disposition": "unproved-effect", **evidence},
    )


def row_by_key(key: str) -> CopyMutabilityRow:
    """Return the table row for *key* (KeyError for an unknown probe)."""
    return _ROWS_BY_KEY[key]


def classify_forbidden_change_refusal(
    exc: CkrAssertionError,
    expected_rvs: tuple[Any, ...],
    *,
    label: str,
    operation: str,
) -> None:
    """Verdict for a refused forbidden copy/set change.

    Unsupported-operation refusal skips (capability gap); a plausible
    policy refusal passes with a visible ``sanctioned_refusal`` record;
    any other clean RV xfails and an undefined RV fails via the shared
    negative classifier. The original RV is preserved on every path.
    """
    import pytest

    if exc.rv == int(CKR_FUNCTION_NOT_SUPPORTED):
        pytest.skip(f"{label}: {operation} not supported ({ckr_name(exc.rv)})")
    reject_or_classify(exc, expected_rvs, label=label, kind="policy")
    C.classify(
        "sanctioned_refusal",
        kind="policy",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        actual=exc.rv,
        expected=expected_rvs,
        summary=f"{label}: refused with {ckr_name(exc.rv)} (forbidden change rejected)",
    )


def classify_ignored_or_mutated(
    *,
    mutated: bool,
    label: str,
    operation: str,
    spec_ref: str,
    ignored_summary: str,
    mutated_summary: str,
    detail: dict[str, Any],
) -> NoReturn:
    """Two-tier verdict for an ACCEPTED forbidden change.

    Success with ignored input is a visible API deviation (xfail, recorded
    explicitly as ignored-input); an actual forbidden mutation or policy
    effect, proved by the caller's independent functional leg, fails.
    """
    if mutated:
        fail_as(
            "self_contradiction",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=mutated_summary,
            detail=detail,
        )
    xfail_as(
        "honest_deviation",
        kind="policy",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=spec_ref,
        summary=ignored_summary,
        detail=detail,
    )


def judge_guess_confirm(
    *,
    correct_exc: CkrAssertionError | None,
    wrong_exc: CkrAssertionError | None,
    correct_use: GuessUseOutcome | None,
    wrong_use: GuessUseOutcome | None,
    created_on_refusal: tuple[bool | None, bool | None],
    inventory_rvs: tuple[int | None, int | None] = (None, None),
    expected_rvs: tuple[Any, ...],
    label: str,
    operation: str,
    spec_ref: str,
) -> None:
    """Cross-leg verdict for a C_CopyObject secret-guess pair (#55.1).

    The correct-guess leg (true sealed value) and the wrong-guess leg must
    behave identically: same refusal code, or both accepted with material
    preserved (a recorded safe-ignore deviation). Any asymmetric outcome is
    a copy oracle and fails, as does a refused leg that still creates an
    object. ``created_on_refusal`` carries per-leg creation evidence:
    True proved creation, False proved none, None a refused inventory
    (creation unproved, never assumed absent). Use outcomes ride per
    accepted leg: a refused use voids the material comparison with its
    RV (never a mutation claim). Accepted legs inherit the sibling
    accepted-change tiers. The oracle failures cite no spec clause:
    identical treatment of correct and wrong guesses is a pkcs11-check
    consistency rule (#55.1), carried by the summary text.
    """
    for leg, exc in (("correct", correct_exc), ("wrong", wrong_exc)):
        if exc is not None:
            classify_rv_validity_or_none(
                exc.rv, label=f"{label}: {leg}", operation=operation, kind="policy"
            )
    legs = (
        ("correct", correct_exc, created_on_refusal[0]),
        ("wrong", wrong_exc, created_on_refusal[1]),
    )
    created_legs = [name for name, _exc, flag in legs if flag]
    if created_legs:
        refusing_excs = [
            exc for name, exc, _flag in legs if name in created_legs and exc is not None
        ]
        assert refusing_excs, "created_on_refusal True requires a refused leg"
        refusing = refusing_excs[0]
        fail_as(
            "self_contradiction",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=refusing.rv,
            summary=(
                f"refused guess-confirm leg(s) {', '.join(created_legs)} created "
                f"a session object despite refusing with {ckr_name(refusing.rv)}"
            ),
            detail={
                "label": label,
                "created_legs": created_legs,
                "refusal_rv": ckr_name(refusing.rv),
            },
        )
    unproved_legs = [name for name, exc, flag in legs if flag is None and exc is not None]
    if unproved_legs:
        unproved_exc = next(exc for name, exc, _flag in legs if name in unproved_legs)
        assert unproved_exc is not None
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=unproved_exc.rv,
            summary=(
                f"refused guess-confirm leg(s) {', '.join(unproved_legs)} with "
                f"{ckr_name(unproved_exc.rv)} but the creation inventory was refused; "
                "zero-delta unproved"
            ),
            detail={
                "disposition": "unproved-effect",
                "unproved_legs": unproved_legs,
                "refusal_rv": ckr_name(unproved_exc.rv),
                "inventory_rvs": {
                    leg: (ckr_name(rv) if rv is not None else None)
                    for leg, rv in (("correct", inventory_rvs[0]), ("wrong", inventory_rvs[1]))
                    if leg in unproved_legs
                },
            },
        )
    if correct_exc is not None and wrong_exc is not None:
        if correct_exc.rv != wrong_exc.rv:
            fail_as(
                "self_contradiction",
                kind="policy",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=correct_exc.rv,
                summary=("refusal codes differ between correct and wrong guesses (copy oracle)"),
                detail={"correct_rv": correct_exc.rv, "wrong_rv": wrong_exc.rv},
            )
        classify_forbidden_change_refusal(
            correct_exc, expected_rvs, label=label, operation=operation
        )
        classify_forbidden_change_refusal(wrong_exc, expected_rvs, label=label, operation=operation)
        return
    if correct_exc is None and wrong_exc is None:
        assert correct_use is not None and wrong_use is not None, "accepted legs need use evidence"
        retained = []
        for leg, use in (("correct", correct_use), ("wrong", wrong_use)):
            if use.use_rv is not None:
                rec = _record_rv_validity(
                    use.use_rv,
                    label=f"{label}: {leg} use",
                    operation=use.operation,
                    kind="policy",
                )
                if rec is not None:
                    retained.append(rec)
        if retained:
            raise_for_record(_strongest_record(retained))
        use_legs = (("correct", correct_use), ("wrong", wrong_use))
        refused_uses = [(leg, use) for leg, use in use_legs if use.preserved is None]
        if refused_uses:
            leg, use = refused_uses[0]
            assert use.use_rv is not None
            xfail_as(
                "not_operational",
                kind="policy",
                label=label,
                operation=use.operation,
                mechanism=use.mechanism,
                inherit_mechanism=False,
                actual=use.use_rv,
                summary=(
                    f"{label}: accepted {leg} guess use refused with "
                    f"{ckr_name(use.use_rv)}; material comparison void"
                ),
                detail={
                    "void_leg": leg,
                    "use_rv": ckr_name(use.use_rv),
                    "correct_preserved": correct_use.preserved,
                    "wrong_preserved": wrong_use.preserved,
                },
            )
        classify_ignored_or_mutated(
            mutated=not (correct_use.preserved and wrong_use.preserved),
            label=label,
            operation=operation,
            spec_ref=spec_ref,
            ignored_summary=(
                f"both guesses accepted with sealed material preserved "
                f"({correct_use.operation} output match; safe ignore)"
            ),
            mutated_summary="an accepted guess mutated sealed material",
            detail={
                "correct_preserved": correct_use.preserved,
                "wrong_preserved": wrong_use.preserved,
                "use_operation": correct_use.operation,
            },
        )
    oracle_refusing = correct_exc if correct_exc is not None else wrong_exc
    assert oracle_refusing is not None
    fail_as(
        "self_contradiction",
        kind="policy",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        actual=oracle_refusing.rv,
        summary=(
            "guess legs disagree: one accepted, one refused with "
            f"{ckr_name(oracle_refusing.rv)} (copy oracle)"
        ),
        detail={
            "correct_refused": correct_exc is not None,
            "wrong_refused": wrong_exc is not None,
            "refusal_rv": oracle_refusing.rv,
        },
    )


#: One empty/restated compare leg: ("ok", value-or-None), ("refused", rv),
#: or ("readback-refused", rv) for an accepted copy whose readback refused.
CopyCompareOutcome = tuple[str, Any]


@dataclass(frozen=True)
class GuessUseOutcome:
    """Material-use evidence for one accepted guess-confirm leg (B3).

    ``preserved`` is True when the accepted copy demonstrably kept the
    source material, False when use proves a change, and None when the
    use itself was refused (comparison void, never a mutation claim).
    A refused use carries its RV, operation, and mechanism for the
    judge's unproved record.
    """

    preserved: bool | None
    use_rv: int | None
    operation: str
    mechanism: str


def guess_use_detail(outcome: GuessUseOutcome) -> tuple[bool, str]:
    """Usability of a control duplicate plus the skip detail when unusable."""
    if outcome.preserved is True:
        return True, ""
    detail = f" (use refused with {ckr_name(outcome.use_rv)})" if outcome.use_rv is not None else ""
    return False, detail


def judge_copy_compare(
    *,
    empty: CopyCompareOutcome,
    restated: CopyCompareOutcome,
    source_value: bytes,
    label: str,
    operation: str,
    spec_ref: str,
    expected_rvs: tuple[Any, ...],
) -> None:
    """Cross-leg verdict for empty-template vs unchanged-restatement copies (#58.3).

    Equal answers pass (both preserved, or the same expected refusal
    twice with a record per leg); clean differences xfail as
    compatibility outcomes; a copy that changes the public value fails
    on its own evidence even when the sibling refuses or is unreadable;
    unreadable copy values void the comparison. Refusal RVs are
    collected from BOTH legs before any termination, so a vendor code
    on one leg never preempts an undefined code on the other: the
    strongest retained validity outcome wins.
    """
    retained: list[Any] = []
    for leg, outcome in (("empty", empty), ("restated", restated)):
        if outcome[0] == "refused":
            rec = _record_rv_validity(
                outcome[1], label=f"{label}: {leg}", operation=operation, kind="policy"
            )
        elif outcome[0] == "readback-refused":
            rec = _record_rv_validity(
                outcome[1],
                label=f"{label}: {leg} readback",
                operation="C_GetAttributeValue",
                kind="policy",
            )
        else:
            rec = None
        if rec is not None:
            retained.append(rec)
    if retained:
        raise_for_record(_strongest_record(retained))

    def _value(outcome: CopyCompareOutcome) -> bytes | None:
        return outcome[1] if outcome[0] == "ok" else None

    def _refused_rv(outcome: CopyCompareOutcome) -> int | None:
        return outcome[1] if outcome[0] == "refused" else None

    empty_value, restated_value = _value(empty), _value(restated)
    if empty_value is not None and restated_value is not None:
        if empty_value == restated_value == source_value:
            return
        if (
            int.from_bytes(empty_value, "big")
            == int.from_bytes(restated_value, "big")
            == int.from_bytes(source_value, "big")
        ):
            # D4: byte inequality with integer identity is a
            # re-encoding (leading zeros), not a value change.
            xfail_as(
                "honest_deviation",
                kind="policy",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=int(CKR_OK),
                spec_ref=spec_ref,
                summary=(
                    f"{label}: copy re-encoded the public value "
                    "(leading-zero-only difference; numeric value preserved)"
                ),
                detail={
                    "empty_len": len(empty_value),
                    "restated_len": len(restated_value),
                    "source_len": len(source_value),
                },
            )
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=f"{label}: copy changed the public value",
            detail={
                "empty_matches_source": empty_value == source_value,
                "restated_matches_source": restated_value == source_value,
                "source_len": len(source_value),
            },
        )
    if empty[0] == "refused" and restated[0] == "refused":
        if empty[1] == restated[1] and empty[1] in expected_rvs:
            for leg in ("empty", "restated"):
                C.classify(
                    "sanctioned_refusal",
                    kind="policy",
                    label=f"{label}: {leg}",
                    operation=operation,
                    inherit_mechanism=False,
                    actual=empty[1],
                    summary=(
                        f"{label}: {leg} copy refused with {ckr_name(empty[1])} "
                        "(identical answer on both legs)"
                    ),
                )
            return
        if empty[1] == restated[1]:
            xfail_as(
                "honest_deviation",
                kind="policy",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=empty[1],
                spec_ref=spec_ref,
                summary=(
                    f"{label}: empty and restated copies refused identically with "
                    f"{ckr_name(empty[1])}, outside the copy-shaped refusal set; "
                    "comparison void"
                ),
                detail={"refusal_rv": empty[1]},
            )
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=restated[1],
            spec_ref=spec_ref,
            summary=(
                f"{label}: empty and restated copies refused differently "
                f"({ckr_name(empty[1])} vs {ckr_name(restated[1])}; compat)"
            ),
            detail={"empty_rv": empty[1], "restated_rv": restated[1]},
        )
    (value, value_leg), (other, other_leg) = (
        ((empty_value, "empty"), (restated, "restated"))
        if empty_value is not None
        else ((restated_value, "restated"), (empty, "empty"))
    )
    if value is not None:
        assert isinstance(value, bytes)
        other_refused = _refused_rv(other)
        if int.from_bytes(value, "big") != int.from_bytes(source_value, "big"):
            fail_as(
                "wrong_result",
                kind="crypto",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=int(CKR_OK),
                spec_ref=spec_ref,
                summary=(
                    f"{label}: {value_leg} copy changed the public value "
                    f"(sibling {other_leg} "
                    + (
                        f"refused with {ckr_name(other_refused)}"
                        if other_refused is not None
                        else "unreadable"
                    )
                    + ")"
                ),
                detail={
                    "changed_leg": value_leg,
                    "sibling_leg": other_leg,
                    "sibling_refused": other_refused,
                    "source_len": len(source_value),
                },
            )
        if other_refused is not None:
            xfail_as(
                "honest_deviation",
                kind="policy",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=other_refused,
                spec_ref=spec_ref,
                summary=(
                    f"{label}: empty and restated copies answered differently "
                    f"(one refused with {ckr_name(other_refused)}; compat)"
                ),
                detail={
                    "empty_accepted": empty[0] == "ok",
                    "restated_accepted": restated[0] == "ok",
                    "refusal_rv": other_refused,
                },
            )
    xfail_as(
        "not_operational",
        kind="policy",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        spec_ref=spec_ref,
        summary=f"{label}: copy value unreadable; empty/restated comparison void",
        detail={
            "empty_readable": empty_value is not None,
            "restated_readable": restated_value is not None,
            "empty_refused": _refused_rv(empty),
            "restated_refused": _refused_rv(restated),
        },
    )


def run_copy_compare_leg(
    rs: Any, source: int, template: Mapping[Any, Any], *, label: str, leg: str
) -> CopyCompareOutcome:
    """Run one empty/restated compare leg; refusal RVs ride unjudged.

    Accepted copies are read back (value bytes or None when unreadable)
    and destroyed; refusals return their raw RV for the judge. Readback
    refusals ride as ("readback-refused", rv) so the judge collects
    BOTH legs' RVs before any termination -- the sibling leg always
    runs, and validity defects compete by strength, not by leg order.
    """
    try:
        copy = copy_object(rs.raw, rs.sh, source, template)
    except CkrAssertionError as exc:
        return ("refused", exc.rv)
    if not copy or copy == source:
        # A1: a copy handle aliasing the source (or null) is a proved
        # provider contradiction; fail WITHOUT destroying, or cleanup
        # would delete the source mid-test and poison the sibling leg.
        fail_as(
            "self_contradiction",
            kind="policy",
            label=f"{label}: {leg}",
            operation="C_CopyObject",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            summary=(
                f"{label}: {leg} copy returned the source handle ({copy}); refusing to destroy it"
            ),
            detail={"source": source, "copy": copy},
        )
    try:
        try:
            attrs = read_attributes(rs.raw, rs.sh, copy, [CKA_VALUE])
        except CkrAssertionError as exc:
            return ("readback-refused", exc.rv)
        readback = attr_or_record(
            attrs,
            CKA_VALUE,
            label=f"{label}: {leg} readback",
            reason="not_operational",
            kind="policy",
            inherit_mechanism=False,
        )
        if readback is MISSING_ATTRIBUTE or not isinstance(readback, bytes):
            return ("ok", None)
        return ("ok", readback)
    finally:
        destroy_quietly(rs.raw, rs.sh, copy)


def aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    """Local AES-ECB oracle for one block (independent of the module)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    worker = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # nosec B305
    return worker.update(block) + worker.finalize()


def aes_cbc_encrypt(key: bytes, iv: bytes, block: bytes) -> bytes:
    """Local AES-CBC oracle for one block (independent of the module, G4)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    worker = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return worker.update(block) + worker.finalize()


def check_ecb_oracle_or_fail(
    observed: bytes,
    *,
    label: str,
    operation: str = "C_Encrypt",
    spec_ref: str | None = None,
) -> None:
    """G4: fail unless *observed* matches the local known-key ECB oracle.

    Every QC3 AES leg uses a known imported key, so a successful ECB output
    is functional evidence only if it byte-equals the local oracle output
    over the known material. A mismatch on a successful op is a proved
    mechanism defect (crypto ``wrong_result`` FAIL with accurate
    mechanism-produced-wrong-output attribution), never a policy verdict.
    Length-only evidence; output bytes never enter any record.
    """
    expected = aes_ecb_encrypt(PROBE_ORIGINAL_VALUE, PROBE_PLAINTEXT)
    if observed != expected:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism="CKM_AES_ECB",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: CKM_AES_ECB completed but produced the wrong output "
                f"(observed_len={len(observed)}, expected_len={len(expected)}; "
                "local-oracle mismatch); crypto wrong_result"
            ),
            detail={
                "observed_len": len(observed),
                "expected_len": len(expected),
                "oracle_match": False,
            },
        )


def check_cbc_oracle_or_fail(
    observed: bytes,
    *,
    key: bytes,
    iv: bytes,
    label: str,
    operation: str = "C_Encrypt",
    spec_ref: str | None = None,
) -> None:
    """G4: fail unless *observed* matches the local known-key/IV CBC oracle.

    A module can return CKR_OK with ECB ciphertext for a CBC request, so
    completion alone never proves CBC use. Same fail shape as the ECB check.
    """
    expected = aes_cbc_encrypt(key, iv, PROBE_PLAINTEXT)
    if observed != expected:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism="CKM_AES_CBC",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: CKM_AES_CBC completed but produced the wrong output "
                f"(observed_len={len(observed)}, expected_len={len(expected)}; "
                "local-oracle mismatch); crypto wrong_result"
            ),
            detail={
                "observed_len": len(observed),
                "expected_len": len(expected),
                "oracle_match": False,
            },
        )


def check_ecb_baseline_or_fail(
    baseline: bytes,
    *,
    label: str,
    spec_ref: str | None = None,
) -> None:
    """G4/G5: validate a baseline ECB output before it feeds any comparison.

    A wrong-length successful output is a normatively-pinned malformed crypto
    failure (G5: AES-ECB preserves the input length, §6.10.4/Table 106); a
    right-length output must equal the local known-key oracle (G4). Either
    mismatch FAILs crypto ``wrong_result`` -- a comparison against an
    unvalidated baseline is void evidence. Length-only evidence.
    """
    if len(baseline) != len(PROBE_PLAINTEXT):
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation="C_Encrypt",
            mechanism="CKM_AES_ECB",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: successful ECB baseline output is malformed "
                f"(baseline_len={len(baseline)}, expected {len(PROBE_PLAINTEXT)}; "
                "AES-ECB preserves the input length, §6.10.4/Table 106); "
                "crypto wrong_result"
            ),
            detail={
                "baseline_len": len(baseline),
                "expected_len": len(PROBE_PLAINTEXT),
            },
        )
    check_ecb_oracle_or_fail(baseline, label=label, spec_ref=spec_ref)


def check_ecb_output_length_or_fail(
    observed: bytes,
    *,
    label: str,
    operation: str,
    spec_ref: str | None = None,
) -> None:
    """H2: fail unless a successful ECB output preserves the input length.

    AES-ECB preserves the input length (§6.10.4/Table 106); our fixed
    plaintext is 16 bytes, so every successful ECB output feeding a witness
    comparison must be 16 bytes. A malformed-length successful output is a
    proved crypto defect (``wrong_result`` FAIL), never an unproved policy
    xfail -- exactly the ``check_material_preserved`` G5 arm's semantics.
    The gate constrains the ECB OUTPUT length, never the recovered KEY
    length (16/24/32 witnesses stay valid). Length-only evidence.
    """
    if len(observed) != len(PROBE_PLAINTEXT):
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism="CKM_AES_ECB",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: successful ECB output is malformed "
                f"(observed_len={len(observed)}, expected {len(PROBE_PLAINTEXT)}; "
                "AES-ECB preserves the input length, §6.10.4/Table 106); "
                "crypto wrong_result"
            ),
            detail={
                "observed_len": len(observed),
                "expected_len": len(PROBE_PLAINTEXT),
            },
        )


def xfail_qc3_setup_refusal(
    exc: CkrAssertionError,
    expected_rvs: tuple[Any, ...] | set[Any] | frozenset[Any],
    *,
    label: str,
    operation: str = "C_CreateObject",
    kind: str = "policy",
    mechanism: str | None = None,
) -> NoReturn:
    """G2/I13: classify a clean standard-RV setup refusal as not-operational.

    Call only after ``classify_rv_validity_or_none`` (a standard RV is
    established; vendor/undefined are already routed). EVERY clean standard
    setup refusal xfails with the original RV preserved; the restricted
    *expected_rvs* tuple only selects the summary wording
    (expected-setup-refusal vs generic clean-unavailable-setup) -- both
    xfail. No bare ``raise`` on standard RVs: a clean unavailable setup is
    never a raw error escape.
    """
    if exc.rv in {int(rv) for rv in expected_rvs}:
        wording = "expected-setup-refusal"
    else:
        wording = "clean unavailable setup"
    xfail_as(
        "not_operational",
        kind=kind,
        label=label,
        operation=operation,
        mechanism=mechanism,
        inherit_mechanism=False,
        actual=exc.rv,
        summary=(f"{label} refused with {ckr_name(exc.rv)} ({wording}); setup not operational"),
    )


@dataclass(frozen=True)
class WrapChainValidation:
    """Outcome of provider-independent wrap validation via a local KW oracle (F6)."""

    validated: bool
    evidence: dict[str, Any]


def validate_wrap_chain(
    blob: bytes,
    *,
    kek: bytes,
    expected_key: bytes,
    label: str,
) -> WrapChainValidation:
    """Validate a wrap output by local AES-KW unwrap under the known KEK (F6).

    Provider-independent proof: local ``aes_key_unwrap(kek, blob)`` yields a
    candidate K'; K' == ``expected_key`` (known target bytes) is PROVED
    exposure with no provider use needed. A blob failing local unwrap, or a
    K' mismatch, is unvalidated (callers convert to their own unproved
    shape), never FAIL. Reference mode (``reference_key``) is DELETED: with
    every leg holding known material, two untrusted provider outputs agreeing
    proves nothing. KW blobs must be non-empty multiples of 8 (F6d);
    malformed blobs are unvalidated without an unwrap attempt. Lengths and
    match booleans only; key/blob bytes never enter any record.
    """
    from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap

    if not blob:
        return WrapChainValidation(
            validated=False, evidence={"stage": "empty-output", "blob_len": 0}
        )
    if len(blob) % 8 != 0:
        return WrapChainValidation(
            validated=False,
            evidence={"stage": "malformed-output", "blob_len": len(blob)},
        )
    try:
        candidate = aes_key_unwrap(kek, blob)
    except InvalidUnwrap:
        return WrapChainValidation(
            validated=False,
            evidence={
                "stage": "unwrap-failed",
                "blob_len": len(blob),
                "kek_len": len(kek),
                "key_match": None,
            },
        )
    key_match = candidate == expected_key
    return WrapChainValidation(
        validated=key_match,
        evidence={
            "stage": "compared",
            "blob_len": len(blob),
            "kek_len": len(kek),
            "candidate_len": len(candidate),
            "key_match": key_match,
        },
    )


def check_material_preserved(
    rs: Any,
    handle: int,
    baseline_ct: bytes,
    *,
    original_value: bytes,
    injected_value: bytes,
    plaintext: bytes,
    label: str,
    spec_ref: str,
    operation: str,
) -> NoReturn:
    """Two-tier verdict for an accepted different-value material change.

    Inspects the readback, then independently uses the material
    (encrypt must match the baseline ciphertext; decrypt must round-trip;
    the output must not match the locally computed injected-material
    ciphertext). A forbidden mutation FAILS only on independent functional
    evidence (behaves-as-injected); readback-only divergence leaves mutation
    unproved; proved crypto incoherence fails as wrong_result regardless of
    mutation attribution. Key bytes never enter any record, only match
    booleans and lengths.
    """
    attrs = read_qc3_attributes(
        rs, handle, [CKA_VALUE], label=label, premise=False, spec_ref=spec_ref
    )
    readback = attr_or_record(
        attrs,
        CKA_VALUE,
        label=f"{label}: material readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    try:
        observed_ct = encrypt_single(rs.raw, rs.sh, handle, CKM_AES_ECB, plaintext)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv, label=label, operation="C_Encrypt", mechanism="CKM_AES_ECB", kind="policy"
        )
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: accepted but use refused with {ckr_name(exc.rv)}; "
                "material effect unprovable"
            ),
            detail={"disposition": "unproved-effect", "use_rv": ckr_name(exc.rv)},
        )
    # G5/I5: AES-ECB preserves the input length here (spec §6.10.4/Table
    # 106; our fixed plaintext is 16 bytes, so ECB of one block is one
    # block). A SUCCESSFUL op with a normatively-pinned malformed output is
    # a crypto failure, not unproved policy: FAIL crypto wrong_result with
    # accurate attribution, keeping the malformed bytes OUT of all
    # comparisons (length-only evidence). G4 overturns the round-2 F6e
    # completion-only boundary for mechanism claims: every mechanism output
    # used as functional evidence is oracle-validated (CBC/ECB sanity and
    # baselines via the shared oracle checks; wrap-KW blobs keep
    # unvalidated-xfail -- no normative output shape there).
    if len(baseline_ct) != 16 or len(observed_ct) != 16:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism="CKM_AES_ECB",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: successful ECB output is malformed "
                f"(baseline_len={len(baseline_ct)}, observed_len={len(observed_ct)}; "
                "AES-ECB preserves the 16-byte input length, §6.10.4/Table 106); "
                "crypto wrong_result"
            ),
            detail={
                "baseline_len": len(baseline_ct),
                "observed_len": len(observed_ct),
                "expected_len": 16,
            },
        )
    # G2: the encrypt proof (observed_ct + readback, both pre-decrypt) is
    # evaluated BEFORE the decrypt attempt, so a later decrypt refusal cannot
    # hide an already-established effect. All names below depend only on the
    # encrypt evidence; the post-decrypt record arms reuse them unchanged.
    behaves_original = observed_ct == baseline_ct
    behaves_injected = observed_ct == aes_ecb_encrypt(injected_value, plaintext)
    readback_original = readback is not MISSING_ATTRIBUTE and readback == original_value
    readback_changed = readback is not MISSING_ATTRIBUTE and readback == injected_value
    if readback is MISSING_ATTRIBUTE:
        readback_len: int | None = None
    else:
        readback_len = len(readback)
    evidence: dict[str, Any] = {
        "readback_matches_original": readback_original,
        "readback_matches_injected": readback_changed,
        "readback_len": readback_len,
        "behaves_as_original": behaves_original,
        "behaves_as_injected": behaves_injected,
    }
    try:
        round_trip = decrypt_single(rs.raw, rs.sh, handle, CKM_AES_ECB, observed_ct)
    except CkrAssertionError as exc:
        if behaves_injected:
            # Flag-first (deliberate I13 exception): the mutation is proved by
            # the accepted encrypt output, independent of the decrypt RV, so a
            # proved mutation fails here even for vendor/undefined refusal RVs.
            # Any RV-validity verdict below is subsumed under the proved-mutation
            # FAIL with the RV preserved in use_rv; unproved refusals are
            # unaffected and still take the validity arms below.
            classify_ignored_or_mutated(
                mutated=True,
                label=label,
                operation=operation,
                spec_ref=spec_ref,
                ignored_summary="",
                mutated_summary=(
                    f"{label}: accepted and applied the different value "
                    f"(behaves_as_injected=True, readback_changed={readback_changed}, "
                    f"behaves_as_original={behaves_original}); follow-up decrypt "
                    f"refused with {ckr_name(exc.rv)}"
                ),
                detail={
                    "disposition": "forbidden-mutation",
                    "use_rv": ckr_name(exc.rv),
                    **evidence,
                },
            )
        classify_rv_validity_or_none(
            exc.rv, label=label, operation="C_Decrypt", mechanism="CKM_AES_ECB", kind="policy"
        )
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: accepted but decrypt refused with {ckr_name(exc.rv)}; "
                "material effect unprovable"
            ),
            detail={"disposition": "unproved-effect", "use_rv": ckr_name(exc.rv)},
        )
    # G5/I5 decrypt position: a successful decrypt with a malformed-length
    # output is its own accurately-attributed crypto failure (same normative
    # pin), distinct from a coherent-length wrong plaintext below.
    if len(round_trip) != len(plaintext):
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism="CKM_AES_ECB",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: successful ECB decrypt output is malformed "
                f"(round_trip_len={len(round_trip)}, expected {len(plaintext)}; "
                "AES-ECB preserves the input length, §6.10.4/Table 106); "
                "crypto wrong_result"
            ),
            detail={
                "plaintext_len": len(plaintext),
                "round_trip_len": len(round_trip),
            },
        )
    if round_trip != plaintext:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism="CKM_AES_ECB",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: encrypt/decrypt incoherent (both returned CKR_OK but "
                "decrypt produced the wrong plaintext); crypto wrong_result"
            ),
            detail={
                "plaintext_len": len(plaintext),
                "round_trip_len": len(round_trip),
                "round_trip_matches": False,
            },
        )
    if behaves_injected:
        # Independent functional evidence governs: the target exhibits the
        # injected material's behavior. A readback claiming otherwise is a
        # readback/behavior split, recorded, not a veto on the proved effect.
        classify_ignored_or_mutated(
            mutated=True,
            label=label,
            operation=operation,
            spec_ref=spec_ref,
            ignored_summary="",
            mutated_summary=(
                f"{label}: accepted and applied the different value "
                f"(behaves_as_injected=True, readback_changed={readback_changed}, "
                f"behaves_as_original={behaves_original})"
            ),
            detail={"disposition": "forbidden-mutation", **evidence},
        )
    # F3: ignored-input requires PRESENT + unchanged readback AND no effect.
    # Missing readback + behaves-original is unproved-effect (never claim
    # "readback unchanged" when nothing was read).
    if behaves_original and readback_original:
        classify_ignored_or_mutated(
            mutated=False,
            label=label,
            operation=operation,
            spec_ref=spec_ref,
            ignored_summary=(
                f"{label}: accepted but ignored the different value "
                "(readback unchanged, behaves as original material)"
            ),
            mutated_summary="",
            detail={"disposition": "ignored-input", **evidence},
        )
    if not behaves_original and not behaves_injected:
        # Coherent round-trip, but the target's crypto output matches neither
        # the source baseline nor the injected-material oracle: a proved crypto
        # divergence independent of mutation attribution.
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism="CKM_AES_ECB",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: target crypto diverges from both the source baseline "
                "and the injected-material oracle; mutation unattributed"
            ),
            detail=evidence,
        )
    # Readback diverges (changed or garbage) while behavior matches the
    # original: mutation unproved. Full evidence, length-only for the secret.
    xfail_as(
        "honest_deviation",
        kind="policy",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=spec_ref,
        summary=(
            f"{label}: accepted but the readback diverges from the original while "
            "behavior matches the original material; mutation unproved"
        ),
        detail={"disposition": "unproved-effect", **evidence},
    )
