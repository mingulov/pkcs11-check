"""QC3 copy/set mutability table and shared two-tier verdict helpers (#55).

The table pins, per attribute, whether a different-value change via
``C_CopyObject`` / ``C_SetAttributeValue`` is forbidden, tightening-only,
or allowed, with the normative citation each provider verdict references.
No generic "copy must reject all changes" oracle may be inferred: every
verdict cites its own row.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, NoReturn

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.recipes import decrypt_single, encrypt_single, read_attributes
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
    CKA_SENSITIVE,
    CKA_VALUE,
    CKM_AES_ECB,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_UNEXTRACTABLE,
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
    "label_control",
)

PROBE_ROW: dict[str, str] = {
    "value": "value",
    "allowed_mechanisms_widen": "allowed_mechanisms",
    "allowed_mechanisms_narrow": "allowed_mechanisms",
    "always_authenticate": "always_authenticate",
    "sensitive_downgrade": "sensitive",
    "extractable_escalate": "extractable",
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
#: CKR_KEY_FUNCTION_NOT_PERMITTED is the SOLE CBC proof shape ("use a key
#: for a cryptographic purpose that the key's attributes are not set to
#: allow"). CKR_ACTION_PROHIBITED is excluded by spec (§5.1.6: "can only
#: be returned by C_CopyObject, C_SetAttributeValue and C_DestroyObject"):
#: a CBC refusal with it routes to alternate/unproved with the RV
#: preserved, never "restriction effective". COPY/SET refusal sets keep it
#: (legal there). A transient/device-shaped refusal never proves a policy
#: effect. Re-review round 2 adjudicates this set.
POLICY_SHAPED_REFUSE_RVS: frozenset[int] = frozenset({int(CKR_KEY_FUNCTION_NOT_PERMITTED)})

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
    try:
        round_trip = decrypt_single(rs.raw, rs.sh, handle, CKM_AES_ECB, observed_ct)
    except CkrAssertionError as exc:
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
