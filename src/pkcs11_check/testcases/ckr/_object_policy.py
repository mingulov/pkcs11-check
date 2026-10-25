"""QC4 policy-effect and malformed-object tables and shared legs (#56).

QC4a pins, per function, which participating key carries the
``CKA_ALLOWED_MECHANISMS`` contract (derive -> base key, wrap -> wrapping
key, unwrap -> unwrapping key, encapsulate -> public key, decapsulate ->
private key). The peer/target key's list is observed into evidence but
never carries an oracle. Included legs must complete with an
independently verified effect; excluded legs must refuse with the
Task-15-strict policy singleton (``CKR_KEY_FUNCTION_NOT_PERMITTED``).

QC4b runs the Create/Unwrap/Generate x RSA/EC/offered-PQC malformed
class/type matrix: rejection proves zero inventory delta, acceptance
inspects the readback identity and uses the material, and FAIL fires
only on a proved contradiction.

QC4c re-attempts one QC4b RSA malformed creation per node and, only when
admitted, runs the RSA-sign path with independent local verification.
"""

from __future__ import annotations

import inspect
import sys
import uuid
from collections.abc import Callable, Iterable
from ctypes import byref
from dataclasses import dataclass, replace
from functools import lru_cache
from typing import Any, NoReturn

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from pkcs11_check.classification import (
    classify,
    fail_as,
    get_records,
    raise_for_record,
    record_as,
    xfail_as,
)
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.api import ckm_name
from pkcs11_check.raw.pack import (
    attr_bytes,
    attr_ulong,
    mech_simple,
    mech_string_data,
    template,
)
from pkcs11_check.raw.recipes import (
    create_object,
    decapsulate_key,
    decrypt_single,
    derive_key,
    destroy_quietly,
    encapsulate_key,
    encrypt_single,
    gen_ec_keypair,
    gen_keypair,
    gen_rsa_keypair,
    import_secret_key,
    message_decrypt,
    message_encrypt,
    pack_attrs,
    read_attributes,
    sign_single,
    to_ubyte_buf,
    unwrap_key,
    verify_single,
    wrap_key,
)
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    expect_rv,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_ALLOWED_MECHANISMS,
    CKA_CLASS,
    CKA_COEFFICIENT,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_MODULUS_BITS,
    CKA_PARAMETER_SET,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_PRIVATE_EXPONENT,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKK_AES,
    CKK_EC,
    CKK_GENERIC_SECRET,
    CKK_ML_DSA,
    CKK_RSA,
    CKK_SLH_DSA,
    CKM_AES_ECB,
    CKM_AES_ECB_ENCRYPT_DATA,
    CKM_AES_KEY_WRAP,
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_ML_DSA,
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKM_ML_KEM,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256_RSA_PKCS,
    CKM_SLH_DSA,
    CKM_SLH_DSA_KEY_PAIR_GEN,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKP_ML_DSA_44,
    CKP_ML_DSA_65,
    CKP_ML_DSA_87,
    CKP_SLH_DSA_SHA2_128S,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
)
from pkcs11_check.testcases._attribute_values import (
    MISSING_ATTRIBUTE,
    attr_or_record,
    refusal_rv_for,
)
from pkcs11_check.testcases._copy_mutability import (
    POLICY_SHAPED_REFUSE_RVS,
    PROBE_PLAINTEXT,
    aes_ecb_encrypt,
    classify_rv_validity_or_none,
    read_qc3_attributes,
    validate_qc3_shape,
    validate_wrap_chain,
    xfail_qc3_setup_refusal,
)
from pkcs11_check.testcases._ec_export import split_raw_ecdsa
from pkcs11_check.testcases._local_verify import (
    MalformedSignature,
    rsa_pkcs15_local,
)
from pkcs11_check.testcases.conftest import skip_unless_create_object_supported


@dataclass(frozen=True)
class PolicyFunctionRow:
    """One QC4a function row: the PRIMARY constrained key + citation."""

    key: str
    operation: str
    constrained_role: str
    citation: str


#: Shared refusal-oracle note for the QC4a enforcement rows (F17): none of
#: §§5.18.3/5.18.4/5.18.5/5.18.8/5.18.9 names a refusal RV for policy exclusion
#: (verified against the v3.2 PDF: zero CKR_KEY_FUNCTION_NOT_PERMITTED mentions
#: in those sections, prose or Return values). The strict singleton comes from
#: the general CK_RV definition -- "use a key for a cryptographic purpose that
#: the key's attributes are not set to allow it to do" -- as adjudicated for
#: Task 16, NOT from explicit per-function normative text.
_REFUSAL_ORACLE_NOTE = (
    "refusal oracle: CKR_KEY_FUNCTION_NOT_PERMITTED from the general CK_RV "
    "definition, adopted as the strict singleton by Task 16 adjudication "
    "(the function section names no refusal RV)"
)

POLICY_FUNCTION_TABLE: tuple[PolicyFunctionRow, ...] = (
    PolicyFunctionRow(
        key="derive",
        operation="C_DeriveKey",
        constrained_role="base key",
        citation=(
            "PKCS#11 v3.2 §5.18.5 (C_DeriveKey hBaseKey); CKA_ALLOWED_MECHANISMS "
            "per Table 26 (Key Attributes); " + _REFUSAL_ORACLE_NOTE
        ),
    ),
    PolicyFunctionRow(
        key="wrap",
        operation="C_WrapKey",
        constrained_role="wrapping key",
        citation=(
            "PKCS#11 v3.2 §5.18.3 (C_WrapKey hWrappingKey); CKA_ALLOWED_MECHANISMS "
            "per Table 26 (Key Attributes); " + _REFUSAL_ORACLE_NOTE
        ),
    ),
    PolicyFunctionRow(
        key="unwrap",
        operation="C_UnwrapKey",
        constrained_role="unwrapping key",
        citation=(
            "PKCS#11 v3.2 §5.18.4 (C_UnwrapKey hUnwrappingKey); "
            "CKA_ALLOWED_MECHANISMS per Table 26 (Key Attributes); " + _REFUSAL_ORACLE_NOTE
        ),
    ),
    PolicyFunctionRow(
        key="encapsulate",
        operation="C_EncapsulateKey",
        constrained_role="public key",
        citation=(
            "PKCS#11 v3.2 §5.18.8 (C_EncapsulateKey hKey, the public KEM key); "
            "CKA_ALLOWED_MECHANISMS per Table 26 (Key Attributes); " + _REFUSAL_ORACLE_NOTE
        ),
    ),
    PolicyFunctionRow(
        key="decapsulate",
        operation="C_DecapsulateKey",
        constrained_role="private key",
        citation=(
            "PKCS#11 v3.2 §5.18.9 (C_DecapsulateKey hPrivateKey); "
            "CKA_ALLOWED_MECHANISMS per Table 26 (Key Attributes); " + _REFUSAL_ORACLE_NOTE
        ),
    ),
)

_ROWS_BY_KEY = {row.key: row for row in POLICY_FUNCTION_TABLE}

QC4_LEGS = ("included", "excluded")
QC4_USES = ("classic", "message")

#: QC4b matrix cells: (family, malformation) per operation.
CREATE_CELLS: tuple[tuple[str, str], ...] = (
    ("rsa", "swap_secret_class_asym_type"),
    ("rsa", "swap_asym_class_secret_type"),
    ("rsa", "missing_modulus"),
    ("rsa", "missing_exponent"),
    ("ec", "swap_secret_class_asym_type"),
    ("ec", "swap_asym_class_secret_type"),
    ("ec", "missing_params"),
    ("ec", "missing_point"),
    ("pqc", "swap_secret_class_asym_type"),
    ("pqc", "swap_asym_class_secret_type"),
    ("pqc", "missing_params"),
)
UNWRAP_CELLS: tuple[tuple[str, str], ...] = (
    ("rsa", "swap_secret_class_asym_type"),
    ("rsa", "swap_asym_class_secret_type"),
    ("ec", "swap_secret_class_asym_type"),
    ("ec", "swap_asym_class_secret_type"),
    ("pqc", "swap_secret_class_asym_type"),
    ("pqc", "swap_asym_class_secret_type"),
)
GENERATE_CELLS: tuple[tuple[str, str], ...] = (
    ("rsa", "swap_secret_class_asym_type"),
    ("rsa", "swap_asym_class_secret_type"),
    ("rsa", "missing_modulus_bits"),
    ("ec", "swap_secret_class_asym_type"),
    ("ec", "swap_asym_class_secret_type"),
    ("ec", "missing_params"),
    ("pqc", "swap_secret_class_asym_type"),
    ("pqc", "swap_asym_class_secret_type"),
    ("pqc", "missing_params"),
)

#: QC4c nodes: one downstream sign leg per QC4b RSA Create malformation.
RSA_DOWNSTREAM_MALFORMATIONS: tuple[str, ...] = (
    "swap_secret_class_asym_type",
    "swap_asym_class_secret_type",
    "missing_modulus",
    "missing_exponent",
)

#: Normative ML-KEM-768 sizes (FIPS 203): ciphertext 1088 bytes, secret 32.
ML_KEM_768_CT_LEN = 1088
ML_KEM_768_SECRET_LEN = 32

#: Fixed known AES material shared by the QC4a symmetric legs.
QC4_AES_BASE = bytes(range(0x20, 0x30))
QC4_AES_PEER = bytes(range(0x40, 0x50))
QC4_DERIVE_DATA = b"qc4-derive-data!"
QC4_DERIVE_LEN = 16

#: Fixed sign/verify probe data for the QC4b/QC4c asymmetric use legs.
QC4_SIGN_DATA = b"qc4-sign-probe-data!"
#: Fixed 32-byte digest for the CKM_ECDSA legs: CKM_ECDSA signs the supplied
#: bytes as a digest WITHOUT hashing (PKCS#11 v3.2 §6.3.12), so the probe is
#: an independent fixed digest vector, pinned as a literal (deliberately NOT
#: Hash(QC4_SIGN_DATA): the raw signer signs these bytes directly). The SAME
#: bytes are supplied to the module and to the local Prehashed verifier (F2).
QC4_ECDSA_DIGEST = bytes.fromhex("b23b4b71d4b6f44daf325cb763d636b2728ba80749fd74b026ea9589982f42e5")
#: P-256 coordinate length; token-created ECDSA signatures are always exactly
#: twice this (PKCS#11 v3.2 §6.3.1: "the resulting signature is always of
#: length 2nLen").
P256_HALF_LEN = 32
ECDSA_P256_SIG_LEN = 64
QC4_RSA_BITS = 2048
QC4_P256_PARAMS = bytes.fromhex("06082a8648ce3d030107")


def row_by_key(key: str) -> PolicyFunctionRow:
    """Return the policy-function row for *key* (KeyError for unknown)."""
    return _ROWS_BY_KEY[key]


def _default_label_nonce() -> str:
    """Unique-per-call attempt-label nonce (F12; contracts inject a fixed one)."""
    return uuid.uuid4().hex[:8]


#: Nonce factory for malformed-attempt labels (F12): unique per call, so a
#: leaked object from an earlier run can never hide inside a later run's
#: inventory window. Contracts inject a fixed factory for determinism.
_LABEL_NONCE_FACTORY: Callable[[], str] = _default_label_nonce


def malformed_label(operation: str, family: str, malformation: str) -> str:
    """Inventory label for a QC4b malformed attempt (unique per call, F12)."""
    return f"qc4b-{operation}-{family}-{malformation}-{_LABEL_NONCE_FACTORY()}"


def control_label(operation: str, family: str, malformation: str) -> str:
    """Deterministic inventory label for a QC4b legal control."""
    return f"qc4b-{operation}-{family}-{malformation}-control"


def downstream_label(malformation: str) -> str:
    """Deterministic inventory label for a QC4c downstream attempt."""
    return f"qc4c-rsa-{malformation}"


@dataclass(frozen=True)
class PqcFamily:
    """The offered PQC family under test (ML-DSA first, SLH-DSA fallback)."""

    key: str
    key_type: int
    keygen_mech: int
    keygen_mech_name: str
    sign_mech: int
    sign_mech_name: str
    param_set: int


#: Fixed signature lengths per (key type, parameter set) (FIPS 204 for
#: ML-DSA; FIPS 205 SLH-DSA-SHA2-128s). Length is a property of the pair,
#: never of the bare CKP_* integer: the per-algorithm namespaces overlap
#: (CKP_ML_DSA_44 == CKP_SLH_DSA_SHA2_128S == 1), so an int-keyed map
#: silently deletes a length (N3). Gates pin a qualified set's length.
_PQC_SIG_LENS = {
    (int(CKK_ML_DSA), int(CKP_ML_DSA_44)): 2420,
    (int(CKK_ML_DSA), int(CKP_ML_DSA_65)): 3309,
    (int(CKK_ML_DSA), int(CKP_ML_DSA_87)): 4627,
    (int(CKK_SLH_DSA), int(CKP_SLH_DSA_SHA2_128S)): 7856,
}


_ML_DSA_FAMILY = PqcFamily(
    key="ml-dsa",
    key_type=int(CKK_ML_DSA),
    keygen_mech=int(CKM_ML_DSA_KEY_PAIR_GEN),
    keygen_mech_name="ML_DSA_KEY_PAIR_GEN",
    sign_mech=int(CKM_ML_DSA),
    sign_mech_name="ML_DSA",
    param_set=int(CKP_ML_DSA_65),
)
_SLH_DSA_FAMILY = PqcFamily(
    key="slh-dsa",
    key_type=int(CKK_SLH_DSA),
    keygen_mech=int(CKM_SLH_DSA_KEY_PAIR_GEN),
    keygen_mech_name="SLH_DSA_KEY_PAIR_GEN",
    sign_mech=int(CKM_SLH_DSA),
    sign_mech_name="SLH_DSA",
    param_set=int(CKP_SLH_DSA_SHA2_128S),
)


def resolve_pqc_family(rs: Any) -> PqcFamily:
    """Return the offered PQC family, or skip visibly when none is offered."""
    if rs.has_mechanism(_ML_DSA_FAMILY.keygen_mech_name):
        return _ML_DSA_FAMILY
    if rs.has_mechanism(_SLH_DSA_FAMILY.keygen_mech_name):
        return _SLH_DSA_FAMILY
    pytest.skip("no offered PQC family (neither ML-DSA nor SLH-DSA keygen advertised)")


# ---------------------------------------------------------------------------
# Shared verdict helpers
# ---------------------------------------------------------------------------


def void_qc4_setup_rv(
    rv: int,
    expected_rvs: Any,
    *,
    label: str,
    operation: str,
    kind: str = "policy",
    mechanism: str | None = None,
) -> NoReturn:
    """Void a leg on a raw-RV setup refusal (validity first, RV preserved)."""
    classify_rv_validity_or_none(rv, label=label, operation=operation, kind=kind)
    xfail_qc3_setup_refusal(
        CkrAssertionError(f"{label}: refused with {ckr_name(rv)}", rv),
        expected_rvs,
        label=label,
        operation=operation,
        kind=kind,
        mechanism=mechanism,
    )


def void_qc4_setup_exc(
    exc: CkrAssertionError,
    expected_rvs: Any,
    *,
    label: str,
    operation: str,
    kind: str = "policy",
    mechanism: str | None = None,
) -> NoReturn:
    """Void a leg on a recipe-raised setup refusal (validity first, RV preserved)."""
    classify_rv_validity_or_none(exc.rv, label=label, operation=operation, kind=kind)
    xfail_qc3_setup_refusal(
        exc, expected_rvs, label=label, operation=operation, kind=kind, mechanism=mechanism
    )


def read_constrained_claim(
    rs: Any,
    handle: int,
    *,
    label: str,
    operation: str,
    mechanism: int,
    expect_include: bool,
    spec_ref: str,
) -> list[int]:
    """Read the constrained key's list FIRST and prove the seeded premise.

    The list must be present, well-shaped, and include (or exclude) the
    mechanism under test exactly as seeded. Any mismatch voids the leg:
    a module that did not persist the seeded claim proves nothing about
    enforcement in either direction.
    """
    attrs = read_qc3_attributes(
        rs, handle, [int(CKA_ALLOWED_MECHANISMS)], label=label, premise=True, spec_ref=spec_ref
    )
    claimed = attr_or_record(
        attrs,
        CKA_ALLOWED_MECHANISMS,
        label=f"{label}: constrained claim readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    if claimed is MISSING_ATTRIBUTE:
        xfail_as(
            "not_operational",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            spec_ref=spec_ref,
            summary=(f"{label}: constrained key carries no readable claim; premise void"),
        )
    claimed = validate_qc3_shape(
        claimed,
        "mech_list",
        attr_name="CKA_ALLOWED_MECHANISMS",
        label=label,
        premise=True,
        spec_ref=spec_ref,
    )
    included = mechanism in claimed
    if included != expect_include:
        direction = "include" if expect_include else "exclude"
        xfail_as(
            "not_operational",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            spec_ref=spec_ref,
            summary=(
                f"{label}: constrained claim does not {direction} "
                f"{ckm_name(mechanism)} (reads back "
                f"{[ckm_name(entry) for entry in claimed]}); premise void"
            ),
            detail={"claimed": [ckm_name(entry) for entry in claimed]},
        )
    return list(claimed)


def _note_qc4_observation(description: str, reference: str) -> None:
    """Neutral compliance note for a QC4 auxiliary observation (F1).

    Mirrors Task 15's note-passed observations: evidence rides the compliance
    channel, never a classification record, so the leg's terminal verdict
    always decides the reported outcome. Attributed to the enclosing test,
    not this helper (same outward frame walk as the capability-claims note).
    """
    frame = inspect.currentframe()
    test_id = ""
    caller_qualname = ""
    probe = frame.f_back if frame is not None else None
    try:
        if probe is not None:
            caller_qualname = probe.f_code.co_qualname
        depth = 0
        while probe is not None and depth < 25:
            if probe.f_code.co_name.startswith("test_"):
                test_id = probe.f_code.co_qualname
                break
            probe = probe.f_back
            depth += 1
    finally:
        del frame
        del probe
    note(
        description,
        ComplianceLevel.STANDARD,
        reference=reference,
        test_id=test_id or caller_qualname,
    )


def _peer_refusal_suffix(attrs: Any) -> str:
    """Render the observed refusal CKR for a peer-claim note, if any."""
    ckr = refusal_rv_for(attrs, int(CKA_ALLOWED_MECHANISMS))
    return f" ({ckr_name(ckr)})" if ckr is not None else ""


def _raise_for_fresh_fail(record_count: int) -> None:
    """Fail loud on a contradiction recorded by the immediately preceding read.

    ``attr_or_record`` records a refusal-with-data as ``self_contradiction``
    (FAIL) yet returns ``MISSING_ATTRIBUTE`` like any other absence, so a
    MISSING arm must re-check the record stream. A proved module
    self-contradiction fails loud per framework doctrine (F9 fail-fast); it
    is never noted-and-passed. Fresh xfail records (a refused required
    component) stay in the stream for the report hook and do NOT raise here,
    so a later proved finding is never preempted by an early xfail terminal
    (F9 retention: the hook's fail-dominance keeps the FAIL verdict).
    """
    for fresh in get_records()[record_count:]:
        if fresh.outcome == "fail":
            raise_for_record(fresh)


def read_peer_claim(rs: Any, handle: int, *, label: str) -> list[str] | None:
    """Observe the peer/target key's allow-list without judging its content.

    Pure observation (F1): absence, refusal, and malformed shapes all yield
    None with a neutral compliance note; NO classification record is emitted,
    so the leg's terminal verdict decides the reported outcome. The leg
    carries the observation in its own evidence/detail
    (``peer_allowed_mechanisms``). Only mechanism names ride into evidence,
    never secret bytes. RV validity still applies (F13): an undefined RV on
    this auxiliary read is a metadata FAIL and a vendor RV a visible
    alternate xfail; standard refusals stay neutral. ``CKA_ALLOWED_MECHANISMS``
    is spec-optional (Table 26 row carries no MUST-specify markers -- the
    approved CKA_CHECK_VALUE precedent), so absence takes the
    guard-approved optional-absence hatch (silent MISSING). A proved module
    self-contradiction on this read (refusal-with-data) is RECORDED and
    fails loud (F9 fail-fast) -- never noted-and-passed.
    """
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [int(CKA_ALLOWED_MECHANISMS)])
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv,
            label=f"{label}: peer claim",
            operation="C_GetAttributeValue",
            kind="policy",
        )
        _note_qc4_observation(
            f"{label}: peer claim unreadable ({ckr_name(exc.rv)}); "
            "observation only, enforcement decided by the constrained key",
            "QC4a #56.1 peer observation",
        )
        return None
    record_count = len(get_records())
    claimed = attr_or_record(
        attrs,
        CKA_ALLOWED_MECHANISMS,
        label=f"{label}: peer claim",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
        # Guard-approved hatch pair (R1): CKA_ALLOWED_MECHANISMS is
        # spec-optional (Table 26, no MUST-specify markers; KCV precedent),
        # so a conformant absence stays silent (F1: no record, the leg
        # terminal decides). A refusal-with-data still takes the
        # contradiction arm and fails loud below.
        optional_if_absent=True,
    )
    if claimed is MISSING_ATTRIBUTE:
        # Refusal-with-data takes the hatch's contradiction arm: a proved
        # module self-contradiction fails loud per framework doctrine (F9
        # fail-fast); it is never noted-and-passed. Fresh xfail records
        # stay streamed for the report hook (see _raise_for_fresh_fail).
        _raise_for_fresh_fail(record_count)
        _note_qc4_observation(
            f"{label}: peer claim absent{_peer_refusal_suffix(attrs)}; "
            "observation only, enforcement decided by the constrained key",
            "QC4a #56.1 peer observation",
        )
        return None
    if not isinstance(claimed, list):
        _note_qc4_observation(
            f"{label}: peer claim absent{_peer_refusal_suffix(attrs)}; "
            "observation only, enforcement decided by the constrained key",
            "QC4a #56.1 peer observation",
        )
        return None
    if not all(isinstance(entry, int) and not isinstance(entry, bool) for entry in claimed):
        _note_qc4_observation(
            f"{label}: peer claim malformed; observation only, "
            "enforcement decided by the constrained key",
            "QC4a #56.1 peer observation",
        )
        return None
    return [ckm_name(entry) for entry in claimed]


def classify_excluded_refusal_rv(
    rv: int,
    *,
    label: str,
    operation: str,
    mechanism: str,
    spec_ref: str,
    detail: dict[str, Any] | None = None,
) -> None:
    """Negative oracle for an excluded mechanism: the policy singleton passes.

    Any other standard refusal xfails as an alternate/unproved outcome with
    the RV preserved, never "restriction effective".
    """
    if rv in POLICY_SHAPED_REFUSE_RVS:
        classify(
            "sanctioned_refusal",
            kind="policy",
            label=label,
            operation=operation,
            mechanism=mechanism,
            inherit_mechanism=False,
            actual=rv,
            expected=tuple(POLICY_SHAPED_REFUSE_RVS),
            spec_ref=spec_ref,
            summary=(
                f"{label}: excluded mechanism refused with {ckr_name(rv)} (restriction effective)"
            ),
            detail=detail,
        )
        return
    classify_rv_validity_or_none(
        rv, label=label, operation=operation, kind="policy", mechanism=mechanism
    )
    xfail_as(
        "nonspec_reject",
        kind="policy",
        label=label,
        operation=operation,
        mechanism=mechanism,
        inherit_mechanism=False,
        actual=rv,
        spec_ref=spec_ref,
        summary=(
            f"{label}: excluded mechanism refused with alternate {ckr_name(rv)}; "
            "restriction unproved"
        ),
        detail=detail,
    )


def classify_included_refusal_rv(
    rv: int,
    *,
    label: str,
    operation: str,
    mechanism: str,
    spec_ref: str,
) -> None:
    """An included mechanism refused where supported is a deviation, not a pass."""
    classify_rv_validity_or_none(
        rv, label=label, operation=operation, kind="policy", mechanism=mechanism
    )
    xfail_as(
        "honest_deviation",
        kind="policy",
        label=label,
        operation=operation,
        mechanism=mechanism,
        inherit_mechanism=False,
        actual=rv,
        spec_ref=spec_ref,
        summary=(
            f"{label}: included mechanism refused with {ckr_name(rv)} where the "
            "operation is otherwise supported (deviation, not a pass)"
        ),
    )


def emit_qc4_pass(
    *,
    label: str,
    operation: str,
    mechanism: str | None = None,
    spec_ref: str | None = None,
    summary: str,
    detail: dict[str, Any] | None = None,
    actual: Any = None,
    expected: Any = None,
) -> None:
    """Emit a pass record carrying the terminal evidence (lengths/names only)."""
    classify(
        "sanctioned_refusal",
        kind="policy",
        label=label,
        operation=operation,
        mechanism=mechanism,
        inherit_mechanism=False,
        actual=int(CKR_OK) if actual is None else actual,
        expected=expected,
        spec_ref=spec_ref,
        summary=summary,
        detail=detail,
    )


def check_ecb_use(
    rs: Any,
    handle: int,
    *,
    key_value: bytes | None,
    label: str,
    operation: str,
    use: str,
    spec_ref: str,
    control: bool = False,
) -> None:
    """Prove AES-ECB use of *handle*: oracle match plus decrypt round-trip.

    ``key_value`` is the known key material (None only where the material is
    genuinely unknowable; every QC4a caller knows it). Classic legs use the
    single-part recipes, message legs the message-based ones; the two are
    never merged. A missing message entry point skips (genuine capability
    absence); refused use leaves the accepted effect unproved (or voids a
    control leg, whose inconclusive support cannot admit the negative
    oracle); incoherent or oracle-divergent successful output fails crypto
    wrong_result on main and control legs alike (F5).
    """
    plaintext = PROBE_PLAINTEXT
    if use == "message":
        try:
            observed = message_encrypt(rs.raw, rs.sh, handle, CKM_AES_ECB, plaintext)
        except AttributeError:
            pytest.skip(f"{label}: C_MessageEncryptInit not exposed by the module")
        except CkrAssertionError as exc:
            if exc.rv == int(CKR_FUNCTION_NOT_SUPPORTED):
                pytest.skip(f"{label}: message encrypt not supported ({ckr_name(exc.rv)})")
            _refused_use_or_void_control(
                exc.rv,
                label=label,
                operation=operation,
                use_op="C_EncryptMessage",
                spec_ref=spec_ref,
                control=control,
            )
    else:
        try:
            observed = encrypt_single(rs.raw, rs.sh, handle, CKM_AES_ECB, plaintext)
        except CkrAssertionError as exc:
            _refused_use_or_void_control(
                exc.rv,
                label=label,
                operation=operation,
                use_op="C_Encrypt",
                spec_ref=spec_ref,
                control=control,
            )
    # Validate the encrypt output BEFORE feeding it into decrypt: a malformed
    # or oracle-divergent successful output is already a crypto wrong_result.
    _check_ecb_observed(
        observed,
        key_value=key_value,
        plaintext_len=len(plaintext),
        label=label,
        operation=operation,
        spec_ref=spec_ref,
    )
    if use == "message":
        try:
            round_trip = message_decrypt(rs.raw, rs.sh, handle, CKM_AES_ECB, observed)
        except AttributeError:
            pytest.skip(f"{label}: C_MessageDecryptInit not exposed by the module")
        except CkrAssertionError as exc:
            if exc.rv == int(CKR_FUNCTION_NOT_SUPPORTED):
                pytest.skip(f"{label}: message decrypt not supported ({ckr_name(exc.rv)})")
            _refused_use_or_void_control(
                exc.rv,
                label=label,
                operation=operation,
                use_op="C_DecryptMessage",
                spec_ref=spec_ref,
                control=control,
            )
    else:
        try:
            round_trip = decrypt_single(rs.raw, rs.sh, handle, CKM_AES_ECB, observed)
        except CkrAssertionError as exc:
            _refused_use_or_void_control(
                exc.rv,
                label=label,
                operation=operation,
                use_op="C_Decrypt",
                spec_ref=spec_ref,
                control=control,
            )
    if len(round_trip) != len(plaintext) or round_trip != plaintext:
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
                f"{label}: encrypt/decrypt incoherent "
                f"(round_trip_len={len(round_trip)}, expected {len(plaintext)}); "
                "crypto wrong_result"
            ),
            detail={
                "plaintext_len": len(plaintext),
                "round_trip_len": len(round_trip),
                "round_trip_matches": round_trip == plaintext,
            },
        )


def _check_ecb_observed(
    observed: bytes,
    *,
    key_value: bytes | None,
    plaintext_len: int,
    label: str,
    operation: str,
    spec_ref: str,
) -> None:
    """Validate a successful ECB output: shape first, then the known-key oracle."""
    if len(observed) != plaintext_len:
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
                f"(observed_len={len(observed)}, expected {plaintext_len}; "
                "AES-ECB preserves the input length, §6.10.4/Table 106); "
                "crypto wrong_result"
            ),
            detail={"observed_len": len(observed), "expected_len": plaintext_len},
        )
    if key_value is not None and observed != aes_ecb_encrypt(key_value, PROBE_PLAINTEXT):
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
                f"{label}: successful ECB output misses the local known-key oracle "
                f"(observed_len={len(observed)}); crypto wrong_result"
            ),
            detail={"observed_len": len(observed), "oracle_match": False},
        )


def _xfail_unproved_use(label: str, operation: str, spec_ref: str, use_rv: int) -> NoReturn:
    """Accepted effect with refused follow-on use: unproved, never passed/failed."""
    xfail_as(
        "honest_deviation",
        kind="policy",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=spec_ref,
        summary=(
            f"{label}: accepted but follow-on use refused with {ckr_name(use_rv)}; effect unproved"
        ),
        detail={"disposition": "unproved-effect", "use_rv": ckr_name(use_rv)},
    )


def _refused_use_or_void_control(
    use_rv: int,
    *,
    label: str,
    operation: str,
    use_op: str,
    spec_ref: str,
    control: bool,
) -> NoReturn:
    """Map a refused follow-on use: unproved on a main leg, void on a control.

    A main leg's accepted effect with refused use is unproved (F5 keeps the
    existing shape); a control's refused use voids the leg as setup, since
    inconclusive control support cannot admit the negative oracle. Validity
    adjudicates first on both paths.
    """
    if control:
        void_qc4_setup_rv(use_rv, (), label=label, operation=use_op)
    classify_rv_validity_or_none(use_rv, label=label, operation=use_op, kind="policy")
    _xfail_unproved_use(label, operation, spec_ref, use_rv)


def read_secret_or_unproved(
    rs: Any, handle: int, *, label: str, operation: str, spec_ref: str, control: bool = False
) -> bytes:
    """Read an accepted secret's value, or xfail the effect as unproved.

    A control leg voids instead (F5): an unreadable control secret leaves
    support inconclusive, so the negative oracle cannot be admitted.
    """
    attrs = read_qc3_attributes(
        rs, handle, [int(CKA_VALUE)], label=label, premise=control, spec_ref=spec_ref
    )
    value = attr_or_record(
        attrs,
        CKA_VALUE,
        label=f"{label}: secret readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    if value is MISSING_ATTRIBUTE or not isinstance(value, bytes):
        if control:
            xfail_as(
                "not_operational",
                kind="policy",
                label=f"{label}: secret readback",
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                spec_ref=spec_ref,
                summary=(f"{label}: control secret value is unreadable; support unproved"),
            )
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(f"{label}: accepted but the secret value is unreadable; effect unproved"),
            detail={"disposition": "unproved-effect"},
        )
    return value


def check_kem_secrets(
    first: bytes,
    second: bytes,
    *,
    label: str,
    operation: str,
    expected_len: int,
    spec_ref: str,
) -> None:
    """Both KEM sides must yield the identical non-empty expected-length secret."""
    if len(first) == expected_len and len(second) == expected_len and first == second:
        return
    fail_as(
        "wrong_result",
        kind="crypto",
        label=label,
        operation=operation,
        mechanism="CKM_ML_KEM",
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=spec_ref,
        summary=(
            f"{label}: KEM sides disagree "
            f"(first_len={len(first)}, second_len={len(second)}, "
            f"expected {expected_len}, match={first == second}); crypto wrong_result"
        ),
        detail={
            "first_len": len(first),
            "second_len": len(second),
            "expected_len": expected_len,
            "secrets_match": first == second,
        },
    )


# ---------------------------------------------------------------------------
# QC4a policy legs
# ---------------------------------------------------------------------------


def _import_constrained_aes(
    rs: Any,
    value: bytes,
    attrs: dict[Any, Any],
    *,
    label: str,
    operation: str,
    spec_ref: str,
) -> int:
    """Import a known AES setup key, voiding the leg on any clean refusal."""
    try:
        return import_secret_key(rs.raw, rs.sh, CKK_AES, value, attrs=attrs)
    except CkrAssertionError as exc:
        void_qc4_setup_exc(exc, (), label=label, operation=operation)


def _destroy_all(rs: Any, handles: Iterable[int | None]) -> list[BaseException]:
    """Attempt every owned destroy, collecting raw failures (F14).

    Each handle gets an independent attempt; a raising destroy never skips
    the rest. Handle identity is attached to each failure via ``add_note``.
    """
    errors: list[BaseException] = []
    for handle in handles:
        if not handle:
            continue
        try:
            destroy_quietly(rs.raw, rs.sh, handle)
        except BaseException as exc:
            exc.add_note(f"C_DestroyObject cleanup raised for owned handle {handle}")
            errors.append(exc)
    return errors


def _cleanup_owned(rs: Any, handles: Iterable[int | None]) -> None:
    """Finally-safe owned-handle cleanup (F14).

    With a primary exception in flight the primary is preserved exactly
    and each cleanup failure is attached to it as a note (never replacing
    it, never lost). Without a primary, a single cleanup failure raises
    as-is and several raise grouped.
    """
    errors = _destroy_all(rs, handles)
    if not errors:
        return
    pending = sys.exception()
    if pending is None:
        if len(errors) == 1:
            raise errors[0]
        raise BaseExceptionGroup("QC4 owned-handle cleanup failures", errors)
    for error in errors:
        pending.add_note(f"cleanup also raised {type(error).__name__}: {error}")


def _check_derived_value(value: bytes, *, label: str, spec_ref: str) -> None:
    """The derived value must match the local known-key ECB oracle.

    Shared by the main and control derive legs (F5): a mismatch fails
    crypto wrong_result on either path.
    """
    expected = aes_ecb_encrypt(QC4_AES_BASE, QC4_DERIVE_DATA)
    if len(value) != QC4_DERIVE_LEN or value != expected:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation="C_DeriveKey",
            mechanism="CKM_AES_ECB_ENCRYPT_DATA",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: derived value misses the local known-key oracle "
                f"(value_len={len(value)}, expected {QC4_DERIVE_LEN}); "
                "crypto wrong_result"
            ),
            detail={
                "value_len": len(value),
                "expected_len": QC4_DERIVE_LEN,
                "oracle_match": value == expected,
            },
        )


def _run_derive_policy_leg(rs: Any, leg: str, use: str) -> None:
    row = row_by_key("derive")
    label = f"C_DeriveKey ALLOWED_MECHANISMS {leg} ({use} use)"
    if not rs.has_mechanism("AES_ECB_ENCRYPT_DATA"):
        pytest.skip("CKM_AES_ECB_ENCRYPT_DATA not supported")
    if not rs.has_mechanism("AES_ECB"):
        pytest.skip("CKM_AES_ECB not supported")
    derive_mech = int(CKM_AES_ECB_ENCRYPT_DATA)
    excluded = leg == "excluded"
    base_attrs: dict[Any, Any] = {
        CKA_DERIVE: True,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_LABEL: f"qc4a-derive-{leg}-{use}-base",
        CKA_ALLOWED_MECHANISMS: [derive_mech] if not excluded else [int(CKM_AES_ECB)],
    }
    base = _import_constrained_aes(
        rs,
        QC4_AES_BASE,
        base_attrs,
        label=label,
        operation="C_CreateObject",
        spec_ref=row.citation,
    )
    control_attrs: dict[Any, Any] = {
        CKA_DERIVE: True,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_LABEL: f"qc4a-derive-{leg}-{use}-control",
    }
    if excluded:
        control_attrs[CKA_ALLOWED_MECHANISMS] = [derive_mech]
    control = 0
    try:
        control = _import_constrained_aes(
            rs,
            QC4_AES_BASE,
            control_attrs,
            label=label,
            operation="C_CreateObject",
            spec_ref=row.citation,
        )
        read_constrained_claim(
            rs,
            base,
            label=label,
            operation="C_DeriveKey",
            mechanism=derive_mech,
            expect_include=not excluded,
            spec_ref=row.citation,
        )
        if excluded:
            read_constrained_claim(
                rs,
                control,
                label=f"{label} control",
                operation="C_DeriveKey",
                mechanism=derive_mech,
                expect_include=True,
                spec_ref=row.citation,
            )
        mech_param = mech_string_data(CKM_AES_ECB_ENCRYPT_DATA, QC4_DERIVE_DATA)
        derive_template = {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_AES,
            CKA_VALUE_LEN: QC4_DERIVE_LEN,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_ENCRYPT: True,
            CKA_DECRYPT: True,
            CKA_LABEL: f"qc4a-derive-{leg}-{use}-control-derived",
        }
        try:
            control_derived = derive_key(
                rs.raw,
                rs.sh,
                control,
                CKM_AES_ECB_ENCRYPT_DATA,
                attrs=derive_template,
                mech_param=mech_param,
            )
        except CkrAssertionError as exc:
            void_qc4_setup_exc(
                exc,
                (),
                label=f"{label} control",
                operation="C_DeriveKey",
                mechanism="CKM_AES_ECB_ENCRYPT_DATA",
            )
        # F5: the control runs the SAME value/oracle/effect checks as the
        # main leg before its negative oracle is admitted.
        try:
            control_value = read_secret_or_unproved(
                rs,
                control_derived,
                label=f"{label} control",
                operation="C_DeriveKey",
                spec_ref=row.citation,
                control=True,
            )
            _check_derived_value(control_value, label=f"{label} control", spec_ref=row.citation)
            check_ecb_use(
                rs,
                control_derived,
                key_value=control_value,
                label=f"{label} control",
                operation="C_DeriveKey",
                use=use,
                spec_ref=row.citation,
                control=True,
            )
        finally:
            _cleanup_owned(rs, [control_derived])
        derive_template[CKA_LABEL] = f"qc4a-derive-{leg}-{use}-derived"
        try:
            derived = derive_key(
                rs.raw,
                rs.sh,
                base,
                CKM_AES_ECB_ENCRYPT_DATA,
                attrs=derive_template,
                mech_param=mech_param,
            )
        except CkrAssertionError as exc:
            if not excluded:
                classify_included_refusal_rv(
                    exc.rv,
                    label=label,
                    operation="C_DeriveKey",
                    mechanism="CKM_AES_ECB_ENCRYPT_DATA",
                    spec_ref=row.citation,
                )
                return
            classify_excluded_refusal_rv(
                exc.rv,
                label=label,
                operation="C_DeriveKey",
                mechanism="CKM_AES_ECB_ENCRYPT_DATA",
                spec_ref=row.citation,
            )
            return
        try:
            value = read_secret_or_unproved(
                rs, derived, label=label, operation="C_DeriveKey", spec_ref=row.citation
            )
            _check_derived_value(value, label=label, spec_ref=row.citation)
            check_ecb_use(
                rs,
                derived,
                key_value=value,
                label=label,
                operation="C_DeriveKey",
                use=use,
                spec_ref=row.citation,
            )
            if not excluded:
                emit_qc4_pass(
                    label=label,
                    operation="C_DeriveKey",
                    mechanism="CKM_AES_ECB_ENCRYPT_DATA",
                    spec_ref=row.citation,
                    summary=(
                        f"{label}: included mechanism completed; derived key "
                        "oracle-verified and round-tripped"
                    ),
                    detail={
                        "derived_len": len(value),
                        "oracle_match": True,
                        "round_trip": True,
                        "use": use,
                    },
                )
                return
            fail_as(
                "self_contradiction",
                kind="policy",
                label=label,
                operation="C_DeriveKey",
                mechanism="CKM_AES_ECB_ENCRYPT_DATA",
                inherit_mechanism=False,
                actual=int(CKR_OK),
                spec_ref=row.citation,
                summary=(
                    f"{label}: excluded mechanism completed and the derived key "
                    "was independently verified (policy bypass)"
                ),
                detail={
                    "derived_len": len(value),
                    "oracle_match": True,
                    "round_trip": True,
                    "use": use,
                },
            )
        finally:
            _cleanup_owned(rs, [derived])
    finally:
        _cleanup_owned(rs, [control, base])


def _run_wrap_policy_leg(rs: Any, leg: str, use: str) -> None:
    row = row_by_key("wrap")
    label = f"C_WrapKey ALLOWED_MECHANISMS {leg} ({use} use)"
    if not rs.has_mechanism("AES_KEY_WRAP"):
        pytest.skip("CKM_AES_KEY_WRAP not supported")
    if not rs.has_mechanism("AES_ECB"):
        pytest.skip("CKM_AES_ECB not supported")
    wrap_mech = int(CKM_AES_KEY_WRAP)
    excluded = leg == "excluded"
    kek_attrs: dict[Any, Any] = {
        CKA_WRAP: True,
        CKA_UNWRAP: True,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_LABEL: f"qc4a-wrap-{leg}-{use}-kek",
        CKA_ALLOWED_MECHANISMS: [wrap_mech] if not excluded else [int(CKM_AES_ECB)],
    }
    kek = _import_constrained_aes(
        rs,
        QC4_AES_BASE,
        kek_attrs,
        label=label,
        operation="C_CreateObject",
        spec_ref=row.citation,
    )
    target = 0
    control = 0
    try:
        target = _import_constrained_aes(
            rs,
            QC4_AES_PEER,
            {
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_LABEL: f"qc4a-wrap-{leg}-{use}-target",
            },
            label=label,
            operation="C_CreateObject",
            spec_ref=row.citation,
        )
        control_attrs: dict[Any, Any] = {
            CKA_WRAP: True,
            # F5: the control re-unwraps its own blob (same effect check as
            # the main leg), so it needs UNWRAP like the main KEK (F6-class).
            CKA_UNWRAP: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_LABEL: f"qc4a-wrap-{leg}-{use}-control",
        }
        if excluded:
            control_attrs[CKA_ALLOWED_MECHANISMS] = [wrap_mech]
        control = _import_constrained_aes(
            rs,
            QC4_AES_BASE,
            control_attrs,
            label=label,
            operation="C_CreateObject",
            spec_ref=row.citation,
        )
        read_constrained_claim(
            rs,
            kek,
            label=label,
            operation="C_WrapKey",
            mechanism=wrap_mech,
            expect_include=not excluded,
            spec_ref=row.citation,
        )
        if excluded:
            read_constrained_claim(
                rs,
                control,
                label=f"{label} control",
                operation="C_WrapKey",
                mechanism=wrap_mech,
                expect_include=True,
                spec_ref=row.citation,
            )
        peer_claim = read_peer_claim(rs, target, label=label)
        try:
            control_blob = wrap_key(rs.raw, rs.sh, control, target, CKM_AES_KEY_WRAP)
        except CkrAssertionError as exc:
            void_qc4_setup_exc(
                exc,
                (),
                label=f"{label} control",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
            )
        # F5: SAME blob/oracle/effect checks as the main leg before the
        # negative oracle is admitted; an unvalidated control blob voids.
        control_chain = validate_wrap_chain(
            control_blob,
            kek=QC4_AES_BASE,
            expected_key=QC4_AES_PEER,
            label=f"{label} control",
        )
        if not control_chain.validated:
            xfail_as(
                "not_operational",
                kind="policy",
                label=f"{label} control",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                inherit_mechanism=False,
                actual=int(CKR_OK),
                spec_ref=row.citation,
                summary=(
                    f"{label} control: wrap output fails the local KW oracle; support unproved"
                ),
                detail={"support": "unproved-control", **control_chain.evidence},
            )
        try:
            control_reunwrapped = unwrap_key(
                rs.raw,
                rs.sh,
                control,
                control_blob,
                CKM_AES_KEY_WRAP,
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                    CKA_LABEL: f"{label} control-reunwrapped",
                },
            )
        except CkrAssertionError as exc:
            void_qc4_setup_exc(
                exc,
                (),
                label=f"{label} control",
                operation="C_UnwrapKey",
                mechanism="CKM_AES_KEY_WRAP",
            )
        try:
            check_ecb_use(
                rs,
                control_reunwrapped,
                key_value=QC4_AES_PEER,
                label=f"{label} control",
                operation="C_WrapKey",
                use=use,
                spec_ref=row.citation,
                control=True,
            )
        finally:
            _cleanup_owned(rs, [control_reunwrapped])
        try:
            blob = wrap_key(rs.raw, rs.sh, kek, target, CKM_AES_KEY_WRAP)
        except CkrAssertionError as exc:
            if not excluded:
                classify_included_refusal_rv(
                    exc.rv,
                    label=label,
                    operation="C_WrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    spec_ref=row.citation,
                )
                return
            classify_excluded_refusal_rv(
                exc.rv,
                label=label,
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                spec_ref=row.citation,
                detail={"peer_allowed_mechanisms": peer_claim},
            )
            return
        _check_wrap_blob_and_reunwrap(
            rs,
            kek,
            blob,
            peer_claim=peer_claim,
            label=label,
            use=use,
            excluded=excluded,
            spec_ref=row.citation,
        )
    finally:
        _cleanup_owned(rs, [control, target, kek])


def _check_wrap_blob_and_reunwrap(
    rs: Any,
    kek: int,
    blob: bytes,
    *,
    peer_claim: list[str] | None,
    label: str,
    use: str,
    excluded: bool,
    spec_ref: str,
) -> None:
    """Effect leg for a completed wrap: local KW proof, re-unwrap, round-trip."""
    if not blob or len(blob) % 8 != 0:
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation="C_WrapKey",
            mechanism="CKM_AES_KEY_WRAP",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: accepted but the wrap blob is KW-malformed "
                f"(blob_len={len(blob)}); no normative output shape, effect unproved"
            ),
            detail={
                "disposition": "unproved-effect",
                "blob_len": len(blob),
                "peer_allowed_mechanisms": peer_claim,
            },
        )
    chain = validate_wrap_chain(blob, kek=QC4_AES_BASE, expected_key=QC4_AES_PEER, label=label)
    if not chain.validated:
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation="C_WrapKey",
            mechanism="CKM_AES_KEY_WRAP",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: accepted but the blob fails the local KW oracle; wrap effect unvalidated"
            ),
            detail={
                "disposition": "unproved-effect",
                "peer_allowed_mechanisms": peer_claim,
                **chain.evidence,
            },
        )
    if excluded and chain.validated:
        # F9: the bypass is PROVED by the local KW unwrap to the known
        # target material -- fail before any later fallible call (module
        # re-unwrap, round-trip) can downgrade it to unproved.
        fail_as(
            "self_contradiction",
            kind="policy",
            label=label,
            operation="C_WrapKey",
            mechanism="CKM_AES_KEY_WRAP",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: excluded wrap output locally unwraps to the known "
                "target material; policy bypass"
            ),
            detail={"bypass": "local-kw-unwrap", **chain.evidence},
        )
    try:
        unwrapped = unwrap_key(
            rs.raw,
            rs.sh,
            kek,
            blob,
            CKM_AES_KEY_WRAP,
            {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_AES,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_LABEL: f"{label}-reunwrapped",
            },
        )
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(exc.rv, label=label, operation="C_UnwrapKey", kind="policy")
        _xfail_unproved_use(label, "C_WrapKey", spec_ref, exc.rv)
    try:
        check_ecb_use(
            rs,
            unwrapped,
            key_value=QC4_AES_PEER,
            label=label,
            operation="C_WrapKey",
            use=use,
            spec_ref=spec_ref,
        )
        if not excluded:
            emit_qc4_pass(
                label=label,
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                spec_ref=spec_ref,
                summary=(
                    f"{label}: included mechanism completed; blob re-unwrapped and "
                    "the key oracle-verified and round-tripped"
                ),
                detail={
                    "blob_len": len(blob),
                    "oracle_match": True,
                    "round_trip": True,
                    "use": use,
                    "peer_allowed_mechanisms": peer_claim,
                },
            )
            return
        # Unreachable: an excluded leg with a validated chain fails before
        # the module re-unwrap (F9); anything else xfailed above.
    finally:
        _cleanup_owned(rs, [unwrapped])


def _run_unwrap_policy_leg(rs: Any, leg: str, use: str) -> None:
    row = row_by_key("unwrap")
    label = f"C_UnwrapKey ALLOWED_MECHANISMS {leg} ({use} use)"
    if not rs.has_mechanism("AES_KEY_WRAP"):
        pytest.skip("CKM_AES_KEY_WRAP not supported")
    if not rs.has_mechanism("AES_ECB"):
        pytest.skip("CKM_AES_ECB not supported")
    wrap_mech = int(CKM_AES_KEY_WRAP)
    excluded = leg == "excluded"
    wrapper = _import_constrained_aes(
        rs,
        QC4_AES_BASE,
        {
            CKA_WRAP: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_LABEL: f"qc4a-unwrap-{leg}-{use}-wrapper",
        },
        label=label,
        operation="C_CreateObject",
        spec_ref=row.citation,
    )
    target = 0
    constrained = 0
    control = 0
    try:
        target = _import_constrained_aes(
            rs,
            QC4_AES_PEER,
            {
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_LABEL: f"qc4a-unwrap-{leg}-{use}-target",
            },
            label=label,
            operation="C_CreateObject",
            spec_ref=row.citation,
        )
        try:
            blob = wrap_key(rs.raw, rs.sh, wrapper, target, CKM_AES_KEY_WRAP)
        except CkrAssertionError as exc:
            void_qc4_setup_exc(
                exc,
                (),
                label=f"{label} blob premise",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
            )
        constrained = _import_constrained_aes(
            rs,
            QC4_AES_BASE,
            {
                CKA_UNWRAP: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_LABEL: f"qc4a-unwrap-{leg}-{use}-constrained",
                CKA_ALLOWED_MECHANISMS: ([wrap_mech] if not excluded else [int(CKM_AES_ECB)]),
            },
            label=label,
            operation="C_CreateObject",
            spec_ref=row.citation,
        )
        control_attrs: dict[Any, Any] = {
            CKA_UNWRAP: True,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_LABEL: f"qc4a-unwrap-{leg}-{use}-control",
        }
        if excluded:
            control_attrs[CKA_ALLOWED_MECHANISMS] = [wrap_mech]
        control = _import_constrained_aes(
            rs,
            QC4_AES_BASE,
            control_attrs,
            label=label,
            operation="C_CreateObject",
            spec_ref=row.citation,
        )
        read_constrained_claim(
            rs,
            constrained,
            label=label,
            operation="C_UnwrapKey",
            mechanism=wrap_mech,
            expect_include=not excluded,
            spec_ref=row.citation,
        )
        if excluded:
            read_constrained_claim(
                rs,
                control,
                label=f"{label} control",
                operation="C_UnwrapKey",
                mechanism=wrap_mech,
                expect_include=True,
                spec_ref=row.citation,
            )
        peer_claim = read_peer_claim(rs, wrapper, label=label)
        unwrap_template = {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_AES,
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_ENCRYPT: True,
            CKA_DECRYPT: True,
            CKA_LABEL: f"qc4a-unwrap-{leg}-{use}-control-unwrapped",
        }
        try:
            control_unwrapped = unwrap_key(
                rs.raw, rs.sh, control, blob, CKM_AES_KEY_WRAP, unwrap_template
            )
        except CkrAssertionError as exc:
            void_qc4_setup_exc(
                exc,
                (),
                label=f"{label} control",
                operation="C_UnwrapKey",
                mechanism="CKM_AES_KEY_WRAP",
            )
        # F5: SAME oracle/effect check as the main leg before the negative
        # oracle is admitted.
        try:
            check_ecb_use(
                rs,
                control_unwrapped,
                key_value=QC4_AES_PEER,
                label=f"{label} control",
                operation="C_UnwrapKey",
                use=use,
                spec_ref=row.citation,
                control=True,
            )
        finally:
            _cleanup_owned(rs, [control_unwrapped])
        unwrap_template[CKA_LABEL] = f"qc4a-unwrap-{leg}-{use}-unwrapped"
        try:
            unwrapped = unwrap_key(
                rs.raw, rs.sh, constrained, blob, CKM_AES_KEY_WRAP, unwrap_template
            )
        except CkrAssertionError as exc:
            if not excluded:
                classify_included_refusal_rv(
                    exc.rv,
                    label=label,
                    operation="C_UnwrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    spec_ref=row.citation,
                )
                return
            classify_excluded_refusal_rv(
                exc.rv,
                label=label,
                operation="C_UnwrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                spec_ref=row.citation,
                detail={"peer_allowed_mechanisms": peer_claim},
            )
            return
        try:
            check_ecb_use(
                rs,
                unwrapped,
                key_value=QC4_AES_PEER,
                label=label,
                operation="C_UnwrapKey",
                use=use,
                spec_ref=row.citation,
            )
            if not excluded:
                emit_qc4_pass(
                    label=label,
                    operation="C_UnwrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    spec_ref=row.citation,
                    summary=(
                        f"{label}: included mechanism completed; unwrapped key "
                        "oracle-verified and round-tripped"
                    ),
                    detail={
                        "oracle_match": True,
                        "round_trip": True,
                        "use": use,
                        "peer_allowed_mechanisms": peer_claim,
                    },
                )
                return
            fail_as(
                "self_contradiction",
                kind="policy",
                label=label,
                operation="C_UnwrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                inherit_mechanism=False,
                actual=int(CKR_OK),
                spec_ref=row.citation,
                summary=(
                    f"{label}: excluded mechanism completed and the unwrapped key "
                    "was independently verified (policy bypass)"
                ),
                detail={
                    "oracle_match": True,
                    "round_trip": True,
                    "use": use,
                    "peer_allowed_mechanisms": peer_claim,
                },
            )
        finally:
            _cleanup_owned(rs, [unwrapped])
    finally:
        _cleanup_owned(rs, [control, constrained, target, wrapper])


def _generate_kem_pair(
    rs: Any,
    *,
    label: str,
    pub_list: list[int] | None,
    priv_list: list[int] | None,
    tag: str,
) -> tuple[int, int]:
    """Generate an ML-KEM-768 pair with pinned policy lists, or void setup.

    Delegates to the sanctioned ``test_ckr_kem._generate_ml_kem_keypair``
    (lazy import: that module imports this one for the QC4a node classes).
    """
    from pkcs11_check.testcases.ckr.test_ckr_kem import _generate_ml_kem_keypair

    try:
        return _generate_ml_kem_keypair(
            rs.raw, rs.sh, pub_list=pub_list, priv_list=priv_list, tag=tag
        )
    except CkrAssertionError as exc:
        void_qc4_setup_exc(
            exc,
            (),
            label=label,
            operation="C_GenerateKeyPair",
            mechanism="CKM_ML_KEM_KEY_PAIR_GEN",
        )


def _kem_secret_template(tag: str) -> dict[Any, Any]:
    return {
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_LABEL: tag,
    }


def _check_kem_ciphertext(ct: bytes, *, label: str, operation: str, spec_ref: str) -> None:
    """An ML-KEM-768 ciphertext is normatively 1088 bytes (FIPS 203)."""
    if len(ct) == ML_KEM_768_CT_LEN:
        return
    fail_as(
        "wrong_result",
        kind="crypto",
        label=label,
        operation=operation,
        mechanism="CKM_ML_KEM",
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=spec_ref,
        summary=(
            f"{label}: successful encapsulate returned a malformed ciphertext "
            f"(ct_len={len(ct)}, expected {ML_KEM_768_CT_LEN}); crypto wrong_result"
        ),
        detail={"ct_len": len(ct), "expected_ct_len": ML_KEM_768_CT_LEN},
    )


def _run_encapsulate_policy_leg(rs: Any, leg: str) -> None:
    row = row_by_key("encapsulate")
    label = f"C_EncapsulateKey ALLOWED_MECHANISMS {leg}"
    if not rs.has_mechanism("ML_KEM"):
        pytest.skip("CKM_ML_KEM not supported")
    if not rs.has_mechanism("ML_KEM_KEY_PAIR_GEN"):
        pytest.skip("CKM_ML_KEM_KEY_PAIR_GEN not supported")
    kem_mech = int(CKM_ML_KEM)
    excluded = leg == "excluded"
    other_list = [int(CKM_AES_ECB)]
    pub, priv = _generate_kem_pair(
        rs,
        label=label,
        pub_list=[kem_mech] if not excluded else other_list,
        priv_list=None,
        tag=f"qc4a-encaps-{leg}",
    )
    control_pub = 0
    control_priv = 0
    try:
        control_pub, control_priv = _generate_kem_pair(
            rs,
            label=f"{label} control",
            pub_list=[kem_mech] if excluded else None,
            priv_list=None,
            tag=f"qc4a-encaps-{leg}-control",
        )
        read_constrained_claim(
            rs,
            pub,
            label=label,
            operation="C_EncapsulateKey",
            mechanism=kem_mech,
            expect_include=not excluded,
            spec_ref=row.citation,
        )
        if excluded:
            read_constrained_claim(
                rs,
                control_pub,
                label=f"{label} control",
                operation="C_EncapsulateKey",
                mechanism=kem_mech,
                expect_include=True,
                spec_ref=row.citation,
            )
        peer_claim = read_peer_claim(rs, priv, label=label)
        try:
            control_secret, control_ct = encapsulate_key(
                rs.raw,
                rs.sh,
                control_pub,
                CKM_ML_KEM,
                _kem_secret_template(f"qc4a-encaps-{leg}-control-secret"),
            )
        except CkrAssertionError as exc:
            void_qc4_setup_exc(
                exc,
                (),
                label=f"{label} control",
                operation="C_EncapsulateKey",
                mechanism="CKM_ML_KEM",
            )
        # F5: SAME ciphertext/equality checks as the main leg before the
        # negative oracle is admitted.
        try:
            _check_kem_ciphertext(
                control_ct,
                label=f"{label} control",
                operation="C_EncapsulateKey",
                spec_ref=row.citation,
            )
            try:
                control_peer_secret = decapsulate_key(
                    rs.raw,
                    rs.sh,
                    control_priv,
                    CKM_ML_KEM,
                    control_ct,
                    _kem_secret_template(f"qc4a-encaps-{leg}-control-peer-secret"),
                )
            except CkrAssertionError as exc:
                void_qc4_setup_exc(
                    exc,
                    (),
                    label=f"{label} control",
                    operation="C_DecapsulateKey",
                    mechanism="CKM_ML_KEM",
                )
            try:
                control_first = read_secret_or_unproved(
                    rs,
                    control_secret,
                    label=f"{label} control",
                    operation="C_EncapsulateKey",
                    spec_ref=row.citation,
                    control=True,
                )
                control_second = read_secret_or_unproved(
                    rs,
                    control_peer_secret,
                    label=f"{label} control",
                    operation="C_EncapsulateKey",
                    spec_ref=row.citation,
                    control=True,
                )
                check_kem_secrets(
                    control_first,
                    control_second,
                    label=f"{label} control",
                    operation="C_EncapsulateKey",
                    expected_len=ML_KEM_768_SECRET_LEN,
                    spec_ref=row.citation,
                )
            finally:
                _cleanup_owned(rs, [control_peer_secret])
        finally:
            _cleanup_owned(rs, [control_secret])
        try:
            secret, ct = encapsulate_key(
                rs.raw,
                rs.sh,
                pub,
                CKM_ML_KEM,
                _kem_secret_template(f"qc4a-encaps-{leg}-secret"),
            )
        except CkrAssertionError as exc:
            if not excluded:
                classify_included_refusal_rv(
                    exc.rv,
                    label=label,
                    operation="C_EncapsulateKey",
                    mechanism="CKM_ML_KEM",
                    spec_ref=row.citation,
                )
                return
            classify_excluded_refusal_rv(
                exc.rv,
                label=label,
                operation="C_EncapsulateKey",
                mechanism="CKM_ML_KEM",
                spec_ref=row.citation,
                detail={"peer_allowed_mechanisms": peer_claim},
            )
            return
        try:
            _check_kem_ciphertext(
                ct, label=label, operation="C_EncapsulateKey", spec_ref=row.citation
            )
            try:
                peer_secret = decapsulate_key(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_ML_KEM,
                    ct,
                    _kem_secret_template(f"qc4a-encaps-{leg}-peer-secret"),
                )
            except CkrAssertionError as exc:
                classify_rv_validity_or_none(
                    exc.rv, label=label, operation="C_DecapsulateKey", kind="policy"
                )
                _xfail_unproved_use(label, "C_EncapsulateKey", row.citation, exc.rv)
            try:
                first = read_secret_or_unproved(
                    rs,
                    secret,
                    label=label,
                    operation="C_EncapsulateKey",
                    spec_ref=row.citation,
                )
                second = read_secret_or_unproved(
                    rs,
                    peer_secret,
                    label=label,
                    operation="C_EncapsulateKey",
                    spec_ref=row.citation,
                )
                check_kem_secrets(
                    first,
                    second,
                    label=label,
                    operation="C_EncapsulateKey",
                    expected_len=ML_KEM_768_SECRET_LEN,
                    spec_ref=row.citation,
                )
                if not excluded:
                    emit_qc4_pass(
                        label=label,
                        operation="C_EncapsulateKey",
                        mechanism="CKM_ML_KEM",
                        spec_ref=row.citation,
                        summary=(
                            f"{label}: included mechanism completed; both sides "
                            "yield the identical expected-length secret"
                        ),
                        detail={
                            "ct_len": len(ct),
                            "secret_len": len(first),
                            "secrets_match": True,
                            "peer_allowed_mechanisms": peer_claim,
                        },
                    )
                    return
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label=label,
                    operation="C_EncapsulateKey",
                    mechanism="CKM_ML_KEM",
                    inherit_mechanism=False,
                    actual=int(CKR_OK),
                    spec_ref=row.citation,
                    summary=(
                        f"{label}: excluded mechanism completed and both sides "
                        "yield the identical secret (policy bypass)"
                    ),
                    detail={
                        "ct_len": len(ct),
                        "secret_len": len(first),
                        "secrets_match": True,
                        "peer_allowed_mechanisms": peer_claim,
                    },
                )
            finally:
                _cleanup_owned(rs, [peer_secret])
        finally:
            _cleanup_owned(rs, [secret])
    finally:
        _cleanup_owned(rs, [control_pub, control_priv, pub, priv])


def _run_decapsulate_policy_leg(rs: Any, leg: str) -> None:
    row = row_by_key("decapsulate")
    label = f"C_DecapsulateKey ALLOWED_MECHANISMS {leg}"
    if not rs.has_mechanism("ML_KEM"):
        pytest.skip("CKM_ML_KEM not supported")
    if not rs.has_mechanism("ML_KEM_KEY_PAIR_GEN"):
        pytest.skip("CKM_ML_KEM_KEY_PAIR_GEN not supported")
    kem_mech = int(CKM_ML_KEM)
    excluded = leg == "excluded"
    other_list = [int(CKM_AES_ECB)]
    pub, priv = _generate_kem_pair(
        rs,
        label=label,
        pub_list=None,
        priv_list=[kem_mech] if not excluded else other_list,
        tag=f"qc4a-decaps-{leg}",
    )
    control_pub = 0
    control_priv = 0
    try:
        control_pub, control_priv = _generate_kem_pair(
            rs,
            label=f"{label} control",
            pub_list=None,
            priv_list=[kem_mech] if excluded else None,
            tag=f"qc4a-decaps-{leg}-control",
        )
        read_constrained_claim(
            rs,
            priv,
            label=label,
            operation="C_DecapsulateKey",
            mechanism=kem_mech,
            expect_include=not excluded,
            spec_ref=row.citation,
        )
        if excluded:
            read_constrained_claim(
                rs,
                control_priv,
                label=f"{label} control",
                operation="C_DecapsulateKey",
                mechanism=kem_mech,
                expect_include=True,
                spec_ref=row.citation,
            )
        peer_claim = read_peer_claim(rs, pub, label=label)
        try:
            premise_secret, premise_ct = encapsulate_key(
                rs.raw,
                rs.sh,
                pub,
                CKM_ML_KEM,
                _kem_secret_template(f"qc4a-decaps-{leg}-premise-secret"),
            )
        except CkrAssertionError as exc:
            void_qc4_setup_exc(
                exc,
                (),
                label=f"{label} ciphertext premise",
                operation="C_EncapsulateKey",
                mechanism="CKM_ML_KEM",
            )
        try:
            _check_kem_ciphertext(
                premise_ct, label=label, operation="C_EncapsulateKey", spec_ref=row.citation
            )
            try:
                control_enc_secret, control_ct = encapsulate_key(
                    rs.raw,
                    rs.sh,
                    control_pub,
                    CKM_ML_KEM,
                    _kem_secret_template(f"qc4a-decaps-{leg}-control-secret"),
                )
            except CkrAssertionError as exc:
                void_qc4_setup_exc(
                    exc,
                    (),
                    label=f"{label} control",
                    operation="C_EncapsulateKey",
                    mechanism="CKM_ML_KEM",
                )
            # F5: SAME ciphertext/equality checks as the main leg before the
            # negative oracle is admitted.
            try:
                _check_kem_ciphertext(
                    control_ct,
                    label=f"{label} control",
                    operation="C_EncapsulateKey",
                    spec_ref=row.citation,
                )
                try:
                    control_secret = decapsulate_key(
                        rs.raw,
                        rs.sh,
                        control_priv,
                        CKM_ML_KEM,
                        control_ct,
                        _kem_secret_template(f"qc4a-decaps-{leg}-control-decaps"),
                    )
                except CkrAssertionError as exc:
                    void_qc4_setup_exc(
                        exc,
                        (),
                        label=f"{label} control",
                        operation="C_DecapsulateKey",
                        mechanism="CKM_ML_KEM",
                    )
                try:
                    control_first = read_secret_or_unproved(
                        rs,
                        control_enc_secret,
                        label=f"{label} control",
                        operation="C_DecapsulateKey",
                        spec_ref=row.citation,
                        control=True,
                    )
                    control_second = read_secret_or_unproved(
                        rs,
                        control_secret,
                        label=f"{label} control",
                        operation="C_DecapsulateKey",
                        spec_ref=row.citation,
                        control=True,
                    )
                    check_kem_secrets(
                        control_first,
                        control_second,
                        label=f"{label} control",
                        operation="C_DecapsulateKey",
                        expected_len=ML_KEM_768_SECRET_LEN,
                        spec_ref=row.citation,
                    )
                finally:
                    _cleanup_owned(rs, [control_secret])
            finally:
                _cleanup_owned(rs, [control_enc_secret])
            try:
                secret = decapsulate_key(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_ML_KEM,
                    premise_ct,
                    _kem_secret_template(f"qc4a-decaps-{leg}-secret"),
                )
            except CkrAssertionError as exc:
                if not excluded:
                    classify_included_refusal_rv(
                        exc.rv,
                        label=label,
                        operation="C_DecapsulateKey",
                        mechanism="CKM_ML_KEM",
                        spec_ref=row.citation,
                    )
                    return
                classify_excluded_refusal_rv(
                    exc.rv,
                    label=label,
                    operation="C_DecapsulateKey",
                    mechanism="CKM_ML_KEM",
                    spec_ref=row.citation,
                    detail={"peer_allowed_mechanisms": peer_claim},
                )
                return
            try:
                first = read_secret_or_unproved(
                    rs,
                    premise_secret,
                    label=label,
                    operation="C_DecapsulateKey",
                    spec_ref=row.citation,
                )
                second = read_secret_or_unproved(
                    rs,
                    secret,
                    label=label,
                    operation="C_DecapsulateKey",
                    spec_ref=row.citation,
                )
                check_kem_secrets(
                    first,
                    second,
                    label=label,
                    operation="C_DecapsulateKey",
                    expected_len=ML_KEM_768_SECRET_LEN,
                    spec_ref=row.citation,
                )
                if not excluded:
                    emit_qc4_pass(
                        label=label,
                        operation="C_DecapsulateKey",
                        mechanism="CKM_ML_KEM",
                        spec_ref=row.citation,
                        summary=(
                            f"{label}: included mechanism completed; the secret "
                            "equals the encapsulate side byte-wise"
                        ),
                        detail={
                            "secret_len": len(first),
                            "secrets_match": True,
                            "peer_allowed_mechanisms": peer_claim,
                        },
                    )
                    return
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label=label,
                    operation="C_DecapsulateKey",
                    mechanism="CKM_ML_KEM",
                    inherit_mechanism=False,
                    actual=int(CKR_OK),
                    spec_ref=row.citation,
                    summary=(
                        f"{label}: excluded mechanism completed and the secret "
                        "equals the encapsulate side (policy bypass)"
                    ),
                    detail={
                        "secret_len": len(first),
                        "secrets_match": True,
                        "peer_allowed_mechanisms": peer_claim,
                    },
                )
            finally:
                _cleanup_owned(rs, [secret])
        finally:
            _cleanup_owned(rs, [premise_secret])
    finally:
        _cleanup_owned(rs, [control_pub, control_priv, pub, priv])


# ---------------------------------------------------------------------------
# QC4b malformed matrix
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _rsa2048_key() -> Any:
    return rsa.generate_private_key(public_exponent=65537, key_size=QC4_RSA_BITS)


@lru_cache(maxsize=1)
def _ec_p256_key() -> Any:
    return ec.generate_private_key(ec.SECP256R1())


def rsa2048_material() -> tuple[bytes, bytes, Any]:
    """Real RSA-2048 (modulus, exponent, private key) for valid peer material."""
    key = _rsa2048_key()
    numbers = key.public_key().public_numbers()
    modulus = int(numbers.n).to_bytes(256, "big")
    exp_int = int(numbers.e)
    exponent = exp_int.to_bytes((exp_int.bit_length() + 7) // 8, "big")
    return modulus, exponent, key


def ec_p256_material() -> tuple[bytes, bytes, Any]:
    """Real P-256 (params DER, point DER, private key) for valid peer material."""
    key = _ec_p256_key()
    numbers = key.public_key().public_numbers()
    raw = b"\x04" + int(numbers.x).to_bytes(32, "big") + int(numbers.y).to_bytes(32, "big")
    point_der = b"\x04\x41" + raw
    return QC4_P256_PARAMS, point_der, key


def _parse_ec_point(point_der: bytes) -> tuple[int, int] | None:
    """Parse a DER OCTET STRING wrapped uncompressed P-256 point, or None."""
    if len(point_der) < 2 or point_der[0] != 0x04:
        return None
    length = point_der[1]
    offset = 2
    if length & 0x80:
        size_len = length & 0x7F
        if size_len == 0 or len(point_der) < 2 + size_len:
            return None
        length = int.from_bytes(point_der[2 : 2 + size_len], "big")
        offset = 2 + size_len
    raw = point_der[offset : offset + length]
    if len(raw) != 65 or raw[0] != 0x04:
        return None
    return int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:65], "big")


_CLASS_NAMES = {
    int(CKO_SECRET_KEY): "CKO_SECRET_KEY",
    int(CKO_PUBLIC_KEY): "CKO_PUBLIC_KEY",
    int(CKO_PRIVATE_KEY): "CKO_PRIVATE_KEY",
}
_TYPE_NAMES = {
    int(CKK_RSA): "CKK_RSA",
    int(CKK_EC): "CKK_EC",
    int(CKK_AES): "CKK_AES",
    int(CKK_GENERIC_SECRET): "CKK_GENERIC_SECRET",
    int(CKK_ML_DSA): "CKK_ML_DSA",
    int(CKK_SLH_DSA): "CKK_SLH_DSA",
}

_ASYMMETRIC_TYPES = frozenset(
    {
        int(CKK_RSA),
        int(CKK_EC),
        int(CKK_ML_DSA),
        int(CKK_SLH_DSA),
    }
)
_SECRET_TYPES = frozenset({int(CKK_AES), int(CKK_GENERIC_SECRET)})


def _identity_malformed(obj_class: int, key_type: int) -> bool:
    """True for secret-class/asymmetric-type or asymmetric-class/secret-type."""
    if obj_class == int(CKO_SECRET_KEY) and key_type in _ASYMMETRIC_TYPES:
        return True
    if obj_class in (int(CKO_PUBLIC_KEY), int(CKO_PRIVATE_KEY)):
        return key_type in _SECRET_TYPES
    return False


def _contradicts(use_kind: str, readback: tuple[int, int], pqc_type: int = 0) -> bool:
    """True when a coherent *use_kind* contradicts the readback identity."""
    obj_class, key_type = readback
    if use_kind == "aes":
        return not (
            obj_class == int(CKO_SECRET_KEY) and key_type in (int(CKK_AES), int(CKK_GENERIC_SECRET))
        )
    if use_kind == "rsa_encrypt":
        return not (
            key_type == int(CKK_RSA) and obj_class in (int(CKO_PUBLIC_KEY), int(CKO_PRIVATE_KEY))
        )
    if use_kind == "rsa_sign":
        return not (obj_class == int(CKO_PRIVATE_KEY) and key_type == int(CKK_RSA))
    if use_kind == "ec_sign":
        return not (obj_class == int(CKO_PRIVATE_KEY) and key_type == int(CKK_EC))
    if use_kind == "ec_verify":
        return not (obj_class == int(CKO_PUBLIC_KEY) and key_type == int(CKK_EC))
    if use_kind == "pqc_verify":
        return not (obj_class == int(CKO_PUBLIC_KEY) and key_type == pqc_type)
    if use_kind == "pqc_sign":
        return not (obj_class == int(CKO_PRIVATE_KEY) and key_type == pqc_type)
    return False


@dataclass
class _UseOutcome:
    """One acceptance use-leg result (refusals ride as RV names, never bytes)."""

    coherent: bool = False
    use_kind: str = ""
    failable: bool = True
    unverifiable: bool = False
    attempted: bool = False
    rvs: list[str] | None = None
    #: Identity of the half that performed THIS use (F10); None defaults to
    #: the admitted readback at adjudication (single-handle paths).
    performer: tuple[int, int] | None = None
    #: Performing handle, for evidence (F10).
    handle: int | None = None

    def __post_init__(self) -> None:
        if self.rvs is None:
            self.rvs = []


def _adjudicate_uses(
    outcomes: list[_UseOutcome],
    *,
    readback: tuple[int, int],
    requested: tuple[int, int],
    pqc_type: int,
    label: str,
    operation: str,
    spec_ref: str,
) -> None:
    """Terminal verdict for an accepted malformed object.

    FAIL fires only on a proved contradiction attributed to the PERFORMER
    (F10): a failable coherent use whose own performing identity is
    malformed, or whose use contradicts the performer's identity
    (cross-type use). A malformed sibling that never acted indicts
    nothing. Everything else xfails with full evidence:
    coherent-but-consistent acceptance, unverifiable success, or
    inspected-and-unusable material. Never a quiet pass, never unproved FAIL.
    """
    readback_names = (
        _CLASS_NAMES.get(readback[0], hex(readback[0])),
        _TYPE_NAMES.get(readback[1], hex(readback[1])),
    )
    use_rvs: list[str] = []
    for outcome in outcomes:
        use_rvs.extend(outcome.rvs or [])
    coherent = [outcome for outcome in outcomes if outcome.coherent]
    for outcome in coherent:
        if not outcome.failable:
            continue
        acting = outcome.performer if outcome.performer is not None else readback
        acting_names = (
            _CLASS_NAMES.get(acting[0], hex(acting[0])),
            _TYPE_NAMES.get(acting[1], hex(acting[1])),
        )
        if _identity_malformed(*acting) or _contradicts(outcome.use_kind, acting, pqc_type):
            fail_as(
                "self_contradiction",
                kind="policy",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=int(CKR_OK),
                spec_ref=spec_ref,
                summary=(
                    f"{label}: proved usable material under a malformed identity "
                    f"(cross-type {outcome.use_kind} use by "
                    f"{acting_names[0]}/{acting_names[1]})"
                ),
                detail={
                    "coherent_use": outcome.use_kind,
                    "performer_class": acting_names[0],
                    "performer_type": acting_names[1],
                    "performer_handle": outcome.handle,
                    "readback_class": readback_names[0],
                    "readback_type": readback_names[1],
                    "identity_kept": readback == requested,
                    "use_rvs": use_rvs,
                },
            )
    if coherent:
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: accepted malformed template but produced coherent use "
                f"under {readback_names[0]}/{readback_names[1]} "
                "(accepted-coherent deviation)"
            ),
            detail={
                "disposition": "accepted-coherent",
                "coherent_uses": [outcome.use_kind for outcome in coherent],
                "readback_class": readback_names[0],
                "readback_type": readback_names[1],
                "identity_kept": readback == requested,
                "use_rvs": use_rvs,
            },
        )
    if any(outcome.unverifiable for outcome in outcomes):
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: accepted malformed template with successful but "
                "unverifiable use; contradiction unproved"
            ),
            detail={
                "disposition": "unproved-effect",
                "readback_class": readback_names[0],
                "readback_type": readback_names[1],
                "identity_kept": readback == requested,
                "use_rvs": use_rvs,
            },
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
            f"{label}: accepted malformed template; material inspected and "
            f"unusable under {readback_names[0]}/{readback_names[1]}"
        ),
        detail={
            "disposition": "inspected-unusable",
            "readback_class": readback_names[0],
            "readback_type": readback_names[1],
            "identity_kept": readback == requested,
            "use_attempted": any(outcome.attempted for outcome in outcomes),
            "use_rvs": use_rvs,
        },
    )


#: Find batch size for label inventories; exhaustion is an EMPTY page only
#: (§5.7.8: ulMaxObjectCount is a maximum, never an exhaustion signal).
_FIND_PAGE_SIZE = 256


def _find_by_label(rs: Any, label: str) -> list[int]:
    """Inventory ALL objects carrying *label* (raises CkrAssertionError on refusal).

    Loops Find batches until an empty page (F12/N6): a provider may
    return fewer handles than requested at any point (§5.7.8), so a
    short nonempty page proves nothing about what follows it.
    Finalizes the search on both success and failure paths (mirroring
    the recipe's cleanup).
    """
    tmpl = template(attr_bytes(CKA_LABEL, label.encode("utf-8")))
    rv = rs.raw.C_FindObjectsInit(rs.sh, tmpl.ptr, tmpl.count)
    expect_rv(rv, CKR_OK)
    out: list[int] = []
    try:
        while True:
            handles = (CK_OBJECT_HANDLE * _FIND_PAGE_SIZE)()
            found = CK_ULONG(0)
            rv = rs.raw.C_FindObjects(rs.sh, handles, _FIND_PAGE_SIZE, byref(found))
            expect_rv(rv, CKR_OK)
            count = int(found.value)
            out.extend(int(handles[i]) for i in range(count))
            if count == 0:
                break
    except BaseException:
        try:
            rs.raw.C_FindObjectsFinal(rs.sh)
        except AttributeError:
            pass
        raise
    rv = rs.raw.C_FindObjectsFinal(rs.sh)
    expect_rv(rv, CKR_OK)
    return out


def _record_rv_validity(
    rv: int,
    *,
    label: str,
    operation: str,
    kind: str | None = None,
    mechanism: str | None = None,
) -> Any | None:
    """Non-raising twin of ``classify_rv_validity_or_none`` (N7).

    Mirrors the shared helper's reason/kind mapping exactly (vendor ->
    ``nonspec_reject``, undefined -> ``self_contradiction``/metadata,
    same summaries) but RECORDS without terminating, so the caller can
    run unconditional follow-up work (leak inventory and cleanup) and
    then terminate with the strongest retained outcome. A standard RV
    records nothing and returns None.
    """
    if is_standard_ckr(rv):
        return None
    if is_vendor_defined_ckr(rv):
        return record_as(
            "nonspec_reject",
            kind=kind,
            label=label,
            operation=operation,
            mechanism=mechanism,
            inherit_mechanism=False,
            actual=rv,
            summary=(
                f"{label}: refused with vendor-defined {ckr_name(rv)} "
                "(alternate refusal; standard outcome unproved)"
            ),
            detail={"refusal_rv": ckr_name(rv)},
        )
    return record_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation=operation,
        mechanism=mechanism,
        inherit_mechanism=False,
        actual=rv,
        summary=(
            f"{label}: refused with undefined {ckr_name(rv)} (return-value contract violation)"
        ),
        detail={"refusal_rv": ckr_name(rv)},
    )


def _strongest_record(records: list[Any]) -> Any:
    """The strongest retained outcome: first FAIL, else first xfail (N7)."""
    for record in records:
        if record.outcome == "fail":
            return record
    return records[0]


def _adjudicate_malformed_refusal(
    rs: Any,
    rv: int,
    *,
    label: str,
    operation: str,
    attempt_label: str,
    before: list[int],
    spec_ref: str,
) -> None:
    """Rejection leg: record validity, inventory, terminate strongest (N7).

    The refusal RV's validity defect (undefined/vendor) is RECORDED FIRST
    without terminating and retained even if the later inventory leg
    fails (F9/F13 ordering). The zero-delta inventory and any leak
    cleanup then run for EVERY refusal RV, standard or not (§5.7.1 /
    §5.18.4 / §5.18.2: a refused creation must create nothing).
    Termination raises for the strongest retained record; only a
    standard refusal with a proved zero delta reaches the pass.
    """
    retained = _record_rv_validity(rv, label=label, operation=operation, kind="policy")
    try:
        after = _find_by_label(rs, attempt_label)
    except CkrAssertionError as exc:
        inventory_retained = _record_rv_validity(
            exc.rv, label=f"{label}: inventory", operation="C_FindObjects", kind="policy"
        )
        candidates = [rec for rec in (retained, inventory_retained) if rec is not None]
        if candidates:
            strongest = _strongest_record(candidates)
            detail = strongest.detail if isinstance(strongest.detail, dict) else {}
            detail.setdefault("refusal_rv", ckr_name(rv))
            detail["inventory_rv"] = ckr_name(exc.rv)
            strongest.detail = detail
            raise_for_record(strongest)
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=rv,
            spec_ref=spec_ref,
            summary=(
                f"{label}: refused with {ckr_name(rv)} but the leak inventory "
                f"failed with {ckr_name(exc.rv)}; zero-delta unproved"
            ),
            detail={
                "disposition": "unproved-effect",
                "refusal_rv": ckr_name(rv),
                "inventory_rv": ckr_name(exc.rv),
            },
        )
    before_set = set(before)
    leaked = [handle for handle in after if handle not in before_set]
    if leaked:
        # F14: the established contradiction is RECORDED BEFORE cleanup
        # runs (leak evidence first, then destroy); a destroy failure is
        # attached to the terminal but never replaces it.
        record = record_as(
            "self_contradiction",
            kind="lifecycle",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=rv,
            spec_ref=spec_ref,
            summary=(
                f"{label}: refused with {ckr_name(rv)} yet {len(leaked)} labeled "
                "object(s) appeared (leaked object)"
            ),
            detail={"leaked_count": len(leaked), "refusal_rv": ckr_name(rv)},
        )
        errors = _destroy_all(rs, leaked)
        try:
            raise_for_record(record)
        except BaseException as terminal:
            for error in errors:
                terminal.add_note(f"cleanup also raised {type(error).__name__}: {error}")
            raise
    if retained is not None:
        # N7 trap: a retained validity defect already decided this leg's
        # terminal. Emitting the zero-delta pass here would launder a
        # nonstandard refusal into a proved-clean rejection (F1 flip).
        # The proved zero delta rides in the retained record's detail.
        detail = retained.detail if isinstance(retained.detail, dict) else {}
        detail.setdefault("refusal_rv", ckr_name(rv))
        detail["inventory_delta"] = 0
        retained.detail = detail
        raise_for_record(retained)
    emit_qc4_pass(
        label=label,
        operation=operation,
        spec_ref=spec_ref,
        summary=(
            f"{label}: malformed template refused with {ckr_name(rv)}; zero inventory delta proved"
        ),
        detail={"refusal_rv": ckr_name(rv), "inventory_delta": 0},
        actual=rv,
    )


def _inspect_identity(
    rs: Any, handle: int, *, label: str, operation: str, spec_ref: str
) -> tuple[int, int]:
    """Read back an admitted object's class/type, or xfail the effect unproved."""
    attrs = read_qc3_attributes(
        rs,
        handle,
        [int(CKA_CLASS), int(CKA_KEY_TYPE)],
        label=label,
        premise=False,
        spec_ref=spec_ref,
    )
    obj_class = attr_or_record(
        attrs,
        CKA_CLASS,
        label=f"{label}: class readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    key_type = attr_or_record(
        attrs,
        CKA_KEY_TYPE,
        label=f"{label}: type readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    if obj_class is MISSING_ATTRIBUTE or key_type is MISSING_ATTRIBUTE:
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: accepted but the class/type identity is unreadable; effect unproved"
            ),
            detail={"disposition": "unproved-effect"},
        )
    obj_class = validate_qc3_shape(
        obj_class,
        "ulong",
        attr_name="CKA_CLASS",
        label=label,
        premise=False,
        spec_ref=spec_ref,
    )
    key_type = validate_qc3_shape(
        key_type,
        "ulong",
        attr_name="CKA_KEY_TYPE",
        label=label,
        premise=False,
        spec_ref=spec_ref,
    )
    return obj_class, key_type


def _read_optional_bytes(
    rs: Any, handle: int, attr: int, *, label: str, operation: str, spec_ref: str
) -> bytes | None:
    """Read one key component; absence yields None plus a not_operational record.

    Key components are REQUIRED, not spec-optional, so the optional-absence
    hatch is semantically unavailable here (its docstring forbids it): a
    plain ``attr_or_record`` records absence honestly as ``not_operational``.
    Component readback must not terminate acceptance adjudication (F9/N1):
    an already-witnessed use (e.g. a coherent AES type-confusion) FAILs on
    its own evidence even when a later component read refuses. RV validity
    still fails undefined and xfails vendor on the raising path. A proved
    module self-contradiction (refusal-with-data) fails loud (F9 fail-fast)
    -- never noted-and-passed.

    Corrected caller audit (N8; supersedes the rejected R2 blanket claim
    that no None-path reaches PASS or FAIL -- independent findings DO
    survive a None, and that is intentional). Per caller class:
    (a) Judgments that REQUIRE the missing component void to unproved:
    RSA Create missing_exponent and QC4c lose their oracle (unverifiable
    / explicit unproved-effect xfail; their FAILs require readable
    halves); Unwrap RSA/EC verify ONLY under admitted halves -- missing
    or partial halves yield no oracle and stay unproved (source
    substitution deleted in N8); Generate pub-half rebuilds (RSA
    private components, EC scalar) leave that half unverified.
    (b) Gates a None skips without failing: EC with ``params=None``
    skips the P-256 length gate and an invalid signature stays
    unverifiable (curve unproved); the scalar/point and RSA
    halves-mismatch FAILs require every compared component readable.
    (c) Independent prior witnesses a None does NOT void: generated
    RSA/EC keep a coherent priv-half Sign witnessed BEFORE a
    private-component/scalar absence, and Create keeps a witnessed
    coherent use via the N1 fail-fast -- those adjudicate (and can
    FAIL) on their own evidence. No acceptance leg PASSes on a
    component (adjudication is fail-or-xfail only).
    """
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [int(attr)])
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv, label=label, operation="C_GetAttributeValue", kind="policy"
        )
        _note_qc4_observation(
            f"{label}: component read refused ({ckr_name(exc.rv)}); "
            "treated as unknown for adjudication",
            "QC4b #57.1 component readback",
        )
        return None
    record_count = len(get_records())
    value = attr_or_record(
        attrs,
        attr,
        label=f"{label}: component readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    if value is MISSING_ATTRIBUTE:
        # Refusal-with-data is RECORDED by the plain call above: a proved
        # module self-contradiction fails loud per framework doctrine (F9
        # fail-fast); it is never noted-and-passed. Other absences record
        # not_operational and stay streamed for the report hook.
        _raise_for_fresh_fail(record_count)
        _note_qc4_observation(
            f"{label}: component readback absent; treated as unknown for adjudication",
            "QC4b #57.1 component readback",
        )
        return None
    if not isinstance(value, bytes) or not value:
        return None
    return value


def _read_rsa_halves(
    rs: Any, handle: int, *, label: str, operation: str, spec_ref: str
) -> tuple[bytes | None, bytes | None]:
    modulus = _read_optional_bytes(
        rs, handle, int(CKA_MODULUS), label=label, operation=operation, spec_ref=spec_ref
    )
    exponent = _read_optional_bytes(
        rs,
        handle,
        int(CKA_PUBLIC_EXPONENT),
        label=label,
        operation=operation,
        spec_ref=spec_ref,
    )
    return modulus, exponent


def _read_ec_halves(
    rs: Any, handle: int, *, label: str, operation: str, spec_ref: str
) -> tuple[bytes | None, tuple[int, int] | None]:
    params = _read_optional_bytes(
        rs, handle, int(CKA_EC_PARAMS), label=label, operation=operation, spec_ref=spec_ref
    )
    point_der = _read_optional_bytes(
        rs, handle, int(CKA_EC_POINT), label=label, operation=operation, spec_ref=spec_ref
    )
    point = _parse_ec_point(point_der) if point_der is not None else None
    return params, point


def _use_aes_oracle(
    rs: Any,
    handle: int,
    *,
    key_bytes: bytes,
    label: str,
    operation: str,
    spec_ref: str,
) -> _UseOutcome:
    """Probe AES-ECB use of an admitted object against the local oracle."""
    outcome = _UseOutcome(use_kind="aes", attempted=True, rvs=[])
    assert outcome.rvs is not None
    try:
        observed = encrypt_single(rs.raw, rs.sh, handle, CKM_AES_ECB, PROBE_PLAINTEXT)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(exc.rv, label=label, operation="C_Encrypt", kind="policy")
        outcome.rvs.append(ckr_name(exc.rv))
        return outcome
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
                f"{label}: successful ECB use of the admitted object is malformed "
                f"(observed_len={len(observed)}); crypto wrong_result"
            ),
            detail={"observed_len": len(observed)},
        )
    if observed != aes_ecb_encrypt(key_bytes, PROBE_PLAINTEXT):
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
                f"{label}: successful ECB use of the admitted object misses the "
                "local known-key oracle; crypto wrong_result"
            ),
            detail={"oracle_match": False},
        )
    outcome.coherent = True
    return outcome


def _rsa_oracle_for_admitted(
    known_priv: Any, admitted: tuple[bytes | None, bytes | None]
) -> Any | None:
    """Build the decrypt oracle for the ADMITTED halves, or None (F3).

    Verification runs ONLY under the admitted public-key oracle: the
    admitted modulus/exponent are read from the admitted object itself, and
    the decrypting private half is the known key when the halves match it,
    or is re-derived from the known primes when only the exponent differs
    (same modulus). A foreign modulus, an unreadable half, or an
    exponent with no inverse yields None: the ciphertext cannot be
    interpreted and the use stays unproved, never wrong_result.
    """
    modulus, exponent = admitted
    if not modulus or not exponent:
        return None
    numbers = known_priv.private_numbers()
    ours_n = int(numbers.public_numbers.n)
    ours_e = int(numbers.public_numbers.e)
    admitted_n = int.from_bytes(modulus, "big")
    admitted_e = int.from_bytes(exponent, "big")
    if admitted_n == ours_n and admitted_e == ours_e:
        return known_priv
    if admitted_n != ours_n:
        return None
    try:
        return _rsa_priv_for_exponent(numbers, admitted_e)
    except ValueError:
        return None


def _rsa_priv_from_components(
    modulus: bytes | None,
    exponent: bytes | None,
    private_exponent: bytes | None,
    prime_1: bytes | None,
    prime_2: bytes | None,
    exponent_1: bytes | None,
    exponent_2: bytes | None,
    coefficient: bytes | None,
) -> Any | None:
    """Rebuild an RSA private key from read-back components, or None (F10).

    Lets a generated public half be exercised independently (encrypt with
    the pub half, decrypt locally): the private components come from the
    generated priv half, which the legs request extractable. Any missing
    or inconsistent component yields None (unwitnessable, never wrong).
    """
    parts = (modulus, exponent, private_exponent, prime_1, prime_2, exponent_1, exponent_2)
    if any(part is None or not part for part in (*parts, coefficient)):
        return None
    assert modulus is not None and exponent is not None
    assert private_exponent is not None and prime_1 is not None and prime_2 is not None
    assert exponent_1 is not None and exponent_2 is not None and coefficient is not None
    try:
        return rsa.RSAPrivateNumbers(
            int.from_bytes(prime_1, "big"),
            int.from_bytes(prime_2, "big"),
            int.from_bytes(private_exponent, "big"),
            int.from_bytes(exponent_1, "big"),
            int.from_bytes(exponent_2, "big"),
            int.from_bytes(coefficient, "big"),
            rsa.RSAPublicNumbers(int.from_bytes(exponent, "big"), int.from_bytes(modulus, "big")),
        ).private_key()
    except ValueError:
        return None


def _ec_priv_from_scalar(scalar: bytes | None) -> Any | None:
    """Rebuild a P-256 private key from a read-back scalar, or None (F10)."""
    if not scalar:
        return None
    try:
        return ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())
    except ValueError:
        return None


def _rsa_priv_for_exponent(priv_numbers: Any, exponent: int) -> Any:
    """Re-derive the private half for (*known n*, *admitted e*) from (p, q)."""
    from math import gcd

    p = int(priv_numbers.p)
    q = int(priv_numbers.q)
    lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
    d = pow(exponent, -1, lam)
    rebuilt = rsa.RSAPrivateNumbers(
        p,
        q,
        d,
        d % (p - 1),
        d % (q - 1),
        pow(q, -1, p),
        rsa.RSAPublicNumbers(exponent, int(priv_numbers.public_numbers.n)),
    )
    return rebuilt.private_key()


def _use_rsa_encrypt(
    rs: Any,
    handle: int,
    *,
    private_key: Any | None,
    admitted: tuple[bytes | None, bytes | None] | None = None,
    label: str,
    operation: str,
    spec_ref: str,
) -> _UseOutcome:
    """Probe RSA-PKCS encrypt of an admitted object with local decrypt proof.

    The ciphertext is verified ONLY under the admitted public-key oracle
    (F3): without readable admitted halves the success is unverifiable, and
    only a failure under the admitted oracle fails crypto wrong_result.
    """
    outcome = _UseOutcome(use_kind="rsa_encrypt", attempted=True, rvs=[])
    assert outcome.rvs is not None
    plaintext = b"qc4-rsa-use-probe!"
    try:
        ciphertext = encrypt_single(rs.raw, rs.sh, handle, CKM_RSA_PKCS, plaintext)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(exc.rv, label=label, operation="C_Encrypt", kind="policy")
        outcome.rvs.append(ckr_name(exc.rv))
        return outcome
    oracle = (
        _rsa_oracle_for_admitted(private_key, admitted)
        if private_key is not None and admitted is not None
        else None
    )
    if oracle is None:
        outcome.unverifiable = True
        return outcome
    try:
        recovered = oracle.decrypt(ciphertext, padding.PKCS1v15())
    except ValueError:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism="CKM_RSA_PKCS",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: admitted object encrypted but the ciphertext does not "
                "decrypt under the admitted public-key oracle; crypto wrong_result"
            ),
            detail={"ciphertext_len": len(ciphertext)},
        )
    if recovered != plaintext:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism="CKM_RSA_PKCS",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: admitted object encrypted to the wrong plaintext; crypto wrong_result"
            ),
            detail={"ciphertext_len": len(ciphertext)},
        )
    outcome.coherent = True
    return outcome


def _rsa_pub_from_halves(modulus: bytes | None, exponent: bytes | None) -> Any | None:
    if modulus is None or exponent is None or not modulus or not exponent:
        return None
    try:
        numbers = rsa.RSAPublicNumbers(
            int.from_bytes(exponent, "big"), int.from_bytes(modulus, "big")
        )
        return numbers.public_key()
    except ValueError:
        return None


def _use_rsa_sign(
    rs: Any,
    handle: int,
    *,
    pub: Any | None,
    label: str,
    operation: str,
    spec_ref: str,
) -> _UseOutcome:
    """Probe RSA sign of an admitted object with independent local verification."""
    outcome = _UseOutcome(use_kind="rsa_sign", attempted=True, rvs=[])
    assert outcome.rvs is not None
    try:
        signature = sign_single(rs.raw, rs.sh, handle, CKM_SHA256_RSA_PKCS, QC4_SIGN_DATA)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(exc.rv, label=label, operation="C_Sign", kind="policy")
        outcome.rvs.append(ckr_name(exc.rv))
        return outcome
    if pub is None:
        outcome.unverifiable = True
        return outcome
    if not rsa_pkcs15_local(pub, QC4_SIGN_DATA, signature, hashes.SHA256()):
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism="CKM_SHA256_RSA_PKCS",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: admitted object signed but the signature is invalid "
                f"(sig_len={len(signature)}); crypto wrong_result"
            ),
            detail={"sig_len": len(signature)},
        )
    outcome.coherent = True
    return outcome


def _ec_pub_from_point(point: tuple[int, int] | None) -> Any | None:
    if point is None:
        return None
    try:
        numbers = ec.EllipticCurvePublicNumbers(point[0], point[1], ec.SECP256R1())
        return numbers.public_key()
    except ValueError:
        return None


def _ec_local_key_for_point(point: tuple[int, int] | None) -> Any | None:
    """The known local private half iff the admitted point is ours (F8).

    A Verify-role exercise needs a locally valid signature, which needs
    the private half of the admitted point. That exists only when the
    read-back point equals the seeded known point; anything else (or an
    unreadable point) leaves Verify unwitnessable.
    """
    if point is None:
        return None
    _, known_point_der, known_priv = ec_p256_material()
    # _parse_ec_point reports malformed input as None, never by raising, so
    # no except arm is needed: an unparseable known point compares unequal.
    known = _parse_ec_point(known_point_der)
    return known_priv if known == point else None


def _use_ec_verify(
    rs: Any,
    handle: int,
    *,
    local_priv: Any,
    label: str,
    operation: str,
    spec_ref: str,
) -> _UseOutcome:
    """Verify-role exercise of an admitted EC public object (F8).

    Signs the fixed probe digest LOCALLY with the known private half and
    asks the module to verify with the admitted handle: the
    role-appropriate op for a public object, independently witnessed. The
    local signature is valid by construction, so a module "invalid" is a
    crypto contradiction (the module disagrees with its own read-back
    point); a refusal is recorded and non-coherent.
    """
    outcome = _UseOutcome(use_kind="ec_verify", attempted=True, rvs=[])
    assert outcome.rvs is not None
    der = local_priv.sign(QC4_ECDSA_DIGEST, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(der)
    raw_sig = int(r).to_bytes(P256_HALF_LEN, "big") + int(s).to_bytes(P256_HALF_LEN, "big")
    try:
        verified = verify_single(rs.raw, rs.sh, handle, CKM_ECDSA, QC4_ECDSA_DIGEST, raw_sig)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(exc.rv, label=label, operation="C_Verify", kind="policy")
        outcome.rvs.append(ckr_name(exc.rv))
        return outcome
    if not verified:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism="CKM_ECDSA",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: admitted object rejects a locally valid signature "
                "for its own read-back point; crypto wrong_result"
            ),
            detail={"sig_len": len(raw_sig)},
        )
    outcome.coherent = True
    return outcome


def _use_ec_sign(
    rs: Any,
    handle: int,
    *,
    params: bytes | None,
    point: tuple[int, int] | None,
    label: str,
    operation: str,
    spec_ref: str,
) -> _UseOutcome:
    """Probe ECDSA sign of an admitted object with independent local verification.

    CKM_ECDSA signs the supplied digest WITHOUT hashing (PKCS#11 v3.2
    §6.3.12), so the fixed probe digest is supplied to the module and the
    SAME bytes are verified locally via Prehashed SHA-256 (F2: never
    ``verify`` with a hash over the input). The curve is trusted only from
    a read-back P-256 params OID; with unknown params a valid signature
    still proves usability, but an invalid one proves nothing (the module
    may use another curve).
    """
    outcome = _UseOutcome(use_kind="ec_sign", attempted=True, rvs=[])
    assert outcome.rvs is not None
    try:
        signature = sign_single(rs.raw, rs.sh, handle, CKM_ECDSA, QC4_ECDSA_DIGEST)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(exc.rv, label=label, operation="C_Sign", kind="policy")
        outcome.rvs.append(ckr_name(exc.rv))
        return outcome
    # N2/F4 shape gate immediately after a successful Sign, BEFORE any
    # point/oracle requirement: with readable P-256 params a successful
    # output is always exactly 2x32 bytes (PKCS#11 v3.2 §6.3.1), so a
    # wrong-length output is a proved shape contradiction even when the
    # point is unreadable. With unknown params the curve is unproved, so
    # a non-64-byte output stays unverifiable below.
    if params == QC4_P256_PARAMS and len(signature) != ECDSA_P256_SIG_LEN:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation=operation,
            mechanism="CKM_ECDSA",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: successful P-256 ECDSA output has the wrong shape "
                f"(sig_len={len(signature)}, expected {ECDSA_P256_SIG_LEN} "
                "fixed-width r||s halves per §6.3.1); crypto wrong_result"
            ),
            detail={"sig_len": len(signature), "expected_sig_len": ECDSA_P256_SIG_LEN},
        )
    pub = _ec_pub_from_point(point)
    if pub is None:
        outcome.unverifiable = True
        return outcome
    try:
        r, s = split_raw_ecdsa(signature, P256_HALF_LEN)
    except MalformedSignature:
        outcome.unverifiable = True
        return outcome
    try:
        pub.verify(
            utils.encode_dss_signature(r, s),
            QC4_ECDSA_DIGEST,
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
    except InvalidSignature:
        valid = False
    else:
        valid = True
    if valid:
        outcome.coherent = True
        return outcome
    if params != QC4_P256_PARAMS:
        outcome.unverifiable = True
        return outcome
    fail_as(
        "wrong_result",
        kind="crypto",
        label=label,
        operation=operation,
        mechanism="CKM_ECDSA",
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=spec_ref,
        summary=(
            f"{label}: admitted object signed but the signature is invalid "
            f"(sig_len={len(signature)}); crypto wrong_result"
        ),
        detail={"sig_len": len(signature)},
    )


def _check_pqc_sig_shape(
    signature: bytes,
    *,
    family: PqcFamily,
    label: str,
    operation: str,
    spec_ref: str,
) -> None:
    """Gate a successful PQC signature against a qualified parameter set.

    The caller passes a *qualified* family: its ``param_set`` is the set
    the template requested, or the read-back set of the admitted key
    (N3) -- never a statically assumed default. PQC signatures have a
    FIXED length per (family, set); an empty or wrong-length successful
    output is a proved shape contradiction (crypto wrong_result) that
    never reaches the usability adjudicator. An unrecognized (family,
    set) pair cannot be gated and is returned unjudged.
    """
    expected = _PQC_SIG_LENS.get((int(family.key_type), int(family.param_set)))
    if expected is None or len(signature) == expected:
        return
    fail_as(
        "wrong_result",
        kind="crypto",
        label=label,
        operation=operation,
        mechanism=ckm_name(family.sign_mech),
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=spec_ref,
        summary=(
            f"{label}: successful PQC signature output has the wrong shape "
            f"(sig_len={len(signature)}, expected {expected} for the "
            "qualified parameter set); crypto wrong_result"
        ),
        detail={"sig_len": len(signature), "expected_sig_len": expected},
    )


def _read_admitted_pqc_param_set(
    rs: Any, handle: int, *, family: PqcFamily, label: str
) -> int | None:
    """Qualify an admitted PQC key's set by readback, or None (N3).

    Only reached when the template did not specify a set. An unreadable,
    malformed, or unrecognized-for-the-family value leaves the set
    unqualified (None): the shape gate then does not FAIL and the leg
    stays at its existing unverifiable ceiling. Never guess a default.
    """
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [int(CKA_PARAMETER_SET)])
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv, label=label, operation="C_GetAttributeValue", kind="policy"
        )
        _note_qc4_observation(
            f"{label}: parameter-set readback refused ({ckr_name(exc.rv)}); "
            "parameter set unqualified",
            "QC4b #56.2 PQC parameter-set qualification",
        )
        return None
    record_count = len(get_records())
    value = attr_or_record(
        attrs,
        CKA_PARAMETER_SET,
        label=f"{label}: parameter-set readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    if value is MISSING_ATTRIBUTE:
        _raise_for_fresh_fail(record_count)
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    if (int(family.key_type), int(value)) not in _PQC_SIG_LENS:
        _note_qc4_observation(
            f"{label}: read-back parameter set unrecognized for the family; "
            "parameter set unqualified",
            "QC4b #56.2 PQC parameter-set qualification",
        )
        return None
    return int(value)


def _use_pqc_verify_admitted(
    rs: Any,
    admitted: int,
    *,
    family: PqcFamily,
    signer: int,
    label: str,
    operation: str,
    spec_ref: str,
) -> _UseOutcome:
    """Sign with a trusted key, verify with the admitted object (module verify).

    Module self-agreement only, NEVER failable (F11): no independent local
    ML-DSA/SLH-DSA verify oracle exists in this tree (the CCTV and HashML-DSA
    suites verify by module round-trip; no vendored PQC library is available),
    so a coherent outcome is an accepted-coherent ceiling, never a FAIL.
    """
    outcome = _UseOutcome(use_kind="pqc_verify", attempted=True, rvs=[], failable=False)
    assert outcome.rvs is not None
    try:
        signature = sign_single(rs.raw, rs.sh, signer, family.sign_mech, QC4_SIGN_DATA)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(exc.rv, label=label, operation="C_Sign", kind="policy")
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: accepted but the trusted PQC signature setup refused "
                f"with {ckr_name(exc.rv)}; usability unproved"
            ),
            detail={"disposition": "unproved-effect", "use_rv": ckr_name(exc.rv)},
        )
    # Qualification (N3): the signer is a sourcing pair generated with an
    # explicit set (family.param_set), so that requested set gates its
    # output -- no re-read is needed or done.
    _check_pqc_sig_shape(
        signature, family=family, label=label, operation=operation, spec_ref=spec_ref
    )
    try:
        verified = verify_single(
            rs.raw, rs.sh, admitted, family.sign_mech, QC4_SIGN_DATA, signature
        )
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(exc.rv, label=label, operation="C_Verify", kind="policy")
        outcome.rvs.append(ckr_name(exc.rv))
        return outcome
    outcome.coherent = verified
    return outcome


def _use_pqc_sign_admitted(
    rs: Any,
    admitted: int,
    *,
    family: PqcFamily,
    qualified_family: PqcFamily | None,
    verifier: int,
    label: str,
    operation: str,
    spec_ref: str,
    failable: bool,
) -> _UseOutcome:
    """Sign with the admitted object, verify with a trusted key (module verify).

    Module self-agreement, unfailable in every caller since F11 (no local
    PQC verify oracle exists; see the survey note on the verify-admitted
    twin). The flag stays explicit at call sites so a future witness can
    re-arm it deliberately. ``qualified_family`` carries the admitted
    set qualification for the shape gate (N3): None means unqualified --
    the gate does not FAIL and the state is noted, never guessed.
    """
    outcome = _UseOutcome(use_kind="pqc_sign", attempted=True, rvs=[], failable=failable)
    assert outcome.rvs is not None
    try:
        signature = sign_single(rs.raw, rs.sh, admitted, family.sign_mech, QC4_SIGN_DATA)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(exc.rv, label=label, operation="C_Sign", kind="policy")
        outcome.rvs.append(ckr_name(exc.rv))
        return outcome
    if qualified_family is None:
        _note_qc4_observation(
            f"{label}: PQC parameter set unqualified; signature shape not gated "
            f"(sig_len={len(signature)})",
            "QC4b #56.2 PQC parameter-set qualification",
        )
    else:
        _check_pqc_sig_shape(
            signature, family=qualified_family, label=label, operation=operation, spec_ref=spec_ref
        )
    try:
        verified = verify_single(
            rs.raw, rs.sh, verifier, family.sign_mech, QC4_SIGN_DATA, signature
        )
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(exc.rv, label=label, operation="C_Verify", kind="policy")
        outcome.unverifiable = True
        outcome.rvs.append(ckr_name(exc.rv))
        return outcome
    outcome.coherent = verified
    return outcome


_QC4B_SPEC = "PKCS#11 v3.2 §5.7.1/§5.18.4/§5.18.2 mandatory template attributes"


def _create_rsa_templates(malformation: str, label: str) -> tuple[dict[Any, Any], tuple[int, int]]:
    modulus, exponent, _ = rsa2048_material()
    secret = int(CKO_SECRET_KEY)
    public = int(CKO_PUBLIC_KEY)
    rsa_type = int(CKK_RSA)
    if malformation == "swap_secret_class_asym_type":
        return (
            {
                CKA_CLASS: secret,
                CKA_KEY_TYPE: rsa_type,
                CKA_VALUE: QC4_AES_PEER,
                CKA_ENCRYPT: True,
                CKA_TOKEN: False,
                CKA_LABEL: label,
            },
            (secret, rsa_type),
        )
    if malformation == "swap_asym_class_secret_type":
        return (
            {
                CKA_CLASS: public,
                CKA_KEY_TYPE: int(CKK_AES),
                CKA_VALUE: QC4_AES_PEER,
                CKA_ENCRYPT: True,
                CKA_TOKEN: False,
                CKA_LABEL: label,
            },
            (public, int(CKK_AES)),
        )
    if malformation == "missing_modulus":
        return (
            {
                CKA_CLASS: public,
                CKA_KEY_TYPE: rsa_type,
                CKA_PUBLIC_EXPONENT: exponent,
                CKA_ENCRYPT: True,
                CKA_TOKEN: False,
                CKA_LABEL: label,
            },
            (public, rsa_type),
        )
    if malformation == "missing_exponent":
        return (
            {
                CKA_CLASS: public,
                CKA_KEY_TYPE: rsa_type,
                CKA_MODULUS: modulus,
                CKA_ENCRYPT: True,
                CKA_TOKEN: False,
                CKA_LABEL: label,
            },
            (public, rsa_type),
        )
    raise KeyError(malformation)


def _create_rsa_control(attempt: dict[Any, Any], label: str) -> dict[Any, Any]:
    """Legal RSA control derived from the attempt (N4/F7).

    A copy of the attempt with ONLY the malformation corrected -- the
    missing component sourced from the same family material -- so every
    usage/token premise the attempt carries (notably CKA_ENCRYPT) is
    inherited verbatim. A control built from scratch could be admitted
    where permission-bearing imports are refused, passing the cell
    without the missing component ever being evaluated.
    """
    modulus, exponent, _ = rsa2048_material()
    control = dict(attempt)
    control.pop(CKA_VALUE, None)
    control.update(
        {
            CKA_CLASS: int(CKO_PUBLIC_KEY),
            CKA_KEY_TYPE: int(CKK_RSA),
            CKA_MODULUS: modulus,
            CKA_PUBLIC_EXPONENT: exponent,
            CKA_LABEL: label,
        }
    )
    return control


def _create_aes_secret_control(attempt: dict[Any, Any], label: str) -> dict[Any, Any]:
    """Well-formed AES-secret control for an AES-material cell (F7/N4).

    A copy of the attempt with ONLY the malformation corrected: same AES
    value material, same usage premise (ENCRYPT or VERIFY, whichever the
    attempt carries), coherent SECRET/AES identity. An AES-material
    cell gets this AES control, never an RSA/EC one (a module can
    support RSA import yet lack AES import).
    """
    control = dict(attempt)
    control.update(
        {
            CKA_CLASS: int(CKO_SECRET_KEY),
            CKA_KEY_TYPE: int(CKK_AES),
            CKA_LABEL: label,
        }
    )
    return control


def _cell_material_is_aes(family: str, malformation: str) -> bool:
    """True when the cell's template carries AES value material (F7).

    ``swap_asym_class_secret_type`` carries AES bytes in every family; the
    classic ``swap_secret_class_asym_type`` cells do too. PQC secret-swap
    cells carry a PQC public value instead, and missing-component cells
    carry family components, so those keep their family controls.
    """
    if malformation == "swap_asym_class_secret_type":
        return True
    return family in ("rsa", "ec") and malformation == "swap_secret_class_asym_type"


def _create_ec_templates(malformation: str, label: str) -> tuple[dict[Any, Any], tuple[int, int]]:
    params, point, _ = ec_p256_material()
    secret = int(CKO_SECRET_KEY)
    public = int(CKO_PUBLIC_KEY)
    ec_type = int(CKK_EC)
    if malformation == "swap_secret_class_asym_type":
        return (
            {
                CKA_CLASS: secret,
                CKA_KEY_TYPE: ec_type,
                CKA_VALUE: QC4_AES_PEER,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_LABEL: label,
            },
            (secret, ec_type),
        )
    if malformation == "swap_asym_class_secret_type":
        return (
            {
                CKA_CLASS: public,
                CKA_KEY_TYPE: int(CKK_AES),
                CKA_VALUE: QC4_AES_PEER,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_LABEL: label,
            },
            (public, int(CKK_AES)),
        )
    if malformation == "missing_params":
        return (
            {
                CKA_CLASS: public,
                CKA_KEY_TYPE: ec_type,
                CKA_EC_POINT: point,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_LABEL: label,
            },
            (public, ec_type),
        )
    if malformation == "missing_point":
        return (
            {
                CKA_CLASS: public,
                CKA_KEY_TYPE: ec_type,
                CKA_EC_PARAMS: params,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_LABEL: label,
            },
            (public, ec_type),
        )
    raise KeyError(malformation)


def _create_ec_control(attempt: dict[Any, Any], label: str) -> dict[Any, Any]:
    """Legal EC control derived from the attempt (N4/F7): copy it, source
    the missing params/point from the same family material, and inherit
    every usage/token premise (notably CKA_VERIFY) verbatim."""
    params, point, _ = ec_p256_material()
    control = dict(attempt)
    control.pop(CKA_VALUE, None)
    control.update(
        {
            CKA_CLASS: int(CKO_PUBLIC_KEY),
            CKA_KEY_TYPE: int(CKK_EC),
            CKA_EC_PARAMS: params,
            CKA_EC_POINT: point,
            CKA_LABEL: label,
        }
    )
    return control


def _create_pqc_templates(
    family: PqcFamily, malformation: str, pub_value: bytes, label: str
) -> tuple[dict[Any, Any], tuple[int, int]]:
    secret = int(CKO_SECRET_KEY)
    public = int(CKO_PUBLIC_KEY)
    if malformation == "swap_secret_class_asym_type":
        return (
            {
                CKA_CLASS: secret,
                CKA_KEY_TYPE: family.key_type,
                CKA_VALUE: pub_value,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_LABEL: label,
            },
            (secret, family.key_type),
        )
    if malformation == "swap_asym_class_secret_type":
        return (
            {
                CKA_CLASS: public,
                CKA_KEY_TYPE: int(CKK_AES),
                CKA_VALUE: QC4_AES_PEER,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_LABEL: label,
            },
            (public, int(CKK_AES)),
        )
    if malformation == "missing_params":
        return (
            {
                CKA_CLASS: public,
                CKA_KEY_TYPE: family.key_type,
                CKA_VALUE: pub_value,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_LABEL: label,
            },
            (public, family.key_type),
        )
    raise KeyError(malformation)


def _create_pqc_control(attempt: dict[Any, Any], family: PqcFamily, label: str) -> dict[Any, Any]:
    """Legal PQC control derived from the attempt (N4/F7): copy it,
    correct only class/type coherence and the missing parameter set,
    and inherit every usage/token/material premise verbatim."""
    control = dict(attempt)
    control.update(
        {
            CKA_CLASS: int(CKO_PUBLIC_KEY),
            CKA_KEY_TYPE: family.key_type,
            CKA_PARAMETER_SET: family.param_set,
            CKA_LABEL: label,
        }
    )
    return control


def _generate_pqc_sourcing_pair(rs: Any, family: PqcFamily, *, label: str) -> tuple[int, int]:
    """Generate a valid PQC pair (sanctioned mechanism_helpers keygen pattern)."""
    try:
        return gen_keypair(
            rs.raw,
            rs.sh,
            family.keygen_mech,
            pub_base=[attr_ulong(CKA_PARAMETER_SET, family.param_set)],
            priv_base=[],
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False, CKA_LABEL: f"{label}-src-pub"},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False, CKA_LABEL: f"{label}-src-priv"},
            pub_skip={CKA_PARAMETER_SET},
        )
    except CkrAssertionError as exc:
        void_qc4_setup_exc(
            exc,
            (),
            label=f"{label} PQC sourcing",
            operation="C_GenerateKeyPair",
            mechanism=ckm_name(family.keygen_mech),
        )


def _read_sourcing_pub(rs: Any, handle: int, *, label: str) -> bytes:
    """Read the sourcing pair's public value, or void the PQC setup."""
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [int(CKA_VALUE)])
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv,
            label=f"{label} PQC sourcing",
            operation="C_GetAttributeValue",
            kind="policy",
        )
        xfail_as(
            "not_operational",
            kind="policy",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            actual=exc.rv,
            spec_ref=_QC4B_SPEC,
            summary=(
                f"{label}: sourcing public value refused with {ckr_name(exc.rv)}; PQC setup void"
            ),
        )
    value = attr_or_record(
        attrs,
        CKA_VALUE,
        label=f"{label}: sourcing public readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    if value is MISSING_ATTRIBUTE or not isinstance(value, bytes) or not value:
        xfail_as(
            "not_operational",
            kind="policy",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            spec_ref=_QC4B_SPEC,
            summary=(f"{label}: sourcing public value unavailable; PQC setup void"),
        )
    return value


def _run_create_malformed_cell(rs: Any, family: str, malformation: str) -> None:
    label = f"C_CreateObject malformed {family}/{malformation}"
    skip_unless_create_object_supported(rs)
    attempt_label = malformed_label("create", family, malformation)
    ctrl_label = control_label("create", family, malformation)
    pqc: PqcFamily | None = resolve_pqc_family(rs) if family == "pqc" else None
    src_pub = 0
    src_priv = 0
    try:
        if family == "rsa":
            attempt_attrs, requested = _create_rsa_templates(malformation, attempt_label)
            if _cell_material_is_aes(family, malformation):
                control_attrs = _create_aes_secret_control(attempt_attrs, ctrl_label)
            else:
                control_attrs = _create_rsa_control(attempt_attrs, ctrl_label)
            _, _, rsa_priv = rsa2048_material()
        elif family == "ec":
            attempt_attrs, requested = _create_ec_templates(malformation, attempt_label)
            if _cell_material_is_aes(family, malformation):
                control_attrs = _create_aes_secret_control(attempt_attrs, ctrl_label)
            else:
                control_attrs = _create_ec_control(attempt_attrs, ctrl_label)
            rsa_priv = None
        else:
            assert pqc is not None
            src_pub, src_priv = _generate_pqc_sourcing_pair(rs, pqc, label=label)
            pub_value = _read_sourcing_pub(rs, src_pub, label=label)
            attempt_attrs, requested = _create_pqc_templates(
                pqc, malformation, pub_value, attempt_label
            )
            if _cell_material_is_aes(family, malformation):
                control_attrs = _create_aes_secret_control(attempt_attrs, ctrl_label)
            else:
                control_attrs = _create_pqc_control(attempt_attrs, pqc, ctrl_label)
            rsa_priv = None
        try:
            control = create_object(rs.raw, rs.sh, control_attrs)
        except CkrAssertionError as exc:
            void_qc4_setup_exc(exc, (), label=f"{label} legal control", operation="C_CreateObject")
        _cleanup_owned(rs, [control])
        try:
            before = _find_by_label(rs, attempt_label)
        except CkrAssertionError as exc:
            void_qc4_setup_exc(exc, (), label=f"{label}: inventory", operation="C_FindObjects")
        tmpl = template(*pack_attrs(attempt_attrs))
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv != int(CKR_OK):
            _adjudicate_malformed_refusal(
                rs,
                rv,
                label=label,
                operation="C_CreateObject",
                attempt_label=attempt_label,
                before=before,
                spec_ref=_QC4B_SPEC,
            )
            return
        try:
            readback = _inspect_identity(
                rs,
                handle.value,
                label=label,
                operation="C_CreateObject",
                spec_ref=_QC4B_SPEC,
            )
            outcomes = _create_acceptance_uses(
                rs,
                handle.value,
                family,
                malformation,
                attempt_attrs,
                pqc=pqc,
                src_priv=src_priv,
                rsa_priv=rsa_priv,
                readback=readback,
                requested=requested,
                label=label,
                spec_ref=_QC4B_SPEC,
            )
            for outcome in outcomes:
                outcome.performer = readback
                outcome.handle = handle.value
            _adjudicate_uses(
                outcomes,
                readback=readback,
                requested=requested,
                pqc_type=pqc.key_type if pqc else 0,
                label=label,
                operation="C_CreateObject",
                spec_ref=_QC4B_SPEC,
            )
        finally:
            _cleanup_owned(rs, [handle.value])
    finally:
        _cleanup_owned(rs, [src_pub, src_priv])


def _has_proved_contradiction(
    outcomes: list[_UseOutcome], *, readback: tuple[int, int], pqc_type: int
) -> bool:
    """True when a collected outcome already proves the FAIL (N1).

    Mirrors ``_adjudicate_uses``' FAIL condition exactly: a failable
    coherent use whose performing identity is malformed or whose use
    contradicts that identity.
    """
    for outcome in outcomes:
        if not outcome.coherent or not outcome.failable:
            continue
        acting = outcome.performer if outcome.performer is not None else readback
        if _identity_malformed(*acting) or _contradicts(outcome.use_kind, acting, pqc_type):
            return True
    return False


def _create_acceptance_uses(
    rs: Any,
    handle: int,
    family: str,
    malformation: str,
    attempt_attrs: dict[Any, Any],
    *,
    pqc: PqcFamily | None,
    src_priv: int,
    rsa_priv: Any | None,
    readback: tuple[int, int],
    requested: tuple[int, int],
    label: str,
    spec_ref: str,
) -> list[_UseOutcome]:
    """Run the family use legs for an admitted Create, proving usability.

    N1 fail-fast: the moment a collected outcome proves the FAIL, it is
    adjudicated BEFORE the next provider call, so a later fallible read
    or probe (whose vendor/undefined validity arm raises) can never
    preempt a witnessed contradiction. Non-contradictory outcomes keep
    the ordinary collect-then-adjudicate flow and ceilings.
    """
    outcomes: list[_UseOutcome] = []
    pqc_type = pqc.key_type if pqc else 0

    def collect(outcome: _UseOutcome) -> None:
        outcome.performer = readback
        outcome.handle = handle
        outcomes.append(outcome)
        if _has_proved_contradiction(outcomes, readback=readback, pqc_type=pqc_type):
            _adjudicate_uses(
                list(outcomes),
                readback=readback,
                requested=requested,
                pqc_type=pqc_type,
                label=label,
                operation="C_CreateObject",
                spec_ref=spec_ref,
            )

    swap = malformation in ("swap_secret_class_asym_type", "swap_asym_class_secret_type")
    if family == "rsa":
        can_aes = swap and rs.has_mechanism("AES_ECB")
        can_rsa = rs.has_mechanism("RSA_PKCS")
        if not can_aes and not can_rsa:
            _xfail_use_unavailable(label, "C_CreateObject", "CKM_RSA_PKCS", spec_ref)
        if can_aes:
            value = attempt_attrs.get(CKA_VALUE)
            if isinstance(value, bytes) and len(value) in (16, 24, 32):
                collect(
                    _use_aes_oracle(
                        rs,
                        handle,
                        key_bytes=value,
                        label=label,
                        operation="C_CreateObject",
                        spec_ref=spec_ref,
                    )
                )
        if can_rsa:
            if malformation == "missing_exponent":
                admitted_halves = _read_rsa_halves(
                    rs, handle, label=label, operation="C_CreateObject", spec_ref=spec_ref
                )
                collect(
                    _use_rsa_encrypt(
                        rs,
                        handle,
                        private_key=rsa_priv,
                        admitted=admitted_halves,
                        label=label,
                        operation="C_CreateObject",
                        spec_ref=spec_ref,
                    )
                )
            else:
                collect(
                    _use_rsa_encrypt(
                        rs,
                        handle,
                        private_key=None,
                        label=label,
                        operation="C_CreateObject",
                        spec_ref=spec_ref,
                    )
                )
        return outcomes
    if family == "ec":
        can_aes = swap and rs.has_mechanism("AES_ECB")
        can_ec = rs.has_mechanism("ECDSA")
        if not can_aes and not can_ec:
            _xfail_use_unavailable(label, "C_CreateObject", "CKM_ECDSA", spec_ref)
        if can_aes:
            value = attempt_attrs.get(CKA_VALUE)
            if isinstance(value, bytes) and len(value) in (16, 24, 32):
                collect(
                    _use_aes_oracle(
                        rs,
                        handle,
                        key_bytes=value,
                        label=label,
                        operation="C_CreateObject",
                        spec_ref=spec_ref,
                    )
                )
        if can_ec:
            params, point = _read_ec_halves(
                rs, handle, label=label, operation="C_CreateObject", spec_ref=spec_ref
            )
            local_priv = _ec_local_key_for_point(point)
            if local_priv is None:
                # Role-appropriate op unwitnessable (F8): no private half
                # for this point, so Verify cannot be attempted; unproved,
                # never "inspected and unusable".
                collect(
                    _UseOutcome(use_kind="ec_verify", attempted=False, rvs=[], unverifiable=True)
                )
            else:
                collect(
                    _use_ec_verify(
                        rs,
                        handle,
                        local_priv=local_priv,
                        label=label,
                        operation="C_CreateObject",
                        spec_ref=spec_ref,
                    )
                )
            # Private-role misuse probe (kept): success from a public handle
            # is type confusion (contradiction FAIL); refusal is correct and
            # non-terminal. The usability verdict comes from Verify above.
            collect(
                _use_ec_sign(
                    rs,
                    handle,
                    params=params,
                    point=point,
                    label=label,
                    operation="C_CreateObject",
                    spec_ref=spec_ref,
                )
            )
        return outcomes
    assert pqc is not None
    if not rs.has_mechanism(pqc.sign_mech_name):
        _xfail_use_unavailable(label, "C_CreateObject", ckm_name(pqc.sign_mech), spec_ref)
    if swap and rs.has_mechanism("AES_ECB"):
        value = attempt_attrs.get(CKA_VALUE)
        if isinstance(value, bytes) and len(value) in (16, 24, 32):
            collect(
                _use_aes_oracle(
                    rs,
                    handle,
                    key_bytes=value,
                    label=label,
                    operation="C_CreateObject",
                    spec_ref=spec_ref,
                )
            )
    collect(
        _use_pqc_verify_admitted(
            rs,
            handle,
            family=pqc,
            signer=src_priv,
            label=label,
            operation="C_CreateObject",
            spec_ref=spec_ref,
        )
    )
    return outcomes


def _xfail_use_unavailable(label: str, operation: str, mechanism: str, spec_ref: str) -> NoReturn:
    """Admission stands but no family use entry exists: visible xfail, not a skip."""
    xfail_as(
        "honest_deviation",
        kind="policy",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=spec_ref,
        summary=(
            f"{label}: admitted malformed template but the family use "
            f"mechanism is unavailable ({mechanism} not supported); "
            "usability unproved"
        ),
        detail={"disposition": "unproved-effect", "use_attempted": False},
    )


def _unwrap_templates(
    family_type: int, malformation: str, label: str
) -> tuple[dict[Any, Any], tuple[int, int]]:
    secret = int(CKO_SECRET_KEY)
    public = int(CKO_PUBLIC_KEY)
    base: dict[Any, Any] = {
        CKA_SIGN: True,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_LABEL: label,
    }
    if malformation == "swap_secret_class_asym_type":
        return (
            {CKA_CLASS: secret, CKA_KEY_TYPE: family_type, **base},
            (secret, family_type),
        )
    if malformation == "swap_asym_class_secret_type":
        return (
            {CKA_CLASS: public, CKA_KEY_TYPE: int(CKK_AES), **base},
            (public, int(CKK_AES)),
        )
    raise KeyError(malformation)


def _unwrap_control_template(family_type: int, label: str) -> dict[Any, Any]:
    return {
        CKA_CLASS: int(CKO_PRIVATE_KEY),
        CKA_KEY_TYPE: family_type,
        CKA_SIGN: True,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_LABEL: label,
    }


def _generate_family_source(
    rs: Any, family: str, pqc: PqcFamily | None, *, label: str
) -> tuple[int, int]:
    """Generate an extractable family source pair, or void the setup."""
    op_label = f"{label} source pair"
    try:
        if family == "rsa":
            return gen_rsa_keypair(
                rs.raw,
                rs.sh,
                QC4_RSA_BITS,
                public_attrs={
                    # N5: pin the Encrypt premise explicitly (the recipe
                    # default already carries it via the sign+decrypt
                    # usage, so the wire template is unchanged -- the
                    # Generate control and the Unwrap source pair share
                    # this builder and both already carried it).
                    CKA_ENCRYPT: True,
                    CKA_VERIFY: True,
                    CKA_TOKEN: False,
                    CKA_LABEL: f"{label}-src-pub",
                },
                private_attrs={
                    CKA_SIGN: True,
                    CKA_DECRYPT: True,
                    CKA_TOKEN: False,
                    CKA_EXTRACTABLE: True,
                    CKA_LABEL: f"{label}-src-priv",
                },
            )
        if family == "ec":
            return gen_ec_keypair(
                rs.raw,
                rs.sh,
                QC4_P256_PARAMS,
                public_attrs={
                    CKA_VERIFY: True,
                    CKA_TOKEN: False,
                    CKA_LABEL: f"{label}-src-pub",
                },
                private_attrs={
                    CKA_SIGN: True,
                    CKA_TOKEN: False,
                    CKA_EXTRACTABLE: True,
                    CKA_LABEL: f"{label}-src-priv",
                },
            )
        assert pqc is not None
        return gen_keypair(
            rs.raw,
            rs.sh,
            pqc.keygen_mech,
            pub_base=[attr_ulong(CKA_PARAMETER_SET, pqc.param_set)],
            priv_base=[],
            public_attrs={
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_LABEL: f"{label}-src-pub",
            },
            private_attrs={
                CKA_SIGN: True,
                CKA_TOKEN: False,
                CKA_EXTRACTABLE: True,
                CKA_LABEL: f"{label}-src-priv",
            },
            pub_skip={CKA_PARAMETER_SET},
        )
    except CkrAssertionError as exc:
        void_qc4_setup_exc(exc, (), label=op_label, operation="C_GenerateKeyPair")


def _run_unwrap_malformed_cell(rs: Any, family: str, malformation: str) -> None:
    label = f"C_UnwrapKey malformed {family}/{malformation}"
    if not rs.has_mechanism("AES_KEY_WRAP"):
        pytest.skip("CKM_AES_KEY_WRAP not supported")
    if family == "rsa" and not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
        pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
    if family == "ec" and not rs.has_mechanism("EC_KEY_PAIR_GEN"):
        pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
    pqc: PqcFamily | None = resolve_pqc_family(rs) if family == "pqc" else None
    family_type = {"rsa": int(CKK_RSA), "ec": int(CKK_EC)}.get(family, pqc.key_type if pqc else 0)
    attempt_label = malformed_label("unwrap", family, malformation)
    ctrl_label = control_label("unwrap", family, malformation)
    src_pub = 0
    src_priv = 0
    kek = 0
    try:
        src_pub, src_priv = _generate_family_source(rs, family, pqc, label=label)
        kek = _import_constrained_aes(
            rs,
            QC4_AES_BASE,
            {
                CKA_WRAP: True,
                # F6: the KEK unwraps (control + attempt); a provider with a
                # false UNWRAP default refuses a template that omits it.
                CKA_UNWRAP: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_LABEL: f"{label}-kek",
            },
            label=label,
            operation="C_CreateObject",
            spec_ref=_QC4B_SPEC,
        )
        try:
            blob = wrap_key(rs.raw, rs.sh, kek, src_priv, CKM_AES_KEY_WRAP)
        except CkrAssertionError as exc:
            void_qc4_setup_exc(
                exc,
                (),
                label=f"{label} blob premise",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
            )
        attempt_attrs, requested = _unwrap_templates(family_type, malformation, attempt_label)
        control_attrs = _unwrap_control_template(family_type, ctrl_label)
        try:
            control = unwrap_key(rs.raw, rs.sh, kek, blob, CKM_AES_KEY_WRAP, control_attrs)
        except CkrAssertionError as exc:
            void_qc4_setup_exc(
                exc,
                (),
                label=f"{label} legal control",
                operation="C_UnwrapKey",
                mechanism="CKM_AES_KEY_WRAP",
            )
        _cleanup_owned(rs, [control])
        try:
            before = _find_by_label(rs, attempt_label)
        except CkrAssertionError as exc:
            void_qc4_setup_exc(exc, (), label=f"{label}: inventory", operation="C_FindObjects")
        tmpl = template(*pack_attrs(attempt_attrs))
        in_buf = to_ubyte_buf(blob)
        handle = CK_OBJECT_HANDLE(0)
        mech = mech_simple(CKM_AES_KEY_WRAP)
        rv = rs.raw.C_UnwrapKey(
            rs.sh,
            mech.byref(),
            kek,
            in_buf,
            len(blob),
            tmpl.ptr,
            tmpl.count,
            byref(handle),
        )
        if rv != int(CKR_OK):
            _adjudicate_malformed_refusal(
                rs,
                rv,
                label=label,
                operation="C_UnwrapKey",
                attempt_label=attempt_label,
                before=before,
                spec_ref=_QC4B_SPEC,
            )
            return
        try:
            readback = _inspect_identity(
                rs,
                handle.value,
                label=label,
                operation="C_UnwrapKey",
                spec_ref=_QC4B_SPEC,
            )
            outcomes = _unwrap_acceptance_uses(
                rs,
                handle.value,
                family,
                src_pub,
                pqc=pqc,
                label=label,
                spec_ref=_QC4B_SPEC,
            )
            for outcome in outcomes:
                outcome.performer = readback
                outcome.handle = handle.value
            _adjudicate_uses(
                outcomes,
                readback=readback,
                requested=requested,
                pqc_type=pqc.key_type if pqc else 0,
                label=label,
                operation="C_UnwrapKey",
                spec_ref=_QC4B_SPEC,
            )
        finally:
            _cleanup_owned(rs, [handle.value])
    finally:
        _cleanup_owned(rs, [kek, src_pub, src_priv])


def _unwrap_acceptance_uses(
    rs: Any,
    handle: int,
    family: str,
    src_pub: int,
    *,
    pqc: PqcFamily | None,
    label: str,
    spec_ref: str,
) -> list[_UseOutcome]:
    """Run the family use legs for an admitted unwrap, proving usability.

    Verification runs ONLY under the admitted key's own read-back halves
    (N8/F3): §5.18.4 creates a new object, so equivalence with the
    source key is a claim needing its own evidence. Missing admitted
    halves yield no oracle and the use stays unproved -- source
    components are never substituted.
    """
    if family == "rsa":
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            _xfail_use_unavailable(label, "C_UnwrapKey", "CKM_SHA256_RSA_PKCS", spec_ref)
        modulus, exponent = _read_rsa_halves(
            rs, handle, label=label, operation="C_UnwrapKey", spec_ref=spec_ref
        )
        return [
            _use_rsa_sign(
                rs,
                handle,
                pub=_rsa_pub_from_halves(modulus, exponent),
                label=label,
                operation="C_UnwrapKey",
                spec_ref=spec_ref,
            )
        ]
    if family == "ec":
        if not rs.has_mechanism("ECDSA"):
            _xfail_use_unavailable(label, "C_UnwrapKey", "CKM_ECDSA", spec_ref)
        params, point = _read_ec_halves(
            rs, handle, label=label, operation="C_UnwrapKey", spec_ref=spec_ref
        )
        return [
            _use_ec_sign(
                rs,
                handle,
                params=params,
                point=point,
                label=label,
                operation="C_UnwrapKey",
                spec_ref=spec_ref,
            )
        ]
    assert pqc is not None
    if not rs.has_mechanism(pqc.sign_mech_name):
        _xfail_use_unavailable(label, "C_UnwrapKey", ckm_name(pqc.sign_mech), spec_ref)
    return [
        _use_pqc_sign_admitted(
            rs,
            handle,
            family=pqc,
            # Qualification (N3): the unwrapped material came from a
            # sourcing pair generated with an explicit set, so the
            # requested set qualifies -- no re-read is done.
            qualified_family=pqc,
            verifier=src_pub,
            label=label,
            operation="C_UnwrapKey",
            spec_ref=spec_ref,
            # Unfailable since F11: module self-agreement, no local oracle.
            failable=False,
        )
    ]


def _generate_templates(
    family: str,
    pqc: PqcFamily | None,
    malformation: str,
    label: str,
) -> tuple[int, dict[Any, Any], dict[Any, Any], tuple[int, int]]:
    """Malformed keygen mechanism + pub/priv templates + requested pub identity."""
    secret = int(CKO_SECRET_KEY)
    public = int(CKO_PUBLIC_KEY)
    priv_base: dict[Any, Any] = {
        CKA_SIGN: True,
        CKA_TOKEN: False,
        CKA_EXTRACTABLE: True,
        CKA_LABEL: label,
    }
    if family == "rsa":
        pub_base: dict[Any, Any] = {
            CKA_PUBLIC_EXPONENT: b"\x01\x00\x01",
            # N5 premise rule (F8): the public half's role exercise is
            # Encrypt, so the attempt requests that permission -- a
            # refusal is then attributable to the malformation, not the
            # harness. (No claim about omitted-attribute defaults.)
            CKA_ENCRYPT: True,
            CKA_VERIFY: True,
            CKA_TOKEN: False,
            CKA_LABEL: label,
        }
        if malformation == "swap_secret_class_asym_type":
            return (
                int(CKM_RSA_PKCS_KEY_PAIR_GEN),
                {
                    CKA_CLASS: secret,
                    CKA_MODULUS_BITS: QC4_RSA_BITS,
                    **pub_base,
                },
                dict(priv_base),
                (secret, int(CKK_RSA)),
            )
        if malformation == "swap_asym_class_secret_type":
            return (
                int(CKM_RSA_PKCS_KEY_PAIR_GEN),
                {
                    CKA_CLASS: public,
                    CKA_KEY_TYPE: int(CKK_AES),
                    CKA_MODULUS_BITS: QC4_RSA_BITS,
                    **pub_base,
                },
                dict(priv_base),
                (public, int(CKK_AES)),
            )
        if malformation == "missing_modulus_bits":
            return (
                int(CKM_RSA_PKCS_KEY_PAIR_GEN),
                dict(pub_base),
                dict(priv_base),
                (public, int(CKK_RSA)),
            )
        raise KeyError(malformation)
    if family == "ec":
        pub_base = {
            CKA_VERIFY: True,
            CKA_TOKEN: False,
            CKA_LABEL: label,
        }
        if malformation == "swap_secret_class_asym_type":
            return (
                int(CKM_EC_KEY_PAIR_GEN),
                {CKA_CLASS: secret, CKA_EC_PARAMS: QC4_P256_PARAMS, **pub_base},
                dict(priv_base),
                (secret, int(CKK_EC)),
            )
        if malformation == "swap_asym_class_secret_type":
            return (
                int(CKM_EC_KEY_PAIR_GEN),
                {
                    CKA_CLASS: public,
                    CKA_KEY_TYPE: int(CKK_AES),
                    CKA_EC_PARAMS: QC4_P256_PARAMS,
                    **pub_base,
                },
                dict(priv_base),
                (public, int(CKK_AES)),
            )
        if malformation == "missing_params":
            return (
                int(CKM_EC_KEY_PAIR_GEN),
                dict(pub_base),
                dict(priv_base),
                (public, int(CKK_EC)),
            )
        raise KeyError(malformation)
    assert pqc is not None
    pub_base = {
        CKA_VERIFY: True,
        CKA_TOKEN: False,
        CKA_LABEL: label,
    }
    if malformation == "swap_secret_class_asym_type":
        return (
            pqc.keygen_mech,
            {CKA_CLASS: secret, CKA_PARAMETER_SET: pqc.param_set, **pub_base},
            dict(priv_base),
            (secret, pqc.key_type),
        )
    if malformation == "swap_asym_class_secret_type":
        return (
            pqc.keygen_mech,
            {
                CKA_CLASS: public,
                CKA_KEY_TYPE: int(CKK_AES),
                CKA_PARAMETER_SET: pqc.param_set,
                **pub_base,
            },
            dict(priv_base),
            (public, int(CKK_AES)),
        )
    if malformation == "missing_params":
        return (
            pqc.keygen_mech,
            dict(pub_base),
            dict(priv_base),
            (public, pqc.key_type),
        )
    raise KeyError(malformation)


def _run_generate_malformed_cell(rs: Any, family: str, malformation: str) -> None:
    label = f"C_GenerateKeyPair malformed {family}/{malformation}"
    if family == "rsa" and not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
        pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
    if family == "ec" and not rs.has_mechanism("EC_KEY_PAIR_GEN"):
        pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
    pqc: PqcFamily | None = resolve_pqc_family(rs) if family == "pqc" else None
    attempt_label = malformed_label("generate", family, malformation)
    ctrl_label = control_label("generate", family, malformation)
    keygen_mech, pub_attrs, priv_attrs, requested = _generate_templates(
        family, pqc, malformation, attempt_label
    )
    ctrl_pub, ctrl_priv = _generate_family_source(rs, family, pqc, label=ctrl_label)
    _cleanup_owned(rs, [ctrl_pub, ctrl_priv])
    try:
        before = _find_by_label(rs, attempt_label)
    except CkrAssertionError as exc:
        void_qc4_setup_exc(exc, (), label=f"{label}: inventory", operation="C_FindObjects")
    pub_tmpl = template(*pack_attrs(pub_attrs))
    priv_tmpl = template(*pack_attrs(priv_attrs))
    mech = mech_simple(keygen_mech)
    pub_handle = CK_OBJECT_HANDLE(0)
    priv_handle = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKeyPair(
        rs.sh,
        mech.byref(),
        pub_tmpl.ptr,
        pub_tmpl.count,
        priv_tmpl.ptr,
        priv_tmpl.count,
        byref(pub_handle),
        byref(priv_handle),
    )
    if rv != int(CKR_OK):
        _adjudicate_malformed_refusal(
            rs,
            rv,
            label=label,
            operation="C_GenerateKeyPair",
            attempt_label=attempt_label,
            before=before,
            spec_ref=_QC4B_SPEC,
        )
        return
    try:
        readback = _inspect_identity(
            rs,
            pub_handle.value,
            label=label,
            operation="C_GenerateKeyPair",
            spec_ref=_QC4B_SPEC,
        )
        priv_readback = _inspect_identity(
            rs,
            priv_handle.value,
            label=label,
            operation="C_GenerateKeyPair",
            spec_ref=_QC4B_SPEC,
        )
        _requested_param_set = pub_attrs.get(CKA_PARAMETER_SET)
        outcomes = _generate_acceptance_uses(
            rs,
            pub_handle.value,
            priv_handle.value,
            family,
            pqc=pqc,
            pub_readback=readback,
            priv_readback=priv_readback,
            pqc_requested_param_set=(
                int(_requested_param_set) if isinstance(_requested_param_set, int) else None
            ),
            label=label,
            spec_ref=_QC4B_SPEC,
        )
        _adjudicate_uses(
            outcomes,
            readback=readback,
            requested=requested,
            pqc_type=pqc.key_type if pqc else 0,
            label=label,
            operation="C_GenerateKeyPair",
            spec_ref=_QC4B_SPEC,
        )
    finally:
        _cleanup_owned(rs, [pub_handle.value, priv_handle.value])


def _generate_acceptance_uses(
    rs: Any,
    pub: int,
    priv: int,
    family: str,
    *,
    pqc: PqcFamily | None,
    pub_readback: tuple[int, int],
    priv_readback: tuple[int, int],
    pqc_requested_param_set: int | None = None,
    label: str,
    spec_ref: str,
) -> list[_UseOutcome]:
    """Run the family use legs for an admitted generate, proving usability.

    BOTH halves are exercised independently with their own role-appropriate
    op (F10): the priv half signs, the pub half encrypts/verifies. Each
    outcome carries its performing handle + identity, so adjudication
    attributes a proved use to the half that performed it -- a malformed
    sibling that never acted indicts nothing.
    """
    if family == "rsa":
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            _xfail_use_unavailable(label, "C_GenerateKeyPair", "CKM_SHA256_RSA_PKCS", spec_ref)
        modulus, exponent = _read_rsa_halves(
            rs, pub, label=label, operation="C_GenerateKeyPair", spec_ref=spec_ref
        )
        priv_outcome = _use_rsa_sign(
            rs,
            priv,
            pub=_rsa_pub_from_halves(modulus, exponent),
            label=label,
            operation="C_GenerateKeyPair",
            spec_ref=spec_ref,
        )
        priv_outcome.performer = priv_readback
        priv_outcome.handle = priv
        # Pub half, role op: encrypt with pub, decrypt locally via the
        # priv half's read-back components (extractable by template).
        priv_modulus, priv_exponent = _read_rsa_halves(
            rs, priv, label=label, operation="C_GenerateKeyPair", spec_ref=spec_ref
        )
        local_priv: Any | None = None
        halves_match = (
            modulus is not None
            and exponent is not None
            and (priv_modulus, priv_exponent) == (modulus, exponent)
        )
        if halves_match:
            assert modulus is not None and exponent is not None
            local_priv = _rsa_priv_from_components(
                modulus,
                exponent,
                _read_optional_bytes(
                    rs,
                    priv,
                    CKA_PRIVATE_EXPONENT,
                    label=label,
                    operation="C_GenerateKeyPair",
                    spec_ref=spec_ref,
                ),
                _read_optional_bytes(
                    rs,
                    priv,
                    CKA_PRIME_1,
                    label=label,
                    operation="C_GenerateKeyPair",
                    spec_ref=spec_ref,
                ),
                _read_optional_bytes(
                    rs,
                    priv,
                    CKA_PRIME_2,
                    label=label,
                    operation="C_GenerateKeyPair",
                    spec_ref=spec_ref,
                ),
                _read_optional_bytes(
                    rs,
                    priv,
                    CKA_EXPONENT_1,
                    label=label,
                    operation="C_GenerateKeyPair",
                    spec_ref=spec_ref,
                ),
                _read_optional_bytes(
                    rs,
                    priv,
                    CKA_EXPONENT_2,
                    label=label,
                    operation="C_GenerateKeyPair",
                    spec_ref=spec_ref,
                ),
                _read_optional_bytes(
                    rs,
                    priv,
                    CKA_COEFFICIENT,
                    label=label,
                    operation="C_GenerateKeyPair",
                    spec_ref=spec_ref,
                ),
            )
        elif (
            modulus is not None
            and exponent is not None
            and priv_modulus is not None
            and priv_exponent is not None
        ):
            fail_as(
                "self_contradiction",
                kind="policy",
                label=label,
                operation="C_GenerateKeyPair",
                inherit_mechanism=False,
                actual=int(CKR_OK),
                spec_ref=spec_ref,
                summary=(
                    f"{label}: generated halves disagree on the public "
                    "components; module self-contradiction"
                ),
                detail={"halves": "mismatched"},
            )
        pub_outcome = _use_rsa_encrypt(
            rs,
            pub,
            private_key=local_priv,
            admitted=(modulus, exponent),
            label=label,
            operation="C_GenerateKeyPair",
            spec_ref=spec_ref,
        )
        pub_outcome.performer = pub_readback
        pub_outcome.handle = pub
        return [priv_outcome, pub_outcome]
    if family == "ec":
        if not rs.has_mechanism("ECDSA"):
            _xfail_use_unavailable(label, "C_GenerateKeyPair", "CKM_ECDSA", spec_ref)
        params, point = _read_ec_halves(
            rs, pub, label=label, operation="C_GenerateKeyPair", spec_ref=spec_ref
        )
        priv_outcome = _use_ec_sign(
            rs,
            priv,
            params=params,
            point=point,
            label=label,
            operation="C_GenerateKeyPair",
            spec_ref=spec_ref,
        )
        priv_outcome.performer = priv_readback
        priv_outcome.handle = priv
        # Pub half, role op: verify with pub, sign locally via the priv
        # half's read-back scalar (extractable by template).
        scalar = _read_optional_bytes(
            rs,
            priv,
            CKA_VALUE,
            label=label,
            operation="C_GenerateKeyPair",
            spec_ref=spec_ref,
        )
        local_key = _ec_priv_from_scalar(scalar)
        if local_key is None or point is None:
            pub_outcome = _UseOutcome(
                use_kind="ec_verify", attempted=False, rvs=[], unverifiable=True
            )
        else:
            derived = local_key.public_key().public_numbers()
            if (int(derived.x), int(derived.y)) != point:
                if params != QC4_P256_PARAMS:
                    pub_outcome = _UseOutcome(
                        use_kind="ec_verify", attempted=False, rvs=[], unverifiable=True
                    )
                else:
                    fail_as(
                        "self_contradiction",
                        kind="policy",
                        label=label,
                        operation="C_GenerateKeyPair",
                        inherit_mechanism=False,
                        actual=int(CKR_OK),
                        spec_ref=spec_ref,
                        summary=(
                            f"{label}: generated scalar does not match the "
                            "read-back point on P-256; module self-contradiction"
                        ),
                        detail={"halves": "mismatched"},
                    )
            else:
                pub_outcome = _use_ec_verify(
                    rs,
                    pub,
                    local_priv=local_key,
                    label=label,
                    operation="C_GenerateKeyPair",
                    spec_ref=spec_ref,
                )
        pub_outcome.performer = pub_readback
        pub_outcome.handle = pub
        return [priv_outcome, pub_outcome]
    assert pqc is not None
    if not rs.has_mechanism(pqc.sign_mech_name):
        _xfail_use_unavailable(label, "C_GenerateKeyPair", ckm_name(pqc.sign_mech), spec_ref)
    # Qualification (N3): the set the template requested when it specified
    # one, else the admitted public key's read-back set. Unqualified
    # leaves the shape gate unfailable at the existing ceiling.
    qualified_set = pqc_requested_param_set
    if qualified_set is None:
        qualified_set = _read_admitted_pqc_param_set(rs, pub, family=pqc, label=label)
    qualified_family = replace(pqc, param_set=qualified_set) if qualified_set is not None else None
    # Module-only coherence with no trusted anchor: recorded, never failable.
    pqc_outcome = _use_pqc_sign_admitted(
        rs,
        priv,
        family=pqc,
        qualified_family=qualified_family,
        verifier=pub,
        label=label,
        operation="C_GenerateKeyPair",
        spec_ref=spec_ref,
        failable=False,
    )
    pqc_outcome.performer = priv_readback
    pqc_outcome.handle = priv
    return [pqc_outcome]


# ---------------------------------------------------------------------------
# QC4c conditional downstream sign leg
# ---------------------------------------------------------------------------


def _run_rsa_sign_downstream(rs: Any, malformation: str) -> None:
    label = f"RSA sign downstream of malformed create {malformation}"
    skip_unless_create_object_supported(rs)
    if not rs.has_mechanism("SHA256_RSA_PKCS"):
        pytest.skip("CKM_SHA256_RSA_PKCS not supported")
    spec_ref = "PKCS#11 v3.2 §6.1.1 RSA sign with a malformed key (defense in depth)"
    attempt_attrs, _ = _create_rsa_templates(malformation, downstream_label(malformation))
    tmpl = template(*pack_attrs(attempt_attrs))
    handle = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
    if rv != int(CKR_OK):
        # F13: only STANDARD refusals skip as inapplicable; undefined fails
        # the metadata contract and vendor takes the visible alternate xfail.
        classify_rv_validity_or_none(rv, label=label, operation="C_CreateObject", kind="policy")
        pytest.skip(
            "inapplicable: malformed object correctly refused; downstream row not exercised"
        )
    try:
        try:
            signature = sign_single(rs.raw, rs.sh, handle.value, CKM_SHA256_RSA_PKCS, QC4_SIGN_DATA)
        except CkrAssertionError as exc:
            classify_rv_validity_or_none(exc.rv, label=label, operation="C_Sign", kind="policy")
            xfail_as(
                "honest_deviation",
                kind="policy",
                label=label,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
                inherit_mechanism=False,
                actual=exc.rv,
                spec_ref=spec_ref,
                summary=(
                    f"{label}: sign path refused with {ckr_name(exc.rv)}; "
                    "defense in depth held at use (not a cryptographic failure)"
                ),
            )
        modulus, exponent = _read_rsa_halves(
            rs, handle.value, label=label, operation="C_Sign", spec_ref=spec_ref
        )
        pub = _rsa_pub_from_halves(modulus, exponent)
        if pub is None:
            xfail_as(
                "honest_deviation",
                kind="policy",
                label=label,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
                inherit_mechanism=False,
                actual=int(CKR_OK),
                spec_ref=spec_ref,
                summary=(
                    f"{label}: admitted key signed but its public half is "
                    "unavailable; exploitability unproved"
                ),
                detail={"disposition": "unproved-effect"},
            )
        if rsa_pkcs15_local(pub, QC4_SIGN_DATA, signature, hashes.SHA256()):
            fail_as(
                "self_contradiction",
                kind="policy",
                label=label,
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
                inherit_mechanism=False,
                actual=int(CKR_OK),
                spec_ref=spec_ref,
                summary=(
                    f"{label}: valid signature from a malformed key "
                    f"(sig_len={len(signature)}); type-confusion exploitability"
                ),
                detail={"sig_len": len(signature)},
            )
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation="C_Sign",
            mechanism="CKM_SHA256_RSA_PKCS",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: admitted key produced an invalid signature "
                f"(sig_len={len(signature)}); crypto wrong_result"
            ),
            detail={"sig_len": len(signature)},
        )
    finally:
        _cleanup_owned(rs, [handle.value])
