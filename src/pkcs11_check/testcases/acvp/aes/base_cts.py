"""Shared helpers for AES-CBC-CS (Ciphertext Stealing) ACVP tests.

Contains CS variant auto-detection, vector loading, and test runners
shared across test_cts_cs1.py, test_cts_cs2.py, test_cts_cs3.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, NoReturn

import pytest

from pkcs11_check.classification import classify, xfail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    get_mechanism_info,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_ENCRYPT,
    CKM_AES_CTS,
    CKR_DEVICE_ERROR,
    CKR_OK,
)
from pkcs11_check.testcases._operability import (
    Operability,
    OperabilityResult,
    classify_kat_clean_error,
)
from pkcs11_check.testcases.acvp.aes.base import _import_aes_key, _load_vectors
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    CIPHER_OP_RUNTIME_REJECT_RVS,
    assert_correct,
    is_known_error,
)

# ---------------------------------------------------------------------------
# Vector loading
# ---------------------------------------------------------------------------


def load_cbc_cs_vectors(
    cs_version: str,
) -> tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]]:
    """Load AES-CBC-CS1/CS2/CS3 ACVP vectors.

    Vectors with non-byte-aligned payloadLen are excluded: PKCS#11
    CKM_AES_CTS operates on whole bytes, but ACVP CBC-CS vectors may
    specify bit-level payloads.  The CTS "stealing" portion changes
    size when rounded to bytes, producing different ciphertext.
    """
    encrypt_fields = {
        "key": "key",
        "iv": "iv",
        "pt": "pt",
        "ct_expected": "ct",
    }
    decrypt_fields = {
        "key": "key",
        "iv": "iv",
        "ct": "ct",
        "pt_expected": "pt",
    }

    encrypt_vecs, decrypt_vecs = _load_vectors(
        f"ACVP-AES-CBC-CS{cs_version}-1.0",
        encrypt_fields,
        decrypt_fields,
        extra_group_fields={"payload_len_bits": "payloadLen"},
    )

    def _byte_aligned(v: dict[str, Any]) -> bool:
        pl = v.get("payload_len_bits")
        return pl is None or pl % 8 == 0

    encrypt_vecs = [(f"CBC-CS{cs_version}-{vid}", v) for vid, v in encrypt_vecs if _byte_aligned(v)]
    decrypt_vecs = [(f"CBC-CS{cs_version}-{vid}", v) for vid, v in decrypt_vecs if _byte_aligned(v)]

    return encrypt_vecs, decrypt_vecs


# ---------------------------------------------------------------------------
# CS variant auto-detection
# ---------------------------------------------------------------------------


class CtsDetectionStatus(Enum):
    """Outcome of the CTS capability/variant probe."""

    ABSENT = "absent"
    SETUP_UNAVAILABLE = "setup_unavailable"
    SETUP_REJECTED = "setup_rejected"
    SETUP_ERROR = "setup_error"
    NOT_OPERATIONAL = "not_operational"
    WRONG_RESULT = "wrong_result"
    DETECTED = "detected"


@dataclass(frozen=True)
class CtsDetectionResult:
    """Structured CTS probe outcome retained by the isolated test process."""

    status: CtsDetectionStatus
    variant: str | None = None
    key_bits: int | None = None
    error_rv: int | None = None
    detail: dict[str, Any] = field(default_factory=dict)


# Each key size has independent fixed-key answers.  Several providers expose
# CTS only for one AES size, so a clean key-size refusal is not enough to call
# the advertised mechanism dead.
_CTS_ORACLE_KEY = bytes(range(16))
_CTS_ORACLE_IV = bytes(16)
_CTS_ORACLE_PLAINTEXT_ALIGNED = bytes(range(32))
_CTS_ORACLE_PLAINTEXT_UNALIGNED = bytes(range(33))
_CTS_ORACLE_OUTPUTS: dict[str, tuple[bytes, bytes]] = {
    "1": (
        bytes.fromhex("0a940bb5416ef045f1c39458c653ea5a3cf456b4ca488aa383c79c98b34797cb"),
        bytes.fromhex("0a940bb5416ef045f1c39458c653ea5a3c805a979c08338ad33b5ab497158f41bf"),
    ),
    "2": (
        bytes.fromhex("0a940bb5416ef045f1c39458c653ea5a3cf456b4ca488aa383c79c98b34797cb"),
        bytes.fromhex("0a940bb5416ef045f1c39458c653ea5a805a979c08338ad33b5ab497158f41bf3c"),
    ),
    "3": (
        bytes.fromhex("3cf456b4ca488aa383c79c98b34797cb0a940bb5416ef045f1c39458c653ea5a"),
        bytes.fromhex("0a940bb5416ef045f1c39458c653ea5a805a979c08338ad33b5ab497158f41bf3c"),
    ),
}

_CTS_ORACLE_CASES: dict[int, tuple[bytes, dict[str, tuple[bytes, bytes]]]] = {
    128: (_CTS_ORACLE_KEY, _CTS_ORACLE_OUTPUTS),
    192: (
        bytes(range(24)),
        {
            "1": (
                bytes.fromhex("0060bffe46834bb8da5cf9a61ff220aeb9770009a06cb2d7f6f296be878bb327"),
                bytes.fromhex("0060bffe46834bb8da5cf9a61ff220aeb9e38155f278d601ee52b3993bedbbbecf"),
            ),
            "2": (
                bytes.fromhex("0060bffe46834bb8da5cf9a61ff220aeb9770009a06cb2d7f6f296be878bb327"),
                bytes.fromhex("0060bffe46834bb8da5cf9a61ff220aee38155f278d601ee52b3993bedbbbecfb9"),
            ),
            "3": (
                bytes.fromhex("b9770009a06cb2d7f6f296be878bb3270060bffe46834bb8da5cf9a61ff220ae"),
                bytes.fromhex("0060bffe46834bb8da5cf9a61ff220aee38155f278d601ee52b3993bedbbbecfb9"),
            ),
        },
    ),
    256: (
        bytes(range(32)),
        {
            "1": (
                bytes.fromhex("5a6e045708fb7196f02e553d02c3a692c77147ebd5121de8d0fae7762423b6bf"),
                bytes.fromhex("5a6e045708fb7196f02e553d02c3a692c77701c065cbc2b06542c46d328514483e"),
            ),
            "2": (
                bytes.fromhex("5a6e045708fb7196f02e553d02c3a692c77147ebd5121de8d0fae7762423b6bf"),
                bytes.fromhex("5a6e045708fb7196f02e553d02c3a6927701c065cbc2b06542c46d328514483ec7"),
            ),
            "3": (
                bytes.fromhex("c77147ebd5121de8d0fae7762423b6bf5a6e045708fb7196f02e553d02c3a692"),
                bytes.fromhex("5a6e045708fb7196f02e553d02c3a6927701c065cbc2b06542c46d328514483ec7"),
            ),
        },
    ),
}
_CTS_ORACLE_PROBE_ORDER = (256, 192, 128)


def skip_unless_cts_encrypt_decrypt(rs: Any) -> None:
    """Skip CTS vector probes unless C_GetMechanismInfo advertises enc/dec."""
    if not rs.has_mechanism("AES_CTS"):
        pytest.skip("CKM_AES_CTS not supported by module")
    info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_CTS)
    required = int(CKF_ENCRYPT) | int(CKF_DECRYPT)
    if int(info["flags"]) & required != required:
        pytest.skip("CKM_AES_CTS does not advertise CKF_ENCRYPT|CKF_DECRYPT")


def _output_detail(expected: bytes, actual: bytes) -> dict[str, Any]:
    """Describe an exact output mismatch without truncating provider bytes."""
    return {
        "expected": expected.hex(),
        "actual": actual.hex(),
        "expected_length": len(expected),
        "actual_length": len(actual),
    }


def _attempt_detail(
    *,
    stage: str,
    operation: str,
    key_bits: int,
    case: str | None,
    ckr: int | None,
    **extra: Any,
) -> dict[str, Any]:
    """Return a uniformly shaped, auditable detector attempt record."""
    return {
        "stage": stage,
        "operation": operation,
        "key_bits": key_bits,
        "case": case,
        "ckr": ckr,
        **extra,
    }


def _wrong_output_detail(
    key_bits: int,
    expected_by_variant: dict[str, tuple[bytes, bytes]],
    *,
    viable_variants: tuple[str, ...],
    aligned: bytes | None = None,
    unaligned: bytes | None = None,
) -> dict[str, Any]:
    """Describe an exact KAT output that eliminated every variant candidate."""
    detail: dict[str, Any] = {
        "key_bits": key_bits,
        "viable_variants": [f"CS{variant}" for variant in viable_variants],
        "expected_variants": {
            f"CS{variant}": {
                "aligned": expected_pair[0].hex(),
                "unaligned": expected_pair[1].hex(),
            }
            for variant, expected_pair in expected_by_variant.items()
        },
        "output": {},
    }

    def mismatch_detail(output_index: int, actual: bytes) -> dict[str, Any]:
        expected_details = {
            f"CS{variant}": {
                "expected": expected_by_variant[variant][output_index].hex(),
                "expected_length": len(expected_by_variant[variant][output_index]),
            }
            for variant in viable_variants
        }
        if len(viable_variants) == 1:
            return _output_detail(
                expected_by_variant[viable_variants[0]][output_index],
                actual,
            )
        return {
            "actual": actual.hex(),
            "actual_length": len(actual),
            "expected_by_variant": expected_details,
        }

    if aligned is not None:
        detail["output"]["aligned"] = mismatch_detail(0, aligned)
    if unaligned is not None:
        detail["output"]["unaligned"] = mismatch_detail(1, unaligned)
    return detail


def _detect_cts_variant(rs: Any) -> CtsDetectionResult:
    """Detect which CBC-CS variant (CS1/CS2/CS3) the module implements.

    Uses two exact, independent fixed-key known-answer probes.  The aligned
    32-byte answer distinguishes CS3 (the final two blocks are swapped) from
    CS1/CS2.  The unaligned 33-byte answer distinguishes CS1 (the partial
    stolen block comes first) from CS2/CS3.  No provider CBC result is used as
    an oracle, and every returned byte (including length) must match.

    Returns a structured status.  A clean operation refusal is
    ``NOT_OPERATIONAL``; CKR_OK with bytes that do not match an independent
    KAT is ``WRONG_RESULT`` and is never downgraded to an xfail.  A CKR
    outside the known runtime-reject tuples is ``SETUP_ERROR``: gathered here
    so collection survives, re-raised by the sentinel reporter at runtime.
    """
    if not rs.has_mechanism("AES_CTS"):
        return CtsDetectionResult(CtsDetectionStatus.ABSENT)

    successful: list[tuple[int, str]] = []
    attempted: list[dict[str, Any]] = []
    last_operation_error_rv: int | None = None
    last_setup_error_rv: int | None = None
    last_operation_unlisted_rv: int | None = None
    last_setup_unlisted_rv: int | None = None
    setup_unavailable = False
    setup_rejected = False
    operation_attempted = False

    # Keep the established 256-bit-first preference; providers that expose
    # only 192- or 128-bit CTS still fall through deterministically.
    for key_bits in _CTS_ORACLE_PROBE_ORDER:
        oracle_key, expected_by_variant = _CTS_ORACLE_CASES[key_bits]
        key = 0
        try:
            key = _import_aes_key(rs, oracle_key, encrypt=True, decrypt=False)
        except pytest.skip.Exception:
            setup_unavailable = True
            attempted.append(
                _attempt_detail(
                    stage="setup",
                    operation="C_CreateObject",
                    key_bits=key_bits,
                    case=None,
                    ckr=None,
                )
            )
            continue
        except CkrAssertionError as exc:
            # Off-contract CKRs are gathered, never raised: raising here becomes
            # a pytest INTERNALERROR that deletes the whole file (round-0197 wolf
            # evidence). The sentinel reporter re-raises the last off-contract
            # code at runtime, where the plugin gate records it as a finding.
            setup_rejected = True
            last_setup_error_rv = exc.rv
            if not is_known_error(exc, AES_KEYGEN_RUNTIME_REJECT_RVS):
                last_setup_unlisted_rv = exc.rv
            attempted.append(
                _attempt_detail(
                    stage="setup",
                    operation="C_CreateObject",
                    key_bits=key_bits,
                    case=None,
                    ckr=exc.rv,
                )
            )
            continue

        try:
            candidates = set(expected_by_variant)
            actual_aligned: bytes | None = None
            for case, plaintext, output_index in (
                ("aligned", _CTS_ORACLE_PLAINTEXT_ALIGNED, 0),
                ("unaligned", _CTS_ORACLE_PLAINTEXT_UNALIGNED, 1),
            ):
                operation_attempted = True
                try:
                    actual = bytes(
                        encrypt_single(
                            rs.raw,
                            rs.sh,
                            key,
                            CKM_AES_CTS,
                            plaintext,
                            mech_param=mech_bytes(CKM_AES_CTS, _CTS_ORACLE_IV),
                        )
                    )
                except CkrAssertionError as exc:
                    # Gathered, never raised: see the setup-stage note above.
                    last_operation_error_rv = exc.rv
                    if not is_known_error(exc, CIPHER_OP_RUNTIME_REJECT_RVS):
                        last_operation_unlisted_rv = exc.rv
                    attempted.append(
                        _attempt_detail(
                            stage="operation",
                            operation="C_Encrypt",
                            key_bits=key_bits,
                            case=case,
                            ckr=exc.rv,
                        )
                    )
                    break

                attempted.append(
                    _attempt_detail(
                        stage="operation",
                        operation="C_Encrypt",
                        key_bits=key_bits,
                        case=case,
                        ckr=int(CKR_OK),
                    )
                )
                if case == "aligned":
                    actual_aligned = actual
                viable_candidates = tuple(sorted(candidates))
                candidates = {
                    candidate
                    for candidate in candidates
                    if expected_by_variant[candidate][output_index] == actual
                }
                if not candidates:
                    detail = _wrong_output_detail(
                        key_bits,
                        expected_by_variant,
                        viable_variants=viable_candidates,
                        aligned=actual_aligned,
                        unaligned=actual if case == "unaligned" else None,
                    )
                    detail["attempts"] = attempted
                    return CtsDetectionResult(
                        CtsDetectionStatus.WRONG_RESULT,
                        key_bits=key_bits,
                        detail=detail,
                    )
            else:
                variant = next(iter(candidates))
                attempted[-1]["variant"] = variant
                successful.append((key_bits, variant))
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)

    if not successful:
        # Off-contract evidence dominates clean rejects: a definitive answer
        # (DETECTED/WRONG_RESULT) already returned above, so anything left
        # carrying an unlisted CKR is a detection error. The operation flavor
        # wins over setup: reaching the encrypt stage means setup recovered.
        if last_operation_unlisted_rv is not None:
            return CtsDetectionResult(
                CtsDetectionStatus.SETUP_ERROR,
                error_rv=last_operation_unlisted_rv,
                detail={"attempts": attempted},
            )
        if last_setup_unlisted_rv is not None:
            return CtsDetectionResult(
                CtsDetectionStatus.SETUP_ERROR,
                error_rv=last_setup_unlisted_rv,
                detail={"attempts": attempted},
            )
        if operation_attempted:
            return CtsDetectionResult(
                CtsDetectionStatus.NOT_OPERATIONAL,
                error_rv=last_operation_error_rv,
                detail={"attempts": attempted},
            )
        if setup_unavailable:
            return CtsDetectionResult(
                CtsDetectionStatus.SETUP_UNAVAILABLE,
                detail={"attempts": attempted},
            )
        if setup_rejected:
            return CtsDetectionResult(
                CtsDetectionStatus.SETUP_REJECTED,
                error_rv=last_setup_error_rv,
                detail={"attempts": attempted},
            )
        return CtsDetectionResult(CtsDetectionStatus.ABSENT, detail={"attempts": attempted})

    variants = {variant for _key_bits, variant in successful}
    if len(variants) != 1:
        return CtsDetectionResult(
            CtsDetectionStatus.WRONG_RESULT,
            detail={"attempts": attempted, "reason": "inconsistent CTS variant by key size"},
        )
    return CtsDetectionResult(
        CtsDetectionStatus.DETECTED,
        variant=successful[0][1],
        key_bits=successful[0][0],
        detail={"attempts": attempted},
    )


# Module-level cache for the structured detector result.
_cts_detection_result: CtsDetectionResult | None = None


def reset_cts_detection_cache() -> None:
    """Forget the per-process CTS detector result (test hook)."""
    global _cts_detection_result  # noqa: PLW0603
    _cts_detection_result = None


def get_cts_detection(rs: Any) -> CtsDetectionResult:
    """Get or detect the structured CTS result, cached within one isolated process."""
    global _cts_detection_result  # noqa: PLW0603
    if _cts_detection_result is None:
        _cts_detection_result = _detect_cts_variant(rs)
    return _cts_detection_result


def get_detected_variant(rs: Any) -> str | None:
    """Compatibility helper returning the detected variant, if any."""
    return get_cts_detection(rs).variant


def report_cts_detection(result: CtsDetectionResult) -> None:
    """Emit the one authoritative pytest outcome for a CTS detection result."""
    label = "CKM_AES_CTS:variant-detection"
    if result.status is CtsDetectionStatus.ABSENT:
        pytest.skip("CKM_AES_CTS not supported by module")
    if result.status is CtsDetectionStatus.SETUP_UNAVAILABLE:
        pytest.skip("C_CreateObject capability unavailable for CKM_AES_CTS detection")
    if result.status is CtsDetectionStatus.SETUP_REJECTED:
        classify(
            "not_operational",
            kind="crypto",
            label=label,
            operation="C_CreateObject",
            mechanism="CKM_AES_CTS",
            actual=result.error_rv,
            summary="CKM_AES_CTS fixed-key detection could not import its probe key",
            detail=result.detail,
        )
    if result.status is CtsDetectionStatus.NOT_OPERATIONAL:
        classify(
            "not_operational",
            kind="crypto",
            label=label,
            operation="C_Encrypt",
            mechanism="CKM_AES_CTS",
            actual=result.error_rv,
            summary=("CKM_AES_CTS advertised but fixed-key variant detection was not operational"),
            detail=result.detail,
        )
    if result.status is CtsDetectionStatus.WRONG_RESULT:
        classify(
            "wrong_result",
            kind="crypto",
            label=label,
            operation="C_Encrypt",
            mechanism="CKM_AES_CTS",
            summary="CKM_AES_CTS fixed-key variant detection returned incorrect ciphertext",
            detail=result.detail,
        )
    if result.status is CtsDetectionStatus.SETUP_ERROR:
        # Re-raise at runtime: collection contained the off-contract CKR so the
        # file survives; the plugin gate now records it as a provider finding,
        # exactly like any other unlisted CKR from a positive probe.
        rv = result.error_rv
        if rv is None:
            raise RuntimeError(
                "CTS detection reported setup_error without a CKR; the detector misbuilt the result"
            )
        attempts = result.detail.get("attempts", []) if result.detail else []
        if not attempts:
            # Probe-scaffolding failures (login, session, mechanism list) carry
            # the provider's answer as a reason string instead of attempts.
            reason = (result.detail or {}).get("reason", "detection scaffolding failed")
            raise CkrAssertionError(
                f"CTS detection setup failed: {reason} ({ckr_name(rv)} outside the known contract)",
                int(rv),
            )
        # error_rv carries operation priority, so the naming attempt is the
        # last one that recorded this CKR -- not necessarily the last attempt.
        last = next(
            (attempt for attempt in reversed(attempts) if attempt.get("ckr") == rv),
            attempts[-1],
        )
        raise CkrAssertionError(
            f"CTS detection {last.get('stage', 'detection')} "
            f"{last.get('operation', 'C_CreateObject')} rejected with "
            f"{ckr_name(rv)} outside the known contract",
            int(rv),
        )


def skip_unless_cts_variant(rs: Any, expected_cs: str) -> None:
    """Skip test if module's CTS variant doesn't match expected_cs."""
    skip_unless_cts_encrypt_decrypt(rs)
    result = get_cts_detection(rs)
    report_cts_detection(result)
    if result.variant != expected_cs:
        pytest.skip(f"Module implements CS{result.variant}, skipping CS{expected_cs} vectors")


# ---------------------------------------------------------------------------
# Test runners
# ---------------------------------------------------------------------------


def _cts_operability(rs: Any) -> OperabilityResult:
    """CTS operability from the existing variant-detection canonical probe.

    Variant detection runs canonical CKM_AES_CTS encrypts and classifies the
    EFFECT (CS1/CS2/CS3).  A clean refusal is not-operational evidence, while
    a CKR_OK wrong result remains a crypto failure and must not be downgraded.
    """
    result = get_cts_detection(rs)
    if result.status is CtsDetectionStatus.WRONG_RESULT:
        return OperabilityResult(
            Operability.WRONG_OUTPUT,
            "canonical CTS variant-detection returned wrong ciphertext",
        )
    if result.status.value in {
        CtsDetectionStatus.SETUP_UNAVAILABLE.value,
        CtsDetectionStatus.SETUP_REJECTED.value,
        CtsDetectionStatus.SETUP_ERROR.value,
    }:
        return OperabilityResult(
            Operability.INCONCLUSIVE,
            f"canonical CTS variant-detection setup is {result.status.value}",
        )
    if result.status is not CtsDetectionStatus.DETECTED:
        return OperabilityResult(
            Operability.NOT_OPERATIONAL,
            f"canonical CTS variant-detection is {result.status.value}",
        )
    return OperabilityResult(Operability.OPERATIONAL, f"CTS variant CS{result.variant} detected")


def _handle_cts_error(rs: Any, exc: CkrAssertionError, vec_id: str, direction: str) -> NoReturn:
    """Handle CTS encrypt/decrypt errors with appropriate reporting."""
    if is_known_error(exc, {CKR_DEVICE_ERROR}):
        note(
            f"CKM_AES_CTS {direction} returned CKR_DEVICE_ERROR for {vec_id}. "
            "Module advertises CTS but fails on valid input.",
            ComplianceLevel.CRITICAL,
            reference="PKCS#11 v3.2 CKM_AES_CTS",
        )
        xfail_as(
            "not_operational",
            kind="crypto",
            label=f"CKM_AES_CTS:{direction}",
            summary=f"CKM_AES_CTS advertised but CBC-CS {direction} failed: {exc}",
        )
    classify_kat_clean_error(
        exc, result=_cts_operability(rs), label=f"CKM_AES_CTS CBC-CS {direction}"
    )


def run_cbc_cs_encrypt_test(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """Run AES-CBC-CS encrypt test."""
    rs = p11_module_session
    if not rs.has_mechanism("AES_CTS"):
        pytest.skip("AES_CTS not supported by module")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=True, decrypt=False)
        try:
            mech = mech_bytes(CKM_AES_CTS, vec["iv"])
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CTS,
                vec["pt"],
                mech_param=mech,
            )
        except CkrAssertionError as exc:
            _handle_cts_error(rs, exc, vec_id, "encrypt")

        assert_correct(
            actual=ct,
            expected=vec["ct_expected"],
            label=f"AES-CTS:C_Encrypt KAT {vec_id}",
            operation="C_Encrypt",
            mechanism="CKM_AES_CTS",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


def run_cbc_cs_decrypt_test(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """Run AES-CBC-CS decrypt test."""
    rs = p11_module_session
    if not rs.has_mechanism("AES_CTS"):
        pytest.skip("AES_CTS not supported by module")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=False, decrypt=True)
        try:
            mech = mech_bytes(CKM_AES_CTS, vec["iv"])
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CTS,
                vec["ct"],
                mech_param=mech,
            )
        except CkrAssertionError as exc:
            _handle_cts_error(rs, exc, vec_id, "decrypt")

        assert_correct(
            actual=pt,
            expected=vec["pt_expected"],
            label=f"AES-CTS:C_Decrypt KAT {vec_id}",
            operation="C_Decrypt",
            mechanism="CKM_AES_CTS",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)
