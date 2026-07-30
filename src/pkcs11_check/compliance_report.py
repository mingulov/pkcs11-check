"""Machine-readable PKCS#11 compliance report generator.

Produces a JSON compliance matrix covering mechanism support, function
test coverage, CKR spec coverage, and compliance notes.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pkcs11_check.compliance import ComplianceNote, get_notes
from pkcs11_check.core.report_log import iter_report_log_records
from pkcs11_check.core.run_metrics import RESULT_OUTCOME_KEYS as _OUTCOME_KEYS

# _OUTCOME_KEYS is the single canonical outcome vocabulary (core.run_metrics); importing it
# here (rather than re-listing it) keeps the compliance counts in lockstep with the metrics
# and report layers if a new outcome status is ever added.

_COMPLIANCE_NOTE_FIELDS: tuple[str, ...] = (
    "description",
    "level",
    "reference",
    "test_id",
    "nodeid",
)


def _empty_test_counts() -> dict[str, int]:
    counts = {key: 0 for key in _OUTCOME_KEYS}
    counts["tests"] = 0
    return counts


def _count_value(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return max(value, 0)
    return 0


def _counts_for_base(counts: dict[str, dict[str, int]], base: str) -> dict[str, int]:
    if base not in counts:
        counts[base] = _empty_test_counts()
    return counts[base]


def _outcome_from_status(status: str) -> str:
    if status in _OUTCOME_KEYS:
        return status
    if status == "crash":
        return "crashed"
    if status in {"errored", "error"}:
        return "error"
    return "error"


def _outcome_from_pytest_report(outcome: str, wasxfail: Any) -> str:
    if outcome == "passed" and wasxfail is not None:
        return "xpassed"
    if outcome == "skipped" and wasxfail is not None:
        return "xfailed"
    return _outcome_from_status(outcome)


def _add_outcome(counts: dict[str, int], outcome: str, amount: int = 1) -> None:
    normalized = _outcome_from_status(outcome)
    clean_amount = max(amount, 0)
    counts[normalized] += clean_amount
    counts["tests"] += clean_amount


def _status_from_counts(totals: Mapping[str, int]) -> str:
    total_tests = sum(int(totals.get(key, 0)) for key in _OUTCOME_KEYS)
    if total_tests == 0:
        return "NOT_TESTED"
    if totals.get("timeout", 0) > 0:
        return "TIMEOUT"
    if totals.get("crashed", 0) > 0:
        return "CRASHED"
    if totals.get("error", 0) > 0:
        return "ERROR"
    if totals.get("failed", 0) > 0:
        return "FAIL"
    if totals.get("xfailed", 0) > 0:
        return "XFAIL"
    if totals.get("xpassed", 0) > 0:
        return "XPASS"
    if totals.get("passed", 0) > 0:
        return "PASS"
    return "SKIP"


# ---------------------------------------------------------------------------
# Standard PKCS#11 mechanism names (representative subset)
# ---------------------------------------------------------------------------

STANDARD_MECHANISMS: list[str] = [
    # RSA
    "RSA_PKCS_KEY_PAIR_GEN",
    "RSA_PKCS",
    "RSA_PKCS_OAEP",
    "RSA_PKCS_PSS",
    "SHA1_RSA_PKCS",
    "SHA256_RSA_PKCS",
    "SHA384_RSA_PKCS",
    "SHA512_RSA_PKCS",
    "SHA256_RSA_PKCS_PSS",
    "SHA384_RSA_PKCS_PSS",
    "SHA512_RSA_PKCS_PSS",
    # AES
    "AES_KEY_GEN",
    "AES_CBC",
    "AES_CBC_PAD",
    "AES_GCM",
    "AES_CTR",
    "AES_ECB",
    "AES_KEY_WRAP",
    "AES_KEY_WRAP_PAD",
    # EC
    "EC_KEY_PAIR_GEN",
    "ECDSA",
    "ECDSA_SHA256",
    "ECDSA_SHA384",
    "ECDSA_SHA512",
    "ECDH1_DERIVE",
    # EdDSA / Edwards
    "EC_EDWARDS_KEY_PAIR_GEN",
    "EDDSA",
    # Digest
    "SHA_1",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA224",
    "SHA3_256",
    "SHA3_384",
    "SHA3_512",
    # HMAC
    "SHA256_HMAC",
    "SHA384_HMAC",
    "SHA512_HMAC",
    "SHA_1_HMAC",
    # Key derivation
    "GENERIC_SECRET_KEY_GEN",
    "HKDF_DERIVE",
    "HKDF_DATA",
    # PQC (v3.2)
    "ML_KEM_KEY_PAIR_GEN",
    "ML_KEM",
    "ML_DSA_KEY_PAIR_GEN",
    "ML_DSA",
    "SLH_DSA_KEY_PAIR_GEN",
    "SLH_DSA",
    # DES/3DES (legacy)
    "DES3_KEY_GEN",
    "DES3_CBC",
    "DES3_ECB",
    "DES3_MAC",
    "DES3_CMAC",
    # DH
    "DH_PKCS_KEY_PAIR_GEN",
    "DH_PKCS_DERIVE",
    "DH_PKCS_PARAMETER_GEN",
    "X9_42_DH_KEY_PAIR_GEN",
    "X9_42_DH_DERIVE",
    # DSA
    "DSA_KEY_PAIR_GEN",
    "DSA",
    "DSA_SHA256",
    "DSA_SHA384",
    "DSA_SHA512",
    "DSA_PARAMETER_GEN",
    # Additional AES
    "AES_CCM",
    "AES_CMAC",
    "AES_GMAC",
    "AES_XTS",
    "AES_CTS",
    "AES_CFB128",
    "AES_OFB",
    "AES_MAC",
    # Additional RSA
    "RSA_X_509",
    "RSA_AES_KEY_WRAP",
    "SHA224_RSA_PKCS",
    "SHA224_RSA_PKCS_PSS",
    "SHA1_RSA_PKCS_PSS",
    "SHA3_256_RSA_PKCS",
    "SHA3_256_RSA_PKCS_PSS",
    # Additional EC
    "ECDSA_SHA1",
    "ECDSA_SHA224",
    "ECDSA_SHA3_256",
    "ECDSA_SHA3_384",
    "ECDSA_SHA3_512",
    "EC_MONTGOMERY_KEY_PAIR_GEN",
    "ECDH1_COFACTOR_DERIVE",
    # Additional hash/HMAC
    "SHA3_224",
    "SHA224_HMAC",
    "SHA3_224_HMAC",
    "SHA3_256_HMAC",
    "SHA3_384_HMAC",
    "SHA3_512_HMAC",
    "SHA512_224_HMAC",
    "SHA512_256_HMAC",
    # KDF
    "SP800_108_COUNTER_KDF",
    "SP800_108_FEEDBACK_KDF",
    "PKCS5_PBKD2",
    "HKDF_KEY_GEN",
    # PQC extended
    "HASH_ML_DSA",
    "HASH_SLH_DSA",
    "HSS_KEY_PAIR_GEN",
    "HSS",
    "XMSS_KEY_PAIR_GEN",
    "XMSS",
    # Stream ciphers
    "CHACHA20_POLY1305",
    # Regional ciphers
    "CAMELLIA_KEY_GEN",
    "CAMELLIA_ECB",
    "CAMELLIA_CBC",
    "ARIA_KEY_GEN",
    "ARIA_ECB",
    "ARIA_CBC",
    "SEED_KEY_GEN",
    "SEED_ECB",
    "SEED_CBC",
    "BLOWFISH_KEY_GEN",
    "BLOWFISH_CBC",
    "TWOFISH_KEY_GEN",
    "TWOFISH_CBC",
    # Protocol
    "TLS12_MASTER_KEY_DERIVE",
    "TLS12_KEY_AND_MAC_DERIVE",
    "SSL3_PRE_MASTER_KEY_GEN",
    "SSL3_MASTER_KEY_DERIVE",
]

# ---------------------------------------------------------------------------
# Standard PKCS#11 C_* functions
# ---------------------------------------------------------------------------

STANDARD_FUNCTIONS: list[str] = [
    # General-purpose
    "C_Initialize",
    "C_Finalize",
    "C_GetInfo",
    # Slot and token management
    "C_GetSlotList",
    "C_GetSlotInfo",
    "C_GetTokenInfo",
    "C_GetMechanismList",
    "C_GetMechanismInfo",
    "C_InitToken",
    "C_InitPIN",
    "C_SetPIN",
    # Session management
    "C_OpenSession",
    "C_CloseSession",
    "C_CloseAllSessions",
    "C_GetSessionInfo",
    "C_GetOperationState",
    "C_SetOperationState",
    "C_Login",
    "C_Logout",
    # Object management
    "C_CreateObject",
    "C_CopyObject",
    "C_DestroyObject",
    "C_GetObjectSize",
    "C_GetAttributeValue",
    "C_SetAttributeValue",
    "C_FindObjectsInit",
    "C_FindObjects",
    "C_FindObjectsFinal",
    # Encryption
    "C_EncryptInit",
    "C_Encrypt",
    "C_EncryptUpdate",
    "C_EncryptFinal",
    # Decryption
    "C_DecryptInit",
    "C_Decrypt",
    "C_DecryptUpdate",
    "C_DecryptFinal",
    # Digest
    "C_DigestInit",
    "C_Digest",
    "C_DigestUpdate",
    "C_DigestFinal",
    # Signing
    "C_SignInit",
    "C_Sign",
    "C_SignUpdate",
    "C_SignFinal",
    # Verification
    "C_VerifyInit",
    "C_Verify",
    "C_VerifyUpdate",
    "C_VerifyFinal",
    # Key management
    "C_GenerateKey",
    "C_GenerateKeyPair",
    "C_WrapKey",
    "C_UnwrapKey",
    "C_DeriveKey",
    # Random
    "C_SeedRandom",
    "C_GenerateRandom",
    # Misc
    "C_WaitForSlotEvent",
    # v3.0+
    "C_LoginUser",
    "C_SessionCancel",
    "C_GetInterfaceList",
    "C_GetInterface",
    # v3.0 message-based
    "C_MessageEncryptInit",
    "C_EncryptMessage",
    "C_MessageDecryptInit",
    "C_DecryptMessage",
    "C_MessageSignInit",
    "C_SignMessage",
    "C_MessageVerifyInit",
    "C_VerifyMessage",
    # v3.2 KEM
    "C_EncapsulateKey",
    "C_DecapsulateKey",
    # Dual-function
    "C_DigestEncryptUpdate",
    "C_DecryptDigestUpdate",
    "C_SignEncryptUpdate",
    "C_DecryptVerifyUpdate",
    # Sign/Verify recover
    "C_SignRecoverInit",
    "C_SignRecover",
    "C_VerifyRecoverInit",
    "C_VerifyRecover",
    # Digest key
    "C_DigestKey",
]

# ---------------------------------------------------------------------------
# Function-to-test keyword mapping
# ---------------------------------------------------------------------------

# Maps PKCS#11 function names to pytest marker/keyword patterns that exercise them.
_FUNCTION_KEYWORDS: dict[str, list[str]] = {
    # General-purpose
    "C_Initialize": ["test_init", "test_interface"],
    "C_Finalize": ["test_init", "test_reinitialize"],
    "C_GetInfo": ["test_init", "test_interface", "test_token_flags"],
    # Slot and token management
    "C_GetSlotList": ["test_slot"],
    "C_GetSlotInfo": ["test_slot", "test_token_flags"],
    "C_GetTokenInfo": ["test_slot", "test_token_flags"],
    "C_GetMechanismList": ["test_slot", "test_mechanism", "test_surface_audit"],
    "C_GetMechanismInfo": ["test_slot", "test_mechanism"],
    "C_InitToken": ["test_init", "test_pin"],
    "C_InitPIN": ["test_access_levels", "test_pin", "test_so_pin"],
    "C_SetPIN": ["test_access_levels", "test_pin", "test_so_pin"],
    "C_WaitForSlotEvent": ["test_slot"],
    # Session management
    "C_OpenSession": ["test_session", "test_ro_session", "test_session_state_machine"],
    "C_CloseSession": ["test_session", "test_session_edge_cases"],
    "C_CloseAllSessions": ["test_session", "test_session_edge_cases"],
    "C_GetSessionInfo": ["test_session", "test_session_info"],
    "C_GetOperationState": ["test_operation_state"],
    "C_SetOperationState": ["test_operation_state"],
    "C_Login": ["test_session", "test_access_levels", "test_session_state_machine"],
    "C_Logout": ["test_session", "test_access_levels", "test_session_state_machine"],
    "C_LoginUser": ["test_v30_session"],
    "C_SessionCancel": ["test_v30_session"],
    # Object management
    "C_CreateObject": ["test_object", "test_data_objects"],
    "C_CopyObject": ["test_access_control", "test_api_security"],
    "C_DestroyObject": ["test_object", "test_attribute_enforcement"],
    "C_GetObjectSize": ["test_object_size"],
    "C_GetAttributeValue": ["test_object", "test_attribute_enforcement", "test_attribute_defaults"],
    "C_SetAttributeValue": ["test_set_attribute", "test_attribute_enforcement"],
    "C_FindObjectsInit": ["test_search", "test_object_visibility", "test_object_search_patterns"],
    "C_FindObjects": ["test_search", "test_object_visibility", "test_object_search_patterns"],
    "C_FindObjectsFinal": ["test_search", "test_object_visibility"],
    # Encryption
    "C_EncryptInit": ["test_encrypt", "test_aes_modes"],
    "C_Encrypt": ["test_encrypt", "test_aes_modes"],
    "C_EncryptUpdate": ["test_encrypt", "test_multipart"],
    "C_EncryptFinal": ["test_encrypt", "test_multipart"],
    # Decryption
    "C_DecryptInit": ["test_encrypt", "test_aes_modes"],
    "C_Decrypt": ["test_encrypt", "test_aes_modes"],
    "C_DecryptUpdate": ["test_encrypt", "test_multipart"],
    "C_DecryptFinal": ["test_encrypt", "test_multipart"],
    # Digest
    "C_DigestInit": ["test_digest", "test_sha3"],
    "C_Digest": ["test_digest", "test_sha3"],
    "C_DigestUpdate": ["test_digest", "test_multipart"],
    "C_DigestFinal": ["test_digest", "test_multipart"],
    "C_DigestKey": ["test_digest"],
    # Signing
    "C_SignInit": ["test_sign", "test_pqc_sign"],
    "C_Sign": ["test_sign", "test_pqc_sign"],
    "C_SignUpdate": ["test_sign", "test_multipart"],
    "C_SignFinal": ["test_sign", "test_multipart"],
    "C_SignRecoverInit": ["test_sign_recover"],
    "C_SignRecover": ["test_sign_recover"],
    # Verification
    "C_VerifyInit": ["test_sign", "test_crossverify"],
    "C_Verify": ["test_sign", "test_crossverify"],
    "C_VerifyUpdate": ["test_sign", "test_multipart"],
    "C_VerifyFinal": ["test_sign", "test_multipart"],
    "C_VerifyRecoverInit": ["test_sign_recover"],
    "C_VerifyRecover": ["test_sign_recover"],
    # Dual-function
    "C_DigestEncryptUpdate": ["test_dual_function"],
    "C_DecryptDigestUpdate": ["test_dual_function"],
    "C_SignEncryptUpdate": ["test_dual_function"],
    "C_DecryptVerifyUpdate": ["test_dual_function"],
    # Key management
    "C_GenerateKey": ["test_keymgmt", "test_encrypt", "test_aes_modes"],
    "C_GenerateKeyPair": ["test_keymgmt", "test_sign", "test_pqc_sign"],
    "C_WrapKey": ["test_keymgmt", "test_rsa_key_wrapping", "test_authenticated_wrap"],
    "C_UnwrapKey": ["test_keymgmt", "test_rsa_key_wrapping", "test_authenticated_wrap"],
    "C_DeriveKey": ["test_kdf", "test_ecdh", "test_dh_key_agreement", "test_hkdf"],
    # Random
    "C_SeedRandom": ["test_rng"],
    "C_GenerateRandom": ["test_rng"],
    # v3.0 interface
    "C_GetInterfaceList": ["test_interface", "test_interface_negotiation"],
    "C_GetInterface": ["test_interface", "test_interface_negotiation"],
    # v3.0 message-based
    "C_MessageEncryptInit": ["test_aead"],
    "C_EncryptMessage": ["test_aead"],
    "C_MessageDecryptInit": ["test_aead"],
    "C_DecryptMessage": ["test_aead"],
    "C_MessageSignInit": ["test_aead"],
    "C_SignMessage": ["test_aead"],
    "C_MessageVerifyInit": ["test_aead"],
    "C_VerifyMessage": ["test_aead"],
    # v3.2 KEM
    "C_EncapsulateKey": ["test_kem"],
    "C_DecapsulateKey": ["test_kem"],
}


def _collect_mechanisms(module: Any, slot_index: int = 0) -> dict[str, str]:
    """Probe module for mechanism support against the standard list."""
    result: dict[str, str] = {}
    try:
        slots = module.get_slots(token_present=True)
    except Exception:
        return {m: "ERROR" for m in STANDARD_MECHANISMS}

    if slot_index >= len(slots):
        return {m: "ERROR" for m in STANDARD_MECHANISMS}

    slot = slots[slot_index]
    try:
        supported = slot.get_mechanisms()
    except Exception:
        return {m: "ERROR" for m in STANDARD_MECHANISMS}

    supported_names: set[str] = set()
    for mech in supported:
        name = getattr(mech, "name", None)
        if isinstance(name, str):
            supported_names.add(name)
        else:
            supported_names.add(str(mech))

    for mech_name in STANDARD_MECHANISMS:
        if mech_name in supported_names:
            result[mech_name] = "SUPPORTED"
        else:
            result[mech_name] = "NOT_SUPPORTED"

    return result


def _parse_test_results(
    results_path: Path,
) -> dict[str, dict[str, int]]:
    """Parse a pytest-json-report, pkcs11-check isolated, or unified results JSON.

    Returns a mapping of test file base name to outcome counts.
    """
    data = json.loads(results_path.read_text(encoding="utf-8"))

    counts: dict[str, dict[str, int]] = {}

    # Unified format: {"kind": "test-run", "units": [{"target": ..., "counts": ...}]}
    if data.get("kind") == "test-run":
        for unit in data.get("units", []):
            target = unit.get("target", "")
            base = target.split("::")[0].split("/")[-1].replace(".py", "")
            if not base:
                continue
            base_counts = _counts_for_base(counts, base)
            unit_counts = unit.get("counts")
            if isinstance(unit_counts, dict):
                outcome_total = 0
                for key in _OUTCOME_KEYS:
                    value = _count_value(unit_counts.get(key))
                    base_counts[key] += value
                    outcome_total += value
                explicit_total = max(
                    _count_value(unit_counts.get("tests")),
                    _count_value(unit_counts.get("total")),
                )
                status_outcome = _outcome_from_status(str(unit.get("status", "")))
                if (
                    status_outcome in {"crashed", "timeout", "error"}
                    and _count_value(unit_counts.get(status_outcome)) == 0
                ):
                    base_counts[status_outcome] += 1
                    outcome_total += 1
                base_counts["tests"] += max(outcome_total, explicit_total)
            else:
                status = str(unit.get("status", ""))
                if status:
                    _add_outcome(base_counts, _outcome_from_status(status))
        return counts

    # pytest-json-report format: {"tests": [{"nodeid": "...", "outcome": "..."}]}
    tests = data.get("tests", [])
    if not tests:
        # pkcs11-check isolated run format: {"results": [...]}
        for r in data.get("results", []):
            target = r.get("target", "")
            status = r.get("status", "")
            # Extract base filename
            base = target.split("::")[0].split("/")[-1].replace(".py", "")
            if not base:
                continue
            status_text = str(status)
            if status_text:
                _add_outcome(_counts_for_base(counts, base), status_text)
        return counts

    for test in tests:
        nodeid = test.get("nodeid", "")
        outcome = test.get("outcome", "")
        # Extract base filename
        base = nodeid.split("::")[0].split("/")[-1].replace(".py", "")
        if not base:
            continue
        report_outcome = _outcome_from_pytest_report(str(outcome), test.get("wasxfail"))
        _add_outcome(_counts_for_base(counts, base), report_outcome)

    return counts


def _json_mapping(path: Path) -> Mapping[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, Mapping) else None


def _coverage_mapping_from_payload(payload: Mapping[str, Any]) -> Mapping[str, Any] | None:
    embedded = payload.get("coverage")
    if isinstance(embedded, Mapping) and isinstance(embedded.get("function_coverage"), Mapping):
        return embedded
    if isinstance(payload.get("function_coverage"), Mapping):
        return payload
    return None


def _counts_from_coverage_payload(coverage: Mapping[str, Any]) -> dict[str, dict[str, int]] | None:
    raw_fc = coverage.get("function_coverage")
    if not isinstance(raw_fc, Mapping):
        return None

    raw_called_names = raw_fc.get("called_names")
    if isinstance(raw_called_names, list):
        called_names = {str(name) for name in raw_called_names if isinstance(name, str)}
    else:
        called_names = set()
    raw_called_counts = raw_fc.get("called_counts")
    called_counts = raw_called_counts if isinstance(raw_called_counts, Mapping) else {}
    called_names.update(str(name) for name in called_counts if isinstance(name, str))
    if not called_names:
        return None

    result: dict[str, dict[str, int]] = {}
    for name in sorted(called_names):
        count = _count_value(called_counts.get(name))
        if count <= 0:
            count = 1
        result[name] = {"tests": count}
    return result


def _compliance_note_from_mapping(
    raw_note: Mapping[str, Any],
    *,
    nodeid: str = "",
) -> dict[str, str] | None:
    note = {
        field: str(raw_note.get(field, ""))
        for field in _COMPLIANCE_NOTE_FIELDS
        if raw_note.get(field, "") not in (None, "")
    }
    if "nodeid" not in note and nodeid:
        note["nodeid"] = nodeid
    if not note.get("description") or not note.get("level"):
        return None
    return note


def _compliance_notes_from_user_properties(
    user_properties: Any,
    *,
    nodeid: str = "",
) -> list[dict[str, str]]:
    if not isinstance(user_properties, list):
        return []

    notes: list[dict[str, str]] = []
    for prop in user_properties:
        if not isinstance(prop, (list, tuple)) or len(prop) != 2:
            continue
        name, value = prop
        if name != "pkcs11_compliance_notes" or not isinstance(value, list):
            continue
        for raw_note in value:
            if not isinstance(raw_note, Mapping):
                continue
            note = _compliance_note_from_mapping(raw_note, nodeid=nodeid)
            if note is not None:
                notes.append(note)
    return notes


def _append_unique_compliance_note(
    notes: list[dict[str, str]],
    seen: set[tuple[tuple[str, str], ...]],
    note: Mapping[str, str],
) -> None:
    key = tuple((field, note.get(field, "")) for field in _COMPLIANCE_NOTE_FIELDS)
    if key in seen:
        return
    seen.add(key)
    notes.append(dict(note))


def _compliance_notes_from_results_payload(payload: Mapping[str, Any]) -> list[dict[str, str]]:
    notes: list[dict[str, str]] = []
    seen: set[tuple[tuple[str, str], ...]] = set()

    units = payload.get("units")
    if isinstance(units, list):
        for unit in units:
            if not isinstance(unit, Mapping):
                continue
            target = str(unit.get("target", ""))
            raw_notes = unit.get("compliance_notes")
            if not isinstance(raw_notes, list):
                continue
            for raw_note in raw_notes:
                if not isinstance(raw_note, Mapping):
                    continue
                note = _compliance_note_from_mapping(raw_note, nodeid=target)
                if note is not None:
                    _append_unique_compliance_note(notes, seen, note)

    tests = payload.get("tests")
    if isinstance(tests, list):
        for test in tests:
            if not isinstance(test, Mapping):
                continue
            nodeid = str(test.get("nodeid", ""))
            for note in _compliance_notes_from_user_properties(
                test.get("user_properties"),
                nodeid=nodeid,
            ):
                _append_unique_compliance_note(notes, seen, note)

    return notes


def _compliance_notes_from_report_jsonl(jsonl_path: Path) -> list[dict[str, str]]:
    notes: list[dict[str, str]] = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    try:
        fh = jsonl_path.open(encoding="utf-8")
    except OSError:
        return notes
    with fh:
        for line in fh:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, Mapping):
                continue
            if record.get("$report_type", "TestReport") != "TestReport":
                continue
            nodeid = str(record.get("nodeid", ""))
            for note in _compliance_notes_from_user_properties(
                record.get("user_properties"),
                nodeid=nodeid,
            ):
                _append_unique_compliance_note(notes, seen, note)
    return notes


def _load_artifact_compliance_notes(results_path: Path) -> list[dict[str, str]]:
    notes: list[dict[str, str]] = []
    seen: set[tuple[tuple[str, str], ...]] = set()

    payload = _json_mapping(results_path)
    if payload is not None:
        for note in _compliance_notes_from_results_payload(payload):
            _append_unique_compliance_note(notes, seen, note)

    for note in _compliance_notes_from_report_jsonl(results_path.parent / "report.jsonl"):
        _append_unique_compliance_note(notes, seen, note)

    return notes


def _rv_trace_from_user_properties(user_properties: Any) -> list[Mapping[str, Any]]:
    if not isinstance(user_properties, list):
        return []
    for prop in user_properties:
        if not isinstance(prop, (list, tuple)) or len(prop) != 2:
            continue
        name, value = prop
        if name not in {"pkcs11_rv_trace", "pkcs11_rv_trace_compact"}:
            continue
        if isinstance(value, list):
            return [entry for entry in value if isinstance(entry, Mapping)]
    return []


def _counts_from_report_jsonl(jsonl_path: Path) -> dict[str, dict[str, int]] | None:
    counts: dict[str, dict[str, int]] = {}
    for record in iter_report_log_records(jsonl_path):
        if record.get("$report_type", "TestReport") != "TestReport":
            continue
        trace = _rv_trace_from_user_properties(record.get("user_properties"))
        if not trace:
            continue
        outcome = _outcome_from_pytest_report(
            str(record.get("outcome", "")),
            record.get("wasxfail"),
        )
        for entry in trace:
            fn = entry.get("fn")
            if not isinstance(fn, str) or not fn.startswith("C_"):
                continue
            _add_outcome(_counts_for_base(counts, fn), outcome)
    return counts or None


def _load_observed_function_coverage(results_path: Path) -> dict[str, dict[str, int]] | None:
    """Load observed C_* coverage from results/coverage/report-log artifacts."""
    observed: dict[str, dict[str, int]] = {}

    payload = _json_mapping(results_path)
    if payload is not None:
        coverage = _coverage_mapping_from_payload(payload)
        if coverage is not None:
            coverage_counts = _counts_from_coverage_payload(coverage)
            if coverage_counts:
                observed.update(coverage_counts)

    sibling_coverage = _json_mapping(results_path.parent / "coverage.json")
    if sibling_coverage is not None:
        coverage = _coverage_mapping_from_payload(sibling_coverage)
        if coverage is not None:
            coverage_counts = _counts_from_coverage_payload(coverage)
            if coverage_counts:
                observed.update(coverage_counts)

    report_counts = _counts_from_report_jsonl(results_path.parent / "report.jsonl")
    if report_counts:
        observed.update(report_counts)

    return observed or None


def _classify_functions_from_observed_coverage(
    observed_function_counts: Mapping[str, Mapping[str, int]],
) -> dict[str, dict[str, Any]]:
    """Classify functions from observed C_* calls, not filename keywords."""
    result: dict[str, dict[str, Any]] = {}

    for func_name in STANDARD_FUNCTIONS:
        raw_counts = observed_function_counts.get(func_name)
        totals = _empty_test_counts()
        if raw_counts is not None:
            for key in _OUTCOME_KEYS:
                totals[key] = _count_value(raw_counts.get(key))
            explicit_tests = _count_value(raw_counts.get("tests"))
            outcome_total = sum(totals[key] for key in _OUTCOME_KEYS)
            totals["tests"] = max(explicit_tests, outcome_total)

        result[func_name] = {
            "status": _status_from_counts(totals),
            "tests": totals["tests"],
            "passed": totals["passed"],
            "failed": totals["failed"],
            "skipped": totals["skipped"],
            "xfailed": totals["xfailed"],
            "xpassed": totals["xpassed"],
            "error": totals["error"],
            "crashed": totals["crashed"],
            "timeout": totals["timeout"],
        }

    return result


def _classify_functions(
    test_counts: dict[str, dict[str, int]],
) -> dict[str, dict[str, Any]]:
    """Classify each standard function based on test results."""
    result: dict[str, dict[str, Any]] = {}

    for func_name in STANDARD_FUNCTIONS:
        keywords = _FUNCTION_KEYWORDS.get(func_name, [])
        totals = _empty_test_counts()

        for keyword in keywords:
            for file_base, cnts in test_counts.items():
                if keyword in file_base:
                    for key in _OUTCOME_KEYS:
                        totals[key] += cnts.get(key, 0)

        total_tests = sum(totals[key] for key in _OUTCOME_KEYS)
        status = _status_from_counts(totals)

        result[func_name] = {
            "status": status,
            "tests": total_tests,
            "passed": totals["passed"],
            "failed": totals["failed"],
            "skipped": totals["skipped"],
            "xfailed": totals["xfailed"],
            "xpassed": totals["xpassed"],
            "error": totals["error"],
            "crashed": totals["crashed"],
            "timeout": totals["timeout"],
        }

    return result


def _ckr_test_base_for_spec(attr_name: str) -> str:
    return f"test_{attr_name.lower()}"


def _ckr_file_has_executed_tests(counts: Mapping[str, int]) -> bool:
    return any(
        _count_value(counts.get(key)) > 0
        for key in ("passed", "failed", "xfailed", "xpassed", "error", "crashed", "timeout")
    )


def _ckr_coverage_summary(
    test_counts: Mapping[str, Mapping[str, int]] | None = None,
) -> dict[str, int]:
    """Count CKR spec expectations and tested coverage."""
    try:
        from pkcs11_check.testcases.ckr import _ckr_spec
    except ImportError:
        return {"total_specs": 0, "tested": 0, "untestable": 0, "untested": 0}

    total = 0
    tested = 0
    untestable = 0
    for attr_name in dir(_ckr_spec):
        attr = getattr(_ckr_spec, attr_name)
        if isinstance(attr, dict) and attr_name.startswith("CKR_"):
            total += len(attr)
            testable_entries = 0
            for _key, expectation in attr.items():
                if getattr(expectation, "untestable", False):
                    untestable += 1
                    continue
                testable_entries += 1
            if test_counts is None:
                continue
            file_counts = test_counts.get(_ckr_test_base_for_spec(attr_name))
            if file_counts is not None and _ckr_file_has_executed_tests(file_counts):
                tested += testable_entries
    if test_counts is None:
        for attr_name in dir(_ckr_spec):
            attr = getattr(_ckr_spec, attr_name)
            if not isinstance(attr, dict) or not attr_name.startswith("CKR_"):
                continue
            for _key, expectation in attr.items():
                if not getattr(expectation, "untestable", False):
                    tested += 1
    else:
        tested = min(tested, max(total - untestable, 0))

    return {
        "total_specs": total,
        "tested": tested,
        "untestable": untestable,
        "untested": max(total - untestable - tested, 0),
    }


def _compliance_notes_list() -> list[dict[str, str]]:
    """Serialize collected compliance notes."""
    notes: list[ComplianceNote] = get_notes()
    result: list[dict[str, str]] = []
    for n in notes:
        result.append(
            {
                "description": n.description,
                "level": n.level.value,
                "reference": n.reference,
                "test_id": n.test_id,
            }
        )
    return result


def _merge_compliance_notes(
    process_notes: list[dict[str, str]],
    artifact_notes: list[dict[str, str]],
) -> list[dict[str, str]]:
    notes: list[dict[str, str]] = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    for note in [*process_notes, *artifact_notes]:
        _append_unique_compliance_note(notes, seen, note)
    return notes


def generate_report(
    module_path: str,
    module: Any,
    test_results_path: Path | None = None,
    slot_index: int = 0,
) -> dict[str, Any]:
    """Generate a compliance report dictionary.

    Args:
        module_path: Path string of the PKCS#11 module.
        module: A loaded P11Module instance.
        test_results_path: Optional path to a JSON test results file
            (pytest-json-report or pkcs11-check isolated run format).
        slot_index: Which slot to probe for mechanisms (default 0).

    Returns:
        A dictionary suitable for JSON serialization containing mechanism
        support, function coverage, CKR coverage, compliance notes, and
        aggregate scores.
    """
    interface_version = getattr(module, "interface_version", "2.40")

    # Mechanism support
    mechanisms = _collect_mechanisms(module, slot_index=slot_index)

    # Function coverage from test results
    test_counts: dict[str, dict[str, int]] | None = None
    if test_results_path and test_results_path.exists():
        test_counts = _parse_test_results(test_results_path)
        observed_function_counts = _load_observed_function_coverage(test_results_path)
        if observed_function_counts is not None:
            functions = _classify_functions_from_observed_coverage(
                observed_function_counts,
            )
        else:
            functions = _classify_functions(test_counts)
    else:
        functions = {
            f: {
                "status": "NOT_TESTED",
                "tests": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "xfailed": 0,
                "xpassed": 0,
                "error": 0,
                "crashed": 0,
                "timeout": 0,
            }
            for f in STANDARD_FUNCTIONS
        }

    # CKR coverage
    ckr_coverage = _ckr_coverage_summary(test_counts)

    # Compliance notes
    artifact_compliance_notes: list[dict[str, str]] = []
    if test_results_path and test_results_path.exists():
        artifact_compliance_notes = _load_artifact_compliance_notes(test_results_path)
    compliance_notes = _merge_compliance_notes(
        _compliance_notes_list(),
        artifact_compliance_notes,
    )

    # Aggregate scores
    mechs_supported = sum(1 for v in mechanisms.values() if v == "SUPPORTED")
    funcs_tested = sum(1 for v in functions.values() if v["status"] not in {"NOT_TESTED", "SKIP"})
    ckr_total = ckr_coverage["total_specs"]
    ckr_tested = ckr_coverage["tested"]
    ckr_pct = round(ckr_tested / ckr_total * 100, 1) if ckr_total > 0 else 0.0

    return {
        "module": module_path,
        "interface_version": interface_version,
        "timestamp": datetime.now(UTC).isoformat(),
        "mechanisms": mechanisms,
        "functions": functions,
        "ckr_coverage": ckr_coverage,
        "compliance_notes": compliance_notes,
        "aggregate": {
            "mechanisms_supported": mechs_supported,
            "mechanisms_total": len(STANDARD_MECHANISMS),
            "functions_tested": funcs_tested,
            "functions_total": len(STANDARD_FUNCTIONS),
            "ckr_coverage_pct": ckr_pct,
        },
    }


def generate_report_json(
    module_path: str,
    module: Any,
    test_results_path: Path | None = None,
    slot_index: int = 0,
) -> str:
    """Generate a compliance report as a JSON string.

    Convenience wrapper around :func:`generate_report`.
    """
    report = generate_report(
        module_path=module_path,
        module=module,
        test_results_path=test_results_path,
        slot_index=slot_index,
    )
    return json.dumps(report, indent=2)
