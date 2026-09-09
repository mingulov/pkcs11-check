"""Operation-state use-after-free: ``C_DestroyObject`` mid-operation.

After ``C_DestroyObject`` on a key with an active operation, the operation's
stored key reference may point to freed memory if the module holds a raw pointer
rather than copying key material at ``*Init`` time.  The next completion call
then dereferences freed memory → heap-use-after-free.

For pre-bound multipart operations, conformant behaviour is either refusal of
the destroy while the operation is active, a clean completion error, or
successful completion because key material was copied at ``*Init`` time.  The
digest and derive probes are direct-handle operations instead: ``C_DigestInit``
binds no key and ``C_DigestKey`` first receives the handle after destruction,
while ``C_DeriveKey`` is atomic.  After a successful destroy, those probes
must return ``CKR_KEY_HANDLE_INVALID``; successful use is a lifecycle
self-contradiction and another clean rejection is a nonspec deviation.  The
**one** hard requirement for every probe is no crash.

Fifteen probes (single-threaded, no race required):

- Sign (HMAC)             — ``CKM_SHA256_HMAC`` key destroyed between
  ``C_SignInit`` and ``C_Sign``.
- Encrypt/Decrypt (AES)   — parametrized family over ECB / CBC / CTR / GCM
  (8 test cases): AES key destroyed between ``C_EncryptInit``/``C_DecryptInit``
  and the completion call.  Encrypt cases additionally carry a wrong-output
  oracle: the expected ciphertext is captured with the live key before the
  destroy; if the post-destroy encrypt also completes the outputs are compared
  for a crypto self-contradiction.
- Digest                  — ``C_DigestInit(CKM_SHA256)`` then ``C_DigestKey``
  on the already-destroyed key handle.
- Verify                  — ``CKM_SHA256_HMAC`` key destroyed between
  ``C_VerifyInit`` and ``C_Verify``.
- Derive                  — EC private key destroyed before ``C_DeriveKey``; the
  module must reject the stale handle cleanly, not dereference freed memory.
- Cross-session           — token HMAC key sign-inited from session A, destroyed
  from session B, then ``C_Sign`` completed in session A; CWE-416 across session
  boundaries. (Token object cleaned up; test skips if token creation fails.)
- Sign (ECDSA)            — EC private key destroyed between
  ``C_SignInit(CKM_ECDSA)`` and ``C_Sign``; asymmetric scalar operation on
  possibly-freed key material.
- Decrypt (RSA)           — RSA private key destroyed between
  ``C_DecryptInit(CKM_RSA_PKCS)`` and ``C_Decrypt``; invalid ciphertext (zero
  bytes) so a clean decrypt error is also acceptable.
"""

from __future__ import annotations

# ruff: noqa: I001 - retain imports required by the focused source contracts

import ctypes
import json
import re
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - classification alias convention
from pkcs11_check.classification import fail_as
from pkcs11_check.core.process_observation import termination_from_returncode
from pkcs11_check.raw.rv import ckr_name, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID,
    CKR_OK,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OPERATION_NOT_INITIALIZED,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import SUBPROCESS_TIMEOUT_MARKER, pin_from_config
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

# CKRs accepted as a "clean" completion after the key handle was destroyed.
# allow_ok=True is also passed so snapshot-based modules (which copied key
# material at *Init time) can return CKR_OK without being flagged.
_COMPLETION_REJECT_RVS = (
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_KEY_HANDLE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
)

# For the RSA decrypt probe the ciphertext is intentionally invalid (256 zero
# bytes), so a snapshot-based module that copied the key at *Init time may
# proceed to decrypt and then reject the bad ciphertext with one of these
# spec-defined codes — both are conformant, not findings.
_RSA_DECRYPT_REJECT_RVS = _COMPLETION_REJECT_RVS + (
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
)

# For the AES-GCM decrypt probe the 16-byte input is a 0-byte ciphertext plus
# a 16-byte authentication tag.  A conformant module that copied the key at
# *Init time may proceed to decrypt and reject the bad tag with one of these
# spec-defined codes — both are conformant, not findings.  (ECB/CBC/CTR are
# unaffected: they complete with CKR_OK on the valid 16-byte block.)
_AES_DECRYPT_REJECT_RVS = _COMPLETION_REJECT_RVS + (
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
)


def _parse_rv(output: str, prefix: str) -> int | None:
    """Return the integer rv printed as ``<prefix>0x…`` or ``None`` if absent."""
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    return None


def _parse_line(output: str, prefix: str) -> str | None:
    """Return the value printed as ``<prefix><value>`` or ``None`` if absent."""
    for line in output.splitlines():
        if line.startswith(prefix):
            return line.removeprefix(prefix)
    return None


# ---------------------------------------------------------------------------
# Sign probe (CKM_SHA256_HMAC)
# ---------------------------------------------------------------------------


class TestSignOperationStateUAF:
    """``C_Sign`` after ``C_DestroyObject`` on the active key must not crash."""

    def test_sign_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the HMAC key mid-sign must not cause a use-after-free crash.

        After ``C_DestroyObject`` on the active key, the operation's stored key
        reference may point to freed memory.  A conformant module either refuses
        the destroy while the operation is active, invalidates the operation so
        ``C_Sign`` returns a clean error, or (snapshot-based) completes normally.
        A crash is the finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "sign",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Sign after C_DestroyObject (operation-state UAF)",
        )
        sign_rv = _parse_rv(out, "SIGN_RV:")
        if sign_rv is not None:
            classify_negative_rv(
                sign_rv,
                _COMPLETION_REJECT_RVS,
                label="C_Sign after destroy of active HMAC key",
                allow_ok=True,
            )
        sign_rv2 = _parse_rv(out, "SIGN_RV2:")
        if sign_rv2 is not None:
            classify_negative_rv(
                sign_rv2,
                _COMPLETION_REJECT_RVS,
                label="C_Sign(2nd pass) after destroy of active HMAC key",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# AES destroy-mid-operation UAF (ECB / CBC / CTR / GCM) — parametrized family
# ---------------------------------------------------------------------------

# (label, has_mechanism_name, ckm_const_name)
_AES_UAF_CASES = [
    ("AES-ECB", "AES_ECB", "CKM_AES_ECB"),
    ("AES-CBC", "AES_CBC", "CKM_AES_CBC"),
    ("AES-CTR", "AES_CTR", "CKM_AES_CTR"),
    ("AES-GCM", "AES_GCM", "CKM_AES_GCM"),
]


@pytest.mark.parametrize("label,mech_name,ckm", _AES_UAF_CASES)
class TestAesEncryptDestroyUAF:
    """Parametrized AES ``C_Encrypt`` after ``C_DestroyObject`` — ECB/CBC/CTR/GCM."""

    def test_encrypt_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        label: str,
        mech_name: str,
        ckm: str,
    ) -> None:
        """Destroying the AES key mid-encrypt must not cause a use-after-free crash.

        After ``C_DestroyObject`` on the active key, the operation's stored key
        reference may point to freed memory.  The probe covers ECB, CBC, CTR, and
        GCM mechanism variants to exercise different parameter-carrying code paths.
        An encrypt oracle captures the expected ciphertext before the destroy; if the
        post-destroy ``C_Encrypt`` also completes, the outputs are compared for a
        crypto self-contradiction (use-after-free corrupting the key material).
        A crash is the primary finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "aes_encrypt",
                "ckm": ckm,
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context=f"C_Encrypt({ckm}) after C_DestroyObject (operation-state UAF)",
        )
        enc_rv = _parse_rv(out, "ENCRYPT_RV:")
        if enc_rv is not None:
            classify_negative_rv(
                enc_rv,
                _COMPLETION_REJECT_RVS,
                label=f"C_Encrypt({label}) after destroy of active AES key",
                allow_ok=True,
            )
        enc_rv2 = _parse_rv(out, "ENCRYPT_RV2:")
        if enc_rv2 is not None:
            classify_negative_rv(
                enc_rv2,
                _COMPLETION_REJECT_RVS,
                label=f"C_Encrypt({label}, 2nd pass) after destroy of active AES key",
                allow_ok=True,
            )
        # Oracle: if both the live-key reference encrypt and the post-destroy encrypt
        # completed, compare ciphertexts — a mismatch is a crypto self-contradiction.
        expected_hex = _parse_line(out, "EXPECTED:")
        ct_hex = _parse_line(out, "ENCRYPT_CT:")
        if expected_hex is not None and ct_hex is not None and expected_hex != ct_hex:
            fail_as(
                "self_contradiction",
                kind="crypto",
                label=(
                    f"{label} C_Encrypt after C_DestroyObject produced output differing"
                    " from the live-key encryption (use-after-free corrupted the key)"
                ),
            )


@pytest.mark.parametrize("label,mech_name,ckm", _AES_UAF_CASES)
class TestAesDecryptDestroyUAF:
    """Parametrized AES ``C_Decrypt`` after ``C_DestroyObject`` — ECB/CBC/CTR/GCM."""

    def test_decrypt_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        label: str,
        mech_name: str,
        ckm: str,
    ) -> None:
        """Destroying the AES key mid-decrypt must not cause a use-after-free crash.

        After ``C_DestroyObject`` on the active key, the operation's stored key
        reference may point to freed memory.  The probe covers ECB, CBC, CTR, and
        GCM mechanism variants.  A crash is the primary finding; a clean error or
        (snapshot-based) success are both conformant.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "aes_decrypt",
                "ckm": ckm,
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context=f"C_Decrypt({ckm}) after C_DestroyObject (operation-state UAF)",
        )
        dec_rv = _parse_rv(out, "DECRYPT_RV:")
        if dec_rv is not None:
            classify_negative_rv(
                dec_rv,
                _AES_DECRYPT_REJECT_RVS,
                label=f"C_Decrypt({label}) after destroy of active AES key",
                allow_ok=True,
            )
        dec_rv2 = _parse_rv(out, "DECRYPT_RV2:")
        if dec_rv2 is not None:
            classify_negative_rv(
                dec_rv2,
                _AES_DECRYPT_REJECT_RVS,
                label=f"C_Decrypt({label}, 2nd pass) after destroy of active AES key",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# Digest probe (CKM_SHA256 + C_DigestKey on destroyed handle)
# ---------------------------------------------------------------------------


class TestDigestOperationStateUAF:
    """``C_DigestKey`` on a destroyed handle must not cause a use-after-free crash."""

    def test_digest_key_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Using a destroyed key handle in ``C_DigestKey`` must not UAF.

        ``C_DigestInit(CKM_SHA256)`` binds no key: ``C_DigestKey`` first receives
        the key handle after ``C_DestroyObject``.  There is therefore no
        snapshot-success path.  A crash is the finding.  If destruction is
        refused, the stale-handle premise is not established; after successful
        destruction, the exact conformant result is ``CKR_KEY_HANDLE_INVALID``.
        Other standard/vendor rejections are reported as nonspec deviations,
        while ``CKR_OK`` is a lifecycle self-contradiction.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "digest",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        _check_digest_probe(
            rc,
            out,
            err,
            context="C_DigestKey on destroyed key handle (use-after-destroy)",
        )


# ---------------------------------------------------------------------------
# Verify probe (CKM_SHA256_HMAC)
# ---------------------------------------------------------------------------


class TestVerifyOperationStateUAF:
    """``C_Verify`` after ``C_DestroyObject`` on the active key must not crash."""

    def test_verify_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the HMAC key mid-verify must not cause a use-after-free crash.

        After ``C_DestroyObject`` on the active key, ``C_Verify`` may dereference
        the operation's stored key reference, which now points to freed memory
        (CWE-416).  A conformant module either refuses the destroy while the
        operation is active, invalidates the operation so ``C_Verify`` returns a
        clean error, or (snapshot-based) completes normally.  A crash is the
        finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "verify",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Verify after C_DestroyObject (operation-state UAF)",
        )
        verify_rv = _parse_rv(out, "VERIFY_RV:")
        if verify_rv is not None:
            classify_negative_rv(
                verify_rv,
                _COMPLETION_REJECT_RVS,
                label="C_Verify after destroy of active HMAC verify key",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# Derive probe (CKM_ECDH1_DERIVE — use-after-destroy of the base private key)
# ---------------------------------------------------------------------------
#
# C_DeriveKey is atomic (no Init/complete split), so the UAF pattern is
# modelled as a use-after-destroy of the base key handle: generate an EC
# keypair, destroy the private key, then call C_DeriveKey with the stale
# handle.  Unlike the other probes in this file, there is no Init-bound key
# reference that could snapshot key material.  A conformant module must reject
# the stale handle with a clean CKR (normally CKR_KEY_HANDLE_INVALID) without
# dereferencing freed memory.


_UAF_FACT_MAX_BYTES = 1024
_UAF_RV_RE = re.compile(rf"0x[0-9a-f]{{8,{2 * ctypes.sizeof(ctypes.c_ulong)}}}")
_UAF_MISSING_FACT = {
    "schema": 1,
    "probe": "derive",
    "event": "SETUP_ATTRIBUTE",
    "attribute": {"name": "CKA_EC_POINT", "id": 385},
    "state": "missing",
    "value_type": None,
    "value_len": None,
}


def _json_no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Decode one JSON object while rejecting duplicate keys."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant {value!r}")


def _parse_uaf_missing_fact(line: str) -> dict[str, object]:
    """Parse and validate the one exact missing-peer-point fact."""
    payload = line.removeprefix("UAF:")
    if len(payload.encode("utf-8")) > _UAF_FACT_MAX_BYTES:
        raise ValueError("UAF fact exceeds bounded JSON size")
    value = json.loads(
        payload,
        object_pairs_hook=_json_no_duplicate_keys,
        parse_constant=_reject_json_constant,
    )
    if not isinstance(value, dict) or value != _UAF_MISSING_FACT:
        raise ValueError("UAF fact does not match the exact derive omission schema")
    # Equality above catches all value changes; explicit type checks prevent Python's
    # bool-as-int equality from ever widening the accepted protocol.
    attribute = value["attribute"]
    if type(value["schema"]) is not int or not isinstance(attribute, dict):
        raise ValueError("UAF fact uses a boolean where an integer is required")
    if type(attribute["id"]) is not int:
        raise ValueError("UAF fact uses a boolean where an integer is required")
    return value


def _parse_uaf_rv(line: str, prefix: str) -> int:
    """Parse a child CK_RV marker in its bounded, canonical form."""
    payload = line.removeprefix(prefix)
    if _UAF_RV_RE.fullmatch(payload) is None:
        raise ValueError(f"malformed {prefix[:-1]} marker")
    rv = int(payload, 16)
    if f"0x{rv:08x}" != payload:
        raise ValueError(f"non-canonical {prefix[:-1]} marker")
    return rv


def _uaf_protocol_error(context: str, errors: list[str]) -> C.Classification:
    return C.record_as(
        "harness_error",
        label=context,
        summary=f"{context}: malformed UAF protocol: {'; '.join(errors)}",
        detail={"protocol": "UAF", "errors": list(errors)},
    )


def _uaf_record_missing_fact(context: str, fact: dict[str, object]) -> C.Classification:
    return C.record_as(
        "not_operational",
        kind="metadata",
        label=context,
        operation="C_GetAttributeValue",
        mechanism="CKM_ECDH1_DERIVE",
        actual=None,
        summary=(
            f"{context}: CKA_EC_POINT is unavailable; C_DeriveKey dependency could not be exercised"
        ),
        detail={"protocol": "UAF", "dependency": "C_DeriveKey", **fact},
    )


def _uaf_record_destroy_refusal(
    context: str,
    destroy_rv: int,
    target_rv: int | None,
    *,
    target_key: str,
    destroy_description: str,
) -> C.Classification:
    return C.record_as(
        "not_operational",
        label=context,
        operation="C_DestroyObject",
        actual=destroy_rv,
        summary=(
            f"{context}: C_DestroyObject refused destruction of the {destroy_description} "
            f"({destroy_rv:#010x})"
        ),
        detail={
            "protocol": "UAF",
            "destroy_rv": destroy_rv,
            target_key: target_rv,
        },
    )


def _uaf_record_undefined_rv(
    context: str,
    *,
    operation: str,
    rv: int,
    destroy_rv: int | None = None,
    target_rv: int | None = None,
    target_key: str,
    mechanism: str | None,
) -> C.Classification:
    return C.record_as(
        "self_contradiction",
        kind="metadata",
        label=context,
        operation=operation,
        mechanism=mechanism,
        actual=rv,
        summary=f"{context}: {operation} returned undefined CK_RV {ckr_name(rv)}",
        detail={
            "protocol": "UAF",
            "destroy_rv": destroy_rv,
            target_key: target_rv,
            "undefined_rv": rv,
        },
    )


def _uaf_record_target_refusal(
    context: str,
    destroy_rv: int,
    target_rv: int,
    *,
    target_key: str,
    target_operation: str,
    target_mechanism: str,
    expected_rv: int,
    target_description: str,
) -> C.Classification:
    return C.record_as(
        "nonspec_reject",
        label=context,
        operation=target_operation,
        mechanism=target_mechanism,
        expected=(expected_rv,),
        actual=target_rv,
        summary=(
            f"{context}: {target_operation} rejected the destroyed {target_description} "
            f"with {target_rv:#010x}"
        ),
        detail={
            "protocol": "UAF",
            "destroy_rv": destroy_rv,
            target_key: target_rv,
        },
    )


def _check_direct_handle_probe(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
    target_marker: str,
    target_key: str,
    target_operation: str,
    target_mechanism: str,
    target_description: str,
    destroy_description: str,
    allow_missing_fact: bool,
) -> None:
    """Classify a synchronous stale-handle probe's protocol and process disposition."""
    termination = termination_from_returncode(
        rc,
        timed_out=SUBPROCESS_TIMEOUT_MARKER in stderr,
        stderr=stderr,
    )
    interrupted = str(termination["kind"]) in {"signal", "exception", "timeout"}
    normal_completion = rc == 0 and not interrupted
    errors: list[str] = []
    marker_order: list[str] = []
    marker_validity: list[bool] = []
    setup_payloads: list[str] = []
    facts: list[dict[str, object]] = []
    destroy_rvs: list[int] = []
    target_rvs: list[int] = []

    for line in stdout.splitlines():
        if line.startswith("SETUP_XFAIL:"):
            marker_order.append("setup")
            payload = line.removeprefix("SETUP_XFAIL:").strip()
            if not payload:
                errors.append("empty SETUP_XFAIL marker")
                marker_validity.append(False)
            else:
                setup_payloads.append(payload)
                marker_validity.append(True)
            continue
        if line.startswith("UAF:"):
            marker_order.append("fact")
            if allow_missing_fact:
                try:
                    facts.append(_parse_uaf_missing_fact(line))
                except (ValueError, TypeError, json.JSONDecodeError) as exc:
                    errors.append(f"malformed UAF fact: {exc}")
                    marker_validity.append(False)
                else:
                    marker_validity.append(True)
            else:
                errors.append("malformed UAF protocol marker")
                marker_validity.append(False)
            continue
        if line.startswith("DESTROY_RV:"):
            marker_order.append("destroy")
            try:
                destroy_rvs.append(_parse_uaf_rv(line, "DESTROY_RV:"))
            except ValueError as exc:
                errors.append(str(exc))
                marker_validity.append(False)
            else:
                marker_validity.append(True)
            continue
        if line.startswith(f"{target_marker}:"):
            marker_order.append("target")
            try:
                target_rvs.append(_parse_uaf_rv(line, f"{target_marker}:"))
            except ValueError as exc:
                errors.append(str(exc))
                marker_validity.append(False)
            else:
                marker_validity.append(True)
            continue
        reserved_marker = "DIGEST_KEY_RV" if target_marker == "DERIVE_RV" else "DERIVE_RV"
        if line.startswith(reserved_marker):
            marker_order.append("reserved")
            marker_validity.append(False)
            errors.append(f"reserved UAF protocol marker: {reserved_marker}")
            continue
        if line.startswith(("SETUP_XFAIL", "UAF", "DESTROY_RV", target_marker)):
            marker = line.split(":", 1)[0]
            marker_order.append(
                "setup"
                if marker == "SETUP_XFAIL"
                else "fact"
                if marker == "UAF"
                else "destroy"
                if marker == "DESTROY_RV"
                else "target"
            )
            marker_validity.append(False)
            errors.append("malformed UAF protocol marker")

    if len(setup_payloads) > 1:
        errors.append("duplicate SETUP_XFAIL markers")
    if len(facts) > 1:
        errors.append("duplicate UAF missing-point facts")
    if len(destroy_rvs) > 1:
        errors.append("duplicate DESTROY_RV markers")
    if len(target_rvs) > 1:
        errors.append(f"duplicate {target_marker} markers")

    if normal_completion:
        valid_setup = len(setup_payloads) == 1 and marker_order == ["setup"]
        valid_missing = allow_missing_fact and len(facts) == 1 and marker_order == ["fact"]
        valid_target = (
            len(destroy_rvs) == 1 and len(target_rvs) == 1 and marker_order == ["destroy", "target"]
        )
        if not (valid_setup or valid_missing or valid_target):
            errors.append("normal completion does not contain one valid terminal branch")
    elif marker_order:
        if len(setup_payloads) == 1 and marker_order != ["setup"]:
            errors.append("SETUP_XFAIL is mixed with another UAF branch")
        if len(facts) == 1 and marker_order != ["fact"]:
            errors.append("missing UAF fact is mixed with target RV markers")
        if (
            not setup_payloads
            and not facts
            and marker_order
            not in (
                ["destroy"],
                ["destroy", "target"],
            )
        ):
            errors.append("UAF markers are not a valid interrupted prefix")

    semantic: list[C.Classification] = []
    first_valid_marker = next(
        (marker_order[index] for index, valid in enumerate(marker_validity) if valid),
        None,
    )
    if first_valid_marker == "setup" and setup_payloads:
        semantic.append(
            C.record_as(
                "not_operational",
                label=context,
                summary=f"{context}: {setup_payloads[0]}",
                detail={"protocol": "UAF", "protocol_marker": "SETUP_XFAIL"},
            )
        )
    if first_valid_marker == "fact" and facts:
        semantic.append(_uaf_record_missing_fact(context, facts[0]))

    # Keep the longest valid target prefix independently of later protocol
    # corruption.  A valid DESTROY_RV/target-RV pair followed by a late marker
    # still proves its provider outcome; the trailing marker is a separate
    # harness defect and must not erase that evidence.
    target_prefix_len = 0
    for expected in ("destroy", "target"):
        index = target_prefix_len
        if (
            index >= len(marker_order)
            or marker_order[index] != expected
            or not marker_validity[index]
        ):
            break
        target_prefix_len += 1

    if target_prefix_len:
        destroy_rv = destroy_rvs[0]
        target_rv = target_rvs[0] if target_prefix_len == 2 else None
        destroy_defined = is_standard_ckr(destroy_rv) or is_vendor_defined_ckr(destroy_rv)
        target_defined = (
            target_rv is None or is_standard_ckr(target_rv) or is_vendor_defined_ckr(target_rv)
        )
        if not destroy_defined:
            semantic.append(
                _uaf_record_undefined_rv(
                    context,
                    operation="C_DestroyObject",
                    rv=destroy_rv,
                    destroy_rv=destroy_rv,
                    target_rv=target_rv,
                    target_key=target_key,
                    mechanism=None,
                )
            )
        if target_rv is not None and not target_defined:
            semantic.append(
                _uaf_record_undefined_rv(
                    context,
                    operation=target_operation,
                    rv=target_rv,
                    destroy_rv=destroy_rv,
                    target_rv=target_rv,
                    target_key=target_key,
                    mechanism=target_mechanism,
                )
            )
        if destroy_defined and destroy_rv != int(CKR_OK):
            semantic.append(
                _uaf_record_destroy_refusal(
                    context,
                    destroy_rv,
                    target_rv,
                    target_key=target_key,
                    destroy_description=destroy_description,
                )
            )
        elif (
            destroy_defined
            and destroy_rv == int(CKR_OK)
            and target_rv is not None
            and target_defined
        ):
            if target_rv == int(CKR_KEY_HANDLE_INVALID):
                pass
            elif target_rv == int(CKR_OK):
                semantic.append(
                    C.record_as(
                        "self_contradiction",
                        kind="lifecycle",
                        label=context,
                        operation=target_operation,
                        mechanism=target_mechanism,
                        expected=(CKR_KEY_HANDLE_INVALID,),
                        actual=target_rv,
                        summary=(
                            f"{context}: {target_operation} accepted a destroyed "
                            f"{target_description} handle after C_DestroyObject"
                        ),
                        detail={
                            "protocol": "UAF",
                            "destroy_rv": destroy_rv,
                            target_key: target_rv,
                        },
                    )
                )
            else:
                semantic.append(
                    _uaf_record_target_refusal(
                        context,
                        destroy_rv,
                        target_rv,
                        target_key=target_key,
                        target_operation=target_operation,
                        target_mechanism=target_mechanism,
                        expected_rv=int(CKR_KEY_HANDLE_INVALID),
                        target_description=target_description,
                    )
                )

    protocol_record = _uaf_protocol_error(context, errors) if errors else None

    before_process = len(C.get_records())
    explicit_harness = False
    capability_skip: BaseException | None = None
    try:
        _, explicit_harness = assert_subprocess_completed(rc, stdout, stderr, context=context)
    except BaseException as exc:
        process_records = C.get_records()[before_process:]
        crash = next((item for item in reversed(process_records) if item.reason == "crash"), None)
        if crash is not None:
            crash.detail = {
                **(crash.detail or {}),
                "parsed_measurement": {
                    "destroy_rv": destroy_rvs[0] if destroy_rvs else None,
                    target_key: target_rvs[0] if target_rvs else None,
                },
            }
            # Crash/timeout is authoritative after preserving the parsed provider
            # prefix in the crash record.
            raise
        process_harness = next(
            (item for item in reversed(process_records) if item.reason == "harness_error"),
            None,
        )
        if process_harness is None:
            if isinstance(exc, pytest.skip.Exception):
                capability_skip = exc
            else:
                raise
        # Positive child exits are deferred until provider hard/protocol evidence
        # has taken precedence over this process-level harness defect.
        explicit_harness = True
    process_records = C.get_records()[before_process:]
    process_harness = next(
        (item for item in reversed(process_records) if item.reason == "harness_error"),
        None,
    )

    hard = next((item for item in semantic if item.outcome == "fail"), None)
    if hard is not None:
        C.raise_for_record(hard)
    if protocol_record is not None:
        C.raise_for_record(protocol_record)
    if explicit_harness and process_harness is not None:
        C.raise_for_record(process_harness)
    provider = next((item for item in semantic if item.outcome == "xfail"), None)
    if provider is not None:
        C.raise_for_record(provider)
    if capability_skip is not None:
        raise capability_skip
    if not interrupted and rc != 0 and process_harness is not None:
        C.raise_for_record(process_harness)


def _check_derive_probe(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
) -> None:
    """Classify the derive probe's bounded protocol and process disposition."""
    _check_direct_handle_probe(
        rc,
        stdout,
        stderr,
        context=context,
        target_marker="DERIVE_RV",
        target_key="derive_rv",
        target_operation="C_DeriveKey",
        target_mechanism="CKM_ECDH1_DERIVE",
        target_description="EC private key",
        destroy_description="derive base object",
        allow_missing_fact=True,
    )


def _check_digest_probe(
    rc: int,
    stdout: str,
    stderr: str,
    *,
    context: str,
) -> None:
    """Classify the digest stale-handle probe's protocol and process disposition."""
    _check_direct_handle_probe(
        rc,
        stdout,
        stderr,
        context=context,
        target_marker="DIGEST_KEY_RV",
        target_key="digest_key_rv",
        target_operation="C_DigestKey",
        target_mechanism="CKM_SHA256",
        target_description="digest key",
        destroy_description="digest key",
        allow_missing_fact=False,
    )


class TestDeriveOperationStateUAF:
    """``C_DeriveKey`` with a destroyed base-key handle must not cause a UAF crash."""

    def test_derive_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Using a destroyed private-key handle in ``C_DeriveKey`` must not UAF.

        ``C_DeriveKey`` is atomic (no Init/complete split), so the use-after-free
        pattern is modelled as a use-after-destroy of the base key: the EC private
        key is destroyed immediately before ``C_DeriveKey`` is called with the stale
        handle.  There is no key-binding Init phase and therefore no snapshot-based
        success path: a conformant module must reject the stale handle with a clean
        error (CWE-416) rather than dereferencing freed memory.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "derive",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        _check_derive_probe(
            rc,
            out,
            err,
            context="C_DeriveKey with destroyed base-key handle (use-after-destroy)",
        )


# ---------------------------------------------------------------------------
# Cross-session probe: token key sign-inited in session A, destroyed from B
# ---------------------------------------------------------------------------
#
# Token objects are shared across sessions on the same slot.  If the module
# tracks the key reference by raw pointer and a second session frees the
# object store entry, the first session's pending C_Sign may dereference freed
# memory.  The probe exercises this path single-threadedly, sequentially:
#   Session A: C_SignInit(token_key)
#   Session B: C_DestroyObject(token_key)
#   Session A: C_Sign(...)
# A crash is the only finding; completion and clean rejection are both
# conformant (CWE-416, PKCS#11 object-lifecycle / session-sharing semantics).


class TestCrossSessionOperationStateUAF:
    """Cross-session UAF: token key destroyed from session B during active sign in A."""

    def test_cross_session_sign_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying a token key from session B while session A has it sign-inited.

        Token objects are visible across all sessions on the same slot.  If the
        module tracks the active operation's key by raw pointer and another session
        frees the backing object, the pending ``C_Sign`` in session A may dereference
        freed memory (CWE-416).  Conformant outcomes: the destroy is refused while
        the operation is active, the operation is invalidated so ``C_Sign`` returns a
        clean error, or (snapshot-based) the sign completes normally.  A crash is the
        finding.  The token object is cleaned up before the probe exits so no
        persistent mutation is left on the token.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "cross_session",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Sign in session A after C_DestroyObject from session B (cross-session UAF)",
        )
        xsession_rv = _parse_rv(out, "XSESSION_SIGN_RV:")
        if xsession_rv is not None:
            classify_negative_rv(
                xsession_rv,
                _COMPLETION_REJECT_RVS,
                label="C_Sign(session A) after cross-session destroy of active token key",
                allow_ok=True,
            )
        xsession_rv2 = _parse_rv(out, "XSESSION_SIGN_RV2:")
        if xsession_rv2 is not None:
            classify_negative_rv(
                xsession_rv2,
                _COMPLETION_REJECT_RVS,
                label="C_Sign(session A, 2nd pass) after cross-session destroy of active token key",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# ECDSA sign probe — asymmetric destroy-mid-sign
# ---------------------------------------------------------------------------
#
# C_SignInit(CKM_ECDSA, priv) → C_DestroyObject(priv) → C_Sign on the stale
# operation state.  ECDSA modular arithmetic dereferences the private-key scalar;
# if the module holds a raw pointer to the key's CKA_VALUE field and the object
# store entry is freed by C_DestroyObject, the subsequent C_Sign walks freed
# memory (CWE-416).  The probe is single-threaded and sequential.


class TestSignEcdsaOperationStateUAF:
    """``C_Sign`` (ECDSA) after ``C_DestroyObject`` on the private key must not crash."""

    def test_ecdsa_sign_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the EC private key mid-ECDSA-sign must not cause a UAF crash.

        After ``C_DestroyObject`` on the active EC private key, the operation's stored
        key reference may point to freed memory (CWE-416).  A conformant module either
        refuses the destroy while the operation is active, invalidates the operation so
        ``C_Sign`` returns a clean error, or (snapshot-based) completes normally.  A
        crash is the finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "ecdsa_sign",
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Sign(ECDSA) after C_DestroyObject (operation-state UAF)",
        )
        sign_rv = _parse_rv(out, "SIGN_RV:")
        if sign_rv is not None:
            classify_negative_rv(
                sign_rv,
                _COMPLETION_REJECT_RVS,
                label="C_Sign(ECDSA) after destroy of active EC private key",
                allow_ok=True,
            )
        sign_rv2 = _parse_rv(out, "SIGN_RV2:")
        if sign_rv2 is not None:
            classify_negative_rv(
                sign_rv2,
                _COMPLETION_REJECT_RVS,
                label="C_Sign(ECDSA, 2nd pass) after destroy of active EC private key",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# RSA decrypt probe — asymmetric destroy-mid-decrypt
# ---------------------------------------------------------------------------
#
# C_DecryptInit(CKM_RSA_PKCS, priv) → C_DestroyObject(priv) → C_Decrypt on
# a modulus-sized zero buffer.  RSA PKCS#1 v1.5 decryption performs private-key
# scalar operations that dereference the CRT key material; if the module holds
# raw pointers into the object store entry freed by C_DestroyObject, the
# subsequent C_Decrypt walks freed memory (CWE-416).  The ciphertext is
# intentionally invalid (256 zero bytes) so a clean decrypt error is acceptable;
# the only hard requirement is no crash.


class TestDecryptRsaOperationStateUAF:
    """``C_Decrypt`` (RSA_PKCS) after ``C_DestroyObject`` on the active key must not crash."""

    def test_rsa_decrypt_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the RSA private key mid-decrypt must not cause a UAF crash.

        After ``C_DestroyObject`` on the active RSA private key, the operation's stored
        key reference may point to freed memory (CWE-416).  A conformant module either
        refuses the destroy while the operation is active, invalidates the operation so
        ``C_Decrypt`` returns a clean error, or (snapshot-based) proceeds to a clean
        error on the invalid ciphertext.  A crash is the finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        result = run_probe(
            "operation_state_uaf",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "rsa_decrypt",
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        rc, out, err = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Decrypt(RSA_PKCS) after C_DestroyObject (operation-state UAF)",
        )
        dec_rv = _parse_rv(out, "DECRYPT_RV:")
        if dec_rv is not None:
            classify_negative_rv(
                dec_rv,
                _RSA_DECRYPT_REJECT_RVS,
                label="C_Decrypt(RSA_PKCS) after destroy of active RSA private key",
                allow_ok=True,
            )
        dec_rv2 = _parse_rv(out, "DECRYPT_RV2:")
        if dec_rv2 is not None:
            classify_negative_rv(
                dec_rv2,
                _RSA_DECRYPT_REJECT_RVS,
                label="C_Decrypt(RSA_PKCS, 2nd pass) after destroy of active RSA private key",
                allow_ok=True,
            )
