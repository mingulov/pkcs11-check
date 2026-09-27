"""Regression tests for crash-survival subprocess wrappers."""

from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.testcases._probes import error_path_kwp as error_path_kwp_probe
from pkcs11_check.testcases._probes import error_path_rsa as error_path_rsa_probe
from pkcs11_check.testcases._probes import ffi_length as ffi_length_probe
from pkcs11_check.testcases._probes.runner import ProbeResult
from pkcs11_check.testcases._subprocess_preamble import SUBPROCESS_TIMEOUT_MARKER
from pkcs11_check.testcases.security import (
    test_api_boundary,
    test_arithmetic_overflow,
    test_error_path_rsa,
    test_ffi_length_boundary,
    test_ffi_null_pointer,
    test_output_length_truncation,
    test_recover_length_boundary,
)
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash
from tests._attribute_access_guard import analyze_file
from tests._skip_assert import assert_skips


class _Pin:
    def get_secret_value(self) -> str:
        return "1234"


class _RawSession:
    raw = object()
    sh = object()

    def has_mechanism(self, _name: str) -> bool:
        return True


def test_assert_subprocess_no_crash_rejects_positive_exit() -> None:
    """A child Python error is not a valid no-crash pass."""
    with pytest.raises(pytest.fail.Exception, match="subprocess exited with code 1"):
        assert_subprocess_no_crash(
            1,
            "",
            "SyntaxError: expected 'except' or 'finally' block",
            context="generated child script",
        )


def test_assert_subprocess_no_crash_converts_setup_marker_to_xfail() -> None:
    """A controlled child setup rejection is an xfail, not a silent pass."""
    with pytest.raises(pytest.xfail.Exception, match="AES key generation rejected"):
        assert_subprocess_no_crash(
            0,
            "SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED",
            "",
            context="generated child script",
        )


def test_kwp_decrypt_child_uses_minimal_guarded_output_buffer() -> None:
    """The decrypt crash path must expose output-buffer overwrites.

    The AES-KWP/KW error-path child now lives in ``_probes/error_path_kwp.py``;
    the minimal guarded-output-buffer logic must survive the migration.
    """
    src = inspect.getsource(error_path_kwp_probe)
    assert "minimal_len = max(0, len(corrupted) - 8)" in src
    assert 'guard_sentinel = b"PKCS11CHK"' in src
    assert "wrote past the minimal output buffer" in src


def test_rsa_decrypt_probe_xfails_setup_before_child(monkeypatch: pytest.MonkeyPatch) -> None:
    """RSA decrypt crash probes should not spawn if setup keygen is unavailable."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _setup_marker(*_args: object, **_kwargs: object) -> ProbeResult:
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:RSA decrypt keypair generation rejected: CKR_FUNCTION_FAILED\n",
            stderr="",
        )

    monkeypatch.setattr(test_error_path_rsa, "run_probe", _setup_marker)

    with pytest.raises(pytest.xfail.Exception, match="keypair generation"):
        test_error_path_rsa.TestRsaPkcsDecryptErrorPaths().test_rsa_pkcs_decrypt_random_ciphertext(
            _RawSession(),
            cfg,
        )


def test_rsa_verify_probe_xfails_setup_before_child(monkeypatch: pytest.MonkeyPatch) -> None:
    """RSA verify crash probes should not spawn if setup keygen is unavailable."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _setup_marker(*_args: object, **_kwargs: object) -> ProbeResult:
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:RSA verify keypair generation rejected: CKR_FUNCTION_FAILED\n",
            stderr="",
        )

    monkeypatch.setattr(test_error_path_rsa, "run_probe", _setup_marker)

    with pytest.raises(pytest.xfail.Exception, match="keypair generation"):
        test_error_path_rsa.TestRsaVerifyCorruptedSignature().test_rsa_verify_corrupted_signature(
            _RawSession(),
            cfg,
        )


def _rsa_marker(prefix: str, payload: str) -> str:
    return f"{prefix}:{payload}\n"


def _rsa_complete_decrypt_output(*, case: str = "decrypt:pkcs:random", rv: int = 0x40) -> str:
    return "".join(
        (
            _rsa_marker(
                "RSA_ATTRIBUTE",
                (
                    f'{{"schema":1,"case":"{case}","operation":"C_GetAttributeValue",'
                    '"attribute":{"name":"CKA_MODULUS","id":288},'
                    '"state":"present","value_len":256,"modulus_bits":2048}'
                ),
            ),
            _rsa_marker(
                "RSA_RV",
                (
                    f'{{"schema":1,"case":"{case}","stage":"decrypt_init",'
                    '"operation":"C_DecryptInit","mechanism":"CKM_RSA_PKCS","rv":0}'
                ),
            ),
            _rsa_marker(
                "RSA_RV",
                (
                    f'{{"schema":1,"case":"{case}","stage":"decrypt",'
                    f'"operation":"C_Decrypt","mechanism":"CKM_RSA_PKCS","rv":{rv}}}'
                ),
            ),
            _rsa_marker(
                "RSA_DONE",
                f'{{"schema":1,"case":"{case}","status":"complete"}}',
            ),
        )
    )


def test_rsa_protocol_accepts_complete_rejection_without_legacy_markers() -> None:
    """The RSA child protocol carries a complete, case-bound provider observation."""
    test_error_path_rsa._check_protocol(
        0,
        _rsa_complete_decrypt_output(),
        "",
        case_id="decrypt:pkcs:random",
        mechanism="CKM_RSA_PKCS",
        operation="C_Decrypt",
        expected_rvs=(0x40,),
        requires_attribute=True,
    )
    assert C.get_records() == []


def test_rsa_protocol_preserves_modulus_omission_without_inventing_ckr() -> None:
    output = "".join(
        (
            _rsa_marker(
                "RSA_ATTRIBUTE",
                '{"schema":1,"case":"decrypt:pkcs:random","operation":"C_GetAttributeValue",'
                '"attribute":{"name":"CKA_MODULUS","id":288},"state":"missing"}',
            ),
            _rsa_marker(
                "RSA_DONE",
                '{"schema":1,"case":"decrypt:pkcs:random","status":"omitted"}',
            ),
        )
    )
    with pytest.raises(pytest.xfail.Exception, match="modulus unavailable"):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id="decrypt:pkcs:random",
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation"]
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].actual_ckr is None


def test_rsa_protocol_parses_independent_rv_after_malformed_attribute() -> None:
    output = "".join(
        (
            _rsa_marker(
                "RSA_ATTRIBUTE",
                '{"schema":1,"case":"decrypt:pkcs:random","operation":"C_GetAttributeValue",'
                '"attribute":{"name":"CKA_MODULUS","id":288},'
                '"state":"present","value_len":256,"modulus_bits":2048,}',
            ),
            _rsa_marker(
                "RSA_RV",
                (
                    '{"schema":1,"case":"decrypt:pkcs:random","stage":"decrypt_init",'
                    '"operation":"C_DecryptInit","mechanism":"CKM_RSA_PKCS","rv":0}'
                ),
            ),
            _rsa_marker(
                "RSA_RV",
                (
                    '{"schema":1,"case":"decrypt:pkcs:random","stage":"decrypt",'
                    '"operation":"C_Decrypt","mechanism":"CKM_RSA_PKCS","rv":0}'
                ),
            ),
            _rsa_marker(
                "RSA_DONE",
                '{"schema":1,"case":"decrypt:pkcs:random","status":"complete"}',
            ),
        )
    )
    # FABLE I-3: CKR_OK on a CKM_RSA_PKCS decrypt of malformed ciphertext is classified
    # honest_deviation (implicit-rejection countermeasure), not accepted_invalid --
    # it no longer outranks the independent harness_error from the malformed
    # attribute marker, so that is what _raise_strongest surfaces here. The rv is
    # still parsed and recorded independently of the malformed attribute, which is
    # the property this test exists to prove.
    with pytest.raises(pytest.fail.Exception, match="malformed RSA child protocol"):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id="decrypt:pkcs:random",
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation", "harness_error"]
    assert records[0].detail is not None
    assert records[0].detail.get("implicit_rejection_suspected") is True


# FABLE I-3 regression: RSA PKCS#1 v1.5 implicit rejection (the Bleichenbacher/Marvin
# countermeasure implemented by OpenSSL >= 3.2 and NSS by design) must not be
# branded a CRITICAL accepted_invalid crypto break. CKR_OK on malformed
# CKM_RSA_PKCS decrypt input is honest_deviation (xfail, LOW), carrying
# detail.implicit_rejection_suspected=True; the observation is kept, not hidden.
# CKM_RSA_PKCS_OAEP is unaffected -- implicit rejection is specific to PKCS#1
# v1.5 padding, so CKR_OK there remains a real accepted_invalid finding.
# Mutation check: removing the `stage == "decrypt" and item_mechanism ==
# "CKM_RSA_PKCS"` branch from _record_rv turns
# test_rsa_pkcs_decrypt_ckr_ok_is_honest_deviation_not_accepted_invalid red
# (reason reverts to accepted_invalid/CRITICAL and severity/xfail assertions fail).


def test_rsa_pkcs_decrypt_ckr_ok_is_honest_deviation_not_accepted_invalid() -> None:
    payload = {
        "schema": 1,
        "case": "decrypt:pkcs:random",
        "stage": "decrypt",
        "operation": "C_Decrypt",
        "mechanism": "CKM_RSA_PKCS",
        "rv": 0,
    }
    record = test_error_path_rsa._record_rv(
        payload,
        label="decrypt:pkcs:random C_Decrypt",
        mechanism="CKM_RSA_PKCS",
        expected_rvs=(0x40,),
    )
    assert record is not None
    assert record.reason == "honest_deviation"
    assert record.outcome == "xfail"
    assert record.severity == "LOW"
    assert record.detail is not None
    assert record.detail.get("implicit_rejection_suspected") is True


def test_rsa_oaep_decrypt_ckr_ok_remains_accepted_invalid() -> None:
    payload = {
        "schema": 1,
        "case": "decrypt:oaep:random",
        "stage": "decrypt",
        "operation": "C_Decrypt",
        "mechanism": "CKM_RSA_PKCS_OAEP",
        "rv": 0,
    }
    record = test_error_path_rsa._record_rv(
        payload,
        label="decrypt:oaep:random C_Decrypt",
        mechanism="CKM_RSA_PKCS_OAEP",
        expected_rvs=(0x40,),
    )
    assert record is not None
    assert record.reason == "accepted_invalid"
    assert record.outcome == "fail"
    assert record.severity == "CRITICAL"
    assert record.kind == "crypto"


def test_rsa_pkcs_decrypt_ckr_ok_end_to_end_is_xfail_not_fail() -> None:
    """End-to-end via _check_protocol: a clean CKR_OK-only decrypt trace for
    CKM_RSA_PKCS now xfails (implicit-rejection observation), it does not fail."""
    output = _rsa_complete_decrypt_output(rv=0)
    with pytest.raises(pytest.xfail.Exception):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id="decrypt:pkcs:random",
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation"]


def test_rsa_protocol_accepts_native_width_vendor_ckr() -> None:
    # CK_ULONG is 64-bit on LP64 but 32-bit on Windows: clamp the vendor-range
    # probe to the platform's native max so it stays in the accept region.
    vendor_rv = min(0x1_0000_0001, test_error_path_rsa._NATIVE_CKR_MAX)
    output = _rsa_complete_decrypt_output(rv=vendor_rv)
    with pytest.raises(pytest.xfail.Exception, match="rejected invalid RSA input"):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id="decrypt:pkcs:random",
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    records = C.get_records()
    assert [record.reason for record in records] == ["nonspec_reject"]
    assert records[0].actual_ckr == hex(vendor_rv)


def test_rsa_protocol_rejects_case_mismatch_as_harness_error() -> None:
    with pytest.raises(pytest.fail.Exception, match="case"):
        test_error_path_rsa._check_protocol(
            0,
            _rsa_complete_decrypt_output(case="decrypt:pkcs:truncated"),
            "",
            case_id="decrypt:pkcs:random",
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    assert [record.reason for record in C.get_records()] == ["harness_error"]


def test_rsa_protocol_rejects_mismatched_modulus_attribute_id() -> None:
    output = _rsa_complete_decrypt_output().replace('"id":288', '"id":289')
    with pytest.raises(pytest.fail.Exception, match="attribute descriptor"):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id="decrypt:pkcs:random",
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    assert [record.reason for record in C.get_records()] == ["harness_error"]


def test_rsa_protocol_empty_signature_is_hard_crypto_result() -> None:
    case = "verify:sha256_rsa_pkcs:bitflip"
    output = "".join(
        (
            _rsa_marker(
                "RSA_RV",
                (
                    f'{{"schema":1,"case":"{case}","stage":"sign",'
                    '"operation":"C_Sign","mechanism":"CKM_SHA256_RSA_PKCS",'
                    '"rv":0,"value_len":0}'
                ),
            ),
            _rsa_marker(
                "RSA_RV",
                (
                    f'{{"schema":1,"case":"{case}","stage":"verify_init",'
                    '"operation":"C_VerifyInit","mechanism":"CKM_SHA256_RSA_PKCS","rv":0}'
                ),
            ),
            _rsa_marker(
                "RSA_RV",
                (
                    f'{{"schema":1,"case":"{case}","stage":"verify",'
                    '"operation":"C_Verify","mechanism":"CKM_SHA256_RSA_PKCS","rv":192}'
                ),
            ),
            _rsa_marker("RSA_DONE", f'{{"schema":1,"case":"{case}","status":"complete"}}'),
        )
    )
    with pytest.raises(pytest.fail.Exception, match="empty signature"):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id=case,
            mechanism="CKM_SHA256_RSA_PKCS",
            operation="C_Verify",
            expected_rvs=(0xC0,),
            requires_attribute=False,
        )
    records = C.get_records()
    assert [record.reason for record in records] == [
        "wrong_result",
        "honest_deviation",
        "harness_error",
    ]
    assert records[0].kind == "crypto"


def _rsa_verify_output(*, baseline_rv: int, mutated_rv: int) -> str:
    case = "verify:sha256_rsa_pkcs:bitflip"
    return "".join(
        (
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"sign",'
                '"operation":"C_Sign","mechanism":"CKM_SHA256_RSA_PKCS",'
                '"rv":0,"value_len":256}',
            ),
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"verify_baseline_init",'
                '"operation":"C_VerifyInit","mechanism":"CKM_SHA256_RSA_PKCS","rv":0}',
            ),
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"verify_baseline",'
                f'"operation":"C_Verify","mechanism":"CKM_SHA256_RSA_PKCS","rv":{baseline_rv}}}',
            ),
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"verify_init",'
                '"operation":"C_VerifyInit","mechanism":"CKM_SHA256_RSA_PKCS","rv":0}',
            ),
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"verify",'
                f'"operation":"C_Verify","mechanism":"CKM_SHA256_RSA_PKCS","rv":{mutated_rv}}}',
            ),
            _rsa_marker("RSA_DONE", f'{{"schema":1,"case":"{case}","status":"complete"}}'),
        )
    )


def _rsa_verify_output_with_malformed_rv(*, stage: str | None, escaped: bool = False) -> str:
    case = "verify:sha256_rsa_pkcs:bitflip"
    stage_value = "null" if stage is None else f'"{stage}"'
    if escaped:
        stage_value = '"verify_\\u0062aseline"'
    malformed = _rsa_marker(
        "RSA_RV",
        (
            f'{{"schema":1,"case":"{case}","stage":{stage_value},'
            '"operation":"C_Verify","mechanism":"CKM_SHA256_RSA_PKCS","rv":true}'
        ),
    )
    done = f'RSA_DONE:{{"schema":1,"case":"{case}","status":"complete"}}\n'
    return _rsa_verify_output(baseline_rv=0, mutated_rv=0).replace(done, malformed + done)


def _rsa_verify_output_with_duplicate_stage(*, stage_fields: str) -> str:
    case = "verify:sha256_rsa_pkcs:bitflip"
    malformed = _rsa_marker(
        "RSA_RV",
        (
            f'{{"schema":1,"case":"{case}",{stage_fields},'
            '"operation":"C_Verify","mechanism":"CKM_SHA256_RSA_PKCS","rv":true}'
        ),
    )
    done = f'RSA_DONE:{{"schema":1,"case":"{case}","status":"complete"}}\n'
    return _rsa_verify_output(baseline_rv=0, mutated_rv=0).replace(done, malformed + done)


@pytest.mark.parametrize("state", ["missing", "malformed", "inconsistent"])
@pytest.mark.parametrize("decrypt_rv", [0, 0x40, 0x54])
def test_rsa_terminal_attribute_disables_decrypt_oracle_for_all_terminal_rvs(
    state: str, decrypt_rv: int
) -> None:
    case = "decrypt:pkcs:random"
    fields: dict[str, object] = {
        "missing": {"state": "missing"},
        "malformed": {"state": "malformed", "value_type": "bytes", "value_repr": "bad"},
        "inconsistent": {
            "state": "inconsistent",
            "value_len": 255,
            "modulus_bits": 2040,
            "expected_bits": 2048,
        },
    }[state]
    attribute_payload = {
        "schema": 1,
        "case": case,
        "operation": "C_GetAttributeValue",
        "attribute": {"name": "CKA_MODULUS", "id": 288},
        **fields,
    }
    done_status = "omitted" if state == "missing" else "malformed"
    output = "".join(
        (
            _rsa_marker("RSA_ATTRIBUTE", json.dumps(attribute_payload, separators=(",", ":"))),
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"decrypt_init",'
                '"operation":"C_DecryptInit","mechanism":"CKM_RSA_PKCS","rv":0}',
            ),
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"decrypt",'
                f'"operation":"C_Decrypt","mechanism":"CKM_RSA_PKCS","rv":{decrypt_rv}}}',
            ),
            _rsa_marker(
                "RSA_DONE",
                f'{{"schema":1,"case":"{case}","status":"{done_status}"}}',
            ),
        )
    )
    with pytest.raises(pytest.fail.Exception):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id=case,
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    records = C.get_records()
    assert not any(record.reason == "accepted_invalid" for record in records)
    dependent = [
        record
        for record in records
        if record.detail is not None
        and record.detail.get("stage") == "decrypt"
        and record.detail.get("oracle_disabled") is True
    ]
    assert len(dependent) == 1
    assert dependent[0].actual_ckr == test_error_path_rsa.ckr_name(decrypt_rv)
    assert any(record.reason == "harness_error" for record in records)


@pytest.mark.parametrize(
    ("rc", "stderr"),
    [(-11, "segmentation fault"), (0, f"{SUBPROCESS_TIMEOUT_MARKER}:15s\n")],
)
def test_rsa_terminal_attribute_preserves_oracle_disabled_evidence_on_process_failure(
    rc: int, stderr: str
) -> None:
    case = "decrypt:pkcs:random"
    output = "".join(
        (
            _rsa_marker(
                "RSA_ATTRIBUTE",
                (
                    f'{{"schema":1,"case":"{case}","operation":"C_GetAttributeValue",'
                    '"attribute":{"name":"CKA_MODULUS","id":288},'
                    '"state":"inconsistent","value_len":255,"modulus_bits":2040,'
                    '"expected_bits":2048}'
                ),
            ),
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"decrypt_init",'
                '"operation":"C_DecryptInit","mechanism":"CKM_RSA_PKCS","rv":0}',
            ),
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"decrypt",'
                '"operation":"C_Decrypt","mechanism":"CKM_RSA_PKCS","rv":0}',
            ),
            _rsa_marker("RSA_DONE", f'{{"schema":1,"case":"{case}","status":"malformed"}}'),
        )
    )
    with pytest.raises(pytest.fail.Exception):
        test_error_path_rsa._check_protocol(
            rc,
            output,
            stderr,
            case_id=case,
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    records = C.get_records()
    assert not any(record.reason == "accepted_invalid" for record in records)
    assert any(
        record.detail is not None
        and record.detail.get("stage") == "decrypt"
        and record.detail.get("oracle_disabled") is True
        for record in records
    )
    assert any(record.reason == "harness_error" for record in records)
    assert any(record.reason == "crash" for record in records)


@pytest.mark.parametrize(
    ("stage", "escaped"),
    [("sign", False), (None, True), ("verify_init", False), ("verify", False), (None, False)],
)
def test_rsa_malformed_lineage_marker_disables_mutation_oracle(
    stage: str | None, escaped: bool
) -> None:
    with pytest.raises(pytest.fail.Exception):
        test_error_path_rsa._check_protocol(
            0,
            _rsa_verify_output_with_malformed_rv(stage=stage, escaped=escaped),
            "",
            case_id="verify:sha256_rsa_pkcs:bitflip",
            mechanism="CKM_SHA256_RSA_PKCS",
            operation="C_Verify",
            expected_rvs=(0xC0,),
            requires_attribute=False,
        )
    records = C.get_records()
    assert not any(record.reason == "accepted_invalid" for record in records)
    assert any(record.reason == "harness_error" for record in records)


@pytest.mark.parametrize(
    "stage_fields",
    [
        '"stage":"sign","stage":"keygen"',
        '"stage":"keygen","stage":"sign"',
        '"stage":"sign","\\u0073tage":"keygen"',
        '"stage":"sign","stage":"\\u006beygen"',
    ],
)
@pytest.mark.parametrize(
    ("rc", "stderr", "expected_records"),
    [
        (0, "", ["honest_deviation", "harness_error"]),
        (-11, "segmentation fault", ["honest_deviation", "harness_error", "crash"]),
        (0, f"{SUBPROCESS_TIMEOUT_MARKER}:15s\n", ["honest_deviation", "harness_error", "crash"]),
    ],
)
def test_rsa_duplicate_stage_keys_conservatively_disable_mutation_oracle(
    stage_fields: str,
    rc: int,
    stderr: str,
    expected_records: list[str],
) -> None:
    with pytest.raises(pytest.fail.Exception):
        test_error_path_rsa._check_protocol(
            rc,
            _rsa_verify_output_with_duplicate_stage(stage_fields=stage_fields),
            stderr,
            case_id="verify:sha256_rsa_pkcs:bitflip",
            mechanism="CKM_SHA256_RSA_PKCS",
            operation="C_Verify",
            expected_rvs=(0xC0,),
            requires_attribute=False,
        )
    records = C.get_records()
    assert [record.reason for record in records] == expected_records
    assert not any(record.reason == "accepted_invalid" for record in records)
    assert records[0].detail is not None
    assert records[0].detail["oracle_disabled"] is True


def test_rsa_verify_baseline_rejection_is_visible_and_disables_mutation_oracle() -> None:
    with pytest.raises(pytest.fail.Exception, match="own successful signature"):
        test_error_path_rsa._check_protocol(
            0,
            _rsa_verify_output(baseline_rv=0xC0, mutated_rv=0),
            "",
            case_id="verify:sha256_rsa_pkcs:bitflip",
            mechanism="CKM_SHA256_RSA_PKCS",
            operation="C_Verify",
            expected_rvs=(0xC0,),
            requires_attribute=False,
        )
    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "honest_deviation"]
    assert records[0].kind == "crypto"
    assert not any(record.reason == "accepted_invalid" for record in records)


def test_rsa_verify_baseline_success_allows_mutation_rejection() -> None:
    test_error_path_rsa._check_protocol(
        0,
        _rsa_verify_output(baseline_rv=0, mutated_rv=0xC0),
        "",
        case_id="verify:sha256_rsa_pkcs:bitflip",
        mechanism="CKM_SHA256_RSA_PKCS",
        operation="C_Verify",
        expected_rvs=(0xC0,),
        requires_attribute=False,
    )
    assert C.get_records() == []


@pytest.mark.parametrize(
    ("stage", "rv", "status", "operation", "mechanism", "expected_reason"),
    [
        (
            "keygen",
            0x54,
            "setup_refused",
            "C_GenerateKeyPair",
            "CKM_RSA_PKCS_KEY_PAIR_GEN",
            "not_operational",
        ),
        (
            "keygen",
            0x80000001,
            "setup_refused",
            "C_GenerateKeyPair",
            "CKM_RSA_PKCS_KEY_PAIR_GEN",
            "not_operational",
        ),
        (
            "keygen",
            0x7FFFFFFF,
            "setup_refused",
            "C_GenerateKeyPair",
            "CKM_RSA_PKCS_KEY_PAIR_GEN",
            "wrong_result",
        ),
        (
            "attribute_read",
            0x54,
            "oracle_disabled",
            "C_GetAttributeValue",
            "CKM_RSA_PKCS",
            "not_operational",
        ),
        (
            "attribute_read",
            0x80000001,
            "oracle_disabled",
            "C_GetAttributeValue",
            "CKM_RSA_PKCS",
            "not_operational",
        ),
        (
            "attribute_read",
            0x7FFFFFFF,
            "oracle_disabled",
            "C_GetAttributeValue",
            "CKM_RSA_PKCS",
            "wrong_result",
        ),
    ],
)
def test_rsa_terminal_setup_rv_is_classified_without_modulus(
    stage: str,
    rv: int,
    status: str,
    operation: str,
    mechanism: str,
    expected_reason: str,
) -> None:
    case = "decrypt:pkcs:random"
    output = "".join(
        (
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"{stage}",'
                f'"operation":"{operation}","mechanism":"{mechanism}","rv":{rv}}}',
            ),
            _rsa_marker("RSA_DONE", f'{{"schema":1,"case":"{case}","status":"{status}"}}'),
        )
    )
    outcome = (
        pytest.xfail.Exception if expected_reason == "not_operational" else pytest.fail.Exception
    )
    with pytest.raises(outcome):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id=case,
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    records = C.get_records()
    assert [record.reason for record in records] == [expected_reason]
    if expected_reason == "wrong_result":
        assert records[0].kind == "metadata"


def test_rsa_terminal_setup_branch_rejects_mixed_attribute() -> None:
    case = "decrypt:pkcs:random"
    output = (
        _rsa_marker(
            "RSA_RV",
            f'{{"schema":1,"case":"{case}","stage":"keygen",'
            '"operation":"C_GenerateKeyPair","mechanism":"CKM_RSA_PKCS_KEY_PAIR_GEN","rv":84}',
        )
        + _rsa_marker(
            "RSA_ATTRIBUTE",
            f'{{"schema":1,"case":"{case}","operation":"C_GetAttributeValue",'
            '"attribute":{"name":"CKA_MODULUS","id":288},"state":"missing"}',
        )
        + _rsa_marker("RSA_DONE", f'{{"schema":1,"case":"{case}","status":"setup_refused"}}')
    )
    with pytest.raises(pytest.fail.Exception):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id=case,
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    assert any(record.reason == "harness_error" for record in C.get_records())


def test_rsa_setup_marker_is_recorded_when_rsa_markers_are_mixed() -> None:
    output = "SETUP_XFAIL:module setup incomplete\n" + _rsa_complete_decrypt_output(rv=0x40)
    with pytest.raises(pytest.fail.Exception, match="malformed RSA child protocol"):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id="decrypt:pkcs:random",
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    assert [record.reason for record in C.get_records()] == ["not_operational", "harness_error"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_rsa_done_before_cleanup_crash_is_validated_before_crash() -> None:
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        test_error_path_rsa._check_protocol(
            -11,
            _rsa_complete_decrypt_output(rv=0x40),
            "cleanup access violation",
            case_id="decrypt:pkcs:random",
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    records = C.get_records()
    assert [record.reason for record in records] == ["crash"]
    assert records[0].detail is not None
    assert records[0].detail["parsed_measurement"]["done"] == [{"status": "complete"}]


def test_rsa_missing_modulus_attaches_dependent_terminal_measurement() -> None:
    case = "decrypt:pkcs:random"
    output = "".join(
        (
            _rsa_marker(
                "RSA_ATTRIBUTE",
                f'{{"schema":1,"case":"{case}","operation":"C_GetAttributeValue",'
                '"attribute":{"name":"CKA_MODULUS","id":288},"state":"missing"}',
            ),
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"decrypt_init",'
                '"operation":"C_DecryptInit","mechanism":"CKM_RSA_PKCS","rv":0}',
            ),
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"decrypt",'
                '"operation":"C_Decrypt","mechanism":"CKM_RSA_PKCS","rv":84}',
            ),
            _rsa_marker("RSA_DONE", f'{{"schema":1,"case":"{case}","status":"omitted"}}'),
        )
    )
    with pytest.raises(pytest.fail.Exception, match="attribute_terminality"):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id=case,
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    records = C.get_records()
    omission = next(record for record in records if record.reason == "honest_deviation")
    assert omission.actual_ckr is None
    assert omission.detail is not None
    assert omission.detail["dependent_terminal"][0]["actual_ckr"] == "CKR_FUNCTION_NOT_SUPPORTED"
    assert any(record.reason == "harness_error" for record in records)


def test_rsa_baseline_pending_is_nonterminal_and_never_accepts_mutation() -> None:
    with pytest.raises(pytest.xfail.Exception):
        test_error_path_rsa._check_protocol(
            0,
            _rsa_verify_output(baseline_rv=0x204, mutated_rv=0),
            "",
            case_id="verify:sha256_rsa_pkcs:bitflip",
            mechanism="CKM_SHA256_RSA_PKCS",
            operation="C_Verify",
            expected_rvs=(0xC0,),
            requires_attribute=False,
        )
    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation", "honest_deviation"]
    assert all(record.detail is not None for record in records)
    assert not any(record.reason == "accepted_invalid" for record in records)


def test_rsa_duplicate_baseline_never_enables_mutation_oracle() -> None:
    output = _rsa_verify_output(baseline_rv=0, mutated_rv=0).replace(
        'RSA_DONE:{"schema":1,"case":"verify:sha256_rsa_pkcs:bitflip","status":"complete"}',
        _rsa_marker(
            "RSA_RV",
            '{"schema":1,"case":"verify:sha256_rsa_pkcs:bitflip","stage":"verify_baseline",'
            '"operation":"C_Verify","mechanism":"CKM_SHA256_RSA_PKCS","rv":0}',
        ).rstrip("\n")
        + "\n"
        + 'RSA_DONE:{"schema":1,"case":"verify:sha256_rsa_pkcs:bitflip","status":"complete"}',
    )
    with pytest.raises(pytest.fail.Exception):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id="verify:sha256_rsa_pkcs:bitflip",
            mechanism="CKM_SHA256_RSA_PKCS",
            operation="C_Verify",
            expected_rvs=(0xC0,),
            requires_attribute=False,
        )
    assert not any(record.reason == "accepted_invalid" for record in C.get_records())


def test_rsa_incoherent_baseline_order_never_enables_mutation_oracle() -> None:
    output = _rsa_verify_output(baseline_rv=0, mutated_rv=0)
    baseline_init = _rsa_marker(
        "RSA_RV",
        '{"schema":1,"case":"verify:sha256_rsa_pkcs:bitflip","stage":"verify_baseline_init",'
        '"operation":"C_VerifyInit","mechanism":"CKM_SHA256_RSA_PKCS","rv":0}',
    )
    baseline = _rsa_marker(
        "RSA_RV",
        '{"schema":1,"case":"verify:sha256_rsa_pkcs:bitflip","stage":"verify_baseline",'
        '"operation":"C_Verify","mechanism":"CKM_SHA256_RSA_PKCS","rv":0}',
    )
    output = output.replace(baseline_init + baseline, baseline + baseline_init)
    with pytest.raises(pytest.fail.Exception):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id="verify:sha256_rsa_pkcs:bitflip",
            mechanism="CKM_SHA256_RSA_PKCS",
            operation="C_Verify",
            expected_rvs=(0xC0,),
            requires_attribute=False,
        )
    assert not any(record.reason == "accepted_invalid" for record in C.get_records())


@pytest.mark.parametrize(
    "output",
    [
        _rsa_marker(
            "RSA_RV",
            '{"schema":1,"case":"decrypt:pkcs:random","stage":"decrypt",'
            '"operation":"C_Decrypt","mechanism":"CKM_RSA_PKCS","rv":0}',
        ),
        _rsa_marker(
            "RSA_RV",
            '{"schema":1,"case":"verify:sha256_rsa_pkcs:bitflip","stage":"verify_baseline",'
            '"operation":"C_Verify","mechanism":"CKM_SHA256_RSA_PKCS","rv":0}',
        ),
    ],
)
def test_rsa_impossible_interrupted_transition_is_harness_error(output: str) -> None:
    case = "decrypt:pkcs:random" if "C_Decrypt" in output else "verify:sha256_rsa_pkcs:bitflip"
    mechanism = "CKM_RSA_PKCS" if case.startswith("decrypt") else "CKM_SHA256_RSA_PKCS"
    operation = "C_Decrypt" if case.startswith("decrypt") else "C_Verify"
    with pytest.raises(pytest.fail.Exception):
        test_error_path_rsa._check_protocol(
            -11,
            output,
            "segmentation fault",
            case_id=case,
            mechanism=mechanism,
            operation=operation,
            expected_rvs=(0x40,) if case.startswith("decrypt") else (0xC0,),
            requires_attribute=case.startswith("decrypt"),
        )
    assert any(record.reason == "harness_error" for record in C.get_records())


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
@pytest.mark.parametrize("state", ["missing", "malformed", "inconsistent"])
def test_rsa_attribute_terminal_state_rejects_decrypt_tail_on_crash(state: str) -> None:
    case = "decrypt:pkcs:random"
    fields: dict[str, dict[str, object]] = {
        "missing": {"state": "missing"},
        "malformed": {
            "state": "malformed",
            "value_type": "bytes",
            "value_repr": "bad",
        },
        "inconsistent": {
            "state": "inconsistent",
            "value_len": 255,
            "modulus_bits": 2040,
            "expected_bits": 2048,
        },
    }
    attribute_payload = {
        "schema": 1,
        "case": case,
        "operation": "C_GetAttributeValue",
        "attribute": {"name": "CKA_MODULUS", "id": 288},
        **fields[state],
    }
    output = "".join(
        (
            _rsa_marker(
                "RSA_ATTRIBUTE",
                json.dumps(attribute_payload, separators=(",", ":")),
            ),
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"decrypt_init",'
                '"operation":"C_DecryptInit","mechanism":"CKM_RSA_PKCS","rv":0}',
            ),
        )
    )
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        test_error_path_rsa._check_protocol(
            -11,
            output,
            "segmentation fault",
            case_id=case,
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    records = C.get_records()
    assert records[-1].reason == "crash"
    assert any(record.reason == "harness_error" for record in records)


def test_rsa_mutation_unexpected_defined_rv_is_oracle_disabled_without_baseline() -> None:
    with pytest.raises(pytest.xfail.Exception):
        test_error_path_rsa._check_protocol(
            0,
            _rsa_verify_output(baseline_rv=0x54, mutated_rv=0x05),
            "",
            case_id="verify:sha256_rsa_pkcs:bitflip",
            mechanism="CKM_SHA256_RSA_PKCS",
            operation="C_Verify",
            expected_rvs=(0xC0,),
            requires_attribute=False,
        )
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "honest_deviation"]
    assert records[1].detail is not None
    assert records[1].detail["oracle_disabled"] is True


@pytest.mark.parametrize(
    ("defect", "reason"),
    [
        ("unknown", "harness_error"),
        ("missing_done", "probe_incomplete"),
        ("wrong_status", "harness_error"),
        ("duplicate_done", "harness_error"),
        ("malformed_done", "harness_error"),
    ],
)
def test_rsa_valid_baseline_keeps_mutation_finding_with_unrelated_protocol_defect(
    defect: str,
    reason: str,
) -> None:
    case = "verify:sha256_rsa_pkcs:bitflip"
    output = _rsa_verify_output(baseline_rv=0, mutated_rv=0)
    done = 'RSA_DONE:{"schema":1,"case":"verify:sha256_rsa_pkcs:bitflip","status":"complete"}\n'
    if defect == "unknown":
        output += 'RSA_FUTURE:{"schema":1}\n'
    elif defect == "missing_done":
        output = output.replace(done, "")
    elif defect == "wrong_status":
        output = output.replace('"status":"complete"', '"status":"omitted"')
    elif defect == "duplicate_done":
        output += done
    else:
        output = output.replace(done, "RSA_DONE:{not-json}\n")
    with pytest.raises(pytest.fail.Exception, match="accepted invalid"):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id=case,
            mechanism="CKM_SHA256_RSA_PKCS",
            operation="C_Verify",
            expected_rvs=(0xC0,),
            requires_attribute=False,
        )
    records = C.get_records()
    assert [record.reason for record in records] == ["accepted_invalid", reason]


def test_rsa_valid_baseline_keeps_mutation_finding_before_timeout() -> None:
    with pytest.raises(pytest.fail.Exception, match="timed out"):
        test_error_path_rsa._check_protocol(
            0,
            _rsa_verify_output(baseline_rv=0, mutated_rv=0),
            f"{SUBPROCESS_TIMEOUT_MARKER}:15s\n",
            case_id="verify:sha256_rsa_pkcs:bitflip",
            mechanism="CKM_SHA256_RSA_PKCS",
            operation="C_Verify",
            expected_rvs=(0xC0,),
            requires_attribute=False,
        )
    assert [record.reason for record in C.get_records()] == ["accepted_invalid", "crash"]


def test_rsa_protocol_duplicate_json_key_is_harness_error() -> None:
    case = "decrypt:pkcs:random"
    output = "".join(
        (
            _rsa_marker(
                "RSA_ATTRIBUTE",
                (
                    f'{{"schema":1,"schema":1,"case":"{case}",'
                    '"attribute":"CKA_MODULUS","state":"missing"}'
                ),
            ),
            _rsa_marker("RSA_DONE", f'{{"schema":1,"case":"{case}","status":"omitted"}}'),
        )
    )
    with pytest.raises(pytest.fail.Exception, match="duplicate key"):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id=case,
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    assert [record.reason for record in C.get_records()] == ["harness_error"]


def test_rsa_protocol_missing_downstream_stage_is_harness_error() -> None:
    case = "decrypt:pkcs:random"
    output = "".join(
        (
            _rsa_marker(
                "RSA_ATTRIBUTE",
                f'{{"schema":1,"case":"{case}","operation":"C_GetAttributeValue",'
                '"attribute":{"name":"CKA_MODULUS","id":288},'
                '"state":"present","value_len":256,"modulus_bits":2048}',
            ),
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"decrypt_init",'
                '"operation":"C_DecryptInit","mechanism":"CKM_RSA_PKCS","rv":0}',
            ),
            _rsa_marker("RSA_DONE", f'{{"schema":1,"case":"{case}","status":"complete"}}'),
        )
    )
    with pytest.raises(pytest.fail.Exception, match="cardinality"):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id=case,
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    assert [record.reason for record in C.get_records()] == ["harness_error"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_rsa_setup_marker_survives_later_signal_crash() -> None:
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        test_error_path_rsa._check_protocol(
            -11,
            "SETUP_XFAIL:RSA keypair generation rejected: CKR_FUNCTION_FAILED\n",
            "segmentation fault",
            case_id="decrypt:pkcs:random",
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "crash"]


def test_rsa_bad_random_ciphertext_is_outside_modulus() -> None:
    modulus = (1 << 2047) + 159
    bad = error_path_rsa_probe._make_bad_ct("random", modulus.to_bytes(256, "big"), 256)
    assert len(bad) == 256
    assert int.from_bytes(bad, "big") >= modulus


def test_rsa_child_emits_successful_decrypt_init_before_terminal_crash(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class _CrashOnDecrypt:
        def C_DecryptInit(self, *_args: object) -> int:  # noqa: N802
            return 0

        def C_Decrypt(self, *_args: object) -> int:  # noqa: N802
            raise OSError("provider crash")

    with pytest.raises(OSError, match="provider crash"):
        error_path_rsa_probe._pkcs_decrypt(
            _CrashOnDecrypt(),
            1,
            2,
            b"\x00" * 256,
            256,
            "decrypt:pkcs:all_zeros",
        )

    output = capsys.readouterr().out
    assert '"stage":"decrypt_init"' in output
    assert '"rv":0' in output
    assert '"stage":"decrypt"' not in output


def test_rsa_child_keygen_refusal_is_case_bound_rv(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A provider key-generation refusal is evidence, not a generic setup marker."""
    error = error_path_rsa_probe.CkrAssertionError("refused", 0x54)

    def _refuse(*_args: object, **_kwargs: object) -> tuple[int, int]:
        raise error

    monkeypatch.setattr(error_path_rsa_probe, "gen_rsa_keypair", _refuse)
    ctx = SimpleNamespace(raw=object(), sh=1)
    error_path_rsa_probe._run_decrypt(
        ctx,
        {"probe": "decrypt", "mech": "pkcs", "variant": "random"},
    )
    output = capsys.readouterr().out
    assert "SETUP_XFAIL" not in output
    assert '"stage":"keygen"' in output
    assert '"operation":"C_GenerateKeyPair"' in output
    assert '"status":"setup_refused"' in output


def test_rsa_child_attribute_refusal_is_case_bound_rv(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A modulus read refusal identifies C_GetAttributeValue and disables the oracle."""
    monkeypatch.setattr(error_path_rsa_probe, "gen_rsa_keypair", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(
        error_path_rsa_probe,
        "read_attributes",
        lambda *_a, **_k: (_ for _ in ()).throw(
            error_path_rsa_probe.CkrAssertionError("refused", 0x54)
        ),
    )
    monkeypatch.setattr(error_path_rsa_probe, "destroy_quietly", lambda *_a, **_k: None)
    ctx = SimpleNamespace(raw=object(), sh=1)
    error_path_rsa_probe._run_decrypt(
        ctx,
        {"probe": "decrypt", "mech": "pkcs", "variant": "random"},
    )
    output = capsys.readouterr().out
    assert '"stage":"attribute_read"' in output
    assert '"operation":"C_GetAttributeValue"' in output
    assert '"status":"oracle_disabled"' in output


def test_rsa_child_missing_modulus_emits_one_fact_and_cleans_both_handles(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A missing modulus omits decrypt while preserving exact evidence and cleanup."""
    handles: list[int] = []
    monkeypatch.setattr(error_path_rsa_probe, "gen_rsa_keypair", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(error_path_rsa_probe, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        error_path_rsa_probe,
        "destroy_quietly",
        lambda _raw, _sh, handle: handles.append(handle),
    )
    ctx = SimpleNamespace(raw=object(), sh=1)

    error_path_rsa_probe._run_decrypt(
        ctx,
        {"probe": "decrypt", "mech": "pkcs", "variant": "random"},
    )

    assert capsys.readouterr().out == (
        'RSA_ATTRIBUTE:{"schema":1,"case":"decrypt:pkcs:random",'
        '"operation":"C_GetAttributeValue","attribute":{"name":"CKA_MODULUS",'
        '"id":288},"state":"missing"}\n'
        'RSA_DONE:{"schema":1,"case":"decrypt:pkcs:random","status":"omitted"}\n'
    )
    assert handles == [11, 12]


def test_rsa_child_present_none_modulus_is_malformed_and_cleans_both_handles(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A present ``None`` modulus is malformed, not provider omission."""
    handles: list[int] = []
    decrypt_calls: list[object] = []
    monkeypatch.setattr(error_path_rsa_probe, "gen_rsa_keypair", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(
        error_path_rsa_probe,
        "read_attributes",
        lambda *_a, **_k: {error_path_rsa_probe.CKA_MODULUS: None},
    )
    monkeypatch.setattr(
        error_path_rsa_probe,
        "destroy_quietly",
        lambda _raw, _sh, handle: handles.append(handle),
    )
    monkeypatch.setattr(
        error_path_rsa_probe,
        "_pkcs_decrypt",
        lambda *_a, **_k: decrypt_calls.append(object()),
    )
    ctx = SimpleNamespace(raw=object(), sh=1)

    error_path_rsa_probe._run_decrypt(
        ctx,
        {"probe": "decrypt", "mech": "pkcs", "variant": "random"},
    )

    assert capsys.readouterr().out == (
        'RSA_ATTRIBUTE:{"schema":1,"case":"decrypt:pkcs:random",'
        '"operation":"C_GetAttributeValue","attribute":{"name":"CKA_MODULUS",'
        '"id":288},"state":"malformed","value_type":"NoneType",'
        '"value_repr":"None"}\n'
        'RSA_DONE:{"schema":1,"case":"decrypt:pkcs:random","status":"malformed"}\n'
    )
    assert decrypt_calls == []
    assert handles == [11, 12]


def test_rsa_error_path_has_no_attribute_access_guard_findings() -> None:
    path = Path(__file__).parents[1] / "src/pkcs11_check/testcases/_probes/error_path_rsa.py"

    assert analyze_file(path) == []


@pytest.mark.parametrize("field", ["case", "stage", "mechanism", "status"])
def test_rsa_hostile_protocol_field_is_harness_error(field: str) -> None:
    case = "decrypt:pkcs:random"
    if field == "status":
        payload: dict[str, object] = {"schema": 1, "case": case, "status": []}
        output = _rsa_marker("RSA_DONE", json.dumps(payload, separators=(",", ":")))
    else:
        payload = {
            "schema": 1,
            "case": [] if field == "case" else case,
            "stage": [] if field == "stage" else "decrypt_init",
            "operation": "C_DecryptInit",
            "mechanism": [] if field == "mechanism" else "CKM_RSA_PKCS",
            "rv": 0,
        }
        output = _rsa_marker("RSA_RV", json.dumps(payload, separators=(",", ":")))
    with pytest.raises(pytest.fail.Exception):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id=case,
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    assert all(record.reason == "harness_error" for record in C.get_records())


def test_rsa_zero_modulus_is_provider_metadata_finding() -> None:
    case = "decrypt:pkcs:random"
    output = _rsa_marker(
        "RSA_ATTRIBUTE",
        f'{{"schema":1,"case":"{case}","operation":"C_GetAttributeValue",'
        '"attribute":{"name":"CKA_MODULUS","id":288},"state":"malformed",'
        '"value_type":"bytes","value_repr":"zero modulus","value_len":0,"modulus_bits":0}',
    ) + _rsa_marker("RSA_DONE", f'{{"schema":1,"case":"{case}","status":"malformed"}}')
    with pytest.raises(pytest.fail.Exception, match="modulus metadata"):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id=case,
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    assert [record.reason for record in C.get_records()] == ["wrong_result"]
    assert C.get_records()[0].kind == "metadata"


def test_rsa_missing_modulus_does_not_hide_independent_rv_evidence() -> None:
    case = "decrypt:pkcs:random"
    output = "".join(
        (
            _rsa_marker(
                "RSA_ATTRIBUTE",
                f'{{"schema":1,"case":"{case}","operation":"C_GetAttributeValue",'
                '"attribute":{"name":"CKA_MODULUS","id":288},"state":"missing"}',
            ),
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"decrypt_init",'
                '"operation":"C_DecryptInit","mechanism":"CKM_RSA_PKCS","rv":84}',
            ),
            _rsa_marker(
                "RSA_RV",
                f'{{"schema":1,"case":"{case}","stage":"decrypt",'
                '"operation":"C_Decrypt","mechanism":"CKM_RSA_PKCS","rv":2147483647}',
            ),
            _rsa_marker("RSA_DONE", f'{{"schema":1,"case":"{case}","status":"omitted"}}'),
        )
    )
    with pytest.raises(pytest.fail.Exception):
        test_error_path_rsa._check_protocol(
            0,
            output,
            "",
            case_id=case,
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    records = C.get_records()
    assert {record.reason for record in records} >= {
        "honest_deviation",
        "not_operational",
        "wrong_result",
    }
    assert not any(record.reason == "accepted_invalid" for record in records)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_rsa_crash_retains_bounded_parsed_measurements() -> None:
    case = "decrypt:pkcs:random"
    output = _rsa_marker(
        "RSA_ATTRIBUTE",
        f'{{"schema":1,"case":"{case}","operation":"C_GetAttributeValue",'
        '"attribute":{"name":"CKA_MODULUS","id":288},"state":"present",'
        '"value_len":256,"modulus_bits":2048}',
    ) + _rsa_marker(
        "RSA_RV",
        f'{{"schema":1,"case":"{case}","stage":"decrypt_init",'
        '"operation":"C_DecryptInit","mechanism":"CKM_RSA_PKCS","rv":0}',
    )
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        test_error_path_rsa._check_protocol(
            -11,
            output,
            "segmentation fault",
            case_id=case,
            mechanism="CKM_RSA_PKCS",
            operation="C_Decrypt",
            expected_rvs=(0x40,),
            requires_attribute=True,
        )
    crash = next(record for record in C.get_records() if record.reason == "crash")
    assert crash.detail is not None
    assert "parsed_measurement" in crash.detail
    assert len(crash.detail["parsed_measurement"]["rvs"]) == 1


def test_rsa_cleanup_attempts_both_handles_and_prefers_access_violation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    first = OSError("exception: access violation")

    def _destroy(_raw: object, _sh: int, handle: int) -> None:
        calls.append(handle)
        if handle == 11:
            raise first
        raise RuntimeError("second cleanup error")

    monkeypatch.setattr(error_path_rsa_probe, "destroy_quietly", _destroy)
    monkeypatch.setattr(
        error_path_rsa_probe,
        "ctypes_access_violation_code",
        lambda exc: 1 if exc is first else None,
    )
    with pytest.raises(OSError, match="access violation"):
        error_path_rsa_probe._destroy_pair(object(), 1, 11, 12)
    assert calls == [11, 12]


def test_rsa_cleanup_attempts_both_handles_and_preserves_first_noncrash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    first = RuntimeError("first cleanup error")

    def _destroy(_raw: object, _sh: int, handle: int) -> None:
        calls.append(handle)
        if handle == 11:
            raise first
        raise OSError("second cleanup error")

    monkeypatch.setattr(error_path_rsa_probe, "destroy_quietly", _destroy)
    monkeypatch.setattr(error_path_rsa_probe, "ctypes_access_violation_code", lambda _exc: None)
    with pytest.raises(RuntimeError, match="first cleanup error"):
        error_path_rsa_probe._destroy_pair(object(), 1, 11, 12)
    assert calls == [11, 12]


def test_zero_length_aes_cbc_probe_calls_run_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """AES-CBC zero-length crash probe must invoke run_probe with correct params."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(test_api_boundary, "gen_aes_key_or_xfail", lambda *_a, **_kw: 1)
    monkeypatch.setattr(test_api_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_api_boundary, "run_probe", _stub_probe)

    test_api_boundary.TestZeroLengthData().test_zero_length_data(
        _RawSession(),
        cfg,
        "encrypt",
        "AES_CBC",
        "CKM_AES_CBC",
    )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "api_boundary"
    assert params.get("which") == "zero_length_aes"
    assert params.get("operation") == "encrypt"
    assert params.get("mech_name") == "CKM_AES_CBC"


def test_zero_length_aes_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Zero-length AES crash probes should not spawn if setup keygen is unavailable."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(test_api_boundary, "gen_aes_key_or_xfail", _xfail_setup, raising=False)
    monkeypatch.setattr(test_api_boundary, "run_probe", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_api_boundary.TestZeroLengthData().test_zero_length_data(
            _RawSession(),
            cfg,
            "encrypt",
            "AES_ECB",
            "CKM_AES_ECB",
        )


def test_arithmetic_aes_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Arithmetic AES crash probes should preflight setup key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_arithmetic_overflow,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_arithmetic_overflow, "run_probe", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_arithmetic_overflow.TestDataLengthOverflow().test_data_length_overflow(
            _RawSession(),
            cfg,
            0x80000000,
            "C_Encrypt",
            "C_EncryptInit",
        )


def test_arithmetic_aes_probe_calls_run_probe_with_correct_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Arithmetic AES data-length probe must call run_probe with correct probe name and params."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(test_arithmetic_overflow, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_arithmetic_overflow, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_arithmetic_overflow, "run_probe", _stub_probe)

    test_arithmetic_overflow.TestDataLengthOverflow().test_data_length_overflow(
        _RawSession(),
        cfg,
        0x80000000,
        "C_Encrypt",
        "C_EncryptInit",
    )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "arithmetic_overflow"
    assert params.get("which") == "data_length_overflow"
    assert params.get("func") == "C_Encrypt"
    assert params.get("init_func") == "C_EncryptInit"
    assert params.get("data_len") == 0x80000000


def test_arithmetic_pss_probe_calls_run_probe_with_correct_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Arithmetic RSA-PSS probe must call run_probe with correct probe name and params."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        test_arithmetic_overflow,
        "gen_rsa_keypair_or_xfail",
        lambda *_a, **_k: (1, 2),
    )
    monkeypatch.setattr(test_arithmetic_overflow, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_arithmetic_overflow, "run_probe", _stub_probe)

    test_arithmetic_overflow.TestPssSaltLengthOverflow().test_pss_salt_length_overflow(
        _RawSession(),
        cfg,
        0xFFFFFFFF,
    )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "arithmetic_overflow"
    assert params.get("which") == "pss_salt_length_overflow"
    assert params.get("salt_len") == 0xFFFFFFFF


def test_ffi_length_aes_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FFI length AES crash probes should preflight setup key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_length_boundary,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ffi_length_boundary.TestIsizeMaxDataLength().test_encrypt_isize_boundary(
            _RawSession(),
            cfg,
            0x8000000000000000,
        )


def test_ffi_length_aes_child_script_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FFI length AES probe must classify a child setup reject (SETUP_XFAIL) as xfail.

    The AES-keygen setup-reject logic now lives in the ``_probes/ffi_length.py`` child
    (``AES_KEYGEN_RUNTIME_REJECT_RVS`` -> ``_setup_reject_or_raise``); when the child emits
    ``SETUP_XFAIL`` the parent classifies it via ``_classify_unhonorable_length_outcome``
    into an xfail rather than a silent pass.
    """
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestIsizeMaxDataLength().test_encrypt_isize_boundary(
            _RawSession(),
            cfg,
            0x8000000000000000,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "encrypt_isize"
    # The setup-reject logic must live in the probe child, keyed on AES_KEYGEN_RUNTIME_REJECT_RVS.


@pytest.mark.parametrize(
    ("rc", "stderr", "expected"),
    [
        (-11, "", "module crashed with signal 11"),
        (0xC0000005, "", "module crashed with Windows exception"),
        (124, SUBPROCESS_TIMEOUT_MARKER, "module hung"),
    ],
)
def test_unbackable_length_setup_marker_never_hides_crash_or_timeout(
    rc: int, stderr: str, expected: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    if rc == -11 and sys.platform == "win32":
        # On Windows the real platform already renders rc=-11 as the 0xFFFFFFF5
        # NTSTATUS form, so the POSIX "signal 11" text never appears there.
        expected = "module crashed with Windows exception"
    if rc >= 0:
        monkeypatch.setattr("pkcs11_check.core.process_observation.sys.platform", "win32")
    try:
        with pytest.raises(pytest.fail.Exception, match=expected):
            test_ffi_length_boundary._classify_unhonorable_length_outcome(
                rc,
                "SETUP_XFAIL:AES setup failed before teardown\n",
                stderr,
                reject_rvs=(),
                label_op="C_Encrypt(dataLen=2^63)",
                test_id="near-size-max",
            )
    except pytest.xfail.Exception as exc:
        pytest.fail(f"setup marker hid crash/timeout: {exc}")


def test_unhonorable_length_skip_marker_skips_not_xfails() -> None:
    """A child SKIP: line (v3.0 message-family Init/Begin FNS -- capability absence,
    see _probes/_ffi_length_message.py._message_setup_reject) must skip, checked
    before the generic SETUP_XFAIL handling."""
    assert_skips(
        test_ffi_length_boundary._classify_unhonorable_length_outcome,
        0,
        "SKIP:C_MessageEncryptInit rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
        "",
        reject_rvs=(),
        label_op="C_EncryptMessageBegin(plaintext_len=2^63)",
        test_id="near-size-max",
        match="C_MessageEncryptInit",
    )


def test_ffi_length_keypair_child_scripts_mark_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """EC/RSA FFI probes must classify a child setup reject (SETUP_XFAIL) as xfail.

    The keypair-keygen setup-reject logic now lives in the ``_probes/ffi_length.py`` child
    (``KEYPAIR_RUNTIME_REJECT_RVS`` -> ``_setup_reject_or_raise``); when the child emits
    ``SETUP_XFAIL`` the parent classifies it (via ``assert_subprocess_no_crash``) into an
    xfail rather than exposing setup keygen as a probe failure.
    """
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:keypair generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(
        test_ffi_length_boundary,
        "gen_ec_keypair_or_xfail",
        lambda *_a, **_k: (1, 2),
    )
    monkeypatch.setattr(
        test_ffi_length_boundary,
        "gen_rsa_keypair_or_xfail",
        lambda *_a, **_k: (3, 4),
    )
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestMechanismNullInnerParams().test_ecdh_null_public_data(
            _RawSession(),
            cfg,
        )
    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestMechanismNullInnerParams().test_oaep_null_source_data(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 2
    assert all(probe == "ffi_length" for probe, _ in calls)
    assert {params.get("probe") for _, params in calls} == {
        "ecdh_null_public_data",
        "oaep_null_source_data",
    }
    # The setup-reject logic must live in the probe child, keyed on KEYPAIR_RUNTIME_REJECT_RVS.


def test_ffi_length_eddsa_child_script_uses_edwards_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ed25519 crash probes must use CKM_EC_EDWARDS_KEY_PAIR_GEN setup (in the probe child)."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:EC_EDWARDS keygen rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(
        test_ffi_length_boundary,
        "gen_edwards_keypair_or_xfail",
        lambda *_a, **_k: (1, 2),
        raising=False,
    )
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestEddsaNullContext().test_eddsa_null_context_data(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "eddsa_null_context_data"
    # The EdDSA keygen (Edwards) must live in the probe child, not via gen_ec_keypair.
    eddsa_src = inspect.getsource(ffi_length_probe._run_eddsa_null_context_data)
    assert "CKM_EC_EDWARDS_KEY_PAIR_GEN" in eddsa_src
    assert "gen_keypair" in eddsa_src
    assert "gen_ec_keypair" not in eddsa_src


def test_ffi_null_update_aes_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NULL-pointer AES update probes should preflight setup key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=None)

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_null_pointer,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_null_pointer, "run_probe", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ffi_null_pointer.TestNullDataUpdate().test_null_data_update(
            _RawSession(),
            cfg,
            "encrypt",
            "C_EncryptInit",
            "C_EncryptUpdate",
            "AES_CBC",
        )


def test_ffi_null_final_aes_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NULL-output final probes should preflight setup key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=None)

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_null_pointer,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_null_pointer, "run_probe", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ffi_null_pointer.TestNullOutputFinal().test_null_output_final(
            _RawSession(),
            cfg,
            "encrypt",
            "C_EncryptFinal",
            "AES_CBC",
        )


def test_ffi_null_oneshot_aes_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NULL one-shot AES probes should preflight setup key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=None)

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_null_pointer,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_null_pointer, "run_probe", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ffi_null_pointer.TestNullDataOneShot().test_null_data_oneshot(
            _RawSession(),
            cfg,
            "encrypt",
            "C_Encrypt",
            "AES_ECB",
        )


def test_ffi_null_unwrap_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NULL wrapped-data probes should preflight unwrap-key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=None)

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_null_pointer,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_null_pointer, "run_probe", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ffi_null_pointer.TestNullWrapUnwrap().test_unwrap_key_null_wrapped_data(
            _RawSession(),
            cfg,
        )


def test_ffi_null_kem_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NULL KEM ciphertext probes should preflight setup key generation."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=None)

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_ffi_null_pointer,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_ffi_null_pointer, "run_probe", _child_should_not_run)

    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        test_ffi_null_pointer.TestNullKemApi().test_decapsulate_key_null_ciphertext(
            _RawSession(),
            cfg,
        )


def test_ffi_null_pin_scripts_use_utf8char_pointers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIN child probes must dispatch with the correct which keys."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=None)
    calls: list[tuple[str, dict[str, object]]] = []

    def _capture(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(test_ffi_null_pointer, "run_probe", _capture)

    test_ffi_null_pointer.TestNullPinBuffer().test_set_pin_null_old_pin(cfg)
    test_ffi_null_pointer.TestNullPinBuffer().test_set_pin_null_new_pin(cfg)

    assert len(calls) == 2
    assert all(probe == "ffi_null_pointer" for probe, _ in calls)
    which_values = {params.get("which") for _, params in calls}
    assert which_values == {"set_pin_null_old_pin", "set_pin_null_new_pin"}


def test_ffi_null_init_token_scripts_use_utf8char_pointers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_InitToken child probes must dispatch with the correct which keys."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=None)
    calls: list[tuple[str, dict[str, object]]] = []

    def _capture(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(test_ffi_null_pointer, "run_probe", _capture)

    test_ffi_null_pointer.TestNullInitToken().test_init_token_null_pin(cfg)
    test_ffi_null_pointer.TestNullInitToken().test_init_token_null_label(cfg)

    assert len(calls) == 2
    assert all(probe == "ffi_null_pointer" for probe, _ in calls)
    which_values = {params.get("which") for _, params in calls}
    assert which_values == {"init_token_null_pin", "init_token_null_label"}


# ---------------------------------------------------------------------------
# Wave 1: FFI length-boundary probe extensions regression tests.
# Each asserts that the generated child script (a) marks setup rejects inside
# the child and (b) references the right reject-CKR set name. _capture returns
# a SETUP_XFAIL stdout so assert_subprocess_no_crash xfails the probe before
# _parse_prefixed_int runs (these probe classes classify the target rv, unlike
# the legacy TestIsizeMaxDataLength which stops at the no-crash assertion).
# ---------------------------------------------------------------------------


def test_ffi_length_oaep_source_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RSA-OAEP source-data length probe must classify setup rejects in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:RSA keypair generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(
        test_ffi_length_boundary,
        "gen_rsa_keypair_or_xfail",
        lambda *_a, **_k: (3, 4),
    )
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    for boundary in (0x7FFFFFFFFFFFFFFF, 0x8000000000000000):
        with pytest.raises(pytest.xfail.Exception):
            test_ffi_length_boundary.TestRsaOaepSourceDataLengthBoundary().test_rsa_oaep_source_data_length_boundary(  # noqa: E501
                _RawSession(),
                cfg,
                boundary,
            )

    assert len(calls) == 2
    assert all(probe == "ffi_length" for probe, _ in calls)
    assert {params.get("probe") for _, params in calls} == {"rsa_oaep_source_data_length"}


def test_ffi_length_gcm_iv_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TestGcmIvLengthBoundary setup reject must be classified in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    for boundary in (0x7FFFFFFFFFFFFFFF, 0x8000000000000000):
        with pytest.raises(pytest.xfail.Exception):
            test_ffi_length_boundary.TestGcmIvLengthBoundary().test_gcm_iv_length_boundary(
                _RawSession(),
                cfg,
                boundary,
            )

    assert len(calls) == 2
    assert all(probe == "ffi_length" for probe, _ in calls)
    assert {params.get("probe") for _, params in calls} == {"gcm_iv_length"}


def test_ffi_length_gcm_tag_bits_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TestGcmTagBitsLengthBoundary setup reject must be classified in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    for boundary in (0x7FFFFFFFFFFFFFFF, 0x8000000000000000):
        with pytest.raises(pytest.xfail.Exception):
            test_ffi_length_boundary.TestGcmTagBitsLengthBoundary().test_gcm_tag_bits_length_boundary(
                _RawSession(),
                cfg,
                boundary,
            )

    assert len(calls) == 2
    assert all(probe == "ffi_length" for probe, _ in calls)
    assert {params.get("probe") for _, params in calls} == {"gcm_tag_bits_length"}


def test_ffi_length_ccm_nonce_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TestCcmNonceLengthBoundary setup reject must be classified in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    for boundary in (0x7FFFFFFFFFFFFFFF, 0x8000000000000000):
        with pytest.raises(pytest.xfail.Exception):
            test_ffi_length_boundary.TestCcmNonceLengthBoundary().test_ccm_nonce_length_boundary(
                _RawSession(),
                cfg,
                boundary,
            )

    assert len(calls) == 2
    assert all(probe == "ffi_length" for probe, _ in calls)
    assert {params.get("probe") for _, params in calls} == {"ccm_nonce_length"}


def test_ffi_length_ccm_mac_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TestCcmMacLengthBoundary setup reject must be classified in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    for boundary in (0x7FFFFFFFFFFFFFFF, 0x8000000000000000):
        with pytest.raises(pytest.xfail.Exception):
            test_ffi_length_boundary.TestCcmMacLengthBoundary().test_ccm_mac_length_boundary(
                _RawSession(),
                cfg,
                boundary,
            )

    assert len(calls) == 2
    assert all(probe == "ffi_length" for probe, _ in calls)
    assert {params.get("probe") for _, params in calls} == {"ccm_mac_length"}


def test_ffi_length_eddsa_context_child_uses_edwards_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """EdDSA context-length probe must use CKM_EC_EDWARDS_KEY_PAIR_GEN setup in the child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:EC_EDWARDS keygen rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(
        test_ffi_length_boundary,
        "gen_edwards_keypair_or_xfail",
        lambda *_a, **_k: (1, 2),
        raising=False,
    )
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    for boundary in (0x7FFFFFFFFFFFFFFF, 0x8000000000000000):
        with pytest.raises(pytest.xfail.Exception):
            test_ffi_length_boundary.TestEddsaContextLengthBoundary().test_eddsa_context_length_boundary(  # noqa: E501
                _RawSession(),
                cfg,
                boundary,
            )

    assert len(calls) == 2
    assert all(probe == "ffi_length" for probe, _ in calls)
    assert {params.get("probe") for _, params in calls} == {"eddsa_context_length"}
    eddsa_src = inspect.getsource(ffi_length_probe._run_eddsa_context_length)
    assert "CKM_EC_EDWARDS_KEY_PAIR_GEN" in eddsa_src
    assert "gen_keypair" in eddsa_src
    assert "gen_ec_keypair" not in eddsa_src


# ---------------------------------------------------------------------------
# Wave 4: TestUpdateOutputGuard + TestContinueAfterNullOutputQuery regressions
# ---------------------------------------------------------------------------


def test_ffi_length_encrypt_update_guard_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_EncryptUpdate probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestUpdateOutputGuard().test_encrypt_update_one_byte_output_preserves_guard(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "encrypt_update_guard"
    guard_src = inspect.getsource(ffi_length_probe._run_encrypt_update_guard)
    assert "C_EncryptUpdate" in guard_src


def test_ffi_length_encrypt_final_continuation_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_EncryptFinal probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestContinueAfterNullOutputQuery().test_encrypt_final_continuation_after_size_query(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "encrypt_final_continuation"
    guard_src = inspect.getsource(ffi_length_probe._run_encrypt_final_continuation)
    assert "C_EncryptFinal" in guard_src


# ---------------------------------------------------------------------------
# Phase 6 (June-gap I6): TestRecoverInputLengthBoundary + TestRecoverOutputLengthBoundary
# ---------------------------------------------------------------------------


def test_recover_input_length_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_SignRecover input-length probe must classify setup rejects in child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _capture(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        _xfail_stdout = (
            "SETUP_XFAIL:RSA recover keypair generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n"
        )
        return ProbeResult(returncode=0, stdout=_xfail_stdout, stderr="")

    monkeypatch.setattr(test_recover_length_boundary, "run_probe", _capture)

    with pytest.raises(pytest.xfail.Exception):
        test_recover_length_boundary.TestRecoverInputLengthBoundary().test_sign_recover_huge_data_len_does_not_crash(
            _RawSession(),
            cfg,
            0x7FFFFFFFFFFFFFFF,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "recover_length"
    assert params.get("which") == "sign_huge_data_len"
    assert params.get("data_len") == 0x7FFFFFFFFFFFFFFF


def test_recover_output_length_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_VerifyRecover output-length probe must classify setup rejects in child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _capture(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        _xfail_stdout = (
            "SETUP_XFAIL:RSA recover keypair generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n"
        )
        return ProbeResult(returncode=0, stdout=_xfail_stdout, stderr="")

    monkeypatch.setattr(test_recover_length_boundary, "run_probe", _capture)

    with pytest.raises(pytest.xfail.Exception):
        test_recover_length_boundary.TestRecoverOutputLengthBoundary().test_verify_recover_inflated_pul_data_len_does_not_crash(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "recover_length"
    assert params.get("which") == "verify_inflated_out_len"


def test_recover_input_length_child_skips_on_function_level_fns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKR_FUNCTION_NOT_SUPPORTED at C_SignRecoverInit is capability absence (the
    optional recover function itself is unimplemented), not a deviation -- must
    skip, never record an "advertised but not operational" xfail finding."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)

    def _capture(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        skip_stdout = "SKIP:C_SignRecoverInit rejected: CKR_FUNCTION_NOT_SUPPORTED\n"
        return ProbeResult(returncode=0, stdout=skip_stdout, stderr="")

    monkeypatch.setattr(test_recover_length_boundary, "run_probe", _capture)

    assert_skips(
        test_recover_length_boundary.TestRecoverInputLengthBoundary().test_sign_recover_huge_data_len_does_not_crash,
        _RawSession(),
        cfg,
        0x7FFFFFFFFFFFFFFF,
        match="C_SignRecoverInit",
    )


def test_recover_output_length_child_skips_on_function_level_fns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same rule for C_VerifyRecoverInit on the output-length boundary probe."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)

    def _capture(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        skip_stdout = "SKIP:C_VerifyRecoverInit rejected: CKR_FUNCTION_NOT_SUPPORTED\n"
        return ProbeResult(returncode=0, stdout=skip_stdout, stderr="")

    monkeypatch.setattr(test_recover_length_boundary, "run_probe", _capture)

    assert_skips(
        test_recover_length_boundary.TestRecoverOutputLengthBoundary().test_verify_recover_inflated_pul_data_len_does_not_crash,
        _RawSession(),
        cfg,
        match="C_VerifyRecoverInit",
    )


# ---------------------------------------------------------------------------
# Phase 6 (June-gap I7): decrypt-update guard + continuation uncovered methods
# ---------------------------------------------------------------------------


def test_ffi_length_decrypt_update_guard_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_DecryptUpdate probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestUpdateOutputGuard().test_decrypt_update_one_byte_output_preserves_guard(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "decrypt_update_guard"
    guard_src = inspect.getsource(ffi_length_probe._run_decrypt_update_guard)
    assert "C_DecryptUpdate" in guard_src


def test_ffi_length_encrypt_update_continuation_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_EncryptUpdate probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestContinueAfterNullOutputQuery().test_encrypt_update_continuation_after_size_query(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "encrypt_update_continuation"
    guard_src = inspect.getsource(ffi_length_probe._run_encrypt_update_continuation)
    assert "C_EncryptUpdate" in guard_src


def test_ffi_length_decrypt_update_continuation_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_DecryptUpdate probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestContinueAfterNullOutputQuery().test_decrypt_update_continuation_after_size_query(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "decrypt_update_continuation"
    guard_src = inspect.getsource(ffi_length_probe._run_decrypt_update_continuation)
    assert "C_DecryptUpdate" in guard_src


def test_ffi_length_decrypt_final_continuation_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_DecryptFinal probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestContinueAfterNullOutputQuery().test_decrypt_final_continuation_after_size_query(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "decrypt_final_continuation"
    guard_src = inspect.getsource(ffi_length_probe._run_decrypt_final_continuation)
    assert "C_DecryptFinal" in guard_src


# ---------------------------------------------------------------------------
# Phase 2 (June-gap F1/M1): every Category-A FFI length probe must parse + classify its
# child rv, and no dead SETUP_XFAIL classify block may remain.
# ---------------------------------------------------------------------------

_F1_CATEGORY_A = [
    "test_encrypt_isize_boundary",
    "test_decrypt_isize_boundary",
    "test_sign_isize_boundary",
    "test_verify_isize_data_len",
    "test_digest_isize_boundary",
    "test_update_isize_data_len",
    "test_verify_isize_sig_len",
    "test_gcm_null_iv",
    "test_ecdh_null_public_data",
    "test_oaep_null_source_data",
    "test_hkdf_null_salt",
    "test_hkdf_null_info",
    "test_eddsa_null_context_data",
    "test_ccm_null_nonce",
    "test_concat_base_data_null",
    "test_tls_kdf_null_label",
    "test_sp800_108_null_data_params",
]


def _ffi_length_probe_sources() -> str:
    """Concatenated source of the ffi_length probe module and its _ffi_length_* siblings.

    The god-module split (2026-07-17) moved the dispatch arms (which print the
    ``TARGET_RV:`` protocol lines) into ``_ffi_length_*`` sibling modules; the guard's
    intent is that the child protocol exists in the probe implementation, wherever the
    arm bodies live.
    """
    import importlib
    import pkgutil

    import pkcs11_check.testcases._probes as probes_pkg

    names = sorted(
        mod.name
        for mod in pkgutil.iter_modules(probes_pkg.__path__)
        if mod.name == "ffi_length" or mod.name.startswith("_ffi_length")
    )
    return "\n".join(
        inspect.getsource(importlib.import_module(f"{probes_pkg.__name__}.{name}"))
        for name in names
    )


def test_f1_category_a_methods_parse_and_classify_target_rv() -> None:
    """Every Category-A FFI length probe must parse + classify its child rv.

    Migrated methods delegate the child ``TARGET_RV`` emission to the ``_probes/ffi_length.py``
    module (and its ``_ffi_length_*`` arm modules) via ``run_probe``; not-yet-migrated methods
    still build an inline child script.  Either way the parent must classify the returned rv,
    and the child protocol string must exist (inline in the parent body, or via a ``run_probe``
    call backed by the probe modules).
    """
    src = inspect.getsource(test_ffi_length_boundary)
    probe_src = _ffi_length_probe_sources()
    for name in _F1_CATEGORY_A:
        idx = src.index(f"def {name}(")
        end = src.index("\n    def ", idx + 1) if "\n    def " in src[idx + 1 :] else len(src)
        body = src[idx:end]
        emits_rv = "TARGET_RV:" in body or "run_probe(" in body
        assert emits_rv, f"{name}: child must print TARGET_RV: (inline or via run_probe)"
        classifies = (
            "classify_negative_rv(" in body or "_classify_unhonorable_length_outcome(" in body
        )
        assert classifies, f"{name}: parent must classify the rv"
    assert "TARGET_RV:" in probe_src, (
        "the _probes ffi_length modules must emit the TARGET_RV protocol"
    )


def test_no_dead_setup_xfail_classify_blocks() -> None:
    """No probe may keep an unreachable `if \"SETUP_XFAIL:\" in stdout: classify(...)`."""
    src = inspect.getsource(test_ffi_length_boundary)
    assert 'if "SETUP_XFAIL:" in stdout:' not in src


def test_isize_boundary_lengths_includes_truncation_ids() -> None:
    """_ISIZE_BOUNDARY_LENGTHS must carry the un-honorable isize-boundary param ids.

    The normal lane keeps only unbackable near-SIZE_MAX values. A crash or hang stays a
    finding, but definitive read-vs-write attribution requires the gated ASAN rerun because
    the normal honeypot cannot map the claimed 2^63 bytes. Honorable ~4 GB values remain
    out of this small-buffer lane for the same mapping-fidelity reason.
    """
    ids = [p.id for p in test_ffi_length_boundary._ISIZE_BOUNDARY_LENGTHS]
    assert "isize_max" in ids, "un-honorable isize_max param must be present"
    assert "isize_max_plus_1" in ids, "un-honorable isize_max_plus_1 param must be present"
    assert "trunc_low0" not in ids, "honorable trunc_low0 must not be in small-buffer reject probes"
    assert "trunc_low8" not in ids, "honorable trunc_low8 must not be in small-buffer reject probes"


# ---------------------------------------------------------------------------
# WS2 Phase 2 (Family B): demand-zero output-write truncation oracle for
# C_Encrypt / C_Decrypt.  Each meta-test drives the probe via a monkeypatched
# run_probe, asserts the correct probe name and dispatch key, and confirms that
# setup rejects xfail before the child is spawned.
# ---------------------------------------------------------------------------

_OUTPUT_TRUNCATION_PROBES = [
    pytest.param(
        "TestEncryptOutputLengthTruncation",
        "test_encrypt_oversized_length_rejects_or_honors",
        "aes_ctr_encrypt",
        id="encrypt",
    ),
    pytest.param(
        "TestDecryptOutputLengthTruncation",
        "test_decrypt_oversized_length_rejects_or_honors",
        "aes_ctr_decrypt",
        id="decrypt",
    ),
]


@pytest.mark.parametrize("cls_name,method_name,which", _OUTPUT_TRUNCATION_PROBES)
def test_output_truncation_child_marks_setup_reject_and_carries_oracle(
    monkeypatch: pytest.MonkeyPatch,
    cls_name: str,
    method_name: str,
    which: str,
) -> None:
    """C_Encrypt/C_Decrypt output-truncation probe must invoke run_probe with correct params.

    Returns a SETUP_XFAIL stdout so the probe xfails before the parent parses TARGET_RV.
    The probe name must be ``"output_length"`` and the ``which`` key must select the
    correct cipher direction (aes_ctr_encrypt or aes_ctr_decrypt).
    """
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_output_length_truncation, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_output_length_truncation, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_output_length_truncation, "run_probe", _stub_probe)

    cls = getattr(test_output_length_truncation, cls_name)
    method = getattr(cls(), method_name)
    with pytest.raises(pytest.xfail.Exception):
        method(_RawSession(), cfg)

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "output_length"
    assert params.get("which") == which
    assert params.get("module_path") == "/tmp/fake-pkcs11.so"


@pytest.mark.parametrize("cls_name,method_name,which", _OUTPUT_TRUNCATION_PROBES)
def test_output_truncation_probe_xfails_setup_before_child(
    monkeypatch: pytest.MonkeyPatch,
    cls_name: str,
    method_name: str,
    which: str,
) -> None:
    """Output-truncation probes must preflight keygen setup before spawning a child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin())

    def _xfail_setup(*_args: object, **_kwargs: object) -> int:
        pytest.xfail("AES setup unavailable")

    def _child_should_not_run(*_args: object, **_kwargs: object) -> ProbeResult:
        pytest.fail("child spawned before setup preflight")

    monkeypatch.setattr(
        test_output_length_truncation,
        "gen_aes_key_or_xfail",
        _xfail_setup,
        raising=False,
    )
    monkeypatch.setattr(test_output_length_truncation, "run_probe", _child_should_not_run)

    cls = getattr(test_output_length_truncation, cls_name)
    method = getattr(cls(), method_name)
    with pytest.raises(pytest.xfail.Exception, match="AES setup unavailable"):
        method(_RawSession(), cfg)


def test_output_truncation_skips_wrapkey_and_generatekey() -> None:
    """C_WrapKey / C_GenerateKey must NOT get a demand-zero output probe.

    Their written length is governed by the key object, not a caller input length
    the caller can inflate, so the output oracle cannot prove truncation and would
    only false-fail compliant providers.  The module must document this and expose
    no such probe (the only oracle ops are C_Encrypt / C_Decrypt).
    """
    src = inspect.getsource(test_output_length_truncation)
    # No WrapKey/GenerateKey op is driven through the oracle.
    assert "C_WrapKey" not in src or "NOT a Family-B target" in src
    assert "raw.C_WrapKey(" not in src, "C_WrapKey must not be probed by the output oracle"
    assert "raw.C_GenerateKey(" not in src, "C_GenerateKey must not be probed by the output oracle"
    # The rationale for the skip is documented in the module.
    assert "NOT a Family-B target" in src
    assert "does NOT satisfy it" in src
    assert "C_GenerateKey" in src


# ---------------------------------------------------------------------------
# WS4 Phase 1: TestSingleShotOutputGuard regressions
# ---------------------------------------------------------------------------


def test_ffi_length_encrypt_single_shot_guard_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_Encrypt probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestSingleShotOutputGuard().test_encrypt_one_byte_output_preserves_guard(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "encrypt_single_shot_guard"
    guard_src = inspect.getsource(ffi_length_probe._run_encrypt_single_shot_guard)
    assert "C_Encrypt" in guard_src
    assert "GUARD_OVERWRITE" in inspect.getsource(ffi_length_probe._run_encrypt_single_shot_guard)


def test_ffi_length_decrypt_single_shot_guard_child_marks_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_Decrypt probe must classify a setup reject in the probe child."""
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", pin=_Pin(), slot=0)
    calls: list[tuple[str, dict[str, object]]] = []

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        calls.append((probe, dict(params)))
        return ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            stderr="",
        )

    monkeypatch.setattr(test_ffi_length_boundary, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ffi_length_boundary, "destroy_returned_handles", lambda *_a: None)
    monkeypatch.setattr(test_ffi_length_boundary, "run_probe", _stub_probe)

    with pytest.raises(pytest.xfail.Exception):
        test_ffi_length_boundary.TestSingleShotOutputGuard().test_decrypt_one_byte_output_preserves_guard(
            _RawSession(),
            cfg,
        )

    assert len(calls) == 1
    probe_name, params = calls[0]
    assert probe_name == "ffi_length"
    assert params.get("probe") == "decrypt_single_shot_guard"
    guard_src = inspect.getsource(ffi_length_probe._run_decrypt_single_shot_guard)
    assert "C_Decrypt" in guard_src
    assert "GUARD_OVERWRITE" in inspect.getsource(ffi_length_probe._run_decrypt_single_shot_guard)


def test_probe_hang_classifies_as_crash_finding_not_unclassified() -> None:
    """A subprocess hang (module did not return) must classify as a crash-class
    finding, never escape as an unclassified TimeoutExpired leak.

    Regression for the kryoptic CKA_VALUE_LEN=(1<<32)+8 hang found by the
    softhsm2/kryoptic pool validation: the module tried to allocate ~4 GiB and
    hung. Since the probe-script extraction the launch path is ``run_probe``,
    which converts the child TimeoutExpired into rc 124 + the timeout marker (I8);
    ``assert_subprocess_completed`` must then turn that into a recorded finding.
    """
    from pkcs11_check.testcases._probes.runner import run_probe
    from pkcs11_check.testcases._subprocess_preamble import (
        SUBPROCESS_TIMEOUT_MARKER,
        SUBPROCESS_TIMEOUT_RC,
    )
    from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

    # The _echo probe sleeps past the 1s timeout, forcing run_probe's hang path.
    result = run_probe("_echo", {"module_path": "/nonexistent.so", "sleep": 5}, timeout=1)
    assert result.returncode == SUBPROCESS_TIMEOUT_RC
    assert SUBPROCESS_TIMEOUT_MARKER in result.stderr
    # The parent must turn the hang into a recorded (crash-class) finding.
    with pytest.raises(pytest.fail.Exception):
        assert_subprocess_completed(
            result.returncode, result.stdout, result.stderr, context="probe hang regression"
        )


def test_ffi_length_reject_rv_tuples_are_canonical_and_correct() -> None:
    """The ffi_length probes classify setup rejects through the shared reject-RV tuples.

    Replaces the former per-probe ``"AES_KEYGEN_RUNTIME_REJECT_RVS" in getsource(...)`` source-text
    checks (brittle to refactors, blind to a wrong tuple *value*) with a stronger contract: the
    probe module must expose the SAME tuple objects as ``testcases.conftest`` (not a divergent
    local copy), and those tuples must contain the reject codes a not-operational advertised
    capability legitimately returns.
    """
    from pkcs11_check.raw.types_std import (
        CKR_FUNCTION_NOT_SUPPORTED,
        CKR_KEY_SIZE_RANGE,
        CKR_MECHANISM_INVALID,
        CKR_TEMPLATE_INCONSISTENT,
    )
    from pkcs11_check.testcases import conftest

    # getattr: the probe module re-imports these (not an explicit export), so access dynamically.
    assert (
        getattr(ffi_length_probe, "AES_KEYGEN_RUNTIME_REJECT_RVS")
        is conftest.AES_KEYGEN_RUNTIME_REJECT_RVS
    )
    assert (
        getattr(ffi_length_probe, "KEYPAIR_RUNTIME_REJECT_RVS")
        is conftest.KEYPAIR_RUNTIME_REJECT_RVS
    )
    for tup in (conftest.AES_KEYGEN_RUNTIME_REJECT_RVS, conftest.KEYPAIR_RUNTIME_REJECT_RVS):
        assert CKR_FUNCTION_NOT_SUPPORTED in tup
        assert CKR_MECHANISM_INVALID in tup
        assert CKR_KEY_SIZE_RANGE in tup
        assert CKR_TEMPLATE_INCONSISTENT in tup


# ---------------------------------------------------------------------------
# F2 (v0.2.2 correction release): honest-region contract for huge-length
# probes (P11C-0198-010).
#
# New tests only, in clearly named TestF2* classes. F11 appends its own
# section to this file later, so these hunks stay separable: nothing above
# this line is modified for F2 (function-local imports throughout).
# ---------------------------------------------------------------------------


def _f2_extended_notes() -> list[str]:
    """Drain and return EXTENDED compliance-note descriptions (F2-local)."""
    from pkcs11_check import compliance

    try:
        return [
            n.description
            for n in compliance.get_notes()
            if n.level is compliance.ComplianceLevel.EXTENDED
        ]
    finally:
        compliance.clear_notes()


def _f2_reset_notes() -> None:
    from pkcs11_check import compliance

    compliance.clear_notes()


def _f2_recording_demand(
    monkeypatch: pytest.MonkeyPatch, module: object, *, fail: bool = False
) -> list[int]:
    """Replace ``module.demand_zero_region`` with a recorder (F2-local).

    Returns the list of requested minima. The fake region reports
    ``mapped_length == minimum`` over a small real buffer (no huge backing).
    With ``fail=True`` every demand raises ``HoneypotUnavailable``.
    """
    import ctypes

    from pkcs11_check.testcases._probes import honeypot

    calls: list[int] = []
    keepalive: list[object] = []

    def _fake(minimum_length: int = 0) -> honeypot.ZeroRegion:
        calls.append(minimum_length)
        if fail:
            raise honeypot.HoneypotUnavailable("f2 fake: no mapping")
        buf = (ctypes.c_ubyte * 64)()
        keepalive.append(buf)
        return honeypot.ZeroRegion(
            ptr=ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)),
            mapped_length=minimum_length,
            honest=1,
        )

    monkeypatch.setattr(module, "demand_zero_region", _fake)
    return calls


class TestF2HostileCallerObservation:
    """The hostile observer records EXTENDED robustness notes and never fails."""

    def test_f2_ffi_hostile_crash_is_observation_not_finding(self) -> None:
        _f2_reset_notes()
        test_ffi_length_boundary._observe_hostile_caller_robustness(
            -11,
            "HOSTILE_CALLER:C_Encrypt(ulDataLen=0x7fffffffffffffff) unbacked\n",
            "",
            label_op="C_Encrypt(ulDataLen=0x7fffffffffffffff)",
            test_id="TestF2.test",
        )
        (note,) = _f2_extended_notes()
        assert "hostile-caller" in note
        assert "non-normative" in note
        assert "not a conformance" in note

    def test_f2_ffi_hostile_windows_crash_is_observation(self) -> None:
        _f2_reset_notes()
        test_ffi_length_boundary._observe_hostile_caller_robustness(
            0xC0000005,
            "HOSTILE_CALLER:C_Sign unbacked\n",
            "",
            label_op="C_Sign(ulDataLen=0x8000000000000000)",
            test_id="TestF2.test",
        )
        (note,) = _f2_extended_notes()
        assert "hostile-caller" in note

    def test_f2_ffi_hostile_timeout_is_observation_not_hang_finding(self) -> None:
        _f2_reset_notes()
        test_ffi_length_boundary._observe_hostile_caller_robustness(
            124,
            "HOSTILE_CALLER:C_Digest unbacked\n",
            f"partial\n{SUBPROCESS_TIMEOUT_MARKER}:30s\n",
            label_op="C_Digest(ulDataLen=0x7fffffffffffffff)",
            test_id="TestF2.test",
        )
        (note,) = _f2_extended_notes()
        assert "hostile-caller" in note
        assert "timed out" in note

    def test_f2_ffi_hostile_clean_reject_is_observation(self) -> None:
        _f2_reset_notes()
        test_ffi_length_boundary._observe_hostile_caller_robustness(
            0,
            "HOSTILE_CALLER:C_Encrypt unbacked\nTARGET_RV:0x00000007\n",
            "",
            label_op="C_Encrypt(ulDataLen=0x7fffffffffffffff)",
            test_id="TestF2.test",
        )
        (note,) = _f2_extended_notes()
        assert "hostile-caller" in note
        assert "CKR_ARGUMENTS_BAD" in note

    def test_f2_ffi_hostile_ckr_ok_is_observation_not_accepted_invalid(self) -> None:
        _f2_reset_notes()
        test_ffi_length_boundary._observe_hostile_caller_robustness(
            0,
            "HOSTILE_CALLER:C_Encrypt unbacked\nTARGET_RV:0x00000000\n",
            "",
            label_op="C_Encrypt(ulDataLen=0x7fffffffffffffff)",
            test_id="TestF2.test",
        )
        (note,) = _f2_extended_notes()
        assert "hostile-caller" in note
        assert "CKR_OK" in note

    def test_f2_ffi_hostile_missing_rv_is_inconclusive_observation(self) -> None:
        _f2_reset_notes()
        test_ffi_length_boundary._observe_hostile_caller_robustness(
            0,
            "HOSTILE_CALLER:C_Encrypt unbacked\n",
            "",
            label_op="C_Encrypt(ulDataLen=0x7fffffffffffffff)",
            test_id="TestF2.test",
        )
        (note,) = _f2_extended_notes()
        assert "hostile-caller" in note

    def test_f2_ffi_hostile_traceback_exit_stays_loud(self) -> None:
        _f2_reset_notes()
        with pytest.raises(AssertionError, match="hostile-path probe bug"):
            test_ffi_length_boundary._observe_hostile_caller_robustness(
                1,
                "HOSTILE_CALLER:C_Encrypt unbacked\n",
                "Traceback (most recent call last):\n  File ...\nValueError: f2 probe bug\n",
                label_op="C_Encrypt(ulDataLen=0x7fffffffffffffff)",
                test_id="TestF2.test",
            )
        assert _f2_extended_notes() == []

    def test_f2_ffi_hostile_abrupt_exit_is_observation(self) -> None:
        _f2_reset_notes()
        test_ffi_length_boundary._observe_hostile_caller_robustness(
            5,
            "HOSTILE_CALLER:C_Encrypt unbacked\n",
            "module stderr without traceback\n",
            label_op="C_Encrypt(ulDataLen=0x7fffffffffffffff)",
            test_id="TestF2.test",
        )
        (note,) = _f2_extended_notes()
        assert "hostile-caller" in note

    def test_f2_ffi_is_hostile_caller_matches_marker_only(self) -> None:
        assert test_ffi_length_boundary._is_hostile_caller("HOSTILE_CALLER:x\nTARGET_RV:0x5\n")
        assert not test_ffi_length_boundary._is_hostile_caller("TARGET_RV:0x5\n")
        assert not test_ffi_length_boundary._is_hostile_caller("SETUP_XFAIL:keygen rejected\n")
        assert not test_ffi_length_boundary._is_hostile_caller("")
        assert test_arithmetic_overflow._is_hostile_caller("HOSTILE_CALLER:x\nrv=5\n")
        assert not test_arithmetic_overflow._is_hostile_caller("rv=5\n")

    def test_f2_arith_hostile_crash_is_observation_not_finding(self) -> None:
        _f2_reset_notes()
        test_arithmetic_overflow._observe_hostile_caller_robustness(
            -11,
            "HOSTILE_CALLER:C_CreateObject(template_count=0xffffffffffffffff) unbacked\n",
            "",
            context="C_CreateObject(template_count=0xffffffffffffffff)",
            test_id="TestF2.test",
        )
        (note,) = _f2_extended_notes()
        assert "hostile-caller" in note
        assert "non-normative" in note
        assert "not a conformance" in note

    def test_f2_arith_hostile_clean_reject_is_observation(self) -> None:
        _f2_reset_notes()
        test_arithmetic_overflow._observe_hostile_caller_robustness(
            0,
            "HOSTILE_CALLER:C_UnwrapKey unbacked\nrv=7\n",
            "",
            context="C_UnwrapKey(template_count=0xffffffffffffffff)",
            test_id="TestF2.test",
        )
        (note,) = _f2_extended_notes()
        assert "hostile-caller" in note
        assert "CKR_ARGUMENTS_BAD" in note

    def test_f2_arith_hostile_ckr_ok_is_observation_not_accepted_invalid(self) -> None:
        _f2_reset_notes()
        test_arithmetic_overflow._observe_hostile_caller_robustness(
            0,
            "HOSTILE_CALLER:C_GenerateKey unbacked\nrv=0\n",
            "",
            context="C_GenerateKey(template_count=0xffffffffffffffff)",
            test_id="TestF2.test",
        )
        (note,) = _f2_extended_notes()
        assert "hostile-caller" in note
        assert "CKR_OK" in note

    def test_f2_arith_hostile_traceback_exit_stays_loud(self) -> None:
        _f2_reset_notes()
        with pytest.raises(AssertionError, match="hostile-path probe bug"):
            test_arithmetic_overflow._observe_hostile_caller_robustness(
                1,
                "HOSTILE_CALLER:C_CreateObject unbacked\n",
                "Traceback (most recent call last):\nValueError: f2 probe bug\n",
                context="C_CreateObject(template_count=0xffffffffffffffff)",
                test_id="TestF2.test",
            )
        assert _f2_extended_notes() == []


class TestF2HonestDemandHelpers:
    """Owned demand helpers back the claimed length or mark hostile (honest=0)."""

    def test_f2_base_helper_demands_exactly_the_claimed_length(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.testcases._probes import _ffi_length_base as base

        calls = _f2_recording_demand(monkeypatch, base)
        region, _keep = base._demand_readable_or_hostile(0x80000000)
        assert calls == [0x80000000]
        assert region.honest == 1
        assert region.mapped_length >= 0x80000000

    def test_f2_base_helper_marks_unmappable_magnitudes_hostile(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.testcases._probes import _ffi_length_base as base

        calls = _f2_recording_demand(monkeypatch, base)
        region, keep = base._demand_readable_or_hostile(0x7FFFFFFFFFFFFFFF)
        assert calls == []
        assert region.honest == 0
        assert region.mapped_length == 0
        assert keep is not None

    def test_f2_base_helper_propagates_honeypot_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pkcs11_check.testcases._probes import _ffi_length_base as base
        from pkcs11_check.testcases._probes import honeypot

        _f2_recording_demand(monkeypatch, base, fail=True)
        with pytest.raises(honeypot.HoneypotUnavailable):
            base._demand_readable_or_hostile(0x80000000)

    def test_f2_arith_template_helper_backs_small_counts_honestly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import ctypes

        from pkcs11_check.raw.types_std import CK_ATTRIBUTE, CK_ULONG, CKA_CLASS, CKO_DATA
        from pkcs11_check.testcases._probes import arithmetic_overflow as arith

        cls_val = CK_ULONG(CKO_DATA)
        first = CK_ATTRIBUTE()
        first.type = CKA_CLASS
        first.pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
        first.ulValueLen = ctypes.sizeof(cls_val)

        saved = arith.demand_zero_region

        def _backed(minimum_length: int = 0):  # type: ignore[no-untyped-def]
            assert minimum_length == 3 * ctypes.sizeof(CK_ATTRIBUTE)
            buf = (ctypes.c_ubyte * minimum_length)()
            from pkcs11_check.testcases._probes import honeypot

            return honeypot.ZeroRegion(
                ptr=ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)),
                mapped_length=minimum_length,
                honest=1,
            )

        monkeypatch.setattr(arith, "demand_zero_region", _backed)
        try:
            tmpl, _keep, hostile = arith._honest_template_or_hostile(3, first)
            assert hostile is False
            assert tmpl[0].type == CKA_CLASS
            assert tmpl[0].ulValueLen == ctypes.sizeof(cls_val)
            # The tail stays demand-zero: no advertised byte is left unmapped.
            assert tmpl[1].type == 0
            assert tmpl[2].type == 0
        finally:
            monkeypatch.setattr(arith, "demand_zero_region", saved)

    def test_f2_arith_template_helper_marks_unmappable_counts_hostile(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import ctypes

        from pkcs11_check.raw.types_std import CK_ATTRIBUTE, CK_ULONG, CKA_CLASS, CKO_DATA
        from pkcs11_check.testcases._probes import arithmetic_overflow as arith

        cls_val = CK_ULONG(CKO_DATA)
        first = CK_ATTRIBUTE()
        first.type = CKA_CLASS
        first.pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
        first.ulValueLen = ctypes.sizeof(cls_val)

        def _must_not_demand(minimum_length: int = 0):  # type: ignore[no-untyped-def]
            raise AssertionError("hostile counts must not demand a mapping")

        monkeypatch.setattr(arith, "demand_zero_region", _must_not_demand)
        tmpl, _keep, hostile = arith._honest_template_or_hostile(0xFFFFFFFFFFFFFFFF, first)
        assert hostile is True
        assert tmpl[0].type == CKA_CLASS


class TestF2ProbeHonestMigration:
    """Migrated probes: honest minima, hostile markers, setup-xfail routing."""

    def test_f2_data_length_probe_demands_honest_minimum(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from pkcs11_check.testcases._probes import arithmetic_overflow as arith

        seen: dict[str, object] = {}

        class _Raw:
            def C_EncryptInit(self, *_a: object) -> int:  # noqa: N802
                return 0

            def C_Encrypt(self, _sh: object, buf: object, n: object, *_a: object) -> int:  # noqa: N802
                seen["buf"] = buf
                seen["n"] = n
                return 0x05

        calls = _f2_recording_demand(monkeypatch, arith)
        monkeypatch.setattr(arith, "gen_aes_key", lambda *_a, **_k: 7)
        monkeypatch.setattr(arith, "destroy_quietly", lambda *_a, **_k: None)
        arith._run_data_length_overflow(
            SimpleNamespace(raw=_Raw(), sh=1),
            {"func": "C_Encrypt", "init_func": "C_EncryptInit", "data_len": 0x80000000},
        )
        out = capsys.readouterr().out
        assert calls == [0x80000000]
        assert seen["n"] == 0x80000000
        assert "HOSTILE_CALLER:" not in out
        assert "rv=5" in out

    def test_f2_data_length_probe_marks_unmappable_hostile(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from pkcs11_check.testcases._probes import arithmetic_overflow as arith

        seen: dict[str, object] = {}

        class _Raw:
            def C_EncryptInit(self, *_a: object) -> int:  # noqa: N802
                return 0

            def C_Encrypt(self, _sh: object, buf: object, n: object, *_a: object) -> int:  # noqa: N802
                seen["buf"] = buf
                seen["n"] = n
                return 0x05

        calls = _f2_recording_demand(monkeypatch, arith)
        monkeypatch.setattr(arith, "gen_aes_key", lambda *_a, **_k: 7)
        monkeypatch.setattr(arith, "destroy_quietly", lambda *_a, **_k: None)
        arith._run_data_length_overflow(
            SimpleNamespace(raw=_Raw(), sh=1),
            {
                "func": "C_Encrypt",
                "init_func": "C_EncryptInit",
                "data_len": 0xFFFFFFFFFFFFFFFF,
            },
        )
        out = capsys.readouterr().out
        assert calls == []
        assert seen["n"] == 0xFFFFFFFFFFFFFFFF
        assert "HOSTILE_CALLER:" in out
        assert "rv=5" in out

    def test_f2_data_length_probe_setup_xfails_when_honest_mapping_fails(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from pkcs11_check.testcases._probes import arithmetic_overflow as arith

        class _Raw:
            def C_EncryptInit(self, *_a: object) -> int:  # noqa: N802
                return 0

            def C_Encrypt(self, *_a: object) -> int:  # noqa: N802
                raise AssertionError("under-backed provider call must not execute")

        _f2_recording_demand(monkeypatch, arith, fail=True)
        monkeypatch.setattr(arith, "gen_aes_key", lambda *_a, **_k: 7)
        monkeypatch.setattr(arith, "destroy_quietly", lambda *_a, **_k: None)
        arith._run_data_length_overflow(
            SimpleNamespace(raw=_Raw(), sh=1),
            {"func": "C_Encrypt", "init_func": "C_EncryptInit", "data_len": 0x80000000},
        )
        out = capsys.readouterr().out
        assert "SETUP_XFAIL:" in out
        assert "HOSTILE_CALLER:" not in out
        assert "rv=" not in out

    def test_f2_gcm_accumulation_passes_full_claimed_minimum(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from pkcs11_check.testcases._probes import arithmetic_overflow as arith

        seen: dict[str, object] = {}

        class _Raw:
            def C_DecryptInit(self, *_a: object) -> int:  # noqa: N802
                return 0x10

        def _record_min(min_size: int = 0):  # type: ignore[no-untyped-def]
            import ctypes

            seen["min_size"] = min_size
            return (ctypes.c_ubyte * 1)()

        monkeypatch.setattr(arith, "demand_zero_buffer", _record_min)
        monkeypatch.setattr(arith, "gen_aes_key", lambda *_a, **_k: 7)
        monkeypatch.setattr(arith, "destroy_quietly", lambda *_a, **_k: None)
        arith._run_gcm_decrypt_update_accumulation(SimpleNamespace(raw=_Raw(), sh=1), {})
        capsys.readouterr()
        assert seen["min_size"] == 0xFFFFFFFF

    def test_f2_template_count_probe_splits_honest_and_hostile(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import ctypes

        from pkcs11_check.testcases._probes import arithmetic_overflow as arith
        from pkcs11_check.testcases._probes import honeypot

        seen: dict[str, object] = {}

        class _Raw:
            def C_FindObjectsInit(self, _sh: object, tmpl: object, n: object) -> int:  # noqa: N802
                seen["n"] = n
                arr = ctypes.cast(tmpl, ctypes.POINTER(arith.CK_ATTRIBUTE))
                seen["first_type"] = arr[0].type
                return 0x12

        def _fake(minimum_length: int = 0):  # type: ignore[no-untyped-def]
            buf = (ctypes.c_ubyte * 64)()
            return honeypot.ZeroRegion(
                ptr=ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)),
                mapped_length=minimum_length,
                honest=1,
            )

        monkeypatch.setattr(arith, "demand_zero_region", _fake)
        # 2**32 attributes need 96 GiB of honest mapping: mappable, stays strict.
        arith._run_template_count_overflow(
            SimpleNamespace(raw=_Raw(), sh=1),
            {"op": "C_FindObjectsInit", "count": 0x100000000},
        )
        out = capsys.readouterr().out
        assert seen["n"] == 0x100000000
        assert "HOSTILE_CALLER:" not in out
        assert "rv=" in out
        # ULONG_MAX attributes are un-mappable: hostile observation only.
        arith._run_template_count_overflow(
            SimpleNamespace(raw=_Raw(), sh=1),
            {"op": "C_FindObjectsInit", "count": 0xFFFFFFFFFFFFFFFF},
        )
        out = capsys.readouterr().out
        assert seen["n"] == 0xFFFFFFFFFFFFFFFF
        assert "HOSTILE_CALLER:" in out
        assert "rv=" in out

    def test_f2_isize_encrypt_probe_marks_isize_hostile(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from pkcs11_check.testcases._probes import _ffi_length_isize as isize

        class _Raw:
            def C_EncryptInit(self, *_a: object) -> int:  # noqa: N802
                return 0

            def C_Encrypt(self, *_a: object) -> int:  # noqa: N802
                return 0x05

        monkeypatch.setattr(isize, "gen_aes_key", lambda *_a, **_k: 7)
        monkeypatch.setattr(isize, "destroy_quietly", lambda *_a, **_k: None)
        isize._run_encrypt_isize(
            SimpleNamespace(raw=_Raw(), sh=1),
            {"probe": "encrypt_isize", "data_len": 0x7FFFFFFFFFFFFFFF},
        )
        out = capsys.readouterr().out
        assert "HOSTILE_CALLER:" in out
        assert "TARGET_RV:0x00000005" in out

    def test_f2_sign_output_probe_marks_isize_capacity_hostile(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from pkcs11_check.testcases._probes import _ffi_length_isize as isize

        class _Raw:
            def C_SignInit(self, *_a: object) -> int:  # noqa: N802
                return 0

            def C_Sign(self, *_a: object) -> int:  # noqa: N802
                return 0x05

        monkeypatch.setattr(isize, "_import_hmac_key_notop", lambda *_a, **_k: 9)
        monkeypatch.setattr(isize, "destroy_quietly", lambda *_a, **_k: None)
        isize._run_sign_isize_output(
            SimpleNamespace(raw=_Raw(), sh=1),
            {"probe": "sign_isize_output", "out_len": 0x8000000000000000},
        )
        out = capsys.readouterr().out
        assert "HOSTILE_CALLER:" in out
        assert "TARGET_RV:0x00000005" in out

    def test_f2_aes_cbc_null_case_runs_without_a_region(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from pkcs11_check.testcases._probes import _ffi_length_length_params as params

        class _Raw:
            def C_DeriveKey(self, *_a: object) -> int:  # noqa: N802
                return 0x10

        def _must_not_demand(*_a: object, **_k: object) -> object:
            raise AssertionError("NULL case must not demand a region")

        monkeypatch.setattr(params, "_demand_readable_or_hostile", _must_not_demand)
        monkeypatch.setattr(params, "import_secret_key", lambda *_a, **_k: 5)
        monkeypatch.setattr(params, "destroy_quietly", lambda *_a, **_k: None)
        params._run_aes_cbc_encrypt_data_malformed(
            SimpleNamespace(raw=_Raw(), sh=1),
            {
                "probe": "aes_cbc_encrypt_data_malformed",
                "case_label": "pData=NULL,length=16",
                "null_data": True,
                "data_len": 16,
            },
        )
        out = capsys.readouterr().out
        assert "HOSTILE_CALLER:" not in out
        assert "TARGET_RV:0x00000010" in out

    def test_f2_aes_cbc_tiny_huge_case_is_hostile(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from pkcs11_check.testcases._probes import _ffi_length_length_params as params

        class _Raw:
            def C_DeriveKey(self, *_a: object) -> int:  # noqa: N802
                return 0x10

        monkeypatch.setattr(params, "import_secret_key", lambda *_a, **_k: 5)
        monkeypatch.setattr(params, "destroy_quietly", lambda *_a, **_k: None)
        params._run_aes_cbc_encrypt_data_malformed(
            SimpleNamespace(raw=_Raw(), sh=1),
            {
                "probe": "aes_cbc_encrypt_data_malformed",
                "case_label": "pData=tiny,length=isize_max_plus_1",
                "null_data": False,
                "data_len": 0x8000000000000000,
            },
        )
        out = capsys.readouterr().out
        assert "HOSTILE_CALLER:" in out
        assert "TARGET_RV:0x00000010" in out


class TestF2SoundCasesStayStrict:
    """NULL, scalar-overflow, and backed-allocation probes keep strict wiring."""

    def test_f2_gcm_null_iv_still_passes_null_with_nonzero_length(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from pkcs11_check.testcases._probes import _ffi_length_null_params as nulls

        seen: dict[str, object] = {}

        class _Raw:
            def C_EncryptInit(self, _sh: object, mech: object, _key: object) -> int:  # noqa: N802
                import ctypes

                from pkcs11_check.raw.types_std import CK_AES_GCM_PARAMS, CK_MECHANISM

                m = ctypes.cast(mech, ctypes.POINTER(CK_MECHANISM)).contents
                p = ctypes.cast(m.pParameter, ctypes.POINTER(CK_AES_GCM_PARAMS)).contents
                seen["pIv"] = p.pIv
                seen["ulIvLen"] = p.ulIvLen
                return 0x10

        monkeypatch.setattr(nulls, "gen_aes_key", lambda *_a, **_k: 7)
        monkeypatch.setattr(nulls, "destroy_quietly", lambda *_a, **_k: None)
        nulls._run_gcm_null_iv(SimpleNamespace(raw=_Raw(), sh=1), {"probe": "gcm_null_iv"})
        out = capsys.readouterr().out
        assert seen["pIv"] is None
        assert seen["ulIvLen"] == 12
        assert "HOSTILE_CALLER:" not in out
        assert "TARGET_RV:0x00000010" in out

    def test_f2_key_value_len_still_uses_a_backed_scalar(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import ctypes

        from pkcs11_check.raw.types_std import CK_ATTRIBUTE, CKA_VALUE_LEN
        from pkcs11_check.testcases._probes import arithmetic_overflow as arith

        seen: dict[str, object] = {}

        class _Raw:
            def C_GenerateKey(  # noqa: N802
                self, _sh: object, _mech: object, tmpl: object, n: object, _out: object
            ) -> int:
                arr = ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE))
                assert n == 3
                for i in range(3):
                    if arr[i].type == CKA_VALUE_LEN:
                        seen["len"] = ctypes.cast(
                            arr[i].pValue, ctypes.POINTER(ctypes.c_ulong)
                        ).contents.value
                return 0x10

        arith._run_key_value_len_overflow(
            SimpleNamespace(raw=_Raw(), sh=1),
            {"which": "key_value_len_overflow", "mech_name": "CKM_AES_KEY_GEN"},
        )
        out = capsys.readouterr().out
        assert seen["len"] == arith._CK_ULONG_MAX
        assert "HOSTILE_CALLER:" not in out
        assert "rv=" in out
