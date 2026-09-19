"""Runtime classification meta-tests for ckr/test_ckr_raw_attrs permission flags (policy).

CKA_ENCRYPT=False / CKA_DECRYPT=False enforcement, exercised in a subprocess.
The outer test parses the subprocess output and applies a policy claim/effect-check:
claimed = the key reads back the permission flag as False; violated = the
corresponding C_*Init still returned CKR_OK -> fail; not claimed -> xfail.
"""

from __future__ import annotations

import ctypes
import sys
from types import SimpleNamespace
from typing import Any, cast

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_ENCRYPT,
    CKR_ARGUMENTS_BAD,
    CKR_PENDING,
)
from pkcs11_check.testcases._probes import ckr_raw_attrs as raw_probe
from pkcs11_check.testcases._probes.session import ProbeContext
from pkcs11_check.testcases.ckr import test_ckr_raw_attrs as tra


def _cfg() -> Any:
    return type("Cfg", (), {"module": "x", "pin": None})()


def _patch_run(monkeypatch: pytest.MonkeyPatch, out: str) -> None:
    def fake_run_probe(probe: str, params: Any, **_kwargs: Any) -> SimpleNamespace:
        assert probe == "ckr_raw_attrs"
        assert params["probe"] in ("encrypt", "sign", "decrypt")
        return SimpleNamespace(returncode=0, stdout=out, stderr="")

    monkeypatch.setattr(tra, "run_probe", fake_run_probe)
    monkeypatch.setattr(tra, "assert_ckr_subprocess_ok", lambda *_a, **_k: None)


_ENC_OMITTED = (
    'ATTRIBUTE_EVENT:{"operation":"C_EncryptInit","event":"omitted",'
    '"attribute":{"name":"CKA_ENCRYPT","id":260}}'
)
_ENC_FALSE = (
    'ATTRIBUTE_EVENT:{"operation":"C_EncryptInit","event":"boolean",'
    '"attribute":{"name":"CKA_ENCRYPT","id":260},"value":false}'
)
_ENC_TRUE = (
    'ATTRIBUTE_EVENT:{"operation":"C_EncryptInit","event":"boolean",'
    '"attribute":{"name":"CKA_ENCRYPT","id":260},"value":true}'
)
_ENC_CLAIMED_REJECTED = f"{_ENC_FALSE}\nCKR:0x00000068\nOK"  # KEY_FUNCTION_NOT_PERMITTED
_ENC_NOT_CLAIMED = f"{_ENC_TRUE}\nCKR:0x00000000\nOK"
_ENC_OK = f"{_ENC_FALSE}\nCKR:0x00000000\nOK"
_SIGN_FALSE = (
    _ENC_FALSE.replace("C_EncryptInit", "C_SignInit")
    .replace("CKA_ENCRYPT", "CKA_SIGN")
    .replace("260", "264")
)
_SIGN_TRUE = (
    _ENC_TRUE.replace("C_EncryptInit", "C_SignInit")
    .replace("CKA_ENCRYPT", "CKA_SIGN")
    .replace("260", "264")
)
_DEC_FALSE = (
    _ENC_FALSE.replace("C_EncryptInit", "C_DecryptInit")
    .replace("CKA_ENCRYPT", "CKA_DECRYPT")
    .replace("260", "261")
)
_DEC_TRUE = (
    _ENC_TRUE.replace("C_EncryptInit", "C_DecryptInit")
    .replace("CKA_ENCRYPT", "CKA_DECRYPT")
    .replace("260", "261")
)


def test_encrypt_claimed_violated_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _ENC_OK)
    with pytest.raises(Failed) as ei:
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())
    assert not isinstance(ei.value, XFailed)


def test_encrypt_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _ENC_NOT_CLAIMED)
    with pytest.raises(pytest.xfail.Exception):
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())


def test_encrypt_claimed_enforced_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _ENC_CLAIMED_REJECTED)
    tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())


def test_decrypt_claimed_violated_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _ENC_OK)
    with pytest.raises(Failed) as ei:
        tra.TestKeyFunctionNotPermitted().test_decrypt_not_permitted(_cfg())
    assert not isinstance(ei.value, XFailed)


def test_decrypt_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, f"{_DEC_TRUE}\nCKR:0x00000000\nOK")
    with pytest.raises(pytest.xfail.Exception):
        tra.TestKeyFunctionNotPermitted().test_decrypt_not_permitted(_cfg())


def test_decrypt_claimed_enforced_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, f"{_DEC_FALSE}\nCKR:0x00000068\nOK")
    tra.TestKeyFunctionNotPermitted().test_decrypt_not_permitted(_cfg())


def test_sign_claimed_violated_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, _ENC_OK)
    with pytest.raises(Failed) as ei:
        tra.TestKeyFunctionNotPermitted().test_sign_not_permitted(_cfg())
    assert not isinstance(ei.value, XFailed)


def test_sign_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, f"{_SIGN_TRUE}\nCKR:0x00000000\nOK")
    with pytest.raises(pytest.xfail.Exception):
        tra.TestKeyFunctionNotPermitted().test_sign_not_permitted(_cfg())


def test_sign_claimed_enforced_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, f"{_SIGN_FALSE}\nCKR:0x00000068\nOK")
    tra.TestKeyFunctionNotPermitted().test_sign_not_permitted(_cfg())


def test_missing_claim_is_structured_omission_and_disables_only_policy_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An absent flag is not a fabricated claim or CKR, and later CKR is retained."""
    out = f"{_ENC_OMITTED}\n"
    out += "CKR:0x00000000\nOK"
    _patch_run(monkeypatch, out)

    with pytest.raises(pytest.xfail.Exception):
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].actual_ckr is None
    assert records[0].detail is not None
    assert records[0].detail["attribute"] == {"name": "CKA_ENCRYPT", "id": 260}
    assert records[0].detail["dependent_operation"] == "C_EncryptInit"
    assert records[0].detail["dependent_actual_ckr"] == "CKR_OK"


def test_present_true_remains_a_claim_deviation_not_an_omission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_run(monkeypatch, f"{_ENC_TRUE}\nCKR:0x00000068\nOK")

    with pytest.raises(pytest.xfail.Exception):
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].actual_ckr is None
    assert records[0].detail is not None
    assert records[0].detail["dependent_operation"] == "C_EncryptInit"
    assert records[0].detail["dependent_actual_ckr"] == "CKR_KEY_FUNCTION_NOT_PERMITTED"


def test_malformed_present_claim_is_hard_metadata_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = (
        'ATTRIBUTE_EVENT:{"operation":"C_EncryptInit","event":"malformed",'
        '"attribute":{"name":"CKA_ENCRYPT","id":260},'
        '"value_type":"bytes","value_repr":"empty"}\n'
        "CKR:0x00000068\nOK"
    )
    _patch_run(monkeypatch, out)

    with pytest.raises(pytest.fail.Exception):
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "metadata"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].actual_ckr is None


def test_event_operation_mismatch_is_harness_error(monkeypatch: pytest.MonkeyPatch) -> None:
    out = (
        'ATTRIBUTE_EVENT:{"operation":"C_SignInit","event":"omitted",'
        '"attribute":{"name":"CKA_ENCRYPT","id":260}}\n'
        "CKR:0x00000068\nOK"
    )
    _patch_run(monkeypatch, out)

    with pytest.raises(pytest.fail.Exception, match="operation"):
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())
    assert C.get_records()[-1].reason == "harness_error"


def test_bool_attribute_id_is_harness_error(monkeypatch: pytest.MonkeyPatch) -> None:
    out = (
        'ATTRIBUTE_EVENT:{"operation":"C_EncryptInit","event":"omitted",'
        '"attribute":{"name":"CKA_ENCRYPT","id":true}}\n'
        "CKR:0x00000068\nOK"
    )
    _patch_run(monkeypatch, out)

    with pytest.raises(pytest.fail.Exception, match="attribute"):
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())
    assert C.get_records()[-1].reason == "harness_error"


def test_malformed_event_requires_bounded_value_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = (
        'ATTRIBUTE_EVENT:{"operation":"C_EncryptInit","event":"malformed",'
        '"attribute":{"name":"CKA_ENCRYPT","id":260},"value_type":"bytes"}\n'
        "CKR:0x00000068\nOK"
    )
    _patch_run(monkeypatch, out)

    with pytest.raises(pytest.fail.Exception, match="value_repr"):
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())


@pytest.mark.parametrize("rv", [int(CKR_ARGUMENTS_BAD), int(CKR_PENDING)])
def test_defined_non_spec_refusal_is_visible_with_actual_ckr(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
) -> None:
    _patch_run(monkeypatch, f"{_ENC_FALSE}\nCKR:0x{rv:08x}\nOK")

    with pytest.raises(pytest.xfail.Exception):
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())
    record = C.get_records()[-1]
    assert record.reason == "nonspec_reject"
    assert record.actual_ckr is not None
    assert record.operation == "C_EncryptInit"


def test_undefined_ckr_is_hard_metadata_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, f"{_ENC_FALSE}\nCKR:0x000001ff\nOK")

    with pytest.raises(pytest.fail.Exception):
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())
    record = C.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.actual_ckr == "0x000001ff"


@pytest.mark.parametrize(
    ("out", "reason"),
    [
        (f"{_ENC_FALSE}\nOK", "probe_incomplete"),
        (f"{_ENC_FALSE}\nCKR:0x00000068\nCKR:0x00000068\nOK", "harness_error"),
        (f"{_ENC_FALSE}\nCKR:0x0000000g\nOK", "harness_error"),
    ],
    ids=["missing", "duplicate", "non-hex"],
)
def test_ckr_protocol_cardinality_and_syntax_reasons(
    monkeypatch: pytest.MonkeyPatch,
    out: str,
    reason: str,
) -> None:
    _patch_run(monkeypatch, out)

    with pytest.raises(pytest.fail.Exception, match="CKR"):
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())
    assert C.get_records()[-1].reason == reason


def test_child_emits_omission_marker_for_absent_permission_flag(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(raw_probe, "read_attributes", lambda *_a, **_k: {})
    ctx = cast(ProbeContext, SimpleNamespace(raw=SimpleNamespace(), sh=1))

    raw_probe._claim(ctx, 1, 2, CKA_ENCRYPT, operation="C_EncryptInit")

    output = capsys.readouterr().out
    assert output.startswith("ATTRIBUTE_EVENT:")
    assert '"operation":"C_EncryptInit"' in output


@pytest.mark.parametrize("value", [False, True])
def test_child_keeps_present_boolean_claims_distinct_from_omission(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    value: bool,
) -> None:
    monkeypatch.setattr(raw_probe, "read_attributes", lambda *_a, **_k: {CKA_ENCRYPT: value})
    ctx = cast(ProbeContext, SimpleNamespace(raw=SimpleNamespace(), sh=1))

    raw_probe._claim(ctx, 1, 2, CKA_ENCRYPT, operation="C_EncryptInit")

    output = capsys.readouterr().out
    assert output.startswith("ATTRIBUTE_EVENT:")
    assert '"event":"boolean"' in output
    assert f'"value":{str(value).lower()}' in output


@pytest.mark.parametrize("value", [0, b"", None], ids=["zero", "empty-bytes", "none"])
def test_child_emits_structured_marker_for_present_malformed_value(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    value: Any,
) -> None:
    monkeypatch.setattr(raw_probe, "read_attributes", lambda *_a, **_k: {CKA_ENCRYPT: value})
    ctx = cast(ProbeContext, SimpleNamespace(raw=SimpleNamespace(), sh=1))

    raw_probe._claim(ctx, 1, 2, CKA_ENCRYPT, operation="C_EncryptInit")

    output = capsys.readouterr().out
    assert output.startswith("ATTRIBUTE_EVENT:")
    assert '"event":"malformed"' in output
    assert '"attribute":{"name":"CKA_ENCRYPT","id":260}' in output


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_omission_is_retained_before_real_crash_disposition() -> None:
    out = f"{_ENC_OMITTED}\nCKR:0x00000000\nOK\n"
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        tra._check_permission_probe(
            -11,
            out,
            "segmentation fault",
            context="C_EncryptInit with CKA_ENCRYPT=False",
            operation="C_EncryptInit",
            attribute=CKA_ENCRYPT,
        )
    assert [record.reason for record in C.get_records()] == ["honest_deviation", "crash"]


def test_omission_is_retained_before_real_timeout_disposition() -> None:
    from pkcs11_check.testcases._subprocess_preamble import SUBPROCESS_TIMEOUT_MARKER

    out = f"{_ENC_OMITTED}\nCKR:0x00000000\nOK\n"
    with pytest.raises(pytest.fail.Exception, match="timed out"):
        tra._check_permission_probe(
            124,
            out,
            f"{SUBPROCESS_TIMEOUT_MARKER}:15s",
            context="C_EncryptInit with CKA_ENCRYPT=False",
            operation="C_EncryptInit",
            attribute=CKA_ENCRYPT,
        )
    assert [record.reason for record in C.get_records()] == ["honest_deviation", "crash"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_event_without_ckr_before_real_crash_is_not_synthetic_harness_error() -> None:
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        tra._check_permission_probe(
            -11,
            f"{_ENC_OMITTED}\n",
            "segmentation fault",
            context="C_EncryptInit with CKA_ENCRYPT=False",
            operation="C_EncryptInit",
            attribute=CKA_ENCRYPT,
        )
    assert [record.reason for record in C.get_records()] == ["honest_deviation", "crash"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_crash_before_any_marker_is_only_a_crash() -> None:
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        tra._check_permission_probe(
            -11,
            "",
            "segmentation fault",
            context="C_EncryptInit with CKA_ENCRYPT=False",
            operation="C_EncryptInit",
            attribute=CKA_ENCRYPT,
        )
    assert [record.reason for record in C.get_records()] == ["crash"]


def test_setup_refusal_is_handled_by_shared_helper_without_synthetic_protocol_errors() -> None:
    with pytest.raises(pytest.xfail.Exception, match="C_GenerateKey"):
        tra._check_permission_probe(
            0,
            "SETUP_XFAIL:C_GenerateKey for CKA_ENCRYPT=False failed: CKR_FUNCTION_NOT_SUPPORTED\n",
            "",
            context="C_EncryptInit with CKA_ENCRYPT=False",
            operation="C_EncryptInit",
            attribute=CKA_ENCRYPT,
        )
    assert [record.reason for record in C.get_records()] == ["not_operational"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_setup_only_then_crash_preserves_setup_and_terminal_crash() -> None:
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        tra._check_permission_probe(
            -11,
            "SETUP_XFAIL:C_GenerateKey for CKA_ENCRYPT=False failed: CKR_FUNCTION_NOT_SUPPORTED\n",
            "segmentation fault",
            context="C_EncryptInit with CKA_ENCRYPT=False",
            operation="C_EncryptInit",
            attribute=CKA_ENCRYPT,
        )
    assert [record.reason for record in C.get_records()] == ["not_operational", "crash"]


def test_native_width_vendor_ckr_remains_a_visible_nonspec_deviation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vendor_rv = 0x80000000 if ctypes.sizeof(CK_ULONG) == 4 else 0x8000000000000001
    _patch_run(monkeypatch, f"{_ENC_FALSE}\nCKR:0x{vendor_rv:x}\nOK")

    with pytest.raises(pytest.xfail.Exception):
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())
    record = C.get_records()[-1]
    assert record.reason == "nonspec_reject"
    assert record.actual_ckr is not None


def test_ckr_above_native_ulong_range_is_harness_error(monkeypatch: pytest.MonkeyPatch) -> None:
    native_max = (1 << (ctypes.sizeof(CK_ULONG) * 8)) - 1
    _patch_run(monkeypatch, f"{_ENC_FALSE}\nCKR:0x{native_max + 1:x}\nOK")

    with pytest.raises(pytest.fail.Exception, match="CKR"):
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())
    assert C.get_records()[-1].reason == "harness_error"


@pytest.mark.parametrize("rv", [0x000001FF, int(CKR_ARGUMENTS_BAD)])
def test_valid_ckr_is_preserved_when_event_json_is_invalid(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
) -> None:
    _patch_run(monkeypatch, f"ATTRIBUTE_EVENT:{{not-json}}\nCKR:0x{rv:08x}\nOK")

    with pytest.raises(pytest.fail.Exception):
        tra.TestKeyFunctionNotPermitted().test_encrypt_not_permitted(_cfg())
    assert [record.reason for record in C.get_records()] == [
        "harness_error",
        "wrong_result" if rv == 0x000001FF else "nonspec_reject",
    ]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_boolean_true_readback_survives_signal_before_ckr() -> None:
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        tra._check_permission_probe(
            -11,
            f"{_ENC_TRUE}\n",
            "segmentation fault",
            context="C_EncryptInit with CKA_ENCRYPT=False",
            operation="C_EncryptInit",
            attribute=CKA_ENCRYPT,
        )
    assert [record.reason for record in C.get_records()] == ["honest_deviation", "crash"]


def test_setup_mixed_with_claim_and_ckr_preserves_hard_policy_finding() -> None:
    out = (
        "SETUP_XFAIL:C_GenerateKey for CKA_ENCRYPT=False failed: CKR_FUNCTION_NOT_SUPPORTED\n"
        f"{_ENC_FALSE}\nCKR:0x00000000\nOK\n"
    )
    with pytest.raises(pytest.fail.Exception, match="accepted the operation"):
        tra._check_permission_probe(
            0,
            out,
            "",
            context="C_EncryptInit with CKA_ENCRYPT=False",
            operation="C_EncryptInit",
            attribute=CKA_ENCRYPT,
        )
    assert [record.reason for record in C.get_records()] == [
        "self_contradiction",
        "not_operational",
    ]


def test_setup_mixed_with_malformed_event_preserves_both_findings() -> None:
    out = (
        "SETUP_XFAIL:C_GenerateKey for CKA_ENCRYPT=False failed: CKR_FUNCTION_NOT_SUPPORTED\n"
        'ATTRIBUTE_EVENT:{"operation":"C_EncryptInit","event":"malformed",'
        '"attribute":{"name":"CKA_ENCRYPT","id":260},'
        '"value_type":"bytes","value_repr":"empty"}\n'
    )
    with pytest.raises(pytest.fail.Exception, match="malformed"):
        tra._check_permission_probe(
            0,
            out,
            "",
            context="C_EncryptInit with CKA_ENCRYPT=False",
            operation="C_EncryptInit",
            attribute=CKA_ENCRYPT,
        )
    assert {record.reason for record in C.get_records()} == {"wrong_result", "not_operational"}


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")
def test_setup_mixed_with_omission_and_crash_preserves_all_observations() -> None:
    out = (
        "SETUP_XFAIL:C_GenerateKey for CKA_ENCRYPT=False failed: CKR_FUNCTION_NOT_SUPPORTED\n"
        f"{_ENC_OMITTED}\n"
    )
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        tra._check_permission_probe(
            -11,
            out,
            "segmentation fault",
            context="C_EncryptInit with CKA_ENCRYPT=False",
            operation="C_EncryptInit",
            attribute=CKA_ENCRYPT,
        )
    assert [record.reason for record in C.get_records()] == [
        "honest_deviation",
        "not_operational",
        "crash",
    ]
