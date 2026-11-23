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
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_ULONG,
    CKA_CLASS,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKK_GENERIC_SECRET,
    CKM_AES_KEY_GEN,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_SHA256_HMAC,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_MECHANISM_INVALID,
    CKR_OK,
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


class _SignCaptureRaw:
    """Capture the sign probe's key creation + SignInit calls (fw#96)."""

    def __init__(
        self,
        *,
        sign_rv: int,
        sign_rvs: list[int] | None = None,
        refuse_keygen: set[int] | None = None,
        refuse_create: bool = False,
        keygen_rv: int | None = None,
        create_rv: int | None = None,
        keygen_refuse_predicate: Any = None,
        handle_sequence: list[int] | None = None,
    ) -> None:
        self._sign_rv = sign_rv
        self._sign_rvs = list(sign_rvs) if sign_rvs else []
        self._refuse_keygen = refuse_keygen or set()
        self._refuse_create = refuse_create
        self._keygen_rv = keygen_rv if keygen_rv is not None else int(CKR_MECHANISM_INVALID)
        self._create_rv = create_rv if create_rv is not None else int(CKR_FUNCTION_NOT_SUPPORTED)
        self._keygen_refuse_predicate = keygen_refuse_predicate
        self._handle_sequence = list(handle_sequence) if handle_sequence else []
        self._next_handle = 4242
        self.keygen_calls: list[tuple[int, dict[int, bytes]]] = []
        self.create_calls: list[dict[int, bytes]] = []
        self.sign_mech: int | None = None
        self.sign_calls: list[int] = []

    def _issue_handle(self, out: Any) -> None:
        if self._handle_sequence:
            handle = self._handle_sequence.pop(0)
        else:
            handle = self._next_handle
            self._next_handle += 1
        ctypes.cast(out, ctypes.POINTER(ctypes.c_ulong)).contents.value = handle

    @staticmethod
    def _decode_attrs(tmpl_ptr: Any, count: int) -> dict[int, bytes]:
        array = ctypes.cast(tmpl_ptr, ctypes.POINTER(CK_ATTRIBUTE * count)).contents
        out: dict[int, bytes] = {}
        for i in range(count):
            size = int(array[i].ulValueLen)
            addr = array[i].pValue
            out[int(array[i].type)] = bytes(ctypes.string_at(addr, size)) if addr and size else b""
        return out

    def C_GenerateKey(  # noqa: N802
        self, _sh: int, mech_ptr: Any, tmpl_ptr: Any, count: int, out: Any
    ) -> int:
        mech = int(ctypes.cast(mech_ptr, ctypes.POINTER(CK_MECHANISM)).contents.mechanism)
        attrs = self._decode_attrs(tmpl_ptr, int(count))
        self.keygen_calls.append((mech, attrs))
        if self._keygen_refuse_predicate is not None:
            veto = self._keygen_refuse_predicate(mech, attrs)
            if veto is not None:
                return int(veto)
        if mech in self._refuse_keygen:
            return self._keygen_rv
        self._issue_handle(out)
        return int(CKR_OK)

    def C_CreateObject(self, _sh: int, tmpl_ptr: Any, count: int, out: Any) -> int:  # noqa: N802
        self.create_calls.append(self._decode_attrs(tmpl_ptr, int(count)))
        if self._refuse_create:
            return self._create_rv
        self._issue_handle(out)
        return int(CKR_OK)

    def C_SignInit(self, _sh: int, mech_ptr: Any, _key: int) -> int:  # noqa: N802
        self.sign_mech = int(ctypes.cast(mech_ptr, ctypes.POINTER(CK_MECHANISM)).contents.mechanism)
        self.sign_calls.append(int(_key))
        if self._sign_rvs:
            return self._sign_rvs.pop(0)
        return self._sign_rv


def _ulong_native(value: int) -> bytes:
    return value.to_bytes(ctypes.sizeof(CK_ULONG), sys.byteorder)


def _readback_by_handle(disabled_handle: int = 4242) -> Any:
    """Read back CKA_SIGN=False only for the disabled key (R5-1 twin checks)."""

    def _read(_raw: Any, _sh: int, handle: int, _attrs: Any) -> dict[int, bool]:
        return {CKA_SIGN: int(handle) != disabled_handle}

    return _read


def test_sign_probe_control_success_credits_denial(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R4-3: an enabled twin on the same route must init before denial credits (fw#96)."""
    monkeypatch.setattr(raw_probe, "read_attributes", _readback_by_handle())
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        sign_rvs=[int(CKR_KEY_FUNCTION_NOT_PERMITTED), int(CKR_OK)],
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    assert [mech for mech, _ in raw.keygen_calls] == [
        int(CKM_GENERIC_SECRET_KEY_GEN),
        int(CKM_GENERIC_SECRET_KEY_GEN),
    ]
    assert raw.create_calls == []
    attrs = raw.keygen_calls[0][1]
    assert attrs.get(int(CKA_SIGN)) == b"\x00"
    assert attrs.get(int(CKA_VERIFY)) == b"\x01"
    assert int(CKA_ENCRYPT) not in attrs
    assert attrs.get(int(CKA_VALUE_LEN)) == _ulong_native(32)
    control_attrs = raw.keygen_calls[1][1]
    assert control_attrs.get(int(CKA_SIGN)) == b"\x01"
    assert raw.sign_mech == int(CKM_SHA256_HMAC)
    assert len(raw.sign_calls) == 2
    captured = capsys.readouterr()
    out = captured.out
    assert f"CKR:0x{int(CKR_KEY_FUNCTION_NOT_PERMITTED):08x}" in out
    assert out.rstrip().endswith("OK")
    assert "SETUP_XFAIL" not in out
    assert "SETUP_REFUSED" not in out
    assert "positive control" in captured.err


def test_sign_probe_falls_back_to_create_object(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without generic keygen, the sign probe creates the HMAC key (fw#96)."""
    monkeypatch.setattr(raw_probe, "read_attributes", _readback_by_handle())
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        sign_rvs=[int(CKR_KEY_FUNCTION_NOT_PERMITTED), int(CKR_OK)],
        refuse_keygen={int(CKM_GENERIC_SECRET_KEY_GEN)},
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    assert [mech for mech, _ in raw.keygen_calls] == [int(CKM_GENERIC_SECRET_KEY_GEN)]
    assert len(raw.create_calls) == 2
    created = raw.create_calls[0]
    assert int.from_bytes(created[int(CKA_CLASS)], sys.byteorder) == int(CKO_SECRET_KEY)
    assert int.from_bytes(created[int(CKA_KEY_TYPE)], sys.byteorder) == int(CKK_GENERIC_SECRET)
    assert len(created[int(CKA_VALUE)]) == 32
    assert created.get(int(CKA_SIGN)) == b"\x00"
    assert created.get(int(CKA_VERIFY)) == b"\x01"
    assert int(CKA_ENCRYPT) not in created
    assert raw.create_calls[1].get(int(CKA_SIGN)) == b"\x01"
    assert raw.sign_mech == int(CKM_SHA256_HMAC)
    out = capsys.readouterr().out
    assert out.rstrip().endswith("OK")
    assert "SETUP_XFAIL" not in out


def test_sign_probe_falls_back_to_aes_route(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without generic-secret support, the sign probe keeps today's AES route (fw#96)."""
    monkeypatch.setattr(raw_probe, "read_attributes", _readback_by_handle())
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        sign_rvs=[int(CKR_KEY_FUNCTION_NOT_PERMITTED), int(CKR_OK)],
        refuse_keygen={int(CKM_GENERIC_SECRET_KEY_GEN)},
        refuse_create=True,
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    assert [mech for mech, _ in raw.keygen_calls] == [
        int(CKM_GENERIC_SECRET_KEY_GEN),
        int(CKM_AES_KEY_GEN),
        int(CKM_AES_KEY_GEN),
    ]
    aes_attrs = raw.keygen_calls[1][1]
    assert aes_attrs.get(int(CKA_SIGN)) == b"\x00"
    assert aes_attrs.get(int(CKA_ENCRYPT)) == b"\x01"
    assert raw.keygen_calls[2][1].get(int(CKA_SIGN)) == b"\x01"
    assert raw.sign_mech == int(CKM_SHA256_HMAC)
    out = capsys.readouterr().out
    assert out.rstrip().endswith("OK")
    assert "SETUP_XFAIL" not in out


def test_sign_probe_setup_failure_reports_refused_marker(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R4-4: all key creation refused ends in a numeric marker, no CKR (fw#96)."""
    monkeypatch.setattr(raw_probe, "read_attributes", lambda *_a, **_k: {CKA_SIGN: False})
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        refuse_keygen={int(CKM_GENERIC_SECRET_KEY_GEN), int(CKM_AES_KEY_GEN)},
        refuse_create=True,
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert f"SETUP_REFUSED:C_GenerateKey:0x{int(CKR_MECHANISM_INVALID):08x}" in out
    assert "CKR:" not in out
    assert "OK" not in out.splitlines()


def test_sign_probe_control_init_refused_stays_untested(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R4-3: an enabled twin that also refuses uncredits the denial (no CKR/OK)."""
    monkeypatch.setattr(raw_probe, "read_attributes", _readback_by_handle())
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        sign_rvs=[
            int(CKR_KEY_FUNCTION_NOT_PERMITTED),
            int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        ],
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert f"SETUP_REFUSED:C_SignInit:0x{int(CKR_KEY_FUNCTION_NOT_PERMITTED):08x}" in out
    assert "CKR:" not in out
    assert "OK" not in out.splitlines()
    assert len(raw.keygen_calls) == 2
    assert len(raw.sign_calls) == 2


def test_sign_probe_control_create_refused_stays_untested(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R4-3: a refused control creation names its own op+RV (no CKR/OK)."""
    monkeypatch.setattr(raw_probe, "read_attributes", lambda *_a, **_k: {CKA_SIGN: False})

    def _refuse_signed(mech: int, attrs: dict[int, bytes]) -> int | None:
        if attrs.get(int(CKA_SIGN)) == b"\x01":
            return int(CKR_MECHANISM_INVALID)
        return None

    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        keygen_refuse_predicate=_refuse_signed,
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert f"SETUP_REFUSED:C_GenerateKey:0x{int(CKR_MECHANISM_INVALID):08x}" in out
    assert "CKR:" not in out
    assert "OK" not in out.splitlines()
    assert len(raw.sign_calls) == 1


def test_sign_probe_control_init_undefined_rv_is_refused_marker(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R4-3: an undefined control RV keeps its exact value in the marker."""
    monkeypatch.setattr(raw_probe, "read_attributes", _readback_by_handle())
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        sign_rvs=[int(CKR_KEY_FUNCTION_NOT_PERMITTED), 0x00FFFFFF],
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert "SETUP_REFUSED:C_SignInit:0x00ffffff" in out
    assert "CKR:" not in out
    assert "OK" not in out.splitlines()


def test_sign_probe_control_aliased_handle_breaks(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R5-1: a twin aliasing the disabled handle is a hard break, never credit."""
    monkeypatch.setattr(raw_probe, "read_attributes", _readback_by_handle())
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        sign_rvs=[int(CKR_KEY_FUNCTION_NOT_PERMITTED), int(CKR_OK)],
        handle_sequence=[4242, 4242],
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert "BREAK:" in out
    assert "aliases" in out
    assert "CKR:" not in out
    assert "OK" not in out.splitlines()
    assert len(raw.sign_calls) == 1


def test_sign_probe_control_twin_unclaimed_breaks(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R5-1: a twin reading back SIGN=False voids the control (hard break)."""
    monkeypatch.setattr(raw_probe, "read_attributes", lambda *_a, **_k: {CKA_SIGN: False})
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        sign_rvs=[int(CKR_KEY_FUNCTION_NOT_PERMITTED), int(CKR_OK)],
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert "BREAK:" in out
    assert "CKA_SIGN=True" in out
    assert "CKR:" not in out
    assert "OK" not in out.splitlines()
    assert len(raw.sign_calls) == 1


def test_sign_probe_control_twin_omitted_deviates(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R6-1: a twin omitting the flag deviates (oracle disabled), uncredited."""

    def _omit_twin(_raw: Any, _sh: int, handle: int, _attrs: Any) -> dict[int, Any]:
        if int(handle) != 4242:
            return {}
        return {CKA_SIGN: False}

    monkeypatch.setattr(raw_probe, "read_attributes", _omit_twin)
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        sign_rvs=[int(CKR_KEY_FUNCTION_NOT_PERMITTED), int(CKR_OK)],
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert "DEVIATION_XFAIL:" in out
    assert "oracle disabled" in out
    assert "BREAK:" not in out
    assert "CKR:" not in out
    assert "OK" not in out.splitlines()
    assert len(raw.sign_calls) == 1


def test_sign_probe_control_twin_malformed_breaks(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R6-1: a twin with a malformed flag readback stays loud (break)."""

    def _malform_twin(_raw: Any, _sh: int, handle: int, _attrs: Any) -> dict[int, Any]:
        if int(handle) != 4242:
            return {CKA_SIGN: b""}
        return {CKA_SIGN: False}

    monkeypatch.setattr(raw_probe, "read_attributes", _malform_twin)
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        sign_rvs=[int(CKR_KEY_FUNCTION_NOT_PERMITTED), int(CKR_OK)],
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert "BREAK:" in out
    assert "CKR:" not in out
    assert "OK" not in out.splitlines()
    assert len(raw.sign_calls) == 1


def test_sign_probe_control_twin_refusal_with_data_breaks(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R7-1: twin refusal-with-data is a hard break (RV + length kept)."""
    from pkcs11_check.raw.recipes import AttrReadResult, AttrRefusal

    def _leak_twin(_raw: Any, _sh: int, handle: int, _attrs: Any) -> dict[int, Any]:
        if int(handle) == 4242:
            return {CKA_SIGN: False}
        result = AttrReadResult()
        result.refusals[int(CKA_SIGN)] = AttrRefusal(
            ckr=int(CKR_ATTRIBUTE_TYPE_INVALID), leaked_len=1
        )
        return result

    monkeypatch.setattr(raw_probe, "read_attributes", _leak_twin)
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        sign_rvs=[int(CKR_KEY_FUNCTION_NOT_PERMITTED), int(CKR_OK)],
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert "BREAK:" in out
    assert "CKR_ATTRIBUTE_TYPE_INVALID" in out
    assert "1 bytes" in out
    assert "CKR:" not in out
    assert "OK" not in out.splitlines()
    assert len(raw.sign_calls) == 1


def test_sign_probe_control_twin_clean_refusal_names_rv(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R7-1: a clean twin refusal deviates, naming the observed RV."""
    from pkcs11_check.raw.recipes import AttrReadResult, AttrRefusal

    def _refuse_twin(_raw: Any, _sh: int, handle: int, _attrs: Any) -> dict[int, Any]:
        if int(handle) == 4242:
            return {CKA_SIGN: False}
        result = AttrReadResult()
        result.refusals[int(CKA_SIGN)] = AttrRefusal(ckr=int(CKR_ATTRIBUTE_SENSITIVE))
        return result

    monkeypatch.setattr(raw_probe, "read_attributes", _refuse_twin)
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        sign_rvs=[int(CKR_KEY_FUNCTION_NOT_PERMITTED), int(CKR_OK)],
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert "DEVIATION_XFAIL:" in out
    assert "CKR_ATTRIBUTE_SENSITIVE" in out
    assert "BREAK:" not in out
    assert "CKR:" not in out
    assert "OK" not in out.splitlines()
    assert len(raw.sign_calls) == 1


def test_sign_probe_control_twin_malformed_refusal_deviates(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R8-1: a malformed twin refusal deviates by name (uncredited, no leak)."""
    from pkcs11_check.raw.recipes import AttrReadResult, AttrRefusal

    def _malform_twin(_raw: Any, _sh: int, handle: int, _attrs: Any) -> dict[int, Any]:
        if int(handle) == 4242:
            return {CKA_SIGN: False}
        result = AttrReadResult()
        result.refusals[int(CKA_SIGN)] = AttrRefusal(
            ckr=int(CKR_ATTRIBUTE_TYPE_INVALID), malformed=True
        )
        return result

    monkeypatch.setattr(raw_probe, "read_attributes", _malform_twin)
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        sign_rvs=[int(CKR_KEY_FUNCTION_NOT_PERMITTED), int(CKR_OK)],
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert "DEVIATION_XFAIL:" in out
    assert "malformed refusal" in out
    assert "BREAK:" not in out
    assert "CKR:" not in out
    assert "OK" not in out.splitlines()
    assert len(raw.sign_calls) == 1


def test_deviation_transcript_xfails_without_missing_ckr_noise() -> None:
    """R6-1: DEVIATION is terminal (xfail); no missing-CKR harness record."""
    out = (
        f"{_SIGN_FALSE}\nDEVIATION_XFAIL:control twin omits CKA_SIGN; enforcement oracle disabled\n"
    )
    with pytest.raises(pytest.xfail.Exception, match="oracle disabled"):
        tra._check_permission_probe(
            0,
            out,
            "",
            context="C_SignInit with CKA_SIGN=False",
            operation="C_SignInit",
            attribute=CKA_SIGN,
        )
    assert any(record.reason == "honest_deviation" for record in C.get_records())
    assert not any("CKR marker is missing" in (record.summary or "") for record in C.get_records())


def test_break_transcript_fails_without_missing_ckr_noise() -> None:
    """R5-1: BREAK is terminal (fail); no missing-CKR harness record beside it."""
    out = f"{_SIGN_FALSE}\nBREAK:control twin aliases the disabled key (handle 4242)\n"
    with pytest.raises(pytest.fail.Exception, match="aliases"):
        tra._check_permission_probe(
            0,
            out,
            "",
            context="C_SignInit with CKA_SIGN=False",
            operation="C_SignInit",
            attribute=CKA_SIGN,
        )
    assert any(record.reason == "self_contradiction" for record in C.get_records())
    assert not any("CKR marker is missing" in (record.summary or "") for record in C.get_records())


def test_sign_probe_disabled_accepted_runs_no_control(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R4-3: the hard CKR_OK failure path runs no control (single key+init)."""
    monkeypatch.setattr(raw_probe, "read_attributes", lambda *_a, **_k: {CKA_SIGN: False})
    raw = _SignCaptureRaw(sign_rv=int(CKR_OK))
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert "CKR:0x00000000" in out
    assert out.rstrip().endswith("OK")
    assert len(raw.keygen_calls) == 1
    assert len(raw.sign_calls) == 1


def test_sign_probe_other_refusal_runs_no_control(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R4-3: non-63 refusals pass through; the control gates on NOT_PERMITTED."""
    monkeypatch.setattr(raw_probe, "read_attributes", lambda *_a, **_k: {CKA_SIGN: False})
    raw = _SignCaptureRaw(sign_rv=int(CKR_MECHANISM_INVALID))
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert f"CKR:0x{int(CKR_MECHANISM_INVALID):08x}" in out
    assert out.rstrip().endswith("OK")
    assert len(raw.keygen_calls) == 1
    assert len(raw.sign_calls) == 1


def test_sign_probe_unclaimed_runs_no_control(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R4-3: a True readback never reaches the credit path, so no control runs."""
    monkeypatch.setattr(raw_probe, "read_attributes", lambda *_a, **_k: {CKA_SIGN: True})
    raw = _SignCaptureRaw(sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED))
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert f"CKR:0x{int(CKR_KEY_FUNCTION_NOT_PERMITTED):08x}" in out
    assert out.rstrip().endswith("OK")
    assert len(raw.keygen_calls) == 1
    assert len(raw.sign_calls) == 1


def test_sign_probe_aes_fallback_control_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R4-3: the AES route controls with an AES twin (same route, SIGN=True)."""
    monkeypatch.setattr(raw_probe, "read_attributes", _readback_by_handle())
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        sign_rvs=[int(CKR_KEY_FUNCTION_NOT_PERMITTED), int(CKR_OK)],
        refuse_keygen={int(CKM_GENERIC_SECRET_KEY_GEN)},
        refuse_create=True,
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    assert [mech for mech, _ in raw.keygen_calls] == [
        int(CKM_GENERIC_SECRET_KEY_GEN),
        int(CKM_AES_KEY_GEN),
        int(CKM_AES_KEY_GEN),
    ]
    assert raw.keygen_calls[2][1].get(int(CKA_SIGN)) == b"\x01"
    assert len(raw.sign_calls) == 2
    out = capsys.readouterr().out
    assert f"CKR:0x{int(CKR_KEY_FUNCTION_NOT_PERMITTED):08x}" in out
    assert out.rstrip().endswith("OK")


def test_sign_probe_aes_fallback_control_refused(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R4-3: a refused AES twin uncredits the AES denial (Codex round-3 shape)."""
    monkeypatch.setattr(raw_probe, "read_attributes", _readback_by_handle())
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        sign_rvs=[
            int(CKR_KEY_FUNCTION_NOT_PERMITTED),
            int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        ],
        refuse_keygen={int(CKM_GENERIC_SECRET_KEY_GEN)},
        refuse_create=True,
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert f"SETUP_REFUSED:C_SignInit:0x{int(CKR_KEY_FUNCTION_NOT_PERMITTED):08x}" in out
    assert "CKR:" not in out
    assert "OK" not in out.splitlines()


def test_sign_probe_aes_setup_undefined_rv_is_hard_metadata_fail(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R4-4: undefined AES setup RV reaches the parent as metadata FAIL (e2e)."""
    monkeypatch.setattr(raw_probe, "read_attributes", lambda *_a, **_k: {CKA_SIGN: False})

    def _refuse_per_mech(mech: int, _attrs: dict[int, bytes]) -> int | None:
        if mech == int(CKM_GENERIC_SECRET_KEY_GEN):
            return int(CKR_MECHANISM_INVALID)
        if mech == int(CKM_AES_KEY_GEN):
            return 0x00FFFFFF
        return None

    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        refuse_create=True,
        keygen_refuse_predicate=_refuse_per_mech,
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert "SETUP_REFUSED:C_GenerateKey:0x00ffffff" in out
    with pytest.raises(pytest.fail.Exception, match="return-value contract violation"):
        tra._check_permission_probe(
            0,
            out,
            "",
            context="C_SignInit with CKA_SIGN=False",
            operation="C_SignInit",
            attribute=CKA_SIGN,
        )
    refused = [
        record
        for record in C.get_records()
        if record.detail is not None and record.detail.get("protocol_marker") == "SETUP_REFUSED"
    ]
    assert len(refused) == 1
    assert refused[0].reason == "self_contradiction"
    assert refused[0].kind == "metadata"
    assert refused[0].operation == "C_GenerateKey"
    assert refused[0].actual_ckr == "0x00ffffff"


def test_control_refused_marker_is_not_operational_xfail() -> None:
    """R4-3: a refused control routes to not_operational xfail (target untested)."""
    out = f"{_SIGN_FALSE}\nSETUP_REFUSED:C_SignInit:0x{int(CKR_KEY_FUNCTION_NOT_PERMITTED):08x}\n"
    with pytest.raises(pytest.xfail.Exception, match="setup C_SignInit refused"):
        tra._check_permission_probe(
            0,
            out,
            "",
            context="C_SignInit with CKA_SIGN=False",
            operation="C_SignInit",
            attribute=CKA_SIGN,
        )
    refused = [
        record
        for record in C.get_records()
        if record.detail is not None and record.detail.get("protocol_marker") == "SETUP_REFUSED"
    ]
    assert len(refused) == 1
    assert refused[0].reason == "not_operational"
    assert refused[0].outcome == "xfail"
    assert refused[0].operation == "C_SignInit"
    assert refused[0].detail is not None and refused[0].detail.get("target_reached") is False


def test_control_undefined_marker_is_hard_metadata_fail() -> None:
    """R4-3: an undefined control RV fails as metadata beside a clean claim."""
    out = f"{_SIGN_FALSE}\nSETUP_REFUSED:C_SignInit:0x00ffffff\n"
    with pytest.raises(pytest.fail.Exception, match="return-value contract violation"):
        tra._check_permission_probe(
            0,
            out,
            "",
            context="C_SignInit with CKA_SIGN=False",
            operation="C_SignInit",
            attribute=CKA_SIGN,
        )
    refused = [
        record
        for record in C.get_records()
        if record.detail is not None and record.detail.get("protocol_marker") == "SETUP_REFUSED"
    ]
    assert len(refused) == 1
    assert refused[0].reason == "self_contradiction"
    assert refused[0].kind == "metadata"
    assert refused[0].operation == "C_SignInit"
    assert refused[0].actual_ckr == "0x00ffffff"


def test_sign_probe_undefined_keygen_rv_emits_refused_marker(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """F6a: undefined setup RVs emit SETUP_REFUSED, never silently fall back."""
    monkeypatch.setattr(raw_probe, "read_attributes", lambda *_a, **_k: {CKA_SIGN: False})
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        refuse_keygen={int(CKM_GENERIC_SECRET_KEY_GEN)},
        keygen_rv=0x00FFFFFF,
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert "SETUP_REFUSED:C_GenerateKey:0x00ffffff" in out
    assert "CKR:" not in out
    assert "OK" not in out.splitlines()
    assert raw.create_calls == []
    assert [mech for mech, _ in raw.keygen_calls] == [int(CKM_GENERIC_SECRET_KEY_GEN)]


def test_sign_probe_undefined_create_rv_emits_refused_marker(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """F6a: undefined CreateObject RV never falls through to the AES route."""
    monkeypatch.setattr(raw_probe, "read_attributes", lambda *_a, **_k: {CKA_SIGN: False})
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        refuse_keygen={int(CKM_GENERIC_SECRET_KEY_GEN)},
        refuse_create=True,
        create_rv=0x00FFFFFF,
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert "SETUP_REFUSED:C_CreateObject:0x00ffffff" in out
    assert "CKR:" not in out
    assert "OK" not in out.splitlines()
    assert [mech for mech, _ in raw.keygen_calls] == [int(CKM_GENERIC_SECRET_KEY_GEN)]


def test_sign_probe_defined_rv_still_falls_back(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """F6a control: defined setup refusals keep the fallback chain."""
    monkeypatch.setattr(raw_probe, "read_attributes", _readback_by_handle())
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        sign_rvs=[int(CKR_KEY_FUNCTION_NOT_PERMITTED), int(CKR_OK)],
        refuse_keygen={int(CKM_GENERIC_SECRET_KEY_GEN)},
        refuse_create=True,
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    out = capsys.readouterr().out
    assert "SETUP_REFUSED" not in out
    assert out.rstrip().endswith("OK")


def test_sign_probe_fallback_notes_beaten_defined_rv_on_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """F6a: beaten defined RVs stay visible on stderr (unparsed diagnostics)."""
    monkeypatch.setattr(raw_probe, "read_attributes", lambda *_a, **_k: {CKA_SIGN: False})
    raw = _SignCaptureRaw(
        sign_rv=int(CKR_KEY_FUNCTION_NOT_PERMITTED),
        refuse_keygen={int(CKM_GENERIC_SECRET_KEY_GEN)},
    )
    ctx = cast(ProbeContext, SimpleNamespace(raw=raw, sh=1))

    raw_probe._sign(ctx)

    err = capsys.readouterr().err
    assert "setup fallback" in err
    assert "C_GenerateKey" in err


def test_refused_marker_undefined_rv_is_hard_metadata_fail() -> None:
    """F6a: undefined setup RV routes to a hard metadata verdict with op+RV."""
    out = "SETUP_REFUSED:C_GenerateKey:0x00ffffff\n"
    with pytest.raises(pytest.fail.Exception, match="return-value contract violation"):
        tra._check_permission_probe(
            0,
            out,
            "",
            context="C_SignInit with CKA_SIGN=False",
            operation="C_SignInit",
            attribute=CKA_SIGN,
        )
    refused = [
        record
        for record in C.get_records()
        if record.detail is not None and record.detail.get("protocol_marker") == "SETUP_REFUSED"
    ]
    assert len(refused) == 1
    assert refused[0].reason == "self_contradiction"
    assert refused[0].kind == "metadata"
    assert refused[0].operation == "C_GenerateKey"
    assert refused[0].actual_ckr == "0x00ffffff"


def test_refused_marker_defined_rv_is_not_operational_xfail() -> None:
    """F6a: defined setup refusals route to not_operational xfail."""
    out = "SETUP_REFUSED:C_GenerateKey:0x00000006\n"
    with pytest.raises(pytest.xfail.Exception, match="setup C_GenerateKey refused"):
        tra._check_permission_probe(
            0,
            out,
            "",
            context="C_SignInit with CKA_SIGN=False",
            operation="C_SignInit",
            attribute=CKA_SIGN,
        )
    refused = [
        record
        for record in C.get_records()
        if record.detail is not None and record.detail.get("protocol_marker") == "SETUP_REFUSED"
    ]
    assert len(refused) == 1
    assert refused[0].reason == "not_operational"
    assert refused[0].outcome == "xfail"


def test_refused_marker_malformed_is_harness_error() -> None:
    """F6a: malformed refusal markers fail loud as harness errors."""
    out = "SETUP_REFUSED:garbage!!!\n"
    with pytest.raises(pytest.fail.Exception, match="malformed"):
        tra._check_permission_probe(
            0,
            out,
            "",
            context="C_SignInit with CKA_SIGN=False",
            operation="C_SignInit",
            attribute=CKA_SIGN,
        )
    assert any(record.reason == "harness_error" for record in C.get_records())


def test_refused_marker_beside_measurement_is_harness_error() -> None:
    """F6a: a refusal beside a target measurement breaks the wire protocol."""
    out = "SETUP_REFUSED:C_GenerateKey:0x00000006\nCKR:0x00000062\n"
    with pytest.raises(pytest.fail.Exception, match="malformed"):
        tra._check_permission_probe(
            0,
            out,
            "",
            context="C_SignInit with CKA_SIGN=False",
            operation="C_SignInit",
            attribute=CKA_SIGN,
        )
    assert any(record.reason == "harness_error" for record in C.get_records())


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
