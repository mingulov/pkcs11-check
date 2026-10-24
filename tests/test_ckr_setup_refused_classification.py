"""Meta-tests: SETUP_REFUSED marker distinguishes setup-refused from not-applicable (issue #28).

A probe setup step with valid inputs refused by the module must record the
setup operation + refusal CKR explicitly (target untested) instead of folding
into a generic target not_operational record.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pkcs11_check.classification import get_records, serialize
from pkcs11_check.raw.types_std import _CK_ULONG_MAX
from pkcs11_check.report.extract import extract_groups
from pkcs11_check.report.health import outcome_counts
from pkcs11_check.testcases._probes.session import ProbeContext
from pkcs11_check.testcases.ckr import test_ckr_raw_buffer as raw_buffer
from tests._skip_assert import assert_xfails


def test_refused_setup_records_structured_not_operational() -> None:
    """SETUP_REFUSED:<Op>:0x<rv> records the setup op + CKR with target untested."""
    assert_xfails(
        raw_buffer._check_buffer_probe,
        0,
        "SETUP_REFUSED:C_DecryptInit:0x00000006\n",
        "",
        context="buffer probe",
    )
    setup = [
        record
        for record in get_records()
        if record.detail is not None and record.detail.get("protocol_marker") == "SETUP_REFUSED"
    ]
    assert len(setup) == 1
    record = setup[0]
    assert record.reason == "not_operational"
    assert record.outcome == "xfail"
    assert record.operation == "C_DecryptInit"
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"
    assert record.expected_ckr == ["CKR_OK"]
    assert "target untested" in record.summary
    assert record.detail is not None
    assert record.detail["setup_operation"] == "C_DecryptInit"
    assert record.detail["setup_rv"] == 0x06


def test_legacy_setup_xfail_record_shape_unchanged() -> None:
    """SETUP_XFAIL keeps its record shape: free-text summary, no setup operation."""
    assert_xfails(
        raw_buffer._check_buffer_probe,
        0,
        "SETUP_XFAIL:legacy key setup refused\n",
        "",
        context="buffer probe",
    )
    setup = [
        record
        for record in get_records()
        if record.detail is not None and record.detail.get("protocol_marker") == "SETUP_XFAIL"
    ]
    assert len(setup) == 1
    assert setup[0].reason == "not_operational"
    assert setup[0].operation is None
    assert "legacy key setup refused" in setup[0].summary


@pytest.mark.parametrize(
    "line",
    [
        "SETUP_REFUSED:\n",
        "SETUP_REFUSED:not-a-payload\n",
        "SETUP_REFUSED:C_DecryptInit:-1\n",
        "SETUP_REFUSED:!!!:0x6\n",
        # F1 (review): success masquerading as refusal, unrepresentable rv,
        # extra delimiters, and non-identifier ops must fail loud, never xfail.
        "SETUP_REFUSED:C_DecryptInit:0x0\n",
        f"SETUP_REFUSED:C_DecryptInit:0x{_CK_ULONG_MAX + 1:X}\n",
        "SETUP_REFUSED:C_A:B:0x6\n",
        "SETUP_REFUSED:C_!!!:0x6\n",
    ],
)
def test_refused_malformed_payload_is_harness_error(line: str) -> None:
    """Empty, garbage, contradictory, or unrepresentable SETUP_REFUSED payloads fail loud."""
    with pytest.raises(pytest.fail.Exception, match="malformed"):
        raw_buffer._check_buffer_probe(0, line, "", context="buffer probe")
    assert any(record.reason == "harness_error" for record in get_records())


def test_refused_max_ulong_rv_still_xfails() -> None:
    """Boundary pin: the largest representable CK_RV is a refusal, not malformed (F1)."""
    assert_xfails(
        raw_buffer._check_buffer_probe,
        0,
        f"SETUP_REFUSED:C_DecryptInit:0x{_CK_ULONG_MAX:X}\n",
        "",
        context="buffer probe",
    )


@pytest.mark.parametrize(
    "stdout",
    [
        # R2a: a refused setup is a single terminal fact -- real emitters print
        # it once on an early-return path, never beside measurement or OK.
        "SETUP_REFUSED:C_GenerateKey:0x00000006\nSETUP_REFUSED:C_GenerateKey:0x00000006\n",
        "SETUP_REFUSED:C_GenerateKey:0x00000006\n"
        "CKR:0x00000007\nGUARD_OVERWRITTEN:0\nRETURNED_COUNT:16\nOK\n",
        "CKR:0x00000007\nGUARD_OVERWRITTEN:0\nRETURNED_COUNT:16\nOK\n"
        "SETUP_REFUSED:C_GenerateKey:0x00000006\n",
        "SETUP_REFUSED:C_GenerateKey:0x00000006\nOK\n",
        # R3a: a refusal beside any other terminal marker is competing-terminal
        # evidence -- real emitters print exactly one marker per probe run.
        "SETUP_REFUSED:C_GenerateKey:0x00000006\nSETUP_XFAIL:legacy key setup refused\n",
        "SETUP_REFUSED:C_GenerateKey:0x00000006\nDEVIATION_XFAIL:safely refused at end\n",
    ],
)
def test_refused_terminal_contradictions_are_malformed(stdout: str) -> None:
    """Duplicate refusals and refusal-with-measurement fail loud (R2a)."""
    with pytest.raises(pytest.fail.Exception, match="malformed"):
        raw_buffer._check_buffer_probe(0, stdout, "", context="buffer probe")
    assert any(record.reason == "harness_error" for record in get_records())


@pytest.mark.parametrize(
    "empty_marker",
    ["SETUP_XFAIL:", "DEVIATION_XFAIL:", "BREAK:"],
)
@pytest.mark.parametrize("refusal_first", [True, False])
def test_buffer_refusal_beside_empty_marker_is_malformed(
    empty_marker: str, refusal_first: bool
) -> None:
    """Fix round 1 pin: buffer parent already fails loud here (parity proof).

    Either order raises the malformed-marker failure, never the refusal xfail.
    The xfail branch is caught explicitly so a regression cannot mask as green.
    """
    refusal = "SETUP_REFUSED:C_GenerateKey:0x00000006\n"
    malformed_line = f"{empty_marker}\n"
    stdout = refusal + malformed_line if refusal_first else malformed_line + refusal
    try:
        raw_buffer._check_buffer_probe(
            0, stdout, "", context="C_WrapKey undersized output buffer guard"
        )
    except pytest.xfail.Exception as exc:
        # Caught first: XFailed subclasses Failed in this pytest, so the fail
        # branch below would otherwise swallow the exact regression pinned here.
        pytest.fail(f"refusal overrode empty {empty_marker} marker with xfail: {exc!r}")
    except pytest.fail.Exception as exc:
        assert "malformed" in str(exc)
    else:
        pytest.fail(f"refusal beside empty {empty_marker} marker must fail loud")
    assert any(record.reason == "harness_error" for record in get_records())


def test_refused_contradiction_with_provider_fail_raises_fail() -> None:
    """Fail-before-malformed: parsed provider evidence beats the protocol failure (R2a)."""
    stdout = (
        "SETUP_REFUSED:C_GenerateKey:0x00000006\n"
        "SETUP_REFUSED:C_GenerateKey:0x00000006\n"
        "BREAK:wrong-key operation produced output\n"
    )
    with pytest.raises(pytest.fail.Exception, match="wrong-key operation produced output"):
        raw_buffer._check_buffer_probe(0, stdout, "", context="buffer probe")
    assert any(record.reason == "self_contradiction" for record in get_records())


class _RefuseGenerateKey:
    """Fake raw: C_GenerateKey refused; anything else is a test bug."""

    def __init__(self, rv: int) -> None:
        self._rv = rv

    def C_GenerateKey(self, *args: Any, **kwargs: Any) -> int:  # noqa: N802
        return self._rv


def test_decrypt_final_setup_refusal_emits_structured_marker(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The issue #28 probe family emits SETUP_REFUSED:<Op>:0x<rv> on setup refusal."""
    from pkcs11_check.testcases._probes import ckr_raw_buffer as raw_probe

    ctx = ProbeContext(
        raw=cast(Any, _RefuseGenerateKey(0x06)),
        sh=1,
        slot_id=1,
        cleanup=lambda: None,
        module_path="test-module",
    )
    raw_probe._aes_cbc_pad_decrypt_final_buffer_too_small(ctx)
    out = capsys.readouterr().out
    assert "SETUP_REFUSED:C_GenerateKey:0x00000006" in out
    assert "SETUP_XFAIL" not in out


class _RefuseSetupOp:
    """Fake raw: one setup op refused with 0x06; keygen predecessors succeed."""

    def __init__(self, op: str) -> None:
        self._op = op

    def C_GenerateKey(self, *args: Any) -> int:  # noqa: N802
        if self._op == "C_GenerateKey":
            return 0x06
        args[-1]._obj.value = 7
        return 0

    def C_GenerateKeyPair(self, *args: Any) -> int:  # noqa: N802
        if self._op == "C_GenerateKeyPair":
            return 0x06
        args[-2]._obj.value = 7
        args[-1]._obj.value = 8
        return 0

    def C_DigestInit(self, *args: Any) -> int:  # noqa: N802
        return 0x06 if self._op == "C_DigestInit" else 0

    def C_DigestUpdate(self, *args: Any) -> int:  # noqa: N802
        return 0x06 if self._op == "C_DigestUpdate" else 0

    def C_EncryptInit(self, *args: Any) -> int:  # noqa: N802
        return 0x06 if self._op == "C_EncryptInit" else 0

    def C_SignInit(self, *args: Any) -> int:  # noqa: N802
        return 0x06 if self._op == "C_SignInit" else 0


@pytest.mark.parametrize(
    ("probe", "op"),
    [
        ("_digest_buffer_too_small", "C_DigestInit"),
        ("_encrypt_buffer_too_small", "C_GenerateKey"),
        ("_encrypt_buffer_too_small", "C_EncryptInit"),
        ("_sign_buffer_too_small", "C_GenerateKeyPair"),
        ("_sign_buffer_too_small", "C_SignInit"),
        ("_get_operation_state_buffer_too_small", "C_DigestInit"),
        ("_get_operation_state_buffer_too_small", "C_DigestUpdate"),
    ],
)
def test_digest_encrypt_sign_setup_refusal_emits_structured_marker(
    probe: str, op: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Digest/encrypt/sign buffer probes emit SETUP_REFUSED:<Op>:0x<rv> (fw#28)."""
    from pkcs11_check.testcases._probes import ckr_raw_buffer as raw_probe

    ctx = ProbeContext(
        raw=cast(Any, _RefuseSetupOp(op)),
        sh=1,
        slot_id=1,
        cleanup=lambda: None,
        module_path="test-module",
    )
    getattr(raw_probe, probe)(ctx)
    out = capsys.readouterr().out
    assert f"SETUP_REFUSED:{op}:0x00000006" in out
    assert "SETUP_XFAIL" not in out


def test_refused_line_tracked_as_setup_refusal() -> None:
    """SETUP_REFUSED lines feed setup_refusal_indices for ordering checks."""
    (_, _, _, _, _, _, _, _, setup_refusal_indices, _) = raw_buffer._parse_ec_facts(
        "SETUP_REFUSED:C_GenerateKey:0x00000006\n",
        context="buffer probe",
        process_complete=True,
        expected_probe=None,
    )
    assert list(setup_refusal_indices) == [0]


# --- QF5 buffer-family rollout: remaining guard/size-query setup sites ---
#
# Each fake below refuses exactly one setup call with CKR_FUNCTION_FAILED
# (0x06). Any other raw call is a test bug (AttributeError): the guarded
# target must never run on the refusal path, and no OK completion marker
# may be emitted.


class _RefuseGetSlotList:
    def C_GetSlotList(self, *args: Any) -> int:  # noqa: N802
        return 0x06


class _RefuseGetMechanismList:
    def C_GetMechanismList(self, *args: Any) -> int:  # noqa: N802
        return 0x06


class _RefuseGetInterfaceList:
    def available_function_names(self) -> list[str]:
        return ["C_GetInterfaceList"]

    def C_GetInterfaceList(self, *args: Any) -> int:  # noqa: N802
        return 0x06


class _RefuseFindCreate:
    def C_CreateObject(self, *args: Any) -> int:  # noqa: N802
        return 0x06


class _RefuseFindInit:
    def C_CreateObject(self, *args: Any) -> int:  # noqa: N802
        args[-1]._obj.value = 11
        return 0

    def C_FindObjectsInit(self, *args: Any) -> int:  # noqa: N802
        return 0x06

    def C_DestroyObject(self, *args: Any) -> int:  # noqa: N802
        return 0


class _RefuseAttrCreate:
    def C_CreateObject(self, *args: Any) -> int:  # noqa: N802
        return 0x06


class _RefuseAttrSizeQuery:
    def C_CreateObject(self, *args: Any) -> int:  # noqa: N802
        args[-1]._obj.value = 12
        return 0

    def C_GetAttributeValue(self, *args: Any) -> int:  # noqa: N802
        return 0x06

    def C_DestroyObject(self, *args: Any) -> int:  # noqa: N802
        return 0


class _RefuseWrapKeygen:
    def C_GenerateKey(self, *args: Any) -> int:  # noqa: N802
        return 0x06


class _RefuseWrapTargetKeygen:
    def __init__(self) -> None:
        self.keygens = 0

    def C_GenerateKey(self, *args: Any) -> int:  # noqa: N802
        self.keygens += 1
        if self.keygens == 1:
            args[-1]._obj.value = 21
            return 0
        return 0x06

    def C_DestroyObject(self, *args: Any) -> int:  # noqa: N802
        return 0


class _RefuseWrapSizeQuery:
    def __init__(self) -> None:
        self.keygens = 0

    def C_GenerateKey(self, *args: Any) -> int:  # noqa: N802
        self.keygens += 1
        args[-1]._obj.value = 20 + self.keygens
        return 0

    def C_WrapKey(self, *args: Any) -> int:  # noqa: N802
        return 0x06

    def C_DestroyObject(self, *args: Any) -> int:  # noqa: N802
        return 0


class _RefuseECKeypair:
    def C_GenerateKeyPair(self, *args: Any) -> int:  # noqa: N802
        return 0x06


class _ECGuardFakeBase:
    """EC guard fake: keypair/import/target succeed unless a subclass refuses one."""

    refused_op: str = ""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def C_GenerateKeyPair(self, *args: Any) -> int:  # noqa: N802
        self.calls.append("C_GenerateKeyPair")
        if self.refused_op == "C_GenerateKeyPair":
            return 0x06
        args[-2]._obj.value = 1
        args[-1]._obj.value = 2
        return 0

    def C_CreateObject(self, *args: Any) -> int:  # noqa: N802
        self.calls.append("C_CreateObject")
        if self.refused_op == "C_CreateObject":
            return 0x06
        args[-1]._obj.value = 3
        return 0

    def C_GenerateKey(self, *args: Any) -> int:  # noqa: N802
        self.calls.append("C_GenerateKey")
        if self.refused_op == "C_GenerateKey":
            return 0x06
        args[-1]._obj.value = 4
        return 0

    def C_WrapKey(self, *args: Any) -> int:  # noqa: N802
        self.calls.append("C_WrapKey")
        return 0x06 if self.refused_op == "C_WrapKey" else 0

    def C_DestroyObject(self, *args: Any) -> int:  # noqa: N802
        return 0


class _RefuseECImport(_ECGuardFakeBase):
    refused_op = "C_CreateObject"


class _RefuseECTargetKeygen(_ECGuardFakeBase):
    refused_op = "C_GenerateKey"


class _RefuseECWrapSizeQuery(_ECGuardFakeBase):
    refused_op = "C_WrapKey"


class _RefuseOperationStateSizeQuery:
    def C_DigestInit(self, *args: Any) -> int:  # noqa: N802
        return 0

    def C_DigestUpdate(self, *args: Any) -> int:  # noqa: N802
        return 0

    def C_GetOperationState(self, *args: Any) -> int:  # noqa: N802
        return 0x06


def _raw_p256_point_for_ec_guard() -> bytes:
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def _patch_ec_attributes(monkeypatch: pytest.MonkeyPatch, raw_probe: Any) -> None:
    point = _raw_p256_point_for_ec_guard()
    monkeypatch.setattr(
        raw_probe,
        "read_attributes",
        lambda *_args: {
            raw_probe.CKA_EC_POINT: point,
            raw_probe.CKA_EC_PARAMS: b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        },
    )


@pytest.mark.parametrize(
    ("probe", "op", "fake"),
    [
        ("_get_slot_list_guard", "C_GetSlotList", _RefuseGetSlotList()),
        ("_get_mechanism_list_guard", "C_GetMechanismList", _RefuseGetMechanismList()),
        ("_get_interface_list_guard", "C_GetInterfaceList", _RefuseGetInterfaceList()),
        ("_find_objects_max_count_one_guard", "C_CreateObject", _RefuseFindCreate()),
        ("_find_objects_max_count_one_guard", "C_FindObjectsInit", _RefuseFindInit()),
        ("_get_attribute_value_guard", "C_CreateObject", _RefuseAttrCreate()),
        ("_get_attribute_value_guard", "C_GetAttributeValue", _RefuseAttrSizeQuery()),
        ("_wrap_key_buffer_too_small", "C_GenerateKey", _RefuseWrapKeygen()),
        ("_wrap_key_buffer_too_small", "C_GenerateKey", _RefuseWrapTargetKeygen()),
        ("_wrap_key_buffer_too_small", "C_WrapKey", _RefuseWrapSizeQuery()),
        (
            "_ecdh_aes_wrap_compressed_public_key_buffer_too_small",
            "C_GenerateKeyPair",
            _RefuseECKeypair(),
        ),
        (
            "_ecdh_aes_wrap_compressed_public_key_buffer_too_small",
            "C_CreateObject",
            _RefuseECImport(),
        ),
        (
            "_ecdh_aes_wrap_compressed_public_key_buffer_too_small",
            "C_GenerateKey",
            _RefuseECTargetKeygen(),
        ),
        (
            "_ecdh_aes_wrap_compressed_public_key_buffer_too_small",
            "C_WrapKey",
            _RefuseECWrapSizeQuery(),
        ),
        (
            "_get_operation_state_buffer_too_small",
            "C_GetOperationState",
            _RefuseOperationStateSizeQuery(),
        ),
    ],
)
def test_migrated_buffer_site_emits_setup_refused(
    probe: str,
    op: str,
    fake: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """QF5 buffer rollout: each refused setup emits SETUP_REFUSED, target unrun (fw#28)."""
    from pkcs11_check.testcases._probes import ckr_raw_buffer as raw_probe

    if probe == "_ecdh_aes_wrap_compressed_public_key_buffer_too_small" and not isinstance(
        fake, _RefuseECKeypair
    ):
        _patch_ec_attributes(monkeypatch, raw_probe)
    ctx = ProbeContext(
        raw=cast(Any, fake),
        sh=9,
        slot_id=1,
        cleanup=lambda: None,
        module_path="test-module",
    )
    getattr(raw_probe, probe)(ctx)
    out = capsys.readouterr().out
    assert f"SETUP_REFUSED:{op}:0x00000006" in out
    assert "SETUP_XFAIL" not in out
    assert not any(line.startswith("CKR:") for line in out.splitlines())
    assert "OK" not in out.splitlines()


def test_refused_record_marks_target_unreached_with_setup_contract() -> None:
    """QF5: a refusal records the setup contract and target_reached=false (fw#28)."""
    assert_xfails(
        raw_buffer._check_buffer_probe,
        0,
        "SETUP_REFUSED:C_WrapKey:0x00000006\n",
        "",
        context="C_WrapKey undersized output buffer guard",
    )
    setup = [
        record
        for record in get_records()
        if record.detail is not None and record.detail.get("protocol_marker") == "SETUP_REFUSED"
    ]
    assert len(setup) == 1
    record = setup[0]
    assert record.reason == "not_operational"
    assert record.outcome == "xfail"
    assert record.operation == "C_WrapKey"
    assert record.expected_ckr == ["CKR_OK"]
    assert record.actual_ckr == "CKR_FUNCTION_FAILED"
    assert record.detail is not None
    assert record.detail["setup_operation"] == "C_WrapKey"
    assert record.detail["setup_rv"] == 0x06
    assert record.detail["target_reached"] is False


def test_refused_record_survives_json_serialization() -> None:
    """QF5: setup op/RV/target_reached survive the JSONL artifact round-trip (fw#28)."""
    assert_xfails(
        raw_buffer._check_buffer_probe,
        0,
        "SETUP_REFUSED:C_GetSlotList:0x00000006\n",
        "",
        context="C_GetSlotList undersized list buffer guard",
    )
    payload = json.loads(json.dumps(serialize(get_records())))
    setup = [item for item in payload if item["detail"]["protocol_marker"] == "SETUP_REFUSED"]
    assert len(setup) == 1
    item = setup[0]
    assert item["operation"] == "C_GetSlotList"
    assert item["expected_ckr"] == ["CKR_OK"]
    assert item["actual_ckr"] == "CKR_FUNCTION_FAILED"
    assert item["detail"]["setup_operation"] == "C_GetSlotList"
    assert item["detail"]["setup_rv"] == 0x06
    assert item["detail"]["target_reached"] is False


def test_refused_keygen_setup_issues_no_target_operation_record() -> None:
    """QF5 pin: a refused keygen never credits the guarded target operation (fw#28).

    The record groups under the refusing setup call (C_GenerateKey), never the
    untested guarded target (C_WrapKey), and the outcome is xfail, never pass.
    """
    assert_xfails(
        raw_buffer._check_buffer_probe,
        0,
        "SETUP_REFUSED:C_GenerateKey:0x00000006\n",
        "",
        context="C_WrapKey undersized output buffer guard",
    )
    records = get_records()
    assert records
    assert all(record.outcome == "xfail" for record in records)
    assert all(record.operation != "C_WrapKey" for record in records)
    assert any(record.operation == "C_GenerateKey" for record in records)


def test_refused_new_op_without_completion_still_xfails() -> None:
    """QF5 pin: a lone refusal is terminal without OK/fields (missing-target control)."""
    assert_xfails(
        raw_buffer._check_buffer_probe,
        0,
        "SETUP_REFUSED:C_GetOperationState:0x00000006\n",
        "",
        context="C_GetOperationState undersized state buffer guard",
    )
    assert [record.reason for record in get_records()] == ["not_operational"]


def test_refused_new_op_with_ok_is_malformed() -> None:
    """QF5 pin: a refusal beside OK completion is contradictory evidence (fw#28)."""
    with pytest.raises(pytest.fail.Exception, match="malformed"):
        raw_buffer._check_buffer_probe(
            0,
            "SETUP_REFUSED:C_GetOperationState:0x00000006\nOK\n",
            "",
            context="C_GetOperationState undersized state buffer guard",
        )
    assert any(record.reason == "harness_error" for record in get_records())


# --- Fix round 1: end-to-end grouping/coverage proof (finding 2) ---
#
# The QF5 grouping tests only round-tripped serialized dicts through JSON, so a
# grouping layer that dropped attribution (or credited the untested target)
# could not fail them. These tests feed captured production-probe output through
# the production parent plus the production report grouping
# (``extract_groups``) and accounting (``outcome_counts``).


def _write_report_jsonl(tmp_path: Path, entries: list[tuple[str, list[Any]]]) -> Path:
    """Write TestReport lines carrying phase-scoped pkcs11_classification lists.

    Same record shape the runner persists (cf. test_report_extract.py); the
    payload round-trips through JSON exactly as the JSONL artifact requires.
    """
    lines = [
        {
            "$report_type": "TestReport",
            "when": "call",
            "nodeid": nodeid,
            "outcome": "failed",
            "user_properties": [["pkcs11_classification", payload]],
        }
        for nodeid, payload in entries
    ]
    path = tmp_path / "report.jsonl"
    path.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
    return path


def _grouped_parent_records(tmp_path: Path, nodeid: str) -> list[dict[str, Any]]:
    """Feed parent records through the production JSONL report grouping."""
    payload = json.loads(json.dumps(serialize(get_records())))
    return extract_groups(_write_report_jsonl(tmp_path, [(nodeid, payload)]), crashes=[])


def _capture_refused_buffer_output(
    probe: str,
    fake_cls: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> str:
    """Run one production buffer probe with a refusing fake; return its stdout."""
    from pkcs11_check.testcases._probes import ckr_raw_buffer as raw_probe

    if probe == "_ecdh_aes_wrap_compressed_public_key_buffer_too_small" and (
        fake_cls is not _RefuseECKeypair
    ):
        _patch_ec_attributes(monkeypatch, raw_probe)
    ctx = ProbeContext(
        raw=cast(Any, fake_cls()),
        sh=9,
        slot_id=1,
        cleanup=lambda: None,
        module_path="test-module",
    )
    getattr(raw_probe, probe)(ctx)
    return capsys.readouterr().out


_BUFFER_PROBES = {
    "_ecdh_aes_wrap_compressed_public_key_buffer_too_small": (
        "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
    ),
}
"""Production ``probe=`` selectors (only the EC guard parent takes one)."""


_BUFFER_CONTEXTS = {
    "_get_slot_list_guard": "C_GetSlotList undersized list buffer guard",
    "_get_mechanism_list_guard": "C_GetMechanismList undersized list buffer guard",
    "_get_interface_list_guard": "C_GetInterfaceList undersized list buffer guard",
    "_find_objects_max_count_one_guard": "C_FindObjects one-handle output guard",
    "_get_attribute_value_guard": "C_GetAttributeValue undersized attribute buffer guard",
    "_wrap_key_buffer_too_small": "C_WrapKey undersized output buffer guard",
    "_ecdh_aes_wrap_compressed_public_key_buffer_too_small": (
        "ECDH-AES C_WrapKey compressed public key undersized output buffer guard"
    ),
    "_get_operation_state_buffer_too_small": ("C_GetOperationState undersized output buffer guard"),
}


@pytest.mark.parametrize(
    ("probe", "op", "fake_cls"),
    [
        ("_get_slot_list_guard", "C_GetSlotList", _RefuseGetSlotList),
        ("_get_mechanism_list_guard", "C_GetMechanismList", _RefuseGetMechanismList),
        ("_get_interface_list_guard", "C_GetInterfaceList", _RefuseGetInterfaceList),
        ("_find_objects_max_count_one_guard", "C_CreateObject", _RefuseFindCreate),
        ("_find_objects_max_count_one_guard", "C_FindObjectsInit", _RefuseFindInit),
        ("_get_attribute_value_guard", "C_CreateObject", _RefuseAttrCreate),
        ("_get_attribute_value_guard", "C_GetAttributeValue", _RefuseAttrSizeQuery),
        ("_wrap_key_buffer_too_small", "C_GenerateKey", _RefuseWrapKeygen),
        ("_wrap_key_buffer_too_small", "C_GenerateKey", _RefuseWrapTargetKeygen),
        ("_wrap_key_buffer_too_small", "C_WrapKey", _RefuseWrapSizeQuery),
        (
            "_ecdh_aes_wrap_compressed_public_key_buffer_too_small",
            "C_GenerateKeyPair",
            _RefuseECKeypair,
        ),
        (
            "_ecdh_aes_wrap_compressed_public_key_buffer_too_small",
            "C_CreateObject",
            _RefuseECImport,
        ),
        (
            "_ecdh_aes_wrap_compressed_public_key_buffer_too_small",
            "C_GenerateKey",
            _RefuseECTargetKeygen,
        ),
        (
            "_ecdh_aes_wrap_compressed_public_key_buffer_too_small",
            "C_WrapKey",
            _RefuseECWrapSizeQuery,
        ),
        (
            "_get_operation_state_buffer_too_small",
            "C_GetOperationState",
            _RefuseOperationStateSizeQuery,
        ),
    ],
)
def test_injected_buffer_refusals_survive_production_grouping(
    probe: str,
    op: str,
    fake_cls: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Fix round 1: every injected refusal keeps attribution through grouping."""
    context = _BUFFER_CONTEXTS[probe]
    out = _capture_refused_buffer_output(probe, fake_cls, monkeypatch, capsys)
    assert f"SETUP_REFUSED:{op}:0x00000006" in out
    assert_xfails(
        raw_buffer._check_buffer_probe,
        0,
        out,
        "",
        context=context,
        probe=_BUFFER_PROBES.get(probe),
    )
    groups = _grouped_parent_records(
        tmp_path,
        f"src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::Test::{probe}",
    )
    assert len(groups) == 1
    grp = groups[0]
    assert grp["operation"] == op
    assert grp["expected_ckr"] == ["CKR_OK"]
    assert grp["actual_ckr"] == "CKR_FUNCTION_FAILED"
    assert grp["reason"] == "not_operational"
    assert grp["outcome"] == "xfail"
    assert grp["detail"]["setup_operation"] == op
    assert grp["detail"]["setup_rv"] == 0x06
    assert grp["detail"]["target_reached"] is False
    assert grp["count"] == 1
    counts = outcome_counts(groups)
    assert counts["xfail"] == 1
    assert counts["fail"] == 0
    assert counts["harness_error"] == 0
    assert counts["crash"] == 0


@pytest.mark.parametrize(
    ("probe", "op", "fake_cls", "target"),
    [
        ("_wrap_key_buffer_too_small", "C_GenerateKey", _RefuseWrapKeygen, "C_WrapKey"),
        (
            "_wrap_key_buffer_too_small",
            "C_GenerateKey",
            _RefuseWrapTargetKeygen,
            "C_WrapKey",
        ),
        (
            "_ecdh_aes_wrap_compressed_public_key_buffer_too_small",
            "C_GenerateKeyPair",
            _RefuseECKeypair,
            "C_WrapKey",
        ),
        (
            "_ecdh_aes_wrap_compressed_public_key_buffer_too_small",
            "C_CreateObject",
            _RefuseECImport,
            "C_WrapKey",
        ),
        (
            "_ecdh_aes_wrap_compressed_public_key_buffer_too_small",
            "C_GenerateKey",
            _RefuseECTargetKeygen,
            "C_WrapKey",
        ),
        (
            "_find_objects_max_count_one_guard",
            "C_CreateObject",
            _RefuseFindCreate,
            "C_FindObjects",
        ),
        (
            "_get_attribute_value_guard",
            "C_CreateObject",
            _RefuseAttrCreate,
            "C_GetAttributeValue",
        ),
    ],
)
def test_grouped_buffer_refusal_credits_no_guarded_target(
    probe: str,
    op: str,
    fake_cls: Any,
    target: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Fix round 1: the guarded target gets no group/coverage credit (fw#28)."""
    context = _BUFFER_CONTEXTS[probe]
    out = _capture_refused_buffer_output(probe, fake_cls, monkeypatch, capsys)
    assert f"SETUP_REFUSED:{op}:0x00000006" in out
    assert_xfails(
        raw_buffer._check_buffer_probe,
        0,
        out,
        "",
        context=context,
        probe=_BUFFER_PROBES.get(probe),
    )
    groups = _grouped_parent_records(
        tmp_path,
        f"src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::Test::{probe}",
    )
    credited = {group["operation"] for group in groups}
    assert credited == {op}
    assert target not in credited


def test_grouped_buffer_measurement_credits_target_context_when_it_runs(
    tmp_path: Path,
) -> None:
    """Fix round 1 positive control: a ran-and-deviated target IS grouped by context."""
    context = "C_WrapKey undersized output buffer guard"
    stdout = "CKR:0x00000000\nGUARD_OVERWRITTEN:0\nRETURNED_COUNT:1\nOK\n"
    assert_xfails(raw_buffer._check_buffer_probe, 0, stdout, "", context=context)
    groups = _grouped_parent_records(
        tmp_path,
        "src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::Test::wrap_guard_ran",
    )
    assert len(groups) == 1
    assert groups[0]["operation"] == context
    assert groups[0]["reason"] == "honest_deviation"
    assert groups[0]["outcome"] == "xfail"


def test_grouped_legacy_setup_xfail_keeps_unattributed_operation(
    tmp_path: Path,
) -> None:
    """Fix round 1 legacy control: free-text refusals group without an operation."""
    assert_xfails(
        raw_buffer._check_buffer_probe,
        0,
        "SETUP_XFAIL:legacy key setup refused\n",
        "",
        context="buffer probe",
    )
    groups = _grouped_parent_records(
        tmp_path,
        "src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::Test::legacy",
    )
    assert len(groups) == 1
    assert groups[0]["reason"] == "not_operational"
    assert groups[0]["operation"] is None
    assert groups[0]["outcome"] == "xfail"


def test_grouped_buffer_refusal_contradiction_accounts_harness_error(
    tmp_path: Path,
) -> None:
    """Fix round 1 malformed control: refusal+OK groups as harness_error, never xfail."""
    with pytest.raises(pytest.fail.Exception, match="malformed"):
        raw_buffer._check_buffer_probe(
            0,
            "SETUP_REFUSED:C_GenerateKey:0x00000006\nOK\n",
            "",
            context="C_WrapKey undersized output buffer guard",
        )
    groups = _grouped_parent_records(
        tmp_path,
        "src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::Test::contradiction",
    )
    # Both observations survive grouping: the refusal record plus the
    # malformed-marker failure (the parent preserves every record; only the
    # raised headline is ordered, and it was the failure asserted above).
    assert sorted(group["reason"] for group in groups) == [
        "harness_error",
        "not_operational",
    ]
    failed = [group for group in groups if group["reason"] == "harness_error"]
    assert len(failed) == 1
    assert failed[0]["outcome"] == "fail"
    counts = outcome_counts(groups)
    assert counts["harness_error"] == 1
    assert counts["xfail"] == 1
    assert counts["fail"] == 0
    assert counts["crash"] == 0
