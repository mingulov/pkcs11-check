"""Runtime protocol and classification tests for the derive UAF probe."""

from __future__ import annotations

import ctypes
import json
import sys
from collections.abc import Iterator
from types import SimpleNamespace
from typing import cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification as C  # noqa: N812 - classification alias convention
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EC_POINT,
    CKR_KEY_HANDLE_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
)
from pkcs11_check.testcases._probes import _attribute_facts as facts
from pkcs11_check.testcases._probes import operation_state_uaf as probe
from pkcs11_check.testcases._probes.session import ProbeContext
from pkcs11_check.testcases._subprocess_preamble import SUBPROCESS_TIMEOUT_MARKER
from pkcs11_check.testcases.security import test_operation_state_uaf as uaf
from tests._attribute_access_guard import analyze_file
from tests._skip_assert import assert_skips


def _config() -> SimpleNamespace:
    return SimpleNamespace(module="/module.so", slot=0)


def _missing_point_fact() -> str:
    return (
        'UAF:{"schema":1,"probe":"derive","event":"SETUP_ATTRIBUTE",'
        '"attribute":{"name":"CKA_EC_POINT","id":385},"state":"missing",'
        '"value_type":null,"value_len":null}\n'
    )


def _setup_fact(state: str, **fields: object) -> str:
    payload = {
        "schema": 1,
        "probe": "derive",
        "event": "SETUP_ATTRIBUTE",
        "attribute": {"name": "CKA_EC_POINT", "id": 385},
        "state": state,
        **fields,
    }
    return f"UAF:{json.dumps(payload, separators=(',', ':'))}\n"


def test_derive_missing_peer_point_is_a_structured_not_operational_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid omitted peer point is reported without inventing an attribute CKR."""
    monkeypatch.setattr(
        uaf,
        "run_probe",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=_missing_point_fact(),
            stderr="",
        ),
    )
    session = SimpleNamespace(has_mechanism=lambda _name: True)

    with pytest.raises(pytest.xfail.Exception):
        uaf.TestDeriveOperationStateUAF().test_derive_after_destroy_does_not_crash(
            session,
            _config(),
        )

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "not_operational"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.actual_ckr is None


@pytest.mark.parametrize(
    ("state", "fields"),
    [
        ("unusable", {"value_type": "NoneType", "value_len": None}),
        ("malformed_encoding", {"diagnostic": "noncanonical DER"}),
    ],
)
def test_derive_setup_fact_is_metadata_not_operational_without_ckr(
    state: str, fields: dict[str, object]
) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _check(_setup_fact(state, **fields))

    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.actual_ckr is None


def test_derive_invalid_point_fact_is_a_hard_crypto_failure() -> None:
    with pytest.raises(pytest.fail.Exception, match="invalid point"):
        _check(_setup_fact("invalid_point", diagnostic="not on secp256r1"))

    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.actual_ckr is None


def test_derive_read_error_preserves_standard_rv_as_metadata_xfail() -> None:
    with pytest.raises(pytest.xfail.Exception):
        _check(_setup_fact("read_error", operation="C_GetAttributeValue", rv=0x12))

    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None


def test_derive_read_error_undefined_rv_is_metadata_failure() -> None:
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        _check(_setup_fact("read_error", operation="C_GetAttributeValue", rv=0x7F))

    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.actual_ckr == "0x0000007f"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None


def test_derive_vendor_read_error_is_visible_not_operational() -> None:
    with pytest.raises(pytest.xfail.Exception):
        _check(_setup_fact("read_error", operation="C_GetAttributeValue", rv=0x80000042))

    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.actual_ckr == "0x80000042"


@pytest.mark.parametrize(
    ("state", "fields"),
    [
        ("missing", {"value_type": None, "value_len": None}),
        ("unusable", {"value_type": "NoneType", "value_len": None}),
        ("malformed_encoding", {"diagnostic": "noncanonical DER"}),
        ("invalid_point", {"diagnostic": "not on secp256r1"}),
        ("read_error", {"operation": "C_GetAttributeValue", "rv": 0x12}),
        ("read_error", {"operation": "C_GetAttributeValue", "rv": 0x7F}),
    ],
)
def test_derive_setup_fact_readback_records_do_not_inherit_stale_mechanism(
    state: str, fields: dict[str, object]
) -> None:
    """Every setup-readback branch is mechanism-free, even with an active stale op."""
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    fact = uaf._parse_uaf_fact(_setup_fact(state, **fields).rstrip())

    record = uaf._uaf_record_setup_fact("derive protocol", fact)

    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    assert record.detail is not None
    assert record.detail["dependency"] == "C_DeriveKey"


@pytest.mark.parametrize(
    "fact",
    [
        _setup_fact("missing", value_type="wrong", value_len=None),
        _setup_fact("unusable", value_type=True, value_len=None),
        _setup_fact("unusable", value_type="bytes", value_len=True),
        _setup_fact("read_error", operation="C_GetAttributeValue", rv=0),
        _setup_fact("read_error", operation="C_GetAttributeValue", rv=True),
        _setup_fact(
            "read_error",
            operation="C_GetAttributeValue",
            rv=1 << (8 * ctypes.sizeof(ctypes.c_ulong)),
        ),
        _setup_fact("malformed_encoding", diagnostic=""),
        _setup_fact("invalid_point", diagnostic="x" * 257),
    ],
)
def test_derive_setup_fact_union_rejects_wrong_types_and_bounds(fact: str) -> None:
    with pytest.raises(pytest.fail.Exception, match="malformed UAF protocol"):
        _check(fact)

    assert [item.reason for item in C.get_records()] == ["harness_error"]


def test_derive_setup_fact_rejects_duplicate_keys_and_unknown_fields() -> None:
    duplicate = (
        'UAF:{"schema":1,"probe":"derive","event":"SETUP_ATTRIBUTE",'
        '"attribute":{"name":"CKA_EC_POINT","id":385},"state":"missing",'
        '"value_type":null,"value_len":null,"value_len":null}\n'
    )
    unknown = (
        _setup_fact("missing")[:-1].replace('"value_len":null}', '"value_len":null,"extra":0}')
        + "\n"
    )
    for output in (duplicate, unknown):
        with pytest.raises(pytest.fail.Exception, match="malformed UAF protocol"):
            _check(output)
        assert [item.reason for item in C.get_records()] == ["harness_error"]
        C.clear()


def test_derive_setup_fact_rejects_wrong_identity_fields() -> None:
    for key, value in (("schema", 2), ("probe", "other"), ("event", "attribute")):
        payload = {
            "schema": 1,
            "probe": "derive",
            "event": "SETUP_ATTRIBUTE",
            "attribute": {"name": "CKA_EC_POINT", "id": 385},
            "state": "missing",
            "value_type": None,
            "value_len": None,
        }
        payload[key] = value
        output = f"UAF:{json.dumps(payload, separators=(',', ':'))}\n"
        with pytest.raises(pytest.fail.Exception, match="malformed UAF protocol"):
            _check(output)
        assert [item.reason for item in C.get_records()] == ["harness_error"]
        C.clear()


def test_derive_setup_fact_is_bounded_and_does_not_print_raw_point_material(
    capsys: pytest.CaptureFixture[str],
) -> None:
    worst_case = ('😀"\\\n' * 100) + ("x" * 256)
    facts.emit_missing_attribute(
        CKA_EC_POINT,
        protocol="UAF",
        context="derive",
        state="malformed_encoding",
        diagnostic=worst_case,
    )
    output = capsys.readouterr().out
    encoded_payload = output.removeprefix("UAF:").strip()
    payload = json.loads(encoded_payload)
    assert len(encoded_payload.encode("utf-8")) <= 1024
    assert 0 < len(payload["diagnostic"]) <= 256
    assert "04" * 32 not in output

    with pytest.raises(pytest.xfail.Exception):
        _check(output)
    detail = C.get_records()[0].detail
    assert detail is not None
    assert detail["diagnostic"] == payload["diagnostic"]


def _target(destroy: int, derive: int) -> str:
    return f"DESTROY_RV:0x{destroy:08x}\nDERIVE_RV:0x{derive:08x}\n"


def _digest_target(destroy: int, digest_key: int) -> str:
    return f"DESTROY_RV:0x{destroy:08x}\nDIGEST_KEY_RV:0x{digest_key:08x}\n"


def _check(output: str, *, rc: int = 0, stderr: str = "") -> None:
    uaf._check_derive_probe(rc, output, stderr, context="derive protocol")


def _check_digest(output: str, *, rc: int = 0, stderr: str = "") -> None:
    uaf._check_digest_probe(rc, output, stderr, context="digest protocol")


def test_digest_destroy_ok_key_handle_invalid_is_spec_pass() -> None:
    _check_digest(_digest_target(0, int(CKR_KEY_HANDLE_INVALID)))
    assert C.get_records() == []


def test_digest_destroy_ok_digest_key_ok_is_lifecycle_failure() -> None:
    with pytest.raises(pytest.fail.Exception, match="accepted a destroyed"):
        _check_digest(_digest_target(0, 0))

    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.operation == "C_DigestKey"
    assert record.mechanism == "CKM_SHA256"
    assert record.actual_ckr == "CKR_OK"


def test_digest_destroy_ok_other_reject_is_nonspec_xfail() -> None:
    with pytest.raises(pytest.xfail.Exception):
        _check_digest(_digest_target(0, int(CKR_OBJECT_HANDLE_INVALID)))

    record = C.get_records()[0]
    assert record.reason == "nonspec_reject"
    assert record.actual_ckr == "CKR_OBJECT_HANDLE_INVALID"
    assert record.detail == {
        "protocol": "UAF",
        "destroy_rv": 0,
        "digest_key_rv": int(CKR_OBJECT_HANDLE_INVALID),
    }


def test_digest_destroy_refusal_retains_target_as_context() -> None:
    target_rv = 0x80000042
    with pytest.raises(pytest.xfail.Exception):
        _check_digest(_digest_target(int(CKR_OBJECT_HANDLE_INVALID), target_rv))

    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_DestroyObject"
    assert record.actual_ckr == "CKR_OBJECT_HANDLE_INVALID"
    assert record.detail == {
        "protocol": "UAF",
        "destroy_rv": int(CKR_OBJECT_HANDLE_INVALID),
        "digest_key_rv": target_rv,
    }


def test_digest_destroy_refusal_with_ok_target_has_no_stale_handle_conclusion() -> None:
    with pytest.raises(pytest.xfail.Exception):
        _check_digest(_digest_target(int(CKR_OBJECT_HANDLE_INVALID), 0))

    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.actual_ckr == "CKR_OBJECT_HANDLE_INVALID"
    assert record.detail is not None
    assert record.detail["digest_key_rv"] == 0


@pytest.mark.parametrize(
    "output",
    [
        "DERIVE_RV:0x00000082\n" + _digest_target(0, int(CKR_KEY_HANDLE_INVALID)),
        _digest_target(0, int(CKR_KEY_HANDLE_INVALID)) + "DERIVE_RV:0x00000082\n",
    ],
)
def test_digest_reserved_derive_marker_invalidates_causal_prefix(output: str) -> None:
    with pytest.raises(pytest.fail.Exception, match="malformed UAF protocol"):
        _check_digest(output)

    assert [item.reason for item in C.get_records()] == ["harness_error"]


@pytest.mark.parametrize(
    "output",
    [
        "DIGEST_KEY_RV:0x00000082\n" + _target(0, int(CKR_KEY_HANDLE_INVALID)),
        _target(0, int(CKR_KEY_HANDLE_INVALID)) + "DIGEST_KEY_RV:0x00000082\n",
    ],
)
def test_derive_reserved_digest_marker_invalidates_causal_prefix(output: str) -> None:
    with pytest.raises(pytest.fail.Exception, match="malformed UAF protocol"):
        _check(output)

    assert [item.reason for item in C.get_records()] == ["harness_error"]


@pytest.mark.parametrize(
    ("operation", "output"),
    [
        ("destroy", _digest_target(0x0000007F, int(CKR_KEY_HANDLE_INVALID))),
        ("digest", _digest_target(0, 0x0000007F)),
    ],
)
def test_digest_undefined_rv_is_metadata_failure(operation: str, output: str) -> None:
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        _check_digest(output)

    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.actual_ckr == "0x0000007f"
    assert record.operation == ("C_DestroyObject" if operation == "destroy" else "C_DigestKey")
    assert record.detail == {
        "protocol": "UAF",
        "destroy_rv": (0x0000007F if operation == "destroy" else 0),
        "digest_key_rv": (int(CKR_KEY_HANDLE_INVALID) if operation == "destroy" else 0x0000007F),
        "undefined_rv": 0x0000007F,
    }


def test_digest_vendor_target_is_nonspec_xfail() -> None:
    with pytest.raises(pytest.xfail.Exception):
        _check_digest(_digest_target(0, 0x80000042))

    record = C.get_records()[0]
    assert record.reason == "nonspec_reject"
    assert record.actual_ckr == "0x80000042"


@pytest.mark.parametrize(
    "output",
    [
        "",
        "DIGEST_KEY_RV:0x00000060\nDESTROY_RV:0x00000000\n",
        "DESTROY_RV:0x00000000\n",
        "DESTROY_RV:not-a-rv\nDIGEST_KEY_RV:0x00000060\n",
        "DESTROY_RV:0x00000000\nDIGEST_KEY_RV:0x00000060\nDIGEST_KEY_RV:0x00000060\n",
        "SETUP_XFAIL:setup\nDESTROY_RV:0x00000000\nDIGEST_KEY_RV:0x00000060\n",
    ],
)
def test_digest_normal_exit_protocol_errors(output: str) -> None:
    with pytest.raises(pytest.fail.Exception, match="malformed UAF protocol"):
        _check_digest(output)


def test_digest_setup_xfail_is_the_only_other_valid_branch() -> None:
    with pytest.raises(pytest.xfail.Exception):
        _check_digest("SETUP_XFAIL:digest key setup rejected\n")

    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.actual_ckr is None


def test_digest_destroy_prefix_crash_retains_structured_measurement() -> None:
    with pytest.raises(pytest.fail.Exception, match="module crashed"):
        _check_digest("DESTROY_RV:0x00000000\n", rc=-11)

    crash = C.get_records()[0]
    assert crash.detail is not None
    assert crash.detail["parsed_measurement"] == {
        "destroy_rv": 0,
        "digest_key_rv": None,
    }


def test_digest_valid_pair_survives_late_protocol_corruption() -> None:
    with pytest.raises(pytest.fail.Exception, match="accepted a destroyed"):
        _check_digest(_digest_target(0, 0) + "SETUP_XFAIL:late setup\n")

    assert [item.reason for item in C.get_records()] == [
        "self_contradiction",
        "harness_error",
    ]


def test_digest_hard_contradiction_precedes_positive_exit_and_capability_skip() -> None:
    with pytest.raises(pytest.fail.Exception, match="accepted a destroyed"):
        _check_digest(
            _digest_target(0, 0),
            rc=1,
            stderr="AttributeError: C_DigestKey not available in this module\n",
        )

    assert [item.reason for item in C.get_records()] == ["self_contradiction"]


def test_digest_capability_skip_is_preserved_without_higher_priority_evidence() -> None:
    assert_skips(
        _check_digest,
        "",
        rc=1,
        stderr="AttributeError: C_DigestKey not available in this module\n",
    )

    assert C.get_records() == []


def test_digest_provider_xfail_precedes_capability_skip() -> None:
    with pytest.raises(pytest.xfail.Exception):
        _check_digest(
            _digest_target(0, int(CKR_OBJECT_HANDLE_INVALID)),
            rc=1,
            stderr="AttributeError: C_DigestKey not available in this module\n",
        )

    assert C.get_records()[0].reason == "nonspec_reject"


def test_init_bound_sign_allows_snapshot_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        uaf,
        "run_probe",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="DESTROY_RV:0x00000000\nSIGN_RV:0x00000000\n",
            stderr="",
        ),
    )
    session = SimpleNamespace(has_mechanism=lambda _name: True)

    uaf.TestSignOperationStateUAF().test_sign_after_destroy_does_not_crash(session, _config())

    assert C.get_records() == []


def test_digest_parent_wires_direct_handle_checker(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[int, str, str, str]] = []

    def check(
        rc: int,
        stdout: str,
        stderr: str,
        *,
        context: str,
    ) -> None:
        calls.append((rc, stdout, stderr, context))

    monkeypatch.setattr(uaf, "_check_digest_probe", check)
    monkeypatch.setattr(
        uaf,
        "run_probe",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="DESTROY_RV:0x00000000\nDIGEST_KEY_RV:0x00000082\n",
            stderr="",
        ),
    )
    session = SimpleNamespace(has_mechanism=lambda _name: True)

    uaf.TestDigestOperationStateUAF().test_digest_key_after_destroy_does_not_crash(
        session,
        _config(),
    )

    assert calls == [
        (
            0,
            "DESTROY_RV:0x00000000\nDIGEST_KEY_RV:0x00000082\n",
            "",
            "C_DigestKey on destroyed key handle (use-after-destroy)",
        )
    ]


def test_derive_missing_fact_plus_crash_retains_fact_before_crash() -> None:
    with pytest.raises(pytest.fail.Exception, match="module crashed"):
        _check(_missing_point_fact(), rc=-11)

    records = C.get_records()
    assert [item.reason for item in records] == ["not_operational", "crash"]
    assert records[0].actual_ckr is None
    assert records[0].operation == "C_GetAttributeValue"
    assert records[1].detail is not None
    # rc=-11 renders as a POSIX signal everywhere except Windows, where the
    # 0xFFFFFFF5 NTSTATUS form classifies as an exception.
    expected_kind = "exception" if sys.platform == "win32" else "signal"
    assert records[1].detail["termination"]["kind"] == expected_kind


def test_derive_unusable_fact_plus_timeout_retains_fact_before_timeout() -> None:
    output = _setup_fact("unusable", value_type="NoneType", value_len=None)
    with pytest.raises(pytest.fail.Exception, match="module hung"):
        _check(output, rc=1, stderr=SUBPROCESS_TIMEOUT_MARKER)

    records = C.get_records()
    assert [item.reason for item in records] == ["not_operational", "crash"]
    assert records[0].operation == "C_GetAttributeValue"
    assert records[1].detail is not None
    assert records[1].detail["termination"]["kind"] == "timeout"


def test_derive_malformed_encoding_fact_plus_late_corruption_retains_fact() -> None:
    output = _setup_fact("malformed_encoding", diagnostic="noncanonical DER") + "UAF:not-json\n"
    with pytest.raises(pytest.fail.Exception, match="malformed UAF protocol"):
        _check(output)

    assert [item.reason for item in C.get_records()] == ["not_operational", "harness_error"]


def test_late_setup_marker_preserves_target_lifecycle_before_protocol_error() -> None:
    with pytest.raises(pytest.fail.Exception, match="accepted a destroyed"):
        _check(_target(0, 0) + "SETUP_XFAIL:late setup\n")

    assert [item.reason for item in C.get_records()] == [
        "self_contradiction",
        "harness_error",
    ]


def test_destroy_refusal_prefix_survives_mixed_protocol_and_crash() -> None:
    output = "DESTROY_RV:0x00000082\nUAF:not-json\n"
    with pytest.raises(pytest.fail.Exception, match="module crashed"):
        _check(output, rc=-11)

    records = C.get_records()
    assert [item.reason for item in records] == [
        "not_operational",
        "harness_error",
        "crash",
    ]
    assert records[0].actual_ckr == "CKR_OBJECT_HANDLE_INVALID"


def test_destroy_prefix_crash_retains_structured_measurement() -> None:
    with pytest.raises(pytest.fail.Exception, match="module crashed"):
        _check("DESTROY_RV:0x00000000\n", rc=-11)

    crash = C.get_records()[0]
    assert crash.detail is not None
    assert crash.detail["parsed_measurement"] == {
        "destroy_rv": 0,
        "derive_rv": None,
    }


def test_duplicate_missing_facts_retain_first_fact_before_crash() -> None:
    output = _missing_point_fact() + _missing_point_fact()
    with pytest.raises(pytest.fail.Exception, match="module crashed"):
        _check(output, rc=-11)

    records = C.get_records()
    assert [item.reason for item in records] == [
        "not_operational",
        "harness_error",
        "crash",
    ]
    assert records[0].operation == "C_GetAttributeValue"


def test_setup_prefix_retain_evidence_after_late_malformed_marker_and_crash() -> None:
    output = "SETUP_XFAIL:EC keypair generation rejected\nDERIVE_RV:not-a-rv\n"
    with pytest.raises(pytest.fail.Exception, match="module crashed"):
        _check(output, rc=-11)

    records = C.get_records()
    assert [item.reason for item in records] == [
        "not_operational",
        "harness_error",
        "crash",
    ]
    assert records[0].detail == {
        "protocol": "UAF",
        "protocol_marker": "SETUP_XFAIL",
    }


def test_derive_prefix_crash_retains_structured_measurement() -> None:
    derive_rv = int(CKR_KEY_HANDLE_INVALID)
    with pytest.raises(pytest.fail.Exception, match="module crashed"):
        _check(_target(0, derive_rv), rc=-11)

    crash = C.get_records()[0]
    assert crash.detail is not None
    assert crash.detail["parsed_measurement"] == {
        "destroy_rv": 0,
        "derive_rv": derive_rv,
    }


def test_hard_provider_contradiction_precedes_positive_exit_disposition() -> None:
    """Provider evidence parsed from the child's own output outranks how it exited.

    The process disposition describes how the child ENDED; the contradiction describes
    what the MODULE did. Both are retained, and the module's is raised.
    """
    with pytest.raises(pytest.fail.Exception, match="accepted a destroyed"):
        _check(_target(0, 0), rc=2)

    assert [item.reason for item in C.get_records()] == [
        "self_contradiction",
        "probe_incomplete",
    ]


def test_hard_provider_contradiction_precedes_capability_skip() -> None:
    with pytest.raises(pytest.fail.Exception, match="accepted a destroyed"):
        _check(
            _target(0, 0),
            rc=1,
            stderr="AttributeError: C_DeriveKey not available in this module\n",
        )

    assert [item.reason for item in C.get_records()] == ["self_contradiction"]


def test_protocol_error_precedes_capability_skip() -> None:
    with pytest.raises(pytest.fail.Exception, match="malformed UAF protocol"):
        _check(
            "UAF:not-json\n",
            rc=1,
            stderr="AttributeError: C_DeriveKey not available in this module\n",
        )

    assert [item.reason for item in C.get_records()] == ["harness_error"]


def test_capability_skip_is_preserved_without_higher_priority_evidence() -> None:
    assert_skips(
        _check,
        _target(0, int(CKR_KEY_HANDLE_INVALID)),
        rc=1,
        stderr="AttributeError: C_DeriveKey not available in this module\n",
    )

    assert C.get_records() == []


@pytest.mark.parametrize(
    "value",
    [
        '{"schema":true,"probe":"derive","event":"SETUP_ATTRIBUTE",'
        '"attribute":{"name":"CKA_EC_POINT","id":385},"state":"missing",'
        '"value_type":null,"value_len":null}',
        '{"schema":1,"probe":"derive","event":"SETUP_ATTRIBUTE",'
        '"attribute":{"name":"CKA_EC_POINT","id":true},"state":"missing",'
        '"value_type":null,"value_len":null}',
        '{"schema":1,"probe":"derive","event":"SETUP_ATTRIBUTE",'
        '"attribute":{"name":"CKA_EC_POINT","id":385},"state":"missing",'
        '"value_type":null,"value_len":null,"extra":0}',
        '{"schema":1,"probe":"derive","event":"SETUP_ATTRIBUTE",'
        '"attribute":{"name":"CKA_EC_POINT","id":385},"state":"present",'
        '"value_type":null,"value_len":null}',
        '{"schema":1,"probe":"derive","event":"SETUP_ATTRIBUTE",'
        '"attribute":{"name":"CKA_EC_POINT","id":385},"state":"missing",'
        '"value_type":null,"value_len":0}',
        '{"schema":1,"probe":"derive","event":"SETUP_ATTRIBUTE",'
        '"attribute":{"name":"CKA_EC_POINT","id":385},"state":"missing",'
        '"value_type":null,"value_len":null,"schema":1}',
    ],
)
def test_malformed_or_duplicate_missing_fact_is_harness_error(value: str) -> None:
    with pytest.raises(pytest.fail.Exception, match="malformed UAF protocol"):
        _check(f"UAF:{value}\n")

    records = C.get_records()
    assert [item.reason for item in records] == ["harness_error"]


def test_missing_fact_mixed_with_target_rvs_keeps_fact_and_reports_harness() -> None:
    with pytest.raises(pytest.fail.Exception, match="malformed UAF protocol"):
        _check(_missing_point_fact() + _target(0, int(CKR_KEY_HANDLE_INVALID)))

    records = C.get_records()
    assert [item.reason for item in records] == ["not_operational", "harness_error"]


@pytest.mark.parametrize(
    "output",
    [
        "",
        "DERIVE_RV:0x00000060\nDESTROY_RV:0x00000000\n",
        "DESTROY_RV:0x00000000\n",
        "DESTROY_RV:0x00000000\nDERIVE_RV:0x00000060\nDERIVE_RV:0x00000060\n",
        "SETUP_XFAIL:setup\nDESTROY_RV:0x00000000\nDERIVE_RV:0x00000060\n",
    ],
)
def test_normal_exit_order_and_cardinality_are_harness_errors(output: str) -> None:
    with pytest.raises(pytest.fail.Exception, match="malformed UAF protocol"):
        _check(output)

    assert [item.reason for item in C.get_records() if item.reason == "harness_error"]


def test_setup_xfail_is_the_only_valid_setup_branch() -> None:
    with pytest.raises(pytest.xfail.Exception):
        _check("SETUP_XFAIL:EC keypair generation rejected\n")

    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.actual_ckr is None


def test_destroy_ok_derive_key_handle_invalid_is_spec_pass() -> None:
    _check(_target(0, int(CKR_KEY_HANDLE_INVALID)))
    assert C.get_records() == []


def test_destroy_ok_derive_ok_is_lifecycle_failure() -> None:
    with pytest.raises(pytest.fail.Exception, match="accepted a destroyed"):
        _check(_target(0, 0))

    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "lifecycle"
    assert record.actual_ckr == "CKR_OK"


def test_destroy_ok_derive_object_handle_invalid_is_nonspec_xfail() -> None:
    with pytest.raises(pytest.xfail.Exception):
        _check(_target(0, int(CKR_OBJECT_HANDLE_INVALID)))

    record = C.get_records()[0]
    assert record.reason == "nonspec_reject"
    assert record.actual_ckr == "CKR_OBJECT_HANDLE_INVALID"


def test_destroy_refusal_removes_stale_handle_conclusion() -> None:
    with pytest.raises(pytest.xfail.Exception):
        _check(_target(int(CKR_OBJECT_HANDLE_INVALID), 0))

    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_DestroyObject"
    assert record.actual_ckr == "CKR_OBJECT_HANDLE_INVALID"


@pytest.mark.parametrize("operation", ["destroy", "derive"])
def test_undefined_target_rv_is_metadata_failure(operation: str) -> None:
    output = _target(0x0000007F, int(CKR_KEY_HANDLE_INVALID))
    if operation == "derive":
        output = _target(0, 0x0000007F)

    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        _check(output)

    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.actual_ckr == "0x0000007f"
    assert record.detail == {
        "protocol": "UAF",
        "destroy_rv": (0x0000007F if operation == "destroy" else 0),
        "derive_rv": (int(CKR_KEY_HANDLE_INVALID) if operation == "destroy" else 0x0000007F),
        "undefined_rv": 0x0000007F,
    }


def test_vendor_defined_derive_rv_is_nonspec_xfail() -> None:
    with pytest.raises(pytest.xfail.Exception):
        _check(_target(0, 0x80000042))

    assert C.get_records()[0].reason == "nonspec_reject"


def test_valid_native_width_rv_is_not_a_protocol_error() -> None:
    if ctypes.sizeof(ctypes.c_ulong) <= 4:
        pytest.skip("native CK_RV width does not exceed 32 bits")

    derive_rv = 0x1_0000_0000
    with pytest.raises(pytest.xfail.Exception):
        _check(f"DESTROY_RV:0x00000000\nDERIVE_RV:0x{derive_rv:x}\n")

    record = C.get_records()[0]
    assert record.reason == "nonspec_reject"
    assert record.actual_ckr == "0x100000000"


def test_true_overwide_rv_is_a_protocol_harness_error_on_all_native_widths() -> None:
    max_digits = 2 * ctypes.sizeof(ctypes.c_ulong)
    output = f"DESTROY_RV:0x{'0' * (max_digits + 1)}\nDERIVE_RV:0x00000082\n"
    with pytest.raises(pytest.fail.Exception, match="malformed DESTROY_RV"):
        _check(output)

    assert [item.reason for item in C.get_records()] == ["harness_error"]


def test_representable_overwide_zero_padding_is_noncanonical() -> None:
    if ctypes.sizeof(ctypes.c_ulong) <= 4:
        pytest.skip("native CK_RV width does not represent over-wide RV text")

    output = "DESTROY_RV:0x00000000\nDERIVE_RV:0x0000000000000082\n"
    with pytest.raises(pytest.fail.Exception, match="non-canonical DERIVE_RV"):
        _check(output)

    assert [item.reason for item in C.get_records()] == ["harness_error"]


def test_abnormal_exit_accepts_valid_prefix_without_terminal_marker() -> None:
    with pytest.raises(pytest.fail.Exception, match="module crashed"):
        _check("DESTROY_RV:0x00000082\n", rc=-11)

    records = C.get_records()
    assert [item.reason for item in records] == ["not_operational", "crash"]
    assert records[0].actual_ckr == "CKR_OBJECT_HANDLE_INVALID"


def test_hard_provider_contradiction_precedes_cleanup_harness_error() -> None:
    with pytest.raises(pytest.fail.Exception, match="accepted a destroyed"):
        _check(_target(0, 0) + "HARNESS_ERROR:cleanup failed\n")

    assert [item.reason for item in C.get_records()] == [
        "self_contradiction",
        "harness_error",
    ]


def test_derive_peer_point_helper_emits_exact_fact_and_distinguishes_presence(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(probe, "read_attributes", lambda *_args: {})
    present, value = probe._read_derive_peer_point(object(), 1, 2)
    assert (present, value) == (False, None)
    assert capsys.readouterr().out == _missing_point_fact()

    for candidate in (None, b"", False, 0, "bad"):
        monkeypatch.setattr(
            probe,
            "read_attributes",
            lambda *_args, value=candidate: {CKA_EC_POINT: value},
        )
        present, value = probe._read_derive_peer_point(object(), 1, 2)
        assert present is True
        assert value is candidate
    assert capsys.readouterr().out == ""


def test_derive_child_missing_peer_point_cleans_all_objects_and_skips_derive(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, int]] = []

    class Raw:
        def C_DestroyObject(self, _session: int, handle: int) -> int:  # noqa: N802
            calls.append(("destroy", handle))
            return 0

        def C_DeriveKey(self, *_args: object) -> int:  # noqa: N802
            calls.append(("derive", 0))
            raise AssertionError("derive must not run after a missing peer point")

    pairs = iter(((11, 12), (13, 14)))
    monkeypatch.setattr(probe, "gen_ec_keypair", lambda *_args, **_kwargs: next(pairs))
    monkeypatch.setattr(probe, "read_attributes", lambda *_args: {})
    cleanups: list[str] = []
    ctx = SimpleNamespace(
        raw=Raw(),
        sh=7,
        cleanup=lambda: cleanups.append("cleanup"),
    )

    probe._run_derive(cast(ProbeContext, ctx), {})

    assert calls == [("destroy", 11), ("destroy", 12), ("destroy", 13), ("destroy", 14)]
    assert cleanups == ["cleanup"]
    assert capsys.readouterr().out == _missing_point_fact()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, {"state": "unusable", "value_type": "NoneType", "value_len": None}),
        (b"", {"state": "unusable", "value_type": "bytes", "value_len": 0}),
        (False, {"state": "unusable", "value_type": "bool", "value_len": None}),
        (0, {"state": "unusable", "value_type": "int", "value_len": None}),
        ("bad", {"state": "unusable", "value_type": "str", "value_len": None}),
    ],
)
def test_derive_child_unusable_peer_point_cleans_all_objects_and_skips_derive(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    value: object,
    expected: dict[str, object],
) -> None:
    calls: list[tuple[str, int]] = []

    class Raw:
        def C_DestroyObject(self, _session: int, handle: int) -> int:  # noqa: N802
            calls.append(("destroy", handle))
            return 0

        def C_DeriveKey(self, *_args: object) -> int:  # noqa: N802
            calls.append(("derive", 0))
            raise AssertionError("derive must not run after an unusable peer point")

    pairs = iter(((11, 12), (13, 14)))
    monkeypatch.setattr(probe, "gen_ec_keypair", lambda *_args, **_kwargs: next(pairs))
    monkeypatch.setattr(probe, "read_attributes", lambda *_args: {CKA_EC_POINT: value})
    cleanups: list[str] = []
    ctx = SimpleNamespace(raw=Raw(), sh=7, cleanup=lambda: cleanups.append("cleanup"))

    probe._run_derive(cast(ProbeContext, ctx), {})

    assert calls == [("destroy", 11), ("destroy", 12), ("destroy", 13), ("destroy", 14)]
    assert cleanups == ["cleanup"]
    payload = json.loads(capsys.readouterr().out.removeprefix("UAF:").strip())
    assert payload == {
        "schema": 1,
        "probe": "derive",
        "event": "SETUP_ATTRIBUTE",
        "attribute": {"name": "CKA_EC_POINT", "id": 385},
        **expected,
    }


def test_derive_child_attribute_ckr_is_a_bounded_read_error_and_cleans_all_objects(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, int]] = []

    class Raw:
        def C_DestroyObject(self, _session: int, handle: int) -> int:  # noqa: N802
            calls.append(("destroy", handle))
            return 0

        def C_DeriveKey(self, *_args: object) -> int:  # noqa: N802
            calls.append(("derive", 0))
            raise AssertionError("derive must not run after an attribute read error")

    pairs = iter(((11, 12), (13, 14)))
    monkeypatch.setattr(probe, "gen_ec_keypair", lambda *_args, **_kwargs: next(pairs))

    def read_error(*_args: object) -> dict[int, object]:
        raise CkrAssertionError("reader rejected", 0x10)

    monkeypatch.setattr(probe, "read_attributes", read_error)
    cleanups: list[str] = []
    ctx = SimpleNamespace(raw=Raw(), sh=7, cleanup=lambda: cleanups.append("cleanup"))

    probe._run_derive(cast(ProbeContext, ctx), {})

    assert calls == [("destroy", 11), ("destroy", 12), ("destroy", 13), ("destroy", 14)]
    assert cleanups == ["cleanup"]
    assert json.loads(capsys.readouterr().out.removeprefix("UAF:").strip()) == {
        "schema": 1,
        "probe": "derive",
        "event": "SETUP_ATTRIBUTE",
        "attribute": {"name": "CKA_EC_POINT", "id": 385},
        "state": "read_error",
        "operation": "C_GetAttributeValue",
        "rv": 0x10,
    }


@pytest.mark.parametrize(
    ("point_kind", "private_value"),
    [("raw", 30), ("wrapped_compressed", 7), ("wrapped_uncompressed", 8)],
)
def test_derive_child_passes_only_normalized_sec1_to_ecdh(
    monkeypatch: pytest.MonkeyPatch,
    point_kind: str,
    private_value: int,
) -> None:
    raw_point = ec.derive_private_key(private_value, ec.SECP256R1()).public_key()
    sec1 = raw_point.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint
        if point_kind == "wrapped_compressed"
        else serialization.PublicFormat.UncompressedPoint,
    )
    value = sec1
    if point_kind.startswith("wrapped"):
        value = b"\x04" + bytes([len(sec1)]) + sec1

    calls: list[tuple[str, object]] = []

    class Raw:
        def C_DestroyObject(self, _session: int, handle: int) -> int:  # noqa: N802
            calls.append(("destroy", handle))
            return 0

        def C_DeriveKey(self, _session: int, mech: object, *_args: object) -> int:  # noqa: N802
            calls.append(("derive", mech))
            return int(CKR_KEY_HANDLE_INVALID)

    class Packed:
        def byref(self) -> None:
            return None

    packed: list[bytes] = []
    pairs: Iterator[tuple[int, int]] = iter(((11, 12), (13, 14)))

    def pack(_mechanism: object, *, kdf: int, public_data: bytes) -> Packed:
        del kdf
        packed.append(public_data)
        return Packed()

    monkeypatch.setattr(probe, "gen_ec_keypair", lambda *_args, **_kwargs: next(pairs))
    monkeypatch.setattr(probe, "read_attributes", lambda *_args: {CKA_EC_POINT: value})
    monkeypatch.setattr(probe, "mech_ecdh", pack)
    ctx = SimpleNamespace(raw=Raw(), sh=7, cleanup=lambda: None)

    probe._run_derive(cast(ProbeContext, ctx), {})

    if point_kind == "raw":
        assert sec1[:2] == b"\x04\x40"
    assert packed == [sec1]
    assert [kind for kind, _value in calls] == [
        "destroy",
        "destroy",
        "destroy",
        "destroy",
        "derive",
    ]


@pytest.mark.parametrize(
    ("value", "state"),
    [
        (b"\x02" + b"\x00" * 32, "malformed_encoding"),
        (b"\x04\x81\x20" + b"\x02" + b"\x00" * 32, "malformed_encoding"),
        (b"\x04\x21" + b"\x02" + b"\x00" * 32 + b"\x00", "malformed_encoding"),
        (
            bytes(
                bytearray(
                    ec.derive_private_key(19, ec.SECP256R1())
                    .public_key()
                    .public_bytes(
                        serialization.Encoding.X962,
                        serialization.PublicFormat.UncompressedPoint,
                    )
                )[:-1]
                + bytes(
                    [
                        ec.derive_private_key(19, ec.SECP256R1())
                        .public_key()
                        .public_bytes(
                            serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint,
                        )[-1]
                        ^ 1,
                    ]
                )
            ),
            "invalid_point",
        ),
        (
            b"\x04"
            + bytes(
                [
                    len(
                        ec.derive_private_key(13, ec.SECP384R1())
                        .public_key()
                        .public_bytes(
                            serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint,
                        )
                    )
                ]
            )
            + ec.derive_private_key(13, ec.SECP384R1())
            .public_key()
            .public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            ),
            "invalid_point",
        ),
    ],
    ids=["raw-compressed", "noncanonical-der", "trailing-der", "off-curve", "wrong-curve"],
)
def test_derive_child_invalid_peer_point_cleans_all_objects_and_skips_stale_handle(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    value: bytes,
    state: str,
) -> None:
    calls: list[tuple[str, int]] = []

    class Raw:
        def C_DestroyObject(self, _session: int, handle: int) -> int:  # noqa: N802
            calls.append(("destroy", handle))
            return 0

        def C_DeriveKey(self, *_args: object) -> int:  # noqa: N802
            calls.append(("derive", 0))
            raise AssertionError("derive must not run after invalid peer point setup")

    pairs = iter(((11, 12), (13, 14)))
    monkeypatch.setattr(probe, "gen_ec_keypair", lambda *_args, **_kwargs: next(pairs))
    monkeypatch.setattr(probe, "read_attributes", lambda *_args: {CKA_EC_POINT: value})
    ctx = SimpleNamespace(raw=Raw(), sh=7, cleanup=lambda: None)

    probe._run_derive(cast(ProbeContext, ctx), {})

    assert calls == [("destroy", 11), ("destroy", 12), ("destroy", 13), ("destroy", 14)]
    payload = json.loads(capsys.readouterr().out.removeprefix("UAF:").strip())
    assert payload["state"] == state
    assert len(payload["diagnostic"]) <= 256


def test_derive_child_native_cleanup_fault_does_not_hide_flushed_fact(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Raw:
        def C_DestroyObject(self, _session: int, _handle: int) -> int:  # noqa: N802
            raise OSError("provider cleanup fault")

    pairs = iter(((11, 12), (13, 14)))
    monkeypatch.setattr(probe, "gen_ec_keypair", lambda *_args, **_kwargs: next(pairs))
    monkeypatch.setattr(probe, "read_attributes", lambda *_args: {})
    ctx = SimpleNamespace(raw=Raw(), sh=7, cleanup=lambda: None)

    with pytest.raises(OSError, match="provider cleanup fault"):
        probe._run_derive(cast(ProbeContext, ctx), {})

    assert capsys.readouterr().out == _missing_point_fact()


def test_derive_child_cleanup_attempts_every_handle_and_prefers_access_violation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    access_violation = OSError("Exception: access violation reading 0x0")
    cleanup_error = RuntimeError("cleanup fault")

    class Raw:
        def C_DestroyObject(self, _session: int, handle: int) -> int:  # noqa: N802
            calls.append(handle)
            if handle == 11:
                raise RuntimeError("first destroy fault")
            if handle == 12:
                raise access_violation
            return 0

    def cleanup() -> None:
        raise cleanup_error

    with pytest.raises(OSError) as caught:
        probe._destroy_derive_setup_handles(Raw(), 7, (11, 12, 13, 14), cleanup)

    assert caught.value is access_violation
    assert calls == [11, 12, 13, 14]


def test_derive_probe_has_no_required_attribute_access_violation() -> None:
    assert analyze_file("src/pkcs11_check/testcases/_probes/operation_state_uaf.py") == []
