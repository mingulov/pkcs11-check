"""Runtime protocol and classification tests for the derive UAF probe."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import cast

import pytest

from pkcs11_check import classification as C  # noqa: N812 - classification alias convention
from pkcs11_check.raw.types_std import (
    CKA_EC_POINT,
    CKR_KEY_HANDLE_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
)
from pkcs11_check.testcases._probes import operation_state_uaf as probe
from pkcs11_check.testcases._probes.session import ProbeContext
from pkcs11_check.testcases.security import test_operation_state_uaf as uaf
from tests._attribute_access_guard import analyze_file


def _config() -> SimpleNamespace:
    return SimpleNamespace(module="/module.so", slot=0)


def _missing_point_fact() -> str:
    return (
        'UAF:{"schema":1,"probe":"derive","event":"SETUP_ATTRIBUTE",'
        '"attribute":{"name":"CKA_EC_POINT","id":385},"state":"missing",'
        '"value_type":null,"value_len":null}\n'
    )


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
    assert record.mechanism == "CKM_ECDH1_DERIVE"
    assert record.actual_ckr is None


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
    with pytest.raises(pytest.skip.Exception):
        _check_digest(
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
    assert records[1].detail["termination"]["kind"] == "signal"


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


def test_hard_provider_contradiction_precedes_positive_exit_harness_error() -> None:
    with pytest.raises(pytest.fail.Exception, match="accepted a destroyed"):
        _check(_target(0, 0), rc=2)

    assert [item.reason for item in C.get_records()] == [
        "self_contradiction",
        "harness_error",
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
    with pytest.raises(pytest.skip.Exception):
        _check(
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


def test_derive_probe_has_no_required_attribute_access_violation() -> None:
    assert analyze_file("src/pkcs11_check/testcases/_probes/operation_state_uaf.py") == []
