"""Runtime classification meta-test for test_operation_state garbage-state guard (Phase 4 N2).

C_SetOperationState with a garbage blob must reject. Converted from a flat
``assert rv in {set}`` to a 3-way ``classify_negative_rv``:

- ``CKR_OK`` (the module accepted a garbage state blob) -> ``fail``,
- ``CKR_SAVED_STATE_INVALID`` (spec) -> ``pass``,
- any other clean reject code -> ``xfail``.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_SAVED_STATE_INVALID,
    CKR_STATE_UNSAVEABLE,
)
from pkcs11_check.testcases import test_operation_state as tos
from pkcs11_check.testcases._probes.runner import ProbeResult

_CROSS_DIGEST = hashlib.sha256(b"cross-session data" + b"cross-session continuation").hexdigest()
_SAME_DIGEST = hashlib.sha256(b"Hello, " + b"PKCS#11 state!").hexdigest()


def _session(set_state_rv: int) -> SimpleNamespace:
    raw = SimpleNamespace(C_SetOperationState=lambda *_a, **_k: int(set_state_rv))
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda n: True)


def _run(set_state_rv: int) -> None:
    tos.TestGetOperationStateAPI().test_garbage_state_raises_saved_state_invalid(
        _session(set_state_rv)
    )


def test_garbage_accepted_fails() -> None:
    with pytest.raises(Failed) as ei:
        _run(int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_get_only_operation_state_test_skips_when_get_pointer_is_missing() -> None:
    raw = SimpleNamespace(available_function_names=lambda: {"C_SetOperationState"})
    session = SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)

    with pytest.raises(pytest.skip.Exception, match="C_GetOperationState"):
        tos.TestGetOperationStateAPI().test_no_active_operation(session)


def test_get_operation_state_function_not_supported_is_capability_skip() -> None:
    raw = SimpleNamespace(
        available_function_names=lambda: {"C_GetOperationState"},
        C_GetOperationState=lambda *_a, **_k: int(CKR_FUNCTION_NOT_SUPPORTED),
    )
    session = SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)

    with pytest.raises(pytest.skip.Exception, match="C_GetOperationState"):
        tos.TestGetOperationStateAPI().test_no_active_operation(session)

    from pkcs11_check.classification import get_records

    assert get_records() == []


def test_set_only_operation_state_test_skips_when_set_pointer_is_missing() -> None:
    raw = SimpleNamespace(available_function_names=lambda: {"C_GetOperationState"})
    session = SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)

    with pytest.raises(pytest.skip.Exception, match="C_SetOperationState"):
        tos.TestGetOperationStateAPI().test_garbage_state_raises_saved_state_invalid(session)


def test_set_operation_state_function_not_supported_is_capability_skip() -> None:
    with pytest.raises(pytest.skip.Exception, match="C_SetOperationState"):
        _run(int(CKR_FUNCTION_NOT_SUPPORTED))

    from pkcs11_check.classification import get_records

    assert get_records() == []


def _get_op_session(rv: int) -> SimpleNamespace:
    raw = SimpleNamespace(
        available_function_names=lambda: {"C_GetOperationState"},
        C_GetOperationState=lambda *_a, **_k: int(rv),
    )
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)


def test_no_active_operation_spec_code_passes_and_records_nothing() -> None:
    """CKR_OPERATION_NOT_INITIALIZED (the spec code) is a clean pass, no finding."""
    tos.TestGetOperationStateAPI().test_no_active_operation(
        _get_op_session(int(CKR_OPERATION_NOT_INITIALIZED))
    )

    from pkcs11_check.classification import get_records

    assert get_records() == []


def test_no_active_operation_ok_is_tolerated_and_records_nothing() -> None:
    """CKR_OK was always in the old "acceptable" set -- classify_negative_rv(allow_ok=True)
    preserves that same silent-pass behavior rather than turning it into a fail."""
    tos.TestGetOperationStateAPI().test_no_active_operation(_get_op_session(int(CKR_OK)))

    from pkcs11_check.classification import get_records

    assert get_records() == []


def test_no_active_operation_unexpected_clean_reject_is_classified_xfail() -> None:
    """Mutation: an unrecognized-but-clean CK_RV (e.g. CKR_ARGUMENTS_BAD).

    Before the fix this was a bare ``assert rv in acceptable`` -- an unclassified pytest
    failure with no reason/kind. It must now surface as a properly classified xfail
    (``nonspec_reject``), matching the "clean error, advertised but not operational" row of
    the classification model -- not a raw unclassified fail.
    """
    with pytest.raises(pytest.xfail.Exception):
        tos.TestGetOperationStateAPI().test_no_active_operation(
            _get_op_session(int(CKR_ARGUMENTS_BAD))
        )

    from pkcs11_check.classification import get_records

    records = get_records()
    assert len(records) == 1
    assert records[0].reason == "nonspec_reject"
    assert records[0].outcome == "xfail"


def test_spec_reject_passes() -> None:
    _run(int(CKR_SAVED_STATE_INVALID))


def test_other_reject_xfails() -> None:
    # CKR_ARGUMENTS_BAD also triggers a note() above, then classifies as xfail.
    with pytest.raises(pytest.xfail.Exception):
        _run(int(CKR_ARGUMENTS_BAD))


def test_operation_state_restored_mismatch_is_wrong_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{_SAME_DIGEST}\n"
                f"SINGLESHOT_OK:{_SAME_DIGEST}\n"
                f"RESTORED:{'00' * 32}\nOK\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    with pytest.raises(pytest.fail.Exception, match="mismatch"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    record = get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"


def test_operation_state_clean_setup_reject_is_not_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="CKR:DigestInit:0x00000054\nOK\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    with pytest.raises(pytest.xfail.Exception, match="not operational"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)


def test_cross_session_unexpected_clean_reject_is_structured_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A different defined rejection is provider evidence, not a raw assertion."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{_CROSS_DIGEST}\n"
                "CROSS_SESSION_REJECTED:0x00000005\nOK:digest_cross_session\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.xfail.Exception):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)


def test_cross_session_rejection_is_recorded_before_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A state-capability skip cannot hide a later cleanup crash."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=-11,
            stdout=f"REFERENCE:{_CROSS_DIGEST}\nCROSS_SESSION_REJECTED:0x00000054\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["crash"]


def test_cross_session_wrong_restored_digest_is_recorded_before_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wrong accepted-path output survives when cleanup subsequently crashes."""
    expected = hashlib.sha256(b"cross-session data" + b"cross-session continuation").hexdigest()
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=-11,
            stdout=(f"REFERENCE:{expected}\nCROSS_SESSION_ACCEPTED:1\nRESTORED:{'00' * 32}\n"),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["wrong_result", "crash"]
    assert records[0].kind == "crypto"


def test_cross_session_clean_rejection_has_one_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A normal cross-session refusal is not recorded twice."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=f"REFERENCE:{_CROSS_DIGEST}\nCROSS_SESSION_REJECTED:0x00000054\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.xfail.Exception):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    assert [record.reason for record in get_records()] == ["not_operational"]


def test_cross_session_valid_output_needs_no_terminal_ok(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Complete cross-session fields are sufficient raw protocol evidence."""
    digest = hashlib.sha256(b"cross-session data" + b"cross-session continuation").hexdigest()
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(f"REFERENCE:{digest}\nCROSS_SESSION_ACCEPTED:1\nRESTORED:{digest}\n"),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    assert get_records() == []


@pytest.mark.parametrize(
    "stdout",
    [
        (
            "CROSS_SESSION_ACCEPTED:1\n"
            "CROSS_SESSION_ACCEPTED:1\n"
            f"REFERENCE:{_CROSS_DIGEST}\n"
            f"RESTORED:{_CROSS_DIGEST}\n"
        ),
        (
            "CROSS_SESSION_ACCEPTED:1\n"
            f"REFERENCE:{_CROSS_DIGEST}\n"
            "CROSS_SESSION_REJECTED:0x00000054\n"
        ),
    ],
)
def test_cross_session_duplicate_or_conflicting_result_is_harness_error(
    monkeypatch: pytest.MonkeyPatch,
    stdout: str,
) -> None:
    """Duplicate/conflicting result markers cannot be provider evidence."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(returncode=0, stdout=stdout, stderr=""),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="Malformed"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    assert [record.reason for record in get_records()] == ["harness_error"]


@pytest.mark.parametrize(
    "rejected_code",
    [CKR_SAVED_STATE_INVALID, CKR_STATE_UNSAVEABLE],
)
def test_cross_session_defined_reject_is_not_operational(
    monkeypatch: pytest.MonkeyPatch,
    rejected_code: int,
) -> None:
    """A clean cross-session refusal is an xfail for defined non-FNS codes."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{_CROSS_DIGEST}\n"
                f"CROSS_SESSION_REJECTED:0x{int(rejected_code):08x}\n"
                "OK:digest_cross_session\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.xfail.Exception, match="not operational"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records
    from pkcs11_check.raw.rv import ckr_name

    classification = get_records()[-1]
    assert classification.reason == "not_operational"
    assert classification.operation == "C_SetOperationState"
    assert classification.actual_ckr == ckr_name(int(rejected_code))


def test_cross_session_function_not_supported_is_capability_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_SetOperationState FNS is an unavailable capability, not provider xfail."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{_CROSS_DIGEST}\n"
                f"CROSS_SESSION_REJECTED:0x{int(CKR_FUNCTION_NOT_SUPPORTED):08x}\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)

    with pytest.raises(pytest.skip.Exception, match="C_SetOperationState"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    assert get_records() == []


def test_same_session_function_not_supported_is_capability_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A state-save FNS marker skips the dependent round-trip without a record."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{_SAME_DIGEST}\n"
                f"SINGLESHOT_OK:{_SAME_DIGEST}\n"
                f"CKR:GetState_len:0x{int(CKR_FUNCTION_NOT_SUPPORTED):08x}\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")

    with pytest.raises(pytest.skip.Exception, match="C_GetOperationState"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    assert get_records() == []


def test_state_function_not_supported_does_not_hide_outer_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=-11,
            stdout=(
                f"REFERENCE:{_SAME_DIGEST}\n"
                f"SINGLESHOT_OK:{_SAME_DIGEST}\n"
                f"CKR:GetState_len:0x{int(CKR_FUNCTION_NOT_SUPPORTED):08x}\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")

    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["crash"]


def test_earlier_hard_semantic_record_controls_before_state_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                "BREAK:provider accepted an impossible transition\n"
                f"CKR:GetState_len:0x{int(CKR_FUNCTION_NOT_SUPPORTED):08x}\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")

    with pytest.raises(pytest.fail.Exception, match="impossible transition"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["self_contradiction"]


def test_unrelated_digest_init_function_not_supported_stays_provider_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only operation-state FNS markers are capability skips."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"CKR:DigestInit:0x{int(CKR_FUNCTION_NOT_SUPPORTED):08x}\n"
                f"CKR:GetState_len:0x{int(CKR_FUNCTION_NOT_SUPPORTED):08x}\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")

    with pytest.raises(pytest.xfail.Exception, match="not operational"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["not_operational"]
    assert records[0].operation == "DigestInit"


def test_cross_session_undefined_reject_is_structured_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An undefined CKR in a clean rejection marker is harness/provider contradiction."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{_CROSS_DIGEST}\n"
                "CROSS_SESSION_REJECTED:0x7fffffff\nOK:digest_cross_session\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="undefined"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    assert get_records()[-1].reason == "self_contradiction"


@pytest.mark.parametrize("operation", ["DigestUpdate_cross", "DigestFinal_cross"])
def test_cross_session_acceptance_followup_reject_is_self_contradiction(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    """Accepted restore followed by a cross-session CKR contradicts the claim."""
    digest = hashlib.sha256(b"cross-session data" + b"cross-session continuation").hexdigest()
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(f"REFERENCE:{digest}\nCROSS_SESSION_ACCEPTED:1\nCKR:{operation}:0x00000054\n"),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="claimed restore success"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records
    from pkcs11_check.raw.rv import ckr_name

    records = get_records()
    assert [record.reason for record in records] == ["self_contradiction"]
    classification = records[-1]
    assert classification.reason == "self_contradiction"
    assert classification.kind == "lifecycle"
    assert classification.operation == "C_SetOperationState"
    assert classification.actual_ckr == ckr_name(0x54)


def test_cross_session_malformed_reject_is_harness_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed child CKR text is incomplete harness protocol."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{_CROSS_DIGEST}\n"
                "CROSS_SESSION_REJECTED:not-a-ckr\nOK:digest_cross_session\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="Malformed cross-session CKR"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)


def test_cross_session_acceptance_compares_restored_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    part1 = b"cross-session data"
    part2 = b"cross-session continuation"
    digest = hashlib.sha256(part1 + part2).hexdigest()
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{digest}\n"
                "CROSS_SESSION_ACCEPTED:1\n"
                f"RESTORED:{digest}\n"
                "OK:digest_cross_session\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)


def test_cross_session_acceptance_wrong_digest_is_wrong_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = hashlib.sha256(b"cross-session data" + b"cross-session continuation").hexdigest()
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{expected}\n"
                "CROSS_SESSION_ACCEPTED:1\n"
                f"RESTORED:{'00' * 32}\n"
                "OK:digest_cross_session\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="restored digest"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    assert get_records()[-1].reason == "wrong_result"


def test_cross_session_acceptance_missing_digest_is_harness_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="CROSS_SESSION_ACCEPTED:1\nOK:digest_cross_session\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="REFERENCE"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)


def test_cross_session_acceptance_malformed_digest_is_harness_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = hashlib.sha256(b"cross-session data" + b"cross-session continuation").hexdigest()
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{expected}\n"
                "CROSS_SESSION_ACCEPTED:1\n"
                "RESTORED:not-hex\n"
                "OK:digest_cross_session\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="Malformed"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)


def test_cross_session_wrong_reference_is_harness_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid-format child REFERENCE is not provider evidence."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(f"REFERENCE:{'00' * 32}\nCROSS_SESSION_ACCEPTED:1\nRESTORED:{_CROSS_DIGEST}\n"),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="REFERENCE"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]
    assert records[0].operation is None
    assert records[0].mechanism is None
    assert records[0].kind is None


def test_cross_session_wrong_reference_and_restored_accumulate_in_protocol_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Harness and provider evidence both survive when both fields are wrong."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(f"REFERENCE:{'00' * 32}\nCROSS_SESSION_ACCEPTED:1\nRESTORED:{'11' * 32}\n"),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error", "wrong_result"]
    assert records[0].operation is None
    assert records[0].mechanism is None
    assert records[1].operation == "C_SetOperationState"
    assert records[1].kind == "crypto"


def test_cross_session_duplicate_reference_preserves_unique_wrong_restored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ambiguous child REFERENCE does not hide unique provider RESTORED evidence."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{_CROSS_DIGEST}\n"
                f"REFERENCE:{_CROSS_DIGEST}\n"
                "CROSS_SESSION_ACCEPTED:1\n"
                f"RESTORED:{'11' * 32}\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="Malformed"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error", "wrong_result"]
    assert records[0].operation is None
    assert records[1].operation == "C_SetOperationState"


def test_cross_session_duplicate_update_is_one_harness_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Duplicate DigestUpdate_cross evidence is malformed protocol, not two findings."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{_CROSS_DIGEST}\n"
                "CROSS_SESSION_ACCEPTED:1\n"
                "CKR:DigestUpdate_cross:0x00000054\n"
                "CKR:DigestUpdate_cross:0x00000054\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="Malformed"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    assert [record.reason for record in get_records()] == ["harness_error"]


def test_cross_session_update_and_final_failures_are_one_harness_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A restored digest cannot fail both follow-up operations in one child path."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{_CROSS_DIGEST}\n"
                "CROSS_SESSION_ACCEPTED:1\n"
                "CKR:DigestUpdate_cross:0x00000054\n"
                "CKR:DigestFinal_cross:0x00000054\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="Malformed"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    assert [record.reason for record in get_records()] == ["harness_error"]


def test_cross_session_malformed_followup_precedes_signal_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed follow-up evidence is retained before a later process crash."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=-11,
            stdout=(
                f"REFERENCE:{_CROSS_DIGEST}\n"
                "CROSS_SESSION_ACCEPTED:1\n"
                "CKR:DigestUpdate_cross:0x00000054\n"
                "CKR:DigestUpdate_cross:0x00000054\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    assert [record.reason for record in get_records()] == ["harness_error", "crash"]


def test_same_session_wrong_reference_is_harness_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same-session REFERENCE is checked against the parent-owned digest oracle."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{'00' * 32}\n"
                f"SINGLESHOT_OK:{_SAME_DIGEST}\n"
                f"RESTORED:{_SAME_DIGEST}\nOK\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    with pytest.raises(pytest.fail.Exception, match="REFERENCE"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    record = get_records()[-1]
    assert record.reason == "harness_error"
    assert record.operation is None
    assert record.mechanism is None


def test_same_session_wrong_restored_is_provider_wrong_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same-session RESTORED is provider output and uses the independent oracle."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{_SAME_DIGEST}\n"
                f"SINGLESHOT_OK:{_SAME_DIGEST}\n"
                f"RESTORED:{'00' * 32}\nOK\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    with pytest.raises(pytest.fail.Exception, match="RESTORED"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    record = get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_SetOperationState"


def test_same_session_wrong_reference_and_restored_accumulate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same-session harness and provider defects are both retained."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{'00' * 32}\nSINGLESHOT_OK:{_SAME_DIGEST}\nRESTORED:{'11' * 32}\nOK\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    with pytest.raises(pytest.fail.Exception):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error", "wrong_result"]


def test_same_session_wrong_restored_before_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A later cleanup crash controls after wrong RESTORED evidence is recorded."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=-11,
            stdout=(
                f"REFERENCE:{_SAME_DIGEST}\nSINGLESHOT_OK:{_SAME_DIGEST}\nRESTORED:{'00' * 32}\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["wrong_result", "crash"]


def test_same_session_singleshot_wrong_digest_is_provider_wrong_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A one-shot provider digest mismatch is not a missing-RESTORED harness error."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=f"REFERENCE:{_SAME_DIGEST}\nSINGLESHOT:{'00' * 32}\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    with pytest.raises(pytest.fail.Exception, match="SINGLESHOT"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["wrong_result"]
    assert records[0].kind == "crypto"


def test_same_session_wrong_reference_and_singleshot_ok_accumulate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SINGLESHOT_OK is provider output, even when the child REFERENCE is wrong."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(f"REFERENCE:{'00' * 32}\nSINGLESHOT_OK:{'00' * 32}\n"),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    with pytest.raises(pytest.fail.Exception, match="REFERENCE"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error", "wrong_result"]
    assert records[0].operation is None
    assert records[0].mechanism is None
    assert records[1].operation == "C_DigestFinal"
    assert records[1].mechanism == "CKM_SHA256"
    assert records[1].kind == "crypto"


def test_same_session_correct_singleshot_is_harness_error_with_wrong_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A correct terminal SINGLESHOT still violates the child's error-only protocol."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(f"REFERENCE:{'00' * 32}\nSINGLESHOT:{_SAME_DIGEST}\n"),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    with pytest.raises(pytest.fail.Exception, match="REFERENCE"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error", "harness_error"]


@pytest.mark.parametrize(
    "stdout",
    [
        f"REFERENCE:{_SAME_DIGEST}\nRESTORED:{_SAME_DIGEST}\nOK\n",
        (
            f"REFERENCE:{_SAME_DIGEST}\n"
            f"SINGLESHOT_OK:{_SAME_DIGEST}\n"
            f"SINGLESHOT_OK:{_SAME_DIGEST}\n"
            f"RESTORED:{_SAME_DIGEST}\nOK\n"
        ),
    ],
)
def test_same_session_restored_success_requires_one_singleshot_ok(
    monkeypatch: pytest.MonkeyPatch,
    stdout: str,
) -> None:
    """Normal restored paths require exactly one single-shot success marker."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(returncode=0, stdout=stdout, stderr=""),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    with pytest.raises(pytest.fail.Exception, match="Malformed"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    assert [record.reason for record in get_records()] == ["harness_error"]


def test_same_session_valid_ckr_survives_malformed_ckr_sibling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed CKR line does not erase a unique provider CKR measurement."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="CKR:DigestInit:0x00000054\nCKR:malformed\nOK\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    with pytest.raises(pytest.fail.Exception, match="Malformed"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error", "not_operational"]
    assert records[1].operation == "DigestInit"


def test_same_session_duplicate_singleshot_ok_preserves_unique_wrong_restored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ambiguous duplicate terminal marker does not hide unique RESTORED evidence."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{_SAME_DIGEST}\n"
                f"SINGLESHOT_OK:{_SAME_DIGEST}\n"
                f"SINGLESHOT_OK:{_SAME_DIGEST}\n"
                f"RESTORED:{'00' * 32}\nOK\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    with pytest.raises(pytest.fail.Exception, match="Malformed"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error", "wrong_result"]
    assert records[0].operation is None
    assert records[0].mechanism is None
    assert records[1].operation == "C_SetOperationState"
    assert records[1].kind == "crypto"


def test_same_session_missing_singleshot_ok_correct_restored_before_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing SINGLESHOT_OK is recorded before a cleanup crash controls the test."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=-11,
            stdout=f"REFERENCE:{_SAME_DIGEST}\nRESTORED:{_SAME_DIGEST}\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    assert [record.reason for record in get_records()] == ["harness_error", "crash"]


@pytest.mark.parametrize("returncode", [0, -11])
def test_same_session_missing_singleshot_ok_wrong_restored_preserves_all_evidence(
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
) -> None:
    """Missing SINGLESHOT_OK preserves RESTORED mismatch and any later crash."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=returncode,
            stdout=f"REFERENCE:{_SAME_DIGEST}\nRESTORED:{'00' * 32}\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    expected_match = "signal 11" if returncode < 0 else "Malformed"
    with pytest.raises(pytest.fail.Exception, match=expected_match):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    expected_reasons = ["harness_error", "wrong_result"]
    if returncode < 0:
        expected_reasons.append("crash")
    records = get_records()
    assert [record.reason for record in records] == expected_reasons
    assert records[1].operation == "C_SetOperationState"
    assert records[1].kind == "crypto"


def test_cross_session_real_rejection_output_is_not_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real child protocol includes its REFERENCE before a clean rejection."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{_CROSS_DIGEST}\n"
                "CROSS_SESSION_REJECTED:0x00000054\n"
                "OK:digest_cross_session\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.xfail.Exception):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["not_operational"]


def test_cross_session_wrong_reference_and_rejection_accumulate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A child-oracle mismatch remains evidence when state support is absent."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{'00' * 32}\n"
                "CROSS_SESSION_REJECTED:0x00000054\n"
                "OK:digest_cross_session\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="REFERENCE"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]
    assert records[0].operation is None


@pytest.mark.parametrize(
    "followup",
    [
        "CKR:DigestUpdate_cross:0x00000000\n",
        ("CKR:DigestUpdate_cross:0x00000000\nCKR:DigestFinal_cross:0x00000054\n"),
    ],
)
def test_cross_session_non_failure_followup_is_harness_error(
    monkeypatch: pytest.MonkeyPatch,
    followup: str,
) -> None:
    """Follow-up markers must be exactly one nonzero CKR from the child."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(f"REFERENCE:{_CROSS_DIGEST}\nCROSS_SESSION_ACCEPTED:1\n{followup}"),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="Malformed"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]


def test_cross_session_failure_and_restored_is_harness_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A follow-up failure and RESTORED together are impossible child output."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=(
                f"REFERENCE:{_CROSS_DIGEST}\n"
                "CROSS_SESSION_ACCEPTED:1\n"
                "CKR:DigestUpdate_cross:0x00000054\n"
                f"RESTORED:{_CROSS_DIGEST}\n"
            ),
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="Malformed"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    assert [record.reason for record in get_records()] == ["harness_error"]


@pytest.mark.parametrize(
    ("partition", "stdout"),
    [
        (
            "missing",
            "CROSS_SESSION_ACCEPTED:1\nCKR:DigestUpdate_cross:0x00000054\n",
        ),
        (
            "invalid",
            "REFERENCE:not-a-digest\nCROSS_SESSION_ACCEPTED:1\nCKR:DigestUpdate_cross:0x00000054\n",
        ),
        (
            "duplicate",
            f"REFERENCE:{_CROSS_DIGEST}\n"
            f"REFERENCE:{_CROSS_DIGEST}\n"
            "CROSS_SESSION_ACCEPTED:1\n"
            "CKR:DigestUpdate_cross:0x00000054\n",
        ),
        (
            "out-of-order",
            "CROSS_SESSION_ACCEPTED:1\n"
            f"REFERENCE:{_CROSS_DIGEST}\n"
            "CKR:DigestUpdate_cross:0x00000054\n",
        ),
    ],
)
def test_cross_session_followup_without_preceding_unique_reference_is_harness_only(
    monkeypatch: pytest.MonkeyPatch,
    partition: str,
    stdout: str,
) -> None:
    """Ambiguous follow-up context cannot become a lifecycle provider finding."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(returncode=0, stdout=stdout, stderr=""),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="Malformed"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]
    assert not any(record.kind == "lifecycle" for record in records)


def test_cross_session_partial_reference_is_checked_before_early_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The explicit cross parser retains a valid reference before setup refusal."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=f"REFERENCE:{_CROSS_DIGEST}\nCKR:DigestInit:0x00000054\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.xfail.Exception):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["not_operational"]
    assert records[0].operation == "DigestInit"


def test_cross_session_partial_reference_without_result_is_harness_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A partial child oracle cannot turn a missing cross-session result into pass."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=f"REFERENCE:{_CROSS_DIGEST}\nOK\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="result"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]


def test_cross_session_missing_partial_reference_accumulates_before_early_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cross probe must retain its missing child oracle alongside provider evidence."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="CKR:DigestInit:0x00000054\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="Malformed"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error", "not_operational"]
    assert records[0].operation is None
    assert records[1].operation == "DigestInit"


def test_cross_session_wrong_partial_reference_accumulates_before_early_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wrong child reference and an early provider CKR remain separate findings."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="REFERENCE:" + "00" * 32 + "\nCKR:DigestInit:0x00000054\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="REFERENCE"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error", "not_operational"]
    assert records[0].operation is None
    assert records[1].operation == "DigestInit"


def test_cross_session_wrong_partial_reference_accumulates_before_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A partial child-oracle mismatch is retained before a later crash."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=-11,
            stdout="REFERENCE:" + "00" * 32 + "\nCKR:DigestInit:0x00000054\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    assert [record.reason for record in get_records()] == [
        "harness_error",
        "not_operational",
        "crash",
    ]


@pytest.mark.parametrize("reference", ["not-a-digest", _CROSS_DIGEST + "0"])
def test_cross_session_ambiguous_partial_reference_preserves_unique_early_ckr(
    monkeypatch: pytest.MonkeyPatch,
    reference: str,
) -> None:
    """Invalid/duplicate references yield one harness record plus provider evidence."""
    if reference == _CROSS_DIGEST + "0":
        stdout = f"REFERENCE:{_CROSS_DIGEST}\nREFERENCE:{reference}\nCKR:DigestInit:0x00000054\n"
    else:
        stdout = f"REFERENCE:{reference}\nCKR:DigestInit:0x00000054\n"
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(returncode=0, stdout=stdout, stderr=""),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="Malformed"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error", "not_operational"]
    assert records[0].operation is None
    assert records[1].operation == "DigestInit"


def test_same_session_reference_is_not_cross_session_protocol() -> None:
    """Generic/same-session inspection must not reinterpret a reference as cross state."""
    semantic, measurements, malformed, has_ckr = tos._inspect_probe(
        0,
        "REFERENCE:" + "00" * 32 + "\nCKR:DigestInit:0x00000054\n",
        "",
        context="same-session-collision",
    )

    assert semantic == []
    assert malformed is False
    assert has_ckr is True
    assert [record.reason for record in measurements] == ["not_operational"]

    from pkcs11_check.classification import get_records

    assert [record.reason for record in get_records()] == ["not_operational"]


def test_cross_session_bootstrap_setup_xfail_is_not_operational_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shared SESSION bootstrap may refuse before the cross-session child runs."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout="SETUP_XFAIL:C_OpenSession rejected with CKR_TOKEN_NOT_PRESENT\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.xfail.Exception, match="C_OpenSession"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["not_operational"]
    assert not any(record.reason == "harness_error" for record in records)


def test_cross_session_bootstrap_setup_xfail_precedes_cleanup_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bootstrap refusal remains provider evidence when teardown later crashes."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=-11,
            stdout="SETUP_XFAIL:C_OpenSession rejected with CKR_TOKEN_NOT_PRESENT\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    with pytest.raises(pytest.fail.Exception, match="signal 11"):
        tos.TestDigestStateRoundTrip().test_digest_state_cross_session(config, None)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["not_operational", "crash"]
    assert not any(record.reason == "harness_error" for record in records)


def test_same_session_correct_singleshot_is_harness_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SINGLESHOT is an error-only marker; a correct value means bad child logic."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=f"REFERENCE:{_SAME_DIGEST}\nSINGLESHOT:{_SAME_DIGEST}\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    with pytest.raises(pytest.fail.Exception, match="SINGLESHOT"):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert [record.reason for record in records] == ["harness_error"]
    assert records[0].operation is None


@pytest.mark.parametrize("marker", ["SINGLESHOT", "SINGLESHOT_OK"])
def test_same_session_terminal_marker_requires_reference(
    monkeypatch: pytest.MonkeyPatch,
    marker: str,
) -> None:
    """A terminal one-shot marker without the preceding child oracle is incomplete."""
    monkeypatch.setattr(
        tos,
        "run_probe",
        lambda *_a, **_k: ProbeResult(
            returncode=0,
            stdout=f"{marker}:{'00' * 32}\n",
            stderr="",
        ),
    )
    config = SimpleNamespace(module="x", slot=0, pin=None)
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "SHA256")
    with pytest.raises(pytest.fail.Exception):
        tos.TestDigestStateRoundTrip().test_digest_state_same_session(config, session)

    from pkcs11_check.classification import get_records

    records = get_records()
    assert records[0].reason == "harness_error"
    assert any(record.reason == "wrong_result" for record in records)
