"""Meta-tests: SETUP_REFUSED marker distinguishes setup-refused from not-applicable (issue #28).

A probe setup step with valid inputs refused by the module must record the
setup operation + refusal CKR explicitly (target untested) instead of folding
into a generic target not_operational record.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from pkcs11_check.classification import get_records
from pkcs11_check.raw.types_std import _CK_ULONG_MAX
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


def test_refused_line_tracked_as_setup_refusal() -> None:
    """SETUP_REFUSED lines feed setup_refusal_indices for ordering checks."""
    (_, _, _, _, _, _, _, _, setup_refusal_indices, _) = raw_buffer._parse_ec_facts(
        "SETUP_REFUSED:C_GenerateKey:0x00000006\n",
        context="buffer probe",
        process_complete=True,
        expected_probe=None,
    )
    assert list(setup_refusal_indices) == [0]
