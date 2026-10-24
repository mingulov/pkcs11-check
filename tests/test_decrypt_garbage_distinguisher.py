"""QF4 (fw#37): fixed garbage v1.5 decrypt stays unresolved on CKR_OK.

One all-zero ciphertext plus one same-input repeat cannot prove plaintext
exposure (the separator-less block has no defined would-be plaintext, so zero
output is not a bypass witness) and cannot confirm implicit rejection (one
input cannot distinguish a ciphertext-derived synthetic decoder from a
constant-output decoder, and there is no valid-control evidence). Any CKR_OK
therefore xfails as visible ``honest_deviation`` with
``detail["assessment"] == "unresolved"`` -- never ``accepted_invalid``, never
a confirmed-rejection claim. Only a malformed length claim (beyond capacity
or the RSA ``k-11`` mechanism maximum) fails as ``wrong_result``.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases import test_errors

_SYNTH_A = bytes((i * 37 + 11) % 256 for i in range(245))
_SYNTH_B = bytes((i * 53 + 7) % 256 for i in range(245))
_ZEROS = bytes(245)

_ScriptEntry = tuple[int, bytes] | tuple[int, bytes, int] | BaseException


class _DecryptScriptRaw:
    """Script (rv, output-bytes[, reported-len]) per C_Decrypt call; count Inits.

    A 3-tuple entry sets the reported output length explicitly while writing
    at most the buffer capacity, so an over-claiming provider is expressible
    without the fake itself reading out of bounds. A BaseException entry is
    raised as a raw provider fault.
    """

    def __init__(
        self,
        script: list[_ScriptEntry],
        *,
        init_script: list[int] | None = None,
    ) -> None:
        self._script = list(script)
        self._init_script = list(init_script or [])
        self.init_count = 0

    def C_GenerateKeyPair(  # noqa: N802
        self,
        _sh: int,
        _mech: Any,
        _pub_tmpl: Any,
        _pub_n: int,
        _priv_tmpl: Any,
        _priv_n: int,
        pub_out: Any,
        priv_out: Any,
    ) -> int:
        # Must match the PKCS#11 entry-point name the helper calls.
        pub_out._obj.value = 31
        priv_out._obj.value = 32
        return int(CKR_OK)

    def C_DecryptInit(self, _sh: int, _mech: Any, _key: int) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the test calls.
        self.init_count += 1
        if self._init_script:
            return self._init_script.pop(0)
        return int(CKR_OK)

    def C_Decrypt(  # noqa: N802
        self, _sh: int, _in_buf: Any, _in_len: int, out_buf: Any, out_len: Any
    ) -> int:
        # Must match the PKCS#11 entry-point name the test calls.
        entry = self._script.pop(0)
        if isinstance(entry, BaseException):
            raise entry
        rv, data = entry[0], entry[1]
        reported = entry[2] if len(entry) == 3 else min(len(data), len(out_buf))
        n = min(len(data), len(out_buf))
        for i in range(n):
            out_buf[i] = data[i]
        out_len._obj.value = reported
        return rv

    def C_DestroyObject(self, _sh: int, _h: int) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the helper calls.
        return int(CKR_OK)


def _run(script: list[_ScriptEntry], *, init_script: list[int] | None = None) -> _DecryptScriptRaw:
    raw = _DecryptScriptRaw(script, init_script=init_script)
    rs = SimpleNamespace(has_mechanism=lambda _name: True, raw=raw, sh=1)
    classification.clear()
    test_errors.TestInvalidOperations().test_decrypt_garbage(rs)
    return raw


def _unresolved_xfail_match() -> pytest.ExceptionInfo[Any]:
    return pytest.raises(pytest.xfail.Exception, match="unresolved")


def test_zero_output_is_unresolved_and_runs_distinguisher() -> None:
    """All-zero output is not a bypass witness; the repeat decrypt still runs."""
    raw = _DecryptScriptRaw([(int(CKR_OK), _ZEROS), (int(CKR_OK), _ZEROS)])
    rs = SimpleNamespace(has_mechanism=lambda _name: True, raw=raw, sh=1)
    classification.clear()
    with _unresolved_xfail_match():
        test_errors.TestInvalidOperations().test_decrypt_garbage(rs)
    assert raw.init_count == 2
    records = classification.get_records()
    assert [r.reason for r in records] == ["honest_deviation"]
    assert records[0].detail is not None
    assert records[0].detail["assessment"] == "unresolved"


def test_identical_synthetic_output_is_unresolved() -> None:
    """One stable nonzero output cannot confirm implicit rejection."""
    with _unresolved_xfail_match():
        _run([(int(CKR_OK), _SYNTH_A), (int(CKR_OK), _SYNTH_A)])
    records = classification.get_records()
    assert [r.reason for r in records] == ["honest_deviation"]
    assert records[0].detail is not None
    assert records[0].detail["assessment"] == "unresolved"
    assert records[0].detail["stable"] is True


def test_varying_output_is_unresolved() -> None:
    """Varying output is unproven either way: visible unresolved evidence."""
    with _unresolved_xfail_match():
        _run([(int(CKR_OK), _SYNTH_A), (int(CKR_OK), _SYNTH_B)])
    records = classification.get_records()
    assert [r.reason for r in records] == ["honest_deviation"]
    assert records[0].detail is not None
    assert records[0].detail["stable"] is False


def test_zero_then_nonzero_is_unresolved() -> None:
    """Any all-zero draw stays unresolved: synthesis and bypass both unproven."""
    with _unresolved_xfail_match():
        _run([(int(CKR_OK), _ZEROS), (int(CKR_OK), _SYNTH_A)])


def test_repeat_reject_is_unresolved() -> None:
    """An unrepeatable CKR_OK keeps its first-call evidence visible, unresolved."""
    with _unresolved_xfail_match():
        _run([(int(CKR_OK), _SYNTH_A), (int(CKR_ENCRYPTED_DATA_INVALID), b"")])
    records = classification.get_records()
    assert [r.reason for r in records] == ["honest_deviation"]
    assert records[0].detail is not None
    assert records[0].detail["stable"] is False


def test_overreported_length_is_wrong_result() -> None:
    """A CKR_OK length beyond capacity fails closed with no repeat past it."""
    from _pytest.outcomes import Failed

    raw = _DecryptScriptRaw([(int(CKR_OK), _SYNTH_A, 300)])
    rs = SimpleNamespace(has_mechanism=lambda _name: True, raw=raw, sh=1)
    classification.clear()
    with pytest.raises(Failed, match="capacity|length"):
        test_errors.TestInvalidOperations().test_decrypt_garbage(rs)
    assert raw.init_count == 1
    records = classification.get_records()
    assert [r.reason for r in records] == ["wrong_result"]


def test_k11_excess_length_is_wrong_result() -> None:
    """256 claimed bytes fit the buffer but exceed the RSA k-11 maximum (245).

    Within-capacity output is safely readable, so the repeat still runs for
    complete stability evidence; the verdict floor is already wrong_result.
    """
    from _pytest.outcomes import Failed

    with pytest.raises(Failed, match="length|k-11|245"):
        _run([(int(CKR_OK), bytes(256)), (int(CKR_OK), _SYNTH_A)])
    records = classification.get_records()
    assert [r.reason for r in records] == ["wrong_result"]


def test_repeat_init_failure_is_unresolved() -> None:
    """A repeat that cannot start keeps its first-call evidence unresolved."""
    with _unresolved_xfail_match():
        _run(
            [(int(CKR_OK), _SYNTH_A)],
            init_script=[int(CKR_OK), int(CKR_DEVICE_ERROR)],
        )


def test_explicit_reject_passes_without_repeat() -> None:
    """Clean rejection passes and needs no repeat decrypt (fw#37)."""
    raw = _run([(int(CKR_ENCRYPTED_DATA_INVALID), b"")])
    assert raw.init_count == 1


def test_first_k11_violation_survives_repeat_fault() -> None:
    """A first-attempt k-11 excess is retained before the risky repeat faults."""
    raw = _DecryptScriptRaw([(int(CKR_OK), bytes(246)), RuntimeError("repeat boom")])
    rs = SimpleNamespace(has_mechanism=lambda _name: True, raw=raw, sh=1)
    classification.clear()
    with pytest.raises(RuntimeError, match="repeat boom"):
        test_errors.TestInvalidOperations().test_decrypt_garbage(rs)
    assert raw.init_count == 2
    records = classification.get_records()
    assert [r.reason for r in records] == ["wrong_result"]


def test_completed_k11_floor_carries_repeat_evidence() -> None:
    """The raised k-11 floor retains the completed repeat's RV/length/bytes.

    Fix round 2 (item 2): raising the first-attempt floor with its
    first-only sample would discard the repeat's RV, length, bytes, and
    stability. The terminal record must carry both attempts.
    """
    from _pytest.outcomes import Failed

    repeat = bytes([7]) * 246
    with pytest.raises(Failed, match="length|k-11|245"):
        _run([(int(CKR_OK), bytes(246)), (int(CKR_OK), repeat)])
    records = classification.get_records()
    assert [r.reason for r in records] == ["wrong_result"]
    assert records[0].detail is not None
    sample = records[0].detail["sample"]
    assert sample["first"]["reported_len"] == 246
    assert sample["repeated"] is not None
    assert sample["repeated"]["rv"] == "CKR_OK"
    assert sample["repeated"]["reported_len"] == 246
    assert sample["repeated"]["output"]["hex"] == repeat.hex()
    assert sample["stable"] is False
