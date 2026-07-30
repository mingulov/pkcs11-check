"""Regression tests for the timing-measurement scope in the padding-oracle suite.

The two "timing sanity" tests compare how long a module takes to decrypt valid vs
invalid ciphertext, and report a >3x gap as a Lucky13-class oracle -- a CRITICAL
finding. They therefore must time the module's ``C_Decrypt`` and nothing else.

Timing the single-shot ``decrypt_single`` recipe instead charged the failure leg for
harness work: a rejected decrypt leaves the operation ACTIVE, the recipe's best-effort
``C_SessionCancel`` does nothing on a pre-v3.0 module that does not export it, and the
next ``C_DecryptInit`` then returns CKR_OPERATION_ACTIVE and pays a session-recovery
round trip. On SoftHSM2 2.5.0 that was ~130us of teardown against ~8us of decrypt --
a fabricated 12x "oracle" against a module whose real ratio is 1.5x, i.e. exactly the
false accusation against a conformant provider the project rules warn about.
"""

from __future__ import annotations

import time
from typing import Any

from pkcs11_check.raw.types_std import CKR_DATA_INVALID, CKR_OK
from pkcs11_check.testcases.security.test_padding_oracle import _timed_decrypt, _timing_ratio

_TEARDOWN_DELAY_S = 0.05


class _FakeRaw:
    """Raw-module stub whose init/teardown are slow and whose C_Decrypt is fast.

    If the measurement window is scoped correctly, the reported time tracks
    ``decrypt_delay_s`` only, and the init/teardown cost never appears.
    """

    def __init__(self, *, rv: int, decrypt_delay_s: float = 0.0) -> None:
        self._rv = rv
        self._decrypt_delay_s = decrypt_delay_s
        self.calls: list[str] = []

    def C_DecryptInit(self, _session: int, _mech: Any, _key: int) -> int:  # noqa: N802
        self.calls.append("C_DecryptInit")
        time.sleep(_TEARDOWN_DELAY_S)
        return int(CKR_OK)

    def C_Decrypt(  # noqa: N802
        self, _session: int, _in_buf: Any, _in_len: int, _out: Any, _out_len: Any
    ) -> int:
        self.calls.append("C_Decrypt")
        time.sleep(self._decrypt_delay_s)
        return self._rv

    def C_DecryptFinal(self, _session: int, _out: Any, _out_len: Any) -> int:  # noqa: N802
        self.calls.append("C_DecryptFinal")
        time.sleep(_TEARDOWN_DELAY_S)
        return int(CKR_OK)


def test_timed_decrypt_excludes_init_and_teardown_on_the_failure_path() -> None:
    """A rejecting decrypt must not be charged for the harness's cleanup call."""
    raw = _FakeRaw(rv=int(CKR_DATA_INVALID))
    elapsed, rv = _timed_decrypt(raw, 1, 2, 0x1085, b"\x00" * 32)

    assert rv == int(CKR_DATA_INVALID)
    # Teardown really did run (state must be cleaned up) ...
    assert "C_DecryptFinal" in raw.calls
    # ... but it is outside the measurement window, as is the slow init.
    assert elapsed < _TEARDOWN_DELAY_S, (
        f"measured {elapsed:.4f}s: init/teardown leaked into the timing window"
    )


def test_timed_decrypt_measures_the_module_call_itself() -> None:
    """The window still covers C_Decrypt, so a genuinely slow module is visible."""
    raw = _FakeRaw(rv=int(CKR_OK), decrypt_delay_s=_TEARDOWN_DELAY_S * 2)
    elapsed, rv = _timed_decrypt(raw, 1, 2, 0x1085, b"\x00" * 32)

    assert rv == int(CKR_OK)
    assert elapsed >= _TEARDOWN_DELAY_S * 2


def test_valid_and_invalid_legs_are_comparable_when_the_module_is_constant_time() -> None:
    """Equal module work -> ratio near 1, even though only one leg needs teardown.

    This is the end-to-end property the fix exists for: before it, the rejecting leg
    alone paid teardown and the ratio blew past the 3.0 CRITICAL threshold.
    """
    ok = _FakeRaw(rv=int(CKR_OK), decrypt_delay_s=0.002)
    bad = _FakeRaw(rv=int(CKR_DATA_INVALID), decrypt_delay_s=0.002)

    valid = [_timed_decrypt(ok, 1, 2, 0x1085, b"\x00" * 32)[0] for _ in range(5)]
    invalid = [_timed_decrypt(bad, 1, 2, 0x1085, b"\x00" * 32)[0] for _ in range(5)]

    # No oracle reported: either the gap is below the reporting floor (None) or the
    # ratio is under the threshold. Both mean "this module is not accused".
    ratio = _timing_ratio(valid, invalid)
    assert ratio is None or ratio < 3.0, (
        f"constant-time module reported as a {ratio:.1f}x timing oracle"
    )


def test_timing_ratio_guards_degenerate_inputs() -> None:
    assert _timing_ratio([], [1.0]) is None
    assert _timing_ratio([1.0], []) is None
    assert _timing_ratio([0.0], [1.0]) is None
    assert _timing_ratio([1.0, 3.0], [1.0]) == 2.0


def test_microsecond_gaps_are_not_reported_as_oracles() -> None:
    """2us vs 10us is a 5x ratio but only an 8us gap -- real SoftHSM2 2.7.0 numbers.

    Once the timing window covers the module call alone the means are microseconds, so
    a bare ratio test would accuse a conformant module over scheduler jitter.
    """
    assert _timing_ratio([0.000002] * 5, [0.000010] * 5) is None


def test_gross_timing_oracles_are_still_reported() -> None:
    """The documented target of these probes -- e.g. 5ms vs 100ms -- must still fire."""
    ratio = _timing_ratio([0.005] * 5, [0.100] * 5)
    assert ratio is not None
    assert ratio > 3.0
