"""The module-reported output-size allocator turns an absurd length into a legible error.

A misbehaving module can report a garbage required-output length; the two-call output
pattern would then allocate ``CK_BYTE * that`` and raise an opaque OverflowError/MemoryError,
masking the finding behind a cryptic harness error. `_alloc_module_output` re-raises it as a
clear ValueError naming the size, and never caps a legitimate size.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.recipes import (
    ImplausibleModuleLengthError,
    _alloc_module_output,
    _two_call_output,
)
from pkcs11_check.raw.types_std import CKR_BUFFER_TOO_SMALL, CKR_OK

# N-003: resolved lazily so the red phase fails as test failures (missing
# typed observation) rather than a collection error.
OutputLengthOverrunError: Any = getattr(raw_recipes, "OutputLengthOverrunError", None)


def test_alloc_module_output_normal_size_returns_zeroed_buffer() -> None:
    buf = _alloc_module_output(64, what="C_Sign")
    assert len(buf) == 64
    assert bytes(buf) == b"\x00" * 64


def test_alloc_module_output_implausible_size_raises_clear_value_error() -> None:
    # 2**63 overflows ctypes array creation; must become a legible ValueError, not OverflowError
    with pytest.raises(ValueError, match="implausible output length"):
        _alloc_module_output(2**63, what="C_Encrypt")


def test_alloc_module_output_implausible_size_raises_typed_subclass() -> None:
    # The dedicated subclass lets collection-time probes contain provider
    # misbehavior without catching (and masking) true harness bugs.
    with pytest.raises(ImplausibleModuleLengthError, match="C_Encrypt"):
        _alloc_module_output(2**63, what="C_Encrypt")


def test_alloc_module_output_does_not_cap_large_but_valid_sizes() -> None:
    # a large-but-allocatable size (1 MiB) must succeed -- no upper cap / false reject
    buf = _alloc_module_output(1 << 20, what="C_WrapKey")
    assert len(buf) == 1 << 20
    assert isinstance(buf, ctypes.Array)


# ---------------------------------------------------------------------------
# N-003: CKR_OK claiming more bytes than capacity must surface, not slice
# ---------------------------------------------------------------------------


def _scripted_output(script: list[tuple[int, int]]) -> SimpleNamespace:
    """Fake module: each call consumes (rv, out_len) and sets the length out-param."""
    calls = list(script)

    def _fn(*args: Any) -> int:
        rv, out_len = calls.pop(0)
        args[-1]._obj.value = out_len
        return int(rv)

    return SimpleNamespace(C_Encrypt=_fn)


def test_two_call_output_overrun_raises_typed_with_lengths() -> None:
    """N-003: capacity 2 + OK + reported 99 -> typed error, not 2 sliced bytes."""
    assert OutputLengthOverrunError is not None, "N-003 typed observation missing"
    raw = _scripted_output([(int(CKR_OK), 2), (int(CKR_OK), 99)])
    with pytest.raises(OutputLengthOverrunError) as ei:
        _two_call_output(raw, "C_Encrypt", 1, b"hi", 2)
    assert ei.value.call == "C_Encrypt"
    assert ei.value.capacity == 2
    assert ei.value.reported == 99
    assert "99" in str(ei.value) and "2" in str(ei.value)


def test_two_call_output_hint_overrun_raises_typed() -> None:
    """N-003: single-call hint path over-reports -> typed error too."""
    assert OutputLengthOverrunError is not None, "N-003 typed observation missing"
    raw = _scripted_output([(int(CKR_OK), 99)])
    with pytest.raises(OutputLengthOverrunError):
        _two_call_output(raw, "C_Encrypt", 1, b"hi", 2, output_size_hint=2)


def test_overrun_error_is_implausible_subclass() -> None:
    """N-003: existing ImplausibleModuleLengthError handlers keep working."""
    assert OutputLengthOverrunError is not None, "N-003 typed observation missing"
    assert issubclass(OutputLengthOverrunError, ImplausibleModuleLengthError)
    assert issubclass(OutputLengthOverrunError, ValueError)


def test_two_call_output_shorter_output_stays_accepted() -> None:
    """N-003 regression pin: a valid shorter output is still accepted."""
    raw = _scripted_output([(int(CKR_OK), 8), (int(CKR_OK), 3)])
    assert _two_call_output(raw, "C_Encrypt", 1, b"hi", 2) == b"\x00\x00\x00"


def test_two_call_output_buffer_too_small_retry_preserved() -> None:
    """N-003 regression pin: the documented retry still recovers and returns."""
    raw = _scripted_output([(int(CKR_OK), 2), (int(CKR_BUFFER_TOO_SMALL), 4), (int(CKR_OK), 4)])
    out = _two_call_output(raw, "C_Encrypt", 1, b"hi", 2, retry_on_buffer_too_small=True)
    assert out == b"\x00\x00\x00\x00"
