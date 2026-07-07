"""The module-reported output-size allocator turns an absurd length into a legible error.

A misbehaving module can report a garbage required-output length; the two-call output
pattern would then allocate ``CK_BYTE * that`` and raise an opaque OverflowError/MemoryError,
masking the finding behind a cryptic harness error. `_alloc_module_output` re-raises it as a
clear ValueError naming the size, and never caps a legitimate size.
"""

from __future__ import annotations

import ctypes

import pytest

from pkcs11_check.raw.recipes import _alloc_module_output


def test_alloc_module_output_normal_size_returns_zeroed_buffer() -> None:
    buf = _alloc_module_output(64, what="C_Sign")
    assert len(buf) == 64
    assert bytes(buf) == b"\x00" * 64


def test_alloc_module_output_implausible_size_raises_clear_value_error() -> None:
    # 2**63 overflows ctypes array creation; must become a legible ValueError, not OverflowError
    with pytest.raises(ValueError, match="implausible output length"):
        _alloc_module_output(2**63, what="C_Encrypt")


def test_alloc_module_output_does_not_cap_large_but_valid_sizes() -> None:
    # a large-but-allocatable size (1 MiB) must succeed -- no upper cap / false reject
    buf = _alloc_module_output(1 << 20, what="C_WrapKey")
    assert len(buf) == 1 << 20
    assert isinstance(buf, ctypes.Array)
