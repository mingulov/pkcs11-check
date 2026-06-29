from __future__ import annotations

import ctypes
import sys

import pytest

from pkcs11_check.testcases._probes.honeypot import (
    SETUP_XFAIL_PREFIX,
    HoneypotUnavailable,
    demand_zero_buffer,
)


def test_setup_xfail_prefix_value() -> None:
    assert SETUP_XFAIL_PREFIX == "SETUP_XFAIL:"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="POSIX mmap only")
def test_demand_zero_buffer_is_readable_far_past_a_small_buffer() -> None:
    ptr = demand_zero_buffer()
    # The whole point: indices far beyond any honestly-provisioned buffer read as 0.
    assert ptr[0] == 0
    assert ptr[1 << 30] == 0  # 1 GiB in - inside the demand-zero mapping


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="POSIX mmap only")
def test_demand_zero_buffer_is_idempotent() -> None:
    ptr1 = demand_zero_buffer()
    ptr2 = demand_zero_buffer()
    # Both calls must return pointers to the same address (same process-lifetime mapping).
    assert ctypes.cast(ptr1, ctypes.c_void_p).value == ctypes.cast(ptr2, ctypes.c_void_p).value


def test_unavailable_carries_setup_xfail_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    import mmap as _mmap

    monkeypatch.delattr(_mmap, "MAP_ANONYMOUS", raising=False)
    with pytest.raises(HoneypotUnavailable) as exc:
        demand_zero_buffer()
    assert "POSIX" in str(exc.value)
