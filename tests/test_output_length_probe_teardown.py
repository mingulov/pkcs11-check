"""Regression: the output_length oracle must survive its own teardown (GH #9 / #11).

The original _run_oracle passed its from_buffer views through ctypes.cast, which left
the mmap's buffer export outstanding. The subsequent mmap.close() then raised

    BufferError: cannot close exported pointers exist

*after* the probe had already printed TARGET_RV. Replacing cast with byref avoided that
direct export but produced pointer-to-array, which the real typed CK_BYTE_PTR argument
rejects before provider dispatch. Both forms prevented a usable truncation verdict.

Drives the real _run_oracle through the generated ``CK_C_Encrypt`` callback type, so
ctypes performs the same pointer conversion as a real PKCS#11 call without requiring a
provider.
"""

from __future__ import annotations

import ctypes
import mmap
from typing import Any

import pytest

from pkcs11_check.raw.types_std import CK_MECHANISM, CKR_OK, CK_C_Encrypt
from pkcs11_check.testcases._probes._emit import HARNESS_ERROR_MARKER
from pkcs11_check.testcases._probes.output_length import _run_oracle
from pkcs11_check.testcases.security._boundary_values import OVERSIZE_WRITE_LEN

CKR_DATA_LEN_RANGE = 0x21


class _StubRaw:
    """Stands in for RawPKCS11: accepts Init, then rejects the oversize length."""

    def __init__(self, op_rv: int) -> None:
        self._op_rv = op_rv
        self.op_called = False
        self._typed_encrypt = CK_C_Encrypt(self._encrypt)

    def C_EncryptInit(self, *_args: Any) -> int:  # noqa: N802
        return CKR_OK

    def _encrypt(self, *_args: Any) -> int:
        self.op_called = True
        return self._op_rv

    def C_Encrypt(self, *args: Any) -> int:  # noqa: N802
        return int(self._typed_encrypt(*args))


class _DispatchErrorRaw:
    """Simulate a harness-side ctypes conversion failure before provider dispatch."""

    def C_EncryptInit(self, *_args: Any) -> int:  # noqa: N802
        return CKR_OK

    def C_Encrypt(self, *_args: Any) -> int:  # noqa: N802
        raise ctypes.ArgumentError("typed pointer conversion failed")


@pytest.fixture
def _demand_zero_capable() -> None:
    """Skip where two 4 GiB demand-zero mappings are not available (the probe's own guard)."""
    if not hasattr(mmap, "MAP_ANONYMOUS"):
        pytest.skip("demand-zero honeypot needs POSIX mmap")
    flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | getattr(mmap, "MAP_NORESERVE", 0)
    try:
        first = mmap.mmap(-1, OVERSIZE_WRITE_LEN, flags=flags)
    except (OSError, ValueError) as exc:
        pytest.skip(f"cannot allocate the oversize demand-zero mapping: {exc}")
    first.close()


@pytest.mark.usefixtures("_demand_zero_capable")
def test_run_oracle_reports_a_clean_rejection_without_dying_in_teardown(
    capsys: pytest.CaptureFixture[str],
) -> None:
    raw = _StubRaw(CKR_DATA_LEN_RANGE)

    # No exception: before the fix this raised BufferError out of the finally block.
    _run_oracle(
        raw,
        1,
        init_fn="C_EncryptInit",
        op_fn="C_Encrypt",
        mech=CK_MECHANISM(),
        key=2,
    )

    out = capsys.readouterr().out
    assert raw.op_called
    assert "TARGET_RV:0x00000021" in out
    assert "TARGET_RV_NAME:CKR_DATA_LEN_RANGE" in out
    # The teardown guard must not have fired: the release path is expected to be clean.
    assert HARNESS_ERROR_MARKER not in out


@pytest.mark.usefixtures("_demand_zero_capable")
def test_run_oracle_attributes_typed_dispatch_errors_to_the_harness(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(ctypes.ArgumentError, match="typed pointer conversion failed"):
        _run_oracle(
            _DispatchErrorRaw(),
            1,
            init_fn="C_EncryptInit",
            op_fn="C_Encrypt",
            mech=CK_MECHANISM(),
            key=2,
        )

    out = capsys.readouterr().out
    assert f"{HARNESS_ERROR_MARKER}C_Encrypt dispatch: ArgumentError" in out
    assert "TARGET_RV:" not in out
