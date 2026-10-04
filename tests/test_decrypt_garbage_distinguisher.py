"""fw#37: garbage v1.5 decrypt must separate bypass from implicit rejection.

A blind strip of an all-zero block can only yield zero bytes, while synthetic
implicit-rejection output is nonzero; rejection (OpenSSL/NSS-style) is
additionally deterministic per input. So: identical nonzero output on a
repeat decrypt xfailed as honest_deviation; anything else (all-zero output,
varying output, unrepeatable CKR_OK) stays a loud accepted_invalid failure.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKR_ENCRYPTED_DATA_INVALID, CKR_OK
from pkcs11_check.testcases import test_errors

_SYNTH_A = bytes((i * 37 + 11) % 256 for i in range(245))
_SYNTH_B = bytes((i * 53 + 7) % 256 for i in range(245))
_ZEROS = bytes(245)


class _DecryptScriptRaw:
    """Script (rv, output-bytes) per C_Decrypt call; count decrypt Inits."""

    def __init__(self, script: list[tuple[int, bytes]]) -> None:
        self._script = list(script)
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
        return int(CKR_OK)

    def C_Decrypt(  # noqa: N802
        self, _sh: int, _in_buf: Any, _in_len: int, out_buf: Any, out_len: Any
    ) -> int:
        # Must match the PKCS#11 entry-point name the test calls.
        rv, data = self._script.pop(0)
        n = min(len(data), len(out_buf))
        for i in range(n):
            out_buf[i] = data[i]
        out_len._obj.value = n
        return rv

    def C_DestroyObject(self, _sh: int, _h: int) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the helper calls.
        return int(CKR_OK)


def _run(script: list[tuple[int, bytes]]) -> _DecryptScriptRaw:
    raw = _DecryptScriptRaw(script)
    rs = SimpleNamespace(has_mechanism=lambda _name: True, raw=raw, sh=1)
    test_errors.TestInvalidOperations().test_decrypt_garbage(rs)
    return raw


def test_zero_output_is_bypass_and_runs_distinguisher() -> None:
    """All-zero output fails loud, and the repeat decrypt ran (fw#37)."""
    raw = _DecryptScriptRaw([(int(CKR_OK), _ZEROS), (int(CKR_OK), _ZEROS)])
    rs = SimpleNamespace(has_mechanism=lambda _name: True, raw=raw, sh=1)
    try:
        test_errors.TestInvalidOperations().test_decrypt_garbage(rs)
    except pytest.fail.Exception as exc:
        assert "padding bypass" in str(exc)
    else:
        pytest.fail("expected accepted_invalid failure, got none")
    assert raw.init_count == 2


def test_identical_synthetic_output_xfails() -> None:
    """Deterministic synthetic output is implicit rejection, not bypass."""
    try:
        _run([(int(CKR_OK), _SYNTH_A), (int(CKR_OK), _SYNTH_A)])
    except pytest.xfail.Exception as exc:
        assert "implicit rejection" in str(exc)
    else:
        pytest.fail("expected honest-deviation xfail, method returned normally")


def test_varying_output_stays_loud() -> None:
    """Varying output fails the identicality arm: unproven, stays loud."""
    try:
        _run([(int(CKR_OK), _SYNTH_A), (int(CKR_OK), _SYNTH_B)])
    except pytest.fail.Exception as exc:
        assert "nondeterministic" in str(exc)
    except pytest.skip.Exception as exc:
        pytest.fail(f"expected loud failure, got skip: {exc}")
    else:
        pytest.fail("expected loud failure, method returned normally")


def test_zero_then_nonzero_stays_loud() -> None:
    """Any all-zero draw fails: synthesis cannot emit zeros (fw#37)."""
    try:
        _run([(int(CKR_OK), _ZEROS), (int(CKR_OK), _SYNTH_A)])
    except pytest.fail.Exception:
        pass
    except pytest.skip.Exception as exc:
        pytest.fail(f"expected loud failure, got skip: {exc}")
    else:
        pytest.fail("expected loud failure, method returned normally")


def test_explicit_reject_passes_without_repeat() -> None:
    """Clean rejection passes and needs no repeat decrypt (fw#37)."""
    raw = _run([(int(CKR_ENCRYPTED_DATA_INVALID), b"")])
    assert raw.init_count == 1
