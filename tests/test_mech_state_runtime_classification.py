"""Runtime classification meta-tests for test_mech_state negative state asserts (Phase 4 N2).

The operation-state guards (op-without-init, double-init) are negative
rejections. Converted from a flat ``assert rv in _NOT_INIT_RVCS`` (which failed
on every non-set code, including a clean but non-spec reject) to a 3-way
``classify_negative_rv``:

- ``CKR_OK`` (the module ran the op without init) -> ``fail``,
- the spec-preferred code -> ``pass``,
- any other clean reject code -> ``xfail``.

The deliberately strict cross-session guards (``_CROSS_SESSION_NOT_INIT_RVCS``)
are intentionally NOT converted: there ``CKR_FUNCTION_FAILED`` /
``CKR_GENERAL_ERROR`` indicate the crash-on-cross-session-probe pattern the test
guards against and must stay ``fail``.
"""

from __future__ import annotations

import ctypes
import hashlib
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, Skipped, XFailed

from pkcs11_check.classification import get_records
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKR_BUFFER_TOO_SMALL,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
)
from pkcs11_check.testcases import test_mech_state as tms
from tests._skip_assert import assert_xfails


class _FakeRaw:
    """Returns ``rv`` from every C_* entry point used by the state guards."""

    def __init__(self, rv: int) -> None:
        self._rv = rv

    def __getattr__(self, _name: str):  # type: ignore[no-untyped-def]
        return lambda *_a, **_k: self._rv


def _session(rv: int) -> SimpleNamespace:
    return SimpleNamespace(raw=_FakeRaw(rv), sh=1, has_mechanism=lambda name: True)


# --- op-without-init (_NOT_INIT_RVCS) ------------------------------------


def _run_no_init(rv: int) -> None:
    tms.TestEncryptState().test_encrypt_without_init(_session(rv))


def test_no_init_ckr_ok_fails() -> None:
    with pytest.raises(Failed) as ei:
        _run_no_init(CKR_OK)
    assert not isinstance(ei.value, XFailed)


def test_no_init_expected_passes() -> None:
    _run_no_init(CKR_OPERATION_NOT_INITIALIZED)


def test_no_init_other_reject_xfails() -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_no_init(CKR_DEVICE_ERROR)


# --- double-init (_ALREADY_ACTIVE_RVCS) ----------------------------------
#
# test_double_encrypt_init generates a key, inits once (CKR_OK), then inits
# again -- the second init's rv is the one classified. With a fake raw that
# returns the same rv everywhere, the first init must be CKR_OK for the test to
# reach the classification, so drive the double-init via test_double_digest_init
# which has no keygen and skips if the first init != CKR_OK. Instead use the
# encrypt path but stub keygen/destroy and force CKR_OK on the first init.


def _run_double_init(second_rv: int) -> SimpleNamespace:
    """Drive test_double_digest_init: first DigestInit must be CKR_OK, second is classified."""
    state = {"init_calls": 0}

    def _dispatch(name: str):  # type: ignore[no-untyped-def]
        def _call(*_a: object, **_k: object) -> int:
            if name == "C_DigestInit":
                state["init_calls"] += 1
                return CKR_OK if state["init_calls"] == 1 else second_rv
            return CKR_OK

        return _call

    class _Raw:
        def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
            return _dispatch(name)

    return SimpleNamespace(raw=_Raw(), sh=1, has_mechanism=lambda name: True)


def test_double_init_ckr_ok_fails() -> None:
    # Second init returning CKR_OK = module accepted a double-init -> fail.
    with pytest.raises(Failed) as ei:
        tms.TestDigestState().test_double_digest_init(_run_double_init(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_double_init_expected_passes() -> None:
    tms.TestDigestState().test_double_digest_init(_run_double_init(CKR_OPERATION_ACTIVE))


def test_double_init_other_reject_xfails() -> None:
    with pytest.raises(pytest.xfail.Exception):
        tms.TestDigestState().test_double_digest_init(_run_double_init(CKR_DEVICE_ERROR))


# --- zero-data Final (TestZeroDataFinal) -----------------------------------
#
# AES-ECB C_EncryptFinal after Init with zero input passes only on CKR_OK with
# exactly zero output length and an unchanged output buffer; empty SHA-256
# C_DigestFinal passes only on CKR_OK with length 32 and the canonical empty
# digest. Defined standard/vendor Init/Final rejection is not_operational
# xfail; undefined RV, wrong length/digest, or buffer mutation is fail. The
# stale 0x63 premise (CKR_KEY_TYPE_INCONSISTENT misread as
# CKR_BUFFER_TOO_SMALL) is gone: 0x63 is adverse xfail, never pass.

_UNDEFINED_RV = 0x7FFFFFFF
_EMPTY_SHA256 = hashlib.sha256(b"").digest()


def _write_ck_ulong(ptr: Any, value: int) -> None:
    ctypes.cast(ptr, ctypes.POINTER(CK_ULONG)).contents.value = value


class _ZeroDataRaw:
    """Scriptable fake for the zero-data Final paths.

    ``final_len``/``final_bytes`` describe what the fake module reports through
    the Final out-parameters; ``flip_buffer`` inverts every output byte to
    simulate an out-of-contract write regardless of the production canary fill.
    """

    def __init__(
        self,
        *,
        init_rv: int = int(CKR_OK),
        final_rv: int = int(CKR_OK),
        final_len: int = 0,
        final_bytes: bytes = b"",
        flip_buffer: bool = False,
    ) -> None:
        self._init_rv = init_rv
        self._final_rv = final_rv
        self._final_len = final_len
        self._final_bytes = final_bytes
        self._flip_buffer = flip_buffer

    def C_EncryptInit(self, *_a: object, **_k: object) -> int:  # noqa: N802
        return self._init_rv

    def C_DigestInit(self, *_a: object, **_k: object) -> int:  # noqa: N802
        return self._init_rv

    def _final(self, buf: Any, len_ptr: Any) -> int:
        _write_ck_ulong(len_ptr, self._final_len)
        for index, byte in enumerate(self._final_bytes):
            buf[index] = byte
        if self._flip_buffer:
            for index in range(len(buf)):
                buf[index] ^= 0xFF
        return self._final_rv

    def C_EncryptFinal(self, _sh: int, buf: Any, len_ptr: Any) -> int:  # noqa: N802
        return self._final(buf, len_ptr)

    def C_DigestFinal(self, _sh: int, buf: Any, len_ptr: Any) -> int:  # noqa: N802
        return self._final(buf, len_ptr)

    def __getattr__(self, _name: str) -> Any:
        return lambda *_a: int(CKR_OK)


def _zero_data_session(raw: _ZeroDataRaw) -> SimpleNamespace:
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda name: True)


def _run_encrypt_final(raw: _ZeroDataRaw, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tms, "gen_aes_key_or_xfail", lambda *a, **k: 42)
    tms.TestZeroDataFinal().test_encrypt_final_no_update(_zero_data_session(raw))


def _run_digest_final(raw: _ZeroDataRaw) -> None:
    tms.TestZeroDataFinal().test_digest_final_no_update(_zero_data_session(raw))


def _assert_fail_record(reason: str, kind: str | None) -> None:
    records = get_records()
    assert len(records) == 1
    assert records[0].reason == reason
    assert records[0].kind == kind
    assert records[0].outcome == "fail"


def test_encrypt_final_zero_length_unchanged_buffer_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _run_encrypt_final(_ZeroDataRaw(), monkeypatch)
    assert get_records() == []


def test_encrypt_final_nonzero_length_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_encrypt_final(_ZeroDataRaw(final_len=16), monkeypatch)
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("wrong_result", "crypto")


def test_encrypt_final_buffer_mutation_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_encrypt_final(_ZeroDataRaw(flip_buffer=True), monkeypatch)
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("self_contradiction", "lifecycle")


def test_encrypt_final_key_type_inconsistent_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """0x63 is CKR_KEY_TYPE_INCONSISTENT, not CKR_BUFFER_TOO_SMALL: adverse xfail."""
    assert int(CKR_KEY_TYPE_INCONSISTENT) == 0x63
    assert_xfails(
        _run_encrypt_final, _ZeroDataRaw(final_rv=int(CKR_KEY_TYPE_INCONSISTENT)), monkeypatch
    )
    records = get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].actual_ckr == ckr_name(int(CKR_KEY_TYPE_INCONSISTENT))
    assert records[0].operation == "C_EncryptFinal"


def test_encrypt_final_real_buffer_too_small_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    assert int(CKR_BUFFER_TOO_SMALL) == 0x150
    assert_xfails(_run_encrypt_final, _ZeroDataRaw(final_rv=int(CKR_BUFFER_TOO_SMALL)), monkeypatch)
    records = get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].actual_ckr == ckr_name(int(CKR_BUFFER_TOO_SMALL))


def test_encrypt_final_data_len_range_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    assert_xfails(_run_encrypt_final, _ZeroDataRaw(final_rv=int(CKR_DATA_LEN_RANGE)), monkeypatch)
    assert get_records()[-1].reason == "not_operational"


def test_encrypt_init_clean_refusal_xfails_not_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """Init rejection is adverse not_operational evidence, never a capability skip."""
    assert_xfails(_run_encrypt_final, _ZeroDataRaw(init_rv=int(CKR_FUNCTION_FAILED)), monkeypatch)
    records = get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_EncryptInit"


def test_encrypt_final_undefined_rv_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_encrypt_final(_ZeroDataRaw(final_rv=_UNDEFINED_RV), monkeypatch)
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("self_contradiction", "metadata")


def test_encrypt_init_undefined_rv_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    try:
        _run_encrypt_final(_ZeroDataRaw(init_rv=_UNDEFINED_RV), monkeypatch)
    except Skipped as exc:
        pytest.fail(f"undefined Init RV must fail, not skip: {exc}")
    except XFailed as exc:
        pytest.fail(f"undefined Init RV must fail, not xfail: {exc}")
    except Failed:
        pass
    else:
        pytest.fail("undefined Init RV must fail, but the test passed")
    _assert_fail_record("self_contradiction", "metadata")


def test_digest_final_canonical_empty_passes() -> None:
    _run_digest_final(_ZeroDataRaw(final_len=32, final_bytes=_EMPTY_SHA256))
    assert get_records() == []


def test_digest_final_wrong_length_fails() -> None:
    with pytest.raises(Failed) as ei:
        _run_digest_final(_ZeroDataRaw(final_len=20, final_bytes=_EMPTY_SHA256[:20]))
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("wrong_result", "crypto")


def test_digest_final_wrong_value_fails() -> None:
    with pytest.raises(Failed) as ei:
        _run_digest_final(_ZeroDataRaw(final_len=32, final_bytes=b"\x00" * 32))
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("wrong_result", "crypto")


def test_digest_final_clean_refusal_xfails_not_skips() -> None:
    assert_xfails(_run_digest_final, _ZeroDataRaw(final_rv=int(CKR_FUNCTION_FAILED)))
    records = get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_DigestFinal"


def test_digest_init_clean_refusal_xfails_not_skips() -> None:
    assert_xfails(_run_digest_final, _ZeroDataRaw(init_rv=int(CKR_FUNCTION_FAILED)))
    assert get_records()[-1].reason == "not_operational"


def test_digest_final_undefined_rv_fails() -> None:
    try:
        _run_digest_final(_ZeroDataRaw(final_rv=_UNDEFINED_RV))
    except Skipped as exc:
        pytest.fail(f"undefined Final RV must fail, not skip: {exc}")
    except XFailed as exc:
        pytest.fail(f"undefined Final RV must fail, not xfail: {exc}")
    except Failed:
        pass
    else:
        pytest.fail("undefined Final RV must fail, but the test passed")
    _assert_fail_record("self_contradiction", "metadata")
