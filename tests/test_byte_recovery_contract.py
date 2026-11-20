"""Contract tests for 1-byte recovery verdicts (#54.3)."""

from __future__ import annotations

import ctypes
import hashlib
import sys
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, Skipped, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.types_std import (
    CK_KEY_DERIVATION_STRING_DATA,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKM_EXTRACT_KEY_FROM_KEY,
    CKM_XOR_BASE_AND_DATA,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import test_misc_kdf as kdf


def test_recovery_refused_passes() -> None:
    kdf._judge_byte_recovery(
        derive_rv=int(CKR_TEMPLATE_INCONSISTENT),
        recovered=False,
        control_ok=True,
        label="sealed",
    )
    assert classification.get_records() == []


def test_recovery_capability_refused_passes() -> None:
    # Refusal needs no oracle: the chain is blocked either way.
    kdf._judge_byte_recovery(
        derive_rv=int(CKR_MECHANISM_INVALID),
        recovered=False,
        control_ok=False,
        label="sealed",
    )
    assert classification.get_records() == []


def test_recovery_recovered_fails() -> None:
    with pytest.raises(Failed):
        kdf._judge_byte_recovery(
            derive_rv=int(CKR_OK), recovered=True, control_ok=True, label="sealed"
        )


def test_recovery_recovered_control_less_fails() -> None:
    # A match is self-evident: no oracle needed to interpret it.
    with pytest.raises(Failed):
        kdf._judge_byte_recovery(
            derive_rv=int(CKR_OK), recovered=True, control_ok=False, label="sealed"
        )


def test_recovery_unproven_xfails_with_control() -> None:
    with pytest.raises(XFailed):
        kdf._judge_byte_recovery(
            derive_rv=int(CKR_OK), recovered=False, control_ok=True, label="sealed"
        )


def test_recovery_unproven_skips_without_control() -> None:
    with pytest.raises(Skipped):
        kdf._judge_byte_recovery(
            derive_rv=int(CKR_OK), recovered=False, control_ok=False, label="sealed"
        )


def test_recovery_blocked_xfails_with_control() -> None:
    with pytest.raises(XFailed):
        kdf._judge_byte_recovery(
            derive_rv=int(CKR_OK), recovered=None, control_ok=True, label="sealed"
        )


def test_recovery_blocked_skips_without_control() -> None:
    with pytest.raises(Skipped):
        kdf._judge_byte_recovery(
            derive_rv=int(CKR_OK), recovered=None, control_ok=False, label="sealed"
        )


def test_recovery_undefined_rv_fails() -> None:
    with pytest.raises(Failed):
        kdf._judge_byte_recovery(derive_rv=0xDEAD, recovered=False, control_ok=True, label="sealed")


def test_recovery_vendor_derive_xfails_alternate() -> None:
    """B2: a vendor derive refusal is a visible alternate, never a silent pass."""
    with pytest.raises(XFailed):
        kdf._judge_byte_recovery(
            derive_rv=0x80000001, recovered=False, control_ok=True, label="sealed"
        )
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "xfail"]
    assert record.reason == "nonspec_reject", record.summary


def test_recovery_blocked_carries_digest_stage() -> None:
    """B2: the blocked residual retains the digest operation and RV."""
    with pytest.raises(XFailed):
        kdf._judge_byte_recovery(
            derive_rv=int(CKR_OK),
            recovered=None,
            control_ok=True,
            label="sealed",
            digest_op="C_DigestFinal",
            digest_rv=int(CKR_DEVICE_ERROR),
        )
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "xfail"]
    assert "C_DigestFinal CKR_DEVICE_ERROR" in (record.summary or ""), record.summary
    assert record.operation == "C_DigestFinal", record.operation
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.summary
    assert (record.detail or {}).get("digest_operation") == "C_DigestFinal", record.detail
    assert (record.detail or {}).get("digest_rv") == "CKR_DEVICE_ERROR", record.detail


def test_recovery_opaque_refusal_xfails_unproved() -> None:
    """R2A4: an opaque derive refusal voids visibly instead of passing silently."""
    with pytest.raises(XFailed):
        kdf._judge_byte_recovery(
            derive_rv=int(CKR_DEVICE_ERROR),
            recovered=False,
            control_ok=True,
            label="sealed",
        )
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "xfail"]
    assert record.reason == "not_operational", record.summary
    assert record.actual_ckr == "CKR_DEVICE_ERROR", record.summary
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail


def _tval(tmpl: Any, count: int, attr: int) -> bytes:
    for i in range(int(count)):
        if int(tmpl[i].type) == int(attr):
            length = int(tmpl[i].ulValueLen)
            if tmpl[i].pValue is None or length == 0:
                return b""
            return bytes(ctypes.string_at(tmpl[i].pValue, length))
    return b""


class _FakeKdfRaw:
    """Byte-exact KDF fake: imports, mechanism-faithful derives, SHA-256 digests."""

    def __init__(self) -> None:
        self.objects: dict[int, bytes] = {}
        self.sealed: dict[int, bool] = {}
        self.extractable: dict[int, bool] = {}
        self.labels: dict[int, bytes] = {}
        self.refuse_sealed = False
        self.refusal_out_handle: int | None = None
        self.derive_child_override: int | None = None
        self.derive_label_override: bytes | None = None
        self.label_read_rv: int | None = None
        self.digest_query_len: int | None = None
        self.digest_read_len: int | None = None
        self.derive_child_len: int | None = None
        self.value_read_rv: int | None = None
        self.digest_init_rv: int | None = None
        self.digest_key_rv: int | None = None
        self.digest_final_rv: int | None = None
        self.destroyed: list[int] = []
        self._next = 0
        self._pending: bytes | None = None
        self.derive_data: list[bytes] = []

    def C_CreateObject(self, _sh: int, tmpl: Any, count: int, handle_ptr: Any) -> int:  # noqa: N802
        self._next += 1
        self.objects[self._next] = _tval(tmpl, count, int(CKA_VALUE))
        self.sealed[self._next] = _tval(tmpl, count, int(CKA_SENSITIVE)) == b"\x01"
        self.extractable[self._next] = _tval(tmpl, count, int(CKA_EXTRACTABLE)) == b"\x01"
        self.labels[self._next] = _tval(tmpl, count, int(CKA_LABEL))
        ctypes.cast(handle_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = self._next
        return int(CKR_OK)

    def C_GetAttributeValue(self, _sh: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        for i in range(int(count)):
            attr = int(tmpl[i].type)
            if attr == int(CKA_SENSITIVE):
                value = b"\x01" if self.sealed.get(int(handle), False) else b"\x00"
            elif attr == int(CKA_EXTRACTABLE):
                value = b"\x01" if self.extractable.get(int(handle), False) else b"\x00"
            elif attr == int(CKA_LABEL):
                # R3F2: label reads serve adoption correlation.
                if self.label_read_rv is not None:
                    return self.label_read_rv
                if int(handle) not in self.labels:
                    return int(CKR_OBJECT_HANDLE_INVALID)
                value = self.labels[int(handle)]
            elif attr == int(CKA_VALUE):
                # R3F5: value reads serve the 1-byte-oracle length gate.
                if self.value_read_rv is not None:
                    return self.value_read_rv
                blob = self.objects.get(int(handle))
                if blob is None:
                    return int(CKR_OBJECT_HANDLE_INVALID)
                value = blob
            else:
                raise AssertionError(f"fake serves only seal flags, label, value, got {attr:#x}")
            if tmpl[i].pValue is None:
                tmpl[i].ulValueLen = len(value)
            else:
                ctypes.memmove(tmpl[i].pValue, value, len(value))
                tmpl[i].ulValueLen = len(value)
        return int(CKR_OK)

    def C_DeriveKey(  # noqa: N802
        self, _sh: int, _mech: Any, base: int, tmpl: Any, count: int, handle_ptr: Any
    ) -> int:
        mech = ctypes.cast(_mech, ctypes.POINTER(CK_MECHANISM)).contents
        mech_id = int(mech.mechanism)
        base_bytes = self.objects[int(base)]
        if mech_id == int(CKM_XOR_BASE_AND_DATA):
            params = ctypes.cast(
                mech.pParameter, ctypes.POINTER(CK_KEY_DERIVATION_STRING_DATA)
            ).contents
            data = bytes(ctypes.string_at(params.pData, int(params.ulLen)))
            self.derive_data.append(data)
            child = bytes([base_bytes[0] ^ data[0]])
        elif mech_id == int(CKM_EXTRACT_KEY_FROM_KEY):
            child = base_bytes[:1]
        else:
            raise AssertionError(f"fake cannot derive mechanism {mech_id:#x}")
        # The recovery oracle is a 1-byte child by construction; any other
        # EXPLICIT requested length is a source bug, failed loud here. An
        # omitted length takes the provider default (R3F5).
        raw_len = _tval(tmpl, count, int(CKA_VALUE_LEN))
        if raw_len == b"":
            default_len = self.derive_child_len if self.derive_child_len is not None else 1
            child = child * default_len
        else:
            value_len = int.from_bytes(raw_len, sys.byteorder)
            assert value_len == 1, value_len
            if self.derive_child_len is not None:
                child = child * self.derive_child_len
        if self.refuse_sealed and self.sealed.get(int(base), False):
            if self.refusal_out_handle is not None:
                ctypes.cast(
                    handle_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)
                ).contents.value = self.refusal_out_handle
            return int(CKR_TEMPLATE_INCONSISTENT)
        if self.derive_child_override is not None:
            # R3F2: succeed with a chosen (possibly foreign) handle; filed
            # with no label so adoption correlation faces it honestly.
            ctypes.cast(
                handle_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)
            ).contents.value = self.derive_child_override
            return int(CKR_OK)
        self._next += 1
        self.objects[self._next] = child
        self.sealed[self._next] = self.sealed.get(int(base), False)
        self.extractable[self._next] = self.extractable.get(int(base), False)
        if self.derive_label_override is not None:
            self.labels[self._next] = self.derive_label_override
        else:
            self.labels[self._next] = _tval(tmpl, count, int(CKA_LABEL))
        ctypes.cast(handle_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = self._next
        return int(CKR_OK)

    def C_DigestInit(self, _sh: int, _mech: Any) -> int:  # noqa: N802
        if self.digest_init_rv is not None:
            return self.digest_init_rv
        self._pending = None
        return int(CKR_OK)

    def C_DigestKey(self, _sh: int, key: int) -> int:  # noqa: N802
        if self.digest_key_rv is not None:
            return self.digest_key_rv
        self._pending = self.objects[int(key)]
        return int(CKR_OK)

    def C_DigestFinal(self, _sh: int, buf: Any, len_ptr: Any) -> int:  # noqa: N802
        if self.digest_final_rv is not None:
            return self.digest_final_rv
        digest = hashlib.sha256(self._pending or b"").digest()
        out_len = ctypes.cast(len_ptr, ctypes.POINTER(CK_ULONG)).contents
        if buf is None:
            if self.digest_query_len is not None:
                out_len.value = self.digest_query_len
            else:
                out_len.value = len(digest)
            return int(CKR_OK)
        ctypes.memmove(buf, digest, len(digest))
        if self.digest_read_len is not None:
            out_len.value = self.digest_read_len
        else:
            out_len.value = len(digest)
        return int(CKR_OK)

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        self.destroyed.append(int(handle))
        self.objects.pop(int(handle), None)
        return int(CKR_OK)


def _kdf_rs(*, refuse_sealed: bool = False) -> Any:
    fake = _FakeKdfRaw()
    fake.refuse_sealed = refuse_sealed
    return SimpleNamespace(raw=fake, sh=7)


def test_recovery_end_to_end_extract_finds_recovery() -> None:
    rs = _kdf_rs()
    with pytest.raises(Failed):
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")
    assert any(
        "recovered through 1-byte child" in rec.summary for rec in classification.get_records()
    )


def test_recovery_end_to_end_xor_full_finds_recovery() -> None:
    rs = _kdf_rs()
    with pytest.raises(Failed):
        kdf._run_byte_recovery_case(rs, shape="xor_full", label="t")
    assert any(
        "recovered through 1-byte child" in rec.summary for rec in classification.get_records()
    )
    # Both legs (control + sealed) carry the full 32-byte pad datum.
    assert rs.raw.derive_data == [kdf._RECOVERY_XOR_FULL_DATA] * 2


def test_recovery_end_to_end_xor_zeros_finds_recovery() -> None:
    """R3.2: the xor_zeros arm passes 32 zero data bytes; the 1-byte child recovers."""
    rs = _kdf_rs()
    with pytest.raises(Failed):
        kdf._run_byte_recovery_case(rs, shape="xor_zeros", label="t")
    assert any(
        "recovered through 1-byte child" in rec.summary for rec in classification.get_records()
    )
    # Both legs (control + sealed) carry the full 32-byte zero pad, not a 1-byte datum.
    assert rs.raw.derive_data == [b"\x00" * 32, b"\x00" * 32]


def test_recovery_end_to_end_xor_short_finds_recovery() -> None:
    """Pre-review 3: the distinct short-data stimulus recovers end to end."""
    rs = _kdf_rs()
    with pytest.raises(Failed):
        kdf._run_byte_recovery_case(rs, shape="xor_short", label="t")
    assert any(
        "recovered through 1-byte child" in rec.summary for rec in classification.get_records()
    )
    # Both legs carry the 1-byte datum: short input, not short output.
    assert rs.raw.derive_data == [kdf._RECOVERY_XOR_SHORT_DATA] * 2
    assert len(kdf._RECOVERY_XOR_SHORT_DATA) == 1


def test_recovery_end_to_end_refused_passes() -> None:
    rs = _kdf_rs(refuse_sealed=True)
    kdf._run_byte_recovery_case(rs, shape="extract", label="t")
    assert classification.get_records() == []


def test_recovery_refused_out_handle_not_destroyed() -> None:
    """R2A1: a refused derive must not donate its output handle to cleanup."""
    rs = _kdf_rs(refuse_sealed=True)
    rs.raw.refusal_out_handle = 3  # the sealed base itself
    kdf._run_byte_recovery_case(rs, shape="extract", label="t")
    assert rs.raw.destroyed == [2, 1, 3], rs.raw.destroyed


@pytest.mark.parametrize(
    ("knob", "operation"),
    [
        ("digest_init_rv", "C_DigestInit"),
        ("digest_key_rv", "C_DigestKey"),
        ("digest_final_rv", "C_DigestFinal"),
    ],
)
def test_digest_staged_attributes_refusing_stage(knob: str, operation: str) -> None:
    """R2A4: a refused digest stage reports its own operation and RV."""
    rs = _kdf_rs()
    rs.raw.objects[99] = b"seed"
    setattr(rs.raw, knob, int(CKR_DEVICE_ERROR))
    with pytest.raises(kdf._DigestStageRefusedError) as excinfo:
        kdf._digest_child_staged(rs, 99)
    assert excinfo.value.operation == operation
    assert excinfo.value.rv == int(CKR_DEVICE_ERROR)


def test_recovery_child_aliasing_base_fails_without_destroy() -> None:
    """R3F2: a derive returning its own base handle fails; the base is cleaned once."""
    rs = _kdf_rs()
    rs.raw.derive_child_override = 1  # the control base itself
    with pytest.raises(Failed, match="alias"):
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")
    # The base's own import-cleanup runs exactly once; the unadopted
    # child output never donates a second destroy of the same handle.
    assert rs.raw.destroyed == [1], rs.raw.destroyed


def test_recovery_child_foreign_handle_with_unreadable_label_skips() -> None:
    """R3F2: an unprovable child voids the leg; never used, never destroyed."""
    rs = _kdf_rs()
    rs.raw.derive_child_override = 999
    with pytest.raises(Skipped, match="ownership unproved"):
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")
    assert 999 not in rs.raw.destroyed, rs.raw.destroyed
    assert rs.raw._pending is None


def test_recovery_child_label_mismatch_fails_without_destroy() -> None:
    """R3F2: a child whose label is not the attempt label fails unadopted."""
    rs = _kdf_rs()
    rs.raw.derive_label_override = b"not-the-attempt-label"
    with pytest.raises(Failed, match="label"):
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")
    assert 2 not in rs.raw.destroyed, rs.raw.destroyed


def test_recovery_child_label_undefined_rv_fails_loud() -> None:
    """R3F2: an undefined label-read RV fails loud, never voids quietly."""
    rs = _kdf_rs()
    rs.raw.label_read_rv = 0x7FFFFFFF
    with pytest.raises(Failed, match="undefined") as exc_info:
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")
    # XFailed subclasses Failed: require the plain failure exactly.
    assert type(exc_info.value) is Failed, exc_info.value


def test_recovery_child_label_vendor_rv_xfails_loud() -> None:
    """R3F2: a vendor label-read RV xfails visibly (never a quiet skip)."""
    rs = _kdf_rs()
    rs.raw.label_read_rv = 0x80000001
    with pytest.raises(XFailed, match="ownership unproved"):
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")


def test_digest_query_length_defect_fails_loud() -> None:
    """R3F5: a non-32 size query on SHA-256 fails (never sizes the buffer)."""
    rs = _kdf_rs()
    rs.raw.digest_query_len = 64
    with pytest.raises(Failed, match="length"):
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")


def test_digest_read_overrun_fails_loud() -> None:
    """R3F5: CKR_OK claiming past capacity fails (never silently truncates)."""
    rs = _kdf_rs()
    rs.raw.digest_read_len = 64
    with pytest.raises(Failed, match="length"):
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")


def test_digest_short_read_fails_loud() -> None:
    """R3F5: a short SHA-256 read fails (never feeds a truncated oracle)."""
    rs = _kdf_rs()
    rs.raw.digest_read_len = 16
    with pytest.raises(Failed, match="length"):
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")


def test_digest_staged_overrun_carries_lengths() -> None:
    """R3F5: the length defect reports query vs observed lengths typed."""
    rs = _kdf_rs()
    rs.raw.objects[99] = b"seed"
    rs.raw.digest_read_len = 64
    with pytest.raises(kdf._DigestLengthDefectError) as exc_info:
        kdf._digest_child_staged(rs, 99)
    assert exc_info.value.operation == "C_DigestFinal"
    assert exc_info.value.query_len == 32
    assert exc_info.value.observed_len == 64


def test_digest_unsupported_carries_stage_and_rv() -> None:
    """R3F5: an unsupported DigestKey keeps its stage and raw RV."""
    rs = _kdf_rs()
    rs.raw.objects[99] = b"seed"
    rs.raw.digest_key_rv = int(CKR_FUNCTION_NOT_SUPPORTED)
    with pytest.raises(kdf._DigestUnsupportedError) as exc_info:
        kdf._recover_byte_via_digest(rs, 99)
    assert exc_info.value.operation == "C_DigestKey"
    assert exc_info.value.rv == int(CKR_FUNCTION_NOT_SUPPORTED)


def test_control_digest_unsupported_skip_names_rv() -> None:
    """R3F5: the control unsupported-skip names the stage RV."""
    rs = _kdf_rs()
    rs.raw.digest_key_rv = int(CKR_FUNCTION_NOT_SUPPORTED)
    with pytest.raises(Skipped, match="CKR_FUNCTION_NOT_SUPPORTED"):
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")


def test_sealed_recovery_attempt_captures_unsupported() -> None:
    """R3F5: a sealed unsupported digest rides as (blocked, op, RV)."""
    rs = _kdf_rs()
    rs.raw.objects[99] = b"seed"
    rs.raw.digest_key_rv = int(CKR_FUNCTION_NOT_SUPPORTED)
    found, op, rv = kdf._attempt_sealed_recovery(rs, 99, label="t")
    assert found is None
    assert op == "C_DigestKey"
    assert rv == int(CKR_FUNCTION_NOT_SUPPORTED)


def test_recovery_short_default_length_row_finds_recovery() -> None:
    """R3F5: short input with omitted length runs the oracle on the default."""
    rs = _kdf_rs()
    with pytest.raises(Failed):
        kdf._run_byte_recovery_case(rs, shape="xor_short_default", label="t")
    assert any(
        "recovered through 1-byte child" in rec.summary for rec in classification.get_records()
    )


def test_recovery_short_default_nonunit_skips() -> None:
    """R3F5: a non-1-byte provider default voids the 1-byte oracle honestly."""
    rs = _kdf_rs()
    rs.raw.derive_child_len = 32
    with pytest.raises(Skipped, match="default"):
        kdf._run_byte_recovery_case(rs, shape="xor_short_default", label="t")


def test_recovery_explicit_length_mismatch_skips() -> None:
    """R3F5: a child ignoring explicit length voids calibration (never KAT-fails)."""
    rs = _kdf_rs()
    rs.raw.derive_child_len = 32
    with pytest.raises(Skipped, match="1-byte"):
        kdf._run_byte_recovery_case(rs, shape="xor_short", label="t")


def test_recovery_child_length_unreadable_skips() -> None:
    """R3F5: an unreadable control length voids the oracle (never assumes)."""
    rs = _kdf_rs()
    rs.raw.value_read_rv = int(CKR_DEVICE_ERROR)
    with pytest.raises(Skipped, match="unreadable"):
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")
