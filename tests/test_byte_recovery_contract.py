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
from pkcs11_check.raw.pack import template, template_ptr_count
from pkcs11_check.raw.pack_mechanisms import mech_string_data
from pkcs11_check.raw.recipes import pack_attrs
from pkcs11_check.raw.types_std import (
    CK_KEY_DERIVATION_STRING_DATA,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_CDMF,
    CKK_DES,
    CKK_DES2,
    CKK_DES3,
    CKK_GENERIC_SECRET,
    CKM_EXTRACT_KEY_FROM_KEY,
    CKM_XOR_BASE_AND_DATA,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
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


def _tpresent(tmpl: Any, count: int, attr: int) -> bool:
    """Whether the template carries ``attr`` at all (R4-F5 rule input)."""
    return any(int(tmpl[i].type) == int(attr) for i in range(int(count)))


#: Key types with a well-defined length for the XOR four-case rule
#: (PKCS#11 v3.0 §2.43.6 = v3.2 §6.43.6: a type-only template needs one;
#: anything absent here -- generic secret, AES, ... -- refuses).
_XOR_WELL_DEFINED_LEN: dict[int, int] = {
    int(CKK_DES): 8,
    int(CKK_DES2): 16,
    int(CKK_DES3): 24,
    int(CKK_CDMF): 8,
}


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
        self.derive_refuse_rv: int | None = None
        self.label_refusal_ckr: int | None = None
        self.label_leak = False
        self.destroy_rv: int | None = None
        self.refuse_sealed_digest = False
        self.refuse_sealed_destroy = False
        self.len_omitted_accept_len: int | None = None
        self.derive_child_bytes: bytes | None = None
        self.refuse_unsealed = False
        self.destroyed: list[int] = []
        self._next = 0
        self._pending: bytes | None = None
        self.derive_data: list[bytes] = []
        self.derive_templates: list[set[int]] = []

    def C_CreateObject(self, _sh: int, tmpl: Any, count: int, handle_ptr: Any) -> int:  # noqa: N802
        self._next += 1
        self.objects[self._next] = _tval(tmpl, count, int(CKA_VALUE))
        self.sealed[self._next] = _tval(tmpl, count, int(CKA_SENSITIVE)) == b"\x01"
        self.extractable[self._next] = _tval(tmpl, count, int(CKA_EXTRACTABLE)) == b"\x01"
        self.labels[self._next] = _tval(tmpl, count, int(CKA_LABEL))
        ctypes.cast(handle_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = self._next
        return int(CKR_OK)

    def C_GetAttributeValue(self, _sh: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        leak = False
        for i in range(int(count)):
            attr = int(tmpl[i].type)
            if attr == int(CKA_SENSITIVE):
                value = b"\x01" if self.sealed.get(int(handle), False) else b"\x00"
            elif attr == int(CKA_EXTRACTABLE):
                value = b"\x01" if self.extractable.get(int(handle), False) else b"\x00"
            elif attr == int(CKA_LABEL):
                # R3F2: label reads serve adoption correlation.
                if self.label_refusal_ckr is not None:
                    # R4: ABI-faithful refusals-channel response: the RV
                    # plus the CK_UNAVAILABLE_INFORMATION sentinel, exactly
                    # as production receives it (read_attributes raises
                    # nothing for SENSITIVE/TYPE_INVALID).
                    tmpl[i].ulValueLen = int(CK_UNAVAILABLE_INFORMATION)
                    return self.label_refusal_ckr
                if self.label_read_rv is not None:
                    return self.label_read_rv
                if int(handle) not in self.labels:
                    return int(CKR_OBJECT_HANDLE_INVALID)
                value = self.labels[int(handle)]
                leak = self.label_leak
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
        if leak:
            # R4: refusal-with-data: the bytes are served but the call
            # still answers SENSITIVE (production must fail, not adopt).
            return int(CKR_ATTRIBUTE_SENSITIVE)
        return int(CKR_OK)

    def _rule_refusal(self) -> int:
        """The XOR rule-error RV (INCOMPLETE default, scriptable)."""
        if self.derive_refuse_rv is not None:
            return self.derive_refuse_rv
        return int(CKR_TEMPLATE_INCOMPLETE)

    def C_DeriveKey(  # noqa: N802
        self, _sh: int, _mech: Any, base: int, tmpl: Any, count: int, handle_ptr: Any
    ) -> int:
        self.derive_templates.append({int(tmpl[i].type) for i in range(int(count))})
        mech = ctypes.cast(_mech, ctypes.POINTER(CK_MECHANISM)).contents
        mech_id = int(mech.mechanism)
        base_bytes = self.objects[int(base)]
        if mech_id == int(CKM_XOR_BASE_AND_DATA):
            params = ctypes.cast(
                mech.pParameter, ctypes.POINTER(CK_KEY_DERIVATION_STRING_DATA)
            ).contents
            data = bytes(ctypes.string_at(params.pData, int(params.ulLen)))
            self.derive_data.append(data)
            # R4-F5: PKCS#11 v3.0 §2.43.6 (= v3.2 §6.43.6) four-case rule,
            # derived from the actual template and input lengths -- never
            # an invented default.
            full = bytes(a ^ b for a, b in zip(base_bytes, data, strict=False))
            available = len(full)
            has_type = _tpresent(tmpl, count, int(CKA_KEY_TYPE))
            raw_len = _tval(tmpl, count, int(CKA_VALUE_LEN))
            if raw_len == b"" and not has_type:
                # Specified default: generic secret of min(data, base).
                child = full
                if self.derive_child_len is not None:
                    # Mutation hook: a non-conforming provider default.
                    child = child[:1] * self.derive_child_len
            elif raw_len != b"" and not has_type:
                # Length without type: generic secret of that length.
                want = int.from_bytes(raw_len, sys.byteorder)
                if want > available:
                    return self._rule_refusal()
                child = full[:want]
            elif raw_len == b"" and has_type:
                # Type without length: needs a well-defined length, else
                # an error is returned; the length must also be available.
                key_type = int.from_bytes(_tval(tmpl, count, int(CKA_KEY_TYPE)), sys.byteorder)
                well = _XOR_WELL_DEFINED_LEN.get(key_type)
                if well is None or well > available:
                    if self.len_omitted_accept_len is None:
                        return self._rule_refusal()
                    # Mutation hook: a lenient provider accepting the
                    # deviant form with a provider-chosen length.
                    pad = full[:1] if full else b"\x00"
                    child = pad * self.len_omitted_accept_len
                else:
                    child = full[:well]
            else:
                # Both present: the explicit length rules. The recovery
                # oracle is a 1-byte child by construction; any other
                # EXPLICIT requested length is a source bug, failed loud.
                value_len = int.from_bytes(raw_len, sys.byteorder)
                assert value_len == 1, value_len
                child = full[:1]
                if self.derive_child_len is not None:
                    child = child * self.derive_child_len
        elif mech_id == int(CKM_EXTRACT_KEY_FROM_KEY):
            child = base_bytes[:1]
            raw_len = _tval(tmpl, count, int(CKA_VALUE_LEN))
            value_len = int.from_bytes(raw_len, sys.byteorder)
            assert value_len == 1, value_len
            if self.derive_child_len is not None:
                child = child * self.derive_child_len
        else:
            raise AssertionError(f"fake cannot derive mechanism {mech_id:#x}")
        if self.refuse_sealed and self.sealed.get(int(base), False):
            if self.refusal_out_handle is not None:
                ctypes.cast(
                    handle_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)
                ).contents.value = self.refusal_out_handle
            return int(CKR_TEMPLATE_INCONSISTENT)
        if self.refuse_unsealed and not self.sealed.get(int(base), False):
            return int(CKR_TEMPLATE_INCONSISTENT)
        if self.derive_child_override is not None:
            # R3F2: succeed with a chosen (possibly foreign) handle; filed
            # with no label so adoption correlation faces it honestly.
            ctypes.cast(
                handle_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)
            ).contents.value = self.derive_child_override
            return int(CKR_OK)
        self._next += 1
        if self.derive_child_bytes is not None:
            # Mutation hook: file caller-chosen bytes instead of the rule output.
            child = self.derive_child_bytes
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
        if self.refuse_sealed_digest and self.sealed.get(int(key), False):
            return int(CKR_DEVICE_ERROR)
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
        if self.destroy_rv is not None:
            # R4: a refused destroy retains the object (production must
            # observe the RV instead of assuming teardown happened).
            return self.destroy_rv
        if self.refuse_sealed_destroy and self.sealed.get(int(handle), False):
            return int(CKR_DEVICE_ERROR)
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


def test_recovery_child_label_refusals_channel_skips() -> None:
    """R4-F2: an unreadable label voids the leg; unreadable is not mismatching."""
    rs = _kdf_rs()
    rs.raw.label_refusal_ckr = int(CKR_ATTRIBUTE_SENSITIVE)
    with pytest.raises(Skipped, match="ownership unproved"):
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")
    assert 2 not in rs.raw.destroyed, rs.raw.destroyed


def test_recovery_child_label_refusal_with_data_fails() -> None:
    """R4-F2: a refusal that still wrote bytes fails (never adopts, never skips)."""
    rs = _kdf_rs()
    rs.raw.label_leak = True
    with pytest.raises(Failed) as exc_info:
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")
    assert "wrote" in str(exc_info.value), str(exc_info.value)
    assert 2 not in rs.raw.destroyed, rs.raw.destroyed


def test_recovery_adoption_requires_leg_stamp() -> None:
    """R4-F2: adoption correlates the per-leg stamp, not the bare case label."""
    rs = _kdf_rs()
    rs.raw.labels[60] = b"t:sealed"
    assert kdf._adopt_recovery_child(rs, 60, 55, label="t", leg="sealed") == 60


def test_recovery_adoption_rejects_other_leg_stamp() -> None:
    """R4-F2: a control-stamped handle never satisfies the sealed leg."""
    rs = _kdf_rs()
    rs.raw.labels[61] = b"t:control"
    with pytest.raises(Failed, match="not the attempt label"):
        kdf._adopt_recovery_child(rs, 61, 55, label="t", leg="sealed")


def test_recovery_control_teardown_refused_fails() -> None:
    """R4-F2: a refused control-child destroy fails; a retained child never leaks on."""
    rs = _kdf_rs(refuse_sealed=True)
    rs.raw.destroy_rv = int(CKR_DEVICE_ERROR)
    try:
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")
    except XFailed as exc:
        pytest.fail(f"control teardown refusal xfailed instead of failing: {exc}")
    except Failed as exc:
        assert type(exc) is Failed, exc
        assert "estroy" in str(exc), str(exc)
    else:
        pytest.fail("control teardown refusal passed instead of failing")


def test_recovery_sealed_teardown_refused_fails() -> None:
    """R4-F2: a refused sealed-child destroy fails even when the verdict xfails."""
    rs = _kdf_rs()
    rs.raw.refuse_sealed_digest = True
    rs.raw.refuse_sealed_destroy = True
    try:
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")
    except XFailed as exc:
        pytest.fail(f"sealed teardown refusal xfailed instead of failing: {exc}")
    except Failed as exc:
        assert type(exc) is Failed, exc
        assert "estroy" in str(exc), str(exc)
    else:
        pytest.fail("sealed teardown refusal passed instead of failing")


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
    # R4-F5: both legs requested the specified default (neither type nor
    # length in the template) -- the 1-byte child came from the rule.
    assert len(rs.raw.derive_templates) == 2, rs.raw.derive_templates
    for tmpl_attrs in rs.raw.derive_templates:
        assert int(CKA_KEY_TYPE) not in tmpl_attrs, tmpl_attrs
        assert int(CKA_VALUE_LEN) not in tmpl_attrs, tmpl_attrs


def test_recovery_short_default_nonunit_fails() -> None:
    """R4-F5: the specified default is min(data, base) = 1; anything else fails."""
    rs = _kdf_rs()
    rs.raw.derive_child_len = 32
    try:
        kdf._run_byte_recovery_case(rs, shape="xor_short_default", label="t")
    except Failed as exc:
        assert "default" in str(exc), str(exc)
    except Skipped as exc:
        pytest.fail(f"non-conforming default skipped instead of failing: {exc}")
    else:
        pytest.fail("non-conforming default passed instead of failing")


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


def _xor_rule_derive(
    fake: _FakeKdfRaw, *, base: bytes, data: bytes, attrs: dict[int, Any]
) -> tuple[int, bytes | None]:
    """Drive the fake XOR derive directly; return (rv, child bytes or None)."""
    fake.objects[50] = base
    fake.sealed[50] = False
    fake.extractable[50] = True
    fake.labels[50] = b"rule-base"
    tmpl = template(*pack_attrs(attrs))
    ptr, count = template_ptr_count(tmpl)
    mech = mech_string_data(int(CKM_XOR_BASE_AND_DATA), data)
    handle = CK_OBJECT_HANDLE(0)
    rv = fake.C_DeriveKey(7, mech.byref(), 50, ptr, count, ctypes.byref(handle))
    child = int(handle.value)
    return int(rv), (fake.objects.get(child) if rv == int(CKR_OK) else None)


def _xor_pairwise(base: bytes, data: bytes, length: int) -> bytes:
    return bytes(a ^ b for a, b in zip(base, data, strict=False))[:length]


@pytest.mark.parametrize(("base_len", "data_len"), [(32, 1), (1, 32), (8, 8)])
def test_fake_xor_rule_both_omitted_derives_min_length(base_len: int, data_len: int) -> None:
    """R4-F5: neither type nor length -> generic secret of min(data, base)."""
    fake = _FakeKdfRaw()
    base = bytes(range(base_len))
    data = bytes([0x5A]) * data_len
    rv, child = _xor_rule_derive(fake, base=base, data=data, attrs={int(CKA_LABEL): "t"})
    assert rv == int(CKR_OK), rv
    assert child == _xor_pairwise(base, data, min(base_len, data_len)), child


def test_fake_xor_rule_type_only_generic_refuses() -> None:
    """R4-F5: generic secret has no well-defined length -> an error is returned."""
    fake = _FakeKdfRaw()
    rv, child = _xor_rule_derive(
        fake,
        base=bytes(range(32)),
        data=b"\x5a",
        attrs={int(CKA_KEY_TYPE): int(CKK_GENERIC_SECRET), int(CKA_LABEL): "t"},
    )
    assert rv == int(CKR_TEMPLATE_INCOMPLETE), rv
    assert child is None


def test_fake_xor_rule_type_only_des_short_data_refuses() -> None:
    """R4-F5: DES needs 8 bytes; 1 input byte cannot supply them -> error."""
    fake = _FakeKdfRaw()
    rv, child = _xor_rule_derive(
        fake,
        base=bytes(range(32)),
        data=b"\x5a",
        attrs={int(CKA_KEY_TYPE): int(CKK_DES), int(CKA_LABEL): "t"},
    )
    assert rv == int(CKR_TEMPLATE_INCOMPLETE), rv
    assert child is None


def test_fake_xor_rule_type_only_des_long_data_derives_8() -> None:
    """R4-F5: DES has a well-defined length; long inputs derive 8 bytes."""
    fake = _FakeKdfRaw()
    base = bytes(range(32))
    data = bytes([0x5A]) * 32
    rv, child = _xor_rule_derive(
        fake,
        base=base,
        data=data,
        attrs={int(CKA_KEY_TYPE): int(CKK_DES), int(CKA_LABEL): "t"},
    )
    assert rv == int(CKR_OK), rv
    assert child == _xor_pairwise(base, data, 8), child


def test_fake_xor_rule_len_only_derives_generic_of_that_length() -> None:
    """R4-F5: a length without a type -> generic secret of the specified length."""
    fake = _FakeKdfRaw()
    base = bytes(range(32))
    data = bytes([0x5A]) * 8
    rv, child = _xor_rule_derive(
        fake,
        base=base,
        data=data,
        attrs={int(CKA_VALUE_LEN): 4, int(CKA_LABEL): "t"},
    )
    assert rv == int(CKR_OK), rv
    assert child == _xor_pairwise(base, data, 4), child


def test_fake_xor_rule_both_present_keeps_explicit() -> None:
    """R4-F5: an explicit length still rules when both attributes are present."""
    fake = _FakeKdfRaw()
    base = bytes(range(32))
    data = bytes([0x5A]) * 32
    rv, child = _xor_rule_derive(
        fake,
        base=base,
        data=data,
        attrs={
            int(CKA_KEY_TYPE): int(CKK_GENERIC_SECRET),
            int(CKA_VALUE_LEN): 1,
            int(CKA_LABEL): "t",
        },
    )
    assert rv == int(CKR_OK), rv
    assert child == _xor_pairwise(base, data, 1), child


def test_fake_xor_rule_refusal_rv_is_scriptable() -> None:
    """R4-F5: the rule-error RV is a hook (INCOMPLETE default)."""
    fake = _FakeKdfRaw()
    fake.derive_refuse_rv = int(CKR_KEY_SIZE_RANGE)
    rv, child = _xor_rule_derive(
        fake,
        base=bytes(range(32)),
        data=b"\x5a",
        attrs={int(CKA_KEY_TYPE): int(CKK_GENERIC_SECRET), int(CKA_LABEL): "t"},
    )
    assert rv == int(CKR_KEY_SIZE_RANGE), rv
    assert child is None


def _xor_short_expected() -> bytes:
    return bytes([kdf._RECOVERY_BASE[0] ^ kdf._RECOVERY_XOR_SHORT_DATA[0]])


def test_len_omitted_sealed_refusal_passes_conforming() -> None:
    """R4-F5: a length-omitted refusal passes as the conforming outcome."""
    rs = _kdf_rs()
    assert kdf._run_byte_recovery_case(rs, shape="xor_short_len_omitted", label="t") is None
    records = [rec for rec in classification.get_records() if rec.outcome != "pass"]
    assert records == [], [(rec.reason, rec.summary) for rec in records]
    conforming = [rec for rec in classification.get_records() if rec.reason == "sanctioned_refusal"]
    assert len(conforming) == 1, [(rec.reason, rec.summary) for rec in conforming]
    assert "2.43.6" in (conforming[0].summary or ""), conforming[0].summary
    assert conforming[0].actual_ckr == "CKR_TEMPLATE_INCOMPLETE", conforming[0].summary


def test_len_omitted_template_split() -> None:
    """R4-F5: control runs full-arity; sealed omits only the length."""
    rs = _kdf_rs()
    kdf._run_byte_recovery_case(rs, shape="xor_short_len_omitted", label="t")
    assert len(rs.raw.derive_templates) == 2, rs.raw.derive_templates
    control, sealed = rs.raw.derive_templates
    assert int(CKA_KEY_TYPE) in control, control
    assert int(CKA_VALUE_LEN) in control, control
    assert int(CKA_KEY_TYPE) in sealed, sealed
    assert int(CKA_VALUE_LEN) not in sealed, sealed
    assert rs.raw.derive_data == [kdf._RECOVERY_XOR_SHORT_DATA] * 2


def test_len_omitted_control_refused_skips() -> None:
    """R4-F5: without a working full-arity control the row is untestable."""
    rs = _kdf_rs()
    rs.raw.refuse_unsealed = True
    with pytest.raises(Skipped, match="fixture unbuildable"):
        kdf._run_byte_recovery_case(rs, shape="xor_short_len_omitted", label="t")


def test_len_omitted_accept_sane_value_xfails_deviation() -> None:
    """R4-F5: accepting the deviant form xfails even when the value is sane."""
    rs = _kdf_rs()
    rs.raw.len_omitted_accept_len = 1
    with pytest.raises(XFailed) as exc_info:
        kdf._run_byte_recovery_case(rs, shape="xor_short_len_omitted", label="t")
    assert "deviation" in str(exc_info.value), str(exc_info.value)
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "xfail"]
    assert record.reason == "honest_deviation", record.summary


def test_len_omitted_accept_wrong_value_fails() -> None:
    """R4-F5: an accepted deviant form with a wrong value fails crypto."""
    rs = _kdf_rs()
    rs.raw.len_omitted_accept_len = 1
    rs.raw.derive_child_bytes = bytes([_xor_short_expected()[0] ^ 0xFF])
    with pytest.raises(Failed) as exc_info:
        kdf._run_byte_recovery_case(rs, shape="xor_short_len_omitted", label="t")
    assert type(exc_info.value) is Failed, exc_info.value
    fails = [rec for rec in classification.get_records() if rec.outcome == "fail"]
    assert len(fails) == 1, [(rec.reason, rec.summary) for rec in fails]
    assert fails[0].reason == "wrong_result", fails[0].summary


def test_len_omitted_accept_long_child_xfails_oracle_na() -> None:
    """R4-F5: an accepted deviant form with a long child xfails (oracle N/A)."""
    rs = _kdf_rs()
    rs.raw.len_omitted_accept_len = 4
    with pytest.raises(XFailed) as exc_info:
        kdf._run_byte_recovery_case(rs, shape="xor_short_len_omitted", label="t")
    assert "N/A" in str(exc_info.value), str(exc_info.value)


def test_len_omitted_accept_blocked_oracle_xfails() -> None:
    """R4-F5: an accepted deviant form with a blocked oracle still xfails."""
    rs = _kdf_rs()
    rs.raw.len_omitted_accept_len = 1
    rs.raw.refuse_sealed_digest = True
    with pytest.raises(XFailed) as exc_info:
        kdf._run_byte_recovery_case(rs, shape="xor_short_len_omitted", label="t")
    assert "blocked" in str(exc_info.value), str(exc_info.value)
