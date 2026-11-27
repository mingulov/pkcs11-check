"""Contract tests for find-by-sealed-component verdicts (#54.2, B1)."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, Skipped, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
    CKA_SEED,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases import test_sensitivity as sens

_OK = int(CKR_OK)


def _out(
    init: int = _OK,
    find: int = _OK,
    final: int = _OK,
    handles: tuple[int, ...] = (),
    complete: bool = True,
) -> sens._FindOutcome:
    return sens._FindOutcome(
        init_rv=init, find_rv=find, final_rv=final, handles=handles, complete=complete
    )


class _PagedRaw:
    """Find surface with scripted pages, Init/Final RVs, and call counts."""

    def __init__(
        self,
        pages: list[tuple[int, ...] | int],
        *,
        init_rv: int = _OK,
        final_rv: int = _OK,
    ) -> None:
        self._pages = [list(p) if isinstance(p, tuple) else p for p in pages]
        self._init_rv = init_rv
        self._final_rv = final_rv
        self.find_calls = 0
        self.final_calls = 0

    def C_FindObjectsInit(self, _sh: int, _tmpl: Any, _count: int) -> int:  # noqa: N802
        return self._init_rv

    def C_FindObjects(self, _sh: int, handles: Any, max_count: int, found_ptr: Any) -> int:  # noqa: N802
        import ctypes

        from pkcs11_check.raw.types_std import CK_ULONG

        self.find_calls += 1
        if not self._pages:
            page: tuple[int, ...] | int = ()
        else:
            page = self._pages.pop(0)
        if isinstance(page, int):
            ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents.value = 0
            return page
        for i, handle in enumerate(page[:max_count]):
            handles[i] = handle
        ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents.value = len(page)
        return _OK

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        self.final_calls += 1
        return self._final_rv


def _page_tmpl() -> Any:
    import ctypes

    return SimpleNamespace(ptr=ctypes.c_void_p(None), count=0)


def _find_role(want: bytes | None) -> str:
    """Route a find template to its leg by the searched value (R4-F4).

    The ML-DSA seed fixtures coincide with the AES value fixtures, so
    one routing serves both public nodes. Unknown templates fail loud:
    the nodes issue exactly three searches each.
    """
    if want == sens._SEALED_FIND_VALUE:
        return "sealed"
    if want == sens._SEALED_FIND_VALUE_ALT:
        return "control"
    if want == sens._absent_value(sens._SEALED_FIND_VALUE, sens._SEALED_FIND_VALUE_ALT):
        return "wrong"
    raise AssertionError(f"fake routes only the three node templates, got {want!r}")


class _SealedNodeFake:
    """ABI-faithful sealed-find node fake (R4-F4).

    Imports file every template attribute; sealed-component reads answer
    exactly as production receives them (an RV plus the
    CK_UNAVAILABLE_INFORMATION sentinel -- never a raised Python
    exception); finds route by the searched value bytes. Symbolic page
    entries "S"/"C" resolve to the sealed/control handles.
    """

    def __init__(self) -> None:
        self.objects: dict[int, dict[int, bytes]] = {}
        self.sealed: dict[int, bool] = {}
        self._next = 0
        self._role_handle: dict[str, int] = {}
        self.value_mode = "sensitive"
        self.value_raise_rv: int | None = None
        self.find_pages: dict[str, list[tuple[Any, ...]]] = {
            "sealed": [()],
            "control": [("C",), ()],
            "wrong": [()],
        }
        self.find_rvs: dict[str, dict[str, int]] = {"sealed": {}, "control": {}, "wrong": {}}
        self.destroyed: list[int] = []
        self._active: str | None = None
        self._page_idx = 0

    def C_CreateObject(self, _sh: int, tmpl: Any, count: int, handle_ptr: Any) -> int:  # noqa: N802
        attrs: dict[int, bytes] = {}
        for i in range(int(count)):
            at = int(tmpl[i].type)
            length = int(tmpl[i].ulValueLen)
            attrs[at] = (
                bytes(ctypes.string_at(tmpl[i].pValue, length))
                if tmpl[i].pValue is not None
                else b""
            )
        self._next += 1
        self.objects[self._next] = attrs
        self.sealed[self._next] = attrs.get(int(CKA_SENSITIVE), b"\x00") == b"\x01"
        if self._next == 1:
            self._role_handle["S"] = 1
        elif self._next == 2:
            self._role_handle["C"] = 2
        ctypes.cast(handle_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = self._next
        return int(CKR_OK)

    def _fill(self, tmpl: Any, i: int, blob: bytes) -> None:
        if tmpl[i].pValue is None:
            tmpl[i].ulValueLen = len(blob)
        else:
            ctypes.memmove(tmpl[i].pValue, blob, len(blob))
            tmpl[i].ulValueLen = len(blob)

    def C_GetAttributeValue(self, _sh: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        obj = self.objects.get(int(handle))
        if obj is None:
            return int(CKR_OBJECT_HANDLE_INVALID)
        call_rv = int(CKR_OK)
        for i in range(int(count)):
            at = int(tmpl[i].type)
            if at in (int(CKA_VALUE), int(CKA_SEED)) and self.sealed.get(int(handle), False):
                mode = self.value_mode
                if mode == "raise":
                    assert self.value_raise_rv is not None, "raise mode needs an RV"
                    return self.value_raise_rv
                blob = obj.get(at, b"")
                if mode == "sensitive":
                    tmpl[i].ulValueLen = int(CK_UNAVAILABLE_INFORMATION)
                    call_rv = int(CKR_ATTRIBUTE_SENSITIVE)
                elif mode == "type_invalid":
                    tmpl[i].ulValueLen = int(CK_UNAVAILABLE_INFORMATION)
                    call_rv = int(CKR_ATTRIBUTE_TYPE_INVALID)
                elif mode == "leak":
                    self._fill(tmpl, i, blob)
                    call_rv = int(CKR_ATTRIBUTE_SENSITIVE)
                elif mode == "malformed":
                    tmpl[i].ulValueLen = len(blob)
                    call_rv = int(CKR_ATTRIBUTE_SENSITIVE)
                else:
                    assert mode == "clear", mode
                    self._fill(tmpl, i, blob)
                continue
            blob = obj.get(at)
            if blob is None:
                tmpl[i].ulValueLen = int(CK_UNAVAILABLE_INFORMATION)
                call_rv = int(CKR_ATTRIBUTE_TYPE_INVALID)
                continue
            self._fill(tmpl, i, blob)
        return call_rv

    def C_FindObjectsInit(self, _sh: int, tmpl: Any, count: int) -> int:  # noqa: N802
        want: bytes | None = None
        for i in range(int(count)):
            if int(tmpl[i].type) in (int(CKA_VALUE), int(CKA_SEED)):
                length = int(tmpl[i].ulValueLen)
                want = (
                    bytes(ctypes.string_at(tmpl[i].pValue, length))
                    if tmpl[i].pValue is not None
                    else b""
                )
        role = _find_role(want)
        self._active = role
        self._page_idx = 0
        return self.find_rvs[role].get("init", int(CKR_OK))

    def C_FindObjects(self, _sh: int, handles: Any, max_count: int, found_ptr: Any) -> int:  # noqa: N802
        assert self._active is not None, "Find without Init"
        role = self._active
        pages = self.find_pages[role]
        out = ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents
        if self._page_idx < len(pages):
            page = pages[self._page_idx]
            self._page_idx += 1
            resolved = tuple(self._role_handle[s] if isinstance(s, str) else s for s in page)
            for i, handle in enumerate(resolved[:max_count]):
                handles[i] = handle
            out.value = len(resolved)
            return int(CKR_OK)
        if "find" in self.find_rvs[role]:
            out.value = 0
            return self.find_rvs[role]["find"]
        out.value = 0
        return int(CKR_OK)

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        assert self._active is not None, "Final without Init"
        return self.find_rvs[self._active].get("final", int(CKR_OK))

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        self.destroyed.append(int(handle))
        self.objects.pop(int(handle), None)
        return int(CKR_OK)


def _node_rs(fake: _SealedNodeFake) -> Any:
    return SimpleNamespace(raw=fake, sh=7, has_mechanism=lambda _name: True)


def _run_aes(fake: _SealedNodeFake) -> None:
    sens.TestSealedFindObjects().test_aes_sealed_value_find(_node_rs(fake))


def _run_seed(fake: _SealedNodeFake) -> None:
    sens.TestSealedFindObjects().test_mldsa_seed_find(_node_rs(fake))


def _assert_reported_skip_without_xfail() -> None:
    """Drive the report hook: a voided verdict must stay skipped (R4-F4)."""
    from pkcs11_check._plugin_report_attach import _apply_recorded_outcome

    report = SimpleNamespace(outcome="skipped")
    _apply_recorded_outcome(report, classification.get_records())
    assert report.outcome == "skipped", report.outcome
    assert not hasattr(report, "wasxfail"), getattr(report, "wasxfail", None)


def test_screen_member_match_xfails_spec_silent() -> None:
    # v3.2 §5.7.7 implies byte-exact match with no sensitivity
    # carve-out: a sealed match is recorded oracle surface (xfail),
    # never a conformance defect (fail).
    with pytest.raises(XFailed):
        sens._screen_sealed_find(outcome=_out(handles=(7, 42)), handle=42, label="sealed")


def test_screen_foreign_hits_without_member_pass_screen() -> None:
    """B1: hits not containing the sealed handle are not a sealed match."""
    sens._screen_sealed_find(outcome=_out(handles=(7,)), handle=42, label="sealed")
    assert classification.get_records() == []


def test_screen_undefined_rv_fails() -> None:
    with pytest.raises(Failed):
        sens._screen_sealed_find(outcome=_out(find=0xDEAD), handle=42, label="sealed")


def test_screen_incomplete_without_member_skips() -> None:
    """R2A3: an unfinished search cannot prove absence: unproved."""
    with pytest.raises(Skipped):
        sens._screen_sealed_find(
            outcome=_out(find=int(CKR_DEVICE_ERROR), handles=(7,), complete=False),
            handle=42,
            label="sealed",
        )


def test_screen_member_survives_final_refusal() -> None:
    """R2A3: delivering pages prove the match even when Final refuses."""
    with pytest.raises(XFailed):
        sens._screen_sealed_find(
            outcome=_out(final=int(CKR_ATTRIBUTE_VALUE_INVALID), handles=(42,)),
            handle=42,
            label="sealed",
        )


def test_screen_undefined_final_behind_refused_find_fails() -> None:
    """R2A3: per-stage scan; no collapse hides an undefined Final."""
    with pytest.raises(Failed):
        sens._screen_sealed_find(
            outcome=_out(find=int(CKR_DEVICE_ERROR), final=0xDEAD, complete=False),
            handle=42,
            label="sealed",
        )


def test_control_incomplete_skips() -> None:
    """R2A3: a short page cannot prove exactly-one: unproved."""
    with pytest.raises(Skipped):
        sens._judge_find_control(
            outcome=_out(find=int(CKR_DEVICE_ERROR), handles=(42,), complete=False),
            handle=42,
            label="control",
        )


def test_control_exact_handle_passes() -> None:
    sens._judge_find_control(outcome=_out(handles=(42,)), handle=42, label="control")
    assert classification.get_records() == []


def test_control_zero_skips() -> None:
    with pytest.raises(Skipped):
        sens._judge_find_control(outcome=_out(handles=()), handle=42, label="control")


def test_control_two_fails() -> None:
    with pytest.raises(Failed):
        sens._judge_find_control(outcome=_out(handles=(42, 43)), handle=42, label="control")


def test_control_wrong_member_fails() -> None:
    """B1: exactly one hit that is not the control is a wrong result."""
    with pytest.raises(Failed):
        sens._judge_find_control(outcome=_out(handles=(43,)), handle=42, label="control")


def test_control_refused_skips() -> None:
    with pytest.raises(Skipped):
        sens._judge_find_control(
            outcome=_out(init=int(CKR_ATTRIBUTE_TYPE_INVALID)), handle=42, label="control"
        )


def test_control_undefined_rv_fails() -> None:
    """B1: validity-first applies to the control leg too."""
    with pytest.raises(Failed):
        sens._judge_find_control(outcome=_out(find=0xDEAD), handle=42, label="control")


def test_negative_no_match_with_control_passes() -> None:
    sens._judge_sealed_negative(outcome=_out(handles=()), label="sealed", control_proved=True)
    assert classification.get_records() == []


def test_negative_no_match_without_control_skips() -> None:
    """B1: without control mechanics a no-match proves nothing (ML-DSA leg)."""
    with pytest.raises(Skipped):
        sens._judge_sealed_negative(outcome=_out(handles=()), label="sealed", control_proved=False)


def test_negative_clean_refusal_passes() -> None:
    sens._judge_sealed_negative(
        outcome=_out(init=int(CKR_ATTRIBUTE_TYPE_INVALID)),
        label="sealed",
        control_proved=False,
    )
    (record,) = classification.get_records()
    assert record.reason == "sanctioned_refusal", record.summary
    assert record.outcome == "pass", record.summary
    assert record.operation == "C_FindObjectsInit", record.operation
    assert record.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID", record.summary


def test_negative_device_error_skips() -> None:
    with pytest.raises(Skipped):
        sens._judge_sealed_negative(
            outcome=_out(find=int(CKR_DEVICE_ERROR)), label="sealed", control_proved=True
        )


def test_effective_rv_is_first_non_ok_stage() -> None:
    assert _out().effective_rv == _OK
    assert _out(init=int(CKR_DEVICE_ERROR)).effective_rv == int(CKR_DEVICE_ERROR)
    assert _out(find=int(CKR_DEVICE_ERROR)).effective_rv == int(CKR_DEVICE_ERROR)
    assert _out(final=int(CKR_DEVICE_ERROR)).effective_rv == int(CKR_DEVICE_ERROR)


def test_screen_init_refusal_reaches_negative() -> None:
    """R3F4: a clean Init refusal returns for the negative judge, never skips."""
    sens._screen_sealed_find(
        outcome=_out(init=int(CKR_ATTRIBUTE_TYPE_INVALID)), handle=7, label="L"
    )
    # No raise: the negative judge sanctions it.
    sens._judge_sealed_negative(
        outcome=_out(init=int(CKR_ATTRIBUTE_TYPE_INVALID)), label="L", control_proved=False
    )
    (record,) = classification.get_records()
    assert record.reason == "sanctioned_refusal", record.summary


def test_screen_final_refusal_with_empty_pages_skips() -> None:
    """R3F4: empty pages plus a refused Final cannot pass absence."""
    with pytest.raises(Skipped):
        sens._screen_sealed_find(
            outcome=_out(final=int(CKR_DEVICE_ERROR), complete=False), handle=7, label="L"
        )


def test_undefined_init_names_init_operation() -> None:
    """R3F4: undefined stage RVs carry their own operation."""
    with pytest.raises(Failed):
        sens._fail_undefined_find_rv("L", _out(init=0xDEAD))
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "fail"]
    assert record.operation == "C_FindObjectsInit", record.operation
    assert "Init" in (record.summary or ""), record.summary


def test_undefined_final_names_final_operation() -> None:
    with pytest.raises(Failed):
        sens._fail_undefined_find_rv("L", _out(final=0xDEAD))
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "fail"]
    assert record.operation == "C_FindObjectsFinal", record.operation


def test_oversized_page_retained_sibling_graded() -> None:
    """R3F4: an oversized page records without raising; siblings still run."""
    raw = _PagedRaw([tuple(range(9))])
    outcome = sens._find_page(raw, 7, _page_tmpl())
    assert len(outcome.retained) == 1, outcome
    assert outcome.retained[0].reason == "self_contradiction"
    assert outcome.complete is False
    assert raw.final_calls == 1, "Final still runs after the retained defect"
    # Sibling evidence grades independently afterwards.
    with pytest.raises(Failed):
        classification.raise_for_record(outcome.retained[0])


def test_unbounded_pages_stop_at_cap_incomplete() -> None:
    """R3F4: a never-empty search stops at the paging bound, inconclusive."""
    raw = _PagedRaw([(9,)] * 1000)
    outcome = sens._find_page(raw, 7, _page_tmpl())
    assert outcome.complete is False
    assert raw.find_calls == sens._FIND_MAX_PAGES, raw.find_calls
    assert outcome.handles == (9,) * sens._FIND_MAX_PAGES


def test_record_sealed_match_journals_member_only() -> None:
    """R4-F4: the match journal fires only for a delivered sealed handle."""
    assert sens._record_sealed_match(outcome=_out(handles=(7,)), handle=7, label="L") is not None
    assert sens._record_sealed_match(outcome=_out(handles=(7,)), handle=8, label="L") is None


def test_screen_vendor_find_falls_through_to_negative() -> None:
    """R4-F4: a vendor Find RV is the negative judge's verdict, never a screen skip."""
    try:
        sens._screen_sealed_find(outcome=_out(find=0x80000001, complete=False), handle=7, label="L")
    except Skipped as exc:
        pytest.fail(f"vendor Find skipped instead of falling through: {exc}")


def test_screen_vendor_final_falls_through_to_negative() -> None:
    """R4-F4: a vendor Final RV is the negative judge's verdict, never a screen skip."""
    try:
        sens._screen_sealed_find(
            outcome=_out(final=0x80000001, complete=False), handle=7, label="L"
        )
    except Skipped as exc:
        pytest.fail(f"vendor Final skipped instead of falling through: {exc}")


def test_negative_vendor_init_names_init_operation() -> None:
    """R4-F4: a vendor Init refusal carries its own stage operation."""
    with pytest.raises(XFailed):
        sens._judge_sealed_negative(
            outcome=_out(init=0x80000001, complete=False), label="L", control_proved=True
        )
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "xfail"]
    assert record.reason == "nonspec_reject", record.summary
    assert record.operation == "C_FindObjectsInit", record.operation


def test_negative_vendor_find_names_find_operation() -> None:
    """R4-F4: a vendor Find refusal carries its own stage operation."""
    with pytest.raises(XFailed):
        sens._judge_sealed_negative(
            outcome=_out(find=0x80000001, complete=False), label="L", control_proved=True
        )
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "xfail"]
    assert record.operation == "C_FindObjects", record.operation


def test_negative_vendor_final_names_final_operation() -> None:
    """R4-F4: a vendor Final refusal carries its own stage operation."""
    with pytest.raises(XFailed):
        sens._judge_sealed_negative(
            outcome=_out(final=0x80000001, complete=False), label="L", control_proved=True
        )
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "xfail"]
    assert record.operation == "C_FindObjectsFinal", record.operation


def test_wrong_value_nonempty_fails() -> None:
    """R3F4: an absent value matching objects proves find is not selective."""
    with pytest.raises(Failed):
        sens._judge_wrong_value_find(outcome=_out(handles=(3,)), label="wrong")
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "fail"]
    assert record.reason == "wrong_result", record.summary
    assert "not selective" in (record.summary or ""), record.summary


def test_wrong_value_empty_passes_refused_skips() -> None:
    sens._judge_wrong_value_find(outcome=_out(handles=()), label="wrong")
    with pytest.raises(Skipped):
        sens._judge_wrong_value_find(outcome=_out(init=int(CKR_DEVICE_ERROR)), label="wrong")
    with pytest.raises(Skipped):
        sens._judge_wrong_value_find(
            outcome=_out(find=int(CKR_DEVICE_ERROR), complete=False), label="wrong"
        )


def test_node_sensitive_read_proceeds_to_pass() -> None:
    """R4-F4: a normal SENSITIVE refusal proves unreadability; the leg runs."""
    fake = _SealedNodeFake()
    try:
        _run_aes(fake)
    except Skipped as exc:
        pytest.fail(f"sensitive read skipped instead of proceeding: {exc}")
    assert fake.destroyed == [1, 2], fake.destroyed


def test_node_readable_component_skips() -> None:
    """R4-F4: flags claiming sealed while bytes serve voids the premise."""
    fake = _SealedNodeFake()
    fake.value_mode = "clear"
    with pytest.raises(Skipped, match="reads back clear"):
        _run_aes(fake)


def test_node_device_error_read_skips_inconclusive() -> None:
    """R4-F4: a call-level read failure proves nothing about the seal."""
    fake = _SealedNodeFake()
    fake.value_mode = "raise"
    fake.value_raise_rv = int(CKR_DEVICE_ERROR)
    with pytest.raises(Skipped, match="inconclusive"):
        _run_aes(fake)


def test_node_vendor_read_xfails_visible() -> None:
    """R4-F4: a vendor read failure is a visible alternate, never a pass."""
    fake = _SealedNodeFake()
    fake.value_mode = "raise"
    fake.value_raise_rv = 0x80000001
    with pytest.raises(XFailed):
        _run_aes(fake)
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "xfail"]
    assert record.reason == "nonspec_reject", record.summary
    assert record.operation == "C_GetAttributeValue", record.operation


def test_node_undefined_read_fails_loud() -> None:
    """R4-F4: an undefined seal-check RV fails the metadata contract."""
    fake = _SealedNodeFake()
    fake.value_mode = "raise"
    fake.value_raise_rv = 0x7FFFFFFF
    with pytest.raises(Failed) as exc_info:
        _run_aes(fake)
    assert type(exc_info.value) is Failed, exc_info.value


def test_node_refusal_with_data_fails() -> None:
    """R4-F4: a refusal that still wrote bytes fails (never adopts, never skips)."""
    fake = _SealedNodeFake()
    fake.value_mode = "leak"
    try:
        _run_aes(fake)
    except Skipped as exc:
        pytest.fail(f"refusal-with-data skipped instead of failing: {exc}")
    except Failed as exc:
        assert type(exc) is Failed, exc
        assert "wrote" in str(exc), str(exc)
    else:
        pytest.fail("refusal-with-data passed instead of failing")


def test_node_malformed_refusal_terminates_without_search() -> None:
    """R9-3: a malformed seal refusal terminates; the dependent search never runs."""
    fake = _SealedNodeFake()
    fake.value_mode = "malformed"
    with pytest.raises(XFailed, match="malformed"):
        _run_aes(fake)
    assert fake._active is None
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "xfail"]
    assert record.reason == "not_operational", record.summary
    assert record.operation == "C_GetAttributeValue", record.operation


def test_node_retry_refusal_after_partial_terminates_without_search() -> None:
    """R14-1: a marked seal refusal proves nothing; the search never runs."""

    class _FlakySealedFake(_SealedNodeFake):
        def __init__(self) -> None:
            super().__init__()
            self.seal_reads = 0

        def C_GetAttributeValue(  # noqa: N802
            self, _sh: int, handle: int, tmpl: Any, count: int
        ) -> int:
            if (
                int(count) == 1
                and int(tmpl[0].type) == int(CKA_VALUE)
                and self.sealed.get(int(handle), False)
            ):
                self.seal_reads += 1
                if self.seal_reads <= 2:
                    tmpl[0].ulValueLen = 3
                    if tmpl[0].pValue:
                        ctypes.memmove(tmpl[0].pValue, b"\x66", 1)
                    return int(CKR_OK)
                tmpl[0].ulValueLen = int(CK_UNAVAILABLE_INFORMATION)
                return int(CKR_ATTRIBUTE_SENSITIVE)
            return super().C_GetAttributeValue(_sh, handle, tmpl, count)

    fake = _FlakySealedFake()
    with pytest.raises(XFailed, match="unproved"):
        _run_aes(fake)
    assert fake._active is None
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "xfail"]
    assert record.reason == "not_operational", record.summary
    assert record.operation == "C_GetAttributeValue", record.operation
    assert record.actual_ckr == "CKR_ATTRIBUTE_SENSITIVE", record.actual_ckr
    assert record.detail is not None
    assert record.detail.get("unproved_delivery") is True


def test_node_typeless_component_skips_moot() -> None:
    """R4-F4: no value present means the seal question is moot (void)."""
    fake = _SealedNodeFake()
    fake.value_mode = "type_invalid"
    with pytest.raises(Skipped, match="moot"):
        _run_aes(fake)


def test_node_match_with_broken_control_stays_skipped() -> None:
    """R4-F4: an uncalibrated match never promotes a control skip to xfail."""
    fake = _SealedNodeFake()
    fake.find_pages["sealed"] = [("S",), ()]
    fake.find_pages["control"] = [("C",)]
    fake.find_rvs["control"] = {"find": int(CKR_DEVICE_ERROR)}
    with pytest.raises(Skipped):
        _run_aes(fake)
    _assert_reported_skip_without_xfail()


def test_node_wrong_value_hit_grades_before_control_void() -> None:
    """R4-F4: a delivered forbidden hit fails even when the control voids."""
    fake = _SealedNodeFake()
    fake.find_pages["wrong"] = [(9,), ()]
    fake.find_pages["control"] = [("C",)]
    fake.find_rvs["control"] = {"find": int(CKR_DEVICE_ERROR)}
    try:
        _run_aes(fake)
    except Skipped as exc:
        pytest.fail(f"forbidden hit hidden behind control skip: {exc}")
    except Failed as exc:
        assert type(exc) is Failed, exc
        assert "not selective" in str(exc), str(exc)
    else:
        pytest.fail("forbidden hit passed instead of failing")


def test_seed_node_sensitive_read_proceeds_to_pass() -> None:
    """R4-F4: the ML-DSA leg runs on a normal SENSITIVE seed refusal."""
    fake = _SealedNodeFake()
    try:
        _run_seed(fake)
    except Skipped as exc:
        pytest.fail(f"sensitive seed read skipped instead of proceeding: {exc}")
    assert fake.destroyed == [1, 2], fake.destroyed


def test_seed_node_match_with_broken_control_stays_skipped() -> None:
    """R4-F4: the ML-DSA leg keeps an uncalibrated match out of the verdict."""
    fake = _SealedNodeFake()
    fake.find_pages["sealed"] = [("S",), ()]
    fake.find_pages["control"] = [("C",)]
    fake.find_rvs["control"] = {"find": int(CKR_DEVICE_ERROR)}
    with pytest.raises(Skipped):
        _run_seed(fake)
    _assert_reported_skip_without_xfail()


def test_seed_node_wrong_value_hit_grades_before_control_void() -> None:
    """R4-F4: the ML-DSA leg fails a forbidden hit before any control void."""
    fake = _SealedNodeFake()
    fake.find_pages["wrong"] = [(9,), ()]
    fake.find_pages["control"] = [("C",)]
    fake.find_rvs["control"] = {"find": int(CKR_DEVICE_ERROR)}
    try:
        _run_seed(fake)
    except Skipped as exc:
        pytest.fail(f"forbidden hit hidden behind control skip: {exc}")
    except Failed as exc:
        assert type(exc) is Failed, exc
        assert "not selective" in str(exc), str(exc)
    else:
        pytest.fail("forbidden hit passed instead of failing")


def test_seed_import_validity_grades() -> None:
    """R3F4: fixture import refusals grade validity before the leg voids."""
    from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR

    sens._grade_seed_import_rv(int(CKR_DEVICE_ERROR), label="L")
    with pytest.raises(XFailed):
        sens._grade_seed_import_rv(0x80000001, label="L")
    with pytest.raises(Failed):
        sens._grade_seed_import_rv(0xDEAD, label="L")
