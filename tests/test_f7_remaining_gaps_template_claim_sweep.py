"""F7 claim-sweep regressions for test_remaining_gaps.py nested-template sites.

Each of the three ``Test*Template`` methods below shares the same shape: a raw
C_GenerateKey/C_CreateObject call that requests a nested-template attribute
(CKA_WRAP_TEMPLATE / CKA_UNWRAP_TEMPLATE / CKA_DERIVE_TEMPLATE) already proves
creation-time acceptance (a rejection classifies/raises before ``claimed`` is
even computed), so a missing readback of that attribute must not disable the
enforcement oracle. Before the fix, ``claimed`` defaulted to ``False`` and only
flipped to ``True`` on a *present* well-formed readback -- a missing readback
silently downgraded a proven enforcement-bypass to an untested no-op.

Mutation used per site: revert ``claimed = True`` (the line immediately after
the setup C_GenerateKey/C_CreateObject call) back to ``claimed = False`` --
each test below then observes ``classify_policy_enforcement`` never being
invoked (or invoked with ``claimed=False``), instead of failing hard.
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKR_OK
from pkcs11_check.testcases import test_remaining_gaps as gaps_case


def _session(*, mechanisms: set[str], raw: Any) -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda name: name in mechanisms)


@pytest.fixture(autouse=True)
def _clear_classifications() -> Any:
    C.clear()
    yield
    C.clear()


class _WrapTemplateRaw:
    """Raw stub: C_GenerateKey (wrapping key) + two C_WrapKey probes."""

    def __init__(self) -> None:
        self.wrap_calls = 0

    def C_GenerateKey(self, _sh: int, _mech: Any, _tmpl_ptr: Any, _count: int, handle: Any) -> int:  # noqa: N802
        handle._obj.value = 900
        return int(CKR_OK)

    def C_WrapKey(  # noqa: N802
        self, _sh: int, _mech: Any, _wrapping: int, _target: int, _out: Any, out_len: Any
    ) -> int:
        self.wrap_calls += 1
        out_len._obj.value = 0
        return int(CKR_OK)


def test_wrap_template_missing_readback_still_fails_on_successful_wrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _WrapTemplateRaw()
    rs = _session(mechanisms={"AES_KEY_GEN", "AES_KEY_WRAP"}, raw=raw)
    monkeypatch.setattr(gaps_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(gaps_case, "gen_aes_key_or_xfail", lambda *_a, **_k: next(_targets))
    monkeypatch.setattr(gaps_case, "destroy_quietly", lambda *_a, **_k: None)
    _targets = iter([901, 902])

    with pytest.raises(Failed) as excinfo:
        gaps_case.TestTemplateConstraintAttributes().test_wrap_template_enforces_target_attributes(
            rs
        )
    assert not isinstance(excinfo.value, XFailed)

    records = C.get_records()
    assert records[0].reason == "honest_deviation"
    assert records[-1].reason == "self_contradiction"
    assert raw.wrap_calls == 2


class _UnwrapTemplateRaw:
    """Raw stub: C_GenerateKey + C_WrapKey (size query + real) + two C_UnwrapKey probes."""

    def __init__(self) -> None:
        self.unwrap_calls = 0

    def C_GenerateKey(self, _sh: int, _mech: Any, _tmpl_ptr: Any, _count: int, handle: Any) -> int:  # noqa: N802
        handle._obj.value = 910
        return int(CKR_OK)

    def C_WrapKey(  # noqa: N802
        self, _sh: int, _mech: Any, _wrapping: int, _source: int, out: Any, out_len: Any
    ) -> int:
        out_len._obj.value = 16
        return int(CKR_OK)

    def C_UnwrapKey(  # noqa: N802
        self,
        _sh: int,
        _mech: Any,
        _unwrapping: int,
        _buf: Any,
        _buf_len: int,
        _tmpl_ptr: Any,
        _count: int,
        handle: Any,
    ) -> int:
        self.unwrap_calls += 1
        handle._obj.value = 920 + self.unwrap_calls
        return int(CKR_OK)


def test_unwrap_template_missing_readback_still_fails_on_successful_unwrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _UnwrapTemplateRaw()
    rs = _session(mechanisms={"AES_KEY_GEN", "AES_KEY_WRAP"}, raw=raw)
    monkeypatch.setattr(gaps_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(gaps_case, "gen_aes_key_or_xfail", lambda *_a, **_k: 911)
    monkeypatch.setattr(gaps_case, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(Failed) as excinfo:
        gaps_case.TestTemplateConstraintAttributes().test_unwrap_template_enforces_created_object_attributes(
            rs
        )
    assert not isinstance(excinfo.value, XFailed)

    records = C.get_records()
    assert records[0].reason == "honest_deviation"
    assert records[-1].reason == "self_contradiction"
    assert raw.unwrap_calls == 2


class _DeriveTemplateRaw:
    """Raw stub: C_CreateObject (base key) + two C_DeriveKey probes."""

    def __init__(self) -> None:
        self.derive_calls = 0

    def C_CreateObject(self, _sh: int, _tmpl_ptr: Any, _count: int, handle: Any) -> int:  # noqa: N802
        handle._obj.value = 930
        return int(CKR_OK)

    def C_DeriveKey(  # noqa: N802
        self, _sh: int, _mech: Any, _base: int, _tmpl_ptr: Any, _count: int, handle: Any
    ) -> int:
        self.derive_calls += 1
        handle._obj.value = 940 + self.derive_calls
        return int(CKR_OK)


def test_derive_template_missing_readback_still_fails_on_successful_derive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _DeriveTemplateRaw()
    rs = _session(mechanisms={"CONCATENATE_BASE_AND_DATA"}, raw=raw)
    monkeypatch.setattr(gaps_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(gaps_case, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(Failed) as excinfo:
        gaps_case.TestTemplateConstraintAttributes().test_derive_template_enforces_created_object_attributes(
            rs
        )
    assert not isinstance(excinfo.value, XFailed)

    records = C.get_records()
    assert records[0].reason == "honest_deviation"
    assert records[-1].reason == "self_contradiction"
    assert raw.derive_calls == 2
