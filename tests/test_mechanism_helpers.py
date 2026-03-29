from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.types_std import CKA_VALUE_LEN, CKK_SHA256_HMAC, CKM_SHA256_KEY_GEN, CKR_OK
from pkcs11_check.testcases import mechanism_helpers as helpers
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig


class _FakeMech:
    def byref(self) -> object:
        return object()


class _FakeRaw:
    def __init__(self) -> None:
        self.calls: list[tuple[int, object, object, int]] = []

    def C_GenerateKey(  # noqa: N802
        self,
        sh: int,
        mech: object,
        tmpl_ptr: object,
        tmpl_count: int,
        handle_ptr: object,
    ) -> int:
        self.calls.append((sh, mech, tmpl_ptr, tmpl_count))
        handle_ptr._obj.value = 99
        return int(CKR_OK)


def test_gen_symmetric_key_falls_back_to_mechanism_info_when_registry_sizes_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, int] = {}
    fake_raw = _FakeRaw()
    rs = SimpleNamespace(raw=fake_raw, sh=7)

    def fake_attr_ulong(attr: int, value: int) -> tuple[int, int]:
        if attr == int(CKA_VALUE_LEN):
            captured["value_len"] = value
        return (attr, value)

    def fake_template(*items: object) -> SimpleNamespace:
        return SimpleNamespace(ptr=object(), count=len(items))

    monkeypatch.setattr("pkcs11_check.raw.pack.attr_ulong", fake_attr_ulong)
    monkeypatch.setattr("pkcs11_check.raw.pack.template", fake_template)
    monkeypatch.setattr(helpers, "pack_attrs", lambda attrs, skip=None: [("attrs", attrs, skip)])
    monkeypatch.setattr(helpers, "mech_simple", lambda mech: _FakeMech())

    entry = MechEntry(
        mech_id=int(CKM_SHA256_KEY_GEN),
        mech_name="SHA256_KEY_GEN",
        flags=0,
        min_key_size=16,
        max_key_size=64,
        config=None,
    )
    config = MechConfig(
        key_type=int(CKK_SHA256_HMAC),
        keygen_mech=int(CKM_SHA256_KEY_GEN),
        key_sizes=(),
        keygen_recipe=KeygenRecipe("symmetric"),
    )

    try:
        handle = helpers.gen_symmetric_key(rs, entry, config)
    except pytest.skip.Exception as exc:
        pytest.fail(f"unexpected skip: {exc}")

    assert handle == 99
    assert captured["value_len"] == 32
    assert len(fake_raw.calls) == 1
