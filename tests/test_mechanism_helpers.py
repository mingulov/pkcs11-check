from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.types_std import (
    CKA_VALUE_LEN,
    CKK_AES,
    CKK_RSA,
    CKK_SHA256_HMAC,
    CKM_AES_CBC,
    CKM_AES_KEY_GEN,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256_KEY_GEN,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import mechanism_helpers as helpers
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig


class _FakeMech:
    def byref(self) -> object:
        return object()


class _FakeRaw:
    def __init__(self, rv: int = int(CKR_OK), keypair_rv: int = int(CKR_OK)) -> None:
        self.calls: list[tuple[int, object, object, int]] = []
        self.keypair_calls: list[tuple[object, ...]] = []
        self.rv = rv
        self.keypair_rv = keypair_rv

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
        return self.rv

    def C_GenerateKeyPair(self, *args: object) -> int:  # noqa: N802
        self.keypair_calls.append(args)
        args[-2]._obj.value = 101  # type: ignore[attr-defined]
        args[-1]._obj.value = 102  # type: ignore[attr-defined]
        return self.keypair_rv


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


def test_generate_key_from_recipe_skips_when_keygen_mechanism_absent() -> None:
    fake_raw = _FakeRaw(rv=int(CKR_FUNCTION_NOT_SUPPORTED))
    rs = SimpleNamespace(raw=fake_raw, sh=7, has_mechanism=lambda _name: False)
    entry = MechEntry(
        mech_id=int(CKM_AES_CBC),
        mech_name="AES_CBC",
        flags=0,
        min_key_size=16,
        max_key_size=32,
        config=None,
    )
    config = MechConfig(
        key_type=int(CKK_AES),
        keygen_mech=int(CKM_AES_KEY_GEN),
        key_sizes=(128,),
        keygen_recipe=KeygenRecipe("symmetric"),
    )

    with pytest.raises(pytest.skip.Exception, match="AES_KEY_GEN not supported"):
        helpers.generate_key_from_recipe(rs, entry, config)

    assert fake_raw.calls == []


def test_generate_key_from_recipe_xfails_when_advertised_keygen_rejects_runtime() -> None:
    fake_raw = _FakeRaw(rv=int(CKR_FUNCTION_NOT_SUPPORTED))
    rs = SimpleNamespace(raw=fake_raw, sh=7, has_mechanism=lambda _name: True)
    entry = MechEntry(
        mech_id=int(CKM_AES_CBC),
        mech_name="AES_CBC",
        flags=0,
        min_key_size=16,
        max_key_size=32,
        config=None,
    )
    config = MechConfig(
        key_type=int(CKK_AES),
        keygen_mech=int(CKM_AES_KEY_GEN),
        key_sizes=(128,),
        keygen_recipe=KeygenRecipe("symmetric"),
    )

    with pytest.raises(pytest.xfail.Exception, match="AES_CBC keygen rejected"):
        helpers.generate_key_from_recipe(rs, entry, config)

    assert len(fake_raw.calls) == 1


def test_gen_symmetric_key_xfails_when_advertised_keygen_rejects_runtime() -> None:
    fake_raw = _FakeRaw(rv=int(CKR_FUNCTION_NOT_SUPPORTED))
    rs = SimpleNamespace(raw=fake_raw, sh=7, has_mechanism=lambda _name: True)
    entry = MechEntry(
        mech_id=int(CKM_AES_KEY_GEN),
        mech_name="AES_KEY_GEN",
        flags=0,
        min_key_size=16,
        max_key_size=32,
        config=None,
    )
    config = MechConfig(
        key_type=int(CKK_AES),
        keygen_mech=int(CKM_AES_KEY_GEN),
        key_sizes=(128,),
        keygen_recipe=KeygenRecipe("symmetric"),
    )

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN keygen rejected"):
        helpers.gen_symmetric_key(rs, entry, config)

    assert len(fake_raw.calls) == 1


@pytest.mark.parametrize(
    "rv_name,rv",
    [
        ("CKR_ATTRIBUTE_VALUE_INVALID", CKR_ATTRIBUTE_VALUE_INVALID),
        ("CKR_KEY_SIZE_RANGE", CKR_KEY_SIZE_RANGE),
        ("CKR_MECHANISM_PARAM_INVALID", CKR_MECHANISM_PARAM_INVALID),
        ("CKR_TEMPLATE_INCOMPLETE", CKR_TEMPLATE_INCOMPLETE),
        ("CKR_TEMPLATE_INCONSISTENT", CKR_TEMPLATE_INCONSISTENT),
    ],
)
def test_gen_symmetric_key_xfails_when_advertised_keygen_rejects_template(
    rv_name: str,
    rv: int,
) -> None:
    fake_raw = _FakeRaw(rv=int(rv))
    rs = SimpleNamespace(raw=fake_raw, sh=7, has_mechanism=lambda _name: True)
    entry = MechEntry(
        mech_id=int(CKM_AES_KEY_GEN),
        mech_name="AES_KEY_GEN",
        flags=0,
        min_key_size=16,
        max_key_size=32,
        config=None,
    )
    config = MechConfig(
        key_type=int(CKK_AES),
        keygen_mech=int(CKM_AES_KEY_GEN),
        key_sizes=(128,),
        keygen_recipe=KeygenRecipe("symmetric"),
    )

    with pytest.raises(pytest.xfail.Exception, match=f"AES_KEY_GEN keygen rejected.*{rv_name}"):
        helpers.gen_symmetric_key(rs, entry, config)

    assert len(fake_raw.calls) == 1


def test_gen_keypair_for_mech_xfails_when_advertised_keypair_rejects_runtime() -> None:
    fake_raw = _FakeRaw(keypair_rv=int(CKR_ATTRIBUTE_VALUE_INVALID))
    rs = SimpleNamespace(raw=fake_raw, sh=7, has_mechanism=lambda _name: True)
    entry = MechEntry(
        mech_id=int(CKM_RSA_PKCS_KEY_PAIR_GEN),
        mech_name="RSA_PKCS_KEY_PAIR_GEN",
        flags=0,
        min_key_size=256,
        max_key_size=512,
        config=None,
    )
    config = MechConfig(
        key_type=int(CKK_RSA),
        keygen_mech=int(CKM_RSA_PKCS_KEY_PAIR_GEN),
        key_sizes=(2048,),
        is_keypair=True,
        keygen_recipe=KeygenRecipe("rsa"),
    )

    with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_KEY_PAIR_GEN keypair rejected"):
        helpers.gen_keypair_for_mech(rs, entry, config)

    assert len(fake_raw.keypair_calls) == 1
