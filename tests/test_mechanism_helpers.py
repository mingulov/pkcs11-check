from __future__ import annotations

import ctypes
from types import SimpleNamespace

import pytest

from pkcs11_check.raw.types_std import (
    CKA_VALUE_LEN,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKK_IDEA,
    CKK_RSA,
    CKK_SHA256_HMAC,
    CKM_AES_CBC,
    CKM_AES_KEY_GEN,
    CKM_ARIA_MAC_GENERAL,
    CKM_PKCS5_PBKD2,
    CKM_RC2_MAC_GENERAL,
    CKM_RC5_CBC,
    CKM_RC5_CBC_PAD,
    CKM_RC5_ECB,
    CKM_RC5_MAC,
    CKM_RC5_MAC_GENERAL,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SALSA20,
    CKM_SALSA20_POLY1305,
    CKM_SHA256_KEY_GEN,
    CKR_ARGUMENTS_BAD,
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
from pkcs11_check.testcases.mechanism_registry import (
    MECHANISM_REGISTRY,
    KeygenRecipe,
    MechConfig,
    ParamRecipe,
)


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


def test_gen_symmetric_key_omits_value_len_for_fixed_length_recipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_value_len_attrs: list[int] = []
    fake_raw = _FakeRaw()
    rs = SimpleNamespace(raw=fake_raw, sh=7)

    def fake_attr_ulong(attr: int, value: int) -> tuple[int, int]:
        if attr == int(CKA_VALUE_LEN):
            captured_value_len_attrs.append(value)
        return (attr, value)

    def fake_template(*items: object) -> SimpleNamespace:
        return SimpleNamespace(ptr=object(), count=len(items))

    monkeypatch.setattr("pkcs11_check.raw.pack.attr_ulong", fake_attr_ulong)
    monkeypatch.setattr("pkcs11_check.raw.pack.template", fake_template)
    monkeypatch.setattr(helpers, "pack_attrs", lambda attrs, skip=None: [("attrs", attrs, skip)])
    monkeypatch.setattr(helpers, "mech_simple", lambda mech: _FakeMech())

    entry = MechEntry(
        mech_id=0x340,
        mech_name="IDEA_KEY_GEN",
        flags=0,
        min_key_size=16,
        max_key_size=16,
        config=None,
    )
    config = MechConfig(
        key_type=int(CKK_IDEA),
        keygen_mech=0x340,
        key_sizes=(128,),
        keygen_recipe=KeygenRecipe("fixed_length"),
    )

    handle = helpers.gen_symmetric_key(rs, entry, config)

    assert handle == 99
    assert captured_value_len_attrs == []
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


def test_gen_symmetric_key_exercises_pbkdf2_with_runtime_params() -> None:
    fake_raw = _FakeRaw()
    rs = SimpleNamespace(raw=fake_raw, sh=7, has_mechanism=lambda _name: True)
    config = MechConfig(
        key_type=int(CKK_GENERIC_SECRET),
        keygen_mech=int(CKM_PKCS5_PBKD2),
        key_sizes=(),
        param_required=True,
        param_recipe=ParamRecipe("pbkdf2"),
        keygen_recipe=KeygenRecipe("symmetric"),
    )
    entry = MechEntry(
        mech_id=int(CKM_PKCS5_PBKD2),
        mech_name="PKCS5_PBKD2",
        flags=0,
        min_key_size=16,
        max_key_size=64,
        config=config,
    )

    try:
        handle = helpers.gen_symmetric_key(rs, entry, config)
    except pytest.skip.Exception as exc:
        pytest.fail(f"unexpected skip: {exc}")

    assert handle == 99
    assert len(fake_raw.calls) == 1


def test_gen_symmetric_key_xfails_when_pbkdf2_returns_arguments_bad() -> None:
    fake_raw = _FakeRaw(rv=int(CKR_ARGUMENTS_BAD))
    rs = SimpleNamespace(raw=fake_raw, sh=7, has_mechanism=lambda _name: True)
    config = MechConfig(
        key_type=int(CKK_GENERIC_SECRET),
        keygen_mech=int(CKM_PKCS5_PBKD2),
        key_sizes=(),
        param_required=True,
        param_recipe=ParamRecipe("pbkdf2"),
        keygen_recipe=KeygenRecipe("symmetric"),
    )
    entry = MechEntry(
        mech_id=int(CKM_PKCS5_PBKD2),
        mech_name="PKCS5_PBKD2",
        flags=0,
        min_key_size=16,
        max_key_size=64,
        config=config,
    )

    with pytest.raises(
        pytest.xfail.Exception,
        match="PKCS5_PBKD2 keygen rejected.*CKR_ARGUMENTS_BAD",
    ):
        helpers.gen_symmetric_key(rs, entry, config)

    assert len(fake_raw.calls) == 1


def test_build_test_params_builds_rc2_mac_general_params() -> None:
    from pkcs11_check.raw.types_std import CK_RC2_MAC_GENERAL_PARAMS

    params = helpers.build_test_params(
        int(CKM_RC2_MAC_GENERAL),
        ParamRecipe("rc2_mac_general", {"effective_bits": 128, "mac_len": 8}),
    )

    assert params != "SKIP"
    assert params.params is not None
    assert isinstance(params.params, CK_RC2_MAC_GENERAL_PARAMS)
    assert params.params.ulEffectiveBits == 128
    assert params.params.ulMacLength == 8


def test_build_params_from_vector_replays_generic_mac_general_length() -> None:
    params = helpers.build_params_from_vector(
        int(CKM_ARIA_MAC_GENERAL),
        ParamRecipe("mac_general", {"mac_len": 8}),
        {"params": {"mac_len": 16}},
    )

    assert params != "SKIP"
    assert ctypes.string_at(params.ck.pParameter, params.ck.ulParameterLen) == (
        (16).to_bytes(8, "little")
    )


@pytest.mark.parametrize(
    ("mech_id", "recipe", "expected_params_type"),
    [
        (CKM_RC5_ECB, ParamRecipe("rc5", {"word_bits": 32, "rounds": 12}), "CK_RC5_PARAMS"),
        (CKM_RC5_MAC, ParamRecipe("rc5", {"word_bits": 32, "rounds": 12}), "CK_RC5_PARAMS"),
        (
            CKM_RC5_CBC,
            ParamRecipe("rc5_cbc", {"word_bits": 32, "rounds": 12}),
            "CK_RC5_CBC_PARAMS",
        ),
        (
            CKM_RC5_CBC_PAD,
            ParamRecipe("rc5_cbc", {"word_bits": 32, "rounds": 12}),
            "CK_RC5_CBC_PARAMS",
        ),
        (
            CKM_RC5_MAC_GENERAL,
            ParamRecipe("rc5_mac_general", {"word_bits": 32, "rounds": 12, "mac_len": 8}),
            "CK_RC5_MAC_GENERAL_PARAMS",
        ),
    ],
)
def test_build_test_params_builds_rc5_params(
    mech_id: int,
    recipe: ParamRecipe,
    expected_params_type: str,
) -> None:
    params = helpers.build_test_params(int(mech_id), recipe)

    assert params != "SKIP"
    assert params.params is not None
    assert type(params.params).__name__ == expected_params_type
    assert params.params.ulWordsize == 32
    assert params.params.ulRounds == 12


@pytest.mark.parametrize(
    ("mech_id", "expected_style"),
    [
        (CKM_RC5_ECB, "rc5"),
        (CKM_RC5_MAC, "rc5"),
        (CKM_RC5_CBC, "rc5_cbc"),
        (CKM_RC5_CBC_PAD, "rc5_cbc"),
        (CKM_RC5_MAC_GENERAL, "rc5_mac_general"),
    ],
)
def test_rc5_registry_uses_buildable_parameter_recipes(
    mech_id: int,
    expected_style: str,
) -> None:
    config = MECHANISM_REGISTRY[int(mech_id)]

    assert config.param_required is True
    assert config.param_recipe.style == expected_style
    assert helpers.build_test_params(int(mech_id), config.param_recipe) != "SKIP"


@pytest.mark.parametrize(
    ("mech_id", "recipe", "expected_params_type"),
    [
        (CKM_SALSA20, ParamRecipe("salsa20", {"nonce_len": 8}), "CK_SALSA20_PARAMS"),
        (
            CKM_SALSA20_POLY1305,
            ParamRecipe("salsa20_poly1305", {"nonce_len": 8, "aad_len": 0}),
            "CK_SALSA20_CHACHA20_POLY1305_PARAMS",
        ),
    ],
)
def test_build_test_params_builds_salsa_params(
    mech_id: int,
    recipe: ParamRecipe,
    expected_params_type: str,
) -> None:
    params = helpers.build_test_params(int(mech_id), recipe)

    assert params != "SKIP"
    assert params.params is not None
    assert type(params.params).__name__ == expected_params_type


@pytest.mark.parametrize(
    ("mech_id", "expected_style"),
    [
        (CKM_SALSA20, "salsa20"),
        (CKM_SALSA20_POLY1305, "salsa20_poly1305"),
    ],
)
def test_salsa_registry_uses_buildable_parameter_recipes(
    mech_id: int,
    expected_style: str,
) -> None:
    config = MECHANISM_REGISTRY[int(mech_id)]

    assert config.param_required is True
    assert config.param_recipe.style == expected_style
    assert helpers.build_test_params(int(mech_id), config.param_recipe) != "SKIP"


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
