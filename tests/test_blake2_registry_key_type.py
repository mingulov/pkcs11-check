"""Pins for BLAKE2b registry key types (P11C-005).

The sixteen BLAKE2b registry entries (four widths times HMAC, HMAC_GENERAL,
KEY_GEN, KEY_DERIVE) must carry their typed CKK_BLAKE2B_*_HMAC key type. With
``key_type=CKK_GENERIC_SECRET`` every shared-mech leg calls the typed
``CKM_BLAKE2B_*_KEY_GEN`` with a disagreeing ``CKA_KEY_TYPE`` in the template,
which compliant modules reject with ``CKR_TEMPLATE_INCONSISTENT`` (40 xfails
per lane that should pass).

Sixteen-row behavioral table: each row drives the real wrong-key-type probe
(``_wrong_secret_key_type``) and the real proper-key path
(``generate_key_for_sign``) against a fake token. The wrong-key probe must
resolve to CKK_AES -- generic-secret keys are legal HMAC operation keys, so
they cannot serve as the "wrong" type once the registry is typed.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKK_AES,
    CKK_BLAKE2B_160_HMAC,
    CKK_BLAKE2B_256_HMAC,
    CKK_BLAKE2B_384_HMAC,
    CKK_BLAKE2B_512_HMAC,
    CKK_GENERIC_SECRET,
    CKM_AES_ECB,
    CKM_BLAKE2B_160_HMAC,
    CKM_BLAKE2B_160_HMAC_GENERAL,
    CKM_BLAKE2B_160_KEY_DERIVE,
    CKM_BLAKE2B_160_KEY_GEN,
    CKM_BLAKE2B_256_HMAC,
    CKM_BLAKE2B_256_HMAC_GENERAL,
    CKM_BLAKE2B_256_KEY_DERIVE,
    CKM_BLAKE2B_256_KEY_GEN,
    CKM_BLAKE2B_384_HMAC,
    CKM_BLAKE2B_384_HMAC_GENERAL,
    CKM_BLAKE2B_384_KEY_DERIVE,
    CKM_BLAKE2B_384_KEY_GEN,
    CKM_BLAKE2B_512_HMAC,
    CKM_BLAKE2B_512_HMAC_GENERAL,
    CKM_BLAKE2B_512_KEY_DERIVE,
    CKM_BLAKE2B_512_KEY_GEN,
    CKM_DES3_ECB,
    CKM_DES_ECB,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_SHA256_HMAC,
    CKM_SHA256_HMAC_GENERAL,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_OK,
)
from pkcs11_check.testcases import test_mech_message, test_mech_negative
from pkcs11_check.testcases._key_type_contracts import wrong_secret_key_type
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_helpers import generate_key_for_sign
from pkcs11_check.testcases.mechanism_registry import get_config


@dataclass(frozen=True)
class _Blake2Case:
    case_id: str
    mech: int
    keygen_mech: int
    key_type: int  # enum member (int subclass)
    legacy: int  # accepted legacy plain-int numeric for the same code
    recipe_style: str


_BLAKE2_CASES: tuple[_Blake2Case, ...] = (
    _Blake2Case(
        "blake2b-160-hmac",
        CKM_BLAKE2B_160_HMAC,
        CKM_BLAKE2B_160_KEY_GEN,
        CKK_BLAKE2B_160_HMAC,
        0x3A,
        "none",
    ),
    _Blake2Case(
        "blake2b-160-hmac-general",
        CKM_BLAKE2B_160_HMAC_GENERAL,
        CKM_BLAKE2B_160_KEY_GEN,
        CKK_BLAKE2B_160_HMAC,
        0x3A,
        "mac_general",
    ),
    _Blake2Case(
        "blake2b-160-key-gen",
        CKM_BLAKE2B_160_KEY_GEN,
        CKM_BLAKE2B_160_KEY_GEN,
        CKK_BLAKE2B_160_HMAC,
        0x3A,
        "none",
    ),
    _Blake2Case(
        "blake2b-160-key-derive",
        CKM_BLAKE2B_160_KEY_DERIVE,
        CKM_BLAKE2B_160_KEY_GEN,
        CKK_BLAKE2B_160_HMAC,
        0x3A,
        "none",
    ),
    _Blake2Case(
        "blake2b-256-hmac",
        CKM_BLAKE2B_256_HMAC,
        CKM_BLAKE2B_256_KEY_GEN,
        CKK_BLAKE2B_256_HMAC,
        0x3B,
        "none",
    ),
    _Blake2Case(
        "blake2b-256-hmac-general",
        CKM_BLAKE2B_256_HMAC_GENERAL,
        CKM_BLAKE2B_256_KEY_GEN,
        CKK_BLAKE2B_256_HMAC,
        0x3B,
        "mac_general",
    ),
    _Blake2Case(
        "blake2b-256-key-gen",
        CKM_BLAKE2B_256_KEY_GEN,
        CKM_BLAKE2B_256_KEY_GEN,
        CKK_BLAKE2B_256_HMAC,
        0x3B,
        "none",
    ),
    _Blake2Case(
        "blake2b-256-key-derive",
        CKM_BLAKE2B_256_KEY_DERIVE,
        CKM_BLAKE2B_256_KEY_GEN,
        CKK_BLAKE2B_256_HMAC,
        0x3B,
        "none",
    ),
    _Blake2Case(
        "blake2b-384-hmac",
        CKM_BLAKE2B_384_HMAC,
        CKM_BLAKE2B_384_KEY_GEN,
        CKK_BLAKE2B_384_HMAC,
        0x3C,
        "none",
    ),
    _Blake2Case(
        "blake2b-384-hmac-general",
        CKM_BLAKE2B_384_HMAC_GENERAL,
        CKM_BLAKE2B_384_KEY_GEN,
        CKK_BLAKE2B_384_HMAC,
        0x3C,
        "mac_general",
    ),
    _Blake2Case(
        "blake2b-384-key-gen",
        CKM_BLAKE2B_384_KEY_GEN,
        CKM_BLAKE2B_384_KEY_GEN,
        CKK_BLAKE2B_384_HMAC,
        0x3C,
        "none",
    ),
    _Blake2Case(
        "blake2b-384-key-derive",
        CKM_BLAKE2B_384_KEY_DERIVE,
        CKM_BLAKE2B_384_KEY_GEN,
        CKK_BLAKE2B_384_HMAC,
        0x3C,
        "none",
    ),
    _Blake2Case(
        "blake2b-512-hmac",
        CKM_BLAKE2B_512_HMAC,
        CKM_BLAKE2B_512_KEY_GEN,
        CKK_BLAKE2B_512_HMAC,
        0x3D,
        "none",
    ),
    _Blake2Case(
        "blake2b-512-hmac-general",
        CKM_BLAKE2B_512_HMAC_GENERAL,
        CKM_BLAKE2B_512_KEY_GEN,
        CKK_BLAKE2B_512_HMAC,
        0x3D,
        "mac_general",
    ),
    _Blake2Case(
        "blake2b-512-key-gen",
        CKM_BLAKE2B_512_KEY_GEN,
        CKM_BLAKE2B_512_KEY_GEN,
        CKK_BLAKE2B_512_HMAC,
        0x3D,
        "none",
    ),
    _Blake2Case(
        "blake2b-512-key-derive",
        CKM_BLAKE2B_512_KEY_DERIVE,
        CKM_BLAKE2B_512_KEY_GEN,
        CKK_BLAKE2B_512_HMAC,
        0x3D,
        "none",
    ),
)


def _selector_entry(mechanism: int) -> MechEntry:
    config = get_config(mechanism)
    assert config is not None, f"no registry config for 0x{mechanism:08x}"
    return MechEntry(
        mech_id=mechanism,
        mech_name=f"selector-{mechanism:x}",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=config,
    )


@pytest.mark.parametrize(
    ("case_id", "mechanism", "expected", "wrapper_skips"),
    [
        ("blake2b-160-hmac", CKM_BLAKE2B_160_HMAC, CKK_AES, False),
        ("blake2b-160-hmac-general", CKM_BLAKE2B_160_HMAC_GENERAL, CKK_AES, False),
        ("blake2b-256-hmac", CKM_BLAKE2B_256_HMAC, CKK_AES, False),
        ("blake2b-256-hmac-general", CKM_BLAKE2B_256_HMAC_GENERAL, CKK_AES, False),
        ("blake2b-384-hmac", CKM_BLAKE2B_384_HMAC, CKK_AES, False),
        ("blake2b-384-hmac-general", CKM_BLAKE2B_384_HMAC_GENERAL, CKK_AES, False),
        ("blake2b-512-hmac", CKM_BLAKE2B_512_HMAC, CKK_AES, False),
        ("blake2b-512-hmac-general", CKM_BLAKE2B_512_HMAC_GENERAL, CKK_AES, False),
        ("ordinary-sha256-hmac", CKM_SHA256_HMAC, CKK_AES, True),
        ("ordinary-sha256-hmac-general", CKM_SHA256_HMAC_GENERAL, CKK_AES, True),
        ("generic-secret", CKM_GENERIC_SECRET_KEY_GEN, CKK_AES, False),
        ("aes", CKM_AES_ECB, CKK_GENERIC_SECRET, False),
        ("des", CKM_DES_ECB, CKK_GENERIC_SECRET, False),
        ("des3", CKM_DES3_ECB, CKK_GENERIC_SECRET, False),
    ],
    ids=lambda row: row if isinstance(row, str) else None,
)
def test_classic_and_message_wrong_key_type_excludes_all_legal_types(
    case_id: str,
    mechanism: int,
    expected: int,
    wrapper_skips: bool,
) -> None:
    """Wrong-key controls must not submit a legal generic-secret BLAKE2 key.

    This test intentionally uses literal expected key types. It catches either
    wrapper reverting to its old duplicated fallback or a selector broadening
    the negative to a legal input.
    """
    entry = _selector_entry(mechanism)
    assert int(wrong_secret_key_type(entry)) == int(expected), case_id
    if wrapper_skips:
        with pytest.raises(pytest.skip.Exception):
            test_mech_negative._wrong_secret_key_type(entry)
        with pytest.raises(pytest.skip.Exception):
            test_mech_message._wrong_message_secret_key_type(entry)
        return

    assert int(test_mech_negative._wrong_secret_key_type(entry)) == int(expected), case_id
    assert int(test_mech_message._wrong_message_secret_key_type(entry)) == int(expected), case_id


def _assert_code_equal(witness: Any, expected: int, legacy: int, label: str) -> None:
    """Assert a CKK/CKR witness portably (enum member or legacy numeric)."""
    assert int(expected) == int(legacy), f"{label}: pin table inconsistent ({expected!r})"
    assert witness is not None, f"{label}: witness is None, expected {expected!r} ({legacy:#x})"
    got = int(witness)
    assert got == int(legacy), f"{label}: witness {witness!r} != {expected!r} ({legacy:#x})"


def _template_ulongs(tmpl: Any, count: int) -> dict[int, int]:
    """Decode ulong-sized template entries to {CKA_*: value}."""
    arr = ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE))
    decoded: dict[int, int] = {}
    for idx in range(count):
        attr = arr[idx]
        if int(attr.ulValueLen) == ctypes.sizeof(CK_ULONG):
            scalar = ctypes.cast(attr.pValue, ctypes.POINTER(CK_ULONG)).contents.value
            decoded[int(attr.type)] = int(scalar)
    return decoded


class _KeygenCaptureRaw:
    """Fake token capturing the C_GenerateKey mechanism id and template."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, dict[int, int]]] = []

    def C_GenerateKey(  # noqa: N802
        self,
        _session: int,
        mech: Any,
        tmpl: Any,
        count: int,
        out: Any,
    ) -> int:
        mech_id = int(ctypes.cast(mech, ctypes.POINTER(CK_MECHANISM)).contents.mechanism)
        self.calls.append((mech_id, _template_ulongs(tmpl, count)))
        ctypes.cast(out, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = 77
        return CKR_OK


class _MessageWrongKeyRaw:
    """Message Init fake that accepts generic-secret but rejects AES."""

    def __init__(self, key_types: dict[int, int]) -> None:
        self.key_types = key_types
        self.calls: list[tuple[str, int]] = []

    def _init(self, operation: str, key: int) -> int:
        self.calls.append((operation, key))
        if self.key_types[key] == int(CKK_AES):
            return int(CKR_KEY_TYPE_INCONSISTENT)
        return int(CKR_OK)

    def C_MessageSignInit(self, _session: int, _mechanism: object, key: int) -> int:  # noqa: N802
        return self._init("sign", key)

    def C_MessageVerifyInit(  # noqa: N802
        self, _session: int, _mechanism: object, key: int
    ) -> int:
        return self._init("verify", key)

    def C_MessageSignFinal(self, _session: int) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_MessageVerifyFinal(self, _session: int) -> int:  # noqa: N802
        return int(CKR_OK)


@pytest.mark.parametrize(
    ("init_name", "final_name"),
    [("C_MessageSignInit", "C_MessageSignFinal"), ("C_MessageVerifyInit", "C_MessageVerifyFinal")],
)
def test_message_wrong_key_nodes_submit_aes_and_preserve_key_material(
    monkeypatch: pytest.MonkeyPatch,
    init_name: str,
    final_name: str,
) -> None:
    """The old message negatives must exercise an actually incompatible key."""
    from types import SimpleNamespace

    entry = _selector_entry(CKM_BLAKE2B_160_HMAC)
    key_types: dict[int, int] = {}
    captured: dict[str, object] = {}

    def _import(
        _rs: object,
        key_type: int,
        value: bytes,
        *,
        attrs: dict[int, object],
        purpose: str,
    ) -> int:
        captured.update(key_type=key_type, value=value, attrs=attrs, purpose=purpose)
        key_types[101] = int(key_type)
        return 101

    monkeypatch.setattr(test_mech_message, "import_secret_key_negotiated", _import)
    raw = _MessageWrongKeyRaw(key_types)
    rs = SimpleNamespace(raw=raw, sh=1)
    attrs = {CKA_TOKEN: False, CKA_SIGN: True, CKA_VERIFY: True}
    key = test_mech_message._import_wrong_message_key_or_xfail(rs, entry, attrs=attrs)

    assert key == 101
    assert captured == {
        "key_type": int(CKK_AES),
        "value": b"\x42" * 32,
        "attrs": attrs,
        "purpose": "selector-400d message wrong-key setup",
    }
    test_mech_message._message_wrong_key_init_must_reject(
        rs,
        entry,
        key=key,
        init_name=init_name,
        final_name=final_name,
        label=f"{entry.mech_name} {init_name} with wrong key type",
    )
    expected_operation = "sign" if init_name == "C_MessageSignInit" else "verify"
    assert raw.calls == [(expected_operation, 101)]


@pytest.mark.parametrize("case", _BLAKE2_CASES, ids=[c.case_id for c in _BLAKE2_CASES])
def test_blake2_registry_key_type(case: _Blake2Case) -> None:
    config = get_config(case.mech)
    assert config is not None, f"{case.case_id}: no registry config for 0x{case.mech:08x}"
    entry = MechEntry(
        mech_id=case.mech,
        mech_name=case.case_id,
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=config,
    )

    # 1. Wrong-key probe: generic-secret keys are legal HMAC operation keys,
    # so the negative must use a genuinely incompatible type (CKK_AES).
    wrong = test_mech_negative._wrong_secret_key_type(entry)
    _assert_code_equal(wrong, CKK_AES, 0x1F, f"{case.case_id}: wrong-key probe type")

    # 2. Proper-key setup must reach C_GenerateKey with the typed CKA_KEY_TYPE.
    raw = _KeygenCaptureRaw()
    rs = SimpleNamespace(raw=raw, sh=1)
    try:
        handle, _verify = generate_key_for_sign(rs, entry, config)
    except pytest.skip.Exception as exc:
        pytest.fail(f"{case.case_id}: proper-key setup skipped ({exc}); expected C_GenerateKey")
    assert handle == 77, f"{case.case_id}: unexpected key handle {handle}"
    assert len(raw.calls) == 1, f"{case.case_id}: expected 1 C_GenerateKey call, saw {raw.calls}"
    seen_mech, attrs = raw.calls[0]
    assert int(seen_mech) == int(case.keygen_mech), (
        f"{case.case_id}: keygen mech 0x{int(seen_mech):08x} != 0x{int(case.keygen_mech):08x}"
    )
    witness = attrs.get(int(CKA_KEY_TYPE))
    assert witness is not None, f"{case.case_id}: CKA_KEY_TYPE missing from keygen template"
    _assert_code_equal(witness, case.key_type, case.legacy, f"{case.case_id}: CKA_KEY_TYPE")
    assert attrs.get(int(CKA_VALUE_LEN)) == 32, (
        f"{case.case_id}: CKA_VALUE_LEN {attrs.get(int(CKA_VALUE_LEN))} != 32"
    )

    # 3. Registry anchors (keygen mech, param recipe, key sizes untouched).
    _assert_code_equal(
        config.key_type, case.key_type, case.legacy, f"{case.case_id}: registry key_type"
    )
    assert config.keygen_mech is not None, f"{case.case_id}: keygen_mech is None"
    assert int(config.keygen_mech) == int(case.keygen_mech), (
        f"{case.case_id}: keygen_mech 0x{int(config.keygen_mech):08x}"
        f" != 0x{int(case.keygen_mech):08x}"
    )
    assert config.param_recipe.style == case.recipe_style, (
        f"{case.case_id}: param recipe {config.param_recipe.style!r} != {case.recipe_style!r}"
    )
    assert config.key_sizes == (), f"{case.case_id}: key sizes {config.key_sizes} != ()"
