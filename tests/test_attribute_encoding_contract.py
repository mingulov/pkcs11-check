"""Production-method contracts for QC7a/QC7b/QC7d (#59.1/.2/.3/.5).

Scope split (Task 18 brief ruling 6): this file covers QC7a attribute
value encodings, QC7b modulus bits, and QC7d omitted-flag defaults.
QC7c unique-id contracts live in ``test_object_identity_contract.py``.

Every production leg is driven through its real testcase method against
a scriptable fake token at the raw ``C_*`` layer (pattern b): the real
``read_attributes`` two-call protocol and the QC7d raw CK_BBOOL reader
run against the fake, so recipe-layer masking (a ``0x02`` bool byte, a
refusal CKR with leaked bytes) is observable. Fakes only; no provider.
"""

from __future__ import annotations

import ctypes
import sys
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import (
    CK_MECHANISM_INFO,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
    CKA_DERIVE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_MODULUS_BITS,
    CKA_SIGN_RECOVER,
    CKA_VALUE,
    CKA_VERIFY_RECOVER,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import test_attribute_defaults as defaults_case
from pkcs11_check.testcases import test_keypair_consistency as pair_case
from pkcs11_check.testcases import test_object as object_case
from tests._skip_assert import assert_xfails

_OK = int(CKR_OK)
_TYPE_INVALID = int(CKR_ATTRIBUTE_TYPE_INVALID)
_SENSITIVE = int(CKR_ATTRIBUTE_SENSITIVE)
_READ_ONLY = int(CKR_ATTRIBUTE_READ_ONLY)
_GENERAL = int(CKR_GENERAL_ERROR)
_NOT_PERMITTED = int(CKR_KEY_FUNCTION_NOT_PERMITTED)
_UNAVAILABLE = int(CK_UNAVAILABLE_INFORMATION)
_VALUE = int(CKA_VALUE)
_DERIVE = int(CKA_DERIVE)
_MODULUS = int(CKA_MODULUS)
_MODULUS_BITS = int(CKA_MODULUS_BITS)


def _ulong_blob(value: int) -> bytes:
    return int(value).to_bytes(ctypes.sizeof(CK_ULONG), sys.byteorder)


def _decode_template(tmpl: Any, count: int) -> dict[int, bytes]:
    if tmpl is None:
        assert count == 0
        return {}
    decoded: dict[int, bytes] = {}
    for i in range(count):
        attr = tmpl[i]
        alen = int(attr.ulValueLen)
        addr = attr.pValue
        decoded[int(attr.type)] = ctypes.string_at(addr, alen) if addr and alen > 0 else b""
    return decoded


def _write_handle(ptr: Any, handle: int) -> None:
    ctypes.cast(ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = handle


class _EncodingRaw:
    """Scriptable fake token for the QC7a/QC7b/QC7d production methods."""

    def __init__(self) -> None:
        self.objects: dict[int, dict[int, bytes]] = {}
        self.roles: dict[int, str] = {}
        self.destroyed: list[int] = []
        self.staged: list[int] = []
        self.create_calls: list[dict[int, bytes]] = []
        self.genpair_calls: list[dict[str, Any]] = []
        self.derive_calls: list[int] = []
        self._next_handle = 100
        self._search: list[int] = []
        # Knobs seeded by individual contracts.
        self.attr_rv_by_role: dict[tuple[str, int], int] = {}
        self.attr_leak_by_role: set[tuple[str, int]] = set()
        self.attr_sentinel_ok_by_role: set[tuple[str, int]] = set()
        self.genpair_queue: list[tuple[dict[int, bytes], dict[int, bytes]]] = []
        self.genpair_bbools: dict[tuple[str, int], bytes] = {}
        self.genpair_pub_value_len: int | None = None
        self.create_overrides: dict[int, bytes] = {}
        self.create_transform: Callable[[dict[int, bytes]], dict[int, bytes]] | None = None
        self.modulus_bits_mode = "derive"  # derive | missing | eight_len | wrong
        self.forbidden_create_mode = "read_only"  # read_only | general | inconsistent | accept
        # O1/O2 knobs for the forbidden-MODULUS_BITS create leg: value
        # written into the output handle on refusal, an object leaked
        # before returning the refusal, and CKR_OK without any object.
        self.forbidden_handle_write: int | None = None
        self.forbidden_leak = "none"  # none | labeled | unlabeled
        self.forbidden_ok_without_object = False
        self.refuse_padded_modulus_rv: int | None = None
        self.derive_on_false_claim = "refuse"  # refuse | succeed

    def _alloc(self, attrs: dict[int, bytes], role: str) -> int:
        self._next_handle += 1
        handle = self._next_handle
        self.objects[handle] = dict(attrs)
        self.roles[handle] = role
        self.staged.append(handle)
        return handle

    # -- attribute reads -------------------------------------------------
    def C_GetAttributeValue(self, _sh: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        stored = self.objects.get(int(handle))
        assert stored is not None, f"read from unknown handle {handle}"
        role = self.roles.get(int(handle), "")
        row_rvs: list[int] = []
        for i in range(count):
            attr = int(tmpl[i].type)
            cap = int(tmpl[i].ulValueLen)
            addr = tmpl[i].pValue
            blob = stored.get(attr)
            key = (role, attr)
            if key in self.attr_leak_by_role and blob is not None:
                if addr:
                    ctypes.memmove(addr, blob, min(len(blob), cap))
                tmpl[i].ulValueLen = len(blob)
                row_rvs.append(_TYPE_INVALID)
                continue
            if key in self.attr_sentinel_ok_by_role:
                tmpl[i].ulValueLen = _UNAVAILABLE
                row_rvs.append(_OK)
                continue
            scripted = self.attr_rv_by_role.get(key)
            if scripted is not None:
                tmpl[i].ulValueLen = _UNAVAILABLE
                row_rvs.append(scripted)
                continue
            if blob is None:
                tmpl[i].ulValueLen = _UNAVAILABLE
                row_rvs.append(_TYPE_INVALID)
                continue
            if addr:
                ctypes.memmove(addr, blob, min(len(blob), cap))
            tmpl[i].ulValueLen = len(blob)
            row_rvs.append(_OK)
        if _SENSITIVE in row_rvs:
            return _SENSITIVE
        if _TYPE_INVALID in row_rvs:
            return _TYPE_INVALID
        return _OK

    # -- creation ---------------------------------------------------------
    def C_CreateObject(self, _sh: int, tmpl: Any, count: int, handle_ptr: Any) -> int:  # noqa: N802
        if count == 0:
            return int(CKR_TEMPLATE_INCOMPLETE)
        attrs = _decode_template(tmpl, int(count))
        self.create_calls.append(attrs)
        if _MODULUS_BITS in attrs:
            refusal = {
                "read_only": _READ_ONLY,
                "general": _GENERAL,
                "inconsistent": int(CKR_TEMPLATE_INCONSISTENT),
            }.get(self.forbidden_create_mode)
            if refusal is not None:
                if self.forbidden_leak != "none":
                    leak_attrs = dict(attrs)
                    if self.forbidden_leak == "unlabeled":
                        leak_attrs.pop(int(CKA_LABEL), None)
                    self._alloc(leak_attrs, "create")
                if self.forbidden_handle_write is not None:
                    _write_handle(handle_ptr, self.forbidden_handle_write)
                return refusal
            if self.forbidden_ok_without_object:
                return _OK  # CKR_OK, sentinel untouched, nothing created.
            # accept: fall through and create (the seeded defect).
        modulus = attrs.get(_MODULUS)
        if (
            self.refuse_padded_modulus_rv is not None
            and modulus is not None
            and modulus.startswith(b"\x00")
        ):
            return self.refuse_padded_modulus_rv
        stored = dict(attrs)
        if modulus is not None and _MODULUS_BITS not in stored:
            if self.modulus_bits_mode == "derive":
                stored[_MODULUS_BITS] = _ulong_blob(int.from_bytes(modulus, "big").bit_length())
            elif self.modulus_bits_mode == "eight_len":
                stored[_MODULUS_BITS] = _ulong_blob(8 * len(modulus))
            elif self.modulus_bits_mode == "wrong":
                stored[_MODULUS_BITS] = _ulong_blob(1024)
        stored.update(self.create_overrides)
        if self.create_transform is not None:
            stored = self.create_transform(stored)
        handle = self._alloc(stored, "create")
        _write_handle(handle_ptr, handle)
        return _OK

    def C_GenerateKeyPair(  # noqa: N802
        self,
        _sh: int,
        mech: Any,
        pub_tmpl: Any,
        pub_count: int,
        priv_tmpl: Any,
        priv_count: int,
        pub_ptr: Any,
        priv_ptr: Any,
    ) -> int:
        pub_attrs = _decode_template(pub_tmpl, int(pub_count))
        priv_attrs = _decode_template(priv_tmpl, int(priv_count))
        self.genpair_calls.append(
            {"mechanism": int(mech._obj.mechanism), "pub": pub_attrs, "priv": priv_attrs}
        )
        pub_stored = dict(pub_attrs)
        priv_stored = dict(priv_attrs)
        # CKA_MODULUS_BITS in a generation template is an input, not a
        # readback: the provider-derived readback exists only when seeded.
        pub_stored.pop(_MODULUS_BITS, None)
        if self.genpair_queue:
            pub_extra, priv_extra = self.genpair_queue.pop(0)
            pub_stored.update(pub_extra)
            priv_stored.update(priv_extra)
        for (role, attr), blob in self.genpair_bbools.items():
            # Omitted-flag readbacks only: an explicitly templated value wins.
            if role == "pub":
                pub_stored.setdefault(attr, blob)
            elif role == "priv":
                priv_stored.setdefault(attr, blob)
        if self.genpair_pub_value_len is not None:
            pub_stored[_VALUE] = b"\x11" * self.genpair_pub_value_len
        pub = self._alloc(pub_stored, "genpair_pub")
        priv = self._alloc(priv_stored, "genpair_priv")
        _write_handle(pub_ptr, pub)
        _write_handle(priv_ptr, priv)
        return _OK

    def C_GenerateKey(  # noqa: N802
        self, _sh: int, _mech: Any, tmpl: Any, count: int, handle_ptr: Any
    ) -> int:
        handle = self._alloc(_decode_template(tmpl, int(count)), "genkey")
        _write_handle(handle_ptr, handle)
        return _OK

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        self.destroyed.append(int(handle))
        self.objects.pop(int(handle), None)
        return _OK

    def C_GetMechanismInfo(self, _slot: int, _mech: int, info_ptr: Any) -> int:  # noqa: N802
        info = ctypes.cast(info_ptr, ctypes.POINTER(CK_MECHANISM_INFO)).contents
        info.ulMinKeySize = 1024
        info.ulMaxKeySize = 4096
        info.flags = 0
        return _OK

    # -- search (label inventory) -----------------------------------------
    def C_FindObjectsInit(self, _sh: int, tmpl: Any, count: int) -> int:  # noqa: N802
        wanted = _decode_template(tmpl, int(count))
        label = wanted.get(int(CKA_LABEL))
        self._search = [
            handle
            for handle, attrs in self.objects.items()
            if label is None or attrs.get(int(CKA_LABEL)) == label
        ]
        return _OK

    def C_FindObjects(self, _sh: int, handles: Any, max_count: int, found_ptr: Any) -> int:  # noqa: N802
        take = self._search[: int(max_count)]
        for i, handle in enumerate(take):
            handles[i] = handle
        ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents.value = len(take)
        self._search = []
        return _OK

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        return _OK

    # -- derive -------------------------------------------------------------
    def C_DeriveKey(  # noqa: N802
        self, _sh: int, _mech: Any, base: int, tmpl: Any, count: int, handle_ptr: Any
    ) -> int:
        self.derive_calls.append(int(base))
        stored = self.objects.get(int(base), {})
        if stored.get(_DERIVE) == b"\x01":
            derived = self._alloc({_VALUE: b"\x22" * 32}, "derived")
            _write_handle(handle_ptr, derived)
            return _OK
        if self.derive_on_false_claim == "succeed":
            derived = self._alloc({_VALUE: b"\x22" * 32}, "derived")
            _write_handle(handle_ptr, derived)
            return _OK
        return _NOT_PERMITTED


@pytest.fixture(autouse=True)
def _clear_classifications() -> Iterator[None]:
    C.clear()
    yield
    C.clear()


def _rs(fake: _EncodingRaw) -> SimpleNamespace:
    return SimpleNamespace(
        raw=fake,
        sh=7,
        slot_id=0,
        has_mechanism=lambda *_a: True,
        has_mechanism_flag=lambda *_a: True,
    )


def _assert_cleanup(fake: _EncodingRaw) -> None:
    assert sorted(fake.destroyed) == sorted(fake.staged), (fake.destroyed, fake.staged)


def _records() -> list[Any]:
    return C.get_records()


# --- QC7a: absent CKA_VALUE inverse oracle (#1-#3) ------------------------


@pytest.mark.parametrize("family", ["rsa", "ec", "edwards", "montgomery"])
def test_public_value_type_invalid_passes(family: str) -> None:
    fake = _EncodingRaw()
    object_case.TestAttributeValueEncodings().test_public_value_absent(_rs(fake), family)
    assert _records() == []
    _assert_cleanup(fake)


@pytest.mark.parametrize("family", ["rsa", "ec", "edwards", "montgomery"])
def test_public_value_present_spki_fails(family: str) -> None:
    fake = _EncodingRaw()
    spki = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    fake.genpair_queue = [({_VALUE: spki}, {})]
    with pytest.raises(Failed):
        object_case.TestAttributeValueEncodings().test_public_value_absent(_rs(fake), family)
    assert any(rec.reason == "wrong_result" for rec in _records())
    _assert_cleanup(fake)


def test_rsa_public_value_present_spki_fails() -> None:
    test_public_value_present_spki_fails("rsa")


def test_ec_public_value_type_invalid_passes() -> None:
    test_public_value_type_invalid_passes("ec")


def test_public_value_type_invalid_with_leaked_bytes_fails() -> None:
    fake = _EncodingRaw()
    fake.genpair_queue = [({_VALUE: b"\x30\x59leaked-spki-bytes"}, {})]
    fake.attr_leak_by_role = {("genpair_pub", _VALUE)}
    with pytest.raises(Failed):
        object_case.TestAttributeValueEncodings().test_public_value_absent(_rs(fake), "rsa")
    assert any(rec.reason == "self_contradiction" for rec in _records())
    _assert_cleanup(fake)


def test_public_value_sentinel_without_ckr_passes() -> None:
    fake = _EncodingRaw()
    fake.attr_sentinel_ok_by_role = {("genpair_pub", _VALUE)}
    object_case.TestAttributeValueEncodings().test_public_value_absent(_rs(fake), "ec")
    _assert_cleanup(fake)


# --- QC7a: DSA / DH raw Y (#4) ---------------------------------------------


def _dsa_spki_transform(stored: dict[int, bytes]) -> dict[int, bytes]:
    from pkcs11_check.raw.types_std import CKA_BASE, CKA_CLASS, CKA_PRIME, CKA_SUBPRIME

    out = dict(stored)
    if out.get(int(CKA_CLASS)) == _ulong_blob(2):  # CKO_PUBLIC_KEY
        numbers = dsa.DSAPublicNumbers(
            y=int.from_bytes(out[_VALUE], "big"),
            parameter_numbers=dsa.DSAParameterNumbers(
                p=int.from_bytes(out[int(CKA_PRIME)], "big"),
                q=int.from_bytes(out[int(CKA_SUBPRIME)], "big"),
                g=int.from_bytes(out[int(CKA_BASE)], "big"),
            ),
        )
        out[_VALUE] = numbers.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    return out


def test_dsa_public_value_raw_y_passes() -> None:
    fake = _EncodingRaw()
    object_case.TestAttributeValueEncodings().test_dsa_public_value_is_raw_y(_rs(fake))
    _assert_cleanup(fake)


def test_dsa_public_value_der_wrapped_is_not_raw() -> None:
    fake = _EncodingRaw()
    fake.create_transform = _dsa_spki_transform
    with pytest.raises(Failed):
        object_case.TestAttributeValueEncodings().test_dsa_public_value_is_raw_y(_rs(fake))
    assert any(rec.reason == "wrong_result" for rec in _records())
    _assert_cleanup(fake)


def test_dh_public_value_raw_y_passes() -> None:
    fake = _EncodingRaw()
    object_case.TestAttributeValueEncodings().test_dh_public_value_is_raw_y(_rs(fake))
    _assert_cleanup(fake)


def test_dh_public_value_leading_zero_padding_passes() -> None:
    fake = _EncodingRaw()

    def _pad(stored: dict[int, bytes]) -> dict[int, bytes]:
        from pkcs11_check.raw.types_std import CKA_CLASS

        out = dict(stored)
        if out.get(int(CKA_CLASS)) == _ulong_blob(2) and _VALUE in out:
            out[_VALUE] = b"\x00" + out[_VALUE]
        return out

    fake.create_transform = _pad
    object_case.TestAttributeValueEncodings().test_dh_public_value_is_raw_y(_rs(fake))
    _assert_cleanup(fake)


# --- QC7a: PQC public lengths ----------------------------------------------


@pytest.mark.parametrize(
    ("family", "expected_len"),
    [("ml_dsa_44", 1312), ("ml_kem_512", 800), ("slh_dsa_sha2_128s", 32)],
)
def test_pqc_public_value_length_passes(family: str, expected_len: int) -> None:
    fake = _EncodingRaw()
    fake.genpair_pub_value_len = expected_len
    object_case.TestAttributeValueEncodings().test_pqc_public_value_raw_lengths(_rs(fake), family)
    _assert_cleanup(fake)


@pytest.mark.parametrize(
    ("family", "expected_len"),
    [("ml_dsa_44", 1312), ("ml_kem_512", 800), ("slh_dsa_sha2_128s", 32)],
)
def test_pqc_public_value_der_length_fails(family: str, expected_len: int) -> None:
    fake = _EncodingRaw()
    fake.genpair_pub_value_len = expected_len + 24  # SPKI-wrapped length shape
    with pytest.raises(Failed):
        object_case.TestAttributeValueEncodings().test_pqc_public_value_raw_lengths(
            _rs(fake), family
        )
    _assert_cleanup(fake)


def test_pqc_public_value_missing_is_recorded() -> None:
    fake = _EncodingRaw()
    assert_xfails(
        object_case.TestAttributeValueEncodings().test_pqc_public_value_raw_lengths,
        _rs(fake),
        "ml_dsa_44",
    )
    assert any(rec.reason == "honest_deviation" for rec in _records())
    _assert_cleanup(fake)


# --- QC7a: private raw known material (#5, #6) ------------------------------


@pytest.mark.parametrize("family", ["ec", "edwards", "montgomery", "ml_dsa_44"])
def test_private_value_raw_known_material_passes(family: str) -> None:
    fake = _EncodingRaw()
    object_case.TestAttributeValueEncodings().test_private_ec_family_value_raw_known_material(
        _rs(fake), family
    )
    _assert_cleanup(fake)


def _ec_pkcs8_transform(stored: dict[int, bytes]) -> dict[int, bytes]:
    out = dict(stored)
    scalar = out.get(_VALUE, b"")
    if len(scalar) == 32:
        key = ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())
        out[_VALUE] = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    return out


def test_ec_private_value_pkcs8_fails_when_unsealed() -> None:
    fake = _EncodingRaw()
    fake.create_transform = _ec_pkcs8_transform
    with pytest.raises(Failed):
        object_case.TestAttributeValueEncodings().test_private_ec_family_value_raw_known_material(
            _rs(fake), "ec"
        )
    assert any(rec.reason == "wrong_result" for rec in _records())
    _assert_cleanup(fake)


def test_ec_private_value_sensitive_refusal_after_unsealed_claim_fails() -> None:
    fake = _EncodingRaw()
    fake.attr_rv_by_role = {("create", _VALUE): _SENSITIVE}
    with pytest.raises(Failed):
        object_case.TestAttributeValueEncodings().test_private_ec_family_value_raw_known_material(
            _rs(fake), "ec"
        )
    _assert_cleanup(fake)


def test_private_value_claim_overridden_is_not_judged() -> None:
    from pkcs11_check.raw.types_std import CKA_SENSITIVE

    fake = _EncodingRaw()
    fake.create_overrides = {int(CKA_SENSITIVE): b"\x01"}
    fake.attr_rv_by_role = {("create", _VALUE): _SENSITIVE}
    assert_xfails(
        object_case.TestAttributeValueEncodings().test_private_ec_family_value_raw_known_material,
        _rs(fake),
        "ec",
    )
    assert any(rec.reason == "honest_deviation" for rec in _records())
    _assert_cleanup(fake)


# --- QC7a: generated/imported equivalence (#7) -------------------------------


def test_generated_imported_private_value_equivalent_passes() -> None:
    fake = _EncodingRaw()
    scalar = b"\x01" + b"\x07" * 31
    fake.genpair_queue = [({}, {_VALUE: scalar})]
    object_case.TestAttributeValueEncodings().test_private_value_generated_imported_equivalent(
        _rs(fake)
    )
    _assert_cleanup(fake)


def test_generated_imported_private_value_mismatch_fails() -> None:
    fake = _EncodingRaw()
    scalar = b"\x01" + b"\x07" * 31
    sec1 = ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1()).private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    fake.genpair_queue = [({}, {_VALUE: sec1})]
    fake.create_transform = _ec_pkcs8_transform
    with pytest.raises(Failed):
        object_case.TestAttributeValueEncodings().test_private_value_generated_imported_equivalent(
            _rs(fake)
        )
    _assert_cleanup(fake)


# --- QC7b: modulus bits (#8-#12) ----------------------------------------------


def _modulus_blob(bits: int) -> bytes:
    return b"\x80" + b"\x11" * (bits // 8 - 1)


@pytest.mark.parametrize("bits", [2048, 3072])
def test_generated_modulus_bits_pass(bits: int) -> None:
    fake = _EncodingRaw()
    fake.genpair_queue = [({_MODULUS: _modulus_blob(bits), _MODULUS_BITS: _ulong_blob(bits)}, {})]
    pair_case.TestRSAModulusBits().test_generated_modulus_bits_match(_rs(fake), bits)
    _assert_cleanup(fake)


def test_modulus_bits_missing_is_recorded_not_silent() -> None:
    fake = _EncodingRaw()
    fake.genpair_queue = [({_MODULUS: _modulus_blob(2048)}, {})]
    assert_xfails(pair_case.TestRSAModulusBits().test_generated_modulus_bits_match, _rs(fake), 2048)
    assert _records() != []
    _assert_cleanup(fake)


def test_modulus_bits_eight_times_length_bug_caught() -> None:
    fake = _EncodingRaw()
    padded = b"\x00" + _modulus_blob(2048)  # 257 bytes, bit length 2048
    fake.genpair_queue = [({_MODULUS: padded, _MODULUS_BITS: _ulong_blob(8 * len(padded))}, {})]
    with pytest.raises(Failed):
        pair_case.TestRSAModulusBits().test_generated_modulus_bits_match(_rs(fake), 2048)
    _assert_cleanup(fake)


def test_modulus_bits_padded_modulus_correct_bits_pass() -> None:
    fake = _EncodingRaw()
    padded = b"\x00" + _modulus_blob(2048)
    fake.genpair_queue = [({_MODULUS: padded, _MODULUS_BITS: _ulong_blob(2048)}, {})]
    pair_case.TestRSAModulusBits().test_generated_modulus_bits_match(_rs(fake), 2048)
    _assert_cleanup(fake)


def test_modulus_bits_malformed_bool_fails() -> None:
    fake = _EncodingRaw()
    fake.genpair_queue = [({_MODULUS: _modulus_blob(2048), _MODULUS_BITS: b"\x01"}, {})]
    with pytest.raises(Failed):
        pair_case.TestRSAModulusBits().test_generated_modulus_bits_match(_rs(fake), 2048)
    _assert_cleanup(fake)


def test_imported_known_modulus_bits_pass() -> None:
    fake = _EncodingRaw()
    pair_case.TestRSAModulusBits().test_imported_known_modulus_bits(_rs(fake))
    assert all(_MODULUS_BITS not in call for call in fake.create_calls)
    _assert_cleanup(fake)


def test_imported_modulus_bits_wrong_fails() -> None:
    fake = _EncodingRaw()
    fake.modulus_bits_mode = "wrong"
    with pytest.raises(Failed):
        pair_case.TestRSAModulusBits().test_imported_known_modulus_bits(_rs(fake))
    _assert_cleanup(fake)


def test_imported_leading_zero_modulus_bits_pass() -> None:
    fake = _EncodingRaw()
    pair_case.TestRSAModulusBits().test_imported_leading_zero_modulus_bits(_rs(fake))
    _assert_cleanup(fake)


def test_imported_leading_zero_refusal_xfails() -> None:
    fake = _EncodingRaw()
    fake.refuse_padded_modulus_rv = _GENERAL
    assert_xfails(pair_case.TestRSAModulusBits().test_imported_leading_zero_modulus_bits, _rs(fake))
    assert any(rec.actual_ckr == "CKR_GENERAL_ERROR" for rec in _records())
    _assert_cleanup(fake)


@pytest.mark.parametrize("supplied", ["correct", "wrong"])
def test_create_with_modulus_bits_read_only_passes(supplied: str) -> None:
    fake = _EncodingRaw()
    pair_case.TestRSAModulusBits().test_create_with_modulus_bits_rejected(_rs(fake), supplied)
    assert fake.staged == []
    assert any(_MODULUS_BITS in call for call in fake.create_calls)


def _forbidden_record(reason: str) -> Any:
    matches = [
        rec
        for rec in _records()
        if rec.reason == reason and "forbidden CKA_MODULUS_BITS" in rec.label
    ]
    assert len(matches) == 1, [(rec.reason, rec.label) for rec in _records()]
    return matches[0]


# O2 (Task 18 Docker adjudication): acceptance judges stored bits against
# the true modulus bit length, not against the supplied value. Storing the
# true value (or dropping the attribute) is an honest deviation; storing a
# false value FAILs. The stored-equals-supplied note stays provenance-honest.
def test_create_with_correct_modulus_bits_accepted_stored_true_xfails_and_cleans_up() -> None:
    fake = _EncodingRaw()
    fake.forbidden_create_mode = "accept"
    assert_xfails(
        pair_case.TestRSAModulusBits().test_create_with_modulus_bits_rejected,
        _rs(fake),
        "correct",
    )
    detail = _forbidden_record("honest_deviation").detail
    assert detail["supplied_bits"] == detail["true_bits"]
    assert detail["stored_bits"] == detail["true_bits"]
    assert detail["stored"] == "stored-equals-supplied"
    assert detail["handle_class"] == "new-live"
    assert detail["found_by_label"] == fake.staged
    assert detail["new_handles"] == fake.staged
    _assert_cleanup(fake)


def test_create_with_wrong_modulus_bits_accepted_stored_wrong_fails_and_cleans_up() -> None:
    fake = _EncodingRaw()
    fake.forbidden_create_mode = "accept"
    with pytest.raises(Failed):
        pair_case.TestRSAModulusBits().test_create_with_modulus_bits_rejected(_rs(fake), "wrong")
    detail = _forbidden_record("accepted_invalid").detail
    assert detail["supplied_bits"] == 1024
    assert detail["stored_bits"] == 1024
    assert detail["true_bits"] != 1024
    assert detail["stored"] == "stored-equals-supplied"
    _assert_cleanup(fake)


def test_create_with_modulus_bits_accepted_stored_overwritten_to_true_xfails() -> None:
    fake = _EncodingRaw()
    fake.forbidden_create_mode = "accept"

    def _true_bits(stored: dict[int, bytes]) -> dict[int, bytes]:
        out = dict(stored)
        modulus = out.get(_MODULUS)
        if modulus is not None and _MODULUS_BITS in out:
            out[_MODULUS_BITS] = _ulong_blob(int.from_bytes(modulus, "big").bit_length())
        return out

    fake.create_transform = _true_bits
    assert_xfails(
        pair_case.TestRSAModulusBits().test_create_with_modulus_bits_rejected,
        _rs(fake),
        "wrong",
    )
    detail = _forbidden_record("honest_deviation").detail
    assert detail["supplied_bits"] == 1024
    assert detail["stored_bits"] == detail["true_bits"]
    assert detail["stored"] == "caller-value-overwritten"
    _assert_cleanup(fake)


def test_create_with_modulus_bits_accepted_stored_dropped_xfails_and_cleans_up() -> None:
    fake = _EncodingRaw()
    fake.forbidden_create_mode = "accept"

    def _drop_bits(stored: dict[int, bytes]) -> dict[int, bytes]:
        out = dict(stored)
        out.pop(_MODULUS_BITS, None)
        return out

    fake.create_transform = _drop_bits
    assert_xfails(
        pair_case.TestRSAModulusBits().test_create_with_modulus_bits_rejected,
        _rs(fake),
        "correct",
    )
    detail = _forbidden_record("honest_deviation").detail
    assert detail["supplied_bits"] == detail["true_bits"]
    assert detail["stored_bits"] is None
    _assert_cleanup(fake)


def test_create_with_modulus_bits_ok_without_object_fails() -> None:
    fake = _EncodingRaw()
    fake.forbidden_create_mode = "accept"
    fake.forbidden_ok_without_object = True
    with pytest.raises(Failed):
        pair_case.TestRSAModulusBits().test_create_with_modulus_bits_rejected(_rs(fake), "correct")
    detail = _forbidden_record("self_contradiction").detail
    assert detail["handle_class"] == "sentinel"
    assert detail["found_by_label"] == []
    assert detail["new_handles"] == []
    assert detail["stored_bits"] is None
    assert fake.staged == []


def test_create_with_wrong_modulus_bits_other_clean_refusal_xfails() -> None:
    fake = _EncodingRaw()
    fake.forbidden_create_mode = "general"
    assert_xfails(
        pair_case.TestRSAModulusBits().test_create_with_modulus_bits_rejected,
        _rs(fake),
        "wrong",
    )
    assert any(rec.actual_ckr == "CKR_GENERAL_ERROR" for rec in _records())
    assert fake.staged == []


# O1 rows for the modulus refusal branch: judge objects, not handle writes.
@pytest.mark.parametrize("mode", ["read_only", "inconsistent"])
def test_create_with_modulus_bits_zero_write_canonical_passes(mode: str) -> None:
    fake = _EncodingRaw()
    fake.forbidden_create_mode = mode
    fake.forbidden_handle_write = 0
    pair_case.TestRSAModulusBits().test_create_with_modulus_bits_rejected(_rs(fake), "correct")
    assert fake.staged == []
    assert fake.destroyed == []


def test_create_with_modulus_bits_zero_write_general_xfails_nonspec() -> None:
    fake = _EncodingRaw()
    fake.forbidden_create_mode = "general"
    fake.forbidden_handle_write = 0
    assert_xfails(
        pair_case.TestRSAModulusBits().test_create_with_modulus_bits_rejected,
        _rs(fake),
        "wrong",
    )
    detail = _forbidden_record("nonspec_reject").detail
    assert detail["handle_after"] == 0
    assert detail["handle_class"] == "zero"
    assert detail["found_by_label"] == []
    assert detail["new_handles"] == []
    assert fake.staged == []
    assert fake.destroyed == []


def test_create_with_modulus_bits_dead_nonzero_xfails_honest_deviation() -> None:
    fake = _EncodingRaw()
    fake.forbidden_handle_write = 987_654
    assert_xfails(
        pair_case.TestRSAModulusBits().test_create_with_modulus_bits_rejected,
        _rs(fake),
        "correct",
    )
    detail = _forbidden_record("honest_deviation").detail
    assert detail["handle_after"] == 987_654
    assert detail["handle_class"] == "dead-nonzero"
    assert detail["found_by_label"] == []
    assert detail["new_handles"] == []
    assert fake.staged == []
    assert 987_654 not in fake.destroyed


def test_create_with_modulus_bits_refusal_labeled_leak_fails_and_cleans_up() -> None:
    fake = _EncodingRaw()
    fake.forbidden_create_mode = "general"
    fake.forbidden_leak = "labeled"
    with pytest.raises(Failed):
        pair_case.TestRSAModulusBits().test_create_with_modulus_bits_rejected(_rs(fake), "correct")
    detail = _forbidden_record("self_contradiction").detail
    assert detail["handle_class"] == "sentinel"
    assert detail["found_by_label"] == fake.staged
    assert detail["new_handles"] == fake.staged
    _assert_cleanup(fake)


def test_create_with_modulus_bits_refusal_unlabeled_new_object_fails_and_cleans_up() -> None:
    fake = _EncodingRaw()
    fake.forbidden_create_mode = "general"
    fake.forbidden_leak = "unlabeled"
    with pytest.raises(Failed):
        pair_case.TestRSAModulusBits().test_create_with_modulus_bits_rejected(_rs(fake), "correct")
    detail = _forbidden_record("self_contradiction").detail
    assert detail["handle_class"] == "sentinel"
    assert detail["found_by_label"] == []
    assert detail["new_handles"] == fake.staged
    _assert_cleanup(fake)


# --- QC7d: strict CK_BBOOL + minimal pairs (#13-#17) --------------------------


def _seed_bbools(
    fake: _EncodingRaw,
    *,
    derive_pub: bytes = b"\x00",
    derive_priv: bytes = b"\x00",
    verify_recover: bytes = b"\x01",
    sign_recover: bytes = b"\x00",
) -> None:
    fake.genpair_bbools = {
        ("pub", _DERIVE): derive_pub,
        ("priv", _DERIVE): derive_priv,
        ("pub", int(CKA_VERIFY_RECOVER)): verify_recover,
        ("priv", int(CKA_SIGN_RECOVER)): sign_recover,
    }


@pytest.mark.parametrize(
    "method_name",
    [
        "test_rsa_minimal_pair_derive_defaults_false",
        "test_ec_minimal_pair_derive_defaults_false",
        "test_rsa_minimal_pair_recover_defaults_are_booleans",
        "test_ec_minimal_pair_recover_defaults_are_booleans",
    ],
)
def test_minimal_pair_defaults_pass(method_name: str) -> None:
    fake = _EncodingRaw()
    _seed_bbools(fake)
    getattr(defaults_case.TestOmittedUsageFlagDefaults(), method_name)(_rs(fake))
    _assert_cleanup(fake)


def test_minimal_templates_really_omit_usage_flags() -> None:
    fake = _EncodingRaw()
    _seed_bbools(fake)
    defaults_case.TestOmittedUsageFlagDefaults().test_rsa_minimal_pair_derive_defaults_false(
        _rs(fake)
    )
    assert len(fake.genpair_calls) == 1
    call = fake.genpair_calls[0]
    for tmpl in (call["pub"], call["priv"]):
        assert _DERIVE not in tmpl
        assert int(CKA_VERIFY_RECOVER) not in tmpl
        assert int(CKA_SIGN_RECOVER) not in tmpl
    _assert_cleanup(fake)


def test_bbool_byte_0x02_is_malformed_not_true() -> None:
    fake = _EncodingRaw()
    _seed_bbools(fake, derive_pub=b"\x02")
    with pytest.raises(Failed):
        defaults_case.TestOmittedUsageFlagDefaults().test_rsa_minimal_pair_derive_defaults_false(
            _rs(fake)
        )
    assert any(rec.reason == "wrong_result" for rec in _records())
    _assert_cleanup(fake)


@pytest.mark.parametrize("blob", [b"\x01\x00", b""])
def test_bbool_wrong_length_is_malformed(blob: bytes) -> None:
    fake = _EncodingRaw()
    _seed_bbools(fake, sign_recover=blob)
    with pytest.raises(Failed):
        defaults_case.TestOmittedUsageFlagDefaults().test_ec_minimal_pair_recover_defaults_are_booleans(
            _rs(fake)
        )
    _assert_cleanup(fake)


def test_derive_default_true_is_visible() -> None:
    fake = _EncodingRaw()
    _seed_bbools(fake, derive_priv=b"\x01")
    assert_xfails(
        defaults_case.TestOmittedUsageFlagDefaults().test_ec_minimal_pair_derive_defaults_false,
        _rs(fake),
    )
    assert any(rec.reason == "honest_deviation" for rec in _records())
    _assert_cleanup(fake)


def test_recover_missing_both_halves_recorded() -> None:
    fake = _EncodingRaw()
    _seed_bbools(fake)
    fake.attr_rv_by_role = {
        ("genpair_pub", int(CKA_VERIFY_RECOVER)): _TYPE_INVALID,
        ("genpair_priv", int(CKA_SIGN_RECOVER)): _TYPE_INVALID,
    }
    assert_xfails(
        defaults_case.TestOmittedUsageFlagDefaults().test_rsa_minimal_pair_recover_defaults_are_booleans,
        _rs(fake),
    )
    recorded_attrs = {
        rec.detail["attribute"]["id"]
        for rec in _records()
        if rec.detail and "attribute" in rec.detail
    }
    assert recorded_attrs == {int(CKA_VERIFY_RECOVER), int(CKA_SIGN_RECOVER)}
    _assert_cleanup(fake)


def test_derive_claim_false_blocks_derive_passes() -> None:
    fake = _EncodingRaw()
    _seed_bbools(fake)
    defaults_case.TestOmittedUsageFlagDefaults().test_derive_false_claim_blocks_derive(_rs(fake))
    assert len(fake.derive_calls) == 2  # positive control + judged leg
    _assert_cleanup(fake)


def test_derive_claim_false_but_derive_succeeds_fails() -> None:
    fake = _EncodingRaw()
    _seed_bbools(fake)
    fake.derive_on_false_claim = "succeed"
    with pytest.raises(Failed):
        defaults_case.TestOmittedUsageFlagDefaults().test_derive_false_claim_blocks_derive(
            _rs(fake)
        )
    assert any(rec.reason == "wrong_result" for rec in _records())
    _assert_cleanup(fake)
