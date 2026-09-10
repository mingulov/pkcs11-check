"""Classic Diffie-Hellman key agreement tests.

Tests CKM_DH_PKCS_KEY_PAIR_GEN, CKM_DH_PKCS_DERIVE, and
CKM_DH_PKCS_PARAMETER_GEN where supported.

Uses RFC 3526 Group 14 (2048-bit MODP) for known-good parameters.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import (
    attr_bool,
    attr_bytes,
    attr_ulong,
    mech_bytes,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import (
    create_object,
    decrypt_single,
    derive_key,
    destroy_quietly,
    encrypt_single,
    read_attributes,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_BASE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_PRIME,
    CKA_PRIME_BITS,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_AES,
    CKK_DH,
    CKK_GENERIC_SECRET,
    CKM_AES_ECB,
    CKM_DH_PKCS_DERIVE,
    CKM_DH_PKCS_KEY_PAIR_GEN,
    CKM_DH_PKCS_PARAMETER_GEN,
    CKO_PRIVATE_KEY,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import (
    assert_correct,
    classify_negative_rv,
    reject_or_classify,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.keymgmt

# RFC 3526 Group 14 (2048-bit MODP) - widely supported safe prime.
DH_PRIME_2048 = bytes.fromhex(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
DH_GEN = bytes([0x02])

_DH_RFC3526_GROUP14_ALICE_PRIVATE = bytes.fromhex(
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
)
_DH_RFC3526_GROUP14_BOB_PUBLIC = bytes.fromhex(
    "f0fee7626bcec4d1c5c1fb11b8058af4061c0e877d02ca7a"
    "edf42e33280eb58f4309a566a74456e01d97fdba45043cd6"
    "74315204b9b2409f26aeffd643010ec5e197ee67b24f0f04"
    "6d1dce630794822cfe9360ed40c6975d5a2bb5892686cea6"
    "469fb9f92a52210564419dd6bfd3e023d33a4468e81b97f3"
    "09c7df7be746d8660089738b09885dc100285952096132ca"
    "8d3e369525e588df9cfa4ee06280f7a9acf92bf180187af"
    "a6a9927b9d65f26adf2417a2e4cf3974bc5992dbd499733"
    "7bec667f7b73c5b59fa03d6455070825c9f69c3f048e705"
    "1485e2c7edd1ef972219ec6c98c973f895982c4ad77784"
    "f8807ae75680ceeb8b1aafca61a1517b42ca7"
)
_DH_RFC3526_GROUP14_EXPECTED_SECRET_32 = bytes.fromhex(
    "b11d9c9a159da66466777ab95e0081fa91576855cdbac2286d05d90eef8fd436"
)

_DH_DERIVE_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_DH_INVALID_PEER_PUBLIC_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

_DH_PARAMETER_TEMPLATE_REJECT_RVS = (CKR_TEMPLATE_INCOMPLETE,)


def _skip_no_dh(p11_raw_session: Any) -> None:
    """Skip if DH mechanisms are not available."""
    if not p11_raw_session.has_mechanism("DH_PKCS_KEY_PAIR_GEN"):
        pytest.skip("CKM_DH_PKCS_KEY_PAIR_GEN not supported")
    if not p11_raw_session.has_mechanism("DH_PKCS_DERIVE"):
        pytest.skip("CKM_DH_PKCS_DERIVE not supported")


def _gen_dh_keypair(
    raw: Any,
    sh: int,
    prime: bytes = DH_PRIME_2048,
    base: bytes = DH_GEN,
    *,
    derive: bool = True,
    extra_pub: dict[int, Any] | None = None,
    extra_priv: dict[int, Any] | None = None,
) -> tuple[int, int]:
    """Generate a DH keypair using C_GenerateKeyPair with given domain params."""
    pub_attrs = [
        attr_bytes(CKA_PRIME, prime),
        attr_bytes(CKA_BASE, base),
        attr_bool(CKA_TOKEN, False),
    ]
    if derive:
        pub_attrs.append(attr_bool(CKA_DERIVE, True))
    if extra_pub:
        from pkcs11_check.raw.pack import attr_auto

        for k, v in extra_pub.items():
            pub_attrs.append(attr_auto(k, v))

    priv_attrs = [
        attr_bool(CKA_TOKEN, False),
    ]
    if derive:
        priv_attrs.append(attr_bool(CKA_DERIVE, True))
    if extra_priv:
        from pkcs11_check.raw.pack import attr_auto

        for k, v in extra_priv.items():
            priv_attrs.append(attr_auto(k, v))

    pub_tmpl = template(*pub_attrs)
    priv_tmpl = template(*priv_attrs)
    mech = mech_simple(CKM_DH_PKCS_KEY_PAIR_GEN)
    pub_h = CK_OBJECT_HANDLE(0)
    priv_h = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        sh,
        mech.byref(),
        pub_tmpl.ptr,
        pub_tmpl.count,
        priv_tmpl.ptr,
        priv_tmpl.count,
        byref(pub_h),
        byref(priv_h),
    )
    expect_rv(rv, CKR_OK)
    return pub_h.value, priv_h.value


def _dh_derive_or_xfail(
    rs: Any,
    private_key: int,
    peer_public_value: bytes,
    attrs: Mapping[Any, Any],
    label: str,
) -> int:
    try:
        return derive_key(
            rs.raw,
            rs.sh,
            private_key,
            CKM_DH_PKCS_DERIVE,
            attrs=attrs,
            mech_param=mech_bytes(CKM_DH_PKCS_DERIVE, peer_public_value),
        )
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _DH_DERIVE_RUNTIME_REJECT_RVS,
            f"{label}: DH derive advertised but not operational",
        )
        raise


def _import_dh_private_key(
    raw: Any,
    sh: int,
    private_value: bytes,
) -> int:
    """Import a DH private key for deterministic derive vectors."""
    return create_object(
        raw,
        sh,
        {
            CKA_CLASS: CKO_PRIVATE_KEY,
            CKA_KEY_TYPE: CKK_DH,
            CKA_PRIME: DH_PRIME_2048,
            CKA_BASE: DH_GEN,
            CKA_VALUE: private_value,
            CKA_DERIVE: True,
            CKA_TOKEN: False,
        },
    )


def _dh_setup_or_xfail(fn: Callable[[], int], label: str) -> int:
    try:
        return fn()
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _DH_DERIVE_RUNTIME_REJECT_RVS,
            f"{label}: DH exact-vector setup is not operational",
        )
        raise


_DH_DERIVE_MECHANISM_NAME = "CKM_DH_PKCS_DERIVE"
_DH_KEYPAIR_MECHANISM_NAME = "CKM_DH_PKCS_KEY_PAIR_GEN"


def _dh_attribute_info(attr: int) -> dict[str, Any]:
    from pkcs11_check.raw.metadata_std import ATTR_NAMES

    return {"name": ATTR_NAMES.get(int(attr), f"0x{int(attr):08x}"), "id": int(attr)}


def _dh_shape_record(
    value: Any,
    *,
    attr: int,
    leg: str,
    label: str,
    expected: str,
    expected_length: int | None,
    producer_operation: str,
    producer_mechanism: str,
) -> C.Classification | None:
    """Record a present provider value that cannot safely feed an oracle."""
    if value is MISSING_ATTRIBUTE:
        return None
    if (
        type(value) is bytes
        and len(value) > 0
        and (expected_length is None or len(value) == expected_length)
    ):
        return None
    try:
        actual_length: int | None = len(value)
    except TypeError:
        actual_length = None
    detail: dict[str, Any] = {
        "attribute": _dh_attribute_info(attr),
        "leg": leg,
        "expected": {
            "type": "bytes",
            "length": expected_length if expected_length is not None else "non-empty",
            "shape": expected,
        },
        "actual": {"type": type(value).__name__, "length": actual_length},
        "producer_operation": producer_operation,
        "producer_mechanism": producer_mechanism,
    }
    return C.record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        mechanism=None,
        detail=detail,
        summary=f"{label}: provider returned a value with the wrong shape",
    )


def _dh_read_and_validate(
    rs: Any,
    handle: int,
    *,
    attr: int,
    leg: str,
    label: str,
    expected: str,
    expected_length: int | None,
    producer_operation: str,
    producer_mechanism: str,
) -> tuple[Any, C.Classification | None]:
    """Read one leg and retain missing/shape evidence without terminating."""
    before = len(C.get_records())
    attrs = read_attributes(rs.raw, rs.sh, handle, [attr])
    value = attr_or_record(
        attrs,
        attr,
        label=label,
        reason="not_operational",
        kind="metadata",
    )
    new_records = C.get_records()[before:]
    if value is MISSING_ATTRIBUTE:
        if not new_records:
            raise AssertionError(f"{label}: missing attribute did not produce evidence")
        record = new_records[-1]
        if record.detail is None:
            record.detail = {}
        record.detail.update(
            {
                "leg": leg,
                "producer_operation": producer_operation,
                "producer_mechanism": producer_mechanism,
            }
        )
        return value, None
    return value, _dh_shape_record(
        value,
        attr=attr,
        leg=leg,
        label=label,
        expected=expected,
        expected_length=expected_length,
        producer_operation=producer_operation,
        producer_mechanism=producer_mechanism,
    )


def _dh_raise_hard(records: list[C.Classification | None]) -> None:
    hard = [record for record in records if record is not None and record.outcome == "fail"]
    if hard:
        C.raise_for_record(hard[0])


def _dh_check_derived_pair(
    first: Any,
    second: Any,
    *,
    first_shape: C.Classification | None,
    second_shape: C.Classification | None,
    label: str,
    relation: str,
) -> None:
    """Raise shape evidence before absence gating and crypto relation checks."""
    _dh_raise_hard([first_shape, second_shape])
    if first is MISSING_ATTRIBUTE or second is MISSING_ATTRIBUTE:
        return
    relation_holds = first == second if relation == "equal" else first != second
    if relation_holds:
        return
    record = C.record_as(
        "wrong_result",
        kind="crypto",
        label=label,
        operation="C_DeriveKey",
        mechanism=_DH_DERIVE_MECHANISM_NAME,
        detail={"relation": relation, "legs": ["first", "second"]},
        summary=f"{label}: derived outputs violate the required relation",
    )
    C.raise_for_record(record)


def _dh_record_kat_mismatch(
    value: Any,
    *,
    expected: bytes,
    label: str,
) -> C.Classification | None:
    """Retain a wrong known-answer result until all paired reads complete."""
    if value is MISSING_ATTRIBUTE or value == expected:
        return None
    return C.record_as(
        "wrong_result",
        kind="crypto",
        label=label,
        operation="C_DeriveKey",
        mechanism=_DH_DERIVE_MECHANISM_NAME,
        source="RFC 3526 Group 14",
        detail={"expected_length": len(expected), "actual_length": len(value)},
        summary=f"{label}: derived value does not match the known answer",
    )


def _dh_record_duplicate_public(
    first: Any,
    second: Any,
    *,
    first_shape: C.Classification | None,
    second_shape: C.Classification | None,
    legs: list[str],
) -> C.Classification | None:
    """Record equal usable generated public values without exposing key material."""
    if (
        first is MISSING_ATTRIBUTE
        or second is MISSING_ATTRIBUTE
        or first_shape is not None
        or second_shape is not None
        or first != second
    ):
        return None
    try:
        actual_length: int | None = len(first)
    except TypeError:
        actual_length = None
    return C.record_as(
        "wrong_result",
        kind="crypto",
        label="CKM_DH_PKCS_KEY_PAIR_GEN:independent public values differ",
        operation="C_GenerateKeyPair",
        mechanism=_DH_KEYPAIR_MECHANISM_NAME,
        detail={
            "attribute": _dh_attribute_info(CKA_VALUE),
            "expected": "different generated public values",
            "actual": {"type": type(first).__name__, "length": actual_length},
            "legs": legs,
        },
        summary=("CKM_DH_PKCS_KEY_PAIR_GEN: independent generated public values were equal"),
    )


class TestDHKeyAgreement:
    """Test DH key pair generation and key derivation."""

    def test_dh_keypair_generation(self, p11_raw_session: Any) -> None:
        """Generate a DH keypair from known parameters."""
        rs = p11_raw_session
        _skip_no_dh(rs)

        pub, priv = _gen_dh_keypair(rs.raw, rs.sh)
        try:
            assert pub is not None
            assert priv is not None

            # Public key value should be non-empty
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_VALUE])
            pub_value = attr_or_record(
                attrs,
                CKA_VALUE,
                label="CKM_DH_PKCS_KEY_PAIR_GEN:public CKA_VALUE readback",
            )
            if pub_value is MISSING_ATTRIBUTE:
                return
            assert isinstance(pub_value, bytes)
            assert len(pub_value) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_dh_derive_shared_secret(self, p11_raw_session: Any) -> None:
        """Alice and Bob derive the same shared AES key."""
        rs = p11_raw_session
        _skip_no_dh(rs)

        # Alice and Bob each generate a keypair
        alice_pub = alice_priv = bob_pub = bob_priv = 0
        try:
            alice_pub, alice_priv = _gen_dh_keypair(rs.raw, rs.sh)
            bob_pub, bob_priv = _gen_dh_keypair(rs.raw, rs.sh)
            alice_value, alice_shape = _dh_read_and_validate(
                rs,
                alice_pub,
                attr=CKA_VALUE,
                leg="Alice public",
                label="CKM_DH_PKCS_DERIVE:Alice public CKA_VALUE",
                expected="non-empty bytes",
                expected_length=None,
                producer_operation="C_GenerateKeyPair",
                producer_mechanism=_DH_KEYPAIR_MECHANISM_NAME,
            )
            bob_value, bob_shape = _dh_read_and_validate(
                rs,
                bob_pub,
                attr=CKA_VALUE,
                leg="Bob public",
                label="CKM_DH_PKCS_DERIVE:Bob public CKA_VALUE",
                expected="non-empty bytes",
                expected_length=None,
                producer_operation="C_GenerateKeyPair",
                producer_mechanism=_DH_KEYPAIR_MECHANISM_NAME,
            )
            public_records: list[C.Classification | None] = [alice_shape, bob_shape]
            duplicate = _dh_record_duplicate_public(
                alice_value,
                bob_value,
                first_shape=alice_shape,
                second_shape=bob_shape,
                legs=["Alice public", "Bob public"],
            )
            if duplicate is not None:
                public_records.append(duplicate)

            # Each derives an AES-128 key using the other's public value
            alice_shared = 0
            bob_shared = 0
            try:
                if bob_value is not MISSING_ATTRIBUTE and bob_shape is None:
                    alice_shared = _dh_derive_or_xfail(
                        rs,
                        alice_priv,
                        bob_value,
                        attrs={
                            CKA_CLASS: CKO_SECRET_KEY,
                            CKA_KEY_TYPE: CKK_AES,
                            CKA_VALUE_LEN: 16,
                            CKA_SENSITIVE: False,
                            CKA_EXTRACTABLE: True,
                            CKA_TOKEN: False,
                        },
                        label="alice shared-secret derive",
                    )
                if alice_value is not MISSING_ATTRIBUTE and alice_shape is None:
                    bob_shared = _dh_derive_or_xfail(
                        rs,
                        bob_priv,
                        alice_value,
                        attrs={
                            CKA_CLASS: CKO_SECRET_KEY,
                            CKA_KEY_TYPE: CKK_AES,
                            CKA_VALUE_LEN: 16,
                            CKA_SENSITIVE: False,
                            CKA_EXTRACTABLE: True,
                            CKA_TOKEN: False,
                        },
                        label="bob shared-secret derive",
                    )
                # Both should derive the same key material
                a_value = b_value = MISSING_ATTRIBUTE
                a_shape = b_shape = None
                if alice_shared:
                    a_value, a_shape = _dh_read_and_validate(
                        rs,
                        alice_shared,
                        attr=CKA_VALUE,
                        leg="Alice derived",
                        label="CKM_DH_PKCS_DERIVE:Alice derived CKA_VALUE",
                        expected="exact-length bytes",
                        expected_length=16,
                        producer_operation="C_DeriveKey",
                        producer_mechanism=_DH_DERIVE_MECHANISM_NAME,
                    )
                if bob_shared:
                    b_value, b_shape = _dh_read_and_validate(
                        rs,
                        bob_shared,
                        attr=CKA_VALUE,
                        leg="Bob derived",
                        label="CKM_DH_PKCS_DERIVE:Bob derived CKA_VALUE",
                        expected="exact-length bytes",
                        expected_length=16,
                        producer_operation="C_DeriveKey",
                        producer_mechanism=_DH_DERIVE_MECHANISM_NAME,
                    )
                _dh_check_derived_pair(
                    a_value,
                    b_value,
                    first_shape=a_shape,
                    second_shape=b_shape,
                    relation="equal",
                    label="CKM_DH_PKCS_DERIVE:shared-secret agreement (A*B == B*A)",
                )
                _dh_raise_hard(public_records)
            finally:
                if alice_shared:
                    destroy_quietly(rs.raw, rs.sh, alice_shared)
                if bob_shared:
                    destroy_quietly(rs.raw, rs.sh, bob_shared)
        finally:
            if alice_pub:
                destroy_quietly(rs.raw, rs.sh, alice_pub)
            if alice_priv:
                destroy_quietly(rs.raw, rs.sh, alice_priv)
            if bob_pub:
                destroy_quietly(rs.raw, rs.sh, bob_pub)
            if bob_priv:
                destroy_quietly(rs.raw, rs.sh, bob_priv)

    def test_dh_derived_key_encrypts(self, p11_raw_session: Any) -> None:
        """Derived AES key from DH can encrypt/decrypt data."""
        rs = p11_raw_session
        _skip_no_dh(rs)

        alice_pub = alice_priv = bob_pub = bob_priv = 0
        try:
            alice_pub, alice_priv = _gen_dh_keypair(rs.raw, rs.sh)
            bob_pub, bob_priv = _gen_dh_keypair(rs.raw, rs.sh)
            bob_value, bob_shape = _dh_read_and_validate(
                rs,
                bob_pub,
                attr=CKA_VALUE,
                leg="Bob public",
                label="CKM_DH_PKCS_DERIVE:Bob public CKA_VALUE for Alice",
                expected="non-empty bytes",
                expected_length=None,
                producer_operation="C_GenerateKeyPair",
                producer_mechanism=_DH_KEYPAIR_MECHANISM_NAME,
            )
            alice_value, alice_shape = _dh_read_and_validate(
                rs,
                alice_pub,
                attr=CKA_VALUE,
                leg="Alice public",
                label="CKM_DH_PKCS_DERIVE:Alice public CKA_VALUE for Bob",
                expected="non-empty bytes",
                expected_length=None,
                producer_operation="C_GenerateKeyPair",
                producer_mechanism=_DH_KEYPAIR_MECHANISM_NAME,
            )
            public_records: list[C.Classification | None] = [bob_shape, alice_shape]

            # Alice derives shared key, encrypts
            shared_key = 0
            bob_key = 0
            try:
                if bob_value is not MISSING_ATTRIBUTE and bob_shape is None:
                    shared_key = _dh_derive_or_xfail(
                        rs,
                        alice_priv,
                        bob_value,
                        attrs={
                            CKA_CLASS: CKO_SECRET_KEY,
                            CKA_KEY_TYPE: CKK_AES,
                            CKA_VALUE_LEN: 16,
                            CKA_ENCRYPT: True,
                            CKA_DECRYPT: True,
                            CKA_TOKEN: False,
                        },
                        label="alice AES derive",
                    )
                if not shared_key:
                    if alice_value is not MISSING_ATTRIBUTE and alice_shape is None:
                        bob_key = _dh_derive_or_xfail(
                            rs,
                            bob_priv,
                            alice_value,
                            attrs={
                                CKA_CLASS: CKO_SECRET_KEY,
                                CKA_KEY_TYPE: CKK_AES,
                                CKA_VALUE_LEN: 16,
                                CKA_ENCRYPT: True,
                                CKA_DECRYPT: True,
                                CKA_TOKEN: False,
                            },
                            label="bob AES derive",
                        )
                    _dh_raise_hard(public_records)
                    return

                plaintext = b"DH key agreement!" + b"\x00" * 15  # pad to 32 bytes
                plaintext = plaintext[:32]
                ct = encrypt_single(rs.raw, rs.sh, shared_key, CKM_AES_ECB, plaintext)
                if ct == plaintext:
                    classify(
                        "wrong_result",
                        kind="crypto",
                        label="CKM_AES_ECB:ciphertext must differ from plaintext",
                        operation="C_Encrypt",
                        mechanism="CKM_AES_ECB",
                        summary=(
                            "CKM_AES_ECB with a DH-derived key returned ciphertext equal "
                            "to the plaintext -- encryption was a no-op"
                        ),
                    )

                # Bob derives the same shared key, decrypts
                if alice_value is MISSING_ATTRIBUTE or alice_shape is not None:
                    _dh_raise_hard(public_records)
                    return
                bob_key = _dh_derive_or_xfail(
                    rs,
                    bob_priv,
                    alice_value,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_VALUE_LEN: 16,
                        CKA_ENCRYPT: True,
                        CKA_DECRYPT: True,
                        CKA_TOKEN: False,
                    },
                    label="bob AES derive",
                )
                pt = decrypt_single(rs.raw, rs.sh, bob_key, CKM_AES_ECB, ct)
                assert_correct(
                    actual=pt,
                    expected=plaintext,
                    label="CKM_DH_PKCS_DERIVE:AES-ECB roundtrip (both parties)",
                    operation="C_Decrypt",
                    mechanism="CKM_AES_ECB",
                )
                _dh_raise_hard(public_records)
            finally:
                if bob_key:
                    destroy_quietly(rs.raw, rs.sh, bob_key)
                if shared_key:
                    destroy_quietly(rs.raw, rs.sh, shared_key)
        finally:
            if alice_pub:
                destroy_quietly(rs.raw, rs.sh, alice_pub)
            if alice_priv:
                destroy_quietly(rs.raw, rs.sh, alice_priv)
            if bob_pub:
                destroy_quietly(rs.raw, rs.sh, bob_pub)
            if bob_priv:
                destroy_quietly(rs.raw, rs.sh, bob_priv)

    def test_dh_pkcs_derive_rfc3526_group14_exact_vector(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKM_DH_PKCS_DERIVE returns the expected RFC 3526 Group 14 secret."""
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_DERIVE"):
            pytest.skip("CKM_DH_PKCS_DERIVE not supported")

        priv = 0
        derived = 0
        try:
            priv = _dh_setup_or_xfail(
                lambda: _import_dh_private_key(
                    rs.raw,
                    rs.sh,
                    _DH_RFC3526_GROUP14_ALICE_PRIVATE,
                ),
                "CKM_DH_PKCS_DERIVE RFC 3526 Group 14 vector",
            )
            derived = _dh_derive_or_xfail(
                rs,
                priv,
                _DH_RFC3526_GROUP14_BOB_PUBLIC,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: len(_DH_RFC3526_GROUP14_EXPECTED_SECRET_32),
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_TOKEN: False,
                },
                label="CKM_DH_PKCS_DERIVE RFC 3526 Group 14 exact vector",
            )
            value_attrs = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])
            value = attr_or_record(
                value_attrs,
                CKA_VALUE,
                label="CKM_DH_PKCS_DERIVE RFC 3526 Group 14:derived CKA_VALUE",
                reason="not_operational",
            )
            if value is MISSING_ATTRIBUTE:
                return
            assert_correct(
                actual=value,
                expected=_DH_RFC3526_GROUP14_EXPECTED_SECRET_32,
                label="CKM_DH_PKCS_DERIVE:C_DeriveKey KAT (RFC 3526 Group 14)",
                operation="C_DeriveKey",
                mechanism="CKM_DH_PKCS_DERIVE",
                source="RFC 3526 Group 14",
            )
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)

    def test_dh_pkcs_derive_rfc3526_group14_value_len_truncation(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKM_DH_PKCS_DERIVE truncates the RFC 3526 secret by removing leading bytes."""
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_DERIVE"):
            pytest.skip("CKM_DH_PKCS_DERIVE not supported")

        priv = 0
        derived_keys: list[int] = []
        try:
            priv = _dh_setup_or_xfail(
                lambda: _import_dh_private_key(
                    rs.raw,
                    rs.sh,
                    _DH_RFC3526_GROUP14_ALICE_PRIVATE,
                ),
                "CKM_DH_PKCS_DERIVE RFC 3526 Group 14 truncation vector",
            )
            derived_values: dict[int, bytes] = {}
            shape_records: list[C.Classification | None] = []
            kat_records: list[C.Classification | None] = []
            for requested_len in (32, 16):
                derived = _dh_derive_or_xfail(
                    rs,
                    priv,
                    _DH_RFC3526_GROUP14_BOB_PUBLIC,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_VALUE_LEN: requested_len,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    label=(f"CKM_DH_PKCS_DERIVE RFC 3526 Group 14 CKA_VALUE_LEN={requested_len}"),
                )
                derived_keys.append(derived)
                value, shape = _dh_read_and_validate(
                    rs,
                    derived,
                    attr=CKA_VALUE,
                    leg=f"requested length {requested_len}",
                    label=(
                        "CKM_DH_PKCS_DERIVE RFC 3526 Group 14:"
                        f"CKA_VALUE_LEN={requested_len} CKA_VALUE"
                    ),
                    expected="exact-length bytes",
                    expected_length=requested_len,
                    producer_operation="C_DeriveKey",
                    producer_mechanism=_DH_DERIVE_MECHANISM_NAME,
                )
                shape_records.append(shape)
                if value is MISSING_ATTRIBUTE:
                    continue
                if type(value) is bytes:
                    derived_values[requested_len] = value
                if requested_len == 32 and type(value) is bytes and len(value) == requested_len:
                    kat_records.append(
                        _dh_record_kat_mismatch(
                            value,
                            expected=_DH_RFC3526_GROUP14_EXPECTED_SECRET_32,
                            label=(
                                "CKM_DH_PKCS_DERIVE:C_DeriveKey KAT (RFC 3526 Group 14, len=32)"
                            ),
                        )
                    )

            _dh_raise_hard(shape_records)
            _dh_raise_hard(kat_records)
            if 32 not in derived_values or 16 not in derived_values:
                return
            if derived_values[16] != derived_values[32][-16:]:
                record = C.record_as(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DH_PKCS_DERIVE:CKA_VALUE_LEN truncation keeps rightmost bytes",
                    operation="C_DeriveKey",
                    mechanism=_DH_DERIVE_MECHANISM_NAME,
                    detail={"relation": "rightmost-bytes", "legs": ["length 32", "length 16"]},
                    summary="DH derived value did not preserve the rightmost bytes",
                )
                C.raise_for_record(record)
        finally:
            for derived in derived_keys:
                destroy_quietly(rs.raw, rs.sh, derived)
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)

    def test_dh_pkcs_derive_rfc3526_group14_rejects_zero_value_len(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKM_DH_PKCS_DERIVE rejects a zero-length requested generic secret."""
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_DERIVE"):
            pytest.skip("CKM_DH_PKCS_DERIVE not supported")

        priv = 0
        derived = 0
        try:
            priv = _dh_setup_or_xfail(
                lambda: _import_dh_private_key(
                    rs.raw,
                    rs.sh,
                    _DH_RFC3526_GROUP14_ALICE_PRIVATE,
                ),
                "CKM_DH_PKCS_DERIVE RFC 3526 Group 14 zero-length vector",
            )
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_DH_PKCS_DERIVE,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_VALUE_LEN: 0,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech_param=mech_bytes(CKM_DH_PKCS_DERIVE, _DH_RFC3526_GROUP14_BOB_PUBLIC),
                )
            except AssertionError as exc:
                reject_or_classify(
                    exc,
                    (CKR_KEY_SIZE_RANGE, CKR_ATTRIBUTE_VALUE_INVALID),
                    label="CKM_DH_PKCS_DERIVE RFC 3526 Group 14 CKA_VALUE_LEN=0",
                )
                return

            raise AssertionError("accepted CKM_DH_PKCS_DERIVE RFC 3526 Group 14 CKA_VALUE_LEN=0")
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)

    def test_dh_derive_respects_requested_value_len_truncation(
        self,
        p11_raw_session: Any,
    ) -> None:
        """DH derived secret must honor CKA_VALUE_LEN by left truncation."""
        rs = p11_raw_session
        _skip_no_dh(rs)

        alice_pub = alice_priv = bob_pub = bob_priv = 0
        derived_keys: list[int] = []
        try:
            alice_pub, alice_priv = _gen_dh_keypair(rs.raw, rs.sh)
            bob_pub, bob_priv = _gen_dh_keypair(rs.raw, rs.sh)
            bob_value, bob_shape = _dh_read_and_validate(
                rs,
                bob_pub,
                attr=CKA_VALUE,
                leg="Bob public",
                label="CKM_DH_PKCS_DERIVE:Bob public CKA_VALUE for truncation",
                expected="non-empty bytes",
                expected_length=None,
                producer_operation="C_GenerateKeyPair",
                producer_mechanism=_DH_KEYPAIR_MECHANISM_NAME,
            )
            _dh_raise_hard([bob_shape])
            if bob_value is MISSING_ATTRIBUTE:
                return
            derived_values: dict[int, bytes] = {}
            shape_records: list[C.Classification | None] = []

            for requested_len in (32, 16):
                key = _dh_derive_or_xfail(
                    rs,
                    alice_priv,
                    bob_value,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_VALUE_LEN: requested_len,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    label=f"DH derive CKA_VALUE_LEN={requested_len}",
                )
                derived_keys.append(key)
                value, shape = _dh_read_and_validate(
                    rs,
                    key,
                    attr=CKA_VALUE,
                    leg=f"requested length {requested_len}",
                    label=f"DH derive CKA_VALUE_LEN={requested_len}:derived CKA_VALUE",
                    expected="exact-length bytes",
                    expected_length=requested_len,
                    producer_operation="C_DeriveKey",
                    producer_mechanism=_DH_DERIVE_MECHANISM_NAME,
                )
                shape_records.append(shape)
                if value is MISSING_ATTRIBUTE:
                    continue
                if type(value) is bytes and len(value) == requested_len:
                    derived_values[requested_len] = value

            _dh_raise_hard(shape_records)
            if 32 not in derived_values or 16 not in derived_values:
                return
            if derived_values[16] != derived_values[32][-16:]:
                record = C.record_as(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DH_PKCS_DERIVE:CKA_VALUE_LEN truncation keeps rightmost bytes",
                    operation="C_DeriveKey",
                    mechanism=_DH_DERIVE_MECHANISM_NAME,
                    detail={"relation": "rightmost-bytes", "legs": ["length 32", "length 16"]},
                    summary="DH derived value did not preserve the rightmost bytes",
                )
                C.raise_for_record(record)
        finally:
            for key in derived_keys:
                destroy_quietly(rs.raw, rs.sh, key)
            if alice_pub:
                destroy_quietly(rs.raw, rs.sh, alice_pub)
            if alice_priv:
                destroy_quietly(rs.raw, rs.sh, alice_priv)
            if bob_pub:
                destroy_quietly(rs.raw, rs.sh, bob_pub)
            if bob_priv:
                destroy_quietly(rs.raw, rs.sh, bob_priv)

    def test_dh_derive_rejects_missing_peer_public_value(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKM_DH_PKCS_DERIVE must reject a missing peer public value parameter."""
        rs = p11_raw_session
        _skip_no_dh(rs)

        _pub, priv = _gen_dh_keypair(rs.raw, rs.sh)
        mech = mech_simple(CKM_DH_PKCS_DERIVE)
        derived = CK_OBJECT_HANDLE(0)
        attrs = template(
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            attr_ulong(CKA_VALUE_LEN, 16),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_EXTRACTABLE, True),
            attr_bool(CKA_TOKEN, False),
        )
        try:
            rv = rs.raw.C_DeriveKey(
                rs.sh,
                mech.byref(),
                priv,
                attrs.ptr,
                attrs.count,
                byref(derived),
            )
            classify_negative_rv(
                rv,
                (CKR_MECHANISM_PARAM_INVALID,),
                label="CKM_DH_PKCS_DERIVE missing peer public value",
            )
        finally:
            if derived.value:
                destroy_quietly(rs.raw, rs.sh, derived.value)
            destroy_quietly(rs.raw, rs.sh, _pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_dh_derive_rejects_malformed_peer_public_value(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKM_DH_PKCS_DERIVE must reject a malformed peer public value."""
        rs = p11_raw_session
        _skip_no_dh(rs)

        _pub, priv = _gen_dh_keypair(rs.raw, rs.sh)
        mech = mech_bytes(CKM_DH_PKCS_DERIVE, b"\x01")
        derived = CK_OBJECT_HANDLE(0)
        attrs = template(
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            attr_ulong(CKA_VALUE_LEN, 16),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_EXTRACTABLE, True),
            attr_bool(CKA_TOKEN, False),
        )
        try:
            rv = rs.raw.C_DeriveKey(
                rs.sh,
                mech.byref(),
                priv,
                attrs.ptr,
                attrs.count,
                byref(derived),
            )
            classify_negative_rv(
                rv,
                _DH_INVALID_PEER_PUBLIC_RVS,
                label="CKM_DH_PKCS_DERIVE malformed peer public value",
            )
        finally:
            if derived.value:
                destroy_quietly(rs.raw, rs.sh, derived.value)
            destroy_quietly(rs.raw, rs.sh, _pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_dh_different_keypairs_different_secrets(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Two independent DH exchanges produce different shared secrets."""
        rs = p11_raw_session
        _skip_no_dh(rs)

        _pub1 = priv1 = pub2 = _priv2 = 0
        _pub3 = priv3 = pub4 = _priv4 = 0
        key1 = key2 = 0
        try:
            # Exchange 1
            _pub1, priv1 = _gen_dh_keypair(rs.raw, rs.sh)
            pub2, _priv2 = _gen_dh_keypair(rs.raw, rs.sh)
            pub2_val, pub2_shape = _dh_read_and_validate(
                rs,
                pub2,
                attr=CKA_VALUE,
                leg="first exchange peer public",
                label="first exchange peer public CKA_VALUE",
                expected="non-empty bytes",
                expected_length=None,
                producer_operation="C_GenerateKeyPair",
                producer_mechanism=_DH_KEYPAIR_MECHANISM_NAME,
            )

            # Exchange 2 (fresh keypairs)
            _pub3, priv3 = _gen_dh_keypair(rs.raw, rs.sh)
            pub4, _priv4 = _gen_dh_keypair(rs.raw, rs.sh)
            pub4_val, pub4_shape = _dh_read_and_validate(
                rs,
                pub4,
                attr=CKA_VALUE,
                leg="second exchange peer public",
                label="second exchange peer public CKA_VALUE",
                expected="non-empty bytes",
                expected_length=None,
                producer_operation="C_GenerateKeyPair",
                producer_mechanism=_DH_KEYPAIR_MECHANISM_NAME,
            )
            public_records: list[C.Classification | None] = [pub2_shape, pub4_shape]
            duplicate = _dh_record_duplicate_public(
                pub2_val,
                pub4_val,
                first_shape=pub2_shape,
                second_shape=pub4_shape,
                legs=["first exchange peer public", "second exchange peer public"],
            )
            if duplicate is not None:
                public_records.append(duplicate)

            if pub2_val is not MISSING_ATTRIBUTE and pub2_shape is None:
                key1 = _dh_derive_or_xfail(
                    rs,
                    priv1,
                    pub2_val,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_VALUE_LEN: 16,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    label="first exchange derive",
                )
            if pub4_val is not MISSING_ATTRIBUTE and pub4_shape is None:
                key2 = _dh_derive_or_xfail(
                    rs,
                    priv3,
                    pub4_val,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_VALUE_LEN: 16,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    label="second exchange derive",
                )

            # Different exchanges should produce different keys.
            v1 = v2 = MISSING_ATTRIBUTE
            v1_shape = v2_shape = None
            if key1:
                v1, v1_shape = _dh_read_and_validate(
                    rs,
                    key1,
                    attr=CKA_VALUE,
                    leg="first exchange derived",
                    label="first exchange derived CKA_VALUE",
                    expected="exact-length bytes",
                    expected_length=16,
                    producer_operation="C_DeriveKey",
                    producer_mechanism=_DH_DERIVE_MECHANISM_NAME,
                )
            if key2:
                v2, v2_shape = _dh_read_and_validate(
                    rs,
                    key2,
                    attr=CKA_VALUE,
                    leg="second exchange derived",
                    label="second exchange derived CKA_VALUE",
                    expected="exact-length bytes",
                    expected_length=16,
                    producer_operation="C_DeriveKey",
                    producer_mechanism=_DH_DERIVE_MECHANISM_NAME,
                )
            _dh_check_derived_pair(
                v1,
                v2,
                first_shape=v1_shape,
                second_shape=v2_shape,
                relation="different",
                label="CKM_DH_PKCS_DERIVE:independent exchanges produce different secrets",
            )
            _dh_raise_hard(public_records)
        finally:
            for handle in (
                key1,
                key2,
                _pub1,
                priv1,
                pub2,
                _priv2,
                _pub3,
                priv3,
                pub4,
                _priv4,
            ):
                if handle:
                    destroy_quietly(rs.raw, rs.sh, handle)


@pytest.mark.slow
class TestDHParameterGeneration:
    """Test CKM_DH_PKCS_PARAMETER_GEN (on-token DH parameter generation)."""

    def test_parameter_gen_rejects_missing_prime_bits(self, p11_raw_session: Any) -> None:
        """CKM_DH_PKCS_PARAMETER_GEN requires CKA_PRIME_BITS in the template."""
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_PARAMETER_GEN"):
            pytest.skip("CKM_DH_PKCS_PARAMETER_GEN not supported")

        tmpl = template(attr_bool(CKA_TOKEN, False))
        dp_handle = CK_OBJECT_HANDLE(0)
        mech = mech_simple(CKM_DH_PKCS_PARAMETER_GEN)
        try:
            rv = rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(dp_handle),
            )
            classify_negative_rv(
                rv,
                _DH_PARAMETER_TEMPLATE_REJECT_RVS,
                label="CKM_DH_PKCS_PARAMETER_GEN missing CKA_PRIME_BITS",
            )
        finally:
            if dp_handle.value:
                destroy_quietly(rs.raw, rs.sh, dp_handle.value)

    def test_generate_dh_parameters(self, p11_raw_session: Any) -> None:
        """Generate DH domain parameters on the token."""
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_PARAMETER_GEN"):
            pytest.skip("CKM_DH_PKCS_PARAMETER_GEN not supported")

        tmpl = template(
            attr_ulong(CKA_PRIME_BITS, 2048),
            attr_bool(CKA_TOKEN, False),
        )
        dp_handle = CK_OBJECT_HANDLE(0)
        mech = mech_simple(CKM_DH_PKCS_PARAMETER_GEN)
        rv = rs.raw.C_GenerateKey(
            rs.sh,
            mech.byref(),
            tmpl.ptr,
            tmpl.count,
            byref(dp_handle),
        )
        expect_rv(rv, CKR_OK)
        try:
            assert dp_handle.value != 0

            attrs = read_attributes(rs.raw, rs.sh, dp_handle.value, [CKA_PRIME])
            prime = attr_or_record(
                attrs,
                CKA_PRIME,
                label="CKM_DH_PKCS_PARAMETER_GEN:CKA_PRIME readback",
            )
            if prime is MISSING_ATTRIBUTE:
                return
            assert isinstance(prime, bytes)
            assert len(prime) * 8 >= 2048
        finally:
            destroy_quietly(rs.raw, rs.sh, dp_handle.value)

    def test_generated_params_produce_valid_keypair(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Generated parameters can produce a keypair that does key agreement."""
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_PARAMETER_GEN"):
            pytest.skip("CKM_DH_PKCS_PARAMETER_GEN not supported")
        if not rs.has_mechanism("DH_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_DH_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("DH_PKCS_DERIVE"):
            pytest.skip("CKM_DH_PKCS_DERIVE not supported")

        # Generate domain parameters
        tmpl = template(
            attr_ulong(CKA_PRIME_BITS, 2048),
            attr_bool(CKA_TOKEN, False),
        )
        dp_handle = CK_OBJECT_HANDLE(0)
        mech = mech_simple(CKM_DH_PKCS_PARAMETER_GEN)
        rv = rs.raw.C_GenerateKey(
            rs.sh,
            mech.byref(),
            tmpl.ptr,
            tmpl.count,
            byref(dp_handle),
        )
        expect_rv(rv, CKR_OK)
        pub_a = priv_a = pub_b = priv_b = 0
        key_a = key_b = 0
        try:
            # Read the generated prime and base
            prime, prime_shape = _dh_read_and_validate(
                rs,
                dp_handle.value,
                attr=CKA_PRIME,
                leg="generated prime",
                label="generated DH parameters:CKA_PRIME",
                expected="non-empty bytes",
                expected_length=None,
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_DH_PKCS_PARAMETER_GEN",
            )
            base, base_shape = _dh_read_and_validate(
                rs,
                dp_handle.value,
                attr=CKA_BASE,
                leg="generated base",
                label="generated DH parameters:CKA_BASE",
                expected="non-empty bytes",
                expected_length=None,
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_DH_PKCS_PARAMETER_GEN",
            )
            _dh_raise_hard([prime_shape, base_shape])
            if prime is MISSING_ATTRIBUTE or base is MISSING_ATTRIBUTE:
                return

            # Generate two keypairs from the params
            generation_complete = False
            try:
                pub_a, priv_a = _gen_dh_keypair(rs.raw, rs.sh, prime, base)
                pub_b, priv_b = _gen_dh_keypair(rs.raw, rs.sh, prime, base)
                generation_complete = True
            finally:
                if not generation_complete:
                    if pub_a:
                        destroy_quietly(rs.raw, rs.sh, pub_a)
                    if priv_a:
                        destroy_quietly(rs.raw, rs.sh, priv_a)
            try:
                pub_b_val, pub_b_shape = _dh_read_and_validate(
                    rs,
                    pub_b,
                    attr=CKA_VALUE,
                    leg="generated-params B public",
                    label="generated-params B public CKA_VALUE",
                    expected="non-empty bytes",
                    expected_length=None,
                    producer_operation="C_GenerateKeyPair",
                    producer_mechanism=_DH_KEYPAIR_MECHANISM_NAME,
                )
                pub_a_val, pub_a_shape = _dh_read_and_validate(
                    rs,
                    pub_a,
                    attr=CKA_VALUE,
                    leg="generated-params A public",
                    label="generated-params A public CKA_VALUE",
                    expected="non-empty bytes",
                    expected_length=None,
                    producer_operation="C_GenerateKeyPair",
                    producer_mechanism=_DH_KEYPAIR_MECHANISM_NAME,
                )
                public_records: list[C.Classification | None] = [pub_b_shape, pub_a_shape]
                duplicate = _dh_record_duplicate_public(
                    pub_a_val,
                    pub_b_val,
                    first_shape=pub_a_shape,
                    second_shape=pub_b_shape,
                    legs=["generated-params A public", "generated-params B public"],
                )
                if duplicate is not None:
                    public_records.append(duplicate)

                if pub_b_val is not MISSING_ATTRIBUTE and pub_b_shape is None:
                    key_a = _dh_derive_or_xfail(
                        rs,
                        priv_a,
                        pub_b_val,
                        attrs={
                            CKA_CLASS: CKO_SECRET_KEY,
                            CKA_KEY_TYPE: CKK_AES,
                            CKA_VALUE_LEN: 16,
                            CKA_SENSITIVE: False,
                            CKA_EXTRACTABLE: True,
                            CKA_TOKEN: False,
                        },
                        label="generated-params A derive",
                    )
                if pub_a_val is not MISSING_ATTRIBUTE and pub_a_shape is None:
                    key_b = _dh_derive_or_xfail(
                        rs,
                        priv_b,
                        pub_a_val,
                        attrs={
                            CKA_CLASS: CKO_SECRET_KEY,
                            CKA_KEY_TYPE: CKK_AES,
                            CKA_VALUE_LEN: 16,
                            CKA_SENSITIVE: False,
                            CKA_EXTRACTABLE: True,
                            CKA_TOKEN: False,
                        },
                        label="generated-params B derive",
                    )
                va = vb = MISSING_ATTRIBUTE
                va_shape = vb_shape = None
                if key_a:
                    va, va_shape = _dh_read_and_validate(
                        rs,
                        key_a,
                        attr=CKA_VALUE,
                        leg="generated-params A derived",
                        label="generated-params A derived CKA_VALUE",
                        expected="exact-length bytes",
                        expected_length=16,
                        producer_operation="C_DeriveKey",
                        producer_mechanism=_DH_DERIVE_MECHANISM_NAME,
                    )
                if key_b:
                    vb, vb_shape = _dh_read_and_validate(
                        rs,
                        key_b,
                        attr=CKA_VALUE,
                        leg="generated-params B derived",
                        label="generated-params B derived CKA_VALUE",
                        expected="exact-length bytes",
                        expected_length=16,
                        producer_operation="C_DeriveKey",
                        producer_mechanism=_DH_DERIVE_MECHANISM_NAME,
                    )
                _dh_check_derived_pair(
                    va,
                    vb,
                    first_shape=va_shape,
                    second_shape=vb_shape,
                    relation="equal",
                    label="CKM_DH_PKCS_DERIVE:shared-secret agreement (generated params)",
                )
                _dh_raise_hard(public_records)
            finally:
                if key_a:
                    destroy_quietly(rs.raw, rs.sh, key_a)
                if key_b:
                    destroy_quietly(rs.raw, rs.sh, key_b)
                if pub_a:
                    destroy_quietly(rs.raw, rs.sh, pub_a)
                if priv_a:
                    destroy_quietly(rs.raw, rs.sh, priv_a)
                if pub_b:
                    destroy_quietly(rs.raw, rs.sh, pub_b)
                if priv_b:
                    destroy_quietly(rs.raw, rs.sh, priv_b)
        finally:
            destroy_quietly(rs.raw, rs.sh, dp_handle.value)
