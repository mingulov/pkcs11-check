"""Classic Diffie-Hellman key agreement tests.

Tests CKM_DH_PKCS_KEY_PAIR_GEN, CKM_DH_PKCS_DERIVE, and
CKM_DH_PKCS_PARAMETER_GEN where supported.

Uses RFC 3526 Group 14 (2048-bit MODP) for known-good parameters.
"""

from __future__ import annotations

import uuid
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
    template_from_dict,
)
from pkcs11_check.raw.recipes import (
    create_object,
    decrypt_single,
    derive_key,
    destroy_quietly,
    encrypt_single,
    find_objects_exhaustive,
    partition_proved_new,
    read_attributes,
)
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    expect_rv,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_BASE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
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
    CKO_PUBLIC_KEY,
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
from pkcs11_check.testcases._exact_search import check_exact_and_changed_search, flip_last_byte
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
        inherit_mechanism=False,
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
        inherit_mechanism=False,
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
                inherit_mechanism=False,
            )
            if pub_value is MISSING_ATTRIBUTE:
                return
            shape_record = _dh_shape_record(
                pub_value,
                attr=CKA_VALUE,
                leg="public",
                label="CKM_DH_PKCS_KEY_PAIR_GEN:public CKA_VALUE readback",
                expected="non-empty bytes",
                expected_length=None,
                producer_operation="C_GenerateKeyPair",
                producer_mechanism=_DH_KEYPAIR_MECHANISM_NAME,
            )
            if shape_record is not None:
                C.raise_for_record(shape_record)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_dh_search_by_exact_public_value(self, p11_raw_session: Any) -> None:
        """Search the generated DH public key by its exact readback value (QC6a).

        Scoped by a per-node unique label plus class/type: the generated
        handle must appear among the exact-value results, and a
        changed-value control differing only in the last value byte must
        not match it. Only key-pair generation is the premise (no derive).
        """
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_DH_PKCS_KEY_PAIR_GEN not supported")

        search_label = f"pkcs11-check-qc6a-dh-{uuid.uuid4().hex[:8]}"
        pub, priv = _gen_dh_keypair(rs.raw, rs.sh, extra_pub={CKA_LABEL: search_label})
        try:
            pub_value, shape_record = _dh_read_and_validate(
                rs,
                pub,
                attr=CKA_VALUE,
                leg="public",
                label="CKM_DH_PKCS_KEY_PAIR_GEN:public CKA_VALUE exact-search readback",
                expected="non-empty bytes",
                expected_length=None,
                producer_operation="C_GenerateKeyPair",
                producer_mechanism=_DH_KEYPAIR_MECHANISM_NAME,
            )
            _dh_raise_hard([shape_record])
            if pub_value is MISSING_ATTRIBUTE:
                return
            exact_template = {
                CKA_LABEL: search_label,
                CKA_CLASS: CKO_PUBLIC_KEY,
                CKA_KEY_TYPE: CKK_DH,
                CKA_VALUE: pub_value,
            }
            changed_template = {
                **exact_template,
                CKA_VALUE: flip_last_byte(pub_value),
            }
            check_exact_and_changed_search(
                rs,
                exact_template=exact_template,
                changed_template=changed_template,
                expected_handle=pub,
                label="DH exact public-value search",
            )
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
                inherit_mechanism=False,
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
                    (
                        CKR_KEY_SIZE_RANGE,
                        CKR_ATTRIBUTE_VALUE_INVALID,
                        CKR_TEMPLATE_INCONSISTENT,
                    ),
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
                inherit_mechanism=False,
            )
            if prime is MISSING_ATTRIBUTE:
                return
            if type(prime) is bytes and len(prime) * 8 >= 2048:
                return
            try:
                actual: dict[str, Any] = {"type": type(prime).__name__, "bits": len(prime) * 8}
            except TypeError:
                actual = {"type": type(prime).__name__, "bits": None}
            record = C.record_as(
                "wrong_result",
                kind="metadata",
                label="CKM_DH_PKCS_PARAMETER_GEN:CKA_PRIME readback",
                operation="C_GetAttributeValue",
                mechanism="CKM_DH_PKCS_PARAMETER_GEN",
                inherit_mechanism=False,
                detail={
                    "attribute": _dh_attribute_info(CKA_PRIME),
                    "expected": {"type": "bytes", "min_bits": 2048},
                    "actual": actual,
                    "producer_operation": "C_GenerateKey",
                    "producer_mechanism": "CKM_DH_PKCS_PARAMETER_GEN",
                },
                summary=(
                    "CKM_DH_PKCS_PARAMETER_GEN:CKA_PRIME readback: provider returned a "
                    "CKA_PRIME with the wrong shape"
                ),
            )
            C.raise_for_record(record)
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


# --- QC9a: DH peer-encoding matrix (#52.1) ------------------------------------
#
# Fixed private exponent (the RFC 3526 Group 14 Alice value) plus an independent
# pow() oracle. Three allowed-encoding legs -- ordinary, leading-zero-equivalent,
# full-width-distinct-from-suffix -- and a separate malformed (overlong/empty)
# slice. Every derived handle is owned only when the exhaustive before/after
# inventory delta proves it new; a refused derive that leaves a proved-new object
# behind fails, an unproved delta stays alive as honest-deviation xfail, and
# clean zero-delta refusals keep the per-leg tiers below. No blind destroy of
# output handles anywhere in these nodes.
#
# Peers are g^e mod p for deterministic SHA-256-labeled fixed exponents
# (qc9a-a-3, qc9a-b-311, qc9a-c-1). All lie in [2, p-2], all four oracles are
# pairwise distinct, and the padded leading-zero form denotes the same integer
# as its minimal form (all pinned by the QC9a contract tests).

_QC9A_VALUE_LEN = len(DH_PRIME_2048)

_QC9A_PEER_ORDINARY = bytes.fromhex(
    "f9966b455fa5f2814cab70512e24af27ee8ec5011113d2d5"
    "bd6922ae6520f08b2373a6c0b07defcb77470039e73c573a"
    "2abb4d0feff9bb0a3e8ba828dea098702ea67436bb79a784"
    "2637365a0c39596861b2c83a7df644bc47a6267d66597dc4"
    "a429a57f308fbd28e7f39de8a2615e89f6cd35b8261ad2a2"
    "70273a21253891a2b7db7766a3b9a66f09c6c4d455e2a2b6"
    "8af80140f23ed2c1956ee64c4765bd9edab2a2c796427114"
    "96a4d17f97ae0a4049e41260c6bec5742b860a91767d1e27"
    "44498b75755bc85734a25aa5b7ff826641c6ef0fea9ee5aa"
    "4c58fbeb47277dac04522ca4d4eb2b7bb29d690a86556250"
    "19d3c50e28cca21c9b74c70e080cd0f8"
)

_QC9A_PEER_LZ_MINIMAL = bytes.fromhex(
    "aa206303caf19e430eb9ecb78f01e090f961c083b17bd4ca"
    "dc311961efe70df16a288e05bffa95c12ab578631028d115"
    "91591d0ff47478d06816652e722dbbf044b0b1ad742942e9"
    "a8c1ae874b3a4c9066a292bc7a2aad223802aa842a0f389e"
    "c8fd01a7c59247ed6caabc098a905993cc0db454f499a1f9"
    "545fd0cb1e9e41a6549665713d31946d0dcb41aec3396842"
    "a4b0507fef88a76279febc48dce7227fa19b05772522a5c0"
    "70247af7b9298943d0325205377033eb33346c41a0d3ec56"
    "fc93f1995bd37669e6ac656b607e28ed9f258c31043b27cc"
    "ecf86017050141a06e1b77f5af3e1265fc4555e706f1a918"
    "93db814665d39d040c894c87081019"
)
_QC9A_PEER_LZ_PADDED = b"\x00" + _QC9A_PEER_LZ_MINIMAL

_QC9A_PEER_FULL = bytes.fromhex(
    "d45b5da2c6f9990c5d850cac55ac50dbeaf7283566c1c578"
    "d07443baf8c0dd48c97743af1cc33b8a6a90db6a5fedb616"
    "4efcd5a03e29d72fd5b3ced560e75a00617b285d3983d59f"
    "04d9a0abe23d61a9deb09c3f87e5e77f60d66ef6c2b6b964"
    "b9a16df6c3711a7864ecf8f99f2fc3ec03df38e2a1dabe78"
    "458a2345a6b3cdfef2fe4eb9b4ea2500b6c2a11b072f275c"
    "4cba07c4104177a3657495dc8ebb1406c11043a32fe50b0f"
    "b6257b8238e88731b301d7ca401635cefc9601f57d7d90a0"
    "46c9b4104a992664f69ba3a36a83938955275ef2572c149c"
    "6c2d0f21faaf74dc55d451e0bea94a57af4757bdb3dbf39a"
    "8575ce60a88c0765acbb66594c5b469e"
)
_QC9A_PEER_SUFFIX = _QC9A_PEER_FULL[1:]
# Out-of-range peer value p + 1 (257 bytes): a leading-zero-padded
# same-integer encoding would be a VALID integer encoding (R12-03), so the
# malformed leg must exceed the modulus itself, not just its width.
_QC9A_OVERLONG = (int.from_bytes(DH_PRIME_2048, "big") + 1).to_bytes(257, "big")
_QC9A_EMPTY = b""

_QC9A_MALFORMED_CANONICAL_RVS = (CKR_MECHANISM_PARAM_INVALID,)
_QC9A_DERIVED_IDENTITY = (CKO_SECRET_KEY, CKK_GENERIC_SECRET)


def _qc9a_oracle(peer_int: int) -> bytes:
    """Independent DH shared-secret oracle: pow(peer, x, p), zero-padded to prime length."""
    prime = int.from_bytes(DH_PRIME_2048, "big")
    exponent = int.from_bytes(_DH_RFC3526_GROUP14_ALICE_PRIVATE, "big")
    return pow(peer_int, exponent, prime).to_bytes(len(DH_PRIME_2048), "big")


def _qc9a_derive_template(label: str) -> dict[Any, Any]:
    """Derive template for one QC9a leg; the unique label anchors proved-new correlation."""
    return {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_VALUE_LEN: _QC9A_VALUE_LEN,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_TOKEN: False,
        CKA_LABEL: label,
    }


def _qc9a_inventory_or_classify(rs: Any, *, label: str, phase: str) -> list[int]:
    """Exhaustive inventory, judging inventory RVs instead of propagating them.

    A clean inventory refusal leaves ownership unprovable (xfail, never pass);
    an undefined inventory RV or a Find-protocol violation fails.
    """
    try:
        return find_objects_exhaustive(rs.raw, rs.sh)
    except CkrAssertionError as exc:
        if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv):
            C.xfail_as(
                "not_operational",
                label=f"{label}: object inventory not operational",
                operation="C_FindObjects",
                inherit_mechanism=False,
                actual=exc.rv,
                detail={"phase": phase, "rv": ckr_name(exc.rv)},
                summary=f"{label}: {phase} inventory refused with {ckr_name(exc.rv)}",
            )
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_FindObjects",
            inherit_mechanism=False,
            actual=exc.rv,
            detail={"phase": phase, "rv": ckr_name(exc.rv)},
            summary=f"{label}: {phase} inventory returned undefined {ckr_name(exc.rv)}",
        )
    except AssertionError as exc:
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_FindObjects",
            inherit_mechanism=False,
            detail={"phase": phase, "error": str(exc)},
            summary=f"{label}: {phase} inventory violated the Find protocol",
        )


def _qc9a_after_inventory_or_judge(
    rs: Any,
    *,
    rv: int,
    handle: int,
    label: str,
    leg: str,
    peer_length: int,
    malformed: bool,
) -> list[int]:
    """After-inventory that preserves already-known derive failures (R12-01).

    An undefined derive RV and a malformed-leg acceptance are known failures
    that a failed after-inventory must not downgrade: the output handle stays
    alive (unproved), but the verdict stays FAIL with both RVs in evidence.
    A defined refusal with a failed inventory is an unproved-effect xfail;
    CKR_OK on an allowed leg keeps the historical not-operational xfail.
    """
    try:
        return find_objects_exhaustive(rs.raw, rs.sh)
    except CkrAssertionError as exc:
        inv_rv = int(exc.rv)
        detail: dict[str, Any] = {
            "phase": "after",
            "leg": leg,
            "peer_length": peer_length,
            "handle_after": handle,
            "derive_rv": ckr_name(rv),
            "inventory_rv": ckr_name(inv_rv),
        }
        if rv != int(CKR_OK) and not (is_standard_ckr(rv) or is_vendor_defined_ckr(rv)):
            C.fail_as(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation="C_DeriveKey",
                mechanism=_DH_DERIVE_MECHANISM_NAME,
                actual=rv,
                detail=detail,
                summary=(
                    f"{label}: refused with undefined {ckr_name(rv)}; "
                    f"after-inventory failed with {ckr_name(inv_rv)}"
                ),
            )
        if not (is_standard_ckr(inv_rv) or is_vendor_defined_ckr(inv_rv)):
            C.fail_as(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation="C_FindObjects",
                inherit_mechanism=False,
                actual=inv_rv,
                detail=detail,
                summary=f"{label}: after inventory returned undefined {ckr_name(inv_rv)}",
            )
        if rv == int(CKR_OK) and malformed:
            C.classify(
                "accepted_invalid",
                label=label,
                operation="C_DeriveKey",
                mechanism=_DH_DERIVE_MECHANISM_NAME,
                actual=rv,
                expected=tuple(_QC9A_MALFORMED_CANONICAL_RVS),
                detail={**detail, "disposition": "unproved-handle-alive"},
                summary=(
                    f"{label}: accepted invalid (CKR_OK) -- must reject; "
                    f"after-inventory failed with {ckr_name(inv_rv)}, "
                    "handle left alive"
                ),
            )
        if rv == int(CKR_OK):
            C.xfail_as(
                "not_operational",
                label=f"{label}: object inventory not operational",
                operation="C_FindObjects",
                inherit_mechanism=False,
                actual=inv_rv,
                detail={"phase": "after", "rv": ckr_name(inv_rv)},
                summary=f"{label}: after inventory refused with {ckr_name(inv_rv)}",
            )
        C.xfail_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation="C_DeriveKey",
            mechanism=_DH_DERIVE_MECHANISM_NAME,
            actual=rv,
            detail={**detail, "disposition": "unproved-effect"},
            summary=(
                f"{label}: refusal {ckr_name(rv)} with a failed after-inventory "
                f"({ckr_name(inv_rv)}); zero-delta unproved"
            ),
        )
    except AssertionError as exc:
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_FindObjects",
            inherit_mechanism=False,
            detail={
                "phase": "after",
                "leg": leg,
                "peer_length": peer_length,
                "handle_after": handle,
                "derive_rv": ckr_name(rv),
                "error": str(exc),
            },
            summary=f"{label}: after inventory violated the Find protocol",
        )
    raise AssertionError("unreachable: every inventory-failure branch terminates")


def _qc9a_derive_raw(
    rs: Any, private_key: int, peer: bytes, attempt: Mapping[Any, Any]
) -> tuple[int, int]:
    """Raw C_DeriveKey returning (rv, output handle) so refusals keep their evidence."""
    mech = mech_bytes(CKM_DH_PKCS_DERIVE, peer)
    tmpl = template_from_dict(dict(attempt))
    out = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_DeriveKey(rs.sh, mech.byref(), private_key, tmpl.ptr, tmpl.count, byref(out))
    return int(rv), int(out.value)


def _qc9a_handle_class(handle: int, *, before: set[int], after: set[int]) -> str:
    """Evidence-only classification of a derive output handle against a delta."""
    if handle == 0:
        return "zero"
    if handle in before:
        return "pre-existing"
    if handle in after:
        return "new-live"
    return "dead-nonzero"


def _qc9a_judge_refusal_ownership(
    rs: Any,
    *,
    rv: int,
    handle: int,
    before: list[int],
    after: list[int],
    attempt: Mapping[Any, Any],
    label: str,
    leg: str,
) -> None:
    """Ownership-first refusal judge shared by the allowed and malformed legs.

    A proved-new leftover is destroyed and fails; an unproved delta stays alive
    as honest-deviation xfail; a clean zero-delta refusal returns so the caller
    can apply its own RV tiers. Never touches unproved handles. An undefined
    operation RV is always a metadata failure, even with an unproved delta
    (R12-02): the partition runs first so proved leftovers are still cleaned.
    """
    proved, unproved = partition_proved_new(
        rs.raw,
        rs.sh,
        before,
        after,
        attempt_templates=(attempt,),
        identities=(_QC9A_DERIVED_IDENTITY,),
        error_handles=(handle,),
    )
    before_set = set(before)
    after_set = set(after)
    detail: dict[str, Any] = {
        "leg": leg,
        "handle_after": handle,
        "handle_class": _qc9a_handle_class(handle, before=before_set, after=after_set),
        "new_handles": sorted(after_set - before_set),
        "proved_new_handles": proved,
        "unproved_new_handles": unproved,
    }
    if proved:
        for leaked in proved:
            destroy_quietly(rs.raw, rs.sh, leaked)
    if not (is_standard_ckr(rv) or is_vendor_defined_ckr(rv)):
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_DeriveKey",
            mechanism=_DH_DERIVE_MECHANISM_NAME,
            actual=rv,
            detail=detail,
            summary=f"{label}: refused with undefined {ckr_name(rv)}",
        )
    if proved:
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_DeriveKey",
            mechanism=_DH_DERIVE_MECHANISM_NAME,
            actual=rv,
            detail=detail,
            summary=f"{label}: refusal {ckr_name(rv)} left an object behind",
        )
    if unproved:
        C.xfail_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation="C_DeriveKey",
            mechanism=_DH_DERIVE_MECHANISM_NAME,
            actual=rv,
            detail={"disposition": "unproved-effect", **detail},
            summary=(
                f"{label}: refusal {ckr_name(rv)} with an unproved inventory delta; left alive"
            ),
        )


def _qc9a_run_allowed_leg(
    rs: Any,
    private_key: int,
    *,
    peer: bytes,
    leg: str,
    label: str,
    suffix: bytes | None = None,
) -> None:
    """One allowed-encoding leg: derive with a valid peer, judge against the oracle.

    CKR_OK with oracle-correct material passes; CKR_OK with wrong material fails;
    CKR_OK with a missing/unreadable value or an unproved handle is unproved
    xfail, never pass. Any clean refusal of these valid inputs is xfail with the
    original RV (no refusal of valid input is a conformant pass); undefined RVs
    fail. When ``suffix`` is given, the value must additionally NOT match the
    suffix oracle (the truncation detector).
    """
    attempt = _qc9a_derive_template(f"qc9a-{leg}-{uuid.uuid4().hex[:8]}")
    before = _qc9a_inventory_or_classify(rs, label=label, phase="before")
    rv, handle = _qc9a_derive_raw(rs, private_key, peer, attempt)
    after = _qc9a_after_inventory_or_judge(
        rs,
        rv=rv,
        handle=handle,
        label=label,
        leg=leg,
        peer_length=len(peer),
        malformed=False,
    )
    if rv != int(CKR_OK):
        _qc9a_judge_refusal_ownership(
            rs,
            rv=rv,
            handle=handle,
            before=before,
            after=after,
            attempt=attempt,
            label=label,
            leg=leg,
        )
        if is_standard_ckr(rv) or is_vendor_defined_ckr(rv):
            C.xfail_as(
                "not_operational",
                label=f"{label}: DH derive advertised but not operational",
                operation="C_DeriveKey",
                mechanism=_DH_DERIVE_MECHANISM_NAME,
                actual=rv,
                detail={
                    "leg": leg,
                    "peer_length": len(peer),
                    "handle_after": handle,
                    "handle_class": _qc9a_handle_class(
                        handle, before=set(before), after=set(after)
                    ),
                },
                summary=f"{label}: refused with {ckr_name(rv)}",
            )
        C.fail_as(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_DeriveKey",
            mechanism=_DH_DERIVE_MECHANISM_NAME,
            actual=rv,
            detail={"leg": leg, "peer_length": len(peer), "handle_after": handle},
            summary=f"{label}: refused with undefined {ckr_name(rv)}",
        )
    owned = handle != 0 and handle in set(after) - set(before)
    if not owned:
        C.xfail_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation="C_DeriveKey",
            mechanism=_DH_DERIVE_MECHANISM_NAME,
            actual=rv,
            detail={
                "disposition": "unproved-handle",
                "leg": leg,
                "peer_length": len(peer),
                "handle_after": handle,
                "handle_class": _qc9a_handle_class(handle, before=set(before), after=set(after)),
                "new_handles": sorted(set(after) - set(before)),
            },
            summary=f"{label}: CKR_OK with an unproved output handle; unproved, never pass",
        )
    try:
        try:
            value_attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_VALUE])
        except CkrAssertionError as exc:
            read_rv = exc.rv
            if not (is_standard_ckr(read_rv) or is_vendor_defined_ckr(read_rv)):
                C.fail_as(
                    "self_contradiction",
                    kind="metadata",
                    label=label,
                    operation="C_DeriveKey",
                    mechanism=_DH_DERIVE_MECHANISM_NAME,
                    actual=read_rv,
                    detail={"leg": leg, "handle_after": handle, "read_rv": ckr_name(read_rv)},
                    summary=f"{label}: derived-value read returned undefined {ckr_name(read_rv)}",
                )
            C.xfail_as(
                "honest_deviation",
                kind="metadata",
                label=label,
                operation="C_DeriveKey",
                mechanism=_DH_DERIVE_MECHANISM_NAME,
                actual=read_rv,
                detail={
                    "disposition": "unreadable-value",
                    "leg": leg,
                    "peer_length": len(peer),
                    "expected_length": _QC9A_VALUE_LEN,
                    "handle_after": handle,
                    "read_rv": ckr_name(read_rv),
                },
                summary=f"{label}: derived value unreadable; unproved, never pass",
            )
        before_records = len(C.get_records())
        value = attr_or_record(
            value_attrs,
            CKA_VALUE,
            label=label,
            reason="honest_deviation",
            kind="metadata",
            inherit_mechanism=False,
        )
        if value is MISSING_ATTRIBUTE:
            new_records = C.get_records()[before_records:]
            if not new_records:
                raise AssertionError(f"{label}: missing attribute did not produce evidence")
            record = new_records[-1]
            if record.detail is None:
                record.detail = {}
            record.detail.update(
                {
                    "leg": leg,
                    "peer_length": len(peer),
                    "expected_length": _QC9A_VALUE_LEN,
                    "handle_after": handle,
                    "producer_operation": "C_DeriveKey",
                    "producer_mechanism": _DH_DERIVE_MECHANISM_NAME,
                }
            )
            if record.reason == "honest_deviation":
                record.detail["disposition"] = "unreadable-value"
            C.raise_for_record(record)
        else:
            oracle_full = _qc9a_oracle(int.from_bytes(peer, "big"))
            match_full = value == oracle_full
            match_suffix = suffix is not None and value == _qc9a_oracle(
                int.from_bytes(suffix, "big")
            )
            if match_full and not match_suffix:
                return
            mismatch: dict[str, Any] = {
                "leg": leg,
                "peer_length": len(peer),
                "expected_length": len(oracle_full),
                "actual_length": len(value),
                "matches_full_oracle": match_full,
            }
            if suffix is not None:
                mismatch["matches_suffix_oracle"] = match_suffix
            C.fail_as(
                "wrong_result",
                kind="crypto",
                label=label,
                operation="C_DeriveKey",
                mechanism=_DH_DERIVE_MECHANISM_NAME,
                source="RFC 3526 Group 14",
                detail=mismatch,
                summary=f"{label}: derived value does not match the independent oracle",
            )
    finally:
        destroy_quietly(rs.raw, rs.sh, handle)


def _qc9a_run_malformed_leg(
    rs: Any,
    private_key: int,
    *,
    peer: bytes,
    leg: str,
    label: str,
) -> None:
    """One malformed-encoding leg: overlong/empty peers must be refused.

    Canonical CKR_MECHANISM_PARAM_INVALID passes; other clean refusals xfail
    with the original RV; acceptance or an undefined RV fails. Ownership-first:
    a proved-new leftover is destroyed and fails even on a canonical refusal,
    and an unproved delta stays alive as honest-deviation xfail.
    """
    attempt = _qc9a_derive_template(f"qc9a-{leg}-{uuid.uuid4().hex[:8]}")
    before = _qc9a_inventory_or_classify(rs, label=label, phase="before")
    rv, handle = _qc9a_derive_raw(rs, private_key, peer, attempt)
    after = _qc9a_after_inventory_or_judge(
        rs,
        rv=rv,
        handle=handle,
        label=label,
        leg=leg,
        peer_length=len(peer),
        malformed=True,
    )
    if rv != int(CKR_OK):
        _qc9a_judge_refusal_ownership(
            rs,
            rv=rv,
            handle=handle,
            before=before,
            after=after,
            attempt=attempt,
            label=label,
            leg=leg,
        )
    elif handle != 0 and handle in set(after) - set(before):
        destroy_quietly(rs.raw, rs.sh, handle)
    classify_negative_rv(rv, _QC9A_MALFORMED_CANONICAL_RVS, label=label)


class TestDHPeerEncoding:
    """QC9a: DH peer-encoding matrix with a fixed private exponent (#52.1)."""

    def test_dh_peer_encoding_ordinary(self, p11_raw_session: Any) -> None:
        """CKM_DH_PKCS_DERIVE with an ordinary full-width peer matches the pow() oracle."""
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_DERIVE"):
            pytest.skip("CKM_DH_PKCS_DERIVE not supported")
        priv = 0
        try:
            priv = _dh_setup_or_xfail(
                lambda: _import_dh_private_key(rs.raw, rs.sh, _DH_RFC3526_GROUP14_ALICE_PRIVATE),
                "QC9a ordinary peer-encoding leg",
            )
            _qc9a_run_allowed_leg(
                rs,
                priv,
                peer=_QC9A_PEER_ORDINARY,
                leg="ordinary",
                label="CKM_DH_PKCS_DERIVE:ordinary peer encoding (QC9a)",
            )
        finally:
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)

    def test_dh_peer_encoding_leading_zero(self, p11_raw_session: Any) -> None:
        """CKM_DH_PKCS_DERIVE with a leading-zero peer encoding matches the same-integer oracle.

        The padded encoding denotes the same integer as its minimal form, so an
        accepting provider must produce that integer's oracle value; a clean
        refusal of this allowed encoding is xfail with the original RV, never pass.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_DERIVE"):
            pytest.skip("CKM_DH_PKCS_DERIVE not supported")
        priv = 0
        try:
            priv = _dh_setup_or_xfail(
                lambda: _import_dh_private_key(rs.raw, rs.sh, _DH_RFC3526_GROUP14_ALICE_PRIVATE),
                "QC9a leading-zero peer-encoding leg",
            )
            _qc9a_run_allowed_leg(
                rs,
                priv,
                peer=_QC9A_PEER_LZ_PADDED,
                leg="leading-zero",
                label="CKM_DH_PKCS_DERIVE:leading-zero peer encoding (QC9a)",
            )
        finally:
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)

    def test_dh_peer_encoding_full_width_suffix_detector(self, p11_raw_session: Any) -> None:
        """CKM_DH_PKCS_DERIVE with a full-width peer must not derive from its suffix.

        The peer is full-width and numerically distinct from its wrongly truncated
        suffix, and the two oracles differ, so a provider deriving from the suffix
        instead of the full value fails loudly on material mismatch.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_DERIVE"):
            pytest.skip("CKM_DH_PKCS_DERIVE not supported")
        priv = 0
        try:
            priv = _dh_setup_or_xfail(
                lambda: _import_dh_private_key(rs.raw, rs.sh, _DH_RFC3526_GROUP14_ALICE_PRIVATE),
                "QC9a full-width peer truncation-detector leg",
            )
            _qc9a_run_allowed_leg(
                rs,
                priv,
                peer=_QC9A_PEER_FULL,
                leg="full-width",
                label="CKM_DH_PKCS_DERIVE:full-width peer truncation detector (QC9a)",
                suffix=_QC9A_PEER_SUFFIX,
            )
        finally:
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)

    def test_dh_peer_encoding_rejects_overlong(self, p11_raw_session: Any) -> None:
        """CKM_DH_PKCS_DERIVE must refuse an out-of-range peer value (p + 1)."""
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_DERIVE"):
            pytest.skip("CKM_DH_PKCS_DERIVE not supported")
        priv = 0
        try:
            priv = _dh_setup_or_xfail(
                lambda: _import_dh_private_key(rs.raw, rs.sh, _DH_RFC3526_GROUP14_ALICE_PRIVATE),
                "QC9a overlong peer-encoding leg",
            )
            _qc9a_run_malformed_leg(
                rs,
                priv,
                peer=_QC9A_OVERLONG,
                leg="overlong",
                label="CKM_DH_PKCS_DERIVE:overlong peer encoding refusal (QC9a)",
            )
        finally:
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)

    def test_dh_peer_encoding_rejects_empty(self, p11_raw_session: Any) -> None:
        """CKM_DH_PKCS_DERIVE must refuse an empty peer encoding."""
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_DERIVE"):
            pytest.skip("CKM_DH_PKCS_DERIVE not supported")
        priv = 0
        try:
            priv = _dh_setup_or_xfail(
                lambda: _import_dh_private_key(rs.raw, rs.sh, _DH_RFC3526_GROUP14_ALICE_PRIVATE),
                "QC9a empty peer-encoding leg",
            )
            _qc9a_run_malformed_leg(
                rs,
                priv,
                peer=_QC9A_EMPTY,
                leg="empty",
                label="CKM_DH_PKCS_DERIVE:empty peer encoding refusal (QC9a)",
            )
        finally:
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)
