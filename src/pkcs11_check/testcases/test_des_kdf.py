"""DES and Triple-DES CBC encrypt-data key-derivation tests.

The generic mechanism test exercises advertised operation availability and output
shape.  The fixed-key tests here are deliberately separate: when a provider can
stage a known DES key, they compare C_DeriveKey output with an independent CBC
oracle and verify the PKCS#11 trailing-ciphertext truncation rule.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NoReturn

import pytest
from cryptography.hazmat.decrepit.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.pack import PackedMechanism
from pkcs11_check.raw.recipes import derive_key, destroy_quietly, read_attributes
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CK_DES_CBC_ENCRYPT_DATA_PARAMS,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_DES,
    CKK_DES3,
    CKK_GENERIC_SECRET,
    CKM_DES3_CBC_ENCRYPT_DATA,
    CKM_DES_CBC_ENCRYPT_DATA,
    CKO_SECRET_KEY,
    CKR_OK,
    CKR_OPERATION_NOT_VALIDATED,
)
from pkcs11_check.testcases._capability_claims import claim_refusal_passes
from pkcs11_check.testcases.conftest import import_secret_key_negotiated
from pkcs11_check.testcases.test_mech_derive import _mech_block_cbc_encrypt_data

pytestmark = [pytest.mark.full, pytest.mark.keymgmt, pytest.mark.derive]


_DES_KEY = bytes.fromhex("133457799BBCDFF1")
_DES3_KEY = bytes.fromhex("0123456789ABCDEFFEDCBA987654321089ABCDEF01234567")
_IV = bytes.fromhex("1234567890ABCDEF")
_DATA = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
_DES_EXPECTED_FULL = bytes.fromhex("b394acb206690c5cd9996818dc892370")
_DES_EXPECTED_TRUNCATED = bytes.fromhex("b394acb206690c5c")
_DES3_EXPECTED_FULL = bytes.fromhex("df1c83924e00a5182234bfd6b27d2dd7")
_DES3_EXPECTED_TRUNCATED = bytes.fromhex("df1c83924e00a518")


def _cbc_oracle(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Encrypt with DES-CBC, represented by 3DES EDE with K1=K2=K3 for DES."""
    effective_key = key if len(key) == 24 else key * 3
    encryptor = Cipher(algorithms.TripleDES(effective_key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _derive_attrs(length: int) -> dict[int, Any]:
    return {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_VALUE_LEN: length,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_TOKEN: False,
    }


def _kat_attribute_failure(
    *,
    attribute: int,
    mechanism_name: str,
    expected: Any,
    actual: Any,
    summary: str,
    reason: str = "wrong_result",
    kind: str = "metadata",
) -> NoReturn:
    """Fail a strict KAT readback without attributing C_GetAttributeValue to a mechanism."""
    C.fail_as(
        reason,
        kind=kind,
        label=f"{mechanism_name}: derived {attribute}",
        operation="C_GetAttributeValue",
        mechanism=None,
        inherit_mechanism=False,
        expected=expected,
        actual=actual,
        spec_ref="PKCS#11 v3.2 · C_GetAttributeValue",
        summary=summary,
        detail={
            "attribute": {"id": int(attribute)},
            "consumer_mechanism": mechanism_name,
            "producer_operation": "C_DeriveKey",
            "producer_mechanism": mechanism_name,
        },
    )


def _validate_kat_derived_attributes(
    attrs: Mapping[Any, Any],
    *,
    expected_value: bytes,
    expected_length: int,
    mechanism_name: str,
) -> None:
    """Require every strict KAT output attribute and validate its exact shape/value."""
    expected_scalars = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_VALUE_LEN: expected_length,
    }
    for attribute, expected in expected_scalars.items():
        if attribute not in attrs:
            _kat_attribute_failure(
                attribute=attribute,
                mechanism_name=mechanism_name,
                expected=expected,
                actual="missing",
                summary=f"{mechanism_name}: required derived attribute {attribute} is missing",
            )
        actual = attrs[attribute]
        if not isinstance(actual, int) or isinstance(actual, bool) or actual != expected:
            _kat_attribute_failure(
                attribute=attribute,
                mechanism_name=mechanism_name,
                expected=expected,
                actual={"type": type(actual).__name__, "value": actual},
                summary=f"{mechanism_name}: derived attribute {attribute} is malformed or wrong",
            )

    if CKA_VALUE not in attrs:
        _kat_attribute_failure(
            attribute=CKA_VALUE,
            mechanism_name=mechanism_name,
            expected={"type": "bytes", "length": expected_length},
            actual="missing",
            summary=f"{mechanism_name}: required derived CKA_VALUE is missing",
        )
    value = attrs[CKA_VALUE]
    if type(value) is not bytes or len(value) != expected_length:
        _kat_attribute_failure(
            attribute=CKA_VALUE,
            mechanism_name=mechanism_name,
            expected={"type": "bytes", "length": expected_length},
            actual={
                "type": type(value).__name__,
                "length": len(value) if isinstance(value, (bytes, bytearray)) else None,
            },
            summary=f"{mechanism_name}: derived CKA_VALUE is malformed or has the wrong length",
        )
    if value != expected_value:
        _kat_attribute_failure(
            attribute=CKA_VALUE,
            mechanism_name=mechanism_name,
            expected={"type": "bytes", "length": expected_length},
            actual={"type": "bytes", "length": len(value), "matches": False},
            summary=f"{mechanism_name}: derived CKA_VALUE differs from the CBC oracle",
            reason="oracle",
            kind="crypto",
        )


def _read_kat_derived_attributes(
    rs: Any,
    handle: int,
    *,
    expected_value: bytes,
    expected_length: int,
    mechanism_name: str,
) -> None:
    """Read and strictly validate all KAT output attributes."""
    try:
        attrs = read_attributes(
            rs.raw,
            rs.sh,
            handle,
            [CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN, CKA_VALUE],
        )
    except CkrAssertionError as exc:
        _kat_attribute_failure(
            attribute=CKA_VALUE,
            mechanism_name=mechanism_name,
            expected="CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN, CKA_VALUE",
            actual=ckr_name(exc.rv),
            summary=(
                f"{mechanism_name}: C_GetAttributeValue failed before strict KAT readback "
                f"could be completed ({ckr_name(exc.rv)})"
            ),
        )
    _validate_kat_derived_attributes(
        attrs,
        expected_value=expected_value,
        expected_length=expected_length,
        mechanism_name=mechanism_name,
    )


def _derive_or_xfail(
    rs: Any,
    base_key: int,
    mechanism: int,
    attrs: dict[int, Any],
    param: PackedMechanism,
    *,
    label: str,
    mechanism_name: str,
) -> int | None:
    """Run C_DeriveKey and classify a clean advertised-operation refusal."""
    try:
        handle = derive_key(
            rs.raw,
            rs.sh,
            base_key,
            mechanism,
            attrs=attrs,
            mech_param=param,
        )
        if handle == 0:
            C.classify(
                "self_contradiction",
                kind="lifecycle",
                label=f"{label}: returned handle",
                operation="C_DeriveKey",
                mechanism=mechanism_name,
                expected="non-zero object handle",
                actual=handle,
                summary=f"{label}: CKR_OK returned a zero derived-key handle",
            )
        return handle
    except CkrAssertionError as exc:
        if exc.rv == int(CKR_OPERATION_NOT_VALIDATED):
            claim_refusal_passes(exc, rs, probe_key=f"{mechanism_name}:derive")
            return None
        C.xfail_as(
            "not_operational",
            label=label,
            operation="C_DeriveKey",
            mechanism=mechanism_name,
            expected=CKR_OK,
            actual=exc.rv,
            summary=f"{label}: advertised but not operational ({ckr_name(exc.rv)})",
        )
        raise AssertionError("classification must raise") from exc


@pytest.mark.parametrize(
    (
        "mechanism_name",
        "mechanism",
        "key_type",
        "key_bytes",
        "expected_full",
        "expected_truncated",
    ),
    [
        (
            "CKM_DES_CBC_ENCRYPT_DATA",
            CKM_DES_CBC_ENCRYPT_DATA,
            CKK_DES,
            _DES_KEY,
            _DES_EXPECTED_FULL,
            _DES_EXPECTED_TRUNCATED,
        ),
        (
            "CKM_DES3_CBC_ENCRYPT_DATA",
            CKM_DES3_CBC_ENCRYPT_DATA,
            CKK_DES3,
            _DES3_KEY,
            _DES3_EXPECTED_FULL,
            _DES3_EXPECTED_TRUNCATED,
        ),
    ],
)
def test_des_cbc_encrypt_data_derive_matches_oracle_and_truncates(
    p11_raw_session: Any,
    mechanism_name: str,
    mechanism: int,
    key_type: int,
    key_bytes: bytes,
    expected_full: bytes,
    expected_truncated: bytes,
) -> None:
    """Known-key CBC derivation matches CBC and discards trailing ciphertext only."""
    rs = p11_raw_session
    if not rs.has_mechanism(mechanism_name.removeprefix("CKM_")):
        pytest.skip(f"{mechanism_name} not supported")

    base_key = 0
    try:
        base_key = import_secret_key_negotiated(
            rs,
            key_type,
            key_bytes,
            attrs={
                CKA_DERIVE: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
            purpose=f"{mechanism_name} fixed-key KAT provisioning",
        )
    except CkrAssertionError as exc:
        C.xfail_as(
            "not_operational",
            label=f"{mechanism_name}: fixed-key provisioning",
            operation="C_CreateObject",
            mechanism=None,
            inherit_mechanism=False,
            actual=exc.rv,
            summary=(
                f"{mechanism_name}: fixed-key KAT provisioning refused by the provider "
                f"({ckr_name(exc.rv)}); C_DeriveKey was not attempted"
            ),
            detail={"consumer_mechanism": mechanism_name},
        )
        raise AssertionError("classification must raise") from exc

    if base_key == 0:
        C.classify(
            "self_contradiction",
            kind="lifecycle",
            label=f"{mechanism_name}: fixed-key provisioning handle",
            operation="C_CreateObject",
            mechanism=None,
            inherit_mechanism=False,
            expected="non-zero object handle",
            actual=base_key,
            summary=(
                f"{mechanism_name}: fixed-key provisioning returned CKR_OK with a zero handle"
            ),
            detail={"consumer_mechanism": mechanism_name},
        )

    derived_full: int | None = None
    derived_truncated: int | None = None
    try:
        expected = _cbc_oracle(key_bytes, _IV, _DATA)
        if expected != expected_full:
            C.classify(
                "harness_error",
                label=f"{mechanism_name}: static oracle constant",
                operation="C_DeriveKey",
                mechanism=mechanism_name,
                expected=expected_full.hex(),
                actual=expected.hex(),
                summary=f"{mechanism_name}: static oracle constant disagrees with cryptography",
            )
        if expected[:8] != expected_truncated:
            C.fail_as(
                "harness_error",
                label=f"{mechanism_name}: static truncation constant",
                operation="C_DeriveKey",
                mechanism=mechanism_name,
                expected=expected[:8].hex(),
                actual=expected_truncated.hex(),
                summary=(
                    f"{mechanism_name}: static truncation constant disagrees with the "
                    "full oracle constant"
                ),
            )
        derived_full = _derive_or_xfail(
            rs,
            base_key,
            mechanism,
            _derive_attrs(len(expected)),
            _mech_block_cbc_encrypt_data(
                mechanism,
                CK_DES_CBC_ENCRYPT_DATA_PARAMS,
                iv=_IV,
                data=_DATA,
            ),
            label=f"{mechanism_name}: full-length C_DeriveKey",
            mechanism_name=mechanism_name,
        )
        if derived_full is None:
            return
        _read_kat_derived_attributes(
            rs,
            derived_full,
            expected_value=expected,
            expected_length=len(expected),
            mechanism_name=mechanism_name,
        )

        derived_truncated = _derive_or_xfail(
            rs,
            base_key,
            mechanism,
            _derive_attrs(8),
            _mech_block_cbc_encrypt_data(
                mechanism,
                CK_DES_CBC_ENCRYPT_DATA_PARAMS,
                iv=_IV,
                data=_DATA,
            ),
            label=f"{mechanism_name}: trailing-ciphertext truncation",
            mechanism_name=mechanism_name,
        )
        if derived_truncated is None:
            return
        _read_kat_derived_attributes(
            rs,
            derived_truncated,
            expected_value=expected_truncated,
            expected_length=8,
            mechanism_name=mechanism_name,
        )
    finally:
        if derived_truncated is not None:
            destroy_quietly(rs.raw, rs.sh, derived_truncated)
        if derived_full is not None:
            destroy_quietly(rs.raw, rs.sh, derived_full)
        destroy_quietly(rs.raw, rs.sh, base_key)
