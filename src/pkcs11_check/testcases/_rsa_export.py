"""RSA attribute export helpers for cross-verification tests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa

from pkcs11_check.classification import xfail_as
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_COEFFICIENT,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_MODULUS,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_PRIVATE_EXPONENT,
    CKA_PUBLIC_EXPONENT,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
)
from pkcs11_check.testcases.conftest import xfail_if_known_ckr

_RSA_PUBLIC_ATTRS = (CKA_MODULUS, CKA_PUBLIC_EXPONENT)
_RSA_PRIVATE_ATTRS = (
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_PRIVATE_EXPONENT,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_COEFFICIENT,
)


def _attr_name(attr: int) -> str:
    return str(attr)


def _rsa_int_attr(
    attrs: Mapping[int, Any],
    attr: int,
    label: str,
    *,
    private: bool = False,
    min_value: int = 1,
) -> int:
    if attr not in attrs:
        kind = "private" if private else "public"
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            summary=f"{label}: missing RSA {kind} attribute {_attr_name(attr)}",
        )

    value = attrs[attr]
    if not isinstance(value, bytes) or not value:
        kind = "private" if private else "public"
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            summary=f"{label}: malformed RSA {kind} attributes: {_attr_name(attr)}={value!r}",
        )

    parsed = int.from_bytes(value, "big")
    if parsed < min_value:
        kind = "private" if private else "public"
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            summary=(
                f"{label}: malformed RSA {kind} attributes: {_attr_name(attr)} value {parsed} "
                f"is below minimum {min_value}"
            ),
        )
    return parsed


def rsa_public_key_from_attrs_or_xfail(
    attrs: Mapping[int, Any],
    *,
    label: str = "RSA public key",
) -> rsa.RSAPublicKey:
    """Build a cryptography RSA public key or xfail malformed provider readback."""
    n = _rsa_int_attr(attrs, CKA_MODULUS, label, min_value=3)
    e = _rsa_int_attr(attrs, CKA_PUBLIC_EXPONENT, label, min_value=3)
    try:
        return rsa.RSAPublicNumbers(e, n).public_key()
    except ValueError as exc:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            summary=f"{label}: malformed RSA public attributes: {exc}",
        )


def read_rsa_public_key_or_xfail(
    rs: Any,
    pub_handle: int,
    *,
    label: str = "RSA public key",
) -> rsa.RSAPublicKey:
    """Read public RSA attributes and build a cryptography public key."""
    try:
        attrs = read_attributes(rs.raw, rs.sh, pub_handle, _RSA_PUBLIC_ATTRS)
    except CkrAssertionError as exc:
        xfail_if_known_ckr(
            exc,
            (CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID),
            f"{label}: cannot read RSA public attributes",
        )
    return rsa_public_key_from_attrs_or_xfail(attrs, label=label)


def read_rsa_private_key_or_xfail(
    rs: Any,
    priv_handle: int,
    *,
    label: str = "RSA private key",
) -> rsa.RSAPrivateKey:
    """Read private RSA attributes and build a cryptography private key."""
    try:
        attrs = read_attributes(rs.raw, rs.sh, priv_handle, _RSA_PRIVATE_ATTRS)
    except CkrAssertionError as exc:
        xfail_if_known_ckr(
            exc,
            (CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID),
            f"{label}: cannot read RSA private attributes",
        )

    n = _rsa_int_attr(attrs, CKA_MODULUS, label, private=True, min_value=3)
    e = _rsa_int_attr(attrs, CKA_PUBLIC_EXPONENT, label, private=True, min_value=3)
    d = _rsa_int_attr(attrs, CKA_PRIVATE_EXPONENT, label, private=True)
    p_int = _rsa_int_attr(attrs, CKA_PRIME_1, label, private=True, min_value=3)
    q_int = _rsa_int_attr(attrs, CKA_PRIME_2, label, private=True, min_value=3)
    dp_int = _rsa_int_attr(attrs, CKA_EXPONENT_1, label, private=True)
    dq_int = _rsa_int_attr(attrs, CKA_EXPONENT_2, label, private=True)
    qi_int = _rsa_int_attr(attrs, CKA_COEFFICIENT, label, private=True)

    try:
        return rsa.RSAPrivateNumbers(
            p_int,
            q_int,
            d,
            dp_int,
            dq_int,
            qi_int,
            rsa.RSAPublicNumbers(e, n),
        ).private_key()
    except ValueError as exc:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            summary=f"{label}: malformed RSA private attributes: {exc}",
        )
