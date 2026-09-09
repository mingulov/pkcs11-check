"""Finite child-side protocol adapters for missing PKCS#11 attributes."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Literal

from pkcs11_check.raw.metadata_std import ATTR_NAMES
from pkcs11_check.raw.types_std import CKA_EC_PARAMS, CKA_EC_POINT, CKA_MODULUS

_RSA_CASES = frozenset(
    f"decrypt:{mechanism}:{variant}"
    for mechanism in ("pkcs", "oaep")
    for variant in ("random", "truncated", "extended", "all_zeros", "all_ff")
)
_EC_PROBE = "ecdh_aes_wrap_compressed_public_key_buffer_too_small"


def _emit_ec_attribute_fact(
    attribute: int,
    *,
    state: Literal["present", "unusable"],
    value: object,
) -> None:
    descriptor = _descriptor(attribute)
    value_type = type(value).__name__[:64]
    value_len = len(value) if isinstance(value, bytes) else None
    payload = {
        "schema": 1,
        "probe": _EC_PROBE,
        "event": "attribute",
        "operation": "C_GetAttributeValue",
        "attribute": descriptor,
        "state": state,
        "value_len": value_len,
    }
    if state == "unusable":
        payload["value_type"] = value_type
    print(f"EC_SETUP:{json.dumps(payload, separators=(',', ':'))}", flush=True)


def _descriptor(attribute: int) -> dict[str, int | str]:
    name = ATTR_NAMES.get(attribute)
    if name is None:
        raise ValueError(f"unknown PKCS#11 attribute ID: {attribute}")
    # The generated table contains a later duplicate for the legacy ECDSA alias;
    # the EC setup parent owns the canonical PKCS#11 spelling.
    if attribute == int(CKA_EC_PARAMS):
        name = "CKA_EC_PARAMS"
    return {"name": name, "id": attribute}


def emit_missing_attribute(
    attribute: int,
    *,
    protocol: Literal["RSA_ATTRIBUTE", "EC_SETUP", "UAF"],
    context: str,
) -> None:
    """Emit one complete, protocol-specific fact for an omitted attribute."""
    if isinstance(attribute, bool) or not isinstance(attribute, int):
        raise TypeError("attribute must be a non-boolean integer")
    if not isinstance(context, str):
        raise TypeError("context must be a string")

    attribute_id = int(attribute)
    descriptor = _descriptor(attribute_id)
    if protocol == "RSA_ATTRIBUTE":
        if attribute_id != int(CKA_MODULUS) or context not in _RSA_CASES:
            raise ValueError("invalid RSA_ATTRIBUTE missing-attribute adapter")
        marker = "RSA_ATTRIBUTE"
        payload: dict[str, object] = {
            "schema": 1,
            "case": context,
            "operation": "C_GetAttributeValue",
            "attribute": descriptor,
            "state": "missing",
        }
    elif protocol == "EC_SETUP":
        if attribute_id not in {int(CKA_EC_POINT), int(CKA_EC_PARAMS)} or context != _EC_PROBE:
            raise ValueError("invalid EC_SETUP missing-attribute adapter")
        marker = "EC_SETUP"
        payload = {
            "schema": 1,
            "probe": context,
            "event": "attribute",
            "operation": "C_GetAttributeValue",
            "attribute": descriptor,
            "state": "missing",
        }
    elif protocol == "UAF":
        if attribute_id != int(CKA_EC_POINT) or context != "derive":
            raise ValueError("invalid UAF missing-attribute adapter")
        marker = "UAF"
        payload = {
            "schema": 1,
            "probe": context,
            "event": "SETUP_ATTRIBUTE",
            "attribute": descriptor,
            "state": "missing",
            "value_type": None,
            "value_len": None,
        }
    else:
        raise ValueError(f"unknown missing-attribute protocol: {protocol!r}")

    print(f"{marker}:{json.dumps(payload, separators=(',', ':'))}", flush=True)


def observe_ec_attribute(
    attributes: Mapping[object, object],
    attribute: int,
    *,
    context: str,
) -> bytes | None:
    """Record one EC setup observation without interpreting provider behavior."""
    if isinstance(attribute, bool) or not isinstance(attribute, int):
        raise TypeError("attribute must be a non-boolean integer")
    if attribute not in {int(CKA_EC_POINT), int(CKA_EC_PARAMS)}:
        raise ValueError("invalid EC setup attribute")
    if not isinstance(context, str):
        raise TypeError("context must be a string")
    if context != _EC_PROBE:
        raise ValueError("invalid EC setup observer context")

    if attribute not in attributes:
        emit_missing_attribute(attribute, protocol="EC_SETUP", context=context)
        return None
    value = attributes[attribute]
    if isinstance(value, bytes) and value:
        _emit_ec_attribute_fact(attribute, state="present", value=value)
        return value
    _emit_ec_attribute_fact(attribute, state="unusable", value=value)
    return None
