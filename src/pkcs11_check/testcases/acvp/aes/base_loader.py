"""ACVP AES vector loading utilities."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import pytest

from pkcs11_check.testcases.data.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors

# Maximum vectors per direction for speed
_MAX_PER_DIRECTION = 10

# Module-level skip if ACVP data not available
if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )


def _load_vectors(
    vector_name: str,
    encrypt_fields: Mapping[str, str | tuple[str, Callable[[str], Any]]],
    decrypt_fields: Mapping[str, str | tuple[str, Callable[[str], Any]]],
    tag_len_bits: int | None = None,
    extra_group_fields: Mapping[str, str] | None = None,
) -> tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]]:
    """Generic ACVP vector loader.

    Args:
        vector_name: Name of the ACVP vector set (e.g., "ACVP-AES-GCM-1.0")
        encrypt_fields: Mapping of field names to input/expected keys for encrypt direction.
            Format: {"field_name": "input_key"} or {"field_name": ("input_key", transform)}
        decrypt_fields: Mapping of field names to input/expected keys for decrypt direction.
        tag_len_bits: Optional tag length from group data
        extra_group_fields: Additional fields to extract from group data

    Returns:
        Tuple of (encrypt_vectors, decrypt_vectors), each a list of (vec_id, merged_dict)
    """
    raw = load_acvp_vectors(vector_name)
    encrypt_vecs: list[tuple[str, dict[str, Any]]] = []
    decrypt_vecs: list[tuple[str, dict[str, Any]]] = []

    for vec in raw:
        group = vec["group"]
        inp = vec["input"]
        exp = vec["expected"]
        direction = group.get("direction", "")
        tc_id = inp.get("tcId", 0)

        if direction == "encrypt":
            if len(encrypt_vecs) >= _MAX_PER_DIRECTION:
                continue

            merged: dict[str, Any] = {"tc_id": tc_id}
            valid = True

            # Extract fields for encrypt direction
            for field_name, field_spec in encrypt_fields.items():
                if isinstance(field_spec, tuple):
                    src_key, transform = field_spec
                else:
                    src_key = field_spec
                    transform = None

                value = inp.get(src_key, "") if src_key in inp else exp.get(src_key, "")

                if field_name == "key" and not value:
                    valid = False
                    break

                if value and transform:
                    value = transform(value)
                elif value and src_key in ("key", "iv", "pt", "ct", "aad", "nonce"):
                    value = bytes.fromhex(value)

                merged[field_name] = value

            if not valid:
                continue

            # Add extra group fields
            if extra_group_fields:
                for field_name, group_key in extra_group_fields.items():
                    merged[field_name] = group.get(group_key)

            if tag_len_bits is not None:
                merged["tag_len_bits"] = tag_len_bits

            vec_id = f"{vector_name.split('-')[1]}-enc-tc{tc_id}"
            encrypt_vecs.append((vec_id, merged))

        elif direction == "decrypt":
            if len(decrypt_vecs) >= _MAX_PER_DIRECTION:
                continue

            merged = {"tc_id": tc_id}
            valid = True

            # Extract fields for decrypt direction
            for field_name, field_spec in decrypt_fields.items():
                if isinstance(field_spec, tuple):
                    src_key, transform = field_spec
                else:
                    src_key = field_spec
                    transform = None

                value = inp.get(src_key, "") if src_key in inp else exp.get(src_key, "")

                if field_name == "key" and not value:
                    valid = False
                    break

                if value and transform:
                    value = transform(value)
                elif value and src_key in ("key", "iv", "pt", "ct", "aad", "nonce", "tag"):
                    value = bytes.fromhex(value)

                merged[field_name] = value

            if not valid:
                continue

            # Add testPassed if present
            if "testPassed" in exp:
                merged["test_passed"] = exp.get("testPassed", True)

            # Add extra group fields
            if extra_group_fields:
                for field_name, group_key in extra_group_fields.items():
                    merged[field_name] = group.get(group_key)

            if tag_len_bits is not None:
                merged["tag_len_bits"] = tag_len_bits

            vec_id = f"{vector_name.split('-')[1]}-dec-tc{tc_id}"
            decrypt_vecs.append((vec_id, merged))

    return encrypt_vecs, decrypt_vecs


def _load_simple_vectors(
    vector_name: str,
    has_iv: bool = True,
    has_aad: bool = False,
) -> tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]]:
    """Load simple encrypt/decrypt vectors (CFB, OFB modes).

    Args:
        vector_name: Name of the ACVP vector set
        has_iv: Whether vectors contain IV
        has_aad: Whether vectors contain AAD (for AEAD modes)

    Returns:
        Tuple of (encrypt_vectors, decrypt_vectors)
    """
    encrypt_fields: dict[str, str] = {"key": "key", "pt": "pt", "ct_expected": "ct"}
    decrypt_fields: dict[str, str] = {"key": "key", "ct": "ct", "pt_expected": "pt"}

    if has_iv:
        encrypt_fields["iv"] = "iv"
        decrypt_fields["iv"] = "iv"
    if has_aad:
        encrypt_fields["aad"] = "aad"
        decrypt_fields["aad"] = "aad"

    return _load_vectors(vector_name, encrypt_fields, decrypt_fields)
