"""Stateful property tests for PKCS#11 session/object lifecycle.

Uses hypothesis.stateful to model a PKCS#11 session as a state machine,
testing that any sequence of valid operations maintains consistency.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    find_objects,
    gen_aes_key,
    generate_random,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_TOKEN,
    CKM_AES_ECB,
    CKM_SHA256,
)
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    require_operational_aes_keygen,
    xfail_if_known_ckr,
)

pytestmark = [pytest.mark.stateful, pytest.mark.fuzz]

_STATEFUL_AES_KEY_BITS = 128


def _gen_stateful_aes_key(rs: Any, attrs: Mapping[Any, Any]) -> int:
    """Generate an AES setup key for lifecycle tests, preserving runtime rejects as xfails."""
    try:
        return gen_aes_key(rs.raw, rs.sh, bits=_STATEFUL_AES_KEY_BITS, attrs=attrs)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            "AES_KEY_GEN advertised but stateful AES key generation is not operational",
        )
        raise


def test_pkcs11_stateful(p11_raw_session: Any) -> None:
    """Run the stateful state machine test."""
    rs = p11_raw_session
    require_operational_aes_keygen(rs)
    # Stateful lifecycle: create, use, search, destroy, verify gone
    key1 = _gen_stateful_aes_key(rs, attrs={CKA_LABEL: "stateful-manual-1"})
    key2 = _gen_stateful_aes_key(rs, attrs={CKA_LABEL: "stateful-manual-2"})

    try:
        # Both keys should work
        ct1 = encrypt_single(rs.raw, rs.sh, key1, CKM_AES_ECB, b"0123456789abcdef")
        ct2 = encrypt_single(rs.raw, rs.sh, key2, CKM_AES_ECB, b"0123456789abcdef")
        assert ct1 != ct2  # Different keys, different ciphertext

        # Destroy one, other still works
        destroy_quietly(rs.raw, rs.sh, key1)
        key1 = 0
        pt2 = decrypt_single(rs.raw, rs.sh, key2, CKM_AES_ECB, ct2)
        assert pt2 == b"0123456789abcdef"

        # Search should only find key2
        found1 = find_objects(rs.raw, rs.sh, template_from_dict({CKA_LABEL: "stateful-manual-1"}))
        assert len(found1) == 0
        found2 = find_objects(rs.raw, rs.sh, template_from_dict({CKA_LABEL: "stateful-manual-2"}))
        assert len(found2) == 1
    finally:
        if key1:
            destroy_quietly(rs.raw, rs.sh, key1)
        destroy_quietly(rs.raw, rs.sh, key2)


def test_generate_use_destroy_cycle(p11_raw_session: Any) -> None:
    """Generate keys, use them, destroy them - verify lifecycle consistency."""
    rs = p11_raw_session
    require_operational_aes_keygen(rs)
    keys: list[int] = []
    labels: list[str] = []

    try:
        # Generate multiple keys
        for i in range(5):
            label = f"stateful-cycle-{i}"
            key = _gen_stateful_aes_key(rs, attrs={CKA_LABEL: label, CKA_TOKEN: False})
            keys.append(key)
            labels.append(label)

        # Each key should work for encrypt/decrypt
        for key in keys:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, b"lifecycle test!!")
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert pt == b"lifecycle test!!"

        # Read attributes should work
        for key in keys:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_KEY_TYPE])
            assert attrs[CKA_KEY_TYPE] is not None

        # Destroy half the keys
        for key in keys[:3]:
            destroy_quietly(rs.raw, rs.sh, key)
        keys[:3] = [0, 0, 0]

        # Remaining keys should still work
        for key in keys[3:]:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, b"still working!!!")
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert pt == b"still working!!!"

        # Generate random should always work
        data = generate_random(rs.raw, rs.sh, 32)
        assert len(data) == 32

        # Digest should always work
        digest = digest_single(rs.raw, rs.sh, CKM_SHA256, b"stateful test")
        assert len(digest) == 32

    finally:
        for key in keys:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)


def test_object_count_consistency(p11_raw_session: Any) -> None:
    """Object count must reflect creates and destroys."""
    rs = p11_raw_session
    require_operational_aes_keygen(rs)
    label_prefix = "stateful-count-"

    # Create 3 keys with unique labels
    created: list[int] = []
    for i in range(3):
        key = _gen_stateful_aes_key(
            rs,
            attrs={CKA_LABEL: f"{label_prefix}{i}", CKA_TOKEN: False},
        )
        created.append(key)

    try:
        # Find them all
        for i, key in enumerate(created):
            found = find_objects(
                rs.raw,
                rs.sh,
                template_from_dict({CKA_LABEL: f"{label_prefix}{i}"}),
            )
            assert len(found) >= 1, f"Key {label_prefix}{i} not found"

        # Destroy one
        destroy_quietly(rs.raw, rs.sh, created[1])
        created[1] = 0

        # The destroyed one should not be findable
        found = find_objects(
            rs.raw,
            rs.sh,
            template_from_dict({CKA_LABEL: f"{label_prefix}1"}),
        )
        assert len(found) == 0, "Destroyed key still found"

        # The others should still exist
        for i in [0, 2]:
            found = find_objects(
                rs.raw,
                rs.sh,
                template_from_dict({CKA_LABEL: f"{label_prefix}{i}"}),
            )
            assert len(found) >= 1
    finally:
        for key in created:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)
