"""Regression tests for digest KAT family routing and vector schema handling."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.classification import get_records
from pkcs11_check.raw.types_std import CKM_SHA224
from pkcs11_check.testcases import mechanism_vectors, test_mech_digest
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig


def _entry() -> MechEntry:
    return MechEntry(
        mech_id=int(CKM_SHA224),
        mech_name="SHA224",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=MechConfig(vector_file="sha.json", input_constraint="digest_only"),
    )


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


@pytest.mark.parametrize("mechanism_name", ["CKM_SHA224", "SHA224"])
def test_valid_digest_vector_still_invokes_provider(
    monkeypatch: pytest.MonkeyPatch,
    mechanism_name: str,
) -> None:
    input_bytes = b"abc"
    expected = hashlib.sha224(input_bytes).digest()
    calls: list[tuple[int, bytes]] = []

    monkeypatch.setattr(
        mechanism_vectors,
        "load_positive_vectors",
        lambda _path: [
            {
                "id": "sha224-abc",
                "mechanism_name": mechanism_name,
                "input_hex": input_bytes.hex(),
                "digest_hex": expected.hex(),
            }
        ],
    )

    def _digest(_raw: object, _sh: int, mechanism: int, data: bytes) -> bytes:
        calls.append((mechanism, data))
        return expected

    monkeypatch.setattr(test_mech_digest, "digest_single", _digest)

    test_mech_digest.TestMechDigestKAT().test_kat_vector(_session(), _entry())

    assert calls == [(int(CKM_SHA224), input_bytes)]


@pytest.mark.parametrize(
    "vector",
    [
        {"id": "missing-input", "mechanism_name": "CKM_SHA224", "digest_hex": "00"},
        {
            "id": "wrong-input-type",
            "mechanism_name": "CKM_SHA224",
            "input_hex": 123,
            "digest_hex": "00",
        },
        {"id": "odd-input", "mechanism_name": "CKM_SHA224", "input_hex": "0", "digest_hex": "00"},
        {
            "id": "bad-input",
            "mechanism_name": "CKM_SHA224",
            "input_hex": "gg",
            "digest_hex": "00",
        },
        {"id": "missing-digest", "mechanism_name": "CKM_SHA224", "input_hex": "00"},
        {
            "id": "wrong-digest-type",
            "mechanism_name": "CKM_SHA224",
            "input_hex": "00",
            "digest_hex": 123,
        },
        {
            "id": "odd-digest",
            "mechanism_name": "CKM_SHA224",
            "input_hex": "00",
            "digest_hex": "0",
        },
        {
            "id": "bad-digest",
            "mechanism_name": "CKM_SHA224",
            "input_hex": "00",
            "digest_hex": "gg",
        },
    ],
)
def test_malformed_selected_digest_vector_is_harness_error(
    monkeypatch: pytest.MonkeyPatch,
    vector: dict[str, Any],
) -> None:
    monkeypatch.setattr(mechanism_vectors, "load_positive_vectors", lambda _path: [vector])

    with pytest.raises(pytest.fail.Exception, match="selected digest vector"):
        test_mech_digest.TestMechDigestKAT().test_kat_vector(_session(), _entry())

    records = get_records()
    assert len(records) == 1
    assert records[0].reason == "harness_error"
    assert records[0].label == "digest vector schema"
    assert records[0].source == "sha.json"
    assert records[0].vector_id == vector["id"]
    assert records[0].summary == "selected digest vector has invalid input_hex/digest_hex"


def test_other_mechanism_vectors_are_filtered_before_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unrelated = {
        "id": "aes-gcm-1",
        "mechanism_name": "CKM_AES_GCM",
        "input_hex": None,
        "digest_hex": None,
    }
    monkeypatch.setattr(mechanism_vectors, "load_positive_vectors", lambda _path: [unrelated])

    with pytest.raises(pytest.skip.Exception, match="No compatible digest vectors"):
        test_mech_digest.TestMechDigestKAT().test_kat_vector(_session(), _entry())

    assert get_records() == []


def test_no_matching_digest_vectors_is_unavailable_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mechanism_vectors, "load_positive_vectors", lambda _path: [])

    with pytest.raises(pytest.skip.Exception, match="No compatible digest vectors"):
        test_mech_digest.TestMechDigestKAT().test_kat_vector(_session(), _entry())

    assert get_records() == []
