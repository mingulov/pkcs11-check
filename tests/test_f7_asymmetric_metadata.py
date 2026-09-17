"""Regression tests for asymmetric-metadata readback classification (F7 slice 03).

Exercises the migrated call sites in ``test_dsa_complete.py``, ``test_eddsa.py``,
``test_pqc_sign.py`` and ``test_provisioned_sign_coherence.py`` directly (not through
pytest collection of those files, which needs a real PKCS#11 module) by monkeypatching
their collaborator functions and invoking the test functions/methods with a fake
session. Each test proves a specific behavior contract: a missing attribute
produces a structured, mechanism-free record instead of a
``KeyError``/``TypeError`` crash; independent work in the same test still runs; handles
are still destroyed; and a present-but-wrong value still fails hard.
"""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.types_std import (
    CKA_BASE,
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_PRIME,
    CKA_PRIME_BITS,
    CKA_SIGN,
    CKA_SUBPRIME,
    CKA_SUBPRIME_BITS,
    CKK_EC,
    CKK_EC_EDWARDS,
    CKK_ML_DSA,
    CKO_PRIVATE_KEY,
)
from pkcs11_check.testcases import test_dsa_complete as dsa
from pkcs11_check.testcases import test_eddsa as eddsa
from pkcs11_check.testcases import test_pqc_sign as pqc
from pkcs11_check.testcases import test_provisioned_sign_coherence as coh
from tests._skip_assert import assert_skips


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session(**extra: Any) -> SimpleNamespace:
    base = {"raw": object(), "sh": 1, "has_mechanism": lambda _name: True}
    base.update(extra)
    return SimpleNamespace(**base)


def _by_handle(mapping_by_handle: dict[int, dict[Any, Any]]) -> Any:
    """Build a read_attributes double that dispatches on the object handle."""

    def _read(_raw: Any, _sh: Any, handle: int, _attrs: Any) -> dict[Any, Any]:
        return dict(mapping_by_handle[handle])

    return _read


# === test_dsa_complete.py ==============================================================

# --- Site class: _gen_dsa_keypair_from_params (PRIME/SUBPRIME/BASE -> keypair) ---------


def test_dsa_keypair_from_params_missing_prime_returns_none_and_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_PRIME omitted on domain-param readback: no KeyError, one xfail record.

    ``raw`` is a bare ``object()`` with no ``C_GenerateKeyPair`` -- if the missing
    attribute were not caught before that call, this test would crash with
    ``AttributeError`` instead of observing a clean ``None`` return.
    """
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    monkeypatch.setattr(
        dsa, "read_attributes", lambda *_a, **_k: {CKA_SUBPRIME: b"Q", CKA_BASE: b"G"}
    )

    result = dsa._gen_dsa_keypair_from_params(object(), 1, 42)

    assert result is None
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.outcome == "xfail"
    assert rec.kind == "metadata"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.mechanism is None
    assert rec.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    assert rec.detail == {"attribute": {"name": "CKA_PRIME", "id": int(CKA_PRIME)}}


def test_dsa_keypair_from_params_present_but_malformed_stays_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-wrong-type CKA_PRIME must still fail hard, not be downgraded."""
    monkeypatch.setattr(
        dsa,
        "read_attributes",
        lambda *_a, **_k: {CKA_PRIME: 12345, CKA_SUBPRIME: b"Q", CKA_BASE: b"G"},
    )

    with pytest.raises(AssertionError):
        dsa._gen_dsa_keypair_from_params(object(), 1, 42)

    # Nothing was missing (CKA_PRIME was present, just malformed) -- no classification.
    assert C.get_records() == []


def test_dsa_keypair_from_params_missing_prime_and_subprime_records_both(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both required DSA domain-parameter siblings must be retained as findings."""
    monkeypatch.setattr(dsa, "read_attributes", lambda *_a, **_k: {CKA_BASE: b"G"})

    result = dsa._gen_dsa_keypair_from_params(object(), 1, 42)

    assert result is None
    records = C.get_records()
    assert len(records) == 2
    assert [rec.detail for rec in records] == [
        {"attribute": {"name": "CKA_PRIME", "id": int(CKA_PRIME)}},
        {"attribute": {"name": "CKA_SUBPRIME", "id": int(CKA_SUBPRIME)}},
    ]


def test_dsa_keypair_from_params_missing_prime_does_not_mask_bad_subprime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed present sibling must remain hard beside a missing sibling."""
    monkeypatch.setattr(
        dsa,
        "read_attributes",
        lambda *_a, **_k: {CKA_SUBPRIME: b"", CKA_BASE: b"G"},
    )

    with pytest.raises(AssertionError):
        dsa._gen_dsa_keypair_from_params(object(), 1, 42)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].detail == {"attribute": {"name": "CKA_PRIME", "id": int(CKA_PRIME)}}


@pytest.mark.parametrize("base", [b"", 12345], ids=["empty", "wrong-type"])
def test_dsa_keypair_from_params_missing_prime_does_not_mask_bad_base(
    monkeypatch: pytest.MonkeyPatch, base: object
) -> None:
    """An omitted sibling must not hide malformed or empty CKA_BASE readback."""
    monkeypatch.setattr(
        dsa,
        "read_attributes",
        lambda *_a, **_k: {CKA_SUBPRIME: b"Q", CKA_BASE: base},
    )

    with pytest.raises(AssertionError):
        dsa._gen_dsa_keypair_from_params(object(), 1, 42)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].detail == {"attribute": {"name": "CKA_PRIME", "id": int(CKA_PRIME)}}


def test_generate_dsa_keypair_wrapper_missing_attribute_cleans_up_and_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Continuation: the keypair wrapper must destroy dp_handle and return None,
    not crash, when a domain-parameter attribute is missing on readback."""
    destroyed: list[int] = []
    monkeypatch.setattr(dsa, "_generate_dsa_params", lambda _raw, _sh: 55)
    monkeypatch.setattr(dsa, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(dsa, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    result = dsa._generate_dsa_keypair(_session())

    assert result is None
    assert destroyed == [55]
    records = C.get_records()
    assert len(records) == 3  # CKA_PRIME, CKA_SUBPRIME, CKA_BASE all omitted
    assert {rec.reason for rec in records} == {"not_operational"}
    assert all(rec.mechanism is None for rec in records)
    assert [rec.detail for rec in records] == [
        {"attribute": {"name": "CKA_PRIME", "id": int(CKA_PRIME)}},
        {"attribute": {"name": "CKA_SUBPRIME", "id": int(CKA_SUBPRIME)}},
        {"attribute": {"name": "CKA_BASE", "id": int(CKA_BASE)}},
    ]


# --- Site class: _assert_generated_dsa_pq_attrs (PRIME/SUBPRIME/BITS) ------------------


def test_assert_generated_pq_attrs_missing_prime_bits_continues_and_returns_pq(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing CKA_PRIME_BITS must not block returning prime/subprime, nor the
    independent CKA_SUBPRIME_BITS check."""
    monkeypatch.setattr(
        dsa,
        "read_attributes",
        lambda *_a, **_k: {CKA_PRIME: b"P", CKA_SUBPRIME: b"Q", CKA_SUBPRIME_BITS: 256},
    )

    result = dsa._assert_generated_dsa_pq_attrs(object(), 1, 7)

    assert result == (b"P", b"Q")
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.mechanism is None
    assert rec.operation == "C_GetAttributeValue"
    assert rec.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    assert rec.detail == {"attribute": {"name": "CKA_PRIME_BITS", "id": int(CKA_PRIME_BITS)}}


def test_assert_generated_pq_attrs_missing_prime_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing CKA_PRIME (essential for dependent base-generation) returns None."""
    monkeypatch.setattr(
        dsa,
        "read_attributes",
        lambda *_a, **_k: {CKA_SUBPRIME: b"Q", CKA_PRIME_BITS: 2048, CKA_SUBPRIME_BITS: 256},
    )

    result = dsa._assert_generated_dsa_pq_attrs(object(), 1, 7)

    assert result is None
    records = C.get_records()
    assert len(records) == 1
    assert records[0].detail == {"attribute": {"name": "CKA_PRIME", "id": int(CKA_PRIME)}}


def test_assert_generated_pq_attrs_missing_prime_and_subprime_records_both(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both missing DSA siblings must be reported independently."""
    monkeypatch.setattr(
        dsa,
        "read_attributes",
        lambda *_a, **_k: {CKA_PRIME_BITS: 2048, CKA_SUBPRIME_BITS: 256},
    )

    result = dsa._assert_generated_dsa_pq_attrs(object(), 1, 7)

    assert result is None
    records = C.get_records()
    assert len(records) == 2
    assert [rec.detail for rec in records] == [
        {"attribute": {"name": "CKA_PRIME", "id": int(CKA_PRIME)}},
        {"attribute": {"name": "CKA_SUBPRIME", "id": int(CKA_SUBPRIME)}},
    ]


def test_assert_generated_pq_attrs_missing_prime_does_not_mask_bad_subprime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present malformed sibling remains a hard finding beside a missing one."""
    monkeypatch.setattr(
        dsa,
        "read_attributes",
        lambda *_a, **_k: {CKA_SUBPRIME: b"", CKA_PRIME_BITS: 2048, CKA_SUBPRIME_BITS: 256},
    )

    with pytest.raises(AssertionError):
        dsa._assert_generated_dsa_pq_attrs(object(), 1, 7)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].detail == {"attribute": {"name": "CKA_PRIME", "id": int(CKA_PRIME)}}


def test_assert_generated_pq_attrs_wrong_prime_bits_stays_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-wrong CKA_PRIME_BITS must still fail hard (wrong_result)."""
    monkeypatch.setattr(
        dsa,
        "read_attributes",
        lambda *_a, **_k: {
            CKA_PRIME: b"P",
            CKA_SUBPRIME: b"Q",
            CKA_PRIME_BITS: 1024,  # wrong: expected 2048
            CKA_SUBPRIME_BITS: 256,
        },
    )

    with pytest.raises(pytest.fail.Exception):
        dsa._assert_generated_dsa_pq_attrs(object(), 1, 7)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"


# --- Site class: single-attribute readback guard (CKA_BASE in FIPS G-gen test) --------


def test_fips_g_gen_missing_base_skips_assert_and_cleans_up_both_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_BASE omitted on the generated-base readback: no crash, both handles freed."""
    destroyed: list[int] = []
    monkeypatch.setattr(dsa, "_generate_dsa_pq_params", lambda *_a, **_k: (1, object()))
    monkeypatch.setattr(dsa, "_assert_generated_dsa_pq_attrs", lambda *_a, **_k: (b"P", b"Q"))
    monkeypatch.setattr(dsa, "_dsa_returned_seed", lambda _mech: b"seed")
    monkeypatch.setattr(dsa, "_generate_dsa_base_from_pq", lambda *_a, **_k: 2)
    monkeypatch.setattr(dsa, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(dsa, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    rs = _session()
    dsa.TestDSAParameterGen().test_fips_g_gen_uses_generated_seed_and_pq(rs)

    assert destroyed == [2, 1]
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.mechanism is None
    assert rec.detail == {"attribute": {"name": "CKA_BASE", "id": int(CKA_BASE)}}


# === test_eddsa.py ======================================================================


def test_eddsa_key_type_missing_pub_continues_to_priv_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_KEY_TYPE omitted for the public key must not block checking the private key."""
    monkeypatch.setattr(
        eddsa,
        "read_attributes",
        _by_handle({11: {}, 12: {CKA_KEY_TYPE: CKK_EC_EDWARDS}}),
    )

    eddsa.TestEdDSAKeyGeneration().test_ed25519_key_type(_session(), (11, 12))

    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.mechanism is None
    assert rec.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    assert rec.detail == {"attribute": {"name": "CKA_KEY_TYPE", "id": int(CKA_KEY_TYPE)}}


def test_eddsa_key_type_present_but_wrong_stays_hard(monkeypatch: pytest.MonkeyPatch) -> None:
    """A present-but-wrong CKA_KEY_TYPE must still fail hard, not be downgraded."""
    monkeypatch.setattr(
        eddsa,
        "read_attributes",
        _by_handle({11: {CKA_KEY_TYPE: CKK_EC_EDWARDS}, 12: {CKA_KEY_TYPE: 0xDEAD}}),
    )

    with pytest.raises(pytest.fail.Exception):
        eddsa.TestEdDSAKeyGeneration().test_ed25519_key_type(_session(), (11, 12))

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"


def test_eddsa_ec_params_missing_records_and_does_not_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_EC_PARAMS omitted on readback: structured record, no KeyError."""
    monkeypatch.setattr(eddsa, "read_attributes", lambda *_a, **_k: {})

    eddsa.TestEdDSAKeyGeneration().test_ed25519_ec_params(_session(), (11, 12))

    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.mechanism is None
    assert rec.detail == {"attribute": {"name": "CKA_ECDSA_PARAMS", "id": int(CKA_EC_PARAMS)}}


# === test_pqc_sign.py ====================================================================


def test_pqc_ml_dsa_classes_missing_pub_continues_to_priv_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_CLASS omitted for the ML-DSA public key must not block the private-key check,
    nor skip cleanup."""
    destroyed: list[int] = []
    monkeypatch.setattr(pqc, "_generate_ml_dsa_keypair", lambda *_a, **_k: (21, 22))
    monkeypatch.setattr(
        pqc,
        "read_attributes",
        _by_handle({21: {}, 22: {CKA_CLASS: CKO_PRIVATE_KEY}}),
    )
    monkeypatch.setattr(pqc, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    pqc.TestMLDSAKeyGeneration().test_ml_dsa_keypair_classes(_session())

    assert destroyed == [21, 22]
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.mechanism is None
    assert rec.detail == {"attribute": {"name": "CKA_CLASS", "id": int(CKA_CLASS)}}


def test_pqc_ml_dsa_key_type_present_but_wrong_stays_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-wrong CKA_KEY_TYPE on an ML-DSA key must still fail hard."""
    monkeypatch.setattr(pqc, "_generate_ml_dsa_keypair", lambda *_a, **_k: (31, 32))
    monkeypatch.setattr(
        pqc,
        "read_attributes",
        _by_handle({31: {CKA_KEY_TYPE: CKK_ML_DSA}, 32: {CKA_KEY_TYPE: 0xBAD}}),
    )
    monkeypatch.setattr(pqc, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception):
        pqc.TestMLDSAKeyGeneration().test_ml_dsa_keypair_key_type(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"


# === test_provisioned_sign_coherence.py ==================================================


def test_match_public_missing_id_falls_through_to_label(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKA_ID omitted must not abort matching: CKA_LABEL is tried next (loop continues)."""
    monkeypatch.setattr(coh, "find_objects", lambda *_a, **_k: [999])

    result = coh._match_public(_session(), {CKA_LABEL: "provisioned-label"})

    assert result == 999
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "honest_deviation"
    assert rec.outcome == "xfail"
    assert rec.mechanism is None
    assert rec.detail == {"attribute": {"name": "CKA_ID", "id": int(CKA_ID)}}


def test_match_public_missing_linking_attributes_have_distinct_labels() -> None:
    """Independent CKA_ID and CKA_LABEL omissions must remain distinguishable."""
    result = coh._match_public(_session(), {})

    assert result is None
    records = C.get_records()
    assert len(records) == 2
    labels_by_attribute = {
        rec.detail["attribute"]["name"]: rec.label for rec in records if rec.detail is not None
    }
    assert set(labels_by_attribute) == {"CKA_ID", "CKA_LABEL"}
    assert labels_by_attribute["CKA_ID"] != labels_by_attribute["CKA_LABEL"]
    assert "CKA_ID" in labels_by_attribute["CKA_ID"]
    assert "CKA_LABEL" in labels_by_attribute["CKA_LABEL"]


def test_match_public_present_empty_id_is_not_missing_and_falls_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-empty CKA_ID is a real value (not an omission): no record,
    business logic still tries CKA_LABEL next."""
    monkeypatch.setattr(coh, "find_objects", lambda *_a, **_k: [7])

    result = coh._match_public(_session(), {CKA_ID: b"", CKA_LABEL: "L"})

    assert result == 7
    assert C.get_records() == []


def test_provisioned_sign_missing_sign_flag_skips_key_and_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_SIGN omitted must skip that key (as if False) and record the omission,
    not crash, ending in the normal no-findable-keys skip."""
    monkeypatch.setattr(coh, "find_objects", lambda *_a, **_k: [201])
    monkeypatch.setattr(coh, "read_attributes", lambda *_a, **_k: {})

    assert_skips(coh.test_provisioned_signing_keys_are_coherent, _session())

    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.mechanism is None
    assert rec.detail == {"attribute": {"name": "CKA_SIGN", "id": int(CKA_SIGN)}}


def test_provisioned_sign_loop_continues_past_two_independent_omissions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Continuation: a missing CKA_SIGN on one key must not stop the loop from
    independently processing the next key (which then hits its own missing
    CKA_KEY_TYPE) -- both are recorded, neither crashes the loop."""
    call_count = {"n": 0}

    def _find_objects(_raw: Any, _sh: Any, _tmpl: Any) -> list[int]:
        call_count["n"] += 1
        if call_count["n"] == 1:
            return [201, 202]
        return [999]  # matched public key for any _match_public probe

    attrs_by_handle = {
        201: {},  # CKA_SIGN missing entirely
        202: {CKA_SIGN: True, CKA_ID: b"id2"},  # CKA_KEY_TYPE missing
    }
    monkeypatch.setattr(coh, "find_objects", _find_objects)
    monkeypatch.setattr(coh, "read_attributes", _by_handle(attrs_by_handle))

    assert_skips(coh.test_provisioned_signing_keys_are_coherent, _session())

    records = C.get_records()
    assert len(records) == 2
    assert {rec.detail["attribute"]["name"] for rec in records if rec.detail} == {
        "CKA_SIGN",
        "CKA_KEY_TYPE",
    }
    assert {rec.reason for rec in records} == {"not_operational"}


def test_provisioned_sign_missing_ec_params_skips_key_without_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKA_EC_PARAMS omitted must not attempt bytes(MISSING_ATTRIBUTE) -- that would
    raise TypeError instead of being recorded and skipped."""

    def _read(_raw: Any, _sh: Any, handle: int, attrs: Any) -> dict[Any, Any]:
        assert handle == 301
        if CKA_EC_PARAMS in attrs:
            return {}
        return {CKA_SIGN: True, CKA_KEY_TYPE: int(CKK_EC), CKA_ID: b"id"}

    def _sign_boom(*_a: Any, **_k: Any) -> bytes:
        raise AssertionError("sign_single must not run when CKA_EC_PARAMS is missing")

    call_count = {"n": 0}

    def _find_objects(_raw: Any, _sh: Any, _tmpl: Any) -> list[int]:
        call_count["n"] += 1
        return [301] if call_count["n"] == 1 else [999]

    monkeypatch.setattr(coh, "find_objects", _find_objects)
    monkeypatch.setattr(coh, "read_attributes", _read)
    monkeypatch.setattr(coh, "sign_single", _sign_boom)

    assert_skips(coh.test_provisioned_signing_keys_are_coherent, _session())

    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == "not_operational"
    assert rec.mechanism is None
    assert rec.detail == {"attribute": {"name": "CKA_ECDSA_PARAMS", "id": int(CKA_EC_PARAMS)}}
