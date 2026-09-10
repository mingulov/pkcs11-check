"""Runtime classification regressions for generic KDF and ECDH checks."""

from __future__ import annotations

from collections.abc import Callable, Generator
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKA_EC_POINT, CKA_VALUE, CKM_SHA3_224_KEY_DERIVE
from pkcs11_check.testcases import _ec_export, test_kdf
from pkcs11_check.testcases._ec_export import ConventionalECPoint
from tests._attribute_access_guard import analyze_file


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )


def _synthetic_point(private_value: int = 7) -> ConventionalECPoint:
    public_key = ec.derive_private_key(private_value, ec.SECP256R1()).public_key()
    point = public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return ConventionalECPoint(point, point, public_key)


def _configure_ecdh_runtime(
    monkeypatch: pytest.MonkeyPatch,
    read_value: Callable[[int], dict[int, Any]],
    *,
    keypairs: tuple[tuple[int, int], ...],
) -> tuple[list[int], list[int]]:
    """Install deterministic ECDH handles and return read/cleanup traces."""
    generated = iter(keypairs)
    derived = iter([101, 102])
    read_handles: list[int] = []
    destroyed: list[int] = []
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_generate_ec_keypair",
        lambda _self, _rs: next(generated),
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_extract_ec_point",
        lambda _self, _rs, _handle: _synthetic_point(),
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_derive_shared",
        lambda _self, *_args: next(derived),
    )

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        read_handles.append(handle)
        return read_value(handle)

    monkeypatch.setattr(test_kdf, "read_attributes", _read)
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    return read_handles, destroyed


def _configure_sha3_runtime(
    monkeypatch: pytest.MonkeyPatch,
    read_value: Callable[[int], dict[int, Any]],
) -> tuple[list[int], list[int]]:
    """Install deterministic SHA3 derive handles and return read/cleanup traces."""
    derived = iter([34, 35])
    read_handles: list[int] = []
    destroyed: list[int] = []
    monkeypatch.setattr(test_kdf, "_import_generic_secret", lambda *_a, **_k: 33)
    monkeypatch.setattr(
        test_kdf,
        "derive_key",
        lambda _raw, _sh, _base, _ckm, **_k: next(derived),
    )

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        read_handles.append(handle)
        return read_value(handle)

    monkeypatch.setattr(test_kdf, "read_attributes", _read)
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    return read_handles, destroyed


def test_hkdf_missing_derived_value_records_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_kdf, "_import_generic_secret", lambda *_a, **_k: 11)
    monkeypatch.setattr(test_kdf, "derive_key", lambda *_a, **_k: 12)
    monkeypatch.setattr(test_kdf, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    test_kdf.TestHKDF().test_hkdf_derive_basic(_session())

    assert destroyed == [11, 12]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"


def test_ecdh_shared_secret_reads_both_missing_outputs_before_gating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 21), (12, 22)])
    derived = iter([101, 102])
    read_handles: list[int] = []
    destroyed: list[int] = []

    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_generate_ec_keypair",
        lambda _self, _rs: next(keypairs),
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_extract_ec_point",
        lambda _self, _rs, handle: _synthetic_point(7 if handle == 11 else 8),
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_derive_shared",
        lambda _self, *_args: next(derived),
    )

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        read_handles.append(handle)
        return {}

    monkeypatch.setattr(test_kdf, "read_attributes", _read)
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    test_kdf.TestECDHDerive().test_ecdh_shared_secret_agreement(_session())

    assert read_handles == [101, 102]
    assert destroyed == [11, 21, 12, 22, 101, 102]
    assert len(C.get_records()) == 2
    assert all(record.reason == "not_operational" for record in C.get_records())


def test_ecdh_shared_missing_outputs_drop_stale_active_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    _read_handles, _destroyed = _configure_ecdh_runtime(
        monkeypatch,
        lambda _handle: {},
        keypairs=((11, 21), (12, 22)),
    )

    test_kdf.TestECDHDerive().test_ecdh_shared_secret_agreement(_session())

    records = C.get_records()
    assert len(records) == 2
    assert all(record.mechanism is None for record in records)
    assert all(record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue" for record in records)


def test_ecdh_shared_malformed_outputs_drop_stale_active_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    _read_handles, _destroyed = _configure_ecdh_runtime(
        monkeypatch,
        lambda _handle: {CKA_VALUE: "malformed"},
        keypairs=((11, 21), (12, 22)),
    )

    with pytest.raises(pytest.fail.Exception, match="non-empty bytes"):
        test_kdf.TestECDHDerive().test_ecdh_shared_secret_agreement(_session())

    records = C.get_records()
    assert len(records) == 2
    assert all(record.mechanism is None for record in records)
    assert all(record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue" for record in records)


def test_ecdh_keypair_independence_cleans_up_when_second_generation_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 21)])
    destroyed: list[int] = []

    def _generate(_self: Any, _rs: Any) -> tuple[int, int]:
        try:
            return next(generated)
        except StopIteration:
            raise RuntimeError("second keypair generation failed") from None

    monkeypatch.setattr(test_kdf.TestECDHDerive, "_generate_ec_keypair", _generate)
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(RuntimeError, match="second keypair"):
        test_kdf.TestECDHDerive().test_ecdh_keypair_independence(_session())

    assert destroyed == [11, 21]


def test_ecdh_shared_secret_cleans_up_when_second_generation_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 21)])
    destroyed: list[int] = []

    def _generate(_self: Any, _rs: Any) -> tuple[int, int]:
        try:
            return next(generated)
        except StopIteration:
            raise RuntimeError("second keypair generation failed") from None

    monkeypatch.setattr(test_kdf.TestECDHDerive, "_generate_ec_keypair", _generate)
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(RuntimeError, match="second keypair"):
        test_kdf.TestECDHDerive().test_ecdh_shared_secret_agreement(_session())

    assert destroyed == [11, 21]


@pytest.mark.parametrize("failed_generation", [2, 3])
def test_ecdh_different_peers_cleans_up_partial_generations(
    monkeypatch: pytest.MonkeyPatch,
    failed_generation: int,
) -> None:
    generated = iter([(11, 21), (12, 22)])
    destroyed: list[int] = []
    calls = 0

    def _generate(_self: Any, _rs: Any) -> tuple[int, int]:
        nonlocal calls
        calls += 1
        if calls == failed_generation:
            raise RuntimeError(f"generation {failed_generation} failed")
        return next(generated)

    monkeypatch.setattr(test_kdf.TestECDHDerive, "_generate_ec_keypair", _generate)
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(RuntimeError, match=f"generation {failed_generation}"):
        test_kdf.TestECDHDerive().test_ecdh_different_peers_different_secrets(_session())

    expected = [11, 21] if failed_generation == 2 else [11, 21, 12, 22]
    assert destroyed == expected


def test_ecdh_different_peers_continues_pair_read_on_missing_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 21), (12, 22), (13, 23)])
    derived = iter([101, 102])
    read_handles: list[int] = []
    destroyed: list[int] = []

    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_generate_ec_keypair",
        lambda _self, _rs: next(keypairs),
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_extract_ec_point",
        lambda _self, _rs, _handle: _synthetic_point(),
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_derive_shared",
        lambda _self, *_args: next(derived),
    )

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        read_handles.append(handle)
        return {} if handle == 101 else {CKA_VALUE: b"value"}

    monkeypatch.setattr(test_kdf, "read_attributes", _read)
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    test_kdf.TestECDHDerive().test_ecdh_different_peers_different_secrets(_session())

    assert read_handles == [101, 102]
    assert destroyed == [11, 21, 12, 22, 13, 23, 101, 102]
    assert [record.reason for record in C.get_records()] == ["not_operational"]


def test_ecdh_shared_mismatch_remains_a_hard_crypto_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 21), (12, 22)])
    derived = iter([101, 102])
    destroyed: list[int] = []

    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_generate_ec_keypair",
        lambda _self, _rs: next(keypairs),
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_extract_ec_point",
        lambda _self, _rs, handle: _synthetic_point(7 if handle == 11 else 8),
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_derive_shared",
        lambda _self, *_args: next(derived),
    )
    monkeypatch.setattr(
        test_kdf,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {CKA_VALUE: b"a" if handle == 101 else b"b"},
    )
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(pytest.fail.Exception, match="does not match"):
        test_kdf.TestECDHDerive().test_ecdh_shared_secret_agreement(_session())

    assert destroyed == [11, 21, 12, 22, 101, 102]
    assert [record.reason for record in C.get_records()] == ["wrong_result"]


def test_ecdh_shared_validates_both_present_legs_before_relation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty first output is a metadata finding, not a crypto comparison."""
    read_handles, destroyed = _configure_ecdh_runtime(
        monkeypatch,
        lambda handle: {CKA_VALUE: b"" if handle == 101 else b"peer-b-output"},
        keypairs=((11, 21), (12, 22)),
    )

    with pytest.raises(pytest.fail.Exception, match="non-empty bytes"):
        test_kdf.TestECDHDerive().test_ecdh_shared_secret_agreement(_session())

    assert read_handles == [101, 102]
    assert destroyed == [11, 21, 12, 22, 101, 102]
    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.detail == {
        "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
        "leg": "ab",
        "expected_shape": "non-empty bytes",
        "actual_type": "bytes",
        "actual_length": 0,
        "producer_operation": "C_DeriveKey",
        "producer_mechanism": "CKM_ECDH1_DERIVE",
    }


def test_ecdh_shared_reports_malformed_sibling_after_missing_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing leg must not hide a malformed present sibling."""
    read_handles, destroyed = _configure_ecdh_runtime(
        monkeypatch,
        lambda handle: {} if handle == 101 else {CKA_VALUE: "not-bytes"},
        keypairs=((11, 21), (12, 22)),
    )

    with pytest.raises(pytest.fail.Exception, match="non-empty bytes"):
        test_kdf.TestECDHDerive().test_ecdh_shared_secret_agreement(_session())

    assert read_handles == [101, 102]
    assert destroyed == [11, 21, 12, 22, 101, 102]
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "wrong_result"]
    malformed = next(record for record in records if record.reason == "wrong_result")
    assert malformed.kind == "metadata"
    assert malformed.operation == "C_GetAttributeValue"
    assert malformed.mechanism is None
    assert malformed.detail == {
        "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
        "leg": "ba",
        "expected_shape": "non-empty bytes",
        "actual_type": "str",
        "actual_length": 9,
        "producer_operation": "C_DeriveKey",
        "producer_mechanism": "CKM_ECDH1_DERIVE",
    }


def test_ecdh_shared_reports_malformed_first_and_missing_second(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reverse missing/malformed order retains both independent observations."""
    read_handles, destroyed = _configure_ecdh_runtime(
        monkeypatch,
        lambda handle: {CKA_VALUE: "not-bytes"} if handle == 101 else {},
        keypairs=((11, 21), (12, 22)),
    )

    with pytest.raises(pytest.fail.Exception, match="non-empty bytes"):
        test_kdf.TestECDHDerive().test_ecdh_shared_secret_agreement(_session())

    assert read_handles == [101, 102]
    assert destroyed == [11, 21, 12, 22, 101, 102]
    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "not_operational"]
    assert all(record.kind == "metadata" for record in records)
    assert not any(record.kind == "crypto" for record in records)


def test_ecdh_shared_retains_two_malformed_present_legs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both malformed outputs are retained before the first hard outcome is raised."""
    _read_handles, destroyed = _configure_ecdh_runtime(
        monkeypatch,
        lambda _handle: {CKA_VALUE: "first-malformed"},
        keypairs=((11, 21), (12, 22)),
    )

    with pytest.raises(pytest.fail.Exception, match="non-empty bytes"):
        test_kdf.TestECDHDerive().test_ecdh_shared_secret_agreement(_session())

    assert destroyed == [11, 21, 12, 22, 101, 102]
    records = C.get_records()
    assert len(records) == 2
    assert [record.reason for record in records] == ["wrong_result", "wrong_result"]
    assert [record.detail["leg"] for record in records if record.detail is not None] == [
        "ab",
        "ba",
    ]
    assert all(record.kind == "metadata" for record in records)
    assert not any(record.kind == "crypto" for record in records)


def test_ecdh_shared_second_reader_error_propagates_after_first_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reader error is not converted into a missing-output or relation result."""

    def _read(handle: int) -> dict[int, Any]:
        if handle == 101:
            return {}
        raise RuntimeError("second ECDH output read failed")

    read_handles, destroyed = _configure_ecdh_runtime(
        monkeypatch,
        _read,
        keypairs=((11, 21), (12, 22)),
    )

    with pytest.raises(RuntimeError, match="second ECDH output read failed"):
        test_kdf.TestECDHDerive().test_ecdh_shared_secret_agreement(_session())

    assert read_handles == [101, 102]
    assert destroyed == [11, 21, 12, 22, 101, 102]
    assert [record.reason for record in C.get_records()] == ["not_operational"]


def test_ecdh_shared_first_malformed_evidence_survives_second_reader_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed first leg remains recorded when the second read raises."""

    def _read(handle: int) -> dict[int, Any]:
        if handle == 101:
            return {CKA_VALUE: "malformed-first"}
        raise RuntimeError("second ECDH output read failed")

    read_handles, destroyed = _configure_ecdh_runtime(
        monkeypatch,
        _read,
        keypairs=((11, 21), (12, 22)),
    )

    with pytest.raises(RuntimeError, match="second ECDH output read failed"):
        test_kdf.TestECDHDerive().test_ecdh_shared_secret_agreement(_session())

    assert read_handles == [101, 102]
    assert destroyed == [11, 21, 12, 22, 101, 102]
    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result"]
    assert records[0].detail is not None
    assert records[0].detail["leg"] == "ab"


def test_ecdh_different_peers_equal_outputs_are_structured_crypto_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The different-peer relation must remain a classified crypto finding."""
    peer_points: list[ConventionalECPoint] = []
    keypairs = iter([(11, 21), (12, 22), (13, 23)])
    derived = iter([101, 102])
    read_handles: list[int] = []
    destroyed: list[int] = []
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_generate_ec_keypair",
        lambda _self, _rs: next(keypairs),
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_extract_ec_point",
        lambda _self, _rs, handle: _synthetic_point(7 if handle == 12 else 8),
    )

    def _derive(_self: Any, _rs: Any, _private: int, peer: ConventionalECPoint) -> int:
        peer_points.append(peer)
        return next(derived)

    monkeypatch.setattr(test_kdf.TestECDHDerive, "_derive_shared", _derive)

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        read_handles.append(handle)
        return {CKA_VALUE: b"same-output"}

    monkeypatch.setattr(test_kdf, "read_attributes", _read)
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(pytest.fail.Exception, match="different peers"):
        test_kdf.TestECDHDerive().test_ecdh_different_peers_different_secrets(_session())

    assert read_handles == [101, 102]
    assert destroyed == [11, 21, 12, 22, 13, 23, 101, 102]
    assert len(peer_points) == 2
    assert (
        peer_points[0].public_key.public_numbers().x != peer_points[1].public_key.public_numbers().x
    )
    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_ECDH1_DERIVE"
    assert record.detail == {"relation": "different_peer_outputs", "legs": ["ab", "ac"]}


def test_ecdh_different_peers_same_x_inverse_outputs_do_not_create_crypto_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Q and -Q can share an ECDH x-coordinate, so equal outputs are not a relation failure."""
    p256_order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    point_q = _synthetic_point(7)
    point_neg_q = _synthetic_point(p256_order - 7)
    assert point_q.public_key.public_numbers().x == point_neg_q.public_key.public_numbers().x
    peer_points: list[ConventionalECPoint] = []
    keypairs = iter([(11, 21), (12, 22), (13, 23)])
    derived = iter([101, 102])
    destroyed: list[int] = []

    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_generate_ec_keypair",
        lambda _self, _rs: next(keypairs),
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_extract_ec_point",
        lambda _self, _rs, handle: point_q if handle == 12 else point_neg_q,
    )

    def _derive(_self: Any, _rs: Any, _private: int, peer: ConventionalECPoint) -> int:
        peer_points.append(peer)
        return next(derived)

    monkeypatch.setattr(test_kdf.TestECDHDerive, "_derive_shared", _derive)
    monkeypatch.setattr(
        test_kdf,
        "read_attributes",
        lambda _raw, _sh, _handle, _attrs: {CKA_VALUE: b"same-output"},
    )
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    test_kdf.TestECDHDerive().test_ecdh_different_peers_different_secrets(_session())

    assert len(peer_points) == 2
    assert (
        peer_points[0].public_key.public_numbers().x == peer_points[1].public_key.public_numbers().x
    )
    assert destroyed == [11, 21, 12, 22, 13, 23, 101, 102]
    assert C.get_records() == []


@pytest.mark.parametrize(
    ("invalid_leg", "invalid_value"),
    [("ab", b""), ("ab", "not-bytes"), ("ac", b""), ("ac", "not-bytes")],
    ids=["ab-empty", "ab-nonbytes", "ac-empty", "ac-nonbytes"],
)
def test_ecdh_different_peers_validates_invalid_leg_before_relation(
    monkeypatch: pytest.MonkeyPatch,
    invalid_leg: str,
    invalid_value: Any,
) -> None:
    """An invalid leg must not pass merely because it differs from a valid leg."""
    read_handles, destroyed = _configure_ecdh_runtime(
        monkeypatch,
        lambda handle: {
            CKA_VALUE: invalid_value if (handle == 101) == (invalid_leg == "ab") else b"valid"
        },
        keypairs=((11, 21), (12, 22), (13, 23)),
    )

    with pytest.raises(pytest.fail.Exception, match="non-empty bytes"):
        test_kdf.TestECDHDerive().test_ecdh_different_peers_different_secrets(_session())

    assert read_handles == [101, 102]
    assert destroyed == [11, 21, 12, 22, 13, 23, 101, 102]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "metadata"
    assert records[0].detail is not None
    assert records[0].detail["leg"] == invalid_leg
    assert not any(record.kind == "crypto" for record in records)


@pytest.mark.parametrize("missing_leg", ["ab", "ac"], ids=["ab-missing", "ac-missing"])
def test_ecdh_different_peers_missing_leg_retains_malformed_sibling(
    monkeypatch: pytest.MonkeyPatch,
    missing_leg: str,
) -> None:
    """Missing output does not hide a malformed sibling or emit a relation result."""
    read_handles, destroyed = _configure_ecdh_runtime(
        monkeypatch,
        lambda handle: {} if (handle == 101) == (missing_leg == "ab") else {CKA_VALUE: "malformed"},
        keypairs=((11, 21), (12, 22), (13, 23)),
    )

    with pytest.raises(pytest.fail.Exception, match="non-empty bytes"):
        test_kdf.TestECDHDerive().test_ecdh_different_peers_different_secrets(_session())

    assert read_handles == [101, 102]
    assert destroyed == [11, 21, 12, 22, 13, 23, 101, 102]
    records = C.get_records()
    assert [record.reason for record in records] == (
        ["not_operational", "wrong_result"]
        if missing_leg == "ab"
        else ["wrong_result", "not_operational"]
    )
    malformed = next(record for record in records if record.reason == "wrong_result")
    assert malformed.detail is not None
    assert malformed.detail["leg"] == ("ac" if missing_leg == "ab" else "ab")
    assert not any(record.kind == "crypto" for record in records)


def test_sha3_missing_derived_value_records_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_kdf, "_import_generic_secret", lambda *_a, **_k: 31)
    monkeypatch.setattr(test_kdf, "derive_key", lambda *_a, **_k: 32)
    monkeypatch.setattr(test_kdf, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    test_kdf.TestSHA3ShakeKeyDerive().test_derive_produces_key(
        _session(), "SHA3_224_KEY_DERIVE", int(CKM_SHA3_224_KEY_DERIVE)
    )

    assert destroyed == [32, 31]
    assert [record.reason for record in C.get_records()] == ["not_operational"]


def test_sha3_missing_derived_value_drops_stale_active_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    monkeypatch.setattr(test_kdf, "_import_generic_secret", lambda *_a, **_k: 31)
    monkeypatch.setattr(test_kdf, "derive_key", lambda *_a, **_k: 32)
    monkeypatch.setattr(test_kdf, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(test_kdf, "destroy_quietly", lambda *_a: None)

    test_kdf.TestSHA3ShakeKeyDerive().test_derive_produces_key(
        _session(), "SHA3_224_KEY_DERIVE", int(CKM_SHA3_224_KEY_DERIVE)
    )

    record = C.get_records()[0]
    assert record.mechanism is None
    assert record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"


@pytest.mark.parametrize("value", [None, b"short"])
def test_sha3_present_invalid_output_remains_a_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    monkeypatch.setattr(test_kdf, "_import_generic_secret", lambda *_a, **_k: 33)
    monkeypatch.setattr(test_kdf, "derive_key", lambda *_a, **_k: 34)
    monkeypatch.setattr(test_kdf, "read_attributes", lambda *_a, **_k: {CKA_VALUE: value})
    monkeypatch.setattr(test_kdf, "destroy_quietly", lambda *_a: None)

    with pytest.raises(AssertionError):
        test_kdf.TestSHA3ShakeKeyDerive().test_derive_produces_key(
            _session(), "SHA3_224_KEY_DERIVE", int(CKM_SHA3_224_KEY_DERIVE)
        )

    assert C.get_records() == []


@pytest.mark.parametrize(
    ("first", "second", "first_type", "first_length"),
    [
        (b"short", b"short", "bytes", 5),
        (None, b"\x00" * 16, "NoneType", None),
    ],
)
def test_sha3_deterministic_validates_each_present_16_byte_output(
    monkeypatch: pytest.MonkeyPatch,
    first: Any,
    second: Any,
    first_type: str,
    first_length: int | None,
) -> None:
    """Malformed equal outputs must not make determinism pass vacuously."""
    read_handles, destroyed = _configure_sha3_runtime(
        monkeypatch,
        lambda handle: {CKA_VALUE: first if handle == 34 else second},
    )

    with pytest.raises(pytest.fail.Exception, match="16-byte bytes"):
        test_kdf.TestSHA3ShakeKeyDerive().test_derive_deterministic(
            _session(), "SHA3_224_KEY_DERIVE", int(CKM_SHA3_224_KEY_DERIVE)
        )

    records = C.get_records()
    expected_bad_legs = ["output_1"]
    if not isinstance(second, bytes) or len(second) != 16:
        expected_bad_legs.append("output_2")
    actual_bad_legs: list[Any] = []
    for record in records:
        assert record.detail is not None
        actual_bad_legs.append(record.detail["leg"])
    assert read_handles == [34, 35]
    assert actual_bad_legs == expected_bad_legs
    assert destroyed == [34, 35, 33]
    first_record = records[0]
    assert first_record.reason == "wrong_result"
    assert first_record.kind == "metadata"
    assert first_record.operation == "C_GetAttributeValue"
    assert first_record.mechanism is None
    assert first_record.detail == {
        "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
        "leg": "output_1",
        "expected_shape": "16-byte bytes",
        "actual_type": first_type,
        "actual_length": first_length,
        "producer_operation": "C_DeriveKey",
        "producer_mechanism": "CKM_SHA3_224_KEY_DERIVE",
    }


def test_sha3_malformed_outputs_drop_stale_active_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    _read_handles, _destroyed = _configure_sha3_runtime(
        monkeypatch,
        lambda _handle: {CKA_VALUE: "malformed"},
    )

    with pytest.raises(pytest.fail.Exception, match="16-byte bytes"):
        test_kdf.TestSHA3ShakeKeyDerive().test_derive_deterministic(
            _session(), "SHA3_224_KEY_DERIVE", int(CKM_SHA3_224_KEY_DERIVE)
        )

    records = C.get_records()
    assert len(records) == 2
    assert all(record.mechanism is None for record in records)
    assert all(record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue" for record in records)


@pytest.mark.parametrize("missing_handle", [34, 35], ids=["first-missing", "second-missing"])
def test_sha3_deterministic_missing_leg_retains_malformed_sibling(
    monkeypatch: pytest.MonkeyPatch,
    missing_handle: int,
) -> None:
    """A missing determinism leg does not hide malformed present output."""
    read_handles, destroyed = _configure_sha3_runtime(
        monkeypatch,
        lambda handle: {} if handle == missing_handle else {CKA_VALUE: b"short"},
    )

    with pytest.raises(pytest.fail.Exception, match="16-byte bytes"):
        test_kdf.TestSHA3ShakeKeyDerive().test_derive_deterministic(
            _session(), "SHA3_224_KEY_DERIVE", int(CKM_SHA3_224_KEY_DERIVE)
        )

    assert read_handles == [34, 35]
    assert destroyed == [34, 35, 33]
    records = C.get_records()
    assert [record.reason for record in records] == (
        ["not_operational", "wrong_result"]
        if missing_handle == 34
        else ["wrong_result", "not_operational"]
    )
    malformed = next(record for record in records if record.reason == "wrong_result")
    assert malformed.detail is not None
    assert malformed.detail["leg"] == ("output_2" if missing_handle == 34 else "output_1")
    assert not any(record.kind == "crypto" for record in records)


def test_sha3_deterministic_second_reader_error_propagates_after_first_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second read error remains a harness/provider error, with exact cleanup."""

    def _read(handle: int) -> dict[int, Any]:
        if handle == 34:
            return {}
        raise RuntimeError("second SHA3 output read failed")

    read_handles, destroyed = _configure_sha3_runtime(
        monkeypatch,
        _read,
    )

    with pytest.raises(RuntimeError, match="second SHA3 output read failed"):
        test_kdf.TestSHA3ShakeKeyDerive().test_derive_deterministic(
            _session(), "SHA3_224_KEY_DERIVE", int(CKM_SHA3_224_KEY_DERIVE)
        )

    assert read_handles == [34, 35]
    assert destroyed == [34, 35, 33]
    assert [record.reason for record in C.get_records()] == ["not_operational"]


def test_sha3_deterministic_first_malformed_evidence_survives_second_reader_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed first leg remains recorded when the second read raises."""

    def _read(handle: int) -> dict[int, Any]:
        if handle == 34:
            return {CKA_VALUE: "malformed-first"}
        raise RuntimeError("second SHA3 output read failed")

    read_handles, destroyed = _configure_sha3_runtime(monkeypatch, _read)

    with pytest.raises(RuntimeError, match="second SHA3 output read failed"):
        test_kdf.TestSHA3ShakeKeyDerive().test_derive_deterministic(
            _session(), "SHA3_224_KEY_DERIVE", int(CKM_SHA3_224_KEY_DERIVE)
        )

    assert read_handles == [34, 35]
    assert destroyed == [34, 35, 33]
    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result"]
    assert records[0].detail is not None
    assert records[0].detail["leg"] == "output_1"


def test_ecdh_extract_delegates_to_curve_aware_export_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b"\x04" + b"\x01" * 64
    calls: list[tuple[int, str]] = []

    def _read(_rs: Any, handle: int, curve: ec.EllipticCurve, *, label: str) -> ConventionalECPoint:
        calls.append((handle, curve.name + ":" + label))
        public_key = ec.derive_private_key(7, ec.SECP256R1()).public_key()
        return ConventionalECPoint(expected, expected, public_key)

    monkeypatch.setattr(test_kdf, "read_conventional_ec_point_or_xfail", _read)
    monkeypatch.setattr(
        test_kdf,
        "read_attributes",
        lambda *_a, **_k: {CKA_EC_POINT: b"\x04\x41" + expected},
    )

    point = test_kdf.TestECDHDerive()._extract_ec_point(_session(), 41)

    assert point.sec1_bytes == expected
    assert calls == [(41, "secp256r1:ECDH P-256 public key")]


@pytest.mark.parametrize("wrapped", [False, True], ids=["raw", "wrapped"])
def test_ecdh_extract_accepts_raw_and_wrapped_p256_points(
    monkeypatch: pytest.MonkeyPatch,
    wrapped: bool,
) -> None:
    curve = ec.SECP256R1()
    raw = (
        ec.derive_private_key(7, curve)
        .public_key()
        .public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )
    data = b"\x04" + bytes([len(raw)]) + raw if wrapped else raw

    def _read(*_args: Any, **_kwargs: Any) -> dict[int, bytes]:
        return {CKA_EC_POINT: data}

    monkeypatch.setattr(test_kdf, "read_attributes", _read)
    monkeypatch.setattr(_ec_export, "read_attributes", _read)

    assert test_kdf.TestECDHDerive()._extract_ec_point(_session(), 42).sec1_bytes == raw


def test_ecdh_extract_malformed_point_is_structured_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _read(*_args: Any, **_kwargs: Any) -> dict[int, bytes]:
        return {CKA_EC_POINT: b"\x04\x03\x04\x01"}

    monkeypatch.setattr(test_kdf, "read_attributes", _read)
    monkeypatch.setattr(_ec_export, "read_attributes", _read)

    with pytest.raises(pytest.xfail.Exception, match="canonical DER"):
        test_kdf.TestECDHDerive()._extract_ec_point(_session(), 43)

    assert [record.reason for record in C.get_records()] == ["not_operational"]


def test_ecdh_extract_off_curve_point_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    curve = ec.SECP256R1()
    raw = bytearray(
        ec.derive_private_key(8, curve)
        .public_key()
        .public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )
    raw[-1] ^= 1

    def _read(*_args: Any, **_kwargs: Any) -> dict[int, bytes]:
        return {CKA_EC_POINT: bytes(raw)}

    monkeypatch.setattr(test_kdf, "read_attributes", _read)
    monkeypatch.setattr(_ec_export, "read_attributes", _read)

    with pytest.raises(pytest.fail.Exception, match="off-curve"):
        test_kdf.TestECDHDerive()._extract_ec_point(_session(), 44)

    assert [record.reason for record in C.get_records()] == ["wrong_result"]


def test_kdf_source_analyzer_is_clean() -> None:
    assert analyze_file("src/pkcs11_check/testcases/test_kdf.py") == []
