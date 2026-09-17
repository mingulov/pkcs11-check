"""Regression tests for readback-attribution ECDH consumers in KAT/KDF/key-management tests."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKF_EC_COMPRESS, CKF_EC_UNCOMPRESS, CKM_ECDH1_DERIVE
from pkcs11_check.testcases import test_ecdh_known_answer as kat
from pkcs11_check.testcases import test_kdf as kdf
from pkcs11_check.testcases import test_keymgmt as keymgmt
from pkcs11_check.testcases._ec_export import ConventionalECPoint


@pytest.fixture(autouse=True)
def _clear_classification() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _point(
    private_value: int = 7,
    form: serialization.PublicFormat = serialization.PublicFormat.UncompressedPoint,
) -> ConventionalECPoint:
    public_key = ec.derive_private_key(private_value, ec.SECP256R1()).public_key()
    sec1 = public_key.public_bytes(serialization.Encoding.X962, form)
    return ConventionalECPoint(sec1, sec1, public_key)


def _session(flags: dict[int, bool]) -> Any:
    calls: list[tuple[int, int]] = []

    def has_flag(mechanism: Any, flag: Any) -> bool:
        calls.append((int(mechanism), int(flag)))
        return flags.get(int(flag), False)

    return SimpleNamespace(has_mechanism_flag=has_flag, flag_calls=calls)


@pytest.mark.parametrize("module", [kat, kdf, keymgmt], ids=["kat", "kdf", "keymgmt"])
@pytest.mark.parametrize(
    ("supports_compressed", "supports_uncompressed"),
    [(False, False), (False, True), (True, False), (True, True)],
    ids=["neither", "uncompressed-only", "compressed-only", "both"],
)
@pytest.mark.parametrize(
    "source_form",
    [serialization.PublicFormat.UncompressedPoint, serialization.PublicFormat.CompressedPoint],
    ids=["source-uncompressed", "source-compressed"],
)
def test_owned_ecdh_consumers_query_target_flags_and_send_exact_wire_form(
    module: Any,
    supports_compressed: bool,
    supports_uncompressed: bool,
    source_form: serialization.PublicFormat,
) -> None:
    rs = _session(
        {
            int(CKF_EC_COMPRESS): supports_compressed,
            int(CKF_EC_UNCOMPRESS): supports_uncompressed,
        }
    )
    point = _point(form=source_form)

    selected = module._select_ecdh_point_for_target(rs, point)

    expected_form = source_form
    current_compressed = source_form is serialization.PublicFormat.CompressedPoint
    current_supported = supports_compressed if current_compressed else supports_uncompressed
    if supports_compressed != supports_uncompressed and not current_supported:
        expected_form = (
            serialization.PublicFormat.CompressedPoint
            if supports_compressed
            else serialization.PublicFormat.UncompressedPoint
        )
    expected = point.public_key.public_bytes(serialization.Encoding.X962, expected_form)
    assert selected == expected
    assert rs.flag_calls == [
        (int(CKM_ECDH1_DERIVE), int(CKF_EC_COMPRESS)),
        (int(CKM_ECDH1_DERIVE), int(CKF_EC_UNCOMPRESS)),
    ]


def test_kat_uses_validated_public_key_for_compressed_software_peer() -> None:
    crypto_private = ec.derive_private_key(19, ec.SECP256R1())
    provider_point = _point(23, serialization.PublicFormat.CompressedPoint)
    expected = crypto_private.exchange(ec.ECDH(), provider_point.public_key)

    kat._assert_kat_secret(expected, crypto_private, provider_point)

    assert C.get_records() == []


def test_kat_compressed_software_peer_wire_preserves_ecdh_secret() -> None:
    software_private = ec.derive_private_key(19, ec.SECP256R1())
    provider_private = ec.derive_private_key(23, ec.SECP256R1())
    rs = _session({int(CKF_EC_COMPRESS): True, int(CKF_EC_UNCOMPRESS): False})

    software_peer = kat._local_ec_point(software_private.public_key())
    wire = kat._select_ecdh_point_for_target(rs, software_peer)
    expected_wire = software_private.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )
    assert wire == expected_wire

    peer_from_wire = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), wire)
    assert provider_private.exchange(ec.ECDH(), peer_from_wire) == provider_private.exchange(
        ec.ECDH(), software_private.public_key()
    )


def test_kat_wrong_secret_is_hard_crypto_failure_with_compressed_peer() -> None:
    crypto_private = ec.derive_private_key(19, ec.SECP256R1())
    provider_point = _point(23, serialization.PublicFormat.CompressedPoint)

    with pytest.raises(pytest.fail.Exception):
        kat._assert_kat_secret(b"wrong" * 8, crypto_private, provider_point)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "crypto"


def test_kdf_keypair_independence_uses_canonical_public_numbers_not_encoding() -> None:
    public_key = ec.derive_private_key(29, ec.SECP256R1()).public_key()
    uncompressed = public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    compressed = public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    first = ConventionalECPoint(uncompressed, uncompressed, public_key)
    second = ConventionalECPoint(compressed, compressed, public_key)

    assert kdf._canonical_ec_point_bytes(first) == kdf._canonical_ec_point_bytes(second)

    different = _point(31)
    assert kdf._canonical_ec_point_bytes(first) != kdf._canonical_ec_point_bytes(different)


def test_kdf_duplicate_public_key_is_structured_crypto_failure_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 12), (13, 14)])
    encoded = iter(
        [
            _point(29, serialization.PublicFormat.UncompressedPoint),
            _point(29, serialization.PublicFormat.CompressedPoint),
        ]
    )
    destroyed: list[int] = []

    monkeypatch.setattr(
        kdf.TestECDHDerive,
        "_generate_ec_keypair",
        lambda _self, _rs: next(generated),
    )
    monkeypatch.setattr(
        kdf.TestECDHDerive,
        "_extract_ec_point",
        lambda _self, _rs, _handle: next(encoded),
    )
    monkeypatch.setattr(
        kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "EC_KEY_PAIR_GEN",
    )

    with pytest.raises(pytest.fail.Exception):
        kdf.TestECDHDerive().test_ecdh_keypair_independence(rs)

    record = C.get_records()
    assert len(record) == 1
    assert record[0].reason == "wrong_result"
    assert record[0].outcome == "fail"
    assert record[0].kind == "crypto"
    assert record[0].operation == "C_GenerateKeyPair"
    assert record[0].mechanism == "CKM_EC_KEY_PAIR_GEN"
    assert destroyed == [11, 12, 13, 14]


def test_kat_setup_failure_preserves_cleanup_and_original_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([(11, 12)])
    destroyed: list[int] = []

    def generate(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        try:
            return next(handles)
        except StopIteration as exc:
            raise RuntimeError("second keypair failed") from exc

    monkeypatch.setattr(kat, "_gen_p256_or_skip", generate)
    monkeypatch.setattr(kat, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "ECDH1_DERIVE",
    )

    with pytest.raises(RuntimeError, match="second keypair failed"):
        kat.TestECDHKnownAnswer().test_ecdh_symmetric_agreement(rs)

    assert destroyed == [11, 12]


def test_keymgmt_setup_failure_preserves_partial_cleanup_and_original_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 12)])
    destroyed: list[int] = []

    def generate(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        try:
            return next(generated)
        except StopIteration as exc:
            raise RuntimeError("second keypair failed") from exc

    monkeypatch.setattr(keymgmt, "gen_ec_keypair_or_xfail", generate)
    monkeypatch.setattr(
        keymgmt,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in {"EC_KEY_PAIR_GEN", "ECDH1_DERIVE"},
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )

    with pytest.raises(RuntimeError, match="second keypair failed"):
        keymgmt.TestKeyDerive().test_ecdh_derive_produces_key(rs)

    assert destroyed == [11, 12]
