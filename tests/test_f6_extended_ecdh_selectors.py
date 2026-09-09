"""Regression tests for mechanism-specific extended ECDH point selection."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check.raw.types_std import (
    CKA_KEY_TYPE,
    CKA_VALUE,
    CKF_EC_COMPRESS,
    CKF_EC_UNCOMPRESS,
    CKK_AES,
    CKM_ECDH1_COFACTOR_DERIVE,
    CKM_ECDH1_DERIVE,
    CKM_ECMQV_DERIVE,
)
from pkcs11_check.testcases import test_ecdh_extended as extended
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE
from pkcs11_check.testcases._ec_export import ConventionalECPoint


def _point(form: serialization.PublicFormat) -> ConventionalECPoint:
    public_key = ec.derive_private_key(23, ec.SECP256R1()).public_key()
    sec1 = public_key.public_bytes(serialization.Encoding.X962, form)
    return ConventionalECPoint(sec1, sec1, public_key)


def _session(flags: dict[tuple[int, int], bool]) -> Any:
    calls: list[tuple[int, int]] = []

    def has_flag(mechanism: Any, flag: Any) -> bool:
        call = (int(mechanism), int(flag))
        calls.append(call)
        return flags.get(call, False)

    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
        has_mechanism_flag=has_flag,
        flag_calls=calls,
    )


@pytest.mark.parametrize(
    ("mechanism", "supports_compressed", "supports_uncompressed"),
    [
        (CKM_ECDH1_DERIVE, False, False),
        (CKM_ECDH1_DERIVE, False, True),
        (CKM_ECDH1_DERIVE, True, False),
        (CKM_ECDH1_DERIVE, True, True),
        (CKM_ECDH1_COFACTOR_DERIVE, False, False),
        (CKM_ECDH1_COFACTOR_DERIVE, False, True),
        (CKM_ECDH1_COFACTOR_DERIVE, True, False),
        (CKM_ECDH1_COFACTOR_DERIVE, True, True),
    ],
    ids=[
        "standard-neither",
        "standard-uncompressed-only",
        "standard-compressed-only",
        "standard-both",
        "cofactor-neither",
        "cofactor-uncompressed-only",
        "cofactor-compressed-only",
        "cofactor-both",
    ],
)
@pytest.mark.parametrize(
    "source_form",
    [
        serialization.PublicFormat.UncompressedPoint,
        serialization.PublicFormat.CompressedPoint,
    ],
    ids=["provider-uncompressed", "provider-compressed"],
)
def test_extended_ecdh_selects_each_target_mechanisms_wire_form(
    monkeypatch: pytest.MonkeyPatch,
    mechanism: int,
    supports_compressed: bool,
    supports_uncompressed: bool,
    source_form: serialization.PublicFormat,
) -> None:
    """Standard and cofactor derive query and honor their own mechanism flags."""
    provider_point = _point(source_form)
    rs = _session(
        {
            (int(mechanism), int(CKF_EC_COMPRESS)): supports_compressed,
            (int(mechanism), int(CKF_EC_UNCOMPRESS)): supports_uncompressed,
        }
    )
    monkeypatch.setattr(
        extended,
        "read_conventional_ec_point_or_xfail",
        lambda *_a, **_k: provider_point,
    )

    selected = extended._p256_point(rs, 7, mechanism=mechanism)
    source_is_compressed = source_form is serialization.PublicFormat.CompressedPoint
    current_supported = supports_compressed if source_is_compressed else supports_uncompressed
    expected_form = source_form
    if supports_compressed != supports_uncompressed and not current_supported:
        expected_form = (
            serialization.PublicFormat.CompressedPoint
            if supports_compressed
            else serialization.PublicFormat.UncompressedPoint
        )
    expected = provider_point.public_key.public_bytes(serialization.Encoding.X962, expected_form)

    assert selected == expected
    assert rs.flag_calls == [
        (int(mechanism), int(CKF_EC_COMPRESS)),
        (int(mechanism), int(CKF_EC_UNCOMPRESS)),
    ]


def test_cofactor_shared_agreement_uses_cofactor_wire_form(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both cofactor peers use the cofactor mechanism's selected representation."""
    provider_point = _point(serialization.PublicFormat.UncompressedPoint)
    rs = _session(
        {
            (int(CKM_ECDH1_COFACTOR_DERIVE), int(CKF_EC_COMPRESS)): True,
            (int(CKM_ECDH1_COFACTOR_DERIVE), int(CKF_EC_UNCOMPRESS)): False,
        }
    )
    monkeypatch.setattr(extended, "_gen_ec_pairs", lambda *_args: [(11, 12), (13, 14)])
    monkeypatch.setattr(
        extended,
        "read_conventional_ec_point_or_xfail",
        lambda *_args, **_kwargs: provider_point,
    )
    derive_calls: list[tuple[int, bytes, int]] = []

    def derive(_rs: Any, private: int, peer: bytes, mechanism: int, **_kwargs: Any) -> int:
        derive_calls.append((private, peer, mechanism))
        return 20 + len(derive_calls)

    monkeypatch.setattr(extended, "_ecdh_derive", derive)
    monkeypatch.setattr(extended, "_read_value", lambda *_args, **_kwargs: b"s" * 32)
    monkeypatch.setattr(extended, "destroy_quietly", lambda *_args: None)

    extended.TestECDH1CofactorDerive().test_cofactor_derive_shared_secret(rs)

    compressed = provider_point.public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )
    assert derive_calls == [
        (12, compressed, CKM_ECDH1_COFACTOR_DERIVE),
        (14, compressed, CKM_ECDH1_COFACTOR_DERIVE),
    ]
    assert rs.flag_calls == [
        (int(CKM_ECDH1_COFACTOR_DERIVE), int(CKF_EC_COMPRESS)),
        (int(CKM_ECDH1_COFACTOR_DERIVE), int(CKF_EC_UNCOMPRESS)),
        (int(CKM_ECDH1_COFACTOR_DERIVE), int(CKF_EC_COMPRESS)),
        (int(CKM_ECDH1_COFACTOR_DERIVE), int(CKF_EC_UNCOMPRESS)),
    ]


def test_standard_and_cofactor_comparison_selects_each_mechanism_independently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The comparison does not reuse standard flags for the cofactor operation."""
    provider_point = _point(serialization.PublicFormat.UncompressedPoint)
    rs = _session(
        {
            (int(CKM_ECDH1_DERIVE), int(CKF_EC_COMPRESS)): True,
            (int(CKM_ECDH1_DERIVE), int(CKF_EC_UNCOMPRESS)): False,
            (int(CKM_ECDH1_COFACTOR_DERIVE), int(CKF_EC_COMPRESS)): False,
            (int(CKM_ECDH1_COFACTOR_DERIVE), int(CKF_EC_UNCOMPRESS)): True,
        }
    )
    monkeypatch.setattr(extended, "_gen_ec_pairs", lambda *_args: [(11, 12), (13, 14)])
    monkeypatch.setattr(
        extended,
        "read_conventional_ec_point_or_xfail",
        lambda *_args, **_kwargs: provider_point,
    )
    derive_calls: list[tuple[int, bytes, int]] = []

    def derive(_rs: Any, private: int, peer: bytes, mechanism: int, **_kwargs: Any) -> int:
        derive_calls.append((private, peer, mechanism))
        return 20 + len(derive_calls)

    monkeypatch.setattr(extended, "_ecdh_derive", derive)
    monkeypatch.setattr(extended, "_read_value", lambda *_args, **_kwargs: b"s" * 32)
    monkeypatch.setattr(extended, "destroy_quietly", lambda *_args: None)

    extended.TestECDH1CofactorDerive().test_cofactor_matches_standard_ecdh(rs)

    compressed = provider_point.public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )
    uncompressed = provider_point.public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    assert derive_calls == [
        (12, compressed, CKM_ECDH1_DERIVE),
        (12, uncompressed, CKM_ECDH1_COFACTOR_DERIVE),
    ]


def test_cofactor_aes_derive_uses_cofactor_wire_form(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The AES-derived-key consumer also uses cofactor mechanism flags."""
    provider_point = _point(serialization.PublicFormat.UncompressedPoint)
    rs = _session(
        {
            (int(CKM_ECDH1_DERIVE), int(CKF_EC_COMPRESS)): False,
            (int(CKM_ECDH1_DERIVE), int(CKF_EC_UNCOMPRESS)): True,
            (int(CKM_ECDH1_COFACTOR_DERIVE), int(CKF_EC_COMPRESS)): True,
            (int(CKM_ECDH1_COFACTOR_DERIVE), int(CKF_EC_UNCOMPRESS)): False,
        }
    )
    monkeypatch.setattr(extended, "_gen_ec_pairs", lambda *_args: [(11, 12), (13, 14)])
    monkeypatch.setattr(
        extended,
        "read_conventional_ec_point_or_xfail",
        lambda *_args, **_kwargs: provider_point,
    )
    derive_calls: list[tuple[int, bytes, int]] = []

    def derive(_rs: Any, private: int, peer: bytes, mechanism: int, **_kwargs: Any) -> int:
        derive_calls.append((private, peer, mechanism))
        return 20

    monkeypatch.setattr(extended, "_ecdh_derive", derive)
    monkeypatch.setattr(
        extended,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_KEY_TYPE: CKK_AES, CKA_VALUE: b"a" * 32},
    )
    monkeypatch.setattr(extended, "destroy_quietly", lambda *_args: None)

    extended.TestECDH1CofactorDerive().test_cofactor_derive_as_aes_key(rs)

    compressed = provider_point.public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )
    assert derive_calls == [
        (
            12,
            compressed,
            CKM_ECDH1_COFACTOR_DERIVE,
        )
    ]
    assert rs.flag_calls == [
        (int(CKM_ECDH1_COFACTOR_DERIVE), int(CKF_EC_COMPRESS)),
        (int(CKM_ECDH1_COFACTOR_DERIVE), int(CKF_EC_UNCOMPRESS)),
    ]


def test_ecmqv_keeps_deliberately_wrong_parameter_structure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ECMQV peer preparation may select flags, but still packs ECDH parameters."""
    provider_point = _point(serialization.PublicFormat.UncompressedPoint)
    rs = _session(
        {
            (int(CKM_ECMQV_DERIVE), int(CKF_EC_COMPRESS)): True,
            (int(CKM_ECMQV_DERIVE), int(CKF_EC_UNCOMPRESS)): False,
        }
    )
    rs.has_mechanism = lambda name: name == "ECMQV_DERIVE"
    monkeypatch.setattr(extended, "_gen_ec_pairs", lambda *_args: [(11, 12), (13, 14)])
    monkeypatch.setattr(
        extended,
        "read_conventional_ec_point_or_xfail",
        lambda *_args, **_kwargs: provider_point,
    )
    mech_calls: list[tuple[int, bytes]] = []

    def pack_mech(mechanism: int, *, kdf: int, public_data: bytes) -> object:
        del kdf
        mech_calls.append((mechanism, public_data))
        return object()

    monkeypatch.setattr(
        extended,
        "mech_ecdh",
        pack_mech,
    )
    monkeypatch.setattr(extended, "derive_key", lambda *_args, **_kwargs: 20)
    monkeypatch.setattr(extended, "_read_value", lambda *_args, **_kwargs: MISSING_ATTRIBUTE)
    monkeypatch.setattr(extended, "destroy_quietly", lambda *_args: None)

    extended.TestECMQVDerive().test_ecmqv_derive(rs)

    compressed = provider_point.public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )
    assert mech_calls == [(CKM_ECMQV_DERIVE, compressed)]
