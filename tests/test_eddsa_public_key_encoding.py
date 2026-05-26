"""Regression tests for adaptive EdDSA public-key encoding selection."""

from __future__ import annotations

from typing import Any

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases import _eddsa_public_key as eddsa_keys


def setup_function() -> None:
    eddsa_keys.clear_eddsa_public_key_encoding_cache()


def test_select_eddsa_public_key_encoding_prefers_raw_when_valid_signature_verifies(
    monkeypatch: Any,
) -> None:
    imported_points: list[bytes] = []
    destroyed: list[int] = []

    def fake_import_ec_public_key(
        raw: object,
        session: int,
        *,
        ec_params: bytes,
        ec_point: bytes,
        key_type: int,
        attrs: dict[int, Any],
    ) -> int:
        imported_points.append(ec_point)
        return 10

    monkeypatch.setattr(eddsa_keys, "import_ec_public_key", fake_import_ec_public_key)
    monkeypatch.setattr(eddsa_keys, "verify_single", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        eddsa_keys,
        "destroy_quietly",
        lambda _raw, _session, key: destroyed.append(key),
    )

    encoding = eddsa_keys.select_eddsa_public_key_encoding(
        object(),
        1,
        ec_params=b"params",
        public_key=b"Q" * 32,
        message=b"message",
        signature=b"S" * 64,
    )

    assert encoding == "raw"
    assert imported_points == [b"Q" * 32]
    assert destroyed == [10]


def test_select_eddsa_public_key_encoding_falls_back_to_der_when_raw_does_not_verify(
    monkeypatch: Any,
) -> None:
    imported_points: list[bytes] = []
    destroyed: list[int] = []

    def fake_import_ec_public_key(
        raw: object,
        session: int,
        *,
        ec_params: bytes,
        ec_point: bytes,
        key_type: int,
        attrs: dict[int, Any],
    ) -> int:
        imported_points.append(ec_point)
        return len(imported_points)

    def fake_verify_single(
        raw: object,
        session: int,
        key: int,
        mechanism: int,
        data: bytes,
        signature: bytes,
        *,
        mech_param: object | None = None,
    ) -> bool:
        return key == 3

    monkeypatch.setattr(eddsa_keys, "import_ec_public_key", fake_import_ec_public_key)
    monkeypatch.setattr(eddsa_keys, "verify_single", fake_verify_single)
    monkeypatch.setattr(
        eddsa_keys,
        "destroy_quietly",
        lambda _raw, _session, key: destroyed.append(key),
    )

    encoding = eddsa_keys.select_eddsa_public_key_encoding(
        object(),
        1,
        ec_params=b"params",
        public_key=b"Q" * 32,
        message=b"message",
        signature=b"S" * 64,
    )

    assert encoding == "der"
    assert imported_points == [b"Q" * 32, b"Q" * 32, b"\x04\x20" + b"Q" * 32]
    assert destroyed == [1, 2, 3]


def test_verify_eddsa_signature_uses_cached_null_mechanism_params(monkeypatch: Any) -> None:
    raw = object()
    mech_params: list[object | None] = []

    def fake_verify_single(
        raw: object,
        session: int,
        key: int,
        mechanism: int,
        data: bytes,
        signature: bytes,
        *,
        mech_param: object | None = None,
    ) -> bool:
        mech_params.append(mech_param)
        return True

    monkeypatch.setattr(eddsa_keys, "verify_single", fake_verify_single)
    eddsa_keys.remember_eddsa_public_key_profile(raw, b"params", "raw", "null")

    verified = eddsa_keys.verify_eddsa_signature_with_supported_params(
        raw,
        1,
        public_key_handle=7,
        ec_params=b"params",
        message=b"message",
        signature=b"S" * 64,
    )

    assert verified is True
    assert mech_params
    assert mech_params[0] is not None


def test_select_eddsa_public_key_encoding_falls_back_to_explicit_params(
    monkeypatch: Any,
) -> None:
    mech_params: list[object | None] = []

    def fake_import_ec_public_key(
        raw: object,
        session: int,
        *,
        ec_params: bytes,
        ec_point: bytes,
        key_type: int,
        attrs: dict[int, Any],
    ) -> int:
        return 10

    def fake_verify_single(
        raw: object,
        session: int,
        key: int,
        mechanism: int,
        data: bytes,
        signature: bytes,
        *,
        mech_param: object | None = None,
    ) -> bool:
        mech_params.append(mech_param)
        if mech_param is not None:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
                int(CKR_FUNCTION_NOT_SUPPORTED),
            )
        return True

    raw = object()
    monkeypatch.setattr(eddsa_keys, "import_ec_public_key", fake_import_ec_public_key)
    monkeypatch.setattr(eddsa_keys, "verify_single", fake_verify_single)
    monkeypatch.setattr(eddsa_keys, "destroy_quietly", lambda *_args: None)

    encoding = eddsa_keys.select_eddsa_public_key_encoding(
        raw,
        1,
        ec_params=b"params",
        public_key=b"Q" * 32,
        message=b"message",
        signature=b"S" * 64,
    )

    assert encoding == "raw"
    assert len(mech_params) == 2
    assert mech_params[0] is not None
    assert mech_params[1] is None


def test_import_eddsa_public_key_uses_cached_der_encoding(monkeypatch: Any) -> None:
    raw = object()
    imported_points: list[bytes] = []

    def fake_import_ec_public_key(
        raw: object,
        session: int,
        *,
        ec_params: bytes,
        ec_point: bytes,
        key_type: int,
        attrs: dict[int, Any],
    ) -> int:
        imported_points.append(ec_point)
        return 7

    monkeypatch.setattr(eddsa_keys, "import_ec_public_key", fake_import_ec_public_key)
    eddsa_keys.remember_eddsa_public_key_encoding(raw, b"params", "der")

    handle = eddsa_keys.import_eddsa_public_key_with_supported_encoding(
        raw,
        1,
        ec_params=b"params",
        public_key=b"R" * 32,
        attrs={},
    )

    assert handle == 7
    assert imported_points == [b"\x04\x20" + b"R" * 32]
