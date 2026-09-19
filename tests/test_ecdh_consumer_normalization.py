"""Runtime regressions for positive ECDH consumer point normalization."""

from __future__ import annotations

import ast
import inspect
from ctypes import sizeof
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import XFailed
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CKA_CLASS,
    CKA_DERIVE_TEMPLATE,
    CKA_EC_POINT,
    CKA_PRIVATE,
    CKA_VALUE,
    CKF_EC_COMPRESS,
    CKF_EC_UNCOMPRESS,
    CKM_ECDH1_COFACTOR_DERIVE,
    CKM_ECDH1_DERIVE,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_GENERAL_ERROR,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases import _ec_export
from pkcs11_check.testcases import test_mech_derive as derive_case
from pkcs11_check.testcases import test_mech_lifecycle as lifecycle_case
from pkcs11_check.testcases import test_nested_template_enforcement_extended as nested_case
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.security import test_public_session_private_creation as public_case


def _p256_point(
    private_value: int = 7,
    form: serialization.PublicFormat = serialization.PublicFormat.UncompressedPoint,
) -> bytes:
    return (
        ec.derive_private_key(private_value, ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.X962, form)
    )


def _wrap_point(point: bytes) -> bytes:
    return b"\x04" + bytes([len(point)]) + point


def _session(*, flags: dict[int, bool] | None = None, mechanisms: set[str] | None = None) -> Any:
    flag_values = flags or {}
    flag_calls: list[tuple[int, int]] = []
    advertised = mechanisms or set()

    def has_flag(mechanism: Any, flag: Any) -> bool:
        call = (int(mechanism), int(flag))
        flag_calls.append(call)
        return flag_values.get(call[1], False)

    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        flag_calls=flag_calls,
        has_mechanism=lambda name: name in advertised,
        has_mechanism_flag=has_flag,
    )
    return rs


def _install_point_reader(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
    provider_point: bytes,
    *,
    attrs: dict[int, Any] | None = None,
) -> None:
    values = {CKA_EC_POINT: provider_point, **(attrs or {})}

    def reader(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        return values

    monkeypatch.setattr(_ec_export, "read_attributes", reader)
    monkeypatch.setattr(module, "read_attributes", reader)


def _entry(mech_id: int) -> MechEntry:
    return MechEntry(
        mech_id=mech_id,
        mech_name="CKM_ECDH1_COFACTOR_DERIVE",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=None,
    )


def _capture_public_data(calls: list[bytes], kwargs: dict[str, Any]) -> object:
    calls.append(kwargs["public_data"])
    return SimpleNamespace(byref=lambda: object())


def _record_derive_call(calls: list[object]) -> int:
    calls.append(object())
    return 21


def _record_encryption(continuation: list[str]) -> bytes:
    continuation.append("encrypt")
    return b"ciphertext"


def _record_import(continuation: list[str]) -> int:
    continuation.append("import")
    return 22


def _record_reimport_decryption(continuation: list[str]) -> bytes:
    continuation.append("decrypt")
    return b"\xfe\xed\xfa\xce" * 8


def _record_decryption(continuation: list[str]) -> bytes:
    continuation.append("decrypt")
    return b"ecdh lifecycle test padded 32byt"


def _run_export_reimport(rs: Any) -> None:
    """Turn the old unrelated capability gate into a visible regression failure."""
    try:
        lifecycle_case.TestExportReimportAES().test_export_reimport_aes_roundtrip(rs)
    except pytest.skip.Exception as exc:
        pytest.fail(f"export/reimport unexpectedly skipped: {exc}")


def test_generic_derive_passes_raw_sec1_and_queries_entry_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cofactor derive unwraps canonical DER and uses flags for its entry mechanism."""
    provider_point = _wrap_point(_p256_point(form=serialization.PublicFormat.CompressedPoint))
    rs = _session(
        flags={int(CKF_EC_COMPRESS): True, int(CKF_EC_UNCOMPRESS): False},
    )
    _install_point_reader(monkeypatch, derive_case, provider_point)
    generated = iter([(11, 12), (13, 14)])
    derive_public_data: list[bytes] = []
    destroyed: list[int] = []

    monkeypatch.setattr(derive_case, "gen_ec_keypair", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(
        derive_case,
        "mech_ecdh",
        lambda *_args, **kwargs: _capture_public_data(derive_public_data, kwargs),
    )
    monkeypatch.setattr(derive_case, "derive_key", lambda *_args, **_kwargs: 21)
    monkeypatch.setattr(
        derive_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    derive_case._derive_ecdh(rs, _entry(int(CKM_ECDH1_COFACTOR_DERIVE)))

    assert derive_public_data == [_p256_point(form=serialization.PublicFormat.CompressedPoint)]
    assert rs.flag_calls == [
        (int(CKM_ECDH1_COFACTOR_DERIVE), int(CKF_EC_COMPRESS)),
        (int(CKM_ECDH1_COFACTOR_DERIVE), int(CKF_EC_UNCOMPRESS)),
    ]
    assert destroyed == [11, 12, 13, 14, 21]


def test_generic_derive_preserves_exact_raw_uncompressed_point(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exact raw uncompressed provider point is never treated as a DER wrapper."""
    provider_point = _p256_point(form=serialization.PublicFormat.UncompressedPoint)
    rs = _session(
        flags={int(CKF_EC_COMPRESS): False, int(CKF_EC_UNCOMPRESS): True},
    )
    _install_point_reader(monkeypatch, derive_case, provider_point)
    generated = iter([(11, 12), (13, 14)])
    derive_public_data: list[bytes] = []

    monkeypatch.setattr(derive_case, "gen_ec_keypair", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(
        derive_case,
        "mech_ecdh",
        lambda *_args, **kwargs: _capture_public_data(derive_public_data, kwargs),
    )
    monkeypatch.setattr(derive_case, "derive_key", lambda *_args, **_kwargs: 21)
    monkeypatch.setattr(derive_case, "destroy_quietly", lambda *_args: None)

    derive_case._derive_ecdh(rs, _entry(int(CKM_ECDH1_DERIVE)))

    assert derive_public_data == [provider_point]


def test_generic_derive_missing_point_xfails_before_derive_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed peer point blocks only derive while all generated handles clean up."""
    rs = _session(flags={int(CKF_EC_COMPRESS): True})
    _install_point_reader(monkeypatch, derive_case, b"malformed")
    generated = iter([(11, 12), (13, 14)])
    derive_calls: list[object] = []
    destroyed: list[int] = []

    monkeypatch.setattr(derive_case, "gen_ec_keypair", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(
        derive_case,
        "derive_key",
        lambda *_args, **_kwargs: _record_derive_call(derive_calls),
    )
    monkeypatch.setattr(
        derive_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(pytest.xfail.Exception):
        derive_case._derive_ecdh(rs, _entry(int(CKM_ECDH1_DERIVE)))

    assert derive_calls == []
    assert destroyed == [11, 12, 13, 14]


def test_lifecycle_uses_raw_point_for_downstream_aes_roundtrip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lifecycle derive receives normalized SEC1 and still reaches AES continuation."""
    provider_point = _wrap_point(_p256_point(form=serialization.PublicFormat.CompressedPoint))
    rs = _session(
        flags={int(CKF_EC_COMPRESS): True, int(CKF_EC_UNCOMPRESS): False},
        mechanisms={"EC_KEY_PAIR_GEN", "ECDH1_DERIVE", "AES_CBC"},
    )
    _install_point_reader(monkeypatch, lifecycle_case, provider_point)
    generated = iter([(11, 12), (13, 14)])
    derive_public_data: list[bytes] = []
    continuation: list[str] = []
    destroyed: list[int] = []

    monkeypatch.setattr(
        lifecycle_case, "gen_ec_keypair_or_xfail", lambda *_args, **_kwargs: next(generated)
    )
    monkeypatch.setattr(
        lifecycle_case,
        "mech_ecdh",
        lambda *_args, **kwargs: _capture_public_data(derive_public_data, kwargs),
    )
    monkeypatch.setattr(lifecycle_case, "derive_key", lambda *_args, **_kwargs: 21)
    monkeypatch.setattr(
        lifecycle_case,
        "encrypt_single",
        lambda *_args, **_kwargs: _record_encryption(continuation),
    )
    monkeypatch.setattr(
        lifecycle_case,
        "decrypt_single",
        lambda *_args, **_kwargs: _record_decryption(continuation),
    )
    monkeypatch.setattr(
        lifecycle_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    lifecycle_case.TestECDHDerivedKeyUse().test_ecdh_derive_and_use(rs)

    assert derive_public_data == [_p256_point(form=serialization.PublicFormat.CompressedPoint)]
    assert continuation == ["encrypt", "decrypt"]
    assert rs.flag_calls == [
        (int(CKM_ECDH1_DERIVE), int(CKF_EC_COMPRESS)),
        (int(CKM_ECDH1_DERIVE), int(CKF_EC_UNCOMPRESS)),
    ]
    assert destroyed == [11, 12, 13, 14, 21]


def test_nested_template_matching_and_violation_reach_policy_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid ECDH point does not bypass matching or violating template derives."""
    provider_point = _wrap_point(_p256_point(form=serialization.PublicFormat.CompressedPoint))
    rs = _session(
        flags={int(CKF_EC_COMPRESS): True, int(CKF_EC_UNCOMPRESS): False},
        mechanisms={"EC_KEY_PAIR_GEN", "ECDH1_DERIVE"},
    )
    _install_point_reader(
        monkeypatch,
        nested_case,
        provider_point,
        attrs={CKA_DERIVE_TEMPLATE: bytes(sizeof(CK_ATTRIBUTE))},
    )
    generate_calls = 0
    derive_calls: list[object] = []
    derive_public_data: list[bytes] = []
    destroyed: list[int] = []

    def _generate(*args: Any) -> int:
        nonlocal generate_calls
        generate_calls += 1
        args[-2]._obj.value = 11 if generate_calls == 1 else 13
        args[-1]._obj.value = 12 if generate_calls == 1 else 14
        return 0

    def _derive(*args: Any) -> int:
        derive_calls.append(args)
        if len(derive_calls) == 1:
            args[-1]._obj.value = 21
            return 0
        return int(CKR_TEMPLATE_INCONSISTENT)

    rs.raw = SimpleNamespace(C_GenerateKeyPair=_generate, C_DeriveKey=_derive)
    monkeypatch.setattr(
        nested_case,
        "mech_ecdh",
        lambda *_args, **kwargs: _capture_public_data(derive_public_data, kwargs),
    )
    monkeypatch.setattr(
        nested_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    nested_case.TestEcdhDeriveTemplateEnforcement().test_ecdh_derive_template_enforces_created_object_label(
        rs
    )

    assert len(derive_calls) == 2
    assert derive_public_data == [_p256_point(form=serialization.PublicFormat.CompressedPoint)]
    assert rs.flag_calls == [
        (int(CKM_ECDH1_DERIVE), int(CKF_EC_COMPRESS)),
        (int(CKM_ECDH1_DERIVE), int(CKF_EC_UNCOMPRESS)),
    ]
    assert destroyed == [21, 14, 13, 12, 11]


def test_public_session_uses_raw_point_before_exact_policy_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Public-session ECDH keeps the point normalization before CKR policy handling."""
    provider_point = _wrap_point(_p256_point(form=serialization.PublicFormat.CompressedPoint))
    rs = _session(
        flags={int(CKF_EC_COMPRESS): True, int(CKF_EC_UNCOMPRESS): False},
        mechanisms={"EC_KEY_PAIR_GEN", "ECDH1_DERIVE"},
    )
    _install_point_reader(monkeypatch, public_case, provider_point)
    derive_public_data: list[bytes] = []
    cleanup: list[str] = []

    monkeypatch.setattr(public_case, "gen_ec_keypair", lambda *_args, **_kwargs: (11, 12))
    monkeypatch.setattr(
        public_case,
        "_establish_public_session",
        lambda *_args, **_kwargs: (99, b"1234"),
    )
    monkeypatch.setattr(
        public_case,
        "mech_ecdh",
        lambda *_args, **kwargs: _capture_public_data(derive_public_data, kwargs),
    )

    def _derive(*_args: Any, **kwargs: Any) -> int:
        raise CkrAssertionError("public session", int(CKR_USER_NOT_LOGGED_IN))

    monkeypatch.setattr(public_case, "derive_key", _derive)
    monkeypatch.setattr(public_case, "_login_user_raw", lambda *_args: cleanup.append("login"))
    monkeypatch.setattr(public_case, "_cleanup_label", lambda *_args: cleanup.append("cleanup"))
    monkeypatch.setattr(
        public_case, "close_session_quietly", lambda *_args: cleanup.append("close")
    )

    public_case.TestPublicSessionPrivateCreation().test_public_cannot_derive_private_ecdh_key(
        rs, SimpleNamespace(pin=b"1234")
    )

    assert derive_public_data == [_p256_point(form=serialization.PublicFormat.CompressedPoint)]
    assert rs.flag_calls == [
        (int(CKM_ECDH1_DERIVE), int(CKF_EC_COMPRESS)),
        (int(CKM_ECDH1_DERIVE), int(CKF_EC_UNCOMPRESS)),
    ]
    assert cleanup == ["login", "cleanup", "close", "cleanup"]


def test_nested_claim_reader_preserves_unexpected_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unexpected claimed-template read CKR is not downgraded to no claim."""
    rs = _session()

    def _reader(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise CkrAssertionError("unexpected template read", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(nested_case, "read_attributes", _reader)
    with pytest.raises(CkrAssertionError) as exc_info:
        nested_case._read_claimed_template(
            rs,
            11,
            CKA_DERIVE_TEMPLATE,
            label="nested template read",
            mechanism="CKM_ECDH1_DERIVE",
        )
    assert exc_info.value.rv == int(CKR_GENERAL_ERROR)
    assert C.get_records() == []


def test_nested_claim_reader_missing_readback_stays_claimed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F7 claim-sweep regression: every call site reaches ``_read_claimed_template``
    only after C_GenerateKey(Pair)/C_CreateObject already returned CKR_OK for a
    template requesting the nested-template attribute, so a missing readback
    must not downgrade that creation-time claim (mutation: reverting the
    ``claimed = False`` initial default -- pre-fix -- turns this back into
    ``claimed is False``)."""
    rs = _session()
    monkeypatch.setattr(nested_case, "read_attributes", lambda *_args, **_kwargs: {})

    claimed, read_record = nested_case._read_claimed_template(
        rs,
        11,
        CKA_DERIVE_TEMPLATE,
        label="nested template read",
        mechanism="CKM_ECDH1_DERIVE",
    )

    assert claimed is True
    assert read_record is not None
    assert read_record.reason == "not_operational"


@pytest.mark.parametrize("rv", [CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID])
def test_nested_claim_reader_refused_read_stays_claimed(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
) -> None:
    """Same fix, for the branch where the readback itself is refused with a
    known refusal CKR rather than merely omitted from the returned mapping."""
    rs = _session()

    def _reader(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise CkrAssertionError("refused template read", int(rv))

    monkeypatch.setattr(nested_case, "read_attributes", _reader)

    claimed, read_record = nested_case._read_claimed_template(
        rs,
        11,
        CKA_DERIVE_TEMPLATE,
        label="nested template read",
        mechanism="CKM_ECDH1_DERIVE",
    )

    assert claimed is True
    assert read_record is not None
    assert read_record.reason == "not_operational"


@pytest.mark.parametrize(
    "malformed",
    [None, b"", b"short", bytes(sizeof(CK_ATTRIBUTE) + 1), 1],
    ids=["none", "empty", "short", "non-integral-record-bytes", "int"],
)
def test_nested_claim_reader_records_malformed_and_runs_later_policy(
    monkeypatch: pytest.MonkeyPatch,
    malformed: Any,
) -> None:
    """Malformed present claims are hard metadata evidence, without skipping policy."""
    rs = _session()

    monkeypatch.setattr(
        nested_case,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_DERIVE_TEMPLATE: malformed},
    )
    claimed, read_record = nested_case._read_claimed_template(
        rs,
        11,
        CKA_DERIVE_TEMPLATE,
        label="nested template read",
        mechanism="CKM_ECDH1_DERIVE",
    )
    assert claimed is False
    assert read_record is not None
    assert read_record.reason == "wrong_result"
    assert read_record.kind == "metadata"

    deferred = [read_record]
    nested_case._defer_policy_result(
        deferred,
        claimed=claimed,
        label="nested template policy after malformed read",
    )
    assert [record.reason for record in deferred] == ["wrong_result", "honest_deviation"]
    with pytest.raises(pytest.fail.Exception, match="invalid nested-template shape"):
        nested_case._raise_strongest(deferred)


@pytest.mark.parametrize(
    "malformed",
    [None, b"", b"short", b"\x00" * 31, b"\x00" * 33, 7],
    ids=["none", "empty", "short", "31-bytes", "33-bytes", "int"],
)
def test_lifecycle_ckavalue_malformed_is_hard_but_original_key_continues(
    monkeypatch: pytest.MonkeyPatch,
    malformed: Any,
) -> None:
    """Malformed export evidence does not suppress the independent original-key check."""
    rs = _session(mechanisms={"AES_ECB", "AES_KEY_GEN"})
    destroyed: list[int] = []
    continuation: list[str] = []
    monkeypatch.setattr(lifecycle_case, "gen_aes_key_or_xfail", lambda *_a, **_k: 11)
    monkeypatch.setattr(
        lifecycle_case,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_VALUE: malformed},
    )
    monkeypatch.setattr(
        lifecycle_case,
        "encrypt_single",
        lambda *_args, **_kwargs: _record_encryption(continuation),
    )
    monkeypatch.setattr(
        lifecycle_case,
        "import_secret_key_negotiated",
        lambda *_args, **_kwargs: pytest.fail("malformed export must not be imported"),
    )
    monkeypatch.setattr(
        lifecycle_case,
        "decrypt_single",
        lambda *_args, **_kwargs: pytest.fail("malformed export must not be decrypted"),
    )
    monkeypatch.setattr(
        lifecycle_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(pytest.fail.Exception, match="present value is malformed"):
        _run_export_reimport(rs)
    assert continuation == ["encrypt"]
    assert destroyed == [11]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.detail == {
        "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
        "expected_length": 32,
        "actual_type": type(malformed).__name__,
        "actual_length": len(malformed) if isinstance(malformed, bytes) else None,
        "producer_operation": "C_GenerateKey",
        "producer_mechanism": "CKM_AES_KEY_GEN",
    }
    assert "secret" not in repr(record.detail)


def test_lifecycle_ckavalue_omission_is_not_operational_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing export evidence leaves the original-key operation independently testable."""
    rs = _session(mechanisms={"AES_ECB", "AES_KEY_GEN"})
    destroyed: list[int] = []
    continuation: list[str] = []
    monkeypatch.setattr(lifecycle_case, "gen_aes_key_or_xfail", lambda *_a, **_k: 11)
    monkeypatch.setattr(lifecycle_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        lifecycle_case,
        "encrypt_single",
        lambda *_args, **_kwargs: _record_encryption(continuation),
    )
    monkeypatch.setattr(
        lifecycle_case,
        "import_secret_key_negotiated",
        lambda *_args, **_kwargs: pytest.fail("missing export must not be imported"),
    )
    monkeypatch.setattr(
        lifecycle_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(pytest.xfail.Exception, match="attribute unavailable"):
        _run_export_reimport(rs)
    assert continuation == ["encrypt"]
    assert destroyed == [11]
    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.detail == {
        "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
        "producer_operation": "C_GenerateKey",
        "producer_mechanism": "CKM_AES_KEY_GEN",
    }


def test_lifecycle_ckavalue_typed_refusal_is_attributed_and_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A clean attribute refusal is recorded at the read and original key still runs."""
    rs = _session(mechanisms={"AES_ECB", "AES_KEY_GEN"})
    destroyed: list[int] = []
    continuation: list[str] = []
    monkeypatch.setattr(lifecycle_case, "gen_aes_key_or_xfail", lambda *_a, **_k: 11)

    def _read(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise CkrAssertionError("CKA_VALUE refused", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(lifecycle_case, "read_attributes", _read)
    monkeypatch.setattr(
        lifecycle_case,
        "encrypt_single",
        lambda *_args, **_kwargs: _record_encryption(continuation),
    )
    monkeypatch.setattr(
        lifecycle_case,
        "import_secret_key_negotiated",
        lambda *_args, **_kwargs: pytest.fail("refused export must not be imported"),
    )
    monkeypatch.setattr(
        lifecycle_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(
        pytest.xfail.Exception, match="attribute read was rejected with CKR_GENERAL_ERROR"
    ):
        _run_export_reimport(rs)

    assert continuation == ["encrypt"]
    assert destroyed == [11]
    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.actual_ckr == "CKR_GENERAL_ERROR"
    assert record.detail == {
        "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
        "producer_operation": "C_GenerateKey",
        "producer_mechanism": "CKM_AES_KEY_GEN",
    }


def test_lifecycle_ckavalue_undefined_refusal_is_hard_but_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An undefined attribute-read CKR is hard evidence, while the original key is tested."""
    rs = _session(mechanisms={"AES_ECB", "AES_KEY_GEN"})
    continuation: list[str] = []
    monkeypatch.setattr(lifecycle_case, "gen_aes_key_or_xfail", lambda *_a, **_k: 11)
    monkeypatch.setattr(
        lifecycle_case,
        "read_attributes",
        lambda *_a, **_k: (_ for _ in ()).throw(CkrAssertionError("undefined", 0x7FFFFFFE)),
    )
    monkeypatch.setattr(
        lifecycle_case,
        "encrypt_single",
        lambda *_args, **_kwargs: _record_encryption(continuation),
    )
    monkeypatch.setattr(lifecycle_case, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        _run_export_reimport(rs)

    assert continuation == ["encrypt"]
    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.actual_ckr == "0x7ffffffe"
    assert record.mechanism is None


def test_lifecycle_ckavalue_refusal_drops_stale_active_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale active mechanism must not leak into a clean CKA_VALUE refusal record."""
    rs = _session(mechanisms={"AES_ECB", "AES_KEY_GEN"})
    destroyed: list[int] = []
    continuation: list[str] = []
    monkeypatch.setattr(lifecycle_case, "gen_aes_key_or_xfail", lambda *_a, **_k: 11)

    def _read(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise CkrAssertionError("CKA_VALUE refused", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(lifecycle_case, "read_attributes", _read)
    monkeypatch.setattr(
        lifecycle_case,
        "encrypt_single",
        lambda *_args, **_kwargs: _record_encryption(continuation),
    )
    monkeypatch.setattr(
        lifecycle_case,
        "import_secret_key_negotiated",
        lambda *_args, **_kwargs: pytest.fail("refused export must not be imported"),
    )
    monkeypatch.setattr(
        lifecycle_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    C.set_mechanism("STALE_MECHANISM", operation="C_Stale")

    with pytest.raises(
        pytest.xfail.Exception, match="attribute read was rejected with CKR_GENERAL_ERROR"
    ):
        _run_export_reimport(rs)

    assert continuation == ["encrypt"]
    assert destroyed == [11]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"


def test_lifecycle_ckavalue_omission_drops_stale_active_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale active mechanism must not leak into a missing CKA_VALUE record."""
    rs = _session(mechanisms={"AES_ECB", "AES_KEY_GEN"})
    destroyed: list[int] = []
    continuation: list[str] = []
    monkeypatch.setattr(lifecycle_case, "gen_aes_key_or_xfail", lambda *_a, **_k: 11)
    monkeypatch.setattr(lifecycle_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        lifecycle_case,
        "encrypt_single",
        lambda *_args, **_kwargs: _record_encryption(continuation),
    )
    monkeypatch.setattr(
        lifecycle_case,
        "import_secret_key_negotiated",
        lambda *_args, **_kwargs: pytest.fail("missing export must not be imported"),
    )
    monkeypatch.setattr(
        lifecycle_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    C.set_mechanism("STALE_MECHANISM", operation="C_Stale")

    with pytest.raises(pytest.xfail.Exception, match="attribute unavailable"):
        _run_export_reimport(rs)

    assert continuation == ["encrypt"]
    assert destroyed == [11]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"


def test_lifecycle_ckavalue_malformed_drops_stale_active_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale active mechanism must not leak into a malformed CKA_VALUE record."""
    rs = _session(mechanisms={"AES_ECB", "AES_KEY_GEN"})
    destroyed: list[int] = []
    continuation: list[str] = []
    monkeypatch.setattr(lifecycle_case, "gen_aes_key_or_xfail", lambda *_a, **_k: 11)
    monkeypatch.setattr(
        lifecycle_case,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_VALUE: b"short"},
    )
    monkeypatch.setattr(
        lifecycle_case,
        "encrypt_single",
        lambda *_args, **_kwargs: _record_encryption(continuation),
    )
    monkeypatch.setattr(
        lifecycle_case,
        "import_secret_key_negotiated",
        lambda *_args, **_kwargs: pytest.fail("malformed export must not be imported"),
    )
    monkeypatch.setattr(
        lifecycle_case,
        "decrypt_single",
        lambda *_args, **_kwargs: pytest.fail("malformed export must not be decrypted"),
    )
    monkeypatch.setattr(
        lifecycle_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    C.set_mechanism("STALE_MECHANISM", operation="C_Stale")

    with pytest.raises(pytest.fail.Exception, match="present value is malformed"):
        _run_export_reimport(rs)

    assert continuation == ["encrypt"]
    assert destroyed == [11]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"


def test_lifecycle_ckavalue_unexpected_reader_error_propagates_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected reader failures are not downgraded and source cleanup still runs."""
    rs = _session(mechanisms={"AES_ECB", "AES_KEY_GEN"})
    destroyed: list[int] = []
    error = RuntimeError("reader transport failed")
    monkeypatch.setattr(lifecycle_case, "gen_aes_key_or_xfail", lambda *_a, **_k: 11)
    monkeypatch.setattr(
        lifecycle_case,
        "read_attributes",
        lambda *_a, **_k: (_ for _ in ()).throw(error),
    )
    monkeypatch.setattr(
        lifecycle_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(RuntimeError) as exc_info:
        _run_export_reimport(rs)
    assert exc_info.value is error
    assert destroyed == [11]
    assert C.get_records() == []


def test_lifecycle_ckavalue_valid_export_keeps_reimport_path_without_generic_keygen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AES-only capability runs the full valid export/import/decrypt continuation."""
    rs = _session(mechanisms={"AES_ECB", "AES_KEY_GEN"})
    continuation: list[str] = []
    destroyed: list[int] = []
    monkeypatch.setattr(lifecycle_case, "gen_aes_key_or_xfail", lambda *_a, **_k: 11)
    monkeypatch.setattr(
        lifecycle_case, "read_attributes", lambda *_a, **_k: {CKA_VALUE: b"\x01" * 32}
    )
    monkeypatch.setattr(
        lifecycle_case,
        "encrypt_single",
        lambda *_args, **_kwargs: _record_encryption(continuation),
    )
    monkeypatch.setattr(
        lifecycle_case,
        "import_secret_key_negotiated",
        lambda *_args, **_kwargs: _record_import(continuation),
    )
    monkeypatch.setattr(
        lifecycle_case,
        "decrypt_single",
        lambda *_args, **_kwargs: _record_reimport_decryption(continuation),
    )
    monkeypatch.setattr(
        lifecycle_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    _run_export_reimport(rs)

    assert continuation == ["encrypt", "import", "decrypt"]
    assert destroyed == [11, 22]
    assert C.get_records() == []


def test_lifecycle_ckavalue_prior_record_survives_original_encrypt_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An original-key failure propagates without erasing earlier export evidence."""
    rs = _session(mechanisms={"AES_ECB", "AES_KEY_GEN"})
    destroyed: list[int] = []
    error = RuntimeError("original encryption failed")
    monkeypatch.setattr(lifecycle_case, "gen_aes_key_or_xfail", lambda *_a, **_k: 11)
    monkeypatch.setattr(lifecycle_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        lifecycle_case,
        "encrypt_single",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(error),
    )
    monkeypatch.setattr(
        lifecycle_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(RuntimeError) as exc_info:
        _run_export_reimport(rs)
    assert exc_info.value is error
    assert destroyed == [11]
    assert len(C.get_records()) == 1
    assert C.get_records()[0].reason == "not_operational"


@pytest.mark.parametrize(
    "reported",
    [False, True, None, b"", b"\x00", 1],
    ids=["false", "true", "none", "empty-bytes", "short-bytes", "int"],
)
def test_public_private_readback_is_strict_and_policy_is_reached(
    monkeypatch: pytest.MonkeyPatch,
    reported: Any,
) -> None:
    """Every present readback reaches the policy oracle, with strict Boolean evidence."""
    rs = _session()
    policy_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        public_case,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_PRIVATE: reported},
    )
    monkeypatch.setattr(
        public_case,
        "classify_policy_enforcement",
        lambda **kwargs: policy_calls.append(kwargs),
    )
    C.set_mechanism("STALE_MECHANISM", operation="C_Stale")

    claimed, read_record = public_case._read_private_claim(
        rs,
        99,
        23,
        label="public-session CKA_PRIVATE readback",
        producer_operation="C_DeriveKey",
        producer_mechanism="CKM_ECDH1_DERIVE",
    )
    if type(reported) is bool:
        public_case._classify_private_policy(
            claimed=claimed,
            read_record=read_record,
            label="public-session policy after CKA_PRIVATE readback",
        )
    else:
        with pytest.raises(pytest.fail.Exception, match="malformed CK_BBOOL"):
            public_case._classify_private_policy(
                claimed=claimed,
                read_record=read_record,
                label="public-session policy after CKA_PRIVATE readback",
            )

    assert len(policy_calls) == 1
    assert policy_calls[0]["claimed"] is (reported is True)
    assert policy_calls[0]["violated"] is True
    if type(reported) is bool:
        assert read_record is None
        assert claimed is reported
    else:
        assert read_record is not None
        assert read_record.reason == "wrong_result"
        assert read_record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"


def test_public_ecdh_runtime_reaches_private_readback_before_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful public-session derive exercises CKA_PRIVATE readback and cleanup."""
    provider_point = _wrap_point(_p256_point(form=serialization.PublicFormat.CompressedPoint))
    rs = _session(
        flags={int(CKF_EC_COMPRESS): True, int(CKF_EC_UNCOMPRESS): False},
        mechanisms={"EC_KEY_PAIR_GEN", "ECDH1_DERIVE"},
    )
    read_requests: list[Any] = []

    def _reader(*_args: Any, **kwargs: Any) -> dict[int, Any]:
        requested = kwargs.get("attr_types", _args[-1] if _args else None)
        read_requests.append(requested)
        return {CKA_EC_POINT: provider_point, CKA_PRIVATE: False}

    monkeypatch.setattr(_ec_export, "read_attributes", _reader)
    monkeypatch.setattr(public_case, "read_attributes", _reader)
    monkeypatch.setattr(public_case, "gen_ec_keypair", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(public_case, "_establish_public_session", lambda *_a, **_k: (99, b"1234"))
    monkeypatch.setattr(public_case, "derive_key", lambda *_a, **_k: 23)
    monkeypatch.setattr(
        public_case,
        "mech_ecdh",
        lambda *_a, **_k: SimpleNamespace(byref=lambda: object()),
    )
    cleanup: list[Any] = []
    monkeypatch.setattr(public_case, "destroy_quietly", lambda *_a: cleanup.append("destroy"))
    monkeypatch.setattr(public_case, "_login_user_raw", lambda *_a: cleanup.append("login"))
    monkeypatch.setattr(public_case, "_cleanup_label", lambda *_a: cleanup.append("cleanup"))
    monkeypatch.setattr(public_case, "close_session_quietly", lambda *_a: cleanup.append("close"))

    with pytest.raises(pytest.xfail.Exception):
        public_case.TestPublicSessionPrivateCreation().test_public_cannot_derive_private_ecdh_key(
            rs, SimpleNamespace(pin=b"1234")
        )
    assert any(request == [CKA_PRIVATE] for request in read_requests)
    assert cleanup == ["login", "destroy", "cleanup", "close", "cleanup"]


def test_public_private_missing_is_not_operational_before_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing CKA_PRIVATE is distinct evidence, but does not erase the creation-time
    claim: every caller already proved the module accepted CKA_PRIVATE=True at creation,
    so the policy oracle still runs as claimed=True and a violation is a hard fail."""
    rs = _session()
    policy_calls: list[dict[str, Any]] = []
    real_classify_policy_enforcement = public_case.classify_policy_enforcement
    monkeypatch.setattr(public_case, "read_attributes", lambda *_a, **_k: {})

    def _spy_classify_policy_enforcement(**kwargs: Any) -> None:
        policy_calls.append(kwargs)
        real_classify_policy_enforcement(**kwargs)

    monkeypatch.setattr(
        public_case,
        "classify_policy_enforcement",
        _spy_classify_policy_enforcement,
    )
    claimed, read_record = public_case._read_private_claim(
        rs,
        99,
        23,
        label="public-session missing CKA_PRIVATE",
        producer_operation="C_DeriveKey",
        producer_mechanism="CKM_ECDH1_DERIVE",
    )
    with pytest.raises(pytest.fail.Exception, match="self-contradiction") as excinfo:
        public_case._classify_private_policy(
            claimed=claimed,
            read_record=read_record,
            label="public-session policy after missing CKA_PRIVATE",
        )
    assert not isinstance(excinfo.value, XFailed)
    assert claimed is True
    assert read_record is not None
    assert read_record.reason == "not_operational"
    assert policy_calls == [
        {
            "claimed": True,
            "violated": True,
            "label": "public-session policy after missing CKA_PRIVATE",
        }
    ]


def test_public_private_missing_readback_preserves_copy_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing CKA_PRIVATE records the read site and C_CopyObject producer separately."""
    rs = _session()
    monkeypatch.setattr(public_case, "read_attributes", lambda *_a, **_k: {})
    C.set_mechanism("STALE_MECHANISM", operation="C_Stale")

    claimed, read_record = public_case._read_private_claim(
        rs,
        99,
        23,
        label="public-session copy CKA_PRIVATE readback",
        producer_operation="C_CopyObject",
    )

    assert claimed is True
    assert read_record is not None
    assert read_record.reason == "not_operational"
    assert read_record.operation == "C_GetAttributeValue"
    assert read_record.mechanism is None
    assert read_record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    assert read_record.detail == {
        "attribute": {"name": "CKA_PRIVATE", "id": int(CKA_PRIVATE)},
        "producer_operation": "C_CopyObject",
    }


@pytest.mark.parametrize(
    "reported",
    [0, 1, b"", b"\x00", None],
    ids=["zero", "one", "empty-bytes", "short-bytes", "none"],
)
def test_public_private_malformed_readback_has_bounded_provenance_detail(
    monkeypatch: pytest.MonkeyPatch,
    reported: Any,
) -> None:
    """Present malformed CKA_PRIVATE values are hard metadata evidence without raw values."""
    rs = _session()
    monkeypatch.setattr(
        public_case,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_PRIVATE: reported},
    )
    C.set_mechanism("STALE_MECHANISM", operation="C_Stale")

    claimed, read_record = public_case._read_private_claim(
        rs,
        99,
        23,
        label="public-session ECDH CKA_PRIVATE readback",
        producer_operation="C_DeriveKey",
        producer_mechanism="CKM_ECDH1_DERIVE",
    )

    assert claimed is False
    assert read_record is not None
    assert read_record.reason == "wrong_result"
    assert read_record.operation == "C_GetAttributeValue"
    assert read_record.mechanism is None
    assert read_record.detail == {
        "attribute": {"name": "CKA_PRIVATE", "id": int(CKA_PRIVATE)},
        "expected": "strict CK_BBOOL (bool)",
        "actual_type": type(reported).__name__,
        "actual_length": len(reported) if isinstance(reported, bytes) else None,
        "producer_operation": "C_DeriveKey",
        "producer_mechanism": "CKM_ECDH1_DERIVE",
    }


@pytest.mark.parametrize(
    ("rv", "reason", "actual_ckr"),
    [
        (int(CKR_GENERAL_ERROR), "not_operational", "CKR_GENERAL_ERROR"),
        (0x7FFFFFFE, "self_contradiction", "0x7ffffffe"),
        (0x80000042, "not_operational", "0x80000042"),
    ],
    ids=["standard", "undefined", "vendor-defined"],
)
def test_public_private_read_refusal_preserves_actual_rv_and_provenance(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
    reason: str,
    actual_ckr: str,
) -> None:
    """Typed C_GetAttributeValue refusals follow standard/vendor versus undefined policy."""
    rs = _session()

    def _reader(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise CkrAssertionError("private read refusal", rv)

    monkeypatch.setattr(public_case, "read_attributes", _reader)
    C.set_mechanism("STALE_MECHANISM", operation="C_Stale")

    claimed, read_record = public_case._read_private_claim(
        rs,
        99,
        23,
        label="public-session unwrap CKA_PRIVATE readback",
        producer_operation="C_UnwrapKey",
        producer_mechanism="CKM_AES_KEY_WRAP",
    )

    assert claimed is True
    assert read_record is not None
    assert read_record.reason == reason
    assert read_record.operation == "C_GetAttributeValue"
    assert read_record.mechanism is None
    assert read_record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    assert read_record.actual_ckr == actual_ckr
    assert read_record.detail == {
        "attribute": {"name": "CKA_PRIVATE", "id": int(CKA_PRIVATE)},
        "producer_operation": "C_UnwrapKey",
        "producer_mechanism": "CKM_AES_KEY_WRAP",
    }


def test_public_private_unexpected_reader_error_propagates_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected read errors are not converted into provider-deviation evidence."""
    rs = _session()
    error = RuntimeError("attribute reader transport failed")
    monkeypatch.setattr(
        public_case,
        "read_attributes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(error),
    )

    with pytest.raises(RuntimeError) as exc_info:
        public_case._read_private_claim(
            rs,
            99,
            23,
            label="public-session CKA_PRIVATE readback",
            producer_operation="C_DeriveKey",
            producer_mechanism="CKM_ECDH1_DERIVE",
        )
    assert exc_info.value is error
    assert C.get_records() == []


def test_public_private_callers_supply_operation_provenance() -> None:
    """All four creation paths identify their producer independently of readback."""
    tree = ast.parse(inspect.getsource(public_case))
    provenance: list[tuple[str | None, str | None]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id != "_read_private_claim":
            continue
        values = {
            keyword.arg: ast.literal_eval(keyword.value)
            for keyword in node.keywords
            if keyword.arg in {"producer_operation", "producer_mechanism"}
        }
        provenance.append((values.get("producer_operation"), values.get("producer_mechanism")))

    assert sorted(provenance) == sorted(
        [
            ("C_UnwrapKey", "CKM_AES_KEY_WRAP"),
            ("C_DeriveKey", "CKM_ECDH1_DERIVE"),
            ("C_DeriveKey", "CKM_HKDF_DERIVE"),
            ("C_CopyObject", None),
        ]
    )


@pytest.mark.parametrize(
    "reported",
    [False, True, CKO_SECRET_KEY, b"", None],
    ids=["false", "true", "wrong-int", "empty-bytes", "none"],
)
def test_derived_public_class_readback_is_strictly_classified(
    monkeypatch: pytest.MonkeyPatch,
    reported: Any,
) -> None:
    """CKM_PUB_KEY_FROM_PRIV_KEY class readback rejects every malformed/wrong value."""
    rs = _session(mechanisms={"EC_KEY_PAIR_GEN"})
    destroyed: list[int] = []
    monkeypatch.setattr(derive_case, "gen_ec_keypair", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(derive_case, "derive_key", lambda *_a, **_k: 21)
    monkeypatch.setattr(
        derive_case,
        "read_attributes",
        lambda *_a, **_k: {CKA_CLASS: reported},
    )
    monkeypatch.setattr(
        derive_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    monkeypatch.setattr(derive_case, "mech_simple", lambda *_a, **_k: object())

    with pytest.raises(pytest.fail.Exception, match="derived object CKA_CLASS"):
        derive_case._derive_pub_from_priv(rs, _entry(1))
    assert destroyed == [11, 12, 21]
    assert C.get_records()[0].reason == "wrong_result"
    # Readback attribution: the class readback carries no borrowed derive
    # mechanism; the producer stays in label/detail only.
    assert C.get_records()[0].mechanism is None


def test_derived_public_class_missing_is_not_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing derived CKA_CLASS is an explicit operational xfail."""
    rs = _session(mechanisms={"EC_KEY_PAIR_GEN"})
    destroyed: list[int] = []
    monkeypatch.setattr(derive_case, "gen_ec_keypair", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(derive_case, "derive_key", lambda *_a, **_k: 21)
    monkeypatch.setattr(derive_case, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        derive_case, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )
    monkeypatch.setattr(derive_case, "mech_simple", lambda *_a, **_k: object())

    with pytest.raises(pytest.xfail.Exception, match="attribute unavailable"):
        derive_case._derive_pub_from_priv(rs, _entry(1))
    assert destroyed == [11, 12, 21]
    assert C.get_records()[0].reason == "not_operational"
    assert C.get_records()[0].mechanism is None
