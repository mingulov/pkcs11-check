"""Runtime regressions for AEAD wrap output readback classification."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKA_VALUE
from pkcs11_check.testcases import test_aead_wrap_outputs as aead
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _rs(*mechanisms: str) -> SimpleNamespace:
    advertised = set(mechanisms or ("AES_GCM",))
    return SimpleNamespace(
        raw=object(),
        sh=1,
        slot_id=0,
        has_mechanism=lambda name: name in advertised,
    )


def test_make_keys_read_failure_cleans_every_created_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([10, 11])
    monkeypatch.setattr(aead, "gen_aes_key", lambda *_args, **_kwargs: next(handles))
    monkeypatch.setattr(
        aead,
        "read_attributes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("read failed")),
    )
    destroyed: list[int] = []
    monkeypatch.setattr(aead, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(RuntimeError, match="read failed"):
        aead._make_keys(_rs(), "CKM_AES_GCM")

    assert destroyed == [11, 10]


def test_make_keys_missing_value_retains_handles_and_returns_sentinel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([10, 11])
    monkeypatch.setattr(aead, "gen_aes_key", lambda *_args, **_kwargs: next(handles))
    monkeypatch.setattr(aead, "read_attributes", lambda *_args, **_kwargs: {})
    destroyed: list[int] = []
    monkeypatch.setattr(aead, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    wrap_h, target, original = aead._make_keys(_rs(), "CKM_AES_GCM")

    assert (wrap_h, target) == (10, 11)
    assert original is MISSING_ATTRIBUTE
    assert destroyed == []
    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.operation == "C_GetAttributeValue"
    # F6: a plain readback is never stamped with the mechanism that produced the
    # object being read; the producer survives in the label instead.
    assert record.mechanism is None
    assert "producer_mechanism=CKM_AES_GCM" in record.label


def _patch_gcm_roundtrip(
    monkeypatch: pytest.MonkeyPatch,
    *,
    read_value: Any,
    iv: Any = b"i" * 12,
    original: Any = b"o" * 16,
    calls: dict[str, int] | None = None,
) -> list[int]:
    monkeypatch.setattr(aead, "_make_keys", lambda _rs, _mechanism: (10, 11, original))
    monkeypatch.setattr(aead, "_require_wrap_flags", lambda *_args, **_kwargs: None)
    mechanism = SimpleNamespace(buffer_bytes=lambda _name: iv)
    monkeypatch.setattr(aead, "mech_gcm_wrap_generated_iv", lambda *_args, **_kwargs: mechanism)
    monkeypatch.setattr(aead, "mech_gcm_wrap", lambda *_args, **_kwargs: object())

    def _wrap(*_args: Any, **_kwargs: Any) -> bytes:
        if calls is not None:
            calls["wrap"] = calls.get("wrap", 0) + 1
        return b"wrapped"

    def _unwrap(*_args: Any, **_kwargs: Any) -> int:
        if calls is not None:
            calls["unwrap"] = calls.get("unwrap", 0) + 1
        return 12

    monkeypatch.setattr(
        aead,
        "wrap_key",
        _wrap,
    )
    monkeypatch.setattr(
        aead,
        "unwrap_key_for_mechanism_roundtrip",
        _unwrap,
    )
    monkeypatch.setattr(aead, "read_attributes", lambda *_args, **_kwargs: read_value)
    destroyed: list[int] = []
    monkeypatch.setattr(aead, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))
    return destroyed


def test_missing_unwrapped_value_is_structured_and_skips_only_equality(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed = _patch_gcm_roundtrip(monkeypatch, read_value={})

    aead.test_gcm_wrap_generated_iv_roundtrip(_rs(), object(), "3.2")

    assert destroyed == [12, 10, 11]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert "producer_mechanism=CKM_AES_GCM" in records[0].label
    assert records[0].detail == {
        "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
    }
    assert MISSING_ATTRIBUTE is not False


def test_missing_target_value_keeps_independent_gcm_legs_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: dict[str, int] = {}
    destroyed = _patch_gcm_roundtrip(
        monkeypatch,
        read_value={CKA_VALUE: b"u" * 16},
        original=MISSING_ATTRIBUTE,
        calls=calls,
    )

    aead.test_gcm_wrap_generated_iv_roundtrip(_rs(), object(), "3.2")

    assert calls == {"wrap": 1, "unwrap": 1}
    assert destroyed == [12, 10, 11]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].mechanism is None
    assert "producer_mechanism=CKM_AES_GCM" in records[0].label


@pytest.mark.parametrize(
    "original", [False, 0, b"", None, b"short"], ids=["false", "zero", "empty", "none", "short"]
)
def test_make_keys_present_malformed_value_is_structured_nonterminal_evidence(
    monkeypatch: pytest.MonkeyPatch,
    original: Any,
) -> None:
    handles = iter([10, 11])
    monkeypatch.setattr(aead, "gen_aes_key", lambda *_args, **_kwargs: next(handles))
    monkeypatch.setattr(aead, "read_attributes", lambda *_args, **_kwargs: {CKA_VALUE: original})
    destroyed: list[int] = []
    monkeypatch.setattr(aead, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    wrap_h, target, returned = aead._make_keys(_rs(), "CKM_AES_GCM")

    assert (wrap_h, target, returned) == (10, 11, original)
    assert destroyed == []
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_AES_GCM"
    assert record.detail is not None
    assert record.detail["attribute"]["actual"] == repr(original)


@pytest.mark.parametrize("value", [False, 0, b"", None], ids=["false", "zero", "empty", "none"])
def test_present_malformed_unwrapped_value_is_structured_crypto_failure(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    destroyed = _patch_gcm_roundtrip(monkeypatch, read_value={CKA_VALUE: value})

    with pytest.raises(pytest.fail.Exception):
        aead.test_gcm_wrap_generated_iv_roundtrip(_rs(), object(), "3.2")

    assert destroyed == [12, 10, 11]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "crypto"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism == "CKM_AES_GCM"
    assert records[0].expected_ckr is None
    assert records[0].actual_ckr is None
    assert records[0].detail is not None
    assert records[0].detail["attribute"]["actual"] == repr(value)


def test_unequal_well_typed_unwrapped_value_is_unwrap_semantic_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed = _patch_gcm_roundtrip(monkeypatch, read_value={CKA_VALUE: b"u" * 16})

    with pytest.raises(pytest.fail.Exception):
        aead.test_gcm_wrap_generated_iv_roundtrip(_rs(), object(), "3.2")

    assert destroyed == [12, 10, 11]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_UnwrapKey"
    assert record.mechanism == "CKM_AES_GCM"
    assert record.expected_ckr is None
    assert record.actual_ckr is None


def test_malformed_target_value_keeps_wrap_and_unwrap_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: dict[str, int] = {}
    destroyed = _patch_gcm_roundtrip(
        monkeypatch,
        read_value={CKA_VALUE: b"u" * 16},
        original=b"short",
        calls=calls,
    )

    with pytest.raises(pytest.fail.Exception):
        aead.test_gcm_wrap_generated_iv_roundtrip(_rs(), object(), "3.2")

    assert calls == {"wrap": 1, "unwrap": 1}
    assert destroyed == [12, 10, 11]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism == "CKM_AES_GCM"
    assert records[0].detail is not None
    assert records[0].detail["attribute"]["actual"] == repr(b"short")


def test_missing_target_value_uses_constant_ccm_data_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: dict[str, list[int]] = {"generated": [], "unwrap": []}
    monkeypatch.setattr(
        aead,
        "_make_keys",
        lambda _rs, _mechanism: (10, 11, MISSING_ATTRIBUTE),
    )
    monkeypatch.setattr(aead, "_require_wrap_flags", lambda *_args, **_kwargs: None)
    generated = SimpleNamespace(buffer_bytes=lambda _name: b"n" * 12)

    def _capture_generated(*_args: Any, **kwargs: Any) -> SimpleNamespace:
        calls["generated"].append(int(kwargs["data_len"]))
        return generated

    def _capture_unwrap(*_args: Any, **kwargs: Any) -> object:
        calls["unwrap"].append(int(kwargs["data_len"]))
        return object()

    monkeypatch.setattr(
        aead,
        "mech_ccm_wrap_generated_nonce",
        _capture_generated,
    )
    monkeypatch.setattr(
        aead,
        "mech_ccm_wrap",
        _capture_unwrap,
    )
    monkeypatch.setattr(aead, "wrap_key", lambda *_args, **_kwargs: b"wrapped")
    monkeypatch.setattr(
        aead,
        "unwrap_key_for_mechanism_roundtrip",
        lambda *_args, **_kwargs: 12,
    )
    monkeypatch.setattr(aead, "read_attributes", lambda *_args, **_kwargs: {CKA_VALUE: b"u" * 16})
    destroyed: list[int] = []
    monkeypatch.setattr(aead, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    aead.test_ccm_wrap_generated_nonce_roundtrip(_rs("AES_CCM"), object(), "3.2")

    assert calls == {"generated": [16], "unwrap": [16]}
    assert destroyed == [12, 10, 11]
    assert C.get_records()[0].mechanism is None
    assert "producer_mechanism=CKM_AES_CCM" in C.get_records()[0].label


def test_earlier_wrap_output_failure_is_preserved_with_missing_unwrapped_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed = _patch_gcm_roundtrip(monkeypatch, read_value={}, iv=b"\x00" * 12)

    with pytest.raises(pytest.fail.Exception):
        aead.test_gcm_wrap_generated_iv_roundtrip(_rs(), object(), "3.2")

    assert destroyed == [12, 10, 11]
    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "not_operational"]
    assert records[0].operation == "C_WrapKey"
    assert records[0].mechanism == "CKM_AES_GCM"
    assert records[0].detail == {
        "parameter": {
            "name": "pIv",
            "expected": "non-zero IV",
            "actual": repr(b"\x00" * 12),
        }
    }
    assert records[1].operation == "C_GetAttributeValue"
    assert records[1].mechanism is None
    assert "producer_mechanism=CKM_AES_GCM" in records[1].label


def test_later_raw_unwrap_error_retains_prior_output_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: dict[str, int] = {}
    destroyed = _patch_gcm_roundtrip(
        monkeypatch,
        read_value={},
        iv=b"\x00" * 12,
        original=MISSING_ATTRIBUTE,
        calls=calls,
    )
    monkeypatch.setattr(
        aead,
        "unwrap_key_for_mechanism_roundtrip",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("unwrap failed")),
    )

    with pytest.raises(RuntimeError, match="unwrap failed"):
        aead.test_gcm_wrap_generated_iv_roundtrip(_rs(), object(), "3.2")

    assert calls == {"wrap": 1}
    assert destroyed == [10, 11]
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "wrong_result"]
    assert records[0].mechanism is None
    assert "producer_mechanism=CKM_AES_GCM" in records[0].label
    assert records[1].operation == "C_WrapKey"
    assert records[1].mechanism == "CKM_AES_GCM"


def test_nonbyte_generated_iv_is_structured_and_skips_dependent_unwrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed = _patch_gcm_roundtrip(monkeypatch, read_value={}, iv=None)

    with pytest.raises(pytest.fail.Exception):
        aead.test_gcm_wrap_generated_iv_roundtrip(_rs(), object(), "3.2")

    assert destroyed == [10, 11]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_WrapKey"
    assert record.mechanism == "CKM_AES_GCM"


def test_wrap_output_modules_attribute_access_analyzer_is_clean() -> None:
    """The migrated wrap-output modules must preserve explicit missing sentinels."""
    source_root = Path(__file__).resolve().parents[1] / "src" / "pkcs11_check" / "testcases"
    from tests._attribute_access_guard import analyze_paths

    paths = [source_root / name for name in ("test_aead_wrap_outputs.py", "test_aes_modes.py")]
    assert analyze_paths(paths) == []
