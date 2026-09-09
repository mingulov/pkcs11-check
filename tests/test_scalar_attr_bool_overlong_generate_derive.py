"""Structural meta-tests for TestBoolOverlongInGenerateDerive (C2 Phase 1).

These are in-process probes that call the PKCS#11 API directly (not
subprocess-based), so full monkeypatching is not cost-effective.  Instead we
assert *structural* properties that guarantee finding-safety:

1. The class and all three probe methods exist.
2. Each probe body calls ``make_bool_attr_overlong`` (keep-alive binding).
3. Each probe body calls ``classify_negative_rv`` with ``TEMPLATE_ERRORS``.
4. Each probe is mechanism-guarded (``has_mechanism`` present in source).
5. The module compiles without syntax errors (implicit: import succeeds).
"""

from __future__ import annotations

import ctypes
import inspect
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed

from pkcs11_check import classification
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_CLASS,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_VALUE_LEN,
    CKF_EC_COMPRESS,
    CKF_EC_UNCOMPRESS,
    CKM_ECDH1_DERIVE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_OK,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases._error_tuples import TEMPLATE_ERRORS
from pkcs11_check.testcases.ckr._malformed_attrs import make_bool_attr_overlong
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security import test_scalar_attr_length_extended as _mod

# ---------------------------------------------------------------------------
# Class presence
# ---------------------------------------------------------------------------


def test_class_exists() -> None:
    """TestBoolOverlongInGenerateDerive must be defined in the module."""
    assert hasattr(_mod, "TestBoolOverlongInGenerateDerive"), (
        "TestBoolOverlongInGenerateDerive not found in test_scalar_attr_length_extended"
    )


# ---------------------------------------------------------------------------
# Method presence
# ---------------------------------------------------------------------------


def test_generate_aes_key_method_exists() -> None:
    """AES keygen probe method must exist."""
    cls = _mod.TestBoolOverlongInGenerateDerive
    assert hasattr(cls, "test_bool_overlong_in_generate_aes_key")


def test_generate_rsa_keypair_method_exists() -> None:
    """RSA keypair probe method must exist."""
    cls = _mod.TestBoolOverlongInGenerateDerive
    assert hasattr(cls, "test_bool_overlong_in_generate_rsa_keypair")


def test_derive_ecdh_method_exists() -> None:
    """ECDH derive probe method must exist."""
    cls = _mod.TestBoolOverlongInGenerateDerive
    assert hasattr(cls, "test_bool_overlong_in_derive_ecdh")


# ---------------------------------------------------------------------------
# Structural source checks per probe
# ---------------------------------------------------------------------------


def _src(method_name: str) -> str:
    return inspect.getsource(getattr(_mod.TestBoolOverlongInGenerateDerive, method_name))


def test_aes_probe_calls_make_bool_attr_overlong() -> None:
    """AES keygen probe must call make_bool_attr_overlong (keep-alive binding)."""
    assert "make_bool_attr_overlong" in _src("test_bool_overlong_in_generate_aes_key")


def test_aes_probe_calls_classify_negative_rv_with_template_errors() -> None:
    """AES keygen probe must classify via classify_negative_rv + TEMPLATE_ERRORS."""
    src = _src("test_bool_overlong_in_generate_aes_key")
    assert "classify_negative_rv" in src
    assert "TEMPLATE_ERRORS" in src


def test_aes_probe_is_mechanism_guarded() -> None:
    """AES keygen probe must guard on has_mechanism."""
    assert "has_mechanism" in _src("test_bool_overlong_in_generate_aes_key")


def test_rsa_probe_calls_make_bool_attr_overlong() -> None:
    """RSA keypair probe must call make_bool_attr_overlong (keep-alive binding)."""
    assert "make_bool_attr_overlong" in _src("test_bool_overlong_in_generate_rsa_keypair")


def test_rsa_probe_calls_classify_negative_rv_with_template_errors() -> None:
    """RSA keypair probe must classify via classify_negative_rv + TEMPLATE_ERRORS."""
    src = _src("test_bool_overlong_in_generate_rsa_keypair")
    assert "classify_negative_rv" in src
    assert "TEMPLATE_ERRORS" in src


def test_rsa_probe_is_mechanism_guarded() -> None:
    """RSA keypair probe must guard on has_mechanism."""
    assert "has_mechanism" in _src("test_bool_overlong_in_generate_rsa_keypair")


def test_derive_probe_calls_make_bool_attr_overlong() -> None:
    """ECDH derive probe must call make_bool_attr_overlong (keep-alive binding)."""
    assert "make_bool_attr_overlong" in _src("test_bool_overlong_in_derive_ecdh")


def test_derive_probe_calls_classify_negative_rv_with_template_errors() -> None:
    """ECDH derive probe must classify via classify_negative_rv + TEMPLATE_ERRORS."""
    src = _src("test_bool_overlong_in_derive_ecdh")
    assert "classify_negative_rv" in src
    assert "TEMPLATE_ERRORS" in src


def test_derive_probe_is_mechanism_guarded() -> None:
    """ECDH derive probe must guard on has_mechanism."""
    assert "has_mechanism" in _src("test_bool_overlong_in_derive_ecdh")


def test_derive_probe_destroys_setup_keys_in_finally() -> None:
    """ECDH derive probe must clean up base keypair handles in a finally block."""
    src = _src("test_bool_overlong_in_derive_ecdh")
    assert "finally" in src
    assert "destroy_quietly" in src


# ---------------------------------------------------------------------------
# Sanity: referenced helpers are importable (compile gate)
# ---------------------------------------------------------------------------


def test_make_bool_attr_overlong_importable() -> None:
    """make_bool_attr_overlong must be importable from _malformed_attrs."""
    assert callable(make_bool_attr_overlong)


def test_classify_negative_rv_importable() -> None:
    """classify_negative_rv must be importable from conftest."""
    assert callable(classify_negative_rv)


def test_template_errors_is_tuple() -> None:
    """TEMPLATE_ERRORS must be a tuple (used as the expected_rvs argument)."""
    assert isinstance(TEMPLATE_ERRORS, tuple)
    assert len(TEMPLATE_ERRORS) > 0


def test_derive_probe_uses_classified_point_reader_and_actual_ecdh_flags() -> None:
    src = _src("test_bool_overlong_in_derive_ecdh")
    assert "read_conventional_ec_point_or_xfail" in src
    assert "select_ecdh_point_form" in src
    assert "CKF_EC_COMPRESS" in src
    assert "CKF_EC_UNCOMPRESS" in src


def test_derive_probe_initializes_all_pair_handles_before_generation() -> None:
    src = _src("test_bool_overlong_in_derive_ecdh")
    assert "pub_a = priv_a = pub_b = priv_b = 0" in src
    assert src.index("pub_a = priv_a = pub_b = priv_b = 0") < src.index("gen_ec_keypair(")


def test_derive_probe_cleans_pair_one_when_pair_two_generation_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )
    calls = 0
    destroyed: list[int] = []

    def _generate(*_args: object, **_kwargs: object) -> tuple[int, int]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return (11, 12)
        raise RuntimeError("second EC keypair generation failed")

    monkeypatch.setattr(_mod, "gen_ec_keypair", _generate)
    monkeypatch.setattr(_mod, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(RuntimeError, match="second EC keypair"):
        _mod.TestBoolOverlongInGenerateDerive().test_bool_overlong_in_derive_ecdh(rs, CKA_ENCRYPT)

    assert destroyed == [11, 12]


def test_derive_probe_destroys_returned_key_before_classifying_acceptance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    destroyed: list[int] = []

    def _derive(*args: object) -> int:
        args[-1]._obj.value = 99  # type: ignore[attr-defined]
        return int(CKR_OK)

    rs = SimpleNamespace(
        raw=SimpleNamespace(C_DeriveKey=_derive),
        sh=1,
        has_mechanism=lambda _name: True,
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )
    point = SimpleNamespace(sec1_bytes=b"\x04" + b"\x01" * 64)
    monkeypatch.setattr(_mod, "gen_ec_keypair", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(_mod, "read_conventional_ec_point_or_xfail", lambda *_a, **_k: point)
    monkeypatch.setattr(_mod, "select_ecdh_point_form", lambda value, **_k: value.sec1_bytes)

    def _destroy(_raw: object, _sh: object, handle: int) -> None:
        destroyed.append(handle)
        events.append(f"destroy:{handle}")

    monkeypatch.setattr(_mod, "destroy_quietly", _destroy)
    monkeypatch.setattr(
        _mod,
        "classify_negative_rv",
        lambda *_a, **_k: events.append("classify"),
    )

    _mod.TestBoolOverlongInGenerateDerive().test_bool_overlong_in_derive_ecdh(rs, CKA_ENCRYPT)

    assert events.index("destroy:99") < events.index("classify")
    assert destroyed == [99, 11, 12, 11, 12]


def _derive_runtime_session(
    rv: int,
    captured: dict[str, object],
    flags: list[tuple[int, int]],
) -> SimpleNamespace:
    def _has_flag(mechanism: Any, flag: Any) -> bool:
        flags.append((int(mechanism), int(flag)))
        return int(flag) == int(CKF_EC_COMPRESS)

    def _derive(*args: Any) -> int:
        template_ptr = args[3]
        count = int(args[4])
        assert hasattr(template_ptr, "__getitem__")
        attrs = [template_ptr[index] for index in range(count)]
        target = next(attribute for attribute in attrs if int(attribute.type) == int(CKA_ENCRYPT))
        captured["count"] = count
        captured["types"] = [int(attribute.type) for attribute in attrs]
        captured["target_len"] = int(target.ulValueLen)
        captured["target_storage"] = ctypes.string_at(target.pValue, ctypes.sizeof(CK_ULONG))
        if rv == int(CKR_OK):
            args[-1]._obj.value = 99
        return rv

    point = SimpleNamespace(sec1_bytes=b"\x04" + b"\x01" * 64)
    return SimpleNamespace(
        raw=SimpleNamespace(C_DeriveKey=_derive),
        sh=1,
        has_mechanism=lambda _name: True,
        has_mechanism_flag=_has_flag,
        point=point,
    )


def _patch_derive_runtime(
    monkeypatch: pytest.MonkeyPatch,
    rs: SimpleNamespace,
    destroyed: list[int],
) -> None:
    monkeypatch.setattr(_mod, "gen_ec_keypair", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(
        _mod,
        "read_conventional_ec_point_or_xfail",
        lambda *_a, **_k: rs.point,
    )
    monkeypatch.setattr(
        _mod,
        "select_ecdh_point_form",
        lambda point, **_k: point.sec1_bytes,
    )
    monkeypatch.setattr(
        _mod,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )


def test_derive_runtime_delivers_exact_malformed_attribute_and_flag_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    flags: list[tuple[int, int]] = []
    destroyed: list[int] = []
    rs = _derive_runtime_session(int(CKR_ATTRIBUTE_VALUE_INVALID), captured, flags)
    _patch_derive_runtime(monkeypatch, rs, destroyed)

    _mod.TestBoolOverlongInGenerateDerive().test_bool_overlong_in_derive_ecdh(rs, CKA_ENCRYPT)

    assert captured == {
        "count": 4,
        "types": [int(CKA_CLASS), int(CKA_KEY_TYPE), int(CKA_VALUE_LEN), int(CKA_ENCRYPT)],
        "target_len": ctypes.sizeof(CK_ULONG),
        "target_storage": b"\x00" * ctypes.sizeof(CK_ULONG),
    }
    assert flags == [
        (int(CKM_ECDH1_DERIVE), int(CKF_EC_COMPRESS)),
        (int(CKM_ECDH1_DERIVE), int(CKF_EC_UNCOMPRESS)),
    ]
    assert destroyed == [11, 12, 11, 12]


def test_derive_malformed_setup_skips_derive_and_cleans_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derive_calls: list[object] = []
    destroyed: list[int] = []
    flags: list[tuple[int, int]] = []
    rs = _derive_runtime_session(int(CKR_ATTRIBUTE_VALUE_INVALID), {}, flags)
    rs.raw.C_DeriveKey = lambda *_args: derive_calls.append(object())
    generated = iter(((11, 12), (13, 14)))
    monkeypatch.setattr(_mod, "gen_ec_keypair", lambda *_a, **_k: next(generated))
    monkeypatch.setattr(
        _mod,
        "read_conventional_ec_point_or_xfail",
        lambda *_a, **_k: pytest.xfail("malformed peer-key setup"),
    )
    monkeypatch.setattr(
        _mod,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.xfail.Exception):
        _mod.TestBoolOverlongInGenerateDerive().test_bool_overlong_in_derive_ecdh(rs, CKA_ENCRYPT)

    assert derive_calls == []
    assert flags == []
    assert destroyed == [11, 12, 13, 14]


@pytest.mark.parametrize(
    ("rv", "reason", "kind"),
    [
        (int(CKR_DEVICE_ERROR), "nonspec_reject", None),
        (int(CKR_VENDOR_DEFINED) + 1, "nonspec_reject", None),
        (0x7FFFFFFF, "self_contradiction", "metadata"),
    ],
    ids=["other-standard", "vendor-defined", "undefined"],
)
def test_derive_runtime_classifies_nonexpected_returns(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
    reason: str,
    kind: str | None,
) -> None:
    classification.clear()
    captured: dict[str, object] = {}
    flags: list[tuple[int, int]] = []
    destroyed: list[int] = []
    rs = _derive_runtime_session(rv, captured, flags)
    _patch_derive_runtime(monkeypatch, rs, destroyed)

    outcome = pytest.raises(pytest.xfail.Exception if reason == "nonspec_reject" else Failed)
    with outcome:
        _mod.TestBoolOverlongInGenerateDerive().test_bool_overlong_in_derive_ecdh(rs, CKA_ENCRYPT)

    record = classification.get_records()[-1]
    assert record.reason == reason
    assert record.kind == kind
    assert destroyed == [11, 12, 11, 12]


def test_derive_runtime_cleans_ckr_ok_key_before_acceptance_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classification.clear()
    captured: dict[str, object] = {}
    flags: list[tuple[int, int]] = []
    destroyed: list[int] = []
    rs = _derive_runtime_session(int(CKR_OK), captured, flags)
    _patch_derive_runtime(monkeypatch, rs, destroyed)

    with pytest.raises(Failed):
        _mod.TestBoolOverlongInGenerateDerive().test_bool_overlong_in_derive_ecdh(rs, CKA_ENCRYPT)

    record = classification.get_records()[-1]
    assert record.reason == "accepted_invalid"
    assert record.kind is None
    assert destroyed == [99, 11, 12, 11, 12]
