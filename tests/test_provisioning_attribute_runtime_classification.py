"""Provisioning omissions preserve fallback, hard evidence, and resource ownership."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw import recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_VALUE,
    CKK_AES,
    CKK_RSA,
    CKO_PRIVATE_KEY,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_UNWRAPPING_KEY_HANDLE_INVALID,
)
from pkcs11_check.testcases import _provisioning as P  # noqa: N812

pytest_plugins = ["pytester"]


@pytest.fixture(autouse=True)
def _isolated() -> Generator[None, None, None]:
    C.clear()
    P._PROFILE_CACHE.clear()
    P.clear_provisioning_events()
    yield
    C.clear()
    P._PROFILE_CACHE.clear()
    P.clear_provisioning_events()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=77)


def _omissions() -> list[int]:
    records = [r for r in C.get_records() if r.reason == "not_operational"]
    for record in records:
        assert record.operation == "C_GetAttributeValue"
        assert record.actual_ckr is None
        assert record.detail is not None
        assert record.detail["attribute"]["name"].startswith("CKA_")
    return [r.detail["attribute"]["id"] for r in records if r.detail is not None]


@pytest.mark.parametrize("missing", [CKA_CLASS, CKA_KEY_TYPE, None])
def test_dispatch_records_both_independent_reads(
    monkeypatch: pytest.MonkeyPatch,
    missing: int | None,
) -> None:
    calls: list[int] = []

    def read(_raw: Any, _sh: int, _handle: int, attrs: Any) -> dict[int, Any]:
        attr = attrs[0]
        calls.append(attr)
        return (
            {}
            if missing is None or attr == missing
            else {attr: {CKA_CLASS: CKO_PRIVATE_KEY, CKA_KEY_TYPE: CKK_RSA}[attr]}
        )

    monkeypatch.setattr(recipes, "read_attributes", read)
    assert P._build_configured_wrap_context(_rs(), SimpleNamespace(wrap_key_handle=12)) is None
    assert calls == [CKA_CLASS, CKA_KEY_TYPE]
    assert _omissions() == ([CKA_CLASS, CKA_KEY_TYPE] if missing is None else [missing])


@pytest.mark.parametrize("value", [None, b"", False, -1])
def test_dispatch_missing_class_does_not_hide_malformed_type(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    monkeypatch.setattr(
        recipes,
        "read_attributes",
        lambda _r, _s, _h, attrs: {} if attrs == (CKA_CLASS,) else {CKA_KEY_TYPE: value},
    )
    with pytest.raises(pytest.fail.Exception):
        P._build_configured_wrap_context(_rs(), SimpleNamespace(wrap_key_handle=12))
    assert _omissions() == [CKA_CLASS]
    assert C.get_records()[-1].outcome == "fail"


@pytest.fixture
def numbers() -> dict[int, bytes]:
    nums = (
        rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key().public_numbers()
    )
    return {CKA_MODULUS: nums.n.to_bytes(128, "big"), CKA_PUBLIC_EXPONENT: b"\x01\x00\x01"}


@pytest.mark.parametrize("id_attrs", [{}, {CKA_ID: b""}])
def test_id_absent_or_empty_uses_label_then_direct(
    monkeypatch: pytest.MonkeyPatch,
    numbers: dict[int, bytes],
    id_attrs: dict[int, Any],
) -> None:
    calls: list[Any] = []

    def read(_r: Any, _s: int, handle: int, attrs: Any) -> dict[int, Any]:
        calls.append(("read", handle, attrs))
        return id_attrs if attrs == (CKA_ID,) else numbers

    def find(_r: Any, _s: int, template: Any) -> list[int]:
        calls.append(("find", template))
        return []

    monkeypatch.setattr(recipes, "read_attributes", read)
    monkeypatch.setattr(recipes, "find_objects", find)
    monkeypatch.setattr("pkcs11_check.raw.pack.template_from_dict", lambda attrs: attrs)
    der = P._configured_rsa_pub_der(_rs(), 12, "kek")
    assert der is not None
    assert isinstance(load_der_public_key(der), rsa.RSAPublicKey)
    assert calls == [
        ("read", 12, (CKA_ID,)),
        ("find", {CKA_CLASS: 2, CKA_LABEL: "kek"}),
        ("read", 12, (CKA_MODULUS, CKA_PUBLIC_EXPONENT)),
    ]
    assert _omissions() == ([CKA_ID] if not id_attrs else [])


@pytest.mark.parametrize("attrs", [{}, {CKA_MODULUS: b""}, {CKA_PUBLIC_EXPONENT: None}])
def test_rsa_components_record_each_missing_even_with_hard_sibling(
    monkeypatch: pytest.MonkeyPatch,
    attrs: dict[int, Any],
) -> None:
    monkeypatch.setattr(
        recipes,
        "read_attributes",
        lambda _r, _s, _h, requested: {CKA_ID: b""} if requested == (CKA_ID,) else attrs,
    )
    if attrs:
        with pytest.raises(pytest.fail.Exception):
            P._configured_rsa_pub_der(_rs(), 12, None)
    else:
        assert P._configured_rsa_pub_der(_rs(), 12, None) is None
    assert _omissions() == [a for a in (CKA_MODULUS, CKA_PUBLIC_EXPONENT) if a not in attrs]


@pytest.mark.parametrize(
    "error", [RuntimeError("reader"), CkrAssertionError("device", CKR_DEVICE_ERROR)]
)
def test_configured_unexpected_read_errors_propagate(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def read(*_args: Any) -> Any:
        raise error

    monkeypatch.setattr(recipes, "read_attributes", read)
    with pytest.raises(type(error)) as raised:
        P._configured_rsa_pub_der(_rs(), 12, None)
    assert raised.value is error
    assert C.get_records() == []


def _bootstrap(monkeypatch: pytest.MonkeyPatch, read: Any) -> list[Any]:
    events: list[Any] = []
    monkeypatch.setattr(
        P, "profile_for", lambda _rs: SimpleNamespace(supports_unwrap_mech=lambda _m: True)
    )
    monkeypatch.setattr(recipes, "gen_rsa_keypair", lambda *_a, **_k: (10, 11))

    def aes(*_a: Any, **_k: Any) -> int:
        events.append("generate AES")
        return 20

    monkeypatch.setattr(recipes, "gen_aes_key", aes)
    monkeypatch.setattr(recipes, "read_attributes", read)
    monkeypatch.setattr(recipes, "destroy_quietly", lambda _r, _s, h: events.append(h))
    monkeypatch.setattr(recipes, "unwrap_key", lambda *_a, **_k: 30)
    return events


def test_bootstrap_missing_rsa_cleans_before_successful_aes_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _bootstrap(
        monkeypatch, lambda _r, _s, h, _a: {} if h == 10 else {CKA_VALUE: bytes(32)}
    )
    ctx = P.build_wrap_context(_rs(), SimpleNamespace())
    assert ctx is not None and ctx.strategy_name == "aes_kwp"
    assert ctx.rsa_unwrap_handle is None
    assert events == [10, 11, "generate AES", 30]
    assert _omissions() == [CKA_MODULUS, CKA_PUBLIC_EXPONENT]


def test_bootstrap_missing_aes_value_destroys_once(monkeypatch: pytest.MonkeyPatch) -> None:
    events = _bootstrap(monkeypatch, lambda *_a: {})
    assert P.build_wrap_context(_rs(), SimpleNamespace()) is None
    assert events == [10, 11, "generate AES", 20]
    assert _omissions() == [CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_VALUE]


@pytest.mark.parametrize("value", [b"", None, False, "bad"])
def test_bootstrap_present_malformed_aes_value_is_hard(
    monkeypatch: pytest.MonkeyPatch, value: Any
) -> None:
    events = _bootstrap(monkeypatch, lambda _r, _s, h, _a: {} if h == 10 else {CKA_VALUE: value})
    with pytest.raises(pytest.fail.Exception):
        P.build_wrap_context(_rs(), SimpleNamespace())
    assert events == [10, 11, "generate AES", 20]
    assert _omissions() == [CKA_MODULUS, CKA_PUBLIC_EXPONENT]


def test_bootstrap_rsa_read_exception_cleans_both_handles(monkeypatch: pytest.MonkeyPatch) -> None:
    def read(*_a: Any) -> Any:
        raise RuntimeError("reader")

    events = _bootstrap(monkeypatch, read)
    with pytest.raises(RuntimeError, match="reader"):
        P.build_wrap_context(_rs(), SimpleNamespace())
    assert events == [10, 11]


@pytest.mark.parametrize("attrs", [{}, {CKA_VALUE: b""}, {CKA_VALUE: None}, {CKA_VALUE: bytes(16)}])
def test_final_readback_distinguishes_unavailable_from_wrong_value(
    monkeypatch: pytest.MonkeyPatch, attrs: dict[int, Any]
) -> None:
    ctx = P.WrapContext(None, aes_kek_handle=20, sym_kek=bytes(32), strategy_name="aes_kwp")
    monkeypatch.setattr(P, "wrap_context_for", lambda *_a: ctx)
    monkeypatch.setattr(recipes, "unwrap_key", lambda *_a, **_k: 30)
    monkeypatch.setattr(recipes, "read_attributes", lambda *_a: attrs)
    destroyed: list[int] = []
    monkeypatch.setattr(recipes, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    if attrs and attrs[CKA_VALUE] != bytes(16):
        with pytest.raises(pytest.fail.Exception):
            P.provision_secret_key(
                _rs(),
                SimpleNamespace(key_inject="force-unwrap"),
                CKK_AES,
                bytes(16),
                {},
                label="target",
            )
        assert destroyed == [30]
        assert C.get_records()[-1].reason == "wrong_result"
    else:
        assert (
            P.provision_secret_key(
                _rs(),
                SimpleNamespace(key_inject="force-unwrap"),
                CKK_AES,
                bytes(16),
                {},
                label="target",
            )
            == 30
        )
        assert destroyed == []
        assert _omissions() == ([] if attrs else [CKA_VALUE])


def test_provisioning_attribute_analyzer_is_clean() -> None:
    from tests._attribute_access_guard import analyze_paths

    source = Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases/_provisioning.py"
    assert analyze_paths([source]) == []


def test_contradictory_configured_class_and_type_is_hard(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        recipes,
        "read_attributes",
        lambda _r, _s, _h, attrs: {CKA_CLASS: CKO_SECRET_KEY, CKA_KEY_TYPE: CKK_RSA},
    )
    with pytest.raises(pytest.fail.Exception):
        P._build_configured_wrap_context(_rs(), SimpleNamespace(wrap_key_handle=12))
    assert C.get_records()[-1].reason == "self_contradiction"


def test_bootstrap_unexpected_aes_generation_error_propagates_after_rsa_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _bootstrap(monkeypatch, lambda *_a: {})
    error = CkrAssertionError("device error", CKR_DEVICE_ERROR)

    def generate(*_a: Any, **_k: Any) -> int:
        assert events == [10, 11]
        raise error

    monkeypatch.setattr(recipes, "gen_aes_key", generate)
    with pytest.raises(CkrAssertionError) as raised:
        try:
            P.build_wrap_context(_rs(), SimpleNamespace())
        except pytest.xfail.Exception:
            pytest.fail("unexpected device failure was converted to fallback xfail")
    assert raised.value is error


@pytest.mark.parametrize(
    "error", [RuntimeError("reader"), CkrAssertionError("wrong read CKR", CKR_MECHANISM_INVALID)]
)
def test_second_acquisition_read_error_cleans_exactly_once(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def read(_r: Any, _s: int, h: int, _a: Any) -> dict[int, Any]:
        if h == 10:
            return {}
        raise error

    events = _bootstrap(monkeypatch, read)
    with pytest.raises(type(error)) as raised:
        P.build_wrap_context(_rs(), SimpleNamespace())
    assert raised.value is error
    assert events == [10, 11, "generate AES", 20]
    assert _omissions() == [CKA_MODULUS, CKA_PUBLIC_EXPONENT]


@pytest.mark.parametrize(
    "error",
    [
        None,
        CkrAssertionError("sensitive", CKR_ATTRIBUTE_SENSITIVE),
        RuntimeError("reader"),
        CkrAssertionError("device", CKR_DEVICE_ERROR),
    ],
)
def test_configured_secret_missing_or_refusal_preserves_other_strategy(
    monkeypatch: pytest.MonkeyPatch, error: Exception | None
) -> None:
    def read(*_a: Any) -> dict[int, Any]:
        if error is not None:
            raise error
        return {}

    monkeypatch.setattr(recipes, "read_attributes", read)
    monkeypatch.setattr(
        P, "profile_for", lambda _rs: SimpleNamespace(supports_unwrap_mech=lambda _m: True)
    )

    class TokenStrategy(P.AesKwp):
        name = "token-strategy"

        def has_material(self, ctx: P.WrapContext) -> bool:
            return ctx.aes_kek_handle is not None

        def wrap(self, ctx: P.WrapContext, target: bytes) -> bytes:
            return target

    monkeypatch.setattr(P, "DEFAULT_STRATEGIES", [P.AesKwp(), TokenStrategy()])
    monkeypatch.setattr(recipes, "unwrap_key", lambda *_a, **_k: 30)
    destroyed: list[int] = []
    monkeypatch.setattr(recipes, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    if error is not None and (
        not isinstance(error, CkrAssertionError) or error.rv == CKR_DEVICE_ERROR
    ):
        with pytest.raises(type(error)) as raised:
            P._configured_secret_material(_rs(), SimpleNamespace(), 12, lambda _s: None)
        assert raised.value is error
        assert destroyed == []
    else:
        ctx = P._configured_secret_material(_rs(), SimpleNamespace(), 12, lambda _s: None)
        assert ctx is not None and ctx.strategy_name == "token-strategy"
        assert ctx.sym_kek is None
        assert destroyed == [30]
        if error is None:
            assert _omissions() == [CKA_VALUE]
        else:
            assert C.get_records()[0].actual_ckr == "CKR_ATTRIBUTE_SENSITIVE"


@pytest.mark.parametrize(
    "error",
    [
        CkrAssertionError("sensitive", CKR_ATTRIBUTE_SENSITIVE),
        RuntimeError("reader"),
        CkrAssertionError("device", CKR_DEVICE_ERROR),
    ],
)
def test_final_reader_refusal_vs_plain_error_preserves_ownership(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    ctx = P.WrapContext(None, aes_kek_handle=20, sym_kek=bytes(32), strategy_name="aes_kwp")
    monkeypatch.setattr(P, "wrap_context_for", lambda *_a: ctx)
    monkeypatch.setattr(recipes, "unwrap_key", lambda *_a, **_k: 30)

    def read(*_a: Any) -> dict[int, Any]:
        raise error

    monkeypatch.setattr(recipes, "read_attributes", read)
    destroyed: list[int] = []
    monkeypatch.setattr(recipes, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    if isinstance(error, CkrAssertionError) and error.rv == CKR_ATTRIBUTE_SENSITIVE:
        assert (
            P.provision_secret_key(
                _rs(),
                SimpleNamespace(key_inject="force-unwrap"),
                CKK_AES,
                bytes(16),
                {},
                label="target",
            )
            == 30
        )
        assert destroyed == []
        assert C.get_records()[0].actual_ckr == "CKR_ATTRIBUTE_SENSITIVE"
    else:
        with pytest.raises(type(error)) as raised:
            P.provision_secret_key(
                _rs(),
                SimpleNamespace(key_inject="force-unwrap"),
                CKK_AES,
                bytes(16),
                {},
                label="target",
            )
        assert raised.value is error
        assert destroyed == [30]


@pytest.mark.parametrize("stage", ["rsa", "aes", "final"])
def test_fresh_invalid_handle_is_lifecycle_failure(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    def read(_r: Any, _s: int, h: int, _a: Any) -> dict[int, Any]:
        if stage == "aes" and h == 10:
            return {}
        raise CkrAssertionError("new handle invalid", CKR_OBJECT_HANDLE_INVALID)

    events = _bootstrap(monkeypatch, read)
    with pytest.raises(pytest.fail.Exception):
        try:
            if stage == "final":
                ctx = P.WrapContext(
                    None, aes_kek_handle=20, sym_kek=bytes(32), strategy_name="aes_kwp"
                )
                monkeypatch.setattr(P, "wrap_context_for", lambda *_a: ctx)
                P.provision_secret_key(
                    _rs(),
                    SimpleNamespace(key_inject="force-unwrap"),
                    CKK_AES,
                    bytes(16),
                    {},
                    label="target",
                )
            else:
                P.build_wrap_context(_rs(), SimpleNamespace())
        except pytest.xfail.Exception:
            pytest.fail("invalid fresh handle became an unavailable capability")
    records = C.get_records()
    assert any(
        r.reason == "self_contradiction"
        and r.kind == "lifecycle"
        and r.actual_ckr == "CKR_OBJECT_HANDLE_INVALID"
        for r in records
    )
    assert events == {"rsa": [10, 11], "aes": [10, 11, "generate AES", 20], "final": [30]}[stage]


@pytest.mark.parametrize("refused", [CKA_CLASS, CKA_KEY_TYPE])
@pytest.mark.parametrize("rv", [CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID])
@pytest.mark.parametrize("sibling", ["missing", "malformed"])
def test_dispatch_refusal_does_not_erase_sibling_evidence(
    monkeypatch: pytest.MonkeyPatch, refused: int, rv: int, sibling: str
) -> None:
    calls: list[int] = []

    def read(_r: Any, _s: int, _h: int, attrs: Any) -> dict[int, Any]:
        attr = attrs[0]
        calls.append(attr)
        if attr == refused:
            raise CkrAssertionError("read refused", rv)
        return {} if sibling == "missing" else {attr: None}

    monkeypatch.setattr(recipes, "read_attributes", read)
    if sibling == "malformed":
        with pytest.raises(pytest.fail.Exception):
            P._build_configured_wrap_context(_rs(), SimpleNamespace(wrap_key_handle=12))
    else:
        assert P._build_configured_wrap_context(_rs(), SimpleNamespace(wrap_key_handle=12)) is None
    assert calls == [CKA_CLASS, CKA_KEY_TYPE]
    assert any(r.actual_ckr is not None for r in C.get_records())
    other = CKA_KEY_TYPE if refused == CKA_CLASS else CKA_CLASS
    assert any(
        (r.label == ("CKA_CLASS" if other == CKA_CLASS else "CKA_KEY_TYPE") and r.outcome == "fail")
        if sibling == "malformed"
        else (r.detail is not None and r.detail.get("attribute", {}).get("id") == other)
        for r in C.get_records()
    )


@pytest.mark.parametrize("stage", ["wrong-final", "aes-refusal", "rsa-pair"])
def test_provider_evidence_precedes_cleanup_fault(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    def read(_r: Any, _s: int, h: int, _a: Any) -> dict[int, Any]:
        if stage == "wrong-final":
            return {CKA_VALUE: b"wrong"}
        if stage == "rsa-pair":
            return {CKA_MODULUS: b"", CKA_PUBLIC_EXPONENT: b""}
        if h == 10:
            return {}
        raise CkrAssertionError("sensitive", CKR_ATTRIBUTE_SENSITIVE)

    events = _bootstrap(monkeypatch, read)

    def destroy(_r: Any, _s: int, h: int) -> None:
        events.append(h)
        if stage == "aes-refusal" and h in (10, 11):
            return
        raise RuntimeError("cleanup fault")

    monkeypatch.setattr(recipes, "destroy_quietly", destroy)
    with pytest.raises((RuntimeError, BaseExceptionGroup)):
        if stage == "wrong-final":
            ctx = P.WrapContext(None, aes_kek_handle=20, sym_kek=bytes(32), strategy_name="aes_kwp")
            monkeypatch.setattr(P, "wrap_context_for", lambda *_a: ctx)
            P.provision_secret_key(
                _rs(),
                SimpleNamespace(key_inject="force-unwrap"),
                CKK_AES,
                bytes(16),
                {},
                label="target",
            )
        else:
            P.build_wrap_context(_rs(), SimpleNamespace())
    records = C.get_records()
    assert any(
        r.reason == "wrong_result"
        if stage != "aes-refusal"
        else r.actual_ckr == "CKR_ATTRIBUTE_SENSITIVE"
        for r in records
    )
    assert any(r.operation == "C_DestroyObject" and r.outcome == "fail" for r in records)
    assert (
        events
        == {"wrong-final": [30], "aes-refusal": [10, 11, "generate AES", 20], "rsa-pair": [10, 11]}[
            stage
        ]
    )


@pytest.mark.parametrize("size", [16, 24])
def test_bootstrap_aes_requires_requested_256_bits(
    monkeypatch: pytest.MonkeyPatch, size: int
) -> None:
    events = _bootstrap(
        monkeypatch, lambda _r, _s, h, _a: {} if h == 10 else {CKA_VALUE: bytes(size)}
    )
    with pytest.raises(pytest.fail.Exception):
        P.build_wrap_context(_rs(), SimpleNamespace())
    assert events == [10, 11, "generate AES", 20]
    assert C.get_records()[-1].reason == "wrong_result"


@pytest.mark.parametrize("configured", [False, True])
def test_successful_hash_fallback_retains_exact_trial_refusal(
    monkeypatch: pytest.MonkeyPatch, numbers: dict[int, bytes], configured: bool
) -> None:
    events = _bootstrap(monkeypatch, lambda *_a: numbers)
    attempts: list[int] = []

    def unwrap(*_a: Any, **_k: Any) -> int:
        attempts.append(1)
        if len(attempts) == 1:
            raise CkrAssertionError("sha256 refused", CKR_MECHANISM_INVALID)
        return 30

    monkeypatch.setattr(recipes, "unwrap_key", unwrap)
    if configured:
        der = P._rsa_public_der(numbers[CKA_MODULUS], numbers[CKA_PUBLIC_EXPONENT])
        ctx = P._configured_strategy_trial(
            _rs(),
            SimpleNamespace(),
            rsa_pub_der=der,
            rsa_unwrap_handle=11,
            aes_kek_handle=None,
            sym_kek=None,
            _fail=lambda _s: None,
        )
    else:
        ctx = P.build_wrap_context(_rs(), SimpleNamespace())
    assert ctx is not None and ctx.oaep_hash == "sha1"
    records = C.get_records()
    assert any(
        r.actual_ckr == "CKR_MECHANISM_INVALID"
        and r.operation == "C_UnwrapKey"
        and r.detail is not None
        and r.detail.get("oaep_hash") == "sha256"
        for r in records
    )
    assert events == ([30] if configured else [10, 30])


def test_bootstrap_rsa_private_handle_invalid_trial_is_lifecycle_failure(
    monkeypatch: pytest.MonkeyPatch, numbers: dict[int, bytes]
) -> None:
    events = _bootstrap(monkeypatch, lambda *_a: numbers)

    def unwrap(*_a: Any, **_k: Any) -> int:
        raise CkrAssertionError("new private handle invalid", CKR_OBJECT_HANDLE_INVALID)

    monkeypatch.setattr(recipes, "unwrap_key", unwrap)
    with pytest.raises(pytest.fail.Exception):
        try:
            P.build_wrap_context(_rs(), SimpleNamespace())
        except pytest.xfail.Exception:
            pytest.fail("fresh private invalid handle became fallback")
    assert any(
        r.reason == "self_contradiction"
        and r.kind == "lifecycle"
        and r.operation == "C_UnwrapKey"
        and r.actual_ckr == "CKR_OBJECT_HANDLE_INVALID"
        for r in C.get_records()
    )
    assert events == [10, 11]


@pytest.mark.parametrize("size", [16, 24, 32])
def test_configured_aes_retains_all_valid_key_sizes(
    monkeypatch: pytest.MonkeyPatch, size: int
) -> None:
    monkeypatch.setattr(recipes, "read_attributes", lambda *_a: {CKA_VALUE: bytes(size)})
    monkeypatch.setattr(
        P, "profile_for", lambda _r: SimpleNamespace(supports_unwrap_mech=lambda _m: True)
    )
    monkeypatch.setattr(recipes, "unwrap_key", lambda *_a, **_k: 30)
    destroyed: list[int] = []
    monkeypatch.setattr(recipes, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    ctx = P._configured_secret_material(_rs(), SimpleNamespace(), 12, lambda _s: None)
    assert ctx is not None and ctx.sym_kek == bytes(size)
    assert destroyed == [30]
    assert C.get_records() == []


@pytest.mark.parametrize("strategy", ["rsa", "aes"])
@pytest.mark.parametrize("rv", [CKR_OBJECT_HANDLE_INVALID, CKR_UNWRAPPING_KEY_HANDLE_INVALID])
def test_fresh_unwrap_keys_invalidity_preserves_exact_lifecycle_code(
    monkeypatch: pytest.MonkeyPatch, numbers: dict[int, bytes], strategy: str, rv: int
) -> None:
    events = _bootstrap(
        monkeypatch, lambda _r, _s, h, _a: numbers if strategy == "rsa" else {CKA_VALUE: bytes(32)}
    )
    if strategy == "aes":
        monkeypatch.setattr(P, "DEFAULT_STRATEGIES", [P.AesKwp()])

    def unwrap(*_a: Any, **_k: Any) -> int:
        raise CkrAssertionError("fresh unwrap handle invalid", rv)

    monkeypatch.setattr(recipes, "unwrap_key", unwrap)
    with pytest.raises(pytest.fail.Exception):
        try:
            P.build_wrap_context(_rs(), SimpleNamespace())
        except pytest.xfail.Exception:
            pytest.fail("fresh unwrap handle invalidity became xfail")
    from pkcs11_check.raw.rv import ckr_name

    expected_mech = "CKM_RSA_AES_KEY_WRAP" if strategy == "rsa" else "CKM_AES_KEY_WRAP_KWP"
    assert any(
        r.reason == "self_contradiction"
        and r.kind == "lifecycle"
        and r.actual_ckr == ckr_name(rv)
        and r.operation == "C_UnwrapKey"
        and r.mechanism == expected_mech
        for r in C.get_records()
    )
    assert events == ([10, 11] if strategy == "rsa" else ["generate AES", 20])


@pytest.mark.usefixtures("classification_report_plugin_enabled")
def test_cleanup_crash_survives_later_error_in_attached_report(pytester: pytest.Pytester) -> None:
    import json

    from pkcs11_check.core.file_runner import postprocess_jsonl_to_unified

    pytester.makeconftest("""
def pytest_configure():
    import pkcs11_check._plugin_report_attach as attach
    attach._is_testcase_item = lambda _item: True
""")
    pytester.makepyfile(
        test_cleanup="""
from types import SimpleNamespace
from pkcs11_check.raw import recipes
from pkcs11_check.testcases import _provisioning as P

def test_cleanup_crash(monkeypatch):
    profile = SimpleNamespace(supports_unwrap_mech=lambda _m: True)
    monkeypatch.setattr(P, "profile_for", lambda _r: profile)
    monkeypatch.setattr(recipes, "gen_rsa_keypair", lambda *_a, **_k: (10, 11))
    monkeypatch.setattr(recipes, "read_attributes", lambda *_a: {})
    attempted = []
    def destroy(_r, _s, handle):
        attempted.append(handle)
        if handle == 10:
            raise OSError("exception: access violation reading 0x0")
        raise RuntimeError("later cleanup fault")
    monkeypatch.setattr(recipes, "destroy_quietly", destroy)
    try:
        P.build_wrap_context(SimpleNamespace(raw=object(), sh=77), SimpleNamespace())
    finally:
        assert attempted == [10, 11]

def test_next_item_is_clean():
    from pkcs11_check import classification as C
    assert C.get_records() == []
"""
    )
    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")
    result.assert_outcomes(failed=1, passed=1)
    reports = [
        json.loads(line) for line in (pytester.path / "report.jsonl").read_text().splitlines()
    ]
    call = next(r for r in reports if r.get("when") == "call" and r.get("outcome") == "failed")
    records = dict(call["user_properties"])["pkcs11_classification"]
    crashes = [r for r in records if r["reason"] == "crash"]
    assert len(crashes) == 1
    assert crashes[0]["operation"] == "C_DestroyObject"
    assert crashes[0]["detail"] == {
        "windows_status": 0xC0000005,
        "signal": "EXCEPTION_ACCESS_VIOLATION",
    }
    assert any(r["reason"] == "oracle" and r["operation"] == "C_DestroyObject" for r in records)
    assert all(r["reason"] != "unclassified" for r in records)
    payload = postprocess_jsonl_to_unified(
        pytester.path / "report.jsonl", pytester.path / "results.json"
    )
    assert payload["summary"]["crashed"] == 1


@pytest.mark.parametrize("rv", [CKR_OBJECT_HANDLE_INVALID, CKR_UNWRAPPING_KEY_HANDLE_INVALID])
def test_configured_stale_unwrap_handle_is_visible_refusal_without_cleanup(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    from pkcs11_check.raw.rv import ckr_name

    monkeypatch.setattr(P, "DEFAULT_STRATEGIES", [P.AesKwp()])
    monkeypatch.setattr(
        P, "profile_for", lambda _r: SimpleNamespace(supports_unwrap_mech=lambda _m: True)
    )

    def unwrap(*_a: Any, **_k: Any) -> int:
        raise CkrAssertionError("configured key stale", rv)

    monkeypatch.setattr(recipes, "unwrap_key", unwrap)
    destroyed: list[int] = []
    monkeypatch.setattr(recipes, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    assert (
        P._configured_strategy_trial(
            _rs(),
            SimpleNamespace(),
            rsa_pub_der=None,
            rsa_unwrap_handle=None,
            aes_kek_handle=12,
            sym_kek=bytes(32),
            _fail=lambda _s: None,
        )
        is None
    )
    assert destroyed == []
    assert len(C.get_records()) == 1
    record = C.get_records()[0]
    assert record.reason == "not_operational" and record.actual_ckr == ckr_name(rv)
    assert record.operation == "C_UnwrapKey" and record.mechanism == "CKM_AES_KEY_WRAP_KWP"
