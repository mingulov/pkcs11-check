"""Regression tests for protocol/resource and wrapping exception boundaries."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR
from pkcs11_check.testcases import test_protocol_edge_cases, test_rsa_key_wrapping


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def test_v240_attribute_probe_destroys_generated_keypair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = test_protocol_edge_cases
    destroyed: list[int] = []
    monkeypatch.setattr(module, "gen_rsa_keypair", lambda *_a, **_k: (10, 11))
    monkeypatch.setattr(
        module,
        "destroy_quietly",
        lambda _raw, _session, handle: destroyed.append(handle),
    )

    module.TestV240V32AttributeMix().test_v32_attrs_on_v240_module(_session(), "2.40")

    assert destroyed == [10, 11]


@pytest.mark.parametrize(
    "error",
    [
        CkrAssertionError("undefined provider return", 0x12345678),
        TypeError("binding bug"),
        AttributeError("binding bug"),
    ],
)
def test_v240_attribute_probe_does_not_hide_unexpected_errors(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    module = test_protocol_edge_cases
    monkeypatch.setattr(
        module,
        "gen_rsa_keypair",
        lambda *_a, **_k: (_ for _ in ()).throw(error),
    )

    expected = pytest.fail.Exception if isinstance(error, CkrAssertionError) else type(error)
    with pytest.raises(expected, match="undefined CK_RV|binding bug"):
        module.TestV240V32AttributeMix().test_v32_attrs_on_v240_module(_session(), "2.40")


@pytest.mark.parametrize("error", [TypeError("binding bug"), AttributeError("binding bug")])
def test_encapsulate_probe_does_not_blame_provider_for_binding_error(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    module = test_protocol_edge_cases
    monkeypatch.setattr(
        module,
        "gen_aes_key",
        lambda *_a, **_k: (_ for _ in ()).throw(error),
    )

    with pytest.raises(type(error), match="binding bug"):
        module.TestV240V32AttributeMix().test_encapsulate_attr_on_non_pqc(_session())


@pytest.mark.parametrize(
    ("method", "operation"),
    [
        ("test_many_session_objects", "gen_aes_key"),
        ("test_many_data_objects", "create_object"),
    ],
)
@pytest.mark.parametrize(
    "error", [AssertionError("binding bug"), CkrAssertionError("undefined", 0x12345678)]
)
def test_resource_exhaustion_does_not_hide_non_typed_errors(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    operation: str,
    error: BaseException,
) -> None:
    module = test_protocol_edge_cases
    monkeypatch.setattr(module, operation, lambda *_a, **_k: (_ for _ in ()).throw(error))
    monkeypatch.setattr(module, "destroy_quietly", lambda *_a, **_k: None)

    expected = pytest.fail.Exception if isinstance(error, CkrAssertionError) else AssertionError
    with pytest.raises(expected, match="binding bug|undefined CK_RV"):
        getattr(module.TestResourceExhaustion(), method)(_session())


def test_sensitive_extractable_wrap_does_not_hide_plain_assertion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = test_rsa_key_wrapping
    monkeypatch.setattr(module, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(module, "gen_aes_key", lambda *_a, **_k: 2)
    monkeypatch.setattr(module, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        module,
        "wrap_key_recipe",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("binding bug")),
    )
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)

    with pytest.raises(AssertionError, match="binding bug"):
        module.TestSensitiveExtractableWrap().test_sensitive_extractable_key_may_be_wrapped(rs)


def test_sensitive_extractable_wrap_reports_undefined_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = test_rsa_key_wrapping
    monkeypatch.setattr(module, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(module, "gen_aes_key", lambda *_a, **_k: 2)
    monkeypatch.setattr(module, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        module,
        "wrap_key_recipe",
        lambda *_a, **_k: (_ for _ in ()).throw(CkrAssertionError("undefined CK_RV", 0x12345678)),
    )
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)

    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        module.TestSensitiveExtractableWrap().test_sensitive_extractable_key_may_be_wrapped(rs)


@pytest.mark.parametrize(
    ("method", "operation"),
    [
        ("test_many_session_objects", "gen_aes_key"),
        ("test_many_data_objects", "create_object"),
    ],
)
@pytest.mark.parametrize("rv", [int(CKR_GENERAL_ERROR), 0x80000001])
def test_resource_exhaustion_accepts_typed_clean_refusal(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    operation: str,
    rv: int,
) -> None:
    module = test_protocol_edge_cases
    monkeypatch.setattr(
        module,
        operation,
        lambda *_a, **_k: (_ for _ in ()).throw(CkrAssertionError("clean refusal", rv)),
    )
    monkeypatch.setattr(module, "destroy_quietly", lambda *_a, **_k: None)

    getattr(module.TestResourceExhaustion(), method)(_session())


@pytest.mark.parametrize("rv", [int(CKR_GENERAL_ERROR), 0x80000001])
def test_sensitive_extractable_wrap_accepts_typed_clean_refusal(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
) -> None:
    module = test_rsa_key_wrapping
    monkeypatch.setattr(module, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(module, "gen_aes_key", lambda *_a, **_k: 2)
    monkeypatch.setattr(module, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        module,
        "wrap_key_recipe",
        lambda *_a, **_k: (_ for _ in ()).throw(CkrAssertionError("clean refusal", rv)),
    )
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)

    module.TestSensitiveExtractableWrap().test_sensitive_extractable_key_may_be_wrapped(rs)
