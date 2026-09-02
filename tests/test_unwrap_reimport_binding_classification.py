"""CKA_UNWRAP_TEMPLATE claim and return-value routing regressions."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_FUNCTION_FAILED, CKR_OK
from pkcs11_check.testcases.security import test_unwrap_reimport as target


class _Raw:
    def __init__(self, rv: int) -> None:
        self.rv = rv

    def C_GenerateKey(self, *_args: Any) -> int:  # noqa: N802
        _args[-1]._obj.value = 7
        return self.rv


def _session(rv: int) -> SimpleNamespace:
    return SimpleNamespace(raw=_Raw(rv), sh=1, has_mechanism=lambda _name: True)


def test_unwrap_template_keygen_unexpected_standard_rv_xfails() -> None:
    with pytest.raises(XFailed, match="C_GenerateKey with CKA_UNWRAP_TEMPLATE"):
        target.TestUnwrapTemplateBinding().test_unwrap_template_binding_enforced(
            _session(int(CKR_DEVICE_ERROR))
        )


def test_unwrap_template_keygen_undefined_rv_fails() -> None:
    with pytest.raises(Failed, match="undefined CK_RV"):
        target.TestUnwrapTemplateBinding().test_unwrap_template_binding_enforced(
            _session(0x12345678)
        )


def test_unwrap_template_accepted_but_missing_readback_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(target, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(target, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(Failed, match="discarded CKA_UNWRAP_TEMPLATE"):
        target.TestUnwrapTemplateBinding().test_unwrap_template_binding_enforced(
            _session(int(CKR_OK))
        )


def test_unwrap_template_readback_operational_error_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        target,
        "read_attributes",
        lambda *_a, **_k: (_ for _ in ()).throw(CkrAssertionError("rv", int(CKR_FUNCTION_FAILED))),
    )
    monkeypatch.setattr(target, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        target,
        "gen_aes_key_or_xfail",
        lambda *_a, **_k: pytest.fail("readback error was masked"),
    )

    with pytest.raises(XFailed, match="accepted CKA_UNWRAP_TEMPLATE.*read back"):
        target.TestUnwrapTemplateBinding().test_unwrap_template_binding_enforced(
            _session(int(CKR_OK))
        )
