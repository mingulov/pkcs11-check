"""fw#38: Init-based negative classes must run on function-scoped sessions.

An accepted *Init in a negative test leaves the operation active; on the
shared module session the next same-kind test then observes
CKR_OPERATION_ACTIVE instead of the answer it probed for, and the provider
finding it meant to check goes unseen. The EdDSA precedent (same file) runs
such negatives on p11_raw_session; these pins extend that to every
Init-based negative class in test_mech_negative.py.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import fixtures as p11_fixtures
from pkcs11_check.raw.types_std import CKM_AES_CBC, CKR_OK
from pkcs11_check.testcases import test_mech_negative
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import get_config

_ISOLATED_CLASSES = (
    "TestWrongKeyType",
    "TestBadParameters",
    "TestMissingPermission",
    "TestEdDSAParameters",
)


def _test_methods(cls: type) -> dict[str, Any]:
    return {
        name: member
        for name, member in inspect.getmembers(cls, inspect.isfunction)
        if name.startswith("test_")
    }


def test_init_negative_classes_use_raw_session() -> None:
    """Every test in the Init-based negative classes takes p11_raw_session."""
    for cls_name in _ISOLATED_CLASSES:
        cls = getattr(test_mech_negative, cls_name)
        methods = _test_methods(cls)
        assert methods, cls_name
        for name, member in methods.items():
            params = set(inspect.signature(member).parameters)
            assert "p11_raw_session" in params, f"{cls_name}.{name}"
            assert "p11_module_session" not in params, f"{cls_name}.{name}"


def test_module_session_shares_holder_raw_does_not() -> None:
    """Pin the sharing premise: module sessions reuse a holder, raw do not."""
    module_params = set(
        inspect.signature(p11_fixtures.p11_module_session._fixture_function).parameters
    )
    raw_params = set(inspect.signature(p11_fixtures.p11_raw_session._fixture_function).parameters)
    assert "_p11_module_session_holder" in module_params
    assert "_p11_module_session_holder" not in raw_params


class _AcceptingRaw:
    """Accept every Init: the provider bug the negative must report loudly."""

    def C_GenerateKey(self, _sh: int, _mech: Any, _tmpl: Any, _n: int, out: Any) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the helper calls.
        out._obj.value = 9
        return int(CKR_OK)

    def C_EncryptInit(self, _sh: int, _mech: Any, _key: int) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the test calls.
        return int(CKR_OK)

    def C_DestroyObject(self, _sh: int, _h: int) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the helper calls.
        return int(CKR_OK)


def _aes_cbc_encrypt_entry() -> MechEntry:
    config = get_config(int(CKM_AES_CBC))
    assert config is not None
    assert config.param_required is True
    return MechEntry(
        mech_id=int(CKM_AES_CBC),
        mech_name="AES_CBC",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=config,
    )


def test_accepted_init_finding_survives() -> None:
    """An accepted Init in the migrated negative must still fail loudly."""
    rs = SimpleNamespace(raw=_AcceptingRaw(), sh=1)
    method = test_mech_negative.TestBadParameters().test_registry_encrypt_missing_required_param
    try:
        method(rs, _aes_cbc_encrypt_entry())
    except pytest.fail.Exception as exc:
        assert "C_EncryptInit with missing required params" in str(exc)
    except pytest.skip.Exception as exc:
        pytest.fail(f"expected a loud failure, got skip instead: {exc}")
    else:
        pytest.fail("expected failure, method returned normally")
