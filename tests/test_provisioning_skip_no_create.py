"""Meta-test: provision_secret_key skips cleanly when C_CreateObject is absent and key_inject=off.

Monkeypatches import_secret_key to raise CkrAssertionError(CKR_FUNCTION_NOT_SUPPORTED) and
asserts that provision_secret_key raises pytest.skip.Exception (not a hard failure).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.config import P11TestConfig
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKK_AES, CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases._provisioning import provision_secret_key


def _reset_cache() -> None:
    import pkcs11_check.testcases._provisioning as _prov

    _prov._PROFILE_CACHE.clear()


class _FakeRaw:
    """Stub raw interface (no-op; import_secret_key is monkeypatched)."""


class _NoCreateRs:
    """Minimal fake session record: import_secret_key raises FNS, no unwrap mechs."""

    sh = 1234
    raw: _FakeRaw = _FakeRaw()

    def has_mechanism(self, name: str) -> bool:
        return False


def test_no_create_no_unwrap_skips_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    """provision_secret_key must raise pytest.skip (not fail) when create is absent + off."""

    def fake_import(raw: Any, sh: int, key_type: Any, value: bytes, attrs: Any) -> int:
        raise CkrAssertionError("not supported", CKR_FUNCTION_NOT_SUPPORTED)

    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", fake_import)
    _reset_cache()

    cfg = P11TestConfig(module=Path("/x.so"), key_inject="off")
    with pytest.raises(pytest.skip.Exception):
        provision_secret_key(_NoCreateRs(), cfg, CKK_AES, b"\x00" * 16, {}, label="x")
