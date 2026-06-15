"""Meta-test: import_ec_private_key_negotiated routes through create_object_negotiated
and inherits the shape-winner cache (no real module needed)."""

from __future__ import annotations

from typing import Any

from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKO_PRIVATE_KEY,
)
from pkcs11_check.testcases import conftest


def _run(monkeypatch) -> tuple[list[dict[Any, Any]], int]:
    seen: list[dict[Any, Any]] = []

    def fake_create_object(raw: Any, sh: int, tmpl: dict[Any, Any]) -> int:
        seen.append(dict(tmpl))
        from pkcs11_check.raw.rv import CkrAssertionError
        from pkcs11_check.raw.types_std import CKR_ATTRIBUTE_READ_ONLY

        if CKA_SENSITIVE in tmpl or CKA_EXTRACTABLE in tmpl:
            raise CkrAssertionError("read only", int(CKR_ATTRIBUTE_READ_ONLY))
        return 42

    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", fake_create_object)
    conftest.reset_import_negotiation_cache()

    rs = type("RS", (), {"raw": object(), "sh": 0, "slot_id": 0})()
    h = conftest.import_ec_private_key_negotiated(
        rs, ec_params=b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07", value=b"\x01" * 32
    )
    return seen, h


def test_negotiates_past_read_only_and_drops_policy_attrs(monkeypatch):
    seen, h = _run(monkeypatch)
    assert h == 42
    winner = seen[-1]
    assert CKA_SENSITIVE not in winner and CKA_EXTRACTABLE not in winner
    assert winner[CKA_CLASS] == int(CKO_PRIVATE_KEY)
    assert winner[CKA_VALUE] == b"\x01" * 32


def test_second_call_uses_cache(monkeypatch):
    seen, _ = _run(monkeypatch)
    n_first = len(seen)
    rs = type("RS", (), {"raw": object(), "sh": 0, "slot_id": 0})()
    conftest.import_ec_private_key_negotiated(
        rs, ec_params=b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07", value=b"\x02" * 32
    )
    assert len(seen) == n_first + 1  # cached winner, no re-walk
