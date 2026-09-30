"""P11C-011: CKM_RSA_X9_31 registry entry must declare the prehash constraint.

X9.31 signs a pre-hashed digest, like PSS. Without input_constraint="prehash"
the registry-driven sign legs feed full-length messages and mis-score
providers. Only test_mech_sign.py consumes "prehash" (roundtrip + tampered
legs); rsa_extended and the registry guard are unaffected.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKM_RSA_X9_31
from pkcs11_check.testcases import test_mech_sign as mech_sign
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig, get_config


def test_rsa_x9_31_declares_prehash_constraint() -> None:
    config = get_config(CKM_RSA_X9_31)
    assert config is not None, "no registry config for CKM_RSA_X9_31"
    assert config.input_constraint == "prehash", (
        f"CKM_RSA_X9_31 input_constraint is {config.input_constraint!r}, expected 'prehash'"
    )


def test_mechconfig_docstring_lists_prehash_and_raw_block() -> None:
    doc = MechConfig.__doc__ or ""
    assert "prehash" in doc, "MechConfig docstring omits the prehash constraint value"
    assert "raw_block" in doc, "MechConfig docstring omits the raw_block constraint value"


def test_roundtrip_leg_hashes_input_for_x9_31(monkeypatch: pytest.MonkeyPatch) -> None:
    """Behavioral pin (F4'): the registry prehash constraint reaches sign_single.

    The roundtrip leg must feed the X9.31 digest (32 bytes, TestRSAX931's
    "exactly hash length" premise), not the full-length message. Uses the real
    registry config, so removing the constraint reddens this test.
    """
    config = get_config(CKM_RSA_X9_31)
    assert config is not None
    entry = MechEntry(
        mech_id=int(CKM_RSA_X9_31),
        mech_name="RSA_X9_31",
        flags=0,
        min_key_size=1024,
        max_key_size=4096,
        config=config,
    )
    seen: list[bytes] = []

    def _capture_sign(
        _raw: Any, _sh: int, _key: int, _mech: Any, data: bytes, **_kwargs: Any
    ) -> bytes:
        seen.append(data)
        return b"s" * 256

    monkeypatch.setattr(mech_sign, "generate_key_for_sign", lambda *_args: (1, None))
    monkeypatch.setattr(mech_sign, "make_mech_param_or_skip", lambda _entry: None)
    monkeypatch.setattr(mech_sign, "sign_single", _capture_sign)
    monkeypatch.setattr(mech_sign, "verify_single", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(mech_sign, "destroy_quietly", lambda *_args: None)
    mech_sign.TestMechSignRoundtrip().test_roundtrip(
        SimpleNamespace(raw=object(), sh=1), entry
    )
    expected = hashlib.sha256(b"hello pkcs11 sign test" * 2).digest()
    assert seen == [expected], f"leg fed {len(seen[0])} bytes, expected 32-byte digest"
    assert len(seen[0]) == 32
