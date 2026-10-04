"""fw#42: recover legs must generate keys with the _RECOVER attributes.

sign_recover_single / verify_recover_single expect CKR_OK from the recover
inits, but _gen_recover_key used default SIGN|DECRYPT usage, so providers
that gate recover on CKA_SIGN_RECOVER / CKA_VERIFY_RECOVER refuse with
CKR_KEY_FUNCTION_NOT_PERMITTED. Recover is a declared RSAUsage purpose.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from pkcs11_check.raw import recipes
from pkcs11_check.raw.recipes import RSAUsage, gen_rsa_keypair, rsa_usage_attrs
from pkcs11_check.raw.types_std import CKA_SIGN_RECOVER, CKA_VERIFY_RECOVER, CKR_OK
from pkcs11_check.testcases import test_sign_recover


def test_rsa_usage_recover_maps_to_recover_attrs() -> None:
    """RECOVER usage must map to the private/public _RECOVER pair (fw#42)."""
    pub, priv = rsa_usage_attrs(RSAUsage.RECOVER)
    assert pub == {CKA_VERIFY_RECOVER: True}
    assert priv == {CKA_SIGN_RECOVER: True}


def _capture_gen_keypair(monkeypatch: Any) -> dict[str, Any]:
    """Replace recipes.gen_keypair with a capture stub; return captured attrs."""
    captured: dict[str, Any] = {}

    def fake_gen_keypair(
        raw: Any,
        session: int,
        mechanism: int,
        *,
        pub_base: Any,
        priv_base: Any,
        public_attrs: Any,
        private_attrs: Any,
        pub_skip: Any = None,
    ) -> tuple[int, int]:
        captured["public_attrs"] = dict(public_attrs)
        captured["private_attrs"] = dict(private_attrs)
        return (101, 102)

    monkeypatch.setattr(recipes, "gen_keypair", fake_gen_keypair)
    return captured


def test_gen_rsa_keypair_recover_usage_templates(monkeypatch: Any) -> None:
    """gen_rsa_keypair with RECOVER usage must template both _RECOVER attrs."""
    captured = _capture_gen_keypair(monkeypatch)
    pub_h, priv_h = gen_rsa_keypair(SimpleNamespace(), 7, usage=RSAUsage.RECOVER)
    assert (pub_h, priv_h) == (101, 102)
    assert captured["public_attrs"].get(CKA_VERIFY_RECOVER) is True
    assert captured["private_attrs"].get(CKA_SIGN_RECOVER) is True


def test_gen_recover_key_requests_recover_usage(monkeypatch: Any) -> None:
    """The recipe tests' key helper must request _RECOVER-capable keys (fw#42)."""
    captured = _capture_gen_keypair(monkeypatch)
    raw = SimpleNamespace(C_SignRecoverInit=lambda _s, _m, _k: int(CKR_OK))
    rs = SimpleNamespace(has_mechanism=lambda _m: True, raw=raw, sh=7)
    pub, priv = test_sign_recover.TestSignRecoverRecipes._gen_recover_key(rs)
    assert (pub, priv) == (101, 102)
    assert captured["public_attrs"].get(CKA_VERIFY_RECOVER) is True
    assert captured["private_attrs"].get(CKA_SIGN_RECOVER) is True
