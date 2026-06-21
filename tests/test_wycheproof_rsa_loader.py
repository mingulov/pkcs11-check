"""Regression tests for Wycheproof RSA vector adaptation."""

from __future__ import annotations

from typing import Any

from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_oaep as rsa_oaep
from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_pss as rsa_pss


class _RsaSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return True


def _find_pss(vec_id: str) -> dict[str, Any]:
    return next(vec for candidate_id, vec in rsa_pss._ALL_PSS_VECTORS if candidate_id == vec_id)


def _find_oaep(vec_id: str) -> dict[str, Any]:
    return next(vec for candidate_id, vec in rsa_oaep._ALL_OAEP_VECTORS if candidate_id == vec_id)


def test_rsa_pss_import_uses_unsigned_pkcs11_bigint_encoding(
    monkeypatch: Any,
) -> None:
    """Wycheproof RSA public-key sign padding must not be imported as modulus."""
    vec_id = "rsa_pss_2048_sha1_mgf1_20_params_test.json:tc1-valid"
    vec = _find_pss(vec_id)
    public_key = vec["_group"]["publicKey"]
    assert public_key["modulus"].startswith("00")

    captured: dict[str, bytes] = {}

    def fake_import_rsa_public_key(
        rs: object,
        *,
        n: bytes,
        e: bytes,
        attrs: dict[int, Any],
        purpose: str = "",
    ) -> int:
        captured["n"] = n
        captured["e"] = e
        return 1

    monkeypatch.setattr(rsa_pss, "import_rsa_public_key_negotiated", fake_import_rsa_public_key)
    monkeypatch.setattr(rsa_pss, "verify_single", lambda *args, **kwargs: True)
    monkeypatch.setattr(rsa_pss, "destroy_quietly", lambda *args: None)
    monkeypatch.setattr(rsa_pss, "generate_random", lambda *args: b"")

    rsa_pss.test_rsa_pss(_RsaSession(), vec_id, vec)

    assert not captured["n"].startswith(b"\x00")
    assert len(captured["n"]) == 256
    assert captured["e"] == b"\x01\x00\x01"


def test_rsa_oaep_import_uses_unsigned_pkcs11_bigint_encoding(
    monkeypatch: Any,
) -> None:
    """Wycheproof RSA private-key sign padding must not be imported as CRT data."""
    vec_id = "rsa_oaep_2048_sha1_mgf1sha1_test.json:tc1-valid"
    vec = _find_oaep(vec_id)
    private_key = vec["_group"]["privateKey"]
    assert private_key["modulus"].startswith("00")
    assert private_key["prime1"].startswith("00")
    assert private_key["prime2"].startswith("00")

    captured: dict[str, bytes] = {}

    def fake_import_rsa_private_key(
        rs: object,
        cfg: object,
        *,
        n: bytes,
        e: bytes,
        d: bytes,
        p: bytes,
        q: bytes,
        dmp1: bytes,
        dmq1: bytes,
        iqmp: bytes,
        attrs: dict[int, Any],
        label: str = "",
    ) -> int:
        captured.update(n=n, e=e, d=d, p=p, q=q, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp)
        return 1

    monkeypatch.setattr(rsa_oaep, "provision_rsa_private_key", fake_import_rsa_private_key)
    monkeypatch.setattr(
        rsa_oaep, "decrypt_single", lambda *args, **kwargs: bytes.fromhex(vec["msg"])
    )
    monkeypatch.setattr(rsa_oaep, "destroy_quietly", lambda *args: None)

    rsa_oaep.test_rsa_oaep(_RsaSession(), None, vec_id, vec)

    assert not captured["n"].startswith(b"\x00")
    assert len(captured["n"]) == 256
    assert not captured["p"].startswith(b"\x00")
    assert len(captured["p"]) == 128
    assert not captured["q"].startswith(b"\x00")
    assert len(captured["q"]) == 128
