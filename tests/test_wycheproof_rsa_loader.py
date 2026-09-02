"""Regression tests for Wycheproof RSA vector adaptation."""

from __future__ import annotations

import json
from typing import Any

import pytest

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


def test_rsa_oaep_loader_retains_multiprime_material(tmp_path: Any, monkeypatch: Any) -> None:
    """OAEP vectors retain exact PKCS#8 and multi-prime metadata for provisioning."""
    payload = {
        "testGroups": [
            {
                "keySize": 2048,
                "sha": "SHA-1",
                "mgfSha": "SHA-1",
                "privateKey": {
                    "modulus": "01",
                    "publicExponent": "03",
                    "privateExponent": "01",
                    "prime1": "01",
                    "prime2": "01",
                    "exponent1": "01",
                    "exponent2": "01",
                    "coefficient": "01",
                    "otherPrimeInfos": [["02", "03", "04"]],
                },
                "privateKeyPkcs8": "deadbeef",
                "tests": [{"tcId": 1, "result": "valid", "ct": "00", "msg": ""}],
            }
        ]
    }
    filename = "synthetic_oaep.json"
    (tmp_path / filename).write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(rsa_oaep, "WYCHEPROOF_DIR", tmp_path)
    monkeypatch.setattr(rsa_oaep, "_OAEP_FILES", [filename])

    vectors = rsa_oaep._load_oaep_vectors()

    assert vectors[0][1]["_pkcs8_hex"] == "deadbeef"
    assert vectors[0][1]["_other_prime_infos"] == [["02", "03", "04"]]


@pytest.mark.parametrize(
    ("other_prime_infos", "modulus"),
    [([], "01"), (["extra-prime"], "01"), ([], "02")],
)
def test_rsa_oaep_caller_only_passes_pkcs8_for_multiprime(
    monkeypatch: Any, other_prime_infos: list[str], modulus: str
) -> None:
    """OAEP passes corpus PKCS#8 only for explicit or inferred multi-prime keys."""
    private_key = {
        "modulus": modulus,
        "publicExponent": "03",
        "privateExponent": "01",
        "prime1": "01",
        "prime2": "01",
        "exponent1": "01",
        "exponent2": "01",
        "coefficient": "01",
    }
    if other_prime_infos:
        private_key["otherPrimeInfos"] = other_prime_infos
    vec = {
        "ct": "00",
        "msg": "",
        "result": "valid",
        "label": "",
        "_sha": "SHA-1",
        "_mgfSha": "SHA-1",
        "_pkcs8_hex": "deadbeef",
        "_other_prime_infos": other_prime_infos,
        "_group": {"privateKey": private_key, "privateKeyPkcs8": "deadbeef"},
    }
    captured: dict[str, Any] = {}

    def fake_provision(rs: Any, cfg: Any, **kwargs: Any) -> int:
        captured.update(kwargs)
        return 1

    monkeypatch.setattr(rsa_oaep, "provision_rsa_private_key", fake_provision)
    monkeypatch.setattr(rsa_oaep, "decrypt_single", lambda *args, **kwargs: b"")
    monkeypatch.setattr(rsa_oaep, "destroy_quietly", lambda *args: None)

    rsa_oaep.test_rsa_oaep(_RsaSession(), None, "synthetic", vec)

    inferred_multiprime = bool(other_prime_infos) or modulus != "01"
    assert captured.get("pkcs8") == (b"\xde\xad\xbe\xef" if inferred_multiprime else None)
