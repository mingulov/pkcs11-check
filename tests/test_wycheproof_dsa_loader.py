"""Regression tests for Wycheproof DSA vector adaptation."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR
from pkcs11_check.testcases.wycheproof import test_wycheproof_dsa as dsa


class _Session:
    raw = object()
    sh = 1

    @staticmethod
    def has_mechanism(_name: str) -> bool:
        return True


def _invalid_signature_vector() -> tuple[str, dict[str, Any]]:
    return next(
        (vec_id, vec)
        for vec_id, vec in dsa._ALL_DSA_VECTORS
        if vec["result"] == "invalid"
        and "_pkcs11_duplicate_of" not in vec
        and "_pkcs11_sig_error" not in vec
    )


def test_der_dsa_vectors_have_pkcs11_p1363_signature() -> None:
    """Valid DER DSA signatures are converted to raw r||s for C_Verify."""
    _vec_id, vec = next(
        (vec_id, item)
        for vec_id, item in dsa._ALL_DSA_VECTORS
        if not item["_is_p1363"] and item["result"] == "valid"
    )
    q = int.from_bytes(bytes.fromhex(vec["_group"]["publicKey"]["q"]), "big")
    q_len = (q.bit_length() + 7) // 8
    sig = bytes.fromhex(vec.get("_pkcs11_sig", ""))

    assert len(sig) == 2 * q_len
    assert sig[0] != 0x30


def test_dsa_import_uses_unsigned_pkcs11_bigint_encoding(monkeypatch: Any) -> None:
    """Wycheproof DSA JSON sign-padding must not be imported as key material."""
    vec_id, vec = next(
        (item_vec_id, item)
        for item_vec_id, item in dsa._ALL_DSA_VECTORS
        if item_vec_id == "dsa_2048_224_sha224_test.json:tc2-valid"
    )
    public_key = vec["_group"]["publicKey"]
    assert public_key["p"].startswith("00")
    assert public_key["q"].startswith("00")

    captured: dict[str, bytes] = {}

    class FakeSession:
        raw = object()
        sh = 1

        def has_mechanism(self, name: str) -> bool:
            return True

    def fake_import_dsa_public_key(
        raw: object,
        session: int,
        *,
        prime: bytes,
        subprime: bytes,
        base_g: bytes,
        value: bytes,
        attrs: dict[int, Any],
    ) -> int:
        captured.update(
            prime=prime,
            subprime=subprime,
            base_g=base_g,
            value=value,
        )
        return 1

    def fake_verify_single(
        raw: object,
        session: int,
        key: int,
        mechanism: int,
        msg: bytes,
        sig: bytes,
    ) -> bool:
        captured["sig"] = sig
        return True

    monkeypatch.setattr(dsa, "import_dsa_public_key", fake_import_dsa_public_key)
    monkeypatch.setattr(dsa, "verify_single", fake_verify_single)
    monkeypatch.setattr(dsa, "destroy_quietly", lambda *args: None)
    monkeypatch.setattr(dsa, "generate_random", lambda *args: b"")

    dsa.test_dsa(FakeSession(), vec_id, vec)

    assert not captured["prime"].startswith(b"\x00")
    assert len(captured["prime"]) == 256
    assert not captured["subprime"].startswith(b"\x00")
    assert len(captured["subprime"]) == 28
    assert len(captured["sig"]) == 56


def test_invalid_signature_valid_key_import_reject_is_visible_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec_id, vec = _invalid_signature_vector()
    monkeypatch.setattr(
        dsa,
        "import_dsa_public_key",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("valid DSA key import rejected", int(CKR_DEVICE_ERROR))
        ),
    )
    monkeypatch.setattr(
        dsa,
        "verify_single",
        lambda *_a, **_k: pytest.fail("signature verdict must not run without the valid key"),
    )

    try:
        dsa.test_dsa(_Session(), vec_id, vec)
    except BaseException as exc:
        assert isinstance(exc, pytest.xfail.Exception)
        assert "DSA:key-import" in str(exc)
    else:
        pytest.fail("valid-key import rejection was hidden")


def test_dsa_key_import_non_ckr_assertion_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec_id, vec = _invalid_signature_vector()
    monkeypatch.setattr(
        dsa,
        "import_dsa_public_key",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("harness bug")),
    )

    try:
        dsa.test_dsa(_Session(), vec_id, vec)
    except BaseException as exc:
        assert type(exc) is AssertionError
        assert "harness bug" in str(exc)
    else:
        pytest.fail("non-CKR assertion was hidden")
