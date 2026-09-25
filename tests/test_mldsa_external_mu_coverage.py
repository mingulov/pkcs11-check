"""Guardrails for ML-DSA ExternalMu semantic coverage."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from pkcs11_check.testcases import test_extended_mechanisms as tem


def test_external_mu_constants_are_exported() -> None:
    from pkcs11_check.raw import metadata_std
    from pkcs11_check.raw.types_std import CKM_ML_DSA_EXTERNAL_MU, CKM_ML_DSA_EXTERNAL_MU_GEN

    # OASIS TC v3.3 allocation (issue #58); the abandoned pre-ratification
    # v3.2 draft values 0x1E/0x22 must not be reintroduced.
    assert int(CKM_ML_DSA_EXTERNAL_MU_GEN) == 0x0000403B
    assert int(CKM_ML_DSA_EXTERNAL_MU) == 0x0000403C
    assert metadata_std.MECHANISM_NAMES[int(CKM_ML_DSA_EXTERNAL_MU_GEN)] == (
        "CKM_ML_DSA_EXTERNAL_MU_GEN"
    )
    assert metadata_std.MECHANISM_NAMES[int(CKM_ML_DSA_EXTERNAL_MU)] == "CKM_ML_DSA_EXTERNAL_MU"


def test_mu_gen_params_struct_is_exported() -> None:
    from pkcs11_check.raw import types_std

    fields = {name: ctype for name, ctype in types_std.CK_MU_GEN_PARAMS._fields_}

    assert fields["hKey"] is types_std.CK_OBJECT_HANDLE
    assert fields["pTR"] is types_std.CK_BYTE_PTR
    assert fields["ulTRLen"] is types_std.CK_ULONG
    assert fields["pctx"] is types_std.CK_BYTE_PTR
    assert fields["ulctxLen"] is types_std.CK_ULONG
    assert types_std.CK_MU_GEN_PARAMS_PTR._type_ is types_std.CK_MU_GEN_PARAMS


def test_external_mu_roundtrip_helper_uses_64_byte_mu(
    monkeypatch: Any,
) -> None:
    from pkcs11_check.raw.types_std import CKM_ML_DSA_EXTERNAL_MU, CKM_ML_DSA_KEY_PAIR_GEN

    calls: list[tuple[Any, ...]] = []
    session = SimpleNamespace(raw=object(), sh=11)

    def _gen_keypair(*_args: Any, **kwargs: Any) -> tuple[int, int]:
        calls.append(("gen", kwargs["mechanism"]))
        return 101, 202

    def _sign_single(_raw: Any, _sh: int, key: int, mechanism: int, mu: bytes) -> bytes:
        calls.append(("sign", key, mechanism, len(mu)))
        return b"external-mu-signature"

    def _verify_single(
        _raw: Any,
        _sh: int,
        key: int,
        mechanism: int,
        mu: bytes,
        signature: bytes,
    ) -> bool:
        calls.append(("verify", key, mechanism, len(mu), signature))
        return mu == tem._EXTERNAL_MU_SAMPLE

    monkeypatch.setattr(tem, "gen_keypair", _gen_keypair)
    monkeypatch.setattr(tem, "sign_single", _sign_single)
    monkeypatch.setattr(tem, "verify_single", _verify_single)
    monkeypatch.setattr(tem, "destroy_quietly", lambda *_args: None)

    tem._external_mu_sign_verify_roundtrip(session)

    assert len(tem._EXTERNAL_MU_SAMPLE) == 64
    assert calls == [
        ("gen", int(CKM_ML_DSA_KEY_PAIR_GEN)),
        ("sign", 202, int(CKM_ML_DSA_EXTERNAL_MU), 64),
        ("verify", 101, int(CKM_ML_DSA_EXTERNAL_MU), 64, b"external-mu-signature"),
        ("verify", 101, int(CKM_ML_DSA_EXTERNAL_MU), 64, b"external-mu-signature"),
    ]
