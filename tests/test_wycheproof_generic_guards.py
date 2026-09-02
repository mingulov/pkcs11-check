"""Regression tests for generic Wycheproof mechanism guards."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.config import P11TestConfig
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_SIGNATURE_INVALID,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases.wycheproof import test_wycheproof as wy


class _NoMechanismSession:
    raw = object()
    sh = 1

    def __init__(self) -> None:
        self.checked: list[str] = []

    def has_mechanism(self, name: str) -> bool:
        self.checked.append(name)
        return False


def _fail_if_called(*_args: Any, **_kwargs: Any) -> int:
    raise AssertionError("PKCS#11 operation reached before mechanism guard")


_STUB_CFG = P11TestConfig(module=Path("/stub.so"), key_inject="off")


@pytest.fixture(autouse=True)
def _clear_classifications() -> None:
    classification.clear()


def _negative_vector(case: str) -> dict[str, Any]:
    common = {"tcId": 1, "result": "invalid", "_source": "synthetic", "_vector_id": "tc1"}
    if case == "gcm":
        return {
            **common,
            "key": "00" * 16,
            "iv": "00" * 12,
            "aad": "",
            "msg": "",
            "ct": "",
            "tag": "00" * 16,
            "flags": ["ModifiedTag"],
            "_group": {},
        }
    if case == "hmac":
        return {
            **common,
            "key": "00" * 32,
            "msg": "",
            "tag": "ff" * 32,
            "flags": ["ModifiedTag"],
            "_group": {"tagSize": 256},
        }
    return {
        **common,
        "key": "00" * 16,
        "iv": "00" * 16,
        "msg": "",
        "ct": "00" * 16,
        "flags": ["BadPadding"],
        "_group": {},
    }


def _run_negative(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    operation: Callable[..., Any],
    *,
    sign_operation: Callable[..., Any] | None = None,
) -> None:
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)
    monkeypatch.setattr(wy, "provision_secret_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(wy, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(wy, "generate_random", lambda *_a, **_k: b"")
    if case == "hmac":
        monkeypatch.setattr(wy, "sign_single", sign_operation or operation, raising=False)
        monkeypatch.setattr(wy, "verify_single", operation)
        wy.TestHMACSHA256Wycheproof().test_hmac_sha256(session, _STUB_CFG, _negative_vector(case))
    elif case == "gcm":
        monkeypatch.setattr(wy, "decrypt_single", operation)
        wy.TestAESGCMWycheproof().test_aes_gcm(session, _STUB_CFG, _negative_vector(case))
    else:
        monkeypatch.setattr(wy, "decrypt_single", operation)
        wy.TestAESCBCPKCS5Wycheproof().test_aes_cbc_pkcs5(
            session, _STUB_CFG, _negative_vector(case)
        )


@pytest.mark.parametrize(
    ("case_factory", "method_name", "vector_factory", "expected_mechanism", "needs_cfg"),
    [
        (wy.TestAESGCMWycheproof, "test_aes_gcm", wy._load_aes_gcm_vectors, "AES_GCM", True),
        (
            wy.TestHMACSHA256Wycheproof,
            "test_hmac_sha256",
            wy._load_hmac_sha256_vectors,
            "SHA256_HMAC",
            True,
        ),
        (
            wy.TestECDSAP256Wycheproof,
            "test_ecdsa_p256_sha256_verify",
            wy._load_ecdsa_p256_vectors,
            "ECDSA",
            False,
        ),
        (
            wy.TestECDSAP384Wycheproof,
            "test_ecdsa_p384_sha384_verify",
            wy._load_ecdsa_p384_vectors,
            "ECDSA",
            False,
        ),
        (
            wy.TestAESCBCPKCS5Wycheproof,
            "test_aes_cbc_pkcs5",
            wy._load_aes_cbc_pkcs5_vectors,
            "AES_CBC_PAD",
            True,
        ),
        (
            wy.TestRSASigWycheproof,
            "test_rsa_sig_2048_sha256",
            wy._load_rsa_sig_vectors,
            "SHA256_RSA_PKCS",
            False,
        ),
    ],
)
def test_generic_wycheproof_skips_when_mechanism_missing(
    monkeypatch: pytest.MonkeyPatch,
    case_factory: Callable[[], object],
    method_name: str,
    vector_factory: Callable[[], list[dict[str, Any]]],
    expected_mechanism: str,
    needs_cfg: bool,
) -> None:
    """Missing mechanisms are capability skips, not failed vector tests."""
    monkeypatch.setattr(wy, "provision_secret_key", _fail_if_called)
    monkeypatch.setattr(wy, "import_ec_public_key_negotiated", _fail_if_called)
    monkeypatch.setattr(wy, "import_rsa_public_key_negotiated", _fail_if_called)

    session = _NoMechanismSession()
    method = getattr(case_factory(), method_name)

    with pytest.raises(pytest.skip.Exception, match="not supported"):
        if needs_cfg:
            method(session, _STUB_CFG, vector_factory()[0])
        else:
            method(session, vector_factory()[0])

    assert session.checked == [expected_mechanism]


class _EcdsaSession(_NoMechanismSession):
    def has_mechanism(self, name: str) -> bool:
        self.checked.append(name)
        return name == "ECDSA"


def test_generic_ecdsa_p384_broad_import_reject_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Batch 3b (A13): a broad P-384 import reject -> xfail (advertised but not operational).

    Reconciles the prior ``..._skips_unsupported_curve_import`` pin: ECDSA is
    advertised, so a broad import-failure CKR is no longer a capability skip.
    """

    def reject_curve(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected CKR_OK",
            int(CKR_ATTRIBUTE_VALUE_INVALID),
        )

    monkeypatch.setattr(wy, "import_ec_public_key_negotiated", reject_curve)
    monkeypatch.setattr(
        wy.pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}")
    )

    session = _EcdsaSession()
    vec = wy._load_ecdsa_p384_vectors()[0]

    with pytest.raises(pytest.xfail.Exception, match="ECDSA:key-import"):
        wy.TestECDSAP384Wycheproof().test_ecdsa_p384_sha384_verify(session, vec)

    assert session.checked == ["ECDSA"]


def test_generic_ecdsa_p384_curve_unsupported_still_skips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Batch 3b (A13): a curve-absence import CKR keeps the genuine-absence skip."""

    def reject_curve(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_CURVE_NOT_SUPPORTED; expected CKR_OK",
            int(CKR_CURVE_NOT_SUPPORTED),
        )

    monkeypatch.setattr(wy, "import_ec_public_key_negotiated", reject_curve)

    session = _EcdsaSession()
    vec = wy._load_ecdsa_p384_vectors()[0]

    with pytest.raises(pytest.skip.Exception, match="Cannot import EC public key on this module"):
        wy.TestECDSAP384Wycheproof().test_ecdsa_p384_sha384_verify(session, vec)

    assert session.checked == ["ECDSA"]


@pytest.mark.parametrize(
    ("rv", "operation"),
    [
        (CKR_GENERAL_ERROR, "AES-GCM decrypt"),
        (CKR_GENERAL_ERROR, "AES-CBC-PAD decrypt"),
        (CKR_GENERAL_ERROR, "HMAC-SHA256 sign"),
        (CKR_ARGUMENTS_BAD, "RSA PKCS#1 verify"),
        (CKR_DEVICE_ERROR, "RSA PKCS#1 verify"),
    ],
)
def test_generic_wycheproof_valid_runtime_rejects_are_xfail(
    rv: int,
    operation: str,
) -> None:
    """Advertised generic Wycheproof operation rejects are findings."""
    exc = CkrAssertionError("Unexpected CK_RV", int(rv))

    with pytest.raises(pytest.xfail.Exception, match=operation):
        wy._xfail_if_generic_runtime_reject(exc, "tc1-valid", operation)


def test_generic_hmac_key_import_reject_is_xfail() -> None:
    """Advertised HMAC key import rejection is setup evidence, not a raw failure."""
    exc = CkrAssertionError("Unexpected CK_RV", int(CKR_KEY_SIZE_RANGE))

    with pytest.raises(pytest.xfail.Exception, match="HMAC-SHA256 key import"):
        wy._xfail_if_generic_runtime_reject(exc, "tc163-valid", "HMAC-SHA256 key import")


@pytest.mark.parametrize("case", ["gcm", "hmac", "cbc"])
@pytest.mark.parametrize(
    "rv",
    [int(CKR_DEVICE_ERROR), int(CKR_GENERAL_ERROR), int(CKR_VENDOR_DEFINED) + 1],
)
def test_generic_negative_other_clean_rejects_are_visible_xfails(
    monkeypatch: pytest.MonkeyPatch, case: str, rv: int
) -> None:
    def reject(*_args: Any, **_kwargs: Any) -> Any:
        raise CkrAssertionError("negative vector rejected", rv)

    with pytest.raises(pytest.xfail.Exception):
        _run_negative(monkeypatch, case, reject)
    assert classification.get_records()[-1].reason == "nonspec_reject"


@pytest.mark.parametrize("case", ["gcm", "hmac", "cbc"])
def test_generic_negative_undefined_ckr_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    def reject(*_args: Any, **_kwargs: Any) -> Any:
        raise CkrAssertionError("negative vector rejected", 0x7FFFFFFF)

    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        _run_negative(monkeypatch, case, reject)
    assert classification.get_records()[-1].reason == "self_contradiction"


@pytest.mark.parametrize("case", ["gcm", "hmac", "cbc"])
def test_generic_negative_non_ckr_assertion_propagates(
    monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    def reject(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("local harness bug")

    with pytest.raises(AssertionError, match="local harness bug"):
        _run_negative(monkeypatch, case, reject)


def _run_valid_gcm(
    monkeypatch: pytest.MonkeyPatch,
    operation: Callable[..., Any],
    *,
    oversized_iv: bool = False,
) -> None:
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)
    vectors = wy._load_aes_gcm_vectors()
    vec = next(
        v
        for v in vectors
        if v["result"] == "valid" and (len(bytes.fromhex(v["iv"])) > 16) == oversized_iv
    )
    monkeypatch.setattr(wy, "provision_secret_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(wy, "decrypt_single", operation)
    monkeypatch.setattr(wy, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(wy, "generate_random", lambda *_a, **_k: b"")
    wy.TestAESGCMWycheproof().test_aes_gcm(session, _STUB_CFG, vec)


def test_gcm_valid_wrong_plaintext_is_a_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful decrypt with wrong plaintext must not be routed as a CKR."""

    with pytest.raises(pytest.fail.Exception, match="does not match known answer"):
        _run_valid_gcm(monkeypatch, lambda *_a, **_k: b"wrong plaintext")


def test_gcm_valid_plain_decrypt_error_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A local decrypt error must remain a harness failure on a valid vector."""

    def reject(*_args: Any, **_kwargs: Any) -> Any:
        raise TypeError("binding bug")

    with pytest.raises(TypeError, match="binding bug"):
        _run_valid_gcm(monkeypatch, reject)


def test_gcm_oversized_iv_accepts_only_optional_reject_ckrs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Oversized valid-vector IV rejection is optional only for the exact CKR set."""

    def reject(*_args: Any, **_kwargs: Any) -> Any:
        raise CkrAssertionError("optional IV rejected", int(CKR_MECHANISM_PARAM_INVALID))

    _run_valid_gcm(monkeypatch, reject, oversized_iv=True)


def test_gcm_oversized_iv_unexpected_ckr_is_visible(monkeypatch: pytest.MonkeyPatch) -> None:
    """A generic reject for an oversized IV is not silently accepted."""

    def reject(*_args: Any, **_kwargs: Any) -> Any:
        raise CkrAssertionError("unexpected reject", int(CKR_GENERAL_ERROR))

    with pytest.raises(pytest.xfail.Exception, match="optional IV length"):
        _run_valid_gcm(monkeypatch, reject, oversized_iv=True)


def test_gcm_oversized_iv_undefined_ckr_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An undefined CK_RV from the optional-IV path remains a hard failure."""

    def reject(*_args: Any, **_kwargs: Any) -> Any:
        raise CkrAssertionError("undefined reject", 0x7FFFFFFF)

    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        _run_valid_gcm(monkeypatch, reject, oversized_iv=True)


@pytest.mark.parametrize("case", ["gcm", "hmac", "cbc"])
def test_generic_negative_setup_reject_is_visible(
    monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    monkeypatch.setattr(
        wy,
        "provision_secret_key",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("valid subject key import rejected", int(CKR_KEY_SIZE_RANGE))
        ),
    )
    monkeypatch.setattr(
        wy,
        "decrypt_single",
        lambda *_a, **_k: pytest.fail("operation reached after setup rejection"),
    )
    monkeypatch.setattr(
        wy,
        "sign_single",
        lambda *_a, **_k: pytest.fail("operation reached after setup rejection"),
        raising=False,
    )
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)

    with pytest.raises(pytest.xfail.Exception, match="key import"):
        if case == "gcm":
            wy.TestAESGCMWycheproof().test_aes_gcm(session, _STUB_CFG, _negative_vector(case))
        elif case == "hmac":
            wy.TestHMACSHA256Wycheproof().test_hmac_sha256(
                session, _STUB_CFG, _negative_vector(case)
            )
        else:
            wy.TestAESCBCPKCS5Wycheproof().test_aes_cbc_pkcs5(
                session, _STUB_CFG, _negative_vector(case)
            )


@pytest.mark.parametrize("case", ["gcm", "hmac", "cbc"])
def test_generic_negative_success_is_hard_accepted_invalid(
    monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    def operation(*_args: Any, **_kwargs: Any) -> bool | bytes:
        return True if case == "hmac" else b""

    with pytest.raises(pytest.fail.Exception, match="[Ii]nvalid"):
        _run_negative(
            monkeypatch,
            case,
            operation,
            sign_operation=(lambda *_a, **_k: b"\x00" * 32) if case == "hmac" else None,
        )
    assert classification.get_records()[-1].reason == "accepted_invalid"


@pytest.mark.parametrize(
    ("case", "rv"),
    [
        ("gcm", int(CKR_ENCRYPTED_DATA_INVALID)),
        ("hmac", int(CKR_SIGNATURE_INVALID)),
        ("cbc", int(CKR_ENCRYPTED_DATA_INVALID)),
    ],
)
def test_generic_negative_expected_reject_passes(
    monkeypatch: pytest.MonkeyPatch, case: str, rv: int
) -> None:
    def reject(*_args: Any, **_kwargs: Any) -> Any:
        raise CkrAssertionError("negative vector rejected", rv)

    _run_negative(monkeypatch, case, reject)
    assert classification.get_records() == []


def test_generic_gcm_valid_wrong_plaintext_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A wrong valid-vector plaintext is a crypto finding, not a runtime reject."""
    vec = next(v for v in wy._load_aes_gcm_vectors() if v["result"] == "valid")
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)
    monkeypatch.setattr(wy, "provision_secret_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(wy, "decrypt_single", lambda *_a, **_k: b"\xff")
    monkeypatch.setattr(wy, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(wy, "generate_random", lambda *_a, **_k: b"")

    with pytest.raises(pytest.fail.Exception, match="does not match known answer"):
        wy.TestAESGCMWycheproof().test_aes_gcm(session, _STUB_CFG, vec)


def test_generic_gcm_plain_decrypt_assertion_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A local assertion in the decrypt binding must remain a harness failure."""
    vec = next(v for v in wy._load_aes_gcm_vectors() if v["result"] == "valid")
    session = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)
    monkeypatch.setattr(wy, "provision_secret_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        wy,
        "decrypt_single",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("binding bug")),
    )
    monkeypatch.setattr(wy, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(AssertionError, match="binding bug"):
        wy.TestAESGCMWycheproof().test_aes_gcm(session, _STUB_CFG, vec)
