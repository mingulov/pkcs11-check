"""Regression tests for Wycheproof AES MAC/AEAD/keywrap invalid-vector classification.

Phase-2 V2: these families were exercised as *produce* operations
(sign/encrypt/wrap), so a fresh correct output never matched the modified
expected output and rejection of invalid vectors was never tested. They are
re-framed to the verify/decrypt/unwrap direction; a module that ACCEPTS an
invalid vector is a crypto-correctness break (crypto -> fail).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_VALUE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_GENERAL_ERROR,
    CKR_SIGNATURE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_VENDOR_DEFINED,
    CKR_WRAPPED_KEY_INVALID,
)
from pkcs11_check.testcases.wycheproof import test_wycheproof_aes as aes

_NO_VECTORS = "Wycheproof vectors not available (run `pkcs11-check fetch-data wycheproof`)"


def _vec(vecs: list[tuple[str, dict[str, Any]]], vec_id: str) -> dict[str, Any]:
    hit = next((v for cid, v in vecs if cid == vec_id), None)
    if hit is None:
        pytest.skip(_NO_VECTORS)
    return hit


def _first(vecs: list[tuple[str, dict[str, Any]]], result: str) -> tuple[str, dict[str, Any]]:
    hit = next(((cid, v) for cid, v in vecs if v["result"] == result), None)
    if hit is None:
        pytest.skip(_NO_VECTORS)
    return hit


class _AesSession:
    raw = object()
    sh = 1

    def __init__(self, mech: str) -> None:
        self._mech = mech

    def has_mechanism(self, name: str) -> bool:
        return name == self._mech


def _handle(*_args: Any, **_kwargs: Any) -> int:
    return 1


# --- AES-CMAC (Task 2d) ---


def test_cmac_invalid_vector_accepted_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid CMAC tag that verifies must fail (forged-tag accepted)."""
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(aes, "generate_random", lambda *_a, **_k: b"")

    with pytest.raises(pytest.fail.Exception, match="accepted invalid tag"):
        aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)


def test_cmac_valid_vector_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid CMAC vector that verifies passes (no exception)."""
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(aes, "generate_random", lambda *_a, **_k: b"")

    aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)


def test_cmac_valid_vector_rejected_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid CMAC vector that does not verify is a finding (fail)."""
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: False)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(aes, "generate_random", lambda *_a, **_k: b"")

    with pytest.raises(pytest.fail.Exception, match="valid CMAC vector"):
        aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)


def test_cmac_invalid_setup_refusal_is_visible(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid result cannot turn subject-key setup refusal into a pass."""
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "invalid")

    def _reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(aes, "import_secret_key_negotiated", _reject)

    with pytest.raises(pytest.xfail.Exception, match="not operational"):
        aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)


def test_cmac_invalid_setup_non_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-CKR setup assertion is a harness defect, not an invalid-vector pass."""
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "invalid")

    def _reject(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("template packing failed")

    monkeypatch.setattr(aes, "import_secret_key_negotiated", _reject)

    with pytest.raises(AssertionError, match="template packing failed"):
        aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)


def test_cmac_invalid_setup_undefined_ckr_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "invalid")

    def _reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("undefined setup result", 0x7FFFFFFF)

    monkeypatch.setattr(aes, "import_secret_key_negotiated", _reject)

    classification.clear()
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)
    assert classification.get_records()[-1].reason == "self_contradiction"


@pytest.mark.parametrize("rv", [CKR_ATTRIBUTE_VALUE_INVALID, CKR_TEMPLATE_INCONSISTENT])
def test_cmac_invalid_key_size_setup_refusal_is_expected(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    """Only the corpus's InvalidKeySize import target may pass setup refusal."""
    # Keep the vector's InvalidKeySize marker while using the ordinary fixture
    # helper to avoid coupling this guard to a particular group ordering.
    vec = next(v for cid, v in aes._AES_CMAC_VECTORS if cid == "tc307-invalid")

    def _reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("invalid key size", int(rv))

    monkeypatch.setattr(aes, "import_secret_key_negotiated", _reject)
    aes.test_aes_cmac(_AesSession("AES_CMAC"), "tc307-invalid", vec)


@pytest.mark.parametrize(
    "rv",
    [CKR_DEVICE_ERROR, CKR_GENERAL_ERROR, CKR_VENDOR_DEFINED + 1],
    ids=["device-error", "general-error", "vendor-defined"],
)
def test_cmac_invalid_clean_reject_is_classified(monkeypatch: pytest.MonkeyPatch, rv: int) -> None:
    """Unexpected clean invalid-tag rejects are visible nonspec deviations."""
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(
        aes,
        "verify_single",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("unexpected clean rejection", int(rv))
        ),
    )
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    classification.clear()
    with pytest.raises(pytest.xfail.Exception):
        aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)
    assert classification.get_records()[-1].reason == "nonspec_reject"


def test_cmac_invalid_expected_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(
        aes,
        "verify_single",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("expected clean rejection", int(CKR_SIGNATURE_INVALID))
        ),
    )
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)


def test_cmac_invalid_undefined_reject_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(
        aes,
        "verify_single",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("undefined rejection", 0x7FFFFFFF)
        ),
    )
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    classification.clear()
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)
    assert classification.get_records()[-1].reason == "self_contradiction"


def test_cmac_invalid_non_ckr_reject_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(
        aes,
        "verify_single",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("not a CKR")),
    )
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(AssertionError, match="not a CKR"):
        aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)


@pytest.mark.parametrize(
    "rv",
    [CKR_DEVICE_ERROR, CKR_GENERAL_ERROR, CKR_VENDOR_DEFINED + 1],
    ids=["device-error", "general-error", "vendor-defined"],
)
def test_cmac_valid_clean_refusal_is_visible(monkeypatch: pytest.MonkeyPatch, rv: int) -> None:
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(
        aes,
        "verify_single",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("valid operation refusal", int(rv))
        ),
    )
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    classification.clear()
    with pytest.raises(pytest.xfail.Exception):
        aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)
    record = classification.get_records()[-1]
    assert record.reason == (
        "not_operational" if rv in (CKR_DEVICE_ERROR, CKR_GENERAL_ERROR) else "nonspec_reject"
    )


def test_cmac_valid_undefined_clean_refusal_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(
        aes,
        "verify_single",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("undefined valid operation", 0x7FFFFFFF)
        ),
    )
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    classification.clear()
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)
    assert classification.get_records()[-1].reason == "self_contradiction"


def test_cmac_valid_non_ckr_refusal_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(
        aes,
        "verify_single",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("binding bug")),
    )
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(AssertionError, match="binding bug"):
        aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)


# --- AES-GMAC (Task 2e) ---


def test_gmac_invalid_vector_accepted_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid GMAC tag that verifies must fail (forged-tag accepted)."""
    vec_id, vec = _first(aes._AES_GMAC_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid tag"):
        aes.test_aes_gmac(_AesSession("AES_GMAC"), vec_id, vec)


def test_gmac_valid_vector_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid GMAC vector that verifies passes (no exception)."""
    vec_id, vec = _first(aes._AES_GMAC_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    aes.test_aes_gmac(_AesSession("AES_GMAC"), vec_id, vec)


def test_gmac_valid_vector_rejected_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid GMAC vector that does not verify is a finding (fail)."""
    vec_id, vec = _first(aes._AES_GMAC_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: False)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="valid GMAC vector"):
        aes.test_aes_gmac(_AesSession("AES_GMAC"), vec_id, vec)


def test_gmac_invalid_expected_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    vec_id, vec = _first(aes._AES_GMAC_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(
        aes,
        "verify_single",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("expected clean rejection", int(CKR_SIGNATURE_INVALID))
        ),
    )
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    aes.test_aes_gmac(_AesSession("AES_GMAC"), vec_id, vec)


# --- AES-CCM (Task 2f) ---


def test_ccm_invalid_vector_decrypt_success_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid CCM vector that decrypts must fail (forged ciphertext/tag accepted)."""
    vec_id, vec = _first(aes._AES_CCM_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "decrypt_single", lambda *_a, **_k: bytes.fromhex(vec["msg"]))
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid ciphertext"):
        aes.test_aes_ccm(_AesSession("AES_CCM"), vec_id, vec)


def test_ccm_valid_vector_decrypts(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid CCM vector that decrypts to the expected plaintext passes."""
    vec_id, vec = _first(aes._AES_CCM_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "decrypt_single", lambda *_a, **_k: bytes.fromhex(vec["msg"]))
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)
    aes.test_aes_ccm(_AesSession("AES_CCM"), vec_id, vec)


def test_ccm_valid_vector_clean_reject_xfails_when_not_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid CCM vector cleanly rejected (ENCRYPTED_DATA_INVALID) when the
    canonical CCM probe is NOT operational is an advertised-but-not-operational
    deviation -> xfail, not a hard fail. (bouncyhsm CCM: 357 such rejects.)"""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_ENCRYPTED_DATA_INVALID
    from pkcs11_check.testcases._operability import Operability, OperabilityResult

    vec_id, vec = _first(aes._AES_CCM_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)

    def _reject(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID", int(CKR_ENCRYPTED_DATA_INVALID)
        )

    monkeypatch.setattr(aes, "decrypt_single", _reject)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(
        aes,
        "_ccm_operability",
        lambda *_a: OperabilityResult(Operability.NOT_OPERATIONAL, "canonical CCM rejected"),
    )

    with pytest.raises(pytest.xfail.Exception, match="not operational"):
        aes.test_aes_ccm(_AesSession("AES_CCM"), vec_id, vec)


def test_ccm_valid_vector_wrong_plaintext_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid CCM vector that decrypts to the wrong plaintext is a finding (fail)."""
    vec_id = "tc2-valid"
    vec = _vec(aes._AES_CCM_VECTORS, vec_id)
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "decrypt_single", lambda *_a, **_k: b"\xde\xad\xbe\xef")
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="does not match known answer"):
        aes.test_aes_ccm(_AesSession("AES_CCM"), vec_id, vec)


@pytest.mark.parametrize(
    "rv",
    [CKR_DEVICE_ERROR, CKR_GENERAL_ERROR, CKR_VENDOR_DEFINED + 1],
    ids=["device-error", "general-error", "vendor-defined"],
)
def test_ccm_invalid_clean_reject_is_classified(monkeypatch: pytest.MonkeyPatch, rv: int) -> None:
    vec_id, vec = _first(aes._AES_CCM_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(
        aes,
        "decrypt_single",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("unexpected clean rejection", int(rv))
        ),
    )
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    classification.clear()
    with pytest.raises(pytest.xfail.Exception):
        aes.test_aes_ccm(_AesSession("AES_CCM"), vec_id, vec)
    assert classification.get_records()[-1].reason == "nonspec_reject"


def test_ccm_invalid_expected_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.testcases._operability import Operability, OperabilityResult

    vec_id, vec = _first(aes._AES_CCM_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(
        aes,
        "decrypt_single",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("expected clean rejection", int(CKR_ENCRYPTED_DATA_INVALID))
        ),
    )
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(
        aes,
        "_ccm_operability",
        lambda *_a: OperabilityResult(Operability.OPERATIONAL, "canonical CCM worked"),
    )

    aes.test_aes_ccm(_AesSession("AES_CCM"), vec_id, vec)


# --- AES-KW (Task 2g) ---


def test_aes_kw_invalid_vector_unwrap_success_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid AES-KW blob that unwraps must fail (forged wrap accepted)."""
    vec_id, vec = _first(aes._AES_WRAP_VECTORS, "invalid")
    msg = bytes.fromhex(vec["msg"])
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "unwrap_key", _handle)
    monkeypatch.setattr(aes, "read_attributes", lambda *_a, **_k: {CKA_VALUE: msg})
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid wrapped key"):
        aes.test_aes_key_wrap(_AesSession("AES_KEY_WRAP"), vec_id, vec)


def test_aes_kw_valid_vector_unwraps(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid AES-KW blob that unwraps to the expected key material passes."""
    vec_id, vec = _first(aes._AES_WRAP_VECTORS, "valid")
    msg = bytes.fromhex(vec["msg"])
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "unwrap_key", _handle)
    monkeypatch.setattr(aes, "read_attributes", lambda *_a, **_k: {CKA_VALUE: msg})
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    aes.test_aes_key_wrap(_AesSession("AES_KEY_WRAP"), vec_id, vec)


@pytest.mark.parametrize(
    "rv",
    [CKR_DEVICE_ERROR, CKR_GENERAL_ERROR, CKR_VENDOR_DEFINED + 1],
    ids=["device-error", "general-error", "vendor-defined"],
)
def test_aes_kw_invalid_clean_reject_is_classified(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    vec_id, vec = _first(aes._AES_WRAP_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)

    def _reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("unexpected clean rejection", int(rv))

    monkeypatch.setattr(aes, "unwrap_key", _reject)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    classification.clear()
    with pytest.raises(pytest.xfail.Exception):
        aes.test_aes_key_wrap(_AesSession("AES_KEY_WRAP"), vec_id, vec)
    assert classification.get_records()[-1].reason == "nonspec_reject"


def test_aes_kw_invalid_expected_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    vec_id, vec = _first(aes._AES_WRAP_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)

    def _reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("expected clean rejection", int(CKR_WRAPPED_KEY_INVALID))

    monkeypatch.setattr(aes, "unwrap_key", _reject)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    aes.test_aes_key_wrap(_AesSession("AES_KEY_WRAP"), vec_id, vec)


def test_aes_kw_invalid_undefined_reject_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    vec_id, vec = _first(aes._AES_WRAP_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)

    def _reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("undefined rejection", 0x7FFFFFFF)

    monkeypatch.setattr(aes, "unwrap_key", _reject)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    classification.clear()
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        aes.test_aes_key_wrap(_AesSession("AES_KEY_WRAP"), vec_id, vec)
    assert classification.get_records()[-1].reason == "self_contradiction"


def test_aes_kw_invalid_non_ckr_reject_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    vec_id, vec = _first(aes._AES_WRAP_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)

    def _reject(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("binding bug")

    monkeypatch.setattr(aes, "unwrap_key", _reject)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(AssertionError, match="binding bug"):
        aes.test_aes_key_wrap(_AesSession("AES_KEY_WRAP"), vec_id, vec)


def test_aes_kw_acceptable_output_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    vec_id, vec = _first(aes._AES_WRAP_VECTORS, "acceptable")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "unwrap_key", _handle)
    monkeypatch.setattr(aes, "read_attributes", lambda *_a, **_k: {CKA_VALUE: b"wrong"})
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="does not match known answer"):
        aes.test_aes_key_wrap(_AesSession("AES_KEY_WRAP"), vec_id, vec)
