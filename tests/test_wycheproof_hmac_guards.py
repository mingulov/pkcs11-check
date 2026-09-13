"""Regression tests for Wycheproof HMAC invalid-vector classification.

Phase-2 V2: HMAC invalid vectors were exercised as *produce* (C_Sign + compare)
operations, so a fresh correct tag never matched the modified expected tag and
rejection was never tested. Re-framed to verify-and-reject: a module that
verifies an invalid (forged) HMAC tag as valid is a crypto-correctness break
(crypto -> fail). A valid MAC that the module rejects (e.g. an unsupported
truncated tag length) is an honest deviation -> xfail.
"""

from __future__ import annotations

import ctypes
from collections.abc import Iterator
from typing import Any

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKK_GENERIC_SECRET,
    CKK_SHA_1_HMAC,
    CKM_SHA_1_HMAC,
    CKM_SHA_1_HMAC_GENERAL,
    CKR_DEVICE_ERROR,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases.wycheproof import test_wycheproof_hmac as hmac


def _first(result: str) -> tuple[str, dict[str, Any]]:
    hit = next(((cid, v) for cid, v in hmac._ALL_HMAC_VECTORS if v["result"] == result), None)
    if hit is None:
        pytest.skip(
            "Wycheproof HMAC vectors not available (run `pkcs11-check fetch-data wycheproof`)"
        )
    return hit


class _HmacSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "SHA_1_HMAC"


class _HmacMechanismSession:
    raw = object()
    sh = 1

    def __init__(self, *mechanisms: str) -> None:
        self.mechanisms = set(mechanisms)
        self.checked: list[str] = []

    def has_mechanism(self, name: str) -> bool:
        self.checked.append(name)
        return name in self.mechanisms


def _handle(*_args: Any, **_kwargs: Any) -> int:
    return 1


@pytest.fixture(autouse=True)
def _clear_hmac_state() -> Iterator[None]:
    hmac._UNSUPPORTED_HMAC_KEYS.clear()
    classification.clear()
    yield
    hmac._UNSUPPORTED_HMAC_KEYS.clear()
    classification.clear()


def _vector(result: str) -> dict[str, Any]:
    return {
        "key": "00" * 16,
        "msg": "01",
        "tag": "02" * 20,
        "result": result,
        "_key_type": CKK_SHA_1_HMAC,
        "_mechanism": CKM_SHA_1_HMAC,
        "_fallback_type": CKK_GENERIC_SECRET,
    }


def _truncated_vector(result: str = "invalid") -> dict[str, Any]:
    return {
        **_vector(result),
        # The group size, not the supplied tag length, selects HMAC_GENERAL.
        "tag": "02" * 3,
        "_group": {"tagSize": 80},
        "_file": "synthetic_hmac_sha1_test.json",
    }


def _raise_ckr(rv: int) -> Any:
    def _raise(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("synthetic CK_RV", int(rv))

    return _raise


def test_hmac_invalid_key_import_rejection_is_visible_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid vector cannot turn a rejected subject-key setup into a pass."""
    vec = _vector("invalid")
    monkeypatch.setattr(hmac, "import_secret_key", _raise_ckr(CKR_KEY_SIZE_RANGE))

    with pytest.raises(XFailed):
        hmac.test_hmac_wycheproof(_HmacSession(), "synthetic-invalid", vec)

    records = classification.serialize(classification.get_records())
    assert len(records) == 1
    assert records[0]["reason"] == "not_operational"
    assert records[0]["actual_ckr"] == "CKR_KEY_SIZE_RANGE"


def test_hmac_non_ckr_key_import_failure_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A Python/setup failure is not a provider capability deviation."""
    vec = _vector("invalid")

    def _raise_non_ckr(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("synthetic setup failure")

    monkeypatch.setattr(hmac, "import_secret_key", _raise_non_ckr)

    with pytest.raises(AssertionError, match="synthetic setup failure"):
        hmac.test_hmac_wycheproof(_HmacSession(), "synthetic-invalid", vec)


def test_hmac_invalid_expected_signature_reject_is_a_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec = _vector("invalid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "verify_single", _raise_ckr(CKR_SIGNATURE_INVALID))
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    hmac.test_hmac_wycheproof(_HmacSession(), "synthetic-invalid", vec)
    assert classification.get_records() == []


@pytest.mark.parametrize("rv", [CKR_DEVICE_ERROR, CKR_GENERAL_ERROR, CKR_VENDOR_DEFINED + 1])
def test_hmac_invalid_noncanonical_signature_reject_is_visible_xfail(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    vec = _vector("invalid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "verify_single", _raise_ckr(rv))
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    with pytest.raises(XFailed):
        hmac.test_hmac_wycheproof(_HmacSession(), "synthetic-invalid", vec)

    records = classification.serialize(classification.get_records())
    assert len(records) == 1
    assert records[0]["reason"] == "nonspec_reject"


def test_hmac_invalid_undefined_signature_reject_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec = _vector("invalid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "verify_single", _raise_ckr(0x7FFFFFFF))
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        hmac.test_hmac_wycheproof(_HmacSession(), "synthetic-invalid", vec)


def test_hmac_invalid_non_ckr_signature_failure_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec = _vector("invalid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(
        hmac,
        "verify_single",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("synthetic verify failure")),
    )
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    with pytest.raises(AssertionError, match="synthetic verify failure"):
        hmac.test_hmac_wycheproof(_HmacSession(), "synthetic-invalid", vec)


def test_hmac_invalid_signature_length_reject_is_a_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec = _vector("invalid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "verify_single", _raise_ckr(CKR_SIGNATURE_LEN_RANGE))
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    hmac.test_hmac_wycheproof(_HmacSession(), "synthetic-invalid", vec)
    assert classification.get_records() == []


def test_hmac_invalid_vector_accepted_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid HMAC tag that verifies must fail (forged tag accepted)."""
    vec_id, vec = _first("invalid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    supplied_tags: list[bytes] = []

    def _verify(*args: Any, **_kwargs: Any) -> bool:
        supplied_tags.append(args[-1])
        return True

    monkeypatch.setattr(hmac, "verify_single", _verify)
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid tag"):
        hmac.test_hmac_wycheproof(_HmacSession(), vec_id, vec)
    assert supplied_tags == [bytes.fromhex(vec["tag"])]


def test_hmac_valid_vector_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid HMAC vector that verifies passes (no exception)."""
    vec_id, vec = _first("valid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    hmac.test_hmac_wycheproof(_HmacSession(), vec_id, vec)


def test_hmac_valid_vector_rejected_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid HMAC vector the module fails to verify is an honest deviation (xfail)."""
    vec_id, vec = _first("valid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "verify_single", lambda *_a, **_k: False)
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.xfail.Exception, match="did not verify a valid HMAC tag"):
        hmac.test_hmac_wycheproof(_HmacSession(), vec_id, vec)


def test_hmac_truncated_vector_uses_general_and_forwards_supplied_tag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Truncated HMAC uses only GENERAL and passes malformed bytes unchanged."""
    vec = _truncated_vector()
    session = _HmacMechanismSession("SHA_1_HMAC_GENERAL")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)
    calls: list[tuple[Any, ...]] = []

    def _verify(*args: Any, **kwargs: Any) -> bool:
        calls.append((args, kwargs))
        return False

    monkeypatch.setattr(hmac, "verify_single", _verify)

    hmac.test_hmac_wycheproof(session, "synthetic-truncated", vec)

    assert session.checked == ["SHA_1_HMAC_GENERAL"]
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[3] == CKM_SHA_1_HMAC_GENERAL
    assert args[-1] == bytes.fromhex(vec["tag"])
    param = kwargs["mech_param"]
    assert int(param.ck.mechanism) == int(CKM_SHA_1_HMAC_GENERAL)
    assert int(param.ck.ulParameterLen) == ctypes.sizeof(CK_ULONG)
    assert CK_ULONG.from_buffer_copy(bytes(param.storage)).value == 10


def test_hmac_truncated_vector_skips_when_general_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fixed HMAC capability does not substitute for missing GENERAL."""
    vec = _truncated_vector()
    session = _HmacMechanismSession("SHA_1_HMAC")
    monkeypatch.setattr(hmac, "import_secret_key", _fail_if_called, raising=False)

    with pytest.raises(pytest.skip.Exception, match="SHA_1_HMAC_GENERAL not supported"):
        hmac.test_hmac_wycheproof(session, "synthetic-truncated", vec)

    assert session.checked == ["SHA_1_HMAC_GENERAL"]


def test_hmac_full_vector_uses_fixed_without_mechanism_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full-length HMAC keeps the fixed mechanism and has no parameter blob."""
    vec = _vector("invalid")
    session = _HmacMechanismSession("SHA_1_HMAC")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)
    calls: list[tuple[Any, ...]] = []

    def _verify(*args: Any, **kwargs: Any) -> bool:
        calls.append((args, kwargs))
        return False

    monkeypatch.setattr(hmac, "verify_single", _verify)

    hmac.test_hmac_wycheproof(session, "synthetic-full", vec)

    assert session.checked == ["SHA_1_HMAC"]
    args, kwargs = calls[0]
    assert args[3] == CKM_SHA_1_HMAC
    assert args[-1] == bytes.fromhex(vec["tag"])
    assert kwargs == {}


def test_hmac_truncated_runtime_reject_remains_visible_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An advertised GENERAL runtime reject remains a non-clean finding."""
    vec = _truncated_vector("valid")
    session = _HmacMechanismSession("SHA_1_HMAC_GENERAL")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(hmac, "verify_single", _raise_ckr(CKR_GENERAL_ERROR))

    with pytest.raises(pytest.xfail.Exception, match="advertised HMAC operation"):
        hmac.test_hmac_wycheproof(session, "synthetic-truncated", vec)

    record = classification.get_records()[-1]
    assert record.reason == "not_operational"
    assert record.mechanism == "SHA_1_HMAC_GENERAL"
    assert record.params == {"hash": "sha-1"}


@pytest.mark.parametrize(
    ("fixed_name", "general_name", "digest_size"),
    [
        ("SHA_1_HMAC", "SHA_1_HMAC_GENERAL", 20),
        ("SHA224_HMAC", "SHA224_HMAC_GENERAL", 28),
        ("SHA384_HMAC", "SHA384_HMAC_GENERAL", 48),
        ("SHA512_HMAC", "SHA512_HMAC_GENERAL", 64),
        ("SHA512_224_HMAC", "SHA512_224_HMAC_GENERAL", 28),
        ("SHA512_256_HMAC", "SHA512_256_HMAC_GENERAL", 32),
        ("SHA3_224_HMAC", "SHA3_224_HMAC_GENERAL", 28),
        ("SHA3_256_HMAC", "SHA3_256_HMAC_GENERAL", 32),
        ("SHA3_384_HMAC", "SHA3_384_HMAC_GENERAL", 48),
        ("SHA3_512_HMAC", "SHA3_512_HMAC_GENERAL", 64),
    ],
)
def test_all_hmac_families_route_full_and_truncated_tags(
    fixed_name: str,
    general_name: str,
    digest_size: int,
) -> None:
    """Every manually registered family keeps its fixed/GENERAL boundary exact."""
    by_name = {name: mechanism for mechanism, name in hmac._MECH_NAMES.items()}
    fixed = by_name[fixed_name]
    general = by_name[general_name]
    assert hmac._HMAC_GENERAL_MECHANISMS[fixed] == general
    assert hmac._HMAC_DIGEST_SIZES[fixed] == digest_size

    full = hmac.route_hmac_mechanism(
        expected_tag_size=digest_size,
        digest_size=digest_size,
        fixed_mechanism=fixed,
        fixed_name=fixed_name,
        general_mechanism=general,
        general_name=general_name,
    )
    assert (full.mechanism, full.display_name, full.mech_param) == (
        fixed,
        fixed_name,
        None,
    )

    truncated = hmac.route_hmac_mechanism(
        expected_tag_size=digest_size - 1,
        digest_size=digest_size,
        fixed_mechanism=fixed,
        fixed_name=fixed_name,
        general_mechanism=general,
        general_name=general_name,
    )
    assert truncated.mechanism == general
    assert truncated.display_name == general_name
    assert truncated.mech_param is not None
    assert CK_ULONG.from_buffer_copy(bytes(truncated.mech_param.storage)).value == digest_size - 1


@pytest.mark.parametrize("expected_tag_size", [0, 21])
def test_hmac_route_rejects_out_of_range_group_size(expected_tag_size: int) -> None:
    with pytest.raises(ValueError, match="expected HMAC tag size"):
        hmac.route_hmac_mechanism(
            expected_tag_size=expected_tag_size,
            digest_size=20,
            fixed_mechanism=CKM_SHA_1_HMAC,
            fixed_name="SHA_1_HMAC",
            general_mechanism=CKM_SHA_1_HMAC_GENERAL,
            general_name="SHA_1_HMAC_GENERAL",
        )


def test_hmac_rejects_non_byte_aligned_group_size(monkeypatch: pytest.MonkeyPatch) -> None:
    vec = _truncated_vector()
    vec.pop("_tag_size", None)
    vec["_group"] = {"tagSize": 79}
    session = _HmacMechanismSession("SHA_1_HMAC_GENERAL")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(hmac, "verify_single", lambda *_a, **_k: False)

    with pytest.raises(ValueError, match="byte-aligned"):
        hmac.test_hmac_wycheproof(session, "synthetic-non-byte-aligned", vec)


def _fail_if_called(*_args: Any, **_kwargs: Any) -> Any:
    raise AssertionError("operation reached after a missing HMAC mechanism")
