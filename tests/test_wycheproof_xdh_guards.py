"""Regression tests for Wycheproof X25519/X448 guards."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases.wycheproof import test_wycheproof_x25519 as xdh


class _XdhSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "ECDH1_DERIVE"


def _fail_if_called(*_args: Any, **_kwargs: Any) -> int:
    raise AssertionError("PKCS#11 import reached after invalid public-key decode")


def _fail_if_duplicate_called(*_args: Any, **_kwargs: Any) -> int:
    raise AssertionError("PKCS#11 import reached for duplicate XDH vector")


def _handle(*_args: Any, **_kwargs: Any) -> int:
    return 1


def _raise_device_error(*_args: Any, **_kwargs: Any) -> int:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK",
        int(CKR_DEVICE_ERROR),
    )


def _raise_arguments_bad(*_args: Any, **_kwargs: Any) -> int:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK",
        int(CKR_ARGUMENTS_BAD),
    )


def _read_zeros(_raw: Any, _session: int, _obj: int, attrs: list[int]) -> dict[int, bytes]:
    return {attr: b"\x00" * 56 for attr in attrs}


@pytest.fixture(autouse=True)
def _clear_classifications() -> None:
    classification.clear()


def _vector(result: str = "acceptable", shared: str = "02" * 32) -> dict[str, Any]:
    return {
        "_oid": xdh.X25519_OID,
        "_key_size": 32,
        "_encoding": "raw",
        "_file": "synthetic",
        "public": "22" * 32,
        "private": "11" * 32,
        "shared": shared,
        "result": result,
        "flags": ["SyntheticRuntimeGuard"],
    }


def _setup_success(
    monkeypatch: pytest.MonkeyPatch,
    *,
    value: bytes | None = b"\x02" * 32,
    derive: Callable[..., int] | None = None,
) -> list[int]:
    destroyed: list[int] = []
    monkeypatch.setattr(xdh, "provision_ec_private_key", lambda *_a, **_k: 101)
    monkeypatch.setattr(xdh, "derive_key", derive or (lambda *_a, **_k: 202))
    monkeypatch.setattr(
        xdh,
        "read_attributes",
        lambda _raw, _sh, _obj, attrs: {} if value is None else {attr: value for attr in attrs},
    )
    monkeypatch.setattr(
        xdh,
        "destroy_quietly",
        lambda *_args: destroyed.append(_args[-1]),
    )
    return destroyed


def test_duplicate_xdh_container_vector_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ASN/PEM/JWK duplicates should not rerun identical PKCS#11 inputs."""
    monkeypatch.setattr(xdh, "provision_ec_private_key", _fail_if_duplicate_called)
    vec_id = "x25519_asn_test.json:tc1-valid"
    vec = next(vec for candidate_id, vec in xdh._ALL_XDH_VECTORS if candidate_id == vec_id)

    with pytest.raises(pytest.skip.Exception, match="Duplicate PKCS#11 XDH operation input"):
        xdh.test_xdh(_XdhSession(), None, vec_id, vec)


def test_invalid_xdh_public_decode_is_unrepresentable_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No provider pass is counted when the harness cannot represent the vector."""
    monkeypatch.setattr(xdh, "provision_ec_private_key", _fail_if_called)
    vec = next(
        vec
        for vec_id, vec in xdh._ALL_XDH_VECTORS
        if vec_id == "x25519_jwk_test.json:tc528-invalid"
    )

    with pytest.raises(pytest.skip.Exception, match="Cannot represent invalid"):
        xdh.test_xdh(_XdhSession(), None, "x25519_jwk_test.json:tc528-invalid", vec)


def test_valid_xdh_private_decoder_bug_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected decoder bugs must not become valid-vector capability skips."""
    monkeypatch.setattr(
        xdh,
        "decode_xdh_private_bytes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("decoder bug")),
    )

    vec_id = "x25519_test.json:tc1-valid"
    vec = next(vec for candidate_id, vec in xdh._ALL_XDH_VECTORS if candidate_id == vec_id)

    try:
        xdh.test_xdh(_XdhSession(), None, vec_id, vec)
    except pytest.skip.Exception as exc:
        pytest.fail(f"valid XDH decoder bug was skipped: {exc}")
    except RuntimeError as exc:
        assert "decoder bug" in str(exc)
    else:
        pytest.fail("valid XDH decoder bug did not propagate")


def test_invalid_xdh_public_decoder_bug_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected decoder bugs must not become invalid-vector passes."""
    monkeypatch.setattr(xdh, "decode_xdh_private_bytes", lambda *_args, **_kwargs: b"\x01" * 32)
    monkeypatch.setattr(
        xdh,
        "decode_xdh_public_bytes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("decoder bug")),
    )

    vec_id = "x25519_jwk_test.json:tc528-invalid"
    vec = next(vec for candidate_id, vec in xdh._ALL_XDH_VECTORS if candidate_id == vec_id)

    with pytest.raises(RuntimeError, match="decoder bug"):
        xdh.test_xdh(_XdhSession(), None, vec_id, vec)


def test_invalid_xdh_public_length_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed public bytes must fail if a provider derives anyway."""
    monkeypatch.setattr(xdh, "provision_ec_private_key", _handle)
    monkeypatch.setattr(xdh, "derive_key", _handle)
    monkeypatch.setattr(xdh, "read_attributes", _read_zeros)
    monkeypatch.setattr(xdh, "destroy_quietly", lambda *_args: None)

    vec = next(
        vec for vec_id, vec in xdh._ALL_XDH_VECTORS if vec_id == "x448_test.json:tc76-invalid"
    )

    with pytest.raises(pytest.fail.Exception, match="invalid-point accepted"):
        xdh.test_xdh(_XdhSession(), None, "x448_test.json:tc76-invalid", vec)


def test_invalid_xdh_correct_length_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid vector that derives must fail even when the public key length is correct.

    The runtime fail-on-derive guard must still fire for a correct-length invalid
    vector. The original exemplar (``x25519_jwk_test.json:tc519-invalid``,
    ``crv: P-256``) was a JWK-wrapper-only invalidity that the decoder strips to a
    valid raw X25519 point -- per RFC 7748 sec 5 there is no invalid-curve attack
    on Montgomery curves, so that vector is now correctly dropped at load (the
    2026-06-11 kryoptic triage). To keep exercising the runtime guard
    provider-generally, drive it with a synthetic raw-encoding invalid vector
    whose public key is the canonical 32-byte length: if a provider derives a
    secret anyway, the test must still report ``invalid-point accepted``.
    """
    vec = {
        "_oid": xdh.X25519_OID,
        "_key_size": 32,
        "_encoding": "raw",
        "_file": "synthetic",
        "public": "00" * 32,
        "private": "01" * 32,
        "shared": "",
        "result": "invalid",
        "flags": ["SyntheticRuntimeGuard"],
    }

    monkeypatch.setattr(xdh, "provision_ec_private_key", _handle)
    monkeypatch.setattr(xdh, "derive_key", _handle)
    monkeypatch.setattr(xdh, "read_attributes", _read_zeros)
    monkeypatch.setattr(xdh, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="invalid-point accepted"):
        xdh.test_xdh(_XdhSession(), None, "synthetic:tc1-invalid", vec)


def test_valid_xdh_derive_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid-vector derive CKRs are advertised-but-not-operational evidence."""
    monkeypatch.setattr(xdh, "provision_ec_private_key", _handle)
    monkeypatch.setattr(xdh, "derive_key", _raise_device_error)
    monkeypatch.setattr(xdh, "destroy_quietly", lambda *_args: None)

    vec_id = "x25519_test.json:tc1-valid"
    vec = next(vec for candidate_id, vec in xdh._ALL_XDH_VECTORS if candidate_id == vec_id)

    with pytest.raises(pytest.xfail.Exception, match="advertised XDH derive is not operational"):
        xdh.test_xdh(_XdhSession(), None, vec_id, vec)


def test_valid_xdh_derive_arguments_bad_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid-vector CKR_ARGUMENTS_BAD reject is advertised-not-operational."""
    monkeypatch.setattr(xdh, "provision_ec_private_key", _handle)
    monkeypatch.setattr(xdh, "derive_key", _raise_arguments_bad)
    monkeypatch.setattr(xdh, "destroy_quietly", lambda *_args: None)

    vec_id = "x25519_test.json:tc1-valid"
    vec = next(vec for candidate_id, vec in xdh._ALL_XDH_VECTORS if candidate_id == vec_id)

    with pytest.raises(pytest.xfail.Exception, match="advertised XDH derive is not operational"):
        xdh.test_xdh(_XdhSession(), None, vec_id, vec)


def test_invalid_xdh_derive_arguments_bad_is_visible_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid vector's non-spec CKR_ARGUMENTS_BAD reject stays visible."""
    monkeypatch.setattr(xdh, "provision_ec_private_key", _handle)
    monkeypatch.setattr(xdh, "derive_key", _raise_arguments_bad)
    monkeypatch.setattr(xdh, "destroy_quietly", lambda *_args: None)

    vec = {
        "_oid": xdh.X25519_OID,
        "_key_size": 32,
        "_encoding": "raw",
        "_file": "synthetic",
        "public": "00" * 32,
        "private": "01" * 32,
        "shared": "",
        "result": "invalid",
        "flags": ["SyntheticRuntimeGuard"],
    }

    with pytest.raises(pytest.xfail.Exception, match="expected .*CKR_MECHANISM_PARAM_INVALID"):
        xdh.test_xdh(_XdhSession(), None, "synthetic:tc1-invalid", vec)

    assert classification.get_records()[-1].reason == "nonspec_reject"


@pytest.mark.parametrize("result", ["invalid", "acceptable"])
def test_xdh_setup_rejection_preserves_capability_disposition(
    monkeypatch: pytest.MonkeyPatch, result: str
) -> None:
    monkeypatch.setattr(
        xdh,
        "provision_ec_private_key",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError(
                "Montgomery private import rejected", int(CKR_ATTRIBUTE_VALUE_INVALID)
            )
        ),
    )

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        xdh.test_xdh(_XdhSession(), None, f"synthetic:tc1-{result}", _vector(result))


def test_invalid_xdh_curve_setup_still_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        xdh,
        "provision_ec_private_key",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("Montgomery curve unavailable", int(CKR_CURVE_NOT_SUPPORTED))
        ),
    )

    with pytest.raises(pytest.skip.Exception, match="Cannot import Montgomery private key"):
        xdh.test_xdh(_XdhSession(), None, "synthetic:tc1-invalid", _vector("invalid"))


def test_invalid_xdh_setup_non_ckr_assertion_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        xdh,
        "provision_ec_private_key",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("setup harness bug")),
    )

    with pytest.raises(AssertionError, match="setup harness bug"):
        xdh.test_xdh(_XdhSession(), None, "synthetic:tc1-invalid", _vector("invalid"))


@pytest.mark.parametrize("result", ["invalid", "acceptable"])
@pytest.mark.parametrize(
    "rv",
    [int(CKR_DEVICE_ERROR), int(CKR_GENERAL_ERROR), int(CKR_VENDOR_DEFINED) + 1],
)
def test_negative_xdh_derive_other_clean_rejections_are_visible_xfails(
    monkeypatch: pytest.MonkeyPatch, rv: int, result: str
) -> None:
    destroyed = _setup_success(
        monkeypatch,
        derive=lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("negative XDH vector rejected", rv)
        ),
    )

    with pytest.raises(pytest.xfail.Exception):
        xdh.test_xdh(_XdhSession(), None, f"synthetic:tc1-{result}", _vector(result))

    assert classification.get_records()[-1].reason == "nonspec_reject"
    assert destroyed == [101]


@pytest.mark.parametrize("result", ["invalid", "acceptable"])
def test_negative_xdh_derive_undefined_ckr_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch, result: str
) -> None:
    destroyed = _setup_success(
        monkeypatch,
        derive=lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("negative XDH vector rejected", 0x7FFFFFFF)
        ),
    )

    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        xdh.test_xdh(_XdhSession(), None, f"synthetic:tc1-{result}", _vector(result))

    record = classification.get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert destroyed == [101]


@pytest.mark.parametrize("result", ["invalid", "acceptable"])
def test_negative_xdh_derive_expected_rejection_passes(
    monkeypatch: pytest.MonkeyPatch, result: str
) -> None:
    destroyed = _setup_success(
        monkeypatch,
        derive=lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("negative XDH vector rejected", int(CKR_MECHANISM_PARAM_INVALID))
        ),
    )

    xdh.test_xdh(_XdhSession(), None, f"synthetic:tc1-{result}", _vector(result))

    assert classification.get_records() == []
    assert destroyed == [101]


@pytest.mark.parametrize(
    ("expected", "actual"),
    [("02" * 32, b"\x03" * 32), ("00" * 32, b"\x03" * 32)],
    ids=["nonzero", "all-zero"],
)
def test_acceptable_xdh_wrong_shared_value_is_reported(
    monkeypatch: pytest.MonkeyPatch,
    expected: str,
    actual: bytes,
) -> None:
    """An accepted acceptable vector must still match its Wycheproof shared value."""
    destroyed = _setup_success(monkeypatch, value=actual)

    with pytest.raises(pytest.fail.Exception, match="output does not match known answer"):
        xdh.test_xdh(
            _XdhSession(),
            None,
            "synthetic:tc1-acceptable",
            _vector("acceptable", expected),
        )

    record = classification.get_records()[-1]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert destroyed == [202, 101]


def test_acceptable_xdh_exact_shared_value_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An accepted acceptable vector with the corpus value passes."""
    destroyed = _setup_success(monkeypatch)

    xdh.test_xdh(_XdhSession(), None, "synthetic:tc1-acceptable", _vector())

    assert classification.get_records() == []
    assert destroyed == [202, 101]


def test_acceptable_xdh_all_zero_shared_value_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An acceptable all-zero Wycheproof output is valid when read back exactly."""
    destroyed = _setup_success(monkeypatch, value=b"\x00" * 32)

    xdh.test_xdh(
        _XdhSession(),
        None,
        "synthetic:tc-zero-acceptable",
        _vector("acceptable", "00" * 32),
    )

    assert classification.get_records() == []
    assert destroyed == [202, 101]


def test_acceptable_xdh_reject_is_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-spec acceptable-vector reject stays visible as an xfail."""
    destroyed = _setup_success(
        monkeypatch,
        derive=lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("acceptable XDH vector rejected", int(CKR_ARGUMENTS_BAD))
        ),
    )

    with pytest.raises(pytest.xfail.Exception):
        xdh.test_xdh(_XdhSession(), None, "synthetic:tc1-acceptable", _vector())

    assert classification.get_records()[-1].reason == "nonspec_reject"
    assert destroyed == [101]


def test_invalid_xdh_success_is_classified_before_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid vector accepted by derive fails before readback can mask it."""
    destroyed = _setup_success(monkeypatch, value=b"\x03" * 32)
    read_called = False

    def _read_failure(*_args: Any, **_kwargs: Any) -> dict[int, bytes]:
        nonlocal read_called
        read_called = True
        raise RuntimeError("readback must not decide invalid acceptance")

    monkeypatch.setattr(xdh, "read_attributes", _read_failure)

    with pytest.raises(pytest.fail.Exception, match="invalid-point accepted"):
        xdh.test_xdh(
            _XdhSession(),
            None,
            "synthetic:tc1-invalid",
            _vector("invalid"),
        )

    record = classification.get_records()[-1]
    assert record.reason == "accepted_invalid"
    assert not read_called
    assert destroyed == [202, 101]


@pytest.mark.parametrize("result", ["valid", "acceptable"])
def test_xdh_success_without_value_is_not_operational_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
    result: str,
) -> None:
    """A productive valid/acceptable derive without CKA_VALUE stays visible."""
    destroyed = _setup_success(monkeypatch, value=None)

    with pytest.raises(pytest.xfail.Exception, match="value unavailable"):
        xdh.test_xdh(
            _XdhSession(),
            None,
            f"synthetic:tc1-{result}",
            _vector(result),
        )

    record = classification.get_records()[-1]
    assert record.reason == "not_operational"
    assert record.outcome == "xfail"
    assert destroyed == [202, 101]


@pytest.mark.parametrize(
    "error",
    [KeyError("missing"), TypeError("wrong type"), AssertionError("unexpected assertion")],
)
def test_acceptable_xdh_unexpected_readback_errors_propagate(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    """Readback bugs must not be converted to acceptable-vector passes."""
    destroyed = _setup_success(monkeypatch)
    monkeypatch.setattr(
        xdh,
        "read_attributes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(error),
    )

    with pytest.raises(type(error), match=str(error)):
        xdh.test_xdh(_XdhSession(), None, "synthetic:tc1-acceptable", _vector())

    assert classification.get_records() == []
    assert destroyed == [202, 101]


@pytest.mark.parametrize("error", [AssertionError("local assertion"), TypeError("bad packing")])
def test_acceptable_xdh_unexpected_derive_errors_propagate(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    """Only CkrAssertionError is a clean acceptable-vector derive rejection."""
    destroyed = _setup_success(
        monkeypatch,
        derive=lambda *_a, **_k: (_ for _ in ()).throw(error),
    )

    with pytest.raises(type(error), match=str(error)):
        xdh.test_xdh(_XdhSession(), None, "synthetic:tc1-acceptable", _vector())

    assert classification.get_records() == []
    assert destroyed == [101]
