"""Regression tests for IKE protocol-KDF coverage."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKM_AES_ECB,
    CKM_IKE1_EXTENDED_DERIVE,
    CKM_IKE1_PRF_DERIVE,
    CKM_IKE2_PRF_PLUS_DERIVE,
    CKM_IKE_PRF_DERIVE,
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases import test_ike


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def test_ike2_prf_plus_base_key_sensitivity_fails_on_same_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_keys = iter((1, 2))
    derived_keys = iter((10, 11))

    monkeypatch.setattr(test_ike, "_create_base_key", lambda *_args, **_kwargs: next(base_keys))
    monkeypatch.setattr(test_ike, "_derive_generic", lambda *_args, **_kwargs: next(derived_keys))
    monkeypatch.setattr(test_ike, "_get_value", lambda *_args, **_kwargs: b"same-ike2-output")
    monkeypatch.setattr(test_ike, "destroy_quietly", lambda *_args, **_kwargs: None)

    rs = _session_with_mechanisms("IKE2_PRF_PLUS_DERIVE")
    with pytest.raises(AssertionError, match="IKE2 PRF\\+ base key"):
        test_ike.TestIKE2PRFPlusDerive().test_base_key_affects_output(rs)


def test_ike_invalid_prf_mechanism_uses_negative_classifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_keys = iter((1, 2, 3, 4))
    keygxy_keys = iter((10, 11))
    derive_calls: list[tuple[int, int, int]] = []
    classifier_calls: list[tuple[BaseException | None, tuple[int, ...], str]] = []

    def _derive_key(
        _raw: object,
        _sh: int,
        base_key: int,
        mechanism: int,
        *_args: object,
        **kwargs: object,
    ) -> int:
        mech_param = kwargs["mech_param"]
        derive_calls.append(
            (
                int(base_key),
                int(mechanism),
                int(mech_param.params.prfMechanism),
            )
        )
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID",
            int(CKR_MECHANISM_PARAM_INVALID),
        )

    def _reject_or_classify(
        exc: BaseException | None,
        expected_rvs: tuple[int, ...],
        *,
        label: str,
    ) -> None:
        classifier_calls.append((exc, tuple(int(rv) for rv in expected_rvs), label))

    monkeypatch.setattr(test_ike, "_create_base_key", lambda *_args, **_kwargs: next(base_keys))
    monkeypatch.setattr(
        test_ike,
        "_create_sha256_hmac_derive_key",
        lambda *_args, **_kwargs: next(base_keys),
    )
    monkeypatch.setattr(
        test_ike,
        "_create_ike1_keygxy_key",
        lambda *_args, **_kwargs: next(keygxy_keys),
    )
    monkeypatch.setattr(test_ike, "derive_key", _derive_key)
    monkeypatch.setattr(test_ike, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_ike, "reject_or_classify", _reject_or_classify, raising=False)

    rs = _session_with_mechanisms(
        "IKE2_PRF_PLUS_DERIVE",
        "IKE_PRF_DERIVE",
        "IKE1_PRF_DERIVE",
        "IKE1_EXTENDED_DERIVE",
    )
    test_ike.TestIKE2PRFPlusDerive().test_rejects_invalid_prf_mechanism(rs)
    test_ike.TestIKEPRFDerive().test_rejects_invalid_prf_mechanism(rs)
    test_ike.TestIKE1PRFDerive().test_rejects_invalid_prf_mechanism(rs)
    test_ike.TestIKE1ExtendedDerive().test_rejects_invalid_prf_mechanism(rs)

    assert derive_calls == [
        (1, int(CKM_IKE2_PRF_PLUS_DERIVE), int(CKM_AES_ECB)),
        (2, int(CKM_IKE_PRF_DERIVE), int(CKM_AES_ECB)),
        (3, int(CKM_IKE1_PRF_DERIVE), int(CKM_AES_ECB)),
        (4, int(CKM_IKE1_EXTENDED_DERIVE), int(CKM_AES_ECB)),
    ]
    assert [call[2] for call in classifier_calls] == [
        "IKE2 PRF+ invalid PRF mechanism",
        "IKE PRF invalid PRF mechanism",
        "IKE1 PRF invalid PRF mechanism",
        "IKE1 extended invalid PRF mechanism",
    ]
    assert all(isinstance(call[0], CkrAssertionError) for call in classifier_calls)
    assert all(int(CKR_MECHANISM_PARAM_INVALID) in call[1] for call in classifier_calls)


def test_ike_prf_rejects_data_as_key_rekey_combination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_keys = iter((1, 2))
    derive_calls: list[tuple[int, int, int, int, int]] = []
    classifier_calls: list[tuple[BaseException | None, tuple[int, ...], str]] = []

    def _derive_key(
        _raw: object,
        _sh: int,
        base_key: int,
        mechanism: int,
        *_args: object,
        **kwargs: object,
    ) -> int:
        mech_param = kwargs["mech_param"]
        derive_calls.append(
            (
                int(base_key),
                int(mechanism),
                int(mech_param.params.bDataAsKey),
                int(mech_param.params.bRekey),
                int(mech_param.params.hNewKey),
            )
        )
        raise CkrAssertionError("Unexpected CK_RV CKR_ARGUMENTS_BAD", int(CKR_ARGUMENTS_BAD))

    def _reject_or_classify(
        exc: BaseException | None,
        expected_rvs: tuple[int, ...],
        *,
        label: str,
    ) -> None:
        classifier_calls.append((exc, tuple(int(rv) for rv in expected_rvs), label))

    monkeypatch.setattr(test_ike, "_create_base_key", lambda *_args, **_kwargs: next(base_keys))
    monkeypatch.setattr(test_ike, "derive_key", _derive_key)
    monkeypatch.setattr(test_ike, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_ike, "reject_or_classify", _reject_or_classify, raising=False)

    rs = _session_with_mechanisms("IKE_PRF_DERIVE")
    test_ike.TestIKEPRFDerive().test_rejects_data_as_key_rekey_combination(rs)

    assert derive_calls == [(1, int(CKM_IKE_PRF_DERIVE), 1, 1, 2)]
    assert len(classifier_calls) == 1
    exc, expected_rvs, label = classifier_calls[0]
    assert isinstance(exc, CkrAssertionError)
    assert expected_rvs == (int(CKR_ARGUMENTS_BAD),)
    assert label == "IKE PRF data-as-key rekey combination"


def test_ike1_prf_exact_vector_uses_typed_helper_and_fails_on_wrong_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int, int]] = []

    monkeypatch.setattr(test_ike, "_create_sha256_hmac_derive_key", lambda *_args: 1)
    monkeypatch.setattr(test_ike, "_create_ike1_keygxy_key", lambda *_args: 2)

    def fake_derive(*args: Any, **kwargs: Any) -> int:
        calls.append((int(args[1]), int(args[2]), int(kwargs["key_number"])))
        return 10

    monkeypatch.setattr(test_ike, "_derive_ike1_prf", fake_derive)
    monkeypatch.setattr(test_ike, "_get_value", lambda *_args, **_kwargs: b"\x00" * 32)
    monkeypatch.setattr(test_ike, "destroy_quietly", lambda *_args, **_kwargs: None)

    rs = _session_with_mechanisms("IKE1_PRF_DERIVE")
    with pytest.raises(AssertionError):
        test_ike.TestIKE1PRFDerive().test_prf_hmac_sha256_exact_vector(rs)

    assert calls == [(1, 2, 0)]


def test_ike1_extended_exact_vector_uses_typed_helper_and_fails_on_wrong_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int, bytes]] = []

    monkeypatch.setattr(test_ike, "_create_sha256_hmac_derive_key", lambda *_args: 1)
    monkeypatch.setattr(test_ike, "_create_ike1_keygxy_key", lambda *_args: 2)

    def fake_derive(*args: Any, **kwargs: Any) -> int:
        calls.append((int(args[1]), int(kwargs["keygxy_key"]), bytes(kwargs["extra_data"])))
        return 10

    monkeypatch.setattr(test_ike, "_derive_ike1_extended", fake_derive)
    monkeypatch.setattr(test_ike, "_get_value", lambda *_args, **_kwargs: b"\x00" * 32)
    monkeypatch.setattr(test_ike, "destroy_quietly", lambda *_args, **_kwargs: None)

    rs = _session_with_mechanisms("IKE1_EXTENDED_DERIVE")
    with pytest.raises(AssertionError):
        test_ike.TestIKE1ExtendedDerive().test_extended_hmac_sha256_exact_vector(rs)

    expected_extra = test_ike._NONCE_I + test_ike._NONCE_R + test_ike._SPI_I + test_ike._SPI_R
    assert calls == [(1, 2, expected_extra)]
