"""Pure verdict logic for the over-delivery boundary probe."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EC_PARAMS,
    CKM_EC_KEY_PAIR_GEN,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_OK,
)
from pkcs11_check.testcases import test_capability_boundary as boundary
from pkcs11_check.testcases.test_capability_boundary import (
    BoundaryCase,
    classify_boundary_outcome,
    rsa_probe_size_below_min,
)


def _refused(rv: int) -> CkrAssertionError:
    return CkrAssertionError("refused", rv)


def test_refused_with_enforced_code_is_pass() -> None:
    # performed=False, a refusal with KEY_SIZE_RANGE -> enforced -> pass (None, no raise)
    assert (
        classify_boundary_outcome(
            BoundaryCase.BELOW_MIN,
            performed=False,
            refusal=_refused(int(CKR_KEY_SIZE_RANGE)),
            weak=True,
        )
        is None
    )


def test_refused_with_other_clean_code_is_xfail() -> None:
    with pytest.raises(XFailed):
        classify_boundary_outcome(
            BoundaryCase.BELOW_MIN,
            performed=False,
            refusal=_refused(int(CKR_GENERAL_ERROR)),
            weak=True,
        )


def test_performed_below_min_is_fail() -> None:
    with pytest.raises(Failed):
        classify_boundary_outcome(BoundaryCase.BELOW_MIN, performed=True, refusal=None, weak=True)


def test_performed_above_max_is_xfail() -> None:
    with pytest.raises(XFailed):
        classify_boundary_outcome(BoundaryCase.ABOVE_MAX, performed=True, refusal=None, weak=False)


def test_performed_unadvertised_known_weak_is_fail() -> None:
    with pytest.raises(Failed):
        classify_boundary_outcome(
            BoundaryCase.UNADVERTISED_MECH, performed=True, refusal=None, weak=True
        )


def test_performed_unadvertised_benign_is_xfail() -> None:
    with pytest.raises(XFailed):
        classify_boundary_outcome(
            BoundaryCase.UNADVERTISED_MECH, performed=True, refusal=None, weak=False
        )


@pytest.mark.parametrize(
    "advertised_min,expected",
    [
        (0, None),  # no range enforced -> inconclusive
        (512, None),  # already at the hard floor -> no smaller valid size
        (256, None),  # below the hard floor -> inconclusive
        (1024, 1016),  # one 8-bit step below
        (2048, 2040),
        (516, 512),  # clamp to the hard floor, still strictly below 516
    ],
)
def test_rsa_probe_size_below_min(advertised_min: int, expected: int | None) -> None:
    assert rsa_probe_size_below_min(advertised_min) == expected


def test_advertised_boundary_info_failure_is_not_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = CkrAssertionError("info failed", int(CKR_GENERAL_ERROR))
    monkeypatch.setattr(
        boundary,
        "get_mechanism_info",
        lambda *_a, **_k: (_ for _ in ()).throw(error),
    )
    rs = SimpleNamespace(has_mechanism=lambda _name: True, raw=object(), slot_id=0)

    with pytest.raises(CkrAssertionError) as caught:
        boundary.TestRSAKeySizeBoundary().test_rsa_below_min_is_refused(rs)

    assert caught.value is error


class _EcBoundaryRaw:
    """In-memory raw boundary for the production EC recipe path."""

    def __init__(self, generate_rv: int) -> None:
        self.generate_rv = generate_rv
        self.mechanism_info_calls: list[tuple[int, int]] = []
        self.generate_calls: list[tuple[int, int, bytes]] = []
        self.destroy_calls: list[tuple[int, int]] = []

    def C_GetMechanismInfo(self, slot_id: int, mechanism: int, info: Any) -> int:  # noqa: N802
        self.mechanism_info_calls.append((slot_id, int(mechanism)))
        info._obj.ulMinKeySize = 256
        info._obj.ulMaxKeySize = 256
        info._obj.flags = 0
        return int(CKR_OK)

    def C_GenerateKeyPair(  # noqa: N802
        self,
        session: int,
        mechanism: Any,
        public_template: Any,
        _public_count: int,
        _private_template: Any,
        _private_count: int,
        public_handle: Any,
        private_handle: Any,
    ) -> int:
        ec_params = next(
            bytes(ctypes.string_at(attribute.pValue, int(attribute.ulValueLen)))
            for attribute in public_template
            if int(attribute.type) == int(CKA_EC_PARAMS)
        )
        self.generate_calls.append((session, int(mechanism._obj.mechanism), ec_params))
        if self.generate_rv == int(CKR_OK):
            public_handle._obj.value = 101
            private_handle._obj.value = 102
        return self.generate_rv

    def C_DestroyObject(self, session: int, handle: int) -> int:  # noqa: N802
        self.destroy_calls.append((session, handle))
        return int(CKR_OK)


def _ec_session(raw: _EcBoundaryRaw) -> SimpleNamespace:
    return SimpleNamespace(
        raw=raw,
        sh=7,
        slot_id=3,
        has_mechanism=lambda name: name == "EC_KEY_PAIR_GEN",
    )


def _run_ec_node(node: str, raw: _EcBoundaryRaw) -> str:
    """Capture pytest outcomes as data so an unexpected xfail fails this meta-test."""
    session = _ec_session(raw)
    testcase = boundary.TestECKeySizeBoundary()
    try:
        getattr(testcase, node)(session)
    except XFailed:
        return "xfail"
    except Failed:
        return "fail"
    return "pass"


@pytest.mark.parametrize(
    ("node", "expected_der"),
    [
        pytest.param(
            "test_ec_below_min_is_refused",
            bytes.fromhex("06052b81040021"),
            id="below-min-secp224r1",
        ),
        pytest.param(
            "test_ec_above_max_is_refused",
            bytes.fromhex("06052b81040022"),
            id="above-max-secp384r1",
        ),
    ],
)
def test_ec_boundary_curve_not_supported_is_a_conformant_refusal(
    node: str,
    expected_der: bytes,
) -> None:
    """Both actual EC nodes pass on the spec-defined unsupported-curve CK_RV."""
    raw = _EcBoundaryRaw(int(CKR_CURVE_NOT_SUPPORTED))

    assert _run_ec_node(node, raw) == "pass"
    assert raw.mechanism_info_calls == [(3, int(CKM_EC_KEY_PAIR_GEN))]
    assert raw.generate_calls == [(7, int(CKM_EC_KEY_PAIR_GEN), expected_der)]
    assert raw.destroy_calls == [(7, 0), (7, 0)]


def test_ec_boundary_successful_handles_are_cleaned_before_classification() -> None:
    raw = _EcBoundaryRaw(int(CKR_OK))

    assert _run_ec_node("test_ec_below_min_is_refused", raw) == "fail"
    assert raw.generate_calls == [(7, int(CKM_EC_KEY_PAIR_GEN), bytes.fromhex("06052b81040021"))]
    assert raw.destroy_calls == [(7, 101), (7, 102)]


def test_ec_boundary_unexpected_recipe_exception_propagates() -> None:
    class RaisingRaw(_EcBoundaryRaw):
        def C_GenerateKeyPair(self, *_args: Any, **_kwargs: Any) -> int:  # noqa: N802
            raise RuntimeError("raw boundary failure")

    raw = RaisingRaw(int(CKR_OK))
    with pytest.raises(RuntimeError, match="raw boundary failure"):
        boundary.TestECKeySizeBoundary().test_ec_below_min_is_refused(_ec_session(raw))
    assert raw.destroy_calls == [(7, 0), (7, 0)]


def test_non_ec_curve_not_supported_remains_a_noncanonical_refusal() -> None:
    classification.clear()
    try:
        with pytest.raises(XFailed):
            classify_boundary_outcome(
                BoundaryCase.BELOW_MIN,
                performed=False,
                refusal=_refused(int(CKR_CURVE_NOT_SUPPORTED)),
                weak=True,
            )
        record = classification.get_records()[-1]
        assert record.reason == "nonspec_reject"
        assert record.actual_ckr == "CKR_CURVE_NOT_SUPPORTED"
    finally:
        classification.clear()
