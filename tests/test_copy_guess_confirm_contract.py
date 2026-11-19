"""Contract for the #55 guess-confirm oracle judge.

The judge compares the two C_CopyObject legs (correct secret guess vs wrong
guess) and emits the verdict: identical refusal wins, identical
accept-with-preserved-material is a recorded deviation, and any asymmetric
outcome (mixed accept/refuse, differing refusal codes, mutated material, or
an object created on a refused leg) fails loud.
"""

from typing import Any

import pytest

import pkcs11_check.testcases._copy_mutability as cm
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_VALUE,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_SENSITIVE,
)

LABEL = "guess-confirm"
OPERATION = "C_CopyObject"
SPEC_REF = "pkcs11-check #55.1 guess-confirm: identical refusal for correct and wrong guesses"
EXPECTED = (CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_SENSITIVE)


class _SimulatedVerdictError(Exception):
    """Sentinel raised by the verdict captures to stop the judge flow."""


@pytest.fixture()
def captures(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    seen: dict[str, list[tuple[str, dict[str, Any]]]] = {"fail": [], "xfail": []}

    def _fail(reason: str, **kw: Any) -> Any:
        seen["fail"].append((reason, kw))
        raise _SimulatedVerdictError(f"fail_as {reason}")

    def _xfail(reason: str, **kw: Any) -> Any:
        seen["xfail"].append((reason, kw))
        raise _SimulatedVerdictError(f"xfail_as {reason}")

    monkeypatch.setattr(cm, "fail_as", _fail)
    monkeypatch.setattr(cm, "xfail_as", _xfail)
    return seen


def _refused(rv: int) -> CkrAssertionError:
    return CkrAssertionError(f"copy refused with 0x{rv:08x}", rv)


def test_same_refusal_passes(captures: dict[str, list[tuple[str, dict[str, Any]]]]) -> None:
    cm.judge_guess_confirm(
        correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
        wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
        correct_preserved=True,
        wrong_preserved=True,
        created_on_refusal=False,
        expected_rvs=EXPECTED,
        label=LABEL,
        operation=OPERATION,
        spec_ref=SPEC_REF,
    )
    assert captures == {"fail": [], "xfail": []}


def test_different_refusal_codes_fail(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_SENSITIVE),
            correct_preserved=True,
            wrong_preserved=True,
            created_on_refusal=False,
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["fail"]
    assert "oracle" in kw["summary"]
    assert captures["xfail"] == []


def test_vendor_divergence_xfails_before_oracle(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    with pytest.raises(_SimulatedVerdictError, match="xfail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(0x80000001),
            wrong_exc=_refused(0x80000002),
            correct_preserved=True,
            wrong_preserved=True,
            created_on_refusal=False,
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    assert [reason for reason, _ in captures["xfail"]] == ["nonspec_reject"]
    assert captures["fail"] == []


def test_undefined_divergence_fails_metadata(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(0xDEAD),
            wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            correct_preserved=True,
            wrong_preserved=True,
            created_on_refusal=False,
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    assert [(reason, kw["kind"]) for reason, kw in captures["fail"]] == [
        ("self_contradiction", "metadata")
    ]


def test_mixed_accept_and_refuse_fails(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=None,
            wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            correct_preserved=True,
            wrong_preserved=True,
            created_on_refusal=False,
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["fail"]
    assert "oracle" in kw["summary"]


def test_both_accepted_preserved_xfails(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    with pytest.raises(_SimulatedVerdictError, match="xfail_as"):
        cm.judge_guess_confirm(
            correct_exc=None,
            wrong_exc=None,
            correct_preserved=True,
            wrong_preserved=True,
            created_on_refusal=False,
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    assert [(reason, kw["kind"]) for reason, kw in captures["xfail"]] == [
        ("honest_deviation", "policy")
    ]
    assert captures["fail"] == []


def test_mutated_material_fails(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=None,
            wrong_exc=None,
            correct_preserved=True,
            wrong_preserved=False,
            created_on_refusal=False,
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    assert [reason for reason, _ in captures["fail"]] == ["self_contradiction"]


def test_object_created_on_refusal_fails(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            correct_preserved=True,
            wrong_preserved=True,
            created_on_refusal=True,
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["fail"]
    assert "created" in kw["summary"]


def test_guess_legs_send_distinct_templates(monkeypatch: pytest.MonkeyPatch) -> None:
    """The two guess legs copy with the correct and wrong bytes respectively."""
    from types import SimpleNamespace

    import pkcs11_check.testcases.test_keymgmt as km

    seen: list[dict[Any, Any]] = []

    def _capture(_raw: Any, _sh: int, _handle: int, attrs: Any) -> int:
        seen.append(dict(attrs))
        raise CkrAssertionError("copy refused", CKR_ATTRIBUTE_READ_ONLY)

    monkeypatch.setattr(km, "copy_object", _capture)
    monkeypatch.setattr(km, "_count_session_objects", lambda _rs: 5)
    rs = SimpleNamespace(raw=object(), sh=1)
    correct_exc, wrong_exc, correct_ok, wrong_ok, created = km._run_guess_legs(
        rs, 100, CKA_VALUE, (b"correct-guess", b"wrong-guess"), b"baseline", lambda *a: True
    )
    assert seen == [{CKA_VALUE: b"correct-guess"}, {CKA_VALUE: b"wrong-guess"}]
    assert correct_exc is not None and wrong_exc is not None
    assert (correct_ok, wrong_ok, created) == (True, True, False)
