"""Contract for the #55 guess-confirm oracle judge.

The judge compares the two C_CopyObject legs (correct secret guess vs wrong
guess) and emits the verdict: identical refusal wins, identical
accept-with-preserved-material is a recorded deviation, and any asymmetric
outcome (mixed accept/refuse, differing refusal codes, mutated material, or
an object created on a refused leg) fails loud.
"""

from types import SimpleNamespace
from typing import Any

import pytest

import pkcs11_check.testcases._copy_mutability as cm
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_UNAVAILABLE_INFORMATION,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_AES,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_DEVICE_ERROR,
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

    def _record_validity(reason: str, **kw: Any) -> Any:
        return SimpleNamespace(
            reason=reason,
            kw=kw,
            outcome="fail" if reason == "self_contradiction" else "xfail",
        )

    def _raise_for_record(rec: Any) -> Any:
        if rec.outcome == "fail":
            seen["fail"].append((rec.reason, rec.kw))
            raise _SimulatedVerdictError(f"fail_as {rec.reason}")
        seen["xfail"].append((rec.reason, rec.kw))
        raise _SimulatedVerdictError(f"xfail_as {rec.reason}")

    monkeypatch.setattr(cm, "fail_as", _fail)
    monkeypatch.setattr(cm, "xfail_as", _xfail)
    monkeypatch.setattr(cm, "record_as", _record_validity)
    monkeypatch.setattr(cm, "raise_for_record", _raise_for_record)
    return seen


def _refused(rv: int) -> CkrAssertionError:
    return CkrAssertionError(f"copy refused with 0x{rv:08x}", rv)


def _use(preserved: bool | None, rv: int | None = None) -> cm.GuessUseOutcome:
    return cm.GuessUseOutcome(
        preserved=preserved, use_rv=rv, operation="C_Encrypt", mechanism="CKM_AES_ECB"
    )


def test_same_refusal_passes(captures: dict[str, list[tuple[str, dict[str, Any]]]]) -> None:
    cm.judge_guess_confirm(
        correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
        wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
        correct_use=_use(True),
        wrong_use=_use(True),
        created_on_refusal=(False, False),
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
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
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
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
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
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
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
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
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
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    assert [(reason, kw["kind"]) for reason, kw in captures["xfail"]] == [
        ("honest_deviation", "policy")
    ]
    assert captures["fail"] == []
    (reason, kw), *_ = captures["xfail"]
    assert "C_Encrypt" in kw["summary"], kw["summary"]
    assert kw["detail"]["use_operation"] == "C_Encrypt", kw["detail"]


def test_mutated_material_fails(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=None,
            wrong_exc=None,
            correct_use=_use(True),
            wrong_use=_use(False),
            created_on_refusal=(False, False),
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
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(True, True),
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
    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({9}, None))
    rs = SimpleNamespace(raw=object(), sh=1)
    out = km._run_guess_legs(
        rs,
        100,
        CKA_VALUE,
        (b"correct-guess", b"wrong-guess"),
        b"baseline",
        lambda *a: _use(True),
        label="t",
    )
    correct_exc, wrong_exc, correct_use, wrong_use, created, inventory_rvs, deltas = out
    assert seen == [{CKA_VALUE: b"correct-guess"}, {CKA_VALUE: b"wrong-guess"}]
    assert correct_exc is not None and wrong_exc is not None
    assert (correct_use, wrong_use, created, inventory_rvs) == (
        None,
        None,
        (False, False),
        (None, None),
    )
    assert deltas == (frozenset(), frozenset()), deltas


def test_accepted_guess_copy_predating_inventory_fails_without_destroy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R3F2: an accepted guess copy returning a baseline handle fails; no destroy."""
    from _pytest.outcomes import Failed

    import pkcs11_check.testcases.test_keymgmt as km

    destroyed: list[int] = []
    monkeypatch.setattr(km, "copy_object", lambda _r, _s, _h, _a: 9)
    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({9}, None))
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    rs = SimpleNamespace(raw=object(), sh=1)
    with pytest.raises(Failed, match="pre-existing"):
        km._run_guess_legs(
            rs, 100, CKA_VALUE, (b"c", b"w"), b"base", lambda *a: _use(True), label="t"
        )
    assert destroyed == [], destroyed


def test_inventory_object_set_unfiltered(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pre-review 4: the inventory template carries no filter (token objects visible)."""
    import pkcs11_check.testcases.test_keymgmt as km

    seen: list[Any] = []

    def _find(_raw: Any, _sh: int, tmpl: Any) -> list[int]:
        seen.append(tmpl)
        return [9]

    monkeypatch.setattr(km, "find_objects_exhaustive", _find)
    rs = SimpleNamespace(raw=object(), sh=1)
    handles, rv = km._inventory_object_set(rs, label="t")
    assert (handles, rv) == ({9}, None)
    assert len(seen) == 1 and seen[0].count == 0, "filtered inventory hides token objects"


def _script_identities(
    monkeypatch: pytest.MonkeyPatch, script: dict[tuple[int, int], Any]
) -> list[tuple[int, int]]:
    """Script (handle, attr) reads for the real adoption logic (R4-F1).

    Returns the consumed-read list; callers assert it to prove the
    correlation reads actually happened (not just the verdict).
    """
    from pkcs11_check.testcases import _adoption as ad

    consumed: list[tuple[int, int]] = []

    def _fake(_rs: Any, handle: int, attr: int, **kw: Any) -> Any:
        key = (int(handle), int(attr))
        assert key in script, f"unscripted identity read {key}"
        consumed.append(key)
        return script[key]

    monkeypatch.setattr(ad, "read_identity_attr", _fake)
    return consumed


def _source_script(handle: int, label: str = "src") -> dict[tuple[int, int], Any]:
    return {
        (handle, int(CKA_LABEL)): label,
        (handle, int(CKA_TOKEN)): False,
        (handle, int(CKA_CLASS)): int(CKO_SECRET_KEY),
        (handle, int(CKA_KEY_TYPE)): int(CKK_AES),
    }


def test_guess_legs_session_delta_proves_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    """R4-F1: a session-correlated delta across a refused copy proves creation."""
    import pkcs11_check.testcases.test_keymgmt as km

    pages = iter([[9], [9, 200], [9], [9]])

    def _find(_raw: Any, _sh: int, _tmpl: Any) -> list[int]:
        return next(pages)

    def _refuse(_raw: Any, _sh: int, _handle: int, _attrs: Any) -> int:
        raise CkrAssertionError("copy refused", CKR_ATTRIBUTE_READ_ONLY)

    monkeypatch.setattr(km, "find_objects_exhaustive", _find)
    monkeypatch.setattr(km, "copy_object", _refuse)
    script = _source_script(100) | _source_script(200)
    consumed = _script_identities(monkeypatch, script)
    rs = SimpleNamespace(raw=object(), sh=1)
    _cx, _wx, _cu, _wu, created, _rvs, deltas = km._run_guess_legs(
        rs,
        100,
        CKA_VALUE,
        (b"correct-guess", b"wrong-guess"),
        b"baseline",
        lambda *a: _use(True),
        label="t",
    )
    assert created == (True, False), created
    assert deltas == (frozenset({200}), frozenset()), deltas
    assert set(consumed) == set(script), consumed


def test_guess_legs_token_delta_without_correlation_is_unproved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R4-F1: a foreign token delta voids creation (never a leak finding)."""
    import pkcs11_check.testcases.test_keymgmt as km

    pages = iter([[9], [9, 200], [9], [9]])

    def _find(_raw: Any, _sh: int, _tmpl: Any) -> list[int]:
        return next(pages)

    def _refuse(_raw: Any, _sh: int, _handle: int, _attrs: Any) -> int:
        raise CkrAssertionError("copy refused", CKR_ATTRIBUTE_READ_ONLY)

    monkeypatch.setattr(km, "find_objects_exhaustive", _find)
    monkeypatch.setattr(km, "copy_object", _refuse)
    script = _source_script(100) | {
        (200, int(CKA_LABEL)): "foreign",
        (200, int(CKA_TOKEN)): True,
        (200, int(CKA_CLASS)): int(CKO_SECRET_KEY),
        (200, int(CKA_KEY_TYPE)): int(CKK_AES),
    }
    _script_identities(monkeypatch, script)
    rs = SimpleNamespace(raw=object(), sh=1)
    _cx, _wx, _cu, _wu, created, _rvs, deltas = km._run_guess_legs(
        rs,
        100,
        CKA_VALUE,
        (b"correct-guess", b"wrong-guess"),
        b"baseline",
        lambda *a: _use(True),
        label="t",
    )
    assert created == (None, False), created
    assert deltas == (frozenset({200}), frozenset()), deltas


def test_guess_legs_unreadable_delta_is_unproved(monkeypatch: pytest.MonkeyPatch) -> None:
    """R4-F1: an unreadable delta voids creation (never assumed absent/present)."""
    import pkcs11_check.testcases.test_keymgmt as km
    from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE

    pages = iter([[9], [9, 200], [9], [9]])

    def _find(_raw: Any, _sh: int, _tmpl: Any) -> list[int]:
        return next(pages)

    def _refuse(_raw: Any, _sh: int, _handle: int, _attrs: Any) -> int:
        raise CkrAssertionError("copy refused", CKR_ATTRIBUTE_READ_ONLY)

    monkeypatch.setattr(km, "find_objects_exhaustive", _find)
    monkeypatch.setattr(km, "copy_object", _refuse)
    script = _source_script(100) | {
        (200, int(CKA_LABEL)): MISSING_ATTRIBUTE,
        (200, int(CKA_TOKEN)): MISSING_ATTRIBUTE,
        (200, int(CKA_CLASS)): MISSING_ATTRIBUTE,
        (200, int(CKA_KEY_TYPE)): MISSING_ATTRIBUTE,
    }
    _script_identities(monkeypatch, script)
    rs = SimpleNamespace(raw=object(), sh=1)
    _cx, _wx, _cu, _wu, created, _rvs, deltas = km._run_guess_legs(
        rs,
        100,
        CKA_VALUE,
        (b"correct-guess", b"wrong-guess"),
        b"baseline",
        lambda *a: _use(True),
        label="t",
    )
    assert created == (None, False), created
    assert deltas == (frozenset({200}), frozenset()), deltas


def test_inventory_object_set_retains_refusal_rv(monkeypatch: pytest.MonkeyPatch) -> None:
    """R3F3: a refused inventory returns (None, rv); validity grades in the judge."""
    import pkcs11_check.testcases.test_keymgmt as km

    def _refuse(_raw: Any, _sh: int, _tmpl: Any) -> list[int]:
        raise CkrAssertionError("inventory refused", 0x80000001)

    monkeypatch.setattr(km, "find_objects_exhaustive", _refuse)
    rs = SimpleNamespace(raw=object(), sh=1)
    assert km._inventory_object_set(rs, label="t") == (None, 0x80000001)


def test_vendor_inventory_does_not_mask_sibling_leg(monkeypatch: pytest.MonkeyPatch) -> None:
    """R3F3: a first-leg vendor inventory RV rides along; the sibling still runs."""
    import pkcs11_check.testcases.test_keymgmt as km

    attempts: list[dict[Any, Any]] = []
    finds: list[Any] = [CkrAssertionError("inventory refused", 0x80000001), [9], [9]]

    def _find(_raw: Any, _sh: int, _tmpl: Any) -> list[int]:
        item = finds.pop(0)
        if isinstance(item, BaseException):
            raise item
        return list(item)

    def _refuse(_raw: Any, _sh: int, _handle: int, attrs: Any) -> int:
        attempts.append(dict(attrs))
        raise CkrAssertionError("copy refused", CKR_ATTRIBUTE_READ_ONLY)

    monkeypatch.setattr(km, "find_objects_exhaustive", _find)
    monkeypatch.setattr(km, "copy_object", _refuse)
    rs = SimpleNamespace(raw=object(), sh=1)
    out = km._run_guess_legs(
        rs, 100, CKA_VALUE, (b"c", b"w"), b"base", lambda *a: _use(True), label="t"
    )
    _cx, _wx, _cu, _wu, created, inventory_rvs, deltas = out
    assert [a[CKA_VALUE] for a in attempts] == [b"c", b"w"], attempts
    assert created == (None, False), created
    assert inventory_rvs == (0x80000001, None), inventory_rvs
    assert deltas == (frozenset(), frozenset()), deltas


def test_vendor_inventory_rv_xfails_nonspec(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """R3F3: a vendor inventory RV is the established result (beats unproved void)."""
    with pytest.raises(_SimulatedVerdictError, match="xfail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(None, False),
            inventory_rvs=(0x80000001, None),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["xfail"]
    assert reason == "nonspec_reject", kw


def test_undefined_inventory_rv_fails(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """R3F3: an undefined inventory RV fails the metadata contract in the judge."""
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(None, False),
            inventory_rvs=(0x7FFFFFFF, None),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["fail"]
    assert reason == "self_contradiction", kw
    assert "undefined" in kw["summary"], kw["summary"]


def test_created_beats_undefined_inventory(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """R3F3: a proved leak fails before an undefined inventory RV (precedence pin)."""
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(True, False),
            inventory_rvs=(0x7FFFFFFF, None),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["fail"]
    assert reason == "self_contradiction", kw
    assert "created" in kw["summary"], kw["summary"]


def test_created_fail_names_delta_handles(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """R3F3: the creation terminal names the retained delta handles per leg."""
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(True, False),
            created_deltas=(frozenset({200}), frozenset()),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["fail"]
    assert reason == "self_contradiction", kw
    assert kw["detail"]["created_handles"] == {"correct": [200], "wrong": []}, kw["detail"]


def test_recycled_handle_leak_still_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """R3F3: a refused copy leaking under a recycled number still fails.

    The delta is graded against the leg's own bracketing inventories
    only: a handle seen in an earlier leg and freed since is a fresh
    leak when it reappears, never voided by naive cross-leg matching.
    R4-F1: the leak is correlation-proved (session + attempt identity).
    """
    from _pytest.outcomes import Failed

    import pkcs11_check.testcases.test_keymgmt as km

    finds = iter([set(), set(), {101}])
    copies = iter([101, CkrAssertionError("copy refused", CKR_ATTRIBUTE_READ_ONLY)])

    def _find(_raw: Any, _sh: int, _tmpl: Any) -> list[int]:
        return list(next(finds))

    def _copy(_raw: Any, _sh: int, _handle: int, _attrs: Any) -> int:
        item = next(copies)
        if isinstance(item, BaseException):
            raise item
        return item

    destroyed: list[int] = []
    monkeypatch.setattr(km, "find_objects_exhaustive", _find)
    monkeypatch.setattr(km, "copy_object", _copy)
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    script = _source_script(100) | _source_script(101)
    consumed = _script_identities(monkeypatch, script)
    rs = SimpleNamespace(raw=object(), sh=1)
    out = km._run_guess_legs(
        rs, 100, CKA_VALUE, (b"c", b"w"), b"base", lambda *a: _use(True), label="t"
    )
    correct_exc, wrong_exc, correct_use, wrong_use, created, inventory_rvs, deltas = out
    assert created == (False, True), created
    assert deltas == (frozenset(), frozenset({101})), deltas
    assert destroyed == [101], destroyed
    assert set(consumed) == set(script), consumed
    with pytest.raises(Failed, match="created"):
        cm.judge_guess_confirm(
            correct_exc=correct_exc,
            wrong_exc=wrong_exc,
            correct_use=correct_use,
            wrong_use=wrong_use,
            created_on_refusal=created,
            inventory_rvs=inventory_rvs,
            created_deltas=deltas,
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )


def test_accepted_guess_without_baseline_skips_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R4-F1: an accepted copy with a refused baseline is never used nor destroyed."""
    from _pytest.outcomes import Skipped

    import pkcs11_check.testcases.test_keymgmt as km

    calls = iter([None])
    uses: list[int] = []
    destroyed: list[int] = []

    def _inventory(_rs: Any, **_kw: Any) -> tuple[Any, Any]:
        if next(calls, "after") is None:
            return None, int(CKR_DEVICE_ERROR)
        return {100}, None

    def _uses(_rs: Any, handle: int, _baseline: bytes) -> Any:
        uses.append(int(handle))
        return _use(True)

    monkeypatch.setattr(km, "_inventory_object_set", _inventory)
    monkeypatch.setattr(km, "copy_object", lambda _r, _s, _h, _a: 101)
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    rs = SimpleNamespace(raw=object(), sh=1)
    with pytest.raises(Skipped, match="ownership unproved"):
        km._run_guess_legs(rs, 100, CKA_VALUE, (b"c", b"w"), b"base", _uses, label="t")
    assert uses == [], uses
    assert destroyed == [], destroyed


def test_accepted_guess_identity_mismatch_fails_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R4-F1: an accepted copy with foreign identity fails; never used nor destroyed."""
    from _pytest.outcomes import Failed

    import pkcs11_check.testcases.test_keymgmt as km

    uses: list[int] = []
    destroyed: list[int] = []

    def _uses(_rs: Any, handle: int, _baseline: bytes) -> Any:
        uses.append(int(handle))
        return _use(True)

    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({100}, None))
    monkeypatch.setattr(km, "copy_object", lambda _r, _s, _h, _a: 101)
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    script = _source_script(100) | {
        (101, int(CKA_LABEL)): "foreign",
        (101, int(CKA_TOKEN)): True,
        (101, int(CKA_CLASS)): int(CKO_SECRET_KEY),
        (101, int(CKA_KEY_TYPE)): int(CKK_AES),
    }
    _script_identities(monkeypatch, script)
    rs = SimpleNamespace(raw=object(), sh=1)
    with pytest.raises(Failed, match="not the attempt"):
        km._run_guess_legs(rs, 100, CKA_VALUE, (b"c", b"w"), b"base", _uses, label="t")
    assert uses == [], uses
    assert destroyed == [], destroyed


def test_accepted_guess_unproved_identity_skips_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R4-F1: an accepted copy with unreadable identity voids; never used nor destroyed."""
    from _pytest.outcomes import Skipped

    import pkcs11_check.testcases.test_keymgmt as km
    from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE

    uses: list[int] = []
    destroyed: list[int] = []

    def _uses(_rs: Any, handle: int, _baseline: bytes) -> Any:
        uses.append(int(handle))
        return _use(True)

    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({100}, None))
    monkeypatch.setattr(km, "copy_object", lambda _r, _s, _h, _a: 101)
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    script = _source_script(100) | {
        (101, int(CKA_LABEL)): MISSING_ATTRIBUTE,
        (101, int(CKA_TOKEN)): MISSING_ATTRIBUTE,
        (101, int(CKA_CLASS)): MISSING_ATTRIBUTE,
        (101, int(CKA_KEY_TYPE)): MISSING_ATTRIBUTE,
    }
    _script_identities(monkeypatch, script)
    rs = SimpleNamespace(raw=object(), sh=1)
    with pytest.raises(Skipped, match="ownership unproved"):
        km._run_guess_legs(rs, 100, CKA_VALUE, (b"c", b"w"), b"base", _uses, label="t")
    assert uses == [], uses
    assert destroyed == [], destroyed


def test_oracle_pair_with_refused_third_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """R3F3: a value-sensitive oracle fails; a refused third never voids the pair."""
    from _pytest.outcomes import Failed

    import pkcs11_check.testcases.test_keymgmt as km

    attempts: list[dict[Any, Any]] = []

    def _oracle(_raw: Any, _sh: int, _handle: int, attrs: Any) -> int:
        attempts.append(dict(attrs))
        if attrs.get(CKA_VALUE) == b"correct":
            return 101
        raise CkrAssertionError("wrong value refused", CKR_ATTRIBUTE_READ_ONLY)

    destroyed: list[int] = []
    monkeypatch.setattr(km, "copy_object", _oracle)
    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({100}, None))
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    script = _source_script(100) | _source_script(101)
    consumed = _script_identities(monkeypatch, script)
    rs = SimpleNamespace(raw=object(), sh=1)
    out = km._run_guess_legs(
        rs, 100, CKA_VALUE, (b"correct", b"wrong"), b"base", lambda *a: _use(True), label="t"
    )
    correct_exc, wrong_exc, correct_use, wrong_use, created, inventory_rvs, deltas = out
    third = km._probe_third_value(rs, 100, CKA_VALUE, b"third", label="t")
    assert [a[CKA_VALUE] for a in attempts] == [b"correct", b"wrong", b"third"], attempts
    assert third == ("refused", int(CKR_ATTRIBUTE_READ_ONLY)), third
    assert set(consumed) == set(script), consumed
    with pytest.raises(Failed, match="oracle"):
        cm.judge_guess_confirm(
            correct_exc=correct_exc,
            wrong_exc=wrong_exc,
            correct_use=correct_use,
            wrong_use=wrong_use,
            created_on_refusal=created,
            inventory_rvs=inventory_rvs,
            created_deltas=deltas,
            third_outcome=third,
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )


def test_node_runs_legs_before_third_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """R3F3: the node judges guess legs first; the third probe qualifies after."""
    from _pytest.outcomes import Failed

    import pkcs11_check.testcases.test_keymgmt as km

    order: list[str] = []
    seen_judge: dict[str, Any] = {}
    monkeypatch.setattr(km, "skip_unless_mechanism", lambda _rs, _m: None)
    monkeypatch.setattr(km, "_import_copy_mutability_source", lambda _rs, **_kw: 100)
    monkeypatch.setattr(km, "_sealed_value_unreadable_or_skip", lambda *a, **k: None)
    monkeypatch.setattr(km, "_encrypt_baseline_or_xfail", lambda *a, **k: b"base")
    monkeypatch.setattr(km, "_copy_unchanged_control_or_skip", lambda *a, **k: None)
    monkeypatch.setattr(km, "row_by_key", lambda _k: SimpleNamespace(citation="cite"))

    def _legs(*args: Any, **kwargs: Any) -> Any:
        order.append("legs")
        return (
            None,
            _refused(CKR_ATTRIBUTE_READ_ONLY),
            _use(True),
            None,
            (False, False),
            (None, None),
            (frozenset(), frozenset()),
        )

    def _probe(*args: Any, **kwargs: Any) -> Any:
        order.append("probe")
        return ("refused", int(CKR_ATTRIBUTE_READ_ONLY))

    real_judge = cm.judge_guess_confirm

    def _judge(**kwargs: Any) -> Any:
        seen_judge.update(kwargs)
        return real_judge(**kwargs)

    monkeypatch.setattr(km, "_run_guess_legs", _legs)
    monkeypatch.setattr(km, "_probe_third_value", _probe)
    monkeypatch.setattr(km, "judge_guess_confirm", _judge)
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _m: True)
    with pytest.raises(Failed, match="oracle"):
        km.TestCopyForbiddenMutation().test_copy_sealed_value_guess_confirm_identical(rs)
    assert order == ["legs", "probe"], order
    assert seen_judge["third_outcome"] == ("refused", int(CKR_ATTRIBUTE_READ_ONLY)), seen_judge


def test_identical_refusals_with_accepted_third_notes_selective() -> None:
    """R3F3: identical refusals beside an accepted third pass as selective."""
    from pkcs11_check.compliance import clear_notes, get_notes

    clear_notes()
    assert (
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
            third_outcome=("accepted", None),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
        is None
    )
    assert any("selective" in n.description for n in get_notes()), get_notes()


def test_identical_refusals_with_refused_third_notes_uniform() -> None:
    """R3F3: identical refusals beside a refused third pass as uniform."""
    from pkcs11_check.compliance import clear_notes, get_notes

    clear_notes()
    assert (
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
            third_outcome=("refused", int(CKR_ATTRIBUTE_READ_ONLY)),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
        is None
    )
    assert any("uniform" in n.description for n in get_notes()), get_notes()


def test_vendor_third_rv_xfails_nonspec(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """R3F3: a vendor third-value RV is the established result over a pair pass."""
    with pytest.raises(_SimulatedVerdictError, match="xfail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
            third_outcome=("refused", 0x80000001),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["xfail"]
    assert reason == "nonspec_reject", kw


def test_undefined_third_rv_fails(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """R3F3: an undefined third-value RV fails the metadata contract."""
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
            third_outcome=("refused", 0x7FFFFFFF),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["fail"]
    assert reason == "self_contradiction", kw
    assert "undefined" in kw["summary"], kw["summary"]


def test_mutation_beats_vendor_inventory(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """R3F3: a proved accepted-pair mutation fails before a vendor inventory xfail."""
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=None,
            wrong_exc=None,
            correct_use=_use(False),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
            inventory_rvs=(0x80000001, None),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["fail"]
    assert reason == "self_contradiction", kw
    assert "mutat" in kw["summary"], kw["summary"]


def test_vendor_inventory_beats_ignored_pair(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """R3F3: a vendor inventory alternate beats an ignored-input deviation."""
    with pytest.raises(_SimulatedVerdictError, match="xfail_as"):
        cm.judge_guess_confirm(
            correct_exc=None,
            wrong_exc=None,
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
            inventory_rvs=(0x80000001, None),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["xfail"]
    assert reason == "nonspec_reject", kw


def test_vendor_inventory_beats_use_void(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """R3F3: a vendor inventory alternate beats an accepted-use void."""
    with pytest.raises(_SimulatedVerdictError, match="xfail_as"):
        cm.judge_guess_confirm(
            correct_exc=None,
            wrong_exc=None,
            correct_use=_use(None, int(CKR_DEVICE_ERROR)),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
            inventory_rvs=(0x80000001, None),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["xfail"]
    assert reason == "nonspec_reject", kw


def test_unchanged_control_preexisting_fails_without_destroy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R3F3: an unchanged control returning a baseline handle fails; source survives."""
    from _pytest.outcomes import Failed

    import pkcs11_check.testcases.test_keymgmt as km

    destroyed: list[int] = []
    monkeypatch.setattr(km, "copy_object", lambda _r, _s, _h, _a: 55)
    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({55}, None))
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    rs = SimpleNamespace(raw=object(), sh=1)
    with pytest.raises(Failed, match="pre-existing"):
        km._copy_unchanged_control_or_skip(rs, 100, b"baseline", label="t")
    assert destroyed == [], destroyed


def test_created_single_leg_names_leg_and_rv(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """A2: the creation terminal names the refusing leg and carries its RV."""
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_SENSITIVE),
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(True, False),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["fail"]
    assert reason == "self_contradiction"
    assert "correct" in kw["summary"]
    assert "wrong" not in kw["summary"].split("despite")[0]
    assert kw["actual"] == CKR_ATTRIBUTE_READ_ONLY
    assert kw["detail"]["created_legs"] == ["correct"]


def test_refused_inventory_voids_refusal_to_unproved(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """A2: a refused creation inventory voids the refusal, never passes it."""
    with pytest.raises(_SimulatedVerdictError, match="xfail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(None, False),
            inventory_rvs=(int(CKR_DEVICE_ERROR), None),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["xfail"]
    assert reason == "honest_deviation"
    assert kw["detail"]["disposition"] == "unproved-effect"
    assert "unproved" in kw["summary"]
    assert kw["detail"]["inventory_rvs"] == {"correct": "CKR_DEVICE_ERROR"}


def test_unproved_inventory_on_accepted_pair_proceeds(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """A2: inventory gaps matter only for refused legs; accepted pairs judge on."""
    with pytest.raises(_SimulatedVerdictError, match="xfail_as"):
        cm.judge_guess_confirm(
            correct_exc=None,
            wrong_exc=None,
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(None, None),
            inventory_rvs=(int(CKR_DEVICE_ERROR), int(CKR_DEVICE_ERROR)),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    assert captures["fail"] == []
    (reason, _kw), *_ = captures["xfail"]
    assert reason == "honest_deviation"


def test_standard_divergence_beats_vendor_inventory(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """R4-F3: differing standard refusals fail despite a vendor inventory alternate."""
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_SENSITIVE),
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
            inventory_rvs=(0x80000001, None),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["fail"]
    assert "oracle" in kw["summary"]
    assert captures["xfail"] == []


def test_standard_divergence_beats_vendor_third_probe(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """R4-F3: differing standard refusals fail despite a vendor third probe."""
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_SENSITIVE),
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
            third_outcome=("refused", 0x80000002),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["fail"]
    assert "oracle" in kw["summary"]
    assert captures["xfail"] == []


@pytest.mark.parametrize("mutated_leg", ["correct", "wrong"])
def test_proved_mutation_beats_sibling_use_void(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
    mutated_leg: str,
) -> None:
    """R4-F3: one leg's proved mutation fails despite the sibling's refused use."""
    voided = _use(None, int(CKR_DEVICE_ERROR))
    mutated = _use(False)
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=None,
            wrong_exc=None,
            correct_use=mutated if mutated_leg == "correct" else voided,
            wrong_use=voided if mutated_leg == "correct" else mutated,
            created_on_refusal=(False, False),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    assert [reason for reason, _ in captures["fail"]] == ["self_contradiction"]


def test_both_accepted_use_refused_voids_not_mutated(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """B3: a refused use voids the comparison with its RV, never a mutation FAIL."""
    with pytest.raises(_SimulatedVerdictError, match="xfail_as"):
        cm.judge_guess_confirm(
            correct_exc=None,
            wrong_exc=None,
            correct_use=_use(None, int(CKR_DEVICE_ERROR)),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["xfail"]
    assert reason == "not_operational"
    assert kw["operation"] == "C_Encrypt"
    assert kw["actual"] == int(CKR_DEVICE_ERROR)
    assert "void" in kw["summary"]
    assert captures["fail"] == []


@pytest.mark.parametrize("undefined_first", [True, False])
def test_use_validity_strongest_wins_regardless_of_order(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
    undefined_first: bool,
) -> None:
    """B3: both legs' use RVs are collected; the undefined FAIL wins either way."""
    first, second = (0xDEAD, 0x80000001) if undefined_first else (0x80000001, 0xDEAD)
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=None,
            wrong_exc=None,
            correct_use=_use(None, first),
            wrong_use=_use(None, second),
            created_on_refusal=(False, False),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    assert [(reason, kw["kind"]) for reason, kw in captures["fail"]] == [
        ("self_contradiction", "metadata")
    ]


class _SealRaw:
    """C_GetAttributeValue stub with scripted per-call RVs and lengths."""

    def __init__(self, rv1: int, rv2: int, *, length: int | None, value: bytes = b"") -> None:
        self._rvs = [rv1, rv2]
        self._length = length
        self._value = value
        self._calls = 0

    def C_GetAttributeValue(self, _sh: int, _handle: int, tmpl: Any, _count: int) -> int:  # noqa: N802
        rv = self._rvs[min(self._calls, 1)]
        self._calls += 1
        if self._length is not None:
            import ctypes as _ct

            tmpl[0].ulValueLen = self._length
            if self._calls == 2 and self._value:
                _ct.memmove(tmpl[0].pValue, self._value, len(self._value))
        return rv


def _seal_rs(raw: _SealRaw) -> Any:
    return SimpleNamespace(raw=raw, sh=7)


def test_seal_observed_sensitive_proves_seal() -> None:
    """B3: an observed SENSITIVE refusal (per-attr) proves the seal."""
    import pkcs11_check.testcases.test_keymgmt as km

    raw = _SealRaw(
        int(CKR_ATTRIBUTE_SENSITIVE),
        int(CKR_ATTRIBUTE_SENSITIVE),
        length=int(CK_UNAVAILABLE_INFORMATION),
    )
    km._sealed_value_unreadable_or_skip(_seal_rs(raw), 100, label="t")


def _patch_km_verdicts(
    monkeypatch: pytest.MonkeyPatch, captures: dict[str, list[tuple[str, dict[str, Any]]]]
) -> None:
    """Route test_keymgmt's own verdict imports into the shared captures."""
    import pkcs11_check.testcases.test_keymgmt as km

    def _fail(reason: str, **kw: Any) -> Any:
        captures["fail"].append((reason, kw))
        raise _SimulatedVerdictError(f"fail_as {reason}")

    def _xfail(reason: str, **kw: Any) -> Any:
        captures["xfail"].append((reason, kw))
        raise _SimulatedVerdictError(f"xfail_as {reason}")

    monkeypatch.setattr(km, "fail_as", _fail)
    monkeypatch.setattr(km, "xfail_as", _xfail)


def test_seal_type_invalid_voids_unproved(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """B3: an unrecognised attribute type is not a seal proof."""
    import pkcs11_check.testcases.test_keymgmt as km

    _patch_km_verdicts(monkeypatch, captures)
    raw = _SealRaw(
        int(CKR_ATTRIBUTE_TYPE_INVALID),
        int(CKR_ATTRIBUTE_TYPE_INVALID),
        length=int(CK_UNAVAILABLE_INFORMATION),
    )
    with pytest.raises(_SimulatedVerdictError, match="xfail_as"):
        km._sealed_value_unreadable_or_skip(_seal_rs(raw), 100, label="t")
    assert [reason for reason, _ in captures["xfail"]] == ["not_operational"]


def test_seal_silent_sentinel_voids_unproved(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """B3: CKR_OK with an unavailable length proves no seal (F20 shape)."""
    import pkcs11_check.testcases.test_keymgmt as km
    from pkcs11_check.raw.types_std import CKR_OK

    _patch_km_verdicts(monkeypatch, captures)
    raw = _SealRaw(int(CKR_OK), int(CKR_OK), length=int(CK_UNAVAILABLE_INFORMATION))
    with pytest.raises(_SimulatedVerdictError, match="xfail_as"):
        km._sealed_value_unreadable_or_skip(_seal_rs(raw), 100, label="t")
    assert [reason for reason, _ in captures["xfail"]] == ["not_operational"]


def test_seal_disclosed_value_skips() -> None:
    """A readable sealed value skips (sensitivity tests own it)."""
    from _pytest.outcomes import Skipped

    import pkcs11_check.testcases.test_keymgmt as km
    from pkcs11_check.raw.types_std import CKR_OK

    raw = _SealRaw(int(CKR_OK), int(CKR_OK), length=16, value=b"v" * 16)
    with pytest.raises(Skipped):
        km._sealed_value_unreadable_or_skip(_seal_rs(raw), 100, label="t")


class _SignStub:
    """Raw stub serving scripted C_Sign payloads (two-call convention)."""

    def __init__(self, payloads: list[bytes]) -> None:
        self._payloads = list(payloads)

    def C_SignInit(self, _sh: int, _mech: Any, _key: int) -> int:  # noqa: N802
        from pkcs11_check.raw.types_std import CKR_OK

        return int(CKR_OK)

    def C_Sign(  # noqa: N802
        self, _sh: int, _in_buf: Any, _in_len: int, out: Any, out_len: Any
    ) -> int:
        import ctypes as _ct

        from pkcs11_check.raw.types_std import CK_ULONG, CKR_OK

        out_len_ref = _ct.cast(out_len, _ct.POINTER(CK_ULONG)).contents
        if out is None:
            out_len_ref.value = len(self._payloads[0])
            return int(CKR_OK)
        payload = self._payloads.pop(0)
        _ct.memmove(out, payload, len(payload))
        out_len_ref.value = len(payload)
        return int(CKR_OK)


def _rsa_baseline_key() -> Any:
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_rsa_baseline_verifying_double_sign_returns() -> None:
    """D4: a deterministic, verifying baseline is returned as-is."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    import pkcs11_check.testcases.test_keymgmt as km

    key = _rsa_baseline_key()
    sig = key.sign(km._RSA_GUESS_MESSAGE, padding.PKCS1v15(), hashes.SHA256())
    numbers = key.public_key().public_numbers()
    n = int(numbers.n).to_bytes(256, "big")
    e = int(numbers.e).to_bytes((int(numbers.e).bit_length() + 7) // 8, "big")
    rs = SimpleNamespace(raw=_SignStub([sig, sig]), sh=1)
    assert km._rsa_sign_baseline_or_xfail(rs, 100, label="t", public_numbers=(n, e)) == sig


def test_rsa_baseline_unverifying_double_sign_voids(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D4: deterministic garbage is not a baseline; the leg voids."""
    import pkcs11_check.testcases.test_keymgmt as km

    _patch_km_verdicts(monkeypatch, captures)
    key = _rsa_baseline_key()
    numbers = key.public_key().public_numbers()
    n = int(numbers.n).to_bytes(256, "big")
    e = int(numbers.e).to_bytes((int(numbers.e).bit_length() + 7) // 8, "big")
    rs = SimpleNamespace(raw=_SignStub([b"G" * 256, b"G" * 256]), sh=1)
    with pytest.raises(_SimulatedVerdictError, match="xfail_as"):
        km._rsa_sign_baseline_or_xfail(rs, 100, label="t", public_numbers=(n, e))
    (reason, kw), *_ = captures["xfail"]
    assert reason == "not_operational"
    assert "does not verify" in kw["summary"], kw["summary"]


def test_vendor_first_undefined_second_fails_metadata(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """R2B1: collection first; the undefined sibling FAIL wins over vendor order."""
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(0x80000001),
            wrong_exc=_refused(0xDEAD),
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(False, False),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    assert [(reason, kw["kind"]) for reason, kw in captures["fail"]] == [
        ("self_contradiction", "metadata")
    ]


def test_mixed_with_unproved_inventory_still_fails_oracle(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """R2B1: a proved asymmetry fails; the unproved inventory rides in detail."""
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=None,
            wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            correct_use=_use(True),
            wrong_use=None,
            created_on_refusal=(False, None),
            inventory_rvs=(None, int(CKR_DEVICE_ERROR)),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["fail"]
    assert reason == "self_contradiction"
    assert "oracle" in kw["summary"]
    assert kw["detail"]["created_on_refusal"] == [False, None]


def test_different_rvs_with_unproved_inventory_still_fails(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """R2B1: a proved code difference fails before the inventory void."""
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_SENSITIVE),
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(None, None),
            inventory_rvs=(int(CKR_DEVICE_ERROR), int(CKR_DEVICE_ERROR)),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["fail"]
    assert reason == "self_contradiction"
    assert "differ" in kw["summary"]


def test_third_probe_accepted_reports_and_destroys(monkeypatch: pytest.MonkeyPatch) -> None:
    """R3F3: an accepted third value reports accepted; the probe copy is destroyed."""
    import pkcs11_check.testcases.test_keymgmt as km

    seen: list[dict[Any, Any]] = []
    destroyed: list[int] = []

    def _copy(_raw: Any, _sh: int, _handle: int, attrs: Any) -> int:
        seen.append(dict(attrs))
        return 55

    monkeypatch.setattr(km, "copy_object", _copy)
    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({9}, None))
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    script = _source_script(100) | {
        (55, int(CKA_LABEL)): "src",
        (55, int(CKA_TOKEN)): False,
    }
    consumed = _script_identities(monkeypatch, script)
    rs = SimpleNamespace(raw=object(), sh=1)
    assert km._probe_third_value(rs, 100, CKA_VALUE, b"v" * 16, label="t") == ("accepted", None)
    assert seen == [{CKA_VALUE: b"v" * 16}]
    assert destroyed == [55]
    assert set(consumed) == set(script), consumed


def test_third_probe_unproved_identity_leaks_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R4-F1: an accepted third with unreadable identity leaks deliberately; signal kept."""
    import pkcs11_check.testcases.test_keymgmt as km
    from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE

    destroyed: list[int] = []
    monkeypatch.setattr(km, "copy_object", lambda _r, _s, _h, _a: 55)
    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({9}, None))
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    script = _source_script(100) | {
        (55, int(CKA_LABEL)): MISSING_ATTRIBUTE,
        (55, int(CKA_TOKEN)): MISSING_ATTRIBUTE,
        (55, int(CKA_CLASS)): MISSING_ATTRIBUTE,
        (55, int(CKA_KEY_TYPE)): MISSING_ATTRIBUTE,
    }
    _script_identities(monkeypatch, script)
    rs = SimpleNamespace(raw=object(), sh=1)
    from pkcs11_check.compliance import get_notes

    before = len(get_notes())
    assert km._probe_third_value(rs, 100, CKA_VALUE, b"v" * 16, label="t") == ("accepted", None)
    assert destroyed == [], destroyed
    fresh = get_notes()[before:]
    assert any("leaked deliberately" in n.description for n in fresh), fresh


def test_third_probe_identity_mismatch_fails_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R4-F1: an accepted third with foreign identity fails; nothing destroyed."""
    from _pytest.outcomes import Failed

    import pkcs11_check.testcases.test_keymgmt as km

    destroyed: list[int] = []
    monkeypatch.setattr(km, "copy_object", lambda _r, _s, _h, _a: 55)
    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({9}, None))
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    script = _source_script(100) | {
        (55, int(CKA_LABEL)): "foreign",
        (55, int(CKA_TOKEN)): True,
        (55, int(CKA_CLASS)): int(CKO_SECRET_KEY),
        (55, int(CKA_KEY_TYPE)): int(CKK_AES),
    }
    _script_identities(monkeypatch, script)
    rs = SimpleNamespace(raw=object(), sh=1)
    with pytest.raises(Failed, match="not the attempt"):
        km._probe_third_value(rs, 100, CKA_VALUE, b"v" * 16, label="t")
    assert destroyed == [], destroyed


def test_third_probe_without_baseline_leaks_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R4-F1: an accepted third with a refused baseline leaks deliberately; signal kept."""
    import pkcs11_check.testcases.test_keymgmt as km

    destroyed: list[int] = []
    monkeypatch.setattr(km, "copy_object", lambda _r, _s, _h, _a: 55)
    monkeypatch.setattr(
        km, "_inventory_object_set", lambda _rs, **_kw: (None, int(CKR_DEVICE_ERROR))
    )
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    rs = SimpleNamespace(raw=object(), sh=1)
    from pkcs11_check.compliance import get_notes

    before = len(get_notes())
    assert km._probe_third_value(rs, 100, CKA_VALUE, b"v" * 16, label="t") == ("accepted", None)
    assert destroyed == [], destroyed
    fresh = get_notes()[before:]
    assert any("leaked deliberately" in n.description for n in fresh), fresh


def test_control_accepted_without_baseline_skips_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R4-F1: an accepted control with a refused baseline is never used nor destroyed."""
    from _pytest.outcomes import Skipped

    import pkcs11_check.testcases.test_keymgmt as km

    uses: list[int] = []
    destroyed: list[int] = []

    def _uses(_rs: Any, handle: int, _baseline: bytes) -> Any:
        uses.append(int(handle))
        return _use(True)

    monkeypatch.setattr(
        km, "_inventory_object_set", lambda _rs, **_kw: (None, int(CKR_DEVICE_ERROR))
    )
    monkeypatch.setattr(km, "copy_object", lambda _r, _s, _h, _a: 55)
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    rs = SimpleNamespace(raw=object(), sh=1)
    with pytest.raises(Skipped, match="ownership unproved"):
        km._copy_unchanged_control_or_skip(rs, 100, b"baseline", label="t", preserves=_uses)
    assert uses == [], uses
    assert destroyed == [], destroyed


def test_control_accepted_identity_mismatch_fails_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R4-F1: an accepted control with foreign identity fails; never used nor destroyed."""
    from _pytest.outcomes import Failed

    import pkcs11_check.testcases.test_keymgmt as km

    uses: list[int] = []
    destroyed: list[int] = []

    def _uses(_rs: Any, handle: int, _baseline: bytes) -> Any:
        uses.append(int(handle))
        return _use(True)

    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({100}, None))
    monkeypatch.setattr(km, "copy_object", lambda _r, _s, _h, _a: 55)
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    script = _source_script(100) | {
        (55, int(CKA_LABEL)): "foreign",
        (55, int(CKA_TOKEN)): True,
        (55, int(CKA_CLASS)): int(CKO_SECRET_KEY),
        (55, int(CKA_KEY_TYPE)): int(CKK_AES),
    }
    _script_identities(monkeypatch, script)
    rs = SimpleNamespace(raw=object(), sh=1)
    with pytest.raises(Failed, match="not the attempt"):
        km._copy_unchanged_control_or_skip(rs, 100, b"baseline", label="t", preserves=_uses)
    assert uses == [], uses
    assert destroyed == [], destroyed


def test_control_accepted_correlated_proceeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """R4-F1: an accepted control with proved identity is used and destroyed."""
    import pkcs11_check.testcases.test_keymgmt as km

    uses: list[int] = []
    destroyed: list[int] = []

    def _uses(_rs: Any, handle: int, _baseline: bytes) -> Any:
        uses.append(int(handle))
        return _use(True)

    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({100}, None))
    monkeypatch.setattr(km, "copy_object", lambda _r, _s, _h, _a: 55)
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    script = _source_script(100) | {
        (55, int(CKA_LABEL)): "src",
        (55, int(CKA_TOKEN)): False,
    }
    consumed = _script_identities(monkeypatch, script)
    rs = SimpleNamespace(raw=object(), sh=1)
    km._copy_unchanged_control_or_skip(rs, 100, b"baseline", label="t", preserves=_uses)
    assert uses == [55], uses
    assert destroyed == [55], destroyed
    assert set(consumed) == set(script), consumed


def test_guess_sources_stamp_labels(monkeypatch: pytest.MonkeyPatch) -> None:
    """R4-F1: guess sources carry labels so copies inherit correlation identity."""
    import pkcs11_check.testcases.test_keymgmt as km

    seen_aes: dict[Any, Any] = {}
    seen_rsa: dict[Any, Any] = {}

    def _aes(*args: Any, **kwargs: Any) -> int:
        seen_aes.update(kwargs.get("attrs", {}))
        return 100

    def _rsa(*args: Any, **kwargs: Any) -> int:
        seen_rsa.update(kwargs.get("attrs", {}))
        return 101

    monkeypatch.setattr(km, "import_secret_key", _aes)
    monkeypatch.setattr(km, "import_rsa_private_key_negotiated", _rsa)
    rs = SimpleNamespace(raw=object(), sh=1)
    km._import_copy_mutability_source(rs)
    km._import_sealed_rsa_or_xfail(
        rs,
        {
            "n": b"n",
            "e": b"e",
            "d": b"d",
            "p": b"p",
            "q": b"q",
            "dmp1": b"a",
            "dmq1": b"b",
            "iqmp": b"c",
        },
        label="t",
    )
    assert seen_aes.get(CKA_LABEL), seen_aes
    assert seen_rsa.get(CKA_LABEL), seen_rsa


def test_direct_copy_mismatch_fails_untouched(monkeypatch: pytest.MonkeyPatch) -> None:
    """R4-F1 variant: the direct copy node adopts only a correlated handle."""
    from _pytest.outcomes import Failed

    import pkcs11_check.testcases.test_keymgmt as km

    checked: list[int] = []
    destroyed: list[int] = []
    monkeypatch.setattr(km, "skip_unless_mechanism", lambda _rs, _m: None)
    monkeypatch.setattr(km, "row_by_key", lambda _k: SimpleNamespace(citation="cite"))
    monkeypatch.setattr(km, "_import_copy_mutability_source", lambda _rs, **_kw: 100)
    monkeypatch.setattr(km, "_encrypt_baseline_or_xfail", lambda *a, **k: b"base")
    monkeypatch.setattr(km, "copy_object", lambda _r, _s, _h, _a: 55)
    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({9}, None))
    monkeypatch.setattr(km, "check_material_preserved", lambda *a, **k: checked.append(1))
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    script = _source_script(100) | {
        (55, int(CKA_LABEL)): "foreign",
        (55, int(CKA_TOKEN)): True,
        (55, int(CKA_CLASS)): int(CKO_SECRET_KEY),
        (55, int(CKA_KEY_TYPE)): int(CKK_AES),
    }
    _script_identities(monkeypatch, script)
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _m: True)
    with pytest.raises(Failed, match="not the attempt"):
        km.TestCopyForbiddenMutation().test_copy_different_value_material_ignored_or_refused(rs)
    assert checked == [], checked
    assert destroyed == [100], destroyed


def test_preserves_use_refusal_names_failing_stage() -> None:
    """R4-F7: a refused use carries the Init or Encrypt stage that refused it."""
    import pkcs11_check.testcases.test_keymgmt as km

    class _UseRaw:
        def __init__(self, init_rv: int, op_rv: int) -> None:
            self._init_rv = init_rv
            self._op_rv = op_rv

        def C_EncryptInit(self, *_args: Any) -> int:  # noqa: N802
            return self._init_rv

        def C_Encrypt(self, *_args: Any) -> int:  # noqa: N802
            return self._op_rv

        def C_SignInit(self, *_args: Any) -> int:  # noqa: N802
            return self._init_rv

        def C_Sign(self, *_args: Any) -> int:  # noqa: N802
            return self._op_rv

    from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_OK

    init_fail = SimpleNamespace(raw=_UseRaw(int(CKR_DEVICE_ERROR), int(CKR_OK)), sh=1)
    outcome = km._copy_preserves_aes_material(init_fail, 5, b"baseline")
    assert outcome.preserved is None
    assert outcome.use_rv == int(CKR_DEVICE_ERROR)
    assert outcome.operation == "C_EncryptInit", outcome.operation

    op_fail = SimpleNamespace(raw=_UseRaw(int(CKR_OK), int(CKR_DEVICE_ERROR)), sh=1)
    outcome = km._copy_preserves_aes_material(op_fail, 5, b"baseline")
    assert outcome.preserved is None
    assert outcome.operation == "C_Encrypt", outcome.operation

    sign_fail = SimpleNamespace(raw=_UseRaw(int(CKR_DEVICE_ERROR), int(CKR_OK)), sh=1)
    outcome = km._copy_preserves_rsa_material(sign_fail, 5, b"sig")
    assert outcome.preserved is None
    assert outcome.operation == "C_SignInit", outcome.operation


def test_unproved_arm_names_retained_deltas(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
) -> None:
    """R4-F3: the unproved terminal names the retained delta handles per leg."""
    with pytest.raises(_SimulatedVerdictError, match="xfail_as"):
        cm.judge_guess_confirm(
            correct_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            wrong_exc=_refused(CKR_ATTRIBUTE_READ_ONLY),
            correct_use=_use(True),
            wrong_use=_use(True),
            created_on_refusal=(None, False),
            inventory_rvs=(int(CKR_DEVICE_ERROR), None),
            created_deltas=(frozenset({200}), frozenset()),
            expected_rvs=EXPECTED,
            label=LABEL,
            operation=OPERATION,
            spec_ref=SPEC_REF,
        )
    (reason, kw), *_ = captures["xfail"]
    assert reason == "honest_deviation"
    assert kw["detail"].get("retained_deltas") == {"correct": [200], "wrong": []}


def test_third_probe_refused_reports_rv_without_skipping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R3F3: a refused third value reports its RV; the pair still gets judged."""
    import pkcs11_check.testcases.test_keymgmt as km

    def _refuse(_raw: Any, _sh: int, _handle: int, _attrs: Any) -> int:
        raise CkrAssertionError("no value overrides", CKR_ATTRIBUTE_READ_ONLY)

    monkeypatch.setattr(km, "copy_object", _refuse)
    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({9}, None))
    rs = SimpleNamespace(raw=object(), sh=1)
    assert km._probe_third_value(rs, 100, CKA_VALUE, b"v" * 16, label="t") == (
        "refused",
        int(CKR_ATTRIBUTE_READ_ONLY),
    )


def test_third_probe_alias_fails_without_destroy(monkeypatch: pytest.MonkeyPatch) -> None:
    """R3F3: a probe copy returning the source fails; the source is left alone."""
    from _pytest.outcomes import Failed

    import pkcs11_check.testcases.test_keymgmt as km

    destroyed: list[int] = []
    monkeypatch.setattr(km, "copy_object", lambda _r, _s, h, _a: h)
    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({9}, None))
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    rs = SimpleNamespace(raw=object(), sh=1)
    with pytest.raises(Failed, match="source handle"):
        km._probe_third_value(rs, 100, CKA_VALUE, b"v" * 16, label="t")
    assert destroyed == [], destroyed


def test_third_probe_preexisting_fails_without_destroy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R3F3: a probe copy returning a baseline handle fails; nothing is destroyed."""
    from _pytest.outcomes import Failed

    import pkcs11_check.testcases.test_keymgmt as km

    destroyed: list[int] = []
    monkeypatch.setattr(km, "copy_object", lambda _r, _s, _h, _a: 55)
    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({55}, None))
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    rs = SimpleNamespace(raw=object(), sh=1)
    with pytest.raises(Failed, match="pre-existing"):
        km._probe_third_value(rs, 100, CKA_VALUE, b"v" * 16, label="t")
    assert destroyed == [], destroyed


def test_control_alias_fails_without_destroy(
    captures: dict[str, list[tuple[str, dict[str, Any]]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R2B1: an aliased control duplicate fails; the source is left alone."""
    import pkcs11_check.testcases.test_keymgmt as km

    _patch_km_verdicts(monkeypatch, captures)
    destroyed: list[int] = []
    monkeypatch.setattr(km, "copy_object", lambda _r, _s, h, _a: h)
    monkeypatch.setattr(km, "_inventory_object_set", lambda _rs, **_kw: ({9}, None))
    monkeypatch.setattr(km, "destroy_quietly", lambda _r, _s, h: destroyed.append(h))
    rs = SimpleNamespace(raw=object(), sh=1)
    with pytest.raises(_SimulatedVerdictError, match="fail_as"):
        km._copy_unchanged_control_or_skip(rs, 100, b"baseline", label="t")
    (reason, kw), *_ = captures["fail"]
    assert reason == "self_contradiction"
    assert 100 not in destroyed, destroyed
