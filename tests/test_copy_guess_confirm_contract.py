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
    CKA_VALUE,
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
    monkeypatch.setattr(km, "_session_object_set", lambda _rs, **_kw: ({9}, None))
    rs = SimpleNamespace(raw=object(), sh=1)
    correct_exc, wrong_exc, correct_use, wrong_use, created, inventory_rvs = km._run_guess_legs(
        rs,
        100,
        CKA_VALUE,
        (b"correct-guess", b"wrong-guess"),
        b"baseline",
        lambda *a: _use(True),
        label="t",
    )
    assert seen == [{CKA_VALUE: b"correct-guess"}, {CKA_VALUE: b"wrong-guess"}]
    assert correct_exc is not None and wrong_exc is not None
    assert (correct_use, wrong_use, created, inventory_rvs) == (
        None,
        None,
        (False, False),
        (None, None),
    )


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
