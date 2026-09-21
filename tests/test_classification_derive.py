import pytest

from pkcs11_check.classification import derive_verdict


@pytest.mark.parametrize(
    "reason,kind,outcome,severity",
    [
        ("wrong_result", "crypto", "fail", "CRITICAL"),
        ("wrong_result", "metadata", "fail", "MEDIUM"),
        ("accepted_invalid", "crypto", "fail", "CRITICAL"),
        ("accepted_invalid", "policy", "fail", "CRITICAL"),
        ("accepted_invalid", "lifecycle", "fail", "HIGH"),
        ("accepted_invalid", "metadata", "fail", "HIGH"),
        ("self_contradiction", "policy", "fail", "CRITICAL"),
        ("self_contradiction", "lifecycle", "fail", "HIGH"),
        ("self_contradiction", "metadata", "fail", "HIGH"),
        ("oracle", "crypto", "fail", "HIGH"),
        ("crash", None, "fail", "HIGH"),
        ("not_operational", None, "xfail", "LOW"),
        ("nonspec_reject", None, "xfail", "LOW"),
        ("honest_deviation", "metadata", "xfail", "LOW"),
        ("sanctioned_refusal", None, "pass", "INFO"),
        ("unclassified", None, "fail", "HIGH"),
        # M-38: the central table must cover every reason in _REASON_OUTCOME.
        # These three were pinned only in satellite files (or not at all), so a
        # one-row deletion here silently unpinned a verdict/severity rule.
        ("undeclared_capability", None, "xfail", "LOW"),
        ("harness_error", None, "fail", "HIGH"),
        ("probe_incomplete", None, "fail", "HIGH"),
    ],
)
def test_derive_verdict(reason, kind, outcome, severity):
    assert derive_verdict(reason, kind) == (outcome, severity)


def test_derive_verdict_rejects_unknown_reason():
    with pytest.raises(ValueError):
        derive_verdict("not_a_reason", None)


def test_central_table_covers_every_reason():
    """M-38: one deleted parametrize row must fail loudly, not unpin a rule.

    Reads the reasons straight off this file's parametrize mark (not a second
    hardcoded list, which could drift the same way) and requires exact cover of
    classification._REASON_OUTCOME.
    """
    from pkcs11_check.classification import _REASON_OUTCOME

    parametrized: set[str] = set()
    for mark in getattr(test_derive_verdict, "pytestmark", []):
        if mark.name != "parametrize":
            continue
        argnames = mark.args[0].split(",")
        reason_at = argnames.index("reason")
        parametrized.update(values[reason_at] for values in mark.args[1])
    assert parametrized, "parametrize-mark introspection found no rows; fix the meta-test"
    assert parametrized == set(_REASON_OUTCOME), (
        "central verdict table drifted from _REASON_OUTCOME "
        f"(missing: {sorted(set(_REASON_OUTCOME) - parametrized)}); "
        "add the missing row(s) above"
    )
