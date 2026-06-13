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
    ],
)
def test_derive_verdict(reason, kind, outcome, severity):
    assert derive_verdict(reason, kind) == (outcome, severity)


def test_derive_verdict_rejects_unknown_reason():
    with pytest.raises(ValueError):
        derive_verdict("not_a_reason", None)
