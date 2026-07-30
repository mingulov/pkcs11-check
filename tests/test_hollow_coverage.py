"""Tests for the aggregate hollow-pass coverage oracle (core/hollow_coverage.py)."""

from __future__ import annotations

from pkcs11_check.core.hollow_coverage import assess_hollow_coverage


def test_kmsp11_sign_once_in_110k_is_flagged() -> None:
    findings = assess_hollow_coverage({"C_Sign": 110_000}, {"C_Sign": 1})
    assert len(findings) == 1
    f = findings[0]
    assert f.operation == "C_Sign"
    assert f.claimed_passes == 110_000
    assert f.productive_ok == 1
    assert f.ratio < 0.001


def test_healthy_provider_is_not_flagged() -> None:
    assert assess_hollow_coverage({"C_Sign": 5000}, {"C_Sign": 5000}) == []


def test_ratio_above_one_not_flagged() -> None:
    # A vector suite invokes C_Sign more than once per test -> ratio > 1, clearly healthy.
    assert assess_hollow_coverage({"C_Sign": 100}, {"C_Sign": 900}) == []


def test_below_min_population_not_flagged() -> None:
    # Only 5 claimed passes -> too small a population to judge, even at ratio 0.
    assert assess_hollow_coverage({"C_Sign": 5}, {"C_Sign": 0}, min_population=20) == []


def test_threshold_tunable() -> None:
    inp_claimed, inp_prod = {"C_Sign": 100}, {"C_Sign": 30}
    assert assess_hollow_coverage(inp_claimed, inp_prod, ratio_threshold=0.10) == []  # 0.30 >= 0.10
    flagged = assess_hollow_coverage(inp_claimed, inp_prod, ratio_threshold=0.50)  # 0.30 < 0.50
    assert len(flagged) == 1


def test_family_map_sums_productive_counts() -> None:
    # A "C_Sign" claim satisfied by multipart C_SignUpdate must not be flagged as hollow.
    findings = assess_hollow_coverage(
        {"C_Sign": 100},
        {"C_SignUpdate": 100},
        family_map={"C_Sign": frozenset({"C_Sign", "C_SignInit", "C_SignUpdate", "C_SignFinal"})},
    )
    assert findings == []


def test_missing_productive_key_counts_as_zero() -> None:
    findings = assess_hollow_coverage({"C_Decrypt": 500}, {})
    assert len(findings) == 1 and findings[0].productive_ok == 0
