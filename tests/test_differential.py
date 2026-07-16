"""Tests for the N-way differential cross-provider oracle (core/differential.py)."""

from __future__ import annotations

from pkcs11_check.core.differential import find_disagreements


def test_odd_one_out_on_deterministic_vector() -> None:
    # 3 providers run the same KAT node-id; two pass, one fails -> the failer is the suspect.
    per_provider = {
        "prov_a": {"t.py::kat[v1]": "passed"},
        "prov_b": {"t.py::kat[v1]": "passed"},
        "prov_c": {"t.py::kat[v1]": "failed"},
    }
    disagreements = find_disagreements(per_provider)
    assert len(disagreements) == 1
    d = disagreements[0]
    assert d.nodeid == "t.py::kat[v1]"
    assert d.majority == "pass"
    assert d.minority_providers == ["prov_c"]


def test_unanimous_pass_is_not_flagged() -> None:
    per_provider = {
        "a": {"t.py::v": "passed"},
        "b": {"t.py::v": "passed"},
        "c": {"t.py::v": "passed"},
    }
    assert find_disagreements(per_provider) == []


def test_skips_excluded_as_capability_gaps() -> None:
    # A provider that SKIPPED (capability gap) is not a disagreement with those that ran.
    per_provider = {
        "a": {"t.py::v": "passed"},
        "b": {"t.py::v": "passed"},
        "c": {"t.py::v": "skipped"},
    }
    assert find_disagreements(per_provider) == []


def test_below_min_providers_not_flagged() -> None:
    # Only one provider actually attempted -> nothing to compare.
    per_provider = {
        "a": {"t.py::v": "passed"},
        "b": {"t.py::v": "skipped"},
    }
    assert find_disagreements(per_provider, min_providers=2) == []


def test_two_way_disagreement_flagged_without_majority() -> None:
    # With exactly 2 attempts that disagree, both are named (no majority to single one out).
    per_provider = {"a": {"t.py::v": "passed"}, "b": {"t.py::v": "failed"}}
    d = find_disagreements(per_provider, min_providers=2)
    assert len(d) == 1
    assert d[0].majority == "tie"
    assert sorted(d[0].minority_providers) == ["a", "b"]


def test_nodeid_filter_restricts_to_kat_suites() -> None:
    per_provider = {
        "a": {"wp.py::kat[v]": "passed", "other.py::x": "passed"},
        "b": {"wp.py::kat[v]": "failed", "other.py::x": "failed"},
    }
    d = find_disagreements(per_provider, nodeid_filter=frozenset({"wp.py::kat[v]"}))
    assert [x.nodeid for x in d] == ["wp.py::kat[v]"]
