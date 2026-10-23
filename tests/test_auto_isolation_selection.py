"""Exact selected-node scheduling for automatic per-test isolation."""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

import pytest

from pkcs11_check.core import _unit_discovery as discovery
from pkcs11_check.core._run_state import build_policy_fingerprint
from pkcs11_check.core._run_units import BackendIsolationPolicy
from pkcs11_check.core.collection import CollectedPytestItem


def _uncached_collection_env() -> dict[str, str]:
    # The collection cache currently keys sorted targets. Ordering controls must
    # collect afresh when they deliberately reverse or interleave selectors.
    return {**os.environ, "PKCS11_CHECK_NO_COLLECTION_CACHE": "1"}


def _save_promotion(path: Path, source: Path, env: dict[str, str]) -> None:
    fingerprint = build_policy_fingerprint([], env)
    discovery.save_isolation_policy(
        path,
        {
            fingerprint: BackendIsolationPolicy(
                fingerprint=fingerprint,
                promoted_files=[str(source.resolve())],
                crashed_tests=[],
            )
        },
    )


def test_fixed_metadata_32_explicit_nodes_expand_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "test_probe.py"
    source.write_text("def test_case(): pass\n", encoding="utf-8")
    selected = [f"{source}::test_case[{index}]" for index in range(32)]
    metadata = [
        CollectedPytestItem(nodeid, str(source), ["subprocess_per_test"]) for nodeid in selected
    ]
    monkeypatch.setattr(discovery, "collect_pytest_item_metadata", lambda *args, **kwargs: metadata)
    canonicalized: list[str] = []
    original_absolute_nodeid = discovery._absolute_nodeid

    def observe_absolute_nodeid(file_key: str, nodeid: str) -> str:
        result = original_absolute_nodeid(file_key, nodeid)
        canonicalized.append(result)
        return result

    monkeypatch.setattr(discovery, "_absolute_nodeid", observe_absolute_nodeid)

    units = discovery.discover_auto_isolation_units(selected, tmp_path, pytest_args=[])

    assert units == selected
    assert Counter(units) == {node: 1 for node in selected}
    # One canonicalization per indexed item also bounds nonempty-metadata
    # expansion; a final-output-only dedup would still do 32 x 32 work.
    assert canonicalized == selected


@pytest.mark.parametrize("promotion", ["marker", "policy"])
def test_native_32_explicit_nodes_preserve_selection(
    promotion: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "test_thirty_two.py"
    marker = "pytestmark = pytest.mark.subprocess_per_test\n" if promotion == "marker" else ""
    source.write_text(
        "import pytest\n"
        f"{marker}"
        "@pytest.mark.parametrize('case', range(32))\n"
        "def test_case(case):\n"
        "    assert case >= 0\n",
        encoding="utf-8",
    )
    order = list(range(32)) if promotion == "marker" else list(reversed(range(32)))
    selected = [f"{source}::test_case[{index}]" for index in order]
    env = _uncached_collection_env()
    policy_file = tmp_path / "policy.json"
    if promotion == "policy":
        _save_promotion(policy_file, source, env)
    collected: list[CollectedPytestItem] = []
    canonicalized: list[str] = []
    original_absolute_nodeid = discovery._absolute_nodeid

    def observe_absolute_nodeid(file_key: str, nodeid: str) -> str:
        result = original_absolute_nodeid(file_key, nodeid)
        canonicalized.append(result)
        return result

    monkeypatch.setattr(discovery, "_absolute_nodeid", observe_absolute_nodeid)

    units = discovery.discover_auto_isolation_units(
        selected,
        tmp_path,
        pytest_args=[],
        policy_file=policy_file if promotion == "policy" else None,
        env=env,
        collected_out=collected,
    )

    assert [item.nodeid.partition("::")[2] for item in collected] == [
        f"test_case[{index}]" for index in order
    ]
    assert len(collected) == 32
    if promotion == "marker":
        assert all("subprocess_per_test" in item.markers for item in collected)
    else:
        assert all("subprocess_per_test" not in item.markers for item in collected)
    assert units == selected
    assert Counter(units) == {node: 1 for node in selected}
    assert canonicalized == selected
    assert all("::" in unit for unit in units)


def test_interleaved_files_keep_first_file_grouping(tmp_path: Path) -> None:
    first = tmp_path / "test_first.py"
    second = tmp_path / "test_second.py"
    for source in (first, second):
        source.write_text(
            "import pytest\n"
            "pytestmark = pytest.mark.subprocess_per_test\n"
            "def test_one(): pass\n"
            "def test_two(): pass\n",
            encoding="utf-8",
        )
    selected = [
        f"{first}::test_one",
        f"{second}::test_one",
        f"{first}::test_two",
        f"{second}::test_two",
    ]
    collected: list[CollectedPytestItem] = []

    units = discovery.discover_auto_isolation_units(
        selected,
        tmp_path,
        pytest_args=[],
        env=_uncached_collection_env(),
        collected_out=collected,
    )

    assert [item.nodeid.partition("::")[2] for item in collected] == [
        "test_one",
        "test_one",
        "test_two",
        "test_two",
    ]
    assert units == [
        f"{first}::test_one",
        f"{first}::test_two",
        f"{second}::test_one",
        f"{second}::test_two",
    ]
    assert Counter(units) == {node: 1 for node in selected}


def test_class_function_and_alias_overlap_keep_opaque_parameter_tails(tmp_path: Path) -> None:
    source = tmp_path / "test_opaque.py"
    ids = ['quote"here', "space here", r"back\slash", "Ω", "outer[inner]"]
    source.write_text(
        "import pytest\n"
        "pytestmark = pytest.mark.subprocess_per_test\n"
        "class TestGroup:\n"
        f"    @pytest.mark.parametrize('case', range(5), ids={ids!r})\n"
        "    def test_case(self, case): pass\n"
        "def test_unselected_sibling(): pass\n",
        encoding="utf-8",
    )
    alias_dir = tmp_path / "alias_dir"
    alias_dir.mkdir()
    alias = alias_dir / ".." / source.name
    selected = [
        f"{source}::TestGroup",
        f"{source}::TestGroup::test_case",
        f"{alias}::TestGroup::test_case[space here]",
    ]
    expected = [f"{source}::TestGroup::test_case[{case_id}]" for case_id in ids]

    units = discovery.discover_auto_isolation_units(
        selected,
        tmp_path,
        pytest_args=[
            "-o",
            "disable_test_id_escaping_and_forfeit_all_rights_to_community_support=true",
        ],
        env=_uncached_collection_env(),
    )

    assert units == expected
    assert Counter(units) == {node: 1 for node in expected}
    assert all("test_unselected_sibling" not in node for node in units)


def test_bare_file_class_function_and_explicit_overlap_includes_sibling(tmp_path: Path) -> None:
    source = tmp_path / "test_overlap.py"
    source.write_text(
        "import pytest\n"
        "pytestmark = pytest.mark.subprocess_per_test\n"
        "def test_one(): pass\n"
        "def test_sibling(): pass\n"
        "class TestGroup:\n"
        "    def test_member(self): pass\n",
        encoding="utf-8",
    )
    selected = [
        f"{source}::test_one",
        f"{source}::TestGroup",
        str(source),
        f"{source}::TestGroup::test_member",
    ]
    collected: list[CollectedPytestItem] = []

    units = discovery.discover_auto_isolation_units(
        selected,
        tmp_path,
        pytest_args=[],
        env=_uncached_collection_env(),
        collected_out=collected,
    )

    assert [item.nodeid.partition("::")[2] for item in collected] == [
        "test_one",
        "test_sibling",
        "TestGroup::test_member",
    ]
    assert units == [
        f"{source}::test_one",
        f"{source}::test_sibling",
        f"{source}::TestGroup::test_member",
    ]
    assert Counter(units) == {node: 1 for node in units}


def test_unpromoted_file_mode_keeps_original_selectors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "test_file_mode.py"
    source.write_text("def test_one(): pass\ndef test_two(): pass\n", encoding="utf-8")
    targets = [f"{source}::test_one", str(source), f"{source}::test_two"]
    metadata = [
        CollectedPytestItem(f"{source}::test_one", str(source), []),
        CollectedPytestItem(f"{source}::test_two", str(source), []),
    ]
    monkeypatch.setattr(discovery, "collect_pytest_item_metadata", lambda *args, **kwargs: metadata)

    assert discovery.discover_auto_isolation_units(targets, tmp_path, pytest_args=[]) == targets


def test_nonempty_metadata_skips_requested_file_missing_from_collection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first = tmp_path / "test_present.py"
    missing = tmp_path / "test_missing.py"
    for source in (first, missing):
        source.write_text("def test_case(): pass\n", encoding="utf-8")
    metadata = [CollectedPytestItem(f"{first}::test_case", str(first), ["subprocess_per_test"])]
    monkeypatch.setattr(discovery, "collect_pytest_item_metadata", lambda *args, **kwargs: metadata)
    monkeypatch.setattr(discovery, "load_promoted_files", lambda *args, **kwargs: {str(missing)})

    units = discovery.discover_auto_isolation_units(
        [str(first), str(missing)], tmp_path, pytest_args=[]
    )

    assert units == [f"{first}::test_case"]


def test_empty_metadata_fallback_collects_each_selector_and_unique_additions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "test_fallback.py"
    source.write_text("def test_a(): pass\ndef test_b(): pass\n", encoding="utf-8")
    first = f"{source}::test_a"
    second = f"{source}::test_b"
    monkeypatch.setattr(discovery, "collect_pytest_item_metadata", lambda *args, **kwargs: [])
    monkeypatch.setattr(discovery, "load_promoted_files", lambda *args, **kwargs: {str(source)})
    fallback_calls: list[list[str]] = []

    def selected_units(
        targets: list[str],
        default_root: Path,
        *,
        granularity: str,
        pytest_args: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> list[str]:
        del default_root, pytest_args, env
        if granularity == "file":
            return list(targets)
        fallback_calls.append(list(targets))
        return [first] if targets == [first] else [first, second]

    monkeypatch.setattr(discovery, "discover_pytest_units", selected_units)

    units = discovery.discover_auto_isolation_units([first, second], tmp_path, pytest_args=[])

    assert fallback_calls == [[first], [second]]
    assert units == [first, second]
    assert Counter(units) == {first: 1, second: 1}
