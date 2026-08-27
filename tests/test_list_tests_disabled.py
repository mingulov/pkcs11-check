"""list-tests must agree with what `test` would actually run (GH #6).

The reporter asked whether list-tests excludes the disabled tests, having compared runs
with and without P11TEST_DISABLED_TESTS_FILE and seen the same count. It did not: the
command never built a P11TestConfig at all, so the whole config layer -- TOML and every
P11TEST_* variable, disabled_tests_file included -- applied to `test` and not to
`list-tests`. The command exists to build disabled-tests files, so listing node-ids that
are already disabled is the wrong default.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pkcs11_check.core.disabled_baseline import resolve_disabled_nodeids


def _baseline(tmp_path: Path, *nodeids: str) -> Path:
    path = tmp_path / "disabled-tests.txt"
    path.write_text("\n".join(nodeids) + "\n", encoding="utf-8")
    return path


def test_resolves_the_configured_baseline(tmp_path: Path) -> None:
    path = _baseline(tmp_path, "a.py::test_one", "b.py::test_two")

    nodeids, fingerprint = resolve_disabled_nodeids(disabled_tests_file=path)

    assert nodeids == {"a.py::test_one", "b.py::test_two"}
    assert fingerprint != "disabled-baseline:none"


def test_ignore_flag_disables_the_baseline(tmp_path: Path) -> None:
    path = _baseline(tmp_path, "a.py::test_one")

    nodeids, fingerprint = resolve_disabled_nodeids(disabled_tests_file=path, ignore=True)

    assert nodeids == set()
    assert fingerprint == "disabled-baseline:none"


def test_missing_baseline_file_is_an_error(tmp_path: Path) -> None:
    """A configured-but-absent baseline must fail loudly, never silently run everything."""
    with pytest.raises(FileNotFoundError):
        resolve_disabled_nodeids(disabled_tests_file=tmp_path / "nope.txt")


def test_list_tests_excludes_disabled_by_default(tmp_path: Path, monkeypatch) -> None:
    from pkcs11_check.cli import list_tests_cmd

    path = _baseline(tmp_path, "x/test_b.py::test_two")
    monkeypatch.setenv("P11TEST_DISABLED_TESTS_FILE", str(path))
    monkeypatch.setattr(
        list_tests_cmd,
        "collect_pytest_nodeids",
        lambda *a, **k: ["x/test_a.py::test_one", "x/test_b.py::test_two"],
    )

    nodeids = list_tests_cmd.enumerate_nodeids(
        [],
        match=None,
        marker=None,
        category=None,
        skip_slow=False,
        only_slow=False,
        module=None,
        interface="auto",
        slot=0,
    )

    assert nodeids == ["x/test_a.py::test_one"], "disabled node-ids must not be listed"


def test_list_tests_can_include_disabled(tmp_path: Path, monkeypatch) -> None:
    from pkcs11_check.cli import list_tests_cmd

    path = _baseline(tmp_path, "x/test_b.py::test_two")
    monkeypatch.setenv("P11TEST_DISABLED_TESTS_FILE", str(path))
    monkeypatch.setattr(
        list_tests_cmd,
        "collect_pytest_nodeids",
        lambda *a, **k: ["x/test_a.py::test_one", "x/test_b.py::test_two"],
    )

    nodeids = list_tests_cmd.enumerate_nodeids(
        [],
        match=None,
        marker=None,
        category=None,
        skip_slow=False,
        only_slow=False,
        module=None,
        interface="auto",
        slot=0,
        include_disabled=True,
    )

    assert nodeids == ["x/test_a.py::test_one", "x/test_b.py::test_two"]


def test_selection_config_reads_the_toml_key(tmp_path: Path, monkeypatch) -> None:
    """The TOML key must work, not only the env var (four-layer config, GH #3/#6)."""
    from pkcs11_check.config import SelectionConfig

    (tmp_path / "pkcs11_check.toml").write_text(
        'disabled_tests_file = "from-toml.txt"\n', encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("P11TEST_DISABLED_TESTS_FILE", raising=False)

    assert SelectionConfig().disabled_tests_file == Path("from-toml.txt")
