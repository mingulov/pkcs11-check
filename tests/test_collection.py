"""Tests for pytest collection metadata helpers."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from pkcs11_check.core import collection as col
from pkcs11_check.core.collection import (
    CollectedPytestItem,
    CollectedSkip,
    _read_collection_cache,
    collect_pytest_item_metadata,
    collect_pytest_items_with_skips,
    load_collection_manifest,
    load_collection_manifest_with_skips,
    save_collection_manifest,
)


def test_collection_manifest_round_trip(tmp_path: Path) -> None:
    manifest_path = tmp_path / "collection.json"
    items = [
        CollectedPytestItem(
            nodeid="tests/test_demo.py::test_case",
            file_path=str((tmp_path / "test_demo.py").resolve()),
            markers=["subprocess_per_test", "smoke"],
        )
    ]

    save_collection_manifest(manifest_path, items)

    assert load_collection_manifest(manifest_path) == items


def test_collect_pytest_item_metadata_reports_markers(tmp_path: Path) -> None:
    target = tmp_path / "test_demo.py"
    target.write_text(
        "import pytest\n"
        "pytestmark = [pytest.mark.subprocess_per_test, pytest.mark.smoke]\n\n"
        "def test_case():\n"
        "    assert True\n",
        encoding="utf-8",
    )

    items = collect_pytest_item_metadata([str(target)], [])

    # Assert the node-id IDENTIFIES this file and test, not its exact relative spelling.
    # The spelling depends on pytest's rootdir, which is the common ancestor of the CWD and
    # the args -- so it is "test_demo.py::test_case" here but an absolute path when the file
    # is on a different drive from the CWD (Windows CI: workspace D:, %TEMP% C:), where
    # pytest emits no path at all and item_nodeid substitutes the absolute one. File
    # identity is the contract; the relative form was an accident of where pytest was run.
    assert len(items) == 1
    assert items[0].nodeid.endswith(f"{target.name}::test_case")
    assert items[0].file_path == str(target.resolve())
    assert set(items[0].markers) >= {"subprocess_per_test", "smoke"}


# ---------------------------------------------------------------------------
# F-016: malformed manifest entries fail loudly, never skip silently
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "items",
    [
        [{"nodeid": 123, "file_path": "x.py"}],
        [{"nodeid": "n"}],
        [{"file_path": "x.py"}],
        ["not-an-object"],
        [None],
        [{"nodeid": "n", "file_path": "f", "markers": "slow"}],
        [{"nodeid": "n", "file_path": "f", "markers": ["ok", 7]}],
        [{"nodeid": "n", "file_path": "f", "markers": None}],
    ],
)
def test_load_collection_manifest_rejects_malformed_entries(
    tmp_path: Path, items: list[object]
) -> None:
    """F-016: every silent-skip shape is now a loud ValueError."""
    manifest_path = tmp_path / "collection.json"
    manifest_path.write_text(json.dumps({"items": items}), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid collection manifest"):
        load_collection_manifest(manifest_path)


def test_load_collection_manifest_keeps_tolerant_shapes(tmp_path: Path) -> None:
    """Strictness rejects malformed entries, not forward-compatible shapes."""
    manifest_path = tmp_path / "collection.json"
    manifest_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "nodeid": "a.py::t",
                        "file_path": "a.py",
                        "future_key": {"nested": [1]},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (item,) = load_collection_manifest(manifest_path)
    assert (item.nodeid, item.file_path, item.markers) == ("a.py::t", "a.py", [])

    bare_path = tmp_path / "bare.json"
    bare_path.write_text(json.dumps([{"nodeid": "b.py::t", "file_path": "b.py"}]), encoding="utf-8")
    (bare,) = load_collection_manifest(bare_path)
    assert (bare.nodeid, bare.file_path) == ("b.py::t", "b.py")


def test_malformed_cache_invalidates(tmp_path: Path) -> None:
    """F-016: a cache with a malformed entry reads as a miss (recollect)."""
    cache_path = tmp_path / "digest.json"
    cache_path.write_text(
        json.dumps(
            {
                "items": [
                    {"nodeid": "a.py::t", "file_path": "a.py", "markers": []},
                    {"bogus": "entry"},
                ]
            }
        ),
        encoding="utf-8",
    )
    assert _read_collection_cache(cache_path) is None


def test_malformed_cache_triggers_fresh_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F-016 composition: corrupt cache is skipped, fresh output wins and replaces it."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    monkeypatch.setattr(col, "_collection_cache_dir", lambda: cache_dir)
    targets, args = ["t.py"], ["-p", "no:cacheprovider"]
    digest = col._collection_inputs_digest(targets, args, None)
    assert digest is not None
    cache_path = cache_dir / f"{digest}.json"
    cache_path.write_text(json.dumps({"items": [{"bogus": "entry"}]}), encoding="utf-8")

    calls: list[list[str]] = []

    def _fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        calls.append(cmd)
        out = Path(cmd[cmd.index("--output") + 1])
        out.write_text(
            json.dumps({"items": [{"nodeid": "t.py::t", "file_path": "t.py", "markers": []}]}),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(col.subprocess, "run", _fake_run)
    items = collect_pytest_item_metadata(targets, args, env={})

    assert len(calls) == 1
    assert [item.nodeid for item in items] == ["t.py::t"]
    assert len(json.loads(cache_path.read_text(encoding="utf-8"))["items"]) == 1


def test_malformed_fresh_collection_fails_visibly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F-016: malformed helper output raises out of collection (exit-2 path)."""

    def _fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        out = Path(cmd[cmd.index("--output") + 1])
        out.write_text(json.dumps({"items": [{"nodeid": 123}]}), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(col.subprocess, "run", _fake_run)
    with pytest.raises(ValueError, match="invalid collection manifest"):
        collect_pytest_item_metadata(
            ["anything.py"], [], env={"PKCS11_CHECK_NO_COLLECTION_CACHE": "1"}
        )


def test_explicit_empty_env_is_not_treated_as_unset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An explicitly-passed empty env means empty, not 'inherit os.environ'."""
    monkeypatch.setenv("PKCS11_CHECK_NO_COLLECTION_CACHE", "1")
    monkeypatch.setenv("PKCS11_CHECK_DATA_DIR", "/should/not/leak")
    seen: dict[str, object] = {}

    def _fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen["env"] = kwargs.get("env")
        out = Path(cmd[cmd.index("--output") + 1])
        out.write_text(json.dumps({"items": []}), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(col.subprocess, "run", _fake_run)
    monkeypatch.setattr(col, "_collection_cache_dir", lambda: tmp_path)
    collect_pytest_item_metadata(["anything.py"], [], env={})
    assert seen["env"] == {}, f"explicit empty env leaked os.environ: {seen['env']!r}"


def _fake_collect_run(
    seen: dict[str, object],
) -> Callable[..., subprocess.CompletedProcess[str]]:
    def _fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen["ran"] = True
        out = Path(cmd[cmd.index("--output") + 1])
        out.write_text(json.dumps({"items": []}), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    return _fake_run


def test_explicit_env_dropping_data_override_bypasses_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Parent override + env without it: digest would hash A while child reads B (F2).

    The cache must be bypassed rather than serve a manifest collected elsewhere.
    """
    data_a = tmp_path / "data-a"
    data_a.mkdir()
    monkeypatch.setenv("PKCS11_CHECK_DATA_DIR", str(data_a))
    monkeypatch.delenv("PKCS11_CHECK_NO_COLLECTION_CACHE", raising=False)
    seen: dict[str, object] = {}
    consulted: list[Path] = []

    def _spy_read_cache(path: Path) -> None:
        consulted.append(path)
        return None

    monkeypatch.setattr("pkcs11_check.core.collection.subprocess.run", _fake_collect_run(seen))
    monkeypatch.setattr(col, "_collection_cache_dir", lambda: tmp_path)
    monkeypatch.setattr(col, "_read_collection_cache", _spy_read_cache)
    collect_pytest_item_metadata(["anything.py"], [], env={})
    assert seen.get("ran") is True, "child collection did not run"
    assert consulted == [], f"stale cache consulted despite dropped override: {consulted!r}"


def test_explicit_env_with_differing_home_bypasses_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Explicit HOME != parent HOME changes the fallback root: bypass (R2b).

    Path.home() honors $HOME, so the parent digest and the child would walk
    different XDG fallback trees.
    """
    home_a = tmp_path / "home-a"
    home_b = tmp_path / "home-b"
    home_a.mkdir()
    home_b.mkdir()
    monkeypatch.setenv("HOME", str(home_a))
    monkeypatch.delenv("PKCS11_CHECK_DATA_DIR", raising=False)
    monkeypatch.delenv("PKCS11_CHECK_NO_COLLECTION_CACHE", raising=False)
    seen: dict[str, object] = {}
    consulted: list[Path] = []

    def _spy_read_cache(path: Path) -> None:
        consulted.append(path)
        return None

    monkeypatch.setattr("pkcs11_check.core.collection.subprocess.run", _fake_collect_run(seen))
    monkeypatch.setattr(col, "_collection_cache_dir", lambda: tmp_path)
    monkeypatch.setattr(col, "_read_collection_cache", _spy_read_cache)
    collect_pytest_item_metadata(["anything.py"], [], env={"HOME": str(home_b)})
    assert seen.get("ran") is True, "child collection did not run"
    assert consulted == [], f"stale cache consulted despite shifted HOME: {consulted!r}"


def test_explicit_env_dropping_home_bypasses_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Explicit env without HOME while the parent has it: bypass (R2b).

    Pwd-fallback equivalence is platform fragile; bypass is always correct.
    """
    home_a = tmp_path / "home-a"
    home_a.mkdir()
    monkeypatch.setenv("HOME", str(home_a))
    monkeypatch.delenv("PKCS11_CHECK_DATA_DIR", raising=False)
    monkeypatch.delenv("PKCS11_CHECK_NO_COLLECTION_CACHE", raising=False)
    seen: dict[str, object] = {}
    consulted: list[Path] = []

    def _spy_read_cache(path: Path) -> None:
        consulted.append(path)
        return None

    monkeypatch.setattr("pkcs11_check.core.collection.subprocess.run", _fake_collect_run(seen))
    monkeypatch.setattr(col, "_collection_cache_dir", lambda: tmp_path)
    monkeypatch.setattr(col, "_read_collection_cache", _spy_read_cache)
    collect_pytest_item_metadata(["anything.py"], [], env={})
    assert seen.get("ran") is True, "child collection did not run"
    assert consulted == [], f"stale cache consulted despite dropped HOME: {consulted!r}"


def test_explicit_env_with_same_home_uses_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Control: carried HOME keeps the cache (R2b)."""
    home_a = tmp_path / "home-a"
    home_a.mkdir()
    monkeypatch.setenv("HOME", str(home_a))
    monkeypatch.delenv("PKCS11_CHECK_DATA_DIR", raising=False)
    monkeypatch.delenv("PKCS11_CHECK_NO_COLLECTION_CACHE", raising=False)
    seen: dict[str, object] = {}
    consulted: list[Path] = []

    def _spy_read_cache(path: Path) -> None:
        consulted.append(path)
        return None

    monkeypatch.setattr("pkcs11_check.core.collection.subprocess.run", _fake_collect_run(seen))
    monkeypatch.setattr(col, "_collection_cache_dir", lambda: tmp_path)
    monkeypatch.setattr(col, "_read_collection_cache", _spy_read_cache)
    carried: dict[str, str] = {"HOME": str(home_a)}
    for var in ("USERPROFILE", "HOMEDRIVE", "HOMEPATH"):
        # Portable control: every home-root input the parent has set must be
        # carried, or the bypass under test fires for the wrong variable.
        if os.environ.get(var) is not None:
            carried[var] = os.environ[var]
    collect_pytest_item_metadata(["anything.py"], [], env=carried)
    assert len(consulted) == 1, "cache not consulted despite identical HOME"


def test_explicit_env_with_differing_userprofile_bypasses_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Windows root input: differing USERPROFILE also bypasses (R2b)."""
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", "C:\\Users\\a")
    monkeypatch.delenv("PKCS11_CHECK_DATA_DIR", raising=False)
    monkeypatch.delenv("PKCS11_CHECK_NO_COLLECTION_CACHE", raising=False)
    seen: dict[str, object] = {}
    consulted: list[Path] = []

    def _spy_read_cache(path: Path) -> None:
        consulted.append(path)
        return None

    monkeypatch.setattr("pkcs11_check.core.collection.subprocess.run", _fake_collect_run(seen))
    monkeypatch.setattr(col, "_collection_cache_dir", lambda: tmp_path)
    monkeypatch.setattr(col, "_read_collection_cache", _spy_read_cache)
    collect_pytest_item_metadata(
        ["anything.py"],
        [],
        env={"USERPROFILE": "C:\\Users\\b", "HOME": str(home_dir)},
    )
    assert seen.get("ran") is True, "child collection did not run"
    assert consulted == [], f"stale cache consulted despite shifted USERPROFILE: {consulted!r}"


@pytest.mark.parametrize("var", ["HOMEDRIVE", "HOMEPATH"])
def test_explicit_env_with_differing_drive_path_bypasses_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, var: str
) -> None:
    """Windows fallback without USERPROFILE: differing drive/path bypasses (R3b).

    USERPROFILE is absent on both sides to isolate the HOMEDRIVE/HOMEPATH
    fallback that Path.home() uses in that case.
    """
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    old = "C:" if var == "HOMEDRIVE" else "\\Users\\a"
    new = "D:" if var == "HOMEDRIVE" else "\\Users\\b"
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv(var, old)
    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.delenv("PKCS11_CHECK_DATA_DIR", raising=False)
    monkeypatch.delenv("PKCS11_CHECK_NO_COLLECTION_CACHE", raising=False)
    seen: dict[str, object] = {}
    consulted: list[Path] = []

    def _spy_read_cache(path: Path) -> None:
        consulted.append(path)
        return None

    monkeypatch.setattr("pkcs11_check.core.collection.subprocess.run", _fake_collect_run(seen))
    monkeypatch.setattr(col, "_collection_cache_dir", lambda: tmp_path)
    monkeypatch.setattr(col, "_read_collection_cache", _spy_read_cache)
    collect_pytest_item_metadata(["anything.py"], [], env={"HOME": str(home_dir), var: new})
    assert seen.get("ran") is True, "child collection did not run"
    assert consulted == [], f"stale cache consulted despite shifted {var}: {consulted!r}"


def test_explicit_env_carrying_drive_path_uses_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Control: identical drive/path keeps the cache (R3b)."""
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("HOMEDRIVE", "C:")
    monkeypatch.setenv("HOMEPATH", "\\Users\\a")
    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.delenv("PKCS11_CHECK_DATA_DIR", raising=False)
    monkeypatch.delenv("PKCS11_CHECK_NO_COLLECTION_CACHE", raising=False)
    seen: dict[str, object] = {}
    consulted: list[Path] = []

    def _spy_read_cache(path: Path) -> None:
        consulted.append(path)
        return None

    monkeypatch.setattr("pkcs11_check.core.collection.subprocess.run", _fake_collect_run(seen))
    monkeypatch.setattr(col, "_collection_cache_dir", lambda: tmp_path)
    monkeypatch.setattr(col, "_read_collection_cache", _spy_read_cache)
    collect_pytest_item_metadata(
        ["anything.py"],
        [],
        env={"HOME": str(home_dir), "HOMEDRIVE": "C:", "HOMEPATH": "\\Users\\a"},
    )
    assert len(consulted) == 1, "cache not consulted despite identical drive/path"


def test_explicit_env_carrying_data_override_uses_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Control: env carrying the same override keeps the cache (no wholesale disable)."""
    data_a = tmp_path / "data-a"
    data_a.mkdir()
    monkeypatch.setenv("PKCS11_CHECK_DATA_DIR", str(data_a))
    monkeypatch.delenv("PKCS11_CHECK_NO_COLLECTION_CACHE", raising=False)
    seen: dict[str, object] = {}
    consulted: list[Path] = []

    def _spy_read_cache(path: Path) -> None:
        consulted.append(path)
        return None

    monkeypatch.setattr("pkcs11_check.core.collection.subprocess.run", _fake_collect_run(seen))
    monkeypatch.setattr(col, "_collection_cache_dir", lambda: tmp_path)
    monkeypatch.setattr(col, "_read_collection_cache", _spy_read_cache)
    collect_pytest_item_metadata(["anything.py"], [], env={"PKCS11_CHECK_DATA_DIR": str(data_a)})
    assert len(consulted) == 1, "cache not consulted despite carried override"


def test_collect_items_with_skips_reports_module_skip(tmp_path: Path) -> None:
    """R18-2a: a module-level skip yields no items and one skip record."""
    target = tmp_path / "test_skipped_mod.py"
    target.write_text(
        "import pytest\n"
        'pytest.skip("vectors not cloned", allow_module_level=True)\n'
        "\n"
        "def test_never():\n"
        "    pass\n",
        encoding="utf-8",
    )
    env = {**os.environ, "PKCS11_CHECK_NO_COLLECTION_CACHE": "1"}
    items, skips = collect_pytest_items_with_skips([str(target)], [], env=env)
    assert items == []
    assert len(skips) == 1
    assert skips[0].nodeid.endswith(target.name)
    assert skips[0].reason == "vectors not cloned"


def test_collection_skip_pairs_empty_nodeid_with_started_collector() -> None:
    """R19-win: an empty report nodeid (cross-rootpath target) resolves via
    the most recent collectstart -- the shape Windows CI produces."""
    from types import SimpleNamespace

    plugin = col._CollectionPlugin()
    plugin.pytest_collectstart(SimpleNamespace(nodeid="", path=Path("C:/Temp/test_skipped_mod.py")))
    plugin.pytest_collectreport(
        SimpleNamespace(
            outcome="skipped",
            nodeid="",
            longrepr=("C:/Temp/test_skipped_mod.py", 2, "Skipped: vectors not cloned"),
        )
    )
    assert plugin.skips == [
        col.CollectedSkip(nodeid="C:/Temp/test_skipped_mod.py", reason="vectors not cloned")
    ]


def test_collection_skip_ignores_stale_started_collector() -> None:
    """R19-win: a mismatched pairing stays empty rather than misattributing."""
    from types import SimpleNamespace

    plugin = col._CollectionPlugin()
    plugin.pytest_collectstart(SimpleNamespace(nodeid="other.py", path=Path("/tmp/other.py")))
    plugin.pytest_collectreport(
        SimpleNamespace(outcome="skipped", nodeid="", longrepr="Skipped: why")
    )
    assert plugin.skips == [col.CollectedSkip(nodeid="", reason="why")]


def test_collect_items_with_skips_matches_legacy_items(tmp_path: Path) -> None:
    """R18-2a: the combined API returns the same items as the legacy one."""
    target = tmp_path / "test_demo.py"
    target.write_text(
        "def test_case():\n    assert True\n",
        encoding="utf-8",
    )
    env = {**os.environ, "PKCS11_CHECK_NO_COLLECTION_CACHE": "1"}
    items, skips = collect_pytest_items_with_skips([str(target)], [], env=env)
    assert skips == []
    assert items == collect_pytest_item_metadata([str(target)], [], env=env)
    assert len(items) == 1


def test_collection_manifest_skips_round_trip(tmp_path: Path) -> None:
    """R18-2a: skips survive a manifest round trip; legacy load ignores them."""
    manifest_path = tmp_path / "collection.json"
    items = [
        CollectedPytestItem(
            nodeid="test_demo.py::test_case",
            file_path=str((tmp_path / "test_demo.py").resolve()),
            markers=[],
        )
    ]
    skips = [CollectedSkip(nodeid="test_skipped.py", reason="vectors not cloned")]
    save_collection_manifest(manifest_path, items, skips)
    assert load_collection_manifest_with_skips(manifest_path) == (items, skips)
    assert load_collection_manifest(manifest_path) == items


def test_collection_manifest_missing_skips_means_none(tmp_path: Path) -> None:
    """R18-2a: old manifests without the skips key load with no skips."""
    manifest_path = tmp_path / "collection.json"
    manifest_path.write_text('{"items": []}\n', encoding="utf-8")
    assert load_collection_manifest_with_skips(manifest_path) == ([], [])


@pytest.mark.parametrize(
    "skips_payload",
    [
        {"nodeid": "x.py"},
        {"reason": "why"},
        {"nodeid": 1, "reason": "why"},
        {"nodeid": "x.py", "reason": None},
        "not-an-object",
    ],
)
def test_collection_manifest_malformed_skips_raise(tmp_path: Path, skips_payload: object) -> None:
    """R18-2a: malformed skip records fail loudly, like malformed items."""
    manifest_path = tmp_path / "collection.json"
    manifest_path.write_text(
        json.dumps({"items": [], "collection_skips": [skips_payload]}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="skip"):
        load_collection_manifest_with_skips(manifest_path)


def test_collection_digest_invalidates_on_external_target_edit(tmp_path: Path) -> None:
    """R19-2: editing an external target file changes the cache digest."""
    target = tmp_path / "test_external.py"
    target.write_text("def test_one(): pass\n", encoding="utf-8")
    before = col._collection_inputs_digest([str(target)], [])
    assert before is not None
    target.write_text("def test_one(): pass\ndef test_two_added(): pass\n", encoding="utf-8")
    after = col._collection_inputs_digest([str(target)], [])
    assert after is not None
    assert before != after


def test_collection_digest_covers_nodeid_and_dir_targets(tmp_path: Path) -> None:
    """R19-2: nodeid targets hash their file; dir targets hash their trees."""
    target = tmp_path / "test_external.py"
    target.write_text("def test_one(): pass\n", encoding="utf-8")
    nodeid_before = col._collection_inputs_digest([f"{target}::test_one"], [])
    dir_before = col._collection_inputs_digest([str(tmp_path)], [])
    target.write_text("def test_one(): pass\ndef test_two_added(): pass\n", encoding="utf-8")
    assert col._collection_inputs_digest([f"{target}::test_one"], []) != nodeid_before
    assert col._collection_inputs_digest([str(tmp_path)], []) != dir_before


def test_collection_recollects_after_external_target_edit(tmp_path: Path) -> None:
    """R19-2 end to end: a new matching test is collected, never stale-hit."""
    first = tmp_path / "test_first.py"
    second = tmp_path / "test_second.py"
    first.write_text("def test_match_me(): pass\n", encoding="utf-8")
    second.write_text("def test_unrelated(): pass\n", encoding="utf-8")
    cache_env = {
        key: value for key, value in os.environ.items() if key != "PKCS11_CHECK_NO_COLLECTION_CACHE"
    }
    args = ["-k", "match_me"]
    # Warm the cache, then add a matching test to the second file.
    assert len(collect_pytest_item_metadata([str(first), str(second)], args, env=cache_env)) == 1
    second.write_text(
        "def test_unrelated(): pass\ndef test_match_me_too(): pass\n", encoding="utf-8"
    )
    items = collect_pytest_item_metadata([str(first), str(second)], args, env=cache_env)
    assert sorted(item.nodeid.split("::")[-1] for item in items) == [
        "test_match_me",
        "test_match_me_too",
    ]
