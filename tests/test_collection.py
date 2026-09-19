"""Tests for pytest collection metadata helpers."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from pkcs11_check.core import collection as col
from pkcs11_check.core.collection import (
    CollectedPytestItem,
    _read_collection_cache,
    collect_pytest_item_metadata,
    load_collection_manifest,
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
