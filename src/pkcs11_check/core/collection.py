"""Pytest collection metadata helpers for isolation planning."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

import pytest


@dataclass(frozen=True)
class CollectedPytestItem:
    """Collection metadata for one pytest item."""

    nodeid: str
    file_path: str
    markers: list[str]


def save_collection_manifest(path: Path, items: list[CollectedPytestItem]) -> None:
    """Persist collected pytest item metadata as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"items": [asdict(item) for item in items]}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def load_collection_manifest(path: Path) -> list[CollectedPytestItem]:
    """Load collected pytest item metadata from JSON."""
    raw = json.loads(path.read_text())
    raw_items = raw.get("items", raw)
    if not isinstance(raw_items, list):
        msg = f"invalid collection manifest: {path}"
        raise ValueError(msg)
    items: list[CollectedPytestItem] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        nodeid = item.get("nodeid")
        file_path = item.get("file_path")
        markers = item.get("markers", [])
        if not isinstance(nodeid, str) or not isinstance(file_path, str):
            continue
        marker_names = [str(marker) for marker in markers if isinstance(marker, str)]
        items.append(
            CollectedPytestItem(
                nodeid=nodeid,
                file_path=file_path,
                markers=marker_names,
            )
        )
    return items


def collect_pytest_item_metadata(
    targets: list[str],
    pytest_args: list[str],
    *,
    env: dict[str, str] | None = None,
) -> list[CollectedPytestItem]:
    """Collect pytest item metadata in a fresh subprocess."""
    input_fd, input_raw_path = tempfile.mkstemp(
        prefix="pkcs11-check-collect-input-",
        suffix=".json",
    )
    output_fd, output_raw_path = tempfile.mkstemp(
        prefix="pkcs11-check-collect-output-",
        suffix=".json",
    )
    input_path = Path(input_raw_path)
    output_path = Path(output_raw_path)
    os.close(input_fd)
    os.close(output_fd)

    try:
        input_path.write_text(
            json.dumps({"targets": targets, "pytest_args": pytest_args}, sort_keys=True) + "\n"
        )
        cmd = [
            sys.executable,
            "-m",
            "pkcs11_check.core.collection",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ]
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            env=dict(env or os.environ),
        )

        if completed.returncode not in {0, 5}:
            details = (
                completed.stderr.strip() or completed.stdout.strip() or "unknown collection error"
            )
            msg = f"pytest metadata collection failed: {details}"
            raise ValueError(msg)

        if not output_path.exists():
            return []

        return load_collection_manifest(output_path)
    finally:
        input_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)


class _CollectionPlugin:
    """Collect marker metadata for each pytest item."""

    def __init__(self) -> None:
        self.items: list[CollectedPytestItem] = []

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        for item in session.items:
            item_path = getattr(item, "path", None)
            if item_path is None:
                file_path = Path(item.nodeid.split("::", 1)[0]).resolve()
            else:
                file_path = Path(item_path).resolve()
            markers = sorted({marker.name for marker in item.iter_markers()})
            self.items.append(
                CollectedPytestItem(
                    nodeid=item.nodeid,
                    file_path=str(file_path),
                    markers=markers,
                )
            )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write pytest collection metadata")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> None:
    """CLI entry point for the helper subprocess."""
    args = _parse_args()
    raw = json.loads(Path(args.input).read_text())
    targets = [str(target) for target in raw.get("targets", [])]
    pytest_args = [str(arg) for arg in raw.get("pytest_args", [])]
    plugin = _CollectionPlugin()
    exit_code = pytest.main(
        [
            *targets,
            *pytest_args,
            "--collect-only",
            "-qq",
            "--no-header",
        ],
        plugins=[plugin],
    )
    save_collection_manifest(Path(args.output), plugin.items)
    raise SystemExit(int(exit_code))


if __name__ == "__main__":
    main()
