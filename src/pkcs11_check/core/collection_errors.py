"""Self-describing diagnostics for a failed pytest collection (GH #3).

Two collectors run pytest to enumerate tests: ``collection.py`` (item metadata, used by
``test``) and ``_unit_discovery.py`` (node-ids, used by ``list-tests``). Both used to
report a failure as

    pytest metadata collection failed: <stderr or stdout>

which drops one of the two streams and says nothing about the environment. A user hit
"ERROR: found no collectors for ...\\testcases" on Windows and neither of us could tell
whether the path was missing, unreadable, empty, or fine -- the run could not start and
the tool could not say why. This module builds one message that answers those questions
up front, so the next report arrives diagnosable.
"""

from __future__ import annotations

import json
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from pkcs11_check.core.nodeids import normalize_nodeid
from pkcs11_check.core.report_log import SessionCompletionTracker

_MAX_STREAM = 4000


def collection_failure_sidecar_path(state_file: Path) -> Path:
    """Return the durable collection-attempt source beside a runner state file."""
    return state_file.with_name(f"{state_file.name}.collection.jsonl")


def ensure_failed_collection_report(
    path: Path,
    *,
    target: str | None,
    status: str,
    returncode: int,
    stdout: str,
    stderr: str,
) -> bool:
    """Append one collection record when pytest failed before reportlog emitted evidence."""
    if status != "failed" or returncode == 0:
        return False

    def matches_target(record: Mapping[str, Any]) -> bool:
        if target is None:
            return record.get("$report_type") in {"TestReport", "CollectReport"}
        nodeid = str(record.get("nodeid", ""))
        if not nodeid:
            return True
        target_file = normalize_nodeid(target.split("::", 1)[0])
        node_file = normalize_nodeid(nodeid.split("::", 1)[0])
        if nodeid == target or node_file == target_file:
            return True
        try:
            return Path(node_file).resolve() == Path(target_file).resolve()
        except OSError:
            return False

    diagnostic = (
        "\n".join([*_stream_excerpt("stderr", stderr), *_stream_excerpt("stdout", stdout)])
        if stderr.strip() or stdout.strip()
        else f"pytest unit {target or '<collection>'} failed with exit code {returncode}"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    record_target = target or "<collection>"
    record_line = (
        json.dumps(
            {
                "$report_type": "CollectReport",
                "nodeid": record_target,
                "when": "collect",
                "outcome": "failed",
                "longrepr": diagnostic,
                "source": "runner-fallback",
            }
        )
        + "\n"
    )
    completion = SessionCompletionTracker()
    existing_collection = False
    existing_test = False
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            inserted = False
            try:
                source = path.open(encoding="utf-8")
            except OSError:
                source = None
            if source is not None:
                with source:
                    for raw_line in source:
                        parsed: object | None = None
                        if raw_line.strip():
                            try:
                                parsed = json.loads(raw_line)
                            except json.JSONDecodeError:
                                completion.invalidate()
                            else:
                                if isinstance(parsed, dict):
                                    completion.observe(parsed)
                                    if matches_target(parsed):
                                        if (
                                            parsed.get("$report_type") == "CollectReport"
                                            and parsed.get("outcome") == "failed"
                                        ):
                                            if (
                                                parsed.get("source") != "runner-fallback"
                                                or parsed.get("longrepr") == diagnostic
                                            ):
                                                existing_collection = True
                                        elif (
                                            parsed.get("$report_type") == "TestReport"
                                            and target != "<collection>"
                                        ):
                                            existing_test = True
                                else:
                                    completion.invalidate()
                        if not inserted:
                            if (
                                isinstance(parsed, dict)
                                and parsed.get("$report_type") == "SessionFinish"
                                and parsed.get("exitstatus") == returncode
                            ):
                                temporary.write(record_line)
                                inserted = True
                        temporary.write(raw_line)
            if existing_collection or existing_test:
                return False
            if (
                target != "<collection>"
                and returncode in {1, 2, 3, 4}
                and not (
                    returncode in {0, 1, 5}
                    and completion.complete
                    and completion.starts == 1
                    and completion.finishes == 1
                    and completion.single_exitstatus == returncode
                )
            ):
                return False
            if not inserted:
                temporary.write(record_line)
        assert temporary_path is not None
        temporary_path.replace(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return True


def _describe_target(raw_target: str) -> str:
    """One line on a collection target: does it exist, is it readable, what is in it."""
    # A node-id target ("file.py::test") only makes sense as its file part on disk.
    path = Path(raw_target.split("::", 1)[0])
    try:
        if not path.exists():
            return f"  {raw_target}: does not exist"
        if path.is_file():
            return f"  {raw_target}: file, {path.stat().st_size} bytes"
        test_files = list(path.rglob("test_*.py"))
        readable = "readable" if _is_readable(path) else "NOT READABLE"
        return f"  {raw_target}: directory, {readable}, {len(test_files)} test_*.py files"
    except OSError as exc:
        # Permission denied, a vanished mount, an AV/indexer lock on Windows: all are
        # answers to "why did collection fail", so report rather than swallow.
        return f"  {raw_target}: cannot stat ({type(exc).__name__}: {exc})"


def _is_readable(path: Path) -> bool:
    try:
        next(path.iterdir(), None)
    except OSError:
        return False
    return True


def _stream_excerpt(label: str, text: str) -> list[str]:
    stripped = text.strip()
    if not stripped:
        return [f"{label}: (empty)"]
    if len(stripped) > _MAX_STREAM:
        omitted = len(stripped) - _MAX_STREAM
        half = _MAX_STREAM // 2
        # Head AND tail: a traceback's exception is on the last line.
        stripped = f"{stripped[:half]}\n... [{omitted} chars omitted] ...\n{stripped[-half:]}"
    return [f"{label}:", stripped]


def collection_failure_message(
    *,
    returncode: int,
    stdout: str,
    stderr: str,
    targets: Sequence[str],
    pytest_args: Sequence[str],
) -> str:
    """Build a collection-failure message that explains itself.

    Reports BOTH streams (pytest writes collection errors to stdout, so an
    ``stderr or stdout`` choice loses them), the exit code, every target with whether it
    exists / is readable / holds test files, the pytest arguments, and the interpreter.
    """
    target_lines = [_describe_target(target) for target in targets] or ["  (none given)"]
    lines = [
        f"pytest collection failed with exit code {returncode}.",
        "",
        "targets:",
        *target_lines,
        "",
        f"pytest args: {list(pytest_args)}",
        f"interpreter: {sys.executable}",
        f"cwd: {Path.cwd()}",
        "",
        *_stream_excerpt("stdout", stdout),
        *_stream_excerpt("stderr", stderr),
        "",
        "If the target looks fine, retry with PKCS11_CHECK_NO_COLLECTION_CACHE=1 to rule "
        "out the collection cache.",
    ]
    return "\n".join(lines)
