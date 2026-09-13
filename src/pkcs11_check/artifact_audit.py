"""Verify and audit artifacts produced by an installed pkcs11-check distribution.

This module deliberately has no source-tree fallback.  The package that imports it must be
the package being attested: its distribution metadata, RECORD file, and on-disk origin are
checked before any artifact is analysed.  The quality portion of the result is always rebuilt
from ``report.jsonl`` and ``results.json`` (and, when present, ``coverage.json``); an existing
``quality.json`` is not an input because it is a derived summary.

The command-line interface is a machine-readable protocol: pass ``--producer-stopped`` only
after the caller has copied a complete private artifact snapshot and stopped its producer;
canonical JSON is written to stdout or ``--output`` and diagnostics go to stderr.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import importlib.metadata
import io
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from pkcs11_check.core._report_records import (
    extract_quality_report_evidence_from_jsonl,
    extract_quality_report_records_from_jsonl,
)
from pkcs11_check.core.quality_audit import build_quality_audit

_DISTRIBUTION_NAME = "pkcs11-check"
_SCHEMA_VERSION = "1"
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_RECORD_B64_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


class ArtifactAuditError(ValueError):
    """Raised when installation identity or artifact inputs cannot be proven."""


@dataclass(frozen=True)
class _FileSnapshot:
    """Identity and digest of one stable, physically opened regular file."""

    device: int
    inode: int
    size: int
    mtime_ns: int
    sha256: str
    data: bytes | None = None


def canonical_installed_files_sha256(
    file_tuples: Sequence[tuple[str, str, int]],
) -> str:
    """Hash sorted ``(record path, content SHA-256, size)`` tuples canonically."""

    canonical = json.dumps(
        [list(item) for item in sorted(file_tuples, key=lambda item: item[0])],
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256_bytes(canonical)


def canonical_json(value: Mapping[str, Any]) -> str:
    """Return the stable UTF-8 JSON representation used by the audit CLI."""

    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ArtifactAuditError(
            "audit contains a value that cannot be represented canonically"
        ) from exc
    return rendered + "\n"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalise_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _strict_sha256(value: str, label: str) -> str:
    if not _SHA256_RE.fullmatch(value):
        raise ArtifactAuditError(f"{label} must be a 64-character hexadecimal SHA-256 digest")
    return value.lower()


def _resolved_path(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ArtifactAuditError(f"{label} cannot be resolved: {path}") from exc
    return resolved


def _relative_to(path: Path, parent: Path, label: str) -> str:
    try:
        relative = path.relative_to(parent)
    except ValueError as exc:
        raise ArtifactAuditError(
            f"{label} is outside the installation prefix; refusing unproven source origin"
        ) from exc
    return relative.as_posix()


def _path_has_symlink(path: Path, resolved: Path) -> bool:
    """Return whether resolution changed a path beyond ordinary ``..`` cleanup."""

    return resolved != Path(os.path.normpath(str(path)))


def _has_symlink_component(path: Path) -> bool:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if current.is_symlink():
            return True
    return False


def _open_nofollow(path: Path, *, label: str) -> int:
    """Open an absolute regular-file path while refusing symlink components."""

    absolute = Path(os.path.abspath(path))
    read_only = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if os.name != "posix" or not hasattr(os, "supports_dir_fd"):
        try:
            symlinked = _has_symlink_component(absolute)
        except OSError as exc:
            raise ArtifactAuditError(f"{label} cannot be opened without symlinks") from exc
        if symlinked:
            raise ArtifactAuditError(f"{label} cannot be opened without symlinks")
        try:
            return os.open(str(absolute), read_only | nofollow)
        except OSError as exc:
            raise ArtifactAuditError(f"{label} cannot be opened without symlinks") from exc

    parts = absolute.parts
    if len(parts) < 2:
        raise ArtifactAuditError(f"{label} is not a file path")
    directory_flags = read_only | nofollow | getattr(os, "O_DIRECTORY", 0)
    dir_fd: int | None = None
    try:
        dir_fd = os.open(parts[0], directory_flags)
        for component in parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        return os.open(parts[-1], read_only | nofollow, dir_fd=dir_fd)
    except OSError as exc:
        raise ArtifactAuditError(f"{label} cannot be opened without symlinks") from exc
    finally:
        if dir_fd is not None:
            try:
                os.close(dir_fd)
            except OSError:
                pass


def _snapshot_file(
    path: Path,
    *,
    label: str,
    collect_data: bool = False,
    copy_to: Path | None = None,
) -> _FileSnapshot:
    """Read one regular file through a stable no-follow FD and optionally copy its bytes."""

    fd = _open_nofollow(path, label=label)
    output_fd: int | None = None
    chunks: list[bytes] = []
    digest = hashlib.sha256()
    total_size = 0
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ArtifactAuditError(f"{label} is not a regular file")
        if copy_to is not None:
            try:
                output_fd = os.open(
                    str(copy_to),
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_BINARY", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                )
            except OSError as exc:
                raise ArtifactAuditError(f"snapshot copy cannot be created: {copy_to}") from exc
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            total_size += len(block)
            if collect_data:
                chunks.append(block)
            if output_fd is not None:
                view = memoryview(block)
                while view:
                    written = os.write(output_fd, view)
                    view = view[written:]
        after = os.fstat(fd)
        identity_equal = (
            before.st_dev == after.st_dev
            and before.st_ino == after.st_ino
            and before.st_size == after.st_size
            and before.st_mtime_ns == after.st_mtime_ns
        )
        if not identity_equal or total_size != before.st_size:
            raise ArtifactAuditError(f"{label} changed while being read")
        if output_fd is not None:
            os.fsync(output_fd)
        return _FileSnapshot(
            device=before.st_dev,
            inode=before.st_ino,
            size=before.st_size,
            mtime_ns=before.st_mtime_ns,
            sha256=digest.hexdigest(),
            data=b"".join(chunks) if collect_data else None,
        )
    finally:
        if output_fd is not None:
            try:
                os.close(output_fd)
            except OSError:
                pass
        try:
            os.close(fd)
        except OSError:
            pass


def _assert_same_snapshot(expected: _FileSnapshot, actual: _FileSnapshot, label: str) -> None:
    if (
        expected.device != actual.device
        or expected.inode != actual.inode
        or expected.size != actual.size
        or expected.mtime_ns != actual.mtime_ns
        or expected.sha256 != actual.sha256
    ):
        raise ArtifactAuditError(f"{label} changed between authoritative reads")


def _find_record_file(
    distribution: importlib.metadata.Distribution,
) -> tuple[Path, PurePosixPath]:
    files = distribution.files
    if files is None:
        raise ArtifactAuditError("distribution has no RECORD file list")
    candidates = [path for path in files if path.as_posix().endswith(".dist-info/RECORD")]
    if len(candidates) != 1:
        raise ArtifactAuditError(
            "distribution RECORD cannot be proven: expected exactly one RECORD entry"
        )
    relative = PurePosixPath(candidates[0].as_posix())
    record_path = Path(str(distribution.locate_file(candidates[0])))
    return record_path, relative


def _record_rows(
    record_bytes: bytes,
    record_relative: PurePosixPath,
) -> list[tuple[PurePosixPath, str, int | None]]:
    try:
        text = record_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArtifactAuditError("distribution RECORD is unreadable UTF-8") from exc

    rows: list[tuple[PurePosixPath, str, int | None]] = []
    seen: set[str] = set()
    try:
        parsed_rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except csv.Error as exc:
        raise ArtifactAuditError("distribution RECORD is malformed CSV") from exc
    for row in parsed_rows:
        if len(row) != 3 or not row[0]:
            raise ArtifactAuditError("distribution RECORD contains a malformed row")
        relative = PurePosixPath(row[0])
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", "."} for part in relative.parts)
            or "\\" in row[0]
        ):
            raise ArtifactAuditError("distribution RECORD contains an unsafe relative path")
        key = relative.as_posix()
        if key in seen:
            raise ArtifactAuditError(f"distribution RECORD contains duplicate path: {key}")
        seen.add(key)

        digest_field = row[1]
        size_field = row[2]
        digest_is_blank = digest_field == ""
        size_is_blank = size_field == ""
        is_pyc = (
            relative.as_posix().endswith(".pyc")
            and len(relative.parts) >= 2
            and relative.parts[-2] == "__pycache__"
        )
        if digest_is_blank != size_is_blank or (
            digest_is_blank and not (relative == record_relative or is_pyc)
        ):
            raise ArtifactAuditError(f"RECORD has an unverifiable partial or blank row for {key}")
        if digest_field:
            algorithm, separator, encoded_digest = digest_field.partition("=")
            if algorithm != "sha256" or separator != "=":
                raise ArtifactAuditError(
                    f"distribution RECORD uses an unverifiable digest for {key}"
                )
            if not _RECORD_B64_RE.fullmatch(encoded_digest):
                raise ArtifactAuditError(f"RECORD digest for {key} is malformed")
            try:
                padding = "=" * (-len(encoded_digest) % 4)
                decoded_digest = base64.urlsafe_b64decode(encoded_digest + padding)
            except (ValueError, binascii.Error) as exc:
                raise ArtifactAuditError(f"RECORD digest for {key} is malformed") from exc
            if len(decoded_digest) != hashlib.sha256().digest_size:
                raise ArtifactAuditError(f"RECORD digest for {key} is not SHA-256")
            canonical_digest = base64.urlsafe_b64encode(decoded_digest).rstrip(b"=").decode("ascii")
            if encoded_digest.rstrip("=") != canonical_digest:
                raise ArtifactAuditError(f"RECORD digest for {key} is malformed")
            expected_digest = decoded_digest.hex()
        else:
            expected_digest = ""
        if size_is_blank:
            if relative != record_relative and not is_pyc:
                raise ArtifactAuditError(f"RECORD has no verifiable size for {key}")
            size = None
        else:
            try:
                size = int(row[2])
            except ValueError as exc:
                raise ArtifactAuditError(
                    f"distribution RECORD has a non-integer size for {key}"
                ) from exc
            if size < 0:
                raise ArtifactAuditError(f"distribution RECORD has a negative size for {key}")
        rows.append((relative, expected_digest, size))
    if not rows:
        raise ArtifactAuditError("distribution RECORD is empty")
    return rows


def _verify_record_files(
    distribution: importlib.metadata.Distribution,
    record_bytes: bytes,
    record_snapshot: _FileSnapshot,
    record_relative: PurePosixPath,
    rows: Sequence[tuple[PurePosixPath, str, int | None]],
    install_prefix: Path,
) -> tuple[str, str, set[PurePosixPath], list[str], dict[PurePosixPath, bytes]]:
    installed_tuples: list[tuple[str, str, int]] = []
    paths: set[PurePosixPath] = set()
    unverified_paths: list[str] = []
    verified_data: dict[PurePosixPath, bytes] = {}
    for relative, expected_digest, expected_size in rows:
        installed = Path(str(distribution.locate_file(relative)))
        snapshot = (
            record_snapshot
            if relative == record_relative
            else _snapshot_file(
                installed,
                label=f"RECORD-listed installed file {relative}",
                collect_data=relative.as_posix().endswith(".dist-info/direct_url.json"),
            )
        )
        resolved_installed = _resolved_path(installed, f"RECORD path {relative}")
        if _path_has_symlink(installed, resolved_installed):
            raise ArtifactAuditError(
                f"RECORD-listed installed path resolves through a symlink: {relative}"
            )
        _relative_to(resolved_installed, install_prefix, f"RECORD path {relative}")
        contents = snapshot.data
        if relative == record_relative:
            contents = record_bytes
        if relative.as_posix().endswith(".dist-info/direct_url.json") and contents is not None:
            verified_data[relative] = contents
        actual_digest = snapshot.sha256
        if relative == record_relative and actual_digest != record_snapshot.sha256:
            raise ArtifactAuditError("distribution RECORD changed while being verified")
        if expected_size is not None and snapshot.size != expected_size:
            raise ArtifactAuditError(f"RECORD size mismatch for {relative}")
        if not expected_digest:
            unverified_paths.append(relative.as_posix())
        if expected_digest and actual_digest != expected_digest:
            raise ArtifactAuditError(f"RECORD digest mismatch for {relative}")
        installed_tuples.append((relative.as_posix(), actual_digest, snapshot.size))
        paths.add(relative)
    installed_digest = canonical_installed_files_sha256(installed_tuples)
    record_digest = _sha256_bytes(record_bytes)
    return record_digest, installed_digest, paths, sorted(unverified_paths), verified_data


def _direct_url_archive_digest(
    record_relative: PurePosixPath,
    record_paths: set[PurePosixPath],
    verified_data: Mapping[PurePosixPath, bytes],
) -> str | None:
    direct_url_path = record_relative.parent / "direct_url.json"
    if direct_url_path not in record_paths:
        return None
    try:
        payload = json.loads(verified_data[direct_url_path].decode("utf-8"))
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactAuditError("distribution direct_url.json is malformed") from exc
    if not isinstance(payload, Mapping):
        raise ArtifactAuditError("distribution direct_url.json is not an object")
    archive_info = payload.get("archive_info")
    if not isinstance(archive_info, Mapping):
        return None
    digest_value = archive_info.get("hash")
    if not isinstance(digest_value, str) or not digest_value.startswith("sha256="):
        return None
    return _strict_sha256(digest_value.removeprefix("sha256="), "direct_url archive hash")


def build_installation_receipt(
    *,
    install_prefix: Path | None = None,
    expected_version: str | None = None,
    expected_archive_sha256: str | None = None,
) -> dict[str, Any]:
    """Prove the running code is a noneditable installed distribution and record its identity.

    The receipt binds the artifact audit to the installed distribution's RECORD and the
    content digest of every RECORD-listed file.  A wheel/archive hash is only accepted when
    PEP 610 ``direct_url.json`` supplies a verifiable SHA-256; ordinary installed wheels do
    not contain proof of their original archive bytes, so callers should compare that value
    externally when the deployment plan has one.
    """

    if expected_archive_sha256 is not None:
        _strict_sha256(expected_archive_sha256, "expected archive digest")
    distribution = _load_distribution()
    metadata_name = distribution.metadata.get("Name")
    if (
        not isinstance(metadata_name, str)
        or _normalise_distribution_name(metadata_name) != _DISTRIBUTION_NAME
    ):
        raise ArtifactAuditError("distribution metadata name is not pkcs11-check")
    version = distribution.version
    from pkcs11_check import __version__ as package_version

    if version != package_version:
        raise ArtifactAuditError(
            "package code version "
            f"{package_version!r} does not match distribution metadata {version!r}"
        )
    if expected_version is not None and version != expected_version:
        raise ArtifactAuditError(
            "installed distribution version "
            f"{version!r} does not match expected {expected_version!r}"
        )

    package_file = _resolved_path(Path(__file__), "pkcs11_check package origin")
    prefix = _resolved_path(install_prefix or Path(sys.prefix), "installation prefix")
    package_lexical = Path(os.path.abspath(__file__))
    if _path_has_symlink(package_lexical, package_file):
        raise ArtifactAuditError("pkcs11_check package origin is a symlink/editable checkout")
    package_origin = _relative_to(package_file, prefix, "pkcs11_check package origin")

    record_path, record_relative = _find_record_file(distribution)
    record_snapshot = _snapshot_file(record_path, label="distribution RECORD", collect_data=True)
    if record_snapshot.data is None:
        raise ArtifactAuditError("distribution RECORD bytes were not captured")
    record_bytes = record_snapshot.data
    rows = _record_rows(record_bytes, record_relative)
    (
        record_digest,
        installed_digest,
        record_paths,
        record_unverified_paths,
        verified_data,
    ) = _verify_record_files(
        distribution, record_bytes, record_snapshot, record_relative, rows, prefix
    )
    second_record_snapshot = _snapshot_file(record_path, label="distribution RECORD")
    _assert_same_snapshot(record_snapshot, second_record_snapshot, "distribution RECORD")
    package_is_recorded = any(
        _resolved_path(Path(str(distribution.locate_file(relative))), "RECORD path") == package_file
        for relative in record_paths
    )
    if not package_is_recorded:
        raise ArtifactAuditError("pkcs11_check package origin is not listed in distribution RECORD")

    archive_digest = _direct_url_archive_digest(record_relative, record_paths, verified_data)
    if expected_archive_sha256 is not None:
        expected_archive = _strict_sha256(expected_archive_sha256, "expected archive digest")
        if archive_digest is None:
            raise ArtifactAuditError(
                "archive digest cannot be proven inside the installed distribution; "
                "compare the deployment archive externally"
            )
        if archive_digest != expected_archive:
            raise ArtifactAuditError("installed archive digest does not match expected digest")

    integrity_binding = "installed-distribution-record"
    if archive_digest is not None:
        integrity_binding += "+pep610-direct-url"

    return {
        "schema_version": _SCHEMA_VERSION,
        "version": version,
        "metadata_name": metadata_name,
        "distribution_record_sha256": record_digest,
        "installed_files_sha256": installed_digest,
        "record_unverified_paths": record_unverified_paths,
        "package_origin": package_origin,
        "integrity_binding": integrity_binding,
        "archive_sha256": archive_digest,
    }


def _load_distribution() -> importlib.metadata.Distribution:
    try:
        return importlib.metadata.distribution(_DISTRIBUTION_NAME)
    except importlib.metadata.PackageNotFoundError as exc:
        raise ArtifactAuditError(
            "pkcs11-check distribution metadata is unavailable; refusing source-tree fallback"
        ) from exc


def _load_mapping_bytes(data: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactAuditError(f"{label} is invalid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ArtifactAuditError(f"{label} must contain a JSON object")
    return payload


def _artifact_digest(snapshot: _FileSnapshot) -> dict[str, int | str]:
    return {"size": snapshot.size, "sha256": snapshot.sha256}


def _require_stable_artifact(
    path: Path,
    *,
    label: str,
    collect_data: bool = False,
    copy_to: Path | None = None,
) -> _FileSnapshot:
    return _snapshot_file(path, label=label, collect_data=collect_data, copy_to=copy_to)


def audit_artifacts(
    artifact_dir: Path,
    *,
    producer_stopped: bool = False,
    install_prefix: Path | None = None,
    expected_version: str | None = None,
    expected_archive_sha256: str | None = None,
) -> dict[str, Any]:
    """Build a canonical quality audit from a producer-stopped private snapshot.

    The caller must set ``producer_stopped=True`` only after its infrastructure has stopped
    the producer and copied the complete artifact set into a private directory.  This generic
    module does not own that lock or copy protocol; it verifies physical file identity and
    detects mutations while reading the snapshot.
    """

    if not producer_stopped:
        raise ArtifactAuditError(
            "artifact audit requires a producer-stopped private snapshot "
            "(pass producer_stopped=True after the infrastructure handoff)"
        )
    if artifact_dir.is_symlink():
        raise ArtifactAuditError("artifact directory must not be a symlink")
    artifact_root = _resolved_path(artifact_dir, "artifact directory")
    if not artifact_root.is_dir():
        raise ArtifactAuditError(f"artifact directory is not a directory: {artifact_dir}")
    report_path = artifact_root / "report.jsonl"
    results_path = artifact_root / "results.json"
    installation = build_installation_receipt(
        install_prefix=install_prefix,
        expected_version=expected_version,
        expected_archive_sha256=expected_archive_sha256,
    )

    result_snapshot = _require_stable_artifact(
        results_path, label="results.json", collect_data=True
    )
    if result_snapshot.data is None:
        raise ArtifactAuditError("results.json bytes were not captured")
    results = _load_mapping_bytes(result_snapshot.data, "results.json")
    coverage_path = artifact_root / "coverage.json"
    coverage_snapshot: _FileSnapshot | None = None
    coverage: dict[str, Any] | None = None
    if os.path.lexists(coverage_path):
        coverage_snapshot = _require_stable_artifact(
            coverage_path, label="coverage.json", collect_data=True
        )
        if coverage_snapshot.data is None:
            raise ArtifactAuditError("coverage.json bytes were not captured")
        coverage = _load_mapping_bytes(coverage_snapshot.data, "coverage.json")

    with tempfile.TemporaryDirectory(prefix="pkcs11-check-audit-") as temp_dir:
        snapshot_report = Path(temp_dir) / "report.jsonl"
        report_snapshot = _require_stable_artifact(
            report_path, label="report.jsonl", copy_to=snapshot_report
        )
        report_records = extract_quality_report_records_from_jsonl(snapshot_report)
        report_between = _require_stable_artifact(report_path, label="report.jsonl")
        _assert_same_snapshot(report_snapshot, report_between, "report.jsonl")
        report_evidence = extract_quality_report_evidence_from_jsonl([snapshot_report])
        report_after = _require_stable_artifact(report_path, label="report.jsonl")
        _assert_same_snapshot(report_snapshot, report_after, "report.jsonl")
    quality = build_quality_audit(
        results=results,
        coverage=coverage,
        report_log_records=report_records,
        quality_report_evidence=report_evidence,
    )
    return {
        "schema_version": _SCHEMA_VERSION,
        "kind": "pkcs11-check-artifact-audit",
        "producer_stopped": True,
        "input_artifacts": {
            "report.jsonl": _artifact_digest(report_snapshot),
            "results.json": _artifact_digest(result_snapshot),
            **(
                {"coverage.json": _artifact_digest(coverage_snapshot)}
                if coverage_snapshot is not None
                else {}
            ),
        },
        "installation": installation,
        "quality_audit": quality,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "artifact_dir", type=Path, help="directory containing report.jsonl and results.json"
    )
    parser.add_argument(
        "--producer-stopped",
        action="store_true",
        help="assert the directory is a private snapshot after its producer stopped",
    )
    parser.add_argument("-o", "--output", type=Path, help="write canonical JSON to this path")
    parser.add_argument(
        "--install-prefix", type=Path, help="installation prefix to bind package origin to"
    )
    parser.add_argument("--expected-version", help="require this installed distribution version")
    parser.add_argument(
        "--expected-archive-sha256",
        help="require a PEP 610-proven archive SHA-256 (ordinary wheels cannot prove this)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the artifact auditor CLI; return a shell-compatible status code."""

    args = _build_parser().parse_args(argv)
    try:
        payload = audit_artifacts(
            args.artifact_dir,
            producer_stopped=args.producer_stopped,
            install_prefix=args.install_prefix,
            expected_version=args.expected_version,
            expected_archive_sha256=args.expected_archive_sha256,
        )
        rendered = canonical_json(payload)
        if args.output is None:
            sys.stdout.write(rendered)
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8", newline="\n")
    except ArtifactAuditError as exc:
        sys.stderr.write(f"artifact audit failed: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
