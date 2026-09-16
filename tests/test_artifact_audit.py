"""Tests for the installed-distribution artifact auditor."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from pkcs11_check.artifact_audit import (
    ArtifactAuditError,
    audit_artifacts,
    build_installation_receipt,
    canonical_installed_files_sha256,
    canonical_json,
)
from pkcs11_check.core._report_records import (
    extract_quality_report_evidence_from_jsonl,
    extract_quality_report_records_from_jsonl,
)
from pkcs11_check.core.quality_audit import build_quality_audit


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False) + "\n", encoding="utf-8")


def _results() -> dict[str, Any]:
    return {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {
            "passed": 1,
            "failed": 1,
            "skipped": 1,
            "xfailed": 1,
            "xpassed": 0,
            "error": 0,
            "total": 4,
        },
        "units": [
            {
                "target": "tests/test_demo.py",
                "status": "complete",
                "counts": {
                    "passed": 1,
                    "failed": 1,
                    "skipped": 1,
                    "xfailed": 1,
                    "xpassed": 0,
                    "error": 0,
                },
                "tests": [
                    {
                        "nodeid": "tests/test_demo.py::test_pass",
                        "outcome": "passed",
                    },
                    {
                        "nodeid": "tests/test_demo.py::test_fail",
                        "outcome": "failed",
                        "longrepr": "AssertionError: bad provider result",
                    },
                    {
                        "nodeid": "tests/test_demo.py::test_skip",
                        "outcome": "skipped",
                        "longrepr": "Skipped: CKM_AES_CBC not supported",
                    },
                    {
                        "nodeid": "tests/test_demo.py::test_xfail",
                        "outcome": "xfailed",
                        "wasxfail": "honest deviation",
                        "longrepr": "Skipped: provider deviation",
                    },
                ],
                "skip_reasons": {
                    "CKM_AES_CBC not supported": 1,
                    "provider deviation": 1,
                },
            }
        ],
    }


def _classification(label: str, *, reason: str = "accepted_invalid") -> dict[str, Any]:
    return {
        "reason": reason,
        "outcome": "fail",
        "severity": "CRITICAL",
        "kind": "crypto",
        "label": label,
        "summary": f"{label}: expected reject, got CKR_OK",
        "operation": "C_Decrypt",
        "mechanism": "CKM_RSA_PKCS",
        "expected_ckr": ["CKR_ENCRYPTED_DATA_INVALID"],
        "actual_ckr": "CKR_OK",
        "schema": 1,
    }


def _report(
    *, malformed: bool = False, multiple: bool = False, reason: str = "accepted_invalid"
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = [
        {"$report_type": "SessionStart"},
        {
            "$report_type": "IsolatedUnitReport",
            "target": "tests/test_demo.py",
            "attempt": 0,
        },
        {
            "$report_type": "TestReport",
            "when": "call",
            "nodeid": "tests/test_demo.py::test_fail",
            "outcome": "failed",
            "user_properties": [
                ["pkcs11_classification", [_classification("first", reason=reason)]],
                *(
                    [["pkcs11_classification", [_classification("second", reason=reason)]]]
                    if multiple
                    else []
                ),
            ],
        },
        {"$report_type": "SessionFinish", "exitstatus": 1},
    ]
    if malformed:
        records[2]["user_properties"] = [
            ["pkcs11_classification", "not-a-list"],
            ["pkcs11_classification", [_classification("survivor", reason="unclassified")]],
        ]
    return records


def _artifact_dir(
    tmp_path: Path,
    *,
    malformed: bool = False,
    multiple: bool = False,
    reason: str = "accepted_invalid",
) -> Path:
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    _write_json(artifact_dir / "results.json", _results())
    (artifact_dir / "report.jsonl").write_text(
        "".join(
            json.dumps(record, ensure_ascii=False) + "\n"
            for record in _report(malformed=malformed, multiple=multiple, reason=reason)
        ),
        encoding="utf-8",
    )
    return artifact_dir


def _venv_python(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _receipt() -> dict[str, Any]:
    return {
        "schema_version": "1",
        "version": "0.2.0",
        "metadata_name": "pkcs11-check",
        "distribution_record_sha256": "a" * 64,
        "installed_files_sha256": "b" * 64,
        "package_origin": "lib/python3.12/site-packages/pkcs11_check/__init__.py",
        "integrity_binding": "installed-distribution-record",
        "archive_sha256": None,
    }


class _FakeDistribution:
    """Tiny metadata distribution used to exercise receipt checks without an editable env."""

    def __init__(
        self,
        prefix: Path,
        *,
        version: str = "0.2.0",
        include_package: bool = True,
        include_pyc: bool = False,
        archive_hash: str | None = None,
        include_unverified: bool = False,
        include_foreign_direct_url: bool = False,
    ) -> None:
        self._site = prefix / "lib" / "python3.12" / "site-packages"
        self._dist_info = self._site / f"pkcs11_check-{version}.dist-info"
        self._package_relative = PurePosixPath("pkcs11_check/artifact_audit.py")
        self._pyc_relative = PurePosixPath(
            "pkcs11_check/__pycache__/artifact_audit.cpython-313.pyc"
        )
        self._direct_url_relative = PurePosixPath(
            f"pkcs11_check-{version}.dist-info/direct_url.json"
        )
        self._foreign_direct_url_relative = PurePosixPath(
            "foreign_distribution-1.0.dist-info/direct_url.json"
        )
        self._unverified_relative = PurePosixPath("README.txt")
        self._record_relative = PurePosixPath(f"pkcs11_check-{version}.dist-info/RECORD")
        self.metadata = {"Name": "pkcs11-check"}
        self.version = version
        package_file = self._site / self._package_relative
        package_file.parent.mkdir(parents=True, exist_ok=True)
        package_file.write_text("installed package", encoding="utf-8")
        rows: list[str] = []
        if include_package:
            content = package_file.read_bytes()
            digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
            rows.append(
                f"{self._package_relative.as_posix()},sha256={digest.decode('ascii')},{len(content)}"
            )
        if include_pyc:
            pyc_file = self._site / self._pyc_relative
            pyc_file.parent.mkdir(parents=True, exist_ok=True)
            pyc_file.write_bytes(b"pyc bytes")
            rows.append(f"{self._pyc_relative.as_posix()},,")
        if include_unverified:
            unverified_file = self._site / self._unverified_relative
            unverified_file.write_text("unverified", encoding="utf-8")
            rows.append(f"{self._unverified_relative.as_posix()},,")
        self._dist_info.mkdir(parents=True, exist_ok=True)
        if archive_hash is not None:
            direct_url_file = self._dist_info / "direct_url.json"
            direct_url_file.write_text(
                json.dumps(
                    {
                        "url": "https://example.invalid/pkcs11-check.whl",
                        "archive_info": {"hash": f"sha256={archive_hash}"},
                    }
                ),
                encoding="utf-8",
            )
            content = direct_url_file.read_bytes()
            digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
            rows.append(
                f"{self._direct_url_relative.as_posix()},sha256={digest.decode('ascii')},{len(content)}"
            )
        if include_foreign_direct_url:
            foreign_url_file = self._site / self._foreign_direct_url_relative
            foreign_url_file.parent.mkdir(parents=True, exist_ok=True)
            foreign_archive_hash = "f" * 64
            foreign_url_file.write_text(
                json.dumps(
                    {
                        "url": "https://example.invalid/foreign.whl",
                        "archive_info": {"hash": f"sha256={foreign_archive_hash}"},
                    }
                ),
                encoding="utf-8",
            )
            content = foreign_url_file.read_bytes()
            digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
            rows.append(
                f"{self._foreign_direct_url_relative.as_posix()},sha256={digest.decode('ascii')},{len(content)}"
            )
        record_path = self._dist_info / "RECORD"
        # Wheel RECORD convention leaves both digest and size blank on RECORD itself.
        rows.append(f"{self._record_relative.as_posix()},,")
        record_path.write_bytes(("\n".join(rows) + "\n").encode("utf-8"))
        self.files = [self._record_relative]
        if include_package:
            self.files.insert(0, self._package_relative)
        if include_pyc:
            self.files.insert(0, self._pyc_relative)
        if include_unverified:
            self.files.insert(0, self._unverified_relative)
        if archive_hash is not None:
            self.files.insert(0, self._direct_url_relative)
        if include_foreign_direct_url:
            self.files.insert(0, self._foreign_direct_url_relative)

    def locate_file(self, path: PurePosixPath) -> Path:
        return self._site / path


def test_audit_uses_authoritative_builder_and_ignores_quality_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_dir = _artifact_dir(tmp_path)
    _write_json(artifact_dir / "coverage.json", {"function_coverage": {"available": 0}})
    _write_json(artifact_dir / "quality.json", {"summary": {"total": 999999}})

    import pkcs11_check.artifact_audit as module

    monkeypatch.setattr(module, "build_installation_receipt", lambda **_: _receipt())
    report_path = artifact_dir / "report.jsonl"
    expected = build_quality_audit(
        results=_results(),
        coverage={"function_coverage": {"available": 0}},
        report_log_records=extract_quality_report_records_from_jsonl(report_path),
        quality_report_evidence=extract_quality_report_evidence_from_jsonl([report_path]),
    )

    audited = audit_artifacts(artifact_dir, producer_stopped=True)

    assert audited["quality_audit"] == expected
    assert audited["installation"] == _receipt()
    assert audited["quality_audit"]["summary"]["total"] != 999999


def test_audit_requires_explicit_producer_stopped_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_dir = _artifact_dir(tmp_path)
    import pkcs11_check.artifact_audit as module

    monkeypatch.setattr(module, "build_installation_receipt", lambda **_: _receipt())
    with pytest.raises(ArtifactAuditError, match="producer-stopped"):
        audit_artifacts(artifact_dir)


def test_static_skip_marker_is_counted_without_fabricating_a_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_dir = _artifact_dir(tmp_path)
    report_path = artifact_dir / "report.jsonl"
    report_path.write_text(
        json.dumps({"$report_type": "IsolatedUnitReport", "target": "test_static.py", "attempt": 0})
        + "\n",
        encoding="utf-8",
    )
    import pkcs11_check.artifact_audit as module

    monkeypatch.setattr(module, "build_installation_receipt", lambda **_: _receipt())
    audited = audit_artifacts(artifact_dir, producer_stopped=True)

    assert audited["quality_audit"]["summary"]["total"] == 4
    assert audited["quality_audit"]["classification_observability"]["status"] == "complete"
    assert (
        audited["quality_audit"]["classification_observability"]["unclassified"]["occurrences"] == 0
    )


def test_multiple_classification_properties_are_counted_exactly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_dir = _artifact_dir(tmp_path, multiple=True, reason="unclassified")
    import pkcs11_check.artifact_audit as module

    monkeypatch.setattr(module, "build_installation_receipt", lambda **_: _receipt())
    audited = audit_artifacts(artifact_dir, producer_stopped=True)
    quality = audited["quality_audit"]

    # Both properties are retained in the authoritative raw evidence. The regular audit
    # groups the two occurrences by their provider finding identity.
    assert quality["classification_observability"]["unclassified"]["occurrences"] == 2
    assert len(quality["classification_observability"]["status_reasons"]) == 0
    assert quality["summary"]["failed"] == 1


def test_malformed_raw_status_is_partial_and_keeps_readable_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_dir = _artifact_dir(tmp_path, malformed=True)
    import pkcs11_check.artifact_audit as module

    monkeypatch.setattr(module, "build_installation_receipt", lambda **_: _receipt())
    audited = audit_artifacts(artifact_dir, producer_stopped=True)
    observability = audited["quality_audit"]["classification_observability"]

    assert observability["status"] == "partial"
    assert observability["malformed_properties"] >= 1
    assert observability["unclassified"]["occurrences"] == 1


def test_audit_binds_exact_input_digests_to_the_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_dir = _artifact_dir(tmp_path)
    _write_json(artifact_dir / "coverage.json", {"function_coverage": {"available": 0}})
    import pkcs11_check.artifact_audit as module

    monkeypatch.setattr(module, "build_installation_receipt", lambda **_: _receipt())
    audited = audit_artifacts(artifact_dir, producer_stopped=True)

    for name in ("report.jsonl", "results.json", "coverage.json"):
        data = (artifact_dir / name).read_bytes()
        assert audited["input_artifacts"][name] == {
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }


def test_audit_rejects_report_mutation_between_authoritative_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_dir = _artifact_dir(tmp_path)
    import pkcs11_check.artifact_audit as module

    monkeypatch.setattr(module, "build_installation_receipt", lambda **_: _receipt())
    original_extract = module.extract_quality_report_records_from_jsonl
    mutated = False

    def mutate_after_extract(path: Path) -> list[dict[str, Any]]:
        nonlocal mutated
        records = original_extract(path)
        if not mutated:
            mutated = True
            report_path = artifact_dir / "report.jsonl"
            report_path.write_bytes(report_path.read_bytes() + b"\n")
        return records

    monkeypatch.setattr(module, "extract_quality_report_records_from_jsonl", mutate_after_extract)
    with pytest.raises(ArtifactAuditError, match="report.jsonl changed"):
        audit_artifacts(artifact_dir, producer_stopped=True)


def test_audit_rejects_symlinked_artifact_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_dir = _artifact_dir(tmp_path)
    external_report = tmp_path / "external-report.jsonl"
    external_report.write_bytes((artifact_dir / "report.jsonl").read_bytes())
    (artifact_dir / "report.jsonl").unlink()
    (artifact_dir / "report.jsonl").symlink_to(external_report)
    import pkcs11_check.artifact_audit as module

    monkeypatch.setattr(module, "build_installation_receipt", lambda **_: _receipt())
    with pytest.raises(ArtifactAuditError, match="without symlinks"):
        audit_artifacts(artifact_dir, producer_stopped=True)


def test_windows_fallback_rejects_symlink_with_common_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pkcs11_check.artifact_audit as module

    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    # Removing dir-fd support exercises the same conservative fallback without changing
    # pathlib's host-platform implementation during this POSIX test.
    monkeypatch.delattr(module.os, "supports_dir_fd", raising=False)

    with pytest.raises(ArtifactAuditError, match="cannot be opened without symlinks"):
        module._open_nofollow(link, label="symlinked input")


@pytest.mark.parametrize(
    ("platform_name", "expected_name"),
    (("posix", "bin/python"), ("nt", "Scripts/python.exe")),
)
def test_venv_python_path_is_portable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_name: str,
    expected_name: str,
) -> None:
    monkeypatch.setattr(os, "name", platform_name)

    assert _venv_python(tmp_path).as_posix().endswith(expected_name)


def test_canonical_json_is_deterministic_and_utf8() -> None:
    value = {"z": "µ", "a": {"b": 2, "a": 1}}
    assert canonical_json(value) == canonical_json({"a": value["a"], "z": "µ"})
    assert canonical_json(value).encode("utf-8").decode("utf-8") == canonical_json(value)


def test_cli_emits_same_canonical_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifact_dir = _artifact_dir(tmp_path)
    # The CLI is executed in a child and therefore uses the real installed distribution. This
    # test only checks the fail-closed contract in this editable development environment.
    output = subprocess.run(
        [sys.executable, "-m", "pkcs11_check.artifact_audit", str(artifact_dir)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert output.returncode != 0
    assert any(
        marker in output.stderr
        for marker in (
            "producer-stopped",
            "outside the installation prefix",
            "RECORD",
            "version",
        )
    )


def test_built_wheel_standard_pip_install_runs_isolated_cli(
    tmp_path: Path,
) -> None:
    """Exercise pip's blank bytecode rows and PEP 610 receipt in a real install."""

    uv = shutil.which("uv")
    if uv is None:
        pytest.fail("uv is required for the offline wheel-build regression")
    project_root = Path(__file__).parents[1]
    command_env = os.environ.copy()
    command_env.setdefault("UV_CACHE_DIR", "/tmp/pkcs11-check-uv-cache")

    # Warm the (possibly cold) isolated cache online first: the offline build
    # below must resolve the hatchling backend from cache, and fresh runners
    # start cold. `uv sync` does not populate it.
    warmed = subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(tmp_path / "warm")],
        cwd=project_root,
        env=command_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert warmed.returncode == 0, warmed.stderr

    wheel_dir = tmp_path / "wheel"
    built = subprocess.run(
        [uv, "build", "--offline", "--wheel", "--out-dir", str(wheel_dir)],
        cwd=project_root,
        env=command_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert built.returncode == 0, built.stderr
    wheels = sorted(wheel_dir.glob("*.whl"))
    assert len(wheels) == 1
    wheel = wheels[0]
    archive_hash = hashlib.sha256(wheel.read_bytes()).hexdigest()

    venv_dir = tmp_path / "pip-venv"
    created = subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert created.returncode == 0, created.stderr
    venv_python = _venv_python(venv_dir)
    # Online: pytest-in-venv is scaffolding, not the offline subject (the wheel
    # build above). It also warms the isolated cache for the run below.
    dependencies = subprocess.run(
        [uv, "pip", "install", "--python", str(venv_python), "pytest"],
        env=command_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert dependencies.returncode == 0, dependencies.stderr
    installed = subprocess.run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            str(wheel),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert installed.returncode == 0, installed.stderr

    artifact_dir = _artifact_dir(tmp_path)
    expected_artifacts = {
        name: {
            "size": (artifact_dir / name).stat().st_size,
            "sha256": hashlib.sha256((artifact_dir / name).read_bytes()).hexdigest(),
        }
        for name in ("report.jsonl", "results.json")
    }
    isolated_env = os.environ.copy()
    isolated_env.pop("PYTHONPATH", None)
    output = subprocess.run(
        [
            str(venv_python),
            "-m",
            "pkcs11_check.artifact_audit",
            "--producer-stopped",
            "--install-prefix",
            str(venv_dir),
            "--expected-version",
            "0.2.0",
            "--expected-archive-sha256",
            archive_hash,
            str(artifact_dir),
        ],
        cwd=tmp_path,
        env=isolated_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert output.returncode == 0, output.stderr
    payload = json.loads(output.stdout)
    assert output.stdout == canonical_json(payload)
    assert payload["input_artifacts"] == expected_artifacts
    installation = payload["installation"]
    assert installation["archive_sha256"] == archive_hash
    assert installation["integrity_binding"] == ("installed-distribution-record+pep610-direct-url")
    unverified = installation["record_unverified_paths"]
    assert "pkcs11_check-0.2.0.dist-info/RECORD" in unverified
    assert any(
        path.startswith("pkcs11_check/__pycache__/") and path.endswith(".pyc")
        for path in unverified
    )


def test_receipt_rejects_expected_archive_digest_without_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pkcs11_check.artifact_audit as module

    distribution = _FakeDistribution(tmp_path)
    monkeypatch.setattr(module, "_load_distribution", lambda: distribution)
    monkeypatch.setattr(
        module, "__file__", str(distribution.locate_file(distribution._package_relative))
    )
    with pytest.raises(ArtifactAuditError, match="archive digest cannot be proven"):
        build_installation_receipt(install_prefix=tmp_path, expected_archive_sha256="a" * 64)


def test_receipt_does_not_attest_foreign_distribution_direct_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pkcs11_check.artifact_audit as module

    distribution = _FakeDistribution(tmp_path, include_foreign_direct_url=True)
    monkeypatch.setattr(module, "_load_distribution", lambda: distribution)
    monkeypatch.setattr(
        module,
        "__file__",
        str(distribution.locate_file(distribution._package_relative)),
    )

    with pytest.raises(ArtifactAuditError, match="archive digest cannot be proven"):
        build_installation_receipt(install_prefix=tmp_path, expected_archive_sha256="f" * 64)


def test_receipt_rejects_wrong_expected_version() -> None:
    with pytest.raises(ArtifactAuditError, match="version"):
        build_installation_receipt(expected_version="definitely-not-installed")


def test_receipt_digest_helper_is_sha256() -> None:
    first = [("module.py", "0" * 64, 10)]
    changed = [("module.py", "1" * 64, 10)]

    assert canonical_installed_files_sha256(first) != canonical_installed_files_sha256(changed)
    assert canonical_installed_files_sha256(first) == canonical_installed_files_sha256(
        list(reversed(first))
    )


def test_receipt_proves_record_and_relative_noneditable_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pkcs11_check.artifact_audit as module

    distribution = _FakeDistribution(tmp_path)
    monkeypatch.setattr(module, "_load_distribution", lambda: distribution)
    monkeypatch.setattr(
        module, "__file__", str(distribution.locate_file(distribution._package_relative))
    )

    receipt = build_installation_receipt(install_prefix=tmp_path, expected_version="0.2.0")

    assert receipt["version"] == "0.2.0"
    assert receipt["metadata_name"] == "pkcs11-check"
    assert len(receipt["distribution_record_sha256"]) == 64
    assert len(receipt["installed_files_sha256"]) == 64
    assert (
        receipt["package_origin"] == "lib/python3.12/site-packages/pkcs11_check/artifact_audit.py"
    )
    assert receipt["archive_sha256"] is None
    assert receipt["record_unverified_paths"] == ["pkcs11_check-0.2.0.dist-info/RECORD"]


def test_receipt_hashes_pycache_bytes_and_exposes_sorted_unverified_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pkcs11_check.artifact_audit as module

    distribution = _FakeDistribution(tmp_path, include_pyc=True)
    monkeypatch.setattr(module, "_load_distribution", lambda: distribution)
    monkeypatch.setattr(
        module, "__file__", str(distribution.locate_file(distribution._package_relative))
    )

    receipt = build_installation_receipt(install_prefix=tmp_path)

    assert receipt["record_unverified_paths"] == sorted(
        [
            "pkcs11_check-0.2.0.dist-info/RECORD",
            "pkcs11_check/__pycache__/artifact_audit.cpython-313.pyc",
        ]
    )
    assert receipt["installed_files_sha256"] == module.canonical_installed_files_sha256(
        [
            (
                "pkcs11_check/artifact_audit.py",
                hashlib.sha256(b"installed package").hexdigest(),
                len(b"installed package"),
            ),
            (
                "pkcs11_check/__pycache__/artifact_audit.cpython-313.pyc",
                hashlib.sha256(b"pyc bytes").hexdigest(),
                len(b"pyc bytes"),
            ),
            (
                "pkcs11_check-0.2.0.dist-info/RECORD",
                hashlib.sha256(
                    distribution.locate_file(distribution._record_relative).read_bytes()
                ).hexdigest(),
                distribution.locate_file(distribution._record_relative).stat().st_size,
            ),
        ]
    )


def test_receipt_rejects_blank_nonpyc_record_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pkcs11_check.artifact_audit as module

    distribution = _FakeDistribution(tmp_path, include_unverified=True)
    monkeypatch.setattr(module, "_load_distribution", lambda: distribution)
    monkeypatch.setattr(
        module, "__file__", str(distribution.locate_file(distribution._package_relative))
    )

    with pytest.raises(ArtifactAuditError, match="blank row"):
        build_installation_receipt(install_prefix=tmp_path)


def test_receipt_accepts_and_checks_pep610_archive_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pkcs11_check.artifact_audit as module

    archive_hash = "c" * 64
    distribution = _FakeDistribution(tmp_path, archive_hash=archive_hash)
    monkeypatch.setattr(module, "_load_distribution", lambda: distribution)
    monkeypatch.setattr(
        module, "__file__", str(distribution.locate_file(distribution._package_relative))
    )

    receipt = build_installation_receipt(
        install_prefix=tmp_path, expected_archive_sha256=archive_hash
    )

    assert receipt["archive_sha256"] == archive_hash
    assert receipt["integrity_binding"] == "installed-distribution-record+pep610-direct-url"


def test_receipt_rejects_conflicting_pep610_archive_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pkcs11_check.artifact_audit as module

    distribution = _FakeDistribution(tmp_path, archive_hash="c" * 64)
    monkeypatch.setattr(module, "_load_distribution", lambda: distribution)
    monkeypatch.setattr(
        module, "__file__", str(distribution.locate_file(distribution._package_relative))
    )

    with pytest.raises(ArtifactAuditError, match="does not match expected"):
        build_installation_receipt(install_prefix=tmp_path, expected_archive_sha256="d" * 64)


def test_receipt_rejects_wrong_version_and_wrong_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pkcs11_check.artifact_audit as module

    distribution = _FakeDistribution(tmp_path)
    monkeypatch.setattr(module, "_load_distribution", lambda: distribution)
    monkeypatch.setattr(
        module, "__file__", str(distribution.locate_file(distribution._package_relative))
    )

    with pytest.raises(ArtifactAuditError, match="does not match expected"):
        build_installation_receipt(install_prefix=tmp_path, expected_version="9.9.9")
    other_prefix = tmp_path / "other"
    other_prefix.mkdir()
    with pytest.raises(ArtifactAuditError, match="outside the installation prefix"):
        build_installation_receipt(install_prefix=other_prefix)


def test_receipt_rejects_editable_origin_not_listed_in_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pkcs11_check.artifact_audit as module

    distribution = _FakeDistribution(tmp_path, include_package=False)
    monkeypatch.setattr(module, "_load_distribution", lambda: distribution)
    monkeypatch.setattr(
        module, "__file__", str(distribution.locate_file(distribution._package_relative))
    )

    with pytest.raises(ArtifactAuditError, match="not listed in distribution RECORD"):
        build_installation_receipt(install_prefix=tmp_path)


def test_receipt_rejects_missing_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import pkcs11_check.artifact_audit as module

    distribution = _FakeDistribution(tmp_path)
    distribution.files = [distribution._package_relative]
    monkeypatch.setattr(module, "_load_distribution", lambda: distribution)
    monkeypatch.setattr(
        module, "__file__", str(distribution.locate_file(distribution._package_relative))
    )

    with pytest.raises(ArtifactAuditError, match="RECORD"):
        build_installation_receipt(install_prefix=tmp_path)
