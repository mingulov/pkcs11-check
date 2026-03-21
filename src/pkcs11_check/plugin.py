"""pytest plugin entry point for pkcs11-check."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.core.preflight import CapabilityManifest, load_manifest, run_preflight_subprocess

# Re-export fixtures so pytest discovers them
from pkcs11_check.fixtures import (  # noqa: F401
    p11_config,
    p11_interface_version,
    p11_module,
    p11_session,
)
from pkcs11_check.markers import MARKER_DEFINITIONS, should_skip_for_version

_MANIFEST_KEY: pytest.StashKey[CapabilityManifest | None] = pytest.StashKey()


def pytest_addoption(parser: Any) -> None:
    """Register pkcs11-check CLI options with pytest."""
    group = parser.getgroup("pkcs11-check", "PKCS#11 testing")
    group.addoption(
        "--p11-module",
        dest="p11_module",
        default=None,
        help="Path to PKCS#11 module (.so/.dll/.dylib)",
    )
    group.addoption(
        "--p11-interface",
        dest="p11_interface",
        default="auto",
        help="Force interface version: auto, 2.40, 3.0, 3.1, 3.2",
    )
    group.addoption(
        "--p11-slot",
        dest="p11_slot",
        type=int,
        default=0,
        help="Slot index (default: 0)",
    )
    group.addoption(
        "--p11-pin",
        dest="p11_pin",
        default=None,
        help="PIN (prefer P11TEST_PIN env var)",
    )
    group.addoption(
        "--p11-destructive",
        dest="p11_destructive",
        action="store_true",
        default=False,
        help="Enable destructive tests",
    )
    group.addoption(
        "--p11-skip-unsupported",
        dest="p11_skip_unsupported",
        action="store_true",
        default=True,
        help="Auto-skip tests for unsupported mechanisms (default: on)",
    )
    group.addoption(
        "--p11-thread-safe",
        dest="p11_thread_safe",
        action="store_true",
        default=False,
        help="Enable concurrent same-session tests (may crash SoftHSM2)",
    )
    group.addoption(
        "--p11-manifest",
        dest="p11_manifest",
        default=None,
        help="Path to a precomputed PKCS#11 capability manifest",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Register pkcs11-check custom markers and inject --report-log for non-isolated runs."""
    for marker in MARKER_DEFINITIONS:
        config.addinivalue_line("markers", f"{marker.name}: {marker.description}")
    config.stash[_MANIFEST_KEY] = None

    # Inject --report-log when PKCS11_CHECK_REPORT_LOG is set (by test_cmd.py for
    # --isolation none JSON runs).  Guard against meta-tests (no --p11-module) and
    # cases where the user already supplied --report-log on the command line.
    if config.getoption("p11_module", default=None) is None:
        return  # Not a pkcs11-check run (e.g. meta-tests)
    if config.getoption("report_log", default=None) is not None:
        return  # User already passed --report-log
    report_log_path = os.environ.get("PKCS11_CHECK_REPORT_LOG")
    if report_log_path:
        config.option.report_log = report_log_path


def _is_testcase_item(item: pytest.Item) -> bool:
    item_path = getattr(item, "path", None)
    if item_path is not None:
        return "testcases" in str(item_path)
    return "testcases" in str(item.fspath)


def _has_dynamic_markers(item: pytest.Item) -> bool:
    return any(
        item.get_closest_marker(marker_name)
        for marker_name in ("requires_v30", "requires_v32", "needs_mechanism")
    )


def _manifest_failure_message(manifest: CapabilityManifest) -> str:
    detail = manifest.error or "unknown error"
    return f"PKCS#11 preflight {manifest.status}: {detail}"


def _marker_version_label(marker_name: str) -> str:
    return marker_name.removeprefix("requires_")


def _ensure_manifest(config: pytest.Config) -> CapabilityManifest | None:
    cached = config.stash[_MANIFEST_KEY]
    if cached is not None:
        return cached

    module_path = config.getoption("p11_module", default=None)
    if module_path is None:
        return None

    manifest_option = config.getoption("p11_manifest", default=None)
    if manifest_option:
        try:
            manifest = load_manifest(Path(manifest_option))
        except Exception as exc:
            pytest.exit(f"Unable to load p11 manifest: {exc}", returncode=2)
        config.stash[_MANIFEST_KEY] = manifest
        return manifest

    manifest_fd, manifest_raw_path = tempfile.mkstemp(
        prefix="pkcs11-check-manifest-", suffix=".json"
    )
    os.close(manifest_fd)
    manifest_path = Path(manifest_raw_path)
    try:
        manifest = run_preflight_subprocess(
            Path(module_path),
            interface=config.getoption("p11_interface", default="auto"),
            slot=config.getoption("p11_slot", default=0),
            timeout=30,
            output_path=manifest_path,
        )
    finally:
        manifest_path.unlink(missing_ok=True)

    if manifest.status != "ok":
        pytest.exit(_manifest_failure_message(manifest), returncode=2)

    config.stash[_MANIFEST_KEY] = manifest
    return manifest


def _runtime_skip_reason(
    item: pytest.Item,
    config: pytest.Config,
    manifest: CapabilityManifest | None,
) -> str | None:
    if manifest is None:
        return None

    for marker_name in ("requires_v30", "requires_v32"):
        if item.get_closest_marker(marker_name) and manifest.interface_version is not None:
            if should_skip_for_version(marker_name, manifest.interface_version):
                return (
                    f"Requires {_marker_version_label(marker_name)}, "
                    f"module has v{manifest.interface_version}"
                )

    if config.getoption("p11_skip_unsupported", default=True):
        marker = item.get_closest_marker("needs_mechanism")
        if marker and marker.args:
            needed = str(marker.args[0])
            if needed not in manifest.mechanisms:
                return f"Mechanism {needed} not supported by module"

    return None


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Apply collection-safe static skips only."""
    module_path = config.getoption("p11_module", default=None)

    # If no module specified, skip all tests in testcases/
    if module_path is None:
        for item in items:
            if _is_testcase_item(item):
                item.add_marker(pytest.mark.skip(reason="No --p11-module specified"))
        return

    destructive_enabled = config.getoption("p11_destructive", default=False)
    thread_safe_enabled = config.getoption("p11_thread_safe", default=False)
    for item in items:
        if not _is_testcase_item(item):
            continue

        if item.get_closest_marker("destructive") and not destructive_enabled:
            item.add_marker(
                pytest.mark.skip(reason="Destructive test (use --p11-destructive to enable)")
            )

        if item.get_closest_marker("thread_safe") and not thread_safe_enabled:
            item.add_marker(
                pytest.mark.skip(
                    reason="Concurrent same-session test (use --p11-thread-safe to enable)"
                )
            )


def pytest_collection_finish(session: pytest.Session) -> None:
    """Prepare a capability manifest after collection, never during module import."""
    config = session.config
    if config.getoption("collectonly", default=False):
        return
    if not any(_is_testcase_item(item) and _has_dynamic_markers(item) for item in session.items):
        return
    _ensure_manifest(config)


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Apply dynamic skip decisions from the capability manifest at runtime."""
    if not _is_testcase_item(item) or not _has_dynamic_markers(item):
        return

    manifest = _ensure_manifest(item.config)
    reason = _runtime_skip_reason(item, item.config, manifest)
    if reason is not None:
        pytest.skip(reason)
