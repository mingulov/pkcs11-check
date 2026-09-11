"""Meta-test configuration for pkcs11-check's own test suite."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from pkcs11_check.testcases.data import ACVP_DIR, CCTV_DIR, WYCHEPROOF_DIR

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from _pytest.terminal import TerminalReporter


@pytest.fixture
def classification_report_plugin_enabled() -> None:
    """Opt a meta-test into exercising the live classification report hook."""


@pytest.fixture(autouse=True)
def _isolate_meta_test_classifications(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """Keep helper-unit classifications from rewriting their outer meta-test result.

    Most tests in this directory call product helpers directly and assert the
    terminating exception and recorded classification.  Those records describe the
    simulated provider action, not the surrounding meta-test.  Integration tests opt
    into the live hook with ``classification_report_plugin_enabled``.
    """
    import pkcs11_check.plugin as plugin_mod
    from pkcs11_check import classification

    classification.clear()
    if "classification_report_plugin_enabled" not in request.fixturenames:
        monkeypatch.setattr(
            plugin_mod,
            "_attach_classification_to_report",
            lambda *args, **kwargs: None,
        )
    yield
    classification.clear()


# Meta-tests that load downloaded Wycheproof/ACVP/CCTV vectors. When fetch-data
# has not populated the vendor data dir (e.g. CI), these have no vectors to read
# and would raise FileNotFoundError/StopIteration/IndexError or assert on empty
# data. Skip them instead -- missing optional test data is an acceptable skip
# (unlike a module crash or a wrong return code, which must always surface).
#
# Each module maps to the data directories it requires; a file is skipped when
# ANY required directory is absent. Completeness is enforced by
# tests/test_no_data_skip_guard.py, which reproduces the no-data condition so a
# newly added vector-dependent file that forgets to register here is caught
# locally rather than only in CI.
_VECTOR_DEPENDENT_MODULES: dict[str, tuple[Path, ...]] = {
    "test_acvp_ecdh_loader.py": (WYCHEPROOF_DIR,),
    "test_acvp_rsa_pss_loader.py": (ACVP_DIR,),
    "test_wycheproof_dsa_loader.py": (WYCHEPROOF_DIR,),
    "test_wycheproof_ecdh_guards.py": (WYCHEPROOF_DIR,),
    "test_wycheproof_ed25519_loader.py": (WYCHEPROOF_DIR,),
    "test_wycheproof_generic_guards.py": (WYCHEPROOF_DIR,),
    "test_wycheproof_aes_mac_guards.py": (WYCHEPROOF_DIR,),
    "test_wycheproof_chacha_guards.py": (WYCHEPROOF_DIR,),
    "test_wycheproof_rsa_loader.py": (WYCHEPROOF_DIR,),
    "test_wycheproof_rsa_oaep_import_classification.py": (WYCHEPROOF_DIR,),
    "test_wycheproof_rsa_siggen_runtime_classification.py": (WYCHEPROOF_DIR,),
    "test_wycheproof_signature_duplicate_guards.py": (WYCHEPROOF_DIR,),
    "test_wycheproof_xdh_guards.py": (WYCHEPROOF_DIR,),
    # Registered 2026-06-17: these load vendor vectors but were not listed, so
    # they failed in CI (no fetch-data) instead of skipping. See the guard test.
    "test_import_skip_xfail_batch3a.py": (WYCHEPROOF_DIR,),
    "test_import_skip_xfail_batch3b.py": (WYCHEPROOF_DIR, CCTV_DIR),
    "test_wycheproof_kryoptic_classification.py": (WYCHEPROOF_DIR,),
    "test_wycheproof_provenance.py": (WYCHEPROOF_DIR,),
}


def _find_mock_module() -> str | None:
    """Return the path to pkcs11-mock.so if discoverable, otherwise None.

    Search order:
    1. P11TEST_MOCK_MODULE env override (CI / developer explicit path).
    2. Standard cache location built by the test-setup makefile.
    3. Additional well-known locations (distro packages, Docker builds).
    """
    candidates = [
        os.environ.get("P11TEST_MOCK_MODULE"),
        str(Path.home() / ".cache" / "pkcs11-check-test" / "pkcs11-mock.so"),
        "/tmp/pkcs11-mock-build/pkcs11-mock.so",  # noqa: S108 -- test temp path only
        "/usr/lib/pkcs11/pkcs11-mock.so",
        "/usr/lib64/libpkcs11-mock.so",
        "/opt/pkcs11_mock/libpkcs11_mock.so",
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


@pytest.fixture(scope="session")
def mock_module_path() -> str:
    """Pytest fixture: absolute path to pkcs11-mock.so.

    Skips the test (not fails) when the mock shared library is not installed.
    Build from upstream (https://github.com/Pkcs11Interop/pkcs11-mock) and set
    P11TEST_MOCK_MODULE=/path/to/pkcs11-mock.so to make it discoverable.
    """
    path = _find_mock_module()
    if path is None:
        pytest.skip(
            "pkcs11-mock.so not found; build from upstream"
            " (https://github.com/Pkcs11Interop/pkcs11-mock)"
            " and set P11TEST_MOCK_MODULE=/path/to/pkcs11-mock.so"
        )
    return path


# Populated by pytest_collection_modifyitems with the vector-dependent module
# names it actually skipped in this session (i.e. missing data, not some other
# skip reason). Read back by pytest_terminal_summary to report the coverage
# gap -- see that function's docstring for why this exists.
_vector_skipped_modules: set[str] = set()


def pytest_collection_modifyitems(config: pytest.Config, items: Iterable[pytest.Item]) -> None:
    """Skip vector-dependent meta-tests when any required data dir is not fetched."""
    for item in items:
        module_name = Path(str(item.fspath)).name
        required = _VECTOR_DEPENDENT_MODULES.get(module_name)
        if required is None:
            continue
        missing = [d for d in required if not d.exists()]
        if missing:
            reason = ", ".join(str(d) for d in missing)
            item.add_marker(
                pytest.mark.skip(reason=f"vector data not fetched: {reason} (run fetch-data)")
            )
            _vector_skipped_modules.add(module_name)


def pytest_terminal_summary(
    terminalreporter: TerminalReporter,
    exitstatus: int,
    config: pytest.Config,
) -> None:
    """Make a data-less run's reduced coverage visible instead of silent.

    An empty ``data/`` (every fresh git worktree, and CI without fetch-data)
    makes ``pytest_collection_modifyitems`` above skip every vector-dependent
    meta-test -- ~290 tests, including 100% of the duplicate-detection guard
    suite (see ``tests/test_wycheproof_signature_duplicate_guards.py``). The
    run still exits green, so nothing distinguishes a full release-grade run
    (~39 skips) from one silently missing that whole defect class (~330
    skips). This line is the only signal: it costs a normal, vector-less
    developer run nothing (still passes, still fast, no new failure mode) but
    makes it impossible to mistake for a release-qualifying run. See
    docs/releasing.md for the release-gate requirement this backs.
    """
    if not _vector_skipped_modules:
        return
    terminalreporter.write_sep("=", "vector data coverage", yellow=True)
    terminalreporter.write_line(
        f"{len(_vector_skipped_modules)} vector-dependent test module(s) skipped -- "
        "Wycheproof/ACVP/CCTV data not fetched under data/. This run is NOT "
        "release-grade: it silently omits ~290 tests, including the entire "
        "duplicate-detection guard suite. Run `pkcs11-check fetch-data` and re-run "
        "before treating results as release evidence; see docs/releasing.md.",
        yellow=True,
    )
