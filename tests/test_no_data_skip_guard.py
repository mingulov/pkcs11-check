"""Guard: vector-dependent meta-tests must SKIP (never fail) without fetch-data.

This reproduces the CI "no vector data" condition locally. CI runs the meta-test
suite without running ``pkcs11-check fetch-data``, so any meta-test that loads
downloaded Wycheproof/ACVP/CCTV vectors must *skip* when the data is absent --
not index an empty list, assert on empty data, or otherwise fail. The skip
plumbing lives in ``tests/conftest.py`` (``_VECTOR_DEPENDENT_MODULES``).

The failure mode this guards against (broke CI on the v0.1.4 push): a newly added
test file loads vendor vectors but is not registered in that allowlist, so it
passes locally (where the data is fetched) and fails only in CI. This test runs
the vector-referencing meta-test files in a subprocess with an empty
``PKCS11_CHECK_DATA_DIR`` and fails -- locally -- if any of them does not cleanly
pass-or-skip, naming the offender.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

_TESTS_DIR = Path(__file__).parent
_REPO_ROOT = _TESTS_DIR.parent

# A meta-test file is "vector-dependent" if it imports a vendor-data loader
# package or references one of the resolved vendor data directories.
_VECTOR_REF = re.compile(
    r"testcases\.(?:wycheproof|acvp|cctv)|WYCHEPROOF_DIR|ACVP_DIR|CCTV_DIR|wycheproof_loader"
)


def _vector_referencing_files() -> list[str]:
    """All tests/test_*.py files that consume downloaded vendor vectors (excluding self)."""
    files = []
    for p in sorted(_TESTS_DIR.glob("test_*.py")):
        if p.name == Path(__file__).name:
            continue  # never recurse into this guard
        if _VECTOR_REF.search(p.read_text(encoding="utf-8")):
            files.append(p.name)
    return files


def test_vector_dependent_meta_tests_skip_without_fetch_data(tmp_path: Path) -> None:
    files = _vector_referencing_files()
    assert files, "expected to discover vector-referencing meta-test files"

    empty_data = tmp_path / "empty-vendor-data"
    empty_data.mkdir()
    # Inherit the real environment, then force an empty vendor data dir so every
    # required data directory resolves to absent (mirrors CI without fetch-data).
    env = {**os.environ, "PKCS11_CHECK_DATA_DIR": str(empty_data)}

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            *(f"tests/{f}" for f in files),
            "-q",
            "--no-header",
            "--tb=line",
            "-p",
            "no:cacheprovider",
            "-o",
            "addopts=",
        ],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )

    # pytest exit 0 = all passed/skipped; 1 = failures; 5 = no tests collected.
    assert proc.returncode == 0, (
        "Vector-dependent meta-tests FAILED with no fetch-data (the CI condition).\n"
        "A meta-test loaded vendor vectors instead of skipping when absent. Register the\n"
        "offending file in tests/conftest.py _VECTOR_DEPENDENT_MODULES (mapping it to the\n"
        "data dir[s] it needs), or guard its data load.\n\n"
        f"pytest exit={proc.returncode}\n"
        f"--- stdout (tail) ---\n{proc.stdout[-3000:]}\n"
        f"--- stderr (tail) ---\n{proc.stderr[-1000:]}"
    )
