"""Regression: collecting the ACVP test tree must not CRASH when vectors are absent.

The ACVP AES package centralized its "skip when vectors not cloned" guard in an
eagerly-imported helper (``base_loader``) re-exported from ``aes/__init__.py``. A
module-level ``pytest.skip(allow_module_level=True)`` there fired during the
conftest-import phase -- importing ``aes/conftest.py`` imports the ``aes`` package
``__init__`` -> ``base`` -> ``base_loader`` -- where pytest does NOT catch
``Skipped``. So ``pytest.main()`` crashed and ``collect_pytest_item_metadata``
raised "pytest metadata collection failed" instead of skipping. Leaf test modules
skip gracefully (the skip fires in the collection path, which pytest catches); the
helper-via-conftest path did not.

This reproduced on any platform once ACVP data was absent -- it surfaced on Wine,
where the vendor data dir did not resolve, while the Linux pool always had the
vectors fetched. A module-level skip must live only in a leaf test module. This
guard runs the production collection helper over the ACVP test tree with an empty
data dir and fails if collection raises instead of skipping.
"""

from __future__ import annotations

import os
from pathlib import Path

from pkcs11_check.core.collection import collect_pytest_item_metadata

_REPO_ROOT = Path(__file__).resolve().parents[1]
_TESTCASES = _REPO_ROOT / "src" / "pkcs11_check" / "testcases"
# The AES package is the crash site: it has a nested conftest.py and an eager
# __init__.py, so a per-file shard here makes pytest import aes/conftest.py ->
# aes/__init__ -> base_loader during initial-conftest loading.
_AES_DIR = _TESTCASES / "acvp" / "aes"
_AES_SHARD_FILE = _AES_DIR / "test_gcm.py"


def _collect_no_data(target: Path, tmp_path: Path) -> list:
    empty_data = tmp_path / "empty-vendor-data"
    empty_data.mkdir(exist_ok=True)
    env = {
        **os.environ,
        "PKCS11_CHECK_DATA_DIR": str(empty_data),
        # Never serve a cached manifest from a prior fetched-data run.
        "PKCS11_CHECK_NO_COLLECTION_CACHE": "1",
    }
    # Must not raise ValueError("pytest metadata collection failed: ...").
    return collect_pytest_item_metadata([str(target)], [], env=env)


def test_acvp_aes_dir_collection_skips_without_vectors(tmp_path: Path) -> None:
    """Collecting the AES package dir with vectors absent must skip, not crash."""
    items = _collect_no_data(_AES_DIR, tmp_path)
    assert isinstance(items, list)


def test_acvp_aes_file_shard_collection_skips_without_vectors(tmp_path: Path) -> None:
    """A per-file shard inside the AES package (how the pool shards) must skip,
    not crash -- this is the exact target shape that broke under Wine."""
    items = _collect_no_data(_AES_SHARD_FILE, tmp_path)
    assert isinstance(items, list)
