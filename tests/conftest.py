"""Meta-test configuration for pkcs11-check's own test suite."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from pkcs11_check.testcases.data import ACVP_DIR, WYCHEPROOF_DIR

if TYPE_CHECKING:
    from collections.abc import Iterable

# Meta-tests that load downloaded Wycheproof/ACVP vectors. When fetch-data has
# not populated the vendor data dir (e.g. CI), these have no vectors to read and
# would raise FileNotFoundError/StopIteration/IndexError. Skip them instead --
# missing optional test data is an acceptable skip (unlike a module crash or a
# wrong return code, which must always surface). Each module maps to the data
# directory it requires.
_VECTOR_DEPENDENT_MODULES: dict[str, Path] = {
    "test_acvp_ecdh_loader.py": WYCHEPROOF_DIR,
    "test_acvp_rsa_pss_loader.py": ACVP_DIR,
    "test_wycheproof_dsa_loader.py": WYCHEPROOF_DIR,
    "test_wycheproof_ecdh_guards.py": WYCHEPROOF_DIR,
    "test_wycheproof_ed25519_loader.py": WYCHEPROOF_DIR,
    "test_wycheproof_generic_guards.py": WYCHEPROOF_DIR,
    "test_wycheproof_rsa_loader.py": WYCHEPROOF_DIR,
    "test_wycheproof_rsa_oaep_import_classification.py": WYCHEPROOF_DIR,
    "test_wycheproof_rsa_siggen_runtime_classification.py": WYCHEPROOF_DIR,
    "test_wycheproof_signature_duplicate_guards.py": WYCHEPROOF_DIR,
    "test_wycheproof_xdh_guards.py": WYCHEPROOF_DIR,
}


def pytest_collection_modifyitems(config: pytest.Config, items: Iterable[pytest.Item]) -> None:
    """Skip vector-dependent meta-tests when their data dir is not fetched."""
    for item in items:
        required = _VECTOR_DEPENDENT_MODULES.get(Path(str(item.fspath)).name)
        if required is not None and not required.exists():
            item.add_marker(
                pytest.mark.skip(reason=f"vector data not fetched: {required} (run fetch-data)")
            )
