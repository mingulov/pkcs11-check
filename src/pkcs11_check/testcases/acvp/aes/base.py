"""Base utilities for ACVP AES test modules.

Shared helpers for loading vectors and running encrypt/decrypt tests
to eliminate code duplication across AES mode test files.

This module re-exports from submodules for backward compatibility.
"""

from __future__ import annotations

# Re-export all public items from submodules for backward compatibility
from pkcs11_check.testcases.acvp.aes.base_loader import (
    _load_simple_vectors,
    _load_vectors,
)
from pkcs11_check.testcases.acvp.aes.base_runner_aead import (
    CKM_AES_GCM_SIV,
    run_ccm_decrypt_test,
    run_ccm_encrypt_test,
    run_gcm_decrypt_test,
    run_gcm_encrypt_test,
)
from pkcs11_check.testcases.acvp.aes.base_runner_simple import (
    _import_aes_key,
    run_simple_decrypt_test,
    run_simple_encrypt_test,
)

__all__ = [
    "CKM_AES_GCM_SIV",
    "_import_aes_key",
    "_load_simple_vectors",
    "_load_vectors",
    "run_ccm_decrypt_test",
    "run_ccm_encrypt_test",
    "run_gcm_decrypt_test",
    "run_gcm_encrypt_test",
    "run_simple_decrypt_test",
    "run_simple_encrypt_test",
]
