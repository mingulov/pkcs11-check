"""Metadata checks for audited high-count session reuse."""

from __future__ import annotations

from pathlib import Path


def _text(path: str) -> str:
    return Path(path).read_text()


def test_hot_vector_files_use_module_session() -> None:
    for path in [
        "src/pkcs11_check/testcases/test_aes_modes.py",
        "src/pkcs11_check/testcases/test_cctv_ed25519.py",
        "src/pkcs11_check/testcases/test_cctv_mldsa.py",
        "src/pkcs11_check/testcases/test_des.py",
        "src/pkcs11_check/testcases/test_dsa_complete.py",
        "src/pkcs11_check/testcases/test_hash_ml_dsa.py",
        "src/pkcs11_check/testcases/test_kem.py",
        "src/pkcs11_check/testcases/x509/test_limbo_import.py",
        "src/pkcs11_check/testcases/x509/test_limbo_stress.py",
    ]:
        text = _text(path)
        assert "p11_module_session" in text, path
        assert "p11_raw_session" not in text, path


def test_setup_heavy_vector_files_use_fast_module_session_marker() -> None:
    for path in [
        "src/pkcs11_check/testcases/test_cctv_ed25519.py",
        "src/pkcs11_check/testcases/test_cctv_mldsa.py",
        "src/pkcs11_check/testcases/x509/test_limbo_import.py",
        "src/pkcs11_check/testcases/x509/test_limbo_stress.py",
    ]:
        assert "pytest.mark.module_session_fast" in _text(path), path
