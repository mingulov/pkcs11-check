from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_hkdf_wycheproof_vectors_run_per_test_in_isolated_runner() -> None:
    source = (ROOT / "src/pkcs11_check/testcases/wycheproof/test_wycheproof_hkdf.py").read_text(
        encoding="utf-8"
    )

    assert "pytest.mark.subprocess_per_test" in source
