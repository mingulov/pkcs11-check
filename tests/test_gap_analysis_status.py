"""Guardrails for stale status claims in the speed/coverage gap analysis."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GAP_DOC = ROOT / "docs/findings/speed-coverage-correctness-gap-analysis-2026-06-11.md"


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_gap_analysis_marks_protocol_kdf_semantics_as_dedicated_coverage() -> None:
    """SP800-108, TLS12 KDF, and PBKDF2 have dedicated semantic tests."""
    sp800 = _read("src/pkcs11_check/testcases/test_sp800_108_kdf.py")
    tls12 = _read("src/pkcs11_check/testcases/test_tls12.py")
    pbkdf2 = _read("src/pkcs11_check/testcases/wycheproof/test_wycheproof_pbkdf2.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "_sp800_108_counter_hmac_sha256_reference" in sp800
    assert "assert val == expected" in sp800
    assert "_tls12_prf_sha256" in tls12
    assert "assert value == expected" in tls12
    assert 'REQUIRED_MECHANISMS = ["PKCS5_PBKD2"]' in pbkdf2
    assert "assert dk_actual == dk_expected" in pbkdf2

    assert "Protocol KDFs are intentionally skipped" not in doc
    assert "Dedicated protocol KDF semantic coverage exists" in doc


def test_gap_analysis_marks_blake2b_keyed_semantics_as_covered() -> None:
    """BLAKE2B keyed HMAC, HMAC_GENERAL, KEY_GEN, and KEY_DERIVE are covered."""
    blake2 = _read("src/pkcs11_check/testcases/test_blake2.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "_BLAKE2B_KEYED_CASES" in blake2
    assert "_blake2b_hmac_reference" in blake2
    assert "assert mac == expected" in blake2
    assert "assert mac == expected_full[:mac_len]" in blake2
    assert "assert attrs[CKA_KEY_TYPE] == case.key_type" in blake2
    assert "assert value == expected" in blake2

    assert "BLAKE2B coverage stops at unkeyed digest" not in doc
    assert "BLAKE2B keyed coverage exists" in doc
