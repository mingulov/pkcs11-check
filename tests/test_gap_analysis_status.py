"""Guardrails for stale status claims in the speed/coverage gap analysis."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GAP_DOC = ROOT / "docs/findings/speed-coverage-correctness-gap-analysis-2026-06-11.md"
COVERAGE_GAPS_PLAN = ROOT / "docs/coverage-gaps-plan.md"


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


def test_coverage_plan_does_not_count_ecmqv_as_kea_coverage() -> None:
    """ECMQV and KEA are different mechanisms; ECMQV tests do not cover KEA."""
    ecdh_extended = _read("src/pkcs11_check/testcases/test_ecdh_extended.py")
    misc_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_misc.py")
    plan = COVERAGE_GAPS_PLAN.read_text(encoding="utf-8")

    assert "TestECMQVDerive" in ecdh_extended
    assert "CKM_KEA_KEY_PAIR_GEN" in misc_registry
    assert "CKM_KEA_DERIVE" in misc_registry

    assert "ECMQV / KEA" not in plan
    assert "KEA remains source-first" in plan


def test_gap_analysis_marks_dsa_dh_domain_parameter_coverage_as_dedicated() -> None:
    """DSA, DH, and X9.42 have dedicated domain-parameter/product tests."""
    dsa = _read("src/pkcs11_check/testcases/test_dsa_complete.py")
    dh = _read("src/pkcs11_check/testcases/test_dh_key_agreement.py")
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "CKM_DSA_PARAMETER_GEN" in dsa
    assert "test_parameter_gen_sign_verify" in dsa
    assert "CKM_DH_PKCS_PARAMETER_GEN" in dh
    assert "test_generated_params_produce_valid_keypair" in dh
    assert "CKM_X9_42_DH_PARAMETER_GEN" in x942
    assert "test_generated_params_produce_valid_derive" in x942

    assert "DSA/DH/X9.42 domain parameter paths are mostly absent" not in doc
    assert "Dedicated DSA/DH/X9.42 domain-parameter coverage exists" in doc


def test_gap_analysis_marks_block_cbc_pad_vectors_as_added() -> None:
    """DES-family, Camellia, ARIA, and SEED CBC_PAD now have KAT vector links."""
    des_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_des.py")
    cipher_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_ciphers.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    for vector_file in ("des_cbc_pad.json", "des3_cbc_pad.json"):
        assert vector_file in des_registry
        assert _read(f"src/pkcs11_check/testcases/data/mechanism_vectors/{vector_file}")

    for vector_file in ("camellia_cbc_pad.json", "aria_cbc_pad.json", "seed_cbc_pad.json"):
        assert vector_file in cipher_registry
        assert _read(f"src/pkcs11_check/testcases/data/mechanism_vectors/{vector_file}")

    assert "DES, 3DES, Camellia, ARIA, and SEED CBC_PAD" in doc
