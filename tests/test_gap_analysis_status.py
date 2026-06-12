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
    wtls = _read("src/pkcs11_check/testcases/test_wtls.py")
    ike = _read("src/pkcs11_check/testcases/test_ike.py")
    pbkdf2 = _read("src/pkcs11_check/testcases/wycheproof/test_wycheproof_pbkdf2.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "_sp800_108_counter_hmac_sha256_reference" in sp800
    assert "assert val == expected" in sp800
    assert "_tls12_prf_sha256" in tls12
    assert "assert value == expected" in tls12
    assert "test_prf_seed_affects_output" in wtls
    assert "test_prf_label_affects_output" in wtls
    assert "test_base_key_affects_output" in ike
    assert 'REQUIRED_MECHANISMS = ["PKCS5_PBKD2"]' in pbkdf2
    assert "assert dk_actual == dk_expected" in pbkdf2

    assert "Protocol KDFs are intentionally skipped" not in doc
    assert "Dedicated protocol KDF semantic coverage exists" in doc
    assert "WTLS PRF seed-sensitivity coverage" in doc
    assert "WTLS PRF label-sensitivity coverage" in doc
    assert "IKE2 PRF+ base-key sensitivity coverage" in doc


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
    assert "test_blake2b_hmac_general_rejects_invalid_lengths" in blake2

    assert "BLAKE2B coverage stops at unkeyed digest" not in doc
    assert "BLAKE2B keyed coverage exists" in doc
    assert "BLAKE2B invalid-length HMAC_GENERAL" in doc


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


def test_gap_analysis_marks_dsa_parameter_variants_as_covered() -> None:
    """DSA FIPS 186-4 parameter-generation variants have product coverage."""
    dsa = _read("src/pkcs11_check/testcases/test_dsa_complete.py")
    remaining_gaps = _read("src/pkcs11_check/testcases/test_remaining_gaps.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "CK_DSA_PARAMETER_GEN_PARAM" in dsa
    assert "CKM_DSA_PROBABILISTIC_PARAMETER_GEN" in dsa
    assert "CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN" in dsa
    assert "CKM_DSA_FIPS_G_GEN" in dsa
    assert "test_probabilistic_parameter_gen_returns_pq" in dsa
    assert "test_shawe_taylor_parameter_gen_returns_pq" in dsa
    assert "test_fips_g_gen_uses_generated_seed_and_pq" in dsa

    assert "test_dsa_probabilistic_parameter_gen_availability" not in remaining_gaps
    assert "DSA parameter-generation variants not covered by `test_dsa_complete.py`" not in doc
    assert "DSA probabilistic/Shawe-Taylor/FIPS-G parameter variants" in doc


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


def test_gap_analysis_marks_block_mac_general_vectors_as_added() -> None:
    """DES-family, Camellia, ARIA, and SEED MAC_GENERAL now have KAT vector links."""
    des_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_des.py")
    cipher_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_ciphers.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    for vector_file in ("des_mac_general.json", "des3_mac_general.json"):
        assert vector_file in des_registry
        assert _read(f"src/pkcs11_check/testcases/data/mechanism_vectors/{vector_file}")

    for vector_file in (
        "camellia_mac_general.json",
        "aria_mac_general.json",
        "seed_mac_general.json",
    ):
        assert vector_file in cipher_registry
        assert _read(f"src/pkcs11_check/testcases/data/mechanism_vectors/{vector_file}")

    assert "DES, 3DES, Camellia, ARIA, and SEED MAC_GENERAL" in doc


def test_gap_analysis_marks_des_family_fixed_mac_vectors_as_added() -> None:
    """DES and 3DES fixed-output MACs now have half-block KAT vector links."""
    des_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_des.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    for vector_file in ("des_mac.json", "des3_mac.json"):
        assert vector_file in des_registry
        assert _read(f"src/pkcs11_check/testcases/data/mechanism_vectors/{vector_file}")

    assert "DES and 3DES fixed-output MAC" in doc
    assert "DES/DES3 fixed-output MAC, RC2/RC5/CAST/CAST3/IDEA fixed-output MAC" not in doc


def test_gap_analysis_marks_half_block_fixed_mac_vectors_as_added() -> None:
    """Camellia, ARIA, and SEED fixed-output MACs now have half-block KAT vectors."""
    cipher_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_ciphers.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    for vector_file in ("camellia_mac.json", "aria_mac.json", "seed_mac.json"):
        assert vector_file in cipher_registry
        assert _read(f"src/pkcs11_check/testcases/data/mechanism_vectors/{vector_file}")

    assert "Camellia, ARIA, and SEED fixed-output MAC" in doc


def test_gap_analysis_marks_des3_cmac_vectors_as_added() -> None:
    """DES3 CMAC and CMAC_GENERAL now have full-block KAT vector links."""
    des_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_des.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    for vector_file in ("des3_cmac.json", "des3_cmac_general.json"):
        assert vector_file in des_registry
        assert _read(f"src/pkcs11_check/testcases/data/mechanism_vectors/{vector_file}")

    assert "DES3 CMAC/CMAC_GENERAL now have full-block" in doc
    assert "DES3 CMAC/CMAC_GENERAL, RC2/RC5/CAST/CAST3/IDEA fixed-output MAC" not in doc


def test_gap_analysis_marks_legacy_fixed_mac_vectors_as_added() -> None:
    """RC2, RC5, CAST128, and IDEA fixed-output MACs now have KAT vector links."""
    legacy_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_legacy.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    for vector_file in ("rc2_mac.json", "rc5_mac.json", "cast128_mac.json", "idea_mac.json"):
        assert vector_file in legacy_registry
        assert _read(f"src/pkcs11_check/testcases/data/mechanism_vectors/{vector_file}")

    assert "RC2, RC5, CAST128/CAST5, and IDEA fixed-output MAC" in doc
    assert "RC2/RC5/CAST/CAST3/IDEA fixed-output MAC" not in doc


def test_gap_analysis_marks_mixed_fail_crash_reporting_as_fixed() -> None:
    """Mixed fail+crash units now surface crash status instead of only failed status."""
    runner = _read("src/pkcs11_check/core/file_runner.py")
    tests = _read("tests/test_file_runner.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert 'for status in ("timeout", "crashed", "failed"' in runner
    assert "test_write_isolated_json_report_crash_status_wins_over_failed_count" in tests
    assert 'status: "crashed"' in doc
    assert "Status: fixed in the current branch. `_overall_unit_status()` gives" in doc
