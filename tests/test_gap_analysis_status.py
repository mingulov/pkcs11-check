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


def test_gap_analysis_marks_ike_prf_base_key_sensitivity_as_added() -> None:
    """CKM_IKE_PRF_DERIVE changes output when only the base key changes."""
    ike = _read("src/pkcs11_check/testcases/test_ike.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "test_prf_base_key_affects_output" in ike
    assert "IKE PRF base key change did not affect derived output" in ike

    assert "IKE PRF base-key sensitivity coverage" in doc


def test_gap_analysis_marks_blake2b_keyed_semantics_as_covered() -> None:
    """BLAKE2B keyed HMAC, HMAC_GENERAL, KEY_GEN, and KEY_DERIVE are covered."""
    blake2 = _read("src/pkcs11_check/testcases/test_blake2.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "_BLAKE2B_KEYED_CASES" in blake2
    assert "_blake2b_hmac_reference" in blake2
    assert "assert mac == expected" in blake2
    assert "assert mac == expected_full[:mac_len]" in blake2
    assert "assert attrs[CKA_KEY_TYPE] == case.key_type" in blake2
    assert "assert value == expected" in blake2
    assert "test_blake2b_hmac_general_rejects_invalid_lengths" in blake2
    assert "test_blake2b_hmac_general_boundary_lengths" in blake2

    assert "BLAKE2B coverage stops at unkeyed digest" not in doc
    assert "BLAKE2B keyed coverage exists" in doc
    assert "BLAKE2B invalid-length HMAC_GENERAL" in doc_flat
    assert "BLAKE2B HMAC_GENERAL boundary-length coverage" in doc_flat


def test_gap_analysis_marks_blake2b_hmac_general_tamper_negative_as_added() -> None:
    """BLAKE2B HMAC_GENERAL truncated MAC verification rejects tampering."""
    blake2 = _read("src/pkcs11_check/testcases/test_blake2.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_blake2b_hmac_general_rejects_tampered_mac" in blake2
    assert "tampered BLAKE2B HMAC_GENERAL verify" in blake2

    assert "BLAKE2B HMAC_GENERAL tampered-MAC coverage" in doc_flat


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


def test_gap_analysis_marks_raw_dsa_wrong_length_negative_as_hard_fail() -> None:
    """Raw CKM_DSA wrong-length digest acceptance is a hard failure."""
    dsa = _read("src/pkcs11_check/testcases/test_dsa_complete.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "CKM_DSA wrong-length digest" in dsa
    assert "classify_negative_rv(" in dsa
    assert "accepted wrong-length digest for CKM_DSA" not in dsa

    assert "Raw CKM_DSA wrong-length digest acceptance" in doc


def test_gap_analysis_marks_dsa_prehash_runtime_rejects_as_classified() -> None:
    """DSA prehash positive/negative runtime rejects use signature policy helpers."""
    dsa = _read("src/pkcs11_check/testcases/test_dsa_complete.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "xfail_if_op_not_operational" in dsa
    assert "signature_rejected_or_xfail" in dsa
    assert "_dsa_sign_or_xfail" in dsa
    assert "_dsa_invalid_verify_rejected_or_xfail" in dsa

    assert "DSA prehash runtime-reject classification" in doc


def test_gap_analysis_marks_raw_dsa_wrong_signature_length_negative_as_added() -> None:
    """Raw DSA verification rejects wrong-length signatures."""
    dsa = _read("src/pkcs11_check/testcases/test_dsa_complete.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "test_raw_dsa_wrong_signature_length_fails" in dsa
    assert "CKM_DSA wrong-length signature" in dsa
    assert "_dsa_invalid_verify_rejected_or_xfail" in dsa

    assert "Raw CKM_DSA wrong-signature-length coverage" in doc_flat


def test_gap_analysis_marks_dsa_sha224_prehash_matrix_as_added() -> None:
    """DSA_SHA224 is part of the complete DSA prehash roundtrip/tamper matrix."""
    dsa = _read("src/pkcs11_check/testcases/test_dsa_complete.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert 'pytest.param("DSA_SHA224"' in dsa
    assert "SHA-224" in dsa

    assert "DSA_SHA224 now participates" in doc


def test_gap_analysis_marks_controlled_child_crash_stats_as_added() -> None:
    """Pool stats separately surface controlled child crashes/timeouts."""
    pool = _read("docker/test_pool.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "controlled_child_counts" in pool
    assert "child_crash" in pool
    assert "child_timeout" in pool

    assert "Controlled child subprocess crash/timeout stats" in doc


def test_gap_analysis_marks_wolf_session_fast_evidence_as_recorded() -> None:
    """wolfPKCS11 session-fast speed evidence is recorded, not left pending."""
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "Remaining evidence: run targeted wolfPKCS11 X.509/CCTV batches" not in doc
    assert "Focused wolfPKCS11 X.509/CCTV evidence now exists" in doc
    assert "artifacts/_focused/wolfpkcs11-health-current/results.json" in doc
    assert 'module_session_health: {"checks": 0, "duration_s": 0.0}' in doc


def test_gap_analysis_marks_classic_dh_runtime_rejects_as_classified() -> None:
    """Classic DH positive derive runtime rejects use provider-general xfail logic."""
    dh = _read("src/pkcs11_check/testcases/test_dh_key_agreement.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "_dh_derive_or_xfail" in dh
    assert "_DH_DERIVE_RUNTIME_REJECT_RVS" in dh
    assert "xfail_if_known_ckr" in dh

    assert "Classic DH derive runtime-reject classification" in doc_flat


def test_gap_analysis_marks_dh_missing_peer_public_negative_as_added() -> None:
    """Classic DH derive has a negative test for missing peer public data."""
    dh = _read("src/pkcs11_check/testcases/test_dh_key_agreement.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "test_dh_derive_rejects_missing_peer_public_value" in dh
    assert "CKM_DH_PKCS_DERIVE missing peer public value" in dh
    assert "classify_negative_rv(" in dh

    assert "Classic DH missing-peer-public negative coverage" in doc_flat


def test_gap_analysis_marks_x942_missing_peer_public_negative_as_added() -> None:
    """X9.42 DH derive has a negative test for missing peer public data."""
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "test_x942_derive_rejects_missing_peer_public_value" in x942
    assert "CKM_X9_42_DH_DERIVE missing peer public value" in x942
    assert "classify_negative_rv(" in x942

    assert "X9.42 DH missing-peer-public negative coverage" in doc_flat


def test_gap_analysis_marks_regional_cipher_encrypt_data_dispatch_as_added() -> None:
    """Camellia/ARIA/SEED encrypt-data derive dispatch is no longer a gap."""
    derive = _read("src/pkcs11_check/testcases/test_mech_derive.py")
    meta = _read("tests/test_mech_derive_cipher_dispatch.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    for token in (
        "CKM_CAMELLIA_ECB_ENCRYPT_DATA",
        "CKM_CAMELLIA_CBC_ENCRYPT_DATA",
        "CKM_ARIA_ECB_ENCRYPT_DATA",
        "CKM_ARIA_CBC_ENCRYPT_DATA",
        "CKM_SEED_ECB_ENCRYPT_DATA",
        "CKM_SEED_CBC_ENCRYPT_DATA",
    ):
        assert token in derive
        assert token in meta

    assert "Camellia/ARIA/SEED encrypt-data and any remaining protocol KDF variants" not in doc
    assert "Regional cipher encrypt-data derive dispatch exists" in doc


def test_gap_analysis_marks_hybrid_wrap_param_coverage_as_added() -> None:
    """RSA-AES and ECDH-AES hybrid wrap params have positive and tamper coverage."""
    rsa = _read("src/pkcs11_check/testcases/test_rsa_extended.py")
    ecdh = _read("src/pkcs11_check/testcases/test_authenticated_wrap.py")
    guards = _read("tests/test_hybrid_wrap_coverage.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "CK_RSA_AES_KEY_WRAP_PARAMS" in rsa
    assert "test_tampered_blob_rejected" in rsa
    assert "classify_discrimination(" in rsa
    assert "_ECDH_AES_KW_CASES" in ecdh
    for token in (
        "CKM_ECDH_AES_KEY_WRAP",
        "CKM_ECDH_COF_AES_KEY_WRAP",
        "CKM_ECDH_X_AES_KEY_WRAP",
    ):
        assert token in ecdh
        assert token in guards

    assert "RSA-AES key wrap, ECDH-AES key wrap" not in doc
    assert "Hybrid wrap parameter coverage exists for RSA-AES and ECDH-AES" in doc


def test_gap_analysis_marks_aes_ctr_wrap_params_as_added() -> None:
    """AES-CTR generic wrap coverage builds CK_AES_CTR_PARAMS instead of skipping."""
    wrap = _read("src/pkcs11_check/testcases/test_mech_wrap.py")
    guards = _read("tests/test_mech_wrap.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "mech_ctr(" in wrap
    assert "CTR wrap needs CK_AES_CTR_PARAMS -- skipped here" not in wrap
    assert "test_make_wrap_mech_param_builds_ctr_params_without_registry_recipe" in guards

    assert "AES-CTR wrap params are now covered" in doc
    assert "AEAD wrap style expansion and AES-CTR wrap params" not in doc


def test_gap_analysis_marks_gcm_ccm_wrap_params_as_added() -> None:
    """AES-GCM and AES-CCM generic wrap coverage builds wrap-specific params."""
    wrap = _read("src/pkcs11_check/testcases/test_mech_wrap.py")
    guards = _read("tests/test_mech_wrap.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "mech_gcm_wrap(" in wrap
    assert "mech_ccm_wrap(" in wrap
    assert "AEAD wrap not covered here" not in wrap
    assert "test_make_wrap_mech_param_builds_gcm_wrap_params" in guards
    assert "test_make_wrap_mech_param_builds_ccm_wrap_params" in guards

    assert "AES-GCM and AES-CCM wrap params are now covered" in doc_flat


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
    """RC2, RC5, CAST/CAST3/CAST128, and IDEA fixed-output MACs have KAT links."""
    legacy_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_legacy.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    for vector_file in (
        "rc2_mac.json",
        "rc5_mac.json",
        "cast_mac.json",
        "cast3_mac.json",
        "cast128_mac.json",
        "idea_mac.json",
    ):
        assert vector_file in legacy_registry
        assert _read(f"src/pkcs11_check/testcases/data/mechanism_vectors/{vector_file}")

    assert "RC2, RC5, CAST/CAST3/CAST128/CAST5, and IDEA fixed-output MAC" in doc
    assert "RC2/RC5/CAST/CAST3/IDEA fixed-output MAC" not in doc
    assert "CKM_CAST/CKM_CAST3 fixed-output MAC" not in doc


def test_gap_analysis_marks_cast_encrypt_vectors_as_added() -> None:
    """CAST and CAST3 ECB/CBC have RFC 2144 KAT vector links."""
    legacy_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_legacy.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    for vector_file in ("cast_ecb.json", "cast3_ecb.json", "cast_cbc.json", "cast3_cbc.json"):
        assert vector_file in legacy_registry
        assert _read(f"src/pkcs11_check/testcases/data/mechanism_vectors/{vector_file}")

    assert "CAST/CAST3 ECB/CBC" in doc


def test_gap_analysis_marks_cast_cbc_pad_vectors_as_added() -> None:
    """CAST and CAST3 CBC_PAD have non-block-aligned KAT vector links."""
    legacy_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_legacy.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    for vector_file in ("cast_cbc_pad.json", "cast3_cbc_pad.json"):
        assert vector_file in legacy_registry
        assert _read(f"src/pkcs11_check/testcases/data/mechanism_vectors/{vector_file}")

    assert "CAST/CAST3 CBC_PAD" in doc
    assert "CAST/CAST3 CBC_PAD variants" not in doc


def test_gap_analysis_marks_cast_mac_general_vectors_as_added() -> None:
    """CAST and CAST3 MAC_GENERAL have full-block KAT vector links."""
    legacy_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_legacy.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    for vector_file in ("cast_mac_general.json", "cast3_mac_general.json"):
        assert vector_file in legacy_registry
        assert _read(f"src/pkcs11_check/testcases/data/mechanism_vectors/{vector_file}")

    assert "CAST/CAST3 MAC_GENERAL" in doc


def test_gap_analysis_marks_gost28147_iv_param_registry_coverage() -> None:
    """GOST28147 has a registry IV recipe but remains source-first for KATs."""
    legacy_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_legacy.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "registry[CKM_GOST28147]" in legacy_registry
    assert "param_recipe=_iv8" in legacy_registry
    assert "CKM_GOST28147 IV-parameter registry coverage" in doc
    assert "GOST28147 exact-output KATs remain source-first" in doc


def test_gap_analysis_marks_skipjack_ecb64_kat_vectors_as_added() -> None:
    """Skipjack ECB64 has source-backed NIST SP 800-17 KAT vector links."""
    legacy_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_legacy.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "skipjack_ecb64.json" in legacy_registry
    vector_file = _read("src/pkcs11_check/testcases/data/mechanism_vectors/skipjack_ecb64.json")
    assert "NIST SP 800-17 appendix B" in vector_file
    assert "CKM_SKIPJACK_ECB64 now has NIST SP 800-17 exact-output KATs" in doc
    assert "SKIPJACK ECB64 exact-output KATs are covered" in doc


def test_gap_analysis_keeps_skipjack_non_ecb64_variants_source_first() -> None:
    """Skipjack non-ECB64 KATs stay pending until IV parameter shape is reconciled."""
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "SKIPJACK non-ECB64 variants remain source-first" in doc
    assert "24-byte IV parameter text" in doc
    assert "SKIPJACK stream/wrap variants" not in doc


def test_gap_analysis_inventories_remaining_legacy_source_first_operations() -> None:
    """Remaining legacy/deprecated operation gaps are explicit and source-first."""
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "Current source-first operation inventory" in doc
    for token in (
        "CKM_CDMF_ECB",
        "CKM_CDMF_CBC",
        "CKM_CDMF_CBC_PAD",
        "CKM_CDMF_MAC",
        "CKM_CDMF_MAC_GENERAL",
        "CKM_SKIPJACK_CBC64",
        "CKM_SKIPJACK_OFB64",
        "CKM_SKIPJACK_CFB64",
        "CKM_SKIPJACK_CFB32",
        "CKM_SKIPJACK_CFB16",
        "CKM_SKIPJACK_CFB8",
        "CKM_SKIPJACK_WRAP",
        "CKM_SKIPJACK_PRIVATE_WRAP",
        "CKM_SKIPJACK_RELAYX",
        "CKM_BATON_ECB128",
        "CKM_BATON_ECB96",
        "CKM_BATON_CBC128",
        "CKM_BATON_COUNTER",
        "CKM_BATON_SHUFFLE",
        "CKM_BATON_WRAP",
        "CKM_JUNIPER_ECB128",
        "CKM_JUNIPER_CBC128",
        "CKM_JUNIPER_COUNTER",
        "CKM_JUNIPER_SHUFFLE",
        "CKM_JUNIPER_WRAP",
        "CKM_GOST28147_ECB",
        "CKM_GOST28147",
        "CKM_GOST28147_MAC",
        "CKM_GOST28147_KEY_WRAP",
        "CKM_TWOFISH_CBC_PAD",
    ):
        assert token in doc


def test_gap_analysis_marks_mixed_fail_crash_reporting_as_fixed() -> None:
    """Mixed fail+crash units now surface crash status instead of only failed status."""
    runner = _read("src/pkcs11_check/core/file_runner.py")
    tests = _read("tests/test_file_runner.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert 'for status in ("timeout", "crashed", "failed"' in runner
    assert "_status_with_detail_counts" in runner
    assert "test_write_isolated_json_report_crash_status_wins_over_failed_count" in tests
    assert (
        "test_write_isolated_json_report_special_detail_status_wins_over_failed_file_result"
        in tests
    )
    assert "the emitted artifact unit surfaces the special status" in doc_flat
    assert "Merged per-test detail counts also promote the emitted unit status" in doc_flat
    assert "Status: fixed in the current branch. `_overall_unit_status()` gives" in doc


def test_gap_analysis_records_bouncyhsm_provider_local_remeasurement() -> None:
    """BouncyHSM MCT speed work has provider-local remeasurement evidence."""
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "Fresh bouncyhsm provider-local pool evidence exists" in doc_flat
    assert "No mechanism coverage state loss" in doc_flat
    assert (
        "13 emitted units each for `test_ofb.py`, `test_cfb8.py`, and `test_cfb128.py`"
        in doc_flat
    )


def test_gap_analysis_records_wolfpkcs11_hkdf_remeasurement() -> None:
    """WolfPKCS11 HKDF subprocess-per-test expansion has fresh artifact evidence."""
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "wolfPKCS11 HKDF remeasurement evidence now exists" in doc_flat
    assert "roughly 241-252s" in doc_flat
    assert "the old roughly 5,403s file-level long pole is gone" in doc_flat


def test_gap_analysis_marks_compliance_note_persistence_as_end_to_end() -> None:
    """Compliance-note persistence has an isolated-subprocess regression test."""
    tests = _read("tests/test_file_runner.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "test_run_isolated_pytest_units_preserves_real_subprocess_compliance_notes" in tests
    assert "end-to-end isolated subprocess regression" in " ".join(doc.split())
