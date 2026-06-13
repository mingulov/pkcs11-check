"""Guardrails for stale status claims in the speed/coverage gap analysis."""

from __future__ import annotations

import re
from pathlib import Path

from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
from pkcs11_check.raw.types_std import (
    CKF_GENERATE,
    CKF_GENERATE_KEY_PAIR,
    CKM_ACTI,
    CKM_BATON_CBC128,
    CKM_BATON_COUNTER,
    CKM_BATON_ECB96,
    CKM_BATON_ECB128,
    CKM_BATON_SHUFFLE,
    CKM_BATON_WRAP,
    CKM_FASTHASH,
    CKM_FORTEZZA_TIMESTAMP,
    CKM_GOST28147,
    CKM_GOST28147_ECB,
    CKM_GOST28147_KEY_WRAP,
    CKM_GOST28147_MAC,
    CKM_HOTP,
    CKM_JUNIPER_CBC128,
    CKM_JUNIPER_COUNTER,
    CKM_JUNIPER_ECB128,
    CKM_JUNIPER_SHUFFLE,
    CKM_JUNIPER_WRAP,
    CKM_KEA_DERIVE,
    CKM_KEA_KEY_DERIVE,
    CKM_KEY_WRAP_LYNKS,
    CKM_KEY_WRAP_SET_OAEP,
    CKM_SECURID,
    CKM_SKIPJACK_CBC64,
    CKM_SKIPJACK_CFB8,
    CKM_SKIPJACK_CFB16,
    CKM_SKIPJACK_CFB32,
    CKM_SKIPJACK_CFB64,
    CKM_SKIPJACK_OFB64,
    CKM_SKIPJACK_PRIVATE_WRAP,
    CKM_SKIPJACK_RELAYX,
    CKM_SKIPJACK_WRAP,
)
from pkcs11_check.testcases.mechanism_registry import MECHANISM_REGISTRY

ROOT = Path(__file__).resolve().parents[1]
GAP_DOC = ROOT / "docs/findings/speed-coverage-correctness-gap-analysis-2026-06-11.md"
COVERAGE_GAPS_PLAN = ROOT / "docs/coverage-gaps-plan.md"


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _gap_inventory_rows(doc: str) -> dict[str, set[str]]:
    rows: dict[str, set[str]] = {}
    for line in doc.splitlines():
        match = re.fullmatch(r"\s*\|\s*([^|]+?)\s*\|\s*(.*?)\s*\|", line)
        if match is None:
            continue
        family, mechanisms = match.groups()
        if family in {"Family", "---"}:
            continue
        rows[family.strip()] = set(re.findall(r"`(CKM_[A-Z0-9_]+)`", mechanisms))
    return rows


_LEGACY_SOURCE_FIRST_NAME_TOKENS = (
    "ACTI",
    "BATON",
    "FASTHASH",
    "FORTEZZA",
    "GOST28147",
    "HOTP",
    "JUNIPER",
    "KEA",
    "KEY_WRAP_LYNKS",
    "KEY_WRAP_SET_OAEP",
    "SECURID",
    "SKIPJACK",
)

_DEDICATED_LEGACY_KAT_IDS = {
    int(CKM_GOST28147_ECB),
    int(CKM_GOST28147_KEY_WRAP),
    int(CKM_GOST28147_MAC),
}


def _source_first_legacy_operation_ids() -> set[int]:
    keygen_flags = int(CKF_GENERATE) | int(CKF_GENERATE_KEY_PAIR)
    result: set[int] = set()
    for mech_id, config in MECHANISM_REGISTRY.items():
        name = MECHANISM_NAMES.get(mech_id, "")
        if config.vector_file is not None:
            continue
        if mech_id in _DEDICATED_LEGACY_KAT_IDS:
            continue
        if not any(token in name for token in _LEGACY_SOURCE_FIRST_NAME_TOKENS):
            continue
        flags = int(config.expected_flags)
        if flags != 0 and flags & ~keygen_flags == 0:
            continue
        result.add(mech_id)
    return result


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
    assert "_derive_wtls_prf_output" in wtls
    assert "None, 0, None" in wtls
    assert 'buffer_bytes("output")' in wtls
    assert "test_base_key_affects_output" in ike
    assert 'REQUIRED_MECHANISMS = ["PKCS5_PBKD2"]' in pbkdf2
    assert "assert dk_actual == dk_expected" in pbkdf2

    assert "Protocol KDFs are intentionally skipped" not in doc
    assert "Dedicated protocol KDF semantic coverage exists" in doc
    assert "WTLS PRF seed-sensitivity coverage" in doc
    assert "WTLS PRF label-sensitivity coverage" in doc
    assert "WTLS PRF output-length coverage" in doc
    assert "WTLS PRF raw output-buffer coverage" in doc
    assert "WTLS key-and-MAC NULL phKey coverage" in doc
    assert "IKE2 PRF+ base-key sensitivity coverage" in doc


def test_gap_analysis_marks_wtls_prf_output_length_as_added() -> None:
    """CKM_WTLS_PRF output length controls the returned raw PRF bytes."""
    wtls = _read("src/pkcs11_check/testcases/test_wtls.py")
    guard = _read("tests/test_wtls_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_prf_output_len_extends_output" in wtls
    assert "output_len=32" in wtls
    assert "test_wtls_prf_output_length_probe_requests_prefix_extension" in guard
    assert "test_wtls_prf_output_length_fails_on_prefix_mismatch" in guard

    assert "WTLS PRF output-length coverage" in doc_flat


def test_gap_analysis_marks_wtls_key_material_null_phkey_as_added() -> None:
    """WTLS key-and-MAC derives follow the OASIS NULL phKey convention."""
    wtls = _read("src/pkcs11_check/testcases/test_wtls.py")
    guard = _read("tests/test_wtls_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "_derive_key_material_to_params" in wtls
    assert "test_wtls_server_key_and_mac_derive_uses_null_phkey" in guard
    assert "test_wtls_client_key_and_mac_derive_uses_null_phkey" in guard
    assert "test_wtls_server_client_differ_uses_param_key_handles" in guard

    assert "WTLS key-and-MAC NULL phKey coverage" in doc_flat


def test_gap_analysis_marks_wtls_prf_invalid_digest_negative_as_added() -> None:
    """CKM_WTLS_PRF rejects an invalid nested digest mechanism selector."""
    wtls = _read("src/pkcs11_check/testcases/test_wtls.py")
    guard = _read("tests/test_wtls_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_prf_rejects_invalid_digest_mechanism" in wtls
    assert "_WTLS_INVALID_DIGEST_REJECT_RVS" in wtls
    assert "CKM_VENDOR_DEFINED" in wtls
    assert "test_wtls_prf_invalid_digest_uses_negative_classifier" in guard

    assert "WTLS PRF invalid-digest negative coverage" in doc_flat


def test_gap_analysis_marks_wtls_derive_invalid_digest_negatives_as_added() -> None:
    """WTLS master/key-material derives reject invalid nested digest selectors."""
    wtls = _read("src/pkcs11_check/testcases/test_wtls.py")
    guard = _read("tests/test_wtls_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "_derive_wtls_master_key_invalid_digest" in wtls
    assert "_derive_wtls_key_material_invalid_digest" in wtls
    assert "test_rejects_invalid_digest_mechanism" in wtls
    assert "test_server_rejects_invalid_digest_mechanism" in wtls
    assert "test_client_rejects_invalid_digest_mechanism" in wtls
    assert "test_wtls_derive_invalid_digest_uses_negative_classifier" in guard

    assert "WTLS derive invalid-digest negative coverage" in doc_flat


def test_gap_analysis_marks_wtls_key_material_template_conflict_as_added() -> None:
    """WTLS key-material derives reject protection attributes that differ from the base key."""
    wtls = _read("src/pkcs11_check/testcases/test_wtls.py")
    guard = _read("tests/test_wtls_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "_derive_wtls_key_material_template_conflict" in wtls
    assert "test_server_rejects_template_protection_conflict" in wtls
    assert "test_client_rejects_template_protection_conflict" in wtls
    assert "_WTLS_TEMPLATE_CONFLICT_REJECT_RVS" in wtls
    assert "test_wtls_key_material_rejects_template_protection_conflict" in guard

    assert "WTLS key-material template-protection negative coverage" in doc_flat


def test_gap_analysis_marks_ike_prf_base_key_sensitivity_as_added() -> None:
    """CKM_IKE_PRF_DERIVE changes output when only the base key changes."""
    ike = _read("src/pkcs11_check/testcases/test_ike.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "test_prf_base_key_affects_output" in ike
    assert "IKE PRF base key change did not affect derived output" in ike

    assert "IKE PRF base-key sensitivity coverage" in doc


def test_gap_analysis_marks_ike_prf_exact_vector_as_added() -> None:
    """CKM_IKE_PRF_DERIVE has a typed-param HMAC-SHA256 exact vector."""
    ike = _read("src/pkcs11_check/testcases/test_ike.py")
    pack = _read("src/pkcs11_check/raw/pack_mechanisms.py")
    raw_pack_tests = _read("tests/test_raw_pack.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "mech_ike_prf_derive" in pack
    assert "CK_IKE_PRF_DERIVE_PARAMS" in pack
    assert "test_ike_prf_derive_packer_uses_typed_oasis_struct" in raw_pack_tests
    assert "test_data_as_key_hmac_sha256_exact_vector" in ike
    assert "_ike_prf_hmac_sha256_reference" in ike

    assert "IKE PRF data-as-key HMAC-SHA256 exact-vector coverage" in doc


def test_gap_analysis_marks_ike2_prf_plus_exact_vector_as_added() -> None:
    """CKM_IKE2_PRF_PLUS_DERIVE has a typed-param HMAC-SHA256 exact vector."""
    ike = _read("src/pkcs11_check/testcases/test_ike.py")
    pack = _read("src/pkcs11_check/raw/pack_mechanisms.py")
    raw_pack_tests = _read("tests/test_raw_pack.py")
    ref_tests = _read("tests/test_protocol_kdf_reference_vectors.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "mech_ike2_prf_plus_derive" in pack
    assert "CK_IKE2_PRF_PLUS_DERIVE_PARAMS" in pack
    assert "test_ike2_prf_plus_derive_packer_uses_typed_oasis_struct" in raw_pack_tests
    assert "test_prf_plus_hmac_sha256_exact_vector" in ike
    assert "test_prf_plus_hmac_sha256_multiblock_exact_vector" in ike
    assert "bits=384" in ike
    assert "_ike2_prf_plus_hmac_sha256_reference" in ike
    assert "test_ike2_prf_plus_hmac_sha256_multiblock_reference_vector" in ref_tests

    assert "IKE2 PRF+ HMAC-SHA256 exact-vector coverage" in doc
    assert "IKE2 PRF+ HMAC-SHA256 multiblock exact-vector coverage" in doc_flat


def test_gap_analysis_marks_ike1_exact_vectors_as_added() -> None:
    """IKEv1 PRF and Extended Derive have typed-param HMAC-SHA256 exact vectors."""
    ike = _read("src/pkcs11_check/testcases/test_ike.py")
    pack = _read("src/pkcs11_check/raw/pack_mechanisms.py")
    raw_pack_tests = _read("tests/test_raw_pack.py")
    ref_tests = _read("tests/test_protocol_kdf_reference_vectors.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "mech_ike1_prf_derive" in pack
    assert "CK_IKE1_PRF_DERIVE_PARAMS" in pack
    assert "mech_ike1_extended_derive" in pack
    assert "CK_IKE1_EXTENDED_DERIVE_PARAMS" in pack
    assert "test_ike1_prf_derive_packer_uses_typed_oasis_struct" in raw_pack_tests
    assert "test_ike1_extended_derive_packer_uses_typed_oasis_struct" in raw_pack_tests
    assert "test_prf_hmac_sha256_exact_vector" in ike
    assert "_ike1_prf_hmac_sha256_reference" in ike
    assert "test_extended_hmac_sha256_exact_vector" in ike
    assert "test_extended_hmac_sha256_multiblock_exact_vector" in ike
    assert "value_len=48" in ike
    assert "_ike1_extended_hmac_sha256_reference" in ike
    assert "test_ike1_extended_hmac_sha256_multiblock_reference_vector" in ref_tests

    assert "IKE1 PRF HMAC-SHA256 exact-vector coverage" in doc
    assert "IKE1 Extended Derive HMAC-SHA256 exact-vector coverage" in doc
    assert "IKE1 Extended Derive HMAC-SHA256 multiblock exact-vector coverage" in doc_flat


def test_gap_analysis_marks_ike_invalid_prf_negative_as_added() -> None:
    """IKE derives reject a nested prfMechanism that is not a MAC mechanism."""
    ike = _read("src/pkcs11_check/testcases/test_ike.py")
    guard = _read("tests/test_ike_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "_INVALID_PRF_REJECT_RVS" in ike
    assert "_INVALID_PRF_MECHANISM = int(CKM_AES_ECB)" in ike
    assert "test_rejects_invalid_prf_mechanism" in ike
    assert "IKE2 PRF+ invalid PRF mechanism" in ike
    assert "IKE PRF invalid PRF mechanism" in ike
    assert "IKE1 PRF invalid PRF mechanism" in ike
    assert "IKE1 extended invalid PRF mechanism" in ike
    assert "test_ike_invalid_prf_mechanism_uses_negative_classifier" in guard

    assert "IKE invalid-PRF negative coverage" in doc_flat


def test_gap_analysis_marks_tls_kdf_tls10_exact_vector_as_added() -> None:
    """CKM_TLS_KDF has an RFC 2246 TLS1.0/1.1 PRF exact vector."""
    tls = _read("src/pkcs11_check/testcases/test_tls12.py")
    guard = _read("tests/test_tls_key_material_derivation.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "_tls_prf_legacy_md5_sha1" in tls
    assert "test_tls_kdf_tls10_prf_exact_vector" in tls
    assert "CKM_TLS_PRF" in tls
    assert "test_tls10_prf_reference_matches_rfc2246_split_secret_vector" in guard
    assert "test_tls_kdf_tls10_exact_vector_uses_tls_prf_mechanism" in guard

    assert "TLS KDF TLS1.0/1.1 exact-vector coverage" in doc


def test_gap_analysis_marks_tls12_kdf_context_data_exact_vector_as_added() -> None:
    """CKM_TLS12_KDF exercises RFC 5705 context data in exact-vector coverage."""
    tls = _read("src/pkcs11_check/testcases/test_tls12.py")
    guard = _read("tests/test_tls_key_material_derivation.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_tls12_kdf_context_data_exact_vector" in tls
    assert "context_data=b\"context-info\"" in tls
    assert "test_tls12_kdf_context_data_exact_vector_uses_context_data" in guard
    assert "test_tls12_kdf_context_data_fails_on_wrong_exact_output" in guard

    assert "TLS 1.2 KDF context-data exact-vector coverage" in doc_flat


def test_gap_analysis_marks_tls_master_secret_exact_vector_as_added() -> None:
    """CKM_TLS_MASTER_KEY_DERIVE has an RFC 2246 PRF exact vector."""
    tls = _read("src/pkcs11_check/testcases/test_tls12.py")
    guard = _read("tests/test_tls_key_material_derivation.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "TLS 1.0/1.1 master secret output mismatch" in tls
    assert "test_tls_master_secret_reference_matches_rfc2246_prf_vector" in guard
    assert "test_tls_master_key_derive_fails_on_wrong_exact_output" in guard

    assert "TLS 1.0/1.1 master-secret exact-vector coverage" in doc_flat


def test_gap_analysis_marks_tls_prf_exact_vector_as_added() -> None:
    """CKM_TLS_PRF has an RFC 2246 exact-output check."""
    tls = _read("src/pkcs11_check/testcases/test_tls12.py")
    guard = _read("tests/test_tls_key_material_derivation.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "CKM_TLS_PRF output mismatch" in tls
    assert "test_tls_prf_fails_on_wrong_exact_output" in guard

    assert "TLS PRF exact-vector coverage" in doc_flat


def test_gap_analysis_marks_tls_key_material_null_phkey_as_added() -> None:
    """CKM_TLS_KEY_AND_MAC_DERIVE follows the OASIS NULL phKey convention."""
    tls = _read("src/pkcs11_check/testcases/test_tls12.py")
    guard = _read("tests/test_tls_key_material_derivation.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "def test_tls_key_and_mac_derive(" in tls
    assert "CKM_TLS_KEY_AND_MAC_DERIVE" in tls
    assert "test_tls_key_and_mac_derive_uses_null_phkey" in guard

    assert "Legacy TLS key-and-MAC NULL phKey coverage" in doc_flat


def test_gap_analysis_marks_tls_key_material_template_conflict_as_added() -> None:
    """TLS key-material derives reject protection attributes that differ from the base key."""
    tls = _read("src/pkcs11_check/testcases/test_tls12.py")
    guard = _read("tests/test_tls_key_material_derivation.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "_derive_tls_key_material_template_conflict" in tls
    assert "test_tls_key_and_mac_rejects_template_protection_conflict" in tls
    assert "test_key_and_mac_rejects_template_protection_conflict" in tls
    assert "test_key_safe_rejects_template_protection_conflict" in tls
    assert "_TLS_TEMPLATE_CONFLICT_REJECT_RVS" in tls
    assert "test_tls_key_material_rejects_template_protection_conflict" in guard

    assert "Legacy TLS/TLS 1.2 key-material template-protection negative coverage" in doc_flat


def test_gap_analysis_marks_tls12_key_safe_iv_suppression_as_added() -> None:
    """CKM_TLS12_KEY_SAFE_DERIVE ignores IV-size requests and returns no IV material."""
    tls = _read("src/pkcs11_check/testcases/test_tls12.py")
    guard = _read("tests/test_tls_key_material_derivation.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_key_safe_derive_ignores_iv_size_request" in tls
    assert "CKM_TLS12_KEY_SAFE_DERIVE wrote IV material" in tls
    assert "test_tls12_key_safe_derive_fails_if_iv_buffer_is_written" in guard

    assert "TLS 1.2 key-safe IV-suppression coverage" in doc_flat


def test_gap_analysis_marks_tls12_extended_master_secret_exact_vector_as_added() -> None:
    """TLS 1.2 extended master secret mechanisms have RFC 7627 PRF exact vectors."""
    tls = _read("src/pkcs11_check/testcases/test_tls12.py")
    guard = _read("tests/test_tls_key_material_derivation.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "_tls12_extended_master_secret_reference" in tls
    assert "extended master secret output mismatch" in tls
    assert "extended master secret DH output mismatch" in tls
    assert "test_tls12_extended_master_secret_reference_matches_rfc7627_prf_vector" in guard
    assert "test_tls12_extended_master_secret_dh_reference_matches_rfc7627_prf_vector" in guard
    assert "test_tls12_extended_master_key_derive_fails_on_wrong_exact_output" in guard
    assert "test_tls12_extended_master_key_derive_dh_fails_on_wrong_exact_output" in guard

    assert "TLS 1.2 extended-master-secret exact-vector coverage" in doc_flat
    assert "TLS 1.2 extended-master-secret DH exact-vector coverage" in doc_flat


def test_gap_analysis_marks_tls12_master_secret_exact_vector_as_added() -> None:
    """TLS 1.2 master secret mechanisms have PRF exact vectors."""
    tls = _read("src/pkcs11_check/testcases/test_tls12.py")
    guard = _read("tests/test_tls_key_material_derivation.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "TLS 1.2 master secret output mismatch" in tls
    assert "TLS 1.2 master secret DH output mismatch" in tls
    assert "test_tls12_master_secret_reference_matches_prf_vector" in guard
    assert "test_tls12_master_secret_dh_reference_matches_prf_vector" in guard
    assert "test_tls12_master_key_derive_fails_on_wrong_exact_output" in guard
    assert "test_tls12_master_key_derive_dh_fails_on_wrong_exact_output" in guard

    assert "TLS 1.2 master-secret exact-vector coverage" in doc_flat
    assert "TLS 1.2 master-secret DH exact-vector coverage" in doc_flat


def test_gap_analysis_marks_ssl3_master_secret_exact_vector_as_added() -> None:
    """CKM_SSL3_MASTER_KEY_DERIVE has an SSL3 master-secret exact vector."""
    ssl3 = _read("src/pkcs11_check/testcases/test_ssl3.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "_ssl3_master_secret_reference" in ssl3
    assert "test_derive_master_secret_exact_vector" in ssl3
    assert "assert raw_val == expected" in ssl3

    assert "SSL3 master-secret exact-vector coverage" in doc


def test_gap_analysis_marks_ssl3_key_material_null_phkey_as_added() -> None:
    """CKM_SSL3_KEY_AND_MAC_DERIVE follows the OASIS NULL phKey convention."""
    ssl3 = _read("src/pkcs11_check/testcases/test_ssl3.py")
    guard = _read("tests/test_ssl3_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "_derive_key_material_to_params" in ssl3
    assert "None," in ssl3
    assert "test_ssl3_key_and_mac_derive_uses_null_phkey" in guard

    assert "SSL3 key-and-MAC NULL phKey coverage" in doc_flat


def test_gap_analysis_marks_ssl3_key_material_template_conflict_as_added() -> None:
    """SSL3 key-material derives reject protection attributes that differ from the base key."""
    ssl3 = _read("src/pkcs11_check/testcases/test_ssl3.py")
    guard = _read("tests/test_ssl3_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "_derive_ssl3_key_material_template_conflict" in ssl3
    assert "test_rejects_template_protection_conflict" in ssl3
    assert "_SSL3_TEMPLATE_CONFLICT_REJECT_RVS" in ssl3
    assert "test_ssl3_key_material_rejects_template_protection_conflict" in guard

    assert "SSL3 key-material template-protection negative coverage" in doc_flat


def test_gap_analysis_marks_ssl3_dh_master_secret_exact_vector_as_added() -> None:
    """CKM_SSL3_MASTER_KEY_DERIVE_DH has an SSL3 master-secret exact vector."""
    ssl3 = _read("src/pkcs11_check/testcases/test_ssl3.py")
    guard = _read("tests/test_ssl3_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_derive_master_secret_dh_exact_vector" in ssl3
    assert "SSL3 master secret DH output mismatch" in ssl3
    assert "test_ssl3_master_key_derive_dh_fails_on_wrong_exact_output" in guard

    assert "SSL3 master-secret DH exact-vector coverage" in doc_flat


def test_gap_analysis_marks_x2ratchet_typed_param_coverage_as_added() -> None:
    """CKM_X2RATCHET derive probes use OASIS mechanism parameter structs."""
    ratchet = _read("src/pkcs11_check/testcases/test_double_ratchet.py")
    guard = _read("tests/test_double_ratchet_runtime_classification.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "CK_X2RATCHET_INITIALIZE_PARAMS" in ratchet
    assert "CK_X2RATCHET_RESPOND_PARAMS" in ratchet
    assert "_mech_x2ratchet_initialize" in ratchet
    assert "_mech_x2ratchet_respond" in ratchet
    assert "mech_param=mech_param" in ratchet
    assert "test_x2ratchet_initialize_runtime_calls_derive_with_params" in guard
    assert "test_x2ratchet_initialize_sensitivity_probe_uses_spec_params" in guard
    assert "test_x2ratchet_respond_x2ratchet_key_type_uses_spec_params" in guard
    assert "test_x2ratchet_initialize_rejects_invalid_curve" in ratchet
    assert "test_x2ratchet_respond_rejects_invalid_curve" in ratchet

    assert "X2RATCHET typed-parameter derive coverage" in doc
    assert "unparameterized `C_DeriveKey` calls" in doc
    assert "X2RATCHET invalid-curve negative coverage" in doc_flat


def test_gap_analysis_marks_x3dh_invalid_kdf_negative_as_added() -> None:
    """X3DH derive rejects KDF selectors outside the OASIS-defined table."""
    x3dh = _read("src/pkcs11_check/testcases/test_x3dh.py")
    guard = _read("tests/test_x3dh_runtime_coverage.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_x3dh_initialize_rejects_invalid_kdf" in x3dh
    assert "test_x3dh_respond_rejects_invalid_kdf" in x3dh
    assert "X3DH_INITIALIZE invalid KDF" in x3dh
    assert "X3DH_RESPOND invalid KDF" in x3dh
    assert "test_x3dh_initialize_invalid_kdf_is_expected_reject" in guard
    assert "test_x3dh_respond_invalid_kdf_is_expected_reject" in guard
    assert "test_x3dh_initialize_invalid_kdf_acceptance_fails" in guard

    assert "X3DH invalid-KDF negative coverage" in doc_flat


def test_gap_analysis_marks_x3dh_missing_prekey_signature_negative_as_added() -> None:
    """X3DH initiator rejects a missing required prekey signature pointer."""
    x3dh = _read("src/pkcs11_check/testcases/test_x3dh.py")
    guard = _read("tests/test_x3dh_runtime_coverage.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_x3dh_initialize_rejects_missing_prekey_signature" in x3dh
    assert "X3DH_INITIALIZE missing prekey signature" in x3dh
    assert "prekey_signature=None" in x3dh
    assert "test_x3dh_initialize_missing_prekey_signature_is_expected_reject" in guard

    assert "X3DH missing-prekey-signature negative coverage" in doc_flat


def test_gap_analysis_marks_x2ratchet_invalid_kdf_negative_as_added() -> None:
    """X2RATCHET derive rejects KDF selectors outside the OASIS-defined table."""
    ratchet = _read("src/pkcs11_check/testcases/test_double_ratchet.py")
    guard = _read("tests/test_double_ratchet_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_x2ratchet_initialize_rejects_invalid_kdf" in ratchet
    assert "test_x2ratchet_respond_rejects_invalid_kdf" in ratchet
    assert "X2RATCHET_INITIALIZE invalid KDF" in ratchet
    assert "X2RATCHET_RESPOND invalid KDF" in ratchet
    assert "test_x2ratchet_initialize_invalid_kdf_is_expected_reject" in guard
    assert "test_x2ratchet_respond_invalid_kdf_is_expected_reject" in guard
    assert "test_x2ratchet_initialize_invalid_kdf_acceptance_fails" in guard

    assert "X2RATCHET invalid-KDF negative coverage" in doc_flat


def test_gap_analysis_marks_x2ratchet_invalid_aead_negative_as_added() -> None:
    """X2RATCHET derive rejects nested mechanisms that are not AEAD ciphers."""
    ratchet = _read("src/pkcs11_check/testcases/test_double_ratchet.py")
    guard = _read("tests/test_double_ratchet_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_x2ratchet_initialize_rejects_invalid_aead" in ratchet
    assert "test_x2ratchet_respond_rejects_invalid_aead" in ratchet
    assert "X2RATCHET_INITIALIZE invalid AEAD" in ratchet
    assert "X2RATCHET_RESPOND invalid AEAD" in ratchet
    assert "test_x2ratchet_invalid_aead_is_expected_reject" in guard

    assert "X2RATCHET invalid-AEAD negative coverage" in doc_flat


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
    assert "test_blake2b_hmac_general_rejects_wrong_length_mac" in blake2
    assert "accepted wrong-length" in blake2

    assert "BLAKE2B HMAC_GENERAL tampered-MAC coverage" in doc_flat
    assert "BLAKE2B HMAC_GENERAL wrong-length MAC coverage" in doc_flat


def test_gap_analysis_marks_blake2b_hmac_wrong_length_mac_as_added() -> None:
    """BLAKE2B fixed-length HMAC rejects truncated and extended MACs."""
    blake2 = _read("src/pkcs11_check/testcases/test_blake2.py")
    guard = _read("tests/test_blake2_keyed_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_blake2b_hmac_rejects_wrong_length_mac" in blake2
    assert "_hmac_rejects_wrong_length_mac" in blake2
    assert "accepted wrong-length" in blake2
    assert "test_blake2b_hmac_wrong_length_mac_variants_are_rejected" in guard

    assert "BLAKE2B fixed-length HMAC wrong-length MAC coverage" in doc_flat


def test_gap_analysis_marks_blake2b_key_derive_default_template_as_added() -> None:
    """BLAKE2B KEY_DERIVE covers the no-key-type/no-length default template rule."""
    blake2 = _read("src/pkcs11_check/testcases/test_blake2.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_blake2b_key_derive_default_template_value" in blake2
    assert "_key_derive_default_template_value" in blake2
    assert "BLAKE2B KEY_DERIVE default-template coverage" in doc_flat


def test_gap_analysis_marks_blake2b_key_derive_length_only_template_as_added() -> None:
    """BLAKE2B KEY_DERIVE covers the no-key-type/with-length template rule."""
    blake2 = _read("src/pkcs11_check/testcases/test_blake2.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_blake2b_key_derive_length_only_template_value" in blake2
    assert "_key_derive_length_only_template_value" in blake2
    assert "BLAKE2B KEY_DERIVE length-only-template coverage" in doc_flat


def test_gap_analysis_marks_blake2b_key_derive_overlong_key_negative_as_added() -> None:
    """BLAKE2B KEY_DERIVE rejects requested keys longer than the digest output."""
    blake2 = _read("src/pkcs11_check/testcases/test_blake2.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_blake2b_key_derive_rejects_overlong_requested_key" in blake2
    assert "BLAKE2B_160_KEY_DERIVE overlong AES-256 output" in blake2
    assert "BLAKE2B KEY_DERIVE overlong-key negative coverage" in doc_flat


def test_gap_analysis_marks_blake2b_key_derive_variable_key_type_negative_as_added() -> None:
    """BLAKE2B KEY_DERIVE rejects variable-length key types without CKA_VALUE_LEN."""
    blake2 = _read("src/pkcs11_check/testcases/test_blake2.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_blake2b_key_derive_rejects_aes_without_value_len" in blake2
    assert "BLAKE2B_256_KEY_DERIVE AES without CKA_VALUE_LEN" in blake2
    assert "BLAKE2B KEY_DERIVE variable-key-type negative coverage" in doc_flat


def test_gap_analysis_marks_blake2b_key_derive_length_only_overlong_as_added() -> None:
    """BLAKE2B KEY_DERIVE rejects length-only generic secrets past digest length."""
    blake2 = _read("src/pkcs11_check/testcases/test_blake2.py")
    guard = _read("tests/test_blake2_keyed_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_blake2b_key_derive_rejects_length_only_overlong" in blake2
    assert (
        "def test_blake2b_key_derive_rejects_length_only_overlong(\n"
        "        self,\n"
        "        p11_raw_session: Any,\n"
        "        case: _Blake2bKeyedCase,"
        in blake2
    )
    assert "BLAKE2B_*_KEY_DERIVE length-only overlong outputs are rejected" in blake2
    assert "test_blake2b_key_derive_length_only_overlong_is_expected_reject" in guard

    assert (
        "BLAKE2B KEY_DERIVE length-only overlong negative coverage now verifies every"
        in doc_flat
    )


def test_gap_analysis_marks_blake2b_key_derive_length_only_zero_as_added() -> None:
    """BLAKE2B KEY_DERIVE rejects length-only generic secrets at zero length."""
    blake2 = _read("src/pkcs11_check/testcases/test_blake2.py")
    guard = _read("tests/test_blake2_keyed_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_blake2b_key_derive_rejects_length_only_zero" in blake2
    assert "BLAKE2B_*_KEY_DERIVE length-only zero-length outputs are rejected" in blake2
    assert "test_blake2b_key_derive_length_only_zero_is_expected_reject" in guard
    assert "CKA_VALUE_LEN: 0" in guard

    assert (
        "BLAKE2B KEY_DERIVE length-only zero-length negative coverage now verifies every"
        in doc_flat
    )


def test_gap_analysis_marks_blake2b_key_derive_value_injection_as_added() -> None:
    """BLAKE2B KEY_DERIVE rejects caller-supplied derived-key bytes."""
    blake2 = _read("src/pkcs11_check/testcases/test_blake2.py")
    guard = _read("tests/test_blake2_keyed_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_blake2b_key_derive_rejects_value_injection" in blake2
    assert "_key_derive_rejects_value_injection" in blake2
    assert "_BLAKE2B_VALUE_INJECTION_REJECT_RVS" in blake2
    assert "accepted caller-supplied CKA_VALUE" in blake2
    assert "ignored caller-supplied CKA_VALUE" in blake2
    assert "test_blake2b_key_derive_value_injection_is_expected_reject" in guard
    assert "test_blake2b_key_derive_value_injection_accepts_injected_value_fails" in guard

    assert "BLAKE2B KEY_DERIVE CKA_VALUE-injection negative coverage" in doc_flat


def test_gap_analysis_marks_shake_xof_and_external_mu_as_dedicated_coverage() -> None:
    """SHAKE/XOF and ML-DSA ExternalMu are no longer registry/smoke only."""
    extended = _read("src/pkcs11_check/testcases/test_extended_mechanisms.py")
    acvp_hash = _read("src/pkcs11_check/testcases/acvp/test_acvp_hash.py")
    shake_guard = _read("tests/test_shake_xof_coverage.py")
    external_mu_guard = _read("tests/test_mldsa_external_mu_coverage.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "C_DigestXofInit" in extended
    assert "C_DigestXofExtract" in extended
    assert "_shake_xof_single_shot_matches_reference" in extended
    assert "_shake_xof_multipart_matches_reference" in extended
    assert '"SHAKE-128-1.0"' in acvp_hash
    assert '"SHAKE-256-1.0"' in acvp_hash
    assert "_run_acvp_shake_vector" in acvp_hash
    assert "SHAKE requires C_DigestXof (not yet in pkcs11_check.raw)" not in acvp_hash
    assert "hashlib.shake_128" in shake_guard
    assert "hashlib.shake_256" in shake_guard
    assert "_external_mu_sign_verify_roundtrip" in extended
    assert "CKM_ML_DSA_EXTERNAL_MU verify rejected a fresh signature" in extended
    assert "CKM_ML_DSA_EXTERNAL_MU verified a tampered mu" in extended
    assert "test_external_mu_roundtrip_helper_uses_64_byte_mu" in external_mu_guard

    assert "SHAKE/XOF and ML-DSA ExternalMu are registry/smoke only" not in doc_flat
    assert "SHAKE/XOF dedicated coverage exists" in doc_flat
    assert "ACVP SHAKE vector replay" in doc_flat
    assert "ML-DSA ExternalMu sign/verify coverage exists" in doc_flat


def test_gap_analysis_marks_kmac_parameter_packing_as_added() -> None:
    """KMAC tests no longer block on a missing CK_KMAC_PARAMS raw binding."""
    extended = _read("src/pkcs11_check/testcases/test_extended_mechanisms.py")
    pack = _read("src/pkcs11_check/raw/pack_mechanisms.py")
    raw_types = _read("src/pkcs11_check/raw/types_std.py")
    raw_pack_tests = _read("tests/test_raw_pack.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "class CK_KMAC_PARAMS" in raw_types
    assert "CK_KMAC_PARAMS._fields_" in raw_types
    assert "def mech_kmac" in pack
    assert "test_mech_kmac_packs_key_handle_mac_length_and_customization" in raw_pack_tests
    assert "requires CK_KMAC_PARAMS mechanism parameter" not in extended

    assert "KMAC parameter packing coverage exists" in doc_flat
    assert "KMAC parameterized signing" in doc_flat


def test_gap_analysis_marks_message_api_registry_init_coverage_as_added() -> None:
    """Message API init coverage is driven from advertised CKF_MESSAGE_* flags."""
    message = _read("src/pkcs11_check/testcases/test_mech_message.py")
    plugin = _read("src/pkcs11_check/plugin.py")
    guard = _read("tests/test_message_registry_coverage.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "TestRegistryMessageInit" in message
    assert "TestRegistryMessageWrongKeyType" in message
    assert "TestRegistryMessageBadParameters" in message
    assert "_message_init_or_xfail" in message
    assert "_message_init_mech_or_skip" in message
    assert "_message_wrong_key_init_must_reject" in message
    assert "_message_bad_param_init_must_reject" in message
    for fixture_name, flag_name in (
        ("mech_message_encrypt_entry", "CKF_MESSAGE_ENCRYPT"),
        ("mech_message_decrypt_entry", "CKF_MESSAGE_DECRYPT"),
        ("mech_message_sign_entry", "CKF_MESSAGE_SIGN"),
        ("mech_message_verify_entry", "CKF_MESSAGE_VERIFY"),
    ):
        assert fixture_name in message
        assert fixture_name in plugin
        assert fixture_name in guard
        assert flag_name in plugin
        assert flag_name in guard

    assert "Message API coverage is representative, not registry-driven" not in doc_flat
    assert "Message API registry-driven init coverage exists" in doc_flat
    assert "Registry-driven message API wrong-key-type coverage exists" in doc_flat
    assert "Registry-driven message API permission negative coverage exists" in doc_flat
    assert "Registry-driven message API required-parameter coverage exists" in doc_flat


def test_gap_analysis_marks_cms_and_ct_kip_runtime_coverage_as_added() -> None:
    """CMS and CT-KIP have parameterized runtime coverage, not only info checks."""
    cms = _read("src/pkcs11_check/testcases/test_cms.py")
    cms_guard = _read("tests/test_cms_runtime_coverage.py")
    otp = _read("src/pkcs11_check/testcases/test_otp.py")
    ct_kip_guard = _read("tests/test_ct_kip_runtime_coverage.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_cms_sig_signs_with_params" in cms
    assert "CK_CMS_SIG_PARAMS" in cms
    assert "CKM_CMS_SIG requires a CK_CMS_SIG_PARAMS structure" in cms
    assert "test_cms_runtime_calls_sign_with_params" in cms_guard

    assert "TestCTKIP" in otp
    assert "_mech_kip" in otp
    assert "CK_KIP_PARAMS" in otp
    assert "test_kip_derive_derives_generic_secret" in otp
    assert "test_kip_wrap_wraps_generic_secret" in otp
    assert "test_kip_mac_signs_and_verifies" in otp
    assert "test_kip_derive_runtime_calls_derive_with_params" in ct_kip_guard

    assert "CMS and CT-KIP are shallow" not in doc_flat
    assert "CMS runtime parameter coverage exists" in doc_flat
    assert "CT-KIP runtime coverage exists" in doc_flat


def test_gap_analysis_marks_registry_negative_roundtrip_halves_as_added() -> None:
    """Registry-driven negative coverage includes both halves of operation pairs."""
    negative = _read("src/pkcs11_check/testcases/test_mech_negative.py")
    guard = _read("tests/test_mech_negative_registry_coverage.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    for test_name in (
        "test_registry_decrypt_wrong_key_type",
        "test_registry_derive_wrong_key_type",
        "test_registry_verify_wrong_key_type",
        "test_registry_wrap_wrong_key_type",
        "test_registry_unwrap_wrong_key_type",
        "test_registry_decrypt_without_flag",
        "test_registry_verify_without_flag",
        "test_registry_wrap_without_flag",
        "test_registry_unwrap_without_flag",
        "test_registry_derive_without_flag",
    ):
        assert test_name in negative
        assert test_name in guard

    assert "Registry-driven decrypt/verify negative coverage exists" in doc_flat
    assert "Registry-driven wrap/unwrap/derive wrong-key-type coverage exists" in doc_flat
    assert "Registry-driven wrap/unwrap missing-permission coverage exists" in doc_flat
    assert "Registry-driven derive missing-permission coverage exists" in doc_flat
    assert "Registry-driven missing-required-parameter coverage exists" in doc_flat


def test_gap_analysis_marks_derived_linked_attribute_invariants_as_added() -> None:
    """Derived linked-attribute invariant contradictions have Type-D coverage."""
    invariants = _read("src/pkcs11_check/testcases/test_attribute_invariants.py")
    guard = _read("tests/test_attribute_invariants_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "TestDerivedAttributeInvariants" in invariants
    assert "test_never_extractable_when_created_non_extractable" in invariants
    assert "test_always_sensitive_when_created_sensitive" in invariants
    assert "test_generated_aes_key_reports_local_key_gen_mechanism" in invariants
    assert "test_imported_aes_key_reports_not_local_no_key_gen_mechanism" in invariants
    assert "CKA_NEVER_EXTRACTABLE on a key created EXTRACTABLE=False" in invariants
    assert "CKA_ALWAYS_SENSITIVE on a key created SENSITIVE=True" in invariants
    assert "CKA_LOCAL/CKA_KEY_GEN_MECHANISM" in invariants
    assert "linked-origin self-contradiction" in invariants
    assert "self-contradiction" in invariants

    assert "test_never_extractable_contradiction_fails" in guard
    assert "test_always_sensitive_contradiction_fails" in guard
    assert "test_generated_aes_origin_wrong_mechanism_fails" in guard
    assert "test_imported_aes_origin_readable_mechanism_fails" in guard
    assert "test_never_extractable_absent_xfails" in guard
    assert "test_always_sensitive_absent_xfails" in guard
    assert "test_generated_aes_origin_missing_local_xfails" in guard
    assert "test_generated_aes_origin_missing_mechanism_xfails" in guard
    assert "test_imported_aes_origin_unsupported_mechanism_xfails" in guard

    assert "Derived linked-attribute invariant coverage exists" in doc_flat
    assert "Generated-key origin linked-attribute coverage exists" in doc_flat
    assert "Imported-key origin linked-attribute coverage exists" in doc_flat
    assert "Remaining work is linked-attribute self-contradiction expansion" not in doc_flat


def test_gap_analysis_marks_malformed_param_negatives_as_added() -> None:
    """Registry-driven bad-parameter coverage includes non-NULL malformed params."""
    negative = _read("src/pkcs11_check/testcases/test_mech_negative.py")
    guard = _read("tests/test_mech_negative_registry_coverage.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_registry_encrypt_malformed_required_param" in negative
    assert "test_registry_decrypt_missing_required_param" in negative
    assert "test_registry_decrypt_malformed_required_param" in negative
    assert "test_registry_sign_malformed_required_param" in negative
    assert "test_registry_verify_missing_required_param" in negative
    assert "test_registry_verify_malformed_required_param" in negative
    assert "test_registry_wrap_missing_required_param" in negative
    assert "test_registry_wrap_malformed_required_param" in negative
    assert "test_registry_unwrap_missing_required_param" in negative
    assert "test_registry_unwrap_malformed_required_param" in negative
    assert "test_registry_digest_missing_required_param" in negative
    assert "test_registry_digest_malformed_required_param" in negative
    assert "test_registry_derive_missing_required_param" in negative
    assert "test_registry_derive_malformed_required_param" in negative
    assert "_MISSING_REQUIRED_PARAM_RVS" in negative
    assert "_MALFORMED_REQUIRED_PARAM_RVS" in negative
    assert "CKR_ARGUMENTS_BAD" in negative
    assert 'mech_bytes(entry.mech_id, b"\\x00")' in negative

    assert "test_registry_encrypt_malformed_required_param" in guard
    assert "test_registry_decrypt_malformed_required_param" in guard
    assert "test_registry_sign_malformed_required_param" in guard
    assert "test_registry_verify_malformed_required_param" in guard
    assert "test_registry_wrap_missing_required_param" in guard
    assert "test_registry_wrap_malformed_required_param" in guard
    assert "test_registry_unwrap_missing_required_param" in guard
    assert "test_registry_unwrap_malformed_required_param" in guard
    assert "test_registry_digest_malformed_required_param" in guard
    assert "test_registry_derive_missing_required_param" in guard
    assert "test_registry_derive_malformed_required_param" in guard

    assert "Registry-driven malformed non-NULL parameter coverage exists" in doc_flat
    assert "Registry-driven decrypt/verify required-parameter coverage exists" in doc_flat
    assert "Registry-driven wrap/unwrap required-parameter coverage exists" in doc_flat
    assert "Registry-driven wrap/unwrap malformed-parameter coverage exists" in doc_flat
    assert "Registry-driven digest required-parameter coverage exists" in doc_flat
    assert "Registry-driven derive required-parameter coverage exists" in doc_flat
    assert "Registry-driven derive malformed-parameter coverage exists" in doc_flat
    assert (
        "Remaining work is broader linked-attribute families, malformed non-NULL parameter coverage"
        not in doc_flat
    )


def test_gap_analysis_marks_unwrap_shape_negative_as_added() -> None:
    """Registry-driven unwrap coverage rejects malformed wrapped-key blobs."""
    negative = _read("src/pkcs11_check/testcases/test_mech_negative.py")
    guard = _read("tests/test_mech_negative_registry_coverage.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_registry_unwrap_rejects_truncated_blob" in negative
    assert "test_registry_unwrap_rejects_empty_blob" in negative
    assert "test_registry_unwrap_rejects_one_byte_blob" in negative
    assert "_MALFORMED_WRAPPED_BLOB_RVS" in negative
    assert "CKR_WRAPPED_KEY_LEN_RANGE" in negative
    assert "CKR_WRAPPED_KEY_INVALID" in negative
    assert "test_unwrap_shape_negatives_are_registry_driven" in guard
    assert "test_registry_unwrap_rejects_empty_blob" in guard
    assert "test_registry_unwrap_rejects_one_byte_blob" in guard

    assert "Registry-driven unwrap malformed-blob coverage exists" in doc_flat
    assert "Registry-driven unwrap empty-blob coverage exists" in doc_flat
    assert "Registry-driven unwrap one-byte-blob coverage exists" in doc_flat
    assert "deeper unwrap shape/error cases" not in doc_flat


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


def test_gap_analysis_marks_raw_dsa_wrong_length_verify_negative_as_added() -> None:
    """Raw DSA verification rejects wrong-length digest inputs."""
    dsa = _read("src/pkcs11_check/testcases/test_dsa_complete.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "test_raw_dsa_wrong_length_verify_digest" in dsa
    assert "CKM_DSA wrong-length verify digest" in dsa
    assert "classify_negative_rv(" in dsa

    assert "Raw CKM_DSA wrong-length verify-digest coverage" in doc_flat


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
    assert "test_raw_dsa_overlong_signature_length_fails" in dsa
    assert "CKM_DSA wrong-length signature" in dsa
    assert "CKM_DSA overlong signature" in dsa
    assert "_dsa_invalid_verify_rejected_or_xfail" in dsa

    assert "Raw CKM_DSA wrong-signature-length coverage" in doc_flat
    assert "Raw CKM_DSA overlong-signature-length coverage" in doc_flat


def test_gap_analysis_marks_dsa_prehash_wrong_signature_length_negative_as_added() -> None:
    """DSA-with-hash verification rejects wrong-length signatures."""
    dsa = _read("src/pkcs11_check/testcases/test_dsa_complete.py")
    runtime = _read("tests/test_dsa_complete_runtime_classification.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "test_wrong_signature_lengths_fail" in dsa
    assert "_wrong_signature_lengths_fail" in dsa
    assert "CKM_{mech_name_str} wrong-length signature" in dsa
    assert "CKM_{mech_name_str} overlong signature" in dsa
    assert "_dsa_invalid_verify_rejected_or_xfail" in dsa
    assert "test_dsa_prehash_wrong_signature_lengths_use_reject_policy" in runtime

    assert "DSA prehash wrong-signature-length coverage" in doc_flat
    assert "DSA prehash overlong-signature-length coverage" in doc_flat


def test_gap_analysis_marks_dsa_sha224_sha256_prehash_matrix_as_added() -> None:
    """DSA_SHA224 and DSA_SHA256 are in the complete DSA prehash matrix."""
    dsa = _read("src/pkcs11_check/testcases/test_dsa_complete.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert 'pytest.param("DSA_SHA224"' in dsa
    assert 'pytest.param("DSA_SHA256"' in dsa
    assert "SHA-224" in dsa
    assert "SHA-256" in dsa

    assert "DSA_SHA224 and DSA_SHA256 now participate" in doc


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
    doc_flat = " ".join(doc.split())

    assert "Remaining evidence: run targeted wolfPKCS11 X.509/CCTV batches" not in doc
    assert (
        "Status: fixed in the current branch. - Implemented: reusable module-session "
        "health checks"
    ) in doc_flat
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


def test_gap_analysis_marks_dh_malformed_peer_public_negative_as_added() -> None:
    """Classic DH derive rejects malformed peer public data."""
    dh = _read("src/pkcs11_check/testcases/test_dh_key_agreement.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "test_dh_derive_rejects_malformed_peer_public_value" in dh
    assert "CKM_DH_PKCS_DERIVE malformed peer public value" in dh
    assert "CKR_DOMAIN_PARAMS_INVALID" in dh

    assert "Classic DH malformed-peer-public negative coverage" in doc_flat


def test_gap_analysis_marks_classic_dh_exact_vector_as_added() -> None:
    """Classic DH derive checks a deterministic RFC 3526 Group 14 exact vector."""
    dh = _read("src/pkcs11_check/testcases/test_dh_key_agreement.py")
    guard = _read("tests/test_dh_key_agreement_runtime_classification.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "test_dh_pkcs_derive_rfc3526_group14_exact_vector" in dh
    assert "test_dh_pkcs_derive_rfc3526_group14_value_len_truncation" in dh
    assert "test_dh_rfc3526_group14_value_len_truncation_uses_rightmost_bytes" in guard
    assert "_DH_RFC3526_GROUP14_EXPECTED_SECRET_32" in dh
    assert "Classic DH RFC 3526 Group 14 exact-vector coverage" in doc_flat
    assert "Classic DH RFC 3526 Group 14 requested-value-length truncation" in doc_flat


def test_gap_analysis_marks_dh_x942_zero_value_len_negatives_as_added() -> None:
    """DH and X9.42 exact-vector derives reject zero requested output length."""
    dh = _read("src/pkcs11_check/testcases/test_dh_key_agreement.py")
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    dh_guard = _read("tests/test_dh_key_agreement_runtime_classification.py")
    x942_guard = _read("tests/test_x942_dh_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_dh_pkcs_derive_rfc3526_group14_rejects_zero_value_len" in dh
    assert "test_dh_rfc3526_group14_zero_value_len_is_expected_reject" in dh_guard
    assert "test_x942_dh_derive_rfc5114_rejects_zero_value_len" in x942
    assert "test_x942_rfc5114_zero_value_len_is_expected_reject" in x942_guard
    assert "CKA_VALUE_LEN: 0" in dh_guard
    assert "CKA_VALUE_LEN: 0" in x942_guard

    assert "Classic DH RFC 3526 Group 14 zero-length request coverage" in doc_flat
    assert "X9.42 DH RFC 5114 zero-length request coverage" in doc_flat


def test_gap_analysis_marks_x942_missing_peer_public_negative_as_added() -> None:
    """X9.42 DH derive has a negative test for missing peer public data."""
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "test_x942_derive_rejects_missing_peer_public_value" in x942
    assert "CKM_X9_42_DH_DERIVE missing peer public value" in x942
    assert "classify_negative_rv(" in x942

    assert "X9.42 DH missing-peer-public negative coverage" in doc_flat


def test_gap_analysis_marks_x942_malformed_peer_public_negative_as_added() -> None:
    """X9.42 DH derive rejects malformed peer public data."""
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "test_x942_derive_rejects_malformed_peer_public_value" in x942
    assert "CKM_X9_42_DH_DERIVE malformed peer public value" in x942
    assert "CKR_DOMAIN_PARAMS_INVALID" in x942

    assert "X9.42 DH malformed-peer-public negative coverage" in doc_flat


def test_gap_analysis_marks_x942_ckd_null_other_info_negative_as_added() -> None:
    """X9.42 DH CKD_NULL derive rejects non-empty OtherInfo."""
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "test_x942_derive_rejects_ckd_null_other_info" in x942
    assert "CKM_X9_42_DH_DERIVE CKD_NULL with OtherInfo" in x942
    assert "other_info" in x942

    assert "X9.42 DH CKD_NULL OtherInfo negative coverage" in doc_flat


def test_gap_analysis_marks_x942_asn1_kdf_missing_other_info_negative_as_added() -> None:
    """X9.42 DH CKD_SHA1_KDF_ASN1 derive rejects missing OtherInfo."""
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "CKD_SHA1_KDF_ASN1" in x942
    assert "test_x942_derive_rejects_asn1_kdf_missing_other_info" in x942
    assert "CKM_X9_42_DH_DERIVE CKD_SHA1_KDF_ASN1 missing OtherInfo" in x942

    assert "X9.42 DH CKD_SHA1_KDF_ASN1 missing-OtherInfo coverage" in doc_flat


def test_gap_analysis_marks_x942_invalid_kdf_negatives_as_added() -> None:
    """X9.42 DH, hybrid, and MQV derive reject an invalid KDF selector."""
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    guard = _read("tests/test_x942_dh_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "_X942_INVALID_KDF" in x942
    assert "test_x942_derive_rejects_invalid_kdf" in x942
    assert "test_hybrid_derive_rejects_invalid_kdf" in x942
    assert "test_mqv_derive_rejects_invalid_kdf" in x942
    assert "test_x942_extended_invalid_kdf_negative_uses_typed_params" in guard

    assert "X9.42 DH invalid-KDF negative coverage" in doc_flat
    assert "X9.42 hybrid/MQV invalid-KDF negative coverage" in doc_flat


def test_gap_analysis_marks_x942_exact_vector_as_added() -> None:
    """X9.42 DH derive checks a deterministic RFC 5114 exact vector."""
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "test_x942_dh_derive_rfc5114_exact_vector" in x942
    assert "_X942_RFC5114_EXPECTED_SECRET_32" in x942
    assert "X9.42 DH RFC 5114 exact-vector coverage" in doc_flat


def test_gap_analysis_marks_x942_value_len_truncation_as_added() -> None:
    """X9.42 DH CKD_NULL derive checks OASIS leading-byte truncation semantics."""
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_x942_dh_derive_rfc5114_value_len_truncation" in x942
    assert "X9.42 DH CKA_VALUE_LEN=16 must keep the rightmost bytes" in x942

    assert "X9.42 DH requested-value-length truncation coverage" in doc_flat


def test_gap_analysis_marks_x942_concatenate_other_info_as_added() -> None:
    """X9.42 DH CKD_SHA1_KDF_CONCATENATE carries optional OtherInfo."""
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    guard = _read("tests/test_x942_dh_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "CKD_SHA1_KDF_CONCATENATE" in x942
    assert "test_x942_dh_derive_concatenate_other_info" in x942
    assert "CKM_X9_42_DH_DERIVE CKD_SHA1_KDF_CONCATENATE with OtherInfo" in x942
    assert "test_x942_concatenate_kdf_other_info_uses_typed_params" in guard

    assert "X9.42 DH CKD_SHA1_KDF_CONCATENATE OtherInfo coverage" in doc_flat


def test_gap_analysis_marks_x942_asn1_other_info_as_added() -> None:
    """X9.42 DH CKD_SHA1_KDF_ASN1 carries supplied DER OtherInfo."""
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    guard = _read("tests/test_x942_dh_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_x942_dh_derive_asn1_other_info" in x942
    assert "CKM_X9_42_DH_DERIVE CKD_SHA1_KDF_ASN1 with DER OtherInfo" in x942
    assert "test_x942_asn1_kdf_other_info_uses_typed_params" in guard

    assert "X9.42 DH CKD_SHA1_KDF_ASN1 DER OtherInfo coverage" in doc_flat


def test_gap_analysis_marks_x942_hybrid_mqv_derive_as_exercised() -> None:
    """X9.42 hybrid/MQV derive coverage reaches typed C_DeriveKey calls."""
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    guard = _read("tests/test_x942_dh_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "CK_X9_42_DH2_DERIVE_PARAMS" in x942
    assert "CK_X9_42_MQV_DERIVE_PARAMS" in x942
    assert "test_hybrid_derive_matches_between_parties" in x942
    assert "test_mqv_derive_matches_between_parties" in x942
    assert "test_hybrid_derive_value_len_truncation" in x942
    assert "test_mqv_derive_value_len_truncation" in x942
    assert "_build_x942_dh2_derive_mech" in x942
    assert "_build_x942_mqv_derive_mech" in x942
    assert "test_x942_extended_derive_value_len_truncation_uses_rightmost_bytes" in guard

    assert "X9.42 hybrid/MQV typed derive coverage" in doc_flat
    assert "X9.42 hybrid/MQV requested-value-length truncation coverage" in doc_flat


def test_gap_analysis_marks_x942_hybrid_mqv_concatenate_other_info_as_added() -> None:
    """X9.42 hybrid/MQV derive carries optional OtherInfo for concatenate KDF."""
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    guard = _read("tests/test_x942_dh_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_hybrid_derive_concatenate_other_info" in x942
    assert "test_mqv_derive_concatenate_other_info" in x942
    assert "CKD_SHA1_KDF_CONCATENATE" in x942
    assert "test_x942_extended_concatenate_kdf_other_info_uses_typed_params" in guard

    assert "X9.42 hybrid/MQV CKD_SHA1_KDF_CONCATENATE OtherInfo coverage" in doc_flat


def test_gap_analysis_marks_x942_hybrid_mqv_asn1_other_info_as_added() -> None:
    """X9.42 hybrid/MQV derive carries supplied DER OtherInfo for ASN.1 KDF."""
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    guard = _read("tests/test_x942_dh_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_hybrid_derive_asn1_other_info" in x942
    assert "test_mqv_derive_asn1_other_info" in x942
    assert "CKD_SHA1_KDF_ASN1" in x942
    assert "test_x942_extended_asn1_kdf_other_info_uses_typed_params" in guard

    assert "X9.42 hybrid/MQV CKD_SHA1_KDF_ASN1 DER OtherInfo coverage" in doc_flat


def test_gap_analysis_marks_x942_hybrid_mqv_other_info_negative_rules_as_added() -> None:
    """X9.42 hybrid/MQV derive rejects invalid OtherInfo/KDF combinations."""
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    guard = _read("tests/test_x942_dh_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_hybrid_derive_rejects_ckd_null_other_info" in x942
    assert "test_hybrid_derive_rejects_asn1_kdf_missing_other_info" in x942
    assert "test_mqv_derive_rejects_ckd_null_other_info" in x942
    assert "test_mqv_derive_rejects_asn1_kdf_missing_other_info" in x942
    assert "test_x942_extended_other_info_negative_rules_use_typed_params" in guard

    assert "X9.42 hybrid/MQV OtherInfo negative coverage" in doc_flat


def test_gap_analysis_marks_x942_hybrid_mqv_malformed_peer_negative_as_added() -> None:
    """X9.42 hybrid/MQV derive rejects malformed peer public values."""
    x942 = _read("src/pkcs11_check/testcases/test_x942_dh.py")
    guard = _read("tests/test_x942_dh_runtime_classification.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "test_hybrid_derive_rejects_malformed_peer_public_value" in x942
    assert "test_mqv_derive_rejects_malformed_peer_public_value" in x942
    assert "test_x942_extended_malformed_peer_public_negative_uses_typed_params" in guard

    assert "X9.42 hybrid/MQV malformed-peer-public negative coverage" in doc_flat


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


def test_gap_analysis_marks_chacha20_poly1305_wrap_as_source_first() -> None:
    """ChaCha20-Poly1305 is not treated as generic C_WrapKey coverage."""
    registry = _read("src/pkcs11_check/testcases/mechanism_registry/_ciphers.py")
    wrap = _read("src/pkcs11_check/testcases/test_mech_wrap.py")
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    start = registry.index("registry[CKM_CHACHA20_POLY1305]")
    end = registry.index("registry[CKM_SALSA20_KEY_GEN]")
    chacha_config = registry[start:end]

    assert "expected_flags=_ENC_DEC" in chacha_config
    assert "CKF_WRAP" not in chacha_config
    assert "ChaCha20-Poly1305 wrap parameter semantics" in wrap

    assert "ChaCha20-Poly1305 generic wrap remains source-first" in doc_flat
    assert "Remaining ChaCha20-Poly1305 wrap parameter expansion" not in doc_flat
    assert "Remaining ChaCha20-Poly1305 wrap params" not in doc_flat


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


def test_gap_analysis_marks_cast_pbe_semantic_cases_as_added() -> None:
    """Historical CAST-family PBE mechanisms are in the semantic PBE case table."""
    pbe = _read("src/pkcs11_check/testcases/test_pbe.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    for token in (
        "CKM_PBE_MD5_CAST_CBC",
        "CKM_PBE_MD5_CAST3_CBC",
        "CKM_PBE_MD5_CAST128_CBC",
        "CKM_PBE_SHA1_CAST128_CBC",
    ):
        assert token in pbe

    assert "historical CAST/CAST3/CAST128 PBE mechanisms" in doc


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
    """GOST28147 has a registry IV recipe but non-ECB KATs remain pending."""
    legacy_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_legacy.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "registry[CKM_GOST28147]" in legacy_registry
    assert "param_recipe=_iv8" in legacy_registry
    assert "CKM_GOST28147 IV-parameter registry coverage" in doc
    assert "GOST28147 non-ECB exact-output KATs remain source-first" in doc_flat
    assert "BATON/JUNIPER and GOST28147 exact-output KATs" not in doc_flat


def test_gap_analysis_marks_gost28147_key_wrap_kat_as_added() -> None:
    """GOST28147 KEY_WRAP has a source-backed RFC 7836 exact-output KAT."""
    gost_tests = _read("src/pkcs11_check/testcases/test_gost.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    gost_row = doc[doc.index("| GOST28147 |") :].splitlines()[0]

    assert "test_key_wrap_rfc7836_tc26_z_vector" in gost_tests
    assert "RFC 7836" in gost_tests
    assert "CKM_GOST28147_KEY_WRAP` now has an RFC 7836" in doc
    assert "CEK_ENC || CEK_MAC" in doc
    assert "CKM_GOST28147_KEY_WRAP" not in gost_row


def test_gap_analysis_marks_gost28147_ecb_kat_as_added() -> None:
    """GOST28147 ECB has a source-backed RFC 8891 Magma exact-output KAT."""
    gost_tests = _read("src/pkcs11_check/testcases/test_gost.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    gost_row = doc[doc.index("| GOST28147 |") :].splitlines()[0]

    assert "test_ecb_rfc8891_magma_tc26_z_vector" in gost_tests
    assert "RFC 8891" in gost_tests
    assert "CKM_GOST28147_ECB` now has an RFC 8891" in doc
    assert "CKA_GOST28147_PARAMS" in doc
    assert "CKM_GOST28147_ECB" not in gost_row


def test_gap_analysis_marks_gost28147_mac_kat_as_added() -> None:
    """GOST28147 MAC has a source-backed RFC 7836 exact-output KAT."""
    gost_tests = _read("src/pkcs11_check/testcases/test_gost.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    gost_row = doc[doc.index("| GOST28147 |") :].splitlines()[0]

    assert "test_mac_rfc7836_tc26_z_vector" in gost_tests
    assert "CKM_GOST28147_MAC` now has an RFC 7836" in doc
    assert "CEK_MAC" in doc
    assert "CKM_GOST28147_MAC" not in gost_row


def test_gap_analysis_marks_skipjack_ecb64_kat_vectors_as_added() -> None:
    """Skipjack ECB64 has source-backed NIST SP 800-17 KAT vector links."""
    legacy_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_legacy.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "skipjack_ecb64.json" in legacy_registry
    vector_file = _read("src/pkcs11_check/testcases/data/mechanism_vectors/skipjack_ecb64.json")
    assert "NIST SP 800-17 appendix B" in vector_file
    assert "CKM_SKIPJACK_ECB64 now has NIST SP 800-17 exact-output KATs" in doc
    assert "SKIPJACK ECB64 exact-output KATs are covered" in doc


def test_gap_analysis_keeps_skipjack_short_cfb_and_wrap_variants_source_first() -> None:
    """Skipjack short-CFB and wrap KATs stay pending until mappings are reconciled."""
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "SKIPJACK CBC64/OFB64/CFB64, CFB32/CFB16/CFB8, and wrap/private-wrap/" in doc
    assert "PKCS#11 operation mappings must be reconciled" in doc
    assert "SKIPJACK non-ECB64 variants remain source-first" not in doc


def test_gap_analysis_marks_twofish_cbc_pad_vector_as_added() -> None:
    """Twofish CBC_PAD has a source-backed exact-output KAT vector link."""
    legacy_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_legacy.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "twofish_cbc_pad.json" in legacy_registry
    vector_file = _read("src/pkcs11_check/testcases/data/mechanism_vectors/twofish_cbc_pad.json")
    assert "Bruce Schneier Twofish reference C implementation" in vector_file
    assert "`CKM_TWOFISH_CBC_PAD` now has" in doc
    assert "| Twofish |" not in doc


def test_gap_analysis_marks_cdmf_kat_vectors_as_added() -> None:
    """CDMF operations have IBM-derived exact-output KAT vector links."""
    legacy_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_legacy.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    for vector_file in (
        "cdmf_ecb.json",
        "cdmf_cbc.json",
        "cdmf_cbc_pad.json",
        "cdmf_mac.json",
        "cdmf_mac_general.json",
    ):
        assert vector_file in legacy_registry
        assert _read(f"src/pkcs11_check/testcases/data/mechanism_vectors/{vector_file}")

    assert "CDMF ECB/CBC/CBC_PAD/MAC/MAC_GENERAL" in doc
    assert "| CDMF |" not in doc


def test_gap_analysis_does_not_mark_rc5_fixed_mac_pending() -> None:
    """RC5 fixed-output MAC coverage should not remain listed as pending."""
    legacy_registry = _read("src/pkcs11_check/testcases/mechanism_registry/_legacy.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert 'vector_file="rc5_mac.json"' in legacy_registry
    assert _read("src/pkcs11_check/testcases/data/mechanism_vectors/rc5_mac.json")

    assert "Fixed-length `CKM_RC5_MAC` still needs" not in doc
    assert "RC2, RC5, CAST/CAST3/CAST128/CAST5, and IDEA fixed-output MAC" in doc


def test_gap_analysis_inventories_remaining_legacy_source_first_operations() -> None:
    """Remaining legacy/deprecated operation gaps are explicit and source-first."""
    doc = GAP_DOC.read_text(encoding="utf-8")
    inventory = _gap_inventory_rows(doc)

    expected = {
        "SKIPJACK": {
            "CKM_SKIPJACK_CBC64",
            "CKM_SKIPJACK_OFB64",
            "CKM_SKIPJACK_CFB64",
            "CKM_SKIPJACK_CFB32",
            "CKM_SKIPJACK_CFB16",
            "CKM_SKIPJACK_CFB8",
            "CKM_SKIPJACK_WRAP",
            "CKM_SKIPJACK_PRIVATE_WRAP",
            "CKM_SKIPJACK_RELAYX",
        },
        "BATON": {
            "CKM_BATON_ECB128",
            "CKM_BATON_ECB96",
            "CKM_BATON_CBC128",
            "CKM_BATON_COUNTER",
            "CKM_BATON_SHUFFLE",
            "CKM_BATON_WRAP",
        },
        "JUNIPER": {
            "CKM_JUNIPER_ECB128",
            "CKM_JUNIPER_CBC128",
            "CKM_JUNIPER_COUNTER",
            "CKM_JUNIPER_SHUFFLE",
            "CKM_JUNIPER_WRAP",
        },
        "GOST28147": {"CKM_GOST28147"},
        "KEA": {"CKM_KEA_DERIVE", "CKM_KEA_KEY_DERIVE"},
        "OTP/Fortezza": {
            "CKM_ACTI",
            "CKM_FORTEZZA_TIMESTAMP",
            "CKM_HOTP",
            "CKM_SECURID",
        },
        "Other legacy": {
            "CKM_KEY_WRAP_LYNKS",
            "CKM_KEY_WRAP_SET_OAEP",
            "CKM_FASTHASH",
        },
    }

    assert "Current source-first operation inventory" in doc
    for family, mechanisms in expected.items():
        assert inventory[family] == mechanisms

    for mechanism_name in set.union(*expected.values()):
        mech_id = next(
            mech_id for mech_id, name in MECHANISM_NAMES.items() if name == mechanism_name
        )
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file is None, mechanism_name

    tracked_source_first = {
        int(CKM_SKIPJACK_CBC64),
        int(CKM_SKIPJACK_OFB64),
        int(CKM_SKIPJACK_CFB64),
        int(CKM_SKIPJACK_CFB32),
        int(CKM_SKIPJACK_CFB16),
        int(CKM_SKIPJACK_CFB8),
        int(CKM_SKIPJACK_WRAP),
        int(CKM_SKIPJACK_PRIVATE_WRAP),
        int(CKM_SKIPJACK_RELAYX),
        int(CKM_BATON_ECB128),
        int(CKM_BATON_ECB96),
        int(CKM_BATON_CBC128),
        int(CKM_BATON_COUNTER),
        int(CKM_BATON_SHUFFLE),
        int(CKM_BATON_WRAP),
        int(CKM_JUNIPER_ECB128),
        int(CKM_JUNIPER_CBC128),
        int(CKM_JUNIPER_COUNTER),
        int(CKM_JUNIPER_SHUFFLE),
        int(CKM_JUNIPER_WRAP),
        int(CKM_GOST28147),
        int(CKM_KEA_DERIVE),
        int(CKM_KEA_KEY_DERIVE),
        int(CKM_ACTI),
        int(CKM_FORTEZZA_TIMESTAMP),
        int(CKM_HOTP),
        int(CKM_SECURID),
        int(CKM_KEY_WRAP_LYNKS),
        int(CKM_KEY_WRAP_SET_OAEP),
        int(CKM_FASTHASH),
    }
    assert {MECHANISM_NAMES[mech_id] for mech_id in tracked_source_first} == set.union(
        *expected.values()
    )
    assert tracked_source_first == _source_first_legacy_operation_ids()


def test_gap_analysis_records_legacy_vector_source_refresh() -> None:
    """The legacy-vector plan records the latest source search conclusions."""
    doc_flat = " ".join(GAP_DOC.read_text(encoding="utf-8").split())

    assert "Legacy vector source refresh" in doc_flat
    assert "BATON and JUNIPER remain source-first" in doc_flat
    assert "public exact-output algorithm vectors were not found" in doc_flat
    assert "KEA remains source-first" in doc_flat
    assert "RFC 2876 and RFC 2773 describe KEA/SKIPJACK protocol use" in doc_flat
    assert "NIST SP 800-135 and ACVP component-test material make protocol KDFs" in doc_flat
    assert (
        "better next exact-vector target than the remaining classified legacy ciphers"
        in doc_flat
    )
    assert (
        "Provider-speed work for bouncyhsm MCT and wolfPKCS11 session health checks "
        "should follow"
        not in doc_flat
    )


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


def test_gap_analysis_marks_unknown_ckr_classification_as_fixed() -> None:
    """Undefined non-vendor CK_RV values fail instead of becoming xfail."""
    conftest = _read("src/pkcs11_check/testcases/conftest.py")
    helper_tests = _read("tests/test_classification_helpers.py")
    doc = GAP_DOC.read_text(encoding="utf-8")

    assert "_xfail_or_fail_unexpected_clean_rv" in conftest
    assert "is_standard_ckr(rv)" in conftest
    assert "is_vendor_defined_ckr(rv)" in conftest
    assert "undefined CK_RV" in conftest
    assert "vendor-defined CK_RV" in conftest
    assert "test_rv_unknown_non_vendor_value_fails" in helper_tests
    assert "test_exc_unknown_non_vendor_value_fails" in helper_tests
    assert "test_rv_vendor_defined_value_xfails_distinctly" in helper_tests
    assert "test_exc_vendor_defined_value_xfails_distinctly" in helper_tests

    assert "Unknown non-CKR values are hard failures" in doc
    assert "can become xfail" not in doc
    assert "A direct probe shows both `0x7fffffff` and `0xdeadbeef` become" not in doc


def test_gap_analysis_marks_mechanism_coverage_telemetry_as_fixed() -> None:
    """Mechanism coverage telemetry now has provider-local state-loss guards."""
    audit = _read("src/pkcs11_check/core/quality_audit.py")
    tests = _read("tests/test_quality_audit.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert '"advertised",' in audit
    assert '"advertised": ["CKM_AES_GCM"]' in tests
    assert "### 5. Mechanism coverage telemetry needs more states" in doc
    assert "Status: fixed in the current branch. Coverage reports and JSONL merge now" in doc
    assert "including advertised-loss" in doc_flat


def test_gap_analysis_records_bouncyhsm_provider_local_remeasurement() -> None:
    """BouncyHSM MCT speed work has provider-local remeasurement evidence."""
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert (
        "Status: fixed in the current branch. - Implemented: provider-local "
        "duration-oracle data"
    ) in doc_flat
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


def test_gap_analysis_marks_retry_report_jsonl_analysis_as_single_pass() -> None:
    """Retry/detail report-jsonl analysis no longer materializes parsed record lists."""
    runner = _read("src/pkcs11_check/core/file_runner.py")
    tests = _read("tests/test_single_pass_refactors.py")
    doc = GAP_DOC.read_text(encoding="utf-8")
    doc_flat = " ".join(doc.split())

    assert "def _analyze_report_jsonl(" in runner
    assert "_load_report_log_records(to_iter_jsonl)" not in runner
    assert "_load_report_log_records(iter_jsonl_path)" not in runner
    assert "_load_report_log_records(unit_jsonl_path)" not in runner
    assert "test_analyze_report_jsonl_streams_detail_culprit_and_cache" in tests
    assert (
        "Status: fixed in the current branch. - Implemented: normal Docker provider "
        "containers"
    ) in doc_flat
    assert "retry/detail analysis now streams each unit report JSONL once" in doc_flat
