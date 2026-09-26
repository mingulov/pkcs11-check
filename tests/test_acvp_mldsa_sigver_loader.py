"""Regression test for ACVP ML-DSA sigVer vector filtering (PC-2).

PKCS#11 v3.2 exposes only the *external* ML-DSA Sign/Verify interface
(CKM_ML_DSA and CKM_HASH_ML_DSA_*), which internally constructs the
M' representative from (M, ctx) per FIPS 204 Algorithm 2. ACVP also
ships vectors for the *internal* Sign_internal/Verify_internal that
operate on a pre-formatted message (`externalMu=false`) or on a
pre-computed mu (`externalMu=true`). Those vectors cannot be tested
through PKCS#11 — feeding their `message` field to CKM_ML_DSA wraps
it again and verification fails for the wrong reason.

This filter was missing in v0.1.1, producing 36 cross-provider
'rejected a VALID' false-fails on the 3 valid tcs of groups 8/10/12
(ML-DSA-44 tc108/112/116, ML-DSA-65 tc139/141/142, ML-DSA-87
tc169/172/174).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkcs11_check.testcases.acvp import acvp_loader
from pkcs11_check.testcases.acvp._mldsa_helpers import load_mldsa_sigver_vectors
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE

pytestmark = pytest.mark.skipif(not ACVP_AVAILABLE, reason="ACVP vectors not cloned")

# tcIds that belong to signatureInterface=internal groups and were
# emitting false-fails. Listed verbatim from artifacts/softhsm2-main/.
_INTERNAL_INTERFACE_FALSE_FAILS: tuple[tuple[str, int], ...] = (
    ("ML-DSA-44", 108),
    ("ML-DSA-44", 112),
    ("ML-DSA-44", 116),
    ("ML-DSA-65", 139),
    ("ML-DSA-65", 141),
    ("ML-DSA-65", 142),
    ("ML-DSA-87", 169),
    ("ML-DSA-87", 172),
    ("ML-DSA-87", 174),
)


def test_sigver_loader_drops_internal_interface_vectors() -> None:
    """No vector from signatureInterface=internal groups must reach the test."""
    vectors = load_mldsa_sigver_vectors()
    if not vectors:
        pytest.skip("ML-DSA-sigVer ACVP vectors not present")

    seen_param_tcs: set[tuple[str, int]] = {(v["param_set"], v["tc_id"]) for _, v in vectors}

    for entry in _INTERNAL_INTERFACE_FALSE_FAILS:
        assert entry not in seen_param_tcs, (
            f"{entry} is from a signatureInterface=internal group and is "
            "not representable through CKM_ML_DSA; loader must skip it."
        )

    # Sanity: external-interface vectors are still included.
    assert ("ML-DSA-44", 1) in seen_param_tcs
    assert ("ML-DSA-65", 31) in seen_param_tcs
    assert ("ML-DSA-87", 61) in seen_param_tcs


def _write_sigver_pair(tmp_path: Path, cases: list[tuple[int, str]]) -> None:
    """Write a synthetic prompt.json + expectedResults.json pair."""
    vec_dir = tmp_path / "ML-DSA-sigVer-FIPS204"
    vec_dir.mkdir()
    prompt_tests = [
        {
            "tcId": tc_id,
            "pk": "02" * 32,
            "message": "ab" * 16,
            "signature": "cd" * 64,
            "context": "",
            "hashAlg": alg,
        }
        for tc_id, alg in cases
    ]
    expected_tests = [{"tcId": tc_id, "testPassed": True} for tc_id, _ in cases]
    group = {"parameterSet": "ML-DSA-44", "preHash": "preHash", "tests": prompt_tests}
    prompt = {"testGroups": [group]}
    expected = {"testGroups": [{"tests": expected_tests}]}
    (vec_dir / "prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
    (vec_dir / "expectedResults.json").write_text(json.dumps(expected), encoding="utf-8")


def test_sigver_loader_excludes_only_unrepresentable_sha2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(acvp_loader, "ACVP_DIR", tmp_path)
    _write_sigver_pair(tmp_path, [(1, "SHA2-512/224"), (2, "SHA2-512/256"), (3, "SHA2-256")])

    vectors = load_mldsa_sigver_vectors()

    assert [v["tc_id"] for _, v in vectors] == [3]
    _, vec = vectors[0]
    assert vec["_source"] == "acvp:ML-DSA-sigVer-FIPS204"
    assert vec["_vector_id"] == "tcId=3"


def test_sigver_loader_raises_on_unknown_spelling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(acvp_loader, "ACVP_DIR", tmp_path)
    _write_sigver_pair(tmp_path, [(9, "SHA2-999")])

    with pytest.raises(ValueError, match="SHA2-999"):
        load_mldsa_sigver_vectors()


def test_sigver_loader_preserves_provenance_on_pinned_data() -> None:
    """Every pinned SigVer vector keeps exact _source/_vector_id (issue #20)."""
    vectors = load_mldsa_sigver_vectors()
    if not vectors:
        pytest.skip("ML-DSA-sigVer ACVP vectors not present")

    assert len(vectors) == 82
    for vec_id, vec in vectors:
        assert vec["_source"] == "acvp:ML-DSA-sigVer-FIPS204", vec_id
        assert vec["_vector_id"] == f"tcId={vec['tc_id']}", vec_id
