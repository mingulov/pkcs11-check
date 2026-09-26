"""Regression: one Hash-ML-DSA resolver drives gates, evidence, and invocation.

Issue #26: invocation resolved the ACVP pre-hash spelling through
``get_mldsa_mechanism`` while capability gates and evidence used the duplicate
spelling map ``_get_mech_name``, which silently fell back to ``ML_DSA`` for
every ``SHA2-*``/``SHA3-*``/``SHAKE-*`` spelling. SigVer additionally omitted
mechanism/operation evidence and its custom loader dropped ``_source`` /
``_vector_id`` provenance. Each vector must be resolved exactly once and that
single result reused for ``has_mechanism``, flag gating, ``set_mechanism``,
and the sign/verify call.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
from pkcs11_check.raw.types_std import CKF_VERIFY, CKP_ML_DSA_44
from pkcs11_check.testcases.acvp import _mldsa_helpers as helpers
from pkcs11_check.testcases.acvp import test_acvp_mldsa as mldsa
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE

# Literal, non-tautological pin of the canonical resolution table:
# (ACVP spelling, numeric CKM value, canonical bare mechanism name).
_RESOLUTION_TABLE: tuple[tuple[str, int, str], ...] = (
    ("pure", 0x1D, "ML_DSA"),
    ("none", 0x1D, "ML_DSA"),
    ("SHA2-224", 0x23, "HASH_ML_DSA_SHA224"),
    ("SHA2-256", 0x24, "HASH_ML_DSA_SHA256"),
    ("SHA2-384", 0x25, "HASH_ML_DSA_SHA384"),
    ("SHA2-512", 0x26, "HASH_ML_DSA_SHA512"),
    ("SHA3-224", 0x27, "HASH_ML_DSA_SHA3_224"),
    ("SHA3-256", 0x28, "HASH_ML_DSA_SHA3_256"),
    ("SHA3-384", 0x29, "HASH_ML_DSA_SHA3_384"),
    ("SHA3-512", 0x2A, "HASH_ML_DSA_SHA3_512"),
    ("SHAKE-128", 0x2B, "HASH_ML_DSA_SHAKE128"),
    ("SHAKE-256", 0x2C, "HASH_ML_DSA_SHAKE256"),
)


def test_resolution_table_covers_exactly_twelve_accepted_inputs() -> None:
    assert len(_RESOLUTION_TABLE) == 12


@pytest.mark.parametrize(("spelling", "ckm", "name"), _RESOLUTION_TABLE)
def test_resolver_returns_canonical_value_and_name(spelling: str, ckm: int, name: str) -> None:
    resolved = helpers.resolve_mldsa_mechanism(spelling)
    assert int(resolved.value) == ckm
    assert resolved.name == name
    # The bare name is derived from the generated constant table, not a copy.
    assert resolved.name == MECHANISM_NAMES[ckm].removeprefix("CKM_")


@pytest.mark.parametrize("spelling", ["SHA2-999", "SHA-256", "SHAKE256", ""])
def test_unknown_spelling_raises_naming_original(spelling: str) -> None:
    """Unknown spellings raise visibly; nothing silently maps to ML_DSA.

    ``SHA-256``/``SHAKE256`` are the legacy normalized spellings: they were
    never public-and-tested resolver inputs, so they are unknown spellings
    now rather than retained aliases.
    """
    with pytest.raises(ValueError, match=f"Unknown ML-DSA pre-hash mode: {spelling!r}"):
        helpers.resolve_mldsa_mechanism(spelling)


@pytest.mark.parametrize(("spelling", "ckm", "_name"), _RESOLUTION_TABLE)
def test_legacy_wrapper_agrees_with_resolver(spelling: str, ckm: int, _name: str) -> None:
    assert int(helpers.get_mldsa_mechanism(spelling)) == ckm


def _siggen_vec(**overrides: Any) -> dict[str, Any]:
    vec: dict[str, Any] = {
        "pre_hash": "preHash",
        "hash_alg": "SHA2-256",
        "context": b"",
        "sk": b"\x01" * 32,
        "pk": b"\x02" * 32,
        "msg": b"message",
        "parameter_set": int(CKP_ML_DSA_44),
        "param_set": "ML-DSA-44",
        "tc_id": 1,
        "_source": "acvp:ML-DSA-sigGen-FIPS204",
        "_vector_id": "tcId=1",
    }
    vec.update(overrides)
    return vec


def test_siggen_sha256_gate_evidence_and_invocation_agree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SigGen SHA2-256: one resolution feeds gate, evidence, and both calls."""
    gates: list[str] = []
    evidence: dict[str, Any] = {}
    invoked: list[int] = []

    def _has_mechanism(name: str) -> bool:
        gates.append(name)
        return True

    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=_has_mechanism)
    monkeypatch.setattr(mldsa, "import_pqc_private_key", lambda *_a, **_k: 10)
    monkeypatch.setattr(mldsa, "import_pqc_public_key", lambda *_a, **_k: 11)
    monkeypatch.setattr(mldsa, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(mldsa, "set_params", lambda *_a, **_k: None)

    def _record_mechanism(
        mechanism: str | None, operation: str | None = None, *, expect_success: bool = False
    ) -> None:
        evidence["mechanism"] = mechanism
        evidence["operation"] = operation
        evidence["expect_success"] = expect_success

    monkeypatch.setattr(mldsa, "set_mechanism", _record_mechanism)
    monkeypatch.setattr(
        mldsa, "sign_single", lambda *a, **_k: (invoked.append(int(a[3])), b"sig")[1]
    )
    monkeypatch.setattr(
        mldsa, "verify_single", lambda *a, **_k: (invoked.append(int(a[3])), True)[1]
    )

    mldsa.TestMlDsaSigGen().test_mldsa_siggen(rs, "ML-DSA-sigGen-sha256", _siggen_vec())

    assert gates == ["HASH_ML_DSA_SHA256"]
    assert evidence == {
        "mechanism": "HASH_ML_DSA_SHA256",
        "operation": "C_Sign",
        "expect_success": True,
    }
    assert invoked == [0x24, 0x24]


def _sigver_vec(**overrides: Any) -> dict[str, Any]:
    vec: dict[str, Any] = {
        "pre_hash": "preHash",
        "hash_alg": "SHAKE-128",
        "context": b"",
        "pk": b"\x02" * 32,
        "msg": b"message",
        "sig": b"\x03" * 64,
        "expected_pass": True,
        "parameter_set": int(CKP_ML_DSA_44),
        "param_set": "ML-DSA-44",
        "tc_id": 2,
        "_source": "acvp:ML-DSA-sigVer-FIPS204",
        "_vector_id": "tcId=2",
    }
    vec.update(overrides)
    return vec


@pytest.mark.parametrize("expected_pass", [True, False])
def test_sigver_shake128_gate_flag_evidence_and_invocation_agree(
    monkeypatch: pytest.MonkeyPatch, expected_pass: bool
) -> None:
    """SigVer SHAKE-128: gate, flag check, evidence, invocation agree.

    Covers a valid and an invalid vector; ``expect_success`` tracks the
    vector verdict so invalid vectors never claim a productive C_Verify.
    """
    gates: list[str] = []
    flags: list[tuple[str, int]] = []
    evidence: dict[str, Any] = {}
    invoked: list[int] = []

    def _has_mechanism(name: str) -> bool:
        gates.append(name)
        return True

    def _has_mechanism_flag(name: str, flag: int) -> bool:
        flags.append((name, flag))
        return True

    rs = SimpleNamespace(
        raw=object(), sh=1, has_mechanism=_has_mechanism, has_mechanism_flag=_has_mechanism_flag
    )
    monkeypatch.setattr(mldsa, "import_pqc_public_key", lambda *_a, **_k: 7)
    monkeypatch.setattr(mldsa, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(mldsa, "set_params", lambda *_a, **_k: None)

    def _record_mechanism(
        mechanism: str | None, operation: str | None = None, *, expect_success: bool = False
    ) -> None:
        evidence["mechanism"] = mechanism
        evidence["operation"] = operation
        evidence["expect_success"] = expect_success

    monkeypatch.setattr(mldsa, "set_mechanism", _record_mechanism)
    monkeypatch.setattr(
        mldsa,
        "verify_single",
        lambda *a, **_k: (invoked.append(int(a[3])), expected_pass)[1],
    )

    vec = _sigver_vec(expected_pass=expected_pass)
    mldsa.TestMlDsaSigVer().test_acvp_mldsa_sigver(rs, "ML-DSA-sigVer-shake128", vec)

    assert gates == ["HASH_ML_DSA_SHAKE128"]
    assert flags == [("HASH_ML_DSA_SHAKE128", int(CKF_VERIFY))]
    assert evidence == {
        "mechanism": "HASH_ML_DSA_SHAKE128",
        "operation": "C_Verify",
        "expect_success": expected_pass,
    }
    assert invoked == [0x2B]


def _write_siggen_projection(tmp_path: Path, hash_algs: list[tuple[int, str]]) -> None:
    vec_dir = tmp_path / "ML-DSA-sigGen-FIPS204"
    vec_dir.mkdir()
    tests = [
        {
            "tcId": tc_id,
            "message": "ab" * 16,
            "signature": "cd" * 64,
            "context": "",
            "sk": "01" * 32,
            "pk": "02" * 32,
            "hashAlg": alg,
        }
        for tc_id, alg in hash_algs
    ]
    payload = {"testGroups": [{"parameterSet": "ML-DSA-44", "preHash": "preHash", "tests": tests}]}
    (vec_dir / "internalProjection.json").write_text(json.dumps(payload), encoding="utf-8")


def test_siggen_loader_excludes_only_unrepresentable_sha2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helpers, "ACVP_DIR", tmp_path)
    _write_siggen_projection(tmp_path, [(1, "SHA2-512/224"), (2, "SHA2-512/256"), (3, "SHA2-256")])

    vectors = helpers.load_mldsa_siggen_vectors()

    assert [tc for _, v in vectors for tc in [v["tc_id"]]] == [3]
    _, vec = vectors[0]
    assert vec["_source"] == "acvp:ML-DSA-sigGen-FIPS204"
    assert vec["_vector_id"] == "tcId=3"


def test_siggen_loader_raises_on_unknown_spelling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helpers, "ACVP_DIR", tmp_path)
    _write_siggen_projection(tmp_path, [(9, "SHA2-999")])

    with pytest.raises(ValueError, match="SHA2-999"):
        helpers.load_mldsa_siggen_vectors()


@pytest.mark.skipif(not ACVP_AVAILABLE, reason="ACVP vectors not cloned")
def test_pinned_data_ml_dsa_collection_counts() -> None:
    """Pinned-data loader output: 75 keygen + 258 SigGen + 82 SigVer.

    Module-level product IDs derive directly from these loader outputs; the
    full 415-node before/after ID-set differential is recorded in the task
    report via collect-only runs.
    """
    assert len(helpers.load_mldsa_keygen_vectors()) == 75
    assert len(helpers.load_mldsa_siggen_vectors()) == 258
    assert len(helpers.load_mldsa_sigver_vectors()) == 82
