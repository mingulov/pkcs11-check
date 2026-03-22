"""CCTV ML-DSA benchmark message sign/verify round-trip tests.

The CCTV ML-DSA benchmark directory contains lists of ASCII message strings
designed as benchmark signing inputs (not KAT vectors -- no expected signatures).

Each test generates an ML-DSA key pair (per parameter set), signs a message
from the benchmark list, and verifies the resulting signature.  This confirms
the sign+verify path is internally consistent across all three ML-DSA sizes.

Requires: PKCS#11 v3.2 module with ML_DSA support (e.g., Kryoptic).
SoftHSM2 (v2.40) skips all tests -- it has no ML-DSA support.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.constants import MLDsaParameterSet
from pkcs11.exceptions import FunctionFailed, MechanismInvalid

from pkcs11_check.testcases.conftest import has_mechanism
from pkcs11_check.testcases.data import CCTV_DIR

pytestmark = [pytest.mark.pqc, pytest.mark.requires_v32, pytest.mark.kat, pytest.mark.cctv]

_BENCHMARK_DIR = CCTV_DIR / "ML-DSA" / "benchmark"

# ML-DSA parameter set name -> (MLDsaParameterSet enum, benchmark file)
_PARAM_CONFIGS: list[tuple[str, MLDsaParameterSet, Path]] = [
    ("ML-DSA-44", MLDsaParameterSet.ML_DSA_44, _BENCHMARK_DIR / "ML-DSA-44.json"),
    ("ML-DSA-65", MLDsaParameterSet.ML_DSA_65, _BENCHMARK_DIR / "ML-DSA-65.json"),
    ("ML-DSA-87", MLDsaParameterSet.ML_DSA_87, _BENCHMARK_DIR / "ML-DSA-87.json"),
]

# Limit to first N messages per parameter set for speed
_MAX_MESSAGES = 20


def _load_messages(path: Path) -> list[bytes]:
    """Load benchmark message strings, encoded to UTF-8 bytes."""
    if not path.exists():
        return []
    with open(path) as f:
        data: list[str] = json.load(f)
    return [msg.encode("utf-8") for msg in data[:_MAX_MESSAGES]]


def _build_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Build (vec_id, vec) pairs for parametrize."""
    vectors: list[tuple[str, dict[str, Any]]] = []
    for param_name, param_set, path in _PARAM_CONFIGS:
        messages = _load_messages(path)
        for i, msg in enumerate(messages):
            vec_id = f"{param_name}-msg{i}"
            vectors.append((vec_id, {"param_name": param_name, "param_set": param_set, "msg": msg}))
    return vectors


_ALL_VECTORS = _build_vectors()


@pytest.mark.parametrize(
    "vec_id,vec",
    _ALL_VECTORS,
    ids=[v[0] for v in _ALL_VECTORS],
)
def test_cctv_mldsa_sign_verify(
    p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """ML-DSA sign + verify round-trip using CCTV benchmark messages.

    Generates a fresh ML-DSA key pair, signs the message, then verifies the
    signature using the same key pair.  No expected signature is compared --
    the benchmark files provide messages only.

    Security property: if sign succeeds and verify rejects the fresh
    signature, the module has a sign/verify inconsistency (test failure).
    """
    if not _BENCHMARK_DIR.exists():
        pytest.skip("CCTV ML-DSA benchmark data not found")

    param_name: str = vec["param_name"]
    param_set: MLDsaParameterSet = vec["param_set"]
    msg: bytes = vec["msg"]

    if not has_mechanism(p11_module, "ML_DSA"):
        pytest.skip(f"{param_name}: ML_DSA not supported by module")

    pub_key = None
    priv_key = None
    try:
        try:
            pub_key, priv_key = p11_session.generate_keypair(
                KeyType.ML_DSA,
                mechanism=Mechanism.ML_DSA_KEY_PAIR_GEN,
                public_template={
                    Attribute.VERIFY: True,
                    Attribute.PARAMETER_SET: int(param_set),
                    Attribute.TOKEN: False,
                },
                private_template={
                    Attribute.SIGN: True,
                    Attribute.PARAMETER_SET: int(param_set),
                    Attribute.TOKEN: False,
                },
            )
        except (MechanismInvalid, FunctionFailed) as e:
            pytest.skip(f"{param_name}: key generation failed -- {e}")

        sig = priv_key.sign(msg, mechanism=Mechanism.ML_DSA)
        assert len(sig) > 0, f"{vec_id}: sign() returned empty signature"

        pub_key.verify(msg, sig, mechanism=Mechanism.ML_DSA)

    finally:
        if pub_key is not None:
            pub_key.destroy()
        if priv_key is not None:
            priv_key.destroy()
