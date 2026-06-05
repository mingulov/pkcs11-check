"""ML-KEM ACVP test helpers - shared utilities for ML-KEM ACVP tests.

This module contains helper functions for loading and processing
NIST ACVP ML-KEM test vectors (FIPS 203).
"""

from __future__ import annotations

from typing import Any

from pkcs11_check.raw.types_std import (
    CKM,
    CKM_ML_KEM,
    CKP_ML_KEM_512,
    CKP_ML_KEM_768,
    CKP_ML_KEM_1024,
)
from pkcs11_check.testcases.acvp._duplicates import mark_duplicate_pkcs11_inputs
from pkcs11_check.testcases.data import ACVP_DIR, load_json_cached

# Parameter set mapping
_ML_KEM_PARAM_MAP: dict[str, int] = {
    "ML-KEM-512": int(CKP_ML_KEM_512),
    "ML-KEM-768": int(CKP_ML_KEM_768),
    "ML-KEM-1024": int(CKP_ML_KEM_1024),
}

# Mechanism mapping for ML-KEM (single mechanism, parameter set via CKA_PARAMETER_SET)
_ML_KEM_MECHANISMS: dict[str, CKM] = {
    "ML-KEM-512": CKM_ML_KEM,
    "ML-KEM-768": CKM_ML_KEM,
    "ML-KEM-1024": CKM_ML_KEM,
}


def get_mlkem_mechanism(param_set: str) -> CKM:
    """Get the ML-KEM mechanism for a parameter set.

    Args:
        param_set: Parameter set name ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")

    Returns:
        The CKM_ML_KEM_* mechanism constant
    """
    return _ML_KEM_MECHANISMS[param_set]


def load_mlkem_keygen_vectors(limit: int | None = None) -> list[tuple[str, dict[str, Any]]]:
    """Load ML-KEM KeyGen ACVP vectors.

    Uses internalProjection.json which contains the expected key pairs
    for deterministic key generation testing.
    """
    keygen_dir = ACVP_DIR / "ML-KEM-keyGen-FIPS203"
    internal_file = keygen_dir / "internalProjection.json"
    if not internal_file.exists():
        return []

    data = load_json_cached(internal_file)

    result: list[tuple[str, dict[str, Any]]] = []

    for tg in data.get("testGroups", []):
        param_set = tg.get("parameterSet", "")
        if param_set not in _ML_KEM_PARAM_MAP:
            continue

        for test in tg.get("tests", []):
            tc_id = test.get("tcId", 0)
            ek_hex = test.get("ek", "")  # encapsulation key (public)
            dk_hex = test.get("dk", "")  # decapsulation key (private)
            d_hex = test.get("d", "")  # seed d
            z_hex = test.get("z", "")  # seed z

            if not ek_hex or not dk_hex:
                continue

            try:
                ek_bytes = bytes.fromhex(ek_hex)
                dk_bytes = bytes.fromhex(dk_hex)
                d_bytes = bytes.fromhex(d_hex) if d_hex else b""
                z_bytes = bytes.fromhex(z_hex) if z_hex else b""
            except ValueError:
                continue

            vec_data: dict[str, Any] = {
                "param_set": param_set,
                "parameter_set": _ML_KEM_PARAM_MAP[param_set],
                "tc_id": tc_id,
                "ek": ek_bytes,
                "dk": dk_bytes,
                "d": d_bytes,
                "z": z_bytes,
            }
            vec_id = f"ML-KEM-keyGen-{param_set}-tc{tc_id}"
            result.append((vec_id, vec_data))

            if limit is not None and len(result) >= limit:
                return mark_duplicate_pkcs11_inputs(result, lambda item: item["parameter_set"])

    return mark_duplicate_pkcs11_inputs(result, lambda item: item["parameter_set"])


def load_mlkem_encap_vectors(limit: int | None = None) -> list[tuple[str, dict[str, Any]]]:
    """Load ML-KEM Encapsulation ACVP vectors.

    Uses internalProjection.json which contains the public key (ek),
    expected ciphertext (c), shared secret (k), and randomness (m).
    """
    encap_dir = ACVP_DIR / "ML-KEM-encapDecap-FIPS203"
    internal_file = encap_dir / "internalProjection.json"
    if not internal_file.exists():
        return []

    data = load_json_cached(internal_file)

    result: list[tuple[str, dict[str, Any]]] = []

    for tg in data.get("testGroups", []):
        param_set = tg.get("parameterSet", "")
        function = tg.get("function", "")
        if param_set not in _ML_KEM_PARAM_MAP:
            continue
        if function != "encapsulation":
            continue

        for test in tg.get("tests", []):
            tc_id = test.get("tcId", 0)
            ek_hex = test.get("ek", "")  # encapsulation key (public)
            dk_hex = test.get("dk", "")  # decapsulation key (for round-trip)
            c_hex = test.get("c", "")  # ciphertext
            k_hex = test.get("k", "")  # shared secret
            m_hex = test.get("m", "")  # randomness

            if not ek_hex or not c_hex or not k_hex:
                continue

            try:
                ek_bytes = bytes.fromhex(ek_hex)
                c_bytes = bytes.fromhex(c_hex)
                k_bytes = bytes.fromhex(k_hex)
                m_bytes = bytes.fromhex(m_hex) if m_hex else b""
            except ValueError:
                continue

            vec_data: dict[str, Any] = {
                "param_set": param_set,
                "parameter_set": _ML_KEM_PARAM_MAP[param_set],
                "tc_id": tc_id,
                "ek": ek_bytes,
                "c": c_bytes,
                "k": k_bytes,
                "m": m_bytes,
            }
            if dk_hex:
                try:
                    vec_data["dk"] = bytes.fromhex(dk_hex)
                except ValueError:
                    pass
            vec_id = f"ML-KEM-encap-{param_set}-tc{tc_id}"
            result.append((vec_id, vec_data))

            if limit is not None and len(result) >= limit:
                return result

    return result


def load_mlkem_decap_vectors(limit: int | None = None) -> list[tuple[str, dict[str, Any]]]:
    """Load ML-KEM Decapsulation ACVP vectors.

    Uses internalProjection.json which contains the private key (dk),
    ciphertext (c), and expected shared secret (k).
    """
    encap_dir = ACVP_DIR / "ML-KEM-encapDecap-FIPS203"
    internal_file = encap_dir / "internalProjection.json"
    if not internal_file.exists():
        return []

    data = load_json_cached(internal_file)

    result: list[tuple[str, dict[str, Any]]] = []

    for tg in data.get("testGroups", []):
        param_set = tg.get("parameterSet", "")
        function = tg.get("function", "")
        if param_set not in _ML_KEM_PARAM_MAP:
            continue
        if function != "decapsulation":
            continue

        for test in tg.get("tests", []):
            tc_id = test.get("tcId", 0)
            dk_hex = test.get("dk", "")  # decapsulation key (private)
            c_hex = test.get("c", "")  # ciphertext
            k_hex = test.get("k", "")  # shared secret

            if not dk_hex or not c_hex or not k_hex:
                continue

            try:
                dk_bytes = bytes.fromhex(dk_hex)
                c_bytes = bytes.fromhex(c_hex)
                k_bytes = bytes.fromhex(k_hex)
            except ValueError:
                continue

            vec_data: dict[str, Any] = {
                "param_set": param_set,
                "parameter_set": _ML_KEM_PARAM_MAP[param_set],
                "tc_id": tc_id,
                "dk": dk_bytes,
                "c": c_bytes,
                "k": k_bytes,
            }
            vec_id = f"ML-KEM-decap-{param_set}-tc{tc_id}"
            result.append((vec_id, vec_data))

            if limit is not None and len(result) >= limit:
                return result

    return result
