"""Mechanism registry for mechanism-driven parametrized tests.

Maps CKM_* mechanism IDs to test configurations. Covers all 480 mechanisms
from the OASIS PKCS#11 v3.2 standard. Each entry describes how to test
a mechanism: what key type it needs, what key sizes, what parameter packer,
whether it supports multi-part, etc.

Usage:
    from pkcs11_check.testcases.mechanism_registry import MECHANISM_REGISTRY, get_config
    config = get_config(CKM_AES_GCM)
    if config and config.key_type == CKK_AES:
        ...
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MechConfig:
    """Configuration for testing a specific PKCS#11 mechanism.

    Fields:
        key_type: CKK_* constant (None for digest-only mechanisms)
        keygen_mech: CKM_* constant for generating the right key (None for digest)
        key_sizes: Valid key sizes in bits. () for digest or curve-based
        is_keypair: True for asymmetric (uses C_GenerateKeyPair)
        is_param_gen: True for domain parameter generation (DSA/DH param gen)
        param_packer: Name of packer function in pack_mechanisms.py
        param_factory: Name of function that creates default test params
        block_size: Block size in bytes (16 for AES block modes, None for stream)
        vector_file: Path to JSON vectors file (relative to data/mechanism_vectors/)
        input_constraint: "block_aligned", "any", "digest_only", "none"
        multi_part_supported: False for AEAD (GCM/CCM), raw ECDSA, etc.
        param_required: True if C_*Init needs non-NULL mechanism params
        auth_tag_included: True for GCM/CCM (ciphertext includes auth tag)
        deterministic: False for CBC with random IV, RSA-OAEP, etc.
        message_based: True if v3.0 C_Message* APIs supported
        expected_flags: Expected CKF_* flags from C_GetMechanismInfo
        notes: Human-readable notes about the mechanism
    """

    key_type: int | None = None
    keygen_mech: int | None = None
    key_sizes: tuple[int, ...] = ()
    is_keypair: bool = False
    is_param_gen: bool = False
    param_packer: str | None = None
    param_factory: str | None = None
    block_size: int | None = None
    vector_file: str | None = None
    input_constraint: str = "any"
    multi_part_supported: bool = True
    param_required: bool = False
    auth_tag_included: bool = False
    deterministic: bool = True
    message_based: bool = False
    expected_flags: int = 0
    notes: str = ""


# Registry: CKM int value → MechConfig
# Populated incrementally by Tasks 2-4
MECHANISM_REGISTRY: dict[int, MechConfig] = {}


def get_config(mech_id: int) -> MechConfig | None:
    """Look up mechanism config by CKM_* integer value.

    Returns None for vendor-defined mechanisms not in the registry.
    """
    return MECHANISM_REGISTRY.get(mech_id)
