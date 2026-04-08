"""Mechanism registry for mechanism-driven parametrized tests.

Maps CKM_* mechanism IDs to test configurations. Covers all 467 mechanisms
from the OASIS PKCS#11 v3.2 standard (464 in MECHANISM_NAMES + 3 extra).
Each entry describes how to test
a mechanism: what key type it needs, what key sizes, what parameter recipe,
whether it supports multi-part, etc.

Usage:
    from pkcs11_check.testcases.mechanism_registry import MECHANISM_REGISTRY, get_config
    config = get_config(CKM_AES_GCM)
    if config and config.key_type == CKK_AES:
        ...
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ParamRecipe:
    """Declarative recipe for creating mechanism test parameters.

    The 'style' field selects a parameter construction strategy.
    The 'defaults' dict provides style-specific configuration.

    Styles:
        "none"         -- No params needed (CKM_AES_ECB, CKM_SHA256, etc.)
        "iv"           -- Random IV of iv_len bytes (CBC, OFB, CFB modes)
        "gcm"          -- CK_AES_GCM_PARAMS with iv_len, tag_bits, optional aad
        "ccm"          -- CK_AES_CCM_PARAMS with nonce_len, mac_len, data_len
        "ctr"          -- CK_AES_CTR_PARAMS with counter_bits
        "pss"          -- CK_RSA_PKCS_PSS_PARAMS with hash_mech, mgf, salt_len
        "oaep"         -- CK_RSA_PKCS_OAEP_PARAMS with hash_mech, mgf
        "eddsa"        -- CK_EDDSA_PARAMS (phFlag=0, no context)
        "ecdh"         -- CK_ECDH1_DERIVE_PARAMS (needs peer public key at runtime)
        "hkdf"         -- CK_HKDF_PARAMS (needs salt/info at runtime)
        "mac_general"  -- CK_MAC_GENERAL_PARAMS (mac_len as CK_ULONG)
        "string_data"  -- CK_KEY_DERIVATION_STRING_DATA (data bytes)
    """

    style: str = "none"
    defaults: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class KeygenRecipe:
    """Declarative recipe for key generation template construction.

    Styles:
        "symmetric"     -- CKA_VALUE_LEN from key_size (AES, Camellia, ARIA, etc.)
        "fixed_length"  -- No CKA_VALUE_LEN needed (DES, SEED, etc.)
        "rsa"           -- CKA_MODULUS_BITS + CKA_PUBLIC_EXPONENT
        "ec"            -- CKA_EC_PARAMS with curve OID
        "ec_edwards"    -- CKA_EC_PARAMS with Edwards curve OID
        "ec_montgomery" -- CKA_EC_PARAMS with Montgomery curve OID
        "pqc"           -- CKA_PARAMETER_SET with param set constant
        "dh"            -- Requires domain parameters (skip for now)
        "dsa"           -- Requires domain parameters (skip for now)
        "generic"       -- CKK_GENERIC_SECRET with CKA_VALUE_LEN
    """

    style: str = "symmetric"
    defaults: dict[str, Any] = field(default_factory=dict)
    # defaults examples:
    # "rsa": {} (uses key_size for MODULUS_BITS, fixed e=65537)
    # "ec": {"curve": "secp256r1"} (default curve when key_sizes empty)
    # "ec_edwards": {"curve": "Ed25519"}
    # "pqc": {"parameter_set": "CKP_ML_DSA_65"}


@dataclass(frozen=True)
class MechConfig:
    """Configuration for testing a specific PKCS#11 mechanism.

    Fields:
        key_type: CKK_* constant (None for digest-only mechanisms)
        keygen_mech: CKM_* constant for generating the right key (None for digest)
        key_sizes: Valid key sizes in bits. () for digest or curve-based
        is_keypair: True for asymmetric (uses C_GenerateKeyPair)
        is_param_gen: True for domain parameter generation (DSA/DH param gen)
        param_recipe: Declarative recipe for mechanism parameter construction
        keygen_recipe: Declarative recipe for key generation template construction
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
    param_recipe: ParamRecipe = field(default_factory=ParamRecipe)
    keygen_recipe: KeygenRecipe = field(default_factory=KeygenRecipe)
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


# Registry: CKM int value -> MechConfig
MECHANISM_REGISTRY: dict[int, MechConfig] = {}


def get_config(mech_id: int) -> MechConfig | None:
    """Look up mechanism config by CKM_* integer value.

    Returns None for vendor-defined mechanisms not in the registry.
    """
    return MECHANISM_REGISTRY.get(mech_id)


# Populate from submodules -- each submodule adds its family's entries.
# These imports are intentionally after the MECHANISM_REGISTRY definition to avoid
# circular imports: submodules import MechConfig from this module.
from pkcs11_check.testcases.mechanism_registry._aes import populate as _pop_aes  # noqa: E402
from pkcs11_check.testcases.mechanism_registry._ciphers import (  # noqa: E402
    populate as _pop_ciphers,
)
from pkcs11_check.testcases.mechanism_registry._des import populate as _pop_des  # noqa: E402
from pkcs11_check.testcases.mechanism_registry._dsa_dh import populate as _pop_dsa_dh  # noqa: E402
from pkcs11_check.testcases.mechanism_registry._ec import populate as _pop_ec  # noqa: E402
from pkcs11_check.testcases.mechanism_registry._hash import populate as _pop_hash  # noqa: E402
from pkcs11_check.testcases.mechanism_registry._hmac import populate as _pop_hmac  # noqa: E402
from pkcs11_check.testcases.mechanism_registry._kdf import populate as _pop_kdf  # noqa: E402
from pkcs11_check.testcases.mechanism_registry._legacy import populate as _pop_legacy  # noqa: E402
from pkcs11_check.testcases.mechanism_registry._misc import populate as _pop_misc  # noqa: E402
from pkcs11_check.testcases.mechanism_registry._pqc import populate as _pop_pqc  # noqa: E402
from pkcs11_check.testcases.mechanism_registry._rsa import populate as _pop_rsa  # noqa: E402

_pop_aes(MECHANISM_REGISTRY)
_pop_rsa(MECHANISM_REGISTRY)
_pop_ec(MECHANISM_REGISTRY)
_pop_hash(MECHANISM_REGISTRY)
_pop_hmac(MECHANISM_REGISTRY)
_pop_pqc(MECHANISM_REGISTRY)
_pop_kdf(MECHANISM_REGISTRY)
_pop_dsa_dh(MECHANISM_REGISTRY)
_pop_des(MECHANISM_REGISTRY)
_pop_ciphers(MECHANISM_REGISTRY)
_pop_legacy(MECHANISM_REGISTRY)
_pop_misc(MECHANISM_REGISTRY)
