"""Miscellaneous mechanism family registry entries.

Covers MD2, MD5 (digest/HMAC/KDF/RSA), GOST R 34.10/34.11, PBE/PBA,
KEA, Fortezza, OTP (SecurID/HOTP/ACTI), CMS, and KIP — approximately 40 mechanisms.
"""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_DERIVE,
    CKF_DIGEST,
    CKF_GENERATE,
    CKF_GENERATE_KEY_PAIR,
    CKF_SIGN,
    CKF_VERIFY,
    CKF_WRAP,
    CKK_GENERIC_SECRET,
    CKK_GOSTR3410,
    CKK_GOSTR3411,
    CKK_KEA,
    CKM_ACTI,
    CKM_ACTI_KEY_GEN,
    CKM_CMS_SIG,
    CKM_FORTEZZA_TIMESTAMP,
    CKM_GOSTR3410,
    CKM_GOSTR3410_DERIVE,
    CKM_GOSTR3410_KEY_PAIR_GEN,
    CKM_GOSTR3410_KEY_WRAP,
    CKM_GOSTR3410_WITH_GOSTR3411,
    CKM_GOSTR3411,
    CKM_GOSTR3411_HMAC,
    CKM_HOTP,
    CKM_HOTP_KEY_GEN,
    CKM_KEA_DERIVE,
    CKM_KEA_KEY_DERIVE,
    CKM_KEA_KEY_PAIR_GEN,
    CKM_KIP_DERIVE,
    CKM_KIP_MAC,
    CKM_KIP_WRAP,
    CKM_MD2,
    CKM_MD2_HMAC,
    CKM_MD2_HMAC_GENERAL,
    CKM_MD2_KEY_DERIVATION,
    CKM_MD2_RSA_PKCS,
    CKM_MD5,
    CKM_MD5_HMAC,
    CKM_MD5_HMAC_GENERAL,
    CKM_MD5_KEY_DERIVATION,
    CKM_MD5_RSA_PKCS,
    CKM_PBA_SHA1_WITH_SHA1_HMAC,
    CKM_PBE_MD2_DES_CBC,
    CKM_PBE_MD5_CAST3_CBC,
    CKM_PBE_MD5_CAST128_CBC,
    CKM_PBE_MD5_CAST_CBC,
    CKM_PBE_MD5_DES_CBC,
    CKM_PBE_SHA1_CAST128_CBC,
    CKM_PBE_SHA1_DES2_EDE_CBC,
    CKM_PBE_SHA1_DES3_EDE_CBC,
    CKM_PBE_SHA1_RC2_40_CBC,
    CKM_PBE_SHA1_RC2_128_CBC,
    CKM_PBE_SHA1_RC4_40,
    CKM_PBE_SHA1_RC4_128,
    CKM_SECURID,
    CKM_SECURID_KEY_GEN,
)
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig, ParamRecipe

_SIG_VER = CKF_SIGN | CKF_VERIFY

_sym = KeygenRecipe("symmetric")
_gost = KeygenRecipe("ec", {"curve": "GOST-2001"})
_kea = KeygenRecipe("ec", {"curve": "KEA-1024"})
_mac_general = ParamRecipe("mac_general", {"mac_len": 8})


def populate(registry: dict[int, MechConfig]) -> None:
    """Add miscellaneous mechanism entries to the registry."""

    # ---------------------------------------------------------------------------
    # MD2 mechanisms (obsolete digest)
    # ---------------------------------------------------------------------------

    registry[CKM_MD2] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="any",
        multi_part_supported=True,
        expected_flags=CKF_DIGEST,
        notes="MD2 digest: 128-bit output (obsolete, RFC 1319)",
    )

    registry[CKM_MD2_HMAC] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=None,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="MD2-HMAC: HMAC with MD2, 128-bit output (obsolete)",
    )

    registry[CKM_MD2_HMAC_GENERAL] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="MD2-HMAC-GENERAL: HMAC-MD2 with variable output length (CK_MAC_GENERAL_PARAMS)",
    )

    registry[CKM_MD2_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=None,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="MD2 key derivation: derive key from MD2 digest of input data",
    )

    # ---------------------------------------------------------------------------
    # MD5 mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_MD5] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="any",
        multi_part_supported=True,
        expected_flags=CKF_DIGEST,
        notes="MD5 digest: 128-bit output (RFC 1321; deprecated for security use)",
    )

    registry[CKM_MD5_HMAC] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=None,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="MD5-HMAC: HMAC with MD5, 128-bit output (RFC 2104)",
    )

    registry[CKM_MD5_HMAC_GENERAL] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        param_recipe=_mac_general,
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="MD5-HMAC-GENERAL: HMAC-MD5 with variable output length (CK_MAC_GENERAL_PARAMS)",
    )

    registry[CKM_MD5_KEY_DERIVATION] = MechConfig(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=None,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=CKF_DERIVE,
        notes="MD5 key derivation: derive key from MD5 digest of input data",
    )

    # ---------------------------------------------------------------------------
    # MD2/MD5 RSA PKCS#1 v1.5 signature
    # ---------------------------------------------------------------------------

    registry[CKM_MD2_RSA_PKCS] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="MD2withRSA PKCS#1 v1.5 signature (obsolete)",
    )

    registry[CKM_MD5_RSA_PKCS] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        is_keypair=True,
        expected_flags=_SIG_VER,
        notes="MD5withRSA PKCS#1 v1.5 signature (deprecated for security use)",
    )

    # ---------------------------------------------------------------------------
    # GOST R 34.10 / 34.11 mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_GOSTR3410_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_GOSTR3410,
        keygen_mech=CKM_GOSTR3410_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_gost,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="GOST R 34.10-2001 key pair generation (256-bit ECC)",
    )

    registry[CKM_GOSTR3410] = MechConfig(
        key_type=CKK_GOSTR3410,
        keygen_mech=CKM_GOSTR3410_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        deterministic=False,
        keygen_recipe=_gost,
        expected_flags=_SIG_VER,
        notes="GOST R 34.10-2001 raw signature (512-bit signature over 256-bit GOST hash)",
    )

    registry[CKM_GOSTR3410_WITH_GOSTR3411] = MechConfig(
        key_type=CKK_GOSTR3410,
        keygen_mech=CKM_GOSTR3410_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        deterministic=False,
        keygen_recipe=_gost,
        expected_flags=_SIG_VER,
        notes="GOST R 34.10-2001 signature with GOST R 34.11-94 hash (full sign+digest)",
    )

    registry[CKM_GOSTR3410_KEY_WRAP] = MechConfig(
        key_type=CKK_GOSTR3410,
        keygen_mech=CKM_GOSTR3410_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_gost,
        expected_flags=CKF_WRAP | CKF_DECRYPT,
        notes="GOST R 34.10 key wrapping for key export/import",
    )

    registry[CKM_GOSTR3410_DERIVE] = MechConfig(
        key_type=CKK_GOSTR3410,
        keygen_mech=CKM_GOSTR3410_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_gost,
        expected_flags=CKF_DERIVE,
        notes="GOST R 34.10 key agreement / derivation (VKO GOST R 34.10-2001)",
    )

    registry[CKM_GOSTR3411] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        input_constraint="any",
        multi_part_supported=True,
        expected_flags=CKF_DIGEST,
        notes="GOST R 34.11-94 digest: 256-bit output (Streebog predecessor)",
    )

    registry[CKM_GOSTR3411_HMAC] = MechConfig(
        key_type=CKK_GOSTR3411,
        keygen_mech=None,
        key_sizes=(),
        keygen_recipe=_sym,
        expected_flags=_SIG_VER,
        notes="GOST R 34.11-94 HMAC: 256-bit output",
    )

    # ---------------------------------------------------------------------------
    # PBE / PBA mechanisms (password-based encryption/authentication)
    # CKM_PKCS5_PBKD2 is registered in _kdf.py — not duplicated here.
    # ---------------------------------------------------------------------------

    registry[CKM_PBE_MD2_DES_CBC] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_GENERATE,
        notes="PBE: MD2 + DES-CBC key/IV derivation (PKCS#5 v1, obsolete)",
    )

    registry[CKM_PBE_MD5_DES_CBC] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_GENERATE,
        notes="PBE: MD5 + DES-CBC key/IV derivation (PKCS#5 v1, deprecated)",
    )

    registry[CKM_PBE_MD5_CAST_CBC] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_GENERATE,
        notes="PBE: MD5 + CAST-CBC key/IV derivation",
    )

    registry[CKM_PBE_MD5_CAST3_CBC] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_GENERATE,
        notes="PBE: MD5 + CAST3-CBC key/IV derivation",
    )

    registry[CKM_PBE_MD5_CAST128_CBC] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_GENERATE,
        notes="PBE: MD5 + CAST128-CBC key/IV derivation (alias CKM_PBE_MD5_CAST5_CBC)",
    )

    registry[CKM_PBE_SHA1_CAST128_CBC] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_GENERATE,
        notes="PBE: SHA-1 + CAST128-CBC key/IV derivation (alias CKM_PBE_SHA1_CAST5_CBC)",
    )

    registry[CKM_PBE_SHA1_RC4_128] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_GENERATE,
        notes="PBE: SHA-1 + RC4-128 key derivation (PKCS#12)",
    )

    registry[CKM_PBE_SHA1_RC4_40] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_GENERATE,
        notes="PBE: SHA-1 + RC4-40 key derivation (PKCS#12)",
    )

    registry[CKM_PBE_SHA1_DES3_EDE_CBC] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_GENERATE,
        notes="PBE: SHA-1 + 3DES-EDE-CBC key/IV derivation (PKCS#12)",
    )

    registry[CKM_PBE_SHA1_DES2_EDE_CBC] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_GENERATE,
        notes="PBE: SHA-1 + 2DES-EDE-CBC key/IV derivation (PKCS#12)",
    )

    registry[CKM_PBE_SHA1_RC2_128_CBC] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_GENERATE,
        notes="PBE: SHA-1 + RC2-128-CBC key/IV derivation (PKCS#12)",
    )

    registry[CKM_PBE_SHA1_RC2_40_CBC] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_GENERATE,
        notes="PBE: SHA-1 + RC2-40-CBC key/IV derivation (PKCS#12)",
    )

    registry[CKM_PBA_SHA1_WITH_SHA1_HMAC] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_GENERATE,
        notes="PBA: SHA-1 HMAC key derivation (password-based authentication)",
    )

    # ---------------------------------------------------------------------------
    # KEA (Key Exchange Algorithm — Fortezza)
    # ---------------------------------------------------------------------------

    registry[CKM_KEA_KEY_PAIR_GEN] = MechConfig(
        key_type=CKK_KEA,
        keygen_mech=CKM_KEA_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_kea,
        expected_flags=CKF_GENERATE_KEY_PAIR,
        notes="KEA key pair generation (Key Exchange Algorithm, Fortezza/DSS-based)",
    )

    registry[CKM_KEA_KEY_DERIVE] = MechConfig(
        key_type=CKK_KEA,
        keygen_mech=CKM_KEA_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_kea,
        expected_flags=CKF_DERIVE,
        notes="KEA key derivation (shared secret from KEA key exchange)",
    )

    registry[CKM_KEA_DERIVE] = MechConfig(
        key_type=CKK_KEA,
        keygen_mech=CKM_KEA_KEY_PAIR_GEN,
        key_sizes=(),
        is_keypair=True,
        keygen_recipe=_kea,
        expected_flags=CKF_DERIVE,
        notes="KEA derive (v3.x alias for CKM_KEA_KEY_DERIVE)",
    )

    # ---------------------------------------------------------------------------
    # Fortezza timestamp
    # ---------------------------------------------------------------------------

    registry[CKM_FORTEZZA_TIMESTAMP] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        expected_flags=CKF_SIGN,
        notes="Fortezza timestamp mechanism: signed timestamp using Skipjack/KEA token",
    )

    # ---------------------------------------------------------------------------
    # OTP mechanisms (SecurID / HOTP / ACTI)
    # ---------------------------------------------------------------------------

    registry[CKM_SECURID_KEY_GEN] = MechConfig(
        key_type=None,
        keygen_mech=CKM_SECURID_KEY_GEN,
        key_sizes=(),
        expected_flags=CKF_GENERATE,
        notes="SecurID OTP seed key generation",
    )

    registry[CKM_SECURID] = MechConfig(
        key_type=None,
        keygen_mech=CKM_SECURID_KEY_GEN,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_SIGN | CKF_VERIFY | CKF_GENERATE,
        notes="SecurID OTP computation (RSA SecurID token algorithm)",
    )

    registry[CKM_HOTP_KEY_GEN] = MechConfig(
        key_type=None,
        keygen_mech=CKM_HOTP_KEY_GEN,
        key_sizes=(),
        expected_flags=CKF_GENERATE,
        notes="HOTP seed key generation (HMAC-based One-Time Password, RFC 4226)",
    )

    registry[CKM_HOTP] = MechConfig(
        key_type=None,
        keygen_mech=CKM_HOTP_KEY_GEN,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_SIGN | CKF_VERIFY | CKF_GENERATE,
        notes="HOTP computation (RFC 4226 HMAC-based OTP)",
    )

    registry[CKM_ACTI_KEY_GEN] = MechConfig(
        key_type=None,
        keygen_mech=CKM_ACTI_KEY_GEN,
        key_sizes=(),
        expected_flags=CKF_GENERATE,
        notes="ACTI OTP seed key generation",
    )

    registry[CKM_ACTI] = MechConfig(
        key_type=None,
        keygen_mech=CKM_ACTI_KEY_GEN,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_SIGN | CKF_VERIFY | CKF_GENERATE,
        notes="ACTI OTP computation",
    )

    # ---------------------------------------------------------------------------
    # CMS / KIP mechanisms
    # ---------------------------------------------------------------------------

    registry[CKM_CMS_SIG] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=_SIG_VER,
        notes="CMS signature: Cryptographic Message Syntax (PKCS#7/CMS) sign/verify",
    )

    registry[CKM_KIP_DERIVE] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_DERIVE,
        notes="KIP key derivation (Key and IV Protection, NIST SP 800-56B supplement)",
    )

    registry[CKM_KIP_WRAP] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=CKF_WRAP | CKF_DECRYPT,
        notes="KIP key wrapping",
    )

    registry[CKM_KIP_MAC] = MechConfig(
        key_type=None,
        keygen_mech=None,
        key_sizes=(),
        param_required=True,
        expected_flags=_SIG_VER,
        notes="KIP MAC computation",
    )
