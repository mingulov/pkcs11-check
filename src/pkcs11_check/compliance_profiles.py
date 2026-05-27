"""PKCS#11 v3.2 conformance-profile requirement tables.

Transcribed from OASIS PKCS#11 Profiles v3.2 §5 (Base Profiles).
Each `ProfileRequirements` describes the *mandatory* functions, object
classes, attributes, and mechanisms a conformant implementation of that
profile must support.

Source: docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.2/cs01/
        pkcs11-profiles-v3.2-cs01.html  (sections 5.1–5.6).

A module that advertises `CKO_PROFILE` with a given `CKA_PROFILE_ID`
asserts conformance to the corresponding profile.  Verifying that
conformance — that every mandated function is present in the function
list, every mandated mechanism is in `C_GetMechanismList`, etc. — is
the role of `TestProfileBehavioralConformance` in `test_profiles.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pkcs11_check.raw.types_std import (
    CKM_HKDF_DATA,
    CKO_CERTIFICATE,
    CKO_DATA,
    CKO_PRIVATE_KEY,
    CKO_PROFILE,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKP_AUTHENTICATION_TOKEN,
    CKP_BASELINE_PROVIDER,
    CKP_EXTENDED_PROVIDER,
    CKP_PUBLIC_CERTIFICATES_TOKEN,
)

# CKP_HKDF_TLS_TOKEN may not be defined as a typed constant; use literal.
CKP_HKDF_TLS_TOKEN_VALUE = 0x00000006
# CKP_COMPLETE_PROVIDER per spec §5.2 — too broad to test piecewise;
# we list it but the behavioral test skips it.
CKP_COMPLETE_PROVIDER_VALUE = 0x00000005


@dataclass(frozen=True)
class ProfileRequirements:
    """Mandatory items a profile imposes on a conformant module.

    Attributes are sets-of-int (or sets-of-str for function names so
    we can match against the module's `available_function_names()`
    output directly).
    """

    profile_id: int
    profile_name: str
    required_functions: frozenset[str] = field(default_factory=frozenset)
    required_object_classes: frozenset[int] = field(default_factory=frozenset)
    required_attributes: frozenset[int] = field(default_factory=frozenset)
    required_mechanisms: frozenset[int] = field(default_factory=frozenset)
    inherits_from: int | None = None


# --- Baseline Provider (§5.1) -------------------------------------------------

_BASELINE_FUNCTIONS = frozenset(
    {
        "C_GetFunctionList",
        "C_GetInterfaceList",
        "C_GetInterface",
        "C_Initialize",
        "C_Finalize",
        "C_GetInfo",
        "C_GetSlotList",
        "C_GetSlotInfo",
        "C_GetTokenInfo",
        "C_OpenSession",
        "C_CloseSession",
        "C_GetSessionInfo",
        "C_FindObjectsInit",
        "C_FindObjects",
        "C_FindObjectsFinal",
        "C_GetAttributeValue",
    }
)


BASELINE_PROVIDER = ProfileRequirements(
    profile_id=int(CKP_BASELINE_PROVIDER),
    profile_name="Baseline Provider",
    required_functions=_BASELINE_FUNCTIONS,
    required_object_classes=frozenset({int(CKO_PROFILE)}),
)


# --- Extended Provider (§5.3, builds on Baseline) ----------------------------

EXTENDED_PROVIDER = ProfileRequirements(
    profile_id=int(CKP_EXTENDED_PROVIDER),
    profile_name="Extended Provider",
    required_functions=_BASELINE_FUNCTIONS
    | frozenset(
        {
            "C_GetMechanismList",
            "C_GetMechanismInfo",
            "C_Login",
            "C_LoginUser",
            "C_Logout",
        }
    ),
    required_object_classes=frozenset({int(CKO_PROFILE)}),
    inherits_from=int(CKP_BASELINE_PROVIDER),
)


# --- Authentication Token (§5.4, builds on Baseline) -------------------------

# Spec: "C_Sign and/or C_SignUpdate and C_SignFinal" — we treat the
# requirement as "at least C_SignInit + one of (C_Sign | (C_SignUpdate + C_SignFinal))".
# Since enforcing the "either-or" needs custom logic, the table lists
# C_SignInit + C_Sign as the standard path; the test relaxes the others.

AUTHENTICATION_TOKEN = ProfileRequirements(
    profile_id=int(CKP_AUTHENTICATION_TOKEN),
    profile_name="Authentication Token",
    required_functions=_BASELINE_FUNCTIONS
    | frozenset(
        {
            "C_Login",
            "C_LoginUser",
            "C_Logout",
            "C_SignInit",
            # Either C_Sign OR (C_SignUpdate + C_SignFinal) — handled in test.
        }
    ),
    required_object_classes=frozenset(
        {int(CKO_PROFILE), int(CKO_PRIVATE_KEY), int(CKO_PUBLIC_KEY)}
    ),
    inherits_from=int(CKP_BASELINE_PROVIDER),
)


# --- Public Certificates Token (§5.5, builds on Baseline) --------------------

PUBLIC_CERTIFICATES_TOKEN = ProfileRequirements(
    profile_id=int(CKP_PUBLIC_CERTIFICATES_TOKEN),
    profile_name="Public Certificates Token",
    required_functions=_BASELINE_FUNCTIONS,
    required_object_classes=frozenset({int(CKO_PROFILE), int(CKO_CERTIFICATE)}),
    inherits_from=int(CKP_BASELINE_PROVIDER),
)


# --- HKDF TLS Token (§5.6, builds on Baseline) -------------------------------

HKDF_TLS_TOKEN = ProfileRequirements(
    profile_id=CKP_HKDF_TLS_TOKEN_VALUE,
    profile_name="HKDF TLS Token",
    required_functions=_BASELINE_FUNCTIONS | frozenset({"C_DeriveKey"}),
    required_object_classes=frozenset({int(CKO_PROFILE), int(CKO_DATA), int(CKO_SECRET_KEY)}),
    required_mechanisms=frozenset({int(CKM_HKDF_DATA)}),
    inherits_from=int(CKP_BASELINE_PROVIDER),
)


# --- Profile lookup ----------------------------------------------------------

PROFILE_TABLE: dict[int, ProfileRequirements] = {
    int(CKP_BASELINE_PROVIDER): BASELINE_PROVIDER,
    int(CKP_EXTENDED_PROVIDER): EXTENDED_PROVIDER,
    int(CKP_AUTHENTICATION_TOKEN): AUTHENTICATION_TOKEN,
    int(CKP_PUBLIC_CERTIFICATES_TOKEN): PUBLIC_CERTIFICATES_TOKEN,
    CKP_HKDF_TLS_TOKEN_VALUE: HKDF_TLS_TOKEN,
}


# Profile IDs that exist in the spec but are excluded from behavioral
# conformance tests because they're too broad ("all of the spec") or
# defined as consumer-side requirements.
PROFILE_TEST_EXCLUDED: frozenset[int] = frozenset(
    {
        CKP_COMPLETE_PROVIDER_VALUE,
    }
)


def lookup_profile(profile_id: int) -> ProfileRequirements | None:
    """Return the profile requirements record, or None if unknown."""
    return PROFILE_TABLE.get(profile_id)


__all__ = [
    "AUTHENTICATION_TOKEN",
    "BASELINE_PROVIDER",
    "CKP_COMPLETE_PROVIDER_VALUE",
    "CKP_HKDF_TLS_TOKEN_VALUE",
    "EXTENDED_PROVIDER",
    "HKDF_TLS_TOKEN",
    "PROFILE_TABLE",
    "PROFILE_TEST_EXCLUDED",
    "PUBLIC_CERTIFICATES_TOKEN",
    "ProfileRequirements",
    "lookup_profile",
]
