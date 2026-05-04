"""Per-module CKR-quirk registry.

Some PKCS#11 modules return non-spec-conformant CKR codes for documented
reasons (e.g. Kryoptic uses CKR_DEVICE_ERROR for any verification failure
instead of the more specific CKR_SIGNATURE_INVALID / CKR_ENCRYPTED_DATA_INVALID).

Tests that want to accept those codes as fallbacks **must** declare the
intent explicitly via this registry rather than hard-coding them in the
accepted-CKR list. That keeps three properties:

1.  Each quirk is documented in one place with a spec reference and a
    pointer to ``docs/module-issues.md``.
2.  Tests stay strict for *every other* module — a fallback only relaxes
    the assertion for the module the quirk was attributed to.
3.  Adding a new fallback CKR forces a code change in this file, which
    shows up in PR review and in ``git blame`` of the quirk entry.

Anti-masking rule (per ``feedback_pkcs11check_philosophy``): do NOT add a
quirk just to silence a test that fails. A quirk is only valid if the
module's behaviour is documented as a known deviation in
``docs/module-issues.md`` and the wrong CKR still indicates the same
*security outcome* as the spec-conformant CKR (e.g. integrity check did
detect tampering, just reported with the wrong code).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_DEVICE_ERROR,
    CKR_GENERAL_ERROR,
)


class ModuleId(Enum):
    """Identity of the PKCS#11 module under test, derived from its library path."""

    SOFTHSM2 = "softhsm2"
    KRYOPTIC = "kryoptic"
    NSS = "nss"
    OPENCRYPTOKI = "opencryptoki"
    TPM2 = "tpm2"
    BOUNCYHSM = "bouncyhsm"
    QRYPTOTOKEN = "qryptotoken"
    PKCS11_MOCK = "pkcs11_mock"
    UNKNOWN = "unknown"


def detect_module(p11_config: Any) -> ModuleId:
    """Identify the module from its library path.

    The mapping is deliberately tolerant of common naming variations
    (``softokn3`` for NSS, ``libkryoptic_pkcs11.so``, etc.). Returns
    ``ModuleId.UNKNOWN`` for anything that doesn't match a known pattern;
    quirk lookups against UNKNOWN return no extras, so unknown modules
    get the strictest assertions by default.
    """
    if p11_config is None:
        return ModuleId.UNKNOWN
    try:
        path = str(p11_config.module).lower()
    except AttributeError:
        return ModuleId.UNKNOWN

    if "softhsm" in path:
        return ModuleId.SOFTHSM2
    if "kryoptic" in path:
        return ModuleId.KRYOPTIC
    if "softokn" in path or path.endswith("nss/libnss3.so"):
        return ModuleId.NSS
    if "opencryptoki" in path or "/pkcs11_api.so" in path:
        return ModuleId.OPENCRYPTOKI
    if "tpm2" in path:
        return ModuleId.TPM2
    if "bouncyhsm" in path or "bouncy" in path:
        return ModuleId.BOUNCYHSM
    if "qrypto" in path:
        return ModuleId.QRYPTOTOKEN
    if "pkcs11-mock" in path or "pkcs11_mock" in path:
        return ModuleId.PKCS11_MOCK
    return ModuleId.UNKNOWN


@dataclass(frozen=True)
class Quirk:
    """A documented per-module CKR deviation.

    Fields:
        description: short explanation of what the module does instead of the
            spec-conformant CKR.
        spec_ref: PKCS#11 spec section that defines the conformant behaviour.
        issue_ref: heading inside ``docs/module-issues.md`` that documents
            the deviation and its severity.
        extra_ckrs: CKR codes the module returns *in addition to* (or
            instead of) the spec-conformant codes for the situation
            identified by the quirk key.
    """

    description: str
    spec_ref: str
    issue_ref: str
    extra_ckrs: tuple[int, ...]


# Each top-level key is a ModuleId; each inner key is a quirk-name string used
# at the test call site. Quirk names must be globally unique and stable —
# changing one is a breaking change for every test that uses it.
MODULE_QUIRKS: dict[ModuleId, dict[str, Quirk]] = {
    ModuleId.KRYOPTIC: {
        "verify_or_integrity_failure": Quirk(
            description=(
                "Kryoptic returns CKR_DEVICE_ERROR (0x30) for any "
                "verification or integrity-check failure (signature "
                "verify, AEAD tag, AES-KEY-WRAP RFC-3394 ICV, etc.) "
                "instead of the spec-specific code "
                "(CKR_SIGNATURE_INVALID / CKR_ENCRYPTED_DATA_INVALID / "
                "CKR_WRAPPED_KEY_INVALID). The check itself IS happening; "
                "only the reported code is wrong."
            ),
            spec_ref="PKCS#11 v3.1 Sec.5.13.2 / Sec.5.14.4 / Sec.6.13.6",
            issue_ref=("docs/module-issues.md Kryoptic §CKR_DEVICE_ERROR on verify failure"),
            extra_ckrs=(CKR_DEVICE_ERROR,),
        ),
    },
    ModuleId.OPENCRYPTOKI: {
        "unwrap_template_class_keytype_rejected": Quirk(
            description=(
                "OpenCryptoki rejects unwrap templates that include "
                "CKA_CLASS or CKA_KEY_TYPE with CKR_ATTRIBUTE_READ_ONLY "
                "before any cryptographic check happens. The behaviour "
                "is consistent across CKM_AES_KEY_WRAP / "
                "CKM_ECDH_AES_KEY_WRAP and the same template that other "
                "modules accept. Tests that assert 'unwrap rejects X' "
                "still observe a rejection — just with this CKR rather "
                "than the spec-conformant code."
            ),
            spec_ref="PKCS#11 v3.1 Sec.5.14.4",
            issue_ref=(
                "docs/module-issues.md OpenCryptoki §"
                "Unwrap-template attribute rejection (CKR_ATTRIBUTE_READ_ONLY"
            ),
            extra_ckrs=(CKR_ATTRIBUTE_READ_ONLY,),
        ),
    },
    ModuleId.SOFTHSM2: {
        "size_range_on_wrap": Quirk(
            description=(
                "SoftHSM2 accepts undersized AES keys at C_CreateObject "
                "(no FIPS 197 size validation) and then returns "
                "CKR_GENERAL_ERROR (0x05) on C_WrapKey instead of "
                "CKR_WRAPPING_KEY_SIZE_RANGE / CKR_KEY_SIZE_RANGE. The "
                "wrap is rejected; only the reported code is wrong."
            ),
            spec_ref="PKCS#11 v3.1 Sec.5.14.3 / FIPS 197 §6.1",
            issue_ref=("docs/module-issues.md SoftHSM2 main §Accepts undersized AES wrap key"),
            extra_ckrs=(CKR_GENERAL_ERROR,),
        ),
    },
}


def quirk_extras(p11_config: Any, quirk_key: str) -> tuple[int, ...]:
    """Return the extra CKRs for the running module under ``quirk_key``.

    Returns ``()`` if no quirk applies — unknown modules and modules
    without a registered quirk get the strictest assertions.

    Use sparingly. Each accepted-CKR fallback is a documented spec
    deviation that masks the cleanest enforcement of the rule. If you
    find yourself adding a new fallback to silence a failing test on a
    NEW module, that is almost certainly a real module bug — file it in
    ``docs/module-issues.md`` first, then add a quirk only if the
    deviation is genuinely a different CKR for the *same security
    outcome*.

    Args:
        p11_config: the ``p11_config`` fixture (has a ``module`` attribute
            pointing at the library path).
        quirk_key: the named quirk to look up (e.g.
            ``"verify_or_integrity_failure"``).

    Returns:
        Tuple of CKR ints to add to the test's accepted-CKR list, or
        ``()`` if no quirk applies.
    """
    module_id = detect_module(p11_config)
    quirks_for_module = MODULE_QUIRKS.get(module_id, {})
    quirk = quirks_for_module.get(quirk_key)
    return quirk.extra_ckrs if quirk else ()


def known_quirk_keys() -> frozenset[str]:
    """All declared quirk-name strings across all modules.

    Used by the meta-test in ``tests/test_module_quirks.py`` to verify
    that every quirk_key argument used in test files actually exists.
    """
    keys: set[str] = set()
    for module_quirks in MODULE_QUIRKS.values():
        keys.update(module_quirks.keys())
    return frozenset(keys)
