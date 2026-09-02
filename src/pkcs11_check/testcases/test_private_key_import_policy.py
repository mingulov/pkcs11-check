"""Conformance: C_CreateObject must accept the spec-legal private-key policy template.

PKCS#11 lists CKA_SENSITIVE and CKA_EXTRACTABLE as attributes that are *set at object
creation*; the §10.7 "one-way" rule (CKA_SENSITIVE false->true, CKA_EXTRACTABLE true->false)
governs *modification* of an existing object via C_SetAttributeValue, NOT the initial values
supplied to C_CreateObject. So importing a private key with the universal template
``CKA_SENSITIVE=false`` / ``CKA_EXTRACTABLE=true`` must be accepted by a module that implements
private-key import.

This is the single, focused conformance probe for that property. It exists because the KAT
suites (ECDH / X25519 / RSA-OAEP / RSA-decrypt) deliberately *negotiate* the storage shape —
they drop the benign policy attrs on a clean shape reject so the crypto KAT still runs — which
means a module that rejects the standard policy shape would otherwise leave no visible record.
Here it surfaces as exactly one recorded deviation.

Observed deviation: some modules return CKR_ATTRIBUTE_READ_ONLY for this template,
because they apply the §10.7 one-way constraint at creation time (new objects default
extractable=false / sensitive=true). Such a module can still import the key with the policy
attrs omitted (the negotiation path the KATs use), so this is a clean single deviation -> xfail
(not_operational), not a crash or crypto-correctness break.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import destroy_quietly, import_ec_private_key
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._provisioning import skip_unless_can_create
from pkcs11_check.testcases.conftest import xfail_if_known_ckr

pytestmark = pytest.mark.keymgmt

# P-256 named-curve OID DER (1.2.840.10045.3.1.7) + a valid in-range scalar.
_EC_P256_PARAMS = bytes.fromhex("06082a8648ce3d030107")
_EC_P256_SCALAR = b"\x01" * 32

# Clean refusals of the spec-legal policy template. CKR_ATTRIBUTE_READ_ONLY covers modules
# that misapply the one-way rule at create; the template/attribute codes cover other
# modules that decline the standard policy shape. Any OTHER CKR (or a crash) is NOT in this
# set and therefore surfaces as a real failure via xfail_if_known_ckr's re-raise.
_STD_POLICY_IMPORT_REFUSED = (
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)


def test_ec_private_key_import_accepts_standard_policy_attrs(p11_module_session: Any) -> None:
    """Import an EC P-256 private key with CKA_SENSITIVE=false / CKA_EXTRACTABLE=true.

    pass:  C_CreateObject returns CKR_OK (the spec-legal template is accepted).
    skip:  module implements no C_CreateObject, or no private-key import (FUNCTION_NOT_SUPPORTED).
    xfail: clean refusal of the standard policy shape (e.g. CKR_ATTRIBUTE_READ_ONLY).
    fail:  any other CKR, or a crash (surfaced by the isolated runner).
    """
    rs = p11_module_session
    skip_unless_can_create(rs, "private")

    try:
        handle = import_ec_private_key(
            rs.raw,
            rs.sh,
            ec_params=_EC_P256_PARAMS,
            value=_EC_P256_SCALAR,
            attrs={
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
        )
    except CkrAssertionError as exc:
        if exc.rv == int(CKR_FUNCTION_NOT_SUPPORTED):
            pytest.skip("Module does not implement private-key C_CreateObject import")
        xfail_if_known_ckr(
            exc,
            _STD_POLICY_IMPORT_REFUSED,
            "C_CreateObject refuses spec-legal EC private-key import template "
            "(CKA_SENSITIVE=false / CKA_EXTRACTABLE=true); these are settable at creation "
            "(§10.7 one-way applies to C_SetAttributeValue, not C_CreateObject)",
        )
        raise  # defensive: xfail_if_known_ckr re-raises on an unlisted CKR
    destroy_quietly(rs.raw, rs.sh, handle)
