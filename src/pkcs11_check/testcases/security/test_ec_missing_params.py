"""Crash-safe probes for EC keys imported without ``CKA_EC_PARAMS``.

An EC key created without ``CKA_EC_PARAMS`` has no curve. A conformant module must
reject the incomplete template (e.g. ``CKR_TEMPLATE_INCOMPLETE``) and must never
dereference a missing curve pointer during create / C_GetAttributeValue / C_Sign /
C_Verify / C_DeriveKey. These crash-safe probes assert no crash and classify the
create result.

The C_VerifyInit probe is no-crash-only: the precondition (C_CreateObject success
for a bare public-key template) is expected to be unreachable on a conformant module.
Any clean error is classified via ``classify_negative_rv``; a crash is a finding.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

# A conformant module rejects a curve-less EC template with one of these.
_CURVELESS_REJECT_RVS = (
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
)


def _parse_rv(output: str, prefix: str) -> int | None:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    return None


class TestEcMissingParams:
    """EC create/use without ``CKA_EC_PARAMS``: must reject cleanly, never crash."""

    def test_public_key_import_no_ec_params_does_not_crash(
        self,
        p11_config: Any,
    ) -> None:
        """C_CreateObject with CKA_EC_POINT but no CKA_EC_PARAMS must not crash.

        A conformant module must reject the incomplete template at create time.
        Any crash is a finding.
        """
        result = run_probe(
            "ec_missing_params",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "public_no_params",
            },
            pin=pin_from_config(p11_config),
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_CreateObject(EC public, no CKA_EC_PARAMS)",
        )
        rv = _parse_rv(result.stdout, "CREATE_RV:")
        assert rv is not None, f"probe did not report CREATE_RV: {result.stdout[-300:]}"
        classify_negative_rv(
            rv,
            _CURVELESS_REJECT_RVS,
            label="C_CreateObject EC public no EC_PARAMS",
        )

    def test_get_ec_params_on_curveless_private_key_does_not_crash(
        self,
        p11_config: Any,
    ) -> None:
        """C_GetAttributeValue(CKA_EC_PARAMS) on a curve-less key must not crash.

        A conformant module rejects the create; if the object is created, reading
        CKA_EC_PARAMS must return a clean error, not crash.
        """
        result = run_probe(
            "ec_missing_params",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "get_ec_params_private",
            },
            pin=pin_from_config(p11_config),
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_GetAttributeValue(CKA_EC_PARAMS) curve-less key",
        )
        rv = _parse_rv(result.stdout, "CREATE_RV:")
        assert rv is not None, f"probe did not report CREATE_RV: {result.stdout[-300:]}"
        classify_negative_rv(
            rv,
            _CURVELESS_REJECT_RVS,
            label="C_CreateObject EC private no EC_PARAMS",
        )

    @pytest.mark.parametrize(
        ("cls_name", "include_value"),
        (
            pytest.param("CKO_PRIVATE_KEY", True, id="private_with_value"),
            pytest.param("CKO_PUBLIC_KEY", False, id="public_bare"),
        ),
    )
    def test_get_ec_point_on_curveless_key_does_not_crash(
        self,
        p11_config: Any,
        cls_name: str,
        include_value: bool,
    ) -> None:
        """C_GetAttributeValue(CKA_EC_POINT) on a curve-less key must not crash.

        Two distinct templates:
        - private_with_value: CKO_PRIVATE_KEY + CKK_EC + CKA_VALUE (3-attr) —
          then C_GetAttributeValue(CKA_EC_POINT).
        - public_bare: CKO_PUBLIC_KEY + CKK_EC only (2-attr, no VALUE/POINT/PARAMS)
          — then C_GetAttributeValue(CKA_EC_POINT).

        A conformant module rejects the create; if the object is created, reading
        CKA_EC_POINT must return a clean error, not crash.
        """
        which = "get_ec_point_private" if include_value else "get_ec_point_public"
        result = run_probe(
            "ec_missing_params",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": which,
            },
            pin=pin_from_config(p11_config),
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_GetAttributeValue(CKA_EC_POINT) curve-less {cls_name}",
        )
        rv = _parse_rv(result.stdout, "CREATE_RV:")
        assert rv is not None, f"probe did not report CREATE_RV: {result.stdout[-300:]}"
        classify_negative_rv(
            rv,
            _CURVELESS_REJECT_RVS,
            label=f"C_CreateObject {cls_name} no EC_PARAMS",
        )

    def test_ecdh_derive_curveless_base_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_DeriveKey(CKM_ECDH1_DERIVE) with a curve-less base key must not crash.

        A conformant module rejects the curve-less create; if the create succeeds,
        the derive call must return a clean error, not crash.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not advertised")
        result = run_probe(
            "ec_missing_params",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "ecdh_derive",
            },
            pin=pin_from_config(p11_config),
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_DeriveKey(ECDH1, curve-less base)",
        )
        rv = _parse_rv(result.stdout, "CREATE_RV:")
        assert rv is not None, f"probe did not report CREATE_RV: {result.stdout[-300:]}"
        classify_negative_rv(
            rv,
            _CURVELESS_REJECT_RVS,
            label="C_CreateObject EC private no EC_PARAMS (ECDH probe)",
        )

    def test_sign_with_curveless_private_key_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_Sign(CKM_ECDSA) with a curve-less private key must not crash.

        Complements x509/test_identity.py (DER import) with a minimal raw-template
        trigger: create a curve-less private key via C_CreateObject, then attempt
        C_SignInit(CKM_ECDSA) + C_Sign with a 32-byte digest. A conformant module
        rejects the create; any crash at create or sign time is a finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not advertised")
        result = run_probe(
            "ec_missing_params",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "sign_private",
            },
            pin=pin_from_config(p11_config),
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_Sign(ECDSA, curve-less private key)",
        )
        rv = _parse_rv(result.stdout, "CREATE_RV:")
        assert rv is not None, f"probe did not report CREATE_RV: {result.stdout[-300:]}"
        classify_negative_rv(
            rv,
            _CURVELESS_REJECT_RVS,
            label="C_CreateObject EC private no EC_PARAMS (sign probe)",
        )

    def test_verify_with_curveless_public_key_does_not_crash(
        self,
        p11_config: Any,
    ) -> None:
        """C_Verify(CKM_ECDSA) with a curve-less public key must not crash — conditional probe.

        A curve-less public key should not be constructible via C_CreateObject on
        a conformant module. This probe attempts the create anyway (bare public key:
        CKA_CLASS + CKA_KEY_TYPE + CKA_EC_POINT, no CKA_EC_PARAMS); if the create
        is rejected (the conformant case), the rejection is classified via
        classify_negative_rv. If the create succeeds (the bug precondition),
        C_VerifyInit + C_Verify are exercised and any crash is a finding.
        Because the precondition may be unreachable, this probe is no-crash-only:
        any clean error at any stage is classified, never hard-failed.
        """
        result = run_probe(
            "ec_missing_params",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "verify_public",
            },
            pin=pin_from_config(p11_config),
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context="C_Verify(ECDSA, curve-less public key)",
        )
        rv = _parse_rv(result.stdout, "CREATE_RV:")
        assert rv is not None, f"probe did not report CREATE_RV: {result.stdout[-300:]}"
        classify_negative_rv(
            rv,
            _CURVELESS_REJECT_RVS,
            label="C_CreateObject EC public no EC_PARAMS (verify probe)",
        )
