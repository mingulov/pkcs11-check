"""Crash-safe probe for an ML-DSA key imported without ``CKA_PARAMETER_SET``.

A conformant module must reject a ``C_CreateObject`` template for
``CKO_PRIVATE_KEY`` / ``CKK_ML_DSA`` that omits ``CKA_PARAMETER_SET`` with
``CKR_TEMPLATE_INCOMPLETE`` (or another clean reject code).  A module that
silently creates the param-less key may crash or produce undefined output when
the module's ML-DSA key-init path attempts to use an uninitialised parameter set.

Note: some modules do not advertise ``CKM_ML_DSA``; this probe is gated behind
``rs.has_mechanism("ML_DSA")`` and will cleanly skip if not available.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess, pytest.mark.pqc]

# A conformant module must reject a param-less ML-DSA create with one of these.
_PARAMLESS_REJECT_RVS = (
    CKR_TEMPLATE_INCOMPLETE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
)


def _parse_rv(output: str, prefix: str) -> int | None:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    return None


class TestMLDSAMissingParamSet:
    """``C_CreateObject`` with a param-less ML-DSA private-key template.

    A conformant module must reject a ``CKO_PRIVATE_KEY`` / ``CKK_ML_DSA``
    template that omits ``CKA_PARAMETER_SET``; it must never crash.
    """

    def test_mldsa_create_without_param_set_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_CreateObject(CKK_ML_DSA) with no CKA_PARAMETER_SET must reject cleanly.

        A missing ``CKA_PARAMETER_SET`` means the module's ML-DSA key-init path
        receives no parameter set; a module that silently accepts the template may
        crash or produce undefined output when signing.  A conformant module rejects
        the template at create time.  If the module accepts it, C_SignInit +
        C_Sign are also attempted -- a crash at any step is the finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ML_DSA"):
            pytest.skip("CKM_ML_DSA not advertised")

        result = run_probe(
            "mldsa_missing_param_set",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "create_without_param_set",
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_CreateObject(CKO_PRIVATE_KEY/CKK_ML_DSA, no CKA_PARAMETER_SET)",
        )

        # Parse CREATE_RV and classify the module's response.
        create_rv = _parse_rv(stdout, "CREATE_RV:")
        assert create_rv is not None, f"probe did not report CREATE_RV: {stdout[-300:]}"

        classify_negative_rv(
            create_rv,
            _PARAMLESS_REJECT_RVS,
            label="C_CreateObject(CKK_ML_DSA, no CKA_PARAMETER_SET)",
        )

        # When create succeeded, classify the sign outcome too.
        sign_rv = _parse_rv(stdout, "SIGN_RV:")
        if sign_rv is not None:
            classify_negative_rv(
                sign_rv,
                (CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_KEY_HANDLE_INVALID, CKR_ARGUMENTS_BAD),
                label="C_Sign with param-less ML-DSA key",
                allow_ok=True,
            )
