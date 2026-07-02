"""CKR attribute permission tests via raw ctypes calls.

Tests CKR_KEY_FUNCTION_NOT_PERMITTED by creating keys with specific
CKA_* attributes set to False, then using raw C_*Init calls that
bypass the python-pkcs11 wrapper's attribute checks.

Each test launches the ``ckr_raw_attrs`` probe module (``_probes/ckr_raw_attrs.py``)
via ``run_probe`` at ``Level.LOGIN``: the probe infra opens a session and -- only when a
PIN is configured -- logs in, with the PIN travelling solely through the ``_P11CHECK_PIN``
env var (never embedded in source or params -- Invariant I3).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok
from pkcs11_check.testcases.conftest import classify_policy_enforcement

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


def _classify_permission_flag(out: str, *, label: str) -> None:
    """policy claim/effect-check from subprocess output.

    The subprocess prints ``CLAIM:0`` (the key read the permission flag back as
    False -- the module claims the restriction) or ``CLAIM:1`` (the flag was not
    honored), and ``CKR:0x...`` for the C_*Init result:

    - claimed (``CLAIM:0``) AND the op returned CKR_OK -> fail (the restriction
      was claimed then ignored -- a self-contradiction),
    - not claimed (``CLAIM:1``) -> xfail (module did not honor the flag at
      create; honest non-support),
    - claimed AND the op was rejected -> pass.
    """
    claimed = "CLAIM:0" in out
    violated = "CKR:0x00000000" in out
    classify_policy_enforcement(claimed=claimed, violated=violated, label=label)


def _run_probe(p11_config: Any, probe: str) -> tuple[int, str, str]:
    result = run_probe(
        "ckr_raw_attrs",
        {"module_path": str(p11_config.module), "probe": probe},
        pin=pin_from_config(p11_config),
        timeout=15,
        coverage="session",
    )
    return result.returncode, result.stdout, result.stderr


class TestKeyFunctionNotPermitted:
    """Keys with CKA_*=False tested via raw C_*Init calls."""

    def test_encrypt_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_ENCRYPT=False -> C_EncryptInit -> CKR_KEY_FUNCTION_NOT_PERMITTED.

        PKCS#11 v3.2: If CKA_ENCRYPT is False, C_EncryptInit MUST return
        CKR_KEY_FUNCTION_NOT_PERMITTED. Some modules return CKR_OK, meaning the key
        permission flag is silently ignored -- keys without CKA_ENCRYPT=True can still
        be used to encrypt. This is a security finding.
        """
        rc, out, err = _run_probe(p11_config, "encrypt")
        assert_ckr_subprocess_ok(rc, out, err, context="C_EncryptInit with CKA_ENCRYPT=False")
        # policy: enforcing CKA_ENCRYPT=False is mandatory (PKCS#11 v3.2).
        # claimed = the key read CKA_ENCRYPT back as False; violated = EncryptInit
        # still returned CKR_OK.
        _classify_permission_flag(
            out,
            label="C_EncryptInit with a CKA_ENCRYPT=False key "
            "(PKCS#11 v3.2 requires CKR_KEY_FUNCTION_NOT_PERMITTED)",
        )

    def test_sign_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_SIGN=False -> C_SignInit -> CKR_KEY_FUNCTION_NOT_PERMITTED."""
        rc, out, err = _run_probe(p11_config, "sign")
        assert_ckr_subprocess_ok(rc, out, err, context="C_SignInit with CKA_SIGN=False")
        # policy: enforcing CKA_SIGN=False is mandatory (PKCS#11 v3.2).
        _classify_permission_flag(
            out,
            label="C_SignInit with a CKA_SIGN=False key "
            "(PKCS#11 v3.2 requires CKR_KEY_FUNCTION_NOT_PERMITTED)",
        )

    def test_decrypt_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_DECRYPT=False -> C_DecryptInit -> CKR_KEY_FUNCTION_NOT_PERMITTED.

        PKCS#11 v3.2: If CKA_DECRYPT is False, C_DecryptInit MUST return
        CKR_KEY_FUNCTION_NOT_PERMITTED. Some modules return CKR_OK, meaning the key
        permission flag is silently ignored -- keys without CKA_DECRYPT=True can still
        be used to decrypt. This is a security finding.
        """
        rc, out, err = _run_probe(p11_config, "decrypt")
        assert_ckr_subprocess_ok(rc, out, err, context="C_DecryptInit with CKA_DECRYPT=False")
        # policy: enforcing CKA_DECRYPT=False is mandatory (PKCS#11 v3.2).
        _classify_permission_flag(
            out,
            label="C_DecryptInit with a CKA_DECRYPT=False key "
            "(PKCS#11 v3.2 requires CKR_KEY_FUNCTION_NOT_PERMITTED)",
        )
