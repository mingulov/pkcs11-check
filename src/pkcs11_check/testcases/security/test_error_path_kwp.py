"""Error-path tests for AES-KWP / AES-KW unwrap with corrupted wrapped key blobs.

Targets heap overflows found in:
- heap overflow in AES-KWP unwrap (module error path)
- OpenSSL PR #30663: heap overflow in AES-KW unwrap with corrupted data

All tests run in a subprocess (the ``error_path_kwp`` probe) for crash safety.
Each probe generates a valid wrapping key, wraps a target key, applies a specific
corruption to the wrapped blob, then attempts to unwrap (C_UnwrapKey) or decrypt
(C_Decrypt) the corrupted data. A crash (negative returncode = signal), child
script failure, or output-buffer guard overwrite confirms the vulnerability.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

# Clean rejections for a corrupted AES-KW / AES-KWP wrapped blob.
# RFC 3394 (AES-KW) and RFC 5649 (AES-KWP) mandate an integrity check
# (AIV/ICV); a conformant module must always reject a corrupted blob.
# CKR_OK means the integrity check was bypassed -- an integrity bypass.
_KW_KWP_REJECT_RVS = (
    CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_KEY_HANDLE_INVALID,
    CKR_GENERAL_ERROR,
)

_CORRUPTIONS = [
    pytest.param("aiv", id="aiv"),
    pytest.param("padding", id="padding"),
    pytest.param("length", id="length"),
    pytest.param("truncate", id="truncate"),
    pytest.param("extend", id="extend"),
    pytest.param("random", id="random"),
    pytest.param("all_zeros", id="all_zeros"),
    pytest.param("all_ff", id="all_ff"),
]

_MECHANISMS = [
    pytest.param("AES_KEY_WRAP_KWP", "CKM_AES_KEY_WRAP_KWP", id="kwp"),
    pytest.param("AES_KEY_WRAP", "CKM_AES_KEY_WRAP", id="kw"),
]

_APIS = [
    pytest.param("unwrap", id="unwrap"),
    pytest.param("decrypt", id="decrypt"),
]

_BIT_FLIP_OFFSETS = [
    pytest.param(0, id="offset_0"),
    pytest.param(8, id="offset_8"),
    pytest.param(16, id="offset_16"),
    pytest.param(24, id="offset_24"),
    pytest.param(32, id="offset_32"),
]


def _parse_ckr_value(raw_str: str) -> int:
    """Parse a CKR value from a string, handling both name and numeric forms.

    Child scripts print CKR objects via f-string interpolation which calls
    ``CKR.__str__`` and yields the constant name (e.g. ``CKR_GENERAL_ERROR``).
    Fall back to integer parsing for any future numeric-form output.
    """
    import pkcs11_check.raw.types_std as _ts

    raw_str = raw_str.strip()
    if raw_str.startswith("CKR_"):
        val = getattr(_ts, raw_str, None)
        if val is not None:
            return int(val)
    # Numeric form (decimal or 0x-hex) -- handles vendor-defined codes
    try:
        return int(raw_str, 0)
    except ValueError:
        raise AssertionError(f"Cannot parse CKR value from {raw_str!r}") from None


def _parse_op_rv(stdout: str, api: str) -> int:
    """Parse the operation return value from child script stdout.

    For the unwrap API the child prints ``unwrap_rv=<CKR name>``.
    For the decrypt API the child prints either ``decrypt_init_rv=<CKR name>``
    (when C_DecryptInit fails) or ``decrypt_rv=<CKR name>`` (when C_Decrypt
    runs).  Either line is the operative rejection rv for the probe.
    """
    prefixes = ["unwrap_rv="] if api == "unwrap" else ["decrypt_init_rv=", "decrypt_rv="]
    for line in stdout.splitlines():
        for prefix in prefixes:
            if line.startswith(prefix):
                return _parse_ckr_value(line.removeprefix(prefix))
    raise AssertionError(f"Missing {api} rv line in subprocess output: {stdout[-300:]}")


class TestCorruptedUnwrap:
    """Corrupted wrapped-key blob unwrap/decrypt -- 8 corruptions x 2 mechs x 2 APIs.

    Each test wraps a valid AES-128 key with a 256-bit AES wrapping key using
    AES-KWP or AES-KW, corrupts the wrapped blob, then attempts unwrap or
    decrypt. The module must reject the corrupted data cleanly (CKR error),
    not crash.

    References:
    - heap overflow in AES-KWP unwrap (module error path)
    - OpenSSL PR #30663: heap overflow in AES-KW unwrap
    - RFC 5649 (AES-KWP), RFC 3394 (AES-KW)
    """

    @pytest.mark.parametrize("corruption", _CORRUPTIONS)
    @pytest.mark.parametrize("mech_check,ckm_name", _MECHANISMS)
    @pytest.mark.parametrize("api", _APIS)
    def test_corrupted_unwrap(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        corruption: str,
        mech_check: str,
        ckm_name: str,
        api: str,
    ) -> None:
        """Corrupted wrapped blob must be rejected, not cause a crash."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_check):
            pytest.skip(f"CKM_{mech_check} not supported")

        result = run_probe(
            "error_path_kwp",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "corrupted_unwrap",
                "ckm_name": ckm_name,
                "corruption": corruption,
                "api": api,
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=(f"{ckm_name} {api}: corruption={corruption}"),
        )
        # assert_subprocess_no_crash xfails (via xfail_as) on SETUP_XFAIL, so if
        # control reaches here the probe ran and an rv line is present in stdout.
        rv = _parse_op_rv(stdout, api)
        classify_negative_rv(
            rv,
            _KW_KWP_REJECT_RVS,
            label=(
                f"{ckm_name} {api}: corrupted blob (corruption={corruption})"
                " must be rejected (RFC 3394/5649 integrity)"
            ),
            kind="crypto",
        )


class TestBitFlipUnwrap:
    """Single-bit-flip corrupted wrapped-key blob unwrap -- 5 offsets x 2 mechs.

    Flips bit 0 at specific byte offsets in the wrapped blob, then attempts
    C_UnwrapKey. Targets subtle corruption that may bypass coarse validation
    but trigger heap corruption in decryption routines.

    References:
    - heap overflow in AES-KWP unwrap (module error path)
    - OpenSSL PR #30663
    """

    @pytest.mark.parametrize("offset", _BIT_FLIP_OFFSETS)
    @pytest.mark.parametrize("mech_check,ckm_name", _MECHANISMS)
    def test_bit_flip_unwrap(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        offset: int,
        mech_check: str,
        ckm_name: str,
    ) -> None:
        """Single-bit-flip in wrapped blob must be rejected, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_check):
            pytest.skip(f"CKM_{mech_check} not supported")

        result = run_probe(
            "error_path_kwp",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "bit_flip_unwrap",
                "ckm_name": ckm_name,
                "offset": offset,
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=(f"{ckm_name} unwrap: bit_flip at byte {offset}"),
        )
        # assert_subprocess_no_crash xfails (via xfail_as) on SETUP_XFAIL, so if
        # control reaches here the probe ran and an rv line is present in stdout.
        rv = _parse_op_rv(stdout, "unwrap")
        classify_negative_rv(
            rv,
            _KW_KWP_REJECT_RVS,
            label=(
                f"{ckm_name} unwrap: corrupted blob (bit_flip at byte {offset})"
                " must be rejected (RFC 3394/5649 integrity)"
            ),
            kind="crypto",
        )
