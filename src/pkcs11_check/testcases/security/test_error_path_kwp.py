"""Error-path tests for AES-KWP / AES-KW unwrap with corrupted wrapped key blobs.

Targets heap overflows found in:
- OpenCryptoki PR #932: heap overflow in AES-KWP unwrap
- OpenSSL PR #30663: heap overflow in AES-KW unwrap with corrupted data

All tests run in subprocess for crash safety. Each test generates a valid
wrapping key, wraps a target key, applies a specific corruption to the wrapped
blob, then attempts to unwrap (C_UnwrapKey) or decrypt (C_Decrypt) the
corrupted data. A crash (negative returncode = signal), child script failure,
or output-buffer guard overwrite confirms the vulnerability.
"""

from __future__ import annotations

from textwrap import indent
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
from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
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

# Corruption logic embedded in subprocess scripts
_CORRUPTION_CODE = """\
import os

corruption_type = "{corruption}"
blob = bytearray(wrapped_blob)

if corruption_type == "aiv":
    for i in range(min(4, len(blob))):
        blob[i] ^= 0xFF
elif corruption_type == "padding":
    for i in range(max(0, len(blob) - 8), len(blob)):
        blob[i] ^= 0xFF
elif corruption_type == "length":
    for i in range(4, min(8, len(blob))):
        blob[i] ^= 0xFF
elif corruption_type == "truncate":
    blob = blob[:-8]
elif corruption_type == "extend":
    blob = blob + bytearray(os.urandom(8))
elif corruption_type == "random":
    blob = bytearray(os.urandom(len(blob)))
elif corruption_type == "all_zeros":
    blob = bytearray(len(blob))
elif corruption_type == "all_ff":
    blob = bytearray(b"\\xff" * len(blob))

corrupted = bytes(blob)
"""

# Bit-flip corruption logic
_BIT_FLIP_CODE = """\
blob = bytearray(wrapped_blob)
offset = {offset}
if offset < len(blob):
    blob[offset] ^= 0x01
corrupted = bytes(blob)
"""

# Unwrap attempt via C_UnwrapKey
_UNWRAP_CODE = """\
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE, CK_ULONG, CK_OBJECT_HANDLE, CK_MECHANISM,
    CKA_CLASS, CKA_KEY_TYPE, CKA_ENCRYPT, CKA_DECRYPT, CKA_TOKEN,
    CKO_SECRET_KEY, CKK_AES, {ckm_name},
)
import ctypes

tmpl_attrs = [
    (int(CKA_CLASS), int(CKO_SECRET_KEY)),
    (int(CKA_KEY_TYPE), int(CKK_AES)),
    (int(CKA_ENCRYPT), 1),
    (int(CKA_DECRYPT), 1),
    (int(CKA_TOKEN), 0),
]
attrs = (CK_ATTRIBUTE * len(tmpl_attrs))()
vals = []
for i, (atype, aval) in enumerate(tmpl_attrs):
    attrs[i].type = atype
    v = CK_ULONG(aval)
    vals.append(v)
    attrs[i].pValue = ctypes.cast(ctypes.pointer(v), ctypes.c_void_p)
    attrs[i].ulValueLen = ctypes.sizeof(v)

mech = CK_MECHANISM()
mech.mechanism = {ckm_name}
mech.pParameter = None
mech.ulParameterLen = 0

data_buf = (ctypes.c_ubyte * len(corrupted))(*corrupted)
new_key = CK_OBJECT_HANDLE(0)
rv = raw.C_UnwrapKey(
    sh, ctypes.byref(mech), wrap_key,
    data_buf, len(corrupted),
    attrs, len(tmpl_attrs),
    ctypes.byref(new_key),
)
print(f"unwrap_rv={{rv}}")
if rv == 0:
    raw.C_DestroyObject(sh, new_key)
"""

# Decrypt attempt via C_DecryptInit + C_Decrypt
_DECRYPT_CODE = """\
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CK_ULONG, {ckm_name},
)
import ctypes

mech = CK_MECHANISM()
mech.mechanism = {ckm_name}
mech.pParameter = None
mech.ulParameterLen = 0

rv = raw.C_DecryptInit(sh, ctypes.byref(mech), wrap_key)
if rv != 0:
    print(f"decrypt_init_rv={{rv}}")
else:
    data_buf = (ctypes.c_ubyte * len(corrupted))(*corrupted)
    minimal_len = max(0, len(corrupted) - 8)
    guard_sentinel = b"PKCS11CHK"
    out_buf = (ctypes.c_ubyte * (minimal_len + len(guard_sentinel)))()
    for i, byte in enumerate(guard_sentinel):
        out_buf[minimal_len + i] = byte
    out_len = CK_ULONG(minimal_len)
    rv = raw.C_Decrypt(sh, data_buf, len(corrupted), out_buf, ctypes.byref(out_len))
    print(f"decrypt_rv={{rv}}")
    guard = bytes(out_buf[minimal_len:minimal_len + len(guard_sentinel)])
    if guard != guard_sentinel:
        raise AssertionError(
            "C_Decrypt wrote past the minimal output buffer on a corrupted "
            f"{ckm_name} error path: guard={{guard.hex()}}"
        )
"""

# Common key generation + wrap preamble for subprocess scripts
_KEYGEN_AND_WRAP = """\
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly
from pkcs11_check.raw.recipes import wrap_key as wrap_key_recipe
from pkcs11_check.testcases.security.conftest import child_setup_reject_known
from pkcs11_check.raw.types_std import (
    CKA_WRAP, CKA_UNWRAP, CKA_ENCRYPT, CKA_DECRYPT,
    CKA_EXTRACTABLE, CKA_SENSITIVE, CKA_TOKEN,
    CKR_FUNCTION_FAILED, CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID, CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
    {ckm_name},
)

# Clean rejections of the wrap *setup* (advertised but not operational for this
# key/mechanism). Classified as SETUP_XFAIL so the probe's real target -- unwrap
# integrity on a corrupted blob -- is not scored as a provider failure. An
# unexpected error or a crash is NOT in this set and still surfaces.
_WRAP_SETUP_REJECT_RVS = (
    int(CKR_FUNCTION_FAILED),
    int(CKR_FUNCTION_NOT_SUPPORTED),
    int(CKR_KEY_FUNCTION_NOT_PERMITTED),
    int(CKR_KEY_TYPE_INCONSISTENT),
    int(CKR_MECHANISM_INVALID),
    int(CKR_WRAPPING_KEY_TYPE_INCONSISTENT),
)

wrap_key = gen_aes_key(raw, sh, 256, attrs={{
    CKA_WRAP: True, CKA_UNWRAP: True,
    CKA_ENCRYPT: True, CKA_DECRYPT: True,
    CKA_TOKEN: False,
}})
target_key = gen_aes_key(raw, sh, 128, attrs={{
    CKA_EXTRACTABLE: True, CKA_SENSITIVE: False,
    CKA_TOKEN: False,
}})

try:
    try:
        # output_size_hint: NSS softoken does not set the wrapped-key length on
        # the NULL-buffer size-query pass for AES-KEY-WRAP-KWP, so the two-call
        # protocol would fail with CKR_BUFFER_TOO_SMALL. 64 covers the 8-byte ICV
        # + up to 15 bytes padding for AES-128/192/256 targets (same hint as
        # test_extended_mechanisms.py). Modules that report the size ignore it.
        wrapped_blob = wrap_key_recipe(
            raw, sh, wrap_key, target_key, {ckm_name}, output_size_hint=64
        )
    except AssertionError as _wrap_exc:
        if child_setup_reject_known(
            _wrap_exc, _WRAP_SETUP_REJECT_RVS, "AES key wrap setup rejected"
        ):
            raise SystemExit(0)
        raise
    destroy_quietly(raw, sh, target_key)

"""

# Cleanup suffix for subprocess scripts
_CLEANUP = """\
finally:
    destroy_quietly(raw, sh, wrap_key)
cleanup()
"""


def _preamble(p11_config: Any) -> str:
    """Build subprocess session preamble from p11_config."""
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=p11_config.pin.get_secret_value() if p11_config.pin else None,
        slot_label="pkcs11-check",
    )


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


def _build_script(
    p11_config: Any,
    *,
    ckm_name: str,
    corruption_code: str,
    api: str,
) -> str:
    """Assemble a full subprocess script for corrupted unwrap/decrypt."""
    preamble = _preamble(p11_config)
    keygen = _KEYGEN_AND_WRAP.format(ckm_name=ckm_name)
    if api == "unwrap":
        action = _UNWRAP_CODE.format(ckm_name=ckm_name)
    else:
        action = _DECRYPT_CODE.format(ckm_name=ckm_name)
    return preamble + keygen + indent(corruption_code + action, "    ") + _CLEANUP


class TestCorruptedUnwrap:
    """Corrupted wrapped-key blob unwrap/decrypt -- 8 corruptions x 2 mechs x 2 APIs.

    Each test wraps a valid AES-128 key with a 256-bit AES wrapping key using
    AES-KWP or AES-KW, corrupts the wrapped blob, then attempts unwrap or
    decrypt. The module must reject the corrupted data cleanly (CKR error),
    not crash.

    References:
    - OpenCryptoki PR #932: heap overflow in AES-KWP unwrap
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

        corruption_code = _CORRUPTION_CODE.format(corruption=corruption)
        script = _build_script(
            p11_config,
            ckm_name=ckm_name,
            corruption_code=corruption_code,
            api=api,
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
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
    - OpenCryptoki PR #932
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

        corruption_code = _BIT_FLIP_CODE.format(offset=offset)
        script = _build_script(
            p11_config,
            ckm_name=ckm_name,
            corruption_code=corruption_code,
            api="unwrap",
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
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
