"""Error-path tests for AES-KWP / AES-KW unwrap with corrupted wrapped key blobs.

Targets heap overflows found in:
- OpenCryptoki PR #932: heap overflow in AES-KWP unwrap
- OpenSSL PR #30663: heap overflow in AES-KW unwrap with corrupted data

All tests run in subprocess for crash safety. Each test generates a valid
wrapping key, wraps a target key, applies a specific corruption to the wrapped
blob, then attempts to unwrap (C_UnwrapKey) or decrypt (C_Decrypt) the
corrupted data. A crash (negative returncode = signal) confirms the
vulnerability.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases._subprocess_preamble import (
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

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
mech.mechanism = int({ckm_name})
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
mech.mechanism = int({ckm_name})
mech.pParameter = None
mech.ulParameterLen = 0

rv = raw.C_DecryptInit(sh, ctypes.byref(mech), wrap_key)
if rv != 0:
    print(f"decrypt_init_rv={{rv}}")
else:
    data_buf = (ctypes.c_ubyte * len(corrupted))(*corrupted)
    out_buf = (ctypes.c_ubyte * (len(corrupted) + 16))()
    out_len = CK_ULONG(len(corrupted) + 16)
    rv = raw.C_Decrypt(sh, data_buf, len(corrupted), out_buf, ctypes.byref(out_len))
    print(f"decrypt_rv={{rv}}")
"""

# Common key generation + wrap preamble for subprocess scripts
_KEYGEN_AND_WRAP = """\
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly
from pkcs11_check.raw.recipes import wrap_key as wrap_key_recipe
from pkcs11_check.raw.types_std import (
    CKA_WRAP, CKA_UNWRAP, CKA_ENCRYPT, CKA_DECRYPT,
    CKA_EXTRACTABLE, CKA_SENSITIVE, CKA_TOKEN,
    {ckm_name},
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
    wrapped_blob = wrap_key_recipe(raw, sh, wrap_key, target_key, {ckm_name})
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
    return preamble + keygen + corruption_code + action + _CLEANUP


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
        rc, stdout, stderr = run_with_coverage(script, timeout=15)
        assert_subprocess_no_crash(
            rc, stdout, stderr,
            context=(
                f"{ckm_name} {api}: corruption={corruption}"
            ),
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
        rc, stdout, stderr = run_with_coverage(script, timeout=15)
        assert_subprocess_no_crash(
            rc, stdout, stderr,
            context=(
                f"{ckm_name} unwrap: bit_flip at byte {offset}"
            ),
        )
