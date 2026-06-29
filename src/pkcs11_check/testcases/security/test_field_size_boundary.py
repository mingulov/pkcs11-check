"""Field-size oversize/truncation probes for key-size, find-count, and KDF-param fields.

WS2 Phase 3: close the remaining field-level gaps not covered by Phase 1
(_ISIZE_BOUNDARY_LENGTHS param extensions) or Phase 2 (output-write oracle).

Probed fields
-------------
1. CKA_MODULUS_BITS oversized VALUE in C_GenerateKeyPair(RSA)
   - Declares CKA_MODULUS_BITS = _MODULUS_BITS_TRUNC = (1<<32)+2048 (low32 = 2048).
   - A 32-bit-truncating provider truncates to 2048 and may generate a key → CKR_OK =
     accepted_invalid (impossible 64-bit value was accepted).
   - A correct provider rejects (CKR_ATTRIBUTE_VALUE_INVALID / CKR_KEY_SIZE_RANGE /
     CKR_TEMPLATE_INCONSISTENT / CKR_ARGUMENTS_BAD).
   - Guard: CKM_RSA_PKCS_KEY_PAIR_GEN must be advertised.

2. CKA_PRIME_BITS oversized VALUE in C_GenerateKeyPair(DH or DSA)
   - Same pattern; guard on CKM_DH_PKCS_KEY_PAIR_GEN (primary) or CKM_DSA_KEY_PAIR_GEN.
   - Skip if neither DH nor DSA is advertised.

3. CKA_VALUE_LEN truncation-revealing value in C_GenerateKey (AES)
   - Declares CKA_VALUE_LEN = TRUNCATION_LOW8 = (1<<32)+8 (low32 = 8).
   - A 32-bit-truncating provider sees value_len=8 (a valid AES-64 key) and returns CKR_OK
     → accepted_invalid (generated a key for an impossible 64-bit value-len).
   - A correct provider rejects the impossible 64-bit length.
   - NOTE: This is a distinct probe from the Phase 2 output oracle — it tests the
     CKA_VALUE_LEN template attribute value (what key size to generate), not the
     output buffer write length.
   - Guard: CKM_AES_KEY_GEN.

4. C_FindObjects ulMaxObjectCount truncation-revealing value
   - CKR_OK treatment: ulMaxObjectCount is a CAP (upper bound on returned handles), not a
     minimum — a provider returning ≤ MAX handles is SPEC-LEGAL regardless of the value.
     Therefore CKR_OK is NOT a finding here. We use allow_ok=True.
   - The finding class for this field is a CRASH or buffer-overrun if the provider tries to
     write more handles than the actual buffer holds. Crashes are caught by subprocess
     isolation (negative returncode).
   - The probe uses a tiny real handle buffer (8 slots) and passes TRUNCATION_LOW8 as
     ulMaxObjectCount. A correct provider returns up to min(found, 8) handles. A
     truncating provider that overruns the handle array would crash → caught by isolation.

5. HKDF ulSaltLen / ulInfoLen 64-bit length truncation detection
   - Detects 64->32-bit length truncation by behavioral comparison: two HKDF derives are
     performed -- one with a full-length demand-zero mmap buffer and ulSaltLen/ulInfoLen =
     OVERSIZE_LEN = (1<<32)+8, then one with only the first 8 bytes (low32 portion).
   - Safety: the mmap is MAP_PRIVATE|MAP_ANONYMOUS, properly sized to OVERSIZE_LEN bytes,
     so no read beyond the mapping occurs regardless of what the module does.
   - If both derives return CKR_OK and produce the SAME key material -> the module silently
     truncated the 64-bit length to its low 32 bits -> wrong_result (crypto kind).
   - If both derives return CKR_OK and produce DIFFERENT key material -> the module honored
     the full 64-bit length and differentiated between 8-byte and 4GB+ inputs.
   - A clean reject (CKR_MECHANISM_PARAM_INVALID / CKR_DATA_LEN_RANGE / etc.) on the
     oversized derive is conformant -> classify_negative_rv.

All probes follow the Family-A accepted_invalid pattern:
  child prints TARGET_RV:0x<hex> → classify_negative_rv (allow_ok=False unless noted).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import fail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    destroy_returned_handles,
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
)
from pkcs11_check.testcases.security._boundary_values import (
    TRUNCATION_LOW8,
    requires_64bit_ck_ulong,
)
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [
    pytest.mark.security,
    pytest.mark.subprocess,
    requires_64bit_ck_ulong,
]

# 64-bit oversized length: low32 = 8, so a 32-bit-truncating module reads only 8 bytes.
_OVERSIZE_LEN = (1 << 32) + 8

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

# Truncation-revealing 64-bit value whose low-32 bits equal 2048.
# A 32-bit-truncating provider reads CKA_MODULUS_BITS=2048 and generates
# an RSA-2048 key; a correct provider rejects the impossible 64-bit value.
_MODULUS_BITS_TRUNC = (1 << 32) + 2048

# Truncation-revealing 64-bit value whose low-32 bits equal 1024.
# For DH/DSA PRIME_BITS; low32=1024 is a standard prime size so a
# truncating provider may succeed.
_PRIME_BITS_TRUNC = (1 << 32) + 1024

# Expected CKRs for a correct provider rejecting an impossible key-size value.
_KEY_SIZE_REJECT_RVS = (
    0x00000023,  # CKR_ATTRIBUTE_VALUE_INVALID
    0x00000010,  # CKR_KEY_SIZE_RANGE
    0x0000000D,  # CKR_TEMPLATE_INCONSISTENT
    0x00000007,  # CKR_ARGUMENTS_BAD
    0x00000070,  # CKR_FUNCTION_NOT_SUPPORTED
)

# Same set for KDF param rejection.
_PARAM_REJECT_RVS = _KEY_SIZE_REJECT_RVS + (
    0x00000031,  # CKR_MECHANISM_PARAM_INVALID
    0x00000021,  # CKR_DATA_LEN_RANGE
)

# Expected CKRs for a correct provider rejecting an impossible CKA_VALUE_LEN.
_VALUE_LEN_REJECT_RVS = (
    0x00000023,  # CKR_ATTRIBUTE_VALUE_INVALID
    0x00000010,  # CKR_KEY_SIZE_RANGE
    0x0000000D,  # CKR_TEMPLATE_INCONSISTENT
    0x00000007,  # CKR_ARGUMENTS_BAD
)


def _preamble(p11_config: Any) -> str:
    """Build subprocess session preamble from p11_config."""
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=p11_config.pin.get_secret_value() if p11_config.pin else None,
    )


def _parse_prefixed_int(output: str, prefix: str) -> int:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    raise AssertionError(f"Missing {prefix!r} line in subprocess output: {output[-300:]}")


# ---------------------------------------------------------------------------
# 1. CKA_MODULUS_BITS oversized value in C_GenerateKeyPair(RSA)
# ---------------------------------------------------------------------------


class TestRsaModulusBitsOversizedValue:
    """CKA_MODULUS_BITS with a truncation-revealing 64-bit value must be rejected.

    Distinct from test_scalar_attr_length_extended.TestRsaModulusBitsInKeygen
    which tests malformed *declared storage length* (ulValueLen wrong) — this
    probe tests the *numeric value* of the attribute itself: (1<<32)+2048
    cannot be a valid modulus bit-count; a 32-bit-truncating provider may
    misread it as 2048 and generate a key (accepted_invalid).
    """

    def test_rsa_modulus_bits_oversized_value(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_GenerateKeyPair(RSA) must reject CKA_MODULUS_BITS=(1<<32)+2048."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not advertised")
        # Setup preflight: ensure RSA keygen works at all.
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        destroy_returned_handles(rs, pub, priv)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_RSA_PKCS_KEY_PAIR_GEN,
    CK_ATTRIBUTE, CK_OBJECT_HANDLE, CKA_MODULUS_BITS, CKA_TOKEN,
    CKA_PRIVATE, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Impossible 64-bit modulus bits value; low32 = 2048 (valid RSA size).
modulus_bits = CK_ULONG({_MODULUS_BITS_TRUNC})
token_false = ctypes.c_ubyte(0)
priv_true = ctypes.c_ubyte(1)

pub_tmpl = (CK_ATTRIBUTE * 2)()
pub_tmpl[0].type = CKA_MODULUS_BITS
pub_tmpl[0].pValue = ctypes.cast(ctypes.pointer(modulus_bits), ctypes.c_void_p)
pub_tmpl[0].ulValueLen = ctypes.sizeof(modulus_bits)
pub_tmpl[1].type = CKA_TOKEN
pub_tmpl[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
pub_tmpl[1].ulValueLen = 1

priv_tmpl = (CK_ATTRIBUTE * 2)()
priv_tmpl[0].type = CKA_TOKEN
priv_tmpl[0].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
priv_tmpl[0].ulValueLen = 1
priv_tmpl[1].type = CKA_PRIVATE
priv_tmpl[1].pValue = ctypes.cast(ctypes.pointer(priv_true), ctypes.c_void_p)
priv_tmpl[1].ulValueLen = 1

mech = CK_MECHANISM()
mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN
mech.pParameter = None
mech.ulParameterLen = 0

pub = CK_OBJECT_HANDLE(0)
priv = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKeyPair(
    sh, ctypes.byref(mech),
    ctypes.cast(pub_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 2,
    ctypes.cast(priv_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 2,
    ctypes.byref(pub), ctypes.byref(priv),
)
if rv == CKR_OK:
    destroy_quietly(raw, sh, pub.value)
    destroy_quietly(raw, sh, priv.value)
print(f"TARGET_RV:0x{{rv:08x}}")
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_GenerateKeyPair(RSA, CKA_MODULUS_BITS={_MODULUS_BITS_TRUNC:#x})",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _KEY_SIZE_REJECT_RVS,
            label=f"C_GenerateKeyPair(RSA, CKA_MODULUS_BITS={_MODULUS_BITS_TRUNC:#x})",
        )


# ---------------------------------------------------------------------------
# 2. CKA_PRIME_BITS oversized value in C_GenerateKeyPair(DH or DSA)
# ---------------------------------------------------------------------------


class TestPrimeBitsOversizedValue:
    """CKA_PRIME_BITS with a truncation-revealing 64-bit value must be rejected.

    Probes DH first (CKM_DH_PKCS_KEY_PAIR_GEN); falls back to DSA if DH is
    absent. Skips if neither mechanism is advertised.
    """

    def test_dh_prime_bits_oversized_value(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_GenerateKeyPair(DH) must reject CKA_PRIME_BITS=(1<<32)+1024."""
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_DH_PKCS_KEY_PAIR_GEN not advertised")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_DH_PKCS_KEY_PAIR_GEN,
    CK_ATTRIBUTE, CK_OBJECT_HANDLE, CKA_PRIME_BITS, CKA_TOKEN, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

prime_bits = CK_ULONG({_PRIME_BITS_TRUNC})
token_false = ctypes.c_ubyte(0)

pub_tmpl = (CK_ATTRIBUTE * 2)()
pub_tmpl[0].type = CKA_PRIME_BITS
pub_tmpl[0].pValue = ctypes.cast(ctypes.pointer(prime_bits), ctypes.c_void_p)
pub_tmpl[0].ulValueLen = ctypes.sizeof(prime_bits)
pub_tmpl[1].type = CKA_TOKEN
pub_tmpl[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
pub_tmpl[1].ulValueLen = 1

priv_tmpl = (CK_ATTRIBUTE * 1)()
priv_tmpl[0].type = CKA_TOKEN
priv_tmpl[0].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
priv_tmpl[0].ulValueLen = 1

mech = CK_MECHANISM()
mech.mechanism = CKM_DH_PKCS_KEY_PAIR_GEN
mech.pParameter = None
mech.ulParameterLen = 0

pub = CK_OBJECT_HANDLE(0)
priv = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKeyPair(
    sh, ctypes.byref(mech),
    ctypes.cast(pub_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 2,
    ctypes.cast(priv_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 1,
    ctypes.byref(pub), ctypes.byref(priv),
)
if rv == CKR_OK:
    destroy_quietly(raw, sh, pub.value)
    destroy_quietly(raw, sh, priv.value)
print(f"TARGET_RV:0x{{rv:08x}}")
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_GenerateKeyPair(DH, CKA_PRIME_BITS={_PRIME_BITS_TRUNC:#x})",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _KEY_SIZE_REJECT_RVS,
            label=f"C_GenerateKeyPair(DH, CKA_PRIME_BITS={_PRIME_BITS_TRUNC:#x})",
        )

    def test_dsa_prime_bits_oversized_value(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_GenerateKeyPair(DSA) must reject CKA_PRIME_BITS=(1<<32)+1024."""
        rs = p11_raw_session
        if not rs.has_mechanism("DSA_KEY_PAIR_GEN"):
            pytest.skip("CKM_DSA_KEY_PAIR_GEN not advertised")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_DSA_KEY_PAIR_GEN,
    CK_ATTRIBUTE, CK_OBJECT_HANDLE, CKA_PRIME_BITS, CKA_TOKEN, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

prime_bits = CK_ULONG({_PRIME_BITS_TRUNC})
token_false = ctypes.c_ubyte(0)

pub_tmpl = (CK_ATTRIBUTE * 2)()
pub_tmpl[0].type = CKA_PRIME_BITS
pub_tmpl[0].pValue = ctypes.cast(ctypes.pointer(prime_bits), ctypes.c_void_p)
pub_tmpl[0].ulValueLen = ctypes.sizeof(prime_bits)
pub_tmpl[1].type = CKA_TOKEN
pub_tmpl[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
pub_tmpl[1].ulValueLen = 1

priv_tmpl = (CK_ATTRIBUTE * 1)()
priv_tmpl[0].type = CKA_TOKEN
priv_tmpl[0].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
priv_tmpl[0].ulValueLen = 1

mech = CK_MECHANISM()
mech.mechanism = CKM_DSA_KEY_PAIR_GEN
mech.pParameter = None
mech.ulParameterLen = 0

pub = CK_OBJECT_HANDLE(0)
priv = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKeyPair(
    sh, ctypes.byref(mech),
    ctypes.cast(pub_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 2,
    ctypes.cast(priv_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 1,
    ctypes.byref(pub), ctypes.byref(priv),
)
if rv == CKR_OK:
    destroy_quietly(raw, sh, pub.value)
    destroy_quietly(raw, sh, priv.value)
print(f"TARGET_RV:0x{{rv:08x}}")
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=30, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_GenerateKeyPair(DSA, CKA_PRIME_BITS={_PRIME_BITS_TRUNC:#x})",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _KEY_SIZE_REJECT_RVS,
            label=f"C_GenerateKeyPair(DSA, CKA_PRIME_BITS={_PRIME_BITS_TRUNC:#x})",
        )


# ---------------------------------------------------------------------------
# 3. CKA_VALUE_LEN truncation-revealing value in C_GenerateKey (AES)
# ---------------------------------------------------------------------------


class TestGenerateKeyValueLenTruncation:
    """CKA_VALUE_LEN with a truncation-revealing 64-bit value in C_GenerateKey.

    Uses TRUNCATION_LOW8 = (1<<32)+8 so low32 = 8 bytes (valid AES-64, though
    unusual). A 32-bit-truncating provider may accept and generate a key with
    value_len=8 → CKR_OK = accepted_invalid (the 64-bit value is impossible).
    A correct provider rejects the impossible 64-bit length or the invalid
    AES key size.

    CKR_OK treatment: NOT spec-legal. The CKA_VALUE_LEN value (1<<32)+8 is
    an impossible key size — no AES key is that large. CKR_OK means the
    provider was truncated to 8 bytes and succeeded, which is the accepted_invalid
    finding. We use allow_ok=False (default).
    """

    def test_aes_keygen_value_len_truncation(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_GenerateKey(AES) must reject CKA_VALUE_LEN=TRUNCATION_LOW8."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not advertised")
        # Setup preflight: ensure AES keygen works at all.
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES value-len truncation probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_KEY_GEN,
    CK_ATTRIBUTE, CK_OBJECT_HANDLE, CKA_VALUE_LEN, CKA_TOKEN, CKA_ENCRYPT,
    CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Impossible 64-bit value_len; low32 = 8 bytes (truncating provider succeeds).
value_len = CK_ULONG({TRUNCATION_LOW8})
token_false = ctypes.c_ubyte(0)
enc_true = ctypes.c_ubyte(1)

tmpl = (CK_ATTRIBUTE * 3)()
tmpl[0].type = CKA_VALUE_LEN
tmpl[0].pValue = ctypes.cast(ctypes.pointer(value_len), ctypes.c_void_p)
tmpl[0].ulValueLen = ctypes.sizeof(value_len)
tmpl[1].type = CKA_TOKEN
tmpl[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
tmpl[1].ulValueLen = 1
tmpl[2].type = CKA_ENCRYPT
tmpl[2].pValue = ctypes.cast(ctypes.pointer(enc_true), ctypes.c_void_p)
tmpl[2].ulValueLen = 1

mech = CK_MECHANISM()
mech.mechanism = CKM_AES_KEY_GEN
mech.pParameter = None
mech.ulParameterLen = 0

key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(
    sh, ctypes.byref(mech),
    ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 3,
    ctypes.byref(key),
)
if rv == CKR_OK:
    destroy_quietly(raw, sh, key.value)
print(f"TARGET_RV:0x{{rv:08x}}")
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_GenerateKey(AES, CKA_VALUE_LEN={TRUNCATION_LOW8:#x})",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _VALUE_LEN_REJECT_RVS,
            label=f"C_GenerateKey(AES, CKA_VALUE_LEN={TRUNCATION_LOW8:#x})",
        )


# ---------------------------------------------------------------------------
# 4. C_FindObjects ulMaxObjectCount truncation-revealing value
# ---------------------------------------------------------------------------


class TestFindObjectsCountTruncation:
    """C_FindObjects with a truncation-revealing ulMaxObjectCount must not crash.

    CKR_OK treatment: ulMaxObjectCount is a CAP (upper bound), not a minimum.
    The spec says C_FindObjects returns AT MOST ulMaxObjectCount handles.
    Returning fewer than the cap is ALWAYS spec-legal, so CKR_OK is NOT a
    finding here. We use allow_ok=True.

    The finding class for this probe is a CRASH or buffer-overrun if the
    provider tries to write handles beyond the actual buffer (8 slots). Crashes
    are caught by subprocess isolation (negative returncode → assert_subprocess_no_crash
    fires). We also check a guard region after the handle array for overwrites.

    Note on TRUNCATION_LOW8 = (1<<32)+8: low32 = 8. A 32-bit-truncating
    provider sees ulMaxObjectCount=8 which exactly matches our buffer size — it
    cannot overrun. A correct 64-bit provider validates the huge value and may
    reject or cap to 8 (both are acceptable). The only finding is if the provider
    tries to interpret the 64-bit count literally and writes beyond the 8-slot
    buffer → crash. This probe is therefore a crash-survival probe with
    allow_ok=True (CKR_OK is legal by spec for a cap field).
    """

    def test_find_objects_oversized_count_survives(
        self,
        p11_raw_session: Any,  # ensures module loaded + session open before subprocess probe
        p11_config: Any,
    ) -> None:
        """C_FindObjects must not crash with ulMaxObjectCount=TRUNCATION_LOW8."""
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE, CK_OBJECT_HANDLE, CKR_OK,
)
from pkcs11_check.raw.rv import ckr_name

# Empty template = match all objects; we are not looking for specific ones.
rv_init = raw.C_FindObjectsInit(sh, None, 0)
if rv_init != CKR_OK:
    print(f"SETUP_XFAIL:C_FindObjectsInit rejected: {{ckr_name(rv_init)}}")
    cleanup()
    raise SystemExit(0)

# 8-slot handle buffer with guard bytes immediately after.
GUARD_SENTINEL = 0xA5
HANDLE_SLOTS = 8
GUARD_SLOTS = 8

class FindProbe(ctypes.Structure):
    _fields_ = [
        ("handles", CK_OBJECT_HANDLE * HANDLE_SLOTS),
        ("guard", ctypes.c_ulong * GUARD_SLOTS),
    ]

probe = FindProbe()
for idx in range(GUARD_SLOTS):
    probe.guard[idx] = GUARD_SENTINEL

count_out = ctypes.c_ulong(0)
rv = raw.C_FindObjects(
    sh,
    ctypes.cast(probe.handles, ctypes.POINTER(CK_OBJECT_HANDLE)),
    {TRUNCATION_LOW8},          # ulMaxObjectCount — cap field, CKR_OK is spec-legal
    ctypes.byref(count_out),
)
print(f"TARGET_RV:0x{{rv:08x}}")
print(f"COUNT_OUT:{{count_out.value}}")

overwritten = sum(1 for g in probe.guard if g != GUARD_SENTINEL)
print(f"GUARD_OVERWRITE:{{overwritten}}")

raw.C_FindObjectsFinal(sh)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        # Crash = buffer overrun (the only real finding for this probe).
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_FindObjects(ulMaxObjectCount={TRUNCATION_LOW8:#x})",
        )
        if "GUARD_OVERWRITE:" in stdout:
            overwritten = _parse_prefixed_int(stdout, "GUARD_OVERWRITE:")
            if overwritten:
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label="C_FindObjects handle-buffer guard overwrite",
                    actual=overwritten,
                    summary=(
                        f"C_FindObjects wrote {overwritten} guard word(s) past the 8-slot handle "
                        f"buffer (ulMaxObjectCount={TRUNCATION_LOW8:#x})"
                    ),
                )
        # CKR_OK is spec-legal (ulMaxObjectCount is a cap), so allow_ok=True.
        if "TARGET_RV:" in stdout:
            rv = _parse_prefixed_int(stdout, "TARGET_RV:")
            classify_negative_rv(
                rv,
                _KEY_SIZE_REJECT_RVS,
                label=f"C_FindObjects(ulMaxObjectCount={TRUNCATION_LOW8:#x})",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# 5. HKDF ulSaltLen / ulInfoLen 64-bit length truncation (mmap-backed, behavioral)
# ---------------------------------------------------------------------------

# Key import helper: imports a 32-byte extractable generic-secret base key.
# CKA_SENSITIVE=False + CKA_EXTRACTABLE=True so derived keys can be read back
# for behavioral comparison.
_HKDF_BASE_KEY_IMPORT = """
import ctypes
import mmap as _mmap
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE, CK_OBJECT_HANDLE, CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE,
    CKA_DERIVE, CKA_TOKEN, CKA_SENSITIVE, CKA_EXTRACTABLE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)
sensitive_false = ctypes.c_ubyte(0)
extractable_true = ctypes.c_ubyte(1)

key_tmpl = (CK_ATTRIBUTE * 7)()
key_tmpl[0].type = CKA_CLASS
key_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = CKA_KEY_TYPE
key_tmpl[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = CKA_VALUE
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 32
key_tmpl[3].type = CKA_DERIVE
key_tmpl[3].pValue = ctypes.cast(ctypes.pointer(derive_true), ctypes.c_void_p)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = CKA_TOKEN
key_tmpl[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
key_tmpl[4].ulValueLen = 1
key_tmpl[5].type = CKA_SENSITIVE
key_tmpl[5].pValue = ctypes.cast(ctypes.pointer(sensitive_false), ctypes.c_void_p)
key_tmpl[5].ulValueLen = 1
key_tmpl[6].type = CKA_EXTRACTABLE
key_tmpl[6].pValue = ctypes.cast(ctypes.pointer(extractable_true), ctypes.c_void_p)
key_tmpl[6].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    7, ctypes.byref(base_key),
)
if rv != CKR_OK:
    from pkcs11_check.raw.rv import ckr_name
    print(f"SETUP_XFAIL:HKDF base key import not operational 0x{{rv:08x}}")
    cleanup()
    raise SystemExit(0)
"""

# Derive template: extractable session key so we can read back CKA_VALUE for comparison.
_HKDF_DERIVE_TEMPLATE = """
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE, CK_OBJECT_HANDLE, CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN,
    CKA_TOKEN, CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_VALUE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET, CK_ULONG,
)

d_cls = ctypes.c_ulong(CKO_SECRET_KEY)
d_kt = ctypes.c_ulong(CKK_GENERIC_SECRET)
d_vl = CK_ULONG(32)
d_tok = ctypes.c_ubyte(0)
d_sens = ctypes.c_ubyte(0)
d_extr = ctypes.c_ubyte(1)
d_tmpl = (CK_ATTRIBUTE * 6)()
d_tmpl[0].type = CKA_CLASS
d_tmpl[0].pValue = ctypes.cast(ctypes.pointer(d_cls), ctypes.c_void_p)
d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
d_tmpl[1].type = CKA_KEY_TYPE
d_tmpl[1].pValue = ctypes.cast(ctypes.pointer(d_kt), ctypes.c_void_p)
d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
d_tmpl[2].type = CKA_VALUE_LEN
d_tmpl[2].pValue = ctypes.cast(ctypes.pointer(d_vl), ctypes.c_void_p)
d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
d_tmpl[3].type = CKA_TOKEN
d_tmpl[3].pValue = ctypes.cast(ctypes.pointer(d_tok), ctypes.c_void_p)
d_tmpl[3].ulValueLen = 1
d_tmpl[4].type = CKA_SENSITIVE
d_tmpl[4].pValue = ctypes.cast(ctypes.pointer(d_sens), ctypes.c_void_p)
d_tmpl[4].ulValueLen = 1
d_tmpl[5].type = CKA_EXTRACTABLE
d_tmpl[5].pValue = ctypes.cast(ctypes.pointer(d_extr), ctypes.c_void_p)
d_tmpl[5].ulValueLen = 1

def _extract_key_value(handle):
    \"\"\"Return 32 bytes of CKA_VALUE from a derived key, or None on failure.\"\"\"
    val_buf = (ctypes.c_ubyte * 32)()
    attr = (CK_ATTRIBUTE * 1)()
    attr[0].type = CKA_VALUE
    attr[0].pValue = ctypes.cast(val_buf, ctypes.c_void_p)
    attr[0].ulValueLen = 32
    rv_get = raw.C_GetAttributeValue(sh, handle, ctypes.cast(attr, ctypes.POINTER(CK_ATTRIBUTE)), 1)
    if rv_get != CKR_OK:
        return None
    return bytes(val_buf)
"""


class TestHkdfParamLengthTruncation:
    """HKDF ulSaltLen / ulInfoLen 64-bit length truncation detection via behavioral comparison.

    Safety: all probes back the oversized-length salt/info field with a properly
    sized MAP_PRIVATE|MAP_ANONYMOUS demand-zero mmap (OVERSIZE_LEN = (1<<32)+8 bytes),
    so no read beyond the mapping occurs regardless of what the module does.

    Detection method: two derives are performed.
      Probe derive: salt/info points to the mmap, length = OVERSIZE_LEN.
      Reference derive: salt/info points to the first 8 bytes only (the low-32 portion).
    If both succeed and produce the SAME key material, the module silently truncated
    the 64-bit length to its low 32 bits -> wrong_result (crypto kind).
    If both succeed but produce DIFFERENT key material, the module distinguished the
    two lengths -> honored (note, ComplianceLevel.EXTENDED).
    A clean reject of the oversized probe -> classify_negative_rv (conformant).
    """

    @pytest.mark.slow
    def test_hkdf_salt_len_truncation(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """HKDF must not silently truncate ulSaltLen from 64 to 32 bits.

        Uses a full-length mmap-backed salt buffer to avoid any over-read.
        Truncation is detected by comparing derived key material: a module that
        truncates ulSaltLen to 8 (low32) produces the same output as the 8-byte
        reference derive -> wrong_result.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not advertised")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _HKDF_BASE_KEY_IMPORT
            + _HKDF_DERIVE_TEMPLATE
            + f"""
from pkcs11_check.raw.types_std import (
    CK_HKDF_PARAMS, CK_MECHANISM, CKM_HKDF_DERIVE, CKM_SHA256,
    CKF_HKDF_SALT_DATA,
)

OVERSIZE_LEN = {_OVERSIZE_LEN}   # (1<<32)+8; low32 = 8

# Full-length demand-zero mmap: OVERSIZE_LEN bytes, properly backed so no
# protected-memory read can occur if a 64-bit module honors the full length.
mm = _mmap.mmap(
    -1, OVERSIZE_LEN,
    _mmap.MAP_PRIVATE | _mmap.MAP_ANONYMOUS,
    _mmap.PROT_READ | _mmap.PROT_WRITE,
)
# Seed the first 8 bytes with a known pattern (the low32 portion).
for i, b in enumerate(b"saltsalt"):
    mm[i] = b
mmap_buf = (ctypes.c_ubyte * OVERSIZE_LEN).from_buffer(mm)

try:
    # --- Probe derive: full OVERSIZE_LEN salt (mmap-backed) ---
    params_probe = CK_HKDF_PARAMS()
    params_probe.bExtract = 1
    params_probe.bExpand = 1
    params_probe.prfHashMechanism = CKM_SHA256
    params_probe.ulSaltType = CKF_HKDF_SALT_DATA
    params_probe.pSalt = ctypes.cast(mmap_buf, ctypes.c_void_p)
    params_probe.ulSaltLen = OVERSIZE_LEN
    params_probe.hSaltKey = 0
    params_probe.pInfo = None
    params_probe.ulInfoLen = 0

    mech_probe = CK_MECHANISM()
    mech_probe.mechanism = CKM_HKDF_DERIVE
    mech_probe.pParameter = ctypes.cast(ctypes.pointer(params_probe), ctypes.c_void_p)
    mech_probe.ulParameterLen = ctypes.sizeof(params_probe)

    derived_probe = CK_OBJECT_HANDLE(0)
    rv_probe = raw.C_DeriveKey(
        sh, ctypes.byref(mech_probe), base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 6,
        ctypes.byref(derived_probe),
    )
    print(f"PROBE_RV:0x{{rv_probe:08x}}")

    if rv_probe == CKR_OK:
        probe_bytes = _extract_key_value(derived_probe.value)
        destroy_quietly(raw, sh, derived_probe.value)
    else:
        probe_bytes = None

    # --- Reference derive: only the first 8 bytes of salt (low32 portion) ---
    if rv_probe == CKR_OK:
        ref_salt = (ctypes.c_ubyte * 8)(*b"saltsalt")
        params_ref = CK_HKDF_PARAMS()
        params_ref.bExtract = 1
        params_ref.bExpand = 1
        params_ref.prfHashMechanism = CKM_SHA256
        params_ref.ulSaltType = CKF_HKDF_SALT_DATA
        params_ref.pSalt = ctypes.cast(ref_salt, ctypes.c_void_p)
        params_ref.ulSaltLen = 8
        params_ref.hSaltKey = 0
        params_ref.pInfo = None
        params_ref.ulInfoLen = 0

        mech_ref = CK_MECHANISM()
        mech_ref.mechanism = CKM_HKDF_DERIVE
        mech_ref.pParameter = ctypes.cast(ctypes.pointer(params_ref), ctypes.c_void_p)
        mech_ref.ulParameterLen = ctypes.sizeof(params_ref)

        derived_ref = CK_OBJECT_HANDLE(0)
        rv_ref = raw.C_DeriveKey(
            sh, ctypes.byref(mech_ref), base_key.value,
            ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 6,
            ctypes.byref(derived_ref),
        )
        if rv_ref == CKR_OK:
            ref_bytes = _extract_key_value(derived_ref.value)
            destroy_quietly(raw, sh, derived_ref.value)
            if ref_bytes is not None and probe_bytes is not None:
                truncated = 1 if probe_bytes == ref_bytes else 0
                print(f"TRUNCATED:{{truncated}}")
                print(f"PROBE_HEX:{{probe_bytes.hex()}}")
                print(f"REF_HEX:{{ref_bytes.hex()}}")
finally:
    del mmap_buf
    mm = None
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=180, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_DeriveKey(HKDF, ulSaltLen={_OVERSIZE_LEN:#x}, mmap-backed)",
        )

        probe_rv_str = next((ln for ln in stdout.splitlines() if ln.startswith("PROBE_RV:")), None)
        if probe_rv_str is None:
            raise AssertionError(f"Missing PROBE_RV: line in output: {stdout[-300:]}")
        probe_rv = int(probe_rv_str.removeprefix("PROBE_RV:"), 0)

        if probe_rv != 0:
            # Module rejected the oversized salt length -- conformant.
            classify_negative_rv(
                probe_rv,
                _PARAM_REJECT_RVS,
                label=f"C_DeriveKey(HKDF, ulSaltLen={_OVERSIZE_LEN:#x}) rejected",
            )
            return

        # Module accepted the oversized length; check for truncation.
        truncated_str = next(
            (ln for ln in stdout.splitlines() if ln.startswith("TRUNCATED:")), None
        )
        if truncated_str is None:
            # Could not extract key bytes for comparison; treat as ambiguous note.
            note(
                f"C_DeriveKey(HKDF, ulSaltLen={_OVERSIZE_LEN:#x}) returned CKR_OK "
                "but derived key bytes could not be extracted for truncation comparison",
                ComplianceLevel.EXTENDED,
                reference="PKCS#11 3.1 CK_HKDF_PARAMS.ulSaltLen",
                test_id="TestHkdfParamLengthTruncation.test_hkdf_salt_len_truncation",
            )
            return

        truncated = int(truncated_str.removeprefix("TRUNCATED:"))
        if truncated:
            fail_as(
                "wrong_result",
                kind="crypto",
                label=(
                    f"C_DeriveKey(HKDF) silently truncated ulSaltLen {_OVERSIZE_LEN:#x} "
                    "to its low-32 bits (8): derived key equals 8-byte-salt reference"
                ),
            )
        else:
            note(
                f"C_DeriveKey(HKDF, ulSaltLen={_OVERSIZE_LEN:#x}) honored the full "
                "64-bit salt length: derived key differs from 8-byte-salt reference",
                ComplianceLevel.EXTENDED,
                reference="PKCS#11 3.1 CK_HKDF_PARAMS.ulSaltLen",
                test_id="TestHkdfParamLengthTruncation.test_hkdf_salt_len_truncation",
            )

    @pytest.mark.slow
    def test_hkdf_info_len_truncation(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """HKDF must not silently truncate ulInfoLen from 64 to 32 bits.

        Uses a full-length mmap-backed info buffer to avoid any over-read.
        Truncation is detected by comparing derived key material: a module that
        truncates ulInfoLen to 8 (low32) produces the same output as the 8-byte
        reference derive -> wrong_result.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not advertised")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _HKDF_BASE_KEY_IMPORT
            + _HKDF_DERIVE_TEMPLATE
            + f"""
from pkcs11_check.raw.types_std import (
    CK_HKDF_PARAMS, CK_MECHANISM, CKM_HKDF_DERIVE, CKM_SHA256,
    CKF_HKDF_SALT_NULL,
)

OVERSIZE_LEN = {_OVERSIZE_LEN}   # (1<<32)+8; low32 = 8

# Full-length demand-zero mmap: OVERSIZE_LEN bytes, properly backed so no
# protected-memory read can occur if a 64-bit module honors the full length.
mm = _mmap.mmap(
    -1, OVERSIZE_LEN,
    _mmap.MAP_PRIVATE | _mmap.MAP_ANONYMOUS,
    _mmap.PROT_READ | _mmap.PROT_WRITE,
)
# Seed the first 8 bytes with a known pattern (the low32 portion).
for i, b in enumerate(b"infoinfo"):
    mm[i] = b
mmap_buf = (ctypes.c_ubyte * OVERSIZE_LEN).from_buffer(mm)

try:
    # --- Probe derive: full OVERSIZE_LEN info (mmap-backed) ---
    params_probe = CK_HKDF_PARAMS()
    params_probe.bExtract = 1
    params_probe.bExpand = 1
    params_probe.prfHashMechanism = CKM_SHA256
    params_probe.ulSaltType = CKF_HKDF_SALT_NULL
    params_probe.pSalt = None
    params_probe.ulSaltLen = 0
    params_probe.hSaltKey = 0
    params_probe.pInfo = ctypes.cast(mmap_buf, ctypes.c_void_p)
    params_probe.ulInfoLen = OVERSIZE_LEN

    mech_probe = CK_MECHANISM()
    mech_probe.mechanism = CKM_HKDF_DERIVE
    mech_probe.pParameter = ctypes.cast(ctypes.pointer(params_probe), ctypes.c_void_p)
    mech_probe.ulParameterLen = ctypes.sizeof(params_probe)

    derived_probe = CK_OBJECT_HANDLE(0)
    rv_probe = raw.C_DeriveKey(
        sh, ctypes.byref(mech_probe), base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 6,
        ctypes.byref(derived_probe),
    )
    print(f"PROBE_RV:0x{{rv_probe:08x}}")

    if rv_probe == CKR_OK:
        probe_bytes = _extract_key_value(derived_probe.value)
        destroy_quietly(raw, sh, derived_probe.value)
    else:
        probe_bytes = None

    # --- Reference derive: only the first 8 bytes of info (low32 portion) ---
    if rv_probe == CKR_OK:
        ref_info = (ctypes.c_ubyte * 8)(*b"infoinfo")
        params_ref = CK_HKDF_PARAMS()
        params_ref.bExtract = 1
        params_ref.bExpand = 1
        params_ref.prfHashMechanism = CKM_SHA256
        params_ref.ulSaltType = CKF_HKDF_SALT_NULL
        params_ref.pSalt = None
        params_ref.ulSaltLen = 0
        params_ref.hSaltKey = 0
        params_ref.pInfo = ctypes.cast(ref_info, ctypes.c_void_p)
        params_ref.ulInfoLen = 8

        mech_ref = CK_MECHANISM()
        mech_ref.mechanism = CKM_HKDF_DERIVE
        mech_ref.pParameter = ctypes.cast(ctypes.pointer(params_ref), ctypes.c_void_p)
        mech_ref.ulParameterLen = ctypes.sizeof(params_ref)

        derived_ref = CK_OBJECT_HANDLE(0)
        rv_ref = raw.C_DeriveKey(
            sh, ctypes.byref(mech_ref), base_key.value,
            ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 6,
            ctypes.byref(derived_ref),
        )
        if rv_ref == CKR_OK:
            ref_bytes = _extract_key_value(derived_ref.value)
            destroy_quietly(raw, sh, derived_ref.value)
            if ref_bytes is not None and probe_bytes is not None:
                truncated = 1 if probe_bytes == ref_bytes else 0
                print(f"TRUNCATED:{{truncated}}")
                print(f"PROBE_HEX:{{probe_bytes.hex()}}")
                print(f"REF_HEX:{{ref_bytes.hex()}}")
finally:
    del mmap_buf
    mm = None
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=180, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_DeriveKey(HKDF, ulInfoLen={_OVERSIZE_LEN:#x}, mmap-backed)",
        )

        probe_rv_str = next((ln for ln in stdout.splitlines() if ln.startswith("PROBE_RV:")), None)
        if probe_rv_str is None:
            raise AssertionError(f"Missing PROBE_RV: line in output: {stdout[-300:]}")
        probe_rv = int(probe_rv_str.removeprefix("PROBE_RV:"), 0)

        if probe_rv != 0:
            # Module rejected the oversized info length -- conformant.
            classify_negative_rv(
                probe_rv,
                _PARAM_REJECT_RVS,
                label=f"C_DeriveKey(HKDF, ulInfoLen={_OVERSIZE_LEN:#x}) rejected",
            )
            return

        # Module accepted the oversized length; check for truncation.
        truncated_str = next(
            (ln for ln in stdout.splitlines() if ln.startswith("TRUNCATED:")), None
        )
        if truncated_str is None:
            # Could not extract key bytes for comparison; treat as ambiguous note.
            note(
                f"C_DeriveKey(HKDF, ulInfoLen={_OVERSIZE_LEN:#x}) returned CKR_OK "
                "but derived key bytes could not be extracted for truncation comparison",
                ComplianceLevel.EXTENDED,
                reference="PKCS#11 3.1 CK_HKDF_PARAMS.ulInfoLen",
                test_id="TestHkdfParamLengthTruncation.test_hkdf_info_len_truncation",
            )
            return

        truncated = int(truncated_str.removeprefix("TRUNCATED:"))
        if truncated:
            fail_as(
                "wrong_result",
                kind="crypto",
                label=(
                    f"C_DeriveKey(HKDF) silently truncated ulInfoLen {_OVERSIZE_LEN:#x} "
                    "to its low-32 bits (8): derived key equals 8-byte-info reference"
                ),
            )
        else:
            note(
                f"C_DeriveKey(HKDF, ulInfoLen={_OVERSIZE_LEN:#x}) honored the full "
                "64-bit info length: derived key differs from 8-byte-info reference",
                ComplianceLevel.EXTENDED,
                reference="PKCS#11 3.1 CK_HKDF_PARAMS.ulInfoLen",
                test_id="TestHkdfParamLengthTruncation.test_hkdf_info_len_truncation",
            )
