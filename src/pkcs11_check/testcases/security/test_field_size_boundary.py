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
     performed -- one with a full-length demand-zero honeypot buffer and ulSaltLen/ulInfoLen
     = OVERSIZE_LEN = (1<<32)+8, then one with only the first 8 bytes (low32 portion).
   - Safety: the buffer is the shared demand-zero honeypot (MAP_PRIVATE|MAP_ANONYMOUS),
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
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
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
    pytest.mark.timeout(240),
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
        result = run_probe(
            "field_size",
            {
                "module_path": str(p11_config.module),
                "which": "rsa_modulus_bits",
                "modulus_bits": _MODULUS_BITS_TRUNC,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_GenerateKeyPair(RSA, CKA_MODULUS_BITS={_MODULUS_BITS_TRUNC:#x})",
        )
        rv = _parse_prefixed_int(result.stdout, "TARGET_RV:")
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
        result = run_probe(
            "field_size",
            {
                "module_path": str(p11_config.module),
                "which": "dh_prime_bits",
                "prime_bits": _PRIME_BITS_TRUNC,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_GenerateKeyPair(DH, CKA_PRIME_BITS={_PRIME_BITS_TRUNC:#x})",
        )
        rv = _parse_prefixed_int(result.stdout, "TARGET_RV:")
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
        result = run_probe(
            "field_size",
            {
                "module_path": str(p11_config.module),
                "which": "dsa_prime_bits",
                "prime_bits": _PRIME_BITS_TRUNC,
            },
            pin=pin_from_config(p11_config),
            timeout=30,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_GenerateKeyPair(DSA, CKA_PRIME_BITS={_PRIME_BITS_TRUNC:#x})",
        )
        rv = _parse_prefixed_int(result.stdout, "TARGET_RV:")
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
        result = run_probe(
            "field_size",
            {
                "module_path": str(p11_config.module),
                "which": "aes_value_len",
                "value_len": TRUNCATION_LOW8,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_GenerateKey(AES, CKA_VALUE_LEN={TRUNCATION_LOW8:#x})",
        )
        rv = _parse_prefixed_int(result.stdout, "TARGET_RV:")
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
        result = run_probe(
            "field_size",
            {
                "module_path": str(p11_config.module),
                "which": "find_objects_count",
                "max_count": TRUNCATION_LOW8,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
        )
        # Crash = buffer overrun (the only real finding for this probe).
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_FindObjects(ulMaxObjectCount={TRUNCATION_LOW8:#x})",
        )
        if "GUARD_OVERWRITE:" in result.stdout:
            overwritten = _parse_prefixed_int(result.stdout, "GUARD_OVERWRITE:")
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
        if "TARGET_RV:" in result.stdout:
            rv = _parse_prefixed_int(result.stdout, "TARGET_RV:")
            classify_negative_rv(
                rv,
                _KEY_SIZE_REJECT_RVS,
                label=f"C_FindObjects(ulMaxObjectCount={TRUNCATION_LOW8:#x})",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# 5. HKDF ulSaltLen / ulInfoLen 64-bit length truncation (honeypot-backed, behavioral)
# ---------------------------------------------------------------------------


class TestHkdfParamLengthTruncation:
    """HKDF ulSaltLen / ulInfoLen 64-bit length truncation detection via behavioral comparison.

    Safety: all probes back the oversized-length salt/info field with the shared demand-zero
    honeypot (MAP_PRIVATE|MAP_ANONYMOUS), so no read beyond the mapping occurs regardless of
    what the module does.

    Detection method: two derives are performed.
      Probe derive: salt/info points to the honeypot, length = OVERSIZE_LEN.
      Reference derive: salt/info points to the first 8 bytes only (the low-32 portion).
    If both succeed and produce the SAME key material, the module silently truncated
    the 64-bit length to its low 32 bits -> wrong_result (crypto kind).
    If both succeed but produce DIFFERENT key material, the module distinguished the
    two lengths -> honored (note, ComplianceLevel.EXTENDED).
    A clean reject of the oversized probe -> classify_negative_rv (conformant).
    """

    @pytest.mark.allocation_amplifying
    @pytest.mark.slow
    def test_hkdf_salt_len_truncation(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """HKDF must not silently truncate ulSaltLen from 64 to 32 bits.

        Uses a full-length honeypot-backed salt buffer to avoid any over-read.
        Truncation is detected by comparing derived key material: a module that
        truncates ulSaltLen to 8 (low32) produces the same output as the 8-byte
        reference derive -> wrong_result.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not advertised")
        result = run_probe(
            "field_size",
            {
                "module_path": str(p11_config.module),
                "which": "hkdf_salt_len",
                "oversize_len": _OVERSIZE_LEN,
            },
            pin=pin_from_config(p11_config),
            timeout=180,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_DeriveKey(HKDF, ulSaltLen={_OVERSIZE_LEN:#x}, honeypot-backed)",
        )

        probe_rv_str = next(
            (ln for ln in result.stdout.splitlines() if ln.startswith("PROBE_RV:")), None
        )
        if probe_rv_str is None:
            raise AssertionError(f"Missing PROBE_RV: line in output: {result.stdout[-300:]}")
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
            (ln for ln in result.stdout.splitlines() if ln.startswith("TRUNCATED:")), None
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

        Uses a full-length honeypot-backed info buffer to avoid any over-read.
        Truncation is detected by comparing derived key material: a module that
        truncates ulInfoLen to 8 (low32) produces the same output as the 8-byte
        reference derive -> wrong_result.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not advertised")
        result = run_probe(
            "field_size",
            {
                "module_path": str(p11_config.module),
                "which": "hkdf_info_len",
                "oversize_len": _OVERSIZE_LEN,
            },
            pin=pin_from_config(p11_config),
            timeout=180,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_DeriveKey(HKDF, ulInfoLen={_OVERSIZE_LEN:#x}, honeypot-backed)",
        )

        probe_rv_str = next(
            (ln for ln in result.stdout.splitlines() if ln.startswith("PROBE_RV:")), None
        )
        if probe_rv_str is None:
            raise AssertionError(f"Missing PROBE_RV: line in output: {result.stdout[-300:]}")
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
            (ln for ln in result.stdout.splitlines() if ln.startswith("TRUNCATED:")), None
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
