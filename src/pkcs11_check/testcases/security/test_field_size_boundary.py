"""Field-size oversize/truncation probes for key-size, find-count, and KDF-param fields.

WS2 Phase 3: close the remaining field-level gaps not covered by Phase 1
(_ISIZE_BOUNDARY_LENGTHS param extensions) or Phase 2 (output-write oracle).

Probed fields
-------------
1. CKA_MODULUS_BITS oversized VALUE in C_GenerateKeyPair(RSA)
   - Declares CKA_MODULUS_BITS = _MODULUS_BITS_TRUNC = (1<<32)+2048 (low32 = 2048).
   - A 32-bit-truncating provider truncates to 2048 and may generate a key → CKR_OK =
     accepted_invalid (impossible 64-bit value was accepted).
   - A correct provider rejects with the canonical triple
     (CKR_ATTRIBUTE_VALUE_INVALID / CKR_TEMPLATE_INCONSISTENT /
     CKR_ARGUMENTS_BAD); CKR_KEY_SIZE_RANGE and other clean rejects are
     adverse XFAIL.
   - Guard: CKM_RSA_PKCS_KEY_PAIR_GEN must be advertised.

2. CKA_PRIME_BITS oversized VALUE in C_GenerateKey(DH/DSA parameter generation)
   - Same pattern; guard on CKM_DH_PKCS_PARAMETER_GEN or CKM_DSA_PARAMETER_GEN.
     CKA_PRIME_BITS applies to parameter generation, not key-pair generation.
   - Skip if the respective parameter-generation mechanism is not advertised.

3. CKA_VALUE_LEN truncation-revealing value in C_GenerateKey (AES)
   - Declares CKA_VALUE_LEN = (1<<32)+16 (low32 = 16, a valid AES key size).
   - A 32-bit-truncating provider sees value_len=16 and returns CKR_OK
     → accepted_invalid (generated a key for an impossible 64-bit value-len).
   - A correct provider rejects the impossible 64-bit length.
   - On CKR_OK the child reads back CKA_VALUE_LEN: a readback of 16 proves
     truncation; without exact readback the finding is invalid-value acceptance.
   - NOTE: This is a distinct probe from the Phase 2 output oracle — it tests the
     CKA_VALUE_LEN template attribute value (what key size to generate), not the
     output buffer write length.
   - Guard: CKM_AES_KEY_GEN.

4. C_FindObjects ulMaxObjectCount with honestly backed capacity
   - CKR_OK treatment: ulMaxObjectCount is a CAP (upper bound on returned handles), not a
     minimum — a provider returning ≤ MAX handles is SPEC-LEGAL regardless of the value.
     Therefore CKR_OK is NOT a finding here. We use allow_ok=True.
   - The child backs all max_count slots plus a guard region beyond them with
     writable demand-zero pages, then always calls C_FindObjectsFinal. The
     declared capacity equals the honestly writable backing; the provider can
     never legally write past it.
   - The finding classes are a CRASH (caught by subprocess isolation), a guard
     overwrite past the declared capacity (memory-safety self-contradiction),
     or a returned count above the declared capacity.
   - A clean CKR_HOST_MEMORY / CKR_DEVICE_MEMORY refusal of the enormous
     capacity is a legitimate resource-refusal PASS; other clean target or
     Final refusals are adverse XFAIL.

5. HKDF ulSaltLen / ulInfoLen 64-bit length truncation detection
   - Detects 64->32-bit length truncation by behavioral comparison: two HKDF derives are
     performed -- one with a full-length demand-zero honeypot buffer and ulSaltLen/ulInfoLen
     = OVERSIZE_LEN = (1<<32)+8, then one with only the first 8 bytes (low32 portion).
   - Safety: the buffer is the shared demand-zero honeypot (MAP_PRIVATE|MAP_ANONYMOUS),
     requested with min_size >= the advertised length, so no read beyond the
     mapping occurs regardless of what the module does.
   - If both derives return CKR_OK and produce the SAME key material -> the module silently
     truncated the 64-bit length to its low 32 bits -> wrong_result (crypto kind).
   - If both derives return CKR_OK and produce DIFFERENT key material -> the module honored
     the full 64-bit length and differentiated between 8-byte and 4GB+ inputs.
   - A canonical reject (CKR_MECHANISM_PARAM_INVALID / CKR_ARGUMENTS_BAD) on the
     oversized derive is conformant -> classify_negative_rv; other clean rejects
     are adverse XFAIL. CKR_OK requires complete TRUNCATED terminal evidence;
     missing/duplicate/malformed/out-of-domain evidence is probe_incomplete FAIL.

All probes follow the Family-A accepted_invalid pattern:
  child prints TARGET_RV:0x<hex> → classify_negative_rv (allow_ok=False unless noted).
FindObjects additionally requires COUNT_OUT/GUARD_OVERWRITE/FINAL_RV markers;
HKDF additionally requires PROBE_RV plus terminal TRUNCATED evidence on CKR_OK.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import fail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_MEMORY,
    CKR_HOST_MEMORY,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)
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

# Truncation-revealing 64-bit value whose low-32 bits equal 16 bytes.
# Sixteen is a valid AES key size, so a 32-bit-truncating provider reads a
# *valid* size and may succeed; a readback of 16 then proves truncation.
_VALUE_LEN_TRUNC = (1 << 32) + 16

# Canonical rejects for an impossible key-size generation premise (RSA modulus
# and DH/DSA domain parameters): PASS only these. Any other defined/vendor
# clean rejection is adverse XFAIL via classify_negative_rv -- including
# CKR_KEY_SIZE_RANGE, whose defined use is for an already-supplied key, not
# this generation premise.
_KEY_SIZE_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
)

# Same canonical generation-premise policy for the AES CKA_VALUE_LEN probe.
_VALUE_LEN_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
)

# HKDF nested parameter length: only a parameter-shape rejection is canonical.
# CKR_DATA_LEN_RANGE (a top-level data length) is not canonical for a nested
# HKDF parameter length -> adverse XFAIL.
_HKDF_PARAM_REJECT_RVS = (
    CKR_MECHANISM_PARAM_INVALID,
    CKR_ARGUMENTS_BAD,
)

# FindObjects resource refusals: the honestly backed capacity is enormous, so
# a clean host/device-memory refusal is a legitimate resource-refusal PASS.
# Every other clean target or Final refusal is adverse XFAIL.
_FIND_OBJECTS_RESOURCE_RVS = (
    CKR_HOST_MEMORY,
    CKR_DEVICE_MEMORY,
)


def _parse_prefixed_int(output: str, prefix: str) -> int:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    raise AssertionError(f"Missing {prefix!r} line in subprocess output: {output[-300:]}")


def _require_single_marker(output: str, prefix: str, *, context: str, protocol: str) -> str:
    """Return the payload of the exactly-one ``prefix`` marker line.

    Missing, duplicate, or malformed child evidence leaves the measurement
    unattributed: ``probe_incomplete`` FAIL, never a compliance note or PASS.
    """
    name = prefix.removesuffix(":")
    matches = [line.removeprefix(prefix) for line in output.splitlines() if line.startswith(prefix)]
    if len(matches) != 1:
        fail_as(
            "probe_incomplete",
            label=context,
            summary=f"{context}: expected exactly one {name} marker, found {len(matches)}",
            detail={"protocol": protocol, "marker": name, "count": len(matches)},
        )
    return matches[0]


def _require_marker_rv(output: str, prefix: str, *, context: str, protocol: str) -> int:
    """Parse an exactly-one ``0x%08x`` return-value marker."""
    raw = _require_single_marker(output, prefix, context=context, protocol=protocol)
    try:
        return int(raw.strip(), 0)
    except ValueError:
        fail_as(
            "probe_incomplete",
            label=context,
            summary=f"{context}: malformed {prefix.removesuffix(':')} marker: {raw!r}",
            detail={"protocol": protocol, "marker": prefix.removesuffix(":"), "value": raw},
        )


def _require_marker_count(output: str, prefix: str, *, context: str, protocol: str) -> int:
    """Parse an exactly-one non-negative decimal count marker."""
    name = prefix.removesuffix(":")
    raw = _require_single_marker(output, prefix, context=context, protocol=protocol)
    try:
        value = int(raw.strip(), 10)
    except ValueError:
        fail_as(
            "probe_incomplete",
            label=context,
            summary=f"{context}: malformed {name} marker: {raw!r}",
            detail={"protocol": protocol, "marker": name, "value": raw},
        )
    if value < 0:
        fail_as(
            "probe_incomplete",
            label=context,
            summary=f"{context}: out-of-domain {name} marker: {raw!r}",
            detail={"protocol": protocol, "marker": name, "value": raw},
        )
    return value


def _require_marker_truncated(output: str, *, context: str) -> int:
    """Parse the terminal TRUNCATED marker: exactly one, value exactly 0 or 1."""
    raw = _require_single_marker(output, "TRUNCATED:", context=context, protocol="hkdf_truncated")
    try:
        value = int(raw.strip(), 10)
    except ValueError:
        fail_as(
            "probe_incomplete",
            label=context,
            summary=f"{context}: malformed TRUNCATED marker: {raw!r}",
            detail={"protocol": "hkdf_truncated", "value": raw},
        )
    if value not in (0, 1):
        fail_as(
            "probe_incomplete",
            label=context,
            summary=f"{context}: out-of-domain TRUNCATED marker: {raw!r}",
            detail={"protocol": "hkdf_truncated", "value": raw},
        )
    return value


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
            interface=getattr(p11_config, "interface", "auto"),
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
# 2. CKA_PRIME_BITS oversized value in C_GenerateKey(DH/DSA parameter generation)
# ---------------------------------------------------------------------------


class TestPrimeBitsOversizedValue:
    """CKA_PRIME_BITS with a truncation-revealing 64-bit value must be rejected.

    Probes C_GenerateKey with CKM_DH_PKCS_PARAMETER_GEN and
    CKM_DSA_PARAMETER_GEN: CKA_PRIME_BITS applies to domain-parameter
    generation. Each node skips unless its parameter mechanism is advertised.
    """

    def test_dh_prime_bits_oversized_value(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_GenerateKey(DH parameter gen) must reject CKA_PRIME_BITS=(1<<32)+1024."""
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_PARAMETER_GEN"):
            pytest.skip("CKM_DH_PKCS_PARAMETER_GEN not advertised")
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
            interface=getattr(p11_config, "interface", "auto"),
        )
        label = f"C_GenerateKey(CKM_DH_PKCS_PARAMETER_GEN, CKA_PRIME_BITS={_PRIME_BITS_TRUNC:#x})"
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=label,
        )
        rv = _parse_prefixed_int(result.stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _KEY_SIZE_REJECT_RVS,
            label=label,
        )

    def test_dsa_prime_bits_oversized_value(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_GenerateKey(DSA parameter gen) must reject CKA_PRIME_BITS=(1<<32)+1024."""
        rs = p11_raw_session
        if not rs.has_mechanism("DSA_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PARAMETER_GEN not advertised")
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
            interface=getattr(p11_config, "interface", "auto"),
        )
        label = f"C_GenerateKey(CKM_DSA_PARAMETER_GEN, CKA_PRIME_BITS={_PRIME_BITS_TRUNC:#x})"
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=label,
        )
        rv = _parse_prefixed_int(result.stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _KEY_SIZE_REJECT_RVS,
            label=label,
        )


# ---------------------------------------------------------------------------
# 3. CKA_VALUE_LEN truncation-revealing value in C_GenerateKey (AES)
# ---------------------------------------------------------------------------


def _classify_aes_acceptance(stdout: str, *, label: str, value_len: int) -> None:
    """Classify CKR_OK on an impossible CKA_VALUE_LEN: FAIL with graded wording.

    A CKA_VALUE_LEN readback equal to the low 32 bits proves the provider
    truncated the 64-bit value; without exact readback the finding is
    invalid-value acceptance, never proven truncation.
    """
    low32 = value_len & 0xFFFFFFFF
    readbacks = [
        line.removeprefix("VALUE_LEN:")
        for line in stdout.splitlines()
        if line.startswith("VALUE_LEN:")
    ]
    readback: int | None = None
    if len(readbacks) == 1:
        try:
            readback = int(readbacks[0].strip(), 10)
        except ValueError:
            readback = None
    if readback == low32:
        fail_as(
            "accepted_invalid",
            label=label,
            summary=(
                f"{label}: accepted invalid (CKR_OK): provider truncated the impossible "
                f"64-bit CKA_VALUE_LEN to its low-32 bits ({low32} bytes, "
                f"CKA_VALUE_LEN readback {readback})"
            ),
        )
    fail_as(
        "accepted_invalid",
        label=label,
        summary=(
            f"{label}: accepted invalid (CKR_OK): provider accepted the impossible 64-bit "
            "CKA_VALUE_LEN without an exact readback, reported as invalid-value acceptance"
        ),
    )


class TestGenerateKeyValueLenTruncation:
    """CKA_VALUE_LEN with a truncation-revealing 64-bit value in C_GenerateKey.

    Uses _VALUE_LEN_TRUNC = (1<<32)+16 so low32 = 16 bytes (a valid AES key
    size). A 32-bit-truncating provider may accept and generate a key with
    value_len=16 → CKR_OK = accepted_invalid (the 64-bit value is impossible).
    A correct provider rejects the impossible 64-bit length.

    CKR_OK treatment: NOT spec-legal. The CKA_VALUE_LEN value (1<<32)+16 is
    an impossible key size — no AES key is that large. CKR_OK means the
    provider accepted the impossible value, which is the accepted_invalid
    finding. We use allow_ok=False (default).
    """

    def test_aes_keygen_value_len_truncation(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_GenerateKey(AES) must reject CKA_VALUE_LEN=(1<<32)+16."""
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
                "value_len": _VALUE_LEN_TRUNC,
            },
            pin=pin_from_config(p11_config),
            timeout=10,
            coverage="session",
            interface=getattr(p11_config, "interface", "auto"),
        )
        label = f"C_GenerateKey(AES, CKA_VALUE_LEN={_VALUE_LEN_TRUNC:#x})"
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=label,
        )
        rv = _parse_prefixed_int(result.stdout, "TARGET_RV:")
        if rv == CKR_OK:
            _classify_aes_acceptance(result.stdout, label=label, value_len=_VALUE_LEN_TRUNC)
            return
        classify_negative_rv(
            rv,
            _VALUE_LEN_REJECT_RVS,
            label=label,
        )


# ---------------------------------------------------------------------------
# 4. C_FindObjects ulMaxObjectCount truncation-revealing value
# ---------------------------------------------------------------------------


class TestFindObjectsCountTruncation:
    """C_FindObjects with an honestly backed ulMaxObjectCount capacity.

    CKR_OK treatment: ulMaxObjectCount is a CAP (upper bound), not a minimum.
    The spec says C_FindObjects returns AT MOST ulMaxObjectCount handles.
    Returning fewer than the cap is ALWAYS spec-legal, so CKR_OK is NOT a
    finding here. We use allow_ok=True.

    The child backs all max_count slots plus a guard region beyond them with
    writable demand-zero pages, so the provider can never legally write past
    the declared capacity. The finding classes are a CRASH (caught by
    subprocess isolation), a guard overwrite (memory-safety
    self-contradiction), or a returned count above the declared capacity.

    A clean CKR_HOST_MEMORY / CKR_DEVICE_MEMORY refusal of the enormous
    capacity is a legitimate resource-refusal PASS; other clean target or
    Final refusals are adverse XFAIL. PASS requires an intact guard,
    count <= capacity, and a successful Final.
    """

    def test_find_objects_oversized_count_survives(
        self,
        p11_raw_session: Any,  # ensures module loaded + session open before subprocess probe
        p11_config: Any,
    ) -> None:
        """C_FindObjects must honor the honestly backed ulMaxObjectCount capacity."""
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
            interface=getattr(p11_config, "interface", "auto"),
        )
        context = f"C_FindObjects(ulMaxObjectCount={TRUNCATION_LOW8:#x})"
        # Crash = buffer overrun (the most severe finding for this probe).
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=context,
        )
        target_rv = _require_marker_rv(
            result.stdout, "TARGET_RV:", context=context, protocol="find_markers"
        )
        count = _require_marker_count(
            result.stdout, "COUNT_OUT:", context=context, protocol="find_markers"
        )
        guard = _require_marker_count(
            result.stdout, "GUARD_OVERWRITE:", context=context, protocol="find_markers"
        )
        final_rv = _require_marker_rv(
            result.stdout, "FINAL_RV:", context=context, protocol="find_markers"
        )
        # Check the guard region first -- an out-of-bounds write is the most
        # severe outcome. Memory-safety evidence, not kind="crypto".
        if guard:
            fail_as(
                "self_contradiction",
                kind="metadata",
                label="C_FindObjects handle-buffer guard overwrite",
                actual=f"{guard} guard word(s)",
                summary=(
                    f"C_FindObjects wrote {guard} guard word(s) past the "
                    f"{TRUNCATION_LOW8}-slot handle buffer "
                    f"(ulMaxObjectCount={TRUNCATION_LOW8:#x}): out-of-bounds write "
                    "(memory-safety)"
                ),
            )
        if count > TRUNCATION_LOW8:
            fail_as(
                "self_contradiction",
                kind="metadata",
                label=(
                    f"C_FindObjects returned {count} handles above the declared "
                    f"capacity {TRUNCATION_LOW8}"
                ),
                actual=f"{count} handles",
                summary=(
                    f"{context}: returned {count} handles above the declared capacity "
                    f"{TRUNCATION_LOW8}"
                ),
            )
        # CKR_OK is spec-legal (ulMaxObjectCount is a cap), so allow_ok=True;
        # only a resource refusal is a canonical PASS alongside it.
        classify_negative_rv(
            target_rv,
            _FIND_OBJECTS_RESOURCE_RVS,
            label=context,
            allow_ok=True,
        )
        # PASS additionally requires a successful Final.
        if final_rv != CKR_OK:
            classify_negative_rv(
                final_rv,
                (),
                label=f"{context} C_FindObjectsFinal",
            )


# ---------------------------------------------------------------------------
# 5. HKDF ulSaltLen / ulInfoLen 64-bit length truncation (honeypot-backed, behavioral)
# ---------------------------------------------------------------------------


def _classify_hkdf_probe(
    stdout: str, *, context: str, test_id: str, field: str, ref_field: str
) -> None:
    """Classify one HKDF oversize-length probe: canonical reject, or CKR_OK with complete evidence.

    CKR_OK requires exactly-one terminal TRUNCATED evidence (0 or 1) after both
    probe and reference derivation/extraction complete; missing, duplicate,
    malformed, or out-of-domain evidence is probe_incomplete FAIL.
    """
    probe_rv = _require_marker_rv(stdout, "PROBE_RV:", context=context, protocol="hkdf_probe_rv")
    if probe_rv != CKR_OK:
        # Module rejected the oversized length -- conformant only if canonical.
        classify_negative_rv(
            probe_rv,
            _HKDF_PARAM_REJECT_RVS,
            label=f"{context} rejected",
        )
        return

    # Module accepted the oversized length; truncation evidence is mandatory.
    truncated = _require_marker_truncated(stdout, context=context)
    if truncated:
        fail_as(
            "wrong_result",
            kind="crypto",
            label=(
                f"C_DeriveKey(HKDF) silently truncated {field} {_OVERSIZE_LEN:#x} "
                f"to its low-32 bits (8): derived key equals 8-byte-{ref_field} reference"
            ),
        )
    else:
        note(
            f"{context} honored the full 64-bit {ref_field} length: derived key differs "
            f"from 8-byte-{ref_field} reference",
            ComplianceLevel.EXTENDED,
            reference=f"PKCS#11 3.1 CK_HKDF_PARAMS.{field}",
            test_id=test_id,
        )


class TestHkdfParamLengthTruncation:
    """HKDF ulSaltLen / ulInfoLen 64-bit length truncation detection via behavioral comparison.

    Safety: all probes back the oversized-length salt/info field with the shared demand-zero
    honeypot (MAP_PRIVATE|MAP_ANONYMOUS), requested with min_size >= the advertised
    length, so no read beyond the mapping occurs regardless of what the module does.

    Detection method: two derives are performed.
      Probe derive: salt/info points to the honeypot, length = OVERSIZE_LEN.
      Reference derive: salt/info points to the first 8 bytes only (the low-32 portion).
    If both succeed and produce the SAME key material, the module silently truncated
    the 64-bit length to its low 32 bits -> wrong_result (crypto kind).
    If both succeed but produce DIFFERENT key material, the module distinguished the
    two lengths -> honored (note, ComplianceLevel.EXTENDED).
    A canonical reject of the oversized probe -> classify_negative_rv (conformant);
    other clean rejects are adverse XFAIL. CKR_OK without complete TRUNCATED
    terminal evidence -> probe_incomplete FAIL.
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
            interface=getattr(p11_config, "interface", "auto"),
        )
        context = f"C_DeriveKey(HKDF, ulSaltLen={_OVERSIZE_LEN:#x}, honeypot-backed)"
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=context,
        )
        _classify_hkdf_probe(
            result.stdout,
            context=context,
            test_id="TestHkdfParamLengthTruncation.test_hkdf_salt_len_truncation",
            field="ulSaltLen",
            ref_field="salt",
        )

    @pytest.mark.allocation_amplifying
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
            interface=getattr(p11_config, "interface", "auto"),
        )
        context = f"C_DeriveKey(HKDF, ulInfoLen={_OVERSIZE_LEN:#x}, honeypot-backed)"
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=context,
        )
        _classify_hkdf_probe(
            result.stdout,
            context=context,
            test_id="TestHkdfParamLengthTruncation.test_hkdf_info_len_truncation",
            field="ulInfoLen",
            ref_field="info",
        )
