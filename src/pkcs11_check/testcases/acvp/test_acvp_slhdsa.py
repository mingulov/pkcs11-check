"""NIST ACVP SLH-DSA test vectors - the ONLY source for SLH-DSA vectors.

Tests SLH-DSA key generation, signature verification and generation using official
NIST ACVP vectors. Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as, set_mechanism, xfail_as
from pkcs11_check.raw.pack_mechanisms import mech_sign_context
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    import_pqc_private_key,
    import_pqc_public_key,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CKA_PUBLIC_KEY_INFO,
    CKA_SIGN,
    CKA_VERIFY,
    CKF_VERIFY,
    CKK_SLH_DSA,
    CKM_SLH_DSA,
    CKP_SLH_DSA_SHA2_128F,
    CKP_SLH_DSA_SHA2_128S,
    CKP_SLH_DSA_SHA2_192F,
    CKP_SLH_DSA_SHA2_192S,
    CKP_SLH_DSA_SHA2_256F,
    CKP_SLH_DSA_SHA2_256S,
    CKP_SLH_DSA_SHAKE_128F,
    CKP_SLH_DSA_SHAKE_128S,
    CKP_SLH_DSA_SHAKE_192F,
    CKP_SLH_DSA_SHAKE_192S,
    CKP_SLH_DSA_SHAKE_256F,
    CKP_SLH_DSA_SHAKE_256S,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases._signature_policy import (
    NON_CLEAN_SIGNATURE_REJECT_RVS,
    SIGNATURE_REJECT_RVS,
    signature_rejected_or_xfail,
)
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors
from pkcs11_check.testcases.conftest import (
    is_known_error,
    skip_unless_mechanism_flag,
    xfail_if_known_ckr,
)
from pkcs11_check.testcases.data import ACVP_DIR, load_json_cached

pytestmark = [pytest.mark.pqc, pytest.mark.kat, pytest.mark.acvp]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

# ACVP parameter set name -> PKCS#11 CKP parameter set int
_PARAM_SET_MAP: dict[str, int] = {
    "SLH-DSA-SHA2-128s": CKP_SLH_DSA_SHA2_128S,
    "SLH-DSA-SHA2-128f": CKP_SLH_DSA_SHA2_128F,
    "SLH-DSA-SHAKE-128s": CKP_SLH_DSA_SHAKE_128S,
    "SLH-DSA-SHAKE-128f": CKP_SLH_DSA_SHAKE_128F,
    "SLH-DSA-SHA2-192s": CKP_SLH_DSA_SHA2_192S,
    "SLH-DSA-SHA2-192f": CKP_SLH_DSA_SHA2_192F,
    "SLH-DSA-SHAKE-192s": CKP_SLH_DSA_SHAKE_192S,
    "SLH-DSA-SHAKE-192f": CKP_SLH_DSA_SHAKE_192F,
    "SLH-DSA-SHA2-256s": CKP_SLH_DSA_SHA2_256S,
    "SLH-DSA-SHA2-256f": CKP_SLH_DSA_SHA2_256F,
    "SLH-DSA-SHAKE-256s": CKP_SLH_DSA_SHAKE_256S,
    "SLH-DSA-SHAKE-256f": CKP_SLH_DSA_SHAKE_256F,
}

# ACVP parameter set name -> expected public-key length in bytes (2n for
# n = 16/24/32). A recovered key of any other length is malformed readback,
# never import input: without this a short key reaches import, the provider
# rejects it with CKR_KEY_SIZE_RANGE, and the import xfail hides the defect.
_SLH_DSA_PUBKEY_LEN: dict[str, int] = {
    "SLH-DSA-SHA2-128s": 32,
    "SLH-DSA-SHA2-128f": 32,
    "SLH-DSA-SHAKE-128s": 32,
    "SLH-DSA-SHAKE-128f": 32,
    "SLH-DSA-SHA2-192s": 48,
    "SLH-DSA-SHA2-192f": 48,
    "SLH-DSA-SHAKE-192s": 48,
    "SLH-DSA-SHAKE-192f": 48,
    "SLH-DSA-SHA2-256s": 64,
    "SLH-DSA-SHA2-256f": 64,
    "SLH-DSA-SHAKE-256s": 64,
    "SLH-DSA-SHAKE-256f": 64,
}

# import-audit D3 boundary: SLH-DSA is advertised when these sites run (has_mechanism gate
# precedes every import). For PQC the genuine-absence signal IS mechanism
# advertisement -- there is no curve-absence CKR analogue. So once advertised,
# ANY clean import reject is "advertised but not operational" -> xfail (mirrors
# the ML-DSA precedent in test_wycheproof_mldsa* and the documented ML-KEM
# raw-private import convention). The previous skip/xfail
# split (CKR_FUNCTION_FAILED alone xfailed; the rest skipped) was an incoherent
# asymmetry -- both buckets are the same not-operational signal.
_PQC_IMPORT_NOT_OPERATIONAL_RVS = (
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_KEY_SIZE_RANGE,
    CKR_FUNCTION_FAILED,
)

_SLHDSA_RUNTIME_REJECT_RVS = (
    *NON_CLEAN_SIGNATURE_REJECT_RVS,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _xfail_if_import_not_operational(exc: AssertionError, label: str) -> None:
    """Advertised SLH-DSA whose canonical key import is refused -> xfail.

    A clean import reject (any code in ``_PQC_IMPORT_NOT_OPERATIONAL_RVS``) on an
    advertised mechanism is "advertised but not operational" per the
    classification model -- recorded as xfail, never hidden as skip. A non-CKR
    AssertionError (harness/ctypes bug) propagates.
    """
    if isinstance(exc, CkrAssertionError) and is_known_error(exc, _PQC_IMPORT_NOT_OPERATIONAL_RVS):
        classify(
            "not_operational",
            kind="crypto",
            label=f"SLH-DSA:import ({label})",
            summary=not_operational_reason(f"SLH-DSA:import ({label})", ckr_name(exc.rv)),
        )
    raise exc


def _xfail_if_slhdsa_runtime_reject(exc: AssertionError, label: str) -> None:
    xfail_if_known_ckr(
        exc,
        _SLHDSA_RUNTIME_REJECT_RVS,
        f"{label}: advertised SLH-DSA operation is not operational",
    )
    raise exc


def _slhdsa_verify_result_or_xfail(exc: AssertionError, label: str, *, expected_pass: bool) -> bool:
    if expected_pass:
        if is_known_error(exc, SIGNATURE_REJECT_RVS):
            return False
        xfail_if_known_ckr(
            exc,
            _SLHDSA_RUNTIME_REJECT_RVS,
            f"{label}: valid SLH-DSA signature verification rejected",
        )
        raise exc
    return signature_rejected_or_xfail(exc, label)


def _der_length(der: bytes, pos: int) -> tuple[int, int]:
    """Return ``(value_offset, value_length)`` for the DER length at ``pos``.

    Enforces DER minimality: short form below 128, long form with no
    leading zero octets and only at 128 and above.
    """
    first = der[pos]
    if first < 0x80:
        return pos + 1, first
    n_bytes = first & 0x7F
    if n_bytes == 0 or n_bytes > 4:
        raise ValueError("indefinite or oversize DER length")
    if der[pos + 1] == 0x00:
        raise ValueError("nonminimal DER length (leading zero octet)")
    length = int.from_bytes(der[pos + 1 : pos + 1 + n_bytes], "big")
    if length < 0x80:
        raise ValueError("nonminimal DER length (long form below 128)")
    return pos + 1 + n_bytes, length


def _wellformed_oid_contents(contents: bytes) -> bool:
    """Whether OID contents are well-formed base-128 subidentifiers.

    Nonempty, every subidentifier terminated (final octet high bit clear)
    and minimal (no leading 0x80 octet). Arc values are not pinned, so
    unfamiliar but well-formed OIDs keep parsing.
    """
    if not contents:
        return False
    start = True
    for byte in contents:
        if start:
            if byte == 0x80:
                return False
            start = False
        if (byte & 0x80) == 0:
            start = True
    return start


def _minimal_twos_complement(contents: bytes) -> bool:
    """Whether INTEGER/ENUMERATED contents are nonempty and minimal."""
    if not contents:
        return False
    if len(contents) == 1:
        return True
    if contents[0] == 0x00:
        return (contents[1] & 0x80) != 0
    if contents[0] == 0xFF:
        return (contents[1] & 0x80) != 0x80
    return True


def _wellformed_bit_string(contents: bytes) -> bool:
    """Whether BIT STRING contents carry a valid unused-bit count with zeroed
    trailing bits."""
    if not contents or contents[0] > 7:
        return False
    unused = contents[0]
    return unused == 0 or (contents[-1] & ((1 << unused) - 1)) == 0


# Universal tag numbers whose constructed bit must be set (SEQUENCE, SET and
# the always-constructed EXTERNAL / EMBEDDED PDV). Every other universal tag
# is primitive-only in DER, including all string types; non-universal classes
# keep the bit free.
_CONSTRUCTED_UNIVERSAL = frozenset({8, 11, 16, 17})


def _tlv_end(der: bytes, at: int, end: int, depth: int = 0) -> int | None:
    """End offset of one well-formed TLV at ``at``, or None.

    Single-byte tags with minimal lengths. Universal tags obey their DER
    encoding rules (constructed-bit direction, no EOC in definite length,
    BOOLEAN/INTEGER/ENUMERATED/BIT STRING content shapes, empty NULL,
    well-formed OIDs); constructed values must hold complete, recursively
    well-formed children. Other primitive contents are opaque bytes. Depth
    is capped: parameters never nest legitimately, so deep nesting is
    treated as malformed rather than risking runaway recursion.
    """
    if depth > 32 or at + 2 > end or (der[at] & 0x1F) == 0x1F:
        return None
    try:
        voff, vlen = _der_length(der, at + 1)
    except (IndexError, ValueError):
        return None
    if voff + vlen > end:
        return None
    tag = der[at]
    contents = der[voff : voff + vlen]
    if (tag & 0xC0) == 0:  # universal class: encoding rules apply
        number = tag & 0x1F
        constructed = (tag & 0x20) != 0
        if tag == 0x00:  # EOC has no place in definite length
            return None
        if constructed != (number in _CONSTRUCTED_UNIVERSAL):
            return None
        if number == 0x01:  # BOOLEAN: one canonical octet
            if contents not in (b"\x00", b"\xff"):
                return None
        elif number in (0x02, 0x0A):  # INTEGER, ENUMERATED
            if not _minimal_twos_complement(contents):
                return None
        elif number == 0x03:  # BIT STRING
            if not _wellformed_bit_string(contents):
                return None
        elif number == 0x05:  # NULL: empty contents only
            if vlen != 0:
                return None
        elif number == 0x06:  # OID: well-formed subidentifiers
            if not _wellformed_oid_contents(contents):
                return None
    if tag & 0x20:  # constructed: complete children, recursively
        pos = voff
        while pos < voff + vlen:
            child = _tlv_end(der, pos, voff + vlen, depth + 1)
            if child is None:
                return None
            pos = child
    return voff + vlen


def _single_tlv(der: bytes, at: int, end: int) -> bool:
    """Whether ``der[at:end]`` is exactly one well-formed TLV."""
    return _tlv_end(der, at, end) == end


def _spki_public_key_bytes(der: bytes) -> bytes | None:
    """Extract raw public-key bytes from a SubjectPublicKeyInfo DER blob.

    Minimal ASN.1 walk over ``SEQUENCE { AlgorithmIdentifier, BIT STRING }``
    returning the BIT STRING contents -- the same shape as the wycheproof
    SPKI fallback (``_key_decoders``).
    The full encoding is validated: lengths are minimal with the outer
    length matching the input exactly (no truncation, no trailing bytes);
    the AlgorithmIdentifier must carry a well-formed OBJECT IDENTIFIER
    (its value is not pinned) followed by at most one well-formed
    parameters element; the BIT STRING must end at the outer end, and the
    key payload must be nonempty (an SLH-DSA public key cannot be empty).
    Returns None when the DER cannot be parsed at all.
    """
    try:
        if len(der) < 2 or der[0] != 0x30:  # outer SEQUENCE
            return None
        pos, outer_len = _der_length(der, 1)
        if pos + outer_len != len(der):  # truncated or trailing garbage
            return None
        if pos >= len(der) or der[pos] != 0x30:  # AlgorithmIdentifier SEQUENCE
            return None
        val, length = _der_length(der, pos + 1)
        if length < 2 or val + length > len(der) or der[val] != 0x06:
            return None
        oval, olen = _der_length(der, val + 1)
        if oval + olen > val + length:  # OID overruns its AlgorithmIdentifier
            return None
        if not _wellformed_oid_contents(der[oval : oval + olen]):
            return None
        params_at, alg_end = oval + olen, val + length
        if params_at < alg_end and not _single_tlv(der, params_at, alg_end):
            return None
        pos = val + length
        if pos >= len(der) or der[pos] != 0x03:  # BIT STRING
            return None
        val, length = _der_length(der, pos + 1)
        if length < 2 or val + length != len(der):  # payload + exact fit
            return None
        if der[val] != 0x00:  # unused-bits count; PQC keys use 0
            return None
        return der[val + 1 : val + length]
    except (IndexError, ValueError):
        return None


def _recover_slhdsa_public_key(rs: Any, priv_key: int, vec_id: str, param_name: str) -> bytes:
    """Recover the SLH-DSA public key from the imported private key.

    Reads back CKA_PUBLIC_KEY_INFO (SubjectPublicKeyInfo DER) and extracts
    the raw key bytes. Returns b"" when recovery is impossible -- attribute
    unsupported, missing, sensitive, refused, or empty -- so the caller emits
    the explicit oracle-unavailable record. Only a DEFINED CKR refusal is
    absorbed here; an undefined CK_RV propagates, and nonempty-but-unparseable
    SPKI bytes fail as provider-malformed metadata (present-malformed fails
    per the require_* idiom; only missing stays unavailable). A structurally
    valid key of the wrong length for ``param_name`` likewise fails here, so
    it never reaches import to decay into a not-operational xfail.
    """
    try:
        attrs = read_attributes(rs.raw, rs.sh, priv_key, [CKA_PUBLIC_KEY_INFO])
    except CkrAssertionError as exc:
        # audit-ok: recovery fallback for DEFINED refusals only (standard or
        # vendor CKRs, e.g. CKR_FUNCTION_FAILED); b"" always reaches the
        # caller's explicit oracle-unavailable xfail, never a silent pass.
        if not (is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv)):
            raise
        return b""
    spki = attr_or_record(
        attrs,
        CKA_PUBLIC_KEY_INFO,
        label=f"{vec_id}: SLH-DSA CKA_PUBLIC_KEY_INFO readback",
        reason="not_operational",
        inherit_mechanism=False,
    )
    if spki is MISSING_ATTRIBUTE or not isinstance(spki, bytes) or len(spki) == 0:
        return b""
    parsed = _spki_public_key_bytes(spki)
    if parsed is None:
        fail_as(
            "wrong_result",
            kind="metadata",
            label=f"{vec_id}: SLH-DSA CKA_PUBLIC_KEY_INFO readback",
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            summary=(
                f"{vec_id}: SLH-DSA CKA_PUBLIC_KEY_INFO readback present but "
                f"malformed ({len(spki)} unparseable bytes)"
            ),
        )
    expected = _SLH_DSA_PUBKEY_LEN.get(param_name)
    if expected is not None and len(parsed) != expected:
        fail_as(
            "wrong_result",
            kind="metadata",
            label=f"{vec_id}: SLH-DSA CKA_PUBLIC_KEY_INFO readback",
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            summary=(
                f"{vec_id}: SLH-DSA CKA_PUBLIC_KEY_INFO readback carries a "
                f"{len(parsed)}-byte key, expected {expected} for {param_name}"
            ),
        )
    return parsed


def _load_keygen_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load SLH-DSA keyGen ACVP vectors.

    Tests deterministic key generation by importing the expected private key
    and verifying it matches the expected public key through sign/verify.
    """
    all_vecs = load_acvp_vectors("SLH-DSA-keyGen-FIPS205")
    result = []
    # Full take: 120 vectors (10 per set x 12 sets). Measured ~0.5-6 s per
    # 2-vector set on SLH-DSA-capable lanes, so the full file stays within
    # the established heavy-file budget (see _load_siggen_vectors).
    for vec in all_vecs:
        group = vec["group"]
        param_name = group.get("parameterSet", "")
        param_set = _PARAM_SET_MAP.get(param_name)
        if param_set is None:
            continue

        exp = vec["expected"]
        sk = exp.get("sk", "")
        pk = exp.get("pk", "")
        if not sk or not pk:
            continue

        merged: dict[str, Any] = {
            "param_set": param_set,
            "param_name": param_name,
            "sk": bytes.fromhex(sk),
            "pk": bytes.fromhex(pk),
            "tc_id": vec["input"].get("tcId", 0),
        }
        vec_id = f"keyGen-{param_name}-tc{merged['tc_id']}"
        result.append((vec_id, merged))
    return result


def _load_sigver_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load SLH-DSA sigVer ACVP vectors merged with expected results."""
    all_vecs = load_acvp_vectors("SLH-DSA-sigVer-FIPS205")
    result = []
    # External-pure take only: 168 vectors (14 per set x 12 sets) out of the
    # 504-row corpus (168 external-pure + 168 external-preHash + 168
    # internal-pure). PreHash groups carry full messages plus a per-test
    # hashAlg for the hash-sign mechanisms -- not pre-hashed digests (proven:
    # sigVer tc15 is a 6361-byte message with hashAlg SHA2-224) -- so they are
    # not pure CKM_SLH_DSA inputs; internal groups use the Verify_internal
    # calling convention, which is not externally verifiable -- routing their
    # expected-valid vectors through pure verify yields false provider
    # failures (proven: internal tc174 fails OpenSSL pure verify while the
    # empty-context external-pure control tc154 passes). Verifies cost ~1-12
    # ms each, so the take adds seconds at most.
    for vec in all_vecs:
        inp = vec["input"]
        exp = vec["expected"]
        group = vec["group"]
        if group.get("signatureInterface") != "external" or group.get("preHash") != "pure":
            continue
        param_name = group.get("parameterSet", "")
        param_set = _PARAM_SET_MAP.get(param_name)
        if param_set is None:
            continue

        pk = inp.get("pk", "")
        msg = inp.get("message", "")
        sig = inp.get("signature", "")
        ctx_hex = inp.get("context", "")
        if not pk or not msg or not sig:
            continue

        merged: dict[str, Any] = {
            "param_set": param_set,
            "param_name": param_name,
            "pk": bytes.fromhex(pk),
            "msg": bytes.fromhex(msg),
            "sig": bytes.fromhex(sig),
            "context": bytes.fromhex(ctx_hex) if ctx_hex else b"",
            "expected_pass": exp.get("testPassed", True),
            "tc_id": inp.get("tcId", 0),
        }
        vec_id = f"sigVer-{param_name}-tc{merged['tc_id']}"
        result.append((vec_id, merged))
    return result


def _load_siggen_pk_by_tcid() -> dict[int, bytes]:
    """Public keys for sigGen vectors, keyed by tcId.

    ``load_acvp_vectors`` merges prompt + expectedResults only, and neither
    carries the public key for sigGen (prompt has sk/message/context;
    expectedResults has the reference signature). The companion
    internalProjection.json carries pk per test; tcIds are unique across
    the file, so a flat map is unambiguous. A missing file yields {} and rows
    without a pk fall back to CKA_PUBLIC_KEY_INFO recovery, xfailing
    not_operational when the sign-then-verify oracle cannot run.
    """
    internal_file = ACVP_DIR / "SLH-DSA-sigGen-FIPS205" / "internalProjection.json"
    if not internal_file.exists():
        return {}
    data = load_json_cached(internal_file)
    result: dict[int, bytes] = {}
    for tg in data.get("testGroups", []):
        for test in tg.get("tests", []):
            pk_hex = test.get("pk", "")
            if not pk_hex:
                continue
            try:
                result[test.get("tcId", 0)] = bytes.fromhex(pk_hex)
            except ValueError:
                continue
    return result


def _load_siggen_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load SLH-DSA sigGen ACVP vectors merged with expected results."""
    all_vecs = load_acvp_vectors("SLH-DSA-sigGen-FIPS205")
    pk_by_tcid = _load_siggen_pk_by_tcid()
    result = []
    # External-pure take only: 168 vectors (14 per set x 12 sets) out of the
    # 624-row corpus (168 external-pure + 168 internal + 288 preHash, both
    # context shapes throughout the take). PreHash groups carry full messages
    # plus a per-test hashAlg for the hash-sign mechanisms -- not pre-hashed
    # digests (proven: sigGen tc8 is a 4405-byte message) -- so they are not
    # pure CKM_SLH_DSA inputs; internal groups use the Sign_internal calling
    # convention, which is not externally verifiable (same proof as
    # _load_sigver_vectors: internal tc174 fails pure verify while the
    # external-pure control tc154 passes). Cost is bounded by measurement:
    # round-0198 lanes ran the sampled file in ~11-43 s (kryoptic/bouncyhsm),
    # so the 168-vector take stays within the established heavy-file budget,
    # which the shard balancer isolates (see DEFAULT_HEAVY_BASENAMES).
    for vec in all_vecs:
        inp = vec["input"]
        group = vec["group"]
        if group.get("signatureInterface") != "external" or group.get("preHash") != "pure":
            continue
        param_name = group.get("parameterSet", "")
        param_set = _PARAM_SET_MAP.get(param_name)
        if param_set is None:
            continue

        sk = inp.get("sk", "")
        msg = inp.get("message", "")
        if not sk or not msg:
            continue

        ctx_hex = inp.get("context", "")

        merged: dict[str, Any] = {
            "param_set": param_set,
            "param_name": param_name,
            "sk": bytes.fromhex(sk),
            "msg": bytes.fromhex(msg),
            "context": bytes.fromhex(ctx_hex) if ctx_hex else b"",
            "tc_id": inp.get("tcId", 0),
        }
        pk = pk_by_tcid.get(merged["tc_id"])
        if pk:
            merged["pk"] = pk
        vec_id = f"sigGen-{param_name}-tc{merged['tc_id']}"
        result.append((vec_id, merged))
    return result


_KEYGEN_VECTORS = _load_keygen_vectors()
_SIGVER_VECTORS = _load_sigver_vectors()
_SIGGEN_VECTORS = _load_siggen_vectors()


@pytest.mark.parametrize("vec_id,vec", _KEYGEN_VECTORS, ids=[v[0] for v in _KEYGEN_VECTORS])
def test_slhdsa_keygen(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """SLH-DSA key generation test from NIST ACVP vectors.

    Imports the expected private key and verifies it can be used for signing,
    with the expected public key used for verification.
    """
    rs = p11_module_session
    if not rs.has_mechanism("SLH_DSA"):
        pytest.skip("SLH_DSA not supported")
    # Roundtrip below signs then verifies with CKM_SLH_DSA: declare C_Sign
    # only, one call -- C_Verify is backstopped by test_slhdsa_sigver.
    set_mechanism("SLH_DSA", operation="C_Sign", expect_success=True)

    param_set: int = vec["param_set"]
    priv_key = 0
    pub_key = 0

    try:
        try:
            # Import the private key from the vector
            priv_key = import_pqc_private_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_SLH_DSA),
                value=vec["sk"],
                parameter_set=param_set,
                attrs={CKA_SIGN: True},
            )
        except AssertionError as exc:
            _xfail_if_import_not_operational(exc, f"private key ({vec['param_name']})")

        try:
            # Import the expected public key
            pub_key = import_pqc_public_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_SLH_DSA),
                value=vec["pk"],
                parameter_set=param_set,
                attrs={CKA_VERIFY: True},
            )
        except AssertionError as exc:
            _xfail_if_import_not_operational(exc, f"public key ({vec['param_name']})")

        try:
            # Test sign/verify roundtrip to verify keypair consistency
            test_msg = b"SLH-DSA keygen test message"
            sig = sign_single(rs.raw, rs.sh, priv_key, CKM_SLH_DSA, test_msg)
            verified = verify_single(rs.raw, rs.sh, pub_key, CKM_SLH_DSA, test_msg, sig)
        except AssertionError as exc:
            _xfail_if_slhdsa_runtime_reject(exc, f"{vec_id}: keygen roundtrip")
        assert verified, f"{vec_id}: Sign/verify roundtrip failed for imported keypair"

    finally:
        if pub_key:
            destroy_quietly(rs.raw, rs.sh, pub_key)
        if priv_key:
            destroy_quietly(rs.raw, rs.sh, priv_key)


@pytest.mark.parametrize("vec_id,vec", _SIGVER_VECTORS, ids=[v[0] for v in _SIGVER_VECTORS])
def test_slhdsa_sigver(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """SLH-DSA signature verification from NIST ACVP vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("SLH_DSA"):
        pytest.skip("SLH_DSA not supported")
    skip_unless_mechanism_flag(rs, CKM_SLH_DSA, int(CKF_VERIFY))

    param_set: int = vec["param_set"]

    pub_key = 0
    try:
        try:
            pub_key = import_pqc_public_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_SLH_DSA),
                value=vec["pk"],
                parameter_set=param_set,
                attrs={CKA_VERIFY: True},
            )
        except AssertionError as exc:
            _xfail_if_import_not_operational(exc, f"public key ({vec['param_name']})")

        # Verify the signature, passing context when non-empty
        context = vec.get("context", b"")
        if isinstance(context, str):
            context = bytes.fromhex(context) if context else b""
        mech_param = mech_sign_context(CKM_SLH_DSA, context=context) if context else None
        try:
            verified = verify_single(
                rs.raw,
                rs.sh,
                pub_key,
                CKM_SLH_DSA,
                vec["msg"],
                vec["sig"],
                mech_param=mech_param,
            )
        except AssertionError as exc:
            verified = _slhdsa_verify_result_or_xfail(
                exc, vec_id, expected_pass=vec["expected_pass"]
            )

        expected = vec["expected_pass"]
        if not expected and verified:
            # Module accepted an invalid signature - security concern
            fail_as(
                "accepted_invalid",
                kind="crypto",
                label="SLH-DSA:verify",
                summary=f"{vec_id}: accepted INVALID signature (expected rejection)",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        if expected and not verified:
            # Module rejected a valid signature - crypto-correctness break
            fail_as(
                "wrong_result",
                kind="crypto",
                label="SLH-DSA:verify",
                summary=f"{vec_id}: rejected VALID SLH-DSA signature",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
    finally:
        if pub_key:
            destroy_quietly(rs.raw, rs.sh, pub_key)


@pytest.mark.parametrize("vec_id,vec", _SIGGEN_VECTORS, ids=[v[0] for v in _SIGGEN_VECTORS])
def test_slhdsa_siggen(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """SLH-DSA signature generation from NIST ACVP message vectors.

    PKCS#11 does not guarantee deterministic SLH-DSA output, so the
    produced signature is verified with the vector's public key instead of
    byte-compared: it must verify under the signing context and must NOT
    verify under a mutated context (catching providers that ignore
    context). The non-empty check is a smoke pre-check only. Exact
    signature comparison is skipped because most PKCS#11 implementations
    use randomized SLH-DSA.
    """
    rs = p11_module_session
    if not rs.has_mechanism("SLH_DSA"):
        pytest.skip("SLH_DSA not supported")
    set_mechanism("SLH_DSA", operation="C_Sign", expect_success=True)

    param_set: int = vec["param_set"]

    priv_key = 0
    try:
        try:
            priv_key = import_pqc_private_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_SLH_DSA),
                value=vec["sk"],
                parameter_set=param_set,
                attrs={CKA_SIGN: True},
            )
        except AssertionError as exc:
            _xfail_if_import_not_operational(exc, f"private key ({vec['param_name']})")

        # Sign with the vector's context, mirroring sigVer: non-empty context
        # selects CK_SIGN_ADDITIONAL_CONTEXT, pure vectors keep NULL params.
        context = vec.get("context", b"")
        if isinstance(context, str):
            context = bytes.fromhex(context) if context else b""
        mech_param = mech_sign_context(CKM_SLH_DSA, context=context) if context else None
        try:
            sig = sign_single(
                rs.raw, rs.sh, priv_key, CKM_SLH_DSA, vec["msg"], mech_param=mech_param
            )
        except AssertionError as exc:
            _xfail_if_slhdsa_runtime_reject(exc, vec_id)
        # Smoke pre-check only: a non-empty signature says nothing about
        # context handling, so the produced signature is verified below.
        assert len(sig) > 0, f"SLH-DSA sign returned empty signature for {vec_id}"

        # The produced signature is only meaningful when verified: resolve the
        # public key from the internalProjection entry first, else recover it
        # from the imported private key via CKA_PUBLIC_KEY_INFO readback. When
        # neither yields a key the sign-then-verify oracle cannot run -- an
        # explicit xfail, never a silent sign-only pass.
        pk_bytes = vec.get("pk", b"")
        if not pk_bytes:
            pk_bytes = _recover_slhdsa_public_key(rs, priv_key, vec_id, vec.get("param_name", ""))
        if not pk_bytes:
            xfail_as(
                "not_operational",
                kind="crypto",
                label="SLH-DSA:sign-verify",
                summary=(
                    f"{vec_id}: SLH-DSA sign-verify oracle unavailable: no "
                    "projection pk and CKA_PUBLIC_KEY_INFO recovery impossible "
                    "(unsupported/missing/sensitive); produced signature unverified"
                ),
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )

        pub_key = 0
        try:
            try:
                pub_key = import_pqc_public_key(
                    rs.raw,
                    rs.sh,
                    key_type=int(CKK_SLH_DSA),
                    value=pk_bytes,
                    parameter_set=param_set,
                    attrs={CKA_VERIFY: True},
                )
            except AssertionError as exc:
                _xfail_if_import_not_operational(exc, f"public key ({vec['param_name']})")

            try:
                verified = verify_single(
                    rs.raw,
                    rs.sh,
                    pub_key,
                    CKM_SLH_DSA,
                    vec["msg"],
                    sig,
                    mech_param=mech_param,
                )
            except AssertionError as exc:
                verified = _slhdsa_verify_result_or_xfail(exc, vec_id, expected_pass=True)
            if not verified:
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label="SLH-DSA:sign-verify",
                    summary=f"{vec_id}: produced SLH-DSA signature failed "
                    "verification under the signing context",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )

            # A provider that ignores context accepts the produced
            # signature under ANY context: it must NOT verify here.
            if context:
                mutated = bytes([context[0] ^ 0x01]) + context[1:]
            else:
                mutated = b"\x00"
            mutated_param = mech_sign_context(CKM_SLH_DSA, context=mutated)
            try:
                wrong_verified = verify_single(
                    rs.raw,
                    rs.sh,
                    pub_key,
                    CKM_SLH_DSA,
                    vec["msg"],
                    sig,
                    mech_param=mutated_param,
                )
            except AssertionError as exc:
                wrong_verified = _slhdsa_verify_result_or_xfail(exc, vec_id, expected_pass=False)
            if wrong_verified:
                fail_as(
                    "accepted_invalid",
                    kind="crypto",
                    label="SLH-DSA:sign-verify",
                    summary=f"{vec_id}: produced SLH-DSA signature verified "
                    "under a mutated context (context ignored)",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
        finally:
            if pub_key:
                destroy_quietly(rs.raw, rs.sh, pub_key)
    finally:
        if priv_key:
            destroy_quietly(rs.raw, rs.sh, priv_key)
