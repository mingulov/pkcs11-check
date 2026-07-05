"""Security probes for weak or invalid mechanism parameters.

Tests that modules correctly reject insecure parameter choices:
- GCM with weak tag sizes, weak/empty IVs, IV reuse, NULL AAD pointer
- PSS with zero or excessive salt length
- XTS with identical key halves
- RSA with weak public exponents
- EC with invalid points (off-curve, infinity, truncated)
- OAEP with SHA-1 MGF, PSS with MD5 hash
- CBC with all-zero IV
- ECB pattern leakage confirmation
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as, xfail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_bytes, mech_bytes, mech_simple
from pkcs11_check.raw.pack_mechanisms import mech_ecdh, mech_gcm, mech_oaep, mech_pss
from pkcs11_check.raw.recipes import (
    decrypt_single,
    derive_key,
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    gen_ec_keypair,
    gen_keypair,
    gen_rsa_keypair,
    import_secret_key,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKD_NULL,
    CKG_MGF1_SHA1,
    CKG_MGF1_SHA256,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_CBC,
    CKM_AES_ECB,
    CKM_AES_GCM,
    CKM_AES_XTS,
    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    CKM_ECDH1_DERIVE,
    CKM_MD5,
    CKM_RSA_PKCS_OAEP,
    CKM_RSA_PKCS_PSS,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA_1,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_SIGNATURE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    gen_aes_key_or_xfail,
    is_known_error,
    reject_or_classify,
    xfail_if_known_ckr,
)
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess_per_test]

# Expected spec-correct rejection codes for insecure/invalid mechanism
# parameters. A module that rejects with one of these is spec-correct (pass);
# any other clean reject code is a noted non-spec deviation (xfail); accepting
# the insecure/invalid parameter is a crypto-correctness break (fail).
_WEAK_PARAM_REJECT_RVS = (
    CKR_MECHANISM_PARAM_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_DATA_LEN_RANGE,
    CKR_ARGUMENTS_BAD,
    CKR_TEMPLATE_INCONSISTENT,
)

# CKRs that a module may legitimately return when refusing to *generate* a
# key shape required by a security probe (e.g. some modules rejecting session RSA
# keys with restrictive attribute policy). The probe targets weak/insecure
# *operation* parameters, not keygen support; if keygen itself is not
# operational, the probe is a missing-capability ``skip``, not a ``fail``.
_KEYGEN_CAPABILITY_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_KEY_SIZE_RANGE,
)

# ---------------------------------------------------------------------------
# GCM tag size validation
# ---------------------------------------------------------------------------

# Each entry is (tag_bits, category) where category is one of:
#   "invalid"  -- structurally impossible for GCM (0 bits, >128 bits); accept = fail
#   "weak"     -- below NIST SP 800-38D 96-bit floor but GCM-constructible;
#                 accept = honest_deviation xfail (produces a correct short tag,
#                 not a crypto break); reject = pass / nonspec_reject xfail
#   "valid"    -- within NIST SP 800-38D (96 or 128 bits); accept = pass;
#                 reject = nonspec_reject xfail (module declining valid params)
_GCM_TAG_CASES = [
    pytest.param((0, "invalid"), id="tag-0-bits"),
    pytest.param((8, "weak"), id="tag-8-bits"),
    pytest.param((32, "weak"), id="tag-32-bits"),
    pytest.param((64, "weak"), id="tag-64-bits"),
    pytest.param((96, "valid"), id="tag-96-bits"),
    pytest.param((128, "valid"), id="tag-128-bits"),
    pytest.param((256, "invalid"), id="tag-256-bits"),
]


class TestGcmTagSize:
    """Probe GCM authentication tag size handling across valid, weak, and invalid lengths.

    NIST SP 800-38D §5.2.1.2 permits tag lengths of 96, 104, 112, 120, or 128 bits
    and restricts 32- and 64-bit tags to special applications. Tags of 0 bits or
    more than 128 bits are structurally invalid for GCM.

    Classification per category:
    - invalid (0, >128 bits): accept → fail (accepted_invalid); reject → pass or xfail.
    - weak (8, 32, 64 bits): accept → xfail (honest_deviation — produces a correct but
      short tag, not a forgery); reject → pass or xfail.
    - valid (96, 128 bits): accept → pass; reject → xfail (honest_deviation).
    """

    @pytest.mark.parametrize("tag_case", _GCM_TAG_CASES)
    def test_gcm_weak_tag_size(self, p11_raw_session: Any, tag_case: tuple[int, str]) -> None:
        tag_bits, category = tag_case
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("AES_GCM not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            iv = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
            pt = b"A" * 32
            mech = mech_gcm(CKM_AES_GCM, iv, tag_bits=tag_bits)
            overhead = tag_bits // 8 if tag_bits > 0 else 0
            ct: bytes | None = None
            rv_on_reject: int | None = None
            try:
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_GCM,
                    pt,
                    mech_param=mech,
                    output_overhead=overhead,
                )
            except AssertionError as exc:
                rv_on_reject = getattr(exc, "rv", None)
                if rv_on_reject is None:
                    raise

            if ct is not None:
                # Measure the tag the module actually produced. encrypt_single does
                # an adaptive 2-call size query, so acceptance alone does NOT prove
                # the requested tag length was honored: a lenient module may accept
                # an out-of-range ulTagBits and default to a full tag.
                tag_len = len(ct) - len(pt)
                if category == "invalid":
                    if tag_len <= 0:
                        # Genuinely unauthenticated output (no tag) — a crypto break.
                        fail_as(
                            "accepted_invalid",
                            kind="crypto",
                            label=(
                                f"AES-GCM accepted a structurally-invalid tag length "
                                f"({tag_bits} bits) and produced an UNAUTHENTICATED "
                                f"({tag_len}-byte tag) output"
                            ),
                        )
                    else:
                        # Module ignored the invalid request and still produced a tag;
                        # lenient input handling, not an authentication break.
                        xfail_as(
                            "honest_deviation",
                            kind="crypto",
                            label=(
                                f"AES-GCM accepted an out-of-range tag length "
                                f"({tag_bits} bits) but produced a {tag_len}-byte tag "
                                f"(lenient input handling, not unauthenticated)"
                            ),
                        )
                elif category == "weak":
                    # Weak but GCM-constructible: produces a correct short tag (NIST
                    # SP 800-38D restricted use). Not a forgery — recorded as deviation.
                    xfail_as(
                        "honest_deviation",
                        kind="crypto",
                        label=(
                            f"AES-GCM accepted a sub-96-bit tag ({tag_bits} bits) "
                            f"— weak but produces a correct short tag (NIST SP 800-38D restricted)"
                        ),
                    )
                # valid: accepting a valid tag length is correct → pass (fall through)
            else:
                assert rv_on_reject is not None
                if category == "valid":
                    # A module that rejects a NIST-permitted tag length deviates from
                    # the spec; a module declining valid GCM params is an honest
                    # deviation — recorded as xfail, never a hard fail.
                    xfail_as(
                        "honest_deviation",
                        kind="crypto",
                        label=(f"AES-GCM rejected a NIST-permitted tag length ({tag_bits} bits)"),
                        actual=rv_on_reject,
                    )
                else:
                    # invalid or weak: reject is expected — classify via rv.
                    suffix = (
                        "structurally invalid"
                        if category == "invalid"
                        else "below 96-bit NIST floor"
                    )
                    classify_negative_rv(
                        rv_on_reject,
                        _WEAK_PARAM_REJECT_RVS,
                        label=f"AES-GCM with {tag_bits}-bit tag ({suffix})",
                        kind="crypto",
                    )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# GCM full-tag enforcement on decryption (G2.4)
# ---------------------------------------------------------------------------

# CKRs that a conformant module returns when GCM tag verification fails.
_GCM_TAG_VERIFY_REJECT_RVS = (
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_SIGNATURE_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
)


class TestGcmFullTagEnforcedOnVerify:
    """Probe whether the module verifies the full GCM tag on decryption.

    A conformant AES-GCM implementation must recompute and compare all 128 bits
    of the tag. A module that verifies only a prefix of the tag will accept
    ciphertext whose trailing tag bytes have been corrupted, enabling authentication
    bypass. This probe encrypts with a 128-bit tag, corrupts the trailing 4 bytes
    of the tag, and asserts that decryption is rejected.

    References: NIST SP 800-38D §7.2 (decryption); PKCS#11 v3.1 §2.15.
    """

    def test_gcm_full_tag_enforced_on_verify(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("AES_GCM not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            iv = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
            pt = b"F" * 32
            # Encrypt with a 128-bit tag; output = ciphertext || 16-byte tag.
            mech_enc = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                pt,
                mech_param=mech_enc,
                output_overhead=16,
            )
            # Corrupt the trailing 4 bytes of the tag (the suffix of the 16-byte tag).
            # A full-tag-verifying module will always reject this; a prefix-only
            # verifier may accept it.
            tampered = ct[:-4] + bytes(b ^ 0xFF for b in ct[-4:])
            # Decrypt with the same 128-bit tag spec — do NOT lower to 96 bits.
            mech_dec = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            rv_on_reject: int | None = None
            try:
                decrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_GCM,
                    tampered,
                    mech_param=mech_dec,
                    output_size_hint=len(pt),
                )
            except AssertionError as exc:
                rv_on_reject = getattr(exc, "rv", None)
                if rv_on_reject is None:
                    raise
            if rv_on_reject is None:
                # Decryption succeeded despite corrupted trailing tag bytes.
                fail_as(
                    "accepted_invalid",
                    kind="crypto",
                    label=(
                        "AES-GCM verified only a tag prefix — "
                        "accepted ciphertext with corrupted trailing tag bytes"
                    ),
                )
            else:
                # Rejection is the correct outcome — classify via rv.
                classify_negative_rv(
                    rv_on_reject,
                    _GCM_TAG_VERIFY_REJECT_RVS,
                    label="AES-GCM decryption rejection of corrupted trailing tag bytes",
                    kind="crypto",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# CCM NULL nonce with non-zero length (subprocess -- crash risk) (G2.5)
# ---------------------------------------------------------------------------


class TestCcmNullNonceWithLength:
    """Test CCM with NULL nonce pointer but non-zero ulNonceLen.

    This NULL-pointer + non-zero-length mismatch can cause a NULL dereference
    crash in modules that use ulNonceLen without first checking whether
    pNonce is non-NULL. The probe asserts that C_EncryptInit either returns a
    clean error or initialises successfully without crashing.

    References: NIST SP 800-38C §A.1 (nonce requirements); PKCS#11 v3.1 §2.15.
    """

    def test_ccm_null_nonce_with_length(self, p11_raw_session: Any, p11_config: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CCM"):
            pytest.skip("AES_CCM not supported")
        result = run_probe(
            "parameter_validation",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "ccm_null_nonce",
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
            context="CCM NULL nonce pointer with nonzero ulNonceLen",
        )


# ---------------------------------------------------------------------------
# GCM IV weakness
# ---------------------------------------------------------------------------

_WEAK_GCM_IVS = [
    pytest.param(b"", id="empty-iv"),
    pytest.param(b"\x00", id="single-zero-byte-iv"),
    pytest.param(b"\x00" * 4, id="4-zero-bytes-iv"),
]


class TestGcmIvWeakness:
    """Probe whether the module accepts weak/short GCM IVs.

    NIST SP 800-38D strongly recommends 96-bit (12-byte) IVs.
    Shorter or empty IVs are insecure.
    """

    @pytest.mark.parametrize("iv", _WEAK_GCM_IVS)
    def test_gcm_weak_iv(self, p11_raw_session: Any, iv: bytes) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("AES_GCM not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            pt = b"B" * 32
            mech = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            # crypto-correctness: an empty/short GCM IV undermines the
            # uniqueness guarantee; accepting it is a break (fail).
            reject_exc: AssertionError | None = None
            try:
                encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_GCM,
                    pt,
                    mech_param=mech,
                    output_overhead=16,
                )
            except AssertionError as exc:
                reject_exc = exc
            reject_or_classify(
                reject_exc,
                _WEAK_PARAM_REJECT_RVS,
                label=f"AES-GCM with {len(iv)}-byte IV (below NIST 96-bit recommendation)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# GCM IV reuse
# ---------------------------------------------------------------------------


class TestGcmIvReuse:
    """Probe whether the module prevents IV reuse with the same key.

    Reusing an IV with the same key in GCM completely breaks confidentiality
    and authenticity. NIST SP 800-38D requires IV uniqueness per key.
    """

    def test_gcm_iv_reuse_same_key(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("AES_GCM not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            iv = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
            pt1 = b"A" * 32
            pt2 = b"B" * 32
            mech1 = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            ct1 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                pt1,
                mech_param=mech1,
                output_overhead=16,
            )
            # Second encrypt with SAME key + SAME IV. crypto-correctness:
            # IV reuse with the same GCM key breaks confidentiality and
            # authenticity; accepting the second encrypt is a break (fail).
            mech2 = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            reject_exc: AssertionError | None = None
            try:
                ct2 = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_GCM,
                    pt2,
                    mech_param=mech2,
                    output_overhead=16,
                )
                _ = ct1, ct2  # suppress unused warnings
            except AssertionError as exc:
                reject_exc = exc
            reject_or_classify(
                reject_exc,
                _WEAK_PARAM_REJECT_RVS,
                label="AES-GCM IV reuse with the same key (NIST SP 800-38D requires unique IVs)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# GCM NULL AAD pointer with non-zero length (subprocess -- crash risk)
# ---------------------------------------------------------------------------


class TestGcmAadNullWithLength:
    """Test GCM with NULL AAD pointer but non-zero AAD length.

    This NULL-pointer + non-zero-length mismatch can cause crashes in
    modules that dereference pAAD without checking ulAADLen first.
    """

    def test_gcm_null_aad_pointer_nonzero_length(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("AES_GCM not supported")
        result = run_probe(
            "parameter_validation",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "probe": "gcm_null_aad",
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
            context="GCM NULL AAD pointer with nonzero ulAADLen",
        )


# ---------------------------------------------------------------------------
# PSS salt length validation
# ---------------------------------------------------------------------------

_PSS_SALT_LENGTHS = [
    pytest.param(0, id="sLen-0-deterministic"),
]


class TestPssSaltLength:
    """Probe RSA-PSS salt length edge cases.

    sLen=0 makes PSS deterministic, but it is a STANDARDIZED variant (RFC 8017
    §9.1 / FIPS 186-5) that yields correct, verifiable, non-forgeable signatures
    -- accepting it is NOT a crypto-correctness break. So a module that signs
    sLen=0 and the signature verifies is correct (pass); one that cleanly
    declines deterministic PSS is exercising a policy choice (xfail); only a
    module that accepts sLen=0 yet produces a signature that does NOT verify has
    a real break (fail). (sLen > modLen/8 - hLen - 2 IS invalid and is covered
    by test_pss_excessive_salt_length.)
    """

    @pytest.mark.parametrize("salt_len", _PSS_SALT_LENGTHS)
    def test_pss_zero_salt_length(self, p11_raw_session: Any, salt_len: int) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS_PSS"):
            pytest.skip("SHA256_RSA_PKCS_PSS not supported")
        try:
            pub, priv = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
                public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            )
        except AssertionError as exc:
            if is_known_error(exc, _KEYGEN_CAPABILITY_REJECT_RVS):
                pytest.skip(f"RSA keygen for PSS zero-salt probe not operational: {exc}")
            raise
        try:
            pss = mech_pss(
                CKM_SHA256_RSA_PKCS_PSS,
                hash_mech=CKM_SHA256,
                mgf=CKG_MGF1_SHA256,
                salt_len=salt_len,
            )
            data = b"PSS salt length test"
            # sLen=0 is a VALID deterministic PSS variant (RFC 8017 §9.1 /
            # FIPS 186-5). The finding is NOT "the module accepted it" -- that is
            # correct -- but only "the module produced a signature that does not
            # verify". Sign, then verify the result with the same sLen.
            signature: bytes | None = None
            try:
                signature = sign_single(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_SHA256_RSA_PKCS_PSS,
                    data,
                    mech_param=pss,
                )
            except AssertionError as exc:
                # A module/policy may decline deterministic PSS with a clean
                # reject -- a recorded capability/policy deviation, not a finding.
                xfail_if_known_ckr(
                    exc,
                    _WEAK_PARAM_REJECT_RVS,
                    f"RSA-PSS sLen={salt_len} (deterministic, RFC 8017 §9.1) declined by module",
                )
                raise
            pss_verify = mech_pss(
                CKM_SHA256_RSA_PKCS_PSS,
                hash_mech=CKM_SHA256,
                mgf=CKG_MGF1_SHA256,
                salt_len=salt_len,
            )
            verified = verify_single(
                rs.raw,
                rs.sh,
                pub,
                CKM_SHA256_RSA_PKCS_PSS,
                data,
                signature,
                mech_param=pss_verify,
            )
            if not verified:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label=f"RSA-PSS sLen={salt_len} deterministic signature",
                    operation="C_Sign",
                    mechanism="CKM_SHA256_RSA_PKCS_PSS",
                    summary=f"RSA-PSS sLen={salt_len}: module accepted the deterministic-PSS sign "
                    f"operation but the produced signature does not verify (invalid signature)",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_pss_excessive_salt_length(self, p11_raw_session: Any) -> None:
        """PSS with salt exceeding maximum: sLen > (modLen/8 - hashLen - 2).

        For 2048-bit RSA with SHA-256 (32-byte hash):
        max sLen = 256 - 32 - 2 = 222 bytes.
        We use sLen = 255 which exceeds the limit.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS_PSS"):
            pytest.skip("SHA256_RSA_PKCS_PSS not supported")
        try:
            pub, priv = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
                public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            )
        except AssertionError as exc:
            if is_known_error(exc, _KEYGEN_CAPABILITY_REJECT_RVS):
                pytest.skip(f"RSA keygen for PSS excessive-salt probe not operational: {exc}")
            raise
        try:
            # max sLen = 256 - 32 - 2 = 222 for 2048-bit RSA / SHA-256
            pss = mech_pss(
                CKM_SHA256_RSA_PKCS_PSS,
                hash_mech=CKM_SHA256,
                mgf=CKG_MGF1_SHA256,
                salt_len=255,
            )
            data = b"PSS excessive salt test"
            try:
                sig = sign_single(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_SHA256_RSA_PKCS_PSS,
                    data,
                    mech_param=pss,
                )
                note(
                    f"RSA-PSS accepts sLen=255 exceeding maximum of 222 "
                    f"(produced {len(sig)}-byte signature)",
                    ComplianceLevel.VENDOR,
                    reference="RFC 8017 Section 9.1: sLen must not exceed emLen - hLen - 2",
                )
            except (AssertionError, OSError):
                pass  # audit-ok: hardening probe; rejecting the over-large salt is correct
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


# ---------------------------------------------------------------------------
# XTS identical key halves
# ---------------------------------------------------------------------------


class TestXtsKeyValidation:
    """Probe whether the module rejects XTS keys with identical halves.

    AES-XTS uses two independent 128-bit keys. If both halves are identical,
    the tweak encryption degenerates, weakening the construction to ECB-like
    behavior. NIST SP 800-38E forbids this.
    """

    def test_xts_identical_keys(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_XTS"):
            pytest.skip("AES_XTS not supported")
        # 256-bit key = 128-bit data key + 128-bit tweak key (identical)
        half = b"\xaa" * 16
        key_material = half + half  # Both halves identical
        # crypto-correctness: identical XTS key halves degenerate the
        # construction to ECB-like behavior (NIST SP 800-38E forbids it).
        # Rejecting at import is a spec-correct rejection (pass). If import is
        # accepted, the encrypt must reject -- accepting the encrypt is a break.
        try:
            key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_AES,
                key_material,
                attrs={
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                    CKA_TOKEN: False,
                },
            )
        except AssertionError as import_exc:
            reject_or_classify(
                import_exc,
                _WEAK_PARAM_REJECT_RVS,
                label="AES-XTS import of a key with identical halves",
            )
            return
        # Key was imported; try to use it
        try:
            mech = mech_simple(CKM_AES_XTS)
            pt = b"C" * 32  # At least two blocks
            reject_exc: AssertionError | None = None
            try:
                encrypt_single(rs.raw, rs.sh, key, CKM_AES_XTS, pt, mech_param=mech)
            except AssertionError as exc:
                reject_exc = exc
            reject_or_classify(
                reject_exc,
                _WEAK_PARAM_REJECT_RVS,
                label="AES-XTS encrypt with identical key halves (NIST SP 800-38E violation)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


# ---------------------------------------------------------------------------
# RSA weak public exponent
# ---------------------------------------------------------------------------

_WEAK_RSA_EXPONENTS = [
    pytest.param(0, id="e=0"),
    pytest.param(1, id="e=1"),
    pytest.param(2, id="e=2"),
    pytest.param(3, id="e=3-low"),
    pytest.param(4, id="e=4"),
]

# Cryptographically invalid public exponents (no usable RSA key exists): e=0
# (no inverse), e=1 (identity -- no encryption), and even exponents e=2/e=4
# (no inverse modulo phi(n)). Accepting one of these is a
# crypto-correctness break (fail). e=3 is a valid (if low) odd exponent that a
# conformant module may legitimately accept, so it stays a posture note.
_CRYPTO_INVALID_RSA_EXPONENTS = {0, 1, 2, 4}


class TestRsaExponent:
    """Probe whether the module rejects weak RSA public exponents.

    e=0 is invalid, e=1 produces identity encryption (m^1 mod n = m), e=2/e=4
    are even, and e=3 is a historically common but weak low public exponent.
    The cryptographically invalid exponents (e in {0, 1, 2, 4}) must be
    rejected; e=3 is weak-but-valid posture.
    """

    @pytest.mark.parametrize("exponent", _WEAK_RSA_EXPONENTS)
    def test_rsa_weak_public_exponent(self, p11_raw_session: Any, exponent: int) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        # Encode exponent as big-endian bytes
        byte_len = max(1, (exponent.bit_length() + 7) // 8)
        exp_bytes = exponent.to_bytes(byte_len, "big")
        reject_exc: AssertionError | None = None
        pub = priv = 0
        try:
            pub, priv = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                public_attrs={CKA_PUBLIC_EXPONENT: exp_bytes},
            )
        except AssertionError as exc:
            reject_exc = exc

        if exponent in _CRYPTO_INVALID_RSA_EXPONENTS:
            # crypto-correctness: no usable RSA key exists for this
            # exponent; acceptance is a break (fail).
            try:
                reject_or_classify(
                    reject_exc,
                    _WEAK_PARAM_REJECT_RVS,
                    label=f"RSA keygen with cryptographically invalid exponent e={exponent}",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, pub)
                destroy_quietly(rs.raw, rs.sh, priv)
            return

        # e=3: valid-but-weak low exponent -- posture choice, not a break.
        if reject_exc is not None:
            return  # Module rejected the low exponent -- acceptable
        try:
            note(
                f"Module accepts RSA keygen with public exponent e={exponent}",
                ComplianceLevel.VENDOR,
                reference="FIPS 186-5: public exponent must be odd and >= 65537 for key generation",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


# ---------------------------------------------------------------------------
# EC point validation for ECDH
# ---------------------------------------------------------------------------

_INVALID_EC_POINTS = [
    pytest.param("off_curve", id="off-curve-point"),
    pytest.param("infinity", id="point-at-infinity"),
    pytest.param("truncated", id="truncated-point"),
]

# Low-order u-coordinates for Montgomery curves (raw little-endian, no DER wrapper).
# For X25519: u=0 is definitively low-order; X25519(k, 0) == 0 for all k.
# For X448: u=0 is definitively low-order; X448(k, 0) == 0 for all k.
# RFC 7748 §6.1 defines the all-zero shared secret as the low-order / small-subgroup
# result and makes the contributory-behaviour check OPTIONAL.
_MONTGOMERY_LOW_ORDER_POINTS = [
    pytest.param(
        "x25519",
        b"\x00" * 32,  # u=0 (little-endian), low-order point
        32,
        id="x25519-u0",
    ),
    pytest.param(
        "x448",
        b"\x00" * 56,  # u=0 (little-endian), low-order point
        56,
        id="x448-u0",
    ),
]


class TestEcPointValidation:
    """Probe whether the module validates EC public keys in ECDH derive.

    Invalid points (off-curve, infinity, truncated) used in ECDH can leak
    the private key through invalid-curve attacks. Modules must validate
    incoming public keys per NIST SP 800-56A.
    """

    @pytest.mark.parametrize("point_type", _INVALID_EC_POINTS)
    def test_ecdh_invalid_point(self, p11_raw_session: Any, point_type: str) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("ECDH1_DERIVE not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        try:
            pub, priv = gen_ec_keypair(
                rs.raw,
                rs.sh,
                curve_oid,
                private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
            )
        except AssertionError as exc:
            if is_known_error(exc, _KEYGEN_CAPABILITY_REJECT_RVS):
                pytest.skip(f"EC keygen for invalid-point probe not operational: {exc}")
            raise
        try:
            # Read the valid EC point to use as a base for crafting invalid ones
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_EC_POINT])
            ec_point_val = attrs[CKA_EC_POINT]
            assert isinstance(ec_point_val, bytes)
            raw_point = decode_ec_point(ec_point_val)

            invalid_point = self._craft_invalid_point(raw_point, point_type)

            # crypto-correctness: deriving a shared secret from an
            # off-curve / infinity / truncated public point enables an
            # invalid-curve attack that can leak the private key (NIST SP
            # 800-56A requires full public-key validation). Accepting the
            # derive is a break (fail); an expected reject is pass; another
            # clean reject is xfail.
            derived = 0
            reject_exc: AssertionError | None = None
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_ECDH1_DERIVE,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                        CKA_VALUE_LEN: 32,
                    },
                    mech_param=mech_ecdh(
                        CKM_ECDH1_DERIVE,
                        kdf=CKD_NULL,
                        public_data=invalid_point,
                    ),
                )
            except AssertionError as exc:
                reject_exc = exc

            try:
                reject_or_classify(
                    reject_exc,
                    _WEAK_PARAM_REJECT_RVS,
                    label=f"ECDH derive with {point_type} EC public point (invalid-curve attack)",
                )
            finally:
                if derived:
                    destroy_quietly(rs.raw, rs.sh, derived)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize("curve_name,low_order_point,secret_len", _MONTGOMERY_LOW_ORDER_POINTS)
    def test_ecdh_montgomery_low_order_point(
        self,
        p11_raw_session: Any,
        curve_name: str,
        low_order_point: bytes,
        secret_len: int,
    ) -> None:
        """Probe X25519/X448 ECDH with a low-order peer point (u=0).

        A low-order peer public key leads to a degenerate shared secret. RFC 7748
        §6.1 permits -- but does not require -- modules to reject low-order inputs:
        scalar clamping already protects the private key, so a module that produces
        an all-zero shared secret is conformant. The only outright crypto-correctness
        break is a NON-ZERO shared secret from a low-order point (miscomputation on
        a Montgomery ladder).

        Outcomes (RFC 7748 §6.1):
        - Derive rejected cleanly → module enforces contributory-behaviour check
          (optional hardening). Recorded as a compliance note, not a finding.
        - Derive succeeds, shared secret is all-zero → permitted per RFC 7748 §6.1.
          Recorded as a compliance note.
        - Derive succeeds, shared secret is non-zero → miscomputation; X(k,0)==0
          for all k by definition of the Montgomery ladder. Hard-fail (crypto kind).
        - Derive succeeds but secret is unreadable → xfail (not_operational).
        """
        rs = p11_raw_session
        if not rs.has_mechanism("EC_MONTGOMERY_KEY_PAIR_GEN"):
            pytest.skip(f"EC_MONTGOMERY_KEY_PAIR_GEN not supported ({curve_name} probe skipped)")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip(f"CKM_ECDH1_DERIVE not supported ({curve_name} probe skipped)")

        curve_oid = encode_named_curve_parameters(curve_name)
        pub = 0
        priv = 0
        derived = 0
        try:
            try:
                pub, priv = gen_keypair(
                    rs.raw,
                    rs.sh,
                    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
                    pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
                    priv_base=[],
                    public_attrs={CKA_TOKEN: False},
                    private_attrs={CKA_SENSITIVE: True, CKA_TOKEN: False, CKA_DERIVE: True},
                    pub_skip={CKA_EC_PARAMS},
                )
            except AssertionError as exc:
                if is_known_error(exc, _KEYGEN_CAPABILITY_REJECT_RVS):
                    pytest.skip(f"{curve_name} keygen not operational: {exc}")
                raise

            reject_exc: CkrAssertionError | None = None
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_ECDH1_DERIVE,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                        CKA_VALUE_LEN: secret_len,
                    },
                    mech_param=mech_ecdh(
                        CKM_ECDH1_DERIVE,
                        kdf=CKD_NULL,
                        public_data=low_order_point,
                    ),
                )
            except CkrAssertionError as exc:
                reject_exc = exc

            if reject_exc is not None:
                # Module rejected the low-order peer point -- contributory-behaviour
                # check is present (RFC 7748 §6.1 permits this; it is good hygiene).
                note(
                    f"{curve_name} ECDH derive rejected a low-order peer point (u=0) "
                    f"with {ckr_name(reject_exc.rv)} — "
                    "contributory-behaviour check present (RFC 7748 §6.1, optional)",
                    ComplianceLevel.EXTENDED,
                    reference="RFC 7748 §6.1",
                )
                return

            # Derive succeeded -- read the shared secret value.
            try:
                result = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])
                secret = result[CKA_VALUE]
            except AssertionError:
                xfail_as(
                    "not_operational",
                    kind="crypto",
                    label=(
                        f"{curve_name} ECDH low-order point: derive returned CKR_OK "
                        "but shared secret is unreadable"
                    ),
                )

            assert isinstance(secret, bytes)
            if secret == b"\x00" * len(secret):
                # All-zero shared secret: correct behaviour for a low-order point.
                note(
                    f"{curve_name} ECDH derive accepted a low-order peer point (u=0) "
                    "and produced an all-zero shared secret — "
                    "contributory-behaviour check not enforced (permitted, RFC 7748 §6.1)",
                    ComplianceLevel.EXTENDED,
                    reference="RFC 7748 §6.1",
                )
            else:
                # Non-zero secret from a low-order point: definitive miscomputation.
                # A correct Montgomery ladder satisfies X(k, 0) == 0 for all k.
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label=(
                        f"{curve_name} ECDH low-order point (u=0) produced a non-zero "
                        "shared secret — miscomputation: a correct Montgomery ladder "
                        "must yield all-zero for u=0 (RFC 7748 §5)"
                    ),
                )
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)
            if pub:
                destroy_quietly(rs.raw, rs.sh, pub)

    @staticmethod
    def _craft_invalid_point(valid_point: bytes, point_type: str) -> bytes:
        """Craft an invalid EC point from a valid uncompressed point.

        Args:
            valid_point: Uncompressed point (0x04 || x || y) for P-256 (65 bytes).
            point_type: Type of invalidity to introduce.

        Returns:
            Invalid point bytes.
        """
        if point_type == "off_curve":
            # Flip the last byte of Y coordinate to move point off curve
            modified = bytearray(valid_point)
            modified[-1] ^= 0x01
            return bytes(modified)
        elif point_type == "infinity":
            # Point at infinity encoded as a single 0x00 byte
            return b"\x00"
        elif point_type == "truncated":
            # Cut the point short -- missing half of Y coordinate
            return valid_point[: len(valid_point) // 2]
        else:
            raise ValueError(f"Unknown point type: {point_type}")


# ---------------------------------------------------------------------------
# Standalone weakness probes
# ---------------------------------------------------------------------------


class TestRsaOaepSha1Mgf:
    """Probe whether RSA-OAEP with SHA-1 MGF is accepted."""

    def test_rsa_oaep_sha1_mgf(self, p11_raw_session: Any) -> None:
        """RSA-OAEP with SHA-1 as MGF hash -- weakness report.

        SHA-1 is deprecated for collision resistance (SHAttered, 2017).
        While OAEP does not directly rely on collision resistance,
        using SHA-1 in MGF is a cryptographic hygiene concern.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("RSA_PKCS_OAEP not supported")
        try:
            pub, priv = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
                private_attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
            )
        except AssertionError as exc:
            if is_known_error(exc, _KEYGEN_CAPABILITY_REJECT_RVS):
                pytest.skip(f"RSA keygen for OAEP-SHA1 probe not operational: {exc}")
            raise
        try:
            oaep = mech_oaep(
                CKM_RSA_PKCS_OAEP,
                hash_mech=CKM_SHA_1,
                mgf=CKG_MGF1_SHA1,
            )
            pt = b"OAEP SHA-1 MGF test"
            try:
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    CKM_RSA_PKCS_OAEP,
                    pt,
                    mech_param=oaep,
                )
                _ = ct
                note(
                    "RSA-OAEP accepts SHA-1 as MGF hash function",
                    ComplianceLevel.VENDOR,
                    reference="SHA-1 deprecated per NIST SP 800-131A Rev.2; "
                    "prefer SHA-256 or stronger for new applications",
                )
            except (AssertionError, OSError):
                pass  # audit-ok: hardening probe; rejecting the SHA-1 MGF is correct
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestRsaPssMd5Hash:
    """Probe whether RSA-PSS with MD5 hash is accepted."""

    def test_rsa_pss_md5_hash(self, p11_raw_session: Any) -> None:
        """RSA-PSS with MD5 as hash -- weakness report.

        MD5 has been broken for collision resistance since 2004.
        Using MD5 in PSS signatures enables forgery attacks.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        if not rs.has_mechanism("RSA_PKCS_PSS"):
            pytest.skip("RSA_PKCS_PSS not supported")
        try:
            pub, priv = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
                public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            )
        except AssertionError as exc:
            if is_known_error(exc, _KEYGEN_CAPABILITY_REJECT_RVS):
                pytest.skip(f"RSA keygen for PSS probe not operational: {exc}")
            raise
        try:
            # MD5 hash with SHA-256 MGF -- intentionally mismatched
            # to specifically test whether MD5 hash is accepted
            pss = mech_pss(
                CKM_RSA_PKCS_PSS,
                hash_mech=CKM_MD5,
                mgf=CKG_MGF1_SHA256,
                salt_len=16,  # MD5 digest length
            )
            data = b"PSS MD5 hash test"
            try:
                sig = sign_single(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_RSA_PKCS_PSS,
                    data,
                    mech_param=pss,
                )
                _ = sig
                note(
                    "RSA-PSS accepts MD5 as hash algorithm",
                    ComplianceLevel.VENDOR,
                    reference="MD5 collision attacks are practical since 2004; "
                    "NIST SP 800-131A Rev.2 disallows MD5 for digital signatures",
                )
            except (AssertionError, OSError):
                pass  # audit-ok: hardening probe; rejecting MD5 is correct
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestCbcIvAllZeros:
    """Probe whether AES-CBC accepts an all-zero IV."""

    def test_cbc_iv_all_zeros(self, p11_raw_session: Any) -> None:
        """AES-CBC with all-zero IV -- weakness report.

        An all-zero IV makes the first block encryption equivalent to ECB
        for the first block. While not always a vulnerability, it indicates
        weak IV generation practices.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("AES_CBC not supported")
        key = gen_aes_key_or_xfail(rs, 256)
        try:
            zero_iv = b"\x00" * 16  # 128-bit all-zero IV
            pt = b"D" * 16  # Single AES block
            try:
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_CBC,
                    pt,
                    mech_param=mech_bytes(CKM_AES_CBC, zero_iv),
                )
                _ = ct
                note(
                    "AES-CBC accepts all-zero IV -- weak IV generation indicator",
                    ComplianceLevel.VENDOR,
                    reference="CWE-329: not using a random IV for CBC makes "
                    "the first block equivalent to ECB",
                )
            except (AssertionError, OSError):
                pass  # audit-ok: hardening probe; rejecting the all-zero IV is acceptable
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestEcbPatternLeakage:
    """Confirm ECB mode leaks plaintext patterns.

    ECB encrypts each block independently, so identical plaintext blocks
    produce identical ciphertext blocks. This is inherent to ECB and is
    a compliance note confirming expected behavior.
    """

    def test_ecb_pattern_leakage(self, p11_raw_session: Any) -> None:
        """Encrypt two identical blocks and verify identical ciphertext."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("AES_ECB not supported")
        key = gen_aes_key_or_xfail(rs, 256)
        try:
            # Two identical 16-byte blocks
            block = b"E" * 16
            pt = block + block  # 32 bytes = 2 identical blocks
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, pt)
            ct_block1 = ct[:16]
            ct_block2 = ct[16:32]
            if ct_block1 == ct_block2:
                note(
                    "AES-ECB produces identical ciphertext for identical plaintext blocks "
                    "-- expected pattern leakage confirmed",
                    ComplianceLevel.VENDOR,
                    reference="NIST SP 800-38A: ECB mode does not provide "
                    "semantic security; avoid for multi-block data",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
