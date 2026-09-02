"""Security probes for DH domain-parameter validation.

Tests that modules reject structurally-impossible DH domain parameters
as required by sound cryptographic practice (NIST SP 800-56A, rev. 3,
§5.5.1: domain-parameter validation is a prerequisite for key generation).

Three cases:

1. **prime = 1 (b"\\x01")** — DH modular arithmetic mod 1 collapses every
   element to 0; no valid DH key can exist.  A conformant module must
   reject this.

2. **prime = 15 (b"\\x0f")** — below any recognised DH modulus size; also not
   prime.  Invalid both by size (sub-64-bit) and by value.  A conformant
   module must reject this.

3. **base = 0 with a valid 2048-bit prime** — the generator 0 means every
   public value is 0 regardless of the private key; the group is degenerate.
   PKCS#11 permits lazy validation (accept at keygen, reject at derive), so a
   bare CKR_OK is not proof of a break: the test verifies the EFFECT.  A hard
   fail is recorded only when the module silently substitutes a generator
   (self_contradiction) or produces a USABLE key over the degenerate group
   (accepted_invalid).  A module that accepts at keygen but rejects at derive
   is recorded as an xfail (lazy-but-conformant), never a hard fail.

4. **1024-bit safe prime (RFC 2409 Group 2 / Oakley Group 2)** —
   mathematically valid but below the 2048-bit minimum recommended by NIST
   SP 800-56A rev. 3, §5.5.1.1 (Table 1).  Either accepting or rejecting
   is conformant; the outcome is recorded as a NOT_RECOMMENDED compliance
   note, never as a hard finding.

Deliberately excluded:
- Large composite primes: PKCS#11 does not mandate that a module validate
  the primality of caller-supplied CKA_PRIME; a trusting-but-conformant
  module may accept them.  Asserting rejection would false-accuse such a
  module.  These are therefore not tested here.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.pack import attr_bool, attr_bytes, mech_bytes, mech_simple, template
from pkcs11_check.raw.recipes import derive_key, destroy_quietly, read_attributes
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_BASE,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_PRIME,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_DH_PKCS_DERIVE,
    CKM_DH_PKCS_KEY_PAIR_GEN,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = pytest.mark.security

# ---------------------------------------------------------------------------
# Known-good DH domain parameters used as a baseline
# (RFC 3526 Group 14, 2048-bit MODP safe prime)
# ---------------------------------------------------------------------------

_DH_PRIME_2048 = bytes.fromhex(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
_DH_GEN_2 = bytes([0x02])

# RFC 2409 Group 2 / Oakley Group 2, 1024-bit MODP safe prime (public constant).
# Generator is 2.  This is a well-known, mathematically valid safe prime, but at
# 1024 bits it falls below the 2048-bit minimum recommended by NIST SP 800-56A
# rev. 3 Table 1 for key establishment schemes.
_DH_PRIME_1024_RFC2409_GROUP2 = bytes.fromhex(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE65381FFFFFFFFFFFFFFFF"
)

# Expected reject codes for structurally-invalid domain parameters.
# PKCS#11 v3.0 §11.14 (C_GenerateKeyPair) does not enumerate a single required
# return code for invalid domain parameters; any of these constitutes a
# spec-permitted rejection.
_DH_DOMAIN_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _try_gen_dh_keypair(raw: Any, sh: int, prime: bytes, base: bytes) -> tuple[int, int, int]:
    """Attempt C_GenerateKeyPair with the given DH domain params.

    Returns ``(rv, pub_handle, priv_handle)``.  On a non-``CKR_OK`` ``rv`` both
    handles are 0.  On ``CKR_OK`` the live handles are returned; the CALLER owns
    them and must ``destroy_quietly`` both (effect-verification needs them, so
    this helper deliberately does not free them itself).
    """
    pub_tmpl = template(
        attr_bytes(CKA_PRIME, prime),
        attr_bytes(CKA_BASE, base),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_DERIVE, True),
    )
    priv_tmpl = template(
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_DERIVE, True),
    )
    mech = mech_simple(CKM_DH_PKCS_KEY_PAIR_GEN)
    pub_h = CK_OBJECT_HANDLE(0)
    priv_h = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        sh,
        mech.byref(),
        pub_tmpl.ptr,
        pub_tmpl.count,
        priv_tmpl.ptr,
        priv_tmpl.count,
        byref(pub_h),
        byref(priv_h),
    )
    if rv != 0:  # not CKR_OK
        return int(rv), 0, 0
    return int(rv), pub_h.value, priv_h.value


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDHDomainParameterValidation:
    """DH domain-parameter validation probes (NIST SP 800-56A, rev. 3, §5.5.1)."""

    def test_dh_rejects_prime_value_one(self, p11_raw_session: Any) -> None:
        """CKM_DH_PKCS_KEY_PAIR_GEN must reject prime=1 (b"\\x01").

        DH modular arithmetic mod 1 makes every element identically 0.
        No valid DH key can be generated over this group; the parameter is
        structurally impossible.  A conformant module must refuse it.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_DH_PKCS_KEY_PAIR_GEN not supported")

        rv, pub, priv = _try_gen_dh_keypair(rs.raw, rs.sh, prime=b"\x01", base=_DH_GEN_2)
        try:
            classify_negative_rv(
                rv,
                _DH_DOMAIN_REJECT_RVS,
                label="CKM_DH_PKCS_KEY_PAIR_GEN rejects structurally-invalid prime=1",
                kind="crypto",
            )
        finally:
            if pub:
                destroy_quietly(rs.raw, rs.sh, pub)
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)

    def test_dh_rejects_tiny_prime(self, p11_raw_session: Any) -> None:
        """CKM_DH_PKCS_KEY_PAIR_GEN must reject a sub-byte-length prime (b"\\x0f" = 15).

        15 is not prime and is far below any recognised DH modulus size
        (minimum is 512 bits per the weakest profiles, 2048 bits per NIST).
        The value is invalid both structurally (not prime) and by size.
        A conformant module must refuse it.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_DH_PKCS_KEY_PAIR_GEN not supported")

        rv, pub, priv = _try_gen_dh_keypair(rs.raw, rs.sh, prime=b"\x0f", base=_DH_GEN_2)
        try:
            classify_negative_rv(
                rv,
                _DH_DOMAIN_REJECT_RVS,
                label="CKM_DH_PKCS_KEY_PAIR_GEN rejects structurally-invalid tiny prime (15)",
                kind="crypto",
            )
        finally:
            if pub:
                destroy_quietly(rs.raw, rs.sh, pub)
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)

    def test_dh_rejects_zero_generator(self, p11_raw_session: Any) -> None:
        """CKM_DH_PKCS_KEY_PAIR_GEN with base (generator) = 0 -- verify the effect.

        A generator of 0 means g^x = 0 for any private key x, so every
        public value is 0 regardless of the secret chosen.  The group is
        degenerate; no valid DH exchange can occur.

        PKCS#11 does NOT prohibit lazy domain-parameter validation: a
        conformant module MAY accept base=0 at C_GenerateKeyPair and reject it
        later at C_DeriveKey.  Acceptance alone therefore does not prove a
        break.  This test verifies what actually happened before deciding:

        - Reject at keygen -> pass / xfail (spec-permitted, conservative).
        - CKR_OK + module silently substituted a real generator for the
          requested 0 -> self_contradiction fail.
        - CKR_OK + base reads back as 0 + a derive over the degenerate group
          SUCCEEDS -> the module produced a usable key whose shared secret is
          forced to 0 -> accepted_invalid fail.
        - CKR_OK + the derive is cleanly rejected -> lazy-but-conformant
          validation -> xfail (not a keygen break).
        """
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_DH_PKCS_KEY_PAIR_GEN not supported")

        rv, pub, priv = _try_gen_dh_keypair(rs.raw, rs.sh, prime=_DH_PRIME_2048, base=b"\x00")
        try:
            if rv != 0:  # not CKR_OK -- reject path (unchanged)
                classify_negative_rv(
                    rv,
                    _DH_DOMAIN_REJECT_RVS,
                    label="CKM_DH_PKCS_KEY_PAIR_GEN rejects degenerate generator=0",
                    kind="crypto",
                )
                return

            # CKR_OK -- verify the effect rather than fail on bare acceptance.
            self._classify_accepted_zero_generator(rs, pub, priv)
        finally:
            if pub:
                destroy_quietly(rs.raw, rs.sh, pub)
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)

    @staticmethod
    def _classify_accepted_zero_generator(rs: Any, pub: int, priv: int) -> None:
        """Decide the verdict after C_GenerateKeyPair(base=0) returned CKR_OK.

        Reads back CKA_BASE / CKA_VALUE from the generated public key and, if the
        group is genuinely degenerate, probes a derive to confirm usability.
        """
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_BASE, CKA_VALUE])
        except CkrAssertionError:
            fail_as(
                "self_contradiction",
                kind="crypto",
                label=(
                    "CKM_DH_PKCS_KEY_PAIR_GEN returned CKR_OK for base=0 "
                    "but the public key object is incoherent (CKA_BASE/CKA_VALUE unreadable)"
                ),
            )

        base_back = pub_attrs.get(CKA_BASE)
        if isinstance(base_back, bytes) and int.from_bytes(base_back, "big") != 0:
            fail_as(
                "self_contradiction",
                kind="crypto",
                label=(
                    "CKM_DH_PKCS_KEY_PAIR_GEN returned CKR_OK but silently substituted a "
                    "generator for the requested base=0"
                ),
            )

        peer_value = pub_attrs.get(CKA_VALUE)
        if not isinstance(peer_value, bytes):
            fail_as(
                "self_contradiction",
                kind="crypto",
                label=(
                    "CKM_DH_PKCS_KEY_PAIR_GEN returned CKR_OK for base=0 "
                    "but the public key has no readable CKA_VALUE to use as a peer point"
                ),
            )

        # Confirm usability: a degenerate generator is only a real break if it
        # yields a usable DH key.  Reuse the generated public value (which is 0
        # when g=0) as the peer point.
        derived = 0
        try:
            derived = derive_key(
                rs.raw,
                rs.sh,
                priv,
                CKM_DH_PKCS_DERIVE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 16,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_TOKEN: False,
                },
                mech_param=mech_bytes(CKM_DH_PKCS_DERIVE, peer_value),
            )
        except CkrAssertionError as exc:
            # Clean rejection at derive -> lazy-but-conformant validation.
            derive_rv = getattr(exc, "rv", None)
            rv_label = ckr_name(derive_rv) if isinstance(derive_rv, int) else "unknown"
            xfail_as(
                "not_operational",
                kind="crypto",
                label=(
                    "CKM_DH_PKCS_KEY_PAIR_GEN accepted generator=0 but C_DeriveKey rejected it "
                    f"(lazy domain-parameter validation, derive rv={rv_label})"
                ),
            )
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)

        # Derive succeeded -> usable key over a degenerate group.
        fail_as(
            "accepted_invalid",
            kind="crypto",
            label=(
                "CKM_DH_PKCS_KEY_PAIR_GEN accepted generator=0 and produced a usable key over a "
                "degenerate group (shared secret forced to 0)"
            ),
        )

    def test_dh_1024bit_prime_posture(self, p11_raw_session: Any) -> None:
        """1024-bit DH prime acceptance posture note (NIST SP 800-56A, rev. 3).

        RFC 2409 Group 2 / Oakley Group 2 is a well-known 1024-bit MODP safe
        prime (mathematically valid).  NIST SP 800-56A rev. 3 Table 1 requires
        a minimum 2048-bit modulus for key-establishment schemes; accepting a
        1024-bit prime is allowed but not recommended.

        Either outcome (accept or reject) is conformant.  This test records
        whichever posture the module takes as a NOT_RECOMMENDED compliance note
        and never hard-fails.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_DH_PKCS_KEY_PAIR_GEN not supported")

        rv, pub, priv = _try_gen_dh_keypair(
            rs.raw, rs.sh, prime=_DH_PRIME_1024_RFC2409_GROUP2, base=_DH_GEN_2
        )
        try:
            if rv == 0:  # CKR_OK — accepted
                note(
                    "DH key generated with a 1024-bit prime (RFC 2409 Group 2 / Oakley Group 2),"
                    " below the 2048-bit minimum recommended by NIST SP 800-56A rev. 3 Table 1",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="NIST SP 800-56A rev. 3, §5.5.1.1, Table 1",
                    test_id="TestDHDomainParameterValidation.test_dh_1024bit_prime_posture",
                )
            else:
                note(
                    "Module rejected a 1024-bit DH prime (RFC 2409 Group 2 / Oakley Group 2);"
                    " this is a conservative posture consistent with NIST SP 800-56A rev. 3",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="NIST SP 800-56A rev. 3, §5.5.1.1, Table 1",
                    test_id="TestDHDomainParameterValidation.test_dh_1024bit_prime_posture",
                )
        finally:
            if pub:
                destroy_quietly(rs.raw, rs.sh, pub)
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)
