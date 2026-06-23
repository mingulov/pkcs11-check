"""HKDF-Expand output-length cap: L > 255 * HashLen must be rejected (RFC 5869 §2.3).

RFC 5869 §2.3 REQUIRES that an HKDF implementation reject an output-length request
exceeding 255 * HashLen.  A PKCS#11 module advertising CKM_HKDF_DERIVE MUST enforce
this cap.  A module that accepts such a request violates the HKDF specification and
may cause downstream key-material truncation or buffer overflows in callers that
rely on the spec guarantee.

The test requests exactly ``hkdf_max_output(HashLen) + 1`` bytes of derived material
(one byte over the RFC cap) via C_DeriveKey with CKA_VALUE_LEN set to that value.

Verdict:
- CKR_OK (module accepted) → ``fail`` / ``accepted_invalid`` / ``crypto``
- Spec-correct rejection → ``pass``
- Other clean rejection  → ``xfail`` / ``nonspec_reject`` / ``crypto``

CKM_TLS12_KEY_AND_MAC_DERIVE is skipped: RFC 5869 §2.3 applies only to HKDF; the
TLS 1.2 PRF uses a different construction, and no sound over-length probe exists for
that mechanism without a validation module to calibrate it.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import fail_as
from pkcs11_check.raw.pack import mech_hkdf
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_HKDF_DERIVE,
    CKM_SHA256,
    CKM_SHA512,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_KEY_SIZE_RANGE,
)
from pkcs11_check.testcases.conftest import classify_negative_rv, import_secret_key_negotiated

pytestmark = pytest.mark.security

# ---------------------------------------------------------------------------
# Public helper (tested directly by tests/test_kdf_cap_unit.py)
# ---------------------------------------------------------------------------


def hkdf_max_output(hash_len: int) -> int:
    """Return the RFC 5869 §2.3 maximum HKDF-Expand output length for *hash_len* bytes.

    RFC 5869 §2.3 states: ``L`` must satisfy ``L <= 255 * HashLen``.  This function
    returns ``255 * hash_len``, i.e. the maximum legal output byte count.
    """
    return 255 * hash_len


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Expected spec-correct rejection codes for an over-cap CKA_VALUE_LEN request.
_OVER_CAP_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_DATA_LEN_RANGE,
)


def _import_ikm(rs: Any) -> int:
    """Import a 32-byte generic-secret key usable for HKDF derivation."""
    return import_secret_key_negotiated(
        rs,
        CKK_GENERIC_SECRET,
        bytes(range(32)),
        attrs={
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
        },
    )


# ---------------------------------------------------------------------------
# HKDF output-length cap check
# ---------------------------------------------------------------------------


class TestHKDFOutputCap:
    """HKDF-Expand must reject output length > 255 * HashLen (RFC 5869 §2.3).

    For each advertised HKDF hash variant the test requests CKA_VALUE_LEN equal to
    hkdf_max_output(HashLen) + 1.  A conformant module rejects the call; accepting
    it is a crypto-correctness violation.
    """

    @pytest.mark.parametrize(
        "hash_mech,mech_name,hash_name,hlen",
        [
            pytest.param(CKM_SHA256, "HKDF_DERIVE", "sha256", 32, id="sha256"),
            pytest.param(CKM_SHA512, "HKDF_DERIVE", "sha512", 64, id="sha512"),
        ],
    )
    def test_hkdf_over_cap_rejected(
        self,
        p11_raw_session: Any,
        hash_mech: Any,
        mech_name: str,
        hash_name: str,
        hlen: int,
    ) -> None:
        """C_DeriveKey(CKM_HKDF_DERIVE, CKA_VALUE_LEN=255*HashLen+1) must be rejected.

        RFC 5869 §2.3: L must not exceed 255 * HashLen.  Requesting one byte more
        than this cap is always illegal; a conformant PKCS#11 module must return a
        non-OK CKR rather than producing truncated or incorrect key material.
        """
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"CKM_{mech_name} not advertised — HKDF output-cap check skipped")

        over_len = hkdf_max_output(hlen) + 1
        base_key = _import_ikm(rs)
        derived = 0
        try:
            derived = derive_key(
                rs.raw,
                rs.sh,
                base_key,
                CKM_HKDF_DERIVE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_TOKEN: False,
                    CKA_VALUE_LEN: over_len,
                },
                mech_param=mech_hkdf(
                    CKM_HKDF_DERIVE,
                    hash_mech=hash_mech,
                    extract=True,
                    expand=True,
                    salt=b"salt",
                    info=b"info",
                ),
            )
            # Reaching here means the module accepted an over-cap output length —
            # a violation of RFC 5869 §2.3.
            fail_as(
                "accepted_invalid",
                kind="crypto",
                label=(
                    f"HKDF-Expand ({hash_name}) accepted output length {over_len} "
                    f"> 255 * HashLen ({255 * hlen}) — violates RFC 5869 §2.3"
                ),
                operation="C_DeriveKey",
                mechanism="CKM_HKDF_DERIVE",
            )
        except AssertionError as exc:
            rv = getattr(exc, "rv", None)
            if rv is None:
                raise
            classify_negative_rv(
                rv,
                _OVER_CAP_REJECT_RVS,
                label=(
                    f"HKDF-Expand ({hash_name}) rejects output > 255*HashLen"
                    f" (RFC 5869 §2.3): requested {over_len}, cap {255 * hlen}"
                ),
                kind="crypto",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)


# ---------------------------------------------------------------------------
# TLS12 leg — skipped (not applicable)
# ---------------------------------------------------------------------------


class TestTLS12KeyMaterialOverLength:
    """CKM_TLS12_KEY_AND_MAC_DERIVE over-length probe — skipped: not applicable.

    RFC 5869 §2.3 restricts HKDF-Expand specifically; it does NOT govern the
    TLS 1.2 PRF (which uses HMAC-SHA{256,384} directly, not HKDF-Expand).
    No sound over-length probe analogous to the HKDF cap exists for
    CKM_TLS12_KEY_AND_MAC_DERIVE: the ``ulKeySizeInBits`` fields in
    ``CK_TLS12_KEY_MAT_PARAMS`` express independent key/IV sizes, not a single
    cumulative output length governed by any standard cap formula.  Constructing
    an "absurd" value probe without a validation module to verify accept-vs-reject
    semantics risks false-accusing conformant implementations.

    Status: intentionally not implemented.  If a sound, validated probe is
    developed against a known-good TLS12-KDF module, it should be added here.
    """

    def test_tls12_key_and_mac_derive_over_length(
        self,
        p11_raw_session: Any,
    ) -> None:
        """TLS12 over-length probe not applicable — skip unconditionally."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS12_KEY_AND_MAC_DERIVE"):
            pytest.skip(
                "CKM_TLS12_KEY_AND_MAC_DERIVE not advertised — TLS12 over-length check skipped"
            )
        pytest.skip(
            "TLS12 over-length probe not implemented: RFC 5869 §2.3 cap applies only to "
            "HKDF-Expand; no sound analogous probe exists for CKM_TLS12_KEY_AND_MAC_DERIVE "
            "without a calibration module. See module docstring."
        )
