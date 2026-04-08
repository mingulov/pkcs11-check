"""Security posture probes -- weak algorithms and deprecated mechanisms.

These are NOT pass/fail tests. They report findings via compliance.note().
Supporting DES or 1024-bit RSA is a security observation, not a module bug.

Covers:
- Weak RSA key size acceptance (512, 768, 1024-bit)
- Deprecated mechanism availability (DES, RC4, MD2/MD5, SSL3)
- Deprecated mechanism operation (actual sign with weak algorithms)
- RSA PKCS v1.5 encryption availability
- Weak symmetric key size acceptance
- PIN timing side-channel analysis
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    get_mechanism_info,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKF_ENCRYPT,
    CKM_MD5_RSA_PKCS,
    CKM_RSA_PKCS,
    CKM_SHA1_RSA_PKCS,
    CKM_SSL3_MD5_MAC,
    CKM_SSL3_SHA1_MAC,
    CKR_PIN_INCORRECT,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
    CKU_USER,
)

pytestmark = pytest.mark.security

# ---------------------------------------------------------------------------
# Parametrization data
# ---------------------------------------------------------------------------

_WEAK_RSA_SIZES = [
    pytest.param(512, "CRITICAL", id="512-bit"),
    pytest.param(768, "CRITICAL", id="768-bit"),
    pytest.param(1024, "HIGH", id="1024-bit"),
]

_DEPRECATED_MECHANISMS: list[Any] = [
    pytest.param("DES_ECB", "HIGH", "56-bit key, brute-forceable", id="DES_ECB"),
    pytest.param("DES_CBC", "HIGH", "56-bit key, brute-forceable", id="DES_CBC"),
    pytest.param(
        "DES3_ECB", "MEDIUM", "Sweet32 birthday attack (CVE-2016-2183)", id="DES3_ECB"
    ),
    pytest.param(
        "DES3_CBC", "MEDIUM", "Sweet32 birthday attack (CVE-2016-2183)", id="DES3_CBC"
    ),
    pytest.param("RC4", "CRITICAL", "stream cipher broken per RFC 7465", id="RC4"),
    pytest.param("MD2", "HIGH", "obsolete hash, collision-broken", id="MD2"),
    pytest.param("MD5", "MEDIUM", "collision attacks practical since 2004", id="MD5"),
    pytest.param(
        "MD5_RSA_PKCS",
        "HIGH",
        "RSA signature with MD5, practical collision attacks",
        id="MD5_RSA_PKCS",
    ),
    pytest.param(
        "SHA1_RSA_PKCS",
        "MEDIUM",
        "RSA signature with SHA-1, SHAttered collision (2017)",
        id="SHA1_RSA_PKCS",
    ),
    pytest.param(
        "SSL3_MD5_MAC",
        "CRITICAL",
        "SSL 3.0 MAC, POODLE attack (CVE-2014-3566)",
        id="SSL3_MD5_MAC",
    ),
    pytest.param(
        "SSL3_SHA1_MAC",
        "CRITICAL",
        "SSL 3.0 MAC, POODLE attack (CVE-2014-3566)",
        id="SSL3_SHA1_MAC",
    ),
    pytest.param(
        "SSL3_PRE_MASTER_KEY_GEN",
        "CRITICAL",
        "SSL 3.0 key exchange, POODLE attack (CVE-2014-3566)",
        id="SSL3_PRE_MASTER_KEY_GEN",
    ),
]

_DEPRECATED_SIGN_MECHS: list[Any] = [
    pytest.param(
        "MD5_RSA_PKCS",
        CKM_MD5_RSA_PKCS,
        "RSA",
        id="MD5_RSA_PKCS",
    ),
    pytest.param(
        "SHA1_RSA_PKCS",
        CKM_SHA1_RSA_PKCS,
        "RSA",
        id="SHA1_RSA_PKCS",
    ),
    pytest.param(
        "SSL3_MD5_MAC",
        CKM_SSL3_MD5_MAC,
        "SSL3",
        id="SSL3_MD5_MAC",
    ),
    pytest.param(
        "SSL3_SHA1_MAC",
        CKM_SSL3_SHA1_MAC,
        "SSL3",
        id="SSL3_SHA1_MAC",
    ),
]

# Symmetric mechanisms and their smallest plausible key sizes (bits)
_WEAK_SYMMETRIC_SIZES: list[Any] = [
    pytest.param("AES_ECB", "AES_KEY_GEN", 64, "AES with 64-bit key", id="AES-64"),
    pytest.param("DES_ECB", "DES_KEY_GEN", 56, "DES with 56-bit key", id="DES-56"),
    pytest.param(
        "DES3_ECB", "DES3_KEY_GEN", 80, "3DES with 80-bit key", id="3DES-80"
    ),
]

# ---------------------------------------------------------------------------
# PIN timing constants
# ---------------------------------------------------------------------------

_PIN_TIMING_ITERATIONS = 50
_PIN_TIMING_THRESHOLD_PCT = 20  # report if timing difference exceeds 20%


class TestWeakRsaKeySize:
    """Probe whether the module accepts generation of weak RSA key sizes."""

    @pytest.mark.parametrize("bits,severity", _WEAK_RSA_SIZES)
    def test_weak_rsa_key_generation(
        self, p11_raw_session: Any, bits: int, severity: str
    ) -> None:
        """Attempt to generate an RSA keypair with a weak modulus size."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        try:
            pub, priv = gen_rsa_keypair(rs.raw, rs.sh, bits)
        except (AssertionError, OSError):
            return  # Module rejected weak key size -- good
        try:
            note(
                f"Module accepts {bits}-bit RSA key generation",
                ComplianceLevel.VENDOR,
                reference=f"NIST SP 800-57: {bits}-bit RSA is {severity} risk",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestDeprecatedMechanism:
    """Check whether deprecated/weak mechanisms are advertised."""

    @pytest.mark.parametrize("mech_name,severity,reason", _DEPRECATED_MECHANISMS)
    def test_deprecated_mechanism_available(
        self,
        p11_raw_session: Any,
        mech_name: str,
        severity: str,
        reason: str,
    ) -> None:
        """Report if a deprecated mechanism is listed in C_GetMechanismList."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name):
            return  # Not available -- no finding
        note(
            f"Module supports deprecated {mech_name}: {reason}",
            ComplianceLevel.VENDOR,
            reference=f"Severity: {severity}",
        )


class TestDeprecatedMechanismOperation:
    """Attempt actual operations with deprecated signing mechanisms."""

    @pytest.mark.parametrize("mech_name,mech_id,key_type", _DEPRECATED_SIGN_MECHS)
    def test_deprecated_sign_operation(
        self,
        p11_raw_session: Any,
        mech_name: str,
        mech_id: Any,
        key_type: str,
    ) -> None:
        """Attempt a sign operation with a deprecated mechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")

        if key_type == "RSA":
            if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
                pytest.skip("RSA keygen not supported")
            pub, priv = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
                public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            )
            try:
                data = b"deprecated mechanism sign test"
                try:
                    sig = sign_single(rs.raw, rs.sh, priv, mech_id, data)
                    note(
                        f"Module performs sign with deprecated {mech_name} "
                        f"(produced {len(sig)}-byte signature)",
                        ComplianceLevel.VENDOR,
                        reference=f"CKM_{mech_name} uses a weak hash algorithm",
                    )
                except (AssertionError, OSError):
                    pass  # Module rejected the operation -- acceptable
            finally:
                destroy_quietly(rs.raw, rs.sh, pub)
                destroy_quietly(rs.raw, rs.sh, priv)
        else:
            # SSL3 MAC mechanisms need a generic secret key; these typically
            # require SSL-specific parameters. Just note the availability.
            note(
                f"Module advertises deprecated {mech_name} and may accept "
                f"sign operations",
                ComplianceLevel.VENDOR,
                reference=f"CKM_{mech_name} is part of deprecated SSL 3.0",
            )


class TestRsaPkcsV15Encrypt:
    """Check if RSA PKCS v1.5 encryption is available (Bleichenbacher risk)."""

    def test_rsa_pkcs_v15_encrypt_available(self, p11_raw_session: Any) -> None:
        """CKM_RSA_PKCS with CKF_ENCRYPT indicates PKCS v1.5 encryption support.

        PKCS v1.5 encryption is vulnerable to Bleichenbacher's adaptive
        chosen-ciphertext attack (1998). Modern usage should prefer OAEP.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            return  # Not available
        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_RSA_PKCS)
        except (AssertionError, OSError):
            return  # Cannot query mechanism info
        if info["flags"] & int(CKF_ENCRYPT):
            note(
                "Module supports CKM_RSA_PKCS encryption (PKCS v1.5 padding)",
                ComplianceLevel.VENDOR,
                reference="Bleichenbacher 1998: PKCS v1.5 encryption is vulnerable "
                "to adaptive chosen-ciphertext attacks; prefer CKM_RSA_PKCS_OAEP",
            )


class TestWeakKeySizeAcceptance:
    """Probe whether symmetric mechanisms accept unusually small key sizes."""

    @pytest.mark.parametrize(
        "mech_name,keygen_name,bits,description", _WEAK_SYMMETRIC_SIZES
    )
    def test_weak_key_size_acceptance(
        self,
        p11_raw_session: Any,
        mech_name: str,
        keygen_name: str,
        bits: int,
        description: str,
    ) -> None:
        """Try to generate a symmetric key with a weak/small key size."""
        from pkcs11_check.raw.recipes import gen_aes_key
        from pkcs11_check.raw.types_std import (
            CKM_AES_KEY_GEN,
            CKM_DES3_KEY_GEN,
            CKM_DES_KEY_GEN,
        )

        rs = p11_raw_session
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")
        if not rs.has_mechanism(keygen_name):
            pytest.skip(f"CKM_{keygen_name} not supported")

        keygen_map: dict[str, int] = {
            "AES_KEY_GEN": int(CKM_AES_KEY_GEN),
            "DES_KEY_GEN": int(CKM_DES_KEY_GEN),
            "DES3_KEY_GEN": int(CKM_DES3_KEY_GEN),
        }
        mechanism = keygen_map.get(keygen_name)
        if mechanism is None:
            pytest.skip(f"Unknown keygen mechanism {keygen_name}")

        try:
            key_h = gen_aes_key(rs.raw, rs.sh, bits, mechanism=mechanism)
        except (AssertionError, OSError):
            return  # Module rejected weak key size -- good
        try:
            note(
                f"Module accepts {description}",
                ComplianceLevel.VENDOR,
                reference=f"Key size {bits}-bit is below recommended minimums",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


@pytest.mark.destructive
class TestPinTimingSideChannel:
    """Analyse whether PIN validation timing leaks information."""

    def test_pin_timing_side_channel(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Time correct vs wrong PIN logins to detect timing side channels.

        Measures login latency for correct and incorrect PINs, then compares
        the mean times. A large difference suggests the module short-circuits
        on PIN mismatch, leaking whether the PIN length or prefix is correct.
        """
        from pkcs11_check.raw.bootstrap import logout_quietly
        from pkcs11_check.raw.types_std import CK_UTF8CHAR

        rs = p11_raw_session
        if p11_config.pin is None:
            pytest.skip("No PIN configured (--p11-pin)")

        pin_bytes = p11_config.pin.get_secret_value().encode("utf-8")
        wrong_pin = b"WRONG_PIN_FOR_TIMING_TEST_12345"

        # Ensure we start logged out
        logout_quietly(rs.raw, rs.sh)

        correct_times: list[int] = []
        wrong_times: list[int] = []

        for _ in range(_PIN_TIMING_ITERATIONS):
            # Time correct PIN login
            pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
            t0 = time.perf_counter_ns()
            rv_ok = rs.raw.C_Login(rs.sh, int(CKU_USER), pin_buf, len(pin_bytes))
            t1 = time.perf_counter_ns()
            if rv_ok in (int(CKR_USER_ALREADY_LOGGED_IN), int(CKR_USER_TYPE_INVALID)):
                # Cannot measure -- session state prevents re-login
                return
            correct_times.append(t1 - t0)
            logout_quietly(rs.raw, rs.sh)

            # Time wrong PIN login
            wrong_buf = (CK_UTF8CHAR * len(wrong_pin))(*wrong_pin)
            t0 = time.perf_counter_ns()
            rv_bad = rs.raw.C_Login(rs.sh, int(CKU_USER), wrong_buf, len(wrong_pin))
            t1 = time.perf_counter_ns()
            if rv_bad == int(CKR_USER_ALREADY_LOGGED_IN):
                return  # Cannot measure
            if rv_bad != int(CKR_PIN_INCORRECT):
                # Unexpected error -- abort measurement
                return
            wrong_times.append(t1 - t0)

        if not correct_times or not wrong_times:
            return  # Not enough data

        mean_correct = sum(correct_times) / len(correct_times)
        mean_wrong = sum(wrong_times) / len(wrong_times)

        # Avoid division by zero
        if mean_correct == 0 and mean_wrong == 0:
            return

        baseline = max(mean_correct, mean_wrong)
        diff_pct = abs(mean_correct - mean_wrong) / baseline * 100

        if diff_pct > _PIN_TIMING_THRESHOLD_PCT:
            note(
                f"PIN timing variance detected: correct login avg "
                f"{mean_correct / 1e6:.2f}ms vs wrong PIN avg "
                f"{mean_wrong / 1e6:.2f}ms ({diff_pct:.1f}% difference)",
                ComplianceLevel.VENDOR,
                reference="Timing side channels can reveal PIN validity; "
                "constant-time comparison recommended",
            )

        # Re-login so the session fixture teardown finds a logged-in state
        pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
        rv_final = rs.raw.C_Login(rs.sh, int(CKU_USER), pin_buf, len(pin_bytes))
        # Ignore CKR_USER_ALREADY_LOGGED_IN here
        if rv_final not in (0, int(CKR_USER_ALREADY_LOGGED_IN)):
            pass  # Best-effort re-login
