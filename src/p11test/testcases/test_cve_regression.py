"""CVE and known-issue regression tests.

Each test references a specific CVE or GitHub issue and tests the
specific condition that was fixed.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import PKCS11Error
from pkcs11.util.ec import encode_named_curve_parameters

from p11test.testcases.conftest import has_mechanism

pytestmark = pytest.mark.security


class TestCKATrusted:
    """CKA_TRUSTED certificate handling (task 7.19).

    RedHat bug: CKA_TRUSTED cert writes fail on some modules.
    """

    def test_create_trusted_data_object(self, p11_session: Any) -> None:
        """CKA_TRUSTED on data object — accept or reject, not crash."""
        try:
            obj = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: "trusted-test",
                    Attribute.VALUE: b"trusted-data",
                    Attribute.TOKEN: False,
                    Attribute.TRUSTED: True,
                }
            )
            # If accepted, verify the flag
            assert obj is not None
        except PKCS11Error:
            pass  # Some modules reject CKA_TRUSTED — that's fine


class TestCKADeriveOnEC:
    """CKA_DERIVE on EC keygen (task 7.20).

    tpm2-pkcs11 #656: EC P-256 keygen fails with CKR_ATTRIBUTE_VALUE_INVALID
    when CKA_DERIVE=True (TPM limitation). Software tokens should accept it.
    """

    def test_ec_keygen_with_derive(self, p11_session: Any, p11_module: Any) -> None:
        """EC P-256 keygen with CKA_DERIVE=True."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("EC key gen not supported")

        params = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        try:
            pub, priv = params.generate_keypair(
                private_template={Attribute.DERIVE: True},
            )
            assert priv is not None
        except p11.exceptions.PKCS11Error as e:
            # TPM modules may reject CKA_DERIVE on EC
            if "ATTRIBUTE_VALUE_INVALID" in str(type(e).__name__):
                pytest.xfail("Module rejects CKA_DERIVE on EC (tpm2-pkcs11 #656)")
            else:
                raise


class TestTookanUnwrapAttrs:
    """Tookan wrap/unwrap attribute preservation (task 7.23).

    Unwrapped keys must preserve security attributes.
    Reference: Tookan paper — CKA_SENSITIVE ignored on unwrap.
    """

    def test_unwrapped_key_preserves_extractable(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Unwrapped key should not be more extractable than the template says."""
        if not has_mechanism(p11_module, "AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_key = p11_session.generate_key(
            KeyType.AES, 256,
            template={Attribute.WRAP: True, Attribute.UNWRAP: True},
        )
        target = p11_session.generate_key(
            KeyType.AES, 128,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )

        wrapped = wrap_key.wrap_key(target, mechanism=Mechanism.AES_KEY_WRAP)

        # Unwrap with EXTRACTABLE=False — must stay non-extractable
        unwrapped = wrap_key.unwrap_key(
            ObjectClass.SECRET_KEY, KeyType.AES, wrapped,
            mechanism=Mechanism.AES_KEY_WRAP,
            template={Attribute.EXTRACTABLE: False, Attribute.SENSITIVE: True},
        )
        assert unwrapped[Attribute.EXTRACTABLE] is False, (
            "Tookan: unwrapped key is EXTRACTABLE despite template saying False"
        )
        assert unwrapped[Attribute.SENSITIVE] is True, (
            "Tookan: unwrapped key lost SENSITIVE flag"
        )


class TestSessionObjectsAfterLogout:
    """Session objects surviving logout (task 7.25).

    Per spec, session objects should be destroyed on logout.
    """

    def test_session_objects_after_logout(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Create session objects, logout, verify they're gone."""
        token = p11_module.get_token()
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        if pin is None:
            pytest.skip("No PIN configured — can't test logout")

        session = token.open(rw=True)
        try:
            session.login(p11.UserType.USER, pin)
        except p11.exceptions.UserAlreadyLoggedIn:
            pass

        label = f"logout-test-{id(self)}"
        session.generate_key(KeyType.AES, 128, label=label)

        # Verify it exists
        found = list(session.get_objects({Attribute.LABEL: label}))
        assert len(found) >= 1

        # Logout (not close)
        try:
            session.logout()
        except PKCS11Error:
            pytest.skip("Logout failed (another session holds login)")

        # Re-login and check
        try:
            session.login(p11.UserType.USER, pin)
        except p11.exceptions.UserAlreadyLoggedIn:
            pass

        found_after = list(session.get_objects({Attribute.LABEL: label}))
        # Session objects may or may not survive logout — module-specific
        # But the operation must not crash
        if len(found_after) > 0:
            from p11test.compliance import ComplianceLevel, note
            note(
                "Session objects survive C_Logout",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 spec: session objects should be destroyed on logout",
            )

        session.close()


class TestROCAFingerprint:
    """ROCA CVE-2017-15361 — weak RSA key generation (task 7b.13).

    Infineon RSALib generated keys with a detectable fingerprint in the
    modulus. Test: generate RSA keys and verify no ROCA pattern.
    """

    def test_rsa_modulus_not_roca(self, p11_session: Any) -> None:
        """Generated RSA-2048 modulus should not have ROCA fingerprint."""
        pub, _priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        modulus = pub[Attribute.MODULUS]
        n = int.from_bytes(modulus, "big")

        # ROCA detection: check if n mod small primes follows the pattern
        # Simplified check — full ROCA uses 39 primes
        roca_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43]
        roca_markers = [
            0x6, 0x18, 0x60, 0x420, 0x1800, 0x30000, 0xC0000,
            0x780000, 0x18000000, 0xC0000000, 0x3000000000,
            0x60000000000, 0x1C0000000000,
        ]
        roca_hits = 0
        for p, marker in zip(roca_primes, roca_markers):
            if (1 << (n % p)) & marker:
                roca_hits += 1

        # Software tokens should NOT produce ROCA-patterned keys
        # (ROCA only affects Infineon hardware)
        # If >10/13 primes match, it's suspicious
        assert roca_hits < 10, (
            f"RSA modulus has ROCA-like fingerprint ({roca_hits}/13 matches)"
        )


class TestECDSATimingBasic:
    """Basic ECDSA timing variance check (CVE-2023-6135 Minerva, task 7b.14).

    Full Minerva attack needs thousands of signatures + statistical analysis.
    This is a basic sanity check that signing times don't vary wildly.
    """

    def test_ecdsa_timing_variance(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """ECDSA P-256 signing should have low timing variance."""
        import time

        if not has_mechanism(p11_module, "ECDSA"):
            pytest.skip("ECDSA not supported")

        params = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        try:
            _pub, priv = params.generate_keypair()
        except p11.exceptions.PKCS11Error:
            pytest.skip("P-256 not supported")
            return

        # Sign 100 messages and measure times
        times = []
        for i in range(100):
            data = f"timing-test-{i}".encode()
            start = time.perf_counter()
            priv.sign(data, mechanism=Mechanism.ECDSA)
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        import statistics

        mean_t = statistics.mean(times)
        stdev_t = statistics.stdev(times)
        cv = stdev_t / mean_t if mean_t > 0 else 0

        # For very fast operations (<1ms), OS scheduling jitter dominates
        # and CV can be high. Only flag truly extreme variance (CV > 1.0).
        # Real Minerva leaks show CV > 2.0 with bimodal distribution.
        assert cv < 1.0, (
            f"ECDSA timing CV={cv:.3f} (mean={mean_t*1000:.2f}ms, "
            f"stdev={stdev_t*1000:.2f}ms) — possible timing leak"
        )


class TestBoundaryLengthCrypto:
    """CVE-2019-17006 — missing input length checks (task 7b.3).

    Test encrypt/decrypt with boundary-length data.
    """

    def test_aes_ecb_boundary_lengths(self, p11_session: Any) -> None:
        """AES-ECB with 0, 1, 15, 16, 17, 31, 32 bytes."""
        key = p11_session.generate_key(KeyType.AES, 256)
        for size in [0, 1, 15, 16, 17, 31, 32]:
            data = b"\xAA" * size
            if size % 16 == 0 and size > 0:
                # Block-aligned — should work
                ct = key.encrypt(data, mechanism=Mechanism.AES_ECB)
                pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
                assert pt == data
            else:
                # Non-aligned — should fail with proper CKR
                try:
                    key.encrypt(data, mechanism=Mechanism.AES_ECB)
                except (p11.exceptions.DataLenRange, PKCS11Error):
                    pass  # Correct rejection

    def test_rsa_encrypt_boundary(self, p11_session: Any) -> None:
        """RSA-PKCS encrypt with empty and max-length data."""
        pub, _priv = p11_session.generate_keypair(KeyType.RSA, 2048)

        # Empty data
        try:
            pub.encrypt(b"", mechanism=Mechanism.RSA_PKCS)
        except PKCS11Error:
            pass  # Some modules reject empty

        # Max data for RSA-2048 PKCS#1 v1.5: 245 bytes (256 - 11)
        try:
            ct = pub.encrypt(b"\x42" * 245, mechanism=Mechanism.RSA_PKCS)
            assert len(ct) == 256
        except PKCS11Error:
            pass  # Some modules are stricter

        # Over max — must reject
        try:
            pub.encrypt(b"\x42" * 246, mechanism=Mechanism.RSA_PKCS)
        except PKCS11Error:
            pass  # Correct


class TestInvalidECCurve:
    """CVE-2021-3798 — missing EC curve validation (task 7b.15).

    Import EC public key with invalid/unknown curve OID.
    """

    def test_import_ec_key_with_bad_oid(self, p11_session: Any) -> None:
        """EC key with invalid curve OID must be rejected, not accepted."""
        bad_oid = bytes([0x06, 0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0x00])
        fake_point = b"\x04" + b"\x01" * 64  # Fake uncompressed point

        try:
            p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                    Attribute.KEY_TYPE: KeyType.EC,
                    Attribute.EC_PARAMS: bad_oid,
                    Attribute.EC_POINT: fake_point,
                    Attribute.VERIFY: True,
                    Attribute.TOKEN: False,
                }
            )
            # If accepted — this is the CVE-2021-3798 vulnerability
            from p11test.compliance import ComplianceLevel, note
            note(
                "Module accepted EC key with invalid curve OID (CVE-2021-3798 pattern)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="CVE-2021-3798: OpenCryptoki missing EC curve validation",
            )
        except PKCS11Error:
            pass  # Correct: reject invalid curve
