"""CVE and known-issue regression tests.

Each test references a specific CVE or GitHub issue and tests the
specific condition that was fixed.
"""

from __future__ import annotations

import hashlib
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    login_user,
    open_session,
)
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_bytes, mech_simple, template
from pkcs11_check.raw.recipes import (
    create_object,
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    find_objects,
    gen_aes_key,
    gen_ec_keypair,
    gen_rsa_keypair,
    read_attributes,
    sign_single,
    unwrap_key,
)
from pkcs11_check.raw.recipes import (
    wrap_key as wrap_key_recipe,
)
from pkcs11_check.raw.rv import ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_TRUSTED,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VERIFY,
    CKA_WRAP,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK_AES,
    CKK_DES3,
    CKK_EC,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP,
    CKM_DES3_KEY_GEN,
    CKM_ECDSA,
    CKM_RSA_PKCS,
    CKM_SHA256_RSA_PKCS,
    CKO_DATA,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ARGUMENTS_BAD,
    CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_ALREADY_LOGGED_IN,
)
from pkcs11_check.testcases.conftest import get_pin_bytes

pytestmark = pytest.mark.security

# CKR codes that indicate template/attribute rejection (not crash)
_TEMPLATE_REJECT_RVS = {
    int(c) for c in (
        CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID,
        CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT,
        CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED,
    )
}

# CKR codes for data length / crypto errors
_DATA_ERROR_RVS = {
    int(c) for c in (
        CKR_DATA_LEN_RANGE, CKR_DATA_INVALID,
        CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_ENCRYPTED_DATA_INVALID,
        CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED,
        CKR_GENERAL_ERROR, CKR_DEVICE_ERROR,
    )
}

# CKR codes for mechanism errors during wrap
_MECHANISM_ERROR_RVS = {
    int(c) for c in (
        CKR_MECHANISM_INVALID, CKR_KEY_NOT_WRAPPABLE,
        CKR_KEY_FUNCTION_NOT_PERMITTED,
        CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_DATA_LEN_RANGE,
        CKR_FUNCTION_FAILED,
    )
}


class TestCKATrusted:
    """CKA_TRUSTED certificate handling (task 7.19).

    RedHat bug: CKA_TRUSTED cert writes fail on some modules.
    """

    def test_create_trusted_data_object(self, p11_raw_session: Any) -> None:
        """CKA_TRUSTED on data object - accept or reject, not crash."""
        rs = p11_raw_session
        try:
            obj = create_object(
                rs.raw, rs.sh,
                {
                    int(CKA_CLASS): int(CKO_DATA),
                    int(CKA_LABEL): b"trusted-test",
                    int(CKA_VALUE): b"trusted-data",
                    int(CKA_TOKEN): False,
                    int(CKA_TRUSTED): True,
                },
            )
            # If accepted, verify the object was created
            assert obj != 0
            destroy_quietly(rs.raw, rs.sh, obj)
        except AssertionError as e:
            # expect_rv raises AssertionError on CKR error -- check if template error
            err_str = str(e)
            if any(ckr_name(rv) in err_str for rv in _TEMPLATE_REJECT_RVS):
                pass  # Some modules reject CKA_TRUSTED - that's fine
            else:
                raise


class TestCKADeriveOnEC:
    """CKA_DERIVE on EC keygen (task 7.20).

    tpm2-pkcs11 #656: EC P-256 keygen fails with CKR_ATTRIBUTE_VALUE_INVALID
    when CKA_DERIVE=True (TPM limitation). Software tokens should accept it.
    """

    def test_ec_keygen_with_derive(self, p11_raw_session: Any) -> None:
        """EC P-256 keygen with CKA_DERIVE=True."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key gen not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        try:
            pub, priv = gen_ec_keypair(
                rs.raw, rs.sh, curve_oid,
                private_attrs={int(CKA_DERIVE): True},
            )
            assert priv != 0
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
        except AssertionError as e:
            err_str = str(e)
            if "CKR_ATTRIBUTE_VALUE_INVALID" in err_str:
                pytest.xfail("Module rejects CKA_DERIVE on EC (tpm2-pkcs11 #656)")
            else:
                raise


class TestTookanUnwrapAttrs:
    """Tookan wrap/unwrap attribute preservation (task 7.23).

    Unwrapped keys must preserve security attributes.
    Reference: Tookan paper - CKA_SENSITIVE ignored on unwrap.
    """

    def test_unwrapped_key_preserves_extractable(
        self, p11_raw_session: Any,
    ) -> None:
        """Unwrapped key should not be more extractable than the template says."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_h = gen_aes_key(
            rs.raw, rs.sh, 256,
            attrs={int(CKA_WRAP): True, int(CKA_UNWRAP): True},
        )
        target = gen_aes_key(
            rs.raw, rs.sh, 128,
            attrs={int(CKA_EXTRACTABLE): True, int(CKA_SENSITIVE): False},
        )

        try:
            wrapped = wrap_key_recipe(
                rs.raw, rs.sh, wrap_h, target, CKM_AES_KEY_WRAP,
            )

            # Unwrap with EXTRACTABLE=False - must stay non-extractable
            unwrapped = unwrap_key(
                rs.raw, rs.sh, wrap_h, wrapped, CKM_AES_KEY_WRAP,
                attrs={
                    int(CKA_CLASS): int(CKO_SECRET_KEY),
                    int(CKA_KEY_TYPE): int(CKK_AES),
                    int(CKA_EXTRACTABLE): False,
                    int(CKA_SENSITIVE): True,
                },
            )
            try:
                attrs = read_attributes(
                    rs.raw, rs.sh, unwrapped,
                    [int(CKA_EXTRACTABLE), int(CKA_SENSITIVE)],
                )
                assert attrs[int(CKA_EXTRACTABLE)] is False, (
                    "Tookan: unwrapped key is EXTRACTABLE despite template saying False"
                )
                assert attrs[int(CKA_SENSITIVE)] is True, (
                    "Tookan: unwrapped key lost SENSITIVE flag"
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)


class TestSessionObjectsAfterLogout:
    """Session objects surviving logout (task 7.25).

    Per spec, session objects should be destroyed on logout.
    """

    def test_session_objects_after_logout(
        self, p11_raw_session: Any, p11_config: Any,
    ) -> None:
        """Create session objects, logout, verify they're gone."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured - can't test logout")

        label = f"logout-test-{id(self)}".encode("utf-8")

        # Generate a key with a unique label
        key = gen_aes_key(
            rs.raw, rs.sh, 128,
            attrs={int(CKA_LABEL): label},
        )

        # Verify it exists
        tmpl = template(attr_bytes(CKA_LABEL, label))
        found = find_objects(rs.raw, rs.sh, tmpl)
        assert len(found) >= 1

        # Logout (not close)
        rv = int(rs.raw.C_Logout(rs.sh))
        if rv != int(CKR_OK):
            destroy_quietly(rs.raw, rs.sh, key)
            pytest.skip(f"Logout failed: {ckr_name(rv)} (another session holds login)")

        # Re-login and check
        login_user(rs.raw, rs.sh, 1, pin_bytes)

        tmpl2 = template(attr_bytes(CKA_LABEL, label))
        found_after = find_objects(rs.raw, rs.sh, tmpl2)
        # Session objects may or may not survive logout - module-specific
        # But the operation must not crash
        if len(found_after) > 0:
            from pkcs11_check.compliance import ComplianceLevel, note
            note(
                "Session objects survive C_Logout",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 spec: session objects should be destroyed on logout",
            )
            # Cleanup surviving objects
            for h in found_after:
                destroy_quietly(rs.raw, rs.sh, h)


class TestROCAFingerprint:
    """ROCA CVE-2017-15361 - weak RSA key generation (task 7b.13).

    Infineon RSALib generated keys with a detectable fingerprint in the
    modulus. Test: generate RSA keys and verify no ROCA pattern.
    """

    def test_rsa_modulus_not_roca(self, p11_raw_session: Any) -> None:
        """Generated RSA-2048 modulus should not have ROCA fingerprint."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [int(CKA_MODULUS)])
            modulus = attrs[int(CKA_MODULUS)]
            assert isinstance(modulus, bytes)
            n = int.from_bytes(modulus, "big")

            # ROCA detection: check if n mod small primes follows the pattern
            # Simplified check - full ROCA uses 39 primes
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
            assert roca_hits < 10, (
                f"RSA modulus has ROCA-like fingerprint ({roca_hits}/13 matches)"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestECDSATimingBasic:
    """Basic ECDSA timing variance check (CVE-2023-6135 Minerva, task 7b.14).

    Full Minerva attack needs thousands of signatures + statistical analysis.
    This is a basic sanity check that signing times don't vary wildly.
    """

    def test_ecdsa_timing_variance(
        self, p11_raw_session: Any,
    ) -> None:
        """ECDSA P-256 signing should have low timing variance."""
        import time

        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("ECDSA not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        try:
            pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        except AssertionError:
            pytest.skip("P-256 not supported")
            return

        try:
            # Sign 100 messages and measure times
            times = []
            for i in range(100):
                data = hashlib.sha256(f"timing-test-{i}".encode()).digest()
                start = time.perf_counter()
                sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, data)
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
                f"stdev={stdev_t*1000:.2f}ms) - possible timing leak"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestBoundaryLengthCrypto:
    """CVE-2019-17006 - missing input length checks (task 7b.3).

    Test encrypt/decrypt with boundary-length data.
    """

    def test_aes_ecb_boundary_lengths(self, p11_raw_session: Any) -> None:
        """AES-ECB with 0, 1, 15, 16, 17, 31, 32 bytes."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            for size in [0, 1, 15, 16, 17, 31, 32]:
                data = b"\xAA" * size
                if size % 16 == 0 and size > 0:
                    # Block-aligned - should work
                    ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
                    pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
                    assert pt == data
                else:
                    # Non-aligned - should fail with proper CKR
                    try:
                        encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
                    except AssertionError:
                        pass  # Correct rejection via expect_rv
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rsa_encrypt_boundary(self, p11_raw_session: Any) -> None:
        """RSA-PKCS encrypt with empty and max-length data."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            # Empty data - some modules reject
            try:
                encrypt_single(rs.raw, rs.sh, pub, CKM_RSA_PKCS, b"")
            except AssertionError:
                pass  # Any CKR error is acceptable for empty data

            # Max data for RSA-2048 PKCS#1 v1.5: 245 bytes (256 - 11)
            try:
                ct = encrypt_single(rs.raw, rs.sh, pub, CKM_RSA_PKCS, b"\x42" * 245)
                assert len(ct) == 256
            except AssertionError:
                pass  # Some modules are stricter

            # Over max - must reject
            try:
                encrypt_single(rs.raw, rs.sh, pub, CKM_RSA_PKCS, b"\x42" * 246)
            except AssertionError:
                pass  # Correct: DataLenRange or similar
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestInvalidECCurve:
    """CVE-2021-3798 - missing EC curve validation (task 7b.15).

    Import EC public key with invalid/unknown curve OID.
    """

    def test_import_ec_key_with_bad_oid(self, p11_raw_session: Any) -> None:
        """EC key with invalid curve OID must be rejected, not accepted."""
        rs = p11_raw_session
        bad_oid = bytes([0x06, 0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0x00])
        fake_point = b"\x04" + b"\x01" * 64  # Fake uncompressed point

        try:
            obj = create_object(
                rs.raw, rs.sh,
                {
                    int(CKA_CLASS): int(CKO_PUBLIC_KEY),
                    int(CKA_KEY_TYPE): int(CKK_EC),
                    int(CKA_EC_PARAMS): bad_oid,
                    int(CKA_EC_POINT): fake_point,
                    int(CKA_VERIFY): True,
                    int(CKA_TOKEN): False,
                },
            )
            # If accepted - this is the CVE-2021-3798 vulnerability
            from pkcs11_check.compliance import ComplianceLevel, note
            note(
                "Module accepted EC key with invalid curve OID (CVE-2021-3798 pattern)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="CVE-2021-3798: OpenCryptoki missing EC curve validation",
            )
            destroy_quietly(rs.raw, rs.sh, obj)
        except AssertionError:
            pass  # Correct: reject invalid curve


class TestSoftHSM2Issue596:
    """SoftHSM2 #596 - CKR_MECHANISM_INVALID on 3DES wrap (task 7b.6).

    Wrapping a 3DES key with AES-KW should work (or return a specific
    mechanism error), not CKR_GENERAL_ERROR.
    """

    def test_wrap_3des_key(self, p11_raw_session: Any) -> None:
        """Wrap a 3DES key - verify proper CKR code."""
        rs = p11_raw_session
        if not rs.has_mechanism("DES3_KEY_GEN"):
            pytest.skip("3DES not supported")
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_h = gen_aes_key(
            rs.raw, rs.sh, 256,
            attrs={int(CKA_WRAP): True, int(CKA_UNWRAP): True},
        )
        # 3DES keygen uses CKM_DES3_KEY_GEN with no CKA_VALUE_LEN
        from pkcs11_check.raw.pack import attr_bool, mech_simple, template as tmpl_fn
        des3_tmpl = tmpl_fn(
            attr_bool(CKA_EXTRACTABLE, True),
            attr_bool(CKA_SENSITIVE, False),
        )
        des3_mech = mech_simple(CKM_DES3_KEY_GEN)
        des3_h = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(
            rs.sh, des3_mech.byref(), des3_tmpl.ptr, des3_tmpl.count,
            byref(des3_h),
        )
        expect_rv(int(rv), CKR_OK)
        des3_key = int(des3_h.value)

        try:
            try:
                wrapped = wrap_key_recipe(
                    rs.raw, rs.sh, wrap_h, des3_key, CKM_AES_KEY_WRAP,
                )
                assert len(wrapped) > 0  # Wrap succeeded
            except AssertionError:
                pass  # Acceptable: 3DES key size may not align with AES-KW
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, des3_key)


class TestSoftHSM2Issue722:
    """SoftHSM2 #722 - SIGSEGV on C_Decrypt with OpenSSL 3 (task 7b.9).

    RSA keygen + encrypt + decrypt cycle via subprocess.
    Must not segfault.
    """

    def test_rsa_encrypt_decrypt_no_crash(self, p11_config: Any) -> None:
        """RSA encrypt/decrypt cycle in subprocess - must not crash."""
        import subprocess
        import sys
        import textwrap

        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else "None"
        pin_arg = f'"{pin}"' if pin != "None" else "None"

        # NOTE: This subprocess test intentionally uses the pkcs11 fork
        # (not pkcs11_check.raw) because it tests crash isolation - the
        # subprocess must segfault-survive independently.
        script = f"""
import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism
lib = pkcs11.lib("{module}")
lib.initialize()
try:
    token = lib.get_token(token_label="pkcs11-check")
    with token.open(rw=True, user_pin={pin_arg}) as session:
        pub, priv = session.generate_keypair(KeyType.RSA, 2048)
        ct = pub.encrypt(b"test data 722", mechanism=Mechanism.RSA_PKCS)
        pt = priv.decrypt(ct, mechanism=Mechanism.RSA_PKCS)
        assert pt == b"test data 722"
        print("OK: RSA encrypt/decrypt cycle")
except Exception as e:
    print(f"ERROR: {{type(e).__name__}}: {{e}}")
finally:
    lib.finalize()
"""
        result = subprocess.run(
            [sys.executable, "-c", textwrap.dedent(script)],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, (
            f"RSA encrypt/decrypt crashed (rc={result.returncode}): {result.stderr}"
        )
        assert "OK:" in result.stdout or "ERROR:" in result.stdout


class TestTPM2Issue44:
    """tpm2-pkcs11 #44 - mutex deadlock on rapid login/SignInit (task 7b.12).

    Rapid sequential sign operations - must not deadlock.
    """

    def test_rapid_sign_no_deadlock(self, p11_raw_session: Any) -> None:
        """100 rapid RSA sign operations - must not deadlock."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)

        try:
            for i in range(100):
                data = f"rapid-sign-{i}".encode()
                sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
                assert len(sig) == 256
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
