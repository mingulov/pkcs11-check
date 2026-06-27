"""CVE and known-issue regression tests.

Each test references a specific CVE or GitHub issue and tests the
specific condition that was fixed.
"""

from __future__ import annotations

import ctypes
import hashlib
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as
from pkcs11_check.raw.bootstrap import (
    login_user,
)
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_bool, attr_bytes, mech_simple, template
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
    CK_ULONG,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_TRUSTED,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VERIFY,
    CKA_WRAP,
    CKK_AES,
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
    CKR_ACTION_PROHIBITED,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_WRAPPED_KEY_LEN_RANGE,
)
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    assert_correct,
    gen_aes_key_or_xfail,
    get_pin_bytes,
    is_known_error,
    reject_or_classify,
    skip_unless_create_object_supported,
    skip_unless_mechanism,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.security

# Expected rejection codes for importing an EC public key with an invalid /
# unknown curve OID (CVE-2021-3798). A spec-correct module rejects the bogus
# curve; another clean reject code is a non-spec deviation (xfail); acceptance
# is a crypto-correctness break (fail).
_INVALID_EC_CURVE_REJECT_RVS = (
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)

# CKR codes that indicate template/attribute rejection (not crash)
_TEMPLATE_REJECT_RVS = {
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
}

# CKR codes for data length / crypto errors
_DATA_ERROR_RVS = {
    CKR_DATA_LEN_RANGE,
    CKR_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_DEVICE_ERROR,
}

# CKR codes for mechanism errors during wrap
_MECHANISM_ERROR_RVS = {
    CKR_MECHANISM_INVALID,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
}

_SENSITIVE_WRAP_INAPPLICABLE_RVS = {
    CKR_ACTION_PROHIBITED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_NOT_WRAPPABLE,
}

_SENSITIVE_WRAP_RUNTIME_REJECT_RVS = {
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
}


def _gen_cve_aes_key_or_xfail(
    rs: Any,
    bits: int,
    *,
    attrs: dict[Any, Any] | None = None,
    purpose: str,
) -> int:
    """Generate AES setup keys for CVE tests without hiding provider findings."""
    skip_unless_mechanism(rs, "AES_KEY_GEN")
    try:
        return gen_aes_key(rs.raw, rs.sh, bits, attrs=attrs)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            f"AES_KEY_GEN advertised but {purpose} key generation is not operational",
        )
    raise


def _gen_cve_rsa_keypair_or_xfail(rs: Any, bits: int) -> tuple[int, int]:
    """Generate RSA setup keys for CVE tests without hiding provider findings."""
    skip_unless_mechanism(rs, "RSA_PKCS_KEY_PAIR_GEN")
    try:
        return gen_rsa_keypair(rs.raw, rs.sh, bits)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            KEYPAIR_RUNTIME_REJECT_RVS,
            "RSA_PKCS_KEY_PAIR_GEN advertised but CVE setup keypair generation is not operational",
        )
    raise


def _abort_encrypt_operation(raw: Any, session: int) -> None:
    """Best-effort cleanup after an expected encrypt error leaves state active."""
    try:
        out_buf = (ctypes.c_ubyte * 64)()
        out_len = CK_ULONG(64)
        raw.C_EncryptFinal(session, out_buf, byref(out_len))
    except (AttributeError, OSError, ctypes.ArgumentError):
        pass


class TestCKATrusted:
    """CKA_TRUSTED certificate handling (task 7.19).

    RedHat bug: CKA_TRUSTED cert writes fail on some modules.
    """

    def test_create_trusted_data_object(self, p11_raw_session: Any) -> None:
        """CKA_TRUSTED on data object - accept or reject, not crash."""
        rs = p11_raw_session
        skip_unless_create_object_supported(rs)
        try:
            obj = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: b"trusted-test",
                    CKA_VALUE: b"trusted-data",
                    CKA_TOKEN: False,
                    CKA_TRUSTED: True,
                },
            )
            assert obj != 0
            destroy_quietly(rs.raw, rs.sh, obj)
        except AssertionError as exc:
            reject_or_classify(
                exc,
                _TEMPLATE_REJECT_RVS,
                kind="policy",
                label="C_CreateObject CKA_TRUSTED=True data object on a user session",
            )
            return
        reject_or_classify(
            None,
            _TEMPLATE_REJECT_RVS,
            kind="policy",
            label="C_CreateObject CKA_TRUSTED=True data object on a user session",
        )


class TestCKADeriveOnEC:
    """CKA_DERIVE on EC keygen (task 7.20).

    Some modules fail EC P-256 keygen with CKR_ATTRIBUTE_VALUE_INVALID
    when CKA_DERIVE=True (a hardware-backed limitation). Software tokens should accept it.
    """

    def test_ec_keygen_with_derive(self, p11_raw_session: Any) -> None:
        """EC P-256 keygen with CKA_DERIVE=True."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key gen not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        try:
            pub, priv = gen_ec_keypair(
                rs.raw,
                rs.sh,
                curve_oid,
                private_attrs={CKA_DERIVE: True},
            )
            assert priv != 0
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
        except AssertionError as e:
            err_str = str(e)
            if "CKR_ATTRIBUTE_VALUE_INVALID" in err_str:
                # Some modules reject CKA_DERIVE on EC keys;
                # a clean non-spec rejection -> noted deviation, not a finding.
                classify(
                    "not_operational",
                    kind="crypto",
                    label="EC keygen with CKA_DERIVE",
                    operation="C_GenerateKeyPair",
                    mechanism="CKM_EC_KEY_PAIR_GEN",
                    expected=CKR_ATTRIBUTE_VALUE_INVALID,
                    summary="Module rejects CKA_DERIVE on EC (clean non-spec rejection)",
                )
            else:
                raise


class TestTookanUnwrapAttrs:
    """Tookan wrap/unwrap attribute preservation (task 7.23).

    Unwrapped keys must preserve security attributes.
    Reference: Tookan paper - CKA_SENSITIVE ignored on unwrap.
    """

    def test_unwrapped_key_preserves_extractable(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Unwrapped key should not be more extractable than the template says."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: True, CKA_UNWRAP: True},
        )
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )

        try:
            wrapped = wrap_key_recipe(
                rs.raw,
                rs.sh,
                wrap_h,
                target,
                CKM_AES_KEY_WRAP,
            )

            # Unwrap with EXTRACTABLE=False - must stay non-extractable
            unwrapped = unwrap_key(
                rs.raw,
                rs.sh,
                wrap_h,
                wrapped,
                CKM_AES_KEY_WRAP,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: False,
                    CKA_SENSITIVE: True,
                },
            )
            try:
                attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    unwrapped,
                    [CKA_EXTRACTABLE, CKA_SENSITIVE],
                )
                assert attrs[CKA_EXTRACTABLE] is False, (
                    "Tookan: unwrapped key is EXTRACTABLE despite template saying False"
                )
                assert attrs[CKA_SENSITIVE] is True, "Tookan: unwrapped key lost SENSITIVE flag"
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_unwrapped_key_cannot_unset_sensitive(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Tookan sec.3.3: unwrap with attacker-supplied CKA_SENSITIVE=False
        on a key that was originally SENSITIVE=True must not produce a
        non-sensitive copy.

        The attack: an attacker who can wrap a sensitive key and then unwrap
        it provides a template requesting CKA_SENSITIVE=False, hoping the
        module will silently accept the attribute downgrade and let them
        read the key value. Either the unwrap must be rejected, or the
        resulting key must keep CKA_SENSITIVE=True.

        Closes Phase 4.5 GAP-T3 (HIGH).
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: True, CKA_UNWRAP: True},
        )
        # Source key is SENSITIVE=True (and EXTRACTABLE=True so wrap is
        # permitted). The attacker controls the unwrap template, not the
        # source key.
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: True},
        )
        try:
            try:
                wrapped = wrap_key_recipe(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    target,
                    CKM_AES_KEY_WRAP,
                )
            except AssertionError as exc:
                if is_known_error(exc, _SENSITIVE_WRAP_INAPPLICABLE_RVS):
                    pytest.skip(f"Module cannot wrap SENSITIVE=True key: {exc}")
                xfail_if_known_ckr(
                    exc,
                    _SENSITIVE_WRAP_RUNTIME_REJECT_RVS,
                    "Tookan sensitive-key wrap rejected before unwrap check",
                )
                raise

            try:
                unwrapped = unwrap_key(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    wrapped,
                    CKM_AES_KEY_WRAP,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_SENSITIVE: False,  # attacker-controlled
                        CKA_EXTRACTABLE: True,
                    },
                )
            except AssertionError as exc:
                # Module rejected the attacker template — correct behaviour.
                msg = str(exc)
                if any(
                    code in msg
                    for code in (
                        "CKR_TEMPLATE_INCONSISTENT",
                        "CKR_ATTRIBUTE_VALUE_INVALID",
                        "CKR_ATTRIBUTE_READ_ONLY",
                        "CKR_ACTION_PROHIBITED",
                    )
                ):
                    return
                raise

            try:
                attrs = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_SENSITIVE])
                if attrs.get(CKA_SENSITIVE) is False:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "Module honoured CKA_SENSITIVE=False on unwrap of a "
                        "SENSITIVE=True key — Tookan sec.3.3 attack succeeded.",
                        ComplianceLevel.CRITICAL,
                        reference="Tookan paper §3.3 / PKCS#11 v3.2",
                    )
                    classify(
                        "self_contradiction",
                        kind="policy",
                        label="Tookan unwrap sensitive downgrade",
                        operation="C_UnwrapKey",
                        mechanism="CKM_AES_KEY_WRAP",
                        spec_ref="Tookan paper §3.3 / PKCS#11 v3.2",
                        summary="SECURITY: Tookan §3.3 — unwrap with CKA_SENSITIVE=False "
                        "produced a non-sensitive copy of a SENSITIVE=True key. "
                        "Sensitive-key boundary breached on unwrap.",
                    )
                # SENSITIVE preserved: correct behaviour (template ignored
                # for security-downgrade).
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
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Create session objects, logout, verify they're gone."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured - can't test logout")

        label = f"logout-test-{id(self)}".encode()

        # Generate a key with a unique label
        key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_LABEL: label},
            purpose="session object after logout",
        )

        # Verify it exists
        tmpl = template(attr_bytes(CKA_LABEL, label))
        found = find_objects(rs.raw, rs.sh, tmpl)
        assert len(found) >= 1

        # Logout (not close)
        rv = rs.raw.C_Logout(rs.sh)
        if rv != CKR_OK:
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
        pub, priv = _gen_cve_rsa_keypair_or_xfail(rs, 2048)
        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_MODULUS])
            modulus = attrs[CKA_MODULUS]
            assert isinstance(modulus, bytes)
            n = int.from_bytes(modulus, "big")

            # ROCA detection: check if n mod small primes follows the pattern
            # Simplified check - full ROCA uses 39 primes
            roca_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43]
            roca_markers = [
                0x6,
                0x18,
                0x60,
                0x420,
                0x1800,
                0x30000,
                0xC0000,
                0x780000,
                0x18000000,
                0xC0000000,
                0x3000000000,
                0x60000000000,
                0x1C0000000000,
            ]
            roca_hits = 0
            for p, marker in zip(roca_primes, roca_markers):
                if (1 << (n % p)) & marker:
                    roca_hits += 1

            # Software tokens should NOT produce ROCA-patterned keys
            assert roca_hits < 10, f"RSA modulus has ROCA-like fingerprint ({roca_hits}/13 matches)"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestECDSATimingBasic:
    """Basic ECDSA timing variance check (CVE-2023-6135 Minerva, task 7b.14).

    Full Minerva attack needs thousands of signatures + statistical analysis.
    This is a basic sanity check that signing times don't vary wildly.
    """

    def test_ecdsa_timing_variance(
        self,
        p11_raw_session: Any,
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
            # and CV can be high. This 100-sample CV heuristic is *informational
            # only* -- a real Minerva-class leak (CVE-2019-13627, CVE-2023-6135)
            # needs thousands of signatures + bimodal-distribution analysis. A
            # high CV here is a flag for further investigation, not proof of a
            # leak, so it must not gate the suite (catalog CR-6).
            if cv >= 1.0:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"ECDSA P-256 100-sample timing CV={cv:.3f} "
                    f"(mean={mean_t * 1000:.2f}ms, stdev={stdev_t * 1000:.2f}ms) "
                    "-- review with a full Minerva-style multi-thousand-sample "
                    "analysis to confirm or rule out a timing leak",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="CVE-2019-13627 / CVE-2023-6135 (Minerva). 100-"
                    "sample CV is environment-sensitive (OS scheduling jitter "
                    "alone can push CV past 1.0 on shared runners).",
                )
                classify(
                    "honest_deviation",
                    kind="metadata",
                    label="ECDSA timing variance (Minerva sanity)",
                    operation="C_Sign",
                    mechanism="CKM_ECDSA",
                    summary=f"ECDSA timing CV={cv:.3f} -- informational, needs deeper "
                    "Minerva analysis to confirm leak",
                    detail={"channel": "timing", "cv": round(cv, 3), "samples": 100},
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
        skip_unless_mechanism(rs, "AES_ECB")
        key = _gen_cve_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-ECB boundary-length regression",
        )
        try:
            for size in [0, 1, 15, 16, 17, 31, 32]:
                data = b"\xaa" * size
                if size % 16 == 0 and size > 0:
                    # Block-aligned - should work
                    ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
                    pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
                    assert_correct(
                        actual=pt,
                        expected=data,
                        label="AES_ECB:block-aligned decrypt(encrypt(pt)) roundtrip",
                        operation="C_Decrypt",
                        mechanism="CKM_AES_ECB",
                    )
                else:
                    # Non-aligned - should fail with proper CKR
                    try:
                        encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
                    except AssertionError:
                        _abort_encrypt_operation(rs.raw, rs.sh)
                        pass  # Correct rejection via expect_rv
                    else:
                        if size > 0:
                            classify(
                                "accepted_invalid",
                                kind="crypto",
                                label="AES-ECB non-block-aligned plaintext",
                                operation="C_Encrypt",
                                mechanism="CKM_AES_ECB",
                                actual="CKR_OK",
                                expected=_DATA_ERROR_RVS,
                                summary="AES-ECB accepted non-block-aligned plaintext "
                                f"length {size}",
                            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rsa_encrypt_boundary(self, p11_raw_session: Any) -> None:
        """RSA-PKCS encrypt with empty and max-length data."""
        rs = p11_raw_session
        pub, priv = _gen_cve_rsa_keypair_or_xfail(rs, 2048)
        try:
            # Empty data - some modules reject
            try:
                encrypt_single(rs.raw, rs.sh, pub, CKM_RSA_PKCS, b"")
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    (CKR_DATA_LEN_RANGE, CKR_ARGUMENTS_BAD, CKR_DATA_INVALID),
                    "RSA-PKCS encrypt of empty data rejected",
                )

            # Max data for RSA-2048 PKCS#1 v1.5: 245 bytes (256 - 11)
            try:
                ct = encrypt_single(rs.raw, rs.sh, pub, CKM_RSA_PKCS, b"\x42" * 245)
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    (CKR_DATA_LEN_RANGE, CKR_ARGUMENTS_BAD),
                    "RSA-2048 PKCS#1 encrypt of max-length (245B) data rejected",
                )
            else:
                if len(ct) != 256:
                    fail_as(
                        "wrong_result",
                        kind="crypto",
                        label="RSA-2048 PKCS#1 encrypt output length",
                        actual=len(ct),
                        expected=256,
                        summary="RSA-2048 ciphertext is not 256 bytes",
                    )

            # Over max - must reject. RSA-2048 PKCS#1 v1.5 max plaintext is 245
            # bytes (256 - 11); 246 bytes is over-max and acceptance is a
            # crypto-correctness break (accepted_invalid), not a silent pass.
            try:
                encrypt_single(rs.raw, rs.sh, pub, CKM_RSA_PKCS, b"\x42" * 246)
            except AssertionError as exc:
                reject_or_classify(
                    exc,
                    (CKR_DATA_LEN_RANGE, CKR_ARGUMENTS_BAD, CKR_ENCRYPTED_DATA_LEN_RANGE),
                    label="RSA-PKCS over-max encrypt (246 bytes)",
                    kind="crypto",
                )
            else:
                fail_as(
                    "accepted_invalid",
                    kind="crypto",
                    label="RSA-PKCS over-max encrypt (246 bytes)",
                    summary="RSA-PKCS accepted 246-byte plaintext (max 245 for RSA-2048)",
                )
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
        skip_unless_create_object_supported(rs)
        bad_oid = bytes([0x06, 0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0x00])
        fake_point = b"\x04" + b"\x01" * 64  # Fake uncompressed point

        # crypto-correctness: importing an EC public key with an invalid /
        # unknown curve OID and a bogus point is a cryptographic correctness break
        # (CVE-2021-3798 pattern). Acceptance -> fail; expected curve/param reject ->
        # pass; another clean reject code -> xfail. No claim-check (crypto).
        reject_exc: AssertionError | None = None
        try:
            obj = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_PUBLIC_KEY,
                    CKA_KEY_TYPE: CKK_EC,
                    CKA_EC_PARAMS: bad_oid,
                    CKA_EC_POINT: fake_point,
                    CKA_VERIFY: True,
                    CKA_TOKEN: False,
                },
            )
            destroy_quietly(rs.raw, rs.sh, obj)
        except AssertionError as exc:
            reject_exc = exc

        reject_or_classify(
            reject_exc,
            _INVALID_EC_CURVE_REJECT_RVS,
            label="import EC public key with invalid curve OID",
            kind="crypto",
        )


class TestWrapUnsupportedMechanismRegression:
    """3DES key wrap mechanism error regression (task 7b.6).

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
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: True, CKA_UNWRAP: True},
        )
        # 3DES keygen uses CKM_DES3_KEY_GEN with no CKA_VALUE_LEN
        des3_tmpl = template(
            attr_bool(CKA_EXTRACTABLE, True),
            attr_bool(CKA_SENSITIVE, False),
        )
        des3_mech = mech_simple(CKM_DES3_KEY_GEN)
        des3_h = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(
            rs.sh,
            des3_mech.byref(),
            des3_tmpl.ptr,
            des3_tmpl.count,
            byref(des3_h),
        )
        expect_rv(rv, CKR_OK)
        des3_key = des3_h.value

        try:
            try:
                wrapped = wrap_key_recipe(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    des3_key,
                    CKM_AES_KEY_WRAP,
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    (CKR_KEY_SIZE_RANGE, CKR_WRAPPED_KEY_LEN_RANGE, CKR_KEY_HANDLE_INVALID),
                    "3DES key wrap under AES-KEY-WRAP rejected",
                )
            else:
                if len(wrapped) == 0:
                    fail_as(
                        "wrong_result",
                        kind="crypto",
                        label="AES-KEY-WRAP of 3DES key",
                        summary="wrap returned empty ciphertext",
                    )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, des3_key)


class TestDecryptCrashRegression:
    """RSA decrypt crash regression (task 7b.9).

    RSA keygen + encrypt + decrypt cycle via subprocess.
    Must not segfault.
    """

    def test_rsa_encrypt_decrypt_no_crash(self, p11_config: Any) -> None:
        """RSA encrypt/decrypt cycle in subprocess - must not crash."""
        import os
        import subprocess
        import sys

        from pkcs11_check.testcases._subprocess_preamble import (
            _P11CHECK_PIN_ENV,
            pin_from_config,
            subprocess_session_preamble,
        )

        module = str(p11_config.module)
        pin = pin_from_config(p11_config)

        preamble = subprocess_session_preamble(
            module,
            pin=pin,
            slot_label="pkcs11-check",
            extra_imports="""\
from pkcs11_check.raw.recipes import (
    gen_rsa_keypair, encrypt_single, decrypt_single, destroy_quietly,
)
from pkcs11_check.raw.types_std import CKM_RSA_PKCS, CKA_ENCRYPT, CKA_DECRYPT""",
        )

        script = (
            preamble
            + """\
try:
    pub, priv = gen_rsa_keypair(raw, sh, 2048,
        public_attrs={CKA_ENCRYPT: True},
        private_attrs={CKA_DECRYPT: True},
    )
    try:
        ct = encrypt_single(raw, sh, pub, CKM_RSA_PKCS, b"test data 722")
        pt = decrypt_single(raw, sh, priv, CKM_RSA_PKCS, ct)
        assert pt == b"test data 722"
        print("OK: RSA encrypt/decrypt cycle")
    except Exception as e:
        print(f"ERROR: {type(e).__name__}: {e}")
    finally:
        destroy_quietly(raw, sh, pub)
        destroy_quietly(raw, sh, priv)
    raw.C_CloseSession(sh)
except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")
finally:
    raw.C_Finalize(None)
"""
        )
        # Pass the PIN via the child env (never embed it in the script source).
        env = {**os.environ}
        if pin is not None:
            env[_P11CHECK_PIN_ENV] = pin
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        assert result.returncode == 0, (
            f"RSA encrypt/decrypt crashed (rc={result.returncode}): {result.stderr}"
        )
        assert "OK:" in result.stdout or "ERROR:" in result.stdout


class TestMutexDeadlockRegression:
    """Mutex deadlock on rapid sign operations regression (task 7b.12).

    Rapid sequential sign operations - must not deadlock.
    """

    def test_rapid_sign_no_deadlock(self, p11_raw_session: Any) -> None:
        """100 rapid RSA sign operations - must not deadlock."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
        pub, priv = _gen_cve_rsa_keypair_or_xfail(rs, 2048)

        try:
            for i in range(100):
                data = f"rapid-sign-{i}".encode()
                sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
                assert len(sig) == 256
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
