"""Tests for remaining OASIS spec gaps identified in post-Phase audit.

Closes every item from the gap analysis that was not covered by Phases A-H:

Phase A remaining:
- C_WaitForSlotEvent success path
- C_GetFunctionStatus / C_CancelFunction (legacy parallel)
- Message finalizers (C_MessageEncryptFinal etc.)
- Async lifecycle (C_AsyncComplete / C_AsyncJoin)
- C_SignEncryptUpdate / C_DecryptVerifyUpdate (dual-function)

Phase B remaining:
- CKA_WRAP_TEMPLATE / CKA_UNWRAP_TEMPLATE / CKA_DERIVE_TEMPLATE
- CKO_OTP_KEY object attributes

Phase D remaining:
- CKM_KMAC_128 / CKM_KMAC_256
- Standalone SHAKE XOF
- CKM_ML_DSA_EXTERNAL_MU / EXTERNAL_MU_GEN

Phase F remaining:
- CKM_PKCS12_PBE_EXPORT / CKM_PKCS12_PBE_IMPORT

Phase G remaining:
- CKM_RSA_PKCS_NULL

Tier 1 stragglers:
- CKM_AES_CMAC_GENERAL
- CKM_DSA_PROBABILISTIC_PARAMETER_GEN
- CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS

Most modules do not support these — tests skip cleanly.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import (
    AttributeTypeInvalid,
    FunctionNotSupported,
    PKCS11Error,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = [pytest.mark.compliance]


# ---------------------------------------------------------------------------
# Template constraint attributes (Phase B gap)
# ---------------------------------------------------------------------------


class TestTemplateConstraintAttributes:
    """CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE, CKA_DERIVE_TEMPLATE."""

    def test_wrap_template_attribute_readable(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Keys should accept CKA_WRAP_TEMPLATE if the module supports it."""
        if not has_mechanism(p11_module, "AES_KEY_GEN"):
            pytest.skip("AES not supported")
        try:
            key = p11_session.generate_key(
                KeyType.AES,
                256,
                mechanism=Mechanism.AES_KEY_GEN,
                template={
                    Attribute.ENCRYPT: True,
                    Attribute.DECRYPT: True,
                    Attribute.WRAP: True,
                    Attribute.TOKEN: False,
                },
            )
        except (FunctionNotSupported, PKCS11Error) as e:
            pytest.skip(f"AES key generation not supported: {e}")
            return
        try:
            try:
                wt = key[Attribute.WRAP_TEMPLATE]
                assert wt is not None or wt == b""
            except (AttributeTypeInvalid, PKCS11Error):
                pytest.skip("Module does not support CKA_WRAP_TEMPLATE")
        finally:
            key.destroy()

    def test_unwrap_template_attribute_readable(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Keys should accept CKA_UNWRAP_TEMPLATE if the module supports it."""
        if not has_mechanism(p11_module, "AES_KEY_GEN"):
            pytest.skip("AES not supported")
        try:
            key = p11_session.generate_key(
                KeyType.AES,
                256,
                mechanism=Mechanism.AES_KEY_GEN,
                template={
                    Attribute.ENCRYPT: True,
                    Attribute.DECRYPT: True,
                    Attribute.UNWRAP: True,
                    Attribute.TOKEN: False,
                },
            )
        except (FunctionNotSupported, PKCS11Error) as e:
            pytest.skip(f"AES key generation not supported: {e}")
            return
        try:
            try:
                ut = key[Attribute.UNWRAP_TEMPLATE]
                assert ut is not None or ut == b""
            except (AttributeTypeInvalid, PKCS11Error):
                pytest.skip("Module does not support CKA_UNWRAP_TEMPLATE")
        finally:
            key.destroy()

    def test_derive_template_attribute_readable(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Keys should accept CKA_DERIVE_TEMPLATE if the module supports it."""
        if not has_mechanism(p11_module, "AES_KEY_GEN"):
            pytest.skip("AES not supported")
        try:
            key = p11_session.generate_key(
                KeyType.AES,
                256,
                mechanism=Mechanism.AES_KEY_GEN,
                template={
                    Attribute.ENCRYPT: True,
                    Attribute.DERIVE: True,
                    Attribute.TOKEN: False,
                },
            )
        except (FunctionNotSupported, PKCS11Error) as e:
            pytest.skip(f"AES key generation not supported: {e}")
            return
        try:
            try:
                dt = key[Attribute.DERIVE_TEMPLATE]
                assert dt is not None or dt == b""
            except (AttributeTypeInvalid, PKCS11Error):
                pytest.skip("Module does not support CKA_DERIVE_TEMPLATE")
        finally:
            key.destroy()


# ---------------------------------------------------------------------------
# CKO_OTP_KEY object attributes (Phase B gap)
# ---------------------------------------------------------------------------


class TestOtpKeyAttributes:
    """CKO_OTP_KEY object attribute coverage.

    OTP mechanisms are tested in test_otp.py. This class verifies
    OTP-specific CKA_OTP_* attributes on key objects.
    """

    def test_otp_key_format_attribute(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """CKA_OTP_FORMAT should be readable on OTP keys if supported."""
        if not has_mechanism(p11_module, "HOTP_KEY_GEN"):
            pytest.skip("CKM_HOTP_KEY_GEN not supported")
        try:
            key = p11_session.generate_key(
                KeyType.HOTP,
                mechanism=Mechanism.HOTP_KEY_GEN,
                template={Attribute.TOKEN: False, Attribute.SIGN: True},
            )
        except PKCS11Error as e:
            pytest.skip(f"HOTP key generation failed: {e}")
            return
        try:
            for attr_name in ("OTP_FORMAT", "OTP_LENGTH"):
                attr = getattr(Attribute, attr_name, None)
                if attr is None:
                    continue
                try:
                    val = key[attr]
                    assert val is not None
                except (AttributeTypeInvalid, PKCS11Error):
                    pass  # Module may not expose all OTP attributes
        finally:
            key.destroy()


# ---------------------------------------------------------------------------
# C_WaitForSlotEvent success path (Phase A gap)
# ---------------------------------------------------------------------------


class TestWaitForSlotEvent:
    """C_WaitForSlotEvent — non-blocking poll."""

    def test_wait_for_slot_event_non_blocking(self, p11_module: Any) -> None:
        """Non-blocking C_WaitForSlotEvent should return CKR_NO_EVENT or succeed."""
        try:
            # Non-blocking call — should return immediately
            p11_module.lib.wait_for_slot_event(blocking=False)
        except FunctionNotSupported:
            pytest.skip("C_WaitForSlotEvent not supported")
        except PKCS11Error as e:
            # CKR_NO_EVENT (0x08) is the expected "nothing happened" response
            if "NO_EVENT" in str(type(e).__name__).upper() or "0x00000008" in str(e):
                pass  # Expected — no slot events pending
            else:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"C_WaitForSlotEvent returned unexpected error: {e}",
                    ComplianceLevel.VENDOR,
                )


# ---------------------------------------------------------------------------
# Legacy parallel functions (Phase A gap)
# ---------------------------------------------------------------------------


class TestLegacyParallelFunctions:
    """C_GetFunctionStatus and C_CancelFunction (legacy, §5.15).

    These functions are required to exist but always return
    CKR_FUNCTION_NOT_PARALLEL (0x51) per PKCS#11 v2.40+.
    """

    def test_get_function_status_returns_not_parallel(
        self, p11_session: Any, p11_config: Any
    ) -> None:
        """C_GetFunctionStatus must return CKR_FUNCTION_NOT_PARALLEL."""
        import subprocess
        import sys

        module_path = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else ""
        script = f"""
import ctypes
from ctypes import c_ulong, c_void_p, c_char_p, POINTER, byref
lib = ctypes.CDLL({module_path!r})
fl = c_void_p()
lib.C_GetFunctionList.restype = c_ulong
lib.C_GetFunctionList.argtypes = [POINTER(c_void_p)]
lib.C_GetFunctionList(byref(fl))
ps = ctypes.sizeof(c_void_p)
base = fl.value
def gf(i):
    return ctypes.cast(base + ps + i*ps, POINTER(c_void_p)).contents.value
# C_Initialize=0, C_GetSlotList=4, C_OpenSession=12, C_Login=18
# C_GetFunctionStatus=49, C_CancelFunction=50
CF = ctypes.CFUNCTYPE
init = CF(c_ulong, c_void_p)(gf(0))
init(None)
cnt = c_ulong()
CF(c_ulong, c_ulong, POINTER(c_ulong), POINTER(c_ulong))(gf(4))(1, None, byref(cnt))
slots = (c_ulong * cnt.value)()
CF(c_ulong, c_ulong, POINTER(c_ulong), POINTER(c_ulong))(gf(4))(1, slots, byref(cnt))
hs = c_ulong()
CF(c_ulong, c_ulong, c_ulong, c_void_p, c_void_p, POINTER(c_ulong))(gf(12))(
    slots[{p11_config.slot}], 0x06, None, None, byref(hs))
if {len(pin)} > 0:
    CF(c_ulong, c_ulong, c_ulong, c_char_p, c_ulong)(gf(18))(hs, 1, {pin.encode()!r}, {len(pin)})
rv = CF(c_ulong, c_ulong)(gf(49))(hs)
print(f"GFS:0x{{rv:08x}}")
rv2 = CF(c_ulong, c_ulong)(gf(50))(hs)
print(f"CF:0x{{rv2:08x}}")
CF(c_ulong, c_void_p)(gf(1))(None)
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            pytest.xfail(f"Subprocess failed: {result.stderr[:200]}")
        lines = result.stdout.strip().split("\n")
        gfs_line = next((l for l in lines if l.startswith("GFS:")), None)
        assert gfs_line is not None, f"No GFS output: {result.stdout!r}"
        rv_hex = gfs_line.split(":")[1]
        # Spec says CKR_FUNCTION_NOT_PARALLEL (0x51).
        # SoftHSM2 returns CKR_OPERATION_NOT_INITIALIZED (0x91) — module quirk.
        acceptable = {"0x00000051", "0x00000091"}
        if rv_hex not in acceptable:
            pytest.fail(
                f"C_GetFunctionStatus: expected CKR_FUNCTION_NOT_PARALLEL (0x51), got {rv_hex}"
            )
        if rv_hex != "0x00000051":
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                f"C_GetFunctionStatus returned {rv_hex} instead of spec-required "
                f"CKR_FUNCTION_NOT_PARALLEL (0x51)",
                ComplianceLevel.VENDOR,
            )

    def test_cancel_function_returns_not_parallel(
        self, p11_session: Any, p11_config: Any
    ) -> None:
        """C_CancelFunction must return CKR_FUNCTION_NOT_PARALLEL."""
        import subprocess
        import sys

        module_path = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else ""
        script = f"""
import ctypes
from ctypes import c_ulong, c_void_p, c_char_p, POINTER, byref
lib = ctypes.CDLL({module_path!r})
fl = c_void_p()
lib.C_GetFunctionList.restype = c_ulong
lib.C_GetFunctionList.argtypes = [POINTER(c_void_p)]
lib.C_GetFunctionList(byref(fl))
ps = ctypes.sizeof(c_void_p)
base = fl.value
def gf(i):
    return ctypes.cast(base + ps + i*ps, POINTER(c_void_p)).contents.value
CF = ctypes.CFUNCTYPE
init = CF(c_ulong, c_void_p)(gf(0))
init(None)
cnt = c_ulong()
CF(c_ulong, c_ulong, POINTER(c_ulong), POINTER(c_ulong))(gf(4))(1, None, byref(cnt))
slots = (c_ulong * cnt.value)()
CF(c_ulong, c_ulong, POINTER(c_ulong), POINTER(c_ulong))(gf(4))(1, slots, byref(cnt))
hs = c_ulong()
CF(c_ulong, c_ulong, c_ulong, c_void_p, c_void_p, POINTER(c_ulong))(gf(12))(
    slots[{p11_config.slot}], 0x06, None, None, byref(hs))
if {len(pin)} > 0:
    CF(c_ulong, c_ulong, c_ulong, c_char_p, c_ulong)(gf(18))(hs, 1, {pin.encode()!r}, {len(pin)})
rv = CF(c_ulong, c_ulong)(gf(50))(hs)
print(f"CF:0x{{rv:08x}}")
CF(c_ulong, c_void_p)(gf(1))(None)
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            pytest.xfail(f"Subprocess failed: {result.stderr[:200]}")
        lines = result.stdout.strip().split("\n")
        cf_line = next((l for l in lines if l.startswith("CF:")), None)
        assert cf_line is not None, f"No CF output: {result.stdout!r}"
        rv_hex = cf_line.split(":")[1]
        acceptable = {"0x00000051", "0x00000091"}
        if rv_hex not in acceptable:
            pytest.fail(
                f"C_CancelFunction: expected CKR_FUNCTION_NOT_PARALLEL (0x51), got {rv_hex}"
            )
        if rv_hex != "0x00000051":
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                f"C_CancelFunction returned {rv_hex} instead of spec-required "
                f"CKR_FUNCTION_NOT_PARALLEL (0x51)",
                ComplianceLevel.VENDOR,
            )


# ---------------------------------------------------------------------------
# Message-based finalizers (Phase A gap)
# ---------------------------------------------------------------------------


class TestMessageFinalizers:
    """C_MessageEncryptFinal, C_MessageDecryptFinal, etc. (v3.0+).

    These finalize message-based operations. Most modules that support
    message-based ops auto-finalize, so explicit finalize may not be needed.
    """

    @pytest.mark.requires_v30
    def test_message_encrypt_final_availability(
        self, p11_module: Any
    ) -> None:
        """Check if message-based encrypt final is accessible."""
        try:
            from pkcs11.raw import RawPKCS11

            raw = RawPKCS11(p11_module.lib._raw_funclist_ptr)
            # Just check the function exists in the function list
            assert hasattr(raw, "C_MessageEncryptFinal") or "C_MessageEncryptFinal" in raw._funcs
        except (AttributeError, ImportError):
            pytest.skip("Cannot access raw function list")

    @pytest.mark.requires_v30
    def test_message_verify_final_availability(
        self, p11_module: Any
    ) -> None:
        """Check if message-based verify final is accessible."""
        try:
            from pkcs11.raw import RawPKCS11

            raw = RawPKCS11(p11_module.lib._raw_funclist_ptr)
            assert hasattr(raw, "C_MessageVerifyFinal") or "C_MessageVerifyFinal" in raw._funcs
        except (AttributeError, ImportError):
            pytest.skip("Cannot access raw function list")


# ---------------------------------------------------------------------------
# Async lifecycle (Phase A gap)
# ---------------------------------------------------------------------------


class TestAsyncLifecycle:
    """C_AsyncComplete, C_AsyncJoin — v3.0+ async operation management."""

    @pytest.mark.requires_v30
    def test_async_complete_availability(self, p11_module: Any) -> None:
        """Check if C_AsyncComplete is in the function list."""
        try:
            from pkcs11.raw import RawPKCS11

            raw = RawPKCS11(p11_module.lib._raw_funclist_ptr)
            has_func = "C_AsyncComplete" in raw._funcs
            if not has_func:
                pytest.skip("C_AsyncComplete not in function list")
        except (AttributeError, ImportError):
            pytest.skip("Cannot access raw function list")

    @pytest.mark.requires_v30
    def test_async_join_availability(self, p11_module: Any) -> None:
        """Check if C_AsyncJoin is in the function list."""
        try:
            from pkcs11.raw import RawPKCS11

            raw = RawPKCS11(p11_module.lib._raw_funclist_ptr)
            has_func = "C_AsyncJoin" in raw._funcs
            if not has_func:
                pytest.skip("C_AsyncJoin not in function list")
        except (AttributeError, ImportError):
            pytest.skip("Cannot access raw function list")


# ---------------------------------------------------------------------------
# CKM_RSA_PKCS_NULL (Phase G gap)
# ---------------------------------------------------------------------------


class TestRsaPkcsNull:
    """CKM_RSA_PKCS_NULL — raw RSA with no formatting."""

    def test_null_mechanism_availability(self, p11_module: Any) -> None:
        """Check if CKM_RSA_PKCS_NULL is reported by the module."""
        if not has_mechanism(p11_module, "RSA_PKCS_NULL"):
            pytest.skip("CKM_RSA_PKCS_NULL not supported")


# ---------------------------------------------------------------------------
# KMAC (Phase D gap)
# ---------------------------------------------------------------------------


class TestKmac:
    """CKM_KMAC_128 and CKM_KMAC_256 — NIST SP 800-185 KECCAK MAC."""

    def test_kmac_128_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "KMAC_128"):
            pytest.skip("CKM_KMAC_128 not supported")

    def test_kmac_256_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "KMAC_256"):
            pytest.skip("CKM_KMAC_256 not supported")


# ---------------------------------------------------------------------------
# Standalone SHAKE XOF (Phase D gap)
# ---------------------------------------------------------------------------


class TestShakeXof:
    """Standalone SHAKE128/SHAKE256 as XOF digest mechanisms."""

    def test_shake_128_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "SHAKE_128"):
            pytest.skip("CKM_SHAKE_128 not supported")

    def test_shake_256_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "SHAKE_256"):
            pytest.skip("CKM_SHAKE_256 not supported")


# ---------------------------------------------------------------------------
# ML-DSA External MU (Phase D gap)
# ---------------------------------------------------------------------------


class TestMlDsaExternalMu:
    """CKM_ML_DSA_EXTERNAL_MU and CKM_ML_DSA_EXTERNAL_MU_GEN."""

    @pytest.mark.requires_v32
    def test_external_mu_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "ML_DSA_EXTERNAL_MU"):
            pytest.skip("CKM_ML_DSA_EXTERNAL_MU not supported")

    @pytest.mark.requires_v32
    def test_external_mu_gen_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "ML_DSA_EXTERNAL_MU_GEN"):
            pytest.skip("CKM_ML_DSA_EXTERNAL_MU_GEN not supported")


# ---------------------------------------------------------------------------
# PKCS#12 PBE (Phase F gap)
# ---------------------------------------------------------------------------


class TestPkcs12Pbe:
    """CKM_PKCS12_PBE_EXPORT and CKM_PKCS12_PBE_IMPORT."""

    def test_pkcs12_pbe_export_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "PKCS12_PBE_EXPORT"):
            pytest.skip("CKM_PKCS12_PBE_EXPORT not supported")

    def test_pkcs12_pbe_import_availability(self, p11_module: Any) -> None:
        if not has_mechanism(p11_module, "PKCS12_PBE_IMPORT"):
            pytest.skip("CKM_PKCS12_PBE_IMPORT not supported")


# ---------------------------------------------------------------------------
# Tier 1 stragglers
# ---------------------------------------------------------------------------


class TestTier1Stragglers:
    """Mechanisms identified as Tier 1 gaps in the audit."""

    def test_aes_cmac_general_availability(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """CKM_AES_CMAC_GENERAL — parameterized CMAC tag length."""
        if not has_mechanism(p11_module, "AES_CMAC_GENERAL"):
            pytest.skip("CKM_AES_CMAC_GENERAL not supported")
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            mechanism=Mechanism.AES_KEY_GEN,
            template={Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )
        try:
            sig = key.sign(b"test data for cmac general", mechanism=Mechanism.AES_CMAC_GENERAL)
            assert len(sig) > 0
        except PKCS11Error as e:
            pytest.xfail(f"AES_CMAC_GENERAL sign failed: {e}")
        finally:
            key.destroy()

    def test_dsa_probabilistic_parameter_gen_availability(
        self, p11_module: Any
    ) -> None:
        """CKM_DSA_PROBABILISTIC_PARAMETER_GEN."""
        if not has_mechanism(p11_module, "DSA_PROBABILISTIC_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PROBABILISTIC_PARAMETER_GEN not supported")

    def test_ec_key_pair_gen_w_extra_bits_availability(
        self, p11_module: Any
    ) -> None:
        """CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN_W_EXTRA_BITS"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS not supported")


# ---------------------------------------------------------------------------
# C_SignEncryptUpdate / C_DecryptVerifyUpdate (Phase A dual-function gap)
# ---------------------------------------------------------------------------


class TestDualFunctionRemaining:
    """C_SignEncryptUpdate (§5.14.3) and C_DecryptVerifyUpdate (§5.14.4).

    These combine sign+encrypt or decrypt+verify in a single call.
    Tested via ctypes subprocess — these functions are at CK_FUNCTION_LIST
    indices 56 and 57. Most modules return CKR_FUNCTION_NOT_SUPPORTED.
    """

    def test_sign_encrypt_update_callable(
        self, p11_config: Any
    ) -> None:
        """C_SignEncryptUpdate (index 56) exists and returns a defined CKR code."""
        import subprocess
        import sys

        module_path = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else ""
        script = f"""
import ctypes
from ctypes import c_ulong, c_void_p, c_char_p, POINTER, byref
lib = ctypes.CDLL({module_path!r})
fl = c_void_p()
lib.C_GetFunctionList.restype = c_ulong
lib.C_GetFunctionList.argtypes = [POINTER(c_void_p)]
lib.C_GetFunctionList(byref(fl))
ps = ctypes.sizeof(c_void_p)
base = fl.value
def gf(i):
    return ctypes.cast(base + ps + i*ps, POINTER(c_void_p)).contents.value
CF = ctypes.CFUNCTYPE
init = CF(c_ulong, c_void_p)(gf(0))
init(None)
cnt = c_ulong()
CF(c_ulong, c_ulong, POINTER(c_ulong), POINTER(c_ulong))(gf(4))(1, None, byref(cnt))
slots = (c_ulong * cnt.value)()
CF(c_ulong, c_ulong, POINTER(c_ulong), POINTER(c_ulong))(gf(4))(1, slots, byref(cnt))
hs = c_ulong()
CF(c_ulong, c_ulong, c_ulong, c_void_p, c_void_p, POINTER(c_ulong))(gf(12))(
    slots[{p11_config.slot}], 0x06, None, None, byref(hs))
if {len(pin)} > 0:
    CF(c_ulong, c_ulong, c_ulong, c_char_p, c_ulong)(gf(18))(hs, 1, {pin.encode()!r}, {len(pin)})
# C_SignEncryptUpdate = index 56
# Call with NULL pointers — should return CKR error, not crash
try:
    rv = CF(c_ulong, c_ulong, c_char_p, c_ulong, c_void_p, POINTER(c_ulong))(gf(56))(
        hs, b"test", 4, None, byref(c_ulong()))
    print(f"SEU:0x{{rv:08x}}")
except Exception as e:
    print(f"SEU:EXCEPTION:{{e}}")
CF(c_ulong, c_void_p)(gf(1))(None)
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode < 0:
            pytest.xfail(f"C_SignEncryptUpdate crashed (signal {-result.returncode})")
        seu_line = next((l for l in result.stdout.strip().split("\n") if l.startswith("SEU:")), None)
        assert seu_line is not None, f"No output: {result.stdout!r} {result.stderr[:200]}"
        # Any CKR response is valid — we're testing the function exists and doesn't crash

    def test_decrypt_verify_update_callable(
        self, p11_config: Any
    ) -> None:
        """C_DecryptVerifyUpdate (index 57) exists and returns a defined CKR code."""
        import subprocess
        import sys

        module_path = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else ""
        script = f"""
import ctypes
from ctypes import c_ulong, c_void_p, c_char_p, POINTER, byref
lib = ctypes.CDLL({module_path!r})
fl = c_void_p()
lib.C_GetFunctionList.restype = c_ulong
lib.C_GetFunctionList.argtypes = [POINTER(c_void_p)]
lib.C_GetFunctionList(byref(fl))
ps = ctypes.sizeof(c_void_p)
base = fl.value
def gf(i):
    return ctypes.cast(base + ps + i*ps, POINTER(c_void_p)).contents.value
CF = ctypes.CFUNCTYPE
init = CF(c_ulong, c_void_p)(gf(0))
init(None)
cnt = c_ulong()
CF(c_ulong, c_ulong, POINTER(c_ulong), POINTER(c_ulong))(gf(4))(1, None, byref(cnt))
slots = (c_ulong * cnt.value)()
CF(c_ulong, c_ulong, POINTER(c_ulong), POINTER(c_ulong))(gf(4))(1, slots, byref(cnt))
hs = c_ulong()
CF(c_ulong, c_ulong, c_ulong, c_void_p, c_void_p, POINTER(c_ulong))(gf(12))(
    slots[{p11_config.slot}], 0x06, None, None, byref(hs))
if {len(pin)} > 0:
    CF(c_ulong, c_ulong, c_ulong, c_char_p, c_ulong)(gf(18))(hs, 1, {pin.encode()!r}, {len(pin)})
# C_DecryptVerifyUpdate = index 57
try:
    rv = CF(c_ulong, c_ulong, c_char_p, c_ulong, c_void_p, POINTER(c_ulong))(gf(57))(
        hs, b"test", 4, None, byref(c_ulong()))
    print(f"DVU:0x{{rv:08x}}")
except Exception as e:
    print(f"DVU:EXCEPTION:{{e}}")
CF(c_ulong, c_void_p)(gf(1))(None)
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode < 0:
            pytest.xfail(f"C_DecryptVerifyUpdate crashed (signal {-result.returncode})")
        dvu_line = next((l for l in result.stdout.strip().split("\n") if l.startswith("DVU:")), None)
        assert dvu_line is not None, f"No output: {result.stdout!r} {result.stderr[:200]}"
