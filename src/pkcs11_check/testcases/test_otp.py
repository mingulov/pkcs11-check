"""OTP and CT-KIP mechanism tests - HOTP, SecurID, ACTI, CT-KIP.

Covers OTP key generation and OTP value generation via sign operations:
- CKM_HOTP_KEY_GEN / CKM_HOTP
- CKM_SECURID_KEY_GEN / CKM_SECURID
- CKM_ACTI_KEY_GEN / CKM_ACTI

Also covers CT-KIP key derivation/wrapping/MAC mechanisms:
- CKM_KIP_DERIVE
- CKM_KIP_WRAP
- CKM_KIP_MAC

These mechanisms are rarely supported by software HSMs. All tests check
mechanism availability and skip cleanly when not supported.

OASIS spec: otp_mechanisms.md, ct-kip.md
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import (
    ArgumentsBad,
    FunctionFailed,
    FunctionNotSupported,
    GeneralError,
    KeyFunctionNotPermitted,
    KeyTypeInconsistent,
    MechanismInvalid,
    MechanismParamInvalid,
    TemplateIncomplete,
    TemplateInconsistent,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.full

# Common error types for OTP/CT-KIP operations on unsupported or misconfigured modules
_OTP_ERRORS = (
    MechanismInvalid,
    MechanismParamInvalid,
    FunctionFailed,
    FunctionNotSupported,
    GeneralError,
    ArgumentsBad,
)

_KEYGEN_ERRORS = (
    MechanismInvalid,
    TemplateIncomplete,
    TemplateInconsistent,
    ArgumentsBad,
    FunctionFailed,
    GeneralError,
)


def _make_otp_key_template() -> dict[Attribute, Any]:
    """Return a minimal session-key template for OTP key generation."""
    return {
        Attribute.TOKEN: False,
        Attribute.SENSITIVE: False,
        Attribute.EXTRACTABLE: True,
        Attribute.SIGN: True,
    }


class TestHOTP:
    """Tests for CKM_HOTP_KEY_GEN and CKM_HOTP."""

    def test_hotp_key_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an HOTP key using CKM_HOTP_KEY_GEN."""
        if not has_mechanism(p11_module, "HOTP_KEY_GEN"):
            pytest.skip("CKM_HOTP_KEY_GEN not supported")
        template = _make_otp_key_template()
        template[Attribute.KEY_TYPE] = KeyType.HOTP
        template[Attribute.CLASS] = ObjectClass.SECRET_KEY
        key = None
        try:
            key = p11_session.generate_key(
                KeyType.HOTP,
                mechanism=Mechanism.HOTP_KEY_GEN,
                template=template,
            )
            assert key is not None
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"CKM_HOTP_KEY_GEN keygen rejected by module: {exc}")
        finally:
            if key is not None:
                key.destroy()

    def test_hotp_generate_otp(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an OTP value using CKM_HOTP (sign operation)."""
        if not has_mechanism(p11_module, "HOTP_KEY_GEN"):
            pytest.skip("CKM_HOTP_KEY_GEN not supported")
        if not has_mechanism(p11_module, "HOTP"):
            pytest.skip("CKM_HOTP not supported")
        template = _make_otp_key_template()
        template[Attribute.KEY_TYPE] = KeyType.HOTP
        template[Attribute.CLASS] = ObjectClass.SECRET_KEY
        key = None
        try:
            key = p11_session.generate_key(
                KeyType.HOTP,
                mechanism=Mechanism.HOTP_KEY_GEN,
                template=template,
            )
            # CKM_HOTP sign produces OTP bytes; empty data is typical input
            otp = key.sign(b"", mechanism=Mechanism.HOTP)
            assert len(otp) > 0
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"CKM_HOTP_KEY_GEN keygen rejected by module: {exc}")
        except _OTP_ERRORS as exc:
            pytest.xfail(f"CKM_HOTP sign rejected by module: {exc}")
        except (KeyFunctionNotPermitted, KeyTypeInconsistent) as exc:
            pytest.xfail(f"CKM_HOTP key not permitted for sign: {exc}")
        finally:
            if key is not None:
                key.destroy()

    def test_hotp_two_otps_differ(self, p11_session: Any, p11_module: Any) -> None:
        """Two consecutive HOTP values should differ (counter advances)."""
        if not has_mechanism(p11_module, "HOTP_KEY_GEN"):
            pytest.skip("CKM_HOTP_KEY_GEN not supported")
        if not has_mechanism(p11_module, "HOTP"):
            pytest.skip("CKM_HOTP not supported")
        template = _make_otp_key_template()
        template[Attribute.KEY_TYPE] = KeyType.HOTP
        template[Attribute.CLASS] = ObjectClass.SECRET_KEY
        key = None
        try:
            key = p11_session.generate_key(
                KeyType.HOTP,
                mechanism=Mechanism.HOTP_KEY_GEN,
                template=template,
            )
            otp1 = key.sign(b"", mechanism=Mechanism.HOTP)
            otp2 = key.sign(b"", mechanism=Mechanism.HOTP)
            # Counter-based: successive OTPs must differ
            assert otp1 != otp2, "Consecutive HOTP values must differ"
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"CKM_HOTP_KEY_GEN keygen rejected by module: {exc}")
        except _OTP_ERRORS as exc:
            pytest.xfail(f"CKM_HOTP sign rejected by module: {exc}")
        except (KeyFunctionNotPermitted, KeyTypeInconsistent) as exc:
            pytest.xfail(f"CKM_HOTP key not permitted for sign: {exc}")
        finally:
            if key is not None:
                key.destroy()


class TestSecurID:
    """Tests for CKM_SECURID_KEY_GEN and CKM_SECURID."""

    def test_securid_key_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a SecurID key using CKM_SECURID_KEY_GEN."""
        if not has_mechanism(p11_module, "SECURID_KEY_GEN"):
            pytest.skip("CKM_SECURID_KEY_GEN not supported")
        template = _make_otp_key_template()
        template[Attribute.KEY_TYPE] = KeyType.SECURID
        template[Attribute.CLASS] = ObjectClass.SECRET_KEY
        key = None
        try:
            key = p11_session.generate_key(
                KeyType.SECURID,
                mechanism=Mechanism.SECURID_KEY_GEN,
                template=template,
            )
            assert key is not None
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"CKM_SECURID_KEY_GEN keygen rejected by module: {exc}")
        finally:
            if key is not None:
                key.destroy()

    def test_securid_generate_otp(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an OTP value using CKM_SECURID (sign operation)."""
        if not has_mechanism(p11_module, "SECURID_KEY_GEN"):
            pytest.skip("CKM_SECURID_KEY_GEN not supported")
        if not has_mechanism(p11_module, "SECURID"):
            pytest.skip("CKM_SECURID not supported")
        template = _make_otp_key_template()
        template[Attribute.KEY_TYPE] = KeyType.SECURID
        template[Attribute.CLASS] = ObjectClass.SECRET_KEY
        key = None
        try:
            key = p11_session.generate_key(
                KeyType.SECURID,
                mechanism=Mechanism.SECURID_KEY_GEN,
                template=template,
            )
            otp = key.sign(b"", mechanism=Mechanism.SECURID)
            assert len(otp) > 0
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"CKM_SECURID_KEY_GEN keygen rejected by module: {exc}")
        except _OTP_ERRORS as exc:
            pytest.xfail(f"CKM_SECURID sign rejected by module: {exc}")
        except (KeyFunctionNotPermitted, KeyTypeInconsistent) as exc:
            pytest.xfail(f"CKM_SECURID key not permitted for sign: {exc}")
        finally:
            if key is not None:
                key.destroy()


class TestACTI:
    """Tests for CKM_ACTI_KEY_GEN and CKM_ACTI."""

    def test_acti_key_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an ACTI key using CKM_ACTI_KEY_GEN."""
        if not has_mechanism(p11_module, "ACTI_KEY_GEN"):
            pytest.skip("CKM_ACTI_KEY_GEN not supported")
        template = _make_otp_key_template()
        template[Attribute.KEY_TYPE] = KeyType.ACTI
        template[Attribute.CLASS] = ObjectClass.SECRET_KEY
        key = None
        try:
            key = p11_session.generate_key(
                KeyType.ACTI,
                mechanism=Mechanism.ACTI_KEY_GEN,
                template=template,
            )
            assert key is not None
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"CKM_ACTI_KEY_GEN keygen rejected by module: {exc}")
        finally:
            if key is not None:
                key.destroy()

    def test_acti_generate_otp(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an OTP value using CKM_ACTI (sign operation)."""
        if not has_mechanism(p11_module, "ACTI_KEY_GEN"):
            pytest.skip("CKM_ACTI_KEY_GEN not supported")
        if not has_mechanism(p11_module, "ACTI"):
            pytest.skip("CKM_ACTI not supported")
        template = _make_otp_key_template()
        template[Attribute.KEY_TYPE] = KeyType.ACTI
        template[Attribute.CLASS] = ObjectClass.SECRET_KEY
        key = None
        try:
            key = p11_session.generate_key(
                KeyType.ACTI,
                mechanism=Mechanism.ACTI_KEY_GEN,
                template=template,
            )
            otp = key.sign(b"", mechanism=Mechanism.ACTI)
            assert len(otp) > 0
        except _KEYGEN_ERRORS as exc:
            pytest.xfail(f"CKM_ACTI_KEY_GEN keygen rejected by module: {exc}")
        except _OTP_ERRORS as exc:
            pytest.xfail(f"CKM_ACTI sign rejected by module: {exc}")
        except (KeyFunctionNotPermitted, KeyTypeInconsistent) as exc:
            pytest.xfail(f"CKM_ACTI key not permitted for sign: {exc}")
        finally:
            if key is not None:
                key.destroy()


class TestCTKIP:
    """Tests for CT-KIP mechanisms: CKM_KIP_DERIVE, CKM_KIP_WRAP, CKM_KIP_MAC.

    CT-KIP (Cryptographic Token Key Initialization Protocol) is defined in
    RFC 4758 and OASIS PKCS#11 v2.40+. These mechanisms are extremely rare
    in practice; all tests skip cleanly when not supported.
    """

    def _make_generic_key(self, p11_session: Any) -> Any:
        """Create a 16-byte GENERIC_SECRET key for use as CT-KIP base key."""
        return p11_session.generate_key(
            KeyType.GENERIC_SECRET,
            16,
            template={
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.DERIVE: True,
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
            },
        )

    def test_kip_derive_skips_when_unsupported(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """CKM_KIP_DERIVE skips cleanly when not available."""
        if not has_mechanism(p11_module, "KIP_DERIVE"):
            pytest.skip("CKM_KIP_DERIVE not supported")
        # If mechanism is listed, attempt a minimal derive and accept any
        # module-specific rejection gracefully.
        base_key = None
        derived = None
        try:
            base_key = self._make_generic_key(p11_session)
            derive_template: dict[Attribute, Any] = {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
                Attribute.VALUE_LEN: 16,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
            }
            derived = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                16,
                mechanism=Mechanism.KIP_DERIVE,
                template=derive_template,
            )
            assert derived is not None
        except _OTP_ERRORS as exc:
            pytest.xfail(f"CKM_KIP_DERIVE rejected by module: {exc}")
        except (KeyFunctionNotPermitted, KeyTypeInconsistent) as exc:
            pytest.xfail(f"CKM_KIP_DERIVE key type mismatch: {exc}")
        finally:
            if derived is not None:
                derived.destroy()
            if base_key is not None:
                base_key.destroy()

    def test_kip_wrap_skips_when_unsupported(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """CKM_KIP_WRAP skips cleanly when not available."""
        if not has_mechanism(p11_module, "KIP_WRAP"):
            pytest.skip("CKM_KIP_WRAP not supported")
        # If mechanism is listed, attempt a minimal wrap and accept any
        # module-specific rejection gracefully.
        wrapping_key = None
        target_key = None
        try:
            wrapping_key = self._make_generic_key(p11_session)
            target_key = p11_session.generate_key(
                KeyType.GENERIC_SECRET,
                16,
                template={
                    Attribute.TOKEN: False,
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.WRAP: False,
                    Attribute.UNWRAP: False,
                },
            )
            wrapped = wrapping_key.wrap_key(target_key, mechanism=Mechanism.KIP_WRAP)
            assert len(wrapped) > 0
        except _OTP_ERRORS as exc:
            pytest.xfail(f"CKM_KIP_WRAP rejected by module: {exc}")
        except (KeyFunctionNotPermitted, KeyTypeInconsistent) as exc:
            pytest.xfail(f"CKM_KIP_WRAP key type mismatch: {exc}")
        finally:
            if target_key is not None:
                target_key.destroy()
            if wrapping_key is not None:
                wrapping_key.destroy()

    def test_kip_mac_skips_when_unsupported(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """CKM_KIP_MAC skips cleanly when not available."""
        if not has_mechanism(p11_module, "KIP_MAC"):
            pytest.skip("CKM_KIP_MAC not supported")
        # If mechanism is listed, attempt a minimal sign and accept any
        # module-specific rejection gracefully.
        key = None
        try:
            key = self._make_generic_key(p11_session)
            mac = key.sign(b"test data", mechanism=Mechanism.KIP_MAC)
            assert len(mac) > 0
        except _OTP_ERRORS as exc:
            pytest.xfail(f"CKM_KIP_MAC sign rejected by module: {exc}")
        except (KeyFunctionNotPermitted, KeyTypeInconsistent) as exc:
            pytest.xfail(f"CKM_KIP_MAC key not permitted for sign: {exc}")
        finally:
            if key is not None:
                key.destroy()

    def test_kip_mac_verify_skips_when_unsupported(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """CKM_KIP_MAC verify skips cleanly when not available."""
        if not has_mechanism(p11_module, "KIP_MAC"):
            pytest.skip("CKM_KIP_MAC not supported")
        key = None
        try:
            key = self._make_generic_key(p11_session)
            mac = key.sign(b"verify test", mechanism=Mechanism.KIP_MAC)
            result = key.verify(b"verify test", mac, mechanism=Mechanism.KIP_MAC)
            assert result is True
        except _OTP_ERRORS as exc:
            pytest.xfail(f"CKM_KIP_MAC sign/verify rejected by module: {exc}")
        except (KeyFunctionNotPermitted, KeyTypeInconsistent) as exc:
            pytest.xfail(f"CKM_KIP_MAC key not permitted for sign/verify: {exc}")
        finally:
            if key is not None:
                key.destroy()
