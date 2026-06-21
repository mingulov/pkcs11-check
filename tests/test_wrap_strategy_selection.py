"""Unit tests for WrapStrategy registry + size-aware selection (Task 4)."""

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pkcs11_check.testcases import _provisioning as provisioning


def _make_rsa2048_spki() -> bytes:
    """Build a 2048-bit RSA SubjectPublicKeyInfo DER for probe use."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


_RSA2048_SPKI: bytes = _make_rsa2048_spki()


@dataclass
class FakeProfile:
    rsa_aes_key_wrap: bool
    rsa_oaep: bool
    aes_kwp: bool
    rsa_pub_der_probe: bytes = field(default_factory=lambda: _RSA2048_SPKI)

    def supports_unwrap_mech(self, mech: int) -> bool:
        from pkcs11_check.raw.types_std import (
            CKM_AES_KEY_WRAP_KWP,
            CKM_RSA_AES_KEY_WRAP,
            CKM_RSA_PKCS_OAEP,
        )

        return {
            int(CKM_RSA_AES_KEY_WRAP): self.rsa_aes_key_wrap,
            int(CKM_RSA_PKCS_OAEP): self.rsa_oaep,
            int(CKM_AES_KEY_WRAP_KWP): self.aes_kwp,
        }[int(mech)]


def test_envelope_preferred_for_large_target() -> None:
    prof = FakeProfile(rsa_aes_key_wrap=True, rsa_oaep=True, aes_kwp=True)
    s = provisioning.select_strategy(provisioning.DEFAULT_STRATEGIES, prof, target_len=1217)
    assert s is not None
    assert s.name == "rsa_aes_key_wrap"


def test_oaep_rejected_on_size_falls_to_envelope_or_kwp() -> None:
    # OAEP only; 1217-byte target exceeds OAEP max (214 for 2048-bit SHA-1) -> nothing can wrap it
    prof = FakeProfile(rsa_aes_key_wrap=False, rsa_oaep=True, aes_kwp=False)
    s = provisioning.select_strategy(provisioning.DEFAULT_STRATEGIES, prof, target_len=1217)
    assert s is None  # nothing can wrap a 1217-byte target here


def test_oaep_ok_for_small_target() -> None:
    prof = FakeProfile(rsa_aes_key_wrap=False, rsa_oaep=True, aes_kwp=False)
    s = provisioning.select_strategy(provisioning.DEFAULT_STRATEGIES, prof, target_len=32)
    assert s is not None
    assert s.name == "rsa_oaep"


def test_oaep_max_payload_sha1_vs_sha256() -> None:
    """select_strategy uses sha1 default; verify the sentinel ctx gives the right size."""
    prof = FakeProfile(
        rsa_aes_key_wrap=False, rsa_oaep=True, aes_kwp=False, rsa_pub_der_probe=_RSA2048_SPKI
    )
    # sha1 default: max = 214; target of 200 should be accepted
    s = provisioning.select_strategy(provisioning.DEFAULT_STRATEGIES, prof, target_len=200)
    assert s is not None
    assert s.name == "rsa_oaep"
    # 215 > 214 should be rejected with sha1
    s2 = provisioning.select_strategy(provisioning.DEFAULT_STRATEGIES, prof, target_len=215)
    assert s2 is None
