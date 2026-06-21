"""Key-provisioning injection: get a setup object into the token by the best available means.

create -> (opt-in) unwrap -> skip. See docs/.../key-provisioning-injection-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from pkcs11_check.raw import sw_wrap
from pkcs11_check.raw.pack import PackedMechanism
from pkcs11_check.raw.pack_mechanisms import mech_oaep, mech_rsa_aes_key_wrap
from pkcs11_check.raw.types_std import (
    CKG_MGF1_SHA256,
    CKM_AES_KEY_WRAP_KWP,
    CKM_RSA_AES_KEY_WRAP,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256,
)


@dataclass(frozen=True)
class WrapContext:
    rsa_pub_der: bytes | None  # bootstrap/configured RSA unwrap key public part
    unwrapping_key_handle: int  # in-token handle used by C_UnwrapKey
    sym_kek: bytes | None = None  # symmetric KEK value (configured/readable), for AES-KWP
    aes_bits: int = 256


@runtime_checkable
class WrapStrategy(Protocol):
    name: str
    unwrap_mech: int

    def usable(self, profile: Any) -> bool: ...

    def max_target_size(self, ctx: WrapContext) -> int | None: ...  # None = unbounded

    def wrap(self, ctx: WrapContext, target: bytes) -> bytes: ...

    def unwrap_mech_param(self, ctx: WrapContext) -> PackedMechanism | None: ...


class RsaAesKeyWrap:
    name = "rsa_aes_key_wrap"
    unwrap_mech = int(CKM_RSA_AES_KEY_WRAP)

    def usable(self, profile: Any) -> bool:
        return bool(profile.supports_unwrap_mech(self.unwrap_mech))

    def max_target_size(self, ctx: WrapContext) -> int | None:
        return None  # AES-KWP layer carries any size

    def wrap(self, ctx: WrapContext, target: bytes) -> bytes:
        assert ctx.rsa_pub_der is not None
        return sw_wrap.rsa_aes_key_wrap_blob(ctx.rsa_pub_der, target, aes_bits=ctx.aes_bits)

    def unwrap_mech_param(self, ctx: WrapContext) -> PackedMechanism:
        return mech_rsa_aes_key_wrap(aes_bits=ctx.aes_bits)


class RsaOaep:
    name = "rsa_oaep"
    unwrap_mech = int(CKM_RSA_PKCS_OAEP)

    def usable(self, profile: Any) -> bool:
        return bool(profile.supports_unwrap_mech(self.unwrap_mech))

    def max_target_size(self, ctx: WrapContext) -> int | None:
        assert ctx.rsa_pub_der is not None
        return sw_wrap.oaep_max_payload(ctx.rsa_pub_der)

    def wrap(self, ctx: WrapContext, target: bytes) -> bytes:
        assert ctx.rsa_pub_der is not None
        return sw_wrap.rsa_oaep_wrap(ctx.rsa_pub_der, target)

    def unwrap_mech_param(self, ctx: WrapContext) -> PackedMechanism:
        return mech_oaep(CKM_RSA_PKCS_OAEP, hash_mech=int(CKM_SHA256), mgf=int(CKG_MGF1_SHA256))


class AesKwp:
    name = "aes_kwp"
    unwrap_mech = int(CKM_AES_KEY_WRAP_KWP)

    def usable(self, profile: Any) -> bool:
        return bool(profile.supports_unwrap_mech(self.unwrap_mech))

    def max_target_size(self, ctx: WrapContext) -> int | None:
        return None if ctx.sym_kek is not None else 0  # needs a symmetric KEK value

    def wrap(self, ctx: WrapContext, target: bytes) -> bytes:
        assert ctx.sym_kek is not None
        return sw_wrap.aes_kwp_wrap(ctx.sym_kek, target)

    def unwrap_mech_param(self, ctx: WrapContext) -> None:
        return None  # CKM_AES_KEY_WRAP_KWP takes no params


DEFAULT_STRATEGIES: tuple[WrapStrategy, ...] = (RsaAesKeyWrap(), RsaOaep(), AesKwp())


def select_strategy(
    strategies: tuple[WrapStrategy, ...], profile: Any, target_len: int
) -> WrapStrategy | None:
    """First strategy that is usable AND can carry ``target_len`` bytes; else None.

    Size check uses a sentinel WrapContext with the profile's bootstrap RSA size so OAEP's
    max-payload is honoured. The real ctx (Task 6) has the same rsa_pub_der size.
    """
    probe_ctx = WrapContext(
        rsa_pub_der=getattr(profile, "rsa_pub_der_probe", None),
        unwrapping_key_handle=0,
        sym_kek=b"\x00" * 32 if getattr(profile, "aes_kwp", False) else None,
    )
    for s in strategies:
        if not s.usable(profile):
            continue
        cap = s.max_target_size(probe_ctx)
        if cap is not None and target_len > cap:
            continue
        return s
    return None
