"""Key-provisioning injection: get a setup object into the token by the best available means.

create -> (opt-in) unwrap -> skip. See docs/.../key-provisioning-injection-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from pkcs11_check.raw import sw_wrap
from pkcs11_check.raw.pack import PackedMechanism
from pkcs11_check.raw.pack_mechanisms import mech_oaep, mech_rsa_aes_key_wrap
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKG_MGF1_SHA256,
    CKK_AES,
    CKM_AES_KEY_WRAP_KWP,
    CKM_RSA_AES_KEY_WRAP,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_UNEXTRACTABLE,
    CKR_TEMPLATE_INCONSISTENT,
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

# ---------------------------------------------------------------------------
# ProvisioningProfile — per-class create-availability probe
# ---------------------------------------------------------------------------

_PROFILE_CACHE: dict[int, ProvisioningProfile] = {}

_CREATE_PROHIBITED_RVS: frozenset[int] = frozenset(
    {
        CKR_TEMPLATE_INCONSISTENT,
        CKR_KEY_FUNCTION_NOT_PERMITTED,
        CKR_KEY_UNEXTRACTABLE,
        CKR_ATTRIBUTE_VALUE_INVALID,
    }
)


@dataclass
class ProvisioningProfile:
    """Per-session profile: caches per-class create verdicts + mechanism availability.

    Keyed by ``rs.sh`` (session handle) in ``_PROFILE_CACHE``.
    ``rsa_pub_der_probe`` is populated by Task 6; None here in Phase 1.
    """

    rs: Any
    rsa_pub_der_probe: bytes | None = None
    _verdicts: dict[str, str] = field(default_factory=dict)

    def supports_unwrap_mech(self, mech: int) -> bool:
        """True iff the RS advertises the named mechanism for ``mech``."""
        from pkcs11_check.raw.metadata_std import MECHANISM_NAMES

        name = MECHANISM_NAMES.get(int(mech))
        return bool(name) and self.rs.has_mechanism(name)

    def create_verdict(self, obj_class: str) -> str:
        """Return a cached verdict ∈ {create_available, create_absent, create_prohibited}."""
        if obj_class in self._verdicts:
            return self._verdicts[obj_class]
        v = self._probe_secret() if obj_class == "secret" else self._probe_private(obj_class)
        self._verdicts[obj_class] = v
        return v

    def _probe_secret(self) -> str:
        """Probe AES-128 import; map outcome to a create verdict."""
        from pkcs11_check.raw.recipes import destroy_quietly, import_secret_key

        try:
            h = import_secret_key(
                self.rs.raw,
                self.rs.sh,
                int(CKK_AES),
                b"\x00" * 16,
                attrs={
                    CKA_TOKEN: False,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                },
            )
        except CkrAssertionError as exc:
            if exc.rv == CKR_FUNCTION_NOT_SUPPORTED:
                return "create_absent"
            if exc.rv in _CREATE_PROHIBITED_RVS:
                return "create_prohibited"
            raise
        destroy_quietly(self.rs.raw, self.rs.sh, h)
        return "create_available"

    def _probe_private(self, obj_class: str) -> str:  # noqa: ARG002
        # Phase 2 wires real private-key probes; Phase 1 only needs "secret".
        return "create_available"


def profile_for(rs: Any) -> ProvisioningProfile:
    """Return (cached) ``ProvisioningProfile`` for the given session handle."""
    prof = _PROFILE_CACHE.get(rs.sh)
    if prof is None:
        prof = ProvisioningProfile(rs=rs)
        _PROFILE_CACHE[rs.sh] = prof
    return prof


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
