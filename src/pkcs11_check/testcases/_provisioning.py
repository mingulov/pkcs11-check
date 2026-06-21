"""Key-provisioning injection: get a setup object into the token by the best available means.

create -> (opt-in) unwrap -> skip. See docs/.../key-provisioning-injection-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa as _crypto_rsa
from cryptography.hazmat.primitives.serialization import Encoding as _Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat as _PublicFormat

from pkcs11_check.raw import sw_wrap
from pkcs11_check.raw.pack import PackedMechanism
from pkcs11_check.raw.pack_mechanisms import mech_oaep, mech_rsa_aes_key_wrap
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_WRAP,
    CKG,
    CKG_MGF1_SHA1,
    CKG_MGF1_SHA256,
    CKK_AES,
    CKM,
    CKM_AES_KEY_WRAP_KWP,
    CKM_RSA_AES_KEY_WRAP,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256,
    CKM_SHA_1,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_UNEXTRACTABLE,
    CKR_TEMPLATE_INCONSISTENT,
)


@dataclass(frozen=True)
class WrapContext:
    rsa_pub_der: bytes | None  # bootstrap/configured RSA unwrap key public part
    unwrapping_key_handle: int  # in-token handle used by C_UnwrapKey
    sym_kek: bytes | None = None  # symmetric KEK value (configured/readable), for AES-KWP
    aes_bits: int = 256
    oaep_hash: str = "sha1"  # OAEP hash algorithm: "sha1" or "sha256"


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
    unwrap_mech: int = CKM_RSA_AES_KEY_WRAP

    def usable(self, profile: Any) -> bool:
        return bool(profile.supports_unwrap_mech(self.unwrap_mech))

    def max_target_size(self, ctx: WrapContext) -> int | None:
        return None  # AES-KWP layer carries any size

    def wrap(self, ctx: WrapContext, target: bytes) -> bytes:
        assert ctx.rsa_pub_der is not None
        return sw_wrap.rsa_aes_key_wrap_blob(
            ctx.rsa_pub_der, target, aes_bits=ctx.aes_bits, oaep_hash=ctx.oaep_hash
        )

    def unwrap_mech_param(self, ctx: WrapContext) -> PackedMechanism:
        return mech_rsa_aes_key_wrap(aes_bits=ctx.aes_bits, oaep_hash=ctx.oaep_hash)


class RsaOaep:
    name = "rsa_oaep"
    unwrap_mech: int = CKM_RSA_PKCS_OAEP

    def usable(self, profile: Any) -> bool:
        return bool(profile.supports_unwrap_mech(self.unwrap_mech))

    def max_target_size(self, ctx: WrapContext) -> int | None:
        assert ctx.rsa_pub_der is not None
        return sw_wrap.oaep_max_payload(ctx.rsa_pub_der, oaep_hash=ctx.oaep_hash)

    def wrap(self, ctx: WrapContext, target: bytes) -> bytes:
        assert ctx.rsa_pub_der is not None
        return sw_wrap.rsa_oaep_wrap(ctx.rsa_pub_der, target, oaep_hash=ctx.oaep_hash)

    def unwrap_mech_param(self, ctx: WrapContext) -> PackedMechanism:
        if ctx.oaep_hash == "sha1":
            h_mech: CKM | int = CKM_SHA_1
            h_mgf: CKG | int = CKG_MGF1_SHA1
        else:
            h_mech = CKM_SHA256
            h_mgf = CKG_MGF1_SHA256
        return mech_oaep(CKM_RSA_PKCS_OAEP, hash_mech=h_mech, mgf=h_mgf)


class AesKwp:
    name = "aes_kwp"
    unwrap_mech: int = CKM_AES_KEY_WRAP_KWP

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
                CKK_AES,
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
        oaep_hash="sha1",
    )
    for s in strategies:
        if not s.usable(profile):
            continue
        cap = s.max_target_size(probe_ctx)
        if cap is not None and target_len > cap:
            continue
        return s
    return None


# ---------------------------------------------------------------------------
# Bootstrap RSA unwrap key with size escalation (Task 6)
# ---------------------------------------------------------------------------

_RSA_SIZE_REFUSED: frozenset[int] = frozenset(
    {
        CKR_KEY_SIZE_RANGE,
        CKR_ATTRIBUTE_VALUE_INVALID,
        CKR_TEMPLATE_INCONSISTENT,
        CKR_FUNCTION_FAILED,
    }
)


def _bootstrap_rsa_unwrap_key(rs: Any, start_bits: int) -> tuple[int, int, int] | None:
    """Generate an RSA wrap/unwrap keypair, escalating size if the provider refuses.

    Returns ``(pub_handle, priv_handle, bits)`` on success or ``None`` if every
    candidate size is refused by the provider.  An unexpected keygen CKR (not a
    size-refusal code) is re-raised immediately so it surfaces as a finding.
    """
    from pkcs11_check.raw.recipes import gen_rsa_keypair

    sizes = [b for b in (start_bits, 3072, 4096) if b >= start_bits]
    seen: set[int] = set()
    for bits in sizes:
        if bits in seen:
            continue
        seen.add(bits)
        try:
            pub, priv = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                bits=bits,
                public_attrs={CKA_TOKEN: False, CKA_WRAP: True},
                private_attrs={CKA_TOKEN: False, CKA_UNWRAP: True},
            )
            return pub, priv, bits
        except CkrAssertionError as exc:
            if exc.rv in _RSA_SIZE_REFUSED:
                continue  # try a larger size
            raise  # an unexpected keygen error is a real finding
    return None


def _negotiate_oaep_hash(
    rs: Any,
    strategy: WrapStrategy,
    rsa_pub_der: bytes,
    unwrapping_key_handle: int,
    aes_bits: int,
) -> str | None:
    """Probe the module to find the best supported OAEP hash for wrapping.

    Tries candidates in order (sha256 first, sha1 second).  For each, wraps a
    16-byte probe value and attempts C_UnwrapKey with a minimal AES secret-key
    template.  Returns the first candidate that succeeds, or ``None`` if every
    candidate fails.

    The throwaway unwrapped key is destroyed quietly on success.
    """
    from pkcs11_check.raw.recipes import destroy_quietly, unwrap_key

    probe = b"\x00" * 16
    probe_attrs = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_AES,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_ENCRYPT: True,
    }
    for cand in ("sha256", "sha1"):
        ctx = WrapContext(
            rsa_pub_der=rsa_pub_der,
            unwrapping_key_handle=unwrapping_key_handle,
            aes_bits=aes_bits,
            oaep_hash=cand,
        )
        blob = strategy.wrap(ctx, probe)
        try:
            handle = unwrap_key(
                rs.raw,
                rs.sh,
                unwrapping_key_handle,
                blob,
                strategy.unwrap_mech,
                attrs=probe_attrs,
                mech_param=strategy.unwrap_mech_param(ctx),
            )
        except CkrAssertionError:
            continue
        destroy_quietly(rs.raw, rs.sh, handle)
        return cand
    return None


def build_wrap_context(rs: Any, cfg: Any) -> WrapContext | None:
    """Build a ``WrapContext`` for the bootstrap path.

    Generates a session RSA wrap keypair (escalating size if the provider refuses
    smaller keys), reads the public modulus and exponent, assembles an SPKI DER blob
    via ``cryptography``, and returns a ``WrapContext``.  Returns ``None`` when every
    candidate size is refused (→ caller should skip the unwrap path).

    Sets ``profile_for(rs).rsa_pub_der_probe`` so ``select_strategy`` can size-check
    OAEP payloads correctly before the real ``WrapContext`` is passed.

    When ``cfg.wrap_oaep_hash == "auto"`` (the default), probes the module by
    attempting a round-trip with each candidate hash (sha256 preferred, sha1
    fallback).  Returns ``None`` when no OAEP hash succeeds in auto mode.

    The ``configured`` wrap-key-source path is not yet implemented; a
    ``NotImplementedError`` is raised for that branch.
    """
    wrap_key_source: str = getattr(cfg, "wrap_key_source", "bootstrap")
    if wrap_key_source != "bootstrap":
        raise NotImplementedError(
            f"wrap_key_source={wrap_key_source!r} is not yet implemented; "
            "only 'bootstrap' is supported in Phase 1"
        )

    start_bits: int = getattr(cfg, "wrap_rsa_bits", 2048)
    result = _bootstrap_rsa_unwrap_key(rs, start_bits)
    if result is None:
        return None

    pub_handle, priv_handle, _bits = result

    from pkcs11_check.raw.recipes import read_attributes

    attrs = read_attributes(rs.raw, rs.sh, pub_handle, (CKA_MODULUS, CKA_PUBLIC_EXPONENT))
    n = int.from_bytes(attrs[CKA_MODULUS], "big")
    e = int.from_bytes(attrs[CKA_PUBLIC_EXPONENT], "big")
    pub_key = _crypto_rsa.RSAPublicNumbers(e, n).public_key()
    der = pub_key.public_bytes(_Encoding.DER, _PublicFormat.SubjectPublicKeyInfo)

    profile_for(rs).rsa_pub_der_probe = der

    oaep_hash_cfg: str = getattr(cfg, "wrap_oaep_hash", "auto")
    if oaep_hash_cfg == "auto":
        strategy = select_strategy(DEFAULT_STRATEGIES, profile_for(rs), 16)
        if strategy is None:
            return None
        oaep_hash = _negotiate_oaep_hash(rs, strategy, der, priv_handle, 256)
        if oaep_hash is None:
            return None
    else:
        oaep_hash = oaep_hash_cfg

    return WrapContext(rsa_pub_der=der, unwrapping_key_handle=priv_handle, oaep_hash=oaep_hash)


# ---------------------------------------------------------------------------
# provision_secret_key — resolution entry point (Task 7)
# ---------------------------------------------------------------------------

#: Attribute keys that carry the secret material; must be stripped from the
#: unwrap template so the value comes from the encrypted blob, not the template.
_VALUE_BEARING: frozenset[int] = frozenset({CKA_VALUE, CKA_VALUE_LEN})


def provision_secret_key(
    rs: Any,
    cfg: Any,
    key_type: int,
    value: bytes,
    attrs: dict[Any, Any],
    *,
    label: str,
) -> int:
    """Provision a secret key into the token by the best available means.

    Resolution order (per design §3.2):

    1. If ``cfg.key_inject != "force-unwrap"``, probe create availability.
       When the module supports C_CreateObject for secrets, call
       ``import_secret_key`` directly and return the handle.

    2. If create is unavailable/prohibited OR ``cfg.key_inject == "force-unwrap"``:
       - ``key_inject == "off"`` → ``pytest.skip`` (no injection path).
       - Build a ``WrapContext`` (bootstrap RSA keypair); ``None`` → ``pytest.skip``.
       - ``select_strategy`` for the target size; ``None`` → ``pytest.skip``.
       - Encrypt the value into a blob, call ``unwrap_key`` with the blob.
       - Value-integrity: when the key is non-sensitive, read back ``CKA_VALUE``
         and assert it equals ``value``; mismatch → ``pytest.skip`` (corrupted
         setup, not a target-operation finding).
       - Return the unwrapped key handle.

    Args:
        rs:       Session record with ``.raw``, ``.sh``, and ``has_mechanism``.
        cfg:      Config carrying ``key_inject``, ``wrap_rsa_bits``, etc.
        key_type: ``CKK_*`` int (bare constant, not wrapped in ``int()``).
        value:    Raw key bytes to inject.
        attrs:    Template attributes for the resulting object.  Must not
                  include ``CKA_VALUE`` / ``CKA_VALUE_LEN`` for the unwrap
                  path (they are stripped automatically).
        label:    Human-readable label used in skip messages.

    Returns:
        Object handle (int) of the provisioned key.

    Raises:
        pytest.skip.Exception: When the module has no injection path or the
            wrap-context / strategy is unavailable.
    """
    from pkcs11_check.raw.recipes import import_secret_key, read_attributes, unwrap_key

    mode: str = getattr(cfg, "key_inject", "off")

    # ------------------------------------------------------------------
    # Fast path: create_available (unless caller forces the unwrap path)
    # ------------------------------------------------------------------
    if mode != "force-unwrap":
        verdict = profile_for(rs).create_verdict("secret")
        if verdict == "create_available":
            return import_secret_key(rs.raw, rs.sh, key_type, value, attrs)

    # ------------------------------------------------------------------
    # Unwrap path (or forced)
    # ------------------------------------------------------------------
    if mode == "off":
        pytest.skip(f"{label}: Module does not implement C_CreateObject")

    ctx = build_wrap_context(rs, cfg)
    if ctx is None:
        pytest.skip(f"{label}: no wrapping path")

    strategy = select_strategy(DEFAULT_STRATEGIES, profile_for(rs), len(value))
    if strategy is None:
        pytest.skip(f"{label}: no wrapping path: no usable wrap mechanism for this target size")

    blob = strategy.wrap(ctx, value)
    unwrap_template = {k: v for k, v in attrs.items() if k not in _VALUE_BEARING}
    # C_UnwrapKey requires the new key's class and type in the template; add them
    # if the caller didn't already supply them (setdefault is a no-op otherwise).
    unwrap_template.setdefault(CKA_CLASS, CKO_SECRET_KEY)
    unwrap_template.setdefault(CKA_KEY_TYPE, key_type)
    handle = unwrap_key(
        rs.raw,
        rs.sh,
        ctx.unwrapping_key_handle,
        blob,
        strategy.unwrap_mech,
        attrs=unwrap_template,
        mech_param=strategy.unwrap_mech_param(ctx),
    )

    # Value-integrity readback for non-sensitive keys
    is_sensitive = attrs.get(CKA_SENSITIVE)
    if not is_sensitive:
        read_back = read_attributes(rs.raw, rs.sh, handle, (CKA_VALUE,))
        actual = read_back.get(CKA_VALUE)
        if actual != value:
            pytest.skip(
                f"{label}: provisioned key value mismatch "
                f"(expected {value.hex()!r}, got {actual!r})"
            )

    return handle
