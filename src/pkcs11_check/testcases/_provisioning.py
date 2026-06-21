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
    CKK_RSA,
    CKM,
    CKM_AES_KEY_WRAP_KWP,
    CKM_RSA_AES_KEY_WRAP,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256,
    CKM_SHA_1,
    CKO_PRIVATE_KEY,
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
    rsa_unwrap_handle: int | None = None  # RSA private key handle for C_UnwrapKey
    aes_kek_handle: int | None = None  # AES KEK handle for C_UnwrapKey (AES-KWP path)
    sym_kek: bytes | None = None  # symmetric KEK value (readable AES key bytes)
    aes_bits: int = 256
    oaep_hash: str = "sha1"  # OAEP hash algorithm: "sha1" or "sha256"
    strategy_name: str | None = None  # resolved winning strategy name


@runtime_checkable
class WrapStrategy(Protocol):
    name: str
    unwrap_mech: int

    def usable(self, profile: Any) -> bool: ...

    def max_target_size(self, ctx: WrapContext) -> int | None: ...  # None = unbounded

    def wrap(self, ctx: WrapContext, target: bytes) -> bytes: ...

    def unwrap_mech_param(self, ctx: WrapContext) -> PackedMechanism | None: ...

    def unwrapping_key_handle(self, ctx: WrapContext) -> int | None: ...

    def has_material(self, ctx: WrapContext) -> bool: ...


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

    def unwrapping_key_handle(self, ctx: WrapContext) -> int | None:
        return ctx.rsa_unwrap_handle

    def has_material(self, ctx: WrapContext) -> bool:
        return ctx.rsa_pub_der is not None and ctx.rsa_unwrap_handle is not None


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

    def unwrapping_key_handle(self, ctx: WrapContext) -> int | None:
        return ctx.rsa_unwrap_handle

    def has_material(self, ctx: WrapContext) -> bool:
        return ctx.rsa_pub_der is not None and ctx.rsa_unwrap_handle is not None


class AesKwp:
    name = "aes_kwp"
    unwrap_mech: int = CKM_AES_KEY_WRAP_KWP

    def usable(self, profile: Any) -> bool:
        return bool(profile.supports_unwrap_mech(self.unwrap_mech))

    def max_target_size(self, ctx: WrapContext) -> int | None:
        return None if self.has_material(ctx) else 0  # needs a symmetric KEK value

    def wrap(self, ctx: WrapContext, target: bytes) -> bytes:
        assert ctx.sym_kek is not None
        return sw_wrap.aes_kwp_wrap(ctx.sym_kek, target)

    def unwrap_mech_param(self, ctx: WrapContext) -> None:
        return None  # CKM_AES_KEY_WRAP_KWP takes no params

    def unwrapping_key_handle(self, ctx: WrapContext) -> int | None:
        return ctx.aes_kek_handle

    def has_material(self, ctx: WrapContext) -> bool:
        return ctx.sym_kek is not None and ctx.aes_kek_handle is not None


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

# Probe template used by build_wrap_context for the trial round-trip unwrap.
_PROBE_ATTRS: dict[int, Any] = {
    CKA_CLASS: CKO_SECRET_KEY,
    CKA_KEY_TYPE: CKK_AES,
    CKA_TOKEN: False,
    CKA_SENSITIVE: False,
    CKA_EXTRACTABLE: True,
    CKA_ENCRYPT: True,
}


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
        """Probe EC P-256 private-key import; map outcome to a create verdict.

        Attempts to import a throwaway EC P-256 private key via C_CreateObject.
        Maps the outcome:
        - success → destroy the key and return ``"create_available"``
        - ``CKR_FUNCTION_NOT_SUPPORTED`` → ``"create_absent"``
        - rv in ``_CREATE_PROHIBITED_RVS`` → ``"create_prohibited"``
        - any other CKR → re-raise (real finding)

        The ``obj_class`` parameter is unused (only ``"private"`` reaches this
        method) but kept for API symmetry with the dispatch in ``create_verdict``.
        """
        from pkcs11_check.raw.recipes import destroy_quietly, import_ec_private_key

        # P-256 named-curve OID DER: 1.2.840.10045.3.1.7
        ec_p256_params = bytes.fromhex("06082a8648ce3d030107")
        # A valid P-256 private scalar (32 bytes, small but in-range)
        ec_p256_scalar = b"\x01" * 32

        try:
            h = import_ec_private_key(
                self.rs.raw,
                self.rs.sh,
                ec_params=ec_p256_params,
                value=ec_p256_scalar,
                attrs={
                    CKA_TOKEN: False,
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
    max-payload is honoured.  The real wrap context (built by ``build_wrap_context``) carries
    the actual key material; this function is a pre-flight utility for callers (e.g. Phase 2
    private-key provisioning) that need to know which strategy will be selected before
    committing to a full bootstrap.  ``provision_secret_key`` does NOT use this function;
    it resolves strategy through ``build_wrap_context``'s trial round-trip and stores the
    result in ``WrapContext.strategy_name``.
    """
    _aes_kwp_usable = AesKwp().usable(profile)
    probe_ctx = WrapContext(
        rsa_pub_der=getattr(profile, "rsa_pub_der_probe", None),
        rsa_unwrap_handle=None,
        # Sentinel: if AES-KWP is usable, set both sym_kek and aes_kek_handle so that
        # AesKwp.has_material() returns True and max_target_size() returns None (unbounded).
        # The actual key material is supplied by build_wrap_context; these are probe-only
        # placeholders and are never used to perform a real wrap operation here.
        sym_kek=b"\x00" * 32 if _aes_kwp_usable else None,
        aes_kek_handle=0 if _aes_kwp_usable else None,
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

#: CKRs that trigger RSA keygen size escalation (2048 → 3072 → 4096).
#:
#: ``CKR_KEY_SIZE_RANGE`` and ``CKR_ATTRIBUTE_VALUE_INVALID`` are the canonical
#: size-refusal codes.  ``CKR_TEMPLATE_INCONSISTENT`` and ``CKR_FUNCTION_FAILED``
#: are also included because some real HSM implementations return them for
#: unsupported key sizes (see docs/module-issues.md for per-module notes).
#: An unexpected keygen error not in this set is re-raised as a finding.
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


def build_wrap_context(rs: Any, cfg: Any) -> WrapContext | None:
    """Build a ``WrapContext`` by probing ALL usable strategies in DEFAULT_STRATEGIES order.

    For each strategy, bootstraps the required key material lazily (RSA keypair or AES KEK),
    then performs a trial round-trip (wrap + C_UnwrapKey with a 16-byte probe) to confirm
    the strategy + hash combo works end-to-end.  Returns the first winning ``WrapContext``
    (with ``strategy_name`` set), or ``None`` if every combo fails.

    RSA strategies try candidate hashes in order (sha256 preferred, sha1 fallback) when
    ``cfg.wrap_oaep_hash == "auto"``; an explicit hash is used as-is.  AES-KWP has no
    hash parameter.

    Sets ``profile_for(rs).rsa_pub_der_probe`` when RSA material is successfully
    bootstrapped so ``select_strategy`` can size-check OAEP payloads correctly.

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
    oaep_hash_cfg: str = getattr(cfg, "wrap_oaep_hash", "auto")

    # Material accumulated lazily across strategies
    rsa_pub_der: bytes | None = None
    rsa_unwrap_handle: int | None = None
    aes_kek_handle: int | None = None
    sym_kek: bytes | None = None

    # Track bootstrap attempts to avoid retrying a failing bootstrap
    rsa_bootstrapped = False
    aes_bootstrapped = False

    from pkcs11_check.raw.recipes import destroy_quietly, unwrap_key

    for strategy in DEFAULT_STRATEGIES:
        if not strategy.usable(profile_for(rs)):
            continue

        # ------------------------------------------------------------------
        # Lazy bootstrap for this strategy's required material
        # ------------------------------------------------------------------
        if strategy.name in ("rsa_aes_key_wrap", "rsa_oaep") and not rsa_bootstrapped:
            rsa_bootstrapped = True
            result = _bootstrap_rsa_unwrap_key(rs, start_bits)
            if result is not None:
                from pkcs11_check.raw.recipes import read_attributes

                pub_handle, priv_handle, _bits = result
                attrs = read_attributes(
                    rs.raw, rs.sh, pub_handle, (CKA_MODULUS, CKA_PUBLIC_EXPONENT)
                )
                n = int.from_bytes(attrs[CKA_MODULUS], "big")
                e = int.from_bytes(attrs[CKA_PUBLIC_EXPONENT], "big")
                pub_key = _crypto_rsa.RSAPublicNumbers(e, n).public_key()
                der = pub_key.public_bytes(_Encoding.DER, _PublicFormat.SubjectPublicKeyInfo)
                rsa_pub_der = der
                rsa_unwrap_handle = priv_handle
                profile_for(rs).rsa_pub_der_probe = der

        if strategy.name == "aes_kwp" and not aes_bootstrapped:
            aes_bootstrapped = True
            try:
                from pkcs11_check.raw.recipes import gen_aes_key, read_attributes

                kek_handle = gen_aes_key(
                    rs.raw,
                    rs.sh,
                    bits=256,
                    attrs={
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_WRAP: True,
                        CKA_UNWRAP: True,
                    },
                )
                try:
                    kek_attrs = read_attributes(rs.raw, rs.sh, kek_handle, (CKA_VALUE,))
                    kek_val = kek_attrs.get(CKA_VALUE)
                except CkrAssertionError:
                    kek_val = None
                if kek_val is not None:
                    aes_kek_handle = kek_handle
                    sym_kek = kek_val
                else:
                    destroy_quietly(rs.raw, rs.sh, kek_handle)  # readable-KEK path unavailable
            except CkrAssertionError:
                pass  # AES keygen not available → skip AES-KWP

        # Build a probe context with all material gathered so far
        probe_ctx = WrapContext(
            rsa_pub_der=rsa_pub_der,
            rsa_unwrap_handle=rsa_unwrap_handle,
            aes_kek_handle=aes_kek_handle,
            sym_kek=sym_kek,
            aes_bits=256,
            oaep_hash="sha1",  # placeholder; overridden per candidate below
            strategy_name=strategy.name,
        )

        if not strategy.has_material(probe_ctx):
            continue

        # ------------------------------------------------------------------
        # Determine hash candidates for this strategy
        # ------------------------------------------------------------------
        if strategy.name in ("rsa_aes_key_wrap", "rsa_oaep"):
            hash_candidates: tuple[str | None, ...] = (
                ("sha256", "sha1") if oaep_hash_cfg == "auto" else (oaep_hash_cfg,)
            )
        else:
            hash_candidates = (None,)

        # ------------------------------------------------------------------
        # Trial round-trip for each hash candidate
        # ------------------------------------------------------------------
        for cand in hash_candidates:
            trial_ctx = WrapContext(
                rsa_pub_der=rsa_pub_der,
                rsa_unwrap_handle=rsa_unwrap_handle,
                aes_kek_handle=aes_kek_handle,
                sym_kek=sym_kek,
                aes_bits=256,
                oaep_hash=cand if cand is not None else "sha1",
                strategy_name=strategy.name,
            )
            unwrap_handle = strategy.unwrapping_key_handle(trial_ctx)
            if unwrap_handle is None:
                continue  # material check passed but no handle (shouldn't happen)
            blob = strategy.wrap(trial_ctx, b"\x00" * 16)
            try:
                handle = unwrap_key(
                    rs.raw,
                    rs.sh,
                    unwrap_handle,
                    blob,
                    strategy.unwrap_mech,
                    attrs=_PROBE_ATTRS,
                    mech_param=strategy.unwrap_mech_param(trial_ctx),
                )
            except CkrAssertionError:
                continue
            destroy_quietly(rs.raw, rs.sh, handle)
            return trial_ctx

    return None


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
       - Build a ``WrapContext`` (bootstrap + multi-strategy negotiation);
         ``None`` → ``pytest.skip``.
       - Look up the resolved strategy by ``ctx.strategy_name``; not found → ``pytest.skip``.
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

    strategy = next((s for s in DEFAULT_STRATEGIES if s.name == ctx.strategy_name), None)
    if strategy is None:
        pytest.skip(f"{label}: no wrapping path: resolved strategy not found")

    cap = strategy.max_target_size(ctx)
    if cap is not None and len(value) > cap:
        pytest.skip(f"{label}: no wrapping path: no usable wrap mechanism for this target size")

    unwrap_handle = strategy.unwrapping_key_handle(ctx)
    if unwrap_handle is None:
        pytest.skip(f"{label}: no wrapping path: resolved strategy has no unwrap handle")
    blob = strategy.wrap(ctx, value)
    unwrap_template = {k: v for k, v in attrs.items() if k not in _VALUE_BEARING}
    # C_UnwrapKey requires the new key's class and type in the template; add them
    # if the caller didn't already supply them (setdefault is a no-op otherwise).
    unwrap_template.setdefault(CKA_CLASS, CKO_SECRET_KEY)
    unwrap_template.setdefault(CKA_KEY_TYPE, key_type)
    handle = unwrap_key(
        rs.raw,
        rs.sh,
        unwrap_handle,
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


# ---------------------------------------------------------------------------
# provision_rsa_private_key — resolution entry point (Task 3)
# ---------------------------------------------------------------------------


def provision_rsa_private_key(
    rs: Any,
    cfg: Any,
    *,
    n: bytes,
    e: bytes,
    d: bytes,
    p: bytes,
    q: bytes,
    dmp1: bytes,
    dmq1: bytes,
    iqmp: bytes,
    attrs: dict[Any, Any],
    label: str,
) -> int:
    """Provision an RSA private key into the token by the best available means.

    Resolution order (per design §3.2):

    1. If ``cfg.key_inject != "force-unwrap"``, probe create availability.
       When the module supports C_CreateObject for private keys, call
       ``import_rsa_private_key_negotiated`` directly and return the handle.

    2. If create is unavailable/prohibited OR ``cfg.key_inject == "force-unwrap"``:
       - ``key_inject == "off"`` → ``pytest.skip`` (no injection path).
       - Build a ``WrapContext`` (bootstrap + multi-strategy negotiation);
         ``None`` → ``pytest.skip``.
       - Look up the resolved strategy by ``ctx.strategy_name``; not found → ``pytest.skip``.
       - Encode the CRT components as PKCS#8 DER, check against strategy size cap.
       - Call ``unwrap_key`` with the encrypted PKCS#8 blob.
       - Record a compliance note (no value-integrity readback — private keys are sensitive).
       - Return the unwrapped key handle.

    Args:
        rs:     Session record with ``.raw``, ``.sh``, and ``has_mechanism``.
        cfg:    Config carrying ``key_inject``, ``wrap_rsa_bits``, etc.
        n:      RSA modulus (big-endian bytes).
        e:      Public exponent (big-endian bytes).
        d:      Private exponent (big-endian bytes).
        p:      First prime factor (big-endian bytes).
        q:      Second prime factor (big-endian bytes).
        dmp1:   d mod (p-1) (big-endian bytes).
        dmq1:   d mod (q-1) (big-endian bytes).
        iqmp:   q^{-1} mod p (big-endian bytes).
        attrs:  Usage-flag attributes for the resulting object (e.g.
                ``CKA_SIGN``, ``CKA_DECRYPT``, ``CKA_TOKEN``).  Must NOT
                include CRT component attributes; those come from the kwargs.
        label:  Human-readable label used in skip messages.

    Returns:
        Object handle (int) of the provisioned private key.

    Raises:
        pytest.skip.Exception: When the module has no injection path or the
            wrap-context / strategy is unavailable.
    """
    from pkcs11_check.raw.key_encoding import rsa_pkcs8_from_crt
    from pkcs11_check.raw.recipes import unwrap_key

    mode: str = getattr(cfg, "key_inject", "off")

    # ------------------------------------------------------------------
    # Fast path: create_available (unless caller forces the unwrap path)
    # ------------------------------------------------------------------
    if mode != "force-unwrap":
        verdict = profile_for(rs).create_verdict("private")
        if verdict == "create_available":
            from pkcs11_check.testcases.conftest import import_rsa_private_key_negotiated

            return import_rsa_private_key_negotiated(
                rs, n=n, e=e, d=d, p=p, q=q, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp, attrs=attrs
            )

    # ------------------------------------------------------------------
    # Unwrap path (or forced)
    # ------------------------------------------------------------------
    if mode == "off":
        pytest.skip(f"{label}: Module does not implement C_CreateObject")

    ctx = build_wrap_context(rs, cfg)
    if ctx is None:
        pytest.skip(f"{label}: no wrapping path")

    strategy = next((s for s in DEFAULT_STRATEGIES if s.name == ctx.strategy_name), None)
    if strategy is None:
        pytest.skip(f"{label}: no wrapping path: resolved strategy not found")

    pkcs8 = rsa_pkcs8_from_crt(n=n, e=e, d=d, p=p, q=q, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp)

    cap = strategy.max_target_size(ctx)
    if cap is not None and len(pkcs8) > cap:
        pytest.skip(f"{label}: no wrapping path: no usable wrap mechanism for this target size")

    unwrap_handle = strategy.unwrapping_key_handle(ctx)
    if unwrap_handle is None:
        pytest.skip(f"{label}: no wrapping path: resolved strategy has no unwrap handle")

    blob = strategy.wrap(ctx, pkcs8)
    unwrap_template: dict[Any, Any] = {CKA_CLASS: CKO_PRIVATE_KEY, CKA_KEY_TYPE: CKK_RSA}
    unwrap_template.update(attrs)

    handle = unwrap_key(
        rs.raw,
        rs.sh,
        unwrap_handle,
        blob,
        strategy.unwrap_mech,
        attrs=unwrap_template,
        mech_param=strategy.unwrap_mech_param(ctx),
    )

    from pkcs11_check.compliance import ComplianceLevel, note

    note(
        f"{label}: private key provisioned via C_UnwrapKey ({ctx.strategy_name})",
        ComplianceLevel.STANDARD,
    )
    return handle
