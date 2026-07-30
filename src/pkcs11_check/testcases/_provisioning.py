"""Key-provisioning injection: get a setup object into the token by the best available means.

create -> (opt-in) unwrap -> skip. See docs/.../key-provisioning-injection-design.md.
"""

from __future__ import annotations

import shlex
import sys
from collections.abc import Mapping
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
    CKA_CERTIFICATE_TYPE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_EC_PARAMS,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SUBJECT,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_WRAP,
    CKC_X_509,
    CKG,
    CKG_MGF1_SHA1,
    CKG_MGF1_SHA256,
    CKK_AES,
    CKK_EC,
    CKK_RSA,
    CKM,
    CKM_AES_KEY_WRAP_KWP,
    CKM_RSA_AES_KEY_WRAP,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256,
    CKM_SHA_1,
    CKO_CERTIFICATE,
    CKO_DATA,
    CKO_PRIVATE_KEY,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_UNEXTRACTABLE,
    CKR_TEMPLATE_INCONSISTENT,
)


def _split_provision_cmd(cmd_str: str) -> list[str]:
    """Split an external-provision command line. POSIX shells use POSIX quoting;
    on Windows, backslash path separators must not be treated as escapes."""
    return shlex.split(cmd_str, posix=(sys.platform != "win32"))


@dataclass(frozen=True)
class ProvisioningEvent:
    obj_class: str  # "secret" | "private" | "public" | "cert" | "data"
    method: str  # "ran_via_create" | "ran_via_unwrap" | "ran_via_external" | "skipped_no_path"


_provisioning_events: list[ProvisioningEvent] = []


def record_provisioning_event(obj_class: str, method: str) -> None:
    """Append a ProvisioningEvent; best-effort — never raises (observability never breaks tests)."""
    try:
        _provisioning_events.append(ProvisioningEvent(obj_class, method))
    except Exception:  # noqa: BLE001
        return  # observability must never break a test; swallow silently


def get_provisioning_events() -> list[ProvisioningEvent]:
    """Return a copy of the current event list."""
    return list(_provisioning_events)


def clear_provisioning_events() -> None:
    """Clear all accumulated provisioning events."""
    _provisioning_events.clear()


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

#: Per-session cache of the built ``WrapContext`` (keyed by ``rs.sh``), mirroring
#: ``_PROFILE_CACHE``.  ``build_wrap_context`` bootstraps key material (RSA/AES keygen +
#: trial round-trips), so it MUST run once per session and be reused — rebuilding it on
#: every provision leaks the bootstrap objects (observed as ``CKR_HOST_MEMORY`` on
#: resource-limited modules) and runs a keygen per KAT vector.  A
#: legitimate ``None`` (no wrapping path) is cached via ``_WRAP_CONTEXT_COMPUTED`` so it
#: is not re-probed on every provision.
_WRAP_CONTEXT_CACHE: dict[int, WrapContext | None] = {}
_WRAP_CONTEXT_COMPUTED: set[int] = set()

_CREATE_PROHIBITED_RVS: frozenset[int] = frozenset(
    {
        CKR_TEMPLATE_INCONSISTENT,
        CKR_KEY_FUNCTION_NOT_PERMITTED,
        CKR_KEY_UNEXTRACTABLE,
        CKR_ATTRIBUTE_VALUE_INVALID,
        # Safety net: if even the storage-shape-negotiated template (which already drops the
        # benign policy attrs CKA_SENSITIVE/CKA_EXTRACTABLE) is still rejected read-only, the
        # module prohibits this create shape — route to unwrap/external/skip rather than
        # hard-failing. Some modules instead accept the dropped variant (so they never reach
        # here); this only catches modules that forbid the minimal shape outright.
        CKR_ATTRIBUTE_READ_ONLY,
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
        if obj_class == "secret":
            v = self._probe_secret()
        elif obj_class == "private":
            v = self._probe_private(obj_class)
        elif obj_class == "public":
            v = self._probe_public()
        elif obj_class == "cert":
            v = self._probe_cert()
        elif obj_class == "data":
            v = self._probe_data()
        else:
            v = self._probe_private(obj_class)
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

        The probe imports the throwaway key through the SAME storage-shape negotiation the
        real KAT import uses (``_storage_variants`` + ``negotiate_request``), so its verdict
        matches what ``import_ec_private_key_negotiated`` can actually achieve. A module that
        rejects the canonical policy attrs on create (e.g. returning
        CKR_ATTRIBUTE_READ_ONLY for CKA_EXTRACTABLE=true / CKA_SENSITIVE=false) but accepts
        the dropped-policy variant probes as ``create_available`` — the throwaway object's
        policy shape is irrelevant (it is destroyed immediately). The probe and the KAT EC
        key share an ``_import_shape_key``, so this also warms ``_IMPORT_SHAPE_WINNERS``.
        ``negotiate_request`` re-raises the final CKR on exhaustion (it does NOT skip), so the
        verdict classification below stays intact for no-create / prohibited modules.
        """
        from pkcs11_check.raw.recipes import create_object, destroy_quietly
        from pkcs11_check.testcases._negotiation import negotiate_request
        from pkcs11_check.testcases.conftest import (
            IMPORT_STORAGE_SHAPE_REJECTS,
            _storage_variants,
        )

        # P-256 named-curve OID DER: 1.2.840.10045.3.1.7
        ec_p256_params = bytes.fromhex("06082a8648ce3d030107")
        # A valid P-256 private scalar (32 bytes, small but in-range)
        ec_p256_scalar = b"\x01" * 32
        base: dict[int, Any] = {
            CKA_CLASS: CKO_PRIVATE_KEY,
            CKA_KEY_TYPE: int(CKK_EC),
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_EC_PARAMS: ec_p256_params,
            CKA_VALUE: ec_p256_scalar,
        }

        def attempt(delta: Mapping[int, Any]) -> int:
            return create_object(self.rs.raw, self.rs.sh, dict(delta))

        try:
            h, _idx = negotiate_request(
                attempt,
                _storage_variants(base),
                label="private create probe",
                shape_rejects=IMPORT_STORAGE_SHAPE_REJECTS,
            )
        except CkrAssertionError as exc:
            if exc.rv == CKR_FUNCTION_NOT_SUPPORTED:
                return "create_absent"
            if exc.rv in _CREATE_PROHIBITED_RVS:
                return "create_prohibited"
            raise
        destroy_quietly(self.rs.raw, self.rs.sh, h)
        return "create_available"

    def _probe_public(self) -> str:
        """Probe EC P-256 public-key import; map outcome to a create verdict.

        Generates a throwaway P-256 key pair in software and imports only the
        public key via ``import_ec_public_key`` (C_CreateObject).  Maps the
        outcome:
        - success → destroy the key and return ``"create_available"``
        - ``CKR_FUNCTION_NOT_SUPPORTED`` → ``"create_absent"``
        - rv in ``_CREATE_PROHIBITED_RVS`` → ``"create_prohibited"``
        - any other CKR → re-raise (real finding)
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        from pkcs11_check.raw.recipes import destroy_quietly, import_ec_public_key

        pub = ec.generate_private_key(ec.SECP256R1()).public_key()
        raw_point = pub.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        # DER OCTET STRING wrapper: tag 0x04, length, value
        ec_point = bytes([0x04, len(raw_point)]) + raw_point
        ec_params = bytes.fromhex("06082a8648ce3d030107")  # P-256 named-curve OID

        try:
            h = import_ec_public_key(
                self.rs.raw,
                self.rs.sh,
                ec_params=ec_params,
                ec_point=ec_point,
            )
        except CkrAssertionError as exc:
            if exc.rv == CKR_FUNCTION_NOT_SUPPORTED:
                return "create_absent"
            if exc.rv in _CREATE_PROHIBITED_RVS:
                return "create_prohibited"
            raise
        destroy_quietly(self.rs.raw, self.rs.sh, h)
        return "create_available"

    def _probe_cert(self) -> str:
        """Probe X.509 certificate import; map outcome to a create verdict.

        Builds a minimal self-signed DER certificate in software and creates
        it as a ``CKO_CERTIFICATE`` via ``create_object`` (C_CreateObject).
        Maps the outcome:
        - success → destroy the object and return ``"create_available"``
        - ``CKR_FUNCTION_NOT_SUPPORTED`` → ``"create_absent"``
        - rv in ``_CREATE_PROHIBITED_RVS`` → ``"create_prohibited"``
        - any other CKR → re-raise (real finding)
        """
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        from pkcs11_check.raw.recipes import create_object, destroy_quietly

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "prov-probe")])
        nb = datetime.datetime(2020, 1, 1)
        na = datetime.datetime(2030, 1, 1)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(nb)
            .not_valid_after(na)
            .sign(key, hashes.SHA256())
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        subject_der = name.public_bytes()

        try:
            h = create_object(
                self.rs.raw,
                self.rs.sh,
                {
                    CKA_CLASS: CKO_CERTIFICATE,
                    CKA_CERTIFICATE_TYPE: CKC_X_509,
                    CKA_VALUE: der,
                    CKA_SUBJECT: subject_der,
                    CKA_ID: b"\x01",
                    CKA_TOKEN: False,
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

    def _probe_data(self) -> str:
        """Probe CKO_DATA object creation; map outcome to a create verdict.

        Creates a minimal ``CKO_DATA`` object via ``create_object``
        (C_CreateObject).  Maps the outcome:
        - success → destroy the object and return ``"create_available"``
        - ``CKR_FUNCTION_NOT_SUPPORTED`` → ``"create_absent"``
        - rv in ``_CREATE_PROHIBITED_RVS`` → ``"create_prohibited"``
        - any other CKR → re-raise (real finding)
        """
        from pkcs11_check.raw.recipes import create_object, destroy_quietly

        try:
            h = create_object(
                self.rs.raw,
                self.rs.sh,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: b"prov-probe",
                    CKA_VALUE: b"\x00",
                    CKA_TOKEN: False,
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


def wrap_context_for(rs: Any, cfg: Any) -> WrapContext | None:
    """Return the (cached) ``WrapContext`` for this session, building it at most once.

    ``build_wrap_context`` bootstraps key material and runs trial round-trips; it MUST be
    built once per session and reused.  A legitimate ``None`` result (no wrapping path) is
    cached too, so a no-path module is not re-probed on every provision.  Keyed by ``rs.sh``
    like ``profile_for`` (per-file subprocess isolation keeps the handle stable within a run).
    """
    sh = rs.sh
    if sh not in _WRAP_CONTEXT_COMPUTED:
        _WRAP_CONTEXT_CACHE[sh] = build_wrap_context(rs, cfg)
        _WRAP_CONTEXT_COMPUTED.add(sh)
    return _WRAP_CONTEXT_CACHE[sh]


def skip_unless_can_create(rs: Any, obj_class: str) -> None:
    """Skip cleanly when the module cannot create *obj_class* objects via C_CreateObject.

    Uses the valid-material per-class create probe (more robust than an empty-template
    probe).  ``create_available`` returns (the caller creates normally and any failure
    surfaces as a real finding); ``create_absent``/``create_prohibited`` skip.
    """
    verdict = profile_for(rs).create_verdict(obj_class)
    if verdict in ("create_absent", "create_prohibited"):
        record_provisioning_event(obj_class, "skipped_no_path")
        pytest.skip(f"Module does not support C_CreateObject for {obj_class} objects ({verdict})")


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
#: unsupported key sizes.
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
            record_provisioning_event("secret", "ran_via_create")
            return import_secret_key(rs.raw, rs.sh, key_type, value, attrs)

    # ------------------------------------------------------------------
    # Unwrap path (or forced)
    # ------------------------------------------------------------------
    if mode == "off":
        return _external_or_skip(
            rs,
            cfg,
            material=value,
            label=label,
            key_type=key_type,
            obj_class="secret",
            skip_msg=f"{label}: Module does not implement C_CreateObject",
        )

    ctx = wrap_context_for(rs, cfg)
    if ctx is None:
        return _external_or_skip(
            rs,
            cfg,
            material=value,
            label=label,
            key_type=key_type,
            obj_class="secret",
            skip_msg=f"{label}: no wrapping path",
        )

    strategy = next((s for s in DEFAULT_STRATEGIES if s.name == ctx.strategy_name), None)
    if strategy is None:
        return _external_or_skip(
            rs,
            cfg,
            material=value,
            label=label,
            key_type=key_type,
            obj_class="secret",
            skip_msg=f"{label}: no wrapping path: resolved strategy not found",
        )

    cap = strategy.max_target_size(ctx)
    if cap is not None and len(value) > cap:
        return _external_or_skip(
            rs,
            cfg,
            material=value,
            label=label,
            key_type=key_type,
            obj_class="secret",
            skip_msg=f"{label}: no wrapping path: no usable wrap mechanism for this target size",
        )

    unwrap_handle = strategy.unwrapping_key_handle(ctx)
    if unwrap_handle is None:
        return _external_or_skip(
            rs,
            cfg,
            material=value,
            label=label,
            key_type=key_type,
            obj_class="secret",
            skip_msg=f"{label}: no wrapping path: resolved strategy has no unwrap handle",
        )
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
        if actual is not None and actual != value:
            record_provisioning_event("secret", "skipped_no_path")
            pytest.skip(
                f"{label}: provisioned key value mismatch "
                f"(expected {value.hex()!r}, got {actual!r})"
            )
        if actual is None:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                f"{label}: unwrapped key value not exposed (CKA_VALUE unreadable); "
                "trusting wrap/unwrap roundtrip",
                ComplianceLevel.STANDARD,
            )

    record_provisioning_event("secret", "ran_via_unwrap")
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

            record_provisioning_event("private", "ran_via_create")
            return import_rsa_private_key_negotiated(
                rs, n=n, e=e, d=d, p=p, q=q, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp, attrs=attrs
            )

    # ------------------------------------------------------------------
    # Unwrap path (or forced)
    # ------------------------------------------------------------------
    # Compute PKCS#8 DER once here so it is available for all external-tier fallbacks below.
    pkcs8 = rsa_pkcs8_from_crt(n=n, e=e, d=d, p=p, q=q, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp)

    if mode == "off":
        return _external_or_skip(
            rs,
            cfg,
            material=pkcs8,
            label=label,
            key_type=CKK_RSA,
            obj_class="private",
            skip_msg=f"{label}: Module does not implement C_CreateObject",
        )

    ctx = wrap_context_for(rs, cfg)
    if ctx is None:
        return _external_or_skip(
            rs,
            cfg,
            material=pkcs8,
            label=label,
            key_type=CKK_RSA,
            obj_class="private",
            skip_msg=f"{label}: no wrapping path",
        )

    strategy = next((s for s in DEFAULT_STRATEGIES if s.name == ctx.strategy_name), None)
    if strategy is None:
        return _external_or_skip(
            rs,
            cfg,
            material=pkcs8,
            label=label,
            key_type=CKK_RSA,
            obj_class="private",
            skip_msg=f"{label}: no wrapping path: resolved strategy not found",
        )

    cap = strategy.max_target_size(ctx)
    if cap is not None and len(pkcs8) > cap:
        return _external_or_skip(
            rs,
            cfg,
            material=pkcs8,
            label=label,
            key_type=CKK_RSA,
            obj_class="private",
            skip_msg=f"{label}: no wrapping path: no usable wrap mechanism for this target size",
        )

    unwrap_handle = strategy.unwrapping_key_handle(ctx)
    if unwrap_handle is None:
        return _external_or_skip(
            rs,
            cfg,
            material=pkcs8,
            label=label,
            key_type=CKK_RSA,
            obj_class="private",
            skip_msg=f"{label}: no wrapping path: resolved strategy has no unwrap handle",
        )

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
    record_provisioning_event("private", "ran_via_unwrap")
    return handle


# ---------------------------------------------------------------------------
# provision_ec_private_key — resolution entry point (Task 4)
# ---------------------------------------------------------------------------

#: Attributes that MUST be stripped from the EC unwrap template.
#: ``CKA_EC_PARAMS`` is READ_ONLY on C_UnwrapKey (derived from the PKCS#8 payload;
#: some modules return CKR_ATTRIBUTE_READ_ONLY if supplied).
#: ``CKA_VALUE`` comes from the encrypted blob, not the template.
_EC_UNWRAP_STRIP: frozenset[int] = frozenset({CKA_EC_PARAMS, CKA_VALUE})


def provision_ec_private_key(
    rs: Any,
    cfg: Any,
    *,
    ec_params: bytes,
    value: bytes,
    key_type: int,
    attrs: dict[Any, Any],
    label: str,
) -> int:
    """Provision an EC/Edwards/Montgomery private key into the token by the best available means.

    Resolution order (per design §3.2):

    1. If ``cfg.key_inject != "force-unwrap"``, probe create availability.
       When the module supports C_CreateObject for private keys, call
       ``import_ec_private_key_negotiated`` directly and return the handle.

    2. If create is unavailable/prohibited OR ``cfg.key_inject == "force-unwrap"``:
       - ``key_inject == "off"`` → ``pytest.skip`` (no injection path).
       - Build a ``WrapContext`` (bootstrap + multi-strategy negotiation);
         ``None`` → ``pytest.skip``.
       - Look up the resolved strategy by ``ctx.strategy_name``; not found → ``pytest.skip``.
       - Encode the scalar as a PKCS#8 DER blob; ``ValueError`` (unsupported curve/type)
         → ``pytest.skip`` (clean; not a finding).
       - Check against strategy size cap; call ``unwrap_key`` with the encrypted blob.
       - Template: ``{CKA_CLASS: CKO_PRIVATE_KEY, CKA_KEY_TYPE: key_type}`` plus caller
         ``attrs`` with ``CKA_EC_PARAMS`` and ``CKA_VALUE`` stripped.
       - Record a compliance note (no value-integrity readback — private keys are sensitive).
       - Return the unwrapped key handle.

    Args:
        rs:        Session record with ``.raw``, ``.sh``, and ``has_mechanism``.
        cfg:       Config carrying ``key_inject``, ``wrap_rsa_bits``, etc.
        ec_params: DER-encoded curve OID (for CKK_EC) or ignored bytes (Edwards/Montgomery).
        value:     Raw private scalar bytes.
        key_type:  ``CKK_EC``, ``CKK_EC_EDWARDS``, or ``CKK_EC_MONTGOMERY`` bare constant.
        attrs:     Usage-flag attributes for the resulting object.  ``CKA_EC_PARAMS`` and
                   ``CKA_VALUE`` are stripped defensively if present.
        label:     Human-readable label used in skip messages.

    Returns:
        Object handle (int) of the provisioned private key.

    Raises:
        pytest.skip.Exception: When the module has no injection path, the wrap-context /
            strategy is unavailable, or ``ec_pkcs8_from_private`` raises ``ValueError``
            on the unwrap path.
    """
    from pkcs11_check.raw.recipes import unwrap_key

    mode: str = getattr(cfg, "key_inject", "off")

    # ------------------------------------------------------------------
    # Fast path: create_available (unless caller forces the unwrap path)
    # ------------------------------------------------------------------
    if mode != "force-unwrap":
        verdict = profile_for(rs).create_verdict("private")
        if verdict == "create_available":
            from pkcs11_check.testcases.conftest import import_ec_private_key_negotiated

            record_provisioning_event("private", "ran_via_create")
            return import_ec_private_key_negotiated(
                rs, ec_params=ec_params, value=value, key_type=key_type, attrs=attrs
            )

    # ------------------------------------------------------------------
    # Unwrap path (or forced)
    # ------------------------------------------------------------------
    # Compute PKCS#8 DER once so it is available for all external-tier fallbacks below.
    # If encoding fails, external cannot receive material for this key type → skip early.
    try:
        from pkcs11_check.raw.key_encoding import ec_pkcs8_from_private

        pkcs8: bytes = ec_pkcs8_from_private(scalar=value, ec_params=ec_params, key_type=key_type)
    except ValueError:
        record_provisioning_event("private", "skipped_no_path")
        pytest.skip(f"{label}: no PKCS#8 encoding for this key type")

    if mode == "off":
        return _external_or_skip(
            rs,
            cfg,
            material=pkcs8,
            label=label,
            key_type=key_type,
            obj_class="private",
            skip_msg=f"{label}: Module does not implement C_CreateObject",
        )

    ctx = wrap_context_for(rs, cfg)
    if ctx is None:
        return _external_or_skip(
            rs,
            cfg,
            material=pkcs8,
            label=label,
            key_type=key_type,
            obj_class="private",
            skip_msg=f"{label}: no wrapping path",
        )

    strategy = next((s for s in DEFAULT_STRATEGIES if s.name == ctx.strategy_name), None)
    if strategy is None:
        return _external_or_skip(
            rs,
            cfg,
            material=pkcs8,
            label=label,
            key_type=key_type,
            obj_class="private",
            skip_msg=f"{label}: no wrapping path: resolved strategy not found",
        )

    cap = strategy.max_target_size(ctx)
    if cap is not None and len(pkcs8) > cap:
        return _external_or_skip(
            rs,
            cfg,
            material=pkcs8,
            label=label,
            key_type=key_type,
            obj_class="private",
            skip_msg=f"{label}: no wrapping path: no usable wrap mechanism for this target size",
        )

    unwrap_handle = strategy.unwrapping_key_handle(ctx)
    if unwrap_handle is None:
        return _external_or_skip(
            rs,
            cfg,
            material=pkcs8,
            label=label,
            key_type=key_type,
            obj_class="private",
            skip_msg=f"{label}: no wrapping path: resolved strategy has no unwrap handle",
        )

    blob = strategy.wrap(ctx, pkcs8)
    unwrap_template: dict[Any, Any] = {CKA_CLASS: CKO_PRIVATE_KEY, CKA_KEY_TYPE: key_type}
    unwrap_template.update({k: v for k, v in attrs.items() if k not in _EC_UNWRAP_STRIP})

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
    record_provisioning_event("private", "ran_via_unwrap")
    return handle


# ---------------------------------------------------------------------------
# external_provision — operator-command provisioning tier (Task 2)
# ---------------------------------------------------------------------------

#: Maximum seconds to wait for the operator-supplied provisioning command.
_EXTERNAL_CMD_TIMEOUT: int = 120


def external_provision(
    rs: Any,
    cfg: Any,
    *,
    material: bytes,
    label: str,
    key_type: int,
    obj_class: str,
) -> int | None:
    """Provision an object via the operator's external command. Returns a handle, or None.

    INERT (returns None immediately) unless BOTH cfg.allow_external_provision is True
    AND cfg.external_provision_cmd is a non-empty template. Writes ``material`` to a
    0600 temp file; substitutes {keyfile}/{label}/{key_type}/{key_class} into the
    command; runs it with a timeout; resolves the loaded object by CKA_LABEL via
    C_FindObjects. On success records a provisioning event + compliance.note and
    returns the handle. Any failure (timeout / non-zero exit / not found / exception)
    returns None — the caller decides whether to skip. NEVER raises.
    """
    import os
    import subprocess
    import tempfile

    # Gate: both flags must be set and non-empty.
    if not getattr(cfg, "allow_external_provision", False) or not getattr(
        cfg, "external_provision_cmd", None
    ):
        return None

    template: str = cfg.external_provision_cmd

    # Create the temp file. If mkstemp itself fails, no file exists — nothing to clean up.
    try:
        fd, path = tempfile.mkstemp()
    except Exception:  # noqa: BLE001
        return None

    # From here the file exists on disk; the finally below ALWAYS unlinks it, so a failure
    # while writing the material (e.g. ENOSPC) cannot leave key material behind.
    try:
        try:
            if hasattr(os, "fchmod"):
                # POSIX owner-only tightening. Absent on Windows, where the key file
                # lives in the per-user temp dir; do not let its absence disable the tier.
                os.fchmod(fd, 0o600)
            os.write(fd, material)
            os.close(fd)
        except Exception:  # noqa: BLE001
            return None

        # Build and run the command.
        try:
            cmd_str = template.format(
                keyfile=path,
                label=label,
                key_type=str(key_type),
                key_class=obj_class,
            )
            args = _split_provision_cmd(cmd_str)
        except Exception:  # noqa: BLE001
            return None

        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                timeout=_EXTERNAL_CMD_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return None
        except Exception:  # noqa: BLE001
            return None

        if proc.returncode != 0:
            return None

        # Resolve the loaded object by CKA_LABEL.
        try:
            from pkcs11_check.raw.pack import template_from_dict
            from pkcs11_check.raw.recipes import find_objects

            lbl_bytes: bytes = label.encode() if isinstance(label, str) else label
            tmpl = template_from_dict({CKA_LABEL: lbl_bytes})
            handles = find_objects(rs.raw, rs.sh, tmpl)
        except Exception:  # noqa: BLE001
            return None

        if not handles:
            return None

        handle = handles[0]
        try:
            record_provisioning_event(obj_class, "ran_via_external")
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                f"{label}: provisioned externally via operator command ({obj_class})"
                " — NOT a PKCS#11-API capability",
                ComplianceLevel.CRITICAL,
            )
        except Exception:  # noqa: BLE001
            return handle  # best-effort: event/note failure must not block provisioning
        return handle

    finally:
        # Best-effort: overwrite the file with zeros then unlink.
        try:
            with open(path, "r+b") as fh:
                fh.write(b"\x00" * len(material))
                fh.flush()
        except OSError:
            pass  # best-effort zeroing; unlink still attempted below
        try:
            os.unlink(path)
        except OSError:
            pass  # best-effort unlink; file may already be gone


# ---------------------------------------------------------------------------
# _external_or_skip — helper: try external tier, else record + skip
# ---------------------------------------------------------------------------


def _external_or_skip(
    rs: Any,
    cfg: Any,
    *,
    material: bytes,
    label: str,
    key_type: int,
    obj_class: str,
    skip_msg: str,
) -> int:
    """Try external provisioning; on success return the handle, else pytest.skip(skip_msg)."""
    handle = external_provision(
        rs, cfg, material=material, label=label, key_type=key_type, obj_class=obj_class
    )
    if handle is not None:
        return handle
    record_provisioning_event(obj_class, "skipped_no_path")
    pytest.skip(skip_msg)


# ---------------------------------------------------------------------------
# provision_public_key — create → external → skip (no unwrap path)
# ---------------------------------------------------------------------------


def provision_public_key(
    rs: Any,
    cfg: Any,
    *,
    key_type: int,
    attrs: dict[Any, Any],
    label: str,
    ec_params: bytes | None = None,
    ec_point: bytes | None = None,
    rsa_n: bytes | None = None,
    rsa_e: bytes | None = None,
) -> int:
    """Provision a public key into the token by the best available means.

    Resolution order (create → external → skip):

    1. Probe create availability.  When the module supports C_CreateObject for public
       keys, call the negotiated public importer and return the handle.

    2. Else (create_absent / create_prohibited):
       - Build a SPKI DER blob from the supplied key material for the external tier.
         RSA: ``rsa_n`` / ``rsa_e`` → ``RSAPublicNumbers(...).public_key()``.
         EC:  ``ec_params`` / ``ec_point`` → decoded public key via *cryptography*.
         On any encoding failure the best-effort fallback is ``ec_point or b""``.
       - Attempt ``external_provision``; if it returns a handle, record and return it.
       - No handle → ``record_provisioning_event("public", "skipped_no_path")``
         + ``pytest.skip``.

    Public keys have NO unwrap path; ``force-unwrap`` mode does not apply.

    Args:
        rs:        Session record with ``.raw``, ``.sh``, and ``has_mechanism``.
        cfg:       Config carrying external-provision settings.
        key_type:  ``CKK_*`` bare int constant (e.g. ``CKK_RSA``, ``CKK_EC``).
        attrs:     Usage-flag attributes for the resulting object (e.g. ``CKA_VERIFY``).
        label:     Human-readable label used in skip messages.
        ec_params: DER-encoded curve OID (EC keys).
        ec_point:  DER OCTET STRING-wrapped X9.62 uncompressed point (EC keys).
        rsa_n:     RSA modulus bytes, big-endian (RSA keys).
        rsa_e:     RSA public exponent bytes, big-endian (RSA keys).

    Returns:
        Object handle (int) of the provisioned public key.

    Raises:
        pytest.skip.Exception: When the module has no create path and external
            provisioning is not configured or fails.
    """
    verdict = profile_for(rs).create_verdict("public")
    if verdict == "create_available":
        record_provisioning_event("public", "ran_via_create")
        if rsa_n is not None and rsa_e is not None:
            from pkcs11_check.testcases.conftest import import_rsa_public_key_negotiated

            return import_rsa_public_key_negotiated(rs, n=rsa_n, e=rsa_e, attrs=attrs)
        # EC (or other) path
        from pkcs11_check.testcases.conftest import import_ec_public_key_negotiated

        return import_ec_public_key_negotiated(
            rs, ec_params=ec_params or b"", ec_point=ec_point or b"", key_type=key_type, attrs=attrs
        )

    # Build SPKI DER for the external tier (best-effort; encoding failure → raw fallback).
    try:
        if rsa_n is not None and rsa_e is not None:
            from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

            material: bytes = (
                _rsa.RSAPublicNumbers(int.from_bytes(rsa_e, "big"), int.from_bytes(rsa_n, "big"))
                .public_key()
                .public_bytes(_Encoding.DER, _PublicFormat.SubjectPublicKeyInfo)
            )
        elif ec_params is not None and ec_point is not None:
            from cryptography.hazmat.primitives.asymmetric import ec as _ec

            # Decode OID from DER: skip tag(0x06)+length bytes → OID value bytes
            oid_der = ec_params
            if len(oid_der) >= 2 and oid_der[0] == 0x06:
                from cryptography.hazmat.primitives.asymmetric.ec import (
                    get_curve_for_oid,
                )
                from cryptography.x509 import ObjectIdentifier

                oid_len = oid_der[1]
                oid_bytes = oid_der[2 : 2 + oid_len]
                curve_oid = ObjectIdentifier(".".join(str(x) for x in _decode_oid_value(oid_bytes)))
                curve = get_curve_for_oid(curve_oid)()
                # Strip DER OCTET STRING wrapper from ec_point if present (tag 0x04 + len)
                raw_point: bytes
                if len(ec_point) >= 2 and ec_point[0] == 0x04 and ec_point[1] == len(ec_point) - 2:
                    raw_point = ec_point[2:]
                else:
                    raw_point = ec_point
                from cryptography.hazmat.primitives.serialization import (
                    Encoding as _CryptoEnc,
                )
                from cryptography.hazmat.primitives.serialization import PublicFormat

                ec_pub = _ec.EllipticCurvePublicKey.from_encoded_point(curve, raw_point)
                material = ec_pub.public_bytes(_CryptoEnc.DER, PublicFormat.SubjectPublicKeyInfo)
            else:
                material = ec_point if ec_point is not None else b""
        else:
            material = b""
    except Exception:  # noqa: BLE001
        # Best-effort: encoding failure must not block the external command attempt.
        material = ec_point if ec_point is not None else b""

    return _external_or_skip(
        rs,
        cfg,
        material=material,
        label=label,
        key_type=key_type,
        obj_class="public",
        skip_msg=(
            f"{label}: no provisioning path for public key"
            " (no C_CreateObject; external not configured/failed)"
        ),
    )


def _decode_oid_value(oid_bytes: bytes) -> list[int]:
    """Decode the value bytes of a DER OID into a list of integer arcs.

    The first byte encodes the first two arcs as ``40 * arc0 + arc1``.
    Subsequent arcs are base-128 big-endian encoded (high bit = continuation).
    """
    arcs: list[int] = []
    # First byte encodes arc0 and arc1
    first = oid_bytes[0]
    arcs.append(first // 40)
    arcs.append(first % 40)
    i = 1
    while i < len(oid_bytes):
        val = 0
        while i < len(oid_bytes):
            b = oid_bytes[i]
            i += 1
            val = (val << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        arcs.append(val)
    return arcs


# ---------------------------------------------------------------------------
# provision_certificate — create → external → skip (no unwrap path)
# ---------------------------------------------------------------------------


def provision_certificate(
    rs: Any,
    cfg: Any,
    *,
    value: bytes,
    attrs: dict[Any, Any],
    label: str,
) -> int:
    """Provision a certificate object into the token by the best available means.

    Resolution order (create → external → skip):

    1. Probe create availability.  When the module supports C_CreateObject for
       certificate objects, call ``create_object`` with the canonical
       ``{CKA_CLASS: CKO_CERTIFICATE, CKA_CERTIFICATE_TYPE: CKC_X_509,
       CKA_VALUE: value, CKA_TOKEN: False, **attrs}`` template and return the handle.

    2. Else (create_absent / create_prohibited):
       - Pass ``value`` (the DER-encoded certificate) to the external tier.
       - On success record and return the handle.
       - No handle → ``record_provisioning_event("cert", "skipped_no_path")``
         + ``pytest.skip``.

    Certificate objects have NO unwrap path.

    Args:
        rs:    Session record with ``.raw``, ``.sh``, and ``has_mechanism``.
        cfg:   Config carrying external-provision settings.
        value: DER-encoded X.509 certificate bytes.
        attrs: Additional attributes for the resulting object
               (e.g. ``CKA_LABEL``, ``CKA_SUBJECT``, ``CKA_TOKEN``).
        label: Human-readable label used in skip messages.

    Returns:
        Object handle (int) of the provisioned certificate.

    Raises:
        pytest.skip.Exception: When the module has no create path and external
            provisioning is not configured or fails.
    """
    from pkcs11_check.raw.recipes import create_object

    verdict = profile_for(rs).create_verdict("cert")
    if verdict == "create_available":
        record_provisioning_event("cert", "ran_via_create")
        return create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_CERTIFICATE,
                CKA_CERTIFICATE_TYPE: CKC_X_509,
                CKA_VALUE: value,
                CKA_TOKEN: False,
                **attrs,
            },
        )

    return _external_or_skip(
        rs,
        cfg,
        material=value,
        label=label,
        key_type=0,
        obj_class="cert",
        skip_msg=(
            f"{label}: no provisioning path for cert"
            " (no C_CreateObject; external not configured/failed)"
        ),
    )


# ---------------------------------------------------------------------------
# provision_data — create → external → skip (no unwrap path)
# ---------------------------------------------------------------------------


def provision_data(
    rs: Any,
    cfg: Any,
    *,
    value: bytes,
    attrs: dict[Any, Any],
    label: str,
) -> int:
    """Provision a CKO_DATA object into the token by the best available means.

    Resolution order (create → external → skip):

    1. Probe create availability.  When the module supports C_CreateObject for
       data objects, call ``create_object`` with the canonical
       ``{CKA_CLASS: CKO_DATA, CKA_VALUE: value, CKA_TOKEN: False, **attrs}``
       template and return the handle.

    2. Else (create_absent / create_prohibited):
       - Pass ``value`` to the external tier.
       - On success record and return the handle.
       - No handle → ``record_provisioning_event("data", "skipped_no_path")``
         + ``pytest.skip``.

    Data objects have NO unwrap path.

    Args:
        rs:    Session record with ``.raw``, ``.sh``, and ``has_mechanism``.
        cfg:   Config carrying external-provision settings.
        value: Raw data bytes.
        attrs: Additional attributes for the resulting object
               (e.g. ``CKA_LABEL``, ``CKA_TOKEN``, ``CKA_PRIVATE``).
        label: Human-readable label used in skip messages.

    Returns:
        Object handle (int) of the provisioned data object.

    Raises:
        pytest.skip.Exception: When the module has no create path and external
            provisioning is not configured or fails.
    """
    from pkcs11_check.raw.recipes import create_object

    verdict = profile_for(rs).create_verdict("data")
    if verdict == "create_available":
        record_provisioning_event("data", "ran_via_create")
        return create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_VALUE: value,
                CKA_TOKEN: False,
                **attrs,
            },
        )

    return _external_or_skip(
        rs,
        cfg,
        material=value,
        label=label,
        key_type=0,
        obj_class="data",
        skip_msg=(
            f"{label}: no provisioning path for data"
            " (no C_CreateObject; external not configured/failed)"
        ),
    )
