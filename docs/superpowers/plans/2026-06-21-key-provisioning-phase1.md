# Key-Provisioning Injection — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provision secret-key KAT material via `C_UnwrapKey` (envelope wrapping) when
`C_CreateObject` is unavailable or policy-prohibited, with a clean classified skip by default and
opt-in injection — eliminating the 321 `unclassified/HIGH` mis-classifications.

**Architecture:** A new `testcases/_provisioning.py` holds a session-cached `ProvisioningProfile`
(per-class create-availability verdict from a valid-material probe) and a `provision_secret_key`
entry point that resolves create → (opt-in) unwrap → skip. A pure-software `raw/sw_wrap.py` builds
the `CKM_RSA_AES_KEY_WRAP` / OAEP / AES-KWP blobs, which a `WrapContext` feeds to the existing
`recipes.unwrap_key`. Self-bootstrap generates an RSA-2048 unwrap keypair once per session.

**Tech Stack:** Python 3.12+, `uv`, pytest, `cryptography>=46.0.5` (software wrap), `ctypes` raw
PKCS#11 binding, pydantic-settings config.

**Spec:** `docs/superpowers/specs/2026-06-21-key-provisioning-injection-design.md` (read §3–§6, §9).

## Global Constraints

- Python 3.12 floor; mypy `--strict`; `ruff` + `ruff format --check` are gates; line length 100.
- ALWAYS `uv run` (tools are not on PATH). Full `pytest tests/` is a gate, not just targeted runs.
- At-source classification only: tests record verdicts via `classification.classify`/`xfail_as` or
  the `classify_*` helpers / `pytest.skip` — NEVER raw `pytest.fail`/`pytest.xfail` in `testcases/`
  (enforced by `tests/test_no_raw_xfail_fail.py`). `reason="unclassified"` must never be emitted.
- Injection is invisible to the test verdict; injection-capability failure → `skip`, never a
  target-op `fail`. `provision_*` is for VALID key material only.
- A `create_available` module is NEVER silently re-routed to unwrap; a real create failure surfaces.
- No per-provider config / identity. Wrapping config is generic deployment config.
- Default `--key-inject=off` (create → skip). Inject is opt-in.

**Key existing signatures (do not re-implement):**
- `RawSession` (`fixtures.py`): fields `raw: RawPKCS11`, `sh: int`, `slot_id: int`; property
  `.mechanisms: frozenset[str]`; method `.has_mechanism(name)`.
- `recipes.import_secret_key(raw, session, key_type, value, attrs=None) -> int` (uses C_CreateObject).
- `recipes.unwrap_key(raw, session, unwrapping_key, wrapped_key, mechanism, attrs=None, *, mech_param=None) -> int`.
- `recipes.gen_rsa_keypair(raw, session, bits=2048, public_attrs=None, private_attrs=None) -> tuple[int,int]`.
- `recipes.read_attributes(raw, session, handle, attr_ids) -> dict` (export modulus/exponent).
- `recipes.destroy_quietly(raw, session, handle) -> None`.
- `pack_mechanisms.mech_oaep(hash_alg, mgf, ...)` packs `CK_RSA_PKCS_OAEP_PARAMS`.
- `classification.classify(reason, *, kind=None, label="", summary=None, ...)`.
- Types in `raw/types_std.py`: `CKM_RSA_AES_KEY_WRAP`, `CKM_RSA_PKCS_OAEP`, `CKM_AES_KEY_WRAP_KWP`,
  `CK_RSA_AES_KEY_WRAP_PARAMS`, `CK_RSA_PKCS_OAEP_PARAMS`, `CKM_SHA256`, `CKG_MGF1_SHA256`,
  `CKK_AES`, `CKK_GENERIC_SECRET`, `CKO_SECRET_KEY`, `CKA_*`, `CKR_FUNCTION_NOT_SUPPORTED`.

---

### Task 1: Config fields

**Files:**
- Modify: `src/pkcs11_check/config.py` (add fields to `P11TestConfig`, after `rv_trace_compact`)
- Test: `tests/test_config_key_inject.py` (create)

**Interfaces:**
- Produces: `P11TestConfig.key_inject: str` ∈ {"off","unwrap","force-unwrap"}; `.wrap_key_source: str`
  ∈ {"bootstrap","configured"}; `.wrap_key_label: str|None`; `.wrap_key_handle: int|None`;
  `.wrap_key_value: str|None` (hex); `.wrap_mech: str|None`; `.wrap_rsa_bits: int` (default 2048).

- [ ] **Step 1: Write the failing test**
```python
# tests/test_config_key_inject.py
from pathlib import Path
from pkcs11_check.config import P11TestConfig


def test_key_inject_defaults():
    cfg = P11TestConfig(module=Path("/x.so"))
    assert cfg.key_inject == "off"
    assert cfg.wrap_key_source == "bootstrap"
    assert cfg.wrap_rsa_bits == 2048
    assert cfg.wrap_key_label is None and cfg.wrap_key_value is None


def test_key_inject_override():
    cfg = P11TestConfig(module=Path("/x.so"), key_inject="force-unwrap", wrap_rsa_bits=3072)
    assert cfg.key_inject == "force-unwrap"
    assert cfg.wrap_rsa_bits == 3072
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_config_key_inject.py -v`
Expected: FAIL (`AttributeError`/`ValidationError`: no `key_inject`).

- [ ] **Step 3: Implement** — add to `P11TestConfig` after line 47 (`rv_trace_compact`):
```python
    # Key-provisioning injection (see docs/.../key-provisioning-injection-design.md).
    # off: create->skip. unwrap: create->unwrap->skip. force-unwrap: unwrap->skip (no create).
    key_inject: str = "off"
    wrap_key_source: str = "bootstrap"  # bootstrap | configured
    wrap_key_label: str | None = None
    wrap_key_handle: int | None = None
    wrap_key_value: str | None = None  # hex; only for a symmetric configured KEK
    wrap_mech: str | None = None  # override auto-selected unwrap mechanism (e.g. "CKM_RSA_AES_KEY_WRAP")
    wrap_rsa_bits: int = 2048
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_config_key_inject.py -v` → PASS.

- [ ] **Step 5: Wire the CLI flags.** In `src/pkcs11_check/cli.py`, find the `test` command's option
  block (search for an existing flag like `rv_trace` / `--rv-trace`) and add matching `typer.Option`
  parameters `--key-inject`, `--wrap-key-source`, `--wrap-key-label`, `--wrap-key-handle`,
  `--wrap-key-value`, `--wrap-mech`, `--wrap-rsa-bits`, threading each into the `P11TestConfig(...)`
  construction exactly as `rv_trace` is threaded. Run `uv run pkcs11-check test --help` and confirm
  the flags appear.

- [ ] **Step 6: Commit**
```bash
git add src/pkcs11_check/config.py src/pkcs11_check/cli.py tests/test_config_key_inject.py
git commit -m "feat(config): key-provisioning injection flags (--key-inject, --wrap-*)"
```

---

### Task 2: Software wrap helpers (`raw/sw_wrap.py`)

**Files:**
- Create: `src/pkcs11_check/raw/sw_wrap.py`
- Test: `tests/test_sw_wrap.py` (create)

**Interfaces:**
- Produces:
  - `rsa_oaep_wrap(rsa_pub_der: bytes, payload: bytes) -> bytes`
  - `aes_kwp_wrap(kek: bytes, payload: bytes) -> bytes`
  - `rsa_aes_key_wrap_blob(rsa_pub_der: bytes, target: bytes, *, aes_bits: int = 256) -> bytes`
    (returns `RSA-OAEP(pub, T) ‖ AES-KWP(T, target)`)
  - `oaep_max_payload(rsa_pub_der: bytes) -> int`
- Consumes: `cryptography` (`hazmat.primitives.asymmetric.padding`, `serialization`,
  `hazmat.primitives.keywrap.aes_key_wrap_with_padding`, `hazmat.primitives.hashes`).

- [ ] **Step 1: Write the failing test** (round-trip in software — no PKCS#11 module needed)
```python
# tests/test_sw_wrap.py
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap_with_padding
from pkcs11_check.raw import sw_wrap


def _rsa_pub_priv():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return pub_der, priv


def test_rsa_aes_key_wrap_roundtrip_large_target():
    pub_der, priv = _rsa_pub_priv()
    target = os.urandom(1217)  # ~ RSA-2048 PKCS#8 private key size; OAEP alone cannot wrap this
    blob = sw_wrap.rsa_aes_key_wrap_blob(pub_der, target, aes_bits=256)
    # blob = c (modulus_bytes) || c' ; recover T then AES-KWP-unwrap to verify
    mod_bytes = priv.key_size // 8
    c, cprime = blob[:mod_bytes], blob[mod_bytes:]
    T = priv.decrypt(c, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                     algorithm=hashes.SHA256(), label=None))
    assert aes_key_unwrap_with_padding(T, cprime) == target


def test_oaep_max_payload():
    pub_der, _ = _rsa_pub_priv()
    assert sw_wrap.oaep_max_payload(pub_der) == 2048 // 8 - 2 * 32 - 2  # 190
```

- [ ] **Step 2: Run** `uv run pytest tests/test_sw_wrap.py -v` → FAIL (no module `sw_wrap`).

- [ ] **Step 3: Implement** `src/pkcs11_check/raw/sw_wrap.py`:
```python
"""Software-side construction of PKCS#11 wrap blobs (CKM_RSA_AES_KEY_WRAP / OAEP / AES-KWP).

Builds the exact bytes the module's C_UnwrapKey will decrypt. OAEP params are fixed to
SHA-256 / MGF1-SHA256 / empty label and MUST match the CK_RSA_*_PARAMS passed to the module.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding
from cryptography.hazmat.primitives.serialization import load_der_public_key

_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _load_rsa_pub(rsa_pub_der: bytes):  # noqa: ANN202 - cryptography RSAPublicKey
    return load_der_public_key(rsa_pub_der)


def oaep_max_payload(rsa_pub_der: bytes) -> int:
    """Max OAEP-SHA256 payload for this key: modulus_bytes - 2*hashlen - 2."""
    pub = _load_rsa_pub(rsa_pub_der)
    return pub.key_size // 8 - 2 * 32 - 2


def rsa_oaep_wrap(rsa_pub_der: bytes, payload: bytes) -> bytes:
    """RSA-OAEP(SHA-256) encrypt ``payload`` (<= oaep_max_payload)."""
    return _load_rsa_pub(rsa_pub_der).encrypt(payload, _OAEP)


def aes_kwp_wrap(kek: bytes, payload: bytes) -> bytes:
    """AES Key Wrap with Padding (RFC 5649) of ``payload`` under ``kek``."""
    return aes_key_wrap_with_padding(kek, payload)


def rsa_aes_key_wrap_blob(rsa_pub_der: bytes, target: bytes, *, aes_bits: int = 256) -> bytes:
    """CKM_RSA_AES_KEY_WRAP blob: RSA-OAEP(pub, T) || AES-KWP(T, target), T a fresh AES KEK."""
    if aes_bits not in (128, 192, 256):
        raise ValueError(f"aes_bits must be 128/192/256, got {aes_bits}")
    kek = os.urandom(aes_bits // 8)
    return rsa_oaep_wrap(rsa_pub_der, kek) + aes_kwp_wrap(kek, target)
```

- [ ] **Step 4: Run** `uv run pytest tests/test_sw_wrap.py -v` → PASS.

- [ ] **Step 5: Commit**
```bash
git add src/pkcs11_check/raw/sw_wrap.py tests/test_sw_wrap.py
git commit -m "feat(raw): software wrap-blob construction (RSA-AES-KEY-WRAP/OAEP/KWP)"
```

---

### Task 3: `mech_rsa_aes_key_wrap` mechanism packer

**Files:**
- Modify: `src/pkcs11_check/raw/pack_mechanisms.py` (add packer near `mech_oaep`, ~line 507)
- Test: `tests/test_mech_rsa_aes_key_wrap.py` (create)

**Interfaces:**
- Produces: `mech_rsa_aes_key_wrap(aes_bits: int = 256) -> PackedMechanism` packing
  `CK_RSA_AES_KEY_WRAP_PARAMS{ulAESKeyBits=aes_bits, pOAEPParams=&(SHA256/MGF1-SHA256/empty)}`,
  mechanism `CKM_RSA_AES_KEY_WRAP`.

- [ ] **Step 1: Write the failing test**
```python
# tests/test_mech_rsa_aes_key_wrap.py
from pkcs11_check.raw.pack_mechanisms import mech_rsa_aes_key_wrap
from pkcs11_check.raw.types_std import CKM_RSA_AES_KEY_WRAP


def test_mech_rsa_aes_key_wrap_packs():
    m = mech_rsa_aes_key_wrap(aes_bits=256)
    # PackedMechanism exposes the CK_MECHANISM; mechanism field must be CKM_RSA_AES_KEY_WRAP
    assert int(m.mech.mechanism) == int(CKM_RSA_AES_KEY_WRAP)
    assert m.mech.parameterLen > 0  # non-empty params (struct + nested OAEP)
```

- [ ] **Step 2: Run** `uv run pytest tests/test_mech_rsa_aes_key_wrap.py -v` → FAIL.

- [ ] **Step 3: Implement.** Read `mech_oaep` (line 507) and the `PackedMechanism` helper it returns
  to follow the exact packing/lifetime pattern (the nested OAEP params and the temp-key params must
  be kept alive — mirror how `mech_oaep` retains its `CK_RSA_PKCS_OAEP_PARAMS`). Add:
```python
def mech_rsa_aes_key_wrap(aes_bits: int = 256) -> PackedMechanism:
    """Pack CK_RSA_AES_KEY_WRAP_PARAMS (envelope: RSA-OAEP of an AES KEK + AES-KWP target).

    OAEP fixed to SHA-256 / MGF1-SHA256 / empty label to match raw/sw_wrap.py.
    """
    oaep = CK_RSA_PKCS_OAEP_PARAMS()
    oaep.hashAlg = int(CKM_SHA256)
    oaep.mgf = int(CKG_MGF1_SHA256)
    oaep.source = CKZ_DATA_SPECIFIED
    oaep.pSourceData = None
    oaep.ulSourceDataLen = 0
    params = CK_RSA_AES_KEY_WRAP_PARAMS()
    params.ulAESKeyBits = aes_bits
    params.pOAEPParams = ctypes.pointer(oaep)
    # Return via the same PackedMechanism constructor mech_oaep uses, retaining BOTH structs
    # so the pointers stay valid for the C_UnwrapKey call. Follow mech_oaep's return shape.
    return _packed_mechanism(CKM_RSA_AES_KEY_WRAP, params, retain=(params, oaep))
```
  (Use the exact retain/return idiom from `mech_oaep`; if it returns
  `PackedMechanism(mech, _keepalive=[...])`, match that. Import `CK_RSA_AES_KEY_WRAP_PARAMS`,
  `CK_RSA_PKCS_OAEP_PARAMS`, `CKM_SHA256`, `CKG_MGF1_SHA256`, `CKZ_DATA_SPECIFIED`,
  `CKM_RSA_AES_KEY_WRAP`, `ctypes` at the top of the file.)

- [ ] **Step 4: Run** `uv run pytest tests/test_mech_rsa_aes_key_wrap.py -v` → PASS.

- [ ] **Step 5: Commit**
```bash
git add src/pkcs11_check/raw/pack_mechanisms.py tests/test_mech_rsa_aes_key_wrap.py
git commit -m "feat(raw): pack CK_RSA_AES_KEY_WRAP_PARAMS (mech_rsa_aes_key_wrap)"
```

---

### Task 4: `WrapStrategy` protocol + strategies + `WrapContext` selection

**Files:**
- Create: `src/pkcs11_check/testcases/_provisioning.py` (strategies + context; profile added in Task 5)
- Test: `tests/test_wrap_strategy_selection.py` (create)

**Interfaces:**
- Produces:
  - `class WrapStrategy(Protocol)`: `name: str`; `unwrap_mech: int`;
    `usable(profile) -> bool`; `max_target_size(wrap_ctx) -> int | None`;
    `wrap(wrap_ctx, target: bytes) -> bytes`; `unwrap_mech_param(wrap_ctx) -> PackedMechanism|None`.
  - Concrete: `RsaAesKeyWrap`, `RsaOaep`, `AesKwp` (instances in `DEFAULT_STRATEGIES` order).
  - `select_strategy(strategies, profile, target_len) -> WrapStrategy | None`.
- Consumes: Task 2 `sw_wrap`, Task 3 `mech_rsa_aes_key_wrap`, `mech_oaep`.

The `wrap_ctx` carries the bootstrap RSA public DER (`rsa_pub_der`), the symmetric KEK value
(`sym_kek: bytes|None`), and the in-token unwrapping-key handle (`unwrapping_key_handle`). It is a
frozen dataclass produced by Task 6; here only its read attributes are used.

- [ ] **Step 1: Write the failing test** (uses a fake profile + fake ctx; no module)
```python
# tests/test_wrap_strategy_selection.py
from dataclasses import dataclass
from pkcs11_check.testcases import _provisioning as P


@dataclass
class FakeProfile:
    rsa_aes_key_wrap: bool
    rsa_oaep: bool
    aes_kwp: bool
    def supports_unwrap_mech(self, mech: int) -> bool:
        from pkcs11_check.raw.types_std import (
            CKM_RSA_AES_KEY_WRAP, CKM_RSA_PKCS_OAEP, CKM_AES_KEY_WRAP_KWP)
        return {int(CKM_RSA_AES_KEY_WRAP): self.rsa_aes_key_wrap,
                int(CKM_RSA_PKCS_OAEP): self.rsa_oaep,
                int(CKM_AES_KEY_WRAP_KWP): self.aes_kwp}[int(mech)]


def test_envelope_preferred_for_large_target():
    prof = FakeProfile(rsa_aes_key_wrap=True, rsa_oaep=True, aes_kwp=True)
    s = P.select_strategy(P.DEFAULT_STRATEGIES, prof, target_len=1217)
    assert s.name == "rsa_aes_key_wrap"


def test_oaep_rejected_on_size_falls_to_envelope_or_kwp():
    # OAEP only; 1217-byte target exceeds OAEP max -> OAEP unusable, no envelope -> None or kwp
    prof = FakeProfile(rsa_aes_key_wrap=False, rsa_oaep=True, aes_kwp=False)
    s = P.select_strategy(P.DEFAULT_STRATEGIES, prof, target_len=1217)
    assert s is None  # nothing can wrap a 1217-byte target here


def test_oaep_ok_for_small_target():
    prof = FakeProfile(rsa_aes_key_wrap=False, rsa_oaep=True, aes_kwp=False)
    s = P.select_strategy(P.DEFAULT_STRATEGIES, prof, target_len=32)
    assert s.name == "rsa_oaep"
```

- [ ] **Step 2: Run** `uv run pytest tests/test_wrap_strategy_selection.py -v` → FAIL.

- [ ] **Step 3: Implement** the strategy layer in `_provisioning.py`:
```python
"""Key-provisioning injection: get a setup object into the token by the best available means.

create -> (opt-in) unwrap -> skip. See docs/.../key-provisioning-injection-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from pkcs11_check.raw import sw_wrap
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
    rsa_pub_der: bytes | None        # bootstrap/configured RSA unwrap key public part
    unwrapping_key_handle: int       # in-token handle used by C_UnwrapKey
    sym_kek: bytes | None = None     # symmetric KEK value (configured/readable), for AES-KWP
    aes_bits: int = 256


@runtime_checkable
class WrapStrategy(Protocol):
    name: str
    unwrap_mech: int
    def usable(self, profile: Any) -> bool: ...
    def max_target_size(self, ctx: WrapContext) -> int | None: ...  # None = unbounded
    def wrap(self, ctx: WrapContext, target: bytes) -> bytes: ...
    def unwrap_mech_param(self, ctx: WrapContext) -> Any: ...


class RsaAesKeyWrap:
    name = "rsa_aes_key_wrap"
    unwrap_mech = int(CKM_RSA_AES_KEY_WRAP)
    def usable(self, profile: Any) -> bool:
        return profile.supports_unwrap_mech(self.unwrap_mech)
    def max_target_size(self, ctx: WrapContext) -> int | None:
        return None  # AES-KWP layer carries any size
    def wrap(self, ctx: WrapContext, target: bytes) -> bytes:
        assert ctx.rsa_pub_der is not None
        return sw_wrap.rsa_aes_key_wrap_blob(ctx.rsa_pub_der, target, aes_bits=ctx.aes_bits)
    def unwrap_mech_param(self, ctx: WrapContext) -> Any:
        return mech_rsa_aes_key_wrap(aes_bits=ctx.aes_bits)


class RsaOaep:
    name = "rsa_oaep"
    unwrap_mech = int(CKM_RSA_PKCS_OAEP)
    def usable(self, profile: Any) -> bool:
        return profile.supports_unwrap_mech(self.unwrap_mech)
    def max_target_size(self, ctx: WrapContext) -> int | None:
        assert ctx.rsa_pub_der is not None
        return sw_wrap.oaep_max_payload(ctx.rsa_pub_der)
    def wrap(self, ctx: WrapContext, target: bytes) -> bytes:
        assert ctx.rsa_pub_der is not None
        return sw_wrap.rsa_oaep_wrap(ctx.rsa_pub_der, target)
    def unwrap_mech_param(self, ctx: WrapContext) -> Any:
        return mech_oaep(int(CKM_SHA256), int(CKG_MGF1_SHA256))


class AesKwp:
    name = "aes_kwp"
    unwrap_mech = int(CKM_AES_KEY_WRAP_KWP)
    def usable(self, profile: Any) -> bool:
        return profile.supports_unwrap_mech(self.unwrap_mech)
    def max_target_size(self, ctx: WrapContext) -> int | None:
        return None if ctx.sym_kek is not None else 0  # needs a symmetric KEK value
    def wrap(self, ctx: WrapContext, target: bytes) -> bytes:
        assert ctx.sym_kek is not None
        return sw_wrap.aes_kwp_wrap(ctx.sym_kek, target)
    def unwrap_mech_param(self, ctx: WrapContext) -> Any:
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
```
  Note: for the unit test, give `FakeProfile` a `rsa_pub_der_probe` of a real 2048-bit SPKI DER (or
  add a small helper) so `RsaOaep.max_target_size` returns 190; in the test above the OAEP-only case
  with a 1217-byte target must return `None`. Adjust the test's `FakeProfile` to include
  `rsa_pub_der_probe` built once via `cryptography` (as in Task 2's `_rsa_pub_priv`).

- [ ] **Step 4: Run** `uv run pytest tests/test_wrap_strategy_selection.py -v` → PASS. Run
  `uv run mypy --strict src/pkcs11_check/testcases/_provisioning.py` → clean.

- [ ] **Step 5: Commit**
```bash
git add src/pkcs11_check/testcases/_provisioning.py tests/test_wrap_strategy_selection.py
git commit -m "feat(provisioning): WrapStrategy registry + size-aware selection"
```

---

### Task 5: `ProvisioningProfile` (per-class create-availability probe)

> **TEST APPROACH (supersedes the softhsm2 test below).** The `tests/` suite is **module-free**
> and is a fast gate — do NOT create a `softhsm2_raw_session` fixture or touch `tests/conftest.py`.
> Write a **fake-`raw` meta-test** following the exact pattern of
> `tests/test_import_ec_private_key_negotiated.py`: `monkeypatch.setattr` the recipe functions this
> code calls (`pkcs11_check.raw.recipes.import_secret_key`, `…destroy_quietly`) and use a synthetic
> `rs = type("RS", (), {"raw": object(), "sh": <int>, "slot_id": 0, "has_mechanism": lambda self,n: <bool>})()`.
> Cover all three verdicts: patch `import_secret_key` to **return a handle** (→ `create_available`),
> to **raise `CkrAssertionError(..., CKR_FUNCTION_NOT_SUPPORTED)`** (→ `create_absent`), and to raise
> a policy code in `_CREATE_PROHIBITED_RVS` (→ `create_prohibited`); and assert `supports_unwrap_mech`
> reflects the fake `has_mechanism`. Reset `_PROFILE_CACHE` between cases (or use distinct `sh`).
> The implementation code below is unchanged; only the test is fake-based. The real-softhsm2
> end-to-end check happens once in Task 9 (controller-run), not here.

**Files:**
- Modify: `src/pkcs11_check/testcases/_provisioning.py` (add `ProvisioningProfile` + `profile_for`)
- Test: `tests/test_provisioning_profile_softhsm2.py` (create; runs against softhsm2)

**Interfaces:**
- Produces:
  - `ProvisioningProfile` with `create_verdict(obj_class: str) -> str` ∈
    {"create_available","create_absent","create_prohibited"}; `supports_unwrap_mech(mech) -> bool`;
    `rsa_pub_der_probe: bytes | None` (None until Task 6 bootstraps).
  - `profile_for(rs) -> ProvisioningProfile` — builds once and caches keyed by `rs.sh`.
- Consumes: `recipes.import_secret_key`, `recipes.destroy_quietly`, `RawSession.has_mechanism`,
  `raw.types_std` RV/CKK constants.

The probe for `"secret"` attempts a throwaway valid 16-byte AES key via `import_secret_key` with
`CKA_TOKEN=False`; maps the outcome: `CKR_OK` → `create_available` (then `destroy_quietly`);
`CKR_FUNCTION_NOT_SUPPORTED` → `create_absent`; a clean policy refusal in
`{CKR_TEMPLATE_INCONSISTENT, CKR_FUNCTION_NOT_PERMITTED, CKR_KEY_UNEXTRACTABLE, CKR_ATTRIBUTE_VALUE_INVALID}`
→ `create_prohibited`; any other CKR re-raises (real finding / harness bug). `supports_unwrap_mech`
checks `rs.has_mechanism` for the mechanism's name.

- [ ] **Step 1: Write the failing test** (softhsm2 supports create + all wrap mechs)
```python
# tests/test_provisioning_profile_softhsm2.py
import pytest
from tests.conftest import softhsm2_raw_session  # existing helper; see other tests/ that build a session
from pkcs11_check.testcases._provisioning import profile_for
from pkcs11_check.raw.types_std import CKM_RSA_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP


def test_softhsm2_profile_create_available_and_unwrap(softhsm2_raw_session):
    prof = profile_for(softhsm2_raw_session)
    assert prof.create_verdict("secret") == "create_available"
    assert prof.supports_unwrap_mech(int(CKM_RSA_AES_KEY_WRAP)) is True
    assert prof.supports_unwrap_mech(int(CKM_AES_KEY_WRAP_KWP)) is True
```
  If `tests/conftest.py` has no `softhsm2_raw_session` fixture, add one that mirrors how other
  `tests/test_*softhsm2*` / `tests/test_ro_unwrap_token_classification.py` build a `RawSession`
  against the locally-built softhsm2 module (read one of those tests and reuse its setup verbatim).

- [ ] **Step 2: Run** `uv run pytest tests/test_provisioning_profile_softhsm2.py -v` → FAIL.

- [ ] **Step 3: Implement** in `_provisioning.py`:
```python
_PROFILE_CACHE: dict[int, "ProvisioningProfile"] = {}

_CREATE_PROHIBITED_RVS = frozenset({
    int(CKR_TEMPLATE_INCONSISTENT), int(CKR_FUNCTION_NOT_PERMITTED),
    int(CKR_KEY_UNEXTRACTABLE), int(CKR_ATTRIBUTE_VALUE_INVALID),
})


@dataclass
class ProvisioningProfile:
    rs: Any
    rsa_pub_der_probe: bytes | None = None
    _verdicts: dict[str, str] = field(default_factory=dict)

    def supports_unwrap_mech(self, mech: int) -> bool:
        from pkcs11_check.raw.metadata_std import MECHANISM_NAMES  # int->"CKM_..." name
        name = MECHANISM_NAMES.get(int(mech))
        return bool(name) and self.rs.has_mechanism(name)

    def create_verdict(self, obj_class: str) -> str:
        if obj_class in self._verdicts:
            return self._verdicts[obj_class]
        v = self._probe_secret() if obj_class == "secret" else self._probe_private(obj_class)
        self._verdicts[obj_class] = v
        return v

    def _probe_secret(self) -> str:
        from ctypes import byref
        from pkcs11_check.raw.recipes import destroy_quietly, import_secret_key
        try:
            h = import_secret_key(self.rs.raw, self.rs.sh, int(CKK_AES), b"\x00" * 16,
                                  attrs={CKA_TOKEN: False, CKA_ENCRYPT: True, CKA_DECRYPT: True,
                                         CKA_SENSITIVE: False, CKA_EXTRACTABLE: True})
        except CkrAssertionError as exc:
            rv = int(exc.rv)
            if rv == int(CKR_FUNCTION_NOT_SUPPORTED):
                return "create_absent"
            if rv in _CREATE_PROHIBITED_RVS:
                return "create_prohibited"
            raise
        destroy_quietly(self.rs.raw, self.rs.sh, h)
        return "create_available"

    def _probe_private(self, obj_class: str) -> str:
        # Phase 2 wires real private probes; Phase 1 only needs "secret".
        return "create_available"


def profile_for(rs: Any) -> ProvisioningProfile:
    prof = _PROFILE_CACHE.get(rs.sh)
    if prof is None:
        prof = ProvisioningProfile(rs=rs)
        _PROFILE_CACHE[rs.sh] = prof
    return prof
```
  Add imports at the top: `from dataclasses import field`; `from pkcs11_check.raw.rv import
  CkrAssertionError`; and the CKA/CKK/CKR constants used
  (`CKK_AES, CKA_TOKEN, CKA_ENCRYPT, CKA_DECRYPT, CKA_SENSITIVE, CKA_EXTRACTABLE,
  CKR_FUNCTION_NOT_SUPPORTED, CKR_TEMPLATE_INCONSISTENT, CKR_FUNCTION_NOT_PERMITTED,
  CKR_KEY_UNEXTRACTABLE, CKR_ATTRIBUTE_VALUE_INVALID`).

- [ ] **Step 4: Run** `uv run pytest tests/test_provisioning_profile_softhsm2.py -v` → PASS.

- [ ] **Step 5: Commit**
```bash
git add src/pkcs11_check/testcases/_provisioning.py tests/test_provisioning_profile_softhsm2.py tests/conftest.py
git commit -m "feat(provisioning): ProvisioningProfile create-availability probe"
```

---

### Task 6: Bootstrap wrapping key → `WrapContext` builder

> **TEST APPROACH (supersedes the softhsm2 test below).** Module-free fake-`raw` meta-test (see
> `tests/test_import_ec_private_key_negotiated.py`). `monkeypatch.setattr` the recipes this code
> calls — `pkcs11_check.raw.recipes.gen_rsa_keypair` (return `(pub_h, priv_h)`) and
> `…read_attributes` (return a dict with `CKA_MODULUS`/`CKA_PUBLIC_EXPONENT` taken from a REAL
> `cryptography`-generated RSA-2048 key's public numbers, big-endian bytes) — plus a synthetic `rs`.
> Assert `build_wrap_context` returns a `WrapContext` whose `rsa_pub_der` round-trips back to the same
> modulus/exponent and whose `unwrapping_key_handle == priv_h`, and that `profile_for(rs).rsa_pub_der_probe`
> is set. **Also test the size-escalation**: a `gen_rsa_keypair` fake that raises
> `CkrAssertionError(CKR_KEY_SIZE_RANGE)` for `bits=2048` but succeeds for `bits=3072` must yield a
> context (assert it retried at 3072); a fake that refuses all sizes must yield `None`. Guard
> `RsaOaep` against a `None` `rsa_pub_der` (the Task 4 latent-assert footgun) — `build_wrap_context`
> always sets `rsa_pub_der` on success, and `provision_secret_key` (Task 7) must not select a strategy
> when no `WrapContext` exists.

**Files:**
- Modify: `src/pkcs11_check/testcases/_provisioning.py` (add `build_wrap_context`)
- Test: `tests/test_wrap_context_bootstrap_softhsm2.py` (create)

**Interfaces:**
- Produces: `build_wrap_context(rs, cfg) -> WrapContext | None` — for `wrap_key_source="bootstrap"`:
  generate an RSA unwrap keypair, **escalating the size 2048 → 3072 → 4096** so a strict/FIPS
  provider that refuses the smaller size still gets a key (cryptographically 2048 suffices — the
  envelope only RSA-wraps the 32-byte KEK — so escalation costs only keygen time, not coverage).
  Then `read_attributes(... CKA_MODULUS, CKA_PUBLIC_EXPONENT)` and assemble the SPKI DER via
  `cryptography` `RSAPublicNumbers(...).public_key()`. Returns `None` (→ skip "no wrapping path") if
  **every** size is refused or `pin is None` blocks private-key creation. Sets
  `profile.rsa_pub_der_probe` so `select_strategy` sizing is correct.
- Consumes: `recipes.gen_rsa_keypair`, `recipes.read_attributes`, `cryptography`.

The size-escalation ladder (start at `cfg.wrap_rsa_bits`, then any larger of 3072/4096):
```python
_RSA_SIZE_REFUSED = frozenset({
    int(CKR_KEY_SIZE_RANGE), int(CKR_ATTRIBUTE_VALUE_INVALID),
    int(CKR_TEMPLATE_INCONSISTENT), int(CKR_FUNCTION_FAILED),
})

def _bootstrap_rsa_unwrap_key(rs, start_bits):  # -> (pub_handle, priv_handle, bits) | None
    sizes = [b for b in (start_bits, 3072, 4096) if b >= start_bits]
    seen: set[int] = set()
    for bits in sizes:
        if bits in seen:
            continue
        seen.add(bits)
        try:
            pub, priv = gen_rsa_keypair(
                rs.raw, rs.sh, bits=bits,
                public_attrs={CKA_TOKEN: False, CKA_WRAP: True},
                private_attrs={CKA_TOKEN: False, CKA_UNWRAP: True})
            return pub, priv, bits
        except CkrAssertionError as exc:
            if int(exc.rv) in _RSA_SIZE_REFUSED:
                continue   # try a larger size
            raise          # an unexpected keygen error is a real finding
    return None
```

- [ ] **Step 1: Write the failing test**
```python
# tests/test_wrap_context_bootstrap_softhsm2.py
from pathlib import Path
from pkcs11_check.config import P11TestConfig
from pkcs11_check.testcases._provisioning import build_wrap_context, profile_for


def test_bootstrap_builds_usable_context(softhsm2_raw_session):
    cfg = P11TestConfig(module=Path("/ignored.so"), key_inject="unwrap", wrap_rsa_bits=2048)
    ctx = build_wrap_context(softhsm2_raw_session, cfg)
    assert ctx is not None
    assert ctx.rsa_pub_der and ctx.unwrapping_key_handle != 0
    assert profile_for(softhsm2_raw_session).rsa_pub_der_probe == ctx.rsa_pub_der
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement** `build_wrap_context` (bootstrap branch first; configured branch is a
  follow-up sub-step). Call `_bootstrap_rsa_unwrap_key(rs, cfg.wrap_rsa_bits)` (the size-escalation
  ladder above); if `None` → return `None`. Convert exported big-endian
  `CKA_MODULUS`/`CKA_PUBLIC_EXPONENT` to ints with `int.from_bytes(..., "big")`, build
  `rsa.RSAPublicNumbers(e, n).public_key().public_bytes(DER, SubjectPublicKeyInfo)`, and return
  `WrapContext(rsa_pub_der=<der>, unwrapping_key_handle=<priv>)`. Set `profile_for(rs).rsa_pub_der_probe`.
  Import `CKR_KEY_SIZE_RANGE, CKR_ATTRIBUTE_VALUE_INVALID, CKR_TEMPLATE_INCONSISTENT,
  CKR_FUNCTION_FAILED, CKA_WRAP, CKA_UNWRAP, CKA_TOKEN, CKA_MODULUS, CKA_PUBLIC_EXPONENT`.

- [ ] **Step 4: Run** → PASS.

- [ ] **Step 5: Commit**
```bash
git add src/pkcs11_check/testcases/_provisioning.py tests/test_wrap_context_bootstrap_softhsm2.py
git commit -m "feat(provisioning): bootstrap RSA unwrap key -> WrapContext"
```

---

### Task 7: `provision_secret_key` resolution + value-integrity

> **TEST APPROACH (supersedes the softhsm2 test below).** Module-free fake-`raw` meta-tests (see
> `tests/test_import_ec_private_key_negotiated.py`). Monkeypatch the recipes (`import_secret_key`,
> `gen_rsa_keypair`, `read_attributes`, `unwrap_key`, `destroy_quietly`) and use a synthetic `rs`
> with a `has_mechanism` that advertises the wrap mechs. Cover the resolution branches:
> (a) `create_available` + mode `off`/`unwrap` → calls `import_secret_key`, returns its handle (no
> unwrap); (b) `create_absent` + `key_inject=off` → `pytest.raises(pytest.skip.Exception)` with reason
> "Module does not implement C_CreateObject"; (c) `create_absent` + `key_inject=unwrap` with a working
> fake `unwrap_key` → returns the unwrapped handle and the value-integrity readback path runs;
> (d) `force-unwrap` → never calls `import_secret_key`, goes straight to unwrap. Use a fake
> `unwrap_key` that records the `(mechanism, mech_param, wrapped_key)` it was handed so the test
> asserts the envelope strategy + blob were used. The value-integrity readback (`read_attributes`
> CKA_VALUE) is monkeypatched to return the injected `value` for the non-sensitive case. The real
> softhsm2 unwrap acceptance is validated in Task 9.

**Files:**
- Modify: `src/pkcs11_check/testcases/_provisioning.py` (add `provision_secret_key`)
- Test: `tests/test_provision_secret_softhsm2.py` (create; force-unwrap path)

**Interfaces:**
- Produces: `provision_secret_key(rs, cfg, key_type, value, attrs, *, label) -> int` (handle) or
  `pytest.skip(...)`. Resolution per spec §3.2; on unwrap, picks a strategy via `select_strategy`,
  builds the blob, calls `recipes.unwrap_key(rs.raw, rs.sh, ctx.unwrapping_key_handle, blob,
  strategy.unwrap_mech, attrs=<attrs minus CKA_VALUE/CKA_VALUE_LEN>, mech_param=strategy.unwrap_mech_param(ctx))`.
  When the resulting key is non-sensitive, read back `CKA_VALUE` via `read_attributes` and assert it
  equals `value` (skip with a clear reason on mismatch — a corrupted setup, not a target finding).
- Consumes: Tasks 4–6, `recipes.unwrap_key`, `recipes.import_secret_key`, `pytest`.

- [ ] **Step 1: Write the failing test** (force-unwrap on softhsm2; the injected key must work)
```python
# tests/test_provision_secret_softhsm2.py
from pathlib import Path
from pkcs11_check.config import P11TestConfig
from pkcs11_check.testcases._provisioning import provision_secret_key
from pkcs11_check.raw.types_std import CKK_AES, CKA_ENCRYPT, CKA_DECRYPT, CKA_TOKEN, CKA_SENSITIVE


def test_force_unwrap_injects_exact_aes_key(softhsm2_raw_session):
    cfg = P11TestConfig(module=Path("/x.so"), key_inject="force-unwrap")
    value = bytes(range(32))
    h = provision_secret_key(
        softhsm2_raw_session, cfg, int(CKK_AES), value,
        {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False, CKA_SENSITIVE: False},
        label="kat-aes")
    assert h != 0
    # value-integrity readback already asserted inside provision_secret_key for non-sensitive keys
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement** `provision_secret_key`:
  - `mode = cfg.key_inject`. If `mode != "force-unwrap"`: consult
    `profile_for(rs).create_verdict("secret")`; if `create_available` → return
    `import_secret_key(rs.raw, rs.sh, key_type, value, attrs)`.
  - If create unavailable/prohibited or mode == `force-unwrap`: if `mode == "off"` →
    `pytest.skip("Module does not implement C_CreateObject")`. Else build/cache the `WrapContext`
    (Task 6); if `None` → `pytest.skip("no wrapping path")`. `select_strategy(...)`; if `None` →
    `pytest.skip("no wrapping path: no usable wrap mechanism for this target size")`. Build blob,
    `unwrap_key(...)`, value-integrity readback when `CKA_SENSITIVE` is False/absent, return handle.

- [ ] **Step 4: Run** → PASS. Also run with `key_inject="unwrap"` and assert (via a counter or the
  returned handle's source) it took the **create** path on softhsm2 (negative validation).

- [ ] **Step 5: Commit**
```bash
git add src/pkcs11_check/testcases/_provisioning.py tests/test_provision_secret_softhsm2.py
git commit -m "feat(provisioning): provision_secret_key (create->unwrap->skip + integrity)"
```

---

### Task 8: Migrate the secret-key KAT sites + clean skip

**Files:**
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py`
  (classes `TestAESGCMWycheproof`, `TestAESCBCPKCS5Wycheproof`, `TestHMACSHA256Wycheproof`)
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py` (clean-skip on create-absent only;
  the secret-key acvp migration to `provision_*` is part of Phase 2 — here just stop the FNS hard-fail)
- Test: existing files run; add `tests/test_provisioning_skip_no_create.py`

**Interfaces:**
- Consumes: `provision_secret_key`, `p11_config` (the test must receive `p11_config` to pass `cfg`).

The wycheproof secret-key sites currently call `import_secret_key(rs.raw, rs.sh, CKK_AES, key_bytes,
attrs={...})` inside `try/except AssertionError`. Replace the **import** call with
`provision_secret_key(rs, p11_config, CKK_AES, key_bytes, {...}, label="wycheproof-aes-gcm")`.
Keep the existing `except AssertionError: if result == "invalid": return; raise` for the genuinely
invalid-key vectors (those still test create-rejection on `create_available` modules). Add
`p11_config` to each test method's signature (it is a fixture).

- [ ] **Step 1: Write the failing test** (capability-absent path skips, never hard-fails)
```python
# tests/test_provisioning_skip_no_create.py
import pytest
from pathlib import Path
from pkcs11_check.config import P11TestConfig
from pkcs11_check.testcases._provisioning import provision_secret_key
from pkcs11_check.raw.types_std import CKK_AES


class _NoCreate:  # minimal fake rs: create + unwrap both FNS
    sh = 1234
    class raw:
        @staticmethod
        def C_CreateObject(*a, **k):
            from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED
            return int(CKR_FUNCTION_NOT_SUPPORTED)
    def has_mechanism(self, name): return False


def test_no_create_no_unwrap_skips_cleanly():
    cfg = P11TestConfig(module=Path("/x.so"), key_inject="off")
    with pytest.raises(pytest.skip.Exception):
        provision_secret_key(_NoCreate(), cfg, int(CKK_AES), b"\x00"*16, {}, label="x")
```
  (Adjust `_NoCreate.raw.C_CreateObject` to whatever `import_secret_key` actually invokes — it calls
  `raw.C_CreateObject(session, ptr, count, byref(handle))` and `expect_rv` raises `CkrAssertionError`
  on non-OK; the fake returning FNS will drive `create_absent` → `key_inject=off` → skip.)

- [ ] **Step 2: Run** `uv run pytest tests/test_provisioning_skip_no_create.py -v` → FAIL.

- [ ] **Step 3: Implement** — make `provision_secret_key` robust to the fake (already designed for
  it), then migrate the three wycheproof secret-key classes' import sites as described above.

- [ ] **Step 4: Run** the migrated product tests against softhsm2 to confirm no regression:
```
uv run pkcs11-check test --module <softhsm2.so> --p11-slot 1 \
  -- src/pkcs11_check/testcases/wycheproof/test_wycheproof.py -k "AESGCM or AESCBC or HMAC"
```
  Expected: same pass/skip profile as before (create path). Then `uv run pytest tests/ -q` (all gates).

- [ ] **Step 5: Commit**
```bash
git add src/pkcs11_check/testcases/wycheproof/test_wycheproof.py \
        src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py \
        tests/test_provisioning_skip_no_create.py
git commit -m "feat(provisioning): route secret-key KAT setup through provision_secret_key"
```

---

### Task 9: Real-softhsm2 force-unwrap validation (CONTROLLER-run, not a subagent task)

This is **not** a `tests/` unit test (the `tests/` gate is module-free). It is a one-time real-module
validation the controller runs after Task 8 to prove softhsm2's `C_UnwrapKey` actually accepts our
software-built `CKM_RSA_AES_KEY_WRAP` envelope blob — the core integration risk. Record the outcome
in the ledger; do not commit a token-dependent test into the gate suite.

Runbook (controller):
1. Provision an ephemeral softhsm2 token in a temp dir:
   `export SOFTHSM2_CONF=$(mktemp); TOK=$(mktemp -d); printf 'directories.tokendir = %s\n' "$TOK" > "$SOFTHSM2_CONF"`,
   then `softhsm2-util --init-token --slot 0 --label kp --so-pin 12345678 --pin 1234`.
2. Run a representative secret-key KAT with **force-unwrap** against the real module:
   `uv run pkcs11-check test --module /usr/lib/softhsm/libsofthsm2.so --p11-slot <provisioned-slot> \
    --pin 1234 --key-inject force-unwrap -- src/pkcs11_check/testcases/wycheproof/test_wycheproof.py -k AESGCM`
3. **Expected:** the AES-GCM KAT cases **pass via the unwrap path** (the bootstrap RSA key is
   generated, the envelope blob is unwrapped into the AES key, the GCM operation succeeds) — i.e. the
   same pass profile as a normal create-path run, proving real-module acceptance.
4. **Negative check:** repeat with `--key-inject unwrap` (not force) → on softhsm2 (create-available)
   it must take the **create** path unchanged; and with `--key-inject off` it must also be unchanged.
5. If force-unwrap fails to round-trip on softhsm2, the most likely cause is an OAEP-param mismatch
   between `sw_wrap._OAEP` and `mech_rsa_aes_key_wrap` (§4.1) — debug there before proceeding to the
   final review.

(Optional, deferred to a later phase: a `@pytest.mark.integration` test gated on a
`P11TEST_SOFTHSM2_MODULE` env var that self-provisions a token, so this validation becomes repeatable
in an environment that has softhsm2. Out of scope for the module-free Phase 1 gate.)

---

## Phase 1 Done-Definition

- `--key-inject` defaults to `off`; the 321 + named-file FNS hard-fails become clean
  `skip("Module does not implement C_CreateObject")` (no `unclassified/HIGH`).
- With `--key-inject=force-unwrap` against softhsm2, secret-key KATs run and pass via the
  `CKM_RSA_AES_KEY_WRAP` unwrap path, with value-integrity verified. The bootstrap RSA size
  auto-escalates (2048 → 3072 → 4096) so strict/FIPS providers that refuse 2048 still bootstrap.
- All gates green. Phases 2–6 follow as separate plans: private-key injection; configured/symmetric
  wrap sources; provisioning report + dedicated finding; broad setup-site sweep; ML-KEM KEM-DEM rung;
  and the strict double-opt-in external-tool provisioning tier (§4.2 — the only path for backends
  like kmsp11 that provision nothing via PKCS#11).
