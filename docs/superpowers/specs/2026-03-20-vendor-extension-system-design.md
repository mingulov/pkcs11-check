# Vendor Extension System Design

## Goal

Add configurable, extensible vendor mechanism support to pkcs11-check so that existing tests (PQC, Wycheproof, ACVP, etc.) can transparently run against vendor-specific mechanism implementations (e.g., IBM/OpenCryptoki's `CKM_IBM_ML_DSA` instead of standard `CKM_ML_DSA`), and vendor-only features can be tested in dedicated test files.

## Architecture

Six layers, bottom-up:

```
┌──────────────────────────────────────────────────────┐
│ Layer 5: CLI control                                  │
│ --p11-vendor=ibm --p11-vendor-prefer=standard|vendor │
├──────────────────────────────────────────────────────┤
│ Layer 4: Vendor-only tests (testcases/vendor/ibm/)   │
├──────────────────────────────────────────────────────┤
│ Layer 3: Automatic integration                        │
│ • has_mechanism() vendor-aware (global, zero changes) │
│ • @needs_mechanism vendor-aware (global)              │
│ • vendor_mechanism() remap fixture                    │
│ • Update ~6 helper functions + ~25 direct calls       │
├──────────────────────────────────────────────────────┤
│ Layer 2: Resolver + ResolvedContext                   │
│ • resolve_mechanism(), resolve_algorithm()            │
│ • --p11-vendor-prefer controls standard vs vendor     │
├──────────────────────────────────────────────────────┤
│ Layer 1: VendorProfile + TOML                         │
│ • Profile data, fingerprints, migration tracking      │
├──────────────────────────────────────────────────────┤
│ Layer 0: python-pkcs11 fork                           │
│ • _missing_ on IntEnum, isinstance relaxation         │
└──────────────────────────────────────────────────────┘
```

## Vendor Landscape

Research across 10+ vendors found wildly different namespacing strategies:

| Vendor | Base | Notable |
|--------|------|---------|
| IBM EP11 / OpenCryptoki | 0x8001xxxx | 45+ mechs: PQC, SHA-3, EdDSA, blockchain |
| AWS CloudHSM | 0x8000xxxx | AES-GCM (HSM-generated IV), KDF, wrapping |
| Thales Luna | 0x8000xxxx | Korean crypto (SEED/KCDSA), DUKPT payments |
| Entrust nShield | 0xDE436972 | Non-standard base! Telecom/3GPP/5G |
| Google Cloud KMS | 0x8001E1xx | Minimal, single AES-GCM variant |
| Mozilla NSS | 0xCE534350 | HKDF, ChaCha20, TLS PRF |
| Yubico YubiHSM | 0x59554200 | Minimal wrapping |
| Qryptotoken (NISEC) | 0x4E534543 | Pre-standard PQC, hybrid |
| Russian GOST (TC26) | 0xD4321000 | GOST R 34.10/34.11-2012 |

Key patterns:
- **Vendor bases are NOT all 0x80000000+** — nShield, NSS, GOST, Yubico all use different magic numbers
- **PQC migration**: vendor mechanisms get standardized (IBM Dilithium → ML-DSA, IBM Kyber → ML-KEM)
- **Same algorithm, different IDs**: IBM SHA-3, IBM EdDSA, IBM ML-DSA are functionally identical to standard equivalents but use different CKM/CKK/CKA values
- **Vendor-only features**: IBM BTC_DERIVE, Luna DUKPT, nShield 3GPP have no standard equivalent

Reference data: `/home/user/src/m/pkcs11-proxy/pkcs11-proxy/examples/vendors/` (8 vendor TOML configs with mechanism IDs).

## Layer 0: python-pkcs11 Fork Changes (PREREQUISITE)

### Problem

The python-pkcs11 Cython binding rejects non-enum values at three points:

1. `_pkcs11.pyx` line 328: `isinstance(mechanism, Mechanism)` check — vendor mechanism integers are rejected
2. `Mechanism(0x80010036)` raises `ValueError` — IntEnum doesn't accept undefined values
3. Same for `KeyType` and `Attribute` — vendor key types and attributes can't be used in templates

Without these changes, no vendor mechanism can flow through the binding layer at all.

### Changes

**Change 1: `_missing_` classmethod on IntEnum classes**

Add to `Mechanism`, `KeyType`, `Attribute`, `ObjectClass` in `mechanisms.py` / `constants.py`:

```python
@classmethod
def _missing_(cls, value):
    obj = int.__new__(cls, value)
    obj._name_ = f"VENDOR_0x{value:08X}"
    obj._value_ = value
    return obj
```

This lets `Mechanism(0x80010036)` return a valid enum member with name `VENDOR_0x80010036` instead of raising ValueError.

**Change 2: Relax isinstance check in `_pkcs11.pyx`**

```python
# Before:
if not isinstance(mechanism, Mechanism):
    raise ArgumentsBad("`mechanism` must be a Mechanism.")

# After:
if not isinstance(mechanism, (Mechanism, int)):
    raise ArgumentsBad("`mechanism` must be a Mechanism or int.")
if isinstance(mechanism, int):
    mechanism = Mechanism(mechanism)
```

**Change 3: Same relaxation for KeyType in `generate_keypair()`, `create_object()` etc.**

Anywhere `isinstance(key_type, KeyType)` is enforced, relax to accept `int` and auto-wrap.

**Change 4: Fallback in `defaults.py` for unknown key types**

`DEFAULT_KEY_CAPABILITIES` and `DEFAULT_GENERATE_MECHANISMS` use `dict[key_type]` lookups that raise `KeyError` for vendor key types. Change to `.get()` with sensible fallbacks:

```python
# defaults.py — change all lookups from:
capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
# to:
capabilities = DEFAULT_KEY_CAPABILITIES.get(key_type)
if capabilities is None:
    raise ArgumentsBad("No default capabilities for this key type. Please specify capabilities.")
```

This preserves the existing error message but makes it explicit rather than a raw KeyError. Tests using vendor key types must always pass explicit `mechanism=` and `capabilities=` parameters — the helpers handle this.

**Scope**: These are small, targeted changes in the existing fork. They don't change behavior for standard mechanisms — only enable vendor values to flow through.

## Layer 1: Vendor Profiles

### Directory Structure

```
src/pkcs11_check/vendors/
  __init__.py              # VendorProfile dataclass, load_vendor_profiles(), registry
  _resolver.py             # MechanismResolver, ResolvedContext
  ibm/
    __init__.py             # IBM profile registration
    profile.toml            # Mechanism/attribute/keytype mappings
    helpers.py              # IBM param builders, key template helpers
  aws/
    __init__.py
    profile.toml
    helpers.py
  qryptotoken/
    __init__.py
    profile.toml
    helpers.py
```

### VendorProfile Dataclass

```python
@dataclass(frozen=True)
class VendorProfile:
    name: str                        # "ibm"
    display_name: str                # "IBM EP11 / OpenCryptoki"

    # Standard → vendor equivalents (same algorithm, different ID)
    mechanism_map: dict[int, int]    # {CKM_ML_DSA: CKM_IBM_ML_DSA}
    keytype_map: dict[int, int]      # {CKK_ML_DSA: CKK_IBM_ML_DSA}
    attribute_map: dict[int, int]    # {CKA_PARAMETER_SET: CKA_IBM_PARAMETER_SET}

    # Reverse maps (computed at load time)
    mechanism_rmap: dict[int, int]   # vendor → standard
    keytype_rmap: dict[int, int]     # vendor → standard

    # Vendor-only mechanisms (no standard equivalent)
    vendor_only: dict[int, str]      # {0x80070001: "CKM_IBM_BTC_DERIVE"}

    # Evolution tracking: vendor mechanism → standard mechanism it became
    migrations: dict[int, int]       # {CKM_IBM_DILITHIUM: CKM_ML_DSA}

    # Auto-detection fingerprint: mechanisms that identify this vendor
    fingerprint: set[int]            # {0x80010001, 0x80010002, ...}
```

### Profile TOML Format

```toml
# vendors/ibm/profile.toml
[profile]
name = "ibm"
display_name = "IBM EP11 / OpenCryptoki"
fingerprint = [0x80010001, 0x80010002, 0x80010003, 0x80010004]

[mechanisms]
# Standard enum name = vendor hex value
ML_DSA_KEY_PAIR_GEN = 0x80010035
ML_DSA = 0x80010036
ML_KEM_KEY_PAIR_GEN = 0x80010037
ML_KEM = 0x80010038
SHA3_224 = 0x80010001
SHA3_256 = 0x80010002
SHA3_384 = 0x80010003
SHA3_512 = 0x80010004
EDDSA = 0x8001001c
AES_CMAC = 0x80010007

[keytypes]
ML_DSA = 0x80010025
ML_KEM = 0x80010026

[attributes]
PARAMETER_SET = 0x80010010

[vendor_only]
CKM_IBM_BTC_DERIVE = 0x80070001
CKM_IBM_ETH_DERIVE = 0x80070002
CKM_IBM_ATTRIBUTEBOUND_WRAP = 0x80020004
CKM_IBM_ML_KEM_WITH_ECDH = 0x8001ff01

[migrations]
# vendor hex value = standard enum name
0x80010023 = "ML_DSA"   # CKM_IBM_DILITHIUM → CKM_ML_DSA
0x80010024 = "ML_KEM"   # CKM_IBM_KYBER → CKM_ML_KEM
```

TOML loading:
- `[mechanisms]`, `[keytypes]`, `[attributes]` keys are standard enum names resolved via `getattr(Mechanism, name)`.
- `[vendor_only]` keys are vendor-specific display names (string → int mapping).
- `[migrations]` keys are hex integer values (the vendor mechanism ID). Values are standard enum names resolved to standard mechanism IDs. This avoids the problem of vendor names not being in any enum.

## Layer 2: MechanismResolver + ResolvedContext

### MechanismResolver

```python
class MechanismResolver:
    def __init__(self, profiles: list[VendorProfile],
                 available: set[int],
                 prefer: str = "standard"):
        self.profiles = profiles
        self.available = available
        self.prefer = prefer  # "standard" or "vendor"

    def resolve_mechanism(self, standard: int) -> tuple[int | None, str | None]:
        """Resolve one mechanism. Returns (actual_id, vendor_name).

        Priority depends on self.prefer:
        - "standard": standard first, vendor fallback
        - "vendor": vendor first, standard fallback
        """
        has_standard = standard in self.available
        vendor_result = None
        for profile in self.profiles:
            v = profile.mechanism_map.get(standard)
            if v and v in self.available:
                vendor_result = (v, profile.name)
                break

        if self.prefer == "standard":
            if has_standard:
                return standard, None
            if vendor_result:
                return vendor_result
        elif self.prefer == "vendor":
            if vendor_result:
                return vendor_result
            if has_standard:
                return standard, None

        return None, None

    def resolve_algorithm(self, name: str) -> ResolvedContext | None:
        """Resolve a full algorithm by standard name (e.g., 'ML_DSA').

        Returns None if neither standard nor vendor mechanism is available.
        """
        mech = getattr(Mechanism, name, None)
        keygen = getattr(Mechanism, f"{name}_KEY_PAIR_GEN", None)
        kt = getattr(KeyType, name, None)
        if mech is None:
            return None

        actual_mech, vendor = self.resolve_mechanism(int(mech))
        if actual_mech is None:
            return None

        if vendor:
            profile = next(p for p in self.profiles if p.name == vendor)
            actual_keygen = profile.mechanism_map.get(int(keygen), int(keygen)) if keygen else None
            actual_kt = profile.keytype_map.get(int(kt), int(kt)) if kt else None
            attr_map = dict(profile.attribute_map)
        else:
            actual_keygen = int(keygen) if keygen else None
            actual_kt = int(kt) if kt else None
            attr_map = {}

        return ResolvedContext(
            mechanism=Mechanism(actual_mech),
            keygen_mechanism=Mechanism(actual_keygen) if actual_keygen else None,
            keytype=KeyType(actual_kt) if actual_kt else None,
            attribute_map=attr_map,
            vendor=vendor,
        )

    def has_profiles(self) -> bool:
        return len(self.profiles) > 0
```

### ResolvedContext

```python
@dataclass(frozen=True)
class ResolvedContext:
    mechanism: Mechanism
    keygen_mechanism: Mechanism | None
    keytype: KeyType | None
    attribute_map: dict[int, int]  # standard attr → vendor attr
    keytype_map: dict[int, int]    # standard keytype → vendor keytype (for template value remapping)
    vendor: str | None             # None if using standard mechanisms

    def map_template(self, template: dict) -> dict:
        """Remap template attribute keys AND known value types for vendor modules.

        When vendor is None, returns template unchanged (identity).
        When vendor is active:
        - Substitutes attribute keys that have mappings (e.g., PARAMETER_SET → IBM_PARAMETER_SET)
        - Substitutes KeyType values at Attribute.KEY_TYPE using keytype_map
        - Substitutes ObjectClass values are left unchanged (standard across vendors)
        """
        if not self.attribute_map and not self.keytype_map:
            return template
        result = {}
        for attr, value in template.items():
            mapped_attr = self.attribute_map.get(int(attr), int(attr))
            # Remap KeyType values in KEY_TYPE attribute
            if int(attr) == int(Attribute.KEY_TYPE) and self.keytype_map:
                if isinstance(value, (KeyType, int)):
                    value = KeyType(self.keytype_map.get(int(value), int(value)))
            result[Attribute(mapped_attr)] = value
        return result
```

## Layer 3: Test Integration

### Configuration

```python
# config.py
class P11TestConfig(BaseSettings):
    # ... existing fields ...
    vendor: str = "none"           # "none" | "auto" | "ibm" | "aws" | ...
    vendor_prefer: str = "standard"  # "standard" | "vendor"
```

- CLI: `--p11-vendor ibm`, `--p11-vendor-prefer vendor`
- Env: `P11TEST_VENDOR=ibm`, `P11TEST_VENDOR_PREFER=vendor`
- TOML: `vendor = "ibm"`, `vendor_prefer = "standard"`

### Fixtures

```python
# fixtures.py

@pytest.fixture(scope="session")
def mechanism_resolver(p11_module, p11_config) -> MechanismResolver:
    """Resolver that maps standard mechanisms to what this module supports."""
    slot = p11_module.get_slots(token_present=True)[p11_config.slot]
    available = {int(m) for m in slot.get_mechanisms()}
    profiles = load_vendor_profiles(p11_config.vendor, available)
    return MechanismResolver(profiles, available, prefer=p11_config.vendor_prefer)

@pytest.fixture(scope="session")
def vendor_mechanism(mechanism_resolver) -> Callable:
    """Remap a standard Mechanism/KeyType to what this module supports.

    Usage: actual_mech = vendor_mechanism(Mechanism.ML_DSA)
    Returns the input unchanged when no vendor profile is active.
    """
    def _remap(m):
        if isinstance(m, KeyType):
            for profile in mechanism_resolver.profiles:
                v = profile.keytype_map.get(int(m))
                if v:
                    return KeyType(v)
            return m
        actual, _ = mechanism_resolver.resolve_mechanism(int(m))
        return Mechanism(actual) if actual else m
    return _remap

@pytest.fixture(scope="session")
def resolve_algorithm(mechanism_resolver) -> Callable:
    """Resolve a standard algorithm name to a full ResolvedContext."""
    return mechanism_resolver.resolve_algorithm
```

### Vendor-Aware `has_mechanism()`

```python
# testcases/conftest.py — updated

def has_mechanism(p11_module: Any, name: str, *,
                  slot_index: int = 0,
                  resolver: MechanismResolver | None = None) -> bool:
    """Check if a PKCS#11 module supports a named mechanism.

    Vendor-aware: when a resolver is provided, also checks for
    vendor equivalents of the named mechanism.

    Args:
        slot_index: Slot to check (default 0; pass p11_config.slot for NSS etc.)
        resolver: Optional MechanismResolver for vendor alias lookup.
    """
    slot = p11_module.get_slots(token_present=True)[slot_index]
    names = {mech_name(m) for m in slot.get_mechanisms()}
    if name in names:
        return True
    # Check vendor aliases
    if resolver and resolver.has_profiles():
        standard = getattr(Mechanism, name, None)
        if standard is not None:
            actual, _ = resolver.resolve_mechanism(int(standard))
            return actual is not None
    return False
```

No module-level globals. The resolver is passed explicitly via the optional `resolver` parameter. Tests that use `vendor_mechanism` fixture already have access to the resolver and can pass it. Tests without vendor support call `has_mechanism(module, "AES_GCM")` unchanged.

### Vendor-Aware `@needs_mechanism` Marker

```python
# plugin.py — updated _runtime_skip_reason()

# The resolver is stashed in config during pytest_collection_finish,
# alongside the existing capability manifest:
#
#   def pytest_collection_finish(session):
#       manifest = run_preflight_subprocess(...)
#       config.stash[_MANIFEST_KEY] = manifest
#       profiles = load_vendor_profiles(vendor_opt, set(manifest.mechanism_ids))
#       config.stash[_RESOLVER_KEY] = MechanismResolver(profiles, ...)

def _runtime_skip_reason(item, config, manifest, resolver):
    marker = item.get_closest_marker("needs_mechanism")
    if marker and marker.args:
        needed = str(marker.args[0])
        # Check standard name in manifest
        if needed in manifest.mechanisms:
            return None
        # Check vendor aliases via resolver
        if resolver and resolver.has_profiles():
            standard = getattr(Mechanism, needed, None)
            if standard is not None:
                actual, _ = resolver.resolve_mechanism(int(standard))
                if actual is not None:
                    return None
        return f"Mechanism {needed} not supported (standard or vendor)"
    # ... rest of skip logic unchanged ...

# Call site in pytest_runtest_setup:
#   manifest = config.stash[_MANIFEST_KEY]
#   resolver = config.stash.get(_RESOLVER_KEY)
#   reason = _runtime_skip_reason(item, config, manifest, resolver)
```

### `@vendor` Marker

```python
# markers.py — add:
MarkerDef("vendor", "Vendor-specific extension test (requires --p11-vendor)")
```

```python
# plugin.py — skip vendor-marked tests when vendor doesn't match
marker = item.get_closest_marker("vendor")
if marker and marker.args:
    required_vendor = str(marker.args[0])
    active_vendor = config.getoption("p11_vendor", "none")
    if active_vendor == "none":
        return f"Vendor test requires --p11-vendor={required_vendor}"
    if active_vendor != "auto" and active_vendor != required_vendor:
        return f"Vendor test requires --p11-vendor={required_vendor}, got {active_vendor}"
    # For auto: check if vendor was detected
    if active_vendor == "auto" and resolver:
        if not any(p.name == required_vendor for p in resolver.profiles):
            return f"Vendor {required_vendor} not detected in auto mode"
```

### Preflight Manifest Enhancement

```python
# core/preflight.py — add mechanism_ids field
@dataclass(frozen=True)
class CapabilityManifest:
    # ... existing fields ...
    mechanisms: list[str]        # Existing: ["AES_GCM", "0x80010036", ...]
    mechanism_ids: set[int]      # NEW: raw integer mechanism IDs
```

The resolver uses `mechanism_ids` (integers). The marker system first checks `mechanisms` (strings), then falls through to the resolver.

### Auto-Detection

When `--p11-vendor=auto`:

```python
def auto_detect_vendor(available: set[int]) -> list[VendorProfile]:
    """Auto-detect vendor profile(s) from mechanism list."""
    candidates = []
    for profile in ALL_PROFILES:
        overlap = profile.fingerprint & available
        if len(overlap) >= 3:  # Minimum 3 fingerprint matches
            candidates.append(profile)
    return candidates
```

## Layer 4: How Existing Tests Adapt

### Impact Assessment

| Test area | File count | Mechanism usage pattern | Update scope |
|-----------|-----------|------------------------|-------------|
| PQC sign/verify | 1 file | Via `_generate_ml_dsa_keypair()` helper | Update helper + ~6 sign/verify calls |
| KEM | 1 file | Via `_generate_ml_kem_keypair()` helper | Update helper + ~4 encap/decap calls |
| Wycheproof ML-DSA | 2 files | Via `create_object({KEY_TYPE: ...})` | Update key import + verify helper |
| Wycheproof ML-KEM | 1 file | Via `create_object()` + encap/decap | Update key import helper |
| ACVP ML-DSA/SLH-DSA | 2 files | Similar to Wycheproof | Update helpers |
| CCTV ML-DSA | 1 file | Via helper function | Update helper |
| SHA-3 | 1 file | `session.digest(mechanism=...)` | ~5 direct calls |
| EdDSA | 1 file | `sign()/verify(mechanism=...)` | ~8 direct calls |
| **All other tests** | **~90 files** | Standard mechanisms only | **No changes** |

Total: ~8-10 helper functions + ~40 direct mechanism references across ~18 files. Note: SHA-3 in compound mechanisms (e.g., `SHA3_256_RSA_PKCS_PSS`) is out of scope for vendor remapping — only standalone SHA-3 digest calls are remapped. CKR test files that reference PQC mechanisms also need updates.

### Example: PQC Test Update

**Before (standard only):**
```python
def _generate_ml_dsa_keypair(session, param_set=None):
    effective_param = int(param_set or MLDsaParameterSet.ML_DSA_65)
    return session.generate_keypair(
        KeyType.ML_DSA,
        mechanism=Mechanism.ML_DSA_KEY_PAIR_GEN,
        public_template={
            Attribute.VERIFY: True,
            Attribute.PARAMETER_SET: effective_param,
            Attribute.TOKEN: False,
        },
        private_template={
            Attribute.SIGN: True,
            Attribute.PARAMETER_SET: effective_param,
            Attribute.TOKEN: False,
        },
    )

def test_ml_dsa_sign(self, p11_session, p11_module):
    if not has_mechanism(p11_module, "ML_DSA"):
        pytest.skip("ML-DSA not supported")
    pub, priv = _generate_ml_dsa_keypair(p11_session)
    sig = priv.sign(_PLAINTEXT, mechanism=Mechanism.ML_DSA)
    assert pub.verify(_PLAINTEXT, sig, mechanism=Mechanism.ML_DSA)
```

**After (standard + vendor):**
```python
def _generate_ml_dsa_keypair(session, remap=None, param_set=None):
    effective_param = int(param_set or MLDsaParameterSet.ML_DSA_65)
    mech = Mechanism.ML_DSA_KEY_PAIR_GEN
    kt = KeyType.ML_DSA
    if remap:
        mech, kt = remap(mech), remap(kt)
    return session.generate_keypair(
        kt,
        mechanism=mech,
        public_template={
            Attribute.VERIFY: True,
            Attribute.PARAMETER_SET: effective_param,
            Attribute.TOKEN: False,
        },
        private_template={
            Attribute.SIGN: True,
            Attribute.PARAMETER_SET: effective_param,
            Attribute.TOKEN: False,
        },
    )

def test_ml_dsa_sign(self, p11_session, p11_module, vendor_mechanism):
    if not has_mechanism(p11_module, "ML_DSA"):
        pytest.skip("ML-DSA not supported")
    mech = vendor_mechanism(Mechanism.ML_DSA)
    pub, priv = _generate_ml_dsa_keypair(p11_session, remap=vendor_mechanism)
    sig = priv.sign(_PLAINTEXT, mechanism=mech)
    assert pub.verify(_PLAINTEXT, sig, mechanism=mech)
```

**Backward compatibility:** When `--p11-vendor=none`, `vendor_mechanism()` is the identity function — returns the input unchanged. `has_mechanism()` behaves exactly as before. Zero behavior change for existing users.

## Layer 5: Vendor-Only Tests

```
testcases/vendor/
  conftest.py              # skip-if-no-vendor, vendor_profile fixture
  ibm/
    conftest.py            # ibm_helpers fixture, IBM-specific param builders
    test_btc_derive.py     # Bitcoin key derivation (CKM_IBM_BTC_DERIVE)
    test_hybrid_kem.py     # ML-KEM + ECDH hybrid (CKM_IBM_ML_KEM_WITH_ECDH)
    test_ibm_pqc.py        # IBM PQC with vendor-specific parameter handling
```

Vendor-only tests use `@pytest.mark.vendor("ibm")` and reference vendor mechanisms directly:

```python
@pytest.mark.vendor("ibm")
@pytest.mark.needs_mechanism("0x80070001")
def test_btc_derive(p11_session, ibm_helpers):
    """Test IBM Bitcoin key derivation (CKM_IBM_BTC_DERIVE)."""
    ...
```

## CLI Behavior Matrix

| Flag combination | Behavior |
|-----------------|----------|
| `--p11-vendor=none` (default) | Standard mechanisms only. Zero behavior change. Vendor tests skipped. |
| `--p11-vendor=ibm` | IBM profile active. Standard preferred, vendor as fallback. IBM vendor tests run. |
| `--p11-vendor=ibm --p11-vendor-prefer=vendor` | IBM profile active. Vendor preferred, standard as fallback. Useful for testing vendor code paths on modules with dual support. |
| `--p11-vendor=auto` | Auto-detect from mechanism fingerprints. Matched vendor tests run. |
| `--p11-vendor=auto --p11-vendor-prefer=vendor` | Auto-detect + prefer vendor mechanisms. |

Running the suite twice (once with `--p11-vendor-prefer=standard`, once with `vendor`) tests both code paths on modules with dual mechanism support.

## Evolution Tracking

When a vendor mechanism becomes standardized (IBM Dilithium → ML-DSA), the profile's `[migrations]` section expresses this. The system can:

1. Test the standard path (`CKM_ML_DSA`) on modules supporting v3.2
2. Test the vendor path (`CKM_IBM_DILITHIUM`) via `--p11-vendor-prefer=vendor`
3. Verify behavioral equivalence by comparing results from both paths (future Phase 2)

## Error Handling

- **Unknown `--p11-vendor` name**: `pytest.exit()` with message listing available profiles (ibm, aws, qryptotoken, none, auto).
- **Malformed `profile.toml`**: `pytest.exit()` with TOML parse error and file path.
- **Unknown mechanism name in TOML `[mechanisms]`**: `pytest.exit()` listing the bad key and available `Mechanism` enum members.
- **Auto-detect finds nothing**: No profiles loaded, `resolver.has_profiles()` returns False. Tests run with standard mechanisms only (same as `--p11-vendor=none`). No error — this is expected on modules without vendor mechanisms.
- **Vendor mechanism available but operation fails**: Test fails normally (module bug or parameter mismatch). No special handling — this is the purpose of testing.

## Preflight Manifest Serialization

The `mechanism_ids` field is serialized as a JSON list of integers (Python `set` is not JSON-serializable):

```python
# In probe_capabilities():
mechanism_ints = sorted(int(m) for m in slots[slot].get_mechanisms())
# Serialized as: {"mechanism_ids": [257, 258, ...]}

# In manifest loader:
manifest.mechanism_ids = set(data.get("mechanism_ids", []))
```

## Validation Target

Phase 1 validation uses OpenCryptoki Docker with the **software token** (`swtok`). The software token via OpenSSL backend does report IBM vendor mechanisms (SHA-3 variants, CMAC). EP11-specific mechanisms (Dilithium, Kyber, BTC_DERIVE) require EP11 hardware and are Phase 2. The IBM PQC mechanisms (`CKM_IBM_ML_DSA`, `CKM_IBM_ML_KEM`) may or may not be available in swtok depending on OpenCryptoki version and OpenSSL capabilities — if unavailable, those vendor-only tests are skipped (clean skip, not failure).

## Future Phase 2 (Not in this plan)

- **Full session wrapper**: transparent mechanism/keytype/attribute substitution at the session level, zero test changes needed
- **`--p11-vendor-mode=both`**: parametrize tests to run with standard AND vendor mechanisms in one run
- **AWS, Thales, nShield, NSS profiles**: extend beyond IBM
- **Vendor-specific parameter structures**: IBM ECIES, nShield nested params, etc.
- **Migration comparison tests**: verify standard and vendor mechanisms produce identical results

## Implementation Scope (Phase 1)

Ordered by dependency:

1. python-pkcs11 fork: `_missing_` on Mechanism/KeyType/Attribute/ObjectClass + isinstance relaxation + `defaults.py` `.get()` fallbacks
2. VendorProfile dataclass + TOML loader (`vendors/__init__.py`) with error handling
3. MechanismResolver + ResolvedContext with `map_template()` value remapping (`vendors/_resolver.py`)
4. IBM profile (`vendors/ibm/profile.toml` + `helpers.py`)
5. Config: `--p11-vendor` and `--p11-vendor-prefer` options with validation
6. Fixtures: `mechanism_resolver`, `vendor_mechanism`, `resolve_algorithm`
7. Vendor-aware `has_mechanism()` in `testcases/conftest.py` (accepts resolver param + slot_index)
8. Vendor-aware `@needs_mechanism` + `@vendor` marker in `plugin.py` (resolver stashed in config)
9. Preflight manifest: add `mechanism_ids: list[int]` field with JSON serialization
10. Update ~8-10 PQC/Wycheproof/ACVP helper functions to accept `vendor_mechanism` remap
11. Update ~40 direct mechanism references across ~18 test files
12. 2-3 IBM vendor-only tests under `testcases/vendor/ibm/`
13. Docker OpenCryptoki swtok validation: run updated tests with `--p11-vendor=ibm`
