# Raw Layer Remaining Gaps — Implementation Plan

**Goal:** Complete pkcs11_check.raw so ALL test files can migrate away from the
python-pkcs11 fork. Every helper must be DRY, KISS, and independently testable.

**Prerequisite:** Sub-project 2 (Raw Layer Completion) is done. This plan covers
the remaining gaps identified by deep analysis of 195 test files.

**Design principles (enforce throughout):**
- Extract shared patterns into internal `_helpers` — never duplicate 3+ lines
- Every public function gets a meta-test (importable, callable, correct signature)
- Integration tests against SoftHSM2 for every recipe that touches C_* calls
- No policy in raw — no default attributes, no auto mechanism selection
- CKR values are data, not exceptions — recipes use `expect_rv()`, tests assert directly

**References:**
- `src/pkcs11_check/raw/README.md` — raw package contract
- `docs/superpowers/specs/2026-03-23-pkcs11-raw-architecture-design.md` — architecture
- `CLAUDE.md` — project rules, commands, test patterns

---

## Existing shared helpers (use these, don't reinvent)

```python
# pack.py — already extracted
_pack_bytes(data, keepalive) -> (void_ptr, length)  # bytes → ctypes buffer
_mech_struct(mech_type, params, origin, keepalive)   # struct → PackedMechanism

# recipes.py — already extracted
_pack_attrs(attrs, skip=)   -> list[PackedAttribute]  # dict → packed attrs
_gen_keypair(raw, session, mechanism, pub_base, priv_base, ...)  # shared keygen
```

---

## Phase 1: Two-call output dedup + core recipes

**Why first:** Every Tier 1 recipe uses the two-call output buffer pattern.
Extract it once, then all recipes become 3-5 lines each.

### Step 1.1: Extract `_two_call_output` helper in recipes.py

The pattern repeated in encrypt_single, decrypt_single, sign_single, digest_single:
```
1. Call C_*Init with mechanism
2. Call C_* with NULL output → get size
3. Allocate buffer
4. Call C_* with buffer → get result
```

Add to recipes.py:
```python
def _two_call_output(
    raw: RawPKCS11,
    session: int,
    call_fn: str,      # e.g. "C_Encrypt"
    *args: Any,         # input args before output buffer
) -> bytes:
    """Execute a PKCS#11 function using the standard two-call size pattern."""
    fn = getattr(raw, call_fn)
    out_len = CK_ULONG(0)
    rv = fn(session, *args, None, byref(out_len))
    expect_rv(int(rv), CKR_OK)
    out_buf = (ctypes.c_ubyte * out_len.value)()
    rv = fn(session, *args, out_buf, byref(out_len))
    expect_rv(int(rv), CKR_OK)
    return bytes(out_buf[:out_len.value])
```

Then refactor encrypt_single, decrypt_single, sign_single, digest_single to use it.

**Tests:** Verify all 4 refactored recipes still pass existing tests.

### Step 1.2: Add `wrap_key` recipe

```python
def wrap_key(
    raw: RawPKCS11,
    session: int,
    wrapping_key: int,
    target_key: int,
    mechanism: CKM,
    *,
    mech_param: PackedMechanism | None = None,
) -> bytes:
```
Uses C_WrapInit is not needed — C_WrapKey is single-call with two-call output.

**Tests:** Meta-test (callable). Integration test with SoftHSM2 AES key wrapping.

### Step 1.3: Add `unwrap_key` recipe

```python
def unwrap_key(
    raw: RawPKCS11,
    session: int,
    unwrapping_key: int,
    wrapped_key: bytes,
    mechanism: CKM,
    attrs: dict[int, Any] | None = None,
    *,
    mech_param: PackedMechanism | None = None,
) -> int:
```

**Tests:** Meta-test. Integration: wrap then unwrap, verify key value matches.

### Step 1.4: Add `derive_key` recipe

```python
def derive_key(
    raw: RawPKCS11,
    session: int,
    base_key: int,
    mechanism: CKM,
    attrs: dict[int, Any] | None = None,
    *,
    mech_param: PackedMechanism | None = None,
) -> int:
```

**Tests:** Meta-test. Integration: ECDH key derivation, HKDF derivation.

### Step 1.5: Add `generate_random` recipe

```python
def generate_random(raw: RawPKCS11, session: int, length: int) -> bytes:
```

Simple — single C_GenerateRandom call.

**Tests:** Meta-test. Integration: generate 32 bytes, verify length.

### Step 1.6: Add `copy_object` recipe

```python
def copy_object(
    raw: RawPKCS11,
    session: int,
    handle: int,
    attrs: dict[int, Any] | None = None,
) -> int:
```

**Tests:** Meta-test. Integration: copy AES key, verify attributes match.

### Step 1.7: Add `set_attributes` recipe

```python
def set_attributes(
    raw: RawPKCS11,
    session: int,
    handle: int,
    attrs: dict[int, Any],
) -> None:
```

Uses `_pack_attrs` (already exists) + C_SetAttributeValue.

**Tests:** Meta-test. Integration: set label, read back.

### Step 1.8: Multi-part operation helpers

Add to recipes.py — these follow the Init/Update/Final pattern:

```python
def encrypt_multipart(raw, session, key, mechanism, chunks, *, mech_param=None) -> bytes:
def decrypt_multipart(raw, session, key, mechanism, chunks, *, mech_param=None) -> bytes:
def sign_multipart(raw, session, key, mechanism, chunks, *, mech_param=None) -> bytes:
def verify_multipart(raw, session, key, mechanism, chunks, signature, *, mech_param=None) -> bool:
def digest_multipart(raw, session, mechanism, chunks) -> bytes:
```

Each takes an iterable of `bytes` chunks. Internal pattern:
```python
def _multipart_output(raw, session, init_fn, update_fn, final_fn, key, mech, chunks):
    """Shared Init → Update(chunks) → Final pattern."""
```

**This is the key dedup** — one shared helper handles all 5 variants.

**Tests:** Meta-tests. Integration: encrypt in chunks, compare with single-shot.

### Step 1.9: Commit and verify

Run full meta-test suite + SoftHSM2 smoke test.

---

## Phase 2: Additional mechanism packers

### Step 2.1: Add mechanism packers to pack.py

All use the existing `_pack_bytes` + `_mech_struct` pattern:

```python
def mech_cbc_pad(mechanism_type: CKM, iv: bytes) -> PackedMechanism:
    """Pack 16-byte IV for AES-CBC-PAD / AES-CBC."""

def mech_ctr(mechanism_type: CKM, bits: int = 128) -> PackedMechanism:
    """Pack CK_AES_CTR_PARAMS."""

def mech_chacha20(mechanism_type: CKM, nonce: bytes, counter: int = 0) -> PackedMechanism:
    """Pack CK_CHACHA20_PARAMS."""

def mech_chacha20_poly1305(mechanism_type: CKM, nonce: bytes, aad: bytes | None = None) -> PackedMechanism:
    """Pack CK_SALSA20_CHACHA20_POLY1305_PARAMS."""

def mech_eddsa(mechanism_type: CKM, *, context_data: bytes | None = None) -> PackedMechanism:
    """Pack CK_EDDSA_PARAMS (optional context for Ed448)."""

def mech_pbkdf2(mechanism_type: CKM, *, salt: bytes, iterations: int,
                 prf: int, password: bytes | None = None) -> PackedMechanism:
    """Pack CK_PKCS5_PBKD2_PARAMS2."""

def mech_string_data(mechanism_type: CKM, data: bytes) -> PackedMechanism:
    """Pack CK_KEY_DERIVATION_STRING_DATA (for DES/AES CBC-encrypt-data derive)."""
```

Each is 5-10 lines using `_pack_bytes` and `_mech_struct`.

**Tests:** One test per packer verifying struct fields match inputs.

### Step 2.2: Commit and verify

---

## Phase 3: DER/ASN.1 encoding utilities

**File:** `src/pkcs11_check/raw/der.py` (new)

These are needed for Wycheproof/cross-verify test migration. Keep them minimal —
only what PKCS#11 tests actually need, not a full ASN.1 library.

### Step 3.1: ECDSA signature format conversion

```python
def ecdsa_sig_to_der(r: int, s: int) -> bytes:
    """Encode (r, s) integers as DER ASN.1 SEQUENCE { INTEGER, INTEGER }."""

def ecdsa_sig_from_der(der: bytes) -> tuple[int, int]:
    """Decode DER ECDSA signature to (r, s) integers."""

def ecdsa_sig_p1363_to_der(raw_sig: bytes) -> bytes:
    """Convert PKCS#11 P1363 format (r||s) to DER."""

def ecdsa_sig_der_to_p1363(der_sig: bytes, key_size: int) -> bytes:
    """Convert DER to PKCS#11 P1363 format (r||s)."""
```

Implementation: hand-written minimal DER encoder/decoder. No asn1crypto dependency.
DER INTEGER encoding is 10-15 lines (tag + length + sign-padded big-endian bytes).

**Tests:** Round-trip tests with known vectors from Wycheproof.

### Step 3.2: EC point encoding/decoding

```python
def encode_ec_point(x: int, y: int, key_size: int) -> bytes:
    """Encode EC point as DER OCTET STRING wrapping uncompressed 0x04||x||y."""

def decode_ec_point(der: bytes) -> bytes:
    """Unwrap DER OCTET STRING to raw point bytes (0x04||x||y)."""
```

Note: `decode_ec_point` already exists as `extract_ec_point` in testcases/conftest.py.
Move it to `der.py` and have conftest import from there.

**Tests:** Known P-256 point encode/decode.

### Step 3.3: RSA key DER encoding

```python
def encode_rsa_public_key_der(modulus: bytes, exponent: bytes) -> bytes:
    """Encode RSA public key as PKCS#1 DER (SEQUENCE { INTEGER, INTEGER })."""

def decode_rsa_public_key_der(der: bytes) -> tuple[bytes, bytes]:
    """Decode PKCS#1 DER to (modulus, exponent) bytes."""
```

Same minimal DER approach — no full X.509 support needed.

**Tests:** Known RSA-2048 key encode/decode.

### Step 3.4: Commit and verify

---

## Phase 4: Operation state and remaining recipes

### Step 4.1: Operation state recipes

```python
def save_operation_state(raw: RawPKCS11, session: int) -> bytes:
    """C_GetOperationState — two-call output pattern."""

def restore_operation_state(
    raw: RawPKCS11, session: int, state: bytes,
    encrypt_key: int = 0, auth_key: int = 0,
) -> None:
    """C_SetOperationState."""
```

### Step 4.2: Token/PIN management recipes

```python
def init_token(raw: RawPKCS11, slot_id: int, so_pin: bytes, label: str) -> None:
def init_pin(raw: RawPKCS11, session: int, pin: bytes) -> None:
def set_pin(raw: RawPKCS11, session: int, old_pin: bytes, new_pin: bytes) -> None:
def seed_random(raw: RawPKCS11, session: int, seed: bytes) -> None:
```

### Step 4.3: Dual-function recipes (if any test needs them)

```python
def digest_encrypt_update(raw, session, data) -> bytes:
def decrypt_digest_update(raw, session, data) -> bytes:
def sign_encrypt_update(raw, session, data) -> bytes:
def decrypt_verify_update(raw, session, data) -> bytes:
```

Only add these if test_dual_function.py migration requires them.

### Step 4.4: Commit and verify

---

## Phase 5: Message-based + v3.2 operations (Tier 3)

Only implement these when specific test files need them during migration.

### Step 5.1: Message-based crypto helpers

```python
def message_encrypt(raw, session, key, mechanism, data, *, aad=None) -> tuple[bytes, bytes]:
    """Single-message encrypt returning (ciphertext, tag)."""

def message_decrypt(raw, session, key, mechanism, ciphertext, tag, *, aad=None) -> bytes:
    """Single-message decrypt with tag verification."""

# Similar for message_sign, message_verify
```

### Step 5.2: KEM operations (v3.2)

```python
def encapsulate_key(raw, session, pub_key, mechanism, attrs=None) -> tuple[int, bytes]:
    """C_EncapsulateKey — returns (secret_key_handle, ciphertext)."""

def decapsulate_key(raw, session, priv_key, mechanism, ciphertext, attrs=None) -> int:
    """C_DecapsulateKey — returns secret_key_handle."""
```

### Step 5.3: Authenticated wrapping (v3.2)

```python
def wrap_key_authenticated(raw, session, wrapping_key, target_key, mechanism, *,
                           mech_param=None) -> tuple[bytes, bytes]:
    """Returns (wrapped_key, tag)."""

def unwrap_key_authenticated(raw, session, unwrapping_key, wrapped_key, tag,
                             mechanism, attrs=None, *, mech_param=None) -> int:
```

### Step 5.4: Commit and verify

---

## Phase 6: Final cleanup

### Step 6.1: Update raw package `__init__.py` exports

Add all new public functions to `__all__`.

### Step 6.2: Update `raw/README.md`

Document all new recipes, packers, and DER helpers.

### Step 6.3: Remove deprecated compatibility modules

If `core.py`, `template.py`, `mechanism.py` are no longer imported anywhere,
delete them.

### Step 6.4: Full verification

```bash
uv run python -m pytest tests/ -q                    # all meta-tests
bash local-builds/test.sh softhsm2 -m smoke          # quick integration
uv tool run ruff check src/pkcs11_check/raw/          # lint
```

---

## Code quality checklist (apply to every phase)

- [ ] Every new function uses existing `_pack_bytes`, `_pack_attrs`, `_two_call_output` helpers
- [ ] No duplicate if/elif/else isinstance cascades — use `_pack_attrs`
- [ ] No duplicate two-call buffer code — use `_two_call_output`
- [ ] No duplicate Init/Update/Final code — use `_multipart_output`
- [ ] Every packer follows the `_mech_struct(type, params, origin, keepalive)` pattern
- [ ] Every recipe takes `mech_param: PackedMechanism | None = None` for struct mechanisms
- [ ] Meta-tests for every new public function (callable, correct arg count)
- [ ] Line length ≤ 100
- [ ] ruff clean
- [ ] Commit after each phase

## Estimated scope

| Phase | New functions | New lines (est.) | Dedup savings |
|-------|--------------|-------------------|---------------|
| 1 | 12 recipes + 2 helpers | ~150 | -60 (refactor existing) |
| 2 | 7 packers | ~70 | 0 (all use _pack_bytes) |
| 3 | 8 DER helpers | ~120 | 0 (new module) |
| 4 | 8 recipes | ~60 | 0 (use _two_call_output) |
| 5 | 6 recipes | ~80 | 0 (use _two_call_output) |
| 6 | 0 | -30 (cleanup) | -30 |
| **Total** | **41 functions** | **~450 net** | **-90** |
