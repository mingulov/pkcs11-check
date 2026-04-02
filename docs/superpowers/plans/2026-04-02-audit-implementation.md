# Audit Gap Implementation Plan

> **For agentic workers:** This plan is designed for ralph-loop autonomous execution. Execute tasks sequentially (1-10). Each task is one iteration — execute all steps, commit, move to next.

**Goal:** Implement fixes and new tests for header-verified gaps from the 42-iteration audit.

**Architecture:** Each iteration modifies specific files following existing codebase patterns (mechanism_registry, pack_mechanisms, test files). Tests use existing fixtures (p11_raw_session, gen_aes_key, sign_single, verify_single, etc.) and follow CLAUDE.md rules.

**Tech Stack:** Python 3.13+, pytest, ctypes PKCS#11 bindings, ruff, mypy --strict

**Spec:** `docs/superpowers/specs/2026-04-02-audit-implementation-design.md`

---

## Key Paths

| Resource | Path |
|----------|------|
| Pack mechanisms | `src/pkcs11_check/raw/pack_mechanisms.py` |
| Types/constants | `src/pkcs11_check/raw/types_std.py` |
| Mechanism registry | `src/pkcs11_check/testcases/mechanism_registry/` |
| Test files | `src/pkcs11_check/testcases/` |
| Audit reports | `docs/audit/` |

## Rules (from CLAUDE.md)

- NEVER skip real failures. NEVER bare `except Exception: pass`.
- Use `rs.has_mechanism()` for skip checks. Use `destroy_quietly` in finally blocks.
- Type annotations on all public functions. Line length: 100. `ruff` for formatting.
- Always use `uv run` prefix. Commit to `dev` branch.

---

## Task 1: Audit Report Corrections

**Files:**
- Modify: `docs/audit/00-index.md`
- Modify: `docs/audit/09-hash-functions.md`
- Modify: `docs/audit/10-mac-operations.md`
- Modify: `docs/audit/08-aead.md`
- Modify: `docs/audit/39-hss-xmss-domain.md`

- [ ] **Step 1: Fix 00-index.md Tier 1 section**

Replace the "Blocking gaps (need new bindings/infrastructure)" section with:

```markdown
**Closed — NOT in PKCS#11 v3.2 header (spec-only / future draft):**
1. ~~C_DigestXof* functions for SHAKE-128/256~~ — NOT in v3.2 pkcs11.h header
2. ~~CK_KMAC_PARAMS for KMAC-128/256~~ — NOT in v3.2 pkcs11.h header (zero KMAC references)
3. CK_SIGN_ADDITIONAL_CONTEXT pure variant param builder — IS in header, needs pack function for CKM_ML_DSA/CKM_SLH_DSA ACVP tests

**Audit corrections (items already implemented):**
- AES_GMAC: already has Wycheproof, ACVP, and message API tests (audit incorrectly said "zero coverage")
- HSS/XMSS: already have comprehensive tests in test_stateful_sigs.py + full registry entries
- CKM_NULL: already in mechanism_registry/_kdf.py
- mech_hash_sign_context: already exists in pack_mechanisms.py for CK_HASH_SIGN_ADDITIONAL_CONTEXT
```

- [ ] **Step 2: Fix 09-hash-functions.md**

Add correction note at top of Coverage Gaps section:

```markdown
**CORRECTION (2026-04-02):** CKM_SHAKE_128/256 as digest mechanisms and C_DigestXof* functions are NOT in the PKCS#11 v3.2 header. Only CKM_SHAKE_128/256_KEY_DERIVE exist. The OASIS spec markdown describes future/draft functionality not yet standardized. These gaps are CLOSED as "not in v3.2".
```

- [ ] **Step 3: Fix 10-mac-operations.md**

Add correction note:

```markdown
**CORRECTION (2026-04-02):** CKM_KMAC128/KMAC256 and CK_KMAC_PARAMS are NOT in the PKCS#11 v3.2 header. Zero KMAC references exist in pkcs11.h. This was spec-only/future draft content. These gaps are CLOSED as "not in v3.2".
```

- [ ] **Step 4: Fix 08-aead.md**

Add correction note for AES_GMAC:

```markdown
**CORRECTION (2026-04-02):** CKM_AES_GMAC already has test coverage in: test_wycheproof_aes.py:348 (Wycheproof), acvp/aes/test_gcm.py:203 (ACVP), test_mech_message.py:210 (message API). Original audit incorrectly stated "zero coverage".
```

- [ ] **Step 5: Fix 39-hss-xmss-domain.md**

Add correction note:

```markdown
**CORRECTION (2026-04-02):** HSS/XMSS/XMSSMT already have comprehensive tests in test_stateful_sigs.py and full registry entries in mechanism_registry/_pqc.py:397-437. Original audit incorrectly stated "no tests".
```

- [ ] **Step 6: Verify and commit**

```bash
uv run ruff check docs/ 2>&1 || true  # docs are markdown, just verify no accidental .py changes
git add docs/audit/00-index.md docs/audit/08-aead.md docs/audit/09-hash-functions.md docs/audit/10-mac-operations.md docs/audit/39-hss-xmss-domain.md
git commit -m "impl(01): correct audit reports — SHAKE/KMAC not in v3.2, GMAC/HSS already tested"
```

---

## Task 2: Mechanism Registry — SHA3/SHAKE KEY_DERIVE

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_registry/_kdf.py`

- [ ] **Step 1: Read existing _kdf.py to find the right insertion point**

Read the file to understand the structure and find where hash-based derive mechanisms should go. These mechanisms use `CK_KEY_DERIVATION_STRING_DATA` as parameter — same as `mech_string_data()` in pack_mechanisms.py.

- [ ] **Step 2: Add imports for SHA3/SHAKE KEY_DERIVE constants**

Add to the imports section of `_kdf.py`:

```python
    CKM_SHA3_224_KEY_DERIVE,
    CKM_SHA3_256_KEY_DERIVE,
    CKM_SHA3_384_KEY_DERIVE,
    CKM_SHA3_512_KEY_DERIVE,
    CKM_SHAKE_128_KEY_DERIVE,
    CKM_SHAKE_256_KEY_DERIVE,
```

- [ ] **Step 3: Add registry entries**

Add 6 entries following the existing pattern. These are simple hash-based key derivation mechanisms — they derive a key by hashing input data with the respective digest. Parameter is `CK_KEY_DERIVATION_STRING_DATA` (packed via `mech_string_data`).

```python
    # -- SHA-3 / SHAKE hash-based key derivation --------------------------------

    _sha3_derive_base = dict(
        key_type=CKK_GENERIC_SECRET,
        keygen_mech=CKM_GENERIC_SECRET_KEY_GEN,
        key_sizes=(256,),
        param_required=True,
        param_recipe=ParamRecipe("string_data", {"data": b"\x00" * 32}),
        keygen_recipe=ParamRecipe("secret_key", {"key_len": 32}),
        expected_flags=MechFlags(derive=True),
    )

    for _ckm, _note in [
        (CKM_SHA3_224_KEY_DERIVE, "SHA3-224 hash-based key derivation"),
        (CKM_SHA3_256_KEY_DERIVE, "SHA3-256 hash-based key derivation"),
        (CKM_SHA3_384_KEY_DERIVE, "SHA3-384 hash-based key derivation"),
        (CKM_SHA3_512_KEY_DERIVE, "SHA3-512 hash-based key derivation"),
        (CKM_SHAKE_128_KEY_DERIVE, "SHAKE-128 hash-based key derivation"),
        (CKM_SHAKE_256_KEY_DERIVE, "SHAKE-256 hash-based key derivation"),
    ]:
        registry[_ckm] = MechConfig(**_sha3_derive_base, notes=_note)
```

**Note:** Read the actual file first to verify `MechConfig`, `MechFlags`, `ParamRecipe` field names and the existing pattern for derive mechanisms. Adjust the code above to match whatever pattern exists. The critical thing is that these 6 mechanisms get registered with `param_recipe=ParamRecipe("string_data", ...)` so mechanism-driven tests can exercise them.

- [ ] **Step 4: Verify imports resolve**

```bash
uv run ruff check src/pkcs11_check/testcases/mechanism_registry/_kdf.py
```

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/testcases/mechanism_registry/_kdf.py
git commit -m "impl(02): add SHA3/SHAKE KEY_DERIVE to mechanism registry (6 mechanisms)"
```

---

## Task 3: CK_SIGN_ADDITIONAL_CONTEXT Pack Function

**Files:**
- Modify: `src/pkcs11_check/raw/pack_mechanisms.py`

- [ ] **Step 1: Read pack_mechanisms.py to understand the pattern**

Read lines 781-803 where `mech_hash_sign_context` is implemented. The new function `mech_sign_context` follows the same pattern but uses `CK_SIGN_ADDITIONAL_CONTEXT` (no `hash` field) instead of `CK_HASH_SIGN_ADDITIONAL_CONTEXT`.

- [ ] **Step 2: Add import for CK_SIGN_ADDITIONAL_CONTEXT**

In the imports at the top of `pack_mechanisms.py`, add:

```python
    CK_SIGN_ADDITIONAL_CONTEXT,
```

(next to the existing `CK_HASH_SIGN_ADDITIONAL_CONTEXT` import)

- [ ] **Step 3: Add mech_sign_context function**

Insert before the `__all__` list:

```python
def mech_sign_context(
    mechanism_type: CKM,
    *,
    hedge: int | None = None,
    context: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_SIGN_ADDITIONAL_CONTEXT for CKM_ML_DSA / CKM_SLH_DSA (pure).

    For hash-and-sign variants (CKM_HASH_ML_DSA, CKM_HASH_SLH_DSA), use
    ``mech_hash_sign_context`` instead — it has a ``hash`` field.
    ``hedge`` defaults to CKH_HEDGE_PREFERRED.
    """
    ka: list[Any] = []
    params = CK_SIGN_ADDITIONAL_CONTEXT()
    params.hedgeVariant = int(CKH_HEDGE_PREFERRED) if hedge is None else hedge
    if context is not None:
        params.pContext, params.ulContextLen = _pack_bytes(context, ka)
    else:
        params.pContext = None
        params.ulContextLen = 0
    return _mech_struct(mechanism_type, params, "mech_sign_context", ka)
```

- [ ] **Step 4: Add to __all__**

Add `"mech_sign_context"` to the `__all__` list (alphabetical order, after `"mech_rc2_cbc"`).

- [ ] **Step 5: Verify**

```bash
uv run ruff check src/pkcs11_check/raw/pack_mechanisms.py
```

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/raw/pack_mechanisms.py
git commit -m "impl(03): add mech_sign_context for CK_SIGN_ADDITIONAL_CONTEXT (pure ML-DSA/SLH-DSA)"
```

---

## Task 4: Fix ML-DSA ACVP Context Passing

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py`

- [ ] **Step 1: Read the ACVP ML-DSA test file**

Read `acvp/test_acvp_mldsa.py` around lines 180-260 to understand the current TODO and how sign/verify are called.

- [ ] **Step 2: Import the new pack function**

Add import:

```python
from pkcs11_check.raw.pack_mechanisms import mech_sign_context
```

- [ ] **Step 3: Fix siggen context passing (line ~185)**

Replace the TODO block with context-passing code. The key pattern: if `vec["context"]` is non-empty, pass it via `mech_sign_context`; otherwise use plain mechanism.

Read the exact code structure first, then modify the sign call to use:

```python
context = bytes.fromhex(vec.get("context", ""))
if context:
    mech_param = mech_sign_context(mech_id, context=context)
    # use mech_param in sign call
```

**Important:** Read the actual code to see how the mechanism is passed to the sign function. The pattern varies — some use `sign_single()` directly with a CKM constant, others use `mech_param`. Adapt to match.

- [ ] **Step 4: Fix sigver context passing (line ~257)**

Same pattern for the verify path.

- [ ] **Step 5: Remove the TODO comments**

Delete the `# TODO: pass vec["context"] via CK_SIGN_ADDITIONAL_CONTEXT` comments.

- [ ] **Step 6: Verify**

```bash
uv run ruff check src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py
```

- [ ] **Step 7: Commit**

```bash
git add src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py
git commit -m "impl(04): pass ACVP ML-DSA context via mech_sign_context, remove TODO"
```

---

## Task 5: Hedge Variant Tests

**Files:**
- Modify: `src/pkcs11_check/testcases/test_pqc_sign.py`

- [ ] **Step 1: Read test_pqc_sign.py**

Read the existing ML-DSA sign test class to understand the pattern.

- [ ] **Step 2: Add hedge variant test class**

Add a new test class that exercises the three hedge variants via `mech_sign_context`:

```python
class TestMLDSAHedgeVariants:
    """Test ML-DSA signing with explicit hedge variants."""

    def test_hedge_preferred(self, p11_raw_session: Any) -> None:
        """CKH_HEDGE_PREFERRED — default randomized signing."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_DSA"):
            pytest.skip("ML_DSA not supported")
        # Generate ML-DSA keypair, sign with hedge=CKH_HEDGE_PREFERRED
        # Verify signature

    def test_hedge_required(self, p11_raw_session: Any) -> None:
        """CKH_HEDGE_REQUIRED — must use randomization."""
        # Same pattern, hedge=int(CKH_HEDGE_REQUIRED)

    def test_deterministic_required(self, p11_raw_session: Any) -> None:
        """CKH_DETERMINISTIC_REQUIRED — must be deterministic."""
        # Same pattern, hedge=int(CKH_DETERMINISTIC_REQUIRED)
        # Verify same input produces same signature (deterministic)
```

**Important:** Read the existing keygen + sign pattern in the file first. Use existing helpers like `gen_keypair`, `sign_single`, `verify_single`, `destroy_quietly`. Import `mech_sign_context` and `CKH_HEDGE_PREFERRED`, `CKH_HEDGE_REQUIRED`, `CKH_DETERMINISTIC_REQUIRED` from types_std.

- [ ] **Step 3: Verify**

```bash
uv run ruff check src/pkcs11_check/testcases/test_pqc_sign.py
```

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/testcases/test_pqc_sign.py
git commit -m "impl(05): add ML-DSA hedge variant tests (preferred/required/deterministic)"
```

---

## Task 6: CKM_AES_MAC Functional Tests

**Files:**
- Modify: `src/pkcs11_check/testcases/test_aes_modes.py`

- [ ] **Step 1: Read test_aes_modes.py MAC section**

Read the existing `CKM_AES_MAC_GENERAL` tests (around line 405+) to understand the pattern.

- [ ] **Step 2: Add CKM_AES_MAC tests**

Add a test class for the fixed-output variant. CKM_AES_MAC produces exactly 8 bytes (half AES block). It takes no parameter (unlike MAC_GENERAL which takes CK_MAC_GENERAL_PARAMS).

```python
class TestAESMAC:
    """CKM_AES_MAC — fixed 8-byte (half-block) CBC-MAC."""

    def test_sign_verify_roundtrip(self, p11_raw_session: Any) -> None:
        """Sign and verify with CKM_AES_MAC."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_MAC"):
            pytest.skip("AES_MAC not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            data = b"AES-MAC test data for roundtrip verification"
            sig = sign_single(rs.raw, rs.sh, key, CKM_AES_MAC, data)
            assert len(sig) == 8, f"AES-MAC output must be 8 bytes, got {len(sig)}"
            ok = verify_single(rs.raw, rs.sh, key, CKM_AES_MAC, data, sig)
            assert ok is True
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_tamper_detection(self, p11_raw_session: Any) -> None:
        """Modified data must fail verification."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_MAC"):
            pytest.skip("AES_MAC not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            sig = sign_single(rs.raw, rs.sh, key, CKM_AES_MAC, b"original")
            ok = verify_single(rs.raw, rs.sh, key, CKM_AES_MAC, b"tampered", sig)
            assert ok is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_different_keys(self, p11_raw_session: Any) -> None:
        """Different keys produce different MACs."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_MAC"):
            pytest.skip("AES_MAC not supported")
        k1 = gen_aes_key(rs.raw, rs.sh, 256)
        k2 = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            data = b"same data different keys"
            sig1 = sign_single(rs.raw, rs.sh, k1, CKM_AES_MAC, data)
            sig2 = sign_single(rs.raw, rs.sh, k2, CKM_AES_MAC, data)
            assert sig1 != sig2
        finally:
            destroy_quietly(rs.raw, rs.sh, k1)
            destroy_quietly(rs.raw, rs.sh, k2)
```

**Important:** Read the actual file first to verify `sign_single`, `verify_single`, `gen_aes_key`, `destroy_quietly` import locations and calling conventions. Add necessary imports. Ensure `CKM_AES_MAC` is imported from `types_std`.

- [ ] **Step 3: Verify**

```bash
uv run ruff check src/pkcs11_check/testcases/test_aes_modes.py
```

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/testcases/test_aes_modes.py
git commit -m "impl(06): add CKM_AES_MAC functional tests (sign/verify, tamper, key independence)"
```

---

## Task 7: SHA3/SHAKE Key Derivation Tests

**Files:**
- Modify: `src/pkcs11_check/testcases/test_kdf.py` or create new file

- [ ] **Step 1: Read test_kdf.py to understand derive test patterns**

Read `test_kdf.py` and `test_mech_derive.py` to see how key derivation tests work. The pattern is typically: generate a base key → call C_DeriveKey with the mechanism → verify derived key is functional.

- [ ] **Step 2: Add SHA3/SHAKE key derivation tests**

These mechanisms use `CK_KEY_DERIVATION_STRING_DATA` (packed via `mech_string_data`). They derive a key by hashing input data.

```python
class TestSHA3KeyDerive:
    """SHA3/SHAKE hash-based key derivation mechanisms."""

    @pytest.mark.parametrize("mech_name,ckm", [
        ("SHA3_224_KEY_DERIVE", CKM_SHA3_224_KEY_DERIVE),
        ("SHA3_256_KEY_DERIVE", CKM_SHA3_256_KEY_DERIVE),
        ("SHA3_384_KEY_DERIVE", CKM_SHA3_384_KEY_DERIVE),
        ("SHA3_512_KEY_DERIVE", CKM_SHA3_512_KEY_DERIVE),
        ("SHAKE_128_KEY_DERIVE", CKM_SHAKE_128_KEY_DERIVE),
        ("SHAKE_256_KEY_DERIVE", CKM_SHAKE_256_KEY_DERIVE),
    ])
    def test_derive_roundtrip(self, p11_raw_session, mech_name, ckm):
        """Derive a key using hash-based derivation and verify it's usable."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_name} not supported")
        # Generate base key, derive with mech_string_data, verify derived key works
```

**Important:** Read existing derive test patterns to match the exact helper functions and derive template used. The derived key template typically needs CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN, CKA_ENCRYPT/DECRYPT=True, CKA_TOKEN=False.

- [ ] **Step 3: Verify**

```bash
uv run ruff check <modified_file>
```

- [ ] **Step 4: Commit**

```bash
git add <modified_file>
git commit -m "impl(07): add SHA3/SHAKE key derivation tests (6 mechanisms)"
```

---

## Task 8: Ed448 Tests

**Files:**
- Modify: `src/pkcs11_check/testcases/test_eddsa.py`

- [ ] **Step 1: Read test_eddsa.py completely**

Read the full file to understand all helpers, fixtures, and test classes.

- [ ] **Step 2: Add Ed448 OID and keygen helper**

```python
ED448_OID = encode_named_curve_parameters("ed448")


def _gen_ed448(rs: Any) -> tuple[int, int]:
    """Generate Ed448 keypair via raw C_GenerateKeyPair."""
    return gen_keypair(
        rs.raw,
        rs.sh,
        CKM_EC_EDWARDS_KEY_PAIR_GEN,
        pub_base=[attr_bytes(CKA_EC_PARAMS, ED448_OID)],
        priv_base=[],
        public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
        private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        pub_skip={CKA_EC_PARAMS},
    )


@pytest.fixture()
def ed448_keypair(p11_raw_session: Any) -> tuple[int, int]:
    """Generate Ed448 keypair, skip if unsupported."""
    rs = p11_raw_session
    if not rs.has_mechanism("EDDSA"):
        pytest.skip("EDDSA mechanism not supported")
    try:
        return _gen_ed448(rs)
    except (AssertionError, OSError):
        pytest.skip("Ed448 keygen not available")
        raise
```

- [ ] **Step 3: Add Ed448 test class**

```python
class TestEd448:
    """Ed448 key generation, signing, and verification."""

    def test_ed448_keygen(self, p11_raw_session: Any, ed448_keypair: tuple[int, int]) -> None:
        """Generate Ed448 key pair."""
        pub, priv = ed448_keypair
        assert pub != 0
        assert priv != 0

    def test_sign_verify_roundtrip(
        self, p11_raw_session: Any, ed448_keypair: tuple[int, int]
    ) -> None:
        """Sign and verify with Ed448."""
        rs = p11_raw_session
        pub, priv = ed448_keypair
        data = b"Ed448 sign-verify test data"
        signature = _sign_eddsa(rs, priv, data)
        assert len(signature) == 114, f"Ed448 signature must be 114 bytes, got {len(signature)}"
        result = _verify_eddsa(rs, pub, data, signature)
        assert result is True

    def test_wrong_data_fails(
        self, p11_raw_session: Any, ed448_keypair: tuple[int, int]
    ) -> None:
        """Verification with wrong data must fail."""
        rs = p11_raw_session
        pub, priv = ed448_keypair
        sig = _sign_eddsa(rs, priv, b"original data")
        result = _verify_eddsa(rs, pub, b"tampered data", sig)
        assert result is False

    def test_signature_length(
        self, p11_raw_session: Any, ed448_keypair: tuple[int, int]
    ) -> None:
        """Ed448 signatures are always exactly 114 bytes."""
        rs = p11_raw_session
        _, priv = ed448_keypair
        for data in [b"", b"x", b"a" * 1000]:
            sig = _sign_eddsa(rs, priv, data)
            assert len(sig) == 114
```

**Important:** `encode_named_curve_parameters("ed448")` must work — verify that the `asn1crypto` or `cryptography` OID mapping includes Ed448. If not, use raw OID bytes: `b"\x06\x03\x2b\x65\x71"` (OID 1.3.101.113).

- [ ] **Step 4: Verify**

```bash
uv run ruff check src/pkcs11_check/testcases/test_eddsa.py
```

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/testcases/test_eddsa.py
git commit -m "impl(08): add Ed448 keygen, sign/verify, and signature length tests"
```

---

## Task 9: AES-CTR Negative + RSA OAEP + Additional Gaps

**Files:**
- Modify: `src/pkcs11_check/testcases/test_aes_modes.py` (CTR negative)
- Modify: `src/pkcs11_check/testcases/test_rsa_oaep.py` (OAEP hash combos)

- [ ] **Step 1: Add AES-CTR negative tests**

Add to the existing CTR test class in `test_aes_modes.py`:

```python
    def test_ctr_counter_bits_zero_rejected(self, p11_raw_session: Any) -> None:
        """ulCounterBits=0 must be rejected per spec."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CTR"):
            pytest.skip("AES_CTR not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            mech = mech_ctr(CKM_AES_CTR, bits=0)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            assert rv != CKR_OK, (
                f"C_EncryptInit accepted ulCounterBits=0 (rv=0x{rv:08x}), "
                "spec requires CKR_MECHANISM_PARAM_INVALID"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_ctr_counter_bits_129_rejected(self, p11_raw_session: Any) -> None:
        """ulCounterBits=129 must be rejected per spec."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CTR"):
            pytest.skip("AES_CTR not supported")
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            mech = mech_ctr(CKM_AES_CTR, bits=129)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            assert rv != CKR_OK, (
                f"C_EncryptInit accepted ulCounterBits=129 (rv=0x{rv:08x}), "
                "spec requires CKR_MECHANISM_PARAM_INVALID"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
```

**Important:** Read the actual file to verify `mech_ctr` accepts a `bits` parameter. If it's called `counter_bits` or doesn't accept that arg, adjust. Also verify how `C_EncryptInit` is called with raw API (some tests use `rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)` returning rv, others use wrappers).

- [ ] **Step 2: Add RSA OAEP hash combos**

Read `test_rsa_oaep.py` and add tests for SHA-384 and SHA-512 OAEP configurations. Follow the existing cross-verification pattern.

- [ ] **Step 3: Verify**

```bash
uv run ruff check src/pkcs11_check/testcases/test_aes_modes.py src/pkcs11_check/testcases/test_rsa_oaep.py
```

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/testcases/test_aes_modes.py src/pkcs11_check/testcases/test_rsa_oaep.py
git commit -m "impl(09): AES-CTR ulCounterBits negative tests, RSA OAEP SHA-384/512 combos"
```

---

## Task 10: Consolidation

**Files:**
- Modify: `docs/audit/00-index.md`

- [ ] **Step 1: Run meta-tests**

```bash
uv run python -m pytest tests/ -q --ignore=tests/test_cli.py 2>&1 | tail -5
```

Verify same pass count as baseline (604) or better. Zero regressions from implementation changes.

- [ ] **Step 2: Run ruff on all modified files**

```bash
uv run ruff check src/pkcs11_check/ --select E,F,I,N,W -q 2>&1 | tail -3
```

No new errors from our changes.

- [ ] **Step 3: Update 00-index.md with implementation status**

Add a new section at the end of `docs/audit/00-index.md`:

```markdown
## Implementation Phase (2026-04-02)

**Spec:** `docs/superpowers/specs/2026-04-02-audit-implementation-design.md`

### Completed

| Iter | Change | Files |
|------|--------|-------|
| 01 | Corrected audit reports (SHAKE/KMAC not in v3.2, GMAC/HSS already tested) | 5 audit reports |
| 02 | Added SHA3/SHAKE KEY_DERIVE to mechanism registry (6 mechanisms) | _kdf.py |
| 03 | Added mech_sign_context pack function for CK_SIGN_ADDITIONAL_CONTEXT | pack_mechanisms.py |
| 04 | Fixed ML-DSA ACVP context passing, removed TODO | test_acvp_mldsa.py |
| 05 | Added ML-DSA hedge variant tests | test_pqc_sign.py |
| 06 | Added CKM_AES_MAC functional tests | test_aes_modes.py |
| 07 | Added SHA3/SHAKE key derivation tests | test_kdf.py |
| 08 | Added Ed448 keygen/sign/verify tests | test_eddsa.py |
| 09 | AES-CTR negative tests, RSA OAEP SHA-384/512 | test_aes_modes.py, test_rsa_oaep.py |

### Remaining (future work)

Items verified as NOT in v3.2 header — closed:
- C_DigestXof* (SHAKE digest) — not in pkcs11.h
- CK_KMAC_PARAMS / CKM_KMAC128/256 — not in pkcs11.h
- CKM_ML_DSA_EXTERNAL_MU — not in pkcs11.h
```

- [ ] **Step 4: Commit**

```bash
git add docs/audit/00-index.md
git commit -m "impl(10): consolidation — update audit index with implementation status"
```

---

## Execution Notes

- **Ralph-loop mode:** Execute Tasks 1-10 sequentially. Each task is one iteration.
- **If blocked:** Document in commit message and move to next task.
- **Commit format:** `impl(NN): description`
- **Branch:** All work on `dev`.
- **Key principle:** Every mechanism/structure referenced in code MUST be verified against `third_party/pkcs11-headers/3.2/pkcs11.h` before use. The OASIS spec docs are a SUPERSET of v3.2.
