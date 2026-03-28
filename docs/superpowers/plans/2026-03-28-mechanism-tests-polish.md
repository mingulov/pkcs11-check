# Mechanism Tests Polish — Remaining Gaps

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Use **Sonnet 4.6** for implementation tasks, **Opus 4.6** for review tasks.

**Goal:** Close four remaining gaps: (1) exercise the GMAC message-sign test, (2) wire KeygenRecipe into key generation dispatch, (3) add RSA/ECDSA KAT sign vectors with private key import, (4) fix SHA-224/384/512 vector_file references.

**Architecture:** 4 independent items. Item 3 (RSA/ECDSA vectors) is the largest — requires a vector generator, a private key import helper in recipes.py, and a branch in TestMechSignKAT. Items 1, 2, 4 are small.

**Tech Stack:** Python 3.11+, ctypes, pytest, `cryptography` library (for vector generation)

---

## Item 1: Exercise GMAC Message-Sign Test (Task 1)

### Task 1: Wire test_message_sign_aes_gmac to use mech_gcm_message

**Goal:** The second test in `test_mech_message.py` currently only checks that `C_MessageSignInit` exists when `CKF_MESSAGE_SIGN` is advertised. Make it actually call `C_MessageSignInit` with the packed mechanism.

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_message.py`

- [ ] **Step 1:** Read `src/pkcs11_check/testcases/test_mech_message.py` in full. The `test_message_sign_aes_gmac` method (line 73) currently ends with a `hasattr` assertion. Replace the assertion with an actual `C_MessageSignInit` call.

- [ ] **Step 2:** Replace the body after the flag/function checks with:

```python
from pkcs11_check.raw.pack_mechanisms import mech_gcm_message
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly
from pkcs11_check.raw.types_std import CKA_SIGN, CKA_TOKEN, CKR_OK, CKR_MECHANISM_INVALID

key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_TOKEN: False, CKA_SIGN: True})
try:
    iv = os.urandom(12)
    init_mech = mech_gcm_message(CKM_AES_GMAC, iv, tag_bits=128)
    rv = rs.raw.C_MessageSignInit(rs.sh, init_mech.byref(), key)
    if rv == int(CKR_MECHANISM_INVALID):
        pytest.skip("C_MessageSignInit: CKR_MECHANISM_INVALID for CKM_AES_GMAC")
    assert rv == int(CKR_OK), f"C_MessageSignInit failed: 0x{rv:08x}"
    # Clean up the initialized state
    if hasattr(rs.raw, "C_MessageSignFinal"):
        rs.raw.C_MessageSignFinal(rs.sh)
finally:
    destroy_quietly(rs.raw, rs.sh, key)
```

Add `import os` at the top of the file if not present.

- [ ] **Step 3:** Lint: `uv run ruff check src/pkcs11_check/testcases/test_mech_message.py`

- [ ] **Step 4:** Test: `bash local-builds/test.sh softhsm2 -k "test_mech_message" -v` (expect skip on v2.40)

- [ ] **Step 5:** Commit:
```bash
git commit -m 'feat: exercise C_MessageSignInit in GMAC message-sign test'
```

---

## Item 2: Wire KeygenRecipe into Key Generation (Tasks 2-3)

### Task 2: Add generate_key_from_recipe() to mechanism_helpers.py

**Goal:** Create a single dispatcher that uses `KeygenRecipe.style` to decide how to generate keys, replacing the ad-hoc `config.key_type` / `config.is_keypair` dispatch chains.

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_helpers.py`

The existing key generation functions (`generate_key_for_encrypt`, `generate_key_for_sign`) have duplicated dispatch logic based on `config.key_type` and `config.is_keypair`. `KeygenRecipe` already encodes this intent declaratively on all 467 entries. The goal is to add a single `generate_key_from_recipe()` that both functions can delegate to.

**KeygenRecipe styles (all 467 entries have one):**
- `"symmetric"` (269): `CKA_VALUE_LEN` from key_size — AES, Camellia, ARIA, etc.
- `"fixed_length"` (72): No `CKA_VALUE_LEN` — DES, SEED, etc.
- `"rsa"` (32): `CKA_MODULUS_BITS` + `CKA_PUBLIC_EXPONENT`
- `"ec"` (26): `CKA_EC_PARAMS` with Weierstrass curve OID
- `"ec_edwards"` (3): `CKA_EC_PARAMS` with Edwards curve OID
- `"ec_montgomery"` (6): `CKA_EC_PARAMS` with Montgomery curve OID
- `"pqc"` (36): `CKA_PARAMETER_SET` with PQC param set constant
- `"dsa"` (15): Domain parameters — skip
- `"dh"` (8): Domain parameters — skip

- [ ] **Step 1:** Read `src/pkcs11_check/testcases/mechanism_helpers.py` — find the existing `generate_key_for_encrypt` (line 440) and `generate_key_for_sign` (line 554). Understand the current dispatch patterns.

- [ ] **Step 2:** Add a new `generate_key_from_recipe()` function above `generate_key_for_encrypt`:

```python
def generate_key_from_recipe(
    rs: Any,
    entry: MechEntry,
    config: MechConfig,
    *,
    extra_attrs: dict[int, Any] | None = None,
) -> tuple[int, int | None]:
    """Generate key(s) using KeygenRecipe style.

    Returns (key_or_pub, priv_or_None).
    Symmetric: (handle, None). Asymmetric: (pub, priv).
    """
    import pytest

    recipe = config.keygen_recipe
    if recipe is None:
        pytest.skip(f"{entry.mech_name}: no keygen_recipe")

    style = recipe.style
    attrs = extra_attrs or {}

    if style in ("symmetric", "fixed_length"):
        return _keygen_symmetric(rs, entry, config, attrs, fixed=style == "fixed_length")
    elif style == "rsa":
        return _keygen_rsa(rs, entry, config, attrs)
    elif style in ("ec", "ec_edwards", "ec_montgomery"):
        return _keygen_ec(rs, entry, config, attrs, style)
    elif style == "pqc":
        return _keygen_pqc(rs, entry, config, attrs)
    elif style in ("dsa", "dh"):
        pytest.skip(f"{entry.mech_name}: {style} requires external domain parameters")
    else:
        pytest.skip(f"{entry.mech_name}: unknown keygen_recipe style {style!r}")

    return 0, None  # unreachable, for type checker
```

Then add the private helpers `_keygen_symmetric`, `_keygen_rsa`, `_keygen_ec`, `_keygen_pqc` — extracting the logic from the existing `generate_key_for_encrypt` and `generate_key_for_sign`. Each helper should:
- Accept `rs, entry, config, attrs, **kwargs`
- Use `config.keygen_mech` as the mechanism
- Use `pick_key_size(entry, config)` for sizes
- Use `recipe.defaults` for curve/parameter_set defaults
- Call `gen_keypair` or `C_GenerateKey` as appropriate
- Return `(key, None)` or `(pub, priv)`

The `_keygen_ec` helper should use `recipe.defaults.get("curve", "secp256r1")` to select the curve, then use the existing `_CURVE_OIDS` or `gen_ec_keypair` / `gen_ec_edwards_keypair` helpers from recipes.py.

- [ ] **Step 3:** Update `generate_key_for_encrypt` to delegate to `generate_key_from_recipe`:

```python
def generate_key_for_encrypt(rs, entry, config):
    return generate_key_from_recipe(
        rs, entry, config,
        extra_attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
    )
```

Keep the AES-XTS special case as a pre-check before delegating.

- [ ] **Step 4:** Update `generate_key_for_sign` similarly:

```python
def generate_key_for_sign(rs, entry, config):
    return generate_key_from_recipe(
        rs, entry, config,
        extra_attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
    )
```

- [ ] **Step 5:** Lint and format: `uv run ruff check src/pkcs11_check/testcases/mechanism_helpers.py`

- [ ] **Step 6:** Test that existing mechanism tests still work:
```bash
bash local-builds/test.sh softhsm2 -k "test_mech_encrypt or test_mech_sign or test_mech_keygen" --no-header 2>&1 | tail -5
```
Expected: same pass/fail/skip counts as before.

- [ ] **Step 7:** Commit:
```bash
git commit -m 'refactor: add generate_key_from_recipe() using KeygenRecipe dispatch'
```

---

### Task 3: Remove KeygenRecipe from "deferred" status in memory + docs

**Files:**
- Modify: `/home/user/.claude/projects/-home-user-src-m-pkcs11-check/memory/project_mechanism_tests_progress.md`

- [ ] **Step 1:** Update memory to note KeygenRecipe is now consumed by `generate_key_from_recipe()`.

- [ ] **Step 2:** Commit if any code docs changed.

---

## Item 3: RSA/ECDSA KAT Sign Vectors (Tasks 4-7)

### Task 4: Add import_rsa_private_key and import_ec_private_key to recipes.py

**Goal:** DRY helpers for importing known private keys into a PKCS#11 session.

**Files:**
- Modify: `src/pkcs11_check/raw/recipes.py`

The pattern already exists in `test_wycheproof_rsa_siggen.py` and `test_cctv_rfc6979.py` but is inlined. Extract into reusable helpers.

- [ ] **Step 1:** Read `src/pkcs11_check/raw/recipes.py` — find `import_secret_key` (line 303) and `create_object` (line 328). The new functions go right after `import_secret_key`.

- [ ] **Step 2:** Add RSA private key import helper:

```python
def import_rsa_private_key(
    raw: Any,
    session: int,
    *,
    n: bytes,
    e: bytes,
    d: bytes,
    p: bytes,
    q: bytes,
    dmp1: bytes,
    dmq1: bytes,
    iqmp: bytes,
    attrs: dict[int, Any] | None = None,
) -> int:
    """Import an RSA private key from CRT components via C_CreateObject.

    All component bytes must be big-endian unsigned, with no leading zero padding
    beyond what the modulus size requires.
    Returns the object handle.
    """
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PRIVATE_KEY,
        CKA_KEY_TYPE: CKK_RSA,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_MODULUS: n,
        CKA_PUBLIC_EXPONENT: e,
        CKA_PRIVATE_EXPONENT: d,
        CKA_PRIME_1: p,
        CKA_PRIME_2: q,
        CKA_EXPONENT_1: dmp1,
        CKA_EXPONENT_2: dmq1,
        CKA_COEFFICIENT: iqmp,
    }
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)
```

Import the needed CKA/CKO/CKK constants at the top of the function (they should already be imported in recipes.py; check first).

- [ ] **Step 3:** Add EC private key import helper:

```python
def import_ec_private_key(
    raw: Any,
    session: int,
    *,
    ec_params: bytes,
    value: bytes,
    attrs: dict[int, Any] | None = None,
) -> int:
    """Import an EC private key from raw scalar via C_CreateObject.

    ``ec_params`` is the DER-encoded curve OID (e.g., from
    ``encode_named_curve_parameters("secp256r1")``).
    ``value`` is the raw big-endian private scalar.
    Returns the object handle.
    """
    base: dict[int, Any] = {
        CKA_CLASS: CKO_PRIVATE_KEY,
        CKA_KEY_TYPE: CKK_EC,
        CKA_TOKEN: False,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_EC_PARAMS: ec_params,
        CKA_VALUE: value,
    }
    if attrs:
        base.update(attrs)
    return create_object(raw, session, base)
```

- [ ] **Step 4:** Lint: `uv run ruff check src/pkcs11_check/raw/recipes.py`

- [ ] **Step 5:** Commit:
```bash
git commit -m 'feat: add import_rsa_private_key and import_ec_private_key helpers'
```

---

### Task 5: Add RSA-PKCS1-SHA256 and RSA-PSS-SHA256 vector generators

**Goal:** Generate sign KAT vectors using `cryptography` library with known RSA keys.

**Files:**
- Modify: `scripts/generate_mechanism_vectors.py`
- Create: `src/pkcs11_check/testcases/data/mechanism_vectors/rsa_pkcs1_sha256.json`
- Create: `src/pkcs11_check/testcases/data/mechanism_vectors/rsa_pss_sha256.json`

- [ ] **Step 1:** Read `scripts/generate_mechanism_vectors.py` to understand generator pattern.

- [ ] **Step 2:** Add RSA vector generator. The vector schema for asymmetric sign is different from symmetric:

```python
def generate_rsa_pkcs1_sha256() -> dict:
    """RSA PKCS#1 v1.5 SHA-256 sign vectors."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding

    # Generate a fixed 2048-bit RSA key (deterministic from seed)
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    nums = private_key.private_numbers()
    pub = nums.public_numbers

    def _i2b(n: int) -> str:
        """Integer to big-endian hex string."""
        byte_len = (n.bit_length() + 7) // 8
        return n.to_bytes(byte_len, "big").hex()

    # Common key component dict
    key_components = {
        "n_hex": _i2b(pub.n),
        "e_hex": _i2b(pub.e),
        "d_hex": _i2b(nums.d),
        "p_hex": _i2b(nums.p),
        "q_hex": _i2b(nums.q),
        "dmp1_hex": _i2b(nums.dmp1),
        "dmq1_hex": _i2b(nums.dmq1),
        "iqmp_hex": _i2b(nums.iqmp),
    }

    vectors = []
    for i, msg in enumerate([b"", b"hello", b"A" * 245]):
        sig = private_key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        vectors.append({
            "id": f"rsa_pkcs1_sha256_{i}",
            "type": "positive",
            "mechanism_name": "CKM_SHA256_RSA_PKCS",
            "key_type": "asymmetric",
            "key_bits": 2048,
            **key_components,
            "input_hex": msg.hex(),
            "signature_hex": sig.hex(),
            "params": {},
        })

    return {
        "mechanism": "CKM_SHA256_RSA_PKCS",
        "family": "rsa_pkcs1_sha256",
        "key_type": "CKK_RSA",
        "source": "generated with cryptography library",
        "vectors": vectors,
    }
```

Note: the RSA key generated by `cryptography` is NOT deterministic from a seed (unlike symmetric keys). This means vectors will change each time the script runs. To make them stable, generate ONCE and commit the JSON. Future runs should only regenerate if `--force` is passed. Alternatively, serialize a fixed key as PEM in the script. Choose whichever approach fits the existing pattern.

- [ ] **Step 3:** Add similar generator for RSA-PSS-SHA256 (uses `padding.PSS` with `padding.PSS.MAX_LENGTH` salt and `hashes.SHA256()`). PSS signatures are non-deterministic, so the vector should store the signature and the test should do **verify** (not sign+compare). Add a `"verify_only": true` field to the vector dict.

- [ ] **Step 4:** Add both generators to `GENERATORS` dict.

- [ ] **Step 5:** Run: `uv run python scripts/generate_mechanism_vectors.py --all`

- [ ] **Step 6:** Update registry `_rsa.py`: restore `vector_file="rsa_pkcs1_sha256.json"` on `CKM_SHA256_RSA_PKCS` and `vector_file="rsa_pss_sha256.json"` on `CKM_SHA256_RSA_PKCS_PSS`.

- [ ] **Step 7:** Commit:
```bash
git add scripts/generate_mechanism_vectors.py src/pkcs11_check/testcases/data/mechanism_vectors/rsa_*.json src/pkcs11_check/testcases/mechanism_registry/_rsa.py
git commit -m 'feat: add RSA PKCS1 and PSS SHA-256 sign KAT vectors'
```

---

### Task 6: Add ECDSA-SHA256 vector generator

**Files:**
- Modify: `scripts/generate_mechanism_vectors.py`
- Create: `src/pkcs11_check/testcases/data/mechanism_vectors/ecdsa_sha256.json`
- Modify: `src/pkcs11_check/testcases/mechanism_registry/_ec.py`

- [ ] **Step 1:** Add ECDSA vector generator:

```python
def generate_ecdsa_sha256() -> dict:
    """ECDSA P-256 SHA-256 sign vectors."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    private_key = ec.generate_private_key(ec.SECP256R1())
    nums = private_key.private_numbers()

    # EC params: DER-encoded OID for P-256 = 06 08 2a 86 48 ce 3d 03 01 07
    ec_params_hex = "06082a8648ce3d030107"
    # Private scalar: 32 bytes big-endian
    d_bytes = nums.private_value.to_bytes(32, "big")

    vectors = []
    for i, msg in enumerate([b"", b"hello ECDSA", b"X" * 100]):
        sig_der = private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        vectors.append({
            "id": f"ecdsa_sha256_{i}",
            "type": "positive",
            "mechanism_name": "CKM_ECDSA_SHA256",
            "key_type": "asymmetric",
            "ec_params_hex": ec_params_hex,
            "ec_private_scalar_hex": d_bytes.hex(),
            "input_hex": msg.hex(),
            "signature_der_hex": sig_der.hex(),
            "verify_only": True,  # ECDSA sigs are non-deterministic
            "params": {},
        })

    return {
        "mechanism": "CKM_ECDSA_SHA256",
        "family": "ecdsa_sha256",
        "key_type": "CKK_EC",
        "source": "generated with cryptography library",
        "vectors": vectors,
    }
```

Note: ECDSA signatures are non-deterministic so `"verify_only": True`. The test should import the key, sign the input, then verify against the imported public key. Alternatively, import the key, verify the stored DER signature using `C_Verify`. The simpler approach: **verify-only** — import the private key, extract public key, and call `C_Verify` with the stored DER signature.

But wait — PKCS#11 ECDSA uses flat `r||s` format, not DER. The vector should store both `signature_der_hex` (for `cryptography` verification) and `signature_p11_hex` (flat r||s for PKCS#11). The generator should convert:

```python
r, s = decode_dss_signature(sig_der)
r_bytes = r.to_bytes(32, "big")
s_bytes = s.to_bytes(32, "big")
sig_p11 = (r_bytes + s_bytes).hex()
```

- [ ] **Step 2:** Add to GENERATORS, run `--all`, restore `vector_file="ecdsa_sha256.json"` in `_ec.py`.

- [ ] **Step 3:** Commit:
```bash
git commit -m 'feat: add ECDSA P-256 SHA-256 sign KAT vectors'
```

---

### Task 7: Branch TestMechSignKAT for asymmetric key import

**Goal:** Make TestMechSignKAT handle both symmetric (HMAC) and asymmetric (RSA/ECDSA) vectors.

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_sign.py`

Currently `test_kat_vector` only handles symmetric keys via `import_secret_key`. For asymmetric vectors, it needs to:
1. Detect `vec.get("key_type") == "asymmetric"`
2. For RSA: use `import_rsa_private_key` with CRT components from the vector
3. For EC: use `import_ec_private_key` with scalar + curve OID from the vector
4. For `"verify_only": True` vectors: import key, call `verify_single` instead of `sign_single`

- [ ] **Step 1:** Read current `test_mech_sign.py` TestMechSignKAT (lines 116-170).

- [ ] **Step 2:** Add the asymmetric branch after the existing symmetric path. The structure:

```python
for vec in vectors:
    # ... existing filter logic ...

    if vec.get("key_type") == "asymmetric":
        # RSA or EC asymmetric KAT
        _run_asymmetric_kat(rs, entry, config, vec)
        continue

    # ... existing symmetric HMAC path ...
```

The `_run_asymmetric_kat` helper (module-level function):

```python
def _run_asymmetric_kat(
    rs: RawSession, entry: MechEntry, config: MechConfig, vec: dict
) -> None:
    """Run a single asymmetric sign KAT vector (RSA or EC)."""
    from pkcs11_check.raw.recipes import (
        import_rsa_private_key, import_ec_private_key,
        verify_single, sign_single, destroy_quietly,
    )

    key_type_int = int(config.key_type) if config.key_type else 0
    key: int = 0

    if "n_hex" in vec:
        # RSA vector
        key = import_rsa_private_key(
            rs.raw, rs.sh,
            n=bytes.fromhex(vec["n_hex"]),
            e=bytes.fromhex(vec["e_hex"]),
            d=bytes.fromhex(vec["d_hex"]),
            p=bytes.fromhex(vec["p_hex"]),
            q=bytes.fromhex(vec["q_hex"]),
            dmp1=bytes.fromhex(vec["dmp1_hex"]),
            dmq1=bytes.fromhex(vec["dmq1_hex"]),
            iqmp=bytes.fromhex(vec["iqmp_hex"]),
            attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
    elif "ec_private_scalar_hex" in vec:
        # EC vector
        key = import_ec_private_key(
            rs.raw, rs.sh,
            ec_params=bytes.fromhex(vec["ec_params_hex"]),
            value=bytes.fromhex(vec["ec_private_scalar_hex"]),
            attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False},
        )
    else:
        return  # Unknown asymmetric format

    try:
        params = build_params_from_vector(entry.mech_id, config.param_recipe, vec)
        if params == "SKIP":
            return
        input_bytes = bytes.fromhex(vec["input_hex"])

        if vec.get("verify_only"):
            # Non-deterministic sig — verify the stored signature
            sig_hex = vec.get("signature_p11_hex") or vec.get("signature_hex", "")
            if not sig_hex:
                return
            ok = verify_single(
                rs.raw, rs.sh, key, CKM(entry.mech_id),
                input_bytes, bytes.fromhex(sig_hex),
                mech_param=params,
            )
            assert ok, f"KAT verify failed for {vec.get('id', '?')}"
        else:
            # Deterministic sig (RSA PKCS#1 v1.5) — sign and compare
            sig = sign_single(
                rs.raw, rs.sh, key, CKM(entry.mech_id),
                input_bytes, mech_param=params,
            )
            expected = bytes.fromhex(vec["signature_hex"])
            assert sig == expected, (
                f"KAT sign mismatch for {vec.get('id', '?')}: "
                f"got {sig.hex()!r}, expected {expected.hex()!r}"
            )
    finally:
        destroy_quietly(rs.raw, rs.sh, key)
```

- [ ] **Step 3:** Lint: `uv run ruff check src/pkcs11_check/testcases/test_mech_sign.py`

- [ ] **Step 4:** Test:
```bash
bash local-builds/test.sh softhsm2 -k "TestMechSignKAT" -v --no-header
```
Expected: HMAC KATs still pass, RSA/ECDSA KATs run (may pass or fail depending on module support for key import).

- [ ] **Step 5:** Commit:
```bash
git commit -m 'feat: support asymmetric key import in TestMechSignKAT (RSA + ECDSA)'
```

---

## Item 4: SHA-224/384/512 vector_file References (Task 8)

### Task 8: Add vector_file="sha.json" to remaining SHA entries

**Goal:** SHA-224, SHA-384, SHA-512 registry entries should point to `sha.json` (which contains vectors for all 5 SHA variants).

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_registry/_hash.py`

- [ ] **Step 1:** Read `_hash.py` — find CKM_SHA224, CKM_SHA384, CKM_SHA512 entries. They currently have no `vector_file`.

- [ ] **Step 2:** Add `vector_file="sha.json"` to each.

- [ ] **Step 3:** Also add `vector_file="hmac.json"` to `CKM_SHA224_HMAC` and `CKM_MD5_HMAC` entries in `_hmac.py` if the `hmac.json` file contains vectors for them (check the file first — it may only have SHA-256/384/512).

- [ ] **Step 4:** Lint: `uv run ruff check src/pkcs11_check/testcases/mechanism_registry/`

- [ ] **Step 5:** Test: `bash local-builds/test.sh softhsm2 -k "TestMechDigestKAT" -v --no-header`
Expected: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 KATs now pass (or skip if mechanism unavailable).

- [ ] **Step 6:** Commit:
```bash
git commit -m 'fix: add vector_file refs for SHA-224/384/512 and remaining HMAC entries'
```
