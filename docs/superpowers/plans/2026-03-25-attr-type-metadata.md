# Attribute Type Metadata — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate an `ATTR_VALUE_TYPES` dict in `metadata_std.py` that maps each CKA_* constant to its value type (`'bool'`, `'ulong'`, `'bytes'`, `'str'`, `'date'`), eliminating the hardcoded `_BBOOL_ATTRS`/`_ULONG_ATTRS` sets in `recipes.py` and fixing the `read_attributes` ULONG-size ambiguity.

**Architecture:** The generator parses attribute type tables from the OASIS spec markdown (157 attrs in `| CKA_NAME | CK_TYPE | Description |` format) and maps spec types to simple type strings. The C headers don't contain type info, but the OASIS spec markdown does. The generator outputs `ATTR_VALUE_TYPES: dict[int, str]` into `metadata_std.py`. Both `read_attributes` (decoding) and `_pack_attrs`/`attr_auto` (encoding) use this table for spec-correct conversion. Explicit `attr_bool`/`attr_ulong`/`attr_bytes` remain in `pack.py` for fault/negative testing.

**Tech Stack:** Python generator script, OASIS spec markdown tables as source, python-pkcs11 `ATTRIBUTE_TYPES` as cross-check.

**OASIS spec location:** `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/*.md`

**Future follow-up (not in this plan):** The OASIS spec also has parseable tables for:
- **Mechanism→Functions capability matrix** (`CKM_RSA_PKCS` → Encrypt✓, Sign✓, Wrap✓) → `MECHANISM_CAPABILITIES`
- **Mechanism→Parameter struct** (`CKM_RSA_PKCS_OAEP` → `CK_RSA_PKCS_OAEP_PARAMS`) → `MECHANISM_PARAMS`
- **Function→CKR codes** (which CKR values each C_* can return) → `FUNCTION_RETURN_CODES`

These would be valuable for compliance testing but are separate sub-projects.

**Table format in spec:**
```
| CKA_CLASS^1^          | CK_OBJECT_CLASS | Object class (type) |
| CKA_TOKEN ^8^         | CK_BBOOL        | CK_TRUE if ... |
| CKA_LABEL ^8^         | RFC2279 string  | Description of the object |
| CKA_MODULUS            | Big integer     | Modulus n |
```

**Type mapping:**
| Spec type | Our type | Notes |
|-----------|----------|-------|
| `CK_BBOOL` | `'bool'` | 1-byte boolean |
| `CK_ULONG`, `CK_OBJECT_CLASS`, `CK_KEY_TYPE`, `CK_MECHANISM_TYPE`, `CK_FLAGS`, `CK_CERTIFICATE_TYPE` | `'ulong'` | Platform CK_ULONG |
| `Byte array`, `CK_BYTE_PTR`, `Big integer` | `'bytes'` | Raw byte arrays |
| `RFC2279 string` | `'str'` | UTF-8 string |
| `CK_DATE` | `'date'` | 8-byte YYYYMMDD |
| `CK_MECHANISM_TYPE_PTR` (array) | `'ulong_array'` | CK_ULONG array |
| `CK_ATTRIBUTE_PTR` (template) | `'template'` | Nested attributes |

---

## File Structure

- Modify: `scripts/generate_raw_standard.py` — add OASIS markdown parser for attr types, emit `ATTR_VALUE_TYPES`
- Modify: `src/pkcs11_check/raw/metadata_std.py` — regenerated, gains `ATTR_VALUE_TYPES`
- Modify: `src/pkcs11_check/raw/pack.py` — add `attr_auto`, `template_from_dict`
- Modify: `src/pkcs11_check/raw/recipes.py` — replace `_BBOOL_ATTRS`/`_ULONG_ATTRS` with `ATTR_VALUE_TYPES`; upgrade `_pack_attrs` to use `attr_auto`
- Modify: `src/pkcs11_check/testcases/test_data_objects.py` — simplify `_read_str` (read_attributes returns str for CKA_LABEL now)
- Modify: `tests/test_raw_generation.py` — drift tests for `ATTR_VALUE_TYPES`
- Cross-check: `python-pkcs11/pkcs11/attributes.py` (132 entries)

---

## Task 1: Parse OASIS spec markdown for attribute types

**Files:**
- Modify: `scripts/generate_raw_standard.py`

The OASIS spec markdown files contain 157 CKA_* attributes in structured tables. The generator parses these tables directly — no manual curation needed.

- [ ] **Step 1: Add OASIS markdown table parser to generator**

Add a function to `scripts/generate_raw_standard.py` that parses attribute type tables from the OASIS spec:

```python
OASIS_SPEC_DIR = Path("/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec")

# Map OASIS spec type strings → our simple type tags
_SPEC_TYPE_MAP: dict[str, str] = {
    "CK_BBOOL": "bool",
    "CK_ULONG": "ulong",
    "CK_OBJECT_CLASS": "ulong",
    "CK_KEY_TYPE": "ulong",
    "CK_MECHANISM_TYPE": "ulong",
    "CK_CERTIFICATE_TYPE": "ulong",
    "CK_FLAGS": "ulong",
    "CK_CERTIFICATE_CATEGORY": "ulong",
    "CK_SECURITY_DOMAIN": "ulong",
    "CK_PROFILE_ID": "ulong",
    "Byte array": "bytes",
    "Big integer": "bytes",
    "RFC2279 string": "str",
    "CK_DATE": "date",
}

_ATTR_ROW_RE = re.compile(
    r"\|\s*(CKA_\w+)[\s^0-9,]*\|\s*([^|]+?)\s*\|",
)

def _parse_oasis_attr_types() -> dict[str, str]:
    """Parse attribute type tables from OASIS spec markdown files."""
    result: dict[str, str] = {}
    for md_file in sorted(OASIS_SPEC_DIR.glob("*.md")):
        for line in md_file.read_text().splitlines():
            m = _ATTR_ROW_RE.match(line)
            if not m:
                continue
            attr_name = m.group(1).strip()
            spec_type = m.group(2).strip()
            # Normalize: strip footnote markers, trailing commas
            spec_type = re.sub(r"\^[\d,]+\^", "", spec_type).strip()
            # Check for array types
            if "CK_MECHANISM_TYPE_PTR" in spec_type or "CK_MECHANISM_TYPE array" in spec_type:
                result[attr_name] = "ulong_array"
            elif "CK_ATTRIBUTE_PTR" in spec_type or "CK_ATTRIBUTE array" in spec_type:
                result[attr_name] = "template"
            else:
                # Direct lookup
                mapped = _SPEC_TYPE_MAP.get(spec_type)
                if mapped:
                    result[attr_name] = mapped
                elif attr_name not in result:
                    result[attr_name] = "bytes"  # default unknown
    return result
```

The regex `_ATTR_ROW_RE` matches lines like `| CKA_CLASS^1^ | CK_OBJECT_CLASS | ...` and extracts the attribute name and spec type.

- [ ] **Step 2: Add fallback curated entries for attrs not in spec tables**

Some attributes may not appear in markdown tables (vendor, deprecated, or only in prose). Add a small fallback dict for anything the parser misses, verified against python-pkcs11:

```python
# Fallback for attributes not found in spec markdown tables.
# Verified against python-pkcs11/pkcs11/attributes.py.
_ATTR_TYPE_FALLBACK: dict[str, str] = {
    "CKA_VALUE": "bytes",
    # Add any others the parser misses after running
}
```

Merge: parser result takes priority, fallback fills gaps.

```python
def _build_attr_type_table() -> dict[str, str]:
    """Build complete attr type table: parsed from spec + fallback."""
    result = dict(_ATTR_TYPE_FALLBACK)
    result.update(_parse_oasis_attr_types())  # parsed wins
    return result
```

- [ ] **Step 3: Log coverage stats**

After parsing, print coverage to stderr so the implementer can verify:

```python
parsed = _build_attr_type_table()
known_cka = {n for n in constants if n.startswith("CKA_")}
covered = known_cka & set(parsed)
missing = known_cka - set(parsed)
print(f"ATTR_VALUE_TYPES: {len(covered)}/{len(known_cka)} attrs covered", file=sys.stderr)
if missing:
    print(f"  Missing: {sorted(missing)}", file=sys.stderr)
```

```python
# Attribute value types per OASIS PKCS#11 v3.2 spec.
# Generated from OASIS spec markdown attribute tables.
# Cross-checked against python-pkcs11 ATTRIBUTE_TYPES in tests.
#
# Types: 'bool' (CK_BBOOL), 'ulong' (CK_ULONG / CK_ULONG enum),
#        'bytes' (byte array / big integer), 'str' (RFC2279 UTF-8 string),
#        'date' (CK_DATE), 'ulong_array' (CK_ULONG[]),
#        'template' (CK_ATTRIBUTE[]).
# Attributes not in this table default to 'bytes' in read_attributes.
_ATTR_TYPE_TABLE: dict[str, str] = {
    # Common object attributes
    "CKA_CLASS": "ulong",
    "CKA_TOKEN": "bool",
    "CKA_PRIVATE": "bool",
    "CKA_LABEL": "str",
    "CKA_UNIQUE_ID": "str",
    "CKA_APPLICATION": "str",
    "CKA_VALUE": "bytes",
    "CKA_OBJECT_ID": "bytes",
    "CKA_CERTIFICATE_TYPE": "ulong",
    "CKA_ISSUER": "bytes",
    "CKA_SERIAL_NUMBER": "bytes",
    "CKA_SUBJECT": "bytes",
    "CKA_ID": "bytes",
    "CKA_URL": "str",
    "CKA_HASH_OF_SUBJECT_PUBLIC_KEY": "bytes",
    "CKA_HASH_OF_ISSUER_PUBLIC_KEY": "bytes",
    "CKA_HASH_OF_CERTIFICATE": "bytes",
    "CKA_CHECK_VALUE": "bytes",
    "CKA_PUBLIC_KEY_INFO": "bytes",
    # Key attributes
    "CKA_KEY_TYPE": "ulong",
    "CKA_SENSITIVE": "bool",
    "CKA_ENCRYPT": "bool",
    "CKA_DECRYPT": "bool",
    "CKA_WRAP": "bool",
    "CKA_UNWRAP": "bool",
    "CKA_SIGN": "bool",
    "CKA_SIGN_RECOVER": "bool",
    "CKA_VERIFY": "bool",
    "CKA_VERIFY_RECOVER": "bool",
    "CKA_DERIVE": "bool",
    "CKA_ENCAPSULATE": "bool",
    "CKA_DECAPSULATE": "bool",
    "CKA_START_DATE": "date",
    "CKA_END_DATE": "date",
    "CKA_MODULUS": "bytes",
    "CKA_MODULUS_BITS": "ulong",
    "CKA_PUBLIC_EXPONENT": "bytes",
    "CKA_PRIVATE_EXPONENT": "bytes",
    "CKA_PRIME_1": "bytes",
    "CKA_PRIME_2": "bytes",
    "CKA_EXPONENT_1": "bytes",
    "CKA_EXPONENT_2": "bytes",
    "CKA_COEFFICIENT": "bytes",
    "CKA_PRIME": "bytes",
    "CKA_SUBPRIME": "bytes",
    "CKA_BASE": "bytes",
    "CKA_PRIME_BITS": "ulong",
    "CKA_SUBPRIME_BITS": "ulong",
    "CKA_VALUE_BITS": "ulong",
    "CKA_VALUE_LEN": "ulong",
    "CKA_EXTRACTABLE": "bool",
    "CKA_LOCAL": "bool",
    "CKA_NEVER_EXTRACTABLE": "bool",
    "CKA_ALWAYS_SENSITIVE": "bool",
    "CKA_KEY_GEN_MECHANISM": "ulong",
    "CKA_MODIFIABLE": "bool",
    "CKA_COPYABLE": "bool",
    "CKA_DESTROYABLE": "bool",
    "CKA_EC_PARAMS": "bytes",
    "CKA_EC_POINT": "bytes",
    "CKA_ALWAYS_AUTHENTICATE": "bool",
    "CKA_WRAP_WITH_TRUSTED": "bool",
    "CKA_TRUSTED": "bool",
    "CKA_WRAP_TEMPLATE": "template",
    "CKA_UNWRAP_TEMPLATE": "template",
    "CKA_DERIVE_TEMPLATE": "template",
    "CKA_ENCAPSULATE_TEMPLATE": "template",
    "CKA_DECAPSULATE_TEMPLATE": "template",
    "CKA_ALLOWED_MECHANISMS": "ulong_array",
    "CKA_PROFILE_ID": "ulong",
    "CKA_MECHANISM_TYPE": "ulong",
    "CKA_PARAMETER_SET": "ulong",
    "CKA_SEED": "bytes",
    "CKA_PUBLIC_CRC64_VALUE": "bytes",
    # HSS attributes
    "CKA_HSS_LEVELS": "ulong",
    "CKA_HSS_LMS_TYPE": "ulong",
    "CKA_HSS_LMOTS_TYPE": "ulong",
    "CKA_HSS_LMS_TYPES": "ulong_array",
    "CKA_HSS_LMOTS_TYPES": "ulong_array",
    "CKA_HSS_KEYS_REMAINING": "ulong",
    # Validation attributes
    "CKA_OBJECT_VALIDATION_FLAGS": "ulong",
    "CKA_VALIDATION_TYPE": "ulong",
    "CKA_VALIDATION_VERSION": "bytes",
    "CKA_VALIDATION_LEVEL": "ulong",
    "CKA_VALIDATION_MODULE_ID": "str",
    "CKA_VALIDATION_FLAG": "ulong",
    "CKA_VALIDATION_AUTHORITY_TYPE": "ulong",
    "CKA_VALIDATION_COUNTRY": "str",
    "CKA_VALIDATION_CERTIFICATE_IDENTIFIER": "str",
    "CKA_VALIDATION_CERTIFICATE_URI": "str",
    "CKA_VALIDATION_VENDOR_URI": "str",
    "CKA_VALIDATION_PROFILE": "str",
    # GOST
    "CKA_GOSTR3410_PARAMS": "bytes",
    "CKA_GOSTR3411_PARAMS": "bytes",
}
```

- [ ] **Step 2: Add generator code to emit `ATTR_VALUE_TYPES`**

In the metadata generation function, add emission of `ATTR_VALUE_TYPES`. This maps the curated name table against the parsed constant values:

```python
def _emit_attr_value_types(constants: dict[str, int]) -> str:
    """Emit ATTR_VALUE_TYPES mapping CKA int → value type string."""
    lines = ["ATTR_VALUE_TYPES: dict[int, str] = {"]
    for name, vtype in sorted(_ATTR_TYPE_TABLE.items(), key=lambda x: constants.get(x[0], 0)):
        if name in constants:
            lines.append(f"    {constants[name]:#x}: {vtype!r},  # {name}")
    lines.append("}")
    return "\n".join(lines)
```

Call this in the main generation flow where other name tables are emitted.

- [ ] **Step 3: Run generator and verify output**

```bash
uv run python scripts/generate_raw_standard.py
```

Check `src/pkcs11_check/raw/metadata_std.py` has `ATTR_VALUE_TYPES` dict.

- [ ] **Step 4: Commit generator changes**

```bash
git add scripts/generate_raw_standard.py src/pkcs11_check/raw/metadata_std.py
git commit -m "feat: generate ATTR_VALUE_TYPES metadata from curated OASIS spec table"
```

---

## Task 2: Replace hardcoded sets in `read_attributes`

**Files:**
- Modify: `src/pkcs11_check/raw/recipes.py`

- [ ] **Step 1: Replace `_BBOOL_ATTRS`/`_ULONG_ATTRS` with metadata import**

Remove the hardcoded frozensets and import the generated table:

```python
from .metadata_std import ATTR_VALUE_TYPES
```

Replace the decoding logic in `read_attributes`:

```python
    result: dict[int, bytes | int | bool] = {}
    for i, at in enumerate(attr_types):
        size = int(tmpl[i].ulValueLen)
        raw_bytes = bytes(buffers[i][:size])
        vtype = ATTR_VALUE_TYPES.get(int(at), "bytes")
        if vtype == "bool" and size == ctypes.sizeof(CK_BBOOL):
            result[at] = raw_bytes[0] != 0
        elif vtype == "ulong" and size == ctypes.sizeof(CK_ULONG):
            result[at] = int.from_bytes(raw_bytes, byteorder=sys.byteorder)
        elif vtype == "str":
            result[at] = raw_bytes.decode("utf-8")
        else:
            # bytes, date, template, ulong_array, biginteger, unknown → raw bytes
            result[at] = raw_bytes
    return result
```

- [ ] **Step 2: Remove the hardcoded `_ULONG_ATTRS` and `_BBOOL_ATTRS` frozensets**

Delete the entire `_ULONG_ATTRS` and `_BBOOL_ATTRS` blocks and their associated CKA imports that are no longer needed.

- [ ] **Step 3: Simplify `_read_str` in test_data_objects.py**

Since `read_attributes` now returns `str` for CKA_LABEL/CKA_APPLICATION (type `'str'` in metadata), the `_read_str` helper can be simplified or removed. Check what the test needs — if `read_attributes` returns str directly, the helper may not be needed at all.

- [ ] **Step 4: Run tests**

```bash
# Meta-tests
uv run python -m pytest tests/ -v --timeout=30
# Batch 1 migrated files
bash local-builds/test.sh softhsm2 -- src/pkcs11_check/testcases/test_slot.py src/pkcs11_check/testcases/test_interface.py src/pkcs11_check/testcases/test_digest.py src/pkcs11_check/testcases/test_encrypt.py src/pkcs11_check/testcases/test_generic_secret.py src/pkcs11_check/testcases/test_errors.py src/pkcs11_check/testcases/test_sign.py src/pkcs11_check/testcases/test_session_info.py src/pkcs11_check/testcases/test_data_objects.py src/pkcs11_check/testcases/test_key_lifecycle.py
```

Expected: 107 passed, 6 skipped (unchanged from baseline).

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/raw/recipes.py src/pkcs11_check/testcases/test_data_objects.py
git commit -m "refactor: use generated ATTR_VALUE_TYPES in read_attributes, remove hardcoded sets"
```

---

## Task 2b: Table-driven packing — `attr_auto` and `_pack_attrs` improvement

**Files:**
- Modify: `src/pkcs11_check/raw/pack.py` (add `attr_auto`)
- Modify: `src/pkcs11_check/raw/recipes.py` (upgrade `_pack_attrs` to use table)

### Why table-driven packing is better

Current `_pack_attrs` infers pack type from the Python value type. This is **wrong** for edge cases:
- `{CKA_TOKEN: 1}` → Python sees `int` → packs as CK_ULONG (8 bytes) → **BUG** (should be CK_BBOOL, 1 byte)
- `{CKA_CLASS: True}` → Python sees `bool` → packs as CK_BBOOL → **BUG** (should be CK_ULONG)

Table-driven packing uses `ATTR_VALUE_TYPES` to determine the correct wire type from the attribute ID, then coerces the Python value. This is not "hidden conversion" — it's **spec-correct serialization**.

The explicit `attr_bool`/`attr_ulong`/`attr_bytes` remain in `pack.py` for fault testing (deliberate mispacking).

- [ ] **Step 1: Add `attr_auto` to `pack.py`**

```python
def attr_auto(attr_type: int, value: Any) -> PackedAttribute:
    """Pack an attribute using ATTR_VALUE_TYPES for spec-correct wire type.

    Uses the generated attribute type table to determine whether to pack as
    CK_BBOOL, CK_ULONG, UTF-8 string, or raw bytes. Falls back to Python
    type inference for unknown attributes.

    For deliberate mispacking (fault tests), use attr_bool/attr_ulong/attr_bytes directly.
    """
    from .metadata_std import ATTR_VALUE_TYPES
    vtype = ATTR_VALUE_TYPES.get(int(attr_type))

    if vtype == "bool":
        return attr_bool(attr_type, bool(value))
    elif vtype == "ulong":
        return attr_ulong(attr_type, int(value))
    elif vtype == "str":
        if isinstance(value, bytes):
            return attr_bytes(attr_type, value)
        return attr_bytes(attr_type, str(value).encode("utf-8"))
    elif vtype is not None:
        # bytes, date, template, ulong_array, biginteger → raw bytes
        if isinstance(value, str):
            return attr_bytes(attr_type, value.encode("utf-8"))
        return attr_bytes(attr_type, bytes(value) if not isinstance(value, (bytes, bytearray)) else value)
    # Unknown attribute: fall back to Python type inference
    if isinstance(value, bool):
        return attr_bool(attr_type, value)
    elif isinstance(value, int):
        return attr_ulong(attr_type, value)
    elif isinstance(value, str):
        return attr_bytes(attr_type, value.encode("utf-8"))
    elif isinstance(value, (bytes, bytearray)):
        return attr_bytes(attr_type, value)
    raise TypeError(f"Cannot pack {type(value)} for attr {attr_type:#x}")
```

- [ ] **Step 2: Add `template_from_dict` to `pack.py`**

```python
def template_from_dict(attrs: dict[int, Any]) -> TemplateArg:
    """Build a template from {CKA_*: value} dict with spec-correct type packing."""
    return template(*[attr_auto(k, v) for k, v in attrs.items()])
```

- [ ] **Step 3: Upgrade `_pack_attrs` in recipes.py to use `attr_auto`**

Replace the manual type-checking in `_pack_attrs` with `attr_auto`:

```python
def _pack_attrs(
    attrs: dict[int, Any] | None,
    *,
    skip: set[int] | None = None,
) -> list[Any]:
    """Convert {attr_type: value} dict to PackedAttributes using spec type table."""
    if not attrs:
        return []
    from .pack import attr_auto
    return [
        attr_auto(attr_type, value)
        for attr_type, value in attrs.items()
        if not (skip and int(attr_type) in skip)
    ]
```

- [ ] **Step 4: Run tests**

```bash
bash local-builds/test.sh softhsm2 -- src/pkcs11_check/testcases/test_slot.py src/pkcs11_check/testcases/test_interface.py src/pkcs11_check/testcases/test_digest.py src/pkcs11_check/testcases/test_encrypt.py src/pkcs11_check/testcases/test_generic_secret.py src/pkcs11_check/testcases/test_errors.py src/pkcs11_check/testcases/test_sign.py src/pkcs11_check/testcases/test_session_info.py src/pkcs11_check/testcases/test_data_objects.py src/pkcs11_check/testcases/test_key_lifecycle.py
```

Expected: 107 passed, 6 skipped.

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/raw/pack.py src/pkcs11_check/raw/recipes.py
git commit -m "feat: add attr_auto and template_from_dict with spec-driven type packing"
```

---

## Task 3: Add drift test

**Files:**
- Modify: `tests/test_raw_generation.py`

- [ ] **Step 1: Add test verifying ATTR_VALUE_TYPES coverage**

```python
def test_attr_value_types_covers_common_attrs() -> None:
    """ATTR_VALUE_TYPES covers at least the common attributes."""
    from pkcs11_check.raw.metadata_std import ATTR_VALUE_TYPES, ATTR_NAMES

    # Every entry in ATTR_VALUE_TYPES must be a valid CKA constant
    for attr_id in ATTR_VALUE_TYPES:
        assert attr_id in ATTR_NAMES, f"Unknown attr {attr_id:#x} in ATTR_VALUE_TYPES"

    # Core attrs must be present
    from pkcs11_check.raw.types_std import (
        CKA_CLASS, CKA_TOKEN, CKA_LABEL, CKA_KEY_TYPE, CKA_VALUE,
        CKA_ENCRYPT, CKA_DECRYPT, CKA_MODULUS, CKA_VALUE_LEN,
    )
    for attr in (CKA_CLASS, CKA_TOKEN, CKA_LABEL, CKA_KEY_TYPE, CKA_VALUE,
                 CKA_ENCRYPT, CKA_DECRYPT, CKA_MODULUS, CKA_VALUE_LEN):
        assert int(attr) in ATTR_VALUE_TYPES, f"{attr} missing from ATTR_VALUE_TYPES"


def test_attr_value_types_valid_type_strings() -> None:
    """All type values are recognized strings."""
    from pkcs11_check.raw.metadata_std import ATTR_VALUE_TYPES

    valid = {"bool", "ulong", "bytes", "str", "date", "ulong_array", "template"}
    for attr_id, vtype in ATTR_VALUE_TYPES.items():
        assert vtype in valid, f"Attr {attr_id:#x} has unknown type {vtype!r}"
```

- [ ] **Step 2: Cross-check against python-pkcs11**

```python
def test_attr_value_types_matches_python_pkcs11() -> None:
    """ATTR_VALUE_TYPES agrees with python-pkcs11 on value type categories."""
    from pkcs11_check.raw.metadata_std import ATTR_VALUE_TYPES

    try:
        from pkcs11.attributes import ATTRIBUTE_TYPES, handle_bool, handle_ulong, handle_str
    except ImportError:
        pytest.skip("python-pkcs11 not available")

    # Map python-pkcs11 handler → our type string
    from pkcs11.attributes import handle_bytes, handle_biginteger, handle_date
    handler_map = {
        id(handle_bool): "bool",
        id(handle_ulong): "ulong",
        id(handle_str): "str",
        id(handle_bytes): "bytes",
        id(handle_biginteger): "bytes",  # big integer stored as bytes
        id(handle_date): "date",
    }

    mismatches = []
    for attr, handler in ATTRIBUTE_TYPES.items():
        attr_id = int(attr)
        if attr_id not in ATTR_VALUE_TYPES:
            continue  # We may not cover all python-pkcs11 attrs
        expected = handler_map.get(id(handler))
        if expected is None:
            continue  # Enum handlers, array handlers — skip for now
        actual = ATTR_VALUE_TYPES[attr_id]
        if actual != expected:
            mismatches.append(f"CKA {attr_id:#x}: ours={actual}, fork={expected}")

    assert not mismatches, f"Type mismatches:\n" + "\n".join(mismatches)
```

- [ ] **Step 3: Run and commit**

```bash
uv run python -m pytest tests/test_raw_generation.py -v -k attr_value
git add tests/test_raw_generation.py
git commit -m "test: add drift tests for ATTR_VALUE_TYPES coverage and cross-check"
```
