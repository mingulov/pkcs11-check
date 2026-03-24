# pkcs11_check.raw

`pkcs11_check.raw` is pkcs11-check's own exact-call PKCS#11 layer.

It is not the old `python-pkcs11` raw shim moved around. The fork is now optional bridge input
for already-loaded libraries, but this package owns the raw API surface, generated standard
declarations, packing helpers, malformed-input helpers, inspection helpers, and extension registry.

## Design Contract

This package is the trust boundary for exact PKCS#11 calls in pkcs11-check.

What it guarantees:

- `C_*` calls return raw integer `CK_RV` values
- no PKCS#11 exceptions are auto-raised by the dispatch core
- no default attributes
- no automatic mechanism selection
- no hidden capability inference
- no silent conversion between `NULL`, empty buffers, or omitted values
- malformed inputs can be modeled deliberately instead of dropped or normalized
- manual `ctypes` escape hatches remain possible

What it must not become:

- a second high-level object API
- a policy wrapper around PKCS#11
- a place that "helps" by silently changing the call

If a future helper changes the meaning of the call without the test author opting into that change
explicitly, it does not belong in `pkcs11_check.raw`.

## Typed Constants

All PKCS#11 constants are typed int subclasses organized by family:

| Class | Family | Example |
|-------|--------|---------|
| `CKA` | Attributes | `CKA_TOKEN`, `CKA_ENCRYPT` |
| `CKM` | Mechanisms | `CKM_AES_KEY_GEN`, `CKM_RSA_PKCS` |
| `CKK` | Key types | `CKK_AES`, `CKK_RSA` |
| `CKO` | Object classes | `CKO_SECRET_KEY`, `CKO_PUBLIC_KEY` |
| `CKR` | Return values | `CKR_OK`, `CKR_GENERAL_ERROR` |
| `CKF` | Flags | `CKF_RW_SESSION`, `CKF_ENCRYPT` |

Import constant classes from `pkcs11_check.raw`, individual constants from `types_std`:

```python
from pkcs11_check.raw import CKA, CKM, RawPKCS11
from pkcs11_check.raw.types_std import CKA_TOKEN, CKM_AES_KEY_GEN
```

Vendor constants need no registration:

```python
CKM_VENDOR_ALGO = CKM(0x80010001, "CKM_VENDOR_ALGO")
# or inline:
mech_simple(CKM(0x80010001))
```

CKF flags support bitwise operations:

```python
flags = CKF_RW_SESSION | CKF_SERIAL_SESSION  # returns CKF
```

## Recipes

Convenience helpers that reduce boilerplate without hiding PKCS#11 semantics.
All take `raw: RawPKCS11` as first parameter and use `expect_rv()` for errors.

- `quick_session(raw, slot_id, flags, pin, user_type)` - open session + login
- `gen_aes_key(raw, session, bits, attrs)` - generate AES key
- `gen_rsa_keypair(raw, session, bits, public_attrs, private_attrs)` - generate RSA keypair
- `gen_ec_keypair(raw, session, curve_oid, public_attrs, private_attrs)` - generate EC keypair
- `import_secret_key(raw, session, key_type, value, attrs)` - import secret key
- `destroy_quietly(raw, session, handle)` - destroy object, ignore errors
- `encrypt_single(raw, session, key, mechanism, plaintext)` - single-part encrypt
- `sign_single(raw, session, key, mechanism, data)` - single-part sign

Recipes call `expect_rv()` and raise on non-OK. For exact CK_RV control, use raw C_* calls.

## Package Layout

- `types_std.py`
  Generated standard `CK_*` constants, aliases, callbacks, structs, and function-list layouts.
- `metadata_std.py`
  Generated function signatures, function indices, and name tables.
- `api.py`
  `RawPKCS11`, the exact `C_*` dispatch layer.
- `bridge.py`
  Bridge helpers from a loaded `python-pkcs11` library or pkcs11-check loader module.
- `pack.py`
  Exact valid-value packers with owned storage.
- `faults.py`
  Explicit malformed pointer/length/count helpers.
- `inspect.py`
  Human-readable rendering of packed and malformed raw values.
- `bootstrap.py`
  Minimal slot/session/login setup helpers for tests.
- `extensions.py`
  Namespace-isolated vendor extension registry.
- `rv.py`
  `CK_RV` naming and explicit assertion helpers.

Compatibility wrappers:

- `core.py`
- `template.py`
- `mechanism.py`

These exist for migration compatibility. New code should prefer the primary modules directly.

## Basic Use

Standalone load from a PKCS#11 module path:

```python
from ctypes import byref

from pkcs11_check.raw import RawPKCS11
from pkcs11_check.raw.core import CK_INFO, CKR_OK

raw = RawPKCS11.from_lib("/path/to/module.so")

info = CK_INFO()
rv = raw.C_GetInfo(byref(info))
assert rv == CKR_OK
```

Bridge from a `python-pkcs11` library already loaded by pkcs11-check:

```python
from pkcs11_check.raw import raw_from_module

raw = raw_from_module(p11_module)
rv = raw.C_GetSessionInfo(session_handle, session_info_ptr)
```

Available entry points are explicit:

```python
names = raw.available_function_names()
if "C_EncapsulateKey" in names:
    ...
```

`RawPKCS11` loads:

- base v2.40 functions from `C_GetFunctionList()` or an equivalent function-list pointer
- v3.0 tails only when the function-list version is actually `>= 3.0`
- v3.2 tails only when the function-list version is actually `>= 3.2`

Do not assume that a generic `C_GetInterface(NULL, NULL, ...)` result is v3.0+.

## Exact Packing

Use `pack.py` when you want exact valid packing with owned backing storage.

```python
from ctypes import byref

from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template

tmpl = template(
    attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
    attr_ulong(CKA_KEY_TYPE, CKK_AES),
    attr_ulong(CKA_VALUE_LEN, 32),
    attr_bool(CKA_ENCRYPT, True),
    attr_bool(CKA_DECRYPT, True),
)
mech = mech_simple(CKM_AES_KEY_GEN)

key = CK_OBJECT_HANDLE()
rv = raw.C_GenerateKey(session, mech.byref(), tmpl.ptr, tmpl.count, byref(key))
```

Important properties:

- packers keep storage alive for the call
- pointer and length/count provenance stay separate
- explicit lengths are preserved when you ask for them
- packers do not invent missing attributes or rewrite your template

Common helpers:

- `attr_bool`
- `attr_ulong`
- `attr_bytes`
- `attr_string`
- `attr_date`
- `attr_array`
- `attr_template`
- `template`
- `mech_simple`
- `mech_bytes`
- mechanism-specific helpers in `pack.py`

## Malformed Inputs

Use `faults.py` when the invalid shape is the point of the test.

```python
from pkcs11_check.raw.faults import null_pointer, nonnull_zero_length_bytes

bad_data = nonnull_zero_length_bytes(b"abc")
rv = raw.C_Sign(session, bad_data.pointer, bad_data.explicit_length, None, sig_len_ptr)
```

Examples of first-class malformedness:

- `null_pointer()`
- `explicit_length(...)`
- `zero_length()`
- `nonnull_zero_length_bytes(...)`
- `incorrect_explicit_length_bytes(...)`
- `truncated_struct(...)`
- `mismatched_template_count(...)`
- `wrong_buffer_shape_ulong_array_as_bytes(...)`

If a malformed case is recurring across tests, add a named helper here instead of open-coding the
same `ctypes` trick repeatedly.

## Inspection

Use `inspect.py` to show what will actually be passed:

```python
from pkcs11_check.raw.inspect import render_mechanism, render_template

print(render_mechanism(mech))
print(render_template(tmpl))
```

This layer is for human review and debugging. It should expose:

- symbolic names when known
- raw numeric values when unknown
- pointer origin and storage kind
- explicit vs native lengths
- byte previews for owned byte buffers

Inspection should describe the call, not reinterpret it.

## Bootstrap Helpers

`bootstrap.py` provides minimal session setup helpers used by tests:

- `get_slot_ids`
- `open_session`
- `login_user`
- `close_session_quietly`

These helpers are intentionally narrow. They do not choose slots, mechanisms, templates, or login
policy for the caller.

One deliberate exception exists in `login_user()`: it accepts both `CKR_OK` and
`CKR_USER_ALREADY_LOGGED_IN`. That preserves the historical setup behavior used by raw subprocess
tests. If a test needs strict `C_Login` return-code checking, call `raw.C_Login(...)` directly
instead of going through `login_user()`.

## Return Values

The dispatch core returns integer `CK_RV` values.

Use `rv.py` for readability:

```python
from pkcs11_check.raw.rv import ckr_name, expect_rv

rv = raw.C_Finalize(None)
print(ckr_name(rv))
expect_rv(rv, CKR_OK)
```

`expect_rv()` is opt-in. It is not part of the dispatch core.

## Vendor Extensions

Vendor-specific symbols and helpers belong in `extensions.py`, not in the generated standard layer.

Register them under an explicit namespace:

```python
from pkcs11_check.raw.extensions import register_extension

register_extension(
    namespace="ibm",
    mechanisms={
        0x80010001: "CKM_IBM_EXAMPLE",
    },
)
```

Rules:

- standard ids and names must not be reused as vendor extensions
- helper lookup must stay namespace-isolated
- registering the same mapping twice is fine
- conflicting registrations in the same namespace are errors
- unknown vendor ids must remain possible without patching the generated standard modules

Vendor packers and inspectors should be added through the registry, not by editing `types_std.py`
or `metadata_std.py`.

## Generated Files

Do not hand-edit:

- `types_std.py`
- `metadata_std.py`

They are generated from the vendored PKCS#11 v3.2 public-domain headers in:

- `third_party/pkcs11-headers/3.2/pkcs11.h`
- `third_party/pkcs11-headers/3.2/pkcs11f.h`
- `third_party/pkcs11-headers/3.2/pkcs11t.h`

Regenerate with:

```bash
uv run python scripts/generate_raw_standard.py
```

Minimum drift checks:

```bash
uv run python -m pytest tests/test_raw_generation.py tests/test_raw_api.py tests/test_raw_bootstrap.py -q
uv run python -m pytest tests/test_raw_pack.py -q
```

If you change generator behavior, rerun the broader raw/meta bundle as well.

## Maintenance Rules

When extending `pkcs11_check.raw`, prefer this order:

1. standard generator changes for standard symbols and ABI
2. `api.py` for dispatch behavior
3. `pack.py` for exact valid packing
4. `faults.py` for named malformed-input modeling
5. `inspect.py` for readability/debugging
6. `extensions.py` for vendor-specific growth

Do not add convenience by hiding exactness. Add convenience only when the exact call remains obvious
and recoverable.
