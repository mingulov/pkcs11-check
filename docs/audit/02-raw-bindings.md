# Audit 02: Raw Bindings Parity

**Date:** 2026-04-01
**OASIS specs referenced:** `general_data_types.md`, `conventions_for_functions_output.md`
**Files audited:** `raw/types_std.py`, `raw/metadata_std.py`, `raw/pack.py`, `raw/pack_mechanisms.py`, `raw/extensions.py`, `raw/attr_metadata.py`

## Findings

### Constant Parity (types_std.py vs pkcs11.h)

| Family | types_std | header | Diff |
|--------|----------|--------|------|
| CKM_* (mechanisms) | 480 | 480 | 0 |
| CKA_* (attributes) | 160 | 160 | 0 |
| CKR_* (return codes) | 105 | 105 | 0 |
| CKK_* (key types) | 69 | 69 | 0 |
| CKO_* (object classes) | 13 | 13 | 0 |
| CKF_* (flags) | 73 | 73 | 0 |

**Result: Perfect parity across all 6 constant families.**

### Function Signatures (metadata_std.py vs pkcs11.h)

- Header: 104 C_* functions
- metadata_std.py: 104 C_* functions
- **Result: Perfect parity.**

### Mechanism Parameter Structures

- `types_std.py` defines 70 `CK_*_PARAMS` structures
- `pack_mechanisms.py` provides 29 dedicated packing functions for the most-used mechanisms
- Gap is expected: many param structs are simple (single field), legacy, or rarely used
- [NOTED] No packing function exists for: CK_WTLS_*, CK_CMS_*, CK_SKIPJACK_*, CK_BATON_*, CK_KEA_* — all legacy/rare

### Extensions Registry

- `extensions.py` handles vendor extension namespaces, not version gating
- v3.0+ and v3.2+ functions (MessageEncrypt, Encapsulate, etc.) are in `metadata_std.py` directly
- Interface version negotiation handled in `core/loader.py`

### Quality Issues

- None found. Raw bindings module is well-maintained.

### Coverage Gaps

- [GAP] 41 CK_*_PARAMS structures have no dedicated packing function in `pack_mechanisms.py` — most are legacy (WTLS, CMS, KEA, Skipjack, BATON) or simple enough to use `mech_simple()`

## Statistics

- Files audited: 6
- Issues found: 0 fixed, 1 gap noted (legacy param structs)
- Tests added: 0
- Lines changed: 0
