# Coverage Call Counters & Version Marker Fix

**Date:** 2026-03-27
**Status:** Design approved, pending implementation

## Problem Statement

Three distinct issues discovered during NSS-PQC investigation:

1. **Version markers too broad:** 8 PQC test files have `requires_v32` at file level, blocking ML-DSA/SLH-DSA sign/verify tests on modules that advertise these mechanisms but negotiate v2.40 interface (e.g., SoftHSM2-main). These tests use only v2.40 API functions (C_GenerateKeyPair, C_SignInit, C_VerifyInit); the v3.2 aspect is the mechanism, not the function.

2. **Bootstrap functions invisible to coverage:** C_Initialize, C_GetSlotList, C_GetSlotInfo, C_OpenSession, and C_Login are called in fixture setup before `reset_call_log()` at `fixtures.py:205`, so they never appear in `called_names`. Coverage reports 45/68 functions called, but 5 additional functions are genuinely exercised.

3. **No call counts in coverage.json:** `api.py._call_log` already tracks per-function invocation counts, but `plugin.py:311` uses only `.keys()`, discarding the counts. `_used_mechanisms` is a set (no counts). The file_runner merges coverage with set union, not count summation. Users cannot see how heavily each function/mechanism is exercised.

## Component 1: Remove `requires_v32` from Sign/Verify PQC Tests

### Files to modify

Remove `requires_v32` from `pytestmark` in these 8 files (keep other markers like `pytest.mark.pqc`):

| File | Current pytestmark | After |
|------|-------------------|-------|
| `test_pqc_sign.py:44` | `[pqc, requires_v32]` | `[pqc]` |
| `test_hash_ml_dsa.py:46` | `[pqc, requires_v32]` | `[pqc]` |
| `test_hash_slh_dsa.py:46` | `[pqc, requires_v32]` | `[pqc]` |
| `test_stateful_sigs.py:64` | `[pqc, requires_v32]` | `[pqc]` |
| `test_cctv_mldsa.py:40` | `[pqc, requires_v32, kat, cctv]` | `[pqc, kat, cctv]` |
| `test_acvp_slhdsa.py:50` | `[pqc, kat, acvp, requires_v32]` | `[pqc, kat, acvp]` |
| `wycheproof/test_wycheproof_mldsa_sign.py:35` | `[wycheproof, pqc, requires_v32]` | `[wycheproof, pqc]` |
| `wycheproof/test_wycheproof_mldsa.py:34` | `[wycheproof, requires_v32, pqc]` | `[wycheproof, pqc]` |

### Files to KEEP `requires_v32`

These use v3.2-only C_* functions (C_EncapsulateKey, C_DecapsulateKey, C_WrapKeyAuthenticated, C_UnwrapKeyAuthenticated):

- `test_kem.py` — C_EncapsulateKey, C_DecapsulateKey
- `wycheproof/test_wycheproof_mlkem.py` — C_EncapsulateKey, C_DecapsulateKey
- `ckr/test_ckr_kem.py` — C_EncapsulateKey error codes
- `ckr/test_ckr_v32_raw.py` — raw v3.2 function tests
- `test_interface.py:115` — v3.2 interface negotiation
- `test_extended_mechanisms.py` — individual method markers (correct)
- `test_remaining_gaps.py` — individual method markers (correct)

### Rationale

PKCS#11 mechanisms can be advertised and used through any interface version. A module negotiating v2.40 can still support CKM_ML_DSA via standard C_SignInit/C_VerifyInit. The `requires_v32` marker should only gate tests that call v3.2 *functions*, not tests that use v3.2 *mechanisms*.

All 8 files already have runtime `has_mechanism()` guards that skip cleanly when the mechanism is not advertised:
```python
def _skip_if_no(rs, mech_name):
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"{mech_name} not supported by module")
```

### Verification

After the fix, SoftHSM2-main (which advertises CKM_ML_DSA but negotiates v2.40) should run ML-DSA tests instead of skipping 60 tests with "Requires v32, module has v2.40".

## Component 2: Bootstrap Call Tracking

### Problem

`fixtures.py` calls these functions before `reset_call_log()`:
- `C_Initialize` (in loader, before fixture)
- `C_GetSlotList` (in `get_slot_ids()`)
- `C_GetSlotInfo` (in `get_slot_ids()`)
- `C_OpenSession` (in `raw_open_session()`)
- `C_Login` (in `login_user()`)

After `reset_call_log()` at line 205, these are erased from `_call_log`. Coverage reports them as "uncalled".

### Solution

Snapshot the call log before resetting it. Store as `bootstrap_counts` on the RawSession or in the config stash.

**In `fixtures.py`, before `reset_call_log()`:**
```python
# Snapshot bootstrap calls before reset
bootstrap_log = dict(raw.call_log)
bootstrap_mechs = dict(raw.mechanism_counts)  # after Component 3 adds this
raw.reset_call_log()
raw.reset_used_mechanisms()
```

Store `bootstrap_log` on the `RawSession` dataclass as a new field:
```python
@dataclass
class RawSession:
    raw: RawPKCS11
    sh: int
    slot_id: int
    _mechanisms: frozenset[str] | None = field(default=None, repr=False)
    bootstrap_call_counts: dict[str, int] = field(default_factory=dict, repr=False)
```

**In `plugin.py` teardown**, collect bootstrap counts once (first session only):
```python
if not config.stash.get(_BOOTSTRAP_COLLECTED, False):
    bootstrap = getattr(rs, 'bootstrap_call_counts', {})
    config.stash[_BOOTSTRAP_FUNCTION_COUNTS] = dict(bootstrap)
    config.stash[_BOOTSTRAP_COLLECTED] = True
```

**In `plugin.py` session finish**, emit in coverage_data:
```python
"function_coverage": {
    ...
    "bootstrap_counts": config.stash.get(_BOOTSTRAP_FUNCTION_COUNTS, {}),
    "called_names": sorted((cumulative | set(bootstrap.keys())) & available),
    ...
}
```

### Effect on `called_names` / `uncalled_names`

Bootstrap functions join `called_names`. C_Initialize, C_GetSlotList, C_GetSlotInfo, C_OpenSession, C_Login move from `uncalled_names` to `called_names`. Coverage goes from ~45/68 to ~50/68.

## Component 3: Call Count Enrichment

### Layer 1: api.py — Track mechanism counts

Add a Counter alongside the existing set:

```python
from collections import Counter, defaultdict

class RawPKCS11:
    def __init__(self, ...):
        self._call_log: dict[str, int] = defaultdict(int)
        self._used_mechanisms: set[int] = set()
        self._mechanism_counts: Counter[int] = Counter()  # NEW
```

In `_call()`:
```python
if name in _MECHANISM_ARG_FUNCS and len(args) >= 2:
    try:
        mech_id = args[1]._obj.mechanism
        self._used_mechanisms.add(mech_id)
        self._mechanism_counts[mech_id] += 1  # NEW
    except (AttributeError, TypeError):
        pass
```

New property:
```python
@property
def mechanism_counts(self) -> dict[int, int]:
    return dict(self._mechanism_counts)

def reset_used_mechanisms(self) -> None:
    self._used_mechanisms.clear()
    self._mechanism_counts.clear()  # ALSO RESET COUNTS
```

Backward-compatible: `used_mechanisms` property unchanged (returns set).

### Layer 2: plugin.py — Accumulate counts across sessions

New stash keys:
```python
_CUMULATIVE_FUNCTION_COUNTS: pytest.StashKey[Counter[str]] = pytest.StashKey()
_CUMULATIVE_MECHANISM_COUNTS: pytest.StashKey[Counter[int]] = pytest.StashKey()
_CUMULATIVE_DETAIL_COUNTS: pytest.StashKey[Counter[str]] = pytest.StashKey()
_BOOTSTRAP_FUNCTION_COUNTS: pytest.StashKey[dict[str, int]] = pytest.StashKey()
_BOOTSTRAP_COLLECTED: pytest.StashKey[bool] = pytest.StashKey()
```

At `pytest_configure`:
```python
config.stash[_CUMULATIVE_FUNCTION_COUNTS] = Counter()
config.stash[_CUMULATIVE_MECHANISM_COUNTS] = Counter()
config.stash[_CUMULATIVE_DETAIL_COUNTS] = Counter()
config.stash[_BOOTSTRAP_FUNCTION_COUNTS] = {}
config.stash[_BOOTSTRAP_COLLECTED] = False
```

At `pytest_runtest_teardown` (alongside existing code):
```python
# Existing: cumulative.update(rs.raw.call_log.keys())
# NEW: also accumulate counts
func_counts = session.config.stash[_CUMULATIVE_FUNCTION_COUNTS]
func_counts.update(rs.raw.call_log)  # Counter.update sums values

# Existing: used.update(rs.raw.used_mechanisms)
# NEW: also accumulate mechanism counts
mech_counts = session.config.stash[_CUMULATIVE_MECHANISM_COUNTS]
mech_counts.update(rs.raw.mechanism_counts)  # Counter.update sums
```

For mechanism detail counts, change `_CUMULATIVE_MECHANISM_DETAILS` from a set to a Counter keyed by the stacked string:
```python
# Instead of detail_set.add((mech_id, frozenset(subs.items())))
# Build the string immediately and count it:
detail_counts = session.config.stash[_CUMULATIVE_DETAIL_COUNTS]
for mech_id, subs in details:
    detail_str = _build_single_stacked_string(mech_id, subs)
    detail_counts[detail_str] += 1
```

At `pytest_sessionfinish`, emit counts in coverage_data:
```python
func_counts = config.stash.get(_CUMULATIVE_FUNCTION_COUNTS, Counter())
mech_counts = config.stash.get(_CUMULATIVE_MECHANISM_COUNTS, Counter())
detail_counts = config.stash.get(_CUMULATIVE_DETAIL_COUNTS, Counter())
bootstrap = config.stash.get(_BOOTSTRAP_FUNCTION_COUNTS, {})

coverage_data = {
    "function_coverage": {
        "available": len(available),
        "called": len(called),
        "called_names": called,
        "called_counts": {k: v for k, v in sorted(func_counts.items())},  # NEW
        "bootstrap_counts": bootstrap,  # NEW
        "uncalled_names": uncalled,
    },
    "mechanism_coverage": {
        "available": len(mech_ckm),
        "available_names": mech_ckm,
        "invoked": len(invoked_names),
        "invoked_names": invoked_names,
        "invoked_counts": {ckm_name(k): v for k, v in sorted(mech_counts.items())},  # NEW
        "not_invoked": len(not_invoked),
        "not_invoked_names": not_invoked,
        "invoked_detail": stacked,
        "invoked_detail_counts": {k: v for k, v in sorted(detail_counts.items())},  # NEW
    },
}
```

### Layer 3: file_runner.py — Merge counts across files

Update `extract_coverage_from_jsonl()` to use Counter addition:

```python
from collections import Counter

all_func_counts: Counter[str] = Counter()
all_mech_counts: Counter[str] = Counter()
all_detail_counts: Counter[str] = Counter()
all_bootstrap_counts: Counter[str] = Counter()

# In the parse loop:
all_func_counts.update(fc.get("called_counts", {}))
all_bootstrap_counts.update(fc.get("bootstrap_counts", {}))
all_mech_counts.update(mc.get("invoked_counts", {}))
all_detail_counts.update(mc.get("invoked_detail_counts", {}))

# In the return dict:
"called_counts": dict(all_func_counts),
"bootstrap_counts": dict(all_bootstrap_counts),
"invoked_counts": dict(all_mech_counts),
"invoked_detail_counts": dict(all_detail_counts),
```

Counter addition correctly sums values when the same key appears in multiple files.

## Output Format

### Example coverage.json (abbreviated)

```json
{
  "function_coverage": {
    "available": 68,
    "called": 50,
    "called_names": ["C_CloseSession", "C_CreateObject", "C_Decrypt", "C_DecryptInit",
                     "C_DestroyObject", "C_Encrypt", "C_EncryptInit", "C_Finalize",
                     "C_GenerateKey", "C_GenerateKeyPair", "C_GetAttributeValue",
                     "C_GetSlotInfo", "C_GetSlotList", "C_GetTokenInfo",
                     "C_Initialize", "C_Login", "C_Logout", "C_OpenSession",
                     "C_Sign", "C_SignInit", "C_Verify", "C_VerifyInit", "..."],
    "called_counts": {
      "C_CloseSession": 1247,
      "C_CreateObject": 891,
      "C_Decrypt": 3100,
      "C_DecryptInit": 3100,
      "C_DestroyObject": 4521,
      "C_Encrypt": 5200,
      "C_EncryptInit": 5200,
      "C_GenerateKey": 2100,
      "C_Sign": 1800,
      "C_SignInit": 1800,
      "C_Verify": 1800,
      "C_VerifyInit": 1800
    },
    "bootstrap_counts": {
      "C_Initialize": 1,
      "C_GetSlotList": 2,
      "C_GetSlotInfo": 1,
      "C_GetTokenInfo": 1,
      "C_OpenSession": 1,
      "C_Login": 1
    },
    "uncalled_names": ["C_CancelFunction", "C_GetFunctionStatus",
                       "C_MessageDecryptFinal", "..."]
  },
  "mechanism_coverage": {
    "available": 140,
    "available_names": ["CKM_AES_CBC", "CKM_AES_CBC_PAD", "..."],
    "invoked": 107,
    "invoked_names": ["CKM_AES_CBC", "CKM_AES_CBC_PAD", "..."],
    "invoked_counts": {
      "CKM_AES_CBC": 200,
      "CKM_AES_CBC_PAD": 150,
      "CKM_AES_ECB": 523,
      "CKM_AES_GCM": 89,
      "CKM_AES_KEY_GEN": 2100,
      "CKM_RSA_PKCS": 1891,
      "CKM_RSA_PKCS_KEY_PAIR_GEN": 340,
      "CKM_SHA256": 1200
    },
    "not_invoked": 33,
    "not_invoked_names": ["CKM_CDMF_KEY_GEN", "..."],
    "invoked_detail": [
      "CKM_AES_CBC_PAD[iv=16B]",
      "CKM_RSA_PKCS_OAEP[hashAlg=CKM_SHA256,mgf=CKG_MGF1_SHA256]"
    ],
    "invoked_detail_counts": {
      "CKM_AES_CBC_PAD[iv=16B]": 150,
      "CKM_RSA_PKCS_OAEP[hashAlg=CKM_SHA256,mgf=CKG_MGF1_SHA256]": 42
    }
  }
}
```

## Backward Compatibility

All existing fields are preserved with identical semantics. Four new fields added:
- `function_coverage.called_counts` — dict of function name to call count
- `function_coverage.bootstrap_counts` — dict of pre-session function calls
- `mechanism_coverage.invoked_counts` — dict of mechanism name to invocation count
- `mechanism_coverage.invoked_detail_counts` — dict of stacked detail string to count

Consumers that only read existing fields are unaffected.

## Testing

1. **Marker fix verification:** Run `bash docker/test.sh softhsm2-main -- test_pqc_sign.py test_hash_ml_dsa.py` — should show passed/failed instead of all-skipped
2. **Bootstrap tracking:** Run any module — C_Initialize should appear in `called_names`
3. **Count accuracy:** Run SoftHSM2 smoke tests, verify `called_counts` values are > 0 for expected functions
4. **Cross-file merging:** Run full suite in isolation mode, verify counts sum correctly across files
5. **Existing tests:** `uv run python -m pytest tests/` meta-tests must pass
